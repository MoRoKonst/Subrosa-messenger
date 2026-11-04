package com.subrosa.messenger

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.StartOffset
import androidx.compose.animation.core.StartOffsetType
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLocale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Bitmap
import android.os.Build
import android.os.IBinder
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.UUID
import java.util.Locale
import android.content.ContentValues
import android.provider.MediaStore
import android.os.Environment
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlin.math.absoluteValue

// Name kept for API stability (12 files reference this val across the
// codebase) — no longer actually JetBrains Mono. App-wide font swap
// 2026-09-22: body/UI text now uses Inter; see ui/theme/Type.kt for the
// NotoSerifJP heading face used separately at specific call sites (app
// name, large titles, profile, contact/group names).
val JetBrainsMono = com.subrosa.messenger.ui.theme.Inter

private const val CHAT_PAGE_SIZE = 50

// S6-57 (external review 2026-09-06) -- product-level cap on voice-message
// recording length; matches server.py's own MAX_VOICE_DURATION_SECONDS
// exactly (see its comment there for the full byte-math derivation). Neither
// client previously had any recording-length limit at all.
private const val MAX_VOICE_RECORDING_SECONDS = 60

data class Message(
    val id: String = UUID.randomUUID().toString(),
    val text: String,
    val isOwn: Boolean,
    val isSystem: Boolean = false,
    val isRead: Boolean = false,
    val isDelivered: Boolean = false,
    val isEdited: Boolean = false,
    val isPending: Boolean = false,
    val imageBitmap: Bitmap? = null,
    val timestamp: Long = System.currentTimeMillis(),
    val replyTo: Message? = null,
    val reactions: Map<String, String> = emptyMap(),
    val voiceFile: File? = null,
    val voiceDuration: Int = 0,
    val fileName: String? = null,
    val filePath: String? = null,
    val videoPath: String? = null,
    val videoDuration: Int = 0,
    val isFailed: Boolean = false,
    val expiresAt: Long = 0L
)

fun compressImageForSend(bitmap: Bitmap): ByteArray {
    val maxDim = 2048
    val scaled = if (bitmap.width > maxDim || bitmap.height > maxDim) {
        val ratio = minOf(maxDim.toFloat() / bitmap.width, maxDim.toFloat() / bitmap.height)
        Bitmap.createScaledBitmap(bitmap, (bitmap.width * ratio).toInt(), (bitmap.height * ratio).toInt(), true)
    } else bitmap
    val stream = java.io.ByteArrayOutputStream()
    val format = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R)
        Bitmap.CompressFormat.WEBP_LOSSY else @Suppress("DEPRECATION") Bitmap.CompressFormat.WEBP
    scaled.compress(format, 80, stream)
    if (scaled !== bitmap) scaled.recycle()
    return stream.toByteArray()
}

fun bitmapToChunks(bitmap: Bitmap): List<String> {
    val base64 = android.util.Base64.encodeToString(compressImageForSend(bitmap), android.util.Base64.DEFAULT)
    return base64.chunked(50000)
}

fun fileToChunks(bytes: ByteArray): List<String> {
    val base64 = android.util.Base64.encodeToString(bytes, android.util.Base64.DEFAULT)
    return base64.chunked(50000)
}

/** GPS coordinates, device make/model, and capture timestamps a camera embeds
 *  in a JPEG/PNG/HEIF/WebP file. Only relevant on the "attach as file" path —
 *  the dedicated photo picker already goes through a Bitmap decode/re-encode
 *  (`compressImageForSend`), which carries no EXIF forward since Bitmap is
 *  pixel data only, not a container format. A raw file attachment skips that
 *  and would otherwise ship the original bytes, metadata and all. */
private val EXIF_TAGS_TO_STRIP = arrayOf(
    androidx.exifinterface.media.ExifInterface.TAG_GPS_LATITUDE,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_LATITUDE_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_LONGITUDE,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_LONGITUDE_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_ALTITUDE,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_ALTITUDE_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_TIMESTAMP,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DATESTAMP,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_PROCESSING_METHOD,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_VERSION_ID,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_MAP_DATUM,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_LATITUDE,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_LATITUDE_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_LONGITUDE,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_LONGITUDE_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_BEARING,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_BEARING_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_DISTANCE,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DEST_DISTANCE_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_SPEED,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_SPEED_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_TRACK,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_TRACK_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_IMG_DIRECTION,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_IMG_DIRECTION_REF,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_SATELLITES,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_STATUS,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_MEASURE_MODE,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DOP,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_AREA_INFORMATION,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_DIFFERENTIAL,
    androidx.exifinterface.media.ExifInterface.TAG_GPS_H_POSITIONING_ERROR,
    androidx.exifinterface.media.ExifInterface.TAG_MAKE,
    androidx.exifinterface.media.ExifInterface.TAG_MODEL,
    androidx.exifinterface.media.ExifInterface.TAG_SOFTWARE,
    androidx.exifinterface.media.ExifInterface.TAG_ARTIST,
    androidx.exifinterface.media.ExifInterface.TAG_COPYRIGHT,
    androidx.exifinterface.media.ExifInterface.TAG_USER_COMMENT,
    androidx.exifinterface.media.ExifInterface.TAG_IMAGE_DESCRIPTION,
    androidx.exifinterface.media.ExifInterface.TAG_DATETIME,
    androidx.exifinterface.media.ExifInterface.TAG_DATETIME_ORIGINAL,
    androidx.exifinterface.media.ExifInterface.TAG_DATETIME_DIGITIZED,
    androidx.exifinterface.media.ExifInterface.TAG_SUBSEC_TIME,
    androidx.exifinterface.media.ExifInterface.TAG_SUBSEC_TIME_ORIGINAL,
    androidx.exifinterface.media.ExifInterface.TAG_SUBSEC_TIME_DIGITIZED,
    androidx.exifinterface.media.ExifInterface.TAG_CAMERA_OWNER_NAME,
    androidx.exifinterface.media.ExifInterface.TAG_BODY_SERIAL_NUMBER,
    androidx.exifinterface.media.ExifInterface.TAG_LENS_SERIAL_NUMBER,
    androidx.exifinterface.media.ExifInterface.TAG_LENS_MAKE,
    androidx.exifinterface.media.ExifInterface.TAG_LENS_MODEL
)

/** Strips GPS/device/timestamp EXIF tags in place, keeping orientation so the
 *  image doesn't display sideways. Falls back to the original bytes on any
 *  failure (e.g. a format ExifInterface doesn't support) — never blocks a send. */
fun stripExif(context: Context, bytes: ByteArray): ByteArray {
    val temp = File(context.cacheDir, "exif_strip_${UUID.randomUUID()}.tmp")
    return try {
        temp.writeBytes(bytes)
        val exif = androidx.exifinterface.media.ExifInterface(temp.absolutePath)
        var changed = false
        for (tag in EXIF_TAGS_TO_STRIP) {
            if (exif.getAttribute(tag) != null) {
                exif.setAttribute(tag, null)
                changed = true
            }
        }
        if (changed) exif.saveAttributes()
        temp.readBytes()
    } catch (e: Exception) {
        bytes
    } finally {
        temp.delete()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    username: String,
    recipient: String,
    onBack: () -> Unit,
    onStartCall: ((isVideo: Boolean) -> Unit)? = null,
    onOpenContactInfo: () -> Unit = {},
    // Set when navigating here from ContactInfoScreen's "Search" row — the
    // search UI itself has to live here (it filters this screen's own
    // message list), so that row re-enters this screen with it pre-armed
    // instead of duplicating a message list in the profile screen.
    initialSearchMode: Boolean = false,
    onSearchModeConsumed: () -> Unit = {}
) {
    androidx.activity.compose.BackHandler { onBack() }
    var isRecording by remember { mutableStateOf(false) }
    var recordingFile by remember { mutableStateOf<File?>(null) }
    var isVideoMode by remember { mutableStateOf(false) }
    var recordingSeconds by remember { mutableStateOf(0) }
    var showAttachMenu by remember { mutableStateOf(false) }
    var playingVoiceId by remember { mutableStateOf<String?>(null) }
    // Live playback position (ms) for whichever voice bubble is currently
    // playing, polled below -- drives the waveform's played/unplayed split
    // and lets the user drag-seek mid-playback. Global speed toggle
    // (1x/2x, pitch-preserving via AudioHelper.setSpeed -- see its own
    // comment) mirrors Telegram: one persistent choice, not per-message.
    var voicePlaybackMs by remember { mutableStateOf(0) }
    var voiceSpeed by remember { mutableStateOf(1f) }
    LaunchedEffect(playingVoiceId) {
        if (playingVoiceId != null) {
            while (playingVoiceId != null && AudioHelper.isPlaying()) {
                voicePlaybackMs = AudioHelper.getCurrentPositionMs()
                delay(80)
            }
        } else {
            voicePlaybackMs = 0
        }
    }
    var playingVideoId by remember { mutableStateOf<String?>(null) }
    var showKeyWarning by remember { mutableStateOf(false) }
    var showRevokedWarning by remember { mutableStateOf(false) }
    var showSendBlockedWarning by remember { mutableStateOf(false) }
    var isTorConnected by remember { mutableStateOf(TorManager.isConnected) }
    val context = LocalContext.current
    var torWarningDismissed by remember {
        mutableStateOf(
            context.getSharedPreferences("beacon_prefs", Context.MODE_PRIVATE)
                .getBoolean("tor_warning_dismissed", false)
        )
    }
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val userId = UserStorage.getUserId(context)

    var pendingCallIsVideo by remember { mutableStateOf(false) }
    val callPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { perms ->
        val audioOk = perms[android.Manifest.permission.RECORD_AUDIO] == true
        if (audioOk) {
            CallManager.init(context)
            onStartCall?.invoke(pendingCallIsVideo)
        }
    }
    val audioPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            try {
                recordingFile = AudioHelper.startRecording(context)
                isRecording = true
            } catch (e: Exception) {
                android.util.Log.e("ChatScreen", "Audio error: ${e.message}")
            }
        }
    }
    val messages = remember { mutableStateListOf<Message>() }

    val pendingDeliveryJobs = remember { mutableMapOf<String, Job>() }
    var inputText by remember { mutableStateOf("") }
    var showVerifyDialog by remember { mutableStateOf(false) }
    var isOnline by remember { mutableStateOf(false) }
    // Header status text ("online"/"offline") — deliberately NOT the same
    // signal as isOnline above, which is this device's own connection to
    // the server (used to gate sending). There is no real presence protocol
    // for contacts (see ContactHealthManager.RECENTLY_ACTIVE_MS) — showing
    // isOnline here used to claim "the contact is online" when it actually
    // only meant "I am online", which is misleading regardless of whether
    // the contact has said anything in hours. This tracks real, recent
    // activity from the contact instead.
    var contactRecentlyActive by remember { mutableStateOf(false) }
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }
    var isTyping by remember { mutableStateOf(false) }
    var typingJob by remember { mutableStateOf<Job?>(null) }
    var typingDots by remember { mutableStateOf(1) }
    val listState = rememberLazyListState()
    var editingMessageId by remember { mutableStateOf<String?>(null) }
    var isEditMode by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val allHistory = remember { mutableListOf<ChatStorage.StoredMessage>() }
    var historyDisplayStart by remember { mutableIntStateOf(0) }
    var hasMoreHistory by remember { mutableStateOf(false) }
    var isLoadingMoreHistory by remember { mutableStateOf(false) }
    // True once this contact can be messaged anonymously (or wasn't a
    // mailbox-bootstrapped contact to begin with). Starts optimistic (true) so
    // existing/established chats never flash a "connecting" state; flipped to
    // false below once the service confirms this is a genuinely pending contact.
    var channelReady by remember { mutableStateOf(true) }
    // Found live: tapping "📍 Геопозиция" in the attach menu sent immediately,
    // no confirmation — an accidental tap (buttons stacked close together in
    // that menu) shared the user's real location with no way to back out.
    var showGeoConfirm by remember { mutableStateOf(false) }

    val sendGeo: () -> Unit = {
        scope.launch {
            try {
                val fusedClient = com.google.android.gms.location.LocationServices
                    .getFusedLocationProviderClient(context)

                var loc: android.location.Location? = suspendCancellableCoroutine { cont ->
                    fusedClient.lastLocation
                        .addOnSuccessListener { cont.resume(it, null) }
                        .addOnFailureListener { cont.resume(null, null) }
                }

                if (loc == null) {
                    loc = withTimeoutOrNull(30_000L) {
                        suspendCancellableCoroutine { cont ->
                            val cts = com.google.android.gms.tasks.CancellationTokenSource()
                            fusedClient.getCurrentLocation(
                                com.google.android.gms.location.Priority.PRIORITY_BALANCED_POWER_ACCURACY,
                                cts.token
                            )
                                .addOnSuccessListener { cont.resume(it, null) }
                                .addOnFailureListener { cont.resume(null, null) }
                            cont.invokeOnCancellation { cts.cancel() }
                        }
                    }
                }

                if (loc != null) {
                    val coordsText = "${loc.latitude},${loc.longitude}"
                    val msgId = messengerService?.send(recipient, coordsText) ?: UUID.randomUUID().toString()
                    messages.add(Message(id = msgId, text = s.chatGeo, isOwn = true))
                    ChatStorage.saveOrUpdateMessage(
                        context, userId, recipient,
                        ChatStorage.StoredMessage(id = msgId, text = coordsText, isOwn = true)
                    )
                    listState.animateScrollToItem(messages.size - 1)
                } else {
                    android.widget.Toast.makeText(context, s.chatGeoFail, android.widget.Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                android.util.Log.e("ChatScreen", "Geo error: ${e.message}")
                android.widget.Toast.makeText(context, s.chatGeoFail, android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    }
    val geoPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) sendGeo()
        else android.widget.Toast.makeText(context, s.chatGeoPermission, android.widget.Toast.LENGTH_SHORT).show()
    }

    var showReactionPicker by remember { mutableStateOf<Message?>(null) }

    var replyToMessage by remember { mutableStateOf<Message?>(null) }

    var contextMenuMessage by remember { mutableStateOf<Message?>(null) }

    var fullscreenImageBitmap by remember { mutableStateOf<Bitmap?>(null) }

    var searchMode by remember { mutableStateOf(initialSearchMode) }
    var searchQuery by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (initialSearchMode) onSearchModeConsumed() }

    var disappearTimerSecs by remember { mutableStateOf(0L) }

    // Local-only auto-delete (not synced to the peer) — distinct from
    // disappearTimerSecs above. Ported from Desktop for parity.
    var autoDeleteSecs by remember { mutableStateOf(0L) }

    var showVideoCircleRecorder by remember { mutableStateOf(false) }

    var showForwardDialog by remember { mutableStateOf<Message?>(null) }

    fun storedToMessage(msg: ChatStorage.StoredMessage, historyMap: Map<String, ChatStorage.StoredMessage>): Message {
        val displayText = if (msg.text.matches(Regex("^-?\\d+\\.\\d+,-?\\d+\\.\\d+$"))) s.chatGeo else msg.text
        val replyStored = msg.replyToId?.let { historyMap[it] }
        val replyMsg = replyStored?.let { r -> Message(id = r.id, text = r.text, isOwn = r.isOwn, timestamp = r.timestamp) }
        return Message(
            id = msg.id,
            text = displayText,
            isOwn = msg.isOwn,
            reactions = msg.reactions,
            voiceFile = if (msg.voicePath != null) File(msg.voicePath) else null,
            voiceDuration = msg.voiceDuration,
            isEdited = msg.isEdited,
            isDelivered = msg.isDelivered,
            isRead = msg.isRead,
            isFailed = msg.isFailed,
            replyTo = replyMsg,
            imageBitmap = if (msg.imagePath != null) {
                try {
                    if (msg.imagePath.endsWith(".enc")) {
                        val bytes = SecureFileStorage.read(context, File(msg.imagePath))
                        android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    } else android.graphics.BitmapFactory.decodeFile(msg.imagePath)
                } catch (e: Exception) { null }
            } else null,
            fileName = msg.fileName,
            filePath = msg.filePath,
            videoPath = msg.videoPath,
            videoDuration = msg.videoDuration,
            expiresAt = msg.expiresAt
        )
    }

    fun loadMessages() {
        scope.launch(Dispatchers.IO) {
            val history = ChatStorage.loadMessages(context, userId, recipient)
            val historyMap = history.associateBy { it.id }
            withContext(Dispatchers.Main) {
                messages.clear()
                history.forEach { msg -> messages.add(storedToMessage(msg, historyMap)) }
            }
        }
    }

    fun loadMoreHistory() {
        if (isLoadingMoreHistory || !hasMoreHistory) return
        scope.launch {
            isLoadingMoreHistory = true
            val newStart = maxOf(0, historyDisplayStart - CHAT_PAGE_SIZE)
            val slice = allHistory.subList(newStart, historyDisplayStart)
            val historyMap = allHistory.associateBy { it.id }
            val decoded = slice.map { storedToMessage(it, historyMap) }
            messages.addAll(0, decoded)
            historyDisplayStart = newStart
            hasMoreHistory = newStart > 0
            listState.scrollToItem(decoded.size)
            isLoadingMoreHistory = false
        }
    }

    val connection = remember {
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                val service = (binder as MessengerService.LocalBinder).getService()
                messengerService = service
                isOnline = service.isOnline()
                contactRecentlyActive = ContactHealthManager.isRecentlyActive(context, recipient)
                service.clearNotifLines("dm_$recipient")

                // If this contact's anonymous channel isn't confirmed established yet,
                // show the connecting state and (re-)kick the bootstrap immediately —
                // opening the chat is exactly the moment the user wants to write, per
                // the "retry on demand" half of the schedule (background timer covers
                // the rest even if the chat is never reopened).
                channelReady = service.isChannelReady(recipient)
                if (!channelReady) service.bootstrapChannelFor(recipient)
                service.onChannelReady = { contact ->
                    if (contact == recipient) channelReady = true
                }

                // sendRead() in the recipient-keyed LaunchedEffect below can race ahead
                // of this binding (both LaunchedEffects launch on first composition, no
                // ordering guarantee between them) — if it loses the race, messengerService
                // is still null there and the safe-call silently drops the read receipt for
                // the whole chat-open session, with no retry. Re-send it here too now that
                // binding is guaranteed; resending the same watermark id is harmless.
                scope.launch(Dispatchers.IO) {
                    val history = ChatStorage.loadMessages(context, userId, recipient)
                    history.lastOrNull { !it.isOwn }?.let { service.sendRead(recipient, it.id) }
                }

                service.onTypingReceived = { from ->
                    if (from == recipient) {
                        isTyping = true
                        typingJob?.cancel()
                        typingJob = scope.launch {
                            delay(3000)
                            isTyping = false
                        }
                    }
                }

                service.onKeyChanged = { contactId ->
                    if (contactId == recipient) showKeyWarning = true
                }

                service.onContactRevoked = { contactId ->
                    if (contactId == recipient) showRevokedWarning = true
                }

                service.onContactSendUnblocked = { contactId ->
                    if (contactId == recipient) showSendBlockedWarning = false
                }

                service.onReadReceived = { messageId ->
                    // The peer only acks the newest message it actually read (watermark
                    // semantics — see sendRead() call sites), implying everything at or
                    // before it was read too. But only sweep messages that were genuinely
                    // delivered: a message that failed to decrypt on the peer's end (e.g.
                    // BAD_DECRYPT from a stale ratchet) never reached "delivered" and must
                    // not be marked "read" just because a later, unrelated message succeeded.
                    val readIndex = messages.indexOfFirst { it.id == messageId }
                    if (readIndex != -1) {
                        for (i in 0..readIndex) {
                            val msg = messages[i]
                            if (msg.isOwn && msg.isDelivered && !msg.isRead) {
                                messages[i] = msg.copy(isRead = true)
                            }
                        }
                        messages[readIndex] = messages[readIndex].copy(isRead = true, isDelivered = true)
                    }
                }

                service.onDeliveredReceived = { messageId ->

                    pendingDeliveryJobs.remove(messageId)?.cancel()
                    val index = messages.indexOfFirst { it.id == messageId }
                    if (index != -1) messages[index] = messages[index].copy(
                        isDelivered = true, isPending = false, isFailed = false
                    )
                }

                service.onReactionReceived = { from, messageId, emoji ->
                    try {
                        val index = messages.indexOfFirst { it.id == messageId }
                        if (index != -1) {
                            val updated = messages[index].copy(
                                reactions = messages[index].reactions.toMutableMap().also { it[from] = emoji }
                            )
                            messages[index] = updated
                            ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                ChatStorage.StoredMessage(
                                    id = updated.id, text = updated.text,
                                    isOwn = updated.isOwn, timestamp = updated.timestamp,
                                    reactions = updated.reactions
                                ))
                        }
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onReactionReceived error: ${e.message}")
                    }
                }

                service.flushPendingReactions()

                scope.launch(Dispatchers.IO) {
                    val timer = ChatStorage.getDisappearTimer(context, userId, recipient)
                    withContext(Dispatchers.Main) { disappearTimerSecs = timer }
                }

                scope.launch(Dispatchers.IO) {
                    val secs = ChatStorage.getAutoDelete(context, userId, recipient)
                    withContext(Dispatchers.Main) { autoDeleteSecs = secs }
                }

                service.onMessageDeleted = { from, messageId ->
                    if (from == recipient) {
                        val idx = messages.indexOfFirst { it.id == messageId }
                        if (idx != -1) messages.removeAt(idx)
                    }
                }

                service.onDisappearTimerChanged = { from, seconds ->
                    if (from == recipient) disappearTimerSecs = seconds
                }

                // Disappearing-message countdown must start on RECEIPT for
                // incoming messages too, mirroring the send-side stamp —
                // otherwise a peer's message only ever disappears on THEIR
                // device. Was missing entirely for every message type before
                // this fix. Also schedules the actual removal (mirroring the
                // own-message send path's deliveryTimeoutJob-style scheduled
                // coroutine below) — merely stamping expiresAt isn't enough
                // on its own, since ChatStorage.loadMessages() only skips
                // already-expired rows on the *next* load; nothing else was
                // watching the in-memory `messages` list for one going stale
                // while the chat stays open.
                fun incomingExpiresAt() = if (disappearTimerSecs > 0L)
                    System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L

                fun scheduleIncomingExpiry(msgId: String, expiresAt: Long) {
                    if (expiresAt <= 0L) return
                    scope.launch {
                        delay(expiresAt - System.currentTimeMillis())
                        val idx = messages.indexOfFirst { it.id == msgId }
                        if (idx != -1) messages.removeAt(idx)
                        withContext(Dispatchers.IO) {
                            ChatStorage.deleteMessage(context, userId, recipient, msgId)
                        }
                    }
                }

                service.onMessageReceived = { from, _ ->
                    if (from == recipient) {
                        contactRecentlyActive = true
                        SoundManager.playMessageReceived()
                        val sender = from
                        scope.launch(Dispatchers.IO) {
                            val history = ChatStorage.loadMessages(context, userId, recipient)
                            val historyMap = history.associateBy { it.id }
                            withContext(Dispatchers.Main) {
                                allHistory.clear()
                                allHistory.addAll(history)
                                val displayStart = historyDisplayStart
                                messages.clear()
                                history.subList(displayStart, history.size).forEach { msg ->
                                    messages.add(storedToMessage(msg, historyMap))
                                    // Reload-based path (text messages), unlike
                                    // the media handlers below which add just
                                    // one message at a time — schedule expiry
                                    // for every not-yet-expired row on each
                                    // reload. Harmless if called again for an
                                    // already-scheduled message: the second
                                    // coroutine's removeAt/deleteMessage calls
                                    // are no-ops against an id that's already
                                    // gone.
                                    if (msg.expiresAt > 0L) scheduleIncomingExpiry(msg.id, msg.expiresAt)
                                }
                                if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
                                history.lastOrNull { !it.isOwn }?.let {
                                    messengerService?.sendRead(sender, it.id)
                                }
                                ChatStorage.markIncomingAsRead(context, userId, recipient)
                                MainActivity.chatListVersion.value++
                            }
                        }
                    }
                }

                service.onStatusChanged = { online -> isOnline = online }

                TorManager.onTorReady = { isTorConnected = true }
                TorManager.onTorError = { isTorConnected = false }

                service.onEditReceived = { messageId, newText ->
                    try {
                        val index = messages.indexOfFirst { it.id == messageId }
                        if (index != -1) {
                            messages[index] = messages[index].copy(text = newText, isEdited = true)
                            ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                ChatStorage.StoredMessage(
                                    id = messageId, text = newText,
                                    isOwn = messages[index].isOwn,
                                    reactions = messages[index].reactions, isEdited = true
                                ))
                        }
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onEditReceived error: ${e.message}")
                    }
                }

                service.onImageReceived = { imageId, bitmap ->
                    try {
                        SoundManager.playMessageReceived()
                        val imageFile = SecureFileStorage.blobFile(context.filesDir, imageId)
                        val stream = java.io.ByteArrayOutputStream()
                        stream.write(compressImageForSend(bitmap))
                        SecureFileStorage.write(context, imageFile, stream.toByteArray())
                        val expiresAt = incomingExpiresAt()
                        messages.add(Message(id = imageId, text = s.chatAttachPhoto, isOwn = false, imageBitmap = bitmap, expiresAt = expiresAt))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(id = imageId, text = s.chatAttachPhoto, isOwn = false, imagePath = imageFile.absolutePath, expiresAt = expiresAt))
                        scheduleIncomingExpiry(imageId, expiresAt)
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onImageReceived error: ${e.message}")
                    }
                }

                service.onVoiceReceived = { voiceId, voiceFile, duration ->
                    try {
                        SoundManager.playMessageReceived()
                        val expiresAt = incomingExpiresAt()
                        messages.add(Message(id = voiceId, text = "Голосовое сообщение", isOwn = false, voiceFile = voiceFile, voiceDuration = duration, expiresAt = expiresAt))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(id = voiceId, text = "Голосовое сообщение", isOwn = false, voicePath = voiceFile.absolutePath, voiceDuration = duration, expiresAt = expiresAt))
                        scheduleIncomingExpiry(voiceId, expiresAt)
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onVoiceReceived error: ${e.message}")
                    }
                }

                service.onFileReceived = { fileId, file, fileName ->
                    try {
                        SoundManager.playMessageReceived()
                        val expiresAt = incomingExpiresAt()
                        messages.add(Message(id = fileId, text = fileName, isOwn = false, expiresAt = expiresAt))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(id = fileId, text = fileName, isOwn = false, filePath = file.absolutePath, fileName = fileName, expiresAt = expiresAt))
                        scheduleIncomingExpiry(fileId, expiresAt)
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onFileReceived error: ${e.message}")
                    }
                }

                service.onVideoReceived = { videoId, file, duration ->
                    try {
                        SoundManager.playMessageReceived()
                        val expiresAt = incomingExpiresAt()
                        messages.add(Message(
                            id = videoId,
                            text = "Видеосообщение",
                            isOwn = false,
                            videoPath = file.absolutePath,
                            videoDuration = duration,
                            expiresAt = expiresAt
                        ))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(
                                id = videoId,
                                text = "Видеосообщение",
                                isOwn = false,
                                videoPath = file.absolutePath,
                                videoDuration = duration,
                                expiresAt = expiresAt
                            ))
                        scheduleIncomingExpiry(videoId, expiresAt)
                        scope.launch { listState.animateScrollToItem(messages.size - 1) }
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onVideoReceived error: ${e.message}")
                    }
                }
            }

            override fun onServiceDisconnected(name: ComponentName) {
                messengerService = null
            }
        }
    }

    LaunchedEffect(recipient) {
        val history = ChatStorage.loadMessages(context, userId, recipient)
        allHistory.clear()
        allHistory.addAll(history)
        val start = maxOf(0, history.size - CHAT_PAGE_SIZE)
        historyDisplayStart = start
        hasMoreHistory = start > 0
        val historyMap = history.associateBy { it.id }
        history.subList(start, history.size).forEach { msg ->
            messages.add(storedToMessage(msg, historyMap))
        }
        if (messages.isNotEmpty()) listState.scrollToItem(messages.size - 1)
        history.lastOrNull { !it.isOwn }?.let { messengerService?.sendRead(recipient, it.id) }
        ChatStorage.markIncomingAsRead(context, userId, recipient)
        MainActivity.chatListVersion.value++
        val draft = ChatStorage.loadDraft(context, userId, recipient)
        if (draft.isNotBlank()) inputText = draft
    }

    // Periodically remove messages older than autoDeleteSecs from THIS
    // device only (not synced to the peer) — mirrors Desktop's identical
    // sweep in ChatScreen.kt.
    LaunchedEffect(autoDeleteSecs) {
        if (autoDeleteSecs <= 0L) return@LaunchedEffect
        while (true) {
            val cutoff = System.currentTimeMillis() - autoDeleteSecs * 1000L
            val expired = messages.filter { it.timestamp < cutoff }
            expired.forEach { msg ->
                messages.removeAll { it.id == msg.id }
                withContext(Dispatchers.IO) {
                    ChatStorage.deleteMessage(context, userId, recipient, msg.id)
                }
            }
            delay(60_000L)
        }
    }

    // Polls rather than hooking onDeliveredReceived directly — that callback
    // only carries a messageId, not the sender, so there's no clean way to
    // confirm a given delivered event is actually for `recipient` without
    // extra plumbing. Polling also covers the "ages back out to offline"
    // side, which no single event captures.
    LaunchedEffect(recipient) {
        while (true) {
            delay(30_000L)
            contactRecentlyActive = ContactHealthManager.isRecentlyActive(context, recipient)
        }
    }

    LaunchedEffect(Unit) {
        context.bindService(Intent(context, MessengerService::class.java), connection, Context.BIND_AUTO_CREATE)
    }

    LaunchedEffect(isTyping) {
        if (isTyping) {
            while (true) {
                delay(400); typingDots = if (typingDots >= 3) 1 else typingDots + 1
            }
        }
    }

    LaunchedEffect(Unit) {
        MainActivity.selectedPhotoUri.collect { uri: android.net.Uri? ->
            uri ?: return@collect
            MainActivity.selectedPhotoUri.value = null

            val pickedMime = context.contentResolver.getType(uri) ?: ""
            if (pickedMime.startsWith("video/")) {
                MainActivity.selectedFileUri.value = uri
                return@collect
            }
            try {
                val bitmap = android.provider.MediaStore.Images.Media.getBitmap(context.contentResolver, uri)

                if (bitmap.byteCount > 100 * 1024 * 1024) {
                    android.widget.Toast.makeText(context, s.chatPhotoTooBig, android.widget.Toast.LENGTH_SHORT).show()
                    bitmap.recycle()
                    return@collect
                }
                val chunks = bitmapToChunks(bitmap)
                if (!isOnline) {
                    android.widget.Toast.makeText(context, s.chatMediaOffline, android.widget.Toast.LENGTH_SHORT).show()
                    return@collect
                }
                messengerService?.sendImage(recipient, chunks)
                val imageFile = SecureFileStorage.blobFile(context.filesDir, UUID.randomUUID().toString())
                SecureFileStorage.write(context, imageFile, compressImageForSend(bitmap))
                val msgId = UUID.randomUUID().toString()
                messages.add(Message(id = msgId, text = s.chatAttachPhoto, isOwn = true, imageBitmap = bitmap))
                ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                    ChatStorage.StoredMessage(id = msgId, text = s.chatAttachPhoto, isOwn = true, imagePath = imageFile.absolutePath))
                scope.launch { listState.animateScrollToItem(messages.size - 1) }
            } catch (e: Exception) {
                android.util.Log.e("ChatScreen", "Фото error: ${e.message}")
            }
        }
    }

    LaunchedEffect(Unit) {
        MainActivity.selectedFileUri.collect { uri: android.net.Uri? ->
            uri ?: return@collect
            MainActivity.selectedFileUri.value = null
            try {
                val cursor = context.contentResolver.query(uri, null, null, null, null)
                val fileName = cursor?.use {
                    if (it.moveToFirst()) {
                        val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        if (nameIndex >= 0) it.getString(nameIndex) else "file"
                    } else "file"
                } ?: "file"

                val mimeType = context.contentResolver.getType(uri) ?: "*/*"

                val rawBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                val bytes = if (rawBytes != null && mimeType.startsWith("image/")) {
                    stripExif(context, rawBytes)
                } else rawBytes

                if (bytes != null && bytes.isNotEmpty()) {
                    if (bytes.size > 20 * 1024 * 1024) {
                        android.widget.Toast.makeText(
                            context,
                            s.chatFileTooBig,
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                        return@collect
                    }

                    if (!isOnline) {
                        android.widget.Toast.makeText(context, s.chatMediaOffline, android.widget.Toast.LENGTH_SHORT).show()
                        return@collect
                    }

                    android.widget.Toast.makeText(
                        context,
                        s.chatFileSending(fileName, bytes.size / 1024),
                        android.widget.Toast.LENGTH_SHORT
                    ).show()

                    val chunks = fileToChunks(bytes)
                    val fileId = UUID.randomUUID().toString()
                    messengerService?.sendFile(recipient, fileName, chunks, fileId)

                    val file = File(context.cacheDir, "blobs/$fileId.dat").apply {
                        parentFile?.mkdirs()
                        writeBytes(bytes)
                    }

                    val displayText = fileName
                    messages.add(Message(
                        id = fileId,
                        text = displayText,
                        isOwn = true,
                        fileName = fileName,
                        filePath = file.absolutePath
                    ))

                    ChatStorage.saveOrUpdateMessage(
                        context, userId, recipient,
                        ChatStorage.StoredMessage(
                            id = fileId,
                            text = displayText,
                            isOwn = true,
                            filePath = file.absolutePath,
                            fileName = fileName
                        )
                    )

                    scope.launch { listState.animateScrollToItem(messages.size - 1) }
                }
            } catch (e: Exception) {
                android.util.Log.e("ChatScreen", "Ошибка обработки файла: ${e.message}")
                android.widget.Toast.makeText(
                    context,
                    s.error(e.message ?: ""),
                    android.widget.Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    DisposableEffect(recipient) {
        onDispose {
            if (!isEditMode) ChatStorage.saveDraft(context, userId, recipient, inputText)
            messengerService?.onVoiceReceived = null
            messengerService?.onKeyChanged = null
            messengerService?.onContactRevoked = null
            messengerService?.onContactSendUnblocked = null
            messengerService?.onReadReceived = null
            messengerService?.onDeliveredReceived = null
            messengerService?.onMessageReceived = null
            messengerService?.onStatusChanged = null
            messengerService?.onTypingReceived = null
            messengerService?.onEditReceived = null
            messengerService?.onImageReceived = null
            messengerService?.onReactionReceived = null
            messengerService?.onVideoReceived = null
            try { context.unbindService(connection) } catch (e: Exception) {}
        }
    }

    Column(modifier = Modifier.fillMaxSize().navigationBarsPadding().imePadding()) {

        TopAppBar(
            title = {
                if (searchMode) {
                    androidx.compose.foundation.text.BasicTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.fillMaxWidth().padding(end = 8.dp),
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 18.sp, color = c.textPrimary),
                        cursorBrush = androidx.compose.ui.graphics.SolidColor(c.accent),
                        decorationBox = { inner ->
                            if (searchQuery.isEmpty()) Text(s.chatSearchPlaceholder, fontSize = 18.sp, color = c.textPrimary.copy(alpha = 0.53f), fontFamily = JetBrainsMono)
                            inner()
                        }
                    )
                } else {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.clickable(onClick = onOpenContactInfo)
                    ) {
                        val recipientName = ChatStorage.getContactName(context, recipient)
                        val avatarColor = remember(recipientName) {
                            listOf(c.primaryBlue, Color(0xFFE74C3C), Color(0xFF27AE60),
                                Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
                            )[recipientName.hashCode().absoluteValue % 6]
                        }
                        val avatarBitmap = AvatarStore.avatars[recipient]
                        if (avatarBitmap != null) {
                            Image(
                                bitmap = avatarBitmap.asImageBitmap(),
                                contentDescription = recipientName,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.size(40.dp).clip(CircleShape)
                            )
                        } else {
                            Surface(shape = CircleShape, color = avatarColor, modifier = Modifier.size(40.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(
                                        text = if (recipientName.isNotEmpty()) recipientName.first().uppercaseChar().toString() else "?",
                                        fontSize = 20.sp, fontWeight = FontWeight.Bold, color = Color.White
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            if (showKeyWarning) {
                                AlertDialog(
                                    onDismissRequest = {},
                                    title = { Text(s.chatKeyWarningTitle) },
                                    text = {
                                        Text(s.chatKeyWarningText, color = Color.Red)
                                    },
                                    confirmButton = {
                                        TextButton(onClick = { KeyHistoryManager.markAsVerified(context, recipient); showKeyWarning = false }) {
                                            Text(s.chatKeyWarningConfirm)
                                        }
                                    },
                                    dismissButton = {
                                        TextButton(onClick = { onBack() }) { Text(s.chatKeyWarningLeave) }
                                    }
                                )
                            }
                            if (showRevokedWarning) {
                                AlertDialog(
                                    onDismissRequest = {},
                                    title = { Text(s.chatRevokedWarningTitle) },
                                    text = {
                                        Text(s.chatRevokedWarningText, color = Color.Red)
                                    },
                                    confirmButton = {
                                        TextButton(onClick = { showRevokedWarning = false }) {
                                            Text(s.chatRevokedWarningConfirm)
                                        }
                                    },
                                    dismissButton = {
                                        TextButton(onClick = { onBack() }) { Text(s.chatKeyWarningLeave) }
                                    }
                                )
                            }
                            if (showSendBlockedWarning) {
                                AlertDialog(
                                    onDismissRequest = { showSendBlockedWarning = false },
                                    title = { Text(s.chatSendBlockedTitle) },
                                    text = { Text(s.chatSendBlockedText) },
                                    confirmButton = {
                                        TextButton(onClick = { showSendBlockedWarning = false }) {
                                            Text(s.chatSendBlockedConfirm)
                                        }
                                    }
                                )
                            }
                            Text(recipientName, fontWeight = FontWeight.SemiBold, fontSize = 20.sp, color = c.textPrimary, fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                val statusKey = when {
                                    isTyping -> "typing"
                                    contactRecentlyActive -> "online"
                                    else     -> "offline"
                                }
                                AnimatedContent(
                                    targetState = statusKey,
                                    transitionSpec = {
                                        (fadeIn(tween(220)) + slideInVertically(tween(220)) { -it }) togetherWith
                                        (fadeOut(tween(160)) + slideOutVertically(tween(160)) { it })
                                    },
                                    label = "status"
                                ) { key ->
                                    when (key) {
                                        "typing" -> Row(
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                s.chatTyping.trimEnd('.', '…', ' '),
                                                fontSize = 16.sp,
                                                color = c.accent,
                                                fontFamily = JetBrainsMono
                                            )
                                            Spacer(Modifier.width(5.dp))
                                            TypingDotsIndicator(color = c.accent)
                                        }
                                        else -> Text(
                                            text = if (key == "online") s.chatOnline else s.chatOffline,
                                            fontSize = 15.sp,
                                            color = if (key == "online") c.accent else c.textPrimary.copy(alpha = 0.5f)
                                        )
                                    }
                                }
                                if (disappearTimerSecs > 0L) {
                                    val label = when (disappearTimerSecs) {
                                        3600L -> s.chatDisappear1hShort
                                        86400L -> s.chatDisappear24hShort
                                        604800L -> s.chatDisappear7dShort
                                        else -> " · ${disappearTimerSecs / 3600}ч"
                                    }
                                    Text(label, fontSize = 14.sp, color = c.accent)
                                }
                            }
                        }
                    }
                }
            },
            navigationIcon = {
                IconButton(onClick = {
                    if (searchMode) { searchMode = false; searchQuery = "" } else onBack()
                }) {
                    Icon(painterResource(R.drawable.ic_back_arrow), contentDescription = s.back)
                }
            },
            actions = {
                // Search and the disappearing-messages timer moved into
                // ContactInfoScreen (reached via the header tap above) —
                // only the call buttons stay up here now, per explicit
                // request to keep the chat top bar down to just those two.
                IconButton(onClick = {
                    pendingCallIsVideo = false
                    callPermissionLauncher.launch(arrayOf(android.Manifest.permission.RECORD_AUDIO))
                }) {
                    Icon(
                        painterResource(R.drawable.ic_sound_call),
                        contentDescription = s.chatAudioCall,
                        tint = c.textPrimary,
                        modifier = Modifier.size(28.dp)
                    )
                }
                IconButton(onClick = {
                    pendingCallIsVideo = true
                    callPermissionLauncher.launch(arrayOf(
                        android.Manifest.permission.RECORD_AUDIO,
                        android.Manifest.permission.CAMERA
                    ))
                }) {
                    Icon(
                        painterResource(R.drawable.ic_video_call),
                        contentDescription = s.chatVideoCall,
                        tint = c.textPrimary,
                        modifier = Modifier.size(28.dp)
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
        )

        if (!isTorConnected && !torWarningDismissed && UserStorage.isTorEnabled(context)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF3D1A00))
                    .padding(start = 14.dp, top = 8.dp, bottom = 8.dp, end = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(painterResource(R.drawable.ic_warning), contentDescription = null,
                    tint = Color(0xFFFFAA44), modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = s.chatDirectConnection,
                    fontSize = 14.sp,
                    color = Color(0xFFFFAA44),
                    fontFamily = JetBrainsMono,
                    modifier = Modifier.weight(1f)
                )
                IconButton(
                    onClick = {
                        torWarningDismissed = true
                        context.getSharedPreferences("beacon_prefs", Context.MODE_PRIVATE)
                            .edit().putBoolean("tor_warning_dismissed", true).apply()
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = null,
                        tint = Color(0xFFFFAA44),
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }

        val displayedMessages = if (searchMode && searchQuery.isNotBlank())
            messages.filter { it.text.contains(searchQuery, ignoreCase = true) }
        else messages

        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize()
                .background(bgGradient)
                .padding(horizontal = 8.dp),
            state = listState
        ) {
            if (hasMoreHistory || isLoadingMoreHistory) {
                item(key = "load_more_header") {
                    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        if (isLoadingMoreHistory) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp).padding(vertical = 4.dp),
                                color = c.accent,
                                strokeWidth = 2.dp
                            )
                        } else {
                            TextButton(onClick = { loadMoreHistory() }) {
                                Text(s.chatLoadEarlier, color = c.accent, fontFamily = JetBrainsMono, fontSize = 15.sp)
                            }
                        }
                    }
                }
            }
            items(displayedMessages, key = { it.id }) { msg ->
                if (msg.replyTo == null) {
                    val storedExpiry = remember(msg.id) {
                        if (disappearTimerSecs > 0L) System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L
                    }
                }
                Box(
                    modifier = Modifier.animateItem(
                        fadeInSpec  = androidx.compose.animation.core.tween(180),
                        fadeOutSpec = androidx.compose.animation.core.tween(120),
                        placementSpec = androidx.compose.animation.core.spring(
                            stiffness = androidx.compose.animation.core.Spring.StiffnessMediumLow,
                            dampingRatio = androidx.compose.animation.core.Spring.DampingRatioLowBouncy
                        )
                    )
                ) {
                    MessageBubble(
                        msg = msg,
                        contactId = recipient,
                        searchQuery = if (searchMode) searchQuery else "",
                        onLongClick = { message -> contextMenuMessage = message },
                        onSwipeToReply = { message -> replyToMessage = message },
                        playingVoiceId = playingVoiceId,
                        onVoicePlay = { id -> playingVoiceId = id },
                        onVoiceStop = { playingVoiceId = null },
                        voicePlaybackMs = voicePlaybackMs,
                        voiceSpeed = voiceSpeed,
                        onVoiceSeek = { ms -> AudioHelper.seekTo(ms); voicePlaybackMs = ms },
                        onVoiceSpeedToggle = {
                            voiceSpeed = when (voiceSpeed) {
                                1f -> 1.5f
                                1.5f -> 2f
                                else -> 1f
                            }
                            if (playingVoiceId != null) AudioHelper.setSpeed(voiceSpeed)
                        },
                        playingVideoId = playingVideoId,
                        onVideoPlay = { id -> playingVideoId = id },
                        onVideoStop = { playingVideoId = null },
                        onImageClick = { bmp -> fullscreenImageBitmap = bmp }
                    )
                }
            }
        }
        val showScrollFab by remember { derivedStateOf { listState.canScrollForward } }
        Box(modifier = Modifier.align(Alignment.BottomEnd).padding(end = 12.dp, bottom = 8.dp)) {
            androidx.compose.animation.AnimatedVisibility(
                visible = showScrollFab,
                enter = fadeIn() + scaleIn(),
                exit = fadeOut() + scaleOut()
            ) {
                FloatingActionButton(
                    onClick = { scope.launch { listState.animateScrollToItem(messages.size - 1) } },
                    containerColor = c.primaryBlue,
                    contentColor = if (c.isDark) Color.White else c.textPrimary,
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(painterResource(R.drawable.ic_arrow_down), contentDescription = null, modifier = Modifier.size(22.dp))
                }
            }
        }
        } // end Box

        if (contextMenuMessage != null) {
            val ctxMsg = contextMenuMessage!!
            AlertDialog(
                onDismissRequest = { contextMenuMessage = null },
                containerColor = c.dialog,
                title = null,
                text = {
                    Column {
                        TextButton(onClick = {
                            replyToMessage = ctxMsg
                            contextMenuMessage = null
                        }) { Text(s.chatContextReply, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        if (!ctxMsg.isSystem) {
                            TextButton(onClick = {
                                showForwardDialog = ctxMsg
                                contextMenuMessage = null
                            }) { Text("Переслать", color = Color(0xFF90CAF9), fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                        if (ctxMsg.imageBitmap != null) {
                            TextButton(onClick = {
                                val bmp = ctxMsg.imageBitmap
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val cv = ContentValues().apply {
                                            put(MediaStore.Images.Media.DISPLAY_NAME, "beacon_${System.currentTimeMillis()}.jpg")
                                            put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
                                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                                put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/Subrosa")
                                            }
                                        }
                                        val uri = context.contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, cv)
                                        uri?.let { context.contentResolver.openOutputStream(it)?.use { os -> bmp.compress(Bitmap.CompressFormat.JPEG, 95, os) } }
                                        withContext(Dispatchers.Main) {
                                            android.widget.Toast.makeText(context, s.chatPhotoSaved, android.widget.Toast.LENGTH_SHORT).show()
                                        }
                                    } catch (_: Exception) {}
                                }
                                contextMenuMessage = null
                            }) { Text(s.chatSavePhoto, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                        if (ctxMsg.voiceFile == null && ctxMsg.imageBitmap == null &&
                            ctxMsg.text.isNotEmpty() && !ctxMsg.isSystem) {
                            TextButton(onClick = {
                                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                cm.setPrimaryClip(ClipData.newPlainText("message", ctxMsg.text))
                                contextMenuMessage = null
                                scope.launch {
                                    delay(60_000L)
                                    @Suppress("DEPRECATION")
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                        cm.clearPrimaryClip()
                                    } else {
                                        cm.setPrimaryClip(ClipData.newPlainText("", ""))
                                    }
                                }
                            }) { Text(s.chatContextCopy, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                        if (!ctxMsg.isOwn) {
                            TextButton(onClick = {
                                showReactionPicker = ctxMsg
                                contextMenuMessage = null
                            }) { Text(s.chatContextReaction, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                        if (ctxMsg.isOwn && ctxMsg.text.isNotEmpty() && ctxMsg.voiceFile == null) {
                            TextButton(onClick = {
                                isEditMode = true
                                editingMessageId = ctxMsg.id
                                inputText = ctxMsg.text
                                contextMenuMessage = null
                            }) { Text(s.chatContextEdit, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                        if (ctxMsg.isOwn && ctxMsg.isFailed && ctxMsg.text.isNotEmpty()) {
                            TextButton(onClick = {
                                val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                                if (idx != -1) messages.removeAt(idx)
                                val replyId = ctxMsg.replyTo?.id
                                scope.launch(Dispatchers.IO) {
                                    ChatStorage.deleteMessage(context, userId, recipient, ctxMsg.id)
                                }
                                val msgId = messengerService?.send(recipient, ctxMsg.text, replyToId = replyId)
                                    ?: UUID.randomUUID().toString()
                                ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                    ChatStorage.StoredMessage(id = msgId, text = ctxMsg.text, isOwn = true, replyToId = replyId))
                                messages.add(Message(id = msgId, text = ctxMsg.text, isOwn = true, replyTo = ctxMsg.replyTo, isPending = true))
                                scope.launch { listState.animateScrollToItem(messages.size - 1) }
                                val deliveryTimeoutJob = scope.launch {
                                    delay(60_000L)
                                    val idx2 = messages.indexOfFirst { it.id == msgId }
                                    if (idx2 != -1) messages[idx2] = messages[idx2].copy(isPending = false, isFailed = true)
                                    withContext(Dispatchers.IO) {
                                        ChatStorage.markFailed(context, userId, recipient, msgId)
                                    }
                                    pendingDeliveryJobs.remove(msgId)
                                }
                                pendingDeliveryJobs[msgId] = deliveryTimeoutJob
                                contextMenuMessage = null
                            }) { Text(s.chatContextResend, color = c.accent, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                        TextButton(onClick = {
                            val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                            if (idx != -1) messages.removeAt(idx)
                            scope.launch(Dispatchers.IO) {
                                ChatStorage.deleteMessage(context, userId, recipient, ctxMsg.id)
                            }
                            contextMenuMessage = null
                        }) { Text(s.chatContextDeleteOwn, color = Color(0xFFFF6B6B), fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        if (ctxMsg.isOwn) {
                            TextButton(onClick = {
                                val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                                if (idx != -1) messages.removeAt(idx)
                                scope.launch(Dispatchers.IO) {
                                    ChatStorage.deleteMessage(context, userId, recipient, ctxMsg.id)
                                }
                                messengerService?.sendDeleteMessage(recipient, ctxMsg.id)
                                contextMenuMessage = null
                            }) { Text(s.chatContextDeleteAll, color = c.error, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                    }
                },
                confirmButton = {}
            )
        }

        if (fullscreenImageBitmap != null) {
            Dialog(
                onDismissRequest = { fullscreenImageBitmap = null },
                properties = DialogProperties(usePlatformDefaultWidth = false)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black)
                        .clickable { fullscreenImageBitmap = null },
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        bitmap = fullscreenImageBitmap!!.asImageBitmap(),
                        contentDescription = null,
                        contentScale = ContentScale.Fit,
                        modifier = Modifier.fillMaxSize()
                    )
                }
            }
        }

        if (showReactionPicker != null) {
            AlertDialog(
                onDismissRequest = { showReactionPicker = null },
                containerColor = c.dialog,
                title = { Text(s.chatPickReaction, color = c.textPrimary, fontFamily = JetBrainsMono) },
                text = {
                    Row(horizontalArrangement = Arrangement.SpaceEvenly, modifier = Modifier.fillMaxWidth()) {
                        listOf("❤️", "👍", "😂", "😮", "😢", "🔥").forEach { emoji ->
                            Text(text = emoji, fontSize = 34.sp,
                                modifier = Modifier.clickable {
                                    val msg = showReactionPicker!!
                                    val index = messages.indexOf(msg)
                                    if (index != -1) {
                                        val updated = msg.copy(reactions = msg.reactions.toMutableMap().also { it[username] = emoji })
                                        messages[index] = updated
                                        ChatStorage.saveOrUpdateMessage(context, UserStorage.getUserId(context), recipient,
                                            ChatStorage.StoredMessage(id = updated.id, text = updated.text, isOwn = updated.isOwn, timestamp = updated.timestamp, reactions = updated.reactions))
                                        messengerService?.sendReaction(recipient, updated.id, emoji)
                                    }
                                    showReactionPicker = null
                                })
                        }
                    }
                },
                confirmButton = {}
            )
        }


        Box {
        androidx.compose.animation.AnimatedVisibility(
            visible = isTyping,
            enter = fadeIn() + expandVertically(expandFrom = Alignment.Top),
            exit  = fadeOut() + shrinkVertically(shrinkTowards = Alignment.Top)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.topBar)
                    .padding(horizontal = 16.dp, vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${ChatStorage.getContactName(context, recipient)} ${s.chatTyping}${".".repeat(typingDots)}",
                    fontSize = 15.sp,
                    color = c.textPrimary.copy(alpha = 0.6f),
                    fontFamily = JetBrainsMono
                )
            }
        }
        } // end typing Box

        if (replyToMessage != null) {
            Row(
                modifier = Modifier.fillMaxWidth()
                    .background(c.topBar)
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_reply),
                    contentDescription = null,
                    tint = c.accent,
                    modifier = Modifier.size(18.dp).padding(end = 4.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(s.chatReplyPreview, fontSize = 13.sp, color = c.accent, fontFamily = JetBrainsMono)
                    Text(replyToMessage!!.text.take(60), fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.7f), maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = JetBrainsMono)
                }
                IconButton(onClick = { replyToMessage = null }) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = null,
                        tint = c.textPrimary.copy(alpha = 0.5f),
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }

        if (isEditMode) {
            Row(modifier = Modifier.fillMaxWidth().background(c.topBar).padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(s.chatEditing, fontSize = 14.sp, color = c.primaryBlue, modifier = Modifier.weight(1f), fontFamily = JetBrainsMono)
                TextButton(onClick = { isEditMode = false; editingMessageId = null; inputText = "" }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.5f), fontSize = 14.sp, fontFamily = JetBrainsMono)
                }
            }
        }

        if (showAttachMenu) {
            AlertDialog(
                onDismissRequest = { showAttachMenu = false },
                title = { Text(s.chatAttach, color = c.textPrimary, fontSize = 22.sp, fontFamily = JetBrainsMono) },
                text = {
                    Column {
                        TextButton(onClick = {
                            showAttachMenu = false
                            try {
                                (context as? MainActivity)?.startActivityForResult(
                                    Intent(Intent.ACTION_GET_CONTENT).apply {
                                        type = "*/*"
                                        putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("image/*", "video/*"))
                                        addCategory(Intent.CATEGORY_OPENABLE)
                                    },
                                    MainActivity.PICK_IMAGE_REQUEST
                                )
                            } catch (e: Exception) {}
                        }) { Text(s.chatAttachMedia, color = c.textPrimary, fontSize = 20.sp, fontFamily = JetBrainsMono) }

                        TextButton(onClick = {
                            showAttachMenu = false
                            try {
                                (context as? MainActivity)?.startActivityForResult(
                                    Intent(Intent.ACTION_GET_CONTENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) },
                                    MainActivity.PICK_FILE_REQUEST
                                )
                            } catch (e: Exception) {}
                        }) { Text(s.chatAttachFile, color = c.textPrimary, fontSize = 20.sp, fontFamily = JetBrainsMono) }

                        TextButton(onClick = {
                            showAttachMenu = false
                            showGeoConfirm = true
                        }) { Text(s.chatGeo, color = c.textPrimary, fontSize = 20.sp, fontFamily = JetBrainsMono) }
                    }
                },
                confirmButton = {},
                containerColor = c.dialog
            )
        }

        if (showGeoConfirm) {
            AlertDialog(
                onDismissRequest = { showGeoConfirm = false },
                title = { Text(s.chatGeoConfirmTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
                text = { Text(s.chatGeoConfirmText, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 16.sp) },
                confirmButton = {
                    TextButton(onClick = {
                        showGeoConfirm = false
                        val permGranted = context.checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) ==
                            android.content.pm.PackageManager.PERMISSION_GRANTED
                        if (permGranted) sendGeo()
                        else geoPermLauncher.launch(android.Manifest.permission.ACCESS_FINE_LOCATION)
                    }) { Text(s.chatGeo, color = c.accent, fontFamily = JetBrainsMono) }
                },
                dismissButton = {
                    TextButton(onClick = { showGeoConfirm = false }) { Text(s.cancel, color = c.textPrimary, fontFamily = JetBrainsMono) }
                },
                containerColor = c.dialog
            )
        }

        // S6-57, STEP 9 (external review 2026-09-06) -- neither client
        // previously capped recording duration at all; the server now
        // enforces MAX_VOICE_DURATION_SECONDS as a hard protocol bound (see
        // server.py's own comment for the byte-math derivation), so a user
        // must never be able to create a voice message the server will
        // later reject. Auto-stops and sends exactly at the cap rather than
        // silently truncating or discarding what was already recorded.
        fun finishRecordingAndSend() {
            recordingFile?.let { file ->
                AudioHelper.stopRecording()
                // Found live: this used to be (file.length() / 1000).toInt() --
                // assumed 1000 bytes/sec, but the actual recording bitrate is
                // roughly double that, so a real 30s recording reported as ~59s.
                // recordingSeconds already tracks real elapsed time (it drives
                // the live "0:30" counter shown above during recording) -- just
                // wasn't being used here at all.
                val duration = recordingSeconds
                val voiceId = UUID.randomUUID().toString()
                val base64 = AudioHelper.encodeToBase64(file)
                messengerService?.sendVoice(recipient, base64, voiceId, duration)
                val encFile = SecureFileStorage.blobFile(context.filesDir, voiceId)
                SecureFileStorage.write(context, encFile, file.readBytes())
                file.delete()
                messages.add(Message(id = voiceId, text = "Голосовое сообщение", isOwn = true, voiceFile = encFile, voiceDuration = duration))
                ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                    ChatStorage.StoredMessage(id = voiceId, text = "Голосовое сообщение", isOwn = true, voicePath = encFile.absolutePath, voiceDuration = duration))
                isRecording = false
                recordingFile = null
            }
        }

        LaunchedEffect(isRecording) {
            if (isRecording) {
                recordingSeconds = 0
                while (isRecording) {
                    delay(1000L)
                    recordingSeconds++
                    if (recordingSeconds >= MAX_VOICE_RECORDING_SECONDS) {
                        finishRecordingAndSend()
                    }
                }
            } else {
                recordingSeconds = 0
            }
        }

        HorizontalDivider(color = c.textPrimary.copy(alpha = 0.06f), thickness = 1.dp)
        AnimatedContent(
            targetState = isRecording,
            transitionSpec = {
                (fadeIn(tween(180)) + scaleIn(tween(180), initialScale = 0.96f)) togetherWith
                (fadeOut(tween(140)) + scaleOut(tween(140), targetScale = 0.96f))
            },
            label = "input_bar_mode"
        ) { recording ->
            if (recording) {

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.topBar)
                        .padding(horizontal = 10.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {

                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .clip(CircleShape)
                            .background(Color(0x28FF4444))
                            .clickable {
                                AudioHelper.stopRecording()
                                recordingFile?.delete()
                                recordingFile = null
                                isRecording = false
                            },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_close),
                            contentDescription = "Отменить",
                            tint = Color(0xFFFF5555),
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    Row(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(28.dp))
                            .background(Color(0x1AFFFFFF))
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        val recDotAlpha = remember { androidx.compose.animation.core.Animatable(1f) }
                        LaunchedEffect(Unit) {
                            while (true) {
                                recDotAlpha.animateTo(0.2f, tween(550))
                                recDotAlpha.animateTo(1f, tween(550))
                            }
                        }
                        Box(
                            modifier = Modifier
                                .size(9.dp)
                                .clip(CircleShape)
                                .background(Color(0xFFFF4444).copy(alpha = recDotAlpha.value))
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = String.format("%d:%02d", recordingSeconds / 60, recordingSeconds % 60),
                            color = c.textPrimary,
                            fontSize = 17.sp,
                            fontFamily = JetBrainsMono,
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        WaveformMicButton(isRecording = true, onClick = {}, size = 38)
                    }

                    PortholeSendButton(
                        enabled = true,
                        onClick = { finishRecordingAndSend() },
                        size = 44
                    )
                }
            } else {

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.topBar)
                        .padding(horizontal = 8.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.Bottom,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {

                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .clip(CircleShape)
                            .background(Color(0x18FFFFFF))
                            .clickable(enabled = channelReady) { showAttachMenu = true },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_attach),
                            contentDescription = null,
                            tint = c.textPrimary.copy(alpha = if (channelReady) 0.85f else 0.3f),
                            modifier = Modifier.size(22.dp)
                        )
                    }

                    val inputInteraction = remember { MutableInteractionSource() }
                    val isInputFocused by inputInteraction.collectIsFocusedAsState()
                    val inputBorderColor by animateColorAsState(
                        targetValue = if (isInputFocused) c.accent.copy(alpha = 0.6f) else Color(0x28B0C4DE),
                        animationSpec = tween(250),
                        label = "inputBorder"
                    )
                    Box(modifier = Modifier.weight(1f)) {
                        androidx.compose.foundation.Canvas(modifier = Modifier.matchParentSize()) {
                            drawRoundRect(
                                color = Color(0x22FFFFFF),
                                cornerRadius = androidx.compose.ui.geometry.CornerRadius(32.dp.toPx())
                            )
                            drawRoundRect(
                                color = inputBorderColor,
                                cornerRadius = androidx.compose.ui.geometry.CornerRadius(32.dp.toPx()),
                                style = androidx.compose.ui.graphics.drawscope.Stroke(width = 1.5.dp.toPx())
                            )
                        }
                        BasicTextField(
                            value = inputText,
                            onValueChange = {
                                inputText = it
                                if (it.isNotEmpty() && !isEditMode) messengerService?.sendTyping(recipient)
                            },
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                            maxLines = 4,
                            readOnly = !channelReady,
                            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 17.sp, color = c.textPrimary),
                            cursorBrush = androidx.compose.ui.graphics.SolidColor(c.accent),
                            interactionSource = inputInteraction,
                            decorationBox = { innerTextField ->
                                if (inputText.isEmpty()) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        if (!channelReady) {
                                            CircularProgressIndicator(
                                                modifier = Modifier.size(13.dp),
                                                strokeWidth = 1.5.dp,
                                                color = c.accent.copy(alpha = 0.7f)
                                            )
                                            Spacer(modifier = Modifier.width(8.dp))
                                        }
                                        Text(
                                            when {
                                                !channelReady -> s.chatEstablishingChannel
                                                isEditMode -> s.chatEditHint
                                                else -> s.chatInputHint
                                            },
                                            fontSize = 17.sp,
                                            color = c.textPrimary.copy(alpha = 0.4f),
                                            fontFamily = JetBrainsMono
                                        )
                                    }
                                }
                                innerTextField()
                            }
                        )
                    }

                    if ((inputText.isNotEmpty() || isEditMode) && channelReady) {
                        PortholeSendButton(
                            enabled = inputText.isNotEmpty(),
                            onClick = {
                                val text = inputText.trim()
                                if (text.isNotEmpty()) {
                                    SoundManager.playMessageSent()
                                    inputText = ""
                                    if (isEditMode && editingMessageId != null) {
                                        val editId = editingMessageId!!
                                        val index = messages.indexOfFirst { it.id == editId }
                                        if (index != -1) {
                                            messages[index] = messages[index].copy(text = text, isEdited = true)
                                            ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                                ChatStorage.StoredMessage(id = editId, text = text, isOwn = true, reactions = messages[index].reactions, isEdited = true))
                                        }
                                        messengerService?.sendEdit(recipient, editId, text)
                                        isEditMode = false
                                        editingMessageId = null
                                    } else if (ContactHealthManager.isSendBlocked(context, recipient)) {
                                        inputText = text
                                        showSendBlockedWarning = true
                                    } else {
                                        val replyId = replyToMessage?.id
                                        val replyMsg = replyToMessage
                                        replyToMessage = null
                                        val msgId = messengerService?.send(recipient, text, replyToId = replyId)
                                            ?: UUID.randomUUID().toString()
                                        val expiresAt = if (disappearTimerSecs > 0L)
                                            System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L
                                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                            ChatStorage.StoredMessage(id = msgId, text = text, isOwn = true,
                                                replyToId = replyId, expiresAt = expiresAt))
                                        messages.add(Message(id = msgId, text = text, isOwn = true, replyTo = replyMsg, isPending = true))
                                        scope.launch { listState.animateScrollToItem(messages.size - 1) }
                                        val deliveryTimeoutJob = scope.launch {
                                            delay(60_000L)
                                            val idx = messages.indexOfFirst { it.id == msgId }
                                            if (idx != -1) messages[idx] = messages[idx].copy(isPending = false, isFailed = true)
                                            withContext(Dispatchers.IO) {
                                                ChatStorage.markFailed(context, userId, recipient, msgId)
                                            }
                                            pendingDeliveryJobs.remove(msgId)
                                        }
                                        pendingDeliveryJobs[msgId] = deliveryTimeoutJob
                                        if (expiresAt > 0L) {
                                            scope.launch {
                                                delay(disappearTimerSecs * 1000L)
                                                val idx = messages.indexOfFirst { it.id == msgId }
                                                if (idx != -1) messages.removeAt(idx)
                                                withContext(Dispatchers.IO) {
                                                    ChatStorage.deleteMessage(context, userId, recipient, msgId)
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            size = 44
                        )
                    } else {
                        CombinedMediaButton(
                            isVideoMode = isVideoMode,
                            onToggleMode = { isVideoMode = !isVideoMode },
                            onStartVoice = {
                                if (!channelReady) return@CombinedMediaButton
                                when {
                                    context.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) ==
                                        android.content.pm.PackageManager.PERMISSION_GRANTED -> {
                                        recordingFile = AudioHelper.startRecording(context)
                                        isRecording = true
                                    }
                                    else -> audioPermissionLauncher.launch(android.Manifest.permission.RECORD_AUDIO)
                                }
                            },
                            onStartVideo = { if (channelReady) showVideoCircleRecorder = true },
                            size = 44
                        )
                    }
                }
            }
        }

        if (showVerifyDialog) {
            val recipientKey = ChatStorage.getContactPublicKey(context, recipient)
            val fingerprint = if (recipientKey != null) {
                try {
                    val keyBytes = android.util.Base64.decode(recipientKey, android.util.Base64.DEFAULT)
                    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(keyBytes)
                    digest.take(5).joinToString("  ") { EMOJI_SET[it.toInt().and(0xFF) % EMOJI_SET.size] }
                } catch (e: Exception) { s.chatVerifyKeyError }
            } else s.chatVerifyUnknown

            AlertDialog(
                onDismissRequest = { showVerifyDialog = false },
                title = { Text(s.chatVerifyTitle, color = c.textPrimary) },
                text = {
                    Column {
                        Text(s.chatVerifyFingerprintLabel, fontWeight = FontWeight.Bold, color = c.textPrimary)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(fingerprint, fontSize = 30.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(s.chatVerifyHint, fontSize = 16.sp, color = c.textPrimary)
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showVerifyDialog = false }) { Text(s.close, color = c.textPrimary) }
                },
                containerColor = c.dialog
            )
        }

        if (showVideoCircleRecorder) {
            VideoCircleRecorder(
                onSend = { videoFile, duration ->
                    showVideoCircleRecorder = false
                    val videoId = UUID.randomUUID().toString()

                    scope.launch(Dispatchers.IO) {
                        try {
                            val plainBytes = videoFile.readBytes()
                            videoFile.delete()
                            val encFile = SecureFileStorage.blobFile(context.filesDir, videoId)
                            SecureFileStorage.write(context, encFile, plainBytes)

                            withContext(Dispatchers.Main) {
                                messengerService?.sendVideoCircle(recipient, videoId, plainBytes, duration, encFile.absolutePath)
                                messages.add(Message(
                                    id = videoId,
                                    text = "Видеосообщение",
                                    isOwn = true,
                                    videoPath = encFile.absolutePath,
                                    videoDuration = duration
                                ))
                                ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                    ChatStorage.StoredMessage(
                                        id = videoId,
                                        text = "Видеосообщение",
                                        isOwn = true,
                                        videoPath = encFile.absolutePath,
                                        videoDuration = duration
                                    ))
                                scope.launch { listState.animateScrollToItem(messages.size - 1) }
                            }
                        } catch (e: Exception) {
                            android.util.Log.e("ChatScreen", "Video enc error: ${e.message}")
                        }
                    }
                },
                onCancel = { showVideoCircleRecorder = false }
            )
        }

        if (showForwardDialog != null) {
            val forwardMsg = showForwardDialog!!
            val contacts = remember { ChatStorage.getContacts(context) }
            AlertDialog(
                onDismissRequest = { showForwardDialog = null },
                containerColor = c.dialog,
                title = { Text("Переслать", color = c.textPrimary, fontFamily = JetBrainsMono) },
                text = {
                    androidx.compose.foundation.lazy.LazyColumn(
                        modifier = Modifier.heightIn(max = 300.dp)
                    ) {
                        items(contacts.filter { it != userId }) { contactId ->
                            val name = ChatStorage.getContactName(context, contactId)
                            TextButton(
                                onClick = {
                                    showForwardDialog = null

                                    when {
                                        forwardMsg.videoPath != null -> {

                                            val videoPathRef = forwardMsg.videoPath
                                            val videoDurRef = forwardMsg.videoDuration
                                            val svcRef = messengerService
                                            scope.launch(Dispatchers.IO) {
                                                try {
                                                    val plainBytes = SecureFileStorage.read(context, File(videoPathRef))
                                                    val newId = UUID.randomUUID().toString()
                                                    withContext(Dispatchers.Main) {
                                                        svcRef?.sendVideoCircle(contactId, newId, plainBytes, videoDurRef)
                                                    }
                                                } catch (e: Exception) {
                                                    android.util.Log.e("ChatScreen", "Forward video error: ${e.message}")
                                                }
                                            }
                                        }
                                        forwardMsg.voiceFile != null -> {

                                            val voiceFileRef = forwardMsg.voiceFile
                                            val voiceDurRef = forwardMsg.voiceDuration
                                            val svcRef = messengerService
                                            scope.launch(Dispatchers.IO) {
                                                try {
                                                    val plainBytes = SecureFileStorage.read(context, voiceFileRef)
                                                    val base64 = android.util.Base64.encodeToString(plainBytes, android.util.Base64.DEFAULT)
                                                    val newId = UUID.randomUUID().toString()
                                                    withContext(Dispatchers.Main) {
                                                        svcRef?.sendVoice(contactId, base64, newId, voiceDurRef)
                                                    }
                                                } catch (e: Exception) {
                                                    android.util.Log.e("ChatScreen", "Forward voice error: ${e.message}")
                                                }
                                            }
                                        }
                                        forwardMsg.imageBitmap != null -> {
                                            val chunks = bitmapToChunks(forwardMsg.imageBitmap)
                                            messengerService?.sendImage(contactId, chunks)
                                        }
                                        forwardMsg.text.isNotEmpty() && !forwardMsg.isSystem -> {
                                            messengerService?.send(contactId, forwardMsg.text)
                                        }
                                    }
                                    android.widget.Toast.makeText(context, "Переслано", android.widget.Toast.LENGTH_SHORT).show()
                                }
                            ) {
                                Text(name, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp)
                            }
                        }
                    }
                },
                confirmButton = {}
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MessageBubble(
    msg: Message,
    contactId: String = "",
    onLongClick: ((Message) -> Unit)? = null,
    onReactionClick: ((Message) -> Unit)? = null,
    onSwipeToReply: ((Message) -> Unit)? = null,
    playingVoiceId: String? = null,
    onVoicePlay: ((String) -> Unit)? = null,
    onVoiceStop: (() -> Unit)? = null,
    voicePlaybackMs: Int = 0,
    voiceSpeed: Float = 1f,
    onVoiceSeek: ((Int) -> Unit)? = null,
    onVoiceSpeedToggle: (() -> Unit)? = null,
    playingVideoId: String? = null,
    onVideoPlay: ((String) -> Unit)? = null,
    onVideoStop: (() -> Unit)? = null,
    onImageClick: ((Bitmap) -> Unit)? = null,
    searchQuery: String = ""
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    var showMapDialog by remember { mutableStateOf(false) }

    val isGeoLocation = msg.text == s.chatGeo || msg.text == "📍 Геопозиция"
    val geoCoordinates = if (isGeoLocation) {

        try {
            val storedMsg = ChatStorage.loadMessages(
                context,
                UserStorage.getUserId(context),
                contactId
            ).find { it.id == msg.id }

            storedMsg?.text?.split(",")?.let { coords ->
                if (coords.size == 2) {
                    Pair(coords[0].toDouble(), coords[1].toDouble())
                } else null
            }
        } catch (e: Exception) {
            null
        }
    } else null

    val bubbleColor = when {
        msg.isSystem -> c.bubbleSystem
        msg.isOwn -> c.bubbleOwn
        else -> c.bubbleOther
    }
    val alignment = if (msg.isOwn) Alignment.CenterEnd else Alignment.CenterStart

    Box(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp)) {
        Surface(
            modifier = Modifier
                .align(alignment)
                .widthIn(min = if (msg.videoPath != null) 0.dp else 80.dp, max = 700.dp)
                .pointerInput(Unit) {
                    detectHorizontalDragGestures { _, dragAmount ->
                        if (!msg.isSystem) {
                            if (dragAmount > 60) onSwipeToReply?.invoke(msg)
                            else if (dragAmount < -60) onReactionClick?.invoke(msg)
                        }
                    }
                }
                .combinedClickable(
                    onClick = {

                        if (isGeoLocation && geoCoordinates != null) {
                            showMapDialog = true
                        } else if (msg.fileName != null && msg.filePath != null) {
                            openFile(context, msg.filePath, msg.fileName, s.chatFileNotFound, s.chatFileDecryptError, s.chatFileOpenError)
                        }
                    },
                    onLongClick = { if (!msg.isSystem) onLongClick?.invoke(msg) }
                ),
            shape = RoundedCornerShape(
                topStart = if (msg.isOwn) 18.dp else 4.dp,
                topEnd = if (msg.isOwn) 4.dp else 18.dp,
                bottomStart = 18.dp,
                bottomEnd = 18.dp
            ),
            color = if (msg.videoPath != null) Color.Transparent else bubbleColor,
            // No shadow for video circles — a rounded-rect drop shadow
            // behind a transparent Surface still shows a faint rectangular
            // outline around the circle, which is exactly the "square
            // bounds visible" look the video-note redesign was meant to
            // remove.
            shadowElevation = if (msg.videoPath != null) 0.dp else 2.dp
        ) {
            Column {

                if (msg.imageBitmap != null) {
                    Image(
                        bitmap = msg.imageBitmap.asImageBitmap(),
                        contentDescription = s.chatPhotoDesc,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 160.dp, max = 320.dp)
                            .clickable { msg.imageBitmap?.let { onImageClick?.invoke(it) } }
                    )
                }
            Row(
                modifier = Modifier.padding(
                    horizontal = if (msg.videoPath != null) 0.dp else 12.dp,
                    vertical = if (msg.videoPath != null) 0.dp else 8.dp
                ),
                verticalAlignment = Alignment.Bottom
            ) {
                Column(modifier = Modifier.weight(1f, fill = false)) {

                    if (msg.replyTo != null) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 4.dp)
                                .height(IntrinsicSize.Min)
                                .clip(RoundedCornerShape(8.dp))
                                .background(Color(0x22FFFFFF))
                        ) {
                            Spacer(
                                modifier = Modifier
                                    .width(3.dp)
                                    .fillMaxHeight()
                                    .background(c.accent)
                            )
                            Column(modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
                                Text(s.chatReplyLabel, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = c.accent)
                                Text(msg.replyTo.text, fontSize = 14.sp, maxLines = 2, overflow = TextOverflow.Ellipsis, color = c.textPrimary.copy(alpha = 0.7f))
                            }
                        }
                    }

                    if (isGeoLocation && geoCoordinates != null) {
                        Column {
                            GeoLocationMap(
                                latitude = geoCoordinates.first,
                                longitude = geoCoordinates.second,
                                isInteractive = false,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(150.dp)
                                    .padding(bottom = 4.dp)
                            )
                            Text(
                                s.chatGeoTap,
                                fontSize = 14.sp,
                                color = Color.White,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color(0xCC1A237E))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }

                    if (msg.fileName != null && msg.filePath != null && msg.imageBitmap == null && !isGeoLocation) {
                        FilePreview(
                            fileName = msg.fileName,
                            filePath = msg.filePath,
                            context = context
                        )
                    }

                    if (msg.videoPath != null) {
                        val isVideoPlaying = playingVideoId == msg.id
                        Box {
                            VideoCircleBubble(
                                messageId = msg.id,
                                videoPath = msg.videoPath,
                                videoDuration = msg.videoDuration,
                                isPlaying = isVideoPlaying,
                                onPlay = { onVideoPlay?.invoke(msg.id) },
                                onStop = { onVideoStop?.invoke() },
                                cachePrefix = ""
                            )
                            // Time + delivery status live here, overlaid on
                            // the circle itself, instead of as a sibling Row
                            // item outside it (see the comment below this
                            // Column for why that widened the bubble into a
                            // rectangle around the circle). Hidden while
                            // playing, same as the duration badge, so the
                            // video stays clean per the redesign spec.
                            if (!isVideoPlaying && !msg.isSystem) {
                                Row(
                                    modifier = Modifier
                                        .align(Alignment.BottomStart)
                                        .padding(8.dp)
                                        .background(Color(0x88000000), CircleShape)
                                        .padding(horizontal = 6.dp, vertical = 2.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = SimpleDateFormat("HH:mm", LocalLocale.current.platformLocale).format(Date(msg.timestamp)),
                                        fontSize = 11.sp,
                                        color = Color.White
                                    )
                                    if (msg.isOwn) {
                                        Spacer(modifier = Modifier.width(3.dp))
                                        when {
                                            msg.isPending -> Icon(
                                                painter = painterResource(R.drawable.ic_loading),
                                                contentDescription = null,
                                                tint = Color.White.copy(alpha = 0.8f),
                                                modifier = Modifier.size(9.dp)
                                            )
                                            msg.isFailed -> Icon(painter = painterResource(R.drawable.ic_error),
                                                contentDescription = null, tint = Color(0xFFEF5350), modifier = Modifier.size(11.dp))
                                            msg.isRead -> Icon(painter = painterResource(R.drawable.ic_delivered_double),
                                                contentDescription = null, tint = c.accent, modifier = Modifier.size(11.dp))
                                            msg.isDelivered -> Icon(painter = painterResource(R.drawable.ic_delivered_double),
                                                contentDescription = null, tint = Color.White.copy(alpha = 0.8f), modifier = Modifier.size(11.dp))
                                            else -> Icon(painter = painterResource(R.drawable.ic_check),
                                                contentDescription = null, tint = Color.White.copy(alpha = 0.8f), modifier = Modifier.size(11.dp))
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (msg.voiceFile != null) {
                        // Waveform bars decoded off the main thread (AMR-NB
                        // decode via MediaCodec — see AudioHelper.getWaveform's
                        // own comment) and cached there by file path, so
                        // re-entering this LaunchedEffect on recomposition
                        // (LazyColumn scroll) is cheap after the first decode.
                        var waveformBars by remember(msg.id) { mutableStateOf(FloatArray(32)) }
                        LaunchedEffect(msg.voiceFile) {
                            val file = msg.voiceFile ?: return@LaunchedEffect
                            waveformBars = withContext(Dispatchers.IO) {
                                AudioHelper.getWaveform(context, file)
                            }
                        }
                        val isThisPlaying = playingVoiceId == msg.id
                        val totalMs = if (isThisPlaying) {
                            AudioHelper.getDurationMs().takeIf { it > 0 } ?: (msg.voiceDuration * 1000)
                        } else msg.voiceDuration * 1000
                        val progress = if (isThisPlaying && totalMs > 0) {
                            (voicePlaybackMs.toFloat() / totalMs).coerceIn(0f, 1f)
                        } else 0f
                        val shownSeconds = if (isThisPlaying) voicePlaybackMs / 1000 else msg.voiceDuration

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Surface(
                                shape = CircleShape,
                                color = c.primaryBlue,
                                modifier = Modifier.size(48.dp),
                                onClick = {
                                    if (isThisPlaying) {
                                        AudioHelper.stopAudio()
                                        onVoiceStop?.invoke()
                                    } else {
                                        AudioHelper.playAudio(context, msg.voiceFile) { onVoiceStop?.invoke() }
                                        AudioHelper.setSpeed(voiceSpeed)
                                        onVoicePlay?.invoke(msg.id)
                                    }
                                }
                            ) {
                                Box(
                                    contentAlignment = Alignment.Center,
                                    modifier = Modifier.fillMaxSize()
                                ) {
                                    Icon(
                                        painter = painterResource(
                                            if (isThisPlaying) R.drawable.ic_pause else R.drawable.ic_play
                                        ),
                                        contentDescription = null,
                                        tint = if (c.isDark) Color.White else c.textPrimary,
                                        modifier = Modifier.size(24.dp)
                                    )
                                }
                            }
                            Spacer(Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                VoiceWaveform(
                                    bars = waveformBars,
                                    progress = progress,
                                    color = c.primaryBlue,
                                    dimColor = c.primaryBlue.copy(alpha = 0.3f),
                                    onSeek = { frac ->
                                        val targetMs = (frac * totalMs).toInt()
                                        if (!isThisPlaying) {
                                            AudioHelper.playAudio(context, msg.voiceFile) { onVoiceStop?.invoke() }
                                            AudioHelper.setSpeed(voiceSpeed)
                                            onVoicePlay?.invoke(msg.id)
                                        }
                                        onVoiceSeek?.invoke(targetMs)
                                    }
                                )
                                Text("0:${shownSeconds.toString().padStart(2, '0')}",
                                    fontSize = 15.sp, color = c.primaryBlue)
                            }
                            Spacer(Modifier.width(6.dp))
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = c.primaryBlue.copy(alpha = if (voiceSpeed != 1f) 0.9f else 0.15f),
                                modifier = Modifier
                                    .clickable { onVoiceSpeedToggle?.invoke() }
                            ) {
                                Text(
                                    when (voiceSpeed) {
                                        1.5f -> "1.5×"
                                        2f -> "2×"
                                        else -> "1×"
                                    },
                                    fontSize = 14.sp,
                                    color = if (voiceSpeed != 1f) (if (c.isDark) Color.White else c.textPrimary) else c.primaryBlue,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                )
                            }
                        }
                    }

                    if (msg.text.isNotEmpty() && msg.text != s.chatAttachPhoto && msg.text != "📷 Фото"
                        && !(isGeoLocation && geoCoordinates != null) && msg.videoPath == null) {
                        val displayText = if (msg.isEdited) "${msg.text} ${s.chatEdited}" else msg.text
                        if (searchQuery.isNotBlank() && displayText.contains(searchQuery, ignoreCase = true)) {

                            val lowerText = displayText.lowercase()
                            val lowerQuery = searchQuery.lowercase()
                            val startIdx = lowerText.indexOf(lowerQuery)
                            if (startIdx >= 0) {
                                val endIdx = startIdx + searchQuery.length
                                androidx.compose.ui.text.buildAnnotatedString {
                                    append(displayText.substring(0, startIdx))
                                    withStyle(androidx.compose.ui.text.SpanStyle(
                                        background = c.accent.copy(alpha = 0.4f),
                                        color = if (c.isDark) Color.White else c.textPrimary
                                    )) { append(displayText.substring(startIdx, endIdx)) }
                                    append(displayText.substring(endIdx))
                                }.also { annotated ->
                                    Text(text = annotated, fontSize = 20.sp, lineHeight = 20.sp)
                                }
                            } else {
                                Text(text = displayText, fontSize = 20.sp, lineHeight = 20.sp, color = c.textPrimary)
                            }
                        } else {
                            Text(
                                text = displayText,
                                fontSize = 20.sp,
                                lineHeight = 20.sp,
                                color = if (msg.isSystem) c.textPrimary.copy(alpha = 0.6f) else c.textPrimary
                            )
                        }
                    }
                }

                // Video messages render their own time/ticks as a small
                // overlay INSIDE the circle (see the Box wrapping
                // VideoCircleBubble above) instead of here — as a sibling of
                // the circle in this Row, this text/icon pair widened the
                // Row (and the transparent-but-shadowed Surface bubbling it)
                // past the circle's own bounds, which is exactly the
                // "rectangle around the circle" look the redesign was
                // supposed to remove. Found live: the circle itself had
                // already been redesigned, but this sibling metadata was the
                // actual source of the visible rectangular bounding box.
                if (!msg.isSystem && msg.videoPath == null) {
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = SimpleDateFormat("HH:mm", LocalLocale.current.platformLocale).format(Date(msg.timestamp)),
                        fontSize = 12.sp,
                        color = c.textPrimary.copy(alpha = 0.5f)
                    )
                }
                if (msg.isOwn && !msg.isSystem && msg.videoPath == null) {
                    Spacer(modifier = Modifier.width(4.dp))
                    when {
                        msg.isPending   -> {
                            val infiniteTransition = rememberInfiniteTransition(label = "sending_spinner")
                            val angle by infiniteTransition.animateFloat(
                                initialValue = 0f,
                                targetValue = 360f,
                                animationSpec = infiniteRepeatable(
                                    animation = tween(1600, easing = LinearEasing)
                                ),
                                label = "sending_spinner_angle"
                            )
                            Icon(
                                painter = painterResource(R.drawable.ic_loading),
                                contentDescription = null,
                                tint = c.textPrimary.copy(alpha = 0.6f),
                                modifier = Modifier.size(10.dp).rotate(angle)
                            )
                        }
                        msg.isFailed    -> Icon(painter = painterResource(R.drawable.ic_error),
                            contentDescription = null, tint = Color(0xFFE53935), modifier = Modifier.size(12.dp))
                        msg.isRead      -> Icon(painter = painterResource(R.drawable.ic_delivered_double),
                            contentDescription = null, tint = c.accent, modifier = Modifier.size(12.dp))
                        msg.isDelivered -> Icon(painter = painterResource(R.drawable.ic_delivered_double),
                            contentDescription = null, tint = Color(0xFF8899AA), modifier = Modifier.size(12.dp))
                        else            -> Icon(painter = painterResource(R.drawable.ic_check),
                            contentDescription = null, tint = Color(0xFF8899AA), modifier = Modifier.size(12.dp))
                    }
                }
            }
            }
        }

        if (msg.reactions.isNotEmpty()) {
            Row(
                modifier = Modifier
                    .align(if (msg.isOwn) Alignment.BottomEnd else Alignment.BottomStart)
                    .offset(x = if (msg.isOwn) 12.dp else (-12).dp, y = 12.dp)
                    .background(c.card, RoundedCornerShape(12.dp))
                    .padding(horizontal = 6.dp, vertical = 3.dp)
            ) {
                msg.reactions.values.groupBy { it }.forEach { (emoji, reactors) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 2.dp)
                    ) {
                        Text(emoji, fontSize = 15.sp)
                        if (reactors.size > 1) {
                            Text(
                                text = " ${reactors.size}",
                                fontSize = 13.sp,
                                color = c.textPrimary,
                                fontFamily = JetBrainsMono
                            )
                        }
                    }
                }
            }
        }
    }

    if (showMapDialog && geoCoordinates != null) {
        MapDialog(
            latitude = geoCoordinates.first,
            longitude = geoCoordinates.second,
            onDismiss = { showMapDialog = false }
        )
    }
}
@Composable
private fun TypingDotsIndicator(color: Color) {
    val bouncePx = with(LocalDensity.current) { 4.dp.toPx() }
    val tr = rememberInfiniteTransition(label = "typing_dots")

    val dot1 by tr.animateFloat(
        initialValue = 0f, targetValue = -bouncePx,
        animationSpec = infiniteRepeatable(
            tween(280, easing = FastOutSlowInEasing), RepeatMode.Reverse
        ), label = "d1"
    )
    val dot2 by tr.animateFloat(
        initialValue = 0f, targetValue = -bouncePx,
        animationSpec = infiniteRepeatable(
            tween(280, easing = FastOutSlowInEasing), RepeatMode.Reverse,
            StartOffset(120, StartOffsetType.FastForward)
        ), label = "d2"
    )
    val dot3 by tr.animateFloat(
        initialValue = 0f, targetValue = -bouncePx,
        animationSpec = infiniteRepeatable(
            tween(280, easing = FastOutSlowInEasing), RepeatMode.Reverse,
            StartOffset(240, StartOffsetType.FastForward)
        ), label = "d3"
    )

    Row(
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        listOf(dot1, dot2, dot3).forEach { offsetY ->
            Box(
                modifier = Modifier
                    .size(5.dp)
                    .graphicsLayer { translationY = offsetY }
                    .clip(CircleShape)
                    .background(color)
            )
        }
    }
}

@Composable
fun FilePreview(fileName: String, filePath: String, context: Context) {
    val c = LocalSubrosaColors.current
    val fileExtension = fileName.substringAfterLast('.', "").lowercase()
    val file = File(filePath)

    val previewBitmap = remember(filePath) {
        if (fileExtension in listOf("png", "jpg", "jpeg", "webp")) {
            try {
                val options = android.graphics.BitmapFactory.Options().apply {
                    inSampleSize = 2
                }
                android.graphics.BitmapFactory.decodeFile(filePath, options)
            } catch (e: Exception) {
                null
            }
        } else null
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {

        if (previewBitmap != null) {
            Image(
                bitmap = previewBitmap.asImageBitmap(),
                contentDescription = fileName,
                modifier = Modifier
                    .widthIn(max = 250.dp)
                    .heightIn(max = 200.dp)
                    .padding(bottom = 4.dp)
            )
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0x22FFFFFF), RoundedCornerShape(8.dp))
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(painter = painterResource(R.drawable.ic_file), contentDescription = null,
                tint = c.textPrimary, modifier = Modifier.size(24.dp).padding(end = 8.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = fileName,
                    fontSize = 16.sp,
                    color = c.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                if (file.exists()) {
                    val sizeKB = file.length() / 1024
                    val sizeText = if (sizeKB > 1024) {
                        "${sizeKB / 1024} MB"
                    } else {
                        "$sizeKB KB"
                    }
                    Text(
                        text = sizeText,
                        fontSize = 14.sp,
                        color = c.textPrimary.copy(alpha = 0.67f)
                    )
                }
            }

            Icon(
                painter = painterResource(R.drawable.ic_arrow_down),
                contentDescription = null,
                tint = c.textPrimary,
                modifier = Modifier.size(20.dp).padding(start = 8.dp)
            )
        }
    }
}

fun openFile(
    context: Context, filePath: String, fileName: String,
    fileNotFoundMsg: String = "Файл не найден",
    fileDecryptErrorMsg: String = "Ошибка расшифровки файла",
    fileOpenErrorMsg: (String) -> String = { "Не удалось открыть файл: $it" }
) {
    try {
        val file = File(filePath)
        if (!file.exists()) {
            android.widget.Toast.makeText(
                context,
                fileNotFoundMsg,
                android.widget.Toast.LENGTH_SHORT
            ).show()
            return
        }

        val fileToOpen = if (filePath.endsWith(".enc")) {
            try {
                SecureFileStorage.decryptToTemp(context, file, fileName)
            } catch (e: Exception) {
                android.widget.Toast.makeText(context, fileDecryptErrorMsg, android.widget.Toast.LENGTH_SHORT).show()
                return
            }
        } else file

        val uri = androidx.core.content.FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            fileToOpen
        )

        val mimeType = when (fileName.substringAfterLast('.', "").lowercase()) {
            "pdf" -> "application/pdf"
            "doc", "docx" -> "application/msword"
            "png" -> "image/png"
            "jpg", "jpeg" -> "image/jpeg"
            else -> "*/*"
        }

        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        context.startActivity(intent)
    } catch (e: Exception) {
        android.util.Log.e("FileOpen", "Error: ${e.message}")
        android.widget.Toast.makeText(
            context,
            fileOpenErrorMsg(e.message ?: ""),
            android.widget.Toast.LENGTH_SHORT
        ).show()
    }
}
