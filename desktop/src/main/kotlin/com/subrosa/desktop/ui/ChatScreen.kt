@file:OptIn(
    androidx.compose.foundation.ExperimentalFoundationApi::class,
    androidx.compose.ui.ExperimentalComposeUiApi::class
)

package com.subrosa.desktop

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.*
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.*
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.isSecondaryPressed
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.Desktop
import java.net.URI
import java.text.SimpleDateFormat
import java.util.*

private const val CLIPBOARD_CLEAR_DELAY_MS = 30_000L

// S6-57 (external review 2026-09-06) -- product-level cap on voice-message
// recording length; matches server.py's own MAX_VOICE_DURATION_SECONDS
// exactly (see its comment there for the full byte-math derivation). Neither
// client previously had any recording-length limit at all.
private const val MAX_VOICE_RECORDING_SECONDS = 60

// ── Message model ─────────────────────────────────────────────────────────────

data class DesktopMessage(
    val id:          String,
    val fromMe:      Boolean,
    val text:        String?,
    val geoCoords:   String?    = null,
    val imageBytes:  ByteArray? = null,
    val fileName:    String?    = null,
    val filePath:    String?    = null,
    val timestamp:   Long       = System.currentTimeMillis(),
    val isDelivered: Boolean    = false,
    val isRead:      Boolean    = false,
    val isEdited:    Boolean    = false,
    val isFailed:    Boolean    = false,
    val replyToId:   String?    = null,
    val replyPreview: String?   = null,  // text snippet of replied-to message
    // Reactions keyed by reactor fingerprint (mirrors Android's Message.reactions
    // and ChatStorage.StoredMessage.reactions) — a reactor's newer emoji
    // overwrites their older one, no separate dedup needed.
    val reactions:   Map<String, String> = emptyMap(),
    // Disappearing-message expiry (mirrors Android): 0 = never. Set at SEND time
    // to now + disappearTimerSecs*1000 for own outgoing messages when a
    // per-conversation disappear timer is active; the message is removed locally
    // once reached and skipped on load if already past.
    val expiresAt:   Long       = 0L,
    val voiceDuration: Int      = 0,
    // Video circle (Telegram-style round video message) — ported from
    // Android's VideoCircleScreen. videoPath is an encrypted-at-rest blob
    // path, decrypted on demand for thumbnail/playback (same convention as
    // filePath/imageBytes).
    val videoPath: String? = null,
    val videoDuration: Int = 0
)

internal val IMAGE_EXTENSIONS = setOf("png", "jpg", "jpeg", "gif", "bmp", "webp")

/** GPS coordinates, camera make/model, and capture timestamps embedded in a
 *  picked image file. Unlike Android (whose photo picker decodes to a
 *  `Bitmap` and re-encodes to WebP as a normal part of sending — which
 *  incidentally strips EXIF, since `Bitmap` is pixel data with no metadata
 *  container), Desktop's attach dialog reads and sends the picked file's
 *  bytes completely unmodified. Re-encoding through `ImageIO` here is the
 *  equivalent step: decoding to a `BufferedImage` and writing it back out
 *  drops all EXIF the same way. `webp` isn't writable by the JDK's built-in
 *  `ImageIO` (no bundled plugin) — those are sent unmodified, same as any
 *  format `ImageIO` fails to decode or write. */
internal fun stripImageMetadata(bytes: ByteArray, extension: String): ByteArray {
    val writerFormat = when (extension.lowercase()) {
        "jpg", "jpeg" -> "jpg"
        "png" -> "png"
        "bmp" -> "bmp"
        "gif" -> "gif"
        else -> return bytes
    }
    return try {
        val img = javax.imageio.ImageIO.read(java.io.ByteArrayInputStream(bytes)) ?: return bytes
        val out = java.io.ByteArrayOutputStream()
        if (javax.imageio.ImageIO.write(img, writerFormat, out)) out.toByteArray() else bytes
    } catch (e: Exception) {
        bytes
    }
}

// ── Screen ────────────────────────────────────────────────────────────────────

@Composable
fun ChatScreen(
    contact: String,
    onBack: () -> Unit,
    onOpenContactInfo: () -> Unit = {},
    initialSearchMode: Boolean = false,
    onSearchModeConsumed: () -> Unit = {}
) {
    val s            = LocalStrings.current
    val myId         = WebSocketClient.myFingerprint
    val contactLabel = ChatStorage.getContactName(contact)
    val clipboard    = LocalClipboardManager.current
    val scope        = rememberCoroutineScope()

    val messages  = remember { mutableStateListOf<DesktopMessage>() }
    var input     by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    // True once this contact can be messaged anonymously (or wasn't a
    // mailbox-bootstrapped contact to begin with). Starts optimistic (true) so
    // existing/established chats never flash a "connecting" state.
    var channelReady by remember { mutableStateOf(true) }

    // On-screen keyboard for message text — sidesteps hardware/driver keyloggers
    // (see SECURITY.md "Known Limitations"). Off by default; toggled per-chat.
    var showVirtualKb by remember { mutableStateOf(false) }
    var vkSeed by remember { mutableStateOf(0) }

    // Context menu state
    var contextMsg      by remember { mutableStateOf<DesktopMessage?>(null) }

    // Edit mode
    var editingMsg by remember { mutableStateOf<DesktopMessage?>(null) }

    // Reply mode
    var replyingTo by remember { mutableStateOf<DesktopMessage?>(null) }

    // Forward mode
    var forwardingMsg by remember { mutableStateOf<DesktopMessage?>(null) }

    // Typing indicator
    var peerTyping     by remember { mutableStateOf(false) }
    var typingTimer    by remember { mutableStateOf(0L) }

    // Video circle (Telegram-style round video message) — recording dialog
    // trigger. See VideoCircleRecorderDialog.kt/DesktopVideoCircleRecorder.kt.
    var showVideoCircleRecorder by remember { mutableStateOf(false) }

    // Voice PLAYBACK state (Telegram-style waveform bubble) — mirrors
    // Android's identical playingVoiceId/voicePlaybackMs/voiceSpeed exactly.
    // Global (not per-FileRow local state) because only one voice message
    // plays at a time (DesktopVoicePlayer itself only holds one Clip) and
    // the speed toggle is a persistent user choice, not per-message.
    var playingVoiceId by remember { mutableStateOf<String?>(null) }
    var voicePlaybackMs by remember { mutableStateOf(0) }
    var voiceSpeed by remember { mutableStateOf(1f) }
    LaunchedEffect(playingVoiceId) {
        if (playingVoiceId != null) {
            while (playingVoiceId != null && DesktopVoicePlayer.isPlaying) {
                voicePlaybackMs = DesktopVoicePlayer.getCurrentPositionMs()
                delay(80L)
            }
        } else {
            voicePlaybackMs = 0
        }
    }

    // Voice recording
    var isRecordingVoice by remember { mutableStateOf(false) }
    // Combined mic/video record button mode: tap toggles this, long-press
    // starts recording in whichever mode is currently selected — mirrors
    // Android's CombinedMediaButton (SubrosaButtons.kt).
    var isVideoRecordMode by remember { mutableStateOf(false) }
    // Live "0:07" counter shown in the recording bar below — mirrors
    // Android's ChatScreen recordingSeconds exactly. Was entirely absent
    // before this fix: this whole recording bar (timer, pulsing dot,
    // cancel/send buttons) didn't exist on Desktop, so recording had zero
    // visual feedback beyond the mic icon flipping to a stop icon.
    var recordingSeconds by remember { mutableStateOf(0) }

    // S6-57, STEP 9 (external review 2026-09-06) -- auto-stops and sends
    // exactly at the cap rather than silently truncating or discarding what
    // was already recorded; matches server.py's own MAX_VOICE_DURATION_SECONDS
    // (see its comment there for the full byte-math derivation). Neither
    // client previously had any recording-length limit at all.
    fun finishVoiceRecordingAndSend() {
        isRecordingVoice = false
        val wavBytes = VoiceRecorder.stop()
        if (wavBytes != null && wavBytes.size > 44) { // 44 = empty WAV header size
            val id = UUID.randomUUID().toString()
            val voiceBase64 = java.util.Base64.getEncoder().encodeToString(wavBytes)
            val durationSec = VoiceRecorder.durationSeconds(wavBytes)
            WebSocketClient.sendVoice(contact, voiceBase64, id, durationSec)
            val fileDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs")
                .also { it.mkdirs() }
            val outFile = java.io.File(fileDir, "$id.enc")
            runCatching { outFile.writeBytes(DesktopStorage.encryptRaw(wavBytes)) }
            messages.add(DesktopMessage(id = id, fromMe = true, text = null,
                fileName = VoiceRecorder.FILE_NAME, filePath = outFile.absolutePath,
                voiceDuration = durationSec))
            ChatStorage.saveOrUpdateMessage(myId, contact,
                ChatStorage.StoredMessage(id = id, text = "", isOwn = true,
                    filePath = outFile.absolutePath, fileName = VoiceRecorder.FILE_NAME,
                    voiceDuration = durationSec))
        }
    }

    LaunchedEffect(isRecordingVoice) {
        if (isRecordingVoice) {
            recordingSeconds = 0
            while (isRecordingVoice) {
                delay(1000L)
                recordingSeconds++
                if (recordingSeconds >= MAX_VOICE_RECORDING_SECONDS) {
                    finishVoiceRecordingAndSend()
                }
            }
        } else {
            recordingSeconds = 0
        }
    }

    // Auto-delete (LOCAL-only, timestamp-based, not synced to the peer)
    var autoDeleteSecs     by remember { mutableStateOf(UserStorage.getChatAutoDelete(contact)) }

    // Disappearing messages (SYNCED to the peer via the disappear_timer protocol
    // frame — distinct from local auto-delete above). Mirrors Android's
    // ChatScreen.disappearTimerSecs: only 0/1h/24h/7d are offered, the countdown
    // starts on SEND, and it applies to this device's own outgoing messages.
    var disappearTimerSecs by remember { mutableStateOf(0L) }

    // Search within this chat's own message list — entry point lives in
    // ContactInfoScreen now, re-entering here with it pre-armed (see
    // initialSearchMode below), same reasoning as Android's identical setup.
    var searchMode by remember { mutableStateOf(initialSearchMode) }
    var searchQuery by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (initialSearchMode) onSearchModeConsumed() }

    // TOFU key-change / revocation warnings — mirrors Android's ChatScreen.kt
    // showKeyWarning/showRevokedWarning, driven by WebSocketClient.onKeyChanged/
    // onContactRevoked (KeyHistoryManager's TOFU check on each fetched bundle).
    var showKeyWarning by remember { mutableStateOf(false) }
    var showRevokedWarning by remember { mutableStateOf(false) }

    // Send-blocked warning — mirrors Android's ChatScreen.kt
    // showSendBlockedWarning, driven by ContactHealthManager.isSendBlocked()
    // (10 unconfirmed sends in a row with no delivered ack). Was entirely
    // missing on Desktop: the manager function existed nowhere and the send
    // button had no gate at all. Found in the 2026-09-13 ContactHealthManager
    // audit.
    var showSendBlockedWarning by remember { mutableStateOf(false) }

    // ── Load history + register callbacks ────────────────────────────────────
    LaunchedEffect(contact) {
        val stored = ChatStorage.loadMessages(myId, contact)
        messages.clear()
        for (msg in stored) {
            val imgBytes = msg.imagePath?.let { path ->
                runCatching {
                    val f = java.io.File(path)
                    if (!f.exists()) return@runCatching null
                    val raw = f.readBytes()
                    if (path.endsWith(".enc")) DesktopStorage.decryptRaw(raw) else raw
                }.getOrNull()
            }
            messages.add(DesktopMessage(
                id          = msg.id,
                fromMe      = msg.isOwn,
                text        = if (msg.imagePath != null || msg.filePath != null) null
                              else msg.text.takeIf { it.isNotEmpty() },
                imageBytes  = imgBytes,
                fileName    = msg.fileName,
                filePath    = msg.filePath,
                geoCoords   = if (msg.imagePath != null) msg.text.takeIf { it.isNotEmpty() }
                              else null,
                timestamp   = msg.timestamp,
                isDelivered = msg.isDelivered,
                isRead      = msg.isRead,
                isEdited    = msg.isEdited,
                isFailed    = msg.isFailed,
                reactions   = msg.reactions,
                expiresAt   = msg.expiresAt,
                voiceDuration = msg.voiceDuration,
                videoPath   = msg.videoPath,
                videoDuration = msg.videoDuration,
            ))
        }
        input = ChatStorage.loadDraft(myId, contact)
        disappearTimerSecs = ChatStorage.getDisappearTimer(myId, contact)
        // NOT marked read here unconditionally anymore — see the
        // AppFocusTracker.isActivelyPresent LaunchedEffect below, which
        // flushes unread messages (locally AND over the network) only once
        // the window has actually held focus for the read-receipt dwell.
        // Opening this screen with the window unfocused, or on an
        // unattended machine, no longer silently reports every waiting
        // message as read. Found live, 2026-09-18.

        // If this contact's anonymous channel isn't confirmed established yet, show
        // the connecting state and (re-)kick the bootstrap immediately — opening the
        // chat is exactly the moment the user wants to write.
        channelReady = WebSocketClient.isChannelReady(contact)
        if (!channelReady) WebSocketClient.bootstrapChannelFor(contact)
        WebSocketClient.onChannelReady = { readyContact ->
            if (readyContact == contact) channelReady = true
        }

        WebSocketClient.onMessageReceived = { from, text, id, replyToId ->
            if (from == contact) {
                // isRead/sendRead gated on AppFocusTracker.isActivelyPresent
                // — see ChatScreen's dwell-timer LaunchedEffect below and
                // AppFocusTracker's own comment. A message arriving while
                // unfocused (or before the dwell completes) stays unread
                // until that effect flushes it.
                val readNow = AppFocusTracker.isActivelyPresent
                // Disappearing-message countdown must start on RECEIPT for
                // incoming messages too, exactly mirroring the send-side
                // stamp below — otherwise a peer's message only ever
                // disappears on THEIR device, never on ours, which defeats
                // the point of a synced timer. Was missing entirely (on
                // both platforms) before this fix.
                val expiresAt = if (disappearTimerSecs > 0L)
                    System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L
                val replyPreview = replyToId?.let { rid -> messages.find { it.id == rid }?.text?.take(60) }
                messages.add(DesktopMessage(id, false, text, isRead = readNow, expiresAt = expiresAt,
                    replyToId = replyToId, replyPreview = replyPreview))
                // WebSocketClient already persisted this message (with
                // isRead=false, id generated there) so it survives even if
                // no ChatScreen is open to receive the callback — reuse that
                // same id here and just update the read/expiry fields,
                // rather than inserting a second, duplicate row.
                ChatStorage.saveOrUpdateMessage(myId, contact,
                    ChatStorage.StoredMessage(id = id, text = text, isOwn = false, isRead = readNow,
                        replyToId = replyToId, expiresAt = expiresAt))
                if (readNow) WebSocketClient.sendRead(contact, id)
            }
        }
        WebSocketClient.onTypingReceived = { from ->
            if (from == contact) {
                peerTyping  = true
                typingTimer = System.currentTimeMillis()
            }
        }
        WebSocketClient.onReadReceived = { _ ->
            // Mark our sent messages as read
            messages.forEachIndexed { i, m ->
                if (m.fromMe && !m.isRead) messages[i] = m.copy(isRead = true)
            }
        }
        WebSocketClient.onDeliveredReceived = { msgId ->
            val i = messages.indexOfFirst { it.id == msgId }
            if (i >= 0) {
                messages[i] = messages[i].copy(isDelivered = true)
                // A delivered ack for a message in THIS conversation implies
                // it was for `contact` (msgIds are unique app-wide) — mirrors
                // Android's `if (contactId == recipient) showSendBlockedWarning
                // = false` exactly, without onDeliveredReceived carrying a
                // contact id of its own to compare against directly.
                showSendBlockedWarning = false
            }
            ChatStorage.markDelivered(myId, contact, msgId)
        }
        WebSocketClient.onEditReceived = { msgId, newText ->
            val i = messages.indexOfFirst { it.id == msgId }
            if (i >= 0) messages[i] = messages[i].copy(text = newText, isEdited = true)
        }
        WebSocketClient.onMessageDeleted = { from, msgId ->
            if (from == contact) {
                val i = messages.indexOfFirst { it.id == msgId }
                if (i >= 0) messages.removeAt(i)
                ChatStorage.deleteMessage(myId, contact, msgId)
            }
        }
        WebSocketClient.onReactionReceived = { from, msgId, emoji ->
            if (from == contact) {
                val i = messages.indexOfFirst { it.id == msgId }
                if (i >= 0) {
                    val updated = messages[i].copy(
                        reactions = messages[i].reactions.toMutableMap().also { it[from] = emoji }
                    )
                    messages[i] = updated
                    // Persist the reaction onto the stored message (mirrors
                    // Android's onReactionReceived -> saveOrUpdateMessage).
                    ChatStorage.saveOrUpdateMessage(myId, contact,
                        ChatStorage.StoredMessage(
                            id = updated.id, text = updated.text ?: "", isOwn = updated.fromMe,
                            timestamp = updated.timestamp, reactions = updated.reactions,
                            expiresAt = updated.expiresAt))
                }
            }
        }
        WebSocketClient.onKeyChanged = { from ->
            if (from == contact) showKeyWarning = true
        }
        WebSocketClient.onContactRevoked = { from ->
            if (from == contact) showRevokedWarning = true
        }
        WebSocketClient.onDisappearTimerChanged = { from, seconds ->
            // Receive-side handler already validated seconds against
            // CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED and persisted via
            // ChatStorage.setDisappearTimer before invoking this; just reflect
            // it in the UI so the peer's change updates our active timer.
            if (from == contact) disappearTimerSecs = seconds
        }
        WebSocketClient.onImageReceived = { from, imageBytes, geoCoords, id ->
            if (from == contact) {
                // WebSocketClient already wrote the encrypted-at-rest blob
                // (and persisted the ChatStorage row, with isRead=false)
                // before invoking this — reuse its id/path instead of
                // writing a second copy under a fresh one.
                val imgDir  = java.io.File(DesktopStorage.resolveDataDir(), "blobs")
                val imgFile = java.io.File(imgDir, "$id.enc")
                // isRead/sendRead gated on AppFocusTracker.isActivelyPresent
                // — see onMessageReceived above for the full rationale.
                val readNow = AppFocusTracker.isActivelyPresent
                val expiresAt = if (disappearTimerSecs > 0L)
                    System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L
                messages.add(DesktopMessage(
                    id        = id,
                    fromMe    = false,
                    text      = null,
                    imageBytes = imageBytes,
                    geoCoords = geoCoords,
                    isRead    = readNow,
                    expiresAt = expiresAt
                ))
                ChatStorage.saveOrUpdateMessage(myId, contact,
                    ChatStorage.StoredMessage(
                        id        = id,
                        text      = geoCoords ?: "",
                        isOwn     = false,
                        imagePath = imgFile.absolutePath,
                        isRead    = readNow,
                        expiresAt = expiresAt
                    )
                )
                if (readNow) WebSocketClient.sendRead(contact, id)
            }
        }
        WebSocketClient.onFileReceived = { from, fileId, fileName, bytes, durationSec, id ->
            if (from == contact) {
                // WebSocketClient already wrote the encrypted-at-rest blob
                // (keyed by fileId — same rule as before) and persisted the
                // ChatStorage row (with isRead=false, id resolved the same
                // way ChatScreen used to resolve it: fileId itself for voice,
                // a fresh id otherwise) before invoking this.
                val fileDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs")
                val outFile = java.io.File(fileDir, "$fileId.enc")
                // isRead/sendRead gated on AppFocusTracker.isActivelyPresent
                // — see onMessageReceived above for the full rationale.
                val readNow = AppFocusTracker.isActivelyPresent
                val expiresAt = if (disappearTimerSecs > 0L)
                    System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L
                messages.add(DesktopMessage(
                    id       = id,
                    fromMe   = false,
                    text     = null,
                    fileName = fileName,
                    filePath = outFile.absolutePath,
                    isRead   = readNow,
                    voiceDuration = durationSec,
                    expiresAt = expiresAt
                ))
                ChatStorage.saveOrUpdateMessage(myId, contact,
                    ChatStorage.StoredMessage(
                        id       = id,
                        text     = "",
                        isOwn    = false,
                        filePath = outFile.absolutePath,
                        fileName = fileName,
                        isRead   = readNow,
                        voiceDuration = durationSec,
                        expiresAt = expiresAt
                    )
                )
                if (readNow) WebSocketClient.sendRead(contact, id)
            }
        }
        // Video circle (Telegram-style round video message) — unlike
        // onFileReceived, WebSocketClient itself already decrypted and wrote
        // the encrypted-at-rest blob (mirrors Android's onVideoReceived,
        // which also hands back an already-written File) -- this handler
        // just records the metadata.
        WebSocketClient.onVideoReceived = { from, videoId, file, durationSec ->
            if (from == contact) {
                val readNow = AppFocusTracker.isActivelyPresent
                val expiresAt = if (disappearTimerSecs > 0L)
                    System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L
                messages.add(DesktopMessage(
                    id = videoId,
                    fromMe = false,
                    text = null,
                    videoPath = file.absolutePath,
                    videoDuration = durationSec,
                    isRead = readNow,
                    expiresAt = expiresAt
                ))
                ChatStorage.saveOrUpdateMessage(myId, contact,
                    ChatStorage.StoredMessage(
                        id = videoId,
                        text = "",
                        isOwn = false,
                        videoPath = file.absolutePath,
                        videoDuration = durationSec,
                        isRead = readNow,
                        expiresAt = expiresAt
                    )
                )
                if (readNow) WebSocketClient.sendRead(contact, videoId)
            }
        }
    }

    // Read-receipt dwell flush — mirrors Telegram Desktop: only once the
    // window has held focus continuously for AppFocusTracker.READ_DWELL_MS
    // (see that object's own comment) do currently-unread incoming messages
    // in THIS chat actually get marked read and have their receipts sent.
    // Reruns on every contact switch too (not just the focus transition),
    // so opening a different already-unread chat while already past the
    // dwell flushes it immediately — no second 30s wait per contact.
    LaunchedEffect(contact, AppFocusTracker.isActivelyPresent) {
        if (AppFocusTracker.isActivelyPresent) {
            val unread = messages.filter { !it.fromMe && !it.isRead }
            if (unread.isNotEmpty()) {
                unread.forEach { WebSocketClient.sendRead(contact, it.id) }
                ChatStorage.markIncomingAsRead(myId, contact)
                unread.forEach { u ->
                    val idx = messages.indexOfFirst { it.id == u.id }
                    if (idx >= 0) messages[idx] = messages[idx].copy(isRead = true)
                }
            }
        }
    }

    // Clear typing indicator after 3s silence
    LaunchedEffect(typingTimer) {
        if (typingTimer > 0) {
            kotlinx.coroutines.delay(3000)
            if (System.currentTimeMillis() - typingTimer >= 3000) peerTyping = false
        }
    }

    LaunchedEffect(input) { ChatStorage.saveDraft(myId, contact, input) }
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    // Periodically remove expired messages when auto-delete is active
    LaunchedEffect(autoDeleteSecs) {
        if (autoDeleteSecs <= 0L) return@LaunchedEffect
        while (true) {
            val cutoff = System.currentTimeMillis() - autoDeleteSecs * 1000L
            val expired = messages.filter { it.timestamp < cutoff }
            expired.forEach { msg ->
                messages.removeAll { it.id == msg.id }
                ChatStorage.deleteMessage(myId, contact, msg.id)
            }
            kotlinx.coroutines.delay(60_000L)
        }
    }

    // Sweep disappearing messages whose per-message expiresAt has passed
    // (mirrors Android: countdown starts on send; ChatStorage already skips
    // already-expired rows on load, this handles ones that reach expiry while
    // the chat is open). Runs regardless of the current disappearTimerSecs so
    // messages already stamped with an expiry still vanish even if the timer
    // was later turned off.
    LaunchedEffect(contact) {
        while (true) {
            val now = System.currentTimeMillis()
            val expired = messages.filter { it.expiresAt in 1 until now }
            expired.forEach { msg ->
                messages.removeAll { it.id == msg.id }
                ChatStorage.deleteMessage(myId, contact, msg.id)
            }
            kotlinx.coroutines.delay(1_000L)
        }
    }

    // ── Layout ────────────────────────────────────────────────────────────────
    Column(Modifier.fillMaxSize()) {

        // Top bar
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = { if (searchMode) { searchMode = false; searchQuery = "" } else onBack() }) {
                    Icon(AppIcons.get("BACK_ARROW"), contentDescription = "Назад",
                        tint = SubrosaTheme.textPrimary)
                }
                if (searchMode) {
                    androidx.compose.foundation.text.BasicTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 18.sp, color = SubrosaTheme.textPrimary),
                        cursorBrush = androidx.compose.ui.graphics.SolidColor(SubrosaTheme.accent),
                        decorationBox = { inner ->
                            if (searchQuery.isEmpty()) Text("Поиск по чату…", fontSize = 18.sp, color = SubrosaTheme.textSecondary)
                            inner()
                        }
                    )
                } else {
                    Column(Modifier.weight(1f).clickable(onClick = onOpenContactInfo)) {
                        Text(contactLabel, fontSize = 19.sp, fontWeight = FontWeight.SemiBold,
                            color = SubrosaTheme.textPrimary, fontFamily = NotoSerifJP)
                        if (peerTyping) {
                            Text("печатает…", fontSize = 14.sp, color = SubrosaTheme.accent)
                        } else if (disappearTimerSecs > 0L) {
                            // Always-visible reminder that disappearing messages are
                            // active for this chat — previously the only way to see
                            // this was to open the overflow menu and check the
                            // current radio selection, so a peer turning the timer
                            // on (disappearTimerSecs updates reactively from their
                            // "disappear_timer" frame, see onDisappearTimerChanged
                            // above) was invisible unless you went looking for it.
                            val label = when (disappearTimerSecs) {
                                3600L -> "1ч"
                                86400L -> "24ч"
                                604800L -> "7д"
                                else -> "${disappearTimerSecs / 3600}ч"
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(AppIcons.get("AUTO_DELETE_MESS"), contentDescription = null,
                                    tint = SubrosaTheme.accent, modifier = Modifier.size(12.dp))
                                Spacer(Modifier.width(3.dp))
                                Text("Исчезающие сообщения: $label", fontSize = 13.sp, color = SubrosaTheme.accent)
                            }
                        }
                    }
                }
                // Search and the disappearing-messages timer moved into
                // ContactInfoScreen (reached by tapping the header above) —
                // only the call buttons stay up here now, mirrors Android's
                // identical trim.
                IconButton(onClick = { CallUiState.startCall(contact, false) }) {
                    Icon(
                        AppIcons.get("SOUND_CALL"),
                        contentDescription = "Позвонить",
                        tint = SubrosaTheme.textPrimary,
                        modifier = Modifier.size(28.dp)
                    )
                }
                IconButton(onClick = { CallUiState.startCall(contact, true) }) {
                    Icon(
                        AppIcons.get("VIDEO_CALL"),
                        contentDescription = "Видеозвонок",
                        tint = SubrosaTheme.textPrimary,
                        modifier = Modifier.size(28.dp)
                    )
                }
            }
        }

        // Send-blocked warning — mirrors Android's ChatScreen.kt exactly
        // (s.chatSendBlockedTitle/Text/Confirm there). Dismissible, unlike
        // the key-change dialogs below — this isn't a security decision,
        // just an acknowledgement that further sends are paused.
        if (showSendBlockedWarning) {
            AlertDialog(
                onDismissRequest = { showSendBlockedWarning = false },
                containerColor   = SubrosaTheme.dialog,
                title = { Text("Сообщения не доставляются", color = SubrosaTheme.textPrimary) },
                text = {
                    Text(
                        "Последние ${ContactHealthManager.UNCONFIRMED_SEND_BLOCK_THRESHOLD} сообщений этому " +
                        "контакту не были подтверждены доставкой. Отправка приостановлена, чтобы не " +
                        "отправлять сообщения в пустоту — попробуйте восстановить связь.",
                        color = SubrosaTheme.error
                    )
                },
                confirmButton = {
                    TextButton(onClick = { showSendBlockedWarning = false }) {
                        Text("Понятно", color = SubrosaTheme.accent)
                    }
                }
            )
        }
        // Key-change / revocation warnings — mirrors Android's ChatScreen.kt.
        if (showKeyWarning) {
            AlertDialog(
                onDismissRequest = {},
                containerColor   = SubrosaTheme.dialog,
                title = { Text("Ключ контакта изменился", color = SubrosaTheme.textPrimary) },
                text = {
                    Text(
                        "Identity-ключ этого контакта изменился с момента последнего разговора. " +
                        "Это может значить переустановку приложения на новом устройстве — а может " +
                        "быть признаком подмены. Сверьте отпечаток ключа перед тем как доверять " +
                        "новым сообщениям.",
                        color = SubrosaTheme.error
                    )
                },
                confirmButton = {
                    TextButton(onClick = { KeyHistoryManager.markAsVerified(contact); showKeyWarning = false }) {
                        Text("Понятно", color = SubrosaTheme.accent)
                    }
                }
            )
        }
        if (showRevokedWarning) {
            AlertDialog(
                onDismissRequest = {},
                containerColor   = SubrosaTheme.dialog,
                title = { Text("Ключ контакта отозван", color = SubrosaTheme.textPrimary) },
                text = {
                    Text(
                        "Сервер пометил identity-ключ этого контакта как отозванный. Будьте " +
                        "осторожны с любыми новыми сообщениями от этого контакта.",
                        color = SubrosaTheme.error
                    )
                },
                confirmButton = {
                    TextButton(onClick = { showRevokedWarning = false }) {
                        Text("Понятно", color = SubrosaTheme.accent)
                    }
                }
            )
        }

        // Message list
        val displayedMessages = if (searchMode && searchQuery.isNotBlank())
            messages.filter { it.text?.contains(searchQuery, ignoreCase = true) == true }
        else messages
        LazyColumn(
            modifier      = Modifier.weight(1f).padding(horizontal = 8.dp),
            state         = listState,
            reverseLayout = false
        ) {
            items(displayedMessages, key = { it.id }) { msg ->
                MessageBubble(
                    msg       = msg,
                    allMsgs   = messages,
                    onContext = { contextMsg = it },
                    playingVoiceId = playingVoiceId,
                    voicePlaybackMs = voicePlaybackMs,
                    voiceSpeed = voiceSpeed,
                    onVoicePlayingIdChange = { playingVoiceId = it },
                    onVoiceSeek = { ms -> DesktopVoicePlayer.seekTo(ms); voicePlaybackMs = ms },
                    onVoiceSpeedToggle = {
                        voiceSpeed = when (voiceSpeed) {
                            1f -> 1.5f
                            1.5f -> 2f
                            else -> 1f
                        }
                        playingVoiceId?.let { DesktopVoicePlayer.setSpeed(voiceSpeed, it) }
                    }
                )
                Spacer(Modifier.height(2.dp))
            }
        }

        // ── Edit / Reply bar ─────────────────────────────────────────────────
        if (editingMsg != null) {
            Surface(color = SubrosaTheme.card) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Редактирование", fontSize = 13.sp, color = SubrosaTheme.accent,
                            fontWeight = FontWeight.Bold)
                        Text(editingMsg!!.text ?: "", fontSize = 14.sp,
                            color = SubrosaTheme.textSecondary, maxLines = 1)
                    }
                    IconButton(onClick = { editingMsg = null; input = "" }) {
                        Icon(AppIcons.get("CLOSE"), contentDescription = "Отмена", tint = SubrosaTheme.textSecondary, modifier = Modifier.size(16.dp))
                    }
                }
            }
        } else if (replyingTo != null) {
            Surface(color = SubrosaTheme.card) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier.width(3.dp).height(36.dp)
                            .background(SubrosaTheme.accent)
                    )
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text("Ответ", fontSize = 13.sp, color = SubrosaTheme.accent,
                            fontWeight = FontWeight.Bold)
                        Text(replyingTo!!.text ?: "", fontSize = 14.sp,
                            color = SubrosaTheme.textSecondary, maxLines = 1)
                    }
                    IconButton(onClick = { replyingTo = null }) {
                        Icon(AppIcons.get("CLOSE"), contentDescription = "Отмена", tint = SubrosaTheme.textSecondary, modifier = Modifier.size(16.dp))
                    }
                }
            }
        }

        HorizontalDivider(color = SubrosaTheme.divider, thickness = 0.5.dp)

        // Input bar
        Surface(color = SubrosaTheme.inputBg) {
          Column {
            // Recording bar — mirrors Android's ChatScreen exactly (cancel
            // button, pulsing dot + live mm:ss timer, send button). Entirely
            // missing before this fix: recording had zero visual feedback on
            // Desktop beyond the mic icon flipping to a stop glyph. Found
            // live, 2026-09-18.
            if (isRecordingVoice) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(CircleShape)
                            .background(SubrosaTheme.error.copy(alpha = 0.16f))
                            .clickable {
                                VoiceRecorder.cancel()
                                isRecordingVoice = false
                            },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            AppIcons.get("CLOSE"),
                            contentDescription = "Отменить запись",
                            tint = SubrosaTheme.error,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Row(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(24.dp))
                            .background(SubrosaTheme.error.copy(alpha = 0.10f))
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        val dotAlpha = remember { Animatable(1f) }
                        LaunchedEffect(Unit) {
                            while (true) {
                                dotAlpha.animateTo(0.2f, tween(550))
                                dotAlpha.animateTo(1f, tween(550))
                            }
                        }
                        Box(
                            modifier = Modifier
                                .size(9.dp)
                                .clip(CircleShape)
                                .background(SubrosaTheme.error.copy(alpha = dotAlpha.value))
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = String.format("%d:%02d", recordingSeconds / 60, recordingSeconds % 60),
                            color = SubrosaTheme.textPrimary,
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                    IconButton(onClick = { finishVoiceRecordingAndSend() }) {
                        Icon(AppIcons.get("Send"), contentDescription = "Отправить голосовое",
                            tint = SubrosaTheme.accent)
                    }
                }
            } else {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.Bottom
            ) {
                IconButton(
                    enabled = channelReady,
                    onClick  = {
                        val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Прикрепить файл", java.awt.FileDialog.LOAD)
                        dialog.isVisible = true
                        val fileName = dialog.file
                        val dir      = dialog.directory
                        if (fileName != null && dir != null) {
                            val picked = java.io.File(dir, fileName)
                            val bytes  = runCatching { picked.readBytes() }.getOrNull()
                            if (bytes != null) {
                                val ext = picked.extension.lowercase()
                                val id  = UUID.randomUUID().toString()
                                if (ext in IMAGE_EXTENSIONS) {
                                    val cleanBytes = stripImageMetadata(bytes, ext)
                                    WebSocketClient.sendImage(contact, cleanBytes)
                                    val imgDir  = java.io.File(DesktopStorage.resolveDataDir(), "blobs")
                                        .also { it.mkdirs() }
                                    val imgFile = java.io.File(imgDir, "$id.enc")
                                    runCatching { imgFile.writeBytes(DesktopStorage.encryptRaw(cleanBytes)) }
                                    messages.add(DesktopMessage(id = id, fromMe = true, text = null, imageBytes = cleanBytes))
                                    ChatStorage.saveOrUpdateMessage(myId, contact,
                                        ChatStorage.StoredMessage(id = id, text = "", isOwn = true, imagePath = imgFile.absolutePath))
                                } else {
                                    WebSocketClient.sendFile(contact, picked.name, bytes)
                                    val fileDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs")
                                        .also { it.mkdirs() }
                                    val outFile = java.io.File(fileDir, "$id.enc")
                                    runCatching { outFile.writeBytes(DesktopStorage.encryptRaw(bytes)) }
                                    messages.add(DesktopMessage(id = id, fromMe = true, text = null,
                                        fileName = picked.name, filePath = outFile.absolutePath))
                                    ChatStorage.saveOrUpdateMessage(myId, contact,
                                        ChatStorage.StoredMessage(id = id, text = "", isOwn = true,
                                            filePath = outFile.absolutePath, fileName = picked.name))
                                }
                            }
                        }
                    },
                    modifier = Modifier.padding(bottom = 4.dp)
                ) {
                    Icon(AppIcons.get("ATTACH"), contentDescription = s.chatAttach,
                        tint = SubrosaTheme.textSecondary, modifier = Modifier.size(18.dp))
                }
                Spacer(Modifier.width(2.dp))
                OutlinedTextField(
                    value         = input,
                    onValueChange = {
                        if (channelReady) {
                            input = it
                            // Send typing indicator on each keystroke (throttled by server)
                            WebSocketClient.sendTyping(contact)
                        }
                    },
                    readOnly      = !channelReady,
                    modifier      = Modifier.weight(1f).onPreviewKeyEvent { event ->
                        // onPreviewKeyEvent (tunnel/capture phase), not
                        // onKeyEvent (bubble phase) — a multi-line
                        // OutlinedTextField's own internal key handling
                        // consumes a plain Enter press as "insert newline"
                        // before it would ever bubble back up to an
                        // onKeyEvent modifier on the same node, so Enter
                        // silently just added a newline and never reached
                        // this handler at all. Capturing it on the way down
                        // instead lets us intercept it before that internal
                        // handling gets a chance.
                        if (channelReady && event.type == KeyEventType.KeyDown &&
                            event.key == Key.Enter && !event.isShiftPressed) {
                            doSend(myId, contact, input.trim(), editingMsg, replyingTo, messages,
                                disappearTimerSecs, scope,
                                onBlocked = { showSendBlockedWarning = true }) {
                                editingMsg = null; replyingTo = null
                            }
                            input = ""
                            true
                        } else false
                    },
                    placeholder   = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (!channelReady) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(13.dp),
                                    strokeWidth = 1.5.dp,
                                    color = SubrosaTheme.accent.copy(alpha = 0.7f)
                                )
                                Spacer(Modifier.width(8.dp))
                            }
                            Text(
                                if (channelReady) s.chatMessagePlaceholder else s.chatConnectingPlaceholder,
                                color = SubrosaTheme.textSecondary.copy(alpha = 0.5f)
                            )
                        }
                    },
                    maxLines      = 5,
                    colors        = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent,
                    )
                )
                Spacer(Modifier.width(2.dp))
                Box(
                    modifier = Modifier
                        .padding(bottom = 4.dp)
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(if (isVideoRecordMode) SubrosaTheme.accent.copy(alpha = 0.18f) else Color.Transparent)
                        .pointerInput(isVideoRecordMode, channelReady) {
                            detectTapGestures(
                                onTap = { isVideoRecordMode = !isVideoRecordMode },
                                onLongPress = {
                                    if (!channelReady) return@detectTapGestures
                                    if (isVideoRecordMode) {
                                        showVideoCircleRecorder = true
                                    } else {
                                        isRecordingVoice = VoiceRecorder.start()
                                    }
                                }
                            )
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        AppIcons.get(if (isVideoRecordMode) "VIDEO_CALL" else "Micro"),
                        contentDescription = s.chatVoiceOrVideo,
                        modifier = Modifier.size(18.dp),
                        tint = if (isVideoRecordMode) SubrosaTheme.accent else SubrosaTheme.textSecondary
                    )
                }
                Spacer(Modifier.width(2.dp))
                IconButton(
                    onClick  = {
                        doSend(myId, contact, input.trim(), editingMsg, replyingTo, messages,
                            disappearTimerSecs, scope,
                            onBlocked = { showSendBlockedWarning = true }) {
                            editingMsg = null; replyingTo = null
                        }
                        input = ""
                    },
                    enabled  = input.isNotBlank() && channelReady,
                    modifier = Modifier.padding(bottom = 4.dp)
                ) {
                    Icon(AppIcons.get("Send"), contentDescription = "Отправить",
                        tint = if (input.isNotBlank() && channelReady) SubrosaTheme.accent
                               else SubrosaTheme.textSecondary.copy(alpha = 0.4f))
                }
                IconButton(
                    onClick = {
                        if (!showVirtualKb) vkSeed++
                        showVirtualKb = !showVirtualKb
                    },
                    modifier = Modifier.padding(bottom = 4.dp)
                ) {
                    Icon(
                        AppIcons.get("KEYBOARD"),
                        contentDescription = s.chatKeyboard,
                        tint = if (showVirtualKb) SubrosaTheme.accent else SubrosaTheme.textSecondary
                    )
                }
            }
            }
            if (showVirtualKb) {
                Box(Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                    VirtualKeyboard(
                        seed = vkSeed,
                        onChar = { c -> input += c; WebSocketClient.sendTyping(contact) },
                        onBackspace = { if (input.isNotEmpty()) input = input.dropLast(1) }
                    )
                }
            }
          }
        }
    }

    if (showVideoCircleRecorder) {
        VideoCircleRecorderDialog(
            onDismiss = { showVideoCircleRecorder = false },
            onRecorded = { file, durationSec ->
                showVideoCircleRecorder = false
                scope.launch(Dispatchers.IO) {
                    val plainBytes = runCatching { file.readBytes() }.getOrNull()
                    file.delete()
                    if (plainBytes == null) return@launch
                    val id = java.util.UUID.randomUUID().toString()
                    val fileDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs").also { it.mkdirs() }
                    val outFile = java.io.File(fileDir, "$id.enc")
                    runCatching { outFile.writeBytes(DesktopStorage.encryptRaw(plainBytes)) }
                    WebSocketClient.sendVideoCircle(contact, id, plainBytes, durationSec)
                    withContext(Dispatchers.Main) {
                        messages.add(DesktopMessage(
                            id = id, fromMe = true, text = null,
                            videoPath = outFile.absolutePath, videoDuration = durationSec
                        ))
                        ChatStorage.saveOrUpdateMessage(myId, contact,
                            ChatStorage.StoredMessage(
                                id = id, text = "", isOwn = true,
                                videoPath = outFile.absolutePath, videoDuration = durationSec
                            )
                        )
                    }
                }
            }
        )
    }

    // ── Context menu ──────────────────────────────────────────────────────────
    contextMsg?.let { msg ->
        ContextMenuDialog(
            msg       = msg,
            onDismiss = { contextMsg = null },
            onReact   = { emoji ->
                val i = messages.indexOfFirst { it.id == msg.id }
                if (i >= 0) {
                    val updated = messages[i].copy(
                        reactions = messages[i].reactions.toMutableMap().also { it[myId] = emoji }
                    )
                    messages[i] = updated
                    ChatStorage.saveOrUpdateMessage(myId, contact,
                        ChatStorage.StoredMessage(
                            id = updated.id, text = updated.text ?: "", isOwn = updated.fromMe,
                            timestamp = updated.timestamp, reactions = updated.reactions,
                            expiresAt = updated.expiresAt))
                    WebSocketClient.sendReaction(contact, updated.id, emoji)
                }
                contextMsg = null
            },
            onCopy    = {
                val copiedText = msg.text ?: ""
                clipboard.setText(AnnotatedString(copiedText))
                NativeProtection.excludeClipboardFromHistoryAndCloud()
                scope.launch {
                    kotlinx.coroutines.delay(CLIPBOARD_CLEAR_DELAY_MS)
                    if (clipboard.getText()?.text == copiedText) {
                        clipboard.setText(AnnotatedString(""))
                    }
                }
                contextMsg = null
            },
            onEdit    = {
                editingMsg = msg
                input      = msg.text ?: ""
                contextMsg = null
            },
            onReply   = {
                replyingTo = msg
                contextMsg = null
            },
            onRetry   = if (msg.isFailed && msg.text != null) {{
                val sent = WebSocketClient.sendText(contact, msg.text, msg.id)
                if (sent) {
                    val i = messages.indexOfFirst { it.id == msg.id }
                    if (i >= 0) {
                        messages[i] = messages[i].copy(isFailed = false)
                        ChatStorage.saveOrUpdateMessage(myId, contact,
                            ChatStorage.StoredMessage(id = msg.id, text = msg.text,
                                isOwn = true, replyToId = msg.replyToId, isFailed = false))
                    }
                }
                contextMsg = null
            }} else null,
            onForward = {
                forwardingMsg = msg
                contextMsg    = null
            },
            onDelete  = { forAll ->
                val i = messages.indexOfFirst { it.id == msg.id }
                if (i >= 0) messages.removeAt(i)
                ChatStorage.deleteMessage(myId, contact, msg.id)
                if (forAll) WebSocketClient.sendDelete(contact, msg.id)
                contextMsg = null
            }
        )
    }

    // ── Forward dialog ────────────────────────────────────────────────────────
    forwardingMsg?.let { msg ->
        ForwardDialog(
            msg            = msg,
            myId           = myId,
            excludeContact = contact,
            onDismiss      = { forwardingMsg = null },
            onForward      = { targetContact ->
                when {
                    msg.imageBytes != null -> {
                        val fwdId  = UUID.randomUUID().toString()
                        WebSocketClient.sendImage(targetContact, msg.imageBytes, msg.geoCoords)
                        val imgDir  = java.io.File(DesktopStorage.resolveDataDir(), "blobs")
                            .also { it.mkdirs() }
                        val imgFile = java.io.File(imgDir, "$fwdId.enc")
                        runCatching { imgFile.writeBytes(DesktopStorage.encryptRaw(msg.imageBytes)) }
                        ChatStorage.saveOrUpdateMessage(
                            myId, targetContact,
                            ChatStorage.StoredMessage(
                                id        = fwdId,
                                text      = msg.geoCoords ?: "",
                                isOwn     = true,
                                imagePath = imgFile.absolutePath
                            )
                        )
                    }
                    msg.fileName != null && msg.filePath != null -> {
                        val bytes = runCatching {
                            val raw = java.io.File(msg.filePath).readBytes()
                            if (msg.filePath.endsWith(".enc")) DesktopStorage.decryptRaw(raw) else raw
                        }.getOrNull()
                        if (bytes != null) {
                            val fwdId = UUID.randomUUID().toString()
                            WebSocketClient.sendFile(targetContact, msg.fileName, bytes)
                            val fileDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs")
                                .also { it.mkdirs() }
                            val outFile = java.io.File(fileDir, "$fwdId.enc")
                            runCatching { outFile.writeBytes(DesktopStorage.encryptRaw(bytes)) }
                            ChatStorage.saveOrUpdateMessage(
                                myId, targetContact,
                                ChatStorage.StoredMessage(
                                    id = fwdId, text = "", isOwn = true,
                                    filePath = outFile.absolutePath, fileName = msg.fileName
                                )
                            )
                        }
                    }
                    msg.text != null -> {
                        val fwdId = UUID.randomUUID().toString()
                        WebSocketClient.sendText(targetContact, msg.text, fwdId)
                        ChatStorage.saveOrUpdateMessage(
                            myId, targetContact,
                            ChatStorage.StoredMessage(id = fwdId, text = msg.text, isOwn = true)
                        )
                    }
                }
                forwardingMsg = null
            }
        )
    }

}

// ── Message bubble ────────────────────────────────────────────────────────────

@Composable
private fun MessageBubble(
    msg:      DesktopMessage,
    allMsgs:  List<DesktopMessage>,
    onContext: (DesktopMessage) -> Unit,
    playingVoiceId: String? = null,
    voicePlaybackMs: Int = 0,
    voiceSpeed: Float = 1f,
    onVoicePlayingIdChange: (String?) -> Unit = {},
    onVoiceSeek: (Int) -> Unit = {},
    onVoiceSpeedToggle: () -> Unit = {}
) {
    val isOwn   = msg.fromMe
    val bgColor = if (isOwn) SubrosaTheme.bubbleOwn else SubrosaTheme.bubbleOther

    // Find replied-to message
    val repliedMsg = msg.replyToId?.let { id -> allMsgs.find { it.id == id } }

    Box(
        Modifier.fillMaxWidth(),
        contentAlignment = if (isOwn) Alignment.CenterEnd else Alignment.CenterStart
    ) {
        Surface(
            shape          = MaterialTheme.shapes.medium,
            // Video circles get a transparent, zero-padding bubble —
            // otherwise the round video note sits padded inside a solid
            // rounded-rect card, which is exactly the "rectangular
            // attachment with a circle inside" look the video-note redesign
            // was meant to remove. Never fixed here before — only the
            // circle's own inner rendering had been redesigned.
            color          = if (msg.videoPath != null) Color.Transparent else bgColor,
            modifier       = Modifier
                .widthIn(max = 520.dp)
                .contextMenuTarget(onContext, msg)
        ) {
            Column(
                Modifier.padding(
                    horizontal = if (msg.videoPath != null) 0.dp else 12.dp,
                    vertical = if (msg.videoPath != null) 0.dp else 8.dp
                )
            ) {

                // Reply quote
                repliedMsg?.let { r ->
                    Surface(
                        shape  = MaterialTheme.shapes.small,
                        color  = SubrosaTheme.bubbleSystem,
                        modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp)
                    ) {
                        Row(Modifier.padding(6.dp)) {
                            Box(Modifier.width(3.dp).fillMaxHeight().background(SubrosaTheme.accent))
                            Spacer(Modifier.width(6.dp))
                            Text(r.text ?: "", fontSize = 14.sp,
                                color = SubrosaTheme.textSecondary, maxLines = 2)
                        }
                    }
                }

                // Image
                if (msg.imageBytes != null) {
                    val bitmap = remember(msg.id) {
                        androidx.compose.ui.res.loadImageBitmap(msg.imageBytes.inputStream())
                    }
                    androidx.compose.foundation.Image(
                        bitmap             = bitmap,
                        contentDescription = null,
                        modifier           = Modifier.widthIn(max = 400.dp).heightIn(max = 300.dp)
                    )
                    Spacer(Modifier.height(4.dp))
                }

                // Video circle (Telegram-style round video message). Time +
                // ticks overlaid on the circle itself (see the Footer Row
                // further down, skipped for video) instead of as a separate
                // row below — the circle has zero padding around it now, so
                // a lone footer row would have nothing to align against.
                if (msg.videoPath != null) {
                    Box {
                        VideoCircleRow(msg.id, msg.videoPath, msg.videoDuration)
                        Row(
                            modifier = Modifier
                                .align(Alignment.BottomStart)
                                .padding(8.dp)
                                .background(Color(0x88000000), androidx.compose.foundation.shape.CircleShape)
                                .padding(horizontal = 6.dp, vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(formatTime(msg.timestamp), fontSize = 11.sp, color = Color.White)
                            if (isOwn) {
                                Spacer(Modifier.width(3.dp))
                                if (msg.isFailed) {
                                    Icon(AppIcons.get("ERROR"), contentDescription = null,
                                        tint = SubrosaTheme.error, modifier = Modifier.size(11.dp))
                                } else {
                                    val (icon, tickColor) = when {
                                        msg.isRead      -> "DELIVERED_DOUBLE" to SubrosaTheme.readTick
                                        msg.isDelivered -> "DELIVERED_DOUBLE" to Color.White.copy(alpha = 0.8f)
                                        else            -> "DELIVERED"        to Color.White.copy(alpha = 0.8f)
                                    }
                                    Icon(AppIcons.get(icon), contentDescription = null,
                                        tint = tickColor, modifier = Modifier.size(11.dp))
                                }
                            }
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                }

                // File (non-image attachment)
                if (msg.fileName != null) {
                    FileRow(
                        messageId     = msg.id,
                        fileName      = msg.fileName,
                        filePath      = msg.filePath,
                        voiceDuration = msg.voiceDuration,
                        playingId     = playingVoiceId,
                        playbackMs    = voicePlaybackMs,
                        speed         = voiceSpeed,
                        onPlayingIdChange = onVoicePlayingIdChange,
                        onSeek        = onVoiceSeek,
                        onSpeedToggle = onVoiceSpeedToggle
                    )
                    Spacer(Modifier.height(4.dp))
                }

                // Geo
                if (msg.geoCoords != null) {
                    GeoRow(msg.geoCoords)
                    Spacer(Modifier.height(4.dp))
                }

                // Text
                if (!msg.text.isNullOrEmpty()) {
                    Text(msg.text, fontSize = 16.sp, color = SubrosaTheme.textPrimary)
                }

                // Footer: timestamp + edited + read ticks — skipped for
                // video circles, which show their own time+ticks overlay on
                // the circle itself (see above).
                if (msg.videoPath == null) Row(
                    Modifier.align(Alignment.End).padding(top = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (msg.isEdited) {
                        Text("ред.", fontSize = 12.sp, color = SubrosaTheme.textSecondary)
                    }
                    Text(
                        formatTime(msg.timestamp),
                        fontSize = 12.sp,
                        color    = SubrosaTheme.textSecondary
                    )
                    if (isOwn) {
                        if (msg.isFailed) {
                            Icon(AppIcons.get("ERROR"), contentDescription = null,
                                tint = SubrosaTheme.error, modifier = Modifier.size(12.dp))
                        } else {
                            val (icon, tickColor) = when {
                                msg.isRead      -> "DELIVERED_DOUBLE" to SubrosaTheme.readTick
                                msg.isDelivered -> "DELIVERED_DOUBLE" to SubrosaTheme.sentTick
                                else            -> "DELIVERED"        to SubrosaTheme.sentTick
                            }
                            Icon(AppIcons.get(icon), contentDescription = null,
                                tint = tickColor, modifier = Modifier.size(12.dp))
                        }
                    }
                }

                // Reactions (mirrors Android: group by emoji, show a count when
                // more than one reactor picked the same emoji).
                if (msg.reactions.isNotEmpty()) {
                    Row(
                        Modifier
                            .padding(top = 2.dp)
                            .background(SubrosaTheme.bubbleSystem, MaterialTheme.shapes.small)
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        msg.reactions.values.groupBy { it }.forEach { (emoji, reactors) ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(emoji, fontSize = 15.sp)
                                if (reactors.size > 1) {
                                    Text(" ${reactors.size}", fontSize = 13.sp,
                                        color = SubrosaTheme.textPrimary)
                                }
                            }
                        }
                    }
                }

            }
        }
    }
}

// ── Context menu dialog ───────────────────────────────────────────────────────

@Composable
private fun ContextMenuDialog(
    msg:      DesktopMessage,
    onDismiss: () -> Unit,
    onReact:   (String) -> Unit,
    onCopy:    () -> Unit,
    onEdit:    () -> Unit,
    onReply:   () -> Unit,
    onRetry:   (() -> Unit)? = null,
    onForward: () -> Unit,
    onDelete:  (forAll: Boolean) -> Unit
) {
    var showDeleteConfirm by remember { mutableStateOf(false) }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = onDismiss,
            containerColor   = SubrosaTheme.dialog,
            title = { Text("Удалить сообщение?", color = SubrosaTheme.textPrimary) },
            confirmButton = {
                Column {
                    // S6-54 (external review 2026-09-06): UI-side gating is
                    // not the security control (receive-side authorization
                    // in WebSocketClient.kt is), but this was previously
                    // shown even for a contact's own message, unlike
                    // Android's equivalent dialog -- matching that pattern.
                    if (msg.fromMe) {
                        TextButton(onClick = { onDelete(true) }) {
                            Text("Удалить у всех", color = SubrosaTheme.error)
                        }
                    }
                    TextButton(onClick = { onDelete(false) }) {
                        Text("Удалить у себя", color = SubrosaTheme.textPrimary)
                    }
                    TextButton(onClick = onDismiss) {
                        Text("Отмена", color = SubrosaTheme.textSecondary)
                    }
                }
            }
        )
        return
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title = {
            Text(
                msg.text?.take(40)?.let { if (it.length < (msg.text.length)) "$it…" else it } ?: "",
                fontSize = 15.sp,
                color    = SubrosaTheme.textSecondary
            )
        },
        text = {
            Column {
                // Reaction picker — same 6 emojis Android's picker offers, in
                // the same order. Tapping sends a `reaction` for this message.
                Row(
                    Modifier.fillMaxWidth().padding(bottom = 6.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    listOf("❤️", "👍", "😂", "😮", "😢", "🔥").forEach { emoji ->
                        Text(
                            text = emoji, fontSize = 26.sp,
                            modifier = Modifier
                                .clickable { onReact(emoji) }
                                .padding(4.dp)
                        )
                    }
                }
                ContextItem("Ответить", onClick = onReply)
                if (msg.fromMe && msg.isFailed && onRetry != null)
                    ContextItem("Повторить отправку", onClick = onRetry)
                if (!msg.text.isNullOrEmpty()) ContextItem("Копировать", onClick = onCopy)
                if (msg.fromMe && !msg.isFailed) ContextItem("Редактировать", onClick = onEdit)
                if (!msg.text.isNullOrEmpty() || msg.imageBytes != null || msg.fileName != null) ContextItem("Переслать", onClick = onForward)
                ContextItem("Удалить", color = SubrosaTheme.error,
                    onClick = { showDeleteConfirm = true })
            }
        },
        confirmButton = {}
    )
}

@Composable
private fun ContextItem(
    label:   String,
    color:   Color = SubrosaTheme.textPrimary,
    onClick: () -> Unit
) {
    TextButton(
        onClick  = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(label, color = color, modifier = Modifier.align(Alignment.CenterVertically))
    }
}

// ── Geo row ───────────────────────────────────────────────────────────────────

@Composable
private fun GeoRow(coords: String) {
    val parts  = coords.split(",")
    val lat    = parts.getOrNull(0)?.trim()?.toDoubleOrNull() ?: return
    val lon    = parts.getOrNull(1)?.trim()?.toDoubleOrNull() ?: return
    val latFmt = "%.6f".format(lat)
    val lonFmt = "%.6f".format(lon)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                runCatching {
                    Desktop.getDesktop().browse(
                        URI("https://www.openstreetmap.org/?mlat=$lat&mlon=$lon&zoom=17"))
                }
            }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(AppIcons.get("GEO"), contentDescription = null, tint = SubrosaTheme.textPrimary,
            modifier = Modifier.size(22.dp).padding(end = 8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "$latFmt, $lonFmt",
                fontSize = 14.sp,
                color = SubrosaTheme.textPrimary
            )
            Text(
                "Открыть в картах",
                fontSize = 13.sp,
                color = SubrosaTheme.accent
            )
        }
    }
}

// ── Video circle ──────────────────────────────────────────────────────────────

/** Telegram-style round video message bubble — ported from Android's
 *  VideoCircleScreen bubble rendering. Compose Desktop has no built-in video
 *  player widget (unlike Android's VideoView), so this shows a circular
 *  thumbnail (first frame, extracted via ffmpeg) with a play overlay; a
 *  click decrypts the video to a temp file and opens it in the system's
 *  default player — the same "open externally" pattern FileRow already uses
 *  for generic (non-voice) attachments, rather than building a custom
 *  in-app frame-sequence video renderer.
 *
 *  Same thin-ring visual language as Android's VideoCircleBubble, but the
 *  ring here is a static neutral outline only — playback happens in an
 *  external player Desktop doesn't get progress callbacks from, so there's
 *  no in-app "playing" state to drive an accent progress arc without
 *  changing how playback itself works (out of scope for this pass). */
@Composable
private fun VideoCircleRow(messageId: String, videoPath: String?, duration: Int) {
    val scope = rememberCoroutineScope()
    var thumbnail by remember(messageId) { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    LaunchedEffect(messageId, videoPath) {
        if (videoPath == null) return@LaunchedEffect
        thumbnail = withContext(Dispatchers.IO) { extractVideoThumbnail(videoPath) }
    }
    val ringStroke = 3.dp
    val ringGap = 3.dp
    Box(
        modifier = Modifier
            .size(150.dp)
            .clickable(enabled = videoPath != null) {
                if (videoPath == null) return@clickable
                scope.launch(Dispatchers.IO) {
                    val plain = decryptToBytes(videoPath) ?: return@launch
                    val tmp = java.io.File.createTempFile("Subrosa_vc_", ".mp4")
                    runCatching {
                        tmp.writeBytes(plain)
                        SecureMemory.wipe(plain)
                        Runtime.getRuntime().addShutdownHook(Thread { DesktopStorage.secureDelete(tmp) })
                        Desktop.getDesktop().open(tmp)
                    }
                    kotlinx.coroutines.delay(ATTACHMENT_TEMP_FILE_TTL_MS)
                    DesktopStorage.secureDelete(tmp)
                }
            },
        contentAlignment = Alignment.Center
    ) {
        androidx.compose.foundation.Canvas(modifier = Modifier.fillMaxSize()) {
            val strokePx = ringStroke.toPx()
            val inset = strokePx / 2f
            drawArc(
                color = SubrosaTheme.textSecondary.copy(alpha = 0.35f),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                topLeft = androidx.compose.ui.geometry.Offset(inset, inset),
                size = androidx.compose.ui.geometry.Size(size.width - strokePx, size.height - strokePx),
                style = androidx.compose.ui.graphics.drawscope.Stroke(width = strokePx, cap = androidx.compose.ui.graphics.StrokeCap.Round)
            )
        }
        Box(
            modifier = Modifier
                .padding(ringStroke + ringGap)
                .fillMaxSize()
                .clip(androidx.compose.foundation.shape.CircleShape)
                .background(SubrosaTheme.card),
            contentAlignment = Alignment.Center
        ) {
            thumbnail?.let { thumb ->
                androidx.compose.foundation.Image(
                    bitmap = thumb,
                    contentDescription = null,
                    modifier = Modifier.fillMaxSize(),
                    contentScale = androidx.compose.ui.layout.ContentScale.Crop
                )
            }
            Box(
                modifier = Modifier.size(36.dp).clip(androidx.compose.foundation.shape.CircleShape)
                    .background(Color(0x55000000)),
                contentAlignment = Alignment.Center
            ) {
                Icon(AppIcons.get("PLAY"), contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
            }
            if (duration > 0) {
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(8.dp)
                        .background(Color(0x88000000), androidx.compose.foundation.shape.CircleShape)
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text("$duration\"", fontSize = 12.sp, color = Color.White)
                }
            }
        }
    }
}

private fun extractVideoThumbnail(videoPath: String): androidx.compose.ui.graphics.ImageBitmap? {
    val plain = decryptToBytes(videoPath) ?: return null
    val tmpIn = java.io.File.createTempFile("Subrosa_vcthumb_in_", ".mp4")
    val tmpOut = java.io.File.createTempFile("Subrosa_vcthumb_out_", ".jpg")
    return try {
        tmpIn.writeBytes(plain)
        val ffmpegPath = ws.schild.jave.process.ffmpeg.DefaultFFMPEGLocator().executablePath
        val proc = ProcessBuilder(
            ffmpegPath, "-y", "-i", tmpIn.absolutePath,
            "-vframes", "1", "-f", "image2", tmpOut.absolutePath
        ).redirectErrorStream(true).start()
        proc.inputStream.bufferedReader().readText()
        proc.waitFor()
        if (tmpOut.exists() && tmpOut.length() > 0L) {
            androidx.compose.ui.res.loadImageBitmap(tmpOut.inputStream())
        } else null
    } catch (e: Exception) {
        null
    } finally {
        tmpIn.delete(); tmpOut.delete()
    }
}

// ── File row ──────────────────────────────────────────────────────────────────

private fun decryptToBytes(filePath: String): ByteArray? = runCatching {
    val encFile = java.io.File(filePath)
    if (!encFile.exists()) return@runCatching null
    val raw = encFile.readBytes()
    if (filePath.endsWith(".enc")) DesktopStorage.decryptRaw(raw) else raw
}.getOrNull()

private const val ATTACHMENT_TEMP_FILE_TTL_MS = 5 * 60_000L

@Composable
private fun FileRow(
    messageId: String,
    fileName: String,
    filePath: String?,
    voiceDuration: Int,
    playingId: String? = null,
    playbackMs: Int = 0,
    speed: Float = 1f,
    onPlayingIdChange: (String?) -> Unit = {},
    onSeek: (Int) -> Unit = {},
    onSpeedToggle: () -> Unit = {}
) {
    val isVoice = fileName == VoiceRecorder.FILE_NAME
    val scope = rememberCoroutineScope()

    if (isVoice) {
        val isThisPlaying = playingId == messageId
        // Waveform decoded off the main thread and cached by messageId — see
        // DesktopVoicePlayer.getWaveform's own comment (it re-decodes every
        // call, so caching here avoids redoing that on every recomposition).
        var waveformBars by remember(messageId) { mutableStateOf(FloatArray(32)) }
        LaunchedEffect(messageId, filePath) {
            if (filePath == null) return@LaunchedEffect
            waveformBars = withContext(Dispatchers.IO) {
                decryptToBytes(filePath)?.let { DesktopVoicePlayer.getWaveform(it) } ?: FloatArray(32)
            }
        }
        val totalMs = if (isThisPlaying) {
            DesktopVoicePlayer.getDurationMs().takeIf { it > 0 } ?: (voiceDuration * 1000)
        } else voiceDuration * 1000
        val progress = if (isThisPlaying && totalMs > 0) {
            (playbackMs.toFloat() / totalMs).coerceIn(0f, 1f)
        } else 0f
        val shownSeconds = if (isThisPlaying) playbackMs / 1000 else voiceDuration

        fun startPlayback(seekFraction: Float? = null) {
            if (filePath == null) return
            val bytes = decryptToBytes(filePath) ?: return
            DesktopVoicePlayer.play(bytes, messageId, speed) { onPlayingIdChange(null) }
            onPlayingIdChange(messageId)
            if (seekFraction != null) {
                val targetMs = (seekFraction * DesktopVoicePlayer.getDurationMs()).toInt()
                DesktopVoicePlayer.seekTo(targetMs)
                onSeek(targetMs)
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                shape = androidx.compose.foundation.shape.CircleShape,
                color = SubrosaTheme.accent,
                modifier = Modifier.size(36.dp),
                onClick = {
                    if (isThisPlaying) {
                        DesktopVoicePlayer.stop()
                        onPlayingIdChange(null)
                    } else {
                        startPlayback()
                    }
                }
            ) {
                Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                    Icon(AppIcons.get(if (isThisPlaying) "PAUSE" else "PLAY"), contentDescription = null,
                        tint = Color.White, modifier = Modifier.size(14.dp))
                }
            }
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                VoiceWaveform(
                    bars = waveformBars,
                    progress = progress,
                    color = SubrosaTheme.accent,
                    dimColor = SubrosaTheme.accent.copy(alpha = 0.3f),
                    onSeek = { frac ->
                        if (!isThisPlaying) startPlayback(seekFraction = frac)
                        else {
                            val targetMs = (frac * totalMs).toInt()
                            DesktopVoicePlayer.seekTo(targetMs)
                            onSeek(targetMs)
                        }
                    }
                )
                Text("0:${shownSeconds.toString().padStart(2, '0')}",
                    fontSize = 13.sp, color = SubrosaTheme.textSecondary)
            }
            Spacer(Modifier.width(6.dp))
            Surface(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
                color = SubrosaTheme.accent.copy(alpha = if (speed != 1f) 0.9f else 0.15f),
                modifier = Modifier.clickable { onSpeedToggle() }
            ) {
                Text(
                    when (speed) {
                        1.5f -> "1.5×"
                        2f -> "2×"
                        else -> "1×"
                    },
                    fontSize = 13.sp,
                    color = if (speed != 1f) Color.White else SubrosaTheme.accent,
                    modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
                )
            }
        }
        return
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = filePath != null) {
                if (filePath == null) return@clickable
                val plain = decryptToBytes(filePath) ?: return@clickable
                runCatching {
                    val tmp = java.io.File.createTempFile("Subrosa_", "_$fileName")
                    tmp.writeBytes(plain)
                    SecureMemory.wipe(plain)
                    // Best-effort cleanup: a normal delete (or deleteOnExit) leaves
                    // recoverable plaintext on disk. Overwrite it once the external
                    // viewer has had time to read it, and also on JVM shutdown —
                    // this still can't cover a hard crash/kill before either fires.
                    Runtime.getRuntime().addShutdownHook(Thread { DesktopStorage.secureDelete(tmp) })
                    Desktop.getDesktop().open(tmp)
                    scope.launch {
                        kotlinx.coroutines.delay(ATTACHMENT_TEMP_FILE_TTL_MS)
                        DesktopStorage.secureDelete(tmp)
                    }
                }
            }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(AppIcons.get("FILE"), contentDescription = null, tint = SubrosaTheme.textPrimary,
            modifier = Modifier.size(22.dp).padding(end = 8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(fileName, fontSize = 15.sp, color = SubrosaTheme.textPrimary, maxLines = 1)
            Text(
                if (filePath == null) "Недоступно" else "Открыть файл",
                fontSize = 13.sp,
                color = SubrosaTheme.accent
            )
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

private fun doSend(
    myId:       String,
    contact:    String,
    text:       String,
    editingMsg: DesktopMessage?,
    replyingTo: DesktopMessage?,
    messages:   MutableList<DesktopMessage>,
    disappearTimerSecs: Long = 0L,
    scope:      kotlinx.coroutines.CoroutineScope? = null,
    onBlocked:  () -> Unit = {},
    onDone:     () -> Unit
) {
    if (text.isEmpty()) return

    if (editingMsg != null) {
        // Edit existing message — mirrors Android exactly: isSendBlocked()
        // gates only NEW messages, not edits of already-sent ones.
        WebSocketClient.sendEdit(contact, editingMsg.id, text)
        val i = messages.indexOfFirst { it.id == editingMsg.id }
        if (i >= 0) messages[i] = messages[i].copy(text = text, isEdited = true)
        onDone()
        return
    }

    // Mirrors Android's ChatScreen.kt send-button gate exactly — was
    // entirely missing on Desktop (see ContactHealthManager.isSendBlocked()'s
    // own comment). Checked here, once, so both call sites (Enter key and
    // the send button) get it without duplicating the condition.
    if (ContactHealthManager.isSendBlocked(contact)) {
        onBlocked()
        return
    }

    val msgId = UUID.randomUUID().toString()
    val sent  = WebSocketClient.sendText(contact, text, msgId, replyingTo?.id)
    // Disappearing messages: countdown starts on SEND (mirrors Android exactly),
    // applied to our own outgoing messages when a disappear timer is active.
    val expiresAt = if (disappearTimerSecs > 0L)
        System.currentTimeMillis() + disappearTimerSecs * 1000L else 0L
    val newMsg = DesktopMessage(
        id           = msgId,
        fromMe       = true,
        text         = text,
        isFailed     = !sent,
        replyToId    = replyingTo?.id,
        replyPreview = replyingTo?.text?.take(60),
        expiresAt    = expiresAt
    )
    messages.add(newMsg)
    ChatStorage.saveOrUpdateMessage(
        myId, contact,
        ChatStorage.StoredMessage(id = msgId, text = text, isOwn = true,
            replyToId = replyingTo?.id, isFailed = !sent, expiresAt = expiresAt)
    )
    if (expiresAt > 0L && scope != null) {
        scope.launch {
            kotlinx.coroutines.delay(disappearTimerSecs * 1000L)
            val idx = messages.indexOfFirst { it.id == msgId }
            if (idx != -1) messages.removeAt(idx)
            ChatStorage.deleteMessage(myId, contact, msgId)
        }
    }
    onDone()
}

private fun formatTime(ts: Long): String {
    val cal     = Calendar.getInstance()
    val today   = cal.get(Calendar.DAY_OF_YEAR)
    cal.timeInMillis = ts
    return if (cal.get(Calendar.DAY_OF_YEAR) == today) {
        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ts))
    } else {
        SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(Date(ts))
    }
}

// ── Forward dialog ────────────────────────────────────────────────────────────

@Composable
private fun ForwardDialog(
    msg:            DesktopMessage,
    myId:           String,
    excludeContact: String,
    onDismiss:      () -> Unit,
    onForward:      (targetContact: String) -> Unit
) {
    val contacts = remember {
        ChatStorage.getContacts().filter { it != excludeContact }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title = {
            Text("Переслать сообщение", color = SubrosaTheme.textPrimary)
        },
        text = {
            if (contacts.isEmpty()) {
                Text("Нет других контактов", color = SubrosaTheme.textSecondary,
                    modifier = Modifier.padding(vertical = 8.dp))
            } else {
                Column {
                    contacts.forEach { contactId ->
                        TextButton(
                            onClick  = { onForward(contactId) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                ChatStorage.getContactName(contactId),
                                color    = SubrosaTheme.textPrimary,
                                modifier = Modifier.align(Alignment.CenterVertically)
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена", color = SubrosaTheme.textSecondary)
            }
        }
    )
}

// Extension to attach right-click (desktop) + long-click (fallback) context menu
private fun Modifier.contextMenuTarget(
    onContext: (DesktopMessage) -> Unit,
    msg:       DesktopMessage
): Modifier = this
    .combinedClickable(
        onClick     = {},
        onLongClick = { onContext(msg) }
    )
    .pointerInput(msg) {
        awaitPointerEventScope {
            while (true) {
                val event = awaitPointerEvent()
                if (event.type == PointerEventType.Press &&
                    event.buttons.isSecondaryPressed) {
                    onContext(msg)
                }
            }
        }
    }

// ── Auto-delete dialog ────────────────────────────────────────────────────────

private val AUTO_DELETE_OPTIONS = listOf(
    0L       to "Выключено",
    3600L    to "1 час",
    86400L   to "1 день",
    604800L  to "1 неделя"
)

@Composable
internal fun ChatAutoDeleteDialog(
    current:   Long,
    onSelect:  (Long) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title  = { Text("Автоудаление сообщений", color = SubrosaTheme.textPrimary) },
        text   = {
            Column {
                Text(
                    "Сообщения старше выбранного времени будут удалены только с этого устройства. " +
                    "Собеседник и его копия переписки не затрагиваются — это не то же самое, что " +
                    "«Исчезающие сообщения» (тот таймер согласован с собеседником и удаляет у обеих сторон).",
                    fontSize = 15.sp,
                    color    = SubrosaTheme.textSecondary,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                AUTO_DELETE_OPTIONS.forEach { (secs, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(secs) }
                            .padding(vertical = 10.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = secs == current,
                            onClick  = { onSelect(secs) },
                            colors   = RadioButtonDefaults.colors(
                                selectedColor   = SubrosaTheme.accent,
                                unselectedColor = SubrosaTheme.textSecondary
                            )
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(label, fontSize = 16.sp, color = SubrosaTheme.textPrimary)
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена", color = SubrosaTheme.textSecondary)
            }
        }
    )
}

// Only these 4 values (mirrors Android's disappear dialog and
// CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED — the server rejects anything else).
private val DISAPPEAR_OPTIONS = listOf(
    0L       to "Выключено",
    3600L    to "1 час",
    86400L   to "1 день",
    604800L  to "1 неделя"
)

@Composable
internal fun DisappearTimerDialog(
    current:   Long,
    onSelect:  (Long) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title  = { Text("Исчезающие сообщения", color = SubrosaTheme.textPrimary) },
        text   = {
            Column {
                Text(
                    "Новые отправленные сообщения исчезнут через выбранное время у обеих сторон",
                    fontSize = 15.sp,
                    color    = SubrosaTheme.textSecondary,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                DISAPPEAR_OPTIONS.forEach { (secs, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(secs) }
                            .padding(vertical = 10.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = secs == current,
                            onClick  = { onSelect(secs) },
                            colors   = RadioButtonDefaults.colors(
                                selectedColor   = SubrosaTheme.accent,
                                unselectedColor = SubrosaTheme.textSecondary
                            )
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(label, fontSize = 16.sp, color = SubrosaTheme.textPrimary)
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена", color = SubrosaTheme.textSecondary)
            }
        }
    )
}
