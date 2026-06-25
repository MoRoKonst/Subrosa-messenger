package com.bcon.messenger

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
import com.bcon.messenger.ui.theme.LocalBeaconColors
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

val JetBrainsMono = FontFamily(
    androidx.compose.ui.text.font.Font(R.font.jetbrainsmono_regular)
)

private const val CHAT_PAGE_SIZE = 50

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
    val isFailed: Boolean = false
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    username: String,
    recipient: String,
    onBack: () -> Unit,
    onStartCall: ((isVideo: Boolean) -> Unit)? = null,
    onVerifyKey: () -> Unit = {}
) {
    var isRecording by remember { mutableStateOf(false) }
    var recordingFile by remember { mutableStateOf<File?>(null) }
    var isVideoMode by remember { mutableStateOf(false) }
    var recordingSeconds by remember { mutableStateOf(0) }
    var showAttachMenu by remember { mutableStateOf(false) }
    var playingVoiceId by remember { mutableStateOf<String?>(null) }
    var playingVideoId by remember { mutableStateOf<String?>(null) }
    var showKeyWarning by remember { mutableStateOf(false) }
    var isTorConnected by remember { mutableStateOf(TorManager.isConnected) }
    val context = LocalContext.current
    var torWarningDismissed by remember {
        mutableStateOf(
            context.getSharedPreferences("beacon_prefs", Context.MODE_PRIVATE)
                .getBoolean("tor_warning_dismissed", false)
        )
    }
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val userId = UserStorage.getUserId(context)
    // Лаунчер разрешений для звонков
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
    // Активные таймеры ожидания подтверждения доставки (messageId → Job)
    val pendingDeliveryJobs = remember { mutableMapOf<String, Job>() }
    var inputText by remember { mutableStateOf("") }
    var showVerifyDialog by remember { mutableStateOf(false) }
    var isOnline by remember { mutableStateOf(false) }
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

    // Геолокация — вспомогательная логика (Fused Location Provider)
    val sendGeo: () -> Unit = {
        scope.launch {
            try {
                val fusedClient = com.google.android.gms.location.LocationServices
                    .getFusedLocationProviderClient(context)

                // Сначала пробуем кешированную локацию
                var loc: android.location.Location? = suspendCancellableCoroutine { cont ->
                    fusedClient.lastLocation
                        .addOnSuccessListener { cont.resume(it, null) }
                        .addOnFailureListener { cont.resume(null, null) }
                }

                // Если кеша нет — запрашиваем свежую локацию через getCurrentLocation
                // BALANCED работает по WiFi без симки и GPS
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
    // ─── Reply / Quote ────────────────────────────────────────────────────────
    var replyToMessage by remember { mutableStateOf<Message?>(null) }
    // ─── Context menu (долгое нажатие) ───────────────────────────────────────
    var contextMenuMessage by remember { mutableStateOf<Message?>(null) }
    // ─── Полноэкранный просмотр фото ──────────────────────────────────────────
    var fullscreenImageBitmap by remember { mutableStateOf<Bitmap?>(null) }
    // ─── Поиск ───────────────────────────────────────────────────────────────
    var searchMode by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    // ─── Таймер исчезающих сообщений ─────────────────────────────────────────
    var disappearTimerSecs by remember { mutableStateOf(0L) }
    var showDisappearDialog by remember { mutableStateOf(false) }
    // ─── Видеокружки ──────────────────────────────────────────────────────────
    var showVideoCircleRecorder by remember { mutableStateOf(false) }
    // ─── Пересылка сообщений ──────────────────────────────────────────────────
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
            videoDuration = msg.videoDuration
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
                service.clearNotifLines("dm_$recipient")

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

                service.onReadReceived = { _ ->
                    messages.forEachIndexed { i, msg ->
                        if (msg.isOwn && !msg.isRead)
                            messages[i] = msg.copy(isRead = true, isDelivered = true)
                    }
                }

                service.onDeliveredReceived = { messageId ->
                    // Подтверждение доставки получено — отменяем таймер недоставки
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

                // Загружаем таймер исчезающих сообщений
                scope.launch(Dispatchers.IO) {
                    val timer = ChatStorage.getDisappearTimer(context, userId, recipient)
                    withContext(Dispatchers.Main) { disappearTimerSecs = timer }
                }

                // Удаление сообщения у всех
                service.onMessageDeleted = { from, messageId ->
                    if (from == recipient) {
                        val idx = messages.indexOfFirst { it.id == messageId }
                        if (idx != -1) messages.removeAt(idx)
                    }
                }

                // Обновление таймера от собеседника
                service.onDisappearTimerChanged = { from, seconds ->
                    if (from == recipient) disappearTimerSecs = seconds
                }

                service.onMessageReceived = { from, _ ->
                    if (from == recipient) {
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

                // Обновляем статус Tor при изменении
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
                        val imageFile = File(context.filesDir, "image_$imageId.jpg.enc")
                        val stream = java.io.ByteArrayOutputStream()
                        stream.write(compressImageForSend(bitmap))
                        SecureFileStorage.write(context, imageFile, stream.toByteArray())
                        messages.add(Message(id = imageId, text = s.chatAttachPhoto, isOwn = false, imageBitmap = bitmap))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(id = imageId, text = s.chatAttachPhoto, isOwn = false, imagePath = imageFile.absolutePath))
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onImageReceived error: ${e.message}")
                    }
                }

                service.onVoiceReceived = { voiceId, voiceFile, duration ->
                    try {
                        SoundManager.playMessageReceived()
                        messages.add(Message(id = voiceId, text = "🎤 Голосовое сообщение", isOwn = false, voiceFile = voiceFile, voiceDuration = duration))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(id = voiceId, text = "🎤 Голосовое сообщение", isOwn = false, voicePath = voiceFile.absolutePath, voiceDuration = duration))
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onVoiceReceived error: ${e.message}")
                    }
                }

                service.onFileReceived = { fileId, file, fileName ->
                    try {
                        SoundManager.playMessageReceived()
                        messages.add(Message(id = fileId, text = "📄 $fileName", isOwn = false))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(id = fileId, text = "📄 $fileName", isOwn = false, filePath = file.absolutePath, fileName = fileName))
                    } catch (e: Exception) {
                        android.util.Log.e("ChatScreen", "onFileReceived error: ${e.message}")
                    }
                }

                service.onVideoReceived = { videoId, file, duration ->
                    try {
                        SoundManager.playMessageReceived()
                        messages.add(Message(
                            id = videoId,
                            text = "🎥 Видеосообщение",
                            isOwn = false,
                            videoPath = file.absolutePath,
                            videoDuration = duration
                        ))
                        ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                            ChatStorage.StoredMessage(
                                id = videoId,
                                text = "🎥 Видеосообщение",
                                isOwn = false,
                                videoPath = file.absolutePath,
                                videoDuration = duration
                            ))
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

    // Загрузка истории
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

    // Бинд сервиса
    LaunchedEffect(Unit) {
        context.bindService(Intent(context, MessengerService::class.java), connection, Context.BIND_AUTO_CREATE)
    }

    // Анимация точек typing indicator
    LaunchedEffect(isTyping) {
        if (isTyping) {
            while (true) {
                delay(400); typingDots = if (typingDots >= 3) 1 else typingDots + 1
            }
        }
    }

    // Фото / Медиа
    LaunchedEffect(Unit) {
        MainActivity.selectedPhotoUri.collect { uri: android.net.Uri? ->
            uri ?: return@collect
            MainActivity.selectedPhotoUri.value = null
            // Если выбрано видео — перенаправляем в файловый pipeline
            val pickedMime = context.contentResolver.getType(uri) ?: ""
            if (pickedMime.startsWith("video/")) {
                MainActivity.selectedFileUri.value = uri
                return@collect
            }
            try {
                val bitmap = android.provider.MediaStore.Images.Media.getBitmap(context.contentResolver, uri)
                val chunks = bitmapToChunks(bitmap)
                if (chunks.sumOf { it.length } > 20 * 1024 * 1024) {
                    android.widget.Toast.makeText(context, s.chatPhotoTooBig, android.widget.Toast.LENGTH_SHORT).show()
                    return@collect
                }
                if (!isOnline) {
                    android.widget.Toast.makeText(context, s.chatMediaOffline, android.widget.Toast.LENGTH_SHORT).show()
                    return@collect
                }
                messengerService?.sendImage(recipient, chunks)
                val imageFile = File(context.filesDir, "image_${UUID.randomUUID()}.jpg.enc")
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

    // Файлы
    LaunchedEffect(Unit) {
        MainActivity.selectedFileUri.collect { uri: android.net.Uri? ->
            uri ?: return@collect
            MainActivity.selectedFileUri.value = null
            try {
                // Получаем информацию о файле
                val cursor = context.contentResolver.query(uri, null, null, null, null)
                val fileName = cursor?.use {
                    if (it.moveToFirst()) {
                        val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        if (nameIndex >= 0) it.getString(nameIndex) else "file"
                    } else "file"
                } ?: "file"

                val mimeType = context.contentResolver.getType(uri) ?: "*/*"

                // Читаем содержимое файла
                val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }

                if (bytes != null && bytes.isNotEmpty()) {
                    // Проверка размера (макс 20MB)
                    if (bytes.size > 20 * 1024 * 1024) {
                        android.widget.Toast.makeText(
                            context,
                            s.chatFileTooBig,
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                        return@collect
                    }

                    // Определяем иконку по типу файла
                    val fileIcon = when {
                        mimeType.startsWith("image/") -> "🖼️"
                        mimeType.startsWith("video/") -> "🎬"
                        mimeType == "application/pdf" -> "📕"
                        mimeType.contains("word") || mimeType.contains("document") -> "📘"
                        else -> "📄"
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

                    // Отправляем файл
                    val chunks = fileToChunks(bytes)
                    val fileId = UUID.randomUUID().toString()
                    messengerService?.sendFile(recipient, fileName, chunks, fileId)

                    // Сохраняем локально
                    val file = File(context.cacheDir, "files/$fileId/$fileName").apply {
                        parentFile?.mkdirs()
                        writeBytes(bytes)
                    }

                    // Добавляем сообщение
                    val displayText = "$fileIcon $fileName"
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

        // ─── TopBar ───────────────────────────────────────────────────────────
        TopAppBar(
            title = {
                if (searchMode) {
                    // Режим поиска — строка ввода вместо имени
                    androidx.compose.foundation.text.BasicTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.fillMaxWidth().padding(end = 8.dp),
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 16.sp, color = Color.White),
                        cursorBrush = androidx.compose.ui.graphics.SolidColor(c.accent),
                        decorationBox = { inner ->
                            if (searchQuery.isEmpty()) Text(s.chatSearchPlaceholder, fontSize = 16.sp, color = Color(0x88FFFFFF), fontFamily = JetBrainsMono)
                            inner()
                        }
                    )
                } else {
                    Row(verticalAlignment = Alignment.CenterVertically) {
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
                                        fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White
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
                            Text(recipientName, fontWeight = FontWeight.SemiBold, fontSize = 18.sp, color = Color.White)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                val statusKey = when {
                                    isTyping -> "typing"
                                    isOnline -> "online"
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
                                                fontSize = 14.sp,
                                                color = c.accent,
                                                fontFamily = JetBrainsMono
                                            )
                                            Spacer(Modifier.width(5.dp))
                                            TypingDotsIndicator(color = c.accent)
                                        }
                                        else -> Text(
                                            text = if (key == "online") s.chatOnline else s.chatOffline,
                                            fontSize = 13.sp,
                                            color = if (key == "online") c.accent else c.textPrimary.copy(alpha = 0.5f)
                                        )
                                    }
                                }
                                if (disappearTimerSecs > 0L) {
                                    val label = when (disappearTimerSecs) {
                                        3600L -> s.chatDisappear1hShort
                                        86400L -> s.chatDisappear24hShort
                                        604800L -> s.chatDisappear7dShort
                                        else -> " · ⏱"
                                    }
                                    Text(label, fontSize = 12.sp, color = c.accent)
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
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = s.back)
                }
            },
            actions = {
                // Поиск
                IconButton(onClick = { searchMode = !searchMode; if (!searchMode) searchQuery = "" }) {
                    Icon(
                        painter = painterResource(if (searchMode) R.drawable.ic_close else R.drawable.ic_search),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(22.dp)
                    )
                }
                // Таймер исчезающих сообщений
                IconButton(onClick = { showDisappearDialog = true }) {
                    Icon(
                        painter = painterResource(R.drawable.ic_timer),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(22.dp)
                    )
                }
                // Меню — звонки и верификация
                var showOverflowMenu by remember { mutableStateOf(false) }
                Box {
                    IconButton(onClick = { showOverflowMenu = true }) {
                        Icon(Icons.Default.MoreVert, s.chatMenu, tint = Color.White)
                    }
                    DropdownMenu(
                        expanded = showOverflowMenu,
                        onDismissRequest = { showOverflowMenu = false },
                        containerColor = c.dialog
                    ) {
                        DropdownMenuItem(
                            text = { Text(s.chatAudioCall, color = Color.White, fontFamily = JetBrainsMono) },
                            onClick = {
                                showOverflowMenu = false
                                pendingCallIsVideo = false
                                callPermissionLauncher.launch(arrayOf(android.Manifest.permission.RECORD_AUDIO))
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(s.chatVideoCall, color = Color.White, fontFamily = JetBrainsMono) },
                            onClick = {
                                showOverflowMenu = false
                                pendingCallIsVideo = true
                                callPermissionLauncher.launch(arrayOf(
                                    android.Manifest.permission.RECORD_AUDIO,
                                    android.Manifest.permission.CAMERA
                                ))
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(s.chatVerifyAction, color = Color.White, fontFamily = JetBrainsMono) },
                            onClick = {
                                showOverflowMenu = false
                                onVerifyKey()
                            }
                        )
                    }
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
        )

        // ─── Tor предупреждение ───────────────────────────────────────────────
        if (!isTorConnected && !torWarningDismissed) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF3D1A00))
                    .padding(start = 14.dp, top = 8.dp, bottom = 8.dp, end = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("⚠️", fontSize = 14.sp)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = s.chatDirectConnection,
                    fontSize = 12.sp,
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
                        imageVector = Icons.Default.Close,
                        contentDescription = null,
                        tint = Color(0xFFFFAA44),
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }

        // ─── Сообщения ────────────────────────────────────────────────────────
        // Фильтруем по поисковому запросу
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
                                Text(s.chatLoadEarlier, color = c.accent, fontFamily = JetBrainsMono, fontSize = 13.sp)
                            }
                        }
                    }
                }
            }
            items(displayedMessages, key = { it.id }) { msg ->
                // Авто-удаление по таймеру (только для отображаемых сообщений)
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
                        playingVideoId = playingVideoId,
                        onVideoPlay = { id -> playingVideoId = id },
                        onVideoStop = { playingVideoId = null },
                        onImageClick = { bmp -> fullscreenImageBitmap = bmp }
                    )
                }
            }
        }
        // FAB прокрутки вниз
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
                    contentColor = Color.White,
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(Icons.Default.KeyboardArrowDown, contentDescription = null, modifier = Modifier.size(22.dp))
                }
            }
        }
        } // end Box

        // ─── Контекстное меню (долгое нажатие) ───────────────────────────────────
        if (contextMenuMessage != null) {
            val ctxMsg = contextMenuMessage!!
            AlertDialog(
                onDismissRequest = { contextMenuMessage = null },
                containerColor = c.dialog,
                title = null,
                text = {
                    Column {
                        // Ответить
                        TextButton(onClick = {
                            replyToMessage = ctxMsg
                            contextMenuMessage = null
                        }) { Text(s.chatContextReply, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        // Переслать
                        if (!ctxMsg.isSystem) {
                            TextButton(onClick = {
                                showForwardDialog = ctxMsg
                                contextMenuMessage = null
                            }) { Text("Переслать", color = Color(0xFF90CAF9), fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Сохранить фото в галерею
                        if (ctxMsg.imageBitmap != null) {
                            TextButton(onClick = {
                                val bmp = ctxMsg.imageBitmap
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val cv = ContentValues().apply {
                                            put(MediaStore.Images.Media.DISPLAY_NAME, "beacon_${System.currentTimeMillis()}.jpg")
                                            put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
                                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                                put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/B-CON")
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
                            }) { Text(s.chatSavePhoto, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Копировать текст (только для текстовых, не голосовых)
                        if (ctxMsg.voiceFile == null && ctxMsg.imageBitmap == null &&
                            ctxMsg.text.isNotEmpty() && !ctxMsg.isSystem) {
                            TextButton(onClick = {
                                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                cm.setPrimaryClip(ClipData.newPlainText("message", ctxMsg.text))
                                contextMenuMessage = null
                                // Авто-очистка буфера через 60 секунд
                                scope.launch {
                                    delay(60_000L)
                                    @Suppress("DEPRECATION")
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                        cm.clearPrimaryClip()
                                    } else {
                                        cm.setPrimaryClip(ClipData.newPlainText("", ""))
                                    }
                                }
                            }) { Text(s.chatContextCopy, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Реакция (только на чужие)
                        if (!ctxMsg.isOwn) {
                            TextButton(onClick = {
                                showReactionPicker = ctxMsg
                                contextMenuMessage = null
                            }) { Text(s.chatContextReaction, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Редактировать (только свои текстовые)
                        if (ctxMsg.isOwn && ctxMsg.text.isNotEmpty() && ctxMsg.voiceFile == null) {
                            TextButton(onClick = {
                                isEditMode = true
                                editingMessageId = ctxMsg.id
                                inputText = ctxMsg.text
                                contextMenuMessage = null
                            }) { Text(s.chatContextEdit, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Удалить у себя
                        TextButton(onClick = {
                            val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                            if (idx != -1) messages.removeAt(idx)
                            scope.launch(Dispatchers.IO) {
                                ChatStorage.deleteMessage(context, userId, recipient, ctxMsg.id)
                            }
                            contextMenuMessage = null
                        }) { Text(s.chatContextDeleteOwn, color = Color(0xFFFF6B6B), fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        // Удалить у всех (только свои)
                        if (ctxMsg.isOwn) {
                            TextButton(onClick = {
                                val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                                if (idx != -1) messages.removeAt(idx)
                                scope.launch(Dispatchers.IO) {
                                    ChatStorage.deleteMessage(context, userId, recipient, ctxMsg.id)
                                }
                                messengerService?.sendDeleteMessage(recipient, ctxMsg.id)
                                contextMenuMessage = null
                            }) { Text(s.chatContextDeleteAll, color = c.error, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                    }
                },
                confirmButton = {}
            )
        }

        // ─── Полноэкранный просмотр фото ─────────────────────────────────────────
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

        // ─── Реакции ─────────────────────────────────────────────────────────────
        if (showReactionPicker != null) {
            AlertDialog(
                onDismissRequest = { showReactionPicker = null },
                containerColor = c.dialog,
                title = { Text(s.chatPickReaction, color = Color.White, fontFamily = JetBrainsMono) },
                text = {
                    Row(horizontalArrangement = Arrangement.SpaceEvenly, modifier = Modifier.fillMaxWidth()) {
                        listOf("❤️", "👍", "😂", "😮", "😢", "🔥").forEach { emoji ->
                            Text(text = emoji, fontSize = 32.sp,
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

        // ─── Диалог таймера исчезающих сообщений ─────────────────────────────────
        if (showDisappearDialog) {
            AlertDialog(
                onDismissRequest = { showDisappearDialog = false },
                containerColor = c.dialog,
                title = { Text(s.chatDisappearTitle, color = Color.White, fontFamily = JetBrainsMono) },
                text = {
                    Column {
                        listOf(
                            0L to s.chatDisappearOff,
                            3600L to s.chatDisappear1h,
                            86400L to s.chatDisappear24h,
                            604800L to s.chatDisappear7d
                        ).forEach { (secs, label) ->
                            Row(
                                modifier = Modifier.fillMaxWidth().clickable {
                                    disappearTimerSecs = secs
                                    scope.launch(Dispatchers.IO) {
                                        ChatStorage.setDisappearTimer(context, userId, recipient, secs)
                                    }
                                    messengerService?.sendDisappearTimer(recipient, secs)
                                    showDisappearDialog = false
                                }.padding(vertical = 12.dp, horizontal = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = disappearTimerSecs == secs,
                                    onClick = null,
                                    colors = RadioButtonDefaults.colors(selectedColor = c.accent)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(label, color = Color.White, fontFamily = JetBrainsMono, fontSize = 15.sp)
                            }
                        }
                    }
                },
                confirmButton = {}
            )
        }

        // Typing indicator с анимированными точками
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
                    fontSize = 13.sp,
                    color = c.textPrimary.copy(alpha = 0.6f),
                    fontFamily = JetBrainsMono
                )
            }
        }
        } // end typing Box

        // Превью ответа на сообщение
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
                    Text(s.chatReplyPreview, fontSize = 11.sp, color = c.accent, fontFamily = JetBrainsMono)
                    Text(replyToMessage!!.text.take(60), fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.7f), maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = JetBrainsMono)
                }
                IconButton(onClick = { replyToMessage = null }) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = null,
                        tint = Color.Gray,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }

        // Режим редактирования
        if (isEditMode) {
            Row(modifier = Modifier.fillMaxWidth().background(c.topBar).padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(s.chatEditing, fontSize = 12.sp, color = c.primaryBlue, modifier = Modifier.weight(1f), fontFamily = JetBrainsMono)
                TextButton(onClick = { isEditMode = false; editingMessageId = null; inputText = "" }) {
                    Text(s.cancel, color = Color.Gray, fontSize = 12.sp, fontFamily = JetBrainsMono)
                }
            }
        }

        // ─── Attach dialog (вынесен из Row, чтобы работал при AnimatedContent) ─
        if (showAttachMenu) {
            AlertDialog(
                onDismissRequest = { showAttachMenu = false },
                title = { Text(s.chatAttach, color = Color.White, fontSize = 20.sp, fontFamily = JetBrainsMono) },
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
                        }) { Text(s.chatAttachMedia, color = Color.White, fontSize = 18.sp, fontFamily = JetBrainsMono) }

                        TextButton(onClick = {
                            showAttachMenu = false
                            try {
                                (context as? MainActivity)?.startActivityForResult(
                                    Intent(Intent.ACTION_GET_CONTENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) },
                                    MainActivity.PICK_FILE_REQUEST
                                )
                            } catch (e: Exception) {}
                        }) { Text(s.chatAttachFile, color = Color.White, fontSize = 18.sp, fontFamily = JetBrainsMono) }

                        TextButton(onClick = {
                            showAttachMenu = false
                            val permGranted = context.checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) ==
                                android.content.pm.PackageManager.PERMISSION_GRANTED
                            if (permGranted) sendGeo()
                            else geoPermLauncher.launch(android.Manifest.permission.ACCESS_FINE_LOCATION)
                        }) { Text(s.chatGeo, color = Color.White, fontSize = 18.sp, fontFamily = JetBrainsMono) }
                    }
                },
                confirmButton = {},
                containerColor = c.dialog
            )
        }

        // ─── Таймер записи ────────────────────────────────────────────────────
        LaunchedEffect(isRecording) {
            if (isRecording) {
                recordingSeconds = 0
                while (isRecording) {
                    delay(1000L)
                    recordingSeconds++
                }
            } else {
                recordingSeconds = 0
            }
        }

        // ─── Панель ввода ─────────────────────────────────────────────────────
        HorizontalDivider(color = Color.White.copy(alpha = 0.06f), thickness = 1.dp)
        AnimatedContent(
            targetState = isRecording,
            transitionSpec = {
                (fadeIn(tween(180)) + scaleIn(tween(180), initialScale = 0.96f)) togetherWith
                (fadeOut(tween(140)) + scaleOut(tween(140), targetScale = 0.96f))
            },
            label = "input_bar_mode"
        ) { recording ->
            if (recording) {
                // ── Режим записи ─────────────────────────────────────────────
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.topBar)
                        .padding(horizontal = 10.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Кнопка отмены
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
                            imageVector = androidx.compose.material.icons.Icons.Default.Close,
                            contentDescription = "Отменить",
                            tint = Color(0xFFFF5555),
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    // Индикатор записи: точка + таймер + mini-волна
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
                            color = Color.White,
                            fontSize = 15.sp,
                            fontFamily = JetBrainsMono,
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        WaveformMicButton(isRecording = true, onClick = {}, size = 38)
                    }

                    // Кнопка подтверждения (отправить голосовое)
                    PortholeSendButton(
                        enabled = true,
                        onClick = {
                            recordingFile?.let { file ->
                                AudioHelper.stopRecording()
                                val duration = (file.length() / 1000).toInt()
                                val voiceId = UUID.randomUUID().toString()
                                val base64 = AudioHelper.encodeToBase64(file)
                                messengerService?.sendVoice(recipient, base64, voiceId, duration)
                                val encFile = File(context.filesDir, "voice_$voiceId.3gp.enc")
                                SecureFileStorage.write(context, encFile, file.readBytes())
                                file.delete()
                                messages.add(Message(id = voiceId, text = "🎤 Голосовое сообщение", isOwn = true, voiceFile = encFile, voiceDuration = duration))
                                ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                    ChatStorage.StoredMessage(id = voiceId, text = "🎤 Голосовое сообщение", isOwn = true, voicePath = encFile.absolutePath, voiceDuration = duration))
                                isRecording = false
                                recordingFile = null
                            }
                        },
                        size = 44
                    )
                }
            } else {
                // ── Обычный режим ────────────────────────────────────────────
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.topBar)
                        .padding(horizontal = 8.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.Bottom,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    // Кнопка вложений
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .clip(CircleShape)
                            .background(Color(0x18FFFFFF))
                            .clickable { showAttachMenu = true },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_attach),
                            contentDescription = null,
                            tint = c.textPrimary.copy(alpha = 0.85f),
                            modifier = Modifier.size(22.dp)
                        )
                    }

                    // Поле ввода
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
                            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 15.sp, color = Color.White),
                            cursorBrush = androidx.compose.ui.graphics.SolidColor(c.accent),
                            interactionSource = inputInteraction,
                            decorationBox = { innerTextField ->
                                if (inputText.isEmpty()) {
                                    Text(
                                        if (isEditMode) s.chatEditHint else s.chatInputHint,
                                        fontSize = 15.sp,
                                        color = Color(0x66FFFFFF),
                                        fontFamily = JetBrainsMono
                                    )
                                }
                                innerTextField()
                            }
                        )
                    }

                    // Правая кнопка: отправить (если есть текст) или медиа-кнопка
                    if (inputText.isNotEmpty() || isEditMode) {
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
                                when {
                                    context.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) ==
                                        android.content.pm.PackageManager.PERMISSION_GRANTED -> {
                                        recordingFile = AudioHelper.startRecording(context)
                                        isRecording = true
                                    }
                                    else -> audioPermissionLauncher.launch(android.Manifest.permission.RECORD_AUDIO)
                                }
                            },
                            onStartVideo = { showVideoCircleRecorder = true },
                            size = 44
                        )
                    }
                }
            }
        }

        // Верификация
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
                title = { Text(s.chatVerifyTitle, color = Color.White) },
                text = {
                    Column {
                        Text(s.chatVerifyFingerprintLabel, fontWeight = FontWeight.Bold, color = Color.White)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(fingerprint, fontSize = 28.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(s.chatVerifyHint, fontSize = 14.sp, color = c.textPrimary)
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showVerifyDialog = false }) { Text(s.close, color = Color.White) }
                },
                containerColor = c.dialog
            )
        }

        // ─── Видеокружок — запись ─────────────────────────────────────────────
        if (showVideoCircleRecorder) {
            VideoCircleRecorder(
                onSend = { videoFile, duration ->
                    showVideoCircleRecorder = false
                    val videoId = UUID.randomUUID().toString()
                    // Шифруем и сохраняем в filesDir/videos
                    scope.launch(Dispatchers.IO) {
                        try {
                            val plainBytes = videoFile.readBytes()  // читаем plain MP4 один раз
                            videoFile.delete()  // удаляем незашифрованный temp CameraX
                            val encFile = File(context.filesDir, "videos/$videoId.mp4.enc").apply {
                                parentFile?.mkdirs()
                            }
                            SecureFileStorage.write(context, encFile, plainBytes)  // шифруем локально

                            withContext(Dispatchers.Main) {
                                messengerService?.sendVideoCircle(recipient, videoId, plainBytes, duration, encFile.absolutePath)
                                messages.add(Message(
                                    id = videoId,
                                    text = "🎥 Видеосообщение",
                                    isOwn = true,
                                    videoPath = encFile.absolutePath,
                                    videoDuration = duration
                                ))
                                ChatStorage.saveOrUpdateMessage(context, userId, recipient,
                                    ChatStorage.StoredMessage(
                                        id = videoId,
                                        text = "🎥 Видеосообщение",
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

        // ─── Диалог пересылки ─────────────────────────────────────────────────
        if (showForwardDialog != null) {
            val forwardMsg = showForwardDialog!!
            val contacts = remember { ChatStorage.getContacts(context) }
            AlertDialog(
                onDismissRequest = { showForwardDialog = null },
                containerColor = c.dialog,
                title = { Text("Переслать", color = Color.White, fontFamily = JetBrainsMono) },
                text = {
                    androidx.compose.foundation.lazy.LazyColumn(
                        modifier = Modifier.heightIn(max = 300.dp)
                    ) {
                        items(contacts.filter { it != userId }) { contactId ->
                            val name = ChatStorage.getContactName(context, contactId)
                            TextButton(
                                onClick = {
                                    showForwardDialog = null
                                    // Пересылаем в зависимости от типа
                                    when {
                                        forwardMsg.videoPath != null -> {
                                            // .enc нужно расшифровать перед отправкой
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
                                            // .enc нужно расшифровать перед отправкой
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
                                Text(name, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp)
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
    playingVideoId: String? = null,
    onVideoPlay: ((String) -> Unit)? = null,
    onVideoStop: (() -> Unit)? = null,
    onImageClick: ((Bitmap) -> Unit)? = null,
    searchQuery: String = ""
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    var showMapDialog by remember { mutableStateOf(false) }

    // Проверяем, является ли сообщение геопозицией (проверяем оба варианта для совместимости)
    val isGeoLocation = msg.text == s.chatGeo || msg.text == "📍 Геопозиция"
    val geoCoordinates = if (isGeoLocation) {
        // Получаем реальные координаты из хранилища
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
                            if (dragAmount > 60) onSwipeToReply?.invoke(msg)   // свайп вправо → ответить
                            else if (dragAmount < -60) onReactionClick?.invoke(msg)  // свайп влево → реакция
                        }
                    }
                }
                .combinedClickable(
                    onClick = {
                        // Если это геопозиция, показываем карту
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
            shadowElevation = 2.dp
        ) {
            Column {
                // Изображения — край в край, без отступов
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
                    // Reply
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
                                Text(s.chatReplyLabel, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = c.accent)
                                Text(msg.replyTo.text, fontSize = 12.sp, maxLines = 2, overflow = TextOverflow.Ellipsis, color = c.textPrimary.copy(alpha = 0.7f))
                            }
                        }
                    }

                    // Геопозиция с превью карты
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
                                fontSize = 12.sp,
                                color = Color.White,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color(0xCC1A237E))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }


                    // Файлы с превью
                    if (msg.fileName != null && msg.filePath != null && msg.imageBitmap == null && !isGeoLocation) {
                        FilePreview(
                            fileName = msg.fileName,
                            filePath = msg.filePath,
                            context = context
                        )
                    }

                    // Видеокружок — инлайн воспроизведение
                    if (msg.videoPath != null) {
                        var thumbnail    by remember(msg.id) { mutableStateOf<android.graphics.Bitmap?>(null) }
                        val isPlaying    = playingVideoId == msg.id
                        var tempVideo    by remember(msg.id) { mutableStateOf<File?>(null) }
                        var isLoading    by remember(msg.id) { mutableStateOf(false) }
                        var videoViewRef by remember(msg.id) { mutableStateOf<android.widget.VideoView?>(null) }

                        // Превью: первый кадр
                        LaunchedEffect(msg.videoPath) {
                            withContext(Dispatchers.IO) {
                                try {
                                    val bytes = SecureFileStorage.read(context, File(msg.videoPath))
                                    val tmp = File(context.cacheDir, "thumb_${msg.id}.mp4")
                                    tmp.writeBytes(bytes)
                                    val retriever = android.media.MediaMetadataRetriever()
                                    retriever.setDataSource(tmp.absolutePath)
                                    thumbnail = retriever.getFrameAtTime(0)
                                    retriever.release()
                                    tmp.delete()
                                } catch (e: Exception) {
                                    android.util.Log.d("VideoCircle", "thumb: ${e.message}")
                                }
                            }
                        }

                        // Загрузка видео при запуске воспроизведения
                        LaunchedEffect(isPlaying) {
                            if (isPlaying && tempVideo == null) {
                                isLoading = true
                                try {
                                    val f = withContext(Dispatchers.IO) {
                                        val bytes = SecureFileStorage.read(context, File(msg.videoPath!!))
                                        val out = File(context.cacheDir, "vplay_${msg.id}.mp4")
                                        out.writeBytes(bytes)
                                        out
                                    }
                                    tempVideo = f
                                } catch (e: Exception) {
                                    android.util.Log.e("VideoCircle", "play: ${e.message}")
                                    onVideoStop?.invoke()
                                } finally {
                                    isLoading = false
                                }
                            }
                        }

                        // Останавливаем VideoView когда этот кружок перестаёт играть
                        LaunchedEffect(isPlaying) {
                            if (!isPlaying) {
                                videoViewRef?.stopPlayback()
                                videoViewRef = null
                                tempVideo?.delete()
                                tempVideo = null
                            }
                        }

                        // Удаляем temp-файл при уходе со страницы
                        DisposableEffect(msg.id) {
                            onDispose {
                                videoViewRef?.stopPlayback()
                                tempVideo?.delete()
                            }
                        }

                        val circleSize by animateDpAsState(
                            targetValue = if (isPlaying) 340.dp else 150.dp,
                            animationSpec = tween(durationMillis = 300),
                            label = "circleSize"
                        )

                        Box(
                            modifier = Modifier
                                .size(circleSize)
                                .clip(CircleShape)
                                .background(Color(0xFF1A1A2E))
                                .clickable {
                                    if (isPlaying) onVideoStop?.invoke()
                                    else onVideoPlay?.invoke(msg.id)
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            val tv = tempVideo
                            if (isPlaying && tv != null) {
                                // ── Воспроизведение прямо в кружке ──
                                AndroidView(
                                    factory = { ctx ->
                                        android.widget.VideoView(ctx).apply {
                                            videoViewRef = this
                                            setVideoPath(tv.absolutePath)
                                            setOnPreparedListener { mp ->
                                                mp.isLooping = true
                                                start()
                                            }
                                            setOnErrorListener { _, _, _ -> true }
                                        }
                                    },
                                    modifier = Modifier.fillMaxSize()
                                )
                                // Кнопка стоп (полупрозрачный крестик)
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .clip(CircleShape)
                                        .background(Color(0x66000000)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        painter = painterResource(R.drawable.ic_stop),
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            } else if (isLoading) {
                                // ── Спиннер загрузки ──
                                CircularProgressIndicator(
                                    color = Color.White,
                                    modifier = Modifier.size(40.dp),
                                    strokeWidth = 2.dp
                                )
                            } else {
                                // ── Превью + кнопка play ──
                                thumbnail?.let {
                                    Image(
                                        bitmap = it.asImageBitmap(),
                                        contentDescription = "Видеосообщение",
                                        modifier = Modifier.fillMaxSize(),
                                        contentScale = androidx.compose.ui.layout.ContentScale.Crop
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .size(44.dp)
                                        .clip(CircleShape)
                                        .background(Color(0x99000000)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        painter = painterResource(R.drawable.ic_play),
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(22.dp)
                                    )
                                }
                                if (msg.videoDuration > 0) {
                                    Box(
                                        modifier = Modifier
                                            .align(Alignment.BottomCenter)
                                            .padding(bottom = 8.dp)
                                            .background(Color(0x88000000), CircleShape)
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text("${msg.videoDuration}\"", fontSize = 12.sp, color = Color.White, fontFamily = JetBrainsMono)
                                    }
                                }
                            }
                        }
                    }

                    // Голосовые сообщения
                    if (msg.voiceFile != null) {
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
                                    if (playingVoiceId == msg.id) {
                                        AudioHelper.stopAudio()
                                        onVoiceStop?.invoke()
                                    } else {
                                        AudioHelper.playAudio(context, msg.voiceFile) { onVoiceStop?.invoke() }
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
                                            if (playingVoiceId == msg.id) R.drawable.ic_pause else R.drawable.ic_play
                                        ),
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(24.dp)
                                    )
                                }
                            }
                            Spacer(Modifier.width(10.dp))
                            Text("${msg.voiceDuration}\"", fontSize = 17.sp, color = c.primaryBlue)
                        }
                    }

                    // Текст сообщения (не показываем для геопозиции и видеосообщений)
                    if (msg.text.isNotEmpty() && msg.text != s.chatAttachPhoto && msg.text != "📷 Фото"
                        && !(isGeoLocation && geoCoordinates != null) && msg.videoPath == null) {
                        val displayText = if (msg.isEdited) "${msg.text} ${s.chatEdited}" else msg.text
                        if (searchQuery.isNotBlank() && displayText.contains(searchQuery, ignoreCase = true)) {
                            // Подсветка совпадения при поиске
                            val lowerText = displayText.lowercase()
                            val lowerQuery = searchQuery.lowercase()
                            val startIdx = lowerText.indexOf(lowerQuery)
                            if (startIdx >= 0) {
                                val endIdx = startIdx + searchQuery.length
                                androidx.compose.ui.text.buildAnnotatedString {
                                    append(displayText.substring(0, startIdx))
                                    withStyle(androidx.compose.ui.text.SpanStyle(
                                        background = c.accent.copy(alpha = 0.4f),
                                        color = Color.White
                                    )) { append(displayText.substring(startIdx, endIdx)) }
                                    append(displayText.substring(endIdx))
                                }.also { annotated ->
                                    Text(text = annotated, fontSize = 18.sp, lineHeight = 20.sp)
                                }
                            } else {
                                Text(text = displayText, fontSize = 18.sp, lineHeight = 20.sp, color = c.textPrimary)
                            }
                        } else {
                            Text(
                                text = displayText,
                                fontSize = 18.sp,
                                lineHeight = 20.sp,
                                color = if (msg.isSystem) c.textPrimary.copy(alpha = 0.6f) else c.textPrimary
                            )
                        }
                    }
                }

                // Время + статусы
                if (!msg.isSystem) {
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(msg.timestamp)),
                        fontSize = 10.sp,
                        color = c.textPrimary.copy(alpha = 0.5f)
                    )
                }
                if (msg.isOwn && !msg.isSystem) {
                    Spacer(modifier = Modifier.width(4.dp))
                    when {
                        msg.isPending   -> Text("⏳", fontSize = 10.sp, color = c.textPrimary.copy(alpha = 0.6f))
                        msg.isFailed    -> Text("!", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFFE53935))
                        msg.isRead      -> Text("✓✓", fontSize = 10.sp, color = c.accent)
                        msg.isDelivered -> Text("✓✓", fontSize = 10.sp, color = Color(0xFF8899AA))
                        else            -> Text("✓", fontSize = 10.sp, color = Color(0xFF8899AA))
                    }
                }
            }
            }
        }

        // Реакции — группируем по эмодзи и показываем счётчик
        if (msg.reactions.isNotEmpty()) {
            Row(
                modifier = Modifier
                    .align(if (msg.isOwn) Alignment.BottomEnd else Alignment.BottomStart)
                    .offset(x = if (msg.isOwn) 12.dp else (-12).dp, y = 12.dp)
                    .background(Color(0xFF1A2255), RoundedCornerShape(12.dp))
                    .padding(horizontal = 6.dp, vertical = 3.dp)
            ) {
                msg.reactions.values.groupBy { it }.forEach { (emoji, reactors) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 2.dp)
                    ) {
                        Text(emoji, fontSize = 13.sp)
                        if (reactors.size > 1) {
                            Text(
                                text = " ${reactors.size}",
                                fontSize = 11.sp,
                                color = c.textPrimary,
                                fontFamily = JetBrainsMono
                            )
                        }
                    }
                }
            }
        }
    }

    // Диалог с полноэкранной картой
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
    val fileExtension = fileName.substringAfterLast('.', "").lowercase()
    val file = File(filePath)

    // Пытаемся создать превью для изображений
    val previewBitmap = remember(filePath) {
        if (fileExtension in listOf("png", "jpg", "jpeg", "webp")) {
            try {
                val options = android.graphics.BitmapFactory.Options().apply {
                    inSampleSize = 2 // Уменьшаем для превью
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
        // Превью изображения
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

        // Информация о файле
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0x22FFFFFF), RoundedCornerShape(8.dp))
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Иконка по типу файла
            Text(
                text = when (fileExtension) {
                    "pdf" -> "📕"
                    "doc", "docx" -> "📘"
                    "png", "jpg", "jpeg" -> "🖼️"
                    else -> "📄"
                },
                fontSize = 24.sp,
                modifier = Modifier.padding(end = 8.dp)
            )

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = fileName,
                    fontSize = 14.sp,
                    color = Color.White,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                // Размер файла
                if (file.exists()) {
                    val sizeKB = file.length() / 1024
                    val sizeText = if (sizeKB > 1024) {
                        "${sizeKB / 1024} MB"
                    } else {
                        "$sizeKB KB"
                    }
                    Text(
                        text = sizeText,
                        fontSize = 12.sp,
                        color = Color(0xAAFFFFFF)
                    )
                }
            }

            // Кнопка скачивания/открытия
            Text(
                text = "📥",
                fontSize = 20.sp,
                modifier = Modifier.padding(start = 8.dp)
            )
        }
    }
}

// Функция для открытия файла
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

        // .enc файлы расшифровываем во временный файл для передачи внешнему приложению
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
