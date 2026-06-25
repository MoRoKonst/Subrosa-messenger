package com.bcon.messenger

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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import com.bcon.messenger.ui.theme.BubbleOwn
import com.bcon.messenger.ui.theme.BubbleOther
import com.bcon.messenger.ui.theme.Primary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlin.math.absoluteValue

// ─── Вспомогательные форматы текста ──────────────────────────────────────────
// В памяти: "VOICE_FILE:path:duration"  (никогда не сохраняется)
// В хранилище: "VOICE:duration:base64"
// В памяти: "GEO_DISPLAY" — отображается как "📍 Геопозиция"

private fun GroupMessage.isVoice() = text.startsWith("VOICE_FILE:")
private fun GroupMessage.isGeo() = text == "📍 Геопозиция"
private fun GroupMessage.isSystem() = senderId == "system"

private fun GroupMessage.voiceFile(): File? {
    if (!isVoice()) return null
    val path = text.split(":").getOrNull(1) ?: return null
    return File(path)
}

private fun GroupMessage.voiceDuration(): Int {
    if (!isVoice()) return 0
    return text.split(":").getOrNull(2)?.toIntOrNull() ?: 0
}

/** Конвертирует хранимый формат VOICE: → отображаемый VOICE_FILE: */
private fun GroupMessage.toDisplay(context: Context): GroupMessage {
    if (!text.startsWith("VOICE:")) return this
    return try {
        val parts = text.split(":", limit = 3)
        val duration = parts.getOrNull(1)?.toIntOrNull() ?: 0
        val base64 = parts.getOrNull(2) ?: return this
        val file = AudioHelper.decodeAndSave(context, base64, id)
        copy(text = "VOICE_FILE:${file.absolutePath}:$duration")
    } catch (e: Exception) {
        this
    }
}

// ─── Экран группового чата ───────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun GroupChatScreen(
    groupId: String,
    onBack: () -> Unit,
    onOpenInfo: () -> Unit,
    onStartGroupCall: ((isVideo: Boolean) -> Unit)? = null
) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val userId = UserStorage.getUserId(context)
    val username = UserStorage.getUsername(context)

    var group by remember { mutableStateOf<Group?>(null) }
    val messages = remember { mutableStateListOf<GroupMessage>() }
    var inputText by remember { mutableStateOf("") }
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    var editingMessageId by remember { mutableStateOf<String?>(null) }
    var isEditMode by remember { mutableStateOf(false) }
    var showReactionPicker by remember { mutableStateOf<GroupMessage?>(null) }
    var contextMenuMessage by remember { mutableStateOf<GroupMessage?>(null) }

    var isRecording by remember { mutableStateOf(false) }
    var recordingFile by remember { mutableStateOf<File?>(null) }
    var playingVoiceId by remember { mutableStateOf<String?>(null) }

    val audioPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            try {
                recordingFile = AudioHelper.startRecording(context)
                isRecording = true
            } catch (e: Exception) {
                android.util.Log.e("GroupChatScreen", "Audio error: ${e.message}")
            }
        }
    }

    // ─── Загрузка группы ─────────────────────────────────────────────────────
    LaunchedEffect(groupId) {
        group = GroupManager.getGroup(context, groupId)
    }

    if (group == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(color = Color(0xFF00E5FF))
        }
        return
    }

    // ─── Загрузка истории (с декодингом голосовых) ───────────────────────────
    LaunchedEffect(groupId) {
        val history = withContext(Dispatchers.IO) {
            GroupManager.loadGroupMessages(context, userId, groupId)
                .map { it.toDisplay(context) }
        }
        messages.addAll(history)
        if (messages.isNotEmpty()) listState.scrollToItem(messages.size - 1)
    }

    // ─── Подключение сервиса ─────────────────────────────────────────────────
    val connection = remember {
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                val service = (binder as MessengerService.LocalBinder).getService()
                messengerService = service
                service.clearNotifLines("group_$groupId")

                service.onGroupMessageReceived = { receivedGroupId, groupMessage ->
                    if (receivedGroupId == groupId) {
                        scope.launch {
                            val display = withContext(Dispatchers.IO) { groupMessage.toDisplay(context) }
                            val existing = messages.indexOfFirst { it.id == display.id }
                            if (existing == -1) {
                                messages.add(display)
                            } else {
                                messages[existing] = display
                            }
                            if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
                        }
                    }
                }

                service.onGroupReactionReceived = { receivedGroupId, from, messageId, emoji ->
                    if (receivedGroupId == groupId) {
                        val index = messages.indexOfFirst { it.id == messageId }
                        if (index != -1) {
                            val updated = messages[index].copy(
                                reactions = messages[index].reactions.toMutableMap().also { it[from] = emoji }
                            )
                            messages[index] = updated
                            scope.launch(Dispatchers.IO) {
                                GroupManager.saveGroupMessage(context, userId, updated)
                            }
                        }
                    }
                }

                service.onGroupMessageDeleted = { deletedGroupId, messageId ->
                    if (deletedGroupId == groupId) {
                        val idx = messages.indexOfFirst { it.id == messageId }
                        if (idx != -1) messages.removeAt(idx)
                    }
                }
            }

            override fun onServiceDisconnected(name: ComponentName) {
                messengerService = null
            }
        }
    }

    LaunchedEffect(Unit) {
        context.bindService(
            Intent(context, MessengerService::class.java),
            connection,
            Context.BIND_AUTO_CREATE
        )
    }

    DisposableEffect(groupId) {
        onDispose {
            messengerService?.onGroupMessageReceived = null
            messengerService?.onGroupReactionReceived = null
            messengerService?.onGroupMessageDeleted = null
            try { context.unbindService(connection) } catch (e: Exception) {}
        }
    }

    // ─── UI ──────────────────────────────────────────────────────────────────
    Column(modifier = Modifier.fillMaxSize().imePadding()) {

        // TopBar
        TopAppBar(
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        shape = CircleShape,
                        color = Color(0xFF2481CC),
                        modifier = Modifier.size(40.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text(group!!.avatar, fontSize = 20.sp)
                        }
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            group!!.name,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 18.sp,
                            color = Color.White,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            s.groupInfoMembersCount(group!!.members.size),
                            fontSize = 12.sp,
                            color = Color(0xFFE0E6FF).copy(alpha = 0.7f)
                        )
                    }
                }
            },
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, s.back, tint = Color.White)
                }
            },
            actions = {
                // Групповой аудиозвонок
                IconButton(onClick = { onStartGroupCall?.invoke(false) }) {
                    Text("📞", fontSize = 20.sp)
                }
                // Групповой видеозвонок
                IconButton(onClick = { onStartGroupCall?.invoke(true) }) {
                    Text("🎥", fontSize = 20.sp)
                }
                IconButton(onClick = onOpenInfo) {
                    Icon(Icons.Default.MoreVert, s.groupChatInfo, tint = Color.White)
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = Color(0xFF091a66))
        )

        // Список сообщений
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Brush.verticalGradient(listOf(Color(0xFF141e4a), Color(0xFF0d1238))))
                .padding(horizontal = 8.dp),
            state = listState
        ) {
            items(messages, key = { it.id }) { msg ->
                GroupMessageBubble(
                    msg = msg,
                    onLongClick = { message ->
                        if (!message.isSystem()) contextMenuMessage = message
                    },
                    onReactionClick = { message ->
                        if (!message.isSystem()) showReactionPicker = message
                    },
                    playingVoiceId = playingVoiceId,
                    onVoicePlay = { id -> playingVoiceId = id },
                    onVoiceStop = { playingVoiceId = null }
                )
            }
        }

        // ─── Контекстное меню (долгое нажатие) ───────────────────────────────────
        if (contextMenuMessage != null) {
            val ctxMsg = contextMenuMessage!!
            AlertDialog(
                onDismissRequest = { contextMenuMessage = null },
                containerColor = Color(0xFF091a66),
                title = null,
                text = {
                    Column {
                        // Ответить — переход в режим ответа (через inputText)
                        TextButton(onClick = {
                            if (!ctxMsg.isVoice() && !ctxMsg.isSystem()) {
                                isEditMode = false
                                inputText = ""
                                // Показываем превью ответа через editingMessageId
                                // TODO: можно добавить replyTo в GroupMessage в следующей итерации
                            }
                            contextMenuMessage = null
                        }) { Text(s.groupChatReply, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        // Копировать текст
                        if (!ctxMsg.isVoice() && !ctxMsg.isSystem() && ctxMsg.text.isNotEmpty()) {
                            TextButton(onClick = {
                                val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                cm.setPrimaryClip(android.content.ClipData.newPlainText("message", ctxMsg.text))
                                contextMenuMessage = null
                                scope.launch {
                                    kotlinx.coroutines.delay(60_000L)
                                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                                        cm.clearPrimaryClip()
                                    } else {
                                        cm.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
                                    }
                                }
                            }) { Text(s.groupChatCopy, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Реакция
                        if (!ctxMsg.isSystem()) {
                            TextButton(onClick = {
                                showReactionPicker = ctxMsg
                                contextMenuMessage = null
                            }) { Text(s.groupChatReactionLabel, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Редактировать (только свои текстовые)
                        if (ctxMsg.isOwn && !ctxMsg.isVoice() && !ctxMsg.isSystem()) {
                            TextButton(onClick = {
                                isEditMode = true
                                editingMessageId = ctxMsg.id
                                inputText = ctxMsg.text
                                contextMenuMessage = null
                            }) { Text(s.groupChatEditAction, color = Color.White, fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                        // Удалить у себя
                        TextButton(onClick = {
                            val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                            if (idx != -1) messages.removeAt(idx)
                            scope.launch(Dispatchers.IO) {
                                GroupManager.deleteGroupMessage(context, userId, groupId, ctxMsg.id)
                            }
                            contextMenuMessage = null
                        }) { Text(s.groupChatDeleteOwn, color = Color(0xFFFF6B6B), fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        // Удалить у всех (только свои)
                        if (ctxMsg.isOwn) {
                            TextButton(onClick = {
                                val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                                if (idx != -1) messages.removeAt(idx)
                                scope.launch(Dispatchers.IO) {
                                    GroupManager.deleteGroupMessage(context, userId, groupId, ctxMsg.id)
                                }
                                messengerService?.sendGroupDeleteMessage(groupId, ctxMsg.id, group!!.members)
                                contextMenuMessage = null
                            }) { Text(s.groupChatDeleteAll, color = Color(0xFFFF4444), fontFamily = JetBrainsMono, fontSize = 16.sp) }
                        }
                    }
                },
                confirmButton = {}
            )
        }

        // Диалог реакций
        if (showReactionPicker != null) {
            AlertDialog(
                onDismissRequest = { showReactionPicker = null },
                title = { Text(s.groupChatPickReaction, color = Color.White, fontFamily = JetBrainsMono) },
                text = {
                    Row(
                        horizontalArrangement = Arrangement.SpaceEvenly,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        listOf("❤️", "👍", "😂", "😮", "😢", "🔥").forEach { emoji ->
                            Text(
                                text = emoji,
                                fontSize = 32.sp,
                                modifier = Modifier.clickable {
                                    val target = showReactionPicker!!
                                    val index = messages.indexOf(target)
                                    if (index != -1) {
                                        val updated = target.copy(
                                            reactions = target.reactions.toMutableMap().also { it[userId] = emoji }
                                        )
                                        messages[index] = updated
                                        scope.launch(Dispatchers.IO) {
                                            GroupManager.saveGroupMessage(context, userId, updated)
                                        }
                                        // Отправляем реакцию всем участникам группы
                                        messengerService?.sendGroupReaction(
                                            groupId = groupId,
                                            messageId = target.id,
                                            emoji = emoji,
                                            members = group!!.members
                                        )
                                    }
                                    showReactionPicker = null
                                }
                            )
                        }
                    }
                },
                confirmButton = {},
                containerColor = Color(0xFF091a66)
            )
        }

        // Баннер режима редактирования
        if (isEditMode) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF0d1238))
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    s.groupChatEditing,
                    fontSize = 12.sp,
                    color = Primary,
                    modifier = Modifier.weight(1f),
                    fontFamily = JetBrainsMono
                )
                TextButton(onClick = {
                    isEditMode = false
                    editingMessageId = null
                    inputText = ""
                }) {
                    Text(s.cancel, color = Color.Gray, fontSize = 12.sp, fontFamily = JetBrainsMono)
                }
            }
        }

        // ─── Панель ввода ─────────────────────────────────────────────────────
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF091a66))
                .padding(8.dp)
                .navigationBarsPadding()
                .imePadding(),
            verticalAlignment = Alignment.Bottom
        ) {
            // Прикрепить
            var showAttachMenu by remember { mutableStateOf(false) }
            IconButton(onClick = { showAttachMenu = true }) {
                Text("📎", fontSize = 24.sp)
            }

            if (showAttachMenu) {
                AlertDialog(
                    onDismissRequest = { showAttachMenu = false },
                    title = {
                        Text(s.groupChatAttach, color = Color.White, fontSize = 20.sp, fontFamily = JetBrainsMono)
                    },
                    text = {
                        Column {
                            TextButton(onClick = { showAttachMenu = false }) {
                                Text(s.groupChatAttachPhoto, color = Color.White, fontSize = 18.sp, fontFamily = JetBrainsMono)
                            }
                            TextButton(onClick = { showAttachMenu = false }) {
                                Text(s.groupChatAttachFile, color = Color.White, fontSize = 18.sp, fontFamily = JetBrainsMono)
                            }
                            TextButton(onClick = {
                                showAttachMenu = false
                                sendGeoMessage(
                                    context = context,
                                    group = group!!,
                                    userId = userId,
                                    username = username,
                                    messages = messages,
                                    messengerService = messengerService,
                                    scope = scope,
                                    listState = listState,
                                    geoLabel = s.groupChatGeo,
                                    geoPermMsg = s.groupChatGeoPermission,
                                    geoFailMsg = s.groupChatGeoFail
                                )
                            }) {
                                Text(s.groupChatGeo, color = Color.White, fontSize = 18.sp, fontFamily = JetBrainsMono)
                            }
                        }
                    },
                    confirmButton = {},
                    containerColor = Color(0xFF091a66)
                )
            }

            // Поле ввода
            Box(modifier = Modifier.weight(1f).padding(horizontal = 4.dp)) {
                androidx.compose.foundation.Canvas(modifier = Modifier.matchParentSize()) {
                    drawRoundRect(
                        color = androidx.compose.ui.graphics.Color(0x22FFFFFF),
                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(32.dp.toPx())
                    )
                    drawRoundRect(
                        color = androidx.compose.ui.graphics.Color(0x33B0C4DE),
                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(32.dp.toPx()),
                        style = androidx.compose.ui.graphics.drawscope.Stroke(width = 1.5.dp.toPx())
                    )
                }
                BasicTextField(
                    value = inputText,
                    onValueChange = { inputText = it },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    maxLines = 3,
                    textStyle = TextStyle(fontSize = 15.sp, color = Color.White),
                    cursorBrush = SolidColor(Color(0xFFFFD700)),
                    decorationBox = { innerTextField ->
                        if (inputText.isEmpty()) {
                            Text(
                                if (isEditMode) s.groupChatEditHint else s.groupChatMessageHint,
                                fontSize = 15.sp,
                                color = Color(0x88FFFFFF),
                                fontFamily = JetBrainsMono
                            )
                        }
                        innerTextField()
                    }
                )
            }

            // Микрофон
            WaveformMicButton(
                isRecording = isRecording,
                onClick = {
                    if (isRecording) {
                        recordingFile?.let { file ->
                            AudioHelper.stopRecording()
                            val duration = (file.length() / 3000L).toInt().coerceAtLeast(1)
                            val voiceId = UUID.randomUUID().toString()
                            val groupKey = group!!.groupKey

                            if (groupKey != null) {
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val base64 = AudioHelper.encodeToBase64(file)
                                        val voiceText = "VOICE:${duration}:${base64}"
                                        val encrypted = GroupManager.encryptGroupMessage(voiceText, groupKey)

                                        val displayMsg = GroupMessage(
                                            id = voiceId,
                                            groupId = groupId,
                                            senderId = userId,
                                            senderName = username,
                                            text = "VOICE_FILE:${file.absolutePath}:$duration",
                                            isOwn = true
                                        )
                                        val storageMsg = displayMsg.copy(text = voiceText)

                                        GroupManager.saveGroupMessage(context, userId, storageMsg)

                                        withContext(Dispatchers.Main) {
                                            messages.add(displayMsg)
                                            scope.launch { listState.animateScrollToItem(messages.size - 1) }
                                        }

                                        val recipients = group!!.members.filter { it != userId }
                                        messengerService?.sendGroupMessage(
                                            groupId = groupId,
                                            messageId = voiceId,
                                            encryptedText = encrypted,
                                            members = recipients
                                        )
                                    } catch (e: Exception) {
                                        android.util.Log.e("GroupChatScreen", "Voice send error: ${e.message}")
                                    }
                                }
                            }
                            isRecording = false
                            recordingFile = null
                        }
                    } else {
                        when {
                            context.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) ==
                                    android.content.pm.PackageManager.PERMISSION_GRANTED -> {
                                try {
                                    recordingFile = AudioHelper.startRecording(context)
                                    isRecording = true
                                } catch (e: Exception) {
                                    android.util.Log.e("GroupChatScreen", "Audio start error: ${e.message}")
                                }
                            }
                            else -> audioPermissionLauncher.launch(android.Manifest.permission.RECORD_AUDIO)
                        }
                    }
                },
                size = 52
            )

            // Кнопка отправки
            PortholeSendButton(
                enabled = inputText.isNotEmpty(),
                onClick = {
                    val text = inputText.trim()
                    val groupKey = group!!.groupKey
                    if (text.isNotEmpty() && groupKey != null) {
                        inputText = ""

                        if (isEditMode && editingMessageId != null) {
                            val editId = editingMessageId!!
                            val index = messages.indexOfFirst { it.id == editId }
                            if (index != -1) {
                                val updated = messages[index].copy(text = text)
                                messages[index] = updated
                                scope.launch(Dispatchers.IO) {
                                    GroupManager.saveGroupMessage(context, userId, updated)
                                }
                            }
                            isEditMode = false
                            editingMessageId = null
                        } else {
                            val messageId = UUID.randomUUID().toString()
                            val encrypted = GroupManager.encryptGroupMessage(text, groupKey)

                            val groupMessage = GroupMessage(
                                id = messageId,
                                groupId = groupId,
                                senderId = userId,
                                senderName = username,
                                text = text,
                                isOwn = true
                            )
                            messages.add(groupMessage)
                            scope.launch(Dispatchers.IO) {
                                GroupManager.saveGroupMessage(context, userId, groupMessage)
                            }
                            scope.launch { listState.animateScrollToItem(messages.size - 1) }

                            val recipients = group!!.members.filter { it != userId }
                            messengerService?.sendGroupMessage(
                                groupId = groupId,
                                messageId = messageId,
                                encryptedText = encrypted,
                                members = recipients
                            )
                        }
                    }
                },
                size = 52
            )
        }
    }
}

// ─── Отправка геопозиции ─────────────────────────────────────────────────────

private fun sendGeoMessage(
    context: Context,
    group: Group,
    userId: String,
    username: String,
    messages: MutableList<GroupMessage>,
    messengerService: MessengerService?,
    scope: kotlinx.coroutines.CoroutineScope,
    listState: androidx.compose.foundation.lazy.LazyListState,
    geoLabel: String = "📍 Геопозиция",
    geoPermMsg: String = "Разрешите доступ к геопозиции",
    geoFailMsg: String = "Не удалось определить позицию"
) {
    try {
        if (context.checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION)
            != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            android.widget.Toast.makeText(
                context, geoPermMsg, android.widget.Toast.LENGTH_SHORT
            ).show()
            return
        }
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
        val loc = lm.getLastKnownLocation(android.location.LocationManager.GPS_PROVIDER)
            ?: lm.getLastKnownLocation(android.location.LocationManager.NETWORK_PROVIDER)

        if (loc == null) {
            android.widget.Toast.makeText(
                context, geoFailMsg, android.widget.Toast.LENGTH_SHORT
            ).show()
            return
        }

        val groupKey = group.groupKey ?: return
        val coordsText = "${loc.latitude},${loc.longitude}"
        val messageId = UUID.randomUUID().toString()
        val encrypted = GroupManager.encryptGroupMessage(coordsText, groupKey)

        val displayMsg = GroupMessage(
            id = messageId,
            groupId = group.id,
            senderId = userId,
            senderName = username,
            text = geoLabel,
            isOwn = true
        )
        messages.add(displayMsg)
        scope.launch(Dispatchers.IO) {
            GroupManager.saveGroupMessage(context, userId, displayMsg.copy(text = coordsText))
        }
        scope.launch { listState.animateScrollToItem(messages.size - 1) }

        val recipients = group.members.filter { it != userId }
        messengerService?.sendGroupMessage(
            groupId = group.id,
            messageId = messageId,
            encryptedText = encrypted,
            members = recipients
        )
    } catch (e: Exception) {
        android.util.Log.e("GroupChatScreen", "Geo error: ${e.message}")
    }
}

// ─── Пузырь группового сообщения ─────────────────────────────────────────────

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun GroupMessageBubble(
    msg: GroupMessage,
    onLongClick: ((GroupMessage) -> Unit)? = null,
    onReactionClick: ((GroupMessage) -> Unit)? = null,
    playingVoiceId: String? = null,
    onVoicePlay: ((String) -> Unit)? = null,
    onVoiceStop: (() -> Unit)? = null
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val isOwn = msg.isOwn
    val isSystem = msg.isSystem()
    val isVoice = msg.isVoice()
    val voiceFile = msg.voiceFile()
    val voiceDuration = msg.voiceDuration()

    val bubbleColor = when {
        isSystem -> Color(0xFF1a2a1a)
        isOwn -> BubbleOwn
        else -> BubbleOther
    }
    val alignment = if (isOwn || isSystem) Alignment.CenterEnd else Alignment.CenterStart

    val avatarColor = remember(msg.senderName) {
        listOf(
            Color(0xFF2481CC), Color(0xFFE74C3C), Color(0xFF27AE60),
            Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
        )[msg.senderName.hashCode().absoluteValue % 6]
    }

    val timeStr = remember(msg.timestamp) {
        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(msg.timestamp))
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp, vertical = 2.dp),
        horizontalAlignment = if (isOwn || isSystem) Alignment.End else Alignment.Start
    ) {
        // Имя отправителя + аватар (только чужие, не системные)
        if (!isOwn && !isSystem) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(start = 4.dp, bottom = 2.dp)
            ) {
                Surface(
                    shape = CircleShape,
                    color = avatarColor,
                    modifier = Modifier.size(22.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            text = if (msg.senderName.isNotEmpty())
                                msg.senderName.first().uppercaseChar().toString() else "?",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = msg.senderName,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = avatarColor,
                    fontFamily = JetBrainsMono
                )
            }
        }

        Box {
            Surface(
                modifier = Modifier
                    .widthIn(
                        min = if (isSystem) 120.dp else 80.dp,
                        max = if (isSystem) 300.dp else 280.dp
                    )
                    .pointerInput(Unit) {
                        detectHorizontalDragGestures { _, dragAmount ->
                            if (!isSystem && dragAmount < -50) onReactionClick?.invoke(msg)
                        }
                    }
                    .combinedClickable(
                        onClick = {},
                        onLongClick = { if (!isSystem) onLongClick?.invoke(msg) }
                    ),
                shape = RoundedCornerShape(
                    topStart = if (isOwn || isSystem) 18.dp else 4.dp,
                    topEnd = if (isOwn || isSystem) 4.dp else 18.dp,
                    bottomStart = 18.dp,
                    bottomEnd = 18.dp
                ),
                color = bubbleColor,
                shadowElevation = 1.dp
            ) {
                Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {

                    // Голосовое сообщение
                    if (isVoice && voiceFile != null) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    if (playingVoiceId == msg.id) {
                                        AudioHelper.stopAudio()
                                        onVoiceStop?.invoke()
                                    } else {
                                        AudioHelper.playAudio(context, voiceFile) { onVoiceStop?.invoke() }
                                        onVoicePlay?.invoke(msg.id)
                                    }
                                }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = if (playingVoiceId == msg.id) "⏸️" else "▶️",
                                fontSize = 20.sp,
                                modifier = Modifier.padding(end = 8.dp)
                            )
                            Text(
                                text = "${voiceDuration}\"",
                                fontSize = 17.sp,
                                color = Primary
                            )
                        }
                    } else {
                        // Текст
                        Text(
                            text = msg.text,
                            fontSize = if (isSystem) 13.sp else 16.sp,
                            lineHeight = 20.sp,
                            color = if (isSystem) Color(0xFFAAFFAA) else Color(0xFFE0E6FF),
                            fontFamily = if (isSystem) JetBrainsMono else null
                        )
                    }

                    // Время
                    Text(
                        text = timeStr,
                        fontSize = 10.sp,
                        color = Color(0x66FFFFFF),
                        modifier = Modifier
                            .align(Alignment.End)
                            .padding(top = 2.dp)
                    )
                }
            }

            // Реакции
            if (msg.reactions.isNotEmpty()) {
                Row(
                    modifier = Modifier
                        .align(if (isOwn) Alignment.BottomEnd else Alignment.BottomStart)
                        .offset(
                            x = if (isOwn) 12.dp else (-12).dp,
                            y = 12.dp
                        )
                        .background(Color(0xFFFFFFFF), RoundedCornerShape(12.dp))
                        .padding(horizontal = 4.dp, vertical = 2.dp)
                ) {
                    msg.reactions.values.distinct().forEach { emoji ->
                        Text(emoji, fontSize = 14.sp)
                    }
                }
            }
        }

        // Отступ снизу с учётом реакций
        Spacer(modifier = Modifier.height(if (msg.reactions.isNotEmpty()) 14.dp else 2.dp))
    }
}
