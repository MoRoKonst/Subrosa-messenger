package com.subrosa.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.MoreVert
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.*

private const val GROUP_MAX_VOICE_RECORDING_SECONDS = 60

@Composable
fun GroupChatScreen(
    groupId: String,
    onBack: () -> Unit,
    onOpenInfo: () -> Unit = {},
    onStartGroupCall: ((isVideo: Boolean) -> Unit)? = null
) {
    val myId = WebSocketClient.myFingerprint
    var group by remember { mutableStateOf(GroupManager.getGroup(groupId)) }
    val messages = remember { mutableStateListOf<GroupMessage>() }
    var input by remember { mutableStateOf("") }
    // Mirrors ChatScreen.kt's 1:1 replyingTo exactly — group chat had no
    // reply support at all before this.
    var replyingTo by remember { mutableStateOf<GroupMessage?>(null) }
    val listState = rememberLazyListState()

    // Voice recording — mirrors ChatScreen.kt's isRecordingVoice/
    // recordingSeconds exactly, just scoped to this group instead of a 1:1
    // contact. Group voice has no dedicated wire type (see sendGroupVoice
    // below) — it rides inside an ordinary group_message as "VOICE:$dur:$b64",
    // matching Android's GroupChatScreen exactly.
    var isRecordingVoice by remember { mutableStateOf(false) }
    var recordingSeconds by remember { mutableStateOf(0) }

    // Voice playback — simplified vs. ChatScreen's (no scrub bar/speed
    // toggle), just play/pause + duration, since DesktopVoicePlayer.play()
    // takes raw bytes directly (no blob file needed for group voice, unlike
    // image/file attachments).
    var playingVoiceId by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(groupId) {
        messages.clear()
        messages.addAll(GroupManager.loadGroupMessages(myId, groupId))

        WebSocketClient.onGroupMessageReceived = { gId, msg ->
            if (gId == groupId) {
                val idx = messages.indexOfFirst { it.id == msg.id }
                if (idx >= 0) messages[idx] = msg else messages.add(msg)
                group = GroupManager.getGroup(groupId)
            }
        }
        WebSocketClient.onGroupMessageDeleted = { gId, messageId ->
            if (gId == groupId) {
                messages.removeAll { it.id == messageId }
            }
        }
        WebSocketClient.onGroupReactionReceived = { gId, from, messageId, emoji ->
            if (gId == groupId) {
                val idx = messages.indexOfFirst { it.id == messageId }
                if (idx >= 0) {
                    messages[idx] = messages[idx].copy(
                        reactions = messages[idx].reactions.toMutableMap().also { it[from] = emoji }
                    )
                }
            }
        }
        // Persistence (GroupManager.saveGroupMessage) already happened
        // inside WebSocketClient before these fire — just reflect it in the
        // currently-open chat's UI, same pattern as onGroupMessageReceived.
        WebSocketClient.onGroupImageReceived = { gId, from, id, file ->
            if (gId == groupId) {
                val msg = GroupMessage(
                    id = id, groupId = groupId, senderId = from,
                    senderName = ChatStorage.getContactName(from), text = "",
                    isOwn = from == myId, imagePath = file.absolutePath
                )
                val idx = messages.indexOfFirst { it.id == msg.id }
                if (idx >= 0) messages[idx] = msg else messages.add(msg)
            }
        }
        WebSocketClient.onGroupFileReceived = { gId, from, id, file, fileName ->
            if (gId == groupId) {
                val msg = GroupMessage(
                    id = id, groupId = groupId, senderId = from,
                    senderName = ChatStorage.getContactName(from), text = "",
                    isOwn = from == myId, filePath = file.absolutePath, fileName = fileName
                )
                val idx = messages.indexOfFirst { it.id == msg.id }
                if (idx >= 0) messages[idx] = msg else messages.add(msg)
            }
        }
        WebSocketClient.onGroupAvatarUpdated = { gId ->
            if (gId == groupId) group = GroupManager.getGroup(groupId)
        }
    }

    LaunchedEffect(isRecordingVoice) {
        if (isRecordingVoice) {
            recordingSeconds = 0
            while (isRecordingVoice) {
                kotlinx.coroutines.delay(1000L)
                recordingSeconds++
                if (recordingSeconds >= GROUP_MAX_VOICE_RECORDING_SECONDS) {
                    isRecordingVoice = false
                    val wavBytes = VoiceRecorder.stop()
                    if (wavBytes != null && wavBytes.size > 44) {
                        sendGroupVoice(myId, groupId, wavBytes, messages)
                    }
                }
            }
        } else {
            recordingSeconds = 0
        }
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    Column(Modifier.fillMaxSize()) {

        // ── Top bar ──────────────────────────────────────────────────────────
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(AppIcons.get("BACK_ARROW"), contentDescription = "Назад",
                        tint = SubrosaTheme.textPrimary)
                }
                // Group avatar system — previously groups had no avatar at
                // all in this top bar, only in GroupInfoScreen. New
                // 2026-09-21, mirrors Android's identical top-bar avatar.
                val avatarPath = group?.avatarPath
                val avatarBitmap = remember(avatarPath) {
                    avatarPath?.let {
                        try {
                            val bytes = DesktopStorage.decryptRaw(java.io.File(it).readBytes())
                            androidx.compose.ui.res.loadImageBitmap(bytes.inputStream())
                        } catch (e: Exception) { null }
                    }
                }
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(CircleShape)
                        .background(SubrosaTheme.accent.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    if (avatarBitmap != null) {
                        androidx.compose.foundation.Image(
                            bitmap = avatarBitmap,
                            contentDescription = null,
                            contentScale = androidx.compose.ui.layout.ContentScale.Crop,
                            modifier = Modifier.fillMaxSize()
                        )
                    } else {
                        Text(group?.avatar ?: "👥", fontSize = 20.sp)
                    }
                }
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(group?.name ?: "Группа", fontSize = 19.sp, fontWeight = FontWeight.SemiBold,
                        color = SubrosaTheme.textPrimary, fontFamily = NotoSerifJP)
                    Text("${group?.members?.size ?: 0} участников",
                        fontSize = 14.sp, color = SubrosaTheme.textSecondary)
                }
                // Group calls — previously absent from Desktop entirely
                // (no buttons, no mesh WebRTC underneath); now a full mesh
                // port of Android's group-call protocol, see
                // DesktopCallManager.startGroupCall().
                IconButton(onClick = { onStartGroupCall?.invoke(false) }) {
                    Icon(AppIcons.get("SOUND_CALL"), contentDescription = "Голосовой звонок", tint = SubrosaTheme.textPrimary)
                }
                IconButton(onClick = { onStartGroupCall?.invoke(true) }) {
                    Icon(AppIcons.get("VIDEO_CALL"), contentDescription = "Видеозвонок", tint = SubrosaTheme.textPrimary)
                }
                // Members/leave/delete/avatar/description management all
                // moved into the dedicated GroupInfoScreen (mirrors Android's
                // split between GroupChatScreen and GroupInfoScreen) — this
                // used to be a bare "Участники"/"Покинуть группу" dropdown
                // with no avatar/description editing and no delete option
                // for creators at all.
                IconButton(onClick = onOpenInfo) {
                    Icon(AppIcons.get("MENU"), contentDescription = "Информация о группе", tint = SubrosaTheme.textPrimary)
                }
            }
        }

        // ── Message list ─────────────────────────────────────────────────────
        LazyColumn(
            modifier = Modifier.weight(1f).padding(horizontal = 8.dp),
            state = listState
        ) {
            items(messages, key = { it.id }) { msg ->
                GroupMessageBubble(
                    msg = msg,
                    allMsgs = messages,
                    myId = myId,
                    playingVoiceId = playingVoiceId,
                    onVoicePlayingIdChange = { playingVoiceId = it },
                    onDeleteForEveryone = {
                        GroupManager.deleteGroupMessage(myId, groupId, msg.id)
                        WebSocketClient.sendGroupDeleteMessage(groupId, msg.id)
                        messages.removeAll { it.id == msg.id }
                    },
                    onReact = { emoji ->
                        val idx = messages.indexOfFirst { it.id == msg.id }
                        if (idx >= 0) {
                            val updated = messages[idx].copy(
                                reactions = messages[idx].reactions.toMutableMap().also { it[myId] = emoji }
                            )
                            messages[idx] = updated
                            GroupManager.saveGroupMessage(myId, updated)
                            WebSocketClient.sendGroupReaction(groupId, msg.id, emoji)
                        }
                    },
                    onReply = { replyingTo = msg }
                )
                Spacer(Modifier.height(2.dp))
            }
        }

        // ── Reply bar ────────────────────────────────────────────────────────
        // Mirrors ChatScreen.kt's 1:1 replyingTo bar exactly.
        if (replyingTo != null) {
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
                        Text(replyingTo!!.text, fontSize = 14.sp,
                            color = SubrosaTheme.textSecondary, maxLines = 1)
                    }
                    IconButton(onClick = { replyingTo = null }) {
                        Icon(AppIcons.get("CLOSE"), contentDescription = "Отмена", tint = SubrosaTheme.textSecondary, modifier = Modifier.size(16.dp))
                    }
                }
            }
        }

        HorizontalDivider(color = SubrosaTheme.divider, thickness = 0.5.dp)

        // ── Input bar ─────────────────────────────────────────────────────────
        if (isRecordingVoice) {
            Surface(color = SubrosaTheme.inputBg) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = { isRecordingVoice = false; VoiceRecorder.cancel() }) {
                        Icon(AppIcons.get("DELETE"), contentDescription = "Отменить", tint = SubrosaTheme.error)
                    }
                    Spacer(Modifier.width(8.dp))
                    Box(Modifier.size(9.dp).clip(CircleShape).background(SubrosaTheme.error))
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = String.format("%d:%02d", recordingSeconds / 60, recordingSeconds % 60),
                        color = SubrosaTheme.textPrimary, fontSize = 17.sp, fontWeight = FontWeight.Medium,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = {
                        isRecordingVoice = false
                        val wavBytes = VoiceRecorder.stop()
                        if (wavBytes != null && wavBytes.size > 44) {
                            sendGroupVoice(myId, groupId, wavBytes, messages)
                        }
                    }) {
                        Icon(AppIcons.get("Send"), contentDescription = "Отправить голосовое", tint = SubrosaTheme.accent)
                    }
                }
            }
        } else {
        Surface(color = SubrosaTheme.inputBg) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.Bottom
            ) {
                IconButton(
                    onClick = { pickAndSendGroupAttachment(myId, groupId, messages) },
                    modifier = Modifier.padding(bottom = 4.dp)
                ) {
                    Icon(AppIcons.get("ATTACH"), contentDescription = "Прикрепить",
                        tint = SubrosaTheme.textSecondary, modifier = Modifier.size(18.dp))
                }
                Spacer(Modifier.width(2.dp))
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    modifier = Modifier.weight(1f).onPreviewKeyEvent { event ->
                        if (event.type == KeyEventType.KeyDown &&
                            event.key == Key.Enter && !event.isShiftPressed) {
                            sendGroupText(myId, groupId, input.trim(), messages, replyingTo?.id)
                            input = ""
                            replyingTo = null
                            true
                        } else false
                    },
                    placeholder = { Text("Сообщение…", color = SubrosaTheme.textSecondary.copy(alpha = 0.5f)) },
                    maxLines = 5,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent,
                    )
                )
                Spacer(Modifier.width(6.dp))
                if (input.isNotBlank()) {
                    IconButton(
                        onClick = {
                            sendGroupText(myId, groupId, input.trim(), messages, replyingTo?.id)
                            input = ""
                            replyingTo = null
                        },
                        modifier = Modifier.padding(bottom = 4.dp)
                    ) {
                        Icon(AppIcons.get("Send"), contentDescription = "Отправить", tint = SubrosaTheme.accent)
                    }
                } else {
                    IconButton(
                        onClick = { isRecordingVoice = VoiceRecorder.start() },
                        modifier = Modifier.padding(bottom = 4.dp)
                    ) {
                        Icon(AppIcons.get("Micro"), contentDescription = "Голосовое", tint = SubrosaTheme.textSecondary)
                    }
                }
            }
        }
        }
    }

}

private fun sendGroupText(myId: String, groupId: String, text: String, messages: MutableList<GroupMessage>, replyToId: String? = null) {
    if (text.isBlank()) return
    val messageId = UUID.randomUUID().toString()
    val message = GroupMessage(
        id = messageId, groupId = groupId, senderId = myId,
        senderName = UserStorage.getUsername(), text = text, isOwn = true, replyToId = replyToId
    )
    messages.add(message)
    GroupManager.saveGroupMessage(myId, message)
    WebSocketClient.sendGroupMessage(groupId, messageId, text, replyToId)
}

/** Group voice has no dedicated wire type — rides inside an ordinary
 *  group_message as "VOICE:$duration:$base64", exactly matching Android's
 *  GroupChatScreen. Detected on render by GroupMessage.voiceParts() below. */
private fun sendGroupVoice(myId: String, groupId: String, wavBytes: ByteArray, messages: MutableList<GroupMessage>) {
    val duration = VoiceRecorder.durationSeconds(wavBytes)
    val base64 = java.util.Base64.getEncoder().encodeToString(wavBytes)
    sendGroupText(myId, groupId, "VOICE:$duration:$base64", messages)
}

/** Attach an image or generic file — mirrors ChatScreen.kt's own attach
 *  button (same FileDialog, same IMAGE_EXTENSIONS/stripImageMetadata reuse),
 *  just fanned out via sendGroupImage()/sendGroupFile() (group-key
 *  encrypted, multi-recipient) instead of sendImage()/sendFile(). */
private fun pickAndSendGroupAttachment(myId: String, groupId: String, messages: MutableList<GroupMessage>) {
    val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Прикрепить файл", java.awt.FileDialog.LOAD)
    dialog.isVisible = true
    val fileName = dialog.file
    val dir = dialog.directory
    if (fileName == null || dir == null) return
    val picked = java.io.File(dir, fileName)
    val bytes = runCatching { picked.readBytes() }.getOrNull() ?: return
    val ext = picked.extension.lowercase()
    val id = UUID.randomUUID().toString()
    val senderName = UserStorage.getUsername()
    if (ext in IMAGE_EXTENSIONS) {
        val cleanBytes = stripImageMetadata(bytes, ext)
        WebSocketClient.sendGroupImage(groupId, cleanBytes)
        val imgDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs").also { it.mkdirs() }
        val imgFile = java.io.File(imgDir, "$id.enc")
        runCatching { imgFile.writeBytes(DesktopStorage.encryptRaw(cleanBytes)) }
        val message = GroupMessage(
            id = id, groupId = groupId, senderId = myId, senderName = senderName,
            text = "", isOwn = true, imagePath = imgFile.absolutePath
        )
        messages.add(message)
        GroupManager.saveGroupMessage(myId, message)
    } else {
        WebSocketClient.sendGroupFile(groupId, picked.name, bytes)
        val fileDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs").also { it.mkdirs() }
        val outFile = java.io.File(fileDir, "$id.enc")
        runCatching { outFile.writeBytes(DesktopStorage.encryptRaw(bytes)) }
        val message = GroupMessage(
            id = id, groupId = groupId, senderId = myId, senderName = senderName,
            text = "", isOwn = true, filePath = outFile.absolutePath, fileName = picked.name
        )
        messages.add(message)
        GroupManager.saveGroupMessage(myId, message)
    }
}

/** Parses a "VOICE:$duration:$base64" text payload — the wire/storage
 *  convention this session ported from Android's GroupMessage.toDisplay()
 *  (mirrors it exactly). Returns null for an ordinary text message. */
private fun GroupMessage.voiceParts(): Pair<Int, ByteArray>? {
    if (!text.startsWith("VOICE:")) return null
    return try {
        val parts = text.split(":", limit = 3)
        val duration = parts.getOrNull(1)?.toIntOrNull() ?: return null
        val base64 = parts.getOrNull(2) ?: return null
        if (duration < 0 || duration > GROUP_MAX_VOICE_RECORDING_SECONDS) return null
        duration to java.util.Base64.getDecoder().decode(base64)
    } catch (e: Exception) {
        null
    }
}

@Composable
private fun GroupMessageBubble(
    msg: GroupMessage,
    allMsgs: List<GroupMessage>,
    myId: String,
    playingVoiceId: String?,
    onVoicePlayingIdChange: (String?) -> Unit,
    onDeleteForEveryone: () -> Unit,
    onReact: (String) -> Unit,
    onReply: () -> Unit
) {
    val isOwn = msg.senderId == myId
    val isSystem = msg.senderId == "system"
    if (isSystem) {
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Surface(shape = MaterialTheme.shapes.small, color = SubrosaTheme.card) {
                Text(msg.text, fontSize = 13.sp, color = SubrosaTheme.textSecondary,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
            }
        }
        return
    }
    var showMenu by remember { mutableStateOf(false) }
    Box(
        Modifier.fillMaxWidth(),
        contentAlignment = if (isOwn) Alignment.CenterEnd else Alignment.CenterStart
    ) {
        Box {
            Surface(
                shape = MaterialTheme.shapes.medium,
                color = if (isOwn) SubrosaTheme.bubbleOwn else SubrosaTheme.bubbleOther,
                modifier = Modifier
                    .widthIn(max = 520.dp)
                    // Long-press / right-click opens the menu for ANY message —
                    // you can react to others' messages, not just your own
                    // (mirrors Android's GroupChatScreen reaction picker, which
                    // opens on any non-system message).
                    .pointerInput(msg.id) {
                        detectTapGestures(onLongPress = { showMenu = true })
                    }
                    .pointerInput(msg.id) {
                        awaitPointerEventScope {
                            while (true) {
                                val event = awaitPointerEvent()
                                if (event.type == PointerEventType.Press &&
                                    event.buttons.isSecondaryPressed) showMenu = true
                            }
                        }
                    }
            ) {
                Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                    if (!isOwn) {
                        Text(msg.senderName, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = SubrosaTheme.accent)
                        Spacer(Modifier.height(2.dp))
                    }

                    // Reply quote — mirrors ChatScreen.kt's 1:1 repliedMsg block exactly.
                    val repliedMsg = msg.replyToId?.let { id -> allMsgs.find { it.id == id } }
                    repliedMsg?.let { r ->
                        Surface(
                            shape  = MaterialTheme.shapes.small,
                            color  = SubrosaTheme.bubbleSystem,
                            modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp)
                        ) {
                            Row(Modifier.padding(6.dp)) {
                                Box(Modifier.width(3.dp).fillMaxHeight().background(SubrosaTheme.accent))
                                Spacer(Modifier.width(6.dp))
                                Text(r.text.take(80), fontSize = 14.sp,
                                    color = SubrosaTheme.textSecondary, maxLines = 2)
                            }
                        }
                    }

                    val voice = remember(msg.id, msg.text) { msg.voiceParts() }
                    when {
                        voice != null -> {
                            val (duration, wavBytes) = voice
                            val isPlaying = playingVoiceId == msg.id
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                IconButton(
                                    onClick = {
                                        if (isPlaying) {
                                            DesktopVoicePlayer.stop()
                                            onVoicePlayingIdChange(null)
                                        } else {
                                            onVoicePlayingIdChange(msg.id)
                                            DesktopVoicePlayer.play(wavBytes, msg.id, 1f) { onVoicePlayingIdChange(null) }
                                        }
                                    },
                                    modifier = Modifier.size(32.dp)
                                ) {
                                    Icon(AppIcons.get(if (isPlaying) "PAUSE" else "PLAY"), contentDescription = null,
                                        tint = SubrosaTheme.accent, modifier = Modifier.size(18.dp))
                                }
                                Text(String.format("%d:%02d", duration / 60, duration % 60),
                                    fontSize = 14.sp, color = SubrosaTheme.textSecondary)
                            }
                        }
                        msg.imagePath != null -> {
                            val bitmap = remember(msg.id) {
                                runCatching {
                                    val bytes = DesktopStorage.decryptRaw(java.io.File(msg.imagePath).readBytes())
                                    androidx.compose.ui.res.loadImageBitmap(bytes.inputStream())
                                }.getOrNull()
                            }
                            if (bitmap != null) {
                                androidx.compose.foundation.Image(
                                    bitmap = bitmap, contentDescription = null,
                                    modifier = Modifier.widthIn(max = 320.dp).heightIn(max = 260.dp)
                                )
                            } else {
                                Text("[изображение]", fontSize = 14.sp, color = SubrosaTheme.textSecondary)
                            }
                        }
                        msg.fileName != null -> {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(AppIcons.get("FILE"), contentDescription = null,
                                    tint = SubrosaTheme.accent, modifier = Modifier.size(20.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(msg.fileName, fontSize = 15.sp, color = SubrosaTheme.textPrimary)
                            }
                        }
                        else -> Text(msg.text, fontSize = 16.sp, color = SubrosaTheme.textPrimary)
                    }
                    Spacer(Modifier.height(2.dp))
                    Text(
                        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(msg.timestamp)),
                        fontSize = 12.sp, color = SubrosaTheme.textSecondary,
                        modifier = Modifier.align(Alignment.End)
                    )
                    // Reactions (mirrors Android: group by emoji, show count > 1)
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
            DropdownMenu(
                expanded = showMenu,
                onDismissRequest = { showMenu = false },
                containerColor = SubrosaTheme.card
            ) {
                // Reaction picker — same 6 emojis as the 1:1 chat and Android.
                DropdownMenuItem(
                    text = {
                        Row(horizontalArrangement = Arrangement.SpaceEvenly,
                            modifier = Modifier.fillMaxWidth()) {
                            listOf("❤️", "👍", "😂", "😮", "😢", "🔥").forEach { emoji ->
                                Text(emoji, fontSize = 24.sp,
                                    modifier = Modifier
                                        .clickable { showMenu = false; onReact(emoji) }
                                        .padding(4.dp))
                            }
                        }
                    },
                    onClick = {}
                )
                DropdownMenuItem(
                    text = { Text("Ответить", color = SubrosaTheme.textPrimary) },
                    onClick = { showMenu = false; onReply() }
                )
                if (isOwn) {
                    DropdownMenuItem(
                        text = { Text("Удалить у всех", color = SubrosaTheme.textPrimary) },
                        onClick = { showMenu = false; onDeleteForEveryone() }
                    )
                }
            }
        }
    }
}

// MembersDialog removed — member management (promote/remove/add), avatar,
// and description editing all live in the dedicated GroupInfoScreen now
// (opened via the top bar's info button above), mirroring Android's split
// between GroupChatScreen and GroupInfoScreen.
