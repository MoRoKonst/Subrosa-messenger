package com.subrosa.messenger

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
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
import com.subrosa.messenger.ui.theme.BubbleOwn
import com.subrosa.messenger.ui.theme.BubbleOther
import com.subrosa.messenger.ui.theme.Primary
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlin.math.absoluteValue
import androidx.compose.ui.res.painterResource

private fun GroupMessage.isVoice() = text.startsWith("VOICE_FILE:")
private fun GroupMessage.isGeo() = text == "Геопозиция"
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

// S6-57 (external review 2026-09-06) -- group voice rides inside
// group_message's own already-encrypted `text` field ("VOICE:$duration:$base64"),
// a separate wire path from the direct "voice" type server.py's
// VOICE_DATA_MAX_LEN/MAX_VOICE_DURATION_SECONDS bound -- this client-side
// check is this path's own defense-in-depth, same numbers as
// MessengerService's own VOICE_WIRE_MAX_LEN/MAX_VOICE_DURATION_SECONDS.
private const val GROUP_VOICE_WIRE_MAX_LEN = 4 * 1024 * 1024
private const val GROUP_VOICE_MAX_DURATION_SECONDS = 60

private fun GroupMessage.toDisplay(context: Context): GroupMessage {
    if (!text.startsWith("VOICE:")) return this
    return try {
        val parts = text.split(":", limit = 3)
        val duration = parts.getOrNull(1)?.toIntOrNull() ?: 0
        if (duration < 0 || duration > GROUP_VOICE_MAX_DURATION_SECONDS) return this
        val base64 = parts.getOrNull(2) ?: return this
        if (base64.isEmpty() || base64.length > GROUP_VOICE_WIRE_MAX_LEN) return this
        val file = AudioHelper.decodeAndSave(context, base64, id) ?: return this
        copy(text = "VOICE_FILE:${file.absolutePath}:$duration")
    } catch (e: Exception) {
        this
    }
}

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
    val c = LocalSubrosaColors.current
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
    // Mirrors ChatScreen.kt's 1:1 replyToMessage exactly — group chat's
    // context menu already had a "Reply" button (below), it just never did
    // anything: onClick cleared edit mode/dismissed the menu and stopped
    // there, with no state to actually track what's being replied to.
    var replyToMessage by remember { mutableStateOf<GroupMessage?>(null) }

    var isRecording by remember { mutableStateOf(false) }
    var recordingFile by remember { mutableStateOf<File?>(null) }
    var playingVoiceId by remember { mutableStateOf<String?>(null) }
    var playingVideoId by remember { mutableStateOf<String?>(null) }
    // Live "0:07" counter + auto-cap at GROUP_VOICE_MAX_DURATION_SECONDS —
    // mirrors ChatScreen.kt's 1:1 recordingSeconds/finishRecordingAndSend()
    // exactly. Was entirely missing here: tapping the mic just silently
    // toggled recording on/off with the same bare mic icon shown the whole
    // time, no visible recording state, no cancel option, and no length
    // cap. Found live, 2026-09-19.
    var recordingSeconds by remember { mutableStateOf(0) }

    // Video circle (round video message) — mirrors ChatScreen.kt's 1:1
    // isVideoMode/showVideoCircleRecorder exactly. Group chat previously had
    // no video-circle capability at all (send path, receive path, or UI) —
    // the idle-state media button below was a plain voice-only mic with no
    // way to switch to video. Found live, 2026-09-21.
    var isVideoMode by remember { mutableStateOf(false) }
    var showVideoCircleRecorder by remember { mutableStateOf(false) }

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

    // Distinct from "group still null" — group starts null on every fresh
    // composition (normal, brief loading state) and the lookup below is
    // synchronous, but without this flag there's no way to tell that
    // legitimate momentary state apart from "we actually looked and this
    // group doesn't exist" (e.g. just left/deleted it, or a stale deep
    // link/notification for a group that's gone). Found live 2026-09-21:
    // navigating here for a nonexistent group left `group` null forever,
    // and the old code just showed a spinner with no escape — infinite
    // loading screen, not a crash, so easy to miss in testing.
    var groupLookupDone by remember { mutableStateOf(false) }
    LaunchedEffect(groupId) {
        group = GroupManager.getGroup(context, groupId)
        groupLookupDone = true
    }

    if (group == null) {
        if (groupLookupDone) {
            LaunchedEffect(Unit) { onBack() }
        }
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(color = if (c.isDark) Color(0xFFD9A566) else c.accent)
        }
        return
    }

    LaunchedEffect(groupId) {
        val history = withContext(Dispatchers.IO) {
            GroupManager.loadGroupMessages(context, userId, groupId)
                .map { it.toDisplay(context) }
        }
        messages.addAll(history)
        if (messages.isNotEmpty()) listState.scrollToItem(messages.size - 1)
    }

    val connection = remember {
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                val service = (binder as MessengerService.LocalBinder).getService()
                messengerService = service
                service.clearNotifLines("group_$groupId")

                service.onGroupAvatarUpdated = { updatedGroupId ->
                    if (updatedGroupId == groupId) {
                        group = GroupManager.getGroup(context, updatedGroupId)
                    }
                }

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

                service.onGroupImageReceived = { receivedGroupId, from, imageId, file ->
                    if (receivedGroupId == groupId) {
                        SoundManager.playMessageReceived()
                        val displayMsg = GroupMessage(
                            id = imageId,
                            groupId = groupId,
                            senderId = from,
                            senderName = ChatStorage.getContactName(context, from),
                            text = s.groupChatAttachPhoto,
                            isOwn = false,
                            imagePath = file.absolutePath
                        )
                        messages.add(displayMsg)
                        scope.launch(Dispatchers.IO) {
                            GroupManager.saveGroupMessage(context, userId, displayMsg)
                        }
                        scope.launch { listState.animateScrollToItem(messages.size - 1) }
                    }
                }

                service.onGroupFileReceived = { receivedGroupId, from, fileId, file, fileName ->
                    if (receivedGroupId == groupId) {
                        SoundManager.playMessageReceived()
                        val displayMsg = GroupMessage(
                            id = fileId,
                            groupId = groupId,
                            senderId = from,
                            senderName = ChatStorage.getContactName(context, from),
                            text = fileName,
                            isOwn = false,
                            filePath = file.absolutePath,
                            fileName = fileName
                        )
                        messages.add(displayMsg)
                        scope.launch(Dispatchers.IO) {
                            GroupManager.saveGroupMessage(context, userId, displayMsg)
                        }
                        scope.launch { listState.animateScrollToItem(messages.size - 1) }
                    }
                }

                service.onGroupVideoReceived = { receivedGroupId, from, videoId, file, duration ->
                    if (receivedGroupId == groupId) {
                        SoundManager.playMessageReceived()
                        val displayMsg = GroupMessage(
                            id = videoId,
                            groupId = groupId,
                            senderId = from,
                            senderName = ChatStorage.getContactName(context, from),
                            text = "Видеосообщение",
                            isOwn = false,
                            videoPath = file.absolutePath,
                            videoDuration = duration
                        )
                        messages.add(displayMsg)
                        scope.launch(Dispatchers.IO) {
                            GroupManager.saveGroupMessage(context, userId, displayMsg)
                        }
                        scope.launch { listState.animateScrollToItem(messages.size - 1) }
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
            messengerService?.onGroupImageReceived = null
            messengerService?.onGroupFileReceived = null
            messengerService?.onGroupVideoReceived = null
            messengerService?.onGroupAvatarUpdated = null
            try { context.unbindService(connection) } catch (e: Exception) {}
        }
    }

    // Photo/file pickers reuse MainActivity's shared PICK_IMAGE_REQUEST/
    // PICK_FILE_REQUEST StateFlows (see ChatScreen.kt) rather than a
    // dedicated launcher — only one screen is visible at a time, so the
    // global flow is safe to share. Sending itself goes through the group
    // key (sendGroupImage/sendGroupFile), not the 1:1 per-contact path.
    LaunchedEffect(Unit) {
        MainActivity.selectedPhotoUri.collect { uri: android.net.Uri? ->
            uri ?: return@collect
            MainActivity.selectedPhotoUri.value = null
            val g = group ?: return@collect
            val groupKey = g.groupKey ?: return@collect
            try {
                val bitmap = android.provider.MediaStore.Images.Media.getBitmap(context.contentResolver, uri)
                if (bitmap.byteCount > 100 * 1024 * 1024) {
                    android.widget.Toast.makeText(context, s.chatPhotoTooBig, android.widget.Toast.LENGTH_SHORT).show()
                    bitmap.recycle()
                    return@collect
                }
                val imageBytes = compressImageForSend(bitmap)
                val imageId = UUID.randomUUID().toString()
                val imageFile = SecureFileStorage.blobFile(context.filesDir, imageId)
                SecureFileStorage.write(context, imageFile, imageBytes)

                val displayMsg = GroupMessage(
                    id = imageId,
                    groupId = groupId,
                    senderId = userId,
                    senderName = username,
                    text = s.groupChatAttachPhoto,
                    isOwn = true,
                    imagePath = imageFile.absolutePath
                )
                messages.add(displayMsg)
                scope.launch(Dispatchers.IO) {
                    GroupManager.saveGroupMessage(context, userId, displayMsg)
                }
                scope.launch { listState.animateScrollToItem(messages.size - 1) }

                val recipients = g.members.filter { it != userId }
                messengerService?.sendGroupImage(groupId, recipients, groupKey, imageBytes)
            } catch (e: Exception) {
                android.util.Log.e("GroupChatScreen", "Group image send error: ${e.message}")
            }
        }
    }

    LaunchedEffect(Unit) {
        MainActivity.selectedFileUri.collect { uri: android.net.Uri? ->
            uri ?: return@collect
            MainActivity.selectedFileUri.value = null
            val g = group ?: return@collect
            val groupKey = g.groupKey ?: return@collect
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

                if (bytes == null || bytes.isEmpty()) return@collect
                if (bytes.size > 20 * 1024 * 1024) {
                    android.widget.Toast.makeText(context, s.chatFileTooBig, android.widget.Toast.LENGTH_SHORT).show()
                    return@collect
                }

                val fileId = UUID.randomUUID().toString()
                val file = SecureFileStorage.blobFile(context.filesDir, fileId)
                SecureFileStorage.write(context, file, bytes)

                val displayMsg = GroupMessage(
                    id = fileId,
                    groupId = groupId,
                    senderId = userId,
                    senderName = username,
                    text = fileName,
                    isOwn = true,
                    filePath = file.absolutePath,
                    fileName = fileName
                )
                messages.add(displayMsg)
                scope.launch(Dispatchers.IO) {
                    GroupManager.saveGroupMessage(context, userId, displayMsg)
                }
                scope.launch { listState.animateScrollToItem(messages.size - 1) }

                val recipients = g.members.filter { it != userId }
                messengerService?.sendGroupFile(groupId, recipients, groupKey, fileName, bytes)
            } catch (e: Exception) {
                android.util.Log.e("GroupChatScreen", "Group file send error: ${e.message}")
            }
        }
    }

    Column(modifier = Modifier.fillMaxSize().imePadding()) {

        TopAppBar(
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        shape = CircleShape,
                        color = if (c.isDark) Color(0xFFC77B4F) else c.primaryBlue,
                        modifier = Modifier.size(40.dp)
                    ) {
                        val avatarPath = group!!.avatarPath
                        val avatarBitmap = remember(avatarPath) {
                            avatarPath?.let {
                                try {
                                    val bytes = SecureFileStorage.read(context, File(it))
                                    android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                                } catch (e: Exception) { null }
                            }
                        }
                        Box(contentAlignment = Alignment.Center) {
                            if (avatarBitmap != null) {
                                Image(
                                    bitmap = avatarBitmap.asImageBitmap(),
                                    contentDescription = null,
                                    contentScale = ContentScale.Crop,
                                    modifier = Modifier.fillMaxSize()
                                )
                            } else {
                                Text(group!!.avatar, fontSize = 22.sp)
                            }
                        }
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            group!!.name,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 20.sp,
                            color = c.textPrimary,
                            fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            s.groupInfoMembersCount(group!!.members.size),
                            fontSize = 14.sp,
                            color = c.textPrimary.copy(alpha = 0.7f)
                        )
                    }
                }
            },
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(painterResource(R.drawable.ic_back_arrow), s.back, tint = c.textPrimary)
                }
            },
            actions = {

                IconButton(onClick = { onStartGroupCall?.invoke(false) }) {
                    Icon(painterResource(R.drawable.ic_sound_call), contentDescription = null, tint = c.textPrimary)
                }

                IconButton(onClick = { onStartGroupCall?.invoke(true) }) {
                    Icon(painterResource(R.drawable.ic_video_call), contentDescription = null, tint = c.textPrimary)
                }
                IconButton(onClick = onOpenInfo) {
                    Icon(painterResource(R.drawable.ic_menu), s.groupChatInfo, tint = c.textPrimary)
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = if (c.isDark) Color(0xFF4A151A) else c.topBar)
        )

        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(
                        if (c.isDark) listOf(Color(0xFF2B0F14), Color(0xFF180A0C))
                        else listOf(c.gradientStart, c.gradientEnd)
                    )
                )
                .padding(horizontal = 8.dp),
            state = listState
        ) {
            items(messages, key = { it.id }) { msg ->
                GroupMessageBubble(
                    msg = msg,
                    replyToOriginal = msg.replyToId?.let { rid -> messages.find { it.id == rid } },
                    onLongClick = { message ->
                        if (!message.isSystem()) contextMenuMessage = message
                    },
                    onReactionClick = { message ->
                        if (!message.isSystem()) showReactionPicker = message
                    },
                    playingVoiceId = playingVoiceId,
                    onVoicePlay = { id -> playingVoiceId = id },
                    onVoiceStop = { playingVoiceId = null },
                    playingVideoId = playingVideoId,
                    onVideoPlay = { id -> playingVideoId = id },
                    onVideoStop = { playingVideoId = null }
                )
            }
        }

        if (contextMenuMessage != null) {
            val ctxMsg = contextMenuMessage!!
            AlertDialog(
                onDismissRequest = { contextMenuMessage = null },
                containerColor = if (c.isDark) Color(0xFF4A151A) else c.dialog,
                title = null,
                text = {
                    Column {

                        TextButton(onClick = {
                            if (!ctxMsg.isVoice() && !ctxMsg.isSystem()) {
                                isEditMode = false
                                editingMessageId = null
                                inputText = ""
                                replyToMessage = ctxMsg
                            }
                            contextMenuMessage = null
                        }) { Text(s.groupChatReply, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }

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
                            }) { Text(s.groupChatCopy, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }

                        if (!ctxMsg.isSystem()) {
                            TextButton(onClick = {
                                showReactionPicker = ctxMsg
                                contextMenuMessage = null
                            }) { Text(s.groupChatReactionLabel, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }

                        if (ctxMsg.isOwn && !ctxMsg.isVoice() && !ctxMsg.isSystem()) {
                            TextButton(onClick = {
                                isEditMode = true
                                editingMessageId = ctxMsg.id
                                inputText = ctxMsg.text
                                contextMenuMessage = null
                            }) { Text(s.groupChatEditAction, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }

                        TextButton(onClick = {
                            val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                            if (idx != -1) messages.removeAt(idx)
                            scope.launch(Dispatchers.IO) {
                                GroupManager.deleteGroupMessage(context, userId, groupId, ctxMsg.id)
                            }
                            contextMenuMessage = null
                        }) { Text(s.groupChatDeleteOwn, color = Color(0xFFFF6B6B), fontFamily = JetBrainsMono, fontSize = 18.sp) }

                        if (ctxMsg.isOwn) {
                            TextButton(onClick = {
                                val idx = messages.indexOfFirst { it.id == ctxMsg.id }
                                if (idx != -1) messages.removeAt(idx)
                                scope.launch(Dispatchers.IO) {
                                    GroupManager.deleteGroupMessage(context, userId, groupId, ctxMsg.id)
                                }
                                messengerService?.sendGroupDeleteMessage(groupId, ctxMsg.id, group!!.members)
                                contextMenuMessage = null
                            }) { Text(s.groupChatDeleteAll, color = c.error, fontFamily = JetBrainsMono, fontSize = 18.sp) }
                        }
                    }
                },
                confirmButton = {}
            )
        }

        if (showReactionPicker != null) {
            AlertDialog(
                onDismissRequest = { showReactionPicker = null },
                title = { Text(s.groupChatPickReaction, color = c.textPrimary, fontFamily = JetBrainsMono) },
                text = {
                    Row(
                        horizontalArrangement = Arrangement.SpaceEvenly,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        listOf("❤️", "👍", "😂", "😮", "😢", "🔥").forEach { emoji ->
                            Text(
                                text = emoji,
                                fontSize = 34.sp,
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
                containerColor = if (c.isDark) Color(0xFF4A151A) else c.dialog
            )
        }

        if (showVideoCircleRecorder) {
            VideoCircleRecorder(
                onSend = { videoFile, duration ->
                    showVideoCircleRecorder = false
                    val videoId = UUID.randomUUID().toString()
                    val g = group
                    val groupKey = g?.groupKey
                    if (g == null || groupKey == null) {
                        videoFile.delete()
                        return@VideoCircleRecorder
                    }

                    scope.launch(Dispatchers.IO) {
                        try {
                            val plainBytes = videoFile.readBytes()
                            videoFile.delete()
                            val encFile = SecureFileStorage.blobFile(context.filesDir, videoId)
                            SecureFileStorage.write(context, encFile, plainBytes)

                            withContext(Dispatchers.Main) {
                                val displayMsg = GroupMessage(
                                    id = videoId,
                                    groupId = groupId,
                                    senderId = userId,
                                    senderName = username,
                                    text = "Видеосообщение",
                                    isOwn = true,
                                    videoPath = encFile.absolutePath,
                                    videoDuration = duration
                                )
                                messages.add(displayMsg)
                                scope.launch(Dispatchers.IO) {
                                    GroupManager.saveGroupMessage(context, userId, displayMsg)
                                }
                                scope.launch { listState.animateScrollToItem(messages.size - 1) }

                                val recipients = g.members.filter { it != userId }
                                messengerService?.sendGroupVideoCircle(groupId, recipients, groupKey, plainBytes, duration)
                            }
                        } catch (e: Exception) {
                            android.util.Log.e("GroupChatScreen", "Group video enc error: ${e.message}")
                        }
                    }
                },
                onCancel = { showVideoCircleRecorder = false }
            )
        }

        if (isEditMode) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(if (c.isDark) Color(0xFF180A0C) else c.gradientEnd)
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    s.groupChatEditing,
                    fontSize = 14.sp,
                    color = Primary,
                    modifier = Modifier.weight(1f),
                    fontFamily = JetBrainsMono
                )
                TextButton(onClick = {
                    isEditMode = false
                    editingMessageId = null
                    inputText = ""
                }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontSize = 14.sp, fontFamily = JetBrainsMono)
                }
            }
        }

        // Reply preview bar — mirrors ChatScreen.kt's 1:1 replyToMessage bar
        // exactly (icon, "Replying to" label, truncated original text, X to
        // cancel).
        if (replyToMessage != null) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(if (c.isDark) Color(0xFF180A0C) else c.gradientEnd)
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_reply),
                    contentDescription = null,
                    tint = Primary,
                    modifier = Modifier.size(18.dp).padding(end = 4.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(s.chatReplyPreview, fontSize = 13.sp, color = Primary, fontFamily = JetBrainsMono)
                    Text(
                        replyToMessage!!.text.take(60), fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.7f),
                        maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = JetBrainsMono
                    )
                }
                IconButton(onClick = { replyToMessage = null }) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = null,
                        tint = c.textPrimary.copy(alpha = 0.6f),
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }

        // Mirrors ChatScreen.kt's 1:1 finishRecordingAndSend() exactly — see
        // its own comment for why recordingSeconds (real elapsed time) is
        // used for duration instead of a byte-length estimate.
        fun finishGroupRecordingAndSend() {
            recordingFile?.let { file ->
                AudioHelper.stopRecording()
                val duration = recordingSeconds
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
        }

        fun cancelGroupRecording() {
            AudioHelper.stopRecording()
            recordingFile?.delete()
            recordingFile = null
            isRecording = false
        }

        LaunchedEffect(isRecording) {
            if (isRecording) {
                recordingSeconds = 0
                while (isRecording) {
                    delay(1000L)
                    recordingSeconds++
                    if (recordingSeconds >= GROUP_VOICE_MAX_DURATION_SECONDS) {
                        finishGroupRecordingAndSend()
                    }
                }
            } else {
                recordingSeconds = 0
            }
        }

        AnimatedContent(
            targetState = isRecording,
            transitionSpec = {
                (fadeIn(tween(180)) + scaleIn(tween(180), initialScale = 0.96f)) togetherWith
                (fadeOut(tween(140)) + scaleOut(tween(140), targetScale = 0.96f))
            },
            label = "group_input_bar_mode"
        ) { recording ->
            if (recording) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(if (c.isDark) Color(0xFF4A151A) else c.topBar)
                        .padding(horizontal = 10.dp, vertical = 10.dp)
                        .navigationBarsPadding()
                        .imePadding(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .clip(CircleShape)
                            .background(Color(0x28FF4444))
                            .clickable { cancelGroupRecording() },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_close),
                            contentDescription = s.cancel,
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
                        val recDotAlpha = remember { Animatable(1f) }
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
                        onClick = { finishGroupRecordingAndSend() },
                        size = 44
                    )
                }
            } else {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(if (c.isDark) Color(0xFF4A151A) else c.topBar)
                    .padding(8.dp)
                    .navigationBarsPadding()
                    .imePadding(),
                verticalAlignment = Alignment.Bottom
            ) {

                var showAttachMenu by remember { mutableStateOf(false) }
                // Circular icon button matching ChatScreen.kt's 1:1 attach
                // button exactly (was a plain default-ripple IconButton).
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
                Spacer(modifier = Modifier.width(6.dp))

                if (showAttachMenu) {
                    AlertDialog(
                        onDismissRequest = { showAttachMenu = false },
                        title = {
                            Text(s.groupChatAttach, color = c.textPrimary, fontSize = 22.sp, fontFamily = JetBrainsMono)
                        },
                        text = {
                            Column {
                                TextButton(onClick = {
                                    showAttachMenu = false
                                    try {
                                        (context as? MainActivity)?.startActivityForResult(
                                            Intent(Intent.ACTION_GET_CONTENT).apply {
                                                type = "*/*"
                                                putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("image/*"))
                                                addCategory(Intent.CATEGORY_OPENABLE)
                                            },
                                            MainActivity.PICK_IMAGE_REQUEST
                                        )
                                    } catch (e: Exception) {}
                                }) {
                                    Text(s.groupChatAttachPhoto, color = c.textPrimary, fontSize = 20.sp, fontFamily = JetBrainsMono)
                                }
                                TextButton(onClick = {
                                    showAttachMenu = false
                                    try {
                                        (context as? MainActivity)?.startActivityForResult(
                                            Intent(Intent.ACTION_GET_CONTENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) },
                                            MainActivity.PICK_FILE_REQUEST
                                        )
                                    } catch (e: Exception) {}
                                }) {
                                    Text(s.groupChatAttachFile, color = c.textPrimary, fontSize = 20.sp, fontFamily = JetBrainsMono)
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
                                    Text(s.groupChatGeo, color = c.textPrimary, fontSize = 20.sp, fontFamily = JetBrainsMono)
                                }
                            }
                        },
                        confirmButton = {},
                        containerColor = if (c.isDark) Color(0xFF4A151A) else c.dialog
                    )
                }

                Box(modifier = Modifier.weight(1f).padding(horizontal = 4.dp)) {
                    // Focus-animated border matching ChatScreen.kt's 1:1
                    // input field exactly (was a static border — no visual
                    // feedback at all when the field was actually focused).
                    val inputInteraction = remember { MutableInteractionSource() }
                    val isInputFocused by inputInteraction.collectIsFocusedAsState()
                    val inputBorderColor by androidx.compose.animation.animateColorAsState(
                        targetValue = if (isInputFocused) Primary.copy(alpha = 0.6f) else Color(0x33B0C4DE),
                        animationSpec = tween(250),
                        label = "groupInputBorder"
                    )
                    androidx.compose.foundation.Canvas(modifier = Modifier.matchParentSize()) {
                        drawRoundRect(
                            color = androidx.compose.ui.graphics.Color(0x22FFFFFF),
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
                        onValueChange = { inputText = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        maxLines = 3,
                        textStyle = TextStyle(fontSize = 17.sp, color = c.textPrimary),
                        cursorBrush = SolidColor(Color(0xFFFFD700)),
                        interactionSource = inputInteraction,
                        decorationBox = { innerTextField ->
                            if (inputText.isEmpty()) {
                                Text(
                                    if (isEditMode) s.groupChatEditHint else s.groupChatMessageHint,
                                    fontSize = 17.sp,
                                    color = c.textPrimary.copy(alpha = 0.53f),
                                    fontFamily = JetBrainsMono
                                )
                            }
                            innerTextField()
                        }
                    )
                }

                if (inputText.isNotEmpty() || isEditMode) {
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
                                    val replyId = replyToMessage?.id
                                    replyToMessage = null

                                    val groupMessage = GroupMessage(
                                        id = messageId,
                                        groupId = groupId,
                                        senderId = userId,
                                        senderName = username,
                                        text = text,
                                        isOwn = true,
                                        replyToId = replyId
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
                                        members = recipients,
                                        replyToId = replyId
                                    )
                                }
                            }
                        },
                        size = 44
                    )
                } else {
                    // CombinedMediaButton (tap toggles voice/video mode,
                    // long-press starts recording in that mode) matching
                    // ChatScreen.kt's 1:1 idle-state button exactly — was a
                    // plain click-to-record voice-only WaveformMicButton
                    // with no video-circle option at all.
                    CombinedMediaButton(
                        isVideoMode = isVideoMode,
                        onToggleMode = { isVideoMode = !isVideoMode },
                        onStartVoice = {
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
                        },
                        onStartVideo = { showVideoCircleRecorder = true },
                        size = 44
                    )
                }
            }
            }
        }
    }
}

private fun sendGeoMessage(
    context: Context,
    group: Group,
    userId: String,
    username: String,
    messages: MutableList<GroupMessage>,
    messengerService: MessengerService?,
    scope: kotlinx.coroutines.CoroutineScope,
    listState: androidx.compose.foundation.lazy.LazyListState,
    geoLabel: String = "Геопозиция",
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun GroupMessageBubble(
    msg: GroupMessage,
    replyToOriginal: GroupMessage? = null,
    onLongClick: ((GroupMessage) -> Unit)? = null,
    onReactionClick: ((GroupMessage) -> Unit)? = null,
    playingVoiceId: String? = null,
    onVoicePlay: ((String) -> Unit)? = null,
    onVoiceStop: (() -> Unit)? = null,
    playingVideoId: String? = null,
    onVideoPlay: ((String) -> Unit)? = null,
    onVideoStop: (() -> Unit)? = null
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val isOwn = msg.isOwn
    val isSystem = msg.isSystem()
    val isVoice = msg.isVoice()
    val voiceFile = msg.voiceFile()
    val voiceDuration = msg.voiceDuration()

    // Bubble fill is guarded on c.isDark rather than swapped outright: BubbleOwn/
    // BubbleOther are legacy static colors (ui/theme/Color.kt, not SubrosaColors)
    // used here for NAVY *and* DARK today, so an unconditional swap to
    // c.bubbleOwn/c.bubbleOther would recolor NAVY's own-message bubble from
    // maroon to green — a dark-theme visual change that's out of bounds. Only
    // LIGHT (isDark=false) picks up the new theme-driven bubble colors.
    val bubbleColor = when {
        isSystem -> if (c.isDark) Color(0xFF1a2a1a) else c.bubbleSystem
        isOwn -> if (c.isDark) BubbleOwn else c.bubbleOwn
        else -> if (c.isDark) BubbleOther else c.bubbleOther
    }
    val alignment = if (isOwn || isSystem) Alignment.CenterEnd else Alignment.CenterStart

    val avatarColor = remember(msg.senderName) {
        listOf(
            Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
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
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = msg.senderName,
                    fontSize = 14.sp,
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
                // Video circles get a transparent, shadowless, zero-padding
                // bubble — otherwise the round video note sits padded inside
                // a solid rounded-rect card, which is exactly the
                // "rectangular attachment with a circle inside" look the
                // video-note redesign was meant to remove. 1:1 ChatScreen.kt
                // already did this; group chat never had the equivalent fix.
                color = if (msg.videoPath != null) Color.Transparent else bubbleColor,
                shadowElevation = if (msg.videoPath != null) 0.dp else 1.dp
            ) {
                Column(
                    modifier = Modifier.padding(
                        horizontal = if (msg.videoPath != null) 0.dp else 12.dp,
                        vertical = if (msg.videoPath != null) 0.dp else 8.dp
                    )
                ) {

                    // Reply quote — mirrors ChatScreen.kt's 1:1 in-bubble
                    // quote block exactly (accent bar + "Reply" label +
                    // truncated original text).
                    if (replyToOriginal != null) {
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
                                    .background(Primary)
                            )
                            Column(modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
                                Text(s.chatReplyLabel, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Primary)
                                Text(
                                    replyToOriginal.text.take(80), fontSize = 14.sp, maxLines = 2,
                                    overflow = TextOverflow.Ellipsis, color = c.textPrimary.copy(alpha = 0.7f)
                                )
                            }
                        }
                    }

                    if (msg.imagePath != null) {
                        val bitmap = remember(msg.imagePath) {
                            try {
                                if (msg.imagePath.endsWith(".enc")) {
                                    val bytes = SecureFileStorage.read(context, File(msg.imagePath))
                                    android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                                } else android.graphics.BitmapFactory.decodeFile(msg.imagePath)
                            } catch (e: Exception) { null }
                        }
                        if (bitmap != null) {
                            Image(
                                bitmap = bitmap.asImageBitmap(),
                                contentDescription = null,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = 160.dp, max = 320.dp)
                                    .padding(bottom = 4.dp)
                            )
                        }
                    }

                    // Video circle (round video message) — shared
                    // VideoCircleBubble composable, same as ChatScreen.kt's
                    // 1:1 rendering (previously two identical copies of this
                    // block, one per screen).
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
                                cachePrefix = "g"
                            )
                            // Time overlaid on the circle itself, same
                            // reasoning as ChatScreen.kt's 1:1 case — group
                            // messages don't track per-message delivery
                            // ticks, so just the time. Hidden while playing.
                            if (!isVideoPlaying && !isSystem) {
                                Text(
                                    text = timeStr,
                                    fontSize = 11.sp,
                                    color = Color.White,
                                    modifier = Modifier
                                        .align(Alignment.BottomStart)
                                        .padding(8.dp)
                                        .background(Color(0x88000000), CircleShape)
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }
                    }

                    if (msg.fileName != null && msg.filePath != null) {
                        FilePreview(fileName = msg.fileName, filePath = msg.filePath, context = context)
                    }

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
                                fontSize = 22.sp,
                                modifier = Modifier.padding(end = 8.dp)
                            )
                            Text(
                                text = "${voiceDuration}\"",
                                fontSize = 19.sp,
                                color = Primary
                            )
                        }
                    } else if (msg.videoPath == null) {

                        Text(
                            text = msg.text,
                            fontSize = if (isSystem) 13.sp else 16.sp,
                            lineHeight = 20.sp,
                            // System messages keep their dedicated pale-green tint on
                            // NAVY/DARK (bubble bg there is unchanged, see bubbleColor
                            // above); everywhere else — and LIGHT unconditionally —
                            // this is the same c.textPrimary-on-bubble convention
                            // ChatScreen.kt's bubble renderer already uses.
                            color = if (isSystem && c.isDark) Color(0xFFAAFFAA) else c.textPrimary,
                            fontFamily = if (isSystem) JetBrainsMono else null
                        )
                    }

                    // Video circles show their own time overlay on the
                    // circle itself (see the Box above) — this trailing
                    // timeStr would otherwise sit in the now-zero-padding
                    // Column right under the circle with nothing to anchor
                    // it against.
                    if (msg.videoPath == null) {
                        Text(
                            text = timeStr,
                            fontSize = 12.sp,
                            color = c.textPrimary.copy(alpha = 0.4f),
                            modifier = Modifier
                                .align(Alignment.End)
                                .padding(top = 2.dp)
                        )
                    }
                }
            }

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
                        Text(emoji, fontSize = 16.sp)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(if (msg.reactions.isNotEmpty()) 14.dp else 2.dp))
    }
}
