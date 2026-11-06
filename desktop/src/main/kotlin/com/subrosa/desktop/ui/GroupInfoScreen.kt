package com.subrosa.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// Same 32-emoji list as Android's GroupInfoScreen.kt, for a consistent
// avatar picker across platforms.
private val GROUP_AVATAR_EMOJIS = listOf(
    "👥", "💬", "🎮", "📚", "💼", "🎵", "🏠", "🌍",
    "🔒", "🎯", "🏆", "❤️", "🌟", "💡", "🚀", "🎉",
    "🎨", "📱", "💻", "🎓", "🍕", "☕", "🐱", "🦁",
    "🌈", "⚡", "🔥", "💎", "🛡️", "⚔️", "🧩", "🎭"
)

/** Desktop's Telegram-style group settings screen — avatar/description
 *  editing, member roles + promote/remove/add, leave (non-creator) / delete
 *  (creator). Mirrors Android's GroupInfoScreen.kt feature set, styled with
 *  the same SHeader/SGroup/SItem grouped-list components ProfileScreen.kt
 *  established for Desktop's other settings screens.
 *
 *  [onBack] is the ordinary top-bar back arrow (returns to the still-open
 *  group chat). [onGroupGone] is called after a successful leave/delete,
 *  since at that point the group no longer exists locally and navigating
 *  back to the chat screen would show a broken/empty state — callers should
 *  route this to the chat list instead. */
@Composable
fun GroupInfoScreen(groupId: String, onBack: () -> Unit, onGroupGone: () -> Unit = onBack) {
    val myId = WebSocketClient.myFingerprint
    var group by remember { mutableStateOf(GroupManager.getGroup(groupId)) }

    if (group == null) {
        LaunchedEffect(Unit) { onGroupGone() }
        return
    }
    val g = group!!
    val isCreator = g.createdBy == myId
    val isAdmin = remember(group) { GroupManager.isAdmin(groupId, myId) }

    var showEmojiPicker by remember { mutableStateOf(false) }
    // Group chat previously had emoji-only avatars — showAvatarChoice
    // offers a choice between the existing emoji grid and a real photo
    // (mirrors ProfileScreen.kt's own avatar flow, reusing AvatarCropDialog,
    // which already has the fixed zoom/pan transform). New 2026-09-21.
    var showAvatarChoice by remember { mutableStateOf(false) }
    var pendingGroupAvatarImage by remember { mutableStateOf<java.awt.image.BufferedImage?>(null) }
    var showEditDesc by remember { mutableStateOf(false) }
    var descInput by remember { mutableStateOf(g.description) }
    var showAddPicker by remember { mutableStateOf(false) }
    var showLeaveConfirm by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }

    DisposableEffect(groupId) {
        WebSocketClient.onGroupAvatarUpdated = { updatedGroupId ->
            if (updatedGroupId == groupId) {
                group = GroupManager.getGroup(updatedGroupId)
            }
        }
        onDispose { WebSocketClient.onGroupAvatarUpdated = null }
    }
    val scope = rememberCoroutineScope()

    fun pickGroupAvatarPhoto() {
        val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Выбрать фото", java.awt.FileDialog.LOAD)
        dialog.isVisible = true
        val fileName = dialog.file
        val dir = dialog.directory
        if (fileName == null || dir == null) return
        val picked = java.io.File(dir, fileName)
        scope.launch(Dispatchers.IO) {
            try {
                val original = javax.imageio.ImageIO.read(picked) ?: return@launch
                withContext(Dispatchers.Main) { pendingGroupAvatarImage = original }
            } catch (_: Exception) {}
        }
    }

    fun applyCroppedGroupAvatar(cropped: java.awt.image.BufferedImage) {
        pendingGroupAvatarImage = null
        val groupKey = g.groupKey ?: return
        scope.launch(Dispatchers.IO) {
            try {
                val out = java.io.ByteArrayOutputStream()
                javax.imageio.ImageIO.write(cropped, "jpg", out)
                val avatarBytes = out.toByteArray()
                val b64 = java.util.Base64.getEncoder().encodeToString(avatarBytes)
                val avatarDir = java.io.File(DesktopStorage.resolveDataDir(), "blobs").also { it.mkdirs() }
                val avatarFile = java.io.File(avatarDir, "group_avatar_$groupId.enc")
                avatarFile.writeBytes(DesktopStorage.encryptRaw(avatarBytes))
                val updated = g.copy(avatarPath = avatarFile.absolutePath)
                GroupManager.saveGroup(updated)
                withContext(Dispatchers.Main) {
                    group = updated
                    WebSocketClient.sendGroupAvatarUpdate(groupId, b64)
                }
            } catch (e: Exception) {
                System.err.println("GroupInfoScreen: group avatar crop/save failed — ${e.message}")
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(AppIcons.get("BACK_ARROW"), contentDescription = "Назад", tint = SubrosaTheme.textPrimary)
                }
                Text("Информация о группе", fontSize = 19.sp, fontWeight = FontWeight.SemiBold,
                    color = SubrosaTheme.textPrimary)
            }
        }

        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
            Spacer(Modifier.height(20.dp))
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                val avatarPath = g.avatarPath
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
                        .size(84.dp)
                        .clip(CircleShape)
                        .background(SubrosaTheme.accent.copy(alpha = 0.15f))
                        .then(if (isAdmin) Modifier.clickable { showAvatarChoice = true } else Modifier),
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
                        Text(g.avatar, fontSize = 36.sp)
                    }
                }
                if (isAdmin) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Изменить",
                        fontSize = 13.sp,
                        color = SubrosaTheme.textSecondary,
                        modifier = Modifier.clickable { showAvatarChoice = true }
                    )
                }
                Spacer(Modifier.height(10.dp))
                Text(g.name, fontSize = 21.sp, fontWeight = FontWeight.Bold, color = SubrosaTheme.textPrimary, fontFamily = NotoSerifJP)
                Spacer(Modifier.height(4.dp))
                Text("${g.members.size} участников", fontSize = 14.sp, color = SubrosaTheme.textSecondary)
            }

            SHeader("Описание")
            SGroup {
                SItem(
                    icon = "",
                    label = g.description.ifBlank { if (isAdmin) "Добавить описание" else "Нет описания" },
                    onClick = if (isAdmin) {
                        { descInput = g.description; showEditDesc = true }
                    } else null
                ) {
                    if (isAdmin) Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
            }

            SHeader("Участники (${g.members.size})")
            SGroup {
                g.members.forEachIndexed { idx, fp ->
                    val fpIsAdmin = g.admins.contains(fp) || g.createdBy == fp
                    SItem(
                        icon = "",
                        label = if (fp == myId) "Вы" else ChatStorage.getContactName(fp),
                        hint = if (fpIsAdmin) "Админ" else null
                    ) {
                        if (isAdmin && fp != myId) {
                            Row {
                                if (!fpIsAdmin) {
                                    TextButton(onClick = {
                                        GroupManager.promoteToAdmin(groupId, myId, fp)
                                        group = GroupManager.getGroup(groupId)
                                    }) { Text("Админ", color = SubrosaTheme.accent, fontSize = 13.sp) }
                                }
                                TextButton(onClick = {
                                    WebSocketClient.notifyMemberRemoved(groupId, fp)
                                    GroupManager.removeMember(groupId, myId, fp)
                                    WebSocketClient.rotateGroupKey(groupId)
                                    group = GroupManager.getGroup(groupId)
                                }) { Text("Удалить", color = SubrosaTheme.error, fontSize = 13.sp) }
                            }
                        }
                    }
                    if (idx < g.members.size - 1) SLine()
                }
                if (isAdmin) {
                    SLine()
                    SItem(icon = "", label = "Добавить участника", labelColor = SubrosaTheme.accent,
                        onClick = { showAddPicker = true }) {}
                }
            }

            Spacer(Modifier.height(24.dp))
            if (!isCreator) {
                Surface(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)
                        .clickable { showLeaveConfirm = true },
                    shape = RoundedCornerShape(14.dp),
                    color = SubrosaTheme.error.copy(alpha = 0.09f)
                ) {
                    Text("Покинуть группу", fontSize = 16.sp, color = SubrosaTheme.error,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp))
                }
            } else {
                Surface(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)
                        .clickable { showDeleteConfirm = true },
                    shape = RoundedCornerShape(14.dp),
                    color = SubrosaTheme.error.copy(alpha = 0.09f)
                ) {
                    Text("Удалить группу", fontSize = 16.sp, color = SubrosaTheme.error,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp))
                }
            }
        }
    }

    if (showAvatarChoice) {
        AlertDialog(
            onDismissRequest = { showAvatarChoice = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Изменить аватар", color = SubrosaTheme.textPrimary) },
            text = {
                Column {
                    TextButton(onClick = {
                        showAvatarChoice = false
                        pickGroupAvatarPhoto()
                    }) { Text("Выбрать фото", color = SubrosaTheme.textPrimary) }
                    TextButton(onClick = {
                        showAvatarChoice = false
                        showEmojiPicker = true
                    }) { Text("Выбрать эмодзи", color = SubrosaTheme.textPrimary) }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showAvatarChoice = false }) { Text("Отмена", color = SubrosaTheme.textSecondary) }
            }
        )
    }

    pendingGroupAvatarImage?.let { img ->
        AvatarCropDialog(
            source = img,
            onConfirm = { cropped -> applyCroppedGroupAvatar(cropped) },
            onCancel = { pendingGroupAvatarImage = null }
        )
    }

    if (showEmojiPicker) {
        AlertDialog(
            onDismissRequest = { showEmojiPicker = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Выберите эмодзи", color = SubrosaTheme.textPrimary) },
            text = {
                LazyVerticalGrid(columns = GridCells.Fixed(8), modifier = Modifier.heightIn(max = 240.dp)) {
                    items(GROUP_AVATAR_EMOJIS) { emoji ->
                        Box(
                            contentAlignment = Alignment.Center,
                            modifier = Modifier.size(40.dp).clickable {
                                val updated = g.copy(avatar = emoji)
                                GroupManager.saveGroup(updated)
                                group = updated
                                showEmojiPicker = false
                                // Notify other members — was local-only
                                // before. See sendGroupAvatarUpdate()'s own
                                // comment on the "EMOJI:" prefix.
                                WebSocketClient.sendGroupAvatarUpdate(groupId, "EMOJI:$emoji")
                            }
                        ) { Text(emoji, fontSize = 26.sp) }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showEmojiPicker = false }) { Text("Отмена", color = SubrosaTheme.textSecondary) }
            }
        )
    }

    if (showEditDesc) {
        AlertDialog(
            onDismissRequest = { showEditDesc = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Описание группы", color = SubrosaTheme.textPrimary) },
            text = {
                OutlinedTextField(
                    value = descInput,
                    onValueChange = { if (it.length <= 300) descInput = it },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                    maxLines = 5,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val updated = g.copy(description = descInput.trim())
                    GroupManager.saveGroup(updated)
                    group = updated
                    showEditDesc = false
                }) { Text("Сохранить", color = SubrosaTheme.accent) }
            },
            dismissButton = {
                TextButton(onClick = { showEditDesc = false }) { Text("Отмена", color = SubrosaTheme.textSecondary) }
            }
        )
    }

    if (showAddPicker) {
        val candidates = ChatStorage.getContacts().filter { it !in g.members }
        AlertDialog(
            onDismissRequest = { showAddPicker = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Добавить участника", color = SubrosaTheme.textPrimary) },
            text = {
                if (candidates.isEmpty()) {
                    Text("Все ваши контакты уже в группе", color = SubrosaTheme.textSecondary, fontSize = 15.sp)
                } else {
                    Column(Modifier.heightIn(max = 260.dp)) {
                        candidates.forEach { fp ->
                            Row(
                                modifier = Modifier.fillMaxWidth()
                                    .clickable {
                                        WebSocketClient.addGroupMember(groupId, fp)
                                        group = GroupManager.getGroup(groupId)
                                        showAddPicker = false
                                    }
                                    .padding(vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(ChatStorage.getContactName(fp), color = SubrosaTheme.textPrimary, fontSize = 15.sp)
                            }
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showAddPicker = false }) { Text("Отмена", color = SubrosaTheme.textSecondary) }
            }
        )
    }

    if (showLeaveConfirm) {
        AlertDialog(
            onDismissRequest = { showLeaveConfirm = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Покинуть группу?", color = SubrosaTheme.textPrimary) },
            text = { Text("Вы больше не будете получать сообщения из «${g.name}».", color = SubrosaTheme.textSecondary) },
            confirmButton = {
                TextButton(onClick = {
                    showLeaveConfirm = false
                    WebSocketClient.notifyMemberRemoved(groupId, myId)
                    GroupManager.removeMember(groupId, myId, myId)
                    onGroupGone()
                }) { Text("Покинуть", color = SubrosaTheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showLeaveConfirm = false }) { Text("Отмена", color = SubrosaTheme.textSecondary) }
            }
        )
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Удалить группу?", color = SubrosaTheme.textPrimary) },
            text = { Text("Группа «${g.name}» будет удалена без возможности восстановления.", color = SubrosaTheme.textSecondary) },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteConfirm = false
                    GroupManager.deleteGroup(groupId)
                    onGroupGone()
                }) { Text("Удалить", color = SubrosaTheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) { Text("Отмена", color = SubrosaTheme.textSecondary) }
            }
        )
    }
}
