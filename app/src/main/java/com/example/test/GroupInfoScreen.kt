package com.bcon.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.ExitToApp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.absoluteValue
import com.bcon.messenger.ui.theme.LocalBeaconColors


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupInfoScreen(groupId: String, onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val userId = UserStorage.getUserId(context)

    var group by remember { mutableStateOf(GroupManager.getGroup(context, groupId)) }
    var showAddMemberDialog by remember { mutableStateOf(false) }
    var showLeaveDialog by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var showEmojiPickerDialog by remember { mutableStateOf(false) }
    var showEditDescDialog by remember { mutableStateOf(false) }
    var descInput by remember { mutableStateOf(group?.description ?: "") }
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }

    val isAdmin = remember(group) {
        group?.let { GroupManager.isAdmin(context, groupId, userId) } ?: false
    }
    val isCreator = remember(group) { group?.createdBy == userId }

    // Подключение к сервису
    val connection = remember {
        object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName, binder: android.os.IBinder) {
                messengerService = (binder as MessengerService.LocalBinder).getService()
            }

            override fun onServiceDisconnected(name: android.content.ComponentName) {
                messengerService = null
            }
        }
    }

    LaunchedEffect(Unit) {
        context.bindService(
            android.content.Intent(context, MessengerService::class.java),
            connection,
            android.content.Context.BIND_AUTO_CREATE
        )
    }

    DisposableEffect(Unit) {
        onDispose {
            try { context.unbindService(connection) } catch (e: Exception) {}
        }
    }

    if (group == null) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text(s.groupInfoNotFound, color = Color.White)
        }
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.groupInfoTitle, color = Color.White, fontFamily = JetBrainsMono) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, s.back, tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Аватар и название группы
            item {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Surface(
                        shape = CircleShape,
                        color = c.primaryBlue,
                        modifier = Modifier
                            .size(100.dp)
                            .then(
                                if (isAdmin) Modifier.clickable { showEmojiPickerDialog = true }
                                else Modifier
                            )
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text(group!!.avatar, fontSize = 48.sp)
                        }
                    }

                    if (isAdmin) {
                        Text(
                            s.groupInfoChangeAvatar,
                            fontSize = 11.sp,
                            color = c.accent.copy(alpha = 0.7f),
                            fontFamily = JetBrainsMono,
                            modifier = Modifier
                                .clickable { showEmojiPickerDialog = true }
                                .padding(top = 4.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        group!!.name,
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        fontFamily = JetBrainsMono
                    )

                    Text(
                        s.groupInfoMembersCount(group!!.members.size),
                        fontSize = 14.sp,
                        color = c.textPrimary.copy(alpha = 0.6f),
                        fontFamily = JetBrainsMono
                    )
                }
            }

            // Описание группы
            item {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = c.card
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                s.groupInfoDescription,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = c.textPrimary.copy(alpha = 0.6f),
                                fontFamily = JetBrainsMono
                            )
                            if (isAdmin) {
                                TextButton(onClick = {
                                    descInput = group!!.description
                                    showEditDescDialog = true
                                }) {
                                    Text("✏️", fontSize = 18.sp)
                                }
                            }
                        }
                        val desc = group!!.description
                        if (desc.isBlank()) {
                            Text(
                                if (isAdmin) s.groupInfoAddDescription else s.groupInfoNoDescription,
                                fontSize = 14.sp,
                                color = c.textPrimary.copy(alpha = 0.4f),
                                fontFamily = JetBrainsMono
                            )
                        } else {
                            Text(
                                desc,
                                fontSize = 14.sp,
                                color = c.textPrimary,
                                fontFamily = JetBrainsMono
                            )
                        }
                    }
                }
            }

            // Участники
            item {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = c.card
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                s.groupInfoMembersSection,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White,
                                fontFamily = JetBrainsMono
                            )

                            if (isAdmin) {
                                TextButton(onClick = { showAddMemberDialog = true }) {
                                    Text("➕", fontSize = 20.sp, color = c.accent)
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        group!!.members.forEach { memberId ->
                            val memberName = ChatStorage.getContactName(context, memberId)
                            val isMemberAdmin = group!!.admins.contains(memberId)
                            val isMemberCreator = group!!.createdBy == memberId

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                val avatarColor = remember(memberName) {
                                    val colors = listOf(
                                        Color(0xFF2481CC), Color(0xFFE74C3C), Color(0xFF27AE60),
                                        Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
                                    )
                                    colors[memberName.hashCode().absoluteValue % colors.size]
                                }

                                Surface(
                                    shape = CircleShape,
                                    color = avatarColor,
                                    modifier = Modifier.size(40.dp)
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Text(
                                            text = memberName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                            fontSize = 18.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.width(12.dp))

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        memberName,
                                        fontSize = 16.sp,
                                        color = Color.White,
                                        fontFamily = JetBrainsMono
                                    )

                                    if (isMemberCreator) {
                                        Text(
                                            s.groupInfoCreator,
                                            fontSize = 12.sp,
                                            color = Color(0xFFFFD700),
                                            fontFamily = JetBrainsMono
                                        )
                                    } else if (isMemberAdmin) {
                                        Text(
                                            s.groupInfoAdmin,
                                            fontSize = 12.sp,
                                            color = c.accent,
                                            fontFamily = JetBrainsMono
                                        )
                                    }
                                }

                                // Действия с участником
                                if (isAdmin && memberId != userId && !isMemberCreator) {
                                    var showMemberMenu by remember { mutableStateOf(false) }

                                    IconButton(onClick = { showMemberMenu = true }) {
                                        Text("⋮", fontSize = 20.sp, color = Color.White)
                                    }

                                    DropdownMenu(
                                        expanded = showMemberMenu,
                                        onDismissRequest = { showMemberMenu = false }
                                    ) {
                                        if (!isMemberAdmin) {
                                            DropdownMenuItem(
                                                text = { Text(s.groupInfoPromoteAdmin) },
                                                onClick = {
                                                    GroupManager.promoteToAdmin(context, groupId, memberId)
                                                    group = GroupManager.getGroup(context, groupId)
                                                    showMemberMenu = false
                                                }
                                            )
                                        }

                                        DropdownMenuItem(
                                            text = { Text(s.groupInfoRemoveMember, color = Color.Red) },
                                            onClick = {
                                                // Удаляем участника
                                                GroupManager.removeMember(context, groupId, memberId)

                                                // Уведомляем через сервис
                                                messengerService?.notifyMemberRemoved(
                                                    groupId,
                                                    memberId,
                                                    group!!.members
                                                )

                                                // Ротируем ключ
                                                val newGroupKey = GroupManager.generateGroupKey()
                                                val updatedGroup = group!!.copy(groupKey = newGroupKey)
                                                GroupManager.saveGroup(context, updatedGroup)

                                                messengerService?.rotateGroupKey(
                                                    groupId,
                                                    newGroupKey,
                                                    updatedGroup.members
                                                )

                                                group = GroupManager.getGroup(context, groupId)
                                                showMemberMenu = false
                                            }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Действия
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    // Покинуть группу
                    if (!isCreator) {
                        OutlinedButton(
                            onClick = { showLeaveDialog = true },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = Color(0xFFFF6B6B)
                            ),
                            border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFFF6B6B))
                        ) {
                            Icon(Icons.Default.ExitToApp, null, tint = Color(0xFFFF6B6B))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(s.groupInfoLeave, fontFamily = JetBrainsMono)
                        }
                    }

                    // Удалить группу (только создатель)
                    if (isCreator) {
                        OutlinedButton(
                            onClick = { showDeleteDialog = true },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = c.error
                            ),
                            border = androidx.compose.foundation.BorderStroke(1.dp, c.error)
                        ) {
                            Icon(Icons.Default.Delete, null, tint = c.error)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(s.groupInfoDeleteGroup, fontFamily = JetBrainsMono)
                        }
                    }
                }
            }
        }
    }

    // Диалог добавления участника
    // Диалог добавления участника по инвайт-коду
    if (showAddMemberDialog) {
        var inviteCode by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = { showAddMemberDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoAddMemberTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    Text(
                        s.groupInfoAddMemberHint,
                        fontSize = 12.sp,
                        color = c.textPrimary.copy(alpha = 0.7f),
                        fontFamily = JetBrainsMono
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedTextField(
                        value = inviteCode,
                        onValueChange = { inviteCode = it },
                        label = { Text(s.groupInfoAddMemberLabel, fontFamily = JetBrainsMono) },
                        singleLine = false,
                        maxLines = 4,
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = c.accent
                        )
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (inviteCode.isNotBlank()) {
                            // Парсим инвайт-код
                            val parts = inviteCode.trim().split("&")
                            val userId = parts.firstOrNull()?.trim() ?: ""
                            val publicKey = parts.find { it.startsWith("pk=") }
                                ?.removePrefix("pk=")?.trim()

                            if (userId.isNotEmpty() && publicKey != null) {
                                // Проверяем что участник ещё не в группе
                                if (!group!!.members.contains(userId)) {
                                    // Сохраняем контакт если его нет
                                    if (!ChatStorage.getContacts(context).contains(userId)) {
                                        ChatStorage.addContact(context, userId)
                                        ChatStorage.saveContactPublicKey(context, userId, publicKey)
                                    }

                                    // Добавляем в группу
                                    GroupManager.addMember(context, groupId, userId)

                                    // Отправляем приглашение через сервис
                                    messengerService?.addGroupMember(
                                        groupId = groupId,
                                        groupName = group!!.name,
                                        groupAvatar = group!!.avatar,
                                        newMemberId = userId,
                                        groupKey = group!!.groupKey!!
                                    )

                                    group = GroupManager.getGroup(context, groupId)
                                    showAddMemberDialog = false
                                } else {
                                    // Участник уже в группе
                                    android.widget.Toast.makeText(
                                        context,
                                        s.groupInfoAlreadyMember,
                                        android.widget.Toast.LENGTH_SHORT
                                    ).show()
                                }
                            } else {
                                // Неверный формат инвайт-кода
                                android.widget.Toast.makeText(
                                    context,
                                    s.groupInfoBadInvite,
                                    android.widget.Toast.LENGTH_SHORT
                                ).show()
                            }
                        }
                    },
                    enabled = inviteCode.isNotBlank()
                ) {
                    Text(s.add, color = c.accent, fontFamily = JetBrainsMono)
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddMemberDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    // Диалог выхода из группы
    if (showLeaveDialog) {
        AlertDialog(
            onDismissRequest = { showLeaveDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoLeaveTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Text(
                    s.groupInfoLeaveText(group!!.name),
                    color = c.textPrimary,
                    fontFamily = JetBrainsMono
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    // Удаляем себя из группы
                    GroupManager.removeMember(context, groupId, userId)

                    // Уведомляем других участников
                    messengerService?.notifyMemberRemoved(
                        groupId,
                        userId,
                        group!!.members
                    )

                    // Обновляем список чатов
                    MainActivity.chatListVersion.value = System.currentTimeMillis()

                    showLeaveDialog = false
                    onBack()
                }) {
                    Text(s.groupInfoLeaveConfirm, color = Color(0xFFFF6B6B), fontFamily = JetBrainsMono)
                }
            },
            dismissButton = {
                TextButton(onClick = { showLeaveDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    // Диалог выбора эмодзи-аватара
    if (showEmojiPickerDialog) {
        val emojiList = listOf(
            "👥","💬","🎮","📚","💼","🎵","🏠","🌍",
            "🔒","🎯","🏆","❤️","🌟","💡","🚀","🎉",
            "🎨","📱","💻","🎓","🍕","☕","🐱","🦁",
            "🌈","⚡","🔥","💎","🛡️","⚔️","🧩","🎭"
        )
        AlertDialog(
            onDismissRequest = { showEmojiPickerDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoEmojiTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                LazyVerticalGrid(
                    columns = GridCells.Fixed(8),
                    modifier = Modifier.heightIn(max = 240.dp)
                ) {
                    items(emojiList) { emoji ->
                        Box(
                            contentAlignment = Alignment.Center,
                            modifier = Modifier
                                .size(40.dp)
                                .clickable {
                                    val updated = group!!.copy(avatar = emoji)
                                    GroupManager.saveGroup(context, updated)
                                    group = updated
                                    showEmojiPickerDialog = false
                                }
                        ) {
                            Text(emoji, fontSize = 24.sp)
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showEmojiPickerDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    // Диалог редактирования описания
    if (showEditDescDialog) {
        AlertDialog(
            onDismissRequest = { showEditDescDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoDescTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                OutlinedTextField(
                    value = descInput,
                    onValueChange = { if (it.length <= 300) descInput = it },
                    label = { Text(s.groupInfoDescLabel, fontFamily = JetBrainsMono) },
                    singleLine = false,
                    maxLines = 5,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = c.accent,
                        unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                        focusedLabelColor = c.accent,
                        unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        cursorColor = c.accent
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val updated = group!!.copy(description = descInput.trim())
                    GroupManager.saveGroup(context, updated)
                    group = updated
                    showEditDescDialog = false
                }) {
                    Text(s.save, color = c.accent, fontFamily = JetBrainsMono)
                }
            },
            dismissButton = {
                TextButton(onClick = { showEditDescDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    // Диалог удаления группы
    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoDeleteTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Text(
                    s.groupInfoDeleteText(group!!.name),
                    color = c.textPrimary,
                    fontFamily = JetBrainsMono
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    GroupManager.deleteGroup(context, groupId)
                    // Обновляем список чатов
                    MainActivity.chatListVersion.value = System.currentTimeMillis()
                    showDeleteDialog = false
                    onBack()
                }) {
                    Text(s.delete, color = c.error, fontFamily = JetBrainsMono)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }
}