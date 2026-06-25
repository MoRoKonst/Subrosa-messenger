package com.bcon.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import java.util.UUID
import kotlin.math.absoluteValue

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateGroupScreen(onBack: () -> Unit, onGroupCreated: (String) -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val userId = UserStorage.getUserId(context)

    var groupName by remember { mutableStateOf("") }
    var selectedAvatar by remember { mutableStateOf("👥") }
    var selectedMembers by remember { mutableStateOf(setOf<String>()) }

    val contacts = remember { ChatStorage.getContacts(context) }
    val avatarEmojis = listOf("👥", "🎮", "💼", "🎓", "🏠", "🎨", "⚽", "🎵", "🍕", "✈️", "💡", "🔥")

    var showAvatarPicker by remember { mutableStateOf(false) }
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }

    // Подключение к сервису
    val connection = remember {
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                messengerService = (binder as MessengerService.LocalBinder).getService()
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
            android.content.Context.BIND_AUTO_CREATE
        )
    }

    DisposableEffect(Unit) {
        onDispose {
            try {
                context.unbindService(connection)
            } catch (e: Exception) {}
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.createGroupTitle, color = Color.White, fontFamily = JetBrainsMono) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, s.back, tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color(0xFF091a66))
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(Color(0xFF141e4a), Color(0xFF0d1238))))
                .padding(padding)
                .padding(16.dp)
        ) {
            // Аватар группы
            Surface(
                shape = CircleShape,
                color = Color(0xFF2481CC),
                modifier = Modifier
                    .size(100.dp)
                    .align(Alignment.CenterHorizontally)
                    .clickable { showAvatarPicker = true }
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(selectedAvatar, fontSize = 48.sp)
                }
            }

            Text(
                s.createGroupTapAvatar,
                fontSize = 12.sp,
                color = Color(0xFFE0E6FF).copy(alpha = 0.6f),
                modifier = Modifier.align(Alignment.CenterHorizontally).padding(top = 8.dp),
                fontFamily = JetBrainsMono
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Название группы
            OutlinedTextField(
                value = groupName,
                onValueChange = { groupName = it },
                label = { Text(s.createGroupNameLabel, fontFamily = JetBrainsMono) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF00E5FF),
                    unfocusedBorderColor = Color(0xFFE0E6FF).copy(alpha = 0.3f),
                    focusedLabelColor = Color(0xFF00E5FF),
                    unfocusedLabelColor = Color(0xFFE0E6FF).copy(alpha = 0.6f),
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    cursorColor = Color(0xFF00E5FF)
                )
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                s.createGroupMembersTitle(selectedMembers.size),
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White,
                fontFamily = JetBrainsMono
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Список контактов
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(contacts) { contactId ->
                    val contactName = ChatStorage.getContactName(context, contactId)
                    val isSelected = selectedMembers.contains(contactId)

                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                selectedMembers = if (isSelected) {
                                    selectedMembers - contactId
                                } else {
                                    selectedMembers + contactId
                                }
                            },
                        shape = RoundedCornerShape(12.dp),
                        color = if (isSelected) Color(0xFF2481CC).copy(alpha = 0.3f) else Color(0xFF1F2B5E)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            val avatarColor = remember(contactName) {
                                val colors = listOf(
                                    Color(0xFF2481CC), Color(0xFFE74C3C), Color(0xFF27AE60),
                                    Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
                                )
                                colors[contactName.hashCode().absoluteValue % colors.size]
                            }

                            Surface(
                                shape = CircleShape,
                                color = avatarColor,
                                modifier = Modifier.size(40.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(
                                        text = contactName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                        fontSize = 18.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.width(12.dp))

                            Text(
                                contactName,
                                fontSize = 16.sp,
                                color = Color.White,
                                modifier = Modifier.weight(1f),
                                fontFamily = JetBrainsMono
                            )

                            if (isSelected) {
                                Text("✓", fontSize = 24.sp, color = Color(0xFF00E5FF))
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Кнопка создания
            Button(
                onClick = {
                    if (groupName.isNotBlank() && selectedMembers.isNotEmpty()) {
                        val groupId = UUID.randomUUID().toString()
                        val groupKey = GroupManager.generateGroupKey()

                        val allMembers = selectedMembers + userId

                        val group = Group(
                            id = groupId,
                            name = groupName,
                            avatar = selectedAvatar,
                            members = allMembers.toList(),
                            admins = listOf(userId),
                            createdBy = userId,
                            groupKey = groupKey
                        )

                        GroupManager.saveGroup(context, group)

                        // Отправляем приглашения через сервис
                        messengerService?.createGroup(
                            groupId = groupId,
                            groupName = groupName,
                            groupAvatar = selectedAvatar,
                            members = selectedMembers.toList(),
                            groupKey = groupKey
                        )

                        onGroupCreated(groupId)
                    }
                },
                enabled = groupName.isNotBlank() && selectedMembers.isNotEmpty(),
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2481CC))
            ) {
                Text(
                    s.createGroupButton,
                    fontSize = 16.sp,
                    fontFamily = JetBrainsMono
                )
            }
        }
    }

    // Диалог выбора аватара
    if (showAvatarPicker) {
        AlertDialog(
            onDismissRequest = { showAvatarPicker = false },
            title = { Text(s.createGroupAvatarTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    avatarEmojis.chunked(4).forEach { row ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            row.forEach { emoji ->
                                Text(
                                    emoji,
                                    fontSize = 40.sp,
                                    modifier = Modifier
                                        .clickable {
                                            selectedAvatar = emoji
                                            showAvatarPicker = false
                                        }
                                        .padding(8.dp)
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {},
            containerColor = Color(0xFF091a66)
        )
    }
}