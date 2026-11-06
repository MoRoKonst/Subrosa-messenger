package com.subrosa.messenger

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
import androidx.compose.ui.res.painterResource
import com.subrosa.messenger.ui.theme.LocalSubrosaColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateGroupScreen(onBack: () -> Unit, onGroupCreated: (String) -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val userId = UserStorage.getUserId(context)

    var groupName by remember { mutableStateOf("") }
    var selectedAvatar by remember { mutableStateOf("👥") }
    var selectedMembers by remember { mutableStateOf(setOf<String>()) }

    val contacts = remember { ChatStorage.getContacts(context) }
    val avatarEmojis = listOf("👥", "🎮", "💼", "🎓", "🏠", "🎨", "⚽", "🎵", "🍕", "✈️", "💡", "🔥")

    var showAvatarPicker by remember { mutableStateOf(false) }
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }

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
                title = { Text(s.createGroupTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), s.back, tint = c.textPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = if (c.isDark) Color(0xFF4A151A) else c.topBar)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        if (c.isDark) listOf(Color(0xFF2B0F14), Color(0xFF180A0C))
                        else listOf(c.gradientStart, c.gradientEnd)
                    )
                )
                .padding(padding)
                .padding(16.dp)
        ) {

            Surface(
                shape = CircleShape,
                color = if (c.isDark) Color(0xFFC77B4F) else c.primaryBlue,
                modifier = Modifier
                    .size(100.dp)
                    .align(Alignment.CenterHorizontally)
                    .clickable { showAvatarPicker = true }
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(selectedAvatar, fontSize = 50.sp)
                }
            }

            Text(
                s.createGroupTapAvatar,
                fontSize = 14.sp,
                color = c.textPrimary.copy(alpha = 0.6f),
                modifier = Modifier.align(Alignment.CenterHorizontally).padding(top = 8.dp),
                fontFamily = JetBrainsMono
            )

            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = groupName,
                onValueChange = { groupName = it },
                label = { Text(s.createGroupNameLabel, fontFamily = JetBrainsMono) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = if (c.isDark) Color(0xFFD9A566) else c.accent,
                    unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                    focusedLabelColor = if (c.isDark) Color(0xFFD9A566) else c.accent,
                    unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                    focusedTextColor = c.textPrimary,
                    unfocusedTextColor = c.textPrimary,
                    cursorColor = if (c.isDark) Color(0xFFD9A566) else c.accent
                )
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                s.createGroupMembersTitle(selectedMembers.size),
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = c.textPrimary,
                fontFamily = JetBrainsMono
            )

            Spacer(modifier = Modifier.height(8.dp))

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
                        color = if (isSelected) {
                            if (c.isDark) Color(0xFFC77B4F).copy(alpha = 0.3f) else c.primaryBlue.copy(alpha = 0.3f)
                        } else {
                            if (c.isDark) Color(0xFF3A1216) else c.card
                        }
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            val avatarColor = remember(contactName) {
                                val colors = listOf(
                                    Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
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
                                        fontSize = 20.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.width(12.dp))

                            Text(
                                contactName,
                                fontSize = 18.sp,
                                color = c.textPrimary,
                                modifier = Modifier.weight(1f),
                                fontFamily = JetBrainsMono
                            )

                            if (isSelected) {
                                Icon(painterResource(R.drawable.ic_check), contentDescription = null,
                                    tint = if (c.isDark) Color(0xFFD9A566) else c.accent, modifier = Modifier.size(20.dp))
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

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
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (c.isDark) Color(0xFFC77B4F) else c.primaryBlue,
                    contentColor = if (c.isDark) Color.White else c.textPrimary
                )
            ) {
                Text(
                    s.createGroupButton,
                    fontSize = 18.sp,
                    fontFamily = JetBrainsMono
                )
            }
        }
    }

    if (showAvatarPicker) {
        AlertDialog(
            onDismissRequest = { showAvatarPicker = false },
            title = { Text(s.createGroupAvatarTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
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
                                    fontSize = 42.sp,
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
            containerColor = if (c.isDark) Color(0xFF4A151A) else c.dialog
        )
    }
}