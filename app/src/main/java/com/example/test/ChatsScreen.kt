package com.subrosa.messenger

import android.content.Intent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.absoluteValue
import android.util.Log
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.ui.graphics.graphicsLayer
import com.subrosa.messenger.ui.theme.LocalSubrosaColors

sealed class ChatItem {
    data class Contact(val userId: String, val name: String, val lastMessage: String, val unreadCount: Int = 0, val lastTimestamp: Long = 0L) : ChatItem()
    data class GroupChat(val group: Group, val lastMessage: String, val lastTimestamp: Long = 0L) : ChatItem()
    data class ChannelItem(val channel: Channel, val lastPost: String) : ChatItem()
}

private fun formatChatTimestamp(ts: Long): String {
    if (ts == 0L) return ""
    val cal = java.util.Calendar.getInstance()
    val todayStart = cal.apply {
        set(java.util.Calendar.HOUR_OF_DAY, 0); set(java.util.Calendar.MINUTE, 0)
        set(java.util.Calendar.SECOND, 0); set(java.util.Calendar.MILLISECOND, 0)
    }.timeInMillis
    return when {
        ts >= todayStart -> java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(java.util.Date(ts))
        ts >= todayStart - 86_400_000L -> "Вчера"
        else -> java.text.SimpleDateFormat("dd.MM", java.util.Locale.getDefault()).format(java.util.Date(ts))
    }
}

@Composable
private fun OptionRow(
    label: String,
    labelColor: Color? = null,
    onClick: () -> Unit
) {
    val c = LocalSubrosaColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 14.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            fontSize = 16.sp,
            fontFamily = JetBrainsMono,
            color = labelColor ?: c.textPrimary
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatsScreen(
    onOpenChat: (String) -> Unit,
    onOpenProfile: () -> Unit,
    onOpenGroupChat: (String) -> Unit = {},
    onCreateGroup: () -> Unit = {},
    onOpenChannel: (String) -> Unit = {},
    pendingChannelLink: String? = null,
    onChannelLinkConsumed: () -> Unit = {}
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val scope = rememberCoroutineScope()

    var chatItems            by remember { mutableStateOf(listOf<ChatItem>()) }
    var showGroupOptions     by remember { mutableStateOf(false) }
    var showAddDialog        by remember { mutableStateOf(false) }
    var inviteCode           by remember { mutableStateOf("") }
    var deleteTarget         by remember { mutableStateOf<ChatItem.Contact?>(null) }

    var showChannelSubscribeInput  by remember { mutableStateOf(false) }
    var channelLinkInput           by remember { mutableStateOf("") }
    var pendingSubscribeData       by remember { mutableStateOf<ChannelManager.ChannelLinkData?>(null) }
    var showCreateChannelDialog    by remember { mutableStateOf(false) }
    var newChannelName             by remember { mutableStateOf("") }
    var newChannelDesc             by remember { mutableStateOf("") }
    var newChannelAvatar           by remember { mutableStateOf("📢") }

    val myUserId      = remember { UserStorage.getUserId(context) }
    val myDisplayName = remember { UserStorage.getUserDisplayName(context) }
    val myAvatarBitmap = AvatarStore.avatars[myUserId]
    val myAvatarColor = remember(myDisplayName) {
        listOf(
            Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
            Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
        )[myDisplayName.hashCode().absoluteValue % 6]
    }

    fun loadChats() {
        scope.launch(Dispatchers.IO) {
            val loadedContacts = ChatStorage.getContacts(context)
            val loadedGroups   = GroupManager.loadGroups(context)
            val items = mutableListOf<ChatItem>()

            loadedContacts.forEach { contactId ->
                val name     = ChatStorage.getContactName(context, contactId)
                val messages = ChatStorage.loadMessages(context, UserStorage.getUserId(context), contactId)
                val unread   = messages.count { !it.isOwn && !it.isRead }
                val lastTs   = messages.lastOrNull()?.timestamp ?: 0L
                items.add(ChatItem.Contact(contactId, name, messages.lastOrNull()?.text ?: s.chatsNoMessages, unread, lastTs))
            }
            loadedGroups.forEach { group ->
                val messages = GroupManager.loadGroupMessages(context, UserStorage.getUserId(context), group.id)
                val lastTs   = messages.lastOrNull()?.timestamp ?: 0L
                items.add(ChatItem.GroupChat(group, messages.lastOrNull()?.text ?: s.chatsNoMessages, lastTs))
            }
            // Channels feature disabled — see plan history to re-enable.
            // ChannelManager.getChannels(context).forEach { channel ->
            //     val lastPost = ChannelManager.loadPosts(context, channel.id).lastOrNull()?.text ?: s.chatsNoPosts
            //     items.add(ChatItem.ChannelItem(channel, lastPost))
            // }

            items.sortByDescending { item ->
                when (item) {
                    is ChatItem.Contact -> item.lastTimestamp
                    is ChatItem.GroupChat -> item.lastTimestamp
                    is ChatItem.ChannelItem -> 0L
                }
            }

            withContext(Dispatchers.Main) { chatItems = items }
        }
    }

    val chatListVersion by MainActivity.chatListVersion.collectAsState()
    LaunchedEffect(chatListVersion) { loadChats() }


    LaunchedEffect(pendingChannelLink) {
        val link = pendingChannelLink ?: return@LaunchedEffect
        ChannelManager.parseChannelLink(link)?.let { pendingSubscribeData = it }
        onChannelLinkConsumed()
    }

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = {
                    val isConnected by MessengerService.connectionState.collectAsState()
                    val dotTransition = rememberInfiniteTransition(label = "dot")
                    val dotPulse by dotTransition.animateFloat(
                        initialValue = 1f,
                        targetValue = if (isConnected) 1.55f else 1f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(900, easing = FastOutSlowInEasing),
                            repeatMode = RepeatMode.Reverse
                        ),
                        label = "dot_pulse"
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "SUBROSA",
                            color = Color.White,
                            fontFamily = JetBrainsMono,
                            fontWeight = FontWeight.Bold,
                            fontSize = 22.sp
                        )
                        Spacer(Modifier.width(8.dp))
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .graphicsLayer { scaleX = dotPulse; scaleY = dotPulse }
                                .clip(CircleShape)
                                .background(if (isConnected) Color(0xFF4CAF50) else Color(0xFF9E9E9E))
                        )
                    }
                },
                actions = {

                    Box(
                        modifier = Modifier
                            .padding(end = 6.dp)
                            .size(34.dp)
                            .clip(CircleShape)
                            .background(myAvatarColor)
                            .clickable { onOpenProfile() },
                        contentAlignment = Alignment.Center
                    ) {
                        if (myAvatarBitmap != null) {
                            Image(
                                bitmap = myAvatarBitmap.asImageBitmap(),
                                contentDescription = myDisplayName,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.fillMaxSize().clip(CircleShape)
                            )
                        } else {
                            Text(
                                text = myDisplayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White,
                                fontFamily = JetBrainsMono
                            )
                        }
                    }

                    IconButton(onClick = { showGroupOptions = true }) {
                        Icon(
                            Icons.Default.Add,
                            contentDescription = s.chatsCreateTitle,
                            tint = Color.White
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            if (chatItems.isEmpty()) {

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(40.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = s.chatsEmpty,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White.copy(alpha = 0.8f),
                        fontFamily = JetBrainsMono
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = s.chatsEmptyHint,
                        fontSize = 14.sp,
                        color = Color.White.copy(alpha = 0.45f),
                        fontFamily = JetBrainsMono
                    )
                }
            } else {

                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(top = 8.dp, bottom = 80.dp)
                ) {
                    items(
                        chatItems,
                        key = { item ->
                            when (item) {
                                is ChatItem.Contact     -> "c_${item.userId}"
                                is ChatItem.GroupChat   -> "g_${item.group.id}"
                                is ChatItem.ChannelItem -> "ch_${item.channel.id}"
                            }
                        }
                    ) { item ->
                        Column(
                            modifier = Modifier.animateItem(
                                fadeInSpec  = tween(250),
                                fadeOutSpec = tween(180)
                            )
                        ) {
                            when (item) {
                                is ChatItem.Contact -> ContactCard(
                                    userId = item.userId,
                                    name = item.name,
                                    lastMessage = item.lastMessage,
                                    unreadCount = item.unreadCount,
                                    lastTimestamp = item.lastTimestamp,
                                    onClick = { onOpenChat(item.userId) },
                                    onLongClick = { deleteTarget = item }
                                )
                                is ChatItem.GroupChat -> GroupChatCard(
                                    group = item.group,
                                    lastMessage = item.lastMessage,
                                    lastTimestamp = item.lastTimestamp,
                                    onClick = { onOpenGroupChat(item.group.id) }
                                )
                                is ChatItem.ChannelItem -> ChannelCard(
                                    channel = item.channel,
                                    lastPost = item.lastPost,
                                    onClick = { onOpenChannel(item.channel.id) }
                                )
                            }

                            HorizontalDivider(
                                modifier = Modifier.padding(start = 82.dp),
                                color = c.textPrimary.copy(alpha = 0.07f),
                                thickness = 0.5.dp
                            )
                        }
                    }
                }
            }
        }
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            containerColor = c.dialog,
            title = { Text(s.chatsDeleteTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Text(
                    s.chatsDeleteText(target.name),
                    color = c.textPrimary,
                    fontFamily = JetBrainsMono,
                    fontSize = 14.sp
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch(Dispatchers.IO) {
                        val userId = UserStorage.getUserId(context)
                        val msgs = ChatStorage.loadMessages(context, userId, target.userId)
                        val mediaPaths = msgs.flatMap { listOfNotNull(it.imagePath, it.voicePath, it.filePath) }
                        ChatStorage.deleteChat(context, userId, target.userId)
                        SessionKeyManager.deleteSession(target.userId)
                        // Clears MessengerService's own in-memory key cache +
                        // mailbox tag too — ChatStorage.deleteChat() only
                        // owns on-disk state, and this screen has no bound
                        // service reference to call forgetContact() directly.
                        // Found live: without this, routine background
                        // traffic from a peer unaware they were deleted
                        // (health-check pings, token refills) still verified
                        // against the surviving key and silently resurrected
                        // the contact via ChatStorage.addContact() in the
                        // message handlers.
                        context.startService(Intent(context, MessengerService::class.java).apply {
                            putExtra("forget_contact", target.userId)
                        })
                        context.startService(Intent(context, MessengerService::class.java).apply {
                            putExtra("send_session_reset_to", target.userId)
                        })
                        mediaPaths.forEach { path -> java.io.File(path).takeIf { it.exists() }?.delete() }
                        withContext(Dispatchers.Main) {
                            chatItems = chatItems.filter { it !is ChatItem.Contact || it.userId != target.userId }
                            deleteTarget = null
                        }
                    }
                }) { Text(s.delete, color = Color(0xFFEF5350), fontFamily = JetBrainsMono) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = { showAddDialog = false; inviteCode = "" },
            containerColor = c.dialog,
            title = { Text(s.chatsAddContact, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                OutlinedTextField(
                    value = inviteCode,
                    onValueChange = { inviteCode = it },
                    label = { Text(s.chatsInviteCode, fontFamily = JetBrainsMono) },
                    singleLine = false,
                    maxLines = 3,
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
                    if (inviteCode.isNotBlank()) {
                        try {
                            val inviteData = InviteCodeManager.parseInviteCode(inviteCode.trim())
                            if (inviteData != null && InviteCodeManager.verifyInviteCode(inviteData)) {
                                val fingerprint = inviteData.fingerprint
                                val fixedKey = inviteData.publicKey.replace('-', '+').replace('_', '/')
                                val decodedName = inviteData.displayName.ifBlank { fingerprint }
                                ChatStorage.addContact(context, fingerprint)
                                ChatStorage.saveContactPublicKey(context, fingerprint, fixedKey)
                                ChatStorage.saveContactName(context, fingerprint, decodedName)

                                // parseInviteCode()/verifyInviteCode() only ever accept
                                // FORMAT_VERSION codes now — the mailbox tag is always present,
                                // there is no more direct/non-anonymous fallback path here.
                                AnonTokenManager.setContactMailboxTag(context, fingerprint, inviteData.mailboxTag!!)
                                Log.d("ChatsScreen", "DEBUG-BOOTSTRAP redeem: fingerprint=$fingerprint parsedTag=${inviteData.mailboxTag} savedTag=${AnonTokenManager.getContactMailboxTag(context, fingerprint)}")
                                // Kick off the anonymous token exchange immediately, invisibly —
                                // don't wait for the user to type a first message to trigger it.
                                context.startService(
                                    Intent(context, MessengerService::class.java).apply {
                                        putExtra("bootstrap_channel_for", fingerprint)
                                    }
                                )
                                showAddDialog = false; inviteCode = ""
                                loadChats()
                                android.widget.Toast.makeText(
                                    context, s.chatsContactAdded(decodedName), android.widget.Toast.LENGTH_SHORT
                                ).show()
                            } else {
                                android.widget.Toast.makeText(
                                    context, "Неверный или истёкший инвайт-код", android.widget.Toast.LENGTH_SHORT
                                ).show()
                            }
                        } catch (e: Exception) {
                            Log.e("ChatsScreen", "Ошибка парсинга: ${e.message}")
                            android.widget.Toast.makeText(
                                context, s.error(e.message ?: ""), android.widget.Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }) { Text(s.add, color = c.accent) }
            },
            dismissButton = {
                TextButton(onClick = { showAddDialog = false; inviteCode = "" }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }


    if (showGroupOptions) {
        AlertDialog(
            onDismissRequest = { showGroupOptions = false },
            containerColor = c.dialog,
            title = { Text(s.chatsCreateTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    OptionRow(s.chatsCreateContact) {
                        showGroupOptions = false; showAddDialog = true
                    }
                    HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                    OptionRow(s.chatsCreateGroup) {
                        showGroupOptions = false; onCreateGroup()
                    }
                    // Channels feature disabled — see plan history to re-enable.
                    // HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                    // OptionRow(s.chatsSubscribeChannel) {
                    //     showGroupOptions = false; showChannelSubscribeInput = true
                    // }
                    // HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                    // OptionRow(s.chatsCreateChannel, labelColor = c.accent) {
                    //     showGroupOptions = false; showCreateChannelDialog = true
                    // }
                }
            },
            confirmButton = {}
        )
    }

    if (showChannelSubscribeInput) {
        AlertDialog(
            onDismissRequest = { showChannelSubscribeInput = false; channelLinkInput = "" },
            containerColor = c.dialog,
            title = { Text(s.chatsChannelSubscribeTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                OutlinedTextField(
                    value = channelLinkInput,
                    onValueChange = { channelLinkInput = it },
                    label = { Text(s.chatsChannelLinkLabel, fontFamily = JetBrainsMono, fontSize = 12.sp) },
                    singleLine = false,
                    maxLines = 3,
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
                    val parsed = ChannelManager.parseChannelLink(channelLinkInput.trim())
                    if (parsed != null) {
                        showChannelSubscribeInput = false; channelLinkInput = ""
                        pendingSubscribeData = parsed
                    } else {
                        android.widget.Toast.makeText(context, s.chatsChannelBadLink, android.widget.Toast.LENGTH_SHORT).show()
                    }
                }) { Text(s.next, color = c.accent, fontFamily = JetBrainsMono) }
            },
            dismissButton = {
                TextButton(onClick = { showChannelSubscribeInput = false; channelLinkInput = "" }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    pendingSubscribeData?.let { linkData ->
        ChannelSubscribeDialog(
            linkData = linkData,
            onSubscribe = {
                scope.launch(Dispatchers.IO) {
                    if (ChannelManager.getChannel(context, linkData.channelId) == null) {
                        context.startService(
                            Intent(context, MessengerService::class.java).apply {
                                putExtra("channel_subscribe", linkData.channelId)
                                putExtra("channel_subscribe_name", linkData.channelName)
                                putExtra("channel_subscribe_avatar", linkData.channelAvatar)
                            }
                        )
                        ChannelManager.saveChannel(
                            context, Channel(
                                id = linkData.channelId, name = linkData.channelName,
                                avatar = linkData.channelAvatar, adminId = "", isAdmin = false
                            )
                        )
                    }
                    withContext(Dispatchers.Main) {
                        pendingSubscribeData = null; loadChats(); onOpenChannel(linkData.channelId)
                    }
                }
            },
            onDismiss = { pendingSubscribeData = null }
        )
    }

    if (showCreateChannelDialog) {
        AlertDialog(
            onDismissRequest = {
                showCreateChannelDialog = false
                newChannelName = ""; newChannelDesc = ""; newChannelAvatar = "📢"
            },
            containerColor = c.dialog,
            title = { Text(s.chatsChannelCreateTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(
                        newChannelName to s.chatsChannelNameLabel,
                        newChannelDesc to s.chatsChannelDescLabel
                    ).forEachIndexed { idx, (value, label) ->
                        OutlinedTextField(
                            value = value,
                            onValueChange = {
                                when (idx) {
                                    0 -> newChannelName = it
                                    1 -> newChannelDesc = it
                                }
                            },
                            label = { Text(label, fontFamily = JetBrainsMono, fontSize = 12.sp) },
                            singleLine = true,
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
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (newChannelName.isBlank()) {
                        android.widget.Toast.makeText(context, s.chatsChannelFillFields, android.widget.Toast.LENGTH_SHORT).show()
                        return@TextButton
                    }
                    context.startService(
                        Intent(context, MessengerService::class.java).apply {
                            putExtra("channel_create_name",   newChannelName.trim())
                            putExtra("channel_create_desc",   newChannelDesc.trim())
                            putExtra("channel_create_avatar", newChannelAvatar)
                        }
                    )
                    showCreateChannelDialog = false
                    newChannelName = ""; newChannelDesc = ""; newChannelAvatar = "📢"
                }) { Text(s.create, color = c.accent, fontFamily = JetBrainsMono) }
            },
            dismissButton = {
                TextButton(onClick = {
                    showCreateChannelDialog = false
                    newChannelName = ""; newChannelDesc = ""; newChannelAvatar = "📢"
                }) { Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono) }
            }
        )
    }
}

private val avatarPalette = listOf(
    Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
    Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
)

@Composable
private fun AvatarCircle(
    size: Int = 52,
    color: Color,
    content: @Composable BoxScope.() -> Unit
) {
    Box(
        modifier = Modifier
            .size(size.dp)
            .clip(CircleShape)
            .background(color),
        contentAlignment = Alignment.Center,
        content = content
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ContactCard(
    userId: String,
    name: String,
    lastMessage: String,
    unreadCount: Int = 0,
    lastTimestamp: Long = 0L,
    onClick: () -> Unit,
    onLongClick: (() -> Unit)? = null
) {
    val c = LocalSubrosaColors.current
    val avatarBitmap = AvatarStore.avatars[userId]
    val avatarColor  = remember(name) { avatarPalette[name.hashCode().absoluteValue % avatarPalette.size] }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (avatarBitmap != null) {
            Image(
                bitmap = avatarBitmap.asImageBitmap(),
                contentDescription = name,
                contentScale = ContentScale.Crop,
                modifier = Modifier.size(52.dp).clip(CircleShape)
            )
        } else {
            AvatarCircle(color = avatarColor) {
                Text(
                    text = name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color.White,
                    fontFamily = JetBrainsMono
                )
            }
        }

        Spacer(modifier = Modifier.width(14.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = name,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color.White,
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = lastMessage,
                fontSize = 14.sp,
                color = c.textPrimary.copy(alpha = 0.55f),
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        Spacer(modifier = Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            val tsText = formatChatTimestamp(lastTimestamp)
            if (tsText.isNotEmpty()) {
                Text(
                    text = tsText,
                    fontSize = 12.sp,
                    color = if (unreadCount > 0) c.primaryBlue else c.textPrimary.copy(alpha = 0.4f),
                    fontFamily = JetBrainsMono
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            if (unreadCount > 0) {
                Surface(shape = CircleShape, color = c.primaryBlue) {
                    Text(
                        text = if (unreadCount > 99) "99+" else "$unreadCount",
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        color = Color.White,
                        fontFamily = JetBrainsMono,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }
    }
}

@Composable
fun ChannelCard(
    channel: Channel,
    lastPost: String,
    onClick: () -> Unit
) {
    val c = LocalSubrosaColors.current
    val s = LocalStrings.current

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AvatarCircle(color = c.primaryBlue.copy(alpha = 0.7f)) {
            Text(text = channel.avatar, fontSize = 24.sp)
        }

        Spacer(modifier = Modifier.width(14.dp))

        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = channel.name,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color.White,
                    fontFamily = JetBrainsMono,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = c.accent.copy(alpha = 0.15f)
                ) {
                    Text(
                        text = s.chatsChannelBadge,
                        modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                        fontSize = 10.sp,
                        color = c.accent,
                        fontFamily = JetBrainsMono
                    )
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = lastPost,
                fontSize = 14.sp,
                color = c.textPrimary.copy(alpha = 0.55f),
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        if (channel.isAdmin) {
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                "✏️",
                fontSize = 14.sp,
                modifier = Modifier
                    .clip(CircleShape)
                    .background(c.accent.copy(alpha = 0.12f))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            )
        }
    }
}

@Composable
fun GroupChatCard(
    group: Group,
    lastMessage: String,
    lastTimestamp: Long = 0L,
    onClick: () -> Unit
) {
    val c = LocalSubrosaColors.current

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AvatarCircle(color = c.primaryBlue) {
            Text(text = group.avatar, fontSize = 24.sp)
        }

        Spacer(modifier = Modifier.width(14.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = group.name,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color.White,
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = lastMessage,
                fontSize = 14.sp,
                color = c.textPrimary.copy(alpha = 0.55f),
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        Spacer(modifier = Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            val tsText = formatChatTimestamp(lastTimestamp)
            if (tsText.isNotEmpty()) {
                Text(
                    text = tsText,
                    fontSize = 12.sp,
                    color = c.textPrimary.copy(alpha = 0.4f),
                    fontFamily = JetBrainsMono
                )
            }
            Spacer(modifier = Modifier.height(4.dp))

            Surface(shape = CircleShape, color = c.accent.copy(alpha = 0.15f)) {
                Text(
                    text = "${group.members.size}",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                    fontSize = 11.sp,
                    color = c.accent,
                    fontFamily = JetBrainsMono
                )
            }
        }
    }
}
