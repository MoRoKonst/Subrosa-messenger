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
import com.subrosa.messenger.ui.components.IconTile
import com.subrosa.messenger.ui.components.IconTileColors
import androidx.compose.ui.res.painterResource

sealed class ChatItem {
    data class Contact(val userId: String, val name: String, val lastMessage: String, val unreadCount: Int = 0, val lastTimestamp: Long = 0L) : ChatItem()
    data class GroupChat(val group: Group, val lastMessage: String, val lastTimestamp: Long = 0L) : ChatItem()
    data class ChannelItem(val channel: Channel, val lastPost: String) : ChatItem()
}

private fun chatItemKey(item: ChatItem): String = when (item) {
    is ChatItem.Contact     -> "c_${item.userId}"
    is ChatItem.GroupChat   -> "g_${item.group.id}"
    is ChatItem.ChannelItem -> "ch_${item.channel.id}"
}

private fun chatItemName(item: ChatItem): String = when (item) {
    is ChatItem.Contact     -> item.name
    is ChatItem.GroupChat   -> item.group.name
    is ChatItem.ChannelItem -> item.channel.name
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
    // Optional leading color-tile icon (see ui/components/IconTile.kt).
    leadingIcon: (@Composable () -> Unit)? = null,
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
        if (leadingIcon != null) {
            leadingIcon()
            Spacer(modifier = Modifier.width(12.dp))
        }
        Text(
            text = label,
            fontSize = 18.sp,
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
    onOpenGroupInfo: (String) -> Unit = {},
    onOpenContactInfo: (String) -> Unit = {},
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
    // Full message text per chat, keyed the same way as the LazyColumn's
    // item key ("c_$id"/"g_$id") — kept only for global search filtering/
    // snippets, not rendered directly. Built alongside chatItems in
    // loadChats() so search doesn't need a second pass over ChatStorage.
    var chatMessageIndex     by remember { mutableStateOf(mapOf<String, List<String>>()) }
    var searchMode           by remember { mutableStateOf(false) }
    var searchQuery          by remember { mutableStateOf("") }
    var showGroupOptions     by remember { mutableStateOf(false) }
    var showAddDialog        by remember { mutableStateOf(false) }
    var inviteCode           by remember { mutableStateOf("") }
    var deleteTarget         by remember { mutableStateOf<ChatItem.Contact?>(null) }
    // Long-press on any row (contact or group) — mute / open info / delete.
    var chatActionsTarget    by remember { mutableStateOf<ChatItem?>(null) }
    var muteDialogTarget     by remember { mutableStateOf<ChatItem?>(null) }
    var mutedIds             by remember { mutableStateOf(setOf<String>()) }

    fun computeMutedIds(items: List<ChatItem>): Set<String> {
        val now = System.currentTimeMillis()
        return items.mapNotNull { item ->
            val until = when (item) {
                is ChatItem.Contact -> UserStorage.getContactMuteUntil(context, item.userId)
                is ChatItem.GroupChat -> UserStorage.getGroupMuteUntil(context, item.group.id)
                is ChatItem.ChannelItem -> 0L
            }
            if (until > now) chatItemKey(item) else null
        }.toSet()
    }

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
            val index = mutableMapOf<String, List<String>>()

            loadedContacts.forEach { contactId ->
                val name     = ChatStorage.getContactName(context, contactId)
                val messages = ChatStorage.loadMessages(context, UserStorage.getUserId(context), contactId)
                val unread   = messages.count { !it.isOwn && !it.isRead }
                val lastTs   = messages.lastOrNull()?.timestamp ?: 0L
                items.add(ChatItem.Contact(contactId, name, messages.lastOrNull()?.text ?: s.chatsNoMessages, unread, lastTs))
                index["c_$contactId"] = messages.map { it.text }
            }
            loadedGroups.forEach { group ->
                val messages = GroupManager.loadGroupMessages(context, UserStorage.getUserId(context), group.id)
                val lastTs   = messages.lastOrNull()?.timestamp ?: 0L
                items.add(ChatItem.GroupChat(group, messages.lastOrNull()?.text ?: s.chatsNoMessages, lastTs))
                index["g_${group.id}"] = messages.map { it.text }
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

            val muted = computeMutedIds(items)
            withContext(Dispatchers.Main) { chatItems = items; chatMessageIndex = index; mutedIds = muted }
        }
    }

    val chatListVersion by MainActivity.chatListVersion.collectAsState()
    LaunchedEffect(chatListVersion) { loadChats() }

    if (searchMode) {
        androidx.activity.compose.BackHandler { searchMode = false; searchQuery = "" }
    }


    LaunchedEffect(pendingChannelLink) {
        val link = pendingChannelLink ?: return@LaunchedEffect
        ChannelManager.parseChannelLink(link)?.let { pendingSubscribeData = it }
        onChannelLinkConsumed()
    }

    // Search across every chat, not just the currently open one: a match on
    // the contact/group name keeps the row's normal preview, a match found
    // only inside message text swaps the preview for that matching snippet
    // so the reason the chat surfaced is visible before opening it.
    fun matchingSnippet(item: ChatItem): String? {
        if (searchQuery.isBlank()) return null
        return chatMessageIndex[chatItemKey(item)]?.firstOrNull { it.contains(searchQuery, ignoreCase = true) }
    }
    val displayedItems = remember(chatItems, chatMessageIndex, searchQuery) {
        if (searchQuery.isBlank()) chatItems
        else chatItems.filter { item ->
            chatItemName(item).contains(searchQuery, ignoreCase = true) ||
                chatMessageIndex[chatItemKey(item)]?.any { it.contains(searchQuery, ignoreCase = true) } == true
        }
    }

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = {
                    if (searchMode) {
                        androidx.compose.foundation.text.BasicTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 18.sp, color = c.textPrimary, fontFamily = JetBrainsMono),
                            cursorBrush = androidx.compose.ui.graphics.SolidColor(c.accent),
                            decorationBox = { inner ->
                                if (searchQuery.isEmpty()) Text(s.chatsSearchPlaceholder, fontSize = 18.sp, color = c.textPrimary.copy(alpha = 0.53f), fontFamily = JetBrainsMono)
                                inner()
                            }
                        )
                    } else {
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
                                color = c.textPrimary,
                                fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP,
                                fontWeight = FontWeight.Bold,
                                fontSize = 24.sp
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
                    }
                },
                actions = {
                    IconButton(onClick = {
                        searchMode = !searchMode
                        if (!searchMode) searchQuery = ""
                    }) {
                        Icon(
                            painter = painterResource(if (searchMode) R.drawable.ic_close else R.drawable.ic_search),
                            contentDescription = null,
                            tint = c.textPrimary,
                            modifier = Modifier.size(22.dp)
                        )
                    }

                    if (!searchMode) {
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
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White,
                                    fontFamily = JetBrainsMono
                                )
                            }
                        }

                        IconButton(onClick = { showGroupOptions = true }) {
                            Icon(
                                painterResource(R.drawable.ic_plus),
                                contentDescription = s.chatsCreateTitle,
                                tint = c.textPrimary
                            )
                        }
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
                        fontSize = 20.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = c.textPrimary.copy(alpha = 0.8f),
                        fontFamily = JetBrainsMono
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = s.chatsEmptyHint,
                        fontSize = 16.sp,
                        color = c.textPrimary.copy(alpha = 0.45f),
                        fontFamily = JetBrainsMono
                    )
                }
            } else if (searchQuery.isNotBlank() && displayedItems.isEmpty()) {

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(40.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = s.chatsSearchNoResults,
                        fontSize = 18.sp,
                        color = c.textPrimary.copy(alpha = 0.5f),
                        fontFamily = JetBrainsMono
                    )
                }
            } else {

                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(top = 8.dp, bottom = 80.dp)
                ) {
                    items(
                        displayedItems,
                        key = { item -> chatItemKey(item) }
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
                                    lastMessage = matchingSnippet(item) ?: item.lastMessage,
                                    unreadCount = item.unreadCount,
                                    lastTimestamp = item.lastTimestamp,
                                    isMuted = chatItemKey(item) in mutedIds,
                                    onClick = { onOpenChat(item.userId) },
                                    onLongClick = { chatActionsTarget = item }
                                )
                                is ChatItem.GroupChat -> GroupChatCard(
                                    group = item.group,
                                    lastMessage = matchingSnippet(item) ?: item.lastMessage,
                                    lastTimestamp = item.lastTimestamp,
                                    isMuted = chatItemKey(item) in mutedIds,
                                    onClick = { onOpenGroupChat(item.group.id) },
                                    onLongClick = { chatActionsTarget = item }
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

    chatActionsTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { chatActionsTarget = null },
            containerColor = c.dialog,
            title = { Text(s.chatsActionsTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    OptionRow(
                        label = s.chatsActionMute,
                        leadingIcon = { IconTile(iconRes = R.drawable.ic_bell_slash, tileColor = IconTileColors.warningAmber) }
                    ) {
                        chatActionsTarget = null
                        muteDialogTarget = target
                    }
                    HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                    OptionRow(
                        label = s.chatsActionInfo,
                        leadingIcon = { IconTile(iconRes = R.drawable.ic_user_circle, tileColor = IconTileColors.connectivityBlue) }
                    ) {
                        chatActionsTarget = null
                        when (target) {
                            is ChatItem.Contact -> onOpenContactInfo(target.userId)
                            is ChatItem.GroupChat -> onOpenGroupInfo(target.group.id)
                            is ChatItem.ChannelItem -> {}
                        }
                    }
                    if (target is ChatItem.Contact) {
                        HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                        OptionRow(
                            label = s.chatsActionDelete,
                            labelColor = Color(0xFFEF5350),
                            leadingIcon = { IconTile(iconRes = R.drawable.ic_trash, tileColor = IconTileColors.mutedBurgundy) }
                        ) {
                            chatActionsTarget = null
                            deleteTarget = target
                        }
                    }
                }
            },
            confirmButton = {}
        )
    }

    muteDialogTarget?.let { target ->
        val currentUntil = when (target) {
            is ChatItem.Contact -> UserStorage.getContactMuteUntil(context, target.userId)
            is ChatItem.GroupChat -> UserStorage.getGroupMuteUntil(context, target.group.id)
            is ChatItem.ChannelItem -> 0L
        }
        MuteDurationDialog(
            currentMuteUntil = currentUntil,
            onDismiss = { muteDialogTarget = null },
            onSelect = { until ->
                when (target) {
                    is ChatItem.Contact -> UserStorage.setContactMuteUntil(context, target.userId, until)
                    is ChatItem.GroupChat -> UserStorage.setGroupMuteUntil(context, target.group.id, until)
                    is ChatItem.ChannelItem -> {}
                }
                mutedIds = computeMutedIds(chatItems)
                muteDialogTarget = null
            }
        )
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            containerColor = c.dialog,
            title = { Text(s.chatsDeleteTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Text(
                    s.chatsDeleteText(target.name),
                    color = c.textPrimary,
                    fontFamily = JetBrainsMono,
                    fontSize = 16.sp
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
            title = { Text(s.chatsAddContact, color = c.textPrimary, fontFamily = JetBrainsMono) },
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
                        focusedTextColor = c.textPrimary,
                        unfocusedTextColor = c.textPrimary,
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
            title = { Text(s.chatsCreateTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    OptionRow(
                        label = s.chatsCreateContact,
                        leadingIcon = {
                            IconTile(
                                iconRes = R.drawable.ic_person_add,
                                tileColor = IconTileColors.mintGreen
                            )
                        }
                    ) {
                        showGroupOptions = false; showAddDialog = true
                    }
                    HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                    OptionRow(
                        label = s.chatsCreateGroup,
                        leadingIcon = {
                            IconTile(
                                iconRes = R.drawable.ic_users_three,
                                tileColor = IconTileColors.mintGreen
                            )
                        }
                    ) {
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
            title = { Text(s.chatsChannelSubscribeTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                OutlinedTextField(
                    value = channelLinkInput,
                    onValueChange = { channelLinkInput = it },
                    label = { Text(s.chatsChannelLinkLabel, fontFamily = JetBrainsMono, fontSize = 14.sp) },
                    singleLine = false,
                    maxLines = 3,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = c.accent,
                        unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                        focusedLabelColor = c.accent,
                        unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                        focusedTextColor = c.textPrimary,
                        unfocusedTextColor = c.textPrimary,
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
            title = { Text(s.chatsChannelCreateTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
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
                            label = { Text(label, fontFamily = JetBrainsMono, fontSize = 14.sp) },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = c.accent,
                                unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                                focusedLabelColor = c.accent,
                                unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                                focusedTextColor = c.textPrimary,
                                unfocusedTextColor = c.textPrimary,
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
    isMuted: Boolean = false,
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
                    fontSize = 22.sp,
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
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
                color = c.textPrimary,
                fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = lastMessage,
                fontSize = 16.sp,
                color = c.textPrimary.copy(alpha = 0.55f),
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        Spacer(modifier = Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (isMuted) {
                    Icon(
                        painterResource(R.drawable.ic_bell_slash),
                        contentDescription = null,
                        tint = c.textPrimary.copy(alpha = 0.4f),
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                }
                val tsText = formatChatTimestamp(lastTimestamp)
                if (tsText.isNotEmpty()) {
                    Text(
                        text = tsText,
                        fontSize = 14.sp,
                        color = if (unreadCount > 0) c.primaryBlue else c.textPrimary.copy(alpha = 0.4f),
                        fontFamily = JetBrainsMono
                    )
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            if (unreadCount > 0) {
                Surface(shape = CircleShape, color = c.primaryBlue) {
                    Text(
                        text = if (unreadCount > 99) "99+" else "$unreadCount",
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 13.sp,
                        color = if (c.isDark) Color.White else c.textPrimary,
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
            Text(text = channel.avatar, fontSize = 26.sp)
        }

        Spacer(modifier = Modifier.width(14.dp))

        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = channel.name,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = c.textPrimary,
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
                        fontSize = 12.sp,
                        color = c.accent,
                        fontFamily = JetBrainsMono
                    )
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = lastPost,
                fontSize = 16.sp,
                color = c.textPrimary.copy(alpha = 0.55f),
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        if (channel.isAdmin) {
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                "Админ",
                fontSize = 13.sp,
                color = c.accent,
                modifier = Modifier
                    .clip(CircleShape)
                    .background(c.accent.copy(alpha = 0.12f))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun GroupChatCard(
    group: Group,
    lastMessage: String,
    lastTimestamp: Long = 0L,
    isMuted: Boolean = false,
    onClick: () -> Unit,
    onLongClick: (() -> Unit)? = null
) {
    val c = LocalSubrosaColors.current
    val context = LocalContext.current
    val avatarBitmap = remember(group.avatarPath) {
        group.avatarPath?.let {
            try {
                val bytes = SecureFileStorage.read(context, java.io.File(it))
                android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            } catch (e: Exception) { null }
        }
    }

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
                contentDescription = group.name,
                contentScale = ContentScale.Crop,
                modifier = Modifier.size(52.dp).clip(CircleShape)
            )
        } else {
            AvatarCircle(color = c.primaryBlue) {
                Text(text = group.avatar, fontSize = 26.sp)
            }
        }

        Spacer(modifier = Modifier.width(14.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = group.name,
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
                color = c.textPrimary,
                fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = lastMessage,
                fontSize = 16.sp,
                color = c.textPrimary.copy(alpha = 0.55f),
                fontFamily = JetBrainsMono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        Spacer(modifier = Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (isMuted) {
                    Icon(
                        painterResource(R.drawable.ic_bell_slash),
                        contentDescription = null,
                        tint = c.textPrimary.copy(alpha = 0.4f),
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                }
                val tsText = formatChatTimestamp(lastTimestamp)
                if (tsText.isNotEmpty()) {
                    Text(
                        text = tsText,
                        fontSize = 14.sp,
                        color = c.textPrimary.copy(alpha = 0.4f),
                        fontFamily = JetBrainsMono
                    )
                }
            }
            Spacer(modifier = Modifier.height(4.dp))

            Surface(shape = CircleShape, color = c.accent.copy(alpha = 0.15f)) {
                Text(
                    text = "${group.members.size}",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                    fontSize = 13.sp,
                    color = c.accent,
                    fontFamily = JetBrainsMono
                )
            }
        }
    }
}
