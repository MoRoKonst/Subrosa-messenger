@file:OptIn(
    androidx.compose.foundation.ExperimentalFoundationApi::class,
    androidx.compose.ui.ExperimentalComposeUiApi::class
)

package com.subrosa.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.loadImageBitmap
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.isSecondaryPressed
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.*

/** Long-press/right-click target for ChatsScreen's shared "chat actions"
 *  dialog (mute / open info / delete) — contacts and groups aren't a common
 *  sealed type on Desktop the way Android's ChatItem is, so this is a small
 *  local union just for that dialog's own state. */
private sealed class ChatActionTarget {
    data class Contact(val id: String) : ChatActionTarget()
    data class GroupTarget(val group: Group) : ChatActionTarget()
}

@Composable
fun ChatsScreen(
    onOpenChat: (String) -> Unit,
    onOpenGroup: (String) -> Unit = {},
    onOpenChannel: (String) -> Unit = {},
    onOpenProfile: () -> Unit = {},
    onOpenGroupInfo: (String) -> Unit = {},
    onOpenContactInfo: (String) -> Unit = {}
) {
    val s         = LocalStrings.current
    val connected = WebSocketClient.connected.collectAsState().value
    val myId      = WebSocketClient.myFingerprint

    val contacts = remember { mutableStateListOf<String>().also {
        it.addAll(ChatStorage.getContacts())
    }}

    val groups = remember { mutableStateListOf<Group>().also {
        it.addAll(GroupManager.loadGroups())
    }}
    var showCreateGroup by remember { mutableStateOf(false) }

    val channels = remember { mutableStateListOf<Channel>().also {
        it.addAll(ChannelManager.getChannels())
    }}
    var showChannelMenu    by remember { mutableStateOf(false) }
    var showSubscribeDialog by remember { mutableStateOf(false) }
    var showCreateChannel   by remember { mutableStateOf(false) }

    // Unread counts — loaded from storage once, then updated reactively
    val unreadCounts = remember {
        mutableStateMapOf<String, Int>().also { map ->
            ChatStorage.getContacts().forEach { fp ->
                val cnt = ChatStorage.loadMessages(myId, fp).count { !it.isOwn && !it.isRead }
                if (cnt > 0) map[fp] = cnt
            }
        }
    }

    // Right-click delete state
    var contextContact by remember { mutableStateOf<String?>(null) }
    // Long-press/right-click "chat actions" dialog (mute / open info / delete)
    var actionsTarget by remember { mutableStateOf<ChatActionTarget?>(null) }
    var muteDialogTarget by remember { mutableStateOf<ChatActionTarget?>(null) }
    // Bumped after a mute change to force the row list to re-read mute state
    // (mute-until is a plain timestamp in storage, not itself observable).
    var muteVersion by remember { mutableStateOf(0) }

    var showAddDialog by remember { mutableStateOf(false) }
    var showMyInvite  by remember { mutableStateOf(false) }
    var showPlusMenu  by remember { mutableStateOf(false) }

    // Shared by every incoming-content callback below — persistence itself
    // now happens unconditionally inside WebSocketClient regardless of which
    // screen is mounted (see its persistAndNotifyIncoming()/writeEncryptedBlob()
    // comments); this is purely the chat-list's own UI-refresh reaction, same
    // as before, just no longer text-message-only. Previously onImageReceived/
    // onFileReceived/onVideoReceived were never registered here at all, so an
    // image/file/video arriving while browsing the list (not a specific
    // contact's chat) didn't even bump the unread badge. Found live, 2026-09-20.
    fun onIncomingFrom(from: String) {
        if (!contacts.contains(from)) {
            ChatStorage.addContact(from)
            contacts.add(from)
        }
        unreadCounts[from] = (unreadCounts[from] ?: 0) + 1
    }

    LaunchedEffect(Unit) {
        WebSocketClient.onMessageReceived = { from, _, _, _ -> onIncomingFrom(from) }
        WebSocketClient.onImageReceived = { from, _, _, _ -> onIncomingFrom(from) }
        WebSocketClient.onFileReceived = { from, _, _, _, _, _ -> onIncomingFrom(from) }
        WebSocketClient.onVideoReceived = { from, _, _, _ -> onIncomingFrom(from) }
        WebSocketClient.onGroupInviteReceived = { group, _ ->
            if (groups.none { it.id == group.id }) groups.add(group)
        }
        WebSocketClient.onGroupMessageReceived = { groupId, _ ->
            val idx = groups.indexOfFirst { it.id == groupId }
            if (idx == -1) {
                GroupManager.getGroup(groupId)?.let { groups.add(it) }
            }
        }
        // Fired when this device was removed from a group remotely — same
        // shape as onChannelDeleted below. Without this the group stayed
        // visible in the list (stale in-memory state) even though
        // GroupManager already deleted its local record.
        WebSocketClient.onGroupDeleted = { groupId ->
            groups.removeIf { it.id == groupId }
        }
        WebSocketClient.onChannelCreated = { channel ->
            if (channels.none { it.id == channel.id }) channels.add(channel)
        }
        WebSocketClient.onChannelPostReceived = { channelId, _ ->
            if (channels.none { it.id == channelId }) {
                ChannelManager.getChannel(channelId)?.let { channels.add(it) }
            }
        }
        WebSocketClient.onChannelDeleted = { channelId ->
            channels.removeIf { it.id == channelId }
        }
    }

    Column(Modifier.fillMaxSize()) {

        // ── Top bar ───────────────────────────────────────────────────────────
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text     = "Subrosa",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color    = SubrosaTheme.accent,
                    modifier = Modifier.weight(1f)
                )
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(
                            color = if (connected) Color(0xFF4CAF50)
                                    else SubrosaTheme.textSecondary.copy(alpha = 0.35f),
                            shape = CircleShape
                        )
                )
                Spacer(Modifier.width(6.dp))
                TextButton(
                    onClick = { showMyInvite = true },
                    contentPadding = PaddingValues(horizontal = 8.dp)
                ) {
                    Text(s.chatsMyId, fontSize = 15.sp, color = SubrosaTheme.textSecondary)
                }
                IconButton(onClick = onOpenProfile) {
                    Icon(AppIcons.get("HUMAN_AVATAR_PLACEHOLDER"), contentDescription = s.chatsProfile,
                        tint = SubrosaTheme.accent)
                }
                // Channels feature disabled — see plan history to re-enable.
                // Box {
                //     IconButton(onClick = { showChannelMenu = true }) {
                //         Text("📢", fontSize = 20.sp)
                //     }
                //     DropdownMenu(
                //         expanded = showChannelMenu,
                //         onDismissRequest = { showChannelMenu = false },
                //         containerColor = SubrosaTheme.card
                //     ) {
                //         DropdownMenuItem(
                //             text = { Text("Подписаться на канал", color = SubrosaTheme.textPrimary) },
                //             onClick = { showChannelMenu = false; showSubscribeDialog = true }
                //         )
                //         DropdownMenuItem(
                //             text = { Text("Создать канал", color = SubrosaTheme.textPrimary) },
                //             onClick = { showChannelMenu = false; showCreateChannel = true }
                //         )
                //     }
                // }
                // Single "+" merges add-contact and create-group into one
                // menu — mirrors Android's ChatsScreen showGroupOptions
                // dialog exactly (was two separate top-bar buttons before).
                Box {
                    IconButton(onClick = { showPlusMenu = true }) {
                        Icon(AppIcons.get("PLUS"), contentDescription = s.chatsAddContact,
                            tint = SubrosaTheme.accent)
                    }
                    DropdownMenu(
                        expanded = showPlusMenu,
                        onDismissRequest = { showPlusMenu = false },
                        containerColor = SubrosaTheme.card
                    ) {
                        DropdownMenuItem(
                            text = { Text(s.chatsAddContact, color = SubrosaTheme.textPrimary) },
                            onClick = { showPlusMenu = false; showAddDialog = true }
                        )
                        DropdownMenuItem(
                            text = { Text(s.chatsCreateGroup, color = SubrosaTheme.textPrimary) },
                            enabled = contacts.isNotEmpty(),
                            onClick = { showPlusMenu = false; showCreateGroup = true }
                        )
                    }
                }
            }
        }

        HorizontalDivider(color = SubrosaTheme.divider, thickness = 0.5.dp)

        // ── Contact / group / channel list ────────────────────────────────────
        if (contacts.isEmpty() && groups.isEmpty() && channels.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(AppIcons.get("HUMAN_AVATAR_PLACEHOLDER"), contentDescription = null,
                        modifier = Modifier.size(48.dp),
                        tint = SubrosaTheme.textSecondary.copy(alpha = 0.3f))
                    Spacer(Modifier.height(8.dp))
                    Text(s.chatsNoContacts, color = SubrosaTheme.textSecondary.copy(0.5f))
                    Spacer(Modifier.height(4.dp))
                    TextButton(onClick = { showAddDialog = true }) { Text(s.chatsAddContact) }
                }
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                // Channels feature disabled — see plan history to re-enable.
                // items(channels, key = { "channel_${it.id}" }) { channel ->
                //     ListItem(
                //         leadingContent = { Text(channel.avatar.ifBlank { "📢" }, fontSize = 24.sp) },
                //         headlineContent = {
                //             Text(channel.name, color = SubrosaTheme.textPrimary, fontWeight = FontWeight.Medium)
                //         },
                //         supportingContent = {
                //             Text(
                //                 if (channel.isAdmin) "Канал · вы админ" else "Канал",
                //                 fontSize = 14.sp, color = SubrosaTheme.textSecondary
                //             )
                //         },
                //         colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                //         modifier = Modifier.combinedClickable(onClick = { onOpenChannel(channel.id) })
                //     )
                //     HorizontalDivider(thickness = 0.5.dp, color = SubrosaTheme.divider)
                // }
                items(groups, key = { "group_${it.id}" }) { group ->
                    // Group photo avatars — previously groups only ever
                    // showed the emoji/placeholder here, even after the
                    // avatar system's rollout to GroupInfoScreen/
                    // GroupChatScreen. New 2026-09-21, mirrors the 1:1
                    // contact row's identical 44dp circular Image/fallback
                    // pattern just below.
                    val groupAvatarPath = group.avatarPath
                    val groupAvatarBmp = remember(groupAvatarPath) {
                        groupAvatarPath?.let {
                            try {
                                val bytes = DesktopStorage.decryptRaw(java.io.File(it).readBytes())
                                loadImageBitmap(bytes.inputStream())
                            } catch (e: Exception) { null }
                        }
                    }
                    ListItem(
                        leadingContent = {
                            if (groupAvatarBmp != null) {
                                Image(
                                    bitmap = groupAvatarBmp,
                                    contentDescription = group.name,
                                    contentScale = ContentScale.Crop,
                                    modifier = Modifier.size(44.dp).clip(CircleShape)
                                )
                            } else if (group.avatar.isBlank()) {
                                Icon(AppIcons.get("HUMAN_AVATAR_PLACEHOLDER"), contentDescription = null,
                                    modifier = Modifier.size(22.dp), tint = SubrosaTheme.textSecondary)
                            } else {
                                Text(group.avatar, fontSize = 24.sp)
                            }
                        },
                        headlineContent = {
                            Text(group.name, color = SubrosaTheme.textPrimary, fontWeight = FontWeight.Medium, fontFamily = NotoSerifJP)
                        },
                        supportingContent = {
                            Text(s.chatsGroupMembers(group.members.size),
                                fontSize = 14.sp, color = SubrosaTheme.textSecondary)
                        },
                        trailingContent = remember(group.id, muteVersion) {
                            if (UserStorage.getGroupMuteUntil(group.id) > System.currentTimeMillis()) {
                                { Icon(AppIcons.get("BELL_SLASH"), contentDescription = null,
                                    modifier = Modifier.size(16.dp), tint = SubrosaTheme.textSecondary) }
                            } else null
                        },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier
                            .combinedClickable(
                                onClick = { onOpenGroup(group.id) },
                                onLongClick = { actionsTarget = ChatActionTarget.GroupTarget(group) }
                            )
                            .pointerInput(group.id) {
                                awaitPointerEventScope {
                                    while (true) {
                                        val event = awaitPointerEvent()
                                        if (event.type == PointerEventType.Press &&
                                            event.buttons.isSecondaryPressed) {
                                            actionsTarget = ChatActionTarget.GroupTarget(group)
                                        }
                                    }
                                }
                            }
                    )
                    HorizontalDivider(thickness = 0.5.dp, color = SubrosaTheme.divider)
                }
                items(contacts, key = { it }) { contact ->
                    val label     = ChatStorage.getContactName(contact)
                    val lastMsg   = ChatStorage.getLastMessage(myId, contact)
                    val unreadCnt = unreadCounts[contact] ?: 0
                    // Direct reactive read (mutableStateMapOf) so a fresh
                    // avatar_data push while this list is open recomposes
                    // this row; the LaunchedEffect only hydrates the
                    // in-memory cache from disk once per contact.
                    LaunchedEffect(contact) { AvatarStore.loadIfMissing(contact) }
                    val avatarBmp = AvatarStore.avatars[contact]

                    ListItem(
                        leadingContent = {
                            if (avatarBmp != null) {
                                Image(
                                    bitmap = avatarBmp,
                                    contentDescription = label,
                                    contentScale = ContentScale.Crop,
                                    modifier = Modifier.size(44.dp).clip(CircleShape)
                                )
                            } else {
                                Box(
                                    modifier = Modifier.size(44.dp).clip(CircleShape)
                                        .background(avatarColor(label)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = label.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                        fontSize = 18.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = Color.White
                                    )
                                }
                            }
                        },
                        headlineContent = {
                            Text(label, color = SubrosaTheme.textPrimary,
                                fontWeight = FontWeight.Medium, fontFamily = NotoSerifJP)
                        },
                        supportingContent = lastMsg?.let { msg ->
                            {
                                Text(
                                    text     = if (msg.isOwn) "Вы: ${msg.text}" else msg.text,
                                    maxLines = 1,
                                    color    = SubrosaTheme.textSecondary,
                                    fontSize = 15.sp
                                )
                            }
                        },
                        trailingContent = {
                            Column(horizontalAlignment = Alignment.End) {
                                val isMuted = remember(contact, muteVersion) {
                                    UserStorage.getContactMuteUntil(contact) > System.currentTimeMillis()
                                }
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    if (isMuted) {
                                        Icon(AppIcons.get("BELL_SLASH"), contentDescription = null,
                                            modifier = Modifier.size(14.dp).padding(end = 4.dp),
                                            tint = SubrosaTheme.textSecondary)
                                    }
                                    lastMsg?.let {
                                        Text(
                                            text     = formatChatTime(it.timestamp),
                                            fontSize = 13.sp,
                                            color    = if (unreadCnt > 0) SubrosaTheme.accent
                                                       else SubrosaTheme.textSecondary
                                        )
                                    }
                                }
                                if (unreadCnt > 0) {
                                    Spacer(Modifier.height(4.dp))
                                    Box(
                                        modifier = Modifier
                                            .size(20.dp)
                                            .background(SubrosaTheme.accent, CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(
                                            text       = if (unreadCnt > 99) "99+" else "$unreadCnt",
                                            fontSize = 12.sp,
                                            color      = Color.White,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                        },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier
                            .combinedClickable(
                                onClick     = {
                                    unreadCounts.remove(contact)
                                    onOpenChat(contact)
                                },
                                onLongClick = { actionsTarget = ChatActionTarget.Contact(contact) }
                            )
                            .pointerInput(contact) {
                                awaitPointerEventScope {
                                    while (true) {
                                        val event = awaitPointerEvent()
                                        if (event.type == PointerEventType.Press &&
                                            event.buttons.isSecondaryPressed) {
                                            actionsTarget = ChatActionTarget.Contact(contact)
                                        }
                                    }
                                }
                            }
                    )
                    HorizontalDivider(thickness = 0.5.dp, color = SubrosaTheme.divider)
                }
            }
        }
    }

    // ── Chat actions dialog (long-press / right-click) ─────────────────────
    actionsTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { actionsTarget = null },
            containerColor = SubrosaTheme.dialog,
            title = { Text(s.chatsActionsTitle, color = SubrosaTheme.textPrimary) },
            text = {
                Column {
                    Text(
                        s.chatsActionMute,
                        color = SubrosaTheme.textPrimary,
                        fontSize = 16.sp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                actionsTarget = null
                                muteDialogTarget = target
                            }
                            .padding(vertical = 10.dp, horizontal = 4.dp)
                    )
                    Text(
                        s.chatsActionInfo,
                        color = SubrosaTheme.textPrimary,
                        fontSize = 16.sp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                actionsTarget = null
                                when (target) {
                                    is ChatActionTarget.Contact -> onOpenContactInfo(target.id)
                                    is ChatActionTarget.GroupTarget -> onOpenGroupInfo(target.group.id)
                                }
                            }
                            .padding(vertical = 10.dp, horizontal = 4.dp)
                    )
                    if (target is ChatActionTarget.Contact) {
                        Text(
                            s.chatsActionDelete,
                            color = SubrosaTheme.error,
                            fontSize = 16.sp,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    actionsTarget = null
                                    contextContact = target.id
                                }
                                .padding(vertical = 10.dp, horizontal = 4.dp)
                        )
                    }
                }
            },
            confirmButton = {}
        )
    }

    muteDialogTarget?.let { target ->
        val currentUntil = when (target) {
            is ChatActionTarget.Contact -> UserStorage.getContactMuteUntil(target.id)
            is ChatActionTarget.GroupTarget -> UserStorage.getGroupMuteUntil(target.group.id)
        }
        MuteDurationDialog(
            currentMuteUntil = currentUntil,
            onDismiss = { muteDialogTarget = null },
            onSelect = { until ->
                when (target) {
                    is ChatActionTarget.Contact -> UserStorage.setContactMuteUntil(target.id, until)
                    is ChatActionTarget.GroupTarget -> UserStorage.setGroupMuteUntil(target.group.id, until)
                }
                muteVersion++
                muteDialogTarget = null
            }
        )
    }

    // ── Delete contact dialog (right-click) ────────────────────────────────
    contextContact?.let { fp ->
        AlertDialog(
            onDismissRequest = { contextContact = null },
            containerColor   = SubrosaTheme.dialog,
            title  = { Text("Удалить контакт?", color = SubrosaTheme.textPrimary) },
            text   = {
                Text(
                    "«${ChatStorage.getContactName(fp)}» будет удалён. " +
                    "История переписки также будет удалена.",
                    color    = SubrosaTheme.textSecondary,
                    fontSize = 16.sp
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    // Mirrors Android's ChatsScreen delete-contact flow: collect
                    // attached media paths BEFORE deleteChat() wipes the message
                    // list, delete those files from disk after, and tell the
                    // peer their session is gone so they don't silently keep
                    // encrypting to a session we just tore down. All three were
                    // missing from Desktop's version — found in the 2026-09-12
                    // full-logic audit (deleted chats leaked their images/files
                    // on disk indefinitely, and the peer never re-handshook).
                    val mediaPaths = ChatStorage.loadMessages(myId, fp)
                        .flatMap { listOfNotNull(it.imagePath, it.filePath) }
                    ChatStorage.removeContact(fp)
                    ChatStorage.deleteChat(myId, fp)
                    WebSocketClient.forgetContact(fp)
                    WebSocketClient.notifyContactOfDeletion(fp)
                    ContactHealthManager.clearContact(fp)
                    mediaPaths.forEach { path -> java.io.File(path).takeIf { it.exists() }?.delete() }
                    contacts.remove(fp)
                    unreadCounts.remove(fp)
                    contextContact = null
                }) { Text("Удалить", color = SubrosaTheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { contextContact = null }) {
                    Text("Отмена", color = SubrosaTheme.textSecondary)
                }
            }
        )
    }

    // ── My invite dialog ───────────────────────────────────────────────────
    if (showMyInvite) {
        MyInviteDialog(onDismiss = { showMyInvite = false })
    }

    // ── Add contact dialog ─────────────────────────────────────────────────
    if (showAddDialog) {
        AddContactDialog(
            onConfirm = { fingerprint, _ ->
                if (fingerprint.isNotBlank() && !contacts.contains(fingerprint)) {
                    contacts.add(fingerprint)
                }
                showAddDialog = false
            },
            onDismiss = { showAddDialog = false }
        )
    }

    // ── Create group dialog ─────────────────────────────────────────────────
    if (showCreateGroup) {
        CreateGroupDialog(
            contacts = contacts,
            onCreate = { name, avatar, selected ->
                WebSocketClient.createGroup(name, avatar, selected)
                GroupManager.getGroup(GroupManager.loadGroups().maxByOrNull { it.createdAt }?.id ?: "")
                    ?.let { groups.add(it) }
                showCreateGroup = false
            },
            onDismiss = { showCreateGroup = false }
        )
    }

    // ── Subscribe to channel dialog ──────────────────────────────────────────
    if (showSubscribeDialog) {
        SubscribeChannelDialog(
            onSubscribe = { data ->
                WebSocketClient.subscribeToChannel(data.channelId)
                val channel = Channel(
                    id = data.channelId, name = data.channelName,
                    avatar = data.channelAvatar, adminId = ""
                )
                ChannelManager.saveChannel(channel)
                if (channels.none { it.id == channel.id }) channels.add(channel)
                showSubscribeDialog = false
            },
            onDismiss = { showSubscribeDialog = false }
        )
    }

    // ── Create channel dialog ────────────────────────────────────────────────
    if (showCreateChannel) {
        CreateChannelDialog(
            onCreate = { name, desc, avatar ->
                WebSocketClient.createChannel(name, desc, avatar)
                showCreateChannel = false
            },
            onDismiss = { showCreateChannel = false }
        )
    }
}

// ── Create group dialog ─────────────────────────────────────────────────────

@Composable
private fun CreateGroupDialog(
    contacts: List<String>,
    onCreate: (name: String, avatar: String, members: List<String>) -> Unit,
    onDismiss: () -> Unit
) {
    var name    by remember { mutableStateOf("") }
    val avatars = listOf("👥", "💬", "🚀", "🔥", "⭐", "🎯", "🛡", "📌")
    var avatar  by remember { mutableStateOf(avatars.first()) }
    val selected = remember { mutableStateListOf<String>() }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title = { Text("Новая группа", color = SubrosaTheme.textPrimary) },
        text  = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название группы") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent,
                    )
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    avatars.forEach { a ->
                        Surface(
                            shape = CircleShape,
                            color = if (a == avatar) SubrosaTheme.accent.copy(alpha = 0.25f) else Color.Transparent,
                            modifier = Modifier.size(34.dp).combinedClickable(onClick = { avatar = a })
                        ) {
                            Box(contentAlignment = Alignment.Center) { Text(a, fontSize = 18.sp) }
                        }
                    }
                }
                Spacer(Modifier.height(12.dp))
                Text("Участники", fontSize = 14.sp, color = SubrosaTheme.textSecondary)
                Spacer(Modifier.height(4.dp))
                Column(Modifier.heightIn(max = 220.dp)) {
                    contacts.forEach { fp ->
                        val checked = selected.contains(fp)
                        Row(
                            modifier = Modifier.fillMaxWidth()
                                .combinedClickable(onClick = {
                                    if (checked) selected.remove(fp) else selected.add(fp)
                                })
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = checked,
                                onCheckedChange = { if (it) selected.add(fp) else selected.remove(fp) },
                                colors = CheckboxDefaults.colors(checkedColor = SubrosaTheme.accent)
                            )
                            Text(ChatStorage.getContactName(fp), color = SubrosaTheme.textPrimary, fontSize = 15.sp)
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                enabled = name.isNotBlank() && selected.isNotEmpty(),
                onClick = { onCreate(name.trim(), avatar, selected.toList()) },
                colors  = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent)
            ) { Text("Создать") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена", color = SubrosaTheme.textSecondary) }
        }
    )
}

// ── "My invite link" dialog ────────────────────────────────────────────────────

@Composable
private fun MyInviteDialog(onDismiss: () -> Unit) {
    val s          = LocalStrings.current
    val clipboard = LocalClipboardManager.current
    var link      by remember { mutableStateOf(InviteCodeManager.generateInviteLink()) }
    var qrBitmap  by remember { mutableStateOf(generateQRCode(link, 260)) }
    var copied    by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title = { Text(s.chatsMyInviteTitle, color = SubrosaTheme.textPrimary) },
        text  = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    "Отсканируй QR-код или скопируй ссылку и отправь другому пользователю Subrosa. " +
                    "Ссылка действительна 7 дней.",
                    fontSize = 14.sp,
                    color    = SubrosaTheme.textSecondary
                )
                Spacer(Modifier.height(12.dp))
                qrBitmap?.let { bmp ->
                    Image(
                        bitmap = bmp,
                        contentDescription = "QR-код инвайта",
                        modifier = Modifier.size(200.dp)
                    )
                    Spacer(Modifier.height(12.dp))
                }
                Surface(
                    shape          = MaterialTheme.shapes.small,
                    color          = SubrosaTheme.card,
                    tonalElevation = 2.dp,
                    modifier       = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text     = link,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(10.dp),
                        color    = SubrosaTheme.textSecondary
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                // Explicit rotation on copy — mirrors Android's
                // ProfileScreen.kt regenerateInviteCode() (desktop/Android
                // symmetry audit, 2026-09-03): closes the exposure window
                // on whatever code was shown before, the moment the user
                // actually hands a fresh one out.
                link = InviteCodeManager.regenerateInviteLink()
                qrBitmap = generateQRCode(link, 260)
                clipboard.setText(AnnotatedString(link))
                copied = true
            }) {
                Text(if (copied) s.copied else s.copy)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(s.close, color = SubrosaTheme.textSecondary)
            }
        }
    )
}

// ── "Add contact" dialog — accepts Subrosa://invite?... link ───────────────────

@Composable
private fun AddContactDialog(
    onConfirm: (fingerprint: String, displayName: String) -> Unit,
    onDismiss: () -> Unit
) {
    val s          = LocalStrings.current
    val clipboard = LocalClipboardManager.current
    var link      by remember { mutableStateOf("") }
    var error     by remember { mutableStateOf("") }
    var preview   by remember { mutableStateOf<InviteData?>(null) }

    LaunchedEffect(link) {
        error   = ""
        preview = null
        val raw = link.trim()
        if (raw.isEmpty()) return@LaunchedEffect
        val data = InviteCodeManager.parseInviteCode(raw)
        if (data == null) {
            error = s.chatsInvalidLinkFormat
            return@LaunchedEffect
        }
        if (!InviteCodeManager.verifyInviteCode(data)) {
            error = s.chatsInvalidOrExpiredLink
            return@LaunchedEffect
        }
        preview = data
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title = { Text(s.chatsAddContactTitle, color = SubrosaTheme.textPrimary) },
        text  = {
            Column {
                Text(
                    s.chatsAddContactHint,
                    fontSize = 14.sp,
                    color    = SubrosaTheme.textSecondary
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value         = link,
                    onValueChange = { link = it },
                    label         = { Text(s.chatsInviteLinkLabel) },
                    minLines      = 2,
                    maxLines      = 4,
                    modifier      = Modifier.fillMaxWidth(),
                    colors        = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent,
                    ),
                    trailingIcon  = {
                        TextButton(
                            onClick = { link = clipboard.getText()?.text ?: link },
                            contentPadding = PaddingValues(horizontal = 4.dp)
                        ) {
                            Text(s.paste, fontSize = 13.sp, color = SubrosaTheme.accent)
                        }
                    }
                )
                Spacer(Modifier.height(4.dp))
                TextButton(
                    onClick = {
                        val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Загрузить QR-код", java.awt.FileDialog.LOAD)
                        dialog.isVisible = true
                        val fileName = dialog.file
                        val dir = dialog.directory
                        if (fileName != null && dir != null) {
                            val decoded = decodeQrFromFile(java.io.File(dir, fileName))
                            if (decoded != null) {
                                link = decoded
                            } else {
                                error = s.chatsQrDecodeFailed
                            }
                        }
                    },
                    contentPadding = PaddingValues(horizontal = 4.dp)
                ) {
                    Text(s.chatsLoadQrFromFile, fontSize = 14.sp, color = SubrosaTheme.accent)
                }
                if (error.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text(error, color = SubrosaTheme.error, fontSize = 14.sp)
                }
                preview?.let { data ->
                    Spacer(Modifier.height(10.dp))
                    Surface(
                        shape          = MaterialTheme.shapes.small,
                        color          = SubrosaTheme.card,
                        tonalElevation = 2.dp,
                        modifier       = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(10.dp)) {
                            Text("Имя: ${data.displayName}", fontSize = 15.sp,
                                color = SubrosaTheme.textPrimary)
                            Text("ID:  ${data.fingerprint}", fontSize = 13.sp,
                                color = SubrosaTheme.textSecondary)
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val addedName = InviteCodeManager.acceptInvite(link.trim()) ?: return@Button
                    val fp = InviteCodeManager.parseInviteCode(link.trim())?.fingerprint
                        ?: return@Button
                    onConfirm(fp, addedName)
                },
                enabled = preview != null
            ) { Text(s.chatsAddContact) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(s.cancel, color = SubrosaTheme.textSecondary)
            }
        }
    )
}

// ── Time formatting ────────────────────────────────────────────────────────────

private fun formatChatTime(ts: Long): String {
    val now    = Calendar.getInstance()
    val msgCal = Calendar.getInstance().also { it.timeInMillis = ts }
    val sameYear = now.get(Calendar.YEAR) == msgCal.get(Calendar.YEAR)
    return when {
        sameYear &&
        now.get(Calendar.DAY_OF_YEAR) == msgCal.get(Calendar.DAY_OF_YEAR) ->
            SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ts))

        sameYear &&
        now.get(Calendar.DAY_OF_YEAR) - msgCal.get(Calendar.DAY_OF_YEAR) == 1 ->
            "Вчера"

        else ->
            SimpleDateFormat("dd.MM", Locale.getDefault()).format(Date(ts))
    }
}

// ── Subscribe to channel dialog ────────────────────────────────────────────────

@Composable
private fun SubscribeChannelDialog(
    onSubscribe: (ChannelManager.ChannelLinkData) -> Unit,
    onDismiss: () -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var link  by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var preview by remember { mutableStateOf<ChannelManager.ChannelLinkData?>(null) }

    LaunchedEffect(link) {
        error = ""
        preview = null
        val raw = link.trim()
        if (raw.isEmpty()) return@LaunchedEffect
        val data = ChannelManager.parseChannelLink(raw)
        if (data == null) {
            error = "Неверный формат ссылки"
            return@LaunchedEffect
        }
        preview = data
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SubrosaTheme.dialog,
        title = { Text("Подписаться на канал", color = SubrosaTheme.textPrimary) },
        text = {
            Column {
                Text(
                    "Вставь ссылку-приглашение канала (Subrosa://channel?…).",
                    fontSize = 14.sp, color = SubrosaTheme.textSecondary
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = link,
                    onValueChange = { link = it },
                    label = { Text("Ссылка на канал") },
                    minLines = 2, maxLines = 4,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent,
                    ),
                    trailingIcon = {
                        TextButton(
                            onClick = { link = clipboard.getText()?.text ?: link },
                            contentPadding = PaddingValues(horizontal = 4.dp)
                        ) { Text("Вставить", fontSize = 13.sp, color = SubrosaTheme.accent) }
                    }
                )
                if (error.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text(error, color = SubrosaTheme.error, fontSize = 14.sp)
                }
                preview?.let { data ->
                    Spacer(Modifier.height(10.dp))
                    Surface(
                        shape = MaterialTheme.shapes.small, color = SubrosaTheme.card,
                        tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(data.channelAvatar, fontSize = 22.sp)
                            Spacer(Modifier.width(8.dp))
                            Text(data.channelName, fontSize = 15.sp, color = SubrosaTheme.textPrimary)
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { preview?.let(onSubscribe) },
                enabled = preview != null
            ) { Text("Подписаться") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена", color = SubrosaTheme.textSecondary) }
        }
    )
}

// ── Create channel dialog ───────────────────────────────────────────────────

@Composable
private fun CreateChannelDialog(
    onCreate: (name: String, description: String, avatar: String) -> Unit,
    onDismiss: () -> Unit
) {
    var name        by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    val avatars = listOf("📢", "📰", "📌", "🔔", "🌐", "📡")
    var avatar   by remember { mutableStateOf(avatars.first()) }
    var error by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        WebSocketClient.onChannelError = { reason -> error = reason }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SubrosaTheme.dialog,
        title = { Text("Создать канал", color = SubrosaTheme.textPrimary) },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название канала") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent,
                    )
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Описание (необязательно)") },
                    minLines = 2, maxLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.fieldBorder,
                        unfocusedBorderColor = SubrosaTheme.divider,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary,
                        cursorColor          = SubrosaTheme.accent,
                    )
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    avatars.forEach { a ->
                        Surface(
                            shape = CircleShape,
                            color = if (a == avatar) SubrosaTheme.accent.copy(alpha = 0.25f) else Color.Transparent,
                            modifier = Modifier.size(34.dp).combinedClickable(onClick = { avatar = a })
                        ) {
                            Box(contentAlignment = Alignment.Center) { Text(a, fontSize = 18.sp) }
                        }
                    }
                }
                if (error.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(error, color = SubrosaTheme.error, fontSize = 14.sp)
                }
            }
        },
        confirmButton = {
            Button(
                enabled = name.isNotBlank(),
                onClick = { onCreate(name.trim(), description.trim(), avatar) },
                colors  = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent)
            ) { Text("Создать") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена", color = SubrosaTheme.textSecondary) }
        }
    )
}
