package com.subrosa.messenger

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.GetContent
import androidx.compose.foundation.Image
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.absoluteValue
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import androidx.compose.ui.res.painterResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** [onBack] is the ordinary top-bar back arrow (returns to the still-open
 *  group chat). [onGroupGone] is called after a successful leave/delete,
 *  since at that point the group no longer exists locally — routing that
 *  through the same [onBack] MainActivity uses for ordinary back navigation
 *  landed back on GroupChatScreen for a group that was just deleted, which
 *  never finishes loading (group stays permanently null) and showed an
 *  infinite spinner. Found live 2026-09-21. Mirrors Desktop's
 *  GroupInfoScreen, which already had this exact split. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupInfoScreen(groupId: String, onBack: () -> Unit, onGroupGone: () -> Unit = onBack) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val userId = UserStorage.getUserId(context)

    var group by remember { mutableStateOf(GroupManager.getGroup(context, groupId)) }
    var showAddMemberDialog by remember { mutableStateOf(false) }
    var showLeaveDialog by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var showEmojiPickerDialog by remember { mutableStateOf(false) }
    // Group chat previously had emoji-only avatars — showAvatarChoiceDialog
    // offers a choice between the existing emoji grid and a real photo
    // (mirrors ProfileScreen.kt's own avatar flow, reusing AvatarCropScreen).
    // New 2026-09-21.
    var showAvatarChoiceDialog by remember { mutableStateOf(false) }
    var pendingGroupAvatarBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var showEditDescDialog by remember { mutableStateOf(false) }
    var descInput by remember { mutableStateOf(group?.description ?: "") }
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }

    val avatarGalleryLauncher = rememberLauncherForActivityResult(GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        MainScope().launch {
            withContext(Dispatchers.IO) {
                try {
                    val bmp = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                        val src = android.graphics.ImageDecoder.createSource(context.contentResolver, uri)
                        android.graphics.ImageDecoder.decodeBitmap(src) { decoder, _, _ ->
                            decoder.allocator = android.graphics.ImageDecoder.ALLOCATOR_SOFTWARE
                        }
                    } else {
                        @Suppress("DEPRECATION")
                        android.provider.MediaStore.Images.Media.getBitmap(context.contentResolver, uri)
                    }
                    withContext(Dispatchers.Main) { pendingGroupAvatarBitmap = bmp }
                } catch (e: Exception) {
                    android.util.Log.e("GroupInfoScreen", "Group avatar photo load error: ${e.message}")
                }
            }
        }
    }

    fun applyCroppedGroupAvatar(cropped: android.graphics.Bitmap) {
        pendingGroupAvatarBitmap = null
        val g = group ?: return
        val groupKey = g.groupKey ?: return
        MainScope().launch {
            withContext(Dispatchers.IO) {
                val out = java.io.ByteArrayOutputStream()
                cropped.compress(android.graphics.Bitmap.CompressFormat.JPEG, 85, out)
                val avatarBytes = out.toByteArray()
                val b64 = android.util.Base64.encodeToString(avatarBytes, android.util.Base64.NO_WRAP)
                val avatarFile = SecureFileStorage.blobFile(context.filesDir, "group_avatar_$groupId")
                SecureFileStorage.write(context, avatarFile, avatarBytes)
                val updated = g.copy(avatarPath = avatarFile.absolutePath)
                GroupManager.saveGroup(context, updated)
                withContext(Dispatchers.Main) {
                    group = updated
                    messengerService?.sendGroupAvatarUpdate(groupId, g.members, groupKey, b64)
                }
            }
        }
    }

    val isAdmin = remember(group) {
        group?.let { GroupManager.isAdmin(context, groupId, userId) } ?: false
    }
    val isCreator = remember(group) { group?.createdBy == userId }

    val connection = remember {
        object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName, binder: android.os.IBinder) {
                val service = (binder as MessengerService.LocalBinder).getService()
                messengerService = service
                service.onGroupAvatarUpdated = { updatedGroupId ->
                    if (updatedGroupId == groupId) {
                        group = GroupManager.getGroup(context, updatedGroupId)
                    }
                }
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
            messengerService?.onGroupAvatarUpdated = null
            try { context.unbindService(connection) } catch (e: Exception) {}
        }
    }

    if (group == null) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text(s.groupInfoNotFound, color = c.textPrimary)
        }
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.groupInfoTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), s.back, tint = c.textPrimary)
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
                                if (isAdmin) Modifier.clickable { showAvatarChoiceDialog = true }
                                else Modifier
                            )
                    ) {
                        val avatarPath = group!!.avatarPath
                        val avatarBitmap = remember(avatarPath) {
                            avatarPath?.let {
                                try {
                                    val bytes = SecureFileStorage.read(context, java.io.File(it))
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
                                Text(group!!.avatar, fontSize = 50.sp)
                            }
                        }
                    }

                    if (isAdmin) {
                        Text(
                            s.groupInfoChangeAvatar,
                            fontSize = 13.sp,
                            color = c.accent.copy(alpha = 0.7f),
                            fontFamily = JetBrainsMono,
                            modifier = Modifier
                                .clickable { showAvatarChoiceDialog = true }
                                .padding(top = 4.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        group!!.name,
                        fontSize = 26.sp,
                        fontWeight = FontWeight.Bold,
                        color = c.textPrimary,
                        fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP
                    )

                    Text(
                        s.groupInfoMembersCount(group!!.members.size),
                        fontSize = 16.sp,
                        color = c.textPrimary.copy(alpha = 0.6f),
                        fontFamily = JetBrainsMono
                    )
                }
            }

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
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = c.textPrimary.copy(alpha = 0.6f),
                                fontFamily = JetBrainsMono
                            )
                            if (isAdmin) {
                                TextButton(onClick = {
                                    descInput = group!!.description
                                    showEditDescDialog = true
                                }) {
                                    Text("Изменить", fontSize = 14.sp, color = c.accent)
                                }
                            }
                        }
                        val desc = group!!.description
                        if (desc.isBlank()) {
                            Text(
                                if (isAdmin) s.groupInfoAddDescription else s.groupInfoNoDescription,
                                fontSize = 16.sp,
                                color = c.textPrimary.copy(alpha = 0.4f),
                                fontFamily = JetBrainsMono
                            )
                        } else {
                            Text(
                                desc,
                                fontSize = 16.sp,
                                color = c.textPrimary,
                                fontFamily = JetBrainsMono
                            )
                        }
                    }
                }
            }

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
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold,
                                color = c.textPrimary,
                                fontFamily = JetBrainsMono
                            )

                            if (isAdmin) {
                                IconButton(onClick = { showAddMemberDialog = true }) {
                                    Icon(painterResource(R.drawable.ic_plus), contentDescription = null,
                                        tint = c.accent, modifier = Modifier.size(20.dp))
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
                                        Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
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
                                            fontSize = 20.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.width(12.dp))

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        memberName,
                                        fontSize = 18.sp,
                                        color = c.textPrimary,
                                        fontFamily = JetBrainsMono
                                    )

                                    if (isMemberCreator) {
                                        Text(
                                            s.groupInfoCreator,
                                            fontSize = 14.sp,
                                            color = Color(0xFFFFD700),
                                            fontFamily = JetBrainsMono
                                        )
                                    } else if (isMemberAdmin) {
                                        Text(
                                            s.groupInfoAdmin,
                                            fontSize = 14.sp,
                                            color = c.accent,
                                            fontFamily = JetBrainsMono
                                        )
                                    }
                                }

                                if (isAdmin && memberId != userId && !isMemberCreator) {
                                    var showMemberMenu by remember { mutableStateOf(false) }

                                    IconButton(onClick = { showMemberMenu = true }) {
                                        Text("⋮", fontSize = 22.sp, color = c.textPrimary)
                                    }

                                    DropdownMenu(
                                        expanded = showMemberMenu,
                                        onDismissRequest = { showMemberMenu = false }
                                    ) {
                                        if (!isMemberAdmin) {
                                            DropdownMenuItem(
                                                text = { Text(s.groupInfoPromoteAdmin) },
                                                onClick = {
                                                    GroupManager.promoteToAdmin(context, groupId, userId, memberId)
                                                    group = GroupManager.getGroup(context, groupId)
                                                    showMemberMenu = false
                                                }
                                            )
                                        }

                                        DropdownMenuItem(
                                            text = { Text(s.groupInfoRemoveMember, color = Color.Red) },
                                            onClick = {

                                                val preRemovalMembers = group!!.members

                                                GroupManager.removeMember(context, groupId, userId, memberId)

                                                messengerService?.notifyMemberRemoved(
                                                    groupId,
                                                    memberId,
                                                    preRemovalMembers
                                                )

                                                // Reload from storage so the rotation goes out to the
                                                // post-removal membership, not the stale Compose state
                                                // captured before removeMember() persisted — otherwise
                                                // the just-kicked member still receives the new key.
                                                val postRemovalGroup = GroupManager.getGroup(context, groupId)
                                                val newGroupKey = GroupManager.generateGroupKey()
                                                val updatedGroup = postRemovalGroup!!.copy(groupKey = newGroupKey)
                                                GroupManager.saveGroup(context, updatedGroup)

                                                messengerService?.rotateGroupKey(
                                                    groupId,
                                                    newGroupKey,
                                                    updatedGroup.members.filter { it != memberId }
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

            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {

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

                    if (isCreator) {
                        OutlinedButton(
                            onClick = { showDeleteDialog = true },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = c.error
                            ),
                            border = androidx.compose.foundation.BorderStroke(1.dp, c.error)
                        ) {
                            Icon(painterResource(R.drawable.ic_delete), null, tint = c.error)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(s.groupInfoDeleteGroup, fontFamily = JetBrainsMono)
                        }
                    }
                }
            }
        }
    }

    if (showAddMemberDialog) {
        var inviteCode by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = { showAddMemberDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoAddMemberTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    Text(
                        s.groupInfoAddMemberHint,
                        fontSize = 14.sp,
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
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (inviteCode.isNotBlank()) {

                            val parts = inviteCode.trim().split("&")
                            // Was named `userId` here, shadowing the outer
                            // current-user `userId` for the rest of this block --
                            // renamed since GroupManager's mutators now need an
                            // explicit, unambiguous actorId (the outer userId).
                            val newMemberId = parts.firstOrNull()?.trim() ?: ""
                            val publicKey = parts.find { it.startsWith("pk=") }
                                ?.removePrefix("pk=")?.trim()

                            if (newMemberId.isNotEmpty() && publicKey != null) {

                                if (!group!!.members.contains(newMemberId)) {

                                    if (!ChatStorage.getContacts(context).contains(newMemberId)) {
                                        ChatStorage.addContact(context, newMemberId)
                                        ChatStorage.saveContactPublicKey(context, newMemberId, publicKey)
                                    }

                                    val preAddMembers = group!!.members

                                    GroupManager.addMember(context, groupId, userId, newMemberId)

                                    // Reload so the roster sent out (and the one
                                    // used to notify existing members) reflects
                                    // the post-addition membership, not the stale
                                    // Compose state captured before addMember()
                                    // persisted — same reasoning as the removal
                                    // path above.
                                    val postAddGroup = GroupManager.getGroup(context, groupId)!!

                                    // Rotate the group key on add too, for backward
                                    // secrecy (OPEN-7, docs/KNOWN_SECURITY_ISSUES.md) —
                                    // previously only removal rotated, so a new member
                                    // got the CURRENT key and could decrypt any
                                    // historical ciphertext they separately obtained
                                    // from before joining. Saved locally BEFORE
                                    // addGroupMember() below so sendGroupInviteTo()
                                    // (called inside it) picks up the rotated key for
                                    // the new member's own group_create invite;
                                    // rotateGroupKey() pushes the same new key to every
                                    // OTHER existing member via the identical
                                    // per-member-encrypted send the removal path above
                                    // already uses — preAddMembers (captured before
                                    // addMember() mutated the roster) so the brand-new
                                    // member doesn't also get a redundant/premature
                                    // group_key_rotation of their own.
                                    val newGroupKey = GroupManager.generateGroupKey()
                                    val rotatedGroup = postAddGroup.copy(groupKey = newGroupKey)
                                    GroupManager.saveGroup(context, rotatedGroup)

                                    messengerService?.addGroupMember(
                                        groupId = groupId,
                                        groupName = rotatedGroup.name,
                                        groupAvatar = rotatedGroup.avatar,
                                        newMemberId = newMemberId,
                                        newMemberName = ChatStorage.getContactName(context, newMemberId),
                                        groupKey = newGroupKey,
                                        allMembers = rotatedGroup.members,
                                        admins = rotatedGroup.admins
                                    )
                                    messengerService?.rotateGroupKey(
                                        groupId,
                                        newGroupKey,
                                        preAddMembers.filter { it != userId }
                                    )

                                    group = rotatedGroup
                                    showAddMemberDialog = false
                                } else {

                                    android.widget.Toast.makeText(
                                        context,
                                        s.groupInfoAlreadyMember,
                                        android.widget.Toast.LENGTH_SHORT
                                    ).show()
                                }
                            } else {

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

    if (showLeaveDialog) {
        AlertDialog(
            onDismissRequest = { showLeaveDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoLeaveTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Text(
                    s.groupInfoLeaveText(group!!.name),
                    color = c.textPrimary,
                    fontFamily = JetBrainsMono
                )
            },
            confirmButton = {
                TextButton(onClick = {

                    GroupManager.removeMember(context, groupId, userId, userId)

                    messengerService?.notifyMemberRemoved(
                        groupId,
                        userId,
                        group!!.members
                    )

                    MainActivity.chatListVersion.value = System.currentTimeMillis()

                    showLeaveDialog = false
                    onGroupGone()
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

    if (showAvatarChoiceDialog) {
        AlertDialog(
            onDismissRequest = { showAvatarChoiceDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoChangeAvatar, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    TextButton(onClick = {
                        showAvatarChoiceDialog = false
                        avatarGalleryLauncher.launch("image/*")
                    }) { Text("Выбрать фото", color = c.textPrimary, fontFamily = JetBrainsMono) }
                    TextButton(onClick = {
                        showAvatarChoiceDialog = false
                        showEmojiPickerDialog = true
                    }) { Text(s.groupInfoEmojiTitle, color = c.textPrimary, fontFamily = JetBrainsMono) }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showAvatarChoiceDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    pendingGroupAvatarBitmap?.let { bmp ->
        AvatarCropScreen(
            source = bmp,
            onConfirm = { cropped -> applyCroppedGroupAvatar(cropped) },
            onCancel = { pendingGroupAvatarBitmap = null }
        )
    }

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
            title = { Text(s.groupInfoEmojiTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
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
                                    val g = group!!
                                    val updated = g.copy(avatar = emoji)
                                    GroupManager.saveGroup(context, updated)
                                    group = updated
                                    showEmojiPickerDialog = false
                                    // Notify other members — was local-only
                                    // before, see sendGroupAvatarUpdate()'s
                                    // own comment on the "EMOJI:" prefix.
                                    val groupKey = g.groupKey
                                    if (groupKey != null) {
                                        messengerService?.sendGroupAvatarUpdate(groupId, g.members, groupKey, "EMOJI:$emoji")
                                    }
                                }
                        ) {
                            Text(emoji, fontSize = 26.sp)
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

    if (showEditDescDialog) {
        AlertDialog(
            onDismissRequest = { showEditDescDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoDescTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
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
                        focusedTextColor = c.textPrimary,
                        unfocusedTextColor = c.textPrimary,
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

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            containerColor = c.dialog,
            title = { Text(s.groupInfoDeleteTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
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

                    MainActivity.chatListVersion.value = System.currentTimeMillis()
                    showDeleteDialog = false
                    onGroupGone()
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