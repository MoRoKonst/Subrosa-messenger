package com.subrosa.messenger

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.subrosa.messenger.ui.components.IconTile
import com.subrosa.messenger.ui.components.IconTileColors
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.launch

/** Mirrors the disappearing-message / auto-delete duration dialogs already
 *  in ChatScreen.kt (RadioButton-list AlertDialog), applied to per-chat mute
 *  instead. Shared by ChatsScreen.kt's long-press "chat actions" dialog and
 *  ContactInfoScreen's own "Notifications" row. [currentMuteUntil]: 0 = not
 *  muted, Long.MAX_VALUE = muted indefinitely, otherwise an epoch-millis
 *  expiry (see UserStorage.getContactMuteUntil/getGroupMuteUntil). */
@Composable
fun MuteDurationDialog(
    currentMuteUntil: Long,
    onDismiss: () -> Unit,
    onSelect: (Long) -> Unit,
    soundMuted: Boolean = false,
    onToggleSound: ((Boolean) -> Unit)? = null
) {
    val c = LocalSubrosaColors.current
    val s = LocalStrings.current
    val isMuted = currentMuteUntil > System.currentTimeMillis()
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = c.dialog,
        title = { Text(s.muteDialogTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
        text = {
            Column {
                if (onToggleSound != null) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp, horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(s.muteSoundOnly, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 16.sp, modifier = Modifier.weight(1f))
                        Switch(
                            checked = soundMuted,
                            onCheckedChange = onToggleSound,
                            colors = SwitchDefaults.colors(checkedThumbColor = c.accent, checkedTrackColor = c.accent.copy(alpha = 0.35f))
                        )
                    }
                    PDivider()
                }
                listOf(
                    0L to s.muteOff,
                    3_600_000L to s.mute1h,
                    7_200_000L to s.mute2h,
                    18_000_000L to s.mute5h,
                    28_800_000L to s.mute8h,
                    Long.MAX_VALUE to s.muteForever
                ).forEach { (durationMs, label) ->
                    // Only "off" and "forever" have a stable identity to
                    // highlight — a timed mute is just an absolute expiry
                    // timestamp once set, with no record of which preset
                    // produced it, so none of the 1h/2h/5h/8h rows ever show
                    // as selected (current state is shown as text elsewhere,
                    // e.g. ContactInfoScreen's row subtitle).
                    val selected = when (durationMs) {
                        0L -> !isMuted
                        Long.MAX_VALUE -> currentMuteUntil == Long.MAX_VALUE
                        else -> false
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth().clickable {
                            onSelect(
                                when (durationMs) {
                                    0L -> 0L
                                    Long.MAX_VALUE -> Long.MAX_VALUE
                                    else -> System.currentTimeMillis() + durationMs
                                }
                            )
                            onDismiss()
                        }.padding(vertical = 12.dp, horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(selected = selected, onClick = null, colors = RadioButtonDefaults.colors(selectedColor = c.accent))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(label, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 17.sp)
                    }
                }
            }
        },
        confirmButton = {}
    )
}

/** 1:1 counterpart to GroupInfoScreen — reached by tapping the avatar/name
 *  in ChatScreen.kt's header. Consolidates everything that used to live in
 *  ChatScreen's 3-dot overflow menu (verify key, auto-delete, restore
 *  connection) plus per-chat mute and a full-size avatar viewer, none of
 *  which had a home before this screen existed. Uses ProfileScreen's
 *  PRow/PSection/IconTile system rather than GroupInfoScreen's older ad-hoc
 *  Row layout, since that's the system this session's icon rollout
 *  standardized on. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactInfoScreen(
    contactId: String,
    onBack: () -> Unit,
    onContactGone: () -> Unit = onBack,
    onOpenVerify: () -> Unit,
    onOpenChatSearch: () -> Unit = {}
) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val userId = remember { UserStorage.getUserId(context) }
    val name = remember { ChatStorage.getContactName(context, contactId) }
    val avatarBitmap = AvatarStore.avatars[contactId]

    // Bound only to push a live "disappear_timer" update to the peer when
    // changed here — mirrors the exact same binding ChatScreen.kt keeps for
    // itself, scoped down to the one call this screen needs.
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }
    DisposableEffect(Unit) {
        val connection = object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName, binder: android.os.IBinder) {
                messengerService = (binder as MessengerService.LocalBinder).getService()
            }
            override fun onServiceDisconnected(name: android.content.ComponentName) { messengerService = null }
        }
        context.bindService(android.content.Intent(context, MessengerService::class.java), connection, android.content.Context.BIND_AUTO_CREATE)
        onDispose { try { context.unbindService(connection) } catch (_: Exception) {} }
    }

    var showFullscreenAvatar by remember { mutableStateOf(false) }
    var showMuteDialog by remember { mutableStateOf(false) }
    var muteUntil by remember { mutableStateOf(UserStorage.getContactMuteUntil(context, contactId)) }
    var muteSound by remember { mutableStateOf(UserStorage.getContactMuteSound(context, contactId)) }
    var showAutoDeleteDialog by remember { mutableStateOf(false) }
    var autoDeleteSecs by remember { mutableStateOf(ChatStorage.getAutoDelete(context, userId, contactId)) }
    var showDisappearDialog by remember { mutableStateOf(false) }
    var disappearTimerSecs by remember { mutableStateOf(ChatStorage.getDisappearTimer(context, userId, contactId)) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    val isVerified = remember { KeyHistoryManager.getHistory(context, contactId).lastOrNull()?.verified == true }

    val locale = LocalConfiguration.current.locales[0]
    val muteSubtitle = when {
        muteUntil == Long.MAX_VALUE -> s.muteStatusForever
        muteUntil > System.currentTimeMillis() ->
            s.muteStatusUntil(java.text.SimpleDateFormat("HH:mm", locale).format(java.util.Date(muteUntil)))
        else -> s.muteStatusOff
    }
    val autoDeleteSubtitle = when (autoDeleteSecs) {
        0L -> s.chatDisappearOff
        3600L -> s.chatDisappear1h
        86400L -> s.chatDisappear24h
        604800L -> s.chatDisappear7d
        else -> "${autoDeleteSecs / 3600}h"
    }
    val disappearSubtitle = when (disappearTimerSecs) {
        0L -> s.chatDisappearOff
        3600L -> s.chatDisappear1h
        86400L -> s.chatDisappear24h
        604800L -> s.chatDisappear7d
        else -> "${disappearTimerSecs / 3600}h"
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.contactInfoTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), contentDescription = s.back, tint = c.textPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        },
        containerColor = c.gradientStart
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(top = 24.dp, bottom = 8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(
                    modifier = Modifier
                        .size(100.dp)
                        .clip(CircleShape)
                        .clickable(enabled = avatarBitmap != null) { showFullscreenAvatar = true },
                    contentAlignment = Alignment.Center
                ) {
                    if (avatarBitmap != null) {
                        Image(
                            bitmap = avatarBitmap.asImageBitmap(),
                            contentDescription = name,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.fillMaxSize()
                        )
                    } else {
                        Box(modifier = Modifier.fillMaxSize().background(c.primaryBlue), contentAlignment = Alignment.Center) {
                            Text(
                                text = name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                fontSize = 36.sp, color = Color.White, fontFamily = JetBrainsMono
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
                Text(name, fontSize = 22.sp, color = c.textPrimary, fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP)
            }

            PSection(s.profileSectionSecurity, leading = { IconTile(iconRes = R.drawable.ic_shield_check, tileColor = IconTileColors.mutedBurgundy) })
            PRow(
                title = s.chatVerifyAction,
                subtitle = if (isVerified) s.verifyAlreadyVerified else null,
                onClick = onOpenVerify,
                trailing = { PChevron() }
            )
            PDivider()
            PRow(
                title = s.contactInfoNotifications,
                subtitle = muteSubtitle,
                onClick = { showMuteDialog = true },
                trailing = { PChevron() }
            )
            PDivider()
            PRow(
                title = s.contactInfoSearch,
                onClick = onOpenChatSearch,
                trailing = { PChevron() }
            )
            PDivider()
            PRow(
                title = s.chatAutoDeleteMenu,
                subtitle = autoDeleteSubtitle,
                onClick = { showAutoDeleteDialog = true },
                trailing = { PChevron() }
            )
            PDivider()
            PRow(
                title = s.chatDisappearTitle,
                subtitle = disappearSubtitle,
                onClick = { showDisappearDialog = true },
                trailing = { PChevron() }
            )
            PDivider()
            PRow(
                title = s.chatRestoreConnection,
                onClick = {
                    if (ContactHealthManager.canManualRestore(context, contactId)) {
                        ContactHealthManager.recordManualRestore(context, contactId)
                        context.startService(android.content.Intent(context, MessengerService::class.java).apply {
                            putExtra("restore_connection", contactId)
                        })
                        android.widget.Toast.makeText(context, s.chatRestoreConnectionStarted, android.widget.Toast.LENGTH_LONG).show()
                    } else {
                        val minutesLeft = (ContactHealthManager.manualRestoreRemainingMs(context, contactId) / 60_000L + 1).toInt()
                        android.widget.Toast.makeText(context, s.chatRestoreConnectionCooldown(minutesLeft), android.widget.Toast.LENGTH_LONG).show()
                    }
                },
                trailing = { PChevron() }
            )

            PSection(s.chatsActionDelete)
            PRow(
                title = s.chatsActionDelete,
                titleColor = Color(0xFFEF5350),
                onClick = { showDeleteConfirm = true }
            )
        }
    }

    if (showFullscreenAvatar && avatarBitmap != null) {
        Dialog(
            onDismissRequest = { showFullscreenAvatar = false },
            properties = DialogProperties(usePlatformDefaultWidth = false)
        ) {
            Box(
                modifier = Modifier.fillMaxSize().background(Color.Black).clickable { showFullscreenAvatar = false },
                contentAlignment = Alignment.Center
            ) {
                Image(
                    bitmap = avatarBitmap.asImageBitmap(),
                    contentDescription = null,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize()
                )
            }
        }
    }

    if (showMuteDialog) {
        MuteDurationDialog(
            currentMuteUntil = muteUntil,
            onDismiss = { showMuteDialog = false },
            onSelect = { until ->
                muteUntil = until
                UserStorage.setContactMuteUntil(context, contactId, until)
                showMuteDialog = false
            },
            soundMuted = muteSound,
            onToggleSound = { muted ->
                muteSound = muted
                UserStorage.setContactMuteSound(context, contactId, muted)
            }
        )
    }

    if (showDisappearDialog) {
        AlertDialog(
            onDismissRequest = { showDisappearDialog = false },
            containerColor = c.dialog,
            title = { Text(s.chatDisappearTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    Text(s.chatDisappearSyncedNote, color = c.textPrimary.copy(alpha = 0.6f),
                        fontFamily = JetBrainsMono, fontSize = 14.sp,
                        modifier = Modifier.padding(bottom = 8.dp))
                    listOf(
                        0L to s.chatDisappearOff,
                        3600L to s.chatDisappear1h,
                        86400L to s.chatDisappear24h,
                        604800L to s.chatDisappear7d
                    ).forEach { (secs, label) ->
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable {
                                disappearTimerSecs = secs
                                scope.launch(kotlinx.coroutines.Dispatchers.IO) {
                                    ChatStorage.setDisappearTimer(context, userId, contactId, secs)
                                }
                                messengerService?.sendDisappearTimer(contactId, secs)
                                showDisappearDialog = false
                            }.padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = disappearTimerSecs == secs,
                                onClick = null,
                                colors = RadioButtonDefaults.colors(selectedColor = c.accent)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(label, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 17.sp)
                        }
                    }
                }
            },
            confirmButton = {}
        )
    }

    if (showAutoDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showAutoDeleteDialog = false },
            containerColor = c.dialog,
            title = { Text(s.chatAutoDeleteTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = {
                Column {
                    Text(s.chatAutoDeleteDescription, color = c.textPrimary.copy(alpha = 0.6f),
                        fontFamily = JetBrainsMono, fontSize = 14.sp,
                        modifier = Modifier.padding(bottom = 8.dp))
                    listOf(
                        0L to s.chatDisappearOff,
                        3600L to s.chatDisappear1h,
                        86400L to s.chatDisappear24h,
                        604800L to s.chatDisappear7d
                    ).forEach { (secs, label) ->
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable {
                                autoDeleteSecs = secs
                                scope.launch(kotlinx.coroutines.Dispatchers.IO) {
                                    ChatStorage.setAutoDelete(context, userId, contactId, secs)
                                }
                                showAutoDeleteDialog = false
                            }.padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = autoDeleteSecs == secs,
                                onClick = null,
                                colors = RadioButtonDefaults.colors(selectedColor = c.accent)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(label, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 17.sp)
                        }
                    }
                }
            },
            confirmButton = {}
        )
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            containerColor = c.dialog,
            title = { Text(s.chatsDeleteTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
            text = { Text(s.chatsDeleteText(name), color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 16.sp) },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch(kotlinx.coroutines.Dispatchers.IO) {
                        val msgs = ChatStorage.loadMessages(context, userId, contactId)
                        val mediaPaths = msgs.flatMap { listOfNotNull(it.imagePath, it.voicePath, it.filePath) }
                        ChatStorage.deleteChat(context, userId, contactId)
                        SessionKeyManager.deleteSession(contactId)
                        context.startService(android.content.Intent(context, MessengerService::class.java).apply {
                            putExtra("forget_contact", contactId)
                        })
                        context.startService(android.content.Intent(context, MessengerService::class.java).apply {
                            putExtra("send_session_reset_to", contactId)
                        })
                        mediaPaths.forEach { path -> java.io.File(path).takeIf { it.exists() }?.delete() }
                        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                            showDeleteConfirm = false
                            onContactGone()
                        }
                    }
                }) { Text(s.delete, color = Color(0xFFEF5350), fontFamily = JetBrainsMono) }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }
}
