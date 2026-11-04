package com.subrosa.desktop

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.loadImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Mirrors ChatScreen.kt's ChatAutoDeleteDialog / disappearing-timer dialog
 *  shape (RadioButton list AlertDialog), applied to per-chat mute instead.
 *  Shared by ChatsScreen.kt's right-click "chat actions" dialog and this
 *  screen's own "Notifications" row. [currentMuteUntil]: 0 = not muted,
 *  Long.MAX_VALUE = muted indefinitely, otherwise an epoch-millis expiry
 *  (see UserStorage.getContactMuteUntil/getGroupMuteUntil). */
@Composable
fun MuteDurationDialog(
    currentMuteUntil: Long,
    onDismiss: () -> Unit,
    onSelect: (Long) -> Unit,
    soundMuted: Boolean = false,
    onToggleSound: ((Boolean) -> Unit)? = null
) {
    val s = LocalStrings.current
    val isMuted = currentMuteUntil > System.currentTimeMillis()
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SubrosaTheme.dialog,
        title = { Text(s.muteDialogTitle, color = SubrosaTheme.textPrimary) },
        text = {
            Column {
                if (onToggleSound != null) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(s.muteSoundOnly, color = SubrosaTheme.textPrimary, fontSize = 16.sp, modifier = Modifier.weight(1f))
                        Switch(
                            checked = soundMuted,
                            onCheckedChange = onToggleSound,
                            colors = SwitchDefaults.colors(checkedThumbColor = SubrosaTheme.accent, checkedTrackColor = SubrosaTheme.accent.copy(alpha = 0.35f))
                        )
                    }
                    androidx.compose.material3.HorizontalDivider(color = SubrosaTheme.divider, thickness = 0.5.dp)
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
                    // produced it. Current state is shown as text elsewhere
                    // (ContactInfoScreen's row subtitle).
                    val selected = when (durationMs) {
                        0L -> !isMuted
                        Long.MAX_VALUE -> currentMuteUntil == Long.MAX_VALUE
                        else -> false
                    }
                    val select = {
                        onSelect(
                            when (durationMs) {
                                0L -> 0L
                                Long.MAX_VALUE -> Long.MAX_VALUE
                                else -> System.currentTimeMillis() + durationMs
                            }
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(onClick = select)
                            .padding(vertical = 10.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selected,
                            onClick = select,
                            colors = RadioButtonDefaults.colors(
                                selectedColor = SubrosaTheme.accent,
                                unselectedColor = SubrosaTheme.textSecondary
                            )
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(label, fontSize = 16.sp, color = SubrosaTheme.textPrimary)
                    }
                }
            }
        },
        confirmButton = {}
    )
}

/** 1:1 counterpart to GroupInfoScreen — reached by tapping the avatar/name
 *  in ChatScreen.kt's header or ChatsScreen's "chat actions" dialog.
 *  Consolidates everything that used to live in ChatScreen's 3-dot overflow
 *  menu (verify key, auto-delete, restore connection — lifted verbatim from
 *  there) plus per-chat mute and a full-size avatar viewer, neither of which
 *  had a home before this screen existed. */
@Composable
fun ContactInfoScreen(
    contactId: String,
    onBack: () -> Unit,
    onContactGone: () -> Unit = onBack,
    onOpenChatSearch: () -> Unit = {}
) {
    val s = LocalStrings.current
    val scope = rememberCoroutineScope()
    val myId = WebSocketClient.myFingerprint
    val name = remember { ChatStorage.getContactName(contactId) }

    LaunchedEffect(contactId) { AvatarStore.loadIfMissing(contactId) }
    val avatarBmp = AvatarStore.avatars[contactId]

    var showFullscreenAvatar by remember { mutableStateOf(false) }
    var showMuteDialog by remember { mutableStateOf(false) }
    var muteUntil by remember { mutableStateOf(UserStorage.getContactMuteUntil(contactId)) }
    var muteSound by remember { mutableStateOf(UserStorage.getContactMuteSound(contactId)) }
    var showAutoDeleteDialog by remember { mutableStateOf(false) }
    var autoDeleteSecs by remember { mutableStateOf(UserStorage.getChatAutoDelete(contactId)) }
    var showDisappearDialog by remember { mutableStateOf(false) }
    var disappearTimerSecs by remember { mutableStateOf(ChatStorage.getDisappearTimer(myId, contactId)) }
    var showVerifyDialog by remember { mutableStateOf(false) }
    var restoreConnectionMessage by remember { mutableStateOf<String?>(null) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    LaunchedEffect(restoreConnectionMessage) {
        if (restoreConnectionMessage != null) {
            kotlinx.coroutines.delay(4000)
            restoreConnectionMessage = null
        }
    }

    val muteSubtitle = when {
        muteUntil == Long.MAX_VALUE -> s.muteStatusForever
        muteUntil > System.currentTimeMillis() ->
            s.muteStatusUntil(java.text.SimpleDateFormat("HH:mm").format(java.util.Date(muteUntil)))
        else -> s.muteStatusOff
    }
    val autoDeleteLabel = when (autoDeleteSecs) {
        0L -> "Выключено"
        3600L -> "1 час"
        86400L -> "1 день"
        604800L -> "1 неделя"
        else -> "${autoDeleteSecs / 3600}ч"
    }
    val disappearLabel = when (disappearTimerSecs) {
        0L -> "Выключено"
        3600L -> "1 час"
        86400L -> "1 день"
        604800L -> "1 неделя"
        else -> "${disappearTimerSecs / 3600}ч"
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
                Text(s.contactInfoTitle, fontSize = 19.sp, fontWeight = FontWeight.SemiBold, color = SubrosaTheme.textPrimary)
            }
        }

        restoreConnectionMessage?.let { msg ->
            Surface(color = SubrosaTheme.accent.copy(alpha = 0.15f), modifier = Modifier.fillMaxWidth()) {
                Text(msg, fontSize = 14.sp, color = SubrosaTheme.textPrimary,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp))
            }
        }

        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
            Spacer(Modifier.height(20.dp))
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    modifier = Modifier
                        .size(84.dp)
                        .clip(CircleShape)
                        .background(SubrosaTheme.accent.copy(alpha = 0.15f))
                        .then(if (avatarBmp != null) Modifier.clickable { showFullscreenAvatar = true } else Modifier),
                    contentAlignment = Alignment.Center
                ) {
                    if (avatarBmp != null) {
                        Image(
                            bitmap = avatarBmp,
                            contentDescription = null,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.fillMaxSize()
                        )
                    } else {
                        Text(
                            name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                            fontSize = 32.sp, color = SubrosaTheme.textPrimary
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(name, fontSize = 21.sp, fontWeight = FontWeight.Bold, color = SubrosaTheme.textPrimary, fontFamily = NotoSerifJP)
            }

            SHeader(s.profileSectionSecurity)
            SGroup {
                SItem(
                    icon = "",
                    label = s.chatVerifyKey,
                    onClick = { showVerifyDialog = true }
                ) { Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f)) }
                SLine()
                SItem(
                    icon = "",
                    label = s.contactInfoNotifications,
                    hint = muteSubtitle,
                    onClick = { showMuteDialog = true }
                ) { Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f)) }
                SLine()
                SItem(
                    icon = "",
                    label = s.contactInfoSearch,
                    onClick = onOpenChatSearch
                ) { Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f)) }
                SLine()
                SItem(
                    icon = "",
                    label = s.chatAutoDeleteMenu,
                    hint = autoDeleteLabel,
                    onClick = { showAutoDeleteDialog = true }
                ) { Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f)) }
                SLine()
                SItem(
                    icon = "",
                    label = s.chatDisappearMenu,
                    hint = disappearLabel,
                    onClick = { showDisappearDialog = true }
                ) { Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f)) }
                SLine()
                SItem(
                    icon = "",
                    label = s.chatRestoreConnection,
                    onClick = {
                        if (ContactHealthManager.canManualRestore(contactId)) {
                            ContactHealthManager.recordManualRestore(contactId)
                            WebSocketClient.forceRestoreConnection(contactId)
                            restoreConnectionMessage = "Восстановление связи запущено…"
                        } else {
                            val minutesLeft = ContactHealthManager.manualRestoreRemainingMs(contactId) / 60_000L + 1
                            restoreConnectionMessage = "Подождите ещё $minutesLeft мин перед повтором"
                        }
                    }
                ) { Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f)) }
            }

            SHeader(s.chatsActionDelete)
            SGroup {
                SItem(
                    icon = "",
                    label = s.chatsActionDelete,
                    labelColor = SubrosaTheme.error,
                    onClick = { showDeleteConfirm = true }
                ) {}
            }
        }
    }

    if (showFullscreenAvatar && avatarBmp != null) {
        Surface(color = Color.Black, modifier = Modifier.fillMaxSize()) {
            Box(
                modifier = Modifier.fillMaxSize().clickable { showFullscreenAvatar = false },
                contentAlignment = Alignment.Center
            ) {
                Image(bitmap = avatarBmp, contentDescription = null, contentScale = ContentScale.Fit, modifier = Modifier.fillMaxSize())
            }
        }
    }

    if (showMuteDialog) {
        MuteDurationDialog(
            currentMuteUntil = muteUntil,
            onDismiss = { showMuteDialog = false },
            onSelect = { until ->
                muteUntil = until
                UserStorage.setContactMuteUntil(contactId, until)
                showMuteDialog = false
            },
            soundMuted = muteSound,
            onToggleSound = { muted ->
                muteSound = muted
                UserStorage.setContactMuteSound(contactId, muted)
            }
        )
    }

    if (showAutoDeleteDialog) {
        ChatAutoDeleteDialog(
            current = autoDeleteSecs,
            onSelect = { secs ->
                autoDeleteSecs = secs
                UserStorage.setChatAutoDelete(contactId, secs)
                showAutoDeleteDialog = false
            },
            onDismiss = { showAutoDeleteDialog = false }
        )
    }

    if (showDisappearDialog) {
        DisappearTimerDialog(
            current = disappearTimerSecs,
            onSelect = { secs ->
                disappearTimerSecs = secs
                ChatStorage.setDisappearTimer(myId, contactId, secs)
                WebSocketClient.sendDisappearTimer(contactId, secs)
                showDisappearDialog = false
            },
            onDismiss = { showDisappearDialog = false }
        )
    }

    if (showVerifyDialog) {
        val fingerprintEmoji = remember(contactId) { fingerprintToEmoji(contactId) }
        val fingerprintHex = remember(contactId) { contactId.chunked(2).joinToString(" ").lowercase() }
        var isVerified by remember(contactId) {
            mutableStateOf(KeyHistoryManager.getHistory(contactId).lastOrNull()?.verified == true)
        }
        AlertDialog(
            onDismissRequest = { showVerifyDialog = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Проверка ключа", color = SubrosaTheme.textPrimary) },
            text = {
                Column {
                    Text(
                        "Сравните эту последовательность с той, что видит $name на своём устройстве — " +
                        "по голосу, при личной встрече или через другой доверенный канал.",
                        color = SubrosaTheme.textSecondary, fontSize = 15.sp
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(fingerprintEmoji, fontSize = 30.sp)
                    Spacer(Modifier.height(8.dp))
                    Text(fingerprintHex, fontSize = 14.sp, color = SubrosaTheme.accent)
                    if (isVerified) {
                        Spacer(Modifier.height(12.dp))
                        Text("Отмечено как проверенное", color = SubrosaTheme.accent, fontSize = 15.sp)
                    }
                }
            },
            confirmButton = {
                if (!isVerified) {
                    TextButton(onClick = {
                        KeyHistoryManager.markAsVerified(contactId)
                        isVerified = true
                    }) { Text("Отметить как проверенное", color = SubrosaTheme.accent) }
                } else {
                    TextButton(onClick = { showVerifyDialog = false }) {
                        Text("Закрыть", color = SubrosaTheme.accent)
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { showVerifyDialog = false }) {
                    Text("Отмена", color = SubrosaTheme.textSecondary)
                }
            }
        )
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text(s.chatsDeleteTitle, color = SubrosaTheme.textPrimary) },
            text = { Text(s.chatsDeleteText(name), color = SubrosaTheme.textSecondary, fontSize = 16.sp) },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch(Dispatchers.IO) {
                        val mediaPaths = ChatStorage.loadMessages(myId, contactId)
                            .flatMap { listOfNotNull(it.imagePath, it.filePath) }
                        ChatStorage.removeContact(contactId)
                        ChatStorage.deleteChat(myId, contactId)
                        WebSocketClient.forgetContact(contactId)
                        WebSocketClient.notifyContactOfDeletion(contactId)
                        ContactHealthManager.clearContact(contactId)
                        mediaPaths.forEach { path -> java.io.File(path).takeIf { it.exists() }?.delete() }
                        withContext(Dispatchers.Main) {
                            showDeleteConfirm = false
                            onContactGone()
                        }
                    }
                }) { Text(s.delete, color = SubrosaTheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) {
                    Text(s.cancel, color = SubrosaTheme.textSecondary)
                }
            }
        )
    }
}
