package com.subrosa.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.onKeyEvent
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

// ─── Material3 color scheme (Navy/Amethyst) ───────────────────────────────────
private val SubrosaColorScheme = darkColorScheme(
    background      = SubrosaTheme.gradientEnd,
    surface         = SubrosaTheme.card,
    primary         = SubrosaTheme.accent,
    onPrimary       = SubrosaTheme.textPrimary,
    onBackground    = SubrosaTheme.textPrimary,
    onSurface       = SubrosaTheme.textPrimary,
    secondary       = SubrosaTheme.cardAlt,
    onSecondary     = SubrosaTheme.textPrimary,
    tertiary        = SubrosaTheme.primaryBlue,
    error           = SubrosaTheme.error,
    surfaceVariant  = SubrosaTheme.bubbleOther,
    outline         = SubrosaTheme.fieldBorder,
)

/** Listens for WebSocketClient.onTotpRequired — this device is logged into
 *  a TOTP-protected account but has no usable code. Offers the recovery-code
 *  fallback. Mirrors Android's MainActivity.RecoveryCodeGate(). */
@Composable
private fun RecoveryCodeGate() {
    var showDialog by remember { mutableStateOf(false) }
    var code by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    var submitted by remember { mutableStateOf(false) }
    // No way out of this dialog otherwise (onDismissRequest is a no-op,
    // confirmButton only submits) — a device pointed at the wrong server
    // (or a server it was never actually meant to talk to) would land here
    // with no way to fix the address and try again. Found live 2026-09-03:
    // "нет кнопки Серверы... на экране регистрации ТОТП".
    var showServerSettings by remember { mutableStateOf(false) }

    DisposableEffect(Unit) {
        WebSocketClient.onTotpRequired = {
            if (submitted) {
                error = true
                submitted = false
            }
            showDialog = true
        }
        onDispose { WebSocketClient.onTotpRequired = null }
    }

    LaunchedEffect(showDialog) {
        while (showDialog) {
            kotlinx.coroutines.delay(1_000)
            if (WebSocketClient.connected.value) {
                showDialog = false
            }
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Защита аккаунта", color = SubrosaTheme.textPrimary) },
            text = {
                Column {
                    Text(
                        "Этому устройству нужен код для входа в аккаунт, защищённый TOTP. У этого устройства нет приложения-аутентификатора — введите один из резервных кодов, полученных при включении защиты.",
                        fontSize = 15.sp, color = SubrosaTheme.textPrimary
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = code,
                        onValueChange = { code = it; error = false },
                        label = { Text("Резервный код") },
                        singleLine = true,
                        isError = error,
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (error) {
                        Spacer(Modifier.height(4.dp))
                        Text("Код не принят — проверьте и попробуйте снова", color = SubrosaTheme.error, fontSize = 14.sp)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = code.isNotBlank(),
                    onClick = {
                        WebSocketClient.submitRecoveryCode(code.trim())
                        code = ""
                        submitted = true
                        error = false
                    }
                ) { Text("Отправить", color = SubrosaTheme.accent) }
            },
            dismissButton = {
                TextButton(onClick = {
                    WebSocketClient.disconnect()
                    showDialog = false
                    submitted = false
                    error = false
                    showServerSettings = true
                }) { Text("Сменить сервер", color = SubrosaTheme.textSecondary) }
            }
        )
    }

    if (showServerSettings) {
        ServerSettingsDialog(onDismiss = { showServerSettings = false })
    }
}

@Composable
fun AppNavigation() {
    MaterialTheme(colorScheme = SubrosaColorScheme, typography = SubrosaTypography) {

        var screen by remember { mutableStateOf(
            if (UserStorage.isRegistered()) "login" else "register"
        ) }
        LaunchedEffect(screen) { AppFocusTracker.currentScreen = screen }
        var pendingChatSearch by remember { mutableStateOf(false) }
        val navScope = rememberCoroutineScope()

        // Panic password — mirrors Android's MainActivity isPanicMode early
        // return: once triggered (LoginScreen's onPanicMode), the fake
        // messenger takes over the whole window for the rest of this
        // process's lifetime, with no way back to any real screen.
        var isPanicMode by remember { mutableStateOf(false) }
        if (isPanicMode) {
            DecoyScreen()
            return@MaterialTheme
        }

        LaunchedEffect(Unit) { CallUiState.ensureWired() }

        // Auto-lock state — read setting once; changes take effect on next launch
        val autoLockTimeoutSecs = remember { UserStorage.getAutoLockTimeout() }
        var lastActivity by remember { mutableStateOf(System.currentTimeMillis()) }
        var isLocked     by remember { mutableStateOf(false) }

        val isAuthScreen = screen == "login" || screen == "register" || screen == "totp_setup_required"

        // Gradient background — wraps all screens
        Box(
            Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(SubrosaTheme.gradientStart, SubrosaTheme.gradientEnd)
                    )
                )
                // Track any pointer activity to reset the inactivity timer
                .pointerInput(Unit) {
                    awaitPointerEventScope {
                        while (true) {
                            awaitPointerEvent()
                            lastActivity = System.currentTimeMillis()
                        }
                    }
                }
                // Track keyboard activity
                .onKeyEvent {
                    lastActivity = System.currentTimeMillis()
                    false
                }
        ) {
            when (screen) {
                "register" -> RegisterScreen(
                    // Mandatory, not optional — see MainActivity.kt on
                    // Android and docs/ISSUE_backup_identity_hijack.md.
                    onRegistered = { screen = "totp_setup_required" }
                )
                "totp_setup_required" -> TotpSettingsScreen(
                    onBack = {},
                    mandatory = true,
                    onCompleted = { screen = "chats" }
                )
                "login" -> LoginScreen(
                    // Mirrors Android's MainActivity fix, found live there:
                    // local registration completes before the mandatory TOTP
                    // step, so quitting mid-setup used to let a later login
                    // skip straight to chats with TOTP still disabled.
                    onLoggedIn = {
                        screen = if (!TotpManager.isEnabled()) "totp_setup_required" else "chats"
                    },
                    onRegister = { screen = "register" },
                    onPanicMode = {
                        isPanicMode = true
                        if (!UserStorage.isDecoyMode()) {
                            // Runs after the fake UI is already showing —
                            // mirrors Android's 400ms post-navigation delay,
                            // so the wipe never blocks the transition to the
                            // decoy screen from being instant.
                            navScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                                kotlinx.coroutines.delay(400)
                                EmergencyWipe.wipeForDecoyKeepAlive()
                            }
                        }
                    }
                )
                "chats" -> ChatsScreen(
                    onOpenChat    = { contact -> screen = "chat:$contact" },
                    onOpenGroup   = { groupId -> screen = "group:$groupId" },
                    // Channels feature disabled — see plan history to re-enable.
                    onOpenChannel = { /* no-op */ },
                    onOpenProfile = { screen = "profile" },
                    onOpenGroupInfo = { groupId -> screen = "group_info:$groupId" },
                    onOpenContactInfo = { contact -> screen = "contact_info:$contact" }
                )
                "profile" -> ProfileScreen(
                    onBack = { screen = "chats" },
                    onOpenTotp = { screen = "totp" },
                    onOpenSecurityGuide = { screen = "security_guide" },
                    onOpenBackup = { screen = "backup" }
                )
                "totp" -> TotpSettingsScreen(onBack = { screen = "profile" })
                "security_guide" -> SecurityGuideScreen(onBack = { screen = "profile" })
                "backup" -> BackupScreen(onBack = { screen = "profile" })
                else -> when {
                    screen.startsWith("chat:") -> {
                        val contact = screen.removePrefix("chat:")
                        ChatScreen(
                            contact = contact,
                            onBack  = { screen = "chats" },
                            onOpenContactInfo = { screen = "contact_info:$contact" },
                            initialSearchMode = pendingChatSearch,
                            onSearchModeConsumed = { pendingChatSearch = false }
                        )
                    }
                    screen.startsWith("group:") -> {
                        val groupId = screen.removePrefix("group:")
                        GroupChatScreen(
                            groupId = groupId,
                            onBack  = { screen = "chats" },
                            onOpenInfo = { screen = "group_info:$groupId" },
                            onStartGroupCall = { isVideo ->
                                val members = GroupManager.getGroup(groupId)?.members ?: emptyList()
                                CallUiState.startGroupCall(groupId, members, isVideo)
                            }
                        )
                    }
                    screen.startsWith("group_info:") -> {
                        val groupId = screen.removePrefix("group_info:")
                        GroupInfoScreen(
                            groupId = groupId,
                            onBack  = { screen = "group:$groupId" },
                            onGroupGone = { screen = "chats" }
                        )
                    }
                    screen.startsWith("contact_info:") -> {
                        val contact = screen.removePrefix("contact_info:")
                        ContactInfoScreen(
                            contactId = contact,
                            onBack = { screen = "chat:$contact" },
                            onContactGone = { screen = "chats" },
                            onOpenChatSearch = { pendingChatSearch = true; screen = "chat:$contact" }
                        )
                    }
                    // Channels feature disabled — see plan history to re-enable.
                    // screen.startsWith("channel:") -> {
                    //     val channelId = screen.removePrefix("channel:")
                    //     ChannelFeedScreen(
                    //         channelId = channelId,
                    //         onBack    = { screen = "chats" }
                    //     )
                    // }
                }
            }

            // Inactivity lock check — only when logged in and timeout is configured
            if (autoLockTimeoutSecs > 0 && !isAuthScreen) {
                LaunchedEffect(autoLockTimeoutSecs) {
                    while (true) {
                        kotlinx.coroutines.delay(10_000L)
                        if (!isLocked &&
                            System.currentTimeMillis() - lastActivity >= autoLockTimeoutSecs * 1000L) {
                            isLocked = true
                        }
                    }
                }
            }

            if (!isAuthScreen) {
                RecoveryCodeGate()
            }

            // Lock screen overlay
            if (isLocked && !isAuthScreen) {
                AutoLockScreen(
                    onUnlocked = {
                        isLocked = false
                        lastActivity = System.currentTimeMillis()
                    }
                )
            }

            // ── Calls (overlay above everything else) ───────────────────────────
            val incoming = CallUiState.incomingCall
            if (incoming != null) {
                IncomingCallDialog(
                    info = incoming,
                    onAccept = {
                        CallUiState.incomingCall = null
                        if (!incoming.isGroup) CallUiState.activeCallPeer = incoming.from
                        CallUiState.mainPeerId = incoming.from
                        DesktopCallManager.acceptCall()
                    },
                    onDecline = {
                        CallUiState.incomingCall = null
                        DesktopCallManager.declineCall()
                    }
                )
            }
            val activePeer = CallUiState.activeCallPeer
            if (activePeer != null || CallUiState.isGroupCall) {
                ActiveCallScreen(peerId = activePeer)
            }

            // "Hide IP during calls" fail-closed banner — standalone (not
            // scoped to ActiveCallScreen) since a refused call never
            // actually reaches that screen. Auto-dismisses like
            // ActiveCallScreen's own cameraWarning.
            CallUiState.relayUnavailableWarning?.let { warning ->
                LaunchedEffect(warning) {
                    kotlinx.coroutines.delay(5_000L)
                    CallUiState.relayUnavailableWarning = null
                }
                androidx.compose.material3.Surface(
                    shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
                    color = SubrosaTheme.error,
                    modifier = Modifier
                        .align(androidx.compose.ui.Alignment.TopCenter)
                        .padding(top = 16.dp)
                ) {
                    androidx.compose.material3.Text(
                        warning,
                        color = androidx.compose.ui.graphics.Color.White,
                        fontSize = 15.sp,
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                    )
                }
            }
        }
    }
}

// ── Auto-lock overlay ─────────────────────────────────────────────────────────

@Composable
private fun AutoLockScreen(onUnlocked: () -> Unit) {
    var password by remember { mutableStateOf("") }
    var hasError by remember { mutableStateOf(false) }

    Box(
        modifier            = Modifier.fillMaxSize().background(Color(0xE8000813)),
        contentAlignment    = Alignment.Center
    ) {
        Surface(
            shape  = RoundedCornerShape(18.dp),
            color  = SubrosaTheme.card,
            modifier = Modifier.width(320.dp)
        ) {
            Column(
                modifier            = Modifier.padding(28.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Приложение заблокировано",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                    color      = SubrosaTheme.textPrimary
                )
                Spacer(Modifier.height(20.dp))
                SecureTextField(
                    value                = password,
                    onValueChange        = { password = it; hasError = false },
                    label                = "Пароль",
                    isError              = hasError,
                    modifier             = Modifier.fillMaxWidth(),
                    colors               = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = SubrosaTheme.accent,
                        unfocusedBorderColor = SubrosaTheme.fieldBorder,
                        focusedLabelColor    = SubrosaTheme.accent,
                        unfocusedLabelColor  = SubrosaTheme.textSecondary,
                        cursorColor          = SubrosaTheme.accent,
                        focusedTextColor     = SubrosaTheme.textPrimary,
                        unfocusedTextColor   = SubrosaTheme.textPrimary
                    )
                )
                if (hasError) {
                    Text(
                        "Неверный пароль",
                        color    = SubrosaTheme.error,
                        fontSize = 14.sp,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = {
                        if (UserStorage.checkPassword(password)) {
                            onUnlocked()
                        } else {
                            hasError = true
                            password = ""
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors   = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent)
                ) {
                    Text("Разблокировать", color = SubrosaTheme.textPrimary)
                }
            }
        }
    }
}
