package com.subrosa.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusEvent
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.compose.ui.res.painterResource

@OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
fun TotpSettingsScreen(
    onBack: () -> Unit,
    // Forced onboarding path (right after RegisterScreen) — no back button,
    // no skipping until setup completes and recovery codes are confirmed
    // saved. See MainActivity.kt, "totp_setup_required".
    mandatory: Boolean = false,
    onCompleted: () -> Unit = {},
    // Mandatory mode has no back button and no other way to reach
    // ServersScreen — found live: a broken/misconfigured server left the
    // user stuck on this screen unable to switch servers or diagnose
    // anything. Only shown when mandatory (non-mandatory already reaches
    // Servers via Profile).
    onOpenServers: (() -> Unit)? = null
) {
    if (!mandatory) androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val clipboard = LocalClipboardManager.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var secretCopied by remember { mutableStateOf(false) }
    var recoveryCodes by remember { mutableStateOf<List<String>?>(null) }
    var recoveryCodesSavedConfirmed by remember { mutableStateOf(false) }

    var messengerService by remember { mutableStateOf<MessengerService?>(null) }
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
        onDispose { try { context.unbindService(connection) } catch (e: Exception) {} }
    }

    var enabled by remember { mutableStateOf(TotpManager.isEnabled(context)) }
    var pendingSecret by remember { mutableStateOf<String?>(null) }
    var codeInput by remember { mutableStateOf("") }
    var disableCodeInput by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    // Set when the server rejects setup with reason "already_enabled" — this
    // account already has a secret from another device, most commonly
    // because this device just logged in via a recovery code (device-gated
    // registration TOTP) and has no way to produce a code for the old
    // secret. A second recovery code authorizes replacing it. See
    // docs/TODO.md "recovery-code takeover window", server.py's totp_setup
    // handler.
    var needsReenrollRecovery by remember { mutableStateOf(false) }
    var reenrollRecoveryInput by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    DisposableEffect(messengerService) {
        val svc = messengerService
        svc?.onTotpSetupResult = { success, reason, codes ->
            busy = false
            if (success) {
                enabled = true
                pendingSecret = null
                codeInput = ""
                needsReenrollRecovery = false
                reenrollRecoveryInput = ""
                message = s.totpEnabledSuccess
                isError = false
                recoveryCodes = codes
                // Also saved locally (hashed) so a future backup export can
                // embed them — see TotpManager's doc comment and
                // docs/ISSUE_backup_identity_hijack.md, "Восстановление при
                // утере TOTP-секрета".
                if (codes != null) {
                    TotpManager.saveRecoveryCodeHashes(context, codes.map { TotpManager.hashRecoveryCode(it) })
                }
            } else if (reason == "already_enabled" && !needsReenrollRecovery) {
                // Don't discard pendingSecret/codeInput — the user already
                // generated and verified a secret against their authenticator,
                // no need to make them redo that. Just reveal the recovery-code
                // field and let them retry the same secret+code with proof.
                needsReenrollRecovery = true
                message = s.totpReenrollPrompt
                isError = false
            } else {
                // Keep client and server in sync — a secret the server refused
                // to register (e.g. it already had one from an earlier attempt)
                // shouldn't be left "enabled" locally, since that would silently
                // include a totp_code in future register() calls that the
                // server was never told to expect.
                TotpManager.disable(context)
                enabled = false
                pendingSecret = null
                message = s.totpErrInvalidCode + (reason?.let { " ($it)" } ?: "")
                isError = true
            }
        }
        svc?.onTotpDisableResult = { success ->
            busy = false
            if (success) {
                TotpManager.disable(context)
                enabled = false
                disableCodeInput = ""
                message = ""
            } else {
                message = s.totpErrInvalidCode
                isError = true
            }
        }
        onDispose {
            svc?.onTotpSetupResult = null
            svc?.onTotpDisableResult = null
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (mandatory) s.totpMandatoryTitle else s.totpTitle, fontWeight = FontWeight.Bold, fontSize = 20.sp) },
                navigationIcon = {
                    if (!mandatory) {
                        IconButton(onClick = onBack) {
                            Icon(painterResource(R.drawable.ic_back_arrow), contentDescription = s.back)
                        }
                    }
                },
                actions = {
                    if (mandatory && onOpenServers != null) {
                        TextButton(onClick = onOpenServers) {
                            Text(s.profileServers, color = c.accent, fontSize = 15.sp)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = c.textPrimary,
                    navigationIconContentColor = c.textPrimary
                )
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .background(bgGradient)
        ) {
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .imePadding()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (mandatory) {
                    Text(
                        s.totpMandatoryIntro,
                        fontSize = 15.sp,
                        lineHeight = 18.sp,
                        color = c.textPrimary.copy(alpha = 0.85f),
                        fontWeight = FontWeight.Bold
                    )
                }

                val codes = recoveryCodes
                if (codes != null) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = c.dangerCard),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(s.totpRecoveryCodesTitle, fontWeight = FontWeight.Bold, color = c.textPrimary)
                            Text(s.totpRecoveryCodesHint, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.75f))
                            SelectionContainer {
                                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    codes.forEach { code ->
                                        Text(code, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontSize = 17.sp, color = c.textPrimary)
                                    }
                                }
                            }
                            var codesCopied by remember { mutableStateOf(false) }
                            TextButton(onClick = {
                                clipboard.setText(AnnotatedString(codes.joinToString("\n")))
                                codesCopied = true
                            }) {
                                Text(if (codesCopied) s.profileCodeCopied else s.totpCopySecret, color = c.accent, fontSize = 14.sp)
                            }
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.clickable { recoveryCodesSavedConfirmed = !recoveryCodesSavedConfirmed }
                            ) {
                                Checkbox(checked = recoveryCodesSavedConfirmed, onCheckedChange = { recoveryCodesSavedConfirmed = it })
                                Text(s.totpRecoveryCodesConfirm, fontSize = 14.sp, color = c.textPrimary)
                            }
                            Button(
                                onClick = {
                                    recoveryCodes = null
                                    recoveryCodesSavedConfirmed = false
                                    if (mandatory) onCompleted()
                                },
                                enabled = recoveryCodesSavedConfirmed,
                                colors = ButtonDefaults.buttonColors(containerColor = c.accent),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(if (mandatory) s.totpRecoveryCodesContinue else s.totpRecoveryCodesDone, color = if (c.isDark) Color.White else c.textPrimary)
                            }
                        }
                    }
                    return@Column
                }

                Text(
                    s.totpDescription,
                    fontSize = 15.sp,
                    lineHeight = 18.sp,
                    color = c.textPrimary.copy(alpha = 0.75f)
                )

                Card(
                    colors = CardDefaults.cardColors(containerColor = c.card),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            if (enabled) s.totpStatusEnabled else s.totpStatusDisabled,
                            color = if (enabled) Color(0xFF66BB6A) else c.textPrimary.copy(alpha = 0.6f),
                            fontWeight = FontWeight.Bold
                        )

                        if (enabled) {
                            Text(s.totpDisableHint, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.6f))
                            val disableCodeBringIntoView = remember { BringIntoViewRequester() }
                            OutlinedTextField(
                                value = disableCodeInput,
                                onValueChange = { disableCodeInput = it },
                                label = { Text(s.totpCodeLabel) },
                                singleLine = true,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .bringIntoViewRequester(disableCodeBringIntoView)
                                    .onFocusEvent {
                                        // A plain immediate bringIntoView() computes the
                                        // scroll target against the pre-keyboard viewport —
                                        // the field often already "fits" at that point, so
                                        // nothing scrolls, and then the IME slides up
                                        // afterward and covers it anyway with no further
                                        // trigger. Delaying past the IME's own show
                                        // animation (~250ms on most devices) lets imePadding
                                        // resize the layout first, so bringIntoView() targets
                                        // the actually-final position. Found live — reported
                                        // repeatedly on this exact screen.
                                        if (it.isFocused) scope.launch {
                                            delay(300)
                                            disableCodeBringIntoView.bringIntoView()
                                        }
                                    }
                            )
                            Button(
                                onClick = {
                                    val svc = messengerService
                                    if (svc == null || !svc.isOnline()) {
                                        message = s.serverTotpErrNotConnected
                                        isError = true
                                    } else {
                                        busy = true
                                        svc.sendTotpDisable(disableCodeInput)
                                        // Server response is async (onTotpDisableResult fires
                                        // later over the WebSocket) — if it never arrives (dead
                                        // connection, reconnect mid-flight), busy would otherwise
                                        // stay true forever with no way to retry. Found live.
                                        scope.launch {
                                            delay(15_000)
                                            if (busy) {
                                                busy = false
                                                message = s.totpErrTimeout
                                                isError = true
                                            }
                                        }
                                    }
                                },
                                enabled = !busy && disableCodeInput.isNotBlank(),
                                colors = ButtonDefaults.buttonColors(containerColor = c.dangerCard)
                            ) {
                                Text(s.totpDisableButton, color = c.textPrimary)
                            }
                            if (busy) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = c.accent)
                                    Spacer(Modifier.width(8.dp))
                                    Text(s.totpConfirmingWithServer, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.7f))
                                }
                            }
                        } else if (pendingSecret == null) {
                            Button(
                                onClick = { pendingSecret = TotpManager.generateSecret() },
                                colors = ButtonDefaults.buttonColors(containerColor = c.accent)
                            ) {
                                Text(s.totpSetupButton, color = if (c.isDark) Color.White else c.textPrimary)
                            }
                        } else {
                            val secret = pendingSecret!!
                            // Collapse the secret/QR-URI block once the code field is
                            // focused — the delay-past-IME-animation bringIntoView() fix
                            // above still wasn't reliably enough on its own (reported
                            // live, repeatedly, on this exact screen). The user has
                            // already had the chance to copy/scan the secret by the time
                            // they tap into the code field, so hiding it then costs
                            // nothing and leaves far less content for the keyboard to
                            // compete with — the field ends up positioned high enough on
                            // screen that it doesn't need to fight the keyboard for
                            // space at all. Reappears if they tap away from the field.
                            var codeFieldFocused by remember { mutableStateOf(false) }

                            if (!codeFieldFocused) {
                                // Secret text and the copy button are on separate lines —
                                // found live: crammed into one Row with Modifier.weight(1f),
                                // the button got squeezed off-screen on a narrower phone
                                // while rendering fine on a wider emulator window. A full-width
                                // text line followed by its own button row can't be squeezed.
                                SelectionContainer {
                                    Text(
                                        secret,
                                        fontSize = 18.sp,
                                        color = c.textPrimary,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                                // Manual text selection (long-press) is unreliable on
                                // emulators/some devices with mouse-simulated touch —
                                // found live while testing the mandatory setup flow. An
                                // explicit copy button doesn't depend on that at all.
                                TextButton(
                                    onClick = {
                                        clipboard.setText(AnnotatedString(secret))
                                        secretCopied = true
                                    },
                                    modifier = Modifier.align(Alignment.End)
                                ) {
                                    Text(if (secretCopied) s.profileCodeCopied else s.totpCopySecret, color = c.accent, fontSize = 14.sp)
                                }
                                SelectionContainer {
                                    Text(
                                        TotpManager.otpAuthUri(secret, UserStorage.getUserId(context)),
                                        fontSize = 13.sp,
                                        color = c.textPrimary.copy(alpha = 0.5f)
                                    )
                                }
                                Text(s.totpSecretLabel, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.6f))
                            }

                            val codeInputBringIntoView = remember { BringIntoViewRequester() }
                            OutlinedTextField(
                                value = codeInput,
                                onValueChange = { codeInput = it },
                                label = { Text(s.totpCodeLabel) },
                                singleLine = true,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .bringIntoViewRequester(codeInputBringIntoView)
                                    .onFocusEvent {
                                        codeFieldFocused = it.isFocused
                                        // See the disableCodeBringIntoView comment above —
                                        // same delay-past-IME-animation fix. Kept as a
                                        // belt-and-suspenders on top of the collapse above.
                                        if (it.isFocused) scope.launch {
                                            delay(300)
                                            codeInputBringIntoView.bringIntoView()
                                        }
                                    }
                            )

                            if (needsReenrollRecovery) {
                                val reenrollBringIntoView = remember { BringIntoViewRequester() }
                                Text(s.totpReenrollPrompt, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.75f))
                                OutlinedTextField(
                                    value = reenrollRecoveryInput,
                                    onValueChange = { reenrollRecoveryInput = it },
                                    label = { Text(s.totpRecoveryFieldLabel) },
                                    singleLine = true,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .bringIntoViewRequester(reenrollBringIntoView)
                                        .onFocusEvent {
                                            // Same delay-past-IME-animation fix.
                                            if (it.isFocused) scope.launch {
                                                delay(300)
                                                reenrollBringIntoView.bringIntoView()
                                            }
                                        }
                                )
                            }

                            Button(
                                onClick = {
                                    val svc = messengerService
                                    if (!TotpManager.verifyCode(secret, codeInput)) {
                                        message = s.totpErrInvalidCode
                                        isError = true
                                    } else if (needsReenrollRecovery && reenrollRecoveryInput.isBlank()) {
                                        message = s.totpReenrollPrompt
                                        isError = true
                                    } else if (svc == null || !svc.isOnline()) {
                                        message = s.serverTotpErrNotConnected
                                        isError = true
                                    } else {
                                        // Enabled locally first so register()'s
                                        // totp_code inclusion and the server
                                        // round-trip use the same secret — rolled
                                        // back in onTotpSetupResult if the server
                                        // refuses it, and by the timeout below if
                                        // no response arrives at all (found live:
                                        // without this, a dead/reconnecting
                                        // connection left the client thinking TOTP
                                        // was enabled while the server never
                                        // actually got the secret — device-gating
                                        // would then silently never trigger).
                                        TotpManager.enable(context, secret)
                                        busy = true
                                        svc.sendTotpSetup(
                                            secret, codeInput,
                                            recoveryCode = if (needsReenrollRecovery) reenrollRecoveryInput else null
                                        )
                                        scope.launch {
                                            delay(15_000)
                                            if (busy) {
                                                TotpManager.disable(context)
                                                busy = false
                                                enabled = false
                                                message = s.totpErrTimeout
                                                isError = true
                                            }
                                        }
                                    }
                                },
                                enabled = !busy && codeInput.isNotBlank() && (!needsReenrollRecovery || reenrollRecoveryInput.isNotBlank()),
                                colors = ButtonDefaults.buttonColors(containerColor = c.accent),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(s.totpConfirmButton, color = if (c.isDark) Color.White else c.textPrimary)
                            }
                            if (busy) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = c.accent)
                                    Spacer(Modifier.width(8.dp))
                                    Text(s.totpConfirmingWithServer, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.7f))
                                }
                            }
                        }

                        if (message.isNotEmpty()) {
                            Text(
                                message,
                                color = if (isError) c.error else Color(0xFF66BB6A),
                                fontSize = 15.sp
                            )
                        }
                    }
                }
            }
        }
    }
}
