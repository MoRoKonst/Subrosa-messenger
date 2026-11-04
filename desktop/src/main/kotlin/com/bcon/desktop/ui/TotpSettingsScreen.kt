package com.subrosa.desktop

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Desktop port of Android's TotpSettingsScreen.kt — same dual-purpose secret
 *  (device-gated registration protection + backup-import gate), same 15s
 *  timeout-with-rollback if the server never answers (found live on Android,
 *  see docs/ISSUE_backup_identity_hijack.md). No service binding needed here
 *  (WebSocketClient is a plain object, not a bound Android service). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TotpSettingsScreen(
    onBack: () -> Unit,
    // Forced onboarding path (right after RegisterScreen) — see
    // AppNavigation.kt, "totp_setup_required".
    mandatory: Boolean = false,
    onCompleted: () -> Unit = {}
) {
    val scope = rememberCoroutineScope()

    var enabled by remember { mutableStateOf(TotpManager.isEnabled()) }
    var pendingSecret by remember { mutableStateOf<String?>(null) }
    var codeInput by remember { mutableStateOf("") }
    var disableCodeInput by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var recoveryCodes by remember { mutableStateOf<List<String>?>(null) }
    var recoveryCodesSavedConfirmed by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    var secretCopied by remember { mutableStateOf(false) }
    // Set when the server rejects setup with reason "already_enabled" — this
    // account already has a secret from another device, most commonly
    // because this device just logged in via a recovery code and has no way
    // to produce a code for the old secret. A second recovery code
    // authorizes replacing it. Mirrors Android's TotpSettingsScreen.kt
    // "needsReenrollRecovery".
    var needsReenrollRecovery by remember { mutableStateOf(false) }
    var reenrollRecoveryInput by remember { mutableStateOf("") }

    DisposableEffect(Unit) {
        WebSocketClient.onTotpSetupResult = { success, reason, codes ->
            busy = false
            if (success) {
                enabled = true
                pendingSecret = null
                codeInput = ""
                needsReenrollRecovery = false
                reenrollRecoveryInput = ""
                message = "TOTP-защита включена"
                isError = false
                recoveryCodes = codes
                // Also saved locally (hashed) so a future backup export can
                // embed them — mirrors Android's TotpSettingsScreen.kt.
                if (codes != null) {
                    TotpManager.saveRecoveryCodeHashes(codes.map { TotpManager.hashRecoveryCode(it) })
                }
            } else if (reason == "already_enabled" && !needsReenrollRecovery) {
                // Don't discard pendingSecret/codeInput — the user already
                // generated and verified a secret against their
                // authenticator, no need to make them redo that. Just
                // reveal the recovery-code field and let them retry the
                // same secret+code with proof.
                needsReenrollRecovery = true
                message = "На этом аккаунте уже настроена TOTP-защита с другого устройства. Введите один из резервных кодов, чтобы заменить секрет."
                isError = false
            } else {
                // Keep client and server in sync — see the matching comment
                // on Android's TotpSettingsScreen.kt.
                TotpManager.disable()
                enabled = false
                pendingSecret = null
                message = "Неверный код" + (reason?.let { " ($it)" } ?: "")
                isError = true
            }
        }
        WebSocketClient.onTotpDisableResult = { success ->
            busy = false
            if (success) {
                TotpManager.disable()
                enabled = false
                disableCodeInput = ""
                message = ""
            } else {
                message = "Неверный код"
                isError = true
            }
        }
        onDispose {
            WebSocketClient.onTotpSetupResult = null
            WebSocketClient.onTotpDisableResult = null
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (mandatory) "Защита аккаунта" else "Двухфакторная защита", fontWeight = FontWeight.Bold, fontSize = 20.sp) },
                navigationIcon = {
                    if (!mandatory) {
                        IconButton(onClick = onBack) {
                            Icon(AppIcons.get("BACK_ARROW"), contentDescription = "Назад")
                        }
                    }
                },
                actions = {
                    // Reachable even in the mandatory (no back button) onboarding
                    // path right after registration — without this, a wrong/
                    // unreachable server address left the user stuck on this
                    // screen with no way out at all. Found live 2026-09-03:
                    // "на экране тотп выход в сервера, не на другом, ровно как
                    // в андроид клиенте".
                    ServerSettingsButton()
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = SubrosaTheme.textPrimary,
                    navigationIconContentColor = SubrosaTheme.textPrimary
                )
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (mandatory) {
                Text(
                    "Прежде чем продолжить — настройте TOTP-защиту. Это обязательный шаг: без него сервер не сможет отличить вас от того, кто украдёт ваш ключ.",
                    fontSize = 15.sp,
                    lineHeight = 18.sp,
                    color = SubrosaTheme.textPrimary.copy(alpha = 0.9f),
                    fontWeight = FontWeight.Bold
                )
            }

            val codes = recoveryCodes
            if (codes != null) {
                Card(colors = CardDefaults.cardColors(containerColor = SubrosaTheme.error.copy(alpha = 0.12f)), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(AppIcons.get("WARNING"), contentDescription = null,
                                tint = SubrosaTheme.textPrimary, modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Резервные коды — сохраните их сейчас", fontWeight = FontWeight.Bold, color = SubrosaTheme.textPrimary)
                        }
                        Text(
                            "Каждый код можно использовать один раз, если вы потеряете доступ к приложению-аутентификатору. Больше эти коды нигде не показываются.",
                            fontSize = 14.sp, color = SubrosaTheme.textPrimary.copy(alpha = 0.75f)
                        )
                        SelectionContainer {
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                codes.forEach { code ->
                                    Text(code, fontFamily = FontFamily.Monospace, fontSize = 17.sp, color = SubrosaTheme.textPrimary)
                                }
                            }
                        }
                        var codesCopied by remember { mutableStateOf(false) }
                        TextButton(onClick = {
                            clipboard.setText(AnnotatedString(codes.joinToString("\n")))
                            codesCopied = true
                        }) {
                            Text(if (codesCopied) "скопировано" else "Копировать", color = SubrosaTheme.accent, fontSize = 14.sp)
                        }
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.clickable { recoveryCodesSavedConfirmed = !recoveryCodesSavedConfirmed }
                        ) {
                            Checkbox(checked = recoveryCodesSavedConfirmed, onCheckedChange = { recoveryCodesSavedConfirmed = it })
                            Text("Я сохранил(а) эти коды в надёжном месте", fontSize = 14.sp, color = SubrosaTheme.textPrimary)
                        }
                        Button(
                            onClick = {
                                recoveryCodes = null
                                recoveryCodesSavedConfirmed = false
                                if (mandatory) onCompleted()
                            },
                            enabled = recoveryCodesSavedConfirmed,
                            colors = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(if (mandatory) "Продолжить" else "Готово", color = Color.White)
                        }
                    }
                }
                return@Column
            }

            Text(
                "Дополнительный фактор защиты аккаунта: код потребуется и при восстановлении бэкапа на новом устройстве, и при попытке зайти под этим же fingerprint'ом с нового устройства, которое сервер раньше не видел. Секрет нужно сохранить отдельно (например, в KeePass) — он не хранится внутри самого бэкапа.",
                fontSize = 15.sp,
                lineHeight = 18.sp,
                color = SubrosaTheme.textPrimary.copy(alpha = 0.75f)
            )

            Card(colors = CardDefaults.cardColors(containerColor = SubrosaTheme.card), modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        if (enabled) "Включено" else "Выключено",
                        color = if (enabled) Color(0xFF66BB6A) else SubrosaTheme.textPrimary.copy(alpha = 0.6f),
                        fontWeight = FontWeight.Bold
                    )

                    if (enabled) {
                        OutlinedTextField(
                            value = disableCodeInput,
                            onValueChange = { disableCodeInput = it },
                            label = { Text("Код из приложения-аутентификатора") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Button(
                            onClick = {
                                if (!WebSocketClient.connected.value) {
                                    message = "Нет соединения с сервером"
                                    isError = true
                                } else {
                                    busy = true
                                    WebSocketClient.sendTotpDisable(disableCodeInput)
                                    scope.launch {
                                        delay(15_000)
                                        if (busy) {
                                            busy = false
                                            message = "Сервер не ответил вовремя — попробуйте ещё раз"
                                            isError = true
                                        }
                                    }
                                }
                            },
                            enabled = !busy && disableCodeInput.isNotBlank(),
                            colors = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.error)
                        ) {
                            Text("Выключить", color = SubrosaTheme.textPrimary)
                        }
                        if (busy) BusyRow()
                    } else if (pendingSecret == null) {
                        Button(
                            onClick = { pendingSecret = TotpManager.generateSecret() },
                            colors = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent)
                        ) {
                            Text("Настроить", color = Color.White)
                        }
                    } else {
                        val secret = pendingSecret!!
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            SelectionContainer(modifier = Modifier.weight(1f)) {
                                Text(secret, fontSize = 18.sp, color = SubrosaTheme.textPrimary, fontWeight = FontWeight.Bold)
                            }
                            Spacer(Modifier.width(8.dp))
                            TextButton(onClick = {
                                clipboard.setText(AnnotatedString(secret))
                                secretCopied = true
                            }) {
                                Text(if (secretCopied) "скопировано" else "Копировать", color = SubrosaTheme.accent, fontSize = 14.sp)
                            }
                        }
                        SelectionContainer {
                            Text(
                                TotpManager.otpAuthUri(secret, UserStorage.getUsername()),
                                fontSize = 13.sp,
                                color = SubrosaTheme.textPrimary.copy(alpha = 0.5f)
                            )
                        }
                        Text("Секрет (сохраните его отдельно, не рядом с бэкапом)", fontSize = 14.sp, color = SubrosaTheme.textPrimary.copy(alpha = 0.6f))

                        OutlinedTextField(
                            value = codeInput,
                            onValueChange = { codeInput = it },
                            label = { Text("Код из приложения-аутентификатора") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )

                        if (needsReenrollRecovery) {
                            OutlinedTextField(
                                value = reenrollRecoveryInput,
                                onValueChange = { reenrollRecoveryInput = it },
                                label = { Text("Резервный код (с уже настроенного устройства)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }

                        Button(
                            onClick = {
                                if (!TotpManager.verifyCode(secret, codeInput)) {
                                    message = "Неверный код"
                                    isError = true
                                } else if (needsReenrollRecovery && reenrollRecoveryInput.isBlank()) {
                                    message = "Введите резервный код, чтобы заменить существующий секрет"
                                    isError = true
                                } else if (!WebSocketClient.connected.value) {
                                    message = "Нет соединения с сервером"
                                    isError = true
                                } else {
                                    // Enabled locally first so register()'s totp_code
                                    // inclusion has the secret ready — rolled back in
                                    // onTotpSetupResult on refusal, and by the timeout
                                    // below if the server never answers at all (found
                                    // live on Android: without this, a dead connection
                                    // left the client thinking TOTP was enabled while
                                    // the server never got the secret).
                                    TotpManager.enable(secret)
                                    busy = true
                                    WebSocketClient.sendTotpSetup(
                                        secret, codeInput,
                                        recoveryCode = if (needsReenrollRecovery) reenrollRecoveryInput else null
                                    )
                                    scope.launch {
                                        delay(15_000)
                                        if (busy) {
                                            TotpManager.disable()
                                            busy = false
                                            enabled = false
                                            message = "Сервер не ответил вовремя — попробуйте ещё раз"
                                            isError = true
                                        }
                                    }
                                }
                            },
                            enabled = !busy && codeInput.isNotBlank() && (!needsReenrollRecovery || reenrollRecoveryInput.isNotBlank()),
                            colors = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Подтвердить и включить", color = Color.White)
                        }
                        if (busy) BusyRow()
                    }
                }
            }

            if (message.isNotEmpty()) {
                Text(
                    message,
                    fontSize = 14.sp,
                    color = if (isError) SubrosaTheme.error else Color(0xFF66BB6A)
                )
            }
        }
    }
}

@Composable
private fun BusyRow() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = SubrosaTheme.accent)
        Spacer(Modifier.width(8.dp))
        Text("Подтверждаем с сервером — подождите...", fontSize = 14.sp, color = SubrosaTheme.textPrimary.copy(alpha = 0.7f))
    }
}
