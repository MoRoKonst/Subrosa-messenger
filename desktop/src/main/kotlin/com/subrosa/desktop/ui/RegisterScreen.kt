package com.subrosa.desktop

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

@Composable
fun RegisterScreen(onRegistered: () -> Unit) {
    var username        by remember { mutableStateOf("") }
    var password        by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var error           by remember { mutableStateOf("") }
    var busy            by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Box(modifier = Modifier.fillMaxSize()) {
        Box(modifier = Modifier.align(Alignment.TopEnd).padding(8.dp)) {
            ServerSettingsButton()
        }
    Column(
        modifier = Modifier.fillMaxSize().padding(48.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Subrosa", fontSize = 30.sp, color = SubrosaTheme.accent, fontFamily = NotoSerifJP)
        Spacer(Modifier.height(4.dp))
        Text("Создание аккаунта", fontSize = 15.sp, color = SubrosaTheme.textSecondary)
        Spacer(Modifier.height(32.dp))

        OutlinedTextField(
            value         = username,
            onValueChange = { username = it; error = "" },
            label         = { Text("Имя пользователя") },
            modifier      = Modifier.width(320.dp),
            singleLine    = true,
            colors        = profileFieldColors()
        )
        Spacer(Modifier.height(8.dp))
        SecureTextField(
            value                = password,
            onValueChange        = { password = it; error = "" },
            label                = "Пароль",
            modifier             = Modifier.width(320.dp)
        )
        Spacer(Modifier.height(8.dp))
        SecureTextField(
            value                = confirmPassword,
            onValueChange        = { confirmPassword = it; error = "" },
            label                = "Повторите пароль",
            modifier             = Modifier.width(320.dp),
            isError              = confirmPassword.isNotEmpty() && confirmPassword != password
        )

        if (error.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(error, color = SubrosaTheme.error, fontSize = 14.sp)
        }
        Spacer(Modifier.height(20.dp))

        Button(
            enabled = !busy,
            onClick = {
                when {
                    username.isBlank()                       -> error = "Введите имя пользователя"
                    password.length < PasswordPolicy.MIN_LENGTH -> error = "Пароль минимум ${PasswordPolicy.MIN_LENGTH} символов"
                    PasswordPolicy.isCommonPassword(password)   -> error = "Этот пароль слишком предсказуем (например, простая последовательность цифр) — выберите менее очевидный"
                    confirmPassword != password              -> error = "Пароли не совпадают"
                    else -> {
                        // A brand-new local account needs a brand-new identity
                        // keypair (and therefore server fingerprint) — reusing
                        // whatever was already in the PKCS12 keystore file
                        // meant every "create new account" on the same
                        // machine profile was actually a reconnect to the
                        // SAME server identity, with whatever TOTP/device
                        // pinning state the server already had on file for
                        // it. Mirrors Android's RegisterScreen.kt
                        // CryptoManager.generateKeyPair()/TotpManager.
                        // disable()/SenderCertManager.clear() sequence
                        // (found live, 2026-09-12: device_auth_failed on a
                        // second local "registration" attempt).
                        DesktopCryptoManager.regenerateKeyPair()
                        TotpManager.disable()
                        SenderCertManager.clear()
                        // A new identity keypair means a new fingerprint —
                        // any chat history/contacts/sessions/anon-routing
                        // state still sitting in local storage belongs to
                        // the PREVIOUS local identity, not this one, and
                        // would otherwise show up as this "new" account's
                        // own chats. Found live, 2026-09-12.
                        BackupManager.wipeCurrentIdentityData()
                        UserStorage.register(username.trim(), password)
                        StorageKeyManager.setup(password)   // активировать SMK
                        WebSocketClient.connect(username.trim())
                        // Wait for the server to actually confirm registration
                        // instead of assuming success — a PoW-gated or access-
                        // restricted server can reject it entirely, and
                        // proceeding to the TOTP screen regardless left the
                        // user stuck trying to set up TOTP for an account that
                        // was never actually created server-side.
                        busy = true
                        error = ""
                        scope.launch {
                            val ok = WebSocketClient.awaitRegistration()
                            busy = false
                            if (ok) {
                                onRegistered()
                            } else {
                                error = "Сервер не подтвердил регистрацию — проверьте адрес сервера/код доступа и повторите"
                            }
                        }
                    }
                }
            },
            modifier = Modifier.width(320.dp),
            colors   = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent)
        ) {
            Text(if (busy) "Регистрируем…" else "Зарегистрироваться")
        }
    }
    }
}

@Composable
internal fun profileFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor   = SubrosaTheme.fieldBorder,
    unfocusedBorderColor = SubrosaTheme.divider,
    focusedTextColor     = SubrosaTheme.textPrimary,
    unfocusedTextColor   = SubrosaTheme.textPrimary,
    cursorColor          = SubrosaTheme.accent,
    focusedLabelColor    = SubrosaTheme.accent,
    unfocusedLabelColor  = SubrosaTheme.textSecondary
)
