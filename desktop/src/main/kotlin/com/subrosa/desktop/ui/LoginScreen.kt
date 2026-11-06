package com.subrosa.desktop

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun LoginScreen(
    onLoggedIn: () -> Unit,
    onRegister: () -> Unit,
    onPanicMode: () -> Unit = {}
) {
    var password by remember { mutableStateOf("") }
    var error    by remember { mutableStateOf("") }

    val displayName = UserStorage.getUsername()
    val myId        = WebSocketClient.myFingerprint  // 16-char hex fingerprint

    Box(modifier = Modifier.fillMaxSize()) {
        Box(modifier = Modifier.align(Alignment.TopEnd).padding(8.dp)) {
            ServerSettingsButton()
        }
    Column(
        modifier = Modifier.fillMaxSize().padding(48.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Subrosa", fontSize = 30.sp, color = MaterialTheme.colorScheme.primary, fontFamily = NotoSerifJP)
        Spacer(Modifier.height(8.dp))
        Text(displayName, fontSize = 18.sp, color = MaterialTheme.colorScheme.onBackground, fontFamily = NotoSerifJP)
        Spacer(Modifier.height(4.dp))
        // Show fingerprint so the user can share it with contacts
        Text(
            text  = "ID: $myId",
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.5f)
        )
        Spacer(Modifier.height(32.dp))

        SecureTextField(
            value         = password,
            onValueChange = { password = it; error = "" },
            label         = "Пароль",
            modifier      = Modifier.width(320.dp)
        )
        if (error.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(error, color = MaterialTheme.colorScheme.error, fontSize = 14.sp)
        }
        Spacer(Modifier.height(16.dp))

        Button(onClick = {
            when {
                password.isBlank() -> error = "Введите пароль"
                // Panic password — mirrors Android's LoginScreen exactly:
                // checked BEFORE the real password, triggers decoy mode +
                // a background wipe (EmergencyWipe.wipeForDecoyKeepAlive)
                // instead of a normal login.
                UserStorage.isPanicPassword(password) -> onPanicMode()
                !UserStorage.checkPassword(password)  -> error = "Неверный пароль"
                // Real password still "works" after a previous panic wipe —
                // its hash was deliberately preserved for this — but now
                // always lands on the decoy screen, never the real one.
                UserStorage.isDecoyMode() -> onPanicMode()
                else -> {
                    // Разблокировать SMK: быстро через keystore, иначе через пароль
                    if (!StorageKeyManager.unlockWithKeystore()) {
                        StorageKeyManager.unlockWithPassword(password)
                    }
                    WebSocketClient.connect(displayName)
                    onLoggedIn()
                }
            }
        }, modifier = Modifier.width(320.dp)) {
            Text("Войти")
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onRegister) {
            Text("Создать аккаунт")
        }
    }
    }
}
