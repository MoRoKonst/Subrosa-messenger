package com.subrosa.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** Desktop port of Android's BackupScreen.kt — a full screen (not a compact
 *  dialog like Desktop had before) with export and import both visible at
 *  once, plus the same "Backup security" warning card. Desktop has no
 *  share-sheet concept, so unlike Android's two export buttons (share /
 *  save-to-files) there's just one (save to a chosen file). */
@Composable
fun BackupScreen(onBack: () -> Unit) {
    var password        by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var status           by remember { mutableStateOf("") }
    var isError          by remember { mutableStateOf(false) }
    var busy             by remember { mutableStateOf(false) }
    var totpSecretInput   by remember { mutableStateOf("") }
    var totpCodeInput     by remember { mutableStateOf("") }
    var totpRecoveryCodeInput by remember { mutableStateOf("") }
    var showImportWipeWarning by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(Modifier.fillMaxSize()) {
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(AppIcons.get("BACK_ARROW"), contentDescription = "Назад", tint = SubrosaTheme.textPrimary)
                }
                Text("Резервное копирование", fontSize = 19.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    color = SubrosaTheme.textPrimary)
            }
        }

        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
        ) {
            Text(
                "Создайте резервную копию контактов, групп и истории сообщений",
                fontSize = 16.sp,
                color = SubrosaTheme.textSecondary
            )

            Spacer(Modifier.height(16.dp))

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = SubrosaTheme.dangerCard,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text("Безопасность бэкапа", fontSize = 16.sp, color = Color(0xFFFF9800))
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Бэкап содержит все ключи и переписку. Защищён паролем, а импорт дополнительно " +
                        "требует TOTP-секрет и текущий код — одного файла и пароля к нему недостаточно, " +
                        "чтобы восстановить identity. Но если у злоумышленника окажутся файл, пароль и " +
                        "TOTP-секрет вместе, аккаунт будет скомпрометирован — относитесь к бэкапу серьёзно.",
                        fontSize = 14.sp,
                        color = SubrosaTheme.textPrimary.copy(alpha = 0.85f)
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "• Используйте надёжный пароль (12+ символов)\n" +
                        "• Не храните файл, пароль и TOTP-секрет в одном месте\n" +
                        "• Храните на зашифрованном диске или в password manager",
                        fontSize = 14.sp,
                        color = SubrosaTheme.textSecondary
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            SecureTextField(
                value = password,
                onValueChange = { password = it; status = "" },
                label = "Пароль для бэкапа",
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            SecureTextField(
                value = confirmPassword,
                onValueChange = { confirmPassword = it; status = "" },
                label = "Повторите пароль",
                modifier = Modifier.fillMaxWidth(),
                isError = confirmPassword.isNotEmpty() && confirmPassword != password
            )
            if (password.isNotEmpty() && password.length >= PasswordPolicy.MIN_LENGTH &&
                PasswordPolicy.isCommonPassword(password)) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "Этот пароль слишком предсказуем (например, простая последовательность цифр) — выберите менее очевидный",
                    fontSize = 13.sp, color = SubrosaTheme.error
                )
            }

            Spacer(Modifier.height(16.dp))

            Button(
                onClick = {
                    when {
                        !TotpManager.isEnabled() -> {
                            status = "Сначала включите TOTP-защиту (Профиль → Двухфакторная защита) — без неё файл бэкапа и пароль дают полный доступ к identity, второго фактора нет"
                            isError = true
                        }
                        password.isEmpty() -> { status = "Введите пароль"; isError = true }
                        password != confirmPassword -> { status = "Пароли не совпадают"; isError = true }
                        password.length < PasswordPolicy.MIN_LENGTH -> {
                            status = "Пароль минимум ${PasswordPolicy.MIN_LENGTH} символов"; isError = true
                        }
                        PasswordPolicy.isCommonPassword(password) -> {
                            status = "Этот пароль слишком предсказуем — выберите менее очевидный"; isError = true
                        }
                        else -> {
                            val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Сохранить бэкап", java.awt.FileDialog.SAVE)
                            dialog.file = BackupManager.getBackupFileName()
                            dialog.isVisible = true
                            val fileName = dialog.file
                            val dir      = dialog.directory
                            if (fileName != null && dir != null) {
                                busy = true
                                status = "Экспорт…"
                                isError = false
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val encoded = BackupManager.exportBackup(password)
                                        java.io.File(dir, fileName).writeText(encoded)
                                        status = "Бэкап сохранён"
                                        password = ""; confirmPassword = ""
                                    } catch (e: Exception) {
                                        status = "Ошибка: ${e.message}"
                                        isError = true
                                    } finally {
                                        busy = false
                                    }
                                }
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                colors = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.topBar)
            ) {
                Text(if (busy) "…" else "Экспорт", color = Color.White, fontSize = 15.sp)
            }

            Spacer(Modifier.height(24.dp))
            HorizontalDivider(color = SubrosaTheme.divider)
            Spacer(Modifier.height(16.dp))

            SecureTextField(
                value = totpSecretInput,
                onValueChange = { totpSecretInput = it; status = "" },
                label = "TOTP-секрет (если был включён на исходном устройстве)",
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            SecureTextField(
                value = totpCodeInput,
                onValueChange = { totpCodeInput = it; status = "" },
                label = "Текущий TOTP-код",
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            Text("или", fontSize = 14.sp, color = SubrosaTheme.textSecondary.copy(alpha = 0.7f))
            Spacer(Modifier.height(4.dp))
            SecureTextField(
                value = totpRecoveryCodeInput,
                onValueChange = { totpRecoveryCodeInput = it; status = "" },
                label = "Резервный код (из тех, что показывались при включении TOTP)",
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    if (password.isEmpty()) { status = "Введите пароль от бэкапа"; isError = true }
                    else showImportWipeWarning = true
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = SubrosaTheme.accent),
                border = androidx.compose.foundation.BorderStroke(1.dp, SubrosaTheme.accent)
            ) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = SubrosaTheme.accent, strokeWidth = 2.dp)
                } else {
                    Text("Импорт")
                }
            }

            if (status.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                Text(
                    status,
                    color = if (isError) SubrosaTheme.error else Color(0xFF27AE60),
                    fontSize = 16.sp
                )
            }
        }
    }

    if (showImportWipeWarning) {
        AlertDialog(
            onDismissRequest = { showImportWipeWarning = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Импорт заменит текущие данные", color = SubrosaTheme.textPrimary) },
            text = {
                Text(
                    "Импорт полностью заменит данные этого устройства новой identity из бэкапа: " +
                    "текущие контакты, сообщения и группы будут безвозвратно удалены. Это не откат " +
                    "к старой истории переписки.",
                    color = SubrosaTheme.textSecondary
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showImportWipeWarning = false
                    val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Открыть бэкап", java.awt.FileDialog.LOAD)
                    dialog.isVisible = true
                    val fileName = dialog.file
                    val dir      = dialog.directory
                    if (fileName != null && dir != null) {
                        busy = true
                        status = "Импорт…"
                        isError = false
                        scope.launch(Dispatchers.IO) {
                            try {
                                val encoded = java.io.File(dir, fileName).readText()
                                val result = BackupManager.importBackup(encoded, password, totpSecretInput, totpCodeInput, totpRecoveryCodeInput)
                                if (result.isSuccess) {
                                    status = result.getOrNull() ?: "Готово"
                                    isError = false
                                } else {
                                    status = "Ошибка: ${result.exceptionOrNull()?.message}"
                                    isError = true
                                }
                            } catch (e: Exception) {
                                status = "Ошибка: ${e.message}"
                                isError = true
                            } finally {
                                busy = false
                            }
                        }
                    }
                }) {
                    Text("Импортировать", color = SubrosaTheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showImportWipeWarning = false }) {
                    Text("Отмена", color = SubrosaTheme.textSecondary)
                }
            }
        )
    }
}
