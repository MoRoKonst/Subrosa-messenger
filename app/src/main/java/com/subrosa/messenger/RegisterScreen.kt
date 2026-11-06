package com.subrosa.messenger

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import com.subrosa.messenger.ui.theme.Inter

// App-wide font swap 2026-09-22 — name kept for API stability.
private val AppFont = Inter

@Composable
fun RegisterScreen(onRegistered: () -> Unit, context: android.content.Context) {
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordRepeat by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var isGeneratingKeys by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    var showImportDialog by remember { mutableStateOf(false) }
    var importPassword by remember { mutableStateOf("") }
    var importError by remember { mutableStateOf("") }
    // Found live 2026-08-30, alongside the StorageKeyManager/UserStorage
    // onboarding-restore fix in BackupManager.importBackup(): this dialog
    // only ever collected the backup's decryption password, never the TOTP
    // secret/code/recovery-code that importBackup() also requires whenever
    // the backup has TOTP enabled (true for effectively every backup since
    // TOTP became mandatory 2026-08-10) — BackupScreen.kt's own import flow
    // already has these three fields, this dialog just never got them.
    // Without them, restoring from onboarding always failed with "Этот
    // бэкап защищён TOTP — введите секрет и текущий код" and nowhere to
    // actually enter either.
    var importTotpSecret by remember { mutableStateOf("") }
    var importTotpCode by remember { mutableStateOf("") }
    var importTotpRecoveryCode by remember { mutableStateOf("") }
    // File is picked FIRST, dialog (password/TOTP) shown only after — reading
    // it up front means the dialog can fail fast on "wrong/corrupt file" before
    // the user's bothered typing a password, and there's nothing left to pick
    // by the time the confirm button runs, so it can call importBackup()
    // directly instead of re-launching the picker.
    var importedFileContent by remember { mutableStateOf<String?>(null) }
    var importPickError by remember { mutableStateOf("") }

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            try {
                val content = context.contentResolver.openInputStream(uri)
                    ?.bufferedReader()?.readText() ?: ""
                withContext(Dispatchers.Main) {
                    importedFileContent = content
                    importPickError = ""
                    showImportDialog = true
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    importPickError = s.error(e.message ?: "")
                }
            }
        }
    }

    fun runImport() {
        val content = importedFileContent ?: return
        scope.launch(Dispatchers.IO) {
            try {
                val result = BackupManager.importBackup(
                    context, content, importPassword,
                    importTotpSecret.ifBlank { null },
                    importTotpCode.ifBlank { null },
                    importTotpRecoveryCode.ifBlank { null }
                )
                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        showImportDialog = false
                        // Found live 2026-08-31, same class of bug already fixed in
                        // BackupScreen.kt's import flow (see its comment): if a
                        // MessengerService instance is somehow already running at
                        // this point (e.g. resurrected by the OS via START_STICKY,
                        // or a leftover from a bootstrap/deep-link intent fired
                        // while this dialog was still open), its onStartCommand()
                        // computes `username` from CryptoManager.getPublicKeyString()
                        // independently of importBackup() — and getSoftwareKeyPair()
                        // silently *generates and persists a brand-new random EC
                        // keypair* if it ran before this restore wrote the real one,
                        // immediately overwriting UserStorage's userId with that
                        // throwaway fingerprint. importBackup() then correctly
                        // overwrites the key material on disk, but an
                        // already-running service instance keeps its own
                        // already-computed (wrong) `username` in memory until
                        // restarted, and registers/reconnects under it forever.
                        // Force a full stop+restart so onRegistered()'s own
                        // startForegroundService() below is guaranteed to be the
                        // one that actually determines this run's identity, reading
                        // it fresh off disk after the restore completed.
                        context.stopService(Intent(context, MessengerService::class.java))
                        onRegistered()
                    } else {
                        importError = s.error(result.exceptionOrNull()?.message ?: "")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    importError = s.error(e.message ?: "")
                }
            }
        }
    }

    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = c.accent,
        unfocusedBorderColor = c.fieldBorder,
        focusedLabelColor = c.accent,
        unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
        focusedTextColor = c.textPrimary,
        unfocusedTextColor = c.textPrimary,
        disabledTextColor = c.textPrimary.copy(alpha = 0.6f),
        disabledBorderColor = c.fieldBorder,
        disabledLabelColor = c.textPrimary.copy(alpha = 0.6f),
        cursorColor = c.accent
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(bgGradient)
    ) {
        Row(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(top = 16.dp, end = 16.dp)
                .background(c.card, RoundedCornerShape(8.dp))
                .clickable {
                    val newLang = if (s.langCode == "ru") "en" else "ru"
                    UserStorage.setLanguage(context, newLang)
                    MainActivity.currentLanguage.value = newLang
                }
                .padding(horizontal = 12.dp, vertical = 6.dp)
        ) {
            Text(
                text = if (s.langCode == "ru") "EN" else "RU",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = c.accent,
                fontFamily = AppFont
            )
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                s.registerTitle,
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold,
                color = c.accent,
                fontFamily = AppFont,
                modifier = Modifier.padding(bottom = 24.dp)
            )

            Text(
                s.registerSubtitle,
                fontSize = 17.sp,
                color = c.textPrimary.copy(alpha = 0.6f),
                fontFamily = AppFont,
                modifier = Modifier.padding(bottom = 32.dp)
            )

            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text(s.registerUsername, fontFamily = AppFont) },
                placeholder = { Text(s.registerUsernamePlaceholder, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont) },
                singleLine = true,
                enabled = !isGeneratingKeys,
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                colors = fieldColors
            )

            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(s.registerPassword, fontFamily = AppFont) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                ),
                enabled = !isGeneratingKeys,
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                colors = fieldColors
            )

            OutlinedTextField(
                value = passwordRepeat,
                onValueChange = { passwordRepeat = it },
                label = { Text(s.registerRepeatPassword, fontFamily = AppFont) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                ),
                enabled = !isGeneratingKeys,
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                colors = fieldColors
            )

            if (error.isNotEmpty()) {
                Text(
                    text = error,
                    color = c.error,
                    fontSize = 15.sp,
                    fontFamily = AppFont,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
            }

            if (isGeneratingKeys) {
                CircularProgressIndicator(modifier = Modifier.padding(16.dp), color = c.accent)
                Text(s.registerGeneratingKeys, fontSize = 16.sp, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
            }

            Button(
                onClick = {
                    when {
                        username.isBlank() -> error = s.registerErrorEnterUsername
                        password.length < PasswordPolicy.MIN_LENGTH -> error = s.registerErrorPasswordLength
                        PasswordPolicy.isCommonPassword(password) -> error = s.registerErrorPasswordCommon
                        password != passwordRepeat -> error = s.registerErrorPasswordMatch
                        else -> {
                            isGeneratingKeys = true
                            error = ""
                            scope.launch(Dispatchers.IO) {
                                try {
                                    CryptoManager.generateKeyPair()
                                    // A TOTP secret is bound to a specific identity — the server
                                    // only checks it on register() for the account it was set up
                                    // under. Any local flag/secret from before this point belongs
                                    // to a different identity by definition (a brand-new keypair
                                    // was just generated above), yet a device backup that survives
                                    // a full uninstall+reinstall outside the app's control (found
                                    // live: MIUI's own OS-level backup, independent of
                                    // android:allowBackup="false") can leave it looking "already
                                    // enabled". The mandatory TOTP screen that follows registration
                                    // then renders its disable/manage flow instead of fresh setup —
                                    // a genuine deadlock, since a code for the old secret means
                                    // nothing to the new account server-side. Reset unconditionally
                                    // so a fresh identity always gets a fresh setup prompt.
                                    TotpManager.disable(context)
                                    // Same identity-scoped leftover problem as the TOTP reset
                                    // right above, for the cached sealed-sender cert (see
                                    // BackupManager.wipeCurrentIdentityData()'s matching fix) —
                                    // a fresh keypair was just generated, so any cert cached from
                                    // before belongs to a fingerprint this device no longer has.
                                    SenderCertManager.clear(context)
                                    UserStorage.register(context, username.trim(), password)

                                    if (!StorageKeyManager.isSetup(context)) {
                                        StorageKeyManager.setup(context, password)
                                    }
                                    val publicKey = CryptoManager.getPublicKey()
                                    val privateKey = CryptoManager.getPrivateKeyPublic()
                                    val inviteCode = InviteCodeManager.generateInviteCode(
                                        publicKey, privateKey, username.trim(),
                                        AnonTokenManager.getOrCreateMyInviteMailboxTag(context)
                                    )
                                    UserStorage.saveInviteCode(context, inviteCode)
                                    withContext(Dispatchers.Main) {
                                        isGeneratingKeys = false
                                        onRegistered()
                                    }
                                } catch (e: Exception) {
                                    withContext(Dispatchers.Main) {
                                        error = s.error(e.message ?: "")
                                        isGeneratingKeys = false
                                    }
                                }
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().height(50.dp),
                enabled = !isGeneratingKeys,
                colors = ButtonDefaults.buttonColors(containerColor = c.dialog)
            ) {
                Text(s.registerButton, fontSize = 18.sp, fontFamily = AppFont, color = c.textPrimary)
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedButton(
                onClick = { importLauncher.launch(arrayOf("*/*")) },
                modifier = Modifier.fillMaxWidth().height(50.dp),
                enabled = !isGeneratingKeys,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = c.accent),
                border = androidx.compose.foundation.BorderStroke(1.dp, c.accent)
            ) {
                Text(s.registerImportBackup, fontSize = 17.sp, fontFamily = AppFont)
            }
            if (importPickError.isNotEmpty()) {
                Text(importPickError, color = c.error, fontSize = 14.sp, fontFamily = AppFont, modifier = Modifier.padding(top = 6.dp))
            }
        }
    }

    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = {
                showImportDialog = false; importPassword = ""; importError = ""
                importTotpSecret = ""; importTotpCode = ""; importTotpRecoveryCode = ""
                importedFileContent = null
            },
            containerColor = c.dialog,
            title = { Text(s.registerImportTitle, color = c.textPrimary, fontFamily = AppFont) },
            text = {
                Column(
                    modifier = Modifier
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(
                        s.registerImportHint,
                        fontSize = 14.sp,
                        color = c.textPrimary.copy(alpha = 0.6f),
                        fontFamily = AppFont,
                        modifier = Modifier.padding(bottom = 12.dp)
                    )
                    OutlinedTextField(
                        value = importPassword,
                        onValueChange = { importPassword = it },
                        label = { Text(s.registerImportPassword, fontFamily = AppFont) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                        ),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.fieldBorder,
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )

                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        s.registerImportTotpHint,
                        fontSize = 13.sp,
                        color = c.textPrimary.copy(alpha = 0.5f),
                        fontFamily = AppFont,
                        modifier = Modifier.padding(bottom = 6.dp)
                    )
                    OutlinedTextField(
                        value = importTotpSecret,
                        onValueChange = { importTotpSecret = it },
                        label = { Text(s.backupTotpSecretLabel, fontFamily = AppFont) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.fieldBorder,
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = importTotpCode,
                        onValueChange = { importTotpCode = it },
                        label = { Text(s.backupTotpCodeLabel, fontFamily = AppFont) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.fieldBorder,
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        s.backupTotpRecoveryOr,
                        fontSize = 14.sp,
                        color = c.textPrimary.copy(alpha = 0.5f),
                        fontFamily = AppFont
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    OutlinedTextField(
                        value = importTotpRecoveryCode,
                        onValueChange = { importTotpRecoveryCode = it },
                        label = { Text(s.backupTotpRecoveryLabel, fontFamily = AppFont) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.fieldBorder,
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )

                    if (importError.isNotEmpty()) {
                        Text(importError, color = c.error, fontSize = 14.sp, fontFamily = AppFont, modifier = Modifier.padding(top = 8.dp))
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (importPassword.isEmpty()) { importError = s.backupErrEnterPassword; return@TextButton }
                    runImport()
                }) { Text(s.registerImportChooseFile, color = c.accent, fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = {
                    showImportDialog = false; importPassword = ""; importError = ""
                    importTotpSecret = ""; importTotpCode = ""; importTotpRecoveryCode = ""
                    importedFileContent = null
                }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }
}
