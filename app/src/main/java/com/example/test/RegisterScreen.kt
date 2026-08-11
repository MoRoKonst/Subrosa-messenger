package com.subrosa.messenger

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
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

private val AppFont = FontFamily(Font(R.font.jetbrainsmono_regular))

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

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            try {
                val content = context.contentResolver.openInputStream(uri)
                    ?.bufferedReader()?.readText() ?: ""
                val result = BackupManager.importBackup(context, content, importPassword)
                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        showImportDialog = false
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
                fontSize = 13.sp,
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
            Text("💬", fontSize = 64.sp, modifier = Modifier.padding(bottom = 16.dp))

            Text(
                s.registerTitle,
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = c.accent,
                fontFamily = AppFont,
                modifier = Modifier.padding(bottom = 8.dp)
            )

            Text(
                s.registerSubtitle,
                fontSize = 15.sp,
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
                enabled = !isGeneratingKeys,
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                colors = fieldColors
            )

            if (error.isNotEmpty()) {
                Text(
                    text = error,
                    color = c.error,
                    fontSize = 13.sp,
                    fontFamily = AppFont,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
            }

            if (isGeneratingKeys) {
                CircularProgressIndicator(modifier = Modifier.padding(16.dp), color = c.accent)
                Text(s.registerGeneratingKeys, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
            }

            Button(
                onClick = {
                    when {
                        username.isBlank() -> error = s.registerErrorEnterUsername
                        password.length < 6 -> error = s.registerErrorPasswordLength
                        password != passwordRepeat -> error = s.registerErrorPasswordMatch
                        else -> {
                            isGeneratingKeys = true
                            error = ""
                            scope.launch(Dispatchers.IO) {
                                try {
                                    CryptoManager.generateKeyPair()
                                    UserStorage.register(context, username.trim(), password)

                                    if (!StorageKeyManager.isSetup(context)) {
                                        StorageKeyManager.setup(context, password)
                                    }
                                    val publicKey = CryptoManager.getPublicKey()
                                    val privateKey = CryptoManager.getPrivateKeyPublic()
                                    val inviteCode = InviteCodeManager.generateInviteCode(
                                        publicKey, privateKey, username.trim(),
                                        AnonTokenManager.getOrCreateMyPersistentMailboxTag(context)
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
                Text(s.registerButton, fontSize = 16.sp, fontFamily = AppFont, color = Color.White)
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedButton(
                onClick = { showImportDialog = true },
                modifier = Modifier.fillMaxWidth().height(50.dp),
                enabled = !isGeneratingKeys,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = c.accent),
                border = androidx.compose.foundation.BorderStroke(1.dp, c.accent)
            ) {
                Text(s.registerImportBackup, fontSize = 15.sp, fontFamily = AppFont)
            }
        }
    }

    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = { showImportDialog = false; importPassword = ""; importError = "" },
            containerColor = c.dialog,
            title = { Text(s.registerImportTitle, color = Color.White, fontFamily = AppFont) },
            text = {
                Column {
                    Text(
                        s.registerImportHint,
                        fontSize = 12.sp,
                        color = c.textPrimary.copy(alpha = 0.6f),
                        fontFamily = AppFont,
                        modifier = Modifier.padding(bottom = 12.dp)
                    )
                    OutlinedTextField(
                        value = importPassword,
                        onValueChange = { importPassword = it },
                        label = { Text(s.registerImportPassword, fontFamily = AppFont) },
                        visualTransformation = PasswordVisualTransformation(),
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
                        Text(importError, color = c.error, fontSize = 12.sp, fontFamily = AppFont, modifier = Modifier.padding(top = 8.dp))
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (importPassword.isEmpty()) { importError = s.backupErrEnterPassword; return@TextButton }
                    importLauncher.launch(arrayOf("*/*"))
                }) { Text(s.registerImportChooseFile, color = c.accent, fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showImportDialog = false; importPassword = ""; importError = "" }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }
}
