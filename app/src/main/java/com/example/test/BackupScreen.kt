package com.bcon.messenger

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import java.io.File
import com.bcon.messenger.ui.theme.LocalBeaconColors

private val AppFont = FontFamily(Font(R.font.jetbrainsmono_regular))

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }
    var pendingBackupContent by remember { mutableStateOf<String?>(null) }

    val saveFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        val content = pendingBackupContent ?: return@rememberLauncherForActivityResult
        try {
            context.contentResolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) }
            message = s.backupCreated
            isError = false
            pendingBackupContent = null
            password = ""
            confirmPassword = ""
        } catch (e: Exception) {
            message = s.error(e.message ?: "")
            isError = true
        }
    }

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        try {
            val content = context.contentResolver.openInputStream(uri)
                ?.bufferedReader()?.readText() ?: ""
            val result = BackupManager.importBackup(context, content, password)
            if (result.isSuccess) {
                message = "✓ ${result.getOrNull()}"
                isError = false
                password = ""
                confirmPassword = ""
            } else {
                message = s.error(result.exceptionOrNull()?.message ?: "")
                isError = true
            }
        } catch (e: Exception) {
            message = s.error(e.message ?: "")
            isError = true
        }
    }

    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = c.accent,
        unfocusedBorderColor = c.fieldBorder,
        focusedLabelColor = c.accent,
        unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
        focusedTextColor = c.textPrimary,
        unfocusedTextColor = c.textPrimary,
        cursorColor = c.accent
    )

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = { Text(s.backupTitle, color = Color.White, fontFamily = AppFont) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, s.back, tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    s.backupSubtitle,
                    fontSize = 14.sp,
                    color = c.textPrimary.copy(alpha = 0.6f),
                    fontFamily = AppFont
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Предупреждение о безопасности бэкапа
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = c.dangerCard)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            s.backupSecurityTitle,
                            fontSize = 14.sp,
                            color = Color(0xFFFF9800),
                            fontFamily = AppFont
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            s.backupSecurityText,
                            fontSize = 12.sp,
                            color = c.textPrimary.copy(alpha = 0.85f),
                            fontFamily = AppFont
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            s.backupSecurityTips,
                            fontSize = 12.sp,
                            color = c.textPrimary.copy(alpha = 0.6f),
                            fontFamily = AppFont
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(s.backupPassword, fontFamily = AppFont) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = confirmPassword,
                    onValueChange = { confirmPassword = it },
                    label = { Text(s.backupRepeatPassword, fontFamily = AppFont) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(24.dp))

                fun validateAndExport(onSuccess: (String) -> Unit) {
                    when {
                        password.isEmpty() -> { message = s.backupErrEnterPassword; isError = true }
                        password != confirmPassword -> { message = s.backupErrPasswordMatch; isError = true }
                        password.length < 8 -> { message = s.backupErrPasswordLength; isError = true }
                        else -> try {
                            onSuccess(BackupManager.exportBackup(context, password))
                        } catch (e: Exception) {
                            message = s.error(e.message ?: ""); isError = true
                        }
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            validateAndExport { backup ->
                                val file = File(context.cacheDir, "messenger_backup_${System.currentTimeMillis()}.backup")
                                file.writeText(backup)
                                val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
                                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                    type = "application/octet-stream"
                                    putExtra(Intent.EXTRA_STREAM, uri)
                                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                }
                                context.startActivity(Intent.createChooser(shareIntent, s.backupSaveChooser))
                                message = s.backupCreated; isError = false
                                password = ""; confirmPassword = ""
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = c.topBar)
                    ) {
                        Text(s.backupExport, fontFamily = AppFont, color = Color.White, fontSize = 13.sp)
                    }
                    Button(
                        onClick = {
                            validateAndExport { backup ->
                                pendingBackupContent = backup
                                saveFileLauncher.launch(BackupManager.getBackupFileName())
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = c.topBar)
                    ) {
                        Text("В файлы", fontFamily = AppFont, color = Color.White, fontSize = 13.sp)
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedButton(
                    onClick = {
                        if (password.isEmpty()) { message = s.backupErrEnterForDecrypt; isError = true }
                        else importLauncher.launch(arrayOf("*/*"))
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = c.accent),
                    border = androidx.compose.foundation.BorderStroke(1.dp, c.accent)
                ) {
                    Text(s.backupImport, fontFamily = AppFont)
                }

                if (message.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        message,
                        color = if (isError) c.error else Color(0xFF27AE60),
                        fontSize = 14.sp,
                        fontFamily = AppFont
                    )
                }
            }
        }
    }

}
