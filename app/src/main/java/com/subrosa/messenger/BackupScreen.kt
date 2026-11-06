package com.subrosa.messenger

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.foundation.layout.size
import androidx.core.content.FileProvider
import java.io.File
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import com.subrosa.messenger.ui.theme.Inter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.ui.res.painterResource

// App-wide font swap 2026-09-22 — name kept for API stability.
private val AppFont = Inter

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupScreen(onBack: () -> Unit, onOpenArchive: () -> Unit = {}) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val scope = rememberCoroutineScope()
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var pendingBackupContent by remember { mutableStateOf<String?>(null) }
    var includeAttachments by remember { mutableStateOf(false) }
    var totpSecretInput by remember { mutableStateOf("") }
    var totpCodeInput by remember { mutableStateOf("") }
    var totpRecoveryCodeInput by remember { mutableStateOf("") }
    var showImportWipeWarning by remember { mutableStateOf(false) }

    val saveFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        val pwd = password
        val withAttachments = includeAttachments
        scope.launch {
            isLoading = true
            try {
                val stats = withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        BackupManager.exportToStream(context, pwd, withAttachments, out)
                    } ?: throw java.io.IOException("openOutputStream returned null")
                }
                message = if (stats.attachmentCount > 0) {
                    s.backupCreatedWithAttachments(
                        stats.attachmentCount,
                        formatBytes(stats.attachmentBytes),
                        stats.missingAttachments
                    )
                } else {
                    s.backupCreated
                }
                isError = false
                password = ""
                confirmPassword = ""
            } catch (e: Exception) {
                // A partially written file is worse than none: it looks like a
                // backup and fails at the moment it is needed. The export
                // cannot be rolled back through the ContentResolver reliably,
                // so say plainly that the file must not be trusted.
                message = s.backupExportFailed(e.message ?: e.javaClass.simpleName)
                isError = true
            } finally {
                isLoading = false
            }
        }
    }

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        val pwd = password
        scope.launch {
            isLoading = true
            try {
                val result = withContext(Dispatchers.IO) {
                    // Stream-based, and the source is a factory because the
                    // container version can only be told from the first bytes
                    // — see BackupManager.importFromStream. A version 8 file
                    // with attachments must never be slurped into a String
                    // first, which is what this replaced.
                    BackupManager.importFromStream(
                        context,
                        { context.contentResolver.openInputStream(uri)
                            ?: throw java.io.IOException("openInputStream returned null") },
                        pwd, totpSecretInput, totpCodeInput, totpRecoveryCodeInput
                    )
                }
                if (result.isSuccess) {
                    message = "${result.getOrNull()}"
                    isError = false
                    password = ""
                    confirmPassword = ""
                    totpSecretInput = ""
                    totpCodeInput = ""
                    totpRecoveryCodeInput = ""

                    // Import changes identity/keys on disk synchronously, but a
                    // MessengerService that's already running keeps its old
                    // cached username/session state until restarted — see
                    // docs/ISSUE_backup_identity_hijack.md, "восстановление
                    // бэкапа на втором активном устройстве". Force a full
                    // restart so onStartCommand recomputes everything from the
                    // now-current identity and reconnects/re-registers.
                    context.stopService(Intent(context, MessengerService::class.java))
                    context.startForegroundService(Intent(context, MessengerService::class.java))
                } else {
                    message = s.error(result.exceptionOrNull()?.message ?: "")
                    isError = true
                }
            } catch (e: Exception) {
                message = s.error(e.message ?: "")
                isError = true
            } finally {
                isLoading = false
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
        cursorColor = c.accent
    )

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = { Text(s.backupTitle, color = c.textPrimary, fontFamily = AppFont) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), s.back, tint = c.textPrimary)
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
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    s.backupSubtitle,
                    fontSize = 16.sp,
                    color = c.textPrimary.copy(alpha = 0.6f),
                    fontFamily = AppFont
                )

                Spacer(modifier = Modifier.height(16.dp))

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = c.dangerCard)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            s.backupSecurityTitle,
                            fontSize = 16.sp,
                            color = Color(0xFFFF9800),
                            fontFamily = AppFont
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            s.backupSecurityText,
                            fontSize = 14.sp,
                            color = c.textPrimary.copy(alpha = 0.85f),
                            fontFamily = AppFont
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            s.backupSecurityTips,
                            fontSize = 14.sp,
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
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                    ),
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
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Checked == version 8 (BackupContainer, streamed). Unchecked
                // == the unchanged version 7 string, which is the format the
                // Desktop client can read — stated in the label rather than
                // left for someone to discover mid-recovery.
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { includeAttachments = !includeAttachments },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = includeAttachments,
                        onCheckedChange = { includeAttachments = it },
                        colors = CheckboxDefaults.colors(checkedColor = c.accent)
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            s.backupIncludeAttachments,
                            fontSize = 15.sp,
                            color = c.textPrimary,
                            fontFamily = AppFont
                        )
                        Text(
                            if (includeAttachments) s.backupIncludeAttachmentsOn
                            else s.backupIncludeAttachmentsOff,
                            fontSize = 12.sp,
                            color = c.textPrimary.copy(alpha = 0.55f),
                            fontFamily = AppFont
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                /** Shared gate for both export buttons. Returns true if the export may proceed. */
                fun validateExport(): Boolean = when {
                    // TOTP was opt-in — an important protection left as a
                    // toggle nobody was pointed at. Export is the one
                    // moment that actually matters (it's what creates the
                    // file+password-only attack surface in the first
                    // place), so gate it here rather than at onboarding —
                    // no hard app-wide lockout risk if someone loses the
                    // secret later, since they simply can't create a new
                    // backup until they re-enable TOTP, existing backups
                    // are unaffected.
                    !TotpManager.isEnabled(context) -> { message = s.backupErrTotpRequired; isError = true; false }
                    password.isEmpty() -> { message = s.backupErrEnterPassword; isError = true; false }
                    password != confirmPassword -> { message = s.backupErrPasswordMatch; isError = true; false }
                    password.length < PasswordPolicy.MIN_LENGTH -> { message = s.backupErrPasswordLength; isError = true; false }
                    // Found live 2026-08-30, alongside the restore-from-onboarding fix
                    // (BackupManager.importBackup()): a weak/common backup password isn't
                    // just an offline-brute-force risk against the exported file — it now
                    // also becomes this device's actual local login password whenever the
                    // backup is restored on a fresh install, so the same strength floor
                    // RegisterScreen enforces for a normal password belongs here too. This
                    // check was missing entirely; only length was enforced.
                    PasswordPolicy.isCommonPassword(password) -> { message = s.registerErrorPasswordCommon; isError = true; false }
                    else -> true
                }

                fun launchExport(onSuccess: (String) -> Unit) {
                    when {
                        // TOTP was opt-in — an important protection left as a
                        // toggle nobody was pointed at. Export is the one
                        // moment that actually matters (it's what creates the
                        // file+password-only attack surface in the first
                        // place), so gate it here rather than at onboarding —
                        // no hard app-wide lockout risk if someone loses the
                        // secret later, since they simply can't create a new
                        // backup until they re-enable TOTP, existing backups
                        // are unaffected.
                        !TotpManager.isEnabled(context) -> { message = s.backupErrTotpRequired; isError = true }
                        password.isEmpty() -> { message = s.backupErrEnterPassword; isError = true }
                        password != confirmPassword -> { message = s.backupErrPasswordMatch; isError = true }
                        password.length < PasswordPolicy.MIN_LENGTH -> { message = s.backupErrPasswordLength; isError = true }
                        // Found live 2026-08-30, alongside the restore-from-onboarding fix
                        // (BackupManager.importBackup()): a weak/common backup password isn't
                        // just an offline-brute-force risk against the exported file — it now
                        // also becomes this device's actual local login password whenever the
                        // backup is restored on a fresh install, so the same strength floor
                        // RegisterScreen enforces for a normal password belongs here too. This
                        // check was missing entirely; only length was enforced.
                        PasswordPolicy.isCommonPassword(password) -> { message = s.registerErrorPasswordCommon; isError = true }
                        else -> {
                            val pwd = password
                            scope.launch {
                                isLoading = true
                                try {
                                    val backup = withContext(Dispatchers.IO) {
                                        BackupManager.exportBackup(context, pwd)
                                    }
                                    onSuccess(backup)
                                } catch (e: Exception) {
                                    message = s.error(e.message ?: ""); isError = true
                                } finally {
                                    isLoading = false
                                }
                            }
                        }
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            launchExport { backup ->
                                val file = File(context.cacheDir, "subrosa_backup_tmp.backup")
                                try {
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
                                } finally {
                                    file.delete()
                                }
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = c.topBar),
                        // Share goes through a FileProvider copy in the cache
                        // directory, which means the whole backup exists twice
                        // for the duration. Acceptable for a metadata-only
                        // file; not for one carrying gigabytes of video. With
                        // attachments on, the only offered route is the picker
                        // below, which streams straight into the destination.
                        enabled = !isLoading && !includeAttachments
                    ) {
                        Text(s.backupExport, fontFamily = AppFont, color = c.textPrimary, fontSize = 15.sp)
                    }
                    Button(
                        onClick = {
                            if (validateExport()) {
                                // Destination first, export second: with
                                // attachments the file is written as a stream,
                                // so the output URI has to exist before the
                                // export starts. The v7 path no longer builds
                                // its string up front either — one flow for
                                // both keeps the two from drifting.
                                message = ""
                                saveFileLauncher.launch(BackupManager.getBackupFileName())
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = c.topBar),
                        enabled = !isLoading
                    ) {
                        Text(s.backupToFiles, fontFamily = AppFont, color = c.textPrimary, fontSize = 15.sp)
                    }
                }
                if (includeAttachments) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        s.backupShareDisabledWithAttachments,
                        fontSize = 12.sp,
                        color = c.textPrimary.copy(alpha = 0.5f),
                        fontFamily = AppFont
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = totpSecretInput,
                    onValueChange = { totpSecretInput = it },
                    label = { Text(s.backupTotpSecretLabel, fontFamily = AppFont) },
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = totpCodeInput,
                    onValueChange = { totpCodeInput = it },
                    label = { Text(s.backupTotpCodeLabel, fontFamily = AppFont) },
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                    colors = fieldColors
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
                    value = totpRecoveryCodeInput,
                    onValueChange = { totpRecoveryCodeInput = it },
                    label = { Text(s.backupTotpRecoveryLabel, fontFamily = AppFont) },
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedButton(
                    onClick = {
                        if (password.isEmpty()) { message = s.backupErrEnterForDecrypt; isError = true }
                        else showImportWipeWarning = true
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isLoading,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = c.accent),
                    border = androidx.compose.foundation.BorderStroke(1.dp, c.accent)
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = c.accent, strokeWidth = 2.dp)
                    } else {
                        Text(s.backupImport, fontFamily = AppFont)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Sits directly under Import on purpose: this is the
                // non-destructive half of the same question ("what's in my
                // backup file?"), and someone who only wants to read an old
                // conversation should find it before they reach for the button
                // that replaces their identity.
                OutlinedButton(
                    onClick = onOpenArchive,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = c.textPrimary),
                    border = androidx.compose.foundation.BorderStroke(1.dp, c.fieldBorder)
                ) {
                    Text(s.archiveOpen, fontFamily = AppFont)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    s.archiveSubtitle,
                    fontSize = 12.sp,
                    color = c.textPrimary.copy(alpha = 0.5f),
                    fontFamily = AppFont
                )

                if (message.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        message,
                        color = if (isError) c.error else Color(0xFF27AE60),
                        fontSize = 16.sp,
                        fontFamily = AppFont
                    )
                }
            }
        }
    }

    if (showImportWipeWarning) {
        AlertDialog(
            onDismissRequest = { showImportWipeWarning = false },
            title = { Text(s.backupImportWipeTitle, fontFamily = AppFont) },
            text = { Text(s.backupImportWipeText, fontFamily = AppFont) },
            confirmButton = {
                TextButton(onClick = {
                    showImportWipeWarning = false
                    importLauncher.launch(arrayOf("*/*"))
                }) {
                    Text(s.backupImport, color = c.error, fontFamily = AppFont)
                }
            },
            dismissButton = {
                TextButton(onClick = { showImportWipeWarning = false }) {
                    Text(s.cancel, fontFamily = AppFont)
                }
            }
        )
    }
}
