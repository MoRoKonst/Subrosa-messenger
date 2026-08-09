package com.subrosa.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.subrosa.messenger.ui.theme.LocalSubrosaColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TotpSettingsScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

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

    DisposableEffect(messengerService) {
        val svc = messengerService
        svc?.onTotpSetupResult = { success, reason ->
            busy = false
            if (success) {
                enabled = true
                pendingSecret = null
                codeInput = ""
                message = s.totpEnabledSuccess
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
                title = { Text(s.totpTitle, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = s.back)
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
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    s.totpDescription,
                    fontSize = 13.sp,
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
                            OutlinedTextField(
                                value = disableCodeInput,
                                onValueChange = { disableCodeInput = it },
                                label = { Text(s.totpCodeLabel) },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
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
                                    }
                                },
                                enabled = !busy && disableCodeInput.isNotBlank(),
                                colors = ButtonDefaults.buttonColors(containerColor = c.dangerCard)
                            ) {
                                Text(s.totpDisableButton, color = c.textPrimary)
                            }
                        } else if (pendingSecret == null) {
                            Button(
                                onClick = { pendingSecret = TotpManager.generateSecret() },
                                colors = ButtonDefaults.buttonColors(containerColor = c.accent)
                            ) {
                                Text(s.totpSetupButton, color = Color.White)
                            }
                        } else {
                            val secret = pendingSecret!!
                            SelectionContainer {
                                Text(secret, fontSize = 16.sp, color = c.textPrimary, fontWeight = FontWeight.Bold)
                            }
                            SelectionContainer {
                                Text(
                                    TotpManager.otpAuthUri(secret, UserStorage.getUserId(context)),
                                    fontSize = 11.sp,
                                    color = c.textPrimary.copy(alpha = 0.5f)
                                )
                            }
                            Text(s.totpSecretLabel, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f))

                            OutlinedTextField(
                                value = codeInput,
                                onValueChange = { codeInput = it },
                                label = { Text(s.totpCodeLabel) },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )

                            Button(
                                onClick = {
                                    val svc = messengerService
                                    if (!TotpManager.verifyCode(secret, codeInput)) {
                                        message = s.totpErrInvalidCode
                                        isError = true
                                    } else if (svc == null || !svc.isOnline()) {
                                        message = s.serverTotpErrNotConnected
                                        isError = true
                                    } else {
                                        // Enabled locally first so register()'s
                                        // totp_code inclusion and the server
                                        // round-trip use the same secret — rolled
                                        // back above if the server refuses it.
                                        TotpManager.enable(context, secret)
                                        busy = true
                                        svc.sendTotpSetup(secret, codeInput)
                                    }
                                },
                                enabled = !busy && codeInput.isNotBlank(),
                                colors = ButtonDefaults.buttonColors(containerColor = c.accent),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(s.totpConfirmButton, color = Color.White)
                            }
                        }

                        if (message.isNotEmpty()) {
                            Text(
                                message,
                                color = if (isError) c.error else Color(0xFF66BB6A),
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }
        }
    }
}
