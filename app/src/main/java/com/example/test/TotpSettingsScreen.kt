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

    var enabled by remember { mutableStateOf(TotpManager.isEnabled(context)) }
    var pendingSecret by remember { mutableStateOf<String?>(null) }
    var codeInput by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }

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
                            Button(
                                onClick = {
                                    TotpManager.disable(context)
                                    enabled = false
                                    pendingSecret = null
                                    codeInput = ""
                                    message = ""
                                },
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
                                    if (TotpManager.verifyCode(secret, codeInput)) {
                                        TotpManager.enable(context, secret)
                                        enabled = true
                                        pendingSecret = null
                                        codeInput = ""
                                        message = s.totpEnabledSuccess
                                        isError = false
                                    } else {
                                        message = s.totpErrInvalidCode
                                        isError = true
                                    }
                                },
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
