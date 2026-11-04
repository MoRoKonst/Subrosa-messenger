package com.subrosa.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusEvent
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.compose.ui.res.painterResource

@OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
fun ChangePasswordScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val scope = rememberCoroutineScope()
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    var currentPassword by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var newPasswordRepeat by remember { mutableStateOf("") }
    var totpCode by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var success by remember { mutableStateOf(false) }
    val totpEnabled = remember { TotpManager.isEnabled(context) }

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
        topBar = {
            TopAppBar(
                title = { Text(s.changePasswordTitle, fontWeight = FontWeight.Bold, fontSize = 20.sp) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), contentDescription = s.back)
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
        Box(Modifier.fillMaxSize().background(bgGradient)) {
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .imePadding()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    s.changePasswordDesc,
                    fontSize = 15.sp,
                    lineHeight = 18.sp,
                    color = c.textPrimary.copy(alpha = 0.75f)
                )

                if (success) {
                    Card(colors = CardDefaults.cardColors(containerColor = c.card), modifier = Modifier.fillMaxWidth()) {
                        Text(
                            s.changePasswordSuccess,
                            modifier = Modifier.padding(16.dp),
                            color = Color(0xFF66BB6A),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    return@Column
                }

                val currentBringIntoView = remember { BringIntoViewRequester() }
                OutlinedTextField(
                    value = currentPassword,
                    onValueChange = { currentPassword = it; error = "" },
                    label = { Text(s.changePasswordCurrent) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                    ),
                    textStyle = TextStyle(color = c.textPrimary),
                    colors = fieldColors,
                    modifier = Modifier
                        .fillMaxWidth()
                        .bringIntoViewRequester(currentBringIntoView)
                        .onFocusEvent {
                            // An immediate bringIntoView() targets the pre-keyboard
                            // viewport (field often already "fits" then), so it does
                            // nothing, and the IME covers the field once it finishes
                            // sliding up with no further trigger. Delaying past the
                            // IME's own show animation fixes this — same issue as
                            // TotpSettingsScreen.kt.
                            if (it.isFocused) scope.launch {
                                delay(300)
                                currentBringIntoView.bringIntoView()
                            }
                        }
                )

                val newBringIntoView = remember { BringIntoViewRequester() }
                OutlinedTextField(
                    value = newPassword,
                    onValueChange = { newPassword = it; error = "" },
                    label = { Text(s.changePasswordNew) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                    ),
                    textStyle = TextStyle(color = c.textPrimary),
                    colors = fieldColors,
                    modifier = Modifier
                        .fillMaxWidth()
                        .bringIntoViewRequester(newBringIntoView)
                        .onFocusEvent {
                            if (it.isFocused) scope.launch {
                                delay(300)
                                newBringIntoView.bringIntoView()
                            }
                        }
                )

                val repeatBringIntoView = remember { BringIntoViewRequester() }
                OutlinedTextField(
                    value = newPasswordRepeat,
                    onValueChange = { newPasswordRepeat = it; error = "" },
                    label = { Text(s.changePasswordRepeat) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                    ),
                    textStyle = TextStyle(color = c.textPrimary),
                    colors = fieldColors,
                    modifier = Modifier
                        .fillMaxWidth()
                        .bringIntoViewRequester(repeatBringIntoView)
                        .onFocusEvent {
                            if (it.isFocused) scope.launch {
                                delay(300)
                                repeatBringIntoView.bringIntoView()
                            }
                        }
                )

                if (totpEnabled) {
                    val totpBringIntoView = remember { BringIntoViewRequester() }
                    OutlinedTextField(
                        value = totpCode,
                        onValueChange = { totpCode = it; error = "" },
                        label = { Text(s.backupTotpCodeLabel) },
                        singleLine = true,
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Number
                        ),
                        textStyle = TextStyle(color = c.textPrimary),
                        colors = fieldColors,
                        modifier = Modifier
                            .fillMaxWidth()
                            .bringIntoViewRequester(totpBringIntoView)
                            .onFocusEvent {
                                if (it.isFocused) scope.launch {
                                    delay(300)
                                    totpBringIntoView.bringIntoView()
                                }
                            }
                    )
                }

                if (error.isNotEmpty()) {
                    Text(error, color = Color(0xFFEF5350), fontSize = 15.sp)
                }

                Button(
                    onClick = {
                        val totpSecret = if (totpEnabled) TotpManager.getSecret(context) else null
                        when {
                            !UserStorage.checkPassword(context, currentPassword) ->
                                error = s.changePasswordErrCurrentWrong
                            totpEnabled && (totpSecret == null || !TotpManager.verifyCode(totpSecret, totpCode)) ->
                                error = s.totpErrInvalidCode
                            newPassword.length < PasswordPolicy.MIN_LENGTH ->
                                error = s.registerErrorPasswordLength
                            PasswordPolicy.isCommonPassword(newPassword) ->
                                error = s.registerErrorPasswordCommon
                            newPassword != newPasswordRepeat ->
                                error = s.registerErrorPasswordMatch
                            newPassword == currentPassword ->
                                error = s.changePasswordErrSameAsOld
                            else -> {
                                try {
                                    // Both must change together: UserStorage's hash gates the
                                    // lock-screen check, StorageKeyManager's is the actual KDF
                                    // input for the Storage Master Key wrap. Falling out of sync
                                    // would mean the lock screen accepts a password that can no
                                    // longer decrypt local data, or vice versa.
                                    UserStorage.updatePassword(context, newPassword)
                                    StorageKeyManager.changePassword(context, newPassword)
                                    currentPassword = ""; newPassword = ""; newPasswordRepeat = ""; totpCode = ""
                                    success = true
                                } catch (e: Exception) {
                                    error = s.error(e.message ?: "")
                                }
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = c.accent)
                ) {
                    Text(s.changePasswordSubmit, color = if (c.isDark) Color.White else c.textPrimary)
                }
            }
        }
    }
}
