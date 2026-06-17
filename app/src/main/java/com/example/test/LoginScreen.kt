package com.bcon.messenger

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.ui.graphics.graphicsLayer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.bcon.messenger.ui.theme.LocalBeaconColors

private val AppFont = FontFamily(Font(R.font.jetbrainsmono_regular))

@Composable
fun LoginScreen(onLoggedIn: () -> Unit, onPanicMode: () -> Unit = {}) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    val displayName = UserStorage.getUserDisplayName(context)
    var isLoading by remember { mutableStateOf(false) }
    var showBiometric by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    var showNotMeConfirm by remember { mutableStateOf(false) }

    // Staggered entrance
    var visibleEmoji by remember { mutableStateOf(false) }
    var visibleTitle by remember { mutableStateOf(false) }
    var visibleForm  by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        visibleEmoji = true
        delay(180)
        visibleTitle = true
        delay(200)
        visibleForm = true
    }
    val emojiAlpha  by animateFloatAsState(if (visibleEmoji) 1f else 0f, tween(500), label = "a0")
    val titleAlpha  by animateFloatAsState(if (visibleTitle) 1f else 0f, tween(480), label = "a1")
    val formAlpha   by animateFloatAsState(if (visibleForm)  1f else 0f, tween(450), label = "a2")

    LaunchedEffect(Unit) {
        if (showBiometric) {
            BiometricHelper.authenticate(
                activity = context as FragmentActivity,
                onSuccess = {
                    StorageKeyManager.unlockWithKeystore(context)
                    onLoggedIn()
                },
                onError = { error = it; showBiometric = false }
            )
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

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(bgGradient)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                "💬",
                fontSize = 64.sp,
                modifier = Modifier
                    .padding(bottom = 16.dp)
                    .graphicsLayer {
                        alpha = emojiAlpha
                        translationY = (1f - emojiAlpha) * -60f
                    }
            )

            Text(
                "B-CON Messenger",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = c.accent,
                fontFamily = AppFont,
                modifier = Modifier
                    .padding(bottom = 8.dp)
                    .graphicsLayer {
                        alpha = titleAlpha
                        translationY = (1f - titleAlpha) * -40f
                    }
            )

            Text(
                s.loginGreeting(displayName),
                fontSize = 16.sp,
                color = c.textPrimary.copy(alpha = 0.6f),
                fontFamily = AppFont,
                modifier = Modifier
                    .padding(bottom = 48.dp)
                    .graphicsLayer {
                        alpha = titleAlpha
                        translationY = (1f - titleAlpha) * -30f
                    }
            )

            Box(modifier = Modifier.fillMaxWidth().graphicsLayer {
                alpha = formAlpha
                translationY = (1f - formAlpha) * 30f
            }) {
            Column(modifier = Modifier.fillMaxWidth()) {
            if (!showBiometric) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(s.loginPassword, fontFamily = AppFont) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                    colors = fieldColors
                )

                if (error.isNotEmpty()) {
                    Text(
                        text = error,
                        color = c.error,
                        fontSize = 13.sp,
                        fontFamily = AppFont,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                }

                Button(
                    onClick = {
                        val (canLogin, remainingSeconds) = LoginAttemptManager.canAttemptLogin(context)
                        if (!canLogin) {
                            val minutes = remainingSeconds / 60
                            val seconds = remainingSeconds % 60
                            error = s.loginTooManyAttempts(minutes, seconds)
                            return@Button
                        }
                        if (password.isBlank()) { error = s.loginEnterPassword; return@Button }

                        scope.launch {
                            isLoading = true
                            delay(500)

                            if (UserStorage.isPanicPassword(context, password)) {
                                // Panic password: показываем decoy вместо wipe.
                                // Реальные данные остаются нетронутыми — правдоподобное отрицание.
                                isLoading = false
                                onPanicMode()
                                return@launch
                            } else if (UserStorage.checkPassword(context, password)) {
                                // После экстренного вайпа реальный пароль открывает фейковые чаты
                                if (UserStorage.isDecoyMode(context)) {
                                    isLoading = false
                                    onPanicMode()
                                } else {
                                    // Разблокировать SMK (второй слой шифрования)
                                    withContext(Dispatchers.IO) {
                                        if (!StorageKeyManager.isSetup(context))
                                            StorageKeyManager.setup(context, password)
                                        else
                                            StorageKeyManager.unlockWithPassword(context, password)
                                    }
                                    onLoggedIn()
                                }
                            } else {
                                error = s.loginWrongPassword
                            }
                            isLoading = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    enabled = !isLoading,
                    colors = ButtonDefaults.buttonColors(containerColor = c.dialog)
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(color = c.accent, modifier = Modifier.size(24.dp))
                    } else {
                        Text(s.loginButton, fontSize = 18.sp, fontFamily = AppFont, color = Color.White)
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                if (BiometricHelper.isBiometricAvailable(context)) {
                    OutlinedButton(
                        onClick = {
                            showBiometric = true
                            BiometricHelper.authenticate(
                                activity = context as FragmentActivity,
                                onSuccess = {
                                    StorageKeyManager.unlockWithKeystore(context)
                                    onLoggedIn()
                                },
                                onError = { error = it; showBiometric = false }
                            )
                        },
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = c.accent),
                        border = androidx.compose.foundation.BorderStroke(1.dp, c.accent)
                    ) {
                        Text(s.loginBiometric, fontSize = 16.sp, fontFamily = AppFont)
                    }
                }
            } else {
                CircularProgressIndicator(modifier = Modifier.padding(16.dp), color = c.accent)
                Text(s.loginWaitingBiometric, fontSize = 14.sp, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
            }
            } // end Column
            } // end Box
        }

        TextButton(
            onClick = { showNotMeConfirm = true },
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 32.dp)
        ) {
            Text(s.loginNotMe, color = c.error, fontSize = 14.sp, fontFamily = AppFont)
        }
    }

    if (showNotMeConfirm) {
        AlertDialog(
            onDismissRequest = { showNotMeConfirm = false },
            containerColor = c.dialog,
            title = { Text(s.loginNotMeTitle, color = Color.White, fontFamily = AppFont) },
            text = { Text(s.loginNotMeText, color = c.textPrimary, fontFamily = AppFont) },
            confirmButton = {
                TextButton(onClick = {
                    showNotMeConfirm = false
                    // Полный экстренный сброс: ключи AndroidKeyStore + все данные + kill процесса
                    (context as? MainActivity)?.emergencyWipe()
                }) {
                    Text(s.loginNotMeConfirm, color = c.error, fontFamily = AppFont)
                }
            },
            dismissButton = {
                TextButton(onClick = { showNotMeConfirm = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }
}
