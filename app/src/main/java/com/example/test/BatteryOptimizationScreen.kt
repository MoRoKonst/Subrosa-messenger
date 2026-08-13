package com.subrosa.messenger

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.subrosa.messenger.ui.theme.LocalSubrosaColors

/** One-time onboarding step, shown right after a fresh registration
 *  completes TOTP setup — asks for the battery-optimization exemption
 *  (see docs/ISSUE_backup_identity_hijack.md, "сворачивание приложения
 *  тихо душит фоновое соединение"). Unlike TOTP this is skippable: it's a
 *  reliability recommendation, not something the account is defenseless
 *  without. Advances to [onDone] either way — after firing the system
 *  Allow/Deny dialog (whatever the user picks there) or immediately on
 *  Skip — this is a one-shot onboarding nudge, not a gate. */
@Composable
fun BatteryOptimizationPromptScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var dialogShown by remember { mutableStateOf(false) }

    // Advance once the user returns from the system dialog — same
    // ON_RESUME re-sync idea used elsewhere for this permission
    // (ProfileScreen.kt), just wired to move on rather than update a
    // toggle. Only fires after we've actually shown the dialog (not on
    // the screen's own first composition).
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && dialogShown) {
                onDone()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(bgGradient)
            .padding(24.dp)
    ) {
        Column(
            modifier = Modifier.align(Alignment.Center),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                s.batteryPromptTitle,
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = c.textPrimary
            )
            Text(
                s.batteryPromptText,
                fontSize = 14.sp,
                lineHeight = 20.sp,
                color = c.textPrimary.copy(alpha = 0.8f)
            )
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = {
                    dialogShown = true
                    try {
                        context.startActivity(
                            Intent(
                                android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                Uri.parse("package:${context.packageName}")
                            )
                        )
                    } catch (e: Exception) {
                        onDone()
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = c.accent),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(s.batteryPromptAllow, color = Color.White)
            }
            TextButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                Text(s.batteryPromptSkip, color = c.textPrimary.copy(alpha = 0.6f))
            }
        }
    }
}
