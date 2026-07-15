package com.bcon.messenger

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import com.bcon.messenger.ui.theme.LocalBeaconColors

@Composable
fun IncomingCallScreen(
    from: String,
    isVideo: Boolean,
    isGroup: Boolean,
    groupId: String,
    onAccept: () -> Unit,
    onDecline: () -> Unit
) {
    val c = LocalBeaconColors.current
    val context = LocalContext.current
    val s = LocalStrings.current
    val haptic = LocalHapticFeedback.current

    var userActed by remember { mutableStateOf(false) }
    DisposableEffect(Unit) {

        CallManager.onCallEnded = { _ ->
            context.startService(Intent(context, CallService::class.java).apply {
                action = CallService.ACTION_END
            })
            userActed = true
            onDecline()
        }
        onDispose {
            CallManager.onIncomingCall = null
            CallManager.onCallEnded = null
            if (!userActed && CallManager.callId.isNotEmpty()) {

                CallManager.declineCall()
            }
        }
    }

    val cameraPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->

        if (!granted) android.widget.Toast.makeText(
            context, s.incomingNoCameraPermission, android.widget.Toast.LENGTH_SHORT
        ).show()
        userActed = true
        CallManager.acceptCall(context)
        onAccept()
    }

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseAlphaOuter by infiniteTransition.animateFloat(
        initialValue = 0.05f, targetValue = 0.18f,
        animationSpec = infiniteRepeatable(tween(900, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "pulseOuter"
    )
    val pulseAlphaMiddle by infiniteTransition.animateFloat(
        initialValue = 0.10f, targetValue = 0.28f,
        animationSpec = infiniteRepeatable(tween(900, 150, FastOutSlowInEasing), RepeatMode.Reverse),
        label = "pulseMiddle"
    )

    val callTypeText = when {
        isGroup -> s.incomingGroupCall
        isVideo -> s.incomingVideoCall
        else    -> s.incomingAudioCall
    }

    val peerName = remember(from) {
        ChatStorage.getContactName(context, from).ifBlank { from }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(c.callGradientEdge, c.topBar, c.callGradientEdge)
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            Spacer(modifier = Modifier.height(48.dp))

            Text(
                callTypeText,
                color = c.accent,
                fontFamily = JetBrainsMono,
                fontSize = 14.sp,
                letterSpacing = 2.sp
            )

            Box(contentAlignment = Alignment.Center) {
                Surface(
                    shape = CircleShape,
                    color = c.primaryBlue.copy(alpha = pulseAlphaOuter),
                    modifier = Modifier.size(148.dp)
                ) {}
                Surface(
                    shape = CircleShape,
                    color = c.primaryBlue.copy(alpha = pulseAlphaMiddle),
                    modifier = Modifier.size(114.dp)
                ) {}
                Surface(
                    shape = CircleShape,
                    color = c.primaryBlue,
                    modifier = Modifier.size(82.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            peerName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                            fontSize = 36.sp,
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontFamily = JetBrainsMono
                        )
                    }
                }
            }

            Text(
                peerName,
                color = Color.White,
                fontFamily = JetBrainsMono,
                fontSize = 24.sp,
                fontWeight = FontWeight.SemiBold
            )

            Text(
                if (isGroup) s.incomingGroupCallHint else s.incomingCallHint,
                color = c.textPrimary.copy(alpha = 0.5f),
                fontFamily = JetBrainsMono,
                fontSize = 13.sp
            )

            Spacer(modifier = Modifier.height(32.dp))

            Row(
                horizontalArrangement = Arrangement.spacedBy(72.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {

                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Surface(
                        shape = CircleShape,
                        color = Color(0xFFE53935),
                        modifier = Modifier.size(76.dp),
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            userActed = true
                            CallManager.declineCall()
                            onDecline()
                        }
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            androidx.compose.material3.Icon(
                                painter = painterResource(R.drawable.ic_close),
                                contentDescription = s.incomingDecline,
                                tint = Color.White,
                                modifier = Modifier.size(32.dp)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(s.incomingDecline, color = c.textPrimary.copy(alpha = 0.7f), fontFamily = JetBrainsMono, fontSize = 12.sp)
                }

                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Surface(
                        shape = CircleShape,
                        color = Color(0xFF43A047),
                        modifier = Modifier.size(76.dp),
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            val camGranted = context.checkSelfPermission(android.Manifest.permission.CAMERA) ==
                                android.content.pm.PackageManager.PERMISSION_GRANTED
                            if (isVideo && !camGranted) {
                                cameraPermLauncher.launch(android.Manifest.permission.CAMERA)
                            } else {
                                userActed = true
                                CallManager.acceptCall(context)
                                onAccept()
                            }
                        }
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text("📞", fontSize = 30.sp)
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(s.incomingAccept, color = c.textPrimary.copy(alpha = 0.7f), fontFamily = JetBrainsMono, fontSize = 12.sp)
                }
            }
        }
    }
}
