package com.subrosa.messenger

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
import com.subrosa.messenger.ui.theme.LocalSubrosaColors

@Composable
fun IncomingCallScreen(
    from: String,
    isVideo: Boolean,
    isGroup: Boolean,
    groupId: String,
    onAccept: () -> Unit,
    onDecline: () -> Unit
) {
    val c = LocalSubrosaColors.current
    val context = LocalContext.current
    val s = LocalStrings.current
    val haptic = LocalHapticFeedback.current

    var userActed by remember { mutableStateOf(false) }

    // Safety net alongside the onCallEnded callback below — see ActiveCallScreen's
    // matching poll for the full reasoning (live testing showed the callback can
    // occasionally not fire even when confirmed non-null right before invoke()).
    // Only relevant while still ringing and untouched: once the user has acted,
    // whatever they triggered (accept/decline) owns navigating away from here.
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(1000)
            if (!userActed && CallManager.callId.isEmpty()) {
                userActed = true
                onDecline()
                break
            }
        }
    }

    // Set right before navigating to ActiveCallScreen on accept — this screen's
    // onDispose must NOT null out CallManager's onCallEnded/onIncomingCall in that
    // case, since ActiveCallScreen sets up its own registration for the same call
    // as part of the same navigation, and Compose doesn't guarantee this screen's
    // onDispose runs before that one's DisposableEffect — if it runs after, it wipes
    // out the new registration, leaving the active screen with no way to react to
    // the call ending (confirmed live: hangup worked at the protocol level, but the
    // other side's call screen never closed because this exact race nulled out its
    // onCallEnded callback).
    var transitioningToCall by remember { mutableStateOf(false) }
    DisposableEffect(Unit) {

        android.util.Log.w("DEBUG-BOOTSTRAP", "IncomingCallScreen: registering onCallEnded")
        CallManager.onCallEnded = { _ ->
            android.util.Log.w("DEBUG-BOOTSTRAP", "IncomingCallScreen: onCallEnded fired, calling onDecline()")
            context.startService(Intent(context, CallService::class.java).apply {
                action = CallService.ACTION_END
            })
            userActed = true
            onDecline()
        }
        onDispose {
            android.util.Log.w("DEBUG-BOOTSTRAP", "IncomingCallScreen: onDispose, transitioningToCall=$transitioningToCall")
            if (!transitioningToCall) {
                CallManager.onIncomingCall = null
                CallManager.onCallEnded = null
            }
            if (!userActed && CallManager.callId.isNotEmpty()) {

                CallManager.declineCall()
            }
        }
    }

    val callAcceptPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { perms ->
        val audioOk = perms[android.Manifest.permission.RECORD_AUDIO]
            ?: (context.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED)
        if (!audioOk) {
            // Audio is required for every call (audio or video) — without it there's
            // nothing to accept into, so decline instead of silently connecting with
            // a dead mic (which is what happened before this check existed: acceptCall()
            // would proceed anyway and createLocalTracks() would just skip the audio
            // track, leaving both sides connected but with no sound).
            android.widget.Toast.makeText(context, s.incomingNoAudioPermission, android.widget.Toast.LENGTH_SHORT).show()
            userActed = true
            CallManager.declineCall()
            onDecline()
            return@rememberLauncherForActivityResult
        }
        val camOk = perms[android.Manifest.permission.CAMERA]
            ?: (context.checkSelfPermission(android.Manifest.permission.CAMERA) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED)
        if (isVideo && !camOk) android.widget.Toast.makeText(
            context, s.incomingNoCameraPermission, android.widget.Toast.LENGTH_SHORT
        ).show()
        userActed = true
        transitioningToCall = true
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
                            val audioGranted = context.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) ==
                                android.content.pm.PackageManager.PERMISSION_GRANTED
                            val camGranted = context.checkSelfPermission(android.Manifest.permission.CAMERA) ==
                                android.content.pm.PackageManager.PERMISSION_GRANTED
                            val needed = buildList {
                                if (!audioGranted) add(android.Manifest.permission.RECORD_AUDIO)
                                if (isVideo && !camGranted) add(android.Manifest.permission.CAMERA)
                            }
                            if (needed.isNotEmpty()) {
                                callAcceptPermissionLauncher.launch(needed.toTypedArray())
                            } else {
                                userActed = true
                                transitioningToCall = true
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
