package com.subrosa.desktop

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Desktop port of Android's VideoCircleScreen recording UI. Simplified vs.
 *  Android's hold-to-record/swipe-to-lock gesture (built for touch, not
 *  mouse) — a plain click-to-start/click-to-stop toggle, which is the
 *  standard desktop convention (matches this app's own voice-message
 *  recording bar). See DesktopVideoCircleRecorder's own comment for the
 *  capture/mux pipeline. */
@Composable
fun VideoCircleRecorderDialog(
    onDismiss: () -> Unit,
    onRecorded: (file: java.io.File, durationSec: Int) -> Unit
) {
    var isRecording by remember { mutableStateOf(false) }
    var isMuxing by remember { mutableStateOf(false) }
    var recordingSeconds by remember { mutableStateOf(0) }
    var previewFrame by remember { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    val scope = rememberCoroutineScope()

    DisposableEffect(Unit) {
        DesktopVideoCircleRecorder.onPreviewFrame = { img ->
            previewFrame = img.toComposeImageBitmap()
        }
        onDispose {
            DesktopVideoCircleRecorder.onPreviewFrame = null
            if (isRecording) DesktopVideoCircleRecorder.cancel()
        }
    }

    fun stopAndSend() {
        if (!isRecording) return
        isRecording = false
        isMuxing = true
        scope.launch {
            val file = withContext(Dispatchers.IO) { DesktopVideoCircleRecorder.stopAndMux() }
            isMuxing = false
            if (file != null) {
                onRecorded(file, recordingSeconds)
            } else {
                onDismiss()
            }
        }
    }

    LaunchedEffect(isRecording) {
        if (isRecording) {
            recordingSeconds = 0
            while (isRecording) {
                delay(1000L)
                recordingSeconds++
                if (recordingSeconds >= DesktopVideoCircleRecorder.MAX_SECONDS) {
                    stopAndSend()
                }
            }
        }
    }

    Dialog(
        onDismissRequest = {
            if (isRecording) DesktopVideoCircleRecorder.cancel()
            onDismiss()
        },
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier.fillMaxSize().background(Color(0xCC000000)),
            contentAlignment = Alignment.Center
        ) {
            Box(
                modifier = Modifier
                    .size(300.dp)
                    .clip(CircleShape)
                    .background(Color(0xFF1A1A2E)),
                contentAlignment = Alignment.Center
            ) {
                previewFrame?.let { frame ->
                    Image(
                        bitmap = frame,
                        contentDescription = null,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = androidx.compose.ui.layout.ContentScale.Crop
                    )
                }
                if (isMuxing) {
                    Box(Modifier.fillMaxSize().background(Color(0x99000000)), contentAlignment = Alignment.Center) {
                        Text("Обработка…", color = Color.White, fontSize = 16.sp)
                    }
                }
                if (isRecording) {
                    // Same thin-ring visual language as the played-back
                    // video-note bubble (ChatScreen.kt's VideoCircleRow) —
                    // Subrosa accent instead of a generic Material green,
                    // and a slimmer stroke (was 6dp, a "loader" thickness).
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val progress = (recordingSeconds.toFloat() / DesktopVideoCircleRecorder.MAX_SECONDS).coerceIn(0f, 1f)
                        drawArc(
                            color = Color(0xFF30D493),
                            startAngle = -90f,
                            sweepAngle = 360f * progress,
                            useCenter = false,
                            style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                        )
                    }
                    val dotAlpha = remember { Animatable(1f) }
                    LaunchedEffect(Unit) {
                        while (true) {
                            dotAlpha.animateTo(0.2f, tween(550))
                            dotAlpha.animateTo(1f, tween(550))
                        }
                    }
                    Box(
                        modifier = Modifier.align(Alignment.TopCenter).padding(top = 16.dp)
                            .background(Color(0x99000000), CircleShape)
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier.size(8.dp).clip(CircleShape)
                                    .background(Color(0xFFFF4444).copy(alpha = dotAlpha.value))
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                String.format("%d:%02d", recordingSeconds / 60, recordingSeconds % 60),
                                color = Color.White, fontSize = 15.sp
                            )
                        }
                    }
                }
            }

            // Close button
            Box(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(24.dp)
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(Color(0x66000000))
                    .clickable(enabled = !isMuxing) {
                        if (isRecording) DesktopVideoCircleRecorder.cancel()
                        onDismiss()
                    },
                contentAlignment = Alignment.Center
            ) {
                Icon(AppIcons.get("CLOSE"), contentDescription = "Закрыть", tint = Color.White)
            }

            // Record/stop button
            Box(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 48.dp)
                    .size(72.dp)
                    .clip(CircleShape)
                    .background(if (isRecording) Color(0xFFFF4444) else Color.White)
                    .clickable(enabled = !isMuxing) {
                        if (!isRecording) {
                            if (!DesktopVideoCircleRecorder.hasCamera()) {
                                onDismiss()
                                return@clickable
                            }
                            if (DesktopVideoCircleRecorder.start()) {
                                isRecording = true
                            } else {
                                onDismiss()
                            }
                        } else {
                            stopAndSend()
                        }
                    },
                contentAlignment = Alignment.Center
            ) {
                if (!isRecording) {
                    Icon(AppIcons.get("VIDEO_CALL"), contentDescription = "Записать", tint = Color(0xFF1A1A2E))
                }
            }
        }
    }
}
