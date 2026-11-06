package com.subrosa.messenger

import android.graphics.Bitmap
import android.widget.VideoView
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.File

/** Telegram-style round video message bubble — shared by ChatScreen.kt and
 *  GroupChatScreen.kt (previously two byte-for-byte-identical copies of this
 *  same block, one per screen). [cachePrefix] keeps each caller's temp
 *  filenames distinct ("" for 1:1, "g" for group) since both write into the
 *  same cacheDir.
 *
 *  Visual redesign only — recording/encryption/upload/playback/protocol/
 *  storage are untouched, this still plays through the exact same looping
 *  VideoView + temp-file-decrypt path as before. The one addition is purely
 *  observational: polling VideoView's own getCurrentPosition()/getDuration()
 *  to drive the progress ring, which doesn't alter playback itself. */
@Composable
fun VideoCircleBubble(
    messageId: String,
    videoPath: String,
    videoDuration: Int,
    isPlaying: Boolean,
    onPlay: () -> Unit,
    onStop: () -> Unit,
    cachePrefix: String = ""
) {
    val context = LocalContext.current
    val c = LocalSubrosaColors.current
    var thumbnail by remember(messageId) { mutableStateOf<Bitmap?>(null) }
    var tempVideo by remember(messageId) { mutableStateOf<File?>(null) }
    var isLoading by remember(messageId) { mutableStateOf(false) }
    var videoViewRef by remember(messageId) { mutableStateOf<VideoView?>(null) }
    var progress by remember(messageId) { mutableStateOf(0f) }

    LaunchedEffect(videoPath) {
        withContext(Dispatchers.IO) {
            try {
                val bytes = SecureFileStorage.read(context, File(videoPath))
                val tmp = File(context.cacheDir, "${cachePrefix}thumb_$messageId.mp4")
                tmp.writeBytes(bytes)
                val retriever = android.media.MediaMetadataRetriever()
                retriever.setDataSource(tmp.absolutePath)
                thumbnail = retriever.getFrameAtTime(0)
                retriever.release()
                tmp.delete()
            } catch (e: Exception) {
                android.util.Log.d("VideoCircle", "thumb: ${e.message}")
            }
        }
    }

    LaunchedEffect(isPlaying) {
        if (isPlaying && tempVideo == null) {
            isLoading = true
            try {
                val f = withContext(Dispatchers.IO) {
                    val bytes = SecureFileStorage.read(context, File(videoPath))
                    val out = File(context.cacheDir, "${cachePrefix}vplay_$messageId.mp4")
                    out.writeBytes(bytes)
                    out
                }
                tempVideo = f
            } catch (e: Exception) {
                android.util.Log.e("VideoCircle", "play: ${e.message}")
                onStop()
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(isPlaying) {
        if (!isPlaying) {
            videoViewRef?.stopPlayback()
            videoViewRef = null
            tempVideo?.delete()
            tempVideo = null
            progress = 0f
        }
    }

    // Purely observational polling of VideoView's own playback position to
    // drive the progress ring — doesn't touch how playback itself runs.
    LaunchedEffect(isPlaying, videoViewRef) {
        if (!isPlaying) return@LaunchedEffect
        while (isActive) {
            val vv = videoViewRef
            if (vv != null) {
                val dur = vv.duration
                if (dur > 0) progress = (vv.currentPosition.toFloat() / dur).coerceIn(0f, 1f)
            }
            delay(150)
        }
    }

    DisposableEffect(messageId) {
        onDispose {
            videoViewRef?.stopPlayback()
            tempVideo?.delete()
        }
    }

    val circleSize by animateDpAsState(
        targetValue = if (isPlaying) 340.dp else 150.dp,
        animationSpec = tween(durationMillis = 300),
        label = "circleSize"
    )
    val ringStroke = 3.dp
    val ringGap = 3.dp

    Box(
        modifier = Modifier
            .size(circleSize)
            .clickable { if (isPlaying) onStop() else onPlay() },
        contentAlignment = Alignment.Center
    ) {
        // Thin progress ring — neutral track always visible, accent arc
        // grows with playback position. No card/background behind it: this
        // Canvas draws only the ring stroke, leaving the rest transparent.
        Canvas(modifier = Modifier.fillMaxSize()) {
            val strokePx = ringStroke.toPx()
            val inset = strokePx / 2f
            val arcSize = Size(size.width - strokePx, size.height - strokePx)
            drawArc(
                color = c.textPrimary.copy(alpha = 0.22f),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = arcSize,
                style = Stroke(width = strokePx, cap = StrokeCap.Round)
            )
            if (progress > 0f) {
                drawArc(
                    color = c.accent,
                    startAngle = -90f,
                    sweepAngle = 360f * progress,
                    useCenter = false,
                    topLeft = Offset(inset, inset),
                    size = arcSize,
                    style = Stroke(width = strokePx, cap = StrokeCap.Round)
                )
            }
        }

        Box(
            modifier = Modifier
                .padding(ringStroke + ringGap)
                .fillMaxSize()
                .clip(CircleShape)
                .background(c.card),
            contentAlignment = Alignment.Center
        ) {
            val tv = tempVideo
            if (isPlaying && tv != null) {
                // Playing: clean video, no icon overlay — tap anywhere to
                // pause (same click target as the rest of this Box).
                AndroidView(
                    factory = { ctx ->
                        VideoView(ctx).apply {
                            videoViewRef = this
                            setVideoPath(tv.absolutePath)
                            setOnPreparedListener { mp ->
                                mp.isLooping = true
                                start()
                            }
                            setOnErrorListener { _, _, _ -> true }
                        }
                    },
                    modifier = Modifier.fillMaxSize()
                )
            } else if (isLoading) {
                CircularProgressIndicator(
                    color = c.accent,
                    modifier = Modifier.size(32.dp),
                    strokeWidth = 2.dp
                )
            } else {
                thumbnail?.let {
                    Image(
                        bitmap = it.asImageBitmap(),
                        contentDescription = "Видеосообщение",
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Crop
                    )
                }
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(Color(0x55000000)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_play),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(16.dp)
                    )
                }
                if (videoDuration > 0) {
                    Box(
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .padding(8.dp)
                            .background(Color(0x88000000), CircleShape)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text("${videoDuration}\"", fontSize = 12.sp, color = Color.White, fontFamily = JetBrainsMono)
                    }
                }
            }
        }
    }
}
