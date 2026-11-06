package com.subrosa.desktop

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp

/** Telegram-style playback waveform — mirrors Android's identical
 *  Composable exactly (see app/src/main/java/com/subrosa/messenger/VoiceWaveform.kt
 *  for the full rationale). [bars] amplitude values (0f..1f), portion left
 *  of [progress] drawn in [color], the rest in [dimColor]. detectDragGestures
 *  alone handles both tap-to-seek (onDragStart fires at the initial
 *  touch-down) and drag-to-seek. */
@Composable
fun VoiceWaveform(
    bars: FloatArray,
    progress: Float,
    color: Color,
    dimColor: Color,
    modifier: Modifier = Modifier,
    onSeek: (Float) -> Unit
) {
    BoxWithConstraints(modifier = modifier.fillMaxWidth().height(24.dp)) {
        val widthPx = constraints.maxWidth.toFloat()
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(Unit) {
                    detectDragGestures(
                        onDragStart = { offset ->
                            if (widthPx > 0f) onSeek((offset.x / widthPx).coerceIn(0f, 1f))
                        },
                        onDrag = { change, _ ->
                            change.consume()
                            if (widthPx > 0f) onSeek((change.position.x / widthPx).coerceIn(0f, 1f))
                        }
                    )
                }
        ) {
            if (bars.isEmpty()) return@Canvas
            val barCount = bars.size
            val gap = 2.dp.toPx()
            val barWidth = ((size.width - gap * (barCount - 1)) / barCount).coerceAtLeast(1f)
            for (i in 0 until barCount) {
                val h = (bars[i] * size.height).coerceAtLeast(2f)
                val x = i * (barWidth + gap)
                val played = (i.toFloat() / barCount) < progress
                drawRoundRect(
                    color = if (played) color else dimColor,
                    topLeft = Offset(x, (size.height - h) / 2f),
                    size = Size(barWidth, h),
                    cornerRadius = CornerRadius(barWidth / 2f, barWidth / 2f)
                )
            }
        }
    }
}
