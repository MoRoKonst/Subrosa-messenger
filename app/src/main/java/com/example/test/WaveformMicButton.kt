package com.bcon.messenger

import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlin.math.*

@Composable
fun WaveformMicButton(
    isRecording: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    size: Int = 52
) {
    var amplitude by remember { mutableStateOf(0.15f) }
    val phase = remember { Animatable(0f) }
    val smoothAmplitude = remember { Animatable(0.15f) }
    val idlePulse = remember { Animatable(0.12f) }

    var currentWaveColor by remember { mutableStateOf(Color(0xFF6B9FD4)) }
    val animatedWaveColor by animateColorAsState(
        targetValue = currentWaveColor,
        animationSpec = tween(400),
        label = "wave_color"
    )

    LaunchedEffect(isRecording) {
        currentWaveColor = if (isRecording) Color(0xFFFF4444) else Color(0xFF6B9FD4)
    }

    // Бегущая фаза — бесконечно
    LaunchedEffect(Unit) {
        while (true) {
            phase.animateTo(
                targetValue = phase.value + 1f,
                animationSpec = tween(durationMillis = 1200, easing = LinearEasing)
            )
        }
    }

    // Пульсация в покое
    LaunchedEffect(isRecording) {
        if (!isRecording) {
            while (!isRecording) {
                idlePulse.animateTo(0.18f, tween(900, easing = LinearEasing))
                idlePulse.animateTo(0.12f, tween(900, easing = LinearEasing))
            }
        }
    }

    // Громкость с микрофона
    LaunchedEffect(isRecording) {
        if (isRecording) {
            launch(Dispatchers.IO) {
                val sampleRate = 44100
                val bufferSize = AudioRecord.getMinBufferSize(
                    sampleRate,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT
                )
                try {
                    val audioRecord = AudioRecord(
                        MediaRecorder.AudioSource.MIC,
                        sampleRate,
                        AudioFormat.CHANNEL_IN_MONO,
                        AudioFormat.ENCODING_PCM_16BIT,
                        bufferSize
                    )
                    audioRecord.startRecording()
                    val buffer = ShortArray(bufferSize)
                    while (isActive && isRecording) {
                        val read = audioRecord.read(buffer, 0, bufferSize)
                        if (read > 0) {
                            var sum = 0.0
                            for (i in 0 until read) sum += buffer[i].toDouble().pow(2)
                            val rms = sqrt(sum / read).toFloat()
                            amplitude = (rms / 8000f).coerceIn(0.1f, 1f)
                        }
                        delay(50)
                    }
                    audioRecord.stop()
                    audioRecord.release()
                } catch (e: SecurityException) {
                    android.util.Log.e("WaveformMicButton", "Нет разрешения: ${e.message}")
                } catch (e: Exception) {
                    android.util.Log.e("WaveformMicButton", "Ошибка: ${e.message}")
                }
                amplitude = 0.15f
            }
        } else {
            amplitude = 0.15f
        }
    }

    // Плавное изменение амплитуды
    LaunchedEffect(amplitude) {
        smoothAmplitude.animateTo(amplitude, tween(80, easing = LinearEasing))
    }

    val currentAmplitude = if (isRecording) smoothAmplitude.value else idlePulse.value

    val bgColor by animateColorAsState(
        targetValue = if (isRecording) Color(0x55FF4444) else Color(0x20FFFFFF),
        animationSpec = tween(300),
        label = "mic_bg"
    )
    val ringScale = remember { Animatable(1f) }
    LaunchedEffect(isRecording) {
        if (isRecording) {
            while (true) {
                ringScale.animateTo(1.28f, tween(650))
                ringScale.animateTo(1f, tween(650))
            }
        } else {
            ringScale.snapTo(1f)
        }
    }

    Box(
        modifier = modifier
            .size(size.dp)
            .pointerInput(Unit) {
                detectTapGestures(onTap = { onClick() })
            },
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val w = this.size.width
            val h = this.size.height
            val center = Offset(w / 2f, h / 2f)
            val radius = minOf(w, h) / 2f

            // Пульсирующее кольцо при записи
            if (isRecording) {
                drawCircle(
                    color = Color(0xFFFF4444).copy(alpha = (1f - (ringScale.value - 1f) / 0.28f) * 0.3f),
                    radius = radius * ringScale.value,
                    center = center
                )
            }

            // Фоновый круг
            drawCircle(color = bgColor, radius = radius * 0.88f, center = center)

            val centerY = h / 2f
            val maxAmp = h * 0.30f * currentAmplitude
            val freq = 2.5f
            val phaseRad = phase.value * 2f * PI.toFloat()

            // Основная волна
            val path1 = Path()
            for (x in 0..w.toInt()) {
                val y = centerY - maxAmp * sin(x * freq * 2f * PI.toFloat() / w + phaseRad)
                if (x == 0) path1.moveTo(x.toFloat(), y) else path1.lineTo(x.toFloat(), y)
            }
            drawPath(path1, animatedWaveColor, style = Stroke(3.5.dp.toPx(), cap = StrokeCap.Round))

            // Вторая волна (тень)
            val path2 = Path()
            for (x in 0..w.toInt()) {
                val y = centerY - maxAmp * 0.5f * sin(x * freq * 2f * PI.toFloat() / w + phaseRad + PI.toFloat())
                if (x == 0) path2.moveTo(x.toFloat(), y) else path2.lineTo(x.toFloat(), y)
            }
            drawPath(
                path2,
                animatedWaveColor.copy(alpha = 0.3f),
                style = Stroke(2.5.dp.toPx(), cap = StrokeCap.Round)
            )
        }
    }
}
