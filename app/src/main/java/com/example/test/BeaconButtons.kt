package com.bcon.messenger

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.bcon.messenger.ui.theme.LocalBeaconColors
import kotlinx.coroutines.launch

@Composable
fun PortholeSendButton(
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    size: Int = 44
) {
    val c = LocalBeaconColors.current
    val scope = rememberCoroutineScope()
    val scale = remember { Animatable(1f) }

    Box(
        modifier = modifier
            .size(size.dp)
            .graphicsLayer {
                scaleX = scale.value
                scaleY = scale.value
            }
            .alpha(if (enabled) 1f else 0.35f)
            .clip(CircleShape)
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(c.primaryBlue, c.accent.copy(alpha = 0.85f))
                )
            )
            .pointerInput(enabled) {
                detectTapGestures(
                    onTap = {
                        if (enabled) {
                            scope.launch {
                                scale.animateTo(
                                    targetValue = 0.82f,
                                    animationSpec = tween(100, easing = EaseIn)
                                )
                                scale.animateTo(
                                    targetValue = 1f,
                                    animationSpec = tween(150, easing = EaseOut)
                                )
                            }
                            onClick()
                        }
                    }
                )
            },
        contentAlignment = Alignment.Center
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_send_arrow),
            contentDescription = "Отправить",
            tint = Color.White,
            modifier = Modifier.size((size * 0.55f).dp)
        )
    }
}

/**
 * Объединённая кнопка медиа:
 * - Tap  → переключение между голосом и видео
 * - Long → начать запись в текущем режиме
 */
@Composable
fun CombinedMediaButton(
    isVideoMode: Boolean,
    onToggleMode: () -> Unit,
    onStartVoice: () -> Unit,
    onStartVideo: () -> Unit,
    modifier: Modifier = Modifier,
    size: Int = 44
) {
    val c = LocalBeaconColors.current
    val scope = rememberCoroutineScope()
    val scale = remember { Animatable(1f) }

    val bgColor by animateColorAsState(
        targetValue = if (isVideoMode) Color(0x30FF9800) else Color(0x22FFFFFF),
        animationSpec = tween(280),
        label = "cmb_bg"
    )
    val iconTint by animateColorAsState(
        targetValue = if (isVideoMode) Color(0xFFFFAA44) else c.textPrimary.copy(alpha = 0.9f),
        animationSpec = tween(280),
        label = "cmb_tint"
    )
    val dotColor by animateColorAsState(
        targetValue = if (isVideoMode) Color(0xFFFF9800) else c.accent,
        animationSpec = tween(280),
        label = "cmb_dot"
    )

    Box(
        modifier = modifier
            .size(size.dp)
            .graphicsLayer {
                scaleX = scale.value
                scaleY = scale.value
            }
            .clip(CircleShape)
            .background(bgColor)
            .pointerInput(isVideoMode) {
                detectTapGestures(
                    onTap = { onToggleMode() },
                    onLongPress = {
                        scope.launch {
                            scale.animateTo(0.84f, tween(80, easing = EaseIn))
                            scale.animateTo(1f, tween(160, easing = EaseOut))
                        }
                        if (isVideoMode) onStartVideo() else onStartVoice()
                    }
                )
            },
        contentAlignment = Alignment.Center
    ) {
        AnimatedContent(
            targetState = isVideoMode,
            transitionSpec = {
                (fadeIn(tween(160)) + scaleIn(tween(160), initialScale = 0.7f)) togetherWith
                (fadeOut(tween(120)) + scaleOut(tween(120), targetScale = 0.7f))
            },
            label = "cmb_icon"
        ) { videoMode ->
            if (videoMode) {
                Icon(
                    painter = painterResource(R.drawable.ic_camera_circle),
                    contentDescription = "Видеосообщение",
                    tint = iconTint,
                    modifier = Modifier.size((size * 0.52f).dp)
                )
            } else {
                Icon(
                    painter = painterResource(R.drawable.ic_mic),
                    contentDescription = "Голосовое",
                    tint = iconTint,
                    modifier = Modifier.size((size * 0.52f).dp)
                )
            }
        }

        // Индикатор режима — маленькая точка в углу
        Box(
            modifier = Modifier
                .size(8.dp)
                .align(Alignment.TopEnd)
                .offset(x = (-3).dp, y = 3.dp)
                .clip(CircleShape)
                .background(dotColor)
        )
    }
}
