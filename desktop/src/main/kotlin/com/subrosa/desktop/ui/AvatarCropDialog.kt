package com.subrosa.desktop

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.awt.image.BufferedImage
import kotlin.math.max
import kotlin.math.min

/** Pure crop transform math — mirrors Android's AvatarCropMath
 *  (AvatarCropScreen.kt) exactly, zoom + pan only, no mutable absolute
 *  top-left offset. Own copy since Desktop and Android are separate Gradle
 *  projects with no shared module — see AvatarCropMathTest.kt (Android
 *  side) for the full root-cause writeup of the bug this replaced: a
 *  single mutable `offset` combining center position + user pan + zoom
 *  compensation, where the zoom slider visibly drifted the image up-left
 *  instead of zooming in place. Found live 2026-09-21. */
internal object AvatarCropMath {
    fun centerOffsetX(sourceW: Int, cropSize: Float, effectiveScale: Float): Float =
        (cropSize - sourceW * effectiveScale) / 2f

    fun centerOffsetY(sourceH: Int, cropSize: Float, effectiveScale: Float): Float =
        (cropSize - sourceH * effectiveScale) / 2f

    fun maxPanX(sourceW: Int, cropSize: Float, effectiveScale: Float): Float =
        max(0f, (sourceW * effectiveScale - cropSize) / 2f)

    fun maxPanY(sourceH: Int, cropSize: Float, effectiveScale: Float): Float =
        max(0f, (sourceH * effectiveScale - cropSize) / 2f)

    fun clamp(value: Float, maxAbs: Float): Float = value.coerceIn(-maxAbs, maxAbs)

    data class CropRect(val left: Int, val top: Int, val size: Int)

    /** Maps the crop-window bounds back into ORIGINAL source-image
     *  coordinates, from the exact same renderOffset/effectiveScale the
     *  preview drew with — never from a downscaled/preview bitmap. */
    fun sourceCropRect(
        sourceW: Int, sourceH: Int, cropSize: Float, effectiveScale: Float,
        renderOffsetX: Float, renderOffsetY: Float
    ): CropRect {
        val srcLeft = (-renderOffsetX / effectiveScale).toInt().coerceIn(0, sourceW - 1)
        val srcTop = (-renderOffsetY / effectiveScale).toInt().coerceIn(0, sourceH - 1)
        val srcSize = (cropSize / effectiveScale).toInt()
            .coerceAtMost(min(sourceW - srcLeft, sourceH - srcTop))
            .coerceAtLeast(1)
        return CropRect(srcLeft, srcTop, srcSize)
    }
}

/** Interactive pan+zoom avatar cropper — replaces the old
 *  g.drawImage(original, 0, 0, 128, 128, null) stretch in ProfileScreen.kt's
 *  pickAvatar(), which distorted any non-square photo directly into a
 *  square instead of letting the user pick which part to keep. Same crop
 *  math as Android's AvatarCropScreen.kt, just mouse-driven (drag to pan,
 *  scroll wheel or the slider to zoom) instead of touch gestures. */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun AvatarCropDialog(
    source: BufferedImage,
    outputSize: Int = 128,
    onConfirm: (BufferedImage) -> Unit,
    onCancel: () -> Unit
) {
    val density = LocalDensity.current
    val cropBoxDp = 280.dp
    val cropBoxPx = with(density) { cropBoxDp.toPx() }

    val baseScale = remember(source) { cropBoxPx / min(source.width, source.height).toFloat() }
    // zoom + pan only — see AvatarCropMath's own comment for why a single
    // mutable absolute offset was the bug. pan=(0,0) at zoom=1 is already
    // the correctly-centered state (AvatarCropMath.centerOffsetX/Y), so no
    // separate "center on first composition" effect is needed anymore.
    var zoom by remember(source) { mutableStateOf(1f) }
    var pan by remember(source) { mutableStateOf(Offset.Zero) }

    fun clampPan(effectiveScale: Float, p: Offset): Offset = Offset(
        AvatarCropMath.clamp(p.x, AvatarCropMath.maxPanX(source.width, cropBoxPx, effectiveScale)),
        AvatarCropMath.clamp(p.y, AvatarCropMath.maxPanY(source.height, cropBoxPx, effectiveScale))
    )

    fun centerOffset(effectiveScale: Float): Offset = Offset(
        AvatarCropMath.centerOffsetX(source.width, cropBoxPx, effectiveScale),
        AvatarCropMath.centerOffsetY(source.height, cropBoxPx, effectiveScale)
    )

    val imageBitmap = remember(source) { source.toComposeImageBitmap() }

    Surface(color = Color.Black, modifier = Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
            Spacer(Modifier.height(24.dp))
            Text("Обрежьте фото", color = Color.White, fontSize = 18.sp)
            Spacer(Modifier.height(16.dp))

            // Base (zoom=1) layout size — FIXED, computed once, never
            // changed per frame. This is the actual remaining bug the
            // first fix missed (found live 2026-09-21, second pass):
            // Modifier.size(displayedWidth, displayedHeight) grew every
            // frame as zoom increased, but Modifier.size() intersects with
            // the INCOMING constraints from the parent — and this Box has
            // a fixed .size(cropBoxDp) — so Compose silently clamped the
            // Image back down to ~280dp regardless of what .size()
            // requested; the offset math assumed the image had actually
            // grown to the full zoomed size, so the visible (never-
            // actually-larger) image appeared to slide instead of scale.
            // graphicsLayer's scaleX/scaleY/translationX/Y are a pure
            // POST-layout visual transform, unaffected by parent
            // measurement constraints, so the image genuinely renders
            // larger than its measured 280dp-ish box. Mirrors Android's
            // identical fix.
            val baseImageWidth = with(density) { (source.width * baseScale).toDp() }
            val baseImageHeight = with(density) { (source.height * baseScale).toDp() }

            Box(
                modifier = Modifier
                    .size(cropBoxDp)
                    // Box doesn't clip its content by default — without
                    // this, a zoomed/panned image extended visibly past
                    // the 280dp crop box, undimmed. Found live 2026-09-21.
                    .clipToBounds()
                    .pointerInput(source) {
                        // Drag modifies only `pan` — never a compensating
                        // top-left position.
                        detectDragGestures { _, dragAmount ->
                            pan = clampPan(baseScale * zoom, pan + dragAmount)
                        }
                    }
                    .pointerInput(source) {
                        awaitPointerEventScope {
                            while (true) {
                                val event = awaitPointerEvent()
                                if (event.type == PointerEventType.Scroll) {
                                    val scrollDelta = event.changes.firstOrNull()?.scrollDelta?.y ?: 0f
                                    if (scrollDelta != 0f) {
                                        // Same order as the slider: update
                                        // zoom, then re-clamp the existing
                                        // pan into the new bounds — never
                                        // derive a compensating pan.
                                        val newZoom = (zoom - scrollDelta * 0.1f).coerceIn(1f, 5f)
                                        zoom = newZoom
                                        pan = clampPan(baseScale * newZoom, pan)
                                    }
                                }
                            }
                        }
                    }
            ) {
                Image(
                    bitmap = imageBitmap,
                    contentDescription = null,
                    modifier = Modifier
                        .size(baseImageWidth, baseImageHeight)
                        .align(Alignment.Center)
                        .graphicsLayer {
                            scaleX = zoom
                            scaleY = zoom
                            transformOrigin = TransformOrigin.Center
                            translationX = pan.x
                            translationY = pan.y
                        }
                )
                // Fully hide everything outside the circular crop window
                // and outline it — only the part of the photo actually
                // inside the circle is what gets cropped. Found live
                // 2026-09-21.
                Canvas(modifier = Modifier.matchParentSize()) {
                    val path = Path().apply {
                        fillType = PathFillType.EvenOdd
                        addRect(Rect(Offset.Zero, size))
                        addOval(Rect(Offset.Zero, size))
                    }
                    clipPath(path) {
                        drawRect(Color.Black)
                    }
                    drawCircle(Color.White, radius = size.minDimension / 2f, style = Stroke(width = 3f))
                }
            }

            Spacer(Modifier.height(24.dp))
            Slider(
                value = zoom,
                onValueChange = { newZoom ->
                    // Update zoom, then clamp the EXISTING pan to the new
                    // bounds — never modify pan to compensate for top-left
                    // movement. With pan==0 this keeps the image optically
                    // centered at every zoom level.
                    val clamped = newZoom.coerceIn(1f, 5f)
                    zoom = clamped
                    pan = clampPan(baseScale * clamped, pan)
                },
                valueRange = 1f..5f,
                modifier = Modifier.width(cropBoxDp)
            )
            Text("Колесо мыши — зум, перетаскивание — сдвиг", fontSize = 13.sp, color = Color.White.copy(alpha = 0.6f))

            Spacer(Modifier.weight(1f))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 24.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                TextButton(onClick = onCancel) { Text("Отмена", color = Color.White) }
                Button(onClick = {
                    val effectiveScale = baseScale * zoom
                    val renderOffset = centerOffset(effectiveScale) + pan
                    val rect = AvatarCropMath.sourceCropRect(
                        source.width, source.height, cropBoxPx, effectiveScale,
                        renderOffset.x, renderOffset.y
                    )
                    val cropped = source.getSubimage(rect.left, rect.top, rect.size, rect.size)
                    val scaled = BufferedImage(outputSize, outputSize, BufferedImage.TYPE_INT_RGB)
                    val g = scaled.createGraphics()
                    g.setRenderingHint(java.awt.RenderingHints.KEY_INTERPOLATION, java.awt.RenderingHints.VALUE_INTERPOLATION_BILINEAR)
                    g.drawImage(cropped, 0, 0, outputSize, outputSize, null)
                    g.dispose()
                    onConfirm(scaled)
                }) { Text("Готово") }
            }
        }
    }
}
