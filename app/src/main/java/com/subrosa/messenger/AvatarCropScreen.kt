package com.subrosa.messenger

import android.graphics.Bitmap
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.max
import kotlin.math.min

/** Pure crop transform math — zoom + pan only, no mutable absolute top-left
 *  offset. Extracted from the composable so it's plain-JUnit-testable (see
 *  AvatarCropMathTest.kt) with zero Compose/Android runtime dependency.
 *
 *  Model: at zoom=1 the smaller source dimension exactly fills the crop
 *  window and the image is optically centered (centerOffset), pan=(0,0).
 *  Changing zoom NEVER touches pan — no top-left-position compensation
 *  math. renderOffset = centerOffset + pan is recomputed every frame from
 *  zoom+pan, never stored itself. This was the actual bug (found live
 *  2026-09-21): the old code stored a single mutable `offset` combining
 *  "center position" + "user pan" + "zoom compensation," and the zoom
 *  slider re-derived a new offset via a center-anchored formula on every
 *  change — mathematically an anchor-preserving transform, but any
 *  floating-point drift or intermediate clamp between steps accumulated
 *  directly into the ONE state variable driving both zoom and pan, with no
 *  way to tell "the user actually panned" apart from "the last zoom step's
 *  compensation math." Splitting zoom/pan into independent state removes
 *  that coupling entirely. */
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
 *  Bitmap.createScaledBitmap(bmp, size, size, true) stretch in
 *  ProfileScreen.kt, which distorted any non-square photo directly into a
 *  square instead of letting the user pick which part to keep. The crop
 *  math keeps the circular window always fully covered by the image (zoom
 *  1x = "smaller image dimension exactly fills the window"), then crops and
 *  scales straight from the original decoded [source] bitmap for
 *  full-resolution output, not from whatever ended up rendered on screen. */
@Composable
fun AvatarCropScreen(
    source: Bitmap,
    outputSize: Int = 128,
    onConfirm: (Bitmap) -> Unit,
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

    // safeDrawingPadding() (status bar + nav bar + display cutouts + IME) —
    // this screen had NO inset handling at all despite being a genuine
    // fillMaxSize() screen (not a Dialog, which gets this for free), so the
    // title/buttons could render underneath system bars depending on
    // device/gesture-nav config. Found live 2026-09-21.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black)
            .safeDrawingPadding(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(24.dp))
        Text("Обрежьте фото", color = Color.White, fontSize = 18.sp)
        Spacer(Modifier.height(16.dp))

        // Base (zoom=1) layout size — FIXED, computed once, never changed
        // per frame. This is the actual remaining bug the previous fix
        // missed (found live 2026-09-21, second pass): the preview used
        // Modifier.size(displayedWidth, displayedHeight).offset(renderOffset)
        // with `displayedWidth/Height` growing every frame as zoom
        // increased. Modifier.size() intersects with the INCOMING
        // constraints from the parent — and this Box has a fixed
        // .size(cropBoxDp) — so Compose silently clamped the Image back
        // down to ~280dp regardless of what .size() requested; the crop
        // math's offset was computed as if the image had actually grown to
        // the full zoomed size, so the visible (never-actually-larger)
        // image appeared to slide up-left instead of scaling in place.
        // graphicsLayer's scaleX/scaleY/translationX/Y are a pure
        // POST-layout visual transform — completely unaffected by parent
        // measurement constraints — so the image genuinely renders larger
        // than its measured 280dp-ish box. Centering is handled by
        // Alignment.Center (base image's own center sits at the box
        // center) + TransformOrigin.Center (scales around that same point,
        // which is what keeps it fixed at every zoom level); pan is then a
        // plain post-scale pixel translation, matching the gesture APIs'
        // own units.
        val baseImageWidth = with(density) { (source.width * baseScale).toDp() }
        val baseImageHeight = with(density) { (source.height * baseScale).toDp() }

        Box(
            modifier = Modifier
                .size(cropBoxDp)
                .testTag("avatarCropBox")
                // Box doesn't clip its content by default in Compose (unlike
                // an Android View) — without this, a zoomed/panned image
                // extends visibly past the 280dp crop box into the
                // surrounding (also black, but undimmed) screen background,
                // fully bright and unmasked. Found live 2026-09-21.
                .clipToBounds()
                .pointerInput(source) {
                    // Pan gesture only ever modifies `pan`. Pinch zoom is
                    // center-anchored (per spec item 5, acceptable when
                    // preserving the exact pinch centroid isn't practical
                    // with this gesture API) — it updates `zoom` alone and
                    // never derives a compensating pan; any pan component
                    // of the SAME gesture frame is added and then clamped,
                    // exactly like the slider's own zoom-then-clamp order.
                    detectTransformGestures { _, gesturePan, gestureZoom, _ ->
                        val newZoom = (zoom * gestureZoom).coerceIn(1f, 5f)
                        zoom = newZoom
                        pan = clampPan(baseScale * newZoom, pan + gesturePan)
                    }
                }
        ) {
            Image(
                bitmap = source.asImageBitmap(),
                contentDescription = null,
                modifier = Modifier
                    .size(baseImageWidth, baseImageHeight)
                    .align(Alignment.Center)
                    .testTag("avatarCropImage")
                    .graphicsLayer {
                        scaleX = zoom
                        scaleY = zoom
                        transformOrigin = TransformOrigin.Center
                        translationX = pan.x
                        translationY = pan.y
                    }
            )
            // Fully hide everything outside the circular crop window and
            // outline it — only the part of the photo actually inside the
            // circle is what gets cropped. Found live 2026-09-21.
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
            modifier = Modifier.width(cropBoxDp).testTag("avatarZoomSlider"),
            onValueChange = { newZoom ->
                // Update zoom, then clamp the EXISTING pan to the new
                // bounds — never modify pan to compensate for top-left
                // movement. With pan==0 this keeps the image optically
                // centered at every zoom level (the actual bug report:
                // moving the slider used to visibly drift the image
                // up-left instead of zooming in place).
                val clamped = newZoom.coerceIn(1f, 5f)
                zoom = clamped
                pan = clampPan(baseScale * clamped, pan)
            },
            valueRange = 1f..5f
        )

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
                val cropped = Bitmap.createBitmap(source, rect.left, rect.top, rect.size, rect.size)
                val scaled = Bitmap.createScaledBitmap(cropped, outputSize, outputSize, true)
                onConfirm(scaled)
            }) { Text("Готово") }
        }
    }
}
