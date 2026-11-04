package com.subrosa.messenger

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Focused tests for AvatarCropMath — the zoom+pan transform model that
 *  replaced a single mutable absolute top-left offset (see
 *  AvatarCropScreen.kt's own comment for the live bug this fixed: moving
 *  the zoom slider visibly drifted the image up-left instead of zooming in
 *  place). Pure math, no Compose/Android dependency, so plain JUnit is
 *  enough — no Robolectric needed. */
class AvatarCropMathTest {

    private val cropSize = 280f

    private fun effectiveScale(sourceW: Int, sourceH: Int, zoom: Float): Float {
        val baseScale = cropSize / minOf(sourceW, sourceH).toFloat()
        return baseScale * zoom
    }

    private fun renderOffset(sourceW: Int, sourceH: Int, zoom: Float, panX: Float, panY: Float): Pair<Float, Float> {
        val scale = effectiveScale(sourceW, sourceH, zoom)
        val cx = AvatarCropMath.centerOffsetX(sourceW, cropSize, scale)
        val cy = AvatarCropMath.centerOffsetY(sourceH, cropSize, scale)
        return (cx + panX) to (cy + panY)
    }

    // ── 1. landscape source, slider 1x -> 5x with pan == 0: centered
    //       content does not drift ──────────────────────────────────────

    @Test
    fun `landscape source zoom 1 to 5 with zero pan keeps center point fixed`() {
        val w = 1920; val h = 1080
        for (zoom in listOf(1f, 2f, 3f, 4f, 5f)) {
            val scale = effectiveScale(w, h, zoom)
            val (ox, oy) = renderOffset(w, h, zoom, 0f, 0f)
            // The point at the crop-window center must always map back to
            // the source image's own center when pan is zero, regardless
            // of zoom.
            val srcCenterX = (cropSize / 2f - ox) / scale
            val srcCenterY = (cropSize / 2f - oy) / scale
            assertEquals(w / 2f, srcCenterX, 0.5f)
            assertEquals(h / 2f, srcCenterY, 0.5f)
        }
    }

    // ── 2. portrait source: same ─────────────────────────────────────────

    @Test
    fun `portrait source zoom 1 to 5 with zero pan keeps center point fixed`() {
        val w = 1080; val h = 1920
        for (zoom in listOf(1f, 2f, 3f, 4f, 5f)) {
            val scale = effectiveScale(w, h, zoom)
            val (ox, oy) = renderOffset(w, h, zoom, 0f, 0f)
            val srcCenterX = (cropSize / 2f - ox) / scale
            val srcCenterY = (cropSize / 2f - oy) / scale
            assertEquals(w / 2f, srcCenterX, 0.5f)
            assertEquals(h / 2f, srcCenterY, 0.5f)
        }
    }

    // ── 3. pan then zoom: image remains within valid crop bounds ────────

    @Test
    fun `pan then zoom keeps render offset within bounds that fully cover the crop window`() {
        val w = 2000; val h = 1200
        // Pan all the way to the max at zoom=2, then zoom out to 1 (bounds
        // shrink) — clamping must re-tighten pan, not leave it stale.
        val scaleAt2 = effectiveScale(w, h, 2f)
        val maxPanAt2 = AvatarCropMath.maxPanX(w, cropSize, scaleAt2)
        var panX = AvatarCropMath.clamp(maxPanAt2 + 500f, maxPanAt2) // simulate a drag past the edge

        val scaleAt1 = effectiveScale(w, h, 1f)
        val maxPanAt1 = AvatarCropMath.maxPanX(w, cropSize, scaleAt1)
        panX = AvatarCropMath.clamp(panX, maxPanAt1)

        assertTrue(panX <= maxPanAt1 && panX >= -maxPanAt1)

        val ox = AvatarCropMath.centerOffsetX(w, cropSize, scaleAt1) + panX
        // Image left edge (ox) must be <= 0 and image right edge
        // (ox + displayedWidth) must be >= cropSize -- i.e. the crop
        // window is always fully covered, never showing empty space.
        val displayedW = w * scaleAt1
        assertTrue("left edge must not expose empty space: ox=$ox", ox <= 0.01f)
        assertTrue("right edge must not expose empty space", ox + displayedW >= cropSize - 0.01f)
    }

    // ── 4. crop output corresponds to preview center ────────────────────

    @Test
    fun `crop rect at zoom 1 pan 0 captures the geometric center of a square region`() {
        val w = 1600; val h = 1000 // landscape; smaller dimension h=1000 fills the crop window at zoom 1
        val scale = effectiveScale(w, h, 1f)
        val (ox, oy) = renderOffset(w, h, 1f, 0f, 0f)
        val rect = AvatarCropMath.sourceCropRect(w, h, cropSize, scale, ox, oy)

        // Cropped square should be centered horizontally within the wider
        // source image, and cover the full height.
        val expectedLeft = ((w - h) / 2f).toInt()
        assertEquals(expectedLeft, rect.left)
        assertEquals(0, rect.top)
        assertTrue("crop must be square-ish within 1px rounding", kotlin.math.abs(rect.size - h) <= 1)
    }

    // ── 5. extreme pan cannot expose empty crop area ─────────────────────

    @Test
    fun `extreme pan request is clamped so the crop window stays fully covered`() {
        val w = 900; val h = 900 // square
        val zoom = 3f
        val scale = effectiveScale(w, h, zoom)
        val maxX = AvatarCropMath.maxPanX(w, cropSize, scale)
        val maxY = AvatarCropMath.maxPanY(h, cropSize, scale)

        // Try to pan absurdly far in every direction.
        val clampedX = AvatarCropMath.clamp(100_000f, maxX)
        val clampedY = AvatarCropMath.clamp(-100_000f, maxY)
        assertEquals(maxX, clampedX, 0f)
        assertEquals(-maxY, clampedY, 0f)

        val ox = AvatarCropMath.centerOffsetX(w, cropSize, scale) + clampedX
        val oy = AvatarCropMath.centerOffsetY(h, cropSize, scale) + clampedY
        val displayedW = w * scale
        val displayedH = h * scale
        assertTrue(ox <= 0.01f && ox + displayedW >= cropSize - 0.01f)
        assertTrue(oy <= 0.01f && oy + displayedH >= cropSize - 0.01f)
    }

    // ── 6. zoom change alone (pan untouched) never violates bounds ──────

    @Test
    fun `zooming out after panning to the edge re-clamps pan into the new tighter bounds`() {
        val w = 1500; val h = 1500
        val scaleAt4 = effectiveScale(w, h, 4f)
        val maxAt4 = AvatarCropMath.maxPanX(w, cropSize, scaleAt4)
        val panAtEdge = maxAt4 // fully panned to the right edge at zoom=4

        // Zoom out to 1x -- at zoom=1 for a square image, max pan is 0.
        val scaleAt1 = effectiveScale(w, h, 1f)
        val maxAt1 = AvatarCropMath.maxPanX(w, cropSize, scaleAt1)
        assertEquals(0f, maxAt1, 0.01f)

        val reClamped = AvatarCropMath.clamp(panAtEdge, maxAt1)
        assertEquals(0f, reClamped, 0.01f)
    }
}
