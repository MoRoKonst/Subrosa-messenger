package com.subrosa.messenger

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeRight
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Instrumented, render-level regression test for AvatarCropScreen's
 *  zoom/pan behavior — the class of bug AvatarCropMathTest (pure math)
 *  could NOT catch, since it never exercises Compose's actual measurement/
 *  layout/graphicsLayer pipeline. Found live 2026-09-21 (second pass):
 *  Modifier.size(displayedWidth, displayedHeight) inside a fixed-size
 *  280dp Box was silently clamped back down to the Box's own constraints
 *  by Compose (size() intersects with incoming parent constraints, unlike
 *  requiredSize()) — the crop math was correct, but the Image never
 *  actually rendered at the size that math assumed, so the visible photo
 *  appeared to drift up-left instead of scaling in place when the zoom
 *  slider moved. Fixed by rendering the image at a FIXED base size,
 *  scaled/translated via graphicsLayer (a post-layout visual transform,
 *  immune to parent constraints) instead of re-measuring every frame.
 *
 *  This test renders the real composable and samples actual pixels — a
 *  synthetic bitmap with a small, distinct color marker at its exact
 *  geometric center lets the test verify "what's visually at the crop-
 *  circle's center" directly, which a bounds/semantics-only check cannot:
 *  graphicsLayer scale/translate do not change a node's reported LAYOUT
 *  bounds, only its rendered pixels. */
@RunWith(AndroidJUnit4::class)
class AvatarCropScreenRenderTest {

    @get:Rule
    val composeRule = createComposeRule()

    /** Landscape bitmap, plain blue background with a small magenta marker
     *  exactly at the geometric center. */
    private fun landscapeMarkerBitmap(): Bitmap {
        val w = 1200; val h = 800
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        for (y in 0 until h) for (x in 0 until w) bmp.setPixel(x, y, Color.BLUE)
        val cx = w / 2; val cy = h / 2
        for (y in (cy - 4)..(cy + 4)) for (x in (cx - 4)..(cx + 4)) bmp.setPixel(x, y, Color.MAGENTA)
        return bmp
    }

    private fun isCloseToMagenta(color: Int): Boolean {
        val r = Color.red(color); val g = Color.green(color); val b = Color.blue(color)
        return r > 180 && b > 180 && g < 100
    }

    @Test
    fun zoomingFrom1xTo5xKeepsSourceCenterAtCropCircleCenter() {
        composeRule.setContent {
            AvatarCropScreen(
                source = landscapeMarkerBitmap(),
                onConfirm = {},
                onCancel = {}
            )
        }
        composeRule.waitForIdle()

        fun centerPixel(): Int {
            val img = composeRule.onNodeWithTag("avatarCropBox").captureToImage().asAndroidBitmap()
            return img.getPixel(img.width / 2, img.height / 2)
        }

        assertTrue(
            "marker must be at the crop-circle center at zoom=1 (baseline)",
            isCloseToMagenta(centerPixel())
        )

        // Drag the zoom slider from its start to its end (1x -> 5x) — a
        // full-width swipe on the Slider node itself, the standard way to
        // drive a Material3 Slider to (near) its max value in a Compose UI
        // test.
        composeRule.onNodeWithTag("avatarZoomSlider").performTouchInput { swipeRight() }
        composeRule.waitForIdle()

        // The required visible invariant: with pan=0, the same source point
        // (the marker) remains exactly at the crop-circle's visual center
        // after zooming 1x -> 5x -- no drift left/up. If the Modifier.size()
        // constraint-clamping bug were still present, the image would never
        // actually have grown, and this pixel would show background blue
        // instead (the marker having "moved" out of the sampled center).
        assertTrue(
            "marker must remain at the crop-circle center after zooming 1x -> 5x (no drift)",
            isCloseToMagenta(centerPixel())
        )
    }
}
