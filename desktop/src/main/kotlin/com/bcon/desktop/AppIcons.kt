package com.subrosa.desktop

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.loadSvgPainter
import androidx.compose.ui.unit.Density

/** Custom SVG icon set (user-supplied, D:\Subrosa_Messenger\icons — bundled
 *  into desktop/src/main/resources/icons at build time), replacing the
 *  Material Icons / emoji placeholders previously used throughout the UI.
 *  Cached per (name, density) since loadSvgPainter re-parses the SVG on
 *  every call otherwise — icons are read from the classpath (works both in
 *  IDE runs and in a packaged jpackage build, unlike an absolute filesystem
 *  path). */
object AppIcons {
    private val cache = mutableMapOf<Pair<String, Density>, Painter>()

    @Composable
    fun get(name: String): Painter {
        val density = LocalDensity.current
        return remember(name, density) {
            cache.getOrPut(name to density) {
                val stream = AppIcons::class.java.getResourceAsStream("/icons/$name.svg")
                    ?: error("AppIcons: missing icon resource /icons/$name.svg")
                stream.use { loadSvgPainter(it, density) }
            }
        }
    }
}
