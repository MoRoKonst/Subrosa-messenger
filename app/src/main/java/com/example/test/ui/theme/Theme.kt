package com.subrosa.messenger.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

@Composable
fun TESTTheme(
    subrosaColors: subrosaColors = NavysubrosaColors,
    content: @Composable () -> Unit
) {
    val colorScheme = if (subrosaColors.isDark) {
        darkColorScheme(
            primary        = subrosaColors.primaryBlue,
            secondary      = subrosaColors.accent,
            background     = subrosaColors.gradientEnd,
            surface        = subrosaColors.card,
            onPrimary      = Color.White,
            onBackground   = subrosaColors.textPrimary,
            onSurface      = subrosaColors.textPrimary
        )
    } else {
        lightColorScheme(
            primary        = subrosaColors.primaryBlue,
            secondary      = subrosaColors.accent,
            background     = subrosaColors.gradientStart,
            surface        = subrosaColors.card,
            onPrimary      = Color.White,
            onBackground   = subrosaColors.textPrimary,
            onSurface      = subrosaColors.textPrimary
        )
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = subrosaColors.topBar.toArgb()
            window.navigationBarColor = subrosaColors.gradientEnd.toArgb()
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars     = !subrosaColors.isDark
                isAppearanceLightNavigationBars = !subrosaColors.isDark
            }
        }
    }

    CompositionLocalProvider(LocalsubrosaColors provides subrosaColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography  = Typography,
            content     = content
        )
    }
}
