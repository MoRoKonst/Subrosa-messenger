package com.bcon.messenger.ui.theme

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
    beaconColors: BeaconColors = NavyBeaconColors,
    content: @Composable () -> Unit
) {
    val colorScheme = if (beaconColors.isDark) {
        darkColorScheme(
            primary        = beaconColors.primaryBlue,
            secondary      = beaconColors.accent,
            background     = beaconColors.gradientEnd,
            surface        = beaconColors.card,
            onPrimary      = Color.White,
            onBackground   = beaconColors.textPrimary,
            onSurface      = beaconColors.textPrimary
        )
    } else {
        lightColorScheme(
            primary        = beaconColors.primaryBlue,
            secondary      = beaconColors.accent,
            background     = beaconColors.gradientStart,
            surface        = beaconColors.card,
            onPrimary      = Color.White,
            onBackground   = beaconColors.textPrimary,
            onSurface      = beaconColors.textPrimary
        )
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = beaconColors.topBar.toArgb()
            window.navigationBarColor = beaconColors.gradientEnd.toArgb()
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars     = !beaconColors.isDark
                isAppearanceLightNavigationBars = !beaconColors.isDark
            }
        }
    }

    CompositionLocalProvider(LocalBeaconColors provides beaconColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography  = Typography,
            content     = content
        )
    }
}
