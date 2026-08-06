package com.subrosa.messenger.ui.theme

import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.graphics.Color

enum class SubrosaTheme { NAVY, DARK, LIGHT }

data class subrosaColors(
    val gradientStart: Color,
    val gradientEnd: Color,
    val topBar: Color,
    val dialog: Color,
    val accent: Color,
    val textPrimary: Color,
    val card: Color,
    val cardAlt: Color,
    val fieldBorder: Color,
    val bubbleOwn: Color,
    val bubbleOther: Color,
    val bubbleSystem: Color,
    val dangerCard: Color,
    val error: Color,
    val primaryBlue: Color,
    val inputBg: Color,
    val callBg: Color,
    val callGradientEdge: Color,
    val isDark: Boolean
)

val NavysubrosaColors = subrosaColors(
    gradientStart    = Color(0xFF141e4a),
    gradientEnd      = Color(0xFF0d1238),
    topBar           = Color(0xFF091a66),
    dialog           = Color(0xFF091a66),
    accent           = Color(0xFF00E5FF),
    textPrimary      = Color(0xFFE0E6FF),
    card             = Color(0xFF1F2B5E),
    cardAlt          = Color(0xFF1A2550),
    fieldBorder      = Color(0xFF2A3B8F),
    bubbleOwn        = Color(0xFF2A3B8F),
    bubbleOther      = Color(0xFF1F2B5E),
    bubbleSystem     = Color(0xFF1A2550),
    dangerCard       = Color(0xFF2A1F1F),
    error            = Color(0xFFFF4444),
    primaryBlue      = Color(0xFF2481CC),
    inputBg          = Color(0xFF0d1238),
    callBg           = Color(0xFF050d26),
    callGradientEdge = Color(0xFF0a1040),
    isDark           = true
)

val DarksubrosaColors = subrosaColors(
    gradientStart    = Color(0xFF1C1C1C),
    gradientEnd      = Color(0xFF0D0D0D),
    topBar           = Color(0xFF242424),
    dialog           = Color(0xFF2A2A2A),
    accent           = Color(0xFF00E5FF),
    textPrimary      = Color(0xFFFFFFFF),
    card             = Color(0xFF2A2A2A),
    cardAlt          = Color(0xFF222222),
    fieldBorder      = Color(0xFF444444),
    bubbleOwn        = Color(0xFF1A5FA8),
    bubbleOther      = Color(0xFF303030),
    bubbleSystem     = Color(0xFF1E1E1E),
    dangerCard       = Color(0xFF3A1A1A),
    error            = Color(0xFFFF4444),
    primaryBlue      = Color(0xFF2481CC),
    inputBg          = Color(0xFF1A1A1A),
    callBg           = Color(0xFF0A0A0A),
    callGradientEdge = Color(0xFF111111),
    isDark           = true
)

val LightsubrosaColors = subrosaColors(
    gradientStart    = Color(0xFFF0F4FF),
    gradientEnd      = Color(0xFFE4EDFF),
    topBar           = Color(0xFF2481CC),
    dialog           = Color(0xFFFFFFFF),
    accent           = Color(0xFF2481CC),
    textPrimary      = Color(0xFF1A1A2E),
    card             = Color(0xFFFFFFFF),
    cardAlt          = Color(0xFFF5F7FF),
    fieldBorder      = Color(0xFFAEC6EF),
    bubbleOwn        = Color(0xFF2481CC),
    bubbleOther      = Color(0xFFFFFFFF),
    bubbleSystem     = Color(0xFFF0F0F5),
    dangerCard       = Color(0xFFFFF0F0),
    error            = Color(0xFFCC2222),
    primaryBlue      = Color(0xFF2481CC),
    inputBg          = Color(0xFFF5F8FF),
    callBg           = Color(0xFFEEF3FF),
    callGradientEdge = Color(0xFFD0E0FF),
    isDark           = false
)

val LocalsubrosaColors = compositionLocalOf<subrosaColors> { NavysubrosaColors }

fun subrosaColorsFor(theme: SubrosaTheme): subrosaColors = when (theme) {
    SubrosaTheme.NAVY  -> NavysubrosaColors
    SubrosaTheme.DARK  -> DarksubrosaColors
    SubrosaTheme.LIGHT -> LightsubrosaColors
}
