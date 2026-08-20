package com.subrosa.messenger.ui.theme

import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.graphics.Color

enum class SubrosaTheme { NAVY, DARK, LIGHT }

data class SubrosaColors(
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

val NavySubrosaColors = SubrosaColors(
    gradientStart    = Color(0xFF2B0F14),
    gradientEnd      = Color(0xFF180A0C),
    topBar           = Color(0xFF4A151A),
    dialog           = Color(0xFF4A151A),
    accent           = Color(0xFFD9A566),
    textPrimary      = Color(0xFFF3E6DC),
    card             = Color(0xFF3A1216),
    cardAlt          = Color(0xFF2F0F13),
    fieldBorder      = Color(0xFF6B2A2A),
    bubbleOwn        = Color(0xFF7A2430),
    bubbleOther      = Color(0xFF3A1216),
    bubbleSystem     = Color(0xFF2F0F13),
    dangerCard       = Color(0xFF2A1F1F),
    error            = Color(0xFFFF4444),
    primaryBlue      = Color(0xFFC77B4F),
    inputBg          = Color(0xFF180A0C),
    callBg           = Color(0xFF120608),
    callGradientEdge = Color(0xFF200B0D),
    isDark           = true
)

val DarkSubrosaColors = SubrosaColors(
    gradientStart    = Color(0xFF1C1414),
    gradientEnd      = Color(0xFF100A0A),
    topBar           = Color(0xFF2A1A1A),
    dialog           = Color(0xFF2E1C1C),
    accent           = Color(0xFFD9A566),
    textPrimary      = Color(0xFFFFFFFF),
    card             = Color(0xFF2A1A1A),
    cardAlt          = Color(0xFF201414),
    fieldBorder      = Color(0xFF4A3030),
    bubbleOwn        = Color(0xFF7A2430),
    bubbleOther      = Color(0xFF302020),
    bubbleSystem     = Color(0xFF1E1414),
    dangerCard       = Color(0xFF3A1A1A),
    error            = Color(0xFFFF4444),
    primaryBlue      = Color(0xFFC77B4F),
    inputBg          = Color(0xFF1A1414),
    callBg           = Color(0xFF0A0808),
    callGradientEdge = Color(0xFF150E0E),
    isDark           = true
)

val LightSubrosaColors = SubrosaColors(
    gradientStart    = Color(0xFFFAF3EC),
    gradientEnd      = Color(0xFFF2E6DA),
    topBar           = Color(0xFF641D17),
    dialog           = Color(0xFFFFFFFF),
    accent           = Color(0xFF8A2A2A),
    textPrimary      = Color(0xFF2A1414),
    card             = Color(0xFFFFFFFF),
    cardAlt          = Color(0xFFF7EFE6),
    fieldBorder      = Color(0xFFD9C2AE),
    bubbleOwn        = Color(0xFF8A2A2A),
    bubbleOther      = Color(0xFFFFFFFF),
    bubbleSystem     = Color(0xFFF0E5DA),
    dangerCard       = Color(0xFFFFF0F0),
    error            = Color(0xFFCC2222),
    primaryBlue      = Color(0xFF8A2A2A),
    inputBg          = Color(0xFFF7EFE6),
    callBg           = Color(0xFFF2E6DA),
    callGradientEdge = Color(0xFFE8D5C0),
    isDark           = false
)

val LocalSubrosaColors = compositionLocalOf<SubrosaColors> { NavySubrosaColors }

fun subrosaColorsFor(theme: SubrosaTheme): SubrosaColors = when (theme) {
    SubrosaTheme.NAVY  -> NavySubrosaColors
    SubrosaTheme.DARK  -> DarkSubrosaColors
    SubrosaTheme.LIGHT -> LightSubrosaColors
}
