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

// Emerald/mint family, built around accent #30D493 — replaces the previous
// burgundy/antique-gold NAVY palette (same hue for every role, only
// saturation/lightness varied: darker for backgrounds/bubbles, lighter for
// badges/ticks/text). User-requested recolor, 2026-09-22.
val NavySubrosaColors = SubrosaColors(
    gradientStart    = Color(0xFF0D1C16),
    gradientEnd      = Color(0xFF08120E),
    topBar           = Color(0xFF143427),
    dialog           = Color(0xFF143427),
    accent           = Color(0xFF30D493),
    textPrimary      = Color(0xFFE7EFEB),
    card             = Color(0xFF12261E),
    cardAlt          = Color(0xFF0F1F18),
    fieldBorder      = Color(0xFF325D4C),
    bubbleOwn        = Color(0xFF206F4F),
    bubbleOther      = Color(0xFF12261E),
    bubbleSystem     = Color(0xFF0F1F18),
    dangerCard       = Color(0xFF1D201F),
    error            = Color(0xFFFF4444),
    primaryBlue      = Color(0xFF5AE2AC),
    inputBg          = Color(0xFF08120E),
    callBg           = Color(0xFF070D0B),
    callGradientEdge = Color(0xFF0A1410),
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

// Warm paper/sepia family, built around background #F0DEC6 and text #5A4634
// — a genuine sepia identity matching NAVY/DARK's own dark-theme look,
// rather than generic Material white. Full revision 2026-09-22: the first
// pass (below in git history) used a caramel/orange accent, which read as a
// second, competing accent system against the app's actual mint identity —
// replaced with the same #30D493 mint NAVY/DARK use, so "selected/active/
// accent" means the same color everywhere regardless of theme. Surfaces
// (card/dialog/topBar) are a warm off-white DERIVED from the background,
// never pure #FFFFFF — see the "no pure white cards on sepia" requirement.
// Text color is LIGHT-theme-only, per request — DARK/NAVY keep their own
// textPrimary unchanged.
val LightSubrosaColors = SubrosaColors(
    gradientStart    = Color(0xFFF7F3ED),
    gradientEnd      = Color(0xFFF0DEC6),
    // Top bar previously a dark brown lifted from an earlier draft — wrong
    // for a light theme (illegible with light status-bar icons, and reads
    // as "a dark theme's top bar pasted onto a light screen"). Now the same
    // warm surface tone as cards, so it "integrates" per spec rather than
    // standing out as its own competing surface.
    topBar           = Color(0xFFF0E7DB),
    dialog           = Color(0xFFF0E7DB),
    accent           = Color(0xFF30D493),   // mint — same as NAVY/DARK, not a competing orange/caramel accent
    textPrimary      = Color(0xFF5A4634),
    card             = Color(0xFFF0E7DB),   // warm surface, lighter than the #F0DEC6 background, never pure white
    cardAlt          = Color(0xFFECE2D5),
    fieldBorder      = Color(0xFFD9C3A6),
    bubbleOwn        = Color(0xFF30D493),   // mint bubble; textPrimary on top is ~4.6:1 contrast (AA pass)
    bubbleOther      = Color(0xFFF0E7DB),
    bubbleSystem     = Color(0xFFECE2D5),
    dangerCard       = Color(0xFFFFF0F0),
    error            = Color(0xFFCC2222),
    primaryBlue      = Color(0xFF30D493),   // same mint — one consistent accent, not a second competing color
    inputBg          = Color(0xFFECE2D5),
    callBg           = Color(0xFFE8D4BA),
    callGradientEdge = Color(0xFFDDBF98),
    isDark           = false
)

val LocalSubrosaColors = compositionLocalOf<SubrosaColors> { NavySubrosaColors }

fun subrosaColorsFor(theme: SubrosaTheme): SubrosaColors = when (theme) {
    SubrosaTheme.NAVY  -> NavySubrosaColors
    SubrosaTheme.DARK  -> DarkSubrosaColors
    SubrosaTheme.LIGHT -> LightSubrosaColors
}
