package com.subrosa.desktop

import androidx.compose.ui.graphics.Color

/**
 * Custom color palette matching Android's NAVY theme — emerald/mint family
 * built around accent #30D493 (same hue everywhere, only saturation/
 * lightness varied: darker for backgrounds/bubbles, lighter for badges/
 * ticks/text). Replaces the previous burgundy/antique-gold palette,
 * user-requested recolor, 2026-09-22. See SubrosaColors.kt (Android) for
 * the mirrored NavySubrosaColors this was derived from.
 * Access via SubrosaTheme.colors from any Composable.
 */
object SubrosaTheme {
    // ── Navy (default) — mirrors Android's NavySubrosaColors ───────────────────
    val gradientStart  = Color(0xFF0D1C16)
    val gradientEnd    = Color(0xFF08120E)
    val topBar         = Color(0xFF143427)
    val dialog         = Color(0xFF143427)
    val accent         = Color(0xFF30D493)   // emerald/mint
    val textPrimary    = Color(0xFFE7EFEB)
    val card           = Color(0xFF12261E)
    val cardAlt        = Color(0xFF0F1F18)
    val fieldBorder    = Color(0xFF325D4C)
    val bubbleOwn      = Color(0xFF206F4F)
    val bubbleOther    = Color(0xFF12261E)
    val bubbleSystem   = Color(0xFF0F1F18)
    val dangerCard     = Color(0xFF1D201F)
    val error          = Color(0xFFFF4444)
    val primaryBlue    = Color(0xFF5AE2AC)   // for badges, reactions — bright mint, name kept for API stability
    val inputBg        = Color(0xFF08120E)
    // Desktop-only fields (no Android equivalent) — kept within the same
    // emerald/mint family rather than copied 1:1.
    val textSecondary  = Color(0xFFA1BAB0)   // muted text
    val divider        = Color(0xFF213B30)
    val unreadBadge    = Color(0xFF5AE2AC)
    val readTick       = Color(0xFF30D493)   // ✓✓ color (read)
    val sentTick       = Color(0xFF628476)   // ✓ color (sent only)
}
