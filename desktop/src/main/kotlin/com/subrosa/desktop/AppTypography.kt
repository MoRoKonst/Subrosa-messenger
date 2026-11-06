package com.subrosa.desktop

import androidx.compose.material3.Typography

// Central Inter typography for the MaterialTheme root (AppNavigation.kt) —
// Desktop previously set no typography at all, falling back to Compose's
// built-in default font everywhere. Every Text() call in this codebase that
// doesn't set fontFamily explicitly resolves through LocalTextStyle, which
// MaterialTheme seeds from these role styles — so this one central change
// applies Inter app-wide without touching every call site. The handful of
// heading/name spots (app identity, profile/settings name, contact/group
// names) get an explicit fontFamily = NotoSerifJP override at their own
// call sites instead, same as Android's Type.kt + per-screen overrides.
private val base = Typography()

val SubrosaTypography = Typography(
    displayLarge = base.displayLarge.copy(fontFamily = Inter),
    displayMedium = base.displayMedium.copy(fontFamily = Inter),
    displaySmall = base.displaySmall.copy(fontFamily = Inter),
    headlineLarge = base.headlineLarge.copy(fontFamily = Inter),
    headlineMedium = base.headlineMedium.copy(fontFamily = Inter),
    headlineSmall = base.headlineSmall.copy(fontFamily = Inter),
    titleLarge = base.titleLarge.copy(fontFamily = Inter),
    titleMedium = base.titleMedium.copy(fontFamily = Inter),
    titleSmall = base.titleSmall.copy(fontFamily = Inter),
    bodyLarge = base.bodyLarge.copy(fontFamily = Inter),
    bodyMedium = base.bodyMedium.copy(fontFamily = Inter),
    bodySmall = base.bodySmall.copy(fontFamily = Inter),
    labelLarge = base.labelLarge.copy(fontFamily = Inter),
    labelMedium = base.labelMedium.copy(fontFamily = Inter),
    labelSmall = base.labelSmall.copy(fontFamily = Inter)
)
