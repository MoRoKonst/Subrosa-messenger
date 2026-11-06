package com.subrosa.desktop

import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.platform.Font

// App-wide typeface pair, mirroring Android's ui/theme/Type.kt — previously
// Desktop had no custom typography at all (pure system-default font).
// NotoSerifJP is the display/heading face — app name, large titles,
// profile/settings screen, contact/group names. Inter is the body/UI face —
// messages, settings rows, labels, timestamps, buttons.
//
// Note the import: androidx.compose.ui.text.platform.Font (not
// androidx.compose.ui.text.font.Font, which on this Compose Multiplatform
// version only exposes the Android-resource-id overload). The platform
// variant resolves a classpath resource path — works both when running
// from Gradle and from the packaged native distribution, unlike a
// java.io.File-based overload which would break once bundled into a jar.
// Same font files bundled on Android — see THIRD_PARTY_LICENSES.md.
val NotoSerifJP = FontFamily(Font("font/noto_serif_jp_variable.ttf"))
val Inter = FontFamily(Font("font/inter_variable.ttf"))
