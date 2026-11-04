package com.subrosa.messenger.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.subrosa.messenger.R

// App-wide typeface pair, replacing the previous single JetBrains Mono
// everywhere. NotoSerifJP is the display/heading face — app name, large
// titles, profile screen, contact/group names. Inter is the body/UI face —
// messages, settings, labels, timestamps, buttons. Both ship as a single
// variable-font file (see THIRD_PARTY_LICENSES.md); Compose maps
// FontWeight on a TextStyle onto the variable weight axis automatically.
val NotoSerifJP = FontFamily(Font(R.font.noto_serif_jp_variable))
val Inter = FontFamily(Font(R.font.inter_variable))

val Typography = Typography(
    bodyLarge = TextStyle(
        fontFamily = Inter,
        fontWeight = FontWeight.Normal,
        fontSize = 18.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.5.sp
    )
)