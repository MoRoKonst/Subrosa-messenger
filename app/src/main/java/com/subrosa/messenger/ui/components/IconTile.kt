package com.subrosa.messenger.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Telegram-like "colored tile + glyph" row icon — a small rounded-square
 * background carrying a section's identity color, with a white icon
 * centered on top, so a row's category reads before its label text does.
 * Icons must come from the provided Phosphor pack only, one weight
 * (fill) per icon, no mixing.
 *
 * Approved after a 3-row trial (add contact / security / appearance) and
 * now rolled out across the rest of Android's settings/navigation rows —
 * see IconTileColors below for the semantic color mapping, and ChatsScreen
 * .kt / ProfileScreen.kt for call sites. Desktop and the message-composer
 * action bar are intentionally not touched yet.
 */
@Composable
fun IconTile(
    iconRes: Int,
    tileColor: Color,
    modifier: Modifier = Modifier,
    iconTint: Color = Color.White,
    tileSize: Dp = 32.dp,
    cornerRadius: Dp = 8.dp,
    iconSize: Dp = 19.dp
) {
    Box(
        modifier = modifier
            .size(tileSize)
            .background(tileColor, RoundedCornerShape(cornerRadius)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            painter = painterResource(iconRes),
            contentDescription = null,
            tint = iconTint,
            modifier = Modifier.size(iconSize)
        )
    }
}

/**
 * Centralized semantic color mapping — one fixed color per category, shared
 * by every row in that category, independent of the active SubrosaTheme so
 * a tile reads the same in NAVY/DARK/LIGHT (same idea as Telegram's per-row
 * tile colors not shifting with dark mode). Adjusting a category's color
 * here updates every row using it; do not hand-pick one-off colors per row.
 *
 *  - mintGreen:      contacts / positive / active     (add contact, create group, invite & QR)
 *  - mutedBurgundy:  security / destructive            (security)
 *  - mutedPurple:    appearance / personalization       (theme)
 *  - connectivityBlue: devices / connectivity / calls  (servers, Tor, battery)
 *  - warningAmber:   keys / backup / warnings           (backup)
 *  - neutralGrayBrown: general / account                (general settings, language, about/source)
 */
object IconTileColors {
    val mintGreen = Color(0xFF32C176)
    val mutedBurgundy = Color(0xFFA8555F)
    val mutedPurple = Color(0xFF8E7CC3)
    val connectivityBlue = Color(0xFF4FA3C7)
    val warningAmber = Color(0xFFC99A3E)
    val neutralGrayBrown = Color(0xFF8C8175)
}
