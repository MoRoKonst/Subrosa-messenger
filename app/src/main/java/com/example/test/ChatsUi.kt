package com.subrosa.messenger

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import com.subrosa.messenger.ui.components.IconTile
import com.subrosa.messenger.ui.components.IconTileColors
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlin.math.absoluteValue

/**
 * Chrome shared by the real chat list and the duress-mode decoy.
 *
 * These used to be two hand-maintained copies, and they had drifted badly
 * enough that the decoy was identifiable at a glance without opening a single
 * conversation: the real bar reads "SUBROSA" in NotoSerifJP next to a pulsing
 * connection dot and offers search, the decoy's read "Subrosa" in JetBrainsMono
 * with no dot and no search button. Rather than re-synchronise two copies and
 * let them drift again on the next UI change, both screens now call the same
 * composables — identity is a property of the code, not of someone remembering
 * to patch DecoyScreen whenever ChatsScreen changes.
 */

internal val avatarPalette = listOf(
    Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
    Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ChatsTopBar(
    searchMode: Boolean,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onToggleSearch: () -> Unit,
    onOpenProfile: () -> Unit,
    onCreate: () -> Unit
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current

    val myUserId = remember { UserStorage.getUserId(context) }
    val myDisplayName = remember { UserStorage.getUserDisplayName(context) }
    val myAvatarBitmap = AvatarStore.avatars[myUserId]
    val myAvatarColor = remember(myDisplayName) {
        avatarPalette[myDisplayName.hashCode().absoluteValue % avatarPalette.size]
    }

    TopAppBar(
        title = {
            if (searchMode) {
                BasicTextField(
                    value = searchQuery,
                    onValueChange = onSearchQueryChange,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    textStyle = TextStyle(fontSize = 18.sp, color = c.textPrimary, fontFamily = JetBrainsMono),
                    cursorBrush = SolidColor(c.accent),
                    decorationBox = { inner ->
                        if (searchQuery.isEmpty()) Text(
                            s.chatsSearchPlaceholder,
                            fontSize = 18.sp,
                            color = c.textPrimary.copy(alpha = 0.53f),
                            fontFamily = JetBrainsMono
                        )
                        inner()
                    }
                )
            } else {
                // Read from the same flow in both modes on purpose. Hardcoding
                // "connected" in the decoy would be a lie the rest of the UI
                // can contradict; showing the genuine transport state is both
                // simpler and consistent with whatever else is on screen.
                val isConnected by MessengerService.connectionState.collectAsState()
                val dotTransition = rememberInfiniteTransition(label = "dot")
                val dotPulse by dotTransition.animateFloat(
                    initialValue = 1f,
                    targetValue = if (isConnected) 1.55f else 1f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(900, easing = FastOutSlowInEasing),
                        repeatMode = RepeatMode.Reverse
                    ),
                    label = "dot_pulse"
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "SUBROSA",
                        color = c.textPrimary,
                        fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP,
                        fontWeight = FontWeight.Bold,
                        fontSize = 24.sp
                    )
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .graphicsLayer { scaleX = dotPulse; scaleY = dotPulse }
                            .clip(CircleShape)
                            .background(if (isConnected) Color(0xFF4CAF50) else Color(0xFF9E9E9E))
                    )
                }
            }
        },
        actions = {
            IconButton(onClick = onToggleSearch) {
                Icon(
                    painter = painterResource(if (searchMode) R.drawable.ic_close else R.drawable.ic_search),
                    contentDescription = null,
                    tint = c.textPrimary,
                    modifier = Modifier.size(22.dp)
                )
            }

            if (!searchMode) {
                Box(
                    modifier = Modifier
                        .padding(end = 6.dp)
                        .size(34.dp)
                        .clip(CircleShape)
                        .background(myAvatarColor)
                        .clickable { onOpenProfile() },
                    contentAlignment = Alignment.Center
                ) {
                    if (myAvatarBitmap != null) {
                        Image(
                            bitmap = myAvatarBitmap.asImageBitmap(),
                            contentDescription = myDisplayName,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.fillMaxSize().clip(CircleShape)
                        )
                    } else {
                        Text(
                            text = myDisplayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            fontFamily = JetBrainsMono
                        )
                    }
                }

                IconButton(onClick = onCreate) {
                    Icon(
                        painterResource(R.drawable.ic_plus),
                        contentDescription = s.chatsCreateTitle,
                        tint = c.textPrimary
                    )
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
    )
}

@Composable
internal fun ChatsEmptyState(title: String, hint: String? = null) {
    val c = LocalSubrosaColors.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = title,
            fontSize = if (hint == null) 18.sp else 20.sp,
            fontWeight = if (hint == null) FontWeight.Normal else FontWeight.SemiBold,
            color = c.textPrimary.copy(alpha = if (hint == null) 0.5f else 0.8f),
            fontFamily = JetBrainsMono
        )
        if (hint != null) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = hint,
                fontSize = 16.sp,
                color = c.textPrimary.copy(alpha = 0.45f),
                fontFamily = JetBrainsMono
            )
        }
    }
}

@Composable
internal fun OptionRow(
    label: String,
    labelColor: Color? = null,
    // Optional leading color-tile icon (see ui/components/IconTile.kt).
    leadingIcon: (@Composable () -> Unit)? = null,
    onClick: () -> Unit
) {
    val c = LocalSubrosaColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 14.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (leadingIcon != null) {
            leadingIcon()
            Spacer(modifier = Modifier.width(12.dp))
        }
        Text(
            text = label,
            fontSize = 18.sp,
            fontFamily = JetBrainsMono,
            color = labelColor ?: c.textPrimary
        )
    }
}

/** Long-press sheet on a chat row. `onDelete == null` renders without the
 *  delete option, which is how group and channel rows behave. */
@Composable
internal fun ChatActionsDialog(
    onMute: () -> Unit,
    onInfo: () -> Unit,
    onDelete: (() -> Unit)?,
    onDismiss: () -> Unit
) {
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = c.dialog,
        title = { Text(s.chatsActionsTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
        text = {
            Column {
                OptionRow(
                    label = s.chatsActionMute,
                    leadingIcon = { IconTile(iconRes = R.drawable.ic_bell_slash, tileColor = IconTileColors.warningAmber) }
                ) { onMute() }
                HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                OptionRow(
                    label = s.chatsActionInfo,
                    leadingIcon = { IconTile(iconRes = R.drawable.ic_user_circle, tileColor = IconTileColors.connectivityBlue) }
                ) { onInfo() }
                if (onDelete != null) {
                    HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f), thickness = 0.5.dp)
                    OptionRow(
                        label = s.chatsActionDelete,
                        labelColor = Color(0xFFEF5350),
                        leadingIcon = { IconTile(iconRes = R.drawable.ic_trash, tileColor = IconTileColors.mutedBurgundy) }
                    ) { onDelete() }
                }
            }
        },
        confirmButton = {}
    )
}

@Composable
internal fun ChatDeleteDialog(
    name: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = c.dialog,
        title = { Text(s.chatsDeleteTitle, color = c.textPrimary, fontFamily = JetBrainsMono) },
        text = {
            Text(
                s.chatsDeleteText(name),
                color = c.textPrimary,
                fontFamily = JetBrainsMono,
                fontSize = 16.sp
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(s.delete, color = Color(0xFFEF5350), fontFamily = JetBrainsMono)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
            }
        }
    )
}
