package com.subrosa.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.loadImageBitmap
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.absoluteValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ─── Avatar color palette ──────────────────────────────────────────────────
// Byte-identical to Android's avatarPalette (ChatsScreen.kt) — String.
// hashCode() is stable across JVMs, so with the same palette + same modulo
// logic the same contact name resolves to the same color on both platforms.
// Previously used a different set of hex values here despite the "matches
// Android" claim in the old comment — fixed as part of the avatar parity
// pass (contact avatars were entirely unrendered on Desktop before this).

val AVATAR_COLORS = listOf(
    Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
    Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
)

fun avatarColor(name: String): Color =
    AVATAR_COLORS[name.hashCode().absoluteValue % AVATAR_COLORS.size]

// ─── Settings group components ────────────────────────────────────────────────

@Composable
internal fun SHeader(label: String) {
    Row(
        modifier = Modifier
            .padding(horizontal = 16.dp)
            .padding(top = 20.dp, bottom = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .width(3.dp)
                .height(11.dp)
                .background(SubrosaTheme.accent, RoundedCornerShape(2.dp))
        )
        Spacer(Modifier.width(8.dp))
        Text(
            text          = label.uppercase(),
            fontSize = 12.sp,
            fontWeight    = FontWeight.Bold,
            color         = SubrosaTheme.textSecondary,
            letterSpacing = 1.4.sp
        )
    }
}

@Composable
internal fun SGroup(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
        shape    = RoundedCornerShape(14.dp),
        color    = SubrosaTheme.card
    ) { Column(content = content) }
}

@Composable
internal fun SItem(
    icon:       String,
    label:      String,
    hint:       String?  = null,
    labelColor: Color?   = null,
    onClick:    (() -> Unit)? = null,
    end: @Composable () -> Unit = {}
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 14.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon.isNotBlank()) {
            Box(
                modifier = Modifier
                    .size(30.dp)
                    .background(SubrosaTheme.accent.copy(alpha = 0.13f), RoundedCornerShape(7.dp)),
                contentAlignment = Alignment.Center
            ) { Text(icon, fontSize = 16.sp) }
            Spacer(Modifier.width(12.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(
                text  = label,
                fontSize = 16.sp,
                color = labelColor ?: SubrosaTheme.textPrimary
            )
            if (hint != null) {
                Text(
                    text     = hint,
                    fontSize = 13.sp,
                    color    = SubrosaTheme.textSecondary,
                    maxLines = 1
                )
            }
        }
        Spacer(Modifier.width(4.dp))
        end()
    }
}

@Composable
internal fun SLine() {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(start = 56.dp)
            .height(0.5.dp)
            .background(SubrosaTheme.textSecondary.copy(alpha = 0.1f))
    )
}

// ─── Main screen ──────────────────────────────────────────────────────────────

@Composable
fun ProfileScreen(onBack: () -> Unit, onOpenTotp: () -> Unit = {}, onOpenSecurityGuide: () -> Unit = {}, onOpenBackup: () -> Unit = {}) {
    val s            = LocalStrings.current
    val clipboard    = LocalClipboardManager.current
    val scrollState  = rememberScrollState()
    val scope        = rememberCoroutineScope()

    val displayName  = UserStorage.getUsername()
    val myId         = WebSocketClient.myFingerprint
    val emojiId: String = remember(myId) { fingerprintToEmoji(myId) }

    // Own avatar — mirrors Android's identical pick/scale/send flow
    // (128x128 JPEG @85%, base64, pushed as profile_update). Was entirely
    // missing on Desktop: no upload UI and no rendering of a set avatar.
    var myAvatarBitmap by remember { mutableStateOf<ImageBitmap?>(null) }
    LaunchedEffect(Unit) {
        val b64 = UserStorage.getMyAvatar()
        if (!b64.isNullOrBlank()) {
            withContext(Dispatchers.IO) {
                try {
                    val bytes = java.util.Base64.getDecoder().decode(b64)
                    val bmp = loadImageBitmap(java.io.ByteArrayInputStream(bytes))
                    withContext(Dispatchers.Main) { myAvatarBitmap = bmp }
                } catch (_: Exception) {}
            }
        }
    }
    // Decoded but not-yet-cropped picked photo — shown via AvatarCropDialog
    // below. Was previously stretched straight into a 128x128 square with
    // g.drawImage(original, 0, 0, 128, 128, null), distorting the aspect
    // ratio of any non-square photo; the crop dialog now lets the user pick
    // which part to keep (drag to pan, scroll wheel/slider to zoom) before
    // it's scaled down.
    var pendingAvatarImage by remember { mutableStateOf<java.awt.image.BufferedImage?>(null) }

    fun pickAvatar() {
        val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Выбрать фото", java.awt.FileDialog.LOAD)
        dialog.isVisible = true
        val fileName = dialog.file
        val dir = dialog.directory
        if (fileName == null || dir == null) return
        val picked = java.io.File(dir, fileName)
        scope.launch(Dispatchers.IO) {
            try {
                val original = javax.imageio.ImageIO.read(picked) ?: return@launch
                withContext(Dispatchers.Main) { pendingAvatarImage = original }
            } catch (_: Exception) {}
        }
    }

    fun applyCroppedAvatar(cropped: java.awt.image.BufferedImage) {
        pendingAvatarImage = null
        scope.launch(Dispatchers.IO) {
            try {
                val out = java.io.ByteArrayOutputStream()
                javax.imageio.ImageIO.write(cropped, "jpg", out)
                val b64 = java.util.Base64.getEncoder().encodeToString(out.toByteArray())
                UserStorage.saveMyAvatar(b64)
                AvatarStore.decodeAndStore(myId, b64)
                WebSocketClient.sendMyAvatarUpdate(b64)
                withContext(Dispatchers.Main) {
                    myAvatarBitmap = loadImageBitmap(java.io.ByteArrayInputStream(out.toByteArray()))
                }
            } catch (_: Exception) {}
        }
    }

    // Invite link
    var inviteLink   by remember { mutableStateOf("") }
    var linkCopied   by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { inviteLink = InviteCodeManager.generateInviteLink() }

    // Server list — see the Server section below, now a chevron row that
    // opens the shared ServerSettingsDialog instead of its own fields.
    var showServerSettings by remember { mutableStateOf(false) }

    // Tor — routes ALL traffic through the local Tor SOCKS proxy regardless
    // of server address, mirrors Android's isTorEnabled toggle. Was missing
    // on Desktop: Tor only ever auto-activated for literal .onion server
    // URLs, giving no anonymization benefit for a normal clearnet server.
    var torEnabled by remember { mutableStateOf(UserStorage.getTorEnabled()) }

    // "Hide IP during calls" — forces relay-only WebRTC (no direct/host/
    // srflx ICE candidates), read fresh by DesktopCallManager on every new
    // PeerConnection. See UserStorage.getHideIpDuringCalls()'s own comment.
    var hideIpDuringCalls by remember { mutableStateOf(UserStorage.getHideIpDuringCalls()) }

    var notificationsEnabled by remember { mutableStateOf(UserStorage.getNotificationsEnabled()) }
    var notificationSoundEnabled by remember { mutableStateOf(UserStorage.getNotificationSoundEnabled()) }

    // Panic password — separate from the real login password; entering it
    // instead shows a fake messenger while destroying real data in the
    // background. Was missing entirely from Desktop before this fix.
    var showPanicDialog by remember { mutableStateOf(false) }

    // Change password dialog
    var showPasswordDialog by remember { mutableStateOf(false) }

    // Security diagnostics
    var showDiagDialog by remember { mutableStateOf(false) }
    var diagRunning    by remember { mutableStateOf(false) }
    var diagResults    by remember { mutableStateOf<List<DiagResult>>(emptyList()) }

    // Exit on debugger toggle
    var exitOnDebugger by remember { mutableStateOf(UserStorage.getExitOnDebugger()) }

    // Cover traffic mode (constant-rate noise packets masking real-message timing)
    var coverTrafficMode by remember { mutableStateOf(UserStorage.getCoverTrafficMode()) }

    // Auto-lock timeout
    var autoLockTimeout    by remember { mutableStateOf(UserStorage.getAutoLockTimeout()) }
    var showAutoLockDialog by remember { mutableStateOf(false) }

    // Duress / compromise confirmation dialogs
    var showNotMeConfirm       by remember { mutableStateOf(false) }
    var showCompromisedConfirm by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {

        // ── Top bar ───────────────────────────────────────────────────────────
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(
                        AppIcons.get("BACK_ARROW"),
                        contentDescription = "Назад",
                        tint = SubrosaTheme.textPrimary
                    )
                }
                Text(
                    s.profileTitle,
                    fontSize = 19.sp,
                    fontWeight = FontWeight.SemiBold,
                    color      = SubrosaTheme.textPrimary
                )
            }
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(bottom = 24.dp)
        ) {

            // ── Profile card ──────────────────────────────────────────────────
            Spacer(Modifier.height(20.dp))
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp),
                shape    = RoundedCornerShape(18.dp),
                color    = SubrosaTheme.card
            ) {
                Column(
                    modifier            = Modifier.fillMaxWidth().padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        modifier         = Modifier
                            .size(72.dp)
                            .clip(CircleShape)
                            .background(avatarColor(displayName))
                            .clickable { pickAvatar() },
                        contentAlignment = Alignment.Center
                    ) {
                        val bmp = myAvatarBitmap
                        if (bmp != null) {
                            Image(
                                bitmap = bmp,
                                contentDescription = displayName,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.fillMaxSize()
                            )
                        } else {
                            Text(
                                text       = displayName.take(1).uppercase(),
                                fontSize = 30.sp,
                                fontWeight = FontWeight.Bold,
                                color      = Color.White
                            )
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        s.profileChangePhoto,
                        fontSize = 12.sp,
                        color    = SubrosaTheme.textSecondary
                    )

                    Spacer(Modifier.height(12.dp))
                    Text(
                        displayName,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color      = SubrosaTheme.textPrimary,
                        fontFamily = NotoSerifJP
                    )
                    Spacer(Modifier.height(6.dp))

                    if (emojiId.isNotEmpty()) {
                        Surface(
                            shape  = RoundedCornerShape(8.dp),
                            color  = SubrosaTheme.accent.copy(alpha = 0.13f)
                        ) {
                            Text(
                                text     = emojiId,
                                fontSize = 20.sp,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                    }

                    Text(
                        text       = myId,
                        fontSize = 13.sp,
                        color      = SubrosaTheme.textSecondary,
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            // ── Identity section ──────────────────────────────────────────────
            SHeader(s.profileSectionIdentity)
            SGroup {
                SItem(
                    icon  = "",
                    label = s.profileMyInvite,
                    hint  = if (inviteLink.length > 40)
                                inviteLink.take(40) + "…"
                            else inviteLink
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(
                            onClick = {
                                // Explicit rotation on copy — mirrors Android's
                                // ProfileScreen.kt regenerateInviteCode(), wired
                                // to the same Copy button (desktop/Android
                                // symmetry audit, 2026-09-03): closes the
                                // exposure window on whatever code was shown
                                // before, the moment the user actually hands a
                                // fresh one out.
                                inviteLink = InviteCodeManager.regenerateInviteLink()
                                clipboard.setText(AnnotatedString(inviteLink))
                                linkCopied = true
                            },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Text(
                                if (linkCopied) s.copied else s.copy,
                                fontSize = 16.sp,
                                color    = SubrosaTheme.accent
                            )
                        }
                        // Desktop has no OS-level share sheet the way Android
                        // does — the closest real system integration is
                        // handing the link to the user's default mail client
                        // via a mailto: URI, falling back to a plain
                        // clipboard copy (same action as the Copy button
                        // above) if mail isn't supported on this platform,
                        // rather than silently doing nothing.
                        TextButton(
                            onClick = {
                                inviteLink = InviteCodeManager.regenerateInviteLink()
                                try {
                                    val desktop = java.awt.Desktop.getDesktop()
                                    if (java.awt.Desktop.isDesktopSupported() && desktop.isSupported(java.awt.Desktop.Action.MAIL)) {
                                        val body = java.net.URLEncoder.encode(inviteLink, "UTF-8").replace("+", "%20")
                                        desktop.mail(java.net.URI("mailto:?subject=Subrosa&body=$body"))
                                    } else {
                                        clipboard.setText(AnnotatedString(inviteLink))
                                        linkCopied = true
                                    }
                                } catch (_: Exception) {
                                    clipboard.setText(AnnotatedString(inviteLink))
                                    linkCopied = true
                                }
                            },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Text(
                                s.profileShareCode,
                                fontSize = 16.sp,
                                color    = SubrosaTheme.accent
                            )
                        }
                    }
                }
                SLine()
                SItem(
                    icon  = "",
                    label = s.profileFingerprint,
                    hint  = myId
                ) {}
            }

            // ── Server section ────────────────────────────────────────────────
            // Replaced the old ad-hoc single-URL + access-code text fields
            // (which duplicated ServerManager's own storage keys via a
            // separate, inconsistent path) with a chevron row opening the
            // same ServerSettingsDialog already used from Login/Register/
            // TotpSettings — mirrors Android's Profile "Servers" row exactly
            // (PRow(s.profileServers, onClick = onOpenServers)), and gives
            // Desktop the same multi-server list/switch UI those other
            // screens already have instead of a single free-text URL field.
            SHeader(s.profileSectionServer)
            SGroup {
                SItem(
                    icon    = "",
                    label   = s.profileServers,
                    onClick = { showServerSettings = true }
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
            }

            // ── Backup section ────────────────────────────────────────────────
            SHeader(s.profileSectionBackup)
            SGroup {
                SItem(
                    icon    = "",
                    label   = s.profileBackupItem,
                    hint    = s.profileBackupHint,
                    onClick = onOpenBackup
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
            }

            // ── Security section ──────────────────────────────────────────────
            SHeader(s.profileSectionSecurity)
            SGroup {
                SItem(
                    icon    = "",
                    label   = s.profileChangePassword,
                    onClick = { showPasswordDialog = true }
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
                SLine()
                SItem(
                    icon    = "",
                    label   = s.profileTotp,
                    hint    = if (TotpManager.isEnabled()) s.profileTotpEnabled else s.profileTotpDisabled,
                    onClick = onOpenTotp
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
                SLine()
                SItem(
                    icon  = "",
                    label = s.profileAutoLock,
                    hint  = when (autoLockTimeout) {
                        0    -> s.profileAutoLockOff
                        300  -> s.profileAutoLock5min
                        900  -> s.profileAutoLock15min
                        1800 -> s.profileAutoLock30min
                        3600 -> s.profileAutoLock1h
                        else -> "${autoLockTimeout / 60} min"
                    },
                    onClick = { showAutoLockDialog = true }
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
                SLine()
                SItem(
                    icon  = "",
                    label = s.profileExitOnDebugger,
                    hint  = s.profileExitOnDebuggerHint
                ) {
                    Switch(
                        checked         = exitOnDebugger,
                        onCheckedChange = {
                            exitOnDebugger = it
                            UserStorage.setExitOnDebugger(it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor       = SubrosaTheme.accent,
                            checkedTrackColor       = SubrosaTheme.accent.copy(alpha = 0.35f),
                            uncheckedThumbColor     = SubrosaTheme.textSecondary,
                            uncheckedTrackColor     = SubrosaTheme.textSecondary.copy(alpha = 0.2f)
                        )
                    )
                }
                SLine()
                SItem(
                    icon  = "",
                    label = s.profileCoverTraffic,
                    hint  = when (coverTrafficMode) {
                        UserStorage.CoverTrafficMode.OFF        -> s.profileCoverTrafficOff
                        UserStorage.CoverTrafficMode.MODERATE   -> s.profileCoverTrafficModerate
                        UserStorage.CoverTrafficMode.AGGRESSIVE -> s.profileCoverTrafficAggressive
                    },
                    onClick = {
                        val next = when (coverTrafficMode) {
                            UserStorage.CoverTrafficMode.OFF        -> UserStorage.CoverTrafficMode.MODERATE
                            UserStorage.CoverTrafficMode.MODERATE   -> UserStorage.CoverTrafficMode.AGGRESSIVE
                            UserStorage.CoverTrafficMode.AGGRESSIVE -> UserStorage.CoverTrafficMode.OFF
                        }
                        coverTrafficMode = next
                        UserStorage.setCoverTrafficMode(next)
                        WebSocketClient.applyCoverTrafficModeChange()
                    }
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
                SLine()
                SItem(
                    icon  = "",
                    label = s.profileTorToggle,
                    hint  = s.profileTorToggleHint
                ) {
                    Switch(
                        checked         = torEnabled,
                        onCheckedChange = {
                            torEnabled = it
                            UserStorage.setTorEnabled(it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor   = SubrosaTheme.accent,
                            checkedTrackColor   = SubrosaTheme.accent.copy(alpha = 0.35f),
                            uncheckedThumbColor = SubrosaTheme.textSecondary,
                            uncheckedTrackColor = SubrosaTheme.textSecondary.copy(alpha = 0.2f)
                        )
                    )
                }
                SLine()
                SItem(
                    icon  = "",
                    label = s.profileHideIpCalls,
                    hint  = s.profileHideIpCallsHint
                ) {
                    Switch(
                        checked         = hideIpDuringCalls,
                        onCheckedChange = {
                            hideIpDuringCalls = it
                            UserStorage.setHideIpDuringCalls(it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor   = SubrosaTheme.accent,
                            checkedTrackColor   = SubrosaTheme.accent.copy(alpha = 0.35f),
                            uncheckedThumbColor = SubrosaTheme.textSecondary,
                            uncheckedTrackColor = SubrosaTheme.textSecondary.copy(alpha = 0.2f)
                        )
                    )
                }
                SLine()
                SItem(
                    icon    = "",
                    label   = s.profileDiagnostics,
                    hint    = s.profileDiagnosticsHint,
                    onClick = {
                        showDiagDialog = true
                        diagRunning    = true
                        diagResults    = emptyList()
                        scope.launch(Dispatchers.IO) {
                            val results = runSecurityDiagnostics()
                            diagRunning = false
                            diagResults = results
                        }
                    }
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
                SLine()
                SItem(
                    icon    = "",
                    label   = s.profilePanicPassword,
                    hint    = s.profilePanicPasswordHint,
                    onClick = { showPanicDialog = true }
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
            }

            SHeader(s.profileSectionNotifications)
            SGroup {
                SItem(
                    icon  = "",
                    label = s.profileNotificationsEnabled,
                    hint  = s.profileNotificationsEnabledHint
                ) {
                    Switch(
                        checked         = notificationsEnabled,
                        onCheckedChange = {
                            notificationsEnabled = it
                            UserStorage.setNotificationsEnabled(it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor   = SubrosaTheme.accent,
                            checkedTrackColor   = SubrosaTheme.accent.copy(alpha = 0.35f),
                            uncheckedThumbColor = SubrosaTheme.textSecondary,
                            uncheckedTrackColor = SubrosaTheme.textSecondary.copy(alpha = 0.2f)
                        )
                    )
                }
                SLine()
                SItem(
                    icon  = "",
                    label = s.profileNotificationSound,
                    hint  = s.profileNotificationSoundHint
                ) {
                    Switch(
                        checked         = notificationSoundEnabled,
                        onCheckedChange = {
                            notificationSoundEnabled = it
                            UserStorage.setNotificationSoundEnabled(it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor   = SubrosaTheme.accent,
                            checkedTrackColor   = SubrosaTheme.accent.copy(alpha = 0.35f),
                            uncheckedThumbColor = SubrosaTheme.textSecondary,
                            uncheckedTrackColor = SubrosaTheme.textSecondary.copy(alpha = 0.2f)
                        )
                    )
                }
            }

            SHeader(s.profileSectionAbout)
            SGroup {
                SItem(
                    icon  = "",
                    label = s.profileLanguage,
                    hint  = if (AppLanguage.code == "en") "English" else "Русский"
                ) {
                    Switch(
                        checked         = AppLanguage.code == "en",
                        onCheckedChange = { AppLanguage.toggle() },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor   = SubrosaTheme.accent,
                            checkedTrackColor   = SubrosaTheme.accent.copy(alpha = 0.35f),
                            uncheckedThumbColor = SubrosaTheme.textSecondary,
                            uncheckedTrackColor = SubrosaTheme.textSecondary.copy(alpha = 0.2f)
                        )
                    )
                }
                SLine()
                SItem(
                    icon    = "",
                    label   = s.profileSecurityGuide,
                    hint    = s.profileSecurityGuideHint,
                    onClick = onOpenSecurityGuide
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
                SLine()
                SItem(
                    icon    = "",
                    label   = s.profileSourceCode,
                    onClick = {
                        try {
                            java.awt.Desktop.getDesktop().browse(java.net.URI("https://github.com/MoRoKonst/Subrosa-messenger"))
                        } catch (_: Exception) {}
                    }
                ) {
                    Text("›", fontSize = 21.sp, color = SubrosaTheme.accent.copy(alpha = 0.5f))
                }
            }

            // ── Duress / compromise actions ──────────────────────────────────
            // Mirrors Android's ProfileScreen.kt "Это не я"/"Меня
            // скомпрометировали" cards — entirely missing from Desktop
            // before this fix (found in the 2026-09-12 full-logic audit).
            // revoke_identity in particular is a protocol-level feature,
            // not tied to being a phone, so its absence here was a real
            // security gap, not an accepted platform limitation.
            Spacer(Modifier.height(24.dp))
            Surface(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)
                    .clickable { showNotMeConfirm = true },
                shape = RoundedCornerShape(16.dp),
                color = SubrosaTheme.error.copy(alpha = 0.09f)
            ) {
                Text(
                    s.profileNotMe,
                    fontSize = 17.sp,
                    color    = SubrosaTheme.error,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 16.dp)
                )
            }
            Spacer(Modifier.height(12.dp))
            Surface(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)
                    .clickable { showCompromisedConfirm = true },
                shape = RoundedCornerShape(16.dp),
                color = SubrosaTheme.error.copy(alpha = 0.09f)
            ) {
                Text(
                    s.profileCompromised,
                    fontSize = 17.sp,
                    color    = SubrosaTheme.error,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 16.dp)
                )
            }
        }
    }

    if (showNotMeConfirm) {
        AlertDialog(
            onDismissRequest = { showNotMeConfirm = false },
            containerColor   = SubrosaTheme.dialog,
            title = { Text("Экстренная очистка", color = SubrosaTheme.textPrimary) },
            text  = {
                Text(
                    "Немедленно и безвозвратно уничтожит всю переписку, контакты и ключ " +
                    "идентификации на этом устройстве. Отменить нельзя. Приложение закроется.",
                    color = SubrosaTheme.textSecondary
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showNotMeConfirm = false
                    EmergencyWipe.wipeEverythingAndExit()
                }) { Text("Уничтожить всё", color = SubrosaTheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showNotMeConfirm = false }) {
                    Text("Отмена", color = SubrosaTheme.textSecondary)
                }
            }
        )
    }

    if (showCompromisedConfirm) {
        AlertDialog(
            onDismissRequest = { showCompromisedConfirm = false },
            containerColor   = SubrosaTheme.dialog,
            title = { Text("Меня скомпрометировали", color = SubrosaTheme.textPrimary) },
            text  = {
                Text(
                    "Сервер пометит текущий fingerprint как отозванный (его больше нельзя " +
                    "будет использовать для регистрации), локальная переписка и контакты " +
                    "будут удалены. Приложение закроется — при следующем запуске нужно " +
                    "будет создать новый аккаунт.",
                    color = SubrosaTheme.textSecondary
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showCompromisedConfirm = false
                    scope.launch {
                        WebSocketClient.requestIdentityRevocation()
                        BackupManager.resetCompromisedIdentity()
                        kotlin.system.exitProcess(0)
                    }
                }) { Text("Подтвердить", color = SubrosaTheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showCompromisedConfirm = false }) {
                    Text("Отмена", color = SubrosaTheme.textSecondary)
                }
            }
        )
    }

    // ── Change password dialog ─────────────────────────────────────────────────
    if (showPasswordDialog) {
        ChangePasswordDialog(onDismiss = { showPasswordDialog = false })
    }

    if (showServerSettings) {
        ServerSettingsDialog(onDismiss = { showServerSettings = false })
    }

    if (showPanicDialog) {
        PanicPasswordDialog(onDismiss = { showPanicDialog = false })
    }

    // ── Security diagnostics dialog ────────────────────────────────────────────
    if (showDiagDialog) {
        DiagnosticsDialog(
            running   = diagRunning,
            results   = diagResults,
            onDismiss = { showDiagDialog = false }
        )
    }

    // ── Auto-lock timeout picker ────────────────────────────────────────────────
    if (showAutoLockDialog) {
        AutoLockTimeoutDialog(
            current  = autoLockTimeout,
            onSelect = { secs ->
                autoLockTimeout = secs
                UserStorage.setAutoLockTimeout(secs)
                showAutoLockDialog = false
            },
            onDismiss = { showAutoLockDialog = false }
        )
    }

    pendingAvatarImage?.let { img ->
        AvatarCropDialog(
            source = img,
            onConfirm = { cropped -> applyCroppedAvatar(cropped) },
            onCancel = { pendingAvatarImage = null }
        )
    }
}

@Composable
private fun ChangePasswordDialog(onDismiss: () -> Unit) {
    var oldPwd   by remember { mutableStateOf("") }
    var newPwd   by remember { mutableStateOf("") }
    var newPwd2  by remember { mutableStateOf("") }
    var totpCode by remember { mutableStateOf("") }
    var error    by remember { mutableStateOf("") }
    var success  by remember { mutableStateOf(false) }
    val totpEnabled = remember { TotpManager.isEnabled() }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title  = { Text("Сменить пароль", color = SubrosaTheme.textPrimary) },
        text   = {
            Column {
                if (success) {
                    Text("Пароль успешно изменён", color = SubrosaTheme.accent)
                } else {
                    SecureTextField(
                        value                = oldPwd,
                        onValueChange        = { oldPwd = it; error = "" },
                        label                = "Текущий пароль",
                        modifier             = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    SecureTextField(
                        value                = newPwd,
                        onValueChange        = { newPwd = it; error = "" },
                        label                = "Новый пароль",
                        modifier             = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    SecureTextField(
                        value                = newPwd2,
                        onValueChange        = { newPwd2 = it; error = "" },
                        label                = "Повторите пароль",
                        modifier             = Modifier.fillMaxWidth(),
                        isError              = newPwd2.isNotEmpty() && newPwd2 != newPwd
                    )
                    if (totpEnabled) {
                        Spacer(Modifier.height(8.dp))
                        SecureTextField(
                            value                = totpCode,
                            onValueChange        = { totpCode = it; error = "" },
                            label                = "Текущий TOTP-код",
                            modifier             = Modifier.fillMaxWidth()
                        )
                    }
                    if (error.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text(error, color = SubrosaTheme.error, fontSize = 14.sp)
                    }
                }
            }
        },
        confirmButton = {
            if (success) {
                TextButton(onClick = onDismiss) { Text("Закрыть", color = SubrosaTheme.accent) }
            } else {
                Button(
                    onClick = {
                        val totpSecret = if (totpEnabled) TotpManager.getSecret() else null
                        when {
                            !UserStorage.checkPassword(oldPwd) -> error = "Неверный текущий пароль"
                            totpEnabled && (totpSecret == null || !TotpManager.verifyCode(totpSecret, totpCode)) -> error = "Неверный код"
                            newPwd.length < PasswordPolicy.MIN_LENGTH -> error = "Новый пароль минимум ${PasswordPolicy.MIN_LENGTH} символов"
                            PasswordPolicy.isCommonPassword(newPwd) -> error = "Этот пароль слишком предсказуем (например, простая последовательность цифр) — выберите менее очевидный"
                            newPwd2 != newPwd                  -> error = "Пароли не совпадают"
                            else -> {
                                UserStorage.changePassword(oldPwd, newPwd)
                                StorageKeyManager.changePassword(newPwd)  // перешифровать SMK
                                success = true
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.accent)
                ) { Text("Сохранить") }
            }
        },
        dismissButton = {
            if (!success) {
                TextButton(onClick = onDismiss) {
                    Text("Отмена", color = SubrosaTheme.textSecondary)
                }
            }
        }
    )
}

// ── Panic password dialog ─────────────────────────────────────────────────────

@Composable
private fun PanicPasswordDialog(onDismiss: () -> Unit) {
    val s = LocalStrings.current
    var panicPassword by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title = { Text(s.profilePanicSetTitle, color = SubrosaTheme.textPrimary) },
        text  = {
            Column {
                Text(
                    s.profilePanicSetInstruction,
                    color    = Color(0xFFFFB74D),
                    fontSize = 15.sp
                )
                Spacer(Modifier.height(12.dp))
                Text(s.profilePanicSetLabel, color = SubrosaTheme.textPrimary, fontSize = 15.sp)
                Spacer(Modifier.height(8.dp))
                SecureTextField(
                    value         = panicPassword,
                    onValueChange = { panicPassword = it },
                    label         = s.profilePanicFieldLabel,
                    modifier      = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (panicPassword.isNotBlank()) {
                    UserStorage.setPanicPassword(panicPassword)
                    panicPassword = ""
                    onDismiss()
                }
            }) { Text(s.save, color = SubrosaTheme.accent) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(s.cancel, color = SubrosaTheme.textSecondary)
            }
        }
    )
}

// ── Security diagnostics dialog ───────────────────────────────────────────────

private val TERMINAL_BG = Color(0xFF0D1117)

@Composable
private fun DiagnosticsDialog(
    running:   Boolean,
    results:   List<DiagResult>,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = { if (!running) onDismiss() },
        containerColor   = SubrosaTheme.dialog,
        title  = { Text("Диагностика безопасности", color = SubrosaTheme.textPrimary) },
        text   = {
            Box(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp, max = 420.dp)
                    .background(TERMINAL_BG, RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                if (running) {
                    Column(
                        Modifier.fillMaxWidth(),
                        verticalArrangement   = Arrangement.Center,
                        horizontalAlignment   = Alignment.CenterHorizontally
                    ) {
                        Spacer(Modifier.height(16.dp))
                        CircularProgressIndicator(
                            color    = SubrosaTheme.accent,
                            modifier = Modifier.size(28.dp),
                            strokeWidth = 2.5.dp
                        )
                        Spacer(Modifier.height(10.dp))
                        Text(
                            "Выполняется диагностика…",
                            color    = Color(0xFF8B949E),
                            fontSize = 14.sp
                        )
                        Spacer(Modifier.height(16.dp))
                    }
                } else {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        results.forEach { res ->
                            when (res.status) {
                                DiagStatus.INFO -> {
                                    Spacer(Modifier.height(6.dp))
                                    Text(
                                        text       = "── ${res.message} ──",
                                        color      = Color(0xFF58A6FF),
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        letterSpacing = 1.sp,
                                        modifier   = Modifier.padding(bottom = 3.dp)
                                    )
                                }
                                else -> {
                                    val (iconName, color) = when (res.status) {
                                        DiagStatus.OK   -> null to Color(0xFF3FB950)
                                        DiagStatus.FAIL -> "ERROR" to Color(0xFFF85149)
                                        DiagStatus.WARN -> "WARNING" to Color(0xFFD29922)
                                        else            -> null to Color(0xFF8B949E)
                                    }
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.padding(vertical = 2.dp)
                                    ) {
                                        Box(modifier = Modifier.size(12.dp)) {
                                            if (iconName != null) {
                                                Icon(AppIcons.get(iconName), contentDescription = null,
                                                    tint = color, modifier = Modifier.size(12.dp))
                                            }
                                        }
                                        Spacer(Modifier.width(6.dp))
                                        Text(
                                            text     = res.message,
                                            color    = color,
                                            fontSize = 14.sp
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (!running) {
                TextButton(onClick = onDismiss) {
                    Text("Закрыть", color = SubrosaTheme.accent)
                }
            }
        }
    )
}

// ── Auto-lock timeout picker ──────────────────────────────────────────────────

private val AUTO_LOCK_OPTIONS = listOf(
    0    to "Выключено",
    300  to "5 минут",
    900  to "15 минут",
    1800 to "30 минут",
    3600 to "1 час"
)

@Composable
private fun AutoLockTimeoutDialog(
    current:  Int,
    onSelect: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = SubrosaTheme.dialog,
        title  = { Text("Автоблокировка", color = SubrosaTheme.textPrimary) },
        text   = {
            Column {
                Text(
                    "Блокировать приложение после периода неактивности",
                    fontSize = 15.sp,
                    color    = SubrosaTheme.textSecondary,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                AUTO_LOCK_OPTIONS.forEach { (secs, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(secs) }
                            .padding(vertical = 10.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = secs == current,
                            onClick  = { onSelect(secs) },
                            colors   = RadioButtonDefaults.colors(
                                selectedColor   = SubrosaTheme.accent,
                                unselectedColor = SubrosaTheme.textSecondary
                            )
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(label, fontSize = 16.sp, color = SubrosaTheme.textPrimary)
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена", color = SubrosaTheme.textSecondary)
            }
        }
    )
}
