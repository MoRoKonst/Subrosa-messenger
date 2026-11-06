package com.subrosa.messenger

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.RequestPermission
import androidx.activity.result.contract.ActivityResultContracts.GetContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlin.math.absoluteValue
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import com.subrosa.messenger.ui.theme.SubrosaTheme
import com.subrosa.messenger.ui.theme.subrosaColorsFor
import com.subrosa.messenger.ui.theme.Inter
import com.subrosa.messenger.ui.theme.NotoSerifJP
import com.subrosa.messenger.ui.components.IconTile
import com.subrosa.messenger.ui.components.IconTileColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// App-wide font swap 2026-09-22 — name kept for API stability. NotoSerifJP
// is used separately at specific heading/name call sites in this file.
private val AppFont = Inter

private fun extractFingerprint(inviteCode: String): String? {
    return try {
        inviteCode.split("&").find { it.startsWith("fp=") }?.removePrefix("fp=")
    } catch (e: Exception) { null }
}

@Composable
internal fun PSection(
    label: String,
    // Optional leading color-tile icon (see ui/components/IconTile.kt).
    leading: (@Composable () -> Unit)? = null
) {
    val c = LocalSubrosaColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 20.dp, top = 24.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (leading != null) {
            leading()
            Spacer(modifier = Modifier.width(10.dp))
        }
        Text(
            text = label.uppercase(),
            fontSize = 13.sp,
            fontFamily = AppFont,
            fontWeight = FontWeight.SemiBold,
            color = c.textPrimary.copy(alpha = 0.45f),
            letterSpacing = 1.sp
        )
    }
}

@Composable
internal fun PRow(
    title: String,
    titleColor: Color? = null,
    subtitle: String? = null,
    // Optional leading color-tile icon (see ui/components/IconTile.kt).
    leading: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
    trailing: @Composable () -> Unit = {}
) {
    val c = LocalSubrosaColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (leading != null) {
            leading()
            Spacer(modifier = Modifier.width(14.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 17.sp,
                fontFamily = AppFont,
                color = titleColor ?: c.textPrimary
            )
            if (subtitle != null) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    fontSize = 14.sp,
                    fontFamily = AppFont,
                    color = c.textPrimary.copy(alpha = 0.5f)
                )
            }
        }
        trailing()
    }
}

@Composable
internal fun PDivider() {
    val c = LocalSubrosaColors.current
    HorizontalDivider(
        modifier = Modifier.padding(horizontal = 20.dp),
        color = c.textPrimary.copy(alpha = 0.08f),
        thickness = 0.5.dp
    )
}

@Composable
internal fun PChevron() {
    val c = LocalSubrosaColors.current
    Icon(
        painter = painterResource(R.drawable.ic_arrow_right),
        contentDescription = null,
        tint = c.textPrimary.copy(alpha = 0.30f),
        modifier = Modifier.size(20.dp)
    )
}

/** Trailing button for Security-settings rows that open their own full
 *  screen — a plain "Настроить" label reads as more informative than a
 *  bare arrow when several rows in a row all navigate somewhere. */
@Composable
internal fun PConfigureButton(onClick: () -> Unit) {
    val c = LocalSubrosaColors.current
    val s = LocalStrings.current
    TextButton(onClick = onClick) {
        Text(
            text = s.profileConfigureBtn,
            fontSize = 14.sp,
            fontFamily = AppFont,
            color = c.accent
        )
    }
}

/** One numbered step in the emergency-wipe setup instructions — replaces the
 *  old wall-of-text with circled-digit unicode glyphs (①②③) crammed into one
 *  paragraph, which the user found hard to follow. [done] greys the row out
 *  once its button has been tapped; [emphasize] highlights step 2 once step 1
 *  has been visited, giving a "now do this one" cue without literally being
 *  able to verify what happened in system Settings in between. */
@Composable
private fun EmergencyStepRow(label: String, desc: String, done: Boolean, emphasize: Boolean = false) {
    val c = LocalSubrosaColors.current
    Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Surface(
            shape = androidx.compose.foundation.shape.CircleShape,
            color = if (done) c.textPrimary.copy(alpha = 0.15f) else if (emphasize) c.accent else c.textPrimary.copy(alpha = 0.25f),
            modifier = Modifier.size(22.dp)
        ) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                if (done) {
                    Icon(painterResource(R.drawable.ic_check), contentDescription = null,
                        tint = c.textPrimary.copy(alpha = 0.5f), modifier = Modifier.size(12.dp))
                } else {
                    Text(label.filter { it.isDigit() }, color = c.textPrimary, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
        Column {
            Text(
                label,
                color = if (done) c.textPrimary.copy(alpha = 0.4f) else c.textPrimary,
                fontFamily = AppFont,
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold
            )
            Text(
                desc,
                color = if (done) c.textPrimary.copy(alpha = 0.4f) else c.textPrimary.copy(alpha = 0.85f),
                fontFamily = AppFont,
                fontSize = 14.sp,
                lineHeight = 16.sp
            )
        }
    }
}

/** Whether the volume-button panic-wipe AccessibilityService is actually
 *  enabled in system settings — not just the (default-true)
 *  UserStorage.isEmergencyWipeEnabled() preference, which only tracks
 *  intent, not the multi-step accessibility grant. Shared with
 *  MessengerService.kt's silent-audio-track gate — see there. */
fun isEmergencyServiceEnabled(context: android.content.Context): Boolean =
    (context.getSystemService(android.content.Context.ACCESSIBILITY_SERVICE) as AccessibilityManager)
        .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        .any {
            it.resolveInfo.serviceInfo.packageName == context.packageName &&
            it.resolveInfo.serviceInfo.name.contains("EmergencyService")
        }

/** Whether the OEM's battery manager is free to throttle/kill this app's
 *  background network — official foreground-service exemptions from Doze
 *  aren't always honored by vendor battery managers (MIUI etc.) unless the
 *  app is also separately whitelisted here. Root-caused live: backgrounding
 *  the app let outgoing writes (delivery receipts, then everything) stall
 *  silently with zero exceptions, then the WebSocket died outright — see
 *  docs/ISSUE_backup_identity_hijack.md. Single system dialog, no multi-step
 *  Settings navigation needed (unlike the accessibility service above). */
fun isIgnoringBatteryOptimizations(context: android.content.Context): Boolean {
    val pm = context.getSystemService(android.content.Context.POWER_SERVICE) as android.os.PowerManager
    return pm.isIgnoringBatteryOptimizations(context.packageName)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileScreen(
    onBack: () -> Unit,
    onOpenGeneralSettings: () -> Unit = {},
    onOpenSecuritySettings: () -> Unit = {}
) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val scope = rememberCoroutineScope()
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    var showNotMeConfirm   by remember { mutableStateOf(false) }
    var showCompromisedConfirm by remember { mutableStateOf(false) }
    var showQr             by remember { mutableStateOf(false) }
    var showCopied         by remember { mutableStateOf(false) }

    val displayName      = UserStorage.getUserDisplayName(context)
    val userId           = UserStorage.getUserId(context)
    val clipboardManager = LocalClipboardManager.current
    val currentTheme     by MainActivity.currentTheme.collectAsState()

    fun resolveInviteCode(): String {
        return try {
            // Reuse the persisted invite code if one already exists AND hasn't
            // expired — minting a fresh one on every Profile visit was the actual
            // bug: a contact who already has your OLD invite code keeps
            // depositing mailbox tokens under the OLD tag forever, while
            // regenerating here would swap "my tag to poll for" out from under
            // them, silently orphaning that exchange (confirmed via live
            // server-side logs: deposits piling up under a tag neither side was
            // fetching for anymore). The invite code — and the invite tag
            // embedded in it — needs to stay stable once shared, not rotate on
            // every screen visit. Still respects the 7-day TTL: an actually-
            // expired code gets replaced, same as before.
            //
            // The tag embedded here is the disposable "invite tag"
            // (AnonTokenManager.getOrCreateMyInviteMailboxTag), NOT the
            // persistent one used for ongoing contact — see that function's
            // doc comment. Regenerating this code (regenerateInviteCode(),
            // wired to the Copy/Share buttons below) mints a fresh invite tag
            // too, so a leaked/observed old code stops working the moment the
            // user asks for a new one, without touching the real ongoing tag.
            val existing = UserStorage.getInviteCode(context)
            val existingTimestamp = existing?.let { InviteCodeManager.parseInviteCode(it) }?.timestamp
            val stillValid = existingTimestamp != null &&
                (System.currentTimeMillis() / 1000 - existingTimestamp) < 7L * 24 * 3600
            val code = if (existing != null && stillValid) {
                existing
            } else {
                val fresh = InviteCodeManager.generateInviteCode(
                    CryptoManager.getPublicKey(),
                    CryptoManager.getPrivateKeyPublic(),
                    displayName.ifBlank { userId },
                    AnonTokenManager.getOrCreateMyInviteMailboxTag(context)
                )
                UserStorage.saveInviteCode(context, fresh)
                fresh
            }
            // Register the tag unconditionally, even when reusing a persisted code —
            // addMyMailboxTag() is idempotent (no-ops if already present). Storage for
            // the invite code text (UserStorage) and for "my mailbox tags"
            // (AnonTokenManager, a separate encrypted prefs file) can end up out of
            // sync — e.g. a partial data reset that clears one but not the other —
            // and only registering the tag in the "generate fresh" branch meant a
            // reused code's tag could silently never make it into the poll list at
            // all, leaving pollMailbox() with nothing to check for indefinitely.
            InviteCodeManager.parseInviteCode(code)?.mailboxTag?.let { tag ->
                AnonTokenManager.syncMyInviteMailboxTag(context, tag)
            }
            code
        } catch (e: Exception) {
            UserStorage.getInviteCode(context) ?: userId
        }
    }

    var inviteCode by remember { mutableStateOf(resolveInviteCode()) }
    var qrBitmap by remember { mutableStateOf(generateQRCode(inviteCode, 512)) }

    // Explicit, user-triggered rotation — see resolveInviteCode()'s doc
    // comment. Only the invite tag changes; the persistent tag (and every
    // already-established contact relying on it) is untouched.
    fun regenerateInviteCode() {
        try {
            val freshTag = AnonTokenManager.regenerateMyInviteMailboxTag(context)
            val fresh = InviteCodeManager.generateInviteCode(
                CryptoManager.getPublicKey(),
                CryptoManager.getPrivateKeyPublic(),
                displayName.ifBlank { userId },
                freshTag
            )
            UserStorage.saveInviteCode(context, fresh)
            inviteCode = fresh
            qrBitmap = generateQRCode(fresh, 512)
        } catch (e: Exception) {}
    }

    val fingerprint      = remember { userId.takeIf { it.isNotBlank() } }
    val emojiFingerprint = remember { fingerprint?.let { fingerprintToEmoji(it) } }

    var myAvatarBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    LaunchedEffect(Unit) {
        val b64 = UserStorage.getMyAvatar(context)
        if (!b64.isNullOrBlank()) {
            withContext(Dispatchers.IO) {
                try {
                    val bytes = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
                    val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    if (bmp != null) withContext(Dispatchers.Main) { myAvatarBitmap = bmp }
                } catch (_: Exception) {}
            }
        }
    }

    // Decoded but not-yet-cropped picked photo — shown via AvatarCropScreen
    // below. Was previously stretched straight into a 128x128 square with
    // Bitmap.createScaledBitmap(bmp, 128, 128, true), distorting the aspect
    // ratio of any non-square photo; the crop screen now lets the user pick
    // which part to keep before it's scaled down.
    var pendingAvatarBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }

    val galleryLauncher = rememberLauncherForActivityResult(GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        MainScope().launch {
            withContext(Dispatchers.IO) {
                try {
                    val bmp = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                        val src = android.graphics.ImageDecoder.createSource(context.contentResolver, uri)
                        android.graphics.ImageDecoder.decodeBitmap(src) { decoder, _, _ ->
                            decoder.allocator = android.graphics.ImageDecoder.ALLOCATOR_SOFTWARE
                        }
                    } else {
                        @Suppress("DEPRECATION")
                        android.provider.MediaStore.Images.Media.getBitmap(context.contentResolver, uri)
                    }
                    withContext(Dispatchers.Main) { pendingAvatarBitmap = bmp }
                } catch (e: Exception) {
                    android.util.Log.e("ProfileScreen", "Ошибка загрузки фото: ${e.message}")
                }
            }
        }
    }

    fun applyCroppedAvatar(cropped: android.graphics.Bitmap) {
        pendingAvatarBitmap = null
        MainScope().launch {
            withContext(Dispatchers.IO) {
                val out = java.io.ByteArrayOutputStream()
                cropped.compress(android.graphics.Bitmap.CompressFormat.JPEG, 85, out)
                val b64 = android.util.Base64.encodeToString(out.toByteArray(), android.util.Base64.NO_WRAP)
                withContext(Dispatchers.Main) {
                    myAvatarBitmap = cropped
                    AvatarStore.avatars[userId] = cropped
                    context.startService(
                        android.content.Intent(context, MessengerService::class.java).apply {
                            putExtra("avatar_update", b64)
                        }
                    )
                }
            }
        }
    }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val scannedCode = result.contents ?: return@rememberLauncherForActivityResult
        val inviteData = InviteCodeManager.parseInviteCode(scannedCode)
        if (inviteData == null) {
            Toast.makeText(context, s.profileInvalidCodeFormat, Toast.LENGTH_SHORT).show()
            return@rememberLauncherForActivityResult
        }
        if (!InviteCodeManager.verifyInviteCode(inviteData)) {
            Toast.makeText(context, s.profileInvalidOrExpiredCode, Toast.LENGTH_SHORT).show()
            return@rememberLauncherForActivityResult
        }
        val fixedKey = inviteData.publicKey.replace('-', '+').replace('_', '/')
        ChatStorage.addContact(context, inviteData.fingerprint)
        ChatStorage.saveContactPublicKey(context, inviteData.fingerprint, fixedKey)
        ChatStorage.saveContactName(context, inviteData.fingerprint, inviteData.displayName)
        Toast.makeText(context, s.chatsContactAdded(inviteData.displayName), Toast.LENGTH_SHORT).show()
    }

    val cameraPermLauncher = rememberLauncherForActivityResult(RequestPermission()) { granted ->
        if (granted) {
            scanLauncher.launch(ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt(s.profileQrScanPrompt)
                setBeepEnabled(false)
            })
        } else {
            Toast.makeText(context, s.profileCameraPermReq, Toast.LENGTH_SHORT).show()
        }
    }

    val avatarColor = remember(displayName) {
        listOf(
            Color(0xFFC77B4F), Color(0xFFE74C3C), Color(0xFF27AE60),
            Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
        )[displayName.hashCode().absoluteValue % 6]
    }

    Scaffold(containerColor = Color.Transparent) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
            ) {

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 28.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 4.dp, vertical = 8.dp)
                    ) {
                        IconButton(onClick = onBack) {
                            Icon(
                                painterResource(R.drawable.ic_back_arrow),
                                contentDescription = s.back,
                                tint = c.textPrimary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Box(
                        modifier = Modifier
                            .size(108.dp)
                            .clickable { galleryLauncher.launch("image/*") },
                        contentAlignment = Alignment.Center
                    ) {

                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .clip(CircleShape)
                                .background(
                                    Brush.radialGradient(
                                        listOf(
                                            c.accent.copy(alpha = 0.30f),
                                            c.accent.copy(alpha = 0.06f)
                                        )
                                    )
                                )
                        )

                        Box(
                            modifier = Modifier
                                .size(96.dp)
                                .clip(CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            if (myAvatarBitmap != null) {
                                Image(
                                    bitmap = myAvatarBitmap!!.asImageBitmap(),
                                    contentDescription = displayName,
                                    contentScale = ContentScale.Crop,
                                    modifier = Modifier.fillMaxSize()
                                )
                            } else {
                                Surface(
                                    shape = CircleShape,
                                    color = avatarColor,
                                    modifier = Modifier.fillMaxSize()
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Text(
                                            text = displayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                            fontSize = 42.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White,
                                            fontFamily = AppFont
                                        )
                                    }
                                }
                            }
                        }

                        Box(
                            modifier = Modifier
                                .size(30.dp)
                                .align(Alignment.BottomEnd)
                                .clip(CircleShape)
                                .background(c.primaryBlue),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.ic_camera_circle),
                                contentDescription = null,
                                // c.primaryBlue is a bright mint in every
                                // theme now — white icons stay correct on
                                // dark themes (unchanged), but need a dark
                                // icon for AA contrast on the light theme's
                                // equally-bright mint. See the identical
                                // pattern a few sites below.
                                tint = if (c.isDark) Color.White else c.textPrimary,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Text(
                        text = displayName,
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Bold,
                        color = c.textPrimary,
                        fontFamily = NotoSerifJP
                    )

                    if (emojiFingerprint != null) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Surface(
                            shape = RoundedCornerShape(20.dp),
                            color = c.textPrimary.copy(alpha = 0.10f)
                        ) {
                            Text(
                                text = emojiFingerprint,
                                fontSize = 24.sp,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)
                            )
                        }
                        Spacer(modifier = Modifier.height(5.dp))
                        Text(
                            text = s.profileFingerprintHint,
                            fontSize = 15.sp,
                            color = c.textPrimary.copy(alpha = 0.55f),
                            fontFamily = AppFont,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 40.dp)
                        )
                    }
                }

                PSection(
                    s.profileInviteCode,
                    leading = {
                        IconTile(
                            iconRes = R.drawable.ic_qr_code,
                            tileColor = IconTileColors.mintGreen
                        )
                    }
                )
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(start = 20.dp, end = 8.dp, top = 12.dp, bottom = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = inviteCode.take(30) + "…",
                                fontSize = 14.sp,
                                fontFamily = AppFont,
                                color = c.accent,
                                maxLines = 1,
                                modifier = Modifier.weight(1f)
                            )
                            IconButton(
                                onClick = {
                                    regenerateInviteCode()
                                    clipboardManager.setText(AnnotatedString(inviteCode))
                                    showCopied = true
                                },
                                modifier = Modifier.size(44.dp)
                            ) {
                                Icon(
                                    painterResource(R.drawable.ic_copy),
                                    contentDescription = s.totpCopySecret,
                                    tint = c.accent,
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                            IconButton(
                                onClick = {
                                    regenerateInviteCode()
                                    val i = Intent(Intent.ACTION_SEND).apply {
                                        type = "text/plain"
                                        putExtra(Intent.EXTRA_TEXT, inviteCode)
                                    }
                                    context.startActivity(Intent.createChooser(i, s.profileShareCode))
                                },
                                modifier = Modifier.size(44.dp)
                            ) {
                                Icon(
                                    painterResource(R.drawable.ic_share),
                                    contentDescription = s.profileShareCode,
                                    tint = c.accent,
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                        }
                        if (showCopied) {
                            LaunchedEffect(Unit) { kotlinx.coroutines.delay(2000); showCopied = false }
                            Text(
                                text = s.profileCodeCopied,
                                fontSize = 15.sp,
                                color = Color(0xFF27AE60),
                                fontFamily = AppFont,
                                modifier = Modifier.padding(start = 20.dp, bottom = 8.dp)
                            )
                        }
                        // Explicit, always-visible — not just in the security
                        // guide — because the failure mode is silent: sharing
                        // one code with a group means everyone after the first
                        // redeemer gets a channel that looks fine locally but
                        // never actually connects (the invite tag is pruned
                        // after its first use, see AnonTokenManager's
                        // PREF_MY_INVITE_TAG). Better to catch the wrong mental
                        // model here, at the point of sharing, than have the
                        // user debug a "why doesn't it work" days later.
                        Text(
                            text = s.profileInviteCodeOneTimeWarning,
                            fontSize = 15.sp,
                            color = Color(0xFFFFA726),
                            fontFamily = AppFont,
                            lineHeight = 15.sp,
                            modifier = Modifier.padding(start = 20.dp, end = 16.dp, bottom = 8.dp)
                        )

                        PDivider()
                        PRow(
                            title = if (showQr) s.profileHideQr else s.profileShowQr,
                            onClick = {
                                // Rotate on show, same as Copy/Share — found live:
                                // this used to just toggle visibility of the
                                // cached QR without regenerating it, so anyone
                                // who scans the QR without the user ever having
                                // pressed Copy/Share gets a code that never
                                // rotates, defeating the whole point of the
                                // one-time invite tag.
                                if (!showQr) regenerateInviteCode()
                                showQr = !showQr
                            },
                            trailing = {
                                Text(
                                    if (showQr) "▲" else "▼",
                                    fontSize = 13.sp,
                                    color = c.textPrimary.copy(alpha = 0.4f)
                                )
                            }
                        )
                        AnimatedVisibility(
                            visible = showQr && qrBitmap != null,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut()
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(14.dp),
                                    color = Color.White,
                                    modifier = Modifier.size(200.dp)
                                ) {
                                    Image(
                                        bitmap = qrBitmap!!.asImageBitmap(),
                                        contentDescription = "QR",
                                        modifier = Modifier.fillMaxSize().padding(10.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    s.profileQrHint,
                                    fontSize = 13.sp,
                                    color = c.textPrimary.copy(alpha = 0.5f),
                                    fontFamily = AppFont,
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier.padding(horizontal = 24.dp)
                                )
                            }
                        }

                        PDivider()
                        PRow(
                            title = s.profileScanQr,
                            onClick = {
                                if (ContextCompat.checkSelfPermission(
                                        context, Manifest.permission.CAMERA
                                    ) == PackageManager.PERMISSION_GRANTED
                                ) {
                                    scanLauncher.launch(ScanOptions().apply {
                                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        setPrompt(s.profileQrScanPrompt)
                                        setBeepEnabled(false)
                                    })
                                } else {
                                    cameraPermLauncher.launch(Manifest.permission.CAMERA)
                                }
                            },
                            trailing = { PChevron() }
                        )
                    }
                }

                PSection(
                    s.profileThemeLabel,
                    leading = {
                        IconTile(
                            iconRes = R.drawable.ic_palette,
                            tileColor = IconTileColors.mutedPurple
                        )
                    }
                )
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            listOf(
                                SubrosaTheme.NAVY  to s.profileThemeNavy,
                                SubrosaTheme.DARK  to s.profileThemeDark,
                                SubrosaTheme.LIGHT to s.profileThemeLight
                            ).forEach { (theme, label) ->
                                val isSelected = theme == currentTheme
                                val previewColors = subrosaColorsFor(theme)
                                // Each button previously took its background
                                // from the PREVIEWED theme's own gradientEnd
                                // (a different color per button — NAVY's dark
                                // red, DARK's near-black, LIGHT's cream) —
                                // three visually unrelated buttons rather
                                // than one coherent selector, and the
                                // hardcoded white selected-label text was
                                // unreadable once a light-themed button's bg
                                // was itself light. Selected/unselected state
                                // now derives entirely from the CURRENT
                                // theme's own accent, so all three buttons
                                // share one base look and the selection
                                // highlight always matches the live theme.
                                // The small accent dot still previews each
                                // theme's own accent color — that's a
                                // legitimate content preview, not a bug.
                                Surface(
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(38.dp)
                                        .clickable {
                                            UserStorage.setTheme(context, theme)
                                            MainActivity.currentTheme.value = theme
                                        },
                                    shape = RoundedCornerShape(10.dp),
                                    color = if (isSelected) c.accent.copy(alpha = 0.18f) else c.card,
                                    border = if (isSelected)
                                        androidx.compose.foundation.BorderStroke(1.5.dp, c.accent)
                                    else null
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxSize(),
                                        horizontalArrangement = Arrangement.Center,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Box(
                                            Modifier
                                                .size(8.dp)
                                                .background(previewColors.accent, CircleShape)
                                        )
                                        Spacer(Modifier.width(5.dp))
                                        Text(
                                            text = label,
                                            fontSize = 13.sp,
                                            fontFamily = AppFont,
                                            color = if (isSelected) c.accent
                                                    else c.textPrimary.copy(alpha = 0.7f),
                                            maxLines = 1,
                                            softWrap = false
                                        )
                                    }
                                }
                            }
                        }
                        PDivider()
                        PRow(
                            title = s.profileLanguageToggle,
                            leading = {
                                IconTile(
                                    iconRes = R.drawable.ic_translate,
                                    tileColor = IconTileColors.neutralGrayBrown
                                )
                            },
                            onClick = {
                                val newLang = if (s.langCode == "ru") "en" else "ru"
                                UserStorage.setLanguage(context, newLang)
                                MainActivity.currentLanguage.value = newLang
                            },
                            trailing = { PChevron() }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    PRow(
                        title = s.profileSectionSecurity,
                        leading = {
                            IconTile(
                                iconRes = R.drawable.ic_shield_check,
                                tileColor = IconTileColors.mutedBurgundy
                            )
                        },
                        onClick = onOpenSecuritySettings,
                        trailing = { PChevron() }
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    PRow(
                        title = s.profileSectionGeneral,
                        leading = {
                            IconTile(
                                iconRes = R.drawable.ic_gear,
                                tileColor = IconTileColors.neutralGrayBrown
                            )
                        },
                        onClick = onOpenGeneralSettings,
                        trailing = { PChevron() }
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x18EF5350))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showNotMeConfirm = true }
                            .padding(horizontal = 20.dp, vertical = 16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            s.profileNotMe,
                            fontSize = 19.sp,
                            fontFamily = AppFont,
                            color = Color(0xFFEF5350),
                            modifier = Modifier.weight(1f)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x18EF5350))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showCompromisedConfirm = true }
                            .padding(horizontal = 20.dp, vertical = 16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            s.profileCompromised,
                            fontSize = 19.sp,
                            fontFamily = AppFont,
                            color = Color(0xFFEF5350),
                            modifier = Modifier.weight(1f)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }

    if (showNotMeConfirm) {
        AlertDialog(
            onDismissRequest = { showNotMeConfirm = false },
            containerColor = c.dialog,
            title = { Text(s.profileNotMeTitle, color = c.textPrimary, fontFamily = AppFont) },
            text = { Text(s.profileNotMeText, color = c.textPrimary, fontFamily = AppFont) },
            confirmButton = {
                TextButton(onClick = {
                    showNotMeConfirm = false
                    (context as? MainActivity)?.emergencyWipe()
                }) { Text(s.profileNotMeConfirm, color = Color(0xFFEF5350), fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showNotMeConfirm = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }

    if (showCompromisedConfirm) {
        AlertDialog(
            onDismissRequest = { showCompromisedConfirm = false },
            containerColor = c.dialog,
            title = { Text(s.profileCompromisedTitle, color = c.textPrimary, fontFamily = AppFont) },
            text = { Text(s.profileCompromisedText, color = c.textPrimary, fontFamily = AppFont) },
            confirmButton = {
                TextButton(onClick = {
                    showCompromisedConfirm = false
                    scope.launch {
                        MessengerService.requestIdentityRevocation(context)
                        BackupManager.resetCompromisedIdentity(context)
                        context.stopService(Intent(context, MessengerService::class.java))
                        android.os.Process.killProcess(android.os.Process.myPid())
                    }
                }) { Text(s.profileCompromisedConfirm, color = Color(0xFFEF5350), fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showCompromisedConfirm = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }

    pendingAvatarBitmap?.let { bmp ->
        AvatarCropScreen(
            source = bmp,
            onConfirm = { cropped -> applyCroppedAvatar(cropped) },
            onCancel = { pendingAvatarBitmap = null }
        )
    }
}

/** Everything that used to live under Profile's "Основное"/"General" section,
 *  split out onto its own screen so Profile's main list isn't one long
 *  scroll — Profile now just has a single row that opens this. Owns its own
 *  battery-optimization resync (moved off Profile's ON_RESUME observer,
 *  which now only handles the emergency-wipe re-sync that stays on Profile). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GeneralSettingsScreen(
    onBack: () -> Unit,
    onOpenServers: () -> Unit,
    onOpenBackup: () -> Unit
) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    var torEnabled          by remember { mutableStateOf(UserStorage.isTorEnabled(context)) }
    var batteryUnrestricted by remember { mutableStateOf(isIgnoringBatteryOptimizations(context)) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                // Re-sync after returning from the system battery-optimization
                // dialog — it's a single Allow/Deny prompt, no multi-step
                // navigation, so this just picks up whatever the user chose.
                batteryUnrestricted = isIgnoringBatteryOptimizations(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Scaffold(
        topBar = {
            // Scaffold+TopAppBar (not a bare Row) so the system status bar
            // inset is reserved automatically under edge-to-edge — a bare Row
            // like the other screens avoid left this button sitting under the
            // phone's own status bar / notch, unreachable on some devices.
            TopAppBar(
                title = { Text(s.profileSectionGeneral, color = c.textPrimary, fontFamily = AppFont) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), contentDescription = s.back, tint = c.textPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            Column(modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                Spacer(modifier = Modifier.height(8.dp))
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {
                        PRow(
                            title = s.profileServers,
                            leading = {
                                IconTile(
                                    iconRes = R.drawable.ic_hard_drives,
                                    tileColor = IconTileColors.connectivityBlue
                                )
                            },
                            onClick = onOpenServers,
                            trailing = { PChevron() }
                        )
                        PDivider()
                        PRow(
                            title = s.profileBackup,
                            leading = {
                                IconTile(
                                    iconRes = R.drawable.ic_cloud_arrow_down,
                                    tileColor = IconTileColors.warningAmber
                                )
                            },
                            onClick = onOpenBackup,
                            trailing = { PChevron() }
                        )
                        PDivider()
                        PRow(
                            title = s.profileTorEnabled,
                            subtitle = s.profileTorEnabledSub,
                            leading = {
                                IconTile(
                                    iconRes = R.drawable.ic_wifi_high,
                                    tileColor = IconTileColors.connectivityBlue
                                )
                            },
                            trailing = {
                                Switch(
                                    checked = torEnabled,
                                    onCheckedChange = {
                                        torEnabled = it
                                        UserStorage.setTorEnabled(context, it)
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = c.accent,
                                        checkedTrackColor = c.accent.copy(alpha = 0.35f)
                                    )
                                )
                            }
                        )
                        PDivider()
                        PRow(
                            title = s.profileBatteryUnrestricted,
                            subtitle = s.profileBatteryUnrestrictedSub,
                            leading = {
                                IconTile(
                                    iconRes = R.drawable.ic_battery_charging,
                                    tileColor = IconTileColors.connectivityBlue
                                )
                            },
                            trailing = {
                                Switch(
                                    checked = batteryUnrestricted,
                                    onCheckedChange = { wantOn ->
                                        // No API to programmatically revoke this once
                                        // granted — only the system dialog can grant
                                        // it. If the user is trying to turn it back
                                        // off, send them to the OS settings screen
                                        // where they can do that manually instead;
                                        // local state isn't flipped speculatively,
                                        // it re-syncs for real on ON_RESUME above.
                                        try {
                                            if (wantOn) {
                                                context.startActivity(
                                                    Intent(
                                                        android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                                        Uri.parse("package:${context.packageName}")
                                                    )
                                                )
                                            } else {
                                                context.startActivity(
                                                    Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                                )
                                            }
                                        } catch (_: Exception) {}
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = c.accent,
                                        checkedTrackColor = c.accent.copy(alpha = 0.35f)
                                    )
                                )
                            }
                        )
                        PDivider()
                        PRow(
                            title = s.profileSourceCode,
                            leading = {
                                IconTile(
                                    iconRes = R.drawable.ic_github_logo,
                                    tileColor = IconTileColors.neutralGrayBrown
                                )
                            },
                            onClick = {
                                try {
                                    context.startActivity(
                                        Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/MoRoKonst/Subrosa-messenger"))
                                    )
                                } catch (_: Exception) {}
                            },
                            trailing = { PChevron() }
                        )
                    }
                }
                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }
}

/** Everything that used to live under Profile's "Безопасность"/"Security"
 *  section, split out onto its own screen the same way as
 *  GeneralSettingsScreen above — Profile now just has a single row that
 *  opens this. Owns the emergency-wipe accessibility-service resync (moved
 *  off Profile's ON_RESUME observer, which had no other reason to exist once
 *  this section moved off Profile). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecuritySettingsScreen(
    onBack: () -> Unit,
    onOpenSecurityGuide: () -> Unit,
    onOpenChangePassword: () -> Unit,
    onOpenTotpSettings: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onOpenWipeSettings: () -> Unit
) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    var showLockDialog     by remember { mutableStateOf(false) }
    var showPanicDialog    by remember { mutableStateOf(false) }
    var panicPassword      by remember { mutableStateOf("") }
    var panicPasswordError by remember { mutableStateOf("") }
    // Validating the panic password runs checkPassword() -> PBKDF2 at 100k
    // iterations; it must not happen on the main thread.
    val panicScope = rememberCoroutineScope()
    var hideNotif          by remember { mutableStateOf(UserStorage.getHideNotificationContent(context)) }
    var currentLock        by remember { mutableStateOf(UserStorage.getAutoLockTimeout(context)) }
    var biometricEnabled   by remember { mutableStateOf(UserStorage.getBiometricUnlockEnabled(context)) }
    var showBiometricWarning by remember { mutableStateOf(false) }
    var emergencyEnabled        by remember { mutableStateOf(UserStorage.isEmergencyWipeEnabled(context) && isEmergencyServiceEnabled(context)) }
    var showEmergencyInfoDialog by remember { mutableStateOf(false) }
    var serviceNotifVisible     by remember { mutableStateOf(UserStorage.isServiceNotificationVisible(context)) }
    var hideIpDuringCalls       by remember { mutableStateOf(UserStorage.getHideIpDuringCalls(context)) }

    val lockLabels = mapOf(
        0    to s.profileLockOff,
        60   to s.profileLock1min,
        300  to s.profileLock5min,
        900  to s.profileLock15min,
        1800 to s.profileLock30min
    )

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                val active = isEmergencyServiceEnabled(context)
                // Found live: the toast said "already enabled" (active==true)
                // but the switch stayed off — emergencyEnabled requires BOTH
                // active AND the separate isEmergencyWipeEnabled() preference
                // (the user's own "I want this" intent flag, deliberately kept
                // apart from the raw OS service state — see the Switch's
                // onCheckedChange below), and this dialog flow never set that
                // preference on success. Safe to set it here specifically
                // because showEmergencyInfoDialog being true means the user
                // got here by toggling the switch ON in the first place — the
                // dialog only opens from that intent, so this isn't opting
                // them into anything they didn't ask for.
                if (active && showEmergencyInfoDialog) {
                    UserStorage.setEmergencyWipeEnabled(context, true)
                }
                emergencyEnabled = active && UserStorage.isEmergencyWipeEnabled(context)
                if (!active) UserStorage.setEmergencyWipeEnabled(context, false)
                // Auto-close the step-by-step instructions once the service is
                // genuinely on — verified via isEmergencyServiceEnabled(), not
                // just "the user came back from Settings" (which proves
                // nothing about what they actually did there).
                if (active && showEmergencyInfoDialog) {
                    showEmergencyInfoDialog = false
                    Toast.makeText(context, s.emergencyInfoDone, Toast.LENGTH_SHORT).show()
                }
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.profileSectionSecurity, color = c.textPrimary, fontFamily = AppFont) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), contentDescription = s.back, tint = c.textPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            Column(modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                Spacer(modifier = Modifier.height(8.dp))

                // Guide entry kept on its own, ungrouped — it's the "read
                // more" gateway, not itself a security feature to classify
                // alongside the rest. Every row below now has a matching
                // article there (see SecurityGuideScreen.kt); this list was
                // previously missing 6 of them entirely.
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    PRow(
                        title = s.profileSecurityGuide,
                        subtitle = s.profileSecurityGuideSub,
                        onClick = onOpenSecurityGuide,
                        trailing = { PChevron() }
                    )
                }

                // Grouped into three kinds of row so the same interaction
                // pattern always lives in the same place: flips a switch,
                // opens an in-place dialog, or navigates to its own screen.
                // Long explanatory subtitles moved to the guide above —
                // these are now just short reminders of what the row does,
                // not the full rationale.
                Spacer(modifier = Modifier.height(20.dp))
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {
                        PRow(
                            title = s.profileHideNotif,
                            subtitle = s.profileHideNotifSub,
                            trailing = {
                                Switch(
                                    checked = hideNotif,
                                    onCheckedChange = {
                                        hideNotif = it
                                        UserStorage.setHideNotificationContent(context, it)
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = c.accent,
                                        checkedTrackColor = c.accent.copy(alpha = 0.35f)
                                    )
                                )
                            }
                        )
                        PDivider()
                        PRow(
                            title = s.profileHideIpCalls,
                            subtitle = s.profileHideIpCallsSub,
                            trailing = {
                                Switch(
                                    checked = hideIpDuringCalls,
                                    onCheckedChange = {
                                        hideIpDuringCalls = it
                                        UserStorage.setHideIpDuringCalls(context, it)
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = c.accent,
                                        checkedTrackColor = c.accent.copy(alpha = 0.35f)
                                    )
                                )
                            }
                        )
                        if (BiometricHelper.isBiometricAvailable(context)) {
                            PDivider()
                            PRow(
                                title = s.profileBiometricTitle,
                                subtitle = s.profileBiometricSub,
                                trailing = {
                                    Switch(
                                        checked = biometricEnabled,
                                        onCheckedChange = { wantEnabled ->
                                            if (wantEnabled) {
                                                // Don't flip the pref until the user explicitly
                                                // acknowledges the coercion-risk warning below.
                                                showBiometricWarning = true
                                            } else {
                                                biometricEnabled = false
                                                UserStorage.setBiometricUnlockEnabled(context, false)
                                            }
                                        },
                                        colors = SwitchDefaults.colors(
                                            checkedThumbColor = c.accent,
                                            checkedTrackColor = c.accent.copy(alpha = 0.35f)
                                        )
                                    )
                                }
                            )
                        }
                        PDivider()
                        PRow(
                            title = s.profileEmergencyBtn,
                            subtitle = s.profileEmergencyBtnSub,
                            trailing = {
                                Switch(
                                    checked = emergencyEnabled,
                                    onCheckedChange = { wantEnabled ->
                                        if (wantEnabled) {
                                            if (isEmergencyServiceEnabled(context)) {
                                                emergencyEnabled = true
                                                UserStorage.setEmergencyWipeEnabled(context, true)
                                            } else {

                                                showEmergencyInfoDialog = true
                                            }
                                        } else {
                                            emergencyEnabled = false
                                            UserStorage.setEmergencyWipeEnabled(context, false)
                                        }
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = Color(0xFFEF5350),
                                        checkedTrackColor = Color(0xFFEF5350).copy(alpha = 0.35f)
                                    )
                                )
                            }
                        )
                        PDivider()
                        PRow(
                            title = s.profileServiceNotifVisible,
                            subtitle = s.profileServiceNotifVisibleSub,
                            trailing = {
                                Switch(
                                    checked = serviceNotifVisible,
                                    onCheckedChange = {
                                        serviceNotifVisible = it
                                        UserStorage.setServiceNotificationVisible(context, it)
                                        // Re-post the running service's notification on
                                        // the new channel immediately, not just on next
                                        // restart.
                                        context.startService(
                                            Intent(context, MessengerService::class.java).apply {
                                                putExtra("refresh_notification", true)
                                            }
                                        )
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = c.accent,
                                        checkedTrackColor = c.accent.copy(alpha = 0.35f)
                                    )
                                )
                            }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {
                        PRow(
                            title = s.profileAutoLock,
                            subtitle = s.profileAutoLockAfter(
                                lockLabels[currentLock] ?: s.profileLockOff
                            ),
                            onClick = { showLockDialog = true },
                            trailing = { PChevron() }
                        )
                        PDivider()
                        PRow(
                            title = s.profilePanicTitle,
                            subtitle = s.profilePanicSub,
                            onClick = { showPanicDialog = true },
                            trailing = {
                                if (UserStorage.hasPanicPassword(context)) {
                                    Text(
                                        s.profilePanicSetStatus,
                                        fontSize = 14.sp,
                                        color = Color(0xFF4CAF50),
                                        fontFamily = AppFont
                                    )
                                } else {
                                    Text(
                                        s.setAction,
                                        fontSize = 15.sp,
                                        color = c.accent,
                                        fontFamily = AppFont
                                    )
                                }
                            }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {
                        PRow(
                            title = s.profileChangePassword,
                            onClick = onOpenChangePassword,
                            trailing = { PConfigureButton(onOpenChangePassword) }
                        )
                        PDivider()
                        PRow(s.profileTotp, onClick = onOpenTotpSettings, trailing = { PConfigureButton(onOpenTotpSettings) })
                        PDivider()
                        PRow(s.profileDiagnostics, onClick = onOpenDiagnostics, trailing = { PConfigureButton(onOpenDiagnostics) })
                        PDivider()
                        PRow(s.wipeSettingsTitle, onClick = onOpenWipeSettings, trailing = { PConfigureButton(onOpenWipeSettings) })
                    }
                }
                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }

    if (showLockDialog) {
        AlertDialog(
            onDismissRequest = { showLockDialog = false },
            containerColor = c.dialog,
            title = { Text(s.profileAutoLock, color = c.textPrimary, fontFamily = AppFont) },
            text = {
                Column {
                    lockLabels.forEach { (secs, label) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    currentLock = secs
                                    UserStorage.setAutoLockTimeout(context, secs)
                                    showLockDialog = false
                                }
                                .padding(vertical = 10.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = currentLock == secs,
                                onClick = null,
                                colors = RadioButtonDefaults.colors(selectedColor = c.accent)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(label, color = c.textPrimary, fontFamily = AppFont, fontSize = 17.sp)
                        }
                    }
                }
            },
            confirmButton = {}
        )
    }

    if (showBiometricWarning) {
        AlertDialog(
            onDismissRequest = { showBiometricWarning = false },
            containerColor = c.dialog,
            title = { Text(s.profileBiometricWarningTitle, color = Color(0xFFFFA726), fontFamily = AppFont) },
            text = { Text(s.profileBiometricWarningText, color = c.textPrimary, fontFamily = AppFont, fontSize = 15.sp, lineHeight = 19.sp) },
            confirmButton = {
                TextButton(onClick = {
                    biometricEnabled = true
                    UserStorage.setBiometricUnlockEnabled(context, true)
                    showBiometricWarning = false
                }) {
                    Text(s.profileBiometricWarningConfirm, color = Color(0xFFFFA726))
                }
            },
            dismissButton = {
                TextButton(onClick = { showBiometricWarning = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f))
                }
            }
        )
    }

    if (showPanicDialog) {
        AlertDialog(
            onDismissRequest = { showPanicDialog = false },
            containerColor = c.dialog,
            title = { Text(s.profilePanicTitle, color = c.textPrimary, fontFamily = AppFont) },
            text = {
                Column {
                    Text(
                        s.profilePanicInstruction,
                        color = Color(0xFFFFB74D),
                        fontFamily = AppFont,
                        fontSize = 15.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(s.profilePanicEnterLabel, color = c.textPrimary, fontFamily = AppFont)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = panicPassword,
                        onValueChange = { panicPassword = it; panicPasswordError = "" },
                        label = { Text(s.profilePanicFieldLabel, fontFamily = AppFont) },
                        singleLine = true,
                        isError = panicPasswordError.isNotEmpty(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedLabelColor = c.accent,
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )
                    if (panicPasswordError.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            panicPasswordError,
                            color = Color(0xFFEF5350),
                            fontFamily = AppFont,
                            fontSize = 14.sp
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    // Validation used to be `isNotBlank()` and nothing else.
                    // Two gaps, the second destructive:
                    //
                    //  - PasswordPolicy is enforced on registration and on
                    //    password change, but was skipped here — so the one
                    //    password in the app that triggers irreversible data
                    //    loss was the only one with no floor on it. A short
                    //    panic password is also the one most likely to be hit
                    //    by the owner's own typo.
                    //  - Nothing stopped it being set to the *login* password.
                    //    PasswordGate checks panic first (it must, so duress is
                    //    never rate-limited), so an identical pair silently
                    //    turns every subsequent normal login into a wipe, with
                    //    no warning at the point of setting it and no way back.
                    val candidate = panicPassword
                    panicScope.launch {
                        val problem = withContext(Dispatchers.IO) {
                            when {
                                candidate.length < PasswordPolicy.MIN_LENGTH -> s.registerErrorPasswordLength
                                PasswordPolicy.isCommonPassword(candidate) -> s.registerErrorPasswordCommon
                                UserStorage.checkPassword(context, candidate) -> s.profilePanicErrSameAsLogin
                                else -> null
                            }
                        }
                        if (problem != null) {
                            panicPasswordError = problem
                            return@launch
                        }
                        withContext(Dispatchers.IO) { UserStorage.setPanicPassword(context, candidate) }
                        showPanicDialog = false
                        panicPassword = ""
                        panicPasswordError = ""
                    }
                }) { Text(s.save, color = c.accent, fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showPanicDialog = false; panicPasswordError = "" }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }

    if (showEmergencyInfoDialog) {
        val isAndroid13Plus = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU
        // Whether step 1 was ever tapped this dialog session — the app has no
        // way to verify "restricted settings" got unlocked (Android exposes no
        // API for that to other apps), so this is deliberately just "did they
        // go there at least once", used only to de-emphasize step 1 visually
        // once they've been. Real completion is checked via
        // isEmergencyServiceEnabled() in the ON_RESUME observer above, which
        // auto-closes this dialog once the service is actually on.
        var step1Visited by remember { mutableStateOf(false) }

        AlertDialog(
            onDismissRequest = { showEmergencyInfoDialog = false },
            containerColor = c.dialog,
            title = { Text(s.emergencyInfoTitle, color = c.textPrimary, fontFamily = AppFont) },
            text = {
                // Action buttons live here, full-width and stacked, instead of
                // crammed into AlertDialog's confirmButton row — found live:
                // "Шаг 1: Настройки приложения" + "Шаг 2: Спец. возможности" +
                // "Отмена" all fighting for one narrow horizontal row wrapped
                // character-by-character, unreadable.
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(s.emergencyInfoWarning, color = c.textPrimary, fontFamily = AppFont, fontSize = 15.sp, lineHeight = 18.sp)

                    if (isAndroid13Plus) {
                        EmergencyStepRow(s.emergencyInfoStepLabel(1), s.emergencyInfoStep1Desc, done = step1Visited)
                        Button(
                            onClick = {
                                step1Visited = true
                                context.startActivity(
                                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                        data = android.net.Uri.fromParts("package", context.packageName, null)
                                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    }
                                )
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = c.cardAlt)
                        ) { Text(s.emergencyInfoOpenAppSettings, color = c.accent, fontFamily = AppFont, fontSize = 15.sp) }

                        EmergencyStepRow(s.emergencyInfoStepLabel(2), s.emergencyInfoStep2Desc, done = false, emphasize = step1Visited)
                        Button(
                            onClick = {
                                context.startActivity(
                                    Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = if (step1Visited) c.accent else c.cardAlt)
                        ) { Text(s.emergencyInfoOpenSettings, color = if (step1Visited) (if (c.isDark) Color.White else c.textPrimary) else c.accent, fontFamily = AppFont, fontSize = 15.sp) }
                    } else {
                        Text(s.emergencyInfoLegacyDesc, color = c.textPrimary, fontFamily = AppFont, fontSize = 15.sp)
                        Button(
                            onClick = {
                                context.startActivity(
                                    Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = c.accent)
                        ) { Text(s.emergencyInfoOpenSettings, color = if (c.isDark) Color.White else c.textPrimary, fontFamily = AppFont, fontSize = 15.sp) }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showEmergencyInfoDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }
}
