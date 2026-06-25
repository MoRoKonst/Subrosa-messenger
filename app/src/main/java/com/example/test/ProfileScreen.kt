package com.bcon.messenger

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.content.pm.PackageManager
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
import com.bcon.messenger.ui.theme.LocalBeaconColors
import com.bcon.messenger.ui.theme.BeaconTheme
import com.bcon.messenger.ui.theme.beaconColorsFor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val AppFont = FontFamily(Font(R.font.jetbrainsmono_regular))

private fun extractFingerprint(inviteCode: String): String? {
    return try {
        inviteCode.split("&").find { it.startsWith("fp=") }?.removePrefix("fp=")
    } catch (e: Exception) { null }
}

// ─── Shared sub-composables ────────────────────────────────────────────────────

@Composable
private fun PSection(label: String) {
    val c = LocalBeaconColors.current
    Text(
        text = label.uppercase(),
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 20.dp, top = 24.dp, bottom = 8.dp),
        fontSize = 11.sp,
        fontFamily = AppFont,
        fontWeight = FontWeight.SemiBold,
        color = c.textPrimary.copy(alpha = 0.45f),
        letterSpacing = 1.sp
    )
}

@Composable
private fun PRow(
    title: String,
    titleColor: Color? = null,
    subtitle: String? = null,
    onClick: (() -> Unit)? = null,
    trailing: @Composable () -> Unit = {}
) {
    val c = LocalBeaconColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 15.sp,
                fontFamily = AppFont,
                color = titleColor ?: c.textPrimary
            )
            if (subtitle != null) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    fontSize = 12.sp,
                    fontFamily = AppFont,
                    color = c.textPrimary.copy(alpha = 0.5f)
                )
            }
        }
        trailing()
    }
}

@Composable
private fun PDivider() {
    val c = LocalBeaconColors.current
    HorizontalDivider(
        modifier = Modifier.padding(horizontal = 20.dp),
        color = c.textPrimary.copy(alpha = 0.08f),
        thickness = 0.5.dp
    )
}

@Composable
private fun PChevron() {
    val c = LocalBeaconColors.current
    Icon(
        imageVector = Icons.Default.KeyboardArrowRight,
        contentDescription = null,
        tint = c.textPrimary.copy(alpha = 0.30f),
        modifier = Modifier.size(20.dp)
    )
}

// ─── Main screen ──────────────────────────────────────────────────────────────

/** Проверяет, активирован ли EmergencyService в системных настройках доступности */
private fun isEmergencyServiceEnabled(context: android.content.Context): Boolean =
    (context.getSystemService(android.content.Context.ACCESSIBILITY_SERVICE) as AccessibilityManager)
        .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        .any {
            it.resolveInfo.serviceInfo.packageName == context.packageName &&
            it.resolveInfo.serviceInfo.name.contains("EmergencyService")
        }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileScreen(
    onBack: () -> Unit,
    onOpenServers: () -> Unit,
    onOpenBackup: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onOpenWipeSettings: () -> Unit = {},
    onOpenSupport: () -> Unit = {}
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    // ── State ──────────────────────────────────────────────────────────────
    var showNotMeConfirm   by remember { mutableStateOf(false) }
    var showSupportDialog  by remember { mutableStateOf(false) }
    var showQr             by remember { mutableStateOf(false) }
    var showCopied         by remember { mutableStateOf(false) }
    var showLockDialog     by remember { mutableStateOf(false) }
    var showPanicDialog    by remember { mutableStateOf(false) }
    var panicPassword      by remember { mutableStateOf("") }
    var hideNotif          by remember { mutableStateOf(UserStorage.getHideNotificationContent(context)) }
    var currentLock        by remember { mutableStateOf(UserStorage.getAutoLockTimeout(context)) }
    var emergencyEnabled        by remember { mutableStateOf(UserStorage.isEmergencyWipeEnabled(context) && isEmergencyServiceEnabled(context)) }
    var showEmergencyInfoDialog by remember { mutableStateOf(false) }

    val displayName      = UserStorage.getUserDisplayName(context)
    val userId           = UserStorage.getUserId(context)
    val clipboardManager = LocalClipboardManager.current
    val currentTheme     by MainActivity.currentTheme.collectAsState()

    // Обновляем состояние переключателя когда пользователь возвращается из системных настроек
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                val active = isEmergencyServiceEnabled(context)
                emergencyEnabled = active && UserStorage.isEmergencyWipeEnabled(context)
                if (!active) UserStorage.setEmergencyWipeEnabled(context, false)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val lockLabels = mapOf(
        0    to s.profileLockOff,
        60   to s.profileLock1min,
        300  to s.profileLock5min,
        900  to s.profileLock15min,
        1800 to s.profileLock30min
    )

    val inviteCode = remember {
        try {
            val fresh = InviteCodeManager.generateInviteCode(
                CryptoManager.getPublicKey(),
                CryptoManager.getPrivateKeyPublic(),
                displayName.ifBlank { userId }
            )
            UserStorage.saveInviteCode(context, fresh)
            // Сохраняем mailboxTag из нового инвайта — будем опрашивать сервер по нему
            InviteCodeManager.parseInviteCode(fresh)?.mailboxTag?.let { tag ->
                AnonTokenManager.addMyMailboxTag(context, tag)
            }
            fresh
        } catch (e: Exception) {
            UserStorage.getInviteCode(context) ?: userId
        }
    }
    val fingerprint      = remember { userId.takeIf { it.isNotBlank() } }
    val emojiFingerprint = remember { fingerprint?.let { fingerprintToEmoji(it) } }
    val qrBitmap         = remember { generateQRCode(inviteCode, 512) }

    // ── Avatar ─────────────────────────────────────────────────────────────
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
                    val scaled = android.graphics.Bitmap.createScaledBitmap(bmp, 128, 128, true)
                    val out = java.io.ByteArrayOutputStream()
                    scaled.compress(android.graphics.Bitmap.CompressFormat.JPEG, 85, out)
                    val b64 = android.util.Base64.encodeToString(out.toByteArray(), android.util.Base64.NO_WRAP)
                    withContext(Dispatchers.Main) {
                        myAvatarBitmap = scaled
                        AvatarStore.avatars[userId] = scaled
                        context.startService(
                            android.content.Intent(context, MessengerService::class.java).apply {
                                putExtra("avatar_update", b64)
                            }
                        )
                    }
                } catch (e: Exception) {
                    android.util.Log.e("ProfileScreen", "Ошибка загрузки фото: ${e.message}")
                }
            }
        }
    }

    // ── QR scanner ────────────────────────────────────────────────────────
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
            Color(0xFF2481CC), Color(0xFFE74C3C), Color(0xFF27AE60),
            Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
        )[displayName.hashCode().absoluteValue % 6]
    }


    // ══════════════════════════════════════════════════════════════════════
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

                // ── Header ────────────────────────────────────────────────
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
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = s.back,
                                tint = Color.White
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Avatar + glow ring + camera badge
                    Box(
                        modifier = Modifier
                            .size(108.dp)
                            .clickable { galleryLauncher.launch("image/*") },
                        contentAlignment = Alignment.Center
                    ) {
                        // Кольцо-свечение
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
                        // Аватар
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
                                            text = displayName.first().uppercaseChar().toString(),
                                            fontSize = 40.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White,
                                            fontFamily = AppFont
                                        )
                                    }
                                }
                            }
                        }
                        // Camera badge
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
                                tint = Color.White,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Text(
                        text = displayName,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        fontFamily = AppFont
                    )

                    // Emoji fingerprint pill
                    if (emojiFingerprint != null) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Surface(
                            shape = RoundedCornerShape(20.dp),
                            color = c.textPrimary.copy(alpha = 0.10f)
                        ) {
                            Text(
                                text = emojiFingerprint,
                                fontSize = 22.sp,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)
                            )
                        }
                        Spacer(modifier = Modifier.height(5.dp))
                        Text(
                            text = s.profileFingerprintHint,
                            fontSize = 11.sp,
                            color = c.textPrimary.copy(alpha = 0.55f),
                            fontFamily = AppFont,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 40.dp)
                        )
                    }
                }

                // ── Invite / QR ───────────────────────────────────────────
                PSection(s.profileInviteCode)
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {
                        // Code preview + copy + share
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(start = 20.dp, end = 8.dp, top = 12.dp, bottom = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = inviteCode.take(30) + "…",
                                fontSize = 12.sp,
                                fontFamily = AppFont,
                                color = c.accent,
                                maxLines = 1,
                                modifier = Modifier.weight(1f)
                            )
                            IconButton(onClick = {
                                clipboardManager.setText(AnnotatedString(inviteCode))
                                showCopied = true
                            }) { Text("📋", fontSize = 18.sp) }
                            IconButton(onClick = {
                                val i = Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_TEXT, inviteCode)
                                }
                                context.startActivity(Intent.createChooser(i, s.profileShareCode))
                            }) { Text("📤", fontSize = 18.sp) }
                        }
                        if (showCopied) {
                            LaunchedEffect(Unit) { kotlinx.coroutines.delay(2000); showCopied = false }
                            Text(
                                text = s.profileCodeCopied,
                                fontSize = 13.sp,
                                color = Color(0xFF27AE60),
                                fontFamily = AppFont,
                                modifier = Modifier.padding(start = 20.dp, bottom = 8.dp)
                            )
                        }

                        PDivider()
                        PRow(
                            title = if (showQr) s.profileHideQr else s.profileShowQr,
                            onClick = { showQr = !showQr },
                            trailing = {
                                Text(
                                    if (showQr) "▲" else "▼",
                                    fontSize = 11.sp,
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
                                    fontSize = 11.sp,
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

                // ── Appearance ────────────────────────────────────────────
                PSection(s.profileThemeLabel)
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
                                BeaconTheme.NAVY  to s.profileThemeNavy,
                                BeaconTheme.DARK  to s.profileThemeDark,
                                BeaconTheme.LIGHT to s.profileThemeLight
                            ).forEach { (theme, label) ->
                                val isSelected = theme == currentTheme
                                val previewColors = beaconColorsFor(theme)
                                Surface(
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(38.dp)
                                        .clickable {
                                            UserStorage.setTheme(context, theme)
                                            MainActivity.currentTheme.value = theme
                                        },
                                    shape = RoundedCornerShape(10.dp),
                                    color = previewColors.gradientEnd.copy(
                                        alpha = if (isSelected) 0.55f else 0.18f
                                    ),
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
                                            fontSize = 11.sp,
                                            fontFamily = AppFont,
                                            color = if (isSelected) Color.White
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
                            onClick = {
                                val newLang = if (s.langCode == "ru") "en" else "ru"
                                UserStorage.setLanguage(context, newLang)
                                MainActivity.currentLanguage.value = newLang
                            },
                            trailing = { PChevron() }
                        )
                    }
                }

                // ── Security ──────────────────────────────────────────────
                PSection(s.profileSectionSecurity)
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
                                        fontSize = 12.sp,
                                        color = Color(0xFF4CAF50),
                                        fontFamily = AppFont
                                    )
                                } else {
                                    Text(
                                        s.setAction,
                                        fontSize = 13.sp,
                                        color = c.accent,
                                        fontFamily = AppFont
                                    )
                                }
                            }
                        )
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
                                                // Сервис не активирован — показываем инструкцию
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
                    }
                }

                // ── General ───────────────────────────────────────────────
                PSection(s.profileSectionGeneral)
                Card(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = c.card)
                ) {
                    Column {
                        PRow(s.profileServers,    onClick = onOpenServers,              trailing = { PChevron() })
                        PDivider()
                        PRow(s.profileBackup,     onClick = onOpenBackup,               trailing = { PChevron() })
                        PDivider()
                        PRow(s.profileSupport,    onClick = { showSupportDialog = true }, trailing = { PChevron() })
                        PDivider()
                        PRow(s.profileDiagnostics, onClick = onOpenDiagnostics,         trailing = { PChevron() })
                        PDivider()
                        PRow(s.wipeSettingsTitle,  onClick = onOpenWipeSettings,         trailing = { PChevron() })
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ── Danger zone ───────────────────────────────────────────
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
                        Text("⚠️", fontSize = 18.sp, modifier = Modifier.padding(end = 12.dp))
                        Text(
                            s.profileNotMe,
                            fontSize = 15.sp,
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

    // ── Dialogs ───────────────────────────────────────────────────────────────

    if (showLockDialog) {
        AlertDialog(
            onDismissRequest = { showLockDialog = false },
            containerColor = c.dialog,
            title = { Text(s.profileAutoLock, color = Color.White, fontFamily = AppFont) },
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
                            Text(label, color = c.textPrimary, fontFamily = AppFont, fontSize = 15.sp)
                        }
                    }
                }
            },
            confirmButton = {}
        )
    }

    if (showPanicDialog) {
        AlertDialog(
            onDismissRequest = { showPanicDialog = false },
            containerColor = c.dialog,
            title = { Text(s.profilePanicTitle, color = Color.White, fontFamily = AppFont) },
            text = {
                Column {
                    Text(
                        s.profilePanicInstruction,
                        color = Color(0xFFFFB74D),
                        fontFamily = AppFont,
                        fontSize = 13.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(s.profilePanicEnterLabel, color = c.textPrimary, fontFamily = AppFont)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = panicPassword,
                        onValueChange = { panicPassword = it },
                        label = { Text(s.profilePanicFieldLabel, fontFamily = AppFont) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedLabelColor = c.accent,
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (panicPassword.isNotBlank()) {
                        UserStorage.setPanicPassword(context, panicPassword)
                        showPanicDialog = false
                        panicPassword = ""
                    }
                }) { Text(s.save, color = c.accent, fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showPanicDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }

    if (showNotMeConfirm) {
        AlertDialog(
            onDismissRequest = { showNotMeConfirm = false },
            containerColor = c.dialog,
            title = { Text(s.profileNotMeTitle, color = Color.White, fontFamily = AppFont) },
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

    // ── Emergency wipe: инструкция по активации accessibility-сервиса ─────────
    if (showEmergencyInfoDialog) {
        AlertDialog(
            onDismissRequest = { showEmergencyInfoDialog = false },
            containerColor = c.dialog,
            title = { Text(s.emergencyInfoTitle, color = Color.White, fontFamily = AppFont) },
            text = { Text(s.emergencyInfoMessage, color = c.textPrimary, fontFamily = AppFont, fontSize = 13.sp) },
            confirmButton = {
                // На Android 13+ сначала нужно разрешить «огр. настройки» в инфо о приложении
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    Row {
                        TextButton(onClick = {
                            showEmergencyInfoDialog = false
                            context.startActivity(
                                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                    data = android.net.Uri.fromParts("package", context.packageName, null)
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                            )
                        }) { Text(s.emergencyInfoOpenAppSettings, color = c.accent, fontFamily = AppFont) }
                        TextButton(onClick = {
                            showEmergencyInfoDialog = false
                            context.startActivity(
                                Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }) { Text(s.emergencyInfoOpenSettings, color = c.accent, fontFamily = AppFont) }
                    }
                } else {
                    TextButton(onClick = {
                        showEmergencyInfoDialog = false
                        context.startActivity(
                            Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    }) { Text(s.emergencyInfoOpenSettings, color = c.accent, fontFamily = AppFont) }
                }
            },
            dismissButton = {
                TextButton(onClick = { showEmergencyInfoDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }

    if (showSupportDialog) {
        AlertDialog(
            onDismissRequest = { showSupportDialog = false },
            containerColor = c.dialog,
            title = { Text(SupportConfig.DIALOG_TITLE, color = Color.White, fontFamily = AppFont) },
            text = {
                Text(
                    SupportConfig.DIALOG_TEXT,
                    color = c.textPrimary,
                    fontFamily = AppFont,
                    fontSize = 14.sp
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    if (SupportConfig.isConfigured) {
                        ChatStorage.addContact(context, SupportConfig.FINGERPRINT)
                        ChatStorage.saveContactPublicKey(context, SupportConfig.FINGERPRINT, SupportConfig.PUBLIC_KEY)
                        ChatStorage.saveContactName(context, SupportConfig.FINGERPRINT, SupportConfig.NAME)
                    }
                    showSupportDialog = false
                    onOpenSupport()
                }) { Text(s.write, color = c.accent, fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showSupportDialog = false }) {
                    Text(s.close, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }
}
