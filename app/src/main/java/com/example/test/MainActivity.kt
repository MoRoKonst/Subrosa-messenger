package com.subrosa.messenger

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.accessibility.AccessibilityManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import com.subrosa.messenger.ui.theme.TESTTheme
import com.subrosa.messenger.ui.theme.SubrosaTheme
import com.subrosa.messenger.ui.theme.subrosaColorsFor
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import java.io.File
import androidx.compose.runtime.LaunchedEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.core.view.WindowCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import androidx.lifecycle.lifecycleScope
import androidx.appcompat.app.AppCompatDelegate
import android.net.Uri
import kotlinx.coroutines.flow.MutableStateFlow
import com.subrosa.messenger.GroupInfoScreen
import com.google.android.datatransport.BuildConfig

class MainActivity : FragmentActivity() {
    companion object {
        val selectedPhotoUri = MutableStateFlow<Uri?>(null)
        val selectedFileUri = MutableStateFlow<Uri?>(null)
        const val PICK_IMAGE_REQUEST = 200
        const val PICK_FILE_REQUEST = 201

        val pendingChatId = MutableStateFlow<String?>(null)
        val pendingChatType = MutableStateFlow<String?>(null)

        val pendingChannelLink = MutableStateFlow<String?>(null)

        val pendingOpenChannelId = MutableStateFlow<String?>(null)

        val pendingIncomingCall = MutableStateFlow<Triple<String, Boolean, String>?>(null)

        val chatListVersion = MutableStateFlow(0L)

        val currentLanguage = MutableStateFlow("ru")

        val currentTheme = MutableStateFlow(SubrosaTheme.NAVY)

        val shouldResetToCalculator = MutableStateFlow(false)
    }

    private val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)

        if (ParanoidMode.isEnabled) {
            val isOurs = intent?.action == "EMERGENCY_WIPE" ||
                intent?.action == "OPEN_INCOMING_CALL" ||
                intent?.action == "OPEN_ACTIVE_CALL" ||
                intent?.data?.scheme == "beacon" ||
                intent?.hasExtra("open_chat") == true
            if (!isOurs) return
        }

        if (intent?.action == "EMERGENCY_WIPE") emergencyWipe(withDecoy = true)

        if (intent?.action == "OPEN_INCOMING_CALL") {

            return
        }
        if (intent?.action == "OPEN_ACTIVE_CALL") {

            return
        }

        intent?.getStringExtra("open_chat")?.let { chatId ->
            pendingChatId.value = chatId
            pendingChatType.value = intent.getStringExtra("chat_type") ?: "chat"
        }

        handleChannelDeepLink(intent)
    }

    private fun handleChannelDeepLink(intent: Intent?) {
        // Channels feature disabled — see plan history to re-enable.
        // val uri = intent?.data
        // if (uri != null && uri.scheme == "beacon" && uri.host == "channel") {
        //     pendingChannelLink.value = uri.toString()
        //     return
        // }
        //
        // intent?.getStringExtra("open_channel")?.let { channelId ->
        //     pendingOpenChannelId.value = channelId
        // }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        super.onCreate(savedInstanceState)
        CryptoManager.init(this)
        ParanoidMode.init(this)
        HoneyTokenManager.init(this)

        // TEMP: disabled for local screenshot-based testing this session — MUST be restored before any real build.
        // window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)

        window.decorView.filterTouchesWhenObscured = true
        WindowCompat.setDecorFitsSystemWindows(window, false)

        if (intent?.action == "EMERGENCY_WIPE") { emergencyWipe(withDecoy = true); return }

        intent?.getStringExtra("open_chat")?.let { chatId ->
            pendingChatId.value = chatId
            pendingChatType.value = intent.getStringExtra("chat_type") ?: "chat"
        }

        handleChannelDeepLink(intent)

        UserStorage.migrateDecoyState(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 0)
        }

        if (!UserStorage.getCalculatorDisguise(this)) checkSpyApps()

        currentLanguage.value = UserStorage.getLanguage(this)

        currentTheme.value = UserStorage.getTheme(this)

        TorManager.start(this, activityScope, if (UserStorage.getLanguage(this) == "en") enStrings else ruStrings)

        registerReceiver(screenLockReceiver, android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF))

        contentResolver.registerContentObserver(
            android.provider.Settings.Secure.getUriFor(
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ),
            false,
            accessibilityObserver
        )

        enableEdgeToEdge()
        setContent {

            val theme by currentTheme.collectAsState()
            val subrosaColors = subrosaColorsFor(theme)

            TESTTheme(subrosaColors = subrosaColors) {

                val lang by currentLanguage.collectAsState()
                val strings = if (lang == "en") enStrings else ruStrings

                androidx.compose.runtime.CompositionLocalProvider(LocalStrings provides strings) {
                    val context = LocalContext.current
                    var rootCheckResult by remember { mutableStateOf<RootDetector.RootCheckResult?>(null) }
                    var signatureTampered by remember { mutableStateOf(false) }

                    LaunchedEffect(Unit) {

                        if (UserStorage.getCalculatorDisguise(context)) return@LaunchedEffect

                        val result = withContext(Dispatchers.IO) { RootDetector.checkResult() }
                        if (result.level != RootDetector.RootLevel.NONE) {
                            if (ParanoidMode.isEnabled) {
                                ParanoidMode.clearLogs()
                                finishAffinity()
                                return@LaunchedEffect
                            }
                            rootCheckResult = result
                        }
                        if (!BuildConfig.DEBUG) {
                            val sigOk = withContext(Dispatchers.IO) { SignatureValidator.isValidSignature(applicationContext) }
                            if (!sigOk) signatureTampered = true
                        }
                    }

                    val appFont = FontFamily(Font(R.font.jetbrainsmono_regular))
                    val result = rootCheckResult
                    val s = LocalStrings.current

                    when {

                        UserStorage.getCalculatorDisguise(context) -> Surface { AppNavigation() }

                        signatureTampered -> AlertDialog(
                            onDismissRequest = {},
                            containerColor = Color(0xFF1a0a0a),
                            title = { Text(s.tamperTitle, color = Color(0xFFFF4444), fontFamily = appFont) },
                            text = {
                                Text(
                                    s.tamperText,
                                    color = Color(0xFFE0E6FF),
                                    fontFamily = appFont,
                                    fontSize = 14.sp
                                )
                            },
                            confirmButton = {
                                TextButton(onClick = { finish() }) {
                                    Text(s.tamperClose, color = Color(0xFFFF4444), fontFamily = appFont)
                                }
                            }
                        )
                        result?.level == RootDetector.RootLevel.DANGER -> AlertDialog(
                            onDismissRequest = {},
                            containerColor = Color(0xFF1a0a0a),
                            title = { Text(s.rootDangerTitle, color = Color(0xFFFF4444), fontFamily = appFont) },
                            text = {
                                Column {
                                    Text(
                                        s.rootDangerText,
                                        color = Color(0xFFE0E6FF),
                                        fontFamily = appFont,
                                        fontSize = 14.sp
                                    )
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Text(
                                        s.rootDangerReasons(result.reasons.joinToString("\n") { "• $it" }),
                                        color = Color(0xFFFF8888),
                                        fontFamily = appFont,
                                        fontSize = 13.sp
                                    )
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Text(
                                        s.rootDangerRecommend,
                                        color = Color(0xFFE0E6FF).copy(alpha = 0.7f),
                                        fontFamily = appFont,
                                        fontSize = 13.sp
                                    )
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = { rootCheckResult = null }) {
                                    Text(s.rootDangerContinue, color = Color(0xFFFF8888), fontFamily = appFont)
                                }
                            },
                            dismissButton = {
                                TextButton(onClick = { finish() }) {
                                    Text(s.close, color = Color(0xFFD9A566), fontFamily = appFont)
                                }
                            }
                        )
                        result?.level == RootDetector.RootLevel.WARNING -> AlertDialog(
                            onDismissRequest = { rootCheckResult = null },
                            containerColor = Color(0xFF4A151A),
                            title = { Text(s.rootWarningTitle, color = Color(0xFFFFCC00), fontFamily = appFont) },
                            text = {
                                Column {
                                    Text(
                                        s.rootWarningText,
                                        color = Color(0xFFE0E6FF),
                                        fontFamily = appFont,
                                        fontSize = 14.sp
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        "• ${result.reasons.first()}",
                                        color = Color(0xFFFFCC88),
                                        fontFamily = appFont,
                                        fontSize = 13.sp
                                    )
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = { rootCheckResult = null }) {
                                    Text(s.rootWarningConfirm, color = Color(0xFFD9A566), fontFamily = appFont)
                                }
                            }
                        )
                        else -> Surface { AppNavigation() }
                    }
                }
            }
        }
    }

    private val emergencyReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: android.content.Context?, intent: android.content.Intent?) {
            emergencyWipe(withDecoy = true)
        }
    }

    private var volumeDownCount = 0
    private var lastVolumeDownMs = 0L

    override fun onKeyDown(keyCode: Int, event: android.view.KeyEvent?): Boolean {
        if (keyCode == android.view.KeyEvent.KEYCODE_VOLUME_DOWN) {
            val now = System.currentTimeMillis()
            if (now - lastVolumeDownMs > 3000) volumeDownCount = 0
            lastVolumeDownMs = now
            volumeDownCount++
            if (volumeDownCount >= 5) {
                volumeDownCount = 0
                emergencyWipe(withDecoy = true)
                return true
            }
        }
        return super.onKeyDown(keyCode, event)
    }

    var lastActiveTimeMs = System.currentTimeMillis()

    val isAppLocked = kotlinx.coroutines.flow.MutableStateFlow(false)

    private var screenWasLocked = false

    private val knownAccessibilityServices = mutableSetOf<String>()

    private val accessibilityObserver = object : android.database.ContentObserver(
        android.os.Handler(android.os.Looper.getMainLooper())
    ) {
        override fun onChange(selfChange: Boolean) {
            checkAccessibilityServicesRuntime()
        }
    }
    private val screenLockReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(ctx: android.content.Context?, intent: android.content.Intent?) {
            if (intent?.action == android.content.Intent.ACTION_SCREEN_OFF) {

                if (CallManager.callId.isEmpty()) screenWasLocked = true
            }
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        lastActiveTimeMs = System.currentTimeMillis()
    }

    override fun onResume() {
        super.onResume()

        if (ParanoidMode.isEnabled) {
            lifecycleScope.launch {
                val rootResult = withContext(Dispatchers.IO) { RootDetector.checkResult() }
                if (rootResult.level != RootDetector.RootLevel.NONE) {
                    ParanoidMode.clearLogs()
                    finishAffinity()
                    return@launch
                }
                val idsResult = withContext(Dispatchers.IO) { IntrusionDetector.scan(this@MainActivity) }
                ParanoidMode.updateIdsResult(idsResult)
                val honeyOk = withContext(Dispatchers.IO) { HoneyTokenManager.checkIntegrity(this@MainActivity) }
                if (idsResult.isCritical() || !honeyOk) {
                    ParanoidMode.handleThreat(this@MainActivity, idsResult, !honeyOk)
                }
            }
        }

        val timeoutWipeHours = UserStorage.getTimeoutWipeHours(this)
        if (timeoutWipeHours > 0 && UserStorage.isRegistered(this)) {
            val lastEntry = UserStorage.getLastPasswordEntry(this)
            val now = System.currentTimeMillis()
            if (lastEntry > 0L && (now - lastEntry) > timeoutWipeHours * 3_600_000L) {
                DeadMansSwitchManager.triggerWarningImmediate(this)
                return
            }
        }
        val filter = android.content.IntentFilter("com.subrosa.messenger.EMERGENCY_WIPE")
        registerReceiver(emergencyReceiver, filter, android.content.Context.RECEIVER_NOT_EXPORTED)

        if (UserStorage.isRegistered(this)) {

            val callActive = CallManager.callId.isNotEmpty()

            if (screenWasLocked && !callActive) {
                screenWasLocked = false
                StorageKeyManager.lock()
                isAppLocked.value = true
                return
            }
            screenWasLocked = false

            val timeoutSecs = UserStorage.getAutoLockTimeout(this)
            if (timeoutSecs > 0 && !callActive) {
                val elapsed = (System.currentTimeMillis() - lastActiveTimeMs) / 1000
                if (elapsed >= timeoutSecs) {
                    StorageKeyManager.lock()
                    isAppLocked.value = true
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()

        if (UserStorage.getCalculatorDisguise(this) && UserStorage.isRegistered(this)) {
            StorageKeyManager.lock()
            shouldResetToCalculator.value = true
        }
    }

    override fun onPause() {
        super.onPause()
        lastActiveTimeMs = System.currentTimeMillis()
        try { unregisterReceiver(emergencyReceiver) } catch (e: Exception) {}
    }

    override fun onDestroy() {
        try { unregisterReceiver(screenLockReceiver) } catch (e: Exception) {}
        try { contentResolver.unregisterContentObserver(accessibilityObserver) } catch (e: Exception) {}
        super.onDestroy()
        TorManager.stop()
    }

    private fun isTrustedPackage(pkg: String) = pkg == packageName ||
        pkg.startsWith("com.android.") || pkg == "android" ||
        pkg.startsWith("com.google.android") ||
        pkg.startsWith("com.samsung.android") ||
        pkg.startsWith("com.miui") ||
        pkg.startsWith("com.xiaomi.") ||
        pkg.startsWith("com.huawei.android") ||
        pkg.startsWith("ru.miui")

    private fun checkAccessibilityServicesRuntime() {
        if (UserStorage.getCalculatorDisguise(this)) return
        val am = getSystemService(AccessibilityManager::class.java) ?: return
        val s = if (UserStorage.getLanguage(this) == "en") enStrings else ruStrings

        val current = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .map { it.resolveInfo.serviceInfo.packageName }
            .filter { !isTrustedPackage(it) }
            .toSet()

        val newThreats = current - knownAccessibilityServices
        knownAccessibilityServices.clear()
        knownAccessibilityServices.addAll(current)

        if (newThreats.isEmpty()) return

        android.app.AlertDialog.Builder(this)
            .setTitle(s.spyAppsTitle)
            .setMessage(
                "⚠️ ${if (UserStorage.getLanguage(this) == "en")
                    "A service that can read the screen or simulate taps just became active:"
                    else "Только что активирована служба, которая может читать экран или имитировать нажатия:"
                }\n\n${newThreats.joinToString("\n") { "  • $it" }}"
            )
            .setPositiveButton(s.ok, null)
            .setCancelable(false)
            .show()
    }

    private fun checkSpyApps() {
        val s = if (UserStorage.getLanguage(this) == "en") enStrings else ruStrings
        val warnings = mutableListOf<String>()
        val suspiciousPackages = mutableSetOf<String>()

        val am = getSystemService(AccessibilityManager::class.java)
        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        val suspiciousServices = enabledServices.filter { svc ->
            !isTrustedPackage(svc.resolveInfo.serviceInfo.packageName)
        }
        if (suspiciousServices.isNotEmpty()) {
            suspiciousPackages += suspiciousServices.map { it.resolveInfo.serviceInfo.packageName }
            warnings += s.spyAppsAccessibilitySection +
                suspiciousServices.joinToString("\n") { "  • ${it.resolveInfo.serviceInfo.packageName}" }
        }

        val dpm = getSystemService(DevicePolicyManager::class.java)
        val admins = dpm.getActiveAdmins() ?: emptyList()
        val suspiciousAdmins = admins.filter { cn -> !isTrustedPackage(cn.packageName) }
        if (suspiciousAdmins.isNotEmpty()) {
            suspiciousPackages += suspiciousAdmins.map { it.packageName }
            warnings += s.spyAppsAdminsSection +
                suspiciousAdmins.joinToString("\n") { "  • ${it.packageName}" }
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            try {
                val appOps = getSystemService(android.app.AppOpsManager::class.java)
                val overlayApps = packageManager
                    .getInstalledPackages(android.content.pm.PackageManager.GET_PERMISSIONS)
                    .filter { pkg ->
                        !isTrustedPackage(pkg.packageName) &&
                        pkg.requestedPermissions
                            ?.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW) == true &&
                        appOps.checkOpNoThrow(
                            android.app.AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                            pkg.applicationInfo.uid,
                            pkg.packageName
                        ) == android.app.AppOpsManager.MODE_ALLOWED
                    }
                if (overlayApps.isNotEmpty()) {
                    suspiciousPackages += overlayApps.map { it.packageName }
                    warnings += s.spyAppsOverlaySection +
                        overlayApps.joinToString("\n") { "  • ${it.packageName}" }
                }
            } catch (_: Exception) {}
        }

        val prefs = getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
        val lastKnown = prefs.getStringSet("known_suspicious_pkgs", emptySet()) ?: emptySet()
        val hasNewThreats = suspiciousPackages.any { it !in lastKnown }
        prefs.edit().putStringSet("known_suspicious_pkgs", suspiciousPackages).apply()

        if (warnings.isEmpty() || !hasNewThreats) return

        android.app.AlertDialog.Builder(this)
            .setTitle(s.spyAppsTitle)
            .setMessage(s.spyAppsMessage(warnings.joinToString("\n\n")))
            .setPositiveButton(s.ok, null)
            .setNeutralButton(s.spyAppsSettings) { _, _ ->
                try { startActivity(Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
                catch (e: Exception) {}
            }
            .setCancelable(false)
            .show()
    }

    fun emergencyWipe(withDecoy: Boolean = false) {
        WipeManager.hardWipe(this, withDecoy)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PICK_IMAGE_REQUEST && resultCode == RESULT_OK) selectedPhotoUri.value = data?.data
        if (requestCode == PICK_FILE_REQUEST && resultCode == RESULT_OK) selectedFileUri.value = data?.data
    }
}

@Composable
fun TorLoadingScreen(progress: Int, status: String) {
    val c = LocalSubrosaColors.current
    val appFont = FontFamily(Font(R.font.jetbrainsmono_regular))

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(32.dp)
        ) {
            Text("🧅", fontSize = 64.sp, modifier = Modifier.padding(bottom = 24.dp))

            Text(
                "Subrosa Messenger",
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = c.accent,
                fontFamily = appFont,
                modifier = Modifier.padding(bottom = 8.dp)
            )

            Text(
                LocalStrings.current.torConnecting,
                fontSize = 14.sp,
                color = c.textPrimary.copy(alpha = 0.7f),
                fontFamily = appFont,
                modifier = Modifier.padding(bottom = 32.dp)
            )

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .background(c.card, RoundedCornerShape(3.dp))
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(progress / 100f)
                        .height(6.dp)
                        .background(
                            Brush.horizontalGradient(listOf(c.topBar, c.accent)),
                            RoundedCornerShape(3.dp)
                        )
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                "$progress%  $status",
                fontSize = 13.sp,
                color = c.accent,
                fontFamily = appFont
            )

            Spacer(modifier = Modifier.height(48.dp))

            Text(
                LocalStrings.current.torIpHidden,
                fontSize = 12.sp,
                color = c.textPrimary.copy(alpha = 0.4f),
                fontFamily = appFont
            )
        }
    }
}

/** Listens for MessengerService.onTotpRequired — this device is logged
 *  into a TOTP-protected account but has no usable code (fresh backup
 *  restore, lost authenticator). Offers the recovery-code fallback instead
 *  of leaving the user stuck on a silently-failing reconnect loop. Mounted
 *  globally (not tied to one screen) since a reconnect can happen at any
 *  time while logged in. */
@Composable
private fun RecoveryCodeGate() {
    val context = LocalContext.current
    val s = LocalStrings.current
    var messengerService by remember { mutableStateOf<MessengerService?>(null) }
    val connection = remember {
        object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName, binder: android.os.IBinder) {
                messengerService = (binder as MessengerService.LocalBinder).getService()
            }
            override fun onServiceDisconnected(name: android.content.ComponentName) {
                messengerService = null
            }
        }
    }
    LaunchedEffect(Unit) {
        try {
            context.bindService(
                Intent(context, MessengerService::class.java),
                connection,
                android.content.Context.BIND_AUTO_CREATE
            )
        } catch (_: Exception) {}
    }
    DisposableEffect(Unit) {
        onDispose { try { context.unbindService(connection) } catch (_: Exception) {} }
    }

    var showDialog by remember { mutableStateOf(false) }
    var code by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    var submitted by remember { mutableStateOf(false) }

    DisposableEffect(messengerService) {
        val svc = messengerService
        svc?.onTotpRequired = {
            if (submitted) {
                // We already tried a code and totp_required fired again —
                // that submission was rejected.
                error = true
                submitted = false
            }
            showDialog = true
        }
        onDispose { svc?.onTotpRequired = null }
    }

    // Doesn't hook into onStatusChanged (a single shared callback slot other
    // screens also use) — polling avoids fighting over that one slot.
    LaunchedEffect(showDialog, messengerService) {
        while (showDialog) {
            kotlinx.coroutines.delay(1_000)
            if (messengerService?.isOnline() == true) {
                showDialog = false
            }
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { },
            title = { Text(s.totpMandatoryTitle) },
            text = {
                Column {
                    Text(s.totpRecoveryPrompt, fontSize = 13.sp)
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = code,
                        onValueChange = { code = it; error = false },
                        label = { Text(s.totpRecoveryFieldLabel) },
                        singleLine = true,
                        isError = error,
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (error) {
                        Spacer(Modifier.height(4.dp))
                        Text(s.totpRecoveryErr, color = MaterialTheme.colorScheme.error, fontSize = 12.sp)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = code.isNotBlank(),
                    onClick = {
                        messengerService?.submitRecoveryCode(code.trim())
                        code = ""
                        submitted = true
                        error = false
                    }
                ) { Text(s.totpRecoverySubmit) }
            }
        )
    }
}

@Composable
fun AppNavigation() {
    val context = LocalContext.current
    val s = LocalStrings.current

    var torReady by remember { mutableStateOf(TorManager.isConnected) }
    var torProgress by remember { mutableStateOf(TorManager.bootstrapProgress) }
    var torStatus by remember { mutableStateOf(s.torStatusStarting) }
    var torError by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        TorManager.onBootstrapProgress = { progress, status ->
            torProgress = progress
            torStatus = status
        }
        TorManager.onTorReady = {
            torReady = true
        }
        TorManager.onTorError = { error ->
            torError = error
            torReady = true
        }

        if (TorManager.isConnected || !TorManager.isOrbotInstalled(context)) {
            torReady = true
        }
    }

    var screen by remember {
        mutableStateOf(
            when {
                UserStorage.getCalculatorDisguise(context) -> "calculator"
                !UserStorage.isRegistered(context) -> "register"
                else -> "login"
            }
        )
    }

    var isPanicMode by remember { mutableStateOf(false) }
    var openedChat by remember { mutableStateOf("") }
    var openedChannelId by remember { mutableStateOf("") }
    var verifyKeyContact by remember { mutableStateOf("") }

    var callFromUser  by remember { mutableStateOf("") }
    var callIsVideo   by remember { mutableStateOf(false) }
    var callIsGroup   by remember { mutableStateOf(false) }
    var callGroupId   by remember { mutableStateOf("") }
    val pendingCallVal by MainActivity.pendingIncomingCall.collectAsState()

    var pendingVideoCallTarget by remember { mutableStateOf("") }
    val cameraPermLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (pendingVideoCallTarget.isNotEmpty()) {
            val target = pendingVideoCallTarget
            pendingVideoCallTarget = ""
            callIsVideo = granted
            CallManager.startCall(context, target, granted)
            context.startForegroundService(Intent(context, CallService::class.java).apply {
                action = CallService.ACTION_ACTIVE
                putExtra(CallService.EXTRA_PEER_NAME, ChatStorage.getContactName(context, target).ifBlank { target })
            })
            screen = "active_call"
            if (!granted) android.widget.Toast.makeText(
                context, s.noCameraPermissionVoiceOnly, android.widget.Toast.LENGTH_SHORT
            ).show()
        }
    }

    val isLocked by (context as? MainActivity)?.isAppLocked?.collectAsState()
        ?: remember { mutableStateOf(false) }.let { s -> s as androidx.compose.runtime.State<Boolean> }

    var lockPassword by remember { mutableStateOf("") }
    var lockPasswordError by remember { mutableStateOf("") }
    val lockScope = rememberCoroutineScope()

    val lockVisible = isLocked == true && screen != "login" && screen != "register" && screen != "calculator"

    val shouldResetCalc by MainActivity.shouldResetToCalculator.collectAsState()
    LaunchedEffect(shouldResetCalc) {
        if (shouldResetCalc) {

            if (screen != "active_call" && screen != "incoming_call") {
                screen = "calculator"
            }
            MainActivity.shouldResetToCalculator.value = false
        }
    }

    LaunchedEffect(pendingCallVal) {
        val call = pendingCallVal ?: return@LaunchedEffect
        if (screen == "login" || screen == "register") return@LaunchedEffect
        val (callId, isVideo, from) = call
        callFromUser = from
        callIsVideo  = isVideo
        callIsGroup  = CallManager.isGroupCall
        callGroupId  = CallManager.groupId
        screen = "incoming_call"
        MainActivity.pendingIncomingCall.value = null
    }

    val pendingChannelLinkVal by MainActivity.pendingChannelLink.collectAsState()
    val pendingOpenChannelIdVal by MainActivity.pendingOpenChannelId.collectAsState()

    LaunchedEffect(pendingOpenChannelIdVal) {
        val channelId = pendingOpenChannelIdVal ?: return@LaunchedEffect
        if (channelId.isEmpty()) return@LaunchedEffect
        if (screen != "login" && screen != "register") {
            openedChannelId = channelId
            screen = "channel_feed"
            MainActivity.pendingOpenChannelId.value = null
        }
    }

    val pendingChatIdFromNotif by MainActivity.pendingChatId.collectAsState()
    val pendingChatTypeFromNotif by MainActivity.pendingChatType.collectAsState()

    LaunchedEffect(pendingChatIdFromNotif) {
        val chatId = pendingChatIdFromNotif ?: return@LaunchedEffect
        if (chatId.isEmpty()) return@LaunchedEffect
        if (screen != "login" && screen != "register") {
            openedChat = chatId
            screen = pendingChatTypeFromNotif ?: "chat"
            MainActivity.pendingChatId.value = null
            MainActivity.pendingChatType.value = null
        }
    }

    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(30_000)
            if (!ParanoidMode.isEnabled) continue
            val result = withContext(kotlinx.coroutines.Dispatchers.IO) {
                IntrusionDetector.scan(context)
            }
            ParanoidMode.updateIdsResult(result)
            val honeyOk = withContext(kotlinx.coroutines.Dispatchers.IO) {
                HoneyTokenManager.checkIntegrity(context)
            }
            if (result.isCritical() || !honeyOk) {
                ParanoidMode.handleThreat(context, result, !honeyOk)
            }
        }
    }

    if (!torReady && UserStorage.isRegistered(context)) {
        TorLoadingScreen(progress = torProgress, status = torStatus)
        return
    }

    if (isPanicMode) {
        DecoyScreen()
        return
    }

    val panicModeNotif by ParanoidMode.panicModeNotif.collectAsState()
    if (panicModeNotif) {
        DecoyScreen()
        return
    }

    val stealthMode by ParanoidMode.stealthMode.collectAsState()
    if (stealthMode) {
        DecoyScreen()
        return
    }

    val navDepths = remember {
        mapOf(
            "login" to 0, "register" to 0,
            "chats" to 1,
            "chat" to 2, "group_chat" to 2, "channel_feed" to 2,
            "profile" to 2, "create_group" to 2,
            "group_info" to 3, "verify_key" to 3, "backup" to 3,
            "servers" to 3, "security_diagnostics" to 3,
            "incoming_call" to 3, "active_call" to 3,
        )
    }

    Box(modifier = Modifier.fillMaxSize()) {

    AnimatedContent(
        targetState = screen,
        transitionSpec = {
            val fwd = (navDepths[targetState] ?: 1) >= (navDepths[initialState] ?: 1)
            val enter = slideInHorizontally(tween(300, easing = FastOutSlowInEasing)) { if (fwd) it / 5 else -it / 5 } +
                        fadeIn(tween(300))
            val exit  = slideOutHorizontally(tween(260)) { if (fwd) -it / 6 else it / 6 } +
                        fadeOut(tween(230))
            enter togetherWith exit
        },
        label = "nav",
        modifier = Modifier.fillMaxSize()
    ) { currentScreen ->

    when (currentScreen) {
        "calculator" -> CalculatorScreen(onUnlock = {

            val uiState = context.getSharedPreferences("beacon_ui_state", Context.MODE_PRIVATE)
            if (uiState.getBoolean("calc_pending_decoy", false)) {
                uiState.edit().remove("calc_pending_decoy").apply()
                isPanicMode = true
            } else when {

                UserStorage.isDecoyMode(context) -> isPanicMode = true
                !UserStorage.isRegistered(context) -> screen = "register"
                else -> screen = "login"
            }
        })

        "backup" -> BackupScreen(onBack = { screen = "profile" })
        "servers" -> ServersScreen(onBack = { screen = "profile" })
        "security_diagnostics" -> SecurityDiagnosticsScreen(onBack = { screen = "profile" })
        "wipe_settings" -> WipeSettingsScreen(onBack = { screen = "profile" })
        "totp_settings" -> TotpSettingsScreen(onBack = { screen = "profile" })

        "incoming_call" -> IncomingCallScreen(
            from    = callFromUser,
            isVideo = callIsVideo,
            isGroup = callIsGroup,
            groupId = callGroupId,
            onAccept  = { screen = "active_call" },
            onDecline = { screen = if (openedChat.isNotEmpty()) "chat" else "chats" }
        )

        "active_call" -> ActiveCallScreen(
            peerId  = if (callIsGroup) "" else callFromUser,
            isVideo = callIsVideo,
            isGroup = callIsGroup,
            onHangUp = { screen = if (openedChat.isNotEmpty()) "chat" else "chats" }
        )

        "create_group" -> CreateGroupScreen(
            onBack = { screen = "chats" },
            onGroupCreated = { groupId ->
                openedChat = groupId
                screen = "group_chat"
            }
        )

        "group_chat" -> GroupChatScreen(
            groupId = openedChat,
            onBack = { screen = "chats" },
            onOpenInfo = { screen = "group_info" },
            onStartGroupCall = { isVideo ->
                val members = GroupManager.getGroup(context, openedChat)?.members?.toList() ?: emptyList()
                callFromUser = openedChat
                callIsVideo  = isVideo
                callIsGroup  = true
                callGroupId  = openedChat
                CallManager.startGroupCall(context, openedChat, members, isVideo)
                context.startForegroundService(Intent(context, CallService::class.java).apply {
                    action = CallService.ACTION_ACTIVE
                    putExtra(CallService.EXTRA_PEER_NAME, s.groupCallPeerName)
                    putExtra(CallService.EXTRA_IS_GROUP, true)
                })
                screen = "active_call"
            }
        )

        "group_info" -> GroupInfoScreen(
            groupId = openedChat,
            onBack = { screen = "group_chat" }
        )

        "register" -> RegisterScreen(
            context = context,
            onRegistered = {
                if (CryptoManager.hasKeys()) {
                    context.startForegroundService(Intent(context, MessengerService::class.java))
                }
                // Mandatory step, not optional — TOTP for new-device
                // registration only protects an account once it's actually
                // set up, so a brand-new account is defenseless until this
                // runs. See docs/ISSUE_backup_identity_hijack.md.
                screen = "totp_setup_required"
            }
        )

        "totp_setup_required" -> TotpSettingsScreen(
            onBack = {},
            mandatory = true,
            onCompleted = { screen = "chats" }
        )

        "login" -> LoginScreen(
            onLoggedIn = {
                UserStorage.setLastPasswordEntry(context, System.currentTimeMillis())
                if (CryptoManager.hasKeys()) {
                    context.startForegroundService(Intent(context, MessengerService::class.java))
                }
                val chatId = MainActivity.pendingChatId.value
                val chatType = MainActivity.pendingChatType.value ?: "chat"
                if (!chatId.isNullOrEmpty()) {
                    openedChat = chatId
                    screen = chatType
                    MainActivity.pendingChatId.value = null
                    MainActivity.pendingChatType.value = null
                } else {
                    screen = if (UserStorage.isRegistered(context)) "chats" else "register"
                }
            },
            onPanicMode = {

                isPanicMode = true
                if (!UserStorage.isDecoyMode(context)) {

                    lockScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                        kotlinx.coroutines.delay(400)
                        WipeManager.wipeForDecoyKeepAlive(context)
                    }
                }
            }
        )

        "channel_feed" -> ChannelFeedScreen(
            channelId = openedChannelId,
            onBack = { screen = "chats" }
        )

        "chats" -> ChatsScreen(
            onOpenChat = { contact -> openedChat = contact; screen = "chat" },
            onOpenProfile = { screen = "profile" },
            onOpenGroupChat = { groupId -> openedChat = groupId; screen = "group_chat" },
            onCreateGroup = { screen = "create_group" },
            onOpenChannel = { channelId -> openedChannelId = channelId; screen = "channel_feed" },
            pendingChannelLink = pendingChannelLinkVal,
            onChannelLinkConsumed = { MainActivity.pendingChannelLink.value = null }
        )

        "profile" -> ProfileScreen(
            onBack = { screen = "chats" },
            onOpenServers = { screen = "servers" },
            onOpenBackup = { screen = "backup" },
            onOpenDiagnostics = { screen = "security_diagnostics" },
            onOpenWipeSettings = { screen = "wipe_settings" },
            onOpenTotpSettings = { screen = "totp_settings" }
        )

        "verify_key" -> VerifyKeyScreen(
            contactId = verifyKeyContact,
            onBack = { screen = "chat" }
        )

        "chat" -> ChatScreen(
            username = UserStorage.getUserId(context),
            recipient = openedChat,
            onBack = { screen = "chats" },
            onVerifyKey = { verifyKeyContact = openedChat; screen = "verify_key" },
            onStartCall = { isVideo ->
                callFromUser = openedChat
                callIsGroup  = false
                callGroupId  = ""
                val camGranted = context.checkSelfPermission(android.Manifest.permission.CAMERA) ==
                    android.content.pm.PackageManager.PERMISSION_GRANTED
                if (isVideo && !camGranted) {

                    pendingVideoCallTarget = openedChat
                    cameraPermLauncher.launch(android.Manifest.permission.CAMERA)
                } else {
                    callIsVideo = isVideo
                    CallManager.startCall(context, openedChat, isVideo)
                    context.startForegroundService(Intent(context, CallService::class.java).apply {
                        action = CallService.ACTION_ACTIVE
                        putExtra(CallService.EXTRA_PEER_NAME, ChatStorage.getContactName(context, openedChat).ifBlank { openedChat })
                    })
                    screen = "active_call"
                }
            }
        )
    }

    }

    if (screen !in listOf("register", "login", "totp_setup_required", "calculator")) {
        RecoveryCodeGate()
    }

    AnimatedVisibility(
        visible = lockVisible,
        enter = fadeIn(tween(280)),
        exit  = fadeOut(tween(320)) + scaleOut(tween(360), targetScale = 1.06f),
        modifier = Modifier.fillMaxSize()
    ) {
        val lockFont = FontFamily(Font(R.font.jetbrainsmono_regular))
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(Color(0xFF2B0F14), Color(0xFF180A0C)))),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier
                    .padding(32.dp)
                    .widthIn(max = 340.dp)
            ) {
                Text("🔒", fontSize = 64.sp, modifier = Modifier.padding(bottom = 24.dp))
                Text(s.lockTitle, fontSize = 18.sp, color = Color.White, fontFamily = lockFont)
                Spacer(modifier = Modifier.height(24.dp))

                OutlinedTextField(
                    value = lockPassword,
                    onValueChange = { lockPassword = it; lockPasswordError = "" },
                    label = { Text(s.loginPassword, fontFamily = lockFont) },
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    singleLine = true,
                    isError = lockPasswordError.isNotEmpty(),
                    supportingText = if (lockPasswordError.isNotEmpty()) {
                        { Text(lockPasswordError, color = Color(0xFFE74C3C), fontFamily = lockFont) }
                    } else null,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Password,
                        imeAction = androidx.compose.ui.text.input.ImeAction.Done
                    ),
                    keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                        onDone = {
                            if (lockPassword.isNotBlank()) {
                                lockScope.launch {
                                    if (UserStorage.isPanicPassword(context, lockPassword)) {
                                        lockPassword = ""
                                        (context as? MainActivity)?.emergencyWipe(withDecoy = true)
                                    } else if (UserStorage.checkPassword(context, lockPassword)) {
                                        withContext(Dispatchers.IO) {
                                            StorageKeyManager.unlockWithPassword(context, lockPassword)
                                        }
                                        lockPassword = ""; lockPasswordError = ""
                                        (context as? MainActivity)?.isAppLocked?.value = false
                                        (context as? MainActivity)?.lastActiveTimeMs = System.currentTimeMillis()
                                    } else {
                                        lockPasswordError = s.loginWrongPassword
                                    }
                                }
                            }
                        }
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFFC77B4F),
                        unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                        focusedLabelColor = Color(0xFFC77B4F),
                        unfocusedLabelColor = Color.White.copy(alpha = 0.5f),
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        cursorColor = Color(0xFFC77B4F),
                        errorBorderColor = Color(0xFFE74C3C),
                        errorLabelColor = Color(0xFFE74C3C)
                    )
                )

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = {
                        if (lockPassword.isBlank()) { lockPasswordError = s.loginEnterPassword; return@Button }
                        lockScope.launch {
                            if (UserStorage.isPanicPassword(context, lockPassword)) {
                                lockPassword = ""
                                (context as? MainActivity)?.emergencyWipe(withDecoy = true)
                            } else if (UserStorage.checkPassword(context, lockPassword)) {
                                withContext(Dispatchers.IO) {
                                    StorageKeyManager.unlockWithPassword(context, lockPassword)
                                }
                                lockPassword = ""; lockPasswordError = ""
                                (context as? MainActivity)?.isAppLocked?.value = false
                                (context as? MainActivity)?.lastActiveTimeMs = System.currentTimeMillis()
                            } else {
                                lockPasswordError = s.loginWrongPassword
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC77B4F))
                ) {
                    Text(s.loginButton, fontFamily = lockFont, fontSize = 16.sp)
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedButton(
                    onClick = {
                        val activity = context as? androidx.fragment.app.FragmentActivity ?: return@OutlinedButton
                        val executor = androidx.core.content.ContextCompat.getMainExecutor(activity)
                        val biometricPrompt = androidx.biometric.BiometricPrompt(
                            activity, executor,
                            object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                                    StorageKeyManager.unlockWithKeystore(context)
                                    (context as? MainActivity)?.isAppLocked?.value = false
                                    (context as? MainActivity)?.lastActiveTimeMs = System.currentTimeMillis()
                                }
                            }
                        )
                        val promptInfo = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                            .setTitle(s.lockBiometricTitle)
                            .setSubtitle(s.lockBiometricSubtitle)
                            .setNegativeButtonText(s.lockBiometricCancel)
                            .build()
                        biometricPrompt.authenticate(promptInfo)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color.White.copy(alpha = 0.3f))
                ) {
                    Text(s.lockUnlock, fontFamily = lockFont, fontSize = 16.sp, color = Color.White)
                }
            }
        }
    }

    }
}