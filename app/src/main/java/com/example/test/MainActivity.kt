package com.bcon.messenger

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
import com.bcon.messenger.ui.theme.TESTTheme
import com.bcon.messenger.ui.theme.BeaconTheme
import com.bcon.messenger.ui.theme.beaconColorsFor
import com.bcon.messenger.ui.theme.LocalBeaconColors
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
import com.bcon.messenger.GroupInfoScreen
import com.google.android.datatransport.BuildConfig

class MainActivity : FragmentActivity() {
    companion object {
        val selectedPhotoUri = MutableStateFlow<Uri?>(null)
        val selectedFileUri = MutableStateFlow<Uri?>(null)
        const val PICK_IMAGE_REQUEST = 200
        const val PICK_FILE_REQUEST = 201
        // Deep-link от уведомлений: id чата и его тип ("chat" / "group_chat")
        val pendingChatId = MutableStateFlow<String?>(null)
        val pendingChatType = MutableStateFlow<String?>(null)
        // Deep-link для каналов: beacon://channel?id=... (subscribe flow)
        val pendingChannelLink = MutableStateFlow<String?>(null)
        // Открытие уже подписанного канала (из уведомления)
        val pendingOpenChannelId = MutableStateFlow<String?>(null)
        // Входящий звонок: Triple(callId, isVideo, fromUserId)
        val pendingIncomingCall = MutableStateFlow<Triple<String, Boolean, String>?>(null)
        // Тикер для автообновления списка чатов при получении нового сообщения
        val chatListVersion = MutableStateFlow(0L)
        // Текущий язык интерфейса ("ru" / "en"). Обновляется без recreate().
        val currentLanguage = MutableStateFlow("ru")
        // Текущая тема. Обновляется без recreate().
        val currentTheme = MutableStateFlow(BeaconTheme.NAVY)
        // (isPanicMode удалён: volume×5 теперь делает emergencyWipe(withDecoy=true))
        // Сигнал для сброса UI к экрану калькулятора при уходе в фон
        val shouldResetToCalculator = MutableStateFlow(false)
    }

    private val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)   // обновляем текущий intent активити

        // В режиме паранойи пропускаем только наши собственные действия
        if (ParanoidMode.isEnabled) {
            val isOurs = intent?.action == "EMERGENCY_WIPE" ||
                intent?.action == "OPEN_INCOMING_CALL" ||
                intent?.action == "OPEN_ACTIVE_CALL" ||
                intent?.data?.scheme == "beacon" ||
                intent?.hasExtra("open_chat") == true
            if (!isOurs) return
        }

        if (intent?.action == "EMERGENCY_WIPE") emergencyWipe(withDecoy = true)
        // Входящий звонок — открыть экран
        if (intent?.action == "OPEN_INCOMING_CALL") {
            // pendingIncomingCall уже заполнен в MessengerService
            return
        }
        if (intent?.action == "OPEN_ACTIVE_CALL") {
            // pendingIncomingCall == null → значит уже в звонке → навигация обрабатывается ниже
            return
        }
        // Если пришло уведомление пока приложение уже открыто
        intent?.getStringExtra("open_chat")?.let { chatId ->
            pendingChatId.value = chatId
            pendingChatType.value = intent.getStringExtra("chat_type") ?: "chat"
        }
        // Deep-link канала: beacon://channel?id=...
        handleChannelDeepLink(intent)
    }

    private fun handleChannelDeepLink(intent: Intent?) {
        // From beacon:// URI (system deep link) — triggers subscribe flow
        val uri = intent?.data
        if (uri != null && uri.scheme == "beacon" && uri.host == "channel") {
            pendingChannelLink.value = uri.toString()
            return
        }
        // From notification tap — directly open channel feed (already subscribed)
        intent?.getStringExtra("open_channel")?.let { channelId ->
            pendingOpenChannelId.value = channelId
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        super.onCreate(savedInstanceState)
        CryptoManager.init(this)
        ParanoidMode.init(this)
        HoneyTokenManager.init(this)
        // Запрет скриншотов и записи экрана во всём приложении
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        // Сбрасывать касания если поверх окна есть оверлей (антиклик-джекинг)
        window.decorView.filterTouchesWhenObscured = true
        WindowCompat.setDecorFitsSystemWindows(window, false)

        if (intent?.action == "EMERGENCY_WIPE") { emergencyWipe(withDecoy = true); return }

        // Читаем deep-link из уведомления (холодный старт)
        intent?.getStringExtra("open_chat")?.let { chatId ->
            pendingChatId.value = chatId
            pendingChatType.value = intent.getStringExtra("chat_type") ?: "chat"
        }
        // Обрабатываем deep-link канала при холодном старте
        handleChannelDeepLink(intent)

        // Восстанавливаем состояние после экстренного вайпа (decoy mode)
        UserStorage.migrateDecoyState(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 0)
        }

        // Разовая проверка шпионских приложений (не при маскировке — диалог раскроет приложение)
        if (!UserStorage.getCalculatorDisguise(this)) checkSpyApps()

        // Синхронизируем реактивный язык с сохранённым значением
        currentLanguage.value = UserStorage.getLanguage(this)
        // Синхронизируем тему
        currentTheme.value = UserStorage.getTheme(this)

        // Запускаем Tor заранее
        TorManager.start(this, activityScope, if (UserStorage.getLanguage(this) == "en") enStrings else ruStrings)

        // Регистрируем приёмник выключения экрана (для форс-блокировки при разблокировке)
        registerReceiver(screenLockReceiver, android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF))

        // Слежение за появлением новых Accessibility-сервисов в реальном времени
        contentResolver.registerContentObserver(
            android.provider.Settings.Secure.getUriFor(
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ),
            false,
            accessibilityObserver
        )

        enableEdgeToEdge()
        setContent {
            // ─── Тема ───────────────────────────────────────────────────────────
            val theme by currentTheme.collectAsState()
            val beaconColors = beaconColorsFor(theme)

            TESTTheme(beaconColors = beaconColors) {
                // ─── Язык ──────────────────────────────────────────────────────
                // collectAsState() реагирует на смену языка без recreate() —
                // screen-state и вся навигация при этом остаются нетронутыми.
                val lang by currentLanguage.collectAsState()
                val strings = if (lang == "en") enStrings else ruStrings

                androidx.compose.runtime.CompositionLocalProvider(LocalStrings provides strings) {
                    val context = LocalContext.current
                    var rootCheckResult by remember { mutableStateOf<RootDetector.RootCheckResult?>(null) }
                    var signatureTampered by remember { mutableStateOf(false) }

                    LaunchedEffect(Unit) {
                        // При включённой маскировке не запускаем проверки —
                        // диалоги с предупреждениями раскрыли бы истинную природу приложения
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
                        // При включённой маскировке — сразу калькулятор, без диалогов
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
                                    Text(s.close, color = Color(0xFF00E5FF), fontFamily = appFont)
                                }
                            }
                        )
                        result?.level == RootDetector.RootLevel.WARNING -> AlertDialog(
                            onDismissRequest = { rootCheckResult = null },
                            containerColor = Color(0xFF091a66),
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
                                    Text(s.rootWarningConfirm, color = Color(0xFF00E5FF), fontFamily = appFont)
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
            emergencyWipe(withDecoy = true)  // EmergencyService = принудительный сценарий
        }
    }

    // ─── Volume × 5 → Emergency Wipe + Decoy ────────────────────────────────
    // Быстро стираем все данные и сохраняем decoy state.
    // После перезапуска: логин реальным паролем → фейковые чаты.
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

    // ─── Автоблокировка ───────────────────────────────────────────────────────
    var lastActiveTimeMs = System.currentTimeMillis()
    // Флаг — показывать экран блокировки при следующем onResume
    val isAppLocked = kotlinx.coroutines.flow.MutableStateFlow(false)

    // Флаг: экран телефона погас → при следующем resume требовать пароль
    private var screenWasLocked = false

    // ─── Детектирование Accessibility-сервисов в реальном времени ────────────
    // Пакеты, замеченные в текущей сессии — чтобы не показывать диалог дважды
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
                // Не блокируем приложение во время активного звонка
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
        // Режим паранойи: проверяем root + IDS + HoneyToken при каждом возврате
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
        // Триггер таймаута пароля — независим от Paranoid Mode
        val timeoutWipeHours = UserStorage.getTimeoutWipeHours(this)
        if (timeoutWipeHours > 0 && UserStorage.isRegistered(this)) {
            val lastEntry = UserStorage.getLastPasswordEntry(this)
            val now = System.currentTimeMillis()
            if (lastEntry > 0L && (now - lastEntry) > timeoutWipeHours * 3_600_000L) {
                DeadMansSwitchManager.triggerWarningImmediate(this)
                return
            }
        }
        val filter = android.content.IntentFilter("com.bcon.messenger.EMERGENCY_WIPE")
        registerReceiver(emergencyReceiver, filter, android.content.Context.RECEIVER_NOT_EXPORTED)

        if (UserStorage.isRegistered(this)) {
            // Не блокируем приложение во время активного звонка
            val callActive = CallManager.callId.isNotEmpty()
            // Блокировка по факту выключения экрана (независимо от таймаута)
            if (screenWasLocked && !callActive) {
                screenWasLocked = false
                StorageKeyManager.lock()
                isAppLocked.value = true
                return
            }
            screenWasLocked = false
            // Блокировка по таймауту (приложение было свёрнуто без выключения экрана)
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
        // При уходе в фон с включённой маскировкой — блокируем SMK и сигналим
        // composable-у вернуться к экрану калькулятора
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

    /** Живая проверка при изменении списка Accessibility-сервисов во время работы приложения. */
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

        // ── Accessibility сервисы ──────────────────────────────────────────────
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

        // ── Администраторы устройства ──────────────────────────────────────────
        val dpm = getSystemService(DevicePolicyManager::class.java)
        val admins = dpm.getActiveAdmins() ?: emptyList()
        val suspiciousAdmins = admins.filter { cn -> !isTrustedPackage(cn.packageName) }
        if (suspiciousAdmins.isNotEmpty()) {
            suspiciousPackages += suspiciousAdmins.map { it.packageName }
            warnings += s.spyAppsAdminsSection +
                suspiciousAdmins.joinToString("\n") { "  • ${it.packageName}" }
        }

        // ── Приложения с правом рисовать поверх экрана ────────────────────────
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

        // Показываем диалог только если появились новые угрозы (не надоедать при каждом запуске)
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

    /**
     * Экстренный вайп.
     *
     * @param withDecoy true  — принудительный сценарий (AccessibilityService / EmergencyService):
     *                          после вайпа сохраняется recovery state, чтобы пользователь мог
     *                          войти со своим паролем и показать фейковые чаты.
     *                  false — добровольный сброс ("Это не я"): чистый старт, регистрация нового
     *                          аккаунта после перезапуска.
     */
    fun emergencyWipe(withDecoy: Boolean = false) {
        WipeManager.hardWipe(this, withDecoy)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PICK_IMAGE_REQUEST && resultCode == RESULT_OK) selectedPhotoUri.value = data?.data
        if (requestCode == PICK_FILE_REQUEST && resultCode == RESULT_OK) selectedFileUri.value = data?.data
    }
}

// ─── Экран загрузки Tor ───────────────────────────────────────────────────────

@Composable
fun TorLoadingScreen(progress: Int, status: String) {
    val c = LocalBeaconColors.current
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
                "B-CON Messenger",
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

            // Прогресс бар
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

// ─── Навигация ────────────────────────────────────────────────────────────────

@Composable
fun AppNavigation() {
    val context = LocalContext.current
    val s = LocalStrings.current

    // Состояние Tor
    var torReady by remember { mutableStateOf(TorManager.isConnected) }
    var torProgress by remember { mutableStateOf(TorManager.bootstrapProgress) }
    var torStatus by remember { mutableStateOf(s.torStatusStarting) }
    var torError by remember { mutableStateOf("") }

    // Подписываемся на события Tor
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
        // Если Tor уже завершил работу до подписки — проверяем сразу
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

    // Panic mode: показывается после wipe+decoy когда isDecoyMode() = true
    var isPanicMode by remember { mutableStateOf(false) }
    var openedChat by remember { mutableStateOf("") }
    var openedChannelId by remember { mutableStateOf("") }
    var verifyKeyContact by remember { mutableStateOf("") }

    // ── Входящий звонок ───────────────────────────────────────────────────────
    var callFromUser  by remember { mutableStateOf("") }
    var callIsVideo   by remember { mutableStateOf(false) }
    var callIsGroup   by remember { mutableStateOf(false) }
    var callGroupId   by remember { mutableStateOf("") }
    val pendingCallVal by MainActivity.pendingIncomingCall.collectAsState()

    // ── Разрешение камеры для видеозвонка ─────────────────────────────────────
    var pendingVideoCallTarget by remember { mutableStateOf("") }
    val cameraPermLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (pendingVideoCallTarget.isNotEmpty()) {
            val target = pendingVideoCallTarget
            pendingVideoCallTarget = ""
            callIsVideo = granted   // видео только если разрешение дано
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

    // ── Автоблокировка ────────────────────────────────────────────────────────
    val isLocked by (context as? MainActivity)?.isAppLocked?.collectAsState()
        ?: remember { mutableStateOf(false) }.let { s -> s as androidx.compose.runtime.State<Boolean> }

    var lockPassword by remember { mutableStateOf("") }
    var lockPasswordError by remember { mutableStateOf("") }
    val lockScope = rememberCoroutineScope()

    val lockVisible = isLocked == true && screen != "login" && screen != "register" && screen != "calculator"

    // Сброс к калькулятору при уходе приложения в фон (если маскировка включена)
    val shouldResetCalc by MainActivity.shouldResetToCalculator.collectAsState()
    LaunchedEffect(shouldResetCalc) {
        if (shouldResetCalc) {
            // Не сбрасываем во время звонка — это сломает активный звонок
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

    // Deep-link: навигация по тапу на уведомление
    val pendingChatIdFromNotif by MainActivity.pendingChatId.collectAsState()
    val pendingChatTypeFromNotif by MainActivity.pendingChatType.collectAsState()

    // Если приложение уже работало (onNewIntent) — переходим сразу, без re-auth
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

    // Периодическое IDS-сканирование (каждые 30 сек в paranoid mode)
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

    // Показываем загрузку Tor только если ещё не готов и не зарегистрирован
    if (!torReady && UserStorage.isRegistered(context)) {
        TorLoadingScreen(progress = torProgress, status = torStatus)
        return
    }

    // Panic mode: показываем decoy вместо реального контента
    if (isPanicMode) {
        DecoyScreen()
        return
    }

    // Panic button from lock screen notification — decoy mode
    val panicModeNotif by ParanoidMode.panicModeNotif.collectAsState()
    if (panicModeNotif) {
        DecoyScreen()
        return
    }

    // Stealth mode: IDS/HoneyToken обнаружил угрозу — маскируемся под decoy
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
            // Plain-prefs флаг надёжнее EncryptedSharedPrefs после холодного старта после вайпа
            val uiState = context.getSharedPreferences("beacon_ui_state", Context.MODE_PRIVATE)
            if (uiState.getBoolean("calc_pending_decoy", false)) {
                uiState.edit().remove("calc_pending_decoy").apply()
                isPanicMode = true
            } else when {
                // После вайпа с decoy — показываем фейковые чаты, не регистрацию
                UserStorage.isDecoyMode(context) -> isPanicMode = true
                !UserStorage.isRegistered(context) -> screen = "register"
                else -> screen = "login"
            }
        })

        "backup" -> BackupScreen(onBack = { screen = "profile" })
        "servers" -> ServersScreen(onBack = { screen = "profile" })
        "security_diagnostics" -> SecurityDiagnosticsScreen(onBack = { screen = "profile" })
        "wipe_settings" -> WipeSettingsScreen(onBack = { screen = "profile" })

        // ── Звонки ────────────────────────────────────────────────────────────
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

        "group_info" -> GroupInfoScreen(  // <- ДОБАВИЛИ
            groupId = openedChat,
            onBack = { screen = "group_chat" }
        )

        "register" -> RegisterScreen(
            context = context,
            onRegistered = {
                if (CryptoManager.hasKeys()) {
                    context.startForegroundService(Intent(context, MessengerService::class.java))
                }
                screen = "chats"
            }
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
                // Всегда показываем DecoyScreen немедленно — никакого
                // подозрительного чёрного экрана или перезапуска.
                isPanicMode = true
                if (!UserStorage.isDecoyMode(context)) {
                    // Полный вайп в фоне пока жертва/наблюдатель видит фейк-чаты.
                    // Ждём 400 мс чтобы DecoyScreen успел отрисовать первый кадр
                    // и закэшировать remember{}-значения до удаления prefs.
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
            onOpenSupport = { openedChat = SupportConfig.FINGERPRINT; screen = "chat" }
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
                    // Запрашиваем разрешение — звонок запустится в колбэке
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

    } // end AnimatedContent

    // ── Экран блокировки — анимированный оверлей поверх навигации ────────────
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
                .background(Brush.verticalGradient(listOf(Color(0xFF141e4a), Color(0xFF0d1238)))),
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
                        focusedBorderColor = Color(0xFF2481CC),
                        unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                        focusedLabelColor = Color(0xFF2481CC),
                        unfocusedLabelColor = Color.White.copy(alpha = 0.5f),
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        cursorColor = Color(0xFF2481CC),
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
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2481CC))
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
    } // end AnimatedVisibility lock

    } // end Box
}