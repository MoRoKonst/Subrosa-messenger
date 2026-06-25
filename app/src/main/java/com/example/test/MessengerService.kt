package com.bcon.messenger

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.database.ContentObserver
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import android.media.AudioFocusRequest
import android.media.session.MediaSession
import android.media.session.PlaybackState
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

class MessengerService : Service() {

    data class FileMeta(val name: String, val total: Int, val chunks: MutableList<Pair<Int, String>>)

    companion object {
        const val CHANNEL_ID = "messenger_channel"
        /** Тихий канал только для foreground-уведомления сервиса. */
        const val CHANNEL_ID_SERVICE = "messenger_service_silent"
        const val NOTIFICATION_ID = 1
        private const val TAG = "MessengerService"
        /** Флаг реального WebSocket-подключения (handshake завершён). Читается из UI. */
        @Volatile var connected: Boolean = false
        /** Реактивный статус подключения для Compose UI. */
        val connectionState = MutableStateFlow(false)
    }

    inner class LocalBinder : Binder() {
        fun getService() = this@MessengerService
    }

    private val binder = LocalBinder()

    /** Возвращает строки для текущего языка приложения. */
    private val s: AppStrings get() = if (UserStorage.getLanguage(this) == "en") enStrings else ruStrings

    // ─── WebSocket ────────────────────────────────────────────────────────────
    private var handshakeComplete = false
    private var webSocket: WebSocket? = null

    // Клиент без Tor (прямое подключение)
    private val wsClient: OkHttpClient by lazy {
        buildOkHttpClient(useTor = false)
    }

    // Клиент через Tor (SOCKS5 → Orbot 127.0.0.1:9050)
    private val wsTorClient: OkHttpClient by lazy {
        buildOkHttpClient(useTor = true)
    }

    private fun buildOkHttpClient(useTor: Boolean): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .pingInterval(0, TimeUnit.SECONDS)
            .connectTimeout(if (useTor) 60 else 15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
        if (useTor) {
            // Кастомный SocketFactory: передаёт имя хоста в Orbot без локального DNS-резолва.
            // Стандартный .proxy() резолвит хост через системный DNS до SOCKS5 — DNS-утечка.
            // createUnresolved() отправляет строку напрямую в Orbot (SOCKS5 DOMAIN-тип),
            // что также позволяет подключаться к .onion-адресам.
            val torProxy = java.net.Proxy(
                java.net.Proxy.Type.SOCKS,
                java.net.InetSocketAddress(TorManager.SOCKS_HOST, TorManager.SOCKS_PORT)
            )
            builder.socketFactory(object : javax.net.SocketFactory() {
                private fun torSocket(host: String, port: Int): java.net.Socket =
                    java.net.Socket(torProxy).apply {
                        connect(java.net.InetSocketAddress.createUnresolved(host, port), 30_000)
                    }
                override fun createSocket(): java.net.Socket = java.net.Socket(torProxy)
                override fun createSocket(host: String, port: Int) = torSocket(host, port)
                override fun createSocket(host: java.net.InetAddress, port: Int) = torSocket(host.hostName, port)
                override fun createSocket(host: String, port: Int, localAddr: java.net.InetAddress, localPort: Int) = torSocket(host, port)
                override fun createSocket(host: java.net.InetAddress, port: Int, localAddr: java.net.InetAddress, localPort: Int) = torSocket(host.hostName, port)
            })
            Log.d(TAG, "OkHttpClient: маршрут через Tor SOCKS5 (без DNS-утечки)")
        }
        if (NetworkConfig.CERT_PIN.isNotEmpty() && NetworkConfig.SERVER_HOSTNAME.isNotEmpty()) {
            builder.certificatePinner(
                okhttp3.CertificatePinner.Builder()
                    .add(NetworkConfig.SERVER_HOSTNAME, NetworkConfig.CERT_PIN)
                    .build()
            )
            Log.d(TAG, "Certificate pinning включён для ${NetworkConfig.SERVER_HOSTNAME}")
        }
        return builder.build()
    }

    // Возвращает нужный клиент в зависимости от состояния Tor
    private fun activeWsClient(): OkHttpClient {
        if (!TorManager.isConnected) return wsClient
        // Проверяем что SOCKS доступен
        val socksAvailable = try {
            val s = java.net.Socket()
            s.connect(java.net.InetSocketAddress(TorManager.SOCKS_HOST, TorManager.SOCKS_PORT), 1000)
            s.close(); true
        } catch (e: Exception) { false }
        return if (socksAvailable) {
            // SOCKS режим — явный прокси без DNS-утечки
            wsTorClient
        } else {
            // VPN режим Orbot — трафик перехватывается системой, используем обычный клиент
            Log.d(TAG, "Orbot VPN режим — используем прямой клиент")
            wsClient
        }
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isConnected: Boolean = false
        set(value) { field = value; connected = value; connectionState.value = value }
    private var isConnecting = false
    private var handshakeDone = false
    private var reconnectAttempts = 0
    private var failuresOnCurrentServer = 0          // счётчик неудач на текущем сервере
    private val MAX_FAILURES_BEFORE_SWITCH = 3       // сколько неудач до переключения
    private var username = ""

    private val publicKeys = mutableMapOf<String, String>()
    private val tokensSentThisSession = mutableSetOf<String>()
    private val pendingMessages = mutableMapOf<String, MutableList<Pair<String, String>>>()
    // Дедупликация групповых сообщений: защита от replay-атаки через сервер
    private val processedGroupMessageIds = mutableSetOf<String>()
    private val pendingSessionMessages = mutableMapOf<String, MutableList<Pair<String, String>>>()
    private val pendingReactions = mutableListOf<Triple<String, String, String>>()
    // Очередь видеокружков для отправки при офлайн / нет ключа
    private data class PendingVideoCircle(val to: String, val videoId: String, val encFilePath: String, val duration: Int)
    private val pendingVideoCircles = mutableListOf<PendingVideoCircle>()
    // id → время получения; очистка по TTL вместо фиксированного окна в 100 сообщений
    private val receivedMessageIds = HashMap<String, Long>()
    private val REPLAY_WINDOW_MS = 60 * 60 * 1000L  // 1 час
    private val imageChunks = mutableMapOf<String, MutableMap<Int, String>>()
    private val imageTotals = mutableMapOf<String, Int>()
    private val fileChunks = mutableMapOf<String, FileMeta>()
    private val imageChunkAcks = mutableMapOf<String, kotlinx.coroutines.channels.Channel<Int>>()
    private val fileChunkAcks = mutableMapOf<String, kotlinx.coroutines.channels.Channel<Int>>()
    private val videoChunkAcks = mutableMapOf<String, kotlinx.coroutines.channels.Channel<Int>>()
    private val cancelledTransfers = mutableSetOf<String>()
    // Накопленные строки для InboxStyle уведомлений: key → список последних сообщений
    private val notifLines = mutableMapOf<String, MutableList<String>>()

    var onMessageReceived: ((String, String) -> Unit)? = null
    var onStatusChanged: ((Boolean) -> Unit)? = null
    var onReactionReceived: ((String, String, String) -> Unit)? = null
    var onTypingReceived: ((String) -> Unit)? = null
    var onReadReceived: ((String) -> Unit)? = null
    var onDeliveredReceived: ((String) -> Unit)? = null   // msgId → sender delivered it
    var onEditReceived: ((String, String) -> Unit)? = null
    var onImageReceived: ((String, android.graphics.Bitmap) -> Unit)? = null
    var onKeyChanged: ((String) -> Unit)? = null
    var onVoiceReceived: ((String, File, Int) -> Unit)? = null
    var onFileReceived: ((String, File, String) -> Unit)? = null
    var onGroupMessageReceived: ((String, GroupMessage) -> Unit)? = null
    var onGroupReactionReceived: ((String, String, String, String) -> Unit)? = null  // groupId, from, messageId, emoji
    var onGroupInviteReceived: ((Group, String) -> Unit)? = null
    var onChannelPostReceived: ((String, ChannelPost) -> Unit)? = null  // channelId, post
    var onChannelCreated: ((Channel) -> Unit)? = null
    var onChannelPostDeleted: ((String, String) -> Unit)? = null        // channelId, postId
    var onChannelInfoUpdated: ((String) -> Unit)? = null                // channelId
    var onChannelDeleted: ((String) -> Unit)? = null                    // channelId
    var onMessageDeleted: ((fromId: String, messageId: String) -> Unit)? = null  // удалено у всех
    var onDisappearTimerChanged: ((fromId: String, seconds: Long) -> Unit)? = null
    var onGroupMessageDeleted: ((groupId: String, messageId: String) -> Unit)? = null
    var onVideoReceived: ((videoId: String, file: File, duration: Int) -> Unit)? = null

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null

    // ─── Silent audio + MediaSession — захватывает Volume кнопки на lock screen ──
    // AudioTrack один недостаточен: Android не знает что приложение "играет".
    // MediaSession с STATE_PLAYING регистрирует нас как активный медиаплеер —
    // только тогда Volume кнопки на lock screen адресуются к STREAM_MUSIC
    // и ContentObserver стабильно получает onChange().
    private var silentTrack: AudioTrack? = null
    private var silentJob: Job? = null
    private var silentSession: MediaSession? = null
    private var volMonitorJob: Job? = null
    private var audioFocusRequest: AudioFocusRequest? = null

    private fun startSilentAudio() {
        if (silentTrack != null || !UserStorage.isEmergencyWipeEnabled(this)) return
        try {
            // 1. AudioTrack: беззвучный поток PCM на STREAM_MUSIC
            val rate = 8000
            val bufSize = AudioTrack.getMinBufferSize(
                rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT
            ).coerceAtLeast(1024)
            silentTrack = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                        .build()
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setSampleRate(rate)
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                        .build()
                )
                .setBufferSizeInBytes(bufSize)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()
                .also { it.play() }

            val silence = ShortArray(bufSize / 2)  // PCM16 → Short, all zeros
            silentJob = scope.launch(Dispatchers.IO) {
                while (isActive) {
                    if (silentTrack?.playState == AudioTrack.PLAYSTATE_PLAYING) {
                        silentTrack?.write(silence, 0, silence.size)
                    } else break
                }
            }

            // 2. AudioFocus: явно занимаем STREAM_MUSIC, чтобы Volume-кнопки
            //    всегда адресовались к медиапотоку, а не рингтону
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val focusAttr = AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build()
                audioFocusRequest = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                    .setAudioAttributes(focusAttr)
                    .setOnAudioFocusChangeListener {}
                    .build()
                getSystemService(AudioManager::class.java).requestAudioFocus(audioFocusRequest!!)
            }

            // 3. MediaSession STATE_PLAYING: сообщает ОС что мы активный медиаплеер
            //    → Volume-кнопки на lock screen → STREAM_MUSIC
            silentSession = MediaSession(this, "beacon_vol_guard").apply {
                setPlaybackToLocal(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                        .build()
                )
                setPlaybackState(
                    PlaybackState.Builder()
                        .setState(PlaybackState.STATE_PLAYING,
                            PlaybackState.PLAYBACK_POSITION_UNKNOWN, 0f)
                        .build()
                )
                isActive = true
            }

            // 4. Поллинг getStreamVolume: работает и при заблокированном экране.
            //    На Android 12+ Settings.System не обновляется при изменении громкости
            //    через lock screen, поэтому ContentObserver ненадёжен — читаем
            //    AudioService напрямую.
            //    Когда громкость достигает минимума — тихо восстанавливаем до safeVol,
            //    чтобы следующие нажатия тоже детектировались (ADJUST_SAME не меняет значение).
            val am = getSystemService(AudioManager::class.java)
            val minVol  = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                am.getStreamMinVolume(AudioManager.STREAM_MUSIC) else 0
            val safeVol = (am.getStreamMaxVolume(AudioManager.STREAM_MUSIC) / 3)
                .coerceAtLeast(minVol + 3)
            // Если уже на минимуме — поднимаем до safeVol, иначе первые нажатия
            // дадут ADJUST_SAME и не будут детектированы
            if (am.getStreamVolume(AudioManager.STREAM_MUSIC) <= minVol) {
                am.setStreamVolume(AudioManager.STREAM_MUSIC, safeVol, 0)
            }
            var lastVol = am.getStreamVolume(AudioManager.STREAM_MUSIC)
            volMonitorJob = scope.launch {
                while (isActive) {
                    delay(100)
                    val current = am.getStreamVolume(AudioManager.STREAM_MUSIC)
                    when {
                        current < lastVol -> {
                            lastVol = current
                            volumeObserver.dispatchChange(false)
                            // Достигли минимума — восстанавливаем без показа UI (flags=0)
                            if (current <= minVol) {
                                am.setStreamVolume(AudioManager.STREAM_MUSIC, safeVol, 0)
                                lastVol = safeVol
                            }
                        }
                        current > lastVol -> lastVol = current
                    }
                }
            }
        } catch (_: Exception) {}
    }

    private fun stopSilentAudio() {
        volMonitorJob?.cancel(); volMonitorJob = null
        silentJob?.cancel(); silentJob = null
        try { silentTrack?.stop(); silentTrack?.release() } catch (_: Exception) {}
        silentTrack = null
        try { silentSession?.isActive = false; silentSession?.release() } catch (_: Exception) {}
        silentSession = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            audioFocusRequest?.let { getSystemService(AudioManager::class.java).abandonAudioFocusRequest(it) }
        }
        audioFocusRequest = null
    }

    // ─── Volume × 5 в фоне → Emergency Wipe ─────────────────────────────────────
    private var volPressCount = 0
    private var firstVolPressMs = 0L
    private val volumeObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) {
            val now = System.currentTimeMillis()
            if (now - firstVolPressMs > 3000L) {
                volPressCount = 1
                firstVolPressMs = now
            } else {
                volPressCount++
                if (volPressCount >= 5) {
                    volPressCount = 0
                    performEmergencyWipe()
                }
            }
        }
    }

    // ─── Детектирование новых Accessibility-сервисов в фоне ─────────────────────
    private val knownA11yServices = mutableSetOf<String>()
    private val a11yObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) {
            val am = getSystemService(android.view.accessibility.AccessibilityManager::class.java) ?: return
            val trusted = setOf("android", packageName)
            val trustedPfx = listOf(
                "com.android.", "com.google.android", "com.samsung.android", "com.miui", "com.huawei.android", "ru.miui"
            )
            fun trusted(pkg: String) = pkg in trusted || trustedPfx.any { pkg.startsWith(it) }

            val current = am.getEnabledAccessibilityServiceList(
                android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            ).map { it.resolveInfo.serviceInfo.packageName }.filter { !trusted(it) }.toSet()

            val newOnes = current - knownA11yServices
            knownA11yServices.clear()
            knownA11yServices.addAll(current)
            if (newOnes.isEmpty()) return

            val intent = Intent(this@MessengerService, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val pending = PendingIntent.getActivity(this@MessengerService, 0, intent, PendingIntent.FLAG_IMMUTABLE)
            val text = "⚠️ Служба ${newOnes.first()} может читать экран или имитировать нажатия"
            val notification = androidx.core.app.NotificationCompat.Builder(this@MessengerService, CHANNEL_ID)
                .setContentTitle("⚠️ Подозрительная активность")
                .setContentText(text)
                .setStyle(androidx.core.app.NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentIntent(pending)
                .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build()
            getSystemService(NotificationManager::class.java).notify(997, notification)
        }
    }

    private fun performEmergencyWipe() {
        var savedPasswordHash: String? = null
        var savedUsername: String? = null
        var savedUserId: String? = null
        var savedCalcDisguise = false
        try {
            val enc = EncryptedStorage.getEncryptedPrefs(this, "user_prefs")
            savedPasswordHash  = enc.getString("password_hash", null)
            savedUsername      = enc.getString("username",      null)
            savedUserId        = enc.getString("user_id",       null)
            savedCalcDisguise  = enc.getBoolean("calculator_disguise", false)
        } catch (_: Exception) {}

        try {
            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()
            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                listOf("_androidx_security_master_key", "_androidx_security_crypto_master_key_")
                    .filter { ks.containsAlias(it) }
                    .forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}

            val dataDir = applicationInfo.dataDir
            File(dataDir, "shared_prefs").deleteRecursively()
            filesDir.deleteRecursively()
            cacheDir.deleteRecursively()
            externalCacheDir?.deleteRecursively()
            File(dataDir, "databases").deleteRecursively()
            File(dataDir, "app_webview").deleteRecursively()
            File(dataDir, "no_backup").deleteRecursively()
            getExternalFilesDir(null)?.parentFile?.deleteRecursively()

            stopSelf()

            if (savedUsername != null && savedPasswordHash != null || savedCalcDisguise) {
                try {
                    val ed = getSharedPreferences("beacon_recovery", Context.MODE_PRIVATE).edit()
                    if (savedUsername != null && savedPasswordHash != null) {
                        ed.putString("username",      savedUsername)
                          .putString("user_id",       savedUserId ?: "")
                          .putString("password_hash", savedPasswordHash)
                    }
                    if (savedCalcDisguise) ed.putBoolean("calculator_disguise", true)
                    ed.commit()
                } catch (_: Exception) {}
            }
        } catch (e: Exception) {
            Log.e(TAG, "Emergency wipe error: ${e.message}", e)
        } finally {
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }

    override fun onCreate() {
        super.onCreate()
        CryptoManager.init(this)
        SessionKeyManager.initialize(this)
        Log.d(TAG, "SessionKeyManager инициализирован")
        createNotificationChannel()
        TorManager.onTorReady = {
            if (!isConnected && !isConnecting) {
                scope.launch { connect() }
            }
        }
        // Orbot не запустился — подключаемся напрямую без Tor
        TorManager.onTorError = { _ ->
            if (!isConnected && !isConnecting) {
                scope.launch { connect() }
            }
        }
        if (TorManager.isConnected) {
            // Tor уже готов (запущен MainActivity ранее) — подключаемся сразу
            scope.launch { connect() }
        } else {
            TorManager.start(this, scope)
        }
        registerNetworkCallback()
        startSilentAudio()
        contentResolver.registerContentObserver(
            android.provider.Settings.Secure.getUriFor(
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ),
            false,
            a11yObserver
        )
    }

    override fun onDestroy() {
        PanicNotificationManager.dismiss(this)
        stopSilentAudio()
        contentResolver.unregisterContentObserver(a11yObserver)
        unregisterNetworkCallback()
        SessionKeyManager.deleteAllSessions()
        System.gc()
        webSocket?.close(1000, "service destroyed")
        scope.cancel()
        super.onDestroy()
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val request = android.net.NetworkRequest.Builder()
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        networkCallback = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                // Сеть появилась — переподключаемся если не подключены
                Log.d(TAG, "Сеть доступна — проверяем соединение")
                if (!isConnected && !isConnecting) {
                    scope.launch { connect() }
                }
            }
            override fun onLost(network: android.net.Network) {
                // Сеть пропала — сначала завершаем активный звонок, потом закрываем сокет
                Log.d(TAG, "Сеть потеряна — закрываем соединение")
                if (CallManager.callId.isNotEmpty() && username.isNotEmpty()) {
                    val peers = CallManager.peerConnections.keys.toList()
                    val cid   = CallManager.callId
                    peers.forEach { peerId ->
                        try {
                            sendAnonOrDirect(peerId, JSONObject().apply {
                                put("type", if (CallManager.isGroupCall) "call_group_leave" else "call_end")
                                put("from", username)
                                put("to",   peerId)
                                put("call_id", cid)
                                put("reason", "network_lost")
                            })
                        } catch (_: Exception) {}
                    }
                    android.os.Handler(android.os.Looper.getMainLooper()).post {
                        CallManager.release()
                    }
                }
                isConnected = false
                webSocket?.close(1000, "network lost")
            }
        }
        cm.registerNetworkCallback(request, networkCallback!!)
    }

    private fun unregisterNetworkCallback() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            networkCallback?.let { cm.unregisterNetworkCallback(it) }
            networkCallback = null
        } catch (e: Exception) {
            Log.e(TAG, "unregisterNetworkCallback error: ${e.message}")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "=== СЕРВИС ЗАПУЩЕН ===")
        // Вычисляем username из текущего ключа AndroidKeyStore (как делает сервер).
        // Если ключи пересоздавались — сохранённый userId мог устареть.
        username = try {
            val pubKeyStr = CryptoManager.getPublicKeyString()
            val keyBytes = android.util.Base64.decode(pubKeyStr, android.util.Base64.NO_WRAP)
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(keyBytes)
            val realId = digest.take(8).joinToString("") { "%02X".format(it) }
            if (realId != UserStorage.getUserId(this)) {
                Log.w(TAG, "userId в хранилище устарел → обновляем")
                UserStorage.setUserId(this, realId)
            }
            realId
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка вычисления username: ${e.message}")
            UserStorage.getUserId(this)
        }

        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        val requestKey = intent?.getStringExtra("request_key")
        if (requestKey != null && isConnected) {
            scope.launch(Dispatchers.IO) {
                sendWs(JSONObject().apply {
                    put("type", "get_key")
                    put("target", requestKey)
                }.toString())
            }
            return START_STICKY
        }

        if (intent?.getBooleanExtra("reload_cover_traffic", false) == true) {
            stopCoverTraffic()
            outboundQueue.clear()
            if (isConnected) startCoverTraffic()
            return START_STICKY
        }

        intent?.getStringExtra("send_session_reset_to")?.let { contactId ->
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendAnonOrDirect(contactId, JSONObject().apply {
                        put("type", "session_reset")
                        put("to", contactId)
                    })
                }
            }
            return START_STICKY
        }

        // Channel operations via intent
        intent?.getStringExtra("channel_post_id")?.let { channelId ->
            val text = intent.getStringExtra("channel_post_text") ?: return@let
            val msgId = intent.getStringExtra("channel_post_msg_id") ?: UUID.randomUUID().toString()
            val imageData = intent.getStringExtra("channel_post_image") ?: ""
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_post")
                        put("channel_id", channelId)
                        put("from", username)
                        put("text", text)
                        put("id", msgId)
                        put("timestamp", System.currentTimeMillis())
                        if (imageData.isNotEmpty()) put("image_data", imageData)
                    }.toString())
                }
            }
            return START_STICKY
        }

        intent?.getStringExtra("channel_subscribe")?.let { channelId ->
            val channelName = intent.getStringExtra("channel_subscribe_name") ?: ""
            val channelAvatar = intent.getStringExtra("channel_subscribe_avatar") ?: "📢"
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_subscribe")
                        put("channel_id", channelId)
                        put("from", username)
                    }.toString())
                }
            } else {
                android.widget.Toast.makeText(this, s.channelNoConnection, android.widget.Toast.LENGTH_SHORT).show()
            }
            return START_STICKY
        }

        intent?.getStringExtra("channel_unsubscribe")?.let { channelId ->
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_unsubscribe")
                        put("channel_id", channelId)
                        put("from", username)
                    }.toString())
                }
            }
            return START_STICKY
        }

        // ── FCM token registration ────────────────────────────────────────────
        intent?.getStringExtra("fcm_token")?.let { token ->
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "register_fcm")
                        put("from", username)
                        put("fcm_token", token)
                    }.toString())
                }
            } else {
                // Сохраняем для отправки после подключения
                getSharedPreferences("fcm_prefs", android.content.Context.MODE_PRIVATE)
                    .edit().putString("pending_fcm_token", token).apply()
            }
            return START_STICKY
        }

        // ── Call signaling via intent ─────────────────────────────────────────
        intent?.getStringExtra("call_signal")?.let { signalJson ->
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    try {
                        val obj = JSONObject(signalJson)
                        val to = obj.optString("to")
                        if (to.isNotBlank()) sendAnonOrDirect(to, obj)
                        else sendWs(signalJson)
                    } catch (_: Exception) { sendWs(signalJson) }
                }
            }
            return START_STICKY
        }

        intent?.getStringExtra("channel_create_name")?.let { name ->
            val desc = intent.getStringExtra("channel_create_desc") ?: ""
            val avatar = intent.getStringExtra("channel_create_avatar") ?: "📢"
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_create")
                        put("channel_name", name)
                        put("channel_description", desc)
                        put("channel_avatar", avatar)
                        put("from", username)
                    }.toString())
                }
            } else {
                android.widget.Toast.makeText(this, s.channelNoConnection, android.widget.Toast.LENGTH_SHORT).show()
            }
            return START_STICKY
        }

        // ── Get channel info (subscriber count, pinned post) ──────────────────
        intent?.getStringExtra("channel_get_info_id")?.let { channelId ->
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_get_info")
                        put("channel_id", channelId)
                        put("from", username)
                    }.toString())
                }
            }
            return START_STICKY
        }

        // ── Delete post ───────────────────────────────────────────────────────
        intent?.getStringExtra("channel_delete_post_channel_id")?.let { channelId ->
            val postId = intent.getStringExtra("channel_delete_post_id") ?: return@let
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_delete_post")
                        put("channel_id", channelId)
                        put("post_id", postId)
                        put("from", username)
                    }.toString())
                }
            }
            return START_STICKY
        }

        // ── Update channel info (name / description / avatar) ─────────────────
        intent?.getStringExtra("channel_update_info_id")?.let { channelId ->
            val name   = intent.getStringExtra("channel_update_info_name") ?: return@let
            val desc   = intent.getStringExtra("channel_update_info_desc") ?: ""
            val avatar = intent.getStringExtra("channel_update_info_avatar") ?: "📢"
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_update_info")
                        put("channel_id", channelId)
                        put("channel_name", name)
                        put("channel_description", desc)
                        put("channel_avatar", avatar)
                        put("from", username)
                    }.toString())
                }
            }
            return START_STICKY
        }

        // ── Delete channel ────────────────────────────────────────────────────
        intent?.getStringExtra("channel_delete_id")?.let { channelId ->
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_delete")
                        put("channel_id", channelId)
                        put("from", username)
                    }.toString())
                }
            }
            return START_STICKY
        }

        // ── Pin / unpin post ──────────────────────────────────────────────────
        intent?.getStringExtra("channel_pin_post_channel_id")?.let { channelId ->
            val postId = intent.getStringExtra("channel_pin_post_id") ?: return@let
            val unpin  = intent.getBooleanExtra("channel_pin_post_unpin", false)
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "channel_pin_post")
                        put("channel_id", channelId)
                        put("post_id", postId)
                        put("unpin", unpin)
                        put("from", username)
                    }.toString())
                }
            }
            return START_STICKY
        }

        // ── Forward post text to contact ──────────────────────────────────────
        intent?.getStringExtra("forward_to")?.let { contactId ->
            val text = intent.getStringExtra("forward_text") ?: return@let
            scope.launch(Dispatchers.IO) { send(contactId, text) }
            return START_STICKY
        }

        // ── Обновление аватара профиля ───────────────────────────────────────
        intent?.getStringExtra("avatar_update")?.let { b64 ->
            UserStorage.saveMyAvatar(this, b64)
            // Обновляем собственный аватар в AvatarStore
            try {
                val bytes = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
                val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                if (bmp != null) AvatarStore.avatars[username] = bmp
            } catch (_: Exception) {}
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply {
                        put("type", "profile_update")
                        put("from", username)
                        put("avatar", b64)
                    }.toString())
                }
            }
            return START_STICKY
        }

        if (username.isNotEmpty()) {
            if (!CryptoManager.hasKeys()) CryptoManager.generateKeyPair()
            if (!isConnected && !isConnecting) {
                scope.launch { connect() }
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent): IBinder = binder

    // ─── WebSocket отправка ───────────────────────────────────────────────────

    // ─── Constant-rate cover traffic ─────────────────────────────────────────
    // AGGRESSIVE: реальные сообщения в очередь, отправляются по таймеру — наблюдатель видит равномерный поток.
    // MODERATE: реальные сообщения немедленно, шум заполняет паузы — без задержки, но паттерн виден.

    private val outboundQueue = java.util.concurrent.LinkedBlockingQueue<String>()
    private var coverTrafficJob: kotlinx.coroutines.Job? = null

    private fun startCoverTraffic() {
        coverTrafficJob?.cancel()
        val mode = UserStorage.getCoverTrafficMode(this)
        if (mode == UserStorage.CoverTrafficMode.OFF) return
        val intervalMs = if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE) 1_000L else 5_000L
        coverTrafficJob = scope.launch(Dispatchers.IO) {
            val rng = java.security.SecureRandom()
            while (isActive) {
                kotlinx.coroutines.delay(intervalMs)
                if (!isConnected) continue
                val packet = outboundQueue.poll()
                if (packet != null) {
                    webSocket?.send(packet)
                } else {
                    // Шумовой пакет — неотличим от реального по размеру
                    val fakeToken = AnonTokenManager.generateDummyToken()
                    val noise = addPadding(JSONObject().apply {
                        put("type", "anon_message")
                        put("token", fakeToken)
                        put("payload", JSONObject().apply {
                            put("v", 2)
                            put("d", android.util.Base64.encodeToString(
                                ByteArray(rng.nextInt(180) + 76).also { rng.nextBytes(it) },
                                android.util.Base64.NO_WRAP
                            ))
                        })
                    }).toString()
                    webSocket?.send(noise)
                }
            }
        }
    }

    private fun stopCoverTraffic() {
        coverTrafficJob?.cancel()
        coverTrafficJob = null
    }

    private fun sendWs(json: String) {
        val mode = UserStorage.getCoverTrafficMode(this)
        if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE && isConnected) {
            outboundQueue.offer(json)
        } else {
            webSocket?.send(json)
        }
    }

    // ─── Connect ──────────────────────────────────────────────────────────────

    private suspend fun connect() {
        if (isConnected) return
        if (isConnecting) return
        isConnecting = true

        while (scope.isActive) {
            try {
                Log.d(TAG, "connect: начало")
                webSocket?.close(1000, "reconnect")
                webSocket = null

                val server = ServerManager.getCurrentServer(this@MessengerService)
                if (server == null) {
                    Log.e(TAG, "Нет доступных серверов")
                    delay(5000)
                    continue
                }

                val wsUrl = server.toWssUrl()

                // Onion-адрес требует Tor — если SOCKS недоступен, ждём
                if (wsUrl.contains(".onion") && !TorManager.isConnected) {
                    Log.w(TAG, "Onion-сервер выбран, но Tor недоступен — ждём Orbot")
                    delay(5000)
                    continue
                }

                Log.d(TAG, "Подключаемся к $wsUrl")


                val request = Request.Builder()
                    .url(wsUrl)
                    .addHeader("Connection", "Upgrade")
                    .addHeader("Upgrade", "websocket")
                    .addHeader("Sec-WebSocket-Version", "13")
                    .addHeader("Sec-WebSocket-Key", generateWebSocketKey())
                    .build()
                val listener = object : WebSocketListener() {

                    override fun onOpen(ws: WebSocket, response: Response) {
                        Log.d(TAG, "WebSocket открыт")
                    }

                    override fun onMessage(ws: WebSocket, text: String) {
                        scope.launch(Dispatchers.IO) {
                            try {
                                val json = JSONObject(text)
                                handleMessage(json)
                            } catch (e: Exception) {
                                Log.e(TAG, "onMessage error: ${e.message}")
                            }
                        }
                    }

                    override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                        Log.e(TAG, "WebSocket ошибка: ${t.message}")
                        isConnected = false
                        stopCoverTraffic()
                        if (!handshakeDone) handshakeDone = true
                        NetworkConfig.TurnCredentials.clear()
                    }

                    override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                        Log.d(TAG, "WebSocket закрыт: $code $reason")
                        isConnected = false
                        stopCoverTraffic()
                        if (!handshakeDone) handshakeDone = true
                        NetworkConfig.TurnCredentials.clear()
                    }
                }

                handshakeDone = false  // Сброс

                // Onion через Orbot VPN — не используем явный SOCKS прокси
                val client = if (wsUrl.contains(".onion")) wsClient else activeWsClient()
                webSocket = client.newWebSocket(request, listener)

                val success = withTimeoutOrNull(15_000) {
                    while (!handshakeDone && scope.isActive) {
                        delay(100)
                    }
                    handshakeDone
                } ?: false

                // BUG FIX: handshakeDone=true устанавливается и при onFailure,
                // поэтому дополнительно проверяем isConnected.
                // Если onFailure сработал → isConnected=false → бросаем исключение.
                if (!success || !isConnected) {
                    Log.e(TAG, "Handshake failed (success=$success, connected=$isConnected)")
                    webSocket?.close(1000, "handshake failed")
                    throw Exception("Handshake failed")
                }

                // Регистрация
                val displayName = UserStorage.getUsername(this@MessengerService)
                val myAvatarB64 = UserStorage.getMyAvatar(this@MessengerService) ?: ""
                sendWs(JSONObject().apply {
                    put("type", "register")
                    put("from", username)
                    put("name", displayName)
                    put("public_key", CryptoManager.getPublicKeyString())
                    put("protocol_version", ProtocolVersion.CURRENT_VERSION)
                    put("device_id", UserStorage.getDeviceId(this@MessengerService))
                    if (myAvatarB64.isNotEmpty()) put("avatar", myAvatarB64)
                }.toString())

                val contacts = ChatStorage.getContacts(this@MessengerService)
                contacts.forEach { contactId ->
                    val savedKey = ChatStorage.getContactPublicKey(this@MessengerService, contactId)
                    if (savedKey != null) publicKeys[contactId] = savedKey
                    // Загружаем сохранённые аватары контактов в AvatarStore
                    val b64 = ChatStorage.getContactAvatar(this@MessengerService, contactId)
                    if (!b64.isNullOrBlank()) {
                        try {
                            val bytes = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
                            val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                            if (bmp != null) withContext(Dispatchers.Main) { AvatarStore.avatars[contactId] = bmp }
                        } catch (e: Exception) {
                            Log.w(TAG, "Ошибка загрузки аватара $contactId: ${e.message}")
                        }
                    }
                }
                SessionKeyManager.deleteAllSessions()
                SessionKeyManager.initialize(this@MessengerService)
                publishPrekeyBundle()

                // Подписываемся на наши анонимные токены доставки
                val myTokens = AnonTokenManager.ensureMyTokenPool(this@MessengerService)
                if (myTokens.isNotEmpty()) {
                    sendWs(JSONObject().apply {
                        put("type", "subscribe_tokens")
                        put("tokens", org.json.JSONArray(myTokens))
                    }.toString())
                }

                startCoverTraffic()
                withContext(Dispatchers.Main) {
                    onStatusChanged?.invoke(true)
                    reconnectAttempts = 0
                    failuresOnCurrentServer = 0
                }

                // Отправляем FCM-токен если есть (для wake-up уведомлений)
                val pendingToken = getSharedPreferences("fcm_prefs", android.content.Context.MODE_PRIVATE)
                    .getString("pending_fcm_token", null)
                    ?: getSharedPreferences("fcm_prefs", android.content.Context.MODE_PRIVATE)
                        .getString("fcm_token", null)
                if (!pendingToken.isNullOrEmpty()) {
                    sendWs(JSONObject().apply {
                        put("type", "register_fcm")
                        put("from", username)
                        put("fcm_token", pendingToken)
                    }.toString())
                    getSharedPreferences("fcm_prefs", android.content.Context.MODE_PRIVATE)
                        .edit().remove("pending_fcm_token").apply()
                }

                flushQueue()

                // Ждём пока соединение живо
                while (isConnected && scope.isActive) {
                    delay(1000)
                }

                Log.d(TAG, "connect: соединение потеряно, переподключаемся...")
                delay(3000)

            } catch (e: Exception) {
                Log.e(TAG, "connect ошибка: ${e.message}")
                isConnected = false
                failuresOnCurrentServer++

                if (failuresOnCurrentServer >= MAX_FAILURES_BEFORE_SWITCH) {
                    // Текущий сервер недоступен — переключаемся на следующий
                    val next = ServerManager.switchToNext(this@MessengerService)
                    failuresOnCurrentServer = 0
                    reconnectAttempts = 0
                    val nextName = next?.name ?: "резервный сервер"
                    Log.w(TAG, "Сервер недоступен — переключаемся на: $nextName")
                    delay(1500)
                } else {
                    val delayMs = minOf(2000L * (1 shl reconnectAttempts), 30000L)
                    reconnectAttempts++
                    Log.d(TAG, "Переподключение через ${delayMs}мс (попытка $reconnectAttempts, неудач на сервере: $failuresOnCurrentServer)")
                    delay(delayMs)
                }
            }
        }
        isConnecting = false
    }

    // ─── Обработка входящих сообщений ─────────────────────────────────────────

    private suspend fun handleMessage(json: JSONObject) {
        val type = json.optString("type")

        when (type) {

            "challenge" -> {
                try {
                    val challengeData = json.getString("data")
                    val challengeBytes = android.util.Base64.decode(challengeData, android.util.Base64.DEFAULT)
                    val signature = CryptoManager.signBytes(challengeBytes)
                    sendWs(JSONObject().apply {
                        put("type", "challenge_response")
                        put("public_key", CryptoManager.getPublicKeyString())
                        put("signature", signature)
                    }.toString())
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка handshake: ${e.message}")
                    isConnected = false
                    handshakeDone = true
                }
            }

            "handshake_ok" -> {
                isConnected = true
                handshakeDone = true
                Log.d(TAG, "Handshake завершён успешно")
                PanicNotificationManager.show(this@MessengerService)

                try {
                    if (!SessionKeyManager.hasSession("__init_check__")) {
                        // Повторная инициализация если нужно
                        SessionKeyManager.initialize(this@MessengerService)
                        Log.d(TAG, "SessionKeyManager переинициализирован")
                    }

                    val bundle = SessionKeyManager.generatePrekeyBundle()
                    val registerBundle = JSONObject().apply {
                        put("type", "register_bundle")
                        put("bundle", bundle)
                    }
                    webSocket?.send(registerBundle.toString())
                    Log.d(TAG, "Prekey bundle отправлен на регистрацию")
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка регистрации bundle: ${e.message}")
                }

                startCoverTraffic()
                withContext(Dispatchers.Main) {
                    onStatusChanged?.invoke(true)
                }

                // Флашим видеокружки, накопившиеся пока были офлайн
                flushPendingVideoCircles()
                // Опрашиваем mailbox только если есть активные инвайт-теги
                pollMailbox()
                scope.launch(Dispatchers.IO) {
                    while (isConnected && scope.isActive) {
                        delay(30_000)
                        if (isConnected && AnonTokenManager.getMyMailboxTags(this@MessengerService).isNotEmpty())
                            pollMailbox()
                    }
                }
            }

            "mailbox_result" -> handleMailboxResult(json)

            "session_conflict" -> {
                Log.w(TAG, "⚠️ session_conflict: аккаунт подключён с другого устройства")
                isConnected = false
                handshakeDone = false
                webSocket?.cancel()
                withContext(Dispatchers.Main) {
                    onStatusChanged?.invoke(false)
                    showSessionConflictNotification()
                }
            }

            "error" -> {
                val reason = json.getString("reason")
                Log.e(TAG, "Ошибка от сервера: $reason")
                isConnected = false
                webSocket?.close(1000, "error")
                withContext(Dispatchers.Main) {
                    android.widget.Toast.makeText(this@MessengerService, s.error(reason), android.widget.Toast.LENGTH_LONG).show()
                    stopSelf()
                }
            }

            "ping" -> sendWs(JSONObject().apply { put("type", "pong") }.toString())

            // Сервер доставляет TURN-учётные данные после регистрации.
            // Хранятся только в памяти — не записываются на диск.
            "turn_config" -> {
                val turnUser = json.optString("user", "")
                val turnPass = json.optString("pass", "")
                if (turnUser.isNotEmpty() && turnPass.isNotEmpty()) {
                    NetworkConfig.TurnCredentials.username = turnUser
                    NetworkConfig.TurnCredentials.password = turnPass
                    Log.d(TAG, "TURN-credentials получены от сервера")
                } else {
                    Log.w(TAG, "turn_config: пустые учётные данные — TURN недоступен")
                }
            }

            // Список меш-пиров от сервера (резервные адреса для фейловера)
            "server_peers" -> {
                val peersArray = json.optJSONArray("peers")
                if (peersArray != null && peersArray.length() > 0) {
                    for (i in 0 until peersArray.length()) {
                        val peerUrl = peersArray.optString(i)
                        if (peerUrl.isNotBlank()) {
                            ServerManager.addDiscoveredPeer(this@MessengerService, peerUrl)
                        }
                    }
                    Log.d(TAG, "server_peers: сохранено ${peersArray.length()} меш-пиров")
                }
            }

            // Сервер доставляет аватар пользователя (при регистрации других или profile_update)
            "avatar_data" -> {
                val fromUser = json.optString("from", null) ?: return
                val b64 = json.optString("avatar", null) ?: return
                if (b64.isBlank()) return
                try {
                    val bytes = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
                    val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    if (bmp != null) {
                        ChatStorage.saveContactAvatar(this@MessengerService, fromUser, b64)
                        withContext(Dispatchers.Main) { AvatarStore.avatars[fromUser] = bmp }
                        Log.d(TAG, "Аватар получен от $fromUser")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Ошибка декодирования аватара от $fromUser: ${e.message}")
                }
            }

            "public_key" -> {
                val targetUsername = json.getString("username")
                val key = if (json.isNull("key")) null else json.getString("key")
                if (key != null) {
                    // Конвертация URL-safe Base64
                    val fixedKey = key.replace('-', '+').replace('_', '/')

                    if (KeyHistoryManager.checkKeyChange(this@MessengerService, targetUsername, fixedKey)) {
                        withContext(Dispatchers.Main) { onKeyChanged?.invoke(targetUsername) }
                    }
                    publicKeys[targetUsername] = fixedKey
                    ChatStorage.saveContactPublicKey(this@MessengerService, targetUsername, fixedKey)
                    // Если были сообщения, ожидавшие этот ключ — сразу отправляем их.
                    // pendingMessages заполняется в flushQueue() когда ключ не закэширован.
                    if (pendingMessages.remove(targetUsername) != null) {
                        MessageQueue.load(this@MessengerService)
                            .filter { it.to == targetUsername }
                            .forEach { sendEncrypted(it.to, it.text, fixedKey, it.id) }
                    }
                } else {
                    Log.w(TAG, "Получен null ключ от $targetUsername")
                }
            }

            "typing" -> {
                val from = json.getString("from")
                withContext(Dispatchers.Main) { onTypingReceived?.invoke(from) }
            }

            "session_reset" -> {
                val from = json.getString("from")
                Log.w(TAG, "session_reset от $from — сбрасываем сессию, ждём их session_init")
                SessionKeyManager.deleteSession(from)
                // НЕ запрашиваем bundle сами — иначе оба инициируют X3DH одновременно и сессии
                // расходятся. Отправитель session_reset сам переинициирует и пришлёт session_init.
            }

            "read" -> {
                val messageId = json.getString("id")
                val from = json.optString("from", null)
                // Персистируем: помечаем все собственные до этого сообщения как прочитанные
                if (from != null) {
                    val myId = UserStorage.getUserId(this@MessengerService)
                    ChatStorage.markRead(this@MessengerService, myId, from, messageId)
                }
                withContext(Dispatchers.Main) { onReadReceived?.invoke(messageId) }
            }

            "delivered" -> {
                val messageId = json.optString("id", null) ?: return
                val from      = json.optString("from", null) ?: return
                // Persist delivery status in storage
                val myId = UserStorage.getUserId(this@MessengerService)
                ChatStorage.markDelivered(this@MessengerService, myId, from, messageId)
                withContext(Dispatchers.Main) { onDeliveredReceived?.invoke(messageId) }
            }

            "edit" -> {
                val messageId = json.getString("id")
                val from = json.getString("from")
                val encryptedText = json.getString("text")
                val signature = json.optString("signature", null)
                val senderPublicKey = publicKeys[from]
                if (signature != null && senderPublicKey != null &&
                    CryptoManager.verify(encryptedText, signature, senderPublicKey)) {
                    try {
                        val decryptedText = CryptoManager.decrypt(encryptedText)
                        withContext(Dispatchers.Main) { onEditReceived?.invoke(messageId, decryptedText) }
                    } catch (e: Exception) {
                        Log.e(TAG, "Ошибка расшифровки edit: ${e.message}")
                    }
                }
            }

            "reaction" -> {
                try {
                    val from = json.getString("from")
                    val messageId = json.getString("message_id")
                    val encryptedEmoji = json.getString("emoji")
                    val emoji = CryptoManager.decrypt(encryptedEmoji)
                    withContext(Dispatchers.Main) { onReactionReceived?.invoke(from, messageId, emoji) }
                } catch (e: Exception) {
                    Log.e(TAG, "reaction error: ${e.message}")
                }
            }

            "message_delete" -> {
                val from = json.getString("from")
                val messageId = json.getString("message_id")
                val myId = UserStorage.getUserId(this@MessengerService)
                ChatStorage.deleteMessage(this@MessengerService, myId, from, messageId)
                withContext(Dispatchers.Main) { onMessageDeleted?.invoke(from, messageId) }
            }

            "disappear_timer" -> {
                val from = json.getString("from")
                val seconds = json.getLong("seconds")
                val myId = UserStorage.getUserId(this@MessengerService)
                ChatStorage.setDisappearTimer(this@MessengerService, myId, from, seconds)
                withContext(Dispatchers.Main) { onDisappearTimerChanged?.invoke(from, seconds) }
            }

            "group_message_delete" -> {
                val groupId = json.getString("group_id")
                val messageId = json.getString("message_id")
                val myId = UserStorage.getUserId(this@MessengerService)
                GroupManager.deleteGroupMessage(this@MessengerService, myId, groupId, messageId)
                withContext(Dispatchers.Main) { onGroupMessageDeleted?.invoke(groupId, messageId) }
            }

            "image_chunk" -> {
                val from = json.getString("from")
                val imageId = json.getString("image_id")
                val chunkIndex = json.getInt("chunk_index")
                val totalChunks = json.getInt("total_chunks")
                val chunkData = json.getString("data")
                val signature = json.optString("signature", null)
                val isEncrypted = json.optBoolean("encrypted", false)

                val senderKey = publicKeys[from]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                        publicKeys[from] = it
                    }

                if (signature != null && senderKey != null &&
                    CryptoManager.verifyChunk(chunkData, signature, senderKey, imageId, chunkIndex)) {

                    // Отправляем ACK
                    sendWs(JSONObject().apply {
                        put("type", "chunk_ack")
                        put("image_id", imageId)
                        put("chunk_index", chunkIndex)
                    }.toString())

                    try {
                        // Ключ буфера включает отправителя, чтобы два разных отправителя
                        // с одинаковым imageId не смешивали чанки друг друга.
                        val transferKey = "$from:$imageId"
                        if (isEncrypted) {
                            // Новый формат: собираем зашифрованные чанки
                            val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
                            chunks[chunkIndex] = chunkData
                            imageTotals[transferKey] = totalChunks

                            if (chunks.size == totalChunks) {
                                Log.d(TAG, "Все image чанки получены, расшифровываем...")

                                val ordered = (0 until totalChunks).map { chunks[it]!! }
                                val packedData = ordered.joinToString("")

                                // Расшифровываем
                                val encryptedFileData = CryptoManager.unpackEncryptedFile(packedData)
                                val decryptedBytes = CryptoManager.decryptFile(encryptedFileData)

                                // Декодируем bitmap
                                val bitmap = android.graphics.BitmapFactory.decodeByteArray(
                                    decryptedBytes, 0, decryptedBytes.size
                                )

                                if (bitmap != null) {
                                    imageChunks.remove(transferKey)
                                    imageTotals.remove(transferKey)
                                    withContext(Dispatchers.Main) {
                                        onImageReceived?.invoke(imageId, bitmap)
                                    }
                                }
                            }
                        } else {
                            // Legacy формат: текстовые чанки
                            val decryptedChunk = CryptoManager.decrypt(chunkData)
                            val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
                            chunks[chunkIndex] = decryptedChunk
                            imageTotals[transferKey] = totalChunks

                            if (chunks.size == totalChunks) {
                                val ordered = (0 until totalChunks).map { chunks[it]!! }
                                val bitmap = ImageHelper.assembleImage(ordered)
                                if (bitmap != null) {
                                    imageChunks.remove(transferKey)
                                    imageTotals.remove(transferKey)
                                    withContext(Dispatchers.Main) {
                                        onImageReceived?.invoke(imageId, bitmap)
                                    }
                                }
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "image chunk error: ${e.message}", e)
                    }
                }
            }

            "file_chunk" -> {
                try {
                    val from = json.getString("from")
                    val fileId = json.getString("file_id")
                    val fileName = json.getString("file_name")
                    val chunkIndex = json.getInt("chunk_index")
                    val totalChunks = json.getInt("total_chunks")
                    val chunkData = json.getString("data")
                    val signature = json.optString("signature", null)
                    val isEncrypted = json.optBoolean("encrypted", false)

                    Log.d(TAG, "Получен file_chunk $chunkIndex/$totalChunks для $fileName (зашифрован: $isEncrypted)")

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }

                    if (senderKey == null) {
                        Log.e(TAG, "⚠️ File chunk без ключа от $from — запрашиваем")
                        requestPrekeyBundle(from)
                        return
                    }

                    if (signature == null || !CryptoManager.verifyChunk(chunkData, signature, senderKey, fileId, chunkIndex)) {
                        Log.e(TAG, "⚠️ Неверная подпись file chunk от $from")
                        return
                    }

                    sendWs(JSONObject().apply {
                        put("type", "chunk_ack")
                        put("file_id", fileId)
                        put("chunk_index", chunkIndex)
                    }.toString())

                    // Ключ буфера включает отправителя — изолируем передачи разных
                    // отправителей с одинаковым fileId друг от друга.
                    val fileTransferKey = "$from:$fileId"

                    if (!fileChunks.containsKey(fileTransferKey)) {
                        fileChunks[fileTransferKey] = FileMeta(fileName, totalChunks, mutableListOf())
                    }
                    fileChunks[fileTransferKey]?.chunks?.add(chunkIndex to chunkData)

                    val receivedChunks = fileChunks[fileTransferKey]?.chunks?.size ?: 0
                    Log.d(TAG, "Собрано чанков: $receivedChunks/$totalChunks для файла $fileName")

                    if (receivedChunks == totalChunks) {
                        Log.d(TAG, "Все чанки получены для $fileId, начинаем сборку")

                        val sortedChunks = fileChunks[fileTransferKey]?.chunks?.sortedBy { it.first }
                        if (sortedChunks == null) {
                            Log.e(TAG, "fileChunks[$fileTransferKey] исчез до сборки — пропускаем")
                            return
                        }
                        val fullPackedData = sortedChunks.joinToString("") { it.second }

                        if (isEncrypted) {
                            Log.d(TAG, "Расшифровываем файл $fileName...")

                            try {
                                val encryptedFileData = CryptoManager.unpackEncryptedFile(fullPackedData)
                                val decryptedBytes = CryptoManager.decryptFile(encryptedFileData)

                                Log.d(TAG, "Файл расшифрован: ${decryptedBytes.size} байт")

                                val file = File(filesDir, "files/$fileId/${fileName}.enc").apply {
                                    parentFile?.mkdirs()
                                }
                                SecureFileStorage.write(this@MessengerService, file, decryptedBytes)

                                Log.d(TAG, "✅ Файл $fileName расшифрован и сохранен зашифрованным: ${file.absolutePath}")

                                withContext(Dispatchers.Main) {
                                    onFileReceived?.invoke(fileId, file, fileName)
                                }

                            } catch (e: Exception) {
                                Log.e(TAG, "❌ Ошибка расшифровки файла: ${e.message}", e)
                            }

                        } else {
                            Log.d(TAG, "Файл в legacy формате (без шифрования)")

                            val fileBytes = android.util.Base64.decode(fullPackedData, android.util.Base64.DEFAULT)
                            val file = File(filesDir, "files/$fileId/${fileName}.enc").apply {
                                parentFile?.mkdirs()
                            }
                            SecureFileStorage.write(this@MessengerService, file, fileBytes)

                            Log.d(TAG, "✅ Legacy файл сохранен зашифрованным: ${file.absolutePath}")

                            withContext(Dispatchers.Main) {
                                onFileReceived?.invoke(fileId, file, fileName)
                            }
                        }

                        fileChunks.remove(fileTransferKey)
                    }

                } catch (e: Exception) {
                    Log.e(TAG, "❌ file_chunk error: ${e.message}", e)
                }
            }

            "video_chunk" -> {
                try {
                    val from = json.getString("from")
                    val videoId = json.getString("video_id")
                    val chunkIndex = json.getInt("chunk_index")
                    val totalChunks = json.getInt("total_chunks")
                    val chunkData = json.getString("data")
                    val duration = json.optInt("duration", 0)
                    val isEncrypted = json.optBoolean("encrypted", true)
                    val signature = json.optString("signature", null)

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }

                    if (signature == null || senderKey == null ||
                        !CryptoManager.verifyChunk(chunkData, signature, senderKey, videoId, chunkIndex)) {
                        Log.e(TAG, "⚠️ video_chunk неверная подпись от $from")
                        return
                    }
                    // Примечание: chunk_ack отправляет сам СЕРВЕР отправителю сразу после
                    // пересылки чанка получателю (см. server.py video_chunk handler).
                    // Получатель НЕ должен отправлять chunk_ack — сервер его не обрабатывает.

                    val transferKey = "$from:$videoId"
                    val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
                    chunks[chunkIndex] = chunkData
                    imageTotals[transferKey] = totalChunks

                    if (chunks.size == totalChunks) {
                        Log.d(TAG, "Все video чанки получены ($totalChunks), расшифровываем...")
                        val packed = (0 until totalChunks).map { chunks[it]!! }.joinToString("")
                        imageChunks.remove(transferKey)
                        imageTotals.remove(transferKey)

                        if (isEncrypted) {
                            val encryptedFileData = CryptoManager.unpackEncryptedFile(packed)
                            val decryptedBytes = CryptoManager.decryptFile(encryptedFileData)
                            val file = File(filesDir, "videos/$videoId.mp4.enc").apply {
                                parentFile?.mkdirs()
                            }
                            SecureFileStorage.write(this@MessengerService, file, decryptedBytes)
                            Log.d(TAG, "✅ Видеокружок расшифрован: ${file.absolutePath}")
                            withContext(Dispatchers.Main) {
                                onVideoReceived?.invoke(videoId, file, duration)
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "video_chunk error: ${e.message}", e)
                }
            }

            "voice" -> {
                try {
                    val from = json.getString("from")
                    val voiceId = json.getString("voice_id")
                    val encryptedData = json.getString("voice_data")
                    val signature = json.optString("signature", null)
                    val duration = json.getInt("duration")

                    val senderKey = publicKeys[from] ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }

                    if (signature == null || senderKey == null) {
                        Log.e(TAG, "⚠️ Voice без ключа от $from — запрашиваем")
                        requestPrekeyBundle(from)
                        return
                    }

                    // ДОБАВЬ КОНВЕРТАЦИЮ:
                    val fixedKey = senderKey.replace('-', '+').replace('_', '/')

                    if (!CryptoManager.verify(encryptedData, signature, fixedKey)) {
                        Log.e(TAG, "⚠️ Неверная подпись голосового от $from")
                        return
                    }

                    val voiceData = CryptoManager.decrypt(encryptedData)
                    val voiceFile = AudioHelper.decodeAndSave(this@MessengerService, voiceData, voiceId)
                    withContext(Dispatchers.Main) { onVoiceReceived?.invoke(voiceId, voiceFile, duration) }
                } catch (e: Exception) {
                    Log.e(TAG, "voice error: ${e.message}")
                }
            }

            "prekey_bundle" -> {
                val fromUser = json.getString("from")
                if (json.has("identity_key") && !json.isNull("identity_key")) {
                    val identityKey = json.getString("identity_key")

                    // Конвертация URL-safe Base64
                    val fixedIdentityKey = identityKey.replace('-', '+').replace('_', '/')

                    // Сохраняем identity key
                    publicKeys[fromUser] = fixedIdentityKey
                    ChatStorage.saveContactPublicKey(this@MessengerService, fromUser, fixedIdentityKey)

                    if (KeyHistoryManager.checkKeyChange(this@MessengerService, fromUser, fixedIdentityKey)) {
                        withContext(Dispatchers.Main) { onKeyChanged?.invoke(fromUser) }
                    }

                    Log.d(TAG, "Публичный ключ из prekey bundle сохранён: $fromUser")
                } else {
                    Log.w(TAG, "Пустой prekey bundle от $fromUser — fallback на legacy")
                }
            }

            "prekey_bundle_response" -> {
                val from = json.getString("from")
                val bundleJsonRaw = if (json.isNull("bundle")) null else json.getJSONObject("bundle")
                if (bundleJsonRaw == null) {
                    Log.w(TAG, "Пустой prekey bundle от $from — fallback на legacy")
                    pendingSessionMessages.remove(from)?.forEach { (text, msgId) ->
                        if (text.startsWith("__voice__|")) {
                            val parts = text.removePrefix("__voice__|").split("|", limit = 3)
                            sendVoice(from, parts[2], parts[0], parts[1].toIntOrNull() ?: 0)
                        } else {
                            val key = publicKeys[from]
                                ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                                    ?.also { publicKeys[from] = it }
                            if (key != null) sendEncrypted(from, text, key, msgId)
                            else Log.e(TAG, "Нет ключа для $from — сообщение не отправлено")
                        }
                    }
                } else {
                    try {
                        val rawBundle = SessionKeyManager.parsePrekeyBundle(bundleJsonRaw)

                        // Нормализуем ВСЕ ключи bundle: URL-safe Base64 → стандартный Base64
                        // (сервер хранит стандартный, но на всякий случай конвертируем всё)
                        fun String.toStdB64() = replace('-', '+').replace('_', '/')
                        val bundle = rawBundle.copy(
                            identityKey    = rawBundle.identityKey.toStdB64(),
                            signedPrekey   = rawBundle.signedPrekey.toStdB64(),
                            spkSignature   = rawBundle.spkSignature.toStdB64(),
                            oneTimePrekeys = rawBundle.oneTimePrekeys.map { opk ->
                                val ci = opk.indexOf(':')
                                if (ci >= 0) "${opk.substring(0, ci + 1)}${opk.substring(ci + 1).toStdB64()}"
                                else opk.toStdB64()
                            }
                        )

                        publicKeys[from] = bundle.identityKey
                        ChatStorage.saveContactPublicKey(this@MessengerService, from, bundle.identityKey)
                        if (KeyHistoryManager.checkKeyChange(this@MessengerService, from, bundle.identityKey)) {
                            Log.w(TAG, "⚠️ TOFU: ключ контакта $from изменился при получении bundle!")
                            withContext(Dispatchers.Main) { onKeyChanged?.invoke(from) }
                        }
                        Log.d(TAG, "Публичный ключ из bundle сохранён: $from")

                        val (_, x3dhHeader) = SessionKeyManager.initiateSession(from, bundle)
                        Log.d(TAG, "X3DH сессия с $from инициирована")

                        pendingSessionMessages.remove(from)?.forEach { (text, msgId) ->
                            if (text.startsWith("__voice__|")) {
                                val parts = text.removePrefix("__voice__|").split("|", limit = 3)
                                sendVoice(from, parts[2], parts[0], parts[1].toIntOrNull() ?: 0)
                            } else {
                                sendWithForwardSecrecy(from, text, msgId, x3dhHeader, isFirst = true)
                            }
                        }
                    } catch (e: SecurityException) {
                        Log.e(TAG, "X3DH FAIL с $from: ${e.message}")
                        // Fallback на legacy шифрование — не теряем сообщения
                        pendingSessionMessages.remove(from)?.forEach { (text, msgId) ->
                            if (text.startsWith("__voice__|")) {
                                val parts = text.removePrefix("__voice__|").split("|", limit = 3)
                                sendVoice(from, parts[2], parts[0], parts[1].toIntOrNull() ?: 0)
                            } else {
                                val key = publicKeys[from]
                                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                                        ?.also { publicKeys[from] = it }
                                if (key != null) sendEncrypted(from, text, key, msgId)
                                else Log.e(TAG, "X3DH failed и нет ключа для $from — сообщение потеряно")
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "prekey_bundle_response error: ${e.message}")
                        // Fallback на legacy шифрование — не теряем сообщения
                        pendingSessionMessages.remove(from)?.forEach { (text, msgId) ->
                            if (text.startsWith("__voice__|")) {
                                val parts = text.removePrefix("__voice__|").split("|", limit = 3)
                                sendVoice(from, parts[2], parts[0], parts[1].toIntOrNull() ?: 0)
                            } else {
                                val key = publicKeys[from]
                                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                                        ?.also { publicKeys[from] = it }
                                if (key != null) sendEncrypted(from, text, key, msgId)
                                else Log.e(TAG, "Bundle error и нет ключа для $from — сообщение потеряно")
                            }
                        }
                    }
                }
                // Флашим видеокружки, ожидавшие ключ этого контакта
                flushPendingVideoCircles(from)
            }

            "session_init" -> {
                val from = json.getString("from")
                val senderIk = json.getString("sender_ik")
                val x3dhHeader = json.getJSONObject("x3dh_header")
                val encryptedText = json.getString("text")
                val signature = json.optString("signature", null)
                val messageId = json.optString("id", null)
                try {
                    // ИСПРАВЬ: Конвертируй и сохрани sender_ik
                    val fixedSenderIk = senderIk.replace('-', '+').replace('_', '/')
                    publicKeys[from] = fixedSenderIk
                    ChatStorage.saveContactPublicKey(this@MessengerService, from, fixedSenderIk)
                    Log.d(TAG, "Публичный ключ из session_init сохранён: $from")

                    val senderKey = publicKeys[from]!!  // Теперь гарантированно есть

                    if (signature == null) {
                        Log.e(TAG, "session_init без подписи от $from")
                        return
                    }
                    if (!CryptoManager.verify(encryptedText, signature, senderKey)) {
                        Log.e(TAG, "Неверная подпись session_init от $from")
                        return
                    }
                    SessionKeyManager.receiveSession(from, fixedSenderIk, x3dhHeader)
                    val sessionHeader = json.getJSONObject("session_header")
                    val decryptedText = CryptoManager.decryptWithForwardSecrecy(from, encryptedText, sessionHeader)
                    handleIncomingDecryptedMessage(from, decryptedText, messageId, json)
                    // Первое сообщение от нового контакта — отправляем им наши токены
                    if (AnonTokenManager.getContactTokens(this@MessengerService, from).isEmpty() &&
                        AnonTokenManager.getMyTokens(this@MessengerService).isNotEmpty()) {
                        scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
                    }
                    // Если были pending сообщения к from (например, после session_reset) — отправляем
                    pendingSessionMessages.remove(from)?.forEach { (text, msgId) ->
                        scope.launch(Dispatchers.IO) { sendWithForwardSecrecy(from, text, msgId) }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "session_init error: ${e.message}")
                    // Не смогли установить сессию — просим отправителя начать заново.
                    requestPrekeyBundle(from)
                    sendAnonOrDirect(from, JSONObject().apply {
                        put("type", "session_reset")
                        put("to", from)
                    })
                }
            }

            "message" -> {
                val messageId = json.optString("id", null)
                val from = json.getString("from")
                val protocolVersion = json.optInt("protocol_version", 1)
                if (messageId != null) {
                    val nowMs = System.currentTimeMillis()
                    // Периодическая очистка протухших записей
                    if (receivedMessageIds.size > 200) {
                        receivedMessageIds.entries.removeIf { nowMs - it.value > REPLAY_WINDOW_MS }
                    }
                    if (receivedMessageIds.containsKey(messageId)) return
                }
                val encryptedText = json.getString("text")
                val signature = json.optString("signature", null)
                val senderPublicKey = publicKeys[from] ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                if (signature == null || senderPublicKey == null) {
                    Log.e(TAG, "Нет ключа от $from — запрашиваем")
                    requestPrekeyBundle(from)
                    return
                }
                if (!CryptoManager.verify(encryptedText, signature, senderPublicKey)) {
                    Log.e(TAG, "Неверная подпись от $from")
                    return
                }
                try {
                    val decryptedText = if (protocolVersion >= 2 && json.has("session_header")) {
                        val sessionHeader = json.getJSONObject("session_header")
                        if (!SessionKeyManager.hasSession(from)) {
                            try {
                                val fallback = CryptoManager.decrypt(encryptedText)
                                handleIncomingDecryptedMessage(from, fallback, messageId, json)
                            } catch (e: Exception) {
                                // Сессия утеряна (переустановка, очистка данных).
                                // Уведомляем отправителя сбросить сессию — иначе он будет
                                // бесконечно слать сообщения старым ключом, и они будут дропаться.
                                requestPrekeyBundle(from)
                                sendAnonOrDirect(from, JSONObject().apply {
                                    put("type", "session_reset")
                                    put("to", from)
                                })
                            }
                            return
                        }
                        CryptoManager.decryptWithForwardSecrecy(from, encryptedText, sessionHeader)
                    } else {
                        CryptoManager.decrypt(encryptedText)
                    }
                    handleIncomingDecryptedMessage(from, decryptedText, messageId, json)
                    // Отправляем токены только если их совсем нет (первый контакт)
                    if (AnonTokenManager.getContactTokens(this@MessengerService, from).isEmpty()) {
                        scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка расшифровки от $from: ${e.message}")
                    SessionKeyManager.deleteSession(from)
                    requestPrekeyBundle(from)
                    // Сигнализируем отправителю, что нужно сбросить сессию
                    sendAnonOrDirect(from, JSONObject().apply {
                        put("type", "session_reset")
                        put("to", from)
                    })
                }
            }

            "chunk_ack" -> {
                val imageId = json.optString("image_id", null)
                val fileId = json.optString("file_id", null)
                val videoId = json.optString("video_id", null)
                val chunkIndex = json.optInt("chunk_index", -1)
                when {
                    videoId != null -> videoChunkAcks[videoId]?.trySend(chunkIndex)
                    imageId != null -> imageChunkAcks[imageId]?.trySend(chunkIndex)
                    fileId != null -> fileChunkAcks[fileId]?.trySend(chunkIndex)
                }
            }
            "group_create" -> {
                val groupId = json.getString("group_id")
                val groupName = json.getString("group_name")
                val groupAvatar = json.getString("group_avatar")
                val from = json.getString("from")
                val encryptedGroupKey = json.getString("encrypted_group_key")
                val signature = json.optString("signature", null)

                try {
                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }

                    if (signature == null || senderKey == null) {
                        Log.e(TAG, "group_create без ключа от $from")
                        return
                    }

                    if (!CryptoManager.verify(encryptedGroupKey, signature, senderKey)) {
                        Log.e(TAG, "Неверная подпись приглашения в группу от $from")
                        return
                    }

                    // Расшифровываем групповой ключ
                    val groupKey = GroupManager.decryptGroupKey(encryptedGroupKey)

                    // Проверяем, не состоим ли уже в группе
                    val existingGroup = GroupManager.getGroup(this@MessengerService, groupId)
                    if (existingGroup != null) {
                        Log.d(TAG, "Уже состоим в группе $groupName")
                        return
                    }

                    // Создаём группу локально
                    val group = Group(
                        id = groupId,
                        name = groupName,
                        avatar = groupAvatar,
                        members = listOf(from, username),
                        admins = listOf(from),
                        createdBy = from,
                        groupKey = groupKey
                    )

                    GroupManager.saveGroup(this@MessengerService, group)

                    // Отправляем уведомление создателю что приняли приглашение
                    val inviteSignature = CryptoManager.sign("$groupId:$username")
                    sendAnonOrDirect(from, JSONObject().apply {
                        put("type", "group_invite_accepted")
                        put("from", username)
                        put("to", from)
                        put("group_id", groupId)
                        put("new_member", username)
                        put("new_member_name", UserStorage.getUsername(this@MessengerService))
                        put("signature", inviteSignature)
                    })

                    Log.d(TAG, "Приглашение в группу $groupName принято")

                    withContext(Dispatchers.Main) {
                        onGroupInviteReceived?.invoke(group, encryptedGroupKey)

                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_create error: ${e.message}")
                }
            }

            "group_message" -> {
                val groupId = json.getString("group_id")
                val messageId = json.getString("message_id")
                val from = json.getString("from")
                val senderName = json.getString("sender_name")
                val encryptedText = json.getString("text")
                val signature = json.optString("signature", null)

                try {
                    // Replay protection: отбрасываем уже обработанные message_id
                    if (!processedGroupMessageIds.add(messageId)) {
                        Log.w(TAG, "group_message replay отклонён: $messageId")
                        return
                    }
                    if (processedGroupMessageIds.size > 2000) processedGroupMessageIds.clear()

                    val group = GroupManager.getGroup(this@MessengerService, groupId)
                    if (group == null) {
                        android.util.Log.w(TAG, "Получено сообщение для неизвестной группы $groupId")
                        return
                    }

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }

                    if (signature == null || senderKey == null) {
                        android.util.Log.e(TAG, "Сообщение группы без ключа от $from")
                        return
                    }

                    if (!CryptoManager.verify(encryptedText, signature, senderKey)) {
                        android.util.Log.e(TAG, "Неверная подпись группового сообщения от $from")
                        return
                    }

                    // Расшифровываем групповым ключом
                    val decryptedText = GroupManager.decryptGroupMessage(encryptedText, group.groupKey!!)

                    val groupMessage = GroupMessage(
                        id = messageId,
                        groupId = groupId,
                        senderId = from,
                        senderName = senderName,
                        text = decryptedText,
                        isOwn = from == username
                    )

                    GroupManager.saveGroupMessage(this@MessengerService, username, groupMessage)

                    withContext(Dispatchers.Main) {
                        val cb = onGroupMessageReceived
                        if (cb != null) cb.invoke(groupId, groupMessage)
                        else showGroupMessageNotification(groupId, senderName, decryptedText)
                        MainActivity.chatListVersion.value = System.currentTimeMillis()
                    }
                } catch (e: Exception) {
                    android.util.Log.e(TAG, "group_message error: ${e.message}")
                }
            }
            "group_reaction" -> {
                try {
                    val groupId   = json.getString("group_id")
                    val from      = json.getString("from")
                    val messageId = json.getString("message_id")
                    val emoji     = json.getString("emoji")
                    withContext(Dispatchers.Main) {
                        onGroupReactionReceived?.invoke(groupId, from, messageId, emoji)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_reaction error: ${e.message}")
                }
            }

            "group_member_removed" -> {
                val groupId = json.getString("group_id")
                val removedMember = json.getString("removed_member")
                val from = json.optString("from", null)
                val removeSignature = json.optString("signature", null)

                try {
                    val group = GroupManager.getGroup(this@MessengerService, groupId)
                    if (group != null) {
                        // Проверяем, что отправитель — администратор группы
                        if (from == null || !GroupManager.isAdmin(this@MessengerService, groupId, from)) {
                            Log.e(TAG, "group_member_removed от не-администратора $from — отклонено")
                            return
                        }
                        // Проверяем подпись администратора
                        val adminKey = publicKeys[from]
                            ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                        if (removeSignature == null || adminKey == null ||
                            !CryptoManager.verify("$groupId:$removedMember", removeSignature, adminKey)) {
                            Log.e(TAG, "group_member_removed: неверная подпись от $from — отклонено")
                            return
                        }
                        GroupManager.removeMember(this@MessengerService, groupId, removedMember)

                        // Системное сообщение о удалении
                        val sysMessage = GroupMessage(
                            id = UUID.randomUUID().toString(),
                            groupId = groupId,
                            senderId = "system",
                            senderName = s.systemSender,
                            text = s.groupMemberLeft(ChatStorage.getContactName(this@MessengerService, removedMember)),
                            isOwn = false
                        )

                        GroupManager.saveGroupMessage(this@MessengerService, username, sysMessage)

                        withContext(Dispatchers.Main) {
                            onGroupMessageReceived?.invoke(groupId, sysMessage)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_member_removed error: ${e.message}")
                }
            }

            "group_key_rotation" -> {
                val groupId = json.getString("group_id")
                val encryptedNewKey = json.getString("encrypted_new_key")
                val signature = json.optString("signature", null)
                val from = json.getString("from")

                try {
                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }

                    if (signature == null || senderKey == null) {
                        Log.e(TAG, "group_key_rotation без ключа от $from")
                        return
                    }

                    if (!CryptoManager.verify(encryptedNewKey, signature, senderKey)) {
                        Log.e(TAG, "Неверная подпись ротации ключа от $from")
                        return
                    }

                    // Расшифровываем новый групповой ключ
                    val newGroupKey = GroupManager.decryptGroupKey(encryptedNewKey)

                    // Обновляем группу с новым ключом
                    val group = GroupManager.getGroup(this@MessengerService, groupId)
                    if (group != null) {
                        val updatedGroup = group.copy(groupKey = newGroupKey)
                        GroupManager.saveGroup(this@MessengerService, updatedGroup)

                        Log.d(TAG, "Групповой ключ обновлён для группы $groupId")

                        // Системное сообщение
                        val sysMessage = GroupMessage(
                            id = UUID.randomUUID().toString(),
                            groupId = groupId,
                            senderId = "system",
                            senderName = s.systemSender,
                            text = s.groupKeyUpdated,
                            isOwn = false
                        )

                        GroupManager.saveGroupMessage(this@MessengerService, username, sysMessage)

                        withContext(Dispatchers.Main) {
                            onGroupMessageReceived?.invoke(groupId, sysMessage)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_key_rotation error: ${e.message}")
                }
            }

            "group_invite_accepted" -> {
                val groupId = json.getString("group_id")
                val newMember = json.getString("new_member")
                val newMemberName = json.getString("new_member_name")
                val inviteSignature = json.optString("signature", null)

                try {
                    // Проверяем подпись нового участника: предотвращает добавление шпиона сервером
                    val memberPublicKey = publicKeys[newMember]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, newMember)
                    if (inviteSignature == null || memberPublicKey == null ||
                        !CryptoManager.verify("$groupId:$newMember", inviteSignature, memberPublicKey)) {
                        Log.e(TAG, "group_invite_accepted: неверная подпись от $newMember — отклонено")
                        return
                    }

                    // Добавляем участника локально
                    GroupManager.addMember(this@MessengerService, groupId, newMember)

                    // Системное сообщение
                    val sysMessage = GroupMessage(
                        id = UUID.randomUUID().toString(),
                        groupId = groupId,
                        senderId = "system",
                        senderName = s.systemSender,
                        text = s.groupMemberJoined(newMemberName),
                        isOwn = false
                    )

                    GroupManager.saveGroupMessage(this@MessengerService, username, sysMessage)

                    withContext(Dispatchers.Main) {
                        onGroupMessageReceived?.invoke(groupId, sysMessage)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_invite_accepted error: ${e.message}")
                }
            }

            // ─── Channel Created (response after channel_create) ──────────────
            "channel_created" -> {
                try {
                    val channelId = json.getString("channel_id")
                    val channelName = json.getString("channel_name")
                    val channelAvatar = json.optString("channel_avatar", "📢")
                    val channelDesc = json.optString("channel_description", "")
                    val channel = Channel(
                        id = channelId,
                        name = channelName,
                        description = channelDesc,
                        avatar = channelAvatar,
                        adminId = username,
                        adminName = UserStorage.getUsername(this@MessengerService),
                        isAdmin = true
                    )
                    ChannelManager.saveChannel(this@MessengerService, channel)
                    Log.d(TAG, "Канал создан: $channelName ($channelId)")
                    withContext(Dispatchers.Main) {
                        onChannelCreated?.invoke(channel)
                        android.widget.Toast.makeText(
                            this@MessengerService,
                            s.channelCreatedToast(channelName),
                            android.widget.Toast.LENGTH_LONG
                        ).show()
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "channel_created error: ${e.message}")
                }
            }

            // ─── Channel Update (new post from admin) ─────────────────────────
            "channel_update" -> {
                try {
                    val channelId = json.getString("channel_id")
                    if (ChannelManager.getChannel(this@MessengerService, channelId) == null) {
                        Log.w(TAG, "channel_update: unknown channel $channelId, ignored")
                        return
                    }
                    val postId = json.getString("post_id")
                    val text = json.getString("text")
                    val timestamp = json.getLong("timestamp")
                    val authorId = json.optString("author_id", "")
                    val authorName = json.optString("author_name", "")
                    val imageData = json.optString("image_data", "")

                    val post = ChannelPost(
                        id = postId,
                        channelId = channelId,
                        text = text,
                        timestamp = timestamp,
                        authorId = authorId,
                        authorName = authorName,
                        imageData = imageData
                    )
                    ChannelManager.addPost(this@MessengerService, post)

                    withContext(Dispatchers.Main) {
                        val cb = onChannelPostReceived
                        if (cb != null) cb.invoke(channelId, post)
                        else {
                            val channel = ChannelManager.getChannel(this@MessengerService, channelId)
                            showChannelPostNotification(channelId, channel?.name ?: s.channelFallbackName, text)
                        }
                        MainActivity.chatListVersion.value = System.currentTimeMillis()
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "channel_update error: ${e.message}")
                }
            }

            // ─── Channel Info (response to channel_get_info) ──────────────────
            "channel_info" -> {
                try {
                    val channelId = json.getString("channel_id")
                    val channelName = json.getString("channel_name")
                    val channelAvatar = json.optString("channel_avatar", "📢")
                    val channelDesc = json.optString("channel_description", "")
                    val isAdmin = json.optBoolean("is_admin", false)
                    val subscriberCount = json.optInt("subscriber_count", -1)
                    val pinnedPostId = json.optString("pinned_post_id", "").takeIf { it.isNotEmpty() }
                    val existing = ChannelManager.getChannel(this@MessengerService, channelId)
                    if (existing != null) {
                        ChannelManager.saveChannel(
                            this@MessengerService,
                            existing.copy(
                                name = channelName,
                                description = channelDesc,
                                avatar = channelAvatar,
                                isAdmin = isAdmin,
                                subscriberCount = if (subscriberCount >= 0) subscriberCount else existing.subscriberCount,
                                pinnedPostId = pinnedPostId ?: existing.pinnedPostId
                            )
                        )
                        withContext(Dispatchers.Main) { onChannelInfoUpdated?.invoke(channelId) }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "channel_info error: ${e.message}")
                }
            }

            // ─── Channel Post Deleted ─────────────────────────────────────────
            "channel_post_deleted" -> {
                try {
                    val channelId = json.getString("channel_id")
                    val postId = json.getString("post_id")
                    ChannelManager.removePost(this@MessengerService, channelId, postId)
                    withContext(Dispatchers.Main) { onChannelPostDeleted?.invoke(channelId, postId) }
                } catch (e: Exception) {
                    Log.e(TAG, "channel_post_deleted error: ${e.message}")
                }
            }

            // ─── Channel Info Updated (response to channel_update_info) ───────
            "channel_info_updated" -> {
                try {
                    val channelId = json.getString("channel_id")
                    val existing = ChannelManager.getChannel(this@MessengerService, channelId)
                    if (existing != null) {
                        ChannelManager.saveChannel(
                            this@MessengerService,
                            existing.copy(
                                name = json.getString("channel_name"),
                                description = json.optString("channel_description", ""),
                                avatar = json.optString("channel_avatar", "📢")
                            )
                        )
                        withContext(Dispatchers.Main) { onChannelInfoUpdated?.invoke(channelId) }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "channel_info_updated error: ${e.message}")
                }
            }

            // ─── Channel Deleted ──────────────────────────────────────────────
            "channel_deleted" -> {
                try {
                    val channelId = json.getString("channel_id")
                    ChannelManager.removeChannel(this@MessengerService, channelId)
                    withContext(Dispatchers.Main) {
                        onChannelDeleted?.invoke(channelId)
                        MainActivity.chatListVersion.value = System.currentTimeMillis()
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "channel_deleted error: ${e.message}")
                }
            }

            // ─── Channel Post Pinned ──────────────────────────────────────────
            "channel_pinned" -> {
                try {
                    val channelId = json.getString("channel_id")
                    val postId = json.optString("post_id", "").takeIf { it.isNotEmpty() }
                    val existing = ChannelManager.getChannel(this@MessengerService, channelId)
                    if (existing != null) {
                        ChannelManager.saveChannel(
                            this@MessengerService,
                            existing.copy(pinnedPostId = postId)
                        )
                        withContext(Dispatchers.Main) { onChannelInfoUpdated?.invoke(channelId) }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "channel_pinned error: ${e.message}")
                }
            }

            // ─── Call Signaling ───────────────────────────────────────────────
            "call_offer" -> {
                try {
                    val from    = json.getString("from")
                    val sdp     = json.getString("sdp")
                    val callId  = json.getString("call_id")
                    val isVideo = json.optBoolean("is_video", false)
                    val isGroup = json.optBoolean("is_group", false)
                    val gId     = json.optString("group_id", "")
                    CallManager.init(this@MessengerService)
                    CallManager.handleOffer(from, sdp, callId, isVideo, isGroup, gId)
                    // Показываем уведомление с full-screen intent
                    val peerName = ChatStorage.getContactName(this@MessengerService, from).ifBlank { from }
                    startService(Intent(this@MessengerService, CallService::class.java).apply {
                        action = CallService.ACTION_INCOMING
                        putExtra(CallService.EXTRA_PEER_NAME, peerName)
                        putExtra(CallService.EXTRA_IS_VIDEO,  isVideo)
                        putExtra(CallService.EXTRA_IS_GROUP,  isGroup)
                    })
                    withContext(Dispatchers.Main) {
                        MainActivity.pendingIncomingCall.value = Triple(callId, isVideo, from)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "call_offer error: ${e.message}")
                }
            }

            "call_group_invite" -> {
                try {
                    val from    = json.getString("from")
                    val callId  = json.getString("call_id")
                    val isVideo = json.optBoolean("is_video", false)
                    val gId     = json.optString("group_id", "")
                    CallManager.init(this@MessengerService)
                    CallManager.handleGroupInvite(from, callId, isVideo, gId)
                    val peerName = ChatStorage.getContactName(this@MessengerService, from).ifBlank { from }
                    startService(Intent(this@MessengerService, CallService::class.java).apply {
                        action = CallService.ACTION_INCOMING
                        putExtra(CallService.EXTRA_PEER_NAME, peerName)
                        putExtra(CallService.EXTRA_IS_VIDEO,  isVideo)
                        putExtra(CallService.EXTRA_IS_GROUP,  true)
                    })
                    withContext(Dispatchers.Main) {
                        MainActivity.pendingIncomingCall.value = Triple(callId, isVideo, from)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "call_group_invite error: ${e.message}")
                }
            }

            "missed_call" -> {
                try {
                    val from    = json.getString("from")
                    val isVideo = json.optBoolean("is_video", false)
                    val name    = ChatStorage.getContactName(this@MessengerService, from).ifBlank { from }
                    showMissedCallNotification(from, name, isVideo)
                } catch (e: Exception) {
                    Log.e(TAG, "missed_call error: ${e.message}")
                }
            }

            "call_answer", "call_group_answer" -> {
                try {
                    val from = json.getString("from")
                    val sdp  = json.getString("sdp")
                    CallManager.handleAnswer(from, sdp)
                } catch (e: Exception) {
                    Log.e(TAG, "call_answer error: ${e.message}")
                }
            }

            "call_group_join" -> {
                try {
                    val from   = json.getString("from")
                    val sdp    = json.getString("sdp")
                    val callId = json.getString("call_id")
                    CallManager.handleGroupJoin(from, sdp, callId)
                } catch (e: Exception) {
                    Log.e(TAG, "call_group_join error: ${e.message}")
                }
            }

            "call_group_peer_list" -> {
                try {
                    val arr   = json.getJSONArray("peers")
                    val peers = (0 until arr.length()).map { arr.getString(it) }
                    CallManager.handleGroupPeerList(peers)
                } catch (e: Exception) {
                    Log.e(TAG, "call_group_peer_list error: ${e.message}")
                }
            }

            "call_ice_restart" -> {
                try {
                    val from = json.getString("from")
                    val sdp  = json.getString("sdp")
                    CallManager.handleIceRestart(from, sdp)
                } catch (e: Exception) {
                    Log.e(TAG, "call_ice_restart error: ${e.message}")
                }
            }

            "call_ice", "call_group_ice" -> {
                try {
                    val from     = json.getString("from")
                    val sdpMid   = json.getString("sdp_mid")
                    val sdpIdx   = json.getInt("sdp_m_line_index")
                    val candidate = json.getString("candidate")
                    CallManager.handleIceCandidate(from, sdpMid, sdpIdx, candidate)
                } catch (e: Exception) {
                    Log.e(TAG, "call_ice error: ${e.message}")
                }
            }

            "call_end", "call_group_leave" -> {
                try {
                    val from   = json.getString("from")
                    val reason = json.optString("reason", "hangup")
                    CallManager.handleCallEnd(from, reason)
                } catch (e: Exception) {
                    Log.e(TAG, "call_end error: ${e.message}")
                }
            }

            "call_ringing" -> { /* UI может показать "Звонит..." */ }

            "status" -> {
                val status = json.optString("status", "")
                val id = json.optString("id", null)
                if (status == "offline" && id != null) {
                    cancelledTransfers.add(id)
                    imageChunkAcks[id]?.close()
                    fileChunkAcks[id]?.close()
                    withContext(Dispatchers.Main) {
                        android.widget.Toast.makeText(this@MessengerService, s.recipientOffline, android.widget.Toast.LENGTH_SHORT).show()
                    }
                }
            }

            "ack" -> {
                val id = json.getString("id")
                MessageQueue.remove(this@MessengerService, id)
            }

            // ── Анонимная доставка по токену ──────────────────────────────────
            "anon_delivery" -> {
                try {
                    val payload = json.getJSONObject("payload")
                    // Потребляем токен — он одноразовый
                    payload.optString("_anon_token").takeIf { it.isNotBlank() }?.let {
                        AnonTokenManager.consumeMyToken(this@MessengerService, it)
                    }
                    // Переиспользуем существующий диспетчер
                    handleMessage(payload)
                } catch (e: Exception) {
                    Log.e(TAG, "anon_delivery error: ${e.message}")
                }
            }
        }
    }

    // ─── Отправка ─────────────────────────────────────────────────────────────

    fun send(to: String, text: String, replyToId: String? = null): String {
        if (isConnected) {
            // Если у контакта есть mailboxTag (v3 инвайт) и нет ещё сессии — используем mailbox
            val mailboxTag = AnonTokenManager.getContactMailboxTag(this, to)
            val hasContactTokens = AnonTokenManager.getContactTokens(this, to).isNotEmpty()
            if (mailboxTag != null && !hasContactTokens && !SessionKeyManager.hasSession(to)) {
                val publicKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this, to)?.also { publicKeys[to] = it }
                if (publicKey != null) {
                    val id = UUID.randomUUID().toString()
                    sendViaMailbox(to, text, publicKey, mailboxTag, id)
                    return id
                }
                // Ключ не найден — очищаем mailboxTag и идём обычным путём
                AnonTokenManager.clearContactMailboxTag(this, to)
            }
            return sendWithForwardSecrecy(to, text, replyToId = replyToId)
        } else {
            val id = UUID.randomUUID().toString()
            MessageQueue.add(this, MessageQueue.QueuedMessage(id = id, to = to, text = text))
            return id
        }
    }

    fun sendWithForwardSecrecy(
        to: String, text: String, msgId: String? = null,
        x3dhHeaderOverride: JSONObject? = null, isFirst: Boolean = false,
        replyToId: String? = null, useAnonRouting: Boolean = true
    ): String {
        val id = msgId ?: UUID.randomUUID().toString()
        scope.launch(Dispatchers.IO) {
            try {
                if (!SessionKeyManager.hasSession(to) && !isFirst) {
                    pendingSessionMessages.getOrPut(to) { mutableListOf() }.add(Pair(text, id))
                    requestPrekeyBundle(to)
                    return@launch
                }
                try {
                    val (encryptedText, sessionHeader) = CryptoManager.encryptWithForwardSecrecy(to, text)
                    val signature = CryptoManager.sign(encryptedText)
                    val packet = JSONObject().apply {
                        put("from", username)
                        put("to", to)
                        put("text", encryptedText)
                        put("signature", signature)
                        put("id", id)
                        put("protocol_version", ProtocolVersion.CURRENT_VERSION)
                        put("session_header", sessionHeader)
                        if (!replyToId.isNullOrBlank()) put("reply_to_id", replyToId)
                        if (isFirst && x3dhHeaderOverride != null) {
                            put("type", "session_init")
                            put("sender_ik", CryptoManager.getPublicKeyString())
                            put("x3dh_header", x3dhHeaderOverride)
                        } else {
                            put("type", "message")
                        }
                    }
                    // Анонимная доставка: используем токен если есть (даже для session_init)
                    val anonToken = AnonTokenManager.consumeNextContactToken(this@MessengerService, to)

                    if (anonToken != null) {
                        val anonPacket = JSONObject().apply {
                            put("type", "anon_message")
                            put("token", anonToken)
                            put("payload", packet)
                        }
                        sendWs(addPadding(anonPacket).toString())
                        // Запрашиваем пополнение пула токенов если кончаются
                        if (AnonTokenManager.needsRefill(this@MessengerService, to)) {
                            scope.launch(Dispatchers.IO) { sendAnonTokensTo(to) }
                        }
                    } else {
                        sendWs(addPadding(packet).toString())
                    }
                } catch (e: SessionKeyManager.SessionRotationRequired) {
                    SessionKeyManager.deleteSession(to)
                    pendingSessionMessages.getOrPut(to) { mutableListOf() }.add(Pair(text, id))
                    requestPrekeyBundle(to)
                }
            } catch (e: Exception) {
                Log.e(TAG, "sendWithForwardSecrecy error: ${e.message}")
                val recipientKey = publicKeys[to]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, to)
                        ?.also { publicKeys[to] = it }
                if (recipientKey != null) sendEncrypted(to, text, recipientKey, id)
            }
        }
        return id
    }

    private fun addPadding(packet: JSONObject): JSONObject {
        val currentSize = packet.toString().toByteArray().size
        val targetSize = ((currentSize / 512) + 1) * 512
        val paddingSize = targetSize - currentSize - 10
        if (paddingSize > 0) {
            val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            val padding = (1..paddingSize).map { chars.random() }.joinToString("")
            packet.put("_p", padding)
        }
        return packet
    }
    private fun generateWebSocketKey(): String {
        val random = ByteArray(16)
        java.security.SecureRandom().nextBytes(random)
        return android.util.Base64.encodeToString(random, android.util.Base64.NO_WRAP)
    }

    private fun sendEncrypted(to: String, text: String, publicKey: String, messageId: String? = null) {
        val id = messageId ?: UUID.randomUUID().toString()
        MessageQueue.remove(this@MessengerService, id)
        try {
            val encrypted = CryptoManager.encrypt(text, publicKey)
            val signature = CryptoManager.sign(encrypted)
            scope.launch(Dispatchers.IO) {
                sendWs(addPadding(JSONObject().apply {
                    put("type", "message")
                    put("from", username)
                    put("to", to)
                    put("text", encrypted)
                    put("signature", signature)
                    put("id", id)
                    put("protocol_version", ProtocolVersion.LEGACY_VERSION)
                }).toString())
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendEncrypted error: ${e.message}")
        }
    }

    fun sendVoice(to: String, voiceBase64: String, voiceId: String, duration: Int) {
        scope.launch(Dispatchers.IO) {
            try {
                val cachedKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also { publicKeys[to] = it }
                if (cachedKey == null) {
                    Log.w(TAG, "sendVoice: нет ключа $to — запрашиваем")
                    requestPrekeyBundle(to)
                    pendingSessionMessages.getOrPut(to) { mutableListOf() }
                        .add("__voice__|${voiceId}|${duration}|$voiceBase64" to voiceId)
                    return@launch
                }
                val encrypted = CryptoManager.encrypt(voiceBase64, cachedKey)
                val signature = CryptoManager.sign(encrypted)
                sendWs(JSONObject().apply {
                    put("type", "voice")
                    put("from", username)
                    put("to", to)
                    put("voice_id", voiceId)
                    put("voice_data", encrypted)
                    put("signature", signature)
                    put("duration", duration)
                }.toString())
            } catch (e: Exception) {
                Log.e(TAG, "sendVoice error: ${e.message}")
            }
        }
    }

    fun sendTyping(to: String) {
        if (!isConnected) return
        val packet = JSONObject().apply {
            put("type", "typing")
            put("from", username)
            put("to", to)
        }
        sendAnonOrDirect(to, packet)
    }

    fun sendRead(to: String, messageId: String) {
        val packet = JSONObject().apply {
            put("type", "read")
            put("from", username)
            put("to", to)
            put("id", messageId)
        }
        sendAnonOrDirect(to, packet)
    }

    private fun sendAnonOrDirect(to: String, packet: JSONObject) {
        val token = AnonTokenManager.consumeNextContactToken(this, to)
        if (token != null) {
            val anonPacket = JSONObject().apply {
                put("type", "anon_message")
                put("token", token)
                put("payload", packet)
            }
            sendWs(addPadding(anonPacket).toString())
        } else {
            sendWs(packet.toString())
        }
    }

    fun sendReaction(to: String, messageId: String, emoji: String) {
        scope.launch(Dispatchers.IO) {
            try {
                val cachedKey = publicKeys[to] ?: return@launch
                val encrypted = CryptoManager.encrypt(emoji, cachedKey)
                val signature = CryptoManager.sign(encrypted)
                sendAnonOrDirect(to, JSONObject().apply {
                    put("type", "reaction")
                    put("from", username)
                    put("to", to)
                    put("message_id", messageId)
                    put("emoji", encrypted)
                    put("signature", signature)
                })
            } catch (e: Exception) {
                Log.e(TAG, "sendReaction error: ${e.message}")
            }
        }
    }

    fun sendEdit(to: String, messageId: String, newText: String) {
        if (!isConnected) return
        val cachedKey = publicKeys[to] ?: return
        scope.launch(Dispatchers.IO) {
            try {
                val encrypted = CryptoManager.encrypt(newText, cachedKey)
                val signature = CryptoManager.sign(encrypted)
                sendAnonOrDirect(to, JSONObject().apply {
                    put("type", "edit")
                    put("from", username)
                    put("to", to)
                    put("id", messageId)
                    put("text", encrypted)
                    put("signature", signature)
                })
            } catch (e: Exception) {
                Log.e(TAG, "sendEdit error: ${e.message}")
            }
        }
    }

    // Сбросить счётчик уведомлений для чата (при открытии чата)
    fun clearNotifLines(key: String) {
        notifLines.remove(key)
    }

    // Удалить сообщение у всех
    fun sendDeleteMessage(to: String, messageId: String) {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            sendAnonOrDirect(to, JSONObject().apply {
                put("type", "message_delete")
                put("from", username)
                put("to", to)
                put("message_id", messageId)
            })
        }
    }

    // Удалить сообщение в группе у всех участников
    fun sendGroupDeleteMessage(groupId: String, messageId: String, members: List<String>) {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            members.filter { it != username }.forEach { memberId ->
                sendWs(JSONObject().apply {
                    put("type", "group_message_delete")
                    put("from", username)
                    put("to", memberId)
                    put("group_id", groupId)
                    put("message_id", messageId)
                }.toString())
            }
        }
    }

    // Отправить настройку таймера исчезающих сообщений (0 = выкл)
    fun sendDisappearTimer(to: String, seconds: Long) {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            sendAnonOrDirect(to, JSONObject().apply {
                put("type", "disappear_timer")
                put("from", username)
                put("to", to)
                put("seconds", seconds)
            })
        }
    }

    fun sendImage(to: String, chunks: List<String>) {
        if (!isConnected) return

        val imageId = UUID.randomUUID().toString()

        val cachedKey = publicKeys[to]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also {
                publicKeys[to] = it
            }

        if (cachedKey == null) {
            Log.w(TAG, "sendImage: нет ключа для $to")
            return
        }

        val ackChannel = kotlinx.coroutines.channels.Channel<Int>(capacity = 1)
        imageChunkAcks[imageId] = ackChannel

        scope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Отправка изображения (${chunks.size} чанков)")

                // Объединяем Base64 чанки в байты
                val base64Data = chunks.joinToString("")
                val imageBytes = android.util.Base64.decode(base64Data, android.util.Base64.DEFAULT)

                // Шифруем изображение целиком
                val encryptedFileData = CryptoManager.encryptFile(imageBytes, cachedKey)
                val packedData = CryptoManager.packEncryptedFile(encryptedFileData)

                // Разбиваем на крупные чанки — меньше RTT-задержек
                val encryptedChunks = packedData.chunked(120_000)

                Log.d(TAG, "Изображение зашифровано: ${encryptedChunks.size} чанков")

                val batchSize = 5
                encryptedChunks.chunked(batchSize).forEachIndexed { batchIdx, batch ->
                    if (cancelledTransfers.contains(imageId)) return@forEachIndexed
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * batchSize + relIdx
                        val signature = CryptoManager.signChunk(chunk, imageId, index)
                        sendAnonOrDirect(to, JSONObject().apply {
                            put("type", "image_chunk")
                            put("from", username)
                            put("to", to)
                            put("image_id", imageId)
                            put("chunk_index", index)
                            put("total_chunks", encryptedChunks.size)
                            put("data", chunk)
                            put("signature", signature)
                            put("encrypted", true)
                        })
                    }
                    delay(30)
                }

                Log.d(TAG, "✅ Изображение отправлено")

            } catch (e: Exception) {
                Log.e(TAG, "sendImage error: ${e.message}", e)
            } finally {
                imageChunkAcks.remove(imageId)
                cancelledTransfers.remove(imageId)
                ackChannel.close()
            }
        }
    }

    // ─── Отправка зашифрованного файла ────────────────────────────────────────

    fun sendFile(to: String, fileName: String, chunks: List<String>, fileId: String) {
        if (!isConnected) {
            Log.w(TAG, "sendFile: не подключены к серверу")
            return
        }

        val cachedKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also {
            publicKeys[to] = it
        }

        if (cachedKey == null) {
            Log.w(TAG, "sendFile: нет ключа для $to — запрашиваем")
            requestPrekeyBundle(to)
            return
        }

        val ackChannel = kotlinx.coroutines.channels.Channel<Int>(capacity = 1)
        fileChunkAcks[fileId] = ackChannel

        scope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Отправка файла: $fileName (${chunks.size} чанков base64)")

                val base64Data = chunks.joinToString("")
                val fileBytes = android.util.Base64.decode(base64Data, android.util.Base64.DEFAULT)

                Log.d(TAG, "Файл декодирован: ${fileBytes.size} байт")

                val encryptedFileData = CryptoManager.encryptFile(fileBytes, cachedKey)
                val packedData = CryptoManager.packEncryptedFile(encryptedFileData)

                Log.d(TAG, "Файл зашифрован: ${packedData.length} символов base64")

                val encryptedChunks = packedData.chunked(120_000)

                Log.d(TAG, "Разбито на ${encryptedChunks.size} зашифрованных чанков")

                val batchSize = 5
                encryptedChunks.chunked(batchSize).forEachIndexed { batchIdx, batch ->
                    if (cancelledTransfers.contains(fileId)) {
                        Log.w(TAG, "Передача файла $fileId отменена")
                        return@forEachIndexed
                    }
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * batchSize + relIdx
                        val signature = CryptoManager.signChunk(chunk, fileId, index)
                        sendAnonOrDirect(to, JSONObject().apply {
                            put("type", "file_chunk")
                            put("from", username)
                            put("to", to)
                            put("file_id", fileId)
                            put("file_name", fileName)
                            put("chunk_index", index)
                            put("total_chunks", encryptedChunks.size)
                            put("data", chunk)
                            put("signature", signature)
                            put("encrypted", true)
                        })
                    }
                    delay(30)
                }

                Log.d(TAG, "✅ Файл $fileName успешно отправлен")

            } catch (e: Exception) {
                Log.e(TAG, "❌ Ошибка отправки файла: ${e.message}", e)
            } finally {
                fileChunkAcks.remove(fileId)
                cancelledTransfers.remove(fileId)
                ackChannel.close()
            }
        }
    }

    // ─── Отправка видеокружка ─────────────────────────────────────────────────

    /**
     * Отправляет видеокружок.
     * [videoBytes] — НЕЗАШИФРОВАННЫЕ байты MP4.
     * [encFilePath] — путь к локальному .enc файлу (для офлайн-очереди); "" = не ставить в очередь.
     * Шифрование для получателя выполняется здесь (CryptoManager.encryptFile).
     * Локальное хранение (SecureFileStorage) выполняется в ChatScreen отдельно.
     */
    fun sendVideoCircle(to: String, videoId: String, videoBytes: ByteArray, duration: Int, encFilePath: String = "") {
        if (!isConnected) {
            if (encFilePath.isNotEmpty()) {
                synchronized(pendingVideoCircles) {
                    pendingVideoCircles.add(PendingVideoCircle(to, videoId, encFilePath, duration))
                }
                Log.w(TAG, "sendVideoCircle: офлайн — $videoId поставлен в очередь")
            } else {
                Log.w(TAG, "sendVideoCircle: офлайн, нет encFilePath — $videoId потерян")
            }
            return
        }

        val cachedKey = publicKeys[to]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also {
                publicKeys[to] = it
            }

        if (cachedKey == null) {
            if (encFilePath.isNotEmpty()) {
                synchronized(pendingVideoCircles) {
                    pendingVideoCircles.add(PendingVideoCircle(to, videoId, encFilePath, duration))
                }
            }
            Log.w(TAG, "sendVideoCircle: нет ключа для $to — запрашиваем, $videoId в очереди")
            requestPrekeyBundle(to)
            return
        }

        val ackChannel = kotlinx.coroutines.channels.Channel<Int>(capacity = 1)
        videoChunkAcks[videoId] = ackChannel

        scope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Отправка видеокружка: $videoId, duration=$duration, size=${videoBytes.size}")
                val encryptedFileData = CryptoManager.encryptFile(videoBytes, cachedKey)
                val packedData = CryptoManager.packEncryptedFile(encryptedFileData)
                // Крупные чанки → меньше кусков → меньше RTT-задержек
                val encryptedChunks = packedData.chunked(120_000)

                Log.d(TAG, "Видеокружок зашифрован: ${encryptedChunks.size} чанков")

                // Отправляем пачками по 5 без ожидания ACK на каждый чанк.
                // TCP flow control сам регулирует скорость; сервер собирает по chunk_index.
                val batchSize = 5
                encryptedChunks.chunked(batchSize).forEachIndexed { batchIdx, batch ->
                    if (cancelledTransfers.contains(videoId)) return@forEachIndexed
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * batchSize + relIdx
                        val signature = CryptoManager.signChunk(chunk, videoId, index)
                        sendAnonOrDirect(to, JSONObject().apply {
                            put("type", "video_chunk")
                            put("from", username)
                            put("to", to)
                            put("video_id", videoId)
                            put("chunk_index", index)
                            put("total_chunks", encryptedChunks.size)
                            put("data", chunk)
                            put("signature", signature)
                            put("duration", duration)
                            put("encrypted", true)
                        })
                    }
                    delay(30) // небольшая пауза между пачками чтобы не перегружать сокет
                }

                Log.d(TAG, "✅ Видеокружок $videoId отправлен: ${encryptedChunks.size} чанков")

            } catch (e: Exception) {
                Log.e(TAG, "sendVideoCircle error: ${e.message}", e)
            } finally {
                videoChunkAcks.remove(videoId)
                cancelledTransfers.remove(videoId)
                ackChannel.close()
            }
        }
    }

    // ─── Флаш офлайн-очереди видеокружков ────────────────────────────────────
    /**
     * Отправляет накопленные в очереди видеокружки.
     * [forContact] — если задан, флашит только для этого контакта (после получения prekey bundle).
     * null — флашит всё (при reconnect).
     */
    private fun flushPendingVideoCircles(forContact: String? = null) {
        val toFlush = synchronized(pendingVideoCircles) {
            if (forContact != null) {
                val filtered = pendingVideoCircles.filter { it.to == forContact }
                pendingVideoCircles.removeAll { it.to == forContact }
                filtered
            } else {
                val all = pendingVideoCircles.toList()
                pendingVideoCircles.clear()
                all
            }
        }
        if (toFlush.isEmpty()) return
        Log.d(TAG, "flushPendingVideoCircles: отправляем ${toFlush.size} видеокружков (contact=$forContact)")
        scope.launch(Dispatchers.IO) {
            toFlush.forEach { pending ->
                try {
                    val file = File(pending.encFilePath)
                    if (!file.exists()) {
                        Log.w(TAG, "flushPendingVideoCircles: файл не найден — ${pending.encFilePath}")
                        return@forEach
                    }
                    val plainBytes = SecureFileStorage.read(this@MessengerService, file)
                    // encFilePath = "" чтобы не зациклиться при повторном фейле
                    sendVideoCircle(pending.to, pending.videoId, plainBytes, pending.duration)
                } catch (e: Exception) {
                    Log.e(TAG, "flushPendingVideoCircles error: ${e.message}")
                }
            }
        }
    }

// ─── Обработка входящих зашифрованных файлов ──────────────────────────────
    fun flushPendingReactions() {
        val iterator = pendingReactions.iterator()
        while (iterator.hasNext()) {
            val (from, messageId, emoji) = iterator.next()
            onReactionReceived?.invoke(from, messageId, emoji)
            iterator.remove()
        }
    }

    // ─── Вспомогательные ─────────────────────────────────────────────────────

    private fun publishPrekeyBundle() {
        scope.launch(Dispatchers.IO) {
            try {
                val bundle = SessionKeyManager.getLocalPrekeyBundle()
                sendWs(JSONObject().apply {
                    put("type", "publish_prekey_bundle")
                    put("bundle", SessionKeyManager.prekeyBundleToJson(bundle))
                }.toString())
            } catch (e: Exception) {
                Log.e(TAG, "publishPrekeyBundle error: ${e.message}")
            }
        }
    }

    private fun requestPrekeyBundle(contactId: String) {
        scope.launch(Dispatchers.IO) {
            sendWs(JSONObject().apply {
                put("type", "get_prekey_bundle")
                put("target", contactId)
            }.toString())
        }
    }

    private suspend fun sendAnonTokensTo(contact: String) {
        val tokens = AnonTokenManager.tokensToShareWith(this@MessengerService)
        if (tokens.isEmpty()) return
        // Токены отправляем ТОЛЬКО через анонимный маршрут (одноразовый токен контакта).
        // Прямая fingerprint-отправка раскрывает граф связей — не делаем это никогда.
        val anonToken = AnonTokenManager.consumeNextContactToken(this@MessengerService, contact)
        if (anonToken == null) {
            Log.d(TAG, "sendAnonTokensTo: нет токенов для $contact, ждём mailbox-обмена")
            return
        }
        val systemText = "__beacon_tokens__:${org.json.JSONArray(tokens)}"
        val recipientKey = publicKeys[contact]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, contact)?.also { publicKeys[contact] = it }
        if (recipientKey == null) {
            Log.w(TAG, "sendAnonTokensTo: нет ключа для $contact")
            return
        }
        val encrypted = CryptoManager.encrypt(systemText, recipientKey)
        val signature = CryptoManager.sign(encrypted)
        val payload = JSONObject().apply {
            put("type", "message")
            put("from", username)
            put("to", contact)
            put("text", encrypted)
            put("signature", signature)
            put("id", UUID.randomUUID().toString())
            put("protocol_version", 1)
        }
        val anonPacket = JSONObject().apply {
            put("type", "anon_message")
            put("token", anonToken)
            put("payload", payload)
        }
        sendWs(addPadding(anonPacket).toString())
        // Обновляем подписку на сервере с актуальным пулом токенов
        val allMyTokens = AnonTokenManager.ensureMyTokenPool(this@MessengerService)
        sendWs(JSONObject().apply {
            put("type", "subscribe_tokens")
            put("tokens", org.json.JSONArray(allMyTokens))
        }.toString())
        Log.d(TAG, "Отправлены анонимные токены → $contact через anon_message")
    }

    private suspend fun handleIncomingDecryptedMessage(from: String, decryptedText: String, messageId: String?, json: JSONObject) {
        if (decryptedText.startsWith("__beacon_tokens__:")) {
            try {
                val arr = org.json.JSONArray(decryptedText.removePrefix("__beacon_tokens__:"))
                val tokens = (0 until arr.length()).map { arr.getString(it) }
                AnonTokenManager.addContactTokens(this@MessengerService, from, tokens)
                // Токены получены — mailbox больше не нужен для этого контакта
                AnonTokenManager.clearContactMailboxTag(this@MessengerService, from)
                ChatStorage.addContact(this@MessengerService, from)
                Log.d(TAG, "Получены анонимные токены от $from: ${tokens.size} шт.")
                if (tokensSentThisSession.add(from)) {
                    scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка обработки beacon_tokens: ${e.message}")
            }
            return
        }

        val senderName = ChatStorage.getContactName(this@MessengerService, from)
            .takeIf { it.isNotBlank() }
            ?: json.optString("name", "").takeIf { it.isNotBlank() }
            ?: from
        if (messageId != null) {
            receivedMessageIds[messageId] = System.currentTimeMillis()
        }
        if (senderName.isNotBlank()) ChatStorage.saveContactName(this@MessengerService, from, senderName)
        ChatStorage.saveOrUpdateMessage(
            this@MessengerService,
            UserStorage.getUserId(this@MessengerService),
            from,
            ChatStorage.StoredMessage(id = messageId ?: UUID.randomUUID().toString(), text = decryptedText, isOwn = false)
        )
        ChatStorage.addContact(this@MessengerService, from)
        // Notify sender that the message reached this device
        if (messageId != null) {
            sendAnonOrDirect(from, JSONObject().apply {
                put("type", "delivered")
                put("to",   from)
                put("id",   messageId)
            })
        }
        withContext(Dispatchers.Main) {
            val callback = onMessageReceived
            if (callback != null) callback.invoke(from, decryptedText)
            else showMessageNotification(from, decryptedText)
            MainActivity.chatListVersion.value = System.currentTimeMillis()
        }
    }

    private suspend fun flushQueue() {
        val queue = MessageQueue.load(this)
        if (queue.isEmpty()) return
        queue.forEach { queued ->
            val cachedKey = publicKeys[queued.to]
                ?: ChatStorage.getContactPublicKey(this@MessengerService, queued.to)
                    ?.also { publicKeys[queued.to] = it }
            if (cachedKey != null) sendEncrypted(queued.to, queued.text, cachedKey, queued.id)
            else {
                pendingMessages.getOrPut(queued.to) { mutableListOf() }.add(Pair(queued.to, queued.text))
                sendWs(JSONObject().apply { put("type", "get_key"); put("target", queued.to) }.toString())
            }
        }
    }

    // ─── Anonymous Mailbox ────────────────────────────────────────────────────

    /** Опрашивает сервер: мои настоящие теги + MBOX_FAKE_COUNT фейковых (сервер не знает какой настоящий). */
    private fun pollMailbox() {
        val tags = AnonTokenManager.buildFetchTagList(this)
        if (tags.isEmpty()) return
        val realCount = AnonTokenManager.getMyMailboxTags(this).size
        Log.d(TAG, "pollMailbox: ${tags.size} тегов ($realCount реальных)")
        scope.launch(Dispatchers.IO) {
            sendWs(JSONObject().apply {
                put("type", "mailbox_fetch")
                put("tags", org.json.JSONArray(tags))
            }.toString())
        }
    }

    /**
     * Отправляет первое сообщение контакту через mailbox вместо fingerprint-маршрутизации.
     * Шифруем {from, text, tokens} публичным ключом получателя, кладём по его mailboxTag.
     * Сервер не знает кто отправитель и кто получатель.
     */
    fun sendViaMailbox(to: String, text: String, publicKey: String, mailboxTag: String, messageId: String? = null) {
        val id = messageId ?: java.util.UUID.randomUUID().toString()
        MessageQueue.remove(this, id)
        scope.launch(Dispatchers.IO) {
            try {
                // Внутри блоба: from (fingerprint), text, наши токены — всё шифруется ключом получателя
                val myTokens = AnonTokenManager.tokensToShareWith(this@MessengerService)
                val inner = JSONObject().apply {
                    put("from", username)
                    put("text", text)
                    put("tokens", org.json.JSONArray(myTokens))
                    put("id", id)
                }.toString()
                val blob = CryptoManager.encrypt(inner, publicKey)
                sendWs(addPadding(JSONObject().apply {
                    put("type", "mailbox_put")
                    put("tag", mailboxTag)
                    put("blob", blob)
                }).toString())
            } catch (e: Exception) {
                Log.e(TAG, "sendViaMailbox error: ${e.message}")
            }
        }
    }

    /** Обрабатывает ответ сервера на mailbox_fetch. */
    private suspend fun handleMailboxResult(json: org.json.JSONObject) {
        val blobsMap = json.optJSONObject("blobs") ?: return
        blobsMap.keys().forEach { tag ->
            val arr = blobsMap.optJSONArray(tag) ?: return@forEach
            for (i in 0 until arr.length()) {
                val blob = arr.optString(i) ?: continue
                try {
                    val inner = CryptoManager.decrypt(blob)
                    val innerJson = org.json.JSONObject(inner)
                    val from = innerJson.getString("from")
                    val text = innerJson.getString("text")
                    val msgId = innerJson.optString("id")
                    val tokensArr = innerJson.optJSONArray("tokens")
                    if (tokensArr != null) {
                        val tokens = (0 until tokensArr.length()).map { tokensArr.getString(it) }
                        AnonTokenManager.addContactTokens(this@MessengerService, from, tokens)
                        if (tokensSentThisSession.add(from)) {
                            scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
                        }
                    }
                    // Убираем этот тег из опроса — сообщение получено
                    AnonTokenManager.removeMyMailboxTag(this@MessengerService, tag)
                    // Сохраняем сообщение и добавляем контакт
                    ChatStorage.addContact(this@MessengerService, from)
                    if (!text.startsWith("__beacon_")) {
                        val storedId = msgId.ifEmpty { java.util.UUID.randomUUID().toString() }
                        ChatStorage.saveOrUpdateMessage(
                            this@MessengerService,
                            UserStorage.getUserId(this@MessengerService),
                            from,
                            ChatStorage.StoredMessage(id = storedId, text = text, isOwn = false)
                        )
                        withContext(Dispatchers.Main) { onMessageReceived?.invoke(from, text) }
                    }
                } catch (e: Exception) {
                    // Блоб не для нас — тихо пропускаем
                }
            }
        }
    }

    fun isOnline() = isConnected

    // ─── Уведомления ─────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.deleteNotificationChannel(CHANNEL_ID)
            val channel = NotificationChannel(CHANNEL_ID, "B-CON Emergency", NotificationManager.IMPORTANCE_HIGH).apply {
                description = s.notifChannelDesc
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setShowBadge(true)
                enableVibration(true)
                enableLights(true)
            }
            nm.createNotificationChannel(channel)

            // Тихий канал для foreground-уведомления сервиса (без звука и вибрации)
            val serviceChannel = NotificationChannel(
                CHANNEL_ID_SERVICE,
                "B-CON Service",
                NotificationManager.IMPORTANCE_MIN
            ).apply {
                description = "Фоновый сервис B-CON"
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
                setShowBadge(false)
            }
            nm.createNotificationChannel(serviceChannel)
        }
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pending = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ID_SERVICE)
            .setContentTitle("💬 B-CON Messenger")
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pending)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
    }

    private fun showSessionConflictNotification() {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pending = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(s.notifSessionTitle)
            .setContentText(s.notifSessionText)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentIntent(pending)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(998, notification)
    }

    private fun showMessageNotification(from: String, text: String) {
        val fromName = ChatStorage.getContactName(this, from)
        val hideContent = UserStorage.getHideNotificationContent(this)
        val notifId = (from.hashCode() and 0x7FFFFFFF) + 1000  // +1000 чтобы не пересекаться с NOTIFICATION_ID

        // Накапливаем строки для InboxStyle (только если контент не скрыт)
        if (!hideContent) {
            val lines = notifLines.getOrPut("dm_$from") { mutableListOf() }
            lines.add(text)
            if (lines.size > 5) lines.removeAt(0)
        }

        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra("open_chat", from)
            putExtra("chat_type", "chat")
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pending = PendingIntent.getActivity(
            this,
            notifId,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(if (hideContent) s.notifNewMessage else "💬 $fromName")
            .setContentText(if (hideContent) s.notifTapToRead else text)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .setVisibility(if (hideContent) NotificationCompat.VISIBILITY_PRIVATE else NotificationCompat.VISIBILITY_PUBLIC)
            .setGroup("beacon_dm_$from")

        // InboxStyle — показываем все накопленные сообщения если их больше 1
        if (!hideContent) {
            val lines = notifLines["dm_$from"] ?: mutableListOf()
            if (lines.size > 1) {
                val style = NotificationCompat.InboxStyle()
                    .setBigContentTitle("💬 $fromName")
                    .setSummaryText(s.notifMessageCount(lines.size))
                lines.forEach { style.addLine(it) }
                builder.setStyle(style).setNumber(lines.size)
            }
        }

        getSystemService(NotificationManager::class.java).notify(notifId, builder.build())
    }

    private fun showChannelPostNotification(channelId: String, channelName: String, text: String) {
        if (ChannelManager.getChannel(this, channelId)?.isMuted == true) return
        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra("open_channel", channelId)
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pending = PendingIntent.getActivity(
            this,
            channelId.hashCode() and 0x7FFFFFFF,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("📢 $channelName")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .build()
        getSystemService(NotificationManager::class.java).notify(System.currentTimeMillis().toInt(), notification)
    }

    private fun showGroupMessageNotification(groupId: String, senderName: String, text: String) {
        val hideContent = UserStorage.getHideNotificationContent(this)
        val group = GroupManager.getGroup(this, groupId)
        val groupName = group?.name ?: s.notifGroupFallback
        val notifId = (groupId.hashCode() and 0x7FFFFFFF) + 2000  // +2000 чтобы не пересекаться

        // Накапливаем строки для InboxStyle
        if (!hideContent) {
            val lines = notifLines.getOrPut("group_$groupId") { mutableListOf() }
            lines.add("$senderName: $text")
            if (lines.size > 5) lines.removeAt(0)
        }

        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra("open_chat", groupId)
            putExtra("chat_type", "group_chat")
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pending = PendingIntent.getActivity(
            this,
            notifId,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(if (hideContent) s.notifNewGroupMessage else "👥 $groupName")
            .setContentText(if (hideContent) s.notifTapToRead else "$senderName: $text")
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .setVisibility(if (hideContent) NotificationCompat.VISIBILITY_PRIVATE else NotificationCompat.VISIBILITY_PUBLIC)
            .setGroup("beacon_group_$groupId")

        // InboxStyle — показываем участников и их сообщения
        if (!hideContent) {
            val lines = notifLines["group_$groupId"] ?: mutableListOf()
            if (lines.size > 1) {
                val style = NotificationCompat.InboxStyle()
                    .setBigContentTitle("👥 $groupName")
                    .setSummaryText(s.notifMessageCount(lines.size))
                lines.forEach { style.addLine(it) }
                builder.setStyle(style).setNumber(lines.size)
            }
        }

        getSystemService(NotificationManager::class.java).notify(notifId, builder.build())
    }

    private fun showMissedCallNotification(from: String, displayName: String, isVideo: Boolean) {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("open_chat", from)
        }
        val pending = PendingIntent.getActivity(
            this, ("missed_$from").hashCode(),
            intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val icon  = if (isVideo) "📹" else "📞"
        val label = if (isVideo) s.notifMissedVideoCall else s.notifMissedCall
        val notifId = (from.hashCode() and 0x7FFFFFFF) + 3000
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("$icon $label")
            .setContentText(s.notifFromCaller(displayName))
            .setSmallIcon(android.R.drawable.ic_menu_call)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MISSED_CALL)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        getSystemService(NotificationManager::class.java).notify(notifId, notification)
    }

    private fun createNotification(): Notification {
        val emergencyIntent = Intent("com.bcon.messenger.EMERGENCY_WIPE").apply { setPackage(packageName) }
        val emergencyPending = PendingIntent.getBroadcast(this, 999, emergencyIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val fullScreenIntent = Intent(this, MainActivity::class.java)
        val fullScreenPending = PendingIntent.getActivity(this, 0, fullScreenIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("B-CON")
            .setContentText(s.notifEmergencyText)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setOngoing(true)
            .setFullScreenIntent(fullScreenPending, true)
            .addAction(android.R.drawable.ic_delete, s.notifEmergencyAction, emergencyPending)
            .build()
    }
    // ─── Групповые чаты ───────────────────────────────────────────────────────

    /**
     * Создать группу и отправить приглашения
     */
    fun createGroup(
        groupId: String,
        groupName: String,
        groupAvatar: String,
        members: List<String>,
        groupKey: ByteArray
    ) {
        if (!isConnected) {
            Log.w(TAG, "createGroup: не подключены к серверу")
            return
        }

        scope.launch(Dispatchers.IO) {
            try {
                members.forEach { memberId ->
                    val memberPublicKey = publicKeys[memberId]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, memberId)?.also {
                            publicKeys[memberId] = it
                        }

                    if (memberPublicKey != null) {
                        // Шифруем групповой ключ для каждого участника
                        val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, memberPublicKey)
                        val signature = CryptoManager.sign(encryptedGroupKey)

                        // Отправляем приглашение
                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_create")
                            put("from", username)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("group_name", groupName)
                            put("group_avatar", groupAvatar)
                            put("encrypted_group_key", encryptedGroupKey)
                            put("signature", signature)
                        })

                        Log.d(TAG, "Приглашение в группу $groupName отправлено для $memberId")
                    } else {
                        Log.w(TAG, "Нет публичного ключа для $memberId")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "createGroup error: ${e.message}", e)
            }
        }
    }

    /**
     * Отправить сообщение в группу
     */
    fun sendGroupMessage(
        groupId: String,
        messageId: String,
        encryptedText: String,
        members: List<String>
    ) {
        if (!isConnected) {
            Log.w(TAG, "sendGroupMessage: не подключены к серверу")
            return
        }

        scope.launch(Dispatchers.IO) {
            try {
                val signature = CryptoManager.sign(encryptedText)
                val senderName = UserStorage.getUsername(this@MessengerService)

                // Отправляем сообщение всем участникам группы
                members.filter { it != username }.forEach { memberId ->
                    sendAnonOrDirect(memberId, JSONObject().apply {
                        put("type", "group_message")
                        put("from", username)
                        put("to", memberId)
                        put("group_id", groupId)
                        put("message_id", messageId)
                        put("sender_name", senderName)
                        put("text", encryptedText)
                        put("signature", signature)
                    })
                }

                Log.d(TAG, "Групповое сообщение отправлено (группа: $groupId)")
            } catch (e: Exception) {
                Log.e(TAG, "sendGroupMessage error: ${e.message}", e)
            }
        }
    }

    /**
     * Отправить реакцию на сообщение в группе всем участникам
     */
    fun sendGroupReaction(
        groupId: String,
        messageId: String,
        emoji: String,
        members: List<String>
    ) {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            try {
                val signature = CryptoManager.sign(emoji)
                members.filter { it != username }.forEach { memberId ->
                    sendAnonOrDirect(memberId, JSONObject().apply {
                        put("type", "group_reaction")
                        put("from", username)
                        put("to", memberId)
                        put("group_id", groupId)
                        put("message_id", messageId)
                        put("emoji", emoji)
                        put("signature", signature)
                    })
                }
            } catch (e: Exception) {
                Log.e(TAG, "sendGroupReaction error: ${e.message}")
            }
        }
    }

    /**
     * Добавить участника в группу
     */
    fun addGroupMember(
        groupId: String,
        groupName: String,
        groupAvatar: String,
        newMemberId: String,
        groupKey: ByteArray
    ) {
        if (!isConnected) {
            Log.w(TAG, "addGroupMember: не подключены к серверу")
            return
        }

        scope.launch(Dispatchers.IO) {
            try {
                val memberPublicKey = publicKeys[newMemberId]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, newMemberId)?.also {
                        publicKeys[newMemberId] = it
                    }

                if (memberPublicKey != null) {
                    val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, memberPublicKey)
                    val signature = CryptoManager.sign(encryptedGroupKey)

                    sendAnonOrDirect(newMemberId, JSONObject().apply {
                        put("type", "group_create")
                        put("from", username)
                        put("to", newMemberId)
                        put("group_id", groupId)
                        put("group_name", groupName)
                        put("group_avatar", groupAvatar)
                        put("encrypted_group_key", encryptedGroupKey)
                        put("signature", signature)
                    })

                    Log.d(TAG, "Участник $newMemberId добавлен в группу $groupName")
                }
            } catch (e: Exception) {
                Log.e(TAG, "addGroupMember error: ${e.message}", e)
            }
        }
    }

    /**
     * Уведомить об удалении участника
     */
    fun notifyMemberRemoved(groupId: String, removedMemberId: String, members: List<String>) {
        if (!isConnected) return

        scope.launch(Dispatchers.IO) {
            try {
                val removeSignature = CryptoManager.sign("$groupId:$removedMemberId")
                members.filter { it != username && it != removedMemberId }.forEach { memberId ->
                    sendAnonOrDirect(memberId, JSONObject().apply {
                        put("type", "group_member_removed")
                        put("from", username)
                        put("to", memberId)
                        put("group_id", groupId)
                        put("removed_member", removedMemberId)
                        put("signature", removeSignature)
                    })
                }
            } catch (e: Exception) {
                Log.e(TAG, "notifyMemberRemoved error: ${e.message}", e)
            }
        }
    }

    /**
     * Ротация группового ключа (при удалении участника)
     */
    fun rotateGroupKey(
        groupId: String,
        newGroupKey: ByteArray,
        members: List<String>
    ) {
        if (!isConnected) return

        scope.launch(Dispatchers.IO) {
            try {
                members.filter { it != username }.forEach { memberId ->
                    val memberPublicKey = publicKeys[memberId]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, memberId)?.also {
                            publicKeys[memberId] = it
                        }

                    if (memberPublicKey != null) {
                        val encryptedNewKey = GroupManager.encryptGroupKeyForMember(newGroupKey, memberPublicKey)
                        val signature = CryptoManager.sign(encryptedNewKey)

                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_key_rotation")
                            put("from", username)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("encrypted_new_key", encryptedNewKey)
                            put("signature", signature)
                        })
                    }
                }

                Log.d(TAG, "Групповой ключ ротирован для группы $groupId")
            } catch (e: Exception) {
                Log.e(TAG, "rotateGroupKey error: ${e.message}", e)
            }
            /**
             * Уведомление о приглашении в группу
             */
            fun showGroupInviteNotification(groupName: String, inviterUserId: String) {
                val inviterName = ChatStorage.getContactName(this@MessengerService, inviterUserId)
                val intent = Intent(this@MessengerService, MainActivity::class.java)
                val pending = PendingIntent.getActivity(
                    this@MessengerService,
                    0,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE
                )

                val notification = NotificationCompat.Builder(this@MessengerService, CHANNEL_ID)
                    .setContentTitle("👥 Приглашение в группу")
                    .setContentText("$inviterName добавил(а) вас в \"$groupName\"")
                    .setSmallIcon(android.R.drawable.ic_dialog_email)
                    .setContentIntent(pending)
                    .setAutoCancel(true)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setDefaults(NotificationCompat.DEFAULT_ALL)
                    .build()

                getSystemService(NotificationManager::class.java)
                    .notify(System.currentTimeMillis().toInt(), notification)
            }
        }
    }
}
