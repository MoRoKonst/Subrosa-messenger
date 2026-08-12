package com.subrosa.messenger

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
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

class MessengerService : Service() {

    data class FileMeta(val name: String, val total: Int, val chunks: MutableList<Pair<Int, String>>)

    /** Strips path-traversal / directory characters from a peer-supplied
     *  file_id or file_name before it's used to build a filesystem path —
     *  these values come straight from another contact's JSON and must not
     *  be trusted to stay inside `files/$fileId/`. */
    private fun sanitizePathComponent(raw: String): String {
        val cleaned = raw.replace(Regex("[^A-Za-z0-9._-]"), "_").replace("..", "_")
        return cleaned.ifBlank { "file" }
    }

    companion object {
        const val CHANNEL_ID = "messenger_channel"

        const val CHANNEL_ID_SERVICE = "messenger_service_silent"
        const val NOTIFICATION_ID = 1
        private const val TAG = "MessengerService"

        @Volatile var connected: Boolean = false

        val connectionState = MutableStateFlow(false)
    }

    inner class LocalBinder : Binder() {
        fun getService() = this@MessengerService
    }

    private val binder = LocalBinder()

    private val s: AppStrings get() = if (UserStorage.getLanguage(this) == "en") enStrings else ruStrings

    private var handshakeComplete = false
    private var webSocket: WebSocket? = null

    private val wsClient: OkHttpClient by lazy {
        buildOkHttpClient(useTor = false)
    }

    private val wsTorClient: OkHttpClient by lazy {
        buildOkHttpClient(useTor = true)
    }

    private fun buildOkHttpClient(useTor: Boolean): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .pingInterval(0, TimeUnit.SECONDS)
            .connectTimeout(if (useTor) 60 else 15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
        if (useTor) {

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

    private fun activeWsClient(): OkHttpClient {
        if (!TorManager.isConnected) return wsClient

        val socksAvailable = try {
            val s = java.net.Socket()
            s.connect(java.net.InetSocketAddress(TorManager.SOCKS_HOST, TorManager.SOCKS_PORT), 1000)
            s.close(); true
        } catch (e: Exception) { false }
        return if (socksAvailable) {

            wsTorClient
        } else {

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
    private var failuresOnCurrentServer = 0
    private val MAX_FAILURES_BEFORE_SWITCH = 3
    private var totpRequiredNotified = false
    @Volatile private var pendingRecoveryCode: String? = null
    private var username = ""

    private val publicKeys = mutableMapOf<String, String>()
    // Peer ML-KEM public keys, sourced from prekey bundles — required to
    // hybridize the legacy ephemeral-ECDH path (encrypt/decrypt, voice, group
    // key distribution) against harvest-now-decrypt-later, same as X3DH.
    private val publicKeysPq = mutableMapOf<String, ByteArray>()
    // Was a mutableSetOf<String> ("sent once ever this process lifetime, never
    // again") — found live: a burst of usage (a video call's signaling traffic,
    // several video circles) can drain a contact's token allocation well
    // within a single service lifetime, but the one-time gate meant the
    // contact never got proactively resupplied, permanently stuck until an
    // app/service restart happened to reset it. A cooldown lets it refill
    // again once the previous grant has had time to actually be used up.
    private val tokensSentThisSession = mutableMapOf<String, Long>()
    private val TOKEN_RESUPPLY_COOLDOWN_MS = 3 * 60_000L

    /** True (and records the attempt) at most once per TOKEN_RESUPPLY_COOLDOWN_MS
     * per contact — replaces the old "once ever" Set.add() check at both call
     * sites below. */
    private fun shouldResupplyTokens(contact: String): Boolean {
        val now = System.currentTimeMillis()
        val last = tokensSentThisSession[contact] ?: 0L
        if (now - last < TOKEN_RESUPPLY_COOLDOWN_MS) return false
        tokensSentThisSession[contact] = now
        return true
    }
    private val pendingMessages = mutableMapOf<String, MutableList<Pair<String, String>>>()

    private val processedGroupMessageIds = mutableSetOf<String>()
    private val pendingSessionMessages = mutableMapOf<String, MutableList<Pair<String, String>>>()

    /** Every real (non-decoy) target requestPrekeyBundle() is currently
     * waiting on — populated there, consumed by "prekey_bundles_batch_response".
     * Found live: that response handler used to filter by
     * pendingSessionMessages.keys alone, which only ever gets populated by
     * sendWithForwardSecrecy()'s queued-text-message path. A video circle /
     * image / file send with no key cached also calls requestPrekeyBundle()
     * but never touches pendingSessionMessages — so its batch response was
     * silently discarded as if it were a decoy entry, and publicKeys/
     * publicKeysPq for that contact never got set, leaving
     * flushPendingVideoCircles() with nothing to flush. It "worked" in one
     * test only because a text message happened to be queued for the same
     * contact at the same time. */
    private val pendingBundleRequests = mutableSetOf<String>()
    private val pendingReactions = mutableListOf<Triple<String, String, String>>()

    // Queued by sendAnonOrDirect() when a contact's anon-token pool is empty —
    // see the "cut the direct fallback" decision in
    // docs/ISSUE_backup_identity_hijack.md. Drained by flushPendingAnon()
    // once fresh tokens arrive for that contact (either path that calls
    // AnonTokenManager.addContactTokens).
    private val pendingAnonPackets = mutableMapOf<String, MutableList<JSONObject>>()

    // Found live: a burst of packets to a contact with no anon token yet
    // (e.g. every chunk of an 84-chunk video circle) each independently
    // triggered their own sendAnonTokensTo(to) -> depositTokensViaMailbox()
    // -> mailbox_put, with no de-duplication at all — 84 chunks meant 84
    // near-simultaneous mailbox_put calls, blowing through the server's
    // mailbox_put rate limit (20/60s) in seconds and getting the connection
    // kicked mid-transfer. This tracks the last bootstrap attempt per
    // contact so a burst collapses into one attempt instead of one per
    // packet.
    private val lastTokenBootstrapAttempt = mutableMapOf<String, Long>()
    private val TOKEN_BOOTSTRAP_COOLDOWN_MS = 3_000L

    private data class PendingVideoCircle(val to: String, val videoId: String, val encFilePath: String, val duration: Int)
    private val pendingVideoCircles = mutableListOf<PendingVideoCircle>()

    // Same pattern as pendingVideoCircles: sendImage/sendFile require BOTH the
    // contact's classical AND PQ public key cached in-memory (a one-shot hybrid
    // encrypt, not the session-based Double Ratchet text uses — which is why text
    // worked fine while photos silently vanished). The PQ key is only ever
    // populated by actually fetching a prekey bundle; a passively-received
    // session_init only carries the classical key. Confirmed live: sendImage
    // logged "нет ключа" and gave up with no retry at all. Queuing here and
    // flushing once the bundle arrives (see flushPendingImages/flushPendingFileSends,
    // called from the same spot as flushPendingVideoCircles) closes that gap.
    private data class PendingImage(val to: String, val chunks: List<String>)
    private val pendingImages = mutableListOf<PendingImage>()
    private data class PendingFileSend(val to: String, val fileName: String, val chunks: List<String>, val fileId: String)
    private val pendingFileSends = mutableListOf<PendingFileSend>()

    private val receivedMessageIds = HashMap<String, Long>()
    private val REPLAY_WINDOW_MS = 60 * 60 * 1000L
    private val imageChunks = mutableMapOf<String, MutableMap<Int, String>>()
    private val imageTotals = mutableMapOf<String, Int>()
    private val fileChunks = mutableMapOf<String, FileMeta>()
    private val imageChunkAcks = mutableMapOf<String, kotlinx.coroutines.channels.Channel<Int>>()
    private val fileChunkAcks = mutableMapOf<String, kotlinx.coroutines.channels.Channel<Int>>()
    private val videoChunkAcks = mutableMapOf<String, kotlinx.coroutines.channels.Channel<Int>>()
    private val cancelledTransfers = mutableSetOf<String>()

    private val notifLines = mutableMapOf<String, MutableList<String>>()

    var onMessageReceived: ((String, String) -> Unit)? = null
    var onStatusChanged: ((Boolean) -> Unit)? = null
    var onReactionReceived: ((String, String, String) -> Unit)? = null
    var onTypingReceived: ((String) -> Unit)? = null
    var onReadReceived: ((String) -> Unit)? = null
    var onDeliveredReceived: ((String) -> Unit)? = null
    var onEditReceived: ((String, String) -> Unit)? = null
    var onImageReceived: ((String, android.graphics.Bitmap) -> Unit)? = null
    var onKeyChanged: ((String) -> Unit)? = null
    var onVoiceReceived: ((String, File, Int) -> Unit)? = null
    var onFileReceived: ((String, File, String) -> Unit)? = null
    var onGroupMessageReceived: ((String, GroupMessage) -> Unit)? = null
    var onGroupReactionReceived: ((String, String, String, String) -> Unit)? = null
    var onGroupInviteReceived: ((Group, String) -> Unit)? = null
    var onTotpSetupResult: ((success: Boolean, reason: String?, recoveryCodes: List<String>?) -> Unit)? = null
    var onTotpDisableResult: ((Boolean) -> Unit)? = null
    // Fired when the server rejects register() with totp_required — this
    // device has no usable TOTP code for the account (fresh backup restore,
    // no authenticator saved locally). Lets a screen offer the recovery-code
    // fallback instead of just logging and silently retrying forever.
    var onTotpRequired: (() -> Unit)? = null
    var onChannelPostReceived: ((String, ChannelPost) -> Unit)? = null
    var onChannelCreated: ((Channel) -> Unit)? = null
    var onChannelPostDeleted: ((String, String) -> Unit)? = null
    var onChannelInfoUpdated: ((String) -> Unit)? = null
    var onChannelDeleted: ((String) -> Unit)? = null
    var onMessageDeleted: ((fromId: String, messageId: String) -> Unit)? = null
    var onDisappearTimerChanged: ((fromId: String, seconds: Long) -> Unit)? = null
    var onGroupMessageDeleted: ((groupId: String, messageId: String) -> Unit)? = null
    var onVideoReceived: ((videoId: String, file: File, duration: Int) -> Unit)? = null

    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null

    private var silentTrack: AudioTrack? = null
    private var silentJob: Job? = null
    private var silentSession: MediaSession? = null
    private var volMonitorJob: Job? = null
    private var audioFocusRequest: AudioFocusRequest? = null

    private fun startSilentAudio() {
        // isEmergencyWipeEnabled() defaults to true and only tracks intent —
        // most installs never touch it, so gating on that alone means this
        // silent track runs constantly for everyone, whether or not the
        // volume-button trigger was ever actually set up (a multi-step
        // Accessibility grant, see ProfileScreen.kt). Found live via AudioFlinger
        // log spam ("[audioTrackData][mute]") on a device that never enabled
        // the accessibility service. Only start it when the service is
        // genuinely active.
        if (silentTrack != null || !UserStorage.isEmergencyWipeEnabled(this) ||
            !isEmergencyServiceEnabled(this)) return
        try {

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

            val silence = ShortArray(bufSize / 2)
            silentJob = scope.launch(Dispatchers.IO) {
                while (isActive) {
                    if (silentTrack?.playState == AudioTrack.PLAYSTATE_PLAYING) {
                        silentTrack?.write(silence, 0, silence.size)
                    } else break
                }
            }

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

            val am = getSystemService(AudioManager::class.java)
            val minVol  = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                am.getStreamMinVolume(AudioManager.STREAM_MUSIC) else 0
            val safeVol = (am.getStreamMaxVolume(AudioManager.STREAM_MUSIC) / 3)
                .coerceAtLeast(minVol + 3)

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
        ensureMyMailboxTagRegistered()
        createNotificationChannel()
        TorManager.onTorReady = {
            if (!isConnected && !isConnecting) {
                scope.launch { connect() }
            }
        }

        TorManager.onTorError = { _ ->
            if (!isConnected && !isConnecting) {
                scope.launch { connect() }
            }
        }
        if (TorManager.isConnected) {

            scope.launch { connect() }
        } else if (UserStorage.isTorEnabled(this)) {
            TorManager.start(this, scope)
        } else {
            scope.launch { connect() }
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

    /** Ensures the account's invite code (and the mailbox tag embedded in it) is
     *  generated and registered as early as possible — previously this only
     *  happened lazily inside ProfileScreen's `remember {}` block, meaning a user
     *  who added contacts without ever opening their own Profile screen first
     *  never registered a mailbox tag for themselves at all. Confirmed live: a
     *  fresh reinstall that only used the "add contact" dialog (never opened
     *  Profile) showed `pollMailbox: 20 тегов (0 реальных)` indefinitely — the
     *  device could deposit tokens for contacts, but had nothing of its own for
     *  contacts to deposit into, so its side of the channel could never complete.
     *  Mirrors ProfileScreen.kt's reuse-until-TTL-expiry logic so both call sites
     *  stay consistent and idempotent. */
    private fun ensureMyMailboxTagRegistered() {
        try {
            // The persistent tag (used for ongoing contact, never published —
            // see AnonTokenManager's PREF_MY_INVITE_TAG doc comment) needs no
            // invite code at all to be registered for polling; ensure it
            // exists independent of whatever's going on with the invite code
            // below, so contacts can reach us even before we've sent anything.
            AnonTokenManager.getOrCreateMyPersistentMailboxTag(this)

            val existing = UserStorage.getInviteCode(this)
            val existingTimestamp = existing?.let { InviteCodeManager.parseInviteCode(it) }?.timestamp
            val stillValid = existingTimestamp != null &&
                (System.currentTimeMillis() / 1000 - existingTimestamp) < 7L * 24 * 3600
            val code = if (existing != null && stillValid) {
                existing
            } else {
                val fresh = InviteCodeManager.generateInviteCode(
                    CryptoManager.getPublicKey(),
                    CryptoManager.getPrivateKeyPublic(),
                    UserStorage.getUsername(this).ifBlank { UserStorage.getUserId(this) },
                    AnonTokenManager.getOrCreateMyInviteMailboxTag(this)
                )
                UserStorage.saveInviteCode(this, fresh)
                fresh
            }
            val embeddedTag = InviteCodeManager.parseInviteCode(code)?.mailboxTag
            embeddedTag?.let { tag ->
                AnonTokenManager.syncMyInviteMailboxTag(this, tag)
            }
            Log.d(TAG, "DEBUG-BOOTSTRAP ensureMyMailboxTagRegistered: reused=${existing != null && stillValid} embeddedTag=$embeddedTag myTags=${AnonTokenManager.getMyMailboxTags(this)}")
        } catch (e: Exception) {
            Log.e(TAG, "ensureMyMailboxTagRegistered: ${e.message}")
        }
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

                Log.d(TAG, "Сеть доступна — проверяем соединение")
                if (!isConnected && !isConnecting) {
                    scope.launch { connect() }
                }
            }
            override fun onLost(network: android.net.Network) {

                // Deliberately NOT touching any active call here anymore. This callback
                // used to instantly send call_end + CallManager.release() on ANY network
                // loss — but onLost() fires on brief, harmless transitions too (network
                // handoff, momentary blips), often followed by onAvailable() within
                // milliseconds. Killing the call unconditionally here pre-empted
                // CallManager's own, more patient network callback (registerNetworkCallback
                // in CallManager.kt), which waits for the network to come back and only
                // gives up after a real ICE restart attempt plus a 10s grace period.
                // Confirmed via live device testing: a call would connect over ICE and then
                // get torn down within ~1-2 seconds by this handler, well before
                // CallManager's own recovery logic ever got a chance to run.
                Log.d(TAG, "Сеть потеряна")
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

        intent?.getStringExtra("bootstrap_channel_for")?.let { contact ->
            if (isConnected) bootstrapChannelFor(contact)
            return START_STICKY
        }

        if (intent?.getBooleanExtra("reload_cover_traffic", false) == true) {
            if (!isConnected) {
                scope.launch(Dispatchers.IO) { connect() }
            } else {
                val drained = mutableListOf<String>()
                outboundQueue.drainTo(drained)
                stopCoverTraffic()
                startCoverTraffic()
                drained.forEach { outboundQueue.offer(it) }
            }
            return START_STICKY
        }

        intent?.getStringExtra("send_session_reset_to")?.let { contactId ->
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendAnonOrDirect(contactId, JSONObject().apply {
                        put("type", "session_reset")
                        put("from", username)
                        put("to", contactId)
                    })
                }
            }
            return START_STICKY
        }

        // Same intent-extra pattern as send_session_reset_to above — used by
        // ChatsScreen's delete-contact flow, which has no bound service
        // reference of its own. See forgetContact() for what this clears
        // and why (in-memory key caches + mailbox tag that a plain
        // ChatStorage.deleteChat() can't reach, since those live in this
        // running service instance / a different storage namespace).
        intent?.getStringExtra("forget_contact")?.let { contactId ->
            forgetContact(contactId)
            return START_STICKY
        }

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

                getSharedPreferences("fcm_prefs", android.content.Context.MODE_PRIVATE)
                    .edit().putString("pending_fcm_token", token).apply()
            }
            return START_STICKY
        }

        intent?.getStringExtra("call_signal")?.let { signalJson ->
            if (!isConnected) {
                Log.w(TAG, "DEBUG-BOOTSTRAP call_signal dropped — not connected: $signalJson")
            }
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    try {
                        val packet = JSONObject(signalJson)
                        val sigType = packet.optString("type")
                        val to = packet.optString("to")
                        if (sigType.startsWith("call_group_")) {
                            // Group calls skip the request/response phase entirely — always direct.
                            sendWs(signalJson)
                        } else {
                            // call_end's one-shot-no-redundancy reliability gap (confirmed via live
                            // testing: "сброс у одного не долетает до другого") is now covered by
                            // CallManager's in-band "bye" over the P2P heartbeat DataChannel, sent
                            // right before this server-routed call_end — see hangUp()/
                            // sendByeOverDataChannel(). This anon-routed send is now just the
                            // fallback for when the DataChannel isn't open yet (still connecting).
                            sendAnonOrDirect(to, packet)
                        }
                    } catch (e: Exception) {
                        // Fail closed, not open: if signalJson itself doesn't
                        // parse we don't even reliably have a "to" to route
                        // by, so a raw sendWs() here was both a metadata leak
                        // (bypasses sendAnonOrDirect above) and pointless —
                        // the server/recipient can't make sense of malformed
                        // call signaling either way. See
                        // docs/ISSUE_backup_identity_hijack.md, "прямая
                        // адресация, не через анон-токен", item 4.
                        Log.e(TAG, "call_signal: не удалось разобрать пакет, сигнал отброшен — ${e.message}")
                    }
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

        intent?.getStringExtra("forward_to")?.let { contactId ->
            val text = intent.getStringExtra("forward_text") ?: return@let
            scope.launch(Dispatchers.IO) { send(contactId, text) }
            return START_STICKY
        }

        intent?.getStringExtra("avatar_update")?.let { b64 ->
            UserStorage.saveMyAvatar(this, b64)

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

    private val outboundQueue = java.util.concurrent.LinkedBlockingQueue<String>(200)
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

    /** One-time provisioning of the device-gated registration TOTP secret.
     * The server refuses this outright if a secret is already on file for
     * this account, so it's only ever meaningful the first time. */
    fun sendTotpSetup(secretBase32: String, code: String) {
        if (!isConnected) {
            onTotpSetupResult?.invoke(false, "not_connected", null)
            return
        }
        sendWs(JSONObject().apply {
            put("type", "totp_setup")
            put("secret", secretBase32)
            put("code", code)
        }.toString())
    }

    /** Response to onTotpRequired() — this device has no usable TOTP code
     *  (fresh backup restore, lost authenticator). Stashes the code for the
     *  next register() attempt and forces a reconnect to retry immediately
     *  instead of waiting for whatever the normal reconnect backoff is. */
    fun submitRecoveryCode(code: String) {
        pendingRecoveryCode = code.trim()
        totpRequiredNotified = false
        webSocket?.close(1000, "recovery_code retry")
    }

    fun sendTotpDisable(code: String) {
        if (!isConnected) {
            onTotpDisableResult?.invoke(false)
            return
        }
        sendWs(JSONObject().apply {
            put("type", "totp_disable")
            put("code", code)
        }.toString())
    }

    /** Canonical string signed/verified for a group's member+admin roster,
     * shared by createGroup()/addGroupMember() (sign) and the group_create
     * handler (verify) — see docs/ISSUE_backup_identity_hijack.md, group
     * roster fix. */
    private fun rosterPayload(groupId: String, members: List<String>, admins: List<String>): String =
        "$groupId|${members.joinToString(",")}|${admins.joinToString(",")}"


    private fun sendWs(json: String) {
        val mode = UserStorage.getCoverTrafficMode(this)
        if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE && isConnected) {
            if (!outboundQueue.offer(json)) {
                Log.w(TAG, "outboundQueue переполнена — отправляем напрямую")
                webSocket?.send(json)
            }
        } else {
            webSocket?.send(json)
        }
    }

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

                handshakeDone = false

                val client = if (wsUrl.contains(".onion")) wsClient else activeWsClient()
                webSocket = client.newWebSocket(request, listener)

                val success = withTimeoutOrNull(15_000) {
                    while (!handshakeDone && scope.isActive) {
                        delay(100)
                    }
                    handshakeDone
                } ?: false

                if (!success || !isConnected) {
                    Log.e(TAG, "Handshake failed (success=$success, connected=$isConnected)")
                    webSocket?.close(1000, "handshake failed")
                    throw Exception("Handshake failed")
                }

                val displayName = UserStorage.getUsername(this@MessengerService)
                val myAvatarB64 = UserStorage.getMyAvatar(this@MessengerService) ?: ""
                // Included unconditionally when locally enabled — harmless on a
                // reconnect from an already-known device_id (server only checks
                // it for a new device_id, see server.py). Avoids needing any
                // "wait for totp_required, then retry" round-trip: a device that
                // already has the secret (set up locally, or restored via a
                // TOTP-protected backup import) can just always include the
                // current code. See docs/ISSUE_backup_identity_hijack.md.
                val totpSecret = TotpManager.getSecret(this@MessengerService)
                // Only relevant for a server running SERVER_ACCESS_PROTECTED —
                // sent unconditionally when present, same "let the server
                // decide" principle as totp_code above. Harmless once already
                // consumed or on a server that doesn't check it at all.
                val accessCode = ServerManager.getCurrentServer(this@MessengerService)?.accessCode
                // Set by submitRecoveryCode() in response to totp_required on a
                // device that doesn't have the TOTP secret at all (e.g. a fresh
                // backup restore, no authenticator saved) — one-shot, cleared
                // immediately so a wrong/expired code isn't silently retried
                // forever on every subsequent reconnect.
                val recoveryCode = pendingRecoveryCode
                pendingRecoveryCode = null
                sendWs(JSONObject().apply {
                    put("type", "register")
                    put("from", username)
                    put("name", displayName)
                    put("public_key", CryptoManager.getPublicKeyString())
                    put("protocol_version", ProtocolVersion.CURRENT_VERSION)
                    put("device_id", UserStorage.getDeviceId(this@MessengerService))
                    if (myAvatarB64.isNotEmpty()) put("avatar", myAvatarB64)
                    if (totpSecret != null) put("totp_code", TotpManager.currentCode(totpSecret))
                    if (!accessCode.isNullOrBlank()) put("access_code", accessCode)
                    if (!recoveryCode.isNullOrBlank()) put("recovery_code", recoveryCode)
                }.toString())

                val contacts = ChatStorage.getContacts(this@MessengerService)
                contacts.forEach { contactId ->
                    val savedKey = ChatStorage.getContactPublicKey(this@MessengerService, contactId)
                    if (savedKey != null) publicKeys[contactId] = savedKey

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
                totpRequiredNotified = false
                Log.d(TAG, "Handshake завершён успешно")
                PanicNotificationManager.show(this@MessengerService)

                try {
                    if (!SessionKeyManager.hasSession("__init_check__")) {

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

                flushPendingVideoCircles()

                val pendingResetContacts = UserStorage.getAndClearPendingSessionResetContacts(this@MessengerService)
                if (pendingResetContacts.isNotEmpty()) {
                    Log.d(TAG, "Рассылаем session_reset ${pendingResetContacts.size} контактам после восстановления бэкапа")
                    scope.launch(Dispatchers.IO) {
                        pendingResetContacts.forEach { contactId ->
                            SessionKeyManager.deleteSession(contactId)
                            sendAnonOrDirect(contactId, JSONObject().apply {
                                put("type", "session_reset")
                                put("from", username)
                                put("to", contactId)
                            })
                        }
                    }
                }

                pollMailbox()
                scope.launch(Dispatchers.IO) {
                    while (isConnected && scope.isActive) {
                        delay(30_000)
                        if (isConnected && AnonTokenManager.getMyMailboxTags(this@MessengerService).isNotEmpty())
                            pollMailbox()
                    }
                }

                scope.launch(Dispatchers.IO) {
                    while (isConnected && scope.isActive) {
                        delay(60_000)
                        if (isConnected) checkContactSilence()
                    }
                }
            }

            "prekey_bundle_request" -> {
                try {
                    publishPrekeyBundle()
                    Log.d(TAG, "Prekey bundle republish по запросу сервера")
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка republish prekey bundle: ${e.message}")
                }
            }

            "totp_setup_ok" -> {
                val recoveryCodes = json.optJSONArray("recovery_codes")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }
                }
                withContext(Dispatchers.Main) { onTotpSetupResult?.invoke(true, null, recoveryCodes) }
            }

            "totp_setup_failed" -> {
                val reason = json.optString("reason", null)
                withContext(Dispatchers.Main) { onTotpSetupResult?.invoke(false, reason, null) }
            }

            "totp_disable_ok" -> {
                withContext(Dispatchers.Main) { onTotpDisableResult?.invoke(true) }
            }

            "totp_disable_failed" -> {
                withContext(Dispatchers.Main) { onTotpDisableResult?.invoke(false) }
            }

            "totp_required" -> {
                // Server rejected register() because this device_id is new to
                // the fingerprint and either no code was included or it didn't
                // match. This device either doesn't have the secret at all (a
                // genuine attacker, a second legitimate device that never went
                // through setup/backup import, or a lost authenticator) or the
                // clock drifted past the verification window. Notified once
                // per connection so a screen can offer the recovery-code
                // fallback instead of just retrying the same failing register()
                // forever.
                if (!totpRequiredNotified) {
                    totpRequiredNotified = true
                    Log.e(TAG, "register отклонён сервером: новое устройство требует TOTP-код")
                    withContext(Dispatchers.Main) { onTotpRequired?.invoke() }
                }
            }

            "access_code_required" -> {
                // Server has SERVER_ACCESS_PROTECTED on and rejected this as a
                // first-ever registration with no/invalid access_code — unlike
                // totp_required (an existing account on a new device), this is
                // typically a brand-new user staring at the register screen
                // right now, so worth a visible signal, not just a log line.
                Log.e(TAG, "register отклонён сервером: требуется код доступа для нового аккаунта")
                withContext(Dispatchers.Main) {
                    android.widget.Toast.makeText(
                        this@MessengerService, s.serversAccessCodeRequired, android.widget.Toast.LENGTH_LONG
                    ).show()
                }
            }

            "mailbox_result" -> handleMailboxResult(json)

            "session_conflict" -> {
                Log.w(TAG, "⚠️ session_conflict: аккаунт подключён с другого устройства")
                isConnected = false
                handshakeDone = false
                webSocket?.cancel()
                val conflictTs = json.optDouble("ts", Double.NaN)
                withContext(Dispatchers.Main) {
                    onStatusChanged?.invoke(false)
                    showSessionConflictNotification(conflictTs)
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

                    val fixedKey = key.replace('-', '+').replace('_', '/')

                    if (KeyHistoryManager.checkKeyChange(this@MessengerService, targetUsername, fixedKey)) {
                        withContext(Dispatchers.Main) { onKeyChanged?.invoke(targetUsername) }
                    }
                    publicKeys[targetUsername] = fixedKey
                    ChatStorage.saveContactPublicKey(this@MessengerService, targetUsername, fixedKey)

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

            }

            "read" -> {
                val messageId = json.getString("id")
                val from = json.optString("from", null)

                if (from != null) {
                    val myId = UserStorage.getUserId(this@MessengerService)
                    ChatStorage.markRead(this@MessengerService, myId, from, messageId)
                }
                withContext(Dispatchers.Main) { onReadReceived?.invoke(messageId) }
            }

            "delivered" -> {
                val messageId = json.optString("id", null) ?: return
                val from      = json.optString("from", null) ?: return

                val myId = UserStorage.getUserId(this@MessengerService)
                ChatStorage.markDelivered(this@MessengerService, myId, from, messageId)
                ContactHealthManager.recordDelivered(this@MessengerService, from)
                withContext(Dispatchers.Main) { onDeliveredReceived?.invoke(messageId) }
            }

            // ── "Забота о собеседнике": peer health-check ping/pong ────────────
            // See docs/ISSUE_backup_identity_hijack.md and ContactHealthManager.
            // Receiving either type just proves the channel is alive right now —
            // reset the silence clock. A pong is sent back in response to a ping
            // (via sendAnonOrDirect, same as any other packet — no special
            // exemption from token consumption) so the *pinger* also sees the
            // round-trip complete, not just the recipient.
            "contact_ping" -> {
                val from = json.optString("from", null) ?: return
                ContactHealthManager.recordIncoming(this@MessengerService, from)
                Log.d(TAG, "contact_ping от $from — отвечаем pong")
                sendAnonOrDirect(from, JSONObject().apply {
                    put("type", "contact_pong")
                    put("from", username)
                    put("to", from)
                    put("id", json.optString("id", UUID.randomUUID().toString()))
                })
            }

            "contact_pong" -> {
                val from = json.optString("from", null) ?: return
                ContactHealthManager.recordIncoming(this@MessengerService, from)
                Log.d(TAG, "contact_pong от $from — канал восстановлен")
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
                    val signature = json.optString("signature", null)
                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                    if (signature == null || senderKey == null || !CryptoManager.verify(encryptedEmoji, signature, senderKey)) {
                        Log.e(TAG, "reaction: неверная или отсутствующая подпись от $from")
                        return
                    }
                    val emoji = CryptoManager.decrypt(encryptedEmoji)
                    withContext(Dispatchers.Main) { onReactionReceived?.invoke(from, messageId, emoji) }
                } catch (e: Exception) {
                    Log.e(TAG, "reaction error: ${e.message}")
                }
            }

            "message_delete" -> {
                val from = json.getString("from")
                val messageId = json.getString("message_id")
                val signature = json.optString("signature", null)
                val senderKey = publicKeys[from]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                if (signature == null || senderKey == null || !CryptoManager.verify(messageId, signature, senderKey)) {
                    Log.e(TAG, "message_delete: неверная или отсутствующая подпись от $from")
                    return
                }
                val myId = UserStorage.getUserId(this@MessengerService)
                ChatStorage.deleteMessage(this@MessengerService, myId, from, messageId)
                withContext(Dispatchers.Main) { onMessageDeleted?.invoke(from, messageId) }
            }

            "disappear_timer" -> {
                val from = json.getString("from")
                val seconds = json.getLong("seconds")
                val signature = json.optString("signature", null)
                val senderKey = publicKeys[from]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                if (signature == null || senderKey == null || !CryptoManager.verify(seconds.toString(), signature, senderKey)) {
                    Log.e(TAG, "disappear_timer: неверная или отсутствующая подпись от $from")
                    return
                }
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

                    sendWs(JSONObject().apply {
                        put("type", "chunk_ack")
                        put("image_id", imageId)
                        put("chunk_index", chunkIndex)
                    }.toString())

                    try {

                        val transferKey = "$from:$imageId"
                        if (isEncrypted) {

                            val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
                            chunks[chunkIndex] = chunkData
                            imageTotals[transferKey] = totalChunks

                            if (chunks.size == totalChunks) {
                                Log.d(TAG, "Все image чанки получены, расшифровываем...")

                                val ordered = (0 until totalChunks).map { chunks[it]!! }
                                val packedData = ordered.joinToString("")

                                val encryptedFileData = CryptoManager.unpackEncryptedFile(packedData)
                                val decryptedBytes = CryptoManager.decryptFile(encryptedFileData)

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
                    val fileId = sanitizePathComponent(json.getString("file_id"))
                    val encryptedFileName = json.optString("encrypted_file_name", null)
                    val legacyFileName = json.optString("file_name", null)
                    val chunkIndex = json.getInt("chunk_index")
                    val totalChunks = json.getInt("total_chunks")
                    val chunkData = json.getString("data")
                    val signature = json.optString("signature", null)
                    val isEncrypted = json.optBoolean("encrypted", false)

                    Log.d(TAG, "Получен file_chunk $chunkIndex/$totalChunks (fileId=$fileId, зашифрован: $isEncrypted)")

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

                    val fileTransferKey = "$from:$fileId"

                    if (!fileChunks.containsKey(fileTransferKey)) {
                        // encrypted_file_name is decrypted once, only when this
                        // transfer's FileMeta is first created — legacy senders
                        // without this field (or a decrypt failure) fall back to
                        // the plaintext file_name if present, else a generic name.
                        val decryptedName = try {
                            when {
                                encryptedFileName != null -> CryptoManager.decrypt(encryptedFileName)
                                legacyFileName != null -> legacyFileName
                                else -> "file"
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Не удалось расшифровать имя файла: ${e.message}")
                            legacyFileName ?: "file"
                        }
                        val fileName = sanitizePathComponent(decryptedName)
                        fileChunks[fileTransferKey] = FileMeta(fileName, totalChunks, mutableListOf())
                    }
                    fileChunks[fileTransferKey]?.chunks?.add(chunkIndex to chunkData)

                    val receivedChunks = fileChunks[fileTransferKey]?.chunks?.size ?: 0
                    Log.d(TAG, "Собрано чанков: $receivedChunks/$totalChunks для файла ${fileChunks[fileTransferKey]?.name}")

                    if (receivedChunks == totalChunks) {
                        Log.d(TAG, "Все чанки получены для $fileId, начинаем сборку")

                        val fileName = fileChunks[fileTransferKey]?.name ?: "file"
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

                                val file = SecureFileStorage.blobFile(filesDir, fileId)
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
                            val file = SecureFileStorage.blobFile(filesDir, fileId)
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
                    processVideoChunk(
                        from = from,
                        videoId = json.getString("video_id"),
                        chunkIndex = json.getInt("chunk_index"),
                        totalChunks = json.getInt("total_chunks"),
                        chunkData = json.getString("data"),
                        duration = json.optInt("duration", 0),
                        isEncrypted = json.optBoolean("encrypted", true),
                        signature = json.optString("signature", null)
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "video_chunk error: ${e.message}", e)
                }
            }

            // Bundles multiple video_chunk payloads into one anon_message —
            // see sendVideoCircle()'s CHUNK_BATCH_SIZE. Tokens are deliberately
            // single-use server-side (see server.py's anon_message handler),
            // so a 60s video's 100+ chunks used to burn through the entire
            // shared token pool before a single chunk got past text messages
            // in the same queue. Batching keeps one-token-per-message but
            // puts far more payload behind each token.
            "video_chunk_batch" -> {
                try {
                    val from = json.getString("from")
                    val videoId = json.getString("video_id")
                    val totalChunks = json.getInt("total_chunks")
                    val duration = json.optInt("duration", 0)
                    val isEncrypted = json.optBoolean("encrypted", true)
                    val chunksArr = json.getJSONArray("chunks")
                    for (i in 0 until chunksArr.length()) {
                        val c = chunksArr.getJSONObject(i)
                        processVideoChunk(
                            from = from,
                            videoId = videoId,
                            chunkIndex = c.getInt("chunk_index"),
                            totalChunks = totalChunks,
                            chunkData = c.getString("data"),
                            duration = duration,
                            isEncrypted = isEncrypted,
                            signature = c.optString("signature", null)
                        )
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "video_chunk_batch error: ${e.message}", e)
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

                    val fixedKey = senderKey.replace('-', '+').replace('_', '/')

                    if (!CryptoManager.verify(encryptedData, signature, fixedKey)) {
                        Log.e(TAG, "⚠️ Неверная подпись голосового от $from")
                        return
                    }

                    val voiceData = CryptoManager.decrypt(encryptedData)
                    val voiceFile = AudioHelper.decodeAndSave(this@MessengerService, voiceData, voiceId)
                    Log.i(TAG, "ПОЛУЧЕНО voice $voiceId ← $from @ ${System.currentTimeMillis()}")
                    withContext(Dispatchers.Main) { onVoiceReceived?.invoke(voiceId, voiceFile, duration) }
                } catch (e: Exception) {
                    Log.e(TAG, "voice error: ${e.message}")
                }
            }

            "prekey_bundle" -> {
                val fromUser = json.getString("from")
                if (json.has("identity_key") && !json.isNull("identity_key")) {
                    val identityKey = json.getString("identity_key")

                    val fixedIdentityKey = identityKey.replace('-', '+').replace('_', '/')

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
                pendingBundleRequests.remove(from)
                val bundleJsonRaw = if (json.isNull("bundle")) null else json.getJSONObject("bundle")
                handleFetchedPrekeyBundle(from, bundleJsonRaw)
            }

            // ── Anonymous batched prekey-bundle fetch response ─────────────────
            // Only entries matching a fingerprint we actually requested
            // (pendingBundleRequests) are processed — decoy entries (present
            // in the batch purely as cover) are discarded outright, since we
            // never asked for a session with them. Not filtered by
            // pendingSessionMessages alone anymore — see pendingBundleRequests'
            // doc comment for the live incident (video circles never reached
            // this handler at all).
            "prekey_bundles_batch_response" -> {
                val bundlesObj = json.optJSONObject("bundles")
                if (bundlesObj != null) {
                    for (target in pendingBundleRequests.toList()) {
                        if (!bundlesObj.has(target)) continue
                        pendingBundleRequests.remove(target)
                        val bundleJsonRaw = if (bundlesObj.isNull(target)) null else bundlesObj.getJSONObject(target)
                        handleFetchedPrekeyBundle(target, bundleJsonRaw)
                    }
                }
            }

            "session_init" -> processSessionInit(json)

            "message" -> {
                val messageId = json.optString("id", null)
                val from = json.getString("from")
                val protocolVersion = json.optInt("protocol_version", 1)
                if (messageId != null) {
                    val nowMs = System.currentTimeMillis()

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

                                requestPrekeyBundle(from)
                                sendAnonOrDirect(from, JSONObject().apply {
                                    put("type", "session_reset")
                                    put("from", username)
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

                    if (AnonTokenManager.getContactTokens(this@MessengerService, from).isEmpty()) {
                        scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка расшифровки от $from: ${e.message}")
                    SessionKeyManager.deleteSession(from)
                    requestPrekeyBundle(from)

                    sendAnonOrDirect(from, JSONObject().apply {
                        put("type", "session_reset")
                        put("from", username)
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
                val rosterSignature = json.optString("roster_signature", null)

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

                    // Full signed roster (members+admins) added so every invitee
                    // starts with the real membership, not just [from, me] —
                    // see docs/ISSUE_backup_identity_hijack.md, group roster fix.
                    // Falls back to the old [from, me]/[from] shape if a legacy
                    // peer sends a packet without these fields.
                    val membersFromPacket = json.optJSONArray("members")?.let { arr ->
                        (0 until arr.length()).map { arr.getString(it) }
                    }
                    val adminsFromPacket = json.optJSONArray("admins")?.let { arr ->
                        (0 until arr.length()).map { arr.getString(it) }
                    }

                    val members: List<String>
                    val admins: List<String>
                    if (membersFromPacket != null && adminsFromPacket != null) {
                        val payload = rosterPayload(groupId, membersFromPacket, adminsFromPacket)
                        if (rosterSignature == null || !CryptoManager.verify(payload, rosterSignature, senderKey)) {
                            Log.e(TAG, "Неверная подпись ростера группы от $from")
                            return
                        }
                        if (username !in membersFromPacket) {
                            Log.e(TAG, "group_create: ростер не содержит получателя — отклонено")
                            return
                        }
                        members = membersFromPacket
                        admins = adminsFromPacket
                    } else {
                        members = listOf(from, username)
                        admins = listOf(from)
                    }

                    val groupKey = GroupManager.decryptGroupKey(encryptedGroupKey)

                    val existingGroup = GroupManager.getGroup(this@MessengerService, groupId)
                    if (existingGroup != null) {
                        Log.d(TAG, "Уже состоим в группе $groupName")
                        return
                    }

                    val group = Group(
                        id = groupId,
                        name = groupName,
                        avatar = groupAvatar,
                        members = members,
                        admins = admins,
                        createdBy = from,
                        groupKey = groupKey
                    )

                    GroupManager.saveGroup(this@MessengerService, group)

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
                    val signature = json.optString("signature", null)

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }

                    if (signature == null || senderKey == null) {
                        Log.e(TAG, "group_reaction без ключа от $from")
                        return
                    }

                    if (!CryptoManager.verify(emoji, signature, senderKey)) {
                        Log.e(TAG, "Неверная подпись group_reaction от $from")
                        return
                    }

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

                        if (from == null || !GroupManager.isAdmin(this@MessengerService, groupId, from)) {
                            Log.e(TAG, "group_member_removed от не-администратора $from — отклонено")
                            return
                        }

                        val adminKey = publicKeys[from]
                            ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                        if (removeSignature == null || adminKey == null ||
                            !CryptoManager.verify("$groupId:$removedMember", removeSignature, adminKey)) {
                            Log.e(TAG, "group_member_removed: неверная подпись от $from — отклонено")
                            return
                        }
                        GroupManager.removeMember(this@MessengerService, groupId, removedMember)

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

            "group_member_added" -> {
                // Symmetric counterpart to group_member_removed — previously
                // addGroupMember() only told the new member (via group_create),
                // never the existing members, so their local rosters silently
                // fell behind. See docs/ISSUE_backup_identity_hijack.md, group
                // roster fix.
                val groupId = json.getString("group_id")
                val newMember = json.getString("new_member")
                val newMemberName = json.optString("new_member_name", newMember)
                val from = json.optString("from", null)
                val addSignature = json.optString("signature", null)

                try {
                    val group = GroupManager.getGroup(this@MessengerService, groupId)
                    if (group != null) {

                        if (from == null || !GroupManager.isAdmin(this@MessengerService, groupId, from)) {
                            Log.e(TAG, "group_member_added от не-администратора $from — отклонено")
                            return
                        }

                        val adminKey = publicKeys[from]
                            ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                        if (addSignature == null || adminKey == null ||
                            !CryptoManager.verify("$groupId:add:$newMember", addSignature, adminKey)) {
                            Log.e(TAG, "group_member_added: неверная подпись от $from — отклонено")
                            return
                        }
                        GroupManager.addMember(this@MessengerService, groupId, newMember)

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
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_member_added error: ${e.message}")
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

                    if (!GroupManager.isAdmin(this@MessengerService, groupId, from)) {
                        Log.e(TAG, "group_key_rotation от не-администратора $from в группе $groupId")
                        return
                    }

                    val newGroupKey = GroupManager.decryptGroupKey(encryptedNewKey)

                    val group = GroupManager.getGroup(this@MessengerService, groupId)
                    if (group != null) {
                        val updatedGroup = group.copy(groupKey = newGroupKey)
                        GroupManager.saveGroup(this@MessengerService, updatedGroup)

                        Log.d(TAG, "Групповой ключ обновлён для группы $groupId")

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

                    val memberPublicKey = publicKeys[newMember]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, newMember)
                    if (inviteSignature == null || memberPublicKey == null ||
                        !CryptoManager.verify("$groupId:$newMember", inviteSignature, memberPublicKey)) {
                        Log.e(TAG, "group_invite_accepted: неверная подпись от $newMember — отклонено")
                        return
                    }

                    GroupManager.addMember(this@MessengerService, groupId, newMember)

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

            "call_offer" -> {
                try {
                    val from    = json.getString("from")
                    val sdp     = json.getString("sdp")
                    val callId  = json.getString("call_id")
                    val isVideo = json.optBoolean("is_video", false)
                    val isGroup = json.optBoolean("is_group", false)
                    val gId     = json.optString("group_id", "")
                    CallManager.init(this@MessengerService)
                    val isFreshIncomingCall = CallManager.handleOffer(from, sdp, callId, isVideo, isGroup, gId)

                    // A call_offer for a request the user already accepted is handled
                    // entirely inside CallManager (auto-proceeds to answering) — showing
                    // the incoming-call UI again here would create a second, stale screen
                    // instance whose eventual dispose would kill the call already in
                    // progress. Only show it for a genuinely fresh incoming offer.
                    if (isFreshIncomingCall) {
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

            "call_ringing" -> {  }

            "call_request_audio", "call_request_video" -> {
                try {
                    val from    = json.getString("from")
                    val callId  = json.getString("call_id")
                    val isVideo = type == "call_request_video"

                    // Found live: a call_request queued (no anon token yet,
                    // sendAnonOrDirect's pendingAnonPackets has no TTL) can
                    // deliver minutes after the caller already gave up and
                    // hung up — the callee's phone starts ringing for a call
                    // that's long over. 45s matches CallManager's own
                    // RINGING_TIMEOUT_MS — if the caller would already have
                    // stopped waiting by now, don't ring at all. Packets from
                    // before this field existed (ts absent) are let through
                    // rather than dropped, to fail open on old clients.
                    val ts = json.optLong("ts", 0L)
                    if (ts != 0L && System.currentTimeMillis() - ts > 45_000L) {
                        Log.w(TAG, "call_request от $from проигнорирован — устарел на ${(System.currentTimeMillis() - ts) / 1000}с")
                        return
                    }

                    CallManager.init(this@MessengerService)
                    CallManager.handleIncomingCallRequest(from, callId, isVideo)

                    val peerName = ChatStorage.getContactName(this@MessengerService, from).ifBlank { from }
                    startService(Intent(this@MessengerService, CallService::class.java).apply {
                        action = CallService.ACTION_INCOMING
                        putExtra(CallService.EXTRA_PEER_NAME, peerName)
                        putExtra(CallService.EXTRA_IS_VIDEO,  isVideo)
                        putExtra(CallService.EXTRA_IS_GROUP,  false)
                    })
                    withContext(Dispatchers.Main) {
                        MainActivity.pendingIncomingCall.value = Triple(callId, isVideo, from)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "call_request error: ${e.message}")
                }
            }

            "call_response" -> {
                try {
                    val from     = json.getString("from")
                    val callId   = json.getString("call_id")
                    val accepted = json.optBoolean("accepted", false)
                    CallManager.handleCallResponse(this@MessengerService, from, callId, accepted)
                } catch (e: Exception) {
                    Log.e(TAG, "call_response error: ${e.message}")
                }
            }

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

            "anon_delivery" -> {
                try {
                    val payload = json.getJSONObject("payload")

                    payload.optString("_anon_token").takeIf { it.isNotBlank() }?.let {
                        AnonTokenManager.consumeMyToken(this@MessengerService, it)
                    }

                    handleMessage(payload)
                } catch (e: Exception) {
                    Log.e(TAG, "anon_delivery error: ${e.message}")
                }
            }
        }
    }

    fun send(to: String, text: String, replyToId: String? = null): String {
        ContactHealthManager.recordOutgoingAttempt(this, to)
        if (isConnected) {

            val mailboxTag = AnonTokenManager.getContactMailboxTag(this, to)
            val hasContactTokens = AnonTokenManager.getContactTokens(this, to).isNotEmpty()
            if (mailboxTag != null && !hasContactTokens && !SessionKeyManager.hasSession(to)) {
                val publicKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this, to)?.also { publicKeys[to] = it }
                if (publicKey != null) {
                    val id = UUID.randomUUID().toString()
                    sendViaMailbox(to, text, publicKey, mailboxTag, id)
                    return id
                }
                // Found live: this used to call clearContactMailboxTag() here,
                // treating "public key not cached yet" as "the tag is stale" —
                // but the key is often just moments away (fetched via
                // sendWithForwardSecrecy's own requestPrekeyBundle() call
                // below). Wiping the tag on a purely transient timing gap
                // permanently killed the only path back into mailbox
                // bootstrap for that contact — nothing else can ever
                // rediscover it (see sendAnonTokensTo's chicken-and-egg
                // comment). Leave it alone; the next send retries mailbox
                // once the key arrives.
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
        replyToId: String? = null, useAnonRouting: Boolean = true,
        bootstrapToken: String? = null
    ): String {
        val id = msgId ?: UUID.randomUUID().toString()
        Log.i(TAG, "ОТПРАВЛЕНО message $id → $to @ ${System.currentTimeMillis()}")
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

                    // A bootstrap token attached to a freshly-fetched prekey bundle
                    // (see requestPrekeyBundlesBatch / prekey_bundle_response) takes
                    // priority for the very first session_init — it's a one-off,
                    // separate from the ordinary per-contact token pool, and lets
                    // this first message be delivered anonymously even though no
                    // regular anon token has been exchanged with this contact yet.
                    val anonToken = bootstrapToken
                        ?: AnonTokenManager.consumeNextContactToken(this@MessengerService, to)

                    if (anonToken != null) {
                        val anonPacket = JSONObject().apply {
                            put("type", "anon_message")
                            put("token", anonToken)
                            put("payload", packet)
                        }
                        sendWs(addPadding(anonPacket).toString())

                        if (AnonTokenManager.needsRefill(this@MessengerService, to) && shouldResupplyTokens(to)) {
                            scope.launch(Dispatchers.IO) { sendAnonTokensTo(to) }
                        }
                    } else if (isFirst) {
                        // No anon/bootstrap token for this brand-new session —
                        // this used to fall straight through to a direct,
                        // fingerprint-addressed sendWs(). See
                        // docs/ISSUE_backup_identity_hijack.md, "session_init
                        // тихо откатывается на прямую адресацию": reuse the
                        // same anonymous mailbox path already relied on for
                        // token bootstrap, instead of a silent non-anonymous
                        // fallback. The full session_init sub-packet (x3dh
                        // header + forward-secrecy ciphertext) travels inside
                        // the mailbox blob so the recipient's session state
                        // ends up identical to a direct delivery — see
                        // handleMailboxResult's session_init_packet handling.
                        val mailboxTag = AnonTokenManager.getContactMailboxTag(this@MessengerService, to)
                        val recipientKey = publicKeys[to]
                            ?: ChatStorage.getContactPublicKey(this@MessengerService, to)
                        if (mailboxTag != null && recipientKey != null) {
                            depositSessionInitViaMailbox(to, mailboxTag, recipientKey, packet)
                        } else {
                            Log.w(TAG, "session_init: нет ни анон-токена, ни mailbox-тега для $to — доставка напрямую")
                            sendWs(addPadding(packet).toString())
                        }
                    } else {
                        // Found live: an ordinary (non-first) message with no
                        // anon token available for this contact used to fall
                        // straight through to a direct, fingerprint-addressed
                        // sendWs() — the exact "cut the direct fallback"
                        // pattern already fixed everywhere else (see
                        // sendAnonOrDirect() and the isFirst branch above),
                        // just never applied here. Confirmed via a live
                        // server log showing "[MSG] message delivered" (the
                        // top-level, non-anonymous "message" handler) during
                        // a period the same log showed this account's tokens
                        // repeatedly queued as offline — token pool was
                        // empty, so this branch leaked the real from/to
                        // fingerprint pair to the server for that message.
                        // Queue and retry via the token refill path instead,
                        // same as sendAnonOrDirect does for everything else —
                        // just route through it directly rather than
                        // duplicating its (synchronized) queuing logic here.
                        sendAnonOrDirect(to, packet)
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
        val pqKey = publicKeysPq[to]
        if (pqKey == null) {
            Log.w(TAG, "sendEncrypted: нет PQ-ключа для $to, запрашиваем бандл и откладываем")
            pendingMessages.getOrPut(to) { mutableListOf() }.add(Pair(to, text))
            requestPrekeyBundle(to)
            return
        }
        try {
            val encrypted = CryptoManager.encrypt(text, publicKey, pqKey)
            val signature = CryptoManager.sign(encrypted)
            // Routed the same as everything else now, instead of an
            // unconditional direct sendWs() — see docs/ISSUE_backup_identity_hijack.md,
            // "прямая адресация, не через анон-токен", item 3. sendAnonOrDirect
            // applies its own padding to whichever wrapper it actually sends
            // (anon_message or the queued packet later), so the packet here
            // is intentionally left unpadded.
            scope.launch(Dispatchers.IO) {
                sendAnonOrDirect(to, JSONObject().apply {
                    put("type", "message")
                    put("from", username)
                    put("to", to)
                    put("text", encrypted)
                    put("signature", signature)
                    put("id", id)
                    put("protocol_version", ProtocolVersion.LEGACY_VERSION)
                })
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendEncrypted error: ${e.message}")
        }
    }

    /** Full teardown for a deleted contact — see the comment on
     *  ChatStorage.deleteChat() for what was missing before this existed.
     *  Clears everything that would otherwise let a stale channel keep
     *  half-working after deletion: the in-memory key caches this running
     *  service instance holds (surviving a plain ChatStorage wipe, since
     *  that's on-disk only), the Double Ratchet session, and the mailbox
     *  tag (so a future mailbox deposit from this fingerprint is rejected
     *  by the existing mutual-add gate, same as any never-added sender). */
    fun forgetContact(contactId: String) {
        publicKeys.remove(contactId)
        publicKeysPq.remove(contactId)
        SessionKeyManager.deleteSession(contactId)
        AnonTokenManager.clearContactMailboxTag(this, contactId)
        // Found live while investigating "delete + fresh invite exchange
        // should behave exactly like first contact" — it didn't, because
        // this function stopped short of the token pool and bootstrap/health
        // bookkeeping below. A re-added contact (same fingerprint — it's
        // derived from their public key) would silently inherit leftover
        // tokens, resupply cooldowns, and ping-state timestamps from the
        // deleted relationship instead of starting clean.
        AnonTokenManager.clearContactTokens(this, contactId)
        ContactHealthManager.clearContact(this, contactId)
        tokensSentThisSession.remove(contactId)
        channelBootstrapStartedAt.remove(contactId)
        channelStuckNotified.remove(contactId)
        pendingChannelJobs.remove(contactId)?.cancel()
        pendingBundleRequests.remove(contactId)
    }

    fun sendVoice(to: String, voiceBase64: String, voiceId: String, duration: Int) {
        Log.i(TAG, "ОТПРАВЛЕНО voice $voiceId → $to @ ${System.currentTimeMillis()}")
        scope.launch(Dispatchers.IO) {
            try {
                val cachedKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also { publicKeys[to] = it }
                val cachedPqKey = publicKeysPq[to]
                if (cachedKey == null || cachedPqKey == null) {
                    Log.w(TAG, "sendVoice: нет ключа $to — запрашиваем")
                    requestPrekeyBundle(to)
                    pendingSessionMessages.getOrPut(to) { mutableListOf() }
                        .add("__voice__|${voiceId}|${duration}|$voiceBase64" to voiceId)
                    return@launch
                }
                val encrypted = CryptoManager.encrypt(voiceBase64, cachedKey, cachedPqKey)
                val signature = CryptoManager.sign(encrypted)
                sendAnonOrDirect(to, JSONObject().apply {
                    put("type", "voice")
                    put("from", username)
                    put("to", to)
                    put("voice_id", voiceId)
                    put("voice_data", encrypted)
                    put("signature", signature)
                    put("duration", duration)
                })
            } catch (e: Exception) {
                Log.e(TAG, "sendVoice error: ${e.message}")
            }
        }
    }

    private val lastTypingSentAt = mutableMapOf<String, Long>()

    /** Debounced to once per ~3s per contact — sent per-keystroke it would burn
     *  through the (finite, 50-slot) anon token pool almost instantly, since it
     *  routes through sendAnonOrDirect just like real messages. The receiving
     *  side already holds its "is typing" indicator for 3s regardless, so this
     *  debounce is invisible to the recipient. Proactive refill-on-low-pool is
     *  handled centrally inside sendAnonOrDirect() itself now — see its
     *  needsRefill()/shouldResupplyTokens() call, added after a burst send
     *  (batched video circle chunks) drained a pool with no early warning
     *  since this and other call sites each used to check it independently. */
    fun sendTyping(to: String) {
        if (!isConnected) return
        val now = System.currentTimeMillis()
        if (now - (lastTypingSentAt[to] ?: 0L) < 3_000L) return
        lastTypingSentAt[to] = now
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

    // No direct/fingerprint-addressed fallback here on purpose — see the
    // "cut the direct fallback" decision in docs/ISSUE_backup_identity_hijack.md.
    // An anonymity layer that silently degrades to non-anonymous the moment
    // its token pool runs dry only provides the illusion of the property it
    // claims. When no token is available, the packet is queued and a token
    // refill/mailbox bootstrap is kicked off instead of sending in the clear.
    private fun sendAnonOrDirect(to: String, packet: JSONObject) {
        val token = AnonTokenManager.consumeNextContactToken(this, to)
        if (token != null) {
            val anonPacket = JSONObject().apply {
                put("type", "anon_message")
                put("token", token)
                put("payload", packet)
            }
            sendWs(addPadding(anonPacket).toString())
            // Proactive early-warning refill — previously only wired into
            // sendWithForwardSecrecy() and sendTyping(), which don't cover
            // this function at all. Found live: a batched video circle send
            // (sendVideoCircle -> sendAnonOrDirect, ~10 tokens for a 60s
            // video after chunk batching) burned through the pool with zero
            // proactive signal, so the contact only found out once a send
            // actually failed — by then the token supply was already at
            // zero, not just low. REFILL_THRESHOLD (16 of ~20 per exchange)
            // means this fires after just a few consumptions, giving the
            // mutual-resupply round trip (sendAnonTokensTo -> their
            // reciprocal shouldResupplyTokens()) time to land before the
            // pool actually runs dry.
            if (AnonTokenManager.needsRefill(this, to) && shouldResupplyTokens(to)) {
                scope.launch(Dispatchers.IO) { sendAnonTokensTo(to) }
            }
        } else {
            val queueSize = synchronized(pendingAnonPackets) {
                pendingAnonPackets.getOrPut(to) { mutableListOf() }.add(packet)
                pendingAnonPackets[to]?.size ?: 0
            }
            Log.d(TAG, "DEBUG-BOOTSTRAP sendAnonOrDirect: нет токена для $to, поставлено в очередь (в очереди: $queueSize) type=${packet.optString("type")}")
            val shouldBootstrap = synchronized(lastTokenBootstrapAttempt) {
                val now = System.currentTimeMillis()
                val last = lastTokenBootstrapAttempt[to] ?: 0L
                if (now - last >= TOKEN_BOOTSTRAP_COOLDOWN_MS) {
                    lastTokenBootstrapAttempt[to] = now
                    true
                } else {
                    false
                }
            }
            if (shouldBootstrap) {
                scope.launch(Dispatchers.IO) { sendAnonTokensTo(to) }
            }
        }
    }

    /** Retries everything queued for [to] by sendAnonOrDirect() while its token
     *  pool was empty. Call after AnonTokenManager.addContactTokens(to, ...) —
     *  a no-op if nothing is queued. Packets that still can't get a token
     *  (pool refilled but not enough for the whole backlog) re-queue
     *  themselves via the same sendAnonOrDirect() call, so this is safe to
     *  call speculatively. */
    private fun flushPendingAnon(to: String) {
        val queued = synchronized(pendingAnonPackets) { pendingAnonPackets.remove(to) } ?: return
        queued.forEach { sendAnonOrDirect(to, it) }
    }

    fun sendReaction(to: String, messageId: String, emoji: String) {
        scope.launch(Dispatchers.IO) {
            try {
                val cachedKey = publicKeys[to] ?: return@launch
                val cachedPqKey = publicKeysPq[to] ?: return@launch
                val encrypted = CryptoManager.encrypt(emoji, cachedKey, cachedPqKey)
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
        val cachedPqKey = publicKeysPq[to] ?: return
        scope.launch(Dispatchers.IO) {
            try {
                val encrypted = CryptoManager.encrypt(newText, cachedKey, cachedPqKey)
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

    fun clearNotifLines(key: String) {
        notifLines.remove(key)
    }

    fun sendDeleteMessage(to: String, messageId: String) {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            sendAnonOrDirect(to, JSONObject().apply {
                put("type", "message_delete")
                put("from", username)
                put("to", to)
                put("message_id", messageId)
                put("signature", CryptoManager.sign(messageId))
            })
        }
    }

    fun sendGroupDeleteMessage(groupId: String, messageId: String, members: List<String>) {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            members.filter { it != username }.forEach { memberId ->
                sendAnonOrDirect(memberId, JSONObject().apply {
                    put("type", "group_message_delete")
                    put("from", username)
                    put("to", memberId)
                    put("group_id", groupId)
                    put("message_id", messageId)
                })
            }
        }
    }

    fun sendDisappearTimer(to: String, seconds: Long) {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            sendAnonOrDirect(to, JSONObject().apply {
                put("type", "disappear_timer")
                put("from", username)
                put("to", to)
                put("seconds", seconds)
                put("signature", CryptoManager.sign(seconds.toString()))
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

        val cachedPqKey = publicKeysPq[to]
        if (cachedKey == null || cachedPqKey == null) {
            synchronized(pendingImages) { pendingImages.add(PendingImage(to, chunks)) }
            Log.w(TAG, "sendImage: нет ключа для $to — запрашиваем, изображение в очереди")
            requestPrekeyBundle(to)
            return
        }

        val ackChannel = kotlinx.coroutines.channels.Channel<Int>(capacity = 1)
        imageChunkAcks[imageId] = ackChannel

        scope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Отправка изображения (${chunks.size} чанков)")

                val base64Data = chunks.joinToString("")
                val imageBytes = android.util.Base64.decode(base64Data, android.util.Base64.DEFAULT)

                val encryptedFileData = CryptoManager.encryptFile(imageBytes, cachedKey, cachedPqKey)
                val packedData = CryptoManager.packEncryptedFile(encryptedFileData)

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

    fun sendFile(to: String, fileName: String, chunks: List<String>, fileId: String) {
        if (!isConnected) {
            Log.w(TAG, "sendFile: не подключены к серверу")
            return
        }

        val cachedKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also {
            publicKeys[to] = it
        }

        val cachedPqKey = publicKeysPq[to]
        if (cachedKey == null || cachedPqKey == null) {
            synchronized(pendingFileSends) { pendingFileSends.add(PendingFileSend(to, fileName, chunks, fileId)) }
            Log.w(TAG, "sendFile: нет ключа для $to — запрашиваем, файл в очереди")
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

                val encryptedFileData = CryptoManager.encryptFile(fileBytes, cachedKey, cachedPqKey)
                val packedData = CryptoManager.packEncryptedFile(encryptedFileData)

                // File name encrypted with the same hybrid scheme as text
                // messages (self-contained, no session state needed) rather
                // than sent in the clear — see docs/ISSUE_backup_identity_hijack.md,
                // "file_name в открытом виде в file_chunk". Computed once and
                // reused across every chunk of this transfer, not recomputed
                // per chunk.
                val encryptedFileName = CryptoManager.encrypt(fileName, cachedKey, cachedPqKey)

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
                            put("encrypted_file_name", encryptedFileName)
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

    private suspend fun processVideoChunk(
        from: String, videoId: String, chunkIndex: Int, totalChunks: Int,
        chunkData: String, duration: Int, isEncrypted: Boolean, signature: String?
    ) {
        val senderKey = publicKeys[from]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                publicKeys[from] = it
            }

        if (signature == null || senderKey == null ||
            !CryptoManager.verifyChunk(chunkData, signature, senderKey, videoId, chunkIndex)) {
            Log.e(TAG, "⚠️ video_chunk неверная подпись от $from")
            return
        }

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
                val file = SecureFileStorage.blobFile(filesDir, videoId)
                SecureFileStorage.write(this@MessengerService, file, decryptedBytes)
                Log.i(TAG, "ПОЛУЧЕНО video_circle $videoId ← $from @ ${System.currentTimeMillis()}")
                withContext(Dispatchers.Main) {
                    onVideoReceived?.invoke(videoId, file, duration)
                }
            }
        }
    }

    fun sendVideoCircle(to: String, videoId: String, videoBytes: ByteArray, duration: Int, encFilePath: String = "") {
        Log.i(TAG, "ОТПРАВЛЕНО video_circle $videoId → $to @ ${System.currentTimeMillis()}")
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

        Log.d(TAG, "DEBUG-BOOTSTRAP sendVideoCircle: to=$to hasKey=${publicKeys[to] != null} hasPqKey=${publicKeysPq[to] != null} encFilePath=${encFilePath.isNotEmpty()}")

        val cachedKey = publicKeys[to]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also {
                publicKeys[to] = it
            }

        val cachedPqKey = publicKeysPq[to]
        if (cachedKey == null || cachedPqKey == null) {
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
                val encryptedFileData = CryptoManager.encryptFile(videoBytes, cachedKey, cachedPqKey)
                val packedData = CryptoManager.packEncryptedFile(encryptedFileData)

                val encryptedChunks = packedData.chunked(120_000)

                Log.d(TAG, "Видеокружок зашифрован: ${encryptedChunks.size} чанков")

                // Chunks are bundled CHUNK_BATCH_SIZE-at-a-time into a single
                // anon_message (see processVideoChunk's "video_chunk_batch"
                // handler) instead of one anon_message per chunk. Found live:
                // anon tokens are deliberately single-use server-side (the
                // whole point — a reusable token would let the server
                // correlate repeated deliveries to the same sender/recipient
                // pair), so a 117-chunk video used to burn 117 tokens from
                // the same small shared-with-this-contact pool (20 per
                // exchange) that ordinary text messages also draw from —
                // text sat queued behind the video for as long as it took
                // several slow mailbox-refill cycles to trickle in enough
                // tokens. 15 chunks × ~120KB ≈ 1.8MB per batch, comfortably
                // under the server's 6MB MAX_PACKET_SIZE_BYTES.
                val CHUNK_BATCH_SIZE = 15
                var interrupted = false
                encryptedChunks.chunked(CHUNK_BATCH_SIZE).forEachIndexed { batchIdx, batch ->
                    if (cancelledTransfers.contains(videoId)) return@forEachIndexed
                    // Found live: this loop used to keep firing chunks at its
                    // fixed pace even after the WebSocket dropped mid-send —
                    // each one silently lost (sendWs has nowhere to put it),
                    // so the receiver was stuck waiting on total_chunks that
                    // would never all arrive, AND a reconnect elsewhere in
                    // the app could trigger a full independent resend,
                    // doubling up traffic against the anon_message rate
                    // limit. Stop cleanly instead: bail out of this attempt
                    // and let the whole video re-queue for one clean resend
                    // once actually reconnected, rather than continuing to
                    // feed a dead connection.
                    if (!isConnected) {
                        interrupted = true
                        return@forEachIndexed
                    }
                    val chunksJson = org.json.JSONArray()
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * CHUNK_BATCH_SIZE + relIdx
                        val signature = CryptoManager.signChunk(chunk, videoId, index)
                        chunksJson.put(JSONObject().apply {
                            put("chunk_index", index)
                            put("data", chunk)
                            put("signature", signature)
                        })
                    }
                    sendAnonOrDirect(to, JSONObject().apply {
                        put("type", "video_chunk_batch")
                        put("from", username)
                        put("to", to)
                        put("video_id", videoId)
                        put("total_chunks", encryptedChunks.size)
                        put("duration", duration)
                        put("encrypted", true)
                        put("chunks", chunksJson)
                    })
                    delay(30)
                }

                if (interrupted) {
                    if (encFilePath.isNotEmpty()) {
                        synchronized(pendingVideoCircles) {
                            pendingVideoCircles.add(PendingVideoCircle(to, videoId, encFilePath, duration))
                        }
                        Log.w(TAG, "sendVideoCircle: соединение упало посреди отправки — $videoId поставлен в очередь на повтор")
                    } else {
                        Log.w(TAG, "sendVideoCircle: соединение упало посреди отправки, нет encFilePath — $videoId потерян")
                    }
                } else {
                    Log.d(TAG, "✅ Видеокружок $videoId отправлен: ${encryptedChunks.size} чанков")
                }

            } catch (e: Exception) {
                Log.e(TAG, "sendVideoCircle error: ${e.message}", e)
            } finally {
                videoChunkAcks.remove(videoId)
                cancelledTransfers.remove(videoId)
                ackChannel.close()
            }
        }
    }

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
        Log.d(TAG, "DEBUG-BOOTSTRAP flushPendingVideoCircles: forContact=$forContact toFlush=${toFlush.size}")
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

                    sendVideoCircle(pending.to, pending.videoId, plainBytes, pending.duration)
                } catch (e: Exception) {
                    Log.e(TAG, "flushPendingVideoCircles error: ${e.message}")
                }
            }
        }
    }

    private fun flushPendingImages(forContact: String? = null) {
        val toFlush = synchronized(pendingImages) {
            if (forContact != null) {
                val filtered = pendingImages.filter { it.to == forContact }
                pendingImages.removeAll { it.to == forContact }
                filtered
            } else {
                val all = pendingImages.toList()
                pendingImages.clear()
                all
            }
        }
        if (toFlush.isEmpty()) return
        Log.d(TAG, "flushPendingImages: отправляем ${toFlush.size} изображений (contact=$forContact)")
        toFlush.forEach { sendImage(it.to, it.chunks) }
    }

    private fun flushPendingFileSends(forContact: String? = null) {
        val toFlush = synchronized(pendingFileSends) {
            if (forContact != null) {
                val filtered = pendingFileSends.filter { it.to == forContact }
                pendingFileSends.removeAll { it.to == forContact }
                filtered
            } else {
                val all = pendingFileSends.toList()
                pendingFileSends.clear()
                all
            }
        }
        if (toFlush.isEmpty()) return
        Log.d(TAG, "flushPendingFileSends: отправляем ${toFlush.size} файлов (contact=$forContact)")
        toFlush.forEach { sendFile(it.to, it.fileName, it.chunks, it.fileId) }
    }

    fun flushPendingReactions() {
        val iterator = pendingReactions.iterator()
        while (iterator.hasNext()) {
            val (from, messageId, emoji) = iterator.next()
            onReactionReceived?.invoke(from, messageId, emoji)
            iterator.remove()
        }
    }

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

    private val MAX_BATCH_BUNDLE_TARGETS = 10

    /** Shared by both prekey_bundle_response and prekey_bundles_batch_response:
     *  parses [bundleJsonRaw] (or handles its absence), initiates X3DH, and
     *  flushes anything queued in pendingSessionMessages for [from] — sending
     *  session_init anonymously via the bundle's bootstrap token when present. */
    private suspend fun handleFetchedPrekeyBundle(from: String, bundleJsonRaw: JSONObject?) {
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
            // Captured once, before the try — both the success path and the
            // catch blocks below need the SAME queued list. Re-querying
            // pendingSessionMessages.remove(from) again inside a catch block
            // would find nothing (already removed here) and silently drop
            // messages that should have fallen back to legacy encryption.
            val queued = pendingSessionMessages.remove(from)
            try {
                val rawBundle = SessionKeyManager.parsePrekeyBundle(bundleJsonRaw)

                fun String.toStdB64() = replace('-', '+').replace('_', '/')
                val bundle = rawBundle.copy(
                    identityKey    = rawBundle.identityKey.toStdB64(),
                    signedPrekey   = rawBundle.signedPrekey.toStdB64(),
                    spkSignature   = rawBundle.spkSignature.toStdB64(),
                    oneTimePrekeys = rawBundle.oneTimePrekeys.map { opk ->
                        val ci = opk.indexOf(':')
                        if (ci >= 0) "${opk.substring(0, ci + 1)}${opk.substring(ci + 1).toStdB64()}"
                        else opk.toStdB64()
                    },
                    pqKemPublicKey = rawBundle.pqKemPublicKey.toStdB64(),
                    pqKemSignature = rawBundle.pqKemSignature.toStdB64()
                )

                publicKeys[from] = bundle.identityKey
                publicKeysPq[from] = android.util.Base64.decode(bundle.pqKemPublicKey, android.util.Base64.NO_WRAP)
                ChatStorage.saveContactPublicKey(this@MessengerService, from, bundle.identityKey)
                if (KeyHistoryManager.checkKeyChange(this@MessengerService, from, bundle.identityKey)) {
                    Log.w(TAG, "⚠️ TOFU: ключ контакта $from изменился при получении bundle!")
                    withContext(Dispatchers.Main) { onKeyChanged?.invoke(from) }
                }
                Log.d(TAG, "Публичный ключ из bundle сохранён: $from")

                // Found live: this used to `return` right here when nothing was
                // queued in pendingSessionMessages, on the reasoning that an X3DH
                // session with nothing to transmit would burn one of the peer's
                // OPKs for no reason. True — but the early return also skipped the
                // flushPendingVideoCircles()/flushPendingImages()/
                // flushPendingFileSends() calls at the bottom of this function,
                // which is exactly what a video circle / image / file send is
                // waiting on. Those never touch pendingSessionMessages at all (only
                // sendWithForwardSecrecy's queued-text path does), so a video-only
                // key fetch always hit this branch and its flush never happened —
                // the fetched key just sat cached, unused. Skip only the X3DH
                // init+send when nothing is queued; still fall through to flush.
                if (!queued.isNullOrEmpty()) {
                    val (_, x3dhHeader) = SessionKeyManager.initiateSession(from, bundle)
                    Log.d(TAG, "X3DH сессия с $from инициирована")
                    markChannelReady(from)
                    withContext(Dispatchers.Main) { onChannelReady?.invoke(from) }

                    queued.forEach { (text, msgId) ->
                        if (text.startsWith("__voice__|")) {
                            val parts = text.removePrefix("__voice__|").split("|", limit = 3)
                            sendVoice(from, parts[2], parts[0], parts[1].toIntOrNull() ?: 0)
                        } else {
                            sendWithForwardSecrecy(from, text, msgId, x3dhHeader, isFirst = true, bootstrapToken = bundle.bootstrapToken)
                        }
                    }
                }
            } catch (e: SecurityException) {
                Log.e(TAG, "X3DH FAIL с $from: ${e.message}")

                queued?.forEach { (text, msgId) ->
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

                queued?.forEach { (text, msgId) ->
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

        Log.d(TAG, "DEBUG-BOOTSTRAP handleFetchedPrekeyBundle: flushing pending sends for $from")
        flushPendingVideoCircles(from)
        flushPendingImages(from)
        flushPendingFileSends(from)
    }

    /** Fetches [contactId]'s prekey bundle. Uses the anonymous batched fetch
     *  (real target padded with decoys drawn from our own contacts, mirroring
     *  the anonymous-mailbox fake-tag pattern in AnonTokenManager) whenever we
     *  have at least one other contact to use as a decoy — a batch of size 1
     *  provides no cover, so a lone/contact-less new install falls back to the
     *  direct, non-anonymous fetch instead of pretending otherwise. */
    private fun requestPrekeyBundle(contactId: String) {
        val decoys = ChatStorage.getContacts(this).filter { it != contactId }
        pendingBundleRequests.add(contactId)
        scope.launch(Dispatchers.IO) {
            if (decoys.isNotEmpty()) {
                val batch = (decoys.shuffled().take(MAX_BATCH_BUNDLE_TARGETS - 1) + contactId).shuffled()
                sendWs(JSONObject().apply {
                    put("type", "get_prekey_bundles_batch")
                    put("targets", org.json.JSONArray(batch))
                }.toString())
            } else {
                sendWs(JSONObject().apply {
                    put("type", "get_prekey_bundle")
                    put("target", contactId)
                }.toString())
            }
        }
    }

    // ── Channel establishment (auto token bootstrap) ────────────────────────────
    // A fresh contact (added via invite code) can't be anonymously messaged until
    // both sides have exchanged AnonTokenManager token pools — and that exchange
    // itself can only be kicked off via the mailbox (it's the one path that needs
    // no pre-existing token, just the invite-code-derived tag + the contact's
    // public key). Waiting for the user to type a real first message to trigger
    // this is bad UX (their message may sit "connecting" for no visible reason)
    // and risky (if it falls through to a non-anonymous path meanwhile, the
    // server sees the real fingerprint pair for that first exchange). Instead,
    // this deposits tokens the moment a contact is added, invisibly, and keeps
    // retrying until confirmed — the UI shows a plain "connecting" state and only
    // allows sending once isChannelReady() is true.
    private val pendingChannelJobs = mutableMapOf<String, Job>()
    private val channelBootstrapStartedAt = mutableMapOf<String, Long>()
    private val channelStuckNotified = mutableSetOf<String>()
    private val CHANNEL_STUCK_THRESHOLD_MS = 5 * 60 * 1000L
    var onChannelReady: ((contact: String) -> Unit)? = null

    /** True once this contact can be messaged anonymously (or was never a
     *  mailbox-bootstrapped contact to begin with — e.g. restored from backup). */
    fun isChannelReady(contact: String): Boolean {
        val mailboxTag = AnonTokenManager.getContactMailboxTag(this, contact) ?: return true
        return AnonTokenManager.getContactTokens(this, contact).isNotEmpty() ||
            SessionKeyManager.hasSession(contact)
    }

    private fun depositTokensViaMailbox(contact: String, mailboxTag: String, publicKey: String) {
        val tokens = AnonTokenManager.tokensToShareWith(this@MessengerService)
        Log.d(TAG, "DEBUG-BOOTSTRAP depositTokensViaMailbox: contact=$contact tag=$mailboxTag tokens=${tokens.size}")
        if (tokens.isEmpty()) return
        try {
            val inner = JSONObject().apply {
                put("from", username)
                put("name", UserStorage.getUsername(this@MessengerService))
                put("text", "__beacon_tokens_only__")
                put("tokens", org.json.JSONArray(tokens))
                put("mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag(this@MessengerService))
                put("id", UUID.randomUUID().toString())
            }.toString()
            val blob = CryptoManager.encryptClassicalOnly(inner, publicKey)
            sendWs(addPadding(JSONObject().apply {
                put("type", "mailbox_put")
                put("tag", mailboxTag)
                put("blob", blob)
            }).toString())
            Log.d(TAG, "DEBUG-BOOTSTRAP mailbox_put sent for $contact")
        } catch (e: Exception) {
            Log.e(TAG, "depositTokensViaMailbox: $contact — ${e.message}")
        }
    }

    private fun attemptChannelBootstrap(contact: String) {
        val mailboxTag = AnonTokenManager.getContactMailboxTag(this, contact)
        val publicKey = publicKeys[contact] ?: ChatStorage.getContactPublicKey(this, contact)
        Log.d(TAG, "DEBUG-BOOTSTRAP attemptChannelBootstrap: contact=$contact tag=$mailboxTag hasKey=${publicKey != null}")
        if (mailboxTag == null || publicKey == null) return
        depositTokensViaMailbox(contact, mailboxTag, publicKey)
    }

    /** Call right after adding a contact (invite-code flow), and again whenever
     *  the user opens a chat with a still-pending contact — safe to call
     *  repeatedly, a retry loop only ever runs once per contact at a time.
     *  Retries indefinitely (no upper bound — a transient issue can still
     *  self-resolve later) but after CHANNEL_STUCK_THRESHOLD_MS (5 minutes)
     *  without success, fires a one-time user-visible notification and a
     *  minimal diagnostic "ticket" to the server (see
     *  docs/ISSUE_backup_identity_hijack.md, "5-минутный ретрай"). Not an
     *  automated report *to the developer directly* — deliberately not
     *  hardcoded contact info for that, per the decision this was built
     *  from — just a clearly-tagged server log line the operator can find
     *  later via ForEXP/admin_logs.py while investigating. */
    fun bootstrapChannelFor(contact: String) {
        if (isChannelReady(contact)) return
        scope.launch(Dispatchers.IO) { attemptChannelBootstrap(contact) }
        if (pendingChannelJobs.containsKey(contact)) return
        channelBootstrapStartedAt.putIfAbsent(contact, System.currentTimeMillis())
        pendingChannelJobs[contact] = scope.launch(Dispatchers.IO) {
            for (d in longArrayOf(30_000L, 30_000L, 30_000L)) {
                delay(d)
                if (isChannelReady(contact)) { pendingChannelJobs.remove(contact); return@launch }
                attemptChannelBootstrap(contact)
                checkChannelStuck(contact)
            }
            while (isActive && !isChannelReady(contact)) {
                delay(90_000L)
                if (isChannelReady(contact)) break
                attemptChannelBootstrap(contact)
                checkChannelStuck(contact)
            }
            pendingChannelJobs.remove(contact)
        }
    }

    private fun checkChannelStuck(contact: String) {
        if (contact in channelStuckNotified) return
        val startedAt = channelBootstrapStartedAt[contact] ?: return
        if (System.currentTimeMillis() - startedAt < CHANNEL_STUCK_THRESHOLD_MS) return
        channelStuckNotified.add(contact)

        Log.w(TAG, "bootstrapChannelFor: $contact всё ещё не готов спустя 5 минут")
        showChannelStuckNotification(contact)

        // Deliberately no contact/target identifier in this packet — that
        // would leak exactly the metadata (who's trying to reach whom) the
        // whole mailbox scheme exists to hide. Just "this account hit a
        // stuck first-contact bootstrap", nothing more.
        sendWs(JSONObject().apply {
            put("type", "bootstrap_diagnostic")
            put("from", username)
        }.toString())
    }

    private fun showChannelStuckNotification(contact: String) {
        val displayName = ChatStorage.getContactName(this, contact).takeIf { it.isNotBlank() } ?: contact
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("open_chat", contact)
        }
        val pending = PendingIntent.getActivity(
            this, ("channel_stuck_$contact").hashCode(),
            intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notifId = (contact.hashCode() and 0x7FFFFFFF) + 4000
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(s.notifChannelStuckTitle)
            .setContentText(s.notifChannelStuckText(displayName))
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        getSystemService(NotificationManager::class.java).notify(notifId, notification)
    }

    private fun markChannelReady(contact: String) {
        pendingChannelJobs.remove(contact)?.cancel()
        channelBootstrapStartedAt.remove(contact)
        channelStuckNotified.remove(contact)
    }

    private suspend fun sendAnonTokensTo(contact: String) {
        val tokens = AnonTokenManager.tokensToShareWith(this@MessengerService)
        if (tokens.isEmpty()) return

        val recipientKey = publicKeys[contact]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, contact)?.also { publicKeys[contact] = it }
        val recipientPqKey = publicKeysPq[contact]

        // anon_message requires a hybrid (classical+PQ) encryption key for the recipient.
        // A brand-new contact whose channel was established purely via mailbox (no
        // X3DH/prekey-bundle exchange has happened yet) won't have a cached PQ key —
        // checked BEFORE consuming an anon token below, so a doomed send doesn't burn
        // one for nothing. Falls back to mailbox, which only needs the classical key.
        if (recipientPqKey == null) {
            val mailboxTag = AnonTokenManager.getContactMailboxTag(this@MessengerService, contact)
            if (mailboxTag != null && recipientKey != null) {
                Log.d(TAG, "sendAnonTokensTo: нет PQ-ключа для $contact — бутстрап токенов через mailbox")
                depositTokensViaMailbox(contact, mailboxTag, recipientKey)
            } else {
                Log.d(TAG, "sendAnonTokensTo: нет токенов/ключей для $contact, ждём mailbox-обмена")
            }
            return
        }

        // allowReserve=true — this IS the resupply message the reserve exists
        // to protect. Every other consumer (sendAnonOrDirect, the ordinary
        // sendWithForwardSecrecy path) uses the default false.
        val anonToken = AnonTokenManager.consumeNextContactToken(this@MessengerService, contact, allowReserve = true)
        if (anonToken == null) {
            // Bootstrapping tokens via anon_message is circular: sending my tokens
            // this way requires a token FROM this contact, which they can only ever
            // give me the same way. The one way to break the cycle is mailbox — but
            // send()'s mailbox branch only fires while `!SessionKeyManager.hasSession(to)`,
            // so if a session got established some other way (e.g. both sides raced
            // to fetch each other's prekey bundle) before mailbox had a chance to run
            // even once, this contact's token pool could otherwise never bootstrap —
            // not "hasn't happened yet", but structurally can't happen. Fall back to
            // the same mailbox bootstrap used on contact-add (see bootstrapChannelFor).
            val mailboxTag = AnonTokenManager.getContactMailboxTag(this@MessengerService, contact)
            if (mailboxTag != null && recipientKey != null) {
                Log.d(TAG, "sendAnonTokensTo: нет anon-токена для $contact — бутстрап токенов через mailbox")
                depositTokensViaMailbox(contact, mailboxTag, recipientKey)
            } else {
                Log.d(TAG, "DEBUG-BOOTSTRAP sendAnonTokensTo: нет токенов для $contact, ждём mailbox-обмена — mailboxTag=${mailboxTag != null} recipientKey=${recipientKey != null} hasSession=${SessionKeyManager.hasSession(contact)}")
            }
            return
        }
        if (recipientKey == null) {
            // Deliberately NOT calling requestPrekeyBundle() here: handleFetchedPrekeyBundle()
            // unconditionally calls SessionKeyManager.initiateSession() once a bundle arrives,
            // regardless of whether anything is actually queued to send. Since this call site
            // never queues into pendingSessionMessages, that would silently create local X3DH
            // session state (consuming one of the peer's OPKs) without ever transmitting a
            // session_init to the peer — leaving the two sides desynchronized until a real
            // message later collides with the orphaned session and forces a session_reset
            // round-trip. Every call site of sendAnonTokensTo() runs right after a message was
            // just sent or received with this contact, so publicKeys[contact] is normally
            // already populated by then; if not, this just retries on the next message.
            Log.w(TAG, "sendAnonTokensTo: нет ключа для $contact, пропускаем — попробуем при следующем сообщении")
            return
        }
        // Piggybacks my persistent mailbox tag on every token exchange — see
        // AnonTokenManager.getOrCreateMyPersistentMailboxTag(), the tag
        // freshness fix. Nearly free: this message already goes out.
        val tokenPayload = JSONObject().apply {
            put("tokens", org.json.JSONArray(tokens))
            put("mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag(this@MessengerService))
        }
        val systemText = "__beacon_tokens__:$tokenPayload"
        val encrypted = CryptoManager.encrypt(systemText, recipientKey, recipientPqKey)
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

        val allMyTokens = AnonTokenManager.ensureMyTokenPool(this@MessengerService)
        sendWs(JSONObject().apply {
            put("type", "subscribe_tokens")
            put("tokens", org.json.JSONArray(allMyTokens))
        }.toString())
        Log.d(TAG, "Отправлены анонимные токены → $contact через anon_message")
    }

    /** True once WE'VE explicitly added this fingerprint (redeemed their
     * invite code — ChatsScreen's redeem flow calls ChatStorage.addContact()
     * synchronously before anything else, so by the time any message could
     * legitimately arrive they're already on the list) and haven't since
     * deleted them (deleteChat() removes them). Deliberately checking list
     * membership rather than AnonTokenManager.getContactMailboxTag(from) —
     * that tag can legitimately go null for an active, still-added contact
     * for unrelated reasons (an old-shape token exchange with no tag field
     * clears it, see handleIncomingDecryptedMessage's __beacon_tokens__
     * branch) and gating regular messages on it would silently break an
     * ongoing conversation, not just block resurrection.
     *
     * Found live: after deleting a contact on both sides, a message that was
     * already mid-flight (queued server-side, or a session that hadn't
     * finished tearing down — a race between the UI's delete action and
     * forgetContact() actually completing) could still decrypt successfully
     * and silently resurrect the contact via ChatStorage.addContact() below,
     * using whatever stale name it carried — "the old contact reappeared"
     * right after a clean delete. */
    private fun isMutuallyAdded(from: String): Boolean =
        ChatStorage.getContacts(this).contains(from)

    private suspend fun handleIncomingDecryptedMessage(from: String, decryptedText: String, messageId: String?, json: JSONObject) {
        ContactHealthManager.recordIncoming(this@MessengerService, from)
        if (!isMutuallyAdded(from)) {
            Log.d(TAG, "message от $from проигнорировано — контакт не добавлен взаимно")
            return
        }
        if (decryptedText.startsWith("__beacon_tokens__:")) {
            try {
                val raw = decryptedText.removePrefix("__beacon_tokens__:")
                // New shape is a JSON object (tokens + mailbox_tag); falls back
                // to the old bare-array shape for an unpatched peer mid-rollout.
                val objAttempt = runCatching { org.json.JSONObject(raw) }.getOrNull()
                val tokensJsonArr = objAttempt?.getJSONArray("tokens") ?: org.json.JSONArray(raw)
                val tokens = (0 until tokensJsonArr.length()).map { tokensJsonArr.getString(it) }
                val freshTag = objAttempt?.optString("mailbox_tag", null)
                AnonTokenManager.addContactTokens(this@MessengerService, from, tokens)
                flushPendingAnon(from)

                // Refreshed to the sender's persistent tag instead of cleared —
                // see AnonTokenManager.getOrCreateMyPersistentMailboxTag(),
                // "tag freshness" fix. Without this, getContactMailboxTag(from)
                // goes permanently null after the very first bootstrap, and
                // both the session_init mailbox fallback and the health-check
                // protocol below silently stop having anything to fall back to
                // for any contact past that point.
                if (freshTag != null) {
                    AnonTokenManager.setContactMailboxTag(this@MessengerService, from, freshTag)
                } else {
                    AnonTokenManager.clearContactMailboxTag(this@MessengerService, from)
                }
                ChatStorage.addContact(this@MessengerService, from)
                Log.d(TAG, "Получены анонимные токены от $from: ${tokens.size} шт.")
                if (shouldResupplyTokens(from)) {
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
        Log.i(TAG, "ПОЛУЧЕНО message ${messageId ?: "?"} ← $from @ ${System.currentTimeMillis()}")

        if (messageId != null) {
            sendAnonOrDirect(from, JSONObject().apply {
                put("type", "delivered")
                put("from", username)
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

    /** "Забота о собеседнике" — checked once a minute per contact while
     * connected. See ContactHealthManager and
     * docs/ISSUE_backup_identity_hijack.md for the full design. Two stages:
     * (1) on first detected silence, ping — consumes a real contact token
     * if one exists (delivered normally), or falls through sendAnonOrDirect's
     * existing queue-and-bootstrap cascade if not (which itself already
     * attempts a mailbox token deposit — this is the "I'm the dry one"
     * case). (2) if still silent after a wait with no pong, one explicit
     * mailbox deposit of a fresh token batch, addressed to the contact's
     * current (now never-stale, see the tag-freshness fix) mailbox tag —
     * covers "they're the dry one and my ping never reached them a
     * different way". No third stage: after that, this contact is left
     * alone until real traffic resumes, matching the design's "one-off,
     * not a loop" requirement — the always-running pollMailbox() loop
     * above remains the ambient backstop for any deposit meant for us.
     */
    private fun checkContactSilence() {
        ChatStorage.getContacts(this).forEach { contactId ->
            if (!ContactHealthManager.isSilent(this, contactId)) return@forEach

            when (ContactHealthManager.getState(this, contactId)) {
                ContactHealthManager.PingState.NONE -> {
                    Log.d(TAG, "contact-health: $contactId молчит ${ContactHealthManager.SILENCE_THRESHOLD_MS / 60_000} мин — пингуем")
                    sendAnonOrDirect(contactId, JSONObject().apply {
                        put("type", "contact_ping")
                        put("from", username)
                        put("to", contactId)
                        put("id", UUID.randomUUID().toString())
                    })
                    ContactHealthManager.setState(this, contactId, ContactHealthManager.PingState.PINGED)
                }

                ContactHealthManager.PingState.PINGED -> {
                    if (ContactHealthManager.stateElapsedMs(this, contactId) < ContactHealthManager.MAILBOX_RETRY_WAIT_MS) {
                        return@forEach
                    }
                    val mailboxTag = AnonTokenManager.getContactMailboxTag(this, contactId)
                    val recipientKey = publicKeys[contactId] ?: ChatStorage.getContactPublicKey(this, contactId)
                    if (mailboxTag != null && recipientKey != null) {
                        Log.d(TAG, "contact-health: $contactId не ответил на pong-ожидание — один запасной депозит токенов через mailbox")
                        depositTokensViaMailbox(contactId, mailboxTag, recipientKey)
                    } else {
                        Log.d(TAG, "contact-health: $contactId — нет mailbox-тега/ключа для запасного депозита, сдаёмся")
                    }
                    ContactHealthManager.setState(this, contactId, ContactHealthManager.PingState.MAILBOX_TRIED)
                }

                ContactHealthManager.PingState.MAILBOX_TRIED -> { /* one-off — nothing further until real traffic resumes */ }
            }
        }
    }

    fun sendViaMailbox(to: String, text: String, publicKey: String, mailboxTag: String, messageId: String? = null) {
        val id = messageId ?: java.util.UUID.randomUUID().toString()
        MessageQueue.remove(this, id)
        scope.launch(Dispatchers.IO) {
            try {

                val myTokens = AnonTokenManager.tokensToShareWith(this@MessengerService)
                val inner = JSONObject().apply {
                    put("from", username)
                    put("text", text)
                    put("tokens", org.json.JSONArray(myTokens))
                    put("id", id)
                }.toString()
                val blob = CryptoManager.encryptClassicalOnly(inner, publicKey)
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

    /** Shared by the direct "session_init" dispatch case and by
     * handleMailboxResult's session_init_packet handling — same processing
     * either way, only the transport differs. */
    private suspend fun processSessionInit(json: JSONObject) {
        val from = json.getString("from")
        val senderIk = json.getString("sender_ik")
        val x3dhHeader = json.getJSONObject("x3dh_header")
        val encryptedText = json.getString("text")
        val signature = json.optString("signature", null)
        val messageId = json.optString("id", null)
        try {
            val fixedSenderIk = senderIk.replace('-', '+').replace('_', '/')
            publicKeys[from] = fixedSenderIk
            ChatStorage.saveContactPublicKey(this@MessengerService, from, fixedSenderIk)
            if (KeyHistoryManager.checkKeyChange(this@MessengerService, from, fixedSenderIk)) {
                Log.w(TAG, "⚠️ TOFU: ключ контакта $from изменился в session_init!")
                withContext(Dispatchers.Main) { onKeyChanged?.invoke(from) }
            }
            Log.d(TAG, "Публичный ключ из session_init сохранён: $from")

            val senderKey = publicKeys[from]!!

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

            if (AnonTokenManager.getContactTokens(this@MessengerService, from).isEmpty() &&
                AnonTokenManager.getMyTokens(this@MessengerService).isNotEmpty()) {
                scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
            }

            pendingSessionMessages.remove(from)?.forEach { (text, msgId) ->
                if (text.startsWith("__voice__|")) {
                    val parts = text.removePrefix("__voice__|").split("|", limit = 3)
                    sendVoice(from, parts[2], parts[0], parts[1].toIntOrNull() ?: 0)
                } else {
                    scope.launch(Dispatchers.IO) { sendWithForwardSecrecy(from, text, msgId) }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "session_init error: ${e.message}")

            requestPrekeyBundle(from)
            sendAnonOrDirect(from, JSONObject().apply {
                put("type", "session_reset")
                put("from", username)
                put("to", from)
            })
        }
    }

    /** Delivers a full session_init sub-packet (x3dh header + forward-secrecy
     * ciphertext) anonymously via mailbox when no anon/bootstrap token is
     * available — see the isFirst branch in sendWithForwardSecrecy() and
     * handleMailboxResult's session_init_packet handling on the receiving
     * end, which routes it through the exact same processSessionInit() as a
     * direct delivery. */
    private fun depositSessionInitViaMailbox(to: String, mailboxTag: String, publicKey: String, sessionInitPacket: JSONObject) {
        scope.launch(Dispatchers.IO) {
            try {
                val inner = JSONObject().apply {
                    put("from", username)
                    put("name", UserStorage.getUsername(this@MessengerService))
                    put("text", "__beacon_session_init__")
                    put("session_init_packet", sessionInitPacket)
                    put("id", UUID.randomUUID().toString())
                }.toString()
                val blob = CryptoManager.encryptClassicalOnly(inner, publicKey)
                sendWs(addPadding(JSONObject().apply {
                    put("type", "mailbox_put")
                    put("tag", mailboxTag)
                    put("blob", blob)
                }).toString())
            } catch (e: Exception) {
                Log.e(TAG, "depositSessionInitViaMailbox: $to — ${e.message}")
            }
        }
    }

    /** Drops a mailbox tag from the poll list once it's served its purpose —
     * but never the account's own persistent tag (getOrCreateMyPersistentMailboxTag).
     * Found live: this used to run unconditionally, so the very first
     * successful deposit into a fresh contact's persistent tag removed that
     * tag from their own poll list — any later bootstrap attempt (e.g. after
     * a delete+re-add, or a dropped channel retrying) silently vanished into
     * a tag nobody was listening for anymore. The persistent tag is meant to
     * be reused indefinitely; only one-off/legacy tags should be pruned. */
    private fun removeMailboxTagIfEphemeral(tag: String) {
        if (tag == AnonTokenManager.getOrCreateMyPersistentMailboxTag(this)) return
        AnonTokenManager.removeMyMailboxTag(this, tag)
    }

    private suspend fun handleMailboxResult(json: org.json.JSONObject) {
        val blobsMap = json.optJSONObject("blobs") ?: return
        Log.d(TAG, "DEBUG-BOOTSTRAP handleMailboxResult: tags=${blobsMap.keys().asSequence().toList()}")
        blobsMap.keys().forEach { tag ->
            val arr = blobsMap.optJSONArray(tag) ?: return@forEach
            Log.d(TAG, "DEBUG-BOOTSTRAP tag=$tag blobCount=${arr.length()}")
            for (i in 0 until arr.length()) {
                val blob = arr.optString(i) ?: continue
                try {
                    val inner = CryptoManager.decryptClassicalOnly(blob)
                    val innerJson = org.json.JSONObject(inner)
                    val from = innerJson.getString("from")

                    // Spam gate: mailbox deposits are reachable by anyone who has
                    // your invite code, which isn't the same as *you* having chosen
                    // to add *them* — the original design was that a message never
                    // reaches the user unless the user added the sender back
                    // themselves (mutual/reciprocal add), otherwise it's dropped
                    // outright. getContactMailboxTag(from) is only ever set by the
                    // "add contact via invite code" flow, so its presence is exactly
                    // the signal that this recipient independently redeemed the
                    // sender's invite code too — not just the other way around.
                    if (AnonTokenManager.getContactMailboxTag(this@MessengerService, from) == null) {
                        Log.d(TAG, "mailbox: депозит от $from проигнорирован — контакт не добавлен взаимно")
                        continue
                    }

                    val sessionInitPacket = innerJson.optJSONObject("session_init_packet")
                    if (sessionInitPacket != null) {
                        removeMailboxTagIfEphemeral(tag)
                        processSessionInit(sessionInitPacket)
                        continue
                    }

                    val text = innerJson.getString("text")
                    val msgId = innerJson.optString("id")
                    val tokensArr = innerJson.optJSONArray("tokens")
                    if (tokensArr != null) {
                        val tokens = (0 until tokensArr.length()).map { tokensArr.getString(it) }
                        AnonTokenManager.addContactTokens(this@MessengerService, from, tokens)
                        flushPendingAnon(from)
                        markChannelReady(from)
                        // Same tag-freshness refresh as the anon_message token
                        // path — a mailbox-delivered token batch can carry it too.
                        innerJson.optString("mailbox_tag", null)?.let { freshTag ->
                            AnonTokenManager.setContactMailboxTag(this@MessengerService, from, freshTag)
                        }
                        withContext(Dispatchers.Main) { onChannelReady?.invoke(from) }
                        if (shouldResupplyTokens(from)) {
                            scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
                        }
                    }

                    removeMailboxTagIfEphemeral(tag)

                    ChatStorage.addContact(this@MessengerService, from)
                    // A mailbox deposit auto-creates the contact (mutual add: if
                    // someone adds you, you see them too) — but until now it never
                    // carried a display name, so it showed up nameless until the
                    // user separately redeemed that contact's invite code, which
                    // does carry a name. Only set it if empty, to not clobber a
                    // name the user may have already customized.
                    innerJson.optString("name").takeIf { it.isNotBlank() }?.let { name ->
                        if (ChatStorage.getContactName(this@MessengerService, from).isBlank()) {
                            ChatStorage.saveContactName(this@MessengerService, from, name)
                        }
                    }
                    if (!text.startsWith("__beacon_")) {
                        val storedId = msgId.ifEmpty { java.util.UUID.randomUUID().toString() }
                        ChatStorage.saveOrUpdateMessage(
                            this@MessengerService,
                            UserStorage.getUserId(this@MessengerService),
                            from,
                            ChatStorage.StoredMessage(id = storedId, text = text, isOwn = false)
                        )
                        Log.i(TAG, "ПОЛУЧЕНО message $storedId ← $from @ ${System.currentTimeMillis()}")
                        withContext(Dispatchers.Main) { onMessageReceived?.invoke(from, text) }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "DEBUG-BOOTSTRAP handleMailboxResult decrypt/process failed for tag=$tag: ${e.message}", e)
                }
            }
        }
    }

    fun isOnline() = isConnected

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.deleteNotificationChannel(CHANNEL_ID)
            val channel = NotificationChannel(CHANNEL_ID, "Subrosa Emergency", NotificationManager.IMPORTANCE_HIGH).apply {
                description = s.notifChannelDesc
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setShowBadge(true)
                enableVibration(true)
                enableLights(true)
            }
            nm.createNotificationChannel(channel)

            val serviceChannel = NotificationChannel(
                CHANNEL_ID_SERVICE,
                "Subrosa Service",
                NotificationManager.IMPORTANCE_MIN
            ).apply {
                description = "Фоновый сервис Subrosa"
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
            .setContentTitle("💬 Subrosa Messenger")
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pending)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
    }

    private fun showSessionConflictNotification(conflictTsSeconds: Double = Double.NaN) {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pending = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        // A timestamp is the one piece of context that doesn't require trusting
        // the server further than it's already trusted to relay this event at
        // all — it doesn't reveal anything the server didn't already know
        // (when it kicked this session), but it's the difference between the
        // user reasoning in a total vacuum and knowing roughly when this
        // happened, e.g. to rule out "oh, that was just me reinstalling".
        val text = if (!conflictTsSeconds.isNaN()) {
            val when_ = java.text.SimpleDateFormat("dd MMM, HH:mm", java.util.Locale.getDefault())
                .format(java.util.Date((conflictTsSeconds * 1000).toLong()))
            "${s.notifSessionText} ($when_)"
        } else {
            s.notifSessionText
        }
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(s.notifSessionTitle)
            .setContentText(text)
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
        val notifId = (from.hashCode() and 0x7FFFFFFF) + 1000

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
        val hideContent = UserStorage.getHideNotificationContent(this)
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
            .setContentTitle(if (hideContent) s.notifNewMessage else "📢 $channelName")
            .setContentText(if (hideContent) s.notifTapToRead else text)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .setVisibility(if (hideContent) NotificationCompat.VISIBILITY_PRIVATE else NotificationCompat.VISIBILITY_PUBLIC)
            .build()
        getSystemService(NotificationManager::class.java).notify(System.currentTimeMillis().toInt(), notification)
    }

    private fun showGroupMessageNotification(groupId: String, senderName: String, text: String) {
        val hideContent = UserStorage.getHideNotificationContent(this)
        val group = GroupManager.getGroup(this, groupId)
        val groupName = group?.name ?: s.notifGroupFallback
        val notifId = (groupId.hashCode() and 0x7FFFFFFF) + 2000

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
        val emergencyIntent = Intent("com.subrosa.messenger.EMERGENCY_WIPE").apply { setPackage(packageName) }
        val emergencyPending = PendingIntent.getBroadcast(this, 999, emergencyIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val fullScreenIntent = Intent(this, MainActivity::class.java)
        val fullScreenPending = PendingIntent.getActivity(this, 0, fullScreenIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Subrosa")
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

    fun createGroup(
        groupId: String,
        groupName: String,
        groupAvatar: String,
        members: List<String>,
        groupKey: ByteArray,
        allMembers: List<String> = members + username,
        admins: List<String> = listOf(username)
    ) {
        if (!isConnected) {
            Log.w(TAG, "createGroup: не подключены к серверу")
            return
        }

        scope.launch(Dispatchers.IO) {
            try {
                val rosterSignature = CryptoManager.sign(rosterPayload(groupId, allMembers, admins))
                members.forEach { memberId ->
                    val memberPublicKey = publicKeys[memberId]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, memberId)?.also {
                            publicKeys[memberId] = it
                        }

                    val memberPqKey = publicKeysPq[memberId]
                    if (memberPublicKey != null && memberPqKey != null) {

                        val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, memberPublicKey, memberPqKey)
                        val signature = CryptoManager.sign(encryptedGroupKey)

                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_create")
                            put("from", username)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("group_name", groupName)
                            put("group_avatar", groupAvatar)
                            put("encrypted_group_key", encryptedGroupKey)
                            put("signature", signature)
                            put("members", JSONArray(allMembers))
                            put("admins", JSONArray(admins))
                            put("roster_signature", rosterSignature)
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

    fun addGroupMember(
        groupId: String,
        groupName: String,
        groupAvatar: String,
        newMemberId: String,
        newMemberName: String,
        groupKey: ByteArray,
        allMembers: List<String>,
        admins: List<String>
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

                val memberPqKey = publicKeysPq[newMemberId]
                if (memberPublicKey != null && memberPqKey != null) {
                    val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, memberPublicKey, memberPqKey)
                    val signature = CryptoManager.sign(encryptedGroupKey)
                    val rosterSignature = CryptoManager.sign(rosterPayload(groupId, allMembers, admins))

                    sendAnonOrDirect(newMemberId, JSONObject().apply {
                        put("type", "group_create")
                        put("from", username)
                        put("to", newMemberId)
                        put("group_id", groupId)
                        put("group_name", groupName)
                        put("group_avatar", groupAvatar)
                        put("encrypted_group_key", encryptedGroupKey)
                        put("signature", signature)
                        put("members", JSONArray(allMembers))
                        put("admins", JSONArray(admins))
                        put("roster_signature", rosterSignature)
                    })

                    Log.d(TAG, "Участник $newMemberId добавлен в группу $groupName")
                }

                // Existing members previously never learned about the new
                // member at all — see docs/ISSUE_backup_identity_hijack.md,
                // group roster fix. Symmetric to notifyMemberRemoved() below.
                val addSignature = CryptoManager.sign("$groupId:add:$newMemberId")
                allMembers.filter { it != username && it != newMemberId }.forEach { memberId ->
                    sendAnonOrDirect(memberId, JSONObject().apply {
                        put("type", "group_member_added")
                        put("from", username)
                        put("to", memberId)
                        put("group_id", groupId)
                        put("new_member", newMemberId)
                        put("new_member_name", newMemberName)
                        put("signature", addSignature)
                    })
                }
            } catch (e: Exception) {
                Log.e(TAG, "addGroupMember error: ${e.message}", e)
            }
        }
    }

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

                    val memberPqKey = publicKeysPq[memberId]
                    if (memberPublicKey != null && memberPqKey != null) {
                        val encryptedNewKey = GroupManager.encryptGroupKeyForMember(newGroupKey, memberPublicKey, memberPqKey)
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
