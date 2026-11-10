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

    // chunks keyed by index, not a MutableList (S6-49, external review
    // 2026-09-05) -- a plain list APPENDED every arrival with no
    // de-duplication, so a duplicate/replayed chunk_index grew the list
    // forever and could corrupt reassembly with duplicate data; a Map
    // makes a repeated index idempotent, matching imageChunks'/videoChunk's
    // own accumulator shape.
    data class FileMeta(val name: String, val total: Int, val chunks: MutableMap<Int, String>)

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
        // Same importance/visibility as CHANNEL_ID, just no sound/vibration
        // — used for a contact/group whose "mute notification sound" toggle
        // is on. Needs its own channel because on Android O+ the channel's
        // own sound config wins over anything set on the individual
        // Notification.Builder, so per-notification setSound(null) alone
        // does nothing once a channel exists.
        const val CHANNEL_ID_SILENT = "messenger_channel_silent"

        const val CHANNEL_ID_SERVICE = "messenger_service_silent"
        // Visible-but-quiet alternative — same notification, no sound/
        // vibration, but IMPORTANCE_LOW instead of IMPORTANCE_MIN so it
        // actually shows a status bar icon instead of being fully hidden.
        // User's own choice (UserStorage.isServiceNotificationVisible) —
        // see docs/ISSUE_backup_identity_hijack.md: MIN was probably chosen
        // for discretion (no visible sign Subrosa is running to someone
        // glancing at the phone), but that same low-priority signal can
        // make OEM battery managers more willing to kill the background
        // connection. Not everyone weighs that tradeoff the same way.
        const val CHANNEL_ID_SERVICE_VISIBLE = "messenger_service_visible"
        const val NOTIFICATION_ID = 1
        private const val TAG = "MessengerService"

        @Volatile var connected: Boolean = false

        val connectionState = MutableStateFlow(false)

        /** Shared by every "burn this identity" path — currently
         *  ProfileScreen.kt's "Меня скомпрометировали" and WipeReceiver.kt's
         *  Dead Man's Switch NUCLEAR wipe. Fires the best-effort
         *  `revoke_identity` WS message through the (still old-identity-
         *  authenticated) running service, then waits briefly for the frame
         *  to actually flush before the caller destroys the local key —
         *  no ack wait by design, matches the "deliberately cheap" spirit
         *  of the rest of the reset flow. See
         *  docs/ISSUE_backup_identity_hijack.md, Тир 5. */
        suspend fun requestIdentityRevocation(context: Context) {
            context.startService(
                Intent(context, MessengerService::class.java).apply {
                    putExtra("revoke_identity", true)
                }
            )
            kotlinx.coroutines.delay(400)
        }
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

    // Separate OkHttpClient instances for anon_channel (Sealed Sender, шаг 2)
    // — deliberately NOT sharing wsClient/wsTorClient. Found live 2026-08-29:
    // reusing the main socket's client would mean sharing its SSLSocketFactory
    // / TLS session cache, letting the two connections' TLS layer resume a
    // session ticket issued during the OTHER connection's handshake — a
    // direct cryptographic link between the identified main socket and the
    // supposedly identity-less anon_channel, visible before any application
    // data at all. A fresh OkHttpClient gets its own SSLContext, so no ticket
    // to reuse across the two.
    private val anonWsClient: OkHttpClient by lazy {
        buildOkHttpClient(useTor = false)
    }

    private val anonWsTorClient: OkHttpClient by lazy {
        buildOkHttpClient(useTor = true)
    }

    private fun buildOkHttpClient(useTor: Boolean): OkHttpClient {
        val builder = OkHttpClient.Builder()
            // Was 0 (disabled) — meant a dead connection was only ever
            // discovered on the next actual write, which could lag the real
            // disconnect by up to a minute (see nginx's proxy_send_timeout,
            // default 60s, with no explicit override in docs/nginx-
            // subrosamessenger.conf.snippet — the only client-side traffic
            // between real sends is pollMailbox's 30s cadence, so a single
            // delayed/missed cycle, more likely on an emulator's virtual NIC
            // than a real phone radio, can silently exceed it). A 20s
            // WebSocket ping both counts as send traffic for that same
            // timeout and lets OkHttp itself detect a dead connection within
            // one ping interval instead of waiting for the next application
            // write.
            .pingInterval(20, TimeUnit.SECONDS)
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
        if (NetworkConfig.isPinningActive) {
            builder.certificatePinner(
                okhttp3.CertificatePinner.Builder()
                    .apply {
                        NetworkConfig.CERT_PINS.forEach { pin ->
                            add(NetworkConfig.SERVER_HOSTNAME, pin)
                        }
                    }
                    .build()
            )
            Log.d(
                TAG,
                "Certificate pinning включён для ${NetworkConfig.SERVER_HOSTNAME}, " +
                    "пинов: ${NetworkConfig.CERT_PINS.size}"
            )
        } else if (!BuildConfig.DEBUG) {
            // Unreachable by construction: assembleRelease fails when the pin
            // list is empty, unless someone passed the documented override.
            // Logged loudly rather than running silently unpinned, which is the
            // exact state this rework existed to make impossible.
            Log.e(
                TAG,
                "ВНИМАНИЕ: release-сборка без certificate pinning — подлинность сервера " +
                    "держится только на системном хранилище CA. Пересоберите с SUBROSA_CERT_PINS."
            )
        } else {
            Log.d(TAG, "Certificate pinning выключен (debug-сборка)")
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

    /** anon_channel equivalent of activeWsClient() — same Tor-availability
     *  logic, but selects from the separate anonWsClient/anonWsTorClient pair
     *  so the two connections never share a TLS session cache. */
    private fun activeAnonWsClient(): OkHttpClient {
        if (!TorManager.isConnected) return anonWsClient

        val socksAvailable = try {
            val s = java.net.Socket()
            s.connect(java.net.InetSocketAddress(TorManager.SOCKS_HOST, TorManager.SOCKS_PORT), 1000)
            s.close(); true
        } catch (e: Exception) { false }
        return if (socksAvailable) anonWsTorClient else anonWsClient
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isConnected: Boolean = false
        set(value) { field = value; connected = value; connectionState.value = value }
    private var isConnecting = false

    // Sealed Sender, шаг 2 — identity-less second connection dedicated to
    // anon_message (see docs/TODO.md). Deliberately much simpler than the
    // main connect() loop (no Tor/server-switch/backoff machinery): if it's
    // not up, sendOnAnonChannel() falls back to the main identified socket
    // rather than blocking or losing the send, and opportunistically retries
    // (throttled) on the next attempt.
    private var anonChannelWs: WebSocket? = null
    private var anonChannelReady = false
    private var anonChannelConnecting = false
    private var anonChannelLastAttemptMs = 0L
    private var lastChallengeBytes: ByteArray? = null
    private var lastRegisterPacket: JSONObject? = null
    // Guards SessionKeyManager.initialize() below — was
    // `!SessionKeyManager.hasSession("__init_check__")`, a sentinel
    // fingerprint never created anywhere in SessionKeyManager, so that
    // check was permanently true and initialize() (SPK rotation check, OPK
    // pool reload+refill, full session reload from disk) ran on literally
    // every successful reconnect instead of once per process lifetime.
    // Root-caused live 2026-08-17 alongside a genuine "OPK N уже
    // использован или не существует" session_init failure — not confirmed
    // as the sole cause, but running this full reinit path far more often
    // than intended is wrong regardless and worth closing on its own.
    private var sessionManagerInitialized = false
    private var reconnectAttempts = 0
    private var failuresOnCurrentServer = 0
    private val MAX_FAILURES_BEFORE_SWITCH = 3
    private var totpRequiredNotified = false
    @Volatile private var pendingRecoveryCode: String? = null
    private var username = ""

    // Watchdog for "zombie" WebSocket connections: writes (webSocket.send())
    // can keep locally succeeding — and OkHttp's own pingInterval ping/pong
    // (see buildOkHttpClient, 20s) can fail to notice — while the read side
    // is actually dead (no onMessage, no onFailure/onClosed either). Found
    // live 2026-08-28: right after a WebRTC call ended (heavy network churn —
    // ICE/TURN, network callback rebinding), one device's main WS kept
    // sending pollMailbox() every ~10-30s with zero replies for over a
    // minute, no text messages or typing indicators arriving, yet isConnected
    // stayed true the whole time since nothing ever told it otherwise.
    //
    // Driven by an explicit app-level ping we send ourselves (see the
    // "pong" case in handleMessage and the sendWs("ping") loop below) —
    // NOT bumped on arbitrary incoming traffic, because a quiet conversation
    // with no messages for 45s+ is a completely normal state. An earlier
    // version of this watchdog treated any silence as staleness and force-
    // reconnected during ordinary idle gaps, causing a needless full
    // 50-token resubscribe every time (regression caught live 2026-08-28,
    // same day as the original fix).
    @Volatile private var lastServerActivityMs = System.currentTimeMillis()
    // Reverted to 45s/15s-ping (2026-08-29) — was temporarily lowered to
    // 15s/5s-ping on 2026-08-28 for faster live-test iteration while
    // chasing the post-call zombie-write-connection bug; that investigation
    // is done (see the token-registration-ordering and spent-token-history
    // fixes), so back to the less trigger-happy normal-operation values.
    private val CONNECTION_WATCHDOG_TIMEOUT_MS = 45_000L

    private val publicKeys = mutableMapOf<String, String>()
    // Peer ML-KEM public keys, sourced from prekey bundles — required to
    // hybridize the legacy ephemeral-ECDH path (encrypt/decrypt, voice, group
    // key distribution) against harvest-now-decrypt-later, same as X3DH.
    private val publicKeysPq = mutableMapOf<String, ByteArray>()

    /** publicKeysPq is populated only by handleFetchedPrekeyBundle() and was
     *  never persisted to disk (unlike publicKeys, which always falls back
     *  to ChatStorage.getContactPublicKey()) — every service restart wiped
     *  it, forcing a full prekey-bundle refetch before any hybrid-encrypted
     *  send to an already-established contact could proceed. Mirrors the
     *  publicKeys[to] ?: ChatStorage.getContactPublicKey(to)?.also{} pattern
     *  used everywhere else in this file. Root-caused live 2026-08-16. */
    private fun resolvePqKey(contactId: String): ByteArray? =
        publicKeysPq[contactId] ?: ChatStorage.getContactPqPublicKey(this, contactId)?.also { publicKeysPq[contactId] = it }
    // Was a mutableSetOf<String> ("sent once ever this process lifetime, never
    // again") — found live: a burst of usage (a video call's signaling traffic,
    // several video circles) can drain a contact's token allocation well
    // within a single service lifetime, but the one-time gate meant the
    // contact never got proactively resupplied, permanently stuck until an
    // app/service restart happened to reset it. A cooldown lets it refill
    // again once the previous grant has had time to actually be used up.
    private val tokensSentThisSession = mutableMapOf<String, Long>()
    private val TOKEN_RESUPPLY_COOLDOWN_MS = 3 * 60_000L

    /** Guards sendAnonTokensTo() against running twice concurrently for the
     *  same contact. Found live 2026-08-28: multiple independent triggers
     *  (proactive low-pool refill, the reactive isReply=true response, the
     *  stuck-pendingAnonPackets retry loop) can all fire within the same
     *  ~1s window for one contact — each one unaware of the others — and
     *  each burns a real token (potentially a reserve one) sending a
     *  redundant duplicate subscribe_tokens batch the peer just discards. */
    private val anonTokenResupplyInFlight = java.util.Collections.synchronizedSet(mutableSetOf<String>())

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
    // groupIds waiting on a member's key to arrive before their group_create
    // invite can be sent — see sendGroupInviteTo()/flushPendingGroupInvites().
    // Populated by createGroup()/addGroupMember() when the invitee's EC/PQ
    // key isn't cached yet (a real, common case: admin has never 1:1-chatted
    // with this member before, e.g. inviting a contact someone else
    // introduced). Before this fix, that invite was just silently dropped —
    // the group was saved locally with this member in its roster, but they
    // never received the group_create that would tell THEM about it, so
    // they never joined despite the admin's own UI showing them as a
    // member. Found live 2026-09-21.
    private val pendingGroupInvites = mutableMapOf<String, MutableSet<String>>()
    private val pendingReactions = mutableListOf<Triple<String, String, String>>()

    // Queued by sendAnonOrDirect() when a contact's anon-token pool is empty —
    // see the "cut the direct fallback" decision in
    // docs/ISSUE_backup_identity_hijack.md. Drained by flushPendingAnon()
    // once fresh tokens arrive for that contact (either path that calls
    // AnonTokenManager.addContactTokens).
    private val pendingAnonPackets = mutableMapOf<String, MutableList<JSONObject>>()

    // Inner message types with NO independent per-message signature of their
    // own (S6-66, external review 2026-09-09) — unlike message/group_message/
    // edit/reaction/voice/group_create/etc, which each verify a
    // CryptoManager signature against the claimed sender's own identity key
    // inside their own handler, these relied ENTIRELY on the anon_delivery
    // envelope's unauthenticated "from" field. Proven exploitable via
    // session_reset: any anon-token holder could claim any "from" and
    // force-delete a victim's session with an arbitrary third party.
    // Originally closed with a sender_cert requirement, replaced (S6-66
    // follow-up) with an end-to-end identity signature — sender_cert's
    // trust anchor is a per-server signing-key pin
    // (SenderCertManager.SERVER_CERT_PUBLIC_KEY_B64), which is deliberately
    // never a globally baked-in constant since Subrosa supports arbitrary
    // self-hosted servers; an identity signature needs no server-specific
    // trust anchor at all, only the sender's own long-term key the
    // recipient already resolves for every other signed type.
    private val ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE = setOf(
        "session_reset", "pq_bundle_refresh", "contact_ping", "contact_pong",
        "call_offer", "call_answer", "call_ice", "call_end", "call_ringing",
        "call_ice_restart", "call_response", "call_request_audio", "call_request_video",
        "call_group_invite", "call_group_join", "call_group_answer",
        "call_group_ice", "call_group_leave", "call_group_peer_list",
    )

    // Fields no receiver ever signed over: "signature" is this transcript's
    // own output, "sender_cert"/"sender_cert_sig" belong to the SEPARATE,
    // still-live Sealed Sender cert mechanism (added later, to a COPY, by
    // sealPacketForRecipient() — never present yet when this signs, but
    // present by the time a receiver decrypts, so both sides must ignore
    // them identically). Excluding them keeps the two mechanisms from
    // interfering while letting them coexist.
    private val CONTROL_ENVELOPE_EXCLUDED_KEYS = setOf("signature", "sender_cert", "sender_cert_sig")

    /** Canonical, domain-separated, unambiguous transcript for every type in
     *  ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE (S6-66 follow-up) — ONE
     *  generic transcript covers all of them rather than one hand-written
     *  string per type — with no per-type field list to keep in sync as new
     *  fields get added. RECURSIVELY canonicalized (verification follow-up,
     *  external review 2026-09-09): a plain `.toString()` on a nested
     *  JSONArray/JSONObject (e.g. call_ice_batch's "candidates", call_group_
     *  peer_list's "peers") serializes nested object keys in whatever order
     *  the underlying library's internal map iterates — Android's built-in
     *  org.json and Desktop's standalone org.json jar are independent
     *  implementations with no documented guarantee of matching iteration
     *  order, so relying on it risked signer/verifier disagreeing on the
     *  exact same logical packet. canonicalizeValue() below sorts EVERY
     *  nested object's keys explicitly (never trusts iteration order at any
     *  depth), preserves array element order (arrays are ordered by
     *  definition), and prefixes every value with an explicit type tag
     *  (o/a/s/i/l/d/b/n) so e.g. the number 5 and the string "5" can never
     *  collide. Length-prefixing throughout rules out delimiter-collision
     *  ambiguity for free-form content like SDP. */
    private fun canonicalizeValue(v: Any?): String = when {
        v == null || v === JSONObject.NULL -> "n"
        v is JSONObject -> {
            val keys = v.keys().asSequence().sorted().toList()
            val sb = StringBuilder("o").append(keys.size).append(':')
            for (k in keys) {
                sb.append(k.length).append(':').append(k)
                val cv = canonicalizeValue(v.get(k))
                sb.append(cv.length).append(':').append(cv)
            }
            sb.toString()
        }
        v is org.json.JSONArray -> {
            val sb = StringBuilder("a").append(v.length()).append(':')
            for (i in 0 until v.length()) {
                val cv = canonicalizeValue(v.get(i))
                sb.append(cv.length).append(':').append(cv)
            }
            sb.toString()
        }
        v is String -> "s${v.length}:$v"
        v is Boolean -> "b${if (v) 1 else 0}"
        v is Int -> "i$v"
        v is Long -> "l$v"
        v is Double -> "d$v"
        else -> { val s = v.toString(); "s${s.length}:$s" }
    }

    private fun controlEnvelopeTranscript(packet: JSONObject): String {
        val keys = packet.keys().asSequence().filter { it !in CONTROL_ENVELOPE_EXCLUDED_KEYS }.sorted()
        val sb = StringBuilder("SUBROSA_CONTROL_V1")
        for (k in keys) {
            val cv = canonicalizeValue(packet.get(k))
            sb.append(':').append(k.length).append(':').append(k)
            sb.append(':').append(cv.length).append(':').append(cv)
        }
        return sb.toString()
    }

    /** Domain-separated canonical transcript for the mailbox "inner" payload
     *  (depositTokensViaMailbox/sendViaMailbox/depositSessionInitViaMailbox) —
     *  found in the 2026-09-13 mailbox-authentication audit: this payload is
     *  only ever RECIPIENT-encrypted (CryptoManager.encryptClassicalOnly(),
     *  an ephemeral-ECDH scheme anyone who knows the recipient's public key
     *  can encrypt to), never sender-authenticated. handleMailboxResult()
     *  trusted the embedded "from" field after decryption purely on the
     *  strength of the mutual-add spam gate (getContactMailboxTag(from) !=
     *  null) — which proves this device once redeemed SOMEONE's invite code
     *  under that name, not that THIS blob's actual sender holds that
     *  fingerprint's private key. Anyone who knows this device's public key
     *  (shared freely via invite codes) could forge a blob claiming to be
     *  any already-added contact and have its tokens/session_init/message
     *  trusted and displayed as if from them. Reuses the exact same
     *  recursive canonicalizeValue() as controlEnvelopeTranscript() above
     *  (sorted keys at every depth, length-prefixed, type-tagged) — a
     *  DIFFERENT domain prefix than SUBROSA_CONTROL_V1 so a signature over
     *  one can never be replayed as the other. Only "signature" itself is
     *  excluded — unlike the control-envelope transcript, mailbox inner
     *  payloads never carry a sender_cert. Generic over whatever keys are
     *  actually present (from/text/session_init_packet/tokens/mailbox_tag/
     *  reply/id today) rather than a hand-picked field list, same reasoning
     *  as controlEnvelopeTranscript()'s own comment — recursion already
     *  covers a nested session_init_packet with no special-casing needed. */
    private fun mailboxTranscript(inner: JSONObject): String {
        val keys = inner.keys().asSequence().filter { it != "signature" }.sorted()
        val sb = StringBuilder("SUBROSA_MAILBOX_V1")
        for (k in keys) {
            val cv = canonicalizeValue(inner.get(k))
            sb.append(':').append(k.length).append(':').append(k)
            sb.append(':').append(cv.length).append(':').append(cv)
        }
        return sb.toString()
    }

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
    // History: 3s originally, bumped to 20s same day (2026-08-28) to stop a burst
    // of queued sends from burning all RESERVE_TOKENS (3) within ~9s — faster than
    // a resupply round trip could realistically land. But 20s turned out too
    // conservative: this cooldown previously only gated a *new* bootstrap attempt,
    // and with nothing else retrying independently, a token-empty contact could
    // stay stuck for minutes after a call if the user wasn't actively typing (no
    // new sendAnonOrDirect call = no new retry). Settled on 10s as a middle
    // ground — survives ~3 reserve tokens for 30s, still gives the round trip
    // room — paired with an independent periodic retry below (not gated on the
    // user doing anything) so recovery doesn't depend on user activity at all.
    //
    // Raised to 30s (external review, 2026-09-13) — 10s turned out to be the
    // actual root cause of a live, reproduced failure: sendAnonTokensTo()
    // re-subscribes the ENTIRE ~100-token "my own" pool on every call, not
    // just the newly-shared batch. During a genuinely active 1:1 exchange
    // (typing + message + read + delivered, each consuming one of the
    // contact's granted tokens), the contact's 20-token grant depletes in
    // seconds, re-entering this queue branch roughly every 10-15s — up to
    // 6 full subscribe_tokens resends per minute from THIS trigger alone,
    // on top of the separate 3-minute-gated needsRefill() trigger and
    // periodic connect()/pollMailbox() traffic. Confirmed live: this blew
    // through server.py's subscribe_tokens rate limit (10/60s) mid-
    // conversation, the server closed the connection with "Rate limit
    // exceeded", and the client had to fully reconnect (fresh handshake +
    // register + bundle fetch) before messaging could resume — the exact
    // "takes about a minute to reconnect to Desktop" symptom reported live.
    // 30s keeps this trigger's worst case at 2/min, leaving real headroom
    // under the server's budget even during a fast back-and-forth.
    private val TOKEN_BOOTSTRAP_COOLDOWN_MS = 30_000L

    // Per-contact escalating backoff for the PERIODIC pendingAnonPackets
    // retry loop below — deliberately separate state from
    // lastTokenBootstrapAttempt/TOKEN_BOOTSTRAP_COOLDOWN_MS above, which
    // exists to collapse a BURST of REACTIVE retries (e.g. 84 video-circle
    // chunks each independently calling sendAnonOrDirect) into one attempt,
    // not to pace an ongoing periodic retry against a contact that's been
    // stuck for a while. Before this fix, the periodic loop reused that
    // SAME cooldown with its OWN 10s tick period — since the loop always
    // ticks exactly TOKEN_BOOTSTRAP_COOLDOWN_MS after its previous tick,
    // "now - last >= TOKEN_BOOTSTRAP_COOLDOWN_MS" was always true and the
    // cooldown never actually delayed the periodic path at all. A contact
    // stuck for a structural reason (no mailbox tag, no session —
    // sendAnonTokensToLocked() has no other fallback for that exact case)
    // got hammered with a fresh 20-token mint + subscribe_tokens +
    // mailbox_put every single tick, forever, no backoff. Confirmed live
    // 2026-09-13 via server.py's own pushback ("[SECURITY] subscribe_tokens:
    // ... превысил лимит(ы)") for exactly this pattern, while auditing the
    // Desktop port and discovering it had no equivalent loop at all to even
    // compare against. Doubles the delay on every retry, capped at 5
    // minutes; reset (via retainAll below) the moment a contact actually
    // drops out of pendingAnonPackets, i.e. succeeds.
    private val periodicRetryDelayMs = mutableMapOf<String, Long>()
    private val periodicRetryNextAt = mutableMapOf<String, Long>()
    private val PERIODIC_RETRY_INITIAL_MS = 10_000L
    private val PERIODIC_RETRY_MAX_MS = 5 * 60_000L

    // Separate state from lastTokenBootstrapAttempt/TOKEN_BOOTSTRAP_COOLDOWN_MS
    // above — gates requestPrekeyBundle() specifically, which is rate-limited
    // server-side as "prekey_fetch" (10/min PER ACCOUNT, not per-contact —
    // server.py rate_limit_check()), a completely separate budget from
    // subscribe_tokens/mailbox_put. Before this, requestPrekeyBundle()'s only
    // guard was pendingBundleRequests, a same-contact IN-FLIGHT dedupe that
    // clears the instant a (possibly null) response arrives — so a contact
    // whose bundle server-side is still null (see SessionKeyManager's
    // isWrappedUnderStaleSmk on Desktop for one real cause) got a fresh
    // get_prekey_bundle on EVERY subsequent trigger — one per received
    // message, since every queued delivered/read receipt calls
    // requestPrekeyBundle() again after failing to send. Confirmed live
    // 2026-09-18: "[RATE_LIMIT] ... превысил лимит prekey_fetch" firing
    // during an ordinary incoming-message burst from a contact stuck this
    // way, forcing a server-side close mid-conversation.
    private val lastPrekeyFetchAttempt = mutableMapOf<String, Long>()
    private val PREKEY_FETCH_COOLDOWN_MS = 30_000L

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

    // S6-49 (external review 2026-09-05) -- receive-side chunk assembly had
    // no bounds at all: chunk_index/total_chunks came straight from JSON
    // with no range validation, imageChunks/fileChunks grew one entry per
    // distinct transfer id with no cap on simultaneous transfers and no
    // expiry for an abandoned one, and file_chunk's accumulator (a
    // MutableList, not a Map -- see FileMeta) APPENDED every arrival
    // instead of de-duplicating by index, so a duplicate/replayed chunk
    // grew the list forever and could corrupt the reassembled file with
    // duplicate data. Server-side envelope limits (server.py's
    // MEDIA_CHUNK_*, same fix) bound TRAFFIC; these bound this device's own
    // memory regardless of what produced the traffic -- a remote
    // authenticated sender this device already trusts enough to have
    // cached a public key for (any contact, or any stranger this device
    // has ever completed an X3DH handshake with) could otherwise mint
    // unlimited distinct image_id/video_id/file_id values that never
    // expire.
    private val MEDIA_CHUNK_MAX_TOTAL_CHUNKS = 20_000
    private val MEDIA_CHUNK_MAX_CONCURRENT_TRANSFERS = 20
    private val MEDIA_CHUNK_TRANSFER_TIMEOUT_MS = 5 * 60 * 1000L
    private val imageVideoTouchedAt = mutableMapOf<String, Long>()
    private val fileTouchedAt = mutableMapOf<String, Long>()

    /** Lazily sweeps any transfer idle past MEDIA_CHUNK_TRANSFER_TIMEOUT_MS
     *  out of [map]/[touchedAt] (self-pruning, no background timer needed),
     *  then admits [transferKey] only if it's already tracked or there's
     *  room under MEDIA_CHUNK_MAX_CONCURRENT_TRANSFERS -- returns false for
     *  a genuinely NEW transfer once at capacity, same "reject new, keep
     *  existing" posture as the server-side per-account caps this session
     *  already applied elsewhere (S6-44/S6-47). Generic over the
     *  accumulator's value type so image/video (MutableMap<Int,String>)
     *  and file (FileMeta) share one implementation. */
    // S6-49 follow-up: the lazy stale sweep below only ever knew about [map]/
    // [touchedAt] -- once byte-accounting (imageVideoReceivedBytes/
    // imageVideoChunkWireLens, fileReceivedBytes/fileChunkWireLens) was added
    // alongside them, an ABANDONED transfer swept here (idle >5 min, evicted
    // opportunistically by some LATER unrelated transfer's own admission
    // check) left its byte-accounting entries behind forever -- they're only
    // otherwise cleared at a handler's own explicit cancel/complete points,
    // which an abandoned transfer never reaches. [receivedBytes]/[wireLens]
    // are swept for the exact same stale keys here so nothing outlives the
    // transfer it was accounting for.
    private fun <V> pruneAndAdmitTransfer(
        map: MutableMap<String, V>,
        touchedAt: MutableMap<String, Long>,
        transferKey: String,
        receivedBytes: MutableMap<String, Long>,
        wireLens: MutableMap<String, MutableMap<Int, Int>>,
    ): Boolean {
        val now = System.currentTimeMillis()
        val stale = touchedAt.filterValues { now - it > MEDIA_CHUNK_TRANSFER_TIMEOUT_MS }.keys
        for (key in stale) {
            map.remove(key)
            touchedAt.remove(key)
            receivedBytes.remove(key)
            wireLens.remove(key)
        }
        if (!map.containsKey(transferKey) && map.size >= MEDIA_CHUNK_MAX_CONCURRENT_TRANSFERS) {
            return false
        }
        touchedAt[transferKey] = now
        return true
    }

    // S6-49 follow-up (external review 2026-09-06) -- MEDIA_CHUNK_MAX_TOTAL_CHUNKS
    // bounds how many distinct indices a transfer may have, but not their total
    // content size: a small total_chunks with each chunk near the server's own
    // per-chunk ceiling (server.py's MEDIA_CHUNK_DATA_MAX_LEN=130,000) could
    // still assemble an unbounded amount of retained memory, and nothing on
    // the client validated an incoming chunk's own `data` length at all --
    // a compromised/malicious server (not just a malicious contact) could
    // hand this device an arbitrarily large single chunk. MEDIA_CHUNK_DATA_MAX_LEN
    // mirrors the server's own bound; MEDIA_TRANSFER_MAX_BYTES (64 MiB) is a
    // generous multiple of the real legitimate maximum (ChatScreen's 20 MB raw
    // file cap, base64-expanded; a 60s video circle; any compressed image) while
    // remaining far below MEDIA_CHUNK_MAX_TOTAL_CHUNKS * MEDIA_CHUNK_DATA_MAX_LEN's
    // own theoretical worst case.
    private val MEDIA_CHUNK_DATA_MAX_LEN = 130_000
    private val MEDIA_TRANSFER_MAX_BYTES = 64L * 1024 * 1024

    // S6-53 (external review 2026-09-06) -- client-side defense-in-depth for
    // message_delete/disappear_timer/group_message_delete. The server now
    // schema-binds and bounds these (server.py's CHAT_CONTROL_ID_MAX_LEN),
    // but a compromised/malicious server could still hand this device an
    // arbitrary frame directly, and a genuinely-authenticated malicious
    // contact can produce a validly-signed message over any content they
    // choose -- signature verification proves ORIGIN, not that the signed
    // value is protocol-sane. seconds especially: ChatStorage.
    // setDisappearTimer()/downstream expiry-timestamp math has no reason to
    // ever see a value the UI itself doesn't offer (ChatScreen's disappear
    // dialog: off/1h/24h/7d), so it's checked against that exact set, not
    // merely a numeric range.
    private val CHAT_CONTROL_ID_MAX_LEN = 128
    private val CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED = setOf(0L, 3600L, 86400L, 604800L)

    // S6-57 (external review 2026-09-06) -- client-side defense-in-depth for
    // "voice": the server now bounds voice_data/signature/voice_id/duration
    // (server.py's VOICE_DATA_MAX_LEN/VOICE_SIGNATURE_MAX_LEN/
    // MAX_VOICE_DURATION_SECONDS), but a compromised/malicious server could
    // still hand this device an arbitrary frame directly -- the server must
    // never be this client's own memory-safety boundary. Checked BEFORE
    // CryptoManager.verify()/decrypt() and AudioHelper.decodeAndSave() ever
    // run, same "reject before expensive work" posture as CHAT_CONTROL_ID_MAX_LEN
    // above. Numbers mirror the server's own derivation exactly (see
    // VOICE_DATA_MAX_LEN's own comment in server.py for the full byte-math):
    // Desktop's uncompressed 16kHz/16-bit WAV codec is the dominant/worst
    // case at any given duration, Android's own AMR-NB is far smaller.
    private val MAX_VOICE_DURATION_SECONDS = 60
    private val VOICE_WIRE_MAX_LEN = 4 * 1024 * 1024          // wire voice_data (base64 ciphertext)
    private val VOICE_SIGNATURE_MAX_LEN = 256                 // mirrors server's own bound
    private val VOICE_ID_MAX_LEN = 64                         // canonical UUID (36 chars) + headroom
    // Post-decrypt bound (STEP 8) -- CryptoManager.decrypt()'s OUTPUT is the
    // base64-encoded audio string (AudioHelper.encodeToBase64()'s own
    // output), checked BEFORE AudioHelper.decodeAndSave() ever base64-decodes
    // or writes a file. ~3 MiB gives real headroom above Desktop's own
    // worst-case ~2.56 MiB (32,000 bytes/sec * 60s * 4/3 base64 expansion).
    private val VOICE_MAX_DECRYPTED_B64_LEN = 3 * 1024 * 1024
    // Post-base64-decode bound (STEP 8) -- the actual raw audio byte count
    // AudioHelper.decodeAndSave() would write to disk. ~2.5 MiB gives
    // headroom above Desktop's own worst-case ~1.92 MiB (32,000 bytes/sec *
    // 60s).
    private val VOICE_MAX_DECODED_AUDIO_BYTES = (2.5 * 1024 * 1024).toInt()
    // S6-59 (external review 2026-09-06) -- client-side defense-in-depth for
    // the anon_delivery unwrap itself, mirroring VOICE_WIRE_MAX_LEN's own
    // "the server must never be this client's own memory-safety boundary"
    // posture one layer further out: a compromised/malicious server could
    // hand this device an anon_delivery whose sealed "blob" is arbitrarily
    // large regardless of what server.py's own ANON_PAYLOAD_MAX_BYTES is
    // supposed to enforce. Checked BEFORE CryptoManager.decrypt(blob) ever
    // runs. Sized generously above the largest legitimate sealed payload
    // today (a max-length sealed voice message, ~5.3 MiB -- see
    // ANON_PAYLOAD_MAX_BYTES's own derivation in server.py) with headroom
    // for encoding variance, while still being a real, finite ceiling.
    private val ANON_DELIVERY_BLOB_MAX_LEN = 6 * 1024 * 1024
    private val imageVideoReceivedBytes = mutableMapOf<String, Long>()
    private val imageVideoChunkWireLens = mutableMapOf<String, MutableMap<Int, Int>>()
    private val fileReceivedBytes = mutableMapOf<String, Long>()
    private val fileChunkWireLens = mutableMapOf<String, MutableMap<Int, Int>>()

    /** Tracks each index's WIRE byte size independently of [imageChunks]/
     *  [fileChunks]'s own stored content, which for image_chunk is NOT always
     *  the wire value (the non-encrypted branch stores a post-decrypt string
     *  of a different length) -- reading "previous size" back out of the
     *  content map would silently under-count a replayed index there. A
     *  dedicated wireLens map keyed the same way (transferKey -> index -> wire
     *  bytes) makes the delta always exact: replaying [chunkIndex] with a
     *  DIFFERENT-sized chunk correctly adjusts [receivedBytes] by the delta
     *  rather than either adding on top of the old size (undercounting reuse)
     *  or silently ignoring the new size (letting a malicious but validly-
     *  signed re-send of the same index inflate real retained memory while
     *  the accounted total stays frozen at whatever the FIRST copy cost).
     *  Returns false (transfer must be cancelled, never partially admitted)
     *  if admitting this chunk would push the running total over
     *  MEDIA_TRANSFER_MAX_BYTES. */
    private fun accountChunkBytes(
        wireLens: MutableMap<Int, Int>,
        receivedBytes: MutableMap<String, Long>,
        transferKey: String,
        chunkIndex: Int,
        chunkWireBytes: Int,
    ): Boolean {
        val prevBytes = wireLens[chunkIndex]?.toLong() ?: 0L
        val projected = (receivedBytes[transferKey] ?: 0L) - prevBytes + chunkWireBytes
        if (projected > MEDIA_TRANSFER_MAX_BYTES) return false
        receivedBytes[transferKey] = projected
        wireLens[chunkIndex] = chunkWireBytes
        return true
    }
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
    var onContactSendUnblocked: ((String) -> Unit)? = null
    var onEditReceived: ((String, String) -> Unit)? = null
    var onImageReceived: ((String, android.graphics.Bitmap) -> Unit)? = null
    var onKeyChanged: ((String) -> Unit)? = null
    // Fired when a fetched prekey bundle is flagged "revoked" by the server
    // (see server.py's get_prekey_bundle/get_prekey_bundles_batch and
    // docs/ISSUE_backup_identity_hijack.md, Тир 5, "Пометка prekey bundle
    // как revoked") — the contact's owner used "Меня скомпрометировали" or
    // Dead Man's Switch, so this identity is no longer trustworthy even
    // though the bundle itself still parses fine. Mirrors onKeyChanged's
    // warn-don't-block precedent: a heads-up, not a hard stop on the
    // session that's about to be established.
    var onContactRevoked: ((String) -> Unit)? = null
    var onVoiceReceived: ((String, File, Int) -> Unit)? = null
    var onFileReceived: ((String, File, String) -> Unit)? = null
    var onGroupMessageReceived: ((String, GroupMessage) -> Unit)? = null
    var onGroupImageReceived: ((groupId: String, from: String, imageId: String, file: File) -> Unit)? = null
    var onGroupFileReceived: ((groupId: String, from: String, fileId: String, file: File, fileName: String) -> Unit)? = null
    var onGroupVideoReceived: ((groupId: String, from: String, videoId: String, file: File, duration: Int) -> Unit)? = null
    var onGroupAvatarUpdated: ((groupId: String) -> Unit)? = null
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
            val text = "Служба ${newOnes.first()} может читать экран или имитировать нажатия"
            val notification = androidx.core.app.NotificationCompat.Builder(this@MessengerService, CHANNEL_ID)
                .setContentTitle("Подозрительная активность")
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

    /**
     * The 5-volume-press trigger. This was a third hand-written copy of the
     * wipe, and it had drifted into being the weakest of the three: it never
     * deleted the `beacon_smk_wrap` Keystore alias, never called
     * `StorageKeyManager.lock()` (which docs/SECURITY.md and
     * SECURITY_INVARIANTS.md #22 both state is the first operation of *any*
     * wipe) and never dismissed the panic notification that outlives the
     * process. Delegating removes the copy rather than re-synchronising it.
     */
    private fun performEmergencyWipe() {
        WipeManager.hardWipe(this, withDecoy = true)
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
        // deleteAllSessions() removed from here (external review 2026-08-23):
        // onDestroy() fires on ANY clean service stop, not just a wipe --
        // including the "error" message handler's stopSelf() on literally any
        // server-reported error, benign or not. That path had nothing to do
        // with a wipe, yet unconditionally erased every Double Ratchet session
        // for every contact from disk (see SessionKeyManager.deleteAllSessions()'s
        // own doc comment -- this is not a memory-only clear). Same failure
        // class as the already-fixed "deleteAllSessions() on every reconnect"
        // bug (see connect(), 2026-08-17) -- forward secrecy means an erased
        // ratchet key is never recoverable, so this could have silently and
        // permanently destroyed every conversation's session state on a
        // routine, recoverable server hiccup. Wipe scenarios already call
        // deleteAllSessions() explicitly and intentionally elsewhere
        // (BackupManager.kt, WipeManager.kt) -- service teardown should not
        // imply a wipe.
        PanicNotificationManager.dismiss(this)
        stopSilentAudio()
        contentResolver.unregisterContentObserver(a11yObserver)
        unregisterNetworkCallback()
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
                //
                // The same naive-close mistake was still here for the main
                // WebSocket, just not caught until later: onLost() fires per
                // Network object, not "internet is gone" — a phone juggling
                // WiFi and mobile can get onLost() for one transport right as
                // the other takes over (a harmless handoff), and this used to
                // force-close a perfectly good, freshly reconnected socket on
                // every such event. Root-caused live 2026-08-16: toggled
                // airplane mode for 30s, watched the server log show a full
                // successful reconnect (register/subscribe_tokens/prekey
                // bundle) immediately followed by another disconnect ~10s
                // later — no real network gap in between, no client-side
                // error at all, matching exactly this pattern. Only close if
                // there's genuinely no active network left at all; a real
                // dead connection on the surviving network still gets caught
                // by the WebSocket's own ping/pong (pingInterval, see
                // buildOkHttpClient) on its own timescale.
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                if (cm.activeNetwork != null) {
                    Log.d(TAG, "Сеть потеряна ($network), но есть другая активная — не трогаем соединение")
                    return
                }
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
                stopControlPlaneNoise()
                startControlPlaneNoise()
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

        // Same intent-extra pattern — "Восстановить связь" button, for
        // screens (ChatScreen's overflow menu) reachable without an already
        // bound service. Cooldown is checked/recorded on the UI side (see
        // ContactHealthManager.canManualRestore()), same convention as
        // isSendBlocked() — this handler always fires when asked.
        intent?.getStringExtra("restore_connection")?.let { contactId ->
            forceRestoreConnection(contactId)
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

        if (intent?.getBooleanExtra("call_ended_force_ws_reconnect", false) == true) {
            // Found live 2026-08-28: after a call, the server started rejecting
            // anon_delivery_ack for tokens as "не принадлежит этому соединению"
            // — evidence of two live WS sessions for the same account at once,
            // one of them a zombie that still answers our own ping/pong (so the
            // staleness watchdog never notices) while real anon_message traffic
            // silently vanishes into it. Call signaling (call_offer/ice/call_end)
            // shares this same socket and appears to be a trigger, even though
            // the actual audio/video only ever goes over TURN/ICE, never this
            // socket. Forcing a clean reconnect right after every call ends is a
            // blunt but targeted fix: whatever duplicate/stale state built up
            // during the call gets wiped, guaranteed one live connection after.
            // Delayed 2s so the call's own final call_end/heartbeat-bye signal
            // (sent moments before this intent) has time to actually go out
            // first — closing the socket out from under it would just recreate
            // the CALL-TRACE-documented "сброс не долетает" gap we already fixed
            // with the P2P DataChannel bye path.
            scope.launch(Dispatchers.IO) {
                delay(2_000)
                if (isConnected) {
                    Log.w(TAG, "call_ended_force_ws_reconnect: форс-переподключение после звонка")
                    isConnected = false
                    webSocket?.close(1000, "post-call forced reconnect")
                }
            }

            // Nudge a token resupply for whoever we were just on a call
            // with — see CallManager.release()'s comment on
            // call_ended_resupply_tokens for why. Deliberately NOT gated on
            // AnonTokenManager.needsRefill() like the other proactive
            // resupply call sites — this isn't about the pool running low,
            // it's that every token already in the pool was subscribed on
            // the WS connection this same handler is about to close above,
            // so the whole pool is about to go stale regardless of its
            // size. shouldResupplyTokens() alone (per-contact cooldown/
            // dedup) is enough to stop this from spamming on rapid calls.
            intent.getStringExtra("call_ended_resupply_tokens")?.let { peersJson ->
                try {
                    val peers = org.json.JSONArray(peersJson)
                    for (i in 0 until peers.length()) {
                        val peer = peers.getString(i)
                        if (shouldResupplyTokens(peer)) {
                            scope.launch(Dispatchers.IO) { sendAnonTokensTo(peer) }
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "call_ended_resupply_tokens: не удалось разобрать список пиров — ${e.message}")
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

        if (intent?.getBooleanExtra("revoke_identity", false) == true) {
            // "Меня скомпрометировали" — see docs/ISSUE_backup_identity_hijack.md,
            // "Candidate fixes" item 4. Fired by ProfileScreen.kt right before it
            // wipes the local key; the server marks this connection's already-
            // authenticated fingerprint revoked so the old key stops being
            // sufficient to register again, even if whoever compromised it still
            // has it.
            if (isConnected) {
                scope.launch(Dispatchers.IO) {
                    sendWs(JSONObject().apply { put("type", "revoke_identity") }.toString())
                }
            }
            return START_STICKY
        }

        if (intent?.getBooleanExtra("refresh_notification", false) == true) {
            // Fired by ProfileScreen.kt right after the user flips the
            // hidden/visible service-notification toggle — re-posts the
            // foreground notification on the now-preferred channel
            // immediately, instead of waiting for the next service restart.
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(NOTIFICATION_ID, buildNotification())
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
    // AGGRESSIVE-mode pacing for anon_channel traffic specifically — see
    // sendOnAnonChannel()/startCoverTraffic(). Separate from outboundQueue
    // (main socket, non-anon traffic) since the two now go out over
    // different sockets and must be paced independently.
    private val anonOutboundQueue = java.util.concurrent.LinkedBlockingQueue<String>(200)
    // Holds anon_message frames while anonChannelWs isn't ready yet — see
    // sendOnAnonChannelNow()'s comment. Deliberately NOT drained to the
    // identified main socket as a fallback (removed 2026-08-29, same
    // reasoning as removing the token-pool fallback earlier this session:
    // a fallback that silently degrades a security property is worse than
    // no fallback) — flushed only once anon_channel_ok actually arrives.
    private val anonChannelPendingQueue = java.util.concurrent.LinkedBlockingQueue<String>(200)
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

                // Main socket (non-anon traffic) — unchanged.
                val packet = outboundQueue.poll()
                if (packet != null) {
                    webSocket?.send(packet)
                }

                // anon_channel — real queued anon_message (see
                // sendOnAnonChannel()'s AGGRESSIVE-mode queueing) takes
                // priority on this tick; if none is waiting, send a decoy
                // instead, so the anon_channel emits exactly one packet per
                // tick either way and a real send is never distinguishable
                // by timing from a decoy. sendOnAnonChannelNow(), not
                // sendOnAnonChannel(), here — this loop IS the pacing, so it
                // must send directly rather than re-queue.
                val anonPacket = anonOutboundQueue.poll()
                if (anonPacket != null) {
                    sendOnAnonChannelNow(anonPacket)
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
                    sendOnAnonChannelNow(noise)
                }
            }
        }
    }

    private fun stopCoverTraffic() {
        coverTrafficJob?.cancel()
        coverTrafficJob = null
    }

    private var controlPlaneNoiseJob: Job? = null

    /** Extends cover traffic to the CONTROL plane, not just the packet-level
     *  noise above. A real bootstrap (requestPrekeyBundle(), see its own
     *  comment) is a rare, one-off event per new contact — even with a full
     *  decoy pool hiding WHICH target in a batch is real, the fact that this
     *  account made a get_prekey_bundles_batch/get_decoy_candidates call AT
     *  ALL, at that specific moment, stands out in server-side logs if it's
     *  the only time this account ever does so. Firing the exact same calls
     *  periodically — with no real target, and discarding whatever comes
     *  back — makes a real bootstrap one indistinguishable instance among
     *  many fake ones instead of a unique, identifiable timestamp. Gated on
     *  the same CoverTrafficMode toggle as startCoverTraffic() rather than a
     *  separate setting, since this is the same feature extended to cover a
     *  gap the packet-level loop never touched. */
    private fun startControlPlaneNoise() {
        controlPlaneNoiseJob?.cancel()
        val mode = UserStorage.getCoverTrafficMode(this)
        if (mode == UserStorage.CoverTrafficMode.OFF) return
        controlPlaneNoiseJob = scope.launch(Dispatchers.IO) {
            val rng = java.security.SecureRandom()
            while (isActive) {
                // Randomized 2-6 min base interval (doubled in MODERATE) —
                // deliberately not packet-loop-frequency: a bootstrap-shaped
                // call every 1-5s would be its own obvious fingerprint (no
                // real account behaves that way) and would burn through the
                // prekey_fetch/decoy_candidates rate-limit buckets for
                // nothing. The randomization itself exists so this noise's
                // own cadence isn't a fixed, fingerprintable interval either.
                val baseMs = 2 * 60_000L + rng.nextInt(4 * 60_000)
                kotlinx.coroutines.delay(if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE) baseMs else baseMs * 2)
                if (!isConnected) continue
                sendControlPlaneBootstrapNoise()
            }
        }
    }

    private fun stopControlPlaneNoise() {
        controlPlaneNoiseJob?.cancel()
        controlPlaneNoiseJob = null
    }

    /** Fires a bootstrap-shaped request with no real target and discards the
     *  response. Using our own real contacts as the batch (when we have any)
     *  rather than synthetic fingerprints is deliberate — the server cannot
     *  distinguish "a genuine bootstrap padded with these contacts as decoys"
     *  from "pure noise naming these same contacts with no real intent",
     *  because the two are byte-for-byte the same request shape. The response
     *  handlers for both prekey_bundles_batch_response and
     *  decoy_candidates_result already no-op safely when there's no matching
     *  pending request (see their own comments), so nothing needs to track or
     *  clean up this call afterward. */
    private fun sendControlPlaneBootstrapNoise() {
        val rng = java.security.SecureRandom()
        val ownContacts = ChatStorage.getContacts(this)
        if (ownContacts.isEmpty()) {
            sendWs(JSONObject().apply {
                put("type", "get_decoy_candidates")
                put("count", 2 + rng.nextInt(MAX_BATCH_BUNDLE_TARGETS - 2))
            }.toString())
            return
        }
        val batch = ownContacts.shuffled().take(1 + rng.nextInt(MAX_BATCH_BUNDLE_TARGETS - 1))
        sendWs(JSONObject().apply {
            put("type", "get_prekey_bundles_batch")
            put("targets", org.json.JSONArray(batch))
        }.toString())
    }

    /** Provisioning of the device-gated registration TOTP secret. The server
     * refuses this if a secret is already on file for this account UNLESS
     * [recoveryCode] proves authorization to replace it (added 2026-08-30,
     * "recovery-code takeover window" fix) — the re-enrollment case for a
     * device that just logged in via a recovery code and needs to properly
     * replace a secret it doesn't hold the authenticator for. Leave null for
     * ordinary first-time setup.
     *
     * [code] is sent as `new_code` (external review 2026-09-04, S6-33) — it
     * is proof of possession of the NEW [secretBase32], never of whatever
     * secret was previously enrolled. The server used to read the same
     * "code" field for both roles, which almost never actually validated
     * against an existing secret (two independent TOTP secrets, ~1 in 10^6
     * coincidence) — this app only ever offers recovery-code re-enrollment
     * in its UI anyway (see TotpSettingsScreen.kt's needsReenrollRecovery),
     * so the rename has no user-visible behavior change here. */
    fun sendTotpSetup(secretBase32: String, code: String, recoveryCode: String? = null) {
        if (!isConnected) {
            onTotpSetupResult?.invoke(false, "not_connected", null)
            return
        }
        sendWs(JSONObject().apply {
            put("type", "totp_setup")
            put("secret", secretBase32)
            put("new_code", code)
            if (!recoveryCode.isNullOrBlank()) put("recovery_code", recoveryCode.trim())
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

    /** [recoveryCode] (added 2026-08-30) lets a device that only has a
     * recovery code, not the current TOTP code, still disable protection —
     * same reasoning as sendTotpSetup's recoveryCode parameter above. */
    fun sendTotpDisable(code: String, recoveryCode: String? = null) {
        if (!isConnected) {
            onTotpDisableResult?.invoke(false)
            return
        }
        sendWs(JSONObject().apply {
            put("type", "totp_disable")
            put("code", code)
            if (!recoveryCode.isNullOrBlank()) put("recovery_code", recoveryCode.trim())
        }.toString())
    }

    /** Canonical string signed/verified for a group's member+admin roster,
     * shared by createGroup()/addGroupMember() (sign) and the group_create
     * handler (verify) — see docs/ISSUE_backup_identity_hijack.md, group
     * roster fix. */
    private fun rosterPayload(groupId: String, members: List<String>, admins: List<String>): String =
        "$groupId|${members.joinToString(",")}|${admins.joinToString(",")}"

    /** Canonical V1 transcript for group_create, shared by createGroup()/
     * addGroupMember() (sign) and the group_create handler (verify) — S6-64
     * (external review 2026-09-09). The PREVIOUS signature covered only
     * `encrypted_group_key`, binding neither `group_id` nor `group_name`/
     * `group_avatar` — a relay could relabel a validly-signed group_create
     * to a FRESH group_id with attacker-chosen name/avatar and it would
     * still verify, durably creating a spoofed/duplicated group locally,
     * attributed to the real (signature-proven) sender. Collisions with an
     * EXISTING group_id were already independently blocked (both platforms'
     * group_create handler no-ops if `getGroup(groupId) != null`), so
     * existing group state itself was never overwritable — hence binding
     * this rather than treating it as unexploitable. Sender identity is
     * already implicitly bound by which public key the signature verifies
     * against (`from`'s own key) — not duplicated into this string.
     * `groupName`/`groupAvatar` are free text (unlike the fixed-alphabet
     * `groupId` UUID or trailing base64 `encryptedGroupKey`), so each is
     * length-prefixed before its own content — two different (name, avatar)
     * pairs can never collide to the same transcript this way, unlike a
     * bare delimiter join. No legacy fallback: both platforms must ship
     * this together, same cutover posture as S6-58's voice transcript. */
    private fun groupCreatePayload(groupId: String, groupName: String, groupAvatar: String, encryptedGroupKey: String): String =
        "SUBROSA_GROUP_CREATE_V1:$groupId:${groupName.length}:$groupName:${groupAvatar.length}:$groupAvatar:$encryptedGroupKey"

    /** Canonical V1 transcript for the "member_keys" roster extension —
     * signed SEPARATELY from roster_signature (rosterPayload() above is left
     * untouched rather than reshaped, matching this file's existing
     * versioning convention of adding a new domain-separated transcript
     * instead of silently changing what an existing signature covers).
     *
     * Lets a group_create/group_member_added recipient learn every fellow
     * member's EC + PQ public key and display name at join time, not just
     * the sender's own. Found live, 2026-09-20: two members added to the
     * same group by a THIRD party, who were never 1:1 contacts of each
     * other, showed no name for one another and had no working group-call
     * connection between them — call_group_join/call_group_answer signature
     * verification needs ChatStorage.getContactPublicKey(from) (see the
     * anon_delivery control-envelope check), which was simply never
     * populated for a fellow member never directly contacted. The group
     * creator/admin already possesses every member's EC+PQ key at this
     * point regardless (encryptGroupKeyForMember() needs them for every
     * recipient), so this costs nothing to also broadcast.
     *
     * Each field is length-prefixed (matches groupCreatePayload()'s own
     * convention) so two different entries can never collide to the same
     * transcript via a bare delimiter join; entries are sorted by
     * fingerprint so the transcript is independent of iteration order. */
    private fun memberKeysPayload(groupId: String, entries: List<JSONObject>): String {
        val canonical = entries.sortedBy { it.getString("fingerprint") }.joinToString(";") { e ->
            val fp = e.getString("fingerprint")
            val pk = e.getString("public_key")
            val pq = e.getString("pq_public_key")
            val name = e.optString("name", "")
            "$fp:${pk.length}:$pk:${pq.length}:$pq:${name.length}:$name"
        }
        return "SUBROSA_GROUP_MEMBER_KEYS_V1:$groupId:$canonical"
    }

    /** Builds one member_keys entry, or null if this device doesn't have
     * both an EC and a PQ key for [fingerprint] on hand (own identity is
     * always available; a fellow member's requires them to already be a
     * resolvable contact — same precondition encryptGroupKeyForMember()
     * already has for the group key itself). */
    private fun buildMemberKeyEntry(fingerprint: String): JSONObject? {
        val publicKey: String?
        val pqPublicKeyB64: String?
        if (fingerprint == username) {
            publicKey = CryptoManager.getPublicKeyString()
            pqPublicKeyB64 = try { SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey } catch (e: Exception) { null }
        } else {
            publicKey = publicKeys[fingerprint]
                ?: ChatStorage.getContactPublicKey(this, fingerprint)?.also { publicKeys[fingerprint] = it }
            pqPublicKeyB64 = resolvePqKey(fingerprint)?.let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
        }
        if (publicKey.isNullOrBlank() || pqPublicKeyB64.isNullOrBlank()) return null
        return JSONObject().apply {
            put("fingerprint", fingerprint)
            put("public_key", publicKey)
            put("pq_public_key", pqPublicKeyB64)
            put("name", if (fingerprint == username) UserStorage.getUserDisplayName(this@MessengerService) else ChatStorage.getContactName(this@MessengerService, fingerprint))
        }
    }


    /** Returns whether the frame actually left this device — false means
     *  webSocket.send() found the socket already closed (or there's no
     *  webSocket at all), a definite failure, not just "unconfirmed". The
     *  AGGRESSIVE-cover-traffic path enqueues onto outboundQueue instead of
     *  sending directly; that always "succeeds" from this function's point
     *  of view (the frame will go out once outboundQueueSenderJob drains
     *  it, same as any other queued frame — not this call's problem to
     *  track further). See sendAnonOrDirect() for why this return value
     *  matters: consumeNextContactToken() already removed a single-use
     *  token from the local pool before this call, and a definite send
     *  failure needs to restore it rather than silently losing the token
     *  and the message both. */
    private fun sendWs(json: String): Boolean {
        // Diagnostic added 2026-08-28 while chasing the post-call zombie-write
        // bug: ping/pong keeps succeeding indefinitely while anon_message
        // traffic silently vanishes before ever reaching the server, on what
        // should be the same single WebSocket — even right after a forced
        // clean reconnect. That symmetry only makes sense if two different
        // WebSocket objects are somehow live and this function is sometimes
        // reading a stale one. Logging identityHashCode(webSocket) + the
        // packet's "type" on every call proves or disproves that directly
        // instead of guessing further.
        val ws = webSocket
        val typeForLog = try { JSONObject(json).optString("type", "?") } catch (e: Exception) { "?" }
        Log.d(TAG, "sendWs: type=$typeForLog ws=${System.identityHashCode(ws)}")
        val mode = UserStorage.getCoverTrafficMode(this)
        if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE && isConnected) {
            if (!outboundQueue.offer(json)) {
                Log.w(TAG, "outboundQueue переполнена — отправляем напрямую")
                return ws?.send(json) ?: false
            }
            return true
        } else {
            return ws?.send(json) ?: false
        }
    }

    /** Sends [tokens] as one or more "subscribe_tokens" messages, each
     *  capped at server.py's own MAX_TOKENS_PER_SUBSCRIBE (100) — that limit
     *  is enforced server-side via a silent `[:100]` slice with no error back
     *  to the client (server.py's subscribe_tokens handler), so a single
     *  oversized call doesn't fail loudly, it just quietly drops whatever
     *  token fell past index 100.
     *
     *  Found live 2026-09-20: AnonTokenManager.tokensToSubscribe() —
     *  ensureMyTokenPool() (capped at MAX_POOL_HARD_CAP=100) PLUS
     *  getMyTokensAckPending() on top, with no combined cap — routinely
     *  exceeds 100 (observed 101 in a live client log) whenever a few
     *  messages are still awaiting anon_delivery_ack_ok at the exact moment
     *  the pool is near its own ceiling, e.g. right after a post-call
     *  forced reconnect (CallManager.release()'s call_ended_force_ws_reconnect)
     *  piles a fresh resupply batch on top of tokens already in flight from
     *  before the call. freshTokensToShare() always PREPENDS new tokens, so
     *  whatever silently fell off the tail of a truncated subscribe was
     *  reliably the OLDEST surviving tokens — exactly the ones a contact was
     *  already holding and addressing us with. That contact's sends then
     *  report "офлайн, сообщение в очереди" forever (never a transient
     *  delay), until enough newer tokens ahead of it in the list get
     *  consumed to shift it back within the first 100, or it's abandoned for
     *  a freshly-resupplied token instead — exactly the symptom reported
     *  live. Chunking here costs nothing (subscribe_tokens's rate limit is
     *  10/min, and pool+ack-pending overlap this large is already the rare
     *  case per server.py's own sizing comment) and guarantees every token
     *  this device owns is always actually registered. */
    private fun sendSubscribeTokens(tokens: List<String>) {
        if (tokens.isEmpty()) return
        tokens.chunked(100).forEach { chunk ->
            sendWs(JSONObject().apply {
                put("type", "subscribe_tokens")
                put("tokens", org.json.JSONArray(chunk))
            }.toString())
        }
    }

    /** Opens the identity-less anon_channel connection (Sealed Sender, шаг
     *  2) — same server, but skips the whole challenge_response/register
     *  dance entirely: server never learns a public_key/fingerprint for this
     *  socket, see server.py's "anon_channel" handshake branch. Called once
     *  the main connection is up; a failure here just leaves anonChannelReady
     *  false — sendOnAnonChannelNow() queues rather than falling back to the
     *  identified main socket (see its own comment), and keeps retrying this
     *  connection until it succeeds. */
    private fun connectAnonChannel() {
        // Found live 2026-08-29: this is called from two separate places on
        // every reconnect (connect()'s post-register continuation and the
        // "handshake_ok" handler). The anonChannelConnecting guard alone only
        // protects against two calls racing WHILE a connect attempt is still
        // in flight — if the first one already finished successfully by the
        // time the second call site runs, this used to open a redundant
        // second connection on top of the working one, silently leaking the
        // first (never closed, anonChannelWs just got overwritten).
        if (anonChannelConnecting || anonChannelReady) return
        anonChannelConnecting = true
        anonChannelLastAttemptMs = System.currentTimeMillis()
        // Random delay before actually opening the socket — found live
        // 2026-08-29 (external review): without this, anon_channel opened a
        // fixed, near-immediate interval after the main socket every single
        // time, which is itself a correlation signal — an observer just
        // watching connection-accept timestamps (no IP, no TLS detail, no
        // application data needed) could pair "these two connections opened
        // within ~1s of each other" with high confidence. 0–3s spread is
        // cheap and doesn't meaningfully delay anon_channel's actual
        // availability (sendOnAnonChannelNow() already queues rather than
        // blocking while it's not ready).
        scope.launch(Dispatchers.IO) {
            kotlinx.coroutines.delay((0L..3000L).random())
            doConnectAnonChannel()
        }
    }

    private fun doConnectAnonChannel() {
        val server = ServerManager.getCurrentServer(this) ?: run { anonChannelConnecting = false; return }
        val wsUrl = server.toWssUrl()
        if (wsUrl.contains(".onion") && !TorManager.isConnected) { anonChannelConnecting = false; return }

        val request = Request.Builder()
            .url(wsUrl)
            .addHeader("Connection", "Upgrade")
            .addHeader("Upgrade", "websocket")
            .addHeader("Sec-WebSocket-Version", "13")
            .addHeader("Sec-WebSocket-Key", generateWebSocketKey())
            .build()

        val listener = object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Log.d(TAG, "anon_channel: открыт ws=${System.identityHashCode(ws)}")
            }

            override fun onMessage(ws: WebSocket, text: String) {
                try {
                    val json = JSONObject(text)
                    when (json.optString("type")) {
                        // Required first frame on every connection regardless
                        // of what handshake follows (see server.py) — anon_channel
                        // doesn't sign it, just acknowledges with its own type.
                        "challenge" -> ws.send(JSONObject().apply { put("type", "anon_channel") }.toString())
                        "anon_channel_ok" -> {
                            anonChannelReady = true
                            anonChannelConnecting = false
                            Log.d(TAG, "anon_channel: готов")
                            // Flush anything that queued up while this
                            // connection wasn't ready — see
                            // anonChannelPendingQueue's comment.
                            var flushed = 0
                            var queued = anonChannelPendingQueue.poll()
                            while (queued != null) {
                                ws.send(queued)
                                flushed++
                                queued = anonChannelPendingQueue.poll()
                            }
                            if (flushed > 0) Log.d(TAG, "anon_channel: разгружено $flushed отложенных пакетов")
                        }
                        "ack" -> {
                            val id = json.optString("id", null)
                            if (id != null) MessageQueue.remove(this@MessengerService, id)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "anon_channel onMessage error: ${e.message}")
                }
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                Log.w(TAG, "anon_channel ошибка: ${t.message}")
                anonChannelReady = false
                anonChannelConnecting = false
                if (anonChannelWs === ws) anonChannelWs = null
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                anonChannelReady = false
                anonChannelConnecting = false
                if (anonChannelWs === ws) anonChannelWs = null
            }
        }

        // Bug found live 2026-08-30: this used to pick anonWsClient (the
        // NON-Tor client, useTor=false) for .onion addresses — the plain
        // client has no SOCKS proxy configured at all and can't resolve an
        // .onion hostname through Android's normal DNS (there's no other way
        // to resolve one). The TorManager.isConnected guard above only
        // confirms Orbot's SOCKS proxy is reachable, it doesn't make the
        // plain client route through it. anonWsTorClient is the one built
        // with the SOCKS5 socketFactory (buildOkHttpClient(useTor=true)),
        // matching how Desktop's WebSocketClient.kt and the main-socket
        // connect() below both handle .onion.
        val client = if (wsUrl.contains(".onion")) anonWsTorClient else activeAnonWsClient()
        anonChannelWs = client.newWebSocket(request, listener)
    }

    /** Anon-channel equivalent of sendWs() — routes anon_message traffic
     *  (real and cover-traffic decoys alike, see startCoverTraffic()) off
     *  the identified main socket. In AGGRESSIVE mode, queues instead of
     *  sending immediately — see startCoverTraffic()'s paced drain of
     *  anonOutboundQueue, mirroring what sendWs() already does for
     *  outboundQueue on the main socket. Found live 2026-08-29: without
     *  this, a real anon_message fired the moment the user sent it,
     *  immediately, while decoys stayed on the fixed 1s cadence — the
     *  timing itself became a tell (real sends no longer hid among the
     *  padded interval), defeating AGGRESSIVE mode's actual purpose for
     *  anon_message traffic specifically. */
    private fun sendOnAnonChannel(json: String): Boolean {
        val mode = UserStorage.getCoverTrafficMode(this)
        if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE && isConnected) {
            if (!anonOutboundQueue.offer(json)) {
                Log.w(TAG, "anonOutboundQueue переполнена — отправляем напрямую")
                return sendOnAnonChannelNow(json)
            }
            return true
        }
        return sendOnAnonChannelNow(json)
    }

    /** Unpaced send — used directly by sendOnAnonChannel() outside
     *  AGGRESSIVE mode, and by startCoverTraffic()'s paced drain loop
     *  (which already IS the pacing, so it must bypass sendOnAnonChannel()'s
     *  own queueing to avoid queuing a queue).
     *
     *  Found live 2026-08-29, removed deliberately: this used to fall back
     *  to sendWs() (the identified main socket) whenever the anon channel
     *  wasn't ready yet — meaning a real anon_message could silently go out
     *  fully identified, with no warning, exactly the "anonymous → identified
     *  fail-open" pattern flagged as the highest-priority gap in sealed
     *  sender's rollout. Same call as removing freshTokensToShare()'s blind
     *  eviction earlier this session: a fallback that silently degrades a
     *  security property is worse than making the caller wait. Now: queues
     *  into anonChannelPendingQueue and opportunistically (re)connects
     *  (throttled to once per 10s) instead — flushed once anon_channel_ok
     *  actually arrives, never routed through the identified socket. */
    private fun sendOnAnonChannelNow(json: String): Boolean {
        val ws = anonChannelWs
        if (anonChannelReady && ws != null) {
            return ws.send(json)
        }
        if (!anonChannelConnecting && System.currentTimeMillis() - anonChannelLastAttemptMs > 10_000) {
            connectAnonChannel()
        }
        if (!anonChannelPendingQueue.offer(json)) {
            Log.w(TAG, "anonChannelPendingQueue переполнена — пакет отброшен")
            return false
        }
        return true
    }

    private fun sendAnonMessageWs(anonPacket: JSONObject): Boolean =
        sendOnAnonChannel(addPadding(anonPacket).toString())

    private fun disconnectAnonChannel() {
        anonChannelWs?.close(1000, "main disconnect")
        anonChannelWs = null
        anonChannelReady = false
        anonChannelConnecting = false
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
                    // Found live: this used to just delay+continue forever without
                    // ever touching failuresOnCurrentServer — since Tor is opt-in
                    // now (off by default), an onion server in the rotation could
                    // never connect, but the failure counter that drives
                    // switchToNext() below never saw it as a failure. The reconnect
                    // loop got stuck retrying the same dead onion entry every 5s
                    // indefinitely instead of cycling to the next server (which
                    // does correctly wrap back to index 0 — the bug was never
                    // reaching that call at all).
                    if (!UserStorage.isTorEnabled(this@MessengerService)) {
                        Log.w(TAG, "Onion-сервер выбран, но Tor выключен пользователем — переключаемся")
                        ServerManager.switchToNext(this@MessengerService)
                        failuresOnCurrentServer = 0
                        reconnectAttempts = 0
                        delay(500)
                        continue
                    }
                    Log.w(TAG, "Onion-сервер выбран, но Tor недоступен — ждём Orbot")
                    delay(5000)
                    failuresOnCurrentServer++
                    if (failuresOnCurrentServer >= MAX_FAILURES_BEFORE_SWITCH) {
                        ServerManager.switchToNext(this@MessengerService)
                        failuresOnCurrentServer = 0
                        reconnectAttempts = 0
                    }
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
                // Generation-scoped synchronization (external review
                // 2026-09-05, S6-40) — replaces the old process-global
                // `handshakeDone` Boolean that `connect()` used to POLL
                // (`while (!handshakeDone) delay(100)`) with an
                // event-driven pair created FRESH for this exact websocket
                // generation and captured directly by this listener's
                // closures below, never shared with any other generation.
                // `handshakeReady` completes once (success or failure) the
                // instant this attempt's handshake outcome is known;
                // `registrationReady` completes only once the server's
                // explicit `register_ok` acknowledgment arrives (or a
                // definitive registration failure/socket teardown makes it
                // clear this generation's registration will not succeed —
                // see the `register_ok`/`totp_required`/etc. branches in
                // handleMessage() below). A stale callback firing after
                // THIS generation has already been abandoned (a new
                // connect() iteration underway) can only ever touch ITS
                // OWN pair, captured by closure here — never a replacement
                // socket's, since a fresh pair is created before any new
                // listener/socket is built.
                val myHandshakeReady = CompletableDeferred<Unit>()
                val myRegistrationReady = CompletableDeferred<Unit>()

                val listener = object : WebSocketListener() {

                    override fun onOpen(ws: WebSocket, response: Response) {
                        Log.d(TAG, "WebSocket открыт ws=${System.identityHashCode(ws)}")
                    }

                    override fun onMessage(ws: WebSocket, text: String) {
                        lastServerActivityMs = System.currentTimeMillis()
                        scope.launch(Dispatchers.IO) {
                            try {
                                val json = JSONObject(text)
                                handleMessage(json, myHandshakeReady, myRegistrationReady)
                            } catch (e: Exception) {
                                Log.e(TAG, "onMessage error: ${e.message}")
                            }
                        }
                    }

                    override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                        Log.e(TAG, "WebSocket ошибка: ${t.message} ws=${System.identityHashCode(ws)} currentWs=${System.identityHashCode(webSocket)}")
                        isConnected = false
                        stopCoverTraffic()
                        stopControlPlaneNoise()
                        disconnectAnonChannel()
                        // completeExceptionally, not complete(Unit) — if this
                        // races AHEAD of "handshake_ok" (socket never even
                        // reached it), connect()'s await() must see a genuine
                        // failure here, not a false "handshake succeeded". A
                        // no-op if "handshake_ok" already completed it first
                        // (CompletableDeferred resolves once) — harmless,
                        // connect() has already moved on by then anyway.
                        myHandshakeReady.completeExceptionally(t)
                        myRegistrationReady.completeExceptionally(Exception("websocket failure before registration completed"))
                        NetworkConfig.TurnCredentials.clear()
                    }

                    override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                        Log.d(TAG, "WebSocket закрыт: $code $reason ws=${System.identityHashCode(ws)} currentWs=${System.identityHashCode(webSocket)}")
                        isConnected = false
                        stopCoverTraffic()
                        stopControlPlaneNoise()
                        disconnectAnonChannel()
                        // Same reasoning as onFailure() above.
                        myHandshakeReady.completeExceptionally(Exception("websocket closed: $code $reason"))
                        myRegistrationReady.completeExceptionally(Exception("websocket closed before registration completed"))
                        NetworkConfig.TurnCredentials.clear()
                    }
                }

                // Same bug as anonWsClient below/above (doConnectAnonChannel) —
                // wsClient has no SOCKS proxy at all, wsTorClient is the one
                // actually built to route through Orbot for a hostname
                // Android's normal DNS can never resolve. Found live 2026-08-30.
                val client = if (wsUrl.contains(".onion")) wsTorClient else activeWsClient()
                webSocket = client.newWebSocket(request, listener)
                Log.d(TAG, "connect: новый webSocket создан ws=${System.identityHashCode(webSocket)}")

                // isConnected is no longer usable as the handshake-success
                // signal here — it now only flips true once registration
                // completes (see "handshake_ok"'s own comment), which hasn't
                // happened yet at this point even on a perfectly successful
                // handshake. myHandshakeReady itself is the signal: the
                // "challenge" handler completes it exceptionally on failure,
                // successfully on a sent challenge_response — so await()
                // throwing (failure or timeout) is the one thing this needs
                // to check.
                try {
                    withTimeout(15_000) { myHandshakeReady.await() }
                } catch (e: Exception) {
                    Log.e(TAG, "Handshake failed: ${e.message}")
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
                val deviceIdForRegister = UserStorage.getDeviceId(this@MessengerService)
                val registerPacket = JSONObject().apply {
                    put("type", "register")
                    put("from", username)
                    put("name", displayName)
                    put("public_key", CryptoManager.getPublicKeyString())
                    put("protocol_version", ProtocolVersion.CURRENT_VERSION)
                    put("device_id", deviceIdForRegister)
                    if (myAvatarB64.isNotEmpty()) put("avatar", myAvatarB64)
                    if (totpSecret != null) put("totp_code", TotpManager.currentCode(totpSecret))
                    if (!accessCode.isNullOrBlank()) put("access_code", accessCode)
                    if (!recoveryCode.isNullOrBlank()) put("recovery_code", recoveryCode)
                    // Device-key authentication (external review 2026-09-03) —
                    // sent unconditionally, same "let the server decide"
                    // principle as totp_code/access_code above: server.py only
                    // actually looks at these when TOTP is configured for this
                    // account (user_totp_secrets), which this device can't
                    // always know locally (e.g. TOTP was enabled from a
                    // DIFFERENT device that holds the secret). Harmless no-op
                    // on any server/account combination that doesn't check
                    // them. See DeviceKeyManager's own comment for why this
                    // keypair is separate from the identity key and never
                    // included in a backup.
                    lastChallengeBytes?.let { challengeBytes ->
                        put("device_public_key", DeviceKeyManager.getPublicKeyString(this@MessengerService))
                        put(
                            "device_signature",
                            DeviceKeyManager.signDeviceChallenge(this@MessengerService, challengeBytes, username, deviceIdForRegister)
                        )
                    }
                }
                // Remembered so the "pow_required" handler below can resend this
                // exact packet with a pow_nonce added, without redoing the
                // recovery_code/access_code/totp gathering above (recoveryCode
                // in particular is one-shot — pendingRecoveryCode is already
                // cleared by the time a retry would happen).
                lastRegisterPacket = registerPacket
                sendWs(registerPacket.toString())

                // Event-driven gate (external review 2026-09-05, S6-40) —
                // account-scoped startup traffic below (register_bundle,
                // publish_prekey_bundle, request_sender_cert,
                // subscribe_tokens, register_fcm, flushQueue()) must not
                // reach the server until THIS socket has actually completed
                // registration — sending any of it earlier is exactly the
                // race that let register_bundle arrive before register on
                // the server, forcing a temporary compatibility exception
                // there (removed now that this ordering is deterministic).
                // Completes on the server's `register_ok` ack (success) or
                // on a definitive registration failure/socket teardown
                // (exceptionally) — see handleMessage()'s handling of
                // those message types. `pow_required` deliberately does
                // NOT complete this: it resends `register` automatically
                // and this same await just keeps waiting for that retry's
                // eventual outcome. A generous timeout covers one PoW
                // round-trip comfortably without polling.
                val registered = try {
                    withTimeoutOrNull(30_000) {
                        myRegistrationReady.await()
                        true
                    } ?: false
                } catch (e: Exception) {
                    Log.w(TAG, "Регистрация не подтверждена сервером: ${e.message}")
                    false
                }

                if (!registered) {
                    Log.e(TAG, "connect: регистрация не подтверждена сервером — переподключаемся")
                    webSocket?.close(1000, "registration not confirmed")
                    throw Exception("Registration not confirmed")
                }

                // Set deterministically HERE too, not only in "handshake_ok"'s
                // own (separate coroutine, separately scheduled) reaction to
                // the same registrationReady completion — this coroutine has
                // already confirmed `registered` sequentially, with no race,
                // so this line can never observe a false negative. Without
                // it, the final `while (isConnected) { delay(1000) }` loop
                // below could run its very first check before the OTHER
                // coroutine gets scheduled, see isConnected still false, and
                // treat a connection that just succeeded as already dead —
                // closing a perfectly good socket and spinning up a redundant
                // one (risking a self-inflicted session_conflict kick).
                // Idempotent — a harmless redundant write if "handshake_ok"'s
                // own assignment already ran first.
                isConnected = true

                // Moved here from the old "handshake_ok" handler (external
                // review 2026-09-05, S6-40) — that handler used to send this
                // the INSTANT the handshake completed, running in a SEPARATE
                // coroutine from this one (spawned per incoming message),
                // with no ordering guarantee at all against this coroutine's
                // own `register` send above. That's exactly the race this
                // fix closes: register_bundle now only ever goes out AFTER
                // this same generation's registration is confirmed.
                try {
                    if (!sessionManagerInitialized) {
                        sessionManagerInitialized = true
                        SessionKeyManager.initialize(this@MessengerService)
                        Log.d(TAG, "SessionKeyManager переинициализирован")
                    }
                    val bundle = SessionKeyManager.generatePrekeyBundle()
                    val registerBundle = JSONObject().apply {
                        put("type", "register_bundle")
                        put("bundle", bundle)
                    }
                    sendWs(registerBundle.toString())
                    Log.d(TAG, "Prekey bundle отправлен на регистрацию")
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка регистрации bundle: ${e.message}")
                }

                // Moved here from the old "handshake_ok" handler — same race
                // as register_bundle/pollMailbox above, just missed when
                // those were fixed (external review 2026-09-05, S6-40): this
                // used to fire get_prekey_bundle the instant the handshake
                // completed, from a separate per-message coroutine with no
                // ordering guarantee against this coroutine's own `register`
                // send. Confirmed live on srv-de-01 2026-09-13: "'get_prekey_
                // bundle' от ... до успешной регистрации — закрываю", server
                // closing the socket before `register` ever landed, which
                // then failed registration itself and looped into repeated
                // reconnects and rate-limit bans. Clearing pendingBundleRequests
                // and re-firing for contacts still waiting (pendingSessionMessages)
                // is unchanged — only the timing moved, now gated on this
                // generation's registration being confirmed.
                pendingBundleRequests.clear()
                pendingSessionMessages.keys.toList().forEach { contactId ->
                    requestPrekeyBundle(contactId)
                }

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
                // Was `SessionKeyManager.deleteAllSessions()` followed by
                // `initialize()` here, unconditionally, on literally every
                // successful register() — i.e. every single reconnect, not
                // just app start. deleteAllSessions() wipes every Double
                // Ratchet session for every contact from BOTH memory AND
                // disk (see its own doc comment), plus the in-memory OPK
                // pool and current SPK. Root-caused live 2026-08-17: this
                // is why a contact's session kept vanishing right around
                // reconnects all evening, cascading into "Пакет повреждён
                // (ephemeral key)" decrypt failures, mutual session_reset,
                // and — worse — permanently undecryptable in-flight
                // messages (their ratchet state was gone on both ends by
                // the time of redelivery, no amount of retrying the same
                // ciphertext could ever fix that). SessionKeyManager.
                // initialize() is already called exactly once per process
                // lifetime elsewhere in this function (the
                // sessionManagerInitialized guard, fixed 2026-08-17) — this
                // was a redundant, unguarded duplicate of that same
                // "run once" intent that never got a guard, and unlike the
                // guarded one it also actively destroyed session state
                // instead of just reloading it. Intentional
                // deleteAllSessions() calls for identity resets/panic wipes
                // (BackupManager.kt, WipeManager.kt) are untouched — this
                // was specifically the unconditional per-reconnect copy.
                publishPrekeyBundle()

                // Sealed Sender, шаг 1: сертификат "это я" — запрашивается по
                // тому же уже аутентифицированному сокету, нечего скрывать на
                // этом шаге (запрос не содержит адресата). Кэшируется и
                // переиспользуется, пока не подойдёт к истечению.
                if (SenderCertManager.getFresh(this@MessengerService) == null) {
                    sendWs(JSONObject().apply {
                        put("type", "request_sender_cert")
                    }.toString())
                }

                val myTokens = AnonTokenManager.tokensToSubscribe(this@MessengerService)
                if (myTokens.isNotEmpty()) {
                    Log.d(TAG, "DEBUG-TOKENLIFE connect(): subscribe_tokens (${myTokens.size}) — ${myTokens.map { "…${it.takeLast(6)}" }}")
                    sendSubscribeTokens(myTokens)
                }

                startCoverTraffic()
                startControlPlaneNoise()
                connectAnonChannel()
                lastServerActivityMs = System.currentTimeMillis()
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

                // Moved here from the old "handshake_ok" handler (external
                // review 2026-09-05, S6-40 follow-up) — same race as
                // register_bundle's original bug: that handler runs in a
                // separate per-message coroutine with no ordering guarantee
                // against this coroutine's own `register` send, so
                // mailbox_fetch could reach the server first and get closed
                // by the hard authorization boundary. Confirmed live on
                // srv-de-01 (repeated connect/mailbox_fetch-rejected/
                // reconnect cycling). Now only sent after this generation's
                // registration is confirmed, same as register_bundle above.
                pollMailbox()
                scope.launch(Dispatchers.IO) {
                    while (isConnected && scope.isActive) {
                        delay(30_000)
                        if (isConnected && AnonTokenManager.getMyMailboxTags(this@MessengerService).isNotEmpty())
                            pollMailbox()
                    }
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

    private suspend fun handleMessage(
        json: JSONObject,
        handshakeReady: CompletableDeferred<Unit>? = null,
        registrationReady: CompletableDeferred<Unit>? = null
    ) {
        val type = json.optString("type")

        when (type) {

            "challenge" -> {
                try {
                    val challengeData = json.getString("data")
                    val challengeBytes = android.util.Base64.decode(challengeData, android.util.Base64.DEFAULT)
                    lastChallengeBytes = challengeBytes
                    val signature = CryptoManager.signBytes(challengeBytes)
                    sendWs(JSONObject().apply {
                        put("type", "challenge_response")
                        put("public_key", CryptoManager.getPublicKeyString())
                        put("signature", signature)
                    }.toString())
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка handshake: ${e.message}")
                    // completeExceptionally, not complete(Unit) — connect()'s
                    // own await() needs to distinguish "challenge_response
                    // sent" from "handshake failed before we could even
                    // respond" now that isConnected no longer doubles as
                    // that signal (see connect()'s own comment).
                    handshakeReady?.completeExceptionally(e)
                }
            }

            "handshake_ok" -> {
                handshakeReady?.complete(Unit)
                totpRequiredNotified = false
                Log.d(TAG, "Handshake завершён успешно")
                PanicNotificationManager.show(this@MessengerService)

                // Handshake only proves possession of the private key — NOT a
                // successful register(). Everything below (isConnected=true,
                // cover traffic, background watchdog/retry loops, flushing
                // queued sends) used to run right here, the instant the
                // handshake completed, which is exactly the S6-40 race this
                // file's other fixes already closed for register_bundle/
                // pollMailbox/get_prekey_bundle: isConnected became a
                // premature "safe to send" signal that let application code
                // (sendAnonOrDirect's own !isConnected check, sendTyping,
                // sendRead, ...) fire real traffic — and, via requestPrekeyBundle(),
                // get_prekey_bundle specifically — before connect()'s own
                // coroutine had even sent `register`, tripping the server's
                // "no message before register_ok" boundary and closing the
                // socket before registration could ever complete. Confirmed
                // live 2026-09-13 (srv-de-01: "'get_prekey_bundle' ... до
                // успешной регистрации — закрываю" firing from THIS path, not
                // the one already fixed). Waiting here for registrationReady
                // — completed by the "register_ok" branch below, in a later,
                // separate handleMessage() invocation for the same generation
                // — means every isConnected=true consumer in this class now
                // genuinely means "registered", not just "handshook". If
                // registration never completes (timeout, rejection, socket
                // teardown), registrationReady completes exceptionally and
                // this coroutine simply stops here: isConnected never flips,
                // no cover traffic/background loop ever starts for a
                // connection the server never actually accepted.
                try {
                    registrationReady?.await()
                } catch (e: Exception) {
                    return
                }
                isConnected = true

                // register_bundle used to be sent here, the instant the
                // handshake completed — moved to connect(), gated on
                // registrationReady (external review 2026-09-05, S6-40):
                // this handler runs in a coroutine spawned per incoming
                // message, with no ordering guarantee against connect()'s
                // own coroutine sending `register`. See connect()'s own
                // comment at the new send site.

                startCoverTraffic()
                startControlPlaneNoise()
                connectAnonChannel()
                withContext(Dispatchers.Main) {
                    onStatusChanged?.invoke(true)
                }

                flushPendingVideoCircles()

                // Retry anything queued by sendAnonOrDirect()/queuePendingAnon() while we
                // were disconnected, now that isConnected is genuinely true. Without this,
                // a queued packet only got retried via flushPendingAnon(from) — which fires
                // solely on receiving fresh tokens FROM that contact — so on a quiet chat
                // with no incoming traffic it could sit stuck indefinitely after a
                // reconnect. See sendAnonTokensTo()'s isConnected guard, added same day.
                synchronized(pendingAnonPackets) { pendingAnonPackets.keys.toList() }.forEach { contact ->
                    flushPendingAnon(contact)
                }

                val pendingResetContacts = UserStorage.getAndClearPendingSessionResetContacts(this@MessengerService)
                if (pendingResetContacts.isNotEmpty()) {
                    Log.d(TAG, "Рассылаем session_reset ${pendingResetContacts.size} контактам после восстановления бэкапа")
                    scope.launch(Dispatchers.IO) {
                        pendingResetContacts.forEach { contactId ->
                            // Found live 2026-08-30 via BAD_DECRYPT loop after
                            // restore: this used to unconditionally delete the
                            // session and send session_reset, racing with the
                            // ORDINARY "no session yet" path — sendWithForwardSecrecy()
                            // already does a full, honest X3DH bootstrap the
                            // moment the user sends (or this loop's own
                            // sendAnonTokensTo() below triggers traffic) with no
                            // session on file, which the peer receives and
                            // decrypts fine on its own. If that happened to land
                            // first, this explicit session_reset — arriving
                            // moments later — told the peer to tear down the
                            // session that had JUST started working, while this
                            // device (which already believes hasSession()==true)
                            // never sends a follow-up session_init to rebuild it.
                            // Peer sits waiting forever; anything it had in
                            // flight under the torn-down ratchet arrives as
                            // BAD_DECRYPT. Only send the explicit reset when
                            // there's genuinely no session yet on this side —
                            // the case the natural bootstrap hasn't (yet) fixed.
                            if (SessionKeyManager.hasSession(contactId)) {
                                // Found live 2026-09-02: this branch used to send
                                // nothing but tokens — fine for the Double Ratchet
                                // session (already working, left untouched on
                                // purpose, see below), but our own SPK/PQ-KEM is
                                // still brand-new since the restore that got us
                                // here (wipeCurrentIdentityData() never survives a
                                // "Это не я" wipe), and this contact's cached copy
                                // of our old bundle was never invalidated by
                                // anything — a second restore cycle after the
                                // first one already healed left them permanently
                                // stuck decrypting anon_delivery against a
                                // doubly-stale key. pq_bundle_refresh carries the
                                // same "go fetch a fresh bundle for me" signal as
                                // session_reset without touching either side's
                                // Double Ratchet session.
                                sendAnonOrDirect(contactId, JSONObject().apply {
                                    put("type", "pq_bundle_refresh")
                                    put("from", username)
                                    put("to", contactId)
                                })
                                sendAnonTokensTo(contactId)
                                return@forEach
                            }
                            SessionKeyManager.deleteSession(contactId)
                            sendAnonOrDirect(contactId, JSONObject().apply {
                                put("type", "session_reset")
                                put("from", username)
                                put("to", contactId)
                            })
                            // Found live 2026-08-30: session_reset alone only
                            // fixes the crypto ratchet (deletes the stale
                            // Double Ratchet session, waits for a fresh
                            // session_init) — it does nothing about anon-token
                            // routing. BackupManager.importBackup() wipes this
                            // device's OWN token pool (AnonTokenManager.clearAll,
                            // via wipeCurrentIdentityData()) and regenerates a
                            // brand-new set of random values with no continuity
                            // to whatever this contact was already holding from
                            // before the restore. The contact's existing tokens
                            // for reaching this identity now route nowhere —
                            // their messages queue silently in the server's
                            // token_pending (up to 24h) with no error on either
                            // side, exactly the "messages from a contact I
                            // didn't touch don't arrive" symptom. Restored
                            // contacts still have a valid, still-usable token
                            // FROM this contact (that side is unaffected by our
                            // restore — the contact's own subscription never
                            // changed), so sendAnonTokensTo() can ride on it (or
                            // fall back to mailbox) to hand them a fresh batch of
                            // our new tokens immediately, without waiting for
                            // them to message first.
                            sendAnonTokensTo(contactId)
                        }
                    }
                }

                // pollMailbox() moved to connect(), gated on registrationReady
                // (external review 2026-09-05, S6-40 follow-up) — this handler
                // used to call it the instant the handshake completed, same
                // bug class as the old register_bundle race S6-40 already
                // fixed: this handler runs in a coroutine spawned per incoming
                // message, with no ordering guarantee against connect()'s own
                // `register` send. Confirmed live on srv-de-01: mailbox_fetch
                // reaching the server before `register` had committed,
                // rejected by the S6-39/S6-40 hard authorization boundary,
                // connection closed, reconnect, repeat — an infinite loop.
                // See connect()'s own comment at the new call site.

                scope.launch(Dispatchers.IO) {
                    while (isConnected && scope.isActive) {
                        delay(60_000)
                        if (isConnected) checkContactSilence()
                    }
                }

                // Retries any packets still sitting in pendingAnonPackets, independent
                // of the user doing anything. Without this, recovery for a contact
                // whose pool went empty (e.g. right after a call) depended entirely on
                // sendAnonOrDirect() being called again — which only happens if the
                // user keeps typing/sending. Found live 2026-08-28: with nobody
                // actively sending, a token-empty contact could sit stuck for minutes
                // (TOKEN_BOOTSTRAP_COOLDOWN_MS gates new attempts, but nothing new was
                // ever triggering one). This just re-runs queuePendingAnon's own
                // cooldown-gated bootstrap logic on a timer so it makes progress on
                // its own.
                scope.launch(Dispatchers.IO) {
                    while (isConnected && scope.isActive) {
                        delay(10_000)
                        if (!isConnected) break
                        val stuckContacts = synchronized(pendingAnonPackets) { pendingAnonPackets.keys.toList() }
                        val stuckSet = stuckContacts.toSet()
                        // Drop backoff state for anything that resolved since
                        // the last tick, so a FUTURE stuck episode starts
                        // fresh instead of inheriting an escalated delay.
                        periodicRetryDelayMs.keys.retainAll(stuckSet)
                        periodicRetryNextAt.keys.retainAll(stuckSet)
                        val now = System.currentTimeMillis()
                        stuckContacts.forEach { contact ->
                            val nextAt = periodicRetryNextAt[contact] ?: 0L
                            if (now >= nextAt) {
                                val delayMs = periodicRetryDelayMs[contact] ?: PERIODIC_RETRY_INITIAL_MS
                                periodicRetryNextAt[contact] = now + delayMs
                                periodicRetryDelayMs[contact] = (delayMs * 2).coerceAtMost(PERIODIC_RETRY_MAX_MS)
                                sendAnonTokensTo(contact)
                            }
                        }
                    }
                }

                // Connection watchdog — re-enabled 2026-08-28 after live evidence of
                // exactly the failure mode this exists for: after two calls in a row,
                // sendWs() kept returning true (frame handed to OkHttp's write buffer)
                // but the message never reached the server at all — no error, no
                // ПОЛУЧЕНО on the other side, completely silent. A write-side zombie
                // connection. Was disabled earlier today only to reduce log noise
                // while chasing the premature-anon_message handshake race (now fixed);
                // that race is unrelated to this failure mode. Drives its own app-level
                // ping/pong (server always replies "pong", see server.py msg_type ==
                // "ping") instead of relying on incoming traffic to prove liveness —
                // silence during a quiet conversation is normal, not staleness.
                scope.launch(Dispatchers.IO) {
                    try {
                        while (isConnected && scope.isActive) {
                            delay(15_000)
                            if (!isConnected) break
                            val pingSent = sendWs(JSONObject().apply { put("type", "ping") }.toString())
                            val silenceMs = System.currentTimeMillis() - lastServerActivityMs
                            Log.d(TAG, "watchdog: ping отправлен sendWs=$pingSent, тишина от сервера ${silenceMs}мс")
                            if (silenceMs > CONNECTION_WATCHDOG_TIMEOUT_MS) {
                                // Set isConnected=false ourselves rather than relying solely
                                // on close()'s onClosed callback — for a genuinely zombie
                                // socket the close frame can vanish into the void too, and
                                // that's exactly the failure mode this watchdog routes around.
                                Log.w(TAG, "watchdog: от сервера нет ответа ${CONNECTION_WATCHDOG_TIMEOUT_MS}мс — форс-переподключение")
                                isConnected = false
                                webSocket?.close(1000, "watchdog: stale connection")
                            }
                        }
                    } catch (e: Exception) {
                        // Found live 2026-08-28: this loop had no try/catch, so any
                        // exception here (e.g. a transient sendWs()/JSONObject issue)
                        // would silently kill the coroutine forever — SupervisorJob
                        // keeps siblings alive, but nothing ever logged the death, so
                        // the watchdog could stop protecting the connection with zero
                        // visible trace, indistinguishable from "everything's fine".
                        Log.e(TAG, "watchdog: цикл упал с исключением, перестал работать: ${e.message}", e)
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
                // Nothing auto-retries this on the same socket (unlike
                // pow_required below) -- registration for THIS generation is
                // done; connect()'s registrationReady.await() must not keep
                // waiting for the full timeout (external review 2026-09-05,
                // S6-40).
                registrationReady?.completeExceptionally(Exception("totp_required"))
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
                registrationReady?.completeExceptionally(Exception("access_code_required"))
            }

            "pow_required" -> {
                // Server wants proof-of-work on this new fingerprint's very
                // first registration (MAX_REGISTERED_USERS/POW_DIFFICULTY_BITS
                // in server.py) — mint cost tied to real device CPU time, not
                // to IP, which a multi-device attacker can't route around.
                // Transparent to the user: solve it and just resend register,
                // no UI involved. Deliberately does NOT complete
                // registrationReady (external review 2026-09-05, S6-40) --
                // this is a mid-flight retry, not a terminal outcome for this
                // generation; connect()'s registrationReady.await() keeps
                // waiting for whatever the retried register eventually gets
                // back (register_ok or a real failure).
                val challengeBytes = lastChallengeBytes
                val basePacket = lastRegisterPacket
                val difficultyBits = json.optInt("difficulty_bits", 18)
                if (challengeBytes == null || basePacket == null) {
                    Log.e(TAG, "pow_required: нет сохранённого challenge/register-пакета для повтора")
                    return
                }
                withContext(Dispatchers.Default) {
                    val nonce = solveProofOfWork(challengeBytes, difficultyBits)
                    val retryPacket = JSONObject(basePacket.toString()).apply {
                        put("pow_nonce", nonce)
                    }
                    sendWs(retryPacket.toString())
                }
            }

            "registration_full" -> {
                // MAX_REGISTERED_USERS reached — nothing to retry, this isn't
                // transient like pow_required.
                Log.e(TAG, "register отклонён сервером: сервер заполнен (достигнут лимит аккаунтов)")
                withContext(Dispatchers.Main) {
                    android.widget.Toast.makeText(
                        this@MessengerService, s.serversRegistrationFull, android.widget.Toast.LENGTH_LONG
                    ).show()
                }
                registrationReady?.completeExceptionally(Exception("registration_full"))
            }

            "device_auth_failed" -> {
                // Server rejected the device_public_key/device_signature pair
                // (see server.py's register()) — missing/malformed fields, a
                // bad signature, or (most seriously) a device_id that's
                // already pinned to a DIFFERENT device_pubkey than the one
                // this device just supplied. That last case, in particular,
                // is never fixable by retrying with the same device_id —
                // this device's local DeviceKeyManager keypair genuinely
                // doesn't match whatever the server already has on file for
                // this device_id (e.g. app data was wiped and regenerated a
                // new keypair, or this is a hijack attempt). Nothing to
                // automatically retry, unlike pow_required.
                Log.e(TAG, "register отклонён сервером: device_auth_failed")
                withContext(Dispatchers.Main) {
                    android.widget.Toast.makeText(
                        this@MessengerService, s.serversDeviceAuthFailed, android.widget.Toast.LENGTH_LONG
                    ).show()
                }
                registrationReady?.completeExceptionally(Exception("device_auth_failed"))
            }

            // Durable per-account device cap reached (server.py
            // MAX_AUTHORIZED_DEVICES_PER_ACCOUNT, S6-37) -- nothing to
            // automatically retry, same family as registration_full/
            // device_auth_failed above. No dedicated UI treatment yet
            // (out of scope for S6-40, which is specifically about
            // registration-completion ordering); logged and unblocks
            // connect()'s registrationReady.await() so it doesn't wait out
            // the full timeout for a definitively-failed attempt.
            "device_limit_reached" -> {
                Log.e(TAG, "register отклонён сервером: device_limit_reached")
                registrationReady?.completeExceptionally(Exception("device_limit_reached"))
            }

            // Durable per-fingerprint second-factor brute-force guard
            // (server.py db_take_second_factor_attempt(), S6-18) -- same
            // "nothing to auto-retry, unblock the wait" treatment.
            "second_factor_rate_limited" -> {
                Log.e(TAG, "register отклонён сервером: second_factor_rate_limited")
                registrationReady?.completeExceptionally(Exception("second_factor_rate_limited"))
            }

            // Explicit, unconditional success acknowledgment for a
            // committed registration (server.py Phase 2, S6-40) -- the one
            // authoritative signal that THIS socket may now send
            // account-scoped startup traffic (register_bundle,
            // publish_prekey_bundle, request_sender_cert, subscribe_tokens,
            // register_fcm, flushQueue()). See connect()'s own comment at
            // the registrationReady.await() gate.
            "register_ok" -> {
                registrationReady?.complete(Unit)
            }

            "identity_revoked" -> {
                // Server rejected register() — this fingerprint was revoked via
                // a previous "Меня скомпрометировали" on another device (or this
                // same device, before a fresh registration). The challenge/
                // response handshake still proves possession of the private
                // key, but that's no longer sufficient once the owner revoked
                // it. Nothing to retry — the identity is permanently done.
                Log.e(TAG, "register отклонён сервером: identity отозвана владельцем")
                isConnected = false
                withContext(Dispatchers.Main) {
                    onStatusChanged?.invoke(false)
                    android.widget.Toast.makeText(
                        this@MessengerService, s.identityRevokedError, android.widget.Toast.LENGTH_LONG
                    ).show()
                }
                registrationReady?.completeExceptionally(Exception("identity_revoked"))
            }

            "mailbox_result" -> handleMailboxResult(json)

            "session_conflict" -> {
                Log.w(TAG, "session_conflict: аккаунт подключён с другого устройства")
                isConnected = false
                handshakeReady?.complete(Unit)
                registrationReady?.completeExceptionally(Exception("session_conflict: kicked by another device"))
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

            "pong" -> {
                lastServerActivityMs = System.currentTimeMillis()
                Log.d(TAG, "watchdog: pong получен")
            }

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

                // Found live 2026-08-30: session_reset only ever cleared the
                // Double Ratchet session — never the separately-cached SPK/
                // PQ-KEM bundle that sealPacketForRecipient() uses for the
                // OUTER sealed-sender envelope. A device that restores a
                // backup onto a fresh install keeps its long-term EC identity
                // (so our classical key cache for it stays valid) but
                // generates a brand-new SPK/PQ-KEM at that fresh install's
                // first boot, unrelated to whatever the backup restored —
                // our cached copy of ITS bundle is now permanently stale, and
                // nothing else ever invalidates it. Every sealed message we
                // send afterward keeps landing as OPENSSL BAD_DECRYPT on
                // their end forever ("не заживает"), with zero error on OUR
                // side to reveal it — sealing against a stale-but-present
                // cached public key always "succeeds" locally; only the
                // recipient, unable to decrypt, ever sees anything wrong.
                // Clearing the cache here and refetching immediately mirrors
                // what processSessionInit() already does for a brand-new
                // contact — except this device has no way of knowing to look
                // until the sender explicitly says so via session_reset.
                publicKeysPq.remove(from)
                ChatStorage.clearContactPqPublicKey(this@MessengerService, from)
                requestPrekeyBundle(from)
            }

            // Found live 2026-09-02: a second full "Это не я"+restore cycle
            // (same identity, brand-new SPK/PQ-KEM each time — see
            // wipeCurrentIdentityData()'s doc comment) landed in the
            // hasSession()==true branch of the pendingResetContacts loop
            // below, which sends nothing but tokens — no signal ever reached
            // this contact to invalidate its now-doubly-stale cached copy of
            // our PQ bundle. Every anon_delivery from them afterward failed
            // BAD_DECRYPT forever, with no further event to ever self-heal
            // it (unlike "session_reset", nothing here needs to touch either
            // side's Double Ratchet session, so it's safe to send even when
            // a session already exists and is working).
            "pq_bundle_refresh" -> {
                val from = json.getString("from")
                Log.w(TAG, "pq_bundle_refresh от $from — наш кэш их PQ-bundle устарел, перезапрашиваем")
                publicKeysPq.remove(from)
                ChatStorage.clearContactPqPublicKey(this@MessengerService, from)
                requestPrekeyBundle(from)
            }

            "sender_cert" -> {
                try {
                    val cert = json.getJSONObject("cert")
                    val signature = json.getString("signature")
                    // Not verified here — this is our OWN cert about ourselves,
                    // signed by the server we're already talking to over an
                    // authenticated TLS connection. Verification against the
                    // server's pinned public key matters on the RECEIVING side
                    // (a peer checking someone else's cert), not here.
                    SenderCertManager.store(this@MessengerService, cert, signature)
                    Log.d(TAG, "sender_cert: получен и закэширован")
                    flushAllPendingAnon()
                } catch (e: Exception) {
                    Log.e(TAG, "sender_cert error: ${e.message}")
                }
            }

            "read" -> {
                val messageId = json.getString("id")
                val from = json.optString("from", null)
                Log.i(TAG, "ПОЛУЧЕНА квитанция read id=$messageId ← $from @ ${System.currentTimeMillis()}")

                if (from != null) {
                    val myId = UserStorage.getUserId(this@MessengerService)
                    ChatStorage.markRead(this@MessengerService, myId, from, messageId)
                }
                withContext(Dispatchers.Main) { onReadReceived?.invoke(messageId) }
            }

            "delivered" -> {
                val messageId = json.optString("id", null) ?: return
                val from      = json.optString("from", null) ?: return
                Log.i(TAG, "ПОЛУЧЕНА квитанция delivered id=$messageId ← $from @ ${System.currentTimeMillis()}")

                val myId = UserStorage.getUserId(this@MessengerService)
                ChatStorage.markDelivered(this@MessengerService, myId, from, messageId)
                ContactHealthManager.recordDelivered(this@MessengerService, from)
                withContext(Dispatchers.Main) {
                    onDeliveredReceived?.invoke(messageId)
                    onContactSendUnblocked?.invoke(from)
                }
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
                    // Rethrown on decrypt failure (external review 2026-08-23) --
                    // was catch-and-log-only, so anon_delivery_ack would confirm
                    // an edit that was never actually applied. Matches the
                    // "message"/session_init/voice pattern in this same file.
                    try {
                        val decryptedText = CryptoManager.decrypt(encryptedText)
                        withContext(Dispatchers.Main) { onEditReceived?.invoke(messageId, decryptedText) }
                    } catch (e: Exception) {
                        Log.e(TAG, "Ошибка расшифровки edit: ${e.message}")
                        throw e
                    }
                }
            }

            "reaction" -> {
                // Rethrown, and the bad-signature check throws instead of a plain
                // return (external review 2026-08-23) -- both used to let
                // anon_delivery_ack fire for a reaction that was rejected or
                // never actually decrypted/applied. Matches the "message"/
                // session_init/voice/edit pattern in this same file.
                try {
                    val from = json.getString("from")
                    val messageId = json.getString("message_id")
                    val encryptedEmoji = json.getString("emoji")
                    val signature = json.optString("signature", null)
                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                    // Transcript must match sendReaction() byte for byte.
                    if (signature == null || senderKey == null ||
                        !CryptoManager.verify(
                            "SUBROSA_REACTION_V1:$messageId:$encryptedEmoji",
                            signature,
                            senderKey
                        )) {
                        Log.e(TAG, "reaction: неверная или отсутствующая подпись от $from")
                        throw SecurityException("reaction: неверная или отсутствующая подпись от $from")
                    }
                    val emoji = CryptoManager.decrypt(encryptedEmoji)
                    withContext(Dispatchers.Main) { onReactionReceived?.invoke(from, messageId, emoji) }
                } catch (e: Exception) {
                    Log.e(TAG, "reaction error: ${e.message}")
                    throw e
                }
            }

            "message_delete" -> {
                // throw instead of a plain return on bad signature (external
                // review 2026-08-27, OPEN-2/AA-7 pattern) -- a plain return
                // let anon_delivery_ack fire for a delete request that was
                // actually rejected, same class of bug already fixed in
                // edit/reaction/session_init.
                val from = json.getString("from")
                val messageId = json.getString("message_id")
                // Defense-in-depth (S6-53, STEP 10): a compromised server
                // could hand this device an arbitrary frame directly, and a
                // valid signature only proves the authenticated `from`
                // signed exactly this content -- not that the content is
                // protocol-sane. Bounded BEFORE the crypto-adjacent
                // publicKeys/verify() work below, same as the server's own
                // CHAT_CONTROL_ID_MAX_LEN.
                if (messageId.length > CHAT_CONTROL_ID_MAX_LEN) {
                    Log.e(TAG, "message_delete: message_id превышает допустимую длину от $from")
                    throw SecurityException("message_delete: message_id too long from $from")
                }
                val signature = json.optString("signature", null)
                val senderKey = publicKeys[from]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                // Transcript versioned (S6-54, external review 2026-09-06):
                // previously verified the bare messageId with no domain
                // separator -- see sendDeleteMessage()'s own comment for why
                // that risks cross-operation signature reuse.
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify(ChatControlTranscripts.messageDelete(messageId), signature, senderKey)) {
                    Log.e(TAG, "message_delete: неверная или отсутствующая подпись от $from")
                    throw SecurityException("message_delete: неверная или отсутствующая подпись от $from")
                }
                val myId = UserStorage.getUserId(this@MessengerService)
                // Authorization (S6-54, external review 2026-09-06): a valid
                // signature only proves `from` requested this deletion, not
                // that `from` is entitled to delete the referenced message.
                // A direct 1:1 conversation has exactly two possible
                // authors -- the local user and `from` themselves -- so the
                // locally stored copy's own `isOwn` flag tells us which: if
                // it's ours (isOwn=true), `from` (the contact) must never be
                // able to delete it merely by knowing its id. Unknown ids
                // (existing == null) remain a safe no-op, same as before.
                val existing = ChatStorage.loadMessages(this@MessengerService, myId, from)
                    .find { it.id == messageId }
                if (existing != null && existing.isOwn) {
                    Log.e(TAG, "message_delete: $from пытается удалить чужое (наше) сообщение $messageId — отклонено")
                    throw SecurityException("message_delete: $from is not authorized to delete $messageId")
                }
                ChatStorage.deleteMessage(this@MessengerService, myId, from, messageId)
                withContext(Dispatchers.Main) { onMessageDeleted?.invoke(from, messageId) }
            }

            "disappear_timer" -> {
                // Same throw-not-return fix as message_delete above.
                val from = json.getString("from")
                val seconds = json.getLong("seconds")
                // Defense-in-depth (S6-53, STEP 10): ChatScreen's disappear
                // dialog only ever offers off/1h/24h/7d -- a genuinely-
                // authenticated malicious contact can still produce a
                // validly-signed message over any `seconds` value they
                // choose (signature proves origin, not protocol sanity), so
                // this is checked against the exact set the UI offers,
                // before it ever reaches ChatStorage.setDisappearTimer()'s
                // downstream expiry-timestamp math.
                if (seconds !in CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED) {
                    Log.e(TAG, "disappear_timer: недопустимое значение seconds=$seconds от $from")
                    throw SecurityException("disappear_timer: invalid seconds=$seconds from $from")
                }
                val signature = json.optString("signature", null)
                val senderKey = publicKeys[from]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify(ChatControlTranscripts.disappearTimer(seconds), signature, senderKey)) {
                    Log.e(TAG, "disappear_timer: неверная или отсутствующая подпись от $from")
                    throw SecurityException("disappear_timer: неверная или отсутствующая подпись от $from")
                }
                val myId = UserStorage.getUserId(this@MessengerService)
                ChatStorage.setDisappearTimer(this@MessengerService, myId, from, seconds)
                withContext(Dispatchers.Main) { onDisappearTimerChanged?.invoke(from, seconds) }
            }

            "group_message_delete" -> {
                // Was entirely unauthenticated and unauthorized (external
                // review 2026-08-27, OPEN-2) -- no signature was ever sent
                // (sendGroupDeleteMessage() didn't produce one) and this
                // handler didn't check `from` at all, let alone that `from`
                // was the original author of the message being deleted. The
                // server does stamp `from` to the real authenticated sender
                // (server.py's group_message_delete relay), so `from` itself
                // can be trusted -- but a malicious/modified client in the
                // group could still ask to delete ANY other member's message,
                // not just their own, and every recipient applied it blindly.
                // Now requires a signature over a versioned transcript AND
                // that `from` matches the stored message's own senderId --
                // i.e. only the original author (proven by signature) can
                // delete-for-everyone their own group message, matching what
                // the UI already only lets the real client request
                // (GroupChatScreen.kt gates the "delete for everyone" button
                // on ctxMsg.isOwn). Transcript versioned (S6-54, external
                // review 2026-09-06) with its OWN domain separator, distinct
                // from direct message_delete's own -- see
                // sendGroupDeleteMessage()'s own comment.
                val groupId = json.getString("group_id")
                val messageId = json.getString("message_id")
                val from = json.getString("from")
                // Defense-in-depth (S6-53, STEP 10) -- same reasoning as
                // message_delete above, applied to both ids this signature
                // covers.
                if (groupId.length > CHAT_CONTROL_ID_MAX_LEN || messageId.length > CHAT_CONTROL_ID_MAX_LEN) {
                    Log.e(TAG, "group_message_delete: group_id/message_id превышает допустимую длину от $from")
                    throw SecurityException("group_message_delete: id too long from $from")
                }
                val signature = json.optString("signature", null)
                val senderKey = publicKeys[from]
                    ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify(ChatControlTranscripts.groupMessageDelete(groupId, messageId), signature, senderKey)) {
                    Log.e(TAG, "group_message_delete: неверная или отсутствующая подпись от $from")
                    throw SecurityException("group_message_delete: неверная или отсутствующая подпись от $from")
                }
                val myId = UserStorage.getUserId(this@MessengerService)
                val existing = GroupManager.loadGroupMessages(this@MessengerService, myId, groupId)
                    .find { it.id == messageId }
                if (existing != null && existing.senderId != from) {
                    Log.e(TAG, "group_message_delete: $from пытается удалить чужое сообщение $messageId — отклонено")
                    throw SecurityException("group_message_delete: $from is not the author of $messageId")
                }
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

                    // S6-49: bound total_chunks/chunk_index and enforce the
                    // simultaneous-transfer cap BEFORE ever touching
                    // imageChunks/imageTotals or acking -- a rejected chunk
                    // must not look delivered to the sender.
                    if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS || chunkIndex !in 0 until totalChunks) {
                        Log.e(TAG, "image_chunk: недопустимый chunk_index/total_chunks от $from ($chunkIndex/$totalChunks)")
                        return
                    }
                    val transferKey = "$from:$imageId"
                    if (!pruneAndAdmitTransfer(imageChunks, imageVideoTouchedAt, transferKey, imageVideoReceivedBytes, imageVideoChunkWireLens)) {
                        Log.w(TAG, "image_chunk: слишком много одновременных передач — $transferKey отклонён")
                        return
                    }
                    if (chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
                        Log.e(TAG, "image_chunk: слишком большой chunk data от $from — отменяем $transferKey")
                        imageChunks.remove(transferKey); imageTotals.remove(transferKey)
                        imageVideoTouchedAt.remove(transferKey); imageVideoReceivedBytes.remove(transferKey)
                        imageVideoChunkWireLens.remove(transferKey)
                        return
                    }
                    val imageWireLens = imageVideoChunkWireLens.getOrPut(transferKey) { mutableMapOf() }
                    if (!accountChunkBytes(imageWireLens, imageVideoReceivedBytes, transferKey, chunkIndex, chunkData.length)) {
                        Log.e(TAG, "image_chunk: передача $transferKey превысила лимит байт — отменяем")
                        imageChunks.remove(transferKey); imageTotals.remove(transferKey)
                        imageVideoTouchedAt.remove(transferKey); imageVideoReceivedBytes.remove(transferKey)
                        imageVideoChunkWireLens.remove(transferKey)
                        return
                    }

                    sendWs(JSONObject().apply {
                        put("type", "chunk_ack")
                        put("image_id", imageId)
                        put("chunk_index", chunkIndex)
                    }.toString())

                    try {

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
                                    imageVideoTouchedAt.remove(transferKey)
                                    imageVideoReceivedBytes.remove(transferKey)
                                    imageVideoChunkWireLens.remove(transferKey)
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
                                    imageVideoTouchedAt.remove(transferKey)
                                    imageVideoReceivedBytes.remove(transferKey)
                                    imageVideoChunkWireLens.remove(transferKey)
                                    withContext(Dispatchers.Main) {
                                        onImageReceived?.invoke(imageId, bitmap)
                                    }
                                }
                            }
                        }
                    } catch (e: Exception) {
                        // Rethrown (external review 2026-08-23) -- see
                        // video_chunk_batch above for the same reasoning.
                        Log.e(TAG, "image chunk error: ${e.message}", e)
                        throw e
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

                    // All three early-exit points below now throw instead of a
                    // plain return (external review 2026-08-23): a silent return
                    // still let anon_delivery_ack fire even though this chunk was
                    // never stored -- the transfer would then hang forever
                    // waiting on a chunk_index that will never arrive again, with
                    // no error surfaced and no server-side retry (the server
                    // believes delivery succeeded).
                    if (senderKey == null) {
                        Log.e(TAG, "File chunk без ключа от $from — запрашиваем")
                        requestPrekeyBundle(from)
                        throw SecurityException("File chunk без ключа от $from")
                    }

                    if (signature == null || !CryptoManager.verifyChunk(chunkData, signature, senderKey, fileId, chunkIndex)) {
                        Log.e(TAG, "Неверная подпись file chunk от $from")
                        throw SecurityException("Неверная подпись file chunk от $from")
                    }

                    // S6-49: bound total_chunks/chunk_index and enforce the
                    // simultaneous-transfer cap BEFORE ever touching
                    // fileChunks or acking -- same guards as image_chunk/
                    // video_chunk above.
                    if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS || chunkIndex !in 0 until totalChunks) {
                        Log.e(TAG, "file_chunk: недопустимый chunk_index/total_chunks от $from ($chunkIndex/$totalChunks)")
                        throw SecurityException("file_chunk: недопустимый chunk_index/total_chunks от $from")
                    }
                    val fileTransferKey = "$from:$fileId"
                    if (!pruneAndAdmitTransfer(fileChunks, fileTouchedAt, fileTransferKey, fileReceivedBytes, fileChunkWireLens)) {
                        Log.w(TAG, "file_chunk: слишком много одновременных передач — $fileTransferKey отклонён")
                        throw SecurityException("file_chunk: слишком много одновременных передач для $from")
                    }
                    if (chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
                        Log.e(TAG, "file_chunk: слишком большой chunk data от $from — отменяем $fileTransferKey")
                        fileChunks.remove(fileTransferKey); fileTouchedAt.remove(fileTransferKey)
                        fileReceivedBytes.remove(fileTransferKey); fileChunkWireLens.remove(fileTransferKey)
                        throw SecurityException("file_chunk: слишком большой chunk data от $from")
                    }
                    val fileWireLens = fileChunkWireLens.getOrPut(fileTransferKey) { mutableMapOf() }
                    if (!accountChunkBytes(fileWireLens, fileReceivedBytes, fileTransferKey, chunkIndex, chunkData.length)) {
                        Log.e(TAG, "file_chunk: передача $fileTransferKey превысила лимит байт — отменяем")
                        fileChunks.remove(fileTransferKey); fileTouchedAt.remove(fileTransferKey)
                        fileReceivedBytes.remove(fileTransferKey); fileChunkWireLens.remove(fileTransferKey)
                        throw SecurityException("file_chunk: передача $fileTransferKey превысила лимит байт")
                    }

                    sendWs(JSONObject().apply {
                        put("type", "chunk_ack")
                        put("file_id", fileId)
                        put("chunk_index", chunkIndex)
                    }.toString())

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
                        fileChunks[fileTransferKey] = FileMeta(fileName, totalChunks, mutableMapOf())
                    }
                    // Keyed by index (S6-49) -- a repeated chunk_index simply
                    // overwrites its own slot instead of appending a
                    // duplicate, matching imageChunks'/videoChunk's own
                    // accumulator shape.
                    fileChunks[fileTransferKey]?.chunks?.set(chunkIndex, chunkData)

                    val receivedChunks = fileChunks[fileTransferKey]?.chunks?.size ?: 0
                    Log.d(TAG, "Собрано чанков: $receivedChunks/$totalChunks для файла ${fileChunks[fileTransferKey]?.name}")

                    if (receivedChunks == totalChunks) {
                        Log.d(TAG, "Все чанки получены для $fileId, начинаем сборку")

                        val fileName = fileChunks[fileTransferKey]?.name ?: "file"
                        val chunkMap = fileChunks[fileTransferKey]?.chunks
                        if (chunkMap == null) {
                            Log.e(TAG, "fileChunks[$fileTransferKey] исчез до сборки — пропускаем")
                            throw IllegalStateException("fileChunks[$fileTransferKey] исчез до сборки")
                        }
                        val fullPackedData = (0 until totalChunks).joinToString("") { chunkMap[it]!! }

                        if (isEncrypted) {
                            Log.d(TAG, "Расшифровываем файл $fileName...")

                            try {
                                val encryptedFileData = CryptoManager.unpackEncryptedFile(fullPackedData)
                                val decryptedBytes = CryptoManager.decryptFile(encryptedFileData)

                                Log.d(TAG, "Файл расшифрован: ${decryptedBytes.size} байт")

                                val file = SecureFileStorage.blobFile(filesDir, fileId)
                                SecureFileStorage.write(this@MessengerService, file, decryptedBytes)

                                Log.d(TAG, "Файл $fileName расшифрован и сохранен зашифрованным: ${file.absolutePath}")

                                withContext(Dispatchers.Main) {
                                    onFileReceived?.invoke(fileId, file, fileName)
                                }

                            } catch (e: Exception) {
                                Log.e(TAG, "Ошибка расшифровки файла: ${e.message}", e)
                                throw e
                            }

                        } else {
                            Log.d(TAG, "Файл в legacy формате (без шифрования)")

                            val fileBytes = android.util.Base64.decode(fullPackedData, android.util.Base64.DEFAULT)
                            val file = SecureFileStorage.blobFile(filesDir, fileId)
                            SecureFileStorage.write(this@MessengerService, file, fileBytes)

                            Log.d(TAG, "Legacy файл сохранен зашифрованным: ${file.absolutePath}")

                            withContext(Dispatchers.Main) {
                                onFileReceived?.invoke(fileId, file, fileName)
                            }
                        }

                        fileChunks.remove(fileTransferKey)
                        fileTouchedAt.remove(fileTransferKey)
                        fileReceivedBytes.remove(fileTransferKey)
                        fileChunkWireLens.remove(fileTransferKey)
                    }

                } catch (e: Exception) {
                    // Rethrown (external review 2026-08-23) -- see
                    // video_chunk_batch above for the same reasoning.
                    Log.e(TAG, "file_chunk error: ${e.message}", e)
                    throw e
                }
            }

            // Reassembly for sendGroupImage()/sendGroupFile() — same batched-
            // chunk-per-member-fanout shape as video_chunk_batch, decrypted
            // with the group's shared AES key (looked up via GroupManager)
            // instead of the sender's per-contact key. transferKey includes
            // groupId so a stalled/duplicate transfer from one group can't
            // collide with another group's transfer using the same imageId.
            "group_image_batch" -> {
                try {
                    val from = json.getString("from")
                    val groupId = json.getString("group_id")
                    val imageId = json.getString("image_id")
                    val totalChunks = json.getInt("total_chunks")
                    val chunksArr = json.getJSONArray("chunks")

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }
                    val groupKey = GroupManager.getGroup(this@MessengerService, groupId)?.groupKey

                    if (senderKey == null || groupKey == null) {
                        Log.w(TAG, "group_image_batch: нет ключа отправителя или группы $groupId")
                        return
                    }

                    // S6-49 follow-up: bound total_chunks/chunk_index/data length
                    // and the per-transfer byte budget the same as image_chunk/
                    // video_chunk -- this handler shares imageChunks/imageTotals
                    // with them and had none of these guards.
                    if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS) {
                        Log.e(TAG, "group_image_batch: недопустимый total_chunks от $from ($totalChunks)")
                        return
                    }
                    val transferKey = "$groupId:$from:$imageId"
                    val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
                    val groupImageWireLens = imageVideoChunkWireLens.getOrPut(transferKey) { mutableMapOf() }
                    var cancelled = false
                    for (i in 0 until chunksArr.length()) {
                        val c = chunksArr.getJSONObject(i)
                        val chunkIndex = c.getInt("chunk_index")
                        val chunkData = c.getString("data")
                        val signature = c.optString("signature", null)
                        if (signature == null || !CryptoManager.verifyChunk(chunkData, signature, senderKey, imageId, chunkIndex)) {
                            Log.e(TAG, "Неверная подпись group_image chunk от $from")
                            continue
                        }
                        if (chunkIndex !in 0 until totalChunks || chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
                            Log.e(TAG, "group_image_batch: недопустимый chunk_index/data от $from — отменяем $transferKey")
                            cancelled = true
                            break
                        }
                        if (!accountChunkBytes(groupImageWireLens, imageVideoReceivedBytes, transferKey, chunkIndex, chunkData.length)) {
                            Log.e(TAG, "group_image_batch: передача $transferKey превысила лимит байт — отменяем")
                            cancelled = true
                            break
                        }
                        chunks[chunkIndex] = chunkData
                    }
                    if (cancelled) {
                        imageChunks.remove(transferKey); imageTotals.remove(transferKey)
                        imageVideoReceivedBytes.remove(transferKey); imageVideoChunkWireLens.remove(transferKey)
                        return
                    }
                    imageTotals[transferKey] = totalChunks

                    if (chunks.size == totalChunks) {
                        val ordered = (0 until totalChunks).map { chunks[it]!! }
                        val packedData = ordered.joinToString("")
                        imageChunks.remove(transferKey)
                        imageTotals.remove(transferKey)
                        imageVideoReceivedBytes.remove(transferKey)
                        imageVideoChunkWireLens.remove(transferKey)

                        val decryptedBase64 = GroupManager.decryptGroupMessage(packedData, groupKey)
                        val imageBytes = android.util.Base64.decode(decryptedBase64, android.util.Base64.NO_WRAP)
                        val file = SecureFileStorage.blobFile(filesDir, imageId)
                        SecureFileStorage.write(this@MessengerService, file, imageBytes)

                        withContext(Dispatchers.Main) {
                            onGroupImageReceived?.invoke(groupId, from, imageId, file)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_image_batch error: ${e.message}", e)
                }
            }

            // Mirrors group_image_batch exactly (same shared imageChunks/
            // imageTotals/imageVideoReceivedBytes/imageVideoChunkWireLens
            // reassembly maps, same signature/bounds/byte-budget guards) —
            // the only difference is video_id instead of image_id and a
            // plaintext duration field. New 2026-09-21, group chat
            // previously had no video-circle receive path at all.
            "group_video_batch" -> {
                try {
                    val from = json.getString("from")
                    val groupId = json.getString("group_id")
                    val videoId = json.getString("video_id")
                    val duration = json.optInt("duration", 0)
                    val totalChunks = json.getInt("total_chunks")
                    val chunksArr = json.getJSONArray("chunks")

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }
                    val groupKey = GroupManager.getGroup(this@MessengerService, groupId)?.groupKey

                    if (senderKey == null || groupKey == null) {
                        Log.w(TAG, "group_video_batch: нет ключа отправителя или группы $groupId")
                        return
                    }

                    if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS) {
                        Log.e(TAG, "group_video_batch: недопустимый total_chunks от $from ($totalChunks)")
                        return
                    }
                    val transferKey = "$groupId:$from:$videoId"
                    val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
                    val groupVideoWireLens = imageVideoChunkWireLens.getOrPut(transferKey) { mutableMapOf() }
                    var cancelled = false
                    for (i in 0 until chunksArr.length()) {
                        val c = chunksArr.getJSONObject(i)
                        val chunkIndex = c.getInt("chunk_index")
                        val chunkData = c.getString("data")
                        val signature = c.optString("signature", null)
                        if (signature == null || !CryptoManager.verifyChunk(chunkData, signature, senderKey, videoId, chunkIndex)) {
                            Log.e(TAG, "Неверная подпись group_video chunk от $from")
                            continue
                        }
                        if (chunkIndex !in 0 until totalChunks || chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
                            Log.e(TAG, "group_video_batch: недопустимый chunk_index/data от $from — отменяем $transferKey")
                            cancelled = true
                            break
                        }
                        if (!accountChunkBytes(groupVideoWireLens, imageVideoReceivedBytes, transferKey, chunkIndex, chunkData.length)) {
                            Log.e(TAG, "group_video_batch: передача $transferKey превысила лимит байт — отменяем")
                            cancelled = true
                            break
                        }
                        chunks[chunkIndex] = chunkData
                    }
                    if (cancelled) {
                        imageChunks.remove(transferKey); imageTotals.remove(transferKey)
                        imageVideoReceivedBytes.remove(transferKey); imageVideoChunkWireLens.remove(transferKey)
                        return
                    }
                    imageTotals[transferKey] = totalChunks

                    if (chunks.size == totalChunks) {
                        val ordered = (0 until totalChunks).map { chunks[it]!! }
                        val packedData = ordered.joinToString("")
                        imageChunks.remove(transferKey)
                        imageTotals.remove(transferKey)
                        imageVideoReceivedBytes.remove(transferKey)
                        imageVideoChunkWireLens.remove(transferKey)

                        val decryptedBase64 = GroupManager.decryptGroupMessage(packedData, groupKey)
                        val videoBytes = android.util.Base64.decode(decryptedBase64, android.util.Base64.NO_WRAP)
                        val file = SecureFileStorage.blobFile(filesDir, videoId)
                        SecureFileStorage.write(this@MessengerService, file, videoBytes)

                        withContext(Dispatchers.Main) {
                            onGroupVideoReceived?.invoke(groupId, from, videoId, file, duration)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_video_batch error: ${e.message}", e)
                }
            }

            // Admin-only, enforced here (not just left to the sender's own
            // UI gating) — a compromised or modified non-admin client could
            // otherwise push an arbitrary avatar to every member. New
            // 2026-09-21, group chat previously had no photo-avatar update
            // path at all.
            "group_avatar_update" -> {
                try {
                    val from = json.getString("from")
                    val groupId = json.getString("group_id")
                    val encryptedAvatar = json.getString("avatar")
                    val signature = json.optString("signature", null)

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }
                    val group = GroupManager.getGroup(this@MessengerService, groupId)
                    val groupKey = group?.groupKey

                    if (senderKey == null || groupKey == null) {
                        Log.w(TAG, "group_avatar_update: нет ключа отправителя или группы $groupId")
                        return
                    }
                    if (!GroupManager.isAdmin(this@MessengerService, groupId, from)) {
                        Log.w(TAG, "group_avatar_update: $from не админ группы $groupId — отклонено")
                        return
                    }
                    if (signature == null || !CryptoManager.verify(encryptedAvatar, signature, senderKey)) {
                        Log.e(TAG, "group_avatar_update: неверная подпись от $from")
                        return
                    }

                    val decrypted = GroupManager.decryptGroupMessage(encryptedAvatar, groupKey)
                    // "EMOJI:" prefix mirrors the existing "VOICE:"-prefix
                    // convention this codebase already uses for group voice
                    // messages riding inside an otherwise-photo/text field —
                    // the emoji picker (GroupInfoScreen.kt) used to only
                    // update local storage, never notifying other members
                    // at all. Now both avatar kinds go through the same
                    // wire message. New 2026-09-21.
                    val updated = if (decrypted.startsWith("EMOJI:")) {
                        group.copy(avatar = decrypted.removePrefix("EMOJI:"))
                    } else {
                        val avatarBytes = android.util.Base64.decode(decrypted, android.util.Base64.NO_WRAP)
                        val avatarFile = SecureFileStorage.blobFile(filesDir, "group_avatar_$groupId")
                        SecureFileStorage.write(this@MessengerService, avatarFile, avatarBytes)
                        group.copy(avatarPath = avatarFile.absolutePath)
                    }
                    GroupManager.saveGroup(this@MessengerService, updated)

                    withContext(Dispatchers.Main) {
                        onGroupAvatarUpdated?.invoke(groupId)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_avatar_update error: ${e.message}", e)
                }
            }

            "group_file_batch" -> {
                try {
                    val from = json.getString("from")
                    val groupId = json.getString("group_id")
                    val fileId = sanitizePathComponent(json.getString("file_id"))
                    val encryptedFileName = json.optString("encrypted_file_name", null)
                    val totalChunks = json.getInt("total_chunks")
                    val chunksArr = json.getJSONArray("chunks")

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }
                    val groupKey = GroupManager.getGroup(this@MessengerService, groupId)?.groupKey

                    if (senderKey == null || groupKey == null) {
                        Log.w(TAG, "group_file_batch: нет ключа отправителя или группы $groupId")
                        return
                    }

                    // S6-49 follow-up: same guards as group_image_batch above.
                    if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS) {
                        Log.e(TAG, "group_file_batch: недопустимый total_chunks от $from ($totalChunks)")
                        return
                    }
                    val transferKey = "$groupId:$from:$fileId"
                    if (!fileChunks.containsKey(transferKey)) {
                        val decryptedName = try {
                            if (encryptedFileName != null) GroupManager.decryptGroupMessage(encryptedFileName, groupKey) else "file"
                        } catch (e: Exception) {
                            Log.e(TAG, "Не удалось расшифровать имя группового файла: ${e.message}")
                            "file"
                        }
                        fileChunks[transferKey] = FileMeta(sanitizePathComponent(decryptedName), totalChunks, mutableMapOf())
                    }

                    val groupFileWireLens = fileChunkWireLens.getOrPut(transferKey) { mutableMapOf() }
                    var cancelled = false
                    for (i in 0 until chunksArr.length()) {
                        val c = chunksArr.getJSONObject(i)
                        val chunkIndex = c.getInt("chunk_index")
                        val chunkData = c.getString("data")
                        val signature = c.optString("signature", null)
                        if (signature == null || !CryptoManager.verifyChunk(chunkData, signature, senderKey, fileId, chunkIndex)) {
                            Log.e(TAG, "Неверная подпись group_file chunk от $from")
                            continue
                        }
                        if (chunkIndex !in 0 until totalChunks || chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
                            Log.e(TAG, "group_file_batch: недопустимый chunk_index/data от $from — отменяем $transferKey")
                            cancelled = true
                            break
                        }
                        if (!accountChunkBytes(groupFileWireLens, fileReceivedBytes, transferKey, chunkIndex, chunkData.length)) {
                            Log.e(TAG, "group_file_batch: передача $transferKey превысила лимит байт — отменяем")
                            cancelled = true
                            break
                        }
                        // Keyed by index (S6-49) -- see file_chunk's own comment.
                        fileChunks[transferKey]?.chunks?.set(chunkIndex, chunkData)
                    }
                    if (cancelled) {
                        fileChunks.remove(transferKey)
                        fileReceivedBytes.remove(transferKey); fileChunkWireLens.remove(transferKey)
                        return
                    }

                    val receivedChunks = fileChunks[transferKey]?.chunks?.size ?: 0
                    if (receivedChunks == totalChunks) {
                        val fileName = fileChunks[transferKey]?.name ?: "file"
                        val chunkMap = fileChunks[transferKey]?.chunks
                        if (chunkMap == null) {
                            Log.e(TAG, "fileChunks[$transferKey] исчез до сборки — пропускаем")
                            return
                        }
                        val fullPackedData = (0 until totalChunks).joinToString("") { chunkMap[it]!! }
                        fileChunks.remove(transferKey)
                        fileReceivedBytes.remove(transferKey)
                        fileChunkWireLens.remove(transferKey)

                        val decryptedBase64 = GroupManager.decryptGroupMessage(fullPackedData, groupKey)
                        val fileBytes = android.util.Base64.decode(decryptedBase64, android.util.Base64.NO_WRAP)
                        val file = SecureFileStorage.blobFile(filesDir, fileId)
                        SecureFileStorage.write(this@MessengerService, file, fileBytes)

                        withContext(Dispatchers.Main) {
                            onGroupFileReceived?.invoke(groupId, from, fileId, file, fileName)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_file_batch error: ${e.message}", e)
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
                    throw e
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
                    // Rethrown (external review 2026-08-23) -- was catch-and-log
                    // only, so anon_delivery_ack could confirm a batch that
                    // processVideoChunk() actually failed partway through.
                    Log.e(TAG, "video_chunk_batch error: ${e.message}", e)
                    throw e
                }
            }

            "voice" -> {
                try {
                    val from = json.getString("from")
                    val voiceId = json.getString("voice_id")
                    val encryptedData = json.getString("voice_data")
                    val signature = json.optString("signature", null)
                    val duration = json.getInt("duration")

                    // Defense-in-depth (S6-57, STEP 7) -- bounded BEFORE any
                    // of the crypto/decode work below, same posture as
                    // CHAT_CONTROL_ID_MAX_LEN above. A compromised/malicious
                    // server could otherwise hand this device an oversized
                    // frame directly and force expensive signature-verify/
                    // decrypt/base64-decode work regardless of what the real
                    // server-side bounds enforce.
                    if (voiceId.length > VOICE_ID_MAX_LEN || voiceId.isEmpty()) {
                        Log.e(TAG, "voice: voiceId вне допустимой длины от $from")
                        throw SecurityException("voice: voiceId out of bounds from $from")
                    }
                    if (encryptedData.isEmpty() || encryptedData.length > VOICE_WIRE_MAX_LEN) {
                        Log.e(TAG, "voice: voice_data вне допустимой длины от $from")
                        throw SecurityException("voice: voice_data out of bounds from $from")
                    }
                    if (signature != null && signature.length > VOICE_SIGNATURE_MAX_LEN) {
                        Log.e(TAG, "voice: signature вне допустимой длины от $from")
                        throw SecurityException("voice: signature out of bounds from $from")
                    }
                    if (duration < 0 || duration > MAX_VOICE_DURATION_SECONDS) {
                        Log.e(TAG, "voice: duration вне допустимого диапазона от $from")
                        throw SecurityException("voice: duration out of range from $from")
                    }

                    val senderKey = publicKeys[from] ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also { publicKeys[from] = it }

                    if (signature == null || senderKey == null) {
                        Log.e(TAG, "Voice без ключа от $from — запрашиваем")
                        requestPrekeyBundle(from)
                        throw SecurityException("voice: нет ключа от $from")
                    }

                    val fixedKey = senderKey.replace('-', '+').replace('_', '/')

                    // Verifies the V1 transcript (S6-58), not bare
                    // `encryptedData` -- binds voiceId/duration into the
                    // signature, closing the metadata-relabeling gap
                    // voiceSignatureTranscript()'s own comment describes.
                    // Hard cutover, no legacy bare-ciphertext fallback: a
                    // fallback would preserve exactly the vulnerability this
                    // fixes (a malicious relay simply presents a legacy-
                    // shaped frame). Any pre-S6-58 voice message still
                    // offline-queued server-side at upgrade time will fail
                    // this verification and be dropped, same as any other
                    // signature failure -- an accepted, explicit tradeoff.
                    if (!CryptoManager.verify(voiceSignatureTranscript(voiceId, duration, encryptedData), signature, fixedKey)) {
                        Log.e(TAG, "Неверная подпись голосового от $from")
                        throw SecurityException("voice: неверная подпись от $from")
                    }

                    // Replay dedup (S6-58, STEP 9) -- voiceId is now
                    // cryptographically bound to the signature, so dedup by
                    // voiceId alone is meaningful (pre-S6-58 an attacker could
                    // trivially defeat any such dedup by relabeling voiceId on
                    // every replay). Mirrors "message"'s own receivedMessageIds
                    // pattern exactly; checked only AFTER verification
                    // succeeds, so this cache can never be poisoned with an
                    // unauthenticated id.
                    if (receivedMessageIds.size > 200) {
                        receivedMessageIds.entries.removeIf { System.currentTimeMillis() - it.value > REPLAY_WINDOW_MS }
                    }
                    if (receivedMessageIds.containsKey(voiceId)) {
                        Log.d(TAG, "Дубликат/повтор voice $voiceId от $from проигнорирован")
                        return
                    }

                    val voiceData = CryptoManager.decrypt(encryptedData)
                    // Post-decrypt bound (S6-57, STEP 8) -- wire-size bounds
                    // above aren't sufficient on their own if decrypt/decode
                    // ever expanded the payload; checked BEFORE
                    // AudioHelper.decodeAndSave() ever base64-decodes or
                    // writes a file. See VOICE_MAX_DECRYPTED_B64_LEN's own
                    // comment for the derivation.
                    if (voiceData.length > VOICE_MAX_DECRYPTED_B64_LEN) {
                        Log.e(TAG, "voice: расшифрованные данные превышают допустимый размер от $from")
                        throw SecurityException("voice: decrypted payload too large from $from")
                    }
                    val voiceFile = AudioHelper.decodeAndSave(this@MessengerService, voiceData, voiceId)
                    if (voiceFile == null) {
                        Log.e(TAG, "voice: аудио превышает допустимый размер после декодирования от $from")
                        throw SecurityException("voice: decoded audio too large from $from")
                    }
                    receivedMessageIds[voiceId] = System.currentTimeMillis()
                    Log.i(TAG, "ПОЛУЧЕНО voice $voiceId ← $from @ ${System.currentTimeMillis()}")
                    withContext(Dispatchers.Main) { onVoiceReceived?.invoke(voiceId, voiceFile, duration) }
                } catch (e: Exception) {
                    Log.e(TAG, "voice error: ${e.message}")
                    // Re-thrown — same class of fix as "message"/session_init
                    // above (docs/ISSUE_backup_identity_hijack.md): a decrypt
                    // failure here shouldn't let anon_delivery_ack fire as if
                    // this voice message had actually been received.
                    throw e
                }
            }

            "prekey_bundle" -> {
                val fromUser = json.getString("from")
                if (json.has("identity_key") && !json.isNull("identity_key")) {
                    val identityKey = json.getString("identity_key")

                    val fixedIdentityKey = identityKey.replace('-', '+').replace('_', '/')

                    // checkKeyChange() BEFORE the trust-assignment below —
                    // was reversed (found in the 2026-09-13 KeyHistoryManager
                    // audit): a changed key must be detected/flagged before
                    // this device starts treating it as the contact's active
                    // identity, not after. checkKeyChange() itself doesn't
                    // depend on publicKeys/ChatStorage having been updated
                    // yet, so this reorder changes nothing else.
                    if (KeyHistoryManager.checkKeyChange(this@MessengerService, fromUser, fixedIdentityKey)) {
                        withContext(Dispatchers.Main) { onKeyChanged?.invoke(fromUser) }
                    }

                    publicKeys[fromUser] = fixedIdentityKey
                    ChatStorage.saveContactPublicKey(this@MessengerService, fromUser, fixedIdentityKey)

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

            // ── Decoy candidates for the anonymous batched bundle fetch ────────
            // See requestPrekeyBundle()/pendingDecoyCandidateRequests' own
            // comments — resolved FIFO against whichever bootstrap is
            // currently waiting, since the candidates aren't tied to any
            // specific contact.
            "decoy_candidates_result" -> {
                val candidates = json.optJSONArray("candidates")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }
                } ?: emptyList()
                pendingDecoyCandidateRequests.poll()?.complete(candidates)
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
                    throw SecurityException("message: нет ключа от $from")
                }
                if (!CryptoManager.verify(encryptedText, signature, senderPublicKey)) {
                    Log.e(TAG, "Неверная подпись от $from")
                    throw SecurityException("message: неверная подпись от $from")
                }
                try {
                    val decryptedText = if (protocolVersion >= 2 && json.has("session_header")) {
                        val sessionHeader = json.getJSONObject("session_header")
                        if (!SessionKeyManager.hasSession(from)) {
                            // Root-caused live 2026-08-31: this used to try
                            // CryptoManager.decrypt(encryptedText) as a
                            // "legacy fallback" — but "text" alongside a
                            // present session_header is ALWAYS the output of
                            // encryptWithForwardSecrecy() (see
                            // sendWithForwardSecrecy(), the only sender that
                            // ever sets both together); nothing in this
                            // codebase ever pairs session_header with
                            // legacy-hybrid ciphertext. That fallback was
                            // therefore guaranteed to fail on a format
                            // mismatch, not a wrong key — every single time
                            // our side had no session but the sender still
                            // did (exactly the common post-reset transition,
                            // where only one side has processed session_reset
                            // so far), this genuinely undecryptable-by-us
                            // message got a doomed decrypt attempt, a
                            // redundant session_reset, and a rethrow that
                            // told the server to keep redelivering a message
                            // we could never decrypt anyway. Recognize this
                            // case directly instead: we have no session, they
                            // do — tell them to reset (so they send a fresh
                            // session_init next) and drop this one message,
                            // acking it so the server stops retrying
                            // something no retry will ever fix.
                            Log.w(TAG, "message с session_header от $from, но сессии нет — просим их session_init, сообщение не восстановить")
                            sendSessionResetDebounced(from)
                            return
                        }
                        CryptoManager.decryptWithForwardSecrecy(from, encryptedText, sessionHeader)
                    } else {
                        CryptoManager.decrypt(encryptedText)
                    }
                    handleIncomingDecryptedMessage(from, decryptedText, messageId, json)

                    // shouldResupplyTokens() gate added (external review 2026-08-23):
                    // this fires on every incoming message while the pool is empty, so
                    // without it, several messages arriving in a burst before a resupply
                    // lands would each queue their own sendAnonTokensTo() call -- unlike
                    // the other four call sites of this function, which already had it.
                    if (AnonTokenManager.getContactTokens(this@MessengerService, from).isEmpty() && shouldResupplyTokens(from)) {
                        scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
                    }
                } catch (e: SessionKeyManager.DuplicateOrStaleMessage) {
                    // Not a decrypt failure — see nextRecvKey()'s comment.
                    // Swallowed deliberately (unlike the generic catch below):
                    // this message was already processed once, so there's
                    // nothing to retry and no ratchet to fix. Returning
                    // normally here (not rethrowing) lets the anon_delivery
                    // handler's ack fire, telling the server to drop its
                    // token_pending fallback copy instead of redelivering
                    // this same duplicate forever. Triggering session_reset
                    // here would be actively harmful — it would tear down a
                    // perfectly healthy ratchet over a message we'd already
                    // consumed.
                    Log.d(TAG, "Дубликат/устаревшее сообщение от $from проигнорирован: ${e.message}")
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка расшифровки от $from: ${e.message}")
                    sendSessionResetDebounced(from)
                    // Re-thrown on purpose — found live 2026-08-17: this
                    // catch used to swallow the failure silently, so
                    // handleMessage() returned "cleanly" from the caller's
                    // point of view even though the message was never
                    // decrypted or shown. The anon_delivery handler (see
                    // its call to handleMessage()) only sends
                    // anon_delivery_ack when handleMessage() returns
                    // without throwing — swallowing this exception meant a
                    // decrypt failure got acked as if it had succeeded, so
                    // the server's token_pending fallback copy got
                    // discarded and the message was never retried after
                    // the session got fixed via the session_reset just
                    // sent above. See docs/ISSUE_backup_identity_hijack.md.
                    throw e
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
                        throw SecurityException("group_create: нет ключа от $from")
                    }

                    // Binds group_id + group_name + group_avatar + the key
                    // blob itself (S6-64) — was encryptedGroupKey alone,
                    // letting a relay relabel group_id/name/avatar on an
                    // otherwise-validly-signed invitation. See
                    // groupCreatePayload()'s own comment.
                    if (!CryptoManager.verify(groupCreatePayload(groupId, groupName, groupAvatar, encryptedGroupKey), signature, senderKey)) {
                        Log.e(TAG, "Неверная подпись приглашения в группу от $from")
                        throw SecurityException("group_create: неверная подпись от $from")
                    }

                    // Full signed roster (members+admins) required, not
                    // merely bounded-if-present, as of S6-65 (external review
                    // 2026-09-09) — the server previously stripped these
                    // fields from every relay, so the "legacy [from, me]/
                    // [from] fallback" this used to have was actually the
                    // ONLY path any current-version group_create ever took,
                    // silently leaving every group >2 people with a wrong
                    // local roster on every non-admin invitee. Now that the
                    // server faithfully relays these, an absent roster means
                    // either a genuinely legacy peer (no longer supported —
                    // no unsigned-roster fallback for a current-version
                    // group_create) or a stripped/tampered relay — reject
                    // either way rather than silently trusting an
                    // unauthenticated 2-person guess. See
                    // docs/ISSUE_backup_identity_hijack.md, group roster fix,
                    // for the original roster-authentication design.
                    val membersFromPacket = json.optJSONArray("members")?.let { arr ->
                        (0 until arr.length()).map { arr.getString(it) }
                    }
                    val adminsFromPacket = json.optJSONArray("admins")?.let { arr ->
                        (0 until arr.length()).map { arr.getString(it) }
                    }
                    if (membersFromPacket == null || adminsFromPacket == null) {
                        Log.e(TAG, "group_create: отсутствует ростер от $from — отклонено")
                        throw SecurityException("group_create: нет ростера от $from")
                    }
                    val payload = rosterPayload(groupId, membersFromPacket, adminsFromPacket)
                    if (rosterSignature == null || !CryptoManager.verify(payload, rosterSignature, senderKey)) {
                        Log.e(TAG, "Неверная подпись ростера группы от $from")
                        throw SecurityException("group_create: неверная подпись ростера от $from")
                    }
                    if (username !in membersFromPacket) {
                        Log.e(TAG, "group_create: ростер не содержит получателя — отклонено")
                        throw SecurityException("group_create: ростер не содержит получателя")
                    }
                    val members = membersFromPacket
                    val admins = adminsFromPacket

                    // member_keys: learn every fellow member's EC/PQ public
                    // key + display name at join time — see
                    // memberKeysPayload()'s own comment for why this exists.
                    // Separately signed from roster_signature above and
                    // verified independently, so a missing/invalid
                    // member_keys just means "no key-learning bonus this
                    // time" (backward compatible with a sender that hasn't
                    // shipped this yet), not "reject the whole invite".
                    val memberKeysArr = json.optJSONArray("member_keys")
                    val memberKeysSig = json.optString("member_keys_signature", null)
                    if (memberKeysArr != null && memberKeysSig != null) {
                        try {
                            val entries = (0 until memberKeysArr.length()).map { memberKeysArr.getJSONObject(it) }
                            if (CryptoManager.verify(memberKeysPayload(groupId, entries), memberKeysSig, senderKey)) {
                                entries.forEach { entry ->
                                    try {
                                        val fp = entry.getString("fingerprint")
                                        if (fp == username) return@forEach
                                        val pk = entry.getString("public_key")
                                        val pqB64 = entry.getString("pq_public_key")
                                        val name = entry.optString("name", "")

                                        // Same fingerprint-self-consistency check
                                        // processSessionInit() already applies to a
                                        // directly-received identity key — the admin
                                        // vouching for a roster doesn't extend to
                                        // vouching for an internally-inconsistent key.
                                        val pkBytes = android.util.Base64.decode(pk, android.util.Base64.NO_WRAP)
                                        val actualFp = java.security.MessageDigest.getInstance("SHA-256")
                                            .digest(pkBytes).take(8).joinToString("") { "%02X".format(it) }
                                        if (actualFp != fp) {
                                            Log.w(TAG, "member_keys: ключ для $fp не соответствует отпечатку (получено $actualFp) — пропущено")
                                            return@forEach
                                        }

                                        if (KeyHistoryManager.checkKeyChange(this@MessengerService, fp, pk)) {
                                            Log.w(TAG, "TOFU: ключ $fp изменился через member_keys группы $groupId!")
                                            withContext(Dispatchers.Main) { onKeyChanged?.invoke(fp) }
                                        }
                                        val pqBytes = android.util.Base64.decode(pqB64, android.util.Base64.NO_WRAP)
                                        ChatStorage.saveContactPublicKey(this@MessengerService, fp, pk)
                                        ChatStorage.saveContactPqPublicKey(this@MessengerService, fp, pqBytes)
                                        publicKeys[fp] = pk
                                        publicKeysPq[fp] = pqBytes
                                        // Don't clobber a name the user already has
                                        // (their own rename, or one learned via a
                                        // real 1:1 exchange) — only fill the gap.
                                        if (name.isNotBlank() && ChatStorage.getContactName(this@MessengerService, fp) == fp.substringBefore("_")) {
                                            ChatStorage.saveContactName(this@MessengerService, fp, name)
                                        }
                                    } catch (e: Exception) {
                                        Log.w(TAG, "member_keys: entry error — ${e.message}")
                                    }
                                }
                            } else {
                                Log.w(TAG, "group_create: неверная подпись member_keys от $from — ключи участников не изучены")
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "group_create: ошибка обработки member_keys — ${e.message}")
                        }
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
                    // Re-thrown (external review 2026-08-27/28, closing the
                    // rest of the AA-7/OPEN-2 pattern) -- was swallowed, so
                    // anon_delivery_ack could fire for a group_create that
                    // was actually rejected (bad signature/roster) or never
                    // applied (an exception mid-processing).
                    Log.e(TAG, "group_create error: ${e.message}")
                    throw e
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

                    // Peek-only — was Set.add(), which inserts AND checks in
                    // one step, marking the id "seen" even when everything
                    // after this point then failed (unknown group, bad
                    // signature, decrypt failure). A later, legitimate retry
                    // of the exact same message (e.g. once a reordered
                    // group_create finally arrives) then hit this same
                    // check, found the id already marked from the FAILED
                    // first attempt, and was silently dropped as a fake
                    // duplicate — permanent loss. Found in the 2026-09-13
                    // voice/group_message dedup audit.
                    if (processedGroupMessageIds.contains(messageId)) {
                        Log.w(TAG, "group_message replay отклонён: $messageId")
                        return
                    }

                    val group = GroupManager.getGroup(this@MessengerService, groupId)
                    if (group == null) {
                        // Thrown, not returned (external review 2026-08-27/28):
                        // an unknown group can mean group_create just hasn't
                        // arrived yet (reordered delivery) -- not ACKing lets
                        // the server's token_pending keep this queued for
                        // retry instead of losing it if group_create later
                        // catches up.
                        android.util.Log.w(TAG, "Получено сообщение для неизвестной группы $groupId")
                        throw SecurityException("group_message: неизвестная группа $groupId")
                    }

                    val senderKey = publicKeys[from]
                        ?: ChatStorage.getContactPublicKey(this@MessengerService, from)?.also {
                            publicKeys[from] = it
                        }

                    if (signature == null || senderKey == null) {
                        android.util.Log.e(TAG, "Сообщение группы без ключа от $from")
                        throw SecurityException("group_message: нет ключа от $from")
                    }

                    if (!CryptoManager.verify(encryptedText, signature, senderKey)) {
                        android.util.Log.e(TAG, "Неверная подпись группового сообщения от $from")
                        throw SecurityException("group_message: неверная подпись от $from")
                    }

                    val decryptedText = GroupManager.decryptGroupMessage(encryptedText, group.groupKey!!)

                    val groupMessage = GroupMessage(
                        id = messageId,
                        groupId = groupId,
                        senderId = from,
                        senderName = senderName,
                        text = decryptedText,
                        isOwn = from == username,
                        replyToId = json.optString("reply_to_id", null)?.takeIf { it.isNotBlank() }
                    )

                    GroupManager.saveGroupMessage(this@MessengerService, username, groupMessage)

                    // Marked processed ONLY now — after group lookup,
                    // signature verification, and decrypt have all already
                    // succeeded. See the peek-only check above for why this
                    // moved.
                    processedGroupMessageIds.add(messageId)
                    if (processedGroupMessageIds.size > 2000) processedGroupMessageIds.clear()

                    withContext(Dispatchers.Main) {
                        val cb = onGroupMessageReceived
                        if (cb != null) cb.invoke(groupId, groupMessage)
                        else showGroupMessageNotification(groupId, senderName, decryptedText)
                        MainActivity.chatListVersion.value = System.currentTimeMillis()
                    }
                } catch (e: Exception) {
                    android.util.Log.e(TAG, "group_message error: ${e.message}")
                    throw e
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
                        throw SecurityException("group_reaction: нет ключа от $from")
                    }

                    // Must match sendGroupReaction()'s transcript byte for
                    // byte -- see its comment for why the envelope is bound.
                    if (!CryptoManager.verify(
                            "SUBROSA_GROUP_REACTION_V1:$groupId:$messageId:$emoji",
                            signature,
                            senderKey
                        )) {
                        Log.e(TAG, "Неверная подпись group_reaction от $from")
                        throw SecurityException("group_reaction: неверная подпись от $from")
                    }

                    withContext(Dispatchers.Main) {
                        onGroupReactionReceived?.invoke(groupId, from, messageId, emoji)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_reaction error: ${e.message}")
                    throw e
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
                            throw SecurityException("group_member_removed: $from не админ")
                        }

                        val adminKey = publicKeys[from]
                            ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                        if (removeSignature == null || adminKey == null ||
                            !CryptoManager.verify("$groupId:$removedMember", removeSignature, adminKey)) {
                            Log.e(TAG, "group_member_removed: неверная подпись от $from — отклонено")
                            throw SecurityException("group_member_removed: неверная подпись от $from")
                        }
                        GroupManager.removeMember(this@MessengerService, groupId, from, removedMember)

                        // removeMember() deletes the local group entirely when WE
                        // are the one removed (self or kicked, see its doc comment)
                        // — nothing left to attach a "member left" system message
                        // to. Instead, bump chatListVersion directly so the chat
                        // list drops the now-gone group immediately, same as the
                        // local leave flow in GroupInfoScreen.kt does.
                        if (GroupManager.getGroup(this@MessengerService, groupId) != null) {
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
                        } else {
                            withContext(Dispatchers.Main) {
                                MainActivity.chatListVersion.value = System.currentTimeMillis()
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "group_member_removed error: ${e.message}")
                    throw e
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
                            throw SecurityException("group_member_added: $from не админ")
                        }

                        val adminKey = publicKeys[from]
                            ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                        if (addSignature == null || adminKey == null ||
                            !CryptoManager.verify("$groupId:add:$newMember", addSignature, adminKey)) {
                            Log.e(TAG, "group_member_added: неверная подпись от $from — отклонено")
                            throw SecurityException("group_member_added: неверная подпись от $from")
                        }
                        GroupManager.addMember(this@MessengerService, groupId, from, newMember)

                        // member_keys: learn the new member's own EC/PQ key —
                        // same handling as group_create's member_keys array,
                        // just a single entry here. Without this, EXISTING
                        // members could see the newcomer's name but never
                        // verify a signed frame FROM them (e.g. a group call
                        // join) — see memberKeysPayload()'s own comment.
                        val memberKeysArr = json.optJSONArray("member_keys")
                        val memberKeysSig = json.optString("member_keys_signature", null)
                        if (memberKeysArr != null && memberKeysSig != null && adminKey != null) {
                            try {
                                val entries = (0 until memberKeysArr.length()).map { memberKeysArr.getJSONObject(it) }
                                if (CryptoManager.verify(memberKeysPayload(groupId, entries), memberKeysSig, adminKey)) {
                                    entries.forEach { entry ->
                                        try {
                                            val fp = entry.getString("fingerprint")
                                            if (fp == username) return@forEach
                                            val pk = entry.getString("public_key")
                                            val pqB64 = entry.getString("pq_public_key")
                                            val name = entry.optString("name", "")

                                            val pkBytes = android.util.Base64.decode(pk, android.util.Base64.NO_WRAP)
                                            val actualFp = java.security.MessageDigest.getInstance("SHA-256")
                                                .digest(pkBytes).take(8).joinToString("") { "%02X".format(it) }
                                            if (actualFp != fp) {
                                                Log.w(TAG, "member_keys: ключ для $fp не соответствует отпечатку (получено $actualFp) — пропущено")
                                                return@forEach
                                            }

                                            if (KeyHistoryManager.checkKeyChange(this@MessengerService, fp, pk)) {
                                                Log.w(TAG, "TOFU: ключ $fp изменился через member_keys группы $groupId!")
                                                withContext(Dispatchers.Main) { onKeyChanged?.invoke(fp) }
                                            }
                                            val pqBytes = android.util.Base64.decode(pqB64, android.util.Base64.NO_WRAP)
                                            ChatStorage.saveContactPublicKey(this@MessengerService, fp, pk)
                                            ChatStorage.saveContactPqPublicKey(this@MessengerService, fp, pqBytes)
                                            publicKeys[fp] = pk
                                            publicKeysPq[fp] = pqBytes
                                            if (name.isNotBlank() && ChatStorage.getContactName(this@MessengerService, fp) == fp.substringBefore("_")) {
                                                ChatStorage.saveContactName(this@MessengerService, fp, name)
                                            }
                                        } catch (e: Exception) {
                                            Log.w(TAG, "member_keys: entry error — ${e.message}")
                                        }
                                    }
                                } else {
                                    Log.w(TAG, "group_member_added: неверная подпись member_keys от $from — ключ не изучен")
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "group_member_added: ошибка обработки member_keys — ${e.message}")
                            }
                        }

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
                    throw e
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
                        throw SecurityException("group_key_rotation: нет ключа от $from")
                    }

                    if (!CryptoManager.verify("$groupId:$encryptedNewKey", signature, senderKey)) {
                        Log.e(TAG, "Неверная подпись ротации ключа от $from")
                        throw SecurityException("group_key_rotation: неверная подпись от $from")
                    }

                    if (!GroupManager.isAdmin(this@MessengerService, groupId, from)) {
                        Log.e(TAG, "group_key_rotation от не-администратора $from в группе $groupId")
                        throw SecurityException("group_key_rotation: $from не админ")
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
                    throw e
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
                        throw SecurityException("group_invite_accepted: неверная подпись от $newMember")
                    }

                    // Processed on the inviting admin's own device once the new
                    // member signs proof of accepting -- actor is this device's
                    // own user (the admin who originated the invite), not the
                    // new member being added.
                    GroupManager.addMember(this@MessengerService, groupId, username, newMember)

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
                    throw e
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
                    val ts      = json.optLong("ts", 0L)
                    CallManager.init(this@MessengerService)
                    val isFreshIncomingCall = CallManager.handleOffer(from, sdp, callId, isVideo, isGroup, gId, ts)

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

            // Single-candidate type — kept for any candidate still in flight
            // from an older build mid-rollout. See "call_ice_batch" below.
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

            // Batches multiple ICE candidates into one anon_message — see
            // CallManager.queueIceCandidate()/ICE_BATCH_DEBOUNCE_MS. A call's
            // ICE gathering burst (10-30+ candidates) used to consume its own
            // anon token per candidate from the same small per-contact pool
            // ordinary messages draw from, exhausting it well before the
            // token-reserve/refill logic (built for the video-circle case)
            // ever got a chance to help.
            "call_ice_batch", "call_group_ice_batch" -> {
                try {
                    val from = json.getString("from")
                    val candidates = json.getJSONArray("candidates")
                    for (i in 0 until candidates.length()) {
                        val c = candidates.getJSONObject(i)
                        CallManager.handleIceCandidate(
                            from, c.getString("sdp_mid"), c.getInt("sdp_m_line_index"), c.getString("candidate")
                        )
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "call_ice_batch error: ${e.message}")
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
                // Hoisted above the try so the catch below can report which
                // inner type/sender a failure was actually about — "No value
                // for from" alone (found live 2026-09-13) gives no way to
                // tell whether the sender omitted a required field or this
                // device mis-dispatched a payload type that's never supposed
                // to arrive via anon_delivery in the first place.
                var innerTypeForLog: String? = null
                var innerFromForLog: String? = null
                try {
                    val rawPayload = json.getJSONObject("payload")
                    val transportToken = json.optString("token", null)

                    // See sealPacketForRecipient()'s comment: senders now wrap
                    // from/to/text in one more layer of encryption keyed to
                    // MY identity, instead of leaving from/to in the clear
                    // next to the token. "blob" present means sealed —
                    // decrypt with my own key (no need to know who sent it
                    // first, unlike the Double Ratchet session itself).
                    // Falls back to using rawPayload directly for an
                    // unpatched peer mid-rollout (old shape had no "blob").
                    val blob = rawPayload.optString("blob", null)
                    if (blob != null && blob.length > ANON_DELIVERY_BLOB_MAX_LEN) {
                        Log.e(TAG, "anon_delivery: blob превышает ANON_DELIVERY_BLOB_MAX_LEN (${blob.length}) — отброшено до decrypt()")
                        return
                    }
                    val payload = if (blob != null) {
                        try {
                            org.json.JSONObject(CryptoManager.decrypt(blob))
                        } catch (e: Exception) {
                            Log.e(TAG, "anon_delivery: не удалось распечатать blob — ${e.message}")
                            return
                        }
                    } else rawPayload
                    innerTypeForLog = payload.optString("type", null)
                    innerFromForLog = payload.optString("from", null)

                    // Sealed Sender, шаг 1 (продолжение): если отправитель
                    // приложил sender_cert/sender_cert_sig внутрь конверта,
                    // проверяем подпись сервера и что сертификат выписан
                    // именно на тот fingerprint, что packet заявляет как
                    // "from" — иначе кто угодно мог бы приложить свой
                    // валидный сертификат к чужому "from".
                    val senderCert    = payload.optJSONObject("sender_cert")
                    val senderCertSig = payload.optString("sender_cert_sig", null)
                    val claimedFrom   = payload.optString("from", null)
                    var certVerified = false
                    if (senderCert != null && senderCertSig != null) {
                        val certFingerprint = senderCert.optString("fingerprint", null)
                        if (certFingerprint != claimedFrom) {
                            Log.w(TAG, "anon_delivery: sender_cert выписан на $certFingerprint, а from=$claimedFrom — не совпадает")
                        } else if (!SenderCertManager.verify(senderCert, senderCertSig)) {
                            Log.w(TAG, "anon_delivery: sender_cert для $claimedFrom не прошёл проверку подписи")
                        } else {
                            certVerified = true
                            Log.d(TAG, "anon_delivery: sender_cert для $claimedFrom подтверждён")
                        }
                    }

                    // Enforced for unsigned control types (S6-66 follow-up)
                    // — end-to-end identity signature, not sender_cert (see
                    // ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE's own
                    // comment for why). No dispatch, no ack, no state
                    // mutation on failure.
                    val innerType = payload.optString("type", null)
                    if (innerType in ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE) {
                        val controlSig = payload.optString("signature", null)
                        val senderKey = if (claimedFrom != null) {
                            publicKeys[claimedFrom]
                                ?: ChatStorage.getContactPublicKey(this@MessengerService, claimedFrom)
                        } else null
                        if (controlSig == null || senderKey == null ||
                            !CryptoManager.verify(controlEnvelopeTranscript(payload), controlSig, senderKey)) {
                            Log.w(TAG, "anon_delivery: $innerType — неверная или отсутствующая подпись отправителя (from=$claimedFrom), отклонено")
                            return
                        }
                    }

                    handleMessage(payload)

                    // Real confirmation that this device actually processed
                    // the delivery — server.py used to treat its own
                    // send_safe() succeeding as final (the write not
                    // raising, not proof this device got it), so a
                    // connection dying in that exact race window silently
                    // lost the message. Only sent once handleMessage()
                    // returns without throwing; server.py keeps the
                    // fallback copy in token_pending (redelivered on next
                    // subscribe_tokens) until this arrives. Root-caused
                    // live 2026-08-17 — see
                    // docs/ISSUE_backup_identity_hijack.md.
                    //
                    // consumeMyToken() moved to markMyTokenAckPending() here
                    // instead — found live 2026-09-03 (external review): the
                    // token used to be fully removed from PREF_MY_TOKENS
                    // BEFORE handleMessage() even ran, let alone before the
                    // ack below was confirmed received. A crash in
                    // handleMessage(), a lost ack, or a reconnect racing this
                    // exact window all had the same result — the token
                    // vanished from our own subscribe_tokens list forever,
                    // so server.py's token_pending fallback copy (meant to be
                    // redelivered on the next subscribe_tokens) had nobody
                    // left listening for it, silently orphaned until its 24h
                    // TTL sweep. markMyTokenAckPending() keeps it in the
                    // subscribe list (see connect()/sendAnonTokensTo()'s
                    // subscribe_tokens payload) until the server's
                    // "anon_delivery_ack_ok" response confirms the ack
                    // truly landed — only then does confirmMyTokenAcked()
                    // (the "anon_delivery_ack_ok" handler below) fully
                    // forget it. sendWs()'s own return value was already
                    // known not to be a reliable enough signal for this —
                    // see the token-restore-disabled comments elsewhere in
                    // this file — an explicit server round-trip is the only
                    // correct confirmation.
                    if (!transportToken.isNullOrBlank()) {
                        AnonTokenManager.markMyTokenAckPending(this@MessengerService, transportToken)
                        sendWs(JSONObject().apply {
                            put("type", "anon_delivery_ack")
                            put("token", transportToken)
                        }.toString())
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "anon_delivery error: innerType=$innerTypeForLog innerFrom=$innerFromForLog — ${e.message}")
                }
            }

            // Server's confirmation that our anon_delivery_ack for this
            // token was actually received and its pending/spent state is
            // now durable — see markMyTokenAckPending()'s comment for why
            // this round-trip exists at all. Only now is it safe to fully
            // forget the token; until this arrives it stays in ACK_PENDING
            // and keeps being included in subscribe_tokens, so a lost ack
            // still gets a chance to be redelivered and re-acked after a
            // reconnect instead of being silently orphaned.
            "anon_delivery_ack_ok" -> {
                val token = json.optString("token", null)
                if (!token.isNullOrBlank()) {
                    AnonTokenManager.confirmMyTokenAcked(this@MessengerService, token)
                }
            }

            // Closes the last gap in the ACK_PENDING self-healing loop —
            // found live 2026-09-03 (external review): anon_delivery_ack_ok
            // itself can be the thing that gets lost (server processed the
            // ack and sent the confirmation, connection died before it
            // arrived) — a token stuck in ACK_PENDING then re-subscribes on
            // every reconnect via tokensToSubscribe() forever, since nothing
            // ever told this device the server already considers it spent.
            // server.py's subscribe_tokens handler now checks spent_tokens
            // for every token in the request and reports back here instead
            // of silently re-registering an already-spent token as if it
            // were still live. Each entry gets the exact same treatment as
            // a genuine anon_delivery_ack_ok.
            "subscribe_tokens_result" -> {
                val spentArr = json.optJSONArray("spent")
                if (spentArr != null) {
                    for (i in 0 until spentArr.length()) {
                        val token = spentArr.optString(i, null)
                        if (!token.isNullOrBlank()) {
                            AnonTokenManager.confirmMyTokenAcked(this@MessengerService, token)
                        }
                    }
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
        // Found live 2026-09-18: this used to log "ОТПРАВЛЕНО" (SENT) right
        // here, unconditionally, before the coroutine below had even checked
        // whether a session exists — let alone attempted a real network
        // send. A message with no session/PQ key yet (e.g. the peer's
        // prekey bundle is still unpublished server-side) falls straight
        // into pendingSessionMessages and can sit there for minutes without
        // ever reaching sendWs(), while the log already claimed success.
        // Server-side confirmation: nothing shows up there at all for that
        // message — it never left the device. Moved the "ОТПРАВЛЕНО" log to
        // each actual transmission point below, with a matching "В ОЧЕРЕДИ"
        // log wherever this falls back to queuing instead, so the log is
        // never lying about what actually happened to a given message id.
        scope.launch(Dispatchers.IO) {
            try {
                if (!SessionKeyManager.hasSession(to) && !isFirst) {
                    Log.i(TAG, "В ОЧЕРЕДИ message $id → $to — нет сессии, ждём prekey bundle @ ${System.currentTimeMillis()}")
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

                    // Seal FIRST, before touching the token pool at all — found live
                    // 2026-09-03 (external review, Android audit, two rounds): a
                    // separate "canSeal" pre-check followed by consumeNextContactToken()
                    // still leaves a TOCTOU gap (key/cache changes between the check
                    // and the actual seal a few lines later), and
                    // AnonTokenManager.restoreContactToken() was removed as
                    // dead/dangerous code (KNOWN_SECURITY_ISSUES.md AA-10), so there is
                    // no safe way to un-consume a token after the fact if sealing then
                    // fails anyway. The seal operation itself IS the availability
                    // check — no separate pre-check needed, and the token pool is
                    // never touched until a sealed blob already exists in hand. Rule:
                    // if a packet must go through the anonymous/sealed path, seal →
                    // consume → send, never canSeal → consume → seal.
                    val sealed = sealPacketForRecipient(to, packet)
                    if (sealed == null) {
                        Log.i(TAG, "В ОЧЕРЕДИ message $id → $to — не удалось запечатать (нет PQ-ключа получателя?), ждём prekey bundle @ ${System.currentTimeMillis()}")
                        pendingSessionMessages.getOrPut(to) { mutableListOf() }.add(Pair(text, id))
                        requestPrekeyBundle(to)
                        return@launch
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
                        val outerPayload = JSONObject().apply {
                            put("id", id)
                            put("blob", sealed)
                        }
                        val anonPacket = JSONObject().apply {
                            put("type", "anon_message")
                            put("token", anonToken)
                            put("payload", outerPayload)
                        }
                        val sent = sendAnonMessageWs(anonPacket)
                        Log.d(TAG, "DEBUG-TOKENLIFE sendWithForwardSecrecy: to=$to id=$id isFirst=$isFirst token=…${anonToken.takeLast(6)} bootstrap=${bootstrapToken != null} sendWs=$sent")
                        if (sent) {
                            Log.i(TAG, "ОТПРАВЛЕНО message $id → $to @ ${System.currentTimeMillis()}")
                        } else {
                            Log.i(TAG, "В ОЧЕРЕДИ message $id → $to — sendWs вернул false @ ${System.currentTimeMillis()}")
                        }
                        // Restore-on-failure DISABLED — found live 2026-08-18: sendWs()
                        // returning false is not a reliable signal that the frame never
                        // left the device (under real network stress — e.g. mid video
                        // call — a "failed" send can still land server-side moments
                        // later). Restoring the token back into the pool in that case
                        // let it be reused for a second, unrelated message while the
                        // server had already delivered-and-invalidated it from the
                        // first use — token …9bc2b4 confirmed delivered once, then
                        // handed out again ~12 minutes later, "офлайн" on the second
                        // use since the server had already cleared its routing entry.
                        // A double-spent single-use token is worse than a lost one — an
                        // occasional restore-denied token is an acceptable trade for
                        // never silently routing a message into the void with the
                        // sender believing it succeeded. See
                        // docs/ISSUE_backup_identity_hijack.md.
                        // if (!sent && bootstrapToken == null) {
                        //     AnonTokenManager.restoreContactToken(this@MessengerService, to, anonToken)
                        // }

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
                            Log.i(TAG, "ОТПРАВЛЕНО message $id → $to через mailbox (session_init) @ ${System.currentTimeMillis()}")
                            depositSessionInitViaMailbox(to, mailboxTag, recipientKey, packet)
                        } else {
                            // Direct sendWs() fallback removed (external review
                            // 2026-08-23): despite the comment on the "else" branch
                            // below claiming "same as sendAnonOrDirect does for
                            // everything else... see the isFirst branch above", this
                            // branch never actually got that fix -- it still sent
                            // fingerprint-addressed session_init directly whenever
                            // no mailbox tag/key was cached yet, contradicting
                            // SECURITY.md's "no fingerprint-addressed fallback"
                            // claim for exactly the first-contact case. Queue and
                            // retry via requestPrekeyBundle instead, same as the
                            // no-session branch at the top of this function --
                            // handleFetchedPrekeyBundle() flushes pendingSessionMessages
                            // once the bundle (and its bootstrap token) arrives.
                            Log.i(TAG, "В ОЧЕРЕДИ message $id → $to — нет mailbox-тега/ключа контакта @ ${System.currentTimeMillis()}")
                            pendingSessionMessages.getOrPut(to) { mutableListOf() }.add(Pair(text, id))
                            requestPrekeyBundle(to)
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
                        // sendAnonOrDirect() logs its own honest outcome
                        // (DEBUG-TOKENLIFE sendWs=true/false, or
                        // DEBUG-BOOTSTRAP ... queued) — not duplicated here to
                        // avoid claiming a result this function can't
                        // directly observe.
                        Log.i(TAG, "message $id → $to передан в sendAnonOrDirect (см. DEBUG-TOKENLIFE/DEBUG-BOOTSTRAP для исхода) @ ${System.currentTimeMillis()}")
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
        val pqKey = resolvePqKey(to)
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
    /** Explicit, immediate revocation of tokens previously shared with
     *  [contactId] — see AnonTokenManager.recordTokensGivenTo(). Unlike
     *  wipeMyTokenPool() (which only stops future re-subscription, taking
     *  effect on the NEXT reconnect), this tells the server directly and
     *  immediately: any outstanding, unspent token from this batch stops
     *  routing to me right now, regardless of whether this device stays
     *  connected. Safe to call even if some/all of these tokens are already
     *  spent or unknown — server.py's unsubscribe_tokens handler only acts
     *  on tokens it currently has this connection registered as owning. */
    fun revokeContactTokens(contactId: String) {
        val given = AnonTokenManager.getTokensGivenTo(this, contactId)
        if (given.isEmpty()) return
        sendWs(JSONObject().apply {
            put("type", "unsubscribe_tokens")
            put("tokens", org.json.JSONArray(given))
        }.toString())
        Log.d(TAG, "DEBUG-TOKENLIFE revokeContactTokens($contactId): отозвано ${given.size} токенов")
    }

    fun forgetContact(contactId: String) {
        publicKeys.remove(contactId)
        publicKeysPq.remove(contactId)
        SessionKeyManager.deleteSession(contactId)
        AnonTokenManager.clearContactMailboxTag(this, contactId)
        revokeContactTokens(contactId)
        // Local-only block (see ChatStorage.blockContact()'s comment) — a
        // deleted contact can't reach a fresh session_init past this point
        // (processSessionInit() checks it first thing). Automatically lifted
        // by ChatStorage.addContact() if this fingerprint is ever legitimately
        // re-invited later, so delete-then-reinvite keeps working.
        ChatStorage.blockContact(this, contactId)
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
        lastTokenBootstrapAttempt.remove(contactId)
        lastPrekeyFetchAttempt.remove(contactId)
        periodicRetryDelayMs.remove(contactId)
        periodicRetryNextAt.remove(contactId)
    }

    /** Canonical V1 voice signature transcript (S6-58, external review
     *  2026-09-06) -- previously both platforms signed the bare `encrypted`
     *  ciphertext string with no domain separator, binding neither
     *  [voiceId] nor [duration] into the signature at all: a malicious/
     *  compromised relay could keep the authentic encrypted audio and its
     *  valid signature while relabeling voiceId/duration freely (S6-57
     *  bounded the SHAPE of these fields, never their end-to-end
     *  authenticity). voiceId in particular doubles as this app's own
     *  local storage/file-naming key (SecureFileStorage.blobFile(id) is
     *  shared across every attachment type) -- an unauthenticated relabel
     *  to an EXISTING message/attachment id silently overwrites that
     *  attachment's file content and (via ChatStorage.saveOrUpdateMessage's
     *  id-only match) that message's stored text/paths, regardless of
     *  isOwn. Delimiter concatenation is unambiguous here specifically
     *  because none of these three fields' canonical alphabets can ever
     *  contain ':': [voiceId] is validated as a canonical UUID (hex digits
     *  and hyphens only) before this is ever called, [duration] is rendered
     *  as a plain decimal integer, and [encryptedData] is standard-alphabet
     *  base64 (CryptoManager.encrypt()'s own Base64.NO_WRAP output --
     *  A-Z/a-z/0-9/+//and padding '=', never ':'). Sender identity is
     *  already bound implicitly by which contact's public key verification
     *  selects (same as every other signed control type in this file, e.g.
     *  message_delete); recipient identity is already bound implicitly by
     *  CryptoManager.encrypt()'s own per-recipient hybrid ECDH+ML-KEM
     *  encryption -- decrypting with any OTHER recipient's private key
     *  fails at the AES-GCM tag-check step regardless of this signature, so
     *  neither field needs to be repeated inside the transcript itself.*/
    private fun voiceSignatureTranscript(voiceId: String, duration: Int, encryptedData: String): String =
        "SUBROSA_VOICE_V1:$voiceId:$duration:$encryptedData"

    fun sendVoice(to: String, voiceBase64: String, voiceId: String, duration: Int) {
        Log.i(TAG, "ОТПРАВЛЕНО voice $voiceId → $to @ ${System.currentTimeMillis()}")
        scope.launch(Dispatchers.IO) {
            try {
                val cachedKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also { publicKeys[to] = it }
                val cachedPqKey = resolvePqKey(to)
                if (cachedKey == null || cachedPqKey == null) {
                    Log.w(TAG, "sendVoice: нет ключа $to — запрашиваем")
                    requestPrekeyBundle(to)
                    pendingSessionMessages.getOrPut(to) { mutableListOf() }
                        .add("__voice__|${voiceId}|${duration}|$voiceBase64" to voiceId)
                    return@launch
                }
                val encrypted = CryptoManager.encrypt(voiceBase64, cachedKey, cachedPqKey)
                // Transcript versioned and domain-separated (S6-58, external
                // review 2026-09-06) -- previously signed the bare `encrypted`
                // ciphertext with no domain separator at all, binding neither
                // voiceId nor duration into the signature and colliding in
                // shape with every other type that also just signs bare
                // ciphertext (message/edit/...). See sendVoiceTranscript()'s
                // own comment.
                val signature = CryptoManager.sign(voiceSignatureTranscript(voiceId, duration, encrypted))
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

    private val lastSessionResetSentAt = mutableMapOf<String, Long>()

    /** Debounced to once per 10s per contact. Every decrypt failure from a
     *  given contact independently wiped the session and fired its own
     *  session_reset + prekey re-fetch — a burst of several failed messages
     *  in a row (e.g. a few queued sends landing back-to-back after a
     *  reconnect) fired that many resets. Found live 2026-08-17: one side
     *  queued 5 session_reset sends to the same contact within ~3.5s (all
     *  stuck behind a temporary token/connection gap), and once delivered,
     *  each one independently deleted the recipient's session again —
     *  including sessions the recipient had *already* freshly
     *  re-established off an earlier reset in the same burst. Self-sustaining
     *  loop, not a one-time hiccup: "Пакет повреждён" / repeated
     *  session_reset never settled on its own. See
     *  docs/ISSUE_backup_identity_hijack.md. */
    private fun sendSessionResetDebounced(to: String) {
        val now = System.currentTimeMillis()
        if (now - (lastSessionResetSentAt[to] ?: 0L) < 10_000L) return
        lastSessionResetSentAt[to] = now
        SessionKeyManager.deleteSession(to)
        requestPrekeyBundle(to)
        sendAnonOrDirect(to, JSONObject().apply {
            put("type", "session_reset")
            put("from", username)
            put("to", to)
        })
    }

    /** Server-side proof-of-work gate on brand-new registrations
     *  (MAX_REGISTERED_USERS/POW_DIFFICULTY_BITS in server.py) — finds a
     *  nonce such that sha256(challenge + nonce) has at least [difficultyBits]
     *  leading zero bits, matching the server's own check byte-for-byte.
     *  Pure CPU work, no network — run off the IO dispatcher (see caller). */
    private fun solveProofOfWork(challenge: ByteArray, difficultyBits: Int): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        var counter = 0L
        while (true) {
            val nonce = counter.toString()
            digest.reset()
            digest.update(challenge)
            digest.update(nonce.toByteArray(Charsets.UTF_8))
            if (powLeadingZeroBits(digest.digest()) >= difficultyBits) return nonce
            counter++
        }
    }

    private fun powLeadingZeroBits(bytes: ByteArray): Int {
        var bits = 0
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            if (v == 0) { bits += 8; continue }
            bits += 8 - (32 - Integer.numberOfLeadingZeros(v))
            break
        }
        return bits
    }

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
        Log.i(TAG, "ОТПРАВЛЯЮ квитанцию read id=$messageId → $to @ ${System.currentTimeMillis()}")
        val packet = JSONObject().apply {
            put("type", "read")
            put("from", username)
            put("to", to)
            put("id", messageId)
        }
        sendAnonOrDirect(to, packet)
    }

    /** Wraps `packet` (which otherwise carries "from"/"to" in the clear
     *  right next to the anon_message token) in one more layer of hybrid
     *  asymmetric encryption keyed to the recipient's own identity — the
     *  same mechanism sendAnonTokensTo() already uses for
     *  __beacon_tokens__. Decryption only needs the recipient's own
     *  private key (CryptoManager.decrypt()), not any prior knowledge of
     *  who sent it, so this doesn't have the chicken-and-egg problem a
     *  Double Ratchet session does (you'd need "from" to pick the session
     *  before you could decrypt something that reveals "from").
     *
     *  Found live 2026-08-29 (user-reported, external review pointed at
     *  the specific fields): the token protects *routing* — the server
     *  never needs from/to to deliver by token — but until this, the
     *  actual JSON payload it relays still carried both in plaintext,
     *  readable by anyone with access to the process at that moment
     *  (and the federation fallback path explicitly read `to`). Sealing
     *  here means the server (or anyone reading over its shoulder) sees
     *  only an opaque blob, never the sender/recipient pair. Deliberate
     *  trade-off, decided with the user: federation's fallback routing by
     *  fingerprint (payload.get("to") when the token isn't known locally)
     *  stops working for anything sent this way — accepted, since the
     *  metadata leak was judged worse than that fallback path.
     *
     *  Returns null if the recipient's keys aren't cached yet — callers
     *  fall back to the old unsealed shape rather than silently losing
     *  the send outright. */
    private fun sealPacketForRecipient(to: String, packet: JSONObject): String? {
        val recipientKey = publicKeys[to] ?: ChatStorage.getContactPublicKey(this, to)?.also { publicKeys[to] = it }
        val recipientPqKey = resolvePqKey(to)
        if (recipientKey == null || recipientPqKey == null) return null
        return try {
            // Sealed Sender, шаг 1 (продолжение): сертификат "это я", если он
            // уже закэширован, едет внутри того же конверта, что и
            // from/to/text — сервер его не видит, только получатель, у
            // которого есть запиненный публичный ключ сервера для проверки
            // подписи (SenderCertManager.verify()). Копия packet, а не
            // мутация на месте — вызывающий код переиспользует исходный
            // packet как unsealed-фоллбэк, если этот вызов вернёт null.
            val enriched = JSONObject(packet.toString())
            SenderCertManager.getFresh(this)?.let { (cert, signature) ->
                enriched.put("sender_cert", cert)
                enriched.put("sender_cert_sig", signature)
            }
            // Diagnostics only (2026-08-31) — see CryptoManager.shortHash()'s
            // comment. Compare this pqKeyHash against the recipient's own
            // logged "myPqPublicHash" in decrypt() to confirm directly
            // whether a persistent BAD_DECRYPT really is a key mismatch.
            Log.d(TAG, "DEBUG-DECRYPT sealPacketForRecipient: to=$to pqKeyHash=${CryptoManager.shortHash(recipientPqKey)}")
            CryptoManager.encrypt(enriched.toString(), recipientKey, recipientPqKey)
        } catch (e: Exception) {
            Log.e(TAG, "sealPacketForRecipient: не удалось запечатать для $to — ${e.message}")
            null
        }
    }

    // No direct/fingerprint-addressed fallback here on purpose — see the
    // "cut the direct fallback" decision in docs/ISSUE_backup_identity_hijack.md.
    // An anonymity layer that silently degrades to non-anonymous the moment
    // its token pool runs dry only provides the illusion of the property it
    // claims. When no token is available, the packet is queued and a token
    // refill/mailbox bootstrap is kicked off instead of sending in the clear.
    private fun sendAnonOrDirect(to: String, packet: JSONObject) {
        // These types carry no per-message signature of their own (S6-66
        // follow-up, external review 2026-09-09) — the original fix required
        // a verified sender_cert instead, but that depends on a per-server
        // signing-key pin with no universal trust anchor across arbitrary
        // self-hosted servers (SERVER_CERT_PUBLIC_KEY_B64 is deliberately
        // never a baked-in constant). Replaced with an end-to-end identity
        // signature — the device's own long-term key, always available
        // immediately, no async cert fetch/queue needed. See
        // controlEnvelopeTranscript()'s own comment for the transcript.
        if (packet.optString("type") in ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE) {
            packet.put("signature", CryptoManager.sign(controlEnvelopeTranscript(packet)))
        }
        // Don't even try to consume a token for a connection we already
        // know is down — consumeNextContactToken() below permanently
        // removes a single-use token from the local pool the instant it's
        // called, regardless of whether the send that follows actually
        // reaches the server. Skipping straight to the queue-and-retry
        // path here avoids burning through the whole pool during an
        // extended outage (found live: a burst of send attempts while
        // offline for 60-90s silently drained tokens with no way to get
        // them back — no server-side trace at all, since the packets never
        // left the device, so it wasn't even the "офлайн, в очередь" path,
        // just silent loss until the 15-minute health-check eventually
        // re-bootstrapped the channel from scratch).
        if (!isConnected) {
            queuePendingAnon(to, packet)
            return
        }
        // Seal FIRST, before touching the token pool at all — found live
        // 2026-09-03 (external review, Android audit, two rounds): a separate
        // "canSeal" pre-check followed by consumeNextContactToken() still
        // leaves a TOCTOU gap (key/cache changes between the check and the
        // actual seal a few lines later), and
        // AnonTokenManager.restoreContactToken() was removed as
        // dead/dangerous code (KNOWN_SECURITY_ISSUES.md AA-10), so there is
        // no safe way to un-consume a token after the fact if sealing then
        // fails anyway. The seal operation itself IS the availability
        // check — no separate pre-check needed, and the token pool is never
        // touched until a sealed blob already exists in hand. Rule: if a
        // packet must go through the anonymous/sealed path, seal → consume →
        // send, never canSeal → consume → seal.
        val sealed = sealPacketForRecipient(to, packet)
        if (sealed == null) {
            queuePendingAnon(to, packet)
            requestPrekeyBundle(to)
            return
        }
        val token = AnonTokenManager.consumeNextContactToken(this, to)
        if (token != null) {
            val outerPayload = JSONObject().apply {
                put("id", packet.optString("id").ifBlank { packet.optString("message_id") })
                put("blob", sealed)
            }
            val anonPacket = JSONObject().apply {
                put("type", "anon_message")
                put("token", token)
                put("payload", outerPayload)
            }
            val sent = sendAnonMessageWs(anonPacket)
            Log.d(TAG, "DEBUG-TOKENLIFE sendAnonOrDirect: to=$to type=${packet.optString("type")} id=${packet.optString("id").ifBlank { packet.optString("message_id") }} token=…${token.takeLast(6)} sendWs=$sent")
            if (!sent) {
                // Token restore DISABLED — see sendWithForwardSecrecy()'s
                // matching comment, docs/ISSUE_backup_identity_hijack.md,
                // 2026-08-18: sendWs()==false isn't a reliable enough signal
                // that the frame never reached the server to safely reuse
                // the token — a token confirmed delivered once and then
                // handed out again is worse than one that's simply lost.
                // The message itself is still queued and retried normally.
                // AnonTokenManager.restoreContactToken(this, to, token)
                queuePendingAnon(to, packet)
                return
            }
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
            queuePendingAnon(to, packet)
        }
    }

    private fun queuePendingAnon(to: String, packet: JSONObject) {
        val queueSize = synchronized(pendingAnonPackets) {
            pendingAnonPackets.getOrPut(to) { mutableListOf() }.add(packet)
            pendingAnonPackets[to]?.size ?: 0
        }
        Log.d(TAG, "DEBUG-BOOTSTRAP sendAnonOrDirect: нет токена/связи для $to, поставлено в очередь (в очереди: $queueSize) type=${packet.optString("type")}")
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

    /** Flushes every contact's pendingAnonPackets queue (S6-66) — called once
     *  a fresh sender_cert arrives, since a packet queued for THAT reason
     *  could be waiting under any contact's key, not just one. Safe to call
     *  speculatively, same as flushPendingAnon() itself: a packet that still
     *  can't go (e.g. genuinely offline) just re-queues via sendAnonOrDirect(). */
    private fun flushAllPendingAnon() {
        val targets = synchronized(pendingAnonPackets) { pendingAnonPackets.keys.toList() }
        targets.forEach { flushPendingAnon(it) }
    }

    fun sendReaction(to: String, messageId: String, emoji: String) {
        scope.launch(Dispatchers.IO) {
            try {
                val cachedKey = publicKeys[to] ?: return@launch
                val cachedPqKey = resolvePqKey(to) ?: return@launch
                val encrypted = CryptoManager.encrypt(emoji, cachedKey, cachedPqKey)
                // Binds message_id (CODE-03, 2026-11-03). This used to sign
                // `encrypted` alone. Unlike group_reaction the signed value
                // is ciphertext, so it was not reusable across conversations
                // (the ciphertext is keyed to this recipient) -- but nothing
                // bound it to a message, so a captured reaction signature
                // could be re-attributed to a DIFFERENT message in the same
                // conversation. Same versioned-prefix pattern as
                // SUBROSA_VOICE_V1 / SUBROSA_GROUP_MESSAGE_DELETE_V1.
                val signature = CryptoManager.sign("SUBROSA_REACTION_V1:$messageId:$encrypted")
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
        val cachedPqKey = resolvePqKey(to) ?: return
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
        // No isConnected guard on purpose — sendAnonOrDirect() already
        // queues correctly when offline (queuePendingAnon), same as every
        // other send path. This function used to bail out entirely while
        // offline: the local copy was deleted immediately, but the peer's
        // copy was never told, permanently and silently, since there was no
        // retry and no error shown to the user. Root-caused live 2026-08-17.
        // Transcript versioned (S6-54, external review 2026-09-06):
        // previously signed the bare messageId with no domain separator at
        // all -- group_member_removed's own "$groupId:$removedMember"
        // transcript is the same two-colon-joined shape as
        // group_message_delete's, so an unprefixed scheme risks a
        // signature computed for one operation verifying for another if
        // their signed values ever happen to coincide.
        // "SUBROSA_MESSAGE_DELETE_V1:" makes this transcript unambiguous
        // and un-replayable as any other operation, including
        // group_message_delete (see its own distinct prefix below).
        scope.launch(Dispatchers.IO) {
            sendAnonOrDirect(to, JSONObject().apply {
                put("type", "message_delete")
                put("from", username)
                put("to", to)
                put("message_id", messageId)
                put("signature", CryptoManager.sign(ChatControlTranscripts.messageDelete(messageId)))
            })
        }
    }

    fun sendGroupDeleteMessage(groupId: String, messageId: String, members: List<String>) {
        // Same fix as sendDeleteMessage() above — no isConnected guard,
        // sendAnonOrDirect() already queues per-member when offline.
        // Signature added (external review 2026-08-27, OPEN-2) -- see the
        // matching receive-side fix in the "group_message_delete" handler
        // for why this was previously unauthenticated entirely. Transcript
        // versioned (S6-54, external review 2026-09-06) with its OWN domain
        // separator, distinct from direct message_delete's -- binds BOTH
        // groupId and messageId so a signature can't be replayed against a
        // different group referencing the same message id.
        val signature = CryptoManager.sign(ChatControlTranscripts.groupMessageDelete(groupId, messageId))
        scope.launch(Dispatchers.IO) {
            members.filter { it != username }.forEach { memberId ->
                sendAnonOrDirect(memberId, JSONObject().apply {
                    put("type", "group_message_delete")
                    put("from", username)
                    put("to", memberId)
                    put("group_id", groupId)
                    put("message_id", messageId)
                    put("signature", signature)
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
                put("signature", CryptoManager.sign(ChatControlTranscripts.disappearTimer(seconds)))
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

        val cachedPqKey = resolvePqKey(to)
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

                Log.d(TAG, "Изображение отправлено")

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

        val cachedPqKey = resolvePqKey(to)
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

                Log.d(TAG, "Файл $fileName успешно отправлен")

            } catch (e: Exception) {
                Log.e(TAG, "Ошибка отправки файла: ${e.message}", e)
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
            Log.e(TAG, "video_chunk неверная подпись от $from")
            throw SecurityException("video_chunk: неверная подпись от $from")
        }

        // S6-49: same bounds/capacity checks as image_chunk -- video shares
        // the same imageChunks/imageTotals accumulator (deliberately, by
        // transferKey), so it needs the same guards.
        if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS || chunkIndex !in 0 until totalChunks) {
            Log.e(TAG, "video_chunk: недопустимый chunk_index/total_chunks от $from ($chunkIndex/$totalChunks)")
            throw SecurityException("video_chunk: недопустимый chunk_index/total_chunks от $from")
        }
        val transferKey = "$from:$videoId"
        if (!pruneAndAdmitTransfer(imageChunks, imageVideoTouchedAt, transferKey, imageVideoReceivedBytes, imageVideoChunkWireLens)) {
            Log.w(TAG, "video_chunk: слишком много одновременных передач — $transferKey отклонён")
            throw SecurityException("video_chunk: слишком много одновременных передач для $from")
        }
        if (chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
            Log.e(TAG, "video_chunk: слишком большой chunk data от $from — отменяем $transferKey")
            imageChunks.remove(transferKey); imageTotals.remove(transferKey)
            imageVideoTouchedAt.remove(transferKey); imageVideoReceivedBytes.remove(transferKey)
            imageVideoChunkWireLens.remove(transferKey)
            throw SecurityException("video_chunk: слишком большой chunk data от $from")
        }
        val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
        val videoWireLens = imageVideoChunkWireLens.getOrPut(transferKey) { mutableMapOf() }
        if (!accountChunkBytes(videoWireLens, imageVideoReceivedBytes, transferKey, chunkIndex, chunkData.length)) {
            Log.e(TAG, "video_chunk: передача $transferKey превысила лимит байт — отменяем")
            imageChunks.remove(transferKey); imageTotals.remove(transferKey)
            imageVideoTouchedAt.remove(transferKey); imageVideoReceivedBytes.remove(transferKey)
            imageVideoChunkWireLens.remove(transferKey)
            throw SecurityException("video_chunk: передача $transferKey превысила лимит байт")
        }
        chunks[chunkIndex] = chunkData
        imageTotals[transferKey] = totalChunks

        if (chunks.size == totalChunks) {
            Log.d(TAG, "Все video чанки получены ($totalChunks), расшифровываем...")
            val packed = (0 until totalChunks).map { chunks[it]!! }.joinToString("")
            imageChunks.remove(transferKey)
            imageTotals.remove(transferKey)
            imageVideoTouchedAt.remove(transferKey)
            imageVideoReceivedBytes.remove(transferKey)
            imageVideoChunkWireLens.remove(transferKey)

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

        Log.d(TAG, "DEBUG-BOOTSTRAP sendVideoCircle: to=$to hasKey=${publicKeys[to] != null} hasPqKey=${resolvePqKey(to) != null} encFilePath=${encFilePath.isNotEmpty()}")

        val cachedKey = publicKeys[to]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, to)?.also {
                publicKeys[to] = it
            }

        val cachedPqKey = resolvePqKey(to)
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
                    Log.d(TAG, "Видеокружок $videoId отправлен: ${encryptedChunks.size} чанков")
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
            // NOT a real fallback — CryptoManager.encrypt() hard-requires a PQ
            // key with no classical-only code path anywhere in this codebase,
            // so sendEncrypted()/sendVoice() below were guaranteed to fail
            // their own PQ check the instant they ran. That used to re-request
            // this exact bundle (server still has none — infinite loop,
            // burning the account's anon-token new-claim budget every cycle,
            // see AnonTokenManager's freshTokensToShare()) and, for text,
            // shift the message into pendingMessages — a queue only drained by
            // the unrelated legacy get_key/public_key round-trip, which pulls
            // from MessageQueue's disk outbox instead of the text actually
            // stored here, so it was never delivered by that path either: a
            // silent message-loss bug dressed up as a "legacy fallback" log
            // line. Leaving the queue untouched instead — connect()'s
            // post-registration pendingSessionMessages retry (or the next
            // real trigger) re-requests the bundle once this contact actually
            // publishes one, with zero churn in between. Found in the
            // 2026-09-13 contact-deletion/token-exhaustion audit.
            Log.w(TAG, "Пустой prekey bundle от $from — контакт ещё не опубликовал bundle, сообщения остаются в очереди")
        } else {
            // Clears lastPrekeyFetchAttempt's cooldown the instant we get a
            // REAL bundle back — found live 2026-09-18: the cooldown (added
            // to stop a contact whose bundle stayed permanently null from
            // triggering a fresh get_prekey_bundle on every single queued
            // send) doesn't distinguish "still null, don't hammer" from
            // "just succeeded, but a NEW message needs a fresh (unspent)
            // OPK" — every bundle fetch consumes a one-time prekey, so a
            // cached bundle from 5 seconds ago can't be silently reused for
            // a second session_init. Without this, typing a message shortly
            // after an earlier fetch (e.g. one triggered by a typing
            // indicator with nothing queued to flush) left it stuck in
            // pendingSessionMessages for up to PREKEY_FETCH_COOLDOWN_MS
            // (30s) before the next request was even allowed to go out —
            // the "thinks and thinks, then the first message finally lands"
            // delay reported live. Leaving the null-branch's own cooldown
            // untouched — that IS the case this gate exists for.
            lastPrekeyFetchAttempt.remove(from)
            // Captured once, before the try — both the success path and the
            // catch blocks below need the SAME queued list. Re-querying
            // pendingSessionMessages.remove(from) again inside a catch block
            // would find nothing (already removed here) and silently drop
            // messages that should have fallen back to legacy encryption.
            val queued = pendingSessionMessages.remove(from)
            if (bundleJsonRaw.optBoolean("revoked", false)) {
                Log.w(TAG, "prekey bundle от $from помечен сервером как revoked")
                withContext(Dispatchers.Main) { onContactRevoked?.invoke(from) }
            }
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

                // checkKeyChange() BEFORE the classical-identity-key trust
                // assignment below — was reversed (found in the 2026-09-13
                // KeyHistoryManager audit): a changed key must be detected/
                // flagged before this device starts treating it as the
                // contact's active identity, not after. Only the classical
                // key is TOFU-tracked here (checkKeyChange's own contract);
                // the PQ key cache right below is independent and unaffected.
                if (KeyHistoryManager.checkKeyChange(this@MessengerService, from, bundle.identityKey)) {
                    Log.w(TAG, "TOFU: ключ контакта $from изменился при получении bundle!")
                    withContext(Dispatchers.Main) { onKeyChanged?.invoke(from) }
                }
                publicKeys[from] = bundle.identityKey
                publicKeysPq[from] = android.util.Base64.decode(bundle.pqKemPublicKey, android.util.Base64.NO_WRAP)
                ChatStorage.saveContactPqPublicKey(this@MessengerService, from, publicKeysPq[from]!!)
                ChatStorage.saveContactPublicKey(this@MessengerService, from, bundle.identityKey)
                // Diagnostics only (2026-08-31) — see CryptoManager.shortHash()'s
                // comment. Should match sealPacketForRecipient()'s logged
                // pqKeyHash for the very next send to this contact; if it
                // doesn't, something between caching here and reading via
                // resolvePqKey() is overwriting it before use.
                Log.d(TAG, "DEBUG-DECRYPT handleFetchedPrekeyBundle: from=$from spkId=${bundle.spkId} pqKeyHash=${CryptoManager.shortHash(publicKeysPq[from]!!)}")
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
        flushPendingGroupInvites(from)
    }

    // Resolved in FIFO order against incoming "decoy_candidates_result"
    // frames (see that handler) — not keyed by contact, because the
    // candidates themselves are generic "other accounts on this server" and
    // are equally usable as cover for whichever bootstrap happens to be
    // waiting; which specific pending request consumes which response batch
    // doesn't matter. Explicitly removed on timeout (see below) so a late
    // response after we've already given up doesn't get consumed by a LATER,
    // unrelated request instead of being dropped.
    private val pendingDecoyCandidateRequests = java.util.concurrent.ConcurrentLinkedQueue<CompletableDeferred<List<String>>>()

    /** Fetches [contactId]'s prekey bundle via the anonymous batched fetch,
     *  padded with decoys. Own contacts are used first; if that alone isn't
     *  enough for real cover (a new or lightly-connected account may have
     *  0-1 contacts total — a batch of size 1 is no cover at all), the
     *  remainder is topped up with server-suggested decoy fingerprints
     *  (get_decoy_candidates — see server.py's own comment on why this
     *  exists) drawn from OTHER accounts on this deployment, not just ours.
     *  Only falls back to the direct, non-anonymous fetch if truly no decoy
     *  of either kind is available (own contacts empty AND the server has
     *  nobody else with a published bundle to offer) — same honest fallback
     *  as before, just hit far less often now. */
    private fun requestPrekeyBundle(contactId: String) {
        // Found live 2026-08-29: no guard here meant two calls for the same
        // brand-new contact (e.g. two quick messages sent before the first
        // bundle response lands) fired two separate get_prekey_bundle
        // requests. The server's pick_bootstrap_token() doesn't mark a token
        // used at pick time (only when actually spent in an anon_message),
        // so both responses could hand back the SAME bootstrap token —
        // sendWithForwardSecrecy() then used it for two different messages,
        // the second silently dropped server-side as already-spent with zero
        // client-visible error. One in-flight request per contact is enough;
        // whichever response arrives flushes everything queued for them.
        //
        // lastPrekeyFetchAttempt/PREKEY_FETCH_COOLDOWN_MS gate ADDED below,
        // separately — pendingBundleRequests alone only dedupes CONCURRENT
        // in-flight requests; it clears the moment a (possibly null)
        // response lands, so a contact whose bundle is still unpublished
        // server-side got a fresh request on every subsequent trigger with
        // zero delay between them. See the field's own comment for the live
        // prekey_fetch rate-limit incident this caused.
        val now = System.currentTimeMillis()
        val lastAttempt = lastPrekeyFetchAttempt[contactId] ?: 0L
        if (now - lastAttempt < PREKEY_FETCH_COOLDOWN_MS) return
        if (!pendingBundleRequests.add(contactId)) return
        lastPrekeyFetchAttempt[contactId] = now
        val ownContacts = ChatStorage.getContacts(this).filter { it != contactId }
        scope.launch(Dispatchers.IO) {
            val needed = (MAX_BATCH_BUNDLE_TARGETS - 1) - ownContacts.size
            if (needed <= 0) {
                sendBundleBatchOrDirect(contactId, ownContacts)
                return@launch
            }
            val deferred = CompletableDeferred<List<String>>()
            pendingDecoyCandidateRequests.add(deferred)
            sendWs(JSONObject().apply {
                put("type", "get_decoy_candidates")
                put("count", needed)
            }.toString())
            // Rate-limited or otherwise unanswered requests must not hang
            // this bootstrap forever — fall back to whatever cover
            // ownContacts alone provides rather than blocking.
            val serverDecoys = withTimeoutOrNull(5_000L) { deferred.await() } ?: emptyList()
            pendingDecoyCandidateRequests.remove(deferred)
            sendBundleBatchOrDirect(contactId, (ownContacts + serverDecoys).distinct())
        }
    }

    private fun sendBundleBatchOrDirect(contactId: String, decoyPool: List<String>) {
        if (decoyPool.isEmpty()) {
            sendWs(JSONObject().apply {
                put("type", "get_prekey_bundle")
                put("target", contactId)
            }.toString())
            return
        }
        val batch = (decoyPool.shuffled().take(MAX_BATCH_BUNDLE_TARGETS - 1) + contactId).shuffled()
        sendWs(JSONObject().apply {
            put("type", "get_prekey_bundles_batch")
            put("targets", org.json.JSONArray(batch))
        }.toString())
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

    private fun depositTokensViaMailbox(contact: String, mailboxTag: String, publicKey: String, isReply: Boolean = false, presetTokens: List<String>? = null) {
        // freshTokensToShare(), not tokensToShareWith() — see its comment.
        // Guarantees the contact never receives a batch that's already dead
        // from their own perspective (their spent-history filter would just
        // discard it), which was exactly the resupply deadlock this
        // function exists to break out of.
        //
        // presetTokens (added 2026-08-31): callers that retry the SAME
        // logical deposit attempt several times (forceRestoreConnection's
        // bounded 0/30s/90s burst) used to call this with no override, so
        // every retry minted its OWN fresh 20-token batch via
        // freshTokensToShare() — three retries of one button press alone
        // added 60 tokens to the shared MY_TOKENS pool, on top of whatever
        // else was already resupplying around the same restore/reset event.
        // Found live 2026-08-31: this reliably blew past MAX_POOL_HARD_CAP
        // within seconds of a backup restore even for a single contact
        // pair, and the resulting eviction preferentially dropped the
        // OLDEST entries — which, right after a restore, are exactly the
        // values restoreMyTokens() just repopulated from the backup so the
        // untouched device's still-held copies would keep working. A
        // genuine retry of an already-sent deposit should resend the SAME
        // batch, not escalate the pool with a new one each time.
        //
        // Cooldown gate (found live 2026-09-14): a contact whose bundle
        // never resolves (resolvePqKey(contact) stays permanently null —
        // e.g. their prekey_bundle_response keeps coming back with
        // bundle:null) makes EVERY independent trigger that calls this
        // function — sendAnonTokensToLocked's own "no PQ key"/"no anon
        // token" fallbacks, attemptChannelBootstrap()'s 30s/90s retry loop,
        // the periodic pendingAnonPackets retry loop, every incoming
        // message's reactive resupply — take this exact branch, each
        // minting its OWN fresh 20-token batch via freshTokensToShare()
        // with no coordination between them. Confirmed live: server log
        // showed the same account re-subscribing 100 tokens seconds (and
        // sometimes under 50ms) apart, tripping subscribe_tokens's own rate
        // limit and getting the connection closed by the server
        // ("Rate limit exceeded"), which then reconnected and immediately
        // re-hit the same limit resubscribing the full pool again — a
        // self-sustaining disconnect loop, not just wasted tokens. Skipped
        // for isReply=true (a single reciprocal answer, already one-shot by
        // design — see the "reply" field's own comment below) and for an
        // explicit presetTokens override (forceRestoreConnection's
        // deliberate bounded 0/30s/90s resend of the SAME batch, not a new
        // one each time). Reuses the same TOKEN_BOOTSTRAP_COOLDOWN_MS/
        // lastTokenBootstrapAttempt pair queuePendingAnon() already applies
        // to sendAnonTokensTo() itself — this closes the gap for every
        // OTHER path that reaches mailbox deposit without going through
        // that gate.
        if (!isReply && presetTokens == null) {
            val now = System.currentTimeMillis()
            val shouldAttempt = synchronized(lastTokenBootstrapAttempt) {
                val last = lastTokenBootstrapAttempt[contact] ?: 0L
                if (now - last >= TOKEN_BOOTSTRAP_COOLDOWN_MS) {
                    lastTokenBootstrapAttempt[contact] = now
                    true
                } else false
            }
            if (!shouldAttempt) {
                Log.d(TAG, "DEBUG-BOOTSTRAP depositTokensViaMailbox: $contact — в кулдауне, пропускаем")
                return
            }
        }
        val tokens = presetTokens ?: AnonTokenManager.freshTokensToShare(this@MessengerService)
        AnonTokenManager.recordTokensGivenTo(this@MessengerService, contact, tokens)
        Log.d(TAG, "DEBUG-BOOTSTRAP depositTokensViaMailbox: contact=$contact tag=$mailboxTag tokens=${tokens.size} reply=$isReply")
        if (tokens.isEmpty()) return
        // This function never called subscribe_tokens at all — found live
        // 2026-08-29 via server-side DEVLOG-DIAG ("is_known=False" on a
        // token that was freshly generated and deposited moments earlier):
        // the tokens got handed to the contact via mailbox, but the server
        // never heard about them until some unrelated later event (the next
        // connect()) happened to resubscribe the full pool. Same fix as
        // sendAnonTokensToLocked's ordering fix — register with the server
        // BEFORE handing them out, not "eventually, whenever".
        val allMyTokens = AnonTokenManager.tokensToSubscribe(this@MessengerService)
        sendSubscribeTokens(allMyTokens)
        try {
            val inner = JSONObject().apply {
                put("from", username)
                put("name", UserStorage.getUsername(this@MessengerService))
                put("text", "__beacon_tokens_only__")
                put("tokens", org.json.JSONArray(tokens))
                put("mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag(this@MessengerService))
                put("id", UUID.randomUUID().toString())
                // Same "reply" semantics as sendAnonTokensTo()'s anon_message path
                // (see its comment) — without this, a mailbox-routed reply to a
                // resupply request looks identical to a fresh request on receipt,
                // and the receiving side's handler (the "reply" check around
                // handleMailboxResult's tokensArr branch) would reciprocate again
                // forever. Found live 2026-08-28: a contact stuck re-depositing
                // every ~10s indefinitely once both sides had fully run out of
                // anon tokens and every exchange had to go through mailbox.
                put("reply", isReply)
            }
            // End-to-end identity signature over every field above — see
            // mailboxTranscript()'s own comment for why this was entirely
            // missing before this fix.
            inner.put("signature", CryptoManager.sign(mailboxTranscript(inner)))
            val blob = CryptoManager.encryptClassicalOnly(inner.toString(), publicKey)
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
     *  later via Server/admin_logs.py while investigating. */
    fun bootstrapChannelFor(contact: String) {
        if (isChannelReady(contact)) return
        // Checked BEFORE the immediate attempt below, not after — two
        // independent callers landing close together (e.g. invite
        // redemption immediately followed by opening the chat screen for
        // the same brand-new contact) each fired their OWN unthrottled
        // immediate attemptChannelBootstrap(), duplicating the mailbox
        // deposit. Confirmed live 2026-09-13: attemptChannelBootstrap for
        // the same contact+tag fired at t and t+1.1s, and the receiving
        // side's addContactTokens() logged the second batch as "already in
        // pool" — wasted tokens, exactly the "tokens rotate more than
        // necessary" symptom reported live. A retry already in flight
        // (loop running) now makes a second call here a no-op; the loop's
        // own periodic attempts are enough once one is scheduled. Found
        // while porting this function to Desktop and discovering it had
        // the exact same latent gap there.
        if (pendingChannelJobs.containsKey(contact)) return
        scope.launch(Dispatchers.IO) { attemptChannelBootstrap(contact) }
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

    /** "Восстановить связь" — manual, user-triggered courier round. Distinct
     *  from bootstrapChannelFor()/sendAnonTokensTo(): both of those need a
     *  still-valid token FROM the contact (bootstrapChannelFor gives up
     *  early via isChannelReady() the moment ANY local tokens exist, even
     *  stale ones the server no longer recognizes; sendAnonTokensTo needs a
     *  live anon_message channel to send the resupply over in the first
     *  place). If both sides' tokens for each other went stale at the same
     *  time (e.g. one side restored a backup — see AnonTokenManager.
     *  restoreMyTokens()'s fix for the ordinary case, this is the manual
     *  fallback for whatever that doesn't cover), neither side can reach
     *  the other to say so — a deadlock only the mailbox breaks, since it
     *  needs no pre-existing token from either side, just the tag+key each
     *  side already cached locally. Meant to be pressed by BOTH parties
     *  when they suspect delivery has quietly died — deliberately not
     *  gated on isChannelReady() at all, unlike the automatic path. */
    fun forceRestoreConnection(contact: String) {
        // Found live 2026-08-30 (reverted a same-day "fix"): tried gating
        // deleteSession()/session_reset behind !hasSession(contact) to dodge
        // an offline-peer race (see git history/old comment here). That broke
        // the button's actual job. hasSession(contact) only reflects OUR OWN
        // ratchet state — it says nothing about whether the CONTACT's cached
        // copy of OUR PQ key is fresh, which is exactly the thing this
        // session_reset packet exists to fix (see the "session_reset" handler
        // below: it clears the SENDER's cached PQ key and refetches). In the
        // common case — a session already naturally exists on both sides —
        // that gate meant forceRestoreConnection sent nothing at all,
        // silently no-opped, while the user kept pressing a button that did
        // nothing. Worse, the receiving handler unconditionally deletes ITS
        // session and waits for our session_init the moment it gets a
        // session_reset — if we don't ALSO delete ours and stay ready to
        // reinitiate, they wait forever for a session_init we never send,
        // believing (per the skipped gate) that everything's fine. This is a
        // deliberate, user-initiated "something's broken, force a resync"
        // action, not silent background automation — occasionally losing one
        // message already in flight from an offline peer is an acceptable
        // cost next to the button simply not working.
        SessionKeyManager.deleteSession(contact)
        // Found live 2026-08-30, same asymmetry as the "session_reset" handler
        // below: sending session_reset to the contact only fixes THEIR cached
        // copy of OUR PQ-KEM key (once they process it). It does nothing about
        // OUR OWN cached copy of THEIR key, which is just as likely to be stale
        // if they're the one who reinstalled. Without this, pressing the button
        // on only one side leaves that side's own outgoing sends broken even
        // after the other side's handler runs.
        publicKeysPq.remove(contact)
        ChatStorage.clearContactPqPublicKey(this, contact)
        requestPrekeyBundle(contact)
        val mailboxTag = AnonTokenManager.getContactMailboxTag(this, contact)
        val publicKey = publicKeys[contact] ?: ChatStorage.getContactPublicKey(this, contact)
        if (mailboxTag == null || publicKey == null) {
            Log.w(TAG, "forceRestoreConnection: нет mailbox-тега/ключа для $contact — восстановление невозможно")
            return
        }
        pendingChannelJobs[contact]?.cancel()
        pendingChannelJobs[contact] = scope.launch(Dispatchers.IO) {
            // Fixed, short retry burst (not indefinite like bootstrapChannelFor's
            // loop) — this is a deliberate one-off user action bounded by its
            // own cooldown, not a background condition to keep polling forever.
            // One batch minted up front and resent for all three attempts
            // (found live 2026-08-31 — see depositTokensViaMailbox()'s
            // presetTokens comment): these are retries of the SAME deposit,
            // not three independent ones, so they shouldn't each mint their
            // own fresh tokens and triple the pool pressure on a single
            // button press.
            val batch = AnonTokenManager.freshTokensToShare(this@MessengerService)
            for (d in longArrayOf(0L, 30_000L, 90_000L)) {
                delay(d)
                depositTokensViaMailbox(contact, mailboxTag, publicKey, presetTokens = batch)
            }
            pendingChannelJobs.remove(contact)
        }
        // Best-effort direct attempt too, in case only ONE side's channel is
        // actually broken (not the mutual-deadlock case above) — costs
        // nothing extra if it silently fails to deliver. Unconditional, same
        // reasoning as deleteSession() above: this packet's real job is
        // telling the CONTACT to refresh their cached copy of our PQ key —
        // that has nothing to do with whether our own session already works.
        if (isConnected) {
            sendAnonOrDirect(contact, JSONObject().apply {
                put("type", "session_reset")
                put("from", username)
                put("to", contact)
            })
        }
    }

    private fun markChannelReady(contact: String) {
        pendingChannelJobs.remove(contact)?.cancel()
        channelBootstrapStartedAt.remove(contact)
        channelStuckNotified.remove(contact)
    }

    private suspend fun sendAnonTokensTo(contact: String, isReply: Boolean = false) {
        // Guard against a race with connect()'s own handshake wait: this is
        // reachable via queuePendingAnon()'s fire-and-forget bootstrap launch,
        // which fires precisely when sendAnonOrDirect() just found !isConnected
        // — i.e. exactly the case where the raw WebSocket object can already be
        // non-null (assigned early in connect()) while the app-level auth
        // handshake hasn't completed yet. Without this check, sendWs() below
        // would still succeed at the OkHttp layer and send anon_message/
        // subscribe_tokens before the server ever saw our challenge_response,
        // which the server treats as a protocol violation and disconnects for
        // — found live 2026-08-28 via server log "[SECURITY] Ожидался
        // challenge_response, получен anon_message", costing the full 15s
        // handshake timeout before reconnecting and silently losing whatever
        // was queued.
        if (!isConnected) return
        if (!anonTokenResupplyInFlight.add(contact)) {
            Log.d(TAG, "sendAnonTokensTo: уже выполняется для $contact, пропускаем дубликат")
            return
        }
        try {
            sendAnonTokensToLocked(contact, isReply)
        } finally {
            anonTokenResupplyInFlight.remove(contact)
        }
    }

    private suspend fun sendAnonTokensToLocked(contact: String, isReply: Boolean) {
        // freshTokensToShare(), not tokensToShareWith() — see its comment.
        // This function IS the "contact needs tokens now" moment (proactive
        // low-pool warning, or a direct reactive reply) — reusing whatever's
        // sitting in the existing pool risks resharing values the contact
        // already marked spent, which can never actually resupply them
        // (found live 2026-08-29: both sides stuck reoffering the same dead
        // batch to each other forever).
        val tokens = AnonTokenManager.freshTokensToShare(this@MessengerService)
        if (tokens.isEmpty()) return
        AnonTokenManager.recordTokensGivenTo(this@MessengerService, contact, tokens)

        val recipientKey = publicKeys[contact]
            ?: ChatStorage.getContactPublicKey(this@MessengerService, contact)?.also { publicKeys[contact] = it }
        val recipientPqKey = resolvePqKey(contact)

        // anon_message requires a hybrid (classical+PQ) encryption key for the recipient.
        // A brand-new contact whose channel was established purely via mailbox (no
        // X3DH/prekey-bundle exchange has happened yet) won't have a cached PQ key —
        // checked BEFORE consuming an anon token below, so a doomed send doesn't burn
        // one for nothing. Falls back to mailbox, which only needs the classical key.
        if (recipientPqKey == null) {
            val mailboxTag = AnonTokenManager.getContactMailboxTag(this@MessengerService, contact)
            if (mailboxTag != null && recipientKey != null) {
                Log.d(TAG, "sendAnonTokensTo: нет PQ-ключа для $contact — бутстрап токенов через mailbox")
                depositTokensViaMailbox(contact, mailboxTag, recipientKey, isReply = isReply)
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
                depositTokensViaMailbox(contact, mailboxTag, recipientKey, isReply = isReply)
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
        // "reply" marks this batch as a direct answer to a resupply we just
        // received from `contact`, not a fresh request — the receiving side's
        // handler uses this to decide whether to reciprocate again. Without
        // it, an unconditional reciprocal send on receipt (see the two
        // "reply=true" call sites below) would ping-pong forever: A sends,
        // B receives and replies, A receives the reply and replies again, ...
        val tokenPayload = JSONObject().apply {
            put("tokens", org.json.JSONArray(tokens))
            put("mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag(this@MessengerService))
            put("reply", isReply)
        }
        val systemText = "__beacon_tokens__:$tokenPayload"
        val encrypted = CryptoManager.encrypt(systemText, recipientKey, recipientPqKey)
        val signature = CryptoManager.sign(encrypted)
        val packetId = UUID.randomUUID().toString()
        val payload = JSONObject().apply {
            put("type", "message")
            put("from", username)
            put("to", contact)
            put("text", encrypted)
            put("signature", signature)
            put("id", packetId)
            put("protocol_version", 1)
        }
        // Sealed, like every other anon_message (SECURITY.md item 31). Found
        // 2026-11-03: this path was the one exception, and item 31 actively
        // claimed otherwise -- it says the fix was applied to
        // sendAnonOrDirect()/sendWithForwardSecrecy() "the same mechanism
        // sendAnonTokensTo() already used for __beacon_tokens__", which was
        // false. This function only ever encrypted the `text` FIELD (above)
        // and left from/to as plain strings beside the token, i.e. exactly
        // the artifact item 31 exists to remove: a readable from->to pair in
        // server memory during the token_to_ws lookup.
        //
        // The marginal leak was small (this send deliberately goes out on the
        // identified socket per item 32(d), and the token's owner is in
        // anon_token_state anyway), but it made the social-graph edge a
        // single readable object instead of something requiring correlation,
        // so any payload capture, crash dump or compelled memory read yielded
        // it directly.
        //
        // No receive-side change needed: the anon_delivery handler already
        // selects sealed vs legacy purely on the presence of "blob",
        // independent of which socket delivered it. Same new->old
        // compatibility break item 31 already documents and accepts.
        val sealed = sealPacketForRecipient(contact, payload)
        if (sealed == null) {
            // Same fallback this function already uses when the recipient's
            // PQ key isn't cached (see the recipientPqKey check above):
            // mailbox, which encrypts the whole inner structure anyway and
            // was never affected by item 31's gap. Deliberately NOT falling
            // back to the unsealed shape -- that would silently reinstate the
            // leak this change closes, the same "fallback that quietly
            // weakens a security property" pattern already removed twice in
            // this file (sendOnAnonChannelNow, freshTokensToShare).
            val mailboxTag = AnonTokenManager.getContactMailboxTag(this@MessengerService, contact)
            if (mailboxTag != null) {
                Log.i(TAG, "sendAnonTokensTo: не удалось запечатать пакет для $contact — отправляю через mailbox")
                depositTokensViaMailbox(contact, mailboxTag, recipientKey, isReply = isReply)
            } else {
                Log.w(TAG, "sendAnonTokensTo: не удалось запечатать пакет для $contact и нет mailbox-тега — пропускаю")
            }
            return
        }
        val anonPacket = JSONObject().apply {
            put("type", "anon_message")
            put("token", anonToken)
            put("payload", JSONObject().apply {
                put("id", packetId)
                put("blob", sealed)
            })
        }
        // subscribe_tokens sent BEFORE the anon_message that hands these
        // tokens to the contact, not after — found live 2026-08-29 via
        // server-side DEVLOG-DIAG: "is_known=False" drops on a token that
        // was freshly generated and shared moments earlier. The old order
        // shared the tokens with the contact first and only registered them
        // with the server afterward — on a fast connection the contact
        // could receive the batch and reply with one of them before this
        // device's own subscribe_tokens had reached/been processed by the
        // server, and the server correctly has no idea what that token is
        // yet. A single WebSocket connection preserves send order, so
        // sending subscribe_tokens first guarantees the server has already
        // registered every token before the contact could possibly have
        // received (let alone used) any of them.
        val allMyTokens = AnonTokenManager.tokensToSubscribe(this@MessengerService)
        Log.d(TAG, "DEBUG-TOKENLIFE sendAnonTokensTo($contact): re-subscribe_tokens (${allMyTokens.size}) — ${allMyTokens.map { "…${it.takeLast(6)}" }}")
        sendSubscribeTokens(allMyTokens)

        // Deliberately NOT sendAnonMessageWs() here, unlike
        // sendWithForwardSecrecy()/sendAnonOrDirect() — see the ordering
        // comment right above: this anon_message must land on the server
        // strictly after the subscribe_tokens a few lines up, and that
        // guarantee only holds because both currently go out on the SAME
        // WebSocket (single-connection send order is preserved; there's no
        // such guarantee across two separate sockets). Moving just this send
        // to the anon_channel would silently reopen the exact
        // "is_known=False" race fixed 2026-08-29.
        //
        // Restore-on-failure DISABLED here too — see sendAnonOrDirect()'s
        // matching comment, docs/ISSUE_backup_identity_hijack.md, 2026-08-18.
        if (!sendWs(addPadding(anonPacket).toString())) {
            // AnonTokenManager.restoreContactToken(this@MessengerService, contact, anonToken)
        }
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
                // Direct reciprocal answer, no cooldown: this is a response to an
                // explicit signal from `from` ("I'm low, here's a top-up"), not a
                // proactive guess — see sendAnonTokensTo()'s "reply" comment for
                // why isReply=true here is what stops this from looping forever.
                val isReplyBatch = objAttempt?.optBoolean("reply", false) ?: false
                if (!isReplyBatch) {
                    scope.launch(Dispatchers.IO) { sendAnonTokensTo(from, isReply = true) }
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
        // Disappearing-message countdown must start on RECEIPT for incoming
        // messages too, mirroring ChatScreen.kt's send-side stamp — otherwise
        // a peer's message only ever disappears on THEIR device, never on
        // ours, defeating the point of a synced timer. Was missing entirely
        // (on both platforms) before this fix.
        val disappearSecs = ChatStorage.getDisappearTimer(this@MessengerService, UserStorage.getUserId(this@MessengerService), from)
        val expiresAt = if (disappearSecs > 0L) System.currentTimeMillis() + disappearSecs * 1000L else 0L
        ChatStorage.saveOrUpdateMessage(
            this@MessengerService,
            UserStorage.getUserId(this@MessengerService),
            from,
            ChatStorage.StoredMessage(id = messageId ?: UUID.randomUUID().toString(), text = decryptedText, isOwn = false, expiresAt = expiresAt)
        )
        ChatStorage.addContact(this@MessengerService, from)
        Log.i(TAG, "ПОЛУЧЕНО message ${messageId ?: "?"} ← $from @ ${System.currentTimeMillis()}")

        if (messageId != null) {
            Log.i(TAG, "ОТПРАВЛЯЮ квитанцию delivered id=$messageId → $from @ ${System.currentTimeMillis()}")
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

                // freshTokensToShare(), not tokensToShareWith() — see its comment.
                val myTokens = AnonTokenManager.freshTokensToShare(this@MessengerService)
                AnonTokenManager.recordTokensGivenTo(this@MessengerService, to, myTokens)
                // subscribe_tokens BEFORE the mailbox deposit — same ordering
                // fix as depositTokensViaMailbox()/sendAnonTokensToLocked().
                val allMyTokens = AnonTokenManager.tokensToSubscribe(this@MessengerService)
                sendSubscribeTokens(allMyTokens)
                val inner = JSONObject().apply {
                    put("from", username)
                    put("text", text)
                    put("tokens", org.json.JSONArray(myTokens))
                    put("id", id)
                }
                // End-to-end identity signature — see mailboxTranscript()'s
                // own comment.
                inner.put("signature", CryptoManager.sign(mailboxTranscript(inner)))
                val blob = CryptoManager.encryptClassicalOnly(inner.toString(), publicKey)
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
        // Local-only block check (Sealed Sender follow-up, 2026-08-29) —
        // deliberately the very first thing, before ANY side effect. Found
        // live: this function used to save the sender's public key
        // (ChatStorage.saveContactPublicKey), establish a new
        // forward-secrecy session (SessionKeyManager.receiveSession), and
        // fetch a prekey bundle — all BEFORE handleIncomingDecryptedMessage()
        // finally checked isMutuallyAdded() and dropped the message content.
        // A deleted/blocked contact could still make this device do all of
        // that real work even though nothing would ever be shown. See
        // ChatStorage.blockContact() for why this is a local-only check,
        // never reported to the server.
        if (ChatStorage.isBlocked(this@MessengerService, from)) {
            Log.d(TAG, "session_init от $from проигнорирован — контакт заблокирован")
            return
        }
        val senderIk = json.getString("sender_ik")
        val x3dhHeader = json.getJSONObject("x3dh_header")
        val encryptedText = json.getString("text")
        val signature = json.optString("signature", null)
        val messageId = json.optString("id", null)

        val fixedSenderIk = senderIk.replace('-', '+').replace('_', '/')

        // Authentication — deliberately OUTSIDE the recovery try/catch
        // below. Found in the 2026-09-13 follow-up to the cross-platform
        // session_init audit: that catch's generic `catch (e: Exception)`
        // always calls sendSessionResetDebounced(from) before rethrowing —
        // and SecurityException IS an Exception. With the fingerprint/
        // signature checks INSIDE that try (as they were immediately after
        // the first fix), an attacker who can route ANY session_init here
        // could set `from` to a victim's fingerprint, fail authentication
        // (correctly, no session got established under the victim's
        // identity) — but still trigger sendSessionResetDebounced(victim):
        // deleting this device's real, healthy session with that victim
        // and sending them a genuine, validly-signed session_reset. Zero
        // proof of owning the victim's fingerprint was needed for that
        // disruptive side effect, only for `from` to name it — a pure
        // availability attack, repeatable against any contact at will.
        // Desktop already had this ordering right; this brings Android to
        // match. Same canonical computation as the account identity's own
        // fingerprint (SHA-256(DER)[:8], uppercase hex) and as
        // SessionKeyManager.initiateSession()'s S6-46 check for the
        // equivalent outbound case.
        val senderIkBytes = try {
            android.util.Base64.decode(fixedSenderIk, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            throw SecurityException("session_init: sender_ik не является валидным Base64 от $from")
        }
        val actualFingerprint = java.security.MessageDigest.getInstance("SHA-256")
            .digest(senderIkBytes).take(8).joinToString("") { "%02X".format(it) }
        if (actualFingerprint != from) {
            Log.e(TAG, "session_init: sender_ik не соответствует заявленному from=$from (реальный=$actualFingerprint)")
            throw SecurityException("session_init: identity key does not match claimed from=$from")
        }
        if (signature == null) {
            // Was a silent `return` (external review 2026-08-23): the
            // caller (anon_delivery handler) only skips anon_delivery_ack
            // if handleMessage() throws -- a plain return let a session_init
            // rejected for a missing signature still get ACKed as if
            // processed, which tells the server to discard its
            // token_pending fallback copy. A tampered/malformed
            // session_init would then never get retried. Thrown instead —
            // and, as of this fix, thrown from OUTSIDE the recovery
            // try/catch below, so it can never trigger
            // sendSessionResetDebounced() either.
            Log.e(TAG, "session_init без подписи от $from")
            throw SecurityException("session_init без подписи от $from")
        }
        if (!CryptoManager.verify(encryptedText, signature, fixedSenderIk)) {
            Log.e(TAG, "Неверная подпись session_init от $from")
            throw SecurityException("Неверная подпись session_init от $from")
        }

        try {
            // ONLY AFTER both the fingerprint binding AND signature checks
            // above have already passed — a changed/unbound key must never
            // be recorded or trusted before both checks pass, and (as of
            // this fix) an authentication failure can never reach this
            // try/catch's sendSessionResetDebounced() at all.
            if (KeyHistoryManager.checkKeyChange(this@MessengerService, from, fixedSenderIk)) {
                Log.w(TAG, "TOFU: ключ контакта $from изменился в session_init!")
                withContext(Dispatchers.Main) { onKeyChanged?.invoke(from) }
            }
            publicKeys[from] = fixedSenderIk
            ChatStorage.saveContactPublicKey(this@MessengerService, from, fixedSenderIk)
            Log.d(TAG, "Публичный ключ из session_init сохранён: $from")

            SessionKeyManager.receiveSession(from, fixedSenderIk, x3dhHeader)
            val sessionHeader = json.getJSONObject("session_header")
            val decryptedText = CryptoManager.decryptWithForwardSecrecy(from, encryptedText, sessionHeader)
            handleIncomingDecryptedMessage(from, decryptedText, messageId, json)

            // shouldResupplyTokens() gate added (external review 2026-08-23) -- see
            // the matching fix at the "message" handler above for why.
            if (AnonTokenManager.getContactTokens(this@MessengerService, from).isEmpty() &&
                AnonTokenManager.getMyTokens(this@MessengerService).isNotEmpty() &&
                shouldResupplyTokens(from)) {
                scope.launch(Dispatchers.IO) { sendAnonTokensTo(from) }
            }

            // session_init's x3dh_header only ever carries a PQ KEM
            // ciphertext encapsulated against OUR public key (see
            // SessionKeyManager.initiateSession) — the sender's own PQ
            // public key is never in it, there's nothing to extract here.
            // Without this, the receiving side of a brand new contact had
            // no PQ key cached until it happened to need one later (reply
            // via sendEncrypted, a reaction, group-key distribution),
            // paying a full prekey-bundle round-trip right when the user
            // was waiting on it. Fetch proactively instead, right when the
            // channel opens. Root-caused live 2026-08-16.
            if (resolvePqKey(from) == null) {
                requestPrekeyBundle(from)
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

            sendSessionResetDebounced(from)
            // Re-thrown — same reasoning as the "message" case's catch
            // block: this is literally yesterday's "OPK N уже использован"
            // failure mode. Without this, handleMessage() (called from the
            // anon_delivery handler) would return "cleanly" and send
            // anon_delivery_ack even though the session was never actually
            // established — the server's token_pending fallback would get
            // discarded, and the sender's message would never get retried
            // once the session_reset above actually gets things back in
            // sync. See docs/ISSUE_backup_identity_hijack.md.
            throw e
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
                }
                // End-to-end identity signature over the whole envelope,
                // including the nested session_init_packet (its own
                // internal signature — verified separately by
                // processSessionInit() — is just data from this transcript's
                // point of view; recursion in mailboxTranscript()/
                // canonicalizeValue() covers it with no special-casing).
                // See mailboxTranscript()'s own comment.
                inner.put("signature", CryptoManager.sign(mailboxTranscript(inner)))
                val blob = CryptoManager.encryptClassicalOnly(inner.toString(), publicKey)
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

                    // CRITICAL, before any mutation (found in the 2026-09-13
                    // mailbox-authentication audit): decryptClassicalOnly()
                    // only proves this device could read the blob — it's a
                    // recipient-encrypted (ephemeral-ECDH) scheme, anyone who
                    // knows this device's public key (freely shared via
                    // invite codes) can encrypt one, so it proves NOTHING
                    // about who actually sent it. The mutual-add spam gate
                    // right below only proves this device once redeemed
                    // SOME invite code claiming to be `from` — not that
                    // THIS blob's real sender holds that fingerprint's
                    // private key. Without an end-to-end signature, anyone
                    // could forge a blob claiming to be any already-added
                    // contact and have its tokens/session_init/message
                    // trusted and displayed as if genuinely from them.
                    // Resolves the sender's key from THIS device's own
                    // long-term TOFU cache (never from anything embedded in
                    // the packet, and never sender_cert, which belongs to a
                    // separate, unrelated mechanism) — by the time the
                    // mutual-add gate below could ever pass, both sides
                    // already exchanged invite codes, which themselves are
                    // self-signed and verified (InviteCodeManager), so a
                    // legitimate sender's key is always already cached here.
                    // No unsigned-legacy fallback: this ships as one
                    // coordinated fix on both platforms, not a staged
                    // migration.
                    val senderKey = publicKeys[from] ?: ChatStorage.getContactPublicKey(this@MessengerService, from)
                    val mailboxSig = innerJson.optString("signature", null)
                    if (senderKey == null) {
                        Log.w(TAG, "mailbox: депозит от $from отклонён — нет доверенного ключа для проверки подписи")
                        continue
                    }
                    if (mailboxSig == null || !CryptoManager.verify(mailboxTranscript(innerJson), mailboxSig, senderKey)) {
                        Log.e(TAG, "mailbox: депозит от $from отклонён — неверная или отсутствующая подпись")
                        continue
                    }

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
                        // Same direct-reciprocal-no-cooldown logic as the anon_message
                        // beacon_tokens path above — mailbox-delivered batches carry
                        // the same "reply" flag.
                        val isReplyBatch = innerJson.optBoolean("reply", false)
                        if (!isReplyBatch) {
                            scope.launch(Dispatchers.IO) { sendAnonTokensTo(from, isReply = true) }
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
                        // Same disappearing-message receive-side stamp as the
                        // direct/anon_channel text path above — this is the
                        // mailbox-deposit delivery path.
                        val disappearSecs = ChatStorage.getDisappearTimer(this@MessengerService, UserStorage.getUserId(this@MessengerService), from)
                        val expiresAt = if (disappearSecs > 0L) System.currentTimeMillis() + disappearSecs * 1000L else 0L
                        ChatStorage.saveOrUpdateMessage(
                            this@MessengerService,
                            UserStorage.getUserId(this@MessengerService),
                            from,
                            ChatStorage.StoredMessage(id = storedId, text = text, isOwn = false, expiresAt = expiresAt)
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

            nm.deleteNotificationChannel(CHANNEL_ID_SILENT)
            val silentChannel = NotificationChannel(CHANNEL_ID_SILENT, "Subrosa (без звука)", NotificationManager.IMPORTANCE_HIGH).apply {
                description = s.notifChannelDesc
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setShowBadge(true)
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
            }
            nm.createNotificationChannel(silentChannel)

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

            // Same silent, badge-less, no-sound notification as above —
            // only the importance level differs, which is what actually
            // controls whether it gets a status bar icon.
            val serviceChannelVisible = NotificationChannel(
                CHANNEL_ID_SERVICE_VISIBLE,
                "Subrosa Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Фоновый сервис Subrosa"
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
                setShowBadge(false)
            }
            nm.createNotificationChannel(serviceChannelVisible)
        }
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pending = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        val visible = UserStorage.isServiceNotificationVisible(this)
        val channelId = if (visible) CHANNEL_ID_SERVICE_VISIBLE else CHANNEL_ID_SERVICE
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("Subrosa Messenger")
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pending)
            .setSilent(true)
            .setPriority(if (visible) NotificationCompat.PRIORITY_LOW else NotificationCompat.PRIORITY_MIN)
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
        if (UserStorage.getContactMuteUntil(this, from) > System.currentTimeMillis()) return
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
        val channelId = if (UserStorage.getContactMuteSound(this, from)) CHANNEL_ID_SILENT else CHANNEL_ID
        val builder = NotificationCompat.Builder(this, channelId)
            .setContentTitle(if (hideContent) s.notifNewMessage else fromName)
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
                    .setBigContentTitle(fromName)
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
            .setContentTitle(if (hideContent) s.notifNewMessage else channelName)
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
        if (UserStorage.getGroupMuteUntil(this, groupId) > System.currentTimeMillis()) return
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
        val channelId = if (UserStorage.getGroupMuteSound(this, groupId)) CHANNEL_ID_SILENT else CHANNEL_ID
        val builder = NotificationCompat.Builder(this, channelId)
            .setContentTitle(if (hideContent) s.notifNewGroupMessage else groupName)
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
                    .setBigContentTitle(groupName)
                    .setSummaryText(s.notifMessageCount(lines.size))
                lines.forEach { style.addLine(it) }
                builder.setStyle(style).setNumber(lines.size)
            }
        }

        getSystemService(NotificationManager::class.java).notify(notifId, builder.build())
    }

    private fun showMissedCallNotification(from: String, displayName: String, isVideo: Boolean) {
        if (UserStorage.getContactMuteUntil(this, from) > System.currentTimeMillis()) return
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("open_chat", from)
        }
        val pending = PendingIntent.getActivity(
            this, ("missed_$from").hashCode(),
            intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val label = if (isVideo) s.notifMissedVideoCall else s.notifMissedCall
        val notifId = (from.hashCode() and 0x7FFFFFFF) + 3000
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(label)
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

    /** (Re)sends a group_create invite for [groupId] to [memberId], built
     *  fresh from the group's CURRENT persisted state (not a snapshot from
     *  whenever the invite was first attempted — a member could have joined/
     *  left since). Shared by createGroup()'s initial fan-out,
     *  addGroupMember()'s own invite, and flushPendingGroupInvites()'s
     *  bootstrap retry, so a delayed invite is byte-identical in shape to an
     *  immediate one. Returns false (nothing sent) if memberId's EC/PQ key
     *  still isn't cached — caller is responsible for queuing a retry via
     *  pendingGroupInvites + requestPrekeyBundle(memberId) in that case. */
    private fun sendGroupInviteTo(groupId: String, memberId: String): Boolean {
        val group = GroupManager.getGroup(this, groupId) ?: return false
        val groupKey = group.groupKey ?: return false
        val memberPublicKey = publicKeys[memberId]
            ?: ChatStorage.getContactPublicKey(this, memberId)?.also { publicKeys[memberId] = it }
        val memberPqKey = resolvePqKey(memberId)
        if (memberPublicKey == null || memberPqKey == null) return false

        val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, memberPublicKey, memberPqKey)
        val signature = CryptoManager.sign(groupCreatePayload(groupId, group.name, group.avatar, encryptedGroupKey))
        val rosterSignature = CryptoManager.sign(rosterPayload(groupId, group.members, group.admins))
        val memberKeyEntries = group.members.mapNotNull { buildMemberKeyEntry(it) }
        val memberKeysArray = JSONArray(memberKeyEntries)
        val memberKeysSignature = CryptoManager.sign(memberKeysPayload(groupId, memberKeyEntries))

        sendAnonOrDirect(memberId, JSONObject().apply {
            put("type", "group_create")
            put("from", username)
            put("to", memberId)
            put("group_id", groupId)
            put("group_name", group.name)
            put("group_avatar", group.avatar)
            put("encrypted_group_key", encryptedGroupKey)
            put("signature", signature)
            put("members", JSONArray(group.members))
            put("admins", JSONArray(group.admins))
            put("roster_signature", rosterSignature)
            put("member_keys", memberKeysArray)
            put("member_keys_signature", memberKeysSignature)
        })
        Log.d(TAG, "Приглашение в группу ${group.name} отправлено для $memberId")
        return true
    }

    /** Queues [groupId]'s invite for [memberId] to be (re)sent once their
     *  EC/PQ key arrives, and kicks off the fetch. Call this instead of
     *  silently dropping an invite whenever sendGroupInviteTo() returns
     *  false. */
    private fun queueGroupInviteRetry(groupId: String, memberId: String) {
        Log.w(TAG, "Нет ключа для $memberId — приглашение в группу отложено, запрашиваю prekey bundle")
        pendingGroupInvites.getOrPut(memberId) { mutableSetOf() }.add(groupId)
        requestPrekeyBundle(memberId)
    }

    /** Drains and (re)sends every group invite queued for [contactId] —
     *  called from handleFetchedPrekeyBundle() alongside its other
     *  flushPendingXxx() calls, once that contact's key is actually
     *  available. A groupId that still fails (key fetch raced with the
     *  group being deleted, or some other transient issue) is re-queued
     *  rather than dropped, symmetric with the other pending queues below. */
    private fun flushPendingGroupInvites(contactId: String) {
        val groupIds = pendingGroupInvites.remove(contactId) ?: return
        groupIds.forEach { groupId ->
            if (!sendGroupInviteTo(groupId, contactId)) {
                pendingGroupInvites.getOrPut(contactId) { mutableSetOf() }.add(groupId)
            }
        }
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
                // Bootstrap-and-retry for a member this device has never
                // 1:1-chatted with (a real, common case: someone else
                // introduced this contact, or the admin just added them and
                // immediately created a group before any key exchange could
                // happen) — sendGroupInviteTo() re-derives the roster/
                // member_keys transcript fresh from GroupManager.getGroup()
                // each time, so createGroup() no longer needs its own copy
                // of that computation. Found live 2026-09-21: this used to
                // just log "Нет публичного ключа" and drop the invite
                // forever — the group stayed in this device's own roster
                // (already saved by the caller before this runs), silently
                // desyncing from a member who never learned they'd been
                // invited at all.
                members.forEach { memberId ->
                    if (!sendGroupInviteTo(groupId, memberId)) {
                        queueGroupInviteRetry(groupId, memberId)
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
        members: List<String>,
        replyToId: String? = null
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
                        if (!replyToId.isNullOrBlank()) put("reply_to_id", replyToId)
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
                // Envelope-bound transcript (CODE-03, 2026-11-03). This used
                // to be CryptoManager.sign(emoji) -- a signature over the
                // bare PLAINTEXT emoji, binding nothing else. That made it a
                // universally reusable token: anyone who had ever observed
                // this sender react once, INCLUDING THE SERVER that relays
                // it, could attach that same signature to any message_id in
                // any group_id, any number of times, and it would verify. The
                // signed alphabet is tiny (a handful of emoji), so a lookup
                // table of reusable per-contact signatures was trivial to
                // build from a few observations.
                //
                // Same bug class the project already fixed twice with this
                // exact pattern: voice (SECURITY.md item 70,
                // "SUBROSA_VOICE_V1:$voiceId:$duration:$encryptedData") and
                // message deletion (item 66,
                // "SUBROSA_GROUP_MESSAGE_DELETE_V1:$groupId:$messageId").
                // Reactions were simply never revisited -- an unfinished
                // sweep, not a design decision.
                //
                // Computed once outside the member loop on purpose: groupId
                // and messageId are identical for every recipient, so there
                // is nothing per-member to bind.
                val signature = CryptoManager.sign(
                    "SUBROSA_GROUP_REACTION_V1:$groupId:$messageId:$emoji"
                )
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

    /** Group photo send. Mirrors sendImage()'s own encrypt-then-chunk shape,
     *  but encrypts once with the shared group AES key (GroupManager) instead
     *  of per-recipient hybrid encryption, and — like sendVideoCircle's
     *  video_chunk_batch — bundles CHUNK_BATCH_SIZE chunks into one
     *  anon_message per member per batch. Without batching this would cost
     *  chunks × members single-use tokens, which is exactly the pattern that
     *  drained the pool for unbatched video/ICE sends earlier. */
    fun sendGroupImage(groupId: String, members: List<String>, groupKey: ByteArray, imageBytes: ByteArray) {
        if (!isConnected) return
        val imageId = UUID.randomUUID().toString()
        val recipients = members.filter { it != username }

        scope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Отправка группового изображения (группа: $groupId, ${recipients.size} получателей)")
                val base64Image = android.util.Base64.encodeToString(imageBytes, android.util.Base64.NO_WRAP)
                val encrypted = GroupManager.encryptGroupMessage(base64Image, groupKey)
                val encryptedChunks = encrypted.chunked(120_000)
                Log.d(TAG, "Групповое изображение зашифровано: ${encryptedChunks.size} чанков")

                val CHUNK_BATCH_SIZE = 15
                encryptedChunks.chunked(CHUNK_BATCH_SIZE).forEachIndexed { batchIdx, batch ->
                    val chunksJson = org.json.JSONArray()
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * CHUNK_BATCH_SIZE + relIdx
                        val signature = CryptoManager.signChunk(chunk, imageId, index)
                        chunksJson.put(JSONObject().apply {
                            put("chunk_index", index)
                            put("data", chunk)
                            put("signature", signature)
                        })
                    }
                    recipients.forEach { memberId ->
                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_image_batch")
                            put("from", username)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("image_id", imageId)
                            put("total_chunks", encryptedChunks.size)
                            put("chunks", chunksJson)
                        })
                    }
                    delay(30)
                }

                Log.d(TAG, "Групповое изображение отправлено")
            } catch (e: Exception) {
                Log.e(TAG, "sendGroupImage error: ${e.message}", e)
            }
        }
    }

    /** Group file send — same batched-chunk-per-member-fanout shape as
     *  sendGroupImage(), plus the file name encrypted with the group key
     *  (mirrors sendFile()'s encrypted_file_name privacy fix, docs/
     *  ISSUE_backup_identity_hijack.md's "file_name в открытом виде"). */
    fun sendGroupFile(groupId: String, members: List<String>, groupKey: ByteArray, fileName: String, fileBytes: ByteArray) {
        if (!isConnected) return
        val fileId = UUID.randomUUID().toString()
        val recipients = members.filter { it != username }

        scope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Отправка группового файла: $fileName (группа: $groupId, ${recipients.size} получателей)")
                val base64File = android.util.Base64.encodeToString(fileBytes, android.util.Base64.NO_WRAP)
                val encrypted = GroupManager.encryptGroupMessage(base64File, groupKey)
                val encryptedFileName = GroupManager.encryptGroupMessage(fileName, groupKey)
                val encryptedChunks = encrypted.chunked(120_000)
                Log.d(TAG, "Групповой файл зашифрован: ${encryptedChunks.size} чанков")

                val CHUNK_BATCH_SIZE = 15
                encryptedChunks.chunked(CHUNK_BATCH_SIZE).forEachIndexed { batchIdx, batch ->
                    val chunksJson = org.json.JSONArray()
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * CHUNK_BATCH_SIZE + relIdx
                        val signature = CryptoManager.signChunk(chunk, fileId, index)
                        chunksJson.put(JSONObject().apply {
                            put("chunk_index", index)
                            put("data", chunk)
                            put("signature", signature)
                        })
                    }
                    recipients.forEach { memberId ->
                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_file_batch")
                            put("from", username)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("file_id", fileId)
                            put("encrypted_file_name", encryptedFileName)
                            put("total_chunks", encryptedChunks.size)
                            put("chunks", chunksJson)
                        })
                    }
                    delay(30)
                }

                Log.d(TAG, "Групповой файл отправлен")
            } catch (e: Exception) {
                Log.e(TAG, "sendGroupFile error: ${e.message}", e)
            }
        }
    }

    /** Group video circle send — same batched-chunk-per-member-fanout shape
     *  as sendGroupImage()/sendGroupFile(), plus a plaintext `duration`
     *  field (mirrors sendVideoCircle()'s own — a clip length isn't
     *  sensitive the way a filename can be, so it doesn't need the group-
     *  key-encrypted treatment sendGroupFile() gives encrypted_file_name).
     *  Group chat previously had no video-circle send path at all — this
     *  and the "group_video_batch" receive handler below are new,
     *  2026-09-21. */
    fun sendGroupVideoCircle(groupId: String, members: List<String>, groupKey: ByteArray, videoBytes: ByteArray, duration: Int) {
        if (!isConnected) return
        val videoId = UUID.randomUUID().toString()
        val recipients = members.filter { it != username }

        scope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Отправка группового видео-кружка (группа: $groupId, ${recipients.size} получателей)")
                val base64Video = android.util.Base64.encodeToString(videoBytes, android.util.Base64.NO_WRAP)
                val encrypted = GroupManager.encryptGroupMessage(base64Video, groupKey)
                val encryptedChunks = encrypted.chunked(120_000)
                Log.d(TAG, "Групповое видео зашифровано: ${encryptedChunks.size} чанков")

                val CHUNK_BATCH_SIZE = 15
                encryptedChunks.chunked(CHUNK_BATCH_SIZE).forEachIndexed { batchIdx, batch ->
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
                    recipients.forEach { memberId ->
                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_video_batch")
                            put("from", username)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("video_id", videoId)
                            put("duration", duration)
                            put("total_chunks", encryptedChunks.size)
                            put("chunks", chunksJson)
                        })
                    }
                    delay(30)
                }

                Log.d(TAG, "Групповое видео отправлено")
            } catch (e: Exception) {
                Log.e(TAG, "sendGroupVideoCircle error: ${e.message}", e)
            }
        }
    }

    /** Group photo avatar — one-shot base64 like 1:1's own avatar_update
     *  (ProfileScreen.kt applyCroppedAvatar()), not chunked like image/file/
     *  video (a 128x128 JPEG at q85 comfortably fits in one message), but
     *  encrypted with the shared group AES key and fanned out per-member
     *  like every other group send, since the server has no concept of
     *  group membership to relay through (unlike 1:1 avatars, which the
     *  server pushes to online contacts on its own — see
     *  apply_avatar_mutation() in server.py). Admin-only: enforced on
     *  receive, not here (this device already checked before calling).
     *  Group chat previously had no way to set a photo avatar at all — only
     *  a 32-emoji picker. New 2026-09-21. */
    fun sendGroupAvatarUpdate(groupId: String, members: List<String>, groupKey: ByteArray, avatarBase64: String) {
        if (!isConnected) return
        val recipients = members.filter { it != username }

        scope.launch(Dispatchers.IO) {
            try {
                val encrypted = GroupManager.encryptGroupMessage(avatarBase64, groupKey)
                val signature = CryptoManager.sign(encrypted)
                recipients.forEach { memberId ->
                    sendAnonOrDirect(memberId, JSONObject().apply {
                        put("type", "group_avatar_update")
                        put("from", username)
                        put("to", memberId)
                        put("group_id", groupId)
                        put("avatar", encrypted)
                        put("signature", signature)
                    })
                }
                Log.d(TAG, "Аватар группы отправлен (группа: $groupId)")
            } catch (e: Exception) {
                Log.e(TAG, "sendGroupAvatarUpdate error: ${e.message}", e)
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
                // Same bootstrap-and-retry as createGroup() — see
                // sendGroupInviteTo()'s own comment. Was signing the bare
                // encryptedGroupKey before the S6-64 hardening (see git
                // history) which broke this call site's invitation until
                // that was fixed 2026-09-13; sendGroupInviteTo() now builds
                // the exact same groupCreatePayload()-bound transcript
                // createGroup() does, so the two can never drift apart
                // again.
                if (!sendGroupInviteTo(groupId, newMemberId)) {
                    queueGroupInviteRetry(groupId, newMemberId)
                }

                // Existing members previously never learned about the new
                // member at all — see docs/ISSUE_backup_identity_hijack.md,
                // group roster fix. Symmetric to notifyMemberRemoved() below.
                // Also now carries the new member's own key/name (single
                // entry, same member_keys shape as group_create) so existing
                // members can actually verify signed frames FROM the new
                // member (e.g. a group call join), not just learn their
                // fingerprint/display name.
                val addSignature = CryptoManager.sign("$groupId:add:$newMemberId")
                val newMemberKeyEntry = buildMemberKeyEntry(newMemberId)
                val newMemberKeysArray = JSONArray(listOfNotNull(newMemberKeyEntry))
                val newMemberKeysSignature = CryptoManager.sign(memberKeysPayload(groupId, listOfNotNull(newMemberKeyEntry)))
                allMembers.filter { it != username && it != newMemberId }.forEach { memberId ->
                    sendAnonOrDirect(memberId, JSONObject().apply {
                        put("type", "group_member_added")
                        put("from", username)
                        put("to", memberId)
                        put("group_id", groupId)
                        put("new_member", newMemberId)
                        put("new_member_name", newMemberName)
                        put("signature", addSignature)
                        put("member_keys", newMemberKeysArray)
                        put("member_keys_signature", newMemberKeysSignature)
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

                    val memberPqKey = resolvePqKey(memberId)
                    if (memberPublicKey != null && memberPqKey != null) {
                        val encryptedNewKey = GroupManager.encryptGroupKeyForMember(newGroupKey, memberPublicKey, memberPqKey)
                        // groupId bound into the signed payload (external
                        // review 2026-08-28, CRYPTO-06) -- it wasn't before,
                        // and encrypted_new_key decrypts using only the
                        // recipient's own identity key (not anything group-
                        // specific), so a signature over encrypted_new_key
                        // alone doesn't stop a malicious server from
                        // relabeling a real, validly-signed rotation for
                        // group X as being for group Y (if the same admin
                        // sends both and the recipient is in both groups) --
                        // the recipient would then silently overwrite group
                        // Y's real key with what was actually group X's.
                        val signature = CryptoManager.sign("$groupId:$encryptedNewKey")

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
                    .setContentTitle("Приглашение в группу")
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
