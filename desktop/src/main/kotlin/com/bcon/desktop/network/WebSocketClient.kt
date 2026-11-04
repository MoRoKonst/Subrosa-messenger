package com.subrosa.desktop

/**
 * Desktop equivalent of Android's MessengerService.
 *
 * Protocol notes (from server.py):
 *   1. Server sends "challenge"
 *   2. Client responds with "challenge_response" containing public_key + signature
 *   3. Server sends "handshake_ok"
 *   4. Client sends "register" with name, public_key, device_id
 *      → server derives username from SHA-256 fingerprint of public key
 *   5. Normal messaging (to/from = fingerprint IDs)
 */

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.*
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit

object WebSocketClient {

    // ── Connection state (Compose-observable) ─────────────────────────────────
    private val _connected = MutableStateFlow(false)
    val connected: StateFlow<Boolean> = _connected

    // ── Callbacks (set by UI) ─────────────────────────────────────────────────
    var onMessageReceived:   ((from: String, text: String, id: String, replyToId: String?) -> Unit)? = null
    var onImageReceived:     ((from: String, imageBytes: ByteArray, geoCoords: String?, id: String) -> Unit)? = null
    // durationSec: 0 for ordinary files (no concept of duration); the
    // actual recorded duration for a voice message (VoiceRecorder.FILE_NAME
    // sentinel) — the wire protocol already carried this in "voice"'s own
    // frame (used for the signature transcript + range validation below)
    // but it was discarded right before reaching the UI, so ChatScreen.kt
    // had no way to persist/display it. Found live, 2026-09-18.
    var onFileReceived:      ((from: String, fileId: String, fileName: String, bytes: ByteArray, durationSec: Int, id: String) -> Unit)? = null
    // Video circle (Telegram-style round video message) — ported from
    // Android's VideoCircleScreen/onVideoReceived. Separate from
    // onFileReceived (unlike voice, which reuses it via the FILE_NAME
    // sentinel) because the bubble UI is genuinely different (circular
    // thumbnail, no filename/generic-file chrome). file is a decrypted,
    // already-muxed MP4 on disk. Found live, 2026-09-18.
    var onVideoReceived:     ((from: String, videoId: String, file: java.io.File, durationSec: Int) -> Unit)? = null
    var onStatusChanged:     ((connected: Boolean) -> Unit)? = null
    var onTypingReceived:    ((from: String) -> Unit)? = null
    var onReadReceived:      ((msgId: String) -> Unit)? = null
    var onDeliveredReceived: ((msgId: String) -> Unit)? = null
    var onEditReceived:      ((msgId: String, newText: String) -> Unit)? = null
    var onMessageDeleted:    ((from: String, msgId: String) -> Unit)? = null
    var onReactionReceived:  ((from: String, msgId: String, emoji: String) -> Unit)? = null
    var onDisappearTimerChanged: ((from: String, seconds: Long) -> Unit)? = null
    var onKeyChanged:        ((fingerprint: String) -> Unit)? = null
    // Fired when a fetched prekey bundle is marked "revoked" by the server —
    // mirrors Android's onContactRevoked (MessengerService.kt), same field
    // though the bundle itself still parses fine.
    var onContactRevoked:    ((fingerprint: String) -> Unit)? = null
    var onGroupInviteReceived: ((group: Group, encryptedGroupKey: String) -> Unit)? = null
    var onGroupMessageReceived: ((groupId: String, message: GroupMessage) -> Unit)? = null
    var onGroupMessageDeleted:  ((groupId: String, messageId: String) -> Unit)? = null
    var onGroupReactionReceived: ((groupId: String, from: String, messageId: String, emoji: String) -> Unit)? = null
    // Mirror Android's onGroupImageReceived/onGroupFileReceived shape —
    // persistence (GroupManager.saveGroupMessage) already happened before
    // this fires, same "don't depend on which screen is mounted" pattern as
    // onImageReceived/onFileReceived above.
    var onGroupImageReceived: ((groupId: String, from: String, id: String, file: java.io.File) -> Unit)? = null
    var onGroupFileReceived:  ((groupId: String, from: String, id: String, file: java.io.File, fileName: String) -> Unit)? = null
    var onGroupAvatarUpdated: ((groupId: String) -> Unit)? = null
    var onChannelCreated:      ((Channel) -> Unit)? = null
    var onChannelPostReceived: ((channelId: String, ChannelPost) -> Unit)? = null
    var onChannelPostDeleted:  ((channelId: String, postId: String) -> Unit)? = null
    var onChannelDeleted:      ((channelId: String) -> Unit)? = null
    // Fired when removeMember() deleted the local group record entirely
    // (this device was the one removed) — mirrors onChannelDeleted's shape
    // exactly, so ChatsScreen's already-established "remove from the list"
    // pattern for channels applies unchanged to groups.
    var onGroupDeleted:        ((groupId: String) -> Unit)? = null
    var onChannelError:       ((reason: String) -> Unit)? = null
    var onTotpSetupResult:    ((success: Boolean, reason: String?, recoveryCodes: List<String>?) -> Unit)? = null
    var onTotpDisableResult:  ((success: Boolean) -> Unit)? = null
    // Fired when the server rejects register() with totp_required — this
    // device has no usable TOTP code (fresh backup restore, no authenticator
    // saved locally). See submitRecoveryCode().
    var onTotpRequired:       (() -> Unit)? = null
    @Volatile private var pendingRecoveryCode: String? = null

    // ── Internals ─────────────────────────────────────────────────────────────
    private const val DEFAULT_SERVER_URL = NetworkConfig.DEFAULT_WS_URL
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var webSocket: WebSocket? = null
    @Volatile private var isConnecting = false
    @Volatile private var userDisconnected = false   // true only when WE called disconnect()
    @Volatile private var handshakeDone = false
    private var reconnectAttempts = 0
    private var displayName = ""    // human-readable name (sent as "name" in register)

    // PoW retry state (S6-45-adjacent gap — server.py's MAX_POW_NONCE_LEN
    // comment used to read "both clients that implement PoW (Android;
    // Desktop doesn't yet send pow_nonce at all)"). Mirrors Android's
    // MessengerService.kt lastChallengeBytes/lastRegisterPacket: remembered
    // so the "pow_required" handler can resend the exact same register
    // packet with a pow_nonce added, without redoing recovery_code/
    // access_code/totp_code gathering (some of those are one-shot).
    private var lastChallengeBytes: ByteArray? = null
    private var lastRegisterPacket: JSONObject? = null

    // Registration-completion gate (mirrors Android's MessengerService.kt
    // myRegistrationReady/S6-40) — Desktop used to fire ALL post-register
    // startup traffic (publishPrekeyBundle/subscribe_tokens/etc.) immediately
    // after SENDING "register", without ever waiting to see whether the
    // server actually accepted it. On a server with POW_DIFFICULTY_BITS
    // configured (the default), that startup traffic reaches the server
    // BEFORE registration completes and gets rejected + the connection
    // closed ("... до успешной регистрации — закрываю"), on an infinite
    // reconnect loop — registration never has a chance to actually finish.
    // Created fresh in connect() before the async connection attempt starts,
    // so it always exists before any server message referencing it can
    // possibly arrive.
    @Volatile private var registrationReady: CompletableDeferred<Boolean>? = null

    // Image chunk reassembly
    private val imageChunks = mutableMapOf<String, MutableMap<Int, String>>()
    private val imageTotals = mutableMapOf<String, Int>()
    private val imageGeos   = mutableMapOf<String, String?>()

    // File chunk reassembly (generic, non-image files)
    private val fileChunks = mutableMapOf<String, MutableMap<Int, String>>()

    // Video circle chunk reassembly — separate maps from fileChunks/
    // imageChunks (unlike Android, which shares its imageChunks/imageTotals
    // between image_chunk AND video_chunk via a "$from:$id" transferKey).
    // Kept independent here for clarity; the shared admission-cap machinery
    // (pruneAndAdmitTransfer/accountChunkBytes) is generic enough to take
    // any of these maps.
    private val videoChunks = mutableMapOf<String, MutableMap<Int, String>>()
    private val videoTotals = mutableMapOf<String, Int>()
    private val videoTouchedAt = mutableMapOf<String, Long>()
    private val videoReceivedBytes = mutableMapOf<String, Long>()
    private val videoDurations = mutableMapOf<String, Int>()

    // S6-49 (external review 2026-09-05, mirrors the Android fix) --
    // receive-side chunk assembly had no bounds at all: chunk_index/
    // total_chunks came straight from JSON with no range validation, and
    // imageChunks/fileChunks grew one entry per distinct transfer id with
    // no cap on simultaneous transfers and no expiry for an abandoned one.
    // Server-side envelope limits (server.py's MEDIA_CHUNK_*, same fix)
    // bound TRAFFIC; these bound this device's own memory regardless of
    // what produced the traffic.
    private val MEDIA_CHUNK_MAX_TOTAL_CHUNKS = 20_000
    private val MEDIA_CHUNK_MAX_CONCURRENT_TRANSFERS = 20
    private val MEDIA_CHUNK_TRANSFER_TIMEOUT_MS = 5 * 60 * 1000L
    private val imageTouchedAt = mutableMapOf<String, Long>()
    private val fileTouchedAt  = mutableMapOf<String, Long>()

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
    private val MEDIA_CHUNK_DATA_MAX_LEN  = 130_000
    private val MEDIA_TRANSFER_MAX_BYTES  = 64L * 1024 * 1024

    // S6-53 (external review 2026-09-06) -- client-side defense-in-depth for
    // message_delete/group_message_delete (mirrors server.py's
    // CHAT_CONTROL_ID_MAX_LEN). Desktop's sendDelete()/sendGroupDeleteMessage()
    // never produce a signature at all (unlike Android) -- see this patch's
    // own report of that as a SEPARATE authorization gap, not fixed here --
    // so this length bound is the only check standing between a compromised
    // server (or a malicious contact, given the missing signature) and an
    // oversized id reaching GroupManager/ChatStorage.
    private val CHAT_CONTROL_ID_MAX_LEN = 128
    // Mirrors Android's MessengerService.CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED
    // and server.py's CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED exactly: off / 1h /
    // 24h / 7d — the only 4 values ChatScreen's disappear dialog offers. A
    // genuinely-authenticated malicious contact can still produce a validly-
    // signed disappear_timer over ANY seconds value (signature proves origin,
    // not protocol sanity), so incoming values are checked against this exact
    // set before setDisappearTimer()'s downstream expiry-timestamp math.
    private val CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED = setOf(0L, 3600L, 86400L, 604800L)
    private val imageReceivedBytes = mutableMapOf<String, Long>()
    private val fileReceivedBytes  = mutableMapOf<String, Long>()

    /** Lazily sweeps any transfer idle past MEDIA_CHUNK_TRANSFER_TIMEOUT_MS
     *  out of [map]/[touchedAt] (self-pruning, no background timer needed),
     *  then admits [transferKey] only if it's already tracked or there's
     *  room under MEDIA_CHUNK_MAX_CONCURRENT_TRANSFERS. [receivedBytes] is
     *  swept for the same stale keys (S6-49 follow-up) -- otherwise an
     *  abandoned transfer evicted here purely by a LATER unrelated
     *  transfer's admission check would leave its byte-accounting entry
     *  behind forever, since it's only cleared at a handler's own explicit
     *  cancel/complete points, which an abandoned transfer never reaches. */
    private fun <V> pruneAndAdmitTransfer(
        map: MutableMap<String, V>,
        touchedAt: MutableMap<String, Long>,
        transferKey: String,
        receivedBytes: MutableMap<String, Long>,
    ): Boolean {
        val now = System.currentTimeMillis()
        val stale = touchedAt.filterValues { now - it > MEDIA_CHUNK_TRANSFER_TIMEOUT_MS }.keys
        for (key in stale) {
            map.remove(key)
            touchedAt.remove(key)
            receivedBytes.remove(key)
        }
        if (!map.containsKey(transferKey) && map.size >= MEDIA_CHUNK_MAX_CONCURRENT_TRANSFERS) {
            return false
        }
        touchedAt[transferKey] = now
        return true
    }

    /** chunkData is base64 (ASCII-only alphabet), so String.length is already
     *  its exact byte size -- no separate decode needed just to account it.
     *  A repeated index replaces its prior contribution (delta accounting)
     *  rather than adding on top of it, so idempotent re-delivery of the same
     *  index can never inflate the running total. Returns false (transfer
     *  must be cancelled, not partially admitted) if applying this chunk
     *  would push the transfer over MEDIA_TRANSFER_MAX_BYTES. */
    private fun accountChunkBytes(
        chunks: MutableMap<Int, String>,
        receivedBytes: MutableMap<String, Long>,
        transferKey: String,
        chunkIndex: Int,
        chunkData: String,
    ): Boolean {
        val chunkBytes = chunkData.length.toLong()
        val prevBytes = chunks[chunkIndex]?.length?.toLong() ?: 0L
        val projected = (receivedBytes[transferKey] ?: 0L) - prevBytes + chunkBytes
        if (projected > MEDIA_TRANSFER_MAX_BYTES) return false
        receivedBytes[transferKey] = projected
        return true
    }

    // Queued by sendAnonOrDirect() when a contact's anon-token pool is empty —
    // see the "cut the direct fallback" decision in
    // docs/ISSUE_backup_identity_hijack.md. Drained by flushPendingAnon()
    // once fresh tokens arrive for that contact.
    private val pendingAnonPackets = mutableMapOf<String, MutableList<JSONObject>>()
    // Cooldown for the queue-triggered sendAnonTokensTo() call in
    // sendAnonOrDirect() below — see that call site's own comment.
    private val lastTokenBootstrapAttempt = mutableMapOf<String, Long>()

    // Mirrors Android's MessengerService.ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE
    // exactly (S6-66 follow-up, external review 2026-09-09) — see its own
    // comment for the full reasoning: these types carry no signature of
    // their own and previously relied on a sender_cert requirement whose
    // trust anchor (a per-server signing-key pin) doesn't universally exist
    // across arbitrary self-hosted servers. Replaced with an end-to-end
    // identity signature instead.
    private val ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE = setOf(
        "session_reset", "pq_bundle_refresh", "contact_ping", "contact_pong",
        "call_offer", "call_answer", "call_ice", "call_end", "call_ringing",
        "call_ice_restart", "call_response", "call_request_audio", "call_request_video",
        "call_group_invite", "call_group_join", "call_group_answer",
        "call_group_ice", "call_group_leave", "call_group_peer_list",
    )

    // Mirrors Android's MessengerService.CONTROL_ENVELOPE_EXCLUDED_KEYS /
    // controlEnvelopeTranscript()/canonicalizeValue() exactly — see their
    // own comments, including the recursive-canonicalization follow-up
    // (never trust JSONObject/JSONArray iteration order at any nesting
    // depth — Android's built-in org.json and this platform's standalone
    // org.json jar are independent implementations with no documented
    // ordering guarantee).
    private val CONTROL_ENVELOPE_EXCLUDED_KEYS = setOf("signature", "sender_cert", "sender_cert_sig")

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
     *  mirrors Android's MessengerService.mailboxTranscript() exactly. Found
     *  in the 2026-09-13 mailbox-authentication audit: this payload is only
     *  ever RECIPIENT-encrypted (CryptoManager.encryptClassicalOnly(), an
     *  ephemeral-ECDH scheme anyone who knows the recipient's public key can
     *  encrypt to), never sender-authenticated. handleMailboxResult() trusted
     *  the embedded "from" field after decryption purely on the strength of
     *  the mutual-add spam gate — which proves this device once redeemed
     *  SOMEONE's invite code under that name, not that THIS blob's actual
     *  sender holds that fingerprint's private key. Reuses the exact same
     *  recursive canonicalizeValue() as controlEnvelopeTranscript() above,
     *  with a DIFFERENT domain prefix so a signature over one can never be
     *  replayed as the other. Only "signature" itself is excluded — mailbox
     *  inner payloads never carry a sender_cert. Generic over whatever keys
     *  are actually present rather than a hand-picked field list — recursion
     *  already covers a nested session_init_packet with no special-casing
     *  needed. */
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

    private val fileTotals = mutableMapOf<String, Int>()
    private val fileNames  = mutableMapOf<String, String>()

    // Replay dedup: msgId → receive timestamp
    private val receivedIds = HashMap<String, Long>()
    private const val REPLAY_WINDOW_MS = 60 * 60 * 1000L

    // S6-57 (external review 2026-09-06) -- client-side defense-in-depth for
    // "voice": the server now bounds voice_data/signature/voice_id/duration
    // (server.py's VOICE_DATA_MAX_LEN/VOICE_SIGNATURE_MAX_LEN/
    // MAX_VOICE_DURATION_SECONDS), but a compromised/malicious server could
    // still hand this device an arbitrary frame directly. Checked BEFORE
    // CryptoManager.verify()/decrypt()/Base64.decode()/AudioTranscoder.toWav()
    // ever run. Numbers mirror the server's own derivation exactly -- see
    // VOICE_DATA_MAX_LEN's own comment in server.py for the full byte-math;
    // Desktop's OWN uncompressed 16kHz/16-bit WAV codec is the dominant/
    // worst case these numbers are actually sized against.
    private const val MAX_VOICE_DURATION_SECONDS = 60
    private const val VOICE_WIRE_MAX_LEN = 4 * 1024 * 1024          // wire voice_data (base64 ciphertext)
    private const val VOICE_SIGNATURE_MAX_LEN = 256                 // mirrors server's own bound
    private const val VOICE_ID_MAX_LEN = 64                         // canonical UUID (36 chars) + headroom
    // Post-decrypt bound -- CryptoManager.decrypt()'s OUTPUT is the base64-
    // encoded audio string. ~3 MiB gives headroom above this client's own
    // worst-case ~2.56 MiB (32,000 bytes/sec * 60s * 4/3 base64 expansion).
    private const val VOICE_MAX_DECRYPTED_B64_LEN = 3 * 1024 * 1024
    // Post-base64-decode bound -- the actual raw WAV byte count handed to
    // AudioTranscoder.toWav(). ~2.5 MiB gives headroom above this client's
    // own worst-case ~1.92 MiB (32,000 bytes/sec * 60s).
    private const val VOICE_MAX_DECODED_AUDIO_BYTES = (2.5 * 1024 * 1024).toInt()

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
    // Mirrors Android's MessengerService.kt constant of the same name.
    private const val ANON_DELIVERY_BLOB_MAX_LEN = 6 * 1024 * 1024

    // Peer public keys for legacy encryption: fingerprint → Base64 X.509 pubkey
    private val peerPublicKeys = mutableMapOf<String, String>()
    // Peer ML-KEM public keys, sourced from prekey bundles — required to
    // hybridize the legacy ephemeral-ECDH path (encrypt/decrypt, group key
    // distribution) against harvest-now-decrypt-later, same as the X3DH path.
    private val peerPqPublicKeys = mutableMapOf<String, ByteArray>()
    // Pending prekey bundles received from server: fingerprint → bundle
    private val pendingBundles = mutableMapOf<String, SessionKeyManager.PrekeyBundle>()
    // Messages queued while waiting for a peer prekey bundle
    private data class QueuedMessage(val text: String, val msgId: String)
    private val messageQueue    = mutableMapOf<String, MutableList<QueuedMessage>>()
    // Fingerprints we've already sent get_prekey_bundle for (avoid duplicates)
    private val bundleRequested = mutableSetOf<String>()
    // Separate cooldown from lastTokenBootstrapAttempt above — gates
    // requestBundleFor() specifically (server-side "prekey_fetch", 10/min
    // PER ACCOUNT). bundleRequested alone only dedupes a CONCURRENT in-flight
    // request; it's cleared the moment a (possibly null) response arrives, so
    // a contact whose bundle is still unpublished server-side got a fresh
    // get_prekey_bundle on every later trigger with zero delay — one per
    // queued send. Mirrors Android's MessengerService lastPrekeyFetchAttempt
    // fix, same root cause. Found live 2026-09-18.
    private val lastPrekeyFetchAttempt = mutableMapOf<String, Long>()
    // Debounce state for sendSessionResetDebounced() — see its own comment.
    private val lastSessionResetSentAt = mutableMapOf<String, Long>()
    // Bootstrap tokens the server attached to a fetched bundle (see
    // requestPrekeyBundlesBatch / prekey_bundle_response) — consumed once,
    // by the session_init that follows, to deliver it anonymously.
    private val pendingBootstrapTokens = mutableMapOf<String, String>()
    // groupIds waiting on a member's key to arrive before their group_create
    // invite can be sent — mirrors Android's identical fix. See
    // sendGroupInviteTo()/flushPendingGroupInvites(). Found live 2026-09-21:
    // createGroup()/addGroupMember() used to silently drop the invite for a
    // member this device had never 1:1-chatted with (no cached key yet) —
    // the group was still saved locally with them in the roster, so the
    // admin's own UI showed them as a member who never actually joined.
    private val pendingGroupInvites = mutableMapOf<String, MutableSet<String>>()

    // sendImage/sendFile require BOTH peerPublicKeys AND peerPqPublicKeys cached —
    // a one-shot hybrid encrypt, not the session-based Double Ratchet text uses.
    // Previously these just logged and gave up with no retry at all if the PQ key
    // wasn't cached yet (mirrors the same gap found and fixed in Android's
    // MessengerService.kt — see SECURITY.md item for the live incident). Queuing
    // here and flushing once a bundle response arrives closes that gap.
    private data class PendingImage(val to: String, val rawBytes: ByteArray, val geo: String?)
    private val pendingImages = mutableListOf<PendingImage>()
    private data class PendingFileSend(val to: String, val fileName: String, val rawBytes: ByteArray)
    private val pendingFileSends = mutableListOf<PendingFileSend>()
    private data class PendingVoiceSend(val to: String, val voiceBase64: String, val voiceId: String, val duration: Int)
    private val pendingVoiceSends = mutableListOf<PendingVoiceSend>()
    // Mirrors Android's PendingVideoCircle exactly (MessengerService.kt) —
    // rawBytes kept in memory (video circles are capped at MAX_SECONDS,
    // typically a few MB) rather than re-reading from disk on flush, unlike
    // Android's encFilePath approach; simpler given Desktop's queue is only
    // ever flushed within the same process lifetime (never restored across
    // a restart).
    private data class PendingVideoSend(val to: String, val videoId: String, val rawBytes: ByteArray, val duration: Int)
    private val pendingVideoSends = mutableListOf<PendingVideoSend>()

    // ── Anonymous routing (port of Android's AnonTokenManager/sendAnonOrDirect) ─
    // Cover-traffic queue only gates traffic sent via sendWs() below (the anon-
    // routing paths); protocol/handshake sends (challenge_response, register,
    // ack, get_key, ...) go straight to the socket as before — mirroring their
    // treatment on Android would require rerouting ~20 unrelated call sites for
    // no anonymity benefit (they don't carry a "to" fingerprint anyway).
    private val outboundQueue = java.util.concurrent.LinkedBlockingQueue<String>(200)
    // AGGRESSIVE-mode pacing for anon_channel traffic specifically — see
    // sendOnAnonChannel()/startCoverTraffic(). Separate from outboundQueue
    // (main socket, non-anon traffic) since the two go out over different
    // sockets and must be paced independently. Mirrors Android's
    // MessengerService.kt (desktop/Android symmetry audit, 2026-09-03).
    private val anonOutboundQueue = java.util.concurrent.LinkedBlockingQueue<String>(200)
    // Holds anon_message frames while anonWebSocket isn't ready yet.
    // Deliberately NOT drained to the identified main socket as a fallback
    // — a fallback that silently degrades a security property is worse
    // than making the caller wait. Flushed only once anon_channel_ok
    // actually arrives.
    private val anonChannelPendingQueue = java.util.concurrent.LinkedBlockingQueue<String>(200)
    private var coverTrafficJob: Job? = null

    // ── Sealed Sender — identity-less second connection ────────────────────────
    private var anonWebSocket: WebSocket? = null
    @Volatile private var anonChannelReady = false
    @Volatile private var anonChannelConnecting = false
    private var anonChannelLastAttemptMs = 0L
    // Was a Set<String> ("resupply this contact's token allocation at most
    // once ever per process lifetime") — mirrors Android's MessengerService.kt
    // fix, same live incident: a burst of usage can drain a contact's 20-token
    // allocation well within one process lifetime, and the one-time gate left
    // them permanently stuck until a restart. Cooldown instead of "never again".
    private val tokensSentThisSession = mutableMapOf<String, Long>()
    private val TOKEN_RESUPPLY_COOLDOWN_MS = 3 * 60_000L

    private fun shouldResupplyTokens(contact: String): Boolean {
        val now = System.currentTimeMillis()
        val last = tokensSentThisSession[contact] ?: 0L
        if (now - last < TOKEN_RESUPPLY_COOLDOWN_MS) return false
        tokensSentThisSession[contact] = now
        return true
    }

    private fun sendWs(json: String) {
        val mode = UserStorage.getCoverTrafficMode()
        if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE && _connected.value) {
            if (!outboundQueue.offer(json)) {
                System.err.println("WebSocketClient: outboundQueue full — sending directly")
                webSocket?.send(json)
            }
        } else {
            webSocket?.send(json)
        }
    }

    /** Sends [tokens] as one or more "subscribe_tokens" messages, each capped
     *  at server.py's own MAX_TOKENS_PER_SUBSCRIBE (100) — mirrors Android's
     *  identical fix (MessengerService.kt sendSubscribeTokens()), see its own
     *  comment for the full root-cause writeup. AnonTokenManager.tokensToSubscribe()
     *  (pool capped at 100, PLUS ack-pending on top with no combined cap)
     *  routinely exceeds 100, and the server silently truncates a call over
     *  that limit rather than erroring — permanently dropping whatever token
     *  fell past index 100, typically the OLDEST ones since freshTokensToShare()
     *  always prepends new tokens. Found live 2026-09-20 via a real
     *  cross-device call-then-chat session (client log showed subscribe_tokens
     *  with 101 tokens in one call). */
    private fun sendSubscribeTokens(tokens: List<String>) {
        if (tokens.isEmpty()) return
        tokens.chunked(100).forEach { chunk ->
            sendWs(JSONObject().apply {
                put("type", "subscribe_tokens")
                put("tokens", JSONArray(chunk))
            }.toString())
        }
    }

    /** Re-applies the current cover-traffic setting immediately, without waiting
     *  for a reconnect. Call this right after changing the setting in the UI —
     *  otherwise a mode switched on mid-session queues packets nobody polls yet,
     *  and a mode switched off mid-session keeps sending noise regardless. */
    fun applyCoverTrafficModeChange() {
        if (_connected.value) startCoverTraffic()
    }

    private fun startCoverTraffic() {
        coverTrafficJob?.cancel()
        val mode = UserStorage.getCoverTrafficMode()
        if (mode == UserStorage.CoverTrafficMode.OFF) return
        val intervalMs = if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE) 1_000L else 5_000L
        coverTrafficJob = scope.launch {
            val rng = java.security.SecureRandom()
            while (isActive) {
                kotlinx.coroutines.delay(intervalMs)
                if (!_connected.value) continue

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
                // must send directly rather than re-queue. Mirrors Android's
                // MessengerService.kt (desktop/Android symmetry audit,
                // 2026-09-03).
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
                            put("d", Base64.getEncoder().encodeToString(
                                ByteArray(rng.nextInt(180) + 76).also { rng.nextBytes(it) }
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

    /** Wraps [packet] in one more layer of hybrid (classical+PQ) encryption
     *  keyed to [to]'s identity, so from/to/text sit encrypted inside the
     *  anon_message payload instead of in the clear next to the token —
     *  server.py's anon_message routing only ever needs the token, never
     *  the payload contents. Embeds our own cached sender_cert if we have
     *  one, so the recipient (not the server) can verify who really sent
     *  this. Ported from Android's MessengerService.sealPacketForRecipient()
     *  (desktop/Android symmetry audit, 2026-09-03) — see
     *  docs/PROTOCOL_STATE_MACHINE.md and SECURITY_INVARIANTS.md #5.
     *
     *  Returns null if the recipient's keys aren't cached yet — callers
     *  fall back to the old unsealed shape rather than losing the send. */
    private fun sealPacketForRecipient(to: String, packet: JSONObject): String? {
        val recipientKey = peerPublicKeys[to] ?: DesktopCryptoManager.getPeerPublicKey(to)
        val recipientPqKey = peerPqPublicKeys[to]
        if (recipientKey == null || recipientPqKey == null) return null
        return try {
            // Copy, not an in-place mutation — callers reuse the original
            // packet as the unsealed fallback if this returns null.
            val enriched = JSONObject(packet.toString())
            SenderCertManager.getFresh()?.let { (cert, signature) ->
                enriched.put("sender_cert", cert)
                enriched.put("sender_cert_sig", signature)
            }
            CryptoManager.encrypt(enriched.toString(), recipientKey, recipientPqKey)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: sealPacketForRecipient: failed to seal for $to — ${e.message}")
            null
        }
    }

    /** Sends [packet] (which must carry a "to" field) anonymously by token if
     *  one is available for that contact. No direct/fingerprint-addressed
     *  fallback on purpose — see the "cut the direct fallback" decision in
     *  docs/ISSUE_backup_identity_hijack.md; mirrors Android's
     *  MessengerService.sendAnonOrDirect(). When no token is available, the
     *  packet is queued and a token refill/mailbox bootstrap is kicked off
     *  instead of sending in the clear. */
    private fun sendAnonOrDirect(to: String, packet: JSONObject) {
        // These types carry no per-message signature of their own (S6-66
        // follow-up) — mirrors Android's own fix exactly, see
        // ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE's own comment. The
        // device's own long-term identity key is always available
        // immediately, no async cert fetch/queue needed.
        if (packet.optString("type") in ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE) {
            packet.put("signature", CryptoManager.sign(controlEnvelopeTranscript(packet)))
        }
        // Don't even try to consume a token for a connection we already know
        // is down — mirrors Android's sendAnonOrDirect() ordering exactly
        // (2026-09-03 audit): consumeNextContactToken() permanently burns a
        // single-use token the instant it's called, regardless of whether
        // the send that follows ever reaches the server.
        if (!_connected.value) {
            queuePendingAnon(to, packet)
            return
        }
        // Seal FIRST, before touching the token pool at all — mirrors
        // Android exactly. Was: consume token -> try seal -> if seal failed,
        // send the UNSEALED packet anyway (fail-open: a from/to/text triple
        // reaching the server in the clear whenever sealing couldn't find a
        // key). Rule: if a packet must go through the anonymous/sealed path,
        // seal -> consume -> send, never canSeal -> consume -> seal, and
        // never fall back to an unsealed send. Found in the 2026-09-13
        // full-logic audit.
        val sealed = sealPacketForRecipient(to, packet)
        if (sealed == null) {
            queuePendingAnon(to, packet)
            requestBundleFor(to)
            return
        }
        val token = AnonTokenManager.consumeNextContactToken(to)
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
            if (!sent) {
                // Token restore intentionally NOT attempted — mirrors
                // Android's matching comment: sendWs()==false isn't a
                // reliable enough signal that the frame never reached the
                // server to safely reuse a single-use token; a token
                // confirmed delivered once and handed out again is worse
                // than one simply lost. The packet itself is still queued
                // and retried (with a freshly consumed token next time).
                // Previously this return value was discarded entirely.
                queuePendingAnon(to, packet)
                return
            }
            // Proactive early-warning refill, centralized here so every
            // sendAnonOrDirect caller (images, files, reactions, typing...)
            // gets it — mirrors Android's MessengerService.kt fix. Previously
            // only sendTyping() checked this, and only after its own send.
            if (AnonTokenManager.needsRefill(to) && shouldResupplyTokens(to)) {
                scope.launch { sendAnonTokensTo(to) }
            }
        } else {
            queuePendingAnon(to, packet)
        }
    }

    /** Queues [packet] for [to] and opportunistically (re)bootstraps the
     *  channel — shared by every sendAnonOrDirect() failure branch (not
     *  connected, seal failed, no token, send failed). Cooldown-gated, NOT
     *  unconditional — sendAnonTokensTo() re-subscribes the ENTIRE "my own"
     *  token pool (~100 tokens) on every call, not just the newly-shared
     *  batch. Calling it with zero throttle on every single queued packet
     *  was confirmed live to blow through server.py's subscribe_tokens rate
     *  limit (10/60s) during a genuinely active 1:1 exchange — typing +
     *  message + read + delivered each consume one of the contact's granted
     *  tokens, re-entering this branch every few seconds. The server closed
     *  the connection with "Rate limit exceeded", forcing a full reconnect
     *  before messaging could resume — the "takes about a minute to
     *  reconnect" symptom reported live, 2026-09-13. Mirrors the same fix
     *  applied to Android's queuePendingAnon(). */
    private fun queuePendingAnon(to: String, packet: JSONObject) {
        synchronized(pendingAnonPackets) {
            pendingAnonPackets.getOrPut(to) { mutableListOf() }.add(packet)
        }
        val shouldBootstrap = synchronized(lastTokenBootstrapAttempt) {
            val now = System.currentTimeMillis()
            val last = lastTokenBootstrapAttempt[to] ?: 0L
            if (now - last >= 30_000L) {
                lastTokenBootstrapAttempt[to] = now
                true
            } else false
        }
        if (shouldBootstrap) {
            scope.launch { sendAnonTokensTo(to) }
        }
        // Was previously a single one-shot attempt with nothing else ever
        // scheduled to retry — if that one sendAnonTokensTo() call itself
        // failed to resolve anything (e.g. no PQ key cached yet for `to`, so
        // it fell back to a mailbox deposit that also didn't complete), this
        // packet just sat in pendingAnonPackets forever, with no periodic
        // nudge, unless the contact happened to message back first
        // (flushPendingAnon via received tokens) or the whole app
        // reconnected. Reusing bootstrapChannelFor()'s already-proven,
        // gentler 30s/30s/30s-then-90s cadence here instead of porting
        // Android's flatter retry loop — this is new functionality on
        // Desktop, not a behavior match, so there's no "must mirror
        // Android's cadence too" requirement. isChannelReady()/
        // attemptChannelBootstrap() no-op harmlessly for a contact that
        // doesn't need mailbox bootstrap at all.
        bootstrapChannelFor(to)
    }

    /** Retries everything queued for [to] by sendAnonOrDirect() while its token
     *  pool was empty. Call after AnonTokenManager.addContactTokens(to, ...) —
     *  a no-op if nothing is queued. */
    private fun flushPendingAnon(to: String) {
        val queued = synchronized(pendingAnonPackets) { pendingAnonPackets.remove(to) } ?: return
        queued.forEach { sendAnonOrDirect(to, it) }
    }

    /** Flushes every contact's pendingAnonPackets queue (S6-66) — mirrors
     *  Android's flushAllPendingAnon(); called once a fresh sender_cert
     *  arrives, since a packet queued for that reason could be waiting
     *  under any contact's key, not just one. */
    private fun flushAllPendingAnon() {
        val targets = synchronized(pendingAnonPackets) { pendingAnonPackets.keys.toList() }
        targets.forEach { flushPendingAnon(it) }
    }

    /** Sends [packet] wrapped in anon_message using an externally-supplied
     *  [token] — used for the one-off bootstrap token attached to a fetched
     *  prekey bundle, which is separate from the ordinary per-contact anon
     *  token pool AnonTokenManager/sendAnonOrDirect draws from.
     *
     *  Returns true only if the packet was actually sealed AND handed to
     *  sendAnonMessageWs() successfully — false for every failure mode
     *  (missing `to`, seal failure, definite local send failure). NEVER
     *  sends [packet] unsealed: was fail-open — outerPayload fell back to
     *  the raw inner packet (from/to/session_init fields in the clear via
     *  anon_message) whenever sealPacketForRecipient() returned null.
     *
     *  This function never queues or retries on its own — [token] is
     *  single-use and the caller already consumed it
     *  (pendingBootstrapTokens.remove()) before calling this, regardless of
     *  outcome; retrying with the SAME token would only be safe if we could
     *  prove the frame never left the device, which sendAnonMessageWs()'s
     *  return value doesn't reliably guarantee (same reasoning as
     *  sendAnonOrDirect()'s own "token restore disabled" comment). A false
     *  return means the caller (initiateAndSend()) must fall back to a
     *  FRESH routing token/path — see its own comment. Found in the
     *  2026-09-13 full-logic audit. */
    private fun sendViaToken(token: String, packet: JSONObject): Boolean {
        val to = packet.optString("to", null) ?: return false
        val sealed = sealPacketForRecipient(to, packet) ?: return false
        val outerPayload = JSONObject().apply {
            put("id", packet.optString("id").ifBlank { packet.optString("message_id") })
            put("blob", sealed)
        }
        val anonPacket = JSONObject().apply {
            put("type", "anon_message")
            put("token", token)
            put("payload", outerPayload)
        }
        return sendAnonMessageWs(anonPacket)
    }

    // ── Channel establishment (auto token bootstrap) ────────────────────────────
    // Mirrors Android's MessengerService equivalent — see its comment for the full
    // rationale. A fresh contact can't be messaged anonymously until both sides
    // exchange AnonTokenManager token pools, and that exchange can only be kicked
    // off via mailbox (the one path needing no pre-existing token). Waiting for
    // the user's first typed message to trigger it risks that message falling
    // through to a non-anonymous path. Instead this deposits tokens the moment a
    // contact is added, invisibly, and keeps retrying until confirmed.
    private val pendingChannelJobs = mutableMapOf<String, Job>()
    var onChannelReady: ((contact: String) -> Unit)? = null

    // "Завис ли bootstrap первого контакта" diagnostics — mirrors Android's
    // MessengerService checkChannelStuck()/CHANNEL_STUCK_THRESHOLD_MS. Was
    // missing entirely from Desktop: a first-contact channel that never
    // establishes just retried silently forever with nothing surfaced
    // anywhere the user (who, on Desktop, is very often also the server
    // operator) could grep for. Found in the 2026-09-12 full-logic audit
    // continuation.
    private const val CHANNEL_STUCK_THRESHOLD_MS = 5 * 60 * 1000L
    private val channelBootstrapStartedAt = mutableMapOf<String, Long>()
    private val channelStuckNotified = mutableSetOf<String>()

    /** True once this contact can be messaged anonymously (or wasn't a
     *  mailbox-bootstrapped contact to begin with — e.g. restored from backup). */
    fun isChannelReady(contact: String): Boolean {
        val mailboxTag = AnonTokenManager.getContactMailboxTag(contact) ?: return true
        return AnonTokenManager.getContactTokens(contact).isNotEmpty() || SessionKeyManager.hasSession(contact)
    }

    private fun depositTokensViaMailbox(
        contact: String, mailboxTag: String, publicKey: String, isReply: Boolean = false,
        presetTokens: List<String>? = null
    ) {
        // freshTokensToShare(), not tokensToShareWith() — see its own
        // comment. Guarantees the contact never receives a batch that's
        // already dead from their own perspective (their spent-history
        // filter would just discard it). Was tokensToShareWith() before
        // this fix, reproducing Android's already-fixed 2026-08-29
        // "resupply deadlock" bug. presetTokens (mirrors Android exactly):
        // callers that retry the SAME logical deposit attempt several times
        // (forceRestoreConnection's bounded burst) must resend the SAME
        // batch, not mint a fresh one on every retry — three retries of one
        // button press minting three fresh 20-token batches was the exact
        // live bug Android fixed 2026-08-31.
        // Cooldown gate (found live 2026-09-14, mirrors the fix on Android) —
        // a contact whose bundle never resolves makes EVERY independent
        // trigger that reaches this function (sendAnonTokensToLocked's own
        // "no PQ key"/"no anon token" fallbacks, bootstrapChannelFor()'s
        // 30s/90s retry loop, every incoming message's reactive resupply)
        // take this exact branch, each minting its OWN fresh 20-token batch
        // with no coordination between them. Confirmed live: the same
        // account re-subscribing 100 tokens seconds (sometimes under 50ms)
        // apart, tripping subscribe_tokens's own rate limit and getting the
        // connection closed — which then reconnected and immediately re-hit
        // the same limit resubscribing the full pool again. Skipped for
        // isReply=true (a single reciprocal answer, already one-shot by
        // design) and for an explicit presetTokens override
        // (forceRestoreConnection's deliberate bounded resend of the SAME
        // batch). Reuses the same lastTokenBootstrapAttempt map
        // queuePendingAnon() already applies to sendAnonTokensTo() itself —
        // this closes the gap for every OTHER path that reaches mailbox
        // deposit without going through that gate.
        if (!isReply && presetTokens == null) {
            val shouldAttempt = synchronized(lastTokenBootstrapAttempt) {
                val now = System.currentTimeMillis()
                val last = lastTokenBootstrapAttempt[contact] ?: 0L
                if (now - last >= 30_000L) {
                    lastTokenBootstrapAttempt[contact] = now
                    true
                } else false
            }
            if (!shouldAttempt) {
                println("WebSocketClient: depositTokensViaMailbox: $contact — cooldown active, skipping")
                return
            }
        }
        val tokens = presetTokens ?: AnonTokenManager.freshTokensToShare()
        if (tokens.isEmpty()) return
        AnonTokenManager.recordTokensGivenTo(contact, tokens)
        // subscribe_tokens BEFORE the mailbox deposit — mirrors Android's
        // identical ordering fix (2026-08-29, "is_known=False" race): the
        // contact could receive this deposit and reply with one of these
        // tokens before the server had processed our own subscribe_tokens,
        // at which point the server correctly has no idea what that token
        // is yet. Was entirely missing on Desktop — this function never
        // called subscribe_tokens at all before this fix.
        sendSubscribeTokens(AnonTokenManager.tokensToSubscribe())
        try {
            val inner = JSONObject().apply {
                put("from", myFingerprint)
                put("name", UserStorage.getUsername())
                // Wire-protocol sentinel — MUST match Android's exact string
                // (MessengerService.kt depositTokensViaMailbox()), not a
                // display-facing string. A "__Subrosa_..." rebrand here
                // desynced from Android's "__beacon_..." prefix check on
                // receipt, so each platform showed the other's token-only
                // mailbox deposit as a literal garbage chat message instead
                // of silently consuming it — found live 2026-09-11.
                put("text", "__beacon_tokens_only__")
                put("tokens", JSONArray(tokens))
                // Same tag-freshness piggyback as the anon_message token
                // path — see AnonTokenManager.getOrCreateMyPersistentMailboxTag().
                put("mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag())
                put("reply", isReply)
                put("id", java.util.UUID.randomUUID().toString())
            }
            // End-to-end identity signature over every field above — see
            // mailboxTranscript()'s own comment.
            inner.put("signature", CryptoManager.sign(mailboxTranscript(inner)))
            val blob = CryptoManager.encryptClassicalOnly(inner.toString(), publicKey)
            sendWs(addPadding(JSONObject().apply {
                put("type", "mailbox_put")
                put("tag", mailboxTag)
                put("blob", blob)
            }).toString())
        } catch (e: Exception) {
            System.err.println("WebSocketClient: depositTokensViaMailbox: $contact — ${e.message}")
        }
    }

    private fun attemptChannelBootstrap(contact: String) {
        val mailboxTag = AnonTokenManager.getContactMailboxTag(contact) ?: return
        val publicKey = peerPublicKeys[contact] ?: DesktopCryptoManager.getPeerPublicKey(contact) ?: return
        depositTokensViaMailbox(contact, mailboxTag, publicKey)
    }

    /** Call right after adding a contact (invite-code flow), and again whenever
     *  the user opens a chat with a still-pending contact — safe to call
     *  repeatedly, a retry loop only ever runs once per contact at a time. */
    fun bootstrapChannelFor(contact: String) {
        if (isChannelReady(contact)) return
        // Checked BEFORE the immediate attempt below, not after — this
        // function was written assuming infrequent, discrete callers (add
        // contact, open a chat), so the immediate attempt had no throttle
        // of its own; the pendingChannelJobs guard only stopped a SECOND
        // retry LOOP from starting. Once sendAnonOrDirect() started calling
        // this on every queued packet for a not-yet-ready contact (see its
        // own comment), a burst of queued packets — typing indicator +
        // message + resupply, all within the same send — each fired their
        // own immediate attemptChannelBootstrap(), completely bypassing the
        // loop's own 30s/90s pacing. Confirmed live 2026-09-13: server logs
        // showed the same fingerprint re-subscribing to 100 tokens seconds
        // (sometimes 1-2s) apart, repeatedly. Now a retry already in flight
        // (loop running) makes every subsequent call here a no-op — the
        // loop's own periodic attempts are enough once one is scheduled.
        if (pendingChannelJobs.containsKey(contact)) return
        scope.launch { attemptChannelBootstrap(contact) }
        channelBootstrapStartedAt.putIfAbsent(contact, System.currentTimeMillis())
        pendingChannelJobs[contact] = scope.launch {
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

    /** Fires once per contact, 5 minutes into a first-contact bootstrap that
     *  still hasn't succeeded — mirrors Android's checkChannelStuck()
     *  exactly, minus the OS notification (no equivalent on Desktop; the
     *  server-side log line is the useful part here anyway). Deliberately
     *  carries no contact/target identifier — that would leak exactly the
     *  metadata (who's trying to reach whom) the mailbox scheme exists to
     *  hide. Just "this account hit a stuck first-contact bootstrap". */
    private fun checkChannelStuck(contact: String) {
        if (contact in channelStuckNotified) return
        val startedAt = channelBootstrapStartedAt[contact] ?: return
        if (System.currentTimeMillis() - startedAt < CHANNEL_STUCK_THRESHOLD_MS) return
        channelStuckNotified.add(contact)
        System.err.println("WebSocketClient: bootstrapChannelFor: $contact still not ready after 5 minutes")
        sendWs(JSONObject().apply {
            put("type", "bootstrap_diagnostic")
        }.toString())
    }

    private fun markChannelReady(contact: String) {
        pendingChannelJobs.remove(contact)?.cancel()
        channelBootstrapStartedAt.remove(contact)
        channelStuckNotified.remove(contact)
    }

    /** "Забота о собеседнике" — mirrors Android's checkContactSilence() in
     *  MessengerService.kt / see ContactHealthManager.kt. (1) on first
     *  detected silence, ping — consumes a real token if one exists, or
     *  falls through the existing mailbox-bootstrap cascade if not. (2) if
     *  still silent after a wait with no pong, one explicit mailbox deposit
     *  of a fresh token batch. No third stage — one-off, not a loop. */
    private fun checkContactSilence() {
        ChatStorage.getContacts().forEach { contactId ->
            if (!ContactHealthManager.isSilent(contactId)) return@forEach

            when (ContactHealthManager.getState(contactId)) {
                ContactHealthManager.PingState.NONE -> {
                    sendAnonOrDirect(contactId, JSONObject().apply {
                        put("type", "contact_ping")
                        put("from", myFingerprint)
                        put("to", contactId)
                        put("id", java.util.UUID.randomUUID().toString())
                    })
                    ContactHealthManager.setState(contactId, ContactHealthManager.PingState.PINGED)
                }

                ContactHealthManager.PingState.PINGED -> {
                    if (ContactHealthManager.stateElapsedMs(contactId) < ContactHealthManager.MAILBOX_RETRY_WAIT_MS) {
                        return@forEach
                    }
                    val mailboxTag = AnonTokenManager.getContactMailboxTag(contactId)
                    val recipientKey = peerPublicKeys[contactId] ?: DesktopCryptoManager.getPeerPublicKey(contactId)
                    if (mailboxTag != null && recipientKey != null) {
                        depositTokensViaMailbox(contactId, mailboxTag, recipientKey)
                    }
                    ContactHealthManager.setState(contactId, ContactHealthManager.PingState.MAILBOX_TRIED)
                }

                ContactHealthManager.PingState.MAILBOX_TRIED -> { /* one-off — nothing further until real traffic resumes */ }
            }
        }
    }

    // Guards sendAnonTokensToLocked() against running twice concurrently for
    // the same contact — multiple independent triggers (proactive low-pool
    // refill, the reactive isReply=true response, the queue-triggered
    // bootstrap above) can fire within the same short window, each unaware
    // of the others; without this, each burns a real token (potentially a
    // reserve one) sending a redundant duplicate subscribe_tokens batch the
    // peer just discards. Mirrors Android's anonTokenResupplyInFlight —
    // was missing on Desktop entirely.
    private val anonTokenResupplyInFlight = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    /** Shares our token pool with [contact] via anon_message (or queues until a
     *  token/mailbox path becomes available). Mirrors Android's sendAnonTokensTo().
     *  [isReply] marks this batch as a direct answer to a resupply we just
     *  received from [contact], not a fresh request — the receiving side's
     *  handler (handleDecryptedTextForTokenExchange) uses this to decide
     *  whether to reciprocate again. Without it, an unconditional reciprocal
     *  send on receipt would ping-pong forever: A sends, B receives and
     *  replies, A receives the reply and replies again, ... */
    private fun sendAnonTokensTo(contact: String, isReply: Boolean = false) {
        if (!anonTokenResupplyInFlight.add(contact)) {
            System.err.println("WebSocketClient: sendAnonTokensTo: already running for $contact, skipping duplicate")
            return
        }
        try {
            sendAnonTokensToLocked(contact, isReply)
        } finally {
            anonTokenResupplyInFlight.remove(contact)
        }
    }

    private fun sendAnonTokensToLocked(contact: String, isReply: Boolean = false) {
        // freshTokensToShare(), not tokensToShareWith() — this IS the
        // "contact needs tokens now" moment (proactive low-pool warning, or
        // a direct reactive reply); reusing whatever's sitting in the
        // existing pool risks resharing values the contact already marked
        // spent, which can never actually resupply them (both sides stuck
        // reoffering the same dead batch to each other forever). Was
        // tokensToShareWith() before this fix.
        val tokens = AnonTokenManager.freshTokensToShare()
        if (tokens.isEmpty()) return
        AnonTokenManager.recordTokensGivenTo(contact, tokens)

        val recipientKey = peerPublicKeys[contact] ?: DesktopCryptoManager.getPeerPublicKey(contact)
        val recipientPqKey = peerPqPublicKeys[contact]

        // anon_message requires a hybrid (classical+PQ) encryption key for the recipient.
        // A brand-new contact whose channel was established purely via mailbox (no
        // X3DH/prekey-bundle exchange has happened yet) won't have a cached PQ key —
        // checked BEFORE consuming an anon token below, so a doomed send doesn't burn
        // one for nothing. Falls back to mailbox (needs only the classical key) instead
        // of a direct get_prekey_bundle request, which would leak the target fingerprint
        // to the server — the same anonymity gap mailbox exists to avoid in the first place.
        if (recipientPqKey == null) {
            val mailboxTag = AnonTokenManager.getContactMailboxTag(contact)
            if (mailboxTag != null && recipientKey != null) {
                System.err.println("WebSocketClient: sendAnonTokensTo: no PQ key for $contact — bootstrapping tokens via mailbox")
                depositTokensViaMailbox(contact, mailboxTag, recipientKey)
            } else {
                System.err.println("WebSocketClient: sendAnonTokensTo: no token/keys for $contact yet, waiting for mailbox exchange")
            }
            return
        }

        // allowReserve=true — this IS the resupply message the reserve
        // exists to protect. Every other consumer (sendAnonOrDirect, the
        // ordinary send path) uses the default false. Was missing this
        // parameter entirely before this fix (Desktop's consumeNextContactToken
        // had no allowReserve concept at all).
        val anonToken = AnonTokenManager.consumeNextContactToken(contact, allowReserve = true)
        if (anonToken == null) {
            // Bootstrapping tokens via anon_message is circular: sending my tokens this
            // way requires a token FROM this contact, which they can only ever give me
            // the same way. Fall back to the same mailbox bootstrap used on contact-add.
            val mailboxTag = AnonTokenManager.getContactMailboxTag(contact)
            if (mailboxTag != null && recipientKey != null) {
                System.err.println("WebSocketClient: sendAnonTokensTo: no anon token for $contact — bootstrapping tokens via mailbox")
                depositTokensViaMailbox(contact, mailboxTag, recipientKey)
            } else {
                System.err.println("WebSocketClient: sendAnonTokensTo: no token for $contact yet, waiting for mailbox exchange")
            }
            return
        }
        if (recipientKey == null) {
            System.err.println("WebSocketClient: sendAnonTokensTo: no key for $contact, skipping — will retry on next message")
            return
        }
        // Piggybacks our persistent mailbox tag on every token exchange — see
        // AnonTokenManager.getOrCreateMyPersistentMailboxTag()'s "tag
        // freshness" doc comment. Nearly free: this message already goes out.
        val tokenPayload = JSONObject().apply {
            put("tokens", JSONArray(tokens))
            put("mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag())
            put("reply", isReply)
        }
        val systemText = "__beacon_tokens__:$tokenPayload"
        val encrypted = runCatching { CryptoManager.encrypt(systemText, recipientKey, recipientPqKey) }.getOrNull() ?: return
        val payload = JSONObject().apply {
            put("type", "message")
            put("from", myFingerprint)
            put("to", contact)
            put("text", encrypted)
            put("signature", CryptoManager.sign(encrypted))
            put("id", java.util.UUID.randomUUID().toString())
            put("protocol_version", 1)
        }
        val anonPacket = JSONObject().apply {
            put("type", "anon_message")
            put("token", anonToken)
            put("payload", payload)
        }
        // subscribe_tokens sent BEFORE the anon_message that hands these
        // tokens to the contact, not after — mirrors Android's identical
        // 2026-08-29 ordering fix ("is_known=False" race): on a fast
        // connection the contact could receive this batch and reply with
        // one of them before this device's own subscribe_tokens had
        // reached/been processed by the server, which correctly has no
        // idea what that token is yet. A single WebSocket connection
        // preserves send order, so sending subscribe_tokens first
        // guarantees the server has already registered every token before
        // the contact could possibly have received (let alone used) any of
        // them. Was ordered the wrong way round on Desktop before this fix.
        val allMyTokens = AnonTokenManager.tokensToSubscribe()
        sendSubscribeTokens(allMyTokens)
        sendWs(addPadding(anonPacket).toString())
    }

    /** Handles an incoming decrypted plaintext that might be a token-exchange
     *  system message rather than a real chat message. Returns true if it was
     *  consumed as such (caller should not surface it to the UI). Mirrors
     *  Android's MessengerService.handleIncomingDecryptedMessage()'s
     *  "__beacon_tokens__" branch (desktop/Android symmetry audit,
     *  2026-09-03). */
    private fun handleDecryptedTextForTokenExchange(from: String, decryptedText: String): Boolean {
        if (!decryptedText.startsWith("__beacon_tokens__:")) return false
        try {
            val raw = decryptedText.removePrefix("__beacon_tokens__:")
            // New shape is a JSON object (tokens + mailbox_tag + reply); falls
            // back to the old bare-array shape for an unpatched peer mid-rollout.
            val objAttempt = runCatching { JSONObject(raw) }.getOrNull()
            val tokensArr = objAttempt?.getJSONArray("tokens") ?: JSONArray(raw)
            val tokens = (0 until tokensArr.length()).map { tokensArr.getString(it) }
            val freshTag = objAttempt?.optString("mailbox_tag", null)
            AnonTokenManager.addContactTokens(from, tokens)
            flushPendingAnon(from)

            // Refreshed to the sender's persistent tag instead of cleared —
            // see AnonTokenManager.getOrCreateMyPersistentMailboxTag()'s
            // "tag freshness" doc comment. Without this, getContactMailboxTag(from)
            // goes permanently null after the very first bootstrap.
            if (freshTag != null) {
                AnonTokenManager.setContactMailboxTag(from, freshTag)
            } else {
                AnonTokenManager.clearContactMailboxTag(from)
            }
            // Direct reciprocal answer, no cooldown: this is a response to an
            // explicit signal from `from` ("I'm low, here's a top-up"), not a
            // proactive guess — see sendAnonTokensTo()'s "reply" parameter for
            // why isReply=true here is what stops this from looping forever.
            val isReplyBatch = objAttempt?.optBoolean("reply", false) ?: false
            if (!isReplyBatch) {
                scope.launch { sendAnonTokensTo(from, isReply = true) }
            }
        } catch (e: Exception) {
            System.err.println("WebSocketClient: failed to process beacon_tokens from $from — ${e.message}")
        }
        return true
    }

    // ── Anonymous mailbox (first-contact bootstrap, Desktop↔Desktop only for now) ─

    /** Polls the anonymous mailbox for any blobs left for our tags, padded with
     *  decoy tags so the server can't tell which one is real. Call on connect. */
    fun pollMailbox() {
        val tags = AnonTokenManager.buildFetchTagList()
        if (tags.isEmpty()) return
        sendWs(JSONObject().apply {
            put("type", "mailbox_fetch")
            put("tags", JSONArray(tags))
        }.toString())
    }

    /** Deposits an encrypted first message + our token pool into [mailboxTag]'s
     *  mailbox, for a contact we've never connected to directly yet. */
    fun sendViaMailbox(to: String, text: String, publicKey: String, mailboxTag: String, messageId: String? = null) {
        val id = messageId ?: java.util.UUID.randomUUID().toString()
        try {
            // freshTokensToShare(), not tokensToShareWith() — see its own
            // comment. Was tokensToShareWith() before this fix.
            val myTokens = AnonTokenManager.freshTokensToShare()
            AnonTokenManager.recordTokensGivenTo(to, myTokens)
            // subscribe_tokens BEFORE the mailbox deposit — same ordering
            // fix as depositTokensViaMailbox()/sendAnonTokensToLocked(), see
            // their own comments. Was missing entirely before this fix.
            sendSubscribeTokens(AnonTokenManager.tokensToSubscribe())
            val inner = JSONObject().apply {
                put("from", myFingerprint)
                put("text", text)
                put("tokens", JSONArray(myTokens))
                put("id", id)
            }
            // End-to-end identity signature — see mailboxTranscript()'s own
            // comment.
            inner.put("signature", CryptoManager.sign(mailboxTranscript(inner)))
            val blob = CryptoManager.encryptClassicalOnly(inner.toString(), publicKey)
            sendWs(addPadding(JSONObject().apply {
                put("type", "mailbox_put")
                put("tag", mailboxTag)
                put("blob", blob)
            }).toString())
        } catch (e: Exception) {
            System.err.println("WebSocketClient: sendViaMailbox error — ${e.message}")
        }
    }

    /** Prunes [tag] from the poll list unless it's our own current
     *  persistent tag — that one is meant to be reused indefinitely, only
     *  one-off/legacy (i.e. invite) tags should be pruned. Mirrors Android's
     *  MessengerService.removeMailboxTagIfEphemeral() (desktop/Android
     *  symmetry audit, 2026-09-03) — the previous check here compared
     *  against the *invite* tag instead, which is backwards: the invite tag
     *  is exactly the one that's supposed to be disposable/prunable after
     *  first use, while the persistent tag must never be pruned. */
    private fun removeMailboxTagIfEphemeral(tag: String) {
        if (tag == AnonTokenManager.getOrCreateMyPersistentMailboxTag()) return
        AnonTokenManager.removeMyMailboxTag(tag)
    }

    /** Shared by every "persist an incoming X unconditionally" helper below
     *  — disappearing-message countdown must start on receipt regardless of
     *  message type, and regardless of which screen (if any) is mounted to
     *  observe it. */
    private fun computeExpiresAt(from: String): Long {
        val timerSecs = ChatStorage.getDisappearTimer(myFingerprint, from)
        return if (timerSecs > 0L) System.currentTimeMillis() + timerSecs * 1000L else 0L
    }

    /** Writes [bytes] to the same encrypted-at-rest blob store ChatScreen
     *  used to write to itself (see the comment on persistAndNotifyIncoming
     *  et al.) — now centralized so image/file/voice persistence doesn't
     *  depend on ChatScreen being mounted either. */
    private fun writeEncryptedBlob(id: String, bytes: ByteArray): java.io.File {
        val dir = java.io.File(DesktopStorage.resolveDataDir(), "blobs").also { it.mkdirs() }
        val file = java.io.File(dir, "$id.enc")
        file.writeBytes(DesktopStorage.encryptRaw(bytes))
        return file
    }

    /** Persists an incoming text message to ChatStorage unconditionally,
     *  THEN notifies whichever UI callback happens to be registered.
     *  Persistence must not depend on which screen is currently mounted:
     *  onMessageReceived is a single overwritable var, and ChatsScreen's own
     *  registration (while browsing the chat list, not a specific contact's
     *  chat) only ever bumped an in-memory unread counter — it never saved
     *  anything. A message that arrived while the list (not that contact's
     *  ChatScreen) was open still got decrypted, acked ("delivered" sent
     *  back) and counted as unread, but was gone for good the moment the
     *  user actually opened the conversation, since nothing had written it
     *  to storage. Found live, 2026-09-20. Returns the persisted id so
     *  callers (ChatScreen) can update the SAME row instead of inserting a
     *  duplicate under a freshly-minted id. Same reasoning — and same fix
     *  shape — applies to image/file/voice below, which had the identical
     *  bug: onImageReceived/onFileReceived were ONLY ever registered by
     *  ChatScreen, so with no specific chat open they were silently dropped
     *  entirely (not even counted as unread). */
    private fun persistAndNotifyIncoming(from: String, text: String, replyToId: String? = null): String {
        val id = java.util.UUID.randomUUID().toString()
        ChatStorage.saveOrUpdateMessage(myFingerprint, from,
            ChatStorage.StoredMessage(id = id, text = text, isOwn = false, isRead = false,
                replyToId = replyToId, expiresAt = computeExpiresAt(from)))
        DesktopNotificationService.notifyIncomingMessage(from, text)
        onMessageReceived?.invoke(from, text, id, replyToId)
        return id
    }

    /** Shared by the direct "session_init" dispatch and by
     *  handleMailboxResult()'s session_init_packet handling — same
     *  processing either way, only the transport differs. Mirrors
     *  Android's MessengerService.processSessionInit() exactly. Extracted
     *  from the inline "session_init" case (2026-09-12 full-logic audit) so
     *  a session_init delivered via mailbox — Android's isFirst/
     *  depositSessionInitViaMailbox() path, previously entirely unhandled
     *  on Desktop — gets identical treatment to a directly-delivered one. */
    private fun processSessionInit(json: JSONObject) {
        val msgId    = json.optString("id", "")
        // Peek-only — see isDuplicateId()'s own comment and the matching
        // "message" handler fix: was dedup(), which marked the id processed
        // immediately, before signature verification/session establishment/
        // decrypt had even run. A session_init that failed any of those
        // steps would then be permanently unretryable even though it was
        // never actually processed. Found in the 2026-09-13 full-logic audit.
        if (msgId.isNotEmpty() && isDuplicateId(msgId)) return
        val from     = json.getString("from")
        // Local-only block check — deliberately first, before ANY side
        // effect: a deleted contact's session_init must not silently
        // re-establish a session, save their key, or fetch a bundle.
        // Auto-lifted only via a fresh addContact() (invite redemption),
        // never implicitly.
        if (ChatStorage.isBlocked(from)) {
            System.err.println("WebSocketClient: session_init from $from ignored — contact is blocked")
            return
        }
        val senderIk = json.getString("sender_ik")
        val x3dhHdr  = json.getJSONObject("x3dh_header")
        val sessHdr  = json.getJSONObject("session_header")
        val ctB64    = json.getString("text")
        val signature = json.optString("signature", null)
        // Wire format sometimes carries URL-safe base64 (matches
        // InviteCodeManager's convention) — normalize BEFORE using
        // as a key, mirrors Android's fixedSenderIk exactly.
        val fixedSenderIk = senderIk.replace('-', '+').replace('_', '/')

        // CRITICAL, BEFORE ANY mutation (found in the 2026-09-13
        // cross-platform session_init audit): the signature check further
        // below only proves "whoever holds sender_ik's private key signed
        // this" — it says NOTHING about whether sender_ik actually belongs
        // to the fingerprint `from` claims to be. The comment this replaced
        // claimed the signature check was "the ONLY thing that binds a
        // session_init to the identity it claims" — it isn't: an attacker
        // able to route a session_init here could use their OWN identity
        // key/signature while setting `from` to a VICTIM's fingerprint, and
        // this device would establish and persist a real session — and
        // cache the attacker's key under KeyHistoryManager/ChatStorage/
        // peerPublicKeys — keyed by the victim's identity. Same canonical
        // computation as the account identity's own fingerprint
        // (SHA-256(DER)[:8], uppercase hex) and as
        // SessionKeyManager.initiateSession()'s S6-46 check for the
        // equivalent outbound case.
        val senderIkBytes = try {
            Base64.getDecoder().decode(fixedSenderIk)
        } catch (e: Exception) {
            throw SecurityException("session_init: sender_ik не является валидным Base64 от $from")
        }
        val actualFingerprint = java.security.MessageDigest.getInstance("SHA-256")
            .digest(senderIkBytes).take(8).joinToString("") { "%02X".format(it) }
        if (actualFingerprint != from) {
            System.err.println("WebSocketClient: session_init: sender_ik does not match claimed from=$from (actual=$actualFingerprint)")
            throw SecurityException("session_init: identity key does not match claimed from=$from")
        }

        // Signature verification — deliberately BEFORE the try block
        // below and thrown, not caught locally, so it propagates out
        // to anon_delivery's outer catch and suppresses the ack for a
        // rejected packet (same "throw not return" pattern as
        // reaction/disappear_timer).
        if (signature == null || !CryptoManager.verify(ctB64, signature, fixedSenderIk)) {
            System.err.println("WebSocketClient: session_init: invalid or missing signature from $from")
            throw SecurityException("session_init: bad or missing signature from $from")
        }
        try {
            if (KeyHistoryManager.checkKeyChange(from, fixedSenderIk)) {
                System.err.println("WebSocketClient: TOFU: contact $from's key changed in session_init!")
                onKeyChanged?.invoke(from)
            }
            SessionKeyManager.receiveSession(from, fixedSenderIk, x3dhHdr)
            peerPublicKeys[from] = fixedSenderIk          // store IK for legacy fallback
            ChatStorage.saveContactPublicKey(from, fixedSenderIk)
            markChannelReady(from)
            onChannelReady?.invoke(from)
            ContactHealthManager.recordIncoming(from)
            val text = CryptoManager.decryptWithForwardSecrecy(from, ctB64, sessHdr)
            if (!handleDecryptedTextForTokenExchange(from, text)) {
                persistAndNotifyIncoming(from, text)
            }
            if (msgId.isNotEmpty()) markProcessed(msgId)
            // sendAnonOrDirect(), not a raw webSocket send — same fix as the
            // "message" handler: a direct send here put the sender→recipient
            // pair on the wire in the clear even when this session_init only
            // reached us via the anonymous/mailbox path.
            sendAnonOrDirect(from, JSONObject().apply {
                put("type", "delivered"); put("from", myFingerprint); put("to", from); put("id", msgId)
            })
        } catch (e: SessionKeyManager.DuplicateOrStaleMessage) {
            // Successful duplicate disposition — mirrors the "message"
            // handler's own DuplicateOrStaleMessage branch: nothing to
            // retry, no ratchet to fix, tearing the session down here would
            // destroy one just successfully (re-)established a moment ago
            // over a session_init we'd already consumed. Mark processed so
            // a retried copy short-circuits on the peek check above, still
            // ack via a "delivered" receipt, and do NOT rethrow.
            System.err.println("WebSocketClient: duplicate/stale session_init from $from ignored: ${e.message}")
            if (msgId.isNotEmpty()) markProcessed(msgId)
            sendAnonOrDirect(from, JSONObject().apply {
                put("type", "delivered"); put("from", myFingerprint); put("to", from); put("id", msgId)
            })
        } catch (e: Exception) {
            System.err.println("WebSocketClient: session_init failed from $from — ${e.message}")
            sendSessionResetDebounced(from)
            // Rethrown — was silently swallowed before this fix. A bare
            // return here let the anon_delivery handler's ack fire as if
            // this session_init had actually been established and its
            // message decrypted/shown, discarding the server's
            // token_pending fallback copy and losing the message for good
            // once session_reset finishes putting things back in sync.
            // Same reasoning as the "message" handler's generic catch
            // (docs/ISSUE_backup_identity_hijack.md, 2026-08-17). Found in
            // the 2026-09-13 full-logic audit.
            throw e
        }
    }

    private fun handleMailboxResult(json: JSONObject) {
        val blobsMap = json.optJSONObject("blobs") ?: return
        blobsMap.keys().forEach { tag ->
            val arr = blobsMap.optJSONArray(tag) ?: return@forEach
            for (i in 0 until arr.length()) {
                val blob = arr.optString(i) ?: continue
                try {
                    val inner = CryptoManager.decryptClassicalOnly(blob)
                    val innerJson = JSONObject(inner)
                    val from = innerJson.getString("from")

                    // CRITICAL, before any mutation (found in the 2026-09-13
                    // mailbox-authentication audit) — mirrors Android's
                    // handleMailboxResult() exactly. decryptClassicalOnly()
                    // only proves this device could read the blob — a
                    // recipient-encrypted (ephemeral-ECDH) scheme anyone who
                    // knows this device's public key can encrypt to, proving
                    // nothing about who actually sent it. The mutual-add
                    // spam gate right below only proves this device once
                    // redeemed SOME invite code claiming to be `from`, not
                    // that THIS blob's real sender holds that fingerprint's
                    // private key. Resolved from this device's own
                    // long-term TOFU cache, never from anything embedded in
                    // the packet, and never sender_cert (a separate,
                    // unrelated mechanism). No unsigned-legacy fallback —
                    // this ships as one coordinated fix on both platforms.
                    val senderKey = peerPublicKeys[from] ?: ChatStorage.getContactPublicKey(from)
                    val mailboxSig = innerJson.optString("signature", null)
                    if (senderKey == null) {
                        System.err.println("WebSocketClient: mailbox: deposit from $from rejected — no trusted key to verify signature")
                        continue
                    }
                    if (mailboxSig == null || !CryptoManager.verify(mailboxTranscript(innerJson), mailboxSig, senderKey)) {
                        System.err.println("WebSocketClient: mailbox: deposit from $from rejected — invalid or missing signature")
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
                    if (AnonTokenManager.getContactMailboxTag(from) == null) {
                        System.err.println("WebSocketClient: mailbox: deposit from $from ignored — contact not mutually added")
                        continue
                    }

                    // A brand-new contact's very first message, deposited here
                    // instead of via anon_message because no token exchange had
                    // completed yet — see initiateAndSend()'s
                    // depositSessionInitViaMailbox() call and Android's
                    // identical isFirst branch. Was entirely unhandled on
                    // Desktop before this fix (innerJson.getString("text")
                    // below would throw on this shape and silently drop the
                    // whole blob) — found in the 2026-09-12 full-logic audit.
                    val sessionInitPacket = innerJson.optJSONObject("session_init_packet")
                    if (sessionInitPacket != null) {
                        removeMailboxTagIfEphemeral(tag)
                        processSessionInit(sessionInitPacket)
                        continue
                    }

                    val text = innerJson.getString("text")
                    val tokensArr = innerJson.optJSONArray("tokens")
                    if (tokensArr != null) {
                        val tokens = (0 until tokensArr.length()).map { tokensArr.getString(it) }
                        AnonTokenManager.addContactTokens(from, tokens)
                        flushPendingAnon(from)
                        markChannelReady(from)
                        // Same tag-freshness refresh as the anon_message token
                        // path — a mailbox-delivered token batch can carry it too.
                        innerJson.optString("mailbox_tag", null)?.let { freshTag ->
                            AnonTokenManager.setContactMailboxTag(from, freshTag)
                        }
                        onChannelReady?.invoke(from)
                        // Same direct-reciprocal-no-cooldown logic as the anon_message
                        // beacon_tokens path — mailbox-delivered batches carry the
                        // same "reply" flag.
                        val isReplyBatch = innerJson.optBoolean("reply", false)
                        if (!isReplyBatch) {
                            scope.launch { sendAnonTokensTo(from, isReply = true) }
                        }
                    }
                    removeMailboxTagIfEphemeral(tag)
                    // Mutual add: whoever deposits for us via mailbox becomes a
                    // contact, same as Android — otherwise a contact who added us
                    // first never shows up locally until we separately redeem
                    // their invite code. Name is optional (older/other-platform
                    // senders may omit it) and never overwrites one already set.
                    ChatStorage.addContact(from)
                    innerJson.optString("name").takeIf { it.isNotBlank() }?.let { name ->
                        if (ChatStorage.getContactName(from).isBlank()) {
                            ChatStorage.saveContactName(from, name)
                        }
                    }
                    // Token-bootstrap-only mailbox deposits (see sendAnonTokensTo's
                    // mailbox fallback) carry a placeholder, not a real message —
                    // must not be surfaced to the UI as a chat bubble. Must match
                    // Android's exact prefix ("__beacon_..."), not a Desktop-only
                    // rebrand — otherwise a mailbox deposit sent by the OTHER
                    // platform leaks through as a literal garbage message.
                    if (!text.startsWith("__beacon_")) {
                        persistAndNotifyIncoming(from, text)
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: mailbox blob decrypt failed — ${e.message}")
                }
            }
        }
    }

    private val client: OkHttpClient by lazy { buildOkHttpClient(useTor = false) }

    // Only built (and only attempts a SOCKS connection) when actually needed —
    // i.e. when the configured server URL is a .onion address.
    private val torClient: OkHttpClient by lazy { buildOkHttpClient(useTor = true) }

    // Separate instances for the identity-less anon_channel connection —
    // deliberately not reusing client/torClient above, so anon_channel
    // shares no TLS session cache / connection pool with the main
    // (identified) socket; a shared client instance would let an observer
    // pair the two connections through that side channel even without
    // reading a username directly. Mirrors Android's
    // anonWsClient/anonWsTorClient (desktop/Android symmetry audit,
    // 2026-09-03).
    private val anonClient: OkHttpClient by lazy { buildOkHttpClient(useTor = false) }
    private val anonTorClient: OkHttpClient by lazy { buildOkHttpClient(useTor = true) }

    /**
     * A desktop Tor daemon or Tor Browser's bundled tor is always a plain
     * local SOCKS5 proxy (no VPN-mode ambiguity like Android/Orbot) — so any
     * .onion server URL is unconditionally routed through it. The raw
     * Socket(proxy) + createUnresolved() approach avoids local DNS
     * resolution entirely, which matters both because .onion addresses
     * aren't DNS-resolvable and to avoid leaking the destination host to the
     * local resolver.
     */
    private fun buildOkHttpClient(useTor: Boolean): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .pingInterval(25, TimeUnit.SECONDS)  // detect dead TCP connections
            .connectTimeout(if (useTor) 60 else 15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
        if (useTor) {
            val socksPort = DesktopTorManager.detectSocksPort() ?: DesktopTorManager.SOCKS_PORT
            val torProxy = java.net.Proxy(
                java.net.Proxy.Type.SOCKS,
                InetSocketAddress(DesktopTorManager.SOCKS_HOST, socksPort)
            )
            builder.socketFactory(object : javax.net.SocketFactory() {
                private fun torSocket(host: String, port: Int): java.net.Socket =
                    java.net.Socket(torProxy).apply {
                        connect(InetSocketAddress.createUnresolved(host, port), 30_000)
                    }
                override fun createSocket(): java.net.Socket = java.net.Socket(torProxy)
                override fun createSocket(host: String, port: Int) = torSocket(host, port)
                override fun createSocket(host: java.net.InetAddress, port: Int) = torSocket(host.hostName, port)
                override fun createSocket(host: String, port: Int, localAddr: java.net.InetAddress, localPort: Int) = torSocket(host, port)
                override fun createSocket(host: java.net.InetAddress, port: Int, localAddr: java.net.InetAddress, localPort: Int) = torSocket(host.hostName, port)
            })
            System.err.println("WebSocketClient: routing via Tor SOCKS5 (${DesktopTorManager.SOCKS_HOST}:$socksPort)")
        }
        if (NetworkConfig.CERT_PIN.isNotEmpty() && NetworkConfig.SERVER_HOSTNAME.isNotEmpty()) {
            builder.certificatePinner(
                okhttp3.CertificatePinner.Builder()
                    .add(NetworkConfig.SERVER_HOSTNAME, NetworkConfig.CERT_PIN)
                    .build()
            )
        }
        return builder.build()
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Returns the server-side identity (SHA-256 fingerprint, 8 bytes, hex uppercase).
     * This is what "to"/"from" fields contain on the server.
     */
    fun computeFingerprint(pubKeyBase64: String): String {
        val keyBytes = Base64.getDecoder().decode(pubKeyBase64)
        return MessageDigest.getInstance("SHA-256").digest(keyBytes)
            .take(8).joinToString("") { "%02x".format(it) }.uppercase()
    }

    /** My own fingerprint on the server. */
    val myFingerprint: String
        get() = computeFingerprint(DesktopCryptoManager.getPublicKeyBase64())

    fun connect(name: String) {
        displayName      = name
        userDisconnected = false
        registrationReady = CompletableDeferred()
        ensureMyMailboxTagRegistered()
        hydratePeerKeyCachesOnce()
        scope.launch { doConnect() }
    }

    @Volatile private var peerKeyCachesHydrated = false

    /** Refills the in-memory peerPublicKeys/peerPqPublicKeys/
     *  DesktopCryptoManager peer-key caches from ChatStorage's persisted
     *  copies — those maps started every process completely empty
     *  otherwise, so EVERY contact needed a fresh get_prekey_bundle round
     *  trip after every single app restart before images/files/group-key
     *  distribution/Sealed-Sender could work again, even though the
     *  classical key was already sitting in ChatStorage unused (write-only
     *  storage, only ever read by exportBackup()). Found via a
     *  desktop/Android literal wire-field audit, 2026-09-11. Runs once per
     *  process. */
    private fun hydratePeerKeyCachesOnce() {
        if (peerKeyCachesHydrated) return
        peerKeyCachesHydrated = true
        ChatStorage.getContacts().forEach { contactId ->
            ChatStorage.getContactPublicKey(contactId)?.let { key ->
                peerPublicKeys[contactId] = key
                DesktopCryptoManager.storePeerPublicKey(contactId, key)
            }
            ChatStorage.getContactPqPublicKey(contactId)?.let { pqKey ->
                peerPqPublicKeys[contactId] = pqKey
            }
        }
    }

    /** Waits for the register() attempt started by the most recent connect()
     *  call to actually resolve server-side — true on "register_ok", false
     *  on any definitive rejection (access_code_required, totp_required,
     *  registration_full) or on timeout. A "pow_required" retry keeps this
     *  pending rather than resolving it (mirrors Android's connect() gate —
     *  see registrationReady's own comment). Callers that create an account
     *  (RegisterScreen) should await this instead of assuming connect()
     *  succeeded, since a PoW-gated or access-restricted server can silently
     *  reject registration entirely. */
    suspend fun awaitRegistration(timeoutMs: Long = 30_000): Boolean {
        val deferred = registrationReady ?: return false
        return try {
            withTimeoutOrNull(timeoutMs) { deferred.await() } ?: false
        } catch (e: Exception) {
            false
        }
    }

    /** Server-side proof-of-work gate on brand-new registrations
     *  (server.py MAX_REGISTERED_USERS/POW_DIFFICULTY_BITS) — finds a nonce
     *  such that sha256(challenge + nonce) has at least [difficultyBits]
     *  leading zero bits, matching the server's own check byte-for-byte.
     *  Pure CPU work, no network — mirrors Android's MessengerService.kt
     *  solveProofOfWork()/powLeadingZeroBits() exactly. Runs synchronously
     *  on the WebSocket listener thread (not the Compose UI thread); at
     *  difficulty 18 this completes in well under a second. */
    private fun solveProofOfWork(challenge: ByteArray, difficultyBits: Int): String {
        val digest = MessageDigest.getInstance("SHA-256")
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

    /** Ensures the account's invite code (and the mailbox tag embedded in it) is
     *  generated and registered as early as possible — previously this only
     *  happened lazily when the user opened Profile and called
     *  InviteCodeManager.generateInviteLink(). A user who added contacts without
     *  ever opening their own Profile screen first never registered a mailbox tag
     *  for themselves at all, so contacts could deposit tokens for them but they
     *  had nowhere of their own to receive a deposit — see Android
     *  MessengerService.kt's ensureMyMailboxTagRegistered() for the live incident
     *  that led to this (pollMailbox reporting zero real tags indefinitely). */
    private fun ensureMyMailboxTagRegistered() {
        try {
            InviteCodeManager.generateInviteLink()
        } catch (e: Exception) {
            System.err.println("WebSocketClient: ensureMyMailboxTagRegistered — ${e.message}")
        }
    }

    fun disconnect() {
        userDisconnected = true          // mark as intentional — suppress reconnect
        stopCoverTraffic()
        disconnectAnonChannel()
        webSocket?.close(1000, "user logout")
        webSocket     = null
        handshakeDone = false
        isConnecting  = false
        _connected.value = false
        // Same reasoning as onFailure/onClosed — a request in flight on
        // this socket will never get its response on whatever connection
        // comes next. Found in the 2026-09-13 bundleRequested lifecycle
        // audit.
        bundleRequested.clear()
        onStatusChanged?.invoke(false)
    }

    /** Mirrors Android's MessengerService.forgetContact() — full teardown for
     *  a deleted contact, clearing the in-memory key caches this running
     *  client holds (ChatStorage.deleteChat() only owns on-disk state), the
     *  Double Ratchet session, and the mailbox tag (so a future mailbox
     *  deposit from this fingerprint is rejected by the existing mutual-add
     *  gate). Without this, a deleted contact's routine background traffic
     *  (health-check pings, token refills) still verified against the
     *  surviving in-memory key and silently resurrected them. */
    fun forgetContact(contactId: String) {
        // Cancel any in-flight bootstrap/retry job for this contact FIRST —
        // otherwise forceRestoreConnection()'s deposit burst or
        // bootstrapChannelFor()'s retry loop can still be mid-flight
        // (recording newly-given tokens, re-populating bundleRequested/
        // channelBootstrapStartedAt) while — or after — the destructive
        // cleanup below runs, silently repopulating exactly what this
        // function is trying to wipe. Found in the 2026-09-13
        // contact-deletion audit.
        pendingChannelJobs.remove(contactId)?.cancel()
        peerPublicKeys.remove(contactId)
        peerPqPublicKeys.remove(contactId)
        SessionKeyManager.deleteSession(contactId)
        AnonTokenManager.clearContactMailboxTag(contactId)
        // Capture/revoke outstanding tokens BEFORE wiping local token
        // state — clearContactTokens() below deletes the very
        // PREF_CT_GIVEN_PREFIX history that revokeContactTokens()'s
        // getTokensGivenTo() reads. Calling clear first (the previous
        // order) left getTokensGivenTo() with nothing to revoke, so
        // unsubscribe_tokens was silently never sent and the server kept
        // routing the deleted contact's outstanding tokens to us. Mirrors
        // Android's forgetContact() ordering exactly. Found in the
        // 2026-09-13 contact-deletion audit.
        revokeContactTokens(contactId)
        AnonTokenManager.clearContactTokens(contactId)
        // Mirrors Android's forgetContact(): a re-added contact (same
        // fingerprint, derived from their public key) would otherwise
        // silently inherit leftover health state, bundle-request gates,
        // resupply cooldowns, and queued packets from the deleted
        // relationship instead of starting clean. Was missing entirely
        // before this fix. Found in the 2026-09-13 contact-deletion audit.
        ContactHealthManager.clearContact(contactId)
        bundleRequested.remove(contactId)
        tokensSentThisSession.remove(contactId)
        lastTokenBootstrapAttempt.remove(contactId)
        lastPrekeyFetchAttempt.remove(contactId)
        synchronized(pendingAnonPackets) { pendingAnonPackets.remove(contactId) }
        channelBootstrapStartedAt.remove(contactId)
        channelStuckNotified.remove(contactId)
        // Local-only block (see ChatStorage.blockContact()'s comment) — a
        // deleted contact can't reach a fresh session_init past this point.
        // Automatically lifted by ChatStorage.addContact() if this
        // fingerprint is ever legitimately re-invited later.
        ChatStorage.blockContact(contactId)
    }

    /** Debounced to once per 10s per contact — mirrors Android's
     *  MessengerService.sendSessionResetDebounced() exactly. Every decrypt
     *  failure from a given contact used to independently wipe the session
     *  and fire its own session_reset + prekey re-fetch: a burst of several
     *  failed messages in a row (e.g. a few queued sends landing back-to-
     *  back after a reconnect) fired that many resets, and each one
     *  independently deleted the recipient's session again — including
     *  sessions the recipient had ALREADY freshly re-established off an
     *  earlier reset in the same burst. Self-sustaining loop, not a
     *  one-time hiccup (Android found this live 2026-08-17). Desktop had no
     *  debounce at all before this fix — found in the 2026-09-12 full-logic
     *  audit. */
    private fun sendSessionResetDebounced(to: String) {
        val now = System.currentTimeMillis()
        if (now - (lastSessionResetSentAt[to] ?: 0L) < 10_000L) return
        lastSessionResetSentAt[to] = now
        SessionKeyManager.deleteSession(to)
        bundleRequested.remove(to)
        requestBundleFor(to)
        sendAnonOrDirect(to, JSONObject().apply {
            put("type", "session_reset")
            put("from", myFingerprint)
            put("to",   to)
        })
    }

    /** One-time, undebounced courtesy notice for a user-initiated contact
     *  deletion — mirrors Android's ChatsScreen delete-contact flow's
     *  "send_session_reset_to" intent. The peer has no idea they were
     *  deleted; without this, their Double Ratchet state silently diverges
     *  from ours the moment they next send using the session we just tore
     *  down in forgetContact(), and they get no explicit signal to
     *  re-handshake — only whatever generic decrypt-failure recovery
     *  eventually kicks in on their end. Found in the 2026-09-12
     *  full-logic audit (Desktop's delete-contact flow never sent this at
     *  all). */
    fun notifyContactOfDeletion(contactId: String) {
        sendAnonOrDirect(contactId, JSONObject().apply {
            put("type", "session_reset")
            put("from", myFingerprint)
            put("to",   contactId)
        })
    }

    /** "Меня скомпрометировали" — mirrors Android's MessengerService.
     *  requestIdentityRevocation(): fires the best-effort revoke_identity
     *  message through the still-old-identity-authenticated connection
     *  (server marks this fingerprint revoked so the old key stops being
     *  sufficient to register again, even if whoever compromised it still
     *  has it), then waits briefly for the frame to actually flush before
     *  the caller destroys the local key. No ack wait by design — matches
     *  the "deliberately cheap" spirit of the rest of the reset flow. Was
     *  entirely missing from Desktop before this (found live, 2026-09-12:
     *  a compromised Desktop identity had no way to revoke itself). */
    suspend fun requestIdentityRevocation() {
        if (handshakeDone) {
            webSocket?.send(JSONObject().apply { put("type", "revoke_identity") }.toString())
        }
        kotlinx.coroutines.delay(400)
    }

    /** "Восстановить связь" — a deliberate, user-initiated "something's
     *  broken, force a resync" action for a stalled 1:1 channel. Mirrors
     *  Android's MessengerService.forceRestoreConnection() exactly: deletes
     *  OUR OWN Double Ratchet session and OUR cached copy of THEIR PQ key
     *  (session_reset's own handler only fixes the asymmetric half — the
     *  RECIPIENT's cached copy of OUR key — so pressing this button on only
     *  one side would otherwise leave that side's own outgoing sends
     *  broken even after the other side reacts), re-requests a fresh
     *  prekey bundle, and re-deposits mailbox tokens in a short bounded
     *  retry burst in case the mutual-add channel bootstrap itself never
     *  completed. Unconditional — not gated on hasSession()/isChannelReady,
     *  since in the common case a session already exists on both sides and
     *  gating on that would make the button silently do nothing (found
     *  live on Android, 2026-08-30, then reverted). Was entirely missing
     *  from Desktop, including the button itself — found in the
     *  2026-09-12 full-logic audit ("1:1 has bugs at every step"). */
    fun forceRestoreConnection(contact: String) {
        SessionKeyManager.deleteSession(contact)
        peerPqPublicKeys.remove(contact)
        ChatStorage.clearContactPqPublicKey(contact)
        bundleRequested.remove(contact)
        requestBundleFor(contact)

        val mailboxTag = AnonTokenManager.getContactMailboxTag(contact)
        val publicKey  = peerPublicKeys[contact] ?: ChatStorage.getContactPublicKey(contact)
        if (mailboxTag == null || publicKey == null) {
            System.err.println("WebSocketClient: forceRestoreConnection: no mailbox tag/key for $contact — cannot restore")
        } else {
            pendingChannelJobs[contact]?.cancel()
            pendingChannelJobs[contact] = scope.launch {
                // One batch minted up front and resent for all three
                // attempts — mirrors Android's identical 2026-08-31 fix:
                // these are retries of the SAME deposit, not three
                // independent ones, so they shouldn't each mint their own
                // fresh batch and triple the pool pressure on a single
                // button press.
                val batch = AnonTokenManager.freshTokensToShare()
                for (d in longArrayOf(0L, 30_000L, 90_000L)) {
                    delay(d)
                    depositTokensViaMailbox(contact, mailboxTag, publicKey, presetTokens = batch)
                }
                pendingChannelJobs.remove(contact)
            }
        }

        // Best-effort direct attempt too, in case only ONE side's channel is
        // actually broken — costs nothing extra if it silently fails to
        // deliver.
        if (handshakeDone) {
            sendAnonOrDirect(contact, JSONObject().apply {
                put("type", "session_reset")
                put("from", myFingerprint)
                put("to",   contact)
            })
        }
    }

    /** Explicit, immediate revocation of tokens previously shared with
     *  [contactId] — mirrors Android's MessengerService.revokeContactTokens().
     *  Unlike just stopping future resupply, this tells the server directly:
     *  any outstanding, unspent token from this batch stops routing to this
     *  contact right now. Safe to call even if some/all tokens are already
     *  spent or unknown to the server. */
    private fun revokeContactTokens(contactId: String) {
        val given = AnonTokenManager.getTokensGivenTo(contactId)
        if (given.isEmpty()) return
        webSocket?.send(JSONObject().apply {
            put("type", "unsubscribe_tokens")
            put("tokens", JSONArray(given))
        }.toString())
        AnonTokenManager.clearTokensGivenTo(contactId)
    }

    /** One-time provisioning of the device-gated registration TOTP secret —
     *  mirrors Android's MessengerService.sendTotpSetup(). Server refuses
     *  outright if a secret is already on file for this account, UNLESS
     *  [recoveryCode] proves ownership (recovery-code takeover re-enroll
     *  window — see server.py's totp_setup handler and Android's
     *  TotpSettingsScreen.kt "needsReenrollRecovery"). */
    fun sendTotpSetup(secretBase32: String, code: String, recoveryCode: String? = null) {
        if (!handshakeDone) {
            onTotpSetupResult?.invoke(false, "not_connected", null)
            return
        }
        webSocket?.send(JSONObject().apply {
            put("type", "totp_setup")
            put("secret", secretBase32)
            put("new_code", code)
            if (!recoveryCode.isNullOrBlank()) put("recovery_code", recoveryCode.trim())
        }.toString())
    }

    /** Response to onTotpRequired() — this device has no usable TOTP code.
     *  Stashes the code for the next register() attempt and forces a
     *  reconnect to retry immediately. Mirrors Android's
     *  MessengerService.submitRecoveryCode(). */
    fun submitRecoveryCode(code: String) {
        pendingRecoveryCode = code.trim()
        webSocket?.close(1000, "recovery_code retry")
    }

    fun sendTotpDisable(code: String, recoveryCode: String? = null) {
        if (!handshakeDone) {
            onTotpDisableResult?.invoke(false)
            return
        }
        webSocket?.send(JSONObject().apply {
            put("type", "totp_disable")
            put("code", code)
            // Mirrors Android's MessengerService.sendTotpDisable() exactly —
            // lets a user who lost their authenticator but saved a recovery
            // code disable TOTP without a live 6-digit code. Was entirely
            // absent on Desktop.
            if (!recoveryCode.isNullOrBlank()) put("recovery_code", recoveryCode.trim())
        }.toString())
    }

    /** to = fingerprint of recipient. Returns false if not connected to
     *  server, OR if the message could only be enqueued (no session/key yet)
     *  rather than actually attempted over the network — see trySend()'s own
     *  comment. ChatScreen.kt uses this to set isFailed on the local message
     *  row; before this fix it always returned true as long as the socket
     *  was up, so a message that silently went straight into messageQueue
     *  (branch ⑤ below) showed as successfully sent in the UI with zero
     *  indication anything was still pending. Mirrors the identical fix
     *  applied to Android's sendWithForwardSecrecy() (the "ОТПРАВЛЕНО"
     *  log was firing before any send was attempted there) — found live
     *  2026-09-18 while auditing Desktop for the same class of bug. */
    // replyToId only threaded through the ① established-session path below —
    // mirrors Android's send()/sendWithForwardSecrecy() exactly: replying
    // requires a message you already received to be visible in history,
    // which itself required a session to have existed, so the ②/④/⑤
    // first-contact-bootstrap paths (X3DH initiate, mailbox deposit, queue-
    // and-fetch-bundle) never realistically need to carry one. Found live,
    // 2026-09-20: this parameter didn't exist here at all — Desktop's
    // reply-to-message feature only ever updated the SENDER's own local
    // storage/UI, never actually put reply_to_id on the wire, so no
    // recipient (Android or another Desktop) ever learned a message was a
    // reply. Same field name Android already uses (`reply_to_id`).
    fun sendText(to: String, text: String, msgId: String, replyToId: String? = null): Boolean {
        if (!handshakeDone) return false
        ContactHealthManager.recordOutgoingAttempt(to)
        return trySend(to, text, msgId, replyToId)
    }

    /** Returns true only when a real transmission was actually attempted
     *  (session send, X3DH initiate, or mailbox deposit) — false when the
     *  message could only be enqueued for later (no session, no fetched
     *  bundle, no mailbox tag/key yet). See sendText()'s own comment for why
     *  this distinction matters to the caller. */
    private fun trySend(to: String, text: String, msgId: String, replyToId: String? = null): Boolean {
        when {
            // ① X3DH Double-Ratchet session already established
            SessionKeyManager.hasSession(to) -> {
                try {
                    val (encrypted, header) = CryptoManager.encryptWithForwardSecrecy(to, text)
                    sendAnonOrDirect(to, JSONObject().apply {
                        put("type",           "message")
                        put("from",           myFingerprint)
                        put("to",             to)
                        put("text",           encrypted)
                        put("id",             msgId)
                        if (!replyToId.isNullOrBlank()) put("reply_to_id", replyToId)
                        // Without this, Android's "message" handler defaults
                        // a missing protocol_version to 1 and refuses to take
                        // the Double-Ratchet path (requires >= 2) — it tries
                        // to parse genuine DR ciphertext with the LEGACY
                        // hybrid decrypt() instead, which fails immediately
                        // as "Пакет повреждён (ephemeral key)" (DR ciphertext
                        // is just iv+AES-GCM, no 2-byte-length-prefixed
                        // ephemeral-key/PQ-ciphertext framing at all) and
                        // resets the session. Explains why the FIRST message
                        // to a new contact (session_init, which doesn't check
                        // protocol_version at all) always worked while every
                        // later "message" on the same established session
                        // failed. Found via a desktop/Android literal
                        // wire-field audit, 2026-09-11 — critical severity
                        // (breaks 1:1 messaging after the first message,
                        // every time).
                        put("protocol_version", ProtocolVersion.CURRENT_VERSION)
                        put("session_header", header)
                        put("signature",      CryptoManager.sign(encrypted))
                    })
                    return true
                } catch (e: SessionKeyManager.SessionRotationRequired) {
                    SessionKeyManager.deleteSession(to)
                    enqueueAndRequestBundle(to, text, msgId)
                    return false
                }
            }
            // ② We already fetched the peer's prekey bundle — initiate X3DH then send
            pendingBundles.containsKey(to) -> {
                val bundle = pendingBundles.remove(to)!!
                initiateAndSend(bundle, to, text, msgId)
                return true
            }
            // Removed ③ "peerPublicKeys.containsKey(to) -> sendLegacy(...)" —
            // Android's send()/sendWithForwardSecrecy() has NO equivalent
            // branch: with no active session and no freshly-fetched bundle,
            // it ALWAYS queues the message and requests a fresh prekey
            // bundle to do a proper X3DH re-handshake, never silently
            // drops to plain non-forward-secret ECDH just because a stale
            // cached static key happens to be lying around. This branch
            // fired live in an ordinary, common case — the local session
            // gets deleted (e.g. by session_reset) while ChatStorage's
            // cached peer key survives — silently and permanently downgrading
            // that contact's messages to legacy encryption with no ratchet
            // and no automatic path back to Double Ratchet. Falls through to
            // ④/⑤ below now, matching Android. Found in the 2026-09-12
            // full-logic audit ("1:1 messaging has bugs at every step").
            // ④ First contact via an invite that carried a mailbox tag: deposit the
            //    message + our token pool anonymously instead of asking the server
            //    for their prekey bundle by fingerprint.
            AnonTokenManager.getContactMailboxTag(to) != null && DesktopCryptoManager.getPeerPublicKey(to) != null -> {
                val tag = AnonTokenManager.getContactMailboxTag(to)!!
                val key = DesktopCryptoManager.getPeerPublicKey(to)!!
                sendViaMailbox(to, text, key, tag, msgId)
                return true
            }
            // ⑤ No key at all — queue the message and request the peer's prekey bundle
            else -> {
                enqueueAndRequestBundle(to, text, msgId)
                return false
            }
        }
    }

    private val lastTypingSentAt = mutableMapOf<String, Long>()

    /** Debounced to once per ~3s per contact — see Android's sendTyping for the
     *  full rationale (per-keystroke would burn through the finite anon token
     *  pool almost instantly). Proactive refill-on-low-pool is handled
     *  centrally inside sendAnonOrDirect() now. */
    fun sendTyping(to: String) {
        if (!handshakeDone) return
        val now = System.currentTimeMillis()
        if (now - (lastTypingSentAt[to] ?: 0L) < 3_000L) return
        lastTypingSentAt[to] = now
        sendAnonOrDirect(to, JSONObject().apply {
            put("type", "typing")
            put("from", myFingerprint)
            put("to",   to)
        })
    }

    /** Pushes the local user's avatar to the server as "profile_update" (no
     *  "to" field — the server fans it out to this user's contacts/channel
     *  subscribers as "avatar_data", same as Android's identical send). */
    fun sendMyAvatarUpdate(base64: String) {
        if (!handshakeDone) return
        sendWs(JSONObject().apply {
            put("type", "profile_update")
            put("from", myFingerprint)
            put("avatar", base64)
        }.toString())
    }

    fun sendRead(to: String, msgId: String) {
        if (!handshakeDone) return
        sendAnonOrDirect(to, JSONObject().apply {
            put("type", "read")
            put("from", myFingerprint)
            put("to",   to)
            put("id",   msgId)
        })
    }

    /** Server expects type="edit" with fields: to, id, text */
    fun sendEdit(to: String, msgId: String, newText: String) {
        if (!handshakeDone) return
        // Edit messages use legacy ephemeral ECDH (the edit protocol frame
        // doesn't carry a session_header, so Double-Ratchet is not applicable here).
        val peerKey = peerPublicKeys[to] ?: run {
            System.err.println("WebSocketClient: no peer key for $to, dropping edit")
            return
        }
        val peerPqKey = peerPqPublicKeys[to] ?: run {
            System.err.println("WebSocketClient: no PQ peer key for $to, dropping edit")
            return
        }
        val encrypted = runCatching { CryptoManager.encrypt(newText, peerKey, peerPqKey) }.getOrElse {
            System.err.println("WebSocketClient: edit encrypt failed — ${it.message}")
            return
        }
        sendAnonOrDirect(to, JSONObject().apply {
            put("type",      "edit")
            put("from",      myFingerprint)
            put("to",        to)
            put("id",        msgId)
            put("text",      encrypted)
            put("signature", CryptoManager.sign(encrypted))
        })
    }

    /** Server expects type="message_delete" relayed by "to" */
    fun sendDelete(to: String, msgId: String) {
        // Signed as of S6-54 (external review 2026-09-06) -- this platform
        // previously sent NO signature at all, so any authenticated contact
        // could ask a recipient to delete an arbitrary message id with
        // nothing proving they were entitled to. "SUBROSA_MESSAGE_DELETE_V1:"
        // domain-separates this transcript from every other signed value in
        // this protocol (group_member_removed's "$groupId:$removedMember"
        // has the same shape as group_message_delete's own transcript, for
        // example) -- ported identically from Android's MessengerService.kt.
        if (!handshakeDone) return
        val signature = CryptoManager.sign("SUBROSA_MESSAGE_DELETE_V1:$msgId")
        sendAnonOrDirect(to, JSONObject().apply {
            put("type", "message_delete")
            put("from", myFingerprint)
            put("to",   to)
            put("id",   msgId)
            put("signature", signature)
        })
    }

    /** Server expects type="reaction" with fields: to, message_id, emoji.
     *  Mirrors Android MessengerService.sendReaction() exactly — the emoji is
     *  hybrid-encrypted (legacy ephemeral ECDH + PQ, same one-shot as edit,
     *  the reaction frame carries no session_header so Double-Ratchet is not
     *  applicable) and the CIPHERTEXT is signed. "reaction" is NOT in
     *  ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE, so it carries this per-
     *  message signature over the ciphertext rather than a control-envelope
     *  transcript signature. */
    fun sendReaction(to: String, msgId: String, emoji: String) {
        if (!handshakeDone) return
        val peerKey = peerPublicKeys[to] ?: run {
            System.err.println("WebSocketClient: no peer key for $to, dropping reaction")
            return
        }
        val peerPqKey = peerPqPublicKeys[to] ?: run {
            System.err.println("WebSocketClient: no PQ peer key for $to, dropping reaction")
            return
        }
        val encrypted = runCatching { CryptoManager.encrypt(emoji, peerKey, peerPqKey) }.getOrElse {
            System.err.println("WebSocketClient: reaction encrypt failed — ${it.message}")
            return
        }
        sendAnonOrDirect(to, JSONObject().apply {
            put("type",       "reaction")
            put("from",       myFingerprint)
            put("to",         to)
            put("message_id", msgId)
            put("emoji",      encrypted)
            put("signature",  CryptoManager.sign(encrypted))
        })
    }

    /** Server expects type="disappear_timer" with fields: to, seconds.
     *  Mirrors Android MessengerService.sendDisappearTimer() exactly — signs
     *  the bare seconds.toString() (the transcript both sides agree on for
     *  this type; it is NOT in ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE).
     *  The value must already be one of CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED
     *  (the UI only offers those 4) — the server rejects anything else too. */
    fun sendDisappearTimer(to: String, seconds: Long) {
        if (!handshakeDone) return
        sendAnonOrDirect(to, JSONObject().apply {
            put("type",      "disappear_timer")
            put("from",      myFingerprint)
            put("to",        to)
            put("seconds",   seconds)
            put("signature", CryptoManager.sign(seconds.toString()))
        })
    }

    /**
     * Encrypt [rawBytes] for [to] and send as image_chunk stream.
     * Mirrors mobile MessengerService.sendImage(): same wire format,
     * same chunk size (120 000 Base64 chars ≈ 90 KB binary), same signing.
     */
    fun sendImage(to: String, rawBytes: ByteArray, geo: String? = null) {
        if (!handshakeDone) return
        val peerPubKey = peerPublicKeys[to]
            ?: DesktopCryptoManager.getPeerPublicKey(to)
            ?: run {
                pendingImages.add(PendingImage(to, rawBytes, geo))
                System.err.println("WebSocketClient: no peer key for $to — requesting, image queued")
                requestBundleFor(to)
                return
            }
        val peerPqKey = peerPqPublicKeys[to] ?: run {
            pendingImages.add(PendingImage(to, rawBytes, geo))
            System.err.println("WebSocketClient: no PQ peer key for $to — requesting, image queued")
            requestBundleFor(to)
            return
        }
        scope.launch {
            try {
                val packed   = DesktopCryptoManager.encryptImageBytes(peerPubKey, rawBytes, peerPqKey) ?: return@launch
                val base64   = Base64.getEncoder().encodeToString(packed)
                val imageId  = java.util.UUID.randomUUID().toString()
                val chunks   = base64.chunked(120_000)
                chunks.forEachIndexed { index, chunk ->
                    val signature = DesktopCryptoManager.signChunk(chunk, imageId, index)
                    sendAnonOrDirect(to, JSONObject().apply {
                        put("type",         "image_chunk")
                        put("from",         myFingerprint)
                        put("to",           to)
                        put("image_id",     imageId)
                        put("chunk_index",  index)
                        put("total_chunks", chunks.size)
                        put("data",         chunk)
                        put("signature",    signature)
                        put("encrypted",    true)
                        if (index == 0 && geo != null) put("geo", geo)
                    })
                    // Throttle: 5 chunks per batch, same as mobile
                    if (index % 5 == 4) kotlinx.coroutines.delay(30)
                }
            } catch (e: Exception) {
                System.err.println("WebSocketClient: sendImage failed — ${e.message}")
            }
        }
    }

    /**
     * Encrypt [rawBytes] for [to] and send as file_chunk stream.
     * Mirrors mobile MessengerService.sendFile(): same wire format,
     * same chunk size, same signing. Uses the same packed encryption
     * layout as sendImage() — the format is generic, not image-specific.
     */
    fun sendFile(to: String, fileName: String, rawBytes: ByteArray) {
        if (!handshakeDone) return
        val peerPubKey = peerPublicKeys[to]
            ?: DesktopCryptoManager.getPeerPublicKey(to)
            ?: run {
                pendingFileSends.add(PendingFileSend(to, fileName, rawBytes))
                System.err.println("WebSocketClient: no peer key for $to — requesting, file queued")
                requestBundleFor(to)
                return
            }
        val peerPqKey = peerPqPublicKeys[to] ?: run {
            pendingFileSends.add(PendingFileSend(to, fileName, rawBytes))
            System.err.println("WebSocketClient: no PQ peer key for $to — requesting, file queued")
            requestBundleFor(to)
            return
        }
        scope.launch {
            try {
                val packed  = DesktopCryptoManager.encryptImageBytes(peerPubKey, rawBytes, peerPqKey) ?: return@launch
                val base64  = Base64.getEncoder().encodeToString(packed)
                val fileId  = java.util.UUID.randomUUID().toString()
                val chunks  = base64.chunked(120_000)
                // Encrypted, not plaintext — mirrors the Android fix, see
                // docs/ISSUE_backup_identity_hijack.md, "file_name в открытом
                // виде в file_chunk". Computed once, reused across all chunks.
                val encryptedFileName = CryptoManager.encrypt(fileName, peerPubKey, peerPqKey)
                chunks.forEachIndexed { index, chunk ->
                    val signature = DesktopCryptoManager.signChunk(chunk, fileId, index)
                    sendAnonOrDirect(to, JSONObject().apply {
                        put("type",               "file_chunk")
                        put("from",               myFingerprint)
                        put("to",                 to)
                        put("file_id",            fileId)
                        put("encrypted_file_name", encryptedFileName)
                        put("chunk_index",        index)
                        put("total_chunks",       chunks.size)
                        put("data",               chunk)
                        put("signature",          signature)
                        put("encrypted",          true)
                    })
                    if (index % 5 == 4) kotlinx.coroutines.delay(30)
                }
            } catch (e: Exception) {
                System.err.println("WebSocketClient: sendFile failed — ${e.message}")
            }
        }
    }

    /**
     * Encrypt and send [voiceBase64] (WAV bytes, base64-encoded) as a single
     * native "voice" message — not chunked, unlike sendImage/sendFile, since
     * voice messages are short enough to fit in one frame. Mirrors Android's
     * MessengerService.sendVoice() wire format exactly (desktop/Android
     * symmetry audit, 2026-09-03).
     *
     * Previously Desktop only had sendFile() tagged with the magic filename
     * VoiceRecorder.FILE_NAME — Android doesn't recognize that convention
     * (shows up as a plain file attachment, not a voice bubble), and worse,
     * Android's native "voice" type had no receive handler on Desktop at
     * all, so a voice message sent BY an Android contact was silently
     * dropped (handleMessage()'s `when` had no matching branch).
     */
    /** Canonical V1 voice signature transcript (S6-58, external review
     *  2026-09-06) -- previously both platforms signed the bare `encrypted`
     *  ciphertext string with no domain separator, binding neither voiceId
     *  nor duration into the signature at all: a malicious/compromised relay
     *  could keep the authentic encrypted audio and its valid signature
     *  while relabeling voiceId/duration freely (S6-57 bounded the SHAPE of
     *  these fields, never their end-to-end authenticity). voiceId in
     *  particular doubles as a local blob-storage filename shared with every
     *  other attachment type on this platform ("$id.enc" under the same
     *  blobs dir) -- an unauthenticated relabel to an EXISTING attachment id
     *  would otherwise silently overwrite that attachment's file content.
     *  Delimiter concatenation is unambiguous here specifically because none
     *  of these three fields' canonical alphabets can ever contain ':':
     *  voiceId is validated as a canonical UUID (hex digits and hyphens
     *  only) before this is ever called, duration is rendered as a plain
     *  decimal integer, and encryptedData is standard-alphabet base64
     *  (CryptoManager.encrypt()'s own output -- A-Z/a-z/0-9/+//and padding
     *  '=', never ':'). Sender identity is already bound implicitly by which
     *  contact's public key verification selects; recipient identity is
     *  already bound implicitly by CryptoManager.encrypt()'s own per-
     *  recipient hybrid ECDH+ML-KEM encryption -- decrypting with any OTHER
     *  recipient's private key fails at the AES-GCM tag-check step
     *  regardless of this signature, so neither field needs to be repeated
     *  inside the transcript itself. Mirrors Android's identical
     *  voiceSignatureTranscript() byte-for-byte (desktop/Android symmetry
     *  audit). */
    private fun voiceSignatureTranscript(voiceId: String, duration: Int, encryptedData: String): String =
        "SUBROSA_VOICE_V1:$voiceId:$duration:$encryptedData"

    fun sendVoice(to: String, voiceBase64: String, voiceId: String, duration: Int) {
        val peerPubKey = peerPublicKeys[to] ?: DesktopCryptoManager.getPeerPublicKey(to)
        val peerPqKey = peerPqPublicKeys[to]
        if (peerPubKey == null || peerPqKey == null) {
            pendingVoiceSends.add(PendingVoiceSend(to, voiceBase64, voiceId, duration))
            System.err.println("WebSocketClient: no key(s) for $to — requesting, voice queued")
            requestBundleFor(to)
            return
        }
        scope.launch {
            try {
                val encrypted = CryptoManager.encrypt(voiceBase64, peerPubKey, peerPqKey)
                val signature = CryptoManager.sign(voiceSignatureTranscript(voiceId, duration, encrypted))
                sendAnonOrDirect(to, JSONObject().apply {
                    put("type", "voice")
                    put("from", myFingerprint)
                    put("to", to)
                    put("voice_id", voiceId)
                    put("voice_data", encrypted)
                    put("signature", signature)
                    put("duration", duration)
                })
            } catch (e: Exception) {
                System.err.println("WebSocketClient: sendVoice failed — ${e.message}")
            }
        }
    }

    /** Video circle (Telegram-style round video message) — ported from
     *  Android's MessengerService.sendVideoCircle(). Wire-compatible with
     *  Android's "video_chunk_batch": [videoBytes] (the muxed MP4, plaintext)
     *  is encrypted+packed the exact same way sendImage/sendFile already do
     *  (DesktopCryptoManager.encryptImageBytes — proven interoperable with
     *  Android's CryptoManager.encryptFile()+packEncryptedFile(), which is
     *  the SAME pair Android's image/file/video sends all use), base64-
     *  encoded, split into 120,000-char chunks, and batched
     *  CHUNK_BATCH_SIZE-at-a-time into one video_chunk_batch anon_message —
     *  see Android's own comment for why batching exists (anon tokens are
     *  single-use; one chunk per token would burn the whole shared pool on
     *  a single video). */
    fun sendVideoCircle(to: String, videoId: String, videoBytes: ByteArray, duration: Int) {
        val peerPubKey = peerPublicKeys[to] ?: DesktopCryptoManager.getPeerPublicKey(to)
        val peerPqKey = peerPqPublicKeys[to]
        if (peerPubKey == null || peerPqKey == null) {
            pendingVideoSends.add(PendingVideoSend(to, videoId, videoBytes, duration))
            System.err.println("WebSocketClient: no key(s) for $to — requesting, video circle queued")
            requestBundleFor(to)
            return
        }
        scope.launch {
            try {
                val packed = DesktopCryptoManager.encryptImageBytes(peerPubKey, videoBytes, peerPqKey)
                if (packed == null) {
                    System.err.println("WebSocketClient: sendVideoCircle: encrypt failed for $videoId")
                    return@launch
                }
                val base64 = java.util.Base64.getEncoder().encodeToString(packed)
                val chunks = base64.chunked(120_000)
                val CHUNK_BATCH_SIZE = 15
                chunks.chunked(CHUNK_BATCH_SIZE).forEachIndexed { batchIdx, batch ->
                    if (!handshakeDone) return@launch
                    val chunksJson = JSONArray()
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
                        put("from", myFingerprint)
                        put("to", to)
                        put("video_id", videoId)
                        put("total_chunks", chunks.size)
                        put("duration", duration)
                        put("encrypted", true)
                        put("chunks", chunksJson)
                    })
                    kotlinx.coroutines.delay(30L)
                }
            } catch (e: Exception) {
                System.err.println("WebSocketClient: sendVideoCircle failed — ${e.message}")
            }
        }
    }

    // ── Groups ─────────────────────────────────────────────────────────────────

    /** Canonical string signed/verified for a group's member+admin roster —
     * mirrors Android's MessengerService.rosterPayload(), same shared logic
     * between createGroup() (sign) and handleGroupCreate() (verify). */
    private fun rosterPayload(groupId: String, members: List<String>, admins: List<String>): String =
        "$groupId|${members.joinToString(",")}|${admins.joinToString(",")}"

    /** Canonical V1 transcript for group_create — mirrors Android's
     * MessengerService.groupCreatePayload() exactly (S6-64, external review
     * 2026-09-09): binds group_id + group_name + group_avatar + the key
     * blob, closing the gap where a relay could relabel a validly-signed
     * group_create (previously signed over encrypted_group_key alone) to a
     * fresh group_id with attacker-chosen name/avatar. See Android's own
     * comment for the full reasoning (sender identity already implicit via
     * which key verifies; length-prefixed free-text fields to rule out a
     * name/avatar boundary collision; no legacy fallback, both platforms
     * cut over together). */
    private fun groupCreatePayload(groupId: String, groupName: String, groupAvatar: String, encryptedGroupKey: String): String =
        "SUBROSA_GROUP_CREATE_V1:$groupId:${groupName.length}:$groupName:${groupAvatar.length}:$groupAvatar:$encryptedGroupKey"

    /** Canonical V1 transcript for the "member_keys" roster extension —
     * mirrors Android's MessengerService.memberKeysPayload() exactly. Signed
     * SEPARATELY from roster_signature (rosterPayload() above is left
     * untouched), so a group_create recipient can learn every fellow
     * member's EC + PQ public key and display name at join time, not just
     * the sender's own.
     *
     * Found live, 2026-09-20: two members added to the same group by a
     * THIRD party, who were never 1:1 contacts of each other, showed no
     * name for one another and had no working group-call connection
     * between them — call_group_join/call_group_answer signature
     * verification needs ChatStorage.getContactPublicKey(from), which was
     * simply never populated for a fellow member never directly contacted.
     * The group creator/admin already possesses every member's EC+PQ key at
     * this point regardless (encryptGroupKeyForMember() needs them for
     * every recipient), so this costs nothing to also broadcast. */
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
     * both an EC and a PQ key for [fingerprint] on hand. */
    private fun buildMemberKeyEntry(fingerprint: String): JSONObject? {
        val publicKey: String?
        val pqPublicKeyB64: String?
        if (fingerprint == myFingerprint) {
            publicKey = DesktopCryptoManager.getPublicKeyBase64()
            pqPublicKeyB64 = try { SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey } catch (e: Exception) { null }
        } else {
            publicKey = peerPublicKeys[fingerprint] ?: DesktopCryptoManager.getPeerPublicKey(fingerprint)
            pqPublicKeyB64 = peerPqPublicKeys[fingerprint]?.let { Base64.getEncoder().encodeToString(it) }
        }
        if (publicKey.isNullOrBlank() || pqPublicKeyB64.isNullOrBlank()) return null
        return JSONObject().apply {
            put("fingerprint", fingerprint)
            put("public_key", publicKey)
            put("pq_public_key", pqPublicKeyB64)
            put("name", if (fingerprint == myFingerprint) displayName else ChatStorage.getContactName(fingerprint))
        }
    }

    /** Creates a group locally and invites [members] (fingerprints, excluding self). */
    /** (Re)sends a group_create invite for [groupId] to [memberId], built
     *  fresh from the group's CURRENT persisted state — mirrors Android's
     *  identical helper. Shared by createGroup()'s initial fan-out,
     *  addGroupMember()'s own invite, and flushPendingGroupInvites()'s
     *  bootstrap retry. Returns false (nothing sent) if memberId's EC/PQ key
     *  still isn't cached — caller must queue a retry via
     *  pendingGroupInvites + requestBundleFor(memberId) in that case. */
    private fun sendGroupInviteTo(groupId: String, memberId: String): Boolean {
        val group = GroupManager.getGroup(groupId) ?: return false
        val groupKey = group.groupKey ?: return false
        val myFp = myFingerprint
        val memberKey = peerPublicKeys[memberId] ?: DesktopCryptoManager.getPeerPublicKey(memberId)
        val memberPqKey = peerPqPublicKeys[memberId]
        if (memberKey == null || memberPqKey == null) return false

        val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, memberKey, memberPqKey)
        val signature = CryptoManager.sign(groupCreatePayload(groupId, group.name, group.avatar, encryptedGroupKey))
        val rosterSignature = CryptoManager.sign(rosterPayload(groupId, group.members, group.admins))
        val memberKeyEntries = group.members.mapNotNull { buildMemberKeyEntry(it) }
        val memberKeysArray = JSONArray(memberKeyEntries)
        val memberKeysSignature = CryptoManager.sign(memberKeysPayload(groupId, memberKeyEntries))

        // Anon-routed like every other group fan-out (sendGroupMessage/
        // sendGroupReaction/etc. below) — was sent via webSocket?.send()
        // directly, bypassing token-routing AND the Sealed Sender wrap
        // (sealPacketForRecipient), so the full member roster/group name/
        // avatar and the from/to pairing were visible to the server in
        // the clear, unlike Android's sendAnonOrDirect()-routed original.
        // Found live via a desktop/Android literal wire-field audit,
        // 2026-09-11.
        sendAnonOrDirect(memberId, JSONObject().apply {
            put("type", "group_create")
            put("from", myFp)
            put("to", memberId)
            put("group_id", groupId)
            put("group_name", group.name)
            put("group_avatar", group.avatar)
            put("encrypted_group_key", encryptedGroupKey)
            put("signature", signature)
            put("members", org.json.JSONArray(group.members))
            put("admins", org.json.JSONArray(group.admins))
            put("roster_signature", rosterSignature)
            put("member_keys", memberKeysArray)
            put("member_keys_signature", memberKeysSignature)
        })
        return true
    }

    /** Queues [groupId]'s invite for [memberId] to be (re)sent once their
     *  EC/PQ key arrives, and kicks off the fetch. Mirrors Android's
     *  identical helper. */
    private fun queueGroupInviteRetry(groupId: String, memberId: String) {
        System.err.println("WebSocketClient: no key for $memberId — group invite deferred, requesting prekey bundle")
        pendingGroupInvites.getOrPut(memberId) { mutableSetOf() }.add(groupId)
        requestBundleFor(memberId)
    }

    /** Drains and (re)sends every group invite queued for [contactId] —
     *  call alongside the other flushPendingXxx() calls once a bundle
     *  response actually resolves their key. Mirrors Android's identical
     *  helper. */
    private fun flushPendingGroupInvites(contactId: String) {
        val groupIds = pendingGroupInvites.remove(contactId) ?: return
        groupIds.forEach { groupId ->
            if (!sendGroupInviteTo(groupId, contactId)) {
                pendingGroupInvites.getOrPut(contactId) { mutableSetOf() }.add(groupId)
            }
        }
    }

    fun createGroup(groupName: String, groupAvatar: String, members: List<String>) {
        if (!handshakeDone) return
        val myFp = myFingerprint
        val groupId = java.util.UUID.randomUUID().toString()
        val groupKey = GroupManager.generateGroupKey()
        val allMembers = (members + myFp).distinct()
        val admins = listOf(myFp)

        val group = Group(
            id = groupId,
            name = groupName,
            avatar = groupAvatar,
            members = allMembers,
            admins = admins,
            createdBy = myFp,
            groupKey = groupKey
        )
        GroupManager.saveGroup(group)

        // Bootstrap-and-retry for a member this device has never 1:1-chatted
        // with — see sendGroupInviteTo()'s own comment. Found live
        // 2026-09-21: this used to just log "no key ... cannot invite" and
        // drop the invite forever, while the group stayed saved locally with
        // that member already in its roster.
        members.forEach { memberId ->
            if (!sendGroupInviteTo(groupId, memberId)) {
                queueGroupInviteRetry(groupId, memberId)
            }
        }
    }

    /** Sends a text message to all members of [groupId]. */
    fun sendGroupMessage(groupId: String, messageId: String, text: String, replyToId: String? = null) {
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val groupKey = group.groupKey ?: return
        val myFp = myFingerprint
        val senderName = displayName

        val encryptedText = GroupManager.encryptGroupMessage(text, groupKey)
        val signature = CryptoManager.sign(encryptedText)

        group.members.filter { it != myFp }.forEach { memberId ->
            sendAnonOrDirect(memberId, JSONObject().apply {
                put("type", "group_message")
                put("from", myFp)
                put("to", memberId)
                put("group_id", groupId)
                put("message_id", messageId)
                put("sender_name", senderName)
                put("text", encryptedText)
                put("signature", signature)
                if (!replyToId.isNullOrBlank()) put("reply_to_id", replyToId)
            })
        }
    }

    /** Sends [imageBytes] to every member of [groupId]. Wire-compatible with
     *  Android's MessengerService.sendGroupImage() (group_image_batch): the
     *  whole base64'd image is encrypted ONCE with the group's shared AES
     *  key (not per-recipient ECDH like 1:1 sendImage()), then the resulting
     *  ciphertext base64 string is split into 120_000-char chunks, batched
     *  15 chunks per JSON message (one "chunks" array, not one message per
     *  chunk like 1:1), and fanned out per-recipient — each chunk signed
     *  individually with this device's identity key for sender auth. */
    fun sendGroupImage(groupId: String, imageBytes: ByteArray) {
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val groupKey = group.groupKey ?: return
        val myFp = myFingerprint
        val imageId = java.util.UUID.randomUUID().toString()
        val recipients = group.members.filter { it != myFp }
        scope.launch {
            try {
                val base64Image = Base64.getEncoder().encodeToString(imageBytes)
                val encrypted = GroupManager.encryptGroupMessage(base64Image, groupKey)
                val encryptedChunks = encrypted.chunked(120_000)
                val chunkBatchSize = 15
                encryptedChunks.chunked(chunkBatchSize).forEachIndexed { batchIdx, batch ->
                    val chunksJson = JSONArray()
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * chunkBatchSize + relIdx
                        val signature = DesktopCryptoManager.signChunk(chunk, imageId, index)
                        chunksJson.put(JSONObject().apply {
                            put("chunk_index", index)
                            put("data", chunk)
                            put("signature", signature)
                        })
                    }
                    recipients.forEach { memberId ->
                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_image_batch")
                            put("from", myFp)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("image_id", imageId)
                            put("total_chunks", encryptedChunks.size)
                            put("chunks", chunksJson)
                        })
                    }
                    kotlinx.coroutines.delay(30)
                }
            } catch (e: Exception) {
                System.err.println("WebSocketClient: sendGroupImage failed — ${e.message}")
            }
        }
    }

    /** Group photo avatar — one-shot base64 (a 128x128 JPEG at q85
     *  comfortably fits in one message), not chunked like image/file/video,
     *  but encrypted with the shared group AES key and fanned out
     *  per-member like every other group send, since the server has no
     *  concept of group membership to relay through. Also used to set an
     *  EMOJI avatar (as "EMOJI:$emoji") — see handleGroupAvatarUpdate()'s
     *  own comment. Admin-only: enforced on receive. Mirrors Android's
     *  identical sendGroupAvatarUpdate(). Group chat previously had no way
     *  to set a photo avatar, or to notify other members of an emoji
     *  change, at all. New 2026-09-21. */
    fun sendGroupAvatarUpdate(groupId: String, avatarPayload: String) {
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val groupKey = group.groupKey ?: return
        val myFp = myFingerprint
        val recipients = group.members.filter { it != myFp }
        scope.launch {
            try {
                val encrypted = GroupManager.encryptGroupMessage(avatarPayload, groupKey)
                val signature = CryptoManager.sign(encrypted)
                recipients.forEach { memberId ->
                    sendAnonOrDirect(memberId, JSONObject().apply {
                        put("type", "group_avatar_update")
                        put("from", myFp)
                        put("to", memberId)
                        put("group_id", groupId)
                        put("avatar", encrypted)
                        put("signature", signature)
                    })
                }
            } catch (e: Exception) {
                System.err.println("WebSocketClient: sendGroupAvatarUpdate failed — ${e.message}")
            }
        }
    }

    /** Group file send — same batched-chunk-per-member-fanout shape as
     *  sendGroupImage() above, plus the file name encrypted with the group
     *  key (mirrors sendFile()'s encrypted_file_name privacy fix). Wire-
     *  compatible with Android's sendGroupFile() (group_file_batch). */
    fun sendGroupFile(groupId: String, fileName: String, fileBytes: ByteArray) {
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val groupKey = group.groupKey ?: return
        val myFp = myFingerprint
        val fileId = java.util.UUID.randomUUID().toString()
        val recipients = group.members.filter { it != myFp }
        scope.launch {
            try {
                val base64File = Base64.getEncoder().encodeToString(fileBytes)
                val encrypted = GroupManager.encryptGroupMessage(base64File, groupKey)
                val encryptedFileName = GroupManager.encryptGroupMessage(fileName, groupKey)
                val encryptedChunks = encrypted.chunked(120_000)
                val chunkBatchSize = 15
                encryptedChunks.chunked(chunkBatchSize).forEachIndexed { batchIdx, batch ->
                    val chunksJson = JSONArray()
                    batch.forEachIndexed { relIdx, chunk ->
                        val index = batchIdx * chunkBatchSize + relIdx
                        val signature = DesktopCryptoManager.signChunk(chunk, fileId, index)
                        chunksJson.put(JSONObject().apply {
                            put("chunk_index", index)
                            put("data", chunk)
                            put("signature", signature)
                        })
                    }
                    recipients.forEach { memberId ->
                        sendAnonOrDirect(memberId, JSONObject().apply {
                            put("type", "group_file_batch")
                            put("from", myFp)
                            put("to", memberId)
                            put("group_id", groupId)
                            put("file_id", fileId)
                            put("encrypted_file_name", encryptedFileName)
                            put("total_chunks", encryptedChunks.size)
                            put("chunks", chunksJson)
                        })
                    }
                    kotlinx.coroutines.delay(30)
                }
            } catch (e: Exception) {
                System.err.println("WebSocketClient: sendGroupFile failed — ${e.message}")
            }
        }
    }

    /** Deletes [messageId] in [groupId] for every other member (fan-out, anon-routed like sendGroupMessage). */
    fun sendGroupDeleteMessage(groupId: String, messageId: String) {
        // Signed as of S6-54 (external review 2026-09-06) -- see sendDelete()'s
        // own comment. "SUBROSA_GROUP_MESSAGE_DELETE_V1:" is a DIFFERENT
        // domain separator from direct message_delete's, and the transcript
        // binds BOTH groupId and messageId, so a signature valid for a
        // deletion in one group cannot be replayed against another group
        // that happens to reference the same message id.
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val myFp = myFingerprint
        val signature = CryptoManager.sign("SUBROSA_GROUP_MESSAGE_DELETE_V1:$groupId:$messageId")
        group.members.filter { it != myFp }.forEach { memberId ->
            sendAnonOrDirect(memberId, JSONObject().apply {
                put("type", "group_message_delete")
                put("from", myFp)
                put("to", memberId)
                put("group_id", groupId)
                put("message_id", messageId)
                put("signature", signature)
            })
        }
    }

    /** Fan-out a group reaction to every other member (anon-routed like
     *  sendGroupMessage). Mirrors Android MessengerService.sendGroupReaction()
     *  exactly: unlike the direct 1:1 `reaction`, the emoji is sent in
     *  PLAINTEXT (group content is protected by the shared group key at the
     *  message level, and a reaction adds no new secret), and the signature is
     *  over the bare plaintext emoji so each recipient can authenticate the
     *  reactor against their identity key. */
    fun sendGroupReaction(groupId: String, messageId: String, emoji: String) {
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val myFp = myFingerprint
        val signature = CryptoManager.sign(emoji)
        group.members.filter { it != myFp }.forEach { memberId ->
            sendAnonOrDirect(memberId, JSONObject().apply {
                put("type", "group_reaction")
                put("from", myFp)
                put("to", memberId)
                put("group_id", groupId)
                put("message_id", messageId)
                put("emoji", emoji)
                put("signature", signature)
            })
        }
    }

    /** Removes [memberId] from [groupId] and notifies remaining members. Admin only. */
    fun notifyMemberRemoved(groupId: String, memberId: String) {
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val myFp = myFingerprint
        val signature = CryptoManager.sign("$groupId:$memberId")

        group.members.filter { it != myFp && it != memberId }.forEach { recipient ->
            sendAnonOrDirect(recipient, JSONObject().apply {
                put("type", "group_member_removed")
                put("from", myFp)
                put("to", recipient)
                put("group_id", groupId)
                put("removed_member", memberId)
                put("signature", signature)
            })
        }
    }

    /** Rotates the group key (call after removing a member) and redistributes it. Admin only. */
    /** Adds [newMemberId] to an already-running group — was entirely
     *  missing on Desktop (no send-side counterpart to the already-existing
     *  handleGroupMemberAdded() receive handler, GroupManager.addMember(),
     *  and "Покинуть группу"). Sends the new member a group_create carrying
     *  the CURRENT (post-add) roster, and tells every other existing member
     *  via group_member_added so their local rosters stay in sync — mirrors
     *  Android's MessengerService.addGroupMember(), with one deliberate
     *  correction: Android's own addGroupMember() signs the group_create it
     *  sends with the pre-S6-64 bare `sign(encryptedGroupKey)` transcript,
     *  while BOTH platforms' "group_create" receive handlers now require
     *  the hardened groupCreatePayload() transcript unconditionally (no
     *  legacy fallback — see that function's own comment: "both platforms
     *  must ship this together"). Porting Android's stale call site
     *  verbatim would produce an invitation that fails verification on
     *  every receiver, Android included — this is a live bug in the
     *  reference implementation, not a deliberate protocol difference
     *  (flagged separately for an Android-side fix). Desktop's own
     *  createGroup() already uses the correct hardened transcript, so this
     *  function does too, for internal consistency and so it actually
     *  works. Found in the 2026-09-12 full-logic audit continuation. */
    fun addGroupMember(groupId: String, newMemberId: String) {
        if (!handshakeDone) return
        val myFp = myFingerprint
        val group = GroupManager.getGroup(groupId) ?: return
        if (!GroupManager.isAdmin(groupId, myFp)) {
            System.err.println("WebSocketClient: addGroupMember: not admin of $groupId")
            return
        }
        if (group.groupKey == null) return
        val preAddMembers = group.members // captured before addMember() below mutates the roster
        GroupManager.addMember(groupId, myFp, newMemberId)
        val updatedGroup = GroupManager.getGroup(groupId) ?: return

        // Rotate the group key on add too, for backward secrecy (OPEN-7,
        // docs/KNOWN_SECURITY_ISSUES.md) — previously only removal rotated,
        // so a new member got the CURRENT key and could decrypt any
        // historical ciphertext they separately obtained from before
        // joining. Saved locally BEFORE sendGroupInviteTo() below so the new
        // member's own group_create invite carries the rotated key (it
        // re-reads group.groupKey fresh from storage); sendGroupKeyRotation()
        // pushes the same new key to every OTHER existing member via the
        // identical per-member-encrypted send the removal path
        // (rotateGroupKey()) already uses. preAddMembers (captured above,
        // before the roster mutated) so the brand-new member doesn't also
        // get a redundant/premature group_key_rotation of their own.
        val newKey = GroupManager.generateGroupKey()
        GroupManager.saveGroup(updatedGroup.copy(groupKey = newKey))
        sendGroupKeyRotation(groupId, newKey, preAddMembers.filter { it != myFp })

        // Bootstrap-and-retry for a member this device has never 1:1-chatted
        // with — see sendGroupInviteTo()'s own comment.
        if (!sendGroupInviteTo(groupId, newMemberId)) {
            queueGroupInviteRetry(groupId, newMemberId)
        }

        // Existing members previously never learned about the new member at
        // all — symmetric to notifyMemberRemoved(). Also now carries the new
        // member's own key/name (single entry) so existing members can
        // actually verify signed frames FROM them (e.g. a group call join).
        val addSignature = CryptoManager.sign("$groupId:add:$newMemberId")
        val newMemberKeyEntry = buildMemberKeyEntry(newMemberId)
        val newMemberKeysArray = JSONArray(listOfNotNull(newMemberKeyEntry))
        val newMemberKeysSignature = CryptoManager.sign(memberKeysPayload(groupId, listOfNotNull(newMemberKeyEntry)))
        updatedGroup.members.filter { it != myFp && it != newMemberId }.forEach { memberId ->
            sendAnonOrDirect(memberId, JSONObject().apply {
                put("type", "group_member_added")
                put("from", myFp)
                put("to", memberId)
                put("group_id", groupId)
                put("new_member", newMemberId)
                put("new_member_name", ChatStorage.getContactName(newMemberId))
                put("signature", addSignature)
                put("member_keys", newMemberKeysArray)
                put("member_keys_signature", newMemberKeysSignature)
            })
        }
    }

    fun rotateGroupKey(groupId: String) {
        if (!handshakeDone) return
        val group = GroupManager.getGroup(groupId) ?: return
        val myFp = myFingerprint
        val newKey = GroupManager.generateGroupKey()
        GroupManager.saveGroup(group.copy(groupKey = newKey))
        sendGroupKeyRotation(groupId, newKey, group.members.filter { it != myFp })
    }

    /** Per-member-encrypted `group_key_rotation` send, shared by
     *  rotateGroupKey() (member removal) and addGroupMember() (member
     *  addition, OPEN-7) — same wire message either way, just a different
     *  caller-supplied key/recipient list. Does NOT generate the key or
     *  touch [GroupManager] state itself; callers own that (they need
     *  different member-list semantics — post-removal vs pre-addition —
     *  around the save). */
    private fun sendGroupKeyRotation(groupId: String, newKey: ByteArray, recipients: List<String>) {
        recipients.forEach { memberId ->
            val memberKey = peerPublicKeys[memberId] ?: DesktopCryptoManager.getPeerPublicKey(memberId)
            val memberPqKey = peerPqPublicKeys[memberId]
            if (memberKey == null || memberPqKey == null) return@forEach
            val encryptedNewKey = GroupManager.encryptGroupKeyForMember(newKey, memberKey, memberPqKey)
            // groupId bound into the signed payload (S6-60, mirrors
            // Android's own CRYPTO-06 fix) — see handleGroupKeyRotation()'s
            // own comment for why encrypted_new_key alone isn't enough.
            val signature = CryptoManager.sign("$groupId:$encryptedNewKey")
            sendAnonOrDirect(memberId, JSONObject().apply {
                put("type", "group_key_rotation")
                put("from", myFingerprint)
                put("to", memberId)
                put("group_id", groupId)
                put("encrypted_new_key", encryptedNewKey)
                put("signature", signature)
            })
        }
    }

    // ── Calls ──────────────────────────────────────────────────────────────────

    /** Sends a call-signaling message, routed anonymously via sendAnonOrDirect for
     *  all types — including call_end, whose one-shot-no-redundancy reliability gap
     *  is covered by DesktopCallManager's in-band "bye" over the P2P heartbeat
     *  DataChannel, sent right before this call. See MessengerService.kt's
     *  call_signal handler (Android) for the full history. */
    fun sendCallSignal(data: JSONObject) {
        if (!handshakeDone) return
        val to = data.optString("to")
        sendAnonOrDirect(to, data)
    }

    // ── Channels ───────────────────────────────────────────────────────────────

    fun createChannel(name: String, description: String, avatar: String) {
        if (!handshakeDone) return
        webSocket?.send(JSONObject().apply {
            put("type", "channel_create")
            put("channel_name", name)
            put("channel_description", description)
            put("channel_avatar", avatar)
        }.toString())
    }

    fun subscribeToChannel(channelId: String) {
        if (!handshakeDone) return
        webSocket?.send(JSONObject().apply {
            put("type", "channel_subscribe")
            put("channel_id", channelId)
        }.toString())
    }

    fun unsubscribeFromChannel(channelId: String) {
        if (!handshakeDone) return
        webSocket?.send(JSONObject().apply {
            put("type", "channel_unsubscribe")
            put("channel_id", channelId)
        }.toString())
    }

    /** Posts to a channel. Server enforces that only the channel admin may post. */
    fun postToChannel(channelId: String, text: String) {
        if (!handshakeDone) return
        webSocket?.send(JSONObject().apply {
            put("type", "channel_post")
            put("channel_id", channelId)
            put("text", text)
            put("id", java.util.UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())
        }.toString())
    }

    // ── Private crypto/session helpers ────────────────────────────────────────

    /** Initiate an X3DH session with [bundle] and send the first message as session_init. */
    private fun initiateAndSend(
        bundle: SessionKeyManager.PrekeyBundle,
        to: String, text: String, msgId: String
    ) {
        try {
            val (_, x3dhHeader)    = SessionKeyManager.initiateSession(to, bundle)
            markChannelReady(to)
            onChannelReady?.invoke(to)
            val (encrypted, sHdr) = CryptoManager.encryptWithForwardSecrecy(to, text)
            val sessionInitPacket = JSONObject().apply {
                put("type",           "session_init")
                // For a direct send the server overwrites this with the
                // authenticated sender's own identity anyway — but for an
                // anon_message-routed send (bootstrap token or a regular
                // per-contact token) the server relays payload verbatim
                // without ever knowing who sent it, so the receiving client
                // needs "from" embedded here to know who to reply to. This
                // was missing until a live two-process test actually routed
                // a session_init through anon_message for the first time
                // and the receiver failed to parse it — no prior test had
                // exercised this specific path before today.
                put("from",           myFingerprint)
                put("to",             to)
                put("id",             msgId)
                put("sender_ik",      CryptoManager.getPublicKeyString())
                put("x3dh_header",   x3dhHeader)
                put("session_header", sHdr)
                put("text",           encrypted)
                put("signature",      CryptoManager.sign(encrypted))
            }
            val bootstrapToken = pendingBootstrapTokens.remove(to)
            // sendViaToken()'s return value MUST be checked — was previously
            // fire-and-forget, so a seal failure or definite local send
            // failure inside it silently dropped the session_init entirely
            // (the bootstrap token is single-use and already consumed above
            // either way, so there was nothing left to retry it with). A
            // false result here falls through to exactly the same recovery
            // path already used when there was no bootstrap token at all —
            // a fresh routing token/mailbox path, not a reuse of the failed
            // one. Found in the 2026-09-13 full-logic audit.
            val sentViaBootstrap = bootstrapToken != null && sendViaToken(bootstrapToken, sessionInitPacket)
            if (!sentViaBootstrap) {
                if (bootstrapToken != null) {
                    System.err.println("WebSocketClient: bootstrap-token session_init send failed for $to — falling back to regular routing")
                }
                when {
                    // No anon/bootstrap token available for this brand-new
                    // session — mirrors Android's MessengerService.kt isFirst
                    // branch/depositSessionInitViaMailbox(): deposit the FULL
                    // session_init sub-packet (x3dh header + forward-secrecy
                    // ciphertext) via the mailbox directly, rather than routing
                    // through sendAnonOrDirect(), which would just queue it and
                    // wait for a token exchange to complete first — an exchange
                    // that ITSELF bootstraps via the exact same mailbox. That
                    // turns the very first message to a new contact into two
                    // sequential mailbox round trips instead of one, and was
                    // missing entirely from Desktop. Found in the 2026-09-12
                    // full-logic audit ("1:1 has bugs at every step") — this is
                    // precisely the fresh-contact/first-message scenario this
                    // session's other mailbox-bootstrap fixes were already
                    // circling around.
                    AnonTokenManager.getContactTokens(to).isEmpty() -> {
                        val mailboxTag   = AnonTokenManager.getContactMailboxTag(to)
                        val recipientKey = peerPublicKeys[to] ?: ChatStorage.getContactPublicKey(to)
                        if (mailboxTag != null && recipientKey != null) {
                            depositSessionInitViaMailbox(to, mailboxTag, recipientKey, sessionInitPacket)
                        } else {
                            sendAnonOrDirect(to, sessionInitPacket)
                        }
                    }
                    else -> sendAnonOrDirect(to, sessionInitPacket)
                }
            }
        } catch (e: Exception) {
            System.err.println("WebSocketClient: X3DH initiate failed for $to — ${e.message}")
            // Fall back to legacy if we already know the peer's public key
            peerPublicKeys[to]?.let { sendLegacy(to, text, msgId) }
        }
    }

    /** Delivers a full session_init sub-packet (x3dh header + forward-secrecy
     *  ciphertext) anonymously via mailbox when no anon/bootstrap token is
     *  available yet — see initiateAndSend()'s own comment. Mirrors
     *  Android's MessengerService.depositSessionInitViaMailbox() exactly;
     *  the receiving end's handleMailboxResult() already unwraps
     *  "session_init_packet" the same way Android's does. */
    private fun depositSessionInitViaMailbox(
        to: String, mailboxTag: String, publicKey: String, sessionInitPacket: JSONObject
    ) {
        try {
            val inner = JSONObject().apply {
                put("from",   myFingerprint)
                put("name",   UserStorage.getUsername())
                put("text",   "__beacon_session_init__")
                put("session_init_packet", sessionInitPacket)
                put("id",     java.util.UUID.randomUUID().toString())
            }
            // End-to-end identity signature over the whole envelope,
            // including the nested session_init_packet (its own internal
            // signature is just data from this transcript's point of view —
            // recursion in mailboxTranscript() covers it). See
            // mailboxTranscript()'s own comment.
            inner.put("signature", CryptoManager.sign(mailboxTranscript(inner)))
            val blob = CryptoManager.encryptClassicalOnly(inner.toString(), publicKey)
            sendWs(addPadding(JSONObject().apply {
                put("type", "mailbox_put")
                put("tag",  mailboxTag)
                put("blob", blob)
            }).toString())
        } catch (e: Exception) {
            System.err.println("WebSocketClient: depositSessionInitViaMailbox error — ${e.message}")
        }
    }

    /** Encrypt with legacy ephemeral-ECDH and send as a plain "message". */
    private fun sendLegacy(to: String, text: String, msgId: String) {
        val peerKey = peerPublicKeys[to] ?: run {
            System.err.println("WebSocketClient: no peer key for $to, queuing")
            enqueueAndRequestBundle(to, text, msgId)
            return
        }
        val peerPqKey = peerPqPublicKeys[to] ?: run {
            System.err.println("WebSocketClient: no PQ peer key for $to, queuing")
            enqueueAndRequestBundle(to, text, msgId)
            return
        }
        val encrypted = runCatching { CryptoManager.encrypt(text, peerKey, peerPqKey) }.getOrElse {
            System.err.println("WebSocketClient: legacy encrypt failed for $to — ${it.message}")
            return
        }
        sendAnonOrDirect(to, JSONObject().apply {
            put("type",      "message")
            put("from",      myFingerprint)
            put("to",        to)
            put("text",      encrypted)
            put("id",        msgId)
            put("signature", CryptoManager.sign(encrypted))
            put("protocol_version", 1)
        })
    }

    private const val MAX_BATCH_BUNDLE_TARGETS = 10

    /** Queue a message and, if not already requested, fetch the peer's prekey bundle.
     *  Uses the anonymous batched fetch (real target padded with decoys drawn from
     *  our own contacts) when we have at least one contact to use as a decoy —
     *  a batch of size 1 provides no cover, so a lone/contact-less new install
     *  falls back to the direct, non-anonymous fetch instead of pretending
     *  otherwise. See requestPrekeyBundlesBatch(). */
    private fun enqueueAndRequestBundle(to: String, text: String, msgId: String) {
        messageQueue.getOrPut(to) { mutableListOf() }.add(QueuedMessage(text, msgId))
        requestBundleFor(to)
    }

    /** Fetches [to]'s prekey bundle if not already requested — shared by the text
     *  queue (enqueueAndRequestBundle) and the image/file queues (sendImage/
     *  sendFile), so any of them can trigger the same anonymous batched fetch. */
    private fun requestBundleFor(to: String) {
        val now = System.currentTimeMillis()
        val lastAttempt = lastPrekeyFetchAttempt[to] ?: 0L
        if (now - lastAttempt < 30_000L) return
        if (bundleRequested.add(to)) {
            lastPrekeyFetchAttempt[to] = now
            val decoys = ChatStorage.getContacts().filter { it != to }
            if (decoys.isNotEmpty()) {
                requestPrekeyBundlesBatch(to, decoys)
            } else {
                webSocket?.send(JSONObject().apply {
                    put("type",   "get_prekey_bundle")
                    put("target", to)
                }.toString())
            }
        }
    }

    private fun flushPendingImages(forContact: String) {
        val toFlush = pendingImages.filter { it.to == forContact }
        pendingImages.removeAll { it.to == forContact }
        toFlush.forEach { sendImage(it.to, it.rawBytes, it.geo) }
    }

    private fun flushPendingFileSends(forContact: String) {
        val toFlush = pendingFileSends.filter { it.to == forContact }
        pendingFileSends.removeAll { it.to == forContact }
        toFlush.forEach { sendFile(it.to, it.fileName, it.rawBytes) }
    }

    private fun flushPendingVoiceSends(forContact: String) {
        val toFlush = pendingVoiceSends.filter { it.to == forContact }
        pendingVoiceSends.removeAll { it.to == forContact }
        toFlush.forEach { sendVoice(it.to, it.voiceBase64, it.voiceId, it.duration) }
    }

    private fun flushPendingVideoSends(forContact: String) {
        val toFlush = pendingVideoSends.filter { it.to == forContact }
        pendingVideoSends.removeAll { it.to == forContact }
        toFlush.forEach { sendVideoCircle(it.to, it.videoId, it.rawBytes, it.duration) }
    }

    /** Anonymous prekey-bundle fetch: [realTarget] padded with up to
     *  [MAX_BATCH_BUNDLE_TARGETS]-1 decoys drawn from [availableDecoys] (our own
     *  contacts — they already legitimately fetch each other's bundles sometimes,
     *  so a decoy fetch is indistinguishable from genuine activity; self-created
     *  "ghost" accounts were considered and rejected — an account that never
     *  carries real traffic is eventually distinguishable as always-a-decoy).
     *  The server never learns which of the batch was the real one. */
    private fun requestPrekeyBundlesBatch(realTarget: String, availableDecoys: List<String>) {
        val decoys = availableDecoys.shuffled().take(MAX_BATCH_BUNDLE_TARGETS - 1)
        val targets = (decoys + realTarget).shuffled()
        webSocket?.send(JSONObject().apply {
            put("type", "get_prekey_bundles_batch")
            put("targets", JSONArray(targets))
        }.toString())
    }

    /** Drain the message queue for [to] after a session or peer key became
     *  available. Does NOT touch bundleRequested — found in the 2026-09-13
     *  bundleRequested lifecycle audit: this returned early whenever
     *  messageQueue had nothing queued for [to] (an image/file/voice-only
     *  bundle fetch, with no text message ever queued), silently skipping
     *  its own bundleRequested.remove(to) call — the gate then stayed set
     *  forever, permanently no-opping every future requestBundleFor(to) for
     *  that contact. Cleanup is now the sole responsibility of the
     *  prekey_bundle_response/prekey_bundles_batch_response handlers
     *  themselves (via try/finally), independent of whether this function
     *  finds anything to drain. */
    private fun drainQueue(to: String) {
        val queued = messageQueue.remove(to) ?: return
        for (msg in queued) trySend(to, msg.text, msg.msgId)
    }

    /** Upload our prekey bundle to the server so peers can initiate X3DH with us. */
    private fun publishPrekeyBundle() {
        try {
            val bundleJson = SessionKeyManager.generatePrekeyBundle()
            webSocket?.send(JSONObject().apply {
                put("type",   "publish_prekey_bundle")
                put("bundle", bundleJson)
            }.toString())
            println("WebSocketClient: prekey bundle published")
        } catch (e: Exception) {
            System.err.println("WebSocketClient: failed to publish prekey bundle — ${e.message}")
        }
    }

    // ── Connection logic ──────────────────────────────────────────────────────

    private suspend fun doConnect() {
        if (isConnecting) return
        isConnecting = true
        try {
            val serverUrl = DesktopStorage.get("server_url")
                ?: DEFAULT_SERVER_URL

            if (serverUrl.contains(".onion") || UserStorage.getTorEnabled()) {
                if (!DesktopTorManager.isAvailable()) {
                    // .onion addresses aren't resolvable without Tor at all,
                    // and the Tor-everything toggle needs the same local
                    // proxy — fail fast with a clear message instead of a
                    // cryptic DNS/connect error, and let the normal
                    // reconnect backoff retry (the user may still be
                    // starting Tor).
                    val reason = if (serverUrl.contains(".onion")) "server is a .onion address"
                                 else "\"Route via Tor\" is enabled"
                    System.err.println(
                        "WebSocketClient: $reason but no local Tor SOCKS proxy " +
                        "was found on ${DesktopTorManager.SOCKS_HOST}:${DesktopTorManager.SOCKS_PORT} " +
                        "(or ${DesktopTorManager.SOCKS_PORT_TOR_BROWSER}) — start Tor/Tor Browser first"
                    )
                    isConnecting = false
                    scheduleReconnect()
                    return
                }
                val request = Request.Builder().url(serverUrl).build()
                webSocket = torClient.newWebSocket(request, Listener())
            } else {
                val request = Request.Builder().url(serverUrl).build()
                webSocket = client.newWebSocket(request, Listener())
            }
        } catch (e: Exception) {
            System.err.println("WebSocketClient: connect failed — ${e.message}")
            isConnecting = false
            scheduleReconnect()
        }
    }

    private fun scheduleReconnect() {
        val delayMs = minOf(30_000L, 2_000L * (1 shl minOf(reconnectAttempts, 4)))
        reconnectAttempts++
        scope.launch {
            delay(delayMs)
            if (!_connected.value) doConnect()
        }
    }

    // ── Sealed Sender — identity-less anon_channel connection ──────────────────
    // Ported from Android's MessengerService.kt (desktop/Android symmetry
    // audit, 2026-09-03) — see docs/PROTOCOL_STATE_MACHINE.md §3 and
    // docs/SECURITY_INVARIANTS.md #2-4 for the full rationale.

    /** Opens the identity-less anon_channel connection — same server, but
     *  skips challenge_response/register entirely: the server never learns
     *  a public_key/fingerprint for this socket (see server.py's
     *  "anon_channel" handshake branch). Called once the main connection is
     *  up; a failure here just leaves anonChannelReady false —
     *  sendOnAnonChannelNow() queues rather than falling back to the
     *  identified main socket, and keeps retrying opportunistically. */
    private fun connectAnonChannel() {
        // Guard against two calls racing (called from both connect()'s
        // post-register continuation and "handshake_ok") while a connect
        // attempt is still in flight, or redundantly reopening an already-
        // working connection.
        if (anonChannelConnecting || anonChannelReady) return
        anonChannelConnecting = true
        anonChannelLastAttemptMs = System.currentTimeMillis()
        // Random delay before actually opening the socket — without this,
        // anon_channel would open a fixed, near-immediate interval after
        // the main socket every time, which is itself a correlation
        // signal: an observer just watching connection-accept timestamps
        // (no IP, no TLS detail, no application data needed) could pair
        // "these two connections opened within ~1s of each other" with
        // high confidence. 0-3s spread is cheap and doesn't meaningfully
        // delay anon_channel's actual availability (sendOnAnonChannelNow()
        // already queues rather than blocking while it's not ready).
        scope.launch {
            delay((0L..3000L).random())
            doConnectAnonChannel()
        }
    }

    private fun doConnectAnonChannel() {
        val serverUrl = DesktopStorage.get("server_url") ?: DEFAULT_SERVER_URL
        val viaTor = serverUrl.contains(".onion") || UserStorage.getTorEnabled()
        if (viaTor && !DesktopTorManager.isAvailable()) {
            anonChannelConnecting = false
            return
        }
        val request = Request.Builder().url(serverUrl).build()

        val listener = object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {}

            override fun onMessage(ws: WebSocket, text: String) {
                try {
                    val json = JSONObject(text)
                    when (json.optString("type")) {
                        // Required first frame on every connection regardless
                        // of what handshake follows — anon_channel doesn't
                        // sign it, just acknowledges with its own type.
                        "challenge" -> ws.send(JSONObject().apply { put("type", "anon_channel") }.toString())
                        "anon_channel_ok" -> {
                            anonChannelReady = true
                            anonChannelConnecting = false
                            println("WebSocketClient: anon_channel ready")
                            // Flush anything that queued up while this
                            // connection wasn't ready.
                            var queued = anonChannelPendingQueue.poll()
                            while (queued != null) {
                                ws.send(queued)
                                queued = anonChannelPendingQueue.poll()
                            }
                        }
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: anon_channel onMessage error — ${e.message}")
                }
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                System.err.println("WebSocketClient: anon_channel error — ${t.message}")
                anonChannelReady = false
                anonChannelConnecting = false
                if (anonWebSocket === ws) anonWebSocket = null
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                anonChannelReady = false
                anonChannelConnecting = false
                if (anonWebSocket === ws) anonWebSocket = null
            }
        }

        val c = if (viaTor) anonTorClient else anonClient
        anonWebSocket = c.newWebSocket(request, listener)
    }

    private fun disconnectAnonChannel() {
        anonWebSocket?.close(1000, "main disconnect")
        anonWebSocket = null
        anonChannelReady = false
        anonChannelConnecting = false
    }

    /** Anon-channel equivalent of sendWs() — routes anon_message traffic
     *  (real and cover-traffic decoys alike, see startCoverTraffic()) off
     *  the identified main socket. In AGGRESSIVE mode, queues instead of
     *  sending immediately — see startCoverTraffic()'s paced drain of
     *  anonOutboundQueue, mirroring what sendWs() already does for
     *  outboundQueue on the main socket. Without this, a real anon_message
     *  would fire the moment it's sent while decoys stayed on the fixed
     *  cadence — the timing itself becomes a tell, defeating AGGRESSIVE
     *  mode's actual purpose for anon_message traffic specifically. */
    private fun sendOnAnonChannel(json: String): Boolean {
        val mode = UserStorage.getCoverTrafficMode()
        if (mode == UserStorage.CoverTrafficMode.AGGRESSIVE && _connected.value) {
            if (!anonOutboundQueue.offer(json)) {
                System.err.println("WebSocketClient: anonOutboundQueue full — sending directly")
                return sendOnAnonChannelNow(json)
            }
            return true
        }
        return sendOnAnonChannelNow(json)
    }

    /** Unpaced send — used directly by sendOnAnonChannel() outside
     *  AGGRESSIVE mode, and by startCoverTraffic()'s paced drain loop
     *  (which already IS the pacing, so it must bypass sendOnAnonChannel()'s
     *  own queueing to avoid queuing a queue). Deliberately never falls back
     *  to sendWs() (the identified main socket) when the anon channel isn't
     *  ready — that would let a real anon_message silently go out fully
     *  identified, the exact "anonymous → identified fail-open" this
     *  connection exists to prevent. Queues into anonChannelPendingQueue and
     *  opportunistically (re)connects (throttled to once per 10s) instead —
     *  flushed once anon_channel_ok actually arrives. */
    private fun sendOnAnonChannelNow(json: String): Boolean {
        val ws = anonWebSocket
        if (anonChannelReady && ws != null) {
            return ws.send(json)
        }
        if (!anonChannelConnecting && System.currentTimeMillis() - anonChannelLastAttemptMs > 10_000) {
            connectAnonChannel()
        }
        if (!anonChannelPendingQueue.offer(json)) {
            System.err.println("WebSocketClient: anonChannelPendingQueue full — packet dropped")
            return false
        }
        return true
    }

    private fun sendAnonMessageWs(anonPacket: JSONObject): Boolean =
        sendOnAnonChannel(addPadding(anonPacket).toString())

    // ── WebSocket listener ────────────────────────────────────────────────────

    private class Listener : WebSocketListener() {

        override fun onOpen(ws: WebSocket, response: Response) {
            isConnecting = false
            webSocket = ws
            // Do NOT send anything here — wait for server's "challenge" first
        }

        override fun onMessage(ws: WebSocket, text: String) {
            scope.launch {
                // Some handlers (reaction/disappear_timer, mirroring Android)
                // THROW on a bad/missing signature so the anon_delivery path
                // suppresses its ack — on the direct socket path there's no
                // ack to suppress, but the throw must still not escape the
                // coroutine as an uncaught exception. Same defensive wrapping
                // the anon_delivery branch already uses around handleMessage().
                try {
                    handleMessage(text, ws)
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: handleMessage error — ${e.message}")
                }
            }
        }

        override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
            // A failure callback for an already-superseded socket (a new
            // doConnect() already reassigned `webSocket` to a newer
            // instance — newWebSocket() returns synchronously, so
            // `webSocket` always points at the latest attempt before any
            // of its callbacks can fire) must not tear down the NEW
            // connection's state. Found in the 2026-09-13 registration
            // state-machine audit.
            if (ws !== webSocket) return
            System.err.println("WebSocketClient: onFailure — ${t.message}")
            isConnecting  = false
            handshakeDone = false
            _connected.value = false
            stopCoverTraffic()
            disconnectAnonChannel()
            // A request in flight on the now-dead socket will never get its
            // response — leaving it in bundleRequested would permanently
            // no-op every future requestBundleFor() for that contact on the
            // NEW connection, since the (stale) response it's waiting for
            // can never arrive. Found in the 2026-09-13 bundleRequested
            // lifecycle audit.
            bundleRequested.clear()
            onStatusChanged?.invoke(false)
            // Unblocks awaitRegistration() promptly on a hard connection
            // failure instead of making the caller wait out its full
            // timeout for an attempt that's already dead. No-op if this
            // generation's registration already resolved one way or another.
            registrationReady?.complete(false)
            if (!userDisconnected) scheduleReconnect()
        }

        override fun onClosed(ws: WebSocket, code: Int, reason: String) {
            // Same reasoning as onFailure above — a close callback for an
            // already-superseded socket must not tear down the NEW
            // connection's state.
            if (ws !== webSocket) return
            isConnecting  = false
            handshakeDone = false
            _connected.value = false
            stopCoverTraffic()
            disconnectAnonChannel()
            // Same reasoning as onFailure above — a request in flight on
            // this now-closed socket will never get its response.
            bundleRequested.clear()
            onStatusChanged?.invoke(false)
            // Same as onFailure — a server-side close before register_ok ever
            // arrived (e.g. an access/PoW rejection that also drops the
            // socket) must not leave awaitRegistration() waiting the full
            // timeout for a generation that's already over.
            registrationReady?.complete(false)
            // Reconnect unless WE explicitly called disconnect() (userDisconnected=true)
            // This handles server-side close (even code=1000) and abnormal closures
            if (!userDisconnected) scheduleReconnect()
        }
    }

    // ── Message dispatcher ────────────────────────────────────────────────────

    // [ws] identifies which socket generation this message actually arrived
    // on — compared against the current live `webSocket` field at every
    // registration-state mutation point below (handshake_ok/register_ok/
    // pow_required/rejection handlers). Mirrors Android's generation-scoped
    // CompletableDeferred pair (captured fresh per connect() attempt,
    // closed over by that attempt's own listener) — Desktop's Listener is a
    // single reused instance rather than one created per attempt, so the
    // frame's own `ws` parameter (already provided by OkHttp on every
    // callback) is the natural generation token here instead of a second
    // object to keep in sync. Without this, a stale handshake_ok/register_ok/
    // rejection frame that arrives from an ALREADY-abandoned socket (a race
    // during reconnect) could flip _connected/handshakeDone/registrationReady
    // for a connection that no longer exists, or resolve registrationReady
    // for the WRONG attempt entirely. Found in the 2026-09-13 registration
    // state-machine audit.
    private fun handleMessage(raw: String, ws: WebSocket) {
        val json = runCatching { JSONObject(raw) }.getOrNull() ?: return
        when (val type = json.optString("type")) {

            // ── Handshake ──────────────────────────────────────────────────────
            "challenge" -> {
                // Server sends base64(raw_32_bytes); must sign the raw bytes, not the b64 string.
                val challengeB64  = json.getString("data")
                val challengeBytes = java.util.Base64.getDecoder().decode(challengeB64)
                lastChallengeBytes = challengeBytes
                val pubKey    = DesktopCryptoManager.getPublicKeyBase64()
                val signature = DesktopCryptoManager.signBase64(challengeBytes)
                // Server requires both public_key and signature in challenge_response
                webSocket?.send(JSONObject().apply {
                    put("type",       "challenge_response")
                    put("public_key", pubKey)
                    put("signature",  signature)
                }.toString())
            }

            "handshake_ok" -> {
                if (ws !== webSocket) return
                // Authentication done — now register our identity. Does NOT
                // mark handshakeDone/_connected/onStatusChanged — found in
                // the 2026-09-13 registration state-machine audit: handshake
                // authentication proves this socket owns the claimed
                // identity key, not that the server actually accepted this
                // as a registered, usable account for THIS device_id (a
                // PoW-gated, access-restricted, or TOTP/device-auth-rejected
                // server can still refuse register() outright). Application
                // traffic must not be able to assume "connected" before
                // register_ok — see its own comment for where these flip
                // instead.
                val pubKey   = DesktopCryptoManager.getPublicKeyBase64()
                val deviceId = UserStorage.getDeviceId()
                val registerPacket = JSONObject().apply {
                    put("type",       "register")
                    put("name",       displayName)
                    put("public_key", pubKey)
                    put("device_id",  deviceId)
                    put("platform",   "desktop")
                    // Only consumed by the server on this fingerprint's very first-
                    // ever registration — harmless to keep sending on every
                    // reconnect. See server.py SERVER_ACCESS_PROTECTED.
                    DesktopStorage.get("server_access_code")?.takeIf { it.isNotBlank() }?.let {
                        put("access_code", it)
                    }
                    // Only checked by the server for a device_id it hasn't seen
                    // before on this fingerprint — see server.py user_totp_secrets.
                    if (TotpManager.isEnabled()) {
                        TotpManager.getSecret()?.let { secret ->
                            put("totp_code", TotpManager.currentCode(secret))
                        }
                    }
                    // Set by submitRecoveryCode() in response to totp_required —
                    // one-shot, cleared immediately.
                    pendingRecoveryCode?.let { put("recovery_code", it) }
                    pendingRecoveryCode = null
                    // Server only actually checks these once TOTP is enabled
                    // for this account (server.py register()'s `username in
                    // user_totp_secrets` gate) — but TOTP setup is mandatory
                    // right after registration on both platforms, so this was
                    // missing entirely before this fix: every Desktop account
                    // would get "device_auth_failed" on its very next
                    // register() (any reconnect) after finishing onboarding,
                    // permanently, with no retry path. Harmless to always
                    // include, same as Android does whenever a fresh
                    // challenge is available.
                    lastChallengeBytes?.let { challengeBytes ->
                        put("device_public_key", DeviceKeyManager.getPublicKeyString())
                        put("device_signature", DeviceKeyManager.signDeviceChallenge(challengeBytes, myFingerprint, deviceId))
                    }
                }
                // Remembered so the "pow_required" handler below can resend this
                // exact packet with a pow_nonce added, without redoing the
                // recovery_code/access_code/totp gathering above.
                lastRegisterPacket = registerPacket
                webSocket?.send(registerPacket.toString())
                reconnectAttempts = 0
            }

            // Server accepted register() — ONLY NOW is it safe to send any
            // account-scoped startup traffic. Moved out of "handshake_ok"
            // (external review, mirrors Android's S6-40): this traffic used
            // to fire immediately after SENDING "register", before the
            // server had actually confirmed it, which a PoW-gated or
            // access-restricted server rejects outright ("... до успешной
            // регистрации — закрываю") — killing the connection before
            // registration (see "pow_required" below) ever got a chance to
            // actually finish.
            "register_ok" -> {
                if (ws !== webSocket) return
                // This IS the point the required invariant flips —
                // "application-ready for traffic" becomes true ONLY now,
                // once the server has actually accepted registration for
                // THIS connection, not merely completed the identity
                // handshake. Moved here from "handshake_ok" — see its own
                // comment. Found in the 2026-09-13 registration
                // state-machine audit.
                handshakeDone = true
                _connected.value = true
                onStatusChanged?.invoke(true)
                registrationReady?.complete(true)
                // Publish our prekey bundle so peers can initiate X3DH with us
                publishPrekeyBundle()
                // Subscribe our anon-routing token pool and check for anonymous
                // mailbox deposits left for us while we were offline.
                sendSubscribeTokens(AnonTokenManager.tokensToSubscribe())
                // Sealed Sender cert — our own "I am this fingerprint" cert,
                // signed by the server we're already talking to over this
                // authenticated connection. Requested here, not on every
                // send, since it's reused until close to expiry. Mirrors
                // Android's MessengerService.kt connect() (desktop/Android
                // symmetry audit, 2026-09-03).
                if (SenderCertManager.getFresh() == null) {
                    webSocket?.send(JSONObject().apply {
                        put("type", "request_sender_cert")
                    }.toString())
                }
                pollMailbox()
                // Recurring poll loop — was previously a single one-shot
                // call here, unlike Android's connect() which follows its
                // own initial pollMailbox() with a 30s-repeating loop for
                // as long as the connection stays up. A one-shot poll fires
                // essentially immediately after registration, before the
                // OTHER side could possibly have redeemed our invite and
                // deposited anything yet — any deposit arriving after that
                // single poll was never picked up again, so the mutual-add
                // mailbox bootstrap could only ever succeed by luck of
                // timing. Found via a desktop/Android literal wire-field
                // audit, 2026-09-11 — this is what made "channel never
                // becomes ready" reproduce consistently against Android
                // while (per the user) Android-to-Android stayed stable.
                scope.launch {
                    while (isActive && handshakeDone) {
                        delay(30_000)
                        if (handshakeDone && AnonTokenManager.getMyMailboxTags().isNotEmpty()) pollMailbox()
                    }
                }
                startCoverTraffic()
                connectAnonChannel()

                // One-time migration for the PQ-hybrid crypto upgrade: any
                // session established before this upgrade has a classical-only
                // root key that can't be hardened retroactively. Reset it and
                // tell the peer to reset their side too, forcing a fresh
                // PQ-hybrid X3DH handshake on the next message.
                SessionKeyManager.consumePendingPqMigrationContacts()?.forEach { contactId ->
                    // Was a raw webSocket.send() — bypassed anon-routing/
                    // Sealed Sender entirely (same class of bug as the
                    // earlier group_create fix) and omitted "from", unlike
                    // Android's MessengerService.kt which always routes
                    // session_reset through sendAnonOrDirect(). Found in the
                    // 2026-09-12 full-logic audit.
                    sendAnonOrDirect(contactId, JSONObject().apply {
                        put("type", "session_reset")
                        put("from", myFingerprint)
                        put("to", contactId)
                    })
                }

                // Durable post-backup-restore recovery — mirrors Android's
                // MessengerService.kt "handshake_ok" handler exactly. A
                // backup restore wipes every local Double Ratchet session
                // (see BackupManager.wipeCurrentIdentityData()) but restored
                // contacts have no way to know that — without this, this
                // device kept trying to send against ratchet state it no
                // longer has (or, if the peer happened to re-initiate X3DH
                // first, receiving fine while THIS side's own SPK/PQ-KEM —
                // also brand-new since the restore — stayed uninvalidated in
                // their cache). BackupManager.importBackup() persists the
                // affected contact ids via UserStorage.
                // setPendingSessionResetContacts(); consumed here, once, on
                // the next successful reconnect. Was entirely missing on
                // Desktop — found in the 2026-09-13 full-logic audit.
                val pendingResetContacts = UserStorage.getAndClearPendingSessionResetContacts()
                if (pendingResetContacts.isNotEmpty()) {
                    pendingResetContacts.forEach { contactId ->
                        if (SessionKeyManager.hasSession(contactId)) {
                            // A session already re-established naturally
                            // (e.g. the peer initiated first) — leave the
                            // healthy Double Ratchet session untouched, just
                            // signal that our own prekey bundle is new.
                            sendAnonOrDirect(contactId, JSONObject().apply {
                                put("type", "pq_bundle_refresh")
                                put("from", myFingerprint)
                                put("to", contactId)
                            })
                            sendAnonTokensTo(contactId)
                            return@forEach
                        }
                        SessionKeyManager.deleteSession(contactId)
                        sendAnonOrDirect(contactId, JSONObject().apply {
                            put("type", "session_reset")
                            put("from", myFingerprint)
                            put("to", contactId)
                        })
                        sendAnonTokensTo(contactId)
                    }
                }

                // "Забота о собеседнике" — see ContactHealthManager.kt. Mirrors
                // the same 60s loop in Android's MessengerService.
                scope.launch {
                    while (isActive && handshakeDone) {
                        delay(60_000)
                        if (handshakeDone) checkContactSilence()
                    }
                }
            }

            // Server wants proof-of-work on this new fingerprint's very first
            // registration (server.py POW_DIFFICULTY_BITS) — mint cost tied to
            // real device CPU time. Transparent to the user: solve it and just
            // resend register, no UI involved. Mirrors Android's
            // MessengerService.kt "pow_required" handler exactly (same
            // sha256(challenge + nonce) leading-zero-bits check). Deliberately
            // does NOT complete registrationReady — this is a mid-flight
            // retry, not a terminal outcome; awaitRegistration() keeps waiting
            // for whatever the retried register eventually gets back.
            "pow_required" -> {
                if (ws !== webSocket) return
                val challengeBytes = lastChallengeBytes
                val basePacket = lastRegisterPacket
                val difficultyBits = json.optInt("difficulty_bits", 18)
                if (challengeBytes == null || basePacket == null) {
                    System.err.println("WebSocketClient: pow_required — no saved challenge/register packet to retry")
                    registrationReady?.complete(false)
                } else {
                    // Registration stays pending while retrying — does NOT
                    // touch handshakeDone/_connected/registrationReady.
                    // application-ready must not flip true just because a
                    // PoW round is in progress, and awaitRegistration() must
                    // keep waiting for whatever the retried register()
                    // eventually gets back.
                    val nonce = solveProofOfWork(challengeBytes, difficultyBits)
                    val retryPacket = JSONObject(basePacket.toString()).apply {
                        put("pow_nonce", nonce)
                    }
                    lastRegisterPacket = retryPacket
                    webSocket?.send(retryPacket.toString())
                }
            }

            // MAX_REGISTERED_USERS reached — nothing to retry, this isn't
            // transient like pow_required.
            "registration_full" -> {
                if (ws !== webSocket) return
                System.err.println("WebSocketClient: register rejected by server: server full (account limit reached)")
                onChannelError?.invoke("Сервер заполнен (достигнут лимит аккаунтов)")
                registrationReady?.complete(false)
            }

            // Missing/invalid device_public_key/device_signature, or a
            // device_id whose pinned pubkey doesn't match what we just sent
            // (server.py register(), only enforced once TOTP is enabled for
            // this account) — nothing to retry automatically, mirrors
            // Android's MessengerService.kt handler.
            "device_auth_failed" -> {
                if (ws !== webSocket) return
                System.err.println("WebSocketClient: register rejected by server: device_auth_failed")
                onChannelError?.invoke("Не удалось подтвердить устройство (device_auth_failed)")
                registrationReady?.complete(false)
            }

            "error" -> {
                val reason = json.optString("reason", json.optString("message", "unknown"))
                System.err.println("WebSocketClient: error — $reason")
                onChannelError?.invoke(reason)
                // A generic server-level "error" (e.g. totp_setup's per-account
                // rate_limit_check() rejection — the ONLY totp_setup failure path
                // that isn't a "totp_setup_failed"/"totp_disable_failed" response)
                // used to just get logged and silently dropped here, leaving
                // TotpSettingsScreen's busy state hanging until its own 15s
                // client-side timeout — looking exactly like "server isn't
                // responding". Resolve any in-flight TOTP callback immediately
                // with the real reason instead. No-op if nothing is listening
                // (TotpSettingsScreen only assigns these while mounted).
                onTotpSetupResult?.invoke(false, reason, null)
                onTotpDisableResult?.invoke(false)
                if (!handshakeDone) disconnect()
            }

            "session_conflict" -> {
                if (ws !== webSocket) return
                System.err.println("WebSocketClient: session_conflict — disconnecting")
                disconnect()
            }

            // ── X3DH session initiation from peer ─────────────────────────────
            "session_init" -> processSessionInit(json)

            // ── Prekey bundle response (we requested it before sending) ────────
            // The whole body runs inside try/finally over bundleRequested —
            // found in the 2026-09-13 bundleRequested lifecycle audit: the
            // success path relied entirely on drainQueue()'s own (buggy,
            // now-removed) removal, so a media-only request — nothing ever
            // queued in messageQueue — left the gate stuck forever, and the
            // catch block below didn't clear it either (a malformed bundle
            // permanently blocked every future requestBundleFor(from) for
            // that contact). finally guarantees removal on every terminal
            // outcome — success, malformed bundle, or exception — the
            // required invariant is "in bundleRequested only while a
            // request is actually in flight," not "until something happens
            // to notice it's done."
            "prekey_bundle_response" -> {
                val from       = json.getString("from")
                val bundleObj  = json.optJSONObject("bundle")
                try {
                    if (bundleObj == null) {
                        // NOT a real fallback — sendLegacy() (despite its name)
                        // calls the same CryptoManager.encrypt() that hard-
                        // requires peerPqPublicKeys[from], which a peer with NO
                        // published bundle at all can never have cached. Calling
                        // it here was guaranteed to fail sendLegacy()'s own PQ
                        // check immediately, which re-queued via
                        // enqueueAndRequestBundle() -> requestBundleFor(from) —
                        // re-firing get_prekey_bundle for this exact fingerprint
                        // right after bundleRequested was just cleared above,
                        // an infinite request/empty-response loop that burns the
                        // account's anon-token new-claim budget every cycle (see
                        // AnonTokenManager.freshTokensToShare()'s own comment).
                        // Leaving messageQueue untouched instead: the next real
                        // trigger (reconnect, or this contact finally publishing
                        // a bundle) re-requests once, not forever. Found in the
                        // 2026-09-13 contact-deletion/token-exhaustion audit
                        // (mirrors Android's matching fix in
                        // handleFetchedPrekeyBundle()).
                        println("WebSocketClient: no prekey bundle for $from — contact hasn't published one yet, messages stay queued")
                    } else {
                        // Clears the prekey_fetch cooldown the instant a REAL
                        // bundle comes back — mirrors Android's identical fix.
                        // Each fetch consumes a one-time prekey, so a bundle
                        // cached from moments ago can't be silently reused for
                        // a second session_init; without this, a message typed
                        // shortly after an earlier (e.g. typing-triggered)
                        // fetch sat in messageQueue for up to the cooldown's
                        // full duration before the next request was even
                        // allowed out. Leaving the null-branch's own cooldown
                        // untouched — that's the case it exists for. Found
                        // live 2026-09-18.
                        lastPrekeyFetchAttempt.remove(from)
                        if (bundleObj.optBoolean("revoked", false)) {
                            System.err.println("WebSocketClient: prekey bundle from $from marked revoked by server")
                            onContactRevoked?.invoke(from)
                        }
                        val bundle = SessionKeyManager.parsePrekeyBundle(bundleObj)
                        if (KeyHistoryManager.checkKeyChange(from, bundle.identityKey)) {
                            System.err.println("WebSocketClient: TOFU: contact $from's key changed on bundle fetch!")
                            onKeyChanged?.invoke(from)
                        }
                        peerPublicKeys[from] = bundle.identityKey
                        peerPqPublicKeys[from] = Base64.getDecoder().decode(bundle.pqKemPublicKey)
                        ChatStorage.saveContactPublicKey(from, bundle.identityKey)
                        ChatStorage.saveContactPqPublicKey(from, peerPqPublicKeys[from]!!)
                        pendingBundles[from] = bundle
                        bundle.bootstrapToken?.let { pendingBootstrapTokens[from] = it }
                        drainQueue(from)     // trySend will pick up pendingBundles[from]
                        flushPendingImages(from)
                        flushPendingFileSends(from)
                        flushPendingVoiceSends(from)
                        flushPendingVideoSends(from)
                        flushPendingGroupInvites(from)
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: bad bundle from $from — ${e.message}")
                } finally {
                    bundleRequested.remove(from)
                }
            }

            // ── Anonymous batched prekey-bundle fetch response ─────────────────
            // Only the entry matching the real target we were actually trying to
            // reach is kept — decoy entries are discarded outright (we never
            // asked for a session with them, keeping their keys around serves
            // no purpose). We don't know from the response alone which entry
            // was "real" — bundleRequested/messageQueue tell us which fingerprint
            // we're actually waiting on.
            "prekey_bundles_batch_response" -> {
                val bundlesObj = json.optJSONObject("bundles")
                if (bundlesObj == null) {
                    // Malformed/empty top-level response — found in the
                    // 2026-09-13 bundleRequested lifecycle audit: with no
                    // "bundles" field at all there's no way to tell which
                    // specific targets this response was even for, so every
                    // currently in-flight batched request must be treated
                    // as terminally failed here rather than left stuck
                    // forever (the per-target loop below never even runs).
                    System.err.println("WebSocketClient: prekey_bundles_batch_response missing 'bundles' — clearing in-flight batch requests")
                    bundleRequested.clear()
                } else {
                    for (target in bundleRequested.toList()) {
                        // Server always includes every requested target's key,
                        // explicit JSON null when it has no bundle (see
                        // server.py get_prekey_bundles_batch: `results[t] =
                        // None`) — distinct from the target simply not being
                        // in the response at all. optJSONObject() can't tell
                        // these apart (null for both), so a bare `?: continue`
                        // silently left a no-bundle peer's messages queued
                        // forever with no fallback, unlike the single-target
                        // "prekey_bundle_response" case right above (which has
                        // its own explicit null-bundle legacy fallback). Since
                        // requestBundleFor() always prefers this batched path
                        // once any contact exists to use as a decoy, this was
                        // actually the MORE commonly hit gap of the two. Found
                        // in the 2026-09-12 full-logic audit continuation.
                        if (!bundlesObj.has(target)) continue
                        if (bundlesObj.isNull(target)) {
                            // Same fix as the single-target branch above — see
                            // its own comment. sendLegacy() here was guaranteed
                            // to fail its own PQ-key check and immediately
                            // re-fire requestBundleFor(target), an infinite
                            // loop. Leave messageQueue queued instead.
                            println("WebSocketClient: no prekey bundle for $target (batch) — contact hasn't published one yet, messages stay queued")
                            bundleRequested.remove(target)
                            continue
                        }
                        val bundleObj = bundlesObj.optJSONObject(target) ?: continue
                        // try/finally over bundleRequested — same fix as the
                        // single-target handler above: the success path used
                        // to rely entirely on drainQueue()'s own (buggy,
                        // now-removed) removal, and the catch block below
                        // didn't clear it either, so a media-only request or
                        // a malformed batched bundle permanently blocked
                        // every future requestBundleFor(target) for that
                        // contact. Found in the 2026-09-13 bundleRequested
                        // lifecycle audit.
                        try {
                            // Same cooldown-clear as the single-target branch
                            // above — see its own comment.
                            lastPrekeyFetchAttempt.remove(target)
                            if (bundleObj.optBoolean("revoked", false)) {
                                System.err.println("WebSocketClient: prekey bundle from $target marked revoked by server")
                                onContactRevoked?.invoke(target)
                            }
                            val bundle = SessionKeyManager.parsePrekeyBundle(bundleObj)
                            if (KeyHistoryManager.checkKeyChange(target, bundle.identityKey)) {
                                System.err.println("WebSocketClient: TOFU: contact $target's key changed on bundle fetch!")
                                onKeyChanged?.invoke(target)
                            }
                            peerPublicKeys[target] = bundle.identityKey
                            peerPqPublicKeys[target] = Base64.getDecoder().decode(bundle.pqKemPublicKey)
                            ChatStorage.saveContactPublicKey(target, bundle.identityKey)
                            ChatStorage.saveContactPqPublicKey(target, peerPqPublicKeys[target]!!)
                            pendingBundles[target] = bundle
                            bundle.bootstrapToken?.let { pendingBootstrapTokens[target] = it }
                            drainQueue(target)
                            flushPendingImages(target)
                            flushPendingFileSends(target)
                            flushPendingVoiceSends(target)
                            flushPendingVideoSends(target)
                            flushPendingGroupInvites(target)
                        } catch (e: Exception) {
                            System.err.println("WebSocketClient: bad batched bundle for $target — ${e.message}")
                        } finally {
                            bundleRequested.remove(target)
                        }
                    }
                }
            }

            // ── Server asks us to replenish OPKs ──────────────────────────────
            "prekey_bundle_request" -> publishPrekeyBundle()

            // ── Sealed Sender cert response ───────────────────────────────────
            "sender_cert" -> {
                try {
                    val cert = json.getJSONObject("cert")
                    val signature = json.getString("signature")
                    // Not verified here — this is our OWN cert about ourselves,
                    // signed by the server we're already talking to over an
                    // authenticated connection. Verification against the
                    // server's pinned public key matters on the RECEIVING
                    // side (a peer checking someone else's cert), not here.
                    SenderCertManager.store(cert, signature)
                    println("WebSocketClient: sender_cert received and cached")
                    flushAllPendingAnon()
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: sender_cert error — ${e.message}")
                }
            }

            // ── Text message ───────────────────────────────────────────────────
            "message" -> {
                val msgId = json.optString("id", "")
                // Peek-only — mirrors Android's MessengerService.kt "message"
                // handler exactly: a cheap duplicate check BEFORE the
                // expensive work (signature verify, decrypt), but the id is
                // only actually marked processed further down once
                // authentication + decrypt + application processing all
                // succeed. Was dedup(), which INSERTED the id immediately —
                // a message that failed signature/decrypt right after would
                // be permanently treated as already-seen and could never be
                // retried, even though it was never actually shown. Found in
                // the 2026-09-13 full-logic audit.
                if (msgId.isNotEmpty() && isDuplicateId(msgId)) return
                val from     = json.getString("from")
                val ctB64    = json.getString("text")
                val sessHdr  = json.optJSONObject("session_header")
                // Per-message identity signature over the raw ciphertext,
                // verified BEFORE decrypt/state mutation — mirrors Android's
                // MessengerService.kt "message" handler exactly. Was
                // entirely absent on Desktop: the Double-Ratchet/legacy AEAD
                // tag authenticates the ciphertext against a SESSION key,
                // not the sender's long-term identity key, so without this
                // check anyone routing a frame to this device as a claimed
                // "from" only needed a session with THAT fingerprint (e.g. a
                // relabeled anon_delivery envelope) to have it decrypt and
                // display as if genuinely from them. Bad/missing key or
                // signature THROWS, not returns, so anon_delivery's outer
                // catch suppresses the ack for a rejected packet. Found in
                // the 2026-09-13 full-logic audit.
                val signature = json.optString("signature", null)
                val senderPublicKey = peerPublicKeys[from]
                    ?: ChatStorage.getContactPublicKey(from)?.also { peerPublicKeys[from] = it }
                if (signature == null || senderPublicKey == null) {
                    System.err.println("WebSocketClient: message: no key for $from — requesting")
                    requestBundleFor(from)
                    throw SecurityException("message: no key from $from")
                }
                if (!CryptoManager.verify(ctB64, signature, senderPublicKey)) {
                    System.err.println("WebSocketClient: message: invalid signature from $from")
                    throw SecurityException("message: bad signature from $from")
                }
                val text = if (sessHdr != null && !SessionKeyManager.hasSession(from)) {
                    // They have a Double-Ratchet session with us, we don't
                    // (fresh install, local session wiped, storage reset,
                    // ...) — mirrors Android's MessengerService.kt "message
                    // с session_header, но сессии нет" branch. Attempting
                    // the legacy decrypt below on genuine DR ciphertext is
                    // guaranteed to fail (wrong format entirely) AND used to
                    // never tell the sender to re-handshake, so every
                    // subsequent message from them kept failing the same
                    // way forever. Ask for a fresh session_init and drop
                    // just this one message instead — found in the
                    // 2026-09-12 full-logic audit.
                    System.err.println("WebSocketClient: message with session_header from $from but no session — requesting their session_init")
                    sendSessionResetDebounced(from)
                    return
                } else if (sessHdr != null) {
                    // Double-Ratchet path
                    try {
                        CryptoManager.decryptWithForwardSecrecy(from, ctB64, sessHdr)
                    } catch (e: SessionKeyManager.DuplicateOrStaleMessage) {
                        // Not a decrypt failure — mirrors Android's
                        // MessengerService.kt catch block (desktop/Android
                        // symmetry audit, 2026-09-03). This message was
                        // already processed once: nothing to retry, no
                        // ratchet to fix, and tearing the session down like
                        // the generic-failure branch below would destroy a
                        // perfectly healthy ratchet over a message we'd
                        // already consumed. A successful duplicate
                        // disposition: mark the id processed (so a retried
                        // copy short-circuits on the cheap peek check above
                        // next time) and still send "delivered" via
                        // sendAnonOrDirect() — not a raw webSocket send,
                        // which would re-expose the sender→recipient pair in
                        // the clear (mirrors anon_delivery_ack's role for
                        // the token-routed path) — then return without
                        // touching session state or showing the message again.
                        System.err.println("WebSocketClient: duplicate/stale message from $from ignored: ${e.message}")
                        if (msgId.isNotEmpty()) markProcessed(msgId)
                        sendAnonOrDirect(from, JSONObject().apply {
                            put("type", "delivered"); put("from", myFingerprint); put("to", from); put("id", msgId)
                        })
                        return
                    } catch (e: Exception) {
                        System.err.println("WebSocketClient: DR decrypt failed from $from — ${e.message}")
                        sendSessionResetDebounced(from)
                        // Thrown, not a plain return — mirrors the Android
                        // fix (docs/ISSUE_backup_identity_hijack.md,
                        // 2026-08-17): a bare return here let the
                        // anon_delivery handler's ack fire as if this
                        // message had actually been decrypted and shown.
                        throw e
                    }
                } else {
                    // Legacy ephemeral-ECDH path
                    runCatching { CryptoManager.decrypt(ctB64) }.getOrElse {
                        System.err.println("WebSocketClient: legacy decrypt failed from $from — ${it.message}")
                        throw it
                    }
                }
                ContactHealthManager.recordIncoming(from)
                if (!handleDecryptedTextForTokenExchange(from, text)) {
                    val replyToId = json.optString("reply_to_id", null)?.takeIf { it.isNotBlank() }
                    persistAndNotifyIncoming(from, text, replyToId)
                }
                if (msgId.isNotEmpty()) markProcessed(msgId)
                // sendAnonOrDirect(), not a raw webSocket send — mirrors
                // Android's handleIncomingDecryptedMessage() exactly. A
                // direct webSocket?.send() here put the sender→recipient
                // pair on the wire in the clear even for a contact reached
                // only via the anonymous-token/mailbox path, defeating the
                // whole point of that routing for this one receipt. Found
                // in the 2026-09-13 full-logic audit.
                sendAnonOrDirect(from, JSONObject().apply {
                    put("type", "delivered")
                    put("from", myFingerprint)
                    put("to",   from)
                    put("id",   msgId)
                })
            }

            // ── Anonymous token routing ─────────────────────────────────────────
            "anon_delivery" -> {
                try {
                    val rawPayload = json.getJSONObject("payload")
                    val transportToken = json.optString("token", null)

                    // Mirrors Android's sealPacketForRecipient()/anon_delivery
                    // handler (desktop/Android symmetry audit, 2026-09-03):
                    // Android has sealed every anon_message send
                    // unconditionally since 2026-08-29, regardless of the
                    // recipient's platform — "blob" present means the real
                    // from/to/text is one more hybrid-encryption layer in,
                    // keyed to OUR identity, no need to know who sent it
                    // first. Without this check, desktop silently dropped
                    // every anon_message-routed message from an Android
                    // contact — rawPayload had no "type" field to dispatch
                    // on, so handleMessage() below just no-opped, no error
                    // logged anywhere. Falls back to using rawPayload
                    // directly for an unpatched peer (old shape had no
                    // "blob").
                    val blob = rawPayload.optString("blob", null)
                    if (blob != null && blob.length > ANON_DELIVERY_BLOB_MAX_LEN) {
                        System.err.println("WebSocketClient: anon_delivery: blob exceeds ANON_DELIVERY_BLOB_MAX_LEN (${blob.length}) — dropped before decrypt()")
                        return
                    }
                    val payload = if (blob != null) {
                        try {
                            JSONObject(CryptoManager.decrypt(blob))
                        } catch (e: Exception) {
                            System.err.println("WebSocketClient: anon_delivery: failed to unseal blob — ${e.message}")
                            return
                        }
                    } else rawPayload

                    // Sealed Sender, шаг 1 (продолжение): if the sender
                    // attached a sender_cert/sender_cert_sig inside the
                    // envelope, verify the server's signature over it and
                    // that it was issued to the fingerprint the packet
                    // claims as "from" — otherwise anyone could attach
                    // their own valid cert to someone else's "from".
                    val senderCert    = payload.optJSONObject("sender_cert")
                    val senderCertSig = payload.optString("sender_cert_sig", null)
                    val claimedFrom   = payload.optString("from", null)
                    var certVerified = false
                    if (senderCert != null && senderCertSig != null) {
                        val certFingerprint = senderCert.optString("fingerprint", null)
                        if (certFingerprint != claimedFrom) {
                            System.err.println("WebSocketClient: anon_delivery: sender_cert issued for $certFingerprint, but from=$claimedFrom — mismatch")
                        } else if (!SenderCertManager.verify(senderCert, senderCertSig)) {
                            System.err.println("WebSocketClient: anon_delivery: sender_cert for $claimedFrom failed signature verification")
                        } else {
                            certVerified = true
                            println("WebSocketClient: anon_delivery: sender_cert for $claimedFrom verified")
                        }
                    }

                    // Enforced for unsigned control types (S6-66 follow-up)
                    // — end-to-end identity signature, not sender_cert.
                    // Mirrors Android exactly. No dispatch, no ack, no state
                    // mutation on failure.
                    val innerType = payload.optString("type", null)
                    if (innerType in ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE) {
                        val controlSig = payload.optString("signature", null)
                        val senderKey = if (claimedFrom != null) {
                            peerPublicKeys[claimedFrom] ?: DesktopCryptoManager.getPeerPublicKey(claimedFrom)
                        } else null
                        if (controlSig == null || senderKey == null ||
                            !CryptoManager.verify(controlEnvelopeTranscript(payload), controlSig, senderKey)) {
                            System.err.println("WebSocketClient: anon_delivery: $innerType — invalid or missing sender signature (from=$claimedFrom), rejected")
                            return
                        }
                    }

                    handleMessage(payload.toString(), ws)
                    // Mirrors the Android fix (docs/ISSUE_backup_identity_hijack.md,
                    // 2026-08-17): server.py now waits for this explicit ack
                    // instead of treating its own send_safe() success as
                    // final delivery — without it, this client would never
                    // clear the server's fallback queue for a token, and
                    // would get every message redelivered on every future
                    // reconnect.
                    if (!transportToken.isNullOrBlank()) {
                        // Moved from an immediate consumeMyToken() (never
                        // actually called on Desktop at all, in fact — the
                        // token just stayed in PREF_MY_TOKENS forever) to
                        // markMyTokenAckPending(): removes it from the
                        // active pool now (so it's never handed out to
                        // another contact via tokensToShareWith()), but
                        // keeps it in ACK_PENDING — included in
                        // tokensToSubscribe() — until the server's
                        // "anon_delivery_ack_ok" (or a "spent" entry in
                        // subscribe_tokens_result) confirms our ack truly
                        // landed. Without this, a spent token could get
                        // resubscribed indefinitely and even reissued to a
                        // brand-new contact, who'd have it rejected by the
                        // server as already-spent with no visible error.
                        // Mirrors Android's identical 2026-09-03 fix. Found
                        // live 2026-09-13.
                        AnonTokenManager.markMyTokenAckPending(transportToken)
                        sendWs(JSONObject().apply {
                            put("type", "anon_delivery_ack")
                            put("token", transportToken)
                        }.toString())
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: anon_delivery error — ${e.message}")
                }
            }

            // Server's confirmation that our anon_delivery_ack for this
            // token was actually received and its pending/spent state is
            // now durable — see markMyTokenAckPending()'s comment for why
            // this round-trip exists at all. Only now is it safe to fully
            // forget the token; until this arrives it stays in ACK_PENDING
            // and keeps being included in subscribe_tokens, so a lost ack
            // still gets a chance to be redelivered and re-acked after a
            // reconnect instead of being silently orphaned. Was entirely
            // unhandled on Desktop before this fix (fell through to
            // `else -> unhandled`). Mirrors Android exactly.
            "anon_delivery_ack_ok" -> {
                val token = json.optString("token", null)
                if (!token.isNullOrBlank()) {
                    AnonTokenManager.confirmMyTokenAcked(token)
                }
            }

            // Closes the last gap in the ACK_PENDING self-healing loop —
            // anon_delivery_ack_ok itself can be the thing that gets lost
            // (server processed the ack and sent the confirmation,
            // connection died before it arrived) — a token stuck in
            // ACK_PENDING then re-subscribes on every reconnect via
            // tokensToSubscribe() forever, since nothing ever told this
            // device the server already considers it spent. server.py's
            // subscribe_tokens handler checks spent_tokens for every token
            // in the request and reports back here instead of silently
            // re-registering an already-spent token as if it were still
            // live. Each entry gets the exact same treatment as a genuine
            // anon_delivery_ack_ok. Was entirely unhandled on Desktop
            // before this fix. Mirrors Android exactly.
            "subscribe_tokens_result" -> {
                val spentArr = json.optJSONArray("spent")
                if (spentArr != null) {
                    for (i in 0 until spentArr.length()) {
                        val token = spentArr.optString(i, null)
                        if (!token.isNullOrBlank()) {
                            AnonTokenManager.confirmMyTokenAcked(token)
                        }
                    }
                }
            }

            "mailbox_result" -> handleMailboxResult(json)

            // ── Image chunks ───────────────────────────────────────────────────
            "image_chunk" -> handleImageChunk(json)

            // ── File chunks (generic files) ────────────────────────────────────
            "file_chunk" -> handleFileChunk(json)

            // ── Video circles (Telegram-style round video messages) ────────────
            // Bundles multiple chunks into one anon_message, same reasoning as
            // Android's own comment (sendVideoCircle/video_chunk_batch): anon
            // tokens are single-use server-side, so one chunk per token would
            // burn a contact's entire shared pool sending a single video.
            "video_chunk_batch" -> {
                try {
                    val from = json.getString("from")
                    val videoId = json.getString("video_id")
                    val totalChunks = json.getInt("total_chunks")
                    val duration = json.optInt("duration", 0)
                    val chunksArr = json.getJSONArray("chunks")
                    for (i in 0 until chunksArr.length()) {
                        val c = chunksArr.getJSONObject(i)
                        handleVideoChunk(
                            from = from,
                            videoId = videoId,
                            chunkIndex = c.getInt("chunk_index"),
                            totalChunks = totalChunks,
                            chunkData = c.getString("data"),
                            duration = duration,
                            signature = c.optString("signature", null)
                        )
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: video_chunk_batch error — ${e.message}")
                    throw e
                }
            }

            // ── Voice messages ────────────────────────────────────────────────
            // Single frame, not chunked — mirrors Android's MessengerService.kt
            // "voice" handler (desktop/Android symmetry audit, 2026-09-03).
            // Routed through onFileReceived with VoiceRecorder.FILE_NAME so the
            // existing FileRow UI (isVoice check) renders it as a voice bubble
            // with no new UI code needed — same path Desktop's own sendFile()-
            // based voice messages already use.
            //
            // Android records voice as AMR-NB/3GPP (MediaRecorder), which
            // javax.sound.sampled can't play directly — AudioTranscoder
            // normalizes to WAV via bundled ffmpeg (JAVE2) before this ever
            // reaches storage/playback; a no-op passthrough for Desktop's own
            // WAV-native voice messages.
            "voice" -> {
                try {
                    val from = json.getString("from")
                    val voiceId = json.getString("voice_id")
                    val encryptedData = json.getString("voice_data")
                    val signature = json.optString("signature", null)
                    val duration = json.getInt("duration")

                    // Defense-in-depth (S6-57, STEP 7) -- bounded BEFORE any
                    // of the crypto/decode work below; the server must never
                    // be this client's own memory-safety boundary. Thrown,
                    // not returned (2026-09-13 dedup/ACK audit) — a plain
                    // return here let anon_delivery's ack fire for a
                    // malformed/oversized frame as if it had actually been
                    // received, same class of fix as the checks below.
                    if (voiceId.isEmpty() || voiceId.length > VOICE_ID_MAX_LEN) {
                        System.err.println("WebSocketClient: voice voiceId outside allowed length from $from")
                        throw SecurityException("voice: voiceId out of bounds from $from")
                    }
                    if (encryptedData.isEmpty() || encryptedData.length > VOICE_WIRE_MAX_LEN) {
                        System.err.println("WebSocketClient: voice voice_data outside allowed length from $from")
                        throw SecurityException("voice: voice_data out of bounds from $from")
                    }
                    if (signature != null && signature.length > VOICE_SIGNATURE_MAX_LEN) {
                        System.err.println("WebSocketClient: voice signature outside allowed length from $from")
                        throw SecurityException("voice: signature out of bounds from $from")
                    }
                    if (duration < 0 || duration > MAX_VOICE_DURATION_SECONDS) {
                        System.err.println("WebSocketClient: voice duration outside allowed range from $from")
                        throw SecurityException("voice: duration out of range from $from")
                    }

                    val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
                    if (signature == null || senderKey == null) {
                        System.err.println("WebSocketClient: voice with no key from $from — requesting")
                        requestBundleFor(from)
                        throw SecurityException("voice: нет ключа от $from")
                    }
                    // Verifies the V1 transcript (S6-58), not bare
                    // `encryptedData` -- binds voiceId/duration into the
                    // signature, closing the metadata-relabeling gap
                    // voiceSignatureTranscript()'s own comment describes.
                    // Hard cutover, no legacy bare-ciphertext fallback: a
                    // fallback would preserve exactly the vulnerability this
                    // fixes. Any pre-S6-58 voice message still offline-queued
                    // server-side at upgrade time will fail this verification
                    // and be dropped, same as any other signature failure --
                    // an accepted, explicit tradeoff.
                    if (!CryptoManager.verify(voiceSignatureTranscript(voiceId, duration, encryptedData), signature, senderKey)) {
                        System.err.println("WebSocketClient: invalid voice signature from $from")
                        throw SecurityException("voice: неверная подпись от $from")
                    }
                    // Replay dedup (S6-58, STEP 9) -- deliberately checked
                    // AFTER verification, unlike "message"/"session_init"'s
                    // own dedup call above: voiceId is now cryptographically
                    // authenticated, so this is the first point where
                    // trusting it as a dedup key is actually sound. Checking
                    // before verification (this platform's usual convention)
                    // would let an attacker pre-emptively "burn" a real
                    // voiceId with an unsigned/invalidly-signed frame,
                    // causing the legitimate sender's real message to be
                    // silently dropped as a false duplicate once it actually
                    // arrives.
                    //
                    // Peek-only (isDuplicateId), not dedup() — found in the
                    // 2026-09-13 voice/group_message dedup audit: dedup()
                    // marks voiceId "seen" immediately, before decrypt/
                    // decode/transcode below had even run. Any of those
                    // failing then permanently poisoned this id — a
                    // legitimate retry of the exact same voice message would
                    // hit this same check, find it already marked from the
                    // FAILED first attempt, and be silently dropped as a
                    // fake duplicate forever. Marked processed only at the
                    // very end, once every step below has actually
                    // succeeded.
                    if (isDuplicateId(voiceId)) {
                        System.err.println("WebSocketClient: duplicate/repeat voice $voiceId from $from ignored")
                        return
                    }
                    val voiceDataB64 = CryptoManager.decrypt(encryptedData)
                    // Post-decrypt bound (S6-57, STEP 8) -- checked BEFORE
                    // Base64.decode()/AudioTranscoder.toWav() ever run.
                    if (voiceDataB64.length > VOICE_MAX_DECRYPTED_B64_LEN) {
                        System.err.println("WebSocketClient: voice decrypted data exceeds allowed size from $from")
                        throw SecurityException("voice: decrypted payload too large from $from")
                    }
                    val decodedBytes = try {
                        Base64.getDecoder().decode(voiceDataB64)
                    } catch (e: Exception) {
                        System.err.println("WebSocketClient: voice invalid base64 from $from")
                        throw e
                    }
                    if (decodedBytes.size > VOICE_MAX_DECODED_AUDIO_BYTES) {
                        System.err.println("WebSocketClient: voice decoded audio exceeds allowed size from $from")
                        throw SecurityException("voice: decoded audio too large from $from")
                    }
                    val wavBytes = AudioTranscoder.toWav(decodedBytes)
                    if (wavBytes == null) {
                        System.err.println("WebSocketClient: voice from $from — failed to normalize to WAV")
                        throw IllegalStateException("voice: WAV normalization failed from $from")
                    }
                    // Marked processed ONLY now — after signature
                    // verification, decrypt, decode, and transcode have all
                    // already succeeded.
                    markProcessed(voiceId)
                    // Persisted centrally (id = voiceId, matching ChatScreen's
                    // own voice-specific id rule) so a voice message arriving
                    // with no ChatScreen open for `from` isn't dropped
                    // entirely — see persistAndNotifyIncoming's comment.
                    val voiceFile = writeEncryptedBlob(voiceId, wavBytes)
                    ChatStorage.saveOrUpdateMessage(myFingerprint, from,
                        ChatStorage.StoredMessage(
                            id = voiceId, text = "", isOwn = false,
                            filePath = voiceFile.absolutePath, fileName = VoiceRecorder.FILE_NAME,
                            isRead = false, voiceDuration = duration, expiresAt = computeExpiresAt(from)
                        )
                    )
                    onFileReceived?.invoke(from, voiceId, VoiceRecorder.FILE_NAME, wavBytes, duration, voiceId)
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: voice error — ${e.message}")
                    // Re-thrown — was silently swallowed before this fix, so
                    // anon_delivery's ack fired as if this voice message had
                    // actually been received even on a genuine decrypt/
                    // decode/transcode failure. Mirrors Android's "voice"
                    // handler and this file's own "message"/session_init
                    // fixes. Found in the 2026-09-13 voice/group_message
                    // dedup audit.
                    throw e
                }
            }

            // ── Groups ─────────────────────────────────────────────────────────
            "group_create" -> handleGroupCreate(json)
            "group_message" -> handleGroupMessage(json)
            "group_image_batch" -> handleGroupImageBatch(json)
            "group_file_batch" -> handleGroupFileBatch(json)
            "group_avatar_update" -> handleGroupAvatarUpdate(json)
            "group_message_delete" -> {
                val groupId   = json.optString("group_id", "")
                val messageId = json.optString("message_id", "")
                val from      = json.optString("from", "")
                // S6-53, STEP 10: bounded before use, mirrors the server's
                // own CHAT_CONTROL_ID_MAX_LEN.
                if (groupId.isEmpty() || messageId.isEmpty() || from.isEmpty() ||
                    groupId.length > CHAT_CONTROL_ID_MAX_LEN || messageId.length > CHAT_CONTROL_ID_MAX_LEN) {
                    return
                }
                // S6-54 (external review 2026-09-06): this platform
                // previously had NO signature at all for this type -- ported
                // Android's scheme identically. The transcript binds BOTH
                // groupId and messageId under a group-delete-specific domain
                // separator, so a signature can't be replayed across groups
                // or reused as a direct message_delete. A valid signature
                // only proves `from` requested this, not that `from` is
                // authorized to delete THIS message -- so after verifying,
                // the locally stored group message is looked up and the
                // delete is applied only if `from` is its original sender
                // (this product has no admin-delete-others'-messages
                // feature; GroupChatScreen.kt's own "delete for everyone"
                // button is author-gated the same way).
                val signature = json.optString("signature", null)
                val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify("SUBROSA_GROUP_MESSAGE_DELETE_V1:$groupId:$messageId", signature, senderKey)) {
                    System.err.println("WebSocketClient: group_message_delete: invalid or missing signature from $from")
                    return
                }
                val existing = GroupManager.loadGroupMessages(myFingerprint, groupId).find { it.id == messageId }
                if (existing != null && existing.senderId != from) {
                    System.err.println("WebSocketClient: group_message_delete: $from tried to delete someone else's message $messageId — rejected")
                    return
                }
                GroupManager.deleteGroupMessage(myFingerprint, groupId, messageId)
                onGroupMessageDeleted?.invoke(groupId, messageId)
            }
            // Mirrors Android MessengerService "group_reaction" handler: the
            // emoji is PLAINTEXT (unlike direct 1:1 reaction), the signature is
            // verified over that plaintext against the reactor's identity key,
            // and a bad/missing signature THROWS so the anon_delivery ack is
            // suppressed for a rejected reaction (same throw-not-return posture).
            "group_reaction" -> {
                val groupId   = json.getString("group_id")
                val from      = json.getString("from")
                val messageId = json.getString("message_id")
                val emoji     = json.getString("emoji")
                val signature = json.optString("signature", null)
                val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
                if (signature == null || senderKey == null) {
                    System.err.println("WebSocketClient: group_reaction with no key from $from")
                    throw SecurityException("group_reaction: no key from $from")
                }
                if (!CryptoManager.verify(emoji, signature, senderKey)) {
                    System.err.println("WebSocketClient: group_reaction: invalid signature from $from")
                    throw SecurityException("group_reaction: bad signature from $from")
                }
                // Persist onto the stored group message (mirrors Android's
                // onGroupReactionReceived -> saveGroupMessage): reactor-keyed,
                // so a member's newer emoji overwrites their older one.
                val existing = GroupManager.loadGroupMessages(myFingerprint, groupId).find { it.id == messageId }
                if (existing != null) {
                    GroupManager.saveGroupMessage(myFingerprint,
                        existing.copy(reactions = existing.reactions.toMutableMap().also { it[from] = emoji }))
                }
                onGroupReactionReceived?.invoke(groupId, from, messageId, emoji)
            }
            "group_member_removed" -> handleGroupMemberRemoved(json)
            "group_member_added" -> handleGroupMemberAdded(json)
            "group_key_rotation" -> handleGroupKeyRotation(json)
            "group_invite_accepted" -> handleGroupInviteAccepted(json)

            // ── Channels ───────────────────────────────────────────────────────
            "channel_created" -> handleChannelCreated(json)
            "channel_update" -> handleChannelUpdate(json)
            "channel_post_deleted" -> {
                val channelId = json.optString("channel_id", "")
                val postId    = json.optString("post_id", "")
                if (channelId.isNotEmpty() && postId.isNotEmpty()) {
                    ChannelManager.removePost(channelId, postId)
                    onChannelPostDeleted?.invoke(channelId, postId)
                }
            }
            "channel_deleted" -> {
                val channelId = json.optString("channel_id", "")
                if (channelId.isNotEmpty()) {
                    ChannelManager.removeChannel(channelId)
                    onChannelDeleted?.invoke(channelId)
                }
            }
            "channel_pinned" -> {
                val channelId = json.optString("channel_id", "")
                val postId = json.optString("post_id", "").takeIf { it.isNotEmpty() }
                ChannelManager.getChannel(channelId)?.let {
                    ChannelManager.saveChannel(it.copy(pinnedPostId = postId))
                }
            }

            // ── Status events ──────────────────────────────────────────────────
            "typing"    -> onTypingReceived?.invoke(json.optString("from"))
            "read"      -> onReadReceived?.invoke(json.optString("id"))
            "delivered" -> {
                json.optString("from", "").takeIf { it.isNotEmpty() }?.let { ContactHealthManager.recordDelivered(it) }
                onDeliveredReceived?.invoke(json.optString("id"))
            }

            // ── "Забота о собеседнике": peer health-check ping/pong ────────────
            // See ContactHealthManager.kt and app/src/main/java/com/example/test/
            // MessengerService.kt's mirror of this. Receiving either type just
            // proves the channel is alive right now — reset the silence clock.
            // A pong is sent back via sendAnonOrDirect like any other packet.
            "contact_ping" -> {
                val from = json.optString("from", "").takeIf { it.isNotEmpty() } ?: return
                ContactHealthManager.recordIncoming(from)
                sendAnonOrDirect(from, JSONObject().apply {
                    put("type", "contact_pong")
                    put("from", myFingerprint)
                    put("to", from)
                    put("id", json.optString("id", java.util.UUID.randomUUID().toString()))
                })
            }

            "contact_pong" -> {
                val from = json.optString("from", "").takeIf { it.isNotEmpty() } ?: return
                ContactHealthManager.recordIncoming(from)
            }

            // ── Registration gates rejected — see server.py SERVER_ACCESS_PROTECTED
            // / user_totp_secrets. Both only fire during register(), never mid-
            // session — no retry loop here, same treatment as session_conflict.
            "access_code_required" -> {
                if (ws !== webSocket) return
                System.err.println("WebSocketClient: access_code_required — server requires a one-time access code to register, none/wrong one was sent")
                onChannelError?.invoke("Сервер требует код доступа для регистрации")
                registrationReady?.complete(false)
                disconnect()
            }

            "totp_required" -> {
                if (ws !== webSocket) return
                // Not a full disconnect() -- that would set userDisconnected
                // and block the auto-reconnect that submitRecoveryCode()
                // relies on to retry. Just mark not-really-connected and let
                // onTotpRequired offer the recovery-code fallback; closing
                // the socket (if the user acts) naturally reconnects via the
                // existing onClosed -> scheduleReconnect() path. handshakeDone/
                // _connected are already false at this point (never flipped
                // true before register_ok — see its own comment); reset here
                // anyway as an explicit, defensive statement of the required
                // invariant rather than relying on "never got set".
                System.err.println("WebSocketClient: totp_required — this device_id needs a valid TOTP code to register")
                handshakeDone = false
                _connected.value = false
                onStatusChanged?.invoke(false)
                registrationReady?.complete(false)
                onTotpRequired?.invoke()
            }

            // ── Interactive TOTP enable/disable — see TotpSettingsScreen.kt ────
            "totp_setup_ok" -> {
                val recoveryCodes = json.optJSONArray("recovery_codes")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }
                }
                onTotpSetupResult?.invoke(true, null, recoveryCodes)
            }
            "totp_setup_failed"  -> onTotpSetupResult?.invoke(false, json.optString("reason", null), null)
            "totp_disable_ok"    -> onTotpDisableResult?.invoke(true)
            "totp_disable_failed" -> onTotpDisableResult?.invoke(false)

            "ack"       -> { /* server acknowledged our sent message */ }

            // Server sends "edit" with fields: from, id, text, signature.
            // Parity + auth fix (desktop/Android symmetry audit): Android's
            // "edit" handler VERIFIES the signature over the ciphertext against
            // the sender's identity key and only applies the edit when it
            // passes — Desktop previously applied ANY edit, letting a
            // compromised server (or any party that could inject an `edit`
            // frame) rewrite the text of an already-delivered message with no
            // authentication at all. Now mirrors Android exactly: verify first,
            // then decrypt/apply.
            "edit" -> {
                val msgId  = json.getString("id")
                val from   = json.getString("from")
                val ctB64  = json.getString("text")
                val signature = json.optString("signature", null)
                val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify(ctB64, signature, senderKey)) {
                    System.err.println("WebSocketClient: edit: invalid or missing signature from $from — rejected")
                    return
                }
                // Edits are always encrypted with legacy ephemeral-ECDH
                val newText = runCatching { CryptoManager.decrypt(ctB64) }.getOrElse {
                    System.err.println("WebSocketClient: edit decrypt failed from $from — ${it.message}")
                    return
                }
                onEditReceived?.invoke(msgId, newText)
            }

            // Server relays "message_delete" as-is
            "message_delete" -> {
                val msgId = json.getString("id")
                val from  = json.optString("from", "")
                // S6-53, STEP 10 -- see CHAT_CONTROL_ID_MAX_LEN's own comment.
                if (from.isEmpty() || msgId.length > CHAT_CONTROL_ID_MAX_LEN) return
                // S6-54 (external review 2026-09-06): this platform
                // previously had NO signature at all for this type -- ported
                // Android's scheme identically ("SUBROSA_MESSAGE_DELETE_V1:"
                // domain-separates this from every other signed transcript
                // in this protocol, including group_message_delete's own).
                // A valid signature only proves `from` requested this
                // deletion, not that `from` is entitled to delete the
                // referenced message -- in a direct 1:1 conversation the
                // only two possible authors are the local user and `from`
                // themselves, so the local copy's own `isOwn` flag tells us
                // which: if it's ours (isOwn=true), `from` (the contact)
                // must never be able to delete it merely by knowing its id.
                val signature = json.optString("signature", null)
                val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify("SUBROSA_MESSAGE_DELETE_V1:$msgId", signature, senderKey)) {
                    System.err.println("WebSocketClient: message_delete: invalid or missing signature from $from")
                    return
                }
                val existing = ChatStorage.loadMessages(myFingerprint, from).find { it.id == msgId }
                if (existing != null && existing.isOwn) {
                    System.err.println("WebSocketClient: message_delete: $from tried to delete someone else's (our) message $msgId — rejected")
                    return
                }
                onMessageDeleted?.invoke(from, msgId)
            }

            // Server relays "reaction" with fields: from, message_id, emoji,
            // signature (see server.py's reaction handler — it rebuilds the
            // payload from exactly those fields). Mirrors Android
            // MessengerService "reaction" handler: the emoji ciphertext's
            // signature is verified against the claimed sender's identity key
            // BEFORE decrypt/apply, and a bad/missing signature THROWS (not a
            // plain return) so the anon_delivery envelope's ack never fires
            // for a reaction that was rejected — same class of fix Android
            // documents there. No emoji allow-list on receipt (Android applies
            // none either — the picker restricts the SEND side); a reaction is
            // keyed by sender, so a user's newer reaction overwrites their
            // older one, no dedup needed.
            "reaction" -> {
                val from = json.getString("from")
                val msgId = json.getString("message_id")
                val encryptedEmoji = json.getString("emoji")
                val signature = json.optString("signature", null)
                val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify(encryptedEmoji, signature, senderKey)) {
                    System.err.println("WebSocketClient: reaction: invalid or missing signature from $from")
                    throw SecurityException("reaction: bad or missing signature from $from")
                }
                val emoji = CryptoManager.decrypt(encryptedEmoji)
                onReactionReceived?.invoke(from, msgId, emoji)
            }

            // Server relays "disappear_timer" with fields: from, to, seconds,
            // signature (see server.py sanitize_chat_control — seconds is
            // already validated against CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED
            // server-side, but this is client-side defense-in-depth mirroring
            // Android: a compromised server could hand this device an
            // arbitrary frame directly, and a validly-signed value from a
            // genuinely-authenticated malicious contact still proves only
            // origin, not protocol sanity). Bad seconds or bad/missing
            // signature THROWS so the anon_delivery ack never fires for a
            // rejected control frame (Android's throw-not-return fix).
            "disappear_timer" -> {
                val from = json.getString("from")
                val seconds = json.getLong("seconds")
                if (seconds !in CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED) {
                    System.err.println("WebSocketClient: disappear_timer: invalid value seconds=$seconds from $from")
                    throw SecurityException("disappear_timer: invalid seconds=$seconds from $from")
                }
                val signature = json.optString("signature", null)
                val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
                if (signature == null || senderKey == null ||
                    !CryptoManager.verify(seconds.toString(), signature, senderKey)) {
                    System.err.println("WebSocketClient: disappear_timer: invalid or missing signature from $from")
                    throw SecurityException("disappear_timer: bad or missing signature from $from")
                }
                ChatStorage.setDisappearTimer(myFingerprint, from, seconds)
                onDisappearTimerChanged?.invoke(from, seconds)
            }

            // Server responds to "get_key" with "public_key", field "key" contains the value
            "public_key" -> {
                val fingerprint = json.getString("username")
                val pubKeyB64   = json.optString("key", "").takeIf { it.isNotEmpty() } ?: return
                // checkKeyChange() BEFORE the trust-assignment below — was
                // reversed (found in the 2026-09-13 KeyHistoryManager
                // audit): a changed key must be detected/flagged before
                // this device starts treating it as the contact's active
                // identity, not after. Every other checkKeyChange() call
                // site in this file already had this ordering; this was the
                // one exception.
                if (KeyHistoryManager.checkKeyChange(fingerprint, pubKeyB64)) {
                    onKeyChanged?.invoke(fingerprint)
                }
                peerPublicKeys[fingerprint] = pubKeyB64    // for legacy ECDH encryption
                DesktopCryptoManager.storePeerPublicKey(fingerprint, pubKeyB64)
                ChatStorage.saveContactPublicKey(fingerprint, pubKeyB64)
                // If there are queued messages for this contact, try sending them now
                drainQueue(fingerprint)
            }

            "session_reset" -> {
                val from = json.optString("from", "")
                if (from.isNotEmpty()) {
                    System.err.println("WebSocketClient: session_reset from $from — clearing session")
                    SessionKeyManager.deleteSession(from)
                    // Was missing entirely — session_reset only ever cleared
                    // the Double Ratchet session, never the separately-
                    // cached SPK/PQ-KEM bundle that sealPacketForRecipient()
                    // uses for the OUTER sealed-sender envelope. A peer who
                    // restored a backup onto a fresh install keeps its
                    // long-term identity key but generates a brand-new SPK/
                    // PQ-KEM, unrelated to what the backup restored — our
                    // cached copy of THEIR bundle is now permanently stale
                    // and nothing else invalidates it. Every sealed message
                    // sent afterward lands as a decrypt failure on their end
                    // forever, with zero error on this side (sealing against
                    // a stale cached key always "succeeds" locally). Mirrors
                    // Android's MessengerService.kt "session_reset" handler
                    // exactly. Found in the 2026-09-12 full-logic audit.
                    peerPqPublicKeys.remove(from)
                    ChatStorage.clearContactPqPublicKey(from)
                    bundleRequested.remove(from)
                    requestBundleFor(from)
                }
            }

            // Mirrors Android's MessengerService "pq_bundle_refresh" handler.
            // A peer whose PQ (ML-KEM) prekey we have cached is telling us that
            // cache is stale (they rotated their PQ bundle) — drop the cached
            // PQ key and re-fetch the full prekey bundle so future encryption
            // targets their current key instead of a dead one. This type is in
            // ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE, so the anon_delivery
            // handler has already verified the sender's identity signature
            // before we get here. Without this handler the packet fell through
            // to `else -> unhandled` and Desktop kept encrypting to the stale
            // PQ key indefinitely.
            "pq_bundle_refresh" -> {
                val from = json.optString("from", "")
                if (from.isNotEmpty()) {
                    System.err.println("WebSocketClient: pq_bundle_refresh from $from — our cached PQ bundle is stale, re-requesting")
                    peerPqPublicKeys.remove(from)
                    ChatStorage.clearContactPqPublicKey(from)
                    bundleRequested.remove(from)
                    requestBundleFor(from)
                }
            }

            "avatar_data" -> {
                val from   = json.optString("from", "")
                val avatar = json.optString("avatar", "")
                if (from.isNotEmpty() && avatar.isNotEmpty()) {
                    ChatStorage.saveContactAvatar(from, avatar)
                    AvatarStore.decodeAndStore(from, avatar)
                }
            }

            "turn_config" -> {
                NetworkConfig.TurnCredentials.username = json.optString("user").takeIf { it.isNotBlank() }
                NetworkConfig.TurnCredentials.password = json.optString("pass").takeIf { it.isNotBlank() }
            }

            // ── Calls ──────────────────────────────────────────────────────────
            "call_offer" -> DesktopCallManager.handleOffer(
                from = json.getString("from"),
                sdp = json.getString("sdp"),
                cId = json.getString("call_id"),
                isVideo = json.optBoolean("is_video", false)
            )
            "call_answer" -> DesktopCallManager.handleAnswer(json.getString("from"), json.getString("sdp"))
            "call_ice" -> DesktopCallManager.handleIceCandidate(
                from = json.getString("from"),
                sdpMid = json.optString("sdp_mid", null),
                sdpMLineIndex = json.optInt("sdp_m_line_index", 0),
                candidate = json.getString("candidate")
            )
            // Android's DEFAULT outgoing ICE path is call_ice_batch (see
            // CallManager.flushIceCandidates / ICE_BATCH_DEBOUNCE_MS) — it
            // coalesces a call's 10-30+ ICE candidates into ONE anon_message
            // to avoid burning one anon token per candidate. Desktop only sent
            // single call_ice, so it received single call_ice fine, but every
            // batch from an Android peer fell through to `else -> unhandled`
            // and its candidates were silently dropped — breaking Desktop←
            // Android call connectivity. Unpack the batch into the same
            // per-candidate handler.
            "call_ice_batch" -> {
                try {
                    val from = json.getString("from")
                    val candidates = json.getJSONArray("candidates")
                    for (i in 0 until candidates.length()) {
                        val c = candidates.getJSONObject(i)
                        DesktopCallManager.handleIceCandidate(
                            from = from,
                            sdpMid = c.optString("sdp_mid", null),
                            sdpMLineIndex = c.optInt("sdp_m_line_index", 0),
                            candidate = c.getString("candidate")
                        )
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: call_ice_batch error — ${e.message}")
                }
            }
            "call_ice_restart" -> DesktopCallManager.handleIceRestart(json.getString("from"), json.getString("sdp"))
            "call_end" -> DesktopCallManager.handleCallEnd(json.getString("from"), json.optString("reason", "hangup"))
            "call_request_audio", "call_request_video" -> DesktopCallManager.handleIncomingCallRequest(
                from = json.getString("from"),
                cId = json.getString("call_id"),
                isVideo = type == "call_request_video"
            )
            "call_response" -> DesktopCallManager.handleCallResponse(
                from = json.getString("from"),
                cId = json.getString("call_id"),
                accepted = json.optBoolean("accepted", false)
            )

            // ── Group calls (mesh) ──────────────────────────────────────────────
            // Full mesh, ported from Android CallManager.kt — see
            // DesktopCallManager's own header comment for exactly what was and
            // wasn't ported. call_ice_batch is intentionally NOT listed here:
            // it's shared with 1:1 calls and already dispatches to
            // DesktopCallManager.handleIceCandidate() above, which now routes
            // by `from` into the correct mesh peer when a group call is active.
            "call_group_invite" -> DesktopCallManager.handleGroupInvite(
                from = json.getString("from"),
                cId = json.getString("call_id"),
                isVideo = json.optBoolean("is_video", false),
                gId = json.optString("group_id", "")
            )
            "call_group_join" -> DesktopCallManager.handleGroupJoin(
                from = json.getString("from"),
                sdp = json.getString("sdp"),
                cId = json.getString("call_id"),
                gId = json.optString("group_id", "")
            )
            "call_group_answer" -> DesktopCallManager.handleGroupAnswer(json.getString("from"), json.getString("sdp"))
            "call_group_peer_list" -> {
                val peersArr = json.optJSONArray("peers")
                if (peersArr != null) {
                    val peers = (0 until peersArr.length()).map { peersArr.getString(it) }
                    DesktopCallManager.handleGroupPeerList(peers)
                }
            }
            "call_group_leave" -> DesktopCallManager.handleGroupLeave(
                json.getString("from"), json.optString("reason", "left")
            )

            "ping" -> webSocket?.send(JSONObject().apply { put("type", "pong") }.toString())

            else -> System.err.println("WebSocketClient: unhandled type=$type")
        }
    }

    // ── Image reassembly ──────────────────────────────────────────────────────

    private fun handleImageChunk(json: JSONObject) {
        val imageId     = json.getString("image_id")
        val chunkIndex  = json.getInt("chunk_index")
        val totalChunks = json.getInt("total_chunks")
        val chunkData   = json.getString("data")
        val geoRaw = json.opt("geo")
        val geo    = if (geoRaw is String && geoRaw.isNotEmpty()) geoRaw else null
        val from   = json.getString("from")
        val signature = json.optString("signature", null)

        // Same gap as file_chunk had (see handleFileChunk) — previously
        // accepted unsigned chunk data from any contact. See
        // docs/ISSUE_backup_identity_hijack.md, Tier 4 item 12b.
        val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
        if (signature == null || senderKey == null ||
            !CryptoManager.verifyChunk(chunkData, signature, senderKey, imageId, chunkIndex)) {
            System.err.println("WebSocketClient: bad image_chunk signature from $from")
            return
        }

        // S6-49: bound total_chunks/chunk_index and enforce the
        // simultaneous-transfer cap BEFORE ever touching imageChunks/
        // imageTotals.
        if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS || chunkIndex !in 0 until totalChunks) {
            System.err.println("WebSocketClient: invalid chunk_index/total_chunks in image_chunk from $from ($chunkIndex/$totalChunks)")
            return
        }
        if (!pruneAndAdmitTransfer(imageChunks, imageTouchedAt, imageId, imageReceivedBytes)) {
            System.err.println("WebSocketClient: too many concurrent image transfers — $imageId rejected")
            return
        }
        if (chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
            System.err.println("WebSocketClient: oversized image_chunk data from $from — cancelling $imageId")
            imageChunks.remove(imageId); imageTotals.remove(imageId); imageTouchedAt.remove(imageId)
            imageGeos.remove(imageId); imageReceivedBytes.remove(imageId)
            return
        }
        val imageBucket = imageChunks.getOrPut(imageId) { mutableMapOf() }
        if (!accountChunkBytes(imageBucket, imageReceivedBytes, imageId, chunkIndex, chunkData)) {
            System.err.println("WebSocketClient: image transfer $imageId exceeded byte ceiling — cancelling")
            imageChunks.remove(imageId); imageTotals.remove(imageId); imageTouchedAt.remove(imageId)
            imageGeos.remove(imageId); imageReceivedBytes.remove(imageId)
            return
        }

        if (chunkIndex == 0 && geo != null) imageGeos[imageId] = geo
        imageBucket[chunkIndex] = chunkData
        imageTotals[imageId] = totalChunks

        if (imageChunks[imageId]!!.size == totalChunks) {
            val combined = (0 until totalChunks)
                .joinToString("") { imageChunks[imageId]!![it]!! }
            imageChunks.remove(imageId)
            imageTotals.remove(imageId)
            imageTouchedAt.remove(imageId)
            imageReceivedBytes.remove(imageId)
            val geoCoords = imageGeos.remove(imageId)

            val encBytes = runCatching { Base64.getDecoder().decode(combined) }.getOrElse {
                System.err.println("WebSocketClient: image base64 decode failed — ${it.message}")
                return
            }
            val rawBytes = DesktopCryptoManager.decryptImageBytes(from, encBytes) ?: return
            // Persisted centrally so an image arriving with no ChatScreen
            // open for `from` isn't dropped entirely — see
            // persistAndNotifyIncoming's comment.
            val id = java.util.UUID.randomUUID().toString()
            try {
                val imgFile = writeEncryptedBlob(id, rawBytes)
                ChatStorage.saveOrUpdateMessage(myFingerprint, from,
                    ChatStorage.StoredMessage(
                        id = id, text = geoCoords ?: "", isOwn = false,
                        imagePath = imgFile.absolutePath, isRead = false, expiresAt = computeExpiresAt(from)
                    )
                )
                onImageReceived?.invoke(from, rawBytes, geoCoords, id)
            } catch (e: Exception) {
                System.err.println("WebSocketClient: failed to store image — ${e.message}")
            }
        }
    }

    // ── File reassembly ───────────────────────────────────────────────────────

    /** Strips path-separator/traversal characters from a peer-supplied
     *  file_id before it's used to build a filesystem path in ChatScreen —
     *  it comes straight from another contact's JSON and must not be
     *  trusted. */
    private fun sanitizePathComponent(raw: String): String {
        val cleaned = raw.replace(Regex("[\\\\/:*?\"<>|]"), "_").replace("..", "_")
        return cleaned.ifBlank { "file" }
    }

    private fun handleFileChunk(json: JSONObject) {
        val fileId      = sanitizePathComponent(json.getString("file_id"))
        val encryptedFileName = json.optString("encrypted_file_name", null)
        val legacyFileName    = json.optString("file_name", null)
        val chunkIndex  = json.getInt("chunk_index")
        val totalChunks = json.getInt("total_chunks")
        val chunkData   = json.getString("data")
        val from        = json.getString("from")
        val signature   = json.optString("signature", null)

        // Previously not checked at all here — Android's file_chunk handler
        // always verified this, Desktop never did. A malicious/compromised
        // contact could otherwise inject arbitrary chunk data attributed to
        // themselves without a valid signature. See
        // docs/ISSUE_backup_identity_hijack.md, Tier 4 item 12b.
        val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
        if (signature == null || senderKey == null ||
            !CryptoManager.verifyChunk(chunkData, signature, senderKey, fileId, chunkIndex)) {
            System.err.println("WebSocketClient: bad file_chunk signature from $from")
            return
        }

        // S6-49: bound total_chunks/chunk_index and enforce the
        // simultaneous-transfer cap BEFORE ever touching fileChunks/
        // fileTotals/fileNames.
        if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS || chunkIndex !in 0 until totalChunks) {
            System.err.println("WebSocketClient: invalid chunk_index/total_chunks in file_chunk from $from ($chunkIndex/$totalChunks)")
            return
        }
        if (!pruneAndAdmitTransfer(fileChunks, fileTouchedAt, fileId, fileReceivedBytes)) {
            System.err.println("WebSocketClient: too many concurrent file transfers — $fileId rejected")
            return
        }
        if (chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
            System.err.println("WebSocketClient: oversized file_chunk data from $from — cancelling $fileId")
            fileChunks.remove(fileId); fileTotals.remove(fileId); fileTouchedAt.remove(fileId)
            fileNames.remove(fileId); fileReceivedBytes.remove(fileId)
            return
        }
        val fileBucket = fileChunks.getOrPut(fileId) { mutableMapOf() }
        if (!accountChunkBytes(fileBucket, fileReceivedBytes, fileId, chunkIndex, chunkData)) {
            System.err.println("WebSocketClient: file transfer $fileId exceeded byte ceiling — cancelling")
            fileChunks.remove(fileId); fileTotals.remove(fileId); fileTouchedAt.remove(fileId)
            fileNames.remove(fileId); fileReceivedBytes.remove(fileId)
            return
        }

        // Decrypted once, only the first time this fileId is seen — mirrors
        // the Android fix. Falls back to a plaintext legacy field, then a
        // generic name, if decryption isn't possible.
        if (!fileNames.containsKey(fileId)) {
            val decryptedName = try {
                when {
                    encryptedFileName != null -> CryptoManager.decrypt(encryptedFileName)
                    legacyFileName != null -> legacyFileName
                    else -> "file"
                }
            } catch (e: Exception) {
                System.err.println("WebSocketClient: file_name decrypt failed — ${e.message}")
                legacyFileName ?: "file"
            }
            fileNames[fileId] = sanitizePathComponent(decryptedName)
        }
        fileBucket[chunkIndex] = chunkData
        fileTotals[fileId] = totalChunks

        if (fileChunks[fileId]!!.size == totalChunks) {
            val combined = (0 until totalChunks)
                .joinToString("") { fileChunks[fileId]!![it]!! }
            fileChunks.remove(fileId)
            fileTotals.remove(fileId)
            fileTouchedAt.remove(fileId)
            fileReceivedBytes.remove(fileId)
            val name = fileNames.remove(fileId) ?: "file"

            val encBytes = runCatching { Base64.getDecoder().decode(combined) }.getOrElse {
                System.err.println("WebSocketClient: file base64 decode failed — ${it.message}")
                return
            }
            val rawBytes = DesktopCryptoManager.decryptImageBytes(from, encBytes) ?: return
            // Persisted centrally so a file arriving with no ChatScreen open
            // for `from` isn't dropped entirely — see persistAndNotifyIncoming's
            // comment. Blob on disk is keyed by the wire fileId (matches
            // ChatScreen's prior behavior); the ChatStorage row gets its own
            // fresh id, same rule ChatScreen used to apply itself.
            val id = java.util.UUID.randomUUID().toString()
            try {
                val outFile = writeEncryptedBlob(fileId, rawBytes)
                ChatStorage.saveOrUpdateMessage(myFingerprint, from,
                    ChatStorage.StoredMessage(
                        id = id, text = "", isOwn = false,
                        filePath = outFile.absolutePath, fileName = name,
                        isRead = false, expiresAt = computeExpiresAt(from)
                    )
                )
                onFileReceived?.invoke(from, fileId, name, rawBytes, 0, id)
            } catch (e: Exception) {
                System.err.println("WebSocketClient: failed to store file — ${e.message}")
            }
        }
    }

    /** Video circle chunk reassembly — mirrors handleFileChunk's pattern
     *  exactly, but (like Android's processVideoChunk) writes the decrypted
     *  result straight to encrypted-at-rest blob storage itself and hands
     *  back a File, rather than raw bytes for the UI to store — matching
     *  Android's onVideoReceived(videoId, file, duration) shape. transferKey
     *  is "$from:$videoId" (not bare videoId) so two different senders can
     *  never collide on the same accumulator entry even if a videoId were
     *  ever reused. */
    private fun handleVideoChunk(
        from: String, videoId: String, chunkIndex: Int, totalChunks: Int,
        chunkData: String, duration: Int, signature: String?
    ) {
        val videoIdSafe = sanitizePathComponent(videoId)
        val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
        if (signature == null || senderKey == null ||
            !CryptoManager.verifyChunk(chunkData, signature, senderKey, videoId, chunkIndex)) {
            System.err.println("WebSocketClient: bad video_chunk signature from $from")
            return
        }
        if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS || chunkIndex !in 0 until totalChunks) {
            System.err.println("WebSocketClient: invalid chunk_index/total_chunks in video_chunk from $from ($chunkIndex/$totalChunks)")
            return
        }
        val transferKey = "$from:$videoIdSafe"
        if (!pruneAndAdmitTransfer(videoChunks, videoTouchedAt, transferKey, videoReceivedBytes)) {
            System.err.println("WebSocketClient: too many concurrent video transfers — $transferKey rejected")
            return
        }
        if (chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
            System.err.println("WebSocketClient: oversized video_chunk data from $from — cancelling $transferKey")
            videoChunks.remove(transferKey); videoTotals.remove(transferKey); videoTouchedAt.remove(transferKey)
            videoReceivedBytes.remove(transferKey); videoDurations.remove(transferKey)
            return
        }
        val bucket = videoChunks.getOrPut(transferKey) { mutableMapOf() }
        if (!accountChunkBytes(bucket, videoReceivedBytes, transferKey, chunkIndex, chunkData)) {
            System.err.println("WebSocketClient: video transfer $transferKey exceeded byte ceiling — cancelling")
            videoChunks.remove(transferKey); videoTotals.remove(transferKey); videoTouchedAt.remove(transferKey)
            videoReceivedBytes.remove(transferKey); videoDurations.remove(transferKey)
            return
        }
        bucket[chunkIndex] = chunkData
        videoTotals[transferKey] = totalChunks
        videoDurations[transferKey] = duration

        if (videoChunks[transferKey]!!.size == totalChunks) {
            val combined = (0 until totalChunks).joinToString("") { videoChunks[transferKey]!![it]!! }
            videoChunks.remove(transferKey)
            videoTotals.remove(transferKey)
            videoTouchedAt.remove(transferKey)
            videoReceivedBytes.remove(transferKey)
            val dur = videoDurations.remove(transferKey) ?: duration

            val encBytes = runCatching { Base64.getDecoder().decode(combined) }.getOrElse {
                System.err.println("WebSocketClient: video base64 decode failed — ${it.message}")
                return
            }
            val rawBytes = DesktopCryptoManager.decryptImageBytes(from, encBytes) ?: return
            try {
                val outFile = writeEncryptedBlob(videoIdSafe, rawBytes)
                // Persisted centrally so a video circle arriving with no
                // ChatScreen open for `from` isn't dropped entirely — see
                // persistAndNotifyIncoming's comment.
                ChatStorage.saveOrUpdateMessage(myFingerprint, from,
                    ChatStorage.StoredMessage(
                        id = videoIdSafe, text = "", isOwn = false,
                        videoPath = outFile.absolutePath, videoDuration = dur,
                        isRead = false, expiresAt = computeExpiresAt(from)
                    )
                )
                println("WebSocketClient: video circle $videoIdSafe received from $from")
                onVideoReceived?.invoke(from, videoIdSafe, outFile, dur)
            } catch (e: Exception) {
                System.err.println("WebSocketClient: failed to store video circle $videoIdSafe — ${e.message}")
            }
        }
    }

    // ── Group protocol handlers ───────────────────────────────────────────────

    private fun handleGroupCreate(json: JSONObject) {
        val groupId   = json.getString("group_id")
        val groupName = json.getString("group_name")
        val groupAvatar = json.getString("group_avatar")
        val from      = json.getString("from")
        val encryptedGroupKey = json.getString("encrypted_group_key")
        val signature = json.optString("signature", null)
        val rosterSignature = json.optString("roster_signature", null)
        try {
            val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
            if (signature == null || senderKey == null) {
                System.err.println("WebSocketClient: group_create without key from $from")
                return
            }
            // Binds group_id + group_name + group_avatar + the key blob
            // itself (S6-64) — see groupCreatePayload()'s own comment.
            if (!CryptoManager.verify(groupCreatePayload(groupId, groupName, groupAvatar, encryptedGroupKey), signature, senderKey)) {
                System.err.println("WebSocketClient: bad group_create signature from $from")
                return
            }
            if (GroupManager.getGroup(groupId) != null) return // already a member

            // Full signed roster required, not merely bounded-if-present, as
            // of S6-65 — mirrors Android's fix. No unsigned-roster fallback
            // for a current-version group_create; see Android's own comment
            // for why the old fallback was actually the ONLY path any
            // current-version group_create ever took (server stripped these
            // fields from every relay until now).
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
                    System.err.println("WebSocketClient: bad group roster signature from $from")
                    return
                }
                if (myFingerprint !in membersFromPacket) {
                    System.err.println("WebSocketClient: group_create roster doesn't include us — rejected")
                    return
                }
                members = membersFromPacket
                admins = adminsFromPacket
            } else {
                System.err.println("WebSocketClient: group_create without roster from $from — rejected")
                return
            }

            // member_keys: learn every fellow member's EC/PQ public key +
            // display name at join time — see memberKeysPayload()'s own
            // comment for why this exists. Separately signed from
            // roster_signature above and verified independently, so a
            // missing/invalid member_keys just means "no key-learning bonus
            // this time" (backward compatible with a sender that hasn't
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
                                if (fp == myFingerprint) return@forEach
                                val pk = entry.getString("public_key")
                                val pqB64 = entry.getString("pq_public_key")
                                val name = entry.optString("name", "")

                                // Same fingerprint-self-consistency check
                                // processSessionInit() already applies to a
                                // directly-received identity key — the admin
                                // vouching for a roster doesn't extend to
                                // vouching for an internally-inconsistent key.
                                val pkBytes = Base64.getDecoder().decode(pk)
                                val actualFp = java.security.MessageDigest.getInstance("SHA-256")
                                    .digest(pkBytes).take(8).joinToString("") { "%02X".format(it) }
                                if (actualFp != fp) {
                                    System.err.println("WebSocketClient: member_keys: key for $fp doesn't match fingerprint (got $actualFp) — skipped")
                                    return@forEach
                                }

                                if (KeyHistoryManager.checkKeyChange(fp, pk)) {
                                    System.err.println("WebSocketClient: TOFU: $fp's key changed via group $groupId member_keys!")
                                    onKeyChanged?.invoke(fp)
                                }
                                val pqBytes = Base64.getDecoder().decode(pqB64)
                                ChatStorage.saveContactPublicKey(fp, pk)
                                ChatStorage.saveContactPqPublicKey(fp, pqBytes)
                                peerPublicKeys[fp] = pk
                                peerPqPublicKeys[fp] = pqBytes
                                // Don't clobber a name the user already has
                                // (their own rename, or one learned via a
                                // real 1:1 exchange) — only fill the gap.
                                if (name.isNotBlank() && ChatStorage.getContactName(fp) == fp.substringBefore("_")) {
                                    ChatStorage.saveContactName(fp, name)
                                }
                            } catch (e: Exception) {
                                System.err.println("WebSocketClient: member_keys entry error — ${e.message}")
                            }
                        }
                    } else {
                        System.err.println("WebSocketClient: group_create: bad member_keys signature from $from — member keys not learned")
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: group_create: member_keys processing error — ${e.message}")
                }
            }

            val groupKey = GroupManager.decryptGroupKey(encryptedGroupKey)
            val group = Group(
                id = groupId,
                name = groupName,
                avatar = groupAvatar,
                members = members,
                admins = admins,
                createdBy = from,
                groupKey = groupKey
            )
            GroupManager.saveGroup(group)

            val inviteSignature = CryptoManager.sign("$groupId:${myFingerprint}")
            webSocket?.send(JSONObject().apply {
                put("type", "group_invite_accepted")
                put("from", myFingerprint)
                put("to", from)
                put("group_id", groupId)
                put("new_member", myFingerprint)
                put("new_member_name", displayName)
                put("signature", inviteSignature)
            }.toString())

            onGroupInviteReceived?.invoke(group, encryptedGroupKey)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: group_create error — ${e.message}")
        }
    }

    private fun handleGroupMessage(json: JSONObject) {
        val groupId    = json.getString("group_id")
        val messageId  = json.getString("message_id")
        val from       = json.getString("from")
        val senderName = json.getString("sender_name")
        val encryptedText = json.getString("text")
        val signature  = json.optString("signature", null)
        try {
            // Peek-only (isDuplicateId), not dedup() — found in the
            // 2026-09-13 voice/group_message dedup audit: dedup() marks
            // messageId "seen" immediately, before the group lookup,
            // signature verification, or decrypt below had even run. Any of
            // those failing then permanently poisoned this id — a
            // legitimate retry of the exact same group message (e.g. once a
            // reordered group_create finally arrives, fixing the "unknown
            // group" case) would hit this same check, find it already
            // marked from the FAILED first attempt, and be silently dropped
            // as a fake duplicate forever. Marked processed only at the end,
            // once group lookup + signature verification + decrypt have all
            // actually succeeded.
            if (isDuplicateId(messageId)) return
            val group = GroupManager.getGroup(groupId) ?: run {
                System.err.println("WebSocketClient: group_message for unknown group $groupId")
                // Thrown, not returned: an unknown group can mean
                // group_create just hasn't arrived yet (reordered delivery)
                // — not ACKing lets the server's token_pending keep this
                // queued for retry instead of losing it if group_create
                // later catches up. Mirrors Android's group_message handler.
                throw SecurityException("group_message: неизвестная группа $groupId")
            }
            val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
            if (signature == null || senderKey == null) {
                System.err.println("WebSocketClient: group_message without key from $from")
                throw SecurityException("group_message: нет ключа от $from")
            }
            if (!CryptoManager.verify(encryptedText, signature, senderKey)) {
                System.err.println("WebSocketClient: bad group_message signature from $from")
                throw SecurityException("group_message: неверная подпись от $from")
            }
            val decryptedText = GroupManager.decryptGroupMessage(encryptedText, group.groupKey!!)
            val message = GroupMessage(
                id = messageId, groupId = groupId, senderId = from,
                senderName = senderName, text = decryptedText, isOwn = from == myFingerprint,
                replyToId = json.optString("reply_to_id", null)?.takeIf { it.isNotBlank() }
            )
            GroupManager.saveGroupMessage(myFingerprint, message)
            // Marked processed ONLY now — after group lookup, signature
            // verification, and decrypt have all already succeeded.
            markProcessed(messageId)
            if (!message.isOwn) DesktopNotificationService.notifyGroupMessage(groupId, senderName, decryptedText)
            onGroupMessageReceived?.invoke(groupId, message)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: group_message error — ${e.message}")
            // Re-thrown — was silently swallowed before this fix, so
            // anon_delivery's ack fired as if this group message had
            // actually been received even on a genuine failure. Mirrors
            // Android's group_message handler and this file's own
            // "message"/session_init/"voice" fixes.
            throw e
        }
    }

    /** Reassembles a group_image_batch — wire-compatible with Android's
     *  MessengerService handler: each incoming message carries a BATCH of
     *  chunks (a "chunks" array, up to 15), not one chunk per message like
     *  1:1 image_chunk. Reuses the same imageChunks/imageTotals/
     *  imageTouchedAt/imageReceivedBytes accumulator maps as 1:1 transfers,
     *  keyed by a compound "$groupId:$from:$imageId" so the two never
     *  collide (mirrors Android's own transferKey scheme). Decrypts with the
     *  GROUP's shared AES key (GroupManager.decryptGroupMessage), not
     *  per-recipient ECDH like 1:1 — matches how sendGroupImage() encrypted
     *  it. Persists unconditionally before notifying the UI callback, same
     *  "don't depend on which screen is mounted" fix as persistAndNotifyIncoming. */
    private fun handleGroupImageBatch(json: JSONObject) {
        val groupId = json.getString("group_id")
        val from = json.getString("from")
        val imageId = json.getString("image_id")
        val totalChunks = json.getInt("total_chunks")
        val chunksArr = json.getJSONArray("chunks")

        val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
        val groupKey = GroupManager.getGroup(groupId)?.groupKey
        if (senderKey == null || groupKey == null) {
            System.err.println("WebSocketClient: group_image_batch: no sender key or group $groupId")
            return
        }
        if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS) {
            System.err.println("WebSocketClient: group_image_batch: invalid total_chunks from $from ($totalChunks)")
            return
        }
        val transferKey = "$groupId:$from:$imageId"
        if (!pruneAndAdmitTransfer(imageChunks, imageTouchedAt, transferKey, imageReceivedBytes)) {
            System.err.println("WebSocketClient: too many concurrent group image transfers — $transferKey rejected")
            return
        }
        val chunks = imageChunks.getOrPut(transferKey) { mutableMapOf() }
        for (i in 0 until chunksArr.length()) {
            val c = chunksArr.getJSONObject(i)
            val chunkIndex = c.getInt("chunk_index")
            val chunkData = c.getString("data")
            val signature = c.optString("signature", null)
            if (signature == null || !CryptoManager.verifyChunk(chunkData, signature, senderKey, imageId, chunkIndex)) {
                System.err.println("WebSocketClient: bad group_image chunk signature from $from")
                continue
            }
            if (chunkIndex !in 0 until totalChunks || chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
                System.err.println("WebSocketClient: group_image_batch: invalid chunk_index/data from $from — cancelling $transferKey")
                imageChunks.remove(transferKey); imageTouchedAt.remove(transferKey); imageReceivedBytes.remove(transferKey)
                return
            }
            if (!accountChunkBytes(chunks, imageReceivedBytes, transferKey, chunkIndex, chunkData)) {
                System.err.println("WebSocketClient: group image transfer $transferKey exceeded byte ceiling — cancelling")
                imageChunks.remove(transferKey); imageTouchedAt.remove(transferKey); imageReceivedBytes.remove(transferKey)
                return
            }
            chunks[chunkIndex] = chunkData
        }
        imageTotals[transferKey] = totalChunks

        if (chunks.size == totalChunks) {
            val combined = (0 until totalChunks).joinToString("") { chunks[it]!! }
            imageChunks.remove(transferKey)
            imageTotals.remove(transferKey)
            imageTouchedAt.remove(transferKey)
            imageReceivedBytes.remove(transferKey)

            try {
                val decryptedBase64 = GroupManager.decryptGroupMessage(combined, groupKey)
                val imageBytes = Base64.getDecoder().decode(decryptedBase64)
                val id = java.util.UUID.randomUUID().toString()
                val imgFile = writeEncryptedBlob(id, imageBytes)
                val message = GroupMessage(
                    id = id, groupId = groupId, senderId = from,
                    senderName = ChatStorage.getContactName(from).ifBlank { from },
                    text = "", isOwn = false, imagePath = imgFile.absolutePath
                )
                GroupManager.saveGroupMessage(myFingerprint, message)
                onGroupImageReceived?.invoke(groupId, from, id, imgFile)
            } catch (e: Exception) {
                System.err.println("WebSocketClient: group_image_batch decrypt/store failed — ${e.message}")
            }
        }
    }

    /** Admin-only, enforced here (not just left to the sender's own UI
     *  gating) — a compromised or modified non-admin client could otherwise
     *  push an arbitrary avatar to every member. Mirrors Android's
     *  identical handleGroupAvatarUpdate(). New 2026-09-21, group chat
     *  previously had no photo-avatar update path at all, and its own
     *  emoji picker never notified other members either. */
    private fun handleGroupAvatarUpdate(json: JSONObject) {
        val from = json.getString("from")
        val groupId = json.getString("group_id")
        val encryptedAvatar = json.getString("avatar")
        val signature = json.optString("signature", null)

        val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
        val group = GroupManager.getGroup(groupId)
        val groupKey = group?.groupKey

        if (senderKey == null || groupKey == null) {
            System.err.println("WebSocketClient: group_avatar_update: no sender key or group $groupId")
            return
        }
        if (!GroupManager.isAdmin(groupId, from)) {
            System.err.println("WebSocketClient: group_avatar_update: $from is not admin of $groupId — rejected")
            return
        }
        if (signature == null || !CryptoManager.verify(encryptedAvatar, signature, senderKey)) {
            System.err.println("WebSocketClient: group_avatar_update: bad signature from $from")
            return
        }

        try {
            val decrypted = GroupManager.decryptGroupMessage(encryptedAvatar, groupKey)
            // "EMOJI:" prefix mirrors the existing "VOICE:"-prefix
            // convention this codebase already uses for group voice
            // messages riding inside an otherwise-photo/text field — the
            // emoji picker used to only update local storage, never
            // notifying other members at all.
            val updated = if (decrypted.startsWith("EMOJI:")) {
                group.copy(avatar = decrypted.removePrefix("EMOJI:"))
            } else {
                val avatarBytes = Base64.getDecoder().decode(decrypted)
                val avatarFile = writeEncryptedBlob("group_avatar_$groupId", avatarBytes)
                group.copy(avatarPath = avatarFile.absolutePath)
            }
            GroupManager.saveGroup(updated)
            onGroupAvatarUpdated?.invoke(groupId)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: group_avatar_update decrypt/store failed — ${e.message}")
        }
    }

    /** Reassembles a group_file_batch — same batched-chunks-per-message shape
     *  and compound-transferKey scheme as handleGroupImageBatch() above, plus
     *  the file name (also encrypted with the group key by sendGroupFile()). */
    private fun handleGroupFileBatch(json: JSONObject) {
        val groupId = json.getString("group_id")
        val from = json.getString("from")
        val fileId = sanitizePathComponent(json.getString("file_id"))
        val encryptedFileName = json.optString("encrypted_file_name", null)
        val totalChunks = json.getInt("total_chunks")
        val chunksArr = json.getJSONArray("chunks")

        val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
        val groupKey = GroupManager.getGroup(groupId)?.groupKey
        if (senderKey == null || groupKey == null) {
            System.err.println("WebSocketClient: group_file_batch: no sender key or group $groupId")
            return
        }
        if (totalChunks !in 1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS) {
            System.err.println("WebSocketClient: group_file_batch: invalid total_chunks from $from ($totalChunks)")
            return
        }
        val transferKey = "$groupId:$from:$fileId"
        if (!pruneAndAdmitTransfer(fileChunks, fileTouchedAt, transferKey, fileReceivedBytes)) {
            System.err.println("WebSocketClient: too many concurrent group file transfers — $transferKey rejected")
            return
        }
        if (!fileNames.containsKey(transferKey)) {
            val decryptedName = try {
                if (encryptedFileName != null) GroupManager.decryptGroupMessage(encryptedFileName, groupKey) else "file"
            } catch (e: Exception) {
                System.err.println("WebSocketClient: group file_name decrypt failed — ${e.message}")
                "file"
            }
            fileNames[transferKey] = sanitizePathComponent(decryptedName)
        }
        val chunks = fileChunks.getOrPut(transferKey) { mutableMapOf() }
        for (i in 0 until chunksArr.length()) {
            val c = chunksArr.getJSONObject(i)
            val chunkIndex = c.getInt("chunk_index")
            val chunkData = c.getString("data")
            val signature = c.optString("signature", null)
            if (signature == null || !CryptoManager.verifyChunk(chunkData, signature, senderKey, fileId, chunkIndex)) {
                System.err.println("WebSocketClient: bad group_file chunk signature from $from")
                continue
            }
            if (chunkIndex !in 0 until totalChunks || chunkData.length > MEDIA_CHUNK_DATA_MAX_LEN) {
                System.err.println("WebSocketClient: group_file_batch: invalid chunk_index/data from $from — cancelling $transferKey")
                fileChunks.remove(transferKey); fileTouchedAt.remove(transferKey); fileReceivedBytes.remove(transferKey); fileNames.remove(transferKey)
                return
            }
            if (!accountChunkBytes(chunks, fileReceivedBytes, transferKey, chunkIndex, chunkData)) {
                System.err.println("WebSocketClient: group file transfer $transferKey exceeded byte ceiling — cancelling")
                fileChunks.remove(transferKey); fileTouchedAt.remove(transferKey); fileReceivedBytes.remove(transferKey); fileNames.remove(transferKey)
                return
            }
            chunks[chunkIndex] = chunkData
        }
        fileTotals[transferKey] = totalChunks

        if (chunks.size == totalChunks) {
            val combined = (0 until totalChunks).joinToString("") { chunks[it]!! }
            val name = fileNames.remove(transferKey) ?: "file"
            fileChunks.remove(transferKey)
            fileTotals.remove(transferKey)
            fileTouchedAt.remove(transferKey)
            fileReceivedBytes.remove(transferKey)

            try {
                val decryptedBase64 = GroupManager.decryptGroupMessage(combined, groupKey)
                val fileBytes = Base64.getDecoder().decode(decryptedBase64)
                val id = java.util.UUID.randomUUID().toString()
                val outFile = writeEncryptedBlob(fileId, fileBytes)
                val message = GroupMessage(
                    id = id, groupId = groupId, senderId = from,
                    senderName = ChatStorage.getContactName(from).ifBlank { from },
                    text = "", isOwn = false, filePath = outFile.absolutePath, fileName = name
                )
                GroupManager.saveGroupMessage(myFingerprint, message)
                onGroupFileReceived?.invoke(groupId, from, id, outFile, name)
            } catch (e: Exception) {
                System.err.println("WebSocketClient: group_file_batch decrypt/store failed — ${e.message}")
            }
        }
    }

    private fun handleGroupMemberRemoved(json: JSONObject) {
        val groupId = json.getString("group_id")
        val removedMember = json.getString("removed_member")
        val from = json.optString("from", null)
        val signature = json.optString("signature", null)
        try {
            val group = GroupManager.getGroup(groupId) ?: return
            if (from == null || !GroupManager.isAdmin(groupId, from)) {
                System.err.println("WebSocketClient: group_member_removed from non-admin $from — rejected")
                return
            }
            val adminKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
            if (signature == null || adminKey == null ||
                !CryptoManager.verify("$groupId:$removedMember", signature, adminKey)) {
                System.err.println("WebSocketClient: bad group_member_removed signature from $from")
                return
            }
            GroupManager.removeMember(groupId, from, removedMember)
            // removeMember() deletes the local group entirely when WE are
            // the one removed (see its own comment) — nothing left to
            // attach a "member left" system message to. Notify the chat
            // list directly instead, same shape as onChannelDeleted.
            if (GroupManager.getGroup(groupId) == null) {
                onGroupDeleted?.invoke(groupId)
            } else {
                val sysMessage = GroupMessage(
                    id = java.util.UUID.randomUUID().toString(), groupId = groupId,
                    senderId = "system", senderName = "Система",
                    text = "${ChatStorage.getContactName(removedMember)} покинул(а) группу", isOwn = false
                )
                GroupManager.saveGroupMessage(myFingerprint, sysMessage)
                onGroupMessageReceived?.invoke(groupId, sysMessage)
            }
        } catch (e: Exception) {
            System.err.println("WebSocketClient: group_member_removed error — ${e.message}")
        }
    }

    private fun handleGroupKeyRotation(json: JSONObject) {
        val groupId = json.getString("group_id")
        val encryptedNewKey = json.getString("encrypted_new_key")
        val signature = json.optString("signature", null)
        val from = json.getString("from")
        try {
            val senderKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
            if (signature == null || senderKey == null) return
            // groupId bound into the signed payload (external review
            // 2026-09-08, S6-60, mirrors Android's own CRYPTO-06 fix) — it
            // wasn't before, and encrypted_new_key decrypts using only the
            // recipient's own identity key (not anything group-specific), so
            // a signature over encrypted_new_key alone didn't stop a
            // malicious server from relabeling a real, validly-signed
            // rotation for group X as being for group Y (if the same admin
            // sends both and the recipient is in both groups) — the
            // recipient would then silently overwrite group Y's real key
            // with what was actually group X's.
            if (!CryptoManager.verify("$groupId:$encryptedNewKey", signature, senderKey)) {
                System.err.println("WebSocketClient: bad group_key_rotation signature from $from")
                return
            }
            if (!GroupManager.isAdmin(groupId, from)) {
                System.err.println("WebSocketClient: group_key_rotation from non-admin $from — rejected")
                return
            }
            val newGroupKey = GroupManager.decryptGroupKey(encryptedNewKey)
            val group = GroupManager.getGroup(groupId) ?: return
            GroupManager.saveGroup(group.copy(groupKey = newGroupKey))
            val sysMessage = GroupMessage(
                id = java.util.UUID.randomUUID().toString(), groupId = groupId,
                senderId = "system", senderName = "Система",
                text = "Групповой ключ обновлён", isOwn = false
            )
            GroupManager.saveGroupMessage(myFingerprint, sysMessage)
            onGroupMessageReceived?.invoke(groupId, sysMessage)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: group_key_rotation error — ${e.message}")
        }
    }

    private fun handleGroupInviteAccepted(json: JSONObject) {
        val groupId = json.getString("group_id")
        val newMember = json.getString("new_member")
        val newMemberName = json.getString("new_member_name")
        val signature = json.optString("signature", null)
        try {
            val memberKey = peerPublicKeys[newMember] ?: DesktopCryptoManager.getPeerPublicKey(newMember)
            if (signature == null || memberKey == null ||
                !CryptoManager.verify("$groupId:$newMember", signature, memberKey)) {
                System.err.println("WebSocketClient: bad group_invite_accepted signature from $newMember")
                return
            }
            // Was applied unconditionally on ANY receiving device — this
            // signature only proves the claimed new_member consented to
            // join, never that an admin actually invited them, and this
            // handler never even looked at the envelope's `from` (external
            // review 2026-09-08, S6-60). A poisoned `members` list then
            // feeds real fan-out (rotateGroupKey()/sendGroupMessage()
            // iterate group.members), so this wasn't just a cosmetic roster
            // entry. Mirrors Android's own mitigation exactly: only apply
            // the add if THIS device is itself the group's current admin —
            // processed on the inviting admin's own device once the new
            // member signs proof of acceptance, actor is this device's own
            // identity, not the new member being added. Ordinary members
            // learn about the join via the authenticated group_member_added
            // broadcast (handleGroupMemberAdded below), not this message.
            GroupManager.addMember(groupId, myFingerprint, newMember)
            val sysMessage = GroupMessage(
                id = java.util.UUID.randomUUID().toString(), groupId = groupId,
                senderId = "system", senderName = "Система",
                text = "$newMemberName присоединил(ся/ась) к группе", isOwn = false
            )
            GroupManager.saveGroupMessage(myFingerprint, sysMessage)
            onGroupMessageReceived?.invoke(groupId, sysMessage)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: group_invite_accepted error — ${e.message}")
        }
    }

    // Mirrors Android's "group_member_added" handler — the admin-signed
    // broadcast that tells EXISTING members about a member added to an
    // already-running group (symmetric counterpart to
    // handleGroupMemberRemoved). Previously missing on Desktop entirely
    // (external review 2026-09-08, S6-60): Desktop members' rosters never
    // updated for a member added after group creation, since
    // handleGroupInviteAccepted above is now correctly restricted to
    // admin-only application.
    private fun handleGroupMemberAdded(json: JSONObject) {
        val groupId = json.getString("group_id")
        val newMember = json.getString("new_member")
        val newMemberName = json.optString("new_member_name", newMember)
        val from = json.optString("from", null)
        val signature = json.optString("signature", null)
        try {
            val group = GroupManager.getGroup(groupId) ?: return
            if (from == null || !GroupManager.isAdmin(groupId, from)) {
                System.err.println("WebSocketClient: group_member_added from non-admin $from — rejected")
                return
            }
            val adminKey = peerPublicKeys[from] ?: DesktopCryptoManager.getPeerPublicKey(from)
            if (signature == null || adminKey == null ||
                !CryptoManager.verify("$groupId:add:$newMember", signature, adminKey)) {
                System.err.println("WebSocketClient: bad group_member_added signature from $from")
                return
            }
            GroupManager.addMember(groupId, from, newMember)

            // member_keys: learn the new member's own EC/PQ key — same
            // handling as group_create's member_keys array, just a single
            // entry here. See memberKeysPayload()'s own comment.
            val memberKeysArr = json.optJSONArray("member_keys")
            val memberKeysSig = json.optString("member_keys_signature", null)
            if (memberKeysArr != null && memberKeysSig != null) {
                try {
                    val entries = (0 until memberKeysArr.length()).map { memberKeysArr.getJSONObject(it) }
                    if (CryptoManager.verify(memberKeysPayload(groupId, entries), memberKeysSig, adminKey)) {
                        entries.forEach { entry ->
                            try {
                                val fp = entry.getString("fingerprint")
                                if (fp == myFingerprint) return@forEach
                                val pk = entry.getString("public_key")
                                val pqB64 = entry.getString("pq_public_key")
                                val name = entry.optString("name", "")

                                val pkBytes = Base64.getDecoder().decode(pk)
                                val actualFp = java.security.MessageDigest.getInstance("SHA-256")
                                    .digest(pkBytes).take(8).joinToString("") { "%02X".format(it) }
                                if (actualFp != fp) {
                                    System.err.println("WebSocketClient: member_keys: key for $fp doesn't match fingerprint (got $actualFp) — skipped")
                                    return@forEach
                                }

                                if (KeyHistoryManager.checkKeyChange(fp, pk)) {
                                    System.err.println("WebSocketClient: TOFU: $fp's key changed via group $groupId member_keys!")
                                    onKeyChanged?.invoke(fp)
                                }
                                val pqBytes = Base64.getDecoder().decode(pqB64)
                                ChatStorage.saveContactPublicKey(fp, pk)
                                ChatStorage.saveContactPqPublicKey(fp, pqBytes)
                                peerPublicKeys[fp] = pk
                                peerPqPublicKeys[fp] = pqBytes
                                if (name.isNotBlank() && ChatStorage.getContactName(fp) == fp.substringBefore("_")) {
                                    ChatStorage.saveContactName(fp, name)
                                }
                            } catch (e: Exception) {
                                System.err.println("WebSocketClient: member_keys entry error — ${e.message}")
                            }
                        }
                    } else {
                        System.err.println("WebSocketClient: group_member_added: bad member_keys signature from $from — key not learned")
                    }
                } catch (e: Exception) {
                    System.err.println("WebSocketClient: group_member_added: member_keys processing error — ${e.message}")
                }
            }

            val sysMessage = GroupMessage(
                id = java.util.UUID.randomUUID().toString(), groupId = groupId,
                senderId = "system", senderName = "Система",
                text = "$newMemberName присоединил(ся/ась) к группе", isOwn = false
            )
            GroupManager.saveGroupMessage(myFingerprint, sysMessage)
            onGroupMessageReceived?.invoke(groupId, sysMessage)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: group_member_added error — ${e.message}")
        }
    }

    // ── Channel handlers ───────────────────────────────────────────────────────

    private fun handleChannelCreated(json: JSONObject) {
        try {
            val channelId   = json.getString("channel_id")
            val channelName = json.getString("channel_name")
            val avatar      = json.optString("channel_avatar", "📢")
            val desc        = json.optString("channel_description", "")
            val channel = Channel(
                id = channelId, name = channelName, description = desc, avatar = avatar,
                adminId = myFingerprint, adminName = displayName, isAdmin = true
            )
            ChannelManager.saveChannel(channel)
            onChannelCreated?.invoke(channel)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: channel_created error — ${e.message}")
        }
    }

    private fun handleChannelUpdate(json: JSONObject) {
        try {
            val channelId = json.getString("channel_id")
            if (ChannelManager.getChannel(channelId) == null) return
            val postId    = json.getString("post_id")
            val text      = json.getString("text")
            val timestamp = json.getLong("timestamp")
            val authorId  = json.optString("author_id", "")
            val authorName = json.optString("author_name", "")
            val imageData = json.optString("image_data", "")

            val post = ChannelPost(
                id = postId, channelId = channelId, text = text, timestamp = timestamp,
                authorId = authorId, authorName = authorName, imageData = imageData
            )
            ChannelManager.addPost(post)
            onChannelPostReceived?.invoke(channelId, post)
        } catch (e: Exception) {
            System.err.println("WebSocketClient: channel_update error — ${e.message}")
        }
    }

    // ── Replay dedup ──────────────────────────────────────────────────────────

    private fun dedup(msgId: String): Boolean {
        if (msgId.isEmpty()) return true
        val now = System.currentTimeMillis()
        receivedIds.entries.removeIf { now - it.value > REPLAY_WINDOW_MS }
        if (receivedIds.containsKey(msgId)) return false
        receivedIds[msgId] = now
        return true
    }

    /** Peek-only duplicate check for "message"/processSessionInit — does
     *  NOT mark [msgId] processed. Unlike dedup() above (used by voice/
     *  reaction/etc., whose processing can't meaningfully fail-and-retry),
     *  these two handlers have expensive work (signature verify, decrypt,
     *  session establishment) that can genuinely fail for reasons unrelated
     *  to replay — marking an id processed before that work succeeds would
     *  make a failed-but-legitimate message permanently unretryable. Caller
     *  must call markProcessed() once processing actually succeeds. */
    private fun isDuplicateId(msgId: String): Boolean {
        if (msgId.isEmpty()) return false
        val now = System.currentTimeMillis()
        receivedIds.entries.removeIf { now - it.value > REPLAY_WINDOW_MS }
        return receivedIds.containsKey(msgId)
    }

    private fun markProcessed(msgId: String) {
        if (msgId.isEmpty()) return
        receivedIds[msgId] = System.currentTimeMillis()
    }
}

// ── Network / TLS configuration ───────────────────────────────────────────────
//
// Certificate pin — SHA-256 SPKI hash of api.Subrosa-app.org public key.
// Server uses Let's Encrypt with `certbot renew --reuse-key` so the SPKI hash
// stays stable across renewals.  Update here + ship a new release if the key
// is ever rotated.
//
// Re-derive pin:
//   openssl s_client -connect api.Subrosa-app.org:4430 </dev/null 2>/dev/null \
//     | openssl x509 -pubkey -noout \
//     | openssl pkey -pubin -outform der \
//     | openssl dgst -sha256 -binary | base64
object NetworkConfig {
    // Corrected 2026-09-03 (desktop/Android symmetry check, found live —
    // "нет соединения в целом"): this pointed at a domain that was never
    // the real deployed server at all — ServerManager.kt's
    // getDefaultServers() on Android has always been
    // "api.subrosamessenger.com", port 8443. Every desktop install was
    // hard-locked to an unreachable host with no way to notice why, until
    // the "Сменить сервер" UI added the same day made the repeated
    // connection failures actually visible.
    const val SERVER_HOSTNAME = "api.subrosamessenger.com"
    const val DEFAULT_WS_URL  = "wss://api.subrosamessenger.com:8443/ws"

    // Corrected again 2026-09-03: the previous pin came from Android's
    // CertificatePinner.kt — but that whole class is dead code, never
    // actually called from anywhere. The REAL, live pinning check is
    // MessengerService.kt's OkHttpClient builder, which reads THIS SAME
    // constant on Android (also named NetworkConfig.CERT_PIN there) — and
    // on Android it's "" (empty). Both here and there, `buildOkHttpClient`
    // only calls certificatePinner() when CERT_PIN is non-empty, so this
    // faithfully matches Android's actual current (pinning-disabled)
    // behavior instead of a stale value from unused code. Confirmed live:
    // the previous non-empty pin didn't match any cert in the real
    // server's actual chain (leaf/intermediate/root all checked), which
    // Android would have hit too if its real CERT_PIN weren't empty.
    const val CERT_PIN = ""

    const val STUN_URL = "stun:stun.l.google.com:19302"
    const val TURN_URL = "turn:turn.subrosamessenger.com:4433?transport=tcp"

    object TurnCredentials {
        var username: String? = null
        var password: String? = null
        fun isAvailable() = !username.isNullOrBlank() && !password.isNullOrBlank()
        fun clear() { username = null; password = null }
    }
}
