package com.subrosa.desktop

/**
 * Desktop port of Android's InviteCodeManager — binary format, matches
 * Android byte-for-byte so invites are interchangeable between platforms.
 *
 * Wire format ("bc:" + URL-safe unpadded Base64 of):
 *   [1]  version (0x03 = current, carries a mailbox tag; 0x02 = legacy, no tag)
 *   [4]  timestamp (seconds since epoch, big-endian)
 *   [8]  nonce
 *   [16] mailbox tag (only when version == 0x03)
 *   [8]  fingerprint (SHA-256(pubkey) first 8 bytes)
 *   [65] EC P-256 point (X9.62 uncompressed — the last 65 bytes of the X.509 key)
 *   [1]  name length
 *   [N]  name (UTF-8, max 255 bytes)
 *   [64] raw ECDSA signature (r||s, 32 bytes each) over everything above
 *
 * TTL: 7 days; future clock protection: ±5 min.
 */

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

data class InviteData(
    val publicKey:   String,        // Base64 URL-safe X.509 public key
    val fingerprint: String,        // 16-char hex (SHA-256 of pubkey bytes, first 8 bytes), uppercase
    val nonce:       String,        // hex-encoded nonce
    val signature:   String,        // Base64 URL-safe raw ECDSA signature (r||s)
    val displayName: String,
    val timestamp:   Long? = null,
    val mailboxTag:  String? = null // 32-char hex anonymous-mailbox tag (version 0x03 only)
)

object InviteCodeManager {

    private const val INVITE_TTL_SECONDS = 7L * 24 * 3600
    private const val FORMAT_VERSION: Byte = 0x03
    private const val PREFIX = "bc:"

    private val EC_P256_X509_HEADER: ByteArray =
        "3059301306072a8648ce3d020106082a8648ce3d030107034200"
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    private val b64Url: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val b64UrlDec: Base64.Decoder = Base64.getUrlDecoder()
    // Padded URL-safe encoder — used ONLY for the internal InviteData.
    // publicKey/signature representation, never for the wire payload
    // itself (that stays unpadded via b64Url above, matching Android's own
    // wire encode exactly). Canonicalized to match Android's parseInviteCode()
    // (which has always produced padded strings here — its encode call
    // never included NO_PADDING) rather than the other way around: Android's
    // one caller of InviteData.publicKey (ChatsScreen.kt) only swaps
    // URL-safe characters for standard ones and never re-pads, so it
    // depends on padding already being present; java.util.Base64's decoders
    // (used everywhere Desktop reads these fields) tolerate padded input
    // fine regardless. Found in the 2026-09-13 full-logic audit.
    private val b64UrlPadded: Base64.Encoder = Base64.getUrlEncoder()

    // ── Generate ──────────────────────────────────────────────────────────────

    private const val PREF_INVITE_LINK = "invite_link_cached"

    /** Reuses the persisted invite code if one exists and hasn't hit the 7-day
     *  TTL. Regenerating on every call used to mint a fresh mailbox tag each
     *  time, silently orphaning any exchange a contact had already started
     *  against the previous tag — the invite code (and its embedded tag)
     *  needs to stay stable once shared, not rotate on every screen visit.
     *  Explicit rotation (regenerateInviteLink(), below) is a separate,
     *  deliberate action wired to the "Copy"/"Share" actions specifically.
     *  Mirrors Android's ProfileScreen.kt resolveInviteCode()
     *  (desktop/Android symmetry audit, 2026-09-03). */
    fun generateInviteLink(): String {
        val cached = DesktopStorage.get(PREF_INVITE_LINK)
        val cachedData = cached?.let { parseInviteCode(it) }
        // Every one of these is required, not just "not expired" — found in
        // the 2026-09-13 full-logic audit: a cached invite surviving an
        // identity replacement (backup import, "Меня скомпрометировали"
        // reset, or a brand-new local account on this machine profile —
        // see BackupManager.wipeCurrentIdentityData(), now the single choke
        // point all three go through) still parsed and still looked
        // un-expired, so it got reused as-is — redistributing the OLD
        // identity's fingerprint/public key under the NEW identity, and
        // restoring the OLD anon-routing mailbox tag into the active
        // invite-tag state via the sync call below. verifyInviteCode()
        // covers parse+signature+expiry+future-clock in one call;
        // belongsToCurrentIdentity() — entirely missing before this fix —
        // is what actually ties the cache to the identity it was minted
        // for.
        val stillValid = cachedData != null &&
            verifyInviteCode(cachedData) &&
            belongsToCurrentIdentity(cachedData)

        val code = if (cached != null && stillValid) {
            cached
        } else {
            val fresh = generateInviteLinkFresh(AnonTokenManager.getOrCreateMyInviteMailboxTag())
            DesktopStorage.put(PREF_INVITE_LINK, fresh)
            fresh
        }
        // Sync unconditionally, even for a reused cached code — the
        // invite-code cache (PREF_INVITE_LINK) and AnonTokenManager's own
        // invite-tag pref can end up out of sync (e.g. a partial data reset,
        // or a code cached before this pref existed), and only syncing on
        // the "generate fresh" branch meant a reused code's tag could
        // silently never make it into the poll list at all.
        parseInviteCode(code)?.mailboxTag?.let { tag -> AnonTokenManager.syncMyInviteMailboxTag(tag) }
        return code
    }

    /** True only if [data]'s fingerprint AND public key both match the
     *  CURRENT DesktopCryptoManager identity — see generateInviteLink()'s
     *  own comment for why this exists. Two independent checks (SHA-256
     *  fingerprint AND the raw X.509 key bytes), not just one, matching
     *  this codebase's usual defense-in-depth style for identity-binding
     *  checks (see S6-46 elsewhere, e.g. SessionKeyManager.initiateSession()). */
    private fun belongsToCurrentIdentity(data: InviteData): Boolean {
        return try {
            val currentX509 = Base64.getDecoder().decode(DesktopCryptoManager.getPublicKeyBase64())
            if (data.fingerprint != computeFingerprint(currentX509)) return false
            b64UrlDec.decode(data.publicKey).contentEquals(currentX509)
        } catch (e: Exception) {
            false
        }
    }

    /** Discards the cached invite code — call on any identity replacement so
     *  a stale invite belonging to the OLD identity can never be considered
     *  for reuse under the NEW one (belongsToCurrentIdentity() above would
     *  now also catch this at the next generateInviteLink() call regardless,
     *  but this is an explicit, independent safeguard at the point identity
     *  actually changes, not a reliance on that runtime check alone). Does
     *  NOT touch AnonTokenManager's own invite-tag state — callers that also
     *  need that invalidated already clear it separately (see
     *  BackupManager.wipeCurrentIdentityData()'s AnonTokenManager.clearAll()
     *  call). Never call this for an ordinary reconnect/logout where the
     *  identity is NOT changing — the whole point of caching is to keep the
     *  same invite code stable across those. Found in the 2026-09-13
     *  full-logic audit. */
    fun clearCachedInvite() {
        DesktopStorage.remove(PREF_INVITE_LINK)
    }

    /** Explicit, user-triggered rotation — mints a fresh invite tag
     *  (immediately closing the exposure window on the previous one, see
     *  AnonTokenManager.regenerateMyInviteMailboxTag()) and a fresh code
     *  around it. Wired to the invite dialogs' "Copy"/"Share" actions —
     *  mirrors Android's ProfileScreen.kt regenerateInviteCode(). Only the
     *  invite tag changes; the persistent tag (and every already-established
     *  contact relying on it) is untouched. */
    fun regenerateInviteLink(): String {
        val freshTag = AnonTokenManager.regenerateMyInviteMailboxTag()
        val fresh = generateInviteLinkFresh(freshTag)
        DesktopStorage.put(PREF_INVITE_LINK, fresh)
        return fresh
    }

    /** The mailbox tag embedded in the currently active invite code. */
    fun myCurrentMailboxTag(): String = AnonTokenManager.getOrCreateMyInviteMailboxTag()

    private fun generateInviteLinkFresh(mailboxTagHex: String): String {
        val x509Bytes = Base64.getDecoder().decode(DesktopCryptoManager.getPublicKeyBase64())
        val ecPoint   = x509Bytes.copyOfRange(x509Bytes.size - 65, x509Bytes.size)
        val fpBytes   = MessageDigest.getInstance("SHA-256").digest(x509Bytes).copyOfRange(0, 8)

        val rng   = java.security.SecureRandom()
        val nonce = ByteArray(8).also { rng.nextBytes(it) }

        // Anonymous-mailbox tag: lets a peer deposit the first message + token
        // pool without the server ever seeing an A→B fingerprint pair.
        val mailboxTagBytes = mailboxTagHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        val ts = (System.currentTimeMillis() / 1000).toInt()
        val nameBytes = UserStorage.getUsername().toByteArray(Charsets.UTF_8).let {
            if (it.size > 255) it.copyOfRange(0, 255) else it
        }

        val preSign = ByteBuffer.allocate(1 + 4 + 8 + 16 + 8 + 65 + 1 + nameBytes.size).apply {
            put(FORMAT_VERSION)
            putInt(ts)
            put(nonce)
            put(mailboxTagBytes)
            put(fpBytes)
            put(ecPoint)
            put(nameBytes.size.toByte())
            put(nameBytes)
        }.array()

        val derSig = Base64.getDecoder().decode(DesktopCryptoManager.signBase64(preSign))
        val rawSig = derToRaw(derSig)

        val payload = preSign + rawSig
        return PREFIX + b64Url.encodeToString(payload)
    }

    // ── Parse ─────────────────────────────────────────────────────────────────

    // Fixed-size fields only (version+ts+nonce+tag+fp+ecPoint+nameLenByte+sig),
    // with a zero-length name — the smallest a structurally valid payload
    // could ever be. Checked before any ByteBuffer reads/allocations, not
    // just relied upon via BufferUnderflowException from a short get() call
    // — mirrors Android's parseInviteCode() exactly. Found in the
    // 2026-09-13 full-logic audit.
    private const val MIN_PAYLOAD_SIZE = 1 + 4 + 8 + 16 + 8 + 65 + 1 + 64

    fun parseInviteCode(input: String): InviteData? {
        val code = input.trim()
        if (!code.startsWith(PREFIX)) return null

        return try {
            val payload = b64UrlDec.decode(code.removePrefix(PREFIX))
            if (payload.size < MIN_PAYLOAD_SIZE) return null
            val buf = ByteBuffer.wrap(payload)

            val version = buf.get()
            // Pre-mailbox-tag (0x02) codes are rejected outright rather than
            // falling back to a direct, server-visible get_key lookup — that
            // fallback silently dropped the anonymity guarantee with no
            // warning to the user. See SCENARIOS.md, "First contact" step 3b.
            if (version != FORMAT_VERSION) return null

            val ts    = buf.int.toLong() and 0xFFFFFFFFL
            val nonce = ByteArray(8).also { buf.get(it) }

            val tagBytes = ByteArray(16).also { buf.get(it) }
            val mailboxTagHex = tagBytes.joinToString("") { "%02x".format(it) }

            val fpBytes   = ByteArray(8).also { buf.get(it) }
            val ecPoint   = ByteArray(65).also { buf.get(it) }
            val nameLen   = buf.get().toInt() and 0xFF
            val nameBytes = ByteArray(nameLen).also { buf.get(it) }
            val rawSig    = ByteArray(64).also { buf.get(it) }

            // Reject non-canonical payloads — trailing bytes beyond the last
            // declared field (the signature) would otherwise be silently
            // ignored: they aren't covered by the signature either way (it's
            // computed over exactly the fields above), so a payload with
            // junk appended still parsed and verified successfully before
            // this check. Mirrors Android's parseInviteCode() exactly. Found
            // in the 2026-09-13 full-logic audit.
            if (buf.remaining() != 0) return null

            val x509Bytes    = EC_P256_X509_HEADER + ecPoint
            val publicKeyB64 = b64UrlPadded.encodeToString(x509Bytes)

            val fingerprintHex = fpBytes.joinToString("") { "%02X".format(it) }
            val nonceHex       = nonce.joinToString("") { "%02X".format(it) }
            val sigB64         = b64UrlPadded.encodeToString(rawSig)
            val displayName    = String(nameBytes, Charsets.UTF_8)

            InviteData(publicKeyB64, fingerprintHex, nonceHex, sigB64, displayName, ts, mailboxTagHex)
        } catch (e: Exception) {
            System.err.println("InviteCodeManager: parse failed — ${e.message}")
            null
        }
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    fun verifyInviteCode(data: InviteData): Boolean {
        return try {
            val timestamp = data.timestamp ?: return false

            val x509Bytes = b64UrlDec.decode(data.publicKey)
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(x509Bytes))

            val expectedFp = MessageDigest.getInstance("SHA-256").digest(x509Bytes)
                .take(8).joinToString("") { "%02X".format(it) }
            if (expectedFp != data.fingerprint) {
                System.err.println("InviteCodeManager: fingerprint mismatch")
                return false
            }

            val now = System.currentTimeMillis() / 1000L
            if (now - timestamp > INVITE_TTL_SECONDS) {
                System.err.println("InviteCodeManager: code expired")
                return false
            }
            if (timestamp > now + 300) {
                System.err.println("InviteCodeManager: code from future")
                return false
            }

            val fpBytes    = data.fingerprint.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val nonceBytes = data.nonce.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val nameBytes  = data.displayName.toByteArray(Charsets.UTF_8)
            val ecPoint    = x509Bytes.copyOfRange(x509Bytes.size - 65, x509Bytes.size)

            // parseInviteCode() only ever produces FORMAT_VERSION InviteData
            // (pre-mailbox-tag codes are rejected at parse time), so the tag
            // is always present here.
            val mailboxTagBytes = data.mailboxTag?.chunked(2)?.map { it.toInt(16).toByte() }?.toByteArray()
                ?: return false
            val preSign = ByteBuffer.allocate(
                1 + 4 + 8 + mailboxTagBytes.size + 8 + 65 + 1 + nameBytes.size
            ).apply {
                put(FORMAT_VERSION)
                putInt(timestamp.toInt())
                put(nonceBytes)
                put(mailboxTagBytes)
                put(fpBytes)
                put(ecPoint)
                put(nameBytes.size.toByte())
                put(nameBytes)
            }.array()

            val rawSig = b64UrlDec.decode(data.signature)
            val derSig = rawToDer(rawSig)

            Signature.getInstance("SHA256withECDSA").also {
                it.initVerify(publicKey)
                it.update(preSign)
            }.verify(derSig)
        } catch (e: Exception) {
            System.err.println("InviteCodeManager: verify failed — ${e.message}")
            false
        }
    }

    /**
     * Parse and verify, then save contact to ChatStorage.
     * Returns the display name on success, null on failure.
     */
    fun acceptInvite(raw: String): String? {
        val data = parseInviteCode(raw) ?: return null
        if (!verifyInviteCode(data)) return null

        // Convert URL-safe Base64 back to standard for storage
        val standardKey = data.publicKey
            .replace('-', '+')
            .replace('_', '/')
            .let {
                val pad = (4 - it.length % 4) % 4
                it + "=".repeat(pad)
            }

        // Falls back to the fingerprint when the invite carried a blank name
        // — mirrors Android's ChatsScreen.kt redeem flow (`ifBlank { fingerprint
        // }`), missing here before this fix: a blank display name would have
        // shown as an empty, unlabeled row in the chat list. Found in the
        // 2026-09-12 full-logic audit continuation.
        val decodedName = data.displayName.ifBlank { data.fingerprint }

        ChatStorage.addContact(data.fingerprint)
        ChatStorage.saveContactPublicKey(data.fingerprint, standardKey)
        ChatStorage.saveContactName(data.fingerprint, decodedName)
        // Pre-load encryption key — the invite code itself already carries the
        // full public key, verified by its signature; no need to also ask the
        // server for it (that would be a direct, server-visible get_key
        // request naming this fingerprint, undermining the anonymous
        // mailbox-tag bootstrap below).
        DesktopCryptoManager.storePeerPublicKey(data.fingerprint, standardKey)

        // parseInviteCode()/verifyInviteCode() only ever accept FORMAT_VERSION
        // codes now — the mailbox tag is always present here.
        data.mailboxTag?.let {
            AnonTokenManager.setContactMailboxTag(data.fingerprint, it)
            // Kick off the anonymous token exchange immediately, invisibly —
            // don't wait for the user to type a first message to trigger it.
            WebSocketClient.bootstrapChannelFor(data.fingerprint)
        }

        return decodedName
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fun computeFingerprint(pubKeyBytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(pubKeyBytes)
            .take(8).joinToString("") { "%02x".format(it) }.uppercase()

    // ── DER ⇄ raw ECDSA signature conversion (P-256, so r/s are 32 bytes each) ──

    private fun derToRaw(der: ByteArray): ByteArray {
        var pos = 2
        pos++
        val rLen = der[pos++].toInt() and 0xFF
        val r = der.copyOfRange(pos, pos + rLen); pos += rLen
        pos++
        val sLen = der[pos++].toInt() and 0xFF
        val s = der.copyOfRange(pos, pos + sLen)
        return padOrTrim32(r) + padOrTrim32(s)
    }

    private fun rawToDer(raw: ByteArray): ByteArray {
        val r = derEncodeInt(raw.copyOfRange(0, 32))
        val s = derEncodeInt(raw.copyOfRange(32, 64))
        val body = byteArrayOf(0x02.toByte(), r.size.toByte()) + r +
                   byteArrayOf(0x02.toByte(), s.size.toByte()) + s
        return byteArrayOf(0x30.toByte(), body.size.toByte()) + body
    }

    private fun padOrTrim32(b: ByteArray): ByteArray {
        val stripped = b.dropWhile { it == 0.toByte() }.toByteArray()
            .let { if (it.isEmpty()) byteArrayOf(0) else it }
        return when {
            stripped.size > 32 -> stripped.copyOfRange(stripped.size - 32, stripped.size)
            stripped.size < 32 -> ByteArray(32 - stripped.size) + stripped
            else -> stripped
        }
    }

    private fun derEncodeInt(b: ByteArray): ByteArray {
        val stripped = b.dropWhile { it == 0.toByte() }.toByteArray()
            .let { if (it.isEmpty()) byteArrayOf(0) else it }
        return if (stripped[0].toInt() and 0x80 != 0) byteArrayOf(0.toByte()) + stripped else stripped
    }
}
