package com.subrosa.desktop

import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.GCMParameterSpec
import java.util.Base64
import org.json.JSONObject
import org.json.JSONArray

object SessionKeyManager {

    private const val TAG = "SessionKeyManager"
    private const val PREFS_NAME = "session_keys"
    private const val SPK_ROTATION_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000L

    private const val RATCHET_ROTATION_THRESHOLD = 50
    private const val RATCHET_ROTATION_TIME_MS = 12 * 60 * 60 * 1000L
    private const val MAX_SKIPPED_KEYS = 100
    private const val SKIPPED_KEY_TTL_MS = 7 * 24 * 60 * 60 * 1000L
    private const val SPK_GRACE_PERIOD_MS = 14 * 24 * 60 * 60 * 1000L
    // How many past DH-ratchet epoch keys (recvRatchetPub values already
    // stepped past) to remember, so a redelivered message from an old epoch
    // is recognized as stale instead of triggering a rollback DH step — see
    // nextRecvKey(). Mirrors Android's SessionKeyManager.kt, 2026-09-03.
    private const val MAX_PREVIOUS_RATCHET_EPOCHS = 5

    data class PrekeyBundle(
        val identityKey: String,
        val signedPrekey: String,
        val spkSignature: String,
        val spkId: Int,
        val oneTimePrekeys: List<String>,
        val pqKemPublicKey: String,
        val pqKemSignature: String,
        // Attached by the SERVER at fetch time (not published by the owning
        // client, so it can never go stale between bundle publishes) — one
        // of the bundle owner's currently-registered anon tokens, letting
        // the resulting session_init be delivered anonymously instead of
        // directly addressed. Null if the owner is offline or has none
        // registered; always null on a bundle you're publishing yourself.
        val bootstrapToken: String? = null
    )

    data class SessionState(
        val contactId: String,
        val sendChainKey: ByteArray,
        val recvChainKey: ByteArray,
        val sendCounter: Int,
        val recvCounter: Int,
        val sessionId: String,
        val createdAt: Long,
        val lastRatchetAt: Long,
        val rootKey: ByteArray = ByteArray(0),
        val sendRatchetPriv: ByteArray = ByteArray(0),
        val sendRatchetPub: ByteArray = ByteArray(0),
        val recvRatchetPub: ByteArray? = null,
        val skippedKeys: Map<String, ByteArray> = emptyMap(),
        val skippedKeyTimestamps: Map<String, Long> = emptyMap(),
        // Base64 recvRatchetPub values from epochs already stepped past
        // (most recent last), bounded by MAX_PREVIOUS_RATCHET_EPOCHS. Public
        // keys, not secret — no SecureMemory.wipe needed.
        val previousRecvRatchetPubs: List<String> = emptyList()
    )

    data class SendKeyResult(
        val messageKey: ByteArray,
        val counter: Int,
        val sessionId: String,
        val dhRatchetPubB64: String?
    )

    private val sessions = java.util.concurrent.ConcurrentHashMap<String, SessionState>()
    private val secureRandom = SecureRandom()
    private var currentSpk: KeyPair? = null
    private var currentSpkId: Int = 0
    private var spkCreatedAt: Long = 0L
    private var previousSpk: KeyPair? = null
    private var previousSpkId: Int = -1
    private var previousSpkCreatedAt: Long = 0L
    private var currentPqKem: PqCrypto.PqKeyPair? = null
    private var previousPqKem: PqCrypto.PqKeyPair? = null
    private val opkPool = java.util.concurrent.ConcurrentHashMap<Int, KeyPair>()
    private val opkIdCounter = java.util.concurrent.atomic.AtomicInteger(0)

    fun init() {
        generateOrRotateSpk()
        loadOpkPool()
        refillOpkPool(targetCount = 10)
        loadAllSessions()
        println("$TAG: SessionKeyManager initialized. SPK id=$currentSpkId, OPK pool=${opkPool.size}, sessions=${sessions.size}")
    }

    /** True only when spk_private_key_$id is SMK-wrapped and fails to decrypt
     *  under the CURRENT SMK with an AEAD tag mismatch specifically — i.e.
     *  it was wrapped under a PREVIOUS, now-orphaned SMK. StorageKeyManager.setup()
     *  mints a brand-new random SMK on every register() (same root cause
     *  DeviceKeyManager.getOrCreateKeyPair() already handles for device_priv
     *  via the identical AEADBadTagException check). Distinct from merely
     *  "locked" (isUnlocked == false, or a plain IllegalStateException from
     *  readSmk()), which is NOT stale and must keep waiting for unlock rather
     *  than discard a possibly-still-valid key.
     *  Found live, 2026-09-18: without this check, the "no rotation needed"
     *  branch below left currentSpk permanently null in this exact scenario —
     *  every getLocalPrekeyBundle()/generatePrekeyBundle() call threw "SPK не
     *  инициализирован" forever, silently swallowed by WebSocketClient's
     *  publishPrekeyBundle(), so this device's prekey bundle was never
     *  published and peers' get_prekey_bundle for it returned null
     *  indefinitely — the fingerprint 066D37A24897CAA9 case. */
    private fun isWrappedUnderStaleSmk(id: Int): Boolean {
        val privB64 = DesktopStorage.get("spk_private_key_$id") ?: return false
        if (!privB64.startsWith(StorageKeyManager.SMK_PREFIX) || !StorageKeyManager.isUnlocked) return false
        return try {
            StorageKeyManager.unwrapBytes(privB64)
            false
        } catch (e: javax.crypto.AEADBadTagException) {
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun generateOrRotateSpk() {
        val savedSpkId = DesktopStorage.getInt("spk_id", -1)
        val savedCreatedAt = DesktopStorage.get("spk_created_at")?.toLongOrNull() ?: 0L
        val now = System.currentTimeMillis()

        val decoder = Base64.getDecoder()
        val encoder = Base64.getEncoder()

        val needsRotation = savedSpkId == -1 || (now - savedCreatedAt) > SPK_ROTATION_INTERVAL_MS ||
            (savedSpkId >= 0 && isWrappedUnderStaleSmk(savedSpkId))

        if (needsRotation) {
            if (savedSpkId >= 0) {
                val oldPrivB64 = DesktopStorage.get("spk_private_key_$savedSpkId")
                val oldPubB64 = DesktopStorage.get("spk_public_$savedSpkId")
                if (oldPrivB64 != null && oldPubB64 != null) {
                    try {
                        val kf = KeyFactory.getInstance("EC")
                        previousSpk = KeyPair(
                            kf.generatePublic(X509EncodedKeySpec(decoder.decode(oldPubB64))),
                            kf.generatePrivate(PKCS8EncodedKeySpec(StorageKeyManager.unwrapBytes(oldPrivB64)))
                        )
                        previousSpkId = savedSpkId
                        previousSpkCreatedAt = savedCreatedAt
                        DesktopStorage.putInt("prev_spk_id", savedSpkId)
                        DesktopStorage.put("prev_spk_created_at", savedCreatedAt.toString())
                        DesktopStorage.put("prev_spk_public", oldPubB64)
                        DesktopStorage.put("prev_spk_private_key", oldPrivB64)
                        println("$TAG: Old SPK saved as previous: id=$savedSpkId")

                        // Carry the matching PQ KEM keypair into the grace period too,
                        // so a handshake still in flight against the old SPK can complete.
                        val oldPqPrivB64 = DesktopStorage.get("pq_kem_private_key_$savedSpkId")
                        val oldPqPubB64  = DesktopStorage.get("pq_kem_public_$savedSpkId")
                        if (oldPqPrivB64 != null && oldPqPubB64 != null) {
                            previousPqKem = PqCrypto.PqKeyPair(decoder.decode(oldPqPubB64), StorageKeyManager.unwrapBytes(oldPqPrivB64))
                            DesktopStorage.put("prev_pq_kem_public", oldPqPubB64)
                            DesktopStorage.put("prev_pq_kem_private_key", oldPqPrivB64)
                        }
                    } catch (e: Exception) {
                        println("$TAG: Failed to save previous SPK: ${e.message}")
                    }
                }
            }
            currentSpk = generateEcKeyPair()
            currentSpkId = (savedSpkId + 1).coerceAtLeast(0)
            spkCreatedAt = now
            DesktopStorage.put("spk_private_key_$currentSpkId", wrapKeyBytes(currentSpk!!.private.encoded))
            DesktopStorage.putInt("spk_id", currentSpkId)
            DesktopStorage.put("spk_created_at", now.toString())
            DesktopStorage.put("spk_public_$currentSpkId", encoder.encodeToString(currentSpk!!.public.encoded))

            val newPqKem = PqCrypto.generateKeyPair()
            currentPqKem = newPqKem
            DesktopStorage.put("pq_kem_private_key_$currentSpkId", wrapKeyBytes(newPqKem.privateKey))
            DesktopStorage.put("pq_kem_public_$currentSpkId", encoder.encodeToString(newPqKem.publicKey))
            println("$TAG: SPK rotated: id=$currentSpkId")
        } else {
            val privateKeyB64 = DesktopStorage.get("spk_private_key_$savedSpkId")
            val publicKeyB64 = DesktopStorage.get("spk_public_$savedSpkId")
            if (privateKeyB64 != null && publicKeyB64 != null) {
                val privateBytes = tryUnwrapKeyBytes(privateKeyB64)
                if (privateBytes != null) {
                    val keyFactory = KeyFactory.getInstance("EC")
                    val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateBytes))
                    val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(decoder.decode(publicKeyB64)))
                    currentSpk = KeyPair(publicKey, privateKey)
                    if (!privateKeyB64.startsWith(StorageKeyManager.SMK_PREFIX) && StorageKeyManager.isUnlocked) {
                        DesktopStorage.put("spk_private_key_$savedSpkId", wrapKeyBytes(privateKey.encoded))
                    }
                } else {
                    println("$TAG: SPK id=$savedSpkId temporarily unavailable (SMK locked) — waiting for unlock")
                }
            } else {
                currentSpk = generateEcKeyPair()
                DesktopStorage.put("spk_private_key_$savedSpkId", wrapKeyBytes(currentSpk!!.private.encoded))
                DesktopStorage.put("spk_public_$savedSpkId", encoder.encodeToString(currentSpk!!.public.encoded))
            }
            currentSpkId = savedSpkId
            spkCreatedAt = savedCreatedAt
            println("$TAG: SPK restored: id=$currentSpkId")

            // Restore (or, for an install upgrading from pre-PQ, generate) the
            // PQ KEM keypair tied to the current SPK id.
            val pqPrivB64 = DesktopStorage.get("pq_kem_private_key_$currentSpkId")
            val pqPubB64  = DesktopStorage.get("pq_kem_public_$currentSpkId")
            if (pqPrivB64 != null && pqPubB64 != null) {
                val pqPrivBytes = tryUnwrapKeyBytes(pqPrivB64)
                if (pqPrivBytes != null) {
                    currentPqKem = PqCrypto.PqKeyPair(decoder.decode(pqPubB64), pqPrivBytes)
                    if (!pqPrivB64.startsWith(StorageKeyManager.SMK_PREFIX) && StorageKeyManager.isUnlocked) {
                        DesktopStorage.put("pq_kem_private_key_$currentSpkId", wrapKeyBytes(pqPrivBytes))
                    }
                } else {
                    println("$TAG: PQ KEM id=$currentSpkId temporarily unavailable (SMK locked) — waiting for unlock")
                }
            } else {
                val migratedPqKem = PqCrypto.generateKeyPair()
                currentPqKem = migratedPqKem
                DesktopStorage.put("pq_kem_private_key_$currentSpkId", wrapKeyBytes(migratedPqKem.privateKey))
                DesktopStorage.put("pq_kem_public_$currentSpkId", encoder.encodeToString(migratedPqKem.publicKey))
                println("$TAG: PQ KEM key generated during migration for existing SPK id=$currentSpkId")
            }

            val prevSpkId = DesktopStorage.getInt("prev_spk_id", -1)
            val prevCreatedAt = DesktopStorage.get("prev_spk_created_at")?.toLongOrNull() ?: 0L
            if (prevSpkId >= 0 && (now - prevCreatedAt) < SPK_GRACE_PERIOD_MS) {
                val prevPrivB64 = DesktopStorage.get("prev_spk_private_key")
                val prevPubB64 = DesktopStorage.get("prev_spk_public")
                if (prevPrivB64 != null && prevPubB64 != null) {
                    try {
                        val kf = KeyFactory.getInstance("EC")
                        previousSpk = KeyPair(
                            kf.generatePublic(X509EncodedKeySpec(decoder.decode(prevPubB64))),
                            kf.generatePrivate(PKCS8EncodedKeySpec(StorageKeyManager.unwrapBytes(prevPrivB64)))
                        )
                        previousSpkId = prevSpkId
                        previousSpkCreatedAt = prevCreatedAt
                        println("$TAG: Previous SPK restored: id=$prevSpkId")

                        val prevPqPrivB64 = DesktopStorage.get("prev_pq_kem_private_key")
                        val prevPqPubB64  = DesktopStorage.get("prev_pq_kem_public")
                        if (prevPqPrivB64 != null && prevPqPubB64 != null) {
                            previousPqKem = PqCrypto.PqKeyPair(decoder.decode(prevPqPubB64), StorageKeyManager.unwrapBytes(prevPqPrivB64))
                        }
                    } catch (e: Exception) {
                        println("$TAG: Failed to restore previous SPK: ${e.message}")
                    }
                }
            }
        }
    }

    private fun loadOpkPool() {
        opkIdCounter.set(DesktopStorage.getInt("opk_counter", 0))
        val idsStr = DesktopStorage.get("opk_ids") ?: ""
        if (idsStr.isBlank()) return
        val ids = idsStr.split(",").mapNotNull { it.trim().toIntOrNull() }
        val keyFactory = KeyFactory.getInstance("EC")
        val decoder = Base64.getDecoder()
        for (id in ids) {
            val privateB64 = DesktopStorage.get("opk_private_$id") ?: continue
            val publicB64 = DesktopStorage.get("opk_public_$id") ?: continue
            try {
                val privateBytes = StorageKeyManager.unwrapBytes(privateB64)
                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateBytes))
                val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(decoder.decode(publicB64)))
                opkPool[id] = KeyPair(publicKey, privateKey)
                if (!privateB64.startsWith(StorageKeyManager.SMK_PREFIX) && StorageKeyManager.isUnlocked) {
                    DesktopStorage.put("opk_private_$id", wrapKeyBytes(privateBytes))
                }
            } catch (e: Exception) {
                println("$TAG: Failed to restore OPK $id: ${e.message}")
            }
        }
        println("$TAG: OPK pool restored: ${opkPool.size} keys")
    }

    private fun refillOpkPool(targetCount: Int) {
        val needed = targetCount - opkPool.size
        if (needed <= 0) return
        val encoder = Base64.getEncoder()
        repeat(needed) {
            val id = opkIdCounter.getAndIncrement()
            val kp = generateEcKeyPair()
            opkPool[id] = kp
            DesktopStorage.put("opk_private_$id", wrapKeyBytes(kp.private.encoded))
            DesktopStorage.put("opk_public_$id", encoder.encodeToString(kp.public.encoded))
        }
        DesktopStorage.put("opk_ids", opkPool.keys.joinToString(","))
        DesktopStorage.putInt("opk_counter", opkIdCounter.get())
        println("$TAG: OPK pool refilled: +$needed, total=${opkPool.size}")
    }

    fun consumeOpk(opkId: Int): KeyPair? {
        val kp = opkPool.remove(opkId) ?: return null
        println("$TAG: OPK $opkId used. Remaining: ${opkPool.size}")
        DesktopStorage.remove("opk_private_$opkId")
        DesktopStorage.remove("opk_public_$opkId")
        DesktopStorage.put("opk_ids", opkPool.keys.joinToString(","))
        return kp
    }

    // Backup export/import for the current SPK+PQ prekey — ported from
    // Android's SessionKeyManager.kt (found live 2026-09-02: without this, a
    // post-restore install always mints a brand new SPK/PQ-KEM with no grace
    // period, since the old one was physically deleted by wipeCurrentIdentityData()
    // and the backup never carried a replacement — every restore became an
    // unplanned, ungraced key rotation that broke incoming decryption for
    // contacts with an already-cached bundle). See docs/SECURITY_INVARIANTS.md
    // #15 and PROTOCOL_STATE_MACHINE.md §7.
    data class PrekeySnapshot(
        val spkId: Int,
        val spkCreatedAt: Long,
        val spkPublic: ByteArray,
        val spkPrivate: ByteArray,
        val pqPublic: ByteArray,
        val pqPrivate: ByteArray
    )

    fun exportCurrentPrekeyForBackup(): PrekeySnapshot? {
        val spk = currentSpk ?: return null
        val pq = currentPqKem ?: return null
        return PrekeySnapshot(
            spkId = currentSpkId,
            spkCreatedAt = spkCreatedAt,
            spkPublic = spk.public.encoded,
            spkPrivate = spk.private.encoded,
            pqPublic = pq.publicKey,
            pqPrivate = pq.privateKey
        )
    }

    /** Restores a prekey snapshot into storage AND in-memory state — writes
     *  under the snapshot's own spkId, so generateOrRotateSpk() on next
     *  init() sees an existing id and treats this like an ordinary reconnect
     *  (or, if SPK_ROTATION_INTERVAL_MS has already elapsed since the real
     *  spkCreatedAt, an ordinary *scheduled* rotation, correctly graced)
     *  instead of a fresh, ungraced mint. Must be called before init() runs
     *  for a fresh restore, but also safe to call on an already-initialized
     *  process (BackupManager's "already logged in" import path) since it
     *  updates the in-memory current* fields directly too. */
    fun restorePrekeyFromBackup(snapshot: PrekeySnapshot) {
        val encoder = Base64.getEncoder()
        DesktopStorage.putInt("spk_id", snapshot.spkId)
        DesktopStorage.put("spk_created_at", snapshot.spkCreatedAt.toString())
        DesktopStorage.put("spk_public_${snapshot.spkId}", encoder.encodeToString(snapshot.spkPublic))
        DesktopStorage.put("pq_kem_public_${snapshot.spkId}", encoder.encodeToString(snapshot.pqPublic))
        DesktopStorage.put("spk_private_key_${snapshot.spkId}", wrapKeyBytes(snapshot.spkPrivate))
        DesktopStorage.put("pq_kem_private_key_${snapshot.spkId}", wrapKeyBytes(snapshot.pqPrivate))

        currentSpkId = snapshot.spkId
        spkCreatedAt = snapshot.spkCreatedAt
        try {
            val kf = KeyFactory.getInstance("EC")
            currentSpk = KeyPair(
                kf.generatePublic(X509EncodedKeySpec(snapshot.spkPublic)),
                kf.generatePrivate(PKCS8EncodedKeySpec(snapshot.spkPrivate))
            )
        } catch (e: Exception) {
            println("$TAG: restorePrekeyFromBackup: failed to restore SPK in memory: ${e.message}")
        }
        currentPqKem = PqCrypto.PqKeyPair(snapshot.pqPublic, snapshot.pqPrivate)
        println("$TAG: Prekey restored from backup: spkId=${snapshot.spkId}")
    }

    /** Only the OPK issuance counter is worth carrying across a backup, not
     *  the actual OPK keypairs — OPKs are one-time by protocol design
     *  (consumeOpk()), so restoring frozen key material risks reissuing an
     *  id already consumed for real between export and a later restore of
     *  the same file. The pool itself is left for the ordinary
     *  refillOpkPool() top-up to repopulate with brand-new keys. */
    fun exportOpkCounterForBackup(): Int = opkIdCounter.get()

    fun restoreOpkCounterFromBackup(counter: Int) {
        if (counter <= 0) return
        // max(), not overwrite — never move the counter backward, in case
        // this device's own post-wipe pool is already ahead of the backup's.
        opkIdCounter.set(maxOf(opkIdCounter.get(), counter))
        DesktopStorage.putInt("opk_counter", opkIdCounter.get())
        println("$TAG: OPK counter raised from backup: ${opkIdCounter.get()}")
    }

    fun getLocalPrekeyBundle(): PrekeyBundle {
        val spk = currentSpk ?: throw IllegalStateException("SPK not initialized")
        val spkPublicB64 = Base64.getEncoder().encodeToString(spk.public.encoded)
        val spkSignature = CryptoManager.sign(spkPublicB64)
        val opkPublics = opkPool.entries.take(5).map { (id, kp) ->
            "$id:${Base64.getEncoder().encodeToString(kp.public.encoded)}"
        }
        val pqKem = currentPqKem ?: throw IllegalStateException("PQ KEM key not initialized")
        val pqPublicB64 = Base64.getEncoder().encodeToString(pqKem.publicKey)
        val pqSignature = CryptoManager.sign(pqPublicB64)
        return PrekeyBundle(
            identityKey = CryptoManager.getPublicKeyString(),
            signedPrekey = spkPublicB64,
            spkSignature = spkSignature,
            spkId = currentSpkId,
            oneTimePrekeys = opkPublics,
            pqKemPublicKey = pqPublicB64,
            pqKemSignature = pqSignature
        )
    }

    fun prekeyBundleToJson(bundle: PrekeyBundle): JSONObject = JSONObject().apply {
        put("identity_key", bundle.identityKey)
        put("signed_prekey", bundle.signedPrekey)
        put("spk_signature", bundle.spkSignature)
        put("spk_id", bundle.spkId)
        put("opks", org.json.JSONArray(bundle.oneTimePrekeys))
        put("pq_kem_public_key", bundle.pqKemPublicKey)
        put("pq_kem_signature", bundle.pqKemSignature)
        // Never set when publishing our own bundle — only the server adds
        // this, at fetch time, to a bundle it hands to someone else.
        bundle.bootstrapToken?.let { put("bootstrap_token", it) }
    }

    fun parsePrekeyBundle(json: JSONObject): PrekeyBundle {
        val opksArray = json.getJSONArray("opks")
        val opks = (0 until opksArray.length()).map { opksArray.getString(it) }
        return PrekeyBundle(
            identityKey = json.getString("identity_key"),
            signedPrekey = json.getString("signed_prekey"),
            spkSignature = json.getString("spk_signature"),
            spkId = json.getInt("spk_id"),
            oneTimePrekeys = opks,
            // Required, not optional: a bundle missing the PQ component is
            // rejected rather than silently downgraded (prevents a
            // strip-the-PQ-field downgrade attack by a malicious server).
            pqKemPublicKey = json.getString("pq_kem_public_key"),
            pqKemSignature = json.getString("pq_kem_signature"),
            // Genuinely optional — omission is an expected fallback (owner
            // offline / no tokens registered), not a downgrade attack: there
            // is nothing cryptographic to downgrade here, only a metadata
            // convenience that gracefully degrades to direct addressing.
            bootstrapToken = json.optString("bootstrap_token", null)
        )
    }

    fun generatePrekeyBundle(): JSONObject {
        val bundle = getLocalPrekeyBundle()
        return prekeyBundleToJson(bundle)
    }

    /**
     * One-time migration for the PQ-hybrid upgrade: sessions established
     * before this upgrade have a purely-classical root key that can't be
     * retroactively hardened. Called once after a successful connection —
     * deletes all local session state (forcing a fresh PQ-hybrid X3DH
     * handshake on the next message either direction) and returns the
     * affected contact ids so the caller can also send them "session_reset"
     * to clear their side and avoid a one-sided desync. Returns null if the
     * migration already ran (idempotent, persisted flag).
     */
    fun consumePendingPqMigrationContacts(): List<String>? {
        if (DesktopStorage.getBoolean("pq_migration_v1_done", false)) return null
        val contactIds = sessions.keys.toList()
        contactIds.forEach { deleteSession(it) }
        DesktopStorage.putBoolean("pq_migration_v1_done", true)
        if (contactIds.isNotEmpty()) {
            println("$TAG: PQ migration — reset ${contactIds.size} pre-upgrade session(s)")
        }
        return contactIds
    }

    /** Current PQ KEM private key — used by CryptoManager's hybrid legacy-ECDH decrypt(). */
    fun getCurrentPqPrivateKey(): ByteArray? = currentPqKem?.privateKey

    /** Previous PQ KEM private key, only while still within the SPK grace period. */
    fun getPreviousPqPrivateKeyIfValid(): ByteArray? {
        if (previousPqKem == null) return null
        if (System.currentTimeMillis() - previousSpkCreatedAt > SPK_GRACE_PERIOD_MS) return null
        return previousPqKem?.privateKey
    }

    // synchronized(this) — mirrors Android's SessionKeyManager.initiateSession()
    // exactly (external review 2026-08-23 there): every function that does
    // `sessions[contactId] = state` (nextSendKey, nextRecvKey, deleteSession,
    // deleteAllSessions, loadAllSessions) must serialize on the SAME monitor
    // as this one and receiveSession() below — these are compound
    // read-modify-write state transitions on SessionState (read old state,
    // derive a new one, write it back), not single atomic map operations, so
    // ConcurrentHashMap alone does not make them safe. Two concurrent
    // handshakes for the same contact (a genuine simultaneous mutual-X3DH
    // race, or a duplicated/replayed session_init) could otherwise each
    // compute an independent SessionState and both write it, last writer
    // wins with no coordination. Was entirely unsynchronized on Desktop
    // before this fix — found in the 2026-09-13 full-logic audit.
    // identityOverride: test-only, mirrors Android's SessionKeyManager.
    // initiateSession() param of the same name — uses this key pair's
    // private key for dh1 instead of this device's real identity
    // (CryptoManager.getPrivateKeyPublic()). Every real call site omits
    // it (defaults to null → zero behavior change). Exists solely so
    // SecurityDiagnostics' session tests can simulate a genuine two-party
    // handshake in one process — see their own comment for why a
    // self-loopback through the one real device identity can't otherwise
    // produce two non-colliding sessions[contactId] entries.
    fun initiateSession(contactId: String, recipientBundle: PrekeyBundle, identityOverride: KeyPair? = null): Pair<SessionState, JSONObject> = synchronized(this) {
        // S6-46: cryptographic identity binding — same fix and rationale as
        // Android's SessionKeyManager.initiateSession() (see its own
        // comment and docs/SECURITY_INVARIANTS.md #59). Checked BEFORE
        // SPK/PQ signature trust, OPK use, or session creation.
        val identityKeyBytes = Base64.getDecoder().decode(recipientBundle.identityKey)
        val actualFingerprint = MessageDigest.getInstance("SHA-256").digest(identityKeyBytes)
            .take(8).joinToString("") { "%02X".format(it) }
        if (actualFingerprint != contactId) {
            throw SecurityException("Identity-ключ bundle не совпадает с запрошенным $contactId — возможна подмена ключа!")
        }

        val isSpkValid = CryptoManager.verify(recipientBundle.signedPrekey, recipientBundle.spkSignature, recipientBundle.identityKey)
        if (!isSpkValid) throw SecurityException("Неверная подпись SPK от $contactId")
        val isPqValid = CryptoManager.verify(recipientBundle.pqKemPublicKey, recipientBundle.pqKemSignature, recipientBundle.identityKey)
        if (!isPqValid) throw SecurityException("Неверная подпись PQ-ключа от $contactId")

        val ephemeralKp = generateEcKeyPair()
        val ephemeralPublicB64 = Base64.getEncoder().encodeToString(ephemeralKp.public.encoded)

        val ikRecipient = loadPublicKey(recipientBundle.identityKey)
        val spkRecipient = loadPublicKey(recipientBundle.signedPrekey)

        var dh1: ByteArray? = null
        var dh2: ByteArray? = null
        var dh3: ByteArray? = null
        var dh4: ByteArray? = null
        var usedOpkId: Int? = null
        var dhMaterial: ByteArray? = null
        var pqSharedSecret: ByteArray? = null
        var sessionKey: ByteArray? = null
        var rootKey0: ByteArray? = null
        var dhR: ByteArray? = null

        try {
            dh1 = ecdh(identityOverride?.private ?: CryptoManager.getPrivateKeyPublic(), spkRecipient)
            dh2 = ecdh(ephemeralKp.private, ikRecipient)
            dh3 = ecdh(ephemeralKp.private, spkRecipient)

            if (recipientBundle.oneTimePrekeys.isNotEmpty()) {
                val parts = recipientBundle.oneTimePrekeys.first().split(":")
                if (parts.size == 2) {
                    usedOpkId = parts[0].toIntOrNull()
                    val opkPublic = loadPublicKey(parts[1])
                    dh4 = ecdh(ephemeralKp.private, opkPublic)
                }
            }

            // Hybrid PQ component: encapsulate against the recipient's ML-KEM
            // public key. The resulting shared secret is combined with (not a
            // replacement for) the classical DH material below — breaking
            // either alone is not enough to recover the session key.
            val pqPublicKeyBytes = Base64.getDecoder().decode(recipientBundle.pqKemPublicKey)
            val encapsulated = PqCrypto.encapsulate(pqPublicKeyBytes)
            val pqCiphertext = encapsulated.ciphertext
            pqSharedSecret = encapsulated.sharedSecret

            dhMaterial = (if (dh4 != null) dh1!! + dh2!! + dh3!! + dh4!! else dh1!! + dh2!! + dh3!!) + pqSharedSecret
            sessionKey = hkdf(dhMaterial, "BeaconX3DHpq".toByteArray(), 64, salt = ephemeralKp.public.encoded)

            rootKey0 = sessionKey.copyOfRange(0, 32)
            val recvChainKey = sessionKey.copyOfRange(32, 64)
            val ratchetKP = generateEcKeyPair()
            dhR = ecdh(ratchetKP.private, spkRecipient)
            val (rootKey1, sendChainKey) = kdfRk(rootKey0, dhR)

            val sessionId = java.util.UUID.randomUUID().toString()
            val now = System.currentTimeMillis()

            val state = SessionState(
                contactId       = contactId,
                sendChainKey    = sendChainKey,
                recvChainKey    = recvChainKey,
                sendCounter     = 0,
                recvCounter     = 0,
                sessionId       = sessionId,
                createdAt       = now,
                lastRatchetAt   = now,
                rootKey         = rootKey1,
                sendRatchetPriv = ratchetKP.private.encoded,
                sendRatchetPub  = ratchetKP.public.encoded,
                recvRatchetPub  = spkRecipient.encoded
            )
            sessions[contactId] = state
            saveSession(state)

            val x3dhHeader = JSONObject().apply {
                put("ephemeral_key", ephemeralPublicB64)
                put("spk_id", recipientBundle.spkId)
                if (usedOpkId != null) put("opk_id", usedOpkId)
                put("session_id", sessionId)
                put("dh_ratchet_pub", Base64.getEncoder().encodeToString(ratchetKP.public.encoded))
                put("pq_kem_ciphertext", Base64.getEncoder().encodeToString(pqCiphertext))
            }

            return Pair(state, x3dhHeader)
        } finally {
            dh1?.let { SecureMemory.wipe(it) }
            dh2?.let { SecureMemory.wipe(it) }
            dh3?.let { SecureMemory.wipe(it) }
            dh4?.let { SecureMemory.wipe(it) }
            pqSharedSecret?.let { SecureMemory.wipe(it) }
            dhMaterial?.let { SecureMemory.wipe(it) }
            sessionKey?.let { SecureMemory.wipe(it) }
            rootKey0?.let { SecureMemory.wipe(it) }
            dhR?.let { SecureMemory.wipe(it) }
        }
    }

    // synchronized(this) — see initiateSession() above for why.
    //
    // Defense-in-depth fingerprint binding (2026-09-13 cross-platform
    // session_init audit) — mirrors Android's SessionKeyManager exactly.
    // The real, authoritative check lives in the caller
    // (WebSocketClient.processSessionInit()), BEFORE any cache is touched;
    // this one only protects a future/other caller that skipped its own
    // verification, not a substitute for that check.
    // identityOverride: test-only — see initiateSession()'s param of the
    // same name for the full rationale. Same contract: every real call
    // site omits this.
    fun receiveSession(contactId: String, senderIdentityKey: String, x3dhHeader: JSONObject, identityOverride: KeyPair? = null): SessionState = synchronized(this) {
        run {
            val ikBytes = try {
                Base64.getDecoder().decode(senderIdentityKey)
            } catch (e: Exception) {
                throw SecurityException("receiveSession: senderIdentityKey не является валидным Base64 для $contactId")
            }
            val actualFingerprint = MessageDigest.getInstance("SHA-256")
                .digest(ikBytes).take(8).joinToString("") { "%02X".format(it) }
            if (actualFingerprint != contactId) {
                throw SecurityException("receiveSession: identity key не соответствует $contactId (реальный=$actualFingerprint)")
            }
        }
        val ephemeralPublicB64 = x3dhHeader.getString("ephemeral_key")
        val spkId = x3dhHeader.getInt("spk_id")
        val opkId = if (x3dhHeader.has("opk_id")) x3dhHeader.getInt("opk_id") else null
        val sessionId = x3dhHeader.getString("session_id")
        // Required, not optional: a handshake missing the PQ ciphertext is
        // rejected rather than silently accepted as classical-only (prevents
        // a downgrade attack by a malicious server stripping the field).
        if (!x3dhHeader.has("pq_kem_ciphertext"))
            throw SecurityException("Рукопожатие без постквантового компонента отклонено (от $contactId)")
        val pqCiphertext = Base64.getDecoder().decode(x3dhHeader.getString("pq_kem_ciphertext"))

        val spk: KeyPair = when {
            spkId == currentSpkId -> currentSpk ?: throw IllegalStateException("SPK не найден")
            spkId == previousSpkId && previousSpk != null -> {
                if (System.currentTimeMillis() - previousSpkCreatedAt > SPK_GRACE_PERIOD_MS)
                    throw SecurityException("Предыдущий SPK id=$spkId истёк")
                previousSpk!!
            }
            else -> throw SecurityException("Неверный spk_id=$spkId, текущий=$currentSpkId")
        }
        val pqKem: PqCrypto.PqKeyPair = when {
            spkId == currentSpkId -> currentPqKem ?: throw IllegalStateException("PQ KEM ключ не найден")
            spkId == previousSpkId && previousPqKem != null -> {
                if (System.currentTimeMillis() - previousSpkCreatedAt > SPK_GRACE_PERIOD_MS)
                    throw SecurityException("Предыдущий PQ-ключ id=$spkId истёк")
                previousPqKem!!
            }
            else -> throw SecurityException("PQ-ключ для spk_id=$spkId недоступен")
        }
        val ikSender = loadPublicKey(senderIdentityKey)
        val ephemeralPublic = loadPublicKey(ephemeralPublicB64)

        var dh1: ByteArray? = null
        var dh2: ByteArray? = null
        var dh3: ByteArray? = null
        var dh4: ByteArray? = null
        var dhMaterial: ByteArray? = null
        var pqSharedSecret: ByteArray? = null
        var sessionKey: ByteArray? = null
        var rootKey0: ByteArray? = null
        var dhOut1: ByteArray? = null
        var rootKey1: ByteArray? = null
        var dhOut2: ByteArray? = null

        try {
            dh1 = ecdh(spk.private, ikSender)
            dh2 = ecdh(identityOverride?.private ?: CryptoManager.getPrivateKeyPublic(), ephemeralPublic)
            dh3 = ecdh(spk.private, ephemeralPublic)

            if (opkId != null) {
                val opkKp = consumeOpk(opkId) ?: throw SecurityException("OPK $opkId не найден")
                dh4 = ecdh(opkKp.private, ephemeralPublic)
            }

            pqSharedSecret = PqCrypto.decapsulate(pqKem.privateKey, pqCiphertext)

            dhMaterial = (if (dh4 != null) dh1!! + dh2!! + dh3!! + dh4!! else dh1!! + dh2!! + dh3!!) + pqSharedSecret
            sessionKey = hkdf(dhMaterial, "BeaconX3DHpq".toByteArray(), 64, salt = ephemeralPublic.encoded)

            val now = System.currentTimeMillis()
            val aliceRatchetPubB64 = if (x3dhHeader.has("dh_ratchet_pub")) x3dhHeader.getString("dh_ratchet_pub") else null

            val state: SessionState
            if (aliceRatchetPubB64 != null) {
                val aliceRatchetPub = loadPublicKey(aliceRatchetPubB64)
                rootKey0 = sessionKey.copyOfRange(0, 32)
                dhOut1 = ecdh(spk.private, aliceRatchetPub)
                val (rk1, recvChainKey) = kdfRk(rootKey0, dhOut1)
                rootKey1 = rk1

                val bobRatchetKP = generateEcKeyPair()
                dhOut2 = ecdh(bobRatchetKP.private, aliceRatchetPub)
                val (rootKey2, sendChainKey) = kdfRk(rootKey1, dhOut2)

                state = SessionState(
                    contactId       = contactId,
                    sendChainKey    = sendChainKey,
                    recvChainKey    = recvChainKey,
                    sendCounter     = 0,
                    recvCounter     = 0,
                    sessionId       = sessionId,
                    createdAt       = now,
                    lastRatchetAt   = now,
                    rootKey         = rootKey2,
                    sendRatchetPriv = bobRatchetKP.private.encoded,
                    sendRatchetPub  = bobRatchetKP.public.encoded,
                    recvRatchetPub  = aliceRatchetPub.encoded
                )
            } else {
                val recvChainKey = sessionKey.copyOfRange(0, 32)
                val sendChainKey = sessionKey.copyOfRange(32, 64)
                state = SessionState(
                    contactId    = contactId,
                    sendChainKey = sendChainKey,
                    recvChainKey = recvChainKey,
                    sendCounter  = 0,
                    recvCounter  = 0,
                    sessionId    = sessionId,
                    createdAt    = now,
                    lastRatchetAt = now
                )
            }

            sessions[contactId] = state
            saveSession(state)
            return state
        } finally {
            dh1?.let { SecureMemory.wipe(it) }
            dh2?.let { SecureMemory.wipe(it) }
            dh3?.let { SecureMemory.wipe(it) }
            dh4?.let { SecureMemory.wipe(it) }
            pqSharedSecret?.let { SecureMemory.wipe(it) }
            dhMaterial?.let { SecureMemory.wipe(it) }
            sessionKey?.let { SecureMemory.wipe(it) }
            rootKey0?.let { SecureMemory.wipe(it) }
            dhOut1?.let { SecureMemory.wipe(it) }
            rootKey1?.let { SecureMemory.wipe(it) }
            dhOut2?.let { SecureMemory.wipe(it) }
        }
    }

    // synchronized(this) — see initiateSession() above for why.
    fun nextSendKey(contactId: String): SendKeyResult = synchronized(this) {
        val state = sessions[contactId] ?: throw IllegalStateException("Нет сессии с $contactId")
        if (needsRatchetRotation(state)) throw SessionRotationRequired(contactId)

        val messageKey = ratchetStep(state.sendChainKey)
        val nextChainKey = ratchetAdvance(state.sendChainKey)
        val counter = state.sendCounter

        val newState = state.copy(sendChainKey = nextChainKey, sendCounter = counter + 1, lastRatchetAt = System.currentTimeMillis())
        sessions[contactId] = newState
        SecureMemory.wipe(state.sendChainKey)
        saveSession(newState)

        val dhPub = if (isDHRatchetActive(state)) Base64.getEncoder().encodeToString(state.sendRatchetPub) else null
        return SendKeyResult(messageKey, counter, state.sessionId, dhPub)
    }

    // Ported from Android's SessionKeyManager.kt (2026-08-30/09-02/09-03
    // fixes) after a desktop/Android symmetry audit found this function had
    // received none of them — see docs/ISSUE_backup_identity_hijack.md and
    // PROTOCOL_STATE_MACHINE.md §7 for the full history of why each step
    // below exists.
    // synchronized(this) — see initiateSession() above for why.
    fun nextRecvKey(contactId: String, expectedCounter: Int, dhKeyB64: String? = null): ByteArray = synchronized(this) {
        var state = sessions[contactId] ?: throw IllegalStateException("Нет сессии с $contactId")

        val now = System.currentTimeMillis()
        val expired = state.skippedKeyTimestamps.filter { now - it.value > SKIPPED_KEY_TTL_MS }.keys
        if (expired.isNotEmpty()) {
            expired.forEach { k -> state.skippedKeys[k]?.let { SecureMemory.wipe(it) } }
            state = state.copy(
                skippedKeys = state.skippedKeys - expired.toSet(),
                skippedKeyTimestamps = state.skippedKeyTimestamps - expired.toSet()
            )
            sessions[contactId] = state
            saveSession(state)
        }

        val inDHRatchet = dhKeyB64 != null && isDHRatchetActive(state)
        val currentDhPubB64 = state.recvRatchetPub?.let { Base64.getEncoder().encodeToString(it) }
        val isDHStep = inDHRatchet && dhKeyB64 != currentDhPubB64

        // Always namespace skipped-key entries by the epoch the INCOMING
        // message actually claims (dhKeyB64), never by whatever we
        // currently have tracked — the old three-way `when` here keyed a
        // DH-step message by currentDhPubB64 (the OLD epoch), which could
        // never match a lookup for the same message keyed by its own
        // dhKeyB64 later.
        val epochPrefix = if (inDHRatchet) "$dhKeyB64:" else ""
        val lookupKey = "$epochPrefix$expectedCounter"

        state.skippedKeys[lookupKey]?.let { skippedKey ->
            val newSkipped = state.skippedKeys.toMutableMap().also { it.remove(lookupKey) }
            val newTs = state.skippedKeyTimestamps.toMutableMap().also { it.remove(lookupKey) }
            val updated = state.copy(skippedKeys = newSkipped, skippedKeyTimestamps = newTs)
            sessions[contactId] = updated
            saveSession(updated)
            return skippedKey
        }

        // DH ratchet step runs unconditionally, before any counter
        // comparison. performDHRatchetStep() resets both sides' counters to
        // 0, so a new epoch's first message always carries a low counter,
        // unrelated to whatever recvCounter accumulated under the previous
        // epoch — comparing the two before stepping wedges the session on a
        // false "stale" rejection (below) that never resolves, since that
        // throw deliberately never touches session state. A message keyed
        // to an epoch already recorded in previousRecvRatchetPubs (e.g. the
        // server's token_pending fallback redelivering an already-processed
        // message) must NOT re-trigger a step — that would roll the live
        // session's root/chain keys and ratchet keypair backward instead of
        // being recognized as a stale duplicate.
        if (isDHStep) {
            if (dhKeyB64 in state.previousRecvRatchetPubs) {
                throw DuplicateOrStaleMessage(contactId, expectedCounter, state.recvCounter)
            }
            val oldChainKey = state.recvChainKey
            val oldRecvPubB64 = currentDhPubB64
            state = performDHRatchetStep(state, dhKeyB64!!)
            if (oldRecvPubB64 != null) {
                val history = (state.previousRecvRatchetPubs + oldRecvPubB64)
                    .takeLast(MAX_PREVIOUS_RATCHET_EPOCHS)
                state = state.copy(previousRecvRatchetPubs = history)
            }
            SecureMemory.wipe(oldChainKey)
            sessions[contactId] = state
            saveSession(state)
        }

        if (expectedCounter < state.recvCounter) {
            // A genuinely older counter with no skipped-key entry means
            // this was already processed once (e.g. token_pending
            // redelivering an already-acked message, or the same message
            // arriving twice via two transports) — not "derive the next
            // key anyway." Falling through to the normal derivation path
            // below would silently derive a bogus key AND advance the
            // chain/counter a second time, permanently desyncing the
            // ratchet from the sender's real position.
            throw DuplicateOrStaleMessage(contactId, expectedCounter, state.recvCounter)
        }

        if (expectedCounter > state.recvCounter) {
            val gap = expectedCounter - state.recvCounter
            if (gap > MAX_SKIPPED_KEYS || state.skippedKeys.size + gap > MAX_SKIPPED_KEYS) {
                throw SecurityException("Разрыв счётчика: $gap")
            }

            var chainKey = state.recvChainKey.copyOf()
            val newSkipped = state.skippedKeys.toMutableMap()
            val newTs = state.skippedKeyTimestamps.toMutableMap()
            val skipTs = System.currentTimeMillis()

            for (i in state.recvCounter until expectedCounter) {
                newSkipped["$epochPrefix$i"] = ratchetStep(chainKey)
                newTs["$epochPrefix$i"] = skipTs
                val next = ratchetAdvance(chainKey)
                SecureMemory.wipe(chainKey)
                chainKey = next
            }

            if (newSkipped.size > MAX_SKIPPED_KEYS) {
                val toEvict = newSkipped.keys.sortedBy { newTs[it] ?: 0L }.take(newSkipped.size - MAX_SKIPPED_KEYS)
                toEvict.forEach { k ->
                    newSkipped[k]?.let { SecureMemory.wipe(it) }
                    newSkipped.remove(k); newTs.remove(k)
                }
                println("$TAG: Skipped-key buffer full — evicted ${toEvict.size} old entries")
            }

            val messageKey   = ratchetStep(chainKey)
            val nextChainKey = ratchetAdvance(chainKey)
            SecureMemory.wipe(chainKey)
            SecureMemory.wipe(state.recvChainKey)
            val newState2 = state.copy(recvChainKey = nextChainKey, recvCounter = expectedCounter + 1, skippedKeys = newSkipped, skippedKeyTimestamps = newTs)
            sessions[contactId] = newState2
            saveSession(newState2)
            return messageKey
        }

        val messageKey   = ratchetStep(state.recvChainKey)
        val nextChainKey = ratchetAdvance(state.recvChainKey)
        val newState3 = state.copy(recvChainKey = nextChainKey, recvCounter = state.recvCounter + 1)
        sessions[contactId] = newState3
        SecureMemory.wipe(state.recvChainKey)
        saveSession(newState3)
        return messageKey
    }

    private fun ratchetStep(chainKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(chainKey, "HmacSHA256"))
        return mac.doFinal(byteArrayOf(0x01))
    }

    private fun ratchetAdvance(chainKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(chainKey, "HmacSHA256"))
        return mac.doFinal(byteArrayOf(0x02))
    }

    private fun needsRatchetRotation(state: SessionState): Boolean {
        if (isDHRatchetActive(state)) return false
        val now = System.currentTimeMillis()
        return state.sendCounter >= RATCHET_ROTATION_THRESHOLD || (now - state.lastRatchetAt) >= RATCHET_ROTATION_TIME_MS
    }

    fun hasSession(contactId: String): Boolean = sessions.containsKey(contactId)

    /** Wipes every contact's session state — used when replacing this
     * device's active identity with a different one from a backup, see
     * BackupManager.wipeCurrentIdentityData(). Mirrors Android's
     * SessionKeyManager.deleteAllSessions(). Also clears opkPool/currentSpk
     * — was previously left in place, unlike Android. Traced every actual
     * caller (BackupManager.wipeCurrentIdentityData(), reached from
     * resetCompromisedIdentity(), importBackup(), and RegisterScreen's
     * new-local-account path): all three are "about to establish a
     * genuinely different identity" moments, same as every Android caller
     * of this function. Leaving the old OPK pool/SPK in place would let a
     * NEW EC identity key publish prekey bundles built on DH key material
     * that was generated (and possibly already used in X3DH handshakes)
     * under the OLD identity — getLocalPrekeyBundle() re-signs with
     * whatever identity key is current at call time, so this wasn't a
     * hard crypto break, but it does mean the new identity's prekeys
     * aren't actually fresh. Found in the 2026-09-13 full-logic audit. */
    fun deleteAllSessions() = synchronized(this) {
        sessions.keys.toList().forEach { deleteSession(it) }
        opkPool.clear()
        currentSpk = null
    }

    // synchronized(this) — see initiateSession() above for why. Mirrors
    // Android's SessionKeyManager.deleteSession(): must serialize against
    // nextSendKey/nextRecvKey's own synchronized blocks, or a burst of
    // concurrently-processed incoming messages for the same contact could
    // have one message's decrypt-failure handler call deleteSession()
    // mid-flight while another was still inside its own nextRecvKey() call
    // for the same contact.
    fun deleteSession(contactId: String) = synchronized(this) {
        val state = sessions.remove(contactId)
        state?.let {
            SecureMemory.wipe(it.sendChainKey)
            SecureMemory.wipe(it.recvChainKey)
            it.skippedKeys.values.forEach { k -> SecureMemory.wipe(k) }
            if (isDHRatchetActive(it)) {
                SecureMemory.wipe(it.rootKey)
                SecureMemory.wipe(it.sendRatchetPriv)
                SecureMemory.wipe(it.sendRatchetPub)
                it.recvRatchetPub?.let { pub -> SecureMemory.wipe(pub) }
            }
        }
        DesktopStorage.remove("session_$contactId")
    }

    fun deleteSessionInternal(contactId: String) {
        deleteSession(contactId)
    }

    fun encryptWithSession(contactId: String, plaintext: String): Pair<String, JSONObject> {
        val result = nextSendKey(contactId)
        val plaintextBytes = plaintext.toByteArray()
        try {
            val encrypted = aesGcmEncrypt(plaintextBytes, result.messageKey)
            val header = JSONObject().apply {
                put("session_id", result.sessionId)
                put("counter", result.counter)
                put("v", if (result.dhRatchetPubB64 != null) 3 else 2)
                result.dhRatchetPubB64?.let { put("dh", it) }
            }
            return Pair(Base64.getEncoder().encodeToString(encrypted), header)
        } finally {
            SecureMemory.wipe(result.messageKey)
            SecureMemory.wipe(plaintextBytes)
        }
    }

    fun decryptWithSession(contactId: String, ciphertextB64: String, header: JSONObject): String {
        val counter = header.getInt("counter")
        val dhKeyB64 = header.optString("dh", null).takeIf { !it.isNullOrBlank() }
        val messageKey = nextRecvKey(contactId, counter, dhKeyB64)
        try {
            val cipherBytes = Base64.getDecoder().decode(ciphertextB64)
            val plaintext = aesGcmDecrypt(cipherBytes, messageKey)
            try {
                return String(plaintext)
            } finally {
                SecureMemory.wipe(plaintext)
            }
        } finally {
            SecureMemory.wipe(messageKey)
        }
    }

    private fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = javax.crypto.spec.SecretKeySpec(key, 0, 32, "AES")
        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(plaintext)
        return iv + ciphertext
    }

    private fun aesGcmDecrypt(encrypted: ByteArray, key: ByteArray): ByteArray {
        val iv = encrypted.copyOfRange(0, 12)
        val ciphertext = encrypted.copyOfRange(12, encrypted.size)
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = javax.crypto.spec.SecretKeySpec(key, 0, 32, "AES")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, javax.crypto.spec.GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun hkdf(ikm: ByteArray, info: ByteArray, outputLen: Int, salt: ByteArray = ByteArray(32)): ByteArray {
        val prk = run {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            mac.doFinal(ikm)
        }
        val result = ByteArray(outputLen)
        var t = ByteArray(0)
        try {
            var pos = 0
            var counter = 1
            while (pos < outputLen) {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(prk, "HmacSHA256"))
                mac.update(t)
                mac.update(info)
                mac.update(counter.toByte())
                val tPrev = t
                t = mac.doFinal()
                if (tPrev.isNotEmpty()) SecureMemory.wipe(tPrev)
                val copy = minOf(t.size, outputLen - pos)
                System.arraycopy(t, 0, result, pos, copy)
                pos += copy
                counter++
            }
            return result
        } finally {
            SecureMemory.wipe(prk)
            if (t.isNotEmpty()) SecureMemory.wipe(t)
        }
    }

    private fun isDHRatchetActive(state: SessionState) = state.rootKey.isNotEmpty() && state.sendRatchetPriv.isNotEmpty()

    private fun kdfRk(rootKey: ByteArray, dhOutput: ByteArray): Pair<ByteArray, ByteArray> {
        val out = hkdf(dhOutput, "BeaconDHRatchet".toByteArray(), 64, salt = rootKey)
        val newRoot  = out.copyOfRange(0, 32)
        val chainKey = out.copyOfRange(32, 64)
        SecureMemory.wipe(out)
        return Pair(newRoot, chainKey)
    }

    private fun performDHRatchetStep(state: SessionState, newDhPubB64: String): SessionState {
        val newDhPub = loadPublicKey(newDhPubB64)
        val decoder = Base64.getDecoder()
        val privKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(state.sendRatchetPriv))

        var dhOut1: ByteArray? = null
        var rootKey1: ByteArray? = null
        var dhOut2: ByteArray? = null

        try {
            dhOut1 = ecdh(privKey, newDhPub)
            val (rk1, recvChainKey) = kdfRk(state.rootKey, dhOut1)
            rootKey1 = rk1

            val newKP = generateEcKeyPair()
            dhOut2 = ecdh(newKP.private, newDhPub)
            val (rootKey2, sendChainKey) = kdfRk(rootKey1, dhOut2)

            return state.copy(
                rootKey          = rootKey2,
                recvChainKey     = recvChainKey,
                sendChainKey     = sendChainKey,
                sendCounter      = 0,
                recvCounter      = 0,
                sendRatchetPriv  = newKP.private.encoded,
                sendRatchetPub   = newKP.public.encoded,
                recvRatchetPub   = newDhPub.encoded,
                lastRatchetAt    = System.currentTimeMillis()
            )
        } finally {
            dhOut1?.let { SecureMemory.wipe(it) }
            rootKey1?.let { SecureMemory.wipe(it) }
            dhOut2?.let { SecureMemory.wipe(it) }
        }
    }

    /** Wraps private key material with the SMK when unlocked, mirroring how
     *  GroupManager already wraps group keys — falls back to plain Base64
     *  when locked so an operation triggered by incoming traffic while the
     *  app is locked keeps working unchanged. `StorageKeyManager.unwrapBytes`
     *  transparently reads both forms. */
    private fun wrapKeyBytes(bytes: ByteArray): String =
        if (StorageKeyManager.isUnlocked) StorageKeyManager.wrapBytes(bytes)
        else Base64.getEncoder().encodeToString(bytes)

    /** Like `StorageKeyManager.unwrapBytes`, but never throws — returns null
     *  if the value is SMK-wrapped and the app is currently locked (e.g. a
     *  process cold start before the user has unlocked this run), or on any
     *  other decode failure. Callers must treat null as "this key isn't
     *  available yet" and skip gracefully rather than regenerating — the key
     *  material is still on disk, just temporarily inaccessible; regenerating
     *  would invalidate an already-published SPK/OPK for no reason.
     *  `reloadSessionsIfNeeded()` retries once the app unlocks. */
    private fun tryUnwrapKeyBytes(stored: String): ByteArray? =
        try {
            StorageKeyManager.unwrapBytes(stored)
        } catch (e: Exception) {
            println("$TAG: Key temporarily unavailable (SMK locked?): ${e.message}")
            null
        }

    private fun generateEcKeyPair(): KeyPair {
        val keyPairGen = KeyPairGenerator.getInstance("EC")
        keyPairGen.initialize(ECGenParameterSpec("secp256r1"))
        return keyPairGen.generateKeyPair()
    }

    private fun ecdh(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(publicKey, true)
        return ka.generateSecret()
    }

    private fun loadPublicKey(keyString: String): PublicKey {
        return CryptoManager.loadPublicKey(keyString)
    }

    private fun saveSession(state: SessionState) {
        try {
            val encoder = Base64.getEncoder()
            val skippedKeysJson = JSONObject()
            state.skippedKeys.forEach { (k, v) -> skippedKeysJson.put(k, encoder.encodeToString(v)) }
            val skippedTsJson = JSONObject()
            state.skippedKeyTimestamps.forEach { (k, v) -> skippedTsJson.put(k, v) }

            val json = JSONObject().apply {
                put("contactId",    state.contactId)
                put("sendChainKey", encoder.encodeToString(state.sendChainKey))
                put("recvChainKey", encoder.encodeToString(state.recvChainKey))
                put("sendCounter",  state.sendCounter)
                put("recvCounter",  state.recvCounter)
                put("sessionId",    state.sessionId)
                put("createdAt",    state.createdAt)
                put("lastRatchetAt",state.lastRatchetAt)
                put("skippedKeys",  skippedKeysJson)
                put("skippedKeyTimestamps", skippedTsJson)
                if (isDHRatchetActive(state)) {
                    put("rootKey",         encoder.encodeToString(state.rootKey))
                    put("sendRatchetPriv", encoder.encodeToString(state.sendRatchetPriv))
                    put("sendRatchetPub",  encoder.encodeToString(state.sendRatchetPub))
                    state.recvRatchetPub?.let { put("recvRatchetPub", encoder.encodeToString(it)) }
                    put("previousRecvRatchetPubs", JSONArray(state.previousRecvRatchetPubs))
                }
            }
            val jsonStr = json.toString()
            val toStore = if (StorageKeyManager.isUnlocked)
                StorageKeyManager.wrapBytes(jsonStr.toByteArray(Charsets.UTF_8))
            else jsonStr
            DesktopStorage.put("session_${state.contactId}", toStore)
        } catch (e: Exception) {
            println("$TAG: Error saving session: ${e.message}")
        }
    }

    /** Re-attempts loading anything that came up empty during `init()`
     *  because the SMK was locked at the time (process cold start before the
     *  user unlocked this run) — current SPK, current PQ KEM key, and any
     *  session whose on-disk blob is SMK-wrapped. Safe to call
     *  unconditionally on every successful unlock. */
    fun reloadSessionsIfNeeded() {
        if (currentSpk == null || currentPqKem == null) {
            generateOrRotateSpk()
            loadOpkPool()
            refillOpkPool(targetCount = 10)
        }
        loadAllSessions()
    }

    // synchronized(this) — mirrors Android's SessionKeyManager.loadAllSessions()
    // exactly: writes sessions[contactId] directly, same as nextSendKey()/
    // nextRecvKey()/deleteSession(), but without their lock this
    // disk-loaded (possibly stale) session could overwrite a freshly-
    // advanced in-memory session if reloadSessionsIfNeeded() ever ran
    // concurrently with an in-flight ratchet step. Serializing on the same
    // monitor as every other session-mutating function closes that gap —
    // by the time this can acquire the lock, any ratchet step already in
    // progress has finished and saved its result to disk (every mutating
    // function above calls saveSession() before releasing the lock), so
    // there is nothing left to overwrite.
    private fun loadAllSessions() = synchronized(this) {
        try {
            val decoder = Base64.getDecoder()
            for (key in DesktopStorage.getAllKeys()) {
                if (!key.startsWith("session_")) continue
                val rawStr = DesktopStorage.get(key) ?: continue
                try {
                    val jsonStr = if (rawStr.startsWith(StorageKeyManager.SMK_PREFIX)) {
                        String(StorageKeyManager.unwrapBytes(rawStr), Charsets.UTF_8)
                    } else rawStr
                    val json = JSONObject(jsonStr)
                    val skJson = json.optJSONObject("skippedKeys") ?: JSONObject()
                    val skippedKeys = mutableMapOf<String, ByteArray>()
                    skJson.keys().forEach { k -> skippedKeys[k] = decoder.decode(skJson.getString(k)) }
                    val tsJson = json.optJSONObject("skippedKeyTimestamps") ?: JSONObject()
                    val skippedTs = mutableMapOf<String, Long>()
                    tsJson.keys().forEach { k -> skippedTs[k] = tsJson.getLong(k) }

                    val rootKey = if (json.has("rootKey")) decoder.decode(json.getString("rootKey")) else ByteArray(0)
                    val sendRatchetPriv = if (json.has("sendRatchetPriv")) decoder.decode(json.getString("sendRatchetPriv")) else ByteArray(0)
                    val sendRatchetPub = if (json.has("sendRatchetPub")) decoder.decode(json.getString("sendRatchetPub")) else ByteArray(0)
                    val recvRatchetPub = if (json.has("recvRatchetPub")) decoder.decode(json.getString("recvRatchetPub")) else null
                    val previousRecvRatchetPubs = json.optJSONArray("previousRecvRatchetPubs")?.let { arr ->
                        (0 until arr.length()).map { i -> arr.getString(i) }
                    } ?: emptyList()

                    sessions[json.getString("contactId")] = SessionState(
                        contactId    = json.getString("contactId"),
                        sendChainKey = decoder.decode(json.getString("sendChainKey")),
                        recvChainKey = decoder.decode(json.getString("recvChainKey")),
                        sendCounter  = json.getInt("sendCounter"),
                        recvCounter  = json.getInt("recvCounter"),
                        sessionId    = json.getString("sessionId"),
                        createdAt    = json.getLong("createdAt"),
                        lastRatchetAt= json.getLong("lastRatchetAt"),
                        skippedKeys  = skippedKeys,
                        skippedKeyTimestamps = skippedTs,
                        rootKey         = rootKey,
                        sendRatchetPriv = sendRatchetPriv,
                        sendRatchetPub  = sendRatchetPub,
                        recvRatchetPub  = recvRatchetPub,
                        previousRecvRatchetPubs = previousRecvRatchetPubs
                    )
                } catch (e: Exception) {
                    println("$TAG: Failed to restore session $key: ${e.message}")
                }
            }
            println("$TAG: Sessions restored from storage: ${sessions.size}")
        } catch (e: Exception) {
            println("$TAG: Error loading sessions: ${e.message}")
        }
    }

    class SessionRotationRequired(val contactId: String) : Exception("Сессия с $contactId требует ротации")

    class DuplicateOrStaleMessage(val contactId: String, val expectedCounter: Int, val recvCounter: Int) :
        Exception("Повторное/устаревшее сообщение от $contactId: counter=$expectedCounter, ожидался >= $recvCounter")
}
