package com.bcon.messenger

import android.content.Context
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.GCMParameterSpec

object SessionKeyManager {

    private const val TAG = "SessionKeyManager"
    private const val PREFS_NAME = "session_keys"
    private const val SPK_ROTATION_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000L

    // ─── Протокол Double Ratchet (v3) ───────────────────────────────────────
    //
    // Реализован полный Double Ratchet (Signal Protocol):
    //   - X3DH для установки начального shared secret
    //   - Symmetric Ratchet: HMAC-SHA256 цепочка ключей сообщений
    //   - DH Ratchet: при каждом обмене генерируется новая EC-пара,
    //     публичный ключ передаётся в session_header {"dh": "..."}.
    //     ECDH(старый_priv, новый_pub_собеседника) → KDF_RK → новые chain keys.
    //     "Break-in recovery": компрометация ChainKey самовосстанавливается после
    //     следующего DH-шага.
    //
    // Совместимость:
    //   - v2 session_header (без поля "dh"): Symmetric Ratchet (legacy)
    //   - v3 session_header (с полем "dh"): Double Ratchet
    //
    // v3-сессии создаются при x3dh_header с полем "dh_ratchet_pub".
    // Для v3-сессий needsRatchetRotation() всегда false — DH ratchet достаточен.
    private const val RATCHET_ROTATION_THRESHOLD = 50   // для v2-сессий; v3 не ротирует
    private const val RATCHET_ROTATION_TIME_MS = 12 * 60 * 60 * 1000L  // для v2-сессий
    private const val MAX_SKIPPED_KEYS = 100
    private const val SKIPPED_KEY_TTL_MS = 7 * 24 * 60 * 60 * 1000L  // 7 days
    private const val SPK_GRACE_PERIOD_MS = 14 * 24 * 60 * 60 * 1000L  // 14 days

    // ─── Структуры данных ────────────────────────────────────────────────────

    data class PrekeyBundle(
        val identityKey: String,
        val signedPrekey: String,
        val spkSignature: String,
        val spkId: Int,
        val oneTimePrekeys: List<String>
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
        // ── DH Ratchet (v3) ─────────────────────────────────────────────────
        // Пустой ByteArray = v2-сессия (DH ratchet не активен)
        val rootKey: ByteArray = ByteArray(0),
        val sendRatchetPriv: ByteArray = ByteArray(0),  // PKCS8 текущей ratchet-пары
        val sendRatchetPub: ByteArray = ByteArray(0),   // X509  текущей ratchet-пары
        val recvRatchetPub: ByteArray? = null,           // X509 последнего ключа собеседника
        // ── Буфер пропущенных ключей ────────────────────────────────────────
        // v2: ключ = "$counter"
        // v3: ключ = "$senderDhPubB64:$counter"  (привязка к DH-эпохе)
        val skippedKeys: Map<String, ByteArray> = emptyMap(),
        val skippedKeyTimestamps: Map<String, Long> = emptyMap()
    )

    // Результат nextSendKey — включает DH ratchet public key для v3
    data class SendKeyResult(
        val messageKey: ByteArray,
        val counter: Int,
        val sessionId: String,
        val dhRatchetPubB64: String?  // null для v2-сессий
    )

    // ─── In-memory хранилище ─────────────────────────────────────────────────

    // ConcurrentHashMap: nextSendKey() вызывается из UI-потока, nextRecvKey() — из WebSocket-потока.
    // Обычный HashMap приводит к ConcurrentModificationException или потере обновлений chain key.
    private val sessions = java.util.concurrent.ConcurrentHashMap<String, SessionState>()
    private val secureRandom = SecureRandom()
    private var currentSpk: KeyPair? = null
    private var currentSpkId: Int = 0
    private var spkCreatedAt: Long = 0L
    private var previousSpk: KeyPair? = null
    private var previousSpkId: Int = -1
    private var previousSpkCreatedAt: Long = 0L
    // ConcurrentHashMap — consumeOpk() может вызываться с WebRTC-треда одновременно с refillOpkPool()
    private val opkPool = java.util.concurrent.ConcurrentHashMap<Int, KeyPair>()
    // AtomicInteger: opkIdCounter++ используется в refillOpkPool и может вызваться с разных потоков.
    // Не атомарный int → дублирующиеся OPK ID при гонке.
    private val opkIdCounter = java.util.concurrent.atomic.AtomicInteger(0)
    private var appContext: Context? = null

    // ─── Инициализация ───────────────────────────────────────────────────────

    fun initialize(context: Context) {
        appContext = context.applicationContext
        generateOrRotateSpk(context)
        loadOpkPool(context)               // Restore persisted OPKs first
        refillOpkPool(context, targetCount = 10)  // Then top up to target size
        loadAllSessions()                  // Восстанавливаем сессии после перезапуска
        Log.d(TAG, "SessionKeyManager инициализирован. SPK id=$currentSpkId, OPK pool=${opkPool.size}, sessions=${sessions.size}")
    }

    // ─── Signed Prekey (SPK) ─────────────────────────────────────────────────

    private fun generateOrRotateSpk(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encPrefs = EncryptedStorage.getEncryptedPrefs(context, "${PREFS_NAME}_secure")
        val savedSpkId = prefs.getInt("spk_id", -1)
        val savedCreatedAt = prefs.getLong("spk_created_at", 0L)
        val now = System.currentTimeMillis()

        val needsRotation = savedSpkId == -1 ||
                (now - savedCreatedAt) > SPK_ROTATION_INTERVAL_MS

        if (needsRotation) {
            // Сохраняем старый SPK как предыдущий перед ротацией (grace period для входящих сессий)
            if (savedSpkId >= 0) {
                val oldPrivB64 = encPrefs.getString("spk_private_key_${savedSpkId}", null)
                val oldPubB64 = prefs.getString("spk_public_${savedSpkId}", null)
                if (oldPrivB64 != null && oldPubB64 != null) {
                    try {
                        val kf = KeyFactory.getInstance("EC")
                        previousSpk = KeyPair(
                            kf.generatePublic(X509EncodedKeySpec(Base64.decode(oldPubB64, Base64.NO_WRAP))),
                            kf.generatePrivate(PKCS8EncodedKeySpec(Base64.decode(oldPrivB64, Base64.NO_WRAP)))
                        )
                        previousSpkId = savedSpkId
                        previousSpkCreatedAt = savedCreatedAt
                        prefs.edit()
                            .putInt("prev_spk_id", savedSpkId)
                            .putLong("prev_spk_created_at", savedCreatedAt)
                            .putString("prev_spk_public", oldPubB64)
                            .apply()
                        encPrefs.edit()
                            .putString("prev_spk_private_key", oldPrivB64)
                            .apply()
                        Log.d(TAG, "Старый SPK сохранён как предыдущий: id=$savedSpkId")
                    } catch (e: Exception) {
                        Log.w(TAG, "Не удалось сохранить предыдущий SPK: ${e.message}")
                    }
                }
            }
            currentSpk = generateEcKeyPair()
            currentSpkId = (savedSpkId + 1).coerceAtLeast(0)
            spkCreatedAt = now
            // Save private key in encrypted storage
            encPrefs.edit()
                .putString(
                    "spk_private_key_${currentSpkId}",
                    Base64.encodeToString(currentSpk!!.private.encoded, Base64.NO_WRAP)
                )
                .apply()
            prefs.edit()
                .putInt("spk_id", currentSpkId)
                .putLong("spk_created_at", now)
                .putString(
                    "spk_public_${currentSpkId}",
                    Base64.encodeToString(currentSpk!!.public.encoded, Base64.NO_WRAP)
                )
                .apply()
            Log.d(TAG, "SPK ротирован: id=$currentSpkId")
        } else {
            // Restore saved SPK key pair — do NOT generate a new one
            val privateKeyB64 = encPrefs.getString("spk_private_key_${savedSpkId}", null)
            val publicKeyB64 = prefs.getString("spk_public_${savedSpkId}", null)
            if (privateKeyB64 != null && publicKeyB64 != null) {
                val keyFactory = KeyFactory.getInstance("EC")
                val privateKey = keyFactory.generatePrivate(
                    PKCS8EncodedKeySpec(Base64.decode(privateKeyB64, Base64.NO_WRAP))
                )
                val publicKey = keyFactory.generatePublic(
                    X509EncodedKeySpec(Base64.decode(publicKeyB64, Base64.NO_WRAP))
                )
                currentSpk = KeyPair(publicKey, privateKey)
            } else {
                // Saved key not found (first upgrade from old version) — generate and save
                currentSpk = generateEcKeyPair()
                encPrefs.edit()
                    .putString(
                        "spk_private_key_${savedSpkId}",
                        Base64.encodeToString(currentSpk!!.private.encoded, Base64.NO_WRAP)
                    )
                    .apply()
                prefs.edit()
                    .putString(
                        "spk_public_${savedSpkId}",
                        Base64.encodeToString(currentSpk!!.public.encoded, Base64.NO_WRAP)
                    )
                    .apply()
            }
            currentSpkId = savedSpkId
            spkCreatedAt = savedCreatedAt
            Log.d(TAG, "SPK восстановлен: id=$currentSpkId")
            // Восстанавливаем предыдущий SPK если в пределах grace period
            val prevSpkId = prefs.getInt("prev_spk_id", -1)
            val prevCreatedAt = prefs.getLong("prev_spk_created_at", 0L)
            if (prevSpkId >= 0 && (now - prevCreatedAt) < SPK_GRACE_PERIOD_MS) {
                val prevPrivB64 = encPrefs.getString("prev_spk_private_key", null)
                val prevPubB64 = prefs.getString("prev_spk_public", null)
                if (prevPrivB64 != null && prevPubB64 != null) {
                    try {
                        val kf = KeyFactory.getInstance("EC")
                        previousSpk = KeyPair(
                            kf.generatePublic(X509EncodedKeySpec(Base64.decode(prevPubB64, Base64.NO_WRAP))),
                            kf.generatePrivate(PKCS8EncodedKeySpec(Base64.decode(prevPrivB64, Base64.NO_WRAP)))
                        )
                        previousSpkId = prevSpkId
                        previousSpkCreatedAt = prevCreatedAt
                        Log.d(TAG, "Предыдущий SPK восстановлен: id=$prevSpkId")
                    } catch (e: Exception) {
                        Log.w(TAG, "Не удалось восстановить предыдущий SPK: ${e.message}")
                    }
                }
            }
        }
    }

    // ─── One-Time Prekeys (OPK) ──────────────────────────────────────────────

    private fun loadOpkPool(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encPrefs = EncryptedStorage.getEncryptedPrefs(context, "${PREFS_NAME}_secure")
        opkIdCounter.set(prefs.getInt("opk_counter", 0))
        val idsStr = prefs.getString("opk_ids", "") ?: ""
        if (idsStr.isBlank()) return
        val ids = idsStr.split(",").mapNotNull { it.trim().toIntOrNull() }
        val keyFactory = KeyFactory.getInstance("EC")
        for (id in ids) {
            val privateB64 = encPrefs.getString("opk_private_$id", null) ?: continue
            val publicB64 = prefs.getString("opk_public_$id", null) ?: continue
            try {
                val privateKey = keyFactory.generatePrivate(
                    PKCS8EncodedKeySpec(Base64.decode(privateB64, Base64.NO_WRAP))
                )
                val publicKey = keyFactory.generatePublic(
                    X509EncodedKeySpec(Base64.decode(publicB64, Base64.NO_WRAP))
                )
                opkPool[id] = KeyPair(publicKey, privateKey)
            } catch (e: Exception) {
                Log.w(TAG, "Не удалось восстановить OPK $id: ${e.message}")
            }
        }
        Log.d(TAG, "OPK pool восстановлен: ${opkPool.size} ключей")
    }

    private fun refillOpkPool(context: Context, targetCount: Int) {
        val needed = targetCount - opkPool.size
        if (needed <= 0) return
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encPrefs = EncryptedStorage.getEncryptedPrefs(context, "${PREFS_NAME}_secure")
        val prefsEditor = prefs.edit()
        val encEditor = encPrefs.edit()
        repeat(needed) {
            val id = opkIdCounter.getAndIncrement()
            val kp = generateEcKeyPair()
            opkPool[id] = kp
            encEditor.putString("opk_private_$id", Base64.encodeToString(kp.private.encoded, Base64.NO_WRAP))
            prefsEditor.putString("opk_public_$id", Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP))
        }
        prefsEditor
            .putString("opk_ids", opkPool.keys.joinToString(","))
            .putInt("opk_counter", opkIdCounter.get())
            .apply()
        encEditor.apply()
        Log.d(TAG, "OPK pool пополнен: +$needed, итого=${opkPool.size}")
    }

    fun consumeOpk(opkId: Int): KeyPair? {
        val kp = opkPool.remove(opkId) ?: return null
        Log.d(TAG, "OPK $opkId использован. Осталось: ${opkPool.size}")
        appContext?.let { ctx ->
            val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val encPrefs = EncryptedStorage.getEncryptedPrefs(ctx, "${PREFS_NAME}_secure")
            encPrefs.edit().remove("opk_private_$opkId").apply()
            prefs.edit()
                .remove("opk_public_$opkId")
                .putString("opk_ids", opkPool.keys.joinToString(","))
                .apply()
        }
        return kp
    }

    // ─── Prekey Bundle ───────────────────────────────────────────────────────

    fun getLocalPrekeyBundle(): PrekeyBundle {
        val spk = currentSpk ?: throw IllegalStateException("SPK не инициализирован")
        val spkPublicB64 = Base64.encodeToString(spk.public.encoded, Base64.NO_WRAP)
        val spkSignature = CryptoManager.sign(spkPublicB64)
        val opkPublics = opkPool.entries.take(5).map { (id, kp) ->
            "$id:${Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)}"
        }
        return PrekeyBundle(
            identityKey = CryptoManager.getPublicKeyString(),
            signedPrekey = spkPublicB64,
            spkSignature = spkSignature,
            spkId = currentSpkId,
            oneTimePrekeys = opkPublics
        )
    }

    fun prekeyBundleToJson(bundle: PrekeyBundle): JSONObject = JSONObject().apply {
        put("identity_key", bundle.identityKey)
        put("signed_prekey", bundle.signedPrekey)
        put("spk_signature", bundle.spkSignature)
        put("spk_id", bundle.spkId)
        put("opks", org.json.JSONArray(bundle.oneTimePrekeys))
    }

    fun parsePrekeyBundle(json: JSONObject): PrekeyBundle {
        val opksArray = json.getJSONArray("opks")
        val opks = (0 until opksArray.length()).map { opksArray.getString(it) }
        return PrekeyBundle(
            identityKey = json.getString("identity_key"),
            signedPrekey = json.getString("signed_prekey"),
            spkSignature = json.getString("spk_signature"),
            spkId = json.getInt("spk_id"),
            oneTimePrekeys = opks
        )
    }
    fun generatePrekeyBundle(): JSONObject {
        val bundle = getLocalPrekeyBundle()
        return prekeyBundleToJson(bundle)
    }

    // ─── X3DH — отправитель ──────────────────────────────────────────────────

    fun initiateSession(
        contactId: String,
        recipientBundle: PrekeyBundle
    ): Pair<SessionState, JSONObject> {

        val isSpkValid = CryptoManager.verify(
            recipientBundle.signedPrekey,
            recipientBundle.spkSignature,
            recipientBundle.identityKey
        )
        if (!isSpkValid) {
            throw SecurityException("Неверная подпись SPK от $contactId — возможна MITM атака!")
        }

        val ephemeralKp = generateEcKeyPair()
        val ephemeralPublicB64 = Base64.encodeToString(ephemeralKp.public.encoded, Base64.NO_WRAP)

        val ikRecipient = loadPublicKey(recipientBundle.identityKey)
        val spkRecipient = loadPublicKey(recipientBundle.signedPrekey)

        var dh1: ByteArray? = null
        var dh2: ByteArray? = null
        var dh3: ByteArray? = null
        var dh4: ByteArray? = null
        var usedOpkId: Int? = null
        var dhMaterial: ByteArray? = null
        var sessionKey: ByteArray? = null
        var rootKey0: ByteArray? = null
        var dhR: ByteArray? = null

        try {
            dh1 = ecdhWithKeystore(spkRecipient)
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

            dhMaterial = if (dh4 != null) dh1!! + dh2!! + dh3!! + dh4!! else dh1!! + dh2!! + dh3!!
            // Соль = байты эфемерного публичного ключа — привязывает PRK к этой сессии
            sessionKey = hkdf(dhMaterial, "BeaconX3DH".toByteArray(), 64, salt = ephemeralKp.public.encoded)

            // ── v3: DH Ratchet инициализация (Alice) ────────────────────────────
            // SK[0:32] как начальный rootKey.
            // Alice делает первый DH-шаг: ECDH(ratchetKP.priv, Bob.SPK) → KDF_RK → sendChainKey.
            // Bob при receiveSession() вычисляет тот же DH симметрично → его recvChainKey == наш sendChainKey.
            rootKey0 = sessionKey.copyOfRange(0, 32)
            val recvChainKey = sessionKey.copyOfRange(32, 64)  // резерв; заменится на первом DH-шаге receive
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
                recvRatchetPub  = spkRecipient.encoded  // Bob's SPK — начальный recv ratchet pub
            )
            sessions[contactId] = state
            saveSession(state)

            val x3dhHeader = JSONObject().apply {
                put("ephemeral_key", ephemeralPublicB64)
                put("spk_id", recipientBundle.spkId)
                if (usedOpkId != null) put("opk_id", usedOpkId)
                put("session_id", sessionId)
                put("dh_ratchet_pub", Base64.encodeToString(ratchetKP.public.encoded, Base64.NO_WRAP))
            }

            return Pair(state, x3dhHeader)
        } finally {
            dh1?.let { SecureMemory.wipe(it) }
            dh2?.let { SecureMemory.wipe(it) }
            dh3?.let { SecureMemory.wipe(it) }
            dh4?.let { SecureMemory.wipe(it) }
            dhMaterial?.let { SecureMemory.wipe(it) }
            sessionKey?.let { SecureMemory.wipe(it) }
            rootKey0?.let { SecureMemory.wipe(it) }
            dhR?.let { SecureMemory.wipe(it) }
        }
    }

    // ─── X3DH — получатель ───────────────────────────────────────────────────

    fun receiveSession(
        contactId: String,
        senderIdentityKey: String,
        x3dhHeader: JSONObject
    ): SessionState {

        val ephemeralPublicB64 = x3dhHeader.getString("ephemeral_key")
        val spkId = x3dhHeader.getInt("spk_id")
        val opkId = if (x3dhHeader.has("opk_id")) x3dhHeader.getInt("opk_id") else null
        val sessionId = x3dhHeader.getString("session_id")

        val spk: KeyPair = when {
            spkId == currentSpkId -> currentSpk ?: throw IllegalStateException("SPK не найден")
            spkId == previousSpkId && previousSpk != null -> {
                if (System.currentTimeMillis() - previousSpkCreatedAt > SPK_GRACE_PERIOD_MS)
                    throw SecurityException("Предыдущий SPK id=$spkId истёк (grace period превышен)")
                Log.d(TAG, "Сессия использует предыдущий SPK id=$spkId — в пределах grace period")
                previousSpk!!
            }
            else -> throw SecurityException("Неверный spk_id=$spkId, текущий=$currentSpkId")
        }
        val ikSender = loadPublicKey(senderIdentityKey)
        val ephemeralPublic = loadPublicKey(ephemeralPublicB64)

        var dh1: ByteArray? = null
        var dh2: ByteArray? = null
        var dh3: ByteArray? = null
        var dh4: ByteArray? = null
        var dhMaterial: ByteArray? = null
        var sessionKey: ByteArray? = null
        var rootKey0: ByteArray? = null
        var dhOut1: ByteArray? = null
        var rootKey1: ByteArray? = null
        var dhOut2: ByteArray? = null

        try {
            dh1 = ecdh(spk.private, ikSender)
            dh2 = ecdhWithKeystore(ephemeralPublic)
            dh3 = ecdh(spk.private, ephemeralPublic)

            if (opkId != null) {
                val opkKp = consumeOpk(opkId)
                    ?: throw SecurityException("OPK $opkId уже использован или не существует")
                dh4 = ecdh(opkKp.private, ephemeralPublic)
            }

            dhMaterial = if (dh4 != null) dh1!! + dh2!! + dh3!! + dh4!! else dh1!! + dh2!! + dh3!!
            // Соль = байты эфемерного публичного ключа — та же соль что использовал отправитель
            sessionKey = hkdf(dhMaterial, "BeaconX3DH".toByteArray(), 64, salt = ephemeralPublic.encoded)

            val now = System.currentTimeMillis()

            // ── v3: DH Ratchet инициализация (Bob) ──────────────────────────────
            // Если x3dhHeader содержит "dh_ratchet_pub" — Alice поддерживает v3.
            // Bob симметрично вычисляет то же ECDH что Alice и сразу инициализирует обе цепочки.
            val aliceRatchetPubB64 = if (x3dhHeader.has("dh_ratchet_pub"))
                x3dhHeader.getString("dh_ratchet_pub") else null

            val state: SessionState
            if (aliceRatchetPubB64 != null) {
                val aliceRatchetPub = loadPublicKey(aliceRatchetPubB64)
                rootKey0 = sessionKey.copyOfRange(0, 32)

                // Шаг 1: ECDH(Bob.SPK.priv, Alice.ratchetPub) == ECDH(Alice.ratchetPriv, Bob.SPK)
                // → Bob.recvChainKey == Alice.sendChainKey (симметрия ECDH гарантирует корректность)
                dhOut1 = ecdh(spk.private, aliceRatchetPub)
                val (rk1, recvChainKey) = kdfRk(rootKey0, dhOut1)
                rootKey1 = rk1

                // Шаг 2: Bob генерирует свою ratchet-пару → sendChainKey
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
                // v2: симметричный ratchet (старые клиенты)
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
            dhMaterial?.let { SecureMemory.wipe(it) }
            sessionKey?.let { SecureMemory.wipe(it) }
            rootKey0?.let { SecureMemory.wipe(it) }
            dhOut1?.let { SecureMemory.wipe(it) }
            rootKey1?.let { SecureMemory.wipe(it) }
            dhOut2?.let { SecureMemory.wipe(it) }
        }
    }

    // ─── Symmetric Ratchet ───────────────────────────────────────────────────

    fun nextSendKey(contactId: String): SendKeyResult = synchronized(this) {
        val state = sessions[contactId]
            ?: throw IllegalStateException("Нет сессии с $contactId. Нужен X3DH.")

        if (needsRatchetRotation(state)) {
            throw SessionRotationRequired(contactId)
        }

        val messageKey = ratchetStep(state.sendChainKey)
        val nextChainKey = ratchetAdvance(state.sendChainKey)
        val counter = state.sendCounter

        val newState = state.copy(
            sendChainKey  = nextChainKey,
            sendCounter   = counter + 1,
            lastRatchetAt = System.currentTimeMillis()
        )
        sessions[contactId] = newState
        SecureMemory.wipe(state.sendChainKey)
        saveSession(newState)

        // v3: включаем текущий ratchet public key в результат
        val dhPub = if (isDHRatchetActive(state))
            Base64.encodeToString(state.sendRatchetPub, Base64.NO_WRAP) else null
        return SendKeyResult(messageKey, counter, state.sessionId, dhPub)
    }

    /**
     * Получить MessageKey для входящего сообщения.
     *
     * [dhKeyB64] — DH ratchet public key из session_header.dh (null для v2-сессий).
     *
     * Логика:
     * 1. TTL-очистка просроченных skipped keys
     * 2. Если v3 и пришёл новый DH-ключ → DH Ratchet Step (новые chain keys, счётчики → 0)
     * 3. counter в skippedKeys → пакет пришёл с опозданием, ключ уже сохранён
     * 4. counter > recvCounter → gap, вычисляем пропущенные ключи
     * 5. counter == recvCounter → нормальный порядок
     */
    fun nextRecvKey(contactId: String, expectedCounter: Int, dhKeyB64: String? = null): ByteArray = synchronized(this) {
        var state = sessions[contactId]
            ?: throw IllegalStateException("Нет сессии с $contactId")

        // ── TTL-очистка просроченных пропущенных ключей ──────────────────────
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

        // ── Определяем DH-эпоху и нужен ли DH-шаг ───────────────────────────
        val inDHRatchet = dhKeyB64 != null && isDHRatchetActive(state)
        val currentDhPubB64 = state.recvRatchetPub?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
        val isDHStep = inDHRatchet && dhKeyB64 != currentDhPubB64

        // Prefix для ключей в skippedKeys:
        // v2: "" → ключ = "$counter"
        // v3 та же эпоха: "$dhKeyB64:" → ключ = "$dhKeyB64:$counter"
        // v3 новая эпоха (заполнение gap из старой): "$currentDhPubB64:"
        val epochPrefix = when {
            !inDHRatchet      -> ""
            !isDHStep         -> "$dhKeyB64:"
            else              -> if (currentDhPubB64 != null) "$currentDhPubB64:" else ""
        }
        val lookupKey = "$epochPrefix$expectedCounter"

        // ── Случай 1: ключ уже в буфере пропущенных ─────────────────────────
        state.skippedKeys[lookupKey]?.let { skippedKey ->
            val newSkipped = state.skippedKeys.toMutableMap().also { it.remove(lookupKey) }
            val newTs = state.skippedKeyTimestamps.toMutableMap().also { it.remove(lookupKey) }
            val updated = state.copy(skippedKeys = newSkipped, skippedKeyTimestamps = newTs)
            sessions[contactId] = updated
            saveSession(updated)
            Log.d(TAG, "Использован пропущенный ключ $lookupKey")
            return skippedKey
        }

        // ── Случай 2: gap — counter > recvCounter ────────────────────────────
        if (expectedCounter > state.recvCounter) {
            val gap = expectedCounter - state.recvCounter
            // Проверяем суммарный размер ДО заполнения, чтобы атакующий не мог
            // раздуть буфер накопленными старыми ключами + большим gap.
            if (gap > MAX_SKIPPED_KEYS || state.skippedKeys.size + gap > MAX_SKIPPED_KEYS) {
                throw SecurityException("Слишком большой разрыв счётчика: gap=$gap, лимит=$MAX_SKIPPED_KEYS")
            }

            var chainKey = state.recvChainKey.copyOf()
            val newSkipped = state.skippedKeys.toMutableMap()
            val newTs = state.skippedKeyTimestamps.toMutableMap()
            val skipTs = System.currentTimeMillis()

            // Заполняем gap ключами из ТЕКУЩЕЙ эпохи (до DH-шага)
            for (i in state.recvCounter until expectedCounter) {
                newSkipped["$epochPrefix$i"] = ratchetStep(chainKey)
                newTs["$epochPrefix$i"] = skipTs
                val next = ratchetAdvance(chainKey)
                SecureMemory.wipe(chainKey)
                chainKey = next
            }

            // Вытесняем по времени добавления (LRU) — не по строковому ключу
            if (newSkipped.size > MAX_SKIPPED_KEYS) {
                val toEvict = newSkipped.keys
                    .sortedBy { k -> newTs[k] ?: 0L }
                    .take(newSkipped.size - MAX_SKIPPED_KEYS)
                toEvict.forEach { k ->
                    newSkipped[k]?.let { SecureMemory.wipe(it) }
                    newSkipped.remove(k); newTs.remove(k)
                }
                Log.w(TAG, "Буфер пропущенных ключей переполнен — вытеснено ${toEvict.size} старых")
            }

            if (isDHStep) {
                // Применяем DH-шаг ПОСЛЕ заполнения gap из старой эпохи.
                // Сначала сохраняем промежуточное состояние с заполненным gap.
                val preStep = state.copy(
                    recvChainKey = chainKey,
                    recvCounter  = expectedCounter,
                    skippedKeys  = newSkipped,
                    skippedKeyTimestamps = newTs
                )
                SecureMemory.wipe(state.recvChainKey)
                state = performDHRatchetStep(preStep, dhKeyB64!!)
                SecureMemory.wipe(chainKey)  // preStep.recvChainKey == chainKey — вайпим после DH-шага
                sessions[contactId] = state
                // После DH-шага счётчики сброшены в 0; берём ключ с позиции 0 новой цепочки
                val messageKey  = ratchetStep(state.recvChainKey)
                val nextChainKey = ratchetAdvance(state.recvChainKey)
                SecureMemory.wipe(state.recvChainKey)
                val newState = state.copy(recvChainKey = nextChainKey, recvCounter = 1)
                sessions[contactId] = newState
                saveSession(newState)
                return messageKey
            }

            // Нет DH-шага — обычный gap в той же эпохе
            val messageKey   = ratchetStep(chainKey)
            val nextChainKey = ratchetAdvance(chainKey)
            SecureMemory.wipe(chainKey)
            SecureMemory.wipe(state.recvChainKey)

            val newState2 = state.copy(
                recvChainKey = nextChainKey,
                recvCounter  = expectedCounter + 1,
                skippedKeys  = newSkipped,
                skippedKeyTimestamps = newTs
            )
            sessions[contactId] = newState2
            saveSession(newState2)
            return messageKey
        }

        // ── Случай 3: нормальный порядок ────────────────────────────────────
        if (isDHStep) {
            // Нормальный порядок, но новый DH-ключ → DH-шаг перед симметричным
            val oldRecvCK = state.recvChainKey
            state = performDHRatchetStep(state, dhKeyB64!!)
            SecureMemory.wipe(oldRecvCK)
            sessions[contactId] = state
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
        // v3-сессии: DH ratchet обеспечивает break-in recovery на каждом обмене,
        // периодический X3DH re-keying не требуется.
        if (isDHRatchetActive(state)) return false
        val now = System.currentTimeMillis()
        return state.sendCounter >= RATCHET_ROTATION_THRESHOLD ||
                (now - state.lastRatchetAt) >= RATCHET_ROTATION_TIME_MS
    }

    fun hasSession(contactId: String): Boolean = sessions.containsKey(contactId)

    fun deleteSession(contactId: String) {
        val state = sessions.remove(contactId)
        state?.let {
            SecureMemory.wipe(it.sendChainKey)
            SecureMemory.wipe(it.recvChainKey)
            it.skippedKeys.values.forEach { k -> SecureMemory.wipe(k) }
            // v3: обнуляем DH ratchet ключи
            if (isDHRatchetActive(it)) {
                SecureMemory.wipe(it.rootKey)
                SecureMemory.wipe(it.sendRatchetPriv)
                SecureMemory.wipe(it.sendRatchetPub)
                it.recvRatchetPub?.let { pub -> SecureMemory.wipe(pub) }
            }
        }
        removeSessionFromStorage(contactId)
    }

    fun deleteAllSessions() {
        sessions.values.forEach {
            SecureMemory.wipe(it.sendChainKey)
            SecureMemory.wipe(it.recvChainKey)
            it.skippedKeys.values.forEach { k -> SecureMemory.wipe(k) }
            // v3: обнуляем DH ratchet ключи
            if (isDHRatchetActive(it)) {
                SecureMemory.wipe(it.rootKey)
                SecureMemory.wipe(it.sendRatchetPriv)
                SecureMemory.wipe(it.sendRatchetPub)
                it.recvRatchetPub?.let { pub -> SecureMemory.wipe(pub) }
            }
        }
        sessions.clear()
        opkPool.clear()
        currentSpk = null
        // Удаляем все персистированные сессии из хранилища
        appContext?.let { ctx ->
            try {
                val encPrefs = EncryptedStorage.getEncryptedPrefs(ctx, "${PREFS_NAME}_sessions")
                val editor = encPrefs.edit()
                encPrefs.all.keys.filter { it.startsWith("session_") }.forEach { editor.remove(it) }
                editor.apply()
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка очистки сессий в хранилище: ${e.message}")
            }
        }
    }

    // ─── Шифрование/расшифровка ───────────────────────────────────────────────

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
            return Pair(Base64.encodeToString(encrypted, Base64.NO_WRAP), header)
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
            val cipherBytes = Base64.decode(ciphertextB64, Base64.NO_WRAP)
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

    // ─── AES-GCM ─────────────────────────────────────────────────────────────

    private fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = javax.crypto.spec.SecretKeySpec(key, 0, 32, "AES")
        // Явная генерация IV через SecureRandom — не полагаемся на провайдер по умолчанию
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
        cipher.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            secretKey,
            javax.crypto.spec.GCMParameterSpec(128, iv)
        )
        return cipher.doFinal(ciphertext)
    }

    // ─── HKDF (RFC 5869) ─────────────────────────────────────────────────────
    // salt по умолчанию = нули (RFC допускает), но для X3DH передаём эфемерный публичный ключ —
    // это привязывает PRK к конкретной сессии и устраняет нулевую соль.

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

    // ─── DH Ratchet — вспомогательные ────────────────────────────────────────

    private fun isDHRatchetActive(state: SessionState) =
        state.rootKey.isNotEmpty() && state.sendRatchetPriv.isNotEmpty()

    // KDF_RK(rootKey, dhOutput) → (newRootKey, chainKey)
    // HKDF с rootKey как солью, DH output как IKM, "BeaconDHRatchet" как info.
    private fun kdfRk(rootKey: ByteArray, dhOutput: ByteArray): Pair<ByteArray, ByteArray> {
        val out = hkdf(dhOutput, "BeaconDHRatchet".toByteArray(), 64, salt = rootKey)
        val newRoot  = out.copyOfRange(0, 32)
        val chainKey = out.copyOfRange(32, 64)
        SecureMemory.wipe(out)
        return Pair(newRoot, chainKey)
    }

    // DH Ratchet Step: вызывается когда получен новый DH-ключ от собеседника.
    // 1. ECDH(наш старый ratchet priv, новый pub) → обновляем rootKey + recvChainKey
    // 2. Генерируем новую ratchet-пару
    // 3. ECDH(новый priv, тот же новый pub) → обновляем rootKey + sendChainKey
    // Счётчики сбрасываются в 0 (новая DH-эпоха).
    private fun performDHRatchetStep(state: SessionState, newDhPubB64: String): SessionState {
        val newDhPub = loadPublicKey(newDhPubB64)  // validateECPoint() включён в loadPublicKey
        val privKey = KeyFactory.getInstance("EC")
            .generatePrivate(PKCS8EncodedKeySpec(state.sendRatchetPriv))

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

    // ─── Вспомогательные ─────────────────────────────────────────────────────

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

    private fun ecdhWithKeystore(peerPublicKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(CryptoManager.getPrivateKeyPublic())
        ka.doPhase(peerPublicKey, true)
        return ka.generateSecret()
    }

    private fun loadPublicKey(keyString: String): PublicKey {
        // Delegates to CryptoManager which calls validateECPoint() — prevents Invalid Curve Attack
        return CryptoManager.loadPublicKey(keyString)
    }

    // ─── Персистентность сессий ───────────────────────────────────────────────

    private fun saveSession(state: SessionState) {
        val ctx = appContext ?: return
        try {
            val skippedKeysJson = JSONObject()
            state.skippedKeys.forEach { (k, v) ->
                skippedKeysJson.put(k.toString(), Base64.encodeToString(v, Base64.NO_WRAP))
            }
            val skippedTsJson = JSONObject()
            state.skippedKeyTimestamps.forEach { (k, v) -> skippedTsJson.put(k.toString(), v) }

            val json = JSONObject().apply {
                put("contactId",    state.contactId)
                put("sendChainKey", Base64.encodeToString(state.sendChainKey, Base64.NO_WRAP))
                put("recvChainKey", Base64.encodeToString(state.recvChainKey, Base64.NO_WRAP))
                put("sendCounter",  state.sendCounter)
                put("recvCounter",  state.recvCounter)
                put("sessionId",    state.sessionId)
                put("createdAt",    state.createdAt)
                put("lastRatchetAt",state.lastRatchetAt)
                put("skippedKeys",  skippedKeysJson)
                put("skippedKeyTimestamps", skippedTsJson)
                // ── DH Ratchet v3 ──────────────────────────────────────────
                if (isDHRatchetActive(state)) {
                    put("rootKey",         Base64.encodeToString(state.rootKey,         Base64.NO_WRAP))
                    put("sendRatchetPriv", Base64.encodeToString(state.sendRatchetPriv, Base64.NO_WRAP))
                    put("sendRatchetPub",  Base64.encodeToString(state.sendRatchetPub,  Base64.NO_WRAP))
                    state.recvRatchetPub?.let { put("recvRatchetPub", Base64.encodeToString(it, Base64.NO_WRAP)) }
                }
            }
            EncryptedStorage.getEncryptedPrefs(ctx, "${PREFS_NAME}_sessions")
                .edit().putString("session_${state.contactId}", json.toString()).apply()
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка сохранения сессии: ${e.message}")
        }
    }

    private fun loadAllSessions() {
        val ctx = appContext ?: return
        try {
            val encPrefs = EncryptedStorage.getEncryptedPrefs(ctx, "${PREFS_NAME}_sessions")
            for ((key, raw) in encPrefs.all) {
                if (!key.startsWith("session_")) continue
                val jsonStr = raw as? String ?: continue
                try {
                    val json = JSONObject(jsonStr)

                    // skippedKeys: Map<String, ByteArray>
                    // Миграция v2: ключи были Int ("5"), теперь String ("5" или "dhPub:5").
                    // JSON хранит числа как строки, поэтому k уже строка — всё совместимо.
                    val skJson = json.optJSONObject("skippedKeys") ?: JSONObject()
                    val skippedKeys = mutableMapOf<String, ByteArray>()
                    skJson.keys().forEach { k ->
                        skippedKeys[k] = Base64.decode(skJson.getString(k), Base64.NO_WRAP)
                    }
                    val tsJson = json.optJSONObject("skippedKeyTimestamps") ?: JSONObject()
                    val skippedTs = mutableMapOf<String, Long>()
                    tsJson.keys().forEach { k -> skippedTs[k] = tsJson.getLong(k) }

                    // ── DH Ratchet v3 (опционально — отсутствуют в v2-сессиях) ──
                    val rootKey = if (json.has("rootKey"))
                        Base64.decode(json.getString("rootKey"), Base64.NO_WRAP) else ByteArray(0)
                    val sendRatchetPriv = if (json.has("sendRatchetPriv"))
                        Base64.decode(json.getString("sendRatchetPriv"), Base64.NO_WRAP) else ByteArray(0)
                    val sendRatchetPub = if (json.has("sendRatchetPub"))
                        Base64.decode(json.getString("sendRatchetPub"), Base64.NO_WRAP) else ByteArray(0)
                    val recvRatchetPub = if (json.has("recvRatchetPub"))
                        Base64.decode(json.getString("recvRatchetPub"), Base64.NO_WRAP) else null

                    sessions[json.getString("contactId")] = SessionState(
                        contactId    = json.getString("contactId"),
                        sendChainKey = Base64.decode(json.getString("sendChainKey"), Base64.NO_WRAP),
                        recvChainKey = Base64.decode(json.getString("recvChainKey"), Base64.NO_WRAP),
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
                        recvRatchetPub  = recvRatchetPub
                    )
                } catch (e: Exception) {
                    Log.w(TAG, "Не удалось восстановить сессию $key: ${e.message}")
                }
            }
            Log.d(TAG, "Сессии восстановлены из хранилища: ${sessions.size}")
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка загрузки сессий: ${e.message}")
        }
    }

    private fun removeSessionFromStorage(contactId: String) {
        val ctx = appContext ?: return
        try {
            EncryptedStorage.getEncryptedPrefs(ctx, "${PREFS_NAME}_sessions")
                .edit().remove("session_$contactId").apply()
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка удаления сессии из хранилища: ${e.message}")
        }
    }

    // ─── Исключения ──────────────────────────────────────────────────────────

    class SessionRotationRequired(val contactId: String) :
        Exception("Сессия с $contactId требует ротации (достигнут лимит ratchet)")
}
