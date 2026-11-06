package com.subrosa.messenger

import android.content.Context
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
object SenderCertManager {

    private const val TAG = "SenderCertManager"

    private const val PREFS_NAME     = "sender_cert"
    private const val PREF_CERT      = "cert_json"
    private const val PREF_SIGNATURE = "signature"

    // Refresh well before the server's issuance TTL (24h, SENDER_CERT_TTL_SEC
    // in server.py) so a clock-skewed or briefly-offline device never ends up
    // presenting an already-expired cert to a recipient.
    private const val REFRESH_MARGIN_SEC = 4 * 3600L

    // Pinned per-deployment, same pattern as NetworkConfig.CERT_PINS (which
    // comes from the SUBROSA_CERT_PINS build property; the old, never-called
    // CertificatePinner.kt this comment used to point at has been deleted) —
    // each self-hosted server generates its own signing keypair on first run
    // (server.py's _load_or_create_cert_signing_key()) and prints the public
    // key (base64 SubjectPublicKeyInfo DER) to its startup log. The operator
    // copies that value in here at build time for this deployment's APK,
    // same as the TLS pin. Left as a placeholder until then — see
    // isPinConfigured().
    private const val SERVER_CERT_PUBLIC_KEY_B64 = "PLACEHOLDER_SENDER_CERT_SERVER_PUBLIC_KEY"

    private fun prefs(ctx: Context) = EncryptedStorage.getEncryptedPrefs(ctx, PREFS_NAME)

    fun isPinConfigured(): Boolean = !SERVER_CERT_PUBLIC_KEY_B64.startsWith("PLACEHOLDER")

    fun store(ctx: Context, cert: JSONObject, signature: String) {
        prefs(ctx).edit()
            .putString(PREF_CERT, cert.toString())
            .putString(PREF_SIGNATURE, signature)
            .apply()
    }

    /** Null if never fetched, malformed, or close enough to expiry (within
     *  REFRESH_MARGIN_SEC) that it should be treated as needing a refresh —
     *  not necessarily already expired, just too risky to keep relying on. */
    fun getFresh(ctx: Context): Pair<JSONObject, String>? {
        val p = prefs(ctx)
        val certStr   = p.getString(PREF_CERT, null) ?: return null
        val signature = p.getString(PREF_SIGNATURE, null) ?: return null
        val cert = try { JSONObject(certStr) } catch (e: Exception) { return null }
        val expiresAt = cert.optLong("expires_at", 0L)
        val nowSec = System.currentTimeMillis() / 1000L
        if (expiresAt <= 0L || nowSec > expiresAt - REFRESH_MARGIN_SEC) return null
        return cert to signature
    }

    /** Reconstructs the exact same pipe-delimited canonical string server.py
     *  signs (see request_sender_cert handler) — deliberately not a
     *  re-serialized JSON blob, since byte-exact JSON canonicalization
     *  (sorted keys, separators, float formatting) is a cross-language
     *  footgun between Python's json.dumps and org.json here. */
    private fun canonicalString(cert: JSONObject): String {
        val fingerprint = cert.getString("fingerprint")
        val publicKey    = cert.getString("public_key")
        val issuedAt     = cert.getLong("issued_at")
        val expiresAt    = cert.getLong("expires_at")
        return "$fingerprint|$publicKey|$issuedAt|$expiresAt"
    }

    /** Verifies a cert (someone else's, received inside a sealed envelope)
     *  against the pinned server public key. Returns false — never throws —
     *  on any malformed input, unpinned build, or expired cert; callers
     *  should treat "false" as "don't trust who this claims to be from",
     *  not as a hard error. */
    fun verify(cert: JSONObject, signatureB64: String): Boolean {
        if (!isPinConfigured()) {
            Log.w(TAG, "verify: SERVER_CERT_PUBLIC_KEY_B64 не запиннен (placeholder) — отклоняю")
            return false
        }
        return try {
            val expiresAt = cert.optLong("expires_at", 0L)
            val nowSec = System.currentTimeMillis() / 1000L
            if (expiresAt <= 0L || nowSec > expiresAt) {
                Log.w(TAG, "verify: сертификат просрочен")
                return false
            }
            val keyBytes = Base64.decode(SERVER_CERT_PUBLIC_KEY_B64, Base64.NO_WRAP)
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(keyBytes))
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(publicKey)
            signature.update(canonicalString(cert).toByteArray(Charsets.UTF_8))
            signature.verify(Base64.decode(signatureB64, Base64.NO_WRAP))
        } catch (e: Exception) {
            Log.e(TAG, "verify: ошибка проверки — ${e.message}")
            false
        }
    }

    fun clear(ctx: Context) {
        prefs(ctx).edit().clear().apply()
    }
}
