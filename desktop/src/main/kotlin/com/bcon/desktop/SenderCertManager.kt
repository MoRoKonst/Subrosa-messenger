package com.subrosa.desktop

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import org.json.JSONObject

/** Desktop counterpart of Android's SenderCertManager.kt — caches the
 *  server-signed "I am fingerprint X" certificate used by Sealed Sender
 *  (see docs/TODO.md, "Крупная архитектурная задача: sealed-sender поверх
 *  token routing"). Requested over the normal, already-authenticated main
 *  socket right after register() — nothing to hide at that step, the
 *  request carries no addressee. The cert itself later gets embedded
 *  inside the sealed envelope (see sealPacketForRecipient()) so only the
 *  recipient (not the server) ever reads it and verifies it against the
 *  server's pinned public key. */
object SenderCertManager {

    private const val TAG = "SenderCertManager"

    private const val PREF_CERT      = "sender_cert_json"
    private const val PREF_SIGNATURE = "sender_cert_signature"

    // Refresh well before the server's issuance TTL (24h, SENDER_CERT_TTL_SEC
    // in server.py) so a clock-skewed or briefly-offline device never ends
    // up presenting an already-expired cert to a recipient.
    private const val REFRESH_MARGIN_SEC = 4 * 3600L

    // Pinned per-deployment, same pattern as Android's SenderCertManager and
    // NetworkConfig.CERT_PIN — each self-hosted server generates its own
    // signing keypair on first run (server.py's _load_or_create_cert_signing_key())
    // and prints the public key to its startup log. The operator copies
    // that value in here at build time for this deployment. Left as a
    // placeholder until then — see isPinConfigured().
    private const val SERVER_CERT_PUBLIC_KEY_B64 = "PLACEHOLDER_SENDER_CERT_SERVER_PUBLIC_KEY"

    fun isPinConfigured(): Boolean = !SERVER_CERT_PUBLIC_KEY_B64.startsWith("PLACEHOLDER")

    fun store(cert: JSONObject, signature: String) {
        DesktopStorage.put(PREF_CERT, cert.toString())
        DesktopStorage.put(PREF_SIGNATURE, signature)
    }

    /** Null if never fetched, malformed, or close enough to expiry (within
     *  REFRESH_MARGIN_SEC) that it should be treated as needing a refresh —
     *  not necessarily already expired, just too risky to keep relying on. */
    fun getFresh(): Pair<JSONObject, String>? {
        val certStr   = DesktopStorage.get(PREF_CERT) ?: return null
        val signature = DesktopStorage.get(PREF_SIGNATURE) ?: return null
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
            println("$TAG: verify: SERVER_CERT_PUBLIC_KEY_B64 not pinned (placeholder) — rejecting")
            return false
        }
        return try {
            val expiresAt = cert.optLong("expires_at", 0L)
            val nowSec = System.currentTimeMillis() / 1000L
            if (expiresAt <= 0L || nowSec > expiresAt) {
                println("$TAG: verify: certificate expired")
                return false
            }
            val keyBytes = Base64.getDecoder().decode(SERVER_CERT_PUBLIC_KEY_B64)
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(keyBytes))
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(publicKey)
            signature.update(canonicalString(cert).toByteArray(Charsets.UTF_8))
            signature.verify(Base64.getDecoder().decode(signatureB64))
        } catch (e: Exception) {
            println("$TAG: verify: verification error — ${e.message}")
            false
        }
    }

    fun clear() {
        DesktopStorage.remove(PREF_CERT)
        DesktopStorage.remove(PREF_SIGNATURE)
    }
}
