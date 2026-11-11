package com.subrosa.desktop

// Package move in BouncyCastle 1.86 -- see the matching note in Android's
// PqCrypto.kt. Class names unchanged, wire format unchanged (verified across
// versions in both directions before upgrading), so this is an import rewrite.
// Both clients must move together: they speak the same handshake.
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import java.security.SecureRandom

/**
 * ML-KEM (FIPS 203, NIST-standardized post-quantum KEM) wrapper used to
 * hybridize the classical ECDH-based X3DH handshake and the legacy
 * ephemeral-ECDH paths against "harvest now, decrypt later" — an adversary
 * recording today's traffic could decrypt it retroactively with a future
 * quantum computer. ML-KEM-768 is used (comparable classical-strength
 * margin to the existing P-256 curve).
 *
 * The shared secret produced here is always combined with (never replaces)
 * the classical ECDH shared secret before being fed into HKDF — see
 * SessionKeyManager.kt / CryptoManager.kt. Breaking ML-KEM alone is not
 * enough to recover the session key; the classical component must also be
 * broken (and vice versa).
 */
object PqCrypto {

    private val PARAMS = MLKEMParameters.ml_kem_768
    private val rng = SecureRandom()

    data class PqKeyPair(val publicKey: ByteArray, val privateKey: ByteArray)
    data class Encapsulated(val ciphertext: ByteArray, val sharedSecret: ByteArray)

    fun generateKeyPair(): PqKeyPair {
        val generator = MLKEMKeyPairGenerator()
        generator.init(MLKEMKeyGenerationParameters(rng, PARAMS))
        val kp = generator.generateKeyPair()
        val pub = (kp.public as MLKEMPublicKeyParameters).encoded
        val priv = (kp.private as MLKEMPrivateKeyParameters).encoded
        return PqKeyPair(pub, priv)
    }

    /** Sender side: derives a fresh shared secret and the ciphertext to send alongside it. */
    fun encapsulate(publicKeyBytes: ByteArray): Encapsulated {
        val publicKey = MLKEMPublicKeyParameters(PARAMS, publicKeyBytes)
        val generator = MLKEMGenerator(rng)
        val result = generator.generateEncapsulated(publicKey)
        return Encapsulated(result.encapsulation, result.secret)
    }

    /** Receiver side: recovers the same shared secret from the received ciphertext. */
    fun decapsulate(privateKeyBytes: ByteArray, ciphertext: ByteArray): ByteArray {
        val privateKey = MLKEMPrivateKeyParameters(PARAMS, privateKeyBytes)
        val extractor = MLKEMExtractor(privateKey)
        return extractor.extractSecret(ciphertext)
    }
}
