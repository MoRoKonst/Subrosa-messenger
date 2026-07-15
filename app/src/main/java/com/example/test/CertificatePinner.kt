package com.bcon.messenger

import java.security.cert.X509Certificate
import javax.net.ssl.*

object CertificatePinner {

    private val TRUSTED_PINS = setOf(
        "lz6oXPzDLTIZzh45LRX1NrORrYQTEOEKtFbOBtSaC0E=",
    )

    fun createPinnedSSLSocketFactory(): SSLSocketFactory {
        val trustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain == null || chain.isEmpty()) {
                    throw java.security.cert.CertificateException("Certificate chain is empty")
                }

                if (TRUSTED_PINS.any { it.startsWith("PLACEHOLDER") }) {
                    android.util.Log.w("CertPinning", "WARNING: Certificate pinning disabled (replace PLACEHOLDER pins before release)")
                    return
                }

                val serverCert = chain[0]
                val publicKey = serverCert.publicKey.encoded
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                val pin = android.util.Base64.encodeToString(
                    digest.digest(publicKey),
                    android.util.Base64.NO_WRAP
                )

                if (!TRUSTED_PINS.contains(pin)) {
                    throw java.security.cert.CertificateException(
                        "Certificate pinning failed! Server pin doesn't match trusted pins."
                    )
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
        return sslContext.socketFactory
    }
}