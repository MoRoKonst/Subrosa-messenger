package com.bcon.messenger

import java.security.cert.X509Certificate
import javax.net.ssl.*

object CertificatePinner {

    // SHA-256 SPKI-отпечатки сервера api.beacon-app.org:4430
    // Получены: openssl s_client | openssl x509 -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64
    // ВАЖНО: Let's Encrypt обновляет сертификат каждые 90 дней.
    //        На сервере настроить: certbot renew --reuse-key  — тогда SPKI hash не меняется.
    //        При смене ключа — обновить pin здесь + выпустить обновление приложения.
    private val TRUSTED_PINS = setOf(
        "lz6oXPzDLTIZzh45LRX1NrORrYQTEOEKtFbOBtSaC0E=", // api.beacon-app.org via Cloudflare
    )

    fun createPinnedSSLSocketFactory(): SSLSocketFactory {
        val trustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain == null || chain.isEmpty()) {
                    throw java.security.cert.CertificateException("Certificate chain is empty")
                }

                // Проверяем pinning только для production
                // Dev mode: все пины — заглушки, пинниг пропускается с предупреждением
                if (TRUSTED_PINS.any { it.startsWith("PLACEHOLDER") }) {
                    android.util.Log.w("CertPinning", "WARNING: Certificate pinning disabled (replace PLACEHOLDER pins before release)")
                    return
                }

                // Production - проверяем отпечаток
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