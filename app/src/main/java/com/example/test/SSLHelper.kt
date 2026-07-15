package com.bcon.messenger

object SSLHelper {

    @Deprecated(
        message = "Trust-all SSL УЯЗВИМ к MITM. Используй certificate pinning (NetworkConfig.CERT_PIN).",
        level = DeprecationLevel.ERROR
    )
    @Suppress("DEPRECATION_ERROR")
    fun getTrustAllSocketFactory(): javax.net.ssl.SSLSocketFactory {
        throw UnsupportedOperationException(
            "getTrustAllSocketFactory() отключён: принятие всех сертификатов — УЯЗВИМОСТЬ БЕЗОПАСНОСТИ. " +
            "Используй certificate pinning через NetworkConfig.CERT_PIN."
        )
    }
}
