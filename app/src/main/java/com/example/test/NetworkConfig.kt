package com.bcon.messenger

object NetworkConfig {

    const val CERT_PIN = ""

    const val SERVER_HOSTNAME = "api.beacon-app.org"

    const val STUN_URL = "stun:stun.l.google.com:19302"
    const val TURN_URL = "turn:turn.beacon-app.org:4433?transport=tcp"

    object TurnCredentials {
        @Volatile var username: String = ""
        @Volatile var password: String = ""

        fun isAvailable() = username.isNotEmpty() && password.isNotEmpty()

        fun clear() {
            username = ""
            password = ""
        }
    }
}
