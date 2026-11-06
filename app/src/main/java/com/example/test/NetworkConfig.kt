package com.subrosa.messenger

object NetworkConfig {

    const val SERVER_HOSTNAME = "api.subrosamessenger.com"

    /**
     * SPKI pins for [SERVER_HOSTNAME], injected at build time from the
     * `SUBROSA_CERT_PINS` property — see the pinning block in
     * `app/build.gradle.kts` for how to compute one and why they are not in
     * this repository.
     *
     * Empty is a legitimate value in a debug build (localhost, the emulator
     * host, a test server) and an impossible one in a release build: the
     * Gradle task-graph check fails `assembleRelease` outright rather than let
     * an unpinned release ship.
     *
     * This replaced `const val CERT_PIN = ""`, which left the pinning branch
     * in `MessengerService.buildHttpClient()` permanently unreachable while
     * the surrounding code — and a second, never-called pinning implementation
     * in a file now deleted — read as though pinning were in force. See
     * docs/KNOWN_SECURITY_ISSUES.md, S9-1.
     */
    val CERT_PINS: List<String> =
        BuildConfig.CERT_PINS.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    val isPinningActive: Boolean get() = CERT_PINS.isNotEmpty() && SERVER_HOSTNAME.isNotEmpty()

    const val STUN_URL = "stun:stun.l.google.com:19302"
    const val TURN_URL = "turn:turn.subrosamessenger.com:4433?transport=tcp"

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
