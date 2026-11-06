package com.subrosa.desktop

import java.net.InetSocketAddress

/**
 * Desktop counterpart of Android's TorManager.
 *
 * Unlike Android (where Orbot can run as a system-wide VPN that transparently
 * intercepts all app traffic, so a plain client sometimes suffices for
 * .onion addresses too — see the comment in WebSocketClient there), a
 * desktop Tor daemon or Tor Browser's bundled tor process is *always* just a
 * local SOCKS5 proxy. There is no VPN-mode ambiguity here: any .onion server
 * URL must always be routed through the explicit SOCKS client, and if the
 * proxy isn't reachable, connecting is pointless (.onion addresses aren't
 * resolvable by normal DNS at all) — fail fast with a clear message rather
 * than let the connection attempt hang or produce a cryptic DNS error.
 *
 * The user is expected to already be running Tor (system tor service, or
 * Tor Browser, which also exposes a local SOCKS proxy) — desktop apps can't
 * launch it the way Android launches Orbot via an intent.
 */
object DesktopTorManager {

    const val SOCKS_HOST = "127.0.0.1"
    /** Standard system tor daemon port. Tor Browser's bundled tor typically uses 9150 instead. */
    const val SOCKS_PORT = 9050
    /** Fallback port used by the Tor Browser bundle when no system tor service is running. */
    const val SOCKS_PORT_TOR_BROWSER = 9150

    /**
     * Probes for a local SOCKS5 proxy on the standard port, then the Tor
     * Browser fallback port. Returns the port to use, or null if neither
     * responds.
     */
    fun detectSocksPort(): Int? {
        for (port in intArrayOf(SOCKS_PORT, SOCKS_PORT_TOR_BROWSER)) {
            try {
                java.net.Socket().use { it.connect(InetSocketAddress(SOCKS_HOST, port), 1000) }
                return port
            } catch (_: Exception) { /* try next */ }
        }
        return null
    }

    fun isAvailable(): Boolean = detectSocksPort() != null
}
