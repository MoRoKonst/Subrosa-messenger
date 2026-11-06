package com.subrosa.desktop

import org.json.JSONArray
import org.json.JSONObject

/**
 * Desktop port of Android's ServerManager (app/src/main/java/com/example/
 * test/ServerManager.kt) — a saved list of servers instead of the single
 * "server_url"/"server_access_code" pair ServerSettingsDialog used to be
 * limited to. Deliberately narrower than Android: no auto-federation/
 * switch-on-failure (WebSocketClient only ever holds one live connection
 * and retries the SAME url with backoff — see scheduleReconnect()), no
 * QR scan/discovered-peers (no camera-capture flow on desktop). Selecting
 * an entry just writes the same "server_url"/"server_access_code" keys
 * WebSocketClient already reads fresh on every connect() call, so no
 * further wiring is needed there.
 */
object ServerManager {
    private const val KEY_SERVERS = "server_list"
    private const val KEY_CURRENT_INDEX = "server_current_index"

    data class Server(
        val host: String,
        val port: Int = 8443,
        val name: String = "",
        val enabled: Boolean = true,
        val path: String = "",
        val accessCode: String? = null
    ) {
        fun toWssUrl(): String {
            if (host.contains("://")) return host
            val suffix = if (path.isNotEmpty()) "/$path" else ""
            return if (port == 443) "wss://$host$suffix" else "wss://$host:$port$suffix"
        }
    }

    private fun getDefaultServers() = listOf(
        Server("api.subrosamessenger.com", 8443, "Основной сервер", true, "ws"),
        Server("ws://amqvpheooju3fg7tafxkmf73c3vg4xg7nycelepiie6jdjzbsqrvrcqd.onion", 80, "Onion (Tor)", true, "")
    )

    /** First read after this list-based manager replaces the old single-
     *  field ServerSettingsDialog — if that field already holds a custom
     *  (non-default) URL, preserve it as a manual entry instead of silently
     *  reverting an already-configured install back to the main server. */
    private fun migrateLegacySingleServer(): List<Server> {
        val defaults = getDefaultServers()
        val legacyUrl = DesktopStorage.get(KEY_SERVERS_URL_COMPAT)
        val alreadyDefault = legacyUrl == null || defaults.any { it.toWssUrl() == legacyUrl }
        if (alreadyDefault) {
            saveServers(defaults)
            return defaults
        }
        val legacyCode = DesktopStorage.get(KEY_SERVERS_ACCESS_CODE_COMPAT)
        val custom = Server(host = legacyUrl!!, name = "Свой сервер", accessCode = legacyCode)
        val servers = defaults + custom
        saveServers(servers)
        DesktopStorage.putInt(KEY_CURRENT_INDEX, servers.size - 1)
        return servers
    }

    fun getServers(): List<Server> {
        val json = DesktopStorage.get(KEY_SERVERS) ?: return migrateLegacySingleServer()
        return try {
            val array = JSONArray(json)
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                Server(
                    host       = obj.getString("host"),
                    port       = obj.optInt("port", 8443),
                    name       = obj.optString("name", ""),
                    enabled    = obj.optBoolean("enabled", true),
                    path       = obj.optString("path", ""),
                    accessCode = obj.optString("accessCode", null).takeIf { !it.isNullOrBlank() }
                )
            }
        } catch (e: Exception) {
            getDefaultServers()
        }
    }

    fun saveServers(servers: List<Server>) {
        val array = JSONArray()
        servers.forEach { server ->
            array.put(JSONObject().apply {
                put("host", server.host)
                put("port", server.port)
                put("name", server.name)
                put("enabled", server.enabled)
                put("path", server.path)
                if (server.accessCode != null) put("accessCode", server.accessCode)
            })
        }
        DesktopStorage.put(KEY_SERVERS, array.toString())
    }

    fun addServer(server: Server) {
        val servers = getServers().toMutableList()
        servers.add(server)
        saveServers(servers)
    }

    fun removeServer(index: Int) {
        val servers = getServers().toMutableList()
        if (index in servers.indices) {
            servers.removeAt(index)
            saveServers(servers)
        }
    }

    /** Index into getServers() of the currently-selected entry, or 0 if
     *  none has been explicitly picked yet (defaults to the first/main
     *  server, matching WebSocketClient's own NetworkConfig.DEFAULT_WS_URL
     *  fallback). */
    fun getCurrentIndex(): Int = DesktopStorage.getInt(KEY_CURRENT_INDEX, 0)

    /** Selects [index] as active AND writes "server_url"/"server_access_code"
     *  — the keys WebSocketClient.doConnect()/doConnectAnonChannel() already
     *  read fresh on every connect() attempt, same as the old single-field
     *  dialog did. Takes effect on the next connect() call. */
    fun selectServer(index: Int) {
        val servers = getServers()
        val server = servers.getOrNull(index) ?: return
        DesktopStorage.putInt(KEY_CURRENT_INDEX, index)
        DesktopStorage.put(KEY_SERVERS_URL_COMPAT, server.toWssUrl())
        val code = server.accessCode
        if (!code.isNullOrBlank()) DesktopStorage.put(KEY_SERVERS_ACCESS_CODE_COMPAT, code)
        else DesktopStorage.remove(KEY_SERVERS_ACCESS_CODE_COMPAT)
    }

    // Same keys as the pre-existing single-field ServerSettingsDialog / what
    // WebSocketClient reads — kept here as named constants instead of
    // repeating the literal strings at each call site.
    private const val KEY_SERVERS_URL_COMPAT = "server_url"
    private const val KEY_SERVERS_ACCESS_CODE_COMPAT = "server_access_code"
}
