package com.bcon.messenger

import android.content.Context

object ServerManager {

    private const val PREFS_NAME = "server_prefs"
    private const val KEY_SERVERS = "server_list"
    private const val KEY_CURRENT = "current_server"
    private const val KEY_DISCOVERED_PEERS = "discovered_peers"
    private const val KEY_FIXED_MODE = "fixed_server_mode"

    data class Server(
        val host: String,
        val port: Int = 9000,
        val name: String = "",
        val enabled: Boolean = true,
        val path: String = ""
    ) {
        fun toWssUrl(): String {
            // Если хост уже содержит протокол — разобрать через Uri и пересобрать правильно
            if (host.contains("://")) {
                return try {
                    val uri = android.net.Uri.parse(host)
                    val h = uri.host?.takeIf { it.isNotEmpty() } ?: host
                    val p = if (uri.port != -1) uri.port else port
                    val rawPath = uri.path?.trim('/') ?: ""
                    val finalPath = rawPath.ifEmpty { path }
                    val scheme = if (uri.scheme == "ws") "ws" else "wss"
                    if (finalPath.isNotEmpty()) "$scheme://$h:$p/$finalPath"
                    else "$scheme://$h:$p"
                } catch (e: Exception) {
                    host
                }
            }
            val suffix = if (path.isNotEmpty()) "/$path" else ""
            // Локальный сервер — без TLS
            if (host == "10.0.2.2" ||
                host == "localhost" ||
                host == "127.0.0.1" ||
                host.startsWith("192.168.") ||
                host.startsWith("10.0.") ||
                host.startsWith("172.16.") ||
                host.matches(Regex("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*"))) {
                return "ws://$host:$port$suffix"
            }
            // Продакшн — TLS
            return if (port == 9000) "wss://$host$suffix" else "wss://$host:$port$suffix"
        }
    }

    fun getServers(context: Context): List<Server> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val json = prefs.getString(KEY_SERVERS, null) ?: return getDefaultServers()
        return try {
            val array = org.json.JSONArray(json)
            val servers = (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                Server(
                    host    = obj.getString("host"),
                    port    = obj.optInt("port", 443),
                    name    = obj.optString("name", ""),
                    enabled = obj.optBoolean("enabled", true),
                    path    = obj.optString("path", "")
                )
            }
            // Миграция: заменяем устаревший адрес сервера на актуальный
            val defaults = getDefaultServers()
            var migrated = servers.map { s ->
                if (s.host == "beacon-app.org") defaults.first() else s
            }.toMutableList()
            // Добавляем onion-сервер если его ещё нет
            val onionServer = defaults[1]
            if (migrated.none { it.host == onionServer.host }) {
                migrated.add(onionServer)
            }
            if (migrated != servers) saveServers(context, migrated)
            migrated
        } catch (e: Exception) {
            getDefaultServers()
        }
    }

    fun saveServers(context: Context, servers: List<Server>) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val array = org.json.JSONArray()
        servers.forEach { server ->
            array.put(org.json.JSONObject().apply {
                put("host", server.host)
                put("port", server.port)
                put("name", server.name)
                put("enabled", server.enabled)
                put("path", server.path)
            })
        }
        prefs.edit().putString(KEY_SERVERS, array.toString()).apply()
    }

    fun isFixedMode(context: Context): Boolean =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME).getBoolean(KEY_FIXED_MODE, false)

    fun setFixedMode(context: Context, fixed: Boolean) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME).edit()
            .putBoolean(KEY_FIXED_MODE, fixed)
            .putInt(KEY_CURRENT, 0)
            .apply()
    }

    fun getCurrentServer(context: Context): Server? {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val servers = if (isFixedMode(context)) {
            getServers(context).filter { it.enabled }
        } else {
            getAllKnownServers(context).filter { it.enabled }
        }
        val index = prefs.getInt(KEY_CURRENT, 0)
        return servers.getOrNull(index)
    }

    fun switchToNext(context: Context): Server? {
        if (isFixedMode(context)) return getCurrentServer(context)
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val servers = getAllKnownServers(context).filter { it.enabled }
        if (servers.isEmpty()) return null
        val current = prefs.getInt(KEY_CURRENT, 0)
        val next = (current + 1) % servers.size
        prefs.edit().putInt(KEY_CURRENT, next).apply()
        return servers[next]
    }

    private fun getDefaultServers() = listOf(
        Server("api.beacon-app.org", 443, "Основной сервер", true, "ws"),
        Server("ws://amqvpheooju3fg7tafxkmf73c3vg4xg7nycelepiie6jdjzbsqrvrcqd.onion", 80, "Onion (Tor)", true, "")
    )

    fun addServer(context: Context, server: Server) {
        val servers = getServers(context).toMutableList()
        servers.add(server)
        saveServers(context, servers)
    }

    fun removeServer(context: Context, index: Int) {
        val servers = getServers(context).toMutableList()
        if (index in servers.indices) {
            servers.removeAt(index)
            saveServers(context, servers)
        }
    }

    // ─── Меш-пиры (динамически полученные от серверов) ────────────────────────

    /** Серверы, присланные через server_peers (кешируются между сессиями). */
    fun getDiscoveredPeers(context: Context): List<Server> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val json = prefs.getString(KEY_DISCOVERED_PEERS, null) ?: return emptyList()
        return try {
            val array = org.json.JSONArray(json)
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                Server(
                    host    = obj.getString("host"),
                    port    = obj.optInt("port", 443),
                    name    = obj.optString("name", ""),
                    enabled = obj.optBoolean("enabled", true),
                    path    = obj.optString("path", "")
                )
            }
        } catch (e: Exception) { emptyList() }
    }

    private fun saveDiscoveredPeers(context: Context, peers: List<Server>) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val array = org.json.JSONArray()
        peers.forEach { s ->
            array.put(org.json.JSONObject().apply {
                put("host", s.host)
                put("port", s.port)
                put("name", s.name)
                put("enabled", s.enabled)
                put("path", s.path)
            })
        }
        prefs.edit().putString(KEY_DISCOVERED_PEERS, array.toString()).apply()
    }

    /** Добавляет пир из полного URL (wss://host:port/path). Дубликаты игнорируются. */
    fun addDiscoveredPeer(context: Context, url: String) {
        val server = serverFromUrl(url) ?: return
        val peers = getDiscoveredPeers(context).toMutableList()
        val key = "${server.host}:${server.port}/${server.path}"
        if (peers.none { "${it.host}:${it.port}/${it.path}" == key }) {
            peers.add(server)
            saveDiscoveredPeers(context, peers)
        }
    }

    /**
     * Все известные серверы: ручные (getServers) + меш-пиры (getDiscoveredPeers).
     * Пиры уже присутствующие в ручном списке не дублируются.
     */
    fun getAllKnownServers(context: Context): List<Server> {
        val manual = getServers(context)
        val discovered = getDiscoveredPeers(context)
        val manualKeys = manual.map { "${it.host}:${it.port}/${it.path}" }.toSet()
        val newPeers = discovered.filter { "${it.host}:${it.port}/${it.path}" !in manualKeys }
        return manual + newPeers
    }

    private fun serverFromUrl(url: String): Server? {
        return try {
            val uri = android.net.Uri.parse(url)
            val host = uri.host?.takeIf { it.isNotEmpty() } ?: return null
            val port = if (uri.port != -1) uri.port else 443
            val path = uri.path?.trim('/') ?: ""
            // Сохраняем полный URL как host — toWssUrl() увидит "://" и правильно
            // сохранит схему (ws:// для домашних серверов без TLS).
            Server(host = url, port = port, name = "$host (peer)", enabled = true, path = path)
        } catch (e: Exception) { null }
    }
}
