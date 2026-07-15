package com.bcon.messenger

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import java.security.KeyStore

object IntrusionDetector {

    enum class ThreatType(val label: String) {
        PROXY("Прокси/MITM"),
        USER_CA("Пользовательский CA-сертификат"),
        VPN("VPN-соединение"),
        ADB("ADB включён"),
        DEV_OPTIONS("Режим разработчика")
    }

    data class ScanResult(
        val threats: List<ThreatType>,
        val ts: Long = System.currentTimeMillis()
    ) {

        fun isCritical() = threats.containsAll(listOf(ThreatType.PROXY, ThreatType.USER_CA))
        fun isEmpty() = threats.isEmpty()
    }

    fun scan(context: Context): ScanResult {
        val threats = mutableListOf<ThreatType>()
        if (isProxyConfigured()) threats += ThreatType.PROXY
        if (hasUserCACerts()) threats += ThreatType.USER_CA
        if (isVPNActive(context)) threats += ThreatType.VPN
        if (isADBEnabled(context)) threats += ThreatType.ADB
        if (isDeveloperOptionsEnabled(context)) threats += ThreatType.DEV_OPTIONS
        return ScanResult(threats)
    }

    private fun isProxyConfigured(): Boolean {
        val host = System.getProperty("http.proxyHost")
        return !host.isNullOrBlank() && host != "null"
    }

    private fun hasUserCACerts(): Boolean {
        return try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                if (aliases.nextElement().startsWith("user:")) return true
            }
            false
        } catch (_: Exception) { false }
    }

    private fun isVPNActive(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(ConnectivityManager::class.java)
            cm.allNetworks.any {
                cm.getNetworkCapabilities(it)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
        } catch (_: Exception) { false }
    }

    private fun isADBEnabled(context: Context): Boolean =
        Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0

    private fun isDeveloperOptionsEnabled(context: Context): Boolean =
        Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0
        ) != 0
}
