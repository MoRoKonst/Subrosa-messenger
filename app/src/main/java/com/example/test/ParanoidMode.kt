package com.subrosa.messenger

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object ParanoidMode {

    private val alertScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _enabled = MutableStateFlow(false)
    val flow = _enabled.asStateFlow()
    val isEnabled: Boolean get() = _enabled.value

    private val _stealthMode = MutableStateFlow(false)
    val stealthMode = _stealthMode.asStateFlow()

    private val _panicModeNotif = MutableStateFlow(false)
    val panicModeNotif = _panicModeNotif.asStateFlow()

    fun activateFromNotification() {
        _panicModeNotif.value = true
    }

    private val _lastIdsResult = MutableStateFlow<IntrusionDetector.ScanResult?>(null)
    val lastIdsResult = _lastIdsResult.asStateFlow()

    fun init(context: Context) {
        _enabled.value = UserStorage.getParanoidMode(context)
    }

    fun setEnabled(context: Context, enabled: Boolean) {
        UserStorage.setParanoidMode(context, enabled)
        _enabled.value = enabled
        if (enabled) clearLogs()
    }

    fun clearLogs() {
        try { Runtime.getRuntime().exec("logcat -c") } catch (_: Exception) {}
    }

    fun updateIdsResult(result: IntrusionDetector.ScanResult) {
        _lastIdsResult.value = result
    }

    fun handleThreat(context: Context, result: IntrusionDetector.ScanResult, honeyTampered: Boolean) {
        clearLogs()
        val desc = buildString {
            if (result.threats.isNotEmpty()) append(result.threats.joinToString { it.label })
            if (honeyTampered) {
                if (result.threats.isNotEmpty()) append(", ")
                append("HoneyTrap")
            }
        }
        sendAlert(context, desc)
        if (UserStorage.getWipeOnBreach(context)) {
            val level = try {
                WipeManager.Level.valueOf(UserStorage.getBreachWipeLevel(context))
            } catch (_: Exception) {
                WipeManager.Level.HARD
            }
            WipeManager.wipe(context, level)
        } else {
            _stealthMode.value = true
        }
    }

    private fun sendAlert(context: Context, threats: String) {
        val url = UserStorage.getAlertUrl(context)
        if (url.isBlank()) return
        alertScope.launch {
            postAlert(url, buildPayload(context, threats))
        }
    }

    /** Fires a real request against [url] and reports whether it was delivered,
     *  so the settings screen can confirm a configured webhook actually works
     *  instead of relying on the silent fire-and-forget path used for real alerts. */
    suspend fun testAlert(context: Context, url: String): Boolean =
        postAlert(url, buildPayload(context, "test"))

    private fun buildPayload(context: Context, threats: String): String =
        JSONObject().apply {
            put("device_id", UserStorage.getDeviceId(context))
            put("threats", threats)
            put("ts", System.currentTimeMillis())
        }.toString()

    private suspend fun postAlert(url: String, payload: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val client = OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build()
            val body = payload.toRequestBody("application/json".toMediaType())
            val req = Request.Builder().url(url).post(body).build()
            client.newCall(req).execute().use { it.isSuccessful }
        } catch (_: Exception) { false }
    }

    /** Alert URLs must be HTTPS (or one of the network_security_config loopback/
     *  .onion exceptions) — anything else silently fails every send because
     *  cleartext traffic is blocked app-wide, which would otherwise look "saved
     *  and armed" to the user while never actually delivering a breach alert. */
    fun isValidAlertUrl(url: String): Boolean {
        if (url.isBlank()) return true
        val parsed = try { java.net.URI(url) } catch (_: Exception) { return false }
        val host = parsed.host ?: return false
        if (parsed.scheme == "https") return true
        return parsed.scheme == "http" && (
            host == "localhost" || host == "127.0.0.1" || host == "10.0.2.2" || host.endsWith(".onion")
        )
    }
}

object BLog {
    fun d(tag: String, msg: String) { if (!ParanoidMode.isEnabled) Log.d(tag, msg) }
    fun i(tag: String, msg: String) { if (!ParanoidMode.isEnabled) Log.i(tag, msg) }
    fun w(tag: String, msg: String) { if (!ParanoidMode.isEnabled) Log.w(tag, msg) }
    fun e(tag: String, msg: String) { Log.e(tag, msg) }
    fun e(tag: String, msg: String, t: Throwable) { Log.e(tag, msg, t) }
}
