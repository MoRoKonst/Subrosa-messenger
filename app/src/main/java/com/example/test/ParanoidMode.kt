package com.bcon.messenger

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
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
        val payload = JSONObject().apply {
            put("device_id", UserStorage.getDeviceId(context))
            put("threats", threats)
            put("ts", System.currentTimeMillis())
        }.toString()
        alertScope.launch {
            try {
                val client = OkHttpClient.Builder()
                    .connectTimeout(5, TimeUnit.SECONDS)
                    .readTimeout(5, TimeUnit.SECONDS)
                    .build()
                val body = payload.toRequestBody("application/json".toMediaType())
                val req = Request.Builder().url(url).post(body).build()
                client.newCall(req).execute().close()
            } catch (_: Exception) {}
        }
    }
}

object BLog {
    fun d(tag: String, msg: String) { if (!ParanoidMode.isEnabled) Log.d(tag, msg) }
    fun i(tag: String, msg: String) { if (!ParanoidMode.isEnabled) Log.i(tag, msg) }
    fun w(tag: String, msg: String) { if (!ParanoidMode.isEnabled) Log.w(tag, msg) }
    fun e(tag: String, msg: String) { Log.e(tag, msg) }
    fun e(tag: String, msg: String, t: Throwable) { Log.e(tag, msg, t) }
}
