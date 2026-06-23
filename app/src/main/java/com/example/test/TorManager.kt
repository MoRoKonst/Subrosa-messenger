package com.bcon.messenger

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Proxy
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

object TorManager {

    private const val TAG = "TorManager"
    const val SOCKS_HOST = "127.0.0.1"
    const val SOCKS_PORT = 9050
    private const val TOR_TIMEOUT_MS = 12_000L
    private const val CONNECT_TIMEOUT_MS = 30_000

    var isConnected = false
        private set
    var bootstrapProgress = 0
        private set

    private val progressListeners = mutableListOf<(Int, String) -> Unit>()
    private val readyListeners = mutableListOf<() -> Unit>()
    private val errorListeners = mutableListOf<(String) -> Unit>()

    var onBootstrapProgress: ((Int, String) -> Unit)? = null
        set(value) { field = value; if (value != null) progressListeners.add(value) }
    var onTorReady: (() -> Unit)? = null
        set(value) { field = value; if (value != null) readyListeners.add(value) }
    var onTorError: ((String) -> Unit)? = null
        set(value) { field = value; if (value != null) errorListeners.add(value) }

    private fun notifyReady() = readyListeners.forEach { it() }
    private fun notifyError(msg: String) = errorListeners.forEach { it(msg) }
    private fun notifyProgress(p: Int, s: String) = progressListeners.forEach { it(p, s) }

    // ─── Запуск ───────────────────────────────────────────────────────────────
    //
    // Если Orbot установлен — запрашиваем старт и ждём пока SOCKS порт откроется.
    // Если нет — сразу сообщаем об ошибке, приложение работает напрямую.

    fun start(context: Context, scope: CoroutineScope, strings: AppStrings = ruStrings) {
        scope.launch(Dispatchers.IO) {
            try {
                // Если Orbot уже запущен — SOCKS сразу доступен
                if (isSocksAvailable()) {
                    isConnected = true
                    bootstrapProgress = 100
                    Log.d(TAG, "Orbot уже запущен — Tor готов")
                    withContext(Dispatchers.Main) {
                        notifyProgress(100, strings.torConnected)
                        notifyReady()
                    }
                    return@launch
                }

                if (!isOrbotInstalled(context)) {
                    Log.d(TAG, "Orbot не установлен — прямое подключение")
                    withContext(Dispatchers.Main) {
                        notifyError("Orbot не установлен — прямое подключение")
                    }
                    return@launch
                }

                Log.d(TAG, "Запрашиваем старт Orbot...")
                withContext(Dispatchers.Main) {
                    notifyProgress(5, strings.torStartingOrbot)
                }

                requestOrbotStart(context)

                // Ждём пока SOCKS порт откроется
                val deadline = System.currentTimeMillis() + TOR_TIMEOUT_MS
                var progress = 5

                while (System.currentTimeMillis() < deadline) {
                    delay(2000)

                    if (isSocksAvailable()) {
                        isConnected = true
                        bootstrapProgress = 100
                        Log.d(TAG, "Orbot SOCKS доступен — Tor готов")
                        withContext(Dispatchers.Main) {
                            notifyProgress(100, strings.torConnected)
                            notifyReady()
                        }
                        return@launch
                    }

                    progress = minOf(progress + 5, 90)
                    bootstrapProgress = progress
                    val status = when {
                        progress < 30 -> strings.torStartingOrbot
                        progress < 60 -> strings.torConnectingNetwork
                        else -> strings.torAlmostReady
                    }
                    withContext(Dispatchers.Main) {
                        notifyProgress(progress, status)
                    }
                }

                Log.w(TAG, "Orbot не ответил — прямое подключение")
                withContext(Dispatchers.Main) {
                    notifyError("Orbot не ответил — прямое подключение")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Ошибка TorManager: ${e.message}")
                withContext(Dispatchers.Main) {
                    notifyError("Ошибка Tor: ${e.message}")
                }
            }
        }
    }

    private fun requestOrbotStart(context: Context) {
        try {
            val intent = Intent("org.torproject.android.intent.action.START")
            intent.setPackage("org.torproject.android")
            intent.putExtra("org.torproject.android.intent.extra.PACKAGE_NAME", context.packageName)
            context.sendBroadcast(intent)
            Log.d(TAG, "Intent START отправлен в Orbot")
        } catch (e: Exception) {
            Log.w(TAG, "Не удалось запустить Orbot: ${e.message}")
        }
    }

    private fun isSocksAvailable(): Boolean {
        return try {
            val socket = java.net.Socket()
            socket.connect(InetSocketAddress(SOCKS_HOST, SOCKS_PORT), 2000)
            socket.close()
            true
        } catch (e: Exception) {
            false
        }
    }

    fun createTorSocket(
        host: String,
        port: Int,
        sslSocketFactory: SSLSocketFactory
    ): SSLSocket {
        Log.d(TAG, "Подключаемся через Tor к $host:$port")
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(SOCKS_HOST, SOCKS_PORT))
        val rawSocket = java.net.Socket(proxy)
        // createUnresolved — имя хоста НЕ резолвится через системный DNS.
        // Передаём строку напрямую в Orbot, который разрешает её внутри Tor.
        // Без этого провайдер видит DNS запрос к серверу (DNS leak).
        rawSocket.connect(InetSocketAddress.createUnresolved(host, port), CONNECT_TIMEOUT_MS)
        val sslSocket = sslSocketFactory.createSocket(rawSocket, host, port, true) as SSLSocket
        sslSocket.enabledProtocols = arrayOf("TLSv1.3")
        return sslSocket
    }

    fun stop() {
        isConnected = false
        bootstrapProgress = 0
        progressListeners.clear()
        readyListeners.clear()
        errorListeners.clear()
        Log.d(TAG, "TorManager остановлен")
    }

    fun isOrbotInstalled(context: Context): Boolean {
        return try {
            context.packageManager.getPackageInfo("org.torproject.android", 0)
            true
        } catch (e: Exception) {
            false
        }
    }
}
