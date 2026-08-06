package com.subrosa.messenger

import android.content.Context
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket
import java.util.UUID

class SocketConnection(
    private val context: Context,
    private val username: String,
    private val onMessageReceived: (String, String) -> Unit,
    private val onAck: (String) -> Unit,
    private val onError: (String) -> Unit,
    private val onStatusChanged: (Boolean) -> Unit
) {
    private var socket: Socket? = null
    private var writer: PrintWriter? = null
    private var reader: BufferedReader? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isConnected = false
    private var host = ""
    private var port = 0

    suspend fun connect(host: String, port: Int): Boolean {
        this.host = host
        this.port = port
        return doConnect()
    }

    private suspend fun doConnect(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                socket?.close()
                socket = Socket()
                socket!!.connect(java.net.InetSocketAddress(host, port), 5000)
                writer = PrintWriter(socket!!.getOutputStream(), true)
                reader = BufferedReader(InputStreamReader(socket!!.getInputStream()))

                val register = JSONObject().apply {
                    put("type", "register")
                    put("from", username)
                }
                writer!!.println(register.toString())

                isConnected = true
                withContext(Dispatchers.Main) { onStatusChanged(true) }
                startListening()
                delay(300)
                flushQueue()
                true
            } catch (e: Exception) {
                android.util.Log.e("SocketConnection", "doConnect ошибка: ${e.message}")
                isConnected = false
                withContext(Dispatchers.Main) { onStatusChanged(false) }
                false
            }
        }
    }

    private suspend fun flushQueue() {
        val queue = MessageQueue.load(context)
        if (queue.isEmpty()) return
        android.util.Log.d("SocketConnection", "Отправляем очередь: ${queue.size} сообщений")
        queue.forEach { queued ->
            val message = JSONObject().apply {
                put("type", "message")
                put("from", username)
                put("to", queued.to)
                put("text", queued.text)
                put("id", queued.id)
            }
            writer?.println(message.toString())
        }
    }

    fun send(to: String, text: String): String {
        val id = UUID.randomUUID().toString()
        MessageQueue.add(context, MessageQueue.QueuedMessage(id = id, to = to, text = text))
        if (isConnected) {
            scope.launch(Dispatchers.IO) {
                try {
                    val message = JSONObject().apply {
                        put("type", "message")
                        put("from", username)
                        put("to", to)
                        put("text", text)
                        put("id", id)
                    }
                    writer?.println(message.toString())
                } catch (e: Exception) {
                    android.util.Log.e("SocketConnection", "send ошибка: ${e.message}")
                }
            }
        }
        return id
    }

    private fun startListening() {
        scope.launch(Dispatchers.IO) {
            try {
                while (isConnected) {
                    val line = reader?.readLine()
                    if (line == null) {
                        android.util.Log.d("SocketConnection", "Соединение закрыто")
                        break
                    }
                    if (line.isBlank()) continue

                    val json = JSONObject(line)
                    when (json.getString("type")) {
                        "ping" -> {

                            scope.launch(Dispatchers.IO) {
                                writer?.println(JSONObject().apply {
                                    put("type", "pong")
                                }.toString())
                            }
                        }
                        "message" -> {
                            val from = json.getString("from")
                            val text = json.getString("text")
                            withContext(Dispatchers.Main) { onMessageReceived(from, text) }
                        }
                        "ack" -> {
                            val id = json.getString("id")
                            MessageQueue.remove(context, id)
                            withContext(Dispatchers.Main) { onAck(id) }
                        }
                        "error" -> {
                            val reason = json.getString("reason")
                            withContext(Dispatchers.Main) { onError(reason) }
                        }
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e("SocketConnection", "startListening ошибка: ${e.message}")
            } finally {
                if (isConnected) {
                    isConnected = false
                    withContext(Dispatchers.Main) { onStatusChanged(false) }
                    scheduleReconnect()
                }
            }
        }
    }

    private fun scheduleReconnect() {
        scope.launch(Dispatchers.IO) {
            var attempt = 1
            while (!isConnected && scope.isActive) {
                android.util.Log.d("SocketConnection", "Reconnect попытка #$attempt")
                delay(2000)
                val ok = doConnect()
                if (ok) break
                attempt++
            }
        }
    }

    fun disconnect() {
        isConnected = false
        scope.cancel()
        try { socket?.close() } catch (e: Exception) { }
    }
}