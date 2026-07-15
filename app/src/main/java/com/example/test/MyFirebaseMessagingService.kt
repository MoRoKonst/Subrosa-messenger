package com.bcon.messenger

import android.content.Intent
import android.util.Log
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.json.JSONObject

class MyFirebaseMessagingService : FirebaseMessagingService() {

    companion object {
        private const val TAG = "FCM"
    }

    override fun onNewToken(token: String) {

        getSharedPreferences("fcm_prefs", MODE_PRIVATE)
            .edit().putString("fcm_token", token).apply()

        sendTokenToServer(token)
    }

    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        val type = remoteMessage.data["type"]
        if (type == "wakeup" || type == null) {

            try {
                val intent = Intent(this, MessengerService::class.java)
                startService(intent)
                Log.d(TAG, "MessengerService запущен по FCM wakeup")
            } catch (e: Exception) {
                Log.e(TAG, "Не удалось запустить MessengerService: ${e.message}")
            }
        }
    }

    private fun sendTokenToServer(token: String) {
        try {
            val intent = Intent(this, MessengerService::class.java).apply {
                putExtra("fcm_token", token)
            }
            startService(intent)
        } catch (e: Exception) {
            Log.e(TAG, "sendTokenToServer error: ${e.message}")
        }
    }
}
