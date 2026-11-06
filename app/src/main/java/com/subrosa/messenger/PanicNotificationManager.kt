package com.subrosa.messenger

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object PanicNotificationManager {

    const val ACTION_EMERGENCY_WIPE = "com.subrosa.messenger.EMERGENCY_WIPE"

    private const val CHANNEL_ID = "panic_button"
    private const val NOTIF_ID   = 9998
    private const val REQ_CODE   = 9200

    fun show(context: Context) {
        if (!UserStorage.getPanicButtonEnabled(context)) return
        ensureChannel(context)

        val s = strings(context)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_delete)
            .setContentTitle(s.panicNotifTitle)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            // PRIORITY_HIGH (pre-O) / IMPORTANCE_HIGH channel (O+, see ensureChannel)
            // — below high, Android collapses the action button until the
            // notification is manually expanded, which defeats the point of a
            // panic button. setOnlyAlertOnce(true) keeps this from re-alerting
            // (sound/vibrate/heads-up) on every re-notify() — this fires on
            // every successful reconnect (MessengerService's handshake_ok),
            // which would otherwise mean a heads-up popup every reconnect.
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setAutoCancel(false)
            .addAction(0, s.panicNotifButton, makeWipePendingIntent(context))
            .build()

        try {
            NotificationManagerCompat.from(context).notify(NOTIF_ID, notification)
        } catch (_: SecurityException) {}
    }

    fun dismiss(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIF_ID)
    }

    private fun makeWipePendingIntent(context: Context): PendingIntent {
        val intent = Intent(context, WipeReceiver::class.java).apply {
            action = ACTION_EMERGENCY_WIPE
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        return PendingIntent.getBroadcast(context, REQ_CODE, intent, flags)
    }

    private fun strings(context: Context): AppStrings =
        if (UserStorage.getLanguage(context) == "en") enStrings else ruStrings

    private fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val s = strings(context)
            val channel = NotificationChannel(
                CHANNEL_ID,
                s.panicNotifTitle,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = s.panicNotifText
                lockscreenVisibility = NotificationCompat.VISIBILITY_PUBLIC
            }
            context.getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }
}
