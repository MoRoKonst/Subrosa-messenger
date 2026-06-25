package com.bcon.messenger

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * Foreground-сервис для звонков.
 * Держит аудиофокус и уведомление пока звонок активен.
 * Запускается через startForegroundService() при начале/принятии звонка.
 */
class CallService : Service() {

    companion object {
        const val TAG = "CallService"
        const val CHANNEL_ID = "call_channel"
        const val NOTIF_INCOMING = 200
        const val NOTIF_ACTIVE   = 201

        const val ACTION_INCOMING = "ACTION_INCOMING_CALL"
        const val ACTION_ACTIVE   = "ACTION_ACTIVE_CALL"
        const val ACTION_END      = "ACTION_END_CALL"

        const val EXTRA_PEER_NAME = "peer_name"
        const val EXTRA_IS_VIDEO  = "is_video"
        const val EXTRA_IS_GROUP  = "is_group"
    }

    private var audioFocusRequest: AudioFocusRequest? = null
    private var wakeLock: android.os.PowerManager.WakeLock? = null
    private val notificationManager by lazy {
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        wakeLock = pm.newWakeLock(
            android.os.PowerManager.SCREEN_BRIGHT_WAKE_LOCK or android.os.PowerManager.ACQUIRE_CAUSES_WAKEUP,
            "beacon:call"
        )
        // Слушаем завершение звонка
        CallManager.onCallEnded = { reason ->
            Log.d(TAG, "Call ended: $reason")
            stopSelf()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_INCOMING -> {
                val peerName = intent.getStringExtra(EXTRA_PEER_NAME) ?: "Звонок"
                val isVideo  = intent.getBooleanExtra(EXTRA_IS_VIDEO, false)
                val isGroup  = intent.getBooleanExtra(EXTRA_IS_GROUP, false)
                showIncomingCallNotification(peerName, isVideo, isGroup)
            }
            ACTION_ACTIVE -> {
                val peerName = intent.getStringExtra(EXTRA_PEER_NAME) ?: "Звонок"
                val isVideo  = intent.getBooleanExtra(EXTRA_IS_VIDEO, false)
                requestAudioFocus()
                if (wakeLock?.isHeld == false) wakeLock?.acquire(2 * 60 * 60 * 1000L) // макс 2 часа
                showActiveCallNotification(peerName, isVideo)
            }
            ACTION_END -> {
                releaseAudioFocus()
                if (wakeLock?.isHeld == true) wakeLock?.release()
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        releaseAudioFocus()
        if (wakeLock?.isHeld == true) wakeLock?.release()
        // ОС может убить сервис без ACTION_END (нехватка памяти, Force Stop и т.п.).
        // Если звонок ещё активен — завершаем его, чтобы собеседник получил call_end.
        // hangUp() idempotent: внутри AtomicBoolean-guard, двойной вызов безопасен.
        if (CallManager.callId.isNotEmpty()) {
            CallManager.hangUp()
        }
        Log.d(TAG, "CallService destroyed")
    }

    // ─── Уведомление входящего звонка ─────────────────────────────────────────

    private fun showIncomingCallNotification(peerName: String, isVideo: Boolean, isGroup: Boolean) {
        val typeStr = when {
            isGroup -> "Групповой звонок"
            isVideo -> "Видеозвонок"
            else    -> "Аудиозвонок"
        }

        // Intent для открытия экрана входящего звонка
        val openIntent = Intent(this, MainActivity::class.java).apply {
            action = "OPEN_INCOMING_CALL"
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openPi = PendingIntent.getActivity(
            this, 0, openIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Intent для отклонения без открытия приложения
        val declineIntent = Intent(this, CallService::class.java).apply { action = ACTION_END }
        val declinePi = PendingIntent.getService(
            this, 1, declineIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_call)
            .setContentTitle("Входящий $typeStr")
            .setContentText(peerName)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setFullScreenIntent(openPi, true)
            .setContentIntent(openPi)
            .addAction(android.R.drawable.ic_delete, "Отклонить", declinePi)
            .setAutoCancel(false)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIF_INCOMING, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL)
        } else {
            startForeground(NOTIF_INCOMING, notification)
        }
    }

    // ─── Уведомление активного звонка ─────────────────────────────────────────

    private fun showActiveCallNotification(peerName: String, isVideo: Boolean = false) {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            action = "OPEN_ACTIVE_CALL"
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openPi = PendingIntent.getActivity(
            this, 2, openIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val endIntent = Intent(this, CallService::class.java).apply { action = ACTION_END }
        val endPi = PendingIntent.getService(
            this, 3, endIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_call)
            .setContentTitle("Звонок активен")
            .setContentText(peerName)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setContentIntent(openPi)
            .addAction(android.R.drawable.ic_delete, "Завершить", endPi)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val serviceType = if (isVideo)
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
            else
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            startForeground(NOTIF_ACTIVE, notification, serviceType)
        } else {
            startForeground(NOTIF_ACTIVE, notification)
        }
    }

    // ─── Аудиофокус ───────────────────────────────────────────────────────────

    private fun requestAudioFocus() {
        val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val req = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build()
                )
                .setAcceptsDelayedFocusGain(false)
                .build()
            audioFocusRequest = req
            am.requestAudioFocus(req)
        } else {
            @Suppress("DEPRECATION")
            am.requestAudioFocus(null, AudioManager.STREAM_VOICE_CALL, AudioManager.AUDIOFOCUS_GAIN)
        }
        am.mode = AudioManager.MODE_IN_COMMUNICATION
    }

    private fun releaseAudioFocus() {
        val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            audioFocusRequest?.let { am.abandonAudioFocusRequest(it) }
        } else {
            @Suppress("DEPRECATION")
            am.abandonAudioFocus(null)
        }
        am.mode = AudioManager.MODE_NORMAL
    }

    // ─── Notification channel ─────────────────────────────────────────────────

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Звонки",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Уведомления о входящих и активных звонках"
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }
        notificationManager.createNotificationChannel(channel)
    }
}
