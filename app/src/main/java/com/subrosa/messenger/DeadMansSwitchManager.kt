package com.subrosa.messenger

import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object DeadMansSwitchManager {

    const val ACTION_DMS_FIRE    = "com.subrosa.messenger.DMS_FIRE"
    const val ACTION_DMS_WIPE    = "com.subrosa.messenger.DMS_WIPE"
    const val ACTION_DMS_CHECKIN = "com.subrosa.messenger.DMS_CHECKIN"

    private const val NOTIF_CHANNEL_ID  = "dms_alert"
    private const val NOTIF_WARNING_ID  = 9001
    private const val REQ_FIRE          = 9100
    private const val REQ_WIPE          = 9101
    private const val REQ_CHECKIN       = 9102
    const val GRACE_PERIOD_MS           = 15 * 60 * 1000L

    fun enable(context: Context, intervalHours: Int) {
        enableMinutes(context, intervalHours * 60)
    }

    /** Same as [enable] but with minute granularity — needed for the
     *  sub-1-hour timer tiers (15/30 min) added alongside the original
     *  hour-based options. See UserStorage.getDmsIntervalMinutes for why
     *  this is a separate stored value rather than reinterpreting the
     *  hours-based one. */
    fun enableMinutes(context: Context, intervalMinutes: Int) {
        UserStorage.setDmsEnabled(context, true)
        UserStorage.setDmsIntervalMinutes(context, intervalMinutes)
        UserStorage.setDmsIntervalHours(context, (intervalMinutes / 60).coerceAtLeast(1))
        checkIn(context)
    }

    fun disable(context: Context) {
        UserStorage.setDmsEnabled(context, false)
        cancelAlarms(context)
        dismissWarningNotification(context)
    }

    fun isEnabled(context: Context): Boolean = UserStorage.getDmsEnabled(context)

    fun getIntervalHours(context: Context): Int = UserStorage.getDmsIntervalHours(context)

    fun getIntervalMinutes(context: Context): Int = UserStorage.getDmsIntervalMinutes(context)

    fun getTimeRemainingMs(context: Context): Long {
        val lastCheckin = UserStorage.getDmsLastCheckin(context)
        if (lastCheckin == 0L) return 0L
        val intervalMs = UserStorage.getDmsIntervalMinutes(context) * 60_000L
        val elapsed = System.currentTimeMillis() - lastCheckin
        return (intervalMs - elapsed).coerceAtLeast(0L)
    }

    fun checkIn(context: Context) {
        val now = System.currentTimeMillis()
        UserStorage.setDmsLastCheckin(context, now)
        cancelAlarms(context)
        dismissWarningNotification(context)
        if (isEnabled(context)) {
            scheduleFireAlarm(context)
        }
    }

    fun triggerWarningImmediate(context: Context) {
        showWarningNotification(context)
        scheduleWipeAlarm(context, GRACE_PERIOD_MS)
    }

    fun scheduleFireAlarm(context: Context) {
        val triggerAt = UserStorage.getDmsLastCheckin(context) +
                UserStorage.getDmsIntervalMinutes(context) * 60_000L
        val intent = makePendingIntent(context, ACTION_DMS_FIRE, REQ_FIRE)
        scheduleExact(context, triggerAt, intent)
    }

    fun scheduleWipeAlarm(context: Context, delayMs: Long = GRACE_PERIOD_MS) {
        val triggerAt = System.currentTimeMillis() + delayMs
        val intent = makePendingIntent(context, ACTION_DMS_WIPE, REQ_WIPE)
        scheduleExact(context, triggerAt, intent)
    }

    private fun scheduleExact(context: Context, triggerAt: Long, intent: PendingIntent) {
        val am = getAlarmManager(context)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !am.canScheduleExactAlarms()) {

            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, intent)
        } else {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, intent)
        }
    }

    fun cancelAlarms(context: Context) {
        getAlarmManager(context).cancel(makePendingIntent(context, ACTION_DMS_FIRE, REQ_FIRE))
        getAlarmManager(context).cancel(makePendingIntent(context, ACTION_DMS_WIPE, REQ_WIPE))
    }

    fun showWarningNotification(context: Context) {
        ensureChannel(context)

        val checkinIntent = makePendingIntent(context, ACTION_DMS_CHECKIN, REQ_CHECKIN)

        val s = strings(context)
        val notification = NotificationCompat.Builder(context, NOTIF_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(s.dmsNotifTitle)
            .setContentText(s.dmsNotifText)
            .setStyle(NotificationCompat.BigTextStyle().bigText(s.dmsNotifGraceText))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setOngoing(true)
            .setAutoCancel(false)
            .addAction(0, s.dmsCheckinBtn, checkinIntent)
            .build()

        try {
            NotificationManagerCompat.from(context).notify(NOTIF_WARNING_ID, notification)
        } catch (_: SecurityException) {}
    }

    fun dismissWarningNotification(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIF_WARNING_ID)
    }

    private fun strings(context: Context): AppStrings =
        if (UserStorage.getLanguage(context) == "en") enStrings else ruStrings

    private fun getAlarmManager(context: Context): AlarmManager =
        context.getSystemService(AlarmManager::class.java)

    private fun makePendingIntent(context: Context, action: String, reqCode: Int): PendingIntent {
        val intent = Intent(context, WipeReceiver::class.java).apply { this.action = action }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        return PendingIntent.getBroadcast(context, reqCode, intent, flags)
    }

    private fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val s = strings(context)
            val channel = NotificationChannel(
                NOTIF_CHANNEL_ID,
                s.dmsNotifTitle,
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = s.dmsSubtitle }
            context.getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }
}
