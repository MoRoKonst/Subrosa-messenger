package com.subrosa.messenger

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class WipeReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            DeadMansSwitchManager.ACTION_DMS_FIRE -> {

                DeadMansSwitchManager.showWarningNotification(context)
                DeadMansSwitchManager.scheduleWipeAlarm(context, DeadMansSwitchManager.GRACE_PERIOD_MS)
            }

            DeadMansSwitchManager.ACTION_DMS_WIPE -> {

                DeadMansSwitchManager.dismissWarningNotification(context)
                WipeManager.wipe(context, WipeManager.Level.NUCLEAR)
            }

            DeadMansSwitchManager.ACTION_DMS_CHECKIN -> {

                DeadMansSwitchManager.checkIn(context)
            }

            PanicNotificationManager.ACTION_EMERGENCY_WIPE -> {
                PanicNotificationManager.dismiss(context)
                if (UserStorage.getPanicButtonDecoy(context)) {

                    ParanoidMode.activateFromNotification()

                    val launchIntent = context.packageManager
                        .getLaunchIntentForPackage(context.packageName)
                        ?.apply { flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP }
                    if (launchIntent != null) context.startActivity(launchIntent)

                    CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
                        kotlinx.coroutines.delay(600)
                        WipeManager.wipeForDecoyKeepAlive(context)
                    }
                } else {

                    WipeManager.wipe(context, WipeManager.Level.HARD)
                }
            }
        }
    }
}
