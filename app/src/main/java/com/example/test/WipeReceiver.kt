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
                // Same server-side identity revocation as ProfileScreen.kt's
                // "Меня скомпрометировали" (see docs/ISSUE_backup_identity_
                // hijack.md, Тир 5) — DMS specifically can fire while the
                // device is online but its owner unreachable (confiscated,
                // not unlocked), so there's a real chance this reaches the
                // server before the wipe below destroys the key it needs to
                // be sent under.
                CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
                    MessengerService.requestIdentityRevocation(context)
                    WipeManager.wipe(context, WipeManager.Level.NUCLEAR)
                }
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
