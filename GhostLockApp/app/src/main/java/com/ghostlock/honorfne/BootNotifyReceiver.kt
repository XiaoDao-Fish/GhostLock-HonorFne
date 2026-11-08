package com.ghostlock.honorfne

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * On boot, reminds the user that Shizuku dropped across the reboot and must be
 * re-enabled (wireless debugging) before the app can grind again. We cannot
 * auto-grant or auto-start Shizuku; this is just a nudge.
 */
class BootNotifyReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channelId = "ghostlock_boot"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(channelId, "GhostLock", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val open = context.packageManager.getLaunchIntentForPackage(context.packageName)
        val pi = PendingIntent.getActivity(
            context, 0, open,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = NotificationCompat.Builder(context, channelId)
            .setContentTitle("GhostLock：请重连 Shizuku")
            .setContentText("设备已重启，临时 root 已失效。请通过无线调试重新启动 Shizuku 并打开本应用继续。")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        nm.notify(1, n)
    }
}
