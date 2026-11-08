package com.ghostlock.honorfne

import android.app.Service
import android.content.Intent
import android.os.IBinder

// Retained only for manifest compatibility. File deployment now uses
// Shizuku.newProcess, so this service is no longer used by the app.
class RootUserService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
}
