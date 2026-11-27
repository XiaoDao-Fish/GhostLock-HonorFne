package com.ghostlock.honorfne

import android.app.Service
import android.content.Intent
import android.os.IBinder



class RootUserService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
}
