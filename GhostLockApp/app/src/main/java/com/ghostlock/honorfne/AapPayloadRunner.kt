package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.delay
import java.math.BigInteger
import java.util.Locale

   
                                        
  
                
                                                                                 
                                                                    
                                                                    
                                                               
  
                                                 
   
class AapPayloadRunner(
    private val context: Context,
    private val log: (String) -> Unit,
    private val status: (String) -> Unit
) {
    private val dir = "/data/local/tmp/aap"
    private val soPath = "$dir/preload.so"
    private val logPath = "$dir/ex.log"
    private val fifo = "$dir/ex.in"

    companion object {
        
        private const val RSA_N = "0x308ae457250bf775"
        private const val RSA_D = "0x5278a6d7aa4dc61"

                                                                   
        fun fnv64(text: String): Long {
            var value = 1469598103934665603L
            for (b in text.toByteArray(Charsets.US_ASCII)) {
                value = value xor (b.toLong() and 0xffL)
                value *= 1099511628211L
            }
            return value
        }

        fun sign(challenge: String): String {
            val n = BigInteger(RSA_N.substring(2), 16)
            val d = BigInteger(RSA_D.substring(2), 16)
            val raw = fnv64(challenge)
            val unsigned = if (raw < 0)
                BigInteger.valueOf(raw).add(BigInteger.ONE.shiftLeft(64))
            else BigInteger.valueOf(raw)
            val m = unsigned.mod(n)
            return String.format(Locale.ROOT, "0x%016x", m.modPow(d, n))
        }
    }

    suspend fun run(): Boolean {
        if (!ShizukuController.hasPermission()) {
            log("[a3][错误] Shizuku 未授权")
            return false
        }
        val bytes = runCatching {
            context.assets.open("aap/preload_honor_vote6b_bootidfix.so").use { it.readBytes() }
        }.getOrNull()
        if (bytes == null) {
            log("[a3][错误] 读取 aap/preload_honor_vote6b_bootidfix.so 失败")
            return false
        }

        ShizukuController.exec(
            "rm -rf $dir; mkdir -p $dir; mkfifo $fifo 2>/dev/null; chmod 600 $fifo", 20_000
        )
        if (!ShizukuController.writeFile(bytes, soPath)) {
            log("[a3][错误] 写入 $soPath 失败")
            return false
        }
        ShizukuController.exec("chmod 755 $soPath", 15_000)

        log("[a3] 启动 LD_PRELOAD 载荷（荣耀500 / AAP-AN00）")
        status("AAP 载荷运行中，请勿操作设备…")
        ShizukuController.exec(
            "( LD_PRELOAD=$soPath /system/bin/true < $fifo > $logPath 2>&1; " +
                "echo EXITCODE=\$? >> $logPath ) >/dev/null 2>&1 &",
            15_000
        )

        
        val deadline = System.currentTimeMillis() + 180_000
        var answered = false
        while (System.currentTimeMillis() < deadline) {
            delay(2_000)
            val text = tail(4_000)
            val m = Regex("\\[Challenge\\]\\s*([0-9a-z]{16})").find(text)
            if (m != null && !answered) {
                val token = m.groupValues[1]
                val sig = sign(token)
                log("[a3] 收到挑战 $token，回送签名 $sig")
                ShizukuController.exec("printf '%s\\n' '$sig' > $fifo 2>/dev/null", 15_000)
                answered = true
            }
            if (answered && suReady()) {
                log("[a3] ✔ su 验证通过，uid=0")
                LogStore.setFatal("AAP-AN00 载荷执行成功：临时 root（su）已就绪", LogStore.RANK_RESULT)
                status("AAP 载荷执行成功")
                return true
            }
            if (text.contains("verify failed") || text.contains("verify failed", true)) {
                log("[a3][错误] 挑战签名被拒绝")
                break
            }
            if (text.contains("EXITCODE=") && ! answered) break
        }

        val tail = tail(4_000)
        if (tail.isNotBlank()) {
            log("[a3] ---- payload 日志尾部 ----")
            tail.lines().filter { it.isNotBlank() }.takeLast(25).forEach { log("[a3] ${it.take(160)}") }
        }
        LogStore.setFatal("AAP-AN00 载荷执行失败：su 未就绪，详见日志", LogStore.RANK_RESULT)
        status("AAP 载荷执行失败")
        return false
    }

    private suspend fun suReady(): Boolean {
        val r = ShizukuController.exec(
            "/data/local/tmp/su -c id 2>/dev/null | head -1", 15_000
        )
        return r.out.contains("uid=0", ignoreCase = true)
    }

    private suspend fun tail(bytes: Int): String {
        val r = ShizukuController.exec("tail -c $bytes '$logPath' 2>/dev/null", 15_000)
        if (ShizukuController.channelDead(r)) return ""
        return r.out.replace("\u0000", "").trim()
    }
}
