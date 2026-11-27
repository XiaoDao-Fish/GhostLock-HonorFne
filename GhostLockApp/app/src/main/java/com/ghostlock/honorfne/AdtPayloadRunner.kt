package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.delay

   
                               
  
                                                         
                                       
                                                                       
                                                          
  
                                                       
                               
   
class AdtPayloadRunner(
    private val context: Context,
    private val log: (String) -> Unit,
    private val status: (String) -> Unit
) {
    private val dir = "/data/local/tmp/glpc"
    private val ksuDir = "/data/local/tmp/ksu_fne"

    suspend fun run(): Boolean {
        if (!ShizukuController.hasPermission()) {
            log("[adt][错误] Shizuku 未授权")
            return false
        }
        val pairs = listOf(
            "adt/glbin" to "$dir/glbin",
            "adt/payload_run.bin" to "$dir/payload_run.bin"
        )
        ShizukuController.exec("rm -rf $dir; mkdir -p $dir $ksuDir", 20_000)
        for ((asset, dest) in pairs) {
            val bytes = runCatching {
                context.assets.open(asset).use { it.readBytes() }
            }.getOrNull()
            if (bytes == null || !ShizukuController.writeFile(bytes, dest)) {
                log("[adt][错误] 写入 $dest 失败")
                return false
            }
        }
        for (f in listOf("ksud", "kernelsu.ko", "magiskpolicy", "ksu_rules")) {
            val bytes = runCatching {
                context.assets.open("ksu_fne/$f").use { it.readBytes() }
            }.getOrNull() ?: continue
            ShizukuController.writeFile(bytes, "$ksuDir/$f")
        }
        ShizukuController.exec(
            "chmod 755 $dir/glbin $ksuDir/ksud $ksuDir/magiskpolicy 2>/dev/null", 15_000
        )

        
        
        status("ADT-AN00 兜底载荷：正在关闭 SELinux…")
        var permissive = false
        repeat(3) { i ->
            ShizukuController.exec(
                "cd $dir && GL_STOP_AFTER_W1=1 ./glbin --ghostlock-app-call --force-attack " +
                    "< $dir/payload_run.bin > $dir/w1.log 2>&1", 60_000
            )
            val en = ShizukuController.exec("getenforce", 10_000).out.trim()
            log("[adt] 第 ${i + 1} 把 W1：SELinux=$en")
            if (en.equals("Permissive", true)) {
                permissive = true
                return@repeat
            }
        }
        if (!permissive) {
            log("[adt][警告] W1 三把未关闭 SELinux，放弃兜底链")
            return false
        }

        status("ADT-AN00 兜底载荷：正在写入 root 权限…")
        ShizukuController.exec(
            "cd $dir && ./glbin --ghostlock-app-call --force-attack " +
                "< $dir/payload_run.bin > $dir/w2.log 2>&1", 120_000
        )

        val deadline = System.currentTimeMillis() + 90_000
        while (System.currentTimeMillis() < deadline) {
            delay(3_000)
            val r = ShizukuController.exec(
                "/data/adb/ksu/bin/su -c id 2>/dev/null | head -1; " +
                    "/data/adb/ksud -c id 2>/dev/null | head -1; " +
                    "su -c id 2>/dev/null | head -1", 15_000
            )
            val suBin = when {
                r.out.contains("uid=0", true) &&
                    ShizukuController.exec("/data/adb/ksu/bin/su -c id 2>/dev/null", 12_000)
                        .out.contains("uid=0", true) -> "/data/adb/ksu/bin/su"
                r.out.contains("uid=0", true) &&
                    ShizukuController.exec("/data/adb/ksud -c id 2>/dev/null", 12_000)
                        .out.contains("uid=0", true) -> "/data/adb/ksud"
                r.out.contains("uid=0", true) -> "su"
                else -> ""
            }
            if (suBin.isNotEmpty()) {
                log("[adt] ✔ su 验证通过（$suBin）")
                ShizukuController.exec(
                    "$suBin -c 'echo 1 > /sys/fs/selinux/enforce' 2>/dev/null", 15_000
                )
                LogStore.setFatal("ADT-AN00 兜底载荷成功：临时 root 已就绪", LogStore.RANK_RESULT)
                status("ADT 兜底载荷执行成功")
                return true
            }
        }
        LogStore.setFatal("ADT-AN00 兜底载荷失败：su 未就绪，详见日志", LogStore.RANK_RESULT)
        status("ADT 兜底载荷执行失败")
        return false
    }
}
