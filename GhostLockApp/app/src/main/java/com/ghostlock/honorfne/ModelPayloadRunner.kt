package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.delay

   
                           
  
                 
  
                         
  
      
                                                           
                                          
                                                                   
      
  
                                              
                                                          
                                                               
                                
  
                                                                  
                                                     
                                                   
                                               
  
                              
  
                                                             
                                                      
                                   
  
          
  
                                          
                          
   
class ModelPayloadRunner(
    private val context: Context,
    private val pack: ModelPayloads.Pack,
    private val log: (String) -> Unit,
    private val status: (String) -> Unit
) {

    private val rundir = "/data/local/tmp/gl_${pack.assetDir}"

                                                
    private val procPattern = pack.procPattern

       
                                                     
                                                          
                                              
       
    private fun readAsset(name: String): ByteArray? {
        val paths = mutableListOf(
            "models/${pack.assetDir}/$name.dat", "models/${pack.assetDir}/$name",
            "models/${pack.baseAssetDir}/$name.dat", "models/${pack.baseAssetDir}/$name"
        )
        if (name in setOf("ksud", "magiskpolicy", "ksu_rules", "kernelsu.ko")) {
            paths += "ksu_fne/$name"
        }
        for (p in paths) {
            val bytes = runCatching {
                context.assets.open(p).use { it.readBytes() }
            }.getOrNull()
            if (bytes != null) return bytes
        }
        return null
    }

    private suspend fun pushAsset(name: String, mode: String): Boolean {
        val bytes = readAsset(name)
        if (bytes == null) {
            log("[a2][错误] 读取载荷文件失败：$name（机型 ${pack.assetDir}）")
            return false
        }
        if (!ShizukuController.writeFile(bytes, "$rundir/$name")) {
            log("[a2][错误] 写入 $rundir/$name 失败（Shizuku 命令通道可能已断）")
            return false
        }
        log("[a2][DEBUG] 推送 $name (${bytes.size} bytes, mode=$mode)")
        return true
    }

    suspend fun run(): Boolean {
        if (!ShizukuController.hasPermission()) {
            log("[a2][错误] Shizuku 未授权，无法下发机型专用载荷。")
            return false
        }
        if (!ModelPayloads.available(context, pack)) {
            log("[a2][错误] 内置物料缺失：models/${pack.assetDir}/exploit")
            return false
        }

        log("[a2] ===== 机型专用载荷链（${pack.displayName}）=====")
        log("[a2] 载荷目录：$rundir")

        
        
        
        ShizukuController.exec(
            "pkill -9 -f '$procPattern' 2>/dev/null; rm -rf $rundir; " +
                "mkdir -p $rundir",
            20_000
        )

        
        
        
        
        for (f in listOf("exploit", "load_ko", "kmsg_dumper", "ksud", "magiskpolicy", "ksu_rules", "kernelsu.ko")) {
            if (!pushAsset(f, if (f in setOf("ksu_rules", "kernelsu.ko")) "644" else "755")) return false
        }
        ShizukuController.exec(
            "chmod 644 $rundir/ksu_rules $rundir/kernelsu.ko 2>/dev/null; " +
                "chmod 755 $rundir/exploit $rundir/load_ko $rundir/kmsg_dumper " +
                "$rundir/ksud $rundir/magiskpolicy 2>/dev/null",
            20_000
        )

        
        
        
        val stamp = System.currentTimeMillis().toString()
        val tmplBytes = readAsset("ksu_loader.tmpl")
        if (tmplBytes == null) {
            log("[a2][错误] 读取 ksu_loader.tmpl 失败")
            return false
        }
        val rendered = tmplBytes.toString(Charsets.UTF_8)
            .replace("@RUNDIR@", rundir)
            .replace("@STAMP@", stamp)
            .replace("@FREEZE_HISECD@", "1")
            .replace("@ALLOW_SHELL@", "0")
            .replace("@STAGES@", "1")
            .replace("@ENFORCE@", "0")
            .replace("@INITSTOP@", "0")
            .replace("@KEEP_KMSG@", "0")
            .replace("@NOLOAD@", "0")
            .replace("@RESUME_HISECD@", "0")
        if (!ShizukuController.writeFile(rendered.toByteArray(Charsets.UTF_8), "$rundir/ksu_loader.sh")) {
            log("[a2][错误] 写入 ksu_loader.sh 失败")
            return false
        }
        ShizukuController.exec("chmod 755 $rundir/ksu_loader.sh", 15_000)

        
        
        
        
        
        
        log("[a2] 启动 exploit（KSU_RUNDIR=$rundir, KSU_LOADER=$rundir/ksu_loader.sh）")
        status("机型专用载荷执行中，请勿操作设备…")
        ShizukuController.exec(
            "cd $rundir && rm -f $rundir/gl.log $rundir/ksu_load.log; " +
                "( cd $rundir && " +
                "KSU_RUNDIR=$rundir KSU_LOADER=$rundir/ksu_loader.sh " +
                "./exploit > $rundir/gl.log 2>&1 </dev/null ) >/dev/null 2>&1 &",
            15_000
        )

        
        return poll()
    }

       
              
      
              
                                                   
                                                                 
      
                                                      
                                      
       
    private suspend fun poll(): Boolean {
        val deadline = System.currentTimeMillis() + 330_000
        var lastLogSize = -1
        var reported = false

        while (System.currentTimeMillis() < deadline) {
            delay(3_000)

            
            val tail = readFileTail("$rundir/ksu_load.log", 1200)
            if (tail.isNotBlank() && tail.length != lastLogSize) {
                lastLogSize = tail.length
                if (!reported) {
                    reported = true
                    log("[a2] 加载器日志（$rundir/ksu_load.log）：")
                }
                tail.lines().filter { it.isNotBlank() }.takeLast(6).forEach {
                    log("[a2]   ${it.take(150)}")
                }
            }

            
            val mod = ShizukuController.exec(
                "grep -c kernelsu /proc/modules 2>/dev/null", 12_000
            )
            if (mod.out.trim().toIntOrNull()?.let { it > 0 } == true) {
                log("[a2] ✔ KernelSU 模块已加载")
                status("模块已加载，正在完成用户态初始化…")
                
                waitSettle()
                reportFinal(true)
                return true
            }

            
            val alive = ShizukuController.exec(
                "pidof '$procPattern' 2>/dev/null | wc -l", 12_000
            )
            val procCount = alive.out.trim().toIntOrNull() ?: 1
            if (procCount == 0) {
                val done = ShizukuController.exec(
                    "grep -c KSU_LOAD_DONE $rundir/ksu_load.log 2>/dev/null", 12_000
                )
                if (done.out.trim().toIntOrNull()?.let { it > 0 } == true) {
                    log("[a2] loader 正常结束但模块未加载 —— 判定失败")
                    reportFinal(false)
                    return false
                }
                
                log("[a2] exploit 进程已消失且无结束标记 —— 判定失败")
                reportFinal(false)
                return false
            }
        }

        log("[a2] 等待超时（330s）—— 判定失败")
        reportFinal(false)
        return false
    }

                                                 
    private suspend fun waitSettle() {
        val deadline = System.currentTimeMillis() + 90_000
        while (System.currentTimeMillis() < deadline) {
            delay(3_000)
            val done = ShizukuController.exec(
                "grep -c KSU_LOAD_DONE $rundir/ksu_load.log 2>/dev/null", 12_000
            )
            if (done.out.trim().toIntOrNull()?.let { it > 0 } == true) {
                log("[a2] loader 收尾完成")
                delay(2_000)
                return
            }
        }
        log("[a2] loader 未在 90s 内收尾（模块已加载，判定成功）")
    }

                                                       
    private suspend fun reportFinal(success: Boolean) {
        val enforce = ShizukuController.exec("getenforce 2>/dev/null", 12_000).out.trim()
        log("[a2] 当前 SELinux：${enforce.ifBlank { "未知" }}")

        val gl = readFileTail("$rundir/gl.log", 3000)
        if (gl.isNotBlank()) {
            log("[a2] ---- exploit 日志尾部 ----")
            gl.lines().filter { it.isNotBlank() }.takeLast(25).forEach {
                log("[a2] ${it.take(160)}")
            }
        }
        val kl = readFileTail("$rundir/ksu_load.log", 3000)
        if (kl.isNotBlank()) {
            log("[a2] ---- 加载器日志尾部 ----")
            kl.lines().filter { it.isNotBlank() }.takeLast(25).forEach {
                log("[a2] ${it.take(160)}")
            }
        }

        if (success) {
            status("机型专用载荷执行成功")
            LogStore.setFatal(
                "链路 A2（${pack.displayName}）执行成功：KernelSU 模块已加载",
                LogStore.RANK_RESULT
            )
        } else {
            status("机型专用载荷执行失败")
            LogStore.setFatal(
                "链路 A2（${pack.displayName}）执行失败：模块未加载，详见日志",
                LogStore.RANK_RESULT
            )
        }
    }

    private suspend fun readFileTail(path: String, bytes: Int): String {
        val r = ShizukuController.exec(
            "tail -c $bytes '$path' 2>/dev/null", 15_000
        )
        if (ShizukuController.channelDead(r)) return ""
        return r.out.replace("\u0000", "").trim()
    }
}
