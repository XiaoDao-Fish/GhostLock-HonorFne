package com.ghostlock.honorfne

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

   
                                   
  
                                                                      
                                                                        
                                                              
                                                
                                              
                                             
                                                             
  
                                         
                                                      
                     
  
                                                    
                                                           
                                                       
                                                          
   
object KsuUserspace {

    private const val TMP = "/data/local/tmp"
    private const val RS_IN = "$TMP/rs.in"
    private const val RS_OUT = "$TMP/rs.out"
    private const val SCRIPT = "$TMP/ksu_fne/ksu_lateload.sh"
    private const val MGR = ManagerCatalog.OFFICIAL_PKG

    private val mutex = Mutex()

                                                       
    suspend fun suReady(): Boolean {
        val r = ShizukuController.exec(
            "su -c id 2>&1; /system/bin/su -c id 2>&1", 15_000
        )
        return r.out.contains("uid=0")
    }

    private suspend fun moduleLive(): Boolean =
        ShizukuController.exec("grep -q kernelsu /proc/modules", 15_000).code == 0

    private suspend fun channelUp(maxTicks: Int = 5): Boolean {
        repeat(maxTicks) {
            val r = ShizukuController.exec(
                "grep -c 'ROOT SHELL CHANNEL UP' $RS_OUT 2>/dev/null", 15_000
            )
            if ((r.out.trim().toIntOrNull() ?: 0) > 0) return true
            delay(3_000)
        }
        return false
    }

                                                          
    private suspend fun deliverScript(log: (String) -> Unit): Boolean {
        
        
        
        
        val w = ShizukuController.exec("echo 'sh $SCRIPT' > $RS_IN", 20_000)
        if (w.code != 0) {
            log("[ksu][提示] root 通道 rs.in 当前不可写（Enforcing 已恢复），改由最终 su 复检判定")
            return false
        }
        repeat(20) { i -> 
            delay(3_000)
            val r = ShizukuController.exec("grep -c KSUTRY_DONE $RS_OUT 2>/dev/null", 15_000)
            if ((r.out.trim().toIntOrNull() ?: 0) > 0) {
                log("[ksu] KSUTRY_DONE ✔ (${(i + 1) * 3}s)")
                return true
            }
        }
        log("[ksu][提示] 60s 内未见 KSUTRY_DONE（通道可能已随 restore_enforce 退出）")
        return false
    }

                                                                 
    private suspend fun debugSuBootstrap(log: (String) -> Unit) {
        val d = "$TMP/ksu_fne"
        val inner = "$d/ksud install; $d/ksud post-fs-data; " +
            "$d/ksud services; $d/ksud boot-completed"
        val r = ShizukuController.exec("echo '$inner' | $d/ksud debug su 2>&1", 30_000)
        log("[ksu][bootstrap] rc=${r.code} out=${r.out.replace("\n", " | ").take(300).trim()}")
        if (r.err.isNotBlank()) {
            log("[ksu][bootstrap] err=${r.err.replace("\n", " | ").take(200).trim()}")
        }
    }

    private suspend fun restartManager(log: (String) -> Unit) {
        
        
        val pkg = selectedManager
        ShizukuController.exec("am force-stop $pkg", 15_000)
        if (pkg == MGR) {
            ShizukuController.exec("am start -n $pkg/$pkg.ui.MainActivity", 15_000)
        } else {
            ShizukuController.exec(
                "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p $pkg",
                15_000
            )
        }
        log("[ksu] 已重启 KernelSU 管理器 $pkg，让它重新拿 KSU 驱动 fd")
    }

                                             
    @Volatile
    var selectedManager: String = MGR


       
                                                   
                               
      
                                                           
                                                                      
                                                                    
       
    suspend fun ensure(log: (String) -> Unit): Boolean = mutex.withLock {
        if (!moduleLive()) {
            log("[ksu][跳过] /proc/modules 未见 kernelsu，本 boot 尚未加载模块")
            return@withLock false
        }
        if (suReady()) {
            log("[ksu] su 已就绪 ✔（uid=0，ksud 用户态随 insmod 一并部署）")
            restartManager(log)
            return@withLock true
        }

        log("[ksu] 模块 Live 但 su 不可用 → 尝试补装 KSU 用户态（只做一次，勿并发重试）")
        if (channelUp()) {
            log("[ksu] root FIFO 通道仍在，投递 $SCRIPT")
            deliverScript(log)
            val tail = ShizukuController.exec("tail -c 1600 $RS_OUT 2>/dev/null", 15_000)
                .out.replace("\u0000", "").replace("\n", " | ").takeLast(400).trim()
            log("[ksu] rs.out 尾部：$tail")
        } else {
            log("[ksu] root 通道已退出，改走 ksud debug su 补装")
            debugSuBootstrap(log)
        }

        delay(3_000)
        val ok = suReady()
        if (ok) {
            log("[ksu] ✔ Enforcing 下 su -c id 返回 uid=0")
            restartManager(log)
        } else {
            
            
            log("[ksu][警告] ksud 已就位但 shell 域 su 仍不可用（管理器 allowlist 未放行）")
            log("[ksu][提示] 打开一次 KernelSU 管理器，确认 shell 授权后再点「查看状态」")
            log("[ksu][提示] root 不持久，重启后重新跑一次完整流程即可")
        }
        ok
    }
}
