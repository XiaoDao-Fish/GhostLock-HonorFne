package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

   
                                                            
  
                                                 
                                                                          
                                                  
                                
  
                                                       
                                              
                                    
  
                                                        
                                                    
                                            
                                     
             
   
object DeviceLogCollector {

    private data class Source(val title: String, val path: String)

       
                                                             
                                        
       
    private val SOURCES = listOf(
        Source("链路A · W1（关 SELinux）", "/data/local/tmp/w1.log"),
        Source("链路A · W2（cred 写入）", "/data/local/tmp/w2.log"),
        Source("链路A · KSU 晚加载链", "/data/local/tmp/ksu_fne/chain.log"),
        Source("链路A · root 通道", "/data/local/tmp/rs.out"),
        Source("链路B · 自检 check", "/data/local/tmp/extract-kit/check.log"),
        Source("链路B · 主链 fake", "/data/local/tmp/extract-kit/fake.log"),
        Source("链路B · payload 自有日志", "/data/local/tmp/cve-2026-98260.log"),
        Source("链路B · KSU 落地", "/data/local/tmp/ksu_stage.out")
    )

                                                
    private const val FIRST_READ_LINES = 200

       
                          
                                                      
                                                       
                              
      
                                                   
                                               
                         
       
    suspend fun collect(context: Context) = withContext(Dispatchers.IO) {
        runCatching {
            val prefs = context.getSharedPreferences("device_log_dump", Context.MODE_PRIVATE)

            
            
            val sizeCmd = SOURCES.joinToString("; ") { s ->
                "if [ -f '${s.path}' ]; then stat -c %s '${s.path}' 2>/dev/null; else echo -1; fi"
            }
            val sr = ShizukuController.exec(sizeCmd, 20_000)
            if (ShizukuController.channelDead(sr)) {
                LogStore.append("[汇总] 设备日志读取时 Shizuku 命令通道已断开，跳过")
                return@runCatching
            }
            val numeric = Regex("^-?\\d+$")
            val sizes = sr.out.lines().map { it.trim() }.filter { numeric.matches(it) }
                .map { it.toLongOrNull() ?: -1L }

            var collected = 0
            var skipped = 0
            SOURCES.forEachIndexed { idx, s ->
                val size = sizes.getOrNull(idx) ?: -1L
                if (size <= 0) return@forEachIndexed

                val key = "off:${s.path}"
                val last = prefs.getLong(key, -1L)
                if (last == size) {           
                    skipped++
                    return@forEachIndexed
                }
                
                
                val cmd = if (last in 0 until size) {
                    "tail -c +${last + 1} '${s.path}' 2>/dev/null"
                } else {
                    "tail -n $FIRST_READ_LINES '${s.path}' 2>/dev/null"
                }
                val r = ShizukuController.exec(cmd, 15_000)
                if (ShizukuController.channelDead(r)) {
                    LogStore.append("[汇总] 读取 ${s.title} 时命令通道断开，其余文件跳过")
                    return@runCatching
                }
                
                prefs.edit().putLong(key, size).apply()

                val body = r.out.replace("\u0000", "").trim('\n', '\r')
                if (body.isBlank()) return@forEachIndexed
                LogStore.appendBlock("设备日志 · ${s.title}", body)
                collected++
            }

            if (collected == 0) {
                LogStore.append(
                    if (skipped > 0) "[汇总] 设备侧日志无新增（${skipped} 份未变化，或已汇总过相同内容）"
                    else "[汇总] 设备侧日志无新增（本次未产生，或已汇总过相同内容）"
                )
            } else {
                LogStore.append("[汇总] 已将 $collected 份设备日志的**新增部分**汇总进本文件")
            }
            LogStore.sync(force = true, reason = "设备日志汇总完成")
        }.onFailure { e ->
            LogStore.append("[汇总] 设备日志汇总跳过：${e.message?.take(100) ?: "未知错误"}")
        }
    }
}
