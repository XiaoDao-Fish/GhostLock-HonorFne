package com.ghostlock.honorfne

import android.content.Context
import android.content.res.AssetManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

   
                                                                             
                                                                               
  
                                                                   
                                                                                
  
                                                          
                                                  
                                                  
                                                             
                                                                   
                                                                                        
  
                                                                         
                                                                             
                                                                              
                                                                     
                                                                           
                                                                             
   
object AssetDeployer {

    private const val TMP = "/data/local/tmp"
    private const val STAMP_PATH = "$TMP/ksu_fne/.payload_stamp"

                                                                                   
    
    
    
    
    
    
    
    
    
    
    private const val PAYLOAD_VERSION = "3.1.2.0"

    private val KSU_EXECUTABLES = setOf(
        "chain_hook.sh", "ksu_lateload.sh", "restore_enforce.sh",
        "magiskpolicy", "ksud", "load_ko", "kmsg_dumper"
    )

                                                                
    private val CRITICAL = listOf(
        "$TMP/e",
        "$TMP/ksu_fne/kernelsu.ko",
        "$TMP/ksu_fne/ksu_lateload.sh",
        "$TMP/ksu_fne/restore_enforce.sh",
        "$TMP/ksu_fne/chain_hook.sh",
        "$TMP/ksu_fne/ksud"
    )

    @Volatile
    private var sizeCacheKey = ""
    @Volatile
    private var sizeCache: List<Int> = emptyList()

       
                                            
                                                 
                                                 
                                                       
       
    fun exploitAssetFor(kernel: String): String = EngineCatalog.exploitAssetFor(kernel)

    private fun assetSize(context: Context, path: String): Int =
        context.assets.open(path).use { it.readBytes().size }

                                                                                        
    private fun expectedSizes(context: Context, kernel: String): List<Int> {
        val key = "$PAYLOAD_VERSION|${exploitAssetFor(kernel)}"
        if (sizeCacheKey == key && sizeCache.size == CRITICAL.size) return sizeCache
        val v = listOf(
            assetSize(context, exploitAssetFor(kernel)),
            assetSize(context, "ksu_fne/kernelsu.ko"),
            assetSize(context, "ksu_fne/ksu_lateload.sh"),
            assetSize(context, "ksu_fne/restore_enforce.sh"),
            assetSize(context, "ksu_fne/chain_hook.sh"),
            assetSize(context, "ksu_fne/ksud")
        )
        sizeCache = v
        sizeCacheKey = key
        return v
    }

    private fun stampFor(kernel: String): String =
        "$PAYLOAD_VERSION|${exploitAssetFor(kernel)}"

       
                                                                                 
                                                                            
       
    suspend fun verify(
        context: Context, kernel: String, log: (String) -> Unit
    ): Boolean = withContext(Dispatchers.IO) {
        val expected = expectedSizes(context, kernel)
        val files = CRITICAL.joinToString(" ") { "'$it'" }
        val cmd = "for f in $files; do wc -c < \"\$f\" 2>/dev/null || echo -1; done; " +
            "echo ---; cat '$STAMP_PATH' 2>/dev/null || echo NO_STAMP"
        val r = ShizukuController.exec(cmd, 20_000)
        val lines = r.out.lines().map { it.trim() }.filter { it.isNotEmpty() }
        val sep = lines.indexOf("---")
        if (sep < 0) {
            log("[deploy] 版本校验无有效输出（code=${r.code} ${r.err.trim().take(120)}）")
            return@withContext false
        }
        val actual = lines.take(sep).mapNotNull { it.toIntOrNull() }
        val stamp = lines.getOrNull(sep + 1).orEmpty()
        val wantStamp = stampFor(kernel)
        if (stamp != wantStamp) {
            log("[deploy] 设备端物料版本 '$stamp' ≠ 本 APK '$wantStamp'，将强制覆盖")
            return@withContext false
        }
        if (actual.size != expected.size || actual != expected) {
            CRITICAL.forEachIndexed { i, path ->
                val a = actual.getOrNull(i) ?: -1
                val e = expected[i]
                if (a != e) log("[deploy][差异] $path：设备 $a B / 本 APK $e B")
            }
            return@withContext false
        }
        true
    }

       
                                                             
      
                                                    
                                              
                               
       
    suspend fun syncManager(context: Context): Boolean = withContext(Dispatchers.IO) {
        val pkg = ManagerSelection.selected(context)
        ShizukuController.writeFile(
            pkg.toByteArray(Charsets.US_ASCII), "$TMP/ksu_fne/.manager_pkg"
        )
    }

    suspend fun deploy(
        context: Context, log: (String) -> Unit, kernel: String = ""
    ): Boolean = withContext(Dispatchers.IO) {
        val asset = exploitAssetFor(kernel)
        log("[deploy] 开始推送物料到 $TMP ... (exploit=$asset, 内核=${kernel.ifBlank { "未读取" }})")

        
        writeAsset(context, asset, "$TMP/e", log)
        ShizukuController.exec("chmod 755 $TMP/e", 15_000)

        
        ShizukuController.exec("mkdir -p $TMP/ksu_fne", 15_000)
        deployDir(context, "ksu_fne", "$TMP/ksu_fne", log)
        KSU_EXECUTABLES.forEach {
            ShizukuController.exec("chmod 755 $TMP/ksu_fne/$it", 15_000)
        }
        
        
        
        syncManager(context)

        
        
        
        
        ShizukuController.exec(
            "rm -f $TMP/rs.in $TMP/rs.out $TMP/ksu_fne/.payload_stamp; " +
                ": > $TMP/ksu_fne/handoff",
            15_000
        )

        
        ShizukuController.exec("mkdir -p $TMP/netfix_packet", 15_000)
        deployDir(context, "netfix_packet", "$TMP/netfix_packet", log)

        
        ShizukuController.exec("mkdir -p $TMP/managers", 15_000)
        deployDir(context, "managers", "$TMP/managers", log)

        
        val wrote = ShizukuController.writeFile(
            stampFor(kernel).toByteArray(Charsets.US_ASCII), STAMP_PATH
        )
        if (!wrote) log("[deploy][警告] 版本戳写入失败，下次会重复全量部署（不影响本轮）")

        
        
        
        val ok = verify(context, kernel, log)
        if (ok) {
            log("[deploy] 完成并校验通过 ✔ 路径：$TMP/e + $TMP/ksu_fne + $TMP/netfix_packet + $TMP/managers")
        } else {
            log("[deploy][错误] 关键文件写入后校验失败，多为 Shizuku 命令通道失效")
            log("[deploy][错误] 请重新连接 Shizuku 后重试，绝不带着旧物料启动 exploit")
        }
        ok
    }

    private suspend fun deployDir(
        context: Context, assetDir: String, destDir: String, log: (String) -> Unit
    ) {
        val am = context.assets
        val entries = am.list(assetDir) ?: return
        for (entry in entries) {
            val assetPath = "$assetDir/$entry"
            val destPath = "$destDir/$entry"
            if (isAssetDir(am, assetPath)) {
                ShizukuController.exec("mkdir -p '$destPath'", 15_000)
                deployDir(context, assetPath, destPath, log)
            } else {
                writeAsset(context, assetPath, destPath, log)
            }
        }
    }

    private suspend fun writeAsset(
        context: Context, assetPath: String, destPath: String, log: (String) -> Unit
    ) {
        val data = context.assets.open(assetPath).use { it.readBytes() }
        val ok = ShizukuController.writeFile(data, destPath)
        if (!ok) log("[deploy] 失败: $assetPath -> $destPath")
        else log("[deploy] $assetPath -> $destPath (${data.size} bytes)")
    }

                                                                       
    private fun isAssetDir(am: AssetManager, path: String): Boolean {
        val listed = am.list(path)
        if (listed != null && listed.isNotEmpty()) return true
        return try {
            am.open(path).close()
            false
        } catch (_: IOException) {
            true
        }
    }
}
