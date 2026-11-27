package com.ghostlock.honorfne

import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

   
                  
  
                                                                            
                                                                         
                                                                            
                                                                              
  
                                                                               
   
object ShizukuController {

    data class ExecResult(val code: Int, val out: String, val err: String)

    private var permissionListener: Shizuku.OnRequestPermissionResultListener? = null
    private var permissionCallback: ((Boolean) -> Unit)? = null
    private var binderListener: Shizuku.OnBinderReceivedListener? = null
    private const val PERM_REQUEST_CODE = 9527

                                                                                 
    fun isAvailable(): Boolean = runCatching { Shizuku.pingBinder() }.getOrDefault(false)

    fun hasPermission(): Boolean = runCatching {
        Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    }.getOrDefault(false)

       
                                                                            
                                                                                
                                                                    
       
    fun observeBinder(onReady: () -> Unit) {
        runCatching {
            if (binderListener == null) {
                val l = Shizuku.OnBinderReceivedListener { onReady() }
                binderListener = l
                Shizuku.addBinderReceivedListenerSticky(l)
            }
        }
    }

    fun releaseBinderObserver() {
        binderListener?.let { runCatching { Shizuku.removeBinderReceivedListener(it) } }
        binderListener = null
    }

                                                                                 
    fun requestPermission(onResult: (granted: Boolean) -> Unit) {
        runCatching {
            if (permissionListener == null) {
                val listener = Shizuku.OnRequestPermissionResultListener { code, grantResult ->
                    if (code == PERM_REQUEST_CODE) {
                        permissionCallback?.invoke(grantResult == PackageManager.PERMISSION_GRANTED)
                    }
                }
                Shizuku.addRequestPermissionResultListener(listener)
                permissionListener = listener
            }
            permissionCallback = onResult
            Shizuku.requestPermission(PERM_REQUEST_CODE)
        }.onFailure { onResult(false) }
    }

       
                                          
      
                                                                
                                              
                                                      
                                                         
       
    suspend fun killStaleExploits(): Pair<String, String> = withContext(Dispatchers.IO) {
        val before = exec("pidof e 2>/dev/null | wc -w", 10_000).out.trim().ifEmpty { "0" }
        exec("pkill -9 -x e 2>/dev/null", 15_000)
        delay(1_000)
        val after = exec("pidof e 2>/dev/null | wc -w", 10_000).out.trim().ifEmpty { "0" }
        before to after
    }

       
                                                                           
                                                                           
                                                                             
                                                                   
       
    suspend fun shellProbe(): ExecResult = exec("echo GL_SHELL_OK", 10_000)

    fun probeOk(r: ExecResult): Boolean = r.code == 0 && r.out.contains("GL_SHELL_OK")

       
                
      
                                                              
                                                        
                                        
                                   
                                    
       
    fun channelDead(r: ExecResult): Boolean =
        r.code == -1 || r.err.contains("binder haven't been received")

       
                                                                          
                                       
      
                                                                                
                                                                                
                                                                             
       
    suspend fun exec(cmd: String, timeoutMs: Long = 30000): ExecResult =
        withContext(Dispatchers.IO) {
            var process: Process? = null
            var pool: ExecutorService? = null
            try {
                process = Shizuku.newProcess(arrayOf("sh", "-c", cmd), null, null)
                val p = process
                
                runCatching { p.outputStream.close() }

                pool = Executors.newCachedThreadPool()
                val executor = pool
                
                
                val fOut = executor.submit(Callable { p.inputStream.bufferedReader().readText() })
                val fErr = executor.submit(Callable { p.errorStream.bufferedReader().readText() })
                val fCode = executor.submit(Callable { p.waitFor() })

                val code = try {
                    fCode.get(timeoutMs, TimeUnit.MILLISECONDS)
                } catch (_: TimeoutException) {
                    runCatching { p.destroy() }
                    return@withContext ExecResult(124, "", "timeout after ${timeoutMs}ms: $cmd")
                }
                val stdout = runCatching { fOut.get(3, TimeUnit.SECONDS) }.getOrDefault("")
                val stderr = runCatching { fErr.get(3, TimeUnit.SECONDS) }.getOrDefault("")
                ExecResult(code, stdout, stderr)
            } catch (t: Throwable) {
                runCatching { process?.destroy() }
                ExecResult(-1, "", t.message ?: t.toString())
            } finally {
                pool?.shutdownNow()
            }
        }

       
                                                
                                                       
       
    data class WriteOutcome(
        val ok: Boolean,
        val code: Int = 0,
        val err: String = "",
        val bytes: Int = 0,
        val dest: String = ""
    ) {
                              
        fun diagnostic(): String = if (ok) {
            "写入成功 ${bytes} B -> $dest"
        } else {
            val reason = err.trim().ifEmpty { "cat 退出码 $code（无 stderr）" }
            "写入失败 $dest（${bytes} B, code=$code）: $reason"
        }
    }

       
                                                                                 
                                                                                  
      
                                                              
       
    suspend fun writeFile(data: ByteArray, dest: String): Boolean =
        writeFileDetailed(data, dest).ok

       
                                   
      
                                                        
                                          
                                                     
                                         
       
    suspend fun writeFileDetailed(data: ByteArray, dest: String): WriteOutcome =
        withContext(Dispatchers.IO) {
            var process: java.lang.Process? = null
            
            
            val pool = java.util.concurrent.Executors.newFixedThreadPool(2)
            try {
                
                
                
                val proc = Shizuku.newProcess(
                    arrayOf("sh", "-c", "rm -rf '$dest' 2>/dev/null; cat > '$dest'"), null, null
                )
                process = proc
                
                
                val futureErr = pool.submit(java.util.concurrent.Callable {
                    proc.errorStream.bufferedReader().readText()
                })

                var written = 0
                var writeError: Throwable? = null
                val os = proc.outputStream
                try {
                    while (written < data.size) {
                        val remaining = data.size - written
                        val n = if (1_000_000 < remaining) 1_000_000 else remaining
                        os.write(data, written, n)
                        os.flush()
                        written += n
                    }
                } catch (t: Throwable) {
                    writeError = t
                } finally {
                    runCatching { os.close() }
                }

                
                
                
                val waitFuture = pool.submit(java.util.concurrent.Callable { proc.waitFor() })
                val code = runCatching {
                    waitFuture.get(20, java.util.concurrent.TimeUnit.SECONDS)
                }.getOrDefault(-1)   
                val err = runCatching {
                    futureErr.get(3, java.util.concurrent.TimeUnit.SECONDS)
                }.getOrDefault("")

                if (code == 0 && writeError == null && written == data.size) {
                    return@withContext WriteOutcome(true, 0, "", data.size, dest)
                }

                
                
                
                val target = runCatching {
                    exec(
                        "if [ -d '$dest' ]; then echo IS_DIR; " +
                            "elif [ -e '$dest' ] && [ ! -w '$dest' ]; then echo NOT_WRITABLE; " +
                            "else echo OK; fi", 8_000
                    ).out.trim()
                }.getOrDefault("")
                val parent = runCatching {
                    exec(
                        "d=\$(dirname '$dest'); if [ ! -d \"\$d\" ]; then echo PARENT_MISSING; " +
                            "elif [ ! -w \"\$d\" ]; then echo PARENT_READONLY; else echo PARENT_OK; fi",
                        8_000
                    ).out.trim()
                }.getOrDefault("")
                val alive = runCatching { probeOk(shellProbe()) }.getOrDefault(false)
                val reason = listOfNotNull(
                    err.trim().ifEmpty { null },
                    writeError?.let { "写入中断：${it.message ?: it.javaClass.simpleName}" },
                    "目标=${target.ifEmpty { "未知" }}",
                    parent.takeIf { it.isNotEmpty() && it != "PARENT_OK" },
                    "命令通道=${if (alive) "正常" else "已断"}"
                ).joinToString("；")
                WriteOutcome(false, if (alive) -3 else -1, reason, written, dest)
            } catch (t: Throwable) {
                
                val alive = runCatching { probeOk(shellProbe()) }.getOrDefault(false)
                WriteOutcome(
                    false,
                    if (alive) -3 else -1,
                    "${t.message ?: t.toString()}；命令通道=${if (alive) "正常" else "已断"}",
                    0,
                    dest
                )
            } finally {
                pool.shutdownNow()
                runCatching { process?.destroy() }
            }
        }
}
