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

/**
 * Shizuku bridge.
 *
 * Shizuku gives us `shell` (uid 2000) privilege — exactly what the original
 * PC+adb flow used. We use [Shizuku.newProcess] to run shell commands as
 * `shell` (equivalent to `adb shell`), and to stream the prebuilt exploit +
 * KernelSU material into /data/local/tmp (the app itself cannot write there).
 *
 * The exploit self-escalates to root via the kernel bug, so `shell` is enough.
 */
object ShizukuController {

    data class ExecResult(val code: Int, val out: String, val err: String)

    private var permissionListener: Shizuku.OnRequestPermissionResultListener? = null
    private var permissionCallback: ((Boolean) -> Unit)? = null
    private var binderListener: Shizuku.OnBinderReceivedListener? = null
    private const val PERM_REQUEST_CODE = 9527

    /** Whether the Shizuku binder is alive (Shizuku app installed & running). */
    fun isAvailable(): Boolean = runCatching { Shizuku.pingBinder() }.getOrDefault(false)

    fun hasPermission(): Boolean = runCatching {
        Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    }.getOrDefault(false)

    /**
     * ShizukuProvider delivers the binder asynchronously. A sticky listener
     * refreshes the UI as soon as it arrives (or immediately if already alive).
     * The callback may run on a binder thread, NOT the main thread.
     */
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

    /** Prompt the Shizuku permission dialog; result delivered via [onResult]. */
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

    /**
     * 杀掉残留的 exploit 进程，返回 (清理前数量, 清理后数量)。
     *
     * W1 的 `GL_HOLD_WAITER=1` 会让进程 "parking forever" 永不退出；app 用
     * detached 方式启动，app 被杀/重启也不会带走它。若不清理，下一次点
     * 「一键临时 Root」就会与旧进程并发 —— 两个 slab_drain fork 风暴会触发
     * 内核保护性重启。原 PC 脚本 gl_cycle.sh 用的是同款 `pkill -9 -x e`。
     */
    suspend fun killStaleExploits(): Pair<String, String> = withContext(Dispatchers.IO) {
        val before = exec("pidof e 2>/dev/null | wc -w", 10_000).out.trim().ifEmpty { "0" }
        exec("pkill -9 -x e 2>/dev/null", 15_000)
        delay(1_000)
        val after = exec("pidof e 2>/dev/null | wc -w", 10_000).out.trim().ifEmpty { "0" }
        before to after
    }

    /**
     * Run a shell command as `shell` and capture stdout/stderr/exit code.
     * Equivalent to `adb shell <cmd>`.
     *
     * [timeoutMs] is a HARD timeout: the remote process is destroyed on expiry.
     * Without this, a hung command (e.g. `pm trim-caches`, `am kill-all`) would
     * block the whole root flow forever, because readText()/waitFor() block.
     */
    suspend fun exec(cmd: String, timeoutMs: Long = 30000): ExecResult =
        withContext(Dispatchers.IO) {
            var process: Process? = null
            var pool: ExecutorService? = null
            try {
                process = Shizuku.newProcess(arrayOf("sh", "-c", cmd), null, null)
                val p = process
                // Some commands wait for stdin EOF; we never write anything.
                runCatching { p.outputStream.close() }

                pool = Executors.newCachedThreadPool()
                val executor = pool
                // Read stdout AND stderr concurrently. Reading stdout to EOF
                // while the child keeps filling stderr can deadlock the pipe.
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

    /**
     * Stream raw bytes to a file at [dest] via `cat > dest`, running as `shell`.
     * Used to deploy the prebuilt binaries into /data/local/tmp (shell-writable).
     */
    suspend fun writeFile(data: ByteArray, dest: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val process =
                    Shizuku.newProcess(arrayOf("sh", "-c", "cat > '$dest'"), null, null)
                process.outputStream.use { os ->
                    var off = 0
                    while (off < data.size) {
                        val remaining = data.size - off
                        val n = if (1_000_000 < remaining) 1_000_000 else remaining
                        os.write(data, off, n)
                        os.flush()
                        off += n
                    }
                }
                process.waitFor() == 0
            } catch (t: Throwable) {
                false
            }
        }
}
