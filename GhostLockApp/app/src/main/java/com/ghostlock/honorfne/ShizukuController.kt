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
     * Real command-channel probe. pingBinder() can still return true while
     * Shizuku.newProcess() silently fails — observed in the field as every
     * shell command (even `getenforce`) returning an empty stdout, while the
     * app kept treating stale w1.log content as a running exploit.
     */
    suspend fun shellProbe(): ExecResult = exec("echo GL_SHELL_OK", 10_000)

    fun probeOk(r: ExecResult): Boolean = r.code == 0 && r.out.contains("GL_SHELL_OK")

    /**
     * 命令通道是否已断。
     *
     * exec() 把所有 Throwable（binder 未收到 / 权限被收回 / Shizuku 进程被杀）
     * 统一吞成 `code = -1` 且 stdout 为空。调用方如果只判「输出里有没有预期内容」，
     * 就会把「通道断了」误报成「文件不存在 / 命令没输出」这类假结论。
     * 2026-11-14 的真机日志就是这么把通道掉线说成了
     * 「/data/local/tmp/e 不存在或不可执行」。
     */
    fun channelDead(r: ExecResult): Boolean =
        r.code == -1 || r.err.contains("binder haven't been received")

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
     * 一次写文件的完整结果。模仿 MagicRoot 的错误报告：失败时把「为什么失败」
     * 带回来（退出码 / stderr / 异常 / 目标路径），而不是只回一个干巴巴的 false。
     */
    data class WriteOutcome(
        val ok: Boolean,
        val code: Int = 0,
        val err: String = "",
        val bytes: Int = 0,
        val dest: String = ""
    ) {
        /** 一行人话诊断，直接可写进日志。 */
        fun diagnostic(): String = if (ok) {
            "写入成功 ${bytes} B -> $dest"
        } else {
            val reason = err.trim().ifEmpty { "cat 退出码 $code（无 stderr）" }
            "写入失败 $dest（${bytes} B, code=$code）: $reason"
        }
    }

    /**
     * Stream raw bytes to a file at [dest] via `cat > dest`, running as `shell`.
     * Used to deploy the prebuilt binaries into /data/local/tmp (shell-writable).
     *
     * 保留原 Boolean 签名给其它调用点；真正需要诊断的链路 B 用 [writeFileDetailed]。
     */
    suspend fun writeFile(data: ByteArray, dest: String): Boolean =
        writeFileDetailed(data, dest).ok

    /**
     * 带诊断的写文件：连 stderr、退出码、异常都带回来。
     *
     * 之前只 `waitFor() == 0` 并吞掉 Throwable，设备上报「写入失败」时日志里
     * 没有任何原因（目录只读 / 文件被占 / 通道掉线都长一个样）。这里把
     * `cat > dest` 的 stderr 和进程退出码一并捕获；写失败后再补一次目录/目标
     * 状态探测，让日志能区分「目录只读」「目标是目录」「通道断了」等情形。
     */
    suspend fun writeFileDetailed(data: ByteArray, dest: String): WriteOutcome =
        withContext(Dispatchers.IO) {
            var process: java.lang.Process? = null
            // 两个独立任务（读 stderr、waitFor）各占一个线程；单线程池下
            // readText() 阻塞会让 waitFor 永远排不上队，超时形同虚设。
            val pool = java.util.concurrent.Executors.newFixedThreadPool(2)
            try {
                // 先删再写：目标可能是上一次 root 会话留下的只读文件，也可能
                // 是仍在执行的二进制（ETXTBSY）。直接 `cat >` 覆盖会让 sh 在
                // 重定向阶段就退出，父进程只看到 EPIPE，真正的 errno 反而丢了。
                val proc = Shizuku.newProcess(
                    arrayOf("sh", "-c", "rm -rf '$dest' 2>/dev/null; cat > '$dest'"), null, null
                )
                process = proc
                // stderr 必须从进程启动就开始读：cat 失败时它的报错在 sh 退出
                // 前就写进管道，等写完再读只剩 EPIPE。
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

                // waitFor 必须带超时：目标若是 FIFO/被 lock 的文件，cat 会永久阻塞，
                // os.write 写满管道后也跟着卡死，整条提权协程无期限占住 IO 线程。
                // exec() 有硬超时而这里曾没有，是通道假活时的死锁点。
                val waitFuture = pool.submit(java.util.concurrent.Callable { proc.waitFor() })
                val code = runCatching {
                    waitFuture.get(20, java.util.concurrent.TimeUnit.SECONDS)
                }.getOrDefault(-1)   // 超时 → -1，进入下面的失败诊断分支
                val err = runCatching {
                    futureErr.get(3, java.util.concurrent.TimeUnit.SECONDS)
                }.getOrDefault("")

                if (code == 0 && writeError == null && written == data.size) {
                    return@withContext WriteOutcome(true, 0, "", data.size, dest)
                }

                // 目标 / 父目录现场 + 通道真探活。EPIPE 只说明 cat 退出了，
                // 不代表 Shizuku 掉线；上一版把它一律当成「命令通道中断」，
                // 让用户反复重连也修不好一个纯粹的文件占用问题。
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
                // newProcess 本身失败：这时才需要怀疑通道，仍然实测一次再定性
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
