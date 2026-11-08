package com.ghostlock.honorfne

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 把临时 Root 全过程持久化到用户可见的存储，供崩溃/重启后取证。
 *
 * 关键设计：写文件**完全用 app 自身的 Android API**，不依赖 Shizuku、不依赖电脑。
 * 之前用 Shizuku 的 shell 进程去 mkdir/cat 到 /storage/emulated/0，在 Android 11+
 * 上常因 FUSE 挂载命名空间看不到 SD 卡而失败（用户看到 XiaoDao 是空的）。
 *
 * 三处同时写，任一成功即可取证：
 *  1) app 私有 filesDir —— 必定可写、跨重启保留；
 *  2) 用户可见目录（优先 /storage/emulated/0/XiaoDao，失败降级到
 *     getExternalFilesDir("XiaoDao")）—— 每条日志即时追加；
 *  3) MediaStore 的「下载/XiaoDao/」—— 文件管理器最容易找到，定期覆盖写最新快照，
 *     并在启动时归档上一次（可能以崩溃结束的）会话。
 */
object LogStore {

    const val SD_DIR = "/storage/emulated/0/XiaoDao"
    const val MEDIA_SUBDIR = "XiaoDao"
    private const val PRIVATE_PREFIX = "gl_session_"

    private var ctx: Context? = null
    private var privateFile: File? = null
    private var publicFile: File? = null
    private var publicDir = ""
    private var mediaUri: Uri? = null
    private var sessionId = ""
    private val lines = StringBuilder()
    private var lastSync = 0L

    @Volatile
    private var syncing = false
    private var pendingArchive: File? = null

    fun init(context: Context) {
        ctx = context.applicationContext
        sessionId = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        privateFile = File(ctx!!.filesDir, "$PRIVATE_PREFIX$sessionId.log")

        // 上一次会话（很可能以崩溃/重启结束），启动时归档到「下载/XiaoDao」
        pendingArchive = ctx!!.filesDir
            .listFiles { _, n -> n.startsWith(PRIVATE_PREFIX) && n.endsWith(".log") }
            ?.filter { it.absolutePath != privateFile!!.absolutePath }
            ?.maxByOrNull { it.lastModified() }

        // 用户可见目录：先试用户指定的根目录，写不进去就降级到 app 外部私有目录
        publicDir = if (ensureWritable(File(SD_DIR))) {
            SD_DIR
        } else {
            (ctx!!.getExternalFilesDir(MEDIA_SUBDIR) ?: ctx!!.filesDir)
                .also { runCatching { it.mkdirs() } }
                .absolutePath
        }
        publicFile = File(publicDir, "ghostlock_latest.log")
    }

    private fun ensureWritable(dir: File): Boolean = try {
        dir.mkdirs()
        val probe = File(dir, ".probe")
        probe.writeText("ok")
        probe.delete()
        true
    } catch (_: Throwable) {
        false
    }

    fun publicDirPath(): String = publicDir
    fun sessionPath(): String = privateFile?.absolutePath ?: "-"
    fun mediaPathLabel(): String = "下载/$MEDIA_SUBDIR/"

    /** 每条日志即时落盘，不需要 Shizuku、不需要协程。 */
    @Synchronized
    fun append(line: String) {
        // 统一在落盘口过滤 NUL：w1.log 稀疏空洞曾让一份日志里出现 6300 个 NUL
        val safe = line.replace("\u0000", "")
        lines.appendLine(safe)
        try {
            privateFile?.appendText(safe + "\n")
        } catch (_: Throwable) {
        }
        try {
            publicFile?.appendText(safe + "\n")
        } catch (_: Throwable) {
        }
    }

    @Synchronized
    fun linesSnapshot(): String = lines.toString()

    /**
     * 定期同步到「下载/XiaoDao」+ 归档上次会话；force 时额外用 Shizuku 抓设备状态。
     * 即使 Shizuku 完全不可用，日志本身也已经由 append() 写好了。
     */
    suspend fun sync(force: Boolean = false, reason: String = "") {
        // force 是关键现场，不要因为一次轻量同步正在进行就整段丢掉
        if (syncing) {
            if (!force) return
            delay(1_000)
            if (syncing) return
        }
        // grind 期间降低 MediaStore 写入频率，避免重 I/O 干扰 exploit 时序
        if (!force && System.currentTimeMillis() - lastSync < 10_000) return
        syncing = true
        try {
            withContext(Dispatchers.IO) {
                writeMediaStore()
                archivePreviousSession()
                if (force) captureDeviceState(reason)
            }
            lastSync = System.currentTimeMillis()
        } catch (_: Throwable) {
        } finally {
            syncing = false
        }
    }

    private fun header(): String = buildString {
        appendLine("===== GhostLock 临时 Root 诊断日志 =====")
        appendLine("时间: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
        appendLine("会话: $sessionId")
        appendLine("用户可见目录: $publicDir")
        appendLine("下载目录副本: ${mediaPathLabel()}")
        appendLine("私有实时日志: ${sessionPath()}")
        appendLine()
    }

    /** 用 MediaStore 写「下载/XiaoDao/ghostlock_latest.txt」，同一 Uri 覆盖更新。 */
    private fun writeMediaStore() {
        val c = ctx ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val resolver = c.contentResolver
        if (mediaUri == null) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, "ghostlock_latest.txt")
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/$MEDIA_SUBDIR")
            }
            mediaUri = runCatching {
                resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            }.getOrNull()
        }
        val uri = mediaUri ?: return
        runCatching {
            resolver.openOutputStream(uri, "wt")?.use {
                it.write((header() + linesSnapshot()).toByteArray(Charsets.UTF_8))
            }
        }
    }

    private fun archivePreviousSession() {
        val f = pendingArchive ?: return
        val c = ctx ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        try {
            val name = "session_" + f.name.removePrefix(PRIVATE_PREFIX).removeSuffix(".log") + ".txt"
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/$MEDIA_SUBDIR")
            }
            val uri = c.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return
            c.contentResolver.openOutputStream(uri, "wt")?.use {
                it.write(
                    ("===== 上一次会话（可能以崩溃 / 重启结束）=====\n" + f.readText() + "\n===== END =====\n")
                        .toByteArray(Charsets.UTF_8)
                )
            }
            append("[logstore] 已归档上次会话 -> ${mediaPathLabel()}$name")
            f.delete()
            pendingArchive = null
        } catch (_: Throwable) {
        }
    }

    /** w1.log 被截断后旧进程在原偏移写入会形成 NUL 稀疏空洞，必须过滤。 */
    private fun cleanOut(s: String): String = s.replace("\u0000", "")

    /**
     * 设备侧线索。旧版把 11 条命令塞进一条超长 `sh -c`：实测 echo 的标题都在，
     * 但所有外部命令输出全空，整份快照变成空壳；且 tail 把 NUL 带进了日志。
     * 改为逐条独立执行，每条单独超时并打印 code / stderr，互不影响。
     */
    private suspend fun captureDeviceState(reason: String) {
        append("----- 设备状态快照（$reason） -----")
        if (!runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            append("[snapshot] Shizuku 未授权，跳过设备侧采集")
            append("----- END -----")
            return
        }
        val shell = ShizukuController.shellProbe()
        if (!ShizukuController.probeOk(shell)) {
            append("[snapshot] Shizuku 命令通道不可用（code=${shell.code} ${cleanOut(shell.err).trim()}）")
            append("[snapshot] 请重新通过无线调试启动 Shizuku 并授权本应用")
            append("----- END -----")
            return
        }

        val probes = listOf(
            "getenforce" to "getenforce",
            "kernelsu_modules" to "grep -c kernelsu /proc/modules",
            "boot_id" to "cat /proc/sys/kernel/random/boot_id",
            "boot_completed" to "getprop sys.boot_completed",
            "w1.log tail" to "tail -c 3000 /data/local/tmp/w1.log 2>/dev/null",
            "w2.log tail" to "tail -c 3000 /data/local/tmp/w2.log 2>/dev/null",
            "chain_status" to "cat /data/local/tmp/ksu_fne/chain_status 2>/dev/null",
            "chain.log tail" to "tail -c 3000 /data/local/tmp/ksu_fne/chain.log 2>/dev/null",
            "pstore" to "ls /sys/fs/pstore/ 2>&1",
            "dmesg tail" to "dmesg 2>&1 | tail -n 30",
            "logcat tail" to "logcat -d -t 150 2>&1 | tail -n 150"
        )
        for ((name, cmd) in probes) {
            val r = ShizukuController.exec(cmd, 12_000)
            append("=== $name (code=${r.code})")
            val out = cleanOut(r.out).trimEnd()
            if (out.isNotEmpty()) append(out.takeLast(4000))
            val err = cleanOut(r.err).trim()
            if (err.isNotEmpty()) append("[stderr] ${err.takeLast(500)}")
        }
        append("----- END -----")
    }
}
