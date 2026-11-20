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
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 单一日志：所有内容（运行过程、设备现场、闪退堆栈、上次崩溃遗留）只写一份文件。
 *
 * 2026-11-15 14:51 的 2.2.9 日志暴露的问题：4 次相同会话反复重打、每次先来
 * 5 行路径说明 + 16 行系统噪音、没有版本 / 时间 / KSU 版本 / 结论，内容还散在
 * ghostlock_latest.log、gl_session_*.log、session_*.txt、crash_latest.txt、
 * w1/w2/chain.log 里。这里全部合并，并固定头部四项，让人和排障者都能一眼看懂：
 *
 *   时间：11月15日 14:59:06
 *   HonorRoot 版本：2.4.0（内部版本号 16）
 *   KSU 版本：v3.3.0 / 32601（正确）
 *   致命问题：第一步启动后设备自动重启，未拿到临时 Root
 *
 * 头部是动态的：致命问题 / KSU 版本在流程中才知道，故 setFatal() / setKsuVersion()
 * 会重写整份文件把最新结论放回最上面。正文仍逐条即时 fsync 追加，内核 panic
 * 这种非正常关机也不会丢最后几行。
 *
 * 写入位置（内容完全相同，任一成功即可取证，全程不依赖 Shizuku / 电脑）：
 *  1) 用户可见目录 /storage/emulated/0/XiaoDao/HonorRoot-Log.log（写不进则降级）；
 *  2) app 私有 filesDir/HonorRoot-Log.private.log；
 *  3) MediaStore「下载/XiaoDao/HonorRoot-Log.txt」，文件管理器最容易找到。
 */
object LogStore {

    const val SD_DIR = "/storage/emulated/0/XiaoDao"
    const val MEDIA_SUBDIR = "XiaoDao"

    // 2026-11-17 用户要求改名：日志对外统一叫 HonorRoot-Log。
    // 三处副本文件名同步改，避免历史版本残留的旧名再被读回。
    private const val FILE_NAME = "HonorRoot-Log.log"
    private const val PRIVATE_NAME = "HonorRoot-Log.private.log"
    private const val MEDIA_NAME = "HonorRoot-Log.txt"
    private const val BODY_MARK = "──────── 以下为详细记录 ────────"
    // 2026-11-20 用户要求：完整成功/失败流程（含设备侧 payload/exploit 日志）都要
    // 汇总进本文件，用户不必再去 /data/local/tmp 翻 w1/fake/ksu_stage 等散落文件。
    // 400 行装不下整条链路，提到 2500；readBackBody 用同一常量，跨重启回读一致。
    private const val MAX_BODY_LINES = 2500
    /** 单个设备日志区块最多保留的行数，防止某份日志异常巨大撑爆正文。 */
    private const val MAX_BLOCK_LINES = 600

    private var ctx: Context? = null
    private var privateFile: File? = null
    private var publicFile: File? = null
    private var publicDir = ""
    private var mediaUri: Uri? = null

    private val body = StringBuilder()
    private var appVersion = "未知"
    private var ksuVersion = "检测中…"

    /**
     * 【2026-11-17】致命问题分级：Shizuku 连接状态只是「前置条件」，
     * 不能覆盖提权链路已经得出的实质结论（内核未收录 / 自检失败 / 第一步崩溃 /
     * Root 成功）。旧版每次 Shizuku binder 抖动都 setFatal("Shizuku 未运行")，
     * 把真正的原因刷掉，用户导出日志永远只看到「Shizuku 未连接」一句话。
     *
     * 用 fatalRank 记当前结论的级别，低级别不允许覆盖高级别：
     *   0 = 空 / 运行中；1 = Shizuku 前置条件；2 = KSU 版本等环境结论；
     *   3 = 提权链路的失败/成功结论（最重要）。
     */
    const val RANK_NONE = 0
    const val RANK_PRECONDITION = 1
    const val RANK_ENV = 2
    const val RANK_RESULT = 3
    private var fatalRank = RANK_NONE

    private var fatal = "暂无（正在运行）"
    private var lastUpdateAt = System.currentTimeMillis()
    private var lastSync = 0L
    private var lastLine = ""
    private var lastLineAt = 0L

    @Volatile
    private var syncing = false

    private val ANSI = Regex("\u001B\\[[0-9;]*[A-Za-z]")
    private val TAG = Regex("^\\[([^\\]]+)\\]\\s*(.*)$", RegexOption.DOT_MATCHES_ALL)
    /** 只认新版带时分秒的行；2.2.9 那种 [init] 旧格式不混进来。 */
    private val NEW_LINE = Regex("^\\[\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\]")
    private val HEAD_TIME = SimpleDateFormat("M月d日 HH:mm:ss", Locale.CHINA)
    private val LINE_TIME = SimpleDateFormat("MM-dd HH:mm:ss", Locale.CHINA)

    /** 技术前缀 → 中文动作标签。保留原始技术细节，只把「谁在说话」翻成人话。 */
    private val LABELS = listOf(
        "init" to "启动", "logstore" to "日志", "snapshot" to "设备状态",
        "engine" to "方式", "配方" to "方式", "memstart" to "内核", "check" to "检查",
        "ksuguard" to "KSU检查", "deploy" to "物料", "cleanup" to "清理",
        "loop" to "轮次", "settle" to "准备", "W1" to "第一步", "W2" to "第二步",
        "wait" to "等待", "取证" to "上次现场", "status" to "状态",
        "root" to "结果", "error" to "错误", "warn" to "提示",
        "adapt" to "自助适配", "闪退" to "闪退", "致命" to "致命问题"
    )

    @Suppress("DEPRECATION") // minSdk 24：PackageInfo.versionCode 全版本可用
    fun init(context: Context) {
        ctx = context.applicationContext
        appVersion = runCatching {
            val p = ctx!!.packageManager.getPackageInfo(ctx!!.packageName, 0)
            // minSdk 24：longVersionCode 要 API 28，用全版本可用的 versionCode
            "${p.versionName}（内部版本号 ${p.versionCode}）"
        }.getOrDefault("未知")

        publicDir = if (ensureWritable(File(SD_DIR))) {
            SD_DIR
        } else {
            (ctx!!.getExternalFilesDir(MEDIA_SUBDIR) ?: ctx!!.filesDir)
                .also { runCatching { it.mkdirs() } }
                .absolutePath
        }
        publicFile = File(publicDir, FILE_NAME)
        privateFile = File(ctx!!.filesDir, PRIVATE_NAME)

        // 读回上一次（很可能以内核崩溃 / 重启结束）的详细记录，现场不会丢。
        val old = readBackBody()
        body.clear()
        if (old.isNotEmpty()) {
            body.append(old)
            if (!old.endsWith("\n")) body.appendLine()
        }
        // 读回上次的头部结论：设备重启后 Shizuku 必然掉线，若不恢复级别，
        // refreshShizukuState() 会立刻用 RANK_PRECONDITION 把上次「第一步崩溃」
        // 这类 RANK_RESULT 结论刷掉，用户永远只看到「Shizuku 未连接」。
        val oldFatal = readBackFatal()
        if (oldFatal.isNotEmpty()) {
            fatal = oldFatal
            fatalRank = rankOf(oldFatal)
        }
        body.appendLine("[${LINE_TIME.format(Date())}] ──── 本次打开软件 ────")
        trimBody()
        writeAll()
    }

    private fun readBackBody(): String = runCatching {
        val f = listOfNotNull(publicFile, privateFile).firstOrNull { it.isFile && it.length() > 0L }
            ?: return ""
        val text = f.readText().replace("\u0000", "")
        val idx = text.indexOf(BODY_MARK)
        val raw = if (idx >= 0) text.substring(idx + BODY_MARK.length) else text
        raw.lines()
            .filter { NEW_LINE.containsMatchIn(it) || it.contains("本次打开软件") }
            .takeLast(MAX_BODY_LINES)
            .joinToString("\n")
            .trimEnd()
    }.getOrDefault("")

    /**
     * 从上一次的日志头读回「致命问题：…」正文，空 / 运行中视为无结论。
     *
     * 【2026-11-17 真机日志实证】若上次结论是「第一步已启动，正在等待结果」
     * 这类**进行中**中间态，能读回它就说明那轮 App 进程已经死了（W1 打歪地址
     * 导致设备重启，或 App 被回收）——否则它会被同进程的 LANDED/MISS 分支
     * 改写成最终结论。此时必须改写成明确的中断结论，不能原样恢复成「正在
     * 等待」，否则重启后重开 App，头部永远卡在「正在等待结果」，用户无法
     * 判断这轮到底是成是败。
     */
    private fun readBackFatal(): String = runCatching {
        val f = listOfNotNull(publicFile, privateFile).firstOrNull { it.isFile && it.length() > 0L }
            ?: return ""
        val raw = f.readText().replace("\u0000", "").lineSequence()
            .firstOrNull { it.startsWith("致命问题：") }
            ?.removePrefix("致命问题：")?.trim()
            ?.takeIf { it.isNotEmpty() && !it.startsWith("暂无") }
            .orEmpty()
        if (raw.isEmpty()) return ""
        // 「进行中：…」能读回来，说明上次那轮进程已经死了（内核崩溃重启 /
        // App 被回收），绝不能再原样恢复成「正在写入 root 权限」。
        if (raw.startsWith("进行中")) {
            val what = raw.removePrefix("进行中：")
                .substringBefore("（").substringBefore("，").trim()
            return "上次提权中断：${what.ifBlank { "提权" }} 没有返回结论" +
                "（设备重启或 App 被回收）；请重新连接 Shizuku 后再跑一次"
        }
        if (raw.startsWith("第一步已启动")) {
            return "上次提权在第一步后中断（设备重启或 App 被回收），未确认拿到 Root；请重新连接 Shizuku 后再跑一次"
        }
        raw
    }.getOrDefault("")

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
    fun logFilePath(): String = publicFile?.absolutePath ?: sessionPath()
    fun mediaPathLabel(): String = "下载/$MEDIA_SUBDIR/"
    /** 对外展示的用户可见文件名，供 UI 提示引用，避免各处硬编码旧名。 */
    fun logFileName(): String = FILE_NAME
    fun mediaFileName(): String = MEDIA_NAME
    // writeMediaStore()/linesSnapshot() 会在 IO 协程里读 body，append() 持锁写
    // 同一个 StringBuilder；StringBuilder 非线程安全，并发 toString 会读到撕裂
    // 内容或抛异常，直接毁掉崩溃取证这一核心功能。与 append 共用同一把锁。
    @Synchronized
    fun fullText(): String = header() + BODY_MARK + "\n" + body.toString()

    /** 头部四项固定显示在最上面；时间精确到秒，随每次结论刷新。 */
    private fun header(): String = buildString {
        appendLine("══════════ HonorRoot 运行日志 ══════════")
        appendLine("时间：${HEAD_TIME.format(Date(lastUpdateAt))}")
        appendLine("HonorRoot 版本：$appVersion")
        appendLine("KSU 版本：$ksuVersion")
        appendLine("致命问题：$fatal")
        appendLine("────────────────────────────────────────")
    }

    /**
     * 每条即时落盘。返回带时间戳与中文标签的文本，界面与文件显示同一份内容。
     * 同一行 1 秒内重复出现直接丢弃，避免 2.2.9 那种整屏复制四次。
     */
    @Synchronized
    fun append(line: String): String {
        val clean = ANSI.replace(line.replace("\u0000", ""), "")
        if (clean.isBlank()) return ""
        val now = System.currentTimeMillis()
        if (clean == lastLine && now - lastLineAt < 1_000L) return ""
        lastLine = clean
        lastLineAt = now

        val stamped = stamp(clean)
        body.appendLine(stamped)
        val trimmed = trimBody()
        if (trimmed) writeAll()
        else appendToDisk(stamped + "\n")
        return stamped
    }

    /**
     * 2026-11-20：把设备侧某个日志文件（payload/exploit 的原始输出）整段汇总进
     * 本文件，让用户只打开 HonorRoot-Log 就能看到完整成功/失败流程，不必再去
     * /data/local/tmp 逐个找 w1.log / fake.log / ksu_stage.out。
     *
     * 与 append() 的区别：
     *  - 整段一次落盘（不是逐行 fsync），几十~几百行只 sync 一次；
     *  - 每行强制带时间戳前缀：readBackBody() 只回读带 [MM-dd HH:mm:ss] 的行，
     *    不带前缀的话跨重启后这段会全部丢失；
     *  - 不过 append() 的「1 秒内相同行去重」，payload 里重复的状态行要完整保留。
     */
    @Synchronized
    fun appendBlock(title: String, rawText: String) {
        val lines = rawText.lineSequence()
            .map { ANSI.replace(it.replace("\u0000", ""), "").trimEnd() }
            .filter { it.isNotBlank() }
            .take(MAX_BLOCK_LINES)
            .toList()
        if (lines.isEmpty()) return
        val time = LINE_TIME.format(Date())
        val sb = StringBuilder()
        sb.appendLine("[$time] ──── $title ────")
        lines.forEach { sb.appendLine("[$time] $it") }
        sb.appendLine("[$time] ──── $title 结束 ────")
        val block = sb.toString()
        body.append(block)
        if (trimBody()) writeAll() else appendToDisk(block)
    }

    private fun stamp(raw: String): String {
        val time = LINE_TIME.format(Date())
        val m = TAG.matchEntire(raw)
        if (m == null) return "[$time] $raw"
        val tag = m.groupValues[1]
        val label = LABELS.firstOrNull { tag.startsWith(it.first) }?.second ?: tag
        val rest = m.groupValues[2].trim()
        return if (rest.isEmpty()) "[$time] $label" else "[$time] $label｜$rest"
    }

    /** 保留最近 MAX_BODY_LINES 行；返回是否真的裁过（裁过就必须重写整份文件）。 */
    private fun trimBody(): Boolean {
        val all = body.lines()
        if (all.size <= MAX_BODY_LINES) return false
        body.clear()
        body.append(all.takeLast(MAX_BODY_LINES).joinToString("\n"))
        return true
    }

    private fun appendToDisk(text: String) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        for (f in listOfNotNull(privateFile, publicFile)) {
            runCatching {
                FileOutputStream(f, true).use { os ->
                    os.write(bytes)
                    os.flush()
                    os.fd.sync()
                }
            }
        }
    }

    /** 头部结论变化时整份重写，保证「致命问题」永远在最上面。 */
    @Synchronized
    private fun writeAll() {
        val bytes = fullText().toByteArray(Charsets.UTF_8)
        for (f in listOfNotNull(privateFile, publicFile)) {
            runCatching {
                FileOutputStream(f, false).use { os ->
                    os.write(bytes)
                    os.flush()
                    os.fd.sync()
                }
            }
        }
        writeMediaStore()
    }

    /**
     * 从结论文本反推级别，供跨进程读回旧结论时用（文件头只存文本，不存 rank）。
     */
    private fun rankOf(text: String): Int = when {
        text.startsWith("进行中") -> RANK_RESULT
        text.startsWith("暂无") -> RANK_NONE
        text.startsWith("Shizuku") -> RANK_PRECONDITION
        text.startsWith("KernelSU 管理器版本") -> RANK_ENV
        else -> RANK_RESULT
    }

    /**
     * 设置本轮致命问题（人话，不写技术黑话）。重复设置同一句不产生新行。
     *
     * @param rank 结论级别；低级别不能覆盖已得出的高级别结论。默认 RANK_RESULT
     *             （提权链路的失败 / 成功、闪退、内核未收录都是最重要的一类）。
     *             Shizuku 前置条件用 RANK_PRECONDITION，KSU 版本用 RANK_ENV。
     */
    @Synchronized
    fun setFatal(text: String, rank: Int = RANK_RESULT) {
        val t = text.trim().ifEmpty { "暂无（正在运行）" }
        if (fatal == t && fatalRank >= rank) return
        // 关键闸门：Shizuku 抖动 / KSU 版本提示不允许冲掉提权链路的实质结论。
        if (rank < fatalRank && fatalRank == RANK_RESULT) return
        if (rank < fatalRank) return
        fatal = t
        fatalRank = rank
        lastUpdateAt = System.currentTimeMillis()
        body.appendLine("[${LINE_TIME.format(Date())}] ❗ 致命问题｜$t")
        trimBody()
        writeAll()
    }

    /**
     * 运行中状态：写头部，但不把它当作结论。
     *
     * 老版本用 setFatal("暂无（正在写入 root 权限）") 表示进行中；一旦 App 被杀
     * 或设备重启，头部会永远停在「正在写入」，用户没法判断这轮到底成没成。
     * 现在统一写成「进行中：…」，readBackFatal() 见到它就知道上次是中断。
     * 记账仍用 RANK_RESULT，避免 Shizuku 前置条件把进度刷掉。
     */
    @Synchronized
    fun setProgress(text: String) {
        val t = "进行中：${text.trim().ifEmpty { "正在运行" }}"
        if (fatal == t) {
            lastUpdateAt = System.currentTimeMillis()
            writeAll()
            return
        }
        fatal = t
        fatalRank = RANK_RESULT
        lastUpdateAt = System.currentTimeMillis()
        body.appendLine("[${LINE_TIME.format(Date())}] ⏳ 进行中｜${text.trim()}")
        trimBody()
        writeAll()
    }

    /**
     * 只清掉指定类别的旧结论，不覆盖已经得出的成功 / 失败结论。
     * 例如「Shizuku 未授权」在用户授权后应消失，但「临时 Root 成功」不能被刷掉。
     */
    @Synchronized
    fun clearFatalIfStartsWith(prefix: String) {
        if (!fatal.startsWith(prefix)) return
        fatal = "暂无（正在运行）"
        fatalRank = RANK_NONE
        lastUpdateAt = System.currentTimeMillis()
        writeAll()
    }

    @Synchronized
    fun setKsuVersion(text: String) {
        val t = text.trim().ifEmpty { "未检测到" }
        if (ksuVersion == t) return
        ksuVersion = t
        lastUpdateAt = System.currentTimeMillis()
        writeAll()
    }

    @Synchronized
    fun linesSnapshot(): String = fullText()

    /** 节流同步 MediaStore 副本；force 时额外抓一次精简设备现场。 */
    suspend fun sync(force: Boolean = false, reason: String = "") {
        if (syncing) {
            if (!force) return
            delay(1_000)
            if (syncing) return
        }
        if (!force && System.currentTimeMillis() - lastSync < 10_000) return
        syncing = true
        try {
            withContext(Dispatchers.IO) {
                writeMediaStore()
                if (force) captureDeviceState(reason)
            }
            lastSync = System.currentTimeMillis()
        } catch (_: Throwable) {
        } finally {
            syncing = false
        }
    }

    /** MediaStore 写「下载/XiaoDao/HonorRoot-Log.txt」，同一 Uri 覆盖更新。 */
    private fun writeMediaStore() {
        val c = ctx ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val resolver = c.contentResolver
        if (mediaUri == null) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, MEDIA_NAME)
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
                it.write(fullText().toByteArray(Charsets.UTF_8))
            }
        }
    }

    private fun cleanOut(s: String): String = s.replace("\u0000", "")

    /**
     * 设备现场：只留三句人话，不再 dump logcat / dmesg / pstore。
     * 之前一份快照 45 行、其中 16 行是音频策略日志，四个会话复制四遍，
     * 真正有用的「设备是不是刚重启过」反而被淹了。
     */
    private suspend fun captureDeviceState(reason: String) {
        if (!runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            append("[snapshot] Shizuku 未授权，跳过设备侧采集")
            return
        }
        val shell = ShizukuController.shellProbe()
        if (!ShizukuController.probeOk(shell)) {
            append("[snapshot] Shizuku 命令通道不可用，请重新授权")
            return
        }

        val enforce = ShizukuController.exec("getenforce", 10_000).out.trim().ifEmpty { "未知" }
        val mods = ShizukuController.exec("grep -c kernelsu /proc/modules", 10_000).out.trim().ifEmpty { "0" }
        val boot = ShizukuController.exec("cat /proc/sys/kernel/random/boot_id", 10_000)
            .out.trim().take(8).ifEmpty { "未知" }
        val ksuLoaded = mods != "0" && mods != "未知"
        // 机型 + 内核版本必须进日志：适配清单是按这两个字段匹配的，
        // 之前只写 SELinux/KSU，出问题只能回头问用户是什么机器。
        val model = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
        val kernel = System.getProperty("os.version") ?: "未知"
        append(
            "[snapshot] 设备状态（$reason）：$model / $kernel，SELinux=$enforce，" +
                "KSU 模块=${if (ksuLoaded) "已加载" else "未加载"}，本次开机标识=$boot"
        )

        // 崩溃前最后一次 exploit 输出，是判断「卡在哪一步」的关键，取尾部即可。
        val w1 = ShizukuController.exec("tail -c 600 /data/local/tmp/w1.log 2>/dev/null", 10_000)
        val w1Tail = cleanOut(ANSI.replace(w1.out, "")).trim().takeLast(220)
        if (w1Tail.isNotEmpty()) append("[snapshot] 上次第一步日志结尾：$w1Tail")
        val w2 = ShizukuController.exec("tail -c 400 /data/local/tmp/w2.log 2>/dev/null", 10_000)
        val w2Tail = cleanOut(ANSI.replace(w2.out, "")).trim().takeLast(160)
        if (w2Tail.isNotEmpty()) append("[snapshot] 上次第二步日志结尾：$w2Tail")
        val chain = ShizukuController.exec(
            "tail -c 300 /data/local/tmp/ksu_fne/chain.log 2>/dev/null", 10_000
        )
        val chainTail = cleanOut(ANSI.replace(chain.out, "")).trim().takeLast(120)
        if (chainTail.isNotEmpty()) append("[snapshot] 上次 KSU 加载日志结尾：$chainTail")
    }
}
