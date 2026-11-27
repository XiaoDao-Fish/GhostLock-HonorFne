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
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

   
                                                        
  
                                                                
                        
                                         
                                               
                                        
   
enum class LogLevel(val tag: String) {
    DEBUG("DEBUG"), INFO("INFO"), WARN("WARN"), ERROR("ERROR")
}

   
                                        
  
                             
                                                            
                                                             
                                                            
  
                                   
                                                                          
                                   
                                                 
  
                                            
                                                  
   
object LogStore {

    const val SD_DIR = "/storage/emulated/0/XiaoDao"
    const val MEDIA_SUBDIR = "XiaoDao"

    private const val FILE_NAME = "HonorRoot-Log.log"
    private const val DEBUG_NAME = "HonorRoot-Debug.log"
    private const val MANIFEST_NAME = "HonorRoot-Manifest.txt"
    private const val PRIVATE_NAME = "HonorRoot-Log.private.log"
    private const val PRIVATE_DEBUG_NAME = "HonorRoot-Debug.private.log"
    private const val PRIVATE_MANIFEST_NAME = "HonorRoot-Manifest.private.txt"
    private const val MEDIA_NAME = "HonorRoot-Log.txt"
    private const val MEDIA_DEBUG_NAME = "HonorRoot-Debug.txt"

    private const val BODY_MARK = "──────── 以下为详细记录 ────────"
    private const val MAX_BODY_LINES = 2500
    private const val MAX_DEBUG_LINES = 6000
                                            
    private const val MAX_BLOCK_LINES = 600

    private var ctx: Context? = null
    private var privateFile: File? = null
    private var privateDebugFile: File? = null
    private var publicFile: File? = null
    private var publicDebugFile: File? = null
    private var publicDir = ""
    private var mediaUri: Uri? = null
    private var mediaDebugUri: Uri? = null

    private val body = StringBuilder()
    private val debugBody = StringBuilder()
    private var appVersion = "未知"
    private var ksuVersion = "检测中…"

       
                                               
                   
                                                
       
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
    private var lastDebugLine = ""
    private var lastDebugLineAt = 0L
    private var omittedEntries = 0

    @Volatile
    private var syncing = false

    private val ANSI = Regex("\u001B\\[[0-9;]*[A-Za-z]")
    private val TAG = Regex("^\\[([^\\]]+)\\]\\s*(.*)$", RegexOption.DOT_MATCHES_ALL)
    private val LEVEL_MARK = Regex("^\\[(DEBUG|INFO|WARN|ERROR)\\]\\s*", RegexOption.IGNORE_CASE)
                                            
    private val NEW_LINE = Regex("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} \\[(DEBUG|INFO|WARN|ERROR)\\]")
    private val LEGACY_LINE = Regex("^\\[\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\]")
    private val HEAD_TIME = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA)
    private val LINE_TIME = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA)
    private val ZIP_TIME = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.CHINA)

                                               
    private val LABELS = listOf(
        "init" to "启动", "logstore" to "日志", "snapshot" to "设备状态",
        "engine" to "方式", "配方" to "方式", "memstart" to "内核", "check" to "检查",
        "ksuguard" to "KSU检查", "deploy" to "物料", "cleanup" to "清理",
        "loop" to "轮次", "settle" to "准备", "W1" to "第一步", "W2" to "第二步",
        "wait" to "等待", "取证" to "上次现场", "status" to "状态",
        "root" to "结果", "error" to "错误", "warn" to "提示", "汇总" to "汇总",
        "适配" to "自助适配", "adapt" to "自助适配", "闪退" to "闪退", "致命" to "致命问题"
    )

    @Suppress("DEPRECATION") 
    fun init(context: Context) {
        ctx = context.applicationContext
        appVersion = runCatching {
            val p = ctx!!.packageManager.getPackageInfo(ctx!!.packageName, 0)
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
        publicDebugFile = File(publicDir, DEBUG_NAME)
        privateFile = File(ctx!!.filesDir, PRIVATE_NAME)
        privateDebugFile = File(ctx!!.filesDir, PRIVATE_DEBUG_NAME)

        
        val old = readBackFrom(listOfNotNull(publicFile, privateFile))
        body.clear()
        if (old.isNotEmpty()) {
            body.append(old)
            if (!old.endsWith("\n")) body.appendLine()
        }
        val oldDebug = readBackFrom(listOfNotNull(publicDebugFile, privateDebugFile), MAX_DEBUG_LINES)
        debugBody.clear()
        if (oldDebug.isNotEmpty()) {
            debugBody.append(oldDebug)
            if (!oldDebug.endsWith("\n")) debugBody.appendLine()
        }
        
        
        val oldFatal = readBackFatal()
        if (oldFatal.isNotEmpty()) {
            fatal = oldFatal
            fatalRank = rankOf(oldFatal)
        }
        appendTyped("本次打开软件", LogLevel.INFO)
        writeAll()
    }

    private fun readBackFrom(files: List<File>, limit: Int = MAX_BODY_LINES): String = runCatching {
        val candidates = files.filter { it.isFile && it.length() > 0L }
        if (candidates.isEmpty()) return ""
        fun extract(f: File): String {
            val text = f.readText().replace("\u0000", "")
            val idx = text.indexOf(BODY_MARK)
            val raw = if (idx >= 0) text.substring(idx + BODY_MARK.length) else text
            return raw.lines()
                .filter {
                    NEW_LINE.containsMatchIn(it) || LEGACY_LINE.containsMatchIn(it) ||
                        it.contains("本次打开软件")
                }
                .joinToString("\n").trimEnd()
        }
        val f = candidates.maxByOrNull { extract(it).length } ?: return ""
        val text = f.readText().replace("\u0000", "")
        val idx = text.indexOf(BODY_MARK)
        val raw = if (idx >= 0) text.substring(idx + BODY_MARK.length) else text
        raw.lines()
            .filter {
                NEW_LINE.containsMatchIn(it) || LEGACY_LINE.containsMatchIn(it) ||
                    it.contains("本次打开软件")
            }
            .takeLast(limit)
            .joinToString("\n")
            .trimEnd()
    }.getOrDefault("")

       
                                            
                                  
       
    private fun readBackFatal(): String = runCatching {
        val f = listOfNotNull(publicFile, privateFile).firstOrNull { it.isFile && it.length() > 0L }
            ?: return ""
        val raw = f.readText().replace("\u0000", "").lineSequence()
            .firstOrNull { it.startsWith("致命问题：") }
            ?.removePrefix("致命问题：")?.trim()
            ?.takeIf { it.isNotEmpty() && !it.startsWith("暂无") }
            .orEmpty()
        if (raw.isEmpty()) return ""
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
    fun debugFilePath(): String = publicDebugFile?.absolutePath
        ?: (privateDebugFile?.absolutePath ?: "-")
    fun manifestPath(): String = File(publicDir, MANIFEST_NAME).absolutePath
    fun mediaPathLabel(): String = "下载/$MEDIA_SUBDIR/"
    fun logFileName(): String = FILE_NAME
    fun debugFileName(): String = DEBUG_NAME
    fun mediaFileName(): String = MEDIA_NAME

    @Synchronized
    fun fullText(): String = header(FILE_NAME, false) + BODY_MARK + "\n" + body.toString()

    @Synchronized
    fun debugText(): String = header(DEBUG_NAME, true) + BODY_MARK + "\n" + debugBody.toString()

                                       
    private fun header(name: String, debug: Boolean): String = buildString {
        appendLine("══════════ HonorRoot ${if (debug) "调试日志" else "运行日志"} ══════════")
        appendLine("文件：$name")
        appendLine("时间：${HEAD_TIME.format(Date(lastUpdateAt))}")
        appendLine("HonorRoot 版本：$appVersion")
        appendLine("KSU 版本：$ksuVersion")
        appendLine("致命问题：$fatal")
        appendLine("分级：DEBUG=调试现场 / INFO=正常进展 / WARN=值得一看 / ERROR=真的出事")
        appendLine("────────────────────────────────────────")
    }

    

                                             
    @Synchronized
    fun append(line: String): String = appendTyped(line, null)

    @Synchronized
    fun debug(line: String): String = appendTyped(line, LogLevel.DEBUG)

    @Synchronized
    fun info(line: String): String = appendTyped(line, LogLevel.INFO)

    @Synchronized
    fun warn(line: String): String = appendTyped(line, LogLevel.WARN)

    @Synchronized
    fun error(line: String): String = appendTyped(line, LogLevel.ERROR)

                                                                  
    private fun resolveLevel(text: String, fallback: LogLevel): LogLevel {
        LEVEL_MARK.find(text)?.groupValues?.get(1)?.let { mark ->
            return when (mark.uppercase(Locale.ROOT)) {
                "DEBUG" -> LogLevel.DEBUG
                "WARN" -> LogLevel.WARN
                "ERROR" -> LogLevel.ERROR
                else -> LogLevel.INFO
            }
        }
        if (text.contains("[错误]") || text.startsWith("❗") ||
            text.startsWith("[fatal]", ignoreCase = true)
        ) return LogLevel.ERROR
        if (text.contains("[警告]") || text.contains("[提示]") ||
            text.startsWith("[warn]", ignoreCase = true)
        ) return LogLevel.WARN
        if (text.startsWith("[debug]", ignoreCase = true)) return LogLevel.DEBUG
        return fallback
    }

    @Synchronized
    private fun appendTyped(raw: String, forced: LogLevel?): String {
        val clean = ANSI.replace(raw.replace("\u0000", ""), "")
        if (clean.isBlank()) return ""
        val now = System.currentTimeMillis()
        val level = forced ?: resolveLevel(clean, LogLevel.INFO)
        val prevLine = if (level == LogLevel.DEBUG) lastDebugLine else lastLine
        val prevAt = if (level == LogLevel.DEBUG) lastDebugLineAt else lastLineAt
        if (clean == prevLine && now - prevAt < 1_000L) return ""
        if (level == LogLevel.DEBUG) {
            lastDebugLine = clean
            lastDebugLineAt = now
        } else {
            lastLine = clean
            lastLineAt = now
        }

        val stamped = stamp(clean, level)
        if (level == LogLevel.DEBUG) {
            debugBody.appendLine(stamped)
            if (trimDebug()) writeAll() else appendToDisk(stamped + "\n", level)
        } else {
            body.appendLine(stamped)
            if (trimBody()) writeAll() else appendToDisk(stamped + "\n", level)
        }
        return stamped
    }

       
                                                 
                                            
                                    
       
    @Synchronized
    fun appendBlock(title: String, rawText: String) {
        val allLines = rawText.lineSequence()
            .map { ANSI.replace(it.replace("\u0000", ""), "").trimEnd() }
            .filter { it.isNotBlank() }
            .toList()
        if (allLines.isEmpty()) return
        if (allLines.size > MAX_BLOCK_LINES) omittedEntries += allLines.size - MAX_BLOCK_LINES
        val lines = allLines.take(MAX_BLOCK_LINES)
        val time = LINE_TIME.format(Date())
        val sb = StringBuilder()
        sb.appendLine("$time [DEBUG] ──── $title ────")
        lines.forEach { sb.appendLine("$time [DEBUG] $it") }
        sb.appendLine("$time [DEBUG] ──── $title 结束 ────")
        val block = sb.toString()
        debugBody.append(block)
        if (trimDebug()) writeAll() else appendToDisk(block, LogLevel.DEBUG)
        appendTyped("[汇总] $title：已写入 ${lines.size} 行到调试日志 ${DEBUG_NAME}", LogLevel.INFO)
    }

    private fun stamp(raw: String, level: LogLevel): String {
        val time = LINE_TIME.format(Date())
        val cleaned = LEVEL_MARK.replace(raw, "").trim()
        val m = TAG.matchEntire(cleaned)
        val body = if (m == null) cleaned else {
            val tag = m.groupValues[1]
            val label = LABELS.firstOrNull { tag.startsWith(it.first) }?.second ?: tag
            val rest = m.groupValues[2].trim()
            if (rest.isEmpty()) "[$label]" else "[$label] $rest"
        }
        return "$time [${level.tag}] ${body.ifEmpty { "（空）" }}"
    }

                                           
    private fun trimBody(): Boolean = trim(buffer = body, limit = MAX_BODY_LINES)
    private fun trimDebug(): Boolean = trim(buffer = debugBody, limit = MAX_DEBUG_LINES)

    private fun trim(buffer: StringBuilder, limit: Int): Boolean {
        val all = buffer.lines()
        if (all.size <= limit) return false
        buffer.clear()
        buffer.append(all.takeLast(limit).joinToString("\n"))
        return true
    }

    private fun appendToDisk(text: String, level: LogLevel) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        val targets = if (level == LogLevel.DEBUG) {
            listOfNotNull(privateDebugFile, publicDebugFile)
        } else {
            listOfNotNull(privateFile, publicFile)
        }
        for (f in targets) {
            runCatching {
                FileOutputStream(f, true).use { os ->
                    os.write(bytes)
                    os.flush()
                    os.fd.sync()
                }
            }
        }
    }

                                    
    @Synchronized
    private fun writeAll() {
        writePair(fullText().toByteArray(Charsets.UTF_8), privateFile, publicFile)
        writePair(debugText().toByteArray(Charsets.UTF_8), privateDebugFile, publicDebugFile)
        writeManifest()
        writeMediaStore()
    }

    private fun writePair(bytes: ByteArray, vararg files: File?) {
        for (f in files.filterNotNull()) {
            runCatching {
                FileOutputStream(f, false).use { os ->
                    os.write(bytes)
                    os.flush()
                    os.fd.sync()
                }
            }
        }
    }

    private fun rankOf(text: String): Int = when {
        text.startsWith("进行中") -> RANK_RESULT
        text.startsWith("暂无") -> RANK_NONE
        text.startsWith("Shizuku") -> RANK_PRECONDITION
        text.startsWith("KernelSU 管理器版本") -> RANK_ENV
        else -> RANK_RESULT
    }

       
                                            
                               
       
    @Synchronized
    fun setFatal(text: String, rank: Int = RANK_RESULT) {
        val t = text.trim().ifEmpty { "暂无（正在运行）" }
        if (fatal == t && fatalRank >= rank) return
        if (rank < fatalRank && fatalRank == RANK_RESULT) return
        if (rank < fatalRank) return
        fatal = t
        fatalRank = rank
        lastUpdateAt = System.currentTimeMillis()
        val level = when {
            t.startsWith("无") || t.startsWith("当前已有") -> LogLevel.INFO
            rank == RANK_PRECONDITION || rank == RANK_ENV -> LogLevel.WARN
            else -> LogLevel.ERROR
        }
        appendTyped("❗ 结论｜$t", level)
        trimBody()
        writeAll()
    }

                                   
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
        appendTyped("⏳ 进行中｜${text.trim()}", LogLevel.INFO)
        trimBody()
        writeAll()
    }

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
                writeManifest()
                writeMediaStore()
                if (force) captureDeviceState(reason)
            }
            lastSync = System.currentTimeMillis()
        } catch (_: Throwable) {
        } finally {
            syncing = false
        }
    }

    private fun writeMediaStore() {
        val c = ctx ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val resolver = c.contentResolver
        runCatching {
            if (mediaUri == null) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, MEDIA_NAME)
                    put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/$MEDIA_SUBDIR")
                }
                mediaUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            }
            mediaUri?.let { uri ->
                resolver.openOutputStream(uri, "wt")?.use {
                    it.write(fullText().toByteArray(Charsets.UTF_8))
                }
            }
            if (mediaDebugUri == null) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, MEDIA_DEBUG_NAME)
                    put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/$MEDIA_SUBDIR")
                }
                mediaDebugUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            }
            mediaDebugUri?.let { uri ->
                resolver.openOutputStream(uri, "wt")?.use {
                    it.write(debugText().toByteArray(Charsets.UTF_8))
                }
            }
        }
    }

    

    private fun sha256(file: File): String = runCatching {
        MessageDigest.getInstance("SHA-256").digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }
    }.getOrDefault("未知")

    private fun lineCount(file: File): Int = runCatching {
        file.readLines().size
    }.getOrDefault(0)

                                                                 
    @Synchronized
    fun manifestText(): String {
        val main = publicFile
        val dbg = publicDebugFile
        val mani = File(publicDir, MANIFEST_NAME)
        return buildString {
            appendLine("== HonorRoot 日志包 v2 ==")
            appendLine("生成时间: ${HEAD_TIME.format(Date())}")
            appendLine("任务: 临时 Root")
            appendLine("状态: $fatal")
            appendLine()
            appendLine("== 设备事实 ==")
            appendLine("机型: ${Build.MANUFACTURER} ${Build.MODEL}")
            appendLine("内核: ${System.getProperty("os.version") ?: "未知"}")
            appendLine("Android: API ${Build.VERSION.SDK_INT}")
            appendLine("KSU 版本: $ksuVersion")
            appendLine()
            appendLine("== App 信息 ==")
            appendLine("包名: ${ctx?.packageName ?: "未知"}")
            appendLine("版本: $appVersion")
            appendLine("日志包格式: v2（主日志 + 调试日志 + 清单，zip 分享）")
            appendLine()
            appendLine("== 文件清单 ==")
            listOfNotNull(main, dbg).forEach { f ->
                appendLine("${f.name}: ${f.length()} 字节 / ${lineCount(f)} 行 / sha256 ${sha256(f)}")
            }
            appendLine("HonorRoot-Manifest.txt: 清单自引用，不参与 sha256 校验")
            appendLine()
            appendLine("== 分级说明 ==")
            appendLine("DEBUG: 调试现场，payload/exploit 原始输出与命令痕迹，不致命")
            appendLine("INFO: 正常进展，启动 / 选路 / 物料就绪 / 当前步骤 / 成功结论")
            appendLine("WARN: 不致命但值得看一眼，前置条件不满足或可重试的异常")
            appendLine("ERROR: 真的出事了，提权失败 / 内核崩溃 / 闪退 / 写入失败")
            appendLine()
            appendLine("== 诊断表 ==")
            appendLine("omittedEntries: $omittedEntries")
            appendLine("truncatedChars: 0")
            appendLine("mainBodyLines: ${body.lines().size}")
            appendLine("debugBodyLines: ${debugBody.lines().size}")
            appendLine("interrupted: ${fatal.startsWith("进行中")}")
        }
    }

    @Synchronized
    private fun writeManifest() {
        val bytes = manifestText().toByteArray(Charsets.UTF_8)
        writePair(bytes, File(ctx?.filesDir ?: return, PRIVATE_MANIFEST_NAME), File(publicDir, MANIFEST_NAME))
    }

       
                                               
                                       
       
    @Synchronized
    fun zipBundle(): File? {
        val dir = File(publicDir)
        if (!dir.isDirectory && !runCatching { dir.mkdirs() }.getOrDefault(false)) return null
        writeManifest()
        val zip = File(dir, "HonorRoot-Logs-${ZIP_TIME.format(Date())}.zip")
        val entries = listOfNotNull(publicFile, publicDebugFile, File(publicDir, MANIFEST_NAME))
            .filter { it.isFile && it.length() > 0L }
        if (entries.isEmpty()) return null
        runCatching {
            ZipOutputStream(FileOutputStream(zip)).use { out ->
                entries.forEach { f ->
                    out.putNextEntry(ZipEntry(f.name))
                    f.inputStream().use { it.copyTo(out) }
                    out.closeEntry()
                }
                out.flush()
            }
        }.getOrElse { return null }
        return zip.takeIf { it.isFile && it.length() > 0L }
    }

    private suspend fun captureDeviceState(reason: String) {
        if (!runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            append("[snapshot] Shizuku 未授权，跳过设备侧采集")
            return
        }
        val shell = ShizukuController.shellProbe()
        if (!ShizukuController.probeOk(shell)) {
            warn("[snapshot] Shizuku 命令通道不可用，请重新授权")
            return
        }

        val enforce = ShizukuController.exec("getenforce", 10_000).out.trim().ifEmpty { "未知" }
        val mods = ShizukuController.exec("grep -c kernelsu /proc/modules", 10_000).out.trim().ifEmpty { "0" }
        val boot = ShizukuController.exec("cat /proc/sys/kernel/random/boot_id", 10_000)
            .out.trim().take(8).ifEmpty { "未知" }
        val ksuLoaded = mods != "0" && mods != "未知"
        val model = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
        val kernel = System.getProperty("os.version") ?: "未知"
        append(
            "[snapshot] 设备状态（$reason）：$model / $kernel，SELinux=$enforce，" +
                "KSU 模块=${if (ksuLoaded) "已加载" else "未加载"}，本次开机标识=$boot"
        )

        val w1 = ShizukuController.exec("tail -c 600 /data/local/tmp/w1.log 2>/dev/null", 10_000)
        val w1Tail = ANSI.replace(w1.out, "").trim().takeLast(220)
        if (w1Tail.isNotEmpty()) debug("[snapshot] 上次第一步日志结尾：$w1Tail")
        val w2 = ShizukuController.exec("tail -c 400 /data/local/tmp/w2.log 2>/dev/null", 10_000)
        val w2Tail = ANSI.replace(w2.out, "").trim().takeLast(160)
        if (w2Tail.isNotEmpty()) debug("[snapshot] 上次第二步日志结尾：$w2Tail")
        val chain = ShizukuController.exec(
            "tail -c 300 /data/local/tmp/ksu_fne/chain.log 2>/dev/null", 10_000
        )
        val chainTail = ANSI.replace(chain.out, "").trim().takeLast(120)
        if (chainTail.isNotEmpty()) debug("[snapshot] 上次 KSU 加载日志结尾：$chainTail")
    }
}
