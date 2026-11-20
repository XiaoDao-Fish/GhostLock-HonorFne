package com.ghostlock.honorfne

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream

/**
 * 自助适配：用户自己导入 boot.img，在本机现场生成 ExtractKit 的 336 B `device.cfg`。
 *
 * 这是把 ExtractKit 标定页（选 boot.img → 解 kallsyms / BTF → 算 call site →
 * 出 profile）搬进 HonorRoot 的最小闭环，产出的东西和内置 `cfg.bin` 里的
 * profile **完全同格式**，payload 侧不需要任何改动：
 *
 * ```
 * boot.img → 切 kernel Image → 内核版本串
 *          → BTF（有就用）拿 struct 偏移，没有就反汇编 kmem_cache_create 的 sizeof
 *          → kallsyms（BASE_RELATIVE）拿 root_user / init_user_ns / init_groups …
 *          → 三处 bl kmem_cache_alloc 的返址低 21 位（call site）
 *          → emitCfgBlob() → 336 B → filesDir/adapt/<kernelKey>.cfg
 * ```
 *
 * 落盘策略：一条内核一份文件（key 由 [EngineCatalog.kernelKey] 归一化），
 * 所以同一个 APK 可以攒多台设备的适配结果，换机不会互相覆盖。
 */
object SelfAdapt {

    /** 表示「用本机导入的 profile」，替代 EngineCatalog 里的内置 profile 下标。 */
    const val CUSTOM_PROFILE = -1

    private const val DIR = "adapt"

    data class Adapted(
        val release: String,
        val key: String,
        val symbolCount: Int,
        val source: String,
        val savedAt: Long,
    ) {
        /** 给界面用的一句短标签。 */
        fun label(): String = release.ifBlank { key }
    }

    data class Outcome(
        val ok: Boolean,
        val adapted: Adapted? = null,
        val sameKernel: Boolean = false,
        /** 内置 payload 是否有这颗内核的分支（5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18）。 */
        val familySupported: Boolean = true,
        val message: String = "",
    )

    /** 仓库里带分支专用 payload 的内核家族（其余走通用 6.x 版，可能被分支守卫拒绝）。 */
    private val PAYLOAD_FAMILIES = setOf("5.10", "5.15", "6.1", "6.6", "6.12", "6.18")

    fun family(kernel: String?): String =
        kernel.orEmpty().trim().split('.').take(2).joinToString(".")

    fun familySupported(kernel: String?): Boolean = family(kernel) in PAYLOAD_FAMILIES

    // ------------------------------------------------------------ 存取

    fun dir(ctx: Context): File = File(ctx.filesDir, DIR).apply { mkdirs() }

    private fun cfgFile(ctx: Context, key: String): File = File(dir(ctx), "$key.cfg")

    private fun metaFile(ctx: Context, key: String): File = File(dir(ctx), "$key.meta")

    /** 已有的适配结果（按保存时间倒序）。 */
    fun list(ctx: Context): List<Adapted> =
        dir(ctx).listFiles { f -> f.isFile && f.name.endsWith(".meta") }
            ?.mapNotNull { runCatching { parseMeta(it.readText()) }.getOrNull() }
            ?.sortedByDescending { it.savedAt }
            ?: emptyList()

    /** 本机内核命中的适配结果；没导入过或不匹配返回 null。 */
    fun match(ctx: Context, kernel: String?): Adapted? {
        val key = EngineCatalog.kernelKey(kernel)
        if (key.isEmpty()) return null
        return list(ctx).firstOrNull { it.key == key && cfgFile(ctx, it.key).isFile }
    }

    /** 取某条适配结果的 336 B cfg；magic 不对当没有。 */
    fun cfgFor(ctx: Context, key: String): ByteArray? {
        val f = cfgFile(ctx, key)
        if (!f.isFile) return null
        val b = runCatching { f.readBytes() }.getOrNull() ?: return null
        return if (CfgGen.isCfg(b)) b else null
    }

    fun delete(ctx: Context, key: String) {
        runCatching { cfgFile(ctx, key).delete() }
        runCatching { metaFile(ctx, key).delete() }
    }

    private fun serializeMeta(a: Adapted): String = buildString {
        appendLine("# HonorRoot self-adapt v1")
        appendLine("release=${a.release}")
        appendLine("key=${a.key}")
        appendLine("syms=${a.symbolCount}")
        appendLine("source=${a.source}")
        appendLine("at=${a.savedAt}")
    }

    private fun parseMeta(text: String): Adapted? {
        val kv = HashMap<String, String>()
        for (line in text.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val i = t.indexOf('=')
            if (i <= 0) continue
            kv[t.substring(0, i)] = t.substring(i + 1)
        }
        val key = kv["key"]?.takeIf { it.isNotBlank() } ?: return null
        return Adapted(
            release = kv["release"].orEmpty(),
            key = key,
            symbolCount = kv["syms"]?.toIntOrNull() ?: 0,
            source = kv["source"].orEmpty(),
            savedAt = kv["at"]?.toLongOrNull() ?: 0L,
        )
    }

    // ------------------------------------------------------------ 解析

    /**
     * 解析用户选的 boot.img 并落盘。
     *
     * @param deviceKernel 当前设备的 `uname -r`，只用于告诉用户「这份 profile 是不是本机的」，
     *                     不影响落盘（别人的 boot.img 也能先存下来）。
     */
    suspend fun analyze(
        ctx: Context,
        uri: Uri,
        deviceKernel: String?,
        onProgress: (String) -> Unit,
    ): Outcome = withContext(Dispatchers.IO) {
        try {
            onProgress("打开文件…")
            val header = readHeader(ctx, uri)
            if (header == null || header.size < 64) return@withContext fail("读不到文件头")
            val info = try {
                BootImage.parseHeader(header)
            } catch (e: BootImage.Unsupported) {
                return@withContext fail(e.message ?: "不支持的镜像格式")
            } ?: return@withContext fail(
                "选中的文件不是 boot 镜像（magic 不匹配 v0~v4）。" +
                    "请选择固件包里解包出的 boot.img，而不是视频、压缩包或改过后缀的文件"
            )
            onProgress(
                "boot 头：version=" + (if (info.headerVersion < 0) "raw Image" else info.headerVersion.toString()) +
                    "，kernel ${info.kernelSize / 1024 / 1024} MiB"
            )

            val payload = readKernel(ctx, uri, info)
            if (payload == null || payload.isEmpty()) return@withContext fail("切不出 kernel 段")
            onProgress("kernel 段：${payload.size / 1024 / 1024} MiB")

            // 内核常常是压缩的（荣耀 5.15 的镜像是 legacy LZ4：26 MiB → 58 MiB），
            // 先还原成裸 Image；认不出格式就明说，不拿压缩字节去扫符号表。
            val raw = BootImage.toRawImage(payload) { onProgress(it) }
                ?: return@withContext fail("kernel 段既不是裸 Image，也不是 LZ4/gzip（zstd/bzip2 暂不支持）")
            val image = raw.image
            if (raw.codec != "raw") {
                onProgress("${raw.codec} 解压 → ${image.size / 1024 / 1024} MiB 裸 Image")
            }

            val release = BootImage.kernelRelease(image)
            if (release.isNullOrBlank()) return@withContext fail("镜像里找不到内核版本串")
            onProgress("内核：$release")
            // NTH-AN00 / 5.4.295-g0fb2656b2b50 这类内核原版 ghostlock 已逐字收录，
            // 不需要也绝不应该现场做 profile：旧版解析器在这颗 5.4 镜像的旧 kallsyms
            // 布局上还会报「没找到 offsets/base」，用户白等几分钟。直接给出正解。
            if (EngineCatalog.GHOSTLOCK_KERNELS.contains(release)) {
                return@withContext fail(
                    "$release 已由链路 A（原版 ghostlock）原生收录，无需自助适配；" +
                        "请直接回首页点「一键临时 Root」。导入本机 boot.img 反而会用它覆盖已验证配方"
                )
            }

            // ---- 结构偏移：有 BTF 用 BTF，没有就反汇编
            var offsets: CfgGen.Offsets? = null
            var source = "code"
            onProgress("找内嵌 BTF…")
            val btfBytes = runCatching { BootImage.extractBtf(image) }.getOrNull()
            if (btfBytes != null) {
                runCatching { Btf.parse(btfBytes) }.onSuccess { parsed ->
                    runCatching { CfgGen.offsetsFromBtf(parsed) }.onSuccess {
                        offsets = it
                        source = "btf"
                        onProgress("BTF 解析成功（${btfBytes.size / 1024} KiB）")
                    }.onFailure { onProgress("! BTF 缺结构：${it.message}，改用指令挖掘") }
                }.onFailure { onProgress("! BTF 解析失败：${it.message}") }
            } else {
                onProgress("镜像没有内嵌 BTF（这代内核裁掉了），改用指令挖掘")
            }

            // ---- kallsyms
            onProgress("扫描 kallsyms（约 5~20 秒）…")
            val found = KallsymsFinder.find(image) { msg -> onProgress(msg) }
                ?: return@withContext fail("扫不到符号表（这版内核的 kallsyms 布局还没适配）")
            val syms = found.symbols
            onProgress("符号 ${syms.size} 个，relative_base=0x${java.lang.Long.toHexString(found.relativeBase)}")

            if (offsets == null) {
                onProgress("从指令里挖结构偏移…")
                offsets = runCatching { CfgGen.offsetsFromCode(image, syms, found.relativeBase) }
                    .getOrNull()
                if (offsets == null) {
                    return@withContext fail("指令里也挖不到结构偏移（init_posix_timers / cred_init / fork_init / exit_creds 未命中）")
                }
                onProgress("指令挖掘成功")
            }

            val off = offsets ?: return@withContext fail("结构偏移为空")
            off.pretty().lineSequence().filter { it.isNotBlank() }.forEach(onProgress)

            // ---- call site
            onProgress("反汇编 call site…")
            val call = CallSiteFinder.find(image, syms, found.relativeBase)
            if (call == null) {
                return@withContext fail("找不到 kmem_cache_alloc 调用点（漏洞可能已修复）")
            }
            call.detail.forEach { onProgress(it) }
            if (call.timerOffset == 0 || call.credLow21 == 0 || call.taskLow21 == 0) {
                return@withContext fail("call site 不全（timer=${call.timerOffset} cred=${call.credLow21} task=${call.taskLow21}）")
            }

            val missing = CfgGen.CORE_SYMBOLS.filter { (syms[it] ?: 0L) == 0L }
            if (missing.isNotEmpty()) {
                return@withContext fail("缺必需符号：${missing.joinToString()}")
            }

            // 【2026-11-20 修正】5.15.104 的日志：自助适配给出 k_itimer size=0x0、
            // cred size=0xb0，check READY 但主链 sizes 实测 0xe8/0xe8 → cred 站点
            // 与尺寸窗口全落空，连续 4 次 `cred leak failed`。这类 cfg 必须拒绝落盘。
            if (off.itimerSize == 0 || off.credSize == 0) {
                return@withContext fail(
                    "结构偏移不完整（k_itimer=${off.itimerSize} cred=${off.credSize}）：" +
                        "这份 cfg 即使自检 READY 也拿不到 cred。请换一份带 BTF 的同版本 boot.img"
                )
            }
            val taskBytes = runCatching { Btf.parse(BootImage.extractBtf(image)!!).sizeOf("task_struct") }
                .getOrNull() ?: 0x12C0
            // 运行时 cred_jar 的 objsize 会被编译选项/对齐抬高（0xb0 → 0xe8），
            // payload 的 cred 尺寸窗口以 cfg 的 CRED_REQ/CRED_ALLOC 为准；
            // 现场读 slab 值比 BTF 的 sizeof 更贴近真实 kmem 记录。
            val liveCred = liveSlabObjSize()
            val credReq = liveCred ?: off.credSize
            if (liveCred != null && liveCred != off.credSize) {
                onProgress("cred_jar 现场 objsize=${String.format("0x%x", liveCred)}（BTF ${String.format("0x%x", off.credSize)}），采用现场值")
            }
            val measured = CfgGen.Measured(
                timerSiteOffset = call.timerOffset,
                credSiteLow21 = call.credLow21,
                taskAllocLow21 = call.taskLow21,
                taskAllocBytes = taskBytes,
                credReq = credReq,
                credAlloc = (credReq + 15) / 16 * 16,
            )
            val blob = runCatching { CfgGen.emitCfgBlob(syms, off, measured) }
                .getOrElse { return@withContext fail("device.cfg 生成失败：${it.message}") }
            if (!CfgGen.isCfg(blob)) return@withContext fail("device.cfg 自检失败（magic/size 不对）")

            val key = EngineCatalog.kernelKey(release)
            if (key.isEmpty()) return@withContext fail("内核版本串无法归一化：$release")
            val adapted = Adapted(
                release = release,
                key = key,
                symbolCount = syms.size,
                source = source,
                savedAt = System.currentTimeMillis(),
            )
            cfgFile(ctx, key).writeBytes(blob)
            metaFile(ctx, key).writeText(serializeMeta(adapted))

            val same = deviceKernel?.let {
                EngineCatalog.kernelKey(it) == key
            } ?: false
            val famOk = familySupported(release)
            onProgress("device.cfg ${blob.size} B 已保存（内核 $release）")
            if (!famOk) {
                onProgress("! 内置 payload 没有 ${family(release)} 分支：cfg 有效，但要真正提权需要自己编一份该分支的 payload")
            }
            Outcome(
                ok = true,
                adapted = adapted,
                sameKernel = same,
                familySupported = famOk,
                message = when {
                    !same -> "内核与本机不同，本机不会使用这份 profile"
                    !famOk -> "已适配本机内核，但内置 payload 无 ${family(release)} 分支"
                    else -> "已适配本机内核"
                },
            )
        } catch (e: Exception) {
            fail("解析异常：${e.message ?: e.javaClass.simpleName}")
        }
    }

    private fun fail(msg: String) = Outcome(ok = false, message = msg)

    /** 现场 cred_jar objsize：优先 sysfs，回落 /proc/slabinfo 第三列。 */
    private suspend fun liveSlabObjSize(): Int? {
        val r = ShizukuController.exec(
            "cat /sys/kernel/slab/cred_jar/object_size 2>/dev/null; " +
                "awk '/^cred_jar/{print \$3; exit}' /proc/slabinfo 2>/dev/null",
            12_000
        )
        return r.out.lineSequence()
            .mapNotNull { it.trim().toIntOrNull() }
            .firstOrNull { it in 0x40..0x400 }
    }

    private fun readHeader(ctx: Context, uri: Uri): ByteArray? = runCatching {
        ctx.contentResolver.openFileDescriptor(uri, "r")!!.use { pfd ->
            FileInputStream(pfd.fileDescriptor).use { input ->
                val head = ByteArray(4096)
                var read = 0
                while (read < head.size) {
                    val n = input.read(head, read, head.size - read)
                    if (n <= 0) break
                    read += n
                }
                head.copyOf(read)
            }
        }
    }.getOrNull()

    private fun readKernel(ctx: Context, uri: Uri, info: BootImage.Info): ByteArray? = runCatching {
        ctx.contentResolver.openFileDescriptor(uri, "r")!!.use { pfd ->
            FileInputStream(pfd.fileDescriptor).use { input ->
                BootImage.readKernel(input, info)
            }
        }
    }.getOrNull()
}
