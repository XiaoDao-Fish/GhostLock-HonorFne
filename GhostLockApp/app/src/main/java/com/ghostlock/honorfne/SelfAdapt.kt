package com.ghostlock.honorfne

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream

   
                                                                
  
                                                                   
                                                     
                                      
  
      
                                    
                                                                   
                                                                               
                                                         
                                                                    
      
  
                                                      
                                   
   
object SelfAdapt {

                                                               
    const val CUSTOM_PROFILE = -1

    private const val DIR = "adapt"

    data class Adapted(
        val release: String,
        val key: String,
        val symbolCount: Int,
        val source: String,
        val savedAt: Long,
    ) {
                          
        fun label(): String = release.ifBlank { key }
    }

    data class Outcome(
        val ok: Boolean,
        val adapted: Adapted? = null,
        val sameKernel: Boolean = false,
                                                                            
        val familySupported: Boolean = true,
        val message: String = "",
    )

                                                         
    private val PAYLOAD_FAMILIES = setOf("5.10", "5.15", "6.1", "6.6", "6.12", "6.18")

    fun family(kernel: String?): String =
        kernel.orEmpty().trim().split('.').take(2).joinToString(".")

    fun familySupported(kernel: String?): Boolean = family(kernel) in PAYLOAD_FAMILIES

    

    fun dir(ctx: Context): File = File(ctx.filesDir, DIR).apply { mkdirs() }

    private fun cfgFile(ctx: Context, key: String): File = File(dir(ctx), "$key.cfg")

    private fun metaFile(ctx: Context, key: String): File = File(dir(ctx), "$key.meta")

                            
    fun list(ctx: Context): List<Adapted> =
        dir(ctx).listFiles { f -> f.isFile && f.name.endsWith(".meta") }
            ?.mapNotNull { runCatching { parseMeta(it.readText()) }.getOrNull() }
            ?.sortedByDescending { it.savedAt }
            ?: emptyList()

                                       
    fun match(ctx: Context, kernel: String?): Adapted? {
        val key = EngineCatalog.kernelKey(kernel)
        if (key.isEmpty()) return null
        return list(ctx).firstOrNull { it.key == key && cfgFile(ctx, it.key).isFile }
    }

                                          
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

            
            
            val raw = BootImage.toRawImage(payload) { onProgress(it) }
                ?: return@withContext fail("kernel 段既不是裸 Image，也不是 LZ4/gzip（zstd/bzip2 暂不支持）")
            val image = raw.image
            if (raw.codec != "raw") {
                onProgress("${raw.codec} 解压 → ${image.size / 1024 / 1024} MiB 裸 Image")
            }

            val release = BootImage.kernelRelease(image)
            if (release.isNullOrBlank()) return@withContext fail("镜像里找不到内核版本串")
            onProgress("内核：$release")
            
            
            
            if (EngineCatalog.GHOSTLOCK_KERNELS.contains(release)) {
                return@withContext fail(
                    "$release 已由链路 A（原版 ghostlock）原生收录，无需自助适配；" +
                        "请直接回首页点「一键临时 Root」。导入本机 boot.img 反而会用它覆盖已验证配方"
                )
            }

            
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

            
            
            
            if (off.itimerSize == 0 || off.credSize == 0) {
                return@withContext fail(
                    "结构偏移不完整（k_itimer=${off.itimerSize} cred=${off.credSize}）：" +
                        "这份 cfg 即使自检 READY 也拿不到 cred。请换一份带 BTF 的同版本 boot.img"
                )
            }
            val taskBytes = runCatching { Btf.parse(BootImage.extractBtf(image)!!).sizeOf("task_struct") }
                .getOrNull() ?: 0x12C0
            
            
            
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
