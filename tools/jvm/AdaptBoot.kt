import java.io.File
import com.ghostlock.honorfne.BootImage
import com.ghostlock.honorfne.KallsymsFinder
import com.ghostlock.honorfne.CallSiteFinder
import com.ghostlock.honorfne.CfgGen
import com.ghostlock.honorfne.Btf

/**
 * JVM 离线驱动：复刻 SelfAdapt.analyze() 的核心流程，从 boot.img 生成 device.cfg。
 * 核心类（BootImage/KallsymsFinder/CfgGen/CallSiteFinder/Btf）零 Android 依赖，可直接 JVM 跑。
 */
fun main(args: Array<String>) {
    val bootPath = args[0]
    val outPath = if (args.size > 1) args[1] else "device.cfg"
    val all = File(bootPath).readBytes()
    fun prog(s: String) = println("[adapt] $s")

    val info = BootImage.parseHeader(all.copyOfRange(0, minOf(64, all.size)))
        ?: error("不是可识别的 boot.img")
    // headerVersion=-1 表示不是 boot.img，而是直接的裸内核 Image（用户已提取好）。
    val isBare = info.headerVersion < 0
    prog(if (isBare)
        "裸内核 Image: ${all.size / 1024 / 1024} MiB（跳过 boot 头切割）"
    else
        "boot 头: version=${info.headerVersion}, kernel ${info.kernelSize / 1024 / 1024} MiB, offset=${info.kernelOffset}")

    val payload = if (isBare) all else {
        val off = info.kernelOffset.toInt()
        all.copyOfRange(off, off + minOf(info.kernelSize, all.size - off))
    }
    val raw = BootImage.toRawImage(payload) { prog(it) } ?: error("kernel 既不是裸 Image 也不是 LZ4/gzip")
    val image = raw.image
    prog("kernel 解码: ${raw.codec} -> ${image.size / 1024 / 1024} MiB 裸 Image")

    val release = BootImage.kernelRelease(image) ?: error("找不到内核版本串")
    prog("内核版本: $release")

    // 结构偏移：优先 BTF
    var offsets: CfgGen.Offsets? = null
    var source = "code"
    val btfBytes = runCatching { BootImage.extractBtf(image) }.getOrNull()
    if (btfBytes != null) {
        runCatching { Btf.parse(btfBytes) }.onSuccess { parsed ->
            runCatching { CfgGen.offsetsFromBtf(parsed) }.onSuccess {
                offsets = it; source = "btf"
                prog("BTF 解析成功 (${btfBytes.size / 1024} KiB)")
            }.onFailure { prog("! BTF 缺结构: ${it.message}") }
        }.onFailure { prog("! BTF 解析失败: ${it.message}") }
    } else {
        prog("无内嵌 BTF")
    }

    // kallsyms
    prog("扫描 kallsyms...")
    val found = KallsymsFinder.find(image) { prog(it) } ?: error("扫不到符号表")
    val syms = found.symbols
    prog("符号 ${syms.size} 个, relative_base=0x${java.lang.Long.toHexString(found.relativeBase)}")

    if (offsets == null) {
        prog("从指令挖结构偏移...")
        offsets = runCatching { CfgGen.offsetsFromCode(image, syms, found.relativeBase) }.getOrNull()
        if (offsets == null) error("指令里挖不到结构偏移")
        prog("指令挖掘成功")
    }
    val o = offsets!!
    prog("==== 结构偏移 ====")
    o.pretty().lineSequence().filter { it.isNotBlank() }.forEach { println("  $it") }

    // call site
    prog("反汇编 call site...")
    val call = CallSiteFinder.find(image, syms, found.relativeBase) ?: error("找不到 kmem_cache_alloc 调用点")
    call.detail.forEach { prog(it) }
    if (call.timerOffset == 0 || call.credLow21 == 0 || call.taskLow21 == 0) {
        error("call site 不全: timer=${call.timerOffset} cred=${call.credLow21} task=${call.taskLow21}")
    }

    val missing = CfgGen.CORE_SYMBOLS.filter { (syms[it] ?: 0L) == 0L }
    if (missing.isNotEmpty()) error("缺必需符号: ${missing.joinToString()}")

    val taskBytes = runCatching { Btf.parse(BootImage.extractBtf(image)!!).sizeOf("task_struct") }.getOrNull() ?: 0x12C0
    val measured = CfgGen.Measured(
        timerSiteOffset = call.timerOffset,
        credSiteLow21 = call.credLow21,
        taskAllocLow21 = call.taskLow21,
        taskAllocBytes = taskBytes,
        credReq = o.credSize,
        credAlloc = (o.credSize + 15) / 16 * 16,
    )
    val blob = CfgGen.emitCfgBlob(syms, o, measured)
    if (!CfgGen.isCfg(blob)) error("device.cfg 自检失败")
    File(outPath).writeBytes(blob)
    prog("device.cfg ${blob.size} B 已写 $outPath")
    prog("kernelKey = ${kernelKey(release)}")
    prog("family 判定见 App SelfAdapt.family()")
    println("RESULT_OK=$release")
}

fun kernelKey(release: String?): String {
    val s = release?.trim()?.lowercase().orEmpty()
    if (s.isEmpty()) return ""
    val ver = Regex("^\\d+\\.\\d+\\.\\d+").find(s)?.value ?: s.take(8)
    val hash = Regex("g([0-9a-f]{8,40})").find(s)?.groupValues?.get(1)?.take(12)
    return if (hash.isNullOrEmpty()) ver else "$ver-g$hash"
}
