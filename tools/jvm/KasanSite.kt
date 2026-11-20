import java.io.File
import com.ghostlock.honorfne.BootImage
import com.ghostlock.honorfne.KallsymsFinder

/**
 * 诊断：KASAN 内核里 prepare_creds 调 __kasan_slab_alloc 而非 kmem_cache_alloc。
 * 用与 CallSiteFinder 相同的 BL 解码算法，把 callee 扩展到 kasan 分配函数，
 * 找出三处函数里的分配返址与低 21 位，判断能否作为 call_site 常量。
 */
fun main(args: Array<String>) {
    val all = File(args[0]).readBytes()
    val info = BootImage.parseHeader(all.copyOfRange(0, minOf(64, all.size)))
    val image = if (info != null && info.headerVersion >= 0) {
        val off = info.kernelOffset.toInt()
        BootImage.toRawImage(all.copyOfRange(off, off + minOf(info.kernelSize, all.size - off))) { }!!.image
    } else all
    val found = KallsymsFinder.find(image) { }
        ?: error("扫不到符号表")
    val syms = found.symbols
    val textVa = found.relativeBase
    println("release=${BootImage.kernelRelease(image)} base=0x${java.lang.Long.toHexString(textVa)} syms=${syms.size}")

    val byAddr = java.util.TreeMap<Long, String>()
    for ((n, a) in syms) byAddr.putIfAbsent(a, n)

    fun readU32(b: ByteArray, o: Int) =
        (b[o].toInt() and 0xFF) or ((b[o+1].toInt() and 0xFF) shl 8) or
        ((b[o+2].toInt() and 0xFF) shl 16) or ((b[o+3].toInt() and 0xFF) shl 24)

    // 所有分配类 callee 地址（kasan + slab + kmem）
    val allocAddr = ArrayList<Pair<Long, String>>()
    for ((n, a) in syms) {
        val bn = n.substringBefore(".cfi_jt").substringBefore(".constprop.0")
        if (bn == "kmem_cache_alloc" || bn == "kmem_cache_alloc_node" ||
            bn == "__kasan_slab_alloc" || bn == "slab_alloc" || bn == "slab_alloc_node" ||
            bn == "kmem_cache_alloc_noprof" || bn == "kmem_cache_alloc_node_noprof") {
            allocAddr.add(a to bn)
        }
    }
    println("分配类 callee ${allocAddr.size} 个")

    fun dump(fn: String) {
        val va = syms[fn] ?: run { println("$fn 符号不存在"); return }
        val start = (va - textVa).toInt()
        val end = minOf(start + 0x1200, image.size - 4)
        println("==== $fn @ 0x${java.lang.Long.toHexString(va)} ====")
        var off = start
        var n = 0
        while (off <= end && n < 900) {
            val insn = readU32(image, off)
            if ((insn and (-0x04000000)) == -0x6C000000) {
                var imm = insn and 0x03FFFFFF
                if ((imm and 0x02000000) != 0) imm -= 0x04000000
                val pcVa = va + (off - start).toLong()
                val target = pcVa + (imm.toLong() shl 2)
                // 匹配分配类 target（含 ±0x80 thunk）
                val hit = allocAddr.filter { kotlin.math.abs(it.first - target) <= 0x80 }
                    .minByOrNull { kotlin.math.abs(it.first - target) }
                if (hit != null) {
                    val ret = pcVa + 4
                    println("  +0x${java.lang.Integer.toHexString(off - start)} BL -> ${hit.second} " +
                        "ret=0x${java.lang.Long.toHexString(ret)} low21=0x${java.lang.Integer.toHexString((ret and 0x1FFFFF).toInt())}")
                }
            }
            off += 4; n++
        }
    }
    dump("do_timer_create")
    dump("prepare_creds")
    dump("copy_process")
    // 也 dump prepare_exec_creds / cred 相关别名
    val credFns = syms.keys.filter { it.contains("prepare") && it.contains("cred") }.take(10)
    println("cred 相关函数: $credFns")
    for (f in credFns) dump(f)
}
