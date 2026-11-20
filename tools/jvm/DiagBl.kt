import java.io.File
import com.ghostlock.honorfne.BootImage
import com.ghostlock.honorfne.KallsymsFinder

/** 诊断：dump 指定函数体里所有 BL 目标，解析成 kallsyms 符号名。 */
fun main(args: Array<String>) {
    val all = File(args[0]).readBytes()
    val fns = args.drop(1)
    val info = BootImage.parseHeader(all.copyOfRange(0, 64))!!
    val off = info.kernelOffset.toInt()
    val payload = all.copyOfRange(off, off + minOf(info.kernelSize, all.size - off))
    val image = BootImage.toRawImage(payload)!!.image
    val found = KallsymsFinder.find(image)!!
    val syms = found.symbols
    val textVa = found.relativeBase

    // name -> addr 反查表
    val byAddr = java.util.TreeMap<Long, String>()
    for ((n, a) in syms) byAddr.putIfAbsent(a, n)

    fun readU32(b: ByteArray, o: Int) =
        (b[o].toInt() and 0xFF) or ((b[o+1].toInt() and 0xFF) shl 8) or
        ((b[o+2].toInt() and 0xFF) shl 16) or ((b[o+3].toInt() and 0xFF) shl 24)

    for (fn in fns) {
        if (syms[fn] == null) { println("$fn: 符号不存在"); continue }
        val va: Long = syms[fn]!!
        val start: Int = (va - textVa).toInt()
        val end = minOf(start + 0x1200, image.size - 4)
        println("==== $fn @ 0x${java.lang.Long.toHexString(va)} (file 0x${java.lang.Integer.toHexString(start)}) ====")
        var off2: Int = start
        var n = 0
        while (off2 <= end && n < 400) {
            val insn = readU32(image, off2)
            if (true) {
                var imm = insn and 0x03FFFFFF
                if ((imm and 0x02000000) != 0) imm -= 0x04000000
                val pcVa: Long = va + (off2 - start).toLong()
                val target = pcVa + (imm.toLong() shl 2)
                // 找最近的符号（前 0x80）
                val e = byAddr.ceilingEntry(target)
                var name = e?.value
                val cand = byAddr.lowerEntry(target)
                if (cand != null && target - cand.key < 0x100) name = cand.value
                if ((insn and (-0x04000000)) == -0x6C000000) println("  +0x${java.lang.Integer.toHexString(off2-start)} BL -> ${name ?: "?"}") else if ((insn and (0xfffffc1f.toInt())) == 0xd63f0000.toInt()) println("  +0x${java.lang.Integer.toHexString(off2-start)} BLR (indirect!)")
                n++
            }
            off2 += 4
        }
    }
}
