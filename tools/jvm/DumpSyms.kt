import java.io.File
import com.ghostlock.honorfne.BootImage
import com.ghostlock.honorfne.KallsymsFinder

/** 从 boot.img/Image dump 关键符号的绝对地址，与内置 profile 交叉验证。 */
fun main(args: Array<String>) {
    val all = File(args[0]).readBytes()
    val info = BootImage.parseHeader(all.copyOfRange(0, minOf(64, all.size)))
    val image = if (info != null && info.headerVersion >= 0) {
        val off = info.kernelOffset.toInt()
        val payload = all.copyOfRange(off, off + minOf(info.kernelSize, all.size - off))
        BootImage.toRawImage(payload) { }!!.image
    } else all // 裸 Image（headerVersion=-1 或不可识别）直接就是
    val release = BootImage.kernelRelease(image)
    println("release=$release")
    val found = KallsymsFinder.find(image) { } ?: error("扫不到符号表")
    val syms = found.symbols
    println("symbols=${syms.size} base=0x${java.lang.Long.toHexString(found.relativeBase)}")
    val want = listOf(
        "do_timer_create", "selinux_state", "panic_on_warn", "root_user",
        "init_user_ns", "init_ucounts", "init_groups"
    )
    println("==== profile #64 关键符号现场地址 ====")
    for (s in want) {
        val v = syms[s]
        println("  %-20s %s".format(s, if (v == null) "缺" else "0x" + java.lang.Long.toHexString(v)))
    }
}
