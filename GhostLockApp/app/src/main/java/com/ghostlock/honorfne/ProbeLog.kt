package com.ghostlock.honorfne

/**
 * `w1.log` 里 memstart 探针结果的判读。
 *
 * 探针本身是「perf IP 采样 + 写死的 span/window 表」，表是按内核构建推的；
 * 表不对时它未必失败 —— 有时照样能凑出一个**假共识**，返回几十 GB 的 slide。
 * arm64 内核镜像的随机化窗口只有 1 GiB 量级，所以 ≥4 GiB 的 slide 一定是野值，
 * 拿它算内核地址必崩。这里把这套判据收在一处，GrindRunner 与首页共用。
 */
object ProbeLog {

    /** 超过这个值的 slide 视为不可能（真 slide 在 1 GiB 量级之内）。 */
    private const val MAX_PLAUSIBLE_SLIDE = 0x1_0000_0000L   // 4 GiB

    /** 取日志里最后一次探针报出的 slide；没有就返回 null。 */
    fun slide(text: String): Long? {
        if (text.isBlank()) return null
        val m = Regex("memstart probe: slide=0x([0-9a-fA-F]+)").findAll(text).lastOrNull() ?: return null
        return m.groupValues[1].toLongOrNull(16)
    }

    /** 探针报了 slide，但数值物理上不可能 —— 即「表不匹配」的假阳性。 */
    fun impossibleSlide(text: String): Long? =
        slide(text)?.takeIf { it >= MAX_PLAUSIBLE_SLIDE }

    fun hex(v: Long): String = "0x" + java.lang.Long.toHexString(v)
}
