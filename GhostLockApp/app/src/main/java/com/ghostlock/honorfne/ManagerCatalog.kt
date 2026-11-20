package com.ghostlock.honorfne

/**
 * 已知 Root 管理器的静态档案（2026-11-20 增补自定义分支）。
 *
 * 为什么需要这张表：
 *  - KernelSU 各分叉的 applicationId 互不相同，而且**多数不含 "ksu" 字样**：
 *    `com.sevenk.core`（7kimisu）、`com.sukisu.nova`（SukiSU-Nova）、
 *    `com.resukisu.resukisu`（BakaSU/ReSukiSU）。旧版 ManagerSelection 用
 *    `contains("ksu")` 过滤，这三个一个都扫不到，用户装完只能看到「未扫描」。
 *  - 每个分支的 /data/adb 工作目录不同（7kimisu 是 /data/adb/sevenk），
 *    排障时必须说清楚去哪儿看，否则日志永远指向 /data/adb/ksu。
 *
 * `bundledKo` = 该管理器能否直接驱动本 APK 内置的 kernelsu.ko。
 *
 * 结论来自源码与签名实测，不是猜的：
 *  - 内置模块编译时带 `KSU_EXPECTED_HASH =
 *    c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6`
 *    （KernelSU 官方 release 证书），`is_manager_apk()` 只认这个签名
 *    （KernelSU-3.3.0/kernel/manager/apk_sign.c）。
 *  - 7kimisu README 明确「内核编译期写死签名，只信任本管理器」；
 *    BakaSU / SukiSU 的 `ksu_manager_apk_gen()` 同样比对自家 EXPECTED_HASH。
 *  - 实测 7kimisu APK 证书 SHA-256 =
 *    13c37282011de6d8e002b424e41ababe094ecd74b127cb3a1a6e55ae382d8bb4，
 *    与官方 c37106…d2d6 不同 → 配内置模块必被拒。
 *
 * 因此这些分支只能「管理器 + 它自己编译的 kernelsu.ko」成对使用。
 * 本 App 不冒充能配它们：选中后明确告知，而不是让用户跑到一半才发现。
 * 提权本身仍可用 —— `ksud insmod ... allow_shell=1` 不依赖管理器 UI 授权。
 */
object ManagerCatalog {

    enum class Lineage {
        OFFICIAL,      // KernelSU 官方
        SEVENK,        // 7kimisu
        RESUKISU,      // BakaSU / ReSukiSU
        SUKISU,        // SukiSU-Nova
        SUKISU_ULTRA,  // SukiSU-Ultra
        KERNELSU_NEXT, // KernelSU Next
        APATCH,        // APatch
        MAGISK,        // Magisk
        OTHER
    }

    data class Known(
        val pkg: String,
        val label: String,
        /** 该分支的 /data/adb 工作目录，仅用于日志与排障。 */
        val workingDir: String,
        /** 能否驱动内置 kernelsu.ko（只有官方签名可以）。 */
        val bundledKo: Boolean,
        val lineage: Lineage
    )

    /** 内置模块唯一配套的包名。 */
    const val OFFICIAL_PKG = "me.weishu.kernelsu"

    private val KNOWN = listOf(
        Known(OFFICIAL_PKG, "KernelSU 官方 3.3.0", "/data/adb/ksu", true, Lineage.OFFICIAL),
        Known("com.sevenk.core", "7kimisu", "/data/adb/sevenk", false, Lineage.SEVENK),
        Known("com.sevenk.core.pr", "7kimisu（PR 版）", "/data/adb/sevenk", false, Lineage.SEVENK),
        Known("com.resukisu.resukisu", "BakaSU / ReSukiSU", "/data/adb/ksu", false, Lineage.RESUKISU),
        Known("com.sukisu.nova", "SukiSU-Nova", "/data/adb/ksu", false, Lineage.SUKISU),
        Known("com.sukisu.nova.pr", "SukiSU-Nova（PR 版）", "/data/adb/ksu", false, Lineage.SUKISU),
        Known("com.sukisu.ultra", "SukiSU-Ultra", "/data/adb/ksu", false, Lineage.SUKISU_ULTRA),
        Known("com.sukisu.ultra.debug", "SukiSU-Ultra（debug）", "/data/adb/ksu", false, Lineage.SUKISU_ULTRA),
        Known("com.rifsxd.ksunext", "KernelSU Next", "/data/adb/ksu", false, Lineage.KERNELSU_NEXT),
        Known("me.bmax.apatch", "APatch", "/data/adb/ap", false, Lineage.APATCH),
        Known("com.topjohnwu.magisk", "Magisk", "/data/adb/magisk", false, Lineage.MAGISK)
    )

    private val BY_PKG = KNOWN.associateBy { it.pkg }

    /**
     * 候选包名关键字。刻意不用裸 "ksu" 之外的宽词：
     * "kernel" 会把一堆系统 App 拉进来，"root" 会命中文件管理器。
     */
    private val KEYWORDS = listOf(
        "kernelsu", "ksunext", "sukisu", "sevenk", "resukisu",
        "bakasu", "apatch", "magisk"
    )

    fun of(pkg: String?): Known? = pkg?.trim()?.let { BY_PKG[it] }

    /** 包名像不像一个 Root 管理器（最终仍要 libksud.so 复核，这里只做粗筛）。 */
    fun looksLikeManager(pkg: String): Boolean {
        val p = pkg.lowercase()
        if (BY_PKG.containsKey(pkg)) return true
        if (KEYWORDS.any { p.contains(it) }) return true
        // `com.xxx.ksu` / `com.xxx.ksu.debug` 这类自定义包名。
        return p.split('.').any { it == "ksu" }
    }

    fun labelOf(pkg: String): String = of(pkg)?.label ?: run {
        val p = pkg.lowercase()
        when {
            p.contains("sevenk") -> "7kimisu"
            p.contains("resukisu") || p.contains("bakasu") -> "BakaSU / ReSukiSU"
            p.contains("sukisu") && p.contains("ultra") -> "SukiSU-Ultra"
            p.contains("sukisu") -> "SukiSU"
            p.contains("ksunext") -> "KernelSU Next"
            p.contains("apatch") -> "APatch"
            p.contains("magisk") -> "Magisk"
            p.contains("kernelsu") -> "KernelSU"
            else -> pkg.substringAfterLast('.').ifBlank { pkg }
        }
    }

    fun workingDirOf(pkg: String): String = of(pkg)?.workingDir ?: "/data/adb/ksu"

    /** 该包能否直接用内置 kernelsu.ko；未知包一律按「不配套」处理，宁可保守。 */
    fun bundledKoFor(pkg: String): Boolean = of(pkg)?.bundledKo == true

    /** UI 用的一行状态。 */
    fun suitabilityText(pkg: String): String = if (bundledKoFor(pkg)) {
        "内置模块可用"
    } else {
        "需自带模块"
    }
}
