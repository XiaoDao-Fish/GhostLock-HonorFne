package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Root 管理器选择（移植月虹 1.7.0 的多管理器思路）。
 *
 * 旧版 HonorRoot 把 `me.weishu.kernelsu` 写死在三个地方（ExtractKitRunner /
 * KsuUserspace / KsuVersionGuard），用户装了 KernelSU Next 等兼容管理器时，
 * 要么守卫把它卸掉重装官方版，要么 payload 找不到目标管理器的 libksud.so。
 *
 * 这里不再假定某个固定包名：扫描已经安装、且 APK 里带 `libksud.so` 的应用，
 * 让用户选一个；选择落到 SharedPreferences，链路 A/B 与守卫都读同一个值。
 * 扫描完全走 Shizuku shell，不需要 root。
 *
 * 2026-11-20 修正（自定义分支适配）：
 *  - 过滤规则从 `contains("ksu")` 改为 [ManagerCatalog]：7kimisu(com.sevenk.core)、
 *    SukiSU-Nova(com.sukisu.nova)、BakaSU(com.resukisu.resukisu) 的包名里
 *    都没有 "ksu" 子串，旧规则会把它们全部漏掉。
 *  - 路径获取从「每个候选一次 pm path」改为一次 `pm list packages -f`，
 *    候选再多也只有一次 shell 往返。
 *  - libksud.so 判定先直接 grep APK 的 zip 目录（明文文件名），不依赖设备
 *    有没有 unzip；grep 失败才回退 unzip。
 */
object ManagerSelection {
    const val DEFAULT_PACKAGE = ManagerCatalog.OFFICIAL_PKG
    private const val PREFS = "root_manager_selection"
    private const val KEY_PACKAGE = "package_name"
    private const val KEY_LABEL = "label"
    private val PACKAGE_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

    data class Manager(val packageName: String, val label: String, val apkPath: String)

    fun selected(context: Context): String {
        val raw = context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_PACKAGE, null)
            ?.trim()
        return if (!raw.isNullOrBlank() && PACKAGE_PATTERN.matches(raw)) raw else DEFAULT_PACKAGE
    }

    fun selectedLabel(context: Context): String {
        val pkg = selected(context)
        return context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_LABEL, null)
            ?.takeIf { it.isNotBlank() }
            ?: ManagerCatalog.labelOf(pkg)
    }

    fun save(context: Context, manager: Manager) {
        val pkg = manager.packageName.trim()
            .takeIf { PACKAGE_PATTERN.matches(it) } ?: DEFAULT_PACKAGE
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PACKAGE, pkg)
            .putString(KEY_LABEL, manager.label)
            .commit()
    }

    fun reset(context: Context) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_PACKAGE)
            .remove(KEY_LABEL)
            .commit()
    }

    /** 当前选择是否与内置 kernelsu.ko 配套（官方签名）。 */
    fun selectedBundledKo(context: Context): Boolean =
        ManagerCatalog.bundledKoFor(selected(context))

    /**
     * 找出设备上带兼容 ksud 的管理器。
     *
     * 候选 = 已知包名（[ManagerCatalog]）∪ 包名关键字命中；
     * 再用 `libksud.so` 是否为该 APK 的一部分做最终复核 —— 关键字只负责少跑
     * 几趟 shell，真正判据是 APK 里确实带了 ksud 用户态。
     */
    suspend fun scan(@Suppress("UNUSED_PARAMETER") context: Context): List<Manager> = withContext(Dispatchers.IO) {
        val listed = ShizukuController.exec("pm list packages -f 2>/dev/null", 25_000)
            .out.lines().mapNotNull { line ->
                // 形如：package:/data/app/~~x==/com.foo-y==/base.apk=com.foo
                val t = line.trim().removePrefix("package:")
                val eq = t.lastIndexOf('=')
                if (eq <= 0) return@mapNotNull null
                val apk = t.substring(0, eq).trim()
                val pkg = t.substring(eq + 1).trim()
                if (apk.startsWith("/") && PACKAGE_PATTERN.matches(pkg)) pkg to apk else null
            }

        listed.filter { (pkg, _) -> ManagerCatalog.looksLikeManager(pkg) }
            // split APK 可能让同一个包出现多行（base.apk + split_*.apk），只留第一行。
            .distinctBy { it.first }
            .mapNotNull { (pkg, apk) ->
                if (!hasKsud(apk)) return@mapNotNull null
                Manager(pkg, ManagerCatalog.labelOf(pkg), apk)
            }
            .sortedWith(compareByDescending<Manager> { it.packageName == DEFAULT_PACKAGE }
                .thenBy { it.label })
    }

    /**
     * APK 里是否带 `lib/<abi>/libksud.so`。
     *
     * zip 的中央目录里文件名是明文，`grep -a` 一次就能判，比 unzip 列目录快一个
     * 数量级；部分 ROM 的 grep 不带 -a 时输出会被当二进制吞掉，故保留 unzip 回退。
     */
    private suspend fun hasKsud(apk: String): Boolean {
        val g = ShizukuController.exec(
            "grep -aq 'libksud\\.so' '$apk' 2>/dev/null && echo YES || echo NO", 15_000
        )
        if (g.out.contains("YES")) return true
        val u = ShizukuController.exec(
            "unzip -Z1 '$apk' 2>/dev/null | grep -c 'libksud\\.so'", 20_000
        )
        return (u.out.trim().toIntOrNull() ?: 0) > 0
    }

    suspend fun installed(@Suppress("UNUSED_PARAMETER") context: Context, pkg: String): Boolean =
        withContext(Dispatchers.IO) {
            ShizukuController.exec("pm path $pkg 2>/dev/null", 12_000).out.contains("package:")
        }
}
