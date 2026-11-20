package com.ghostlock.honorfne

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * KernelSU 3.3.0 用户态入口（su）的唯一补装入口。
 *
 * 老版本的教训（ghostlock_latest.log / ghostlock_latest (1).log，2026-11-14）：
 *  - `ksud insmod` 成功后 /proc/modules 里 kernelsu 是 Live，但 /data/adb/ksud
 *    从未生成，`su 0 id` 一直返回 code=127「inaccessible or not found」；
 *  - 模块已 Live 时旧版只是反复「等待 su 就绪 1/12…」并重跑 W1/W2，
 *    既不补装 ksud，也不重启管理器，还因为多个协程并发把日志刷成 130 KB；
 *  - 更致命的是 ensurePayloads() 只判断文件存在，设备端一直跑旧版
 *    2072 B 的 ksu_lateload.sh（只有 insmod），新版 4439 B 的脚本从没下去过。
 *
 * 这里把「补装 + 重启管理器 + 复检」收拢到一个 Mutex 保护的函数，
 * GrindRunner（一键临时 Root）与 MainActivity（安装管理器 + 模块）共用，
 * 保证任何时刻只有一个协程在做这件事。
 *
 * KSU 3.3.0 的 /system/bin/su 是 sucompat 注册的虚拟路径，内核把
 * execve("/system/bin/su") 重定向到 KSUD_PATH=/data/adb/ksud；用
 * `ls /system/bin/su` 判活必然失败。ksud 必须由官方 `ksud install`
 * 原子部署，手工 cp 会带错 SELinux 上下文导致 shell 域 Permission denied。
 */
object KsuUserspace {

    private const val TMP = "/data/local/tmp"
    private const val RS_IN = "$TMP/rs.in"
    private const val RS_OUT = "$TMP/rs.out"
    private const val SCRIPT = "$TMP/ksu_fne/ksu_lateload.sh"
    private const val MGR = ManagerCatalog.OFFICIAL_PKG

    private val mutex = Mutex()

    /** shell 域能否真正拿到 root；两种写法都试，避免某些 shell 只认其中一种。 */
    suspend fun suReady(): Boolean {
        val r = ShizukuController.exec(
            "su -c id 2>&1; /system/bin/su -c id 2>&1", 15_000
        )
        return r.out.contains("uid=0")
    }

    private suspend fun moduleLive(): Boolean =
        ShizukuController.exec("grep -q kernelsu /proc/modules", 15_000).code == 0

    private suspend fun channelUp(maxTicks: Int = 5): Boolean {
        repeat(maxTicks) {
            val r = ShizukuController.exec(
                "grep -c 'ROOT SHELL CHANNEL UP' $RS_OUT 2>/dev/null", 15_000
            )
            if ((r.out.trim().toIntOrNull() ?: 0) > 0) return true
            delay(3_000)
        }
        return false
    }

    /** 通过常驻 root FIFO 通道投递幂等脚本（内含 ksud install + 三阶段）。 */
    private suspend fun deliverScript(log: (String) -> Unit): Boolean {
        // 注意：rs.in 由 chain_hook（u:r:kernel:s0）以 0666 创建，Enforcing 恢复前
        // App 的 shell(uid 2000) 可写；恢复 Enforcing 后该写入可能被 SELinux 拦下。
        // 这里只是「补装」兜底，写不进属预期（主链路 GrindRunner 早已投递过），
        // 因此只记提示、不报错误，最终以 suReady() 复检为准。
        val w = ShizukuController.exec("echo 'sh $SCRIPT' > $RS_IN", 20_000)
        if (w.code != 0) {
            log("[ksu][提示] root 通道 rs.in 当前不可写（Enforcing 已恢复），改由最终 su 复检判定")
            return false
        }
        repeat(20) { i -> // 60s
            delay(3_000)
            val r = ShizukuController.exec("grep -c KSUTRY_DONE $RS_OUT 2>/dev/null", 15_000)
            if ((r.out.trim().toIntOrNull() ?: 0) > 0) {
                log("[ksu] KSUTRY_DONE ✔ (${(i + 1) * 3}s)")
                return true
            }
        }
        log("[ksu][提示] 60s 内未见 KSUTRY_DONE（通道可能已随 restore_enforce 退出）")
        return false
    }

    /** 通道已随 restore_enforce 退出时的兜底：ksud debug su 直接向内核要 root。 */
    private suspend fun debugSuBootstrap(log: (String) -> Unit) {
        val d = "$TMP/ksu_fne"
        val inner = "$d/ksud install; $d/ksud post-fs-data; " +
            "$d/ksud services; $d/ksud boot-completed"
        val r = ShizukuController.exec("echo '$inner' | $d/ksud debug su 2>&1", 30_000)
        log("[ksu][bootstrap] rc=${r.code} out=${r.out.replace("\n", " | ").take(300).trim()}")
        if (r.err.isNotBlank()) {
            log("[ksu][bootstrap] err=${r.err.replace("\n", " | ").take(200).trim()}")
        }
    }

    private suspend fun restartManager(log: (String) -> Unit) {
        // 月虹式多管理器：官方包用显式 Activity；其它兼容包用 LAUNCHER 解析，
        // 不再假定 `<pkg>/<pkg>.ui.MainActivity` 这种固定类名。
        val pkg = selectedManager
        ShizukuController.exec("am force-stop $pkg", 15_000)
        if (pkg == MGR) {
            ShizukuController.exec("am start -n $pkg/$pkg.ui.MainActivity", 15_000)
        } else {
            ShizukuController.exec(
                "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p $pkg",
                15_000
            )
        }
        log("[ksu] 已重启 KernelSU 管理器 $pkg，让它重新拿 KSU 驱动 fd")
    }

    /** 由 MainActivity 在提权前注入当前选择；默认仍是官方包。 */
    @Volatile
    var selectedManager: String = MGR


    /**
     * 幂等：模块 Live 且 su 已可用时只重启一次管理器；su 不可用时尝试补装用户态。
     * 返回 shell 域 `uid=0` 是否可用。
     *
     * 就绪判定以 suReady() 为准（su 本身就是 ksud install 提供的入口，su 能用即
     * 代表 /data/adb/ksud 已就位），不再用 App 的 shell 直接 [ -x /data/adb/ksud ]
     * —— 那只会因 uid 2000 无权读 /data/adb 而误报「Permission denied / 不可执行」。
     */
    suspend fun ensure(log: (String) -> Unit): Boolean = mutex.withLock {
        if (!moduleLive()) {
            log("[ksu][跳过] /proc/modules 未见 kernelsu，本 boot 尚未加载模块")
            return@withLock false
        }
        if (suReady()) {
            log("[ksu] su 已就绪 ✔（uid=0，ksud 用户态随 insmod 一并部署）")
            restartManager(log)
            return@withLock true
        }

        log("[ksu] 模块 Live 但 su 不可用 → 尝试补装 KSU 用户态（只做一次，勿并发重试）")
        if (channelUp()) {
            log("[ksu] root FIFO 通道仍在，投递 $SCRIPT")
            deliverScript(log)
            val tail = ShizukuController.exec("tail -c 1600 $RS_OUT 2>/dev/null", 15_000)
                .out.replace("\u0000", "").replace("\n", " | ").takeLast(400).trim()
            log("[ksu] rs.out 尾部：$tail")
        } else {
            log("[ksu] root 通道已退出，改走 ksud debug su 补装")
            debugSuBootstrap(log)
        }

        delay(3_000)
        val ok = suReady()
        if (ok) {
            log("[ksu] ✔ Enforcing 下 su -c id 返回 uid=0")
            restartManager(log)
        } else {
            // 真实失败：模块 Live 但 su 始终起不来（管理器 allowlist 未放行，或
            // 补装未生效）。不再误报「ksud 不可执行」，给出准确提示即可。
            log("[ksu][警告] ksud 已就位但 shell 域 su 仍不可用（管理器 allowlist 未放行）")
            log("[ksu][提示] 打开一次 KernelSU 管理器，确认 shell 授权后再点「查看状态」")
            log("[ksu][提示] root 不持久，重启后重新跑一次完整流程即可")
        }
        ok
    }
}
