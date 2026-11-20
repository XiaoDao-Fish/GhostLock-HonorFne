package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.regex.Pattern

/**
 * 启动守卫：每次打开软件、Shizuku 就绪后，确认已安装的 KernelSU 管理器
 * 是与之严格配套的版本（me.weishu.kernelsu / v3.3.0 / code 32601）。
 *
 * 为什么要强制：kernelsu.ko 是按 3.3.0（code 32601）这个 commit 编译的，
 * 管理器与内核驱动必须同版本才能拿到 KSU fd；用户手动升级管理器、或装错
 * 其它分支的 APK 都会导致「模块 Live 但 su 起不来 / 管理器打不开 KSU」。
 *
 * 这里只用到 Shizuku 的 shell 权限（pm / dumpsys 都不需要 root），所以即便
 * 本 boot 还没临时 Root 也能在启动阶段先把管理器版本纠正过来。
 *
 * 纠正策略：
 *  - 未安装 → 直接用内置物料安装正确版本；
 *  - 版本/版本号不符 → 卸载错误版本，再用内置正确 APK 重装；
 *  - 版本正确 → 跳过。
 * 「重新下载正确版本」在本离线工具里即「重装内置 v3.3.0 APK」。
 */
object KsuVersionGuard {

    private const val MGR = ManagerCatalog.OFFICIAL_PKG
    private const val EXPECTED_VERSION = "v3.3.0"   // dumpsys 实际返回 "v3.3.0"
    private const val EXPECTED_CODE = 32601
    private const val TMP_MGR = "/data/local/tmp/managers/KernelSU-manager.apk"
    private const val ASSET = "managers/KernelSU-manager.apk"

    private val VERSION_NAME = Pattern.compile("versionName=(\\S+)")
    private val VERSION_CODE = Pattern.compile("versionCode=(\\d+)")

    /**
     * 入口。返回本次动作：
     *  - "ok"         ：原本就是正确版本，无需处理；
     *  - "installed"  ：原本未安装，已装好内置正确版；
     *  - "fixed"      ：原本版本不对，已卸载并重装正确版；
     *  - "thirdparty" ：用户选了第三方分支管理器（7kimisu / SukiSU / BakaSU …），
     *                   内置模块不认其签名，守卫跳过、不改包、不报错；
     *  - "skipped"    ：Shizuku 通道不可用或查询时掉线，本轮不下结论；
     *  - "failed"     ：处理失败（含异常）。
     * 任何异常都被吞掉，绝不影响 App 正常启动。
     */
    suspend fun enforce(context: Context, log: (String) -> Unit): String =
        withContext(Dispatchers.IO) {
            // 2026-11-15 真机日志（13:13 那轮）：设备重启后 Shizuku binder 尚未重连，
            // exec() 全部返回 code=-1 + 空 stdout（"binder haven't been received"）。
            // 旧代码把「空输出」当成「包不存在」，于是误判管理器未安装 → 卸载 + 重装，
            // 落地又失败、刷一屏错误，甚至有把正确版本卸掉的风险。
            // 通道不通时一律跳过守卫，绝不下任何关于「装没装」的结论。
            val probe = runCatching { ShizukuController.shellProbe() }
                .getOrDefault(ShizukuController.ExecResult(-1, "", "shellProbe threw"))
            if (!ShizukuController.probeOk(probe)) {
                log("[ksuguard] Shizuku 命令通道不可用（code=${probe.code} ${probe.err.trim().take(80)}）" +
                        "→ 跳过版本守卫，不据此判定管理器未安装")
                return@withContext "skipped"
            }
            // 多管理器模式：内置 kernelsu.ko 只与 v3.3.0 官方包配套，用户主动选了
            // KernelSU Next / 7kimisu / SukiSU 等其它管理器时不能把人家卸掉重装官方版
            // （月虹 1.7.0 的做法是先尊重选择）。此时守卫只提示，不强制改包。
            val chosen = ManagerSelection.selected(context)
            if (chosen != ManagerCatalog.OFFICIAL_PKG) {
                val label = ManagerSelection.selectedLabel(context)
                val known = ManagerCatalog.of(chosen)
                log("[ksuguard] 当前管理器 $label（$chosen），第三方分支，跳过官方版本纠正")
                log("[ksuguard] 工作目录：${ManagerCatalog.workingDirOf(chosen)}" +
                        if (known?.bundledKo == false) "；该分支编译期写死自己的 APK 签名，" +
                                "内置 kernelsu.ko（官方签名 c37106…d2d6）不认它" else "")
                log("[ksuguard] 提权不受影响：su 由 ksud 的 allow_shell 提供；" +
                        "但该管理器打开后会显示「内核未加载」，属预期")
                return@withContext "thirdparty"
            }
            runCatching {
                val (installed, dead) = queryVersion()
                when {
                    dead -> {
                        log("[ksuguard] 查询管理器版本时命令通道断开 → 跳过本轮守卫（避免把掉线误判成未安装）")
                        "skipped"
                    }
                    installed == null -> {
                        log("[ksuguard] 未检测到 KernelSU 管理器 → 安装内置 $EXPECTED_VERSION")
                        if (installBundled(context, log)) "installed" else "failed"
                    }
                    !match(installed) -> {
                        log("[ksuguard] 版本不符：code=${installed.second} name=${installed.first}（应为 $EXPECTED_CODE / $EXPECTED_VERSION）")
                        uninstall(log)
                        if (installBundled(context, log)) "fixed" else "failed"
                    }
                    else -> {
                        log("[ksuguard] KernelSU 管理器版本正确 ✔（$EXPECTED_VERSION / $EXPECTED_CODE）")
                        "ok"
                    }
                }
            }.onFailure { e ->
                log("[ksuguard][警告] 版本守卫异常：${e.message?.take(120)}")
            }.getOrDefault("failed")
        }

    /** 归一化比较：去掉前导 v、转小写，避免 "v3.3.0" 与 "3.3.0" 被误判不符。 */
    /** 归一化比较：去掉前导 v、转小写，避免 "v3.3.0" 与 "3.3.0" 被误判不符。
     *  暴露给 MainActivity 用于判断按钮是否置灰（不在这里写 shell）。 */
    internal fun match(installed: Pair<String, Int>): Boolean {
        fun norm(s: String) = s.trim().removePrefix("v").lowercase()
        return norm(installed.first) == norm(EXPECTED_VERSION) &&
            installed.second == EXPECTED_CODE
    }

    /**
     * 返回 (版本, 命令通道是否已断)。
     * exec() 把所有 Throwable 统一吞成 code=-1 + 空 stdout，必须和「包确实不存在」
     * 区分开：一次 Shizuku 掉线不该被当成「管理器未安装」。
     */
    private suspend fun queryVersion(): Pair<Pair<String, Int>?, Boolean> {
        val r = ShizukuController.exec(
            "dumpsys package $MGR 2>/dev/null | " +
                "grep -E 'versionName=|versionCode=' | head -n 4",
            20_000
        )
        if (ShizukuController.channelDead(r)) return Pair(null, true)
        if (r.code != 0 || r.out.isBlank()) return Pair(null, false)
        val mName = VERSION_NAME.matcher(r.out)
        val name = if (mName.find()) mName.group(1) else null
        val mCode = VERSION_CODE.matcher(r.out)
        val code = if (mCode.find()) mCode.group(1)?.toIntOrNull() else null
        return Pair(if (name != null && code != null) name to code else null, false)
    }

    internal suspend fun installedVersion(): Pair<String, Int>? = queryVersion().first

    private suspend fun uninstall(log: (String) -> Unit) {
        // 优先 su 卸载（更稳，避免 shell 安装者上下文问题），失败回退普通 pm uninstall
        var r = ShizukuController.exec("su -c 'pm uninstall $MGR' 2>&1", 30_000)
        if (r.code != 0 || r.out.contains("Failure", ignoreCase = true)) {
            log("[ksuguard] su 卸载未成功，回退 shell pm uninstall：${r.out.take(80).trim()}")
            r = ShizukuController.exec("pm uninstall $MGR 2>&1", 30_000)
        }
        log("[ksuguard] 卸载错误版本 rc=${r.code} ${r.out.take(120).trim()}")
    }

    /** 把内置正确 APK 落地到 local/tmp 并以 -r 重装（保留数据）。 */
    private suspend fun installBundled(context: Context, log: (String) -> Unit): Boolean {
        ShizukuController.exec("mkdir -p /data/local/tmp/managers", 15_000)
        val data = context.assets.open(ASSET).use { it.readBytes() }
        val ok = ShizukuController.writeFile(data, TMP_MGR)
        if (!ok) {
            // 写文件失败有两类原因：APK/路径问题，或 Shizuku 通道在写入中途断掉。
            // 前者是真失败，后者只是「暂时做不了」，别报成「内置 APK 坏了」。
            val alive = runCatching { ShizukuController.probeOk(ShizukuController.shellProbe()) }
                .getOrDefault(false)
            if (!alive) log("[ksuguard] 命令通道断开，内置 APK 无法落地（非文件损坏）；跳过安装，待 Shizuku 恢复后重检")
            else log("[ksuguard][错误] 内置管理器 APK 落地失败，无法安装")
            return false
        }
        val pm = ShizukuController.exec("pm install -r $TMP_MGR 2>&1", 120_000)
        if (ShizukuController.channelDead(pm)) {
            log("[ksuguard] 安装过程中命令通道断开，结果未知；本轮不判定成败")
            return false
        }
        log("[ksuguard] 安装内置 $EXPECTED_VERSION rc=${pm.code} ${(pm.out + pm.err).takeLast(160).trim()}")
        return pm.code == 0 && !pm.out.contains("Failure", ignoreCase = true)
    }
}
