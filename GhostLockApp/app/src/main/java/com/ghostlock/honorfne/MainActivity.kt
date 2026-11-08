package com.ghostlock.honorfne

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.ghostlock.honorfne.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val logLines = StringBuilder()
    private val MAX_LINES = 800

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        LogStore.init(this)

        binding.btnConnect.setOnClickListener { onConnect() }
        binding.btnDeploy.setOnClickListener { onDeploy() }
        binding.btnRoot.setOnClickListener { onRoot() }
        binding.btnStatus.setOnClickListener { onStatus() }
        binding.btnManagers.setOnClickListener { onManagers() }
        binding.btnClear.setOnClickListener {
            logLines.clear()
            binding.tvLog.text = getString(R.string.log_placeholder)
        }

        refreshShizukuState()
        // ShizukuProvider 异步送达 binder，收到后刷新状态（回调在 binder 线程）
        ShizukuController.observeBinder {
            runOnUiThread { refreshShizukuState() }
            // 归档上一次会话（很可能以内核崩溃 / 重启结束）并写完整诊断报告
            lifecycleScope.launch(Dispatchers.IO) {
                LogStore.sync(force = true, reason = "应用启动 / Shizuku 就绪")
            }
        }
        log("[init] 日志即时写入：${LogStore.publicDirPath()}/ghostlock_latest.log")
        log("[init] 另一份在 文件管理器→下载→XiaoDao→ghostlock_latest.txt")
        log("[init] 以上两处都无需 Shizuku/电脑，崩溃重启后直接打开即可")
        log("[init] 私有兜底：${LogStore.sessionPath()}")
    }

    override fun onDestroy() {
        ShizukuController.releaseBinderObserver()
        super.onDestroy()
    }

    private fun refreshShizukuState() {
        when {
            !ShizukuController.isAvailable() ->
                binding.tvStatus.text = getString(R.string.hint_shizuku_missing)
            !ShizukuController.hasPermission() ->
                binding.tvStatus.text = "Shizuku 已运行，但未授权，点「连接 Shizuku」授权"
            else ->
                binding.tvStatus.text = "就绪：Shizuku 已连接，可部署物料"
        }
    }

    private fun onConnect() {
        if (!ShizukuController.isAvailable()) {
            Toast.makeText(
                this,
                "尚未收到 Shizuku binder：请在 Shizuku 里通过无线调试启动服务，然后重新打开本应用",
                Toast.LENGTH_LONG
            ).show()
            return
        }
        if (ShizukuController.hasPermission()) {
            refreshShizukuState()
            return
        }
        ShizukuController.requestPermission { granted ->
            // 授权回调来自 binder 线程，必须切回主线程再更新 UI
            runOnUiThread {
                Toast.makeText(
                    this,
                    if (granted) "Shizuku 已授权" else "Shizuku 授权被拒绝",
                    Toast.LENGTH_SHORT
                ).show()
                refreshShizukuState()
            }
        }
    }

    private fun onDeploy() {
        if (!ShizukuController.hasPermission()) { toast("请先连接并授权 Shizuku"); return }
        lifecycleScope.launch(Dispatchers.IO) {
            val ok = AssetDeployer.deploy(this@MainActivity, ::log)
            toast(if (ok) "物料部署完成（校验通过）" else "部署失败，请看日志")
        }
    }

    /**
     * 「一键临时 Root」前必须确认设备端物料齐全。旧版没有这一步：用户若没点
     * 「部署物料」或重启后 /data/local/tmp 被清，w1.log 只会留下
     * "No such file or directory"，app 却白等 420s 后误判失败并 reboot。
     * 这里缺失即自动重新部署并复检，用户无需手动点「部署物料」。
     */
    private suspend fun ensurePayloads(): Boolean {
        // pingBinder 正常但 newProcess 失效时，test -x 会返回空并被误判为
        // 「物料缺失」，从而反复重新部署。先确认命令通道真的能用。
        val shell = ShizukuController.shellProbe()
        if (!ShizukuController.probeOk(shell)) {
            log("[deploy][错误] Shizuku 命令通道不可用（code=${shell.code} ${shell.err.trim()}）")
            log("[deploy][错误] 请重新通过无线调试启动 Shizuku 并授权本应用")
            return false
        }
        val probe = "test -x /data/local/tmp/e && " +
            "test -f /data/local/tmp/ksu_fne/kernelsu.ko && echo READY"
        val before = ShizukuController.exec(probe, 15_000)
        if (before.code == 0 && before.out.contains("READY")) return true

        log("[deploy] 检测到设备端物料缺失（e / kernelsu.ko），自动重新部署…")
        if (!AssetDeployer.deploy(this@MainActivity, ::log)) return false
        val after = ShizukuController.exec(probe, 15_000)
        val ok = after.code == 0 && after.out.contains("READY")
        if (ok) log("[deploy] 自动部署完成并校验通过 ✔")
        else log("[deploy][错误] 自动部署后仍缺关键物料，请检查 /data/local/tmp 可写性")
        return ok
    }

    private fun onRoot() {
        if (!ShizukuController.hasPermission()) { toast("请先连接 Shizuku 并授权"); return }
        lifecycleScope.launch(Dispatchers.IO) {
            GrindRunner(::log, ::status, { ensurePayloads() }).run()
        }
    }

    private fun onStatus() {
        if (!ShizukuController.hasPermission()) { toast("请先连接 Shizuku"); return }
        lifecycleScope.launch(Dispatchers.IO) {
            log("[status] 日志位置：${LogStore.publicDirPath()}/ghostlock_latest.log")
            log("[status] 或 文件管理器→下载→XiaoDao→ghostlock_latest.txt")
            val stale = ShizukuController.exec("pidof e 2>/dev/null | wc -w", 10_000).out.trim().ifEmpty { "0" }
            log("[status] 当前残留 e 进程数：$stale（点「一键临时 Root」会自动清理）")
            val en = ShizukuController.exec("getenforce", 15_000).out.trim()
            val mods = ShizukuController.exec("grep -c kernelsu /proc/modules", 15_000).out.trim()
            val boot = ShizukuController.exec("getprop sys.boot_completed", 15_000).out.trim()
            status("getenforce=$en | kernelsu模块=$mods | boot_completed=$boot")
            log("[status] SELinux=$en, kernelsu=$mods, boot=$boot")
        }
    }

    private fun onManagers() {
        if (!ShizukuController.hasPermission()) { toast("请先连接 Shizuku"); return }
        lifecycleScope.launch(Dispatchers.IO) {
            log("[mgrs] === 安装管理器 + 模块 ===")
            log("[mgrs] 内置管理器 = KernelSU v3.3.0 / code 32601 / me.weishu.kernelsu")
            log("[mgrs] 与定制 kernelsu.ko 配套；勿随意换成其它 commit 编译的版本")

            // 0) 先如实探测状态并显示真实原因，避免在没 root 时空等 2 分钟
            val bc = ShizukuController.exec("getprop sys.boot_completed", 15_000).out.trim()
            val mods = ShizukuController.exec("grep -c kernelsu /proc/modules", 15_000).out.trim()
            val ksuLoaded = (mods.toIntOrNull() ?: 0) > 0
            val firstSu = ShizukuController.exec("su 0 id", 10_000)
            log("[mgrs] 状态：boot_completed=$bc, kernelsu模块=$mods, su code=${firstSu.code}")
            log("[mgrs] su 0 id 返回：${(firstSu.out + firstSu.err).trim().takeLast(120).ifEmpty { "（无输出）" }}")

            // 1) 管理器 APK 用 Shizuku 的 shell 权限即可安装，不依赖 root —— 先做掉，
            //    不要被后面的 su 检查挡住（原 PC 脚本是在 KSU READY 之后才被调用的）。
            val pkgs = ShizukuController.exec("pm list packages me.weishu.kernelsu", 20_000).out
            if (pkgs.contains("me.weishu.kernelsu")) {
                log("[mgrs] 已安装 KernelSU 管理器，跳过（保留配套版本）")
            } else {
                val custom = ShizukuController.exec(
                    "test -f /data/local/tmp/managers/KernelSU-manager-custom.apk && echo yes",
                    15_000
                ).out.trim() == "yes"
                val apk = if (custom) {
                    log("[mgrs][警告] 检测到自定义管理器，版本可能与 kernelsu.ko 不兼容")
                    "/data/local/tmp/managers/KernelSU-manager-custom.apk"
                } else {
                    "/data/local/tmp/managers/KernelSU-manager.apk"
                }
                val pm = ShizukuController.exec("pm install -r $apk", 90_000)
                log("[mgrs] pm install $apk: code=${pm.code} ${(pm.out + pm.err).takeLast(120).trim()}")
            }

            // 2) 没有 KSU 就不必等 su：模块安装全都需要 root，立即给出明确结论
            if (!ksuLoaded) {
                log("[mgrs][提示] /proc/modules 未发现 kernelsu → 本 boot 尚未加载 KSU")
                log("[mgrs][提示] 临时 Root 还没成功，或设备重启后 KSU 已丢失（root 不持久）")
                log("[mgrs][提示] 管理器 APK 已处理；模块安装跳过。请先「一键临时 Root」看到 KSU READY 再回来")
                toast("KSU 未加载，仅装了管理器；请先完成临时 Root")
                return@launch
            }

            // 3) KSU 已加载、su 可能还没注入 allowlist → 短等，且每次打印真实返回
            var suReady = firstSu.out.contains("uid=0")
            if (!suReady) {
                for (i in 0 until 12) {
                    delay(5_000)
                    val r = ShizukuController.exec("su 0 id", 10_000)
                    log("[mgrs] 等待 su 就绪 ${i + 1}/12: code=${r.code} ${(r.out + r.err).trim().takeLast(100).ifEmpty { "无输出" }}")
                    if (r.out.contains("uid=0")) { suReady = true; break }
                }
            }
            if (!suReady) {
                log("[mgrs][错误] KSU 已加载但 su 仍不可用（allowlist 未注入 / shell 未被授权）")
                log("[mgrs][提示] 打开一次 KernelSU 管理器后再试；也可点「查看状态」确认")
                toast("su 暂不可用，详见日志")
                return@launch
            }
            log("[mgrs] su 已就绪 ✔")

            // 4) ksud 路径解析：/data/adb/ksud 只在管理器首次打开时才由 APK 拷入
            val ksud = ShizukuController.exec(
                "su 0 sh -c 'for k in /data/adb/ksud /data/local/tmp/ksu_fne/ksud; do [ -x \"\$k\" ] && echo \"\$k\" && break; done'",
                20_000
            ).out.trim().lines().firstOrNull()?.trim().orEmpty()
            if (ksud.isEmpty()) {
                log("[mgrs][错误] 未找到 ksud，模块安装跳过")
                toast("未找到 ksud")
                return@launch
            }
            log("[mgrs] 使用 ksud: $ksud")

            // 5) netfix_packet 模块同步
            val nf = ShizukuController.exec(
                "su 0 sh -c 'mkdir -p /data/adb/modules/netfix_packet && cp -rf /data/local/tmp/netfix_packet/. /data/adb/modules/netfix_packet/'",
                60_000
            )
            log("[mgrs] netfix_packet 同步: code=${nf.code}")

            // 6) 模块走 ksud 官方安装（中转路径 + 成功文本校验 + 一次重试）
            for (zip in listOf("ZygiskNext.zip", "LSPosed-zygisk.zip")) {
                val stage = "/data/local/tmp/.gl_mod_${zip.removeSuffix(".zip")}.zip"
                ShizukuController.exec("cp /data/local/tmp/managers/$zip $stage", 30_000)
                var r = ShizukuController.exec("su 0 $ksud module install $stage", 180_000)
                if (!r.out.contains("successfully", ignoreCase = true)) {
                    log("[mgrs] $zip 首次未确认成功，10s 后重试…")
                    delay(10_000)
                    r = ShizukuController.exec("su 0 $ksud module install $stage", 180_000)
                }
                log("[mgrs] $zip: code=${r.code} ${r.out.takeLast(150).trim()}")
                ShizukuController.exec("su 0 rm -f $stage", 15_000)
            }

            // 7) 模块安装会重置 LSPosed daemon，必须原地重打 netfix 补丁
            val patch = ShizukuController.exec(
                "su 0 sh -c 'sh /data/adb/modules/netfix_packet/post-fs-data.sh; sh /data/adb/modules/netfix_packet/service.sh'",
                60_000
            )
            log("[mgrs] netfix 补丁重打: code=${patch.code}")
            log("[mgrs] 完成。模块随下次 KSU 加载生效；LSPosed 入口在通知栏快捷方式。")
            toast("管理器步骤完成（详见日志）")
        }
    }

    // ------------------------------------------------------------- helpers

    private fun log(line: String) {
        // 每条即时落盘到 app 私有文件：内核 panic 是突然的，不能等最后一刻才导出
        LogStore.append(line)
        runOnUiThread {
            logLines.appendLine(line)
            val lines = logLines.lines()
            if (lines.size > MAX_LINES) {
                logLines.clear()
                logLines.append(lines.takeLast(MAX_LINES).joinToString("\n"))
            }
            binding.tvLog.text = logLines.toString()
            // 节流同步到 SD 卡（内部 4s 节流，不会每条都起进程）
            lifecycleScope.launch(Dispatchers.IO) { LogStore.sync() }
        }
    }

    private fun status(text: String) {
        runOnUiThread { binding.tvStatus.text = text }
    }

    private fun toast(text: String) {
        runOnUiThread { Toast.makeText(this, text, Toast.LENGTH_SHORT).show() }
    }
}
