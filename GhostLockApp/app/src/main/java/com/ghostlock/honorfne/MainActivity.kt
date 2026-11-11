package com.ghostlock.honorfne

import android.animation.ValueAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.RenderEffect
import android.graphics.Shader
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.view.animation.Interpolator
import android.widget.FrameLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.ghostlock.honorfne.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlin.math.cos
import kotlin.math.exp

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val logLines = StringBuilder()
    private val MAX_LINES = 800

    private enum class Page { HOME, ROOT, ABOUT }

    private var compatible = false
    private var indicatorItemWidth = 0f

    /** Currently shown page; used to pick the spring-slide direction. */
    private var currentPage = Page.HOME

    /** True while exploit is running: suppress ALL shell polling to avoid
     *  disturbing the race window (the PC script sends no device commands
     *  during W1/W2 either). */
    @Volatile
    private var grinding = false

    private val shanghai = TimeZone.getTimeZone("Asia/Shanghai")
    private val clockFmt = SimpleDateFormat("HH:mm:ss", Locale.CHINA).apply { timeZone = shanghai }
    private val dateFmt = SimpleDateFormat("yyyy年M月d日 EEEE", Locale.CHINA).apply { timeZone = shanghai }

    companion object {
        private const val AUTHOR_HOME_URL = "https://www.coolapk.com/u/45191968"
        private const val GITHUB_URL = "https://github.com/XiaoDao-Fish/GhostLock-HonorFne"
        private const val AUTHOR_QQ = "2996697914"

        /** Exact kernel builds from root/exploit/src/devices/fne/offsets.h.
         *  This is a KERNEL whitelist, not a device-model whitelist: the bundled
         *  exploit binary matches uname -r with strcmp() and aborts with
         *  "no offsets for kernel" when the build is absent from offsets.h.
         *  A different build has different symbol offsets and will corrupt
         *  unrelated kernel memory — never relax this to a prefix like "5.4". */
        private val SUPPORTED_KERNELS = listOf(
            "5.4.289-qgki-gf6cb1f712a6e",
            "5.4.295-qgki-g6aea83b404da",
            "5.4.295-qgki-gc4635e0ca684",
            "5.4.295-qgki-ge32871827345",
            "5.4.295-qgki-g0fe5dd3dbc93",
            "5.4.295-qgki-gc26f40498717",
            "5.4.295-qgki-g165910d83a3a",
            "5.4.295-qgki-g58bd9508770a",
            "5.4.295-qgki-g5e68e68ac2e2",
            "5.4.295-qgki-g351930777161",
            "5.4.295-qgki-g0fb2656b2b50"
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        installCrashLogger()
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        LogStore.init(this)

        applyGlassBlur()
        applyMicroInteractions()
        setupTabIndicator()
        wireLegacyButtons()
        wireNewUi()

        // Local-only info: no shell needed, so it is available even before Shizuku.
        binding.tvDeviceModel.text = "设备型号：${Build.MANUFACTURER} ${Build.MODEL}"
        binding.tvKernel.text = "内核版本：${System.getProperty("os.version") ?: "未知"}"

        updateClock()
        startClockLoop()
        startStateLoop()
        refreshShizukuState()

        // ShizukuProvider 异步送达 binder，收到后刷新状态（回调在 binder 线程）
        ShizukuController.observeBinder {
            runOnUiThread { refreshShizukuState() }
            lifecycleScope.launch(Dispatchers.IO) {
                if (!grinding) {
                    // 归档上一次会话（很可能以内核崩溃 / 重启结束）并写完整诊断报告
                    LogStore.sync(force = true, reason = "应用启动 / Shizuku 就绪")
                    checkCompatibility()
                }
            }
        }

        log("[init] 日志即时写入：${LogStore.publicDirPath()}/ghostlock_latest.log")
        log("[init] 另一份在 文件管理器→下载→XiaoDao→ghostlock_latest.txt")
        log("[init] 以上两处都无需 Shizuku/电脑，崩溃重启后直接打开即可")
        log("[init] 私有兜底：${LogStore.sessionPath()}")
        log("[init] 闪退诊断：${filesDir}/crash_latest.txt")
    }

    /** Any uncaught exception is written to app-private storage, so a crash
     *  can be diagnosed even when no PC / adb is connected. */
    private fun installCrashLogger() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val sw = java.io.StringWriter()
                throwable.printStackTrace(java.io.PrintWriter(sw))
                java.io.File(filesDir, "crash_latest.txt").writeText(
                    "time=${Date()}\nthread=${thread.name}\n$sw"
                )
            }
            if (previous != null) {
                previous.uncaughtException(thread, throwable)
            } else {
                android.os.Process.killProcess(android.os.Process.myPid())
                kotlin.system.exitProcess(1)
            }
        }
    }

    override fun onDestroy() {
        ShizukuController.releaseBinderObserver()
        super.onDestroy()
    }

    // ------------------------------------------------------------ glass UI

    @Suppress("NewApi")
    private fun applyGlassBlur() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val effect = RenderEffect.createBlurEffect(70f, 70f, Shader.TileMode.CLAMP)
            binding.orbBlue.setRenderEffect(effect)
            binding.orbPurple.setRenderEffect(effect)
            // Barely-there soft focus on the lens rim, like a real glass bezel.
            val soft = RenderEffect.createBlurEffect(1.2f, 1.2f, Shader.TileMode.CLAMP)
            binding.tabIndicator.setRenderEffect(soft)
        }
    }

    /** Design system micro interactions: a 0.97 press on every action and a
     *  staggered fade up for the home page. Cosmetic only, never fatal. */
    private fun applyMicroInteractions() = runCatching {
        listOf<View>(
            binding.btnConnect, binding.btnDeploy, binding.btnRoot,
            binding.btnStatus, binding.btnManagers, binding.btnClear,
            binding.btnRefreshCompat, binding.btnStartRoot, binding.btnAuthorHome
        ).forEach { it.setOnTouchListener(pressFeedback) }
        staggerEntrance()
    }

    private val pressFeedback = View.OnTouchListener { v, e ->
        val d = motion(R.integer.ds_dur_micro)
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN ->
                v.animate().scaleX(0.97f).scaleY(0.97f).setDuration(d).start()
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL ->
                v.animate().scaleX(1f).scaleY(1f).setDuration(d).start()
        }
        false   // never consume the gesture, so onClick still fires
    }

    private fun staggerEntrance() {
        listOf<View>(
            binding.homeClockCaption, binding.tvClock, binding.tvDate,
            binding.tvGreeting
        ).forEachIndexed { i, v ->
            v.alpha = 0f
            v.translationY = dp(12).toFloat()
            v.animate()
                .alpha(1f).translationY(0f)
                .setStartDelay(i * 55L)
                .setDuration(motion(R.integer.ds_dur_standard))
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
        binding.tvDeviceModel.post {
            val card = binding.tvDeviceModel.parent as? View ?: return@post
            card.alpha = 0f
            card.translationY = dp(16).toFloat()
            card.animate()
                .alpha(1f).translationY(0f)
                .setStartDelay(180L)
                .setDuration(motion(R.integer.ds_dur_standard))
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    private fun motion(id: Int): Long = resources.getInteger(id).toLong()

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    private fun wireLegacyButtons() {
        binding.btnConnect.setOnClickListener { onConnect() }
        binding.btnDeploy.setOnClickListener { onDeploy() }
        binding.btnRoot.setOnClickListener { onRoot() }
        binding.btnStatus.setOnClickListener { onStatus() }
        binding.btnManagers.setOnClickListener { onManagers() }
        binding.btnClear.setOnClickListener {
            logLines.clear()
            binding.tvLog.text = getString(R.string.log_placeholder)
        }
    }

    private fun wireNewUi() {
        // Plain tap-to-switch navigation (the long-press magnifier was removed).
        binding.tabHome.setOnClickListener { switchPage(Page.HOME) }
        binding.tabRoot.setOnClickListener { switchPage(Page.ROOT) }
        binding.tabAbout.setOnClickListener { switchPage(Page.ABOUT) }

        // Tapping the Shizuku row is the quickest way to (re)authorize.
        binding.tvShizukuState.setOnClickListener { onConnect() }

        binding.btnRefreshCompat.setOnClickListener {
            lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
        }
        binding.btnStartRoot.setOnClickListener { onStartRoot() }

        binding.btnAuthorHome.setOnClickListener { openUrl(AUTHOR_HOME_URL) }
        binding.tvGithub.setOnClickListener { openUrl(GITHUB_URL) }
        binding.tvQq.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Author QQ", AUTHOR_QQ))
            toast("已复制作者QQ：$AUTHOR_QQ")
        }
    }

    /** Size the sliding frosted pill to exactly one third of the bar. */
    private fun setupTabIndicator() {
        binding.tabBar.post {
            val inner = binding.tabBar.width -
                binding.tabBar.paddingLeft - binding.tabBar.paddingRight
            if (inner <= 0) return@post
            indicatorItemWidth = inner / 3f
            val lp = binding.tabIndicator.layoutParams as? FrameLayout.LayoutParams
                ?: return@post
            lp.width = indicatorItemWidth.toInt()
            // 56dp pill centred inside the 64dp bar.
            lp.height = binding.tabBar.height - binding.tabBar.paddingTop - binding.tabBar.paddingBottom
            lp.gravity = Gravity.CENTER_VERTICAL or Gravity.START
            binding.tabIndicator.layoutParams = lp
            moveIndicator(0)
        }
    }

    /** Damped spring travel + subtle liquid stretch while the lens moves between
     *  tabs, mirroring MagicRoot's FloatingBottomBar (critically-damped slide). */
    private fun moveIndicator(index: Int) {
        if (indicatorItemWidth <= 0f) {
            binding.tabBar.post { moveIndicator(index) }
            return
        }
        val target = indicatorItemWidth * index
        binding.tabIndicator.animate()
            .translationX(target)
            .setDuration(motion(R.integer.ds_dur_page))
            .setInterpolator(DampedSpringInterpolator())
            .start()
        // light stretch during travel (MagicRoot stretches the lens with drag velocity)
        ValueAnimator.ofFloat(1f, 1.15f, 1f).apply {
            duration = motion(R.integer.ds_dur_page)
            addUpdateListener { binding.tabIndicator.scaleX = it.animatedValue as Float }
            start()
        }
        ValueAnimator.ofFloat(1f, 0.93f, 1f).apply {
            duration = motion(R.integer.ds_dur_page)
            addUpdateListener { binding.tabIndicator.scaleY = it.animatedValue as Float }
            start()
        }
    }

    /** Critically-damped spring step response (damping ratio = 1.0), matching
     *  MagicRoot's glass/DampedDragAnimation `spring(1f, 1000f)`: fast settle,
     *  zero overshoot. f(t) = 1 - (1 + w*t)·e^(-w*t). */
    private class DampedSpringInterpolator : Interpolator {
        override fun getInterpolation(input: Float): Float {
            if (input <= 0f) return 0f
            if (input >= 1f) return 1f
            val w = 12.0
            val t = input.toDouble()
            val v = 1.0 - (1.0 + w * t) * exp(-w * t)
            return v.toFloat().coerceIn(0f, 1f)
        }
    }

    private fun pageView(page: Page): View = when (page) {
        Page.HOME -> binding.pageHome
        Page.ROOT -> binding.pageRoot
        Page.ABOUT -> binding.pageAbout
    }

    /**
     * Switch pages the way MagicRoot does: a horizontal spring slide. The leaving
     * page slides out (direction follows the tab order), the entering page slides
     * in from the opposite side, both settling with a critically-damped spring
     * (no overshoot) — exactly `pagerState.springAnimateToPage`. The glass lens
     * still slides via [moveIndicator].
     */
    private fun switchPage(page: Page) {
        if (page == currentPage) return
        val fromIndex = currentPage.ordinal   // HOME=0, ROOT=1, ABOUT=2
        val toIndex = page.ordinal
        val dir = if (toIndex > fromIndex) 1 else -1

        val fromView = pageView(currentPage)
        val toView = pageView(page)
        fromView.animate().cancel()
        toView.animate().cancel()

        val slide = (if (binding.pageHost.width > 0) binding.pageHost.width
                     else resources.displayMetrics.widthPixels).toFloat()

        // baseline
        fromView.translationX = 0f
        fromView.alpha = 1f
        toView.translationX = dir * slide
        toView.alpha = 0f
        toView.visibility = View.VISIBLE

        fromView.animate()
            .translationX(-dir * slide)
            .alpha(0f)
            .setDuration(motion(R.integer.ds_dur_page))
            .setInterpolator(DampedSpringInterpolator())
            .withEndAction {
                fromView.visibility = View.GONE
                fromView.translationX = 0f
                fromView.alpha = 1f
            }.start()

        toView.animate()
            .translationX(0f)
            .alpha(1f)
            .setDuration(motion(R.integer.ds_dur_page))
            .setInterpolator(DampedSpringInterpolator())
            .withEndAction {
                toView.translationX = 0f
                toView.alpha = 1f
            }.start()

        currentPage = page
        moveIndicator(toIndex)
        binding.tabHome.animate().alpha(if (page == Page.HOME) 1f else 0.52f).setDuration(motion(R.integer.ds_dur_micro)).start()
        binding.tabRoot.animate().alpha(if (page == Page.ROOT) 1f else 0.52f).setDuration(motion(R.integer.ds_dur_micro)).start()
        binding.tabAbout.animate().alpha(if (page == Page.ABOUT) 1f else 0.52f).setDuration(motion(R.integer.ds_dur_micro)).start()

        if (page == Page.ROOT && !grinding) {
            lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
        }
    }

    private fun updateClock() {
        val now = Date()
        binding.tvClock.text = clockFmt.format(now)
        binding.tvDate.text = dateFmt.format(now)
        val cal = Calendar.getInstance(shanghai, Locale.CHINA).apply { time = now }
        val hour = cal.get(Calendar.HOUR_OF_DAY)
        binding.tvGreeting.text = getString(
            when (hour) {
                in 5..10 -> R.string.home_greeting_morning
                in 11..17 -> R.string.home_greeting_noon
                else -> R.string.home_greeting_night
            }
        )
    }

    private fun startClockLoop() {
        lifecycleScope.launch {
            while (isActive) {
                updateClock()
                delay(1_000)
            }
        }
    }

    private fun startStateLoop() {
        lifecycleScope.launch(Dispatchers.IO) {
            while (isActive) {
                // Never fire shell commands while the exploit owns the CPU.
                if (!grinding) refreshStates()
                delay(6_000)
            }
        }
    }

    private suspend fun refreshStates() {
        val granted = runCatching { ShizukuController.hasPermission() }.getOrDefault(false)
        var rooted = false
        var kernel = ""
        if (granted) {
            val su = ShizukuController.exec("su 0 id", 8_000)
            rooted = su.out.contains("uid=0")
            val uname = ShizukuController.exec("uname -r", 8_000)
            if (uname.code == 0 && uname.out.isNotBlank()) kernel = uname.out.trim()
        }
        withContext(Dispatchers.Main) {
            val okColor = getColor(R.color.glass_ok)
            val badColor = getColor(R.color.glass_bad)
            binding.tvRootState.text = getString(
                if (rooted) R.string.home_root_ok else R.string.home_root_no
            )
            binding.tvRootState.setTextColor(if (rooted) okColor else badColor)
            binding.rootStateDot.backgroundTintList =
                ColorStateList.valueOf(if (rooted) okColor else badColor)
            binding.tvShizukuState.text = getString(
                if (granted) R.string.home_shizuku_ok else R.string.home_shizuku_no
            )
            binding.tvShizukuState.setTextColor(if (granted) okColor else badColor)
            binding.shizukuStateDot.backgroundTintList =
                ColorStateList.valueOf(if (granted) okColor else badColor)
            if (kernel.isNotEmpty()) binding.tvKernel.text = "内核版本：$kernel"
        }
    }

    /** Whitelist check: exact model + exact kernel build from fne/offsets.h. */
    private suspend fun checkCompatibility() {
        if (grinding) return
        // 荣耀 70 = FNE-AN00 / device "HNFNE"；荣耀 50 = NTH-AN00 / device "HNNTH"。
        // 荣耀 50 实测成功记录用的是 MagicOS 8.0.0.221(C00E219R5P6)
        // / 5.4.289-qgki-gf6cb1f712a6e。同型号其它 OTA（如 8.0.0.217
        // / g8f2019ef68d9）是另一个内核构建，没有对应符号偏移表，
        // 所以机型能通过、内核仍需单独精确匹配。
        val modelFields = listOf(Build.MODEL, Build.DEVICE, Build.BOARD, Build.HARDWARE)
        val modelOk = modelFields.any {
            it.contains("FNE", ignoreCase = true) ||
                it.contains("NTH", ignoreCase = true) ||
                it.contains("HNNTH", ignoreCase = true)
        } ||
            Build.MODEL.contains("荣耀 70", ignoreCase = true) ||
            Build.MODEL.contains("Honor 70", ignoreCase = true) ||
            Build.MODEL.contains("荣耀 50", ignoreCase = true) ||
            Build.MODEL.contains("Honor 50", ignoreCase = true)

        var kernel = ""
        if (runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            val r = ShizukuController.exec("uname -r", 8_000)
            if (r.code == 0 && r.out.isNotBlank()) kernel = r.out.trim()
        }
        if (kernel.isBlank()) kernel = System.getProperty("os.version")?.trim().orEmpty()
        val kernelOk = SUPPORTED_KERNELS.any { kernel.startsWith(it) }
        val ok = modelOk && kernelOk

        withContext(Dispatchers.Main) {
            compatible = ok
            val kernelUnknown = kernel.isBlank()
            binding.tvCompat.text = when {
                ok -> "✔ ${getString(R.string.root_check_ok)}"
                !modelOk || kernelUnknown -> "✘ ${getString(R.string.root_check_bad)}"
                else -> "⚠ ${getString(R.string.root_check_kernel_bad)}"
            }
            val titleColor = when {
                ok -> R.color.glass_ok
                !modelOk || kernelUnknown -> R.color.glass_bad
                else -> R.color.glass_warn
            }
            binding.tvCompat.setTextColor(getColor(titleColor))
            val reason = when {
                !modelOk -> "设备型号不匹配（支持荣耀 70 / FNE-AN00、荣耀 50 / NTH-AN00）"
                kernelUnknown -> "无法读取内核版本，请先授权 Shizuku 再重新检测"
                !kernelOk -> "机型已支持，但当前内核构建未收录\n" +
                    "已适配：5.4.289-qgki-gf6cb1f712a6e（荣耀 50 实测 8.0.0.221）\n" +
                    "利用程序按精确内核偏移编写，换构建会写坏内核内存，故不放行"
                else -> "型号与内核均已匹配，物料为 FNE 专用构建"
            }
            binding.tvCompatDetail.text =
                "设备型号：${Build.MANUFACTURER} ${Build.MODEL}\n" +
                    "内核版本：$kernel\n" +
                    "判定：$reason"
            binding.btnStartRoot.visibility = if (ok) View.VISIBLE else View.GONE
        }
    }

    private fun onStartRoot() {
        if (!compatible) {
            toast("机型/内核不匹配，无法进行临时 Root")
            return
        }
        if (!ShizukuController.hasPermission()) {
            toast("请先授权 Shizuku，授权后再点一次")
            onConnect()
            return
        }
        // 点击后提权引导页消失，整页切换为实时日志
        binding.rootIntro.visibility = View.GONE
        binding.rootLogPanel.visibility = View.VISIBLE
        onRoot()
    }

    private fun openUrl(url: String) {
        runCatching {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        }.onFailure { toast("无法打开链接：${it.message}") }
    }

    // ------------------------------------------------------------ Shizuku

    private fun refreshShizukuState() {
        binding.tvStatus.text = when {
            !ShizukuController.isAvailable() -> getString(R.string.hint_shizuku_missing)
            !ShizukuController.hasPermission() -> "Shizuku 已运行，但未授权，点「连接 Shizuku」授权"
            else -> "就绪：Shizuku 已连接，可部署物料"
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
            lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
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
                lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
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
            "test -f /data/local/tmp/ksu_fne/kernelsu.ko && " +
            "test -f /data/local/tmp/ksu_fne/ksu_lateload.sh && " +
            "test -f /data/local/tmp/ksu_fne/restore_enforce.sh && " +
            "test -f /data/local/tmp/ksu_fne/handoff && echo READY"
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
        if (grinding) { toast("临时 Root 正在运行中"); return }
        lifecycleScope.launch(Dispatchers.IO) {
            grinding = true
            try {
                GrindRunner(::log, ::status, { ensurePayloads() }).run()
            } finally {
                grinding = false
                withContext(Dispatchers.Main) { refreshShizukuState() }
            }
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
