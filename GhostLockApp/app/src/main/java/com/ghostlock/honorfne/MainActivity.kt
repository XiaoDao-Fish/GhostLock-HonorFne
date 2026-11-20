package com.ghostlock.honorfne

import android.animation.ValueAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.app.Dialog
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.animation.DecelerateInterpolator
import android.view.animation.Interpolator
import android.view.animation.OvershootInterpolator
import android.widget.Button
import android.widget.CheckBox
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AlertDialog
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import java.io.File
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

    /** 最近一次兼容性判定的结果；决定「开始提权」走哪条链。 */
    @Volatile
    private var engineMatch = EngineMatch(Engine.NONE)

    @Volatile
    private var currentKernel = ""

    /** KernelSU 管理器的本地缓存版本信息（由 enforceKsuVersion() 填充）。 */
    private var ksuVersion: String? = null
    /** KernelSU 管理器版本号是否合规。null = 尚未查过（按钮不因此置灰，由 onRoot() 兜底）。 */
    private var ksuVersionOk: Boolean? = null

    /** 每次冷启动只抓一份设备现场，避免 2.2.9 那种同一快照刷四遍。 */
    @Volatile
    private var snapshotDone = false

    /** 自助适配：正在解析 boot.img（防连点，也避免和提权抢 CPU）。 */
    @Volatile
    private var adaptBusy = false

    /**
     * 选择 boot.img。用 SAF 的 OpenDocument：不申请任何存储权限，
     * 用户选哪个文件我们就只读那一个 fd（boot.img 常是 100 MB 上下）。
     */
    private val bootImagePicker =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) startBootAdapt(uri)
        }

    /** Currently shown page; used to pick the spring-slide direction. */
    private var currentPage = Page.HOME

    /** True while exploit is running: suppress ALL shell polling to avoid
     *  disturbing the race window (the PC script sends no device commands
     *  during W1/W2 either). */
    @Volatile
    private var grinding = false

    /** 防止「安装管理器 + 模块」被连点多次起多个协程并发刷日志 / 重复等 su。 */
    @Volatile
    private var managersBusy = false

    /** 防止启动版本守卫与「安装管理器」步骤并发抢同一个 APK / pm。 */
    @Volatile
    private var ksuGuardBusy = false

    private val shanghai = TimeZone.getTimeZone("Asia/Shanghai")
    private val clockFmt = SimpleDateFormat("HH:mm:ss", Locale.CHINA).apply { timeZone = shanghai }
    private val dateFmt = SimpleDateFormat("yyyy年M月d日 EEEE", Locale.CHINA).apply { timeZone = shanghai }

    companion object {
        private const val AUTHOR_HOME_URL = "https://www.coolapk.com/u/45191968"
        private const val GITHUB_URL = "https://github.com/XiaoDao-Fish/GhostLock-HonorFne"
        private const val AUTHOR_QQ = "2996697914"
        private const val QQ_GROUP_URL = "https://qm.qq.com/q/f1PUUGcCbu"
        private const val QQ_GROUP_NO = "1132352830"
        private const val QQ_PACKAGE = "com.tencent.mobileqq"

        // 内核白名单与 ExtractKit profile 目录统一放在 EngineCatalog：
        // 链路 A 的 28 个 OFFSETS_ENTRY + 链路 B 的 75 条 device.cfg profile。
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 日志必须先就位：闪退处理器要把堆栈写进同一份日志，不能再单开文件。
        LogStore.init(this)
        installCrashLogger()
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        applyMicroInteractions()
        setupTabIndicator()
        applyTabVisuals(Page.HOME)
        wireLegacyButtons()
        wireNewUi()

        // Local-only info: no shell needed, so it is available even before Shizuku.
        // 行内已经有「设备型号 / 内核版本」小标题，值里不再重复前缀。
        binding.tvDeviceModel.text = "${Build.MANUFACTURER} ${Build.MODEL}"
        binding.tvKernel.text = System.getProperty("os.version") ?: "未知"
        // 关于页版本号直接从构建配置读取，与 build.gradle.kts 的 versionName 始终一致，
        // 不再靠 strings.xml 手改（历史上曾长期停留在 2.2.5）。
        binding.tvAboutVersion.text = "${BuildConfig.VERSION_NAME}（内部版本 ${BuildConfig.VERSION_CODE}）"
        // 首页头部也显示版本，和关于页共用同一个来源，避免两处对不上。
        binding.tvHomeVersion.text = "v${BuildConfig.VERSION_NAME}"

        updateClock()
        startClockLoop()
        startStateLoop()
        refreshShizukuState()

        // 自助适配卡片：先用本地 os.version 显示状态（不依赖 Shizuku），
        // 连上之后 checkCompatibility() 会用 uname -r 校正 currentKernel 再刷一次。
        currentKernel = System.getProperty("os.version")?.trim().orEmpty()
        refreshAdaptCard()

        // ShizukuProvider 异步送达 binder，收到后刷新状态（回调在 binder 线程）
        ShizukuController.observeBinder {
            runOnUiThread { refreshShizukuState() }
            lifecycleScope.launch(Dispatchers.IO) {
                if (!grinding) {
                    // 设备现场只抓一次：2.2.9 每次 binder 回调都重打一份 45 行快照，
                    // 四个会话复制四遍，把真正的结论全淹了。
                    if (!snapshotDone) {
                        snapshotDone = true
                        LogStore.sync(force = true, reason = "打开软件")
                        // 崩溃补偿：上次跑链路 A 时内核 panic 重启、App 被杀，
                        // onRoot 的 finally 来不及汇总。这里在 Shizuku 授权后
                        // 把残留的设备日志补进 HonorRoot-Log；内容 hash 去重，
                        // 和 finally 的正常汇总不会重复写入。
                        DeviceLogCollector.collect(this@MainActivity)
                    }
                    checkCompatibility()
                }
                // 每次打开软件：确认 KernelSU 管理器是配套的 v3.3.0，
                // 版本不对就卸载错误版并重装内置正确版（不需要 root）。
                enforceKsuVersion()
            }
        }

        log("[init] 日志文件：${LogStore.logFilePath()}（下载/XiaoDao/ 里也有一份，内容相同）")

        // 启动即弹免责声明，须勾选同意后手动点按钮关闭（不再倒计时自动关闭）
        showDisclaimerDialog()
    }

    /**
     * 打开软件即弹出的免责声明：磨砂玻璃卡片，**不再倒计时自动关闭**。
     *
     * 交互改成"明确同意"：先勾选「我已阅读并同意条款」，上面那个
     * 「我认真观看了以上文本 出事后我不会找开发者麻烦」按钮才从灰色变为可点；
     * 点按钮才关弹窗。不勾选时点按钮、点空白处、按返回键都不能关
     * （setCancelable(false) + 不挂 scrim 的 dismiss）。
     */
    private fun showDisclaimerDialog() {
        val dialog = Dialog(this)
        dialog.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
        dialog.setContentView(R.layout.dialog_disclaimer)
        dialog.setCancelable(false)
        dialog.setCanceledOnTouchOutside(false)
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT
            )
        }

        val card = dialog.findViewById<View>(R.id.card)
        val cbAgree = dialog.findViewById<CheckBox>(R.id.cbAgree)
        val btnAgree = dialog.findViewById<Button>(R.id.btnAgree)

        // 默认灰色不可点：勾选框由 GONE 变 VISIBLE? 不需要——XML 里就是 disabled
        btnAgree.isEnabled = false
        cbAgree.setOnCheckedChangeListener { _, checked ->
            btnAgree.isEnabled = checked
        }
        btnAgree.setOnClickListener {
            // 双保险：只有勾选后按钮才可点，这里再判一次，避免误触穿透
            if (cbAgree.isChecked) dialog.dismiss()
        }

        // 入场：轻微放大 + 淡入，呼应 Liquid Glass 的弹性手感
        card.alpha = 0f
        card.scaleX = 0.92f
        card.scaleY = 0.92f
        card.animate()
            .alpha(1f).scaleX(1f).scaleY(1f)
            .setDuration(resources.getInteger(R.integer.ds_dur_standard).toLong())
            .setInterpolator(OvershootInterpolator(1.2f))
            .start()

        dialog.show()
    }

    /** 关于页「赞助作者」：全屏展示赞赏码，点击任意位置（含二维码本身）关闭。 */
    private fun showSponsorDialog() {
        val dialog = Dialog(this)
        dialog.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
        dialog.setContentView(R.layout.dialog_sponsor)
        dialog.setCancelable(true)
        dialog.setCanceledOnTouchOutside(true)
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT
            )
        }

        val root = dialog.findViewById<View>(R.id.sponsorRoot)
        val qr = dialog.findViewById<ImageView>(R.id.qrImage)

        // 从 assets 读取赞赏码（不经过 AAPT 重编码，原图无损）
        val bmp = runCatching {
            assets.open("sponsor_qr.jpg").use { BitmapFactory.decodeStream(it) }
        }.getOrNull()
        if (bmp == null) {
            toast("赞赏码资源缺失")
            dialog.dismiss()
            return
        }
        qr.setImageBitmap(bmp)

        // 点击任意位置关闭（含二维码本身与四周暗色区域）
        val close = View.OnClickListener { dialog.dismiss() }
        root.setOnClickListener(close)
        qr.setOnClickListener(close)

        dialog.show()
    }

    /**
     * 闪退日志写进**同一份**主日志（不再单开 crash_latest.txt）。
     * 头部「致命问题」同步标红，用户打开文件第一屏就能看到原因。
     */
    private fun installCrashLogger() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val sw = java.io.StringWriter()
                throwable.printStackTrace(java.io.PrintWriter(sw))
                val brief = "${throwable.javaClass.simpleName}: ${throwable.message ?: "无错误信息"}"
                LogStore.append("[闪退] App 异常退出：$brief（线程 ${thread.name}）")
                sw.toString().lines().take(20).forEach { LogStore.append("[闪退] $it") }
                LogStore.setFatal("App 闪退：$brief")
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

    /** Design system micro interactions: a 0.97 press on every action and a
     *  staggered fade up for the home page. Cosmetic only, never fatal. */
    private fun applyMicroInteractions() = runCatching {
        listOf<View>(
            binding.btnClear,
            binding.btnRefreshCompat, binding.btnEnvCheck, binding.btnStartRoot, binding.btnAuthorHome,
            binding.cardBootAdapt, binding.btnSponsorHome, binding.btnSponsorRoot,
            binding.btnShareLog
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
        binding.cardDevice.post {
            val card = binding.cardDevice
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
        // 连接/部署/状态/管理器/日志页 Root 五个按钮已从布局移除：
        // 连接走首页状态行，物料由一键 Root 自动部署，状态启动即采集，
        // 管理器打开 App 自动检测安装，Root 用引导页大按钮。
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

        // 首页「KSU」行：版本不对时点它直接下载/重装正确版本
        binding.llKsuVersion.setOnClickListener {
            if (ksuVersionOk == false) downloadKsuManager()
        }
        binding.tvKsuVersion.setOnClickListener {
            if (ksuVersionOk == false) downloadKsuManager()
        }

        binding.btnRefreshCompat.setOnClickListener {
            if (ksuVersionOk == false) downloadKsuManager()
            else lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
        }
        // 环境自检：不依赖 profile / 白名单，1 秒回答「这台机器能不能跑链路 B」。
        // 先于 boot.img 适配执行，避免为一颗 tracefs 已被锁死的内核白做 profile。
        binding.btnEnvCheck.setOnClickListener {
            lifecycleScope.launch(Dispatchers.IO) {
                log("[env] 环境自检：tracefs 写入能力…")
                val tf = EnvProbe.tracefs()
                tf.detail.forEach { log("[env] ${it.take(160)}") }
                log("[env][结论] ${tf.summary}")
                // 这里只报告探测事实，不下「链路 B 一定跑不了」的定论：payload 的
                // check 走另一套开事件的路径，MAG-AN00 上就出现过探针 deny、check
                // 却 READY 的情况。真要下结论，需要跑一次提权让 check 说话。
                status(if (tf.usable) "tracefs 可直写，链路 B 大概率可运行" else "tracefs 直写被拒，需跑一次 check 复核")
                if (!tf.usable) {
                    LogStore.setFatal(
                        "环境自检：${tf.summary}；链路 B 需 payload 自检复核后才能确认",
                        LogStore.RANK_ENV
                    )
                }
            }
        }
        // 多管理器：月虹式扫描本机带 libksud.so 的 KernelSU 兼容管理器，用户自选目标。
        binding.btnPickManager.setOnClickListener { pickManager() }
        refreshManagerUi()
        // 全量包链接 → boot.img → 自助适配 → 提权（月虹 1.7.0 的远程 OTA 思路）。
        binding.btnOtaAdapt.setOnClickListener { startOtaAdapt() }

        binding.btnStartRoot.setOnClickListener { onStartRoot() }

        // 自助适配卡片：点一下选 boot.img，长按清除已生成的结果。
        binding.cardBootAdapt.setOnClickListener { pickBootImage() }
        binding.cardBootAdapt.setOnLongClickListener {
            clearAdaptedProfile()
            true
        }

        binding.btnAuthorHome.setOnClickListener { openUrl(AUTHOR_HOME_URL) }
        binding.btnSponsor.setOnClickListener { showSponsorDialog() }
        binding.btnSponsorHome.setOnClickListener { showSponsorDialog() }
        binding.btnSponsorRoot.setOnClickListener { showSponsorDialog() }
        binding.btnShareLog.setOnClickListener { shareLogToQqGroup() }
        binding.tvGithub.setOnClickListener { openUrl(GITHUB_URL) }
        binding.tvQq.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Author QQ", AUTHOR_QQ))
            toast("已复制作者QQ：$AUTHOR_QQ")
        }
    }

    /** 选中态只改图标 tint 与文字色，不再整块改 alpha —— alpha 会把
     *  玻璃胶囊也一起压暗，选中项反而看起来更脏。 */
    private fun applyTabVisuals(page: Page) {
        val active = getColor(R.color.ds_primary)
        val idle = getColor(R.color.ds_on_surface_muted)
        listOf(
            Triple(binding.navIconHome, binding.navLabelHome, page == Page.HOME),
            Triple(binding.navIconRoot, binding.navLabelRoot, page == Page.ROOT),
            Triple(binding.navIconAbout, binding.navLabelAbout, page == Page.ABOUT)
        ).forEach { (icon, label, selected) ->
            val color = if (selected) active else idle
            icon.imageTintList = ColorStateList.valueOf(color)
            label.setTextColor(color)
            label.alpha = if (selected) 1f else 0.9f
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
        applyTabVisuals(page)

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
            paintChip(binding.tvShizukuState, if (granted) okColor else badColor)
            if (kernel.isNotEmpty()) binding.tvKernel.text = kernel
        }
    }

    /**
     * 双引擎兼容判定：按 `uname -r` 精确内核构建决定走链路 A 还是链路 B。
     * 机型只用于「已收录但无偏移」的提示，不作为放行门槛 —— 两条 exploit
     * 都按内核符号表工作，Build.MODEL 不参与二进制判定。
     */
    private suspend fun checkCompatibility() {
        if (grinding) return
        val modelFields = listOf(Build.MODEL, Build.DEVICE, Build.BOARD, Build.HARDWARE)

        var kernel = ""
        if (runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            val r = ShizukuController.exec("uname -r", 8_000)
            if (r.code == 0 && r.out.isNotBlank()) kernel = r.out.trim()
        }
        if (kernel.isBlank()) kernel = System.getProperty("os.version")?.trim().orEmpty()
        currentKernel = kernel

        val match = EngineCatalog.resolve(this, kernel, modelFields)
        engineMatch = match
        val ok = match.engine == Engine.GHOSTLOCK || match.engine == Engine.EXTRACTKIT
        if (!ok && runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            LogStore.setFatal("当前内核未收录，无法提权（可在提权页导入 boot.img 自助适配）")
        }

        // 【老版配方回归 · 2026-11-15】删掉「探针 slide ≥4 GiB 就判不兼容」。
        // 老版成功日志开头的快照里就有 `slide=0x1caf600000 votes=2901`
        // （约 123 GiB），同一台机随后一次 ROOTED，说明该判据是误判，
        // 会把本来可用的内核标成「重试只会重启」。结论行只按内核收录表判定。

        withContext(Dispatchers.Main) {
            compatible = ok
            val (text, color) = when (match.engine) {
                Engine.GHOSTLOCK, Engine.EXTRACTKIT ->
                    "✔ ${getString(R.string.root_check_ok)}" to R.color.glass_ok
                Engine.KNOWN_ONLY ->
                    "⚠ ${getString(R.string.root_check_kernel_bad)}" to R.color.glass_warn
                Engine.NONE ->
                    "✘ ${getString(R.string.root_check_bad)}" to R.color.glass_bad
            }
            binding.tvCompat.text = text
            binding.tvCompat.setTextColor(getColor(color))
            // KernelSU 版本行：首页显示，启动时由 enforceKsuVersion() 刷新。
            updateKsuVersionRow()
            // 一键 Root 按钮：内核兼容性与 KSU 版本必须同时通过。
            // 注意 ksuVersionOk 为 null 时（还没查过、比如 Shizuku 未连接）不置灰，
            // 避免用户还没连上 Shizuku 就永远点不了——onRoot() 里会再次检查。
            val knownBad = ksuVersionOk == false
            binding.btnStartRoot.visibility = if (ok) View.VISIBLE else View.GONE
            binding.btnStartRoot.isEnabled = ok && !knownBad
            binding.btnStartRoot.text = if (knownBad) getString(R.string.root_ksu_bad)
                else getString(R.string.root_start)
            // 兼容卡片内的 KSU 版本提示（与首页行同源，只提权页显示）
            binding.tvKsuCompat.visibility = if (ok && knownBad) View.VISIBLE else View.GONE
            // 兼容卡片的「重新检测」按钮：KSU 不正确时变成「下载正确版本」
            binding.btnRefreshCompat.text = if (knownBad) getString(R.string.btn_download_ksu)
                else getString(R.string.root_refresh)
            // 提权引擎介绍（引擎名 / 收录内核数 / 判定原因）已按用户要求从提权页删除，
            // 兼容卡片只保留一行结论；双引擎调度仍在 EngineCatalog.resolve() 里照常工作。
            refreshAdaptCard()
        }
    }

    // ------------------------------------------------------------ 多管理器 / 全量包链接

    private fun refreshManagerUi() {
        val pkg = ManagerSelection.selected(this)
        val label = ManagerSelection.selectedLabel(this)
        // 所有链路共用同一份选择：KsuUserspace 的补装/重启管理器都读这个字段。
        // 原来只在 onRoot() 里赋值，用户先在工具页切了管理器、再点「安装管理器」
        // 时仍会去重启上一个包 —— 这里在每次刷新 UI 时同步。
        KsuUserspace.selectedManager = pkg
        // 配套状态必须跟着包名一起显示：选到 7kimisu/SukiSU 时，用户第一眼就该
        // 知道内置 kernelsu.ko 不认它，而不是等提权完发现管理器一片空白。
        binding.tvManagerState.text = getString(R.string.mgr_chosen, label, pkg) +
            " · " + ManagerCatalog.suitabilityText(pkg)
    }

    /** 扫描带 libksud.so 的已装管理器；用户选择后所有提权链共用这个包名。 */
    private fun pickManager() {
        if (managersBusy) { toast("正在处理管理器，请稍候"); return }
        managersBusy = true
        lifecycleScope.launch(Dispatchers.IO) {
            val found = ManagerSelection.scan(this@MainActivity)
            withContext(Dispatchers.Main) {
                managersBusy = false
                if (found.isEmpty()) {
                    log("[mgrs] 未找到带有可识别 ksud 的管理器；保持当前选择")
                    toast("未扫描到兼容管理器（需要 APK 内含 libksud.so）")
                    return@withContext
                }
                // 列表里直接标出配套性，避免用户选完才发现用不了。
                val items = found.map {
                    "${it.label} · ${it.packageName}  [${ManagerCatalog.suitabilityText(it.packageName)}]"
                }.toTypedArray()
                AlertDialog.Builder(this@MainActivity)
                    .setTitle(R.string.mgr_title)
                    .setItems(items) { _, which ->
                        val m = found[which]
                        if (ManagerCatalog.bundledKoFor(m.packageName)) {
                            applyManager(m)
                        } else {
                            confirmThirdParty(m)
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    private fun applyManager(m: ManagerSelection.Manager) {
        ManagerSelection.save(this, m)
        refreshManagerUi()
        log("[mgrs] 已选择管理器：${m.label}（${m.packageName}）· ${ManagerCatalog.suitabilityText(m.packageName)}")
        toast("已选择 ${m.label}")
    }

    /**
     * 第三方分支（7kimisu / SukiSU / BakaSU / KernelSU Next …）确认框。
     *
     * 不直接禁止：用户可能只是想让这个 App 留在设备上，或准备之后自己换成
     * 该分支的 kernelsu.ko。但必须把「切了也管不了」讲在前面。
     */
    private fun confirmThirdParty(m: ManagerSelection.Manager) {
        val dir = ManagerCatalog.workingDirOf(m.packageName)
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.mgr_tp_title, m.label))
            .setMessage(getString(R.string.mgr_tp_msg, dir))
            .setPositiveButton(R.string.mgr_tp_switch) { _, _ -> applyManager(m) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** 粘贴全量包 https 链接，本地下载/解包/适配，复用同一套 boot.img 分析流程。 */
    private fun startOtaAdapt() {
        if (adaptBusy) { toast("正在解析上一份镜像，请稍候"); return }
        if (grinding) { toast("提权进行中，等本轮结束再导入"); return }
        val url = binding.etOtaUrl.text?.toString()?.trim().orEmpty()
        if (url.isBlank()) { toast("请先粘贴全量包下载链接"); return }
        adaptBusy = true
        binding.tvAdaptState.text = getString(R.string.boot_adapt_busy)
        binding.tvAdaptHint.visibility = View.GONE
        binding.pbAdapt.visibility = View.VISIBLE
        binding.pbAdapt.progress = 0
        log("[ota] 从链接导入全量包：$url")
        lifecycleScope.launch(Dispatchers.IO) {
            val result = OtaBootImporter.fetch(this@MainActivity, url) { pct, msg ->
                log("[ota] $msg")
                runOnUiThread { binding.pbAdapt.progress = pct.coerceIn(0, 99) }
            }
            if (!result.ok || result.file == null) {
                adaptBusy = false
                withContext(Dispatchers.Main) {
                    binding.pbAdapt.visibility = View.GONE
                    binding.tvAdaptState.text = getString(R.string.boot_adapt_fail, result.message)
                    binding.tvAdaptState.setTextColor(getColor(R.color.ds_error))
                }
                log("[ota][失败] ${result.message}")
                return@launch
            }
            log("[ota] ${result.message}，交给自助适配解析")
            startBootAdapt(Uri.fromFile(result.file))
        }
    }

    // ------------------------------------------------------------ 自助适配（导入 boot.img）

    private fun pickBootImage() {
        if (adaptBusy) {
            toast("正在解析上一份 boot.img，请稍候")
            return
        }
        if (grinding) {
            toast("提权进行中，等本轮结束再导入")
            return
        }
        runCatching { bootImagePicker.launch(arrayOf("*/*")) }
            .onFailure { toast("打不开文件选择器：${it.message?.take(80)}") }
    }

    /**
     * 解析用户选的 boot.img：切 kernel → BTF/反汇编拿结构偏移 → kallsyms →
     * call site → 336 B device.cfg。全部在本地完成，不需要 root，也不需要联网。
     */
    private fun startBootAdapt(uri: Uri) {
        if (adaptBusy) return
        adaptBusy = true
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: uri.toString()
        binding.tvAdaptState.text = getString(R.string.boot_adapt_busy)
        binding.tvAdaptState.setTextColor(getColor(R.color.glass_warn))
        binding.tvAdaptHint.visibility = View.GONE
        binding.pbAdapt.visibility = View.VISIBLE
        binding.pbAdapt.progress = 0
        log("[boot] ==== 自助适配：开始解析 boot.img ====")
        log("[boot] 文件：$name")

        lifecycleScope.launch {
            val outcome = SelfAdapt.analyze(this@MainActivity, uri, currentKernel) { msg ->
                log("[boot] $msg")
                runOnUiThread {
                    binding.pbAdapt.progress = (binding.pbAdapt.progress + 6).coerceAtMost(95)
                }
            }
            adaptBusy = false
            binding.pbAdapt.visibility = View.GONE
            binding.pbAdapt.progress = 0
            if (outcome.ok && outcome.adapted != null) {
                val a = outcome.adapted
                log("[boot] ✔ ${outcome.message}：${a.release}（${a.symbolCount} 个符号，来源 ${a.source}）")
                binding.tvAdaptState.text = when {
                    !outcome.sameKernel -> getString(R.string.boot_adapt_other, a.release)
                    !outcome.familySupported ->
                        getString(R.string.boot_adapt_ok_nofam, a.release, SelfAdapt.family(a.release))
                    else -> getString(R.string.boot_adapt_ok, a.release)
                }
                binding.tvAdaptState.setTextColor(
                    getColor(
                        if (outcome.sameKernel && outcome.familySupported) R.color.glass_ok
                        else R.color.glass_warn
                    )
                )
                toast(outcome.message)
                binding.tvAdaptHint.visibility = View.VISIBLE
                lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
            } else {
                log("[boot] ✘ 适配失败：${outcome.message}")
                binding.tvAdaptState.text = getString(R.string.boot_adapt_fail, outcome.message)
                binding.tvAdaptState.setTextColor(getColor(R.color.glass_bad))
                toast("适配失败：${outcome.message}")
            }
        }
    }

    /** 卡片底部状态行：本机是否已有可用的自助适配 profile。 */
    private fun refreshAdaptCard() {
        if (adaptBusy) return
        val hit = SelfAdapt.match(this, currentKernel)
        if (hit != null) {
            binding.tvAdaptState.text = if (SelfAdapt.familySupported(currentKernel)) {
                getString(R.string.boot_adapt_ok, hit.release)
            } else {
                getString(R.string.boot_adapt_ok_nofam, hit.release, SelfAdapt.family(currentKernel))
            }
            binding.tvAdaptState.setTextColor(
                getColor(
                    if (SelfAdapt.familySupported(currentKernel)) R.color.glass_ok else R.color.glass_warn
                )
            )
            binding.tvAdaptHint.visibility = View.VISIBLE
            return
        }
        val other = SelfAdapt.list(this).firstOrNull()
        if (other != null) {
            binding.tvAdaptState.text = getString(R.string.boot_adapt_other, other.release)
            binding.tvAdaptState.setTextColor(getColor(R.color.glass_warn))
            binding.tvAdaptHint.visibility = View.VISIBLE
            return
        }
        binding.tvAdaptState.text = getString(R.string.boot_adapt_none)
        binding.tvAdaptState.setTextColor(getColor(R.color.glass_text_faint))
        binding.tvAdaptHint.visibility = View.GONE
    }

    private fun clearAdaptedProfile() {
        if (grinding || adaptBusy) {
            toast("当前有任务在跑，稍后再试")
            return
        }
        val target = SelfAdapt.match(this, currentKernel) ?: SelfAdapt.list(this).firstOrNull()
        if (target == null) {
            toast("还没有可清除的适配结果")
            return
        }
        SelfAdapt.delete(this, target.key)
        log("[boot] 已清除自助适配 profile：${target.release}")
        toast(getString(R.string.boot_adapt_deleted))
        refreshAdaptCard()
        lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
    }

    private fun onStartRoot() {
        if (!compatible) {
            toast("当前内核构建未收录，无法进行临时 Root")
            return
        }
        if (ksuVersionOk == false) {
            toast("KernelSU 管理器版本不正确，请先下载正确版本")
            downloadKsuManager()
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
        binding.logScroll.post { binding.logScroll.fullScroll(View.FOCUS_DOWN) }
        onRoot()
    }

    /**
     * 提权页「分享日志」：直接拉起 QQ 的「发送给朋友/群聊」界面，把日志文件作为
     * 附件带过去，让用户自己选群。不再跳浏览器群链接（用户点开只会开浏览器、
     * 并不会真正分享，等于没做）。
     *
     * 日志落点有三处（public 用户可见 / external-files 降级 / files 私有），
     * 按存在性挑第一个；target 34 下必须用 FileProvider 发 content:// URI，
     * 否则 file:// 会抛 FileUriExposedException。先直接 startActivity 指定 QQ 包名，
     * 确保进的是 QQ 而不是系统分享面板；仅当拉起失败才回退系统 chooser。
     * 不预先用 getApplicationInfo 判断安装状态（Android 11+ 包可见性会误判）。
     */
    private fun shareLogToQqGroup() {
        // 1) 找到真正存在的日志文件（public 优先，其次降级路径，最后私有副本）
        val candidates = listOfNotNull(
            LogStore.logFilePath(),          // 用户可见：下载/XiaoDao 或 external-files 降级
            LogStore.sessionPath()           // app 私有 filesDir/HonorRoot-Log.private.log
        ).map { File(it) }
        val file = candidates.firstOrNull { it.isFile && it.length() > 0L }
        if (file == null) {
            log("[日志][错误] 分享失败：找不到日志文件")
            toast("日志文件还没生成，先运行一次再分享")
            return
        }

        // 2) 生成 content:// URI 并授权临时读权限
        val uri = runCatching {
            FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        }.getOrNull()
        if (uri == null) {
            log("[日志][错误] 分享失败：无法生成文件 URI")
            toast("分享失败，请手动到 下载/XiaoDao 找日志")
            return
        }

        // 3) ACTION_SEND 把日志作为附件；同时带一段正文（含交流群号）
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "HonorRoot 排障日志")
            putExtra(Intent.EXTRA_TEXT, "HonorRoot 日志（交流群 $QQ_GROUP_NO），请作者帮忙排障")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        // 4) 直接拉 QQ 自带的「选择群聊/好友」界面；拉不起来（没装 / 被
        //    Android 11+ 包可见性挡住）再回退到系统分享面板。
        //    不用 getApplicationInfo 预判断：target 34 且清单无 <queries> 时，
        //    即便装了 QQ 也可能抛 NameNotFoundException 被误判成「没装」，
        //    那样永远进系统面板，用户就到不了 QQ 选群这一步。直接 startActivity
        //    再按结果回退，才是承诺「打开 QQ 分享」的可靠做法。
        val toQq = Intent(send).apply { setPackage(QQ_PACKAGE) }
        val qqResult = runCatching { startActivity(toQq) }
        val viaQq = qqResult.isSuccess

        val launched = if (viaQq) true else runCatching {
            startActivity(Intent.createChooser(send, "分享 HonorRoot 日志"))
        }.isSuccess
        if (launched) {
            log("[日志] 已打开分享（${file.name}，${file.length()} B）" +
                if (viaQq) "，请在QQ里选择群聊发送" else "，请在系统面板里选QQ")
            toast(if (viaQq) "请在QQ里选择群聊发送" else "请在选择面板里选QQ")
        } else {
            log("[日志][错误] 分享 Intent 无法启动")
            toast("无法打开分享，请检查是否安装了QQ")
        }
    }

    private fun openUrl(url: String) {
        runCatching {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        }.onFailure { toast("无法打开链接：${it.message}") }
    }

    // ------------------------------------------------------------ Shizuku

    private fun refreshShizukuState() {
        binding.tvStatus.text = when {
            !ShizukuController.isAvailable() -> {
                // 前置条件级别：设备刚重启、Shizuku 尚未启动时，不能冲掉上次
                // 提权链路得出的实质结论（第一步崩溃 / 自检失败 / 成功等）。
                LogStore.setFatal(
                    "Shizuku 未运行，无法提权（需在 Shizuku 里用无线调试启动服务）",
                    LogStore.RANK_PRECONDITION
                )
                getString(R.string.hint_shizuku_missing)
            }
            !ShizukuController.hasPermission() -> {
                LogStore.setFatal(
                    "Shizuku 未授权，无法提权（点首页「连接 Shizuku」授权）",
                    LogStore.RANK_PRECONDITION
                )
                "Shizuku 已运行，但未授权，点「连接 Shizuku」授权"
            }
            else -> {
                // 只清掉「Shizuku 未授权」这类旧结论，别把已得出的成功结论刷掉
                LogStore.clearFatalIfStartsWith("Shizuku")
                "就绪：Shizuku 已连接，可部署物料"
            }
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

    /**
     * 「一键临时 Root」前必须确认设备端物料**版本正确**。
     *
     * 2026-11-14 老版本的致命 bug：这里只做 `test -x` / `test -f`，设备上有
     * 旧文件就直接 return true。用户覆盖安装新 APK 后，设备端仍然是 2072 B 的
     * ksu_lateload.sh（只有 ksud insmod），于是模块 Live 却永远没有
     * `/data/adb/ksud`，`su 0 id` 恒为 code=127。两份 ghostlock_latest.log
     * 都是同一个问题。
     *
     * 现在改为：版本戳 + 每个关键文件的字节数逐项比对，不一致立刻全量覆盖，
     * 并按 uname -r 选择对应偏移表的 exploit 二进制。
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
        // 兼容检测可能还没跑完（例如用户刚授权 Shizuku 就直接点部署）。
        // 内核字符串决定用哪张偏移表，绝不能拿空值去选二进制。
        if (currentKernel.isBlank()) {
            currentKernel = ShizukuController.exec("uname -r", 8_000).out
                .replace("\u0000", "").trim()
            if (currentKernel.isNotBlank()) log("[deploy] 读取到内核：$currentKernel")
        }
        if (AssetDeployer.verify(this@MainActivity, currentKernel, ::log)) {
            val handoff = ShizukuController.exec(
                "test -f /data/local/tmp/ksu_fne/handoff && echo READY", 15_000
            )
            if (handoff.code == 0 && handoff.out.contains("READY")) {
                // 物料没变也要同步管理器选择：脚本收尾按这个包名拉起 App。
                AssetDeployer.syncManager(this@MainActivity)
                return true
            }
            log("[deploy] handoff 标记丢失，重新部署以恢复 root 通道链路")
        }
        log("[deploy] 设备端物料缺失或版本过旧，强制全量重新部署…")
        if (!AssetDeployer.deploy(this@MainActivity, ::log, currentKernel)) return false
        val ok = AssetDeployer.verify(this@MainActivity, currentKernel, ::log)
        if (ok) log("[deploy] 自动部署完成并逐字节校验通过 ✔")
        else log("[deploy][错误] 自动部署后仍未通过校验，请检查 /data/local/tmp 可写性")
        return ok
    }

    private fun onRoot() {
        if (!ShizukuController.hasPermission()) { toast("请先连接 Shizuku 并授权"); return }
        // 所有提权链共享工作台选择的管理器（月虹式多管理器）。
        KsuUserspace.selectedManager = ManagerSelection.selected(this)

        if (grinding) { toast("临时 Root 正在运行中"); return }
        // 置位必须发生在 launch 之前：onClick 在主线程串行分发，检查+置位同处
        // 主线程才是原子的。原来把 grinding=true 放进 IO 协程，两次快速点击都
        // 会在协程真正启动前通过检查 → 两个 exploit 并发 fork 风暴/物料互相覆盖。
        grinding = true
        val match = engineMatch
        val kernel = currentKernel
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                when (match.engine) {
                    Engine.EXTRACTKIT -> {
                        if (match.profileIdx == SelfAdapt.CUSTOM_PROFILE) {
                            log("[engine] 链路 B：ExtractKit 98260 / 自助适配 profile（${match.label}）")
                        } else {
                            log("[engine] 链路 B：ExtractKit 98260 / profile #${match.profileIdx}（${match.label}）")
                        }
                        ExtractKitRunner(
                            this@MainActivity, match.profileIdx, match.label, ::log, ::status
                        ).run(kernel)
                    }
                    Engine.GHOSTLOCK -> {
                        log("[engine] 链路 A：GhostLock W1/W2 + KSU 晚加载")
                        GrindRunner(::log, ::status, { ensurePayloads() }).run()
                    }
                    else -> log("[engine][错误] 当前内核没有可用提权链，已中止")
                }
            } finally {
                grinding = false
                // 2026-11-20：把设备侧 payload/exploit 日志（w1/w2/fake/ksu_stage/
                // cve payload 等）整段汇总进 HonorRoot-Log。链路无论成功、失败、
                // 提前返回都会经过这里，用户只需打开这一个文件就能看全完整流程。
                DeviceLogCollector.collect(this@MainActivity)
                // root 完成后自动跳转到 KernelSU 管理器（su 真的可用才跳，
                // 失败说明本 boot 没拿到 root，没必要跳转）。
                if (KsuUserspace.suReady()) {
                    log("[root] 临时 Root 已就绪 → 自动打开 KernelSU 管理器")
                    launchKsuManager()
                }
                withContext(Dispatchers.Main) { refreshShizukuState() }
            }
        }
    }

    private fun onManagers() {
        if (!ShizukuController.hasPermission()) { toast("请先连接 Shizuku"); return }
        if (managersBusy) { toast("该步骤正在运行，请勿重复点击"); return }
        managersBusy = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                runManagers()
            } finally {
                managersBusy = false
            }
        }
    }

    private suspend fun runManagers() {
            log("[mgrs] === 安装管理器 + 模块 ===")
            log("[mgrs] 内置管理器 = KernelSU v3.3.0 / code 32601 / me.weishu.kernelsu")
            log("[mgrs] 与定制 kernelsu.ko 配套；勿随意换成其它 commit 编译的版本")
            // 第三方分支（7kimisu / SukiSU / BakaSU …）的 APK 不在本 APK 的 assets 里，
            // 也不该被官方包覆盖安装 —— 它们的签名不配套内置模块，装了也连不上内核。
            val chosen = ManagerSelection.selected(this)
            if (!ManagerCatalog.bundledKoFor(chosen) && !ManagerSelection.installed(this, chosen)) {
                log("[mgrs][提示] 当前选择 $chosen 属第三方分支，本 APK 未内置其安装包")
                log("[mgrs][提示] 请自行安装该管理器，或回到「选择管理器」切回官方版")
            }

            // 0) 先如实探测状态并显示真实原因，避免在没 root 时空等 2 分钟。
            //    KSU 3.3.0 的 /system/bin/su 是 sucompat 虚拟路径，只写
            //    `su 0 id` 在部分 shell 上会报 inaccessible or not found；
            //    两种写法都试，判定只看 uid=0。
            val bc = ShizukuController.exec("getprop sys.boot_completed", 15_000).out.trim()
            val mods = ShizukuController.exec("grep -c kernelsu /proc/modules", 15_000).out.trim()
            val ksuLoaded = (mods.toIntOrNull() ?: 0) > 0
            val firstSu = ShizukuController.exec(
                "su -c id 2>&1; /system/bin/su -c id 2>&1", 15_000
            )
            log("[mgrs] 状态：boot_completed=$bc, kernelsu模块=$mods, su code=${firstSu.code}")
            log("[mgrs] su -c id 返回：${(firstSu.out + firstSu.err).trim().takeLast(120).ifEmpty { "（无输出）" }}")

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
                return
            }

            // 3) KSU 已加载、su 不可用：老版本在这里只是空等 12×5s，什么都没做，
            //    于是 `code=127 inaccessible or not found` 刷满整份日志。
            //    新版直接调用统一的补装入口（ksud install + 三阶段 + 重启管理器），
            //    补装后只短等 3×5s 让管理器 allowlist 生效。
            var suReady = firstSu.out.contains("uid=0")
            if (!suReady) {
                log("[mgrs] su 不可用 → 补装 KSU 用户态（与「一键临时 Root」同一条路径）")
                suReady = KsuUserspace.ensure(::log)
            }
            if (!suReady) {
                for (i in 0 until 3) {
                    delay(5_000)
                    val r = ShizukuController.exec(
                        "su -c id 2>&1; /system/bin/su -c id 2>&1", 10_000
                    )
                    log("[mgrs] 管理器授权后复检 ${i + 1}/3: code=${r.code} ${(r.out + r.err).trim().takeLast(100).ifEmpty { "无输出" }}")
                    if (r.out.contains("uid=0")) { suReady = true; break }
                }
            }
            if (!suReady) {
                log("[mgrs][错误] 补装后 shell 域 su 仍不可用（allowlist 未放行或 ksud 未生成）")
                log("[mgrs][提示] 打开一次 KernelSU 管理器后再试；也可点「查看状态」确认")
                toast("su 暂不可用，详见日志")
                return
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
                return
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

    // ------------------------------------------------------------- KSU 版本守卫 / 跳转 / 首页 KSU 行

    /** KernelSU 版本守卫（启动阶段）+ 首页 KSU 行刷新。
     *  每次 Shizuku 就绪后都跑一次：确认已安装的 KernelSU 管理器是配套 v3.3.0。 */
    private fun enforceKsuVersion() {
        if (ksuGuardBusy || managersBusy || grinding) return
        if (!ShizukuController.hasPermission()) return
        ksuGuardBusy = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val result = KsuVersionGuard.enforce(this@MainActivity, ::log)
                // 守卫跑完之后立刻重新查一次版本，让首页行与一键 Root 按钮反映真实状态。
                // 若守卫因 Shizuku 通道掉线而跳过，installedVersion() 必然也查不到，
                // 这时保留上一次已知状态，不要把「通道断」刷成「版本未知/不符」。
                if (result == "skipped") {
                    LogStore.setKsuVersion("未检测到（Shizuku 命令通道未连通）")
                } else if (result == "thirdparty") {
                    // 用户选了 7kimisu / SukiSU / BakaSU 等分支：内置模块不认它们的签名，
                    // 但提权仍由 ksud 的 allow_shell 提供，所以**不置灰**一键 Root，
                    // 只在 KSU 行如实说明，别让用户以为 root 坏了。
                    val pkg = ManagerSelection.selected(this@MainActivity)
                    ksuVersion = "${ManagerSelection.selectedLabel(this@MainActivity)}（第三方）"
                    ksuVersionOk = null
                    LogStore.setKsuVersion(
                        "${ManagerSelection.selectedLabel(this@MainActivity)} · " +
                                "内置模块不配套（工作目录 ${ManagerCatalog.workingDirOf(pkg)}）"
                    )
                } else {
                    val fresh = KsuVersionGuard.installedVersion()
                    ksuVersion = fresh?.first
                    ksuVersionOk = if (fresh == null) null else KsuVersionGuard.match(fresh)
                    // 头部「KSU 版本」实时反映真实结果，别让日志里写着「检测中…」。
                    LogStore.setKsuVersion(
                        if (fresh == null) "未检测到管理器（需授权 Shizuku）"
                        else "${fresh.first} / ${fresh.second}" +
                                if (ksuVersionOk == true) "（正确）" else "（版本不正确）"
                    )
                    if (ksuVersionOk == false) {
                        LogStore.setFatal("KernelSU 管理器版本不正确，需下载正确版本", LogStore.RANK_ENV)
                    }
                }
                withContext(Dispatchers.Main) {
                    updateKsuVersionRow()
                    when (result) {
                        "installed" -> toast("已安装配套 KernelSU 管理器 v3.3.0")
                        "fixed" -> toast("已纠正 KernelSU 管理器为 v3.3.0")
                        "failed" -> toast("KernelSU 管理器版本纠正失败，见日志")
                    }
                }
            } finally {
                ksuGuardBusy = false
            }
        }
    }

    /** 点击「下载正确版本」的完整动作：删除现有 KernelSU 管理器，
     *  再用内置 v3.3.0 APK 重装（不需要 root，Shizuku shell 权限即可）。
     *  用户看到的文案是「点我下载正确版本」，实际即「卸载错误版 + 重装内置正确版」。 */
    private fun downloadKsuManager() {
        if (!ShizukuController.hasPermission()) {
            toast("请先连接 Shizuku 并授权，才能下载正确版本")
            onConnect()
            return
        }
        if (ksuGuardBusy || managersBusy || grinding) {
            toast("KernelSU 管理器正在处理，请稍后再试")
            return
        }
        // 与 enforceKsuVersion 共用 ksuGuardBusy：两者都在卸载/安装同一个 KSU APK。
        // 主线程置位，挡住连点（本函数原先只检查别人的标志、自己从不置位）。
        ksuGuardBusy = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // 先删现有的（错误版本），再装内置正确版——哪怕 pm uninstall 失败，
                // 后续的 pm install -r 也会覆盖安装，不会漏掉。
                val un = ShizukuController.exec("su -c 'pm uninstall me.weishu.kernelsu' 2>&1", 30_000)
                if (un.code != 0 || un.out.contains("Failure", ignoreCase = true)) {
                    log("[ksudl] su 卸载未成功，回退 shell pm uninstall：${un.out.take(80).trim()}")
                    ShizukuController.exec("pm uninstall me.weishu.kernelsu 2>&1", 30_000)
                }
                log("[ksudl] 卸载现有版本 rc=${un.code} ${un.out.take(120).trim()}")
                delay(500)

                // 用内置物料重装（与 KsuVersionGuard 同源）
                ShizukuController.exec("mkdir -p /data/local/tmp/managers", 15_000)
                val data = assets.open("managers/KernelSU-manager.apk").use { it.readBytes() }
                val ok = ShizukuController.writeFile(data, "/data/local/tmp/managers/KernelSU-manager.apk")
                if (!ok) {
                    log("[ksudl][错误] 内置管理器 APK 落地失败")
                    toast("下载正确版本失败：APK 落地失败")
                    return@launch
                }
                val pm = ShizukuController.exec("pm install -r /data/local/tmp/managers/KernelSU-manager.apk 2>&1", 120_000)
                log("[ksudl] 安装内置 v3.3.0 rc=${pm.code} ${(pm.out + pm.err).takeLast(160).trim()}")
                if (pm.code == 0 && !pm.out.contains("Failure", ignoreCase = true)) {
                    // 安装成功 → 重新查版本并刷新界面
                    val fresh = KsuVersionGuard.installedVersion()
                    ksuVersion = fresh?.first
                    ksuVersionOk = fresh != null && KsuVersionGuard.match(fresh)
                    withContext(Dispatchers.Main) {
                        updateKsuVersionRow()
                        toast("已下载并安装配套 KernelSU 管理器 v3.3.0")
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        toast("下载正确版本失败，详见日志")
                    }
                }
            } catch (e: Exception) {
                log("[ksudl][异常] ${e.message?.take(120)}")
                ksuVersionOk = null  // 恢复为未确认状态，按钮不再置灰
                withContext(Dispatchers.Main) {
                    updateKsuVersionRow()
                    toast("下载正确版本失败：${e.message}")
                }
            } finally {
                // 「APK 落地失败」分支用 return@launch 提前退出，也必须释放互斥标志，
                // 否则此后所有「下载正确版本」点击都被永久挡住。
                ksuGuardBusy = false
            }
        }
    }

    /** 首页「KSU」行与提权页「一键 Root」按钮的联动：KSU 版本不对则按钮置灰。
     *  只读 `ksuVersion` / `ksuVersionOk`（由 enforceKsuVersion() 或
     *  downloadKsuManager() 填充），自己不起 shell。 */
    private fun updateKsuVersionRow() {
        val text = ksuVersion?.take(60) ?: getString(R.string.home_ksu_pending)
        binding.tvKsuVersion.text = when (ksuVersionOk) {
            true -> "KernelSU $text ✔"
            false -> getString(R.string.home_ksu_bad)
            null -> text
        }
        paintChip(binding.tvKsuVersion, when (ksuVersionOk) {
            true -> getColor(R.color.glass_ok)
            false -> getColor(R.color.glass_bad)
            null -> getColor(R.color.glass_warn)
        })
    }

    /**
     * 状态胶囊：文字着色 + 同色 15% 背景。以前只有一行彩色文字，
     * 在一堆正文里并不显眼；现在是一颗小 pill，扫一眼就能分辨状态。
     */
    private fun paintChip(tv: TextView, color: Int) {
        tv.setTextColor(color)
        val bg = (color and 0x00FFFFFF) or (0x26 shl 24)
        tv.backgroundTintList = ColorStateList.valueOf(bg)
    }

    /** 打开当前选择的管理器主界面（root 完成后自动跳转用）。
     *  不再写死 `me.weishu.kernelsu/.ui.MainActivity`：第三方分支的入口类名各不相同，
     *  统一按 LAUNCHER intent 解析。 */
    private suspend fun launchKsuManager() {
        val pkg = ManagerSelection.selected(this)
        val r = ShizukuController.exec(
            "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p $pkg 2>&1",
            15_000
        )
        if (r.code != 0 && !r.out.contains("Starting", ignoreCase = true)) {
            log("[root][提示] 自动打开管理器失败（$pkg）：${r.out.take(120).trim()}")
        }
    }

    // ------------------------------------------------------------- helpers

    private fun log(line: String) {
        // 界面与文件显示同一份带时间戳、中文标签的文本；被去重丢弃的行直接跳过。
        val shown = LogStore.append(line)
        if (shown.isEmpty()) return
        runOnUiThread {
            logLines.appendLine(shown)
            val lines = logLines.lines()
            if (lines.size > MAX_LINES) {
                logLines.clear()
                logLines.append(lines.takeLast(MAX_LINES).joinToString("\n"))
            }
            binding.tvLog.text = logLines.toString()
            autoScrollLog()
            // 节流同步到 SD 卡（内部 4s 节流，不会每条都起进程）
            lifecycleScope.launch(Dispatchers.IO) { LogStore.sync() }
        }
    }

    /**
     * 日志自动滚动：新行追加后跟到最新，不用每次手动往下滑。
     * 但用户主动上翻看历史时不强行拽回——只有当前已在底部附近（一屏内）
     * 才跟随；用户翻到上面就保持其位置，看完了自己往下滑回底部即恢复跟随。
     */
    private fun autoScrollLog() {
        val sv = binding.logScroll
        sv.post {
            val child = sv.getChildAt(0) ?: return@post
            val atBottom = sv.scrollY + sv.height >= child.height - sv.height
            if (atBottom) sv.fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun status(text: String) {
        runOnUiThread { binding.tvStatus.text = text }
    }

    private fun toast(text: String) {
        runOnUiThread { Toast.makeText(this, text, Toast.LENGTH_SHORT).show() }
    }
}
