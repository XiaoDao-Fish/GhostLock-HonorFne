package com.ghostlock.honorfne

import android.animation.ValueAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.Manifest
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.animation.OvershootInterpolator
import android.widget.Button
import android.widget.CheckBox
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AlertDialog
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import java.io.File
import com.ghostlock.honorfne.ui.AppUi
import com.ghostlock.honorfne.ui.HomeTab
import com.ghostlock.honorfne.ui.LiveState
import com.ghostlock.honorfne.ui.ManagerEntry
import com.ghostlock.honorfne.ui.UiState
import com.ghostlock.honorfne.ui.UiStateHolder
import androidx.activity.compose.setContent
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

       
                                                      
                                                     
                                  
       
    private val ui = UiStateHolder()

       
                            
      
                                              
                                              
                                         
                                           
                      
       
    private val live = LiveState()

       
                       
      
                                              
                                                       
                   
       
    private val maxLogLines = 800
    private val logLines = arrayOfNulls<String>(maxLogLines)
    private var logWrite = 0
    private var logCount = 0

    private var compatible = false

                                     
    @Volatile
    private var engineMatch = EngineMatch(Engine.NONE)

    @Volatile
    private var currentKernel = ""

                                                           
    private var ksuVersion: String? = null
                                                                  
    private var ksuVersionOk: Boolean? = null

                                            
    @Volatile
    private var snapshotDone = false

                                               
    @Volatile
    private var adaptBusy = false

       
                                                  
                                                 
       
    private val bootImagePicker =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) startBootAdapt(uri)
        }

                                                                         
    private var currentPage = HomeTab.Home.ordinal

                                                                          
                                                                          
                                
    @Volatile
    private var grinding = false

                                                  
    @Volatile
    private var managersBusy = false

                                             
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

        
        
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 9001)
        }
        LogStore.init(this)
        installCrashLogger()

        
        setContent {
            AppUi(
                state = ui.state,
                live = live,
                onTabChange = { currentPage = it },
                onRoot = { onStartRoot() },
                onRefresh = { onRefreshCompat() },
                onEnvCheck = { onEnvCheck() },
                onPickManager = { pickManager() },
                onOtaUrlChange = { url -> ui.update { it.copy(otaUrl = url) } },
                onOtaAdapt = { startOtaAdapt() },
                onAuthor = { openUrl(AUTHOR_HOME_URL) },
                onSponsor = { showSponsorDialog() },
                onConnect = { onConnect() },
                onKsuTap = { if (ksuVersionOk == false) downloadKsuManager() },
                onCopyQq = { copyAuthorQq() },
                onOpenGithub = { openUrl(GITHUB_URL) },
                onClearProfile = { clearAdaptedProfile() },
                onPickBootImage = { pickBootImage() },
                onSelectManager = { pkg -> selectManager(pkg) },
                onDismissManager = { closeManagerDialog() },
                onClearLog = { clearLog() },
                onShareLog = { shareLogToQqGroup() },
                onBackFromLog = { ui.update { it.copy(rootLogOpen = false) } },
                onDismissSponsor = { ui.update { it.copy(sponsorDialogOpen = false) } }
            )
        }

        
        
        ui.update {
            it.copy(
                deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
                kernel = System.getProperty("os.version") ?: "未知",
                
                
                aboutVersion = "${BuildConfig.VERSION_NAME}（内部版本 ${BuildConfig.VERSION_CODE}）",
                
                homeVersion = "v${BuildConfig.VERSION_NAME}",
                aboutAuthor = "小刀",
                aboutQq = AUTHOR_QQ,
                aboutGithub = "github.com/XiaoDao-Fish"
            )
        }

        
        refreshManagerUi()

        updateClock()
        startClockLoop()
        startStateLoop()
        refreshShizukuState()

        
        
        currentKernel = System.getProperty("os.version")?.trim().orEmpty()
        refreshAdaptCard()

        
        ShizukuController.observeBinder {
            runOnUiThread { refreshShizukuState() }
            lifecycleScope.launch(Dispatchers.IO) {
                if (!grinding) {
                    
                    
                    if (!snapshotDone) {
                        snapshotDone = true
                        LogStore.sync(force = true, reason = "打开软件")
                        
                        
                        
                        
                        DeviceLogCollector.collect(this@MainActivity)
                    }
                    checkCompatibility()
                }
                
                
                enforceKsuVersion()
            }
        }

        log("[init] 主日志：${LogStore.logFilePath()}；调试日志：${LogStore.debugFilePath()}")
        log("[init] 分级：INFO 正常进展 / WARN 值得一看 / ERROR 真的出事 / DEBUG 只在调试日志里")

        
        showDisclaimerDialog()
    }

       
                                         
      
                                     
                                           
                                    
                                                   
       
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

        
        btnAgree.isEnabled = false
        cbAgree.setOnCheckedChangeListener { _, checked ->
            btnAgree.isEnabled = checked
        }
        btnAgree.setOnClickListener {
            
            if (cbAgree.isChecked) dialog.dismiss()
        }

        
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

                                              
       
                                                                  
                                                     
       
    private fun showSponsorDialog() {
        ui.update { it.copy(sponsorDialogOpen = true) }
    }

       
                                               
                                    
       
    private fun installCrashLogger() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val sw = java.io.StringWriter()
                throwable.printStackTrace(java.io.PrintWriter(sw))
                val brief = "${throwable.javaClass.simpleName}: ${throwable.message ?: "无错误信息"}"
                LogStore.error("[闪退] App 异常退出：$brief（线程 ${thread.name}）")
                sw.toString().lines().take(20).forEach { LogStore.debug("[闪退] $it") }
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

    

                                           
    private fun onRefreshCompat() {
        if (ksuVersionOk == false) {
            downloadKsuManager()
            return
        }
        lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
    }

       
                                                  
                                                        
       
    private fun onEnvCheck() {
        lifecycleScope.launch(Dispatchers.IO) {
            log("[env] 环境自检：tracefs 写入能力…")
            val tf = EnvProbe.tracefs()
            tf.detail.forEach { log("[env] ${it.take(160)}") }
            log("[env][结论] ${tf.summary}")
            
            
            
            status(if (tf.usable) "tracefs 可直写，链路 B 大概率可运行" else "tracefs 直写被拒，需跑一次 check 复核")
            if (!tf.usable) {
                LogStore.setFatal(
                    "环境自检：${tf.summary}；链路 B 需 payload 自检复核后才能确认",
                    LogStore.RANK_ENV
                )
            }
        }
    }

                                
    private fun copyAuthorQq() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("Author QQ", AUTHOR_QQ))
        toast("已复制作者QQ：$AUTHOR_QQ")
    }

                                             
    private fun clearLog() {
        logLines.fill(null)
        logWrite = 0
        logCount = 0
        live.logText = ""
    }

       
                                           
                  
       
    private fun joinLogLines(): String {
        if (logCount == 0) return ""
        val sb = StringBuilder(logCount * 64)
        val start = (logWrite - logCount + maxLogLines) % maxLogLines
        for (i in 0 until logCount) {
            val s = logLines[(start + i) % maxLogLines] ?: continue
            if (sb.isNotEmpty()) sb.append('\n')
            sb.append(s)
        }
        return sb.toString()
    }

    private fun updateClock() {
        val now = Date()
        val clockText = clockFmt.format(now)
        val dateText = dateFmt.format(now)
        val cal = Calendar.getInstance(shanghai, Locale.CHINA).apply { time = now }
        val hour = cal.get(Calendar.HOUR_OF_DAY)
        val greetingText = getString(
            when (hour) {
                in 5..10 -> R.string.home_greeting_morning
                in 11..17 -> R.string.home_greeting_noon
                else -> R.string.home_greeting_night
            }
        )
        live.clock = clockText
        live.dateLine = dateText
        live.greeting = greetingText
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
            ui.update {
                it.copy(
                    rootState = getString(
                        if (rooted) R.string.home_root_ok else R.string.home_root_no
                    ),
                    rootStateTone = if (rooted) UiState.TONE_OK else UiState.TONE_ERROR,
                    shizuku = getString(
                        if (granted) R.string.home_shizuku_ok else R.string.home_shizuku_no
                    ),
                    kernel = if (kernel.isNotEmpty()) kernel else it.kernel
                )
            }
        }
    }

       
                                                 
                                              
                                      
       
    private suspend fun checkCompatibility() {
        if (grinding) return
        val modelFields = listOf(
            Build.MODEL, Build.DEVICE, Build.PRODUCT, Build.BOARD, Build.HARDWARE
        )

        var kernel = ""
        if (runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            val r = ShizukuController.exec("uname -r", 8_000)
            if (r.code == 0 && r.out.isNotBlank()) kernel = r.out.trim()
        }
        if (kernel.isBlank()) kernel = System.getProperty("os.version")?.trim().orEmpty()
        currentKernel = kernel

        val match = EngineCatalog.resolve(this, kernel, modelFields)
        engineMatch = match
        val ok = match.engine == Engine.GHOSTLOCK ||
            match.engine == Engine.EXTRACTKIT ||
            match.engine == Engine.MODEL_PAYLOAD
        if (!ok && runCatching { ShizukuController.hasPermission() }.getOrDefault(false)) {
            LogStore.setFatal("当前内核未收录，无法提权（可在提权页导入 boot.img 自助适配）")
        }

        
        
        
        

        withContext(Dispatchers.Main) {
            compatible = ok
            val (text, color) = when (match.engine) {
                Engine.GHOSTLOCK, Engine.EXTRACTKIT, Engine.MODEL_PAYLOAD, Engine.AAP_PAYLOAD ->
                    "✔ ${getString(R.string.root_check_ok)}" to R.color.glass_ok
                Engine.KNOWN_ONLY ->
                    "⚠ ${getString(R.string.root_check_kernel_bad)}" to R.color.glass_warn
                Engine.NONE ->
                    "✘ ${getString(R.string.root_check_bad)}" to R.color.glass_bad
            }
            ui.update {
                it.copy(
                    
                    modelPackName = match.modelPack?.displayName.orEmpty(),
                    modelPackNote = match.modelPack?.note.orEmpty(),
                    modelPackWarning = match.modelPack?.warning.orEmpty(),
                    compatText = text,
                    compatTone = when (color) {
                        R.color.glass_ok -> UiState.TONE_OK
                        R.color.glass_warn -> UiState.TONE_WARN
                        R.color.glass_bad -> UiState.TONE_ERROR
                        else -> UiState.TONE_NEUTRAL
                    }
                )
            }
            
            updateKsuVersionRow()
            
            
            
            val knownBad = ksuVersionOk == false
            ui.update {
                it.copy(
                    rootButtonText = if (knownBad) getString(R.string.root_ksu_bad)
                    else getString(R.string.root_start),
                    rootButtonEnabled = ok && !knownBad
                )
            }
            
            ui.update {
                it.copy(ksuCompatText = if (ok && knownBad) getString(R.string.home_ksu_bad) else "")
            }
            
            ui.update {
                it.copy(
                    refreshLabel = if (knownBad) getString(R.string.btn_download_ksu)
                    else getString(R.string.root_refresh)
                )
            }
            
            
            refreshAdaptCard()
        }
    }

    

    private fun refreshManagerUi() {
        val pkg = ManagerSelection.selected(this)
        val label = ManagerSelection.selectedLabel(this)
        
        
        
        KsuUserspace.selectedManager = pkg
        
        
        
        ui.update {
            it.copy(
                managerState = getString(R.string.mgr_current, label),
                selectedManagerPkg = pkg
            )
        }
    }

       
                 
      
                                       
                                                     
                                  
       
    private fun pickManager() {
        if (managersBusy) { toast("正在处理管理器，请稍候"); return }
        managersBusy = true
        ui.update { it.copy(managerBusy = true) }
        lifecycleScope.launch(Dispatchers.IO) {
            val found = ManagerSelection.scan(this@MainActivity)
            val entries = buildManagerEntries(found)
            withContext(Dispatchers.Main) {
                managersBusy = false
                ui.update {
                    it.copy(
                        managerBusy = false,
                        managerDialogOpen = true,
                        managerEntries = entries
                    )
                }
            }
        }
    }

       
                             
      
                                                
                                                
                            
       
    private fun buildManagerEntries(found: List<ManagerSelection.Manager>): List<ManagerEntry> {
        val installed = found.associateBy { it.packageName }
        val out = mutableListOf<ManagerEntry>()

        
        
        found.forEach { m ->
            out += ManagerEntry(
                pkg = m.packageName,
                label = m.label,
                installed = true,
                version = "",
                bundledKo = ManagerCatalog.bundledKoFor(m.packageName)
            )
        }
        return out
    }

                  
    private fun closeManagerDialog() {
        ui.update { it.copy(managerDialogOpen = false) }
    }

                       
    private fun selectManager(pkg: String) {
        
        ManagerSelection.scanAsync(this) { found ->
            val m = found.firstOrNull { it.packageName == pkg }
            if (m == null) {
                toast("该管理器已不在设备上")
                return@scanAsync
            }
            if (ManagerCatalog.bundledKoFor(m.packageName)) {
                applyManager(m)
            } else {
                confirmThirdParty(m)
            }
        }
    }

    private fun applyManager(m: ManagerSelection.Manager) {
        ManagerSelection.save(this, m)
        refreshManagerUi()
        log("[mgrs] 已选择管理器：${m.label}（${m.packageName}）· ${ManagerCatalog.suitabilityText(m.packageName)}")
        toast("已选择 ${m.label}")
    }

       
                                                             
      
                                           
                                         
       
    private fun confirmThirdParty(m: ManagerSelection.Manager) {
        val dir = ManagerCatalog.workingDirOf(m.packageName)
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.mgr_tp_title, m.label))
            .setMessage(getString(R.string.mgr_tp_msg, dir))
            .setPositiveButton(R.string.mgr_tp_switch) { _, _ -> applyManager(m) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

                                                         
    private fun startOtaAdapt() {
        if (adaptBusy) { toast("正在解析上一份镜像，请稍候"); return }
        if (grinding) { toast("提权进行中，等本轮结束再导入"); return }
        val url = ui.state.otaUrl.trim()
        if (url.isBlank()) { toast("请先粘贴全量包下载链接"); return }
        adaptBusy = true
        ui.update {
            it.copy(
                adaptState = getString(R.string.boot_adapt_busy),
                adaptHint = "",
                adaptBusy = true,
                adaptProgress = 0
            )
        }
        log("[ota] 从链接导入全量包：$url")
        lifecycleScope.launch(Dispatchers.IO) {
            val result = OtaBootImporter.fetch(this@MainActivity, url) { pct, msg ->
                log("[ota] $msg")
                runOnUiThread { ui.update { it.copy(adaptProgress = pct.coerceIn(0, 99)) } }
            }
            if (!result.ok || result.file == null) {
                adaptBusy = false
                withContext(Dispatchers.Main) {
                    ui.update {
                        it.copy(
                            adaptBusy = false,
                            adaptProgress = 0,
                            adaptState = getString(R.string.boot_adapt_fail, result.message)
                        )
                    }
                }
                log("[ota][失败] ${result.message}")
                return@launch
            }
            log("[ota] ${result.message}，交给自助适配解析")
            startBootAdapt(Uri.fromFile(result.file))
        }
    }

    

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

       
                                                           
                                                            
       
    private fun startBootAdapt(uri: Uri) {
        if (adaptBusy) return
        adaptBusy = true
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: uri.toString()
        ui.update {
            it.copy(
                adaptState = getString(R.string.boot_adapt_busy),
                adaptHint = "",
                adaptBusy = true,
                adaptProgress = 0
            )
        }
        log("[boot] ==== 自助适配：开始解析 boot.img ====")
        log("[boot] 文件：$name")

        lifecycleScope.launch {
            val outcome = SelfAdapt.analyze(this@MainActivity, uri, currentKernel) { msg ->
                log("[boot] $msg")
                runOnUiThread {
                    ui.update { s -> s.copy(adaptProgress = (s.adaptProgress + 6).coerceAtMost(95)) }
                }
            }
            adaptBusy = false
            ui.update { it.copy(adaptBusy = false, adaptProgress = 0) }
            if (outcome.ok && outcome.adapted != null) {
                val a = outcome.adapted
                log("[boot] ✔ ${outcome.message}：${a.release}（${a.symbolCount} 个符号，来源 ${a.source}）")
                ui.update {
                    it.copy(
                        adaptState = when {
                            !outcome.sameKernel -> getString(R.string.boot_adapt_other, a.release)
                            !outcome.familySupported ->
                                getString(R.string.boot_adapt_ok_nofam, a.release, SelfAdapt.family(a.release))
                            else -> getString(R.string.boot_adapt_ok, a.release)
                        },
                        adaptHint = if (outcome.sameKernel && outcome.familySupported)
                            "已生成本机 profile"
                        else "该内核与本机不同，生成的是通用 profile"
                    )
                }
                toast(outcome.message)
                lifecycleScope.launch(Dispatchers.IO) { checkCompatibility() }
            } else {
                log("[boot] ✘ 适配失败：${outcome.message}")
                ui.update { it.copy(adaptState = getString(R.string.boot_adapt_fail, outcome.message)) }
                toast("适配失败：${outcome.message}")
            }
        }
    }

                                         
    private fun refreshAdaptCard() {
        if (adaptBusy) return
        val hit = SelfAdapt.match(this, currentKernel)
        if (hit != null) {
            ui.update {
                it.copy(
                    adaptState = if (SelfAdapt.familySupported(currentKernel)) {
                        getString(R.string.boot_adapt_ok, hit.release)
                    } else {
                        getString(R.string.boot_adapt_ok_nofam, hit.release, SelfAdapt.family(currentKernel))
                    },
                    adaptHint = "本机已有可用的自助适配 profile"
                )
            }
            return
        }
        val other = SelfAdapt.list(this).firstOrNull()
        if (other != null) {
            ui.update {
                it.copy(
                    adaptState = getString(R.string.boot_adapt_other, other.release),
                    adaptHint = "本机还没有该内核的 profile，可导入 boot.img 生成"
                )
            }
            return
        }
        ui.update {
            it.copy(
                adaptState = getString(R.string.boot_adapt_none),
                adaptHint = ""
            )
        }
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
        
        
        ui.update { it.copy(rootLogOpen = true, rootBusy = true) }
        onRoot()
    }

       
                                              
                                     
      
                                                              
                                                            
                                       
      
                                                                 
                                                                         
                                                       
                                                      
       
    private fun shareLogToQqGroup() {
        val zip = runCatching { LogStore.zipBundle() }.getOrNull()
        if (zip == null) {
            log("[日志][错误] 分享失败：日志压缩包生成失败")
            toast("日志文件还没生成，先运行一次再分享")
            return
        }

        val uri = runCatching {
            FileProvider.getUriForFile(this, "$packageName.fileprovider", zip)
        }.getOrNull()
        if (uri == null) {
            log("[日志][错误] 分享失败：无法生成压缩包 URI")
            toast("分享失败，请手动到 下载/XiaoDao 找日志")
            return
        }

        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/zip"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "HonorRoot 排障日志包")
            putExtra(
                Intent.EXTRA_TEXT,
                "HonorRoot 日志包（主日志 + 调试日志 + 清单，交流群 $QQ_GROUP_NO），请作者帮忙排障"
            )
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        val toQq = Intent(send).apply { setPackage(QQ_PACKAGE) }
        val viaQq = runCatching { startActivity(toQq) }.isSuccess
        val launched = if (viaQq) true else runCatching {
            startActivity(Intent.createChooser(send, "分享 HonorRoot 日志包"))
        }.isSuccess
        if (launched) {
            log("[日志] 已打开分享（${zip.name}，${zip.length()} B，含主日志/调试日志/清单）" +
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

    

    private fun refreshShizukuState() {
        val statusText = when {
            !ShizukuController.isAvailable() -> {
                
                
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
                
                LogStore.clearFatalIfStartsWith("Shizuku")
                "就绪：Shizuku 已连接，可部署物料"
            }
        }
        live.statusText = statusText
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

       
                                     
      
                                                            
                                                       
                                                      
                                                                     
               
      
                                           
                                        
       
    private suspend fun ensurePayloads(): Boolean {
        
        
        val shell = ShizukuController.shellProbe()
        if (!ShizukuController.probeOk(shell)) {
            log("[deploy][错误] Shizuku 命令通道不可用（code=${shell.code} ${shell.err.trim()}）")
            log("[deploy][错误] 请重新通过无线调试启动 Shizuku 并授权本应用")
            return false
        }
        
        
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
        
        
        
        if (!ShizukuController.hasPermission()) {
            toast("请先连接 Shizuku 并授权")
            ui.update { it.copy(rootBusy = false) }
            return
        }
        
        KsuUserspace.selectedManager = ManagerSelection.selected(this)

        if (grinding) {
            toast("临时 Root 正在运行中")
            ui.update { it.copy(rootBusy = false) }
            return
        }
        
        
        
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
                        
                        
                        
                        if (!KsuUserspace.suReady() &&
                            listOf(Build.MODEL, Build.DEVICE, Build.PRODUCT)
                                .any { it.contains("ADT-AN00", ignoreCase = true) }
                        ) {
                            log("[engine] 链路 A 未拿到 su，尝试 ADT-AN00 专用兜底载荷")
                            AdtPayloadRunner(this@MainActivity, ::log, ::status).run()
                        }
                    }
                    Engine.MODEL_PAYLOAD -> {
                        val pack = match.modelPack
                        if (pack == null) {
                            log("[engine][错误] 链路 A2 命中但载荷信息缺失，已中止")
                        } else {
                            log("[engine] 链路 A2：机型专用载荷（${pack.displayName}）")
                            ModelPayloadRunner(this@MainActivity, pack, ::log, ::status).run()
                        }
                    }
                    Engine.AAP_PAYLOAD -> {
                        log("[engine] 链路 A3：AAP-AN00（荣耀500）LD_PRELOAD 载荷")
                        AapPayloadRunner(this@MainActivity, ::log, ::status).run()
                    }
                    else -> log("[engine][错误] 当前内核没有可用提权链，已中止")
                }
            } finally {
                grinding = false
                ui.update { it.copy(rootBusy = false) }
                
                
                
                DeviceLogCollector.collect(this@MainActivity)
                
                
                if (KsuUserspace.suReady()) {
                    log("[root] 临时 Root 已就绪 → 自动打开 KernelSU 管理器")
                    launchKsuManager()
                }
                withContext(Dispatchers.Main) { refreshShizukuState() }
            }
        }
    }

    private suspend fun runManagers() {
            log("[mgrs] === 安装管理器 + 模块 ===")
            log("[mgrs] 内置管理器 = KernelSU v3.3.0 / code 32601 / me.weishu.kernelsu")
            log("[mgrs] 与定制 kernelsu.ko 配套；勿随意换成其它 commit 编译的版本")
            
            
            val chosen = ManagerSelection.selected(this)
            if (!ManagerCatalog.bundledKoFor(chosen) && !ManagerSelection.installed(this, chosen)) {
                log("[mgrs][提示] 当前选择 $chosen 属第三方分支，本 APK 未内置其安装包")
                log("[mgrs][提示] 请自行安装该管理器，或回到「选择管理器」切回官方版")
            }

            
            
            
            
            val bc = ShizukuController.exec("getprop sys.boot_completed", 15_000).out.trim()
            val mods = ShizukuController.exec("grep -c kernelsu /proc/modules", 15_000).out.trim()
            val ksuLoaded = (mods.toIntOrNull() ?: 0) > 0
            val firstSu = ShizukuController.exec(
                "su -c id 2>&1; /system/bin/su -c id 2>&1", 15_000
            )
            log("[mgrs] 状态：boot_completed=$bc, kernelsu模块=$mods, su code=${firstSu.code}")
            log("[mgrs] su -c id 返回：${(firstSu.out + firstSu.err).trim().takeLast(120).ifEmpty { "（无输出）" }}")

            
            
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

            
            if (!ksuLoaded) {
                log("[mgrs][提示] /proc/modules 未发现 kernelsu → 本 boot 尚未加载 KSU")
                log("[mgrs][提示] 临时 Root 还没成功，或设备重启后 KSU 已丢失（root 不持久）")
                log("[mgrs][提示] 管理器 APK 已处理；模块安装跳过。请先「一键临时 Root」看到 KSU READY 再回来")
                toast("KSU 未加载，仅装了管理器；请先完成临时 Root")
                return
            }

            
            
            
            
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

            
            val nf = ShizukuController.exec(
                "su 0 sh -c 'mkdir -p /data/adb/modules/netfix_packet && cp -rf /data/local/tmp/netfix_packet/. /data/adb/modules/netfix_packet/'",
                60_000
            )
            log("[mgrs] netfix_packet 同步: code=${nf.code}")

            
            
            
            
            
            
            
            log("[mgrs] 完成。")
            toast("管理器步骤完成（详见日志）")
    }

    

                                        
                                                            
    private fun enforceKsuVersion() {
        if (ksuGuardBusy || managersBusy || grinding) return
        if (!ShizukuController.hasPermission()) return
        ksuGuardBusy = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val result = KsuVersionGuard.enforce(this@MainActivity, ::log)
                
                
                
                if (result == "skipped") {
                    LogStore.setKsuVersion("未检测到（Shizuku 命令通道未连通）")
                } else if (result == "thirdparty") {
                    
                    
                    
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
        
        
        ksuGuardBusy = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                
                
                val un = ShizukuController.exec("su -c 'pm uninstall me.weishu.kernelsu' 2>&1", 30_000)
                if (un.code != 0 || un.out.contains("Failure", ignoreCase = true)) {
                    log("[ksudl] su 卸载未成功，回退 shell pm uninstall：${un.out.take(80).trim()}")
                    ShizukuController.exec("pm uninstall me.weishu.kernelsu 2>&1", 30_000)
                }
                log("[ksudl] 卸载现有版本 rc=${un.code} ${un.out.take(120).trim()}")
                delay(500)

                
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
                ksuVersionOk = null  
                withContext(Dispatchers.Main) {
                    updateKsuVersionRow()
                    toast("下载正确版本失败：${e.message}")
                }
            } finally {
                
                
                ksuGuardBusy = false
            }
        }
    }

                                                 
                                                                
                                               
    private fun updateKsuVersionRow() {
        val text = ksuVersion?.take(60) ?: getString(R.string.home_ksu_pending)
        ui.update {
            it.copy(
                ksuVersion = when (ksuVersionOk) {
                    true -> "KernelSU $text ✔"
                    false -> getString(R.string.home_ksu_bad)
                    null -> text
                }
            )
        }
    }


                                     
                                                                  
                                  
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

    

    private fun log(line: String) {
        
        val shown = LogStore.append(line)
        if (shown.isEmpty()) return
        runOnUiThread {
            
            
            
            
            
            
            
            logLines[logWrite] = shown
            logWrite = (logWrite + 1) % maxLogLines
            if (logCount < maxLogLines) logCount++
            live.logText = joinLogLines()
            
            lifecycleScope.launch(Dispatchers.IO) { LogStore.sync() }
        }
    }

       
                                  
                                        
                                         
       
    private fun status(text: String) {
        runOnUiThread { live.statusText = text }
    }

    private fun toast(text: String) {
        runOnUiThread { Toast.makeText(this, text, Toast.LENGTH_SHORT).show() }
    }
}
