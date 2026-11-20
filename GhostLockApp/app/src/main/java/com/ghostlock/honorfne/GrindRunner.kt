package com.ghostlock.honorfne

import kotlinx.coroutines.delay
import kotlin.math.max

/**
 * Ports the original host-side grind loop (run_forever.sh + run_w2.sh) to
 * on-device execution driven through Shizuku.
 *
 * Per boot:
 *   settle -> W1 (--write1, SELinux off) -> W2 (cred write -> root)
 *   -> chain_hook.sh 建立常驻 root FIFO 通道 (S2)
 *   -> App 通过通道投递 ksud insmod (S3) -> 恢复 Enforcing + 验证 (S4)
 *
 * S2-S4 来自「HONOR50-KernelSU晚加载提权实现记录」在 NTH-AN00 上实测成功
 * 的方案：旧的 load_ko + fake kallsyms 链路在该机型上必然 slide mismatch，
 * 因此 chain_hook.sh 见到 handoff 标记后只建通道就退出，后续全部由 App 驱动。
 * 若通道未建立（旧物料 / 异常），仍回退等待 chain_hook 自行完成晚加载。
 *
 * IMPORTANT reboot limitation: a failed W1/W2 can reboot the device, and Shizuku
 * drops across reboot. [waitForBootAndShizuku] blocks until the user re-enables
 * wireless-debugging Shizuku and the device finishes booting.
 */
class GrindRunner(
    private val log: (String) -> Unit,
    private val status: (String) -> Unit,
    /** Ensures /data/local/tmp/e + KSU material exist; auto-deploys if missing. */
    private val ensurePayloads: suspend () -> Boolean
) {

    private val tmpE = "/data/local/tmp/e"
    private val tmpKsu = "/data/local/tmp/ksu_fne"

    // Env prefix used by run_w2.sh (GL_* tuning knobs).
    // 【老版配方回归 · 2026-11-15】与老版本 GrindRunner.SYNC 逐字一致：
    // 只有这 11 个 GL_* 旋钮，没有 DM_PAGE_OFFSET / DM_PHYS_OFFSET。
    // 用户提供的老版成功日志里 w1.log 明确报
    // "dm: no memstart probe result and no DM_PAGE_OFFSET - refusing dm path"，
    // 证明老版确实没注入显式基址；成功轮靠的是探针自己凑出共识放行 DM。
    // 之前为了让探针失败的设备也能过 util.c:1622 硬门而加的显式线性映射基址，
    // 在这台 5.4.295 上把 dm 地址算歪，是真机反复重启的直接原因，已移除。
    private val SYNC = listOf(
        "GL_AIM_DM=1", "GL_W1_ATTEMPTS=2", "GL_ROUTE_ATTEMPTS=1",
        "GL_HOLD_CHAIN=1", "GL_HOLD_WAITER=1", "GL_PUNCH_IN_WINDOW=1",
        "GL_PUNCH_DELAY_USEC=0", "GL_MCAST_ROUTE=1", "GL_PROBE_BOOTID=0",
        "GL_SPRAY_TEST=0", "GL_STAMP_SYNC=1"
    ).joinToString(" ")

    private val W1_LOG = "/data/local/tmp/w1.log"
    private val W2_LOG = "/data/local/tmp/w2.log"

    /**
     * 【老版配方回归 · 2026-11-15】探针照常运行，不注入 GL_MEMSTART_PROBE，
     * 也不注入显式 DM 基址。老版成功日志里 W1 就是靠探针凑出共识后由
     * exploit 自行决定 DM 基址，约 30s 关掉 SELinux。之前为绕开假共识而加的
     * 「禁用探针 + 显式基址」组合在真机上造成反复重启，已整体回退。
     */

    private suspend fun kernelRelease(): String? {
        val r = ShizukuController.exec("uname -r", 10_000)
        if (ShizukuController.channelDead(r) || r.code != 0) return null
        return r.out.trim().takeIf { it.isNotBlank() }
    }

    /** W1/W2 共用的环境变量前缀；与老版逐字一致。 */
    private fun envPrefix(): String = SYNC

    suspend fun run() {
        if (!ShizukuController.hasPermission()) {
            log("[error] Shizuku 未授权，请先连接并授权 Shizuku。")
            return
        }
        // pingBinder() 活着不代表 newProcess 还能用。实测出现过 binder 正常、
        // 但所有 shell 命令返回空（连 getenforce 都空），app 却把 w1.log 里的
        // 旧错误文本当成当前输出，白等 420s 再 reboot。先做真实命令探针。
        if (!ensureShell("开始临时 Root")) {
            log("[error] 已停止，避免无意义的 420s 等待与重启")
            status("Shizuku 命令通道失效，请重新连接")
            return
        }
        status("开始临时 Root")
        val kernel = kernelRelease()
        LogStore.setProgress("正在提权，结果出来后会写在这里")
        log("[配方] 使用老版本方式：原版程序，先静默等 60 秒，系统空闲后才开始；内核=${kernel ?: "未知"}")
        LogStore.sync(force = true, reason = "开始提权")
        // 设备崩溃重启后 app 进程被杀、内存日志清空；/data/local/tmp 跨重启保留。
        // W1 / W2 / chain 三份尾部都捞回来：此前只取 W1，导致反复崩在 W2 时
        // 完全看不到现场，无法判断是 slab_drain、punch 还是 KSU 晚加载阶段。
        val lastW1 = readFileTail(W1_LOG)
        if (lastW1.isNotBlank()) {
            log("[取证] 上次 W1 日志尾部：${lastW1.replace('\n', ' ').takeLast(300).trim()}")
            if (isFatalStart(lastW1)) {
                log("[取证] 上次是「物料缺失 / exploit 未启动」，不是内核崩溃；本次会自动重新部署")
            }
            if (lastW1.contains("SIG_ENFORCE DISABLED") || lastW1.contains("SELinux DISABLED")) {
                log("[取证][结论] 上次 W1 已成功关闭 SELinux，瓶颈在 W2，不在 W1")
            }
            // 【老版配方回归】w1.log 跨重启保留，里面常是上一轮失败留下的
            // no consensus / 野 slide。老版本从不做「取证中止」，只记录后照常重跑 ——
            // 用户提供的老版日志里，成功轮的上一条取证恰恰就是
            // "dm: no memstart probe result and no DM_PAGE_OFFSET - refusing dm path"，
            // 重跑一次就 ROOTED。之前加的中止判断会把流程永久卡死，已全部移除。
            if (lastW1.contains("memstart probe: no consensus")) {
                log("[取证][说明] 上次探针没凑出共识（wins=0）；属单轮失败，按老版做法直接重跑")
            }
            if (lastW1.contains("memstart probe: disabled")) {
                log("[取证][说明] 历史日志来自曾禁用探针的版本；本轮已恢复探针")
            }
            val badSlide = ProbeLog.impossibleSlide(lastW1)
            if (badSlide != null) {
                log("[取证][说明] 历史 w1.log 里的野 slide ${ProbeLog.hex(badSlide)} 来自旧探针；" +
                        "按老版做法只记录、不中止，W1 启动前会自动清空该日志")
            }
        }
        val lastW2 = readFileTail(W2_LOG, 4000)
        if (lastW2.isNotBlank()) {
            log("[取证] 上次 W2 日志尾部：${lastW2.replace('\n', ' ').takeLast(420).trim()}")
            val stage = when {
                lastW2.contains("child is root") -> "已拿到 root（后续可能崩在 KSU 晚加载）"
                lastW2.contains("KSU LOADED") ||
                    lastW2.contains("KernelSU helper reports ready") -> "KSU 晚加载阶段"
                lastW2.contains("slab_drain") -> "slab_drain fork 风暴阶段"
                lastW2.contains("punch") -> "punch 阶段"
                lastW2.contains("route") -> "route 阶段"
                else -> "早期 prepare / 未归类"
            }
            log("[取证] 上次 W2 大致停在：$stage")
            if (stage == "slab_drain fork 风暴阶段") {
                // 老版日志实证：5 波 × 400 全部跑完（drain done）后仍继续到了
                // dm/heap spray 阶段，说明 fork 风暴本身不是崩溃点；成功轮同样
                // 用的是原版 5×400。不要把「wave 3/5」当成必崩证据，更不要改二进制。
                log("[取证][说明] 原版 exploit 的 slab_drain 是 5 波 x 400 fork；老版成功轮同样使用这一档，无需改动")
                log("[取证][说明] 若 W1 报 heap spray failed，瓶颈在 dm 基址/探针共识，不在 fork 风暴")
            }
            if (lastW2.contains("early SELinux policy repair failed")) {
                // 该行来自 e 二进制的早期策略修复尝试；后续 chain_hook 的
                // magiskpolicy --live 会成功，属可容忍事件，别让用户误判成失败。
                log("[取证][说明] early SELinux policy repair failed 是早期尝试，"
                        + "后续 magiskpolicy --live 成功即可；以 KSU LOADED / uid=0 为准")
            }
        }
        val lastChain = readFileTail("$tmpKsu/chain.log", 1200)
        if (lastChain.isNotBlank()) {
            log("[取证] chain.log 尾部：${lastChain.replace('\n', ' ').takeLast(240).trim()}")
            if (lastChain.contains("flipping SELinux enforcing")) {
                log("[取证][结论] KSU 晚加载链曾跑完收尾步骤，说明这套物料与内核配套可用")
            }
        }
        // 关键修复：若 /data/local/tmp/e 不存在（用户没点「部署物料」、设备重启后
        // 被系统清理等），旧版会照样启动 W1，w1.log 只有 "No such file or directory"，
        // app 却当成 exploit 在跑，白等 420s 再误判失败并 reboot。实测连续 3 轮白等。
        if (!ensurePayloads()) {
            log("[error] 设备端物料不可用，已停止：避免无意义的 420s 等待与重启")
            status("物料部署失败，请检查 Shizuku 授权后重试")
            return
        }
        // 抓完现场立刻清残留：W1 进程 parking forever，不清理会与新一轮并发。
        // 清不干净就绝不开跑，否则必然两个 grind 并发触发保护性重启。
        val (b0, a0) = ShizukuController.killStaleExploits()
        log("[cleanup] 本轮开始前：残留 e 进程 $b0 → $a0")
        if (a0 != "0") {
            log("[cleanup][错误] 残留 exploit 清不干净，继续会并发崩溃；请先重启设备")
            status("请先重启设备以清理残留进程")
            return
        }

        // 必须用 for 而不是 repeat：repeat 是 inline，其 `return@repeat` 只是
        // 「跳过本次迭代」(continue 语义)，嵌套时还有标签歧义。上一版因此命中
        // ROOTED 后仍连跑 3 次 W2，并发 fork 风暴把刚拿到的 root 又搞崩了。
        for (tryIndex in 1..8) {
            // 每轮开头先落一条里程碑：设备可能在下面任何一步内核崩溃重启，
            // 14:36 那份日志里六轮全都看不到 TRY/W1，无法判断卡在哪一步。
            log("[loop] === 第 $tryIndex 轮开始（检查命令通道 / 物料 / settle）===")
            // 部署/等待期间 Shizuku 服务端可能被系统回收，每轮重新确认命令通道
            if (!ensureShell("第 $tryIndex 轮")) {
                status("Shizuku 命令通道失效，请重新连接")
                return
            }
            if (!ShizukuController.isAvailable()) {
                log("[warn] Shizuku 失联，等待重连…")
                if (!waitForBootAndShizuku()) return
            }

            // 本 boot 已加载则跳过 exploit（抗 adb 瞬断假阴性），但仍要确认
            // 用户态 su 入口已部署：模块 Live 并不等于管理器能拿到 root。
            if (ksuLoaded()) {
                log("=== 本轮开机 KernelSU 已加载，跳过提权 ===")
                val userspaceOk = ensureKsuUserspace()
                LogStore.setFatal(
                    if (userspaceOk) "无（临时 Root 成功，KernelSU 已就绪）"
                    else "KernelSU 模块已加载，但 su 入口未就绪"
                )
                status(
                    if (userspaceOk) "KernelSU 已就绪，临时 root 成功！"
                    else "KSU 模块已加载，但 su 入口未就绪，请查看日志"
                )
                return
            }

            // 上一轮若 reboot 过，厂商可能清掉 /data/local/tmp；每轮都复检一次。
            // 放在 settle 之前，避免物料缺失还白等 60s 静默 + CPU 空闲检测。
            if (!ensurePayloads()) {
                log("[error] 第 $tryIndex 轮物料自检失败，停止（不会重启设备）")
                status("物料部署失败，请检查 Shizuku 授权")
                return
            }

            if (!settle()) {
                status("Shizuku 命令通道已断开，请重新用无线调试启动 Shizuku 并授权后重试")
                return
            }

            val boot0 = bootId()
            var en = getEnforce()
            log("--- TRY $tryIndex getenforce=$en ---")

            if (en == "<通道断开>") {
                status("Shizuku 命令通道已断开，请重新用无线调试启动 Shizuku 并授权后重试")
                return
            }

            if (en != "Permissive") {
                status("TRY $tryIndex [W1] 关闭 SELinux")
                val w1 = runW1(boot0)
                if (w1 == W1Outcome.NO_OFFSETS) {
                    // 推错 exploit 资产，重推同一份物料 / reboot 都改变不了偏移表。
                    // 结论已在 runW1 里写过，这里只更新界面并停止。
                    status("exploit 资产与内核不匹配，已停止（未重启设备）")
                    return
                }
                if (w1 == W1Outcome.START_FAILED) {
                    // 若命令通道已挂，重新部署也写不进去，先让用户重连 Shizuku
                    if (!ensureShell("W1 启动失败后")) {
                        status("Shizuku 命令通道失效，请重新连接")
                        return
                    }
                    // 物料/权限问题：重启设备解决不了，反而会让 Shizuku 掉线。
                    // 重新部署后直接重跑本轮，绝不发 reboot。
                    log("[W1] 启动失败 → 重新部署物料后重跑本轮（不重启设备）")
                    if (!ensurePayloads()) {
                        status("物料部署失败，请检查 Shizuku 授权")
                        return
                    }
                    continue
                }
                en = getEnforce()
                if (en != "Permissive") {
                    handleRebootIfNeeded(boot0, "W1 未落地")
                    continue
                }
            }

            // Permissive：跑 W2（最多 3 次干净重试）
            var adj = 0
            var done = false
            var w2StartFailure = false
            // W2 阶段失败的具体原因：写进致命问题，别让用户只看到「轮询中」。
            var lastW2Reason = "未启动"
            for (w2n in 1..3) {
                // 同 boot 内 KSU 若已加载，绝不再跑 W2
                if (ksuLoaded()) {
                    log("[W2] 检测到 kernelsu 已加载，跳过重复 W2")
                    done = true
                    break
                }
                status("TRY $tryIndex [W2] cred 写入 ADJ=$adj 第 $w2n/3")
                // 清场失败 / 物料缺失就别再起新 W2，避免并发 fork 风暴或空转
                if (!launchW2(adj)) { w2StartFailure = true; break }
                val res = pollW2()
                when (res) {
                    W2Result.START_FAILED -> {
                        w2StartFailure = true
                        lastW2Reason = "exploit 未启动（物料缺失或 exec 失败）"
                        break
                    }
                    W2Result.ROOTED, W2Result.KSU -> {
                        done = true
                        break
                    }
                    W2Result.LADDER -> {
                        adj = (adj + 8).coerceAtMost(16)
                        lastW2Reason = "erase 已触发但 uid 仍为 2000（ladder）"
                        log("    ladder: erase fired, uid 2000 -> ADJ=$adj")
                    }
                    W2Result.EXITED -> lastW2Reason = "W2 进程已退出，未出现 root 标记"
                    W2Result.TIMEOUT -> lastW2Reason = "W2 等满 420 秒，未出现 root 标记"
                    W2Result.MISS -> lastW2Reason = "W2 未出现 root 标记"
                }
                // 设备仍 Permissive = 干净 miss，可免费重试；否则 boot 丢失
                if (getEnforce() != "Permissive") {
                    lastW2Reason = "设备已离开 Permissive（很可能自重启）"
                    break
                }
                log("    W2 干净 miss，设备仍 Permissive，重试")
            }
            if (done) {
                if (ksuLoaded()) {
                    log("=== KernelSU 已自行加载完成 ===")
                    val userspaceOk = ensureKsuUserspace()
                    LogStore.setFatal(
                        if (userspaceOk) "无（临时 Root 成功，KernelSU 已就绪）"
                        else "KernelSU 模块已加载，但 su 入口未就绪"
                    )
                    status(
                        if (userspaceOk) "KernelSU 已就绪，临时 root 成功！"
                        else "KSU 模块已加载，但 su 入口未就绪，请查看日志"
                    )
                    return
                }
                // HONOR 50 验证链路：常驻 root 通道 -> ksud insmod -> 恢复 Enforcing
                val ok = finishViaRootChannel()
                LogStore.setFatal(
                    if (ok) "无（临时 Root 成功，KernelSU 已就绪）"
                    else "KernelSU 晚加载未确认，临时 Root 可能未生效"
                )
                status(if (ok) "KernelSU 已就绪，临时 root 成功！" else "KSU 晚加载未确认，请查看日志")
                return
            }
            if (w2StartFailure) {
                log("[W2] 启动失败 → 重新部署物料后重跑本轮（不重启设备）")
                if (!ensurePayloads()) {
                    status("物料部署失败，请检查 Shizuku 授权")
                    return
                }
                continue
            }
            LogStore.setFatal("本轮未拿到 root：$lastW2Reason")
            status("未拿到 root：$lastW2Reason；按老配方重启重掷")
            handleRebootIfNeeded(boot0, "W2 用尽")
        }

        log("=== 本轮结束：未拿到临时 Root，可重新点一键 Root ===")
        LogStore.setFatal("本轮未成功：临时 Root 未落地（详见下方记录）")
        status("未成功，点「一键临时 Root」再试")
    }

    // ---------------------------------------------------------------- steps

    /** 真实 shell 命令探针：binder 活着但 newProcess 失效时立刻停止，不再白等。 */
    private suspend fun ensureShell(reason: String): Boolean {
        val p = ShizukuController.shellProbe()
        if (ShizukuController.probeOk(p)) return true
        log("[error][$reason] Shizuku 命令通道不可用（code=${p.code} ${p.err.trim()}）")
        log("[error] 请重新通过无线调试启动 Shizuku 并授权本应用，然后重试")
        return false
    }

    private suspend fun ksuLoaded(): Boolean {
        repeat(2) { i ->
            val r = ShizukuController.exec("grep -q kernelsu /proc/modules", 15_000)
            if (r.code == 0) return true
            if (i < 1) delay(5_000)
        }
        return false
    }

    private suspend fun bootId(): String? {
        val r = ShizukuController.exec("cat /proc/sys/kernel/random/boot_id", 15_000)
        return if (r.code == 0) r.out.trim().ifEmpty { null } else null
    }

    /**
     * @return getenforce 的结果；命令通道已断时返回 "<通道断开>"，
     *         避免和「真的不是 Permissive」混为一谈。
     */
    private suspend fun getEnforce(): String {
        val r = ShizukuController.exec("getenforce", 15_000)
        if (ShizukuController.channelDead(r)) {
            log("[error] Shizuku 命令通道已断开（code=${r.code}），无法读取 SELinux 状态")
            return "<通道断开>"
        }
        return if (r.code == 0) r.out.trim() else "<读取失败 code=${r.code}>"
    }

    /**
     * 【老版配方回归 · 2026-11-15】固定 60 秒静默 + CPU 空闲检测，空闲才开 W1。
     *
     * 老版本一次成功日志（14:43）逐条打印：
     *   [settle] 静默等待 60s（期间请勿操作手机）… → 静默 5s/60s … 静默 60s/60s
     *   → [settle] 开始检测 CPU 空闲度… → [settle] CPU 空闲 95%，开始 W1
     *   → W1 约 30s 关掉 SELinux → W2 ROOTED → KSU 就绪 ok。
     *
     * 之前为「赶在 boot 60s 内开跑以避开 5×400 重档」加的 uptime 预算，
     * 以及 2.2.8 的「补丁资产跳过检测立即开跑」都基于一个已被证伪的推断：
     * 老版日志里 5 波 × 400 全部跑完（drain done）之后流程仍继续，
     * 成功轮用的也正是这一档。等系统真正空闲下来才是关键，故整体恢复。
     *
     * @return true = 可以继续跑 W1；false = Shizuku 命令通道已断，本轮直接结束。
     */
    private suspend fun settle(): Boolean {
        log("[settle] 清理后台…")
        ShizukuController.exec("am force-stop com.hihonor.photos", 15_000)
        ShizukuController.exec("am force-stop com.hihonor.searchservice", 15_000)
        ShizukuController.exec("am kill-all", 15_000)
        ShizukuController.exec("pm trim-caches 999999999999", 30_000)

        log("[settle] 静默等待 60s（期间请勿操作手机）…")
        repeat(12) { i ->
            delay(5_000)
            log("[settle] 静默 ${(i + 1) * 5}s / 60s")
        }

        log("[settle] 开始检测 CPU 空闲度…")
        repeat(12) { i ->
            val (a, deadA) = cpuSnapshot()
            if (deadA) {
                log("[settle][中止] Shizuku 命令通道已断开，读不到 /proc/stat；不再空等，本轮直接结束")
                return false
            }
            delay(5_000)
            val (b, deadB) = cpuSnapshot()
            if (deadB) {
                log("[settle][中止] Shizuku 命令通道已断开，读不到 /proc/stat；不再空等，本轮直接结束")
                return false
            }
            if (a != null && b != null) {
                val dTotal = b.second - a.second
                val dIdle = b.first - a.first
                if (dTotal > 0) {
                    val pct = (100L * dIdle / dTotal).toInt()
                    if (pct >= 85) {
                        log("[settle] CPU 空闲 ${pct}%，开始 W1")
                        return true
                    }
                    if (i % 2 == 0) log("[settle] idle=${pct}% (<85%)，继续等 (${(i + 1) * 5}s)…")
                }
            } else if (i % 2 == 0) {
                log("[settle] 读取 /proc/stat 失败，继续等…")
            }
        }
        log("[settle] 等待空闲超时，不阻断流程，继续尝试 W1")
        return true
    }

    /**
     * 返回 (累计 jiffies, 通道是否已断)；比例算法与 CPU 核数、内核 HZ 无关。
     * 第二个分量用来把「命令通道掉线」和「/proc/stat 解析失败」区分开，
     * 否则会把掉线一路误报成「文件不存在 / 读不到空闲度」。
     */
    private suspend fun cpuSnapshot(): Pair<Pair<Long, Long>?, Boolean> {
        val r = ShizukuController.exec(
            "awk '/^cpu /{idle=\$5+\$6; t=0; for(i=2;i<=NF;i++) t+=\$i; print idle, t}' /proc/stat",
            15_000
        )
        if (ShizukuController.channelDead(r)) return null to true
        val parts = r.out.trim().split(Regex("\\s+"))
        if (parts.size < 2) return null to false
        val idle = parts[0].toLongOrNull() ?: return null to false
        val total = parts[1].toLongOrNull() ?: return null to false
        return (idle to total) to false
    }

    /** 每次启动 exploit 前都必须清场；返回是否清干净。 */
    private suspend fun logCleanup(reason: String): Boolean {
        val (before, after) = ShizukuController.killStaleExploits()
        log("[cleanup] $reason：残留 e 进程 $before → $after" +
            if (after != "0") "（仍有残留）" else " ✔")
        return after == "0"
    }

    private suspend fun launchW1(): Boolean {
        // 双保险：启动前再确认 exploit 真的存在且可执行
        val chk = ShizukuController.exec("test -x $tmpE && echo OK", 10_000)
        if (!chk.out.contains("OK")) {
            // 必须先分清「通道断了」和「文件真的不在」：exec() 把 Throwable 统一
            // 吞成 code=-1 + 空输出，只看输出会把掉线误报成「文件不存在」，
            // 让用户去查一个根本没问题的东西（2026-11-14 真机日志即如此）。
            if (ShizukuController.channelDead(chk)) {
                log("[W1][中止] Shizuku 命令通道已断开（code=${chk.code}），无法确认 $tmpE 状态；本轮不启动 exploit")
                log("[W1][中止] 请重新用无线调试启动 Shizuku 并授权本应用后重试")
            } else {
                log("[W1][中止] $tmpE 不存在或不可执行（code=${chk.code} ${chk.err.trim().take(80)}），本轮不启动 exploit")
            }
            return false
        }
        if (!logCleanup("W1 启动前")) {
            log("[W1][中止] 残留进程清不干净，本轮不启动 exploit")
            return false
        }
        // 备份上一轮日志：设备可能在 W1 期间崩溃重启，而 /data/local/tmp 不随重启清除
        ShizukuController.exec(
            "sh -c 'if [ -f $W1_LOG ]; then cp $W1_LOG ${W1_LOG}.prev; fi; : > $W1_LOG'",
            15_000
        )
        log("[W1][里程碑] 已备份并清空 $W1_LOG，下一步 exec $tmpE --write1")
        // 启动壳的 stdin/stdout/stderr 全部脱离 Shizuku 管道。否则 exec() 的
        // readText() 等不到 EOF → 20s 超时 → destroy() 可能连带杀掉刚起的 exploit。
        val cmd = "( env ${envPrefix()} $tmpE --write1 > $W1_LOG 2>&1 </dev/null ) >/dev/null 2>&1 &"
        val r = ShizukuController.exec(cmd, 15_000)
        if (r.code != 0) log("[W1][警告] 启动壳返回 code=${r.code} ${r.err.trim()}")
        log("[W1] 第一步已启动（关闭 SELinux），明细在 $W1_LOG")
        LogStore.setProgress("第一步已启动，正在等待结果（设备可能黑屏重启）")
        return true
    }

    /**
     * 等待 W1 真正跑完，最长 420s（对应原脚本 run_to 420 ... e --write1）。
     * 原脚本的 6 次 getenforce 确认是在 W1 同步结束之后做的（防 adbd 瞬断）；
     * 之前误把它放在后台启动之后，导致 10s 就误判失败并主动 reboot。
     */
    private enum class W1Outcome { LANDED, MISS, START_FAILED, NO_OFFSETS }

    private suspend fun runW1(boot0: String?): W1Outcome {
        log("[W1] 即将运行 exploit：设备很可能黑屏并自动重启（成功率约 8%），属正常现象，不是工具坏了")
        log("[W1] 若 1-2 分钟未自动开机请手动开机；重启后需重新用无线调试启动 Shizuku 并授权")
        if (!launchW1()) return W1Outcome.START_FAILED
        // 原 PC 脚本 W1 前台同步运行期间，主机只 tail 本地文件、不向设备发任何命令。
        // 这里若每 5s 发 3 条 shell 命令，会在竞态窗口制造大量调度噪声。
        // 改为：每 5s 仅做本地 binder 存活检查（零 shell），每 30s 才发 1 条合并查询。
        log("[W1] 单次最长 420s；低干扰观察（每 30s 查询一次设备）")

        val deadline = System.currentTimeMillis() + 420_000
        var ticks = 0
        while (System.currentTimeMillis() < deadline) {
            delay(5_000)
            ticks++

            // 本地 binder ping，不启动任何远端进程
            if (!ShizukuController.isAvailable()) {
                log("[W1] Shizuku 掉线 → 设备很可能已在 W1 崩溃后自重启")
                return W1Outcome.MISS
            }
            if (ticks % 6 != 0) continue

            val p = w1Probe()
            // 合并查询全部为空 = Shizuku 命令通道已失效，w1.log 里只是旧内容
            if (p.shellLost) {
                log("[W1][错误] 设备查询全部为空 → Shizuku 命令通道在 W1 期间失效")
                log("[W1] 停止轮询；请重新连接 Shizuku，不会重启设备")
                return W1Outcome.START_FAILED
            }
            // 关键修复：w1.log 出现 "No such file or directory" 等说明 exploit
            // 根本没启动，等满 420s 毫无意义，更不能因此 reboot。
            if (p.fatal) {
                log("[W1][错误] exploit 未能启动：${p.tail.takeLast(160).trim()}")
                log("[W1] 这是物料/权限问题，不是内核崩溃；不会重启设备")
                return W1Outcome.START_FAILED
            }
            // exploit 自己打印 no offsets for kernel 时 strcmp 已落空、进程随即退出，
            // 这是资产与内核不匹配（推错二进制），不是内核崩溃也不是竞态。
            // 老版会把它当「运行中」等满 420s，再 reboot 重掷，两轮白等 14 分钟。
            // 重推同一份物料永远修不好，必须立即收尾且不发 reboot。
            if (p.noOffsets) {
                log("[W1][致命] exploit 报 no offsets for kernel：当前下发的二进制没有这颗内核的偏移表")
                log("[W1] 这是资产选择问题，不是内核崩溃；停止轮询，不重启设备")
                val hit = Regex("""no offsets for kernel: (\S+)""").find(p.tail)
                LogStore.setFatal(
                    "exploit 二进制不含内核 ${hit?.groupValues?.get(1) ?: "当前构建"} 的偏移表" +
                        "（推错 exploit 资产）；已停止，未重启设备",
                    LogStore.RANK_RESULT
                )
                return W1Outcome.NO_OFFSETS
            }
            // 【老版配方回归】不再根据 slide 数值中止。老版成功日志开头的快照里
            // 就有 `slide=0x1caf600000 votes=2901`（约 123 GiB），照样一次 ROOTED；
            // 把这类 slide 当「野值」拦下是误判，会把本来能成的一轮直接掐掉。
            if (p.enforce == "Permissive" || p.landed > 0) {
                log("[W1] 第一步成功：SELinux 已关闭（约 ${ticks * 5}s）")
                LogStore.setProgress("第一步成功，正在写入 root 权限（W2 最长 420 秒）")
                return W1Outcome.LANDED
            }
            if (p.boot.isNotEmpty() && boot0 != null && p.boot != boot0) {
                log("[W1] 设备自动重启，本轮作废")
                LogStore.setFatal("第一步启动后设备自动重启，未拿到临时 Root（内核崩溃）")
                return W1Outcome.MISS
            }
            log("[W1] 运行中 ${ticks * 5}s / 420s | getenforce=${p.enforce} | ${p.tail.takeLast(120)}")
        }
        log("[W1] 等满 420 秒仍未成功")
        LogStore.setFatal("第一步超时（420 秒），未能关闭 SELinux")
        return W1Outcome.MISS
    }

    /** 区分「exploit 没跑起来」与「跑了但没打中」——前者绝不能触发 reboot。 */
    private fun isFatalStart(text: String): Boolean = listOf(
        "No such file or directory", "env: exec", "cannot execute",
        "Exec format error", "Permission denied", "not found", "not executable"
    ).any { text.contains(it, ignoreCase = true) }

    private data class W1Probe(
        val enforce: String,
        val boot: String,
        val landed: Int,
        val tail: String,
        val fatal: Boolean,
        val noOffsets: Boolean,
        val shellLost: Boolean
    )

    /** 用单条 shell 命令一次拿全所需信息，把轮询干扰降到最低。 */
    private suspend fun w1Probe(): W1Probe {
        val r = ShizukuController.exec(
            "getenforce; cat /proc/sys/kernel/random/boot_id 2>/dev/null; " +
                "grep -c 'SELinux DISABLED' $W1_LOG 2>/dev/null; tail -c 300 $W1_LOG 2>/dev/null; " +
                "grep -o 'memstart probe: slide=0x[0-9a-f]*' $W1_LOG 2>/dev/null | tail -1; " +
                // no offsets 可能在 w1.log 很靠前的位置，不能被 tail -c 300 截断窗口漏掉；
                // 用明确标记对整个文件 grep，命中数 >0 才算（拒绝旧日志里的残留串误报）。
                "echo NOOFF=$(grep -c 'no offsets for kernel' $W1_LOG 2>/dev/null)",
            15_000
        )
        val l = r.out.lines()
        val tail = l.drop(3).joinToString(" ").trim()
        val enforce = l.getOrNull(0)?.trim() ?: ""
        val boot = l.getOrNull(1)?.trim() ?: ""
        return W1Probe(
            enforce = enforce,
            boot = boot,
            landed = (l.getOrNull(2)?.trim() ?: "0").toIntOrNull() ?: 0,
            tail = tail,
            fatal = isFatalStart(tail),
            noOffsets = Regex("""NOOFF=(\d+)""").find(r.out)?.groupValues?.get(1)?.toIntOrNull()
                ?.let { it > 0 } ?: false,
            // getenforce 与 boot_id 同时为空 = 这条合并命令压根没执行
            shellLost = enforce.isEmpty() && boot.isEmpty()
        )
    }

    private suspend fun launchW2(adj: Int): Boolean {
        val chk = ShizukuController.exec("test -x $tmpE && echo OK", 10_000)
        if (!chk.out.contains("OK")) {
            log("[W2][中止] $tmpE 不存在或不可执行，本轮不启动 W2")
            return false
        }
        // W1 成功后其进程可能仍 parking forever，必须先杀掉再跑 W2，
        // 否则两个 exploit 并发 → slab_drain 二次 fork 风暴 → 内核保护性重启
        if (!logCleanup("W2 启动前")) {
            log("[W2][中止] 残留进程清不干净，不再启动新 W2（避免并发 fork 风暴）")
            return false
        }
        ShizukuController.exec("sh -c ': > $W2_LOG'", 15_000)
        // 文档 fne_local.sh 明确只跑 1 轮：W2 拿到 root 后其 park 的 waiter
        // 不能被二次 PI 操作打扰，否则踢到 ghost 触发 panic。
        val env = "${envPrefix()} GL_W2_ROUNDS=1 GL_W2_CRED_ADJ=$adj"
        log("[W2] 准备启动 cred 写入 …")
        val cmd = "( env $env $tmpE > $W2_LOG 2>&1 </dev/null ) >/dev/null 2>&1 &"
        val r = ShizukuController.exec(cmd, 15_000)
        if (r.code != 0) log("[W2][警告] 启动壳返回 code=${r.code} ${r.err.trim()}")
        log("[W2] 已后台启动 (ADJ=$adj)，见 $W2_LOG")
        return true
    }

    private enum class W2Result { ROOTED, KSU, LADDER, MISS, TIMEOUT, EXITED, START_FAILED }

    private data class W2Probe(val count: Int?, val tail: String, val shellLost: Boolean)

    /** 用单条命令同时取「e 进程数 + w2.log 尾部」，把轮询干扰降到最低。 */
    private suspend fun w2Probe(): W2Probe {
        val r = ShizukuController.exec(
            "pidof e 2>/dev/null | wc -w; tail -c 8000 $W2_LOG 2>/dev/null", 15_000
        )
        if (ShizukuController.channelDead(r)) return W2Probe(null, "", true)
        val lines = r.out.lines()
        val count = lines.getOrNull(0)?.trim()?.toIntOrNull()
        val tail = lines.drop(1).joinToString("\n")
        return W2Probe(count, tail, shellLost = count == null && tail.isBlank())
    }

    /**
     * 等 W2 出结果。
     *
     * 【2026-11-17 真机日志实证】老版本只按时间盲等 900s：W2 进程 30 秒内就
     * 退出了（状态页显示残留 e 进程 0、SELinux 仍 Permissive），界面却一路
     * 「轮询中 (660s)」，用户干等 15 分钟，最后才失败并重启设备。
     * 现在每 15s 同时看三件事：w2.log 标记、命令通道、e 进程是否还活着；
     * 连续两次（30s）确认进程已退出且无 root 标记，立刻以 EXITED 收尾；
     * 总预算收窄到 420s（与 W1 一致），不会再出现 15 分钟静默。
     */
    private suspend fun pollW2(): W2Result {
        val ticks = 28 // 28 × 15s = 420s
        var deadTicks = 0
        repeat(ticks) { i ->
            delay(15_000)
            if (!ShizukuController.isAvailable()) {
                log("[W2] Shizuku 掉线 → 设备很可能已崩溃重启，停止本轮轮询")
                return W2Result.MISS
            }
            val probe = w2Probe()
            val w2log = probe.tail
            if (probe.shellLost) {
                log("[W2] 命令通道没有返回任何内容，停止本轮轮询")
                return W2Result.MISS
            }
            // 与 W1 同理：exploit 没启动就别空转，更不能因此 reboot
            if (isFatalStart(w2log)) {
                log("[W2][错误] exploit 未能启动：${w2log.takeLast(160).trim()}")
                return W2Result.START_FAILED
            }
            if (w2log.contains("child is root")) {
                log("[W2] 第二步成功：已获得临时 Root")
                LogStore.setProgress("已获得临时 Root，正在加载 KernelSU")
                return W2Result.ROOTED
            }
            if (w2log.contains("KernelSU helper reports ready") || w2log.contains("KSU LOADED")) {
                log("[W2] 命中 KSU READY")
                return W2Result.KSU
            }
            if (w2log.contains("erase_ran=1") && w2log.contains("child uid = 2000")) {
                log("[W2] 命中 ladder（erase 触发但 uid 仍 2000）")
                return W2Result.LADDER
            }

            // 进程是否还活着：解析不到就停，不误判成「已退出」。
            val cnt = probe.count
            if (cnt == null) {
                log("[W2] 无法确认 e 进程数，停止轮询")
                return W2Result.MISS
            }
            if (cnt == 0) {
                deadTicks++
                if (deadTicks >= 2) {
                    val tail = w2log.replace('\n', ' ').takeLast(240).trim()
                    log("[W2][结论] e 进程已连续 30s 不存在，w2.log 里也没有 root 标记")
                    log("[W2][结论] w2.log 尾部：${tail.ifBlank { "（空，exploit 没有输出）" }}")
                    return W2Result.EXITED
                }
            } else {
                deadTicks = 0
            }

            val sec = (i + 1) * 15
            if (i % 4 == 0) {
                log("[W2] 轮询中 (${sec}s / 420s)…")
                LogStore.setProgress("正在写入 root 权限（W2 ${sec}s / 420s）")
            }
        }
        log("[W2][结论] 等满 420 秒仍无 root 标记 → 本轮失败")
        return W2Result.TIMEOUT
    }

    // ------------------------------------------- HONOR 50 root channel (S2-S4)

    private val RS_IN = "/data/local/tmp/rs.in"
    private val RS_OUT = "/data/local/tmp/rs.out"

    /** chain_hook.sh 在 handoff 模式下把 root 搬进 FIFO 后写入此标志。 */
    private suspend fun waitRootChannel(maxTicks: Int = 30): Boolean {
        log("[chan] 等待常驻 root shell 通道 (最长 ${maxTicks * 3}s)…")
        repeat(maxTicks) {
            val r = ShizukuController.exec(
                "grep -c 'ROOT SHELL CHANNEL UP' $RS_OUT 2>/dev/null", 15_000
            )
            if ((r.out.trim().toIntOrNull() ?: 0) > 0) {
                log("[chan] ROOT SHELL CHANNEL UP ✔")
                return true
            }
            delay(3_000)
        }
        log("[chan][错误] 未建立 root 通道（chain_hook 未运行或走了旧链路）")
        return false
    }

    /** 向 FIFO 投递一条命令，然后轮询 rs.out 里的完成标记。 */
    private suspend fun deliver(script: String, marker: String, timeoutSec: Int): Boolean {
        log("[chan] 投递：$script")
        val w = ShizukuController.exec("echo 'sh $script' > $RS_IN", 20_000)
        if (w.code != 0) {
            log("[chan][错误] 写入 rs.in 失败 code=${w.code} ${w.err.trim()}")
            return false
        }
        repeat(timeoutSec / 3) { i ->
            delay(3_000)
            val r = ShizukuController.exec("grep -c '$marker' $RS_OUT 2>/dev/null", 15_000)
            if ((r.out.trim().toIntOrNull() ?: 0) > 0) {
                log("[chan] $marker ✔ (${(i + 1) * 3}s)")
                return true
            }
            if (i % 5 == 0) log("[chan] 等待 $marker … ${(i + 1) * 3}s")
        }
        log("[chan][错误] 超时未见 $marker")
        return false
    }

    /**
     * 模块已 Live 时补齐用户态。全部逻辑收拢在 KsuUserspace（Mutex 保护），
     * 「一键临时 Root」和「安装管理器 + 模块」共用同一条路径，避免老版本里
     * 多个协程同时「等待 su 就绪 1/12」、把日志刷成 130 KB 还什么都没补装。
     * KSU 3.3.0 的 /system/bin/su 是 sucompat 虚拟入口，ksud 必须由
     * `ksud install` 原子生成；手工 cp 会带错 SELinux 上下文。
     */
    private suspend fun ensureKsuUserspace(): Boolean = KsuUserspace.ensure(log)

    /** S2-S4 主流程；失败时明确提示设备可能仍停留在 Permissive。 */
    private suspend fun finishViaRootChannel(): Boolean {
        log("=== S2/S3/S4：HONOR 50 验证链路（root 通道 → ksud insmod → Enforcing）===")
        if (!waitRootChannel()) {
            log("[chan] 回退：等待旧 chain_hook 自行完成 KSU 晚加载")
            waitKsu()
            return ksuLoaded()
        }
        // 无论模块是否已 Live 都投递一次：ksu_lateload.sh 内部幂等，
        // 已 Live 时跳过 insmod，但仍执行 ksud install + 重启管理器，
        // 否则 su 入口永远缺失、管理器一直报「获取 Root 失败」。
        val done = deliver("$tmpKsu/ksu_lateload.sh", "KSUTRY_DONE", 120)
        val rsTail = readFileTail(RS_OUT, 2400)
        log("[chan] rs.out 尾部：${rsTail.replace('\n', ' ').takeLast(500).trim()}")
        if (rsTail.contains("KSU_READY")) {
            log("[chan] 脚本自报 KSU_READY（模块 Live + ksud 用户态已安装）")
        } else if (rsTail.contains("KSU_NOT_READY")) {
            log("[chan][警告] 脚本自报 KSU_NOT_READY，检查上面的 install / stages rc")
        }
        if (!done && !ksuLoaded()) {
            log("[chan][错误] ksud insmod 未确认成功，设备可能仍为 Permissive")
            log("[chan][提示] 请勿在此状态长时间使用；重启设备可恢复 Enforcing")
            return false
        }

        // 恢复 Enforcing 必须是最后一步：flip 会杀掉 kernel:s0 的通道 shell，
        // 所以不强等 RESTORE_ENFORCE_DONE，直接投递后验证最终状态。
        ShizukuController.exec("echo 'sh $tmpKsu/restore_enforce.sh' > $RS_IN", 20_000)
        delay(4_000)

        // su 不带路径时 shell 会拼出 /system/bin/su，sucompat 的 stat/execve
        // 重定同样能命中；两种写法都试，避免某些 shell 只认其中一种。
        // /data/adb/ksud 属 root，App 的 shell(uid 2000) 无权直读，故经 su -c 查看，
        // 避免产生误导性的「Permission denied」。
        val v = ShizukuController.exec(
            "getenforce; su -c 'ls -l /data/adb/ksud' 2>&1; " +
                "su -c id 2>&1; /system/bin/su -c id 2>&1; grep kernelsu /proc/modules",
            20_000
        )
        log("[verify] ${v.out.replace("\n", " | ").trim()}")
        var ok = ksuLoaded() && v.out.contains("uid=0")
        if (!ok) {
            // 老版本在这里只打印「请点查看状态复核」就结束，接着用户点
            // 「安装管理器」又开一个并发协程空等 12×5s，su 始终 code=127。
            // 新版必须当场补装，不能把问题留给下一次点击。
            log("[verify][警告] 未同时确认 KSU Live 与 uid=0 → 立即补装用户态")
            if (!v.out.contains("/data/adb/ksud") || v.out.contains("No such file")) {
                log("[verify][提示] /data/adb/ksud 缺失：需 ksud install 部署 sucompat 入口")
            }
            if (KsuUserspace.ensure(log)) {
                val again = ShizukuController.exec(
                    "getenforce; su -c id 2>&1; grep kernelsu /proc/modules", 20_000
                )
                log("[verify][复检] ${again.out.replace("\n", " | ").trim()}")
                ok = again.out.contains("uid=0") && again.out.contains("kernelsu")
            } else {
                log("[verify][错误] 补装后 su 仍不可用；请确认设备端脚本是本 APK 的 ksu_lateload.sh")
            }
        }
        if (ok) log("[verify] ✔ Enforcing 下 root 仍可用，KSU 模块 Live")
        return ok
    }

    private suspend fun waitKsu() {
        log("[wait] 等待 KSU 晚加载 (最长 180s)…")
        repeat(36) {
            delay(5_000)
            val st = readFile("$tmpKsu/chain_status").trim()
            val chainLog = readFile("$tmpKsu/chain.log")
            if (st == "handoff") {
                log("[wait] chain 已交接给 App 的 root 通道，跳过等待")
                return
            }
            if (st == "ok" || chainLog.contains("KSU READY")) {
                log("[wait] KSU 就绪：$st")
                return
            }
            if (it % 6 == 0) log("[wait] chain_status=$st")
        }
        log("[wait] 超时：KSU 可能仍在加载，稍后在「查看状态」确认。")
    }

    private suspend fun handleRebootIfNeeded(boot0: String?, reason: String) {
        // 失败 / 重启前的现场快照：包含 w1.log、w2.log、chain.log、dmesg、logcat
        LogStore.sync(force = true, reason = "$reason：抓取失败现场")
        val alive = ShizukuController.isAvailable()
        val boot1 = bootId()
        // 设备已经崩掉/自重启/离线时，绝不要再发 reboot（那才是「突然关机」的元凶）。
        // boot0 为空 = 起始时没能读到 boot_id，无法判断 boot 是否变化；此时保守
        // 跳过 reboot（发 reboot 可能造成一次非预期重启），只等用户重连。
        if (!alive || boot1 == null || boot0 == null || boot1 != boot0) {
            log("[$reason] 设备已在 W 阶段自重启/掉线，跳过冗余 reboot，等待开机")
            log("[提示] 设备重启后 Shizuku 会失效，请重新用无线调试启动 Shizuku 并授权本应用")
            waitForBootAndShizuku()
            return
        }
        log("[$reason] W 阶段已结束且设备仍在本 boot，执行 reboot 重掷")
        ShizukuController.exec("reboot", 15_000)
        log("[提示] 设备重启后请重新用无线调试启动 Shizuku 并授权本应用")
        waitForBootAndShizuku()
    }

    /**
     * After a reboot Shizuku is gone. Block until the device finishes booting
     * AND the user re-enables wireless-debugging Shizuku and grants permission.
     * Returns true when both are satisfied.
     */
    private suspend fun waitForBootAndShizuku(): Boolean {
        log("[wait] 等待设备开机 + Shizuku 重连（请在设备上重新通过无线调试启动 Shizuku 并授权本应用）")
        repeat(180) { // 最多 15 分钟
            if (ShizukuController.isAvailable() && ShizukuController.hasPermission()) {
                val bc = ShizukuController.exec("getprop sys.boot_completed", 15_000)
                if (bc.code == 0 && bc.out.trim() == "1") {
                    log("[wait] 设备已就绪，继续 grind")
                    return true
                }
            }
            delay(5_000)
        }
        log("[wait] 等待超时：请手动重连 Shizuku 后再次点击「一键临时 Root」。")
        return false
    }

    // w1.log 被 `: >` 截断后，旧进程仍持有 fd 在原偏移写入，会形成 NUL 稀疏空洞。
    // 不过滤的话这些 NUL 会被原样写进 XiaoDao 日志（实测一份日志里有 6300 个）。
    private fun cleanOut(s: String): String = s.replace("\u0000", "")

    private suspend fun readFile(path: String): String {
        val r = ShizukuController.exec("cat '$path' 2>/dev/null", 15_000)
        return if (r.code == 0) cleanOut(r.out) else ""
    }

    /** 只取尾部，避免 exploit 日志变大后每 5s 把整个文件读进内存。 */
    private suspend fun readFileTail(path: String, bytes: Int = 2000): String {
        val r = ShizukuController.exec("tail -c $bytes '$path' 2>/dev/null", 15_000)
        return if (r.code == 0) cleanOut(r.out) else ""
    }
}
