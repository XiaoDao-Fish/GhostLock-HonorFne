package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 2026-11-20：把设备侧散落的 payload / exploit 日志汇总进 HonorRoot-Log。
 *
 * 用户诉求：完整成功 / 失败流程都要在 HonorRoot-Log 这一个文件里看全，不必再
 * 去 /data/local/tmp 逐个翻 w1.log、fake.log、ksu_stage.out、cve-2026-98260.log。
 * 这些文件由 payload/exploit 直接写到设备，App 之前只片段读取来做判因，从不
 * 整段落盘到导出日志里——失败后用户只能拿手机连电脑找文件。
 *
 * 触发点在 MainActivity.onRoot() 的 finally：链路无论成功、失败、提前返回、
 * 崩溃前收尾，都会经过这里收一次。用一条 shell 命令批量读取（减少 Shizuku
 * binder 往返），以罕见分隔符切段，只对存在且非空的文件落盘。
 *
 * 【2026-11-20 二次修正】旧实现每次 `tail -n 600` 读整份文件 + 按内容 hash
 * 去重。payload 日志是 append 的，每跑一次内容就变 → 每次都把 600 行历史重刷
 * 一遍，1827 行导出日志里约 1500 行是同一次自检的重复输出，真正的失败原因
 * 被埋在噪声里。现在改为按字节偏移只读增量：内容天然不重复，日志长度与
 * 实际运行次数成正比。
 */
object DeviceLogCollector {

    private data class Source(val title: String, val path: String)

    /**
     * 链路 A（GhostLock W1/W2 + KSU 晚加载）与链路 B（ExtractKit）的日志文件。
     * 两条链不会同时跑，但都收集是无害的：不存在的 / 空文件会被跳过。
     */
    private val SOURCES = listOf(
        Source("链路A · W1（关 SELinux）", "/data/local/tmp/w1.log"),
        Source("链路A · W2（cred 写入）", "/data/local/tmp/w2.log"),
        Source("链路A · KSU 晚加载链", "/data/local/tmp/ksu_fne/chain.log"),
        Source("链路A · root 通道", "/data/local/tmp/rs.out"),
        Source("链路B · 自检 check", "/data/local/tmp/extract-kit/check.log"),
        Source("链路B · 主链 fake", "/data/local/tmp/extract-kit/fake.log"),
        Source("链路B · payload 自有日志", "/data/local/tmp/cve-2026-98260.log"),
        Source("链路B · KSU 落地", "/data/local/tmp/ksu_stage.out")
    )

    /** 首次见到某个文件（没有偏移记录）时只保留尾部这么多行，避免把历史全灌进来。 */
    private const val FIRST_READ_LINES = 200

    /**
     * 读取并汇总所有设备侧日志。两个调用点：
     *  1) onRoot 的 finally —— 本轮正常结束（成功 / 失败 / 提前返回）；
     *  2) App 启动 binder 就绪后 —— 上次跑链路 A 时内核崩溃重启、App 被杀，
     *     finally 来不及执行的补偿场景。
     *
     * 用 SharedPreferences 记每份日志已读到的字节偏移，两个调用点因此可安全
     * 共存：第二次执行时 size 未变，直接跳过。全程 try 包裹：汇聚失败绝不能
     * 反过来影响提权结论或让 App 崩。
     */
    suspend fun collect(context: Context) = withContext(Dispatchers.IO) {
        runCatching {
            val prefs = context.getSharedPreferences("device_log_dump", Context.MODE_PRIVATE)

            // 1) 一次命令拿到所有文件的当前字节数（-1 = 不存在 / 读不到）。
            //    比逐个 stat 少 7 次 binder 往返，且不会因为某个文件不存在中断。
            val sizeCmd = SOURCES.joinToString("; ") { s ->
                "if [ -f '${s.path}' ]; then stat -c %s '${s.path}' 2>/dev/null; else echo -1; fi"
            }
            val sr = ShizukuController.exec(sizeCmd, 20_000)
            if (ShizukuController.channelDead(sr)) {
                LogStore.append("[汇总] 设备日志读取时 Shizuku 命令通道已断开，跳过")
                return@runCatching
            }
            val sizes = sr.out.lines().map { it.trim().toLongOrNull() ?: -1L }

            var collected = 0
            var skipped = 0
            SOURCES.forEachIndexed { idx, s ->
                val size = sizes.getOrNull(idx) ?: -1L
                if (size <= 0) return@forEachIndexed

                val key = "off:${s.path}"
                val last = prefs.getLong(key, -1L)
                if (last == size) {           // 没有新增内容
                    skipped++
                    return@forEachIndexed
                }
                // last in [0, size) → 只读 last 之后的增量；
                // 首次（-1）或文件被重建（size < last）→ 读尾部固定行数。
                val cmd = if (last in 0 until size) {
                    "tail -c +${last + 1} '${s.path}' 2>/dev/null"
                } else {
                    "tail -n $FIRST_READ_LINES '${s.path}' 2>/dev/null"
                }
                val r = ShizukuController.exec(cmd, 15_000)
                if (ShizukuController.channelDead(r)) {
                    LogStore.append("[汇总] 读取 ${s.title} 时命令通道断开，其余文件跳过")
                    return@runCatching
                }
                // 偏移先落盘：即使下面的写入失败，也不会把同一段内容重复计入下一轮。
                prefs.edit().putLong(key, size).apply()

                val body = r.out.replace("\u0000", "").trim('\n', '\r')
                if (body.isBlank()) return@forEachIndexed
                LogStore.appendBlock("设备日志 · ${s.title}", body)
                collected++
            }

            if (collected == 0) {
                LogStore.append(
                    if (skipped > 0) "[汇总] 设备侧日志无新增（${skipped} 份未变化，或已汇总过相同内容）"
                    else "[汇总] 设备侧日志无新增（本次未产生，或已汇总过相同内容）"
                )
            } else {
                LogStore.append("[汇总] 已将 $collected 份设备日志的**新增部分**汇总进本文件")
            }
            LogStore.sync(force = true, reason = "设备日志汇总完成")
        }.onFailure { e ->
            LogStore.append("[汇总] 设备日志汇总跳过：${e.message?.take(100) ?: "未知错误"}")
        }
    }
}
