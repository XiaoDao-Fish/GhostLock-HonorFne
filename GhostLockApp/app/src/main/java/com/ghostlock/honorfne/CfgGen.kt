package com.ghostlock.honorfne

/**
 * 移植自 ExtractKit 的 `ConfigGen`（只取「从 boot.img 现场生成 profile」用到的那一小块）：
 * 结构偏移、符号清单、`device.cfg` 的 336 字节二进制编码。
 *
 * 内置 75 条 profile 那张大表没有搬过来 —— HonorRoot 用的是离线的
 * `assets/extractkit/cfg.bin`（由 tools/gen_extractkit_assets.py 从 ConfigGen 生成，
 * 字节布局完全一致）。这里只补上「本机导入 boot.img 现场生成」这一条新路径，
 * 两条路径最终产出同一份 336 B 格式，payload 端无需任何改动。
 *
 * 字段顺序必须与 payload/src/runtime_cfg.h 的 load_device_cfg() 一一对应。
 */
object CfgGen {

    /** 从 kallsyms 里取的结构偏移。 */
    data class Offsets(
        val itimerSize: Int,
        val itimerNode: Int,
        val itimerHead: Int,
        val itimerElist: Int,
        val itimerFiring: Int,
        val itimerHandling: Int,
        val taskCred: Int,
        val taskComm: Int,
        val credSize: Int,
        val credUid: Int,
        val credSecurity: Int,
        val credUser: Int,
        val credUserNs: Int,
        val credUcounts: Int,
        val credGroups: Int,
    ) {
        fun pretty(): String = buildString {
            appendLine("k_itimer    size=${hex(itimerSize)} node=${hex(itimerNode)} head=${hex(itimerHead)}")
            appendLine("k_itimer    elist=${hex(itimerElist)} firing=${hex(itimerFiring)} handling=${hex(itimerHandling)}")
            appendLine("task_struct cred=${hex(taskCred)} comm=${hex(taskComm)}")
            appendLine("cred        size=${hex(credSize)} uid=${hex(credUid)} security=${hex(credSecurity)}")
            appendLine("cred        user=${hex(credUser)} user_ns=${hex(credUserNs)}")
            appendLine("cred        ucounts=${hex(credUcounts)} groups=${hex(credGroups)}")
        }

        private fun hex(v: Int) = "0x" + Integer.toHexString(v)
    }

    /** 现场能算的 call site / 尺寸，其余取默认（与 ExtractKit 的默认值一致）。 */
    data class Measured(
        val evCacheAlloc: Int = 269,
        val evCacheFree: Int = 272,
        val evPageFree: Int = 273,
        val evPageAlloc: Int = 275,
        val evPcpuDrain: Int = 277,
        val timerSiteOffset: Int = 0x94,
        val credSiteLow21: Int = 0x38458,
        val credReq: Int = 0xB8,
        val credAlloc: Int = 0xC0,
        val taskAllocLow21: Int = 0x1CB240,
        val taskAllocBytes: Int = 0x12C0,
        val objectsPerSlab: Int = 31,
        val paddingSlabs: Int = 150,
        val ntimers: Int = 4096,
        val victimIdx: Int = 2048,
        val lockers: Int = 3,
        val vmaCount: Long = 50000,
        val selinuxBlobOff: Int = 0x8,
        val selinuxSidKernel: Int = 1,
    )

    /** 需要从 kallsyms 里拿到的符号（panic_on_warn 为条件必需）。 */
    val REQUIRED_SYMBOLS = listOf(
        "do_timer_create",
        "selinux_state",
        "panic_on_warn",
        "root_user",
        "init_user_ns",
        "init_ucounts",
        "init_groups",
    )

    /** 真正决定「能不能拼出一份能跑的 cfg」的符号。 */
    val CORE_SYMBOLS = REQUIRED_SYMBOLS - "panic_on_warn"

    /** 拼 fake cred 绕不开的锚点（5.10 没有 ucounts）。 */
    val ANCHOR_SYMBOLS = listOf("root_user", "init_user_ns", "init_groups")

    fun offsetsFromBtf(btf: Btf): Offsets {
        fun need(struct: String, member: String): Int =
            btf.memberOffset(struct, member)
                ?: throw IllegalStateException("BTF 里 $struct.$member 找不到")
        return Offsets(
            itimerSize = btf.sizeOf("k_itimer") ?: throw IllegalStateException("BTF 里没有 k_itimer"),
            itimerNode = need("k_itimer", "node"),
            itimerHead = need("k_itimer", "head"),
            itimerElist = need("k_itimer", "elist"),
            itimerFiring = need("k_itimer", "firing"),
            itimerHandling = need("k_itimer", "handling"),
            taskCred = need("task_struct", "cred"),
            taskComm = need("task_struct", "comm"),
            credSize = btf.sizeOf("cred") ?: throw IllegalStateException("BTF 里没有 cred"),
            credUid = need("cred", "uid"),
            credSecurity = need("cred", "security"),
            credUser = need("cred", "user"),
            credUserNs = need("cred", "user_ns"),
            credUcounts = need("cred", "ucounts"),
            credGroups = need("cred", "group_info"),
        )
    }

    /**
     * 没有 BTF 的镜像用指令挖偏移（原样移植 ConfigGen.offsetsFromCode）：
     * 三处 `kmem_cache_create` 的 sizeof 参数 + `exit_creds` 清 cred 的 STR XZR。
     */
    fun offsetsFromCode(image: ByteArray, syms: Map<String, Long>, base: Long): Offsets? {
        fun fileOff(name: String): Int? {
            val a = syms[name] ?: return null
            val off = a - base
            return if (off in 0 until image.size - 256) off.toInt() else null
        }

        fun word(p: Int): Long {
            if (p < 0 || p + 4 > image.size) return 0
            return ((image[p].toLong() and 0xFF) or
                ((image[p + 1].toLong() and 0xFF) shl 8) or
                ((image[p + 2].toLong() and 0xFF) shl 16) or
                ((image[p + 3].toLong() and 0xFF) shl 24))
        }

        fun sizeArg(fn: String, lo: Int, hi: Int): Int? {
            val start = fileOff(fn) ?: return null
            var lastW1 = -1
            var lastW2 = -1
            var p = start
            val end = minOf(start + 0x600, image.size - 4)
            while (p < end) {
                val w = word(p)
                val top = w and 0xFF800000L
                val rd = (w and 0x1FL).toInt()
                if ((top == 0x52800000L || top == 0xD2800000L) && (rd == 1 || rd == 2)) {
                    val imm = (w ushr 5) and 0xFFFF
                    val hw = ((w ushr 21) and 0x3L).toInt()
                    val v = (imm shl (16 * hw)).toInt()
                    if (rd == 1) lastW1 = v else lastW2 = v
                } else if ((w and 0xFC000000L) == 0x94000000L) {
                    val cand = if (lastW1 >= 0) lastW1 else lastW2
                    if (cand in lo..hi && cand % 8 == 0) return cand
                    lastW1 = -1
                    lastW2 = -1
                }
                p += 4
            }
            return null
        }

        fun taskCredOff(): Int? {
            val start = fileOff("exit_creds") ?: return null
            var p = start
            val end = minOf(start + 0x200, image.size - 4)
            val hits = ArrayList<Int>(4)
            while (p < end) {
                val w = word(p)
                if ((w and 0xFFC00000L) == 0xF9000000L && (w and 0x1FL) == 31L) {
                    val off = (((w ushr 10) and 0xFFFL).toInt() * 8)
                    if (off in 0x400..0x1600 && !hits.contains(off)) hits.add(off)
                    if (hits.size >= 2) break
                }
                p += 4
            }
            return when {
                hits.size >= 2 -> maxOf(hits[0], hits[1])
                hits.size == 1 -> hits[0] + 8
                else -> null
            }
        }

        val itimerSize = sizeArg("init_posix_timers", 0x80, 0x400) ?: 0
        val credSize = sizeArg("cred_init", 0x80, 0x200) ?: return null
        val taskSize = sizeArg("fork_init", 0x600, 0x3000) ?: return null
        val taskCred = taskCredOff() ?: return null

        val big = credSize >= 0xB0
        val security = credSize - if (big) 0x38 else 0x30
        val user = security + 8
        val userNs = user + 8
        val groups = credSize - 0x18
        val ucounts = if (big) userNs + 8 else groups

        return Offsets(
            itimerSize = itimerSize,
            itimerNode = 0x78,
            itimerHead = 0,
            itimerElist = 0,
            itimerFiring = 0,
            itimerHandling = 0,
            taskCred = taskCred,
            taskComm = taskCred + 0x10,
            credSize = credSize,
            credUid = if (big) 8 else 4,
            credSecurity = security,
            credUser = user,
            credUserNs = userNs,
            credUcounts = ucounts,
            credGroups = groups,
        )
    }

    /** 生成 payload 运行时读的 device.cfg（336 字节），与 ExtractKit 逐字节一致。 */
    fun emitCfgBlob(syms: Map<String, Long>, off: Offsets, m: Measured): ByteArray {
        require(ANCHOR_SYMBOLS.all { (syms[it] ?: 0L) != 0L }) { "kallsyms 缺 cred 锚点符号" }
        val timerSym = syms["do_timer_create"] ?: 0L
        val staticTimer = if (timerSym != 0L) timerSym + m.timerSiteOffset.toLong() else 0L
        val u64 = listOf(
            staticTimer,
            staticTimer and 0x1FFFFF,
            syms["selinux_state"] ?: 0L,
            syms["panic_on_warn"] ?: 0L,
            syms["root_user"] ?: 0L,
            syms["init_user_ns"] ?: 0L,
            syms["init_ucounts"] ?: 0L,
            syms["init_groups"] ?: 0L,
            off.taskCred.toLong(),
            off.taskComm.toLong(),
            m.taskAllocLow21.toLong(),
            m.taskAllocBytes.toLong(),
            m.taskAllocBytes.toLong(),
            m.credReq.toLong(),
            m.credAlloc.toLong(),
            m.credSiteLow21.toLong(),
            off.itimerSize.toLong(),
            off.itimerNode.toLong(),
            off.itimerHead.toLong(),
            off.itimerElist.toLong(),
            off.itimerFiring.toLong(),
            off.itimerHandling.toLong(),
            off.itimerSize.toLong(),
            off.credUid.toLong(),
            off.credSecurity.toLong(),
            off.credUser.toLong(),
            off.credUserNs.toLong(),
            off.credUcounts.toLong(),
            off.credGroups.toLong(),
            0x1f00L,
            m.selinuxBlobOff.toLong(),
            m.selinuxSidKernel.toLong(),
            0x1ffffffffffL,
            m.ntimers.toLong(),
            m.victimIdx.toLong(),
            (m.paddingSlabs * m.objectsPerSlab).toLong(),
            m.lockers.toLong(),
            m.vmaCount,
        )
        require(u64.size == 38) { "字段数应为 38，实际 ${u64.size}" }
        val ev = intArrayOf(m.evCacheAlloc, m.evCacheFree, m.evPageFree, m.evPageAlloc, m.evPcpuDrain)
        val out = java.io.ByteArrayOutputStream()
        out.write("EXKCFG01".toByteArray(Charsets.US_ASCII))
        out.write(byteArrayOf(38, 0, 0, 0))
        val buf = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        u64.forEach { v ->
            buf.clear(); buf.putLong(v); out.write(buf.array())
        }
        ev.forEach { v ->
            buf.clear(); buf.putInt(v); out.write(buf.array(), 0, 4)
        }
        return out.toByteArray()
    }

    /** 是否为一份合法的 device.cfg（payload 认的 magic + 336 B）。 */
    fun isCfg(blob: ByteArray?): Boolean {
        if (blob == null || blob.size != 336) return false
        return String(blob.copyOfRange(0, 8), Charsets.US_ASCII) == "EXKCFG01"
    }
}
