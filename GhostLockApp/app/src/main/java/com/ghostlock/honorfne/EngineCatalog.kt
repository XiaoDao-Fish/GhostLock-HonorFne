package com.ghostlock.honorfne

import android.content.Context

/**
 * 双引擎目录：按 `uname -r` 决定这次用哪条提权链。
 *
 * 链路 A（GHOSTLOCK）：本项目自带的 `assets/ghostlock`（CVE-2026-43499 系），
 *   偏移表在 root/exploit/src/devices 各机型的 offsets.h，共 13 个机型 / 28 个精确内核构建。
 *   二进制用 strcmp(uts.release, ...) 精确匹配，缺条目直接退出，绝不能用前缀放宽。
 *   预编译 ELF 的 known_offsets[] 只有 26 个槽，因此 5.4.289-qgki-gc1fab518d5f6 与
 *   5.4.289-qgki-g7fd5b29213eb 各用一份补丁版二进制（把未经真机验证的最后一个槽换掉），
 *   其余内核仍用原版，由 AssetDeployer 按内核挑选，互不损失。
 *
 * 链路 B（EXTRACTKIT）：ExtractKit 的 CVE-2026-98260 静态 payload，
 *   由 device.cfg（336 B）提供每颗内核的符号与结构偏移，75 条内置 profile。
 *   这是完全不同的漏洞原语，不能靠往链路 A 的白名单加字符串来「适配」。
 *
 * profile 表与 cfg.bin 由 tools/gen_extractkit_assets.py 从 ExtractKit 的
 * ConfigGen.kt 离线生成，保证字节布局与官方 emitCfgBlob() 完全一致。
 */
enum class Engine { GHOSTLOCK, EXTRACTKIT, KNOWN_ONLY, NONE }

data class EngineMatch(
    val engine: Engine,
    val profileIdx: Int = -1,
    val label: String = "",
    val reason: String = ""
)

object EngineCatalog {

    /**
     * 资产选择原则（2026-11-20 修正）：**原版已收录 → 用原版；原版未收录 → 用
     * 只改 uname 串 + offsets entry 的最小补丁版**。绝不用带 force-light / 重推
     * memstart 表的历史补丁版。
     *
     * 原版 assets/ghostlock 的 26 槽实测只收录了 5.4.289-qgki-gf6cb1f712a6e
     * 与 5.4.295-qgki-g0fb2656b2b50 等条目；逐字节核对确认下列 3 颗 5.4.289
     * 内核**不在**原版里：gc1fab518d5f6 / g7fd5b29213eb / g2312a84fef60。
     * 11-15「老版配方回归」把这三颗也一律改成推原版，结果 exploit 一启动就
     * 打印 `[!] no offsets for kernel: ...` 退出，App 却空等两轮 420s 并 reboot。
     * 11-17 只为 g2312a84 开了例外，另外两颗同样需要补丁版——这是同一缺陷。
     *
     * 为什么原版配方仍适用于 g0fb2656b2b50：老版成功日志（14:40~14:43）
     * 只推 `ghostlock`，w1.log 报 `offsets matched: 5.4.295-qgki-g0fb2656b2b50`，
     * W1 30s 关掉 SELinux、W2 `child is root → ROOTED`。之后按 boot.img 重推
     * 224 槽 memstart 表 + force-light（5 波×400 改 2 波×200）的版本反而凑出
     * 125 GiB 假共识 slide 并重启；老版 5 波跑完证明那些「优化」是倒退。
     * 因此那颗内核继续走原版，补丁资产只作为对照、不下发。
     *
     * g7fd5b29213eb 的补丁资产已换回 tools/out/ghostlock_g7fd5b（18:33 生成，
     * 只改 uname + offsets 两处，cmp x8,#60 保持原值），assets 里那份带
     * force-light 的旧版不得再下发。gc1fab518d5f6 的补丁资产经核对无
     * force-light（1ff100f1），文本布局与 gf6cb1f 一致、不需要动 memstart 表。
     */
    val PATCHED_EXPLOITS: Map<String, String> = mapOf(
        "5.4.289-qgki-gc1fab518d5f6" to "ghostlock_gc1fab",
        "5.4.289-qgki-g7fd5b29213eb" to "ghostlock_g7fd5b",
        "5.4.289-qgki-g2312a84fef60" to "ghostlock_g2312a84"
    )

    /** 原版已收录的内核走原版；仅原版未收录且已精确适配的内核走补丁资产。 */
    fun exploitAssetFor(kernel: String): String = PATCHED_EXPLOITS[kernel] ?: "ghostlock"

    /**
     * 老版配方：不禁用 memstart 探针。老版成功轮的环境里没有
     * GL_MEMSTART_PROBE，探针正常跑、凑出共识后由 exploit 自己决定 DM 基址。
     * 之前为绕开假共识而加的「禁用探针 + 显式 DM_PAGE_OFFSET」是真机反复
     * 重启的直接原因，一并回退。
     */
    val PROBE_DISABLED_KERNELS: Set<String> = emptySet()

    fun probeDisabled(release: String): Boolean = false

    /** 与 root/exploit/src/devices 各机型 offsets.h 的 OFFSETS_ENTRY 逐字一致。 */
    val GHOSTLOCK_KERNELS = listOf(
        "5.4.289-qgki-gf6cb1f712a6e",
        "5.4.289-qgki-gc1fab518d5f6",
        "5.4.289-qgki-g7fd5b29213eb",
        "5.4.289-qgki-g2312a84fef60",
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
        // 2026-11-20：只保留荣耀。原 5.10/6.1/6.6/6.12 段里的索尼 Xperia、
        // OPPO（Find X9/Reno10/Pad4）、一加（13/15/Ace6T）、小米 17、vivo
        // （X200/X Fold3/T4）等 15 条非荣耀内核已从白名单移除；非荣耀机型
        // 不再进入链路 A。这些内核的偏移仍在预编译 exploit 二进制里，但
        // 白名单不命中就不会选中它，不影响荣耀内核的配方。
    )

    /** 链路 A 的机型代号，仅用于「机型已支持」提示，不作为放行门槛。 */
    private val GHOSTLOCK_MODELS = setOf(
        "FNE", "NTH", "HNFNE", "HNNTH", "LSA", "TNA"
        // 2026-11-20：只保留荣耀，移除 OPPO/一加/小米/vivo/索尼机型代号。
    )

    private data class ProfileRow(
        val idx: Int, val key: String, val release: String,
        val prefix: String, val models: String, val name: String
    )

    @Volatile private var profilesCache: List<ProfileRow>? = null
    @Volatile private var knownCache: Set<String>? = null

    /** 复刻 ConfigGen.kernelKey：版本号 + g<hash> 前 12 位。 */
    fun kernelKey(release: String?): String {
        val s = release?.trim()?.lowercase().orEmpty()
        if (s.isEmpty()) return ""
        val ver = Regex("^\\d+\\.\\d+\\.\\d+").find(s)?.value ?: s.take(8)
        val hash = Regex("g([0-9a-f]{8,40})").find(s)?.groupValues?.get(1)?.take(12)
        return if (hash.isNullOrEmpty()) ver else "$ver-g$hash"
    }

    private fun readText(ctx: Context, asset: String): String = runCatching {
        ctx.assets.open(asset).use { it.bufferedReader(Charsets.UTF_8).readText() }
    }.getOrDefault("")

    private fun profiles(ctx: Context): List<ProfileRow> {
        profilesCache?.let { return it }
        val rows = readText(ctx, "extractkit/profiles.tsv").lineSequence()
            .map { it.split('\t') }
            .filter { it.size >= 6 }
            .mapNotNull { c ->
                runCatching {
                    ProfileRow(
                        c[0].toInt(), c[1], c[2], c[3], c[4], c[5]
                    )
                }.getOrNull()
            }.toList()
        profilesCache = rows
        return rows
    }

    /** ExtractKit 的机型识别库：known.tsv（53 条）+ iknow.tsv（5479 行，第 2 列是型号）。 */
    private fun knownModels(ctx: Context): Set<String> {
        knownCache?.let { return it }
        val set = HashSet<String>(6000)
        readText(ctx, "extractkit/known.tsv").lineSequence()
            .map { it.split('\t') }
            .filter { it.isNotEmpty() && it[0].isNotBlank() }
            .forEach { set.add(it[0].trim().uppercase()) }
        readText(ctx, "extractkit/iknow.tsv").lineSequence()
            .map { it.split('\t') }
            .filter { it.size >= 2 && it[1].isNotBlank() }
            .forEach { set.add(it[1].trim().uppercase()) }
        knownCache = set
        return set
    }

    fun profileCount(ctx: Context): Int = profiles(ctx).size

    /**
     * @param kernel  uname -r 原始字符串
     * @param modelFields Build.MODEL / DEVICE / BOARD / HARDWARE 等
     */
    fun resolve(ctx: Context, kernel: String, modelFields: List<String>): EngineMatch {
        if (kernel.isBlank()) {
            return EngineMatch(Engine.NONE, reason = "无法读取内核版本，请先授权 Shizuku 再重新检测")
        }

        // 0) 链路 A 优先：必须逐字相等（二进制用 strcmp，前缀匹配会误放行）。
        //    【2026-11-20 修正】以前自助适配放在最前面，用户为 NTH-AN00
        //    （5.4.295-qgki-g0fb2656b2b50，本机 boot.img）生成的 offsets-only
        //    profile 会抢占原版 ghostlock 链；payload 自检 READY 却拿不到 cred，
        //    白跑 6 分钟。这颗内核原版 exploit 本来就收录（老版成功日志实证），
        //    只要逐字命中就必须走链路 A，绝不把已验证的配方降级成现场猜测。
        if (GHOSTLOCK_KERNELS.contains(kernel)) {
            val variant = if (PATCHED_EXPLOITS.containsKey(kernel))
                "；该构建使用按 boot.img 精确提取偏移的补丁版 exploit（${PATCHED_EXPLOITS[kernel]}）" else ""
            val stale = SelfAdapt.match(ctx, kernel)
            return EngineMatch(
                Engine.GHOSTLOCK,
                label = "GhostLock 内核漏洞链",
                reason = "内核构建逐字命中 offsets.h 的 ${GHOSTLOCK_KERNELS.size} 个 OFFSETS_ENTRY 之一" +
                    variant +
                    (if (stale != null) "；本机虽有自助适配 profile，但链路 A 已验证，已忽略该 profile" else "")
            )
        }

        // 1) 自助适配：链路 A 未收录时，用本机 boot.img 现场生成的 profile。
        //    只有内核 key 完全一致才会命中（导入别人机器的 img 不会被误用）。
        SelfAdapt.match(ctx, kernel)?.let { custom ->
            return EngineMatch(
                Engine.EXTRACTKIT,
                profileIdx = SelfAdapt.CUSTOM_PROFILE,
                label = "自助适配 · ${custom.release}",
                reason = "使用本机导入的 boot.img 现场生成的 profile" +
                    "（${custom.symbolCount} 个符号，结构偏移来自 ${custom.source}）"
            )
        }

        // 2) 链路 B：按 kernelKey 精确，再按 prefix 回落（与 ConfigGen.profileFor 一致）
        val rows = profiles(ctx)
        val key = kernelKey(kernel)
        val hit = rows.firstOrNull { it.key == key }
            ?: rows.firstOrNull { kernel.startsWith(it.prefix) }
        if (hit != null) {
            return EngineMatch(
                Engine.EXTRACTKIT,
                profileIdx = hit.idx,
                label = hit.name,
                reason = "命中 ExtractKit 内置 profile #${hit.idx}（${hit.models.ifBlank { "不限机型" }}），" +
                    "将下发 336 B device.cfg 并运行 98260 payload"
            )
        }

        // 3) 机型已收录，但这颗内核没有可用偏移 → 明确提示，不冒充可提权
        val upper = modelFields.map { it.uppercase() }
        val modelHit = GHOSTLOCK_MODELS.any { g -> upper.any { it.contains(g) } } ||
            knownModels(ctx).any { m -> upper.any { it.contains(m) } }
        if (modelHit) {
            return EngineMatch(
                Engine.KNOWN_ONLY,
                label = "机型已收录",
                reason = "该机型在支持列表里，但当前内核构建没有可用偏移表。" +
                    "换 OTA 会改符号布局，强行套用会写坏内核内存，故不放行"
            )
        }
        return EngineMatch(
            Engine.NONE,
            reason = "机型与内核均未收录。白名单按精确内核构建（含 -g<hash>）判定，不是按系统版本号"
        )
    }

    /** 从 cfg.bin 取第 idx 条 336 字节的 device.cfg。 */
    fun cfgFor(ctx: Context, idx: Int): ByteArray? {
        if (idx < 0) return null
        val blob = runCatching {
            ctx.assets.open("extractkit/cfg.bin").use { it.readBytes() }
        }.getOrNull() ?: return null
        val off = idx * 336
        if (off + 336 > blob.size) return null
        val cfg = blob.copyOfRange(off, off + 336)
        val magic = String(cfg.copyOfRange(0, 8), Charsets.US_ASCII)
        return if (magic == "EXKCFG01") cfg else null
    }
}
