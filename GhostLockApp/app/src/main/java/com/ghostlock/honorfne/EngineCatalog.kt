package com.ghostlock.honorfne

import android.content.Context

   
                                 
  
                                                               
                                                                        
                                                         
                                                                       
                                                            
                                         
  
                                                           
                                                      
                                        
  
                                                                     
                                                  
   
enum class Engine {
    GHOSTLOCK,

                                                     
    MODEL_PAYLOAD,

                                                          
    AAP_PAYLOAD,

    EXTRACTKIT, KNOWN_ONLY, NONE
}

data class EngineMatch(
    val engine: Engine,
    val profileIdx: Int = -1,
    val label: String = "",
    val reason: String = "",
                         
    val modelPack: ModelPayloads.Pack? = null
)

object EngineCatalog {

       
                                                    
                                                                
                        
      
                                                                  
                                                             
                                                                 
                                                
                                                                      
                                                  
      
                                                    
                                                                             
                                                                    
                                                               
                                                 
                                 
      
                                                                  
                                                         
                                                   
                                                              
       
    val PATCHED_EXPLOITS: Map<String, String> = mapOf(
        "5.4.289-qgki-gc1fab518d5f6" to "ghostlock_gc1fab",
        "5.4.289-qgki-g7fd5b29213eb" to "ghostlock_g7fd5b",
        "5.4.289-qgki-g2312a84fef60" to "ghostlock_g2312a84"
    )

                                            
    fun exploitAssetFor(kernel: String): String = PATCHED_EXPLOITS[kernel] ?: "ghostlock"

       
                                       
                                                         
                                                 
                    
       
    val PROBE_DISABLED_KERNELS: Set<String> = emptySet()

    fun probeDisabled(release: String): Boolean = false

                                                                         
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
        
        
        
        
        
    )

                                           
    private val GHOSTLOCK_MODELS = setOf(
        "FNE", "NTH", "HNFNE", "HNNTH", "LSA", "TNA"
        
    )

    private data class ProfileRow(
        val idx: Int, val key: String, val release: String,
        val prefix: String, val models: String, val name: String
    )

    @Volatile private var profilesCache: List<ProfileRow>? = null
    @Volatile private var knownCache: Set<String>? = null


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

       
                                    
                                                                   
       
    fun resolve(ctx: Context, kernel: String, modelFields: List<String>): EngineMatch {
        if (kernel.isBlank()) {
            return EngineMatch(Engine.NONE, reason = "无法读取内核版本，请先授权 Shizuku 再重新检测")
        }

        
        
        
        
        
        
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

        
        
        
        
        if (kernel.contains("gfde7767f6ef6", ignoreCase = true) &&
            modelFields.any { it.contains("AAP-AN00", ignoreCase = true) }
        ) {
            return EngineMatch(
                Engine.AAP_PAYLOAD,
                label = "AAP-AN00 专用载荷",
                reason = "机型 AAP-AN00 + 内核 gfde7767f6ef6 命中 LD_PRELOAD 载荷；" +
                    "该内核在链路 B 是 offsets-only 且 tracefs 被 SELinux 拒绝"
            )
        }

        
        
        
        
        
        
        
        
        
        
        
        ModelPayloads.detect(modelFields, kernel)?.let { pack ->
            if (ModelPayloads.available(ctx, pack)) {
                return EngineMatch(
                    Engine.MODEL_PAYLOAD,
                    label = "机型专用载荷 · ${pack.displayName}",
                    reason = "机型命中 ${pack.displayName}（${pack.note}）；" +
                        "该链路使用按机型编译的 exploit，与按内核版本匹配的通用版不同源" +
                        "；本机内核构建未被链路 A 收录，故走此链",
                    modelPack = pack
                )
            }
        }

        
        
        SelfAdapt.match(ctx, kernel)?.let { custom ->
            return EngineMatch(
                Engine.EXTRACTKIT,
                profileIdx = SelfAdapt.CUSTOM_PROFILE,
                label = "自助适配 · ${custom.release}",
                reason = "使用本机导入的 boot.img 现场生成的 profile" +
                    "（${custom.symbolCount} 个符号，结构偏移来自 ${custom.source}）"
            )
        }

        
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
