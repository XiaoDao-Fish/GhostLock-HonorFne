package com.ghostlock.honorfne

import android.content.Context
import android.os.Build

   
                              
  
               
  
                                                    
                                                      
                                 
  
                                                          
                                       
  
                      
                       
                                                           
                                                                                         
  
                                                  
                                            
                                                 
  
                                                                    
                                                  
                                   
  
          
  
                             
  
                                          
                                              
                                
  
                                      
                                                
        
  
          
  
                                            
  
                                 
                                                       
                                      
                                                    
  
                                                                 
                                               
   
object ModelPayloads {

                    
    data class Pack(
                                           
        val assetDir: String,
                   
        val displayName: String,
                                      
        val matchKeys: List<String>,
                          
        val note: String,
                                
        val warning: String,
           
                                              
                                       
                                                      
                       
           
        val kernelHashes: List<String> = emptyList(),
                                                                       
        val baseAssetDir: String = assetDir,
                                           
        val priority: Int = 0,
                                                 
        val procPattern: String = "gl_ex[p]loit",
                                                                
        val ownKsu: Boolean = false
    )

       
                            
      
                                                             
                                              
       
    val A2_KERNEL_MODELS: List<Pair<String, String>> = listOf(
        "5.10.168-android12-9-g804a21a522f0" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.198-android12-9-gc42b584f520f" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.198-android12-9-gc68223d35014" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.198-android12-9-ge28f4cc48488" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.198-android12-9-gae8854726f00" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.209-android12-9-g516fa23f87fc" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.209-android12-9-g3f72b82cd79b" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.209-android12-9-g17b3438a8cf3" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.209-android12-9-g465fb5c2ecc8" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.209-android12-9-g994df2e00710" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.209-android12-9-ga3ff7ae30334" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.209-android12-9-gff94831502de" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.226-android12-9-g9bf3dab43973" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.226-android12-9-gd118e0c61d77" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.236-android12-9-gd1575ab10b30" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.236-android12-9-gf6010a2c8c91" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.236-android12-9-ga88335e8db40" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.236-android12-9-gd671cf8c2b02" to "AGT-AN00（荣耀80GT） / REA-AN00（荣耀90）",
        "5.10.236-android12-9-00006-g71f3aedc8b92" to "REA-NX9（荣耀90国际版）"
    )

       
             
      
                                                                    
                                                       
                           
      
                                                
                                    
                                       
       
    
    val PACKS: List<Pack> = ModelPayloadMatrix.PACKS + listOf(
        Pack(
            assetDir = "anb_an00", displayName = "荣耀 80 Pro 直屏版（9.0.0.230）",
            matchKeys = listOf("ANB-AN00", "HNANB"),
            note = "honor-anb-an00-root 内置载荷，内核 5.10.236-gd671cf8c2b02",
            warning = "", kernelHashes = listOf("gd671cf8c2b02"),
            baseAssetDir = "agt_common", priority = 20, procPattern = "exploi[t]",
            ownKsu = true
        ),
        Pack(
            assetDir = "rea_nx9", displayName = "荣耀 90 国际版（REA-NX9）",
            matchKeys = listOf("REA-NX9", "REA-NX9"),
            note = "honor90-ghostlock 的 REA-NX9 / 9.0.0.211 载荷，内核 5.10.236-g71f3aedc8b92",
            warning = "该载荷来自第三方仓库，未见完整真机验证记录；失败可能重启，请先备份",
            kernelHashes = listOf("g71f3aedc8b92"), priority = 20,
            procPattern = "exploi[t]", ownKsu = true
        ),
        Pack(
            assetDir = "honor90",
            displayName = "荣耀 90",
            matchKeys = listOf("REA-AN00", "REA-AN10", "HONOR90", "BVL-AN00"),
            note = "荣耀 90 专用载荷",
            warning = ""
        ),
        Pack(
            assetDir = "magic4_x50",
            displayName = "荣耀 Magic4 / X50 / X60 Pro",
            matchKeys = listOf(
                "ALN-AL00", "ALN-AL10", "ALN-TL00",   
                "ALI-AN00", "ALI-AN10", "ALI-TL00",   
                "TEL-AN00", "TEL-AN10", "TEL-TL00"    
            ),
            note = "Magic4 与 X50/X60 Pro 共用同一套载荷（二进制逐字节相同）",
            warning = ""
        ),
        Pack(
            
            
            assetDir = "magic4_x50",
            displayName = "荣耀 Play9T（借用 X50 载荷）",
            matchKeys = listOf("LGE-AN00", "LGE-AN10"),
            note = "Play9T 借用 X50 通用载荷",
            warning = "该机型使用 X50 通用提权脚本，成功率极低，存在死机风险，请谨慎测试！"
        )
    )

                                     
    fun packOf(assetDir: String): Pack? = PACKS.firstOrNull { it.assetDir == assetDir }

       
                     
      
                                                                             
                               
       
    fun detect(modelFields: List<String>, kernel: String = ""): Pack? {
        if (modelFields.isEmpty()) return null
        val upper = modelFields.map { it.trim().uppercase() }.filter { it.isNotEmpty() }
        if (upper.isEmpty()) return null
        
        
        val ordered = PACKS.sortedByDescending { it.priority * 1000 + it.matchKeys.size }
        for (pack in ordered) {
            if (pack.kernelHashes.isNotEmpty() &&
                pack.kernelHashes.none { kernel.contains(it, ignoreCase = true) }
            ) continue
            for (key in pack.matchKeys) {
                if (upper.any { it.contains(key) }) return pack
            }
        }
        return null
    }

                                      
    fun detectCurrent(kernel: String = ""): Pack? = detect(
        listOf(Build.MODEL, Build.DEVICE, Build.PRODUCT, Build.BOARD, Build.HARDWARE),
        kernel
    )

       
                                   
       
    fun available(ctx: Context, pack: Pack): Boolean = runCatching {
        val path = listOf("${pack.assetDir}/exploit.dat", "${pack.assetDir}/exploit")
            .first { p -> runCatching { ctx.assets.open("models/$p").close() }.isSuccess }
        path.isNotEmpty()
    }.getOrDefault(false)

       
                           
      
                                
       
    fun coveredByChainA(kernel: String): Boolean =
        EngineCatalog.GHOSTLOCK_KERNELS.contains(kernel)
}
