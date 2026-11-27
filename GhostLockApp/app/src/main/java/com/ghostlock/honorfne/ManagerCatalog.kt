package com.ghostlock.honorfne

   
                                        
  
            
                                                           
                                                                
                                                                    
                                                   
                                                         
                                          
  
                                                 
  
                    
                                   
                                                                       
                                                        
                                                 
                                           
                                                                     
                                 
                                                                       
                                    
  
                                          
                                       
                                                           
   
object ManagerCatalog {

    enum class Lineage {
        OFFICIAL,      
        SEVENK,        
        RESUKISU,      
        SUKISU,        
        SUKISU_ULTRA,  
        KERNELSU_NEXT, 
        APATCH,        
        MAGISK,        
        OTHER
    }

    data class Known(
        val pkg: String,
        val label: String,
                                            
        val workingDir: String,
                                            
        val bundledKo: Boolean,
        val lineage: Lineage
    )

                       
    const val OFFICIAL_PKG = "me.weishu.kernelsu"

    private val KNOWN = listOf(
        Known(OFFICIAL_PKG, "KernelSU 官方 3.3.0", "/data/adb/ksu", true, Lineage.OFFICIAL),
        Known("com.sevenk.core", "7kimisu", "/data/adb/sevenk", false, Lineage.SEVENK),
        Known("com.sevenk.core.pr", "7kimisu（PR 版）", "/data/adb/sevenk", false, Lineage.SEVENK),
        Known("com.resukisu.resukisu", "ReSukiSU（BakaSU 系）", "/data/adb/ksu", false, Lineage.RESUKISU),
        Known("com.sukisu.nova", "SukiSU-Nova", "/data/adb/ksu", false, Lineage.SUKISU),
        Known("com.sukisu.nova.pr", "SukiSU-Nova（PR 版）", "/data/adb/ksu", false, Lineage.SUKISU),
        Known("com.sukisu.ultra", "SukiSU-Ultra", "/data/adb/ksu", false, Lineage.SUKISU_ULTRA),
        Known("com.sukisu.ultra.debug", "SukiSU-Ultra（debug）", "/data/adb/ksu", false, Lineage.SUKISU_ULTRA),
        Known("com.rifsxd.ksunext", "KernelSU Next", "/data/adb/ksu", false, Lineage.KERNELSU_NEXT),
        Known("me.bmax.apatch", "APatch", "/data/adb/ap", false, Lineage.APATCH),
        Known("com.topjohnwu.magisk", "Magisk", "/data/adb/magisk", false, Lineage.MAGISK)
    )

    private val BY_PKG = KNOWN.associateBy { it.pkg }

       
                                 
                                               
       
    private val KEYWORDS = listOf(
        "kernelsu", "ksunext", "sukisu", "sevenk", "resukisu",
        "bakasu", "apatch", "magisk"
    )

    fun of(pkg: String?): Known? = pkg?.trim()?.let { BY_PKG[it] }

                                                       
    fun looksLikeManager(pkg: String): Boolean {
        val p = pkg.lowercase()
        if (BY_PKG.containsKey(pkg)) return true
        if (KEYWORDS.any { p.contains(it) }) return true
        
        return p.split('.').any { it == "ksu" }
    }

    fun labelOf(pkg: String): String = of(pkg)?.label ?: run {
        val p = pkg.lowercase()
        when {
            p.contains("sevenk") -> "7kimisu"
            p.contains("resukisu") || p.contains("bakasu") -> "BakaSU / ReSukiSU"
            p.contains("sukisu") && p.contains("ultra") -> "SukiSU-Ultra"
            p.contains("sukisu") -> "SukiSU"
            p.contains("ksunext") -> "KernelSU Next"
            p.contains("apatch") -> "APatch"
            p.contains("magisk") -> "Magisk"
            p.contains("kernelsu") -> "KernelSU"
            else -> pkg.substringAfterLast('.').ifBlank { pkg }
        }
    }

    fun workingDirOf(pkg: String): String = of(pkg)?.workingDir ?: "/data/adb/ksu"

                                                    
    fun bundledKoFor(pkg: String): Boolean = of(pkg)?.bundledKo == true

                     
    fun suitabilityText(pkg: String): String = if (bundledKoFor(pkg)) {
        "内置模块可用"
    } else {
        "需自带模块"
    }

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
