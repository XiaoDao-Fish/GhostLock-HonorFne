package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

   
                                  
  
                                                                 
                                                              
                                                 
  
                                                 
                                                  
                                
  
                          
                                                                           
                                                                     
                               
                                                      
                         
                                                     
                                 
   
object ManagerSelection {
    const val DEFAULT_PACKAGE = ManagerCatalog.OFFICIAL_PKG
    private const val PREFS = "root_manager_selection"
    private const val KEY_PACKAGE = "package_name"
    private const val KEY_LABEL = "label"
    private val PACKAGE_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

    data class Manager(val packageName: String, val label: String, val apkPath: String)

    fun selected(context: Context): String {
        val raw = context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_PACKAGE, null)
            ?.trim()
        return if (!raw.isNullOrBlank() && PACKAGE_PATTERN.matches(raw)) raw else DEFAULT_PACKAGE
    }

    fun selectedLabel(context: Context): String {
        val pkg = selected(context)
        return context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_LABEL, null)
            ?.takeIf { it.isNotBlank() }
            ?: ManagerCatalog.labelOf(pkg)
    }

    fun save(context: Context, manager: Manager) {
        val pkg = manager.packageName.trim()
            .takeIf { PACKAGE_PATTERN.matches(it) } ?: DEFAULT_PACKAGE
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PACKAGE, pkg)
            .putString(KEY_LABEL, manager.label)
            .commit()
    }

    fun reset(context: Context) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_PACKAGE)
            .remove(KEY_LABEL)
            .commit()
    }

                                          
    fun selectedBundledKo(context: Context): Boolean =
        ManagerCatalog.bundledKoFor(selected(context))

       
                          
      
                                            
                                                     
                                         
       
    suspend fun scan(@Suppress("UNUSED_PARAMETER") context: Context): List<Manager> = withContext(Dispatchers.IO) {
        val listed = ShizukuController.exec("pm list packages -f 2>/dev/null", 25_000)
            .out.lines().mapNotNull { line ->
                
                val t = line.trim().removePrefix("package:")
                val eq = t.lastIndexOf('=')
                if (eq <= 0) return@mapNotNull null
                val apk = t.substring(0, eq).trim()
                val pkg = t.substring(eq + 1).trim()
                if (apk.startsWith("/") && PACKAGE_PATTERN.matches(pkg)) pkg to apk else null
            }

        listed.filter { (pkg, _) -> ManagerCatalog.looksLikeManager(pkg) }
            
            .distinctBy { it.first }
            .mapNotNull { (pkg, apk) ->
                if (!hasKsud(apk)) return@mapNotNull null
                Manager(pkg, ManagerCatalog.labelOf(pkg), apk)
            }
            .sortedWith(compareByDescending<Manager> { it.packageName == DEFAULT_PACKAGE }
                .thenBy { it.label })
    }

       
                                  
      
                                                                  
                                            
                                
       
    fun scanAsync(context: Context, onResult: (List<Manager>) -> Unit) {
        CoroutineScope(Dispatchers.IO).launch {
            val found = scan(context)
            withContext(Dispatchers.Main) { onResult(found) }
        }
    }

       
                             
      
                                       
                                                           
                                                        
                                                        
                                             
                     
      
                                               
                                    
       
    private suspend fun hasKsud(apk: String): Boolean {
        
        
        
        val pattern = "lib(ksud|adbroot|laapkjdiji|ejwxsjydpnf)[.]so"
        val g = ShizukuController.exec(
            "grep -aEc '$pattern' '$apk' 2>/dev/null", 15_000
        )
        if ((g.out.trim().toIntOrNull() ?: 0) > 0) return true
        val u = ShizukuController.exec(
            "unzip -Z1 '$apk' 2>/dev/null | grep -cE '$pattern'", 20_000
        )
        return (u.out.trim().toIntOrNull() ?: 0) > 0
    }

    suspend fun installed(@Suppress("UNUSED_PARAMETER") context: Context, pkg: String): Boolean =
        withContext(Dispatchers.IO) {
            ShizukuController.exec("pm path $pkg 2>/dev/null", 12_000).out.contains("package:")
        }
}
