package com.ghostlock.honorfne.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import top.yukonga.miuix.kmp.theme.ColorSchemeMode
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.ThemeController

   
                   
  
                                                      
                                                              
                                         
  
                                                   
                            
   
@Composable
fun HonorRootTheme(content: @Composable () -> Unit) {
    val controller = remember { ThemeController(colorSchemeMode = ColorSchemeMode.System) }
    MiuixTheme(controller = controller, content = content)
}
