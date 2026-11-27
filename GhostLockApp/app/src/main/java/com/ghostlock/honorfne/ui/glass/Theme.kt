package com.ghostlock.honorfne.ui.glass

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.luminance
import top.yukonga.miuix.kmp.theme.MiuixTheme

   
         
  
                                                                 
                                                       
                                                 
                                                 
   
@Composable
@ReadOnlyComposable
fun isInDarkTheme(): Boolean =
    MiuixTheme.colorScheme.surface.luminance() < 0.5f
