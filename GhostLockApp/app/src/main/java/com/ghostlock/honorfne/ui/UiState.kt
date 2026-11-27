package com.ghostlock.honorfne.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

   
            
  
                                                           
                                                                   
                                                   
                                    
  
                
                                        
                                                  
                                              
                                                        
                                      
                                               
                                                
                                 
   
data class UiState(
                                    
    val tab: Int = 0,

    
    val homeTitle: String = "HonorRoot",
    val homeVersion: String = "",
    val rootState: String = "等待提权",
    val rootStateTone: Int = TONE_NEUTRAL,
    val deviceModel: String = "",
    val kernel: String = "",
    val shizuku: String = "",
    val ksuVersion: String = "",

    
    val compatText: String = "待检测",
                                          
    val refreshLabel: String = "重新检测",
    val compatTone: Int = TONE_NEUTRAL,
    val ksuCompatText: String = "",
    val managerState: String = "",
    val adaptState: String = "",
    val adaptHint: String = "",
    val otaUrl: String = "",
    val adaptBusy: Boolean = false,
    val adaptProgress: Int = 0,
    val rootButtonText: String = "一键临时 Root",
    val rootButtonEnabled: Boolean = true,
    val rootBusy: Boolean = false,

    
    val managerDialogOpen: Boolean = false,
    val managerEntries: List<ManagerEntry> = emptyList(),
    val managerBusy: Boolean = false,
                                  
    val selectedManagerPkg: String = "",

       
                            
                                    
       
    val modelPackName: String = "",
    val modelPackNote: String = "",
                                           
    val modelPackWarning: String = "",

                                         
    val rootLogOpen: Boolean = false,

                     
    val sponsorDialogOpen: Boolean = false,

    
    val aboutVersion: String = "",
    val aboutAuthor: String = "小刀",
    val aboutQq: String = "",
    val aboutGithub: String = ""
) {
    companion object {
        const val TONE_OK = 0
        const val TONE_WARN = 1
        const val TONE_ERROR = 2
        const val TONE_NEUTRAL = 3
    }
}

   
             
  
                                              
                     
   
data class ManagerEntry(
    val pkg: String,
    val label: String,
    val installed: Boolean,
                          
    val version: String,
                                          
    val bundledKo: Boolean
)

   
                           
  
                                             
                                        
                                  
   
class LiveState {
    var clock by mutableStateOf("--:--:--")
    var dateLine by mutableStateOf("")
    var greeting by mutableStateOf("")
    var statusText by mutableStateOf("")
    var logText by mutableStateOf("")
}

                                             
class UiStateHolder(initial: UiState = UiState()) {
    var state by mutableStateOf(initial)
        private set

    fun update(block: (UiState) -> UiState) {
        state = block(state)
    }

    fun set(transform: (UiState) -> Unit) {
        state = state.copy().also(transform)
    }
}
