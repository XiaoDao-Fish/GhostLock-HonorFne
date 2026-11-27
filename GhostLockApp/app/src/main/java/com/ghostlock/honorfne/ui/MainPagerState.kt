package com.ghostlock.honorfne.ui

import androidx.compose.foundation.pager.PagerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.job
import kotlinx.coroutines.launch

   
                                                        
  
                                     
  
                                         
                                                                                
                                                                      
                                                           
                                                    
                                     
  
                                                                   
                                                 
  
                                                         
                                         
  
                                                       
                                                     
   
class MainPagerState(
    val pagerState: PagerState,
    private val coroutineScope: CoroutineScope
) {
                                              
    var selectedPage by mutableIntStateOf(pagerState.currentPage)
        private set

                                                 
    var isNavigating by mutableStateOf(false)
        private set

    private var navJob: Job? = null

       
                                      
                                  
       
    fun animateToPage(targetIndex: Int) {
        if (targetIndex == selectedPage) return
        if (targetIndex !in 0 until pagerState.pageCount) return

        navJob?.cancel()

        selectedPage = targetIndex
        isNavigating = true

        navJob = coroutineScope.launch {
            val myJob = coroutineContext.job
            try {
                pagerState.springAnimateToPage(targetIndex)
            } finally {
                if (navJob === myJob) {
                    isNavigating = false
                    
                    if (pagerState.currentPage != targetIndex) {
                        selectedPage = pagerState.currentPage
                    }
                }
            }
        }
    }

       
                                 
                            
       
    fun syncPage() {
        if (!isNavigating && selectedPage != pagerState.currentPage) {
            selectedPage = pagerState.currentPage
        }
    }
}

@Composable
fun rememberMainPagerState(
    pagerState: PagerState,
    coroutineScope: CoroutineScope = rememberCoroutineScope()
): MainPagerState = remember(pagerState, coroutineScope) {
    MainPagerState(pagerState, coroutineScope)
}
