package com.ghostlock.honorfne.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostlock.honorfne.ui.glass.FloatingBottomBar
import com.ghostlock.honorfne.ui.glass.FloatingBottomBarItem
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.theme.MiuixTheme

                                                   
enum class HomeTab(val label: String, val icon: ImageVector) {
    Home("首页", Icons.Filled.Home),
    Tools("工具", Icons.Filled.Build),
    About("关于", Icons.Filled.Info)
}

   
        
  
                                    
                                                           
                                                    
                                           
                                             
                                                     
                                                   
                                                             
  
                                           
                                        
                                   
                                          
   
@Composable
fun AppUi(
    state: UiState,
    live: LiveState,
    onTabChange: (Int) -> Unit,
    onRoot: () -> Unit,
    onRefresh: () -> Unit,
    onEnvCheck: () -> Unit,
    onPickManager: () -> Unit,
    onOtaUrlChange: (String) -> Unit,
    onOtaAdapt: () -> Unit,
    onAuthor: () -> Unit,
    onSponsor: () -> Unit,
    onConnect: () -> Unit,
    onKsuTap: () -> Unit,
    onCopyQq: () -> Unit,
    onOpenGithub: () -> Unit,
    onClearProfile: () -> Unit,
    onPickBootImage: () -> Unit,
    onSelectManager: (String) -> Unit,
    onDismissManager: () -> Unit,
    onClearLog: () -> Unit,
    onShareLog: () -> Unit,
    onBackFromLog: () -> Unit,
    onDismissSponsor: () -> Unit
) {
    HonorRootTheme {
        val scope = rememberCoroutineScope()
        val pagerState = rememberPagerState(pageCount = { HomeTab.entries.size })
        val mainPagerState = rememberMainPagerState(pagerState, scope)

        
        LaunchedEffect(pagerState) {
            snapshotFlow { pagerState.currentPage }.collect {
                mainPagerState.syncPage()
            }
        }

        
        val surface = MiuixTheme.colorScheme.surface
        val backdrop = rememberLayerBackdrop {
            drawRect(surface)
            drawContent()
        }

        
        
        
        if (state.rootLogOpen) {
            RootLogPage(
                live = live,
                busy = state.rootBusy,
                onBack = onBackFromLog,
                onClear = onClearLog,
                onShare = onShareLog
            )
            return@HonorRootTheme
        }

        Scaffold(
            modifier = Modifier.fillMaxSize(),
            bottomBar = {
                
                
                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.BottomCenter
                ) {
                    FloatingBottomBar(
                        modifier = Modifier.padding(
                            bottom = 12.dp +
                                WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
                        ),
                        
                        
                        
                        selectedIndex = { mainPagerState.selectedPage },
                        onSelected = { index ->
                            onTabChange(index)
                            mainPagerState.animateToPage(index)
                        },
                        backdrop = backdrop,
                        tabsCount = HomeTab.entries.size
                    ) {
                        HomeTab.entries.forEach { tab ->
                            
                            
                            
                            FloatingBottomBarItem(
                                onClick = {
                                    onTabChange(tab.ordinal)
                                    mainPagerState.animateToPage(tab.ordinal)
                                },
                                modifier = Modifier.defaultMinSize(minWidth = 76.dp)
                            ) {
                                
                                
                                
                                Icon(
                                    imageVector = tab.icon,
                                    contentDescription = tab.label
                                )
                                Text(
                                    text = tab.label,
                                    fontSize = 11.sp,
                                    lineHeight = 14.sp,
                                    maxLines = 1,
                                    softWrap = false,
                                    overflow = TextOverflow.Visible
                                )
                            }
                        }
                    }
                }
            }
        ) { inner ->
            HorizontalPager(
                state = pagerState,
                modifier = Modifier
                    .fillMaxSize()
                    .layerBackdrop(backdrop)
                    .padding(top = inner.calculateTopPadding())
            ) { page ->
                when (HomeTab.entries[page]) {
                    HomeTab.Home -> HomePage(
                        state = state,
                        live = live,
                        onConnect = onConnect,
                        onKsuTap = onKsuTap,
                        onSponsor = onSponsor
                    )
                    HomeTab.Tools -> ToolsPage(
                        state = state,
                        live = live,
                        onRoot = onRoot,
                        onRefresh = onRefresh,
                        onEnvCheck = onEnvCheck,
                        onPickManager = onPickManager,
                        onOtaUrlChange = onOtaUrlChange,
                        onOtaAdapt = onOtaAdapt,
                        onClearProfile = onClearProfile,
                        onSponsor = onSponsor,
                        onPickBootImage = onPickBootImage
                    )
                    HomeTab.About -> AboutPage(
                        state = state,
                        onAuthor = onAuthor,
                        onSponsor = onSponsor,
                        onCopyQq = onCopyQq,
                        onOpenGithub = onOpenGithub
                    )
                }
            }
        }
    }

    
    if (state.managerDialogOpen) {
        ManagerPickerDialog(
            entries = state.managerEntries,
            selectedPkg = state.selectedManagerPkg,
            onSelect = onSelectManager,
            onDismiss = onDismissManager
        )
    }

    
    if (state.sponsorDialogOpen) {
        SponsorDialog(onDismiss = onDismissSponsor)
    }

}
