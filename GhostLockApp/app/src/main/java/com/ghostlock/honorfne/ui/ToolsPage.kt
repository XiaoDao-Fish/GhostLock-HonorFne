package com.ghostlock.honorfne.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme

   
                             
  
                                      
                                
  
                                  
                              
   
@Composable
fun ToolsPage(
    state: UiState,
    live: LiveState,
    onRoot: () -> Unit,
    onRefresh: () -> Unit,
    onEnvCheck: () -> Unit,
    onPickManager: () -> Unit,
    onOtaUrlChange: (String) -> Unit,
    onOtaAdapt: () -> Unit,
    onClearProfile: () -> Unit,
    onSponsor: () -> Unit,
    onPickBootImage: () -> Unit
) {
    val scroll = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 16.dp)
    ) {
        SectionTitle("环境")
        GroupCard {
            StatusLine(
                text = state.compatText,
                tone = state.compatTone,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)
            )
            
            
            
            
            if (state.modelPackName.isNotBlank()) {
                GroupDivider()
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                    Text(
                        text = "提权链：${state.modelPackName}",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium,
                        color = MiuixTheme.colorScheme.onSurface
                    )
                    if (state.modelPackNote.isNotBlank()) {
                        Spacer(Modifier.height(3.dp))
                        Text(
                            text = state.modelPackNote,
                            fontSize = 12.sp,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                        )
                    }
                    
                    if (state.modelPackWarning.isNotBlank()) {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = state.modelPackWarning,
                            fontSize = 12.sp,
                            color = MiuixTheme.colorScheme.error,
                            maxLines = Int.MAX_VALUE
                        )
                    }
                }
            }
            if (state.ksuCompatText.isNotBlank()) {
                GroupDivider()
                Text(
                    text = state.ksuCompatText,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            }
            GroupDivider()
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SecondaryAction(
                    text = state.refreshLabel,
                    onClick = onRefresh,
                    modifier = Modifier.weight(1f)
                )
                SecondaryAction(
                    text = "环境自检",
                    onClick = onEnvCheck,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        SectionTitle("管理器")
        GroupCard {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = state.managerState.ifBlank { "未选择" },
                    modifier = Modifier.weight(1f),
                    fontSize = 14.sp,
                    color = MiuixTheme.colorScheme.onSurface
                )
                SecondaryAction(text = "选择", onClick = onPickManager)
            }
        }

        SectionTitle("内核适配")
        GroupCard {
            TextField(
                value = state.otaUrl,
                onValueChange = onOtaUrlChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                label = "全量包下载链接",
                singleLine = true
            )
            if (state.adaptState.isNotBlank()) {
                Text(
                    text = state.adaptState,
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 6.dp),
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            }
            if (state.adaptHint.isNotBlank()) {
                Text(
                    text = state.adaptHint,
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 6.dp),
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            }
            if (state.adaptBusy) {
                LinearProgressIndicator(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    progress = state.adaptProgress / 100f
                )
            }
            
            
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SecondaryAction(
                    text = "下载并适配",
                    onClick = onOtaAdapt,
                    modifier = Modifier.weight(1f),
                    enabled = !state.adaptBusy
                )
                SecondaryAction(
                    text = "导入 boot.img",
                    onClick = onPickBootImage,
                    modifier = Modifier.weight(1f),
                    enabled = !state.adaptBusy
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        PrimaryAction(
            text = state.rootButtonText,
            onClick = onRoot,
            enabled = state.rootButtonEnabled && !state.rootBusy
        )

        
        Spacer(Modifier.height(10.dp))
        LiveText(
            live = live,
            selector = { it.statusText.ifBlank { "等待操作" } },
            modifier = Modifier.padding(horizontal = 4.dp),
            fontSize = 12.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            maxLines = 2
        )

        Spacer(Modifier.height(18.dp))
        SecondaryAction(
            text = "清除已生成的 profile",
            onClick = onClearProfile,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(Modifier.height(10.dp))
        SecondaryAction(
            text = "赞助这个项目",
            onClick = onSponsor,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(110.dp))
    }
}
