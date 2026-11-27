package com.ghostlock.honorfne.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

   
         
  
                                   
                                    
                       
  
                                     
                                                    
   
@Composable
fun RootLogPage(
    live: LiveState,
    busy: Boolean,
    onBack: () -> Unit,
    onClear: () -> Unit,
    onShare: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MiuixTheme.colorScheme.background)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 8.dp, end = 16.dp, top = 14.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "‹  返回",
                modifier = Modifier
                    .clip(RoundedCornerShape(10.dp))
                    .clickable(
                        interactionSource = null,
                        indication = null,
                        onClick = onBack
                    )
                    .padding(horizontal = 10.dp, vertical = 8.dp),
                fontSize = 15.sp,
                color = MiuixTheme.colorScheme.primary
            )
            Spacer(Modifier.weight(1f))
            SecondaryAction(text = "清空", onClick = onClear)
            Spacer(Modifier.width(8.dp))
            SecondaryAction(text = "分享", onClick = onShare)
        }

        LiveText(
            live = live,
            selector = { it.statusText },
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
            fontSize = 13.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary
        )

        val logScroll = rememberScrollState()
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(horizontal = 20.dp, vertical = 8.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(MiuixTheme.colorScheme.surfaceContainer)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(logScroll)
                    .padding(14.dp)
            ) {
                LiveText(
                    live = live,
                    selector = { it.logText.ifBlank { "暂无日志" } },
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Normal,
                    color = MiuixTheme.colorScheme.onSurface
                )
            }
        }
        
        
        
        
        LaunchedEffect(Unit) {
            snapshotFlow { live.logText }.collect {
                logScroll.animateScrollTo(logScroll.maxValue)
            }
        }
        Spacer(Modifier.height(20.dp))
    }
}
