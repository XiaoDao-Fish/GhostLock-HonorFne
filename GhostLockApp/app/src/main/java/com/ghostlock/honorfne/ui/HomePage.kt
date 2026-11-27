package com.ghostlock.honorfne.ui

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
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

   
      
  
                
                                     
                                       
                              
                         
  
                                                
                                      
   
@Composable
fun HomePage(
    state: UiState,
    live: LiveState,
    onConnect: () -> Unit,
    onKsuTap: () -> Unit,
    onSponsor: () -> Unit
) {
    val scroll = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 18.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = state.homeTitle,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = MiuixTheme.colorScheme.onSurface
            )
            if (state.homeVersion.isNotBlank()) {
                Text(
                    text = state.homeVersion,
                    modifier = Modifier.padding(start = 8.dp),
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            }
        }

        Spacer(Modifier.height(22.dp))
        LiveText(
            live = live,
            selector = { it.clock },
            style = TextStyle(
                fontSize = 54.sp,
                fontWeight = FontWeight.Light,
                fontFeatureSettings = "tnum"
            ),
            color = MiuixTheme.colorScheme.onSurface
        )
        LiveText(
            live = live,
            selector = { it.dateLine },
            modifier = Modifier.padding(top = 2.dp),
            fontSize = 13.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary
        )
        LiveText(
            live = live,
            selector = { it.greeting },
            modifier = Modifier.padding(top = 14.dp),
            fontSize = 16.sp,
            fontWeight = FontWeight.Medium,
            color = MiuixTheme.colorScheme.onSurface
        )

        Spacer(Modifier.height(20.dp))
        StatusLine(text = state.rootState, tone = state.rootStateTone)

        SectionTitle("设备")
        GroupCard {
            InfoRow("机型", state.deviceModel.ifBlank { "未知" })
            GroupDivider()
            InfoRow("内核", state.kernel.ifBlank { "未读取" })
            GroupDivider()
            ClickableInfoRow(
                label = "Shizuku",
                value = state.shizuku.ifBlank { "未连接" },
                onClick = onConnect
            )
            GroupDivider()
            ClickableInfoRow(
                label = "KernelSU",
                value = state.ksuVersion.ifBlank { "未检测" },
                onClick = onKsuTap
            )
        }

        Spacer(Modifier.height(18.dp))
        SecondaryAction(
            text = "赞助这个项目",
            onClick = onSponsor,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(96.dp))
    }
}
