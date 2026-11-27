package com.ghostlock.honorfne.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

   
           
  
                                        
  
                                             
                                             
                             
  
                                                
                                                     
                                  
   
@Composable
fun ManagerPickerDialog(
    entries: List<ManagerEntry>,
    selectedPkg: String,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(24.dp))
                .background(MiuixTheme.colorScheme.surfaceContainer)
                .padding(vertical = 18.dp)
        ) {
            Column {
                Text(
                    text = "选择 Root 管理器",
                    modifier = Modifier.padding(horizontal = 20.dp),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = MiuixTheme.colorScheme.onSurface
                )
                Text(
                    text = "本 APK 内置的 kernelsu.ko 只认 KernelSU 官方签名；" +
                        "第三方分支需要配它自己的模块，提权本身不受影响。",
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp),
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 380.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    entries.forEach { entry ->
                        ManagerRow(
                            entry = entry,
                            selected = entry.pkg == selectedPkg,
                            onSelect = { onSelect(entry.pkg) }
                        )
                    }
                }

                Spacer(Modifier.height(6.dp))
                Text(
                    text = "取消",
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(onClick = onDismiss)
                        .padding(vertical = 12.dp),
                    fontSize = 15.sp,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            }
        }
    }
}

@Composable
private fun ManagerRow(
    entry: ManagerEntry,
    selected: Boolean,
    onSelect: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = entry.label,
                modifier = Modifier.weight(1f),
                fontSize = 15.sp,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface
            )
            if (selected) {
                Text(
                    text = "当前",
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.primary
                )
                Spacer(Modifier.width(10.dp))
            }
            SecondaryAction(text = "选用", onClick = onSelect)
        }

        Spacer(Modifier.height(3.dp))
        val detail = buildString {
            append(entry.pkg)
            if (entry.version.isNotBlank()) append(" · ").append(entry.version)
            append(if (entry.bundledKo) " · 内置模块可用" else " · 需自带模块")
        }
        Text(
            text = detail,
            fontSize = 11.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary
        )
    }
}
