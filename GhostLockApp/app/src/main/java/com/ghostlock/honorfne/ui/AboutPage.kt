package com.ghostlock.honorfne.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

   
                                            
                                              
   
@Composable
fun rememberAppLogo(): ImageBitmap {
    val context = LocalContext.current
    return remember(context) {
        val id = context.resources.getIdentifier("hr_logo", "drawable", context.packageName)
        val bmp = if (id != 0) {
            android.graphics.BitmapFactory.decodeResource(context.resources, id)
        } else {
            null
        }
        
        bmp?.asImageBitmap() ?: ImageBitmap(1, 1)
    }
}

   
       
  
                          
                                     
   
@Composable
fun AboutPage(
    state: UiState,
    onAuthor: () -> Unit,
    onSponsor: () -> Unit,
    onCopyQq: () -> Unit,
    onOpenGithub: () -> Unit
) {
    val scroll = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 16.dp)
    ) {
        Spacer(Modifier.height(26.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            
            
            Image(
                bitmap = rememberAppLogo(),
                contentDescription = "HonorRoot",
                modifier = Modifier
                    .size(60.dp)
                    .clip(RoundedCornerShape(16.dp))
            )
            Spacer(Modifier.size(14.dp))
            Column {
                Text(
                    text = "HonorRoot",
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = MiuixTheme.colorScheme.onSurface
                )
                Text(
                    text = state.aboutVersion.ifBlank { "临时 Root 工具" },
                    modifier = Modifier.padding(top = 3.dp),
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            }
        }

        SectionTitle("信息")
        GroupCard {
            InfoRow("作者", state.aboutAuthor)
            GroupDivider()
            ClickableInfoRow(
                label = "QQ",
                value = state.aboutQq,
                onClick = onCopyQq
            )
            GroupDivider()
            ClickableInfoRow(
                label = "GitHub",
                value = state.aboutGithub,
                onClick = onOpenGithub
            )
        }

        Spacer(Modifier.height(18.dp))
        SecondaryAction(
            text = "联系作者",
            onClick = onAuthor,
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
