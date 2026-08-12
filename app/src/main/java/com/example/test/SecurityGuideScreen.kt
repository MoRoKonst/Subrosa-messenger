package com.subrosa.messenger

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.subrosa.messenger.ui.theme.LocalSubrosaColors

private data class GuideItem(val title: String, val desc: String)

/** Expandable-card reference for every protection feature in the app —
 * requested live after a user pushed back on the invite code's one-time-use
 * behavior being non-obvious ("чтобы он не пытался сразу группе людей один
 * код дать"). Collapsed by default; tapping a card expands just that one,
 * others stay closed — reading ten paragraphs at once defeats the purpose
 * of a quick-reference guide. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityGuideScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    val items = remember {
        listOf(
            GuideItem(s.guideInviteTitle, s.guideInviteDesc),
            GuideItem(s.guideKeyVerifyTitle, s.guideKeyVerifyDesc),
            GuideItem(s.guideTotpTitle, s.guideTotpDesc),
            GuideItem(s.guidePanicTitle, s.guidePanicDesc),
            GuideItem(s.guideEmergencyTitle, s.guideEmergencyDesc),
            GuideItem(s.guideAutoLockTitle, s.guideAutoLockDesc),
            GuideItem(s.guideBackupTitle, s.guideBackupDesc),
            GuideItem(s.guideTorTitle, s.guideTorDesc),
            GuideItem(s.guideCoverTitle, s.guideCoverDesc),
            GuideItem(s.guideParanoidTitle, s.guideParanoidDesc),
            GuideItem(s.guideDmsTitle, s.guideDmsDesc),
            GuideItem(s.guideTimeoutWipeTitle, s.guideTimeoutWipeDesc),
            GuideItem(s.guidePanicButtonTitle, s.guidePanicButtonDesc),
            GuideItem(s.guideWipeLevelsTitle, s.guideWipeLevelsDesc),
            GuideItem(s.guideSelfHealTitle, s.guideSelfHealDesc),
            GuideItem(s.guideCompromisedTitle, s.guideCompromisedDesc)
        )
    }
    var expandedIndex by remember { mutableStateOf<Int?>(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.guideTitle, fontWeight = FontWeight.Bold, fontSize = 18.sp, color = Color.White) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, s.back, tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(items.size) { index ->
                    val item = items[index]
                    val expanded = expandedIndex == index
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .animateContentSize(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = c.card)
                    ) {
                        Column {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { expandedIndex = if (expanded) null else index }
                                    .padding(horizontal = 16.dp, vertical = 14.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    item.title,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = c.textPrimary,
                                    modifier = Modifier.weight(1f)
                                )
                                Text(
                                    if (expanded) "▲" else "▼",
                                    fontSize = 11.sp,
                                    color = c.textPrimary.copy(alpha = 0.4f)
                                )
                            }
                            AnimatedVisibility(
                                visible = expanded,
                                enter = expandVertically() + fadeIn(),
                                exit = shrinkVertically() + fadeOut()
                            ) {
                                Text(
                                    item.desc,
                                    fontSize = 13.sp,
                                    lineHeight = 19.sp,
                                    color = c.textPrimary.copy(alpha = 0.8f),
                                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
