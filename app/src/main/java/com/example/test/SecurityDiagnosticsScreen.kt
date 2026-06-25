package com.bcon.messenger

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import com.bcon.messenger.ui.theme.BeaconColors
import com.bcon.messenger.ui.theme.LocalBeaconColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityDiagnosticsScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val scope = rememberCoroutineScope()

    val testLines = remember { mutableStateListOf<String>() }
    val listState = rememberLazyListState()
    var isRunning by remember { mutableStateOf(false) }
    var hasRunOnce by remember { mutableStateOf(false) }
    var showParanoidConfirm by remember { mutableStateOf(false) }

    val lastIdsResult by ParanoidMode.lastIdsResult.collectAsState()
    var isIdsRunning by remember { mutableStateOf(false) }
    var alertUrl by remember { mutableStateOf(UserStorage.getAlertUrl(context)) }

    // Auto-scroll terminal to bottom on new line
    LaunchedEffect(testLines.size) {
        if (testLines.isNotEmpty()) {
            listState.animateScrollToItem(testLines.size - 1)
        }
    }

    // Blinking cursor animation
    val infiniteTransition = rememberInfiniteTransition(label = "cursor")
    val cursorAlpha by infiniteTransition.animateFloat(
        initialValue = 0.15f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(480), RepeatMode.Reverse),
        label = "cursorAlpha"
    )

    // Only show: test headers, result lines (✅/❌/⚠), summary notes
    fun shouldShow(line: String): Boolean {
        val t = line.trim()
        return t.isEmpty() ||
            '✅' in t || '❌' in t || '⚠' in t ||
            t.startsWith("📋") ||
            t.startsWith("🔐") || t.startsWith("💣") || t.startsWith("🔬") || t.startsWith("📊") ||
            (t.length > 4 && t.all { it == '═' || it == ' ' }) ||
            "Если видишь" in t || "Покрыто:" in t
    }

    // Streams a test suite line by line with a small visual delay
    fun runSuite(block: (onLine: (String) -> Unit) -> Unit) {
        if (isRunning) return
        isRunning = true
        hasRunOnce = true
        testLines.clear()
        scope.launch {
            val ch = Channel<String>(Channel.UNLIMITED)
            launch(Dispatchers.IO) {
                block { line -> ch.trySend(line) }
                ch.close()
            }
            for (line in ch) {
                if (shouldShow(line)) {
                    testLines.add(line)
                    delay(14)
                }
            }
            isRunning = false
        }
    }

    // ── Paranoid mode confirm dialog ───────────────────────────────────────────
    if (showParanoidConfirm) {
        AlertDialog(
            onDismissRequest = { showParanoidConfirm = false },
            title = { Text(s.paranoidModeConfirmTitle, fontWeight = FontWeight.Bold, color = Color(0xFFFF6B6B)) },
            text = { Text(s.paranoidModeConfirmText, fontSize = 13.sp, lineHeight = 19.sp, color = c.textPrimary) },
            confirmButton = {
                Button(
                    onClick = { showParanoidConfirm = false; ParanoidMode.setEnabled(context, true) },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935))
                ) { Text(s.paranoidModeConfirmBtn, color = Color.White) }
            },
            dismissButton = {
                TextButton(onClick = { showParanoidConfirm = false }) { Text(s.cancel, color = c.textPrimary) }
            },
            containerColor = c.card
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.diagTitle, fontSize = 18.sp, color = Color.White) },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd)))
                .padding(padding)
        ) {
            // ── Controls ───────────────────────────────────────────────────────
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                // Paranoid Mode row
                val paranoid by ParanoidMode.flow.collectAsState()
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (paranoid) Color(0xFF2D0A0A) else c.card
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(
                                s.paranoidModeTitle,
                                fontWeight = FontWeight.Bold,
                                color = if (paranoid) Color(0xFFFF6B6B) else c.textPrimary,
                                fontSize = 14.sp
                            )
                            Text(
                                s.paranoidModeSub,
                                fontSize = 11.sp,
                                color = if (paranoid) Color(0xFFCC8888) else c.textPrimary.copy(alpha = 0.6f),
                                lineHeight = 14.sp
                            )
                        }
                        if (paranoid) {
                            Surface(color = Color(0x33FF0000), shape = MaterialTheme.shapes.small) {
                                Text(
                                    s.paranoidModeActive,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                    color = Color(0xFFFF6B6B),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        } else {
                            Switch(
                                checked = false,
                                onCheckedChange = { if (it) showParanoidConfirm = true },
                                colors = SwitchDefaults.colors(
                                    uncheckedThumbColor = Color.White,
                                    uncheckedTrackColor = c.cardAlt
                                )
                            )
                        }
                    }
                }

                // IDS row
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (lastIdsResult?.isCritical() == true) Color(0xFF2D1A00) else c.card
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(s.idsTitle, fontWeight = FontWeight.Bold, color = c.textPrimary, fontSize = 14.sp)
                            if (lastIdsResult == null) {
                                Text("—", fontSize = 11.sp, color = c.textPrimary.copy(alpha = 0.4f))
                            } else if (lastIdsResult!!.isEmpty()) {
                                Text(s.idsClean, fontSize = 11.sp, color = Color(0xFF66BB6A))
                            } else {
                                Text(
                                    s.idsThreatFound + ": " + lastIdsResult!!.threats.joinToString(", ") { it.label },
                                    fontSize = 11.sp, color = Color(0xFFFF9800), lineHeight = 14.sp
                                )
                            }
                        }
                        Button(
                            onClick = {
                                isIdsRunning = true
                                scope.launch(Dispatchers.IO) {
                                    val result = IntrusionDetector.scan(context)
                                    ParanoidMode.updateIdsResult(result)
                                    isIdsRunning = false
                                }
                            },
                            enabled = !isIdsRunning,
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = c.primaryBlue, contentColor = Color.White)
                        ) {
                            Text(if (isIdsRunning) "..." else s.idsScanBtn, fontSize = 13.sp)
                        }
                    }
                }

                // Alert URL compact row
                Card(colors = CardDefaults.cardColors(containerColor = c.card)) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = alertUrl,
                            onValueChange = { alertUrl = it },
                            placeholder = { Text(s.alertUrlHint, fontSize = 11.sp) },
                            label = { Text(s.alertUrlLabel, fontSize = 11.sp) },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontSize = 12.sp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = c.primaryBlue,
                                unfocusedBorderColor = c.cardAlt,
                                focusedTextColor = c.textPrimary,
                                unfocusedTextColor = c.textPrimary,
                                cursorColor = c.primaryBlue,
                                focusedLabelColor = c.primaryBlue,
                                unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f)
                            )
                        )
                        FilledTonalButton(
                            onClick = { UserStorage.setAlertUrl(context, alertUrl.trim()) },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) { Text(s.alertUrlSave, fontSize = 12.sp) }
                    }
                }

                // 3 test buttons
                Button(
                    onClick = { runSuite { cb -> CryptoManager.runSecurityDiagnostics(context, cb) } },
                    enabled = !isRunning,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = c.primaryBlue, contentColor = Color.White)
                ) { Text(if (isRunning) s.diagRunning else s.diagBasic, fontSize = 14.sp) }

                Button(
                    onClick = { runSuite { cb -> CryptoManager.runStressTests(context, cb) } },
                    enabled = !isRunning,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFCC3333), contentColor = Color.White)
                ) { Text(if (isRunning) s.diagRunning else s.diagStress, fontSize = 14.sp) }

                Button(
                    onClick = { runSuite { cb -> CryptoManager.runAdvancedTests(context, cb) } },
                    enabled = !isRunning,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1B5E20), contentColor = Color.White)
                ) { Text(if (isRunning) s.diagRunning else s.diagAdvanced, fontSize = 14.sp) }
            }

            // ── Terminal output ────────────────────────────────────────────────
            Surface(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp)
                    .padding(bottom = 12.dp),
                color = Color(0xFF0A0E1A),
                shape = MaterialTheme.shapes.medium
            ) {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(vertical = 6.dp)
                ) {
                    if (!hasRunOnce) {
                        item {
                            Text(
                                text = s.diagInitText,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                color = Color(0xFF4A5568)
                            )
                        }
                    } else {
                        itemsIndexed(testLines) { _, line ->
                            TestLine(line, c)
                        }
                        if (isRunning) {
                            item {
                                Text(
                                    text = "▊",
                                    modifier = Modifier.padding(start = 12.dp, top = 2.dp),
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 13.sp,
                                    color = Color(0xFF00E5FF).copy(alpha = cursorAlpha)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun TestLine(line: String, c: BeaconColors) {
    val t = line.trimEnd()

    if (t.isEmpty()) {
        Spacer(Modifier.height(3.dp))
        return
    }

    val isSep = t.length > 6 && t.all { it == '═' || it == ' ' }
    val isTitle = t.startsWith("🔐") || t.startsWith("💣") || t.startsWith("🔬") ||
            t.startsWith("📊")
    val isTestHeader = t.startsWith("📋")
    val isOk  = '✅' in t
    val isFail = '❌' in t
    val isWarn = '⚠' in t
    val isInfo = 'ℹ' in t

    val color = when {
        isOk   -> Color(0xFF66BB6A)
        isFail -> Color(0xFFEF5350)
        isWarn -> Color(0xFFFFA726)
        isInfo -> Color(0xFF64B5F6)
        isTestHeader -> Color(0xFF00E5FF)
        isTitle      -> Color(0xFFE0E6FF)
        isSep        -> Color(0xFF1E2A4A)
        else         -> Color(0xFF8899BB)
    }

    val weight = when {
        isTitle || isTestHeader || isOk || isFail -> FontWeight.SemiBold
        else -> FontWeight.Normal
    }

    val size = when {
        isTitle -> 12.sp
        isTestHeader -> 12.sp
        isSep -> 9.sp
        else -> 11.sp
    }

    Text(
        text = t,
        color = color,
        fontFamily = FontFamily.Monospace,
        fontSize = size,
        fontWeight = weight,
        lineHeight = 15.sp,
        modifier = Modifier.padding(horizontal = 12.dp, vertical = if (isTestHeader) 3.dp else 1.dp)
    )
}
