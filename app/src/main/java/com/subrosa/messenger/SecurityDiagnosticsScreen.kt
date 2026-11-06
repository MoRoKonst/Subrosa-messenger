package com.subrosa.messenger

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
import com.subrosa.messenger.ui.theme.SubrosaColors
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import androidx.compose.ui.res.painterResource

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityDiagnosticsScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val scope = rememberCoroutineScope()

    val testLines = remember { mutableStateListOf<String>() }
    val listState = rememberLazyListState()
    var isRunning by remember { mutableStateOf(false) }
    var hasRunOnce by remember { mutableStateOf(false) }
    var showParanoidConfirm by remember { mutableStateOf(false) }

    val lastIdsResult by ParanoidMode.lastIdsResult.collectAsState()
    var isIdsRunning by remember { mutableStateOf(false) }
    var alertUrl by remember { mutableStateOf(UserStorage.getAlertUrl(context)) }
    var alertUrlError by remember { mutableStateOf(false) }
    var alertTestStatus by remember { mutableStateOf<Boolean?>(null) }
    var isTestingAlert by remember { mutableStateOf(false) }

    LaunchedEffect(testLines.size) {
        if (testLines.isNotEmpty()) {
            listState.animateScrollToItem(testLines.size - 1)
        }
    }

    val infiniteTransition = rememberInfiniteTransition(label = "cursor")
    val cursorAlpha by infiniteTransition.animateFloat(
        initialValue = 0.15f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(480), RepeatMode.Reverse),
        label = "cursorAlpha"
    )

    fun shouldShow(line: String): Boolean {
        return true
    }

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

    if (showParanoidConfirm) {
        AlertDialog(
            onDismissRequest = { showParanoidConfirm = false },
            title = { Text(s.paranoidModeConfirmTitle, fontWeight = FontWeight.Bold, color = Color(0xFFFF6B6B)) },
            text = { Text(s.paranoidModeConfirmText, fontSize = 15.sp, lineHeight = 19.sp, color = c.textPrimary) },
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
                title = { Text(s.diagTitle, fontSize = 20.sp, color = c.textPrimary) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_back_arrow), s.back, tint = c.textPrimary)
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

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {

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
                                fontSize = 16.sp
                            )
                            Text(
                                s.paranoidModeSub,
                                fontSize = 13.sp,
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
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        } else {
                            Switch(
                                checked = false,
                                onCheckedChange = { if (it) showParanoidConfirm = true },
                                colors = SwitchDefaults.colors(
                                    uncheckedThumbColor = c.textPrimary,
                                    uncheckedTrackColor = c.cardAlt
                                )
                            )
                        }
                    }
                }

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
                            Text(s.idsTitle, fontWeight = FontWeight.Bold, color = c.textPrimary, fontSize = 16.sp)
                            if (lastIdsResult == null) {
                                Text("—", fontSize = 13.sp, color = c.textPrimary.copy(alpha = 0.4f))
                            } else if (lastIdsResult!!.isEmpty()) {
                                Text(s.idsClean, fontSize = 13.sp, color = Color(0xFF66BB6A))
                            } else {
                                Text(
                                    s.idsThreatFound + ": " + lastIdsResult!!.threats.joinToString(", ") { it.label },
                                    fontSize = 13.sp, color = Color(0xFFFF9800), lineHeight = 14.sp
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
                            colors = ButtonDefaults.buttonColors(containerColor = c.primaryBlue, contentColor = if (c.isDark) Color.White else c.textPrimary)
                        ) {
                            Text(if (isIdsRunning) "..." else s.idsScanBtn, fontSize = 15.sp)
                        }
                    }
                }

                Card(colors = CardDefaults.cardColors(containerColor = c.card)) {
                    Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedTextField(
                                value = alertUrl,
                                onValueChange = { alertUrl = it; alertUrlError = false; alertTestStatus = null },
                                placeholder = { Text(s.alertUrlHint, fontSize = 13.sp) },
                                label = { Text(s.alertUrlLabel, fontSize = 13.sp) },
                                isError = alertUrlError,
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                textStyle = LocalTextStyle.current.copy(fontSize = 14.sp),
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
                                onClick = {
                                    val trimmed = alertUrl.trim()
                                    if (ParanoidMode.isValidAlertUrl(trimmed)) {
                                        alertUrlError = false
                                        alertTestStatus = null
                                        UserStorage.setAlertUrl(context, trimmed)
                                    } else {
                                        alertUrlError = true
                                    }
                                },
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                            ) { Text(s.alertUrlSave, fontSize = 14.sp) }
                            FilledTonalButton(
                                onClick = {
                                    val trimmed = alertUrl.trim()
                                    if (trimmed.isBlank() || !ParanoidMode.isValidAlertUrl(trimmed)) {
                                        alertUrlError = true
                                        return@FilledTonalButton
                                    }
                                    alertUrlError = false
                                    isTestingAlert = true
                                    alertTestStatus = null
                                    scope.launch {
                                        alertTestStatus = ParanoidMode.testAlert(context, trimmed)
                                        isTestingAlert = false
                                    }
                                },
                                enabled = !isTestingAlert,
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                            ) { Text(if (isTestingAlert) "..." else s.alertUrlTestBtn, fontSize = 14.sp) }
                        }
                        if (alertUrlError) {
                            Text(s.alertUrlInvalid, fontSize = 12.sp, color = c.error, modifier = Modifier.padding(top = 4.dp))
                        }
                        alertTestStatus?.let { ok ->
                            Text(
                                if (ok) s.alertUrlTestOk else s.alertUrlTestFail,
                                fontSize = 12.sp,
                                color = if (ok) Color(0xFF66BB6A) else c.error,
                                modifier = Modifier.padding(top = 4.dp)
                            )
                        }
                    }
                }

                // Merged from three separate buttons (basic/stress/advanced) into
                // one — they always ran the same crypto layer end-to-end anyway,
                // just at different depths; splitting them only made the user
                // press three buttons in a row for one full check. Runs all three
                // suites in sequence into the same output.
                Button(
                    onClick = {
                        runSuite { cb ->
                            CryptoManager.runSecurityDiagnostics(context, cb)
                            CryptoManager.runStressTests(context, cb)
                            CryptoManager.runAdvancedTests(context, cb)
                        }
                    },
                    enabled = !isRunning,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = c.primaryBlue, contentColor = if (c.isDark) Color.White else c.textPrimary)
                ) { Text(if (isRunning) s.diagRunning else s.diagBasic, fontSize = 16.sp) }
            }

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
                                fontSize = 14.sp,
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
                                    fontSize = 15.sp,
                                    color = Color(0xFFD9A566).copy(alpha = cursorAlpha)
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
private fun TestLine(line: String, c: SubrosaColors) {
    val t = line.trimEnd()

    if (t.isEmpty()) {
        Spacer(Modifier.height(3.dp))
        return
    }

    val isSep = t.length > 6 && t.all { it == '═' || it == ' ' }
    val isTestHeader = t.startsWith("ТЕСТ ") || t.startsWith("НЕГАТИВНЫЙ ТЕСТ ") ||
            t.startsWith("TEST ") || t.startsWith("NEGATIVE TEST ")
    val isTitle = !isTestHeader
    val isOk  = "[OK]" in t
    val isFail = "[FAIL]" in t
    val isWarn = "[WARN]" in t
    val isInfo = 'ℹ' in t

    val color = when {
        isOk   -> Color(0xFF66BB6A)
        isFail -> Color(0xFFEF5350)
        isWarn -> Color(0xFFFFA726)
        isInfo -> Color(0xFF64B5F6)
        isTestHeader -> Color(0xFFD9A566)
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
