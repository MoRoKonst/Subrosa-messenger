package com.bcon.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bcon.messenger.ui.theme.BeaconColors
import com.bcon.messenger.ui.theme.LocalBeaconColors
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WipeSettingsScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    // ── DMS state ─────────────────────────────────────────────────────────────
    var dmsEnabled by remember { mutableStateOf(DeadMansSwitchManager.isEnabled(context)) }
    var dmsIntervalHours by remember { mutableIntStateOf(DeadMansSwitchManager.getIntervalHours(context)) }
    var dmsRemaining by remember { mutableLongStateOf(DeadMansSwitchManager.getTimeRemainingMs(context)) }

    // Обновляем таймер каждые 60 секунд пока DMS включён
    LaunchedEffect(dmsEnabled, dmsIntervalHours) {
        while (dmsEnabled) {
            dmsRemaining = DeadMansSwitchManager.getTimeRemainingMs(context)
            delay(60_000L)
        }
    }

    // ── Timeout wipe state ────────────────────────────────────────────────────
    var timeoutEnabled by remember { mutableStateOf(UserStorage.getTimeoutWipeHours(context) > 0) }
    var timeoutHours by remember { mutableIntStateOf(
        UserStorage.getTimeoutWipeHours(context).takeIf { it > 0 } ?: 24
    )}

    // ── Panic button state ────────────────────────────────────────────────────
    var panicButtonEnabled by remember { mutableStateOf(UserStorage.getPanicButtonEnabled(context)) }
    var panicButtonDecoy   by remember { mutableStateOf(UserStorage.getPanicButtonDecoy(context)) }

    // ── Calculator disguise state ──────────────────────────────────────────────
    var calcDisguise by remember { mutableStateOf(UserStorage.getCalculatorDisguise(context)) }

    // ── Wipe on breach state ──────────────────────────────────────────────────
    var wipeOnBreach by remember { mutableStateOf(UserStorage.getWipeOnBreach(context)) }
    var breachLevel by remember { mutableStateOf(
        runCatching { WipeManager.Level.valueOf(UserStorage.getBreachWipeLevel(context)) }
            .getOrDefault(WipeManager.Level.HARD)
    )}

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(s.wipeSettingsTitle, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = s.back)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = c.textPrimary,
                    navigationIconContentColor = c.textPrimary
                )
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .background(bgGradient)
        ) {
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // ── Warning card ───────────────────────────────────────────────
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0x33FF6B6B)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        s.wipeSettingsWarning,
                        modifier = Modifier.padding(12.dp),
                        fontSize = 12.sp,
                        lineHeight = 17.sp,
                        color = Color(0xFFFF8A80)
                    )
                }

                // ── Wipe levels description ────────────────────────────────────
                SectionHeader("Уровни уничтожения", c.textPrimary.copy(alpha = 0.6f))
                WipeLevelCard(
                    title = s.wipeLevelSoft,
                    desc = s.wipeSoftDesc,
                    color = Color(0xFF66BB6A),
                    c = c
                )
                WipeLevelCard(
                    title = s.wipeLevelHard,
                    desc = s.wipeHardDesc,
                    color = Color(0xFFFFA726),
                    c = c
                )
                WipeLevelCard(
                    title = s.wipeLevelNuclear,
                    desc = s.wipeNuclearDesc,
                    color = Color(0xFFEF5350),
                    c = c
                )

                Spacer(Modifier.height(4.dp))

                // ── Dead Man's Switch ──────────────────────────────────────────
                SectionHeader(s.dmsTitle, c.textPrimary.copy(alpha = 0.6f))
                Card(
                    colors = CardDefaults.cardColors(containerColor = c.card),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(s.dmsSubtitle, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f), lineHeight = 17.sp)

                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(s.dmsEnabledLabel, color = c.textPrimary, fontSize = 14.sp)
                            Switch(
                                checked = dmsEnabled,
                                onCheckedChange = { enabled ->
                                    dmsEnabled = enabled
                                    if (enabled) {
                                        DeadMansSwitchManager.enable(context, dmsIntervalHours)
                                    } else {
                                        DeadMansSwitchManager.disable(context)
                                    }
                                }
                            )
                        }

                        if (dmsEnabled) {
                            Text(s.dmsIntervalLabel, color = c.textPrimary.copy(alpha = 0.6f), fontSize = 13.sp)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                listOf(2, 5, 12, 24, 48, 72).forEach { h ->
                                    FilterChip(
                                        selected = dmsIntervalHours == h,
                                        onClick = {
                                            dmsIntervalHours = h
                                            DeadMansSwitchManager.enable(context, h)
                                            dmsRemaining = DeadMansSwitchManager.getTimeRemainingMs(context)
                                        },
                                        label = { Text("$h ${s.dmsIntervalHours}") }
                                    )
                                }
                            }

                            if (dmsRemaining > 0) {
                                val hours = dmsRemaining / 3_600_000
                                val minutes = (dmsRemaining % 3_600_000) / 60_000
                                Text(
                                    "Осталось: ${hours}ч ${minutes}м",
                                    fontSize = 12.sp,
                                    color = Color(0xFF66BB6A)
                                )
                            }

                            Button(
                                onClick = {
                                    DeadMansSwitchManager.checkIn(context)
                                    dmsRemaining = DeadMansSwitchManager.getTimeRemainingMs(context)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF388E3C)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(s.dmsCheckinBtn, color = Color.White)
                            }
                        }
                    }
                }

                // ── Password timeout wipe ──────────────────────────────────────
                SectionHeader(s.timeoutWipeTitle, c.textPrimary.copy(alpha = 0.6f))
                Card(
                    colors = CardDefaults.cardColors(containerColor = c.card),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(s.timeoutWipeSubtitle, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f), lineHeight = 17.sp)

                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(s.timeoutWipeTitle, color = c.textPrimary, fontSize = 14.sp)
                            Switch(
                                checked = timeoutEnabled,
                                onCheckedChange = { enabled ->
                                    timeoutEnabled = enabled
                                    UserStorage.setTimeoutWipeHours(context, if (enabled) timeoutHours else 0)
                                }
                            )
                        }

                        if (timeoutEnabled) {
                            Text("Уничтожить если нет входа более:", color = c.textPrimary.copy(alpha = 0.6f), fontSize = 13.sp)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                listOf(24, 48, 72).forEach { h ->
                                    FilterChip(
                                        selected = timeoutHours == h,
                                        onClick = {
                                            timeoutHours = h
                                            UserStorage.setTimeoutWipeHours(context, h)
                                        },
                                        label = { Text("$h ${s.dmsIntervalHours}") }
                                    )
                                }
                            }
                        }
                    }
                }

                // ── Wipe on breach ─────────────────────────────────────────────
                SectionHeader(s.wipeOnBreachTitle, c.textPrimary.copy(alpha = 0.6f))
                Card(
                    colors = CardDefaults.cardColors(containerColor = c.card),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(s.wipeOnBreachSubtitle, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f), lineHeight = 17.sp)

                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(s.wipeOnBreachTitle, color = c.textPrimary, fontSize = 14.sp)
                            Switch(
                                checked = wipeOnBreach,
                                onCheckedChange = { enabled ->
                                    wipeOnBreach = enabled
                                    UserStorage.setWipeOnBreach(context, enabled)
                                }
                            )
                        }

                        if (wipeOnBreach) {
                            Text(s.wipeLevelLabel, color = c.textPrimary.copy(alpha = 0.6f), fontSize = 13.sp)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                listOf(
                                    WipeManager.Level.HARD to s.wipeLevelHard,
                                    WipeManager.Level.NUCLEAR to s.wipeLevelNuclear
                                ).forEach { (level, label) ->
                                    FilterChip(
                                        selected = breachLevel == level,
                                        onClick = {
                                            breachLevel = level
                                            UserStorage.setBreachWipeLevel(context, level.name)
                                        },
                                        label = { Text(label, fontSize = 12.sp) }
                                    )
                                }
                            }
                        }
                    }
                }

                // ── Panic button ───────────────────────────────────────────────
                SectionHeader(s.panicButtonLabel, c.textPrimary.copy(alpha = 0.6f))
                Card(
                    colors = CardDefaults.cardColors(containerColor = c.card),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(s.panicButtonSubtitle, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f), lineHeight = 17.sp)

                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(s.panicButtonLabel, color = c.textPrimary, fontSize = 14.sp)
                            Switch(
                                checked = panicButtonEnabled,
                                onCheckedChange = { enabled ->
                                    panicButtonEnabled = enabled
                                    UserStorage.setPanicButtonEnabled(context, enabled)
                                    if (enabled) PanicNotificationManager.show(context)
                                    else PanicNotificationManager.dismiss(context)
                                }
                            )
                        }

                        if (panicButtonEnabled) {
                            HorizontalDivider(color = c.textPrimary.copy(alpha = 0.1f))
                            Text(s.panicButtonDecoySubtitle, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f), lineHeight = 17.sp)
                            Row(
                                Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(s.panicButtonDecoyLabel, color = c.textPrimary, fontSize = 14.sp)
                                Switch(
                                    checked = panicButtonDecoy,
                                    onCheckedChange = { enabled ->
                                        panicButtonDecoy = enabled
                                        UserStorage.setPanicButtonDecoy(context, enabled)
                                    }
                                )
                            }
                        }
                    }
                }

                // ── Calculator disguise ────────────────────────────────────────
                SectionHeader(s.calcDisguiseLabel, c.textPrimary.copy(alpha = 0.6f))
                Card(
                    colors = CardDefaults.cardColors(containerColor = c.card),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(s.calcDisguiseSubtitle, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f), lineHeight = 17.sp)
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(s.calcDisguiseLabel, color = c.textPrimary, fontSize = 14.sp)
                            Switch(
                                checked = calcDisguise,
                                onCheckedChange = { enabled ->
                                    calcDisguise = enabled
                                    UserStorage.setCalculatorDisguise(context, enabled)
                                }
                            )
                        }
                    }
                }

                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String, color: Color) {
    Text(
        title.uppercase(),
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        color = color,
        letterSpacing = 1.sp,
        modifier = Modifier.padding(top = 4.dp, bottom = 2.dp)
    )
}

@Composable
private fun WipeLevelCard(
    title: String,
    desc: String,
    color: Color,
    c: BeaconColors
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = c.card),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                Modifier
                    .size(8.dp)
                    .background(color, shape = RoundedCornerShape(50))
            )
            Column {
                Text(title, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = c.textPrimary)
                Text(desc, fontSize = 12.sp, color = c.textPrimary.copy(alpha = 0.6f))
            }
        }
    }
}
