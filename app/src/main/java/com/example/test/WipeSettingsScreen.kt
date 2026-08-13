package com.subrosa.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
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
import com.subrosa.messenger.ui.theme.SubrosaColors
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WipeSettingsScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    var dmsEnabled by remember { mutableStateOf(DeadMansSwitchManager.isEnabled(context)) }
    var dmsIntervalMinutes by remember { mutableIntStateOf(DeadMansSwitchManager.getIntervalMinutes(context)) }
    var dmsRemaining by remember { mutableLongStateOf(DeadMansSwitchManager.getTimeRemainingMs(context)) }

    LaunchedEffect(dmsEnabled, dmsIntervalMinutes) {
        while (dmsEnabled) {
            dmsRemaining = DeadMansSwitchManager.getTimeRemainingMs(context)
            delay(60_000L)
        }
    }

    var timeoutEnabled by remember { mutableStateOf(UserStorage.getTimeoutWipeHours(context) > 0) }
    var timeoutHours by remember { mutableIntStateOf(
        UserStorage.getTimeoutWipeHours(context).takeIf { it > 0 } ?: 24
    )}

    var panicButtonEnabled by remember { mutableStateOf(UserStorage.getPanicButtonEnabled(context)) }
    var panicButtonDecoy   by remember { mutableStateOf(UserStorage.getPanicButtonDecoy(context)) }

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

                SectionHeader(s.guideWipeLevelsTitle, c.textPrimary.copy(alpha = 0.6f))
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
                                        DeadMansSwitchManager.enableMinutes(context, dmsIntervalMinutes)
                                    } else {
                                        DeadMansSwitchManager.disable(context)
                                    }
                                }
                            )
                        }

                        if (dmsEnabled) {
                            Text(s.dmsIntervalLabel, color = c.textPrimary.copy(alpha = 0.6f), fontSize = 13.sp)
                            // Sub-hour tiers (15/30 min) added for high-threat scenarios where
                            // a 2-hour check-in is too loose — see docs/ISSUE_backup_identity_hijack.md.
                            // Scrollable since 9 chips no longer fit one screen width.
                            Row(
                                modifier = Modifier.horizontalScroll(rememberScrollState()),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                listOf(15, 30, 60, 120, 300, 720, 1440, 2880, 4320).forEach { m ->
                                    val label = if (m < 60) "$m ${s.dmsIntervalMinutes}" else "${m / 60} ${s.dmsIntervalHours}"
                                    FilterChip(
                                        selected = dmsIntervalMinutes == m,
                                        onClick = {
                                            dmsIntervalMinutes = m
                                            DeadMansSwitchManager.enableMinutes(context, m)
                                            dmsRemaining = DeadMansSwitchManager.getTimeRemainingMs(context)
                                        },
                                        label = { Text(label) }
                                    )
                                }
                            }

                            if (dmsRemaining > 0) {
                                val hours = dmsRemaining / 3_600_000
                                val minutes = (dmsRemaining % 3_600_000) / 60_000
                                Text(
                                    s.dmsRemainingText(hours, minutes),
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
                            Text(s.timeoutWipeThresholdLabel, color = c.textPrimary.copy(alpha = 0.6f), fontSize = 13.sp)
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

                // Calculator-disguise toggle intentionally hidden from the public build:
                // it was built for a specific custom deployment that never shipped, and
                // its unlock code is a hardcoded equation (not user-configurable), which
                // is fine for a one-off private deployment but not a real protection in
                // a general-audience app. The underlying mechanism (UserStorage.get/setCalculatorDisguise,
                // CalculatorScreen.kt, MainActivity routing) is left in place for a future
                // deployment where the unlock code is made user-configurable.

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
    c: SubrosaColors
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
