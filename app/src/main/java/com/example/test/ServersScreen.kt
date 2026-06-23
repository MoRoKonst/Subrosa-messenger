package com.bcon.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.clickable
import com.bcon.messenger.ui.theme.LocalBeaconColors
import kotlinx.coroutines.delay

private val AppFont = FontFamily(Font(R.font.jetbrainsmono_regular))

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServersScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var servers by remember { mutableStateOf(ServerManager.getServers(context)) }
    var fixedMode by remember { mutableStateOf(ServerManager.isFixedMode(context)) }
    var coverMode by remember { mutableStateOf(UserStorage.getCoverTrafficMode(context)) }
    var showAddDialog by remember { mutableStateOf(false) }
    var newHost by remember { mutableStateOf("") }
    var newPort by remember { mutableStateOf("9000") }
    var newName by remember { mutableStateOf("") }
    // Реальное состояние WebSocket-подключения, обновляется каждые 500 мс
    var isReallyConnected by remember { mutableStateOf(MessengerService.connected) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(500)
            isReallyConnected = MessengerService.connected
            servers = ServerManager.getServers(context)
        }
    }

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = { Text(s.serversTitle, color = c.textPrimary, fontFamily = AppFont) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, s.back, tint = c.textPrimary)
                    }
                },
                actions = {
                    IconButton(onClick = { showAddDialog = true }) {
                        Icon(Icons.Default.Add, s.serversAdd, tint = c.accent)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                // Режим сервера
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            if (fixedMode) "Фиксированный сервер" else "Авто (федерация)",
                            color = c.textPrimary,
                            fontFamily = AppFont,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp
                        )
                        Text(
                            if (fixedMode) "Только первый сервер в списке" else "Автопереключение между пирами",
                            color = c.textPrimary.copy(alpha = 0.6f),
                            fontFamily = AppFont,
                            fontSize = 12.sp
                        )
                    }
                    Switch(
                        checked = fixedMode,
                        onCheckedChange = { value ->
                            fixedMode = value
                            ServerManager.setFixedMode(context, value)
                        },
                        colors = SwitchDefaults.colors(checkedThumbColor = c.accent, checkedTrackColor = c.accent.copy(alpha = 0.4f))
                    )
                }

                HorizontalDivider(color = c.textPrimary.copy(alpha = 0.1f), modifier = Modifier.padding(horizontal = 16.dp))

                // Постоянный поток трафика
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "Постоянный трафик",
                            color = c.textPrimary,
                            fontFamily = AppFont,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp
                        )
                        Text(
                            when (coverMode) {
                                UserStorage.CoverTrafficMode.OFF -> "Выключен"
                                UserStorage.CoverTrafficMode.MODERATE -> "Умеренный (пакет каждые 5 сек)"
                                UserStorage.CoverTrafficMode.AGGRESSIVE -> "Агрессивный (пакет каждую сек)"
                            },
                            color = c.textPrimary.copy(alpha = 0.6f),
                            fontFamily = AppFont,
                            fontSize = 12.sp
                        )
                    }
                    // Три состояния: OFF → MODERATE → AGGRESSIVE → OFF
                    TextButton(onClick = {
                        val next = when (coverMode) {
                            UserStorage.CoverTrafficMode.OFF -> UserStorage.CoverTrafficMode.MODERATE
                            UserStorage.CoverTrafficMode.MODERATE -> UserStorage.CoverTrafficMode.AGGRESSIVE
                            UserStorage.CoverTrafficMode.AGGRESSIVE -> UserStorage.CoverTrafficMode.OFF
                        }
                        coverMode = next
                        UserStorage.setCoverTrafficMode(context, next)
                        // Перезапускаем сервис чтобы применить новый режим
                        context.stopService(android.content.Intent(context, MessengerService::class.java))
                        context.startForegroundService(android.content.Intent(context, MessengerService::class.java))
                    }) {
                        Text(
                            when (coverMode) {
                                UserStorage.CoverTrafficMode.OFF -> "Вкл"
                                UserStorage.CoverTrafficMode.MODERATE -> "Агресс."
                                UserStorage.CoverTrafficMode.AGGRESSIVE -> "Выкл"
                            },
                            color = c.accent,
                            fontFamily = AppFont,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                HorizontalDivider(color = c.textPrimary.copy(alpha = 0.1f), modifier = Modifier.padding(horizontal = 16.dp))
                Spacer(modifier = Modifier.height(4.dp))

                // Кнопка переключения сервера
                Button(
                    onClick = {
                        ServerManager.switchToNext(context)
                        servers = ServerManager.getServers(context)

                        // Перезапускаем сервис для переподключения
                        context.stopService(android.content.Intent(context, MessengerService::class.java))
                        context.startForegroundService(android.content.Intent(context, MessengerService::class.java))

                        // Принудительно обновить список чатов при возврате
                        MainActivity.chatListVersion.value = System.currentTimeMillis()

                        android.widget.Toast.makeText(
                            context,
                            s.serversSwitching,
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = c.primaryBlue)
                ) {
                    Text(s.serversSwitch, fontFamily = AppFont)
                }

                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp)
                ) {
                    itemsIndexed(servers) { index, server ->
                        val currentServer = ServerManager.getCurrentServer(context)
                        val isActive = currentServer?.host == server.host && currentServer.port == server.port

                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .clickable {
                                    // Клик по серверу - переключиться на него
                                    val prefs = EncryptedStorage.getEncryptedPrefs(context, "server_prefs")
                                    val enabledServers = servers.filter { it.enabled }
                                    val targetIndex = enabledServers.indexOfFirst {
                                        it.host == server.host && it.port == server.port
                                    }
                                    if (targetIndex != -1) {
                                        prefs.edit().putInt("current_server", targetIndex).apply()

                                        // Перезапуск сервиса
                                        context.stopService(android.content.Intent(context, MessengerService::class.java))
                                        context.startForegroundService(android.content.Intent(context, MessengerService::class.java))

                                        // Принудительно обновить список чатов при возврате
                                        MainActivity.chatListVersion.value = System.currentTimeMillis()

                                        servers = ServerManager.getServers(context)
                                    }
                                },
                            colors = CardDefaults.cardColors(
                                containerColor = if (isActive) c.fieldBorder else c.card
                            )
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (isActive) Text(
                                    if (isReallyConnected) "🟢 " else "🟡 ",
                                    fontSize = 16.sp
                                )

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        server.name.ifEmpty { s.serversDefault(index + 1) },
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 16.sp,
                                        color = c.textPrimary,
                                        fontFamily = AppFont
                                    )
                                    Text(
                                        server.toWssUrl(),
                                        fontSize = 14.sp,
                                        color = c.textPrimary.copy(alpha = 0.6f),
                                        fontFamily = AppFont
                                    )
                                    if (isActive) {
                                        Text(
                                            if (isReallyConnected) s.serversConnected else s.serversConnecting,
                                            fontSize = 12.sp,
                                            color = if (isReallyConnected) c.accent else Color(0xFFFFAA00),
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = AppFont
                                        )
                                    }
                                }
                                IconButton(onClick = {
                                    ServerManager.removeServer(context, index)
                                    servers = ServerManager.getServers(context)
                                }) {
                                    Icon(Icons.Default.Delete, s.delete, tint = c.error)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Диалог остаётся без изменений...
    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = { showAddDialog = false },
            containerColor = c.dialog,
            title = { Text(s.serversAddTitle, color = c.textPrimary, fontFamily = AppFont) },
            text = {
                Column {
                    OutlinedTextField(
                        value = newName,
                        onValueChange = { newName = it },
                        label = { Text(s.serversName, fontFamily = AppFont) },
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = newHost,
                        onValueChange = { newHost = it },
                        label = { Text(s.serversHost, fontFamily = AppFont) },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("192.168.1.6", fontFamily = AppFont) },
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = newPort,
                        onValueChange = { newPort = it },
                        label = { Text(s.serversPort, fontFamily = AppFont) },
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = c.textPrimary,
                            unfocusedTextColor = c.textPrimary,
                            cursorColor = c.accent
                        )
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (newHost.isNotEmpty()) {
                        ServerManager.addServer(
                            context,
                            ServerManager.Server(
                                host = newHost,
                                port = newPort.toIntOrNull() ?: 9000,
                                name = newName
                            )
                        )
                        servers = ServerManager.getServers(context)
                        showAddDialog = false
                        newHost = ""
                        newPort = "9000"
                        newName = ""
                    }
                }) { Text(s.add, color = c.accent, fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showAddDialog = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }
}
