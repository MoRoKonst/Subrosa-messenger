package com.subrosa.messenger

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
import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.RequestPermission
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.delay

private val AppFont = FontFamily(Font(R.font.jetbrainsmono_regular))

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServersScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    var servers by remember { mutableStateOf(ServerManager.getServers(context)) }
    var fixedMode by remember { mutableStateOf(ServerManager.isFixedMode(context)) }
    var coverMode by remember { mutableStateOf(UserStorage.getCoverTrafficMode(context)) }
    var pendingCoverMode by remember { mutableStateOf<UserStorage.CoverTrafficMode?>(null) }
    var showCoverWarning by remember { mutableStateOf(false) }
    var showAddDialog by remember { mutableStateOf(false) }
    // One field instead of three: "myserver.com", "myserver.com:9000", or a
    // full "wss://myserver.com:9000/path" all work — parsed on confirm below.
    // Port only needs typing when it isn't the 9000 default.
    var newAddress by remember { mutableStateOf("") }
    var newName by remember { mutableStateOf("") }
    var addDialogError by remember { mutableStateOf("") }

    fun addServerFromQr(payload: String?) {
        if (payload == null) return
        val server = parseServerQrPayload(payload)
        if (server == null) {
            addDialogError = s.serversQrInvalid
            return
        }
        ServerManager.addServer(context, server)
        servers = ServerManager.getServers(context)
        showAddDialog = false
        newAddress = ""
        newName = ""
        addDialogError = ""
    }

    val scanServerQrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val scanned = result.contents
        if (scanned == null) return@rememberLauncherForActivityResult // user cancelled, not an error
        addServerFromQr(scanned)
    }

    val cameraPermLauncherForServer = rememberLauncherForActivityResult(RequestPermission()) { granted ->
        if (granted) {
            scanServerQrLauncher.launch(ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt(s.serversScanQrPrompt)
                setBeepEnabled(false)
            })
        } else {
            addDialogError = s.profileCameraPermReq
        }
    }

    val pickQrImageLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val bitmap = try {
            val stream = context.contentResolver.openInputStream(uri)
            stream?.use { android.graphics.BitmapFactory.decodeStream(it) }
        } catch (e: Exception) {
            null
        }
        val decoded = bitmap?.let { decodeQrFromBitmap(it) }
        if (decoded == null) {
            addDialogError = s.serversQrNotFound
        } else {
            addServerFromQr(decoded)
        }
    }

    var isReallyConnected by remember { mutableStateOf(MessengerService.connected) }
    var currentServer by remember { mutableStateOf(ServerManager.getCurrentServer(context)) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(500)
            isReallyConnected = MessengerService.connected
            servers = ServerManager.getServers(context)
            currentServer = ServerManager.getCurrentServer(context)
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

                    TextButton(onClick = {
                        val next = when (coverMode) {
                            UserStorage.CoverTrafficMode.OFF -> UserStorage.CoverTrafficMode.MODERATE
                            UserStorage.CoverTrafficMode.MODERATE -> UserStorage.CoverTrafficMode.AGGRESSIVE
                            UserStorage.CoverTrafficMode.AGGRESSIVE -> UserStorage.CoverTrafficMode.OFF
                        }
                        if (coverMode == UserStorage.CoverTrafficMode.OFF) {

                            pendingCoverMode = next
                            showCoverWarning = true
                        } else {
                            coverMode = next
                            UserStorage.setCoverTrafficMode(context, next)
                            context.startService(android.content.Intent(context, MessengerService::class.java)
                                .putExtra("reload_cover_traffic", true))
                        }
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

                Button(
                    onClick = {
                        ServerManager.switchToNext(context)
                        servers = ServerManager.getServers(context)
                        currentServer = ServerManager.getCurrentServer(context)

                        context.stopService(android.content.Intent(context, MessengerService::class.java))
                        context.startForegroundService(android.content.Intent(context, MessengerService::class.java))

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
                        val isActive = currentServer?.host == server.host && currentServer?.port == server.port

                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .clickable {

                                    val prefs = EncryptedStorage.getEncryptedPrefs(context, "server_prefs")
                                    val enabledServers = servers.filter { it.enabled }
                                    val targetIndex = enabledServers.indexOfFirst {
                                        it.host == server.host && it.port == server.port
                                    }
                                    if (targetIndex != -1) {
                                        prefs.edit().putInt("current_server", targetIndex).apply()

                                        context.stopService(android.content.Intent(context, MessengerService::class.java))
                                        context.startForegroundService(android.content.Intent(context, MessengerService::class.java))

                                        MainActivity.chatListVersion.value = System.currentTimeMillis()

                                        servers = ServerManager.getServers(context)
                                        currentServer = ServerManager.getCurrentServer(context)
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

    if (showCoverWarning) {
        val mode = pendingCoverMode ?: UserStorage.CoverTrafficMode.MODERATE
        AlertDialog(
            onDismissRequest = { showCoverWarning = false },
            containerColor = c.dialog,
            title = { Text("⚠️ Постоянный трафик", color = c.textPrimary, fontFamily = AppFont) },
            text = {
                Text(
                    "Режим \"${if (mode == UserStorage.CoverTrafficMode.MODERATE) "Умеренный" else "Агрессивный"}\" создаёт непрерывный поток пакетов.\n\n" +
                    "• Умеренный: ~1 пакет / 5 сек ≈ 2–3 МБ/час\n" +
                    "• Агрессивный: ~1 пакет / сек ≈ 20–30 МБ/час\n\n" +
                    "Это повысит расход трафика и батареи даже когда вы не отправляете сообщений. Включать рекомендуется только при высоком уровне угрозы.",
                    color = c.textPrimary.copy(alpha = 0.85f),
                    fontFamily = AppFont,
                    fontSize = 14.sp
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val next = pendingCoverMode ?: return@TextButton
                    coverMode = next
                    UserStorage.setCoverTrafficMode(context, next)
                    context.startService(android.content.Intent(context, MessengerService::class.java)
                        .putExtra("reload_cover_traffic", true))
                    showCoverWarning = false
                }) { Text("Включить", color = c.accent, fontFamily = AppFont, fontWeight = FontWeight.Bold) }
            },
            dismissButton = {
                TextButton(onClick = { showCoverWarning = false }) {
                    Text("Отмена", color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }

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
                        value = newAddress,
                        onValueChange = { newAddress = it },
                        label = { Text(s.serversHost, fontFamily = AppFont) },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("192.168.1.6  or  myserver.com:9000", fontFamily = AppFont) },
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

                    Spacer(modifier = Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            addDialogError = ""
                            val granted = ContextCompat.checkSelfPermission(
                                context, Manifest.permission.CAMERA
                            ) == PackageManager.PERMISSION_GRANTED
                            if (granted) {
                                scanServerQrLauncher.launch(ScanOptions().apply {
                                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    setPrompt(s.serversScanQrPrompt)
                                    setBeepEnabled(false)
                                })
                            } else {
                                cameraPermLauncherForServer.launch(Manifest.permission.CAMERA)
                            }
                        }) { Text(s.serversScanQrButton, color = c.accent, fontFamily = AppFont, fontSize = 12.sp) }

                        OutlinedButton(onClick = {
                            addDialogError = ""
                            pickQrImageLauncher.launch("image/*")
                        }) { Text(s.serversUploadQrButton, color = c.accent, fontFamily = AppFont, fontSize = 12.sp) }
                    }

                    if (addDialogError.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(addDialogError, color = c.error, fontFamily = AppFont, fontSize = 12.sp)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val (parsedHost, parsedPort) = parseServerAddress(newAddress)
                    if (parsedHost.isNotEmpty()) {
                        ServerManager.addServer(
                            context,
                            ServerManager.Server(
                                host = parsedHost,
                                port = parsedPort,
                                name = newName
                            )
                        )
                        servers = ServerManager.getServers(context)
                        showAddDialog = false
                        newAddress = ""
                        newName = ""
                        addDialogError = ""
                    }
                }) { Text(s.add, color = c.accent, fontFamily = AppFont) }
            },
            dismissButton = {
                TextButton(onClick = { showAddDialog = false; addDialogError = "" }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = AppFont)
                }
            }
        )
    }
}

/** Turns whatever the user typed into (host, port) — accepts a bare host
 *  ("myserver.com"), host:port ("myserver.com:9000"), or a full URL
 *  ("wss://myserver.com:9000"). Defaults to port 9000 when none is given,
 *  matching every default server entry elsewhere in this file. Reduces the
 *  "add server" dialog from three fields (host, port, name) to two (address,
 *  optional name) — the port rarely needs to be anything other than 9000. */
/** Parses a scanned/uploaded server QR payload — `subrosa://server?host=...
 *  &port=...&code=...&name=...`, `code`/`name` optional. Returns null if the
 *  text isn't a recognizable Subrosa server link at all, so the caller can
 *  show a clear "not a valid code" error instead of silently doing nothing.
 *  See docs/ISSUE_backup_identity_hijack.md, "server-side allowlist" — `code`
 *  is only meaningful for a server running SERVER_ACCESS_PROTECTED; a plain
 *  link without one just carries the address, same as typing it manually. */
private fun parseServerQrPayload(text: String): ServerManager.Server? {
    return try {
        val uri = android.net.Uri.parse(text.trim())
        if (uri.scheme != "subrosa" || uri.host != "server") return null
        val host = uri.getQueryParameter("host")?.takeIf { it.isNotBlank() } ?: return null
        val port = uri.getQueryParameter("port")?.toIntOrNull() ?: 9000
        val code = uri.getQueryParameter("code")?.takeIf { it.isNotBlank() }
        val name = uri.getQueryParameter("name") ?: ""
        ServerManager.Server(host = host, port = port, name = name, accessCode = code)
    } catch (e: Exception) {
        null
    }
}

/** Decodes a QR code from an already-loaded bitmap (uploaded image file, not
 *  live camera) — for the case where the person only has a phone and the QR
 *  arrived as a picture (chat, email) rather than something to point a
 *  camera at. Returns null if no QR is found in the image at all. */
private fun decodeQrFromBitmap(bitmap: android.graphics.Bitmap): String? {
    return try {
        val width = bitmap.width
        val height = bitmap.height
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
        val source = com.google.zxing.RGBLuminanceSource(width, height, pixels)
        val binaryBitmap = com.google.zxing.BinaryBitmap(com.google.zxing.common.HybridBinarizer(source))
        com.google.zxing.MultiFormatReader().decode(binaryBitmap).text
    } catch (e: Exception) {
        null
    }
}

private fun parseServerAddress(input: String): Pair<String, Int> {
    val trimmed = input.trim()
    if (trimmed.isEmpty()) return "" to 9000
    return try {
        if (trimmed.contains("://")) {
            val uri = android.net.Uri.parse(trimmed)
            val host = uri.host ?: trimmed
            val port = if (uri.port != -1) uri.port else 9000
            host to port
        } else {
            val parts = trimmed.split(":")
            if (parts.size == 2) {
                parts[0] to (parts[1].toIntOrNull() ?: 9000)
            } else {
                trimmed to 9000
            }
        }
    } catch (e: Exception) {
        trimmed to 9000
    }
}
