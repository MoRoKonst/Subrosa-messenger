package com.subrosa.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Settings icon + dialog for pointing this client at a self-hosted server.
 *  Ported to a full multi-server list (mirrors Android's ServersScreen)
 *  instead of the old single-field dialog — no functional/security reason
 *  to differ, just an earlier minimal-effort placeholder. Deliberately
 *  narrower than Android: no auto-federation/switch-on-failure (Desktop's
 *  WebSocketClient only ever holds one live connection and retries the SAME
 *  url with backoff, see scheduleReconnect()), no QR scan/discovered-peers
 *  (no camera-capture flow here). Placed on both LoginScreen and
 *  RegisterScreen since the server has to be reachable before either login
 *  or registration can succeed. Selecting an entry writes "server_url"/
 *  "server_access_code" (ServerManager.selectServer()) — the same keys
 *  WebSocketClient.doConnect()/doConnectAnonChannel() already read fresh
 *  on every connect() attempt, so no extra wiring is needed there. */
@Composable
fun ServerSettingsButton() {
    var showDialog by remember { mutableStateOf(false) }

    IconButton(onClick = { showDialog = true }) {
        Icon(AppIcons.get("SETTINGS"), contentDescription = "Сервер", tint = SubrosaTheme.textSecondary)
    }

    if (showDialog) {
        ServerSettingsDialog(onDismiss = { showDialog = false })
    }
}

@Composable
fun ServerSettingsDialog(onDismiss: () -> Unit) {
    var servers by remember { mutableStateOf(ServerManager.getServers()) }
    var currentIndex by remember { mutableStateOf(ServerManager.getCurrentIndex()) }
    var showAddDialog by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SubrosaTheme.dialog,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Text("Сервер", modifier = Modifier.weight(1f))
                IconButton(onClick = { showAddDialog = true }) {
                    Icon(AppIcons.get("PLUS"), contentDescription = "Добавить", tint = SubrosaTheme.accent)
                }
            }
        },
        text = {
            Column {
                Text(
                    "Нажми на сервер, чтобы сделать его активным. Изменения применятся при следующем подключении.",
                    fontSize = 14.sp,
                    color = SubrosaTheme.textSecondary
                )
                Spacer(Modifier.height(8.dp))
                LazyColumn(modifier = Modifier.heightIn(max = 320.dp)) {
                    itemsIndexed(servers) { index, server ->
                        val isActive = index == currentIndex
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                                .clickable {
                                    ServerManager.selectServer(index)
                                    currentIndex = index
                                }
                                .background(
                                    if (isActive) SubrosaTheme.fieldBorder else Color.Transparent,
                                    androidx.compose.foundation.shape.RoundedCornerShape(8.dp)
                                )
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            if (isActive) {
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .background(Color(0xFF3FB950), androidx.compose.foundation.shape.CircleShape)
                                )
                                Spacer(Modifier.width(8.dp))
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    server.name.ifEmpty { "Сервер ${index + 1}" },
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 16.sp,
                                    color = SubrosaTheme.textPrimary
                                )
                                Text(
                                    server.toWssUrl(),
                                    fontSize = 14.sp,
                                    color = SubrosaTheme.textSecondary
                                )
                            }
                            IconButton(onClick = {
                                ServerManager.removeServer(index)
                                servers = ServerManager.getServers()
                                currentIndex = ServerManager.getCurrentIndex()
                            }) {
                                Icon(AppIcons.get("DELETE"), contentDescription = "Удалить", tint = SubrosaTheme.error)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Готово") }
        }
    )

    if (showAddDialog) {
        AddServerDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { host, port, name, code ->
                ServerManager.addServer(ServerManager.Server(host = host, port = port, name = name, accessCode = code))
                servers = ServerManager.getServers()
                showAddDialog = false
            }
        )
    }
}

@Composable
private fun AddServerDialog(
    onDismiss: () -> Unit,
    onAdd: (host: String, port: Int, name: String, accessCode: String?) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var address by remember { mutableStateOf("") }
    var accessCode by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SubrosaTheme.dialog,
        title = { Text("Добавить сервер") },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название (необязательно)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = profileFieldColors()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = address,
                    onValueChange = { address = it },
                    label = { Text("Адрес") },
                    placeholder = { Text("myserver.com:8443  или  wss://myserver.com:8443/ws") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = profileFieldColors()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = accessCode,
                    onValueChange = { accessCode = it },
                    label = { Text("Код доступа (если есть)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = profileFieldColors()
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = address.isNotBlank(),
                onClick = {
                    val (host, port) = parseServerAddress(address.trim())
                    if (host.isNotEmpty()) {
                        onAdd(host, port, name.trim(), accessCode.trim().takeIf { it.isNotBlank() })
                    }
                }
            ) { Text("Добавить", color = SubrosaTheme.accent) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена", color = SubrosaTheme.textSecondary) }
        }
    )
}

/** Accepts a bare host ("myserver.com"), host:port ("myserver.com:8443"),
 *  or a full "wss://myserver.com:8443/path" URL. Defaults to port 8443
 *  when none is given, matching the default server entries above. Mirrors
 *  Android's ServersScreen.kt parseServerAddress(). */
private fun parseServerAddress(input: String): Pair<String, Int> {
    if (input.isEmpty()) return "" to 8443
    return try {
        if (input.contains("://")) {
            input to 8443
        } else {
            val parts = input.split(":")
            if (parts.size == 2) parts[0] to (parts[1].toIntOrNull() ?: 8443)
            else input to 8443
        }
    } catch (e: Exception) {
        input to 8443
    }
}
