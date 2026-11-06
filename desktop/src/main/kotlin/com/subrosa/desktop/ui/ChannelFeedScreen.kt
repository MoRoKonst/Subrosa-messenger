package com.subrosa.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.*
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun ChannelFeedScreen(channelId: String, onBack: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var channel by remember { mutableStateOf(ChannelManager.getChannel(channelId)) }
    val posts = remember { mutableStateListOf<ChannelPost>() }
    var input by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    var showMenu by remember { mutableStateOf(false) }
    var showLinkDialog by remember { mutableStateOf(false) }
    var showUnsubscribeConfirm by remember { mutableStateOf(false) }

    LaunchedEffect(channelId) {
        posts.clear()
        posts.addAll(ChannelManager.loadPosts(channelId))

        WebSocketClient.onChannelPostReceived = { cId, post ->
            if (cId == channelId) {
                val idx = posts.indexOfFirst { it.id == post.id }
                if (idx >= 0) posts[idx] = post else posts.add(post)
            }
        }
        WebSocketClient.onChannelPostDeleted = { cId, postId ->
            if (cId == channelId) posts.removeIf { it.id == postId }
        }
    }

    LaunchedEffect(posts.size) {
        if (posts.isNotEmpty()) listState.animateScrollToItem(posts.size - 1)
    }

    Column(Modifier.fillMaxSize()) {

        // ── Top bar ──────────────────────────────────────────────────────────
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(AppIcons.get("BACK_ARROW"), contentDescription = "Назад",
                        tint = SubrosaTheme.textPrimary)
                }
                val avatar = channel?.avatar
                if (avatar != null) {
                    Text(avatar, fontSize = 22.sp)
                } else {
                    Icon(AppIcons.get("HUMAN_AVATAR_PLACEHOLDER"), contentDescription = null,
                        modifier = Modifier.size(20.dp), tint = SubrosaTheme.textSecondary)
                }
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(channel?.name ?: "Канал", fontSize = 19.sp, fontWeight = FontWeight.SemiBold,
                        color = SubrosaTheme.textPrimary)
                    if (!channel?.description.isNullOrBlank()) {
                        Text(channel!!.description, fontSize = 14.sp, color = SubrosaTheme.textSecondary, maxLines = 1)
                    }
                }
                Box {
                    IconButton(onClick = { showMenu = true }) {
                        Icon(AppIcons.get("MENU"), contentDescription = "Меню", tint = SubrosaTheme.textPrimary)
                    }
                    DropdownMenu(
                        expanded = showMenu,
                        onDismissRequest = { showMenu = false },
                        containerColor = SubrosaTheme.card
                    ) {
                        if (channel?.isAdmin == true) {
                            DropdownMenuItem(
                                text = { Text("Ссылка для подписки", color = SubrosaTheme.textPrimary) },
                                onClick = { showMenu = false; showLinkDialog = true }
                            )
                        } else {
                            DropdownMenuItem(
                                text = { Text("Отписаться", color = SubrosaTheme.error) },
                                onClick = { showMenu = false; showUnsubscribeConfirm = true }
                            )
                        }
                    }
                }
            }
        }

        // ── Post feed ─────────────────────────────────────────────────────────
        if (posts.isEmpty()) {
            Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                Text("Пока нет постов", color = SubrosaTheme.textSecondary.copy(alpha = 0.5f))
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f).padding(horizontal = 8.dp),
                state = listState
            ) {
                items(posts, key = { it.id }) { post ->
                    ChannelPostBubble(post, isPinned = channel?.pinnedPostId == post.id)
                    Spacer(Modifier.height(6.dp))
                }
            }
        }

        // ── Admin post box ───────────────────────────────────────────────────
        if (channel?.isAdmin == true) {
            HorizontalDivider(color = SubrosaTheme.divider, thickness = 0.5.dp)
            Surface(color = SubrosaTheme.inputBg) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.Bottom
                ) {
                    OutlinedTextField(
                        value = input,
                        onValueChange = { input = it },
                        modifier = Modifier.weight(1f).onPreviewKeyEvent { event ->
                            if (input.isNotBlank() && event.type == KeyEventType.KeyDown &&
                                event.key == Key.Enter && !event.isShiftPressed) {
                                WebSocketClient.postToChannel(channelId, input.trim())
                                input = ""
                                true
                            } else false
                        },
                        placeholder = { Text("Новый пост…", color = SubrosaTheme.textSecondary.copy(alpha = 0.5f)) },
                        maxLines = 6,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor   = SubrosaTheme.fieldBorder,
                            unfocusedBorderColor = SubrosaTheme.divider,
                            focusedTextColor     = SubrosaTheme.textPrimary,
                            unfocusedTextColor   = SubrosaTheme.textPrimary,
                            cursorColor          = SubrosaTheme.accent,
                        )
                    )
                    Spacer(Modifier.width(6.dp))
                    IconButton(
                        onClick = {
                            WebSocketClient.postToChannel(channelId, input.trim())
                            input = ""
                        },
                        enabled = input.isNotBlank(),
                        modifier = Modifier.padding(bottom = 4.dp)
                    ) {
                        Icon(AppIcons.get("Send"), contentDescription = "Опубликовать",
                            tint = if (input.isNotBlank()) SubrosaTheme.accent
                                   else SubrosaTheme.textSecondary.copy(alpha = 0.4f))
                    }
                }
            }
        }
    }

    // ── Subscribe link dialog (admin) ───────────────────────────────────────
    if (showLinkDialog && channel != null) {
        val link = remember(channel) {
            ChannelManager.generateSubscribeLink(channel!!.id, channel!!.name, channel!!.avatar)
        }
        var copied by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { showLinkDialog = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Ссылка для подписки", color = SubrosaTheme.textPrimary) },
            text = {
                Surface(shape = MaterialTheme.shapes.small, color = SubrosaTheme.card, modifier = Modifier.fillMaxWidth()) {
                    Text(link, fontSize = 12.sp, modifier = Modifier.padding(10.dp), color = SubrosaTheme.textSecondary)
                }
            },
            confirmButton = {
                Button(onClick = { clipboard.setText(AnnotatedString(link)); copied = true }) {
                    Text(if (copied) "Скопировано!" else "Копировать")
                }
            },
            dismissButton = {
                TextButton(onClick = { showLinkDialog = false }) { Text("Закрыть", color = SubrosaTheme.textSecondary) }
            }
        )
    }

    // ── Unsubscribe confirm ──────────────────────────────────────────────────
    if (showUnsubscribeConfirm) {
        AlertDialog(
            onDismissRequest = { showUnsubscribeConfirm = false },
            containerColor = SubrosaTheme.dialog,
            title = { Text("Отписаться от канала?", color = SubrosaTheme.textPrimary) },
            confirmButton = {
                TextButton(onClick = {
                    WebSocketClient.unsubscribeFromChannel(channelId)
                    ChannelManager.removeChannel(channelId)
                    showUnsubscribeConfirm = false
                    onBack()
                }) { Text("Отписаться", color = SubrosaTheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showUnsubscribeConfirm = false }) {
                    Text("Отмена", color = SubrosaTheme.textSecondary)
                }
            }
        )
    }
}

@Composable
private fun ChannelPostBubble(post: ChannelPost, isPinned: Boolean) {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = SubrosaTheme.bubbleOther,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            if (isPinned) {
                Text("Закреплено", fontSize = 12.sp, color = SubrosaTheme.accent, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
            }
            Text(post.text, fontSize = 16.sp, color = SubrosaTheme.textPrimary)
            Spacer(Modifier.height(6.dp))
            Text(
                SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(Date(post.timestamp)),
                fontSize = 12.sp, color = SubrosaTheme.textSecondary
            )
        }
    }
}
