package com.subrosa.messenger

import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.launch
import kotlin.math.absoluteValue

/**
 * Duress mode. What the device shows when the panic password, the stealth
 * trigger or the calculator disguise says the person holding it is not the
 * owner.
 *
 * The design rule here is that this file contains no UI of its own. Every row,
 * every bubble, every piece of chrome is the *same composable* the real screens
 * use — ContactCard, MessageBubble, ChatsTopBar, ChatsEmptyState,
 * ChatActionsDialog, MuteDurationDialog, PortholeSendButton,
 * CombinedMediaButton. Only the data differs (DecoyData).
 *
 * That is a deliberate reversal. The previous version was a parallel
 * implementation, and it had drifted into something you could pick out without
 * opening a conversation: list rows with no timestamp and no unread badge,
 * bubbles with no clock and a permanently "delivered" double tick, the title in
 * the wrong typeface with no connection dot, no search button, and every string
 * hardcoded in English while the rest of the app ran in Russian. Each of those
 * was individually a one-line fix and collectively a dead giveaway — which is
 * the argument for not having a second implementation at all.
 *
 * Known remaining differences, listed rather than quietly left for someone to
 * find: the profile avatar, the "+" create button, the attach button, the two
 * call buttons and the message long-press menu are inert here. Reaching parity
 * on those means either replicating ProfileScreen/GroupChatScreen (85KB and
 * 74KB respectively) or letting duress mode reach real code that places calls
 * and touches real storage. Neither belongs in this pass.
 */
@Composable
fun DecoyScreen() {
    val context = LocalContext.current

    DisposableEffect(Unit) {
        var pressCount = 0
        var firstPressMs = 0L
        val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                val now = System.currentTimeMillis()
                if (now - firstPressMs > 3000L) {
                    pressCount = 1
                    firstPressMs = now
                } else {
                    pressCount++
                    if (pressCount >= 5) {
                        pressCount = 0
                        (context as? MainActivity)?.emergencyWipe(withDecoy = true)
                    }
                }
            }
        }
        context.contentResolver.registerContentObserver(
            Settings.System.CONTENT_URI, true, observer
        )
        onDispose { context.contentResolver.unregisterContentObserver(observer) }
    }

    // Bumped whenever the decoy dataset is mutated (a send, a delete) so the
    // regenerated threads are picked up — DecoyData itself is the source of
    // truth and persists, there is no separate in-memory message list to keep
    // in sync.
    var version by remember { mutableIntStateOf(0) }
    val threads = remember(version) { DecoyData.threads(context) }

    var openedId by remember { mutableStateOf<String?>(null) }
    val opened = threads.firstOrNull { it.id == openedId }

    BackHandler(enabled = opened != null) { openedId = null }

    if (opened != null) {
        DecoyChatScreen(
            thread = opened,
            onBack = { openedId = null },
            onSend = { text ->
                DecoyData.appendSent(context, opened.id, text)
                version++
            }
        )
    } else {
        DecoyListScreen(
            threads = threads,
            onOpenChat = { openedId = it.id },
            onChanged = { version++ }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DecoyListScreen(
    threads: List<DecoyData.DecoyThread>,
    onOpenChat: (DecoyData.DecoyThread) -> Unit,
    onChanged: () -> Unit
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    var searchMode by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var actionsTarget by remember { mutableStateOf<DecoyData.DecoyThread?>(null) }
    var muteTarget by remember { mutableStateOf<DecoyData.DecoyThread?>(null) }
    var deleteTarget by remember { mutableStateOf<DecoyData.DecoyThread?>(null) }
    var mutedIds by remember { mutableStateOf(setOf<String>()) }

    fun computeMutedIds(items: List<DecoyData.DecoyThread>): Set<String> {
        val now = System.currentTimeMillis()
        return items.filter { UserStorage.getContactMuteUntil(context, it.id) > now }
            .map { it.id }.toSet()
    }
    LaunchedEffect(threads) { mutedIds = computeMutedIds(threads) }

    if (searchMode) {
        BackHandler { searchMode = false; searchQuery = "" }
    }

    // Same two-level search as the real list: a name match keeps the row's
    // normal preview, a match found only inside the message text swaps the
    // preview for the matching snippet.
    fun matchingSnippet(t: DecoyData.DecoyThread): String? {
        if (searchQuery.isBlank()) return null
        return t.messages.firstOrNull { it.text.contains(searchQuery, ignoreCase = true) }?.text
    }
    val displayed = remember(threads, searchQuery) {
        if (searchQuery.isBlank()) threads
        else threads.filter { t ->
            t.name.contains(searchQuery, ignoreCase = true) ||
                t.messages.any { it.text.contains(searchQuery, ignoreCase = true) }
        }
    }

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            ChatsTopBar(
                searchMode = searchMode,
                searchQuery = searchQuery,
                onSearchQueryChange = { searchQuery = it },
                onToggleSearch = {
                    searchMode = !searchMode
                    if (!searchMode) searchQuery = ""
                },
                onOpenProfile = {},
                onCreate = {}
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            if (threads.isEmpty()) {
                ChatsEmptyState(title = s.chatsEmpty, hint = s.chatsEmptyHint)
            } else if (searchQuery.isNotBlank() && displayed.isEmpty()) {
                ChatsEmptyState(title = s.chatsSearchNoResults)
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(top = 8.dp, bottom = 80.dp)
                ) {
                    items(displayed, key = { it.id }) { thread ->
                        Column(
                            modifier = Modifier.animateItem(
                                fadeInSpec = tween(250),
                                fadeOutSpec = tween(180)
                            )
                        ) {
                            ContactCard(
                                userId = thread.id,
                                name = thread.name,
                                lastMessage = matchingSnippet(thread)
                                    ?: thread.lastMessage.ifEmpty { s.chatsNoMessages },
                                unreadCount = thread.unreadCount,
                                lastTimestamp = thread.lastTimestamp,
                                isMuted = thread.id in mutedIds,
                                onClick = { onOpenChat(thread) },
                                onLongClick = { actionsTarget = thread }
                            )
                            HorizontalDivider(
                                modifier = Modifier.padding(start = 82.dp),
                                color = c.textPrimary.copy(alpha = 0.07f),
                                thickness = 0.5.dp
                            )
                        }
                    }
                }
            }
        }
    }

    actionsTarget?.let { target ->
        ChatActionsDialog(
            onDismiss = { actionsTarget = null },
            onMute = { actionsTarget = null; muteTarget = target },
            // Contact info would mean replicating ContactInfoScreen's verified
            // key / fingerprint surface, which has nothing truthful to show
            // here. Left closing the sheet rather than opening a screen that
            // would contradict itself.
            onInfo = { actionsTarget = null },
            onDelete = { actionsTarget = null; deleteTarget = target }
        )
    }

    muteTarget?.let { target ->
        MuteDurationDialog(
            currentMuteUntil = UserStorage.getContactMuteUntil(context, target.id),
            onDismiss = { muteTarget = null },
            onSelect = { until ->
                UserStorage.setContactMuteUntil(context, target.id, until)
                mutedIds = computeMutedIds(threads)
                muteTarget = null
            }
        )
    }

    deleteTarget?.let { target ->
        ChatDeleteDialog(
            name = target.name,
            onDismiss = { deleteTarget = null },
            onConfirm = {
                DecoyData.deleteThread(context, target.id)
                deleteTarget = null
                onChanged()
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DecoyChatScreen(
    thread: DecoyData.DecoyThread,
    onBack: () -> Unit,
    onSend: (String) -> Unit
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val scope = rememberCoroutineScope()

    var inputText by remember { mutableStateOf("") }
    var isVideoMode by remember { mutableStateOf(false) }
    var searchMode by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    // DecoyMsg -> the real Message the real bubble renders, including quoted
    // replies and reactions, so nothing about the bubble's shape is guesswork.
    val messages = remember(thread) {
        val byId = thread.messages.associateBy { it.id }
        thread.messages.map { m ->
            Message(
                id = m.id,
                text = m.text,
                isOwn = m.isOwn,
                isRead = m.isRead,
                isDelivered = m.isDelivered,
                timestamp = m.timestamp,
                reactions = m.reactions,
                fileName = m.fileName,
                filePath = m.filePath,
                replyTo = m.replyToId?.let { byId[it] }?.let { r ->
                    Message(id = r.id, text = r.text, isOwn = r.isOwn, timestamp = r.timestamp)
                }
            )
        }
    }

    LaunchedEffect(thread.id, messages.size) {
        if (messages.isNotEmpty()) listState.scrollToItem(messages.lastIndex)
    }

    val displayedMessages = if (searchMode && searchQuery.isNotBlank())
        messages.filter { it.text.contains(searchQuery, ignoreCase = true) }
    else messages

    Column(modifier = Modifier.fillMaxSize().navigationBarsPadding().imePadding()) {

        TopAppBar(
            title = {
                if (searchMode) {
                    BasicTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.fillMaxWidth().padding(end = 8.dp),
                        singleLine = true,
                        textStyle = TextStyle(fontSize = 18.sp, color = c.textPrimary),
                        cursorBrush = SolidColor(c.accent),
                        decorationBox = { inner ->
                            if (searchQuery.isEmpty()) Text(
                                s.chatSearchPlaceholder,
                                fontSize = 18.sp,
                                color = c.textPrimary.copy(alpha = 0.53f),
                                fontFamily = JetBrainsMono
                            )
                            inner()
                        }
                    )
                } else {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        // Note the palette: the chat header's first colour is
                        // c.primaryBlue, not the list palette's terracotta.
                        // Matching the real header matters more than being
                        // internally consistent with the list.
                        val avatarColor = remember(thread.name) {
                            listOf(
                                c.primaryBlue, Color(0xFFE74C3C), Color(0xFF27AE60),
                                Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
                            )[thread.name.hashCode().absoluteValue % 6]
                        }
                        val avatarBitmap = AvatarStore.avatars[thread.id]
                        if (avatarBitmap != null) {
                            Image(
                                bitmap = avatarBitmap.asImageBitmap(),
                                contentDescription = thread.name,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.size(40.dp).clip(CircleShape)
                            )
                        } else {
                            Surface(shape = CircleShape, color = avatarColor, modifier = Modifier.size(40.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(
                                        text = thread.name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                        fontSize = 20.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                thread.name,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 20.sp,
                                color = c.textPrimary,
                                fontFamily = com.subrosa.messenger.ui.theme.NotoSerifJP
                            )
                            // The old decoy said "online" unconditionally, for
                            // every contact, forever. Derived from the thread's
                            // own recency instead — the same thing the real
                            // header's contactRecentlyActive flag expresses.
                            val online = remember(thread.id) {
                                System.currentTimeMillis() - thread.lastTimestamp < 20 * 60_000L
                            }
                            AnimatedContent(
                                targetState = online,
                                transitionSpec = {
                                    (fadeIn(tween(220)) + slideInVertically(tween(220)) { -it }) togetherWith
                                        (fadeOut(tween(160)) + slideOutVertically(tween(160)) { it })
                                },
                                label = "status"
                            ) { isOnline ->
                                Text(
                                    text = if (isOnline) s.chatOnline else s.chatOffline,
                                    fontSize = 15.sp,
                                    color = if (isOnline) c.accent else c.textPrimary.copy(alpha = 0.5f)
                                )
                            }
                        }
                    }
                }
            },
            navigationIcon = {
                IconButton(onClick = {
                    if (searchMode) { searchMode = false; searchQuery = "" } else onBack()
                }) {
                    Icon(painterResource(R.drawable.ic_back_arrow), contentDescription = s.back)
                }
            },
            actions = {
                IconButton(onClick = {}) {
                    Icon(
                        painterResource(R.drawable.ic_sound_call),
                        contentDescription = s.chatAudioCall,
                        tint = c.textPrimary,
                        modifier = Modifier.size(28.dp)
                    )
                }
                IconButton(onClick = {}) {
                    Icon(
                        painterResource(R.drawable.ic_video_call),
                        contentDescription = s.chatVideoCall,
                        tint = c.textPrimary,
                        modifier = Modifier.size(28.dp)
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
        )

        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .background(bgGradient)
                    .padding(horizontal = 8.dp),
                state = listState
            ) {
                items(displayedMessages, key = { it.id }) { msg ->
                    Box(
                        modifier = Modifier.animateItem(
                            fadeInSpec = tween(180),
                            fadeOutSpec = tween(120)
                        )
                    ) {
                        MessageBubble(
                            msg = msg,
                            contactId = thread.id,
                            searchQuery = if (searchMode) searchQuery else ""
                        )
                    }
                }
            }

            val showScrollFab by remember { derivedStateOf { listState.canScrollForward } }
            Box(modifier = Modifier.align(Alignment.BottomEnd).padding(end = 12.dp, bottom = 8.dp)) {
                androidx.compose.animation.AnimatedVisibility(
                    visible = showScrollFab,
                    enter = fadeIn() + scaleIn(),
                    exit = fadeOut() + scaleOut()
                ) {
                    FloatingActionButton(
                        onClick = { scope.launch { listState.animateScrollToItem(messages.size - 1) } },
                        containerColor = c.primaryBlue,
                        contentColor = if (c.isDark) Color.White else c.textPrimary,
                        modifier = Modifier.size(40.dp)
                    ) {
                        Icon(
                            painterResource(R.drawable.ic_arrow_down),
                            contentDescription = null,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.topBar)
                .padding(horizontal = 8.dp, vertical = 10.dp),
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(Color(0x18FFFFFF))
                    .clickable {},
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_attach),
                    contentDescription = null,
                    tint = c.textPrimary.copy(alpha = 0.85f),
                    modifier = Modifier.size(22.dp)
                )
            }

            val inputInteraction = remember { MutableInteractionSource() }
            val isInputFocused by inputInteraction.collectIsFocusedAsState()
            val inputBorderColor by animateColorAsState(
                targetValue = if (isInputFocused) c.accent.copy(alpha = 0.6f) else Color(0x28B0C4DE),
                animationSpec = tween(250),
                label = "inputBorder"
            )
            Box(modifier = Modifier.weight(1f)) {
                Canvas(modifier = Modifier.matchParentSize()) {
                    drawRoundRect(
                        color = Color(0x22FFFFFF),
                        cornerRadius = CornerRadius(32.dp.toPx())
                    )
                    drawRoundRect(
                        color = inputBorderColor,
                        cornerRadius = CornerRadius(32.dp.toPx()),
                        style = Stroke(width = 1.5.dp.toPx())
                    )
                }
                BasicTextField(
                    value = inputText,
                    onValueChange = { inputText = it },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                    maxLines = 4,
                    textStyle = TextStyle(fontSize = 17.sp, color = c.textPrimary),
                    cursorBrush = SolidColor(c.accent),
                    interactionSource = inputInteraction,
                    decorationBox = { innerTextField ->
                        if (inputText.isEmpty()) {
                            Text(
                                s.chatInputHint,
                                fontSize = 17.sp,
                                color = c.textPrimary.copy(alpha = 0.4f),
                                fontFamily = JetBrainsMono
                            )
                        }
                        innerTextField()
                    }
                )
            }

            if (inputText.isNotEmpty()) {
                PortholeSendButton(
                    enabled = true,
                    onClick = {
                        val text = inputText.trim()
                        if (text.isNotEmpty()) {
                            SoundManager.playMessageSent()
                            inputText = ""
                            onSend(text)
                        }
                    },
                    size = 44
                )
            } else {
                CombinedMediaButton(
                    isVideoMode = isVideoMode,
                    onToggleMode = { isVideoMode = !isVideoMode },
                    onStartVoice = {},
                    onStartVideo = {},
                    size = 44
                )
            }
        }
    }
}
