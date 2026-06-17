package com.bcon.messenger

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.animation.core.tween
import com.bcon.messenger.ui.theme.LocalBeaconColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChannelFeedScreen(
    channelId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val scope = rememberCoroutineScope()

    var channel by remember { mutableStateOf<Channel?>(null) }
    var posts by remember { mutableStateOf(listOf<ChannelPost>()) }
    var postText by remember { mutableStateOf("") }
    val userId = remember { UserStorage.getUserId(context) }
    val listState = rememberLazyListState()
    val snackbarHostState = remember { SnackbarHostState() }

    // Feature 1: context menu for long-press on post
    var contextMenuPost by remember { mutableStateOf<ChannelPost?>(null) }

    // Feature 2+3: edit/delete channel dialog
    var showEditChannelDialog by remember { mutableStateOf(false) }
    var editName   by remember { mutableStateOf("") }
    var editDesc   by remember { mutableStateOf("") }
    var editAvatar by remember { mutableStateOf("📢") }
    var showDeleteChannelConfirm by remember { mutableStateOf(false) }

    // Feature 5: pull-to-refresh
    var isRefreshing by remember { mutableStateOf(false) }

    // Feature 7: forward post
    var forwardPost by remember { mutableStateOf<ChannelPost?>(null) }
    var contacts by remember { mutableStateOf(listOf<Pair<String, String>>()) }

    // Feature 8: search
    var searchMode by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    val imageLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            try {
                val b64 = ImageHelper.prepareImageSingle(context, uri)
                val text = postText.trim()
                val authorName = UserStorage.getUserDisplayName(context)
                val post = ChannelPost(
                    id = UUID.randomUUID().toString(),
                    channelId = channelId,
                    text = text,
                    timestamp = System.currentTimeMillis(),
                    authorId = userId,
                    authorName = authorName,
                    imageData = b64
                )
                withContext(Dispatchers.Main) { postText = "" }
                context.startService(
                    Intent(context, MessengerService::class.java).apply {
                        putExtra("channel_post_id", channelId)
                        putExtra("channel_post_text", text)
                        putExtra("channel_post_msg_id", post.id)
                        putExtra("channel_post_image", b64)
                    }
                )
                ChannelManager.addPost(context, post)
                withContext(Dispatchers.Main) {
                    posts = ChannelManager.loadPosts(context, channelId)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    snackbarHostState.showSnackbar(s.channelLoadImageError)
                }
            }
        }
    }

    fun loadData() {
        scope.launch(Dispatchers.IO) {
            val ch = ChannelManager.getChannel(context, channelId)
            val ps = ChannelManager.loadPosts(context, channelId)
            withContext(Dispatchers.Main) {
                channel = ch
                posts = ps
            }
        }
    }

    // Initial load + request fresh info from server (subscriber count, pinned post)
    LaunchedEffect(Unit) {
        loadData()
        context.startService(
            Intent(context, MessengerService::class.java).apply {
                putExtra("channel_get_info_id", channelId)
            }
        )
    }

    // Feature 5+6: react to ChannelManager updates (from server responses)
    val channelUpdateTick by ChannelManager.channelUpdateEvents.collectAsState()
    LaunchedEffect(channelUpdateTick) {
        if (channelUpdateTick > 0L) loadData()
    }

    LaunchedEffect(posts.size) {
        if (posts.isNotEmpty()) listState.animateScrollToItem(posts.size - 1)
    }

    val ch = channel

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    if (searchMode) {
                        // Feature 8: search field replaces title
                        BasicTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            singleLine = true,
                            textStyle = TextStyle(color = Color.White, fontSize = 16.sp, fontFamily = JetBrainsMono),
                            cursorBrush = SolidColor(c.accent),
                            modifier = Modifier.fillMaxWidth().padding(end = 8.dp),
                            decorationBox = { inner ->
                                if (searchQuery.isEmpty()) {
                                    Text(
                                        s.channelSearchPlaceholder,
                                        color = c.textPrimary.copy(alpha = 0.45f),
                                        fontSize = 16.sp,
                                        fontFamily = JetBrainsMono
                                    )
                                }
                                inner()
                            }
                        )
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Surface(shape = CircleShape, color = c.primaryBlue, modifier = Modifier.size(36.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(ch?.avatar ?: "📢", fontSize = 18.sp)
                                }
                            }
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    ch?.name ?: s.channelDefault,
                                    color = Color.White,
                                    fontFamily = JetBrainsMono,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                                // Feature 6: subscriber count, fallback to description
                                val subCount = ch?.subscriberCount ?: -1
                                when {
                                    subCount >= 0 ->
                                        Text(
                                            s.channelSubscribers(subCount),
                                            color = c.textPrimary.copy(alpha = 0.6f),
                                            fontSize = 11.sp,
                                            fontFamily = JetBrainsMono
                                        )
                                    !ch?.description.isNullOrBlank() ->
                                        Text(
                                            ch!!.description,
                                            color = c.textPrimary.copy(alpha = 0.6f),
                                            fontSize = 11.sp,
                                            fontFamily = JetBrainsMono,
                                            maxLines = 1
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
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = s.back, tint = Color.White)
                    }
                },
                actions = {
                    // Feature 8: search toggle
                    if (!searchMode) {
                        IconButton(onClick = { searchMode = true }) {
                            Icon(Icons.Default.Search, contentDescription = null, tint = Color.White)
                        }
                    }
                    if (ch?.isAdmin == true && !searchMode) {
                        // Feature 4 (admin): mute toggle
                        IconButton(onClick = {
                            scope.launch(Dispatchers.IO) {
                                val updated = ch.copy(isMuted = !ch.isMuted)
                                ChannelManager.saveChannel(context, updated)
                                withContext(Dispatchers.Main) { channel = updated }
                            }
                        }) {
                            Text(if (ch.isMuted) "🔕" else "🔔", fontSize = 20.sp)
                        }
                        // Copy subscribe link
                        TextButton(onClick = {
                            val link = ChannelManager.generateSubscribeLink(channelId, ch.name, ch.avatar)
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("channel_link", link))
                            scope.launch { snackbarHostState.showSnackbar(s.channelLinkCopied) }
                        }) {
                            Text(s.channelCopyLink, color = c.accent, fontSize = 13.sp, fontFamily = JetBrainsMono)
                        }
                        // Feature 2+3: edit channel
                        IconButton(onClick = {
                            editName   = ch.name
                            editDesc   = ch.description
                            editAvatar = ch.avatar
                            showEditChannelDialog = true
                        }) {
                            Icon(Icons.Default.MoreVert, contentDescription = null, tint = Color.White)
                        }
                    } else if (ch != null && !ch.isAdmin && !searchMode) {
                        // Feature 4 (subscriber): mute toggle
                        IconButton(onClick = {
                            scope.launch(Dispatchers.IO) {
                                val updated = ch.copy(isMuted = !ch.isMuted)
                                ChannelManager.saveChannel(context, updated)
                                withContext(Dispatchers.Main) { channel = updated }
                            }
                        }) {
                            Text(if (ch.isMuted) "🔕" else "🔔", fontSize = 20.sp)
                        }
                        // Unsubscribe
                        TextButton(onClick = {
                            scope.launch(Dispatchers.IO) {
                                context.startService(
                                    Intent(context, MessengerService::class.java).apply {
                                        putExtra("channel_unsubscribe", channelId)
                                    }
                                )
                                ChannelManager.removeChannel(context, channelId)
                                withContext(Dispatchers.Main) { onBack() }
                            }
                        }) {
                            Text(s.channelUnsubscribe, color = Color(0xFFFF4444), fontSize = 13.sp, fontFamily = JetBrainsMono)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        },
        bottomBar = {
            if (ch?.isAdmin == true) {
                Surface(color = c.topBar, shadowElevation = 8.dp) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp, vertical = 8.dp)
                            .imePadding(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        IconButton(onClick = { imageLauncher.launch("image/*") }) {
                            Text("📎", fontSize = 22.sp)
                        }
                        OutlinedTextField(
                            value = postText,
                            onValueChange = { postText = it },
                            modifier = Modifier.weight(1f),
                            placeholder = {
                                Text(
                                    s.channelPostPlaceholder,
                                    color = c.textPrimary.copy(alpha = 0.4f),
                                    fontFamily = JetBrainsMono,
                                    fontSize = 14.sp
                                )
                            },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = c.accent,
                                unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                cursorColor = c.accent
                            ),
                            shape = RoundedCornerShape(20.dp),
                            maxLines = 4
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        IconButton(
                            onClick = {
                                val text = postText.trim()
                                if (text.isBlank()) return@IconButton
                                postText = ""
                                val authorName = UserStorage.getUserDisplayName(context)
                                val post = ChannelPost(
                                    id = UUID.randomUUID().toString(),
                                    channelId = channelId,
                                    text = text,
                                    timestamp = System.currentTimeMillis(),
                                    authorId = userId,
                                    authorName = authorName
                                )
                                context.startService(
                                    Intent(context, MessengerService::class.java).apply {
                                        putExtra("channel_post_id", channelId)
                                        putExtra("channel_post_text", text)
                                        putExtra("channel_post_msg_id", post.id)
                                    }
                                )
                                scope.launch(Dispatchers.IO) {
                                    ChannelManager.addPost(context, post)
                                    withContext(Dispatchers.Main) {
                                        posts = ChannelManager.loadPosts(context, channelId)
                                    }
                                }
                            }
                        ) {
                            Text("➤", fontSize = 26.sp, color = c.accent)
                        }
                    }
                }
            }
        },
        containerColor = c.inputBg
    ) { padding ->
        // Feature 5: pull-to-refresh wraps the entire content area
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = {
                isRefreshing = true
                context.startService(
                    Intent(context, MessengerService::class.java).apply {
                        putExtra("channel_get_info_id", channelId)
                    }
                )
                scope.launch(Dispatchers.IO) {
                    val ps = ChannelManager.loadPosts(context, channelId)
                    withContext(Dispatchers.Main) {
                        posts = ps
                        isRefreshing = false
                    }
                }
            },
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            // Feature 8: filter posts by search query
            val displayedPosts = if (searchMode && searchQuery.isNotBlank())
                posts.filter { it.text.contains(searchQuery, ignoreCase = true) }
            else posts

            if (displayedPosts.isEmpty() && !searchMode) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text("📢", fontSize = 56.sp)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        s.chatsNoPosts,
                        color = c.textPrimary.copy(alpha = 0.5f),
                        fontFamily = JetBrainsMono,
                        fontSize = 16.sp
                    )
                    if (ch?.isAdmin == true) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            s.channelWriteFirst,
                            color = c.textPrimary.copy(alpha = 0.35f),
                            fontFamily = JetBrainsMono,
                            fontSize = 13.sp
                        )
                    }
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // Feature 9: pinned post shown at top
                    val pinnedId = ch?.pinnedPostId
                    val pinnedPost = if (pinnedId != null) posts.find { it.id == pinnedId } else null
                    if (pinnedPost != null && !searchMode) {
                        item(key = "pinned_${pinnedPost.id}") {
                            Column {
                                Text(
                                    "📌 ${s.channelPinned}",
                                    color = c.accent,
                                    fontSize = 11.sp,
                                    fontFamily = JetBrainsMono,
                                    modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                                )
                                ChannelPostCard(
                                    post = pinnedPost,
                                    channelAvatar = ch?.avatar ?: "📢",
                                    channelName = ch?.name ?: "",
                                    isAdmin = ch?.isAdmin == true,
                                    onLongClick = { contextMenuPost = pinnedPost }
                                )
                                HorizontalDivider(
                                    modifier = Modifier.padding(vertical = 8.dp),
                                    color = c.textPrimary.copy(alpha = 0.15f)
                                )
                            }
                        }
                    }

                    // Regular posts (exclude pinned from chronological list to avoid duplicate)
                    val chronoPosts = if (pinnedId != null && !searchMode)
                        displayedPosts.filter { it.id != pinnedId }
                    else displayedPosts

                    items(chronoPosts, key = { it.id }) { post ->
                        Box(Modifier.animateItem(fadeInSpec = tween(220), fadeOutSpec = tween(160))) {
                            ChannelPostCard(
                                post = post,
                                channelAvatar = ch?.avatar ?: "📢",
                                channelName = ch?.name ?: "",
                                isAdmin = ch?.isAdmin == true,
                                onLongClick = { contextMenuPost = post }
                            )
                        }
                    }
                }
            }
        }
    }

    // ─── Feature 1 + 7 + 9: Long-press context menu ───────────────────────────
    val ctxPost = contextMenuPost
    if (ctxPost != null) {
        AlertDialog(
            onDismissRequest = { contextMenuPost = null },
            containerColor = c.card,
            title = null,
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    // Feature 7: Forward
                    TextButton(
                        onClick = {
                            contextMenuPost = null
                            forwardPost = ctxPost
                            scope.launch(Dispatchers.IO) {
                                val fps = ChatStorage.getContacts(context)
                                val named = fps.map { fp ->
                                    fp to (ChatStorage.getContactName(context, fp)
                                        .takeIf { it?.isNotBlank() == true } ?: fp)
                                }
                                withContext(Dispatchers.Main) { contacts = named }
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(s.channelForwardPost, color = c.textPrimary, fontFamily = JetBrainsMono, modifier = Modifier.fillMaxWidth())
                    }
                    if (ch?.isAdmin == true) {
                        // Feature 9: Pin / Unpin
                        val isPinned = ch.pinnedPostId == ctxPost.id
                        TextButton(
                            onClick = {
                                val newPinnedId = if (isPinned) null else ctxPost.id
                                contextMenuPost = null
                                scope.launch(Dispatchers.IO) {
                                    val updated = ch.copy(pinnedPostId = newPinnedId)
                                    ChannelManager.saveChannel(context, updated)
                                    withContext(Dispatchers.Main) { channel = updated }
                                }
                                context.startService(
                                    Intent(context, MessengerService::class.java).apply {
                                        putExtra("channel_pin_post_channel_id", channelId)
                                        putExtra("channel_pin_post_id", ctxPost.id)
                                        putExtra("channel_pin_post_unpin", isPinned)
                                    }
                                )
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                if (isPinned) s.channelUnpinPost else s.channelPinPost,
                                color = c.textPrimary,
                                fontFamily = JetBrainsMono,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                        // Feature 1: Delete post
                        TextButton(
                            onClick = {
                                val postId = ctxPost.id
                                contextMenuPost = null
                                scope.launch(Dispatchers.IO) {
                                    ChannelManager.removePost(context, channelId, postId)
                                    withContext(Dispatchers.Main) {
                                        posts = ChannelManager.loadPosts(context, channelId)
                                    }
                                }
                                context.startService(
                                    Intent(context, MessengerService::class.java).apply {
                                        putExtra("channel_delete_post_channel_id", channelId)
                                        putExtra("channel_delete_post_id", postId)
                                    }
                                )
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(s.channelDeletePost, color = Color(0xFFFF4444), fontFamily = JetBrainsMono, modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { contextMenuPost = null }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    // ─── Feature 7: Forward dialog ────────────────────────────────────────────
    if (forwardPost != null) {
        AlertDialog(
            onDismissRequest = { forwardPost = null },
            containerColor = c.card,
            title = { Text(s.channelForwardTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                if (contacts.isEmpty()) {
                    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = c.accent)
                    }
                } else {
                    LazyColumn(modifier = Modifier.heightIn(max = 300.dp)) {
                        items(contacts) { (fp, name) ->
                            TextButton(
                                onClick = {
                                    val text = forwardPost!!.text
                                    forwardPost = null
                                    context.startService(
                                        Intent(context, MessengerService::class.java).apply {
                                            putExtra("forward_to", fp)
                                            putExtra("forward_text", text)
                                        }
                                    )
                                    scope.launch { snackbarHostState.showSnackbar(s.channelForwardSent) }
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(name, color = c.textPrimary, fontFamily = JetBrainsMono, modifier = Modifier.fillMaxWidth())
                            }
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { forwardPost = null }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )
    }

    // ─── Feature 2+3: Edit / Delete channel dialog ────────────────────────────
    if (showEditChannelDialog && ch != null) {
        AlertDialog(
            onDismissRequest = { showEditChannelDialog = false; showDeleteChannelConfirm = false },
            containerColor = c.card,
            title = { Text(s.channelEditTitle, color = Color.White, fontFamily = JetBrainsMono) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = editAvatar,
                        onValueChange = { editAvatar = it },
                        label = { Text("Avatar", color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono, fontSize = 12.sp) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = c.accent
                        )
                    )
                    OutlinedTextField(
                        value = editName,
                        onValueChange = { editName = it },
                        label = { Text(s.chatsChannelNameLabel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono, fontSize = 12.sp) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = c.accent
                        )
                    )
                    OutlinedTextField(
                        value = editDesc,
                        onValueChange = { editDesc = it },
                        label = { Text(s.chatsChannelDescLabel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono, fontSize = 12.sp) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = c.accent,
                            unfocusedBorderColor = c.textPrimary.copy(alpha = 0.3f),
                            focusedLabelColor = c.accent,
                            unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = c.accent
                        )
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    // Feature 3: delete channel
                    TextButton(
                        onClick = { showDeleteChannelConfirm = true },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(s.channelDeleteChannelTitle, color = Color(0xFFFF4444), fontFamily = JetBrainsMono)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (editName.isBlank()) return@Button
                        val trimmedName   = editName.trim()
                        val trimmedDesc   = editDesc.trim()
                        val trimmedAvatar = editAvatar.trim().ifBlank { "📢" }
                        val updated = ch.copy(name = trimmedName, description = trimmedDesc, avatar = trimmedAvatar)
                        scope.launch(Dispatchers.IO) {
                            ChannelManager.saveChannel(context, updated)
                            withContext(Dispatchers.Main) { channel = updated }
                        }
                        context.startService(
                            Intent(context, MessengerService::class.java).apply {
                                putExtra("channel_update_info_id", channelId)
                                putExtra("channel_update_info_name", trimmedName)
                                putExtra("channel_update_info_desc", trimmedDesc)
                                putExtra("channel_update_info_avatar", trimmedAvatar)
                            }
                        )
                        showEditChannelDialog = false
                        scope.launch { snackbarHostState.showSnackbar(s.channelSaved) }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = c.primaryBlue)
                ) {
                    Text(s.save, color = Color.White, fontFamily = JetBrainsMono)
                }
            },
            dismissButton = {
                TextButton(onClick = { showEditChannelDialog = false; showDeleteChannelConfirm = false }) {
                    Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                }
            }
        )

        // Feature 3: delete confirmation
        if (showDeleteChannelConfirm) {
            AlertDialog(
                onDismissRequest = { showDeleteChannelConfirm = false },
                containerColor = c.card,
                title = { Text(s.channelDeleteChannelTitle, color = Color.White, fontFamily = JetBrainsMono) },
                text = { Text(s.channelDeleteChannelText, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 14.sp) },
                confirmButton = {
                    Button(
                        onClick = {
                            showDeleteChannelConfirm = false
                            showEditChannelDialog = false
                            scope.launch(Dispatchers.IO) {
                                ChannelManager.removeChannel(context, channelId)
                            }
                            context.startService(
                                Intent(context, MessengerService::class.java).apply {
                                    putExtra("channel_delete_id", channelId)
                                }
                            )
                            onBack()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF4444))
                    ) {
                        Text(s.delete, color = Color.White, fontFamily = JetBrainsMono)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showDeleteChannelConfirm = false }) {
                        Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                    }
                }
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ChannelPostCard(
    post: ChannelPost,
    channelAvatar: String,
    channelName: String,
    isAdmin: Boolean = false,
    onLongClick: (() -> Unit)? = null
) {
    val c = LocalBeaconColors.current
    val dateFormat = remember { SimpleDateFormat("d MMM, HH:mm", Locale.getDefault()) }
    val postBitmap = remember(post.id) {
        if (post.imageData.isNotEmpty()) ImageHelper.decodeBase64ToBitmap(post.imageData) else null
    }

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = c.card),
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = {},
                onLongClick = { onLongClick?.invoke() }
            )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(channelAvatar, fontSize = 18.sp)
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    channelName,
                    color = c.accent,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = JetBrainsMono,
                    fontSize = 13.sp
                )
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    dateFormat.format(Date(post.timestamp)),
                    color = c.textPrimary.copy(alpha = 0.45f),
                    fontFamily = JetBrainsMono,
                    fontSize = 11.sp
                )
            }
            if (post.text.isNotBlank()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    post.text,
                    color = c.textPrimary,
                    fontFamily = JetBrainsMono,
                    fontSize = 15.sp,
                    lineHeight = 22.sp
                )
            }
            if (postBitmap != null) {
                Spacer(modifier = Modifier.height(10.dp))
                Image(
                    bitmap = postBitmap.asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp)),
                    contentScale = ContentScale.FillWidth
                )
            }
        }
    }
}

// ─── Subscribe Preview Dialog ─────────────────────────────────────────────────

@Composable
fun ChannelSubscribeDialog(
    linkData: ChannelManager.ChannelLinkData,
    onSubscribe: () -> Unit,
    onDismiss: () -> Unit
) {
    val s = LocalStrings.current
    val c = LocalBeaconColors.current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = c.card,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(shape = CircleShape, color = c.topBar, modifier = Modifier.size(48.dp)) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(linkData.channelAvatar, fontSize = 24.sp)
                    }
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(s.channelDefault, color = c.accent, fontSize = 12.sp, fontFamily = JetBrainsMono)
                    Text(linkData.channelName, color = Color.White, fontWeight = FontWeight.Bold, fontFamily = JetBrainsMono, fontSize = 18.sp)
                }
            }
        },
        text = {
            Text(s.channelSubscribeConfirm, color = c.textPrimary, fontFamily = JetBrainsMono, fontSize = 14.sp)
        },
        confirmButton = {
            Button(onClick = onSubscribe, colors = ButtonDefaults.buttonColors(containerColor = c.primaryBlue)) {
                Text(s.channelSubscribeBtn, color = Color.White, fontFamily = JetBrainsMono)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(s.cancel, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
            }
        }
    )
}
