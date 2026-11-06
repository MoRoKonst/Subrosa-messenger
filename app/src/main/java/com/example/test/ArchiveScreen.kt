package com.subrosa.messenger

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.subrosa.messenger.ui.theme.Inter
import com.subrosa.messenger.ui.theme.LocalSubrosaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val AppFont = Inter

/**
 * Read-only viewer for a backup file. See [BackupArchive] for why this exists
 * separately from import and what it deliberately refuses to do.
 *
 * Three UI-level properties that are part of the security story, not polish:
 *
 *  - **The decrypted archive is dropped on ON_STOP**, not just on back.
 *    Backgrounding the app is the moment someone else may be about to look at
 *    it, and it is also the moment the recents thumbnail is taken (FLAG_SECURE
 *    in MainActivity blanks that, but the plaintext would still be in the heap
 *    of a visible-to-nobody process). The password field is cleared with it, so
 *    coming back requires re-entering it.
 *  - **The file is read into memory, never copied to app storage.** The picker
 *    hands over a content:// URI; this screen reads it through the
 *    ContentResolver and keeps the result in a composable state. Writing a
 *    plaintext (or even ciphertext) copy into filesDir would survive this
 *    screen and would then have to be wiped — so it is never written.
 *  - **Blocked in decoy mode.** Under duress the fake inbox must not offer a
 *    working tool for decrypting a real backup file someone is holding.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ArchiveScreen(onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val context = LocalContext.current
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val scope = rememberCoroutineScope()
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    var password by remember { mutableStateOf("") }
    var pickedUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var pickedName by remember { mutableStateOf<String?>(null) }
    var archive by remember { mutableStateOf<BackupArchive.Archive?>(null) }
    var openThread by remember { mutableStateOf<BackupArchive.Thread?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var pendingSaveBytes by remember { mutableStateOf<ByteArray?>(null) }

    fun clearEverything() {
        // close() wipes the container key the archive holds for lazy
        // attachment extraction — the one piece of real key material this
        // screen keeps alive while it is open.
        archive?.close()
        archive = null
        openThread = null
        pickedUri = null
        pickedName = null
        password = ""
        error = null
        SecureMemory.wipe(pendingSaveBytes)
        pendingSaveBytes = null
    }

    // Drop the plaintext as soon as the app leaves the foreground. DisposableEffect
    // also covers ordinary navigation away from the screen.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) clearEverything()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            clearEverything()
        }
    }

    // Only the URI is kept. Nothing is read until the password is entered, and
    // nothing is ever read whole: a version 8 backup can be larger than the
    // heap, and the previous draft of this screen slurped the file into a
    // String before noticing.
    val pickLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        pickedUri = uri
        pickedName = uri.lastPathSegment?.substringAfterLast('/')
        error = null
    }

    val saveAttachmentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri ->
        val bytes = pendingSaveBytes
        pendingSaveBytes = null
        if (uri == null || bytes == null) {
            SecureMemory.wipe(bytes)
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                }
                error = null
            } catch (e: Exception) {
                error = s.error(e.message ?: "")
            } finally {
                // The copy the user asked for is now outside the app and is
                // their responsibility; this one is not needed any more.
                SecureMemory.wipe(bytes)
            }
        }
    }

    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = c.accent,
        unfocusedBorderColor = c.fieldBorder,
        focusedLabelColor = c.accent,
        unfocusedLabelColor = c.textPrimary.copy(alpha = 0.6f),
        focusedTextColor = c.textPrimary,
        unfocusedTextColor = c.textPrimary,
        cursorColor = c.accent
    )

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        openThread?.name ?: s.archiveTitle,
                        color = c.textPrimary,
                        fontFamily = AppFont
                    )
                },
                navigationIcon = {
                    IconButton(onClick = {
                        if (openThread != null) openThread = null else onBack()
                    }) {
                        Icon(painterResource(R.drawable.ic_back_arrow), s.back, tint = c.textPrimary)
                    }
                },
                actions = {
                    if (archive != null) {
                        TextButton(onClick = { clearEverything() }) {
                            Text(s.archiveClose, color = c.accent, fontFamily = AppFont, fontSize = 13.sp)
                        }
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
            val currentArchive = archive
            val currentThread = openThread
            when {
                currentArchive != null && currentThread != null ->
                    ArchiveThreadView(
                        thread = currentThread,
                        archive = currentArchive,
                        onSave = { bytes, suggestedName ->
                            pendingSaveBytes = bytes
                            saveAttachmentLauncher.launch(suggestedName)
                        }
                    )

                currentArchive != null ->
                    ArchiveThreadList(currentArchive) { openThread = it }

                else -> Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp)
                ) {
                    Text(
                        s.archiveSubtitle,
                        fontSize = 15.sp,
                        color = c.textPrimary.copy(alpha = 0.6f),
                        fontFamily = AppFont
                    )

                    Spacer(Modifier.height(16.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = c.dangerCard)
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Text(
                                s.archiveNoticeTitle,
                                fontSize = 15.sp,
                                color = c.accent,
                                fontFamily = AppFont,
                                fontWeight = FontWeight.Medium
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                s.archiveNoticeText,
                                fontSize = 13.sp,
                                color = c.textPrimary.copy(alpha = 0.85f),
                                fontFamily = AppFont
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                s.archiveNoAttachmentsNote,
                                fontSize = 13.sp,
                                color = c.textPrimary.copy(alpha = 0.6f),
                                fontFamily = AppFont
                            )
                        }
                    }

                    Spacer(Modifier.height(20.dp))

                    OutlinedButton(
                        onClick = { pickLauncher.launch(arrayOf("*/*")) },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !busy
                    ) {
                        Text(
                            pickedName ?: s.archivePick,
                            color = c.textPrimary,
                            fontFamily = AppFont
                        )
                    }

                    Spacer(Modifier.height(12.dp))

                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it; error = null },
                        label = { Text(s.backupPassword, fontFamily = AppFont) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                        ),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = TextStyle(color = c.textPrimary, fontFamily = AppFont),
                        colors = fieldColors
                    )

                    Spacer(Modifier.height(16.dp))

                    Button(
                        onClick = {
                            val uri = pickedUri ?: return@Button
                            val pwd = password
                            scope.launch {
                                busy = true
                                error = null
                                // Argon2id at 64 MiB — must not run on the main
                                // thread, same as every other password check in
                                // the app.
                                val result = withContext(Dispatchers.IO) {
                                    BackupArchive.open(
                                        {
                                            context.contentResolver.openInputStream(uri)
                                                ?: throw java.io.IOException("openInputStream returned null")
                                        },
                                        pwd
                                    )
                                }
                                when (result) {
                                    is BackupArchive.Result.Ok -> {
                                        archive = result.archive
                                        // The password has served its purpose;
                                        // don't leave it in a live Compose state.
                                        password = ""
                                    }
                                    BackupArchive.Result.BadPasswordOrCorrupt ->
                                        error = s.archiveBadPassword
                                    is BackupArchive.Result.Unreadable ->
                                        error = s.archiveUnreadable(result.detail)
                                }
                                busy = false
                            }
                        },
                        enabled = !busy && pickedUri != null && password.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = c.accent)
                    ) {
                        Text(
                            if (busy) s.archiveOpening else s.archiveOpen,
                            color = Color.White,
                            fontFamily = AppFont
                        )
                    }

                    error?.let {
                        Spacer(Modifier.height(12.dp))
                        Text(it, fontSize = 13.sp, color = c.error, fontFamily = AppFont)
                    }
                }
            }
        }
    }
}

@Composable
private fun ArchiveThreadList(
    archive: BackupArchive.Archive,
    onOpen: (BackupArchive.Thread) -> Unit
) {
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text(
                s.archiveSummary(archive.threads.size, archive.messageCount),
                fontSize = 14.sp,
                color = c.textPrimary,
                fontFamily = AppFont
            )
            if (archive.createdAt > 0L) {
                Text(
                    s.archiveCreatedAt(formatArchiveDate(archive.createdAt)),
                    fontSize = 12.sp,
                    color = c.textPrimary.copy(alpha = 0.5f),
                    fontFamily = AppFont
                )
            }
        }
        HorizontalDivider(color = c.textPrimary.copy(alpha = 0.08f))

        if (archive.threads.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    s.archiveEmpty,
                    fontSize = 14.sp,
                    color = c.textPrimary.copy(alpha = 0.5f),
                    fontFamily = AppFont
                )
            }
            return@Column
        }

        LazyColumn(Modifier.fillMaxSize()) {
            items(archive.threads) { thread ->
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clickable { onOpen(thread) }
                        .padding(horizontal = 16.dp, vertical = 12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            thread.name,
                            fontSize = 15.sp,
                            color = c.textPrimary,
                            fontFamily = AppFont,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (thread.isGroup) {
                            Spacer(Modifier.width(6.dp))
                            Text(
                                s.archiveGroupTag,
                                fontSize = 11.sp,
                                color = c.accent,
                                fontFamily = AppFont
                            )
                        }
                        Spacer(Modifier.weight(1f))
                        Text(
                            formatArchiveDate(thread.lastTimestamp),
                            fontSize = 11.sp,
                            color = c.textPrimary.copy(alpha = 0.4f),
                            fontFamily = AppFont
                        )
                    }
                    Spacer(Modifier.height(2.dp))
                    val preview = thread.messages.lastOrNull()
                    Text(
                        when {
                            preview == null -> ""
                            preview.isAttachmentPlaceholder -> s.archiveAttachmentMissing
                            else -> preview.text
                        },
                        fontSize = 13.sp,
                        color = c.textPrimary.copy(alpha = 0.55f),
                        fontFamily = AppFont,
                        maxLines = 1
                    )
                }
                HorizontalDivider(color = c.textPrimary.copy(alpha = 0.06f))
            }
        }
    }
}

/**
 * Deliberately not the real [MessageBubble]: that composable has taps, long-press
 * menus, reactions, reply, delete and media loading wired into live storage.
 * Reusing it here would mean either disabling all of that (and drifting from it
 * over time) or letting a read-only archive reach code that writes. A plain
 * bubble with no affordances is the honest representation of what this is.
 */
@Composable
private fun ArchiveThreadView(
    thread: BackupArchive.Thread,
    archive: BackupArchive.Archive,
    onSave: (ByteArray, String) -> Unit
) {
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp)
    ) {
        items(thread.messages) { msg ->
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = if (msg.isOwn) Arrangement.End else Arrangement.Start
            ) {
                Column(
                    Modifier
                        .widthIn(max = 300.dp)
                        .padding(vertical = 3.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (msg.isOwn) c.bubbleOwn else c.bubbleOther)
                        .padding(horizontal = 10.dp, vertical = 7.dp)
                ) {
                    if (thread.isGroup && !msg.isOwn && msg.senderName != null) {
                        Text(
                            msg.senderName,
                            fontSize = 11.sp,
                            color = c.accent,
                            fontFamily = AppFont
                        )
                    }
                    if (msg.isAttachmentPlaceholder) {
                        Text(
                            s.archiveAttachmentMissing,
                            fontSize = 13.sp,
                            color = c.textPrimary.copy(alpha = 0.45f),
                            fontFamily = AppFont,
                            fontStyle = FontStyle.Italic
                        )
                    } else if (msg.text.isNotBlank()) {
                        Text(
                            msg.text,
                            fontSize = 14.sp,
                            color = c.textPrimary,
                            fontFamily = AppFont
                        )
                    }
                    msg.attachment?.let { att ->
                        Spacer(Modifier.height(4.dp))
                        ArchiveAttachmentRow(att, archive, onSave)
                    }
                    Text(
                        formatArchiveTime(msg.timestamp),
                        fontSize = 10.sp,
                        color = c.textPrimary.copy(alpha = 0.4f),
                        fontFamily = AppFont,
                        modifier = Modifier.align(Alignment.End)
                    )
                }
            }
        }
    }
}

/**
 * One attachment inside a bubble.
 *
 * Extraction is on demand, per tap, and the bytes are released as soon as the
 * row leaves the composition. The alternative — decoding every image in a
 * thread up front — would mean holding an entire conversation's media in the
 * heap to render a list the user scrolls past.
 *
 * "Save" hands the bytes to the SAF picker. That is the only route out of this
 * screen, and it is an explicit user action: the viewer itself still writes
 * nothing, and there is no "open with" (which would hand a decrypted file to an
 * arbitrary third-party app, from a screen whose entire premise is that nothing
 * leaves it by accident).
 */
@Composable
private fun ArchiveAttachmentRow(
    attachment: BackupArchive.Attachment,
    archive: BackupArchive.Archive,
    onSave: (ByteArray, String) -> Unit
) {
    val s = LocalStrings.current
    val c = LocalSubrosaColors.current
    val scope = rememberCoroutineScope()

    var bitmap by remember(attachment.blobId) { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    var working by remember(attachment.blobId) { mutableStateOf(false) }
    var unavailable by remember(attachment.blobId) { mutableStateOf(!archive.hasAttachments) }

    DisposableEffect(attachment.blobId) {
        onDispose { bitmap = null }
    }

    val kindLabel = when (attachment.kind) {
        "image" -> s.archiveAttachmentImage
        "voice" -> s.archiveAttachmentVoice
        "video" -> s.archiveAttachmentVideo
        else -> s.archiveAttachmentFile
    }

    Column {
        bitmap?.let { bmp ->
            androidx.compose.foundation.Image(
                bitmap = bmp,
                contentDescription = kindLabel,
                modifier = Modifier
                    .widthIn(max = 260.dp)
                    .clip(RoundedCornerShape(8.dp))
            )
            Spacer(Modifier.height(4.dp))
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                buildString {
                    append(kindLabel)
                    attachment.name?.let { append(" · ").append(it) }
                    if (attachment.durationSeconds > 0) {
                        append(" · ").append(attachment.durationSeconds).append("s")
                    }
                },
                fontSize = 12.sp,
                color = c.textPrimary.copy(alpha = 0.6f),
                fontFamily = AppFont,
                modifier = Modifier.weight(1f, fill = false)
            )
        }

        when {
            unavailable -> Text(
                s.archiveAttachmentUnavailable,
                fontSize = 11.sp,
                color = c.textPrimary.copy(alpha = 0.45f),
                fontFamily = AppFont,
                fontStyle = FontStyle.Italic
            )
            working -> Text(
                s.archiveAttachmentLoading,
                fontSize = 11.sp,
                color = c.accent,
                fontFamily = AppFont
            )
            else -> Row {
                if (attachment.kind == "image" && bitmap == null) {
                    TextButton(onClick = {
                        scope.launch {
                            working = true
                            val decoded = withContext(Dispatchers.IO) {
                                // 24 MiB cap: an image that doesn't fit is not
                                // worth risking the process over, and the user
                                // can still save it to a file.
                                val bytes = archive.extract(attachment.blobId, maxBytes = 24 * 1024 * 1024)
                                try {
                                    bytes?.let {
                                        android.graphics.BitmapFactory.decodeByteArray(it, 0, it.size)
                                    }
                                } finally {
                                    SecureMemory.wipe(bytes)
                                }
                            }
                            if (decoded == null) unavailable = true
                            bitmap = decoded?.asImageBitmap()
                            working = false
                        }
                    }) {
                        Text(s.archiveAttachmentOpen, fontSize = 12.sp, color = c.accent, fontFamily = AppFont)
                    }
                }
                TextButton(onClick = {
                    scope.launch {
                        working = true
                        val bytes = withContext(Dispatchers.IO) { archive.extract(attachment.blobId) }
                        working = false
                        if (bytes == null) {
                            unavailable = true
                        } else {
                            onSave(bytes, attachment.name ?: defaultAttachmentName(attachment))
                        }
                    }
                }) {
                    Text(s.archiveAttachmentSave, fontSize = 12.sp, color = c.accent, fontFamily = AppFont)
                }
            }
        }
    }
}

/**
 * The backup stores a filename only for messages that had one (files, and
 * nothing else — photos, voice notes and video circles never had a
 * user-visible name). Reconstructing a plausible extension from the kind keeps
 * the saved file openable by whatever the user saves it into.
 */
private fun defaultAttachmentName(attachment: BackupArchive.Attachment): String = when (attachment.kind) {
    "image" -> "subrosa_photo_${attachment.blobId.take(8)}.jpg"
    "voice" -> "subrosa_voice_${attachment.blobId.take(8)}.m4a"
    "video" -> "subrosa_video_${attachment.blobId.take(8)}.mp4"
    else -> "subrosa_file_${attachment.blobId.take(8)}"
}

private fun formatArchiveDate(ts: Long): String =
    if (ts <= 0L) "" else java.text.SimpleDateFormat("dd.MM.yyyy", java.util.Locale.getDefault())
        .format(java.util.Date(ts))

private fun formatArchiveTime(ts: Long): String =
    if (ts <= 0L) "" else java.text.SimpleDateFormat("dd.MM.yyyy HH:mm", java.util.Locale.getDefault())
        .format(java.util.Date(ts))
