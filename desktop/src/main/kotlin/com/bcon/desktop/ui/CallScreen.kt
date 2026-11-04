package com.subrosa.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.onvoid.webrtc.media.FourCC
import dev.onvoid.webrtc.media.video.VideoBufferConverter
import dev.onvoid.webrtc.media.video.VideoFrame
import kotlinx.coroutines.delay
import java.awt.image.BufferedImage
import java.awt.image.DataBufferInt

data class IncomingCallInfo(
    val callId: String, val from: String, val isVideo: Boolean,
    val isGroup: Boolean, val groupName: String
)

/** Global call UI state, wired to DesktopCallManager callbacks once at app
 *  start. remoteFrames/groupPeers/mainPeerId are the group-call additions —
 *  for an ordinary 1:1 call remoteFrames has at most one entry (keyed by
 *  activeCallPeer) and groupPeers stays empty, so the 1:1 rendering path in
 *  ActiveCallScreen below is unchanged in practice. */
object CallUiState {
    var incomingCall by mutableStateOf<IncomingCallInfo?>(null)
    var activeCallPeer by mutableStateOf<String?>(null)
    var isGroupCall by mutableStateOf(false)
    var groupName by mutableStateOf("")
    var isConnected by mutableStateOf(false)
    var localFrame by mutableStateOf<ImageBitmap?>(null)
    val remoteFrames = mutableStateMapOf<String, ImageBitmap>()
    val groupPeers = mutableStateListOf<String>()
    // Which peer's video is shown full-screen in a group call — clicking a
    // thumbnail promotes it, mirrors Android's ActiveCallScreen mainPeerId.
    var mainPeerId by mutableStateOf<String?>(null)
    // Transient banner text shown over the active-call screen — cleared by
    // ActiveCallScreen after a few seconds. See DesktopCallManager's
    // onCameraUnavailable comment: a camera-less machine pressing "video
    // call" used to crash the whole app with no message at all.
    var cameraWarning by mutableStateOf<String?>(null)
    // "Hide IP during calls" fail-closed: shown instead of ever silently
    // falling back to a direct P2P connection. Standalone (not scoped to
    // ActiveCallScreen like cameraWarning above) since a refused call never
    // reaches that screen at all — see DesktopCallManager.onRelayUnavailable.
    var relayUnavailableWarning by mutableStateOf<String?>(null)

    private var wired = false

    fun ensureWired() {
        if (wired) return
        wired = true
        DesktopCallManager.onIncomingCall = { callId, from, isVideo ->
            val group = DesktopCallManager.isGroupCall
            incomingCall = IncomingCallInfo(
                callId, from, isVideo, group,
                if (group) GroupManager.getGroup(DesktopCallManager.groupId)?.name ?: "" else ""
            )
        }
        DesktopCallManager.onCallConnected = { peer ->
            isConnected = true
            if (!isGroupCall) activeCallPeer = peer
            if (mainPeerId == null) mainPeerId = peer
        }
        DesktopCallManager.onPeerJoined = { peer -> if (peer !in groupPeers) groupPeers.add(peer) }
        DesktopCallManager.onPeerLeft = { peer ->
            groupPeers.remove(peer)
            remoteFrames.remove(peer)
            if (mainPeerId == peer) mainPeerId = groupPeers.firstOrNull()
        }
        DesktopCallManager.onCallEnded = {
            incomingCall = null
            activeCallPeer = null
            isGroupCall = false
            groupName = ""
            isConnected = false
            localFrame = null
            remoteFrames.clear()
            groupPeers.clear()
            mainPeerId = null
        }
        DesktopCallManager.onLocalVideoFrame = { frame -> localFrame = frameToImageBitmap(frame) }
        DesktopCallManager.onRemoteVideoFrame = { peer, frame -> remoteFrames[peer] = frameToImageBitmap(frame) }
        DesktopCallManager.onCameraUnavailable = { cameraWarning = "Камера не найдена — звонок продолжится без видео" }
        DesktopCallManager.onRelayUnavailable = {
            val strings = if (AppLanguage.code == "en") EnStrings else RuStrings
            relayUnavailableWarning = strings.profileHideIpCallsFailedNoTurn
        }
    }

    fun startCall(target: String, video: Boolean) {
        activeCallPeer = target
        isGroupCall = false
        mainPeerId = target
        isConnected = false
        DesktopCallManager.startCall(target, video)
    }

    fun startGroupCall(groupId: String, members: List<String>, video: Boolean) {
        isGroupCall = true
        groupName = GroupManager.getGroup(groupId)?.name ?: ""
        groupPeers.clear()
        groupPeers.addAll(members.filter { it != WebSocketClient.myFingerprint })
        mainPeerId = null
        isConnected = false
        DesktopCallManager.startGroupCall(groupId, members, video)
    }
}

private fun frameToImageBitmap(frame: VideoFrame): ImageBitmap {
    val buf = frame.buffer
    val w = buf.width
    val h = buf.height
    val bytes = ByteArray(w * h * 4)
    VideoBufferConverter.convertFromI420(buf, bytes, FourCC.ARGB)
    val srcPixels = IntArray(w * h)
    // FourCC.ARGB is libyuv's "32bpp ARGB, little-endian" format, which in
    // memory is actually B,G,R,A byte order (little-endian storage of the
    // 0xAARRGGBB word) — NOT literal A,R,G,B bytes. Reading it as A,R,G,B
    // shifted every channel by one byte: true alpha (always 255, opaque)
    // landed in the blue slot (constant blue tint), true blue (which varies
    // with content) landed in the alpha slot (variable transparency over
    // the black call-screen background), and red/green were swapped —
    // together this desaturated/darkened the picture into what looked like
    // black-and-white video. Found live, 2026-09-19.
    for (i in 0 until w * h) {
        val o = i * 4
        val b = bytes[o].toInt() and 0xFF
        val g = bytes[o + 1].toInt() and 0xFF
        val r = bytes[o + 2].toInt() and 0xFF
        val a = bytes[o + 3].toInt() and 0xFF
        srcPixels[i] = (a shl 24) or (r shl 16) or (g shl 8) or b
    }
    // frame.rotation (WebRTC convention: degrees to rotate CLOCKWISE for
    // upright display) was ignored entirely before this fix — any camera/OS
    // reporting non-zero capture rotation (common for Windows webcams via
    // DirectShow/MediaFoundation) rendered sideways, both in local self-view
    // and remote peer video. Android never needed this: org.webrtc's
    // SurfaceViewRenderer/EglRenderer applies VideoFrame.rotation internally
    // in its GL draw call. dev.onvoid.webrtc has no equivalent widget for
    // Compose, so CallScreen hand-rolls the buffer→bitmap conversion and
    // must apply it manually. Found live, 2026-09-21.
    val (outW, outH, pixels) = rotatePixels(srcPixels, w, h, frame.rotation)
    val img = BufferedImage(outW, outH, BufferedImage.TYPE_INT_ARGB)
    System.arraycopy(pixels, 0, (img.raster.dataBuffer as DataBufferInt).data, 0, pixels.size)
    return img.toComposeImageBitmap()
}

/** Rotates a [w]x[h] ARGB pixel array by [rotationDegrees] (0/90/180/270,
 *  normalized modulo 360 — WebRTC only ever reports these four values)
 *  clockwise. Returns the new width/height (swapped for 90/270) and the
 *  rotated pixel array. Plain index remapping rather than
 *  Graphics2D/AffineTransform — this runs once per rendered video frame
 *  (up to 30/sec per visible tile), where the allocation/rasterization
 *  overhead of a Graphics2D path is avoidable. */
internal fun rotatePixels(src: IntArray, w: Int, h: Int, rotationDegrees: Int): Triple<Int, Int, IntArray> {
    return when (((rotationDegrees % 360) + 360) % 360) {
        90 -> {
            val out = IntArray(w * h)
            for (y in 0 until h) for (x in 0 until w) {
                out[x * h + (h - 1 - y)] = src[y * w + x]
            }
            Triple(h, w, out)
        }
        180 -> {
            val out = IntArray(w * h)
            for (i in 0 until w * h) out[w * h - 1 - i] = src[i]
            Triple(w, h, out)
        }
        270 -> {
            val out = IntArray(w * h)
            for (y in 0 until h) for (x in 0 until w) {
                out[(w - 1 - x) * h + y] = src[y * w + x]
            }
            Triple(h, w, out)
        }
        else -> Triple(w, h, src)
    }
}

@Composable
fun IncomingCallDialog(info: IncomingCallInfo, onAccept: () -> Unit, onDecline: () -> Unit) {
    val label = if (info.isGroup) info.groupName.ifBlank { "Групповой звонок" } else ChatStorage.getContactName(info.from)
    val subtitle = if (info.isGroup) ChatStorage.getContactName(info.from) else null
    AlertDialog(
        onDismissRequest = {},
        containerColor = SubrosaTheme.dialog,
        title = { Text(if (info.isVideo) "Видеозвонок" else "Звонок", color = SubrosaTheme.textPrimary) },
        text = {
            Column {
                Text(label, color = SubrosaTheme.textSecondary)
                if (subtitle != null) {
                    Text("Приглашает: $subtitle", fontSize = 14.sp, color = SubrosaTheme.textSecondary.copy(alpha = 0.7f))
                }
            }
        },
        confirmButton = {
            Button(onClick = onAccept, colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))) {
                Text("Принять")
            }
        },
        dismissButton = {
            Button(onClick = onDecline, colors = ButtonDefaults.buttonColors(containerColor = SubrosaTheme.error)) {
                Text("Отклонить")
            }
        }
    )
}

@Composable
fun ActiveCallScreen(peerId: String?) {
    val isGroup = CallUiState.isGroupCall
    val mainPeer = if (isGroup) CallUiState.mainPeerId else peerId
    val label = if (isGroup) CallUiState.groupName.ifBlank { "Групповой звонок" } else ChatStorage.getContactName(peerId ?: "")
    var muted by remember { mutableStateOf(false) }
    var cameraOff by remember { mutableStateOf(false) }

    LaunchedEffect(CallUiState.cameraWarning) {
        if (CallUiState.cameraWarning != null) {
            delay(4_000L)
            CallUiState.cameraWarning = null
        }
    }

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        val remote = mainPeer?.let { CallUiState.remoteFrames[it] }
        if (remote != null) {
            Image(remote, contentDescription = null, modifier = Modifier.fillMaxSize())
        } else {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        if (isGroup && mainPeer != null) ChatStorage.getContactName(mainPeer) else label,
                        fontSize = 24.sp, fontWeight = FontWeight.SemiBold, color = Color.White
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(if (CallUiState.isConnected) "Соединено" else "Вызов…", color = Color.White.copy(alpha = 0.7f))
                }
            }
        }

        // Thumbnail strip for every OTHER mesh peer — click to promote to
        // main. Empty (no-op) for an ordinary 1:1 call. Mirrors Android's
        // ActiveCallScreen.kt LazyRow of group peer tiles.
        if (isGroup) {
            val others = CallUiState.groupPeers.filter { it != mainPeer }
            if (others.isNotEmpty()) {
                LazyRow(
                    modifier = Modifier.align(Alignment.TopStart).padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(others) { peer ->
                        val frame = CallUiState.remoteFrames[peer]
                        Box(
                            modifier = Modifier
                                .size(100.dp, 75.dp)
                                .clip(RoundedCornerShapeCompat)
                                .background(Color.DarkGray)
                                .clickable { CallUiState.mainPeerId = peer },
                            contentAlignment = Alignment.Center
                        ) {
                            if (frame != null) {
                                Image(frame, contentDescription = null, modifier = Modifier.fillMaxSize())
                            } else {
                                Text(
                                    ChatStorage.getContactName(peer).take(1).uppercase(),
                                    color = Color.White, fontSize = 22.sp, fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
            }
        }

        val local = CallUiState.localFrame
        if (local != null) {
            Image(
                local, contentDescription = null,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(16.dp)
                    .size(160.dp, 120.dp)
                    .clip(RoundedCornerShapeCompat)
            )
        }

        CallUiState.cameraWarning?.let { warning ->
            Surface(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
                color = Color.Black.copy(alpha = 0.75f),
                modifier = Modifier.align(Alignment.TopCenter).padding(top = 16.dp)
            ) {
                Text(
                    warning,
                    color = Color.White,
                    fontSize = 15.sp,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                )
            }
        }

        Row(
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 40.dp),
            horizontalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            CallControlButton(
                icon = AppIcons.get(if (muted) "DISABLE_MICRO" else "Micro"),
                onClick = { muted = DesktopCallManager.toggleMute() }
            )
            CallControlButton(
                icon = AppIcons.get(if (cameraOff) "DISABLE_CAMERA" else "VIDEO_CALL"),
                onClick = { cameraOff = DesktopCallManager.toggleCamera() }
            )
            CallControlButton(
                icon = AppIcons.get("END_CALL"),
                background = SubrosaTheme.error,
                onClick = { DesktopCallManager.hangUp() }
            )
        }
    }
}

private val RoundedCornerShapeCompat = androidx.compose.foundation.shape.RoundedCornerShape(8.dp)

@Composable
private fun CallControlButton(icon: androidx.compose.ui.graphics.painter.Painter, background: Color = Color.White.copy(alpha = 0.15f), onClick: () -> Unit) {
    Surface(shape = CircleShape, color = background, modifier = Modifier.size(56.dp)) {
        IconButton(onClick = onClick) {
            Icon(icon, contentDescription = null, tint = Color.White)
        }
    }
}
