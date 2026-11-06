package com.subrosa.desktop

import dev.onvoid.webrtc.*
import dev.onvoid.webrtc.media.MediaDevices
import dev.onvoid.webrtc.media.audio.AudioOptions
import dev.onvoid.webrtc.media.audio.AudioTrack
import dev.onvoid.webrtc.media.video.VideoDeviceSource
import dev.onvoid.webrtc.media.video.VideoFrame
import dev.onvoid.webrtc.media.video.VideoTrack
import dev.onvoid.webrtc.media.video.VideoTrackSink
import kotlinx.coroutines.*
import kotlinx.coroutines.swing.Swing
import org.json.JSONObject
import java.net.NetworkInterface
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Audio/video calls for the desktop client, mirroring Android's CallManager
 * signaling protocol over the same WebSocket relay. Uses webrtc-java (JNI
 * wrapper around native libwebrtc).
 *
 * 1:1 calls: call_offer/call_answer/call_ice(_batch)/call_end, a single
 * RTCPeerConnection (peerConnection/peerId fields).
 *
 * Group calls: a full mesh (every participant opens a direct pairwise
 * connection to every other participant, no SFU/relay) — call_group_invite/
 * call_group_join/call_group_answer/call_group_peer_list/call_group_leave,
 * reusing call_ice_batch for ICE (routed per-peer by `from`/`to`). Ported
 * from Android's CallManager.kt (startGroupCall/handleGroupInvite/
 * handleGroupJoin/handleGroupPeerList), which the extensive "// ── Group
 * calls" comment in WebSocketClient.kt used to point to as the reason group
 * frames were safely no-op'd here. Scoped down from Android's version in one
 * respect: no per-peer heartbeat keepalive, ICE-restart-on-failure, or
 * network-change watchdog for the group path in this first pass (those stay
 * 1:1-only, in the `peerConnection`-keyed fields below) — a failed mesh peer
 * is simply dropped (see dropGroupPeer()), not retried. The call itself,
 * and every OTHER peer's connection, keeps working.
 */
object DesktopCallManager {

    private const val HEARTBEAT_INTERVAL_MS = 5_000L
    private const val HEARTBEAT_TIMEOUT_MS  = 15_000L
    private const val DISCONNECT_GRACE_MS   = 7_000L
    private const val ICE_RESTART_GRACE_MS  = 8_000L
    private const val NETWORK_POLL_MS       = 5_000L
    private const val NETWORK_RESTART_GRACE_MS = 10_000L
    private const val RINGING_TIMEOUT_MS    = 45_000L
    // Mirrors Android's CallManager.ICE_BATCH_DEBOUNCE_MS/ICE_BATCH_MAX_SIZE
    // — see queueIceCandidate() below for why this exists (was missing
    // entirely on Desktop before this fix, found in the 2026-09-12
    // full-logic audit).
    private const val ICE_BATCH_DEBOUNCE_MS = 250L
    private const val ICE_BATCH_MAX_SIZE    = 20

    // S6-51 (external review 2026-09-06) -- a compromised/malicious server is
    // not this device's memory-safety boundary; mirrors server.py's own
    // bounds (is_valid_call_uuid()/CALL_SDP_MAX_LEN/CALL_ICE_CANDIDATE_MAX_LEN)
    // and Android's CallManager.kt's identical client-side check.
    private val CALL_ID_RE = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private const val CALL_SDP_MAX_LEN = 64 * 1024
    private const val CALL_ICE_CANDIDATE_MAX_LEN = 1024
    private const val CALL_ICE_SDP_MID_MAX_LEN = 64
    // Real ICE gathering bursts are 10-30 candidates; generous cap, bounds
    // memory if remote description never completes.
    private const val MAX_PENDING_ICE_CANDIDATES = 500

    private fun isValidCallId(value: String?): Boolean = value != null && CALL_ID_RE.matches(value)
    private fun isValidCallSdp(value: String?): Boolean = !value.isNullOrEmpty() && value.length <= CALL_SDP_MAX_LEN
    private fun isValidCallIceCandidate(value: String?): Boolean = !value.isNullOrEmpty() && value.length <= CALL_ICE_CANDIDATE_MAX_LEN

    private var factory: PeerConnectionFactory? = null
    private var peerConnection: RTCPeerConnection? = null

    private var localAudioTrack: AudioTrack? = null
    private var localVideoTrack: VideoTrack? = null
    private var videoSource: VideoDeviceSource? = null

    var callId: String = ""
    var isVideoCall: Boolean = false
    private var peerId: String = ""
    private var isOfferer: Boolean = false

    private var pendingOffer: Triple<String, String, String>? = null // from, sdp, callId
    private val pendingIceCandidates = mutableListOf<RTCIceCandidate>()
    private val callActive = AtomicBoolean(false)

    // Outgoing ICE candidates are batched instead of one call_ice message
    // per candidate — mirrors Android's CallManager.queueIceCandidate()/
    // flushIceCandidates(). WebRTC's ICE gathering typically emits a burst
    // of 10-30+ candidates within about a second of call setup, and
    // sendCallSignal() routes through the same anon-token pool ordinary
    // messages draw from — one call alone could exhaust it before any
    // resupply logic gets a chance to help. Was missing entirely on
    // Desktop before this fix (it could already RECEIVE a batch from an
    // Android peer, just never sent one itself) — found in the 2026-09-12
    // full-logic audit.
    private val pendingOutgoingIce = mutableListOf<JSONObject>()
    private var iceFlushJob: Job? = null

    var onIncomingCall: ((callId: String, from: String, isVideo: Boolean) -> Unit)? = null
    var onCallConnected: ((peerId: String) -> Unit)? = null
    var onCallEnded: ((reason: String) -> Unit)? = null
    var onRemoteVideoFrame: ((peerId: String, frame: VideoFrame) -> Unit)? = null
    var onLocalVideoFrame: ((VideoFrame) -> Unit)? = null
    // Group-call-only: fired as each mesh peer's pairwise connection is
    // established/torn down, mirrors Android's CallManager.onPeerJoined.
    var onPeerJoined: ((peerId: String) -> Unit)? = null
    var onPeerLeft: ((peerId: String) -> Unit)? = null
    // Fired when a video call is started/answered on a machine with no
    // camera, or the native webrtc-java capture init otherwise fails —
    // lets the UI show "camera not found" instead of the call silently
    // going audio-only with no explanation, or (see createLocalTracks'
    // own comment) an uncaught native-layer exception taking down the
    // whole app. Found live, 2026-09-18.
    var onCameraUnavailable: (() -> Unit)? = null
    // Fired when "Hide IP during calls" is on but no TURN server is
    // available — the call is refused rather than silently falling back to
    // a direct (IP-revealing) connection. See UserStorage.getHideIpDuringCalls().
    var onRelayUnavailable: (() -> Unit)? = null

    private val scope = CoroutineScope(Dispatchers.Swing + SupervisorJob())

    private val localVideoSink = VideoTrackSink { frame -> onLocalVideoFrame?.invoke(frame) }
    private var remoteVideoSink: VideoTrackSink? = null

    // ── Reconnection state ──────────────────────────────────────────────────────
    private var disconnectJob: Job? = null
    private var iceRestartDone = false

    // ── Ringing timeout (both caller-side "no answer" and callee-side "unanswered
    // incoming call rings forever" — the latter had no timeout at all before) ────
    private var ringingTimeoutJob: Job? = null

    // ── Two-phase call flow: mirrors Android's CallManager — a lightweight
    // call_request_audio/video (anon-routed) is sent first; only once the other
    // side answers with call_response(accepted=true) does real SDP signaling
    // start. See CallManager.kt for the full reasoning. ──────────────────────────
    private var pendingRequestTarget: String? = null
    private var incomingRequestFrom: String? = null
    private val preAcceptedCallIds = mutableSetOf<String>()

    // ── Heartbeat (DataChannel keepalive) ───────────────────────────────────────
    private var heartbeatChannel: RTCDataChannel? = null
    private var heartbeatJob: Job? = null
    private var lastPongTime = 0L

    // ── Network-change watchdog ─────────────────────────────────────────────────
    private var networkWatchJob: Job? = null
    private var lastNetworkFingerprint: String? = null

    // ── Group call (mesh) state ─────────────────────────────────────────────────
    // Mirrors Android CallManager.kt: CALL_GROUP_PEER_LIST_MAX_COUNT (line
    // ~102), peerConnections becoming a Map<String, RTCPeerConnection>.
    private const val CALL_GROUP_PEER_LIST_MAX_COUNT = 50
    var isGroupCall: Boolean = false
        private set
    var groupId: String = ""
        private set
    private val groupPeers = mutableSetOf<String>()
    private val groupPeerConnections = java.util.concurrent.ConcurrentHashMap<String, RTCPeerConnection>()
    private val groupPendingIce = java.util.concurrent.ConcurrentHashMap<String, MutableList<RTCIceCandidate>>()
    private val groupRemoteVideoSinks = java.util.concurrent.ConcurrentHashMap<String, VideoTrackSink>()
    private val groupOutgoingIce = java.util.concurrent.ConcurrentHashMap<String, MutableList<JSONObject>>()
    private val groupIceFlushJobs = java.util.concurrent.ConcurrentHashMap<String, Job>()

    // "Hide IP during calls" — set at PeerConnection creation time (not
    // re-read afterward), so toggling the setting mid-call never affects an
    // already-established connection, only the NEXT one created. 1:1 calls
    // only ever have one peer, so a single field suffices; group calls need
    // one entry per mesh peer (createGroupPeerConnection() below).
    private var hideIpActive: Boolean = false
    private val hideIpPerGroupPeer = java.util.concurrent.ConcurrentHashMap<String, Boolean>()

    /** Standard ICE candidate SDP attribute marking it as a TURN-relayed
     *  candidate (RFC 5245 §15.1: candidate-types = host/srflx/prflx/relay).
     *  Defense-in-depth check, not the primary enforcement mechanism — see
     *  RTCConfiguration.iceTransportPolicy=RELAY below, which should mean
     *  the native WebRTC binding never even generates a non-relay candidate
     *  to begin with. */
    private fun isRelayCandidate(sdp: String): Boolean = Regex("""\btyp\s+relay\b""").containsMatchIn(sdp)

    private fun init() {
        if (factory != null) return
        factory = PeerConnectionFactory()
    }

    private fun iceServers(hideIp: Boolean): List<RTCIceServer> = buildList {
        // STUN only produces host-reflexive candidates, which RELAY mode
        // must never use — skip requesting them at all rather than relying
        // solely on iceTransportPolicy to discard them.
        if (!hideIp) add(RTCIceServer().apply { urls = listOf(NetworkConfig.STUN_URL) })
        if (NetworkConfig.TurnCredentials.isAvailable()) {
            add(RTCIceServer().apply {
                urls = listOf(NetworkConfig.TURN_URL)
                username = NetworkConfig.TurnCredentials.username
                password = NetworkConfig.TurnCredentials.password
            })
        }
    }

    private fun createLocalTracks(video: Boolean) {
        val f = factory ?: return
        val audioSource = f.createAudioSource(AudioOptions().apply {
            echoCancellation = true
            noiseSuppression = true
            autoGainControl = true
        })
        localAudioTrack = f.createAudioTrack("LA_${UUID.randomUUID()}", audioSource)

        if (video) {
            try {
                val devices = MediaDevices.getVideoCaptureDevices()
                val device = devices.firstOrNull()
                if (device != null) {
                    val src = VideoDeviceSource()
                    src.setVideoCaptureDevice(device)
                    src.start()
                    videoSource = src
                    localVideoTrack = f.createVideoTrack("LV_${UUID.randomUUID()}", src)
                    localVideoTrack?.addSink(localVideoSink)
                } else {
                    System.err.println("DesktopCallManager: no camera devices found")
                    onCameraUnavailable?.invoke()
                }
            } catch (e: Throwable) {
                // Throwable, not Exception — found live 2026-09-18: a
                // camera-less machine pressing "video call" crashed the
                // whole app, not just this call. MediaDevices/VideoDeviceSource
                // are thin JNI wrappers around native webrtc-java code; a
                // missing/unusable capture device can surface as an Error
                // subtype (UnsatisfiedLinkError, native RuntimeException
                // wrapper, etc.), not just a plain Exception — and this runs
                // synchronously on the Compose click handler's thread (see
                // startCall()), so anything uncaught here propagated straight
                // into Compose's event dispatch with no crash boundary.
                // Continues as an audio-only call (localVideoTrack stays
                // null, already handled everywhere via ?.) rather than
                // aborting the call entirely — losing video isn't a reason
                // to also lose audio.
                System.err.println("DesktopCallManager: failed to start camera — ${e.message}")
                onCameraUnavailable?.invoke()
            }
        }
    }

    private fun createPeerConnection(remoteId: String, offerer: Boolean): RTCPeerConnection? {
        val f = factory ?: return null
        val hideIp = UserStorage.getHideIpDuringCalls()
        // Fail closed: a relay-only call with no relay server is not "fall
        // back to a direct connection" — it's "don't place the call at
        // all". Silently degrading to P2P here would be exactly the IP
        // leak this setting exists to prevent.
        if (hideIp && !NetworkConfig.TurnCredentials.isAvailable()) {
            System.err.println("DesktopCallManager: hide IP during calls is on but no TURN server is available — refusing to start (peer=$remoteId)")
            onRelayUnavailable?.invoke()
            return null
        }
        hideIpActive = hideIp
        isOfferer = offerer
        val config = RTCConfiguration().apply {
            iceServers = this@DesktopCallManager.iceServers(hideIp)
            iceTransportPolicy = if (hideIp) RTCIceTransportPolicy.RELAY else RTCIceTransportPolicy.ALL
        }
        val pc = f.createPeerConnection(config, object : PeerConnectionObserver {
            override fun onIceCandidate(candidate: RTCIceCandidate) {
                queueIceCandidate(remoteId, candidate)
            }
            override fun onTrack(transceiver: RTCRtpTransceiver) {
                val track = transceiver.receiver.track
                if (track is VideoTrack) {
                    val sink = VideoTrackSink { frame -> onRemoteVideoFrame?.invoke(remoteId, frame) }
                    remoteVideoSink = sink
                    track.addSink(sink)
                }
            }
            override fun onConnectionChange(state: RTCPeerConnectionState) {
                if (state == RTCPeerConnectionState.CONNECTED) {
                    scope.launch { onCallConnected?.invoke(remoteId) }
                }
            }
            override fun onIceConnectionChange(state: RTCIceConnectionState) {
                when (state) {
                    RTCIceConnectionState.CONNECTED, RTCIceConnectionState.COMPLETED -> {
                        disconnectJob?.cancel(); disconnectJob = null
                        iceRestartDone = false
                    }
                    RTCIceConnectionState.FAILED -> {
                        disconnectJob?.cancel(); disconnectJob = null
                        val currentPc = peerConnection
                        if (!iceRestartDone && isOfferer && currentPc != null) {
                            iceRestartDone = true
                            attemptIceRestart(currentPc, remoteId)
                            disconnectJob = scope.launch {
                                delay(ICE_RESTART_GRACE_MS)
                                if (callActive.get()) hangUp()
                            }
                        } else {
                            scope.launch { if (callActive.get()) hangUp() }
                        }
                    }
                    RTCIceConnectionState.DISCONNECTED -> {
                        disconnectJob?.cancel()
                        disconnectJob = scope.launch {
                            delay(DISCONNECT_GRACE_MS)
                            val current = peerConnection?.iceConnectionState
                            if (current == RTCIceConnectionState.DISCONNECTED ||
                                current == RTCIceConnectionState.FAILED) {
                                hangUp()
                            }
                        }
                    }
                    else -> {}
                }
            }
            override fun onDataChannel(channel: RTCDataChannel) {
                if (channel.label != "heartbeat") return
                scope.launch { setupHeartbeatChannel(channel) }
            }
        }) ?: return null

        localAudioTrack?.let { pc.addTrack(it, listOf("Subrosa-call")) }
        if (isVideoCall) {
            val lvt = localVideoTrack
            if (lvt != null) {
                pc.addTrack(lvt, listOf("Subrosa-call"))
            } else {
                // No camera on this side (see createLocalTracks' own
                // comment) — still add a RECV_ONLY video transceiver so the
                // SDP offer/answer carries a video m-line at all. Without
                // this, a video call initiated or answered from a
                // camera-less machine produced an SDP with NO video m-line
                // whatsoever, so the OTHER side — even with a working
                // camera — had no m-line slot to negotiate its own outgoing
                // video into: per the SDP offer/answer model, the answer
                // must mirror the offer's m-lines 1:1, new ones can't be
                // added later. Confirmed live 2026-09-18: Android, calling
                // (or being called by) a camera-less Desktop, correctly
                // received no video (expected) but ALSO stopped sending its
                // own video (not expected — it has a working camera).
                // The dummy VideoDeviceSource is never .start()'d and never
                // touches real hardware — it exists purely because
                // dev.onvoid.webrtc's addTransceiver has no track-less/
                // kind-only overload, only one that takes a real
                // MediaStreamTrack.
                try {
                    val dummySource = VideoDeviceSource()
                    val dummyTrack = f.createVideoTrack("LV_recvonly_${UUID.randomUUID()}", dummySource)
                    dummyTrack.setEnabled(false)
                    pc.addTransceiver(dummyTrack, RTCRtpTransceiverInit().apply {
                        direction = RTCRtpTransceiverDirection.RECV_ONLY
                    })
                } catch (e: Exception) {
                    System.err.println("DesktopCallManager: failed to add recvonly video transceiver — ${e.message}")
                }
            }
        }

        if (offerer) {
            try {
                val dc = pc.createDataChannel("heartbeat", RTCDataChannelInit().apply {
                    ordered = false
                    maxRetransmits = 0
                })
                setupHeartbeatChannel(dc)
            } catch (e: Exception) {
                System.err.println("DesktopCallManager: DataChannel creation failed — ${e.message}")
            }
        }

        peerConnection = pc
        startNetworkWatch()
        return pc
    }

    private fun attemptIceRestart(pc: RTCPeerConnection, remoteId: String) {
        pc.createOffer(RTCOfferOptions().apply { iceRestart = true }, object : CreateSessionDescriptionObserver {
            override fun onSuccess(sdp: RTCSessionDescription) {
                pc.setLocalDescription(sdp, object : SetSessionDescriptionObserver {
                    override fun onSuccess() {
                        WebSocketClient.sendCallSignal(JSONObject().apply {
                            put("type", "call_ice_restart")
                            put("from", WebSocketClient.myFingerprint)
                            put("to", remoteId)
                            put("call_id", callId)
                            put("sdp", sdp.sdp)
                        })
                    }
                    override fun onFailure(error: String) { System.err.println("DesktopCallManager: ICE restart setLocal fail — $error") }
                })
            }
            override fun onFailure(error: String) { System.err.println("DesktopCallManager: ICE restart createOffer fail — $error") }
        })
    }

    private fun queueIceCandidate(remoteId: String, candidate: RTCIceCandidate) {
        if (hideIpActive && !isRelayCandidate(candidate.sdp)) {
            System.err.println("DesktopCallManager: hide IP during calls — dropping non-relay ICE candidate for $remoteId instead of signaling it")
            return
        }
        val entry = JSONObject().apply {
            put("sdp_mid", candidate.sdpMid)
            put("sdp_m_line_index", candidate.sdpMLineIndex)
            put("candidate", candidate.sdp)
        }
        val shouldFlushNow = synchronized(pendingOutgoingIce) {
            pendingOutgoingIce.add(entry)
            pendingOutgoingIce.size >= ICE_BATCH_MAX_SIZE
        }
        if (shouldFlushNow) {
            flushIceCandidates(remoteId)
        } else {
            iceFlushJob?.cancel()
            iceFlushJob = scope.launch {
                delay(ICE_BATCH_DEBOUNCE_MS)
                flushIceCandidates(remoteId)
            }
        }
    }

    private fun flushIceCandidates(remoteId: String) {
        iceFlushJob?.cancel()
        iceFlushJob = null
        val batch = synchronized(pendingOutgoingIce) {
            if (pendingOutgoingIce.isEmpty()) return
            val copy = pendingOutgoingIce.toList()
            pendingOutgoingIce.clear()
            copy
        }
        WebSocketClient.sendCallSignal(JSONObject().apply {
            put("type", "call_ice_batch")
            put("from", WebSocketClient.myFingerprint)
            put("to", remoteId)
            put("candidates", org.json.JSONArray(batch))
        })
    }

    fun startCall(targetId: String, video: Boolean) {
        if (UserStorage.getHideIpDuringCalls() && !NetworkConfig.TurnCredentials.isAvailable()) {
            System.err.println("DesktopCallManager: hide IP during calls is on but no TURN server is available — refusing to start (peer=$targetId)")
            onRelayUnavailable?.invoke()
            return
        }
        init()
        peerId = targetId
        isVideoCall = video
        callId = UUID.randomUUID().toString()
        callActive.set(true)
        pendingRequestTarget = targetId
        createLocalTracks(video)

        WebSocketClient.sendCallSignal(JSONObject().apply {
            put("type", if (video) "call_request_video" else "call_request_audio")
            put("from", WebSocketClient.myFingerprint)
            put("to", targetId)
            put("call_id", callId)
        })

        val thisCallId = callId
        ringingTimeoutJob?.cancel()
        ringingTimeoutJob = scope.launch {
            delay(RINGING_TIMEOUT_MS)
            if (callActive.get() && callId == thisCallId && pendingRequestTarget == targetId) {
                System.err.println("DesktopCallManager: call request timeout — peer did not answer, ending call")
                pendingRequestTarget = null
                release()
                onCallEnded?.invoke("no_answer")
            }
        }
    }

    // Only called after the target replied call_response(accepted=true) — liveness
    // is already confirmed, so this is the real SDP offer.
    private fun proceedWithRealOffer(targetId: String) {
        val pc = createPeerConnection(targetId, offerer = true) ?: return
        pc.createOffer(RTCOfferOptions(), object : CreateSessionDescriptionObserver {
            override fun onSuccess(sdp: RTCSessionDescription) {
                pc.setLocalDescription(sdp, object : SetSessionDescriptionObserver {
                    override fun onSuccess() {
                        WebSocketClient.sendCallSignal(JSONObject().apply {
                            put("type", "call_offer")
                            put("from", WebSocketClient.myFingerprint)
                            put("to", targetId)
                            put("call_id", callId)
                            put("sdp", sdp.sdp)
                            put("is_video", isVideoCall)
                            put("is_group", false)
                        })
                    }
                    override fun onFailure(error: String) { System.err.println("DesktopCallManager: setLocal fail — $error") }
                })
            }
            override fun onFailure(error: String) { System.err.println("DesktopCallManager: createOffer fail — $error") }
        })
    }

    // Caller side: the target answered our call_request_audio/video.
    fun handleCallResponse(from: String, cId: String, accepted: Boolean) {
        if (callId != cId || pendingRequestTarget != from) return
        ringingTimeoutJob?.cancel(); ringingTimeoutJob = null
        pendingRequestTarget = null
        if (accepted) {
            proceedWithRealOffer(from)
        } else {
            release()
            onCallEnded?.invoke("declined")
        }
    }

    // Callee side: someone sent us a call_request_audio/video — same ring UI/timeout
    // as a real incoming call (reuses onIncomingCall / acceptCall / declineCall).
    fun handleIncomingCallRequest(from: String, cId: String, isVideo: Boolean) {
        if (callId.isNotEmpty() || pendingOffer != null || pendingRequestTarget != null) {
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_response"); put("from", WebSocketClient.myFingerprint)
                put("to", from); put("call_id", cId); put("accepted", false); put("reason", "busy")
            })
            return
        }
        callId = cId
        isVideoCall = isVideo
        peerId = from
        callActive.set(true)
        incomingRequestFrom = from
        onIncomingCall?.invoke(cId, from, isVideo)
        DesktopNotificationService.notifyIncomingCall(from, isVideo)

        ringingTimeoutJob?.cancel()
        ringingTimeoutJob = scope.launch {
            delay(RINGING_TIMEOUT_MS)
            if (callId == cId && incomingRequestFrom == from) {
                System.err.println("DesktopCallManager: incoming call request timeout (${RINGING_TIMEOUT_MS / 1000}s) — auto-declining")
                declineCall("timeout")
            }
        }
    }

    fun handleOffer(from: String, sdp: String, cId: String, isVideo: Boolean) {
        // S6-51: bound before setRemoteDescription() ever sees it -- a
        // compromised/malicious server is not this device's memory boundary.
        if (!isValidCallId(cId) || !isValidCallSdp(sdp)) {
            System.err.println("DesktopCallManager: invalid/oversized call_id or sdp from $from — ignored")
            return
        }
        // If we already agreed to this callId via the request/response phase,
        // this real offer isn't a second incoming call — it's the expected
        // follow-up. Let it through even though callId is already set.
        val preAccepted = callId == cId && preAcceptedCallIds.remove(cId)

        if (!preAccepted && (callId.isNotEmpty() || pendingOffer != null)) {
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_end"); put("from", WebSocketClient.myFingerprint)
                put("to", from); put("call_id", cId); put("reason", "busy")
            })
            return
        }
        callId = cId
        isVideoCall = isVideo
        peerId = from
        callActive.set(true)
        pendingOffer = Triple(from, sdp, cId)

        if (preAccepted) {
            // Already agreed — proceed straight to answering, no second ring/prompt.
            acceptCall()
            return
        }

        onIncomingCall?.invoke(cId, from, isVideo)
        DesktopNotificationService.notifyIncomingCall(from, isVideo)

        // Without this, an unanswered incoming call rang forever — no auto-decline.
        ringingTimeoutJob?.cancel()
        ringingTimeoutJob = scope.launch {
            delay(RINGING_TIMEOUT_MS)
            if (pendingOffer?.third == cId) {
                System.err.println("DesktopCallManager: incoming ringing timeout (${RINGING_TIMEOUT_MS / 1000}s) — auto-declining")
                declineCall("timeout")
            }
        }
    }

    fun acceptCall() {
        ringingTimeoutJob?.cancel(); ringingTimeoutJob = null

        if (isGroupCall) {
            // Group invite already fired onIncomingCall in handleGroupInvite();
            // accepting here means opening our own pairwise connection to the
            // inviter. Any OTHER mesh peers get connected once THEY answer and
            // send back a call_group_peer_list (handleGroupPeerList).
            init()
            createLocalTracks(isVideoCall)
            groupPeers.toList().forEach { connectToGroupPeer(it) }
            return
        }

        val requestFrom = incomingRequestFrom
        if (requestFrom != null && pendingOffer == null) {
            // Still just a request — no real SDP offer has arrived yet. Tell the
            // caller we're in, then wait for handleOffer() to auto-proceed.
            preAcceptedCallIds.add(callId)
            incomingRequestFrom = null
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_response"); put("from", WebSocketClient.myFingerprint)
                put("to", requestFrom); put("call_id", callId); put("accepted", true)
            })
            return
        }

        val (from, offerSdp, cId) = pendingOffer ?: return
        pendingOffer = null
        init()
        createLocalTracks(isVideoCall)

        val pc = createPeerConnection(from, offerer = false) ?: return
        val remoteSdp = RTCSessionDescription(RTCSdpType.OFFER, offerSdp)
        pc.setRemoteDescription(remoteSdp, object : SetSessionDescriptionObserver {
            override fun onSuccess() {
                drainPendingIce(pc)
                pc.createAnswer(RTCAnswerOptions(), object : CreateSessionDescriptionObserver {
                    override fun onSuccess(sdp: RTCSessionDescription) {
                        pc.setLocalDescription(sdp, object : SetSessionDescriptionObserver {
                            override fun onSuccess() {
                                WebSocketClient.sendCallSignal(JSONObject().apply {
                                    put("type", "call_answer")
                                    put("from", WebSocketClient.myFingerprint)
                                    put("to", from)
                                    put("call_id", cId)
                                    put("sdp", sdp.sdp)
                                })
                            }
                            override fun onFailure(error: String) {}
                        })
                    }
                    override fun onFailure(error: String) { System.err.println("DesktopCallManager: createAnswer fail — $error") }
                })
            }
            override fun onFailure(error: String) { System.err.println("DesktopCallManager: setRemote(offer) fail — $error") }
        })
    }

    fun declineCall(reason: String = "decline") {
        ringingTimeoutJob?.cancel(); ringingTimeoutJob = null
        if (isGroupCall) {
            groupPeers.forEach { peer ->
                WebSocketClient.sendCallSignal(JSONObject().apply {
                    put("type", "call_group_leave")
                    put("from", WebSocketClient.myFingerprint)
                    put("to", peer)
                    put("call_id", callId)
                    put("reason", reason)
                })
            }
            release()
            return
        }
        val offer = pendingOffer
        val requestFrom = incomingRequestFrom
        if (offer != null) {
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_end"); put("from", WebSocketClient.myFingerprint)
                put("to", offer.first); put("call_id", offer.third); put("reason", reason)
            })
        } else if (requestFrom != null) {
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_response"); put("from", WebSocketClient.myFingerprint)
                put("to", requestFrom); put("call_id", callId); put("accepted", false); put("reason", reason)
            })
        }
        pendingOffer = null
        incomingRequestFrom = null
        preAcceptedCallIds.remove(callId)
        callId = ""
        callActive.set(false)
        isVideoCall = false
        peerId = ""
        pendingIceCandidates.clear()
    }

    fun handleAnswer(from: String, sdp: String) {
        // S6-51: bound before setRemoteDescription() ever sees it.
        if (!isValidCallSdp(sdp)) {
            System.err.println("DesktopCallManager: oversized/invalid sdp from $from — ignored")
            return
        }
        val pc = peerConnection ?: return
        val remoteSdp = RTCSessionDescription(RTCSdpType.ANSWER, sdp)
        pc.setRemoteDescription(remoteSdp, object : SetSessionDescriptionObserver {
            override fun onSuccess() { drainPendingIce(pc) }
            override fun onFailure(error: String) { System.err.println("DesktopCallManager: setRemote(answer) fail — $error") }
        })
    }

    fun handleIceCandidate(from: String, sdpMid: String?, sdpMLineIndex: Int, candidate: String) {
        // S6-51: bound before ever constructing an RTCIceCandidate/queuing it.
        if (!isValidCallIceCandidate(candidate) || (sdpMid != null && sdpMid.length > CALL_ICE_SDP_MID_MAX_LEN)) {
            System.err.println("DesktopCallManager: invalid/oversized candidate from $from — dropped")
            return
        }
        val ice = RTCIceCandidate(sdpMid, sdpMLineIndex, candidate)
        // call_ice_batch is reused for BOTH 1:1 and group calls (Android
        // does the same — no separate group ICE wire type) — route by `from`
        // into the correct mesh peer's connection instead of the singular
        // 1:1 `peerConnection` whenever a group call is active.
        if (isGroupCall) {
            val gpc = groupPeerConnections[from]
            if (gpc == null || gpc.remoteDescription == null) {
                val queue = groupPendingIce.getOrPut(from) { mutableListOf() }
                if (queue.size < MAX_PENDING_ICE_CANDIDATES) queue.add(ice)
            } else {
                gpc.addIceCandidate(ice)
            }
            return
        }
        val pc = peerConnection
        if (pc == null || pc.remoteDescription == null) {
            if (pendingIceCandidates.size >= MAX_PENDING_ICE_CANDIDATES) {
                System.err.println("DesktopCallManager: pending ICE queue full — candidate dropped")
                return
            }
            pendingIceCandidates.add(ice)
        } else {
            pc.addIceCandidate(ice)
        }
    }

    private fun drainPendingIce(pc: RTCPeerConnection) {
        pendingIceCandidates.forEach { pc.addIceCandidate(it) }
        pendingIceCandidates.clear()
    }

    /** Called on the answering side when the offerer requests an ICE restart. */
    fun handleIceRestart(from: String, sdp: String) {
        // S6-51: bound before setRemoteDescription() ever sees it.
        if (!isValidCallSdp(sdp)) {
            System.err.println("DesktopCallManager: oversized/invalid ICE-restart sdp from $from — ignored")
            return
        }
        val pc = peerConnection ?: return
        disconnectJob?.cancel(); disconnectJob = null
        val remoteSdp = RTCSessionDescription(RTCSdpType.OFFER, sdp)
        pc.setRemoteDescription(remoteSdp, object : SetSessionDescriptionObserver {
            override fun onSuccess() {
                drainPendingIce(pc)
                pc.createAnswer(RTCAnswerOptions(), object : CreateSessionDescriptionObserver {
                    override fun onSuccess(sdp2: RTCSessionDescription) {
                        pc.setLocalDescription(sdp2, object : SetSessionDescriptionObserver {
                            override fun onSuccess() {
                                WebSocketClient.sendCallSignal(JSONObject().apply {
                                    put("type", "call_answer")
                                    put("from", WebSocketClient.myFingerprint)
                                    put("to", from)
                                    put("call_id", callId)
                                    put("sdp", sdp2.sdp)
                                })
                            }
                            override fun onFailure(error: String) {}
                        })
                    }
                    override fun onFailure(error: String) {}
                })
            }
            override fun onFailure(error: String) {}
        })
    }

    fun handleCallEnd(from: String, reason: String) {
        if (callId.isEmpty()) return
        release()
        onCallEnded?.invoke(reason)
    }

    fun hangUp() {
        if (isGroupCall) {
            // Notify every peer we're either connected to or still waiting
            // to connect to — mirrors Android's call_group_leave fan-out.
            (groupPeerConnections.keys + groupPeers).toSet().forEach { peer ->
                WebSocketClient.sendCallSignal(JSONObject().apply {
                    put("type", "call_group_leave")
                    put("from", WebSocketClient.myFingerprint)
                    put("to", peer)
                    put("call_id", callId)
                    put("reason", "hangup")
                })
            }
            release()
            onCallEnded?.invoke("hangup")
            return
        }
        // Covers all phases (still-ringing request, pending offer, or a fully
        // connected call) — peerId is set as soon as either side is known.
        val target = pendingRequestTarget ?: incomingRequestFrom ?: pendingOffer?.first ?: peerId.takeIf { it.isNotEmpty() }
        if (target != null) {
            sendByeOverDataChannel()
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_end"); put("from", WebSocketClient.myFingerprint)
                put("to", target); put("call_id", callId); put("reason", "hangup")
            })
        }
        release()
        onCallEnded?.invoke("hangup")
    }

    // Best-effort in-band hangup over the P2P DataChannel — see the "bye" case in
    // setupHeartbeatChannel's onMessage for the full reasoning. No-op if the channel
    // isn't open yet; the server-routed call_end sent right after is the fallback.
    private fun sendByeOverDataChannel() {
        val dc = heartbeatChannel ?: return
        if (dc.state != RTCDataChannelState.OPEN) return
        try {
            dc.send(RTCDataChannelBuffer(ByteBuffer.wrap("bye".toByteArray(Charsets.UTF_8)), false))
        } catch (e: Exception) {
            System.err.println("DesktopCallManager: sendByeOverDataChannel failed — ${e.message}")
        }
    }

    fun toggleMute(): Boolean {
        val track = localAudioTrack ?: return false
        track.setEnabled(!track.isEnabled)
        return !track.isEnabled
    }

    fun toggleCamera(): Boolean {
        val track = localVideoTrack ?: return false
        track.setEnabled(!track.isEnabled)
        return !track.isEnabled
    }

    // ── Heartbeat over DataChannel ───────────────────────────────────────────────

    private fun setupHeartbeatChannel(dc: RTCDataChannel) {
        heartbeatChannel = dc
        dc.registerObserver(object : RTCDataChannelObserver {
            override fun onBufferedAmountChange(amount: Long) {}
            override fun onStateChange() {
                when (dc.state) {
                    RTCDataChannelState.OPEN -> {
                        lastPongTime = System.currentTimeMillis()
                        scope.launch { startHeartbeat() }
                    }
                    RTCDataChannelState.CLOSED -> {
                        // The heartbeat channel (SCTP/DataChannel) is a separate transport from
                        // the actual call media (SRTP) — it can fail to negotiate or drop on
                        // some network/NAT combos even while audio/video keeps working fine.
                        // Don't treat its closure as fatal; just stop pinging and leave real
                        // disconnect detection to ICE state (onIceConnectionChange already
                        // handles DISCONNECTED/FAILED with its own grace period and restart logic).
                        scope.launch {
                            if (!callActive.get()) return@launch
                            System.err.println("DesktopCallManager: heartbeat channel closed by peer — heartbeat disabled, call continues")
                            stopHeartbeat()
                        }
                    }
                    else -> {}
                }
            }
            override fun onMessage(buffer: RTCDataChannelBuffer) {
                val bytes = ByteArray(buffer.data.remaining())
                buffer.data.get(bytes)
                when (String(bytes, Charsets.UTF_8)) {
                    "ping" -> {
                        lastPongTime = System.currentTimeMillis()
                        sendHeartbeat("pong")
                    }
                    "pong" -> lastPongTime = System.currentTimeMillis()
                    "bye" -> {
                        // In-band hangup over the already-established P2P DataChannel — never
                        // touches the server, so it's invisible to it for this signal, not just
                        // anonymized. See Android CallManager's sendByeOverDataChannel for the
                        // full reasoning (server-routed call_end is one-shot with no redundancy).
                        scope.launch {
                            if (callActive.get()) handleCallEnd(peerId, "hangup")
                        }
                    }
                }
            }
        })
        if (dc.state == RTCDataChannelState.OPEN) {
            lastPongTime = System.currentTimeMillis()
            scope.launch { startHeartbeat() }
        }
    }

    private fun sendHeartbeat(msg: String) {
        val dc = heartbeatChannel ?: return
        try {
            if (dc.state == RTCDataChannelState.OPEN) {
                dc.send(RTCDataChannelBuffer(ByteBuffer.wrap(msg.toByteArray(Charsets.UTF_8)), false))
            }
        } catch (e: Exception) {
            System.err.println("DesktopCallManager: heartbeat send failed — ${e.message}")
        }
    }

    private fun startHeartbeat() {
        heartbeatJob?.cancel()
        heartbeatJob = scope.launch {
            while (isActive && callActive.get()) {
                val dc = heartbeatChannel
                if (dc == null || dc.state == RTCDataChannelState.CLOSED) break
                if (dc.state == RTCDataChannelState.OPEN) {
                    sendHeartbeat("ping")
                    val elapsed = System.currentTimeMillis() - lastPongTime
                    if (elapsed > HEARTBEAT_TIMEOUT_MS) {
                        // Same reasoning as the DataChannel-closed handler above.
                        System.err.println("DesktopCallManager: heartbeat timeout (${elapsed}ms) — heartbeat disabled, call continues")
                        break
                    }
                }
                delay(HEARTBEAT_INTERVAL_MS)
            }
        }
    }

    private fun stopHeartbeat() {
        heartbeatJob?.cancel()
        heartbeatJob = null
        heartbeatChannel = null
    }

    // ── Network-change watchdog ─────────────────────────────────────────────────
    // JVM has no direct equivalent of Android's ConnectivityManager callback, so we
    // poll active (non-loopback, up) interface addresses and treat a fingerprint
    // change as a network transition, retrying ICE the same way Android does.

    private fun networkFingerprint(): String = try {
        NetworkInterface.getNetworkInterfaces().asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.asSequence() }
            .map { it.hostAddress }
            .sorted()
            .joinToString(",")
    } catch (e: Exception) { "" }

    private fun startNetworkWatch() {
        networkWatchJob?.cancel()
        lastNetworkFingerprint = networkFingerprint()
        networkWatchJob = scope.launch {
            while (isActive && callActive.get()) {
                delay(NETWORK_POLL_MS)
                val fp = networkFingerprint()
                if (fp != lastNetworkFingerprint) {
                    lastNetworkFingerprint = fp
                    val pc = peerConnection ?: continue
                    val state = pc.iceConnectionState
                    if (isOfferer && (state == RTCIceConnectionState.DISCONNECTED || state == RTCIceConnectionState.FAILED)) {
                        System.err.println("DesktopCallManager: network change detected — retrying ICE")
                        disconnectJob?.cancel()
                        attemptIceRestart(pc, peerId)
                        disconnectJob = scope.launch {
                            delay(NETWORK_RESTART_GRACE_MS)
                            val current = peerConnection?.iceConnectionState
                            if (current == RTCIceConnectionState.DISCONNECTED || current == RTCIceConnectionState.FAILED) {
                                if (callActive.get()) hangUp()
                            }
                        }
                    }
                }
            }
        }
    }

    private fun stopNetworkWatch() {
        networkWatchJob?.cancel()
        networkWatchJob = null
    }

    private fun release() {
        if (!callActive.compareAndSet(true, false)) return
        disconnectJob?.cancel(); disconnectJob = null
        ringingTimeoutJob?.cancel(); ringingTimeoutJob = null
        stopHeartbeat()
        stopNetworkWatch()
        iceRestartDone = false
        peerConnection?.close()
        peerConnection = null
        localVideoTrack?.removeSink(localVideoSink)
        localVideoTrack = null
        videoSource?.stop()
        videoSource = null
        localAudioTrack = null
        pendingIceCandidates.clear()
        iceFlushJob?.cancel(); iceFlushJob = null
        synchronized(pendingOutgoingIce) { pendingOutgoingIce.clear() }
        pendingOffer = null
        preAcceptedCallIds.remove(callId)
        pendingRequestTarget = null
        incomingRequestFrom = null
        callId = ""
        isVideoCall = false
        peerId = ""
        isOfferer = false
        remoteVideoSink = null
        hideIpActive = false

        // Group-call cleanup — no-op (empty maps) for an ordinary 1:1 call.
        groupPeerConnections.values.forEach { pc -> try { pc.close() } catch (e: Exception) {} }
        groupPeerConnections.clear()
        groupRemoteVideoSinks.clear()
        groupPendingIce.clear()
        groupIceFlushJobs.values.forEach { it.cancel() }
        groupIceFlushJobs.clear()
        groupOutgoingIce.clear()
        groupPeers.clear()
        hideIpPerGroupPeer.clear()
        isGroupCall = false
        groupId = ""
    }

    // ── Group call (mesh) ────────────────────────────────────────────────────────
    // Direct port of Android CallManager.kt's startGroupCall/handleGroupInvite/
    // connectToPeer/handleGroupJoin/handleGroupPeerList (see this file's header
    // comment for what's intentionally NOT ported: per-peer heartbeat/ICE-restart/
    // network-watchdog). Wire types/fields match Android exactly for interop.

    /** Initiator side: fan out an invite to every member, then wait for each
     *  to accept before opening pairwise connections (mirrors Android: the
     *  invitee's acceptCall() is what actually calls connectToGroupPeer). */
    fun startGroupCall(gId: String, members: List<String>, video: Boolean) {
        if (UserStorage.getHideIpDuringCalls() && !NetworkConfig.TurnCredentials.isAvailable()) {
            System.err.println("DesktopCallManager: hide IP during calls is on but no TURN server is available — refusing to start group call $gId")
            onRelayUnavailable?.invoke()
            return
        }
        init()
        isGroupCall = true
        groupId = gId
        isVideoCall = video
        callId = UUID.randomUUID().toString()
        callActive.set(true)
        groupPeers.clear()
        groupPeers.addAll(
            members.filter { it != WebSocketClient.myFingerprint }.take(CALL_GROUP_PEER_LIST_MAX_COUNT)
        )
        createLocalTracks(video)
        groupPeers.forEach { member ->
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_group_invite")
                put("from", WebSocketClient.myFingerprint)
                put("to", member)
                put("call_id", callId)
                put("group_id", groupId)
                put("is_video", video)
            })
        }
    }

    /** Recipient side: reuses the SAME incoming-call ring UI/onIncomingCall
     *  callback as a 1:1 call — acceptCall() branches on isGroupCall to open
     *  a pairwise connection to the inviter instead of answering a single
     *  pending offer. */
    fun handleGroupInvite(from: String, cId: String, isVideo: Boolean, gId: String) {
        if (!isValidCallId(cId)) return
        if (callId.isNotEmpty() || pendingOffer != null || pendingRequestTarget != null) {
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_group_leave")
                put("from", WebSocketClient.myFingerprint)
                put("to", from)
                put("call_id", cId)
                put("reason", "busy")
            })
            return
        }
        isGroupCall = true
        groupId = gId
        callId = cId
        isVideoCall = isVideo
        peerId = from
        callActive.set(true)
        groupPeers.clear()
        groupPeers.add(from)
        onIncomingCall?.invoke(cId, from, isVideo)
        DesktopNotificationService.notifyIncomingCall(from, isVideo)

        ringingTimeoutJob?.cancel()
        ringingTimeoutJob = scope.launch {
            delay(RINGING_TIMEOUT_MS)
            if (callId == cId && groupPeerConnections.isEmpty()) {
                System.err.println("DesktopCallManager: group call ringing timeout — auto-declining")
                declineCall("timeout")
            }
        }
    }

    /** Opens (or no-ops if already open) a pairwise mesh connection to
     *  [remoteId] and sends it our offer. Called both when first accepting a
     *  group invite (against the inviter) and when a peer_list names peers
     *  we're not connected to yet. */
    private fun connectToGroupPeer(remoteId: String) {
        if (groupPeerConnections.containsKey(remoteId)) return
        val pc = createGroupPeerConnection(remoteId) ?: return
        pc.createOffer(RTCOfferOptions(), object : CreateSessionDescriptionObserver {
            override fun onSuccess(sdp: RTCSessionDescription) {
                pc.setLocalDescription(sdp, object : SetSessionDescriptionObserver {
                    override fun onSuccess() {
                        WebSocketClient.sendCallSignal(JSONObject().apply {
                            put("type", "call_group_join")
                            put("from", WebSocketClient.myFingerprint)
                            put("to", remoteId)
                            put("call_id", callId)
                            put("group_id", groupId)
                            put("sdp", sdp.sdp)
                        })
                    }
                    override fun onFailure(error: String) { System.err.println("DesktopCallManager: group setLocal(offer) fail — $error") }
                })
            }
            override fun onFailure(error: String) { System.err.println("DesktopCallManager: group createOffer fail — $error") }
        })
    }

    /** Like createPeerConnection(), but stores into groupPeerConnections[remoteId]
     *  instead of the singular 1:1 `peerConnection` field, and has none of the
     *  1:1 path's heartbeat/ICE-restart wiring — see this file's header comment. */
    private fun createGroupPeerConnection(remoteId: String): RTCPeerConnection? {
        val f = factory ?: return null
        val hideIp = UserStorage.getHideIpDuringCalls()
        if (hideIp && !NetworkConfig.TurnCredentials.isAvailable()) {
            System.err.println("DesktopCallManager: hide IP during calls is on but no TURN server is available — refusing group peer $remoteId")
            onRelayUnavailable?.invoke()
            return null
        }
        hideIpPerGroupPeer[remoteId] = hideIp
        val config = RTCConfiguration().apply {
            iceServers = this@DesktopCallManager.iceServers(hideIp)
            iceTransportPolicy = if (hideIp) RTCIceTransportPolicy.RELAY else RTCIceTransportPolicy.ALL
        }
        val pc = f.createPeerConnection(config, object : PeerConnectionObserver {
            override fun onIceCandidate(candidate: RTCIceCandidate) {
                queueGroupIceCandidate(remoteId, candidate)
            }
            override fun onTrack(transceiver: RTCRtpTransceiver) {
                val track = transceiver.receiver.track
                if (track is VideoTrack) {
                    val sink = VideoTrackSink { frame -> onRemoteVideoFrame?.invoke(remoteId, frame) }
                    groupRemoteVideoSinks[remoteId] = sink
                    track.addSink(sink)
                }
            }
            override fun onConnectionChange(state: RTCPeerConnectionState) {
                if (state == RTCPeerConnectionState.CONNECTED) {
                    scope.launch { onCallConnected?.invoke(remoteId) }
                }
            }
            override fun onIceConnectionChange(state: RTCIceConnectionState) {
                // Partial-mesh failure: drop just THIS peer after a grace
                // period, keep the call alive if others remain — mirrors
                // Android CallManager.kt's `if (peerConnections.size > 1)`
                // check. No retry/ICE-restart for group peers in this pass.
                if (state == RTCIceConnectionState.FAILED || state == RTCIceConnectionState.DISCONNECTED) {
                    scope.launch {
                        delay(DISCONNECT_GRACE_MS)
                        val current = groupPeerConnections[remoteId]?.iceConnectionState
                        if (current == RTCIceConnectionState.FAILED || current == RTCIceConnectionState.DISCONNECTED) {
                            dropGroupPeer(remoteId, notifyPeer = true)
                        }
                    }
                }
            }
            override fun onDataChannel(channel: RTCDataChannel) {}
        }) ?: return null

        localAudioTrack?.let { pc.addTrack(it, listOf("Subrosa-call")) }
        if (isVideoCall) {
            val lvt = localVideoTrack
            if (lvt != null) {
                pc.addTrack(lvt, listOf("Subrosa-call"))
            } else {
                // No camera on this side — same recv-only-transceiver
                // workaround as createPeerConnection() above, see its own
                // comment for why this is needed at all.
                try {
                    val dummySource = VideoDeviceSource()
                    val dummyTrack = f.createVideoTrack("LV_recvonly_${UUID.randomUUID()}", dummySource)
                    dummyTrack.setEnabled(false)
                    pc.addTransceiver(dummyTrack, RTCRtpTransceiverInit().apply {
                        direction = RTCRtpTransceiverDirection.RECV_ONLY
                    })
                } catch (e: Exception) {
                    System.err.println("DesktopCallManager: failed to add group recvonly video transceiver — ${e.message}")
                }
            }
        }

        groupPeerConnections[remoteId] = pc
        groupPeers.add(remoteId)
        return pc
    }

    private fun queueGroupIceCandidate(remoteId: String, candidate: RTCIceCandidate) {
        if (hideIpPerGroupPeer[remoteId] == true && !isRelayCandidate(candidate.sdp)) {
            System.err.println("DesktopCallManager: hide IP during calls — dropping non-relay group ICE candidate for $remoteId instead of signaling it")
            return
        }
        val entry = JSONObject().apply {
            put("sdp_mid", candidate.sdpMid)
            put("sdp_m_line_index", candidate.sdpMLineIndex)
            put("candidate", candidate.sdp)
        }
        val batch = groupOutgoingIce.getOrPut(remoteId) { mutableListOf() }
        val shouldFlushNow = synchronized(batch) {
            batch.add(entry)
            batch.size >= ICE_BATCH_MAX_SIZE
        }
        if (shouldFlushNow) {
            flushGroupIceCandidates(remoteId)
        } else {
            groupIceFlushJobs[remoteId]?.cancel()
            groupIceFlushJobs[remoteId] = scope.launch {
                delay(ICE_BATCH_DEBOUNCE_MS)
                flushGroupIceCandidates(remoteId)
            }
        }
    }

    private fun flushGroupIceCandidates(remoteId: String) {
        groupIceFlushJobs[remoteId]?.cancel()
        groupIceFlushJobs.remove(remoteId)
        val batch = groupOutgoingIce[remoteId] ?: return
        val copy = synchronized(batch) {
            if (batch.isEmpty()) return
            val c = batch.toList()
            batch.clear()
            c
        }
        WebSocketClient.sendCallSignal(JSONObject().apply {
            put("type", "call_ice_batch")
            put("from", WebSocketClient.myFingerprint)
            put("to", remoteId)
            put("candidates", org.json.JSONArray(copy))
        })
    }

    private fun drainGroupPendingIce(remoteId: String, pc: RTCPeerConnection) {
        groupPendingIce.remove(remoteId)?.forEach { pc.addIceCandidate(it) }
    }

    /** Receiving side of a pairwise mesh offer — answers it, then (mirrors
     *  Android's handleGroupJoin exactly) tells the new joiner about every
     *  OTHER peer already in the mesh via call_group_peer_list, so the
     *  joiner opens its own offers to them in turn. */
    fun handleGroupJoin(from: String, sdp: String, cId: String, gId: String) {
        if (!isValidCallSdp(sdp) || !isGroupCall || callId != cId) {
            System.err.println("DesktopCallManager: invalid/unexpected group_join from $from — ignored")
            return
        }
        val pc = createGroupPeerConnection(from) ?: return
        onPeerJoined?.invoke(from)
        val remoteSdp = RTCSessionDescription(RTCSdpType.OFFER, sdp)
        pc.setRemoteDescription(remoteSdp, object : SetSessionDescriptionObserver {
            override fun onSuccess() {
                drainGroupPendingIce(from, pc)
                pc.createAnswer(RTCAnswerOptions(), object : CreateSessionDescriptionObserver {
                    override fun onSuccess(answerSdp: RTCSessionDescription) {
                        pc.setLocalDescription(answerSdp, object : SetSessionDescriptionObserver {
                            override fun onSuccess() {
                                WebSocketClient.sendCallSignal(JSONObject().apply {
                                    put("type", "call_group_answer")
                                    put("from", WebSocketClient.myFingerprint)
                                    put("to", from)
                                    put("call_id", callId)
                                    put("group_id", groupId)
                                    put("sdp", answerSdp.sdp)
                                })
                                val existingPeers = groupPeerConnections.keys.filter { it != from }
                                if (existingPeers.isNotEmpty()) {
                                    WebSocketClient.sendCallSignal(JSONObject().apply {
                                        put("type", "call_group_peer_list")
                                        put("from", WebSocketClient.myFingerprint)
                                        put("to", from)
                                        put("call_id", callId)
                                        put("group_id", groupId)
                                        put("peers", org.json.JSONArray(existingPeers))
                                    })
                                }
                            }
                            override fun onFailure(error: String) {}
                        })
                    }
                    override fun onFailure(error: String) { System.err.println("DesktopCallManager: group createAnswer fail — $error") }
                })
            }
            override fun onFailure(error: String) { System.err.println("DesktopCallManager: group setRemote(offer) fail — $error") }
        })
    }

    fun handleGroupAnswer(from: String, sdp: String) {
        if (!isValidCallSdp(sdp)) return
        val pc = groupPeerConnections[from] ?: return
        val remoteSdp = RTCSessionDescription(RTCSdpType.ANSWER, sdp)
        pc.setRemoteDescription(remoteSdp, object : SetSessionDescriptionObserver {
            override fun onSuccess() { drainGroupPendingIce(from, pc) }
            override fun onFailure(error: String) { System.err.println("DesktopCallManager: group setRemote(answer) fail — $error") }
        })
    }

    /** Sent to a new joiner by whoever just answered its offer — connect to
     *  every peer named here we're not already connected to. */
    fun handleGroupPeerList(peers: List<String>) {
        if (!isGroupCall) return
        peers.take(CALL_GROUP_PEER_LIST_MAX_COUNT).forEach { peer ->
            if (peer != WebSocketClient.myFingerprint && !groupPeerConnections.containsKey(peer)) {
                connectToGroupPeer(peer)
            }
        }
    }

    fun handleGroupLeave(from: String, reason: String) {
        if (!isGroupCall) return
        dropGroupPeer(from, notifyPeer = false)
    }

    /** Tears down one mesh edge — either because that peer told us it's
     *  leaving (handleGroupLeave), or because its connection died and we're
     *  the one giving up on it (createGroupPeerConnection's ICE-failure
     *  branch, notifyPeer=true so IT also knows to stop waiting on us).
     *  Ends the whole call once no peers remain, mirroring Android's own
     *  "only hangUp() when the mesh is empty" behavior. */
    private fun dropGroupPeer(remoteId: String, notifyPeer: Boolean) {
        groupPeerConnections.remove(remoteId)?.let { pc -> try { pc.close() } catch (e: Exception) {} }
        groupRemoteVideoSinks.remove(remoteId)
        groupPendingIce.remove(remoteId)
        groupIceFlushJobs.remove(remoteId)?.cancel()
        groupOutgoingIce.remove(remoteId)
        groupPeers.remove(remoteId)
        hideIpPerGroupPeer.remove(remoteId)
        onPeerLeft?.invoke(remoteId)
        if (notifyPeer) {
            WebSocketClient.sendCallSignal(JSONObject().apply {
                put("type", "call_group_leave")
                put("from", WebSocketClient.myFingerprint)
                put("to", remoteId)
                put("call_id", callId)
                put("reason", "ice_failed")
            })
        }
        if (callActive.get() && groupPeerConnections.isEmpty()) {
            scope.launch { hangUp() }
        }
    }
}
