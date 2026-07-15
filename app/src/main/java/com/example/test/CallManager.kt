package com.bcon.messenger

import android.content.Context
import android.content.Intent
import android.media.AudioManager
import android.net.ConnectivityManager
import android.net.Network
import android.os.PowerManager
import android.util.Log
import org.json.JSONObject
import org.webrtc.*
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

object CallManager {

    private const val TAG = "CallManager"

    private val STUN_URL  get() = NetworkConfig.STUN_URL
    private val TURN_URL  get() = NetworkConfig.TURN_URL
    private val TURN_USER get() = NetworkConfig.TurnCredentials.username
    private val TURN_PASS get() = NetworkConfig.TurnCredentials.password

    private var factory: PeerConnectionFactory? = null
    private var eglBase: EglBase? = null

    val peerConnections = ConcurrentHashMap<String, PeerConnection>()

    var localAudioTrack: AudioTrack? = null
    var localVideoTrack: VideoTrack? = null
    private var videoCapturer: VideoCapturer? = null
    private var surfaceTextureHelper: SurfaceTextureHelper? = null

    var callId: String = ""
    var isGroupCall: Boolean = false
    var groupId: String = ""
    var isVideoCall: Boolean = false

    private var pendingOffer: Triple<String, String, String>? = null

    private val groupPeers = java.util.concurrent.CopyOnWriteArraySet<String>()

    var onIncomingCall: ((callId: String, from: String, isVideo: Boolean, isGroup: Boolean, groupId: String) -> Unit)? = null
    var onCallConnected: ((peerId: String) -> Unit)? = null
    var onCallEnded: ((reason: String) -> Unit)? = null
    var onPeerJoined: ((peerId: String) -> Unit)? = null

    private val pendingVideoTracks = ConcurrentHashMap<String, VideoTrack>()

    var onRemoteVideoTrack: ((peerId: String, track: VideoTrack) -> Unit)? = null
        set(value) {
            field = value

            if (value != null) {
                val iter = pendingVideoTracks.entries.iterator()
                while (iter.hasNext()) {
                    val entry = iter.next()
                    iter.remove()
                    value(entry.key, entry.value)
                }
            }
        }

    private var appContext: Context? = null
    private var isMuted = false
    private var isCameraOff = false
    private var isSpeakerOn = false
    private var audioManager: android.media.AudioManager? = null

    private val pendingIceCandidates = ConcurrentHashMap<String, MutableList<IceCandidate>>()

    var onLocalVideoTrackReady: ((VideoTrack) -> Unit)? = null

    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

    private val disconnectRunnables = ConcurrentHashMap<String, Runnable>()

    private val callActive = java.util.concurrent.atomic.AtomicBoolean(false)

    private val iceRestartDone = ConcurrentHashMap<String, Boolean>()

    private val restartingIce = ConcurrentHashMap<String, Boolean>()

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private var wakeLock: PowerManager.WakeLock? = null

    private val HEARTBEAT_INTERVAL_MS = 5_000L
    private val HEARTBEAT_TIMEOUT_MS  = 15_000L
    private val heartbeatChannels  = ConcurrentHashMap<String, DataChannel>()
    private val lastPongTime       = ConcurrentHashMap<String, Long>()
    private val heartbeatRunnables = ConcurrentHashMap<String, Runnable>()

    private const val RINGING_TIMEOUT_MS = 45_000L
    private var ringingTimeoutRunnable: Runnable? = null

    fun init(context: Context) {
        if (factory != null) return
        appContext = context.applicationContext
        eglBase = EglBase.create()
        PeerConnectionFactory.initialize(
            PeerConnectionFactory.InitializationOptions.builder(context.applicationContext)
                .setEnableInternalTracer(false)
                .createInitializationOptions()
        )

        val encoderFactory = DefaultVideoEncoderFactory(eglBase!!.eglBaseContext, false, false)
        val decoderFactory = DefaultVideoDecoderFactory(eglBase!!.eglBaseContext)
        factory = PeerConnectionFactory.builder()
            .setVideoEncoderFactory(encoderFactory)
            .setVideoDecoderFactory(decoderFactory)
            .createPeerConnectionFactory()
        Log.d(TAG, "PeerConnectionFactory initialized")
    }

    fun getEglBase(): EglBase? = eglBase

    private fun setupAudioForCall(context: Context, isVideo: Boolean) {
        val am = context.getSystemService(Context.AUDIO_SERVICE) as android.media.AudioManager
        audioManager = am

        am.mode = android.media.AudioManager.MODE_IN_COMMUNICATION

        am.isSpeakerphoneOn = isVideo
        isSpeakerOn = isVideo
        acquireWakeLock(context)
        registerNetworkCallback(context)
    }

    private fun createLocalTracks(context: Context, isVideo: Boolean) {
        val f = factory ?: return

        val audioConstraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("googEchoCancellation", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("googNoiseSuppression", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("googAutoGainControl", "true"))
        }
        localAudioTrack = f.createAudioTrack("LA_${UUID.randomUUID()}", f.createAudioSource(audioConstraints))
        localAudioTrack?.setEnabled(true)

        if (isVideo) {
            val camPerm = android.content.pm.PackageManager.PERMISSION_GRANTED
            if (context.checkSelfPermission(android.Manifest.permission.CAMERA) != camPerm) {
                Log.w(TAG, "CAMERA permission not granted — видеотрек не создан")
            } else {
                try {

                    val enumerator = Camera1Enumerator(false)
                    val deviceName = enumerator.deviceNames.firstOrNull { enumerator.isFrontFacing(it) }
                        ?: enumerator.deviceNames.firstOrNull()
                    if (deviceName != null) {
                        videoCapturer = enumerator.createCapturer(deviceName, object : CameraVideoCapturer.CameraEventsHandler {
                            override fun onCameraError(errorDescription: String) {
                                Log.e(TAG, "Camera ERROR: $errorDescription")
                            }
                            override fun onCameraDisconnected() {
                                Log.w(TAG, "Camera disconnected")
                            }
                            override fun onCameraFreezed(errorDescription: String) {
                                Log.e(TAG, "Camera frozen: $errorDescription")
                            }
                            override fun onCameraOpening(cameraName: String) {
                                Log.d(TAG, "Camera opening: $cameraName")
                            }
                            override fun onFirstFrameAvailable() {
                                Log.d(TAG, "First camera frame available")
                            }
                            override fun onCameraClosed() {
                                Log.d(TAG, "Camera closed")
                            }
                        })
                        surfaceTextureHelper = SurfaceTextureHelper.create("CaptureThread", eglBase!!.eglBaseContext)
                        val videoSource = f.createVideoSource(false)
                        videoCapturer?.initialize(surfaceTextureHelper, context, videoSource.capturerObserver)
                        videoCapturer?.startCapture(640, 480, 30)
                        localVideoTrack = f.createVideoTrack("LV_${UUID.randomUUID()}", videoSource)
                        localVideoTrack?.setEnabled(true)

                        localVideoTrack?.let { onLocalVideoTrackReady?.invoke(it) }
                        Log.d(TAG, "Видеотрек создан (Camera1): $deviceName")
                    } else {
                        Log.w(TAG, "Камера не найдена на устройстве")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Ошибка создания видеотрека: ${e.message}")
                }
            }
        }
    }

    private fun createPeerConnection(peerId: String, isOffer: Boolean): PeerConnection? {
        val f = factory ?: return null
        val iceServers = buildList {
            add(PeerConnection.IceServer.builder(STUN_URL).createIceServer())

            if (NetworkConfig.TurnCredentials.isAvailable()) {
                add(
                    PeerConnection.IceServer.builder(TURN_URL)
                        .setUsername(TURN_USER).setPassword(TURN_PASS).createIceServer()
                )
                Log.d(TAG, "ICE: STUN + TURN")
            } else {
                Log.w(TAG, "ICE: только STUN (TURN-credentials ещё не получены от сервера)")
            }
        }
        val config = PeerConnection.RTCConfiguration(iceServers).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY

            bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE

            iceCandidatePoolSize = 3
        }
        val pc = f.createPeerConnection(config, object : PeerConnection.Observer {
            override fun onIceCandidate(candidate: IceCandidate) {
                sendSignal(JSONObject().apply {
                    put("type", "call_ice")
                    put("to", peerId)
                    put("call_id", callId)
                    put("sdp_mid", candidate.sdpMid)
                    put("sdp_m_line_index", candidate.sdpMLineIndex)
                    put("candidate", candidate.sdp)
                })
            }
            override fun onTrack(transceiver: RtpTransceiver) {
                val track = transceiver.receiver.track()
                if (track is VideoTrack) {

                    android.os.Handler(android.os.Looper.getMainLooper()).post {
                        val cb = onRemoteVideoTrack
                        if (cb != null) {
                            cb(peerId, track)
                        } else {
                            pendingVideoTracks[peerId] = track
                        }
                    }
                }
            }
            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {
                Log.d(TAG, "ICE[$peerId]: $state")
                when (state) {
                    PeerConnection.IceConnectionState.CONNECTED,
                    PeerConnection.IceConnectionState.COMPLETED -> {

                        disconnectRunnables.remove(peerId)?.let { mainHandler.removeCallbacks(it) }

                        mainHandler.post { onCallConnected?.invoke(peerId) }
                    }
                    PeerConnection.IceConnectionState.FAILED -> {
                        Log.e(TAG, "ICE FAILED для $peerId")
                        disconnectRunnables.remove(peerId)?.let { mainHandler.removeCallbacks(it) }
                        if (peerConnections.size > 1) {

                            sendSignal(JSONObject().apply {
                                put("type", "call_group_leave")
                                put("to", peerId)
                                put("call_id", callId)
                                put("reason", "ice_failed")
                            })
                            stopHeartbeat(peerId)
                            heartbeatChannels.remove(peerId)
                            peerConnections.remove(peerId)?.close()
                            pendingIceCandidates.remove(peerId)
                            iceRestartDone.remove(peerId)
                            Log.w(TAG, "Пир $peerId удалён после ICE FAILED, звонок продолжается")
                        } else {

                            val alreadyTried = iceRestartDone.put(peerId, true) ?: false
                            val pc = peerConnections[peerId]
                            if (!alreadyTried && isOffer && pc != null) {
                                Log.w(TAG, "ICE FAILED — пробуем ICE restart для $peerId")
                                restartingIce[peerId] = true
                                pc.restartIce()

                                val runnable = Runnable {
                                    disconnectRunnables.remove(peerId)
                                    Log.w(TAG, "ICE restart не восстановил соединение — завершаем")
                                    hangUp()
                                }
                                disconnectRunnables[peerId] = runnable
                                mainHandler.postDelayed(runnable, 8_000L)
                            } else {
                                mainHandler.post { hangUp() }
                            }
                        }
                    }
                    PeerConnection.IceConnectionState.DISCONNECTED -> {

                        Log.w(TAG, "ICE DISCONNECTED для $peerId — ожидаем восстановления 7 сек")
                        disconnectRunnables.remove(peerId)?.let { mainHandler.removeCallbacks(it) }
                        val runnable = Runnable {
                            disconnectRunnables.remove(peerId)
                            val currentState = peerConnections[peerId]?.iceConnectionState()
                            if (currentState == PeerConnection.IceConnectionState.DISCONNECTED ||
                                currentState == PeerConnection.IceConnectionState.FAILED) {
                                Log.w(TAG, "ICE не восстановился за 7 сек — завершаем звонок")
                                hangUp()
                            }
                        }
                        disconnectRunnables[peerId] = runnable
                        mainHandler.postDelayed(runnable, 7_000L)
                    }
                    else -> {}
                }
            }
            override fun onSignalingChange(p0: PeerConnection.SignalingState?) {}
            override fun onIceConnectionReceivingChange(p0: Boolean) {}
            override fun onIceGatheringChange(p0: PeerConnection.IceGatheringState?) {}
            override fun onIceCandidatesRemoved(p0: Array<out IceCandidate>?) {}
            override fun onAddStream(p0: MediaStream?) {}
            override fun onRemoveStream(p0: MediaStream?) {}
            override fun onDataChannel(channel: DataChannel?) {
                val dc = channel ?: return
                if (dc.label() != "heartbeat") return

                mainHandler.post { setupHeartbeatChannel(peerId, dc) }
            }
            override fun onRenegotiationNeeded() {

                if (!callActive.get() || restartingIce[peerId] != true || !isOffer) return
                restartingIce.remove(peerId)
                val pc = peerConnections[peerId] ?: return
                val sdpConstraints = MediaConstraints().apply {
                    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
                    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", if (isVideoCall) "true" else "false"))
                }
                pc.createOffer(object : SdpObserver {
                    override fun onCreateSuccess(sdp: SessionDescription) {
                        pc.setLocalDescription(object : SdpObserver {
                            override fun onSetSuccess() {
                                sendSignal(JSONObject().apply {
                                    put("type", "call_ice_restart")
                                    put("to", peerId)
                                    put("call_id", callId)
                                    put("sdp", sdp.description)
                                })
                                Log.d(TAG, "ICE restart offer sent to $peerId")
                            }
                            override fun onSetFailure(p0: String?) { Log.e(TAG, "ICE restart setLocal fail: $p0") }
                            override fun onCreateSuccess(p0: SessionDescription?) {}
                            override fun onCreateFailure(p0: String?) {}
                        }, sdp)
                    }
                    override fun onCreateFailure(p0: String?) { Log.e(TAG, "ICE restart createOffer fail: $p0") }
                    override fun onSetSuccess() {}
                    override fun onSetFailure(p0: String?) {}
                }, sdpConstraints)
            }
            override fun onAddTrack(p0: RtpReceiver?, p1: Array<out MediaStream>?) {}
        }) ?: return null

        localAudioTrack?.let { pc.addTrack(it) }
        if (isVideoCall) localVideoTrack?.let { pc.addTrack(it) }

        peerConnections[peerId] = pc

        if (isOffer) {
            try {
                val dcInit = DataChannel.Init().apply {
                    ordered       = false
                    maxRetransmits = 0
                }
                val dc = pc.createDataChannel("heartbeat", dcInit)
                setupHeartbeatChannel(peerId, dc)
            } catch (e: Exception) {
                Log.w(TAG, "DataChannel creation failed for $peerId: ${e.message}")
            }
        }

        return pc
    }

    fun startCall(context: Context, targetId: String, isVideo: Boolean) {
        init(context)
        isVideoCall = isVideo
        isGroupCall = false
        callId = UUID.randomUUID().toString()
        callActive.set(true)
        setupAudioForCall(context, isVideo)
        createLocalTracks(context, isVideo)
        CallSoundManager.startRingback()

        val timeoutRunnable = Runnable {
            if (callActive.get()) {
                Log.w(TAG, "Ringing timeout: абонент не ответил, завершаем")
                hangUp()
            }
        }
        ringingTimeoutRunnable = timeoutRunnable
        mainHandler.postDelayed(timeoutRunnable, RINGING_TIMEOUT_MS)

        val pc = createPeerConnection(targetId, isOffer = true) ?: return
        val sdpConstraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", if (isVideo) "true" else "false"))
        }
        pc.createOffer(object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) {
                pc.setLocalDescription(object : SdpObserver {
                    override fun onSetSuccess() {
                        sendSignal(JSONObject().apply {
                            put("type", "call_offer")
                            put("to", targetId)
                            put("call_id", callId)
                            put("sdp", sdp.description)
                            put("is_video", isVideo)
                            put("is_group", false)
                        })
                    }
                    override fun onSetFailure(p0: String?) { Log.e(TAG, "setLocalDesc fail: $p0") }
                    override fun onCreateSuccess(p0: SessionDescription?) {}
                    override fun onCreateFailure(p0: String?) {}
                }, sdp)
            }
            override fun onCreateFailure(p0: String?) { Log.e(TAG, "createOffer fail: $p0") }
            override fun onSetSuccess() {}
            override fun onSetFailure(p0: String?) {}
        }, sdpConstraints)
    }

    fun startGroupCall(context: Context, gId: String, members: List<String>, isVideo: Boolean) {
        init(context)
        isVideoCall = isVideo
        isGroupCall = true
        groupId = gId
        callId = UUID.randomUUID().toString()
        callActive.set(true)
        setupAudioForCall(context, isVideo)
        createLocalTracks(context, isVideo)

        CallSoundManager.startRingback()

        val myId = UserStorage.getUserId(context)
        members.filter { it != myId }.forEach { memberId ->
            groupPeers.add(memberId)
            sendSignal(JSONObject().apply {
                put("type", "call_group_invite")
                put("to", memberId)
                put("call_id", callId)
                put("group_id", gId)
                put("is_video", isVideo)
            })
        }
    }

    fun acceptCall(context: Context) {
        CallSoundManager.stopAll()

        if (isGroupCall && pendingOffer == null) {
            init(context)
            setupAudioForCall(context, isVideoCall)
            createLocalTracks(context, isVideoCall)
            groupPeers.forEach { peerId -> connectToPeer(context, peerId) }
            return
        }
        val (from, offerSdp, cId) = pendingOffer ?: return
        pendingOffer = null
        init(context)
        setupAudioForCall(context, isVideoCall)
        createLocalTracks(context, isVideoCall)

        val pc = createPeerConnection(from, isOffer = false) ?: return
        val remoteSdp = SessionDescription(SessionDescription.Type.OFFER, offerSdp)
        pc.setRemoteDescription(object : SdpObserver {
            override fun onSetSuccess() {

                drainPendingIceCandidates(from, pc)
                val sdpConstraints = MediaConstraints().apply {
                    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
                    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", if (isVideoCall) "true" else "false"))
                }
                pc.createAnswer(object : SdpObserver {
                    override fun onCreateSuccess(sdp: SessionDescription) {
                        pc.setLocalDescription(object : SdpObserver {
                            override fun onSetSuccess() {
                                val msgType = if (isGroupCall) "call_group_answer" else "call_answer"
                                sendSignal(JSONObject().apply {
                                    put("type", msgType)
                                    put("to", from)
                                    put("call_id", cId)
                                    put("sdp", sdp.description)
                                    if (isGroupCall) put("group_id", groupId)
                                })
                            }
                            override fun onSetFailure(p0: String?) {}
                            override fun onCreateSuccess(p0: SessionDescription?) {}
                            override fun onCreateFailure(p0: String?) {}
                        }, sdp)
                    }
                    override fun onCreateFailure(p0: String?) { Log.e(TAG, "createAnswer fail: $p0") }
                    override fun onSetSuccess() {}
                    override fun onSetFailure(p0: String?) {}
                }, sdpConstraints)
            }
            override fun onSetFailure(p0: String?) { Log.e(TAG, "setRemoteDesc fail: $p0") }
            override fun onCreateSuccess(p0: SessionDescription?) {}
            override fun onCreateFailure(p0: String?) {}
        }, remoteSdp)

        if (isGroupCall) {
            groupPeers.filter { it != from }.forEach { peerId ->
                connectToPeer(context, peerId)
            }
        }
    }

    private fun connectToPeer(context: Context, peerId: String) {
        if (peerConnections.containsKey(peerId)) return
        val pc = createPeerConnection(peerId, isOffer = true) ?: return
        val sdpConstraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", if (isVideoCall) "true" else "false"))
        }
        pc.createOffer(object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) {
                pc.setLocalDescription(object : SdpObserver {
                    override fun onSetSuccess() {
                        sendSignal(JSONObject().apply {
                            put("type", "call_group_join")
                            put("to", peerId)
                            put("call_id", callId)
                            put("group_id", groupId)
                            put("sdp", sdp.description)
                        })
                    }
                    override fun onSetFailure(p0: String?) {}
                    override fun onCreateSuccess(p0: SessionDescription?) {}
                    override fun onCreateFailure(p0: String?) {}
                }, sdp)
            }
            override fun onCreateFailure(p0: String?) {}
            override fun onSetSuccess() {}
            override fun onSetFailure(p0: String?) {}
        }, sdpConstraints)
    }

    fun declineCall() {
        CallSoundManager.stopAll()
        val offer = pendingOffer
        if (offer != null) {

            sendSignal(JSONObject().apply {
                put("type", "call_end")
                put("to", offer.first)
                put("call_id", offer.third)
                put("reason", "decline")
            })
        } else if (isGroupCall && callId.isNotEmpty()) {

            val initiator = groupPeers.firstOrNull()
            if (initiator != null) {
                sendSignal(JSONObject().apply {
                    put("type", "call_end")
                    put("to", initiator)
                    put("call_id", callId)
                    put("reason", "decline")
                })
            }
        }

        pendingOffer = null
        callId = ""
        callActive.set(false)
        isGroupCall = false
        isVideoCall = false
        groupId = ""
        groupPeers.clear()
        pendingIceCandidates.clear()
    }

    fun hangUp() {
        peerConnections.keys.toList().forEach { peerId ->
            sendSignal(JSONObject().apply {
                put("type", if (isGroupCall) "call_group_leave" else "call_end")
                put("to", peerId)
                put("call_id", callId)
                put("reason", "hangup")
            })
        }
        if (release()) {
            onCallEnded?.invoke("hangup")
        }
    }

    fun toggleMute(): Boolean {
        isMuted = !isMuted
        localAudioTrack?.setEnabled(!isMuted)
        return isMuted
    }

    fun toggleCamera(): Boolean {
        isCameraOff = !isCameraOff
        localVideoTrack?.setEnabled(!isCameraOff)
        return isCameraOff
    }

    fun switchCamera() {
        (videoCapturer as? CameraVideoCapturer)?.switchCamera(null)
    }

    fun toggleSpeaker(context: Context): Boolean {
        isSpeakerOn = !isSpeakerOn
        val am = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        am.isSpeakerphoneOn = isSpeakerOn
        return isSpeakerOn
    }

    fun handleOffer(from: String, sdp: String, cId: String, isVideo: Boolean, isGroup: Boolean, gId: String) {

        if (callId.isNotEmpty() || pendingOffer != null) {
            sendSignal(JSONObject().apply {
                put("type", "call_end")
                put("to", from)
                put("call_id", cId)
                put("reason", "busy")
            })
            return
        }
        callId = cId
        callActive.set(true)
        isVideoCall = isVideo
        isGroupCall = isGroup
        groupId = gId
        pendingOffer = Triple(from, sdp, cId)
        appContext?.let { CallSoundManager.startRingtone(it) }
        onIncomingCall?.invoke(cId, from, isVideo, isGroup, gId)
    }

    fun handleGroupInvite(from: String, cId: String, isVideo: Boolean, gId: String) {

        if (callId.isNotEmpty() || pendingOffer != null) {
            sendSignal(JSONObject().apply {
                put("type", "call_end")
                put("to", from)
                put("call_id", cId)
                put("reason", "busy")
            })
            return
        }
        callId = cId
        callActive.set(true)
        isVideoCall = isVideo
        isGroupCall = true
        groupId = gId
        groupPeers.add(from)
        appContext?.let { CallSoundManager.startRingtone(it) }
        onIncomingCall?.invoke(cId, from, isVideo, true, gId)
    }

    fun handleAnswer(from: String, sdp: String) {
        CallSoundManager.stopAll()

        ringingTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }
        ringingTimeoutRunnable = null
        val pc = peerConnections[from] ?: return
        val remoteSdp = SessionDescription(SessionDescription.Type.ANSWER, sdp)
        pc.setRemoteDescription(object : SdpObserver {
            override fun onSetSuccess() {
                Log.d(TAG, "Remote answer set for $from")
                drainPendingIceCandidates(from, pc)
            }
            override fun onSetFailure(p0: String?) { Log.e(TAG, "setRemote answer fail: $p0") }
            override fun onCreateSuccess(p0: SessionDescription?) {}
            override fun onCreateFailure(p0: String?) {}
        }, remoteSdp)
    }

    fun handleGroupJoin(from: String, sdp: String, cId: String) {

        groupPeers.add(from)

        android.os.Handler(android.os.Looper.getMainLooper()).post { onPeerJoined?.invoke(from) }
        val pc = createPeerConnection(from, isOffer = false) ?: return
        val remoteSdp = SessionDescription(SessionDescription.Type.OFFER, sdp)
        pc.setRemoteDescription(object : SdpObserver {
            override fun onSetSuccess() {
                drainPendingIceCandidates(from, pc)
                val groupAnswerConstraints = MediaConstraints().apply {
                    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
                    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", if (isVideoCall) "true" else "false"))
                }
                pc.createAnswer(object : SdpObserver {
                    override fun onCreateSuccess(sdp: SessionDescription) {
                        pc.setLocalDescription(object : SdpObserver {
                            override fun onSetSuccess() {
                                sendSignal(JSONObject().apply {
                                    put("type", "call_group_answer")
                                    put("to", from)
                                    put("call_id", cId)
                                    put("group_id", groupId)
                                    put("sdp", sdp.description)
                                })

                                val existingPeers = peerConnections.keys.filter { it != from }
                                if (existingPeers.isNotEmpty()) {
                                    sendSignal(JSONObject().apply {
                                        put("type", "call_group_peer_list")
                                        put("to", from)
                                        put("call_id", cId)
                                        put("group_id", groupId)
                                        put("peers", org.json.JSONArray(existingPeers))
                                    })
                                }
                            }
                            override fun onSetFailure(p0: String?) {}
                            override fun onCreateSuccess(p0: SessionDescription?) {}
                            override fun onCreateFailure(p0: String?) {}
                        }, sdp)
                    }
                    override fun onCreateFailure(p0: String?) {}
                    override fun onSetSuccess() {}
                    override fun onSetFailure(p0: String?) {}
                }, groupAnswerConstraints)
            }
            override fun onSetFailure(p0: String?) {}
            override fun onCreateSuccess(p0: SessionDescription?) {}
            override fun onCreateFailure(p0: String?) {}
        }, remoteSdp)
    }

    fun handleGroupPeerList(peers: List<String>) {

        val ctx = appContext ?: return
        peers.filter { !peerConnections.containsKey(it) }.forEach { peerId ->
            groupPeers.add(peerId)
            connectToPeer(ctx, peerId)
        }
    }

    fun handleIceCandidate(from: String, sdpMid: String, sdpMLineIndex: Int, candidate: String) {
        val ice = IceCandidate(sdpMid, sdpMLineIndex, candidate)
        val pc = peerConnections[from]
        if (pc == null || pc.remoteDescription == null) {

            pendingIceCandidates.getOrPut(from) { mutableListOf() }.add(ice)
            Log.d(TAG, "ICE buffered for $from (pc=${pc != null}, remoteDesc=${pc?.remoteDescription != null})")
        } else {
            pc.addIceCandidate(ice)
        }
    }

    private fun drainPendingIceCandidates(peerId: String, pc: PeerConnection) {
        val pending = pendingIceCandidates.remove(peerId) ?: return
        Log.d(TAG, "Applying ${pending.size} buffered ICE candidates for $peerId")
        pending.forEach { pc.addIceCandidate(it) }
    }

    fun handleCallEnd(from: String, reason: String) {

        if (callId.isEmpty()) return

        disconnectRunnables.remove(from)?.let { mainHandler.removeCallbacks(it) }
        stopHeartbeat(from)
        heartbeatChannels.remove(from)
        iceRestartDone.remove(from)
        peerConnections[from]?.close()
        peerConnections.remove(from)
        pendingIceCandidates.remove(from)
        if (peerConnections.isEmpty()) {
            if (release()) {

                mainHandler.post { onCallEnded?.invoke(reason) }
            }
        }
    }

    fun handleIceRestart(from: String, sdp: String) {
        val pc = peerConnections[from] ?: return

        disconnectRunnables.remove(from)?.let { mainHandler.removeCallbacks(it) }
        iceRestartDone.remove(from)
        val remoteSdp = SessionDescription(SessionDescription.Type.OFFER, sdp)
        pc.setRemoteDescription(object : SdpObserver {
            override fun onSetSuccess() {
                drainPendingIceCandidates(from, pc)
                pc.createAnswer(object : SdpObserver {
                    override fun onCreateSuccess(sdp: SessionDescription) {
                        pc.setLocalDescription(object : SdpObserver {
                            override fun onSetSuccess() {
                                sendSignal(JSONObject().apply {
                                    put("type", "call_answer")
                                    put("to", from)
                                    put("call_id", callId)
                                    put("sdp", sdp.description)
                                })
                                Log.d(TAG, "ICE restart answer sent to $from")
                            }
                            override fun onSetFailure(p0: String?) {}
                            override fun onCreateSuccess(p0: SessionDescription?) {}
                            override fun onCreateFailure(p0: String?) {}
                        }, sdp)
                    }
                    override fun onCreateFailure(p0: String?) { Log.e(TAG, "ICE restart answer fail: $p0") }
                    override fun onSetSuccess() {}
                    override fun onSetFailure(p0: String?) {}
                }, MediaConstraints())
            }
            override fun onSetFailure(p0: String?) { Log.e(TAG, "ICE restart setRemote fail: $p0") }
            override fun onCreateSuccess(p0: SessionDescription?) {}
            override fun onCreateFailure(p0: String?) {}
        }, remoteSdp)
    }

    private fun registerNetworkCallback(context: Context) {
        if (networkCallback != null) return
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (!callActive.get()) return
                Log.d(TAG, "Сеть появилась — проверяем ICE-состояние активных пиров")
                peerConnections.forEach { (peerId, pc) ->
                    val state = pc.iceConnectionState()
                    if (state == PeerConnection.IceConnectionState.DISCONNECTED ||
                        state == PeerConnection.IceConnectionState.FAILED) {

                        disconnectRunnables.remove(peerId)?.let { mainHandler.removeCallbacks(it) }
                        Log.d(TAG, "ICE $state для $peerId — пробуем restart после смены сети")
                        restartingIce[peerId] = true
                        pc.restartIce()
                        val runnable = Runnable {
                            disconnectRunnables.remove(peerId)
                            val s = peerConnections[peerId]?.iceConnectionState()
                            if (s == PeerConnection.IceConnectionState.DISCONNECTED ||
                                s == PeerConnection.IceConnectionState.FAILED) {
                                if (callActive.get()) hangUp()
                            }
                        }
                        disconnectRunnables[peerId] = runnable
                        mainHandler.postDelayed(runnable, 10_000L)
                    }
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "registerNetworkCallback failed: ${e.message}")
            networkCallback = null
        }
    }

    private fun unregisterNetworkCallback(context: Context) {
        val cb = networkCallback ?: return
        networkCallback = null
        try {
            (context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                .unregisterNetworkCallback(cb)
        } catch (e: Exception) {  }
    }

    private fun acquireWakeLock(context: Context) {
        if (wakeLock?.isHeld == true) return
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Beacon:CallWakeLock").apply {
            acquire(60 * 60 * 1000L)
        }
        Log.d(TAG, "WakeLock acquired")
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    private fun sendSignal(data: JSONObject) {
        val ctx = appContext ?: return
        if (!data.has("from")) {
            val myId = UserStorage.getUserId(ctx)
            if (myId.isNotBlank()) data.put("from", myId)
        }
        ctx.startService(Intent(ctx, MessengerService::class.java).apply {
            putExtra("call_signal", data.toString())
        })
    }

    private fun setupHeartbeatChannel(peerId: String, dc: DataChannel) {
        heartbeatChannels[peerId] = dc
        dc.registerObserver(object : DataChannel.Observer {
            override fun onBufferedAmountChange(p0: Long) {}

            override fun onStateChange() {
                when (dc.state()) {
                    DataChannel.State.OPEN -> {
                        lastPongTime[peerId] = System.currentTimeMillis()
                        mainHandler.post { startHeartbeat(peerId) }
                    }
                    DataChannel.State.CLOSED -> {

                        mainHandler.post {
                            if (!callActive.get()) return@post
                            Log.w(TAG, "DataChannel closed by $peerId — завершаем звонок")
                            stopHeartbeat(peerId)
                            if (peerConnections.size > 1) {
                                heartbeatChannels.remove(peerId)
                                peerConnections.remove(peerId)?.close()
                                pendingIceCandidates.remove(peerId)
                                iceRestartDone.remove(peerId)
                            } else {
                                hangUp()
                            }
                        }
                    }
                    else -> {}
                }
            }

            override fun onMessage(buffer: DataChannel.Buffer) {
                val bytes = ByteArray(buffer.data.remaining())
                buffer.data.get(bytes)
                when (String(bytes, Charsets.UTF_8)) {
                    "ping" -> {
                        lastPongTime[peerId] = System.currentTimeMillis()
                        try {
                            if (dc.state() == DataChannel.State.OPEN) {
                                dc.send(DataChannel.Buffer(
                                    ByteBuffer.wrap("pong".toByteArray(Charsets.UTF_8)), false
                                ))
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Heartbeat pong send failed: ${e.message}")
                        }
                    }
                    "pong" -> lastPongTime[peerId] = System.currentTimeMillis()
                }
            }
        })

        if (dc.state() == DataChannel.State.OPEN) {
            lastPongTime[peerId] = System.currentTimeMillis()
            mainHandler.post { startHeartbeat(peerId) }
        }
    }

    private fun startHeartbeat(peerId: String) {
        stopHeartbeat(peerId)
        val runnable = object : Runnable {
            override fun run() {
                if (!callActive.get()) return
                val dc = heartbeatChannels[peerId]

                if (dc == null || dc.state() == DataChannel.State.CLOSED) return
                if (dc.state() == DataChannel.State.OPEN) {
                    try {
                        dc.send(DataChannel.Buffer(
                            ByteBuffer.wrap("ping".toByteArray(Charsets.UTF_8)), false
                        ))
                    } catch (e: Exception) {
                        Log.w(TAG, "Heartbeat ping send failed: ${e.message}")
                    }
                    val elapsed = System.currentTimeMillis() - (lastPongTime[peerId] ?: 0L)
                    if (elapsed > HEARTBEAT_TIMEOUT_MS) {
                        Log.w(TAG, "Heartbeat timeout для $peerId (${elapsed}ms)")
                        stopHeartbeat(peerId)
                        if (peerConnections.size > 1) {
                            heartbeatChannels.remove(peerId)
                            peerConnections.remove(peerId)?.close()
                            pendingIceCandidates.remove(peerId)
                            iceRestartDone.remove(peerId)
                            Log.w(TAG, "Пир $peerId удалён по heartbeat timeout")
                        } else {
                            hangUp()
                        }
                        return
                    }
                }
                mainHandler.postDelayed(this, HEARTBEAT_INTERVAL_MS)
            }
        }
        heartbeatRunnables[peerId] = runnable
        mainHandler.postDelayed(runnable, HEARTBEAT_INTERVAL_MS)
    }

    private fun stopHeartbeat(peerId: String) {
        heartbeatRunnables.remove(peerId)?.let { mainHandler.removeCallbacks(it) }
    }

    fun release(): Boolean {

        if (!callActive.compareAndSet(true, false)) return false

        ringingTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }
        ringingTimeoutRunnable = null

        disconnectRunnables.values.forEach { mainHandler.removeCallbacks(it) }
        disconnectRunnables.clear()
        onLocalVideoTrackReady = null

        CallSoundManager.stopAll()

        heartbeatRunnables.values.forEach { mainHandler.removeCallbacks(it) }
        heartbeatRunnables.clear()
        heartbeatChannels.clear()
        lastPongTime.clear()
        peerConnections.values.forEach { it.close() }
        peerConnections.clear()
        groupPeers.clear()
        pendingIceCandidates.clear()
        pendingVideoTracks.clear()

        try { videoCapturer?.stopCapture() } catch (e: Exception) { Log.w(TAG, "stopCapture: ${e.message}") }

        localVideoTrack?.dispose()
        localVideoTrack = null

        videoCapturer?.dispose()
        videoCapturer = null
        surfaceTextureHelper?.dispose()
        surfaceTextureHelper = null
        localAudioTrack?.dispose()
        localAudioTrack = null
        callId = ""
        isVideoCall = false
        isGroupCall = false
        groupId = ""
        pendingOffer = null
        isMuted = false
        isCameraOff = false
        isSpeakerOn = false
        audioManager?.let { am ->
            am.isSpeakerphoneOn = false
            am.mode = android.media.AudioManager.MODE_NORMAL

        }
        audioManager = null
        releaseWakeLock()
        appContext?.let { unregisterNetworkCallback(it) }
        iceRestartDone.clear()
        restartingIce.clear()
        Log.d(TAG, "CallManager released")
        return true
    }
}
