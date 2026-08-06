package com.subrosa.messenger

import android.annotation.SuppressLint
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMuxer
import android.widget.VideoView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import android.util.Rational
import android.view.Surface
import androidx.camera.core.CameraSelector
import androidx.camera.core.Preview
import androidx.camera.core.UseCaseGroup
import androidx.camera.core.ViewPort
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.video.FileOutputOptions
import androidx.camera.video.Quality
import androidx.camera.video.QualitySelector
import androidx.camera.video.Recorder
import androidx.camera.video.Recording
import androidx.camera.video.VideoCapture
import androidx.camera.video.VideoRecordEvent
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.ui.res.painterResource
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.ByteBuffer
import java.util.UUID

@Composable
fun VideoCircleRecorder(
    onSend: (File, Int) -> Unit,
    onCancel: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    val mainExecutor = ContextCompat.getMainExecutor(context)

    var isRecording by remember { mutableStateOf(false) }
    var isLocked by remember { mutableStateOf(false) }
    var recordingSeconds by remember { mutableStateOf(0) }
    var timerJob by remember { mutableStateOf<Job?>(null) }
    var useFrontCamera by remember { mutableStateOf(true) }
    var pendingAutoRestart by remember { mutableStateOf(false) }

    var activeRecording by remember { mutableStateOf<Recording?>(null) }
    var videoCapture by remember { mutableStateOf<VideoCapture<Recorder>?>(null) }
    var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    var previewViewRef by remember { mutableStateOf<PreviewView?>(null) }

    val outputFiles = remember { mutableListOf<File>() }

    val currentSegmentDeferred = remember { mutableStateOf<CompletableDeferred<File?>?>(null) }

    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {  }

    LaunchedEffect(Unit) {
        val cam = context.checkSelfPermission(android.Manifest.permission.CAMERA)
        val audio = context.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO)
        val denied = android.content.pm.PackageManager.PERMISSION_DENIED
        if (cam == denied || audio == denied) {
            permLauncher.launch(arrayOf(
                android.Manifest.permission.CAMERA,
                android.Manifest.permission.RECORD_AUDIO
            ))
        }
    }

    fun stopAndFinish(send: Boolean) {
        timerJob?.cancel(); timerJob = null
        val rec = activeRecording
        val duration = recordingSeconds
        activeRecording = null
        isRecording = false
        isLocked = false
        pendingAutoRestart = false

        if (send) {
            scope.launch {

                if (rec != null) rec.stop()
                currentSegmentDeferred.value?.await()

                val files = outputFiles.toList()
                outputFiles.clear()

                if (files.isNotEmpty()) {
                    val result = withContext(Dispatchers.IO) {
                        if (files.size == 1) files[0]
                        else mergeVideoSegments(files, context)
                    }
                    if (result != null && result.exists() && result.length() > 0) {
                        onSend(result, duration)
                    } else {
                        result?.delete()
                        onCancel()
                    }
                } else {
                    onCancel()
                }
            }
        } else {
            rec?.stop()
            scope.launch {
                runCatching { currentSegmentDeferred.value?.await() }
                outputFiles.forEach { runCatching { it.delete() } }
                outputFiles.clear()
            }
            onCancel()
        }
    }

    fun switchCamera() {
        if (isRecording) {
            val rec = activeRecording
            activeRecording = null
            pendingAutoRestart = true
            rec?.stop()
        }
        useFrontCamera = !useFrontCamera
    }

    @SuppressLint("MissingPermission")
    fun startRecording() {
        val vc = videoCapture ?: return
        val videoId = UUID.randomUUID().toString()
        val file = File(context.cacheDir, "video_rec_$videoId.mp4").apply { parentFile?.mkdirs() }

        val deferred = CompletableDeferred<File?>()
        currentSegmentDeferred.value = deferred

        try {
            val rec = vc.output
                .prepareRecording(context, FileOutputOptions.Builder(file).build())
                .withAudioEnabled()
                .start(mainExecutor) { event ->
                    when (event) {
                        is VideoRecordEvent.Start ->
                            android.util.Log.d("VideoCircle", "Сегмент начат")
                        is VideoRecordEvent.Finalize -> {
                            if (event.hasError()) {
                                android.util.Log.e("VideoCircle", "Ошибка сегмента: ${event.cause}")
                                deferred.complete(null)
                            } else {
                                android.util.Log.d("VideoCircle", "Сегмент готов: ${file.length()} байт")
                                outputFiles.add(file)
                                deferred.complete(file)
                            }
                        }
                        else -> {}
                    }
                }
            activeRecording = rec
            isRecording = true

            if (timerJob == null) {
                recordingSeconds = 0
                timerJob = scope.launch {
                    repeat(60) {
                        delay(1000)
                        recordingSeconds++
                    }
                    stopAndFinish(true)
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("VideoCircle", "startRecording error: ${e.message}")
        }
    }

    LaunchedEffect(Unit) {
        val future = ProcessCameraProvider.getInstance(context)
        cameraProvider = withContext(Dispatchers.IO) { future.get() }
    }

    LaunchedEffect(cameraProvider, previewViewRef, useFrontCamera) {
        val provider = cameraProvider ?: return@LaunchedEffect
        val pv = previewViewRef ?: return@LaunchedEffect

        if (pendingAutoRestart) {
            currentSegmentDeferred.value?.await()
        }

        val preview = Preview.Builder().build().also {
            it.setSurfaceProvider(pv.surfaceProvider)
        }
        val recorder = Recorder.Builder()
            .setQualitySelector(QualitySelector.from(Quality.SD))
            .build()
        val vc = VideoCapture.withOutput(recorder)
        videoCapture = vc

        val preferred = if (useFrontCamera) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA
        val fallback  = if (useFrontCamera) CameraSelector.DEFAULT_BACK_CAMERA  else CameraSelector.DEFAULT_FRONT_CAMERA

        val viewport = ViewPort.Builder(Rational(1, 1), Surface.ROTATION_0).build()
        val useCaseGroup = UseCaseGroup.Builder()
            .addUseCase(preview)
            .addUseCase(vc)
            .setViewPort(viewport)
            .build()

        try {
            provider.unbindAll()
            provider.bindToLifecycle(lifecycleOwner, preferred, useCaseGroup)
        } catch (e: Exception) {
            try {
                provider.unbindAll()
                provider.bindToLifecycle(lifecycleOwner, fallback, useCaseGroup)
            } catch (e2: Exception) {
                android.util.Log.e("VideoCircle", "Камера недоступна: ${e2.message}")
            }
        }

        if (pendingAutoRestart) {
            pendingAutoRestart = false
            delay(150)
            startRecording()
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            timerJob?.cancel()
            activeRecording?.stop()
            cameraProvider?.unbindAll()
            outputFiles.forEach { runCatching { it.delete() } }
            outputFiles.clear()
        }
    }

    val isRecordingState = rememberUpdatedState(isRecording)
    val isLockedState = rememberUpdatedState(isLocked)

    Dialog(
        onDismissRequest = { stopAndFinish(false) },
        properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnBackPress = true)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xCC000000)),
            contentAlignment = Alignment.Center
        ) {

            Box(
                modifier = Modifier.size(280.dp),
                contentAlignment = Alignment.Center
            ) {
                Box(
                    modifier = Modifier
                        .size(272.dp)
                        .clip(CircleShape)
                ) {
                    AndroidView(
                        factory = { ctx ->
                            PreviewView(ctx).apply {
                                scaleType = PreviewView.ScaleType.FILL_CENTER
                                previewViewRef = this
                            }
                        },
                        modifier = Modifier.fillMaxSize()
                    )
                }

                if (isRecording) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val sweepAngle = (recordingSeconds / 60f) * 360f
                        val strokeW = 7.dp.toPx()
                        val inset = strokeW / 2f
                        drawArc(
                            color = Color(0xFF4CAF50),
                            startAngle = -90f,
                            sweepAngle = sweepAngle,
                            useCenter = false,
                            topLeft = Offset(inset, inset),
                            size = Size(size.width - strokeW, size.height - strokeW),
                            style = Stroke(width = strokeW, cap = StrokeCap.Round)
                        )
                    }
                }
            }

            if (isRecording) {
                Box(
                    modifier = Modifier
                        .offset(y = (-170).dp)
                        .background(Color(0x88000000), CircleShape)
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Text("${recordingSeconds}\"", color = Color.White, fontSize = 15.sp, fontFamily = JetBrainsMono)
                }
            }

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(bottom = 48.dp),
                contentAlignment = Alignment.BottomCenter
            ) {
                if (!isLocked) {
                    Box(
                        modifier = Modifier
                            .size(76.dp)
                            .clip(CircleShape)
                            .background(
                                if (isRecording) Color(0xFFE53935)
                                else Color(0xCCFFFFFF)
                            )
                            .pointerInput(Unit) {
                                awaitPointerEventScope {
                                    while (true) {
                                        val down = awaitPointerEvent()
                                        if (down.type == PointerEventType.Press) {
                                            if (!isRecordingState.value) {
                                                startRecording()
                                            }
                                            val startY = down.changes.first().position.y
                                            var locked = false

                                            while (true) {
                                                val moveEvent = awaitPointerEvent()
                                                val change = moveEvent.changes.firstOrNull() ?: break

                                                if (!change.pressed) {
                                                    if (!locked && isRecordingState.value) {
                                                        stopAndFinish(true)
                                                    }
                                                    break
                                                }

                                                val dy = change.position.y - startY
                                                if (dy < -80f && !locked) {
                                                    locked = true
                                                    isLocked = true
                                                }
                                                change.consume()
                                            }
                                        }
                                    }
                                }
                            },
                        contentAlignment = Alignment.Center
                    ) {
                        if (!isRecording) {
                            Box(
                                modifier = Modifier
                                    .size(60.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFFE53935))
                            )
                        }
                    }

                    if (!isRecording) {
                        Text(
                            "Удержи для записи",
                            color = Color(0xAAFFFFFF),
                            fontSize = 13.sp,
                            fontFamily = JetBrainsMono,
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .padding(bottom = 88.dp)
                        )
                    }

                    if (isRecording) {
                        Text(
                            "↑ Свайп для фиксации",
                            color = Color(0x99FFFFFF),
                            fontSize = 12.sp,
                            fontFamily = JetBrainsMono,
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .padding(bottom = 88.dp)
                        )
                    }
                } else {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 48.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(64.dp)
                                .clip(CircleShape)
                                .background(Color(0x99FF3333))
                                .pointerInput(Unit) {
                                    awaitPointerEventScope {
                                        awaitPointerEvent()
                                        stopAndFinish(false)
                                    }
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.ic_close),
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(28.dp)
                            )
                        }

                        Box(
                            modifier = Modifier
                                .size(64.dp)
                                .clip(CircleShape)
                                .background(Color(0xFF4CAF50))
                                .pointerInput(Unit) {
                                    awaitPointerEventScope {
                                        awaitPointerEvent()
                                        stopAndFinish(true)
                                    }
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.ic_check),
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(28.dp)
                            )
                        }
                    }
                }
            }

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(top = 24.dp, end = 24.dp),
                contentAlignment = Alignment.TopEnd
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(Color(0x66000000))
                        .pointerInput(Unit) {
                            awaitPointerEventScope {
                                awaitPointerEvent()
                                stopAndFinish(false)
                            }
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(top = 24.dp, start = 24.dp),
                contentAlignment = Alignment.TopStart
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .clip(CircleShape)
                            .background(Color(0x88000000))
                            .clickable(
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null
                            ) { switchCamera() },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_flip_camera),
                            contentDescription = "Переключить камеру",
                            tint = Color.White,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "Камера",
                        color = Color(0xAAFFFFFF),
                        fontSize = 10.sp,
                        fontFamily = JetBrainsMono
                    )
                }
            }
        }
    }
}

private fun mergeVideoSegments(segments: List<File>, context: android.content.Context): File? {
    if (segments.isEmpty()) return null
    if (segments.size == 1) return segments[0]

    val outputFile = File(context.cacheDir, "video_merged_${UUID.randomUUID()}.mp4")
    var muxer: MediaMuxer? = null

    try {
        muxer = MediaMuxer(outputFile.absolutePath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)

        val muxerTracks = mutableMapOf<String, Int>()
        val firstEx = MediaExtractor()
        firstEx.setDataSource(segments[0].absolutePath)
        for (i in 0 until firstEx.trackCount) {
            val fmt = firstEx.getTrackFormat(i)
            val mime = fmt.getString(MediaFormat.KEY_MIME) ?: continue
            val key = when {
                mime.startsWith("video/") -> "video"
                mime.startsWith("audio/") -> "audio"
                else -> continue
            }
            if (!muxerTracks.containsKey(key)) muxerTracks[key] = muxer.addTrack(fmt)
        }
        firstEx.release()

        muxer.start()

        val buffer = ByteBuffer.allocate(2 * 1024 * 1024)
        val bufInfo = MediaCodec.BufferInfo()
        var timeOffsetUs = 0L

        for (segFile in segments) {
            val ex = MediaExtractor()
            ex.setDataSource(segFile.absolutePath)

            val localMap = mutableMapOf<Int, Int>()
            for (i in 0 until ex.trackCount) {
                val fmt = ex.getTrackFormat(i)
                val mime = fmt.getString(MediaFormat.KEY_MIME) ?: continue
                val key = when {
                    mime.startsWith("video/") -> "video"
                    mime.startsWith("audio/") -> "audio"
                    else -> continue
                }
                val muxerTrack = muxerTracks[key] ?: continue
                localMap[i] = muxerTrack
                ex.selectTrack(i)
            }

            var maxPtsUs = 0L
            while (true) {
                val trackIdx = ex.sampleTrackIndex
                if (trackIdx < 0) break
                val muxerTrack = localMap[trackIdx]
                if (muxerTrack == null) { ex.advance(); continue }

                val size = ex.readSampleData(buffer, 0)
                if (size < 0) break

                val pts = ex.sampleTime
                if (pts > maxPtsUs) maxPtsUs = pts

                bufInfo.offset = 0
                bufInfo.size = size
                bufInfo.presentationTimeUs = pts + timeOffsetUs
                bufInfo.flags = ex.sampleFlags

                muxer.writeSampleData(muxerTrack, buffer, bufInfo)
                ex.advance()
            }
            ex.release()

            timeOffsetUs += maxPtsUs + 33_333L
        }

        muxer.stop()
        muxer.release()
        muxer = null

        segments.forEach { runCatching { it.delete() } }
        return outputFile
    } catch (e: Exception) {
        android.util.Log.e("VideoCircle", "mergeVideoSegments error: ${e.message}")
        muxer?.runCatching { release() }
        outputFile.delete()
        return null
    }
}

@Composable
fun VideoCirclePlayer(
    videoFile: File,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var tempFile by remember { mutableStateOf<File?>(null) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(videoFile) {
        withContext(Dispatchers.IO) {
            try {
                val decryptedBytes = SecureFileStorage.read(context, videoFile)
                val tmp = File(context.cacheDir, "video_play_${videoFile.nameWithoutExtension}.mp4")
                tmp.writeBytes(decryptedBytes)
                tempFile = tmp
            } catch (e: Exception) {
                android.util.Log.e("VideoCirclePlayer", "Decrypt error: ${e.message}")
            } finally {
                isLoading = false
            }
        }
    }

    DisposableEffect(Unit) {
        onDispose { tempFile?.delete() }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnBackPress = true)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xCC000000)),
            contentAlignment = Alignment.Center
        ) {
            when {
                isLoading -> {
                    CircularProgressIndicator(color = Color.White)
                }
                tempFile != null -> {
                    Box(
                        modifier = Modifier
                            .size(280.dp)
                            .clip(CircleShape)
                    ) {
                        AndroidView(
                            factory = { ctx ->
                                VideoView(ctx).apply {
                                    setVideoPath(tempFile!!.absolutePath)
                                    setOnPreparedListener { mp ->
                                        mp.isLooping = true
                                        start()
                                    }
                                    setOnErrorListener { _, _, _ ->
                                        android.util.Log.e("VideoCirclePlayer", "VideoView error")
                                        true
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxSize()
                        )
                    }
                }
                else -> {
                    Text("Не удалось воспроизвести видео", color = Color.White, fontFamily = JetBrainsMono)
                }
            }

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(top = 24.dp, end = 24.dp),
                contentAlignment = Alignment.TopEnd
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(Color(0x88000000))
                        .pointerInput(Unit) {
                            awaitPointerEventScope {
                                awaitPointerEvent()
                                onDismiss()
                            }
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }
}
