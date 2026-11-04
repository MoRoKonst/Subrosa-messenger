package com.subrosa.desktop

import dev.onvoid.webrtc.PeerConnectionFactory
import dev.onvoid.webrtc.media.FourCC
import dev.onvoid.webrtc.media.MediaDevices
import dev.onvoid.webrtc.media.video.VideoBufferConverter
import dev.onvoid.webrtc.media.video.VideoDeviceSource
import dev.onvoid.webrtc.media.video.VideoFrame
import dev.onvoid.webrtc.media.video.VideoTrack
import dev.onvoid.webrtc.media.video.VideoTrackSink
import java.awt.image.BufferedImage
import java.awt.image.DataBufferInt
import java.io.File
import javax.imageio.ImageIO

/** Desktop port of Android's VideoCircleScreen — records a square, circle-
 *  cropped-on-display video message ("video circle" / Telegram-style video
 *  note). Uses the same webrtc-java camera access already proven in
 *  DesktopCallManager (a SEPARATE PeerConnectionFactory instance here,
 *  decoupled from call state — this is pure local capture, no PeerConnection/
 *  networking involved), and reuses VoiceRecorder unchanged for the audio
 *  track (same TargetDataLine capture already used for voice messages).
 *
 *  Unlike Android (CameraX Recorder writing H.264 directly), there is no
 *  equivalent high-level Java video-encoding API here. Frames are saved as a
 *  JPEG sequence and audio as WAV, then muxed into an actual H.264/AAC MP4
 *  via ffmpeg on stop — located through JAVE2's own bundled-binary locator
 *  (already a project dependency for AMR voice-message transcoding, see
 *  AudioTranscoder.kt), invoked directly rather than through JAVE2's
 *  high-level Encoder API, which has no image-sequence+audio muxing mode. */
object DesktopVideoCircleRecorder {
    const val MAX_SECONDS = 60
    private const val TARGET_FPS = 15
    private const val OUTPUT_SIZE = 480

    private var factory: PeerConnectionFactory? = null
    private var videoSource: VideoDeviceSource? = null
    private var videoTrack: VideoTrack? = null
    private var sink: VideoTrackSink? = null
    private var frameDir: File? = null
    private var frameCount = 0
    private var lastSavedAtMs = 0L

    /** Called from webrtc's native capture thread with each downsampled,
     *  square-cropped preview frame — mirrors CallScreen's onLocalVideoFrame
     *  pattern (also written to Compose state directly from a non-UI
     *  thread; already proven safe in this codebase). */
    var onPreviewFrame: ((BufferedImage) -> Unit)? = null

    fun hasCamera(): Boolean = try {
        MediaDevices.getVideoCaptureDevices().isNotEmpty()
    } catch (e: Throwable) {
        false
    }

    /** Returns false (no state changed) if there's no camera or capture
     *  failed to start — caller should show "camera not found" and not open
     *  the recording UI at all, rather than opening it and immediately
     *  failing. Throwable, not Exception — see DesktopCallManager's
     *  createLocalTracks() comment: a missing/unusable camera can surface as
     *  a native-layer Error subtype through this JNI wrapper, not just an
     *  ordinary Exception, and this runs synchronously on the Compose click
     *  handler's thread with no other crash boundary. */
    fun start(): Boolean {
        return try {
            val device = MediaDevices.getVideoCaptureDevices().firstOrNull() ?: return false
            val f = PeerConnectionFactory()
            val src = VideoDeviceSource()
            src.setVideoCaptureDevice(device)
            val track = f.createVideoTrack("VC_${java.util.UUID.randomUUID()}", src)
            val dir = createFrameDir()
            frameDir = dir
            frameCount = 0
            lastSavedAtMs = 0L
            val s = VideoTrackSink { frame -> onFrame(frame) }
            track.addSink(s)
            factory = f
            videoSource = src
            videoTrack = track
            sink = s
            src.start()
            VoiceRecorder.start()
            true
        } catch (e: Throwable) {
            System.err.println("DesktopVideoCircleRecorder: start failed — ${e.message}")
            cleanupNative()
            false
        }
    }

    private fun createFrameDir(): File {
        val dir = File(System.getProperty("java.io.tmpdir"), "subrosa_vc_${System.currentTimeMillis()}")
        dir.mkdirs()
        return dir
    }

    private fun onFrame(frame: VideoFrame) {
        val now = System.currentTimeMillis()
        if (now - lastSavedAtMs < 1000L / TARGET_FPS) return
        lastSavedAtMs = now
        val img = frameToSquareImage(frame) ?: return
        onPreviewFrame?.invoke(img)
        val dir = frameDir ?: return
        val idx = frameCount++
        val file = File(dir, "frame_%05d.jpg".format(idx))
        try {
            ImageIO.write(img, "jpg", file)
        } catch (_: Exception) {}
    }

    private fun frameToSquareImage(frame: VideoFrame): BufferedImage? = try {
        val buf = frame.buffer
        val w = buf.width
        val h = buf.height
        val bytes = ByteArray(w * h * 4)
        VideoBufferConverter.convertFromI420(buf, bytes, FourCC.ARGB)
        val srcPixels = IntArray(w * h)
        // FourCC.ARGB is libyuv's in-memory B,G,R,A byte order, not literal
        // A,R,G,B — see CallScreen.kt's frameToImageBitmap() for the full
        // explanation of the resulting desaturated/black-and-white look.
        for (i in 0 until w * h) {
            val o = i * 4
            val b = bytes[o].toInt() and 0xFF
            val g = bytes[o + 1].toInt() and 0xFF
            val r = bytes[o + 2].toInt() and 0xFF
            val a = bytes[o + 3].toInt() and 0xFF
            srcPixels[i] = (a shl 24) or (r shl 16) or (g shl 8) or b
        }
        // frame.rotation was ignored entirely before this fix — see
        // CallScreen.kt's frameToImageBitmap() for the full explanation.
        // Applied BEFORE the square crop below, not after: cropping first
        // and rotating a sideways square afterward would still show
        // sideways content, it would just be sideways within a square
        // instead of a rectangle.
        val (rw, rh, rotated) = rotatePixels(srcPixels, w, h, frame.rotation)
        val full = BufferedImage(rw, rh, BufferedImage.TYPE_INT_ARGB)
        System.arraycopy(rotated, 0, (full.raster.dataBuffer as DataBufferInt).data, 0, rotated.size)
        // Center-crop to square (camera frames are typically 4:3/16:9) --
        // mirrors Android's 1:1 ViewPort, just applied per-frame here
        // instead of at the capture-pipeline level.
        val size = minOf(rw, rh)
        val x = (rw - size) / 2
        val y = (rh - size) / 2
        val cropped = full.getSubimage(x, y, size, size)
        val scaled = BufferedImage(OUTPUT_SIZE, OUTPUT_SIZE, BufferedImage.TYPE_INT_ARGB)
        val g2 = scaled.createGraphics()
        g2.drawImage(cropped, 0, 0, OUTPUT_SIZE, OUTPUT_SIZE, null)
        g2.dispose()
        scaled
    } catch (e: Exception) {
        null
    }

    private fun cleanupNative() {
        try { sink?.let { videoTrack?.removeSink(it) } } catch (_: Exception) {}
        try { videoSource?.stop() } catch (_: Exception) {}
        try { videoSource?.dispose() } catch (_: Exception) {}
        try { factory?.dispose() } catch (_: Exception) {}
        videoTrack = null; videoSource = null; sink = null; factory = null
    }

    /** Stops capture and muxes the frame sequence + audio into a square
     *  H.264/AAC MP4. Returns the output file, or null if nothing usable
     *  was captured or muxing failed. Blocking (spawns and waits on the
     *  ffmpeg process) — call off the UI thread. */
    fun stopAndMux(): File? {
        cleanupNative()
        val wavBytes = VoiceRecorder.stop()
        val dir = frameDir
        frameDir = null
        val count = frameCount
        frameCount = 0

        if (dir == null || count == 0) {
            dir?.deleteRecursively()
            return null
        }

        return try {
            val audioFile = File(dir, "audio.wav")
            val hasAudio = wavBytes != null && wavBytes.size > 44
            if (hasAudio) audioFile.writeBytes(wavBytes!!)

            val ffmpegPath = ws.schild.jave.process.ffmpeg.DefaultFFMPEGLocator().executablePath
            val outFile = File(dir.parentFile, "video_circle_${System.currentTimeMillis()}.mp4")
            val args = mutableListOf(
                ffmpegPath, "-y",
                "-framerate", TARGET_FPS.toString(),
                "-i", File(dir, "frame_%05d.jpg").absolutePath
            )
            if (hasAudio) args += listOf("-i", audioFile.absolutePath)
            args += listOf("-c:v", "libx264", "-pix_fmt", "yuv420p")
            if (hasAudio) args += listOf("-c:a", "aac", "-shortest")
            args += listOf("-movflags", "+faststart", outFile.absolutePath)

            val proc = ProcessBuilder(args).redirectErrorStream(true).start()
            // Drain stdout/stderr (merged) so the process can't block on a
            // full pipe buffer while we wait for it.
            proc.inputStream.bufferedReader().readText()
            val exit = proc.waitFor()
            dir.deleteRecursively()
            if (exit == 0 && outFile.exists() && outFile.length() > 0L) outFile else {
                System.err.println("DesktopVideoCircleRecorder: ffmpeg exited $exit")
                null
            }
        } catch (e: Exception) {
            System.err.println("DesktopVideoCircleRecorder: mux failed — ${e.message}")
            dir.deleteRecursively()
            null
        }
    }

    fun cancel() {
        cleanupNative()
        VoiceRecorder.cancel()
        frameDir?.deleteRecursively()
        frameDir = null
        frameCount = 0
    }
}
