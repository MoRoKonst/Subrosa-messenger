package com.subrosa.desktop

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.sound.sampled.AudioFormat
import javax.sound.sampled.AudioSystem
import javax.sound.sampled.Clip
import javax.sound.sampled.LineEvent

/** Telegram-style voice-bubble playback: waveform amplitude extraction,
 *  live position tracking, seek, and a pitch-preserving speed toggle
 *  (1x/1.5x/2x).
 *  javax.sound.sampled.Clip has no such things built in — Clip only gives
 *  play/stop/loop and (usefully) a settable microsecond position, which is
 *  reused directly for seeking.
 *
 *  Speed is NOT done via resampling/playback-rate change — that shifts
 *  pitch upward with speed (the "funny voice" effect the user explicitly
 *  ruled out, same as VK's). Instead [timeStretch] applies a standard
 *  50%-overlap Hann-windowed OLA (overlap-add) time compression: at exactly
 *  50% overlap a Hann window satisfies the COLA (constant overlap-add)
 *  property, so no extra normalization pass is needed at frame boundaries.
 *  The 2x-speed PCM is computed once per (message, speed) and cached in
 *  memory for the lifetime of this object — voice messages are short
 *  (<=60s) so processing the whole buffer up front is cheap and avoids any
 *  real-time DSP complexity.
 *
 *  All input is always WAV by the time it reaches here — AudioTranscoder
 *  already normalizes Android's AMR-NB voice messages to WAV at receive
 *  time (see its own comment), and VoiceRecorder produces WAV directly. */
object DesktopVoicePlayer {

    private var clip: Clip? = null
    private var currentMessageId: String? = null
    private var currentFormat: AudioFormat? = null
    private var normalPcm: ShortArray? = null
    // Keyed by speed (1.5f, 2f, ...) -- each distinct speed gets its own
    // stretched PCM, computed once and reused for the lifetime of the
    // currently loaded message (cleared in stop()/play() on message change).
    private val stretchedPcmCache = mutableMapOf<Float, ShortArray>()
    private var currentSpeed = 1f
    private var pendingOnComplete: () -> Unit = {}

    val isPlaying: Boolean get() = clip?.isRunning == true
    fun currentlyPlayingId(): String? = currentMessageId

    fun getCurrentPositionMs(): Int = try { ((clip?.microsecondPosition ?: 0L) / 1000L).toInt() } catch (e: Exception) { 0 }
    fun getDurationMs(): Int = try { ((clip?.microsecondLength ?: 0L) / 1000L).toInt() } catch (e: Exception) { 0 }

    /** [bytes] must already be WAV (see class comment). Starts playback
     *  fresh from position 0 at [speed]. */
    fun play(bytes: ByteArray, messageId: String, speed: Float, onComplete: () -> Unit) {
        stop()
        val decoded = decodeWav(bytes) ?: return
        val (pcm, format) = decoded
        currentMessageId = messageId
        currentFormat = format
        normalPcm = pcm
        stretchedPcmCache.clear()
        currentSpeed = speed
        pendingOnComplete = onComplete
        val playPcm = if (speed != 1f) getOrBuildStretched(pcm, format, speed) else pcm
        openClip(playPcm, format)
        clip?.start()
    }

    fun stop() {
        clip?.let { c -> try { c.stop(); c.close() } catch (_: Exception) {} }
        clip = null
        currentMessageId = null
        currentFormat = null
        normalPcm = null
        stretchedPcmCache.clear()
        pendingOnComplete = {}
    }

    fun seekTo(ms: Int) {
        try {
            val c = clip ?: return
            val target = (ms.toLong() * 1000L).coerceIn(0L, c.microsecondLength)
            c.microsecondPosition = target
        } catch (_: Exception) {}
    }

    /** Switches speed for whichever message is currently loaded, preserving
     *  content position (fractional progress is speed-invariant — see the
     *  math in the comment inline below) and play/pause state. No-op if
     *  [messageId] isn't the currently loaded one (stale UI callback after
     *  the user switched to a different voice message). */
    fun setSpeed(speed: Float, messageId: String) {
        if (messageId != currentMessageId || speed == currentSpeed) return
        val pcm = normalPcm ?: return
        val format = currentFormat ?: return
        val oldDurationMs = getDurationMs().coerceAtLeast(1)
        val oldPositionMs = getCurrentPositionMs()
        val wasPlaying = isPlaying
        val contentFraction = (oldPositionMs.toFloat() / oldDurationMs).coerceIn(0f, 1f)

        currentSpeed = speed
        clip?.let { c -> try { c.stop(); c.close() } catch (_: Exception) {} }
        clip = null

        val playPcm = if (speed != 1f) getOrBuildStretched(pcm, format, speed) else pcm
        openClip(playPcm, format)
        // Content position is preserved 1:1 as a FRACTION of the total —
        // "40% of the way through the story" is speed-invariant, unlike an
        // absolute ms offset (which scales inversely with speed).
        val newDurationMs = getDurationMs()
        seekTo((contentFraction * newDurationMs).toInt())
        if (wasPlaying) clip?.start()
    }

    /** Peak-bucketed amplitude bars (0f..1f) for the waveform UI. [bytes]
     *  must already be WAV. Pure function of the bytes — callers should
     *  cache the result themselves (keyed by message id) since this decodes
     *  the whole file every call. */
    fun getWaveform(bytes: ByteArray, bars: Int = 32): FloatArray {
        val decoded = decodeWav(bytes) ?: return FloatArray(bars)
        return bucketAmplitude(decoded.first, bars)
    }

    private fun getOrBuildStretched(pcm: ShortArray, format: AudioFormat, speed: Float): ShortArray {
        stretchedPcmCache[speed]?.let { return it }
        val built = timeStretch(pcm, format.sampleRate.toInt(), speed.toDouble())
        stretchedPcmCache[speed] = built
        return built
    }

    private fun openClip(pcm: ShortArray, format: AudioFormat) {
        val bytes = ByteArray(pcm.size * 2)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().put(pcm)
        val newClip = AudioSystem.getClip()
        newClip.open(format, bytes, 0, bytes.size)
        newClip.addLineListener { event ->
            if (event.type == LineEvent.Type.STOP) {
                val c = event.line as Clip
                // Natural end-of-clip vs. an explicit stop()/close() for a
                // speed-switch or user-initiated stop both fire STOP — only
                // the former should invoke onComplete. Within 2ms of the
                // clip's own length is "reached the end", not "interrupted".
                if (c.microsecondLength > 0 && c.microsecondPosition >= c.microsecondLength - 2000) {
                    pendingOnComplete()
                }
            }
        }
        clip = newClip
    }

    private fun decodeWav(bytes: ByteArray): Pair<ShortArray, AudioFormat>? {
        return try {
            val ais = AudioSystem.getAudioInputStream(ByteArrayInputStream(bytes))
            val format = ais.format
            val pcmBytes = ais.readAllBytes()
            val shorts = ShortArray(pcmBytes.size / 2)
            ByteBuffer.wrap(pcmBytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(shorts)
            shorts to format
        } catch (e: Exception) {
            System.err.println("DesktopVoicePlayer: decodeWav failed — ${e.message}")
            null
        }
    }

    private fun bucketAmplitude(pcm: ShortArray, bars: Int): FloatArray {
        if (pcm.isEmpty()) return FloatArray(bars)
        val bucketSize = (pcm.size / bars).coerceAtLeast(1)
        val result = FloatArray(bars)
        var maxPeak = 1
        for (b in 0 until bars) {
            val start = b * bucketSize
            val end = minOf(start + bucketSize, pcm.size)
            var peak = 0
            for (i in start until end) {
                val a = kotlin.math.abs(pcm[i].toInt())
                if (a > peak) peak = a
            }
            result[b] = peak.toFloat()
            if (peak > maxPeak) maxPeak = peak
        }
        for (b in 0 until bars) result[b] = (result[b] / maxPeak).coerceIn(0f, 1f)
        return result
    }

    /** 50%-overlap Hann-windowed OLA time compression by [speed] (>1 =
     *  faster, pitch unchanged). See class comment for why this exists
     *  instead of a resample/playback-rate trick. */
    private fun timeStretch(samples: ShortArray, sampleRate: Int, speed: Double): ShortArray {
        if (samples.isEmpty() || speed <= 1.0) return samples
        val frameSize = (sampleRate * 0.04).toInt().coerceAtLeast(256) // ~40ms analysis frame
        val synthesisHop = frameSize / 2
        val analysisHop = (synthesisHop * speed).toInt().coerceAtLeast(1)

        val window = DoubleArray(frameSize) { i ->
            0.5 - 0.5 * kotlin.math.cos(2.0 * Math.PI * i / (frameSize - 1))
        }

        var numFrames = 0
        var probe = 0
        while (probe + frameSize <= samples.size) {
            numFrames++
            probe += analysisHop
        }
        if (numFrames == 0) return ShortArray(0)

        val outLen = (numFrames - 1) * synthesisHop + frameSize
        val out = DoubleArray(outLen)

        var inPos = 0
        var outPos = 0
        for (f in 0 until numFrames) {
            for (i in 0 until frameSize) {
                out[outPos + i] += samples[inPos + i] * window[i]
            }
            inPos += analysisHop
            outPos += synthesisHop
        }

        return ShortArray(outLen) { i ->
            out[i].coerceIn(Short.MIN_VALUE.toDouble(), Short.MAX_VALUE.toDouble()).toInt().toShort()
        }
    }
}
