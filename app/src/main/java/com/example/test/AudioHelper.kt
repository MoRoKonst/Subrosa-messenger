package com.subrosa.messenger

import android.content.Context
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaRecorder
import android.media.MediaPlayer
import android.util.Base64
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

object AudioHelper {

    // S6-57 (external review 2026-09-06) -- the post-base64-decode byte
    // ceiling for a single voice message's raw audio. Wire/decrypted-string
    // bounds checked upstream (MessengerService.kt's "voice" handler,
    // GroupChatScreen.kt's group-voice path) aren't sufficient on their own
    // if this decode step were ever the first place an oversized value is
    // actually materialized -- this is the last line of defense right before
    // the bytes are written to disk. Mirrors MessengerService's own
    // VOICE_MAX_DECODED_AUDIO_BYTES derivation (Desktop's uncompressed WAV
    // codec's own 60s-max worst case, ~1.92 MiB, plus headroom).
    private const val MAX_DECODED_AUDIO_BYTES = (2.5 * 1024 * 1024).toInt()

    private var recorder: MediaRecorder? = null
    private var player: MediaPlayer? = null
    private val tempPlaybackFiles = mutableListOf<File>()

    fun startRecording(context: Context): File {
        val outputFile = File(context.cacheDir, "voice_rec_temp.3gp")
        if (outputFile.exists()) outputFile.delete()

        recorder = MediaRecorder().apply {
            // VOICE_COMMUNICATION (not MIC) -- MIC is the raw, unprocessed
            // capture path with no platform audio effects applied, which is
            // why voice messages came out far quieter than the same phone's
            // calling/VoIP apps: those all request VOICE_COMMUNICATION,
            // which on most devices auto-attaches AutomaticGainControl (plus
            // noise suppression/echo cancellation) at the HAL level. Found
            // live, 2026-09-18 -- confirmed by the user that other apps on
            // the same hardware recorded normally.
            setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
            setOutputFormat(MediaRecorder.OutputFormat.THREE_GPP)
            setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB)
            setOutputFile(outputFile.absolutePath)
            prepare()
            start()
        }

        return outputFile
    }

    fun stopRecording(): File? {
        return try {
            recorder?.apply {
                stop()
                release()
            }
            recorder = null
            null
        } catch (e: Exception) {
            Log.e("AudioHelper", "Stop recording error: ${e.message}")
            null
        }
    }

    fun encodeToBase64(file: File): String {
        val bytes = file.readBytes()
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    /** Returns null (no file written, no partial state retained) if [base64]
     *  is malformed or decodes to more than [MAX_DECODED_AUDIO_BYTES] --
     *  S6-57, STEP 8: a malicious/oversized payload must never reach a file
     *  write, regardless of what any upstream wire-size check already did. */
    fun decodeAndSave(context: Context, base64: String, voiceId: String): File? {
        val bytes = try {
            Base64.decode(base64, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e("AudioHelper", "decodeAndSave: malformed base64 — ${e.message}")
            return null
        }
        if (bytes.size > MAX_DECODED_AUDIO_BYTES) {
            Log.e("AudioHelper", "decodeAndSave: decoded audio (${bytes.size} bytes) exceeds cap")
            return null
        }
        val encFile = SecureFileStorage.blobFile(context.filesDir, voiceId)
        SecureFileStorage.write(context, encFile, bytes)
        return encFile
    }

    fun playAudio(context: Context, file: File?, onComplete: () -> Unit) {
        if (file == null) return
        stopAudio()

        val playFile = if (file.name.endsWith(".enc")) {
            try {
                val temp = SecureFileStorage.decryptToTemp(context, file, file.name.removeSuffix(".enc"))
                tempPlaybackFiles.add(temp)
                temp
            } catch (e: Exception) {
                Log.e("AudioHelper", "Decrypt for playback failed: ${e.message}")
                return
            }
        } else file

        player = MediaPlayer().apply {
            setDataSource(playFile.absolutePath)
            setOnCompletionListener {
                onComplete()
                cleanupTempPlayback()
            }
            prepare()
            start()
        }
    }

    fun stopAudio() {
        try {
            player?.apply { stop(); release() }
        } catch (_: Exception) {}
        player = null
        cleanupTempPlayback()
    }

    // ── Waveform / seek / speed (Telegram-style voice bubble) ────────────────

    fun getCurrentPositionMs(): Int = try { player?.currentPosition ?: 0 } catch (e: Exception) { 0 }
    fun getDurationMs(): Int = try { player?.duration ?: 0 } catch (e: Exception) { 0 }
    fun isPlaying(): Boolean = try { player?.isPlaying ?: false } catch (e: Exception) { false }

    fun seekTo(ms: Int) {
        try { player?.seekTo(ms) } catch (e: Exception) { Log.w("AudioHelper", "seekTo failed: ${e.message}") }
    }

    /** [speed]=2f for double speed, 1f for normal. pitch is pinned to 1f
     *  (unchanged) -- PlaybackParams (API 23+) is the platform-native way to
     *  do this: unlike a naive sample-rate/resample trick (which shifts
     *  pitch up with speed -- the "funny voice" effect the user explicitly
     *  called out from VK), it re-times the audio while keeping pitch fixed.
     *  Must be called while `player` exists and is prepared/started; a plain
     *  try/catch is enough since the caller only calls this during active
     *  playback. */
    fun setSpeed(speed: Float) {
        try {
            player?.let { it.playbackParams = it.playbackParams.setSpeed(speed).setPitch(1f) }
        } catch (e: Exception) {
            Log.w("AudioHelper", "setSpeed failed: ${e.message}")
        }
    }

    private val waveformCache = mutableMapOf<String, FloatArray>()

    /** Peak-bucketed amplitude bars (0f..1f), [bars] of them, for the
     *  Telegram-style waveform UI. MediaPlayer exposes no amplitude/
     *  visualizer API for a plain file data source, so this decodes the
     *  AMR-NB/3GP voice file to raw PCM via MediaExtractor+MediaCodec
     *  independently of playback. Decrypts to its own throwaway temp file
     *  when needed (separate from playAudio()'s temp -- this can run before
     *  the user has ever pressed play). Cached by the ENCRYPTED file's
     *  stable path so a LazyColumn recomposing the same bubble repeatedly
     *  (scroll) doesn't redecode every time. Blocking -- call off the main
     *  thread. Returns an all-zero array (flat waveform, never throws) on
     *  any decode failure — a message with a genuinely undecodable voice
     *  file still needs to render, not crash the list. */
    fun getWaveform(context: Context, file: File, bars: Int = 32): FloatArray {
        waveformCache[file.absolutePath]?.let { return it }
        val decodeFile = if (file.name.endsWith(".enc")) {
            try {
                SecureFileStorage.decryptToTemp(context, file, "waveform_tmp_${file.nameWithoutExtension}")
            } catch (e: Exception) {
                Log.e("AudioHelper", "getWaveform: decrypt failed — ${e.message}")
                return FloatArray(bars)
            }
        } else file
        return try {
            val pcm = decodeToPcm(decodeFile)
            val result = if (pcm != null) bucketAmplitude(pcm, bars) else FloatArray(bars)
            waveformCache[file.absolutePath] = result
            result
        } finally {
            if (decodeFile != file) decodeFile.delete()
        }
    }

    private fun decodeToPcm(file: File): ShortArray? {
        val extractor = MediaExtractor()
        return try {
            extractor.setDataSource(file.absolutePath)
            var trackIndex = -1
            var format: MediaFormat? = null
            for (i in 0 until extractor.trackCount) {
                val f = extractor.getTrackFormat(i)
                val mime = f.getString(MediaFormat.KEY_MIME) ?: continue
                if (mime.startsWith("audio/")) { trackIndex = i; format = f; break }
            }
            if (trackIndex < 0 || format == null) return null
            extractor.selectTrack(trackIndex)
            val mime = format.getString(MediaFormat.KEY_MIME) ?: return null
            val codec = MediaCodec.createDecoderByType(mime)
            codec.configure(format, null, null, 0)
            codec.start()
            val output = ByteArrayOutputStream()
            val bufferInfo = MediaCodec.BufferInfo()
            var sawInputEOS = false
            var sawOutputEOS = false
            while (!sawOutputEOS) {
                if (!sawInputEOS) {
                    val inIndex = codec.dequeueInputBuffer(10_000)
                    if (inIndex >= 0) {
                        val inBuf = codec.getInputBuffer(inIndex)!!
                        val sampleSize = extractor.readSampleData(inBuf, 0)
                        if (sampleSize < 0) {
                            codec.queueInputBuffer(inIndex, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                            sawInputEOS = true
                        } else {
                            codec.queueInputBuffer(inIndex, 0, sampleSize, extractor.sampleTime, 0)
                            extractor.advance()
                        }
                    }
                }
                val outIndex = codec.dequeueOutputBuffer(bufferInfo, 10_000)
                if (outIndex >= 0) {
                    val outBuf = codec.getOutputBuffer(outIndex)!!
                    val chunk = ByteArray(bufferInfo.size)
                    outBuf.get(chunk)
                    output.write(chunk)
                    codec.releaseOutputBuffer(outIndex, false)
                    if (bufferInfo.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) sawOutputEOS = true
                }
            }
            codec.stop()
            codec.release()
            val bytes = output.toByteArray()
            val shorts = ShortArray(bytes.size / 2)
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(shorts)
            shorts
        } catch (e: Exception) {
            Log.e("AudioHelper", "decodeToPcm failed: ${e.message}")
            null
        } finally {
            extractor.release()
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

    private fun cleanupTempPlayback() {
        tempPlaybackFiles.forEach { if (it.exists()) it.delete() }
        tempPlaybackFiles.clear()
    }
}
