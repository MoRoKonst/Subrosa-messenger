package com.subrosa.desktop

import java.io.ByteArrayOutputStream
import javax.sound.sampled.AudioFormat
import javax.sound.sampled.AudioInputStream
import javax.sound.sampled.AudioSystem
import javax.sound.sampled.TargetDataLine

object VoiceRecorder {

    const val FILE_NAME = "voice_message.wav"

    private const val SAMPLE_RATE = 16000f

    private var line: TargetDataLine? = null
    private var buffer: ByteArrayOutputStream? = null
    private var recordThread: Thread? = null

    val isRecording: Boolean get() = line != null

    private fun format() = AudioFormat(SAMPLE_RATE, 16, 1, true, false)

    fun start(): Boolean {
        if (isRecording) return false
        return try {
            val fmt = format()
            val targetLine = AudioSystem.getLine(
                javax.sound.sampled.DataLine.Info(TargetDataLine::class.java, fmt)
            ) as TargetDataLine
            targetLine.open(fmt)
            targetLine.start()
            line = targetLine
            val out = ByteArrayOutputStream()
            buffer = out
            recordThread = Thread {
                val chunk = ByteArray(4096)
                while (line != null) {
                    val n = targetLine.read(chunk, 0, chunk.size)
                    if (n > 0) out.write(chunk, 0, n)
                }
            }.also { it.isDaemon = true; it.start() }
            true
        } catch (e: Exception) {
            System.err.println("VoiceRecorder: start failed — ${e.message}")
            line = null
            false
        }
    }

    /** Duration in whole seconds of a WAV byte array produced by stop() —
     *  16-bit mono PCM at SAMPLE_RATE, standard 44-byte header. Used when
     *  sending via the native "voice" protocol (see WebSocketClient.sendVoice()),
     *  which carries duration as an explicit field, unlike the old
     *  sendFile()-based fallback that didn't need it. */
    fun durationSeconds(wavBytes: ByteArray): Int {
        val dataBytes = (wavBytes.size - 44).coerceAtLeast(0)
        val samples = dataBytes / 2 // 16-bit = 2 bytes/sample
        return (samples / SAMPLE_RATE).toInt()
    }

    // Java Sound's TargetDataLine captures whatever raw level the OS/driver
    // hands over, with none of the automatic gain control that calling/VoIP
    // apps get from platform-level "communication" audio routing (see
    // Android's AudioHelper.kt for the identical gap — VOICE_COMMUNICATION
    // vs plain MIC — fixed there the same day). Peak-normalizing here brings
    // a quiet raw capture up to full usable range without touching any OS
    // mixer/driver setting, and is a safe no-op on an already-loud capture
    // (gain caps at 1.0x, never attenuates). Found live 2026-09-18 --
    // confirmed the same physical microphone recorded normally through
    // other apps, so the mic/driver itself wasn't at fault. MAX_GAIN caps
    // amplification for a near-silent recording (e.g. muted mic) so it
    // doesn't get boosted into audible noise floor hiss.
    private const val TARGET_PEAK_FRACTION = 0.85
    private const val MAX_GAIN = 12.0

    private fun normalize(pcm: ByteArray): ByteArray {
        if (pcm.size < 2) return pcm
        val sampleCount = pcm.size / 2
        var peak = 0
        for (i in 0 until sampleCount) {
            val lo = pcm[i * 2].toInt() and 0xFF
            val hi = pcm[i * 2 + 1].toInt()
            val sample = (hi shl 8) or lo
            val abs = kotlin.math.abs(sample)
            if (abs > peak) peak = abs
        }
        if (peak == 0) return pcm
        val gain = ((Short.MAX_VALUE * TARGET_PEAK_FRACTION) / peak).coerceIn(1.0, MAX_GAIN)
        if (gain <= 1.0) return pcm
        val out = ByteArray(pcm.size)
        for (i in 0 until sampleCount) {
            val lo = pcm[i * 2].toInt() and 0xFF
            val hi = pcm[i * 2 + 1].toInt()
            val sample = (hi shl 8) or lo
            val scaled = (sample * gain).toInt().coerceIn(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt())
            out[i * 2] = (scaled and 0xFF).toByte()
            out[i * 2 + 1] = ((scaled shr 8) and 0xFF).toByte()
        }
        return out
    }

    /** Stops recording and returns encoded WAV bytes, or null if nothing was recorded. */
    fun stop(): ByteArray? {
        val targetLine = line ?: return null
        targetLine.stop()
        targetLine.close()
        line = null
        recordThread?.join(500)
        recordThread = null

        val pcm = buffer?.toByteArray()
        buffer = null
        if (pcm == null || pcm.isEmpty()) return null

        return try {
            val fmt = format()
            val bais = java.io.ByteArrayInputStream(normalize(pcm))
            val ais = AudioInputStream(bais, fmt, (pcm.size / fmt.frameSize).toLong())
            val out = ByteArrayOutputStream()
            AudioSystem.write(ais, javax.sound.sampled.AudioFileFormat.Type.WAVE, out)
            out.toByteArray()
        } catch (e: Exception) {
            System.err.println("VoiceRecorder: WAV encode failed — ${e.message}")
            null
        }
    }

    fun cancel() {
        val targetLine = line ?: return
        targetLine.stop()
        targetLine.close()
        line = null
        recordThread?.join(500)
        recordThread = null
        buffer = null
    }
}
