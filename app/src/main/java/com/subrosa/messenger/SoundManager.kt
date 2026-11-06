package com.subrosa.messenger

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import kotlin.math.*

object SoundManager {

    private const val SAMPLE_RATE = 44100
    private const val VOLUME      = 0.22f

    @Volatile private var sentBuffer:     ShortArray? = null
    @Volatile private var receivedBuffer: ShortArray? = null

    fun playMessageSent() {
        val buf = sentBuffer ?: buildNote(1046.5f, 80).also { sentBuffer = it }
        play(buf)
    }

    fun playMessageReceived() {
        val buf = receivedBuffer ?: buildChime(
            listOf(659.25f to 50, 880f to 70)
        ).also { receivedBuffer = it }
        play(buf)
    }

    private fun buildNote(
        freq: Float,
        durationMs: Int,
        attackMs: Int = 4,
        warmth: Float = 0.12f
    ): ShortArray {
        val n       = SAMPLE_RATE * durationMs / 1000
        val attackN = SAMPLE_RATE * attackMs  / 1000

        val decayRate = -ln(0.04) / (durationMs / 1000.0)
        val buf = ShortArray(n)
        for (i in 0 until n) {
            val t      = i.toDouble() / SAMPLE_RATE
            val wave   = sin(2.0 * PI * freq * t) + warmth * sin(2.0 * PI * freq * 2.0 * t)
            val attack = if (i < attackN) i.toFloat() / attackN else 1f
            val decay  = exp(-decayRate * t).toFloat()
            buf[i] = (wave * Short.MAX_VALUE * VOLUME * attack * decay).toInt().toShort()
        }
        return buf
    }

    private fun buildChime(notes: List<Pair<Float, Int>>): ShortArray {
        val gapSamples = SAMPLE_RATE * 5 / 1000
        val segments   = notes.map { (f, ms) -> buildNote(f, ms) }
        val totalLen   = segments.sumOf { it.size } + gapSamples * (segments.size - 1)
        val buf        = ShortArray(totalLen)
        var pos        = 0
        for ((idx, seg) in segments.withIndex()) {
            seg.copyInto(buf, pos)
            pos += seg.size
            if (idx < segments.size - 1) pos += gapSamples
        }
        return buf
    }

    private fun play(buf: ShortArray) {
        Thread {
            var track: AudioTrack? = null
            try {
                track = AudioTrack.Builder()
                    .setAudioAttributes(
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_NOTIFICATION_COMMUNICATION_INSTANT)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                            .build()
                    )
                    .setAudioFormat(
                        AudioFormat.Builder()
                            .setSampleRate(SAMPLE_RATE)
                            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                            .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                            .build()
                    )
                    .setBufferSizeInBytes(buf.size * 2)
                    .setTransferMode(AudioTrack.MODE_STATIC)
                    .build()
                track.write(buf, 0, buf.size)
                track.play()
                val durationMs = buf.size.toLong() * 1000L / SAMPLE_RATE
                Thread.sleep(durationMs + 30)
            } catch (_: Exception) {
            } finally {
                try { track?.stop()    } catch (_: Exception) {}
                try { track?.release() } catch (_: Exception) {}
            }
        }.apply { isDaemon = true; start() }
    }
}
