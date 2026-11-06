package com.subrosa.messenger

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.media.MediaPlayer
import android.media.RingtoneManager
import android.util.Log
import kotlin.math.*

object CallSoundManager {

    private const val TAG         = "CallSoundManager"
    private const val SAMPLE_RATE = 44100

    @Volatile private var ringtonePlayer: MediaPlayer? = null
    @Volatile private var ringbackThread: Thread?      = null
    @Volatile private var ringbackRunning = false

    fun startRingtone(context: Context) {
        stopAll()
        try {
            val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            val mp  = MediaPlayer()
            mp.setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
            )
            mp.setDataSource(context.applicationContext, uri)
            mp.isLooping = true
            mp.prepare()
            mp.start()
            ringtonePlayer = mp
            Log.d(TAG, "Рингтон запущен")
        } catch (e: Exception) {
            Log.w(TAG, "startRingtone: ${e.message}")
        }
    }

    fun startRingback() {
        stopAll()
        ringbackRunning = true
        ringbackThread = Thread {
            val tone      = buildRingbackTone(SAMPLE_RATE)
            val silenceMs = 4_000L

            while (ringbackRunning) {
                playOnce(tone)
                if (!ringbackRunning) break
                try { Thread.sleep(silenceMs) } catch (_: InterruptedException) { break }
            }
            Log.d(TAG, "Ringback остановлен")
        }.apply { isDaemon = true; start() }
        Log.d(TAG, "Ringback запущен")
    }

    fun stopAll() {
        ringbackRunning = false
        ringbackThread?.interrupt()
        ringbackThread = null
        try { ringtonePlayer?.stop()    } catch (_: Exception) {}
        try { ringtonePlayer?.release() } catch (_: Exception) {}
        ringtonePlayer = null
    }

    private fun buildRingbackTone(samples: Int): ShortArray {
        val fade = (samples * 0.05f).toInt().coerceAtLeast(1)
        return ShortArray(samples) { i ->
            val t       = i.toDouble() / SAMPLE_RATE
            val fadeIn  = if (i < fade)           i.toFloat() / fade           else 1f
            val fadeOut = if (i > samples - fade) (samples - i).toFloat() / fade else 1f
            val env     = fadeIn * fadeOut
            val wave    = sin(2.0 * PI * 440.0 * t) * 0.5 + sin(2.0 * PI * 480.0 * t) * 0.5
            (wave * Short.MAX_VALUE * 0.35 * env).toInt().toShort()
        }
    }

    private fun playOnce(buf: ShortArray) {
        var track: AudioTrack? = null
        try {
            track = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
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
            if (!ringbackRunning) return
            track.play()
            val durationMs = buf.size.toLong() * 1000L / SAMPLE_RATE
            Thread.sleep(durationMs + 50)
        } catch (_: InterruptedException) {
        } catch (_: Exception) {
        } finally {
            try { track?.stop()    } catch (_: Exception) {}
            try { track?.release() } catch (_: Exception) {}
        }
    }
}
