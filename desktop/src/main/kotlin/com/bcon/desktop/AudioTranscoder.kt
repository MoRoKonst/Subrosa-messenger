package com.subrosa.desktop

import ws.schild.jave.Encoder
import ws.schild.jave.MultimediaObject
import ws.schild.jave.encode.AudioAttributes
import ws.schild.jave.encode.EncodingAttributes
import java.io.File

/** Normalizes a received voice message's audio bytes to WAV, so playback
 *  (FileRow's isVoice branch, javax.sound.sampled) never has to care what
 *  format the sender actually recorded in.
 *
 *  Android records voice messages as AMR-NB inside a 3GPP container
 *  (MediaRecorder.OutputFormat.THREE_GPP / AudioEncoder.AMR_NB — see
 *  AudioHelper.kt) — javax.sound.sampled has no AMR decoder built in, so
 *  without this, a voice message from an Android contact arrived and saved
 *  correctly (see WebSocketClient's "voice" handler) but silently failed
 *  to play. Desktop's own VoiceRecorder already produces WAV directly, so
 *  the common desktop-to-desktop case is a no-op passthrough here, not a
 *  transcode. */
object AudioTranscoder {

    /** Returns WAV bytes, or null if the input couldn't be decoded. Never
     *  throws. */
    fun toWav(bytes: ByteArray): ByteArray? {
        if (isWav(bytes)) return bytes
        return try {
            transcodeToWav(bytes)
        } catch (e: Exception) {
            System.err.println("AudioTranscoder: transcode failed — ${e.message}")
            null
        }
    }

    private fun isWav(bytes: ByteArray): Boolean =
        bytes.size >= 12 &&
        bytes[0] == 'R'.code.toByte() && bytes[1] == 'I'.code.toByte() &&
        bytes[2] == 'F'.code.toByte() && bytes[3] == 'F'.code.toByte() &&
        bytes[8] == 'W'.code.toByte() && bytes[9] == 'A'.code.toByte() &&
        bytes[10] == 'V'.code.toByte() && bytes[11] == 'E'.code.toByte()

    private fun transcodeToWav(sourceBytes: ByteArray): ByteArray? {
        // Content-based format probing (ffmpeg/ffprobe under the hood) —
        // the temp file's extension doesn't need to match the real
        // container for JAVE2/ffmpeg to identify it correctly.
        val inFile  = File.createTempFile("subrosa_voice_in_", ".bin")
        val outFile = File.createTempFile("subrosa_voice_out_", ".wav")
        try {
            inFile.writeBytes(sourceBytes)

            // AMR-NB is always 8 kHz mono (3GPP TS 26.071) — explicit, not
            // a guess, so there's no implicit resampling surprise.
            val audio = AudioAttributes().apply {
                setCodec("pcm_s16le")
                setChannels(1)
                setSamplingRate(8000)
            }
            val attrs = EncodingAttributes().apply {
                setOutputFormat("wav")
                setAudioAttributes(audio)
            }
            Encoder().encode(MultimediaObject(inFile), outFile, attrs)
            return outFile.readBytes()
        } finally {
            // Both may hold decrypted plaintext audio — delete promptly
            // rather than leaving them for the OS temp-cleanup cycle.
            inFile.delete()
            outFile.delete()
        }
    }
}
