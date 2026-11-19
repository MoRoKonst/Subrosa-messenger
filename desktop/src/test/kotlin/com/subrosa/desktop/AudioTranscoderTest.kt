package com.subrosa.desktop

import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import javax.sound.sampled.AudioSystem
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * AudioTranscoder.toWav() is the ONE place the desktop client needs ffmpeg (via JAVE): an incoming
 * Android voice message is AMR-NB in a 3GPP container, which javax.sound.sampled cannot play.
 * This test feeds a REAL AMR-NB/3GP file through it and checks that playable WAV comes out — it exists
 * so that trimming the bundled ffmpeg natives (docs: N6/S2) can never silently break voice messages.
 *
 * Sample: src/test/resources/voice-sample-amr-nb.3gp — 1 s, 440 Hz sine, 8 kHz mono, libopencore_amrnb
 * 7.4 kbit/s in a 3GPP container, generated with the ffmpeg binary bundled in jave-nativebin-win64 3.5.0:
 *   ffmpeg -f lavfi -i "sine=frequency=440:duration=1" -ar 8000 -ac 1 -c:a libopencore_amrnb -b:a 7.4k -f 3gp voice-sample-amr-nb.3gp
 */
class AudioTranscoderTest {
    private fun sample(): ByteArray =
        AudioTranscoderTest::class.java.getResourceAsStream("/voice-sample-amr-nb.3gp")!!.readBytes()

    @Test
    fun `a real AMR-NB 3GP voice message becomes playable 8 kHz mono WAV about one second long`() {
        val amr = sample()
        // the input really is a 3GPP container, not already WAV
        assertEquals("ftyp", String(amr, 4, 4, Charsets.ISO_8859_1))
        val wav = AudioTranscoder.toWav(amr)
        assertNotNull(wav, "transcode returned null — ffmpeg missing or could not decode AMR-NB")
        assertEquals("RIFF", String(wav, 0, 4, Charsets.ISO_8859_1))
        assertEquals("WAVE", String(wav, 8, 4, Charsets.ISO_8859_1))
        val ais = AudioSystem.getAudioInputStream(ByteArrayInputStream(wav))
        val f = ais.format
        assertEquals(8000f, f.sampleRate)
        assertEquals(1, f.channels)
        assertEquals(16, f.sampleSizeInBits)
        val seconds = ais.frameLength / f.frameRate
        assertTrue(seconds in 0.8f..1.4f, "expected about 1 s of audio, got $seconds s")
        // not silence: the 440 Hz tone survived (peak amplitude well above zero)
        val pcm = wav.copyOfRange(44, wav.size)
        var peak = 0
        for (i in 0 until pcm.size - 1 step 2) {
            val s = (pcm[i].toInt() and 0xFF) or (pcm[i + 1].toInt() shl 8)
            if (kotlin.math.abs(s.toShort().toInt()) > peak) peak = kotlin.math.abs(s.toShort().toInt())
        }
        assertTrue(peak > 3000, "decoded audio is (near) silent: peak=$peak")
    }

    @Test
    fun `garbage is rejected with null, not an exception`() {
        assertEquals(null, AudioTranscoder.toWav(ByteArray(64) { it.toByte() }))
    }
}
