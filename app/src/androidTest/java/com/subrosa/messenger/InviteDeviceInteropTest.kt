package com.subrosa.messenger

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

/**
 * KL-13 on a real device, both directions.
 *
 * KL-13 records that the Android and Desktop invite-code format was once
 * incompatible, and that the fix was verified in code only -- "live
 * cross-platform test still not run". The reason the existing suites cannot
 * close it: [InviteVectorsTest] (app/src/test) runs under Robolectric, so the
 * `android.util.Base64` that [InviteCodeManager] encodes with is a
 * reimplementation running on the host JVM, and the signature is produced by
 * the host's SunEC provider. On a phone both come from the platform --
 * Conscrypt/AndroidOpenSSL and the real Base64 -- and a divergence there is
 * invisible to every test that does not run on hardware.
 *
 * So this test is deliberately narrow. It settles the question KL-13 is about
 * (does a code minted by the phone's own platform code parse and verify on the
 * laptop, and the other way round) and nothing else. It does NOT exercise
 * first contact: no server, no blind mailbox deposit, no anonymous-token
 * bootstrap, no message delivery. Those need the app's UI and are a separate
 * claim -- do not read a pass here as "first contact works between the
 * platforms".
 *
 * The identity key here is a software P-256 key generated on the device, not
 * the AndroidKeyStore-backed identity the app really signs invites with. What
 * that still covers is the encoding and the device's ECDSA DER output flowing
 * through `derToRaw`, which is the part that broke. What it does not cover is
 * a hardware-backed key behaving differently.
 *
 * Driving it (foss debug build, phone connected over adb):
 *
 *   cd desktop && ./gradlew inviteFormatBridge -Pargs="gen <dir>/code_desktop.txt"
 *   ./gradlew :app:connectedFossDebugAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=com.subrosa.messenger.InviteDeviceInteropTest \
 *     -Pandroid.testInstrumentationRunnerArguments.desktopCode="$(cat <dir>/code_desktop.txt)"
 *   adb shell cat /sdcard/Android/data/com.subrosa.messenger/cache/invite_from_device.txt > <dir>/code_phone.txt
 *   cd desktop && ./gradlew inviteFormatBridge -Pargs="check <dir>/code_phone.txt"
 */
@RunWith(AndroidJUnit4::class)
class InviteDeviceInteropTest {

    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** Generated on the phone, by the phone's own platform code, for the
     *  laptop to read. The code is written where `adb shell` can reach it and
     *  also printed, because the instrumentation stream is the one channel
     *  that works whatever the device's storage policy is. */
    @Test
    fun phoneGeneratesACodeAndCanReadItBack() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val tagHex = ByteArray(16)
            .also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }

        val code = InviteCodeManager.generateInviteCode(
            publicKey = keyPair.public,
            privateKey = keyPair.private,
            displayName = "phone",
            mailboxTagHex = tagHex
        )

        val parsed = InviteCodeManager.parseInviteCode(code)
        assertNotNull("the phone cannot parse the code it just generated", parsed)
        assertEquals("mailbox tag did not survive the round trip", tagHex, parsed!!.mailboxTag)
        assertEquals("display name did not survive the round trip", "phone", parsed.displayName)
        assertTrue(
            "the phone refused to verify its own fresh code",
            InviteCodeManager.verifyInviteCode(parsed)
        )

        val signatureProvider = java.security.Signature
            .getInstance("SHA256withECDSA").provider.name
        println("PHONE_SIG_PROVIDER=$signatureProvider")
        println("PHONE_KEY_PROVIDER=${keyPair.private.javaClass.name}")
        println("PHONE_INVITE_FP=${parsed.fingerprint}")
        println("PHONE_INVITE_CODE=$code")

        val outside = File(ctx.externalCacheDir, "invite_from_device.txt")
        try {
            outside.writeText(code)
            println("PHONE_INVITE_FILE=${outside.absolutePath}")
        } catch (e: Exception) {
            println("PHONE_INVITE_FILE_FAILED=${e.javaClass.simpleName}: ${e.message}")
        }
        File(ctx.filesDir, "invite_from_device.txt").writeText(code)
    }

    /** The laptop's code, parsed and verified by the phone. Skipped rather
     *  than failed when the argument is absent, so the class stays runnable
     *  without a desktop build -- a skip is visible, a silent pass is not. */
    @Test
    fun phoneAcceptsTheDesktopGeneratedCode() {
        val code = InstrumentationRegistry.getArguments()
            .getString("desktopCode")?.trim().orEmpty()
        assumeTrue(
            "no -e desktopCode argument given: run the desktop inviteFormatBridge gen first",
            code.isNotEmpty()
        )

        println("DESKTOP_CODE_LEN=${code.length}")
        println("DESKTOP_CODE_PREFIX=${code.take(12)}")

        val parsed = InviteCodeManager.parseInviteCode(code)
        assertNotNull("the phone's parser rejected a desktop-generated code", parsed)
        println("DESKTOP_CODE_ON_PHONE fp=${parsed!!.fingerprint} name=${parsed.displayName} tag=${parsed.mailboxTag} ts=${parsed.timestamp}")
        assertTrue(
            "the phone parsed the desktop code but refused to verify it",
            InviteCodeManager.verifyInviteCode(parsed)
        )
    }
}
