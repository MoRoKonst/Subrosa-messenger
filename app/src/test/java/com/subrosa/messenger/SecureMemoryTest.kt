package com.subrosa.messenger

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What these tests can and cannot establish, stated up front because the gap
 * matters more than the assertions:
 *
 *  - They run on the JVM, not ART. They prove the *contract* of
 *    [SecureMemory] (buffer ends up zeroed, no exception on edge cases,
 *    original contents gone), which is what callers depend on.
 *  - They cannot prove the absence of copies elsewhere in the heap, and they
 *    cannot prove that dead-store elimination is defeated on a real device —
 *    that rests on the volatile write, which is a JMM guarantee, not something
 *    a unit test can observe.
 *  - The `String` overload is deliberately not asserted to work. On ART it is
 *    expected to fail silently (hidden-API restriction); a test asserting it
 *    succeeds would pass here and lie about the device.
 */
class SecureMemoryTest {

    @Test
    fun `byte array is zeroed and original content is gone`() {
        val secret = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val original = secret.copyOf()

        SecureMemory.wipe(secret)

        assertArrayEquals(ByteArray(8), secret)
        assertFalse("wipe left the original bytes in place", secret.contentEquals(original))
    }

    @Test
    fun `wipe tolerates null and empty buffers`() {
        SecureMemory.wipe(null as ByteArray?)
        SecureMemory.wipe(ByteArray(0))
        SecureMemory.wipe(null as CharArray?)
        SecureMemory.wipe(CharArray(0))
        // Reaching here without an exception is the assertion: these are the
        // shapes that show up in `finally` blocks where a key was never
        // allocated because an earlier call threw.
    }

    @Test
    fun `wipeAll clears every buffer it is given`() {
        val a = ByteArray(16) { 0x41 }
        val b = ByteArray(32) { 0x42 }

        SecureMemory.wipeAll(a, null, b)

        assertArrayEquals(ByteArray(16), a)
        assertArrayEquals(ByteArray(32), b)
    }

    @Test
    fun `char array no longer contains the password after wiping`() {
        val password = "correct horse battery staple".toCharArray()

        SecureMemory.wipe(password)

        assertFalse(
            "password still readable after wipe",
            String(password).contains("horse")
        )
    }

    /**
     * A 32-byte all-zero buffer is a valid AES key, which is why the wipe
     * passes through random bytes first — see SecureMemory's class doc. This
     * asserts the end state callers rely on (zeroed), and that a large buffer
     * is fully covered rather than only its first block.
     */
    @Test
    fun `whole buffer is covered, not just the first bytes`() {
        val key = ByteArray(4096) { (it % 251).toByte() }

        SecureMemory.wipe(key)

        assertTrue("some bytes survived the wipe", key.all { it == 0.toByte() })
    }
}
