package com.subrosa.desktop

import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopLogTest {
    private fun captureErr(block: () -> Unit): String {
        val old = System.err
        val buf = ByteArrayOutputStream()
        System.setErr(PrintStream(buf, true, "UTF-8"))
        try { block() } finally { System.setErr(old) }
        return buf.toString("UTF-8")
    }

    @Test
    fun `debug is off by default and its message is never even built`() {
        val was = DesktopLog.enabled
        try {
            DesktopLog.enabled = false
            var built = false
            val out = captureErr { DesktopLog.d("T") { built = true; "secret ABCD1234" } }
            assertFalse(built, "the lambda must not run when logging is off")
            assertEquals("", out)
        } finally { DesktopLog.enabled = was }
    }

    @Test
    fun `debug prints when enabled`() {
        val was = DesktopLog.enabled
        try {
            DesktopLog.enabled = true
            val out = captureErr { DesktopLog.d("T") { "hello ${DesktopLog.fp("ABCDEF0123456789")}" } }
            assertTrue(out.contains("[T] hello ABCD…"), out)
            assertFalse(out.contains("ABCDEF0123456789"))
        } finally { DesktopLog.enabled = was }
    }

    @Test
    fun `errors are always printed, with the exception type and message but no stack trace`() {
        val was = DesktopLog.enabled
        try {
            DesktopLog.enabled = false
            val out = captureErr { DesktopLog.e("T", "boom", IllegalStateException("bad")) }
            assertEquals("[T] boom (IllegalStateException: bad)", out.trim())
        } finally { DesktopLog.enabled = was }
    }

    @Test
    fun `fp shortens to four characters and tolerates null and blank`() {
        assertEquals("ABCD…", DesktopLog.fp("ABCDEF0123456789"))
        assertEquals("12…", DesktopLog.fp(12).let { it.replace("12…", "12…") })
        assertEquals("-", DesktopLog.fp(null))
        assertEquals("-", DesktopLog.fp("  "))
    }
}
