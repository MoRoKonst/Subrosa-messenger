package com.subrosa.messenger

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale
import kotlin.random.Random

/**
 * Covers the parts of DecoyData that can fail silently and would only be
 * noticed by whoever is inspecting a seized phone:
 *
 *  - the canary PDF's cross-reference table, which has to carry byte-exact
 *    offsets. Get those wrong and the attachment in the decoy chat refuses to
 *    open, which is far more conspicuous than the 256 random bytes it replaced.
 *  - the timeline, which has to be strictly ordered and sit inside plausible
 *    working hours. A solicitor's thread stamped 03:40 on a Sunday reads wrong
 *    without the reader being able to say why.
 *
 * The seed-to-dataset path itself needs a Context and Keystore-backed prefs,
 * so it isn't covered here; businessify/layoutTimestamps/buildPdf are exposed
 * as internal specifically so the risky pure logic is testable.
 */
@Config(sdk = [34])
@RunWith(RobolectricTestRunner::class)
class DecoyDataTest {

    // ── Generated inbox ─────────────────────────────────────────────────────

    private fun sessionWithSeed(label: String, anchor: Long) = DecoyData.Session(
        seed = label.toByteArray(Charsets.UTF_8).copyOf(32),
        anchor = anchor,
        honeyFileName = "",
        sent = HashMap(),
        hidden = mutableSetOf()
    )

    /** Dumps a full generated inbox so the output can actually be read and
     *  judged, rather than inferred from the grammar. Not an assertion of exact
     *  text — that would be brittle and would freeze the content — but the
     *  structural checks below run against the same real generator output. */
    @Test
    fun `dump a generated inbox for inspection`() {
        val context: Context = ApplicationProvider.getApplicationContext()
        val anchor = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.UK)
            .parse("2026-11-05 17:40")!!.time
        val fmt = SimpleDateFormat("EEE dd MMM HH:mm", Locale.UK)

        listOf("seed-alpha", "seed-beta").forEach { label ->
            val generated = DecoyData.generate(context, sessionWithSeed(label, anchor))
            println("\n################ SEED: $label ################")
            generated.threads.forEach { t ->
                println("\n=== ${t.name}  [unread=${t.unreadCount}, last=${fmt.format(t.lastTimestamp)}]")
                t.messages.forEach { m ->
                    val who = if (m.isOwn) "  me >" else "them >"
                    println("  ${fmt.format(m.timestamp)} $who ${m.text}")
                }
            }
        }
    }

    @Test
    fun `two seeds produce completely different inboxes`() {
        val context: Context = ApplicationProvider.getApplicationContext()
        val anchor = System.currentTimeMillis()
        val a = DecoyData.generate(context, sessionWithSeed("seed-alpha", anchor)).threads
        val b = DecoyData.generate(context, sessionWithSeed("seed-beta", anchor)).threads

        val namesA = a.map { it.name }.toSet()
        val namesB = b.map { it.name }.toSet()
        assertTrue(
            "two installs must not share contacts — overlap was ${namesA intersect namesB}",
            (namesA intersect namesB).isEmpty()
        )
        val textsA = a.flatMap { t -> t.messages.map { it.text } }.toSet()
        val textsB = b.flatMap { t -> t.messages.map { it.text } }.toSet()
        // Some short interjections ("Go on.", "Noted.") legitimately recur —
        // what must not happen is the bulk of the history matching.
        val overlap = (textsA intersect textsB).size.toDouble() / textsA.size
        assertTrue("message overlap between seeds too high: $overlap", overlap < 0.15)
    }

    @Test
    fun `same seed regenerates byte-identical content`() {
        // The property the whole pinned-session design relies on: a decoy that
        // rewrites itself between recompositions is worse than no decoy.
        val context: Context = ApplicationProvider.getApplicationContext()
        val anchor = System.currentTimeMillis()
        val first = DecoyData.generate(context, sessionWithSeed("seed-alpha", anchor)).threads
        val second = DecoyData.generate(context, sessionWithSeed("seed-alpha", anchor)).threads

        assertEquals(first.map { it.name }, second.map { it.name })
        assertEquals(
            first.flatMap { t -> t.messages.map { it.text } },
            second.flatMap { t -> t.messages.map { it.text } }
        )
        assertEquals(
            first.flatMap { t -> t.messages.map { it.timestamp } },
            second.flatMap { t -> t.messages.map { it.timestamp } }
        )
    }

    @Test
    fun `inbox is ordered newest first and every slot is substituted`() {
        val context: Context = ApplicationProvider.getApplicationContext()
        val threads = DecoyData.generate(
            context,
            sessionWithSeed("seed-alpha", System.currentTimeMillis())
        ).threads

        assertTrue("expected a populated inbox", threads.size >= 6)
        for (i in 1 until threads.size) {
            assertTrue(
                "thread list must be ordered by recency",
                threads[i].lastTimestamp <= threads[i - 1].lastTimestamp
            )
        }
        threads.forEach { t ->
            assertTrue("thread has no messages: ${t.name}", t.messages.isNotEmpty())
            t.messages.forEach { m ->
                // An unsubstituted slot is the single most obvious generator
                // tell there is, and a typo in a template name produces exactly
                // that with no other symptom.
                assertFalse(
                    "unsubstituted placeholder in: ${m.text}",
                    m.text.contains('{') || m.text.contains('}')
                )
            }
            // Both sides must speak — a monologue reads wrong immediately.
            assertTrue("no incoming messages in ${t.name}", t.messages.any { !it.isOwn })
            assertTrue("no outgoing messages in ${t.name}", t.messages.any { it.isOwn })
        }
    }

    @Test
    fun `inbox always leaves something unread`() {
        // The first version only marked a thread unread if it happened to end
        // on an incoming message and then rolled 1-in-3, and most scenarios end
        // on an outgoing line — so entire generated inboxes came out with zero
        // unread anywhere. A working inbox with nothing unread is its own tell,
        // and the badge support exists precisely because its absence was one.
        val context: Context = ApplicationProvider.getApplicationContext()
        listOf("seed-alpha", "seed-beta", "seed-gamma", "seed-delta").forEach { label ->
            val threads = DecoyData.generate(
                context,
                sessionWithSeed(label, System.currentTimeMillis())
            ).threads
            assertTrue(
                "seed $label produced an inbox with nothing unread",
                threads.any { it.unreadCount > 0 }
            )
        }
    }

    @Test
    fun `quoted durations stay inside the unit they are quoted in`() {
        // Guards the slot mix-up this caught live: `days` (7..35) was being
        // substituted into "{days} weeks to the next hearing" (35 weeks) and
        // "{days} months' service" (35 months, which contradicted the linked
        // reply "under two years the unfair dismissal risk is limited").
        val context: Context = ApplicationProvider.getApplicationContext()
        val weeksPattern = Regex("""(\d+) weeks""")
        val monthsPattern = Regex("""(\d+) months' service""")

        listOf("seed-alpha", "seed-beta", "seed-gamma", "seed-delta", "seed-eps").forEach { label ->
            DecoyData.generate(context, sessionWithSeed(label, System.currentTimeMillis()))
                .threads
                .flatMap { t -> t.messages.map { it.text } }
                .forEach { text ->
                    weeksPattern.findAll(text).forEach {
                        val n = it.groupValues[1].toInt()
                        assertTrue("implausible duration in: $text", n in 1..40)
                    }
                    monthsPattern.findAll(text).forEach {
                        val n = it.groupValues[1].toInt()
                        assertTrue(
                            "service length of $n months contradicts the advice given: $text",
                            n < 24
                        )
                    }
                }
        }
    }

    @Test
    fun `matter reference and client stay consistent within a thread`() {
        // Referential drift (two matter numbers, two clients in one
        // conversation) is what makes generated dialogue read as generated.
        val context: Context = ApplicationProvider.getApplicationContext()
        val threads = DecoyData.generate(
            context,
            sessionWithSeed("seed-gamma", System.currentTimeMillis())
        ).threads
        val matterPattern = Regex("""\b[A-Z]{3}-\d{4}\b""")

        threads.forEach { t ->
            val matters = t.messages.flatMap { matterPattern.findAll(it.text).map { m -> m.value } }.toSet()
            assertTrue(
                "thread ${t.name} mentions more than one matter reference: $matters",
                matters.size <= 1
            )
        }
    }

    // ── Canary PDF ──────────────────────────────────────────────────────────

    private fun samplePdf(): ByteArray = DecoyData.buildPdf(
        "Advice note - ARD-2291",
        listOf(
            "",
            "Client: Arden Holdings",
            "1. Summary",
            "    1.1 Liability is capped per claim, not in the aggregate.",
            "Round (brackets) and a back\\slash must survive escaping.",
            ""
        )
    )

    @Test
    fun `pdf has the expected header and trailer`() {
        val text = String(samplePdf(), Charsets.ISO_8859_1)
        assertTrue("missing %PDF header", text.startsWith("%PDF-1.4"))
        assertTrue("missing EOF marker", text.trimEnd().endsWith("%%EOF"))
        assertTrue("missing trailer", text.contains("trailer"))
        assertTrue("missing catalog root", text.contains("/Root 1 0 R"))
    }

    @Test
    fun `xref offsets point at the start of each object`() {
        val bytes = samplePdf()
        val text = String(bytes, Charsets.ISO_8859_1)

        val startxref = text.substringAfterLast("startxref").trim().substringBefore("%%EOF").trim().toInt()
        assertTrue("startxref past end of file", startxref < bytes.size)
        assertTrue(
            "startxref does not point at the xref table",
            text.startsWith("xref", startxref)
        )

        // "0 7" — object 0 plus the six real objects.
        val header = text.substring(startxref).lineSequence().elementAt(1).trim()
        assertEquals("0 7", header)

        // Entry 0 is the mandatory free entry; entries 1..6 must each land
        // exactly on "<n> 0 obj".
        val entries = text.substring(startxref)
            .lineSequence()
            .drop(2)
            .take(7)
            .map { it.trim() }
            .toList()
        assertEquals("0000000000 65535 f", entries[0])
        for (n in 1..6) {
            val offset = entries[n].substringBefore(' ').toInt()
            assertTrue(
                "object $n offset $offset is outside the file",
                offset in 0 until bytes.size
            )
            assertTrue(
                "xref entry $n points at '${text.substring(offset, minOf(offset + 12, text.length))}' " +
                    "instead of '$n 0 obj'",
                text.startsWith("$n 0 obj", offset)
            )
        }
    }

    @Test
    fun `content stream length matches the declared Length`() {
        val text = String(samplePdf(), Charsets.ISO_8859_1)
        val declared = text.substringAfter("6 0 obj").substringAfter("/Length ")
            .substringBefore(" ").trim().toInt()
        val stream = text.substringAfter("stream\n").substringBeforeLast("\nendstream")
        assertEquals(declared, stream.toByteArray(Charsets.ISO_8859_1).size)
    }

    @Test
    fun `parentheses and backslashes in text are escaped`() {
        val text = String(samplePdf(), Charsets.ISO_8859_1)
        // The literal must appear escaped, and no unbalanced raw parenthesis
        // from the source line may leak into the stream — an unescaped "(" is
        // what makes a PDF viewer reject the whole content stream.
        assertTrue(text.contains("Round \\(brackets\\)"))
        assertTrue(text.contains("back\\\\slash"))
    }

    @Test
    fun `document is a plausible size for an attachment`() {
        // The point of the rewrite: the old canary was a constant 256 bytes —
        // below the floor any genuine payload here can reach (40-byte Tink
        // header + 16-byte tag + a compressed image/audio/document body). A
        // note of this shape measured 5,554 bytes when checked against pypdf,
        // which sits inside the range the app's real blobs already span.
        val body = List(62) { "    Paragraph $it of the note, at about the length a real one runs to." }
        val size = DecoyData.buildPdf("Advice note - ARD-2291", body).size
        assertTrue("suspiciously small: $size bytes", size > 2_000)
        assertTrue("larger than a short letter should be: $size bytes", size < 200_000)
    }

    // ── Timeline ────────────────────────────────────────────────────────────

    private fun fieldsOf(ts: Long): Triple<Int, Int, Int> {
        val cal = Calendar.getInstance(Locale.UK).apply { timeInMillis = ts }
        return Triple(
            cal.get(Calendar.DAY_OF_WEEK),
            cal.get(Calendar.HOUR_OF_DAY),
            cal.get(Calendar.MINUTE)
        )
    }

    @Test
    fun `businessify never lands on a weekend or in the small hours`() {
        val rnd = Random(20260101)
        val start = System.currentTimeMillis()
        for (i in 0 until 2_000) {
            // Sweep across whole days so every weekday and every hour is hit.
            val candidate = start - i * 37L * 60_000L
            val (dow, hour, _) = fieldsOf(DecoyData.businessify(candidate, rnd))
            assertTrue("landed on a weekend (dow=$dow)", dow != Calendar.SATURDAY && dow != Calendar.SUNDAY)
            assertTrue("landed at $hour:00, outside plausible hours", hour in 8..23)
        }
    }

    @Test
    fun `layoutTimestamps is strictly increasing and ends when asked`() {
        val rnd = Random(777)
        val end = System.currentTimeMillis()
        val times = DecoyData.layoutTimestamps(end, 12, rnd)

        assertEquals(12, times.size)
        for (i in 1 until times.size) {
            assertTrue(
                "message $i (${times[i]}) is not after message ${i - 1} (${times[i - 1]})",
                times[i] > times[i - 1]
            )
        }
        // The last message is the thread's own end point, pulled into working
        // hours — so at or before the requested end, never after it.
        assertTrue("thread ends in the future", times.last() <= end)
    }

    @Test
    fun `layoutTimestamps keeps every message inside working hours`() {
        val rnd = Random(4242)
        val times = DecoyData.layoutTimestamps(System.currentTimeMillis(), 40, rnd)
        times.forEach { ts ->
            val (dow, hour, _) = fieldsOf(ts)
            assertTrue("weekend message", dow != Calendar.SATURDAY && dow != Calendar.SUNDAY)
            assertTrue("message at $hour:00", hour in 8..23)
        }
    }

    @Test
    fun `a single-message thread still produces one timestamp`() {
        val times = DecoyData.layoutTimestamps(System.currentTimeMillis(), 1, Random(1))
        assertEquals(1, times.size)
    }
}
