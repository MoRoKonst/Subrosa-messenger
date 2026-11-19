package com.subrosa.desktop

/**
 * The desktop client's only logging entry point.
 *
 * Why it exists: `S15-1` in docs/KNOWN_SECURITY_ISSUES.md. The client used to call
 * `println`/`System.err.println` at ~300 sites, about 120 of them with a contact
 * fingerprint interpolated, some on the normal send path. Where stdout/stderr is kept
 * (journald, ~/.xsession-errors on Linux/macOS) that is the "who talks to whom, when"
 * graph on disk — the Android release leak `S14-1`, again.
 *
 * - [d] is debug output. It is OFF by default and only turned on by the environment
 *   variable `SUBROSA_DEBUG_LOG=1`. There is deliberately no "release vs debug build"
 *   detection: the desktop has no ProGuard and no reliable build flag, and a silent
 *   "off in release" is exactly what failed in S14-1. The message is a lambda so that,
 *   when logging is off, the string (and any identifier interpolated into it) is never
 *   even built in memory.
 * - [e] is a real error. It is ALWAYS printed (crash diagnosis needs it) and so it must
 *   never carry an identifier except through [fp].
 * - [fp] shortens any identifier (fingerprint, id, key, tag…) to its first 4 characters.
 */
object DesktopLog {
    @PublishedApi
    @Volatile
    internal var enabled: Boolean = System.getenv("SUBROSA_DEBUG_LOG") == "1"

    inline fun d(tag: String, msg: () -> String) {
        if (enabled) System.err.println("[$tag] ${msg()}")
    }

    fun e(tag: String, msg: String, t: Throwable? = null) {
        val suffix = if (t != null) " (${t.javaClass.simpleName}: ${t.message})" else ""
        System.err.println("[$tag] $msg$suffix")
    }

    /** First 4 characters plus an ellipsis; null or blank becomes "-". */
    fun fp(value: Any?): String {
        val s = value?.toString()
        return if (s.isNullOrBlank()) "-" else s.take(4) + "…"
    }
}
