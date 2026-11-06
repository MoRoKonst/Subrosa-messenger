package com.subrosa.desktop

// Mirrors Android's EmojiFingerprint.kt — must stay byte-for-byte identical
// so the same fingerprint produces the same emoji sequence cross-platform.
// Curated to avoid visually near-duplicate pairs a user could mistake for
// each other during a manual key-verification glance — see Android's copy
// for the full rationale (found live, reported while reading the source).
val EMOJI_SET = listOf(
    "🐶","🐱","🐭","🐿️","🐰","🦊","🐻","🐼",
    "🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔",
    "🐧","🐦","🦆","🦅","🦉","🦇","🐺","🐗",
    "🐴","🦄","🐝","🐛","🦋","🐌","🐞","🐜",
    "🦟","🦩","🦚","🐢","🐍","🦎","🦖","🦤",
    "🦜","🦑","🦐","🦀","🐡","🦥","🐟","🐬",
    "🐳","🦭","🦈","🐊","🦌","🐆","🦓","🦍",
    "🦨","🐘","🦛","🦫","🐪","🦔","🦒","🦘"
)

fun fingerprintToEmoji(fingerprint: String): String {
    return try {
        fingerprint.chunked(2)
            .take(5)
            .joinToString("  ") { EMOJI_SET[it.toInt(16) % EMOJI_SET.size] }
    } catch (e: Exception) {
        "🔑"
    }
}
