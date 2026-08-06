package com.subrosa.messenger

val EMOJI_SET = listOf(
    "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼",
    "🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔",
    "🐧","🐦","🦆","🦅","🦉","🦇","🐺","🐗",
    "🐴","🦄","🐝","🐛","🦋","🐌","🐞","🐜",
    "🦟","🦗","🦂","🐢","🐍","🦎","🦖","🦕",
    "🐙","🦑","🦐","🦀","🐡","🐠","🐟","🐬",
    "🐳","🐋","🦈","🐊","🐅","🐆","🦓","🦍",
    "🦧","🐘","🦛","🦏","🐪","🐫","🦒","🦘"
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