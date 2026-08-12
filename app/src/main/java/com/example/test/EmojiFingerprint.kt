package com.subrosa.messenger

// Curated to avoid visually near-duplicate pairs a user could mistake for
// each other during a manual key-verification glance — e.g. the original
// set had both 🐪 (dromedary) and 🐫 (bactrian), differing only by hump
// count, plus 🐳/🐋 (whale, differ only by spout), 🐅/🐯 (tiger body vs
// tiger face — both just read as "tiger"), and 🐟/🐠 (fish, differ mainly
// by stripe color). Each of those pairs undermines the whole point of an
// emoji fingerprint: an attacker's substituted key could differ only in a
// symbol the user isn't reliably going to notice swapped. Replaced one of
// each pair with something silhouette-distinct from everything else in the
// set (🦔🦭🦌🦥) — found live, reported by the user while reading the source.
val EMOJI_SET = listOf(
    "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼",
    "🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔",
    "🐧","🐦","🦆","🦅","🦉","🦇","🐺","🐗",
    "🐴","🦄","🐝","🐛","🦋","🐌","🐞","🐜",
    "🦟","🦗","🦂","🐢","🐍","🦎","🦖","🦕",
    "🐙","🦑","🦐","🦀","🐡","🦥","🐟","🐬",
    "🐳","🦭","🦈","🐊","🦌","🐆","🦓","🦍",
    "🦧","🐘","🦛","🦏","🐪","🦔","🦒","🦘"
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