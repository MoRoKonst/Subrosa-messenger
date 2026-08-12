package com.subrosa.messenger

// Curated to avoid symbols a user could mistake for each other during a
// manual key-verification glance — the whole point of an emoji fingerprint
// is that a substituted key (MITM) should be reliably noticeable, and two
// kinds of problems both defeat that: visually near-identical pairs (🐪
// dromedary vs 🐫 bactrian — differ only by hump count; 🐳/🐋 whale — differ
// only by spout; 🐅/🐯 tiger body vs tiger face — both just read as "tiger";
//🐟/🐠 fish — differ mainly by stripe color; 🦖/🦕 — both just "dinosaur";
// 🐭/🐹 — both just "small rodent"; 🦛/🦏 — both just "big grey animal"), and
// symbols that are individually hard to identify at typical render size
// regardless of pairing (🦗 cricket, 🦂 scorpion, 🐙 octopus, 🦧 orangutan —
// all flagged live by the user reading this file: "я даже понять не могу
// что это вообще такое"). Replaced with silhouette- and color-distinct
// alternatives, keeping the list at exactly 64 entries (the modulo indexing
// depends on that).
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