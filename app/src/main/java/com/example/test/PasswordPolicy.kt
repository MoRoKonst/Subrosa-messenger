package com.subrosa.messenger

// Shared between RegisterScreen (initial password) and ChangePasswordScreen (later
// changes) so both enforce identical rules. This password is the sole entropy
// source feeding the 300k-iteration PBKDF2 that wraps the Storage Master Key
// (StorageKeyManager.kt) — with only a length floor enforced, a trivial password
// like "123456" or "12345678" is directly offline-crackable in seconds from a
// stolen encrypted-prefs blob. The length check alone doesn't catch that, so
// known-weak passwords are rejected explicitly.
object PasswordPolicy {

    const val MIN_LENGTH = 8

    private val COMMON_PASSWORDS = setOf(
        "12345678", "123456789", "1234567890", "password", "password1", "qwertyui",
        "qwerty123", "11111111", "00000000", "87654321", "letmein1", "iloveyou",
        "admin123", "welcome1", "monkey123", "dragon123", "football", "baseball",
        "trustno1", "abc12345", "changeme", "princess", "sunshine", "superman",
        "1q2w3e4r", "zxcvbnm1", "qazwsxed"
    )

    fun isCommonPassword(password: String): Boolean {
        val normalized = password.lowercase()
        if (normalized in COMMON_PASSWORDS) return true
        // All one repeated character ("aaaaaaaa") or a simple ascending/descending
        // numeric run ("12345678"/"87654321", any length) — cheaper to detect than
        // to enumerate every such combination in the list above.
        if (normalized.toSet().size == 1) return true
        val digits = password.map { it.digitToIntOrNull() }
        if (digits.all { it != null }) {
            val nums = digits.map { it!! }
            val ascending = nums.zipWithNext().all { (a, b) -> b == a + 1 || (a == 9 && b == 0) }
            val descending = nums.zipWithNext().all { (a, b) -> b == a - 1 || (a == 0 && b == 9) }
            if (ascending || descending) return true
        }
        return false
    }
}
