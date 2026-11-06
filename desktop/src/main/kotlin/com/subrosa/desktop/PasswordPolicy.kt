package com.subrosa.desktop

// Ported from Android's PasswordPolicy.kt — shared between RegisterScreen,
// ProfileScreen's ChangePasswordDialog and BackupDialog so all three enforce
// identical rules. This password is the sole entropy source feeding the
// PBKDF2 that wraps the Storage Master Key (StorageKeyManager.kt) — and on
// backup export it becomes the login password on restore — so a length
// floor alone isn't enough; known-weak passwords are rejected explicitly.
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
