package com.bcon.messenger

import android.content.Context
import org.json.JSONArray
import java.security.SecureRandom

object AnonTokenManager {

    private const val PREF_MY_TOKENS = "anon_my_tokens"
    private const val PREFS_NAME = "anon_token_store"
    private const val PREF_CT_PREFIX = "anon_ct_"
    private const val POOL_SIZE = 50
    private const val REFILL_THRESHOLD = 10
    private const val BATCH_TO_SHARE = 20

    private val rng = SecureRandom()

    private fun prefs(ctx: Context) = EncryptedStorage.getEncryptedPrefs(ctx, PREFS_NAME)

    // ── Мои токены (сервер слушает их для меня) ───────────────────────────────

    fun getMyTokens(ctx: Context): List<String> {
        val json = prefs(ctx).getString(PREF_MY_TOKENS, "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    fun ensureMyTokenPool(ctx: Context): List<String> {
        val existing = getMyTokens(ctx)
        if (existing.size >= POOL_SIZE / 2) return existing
        val needed = POOL_SIZE - existing.size
        val newTokens = (1..needed).map { generateToken() }
        val combined = existing + newTokens
        prefs(ctx).edit().putString(PREF_MY_TOKENS, JSONArray(combined).toString()).apply()
        return combined
    }

    fun consumeMyToken(ctx: Context, token: String) {
        val tokens = getMyTokens(ctx).toMutableList()
        if (tokens.remove(token)) {
            prefs(ctx).edit().putString(PREF_MY_TOKENS, JSONArray(tokens).toString()).apply()
        }
    }

    // Возвращает BATCH_TO_SHARE токенов для отправки контакту (без удаления из пула)
    fun tokensToShareWith(ctx: Context): List<String> = ensureMyTokenPool(ctx).take(BATCH_TO_SHARE)

    // ── Токены контакта (отправляем ему — сервер роутит к нему) ──────────────

    fun getContactTokens(ctx: Context, fingerprint: String): List<String> {
        val key = "$PREF_CT_PREFIX$fingerprint"
        val json = prefs(ctx).getString(key, "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    fun addContactTokens(ctx: Context, fingerprint: String, tokens: List<String>) {
        val existing = getContactTokens(ctx, fingerprint).toMutableList()
        existing.addAll(tokens.filter { it.isNotBlank() && it.length == 32 })
        prefs(ctx).edit()
            .putString("$PREF_CT_PREFIX$fingerprint", JSONArray(existing).toString())
            .apply()
    }

    fun needsRefill(ctx: Context, fingerprint: String): Boolean =
        getContactTokens(ctx, fingerprint).size < REFILL_THRESHOLD

    // Потребляет следующий токен контакта для отправки. Возвращает null если пул пуст.
    fun consumeNextContactToken(ctx: Context, fingerprint: String): String? {
        val tokens = getContactTokens(ctx, fingerprint).toMutableList()
        if (tokens.isEmpty()) return null
        val token = tokens.removeAt(0)
        prefs(ctx).edit()
            .putString("$PREF_CT_PREFIX$fingerprint", JSONArray(tokens).toString())
            .apply()
        return token
    }

    // ── Служебное ─────────────────────────────────────────────────────────────

    fun generateDummyToken(): String = generateToken()

    private fun generateToken(): String {
        val bytes = ByteArray(16)
        rng.nextBytes(bytes)
        val sb = StringBuilder(32)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            if (v < 16) sb.append('0')
            sb.append(v.toString(16))
        }
        return sb.toString()
    }
}
