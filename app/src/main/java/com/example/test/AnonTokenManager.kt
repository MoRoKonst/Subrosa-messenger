package com.subrosa.messenger

import android.content.Context
import org.json.JSONArray
import java.security.SecureRandom

object AnonTokenManager {

    private const val PREF_MY_TOKENS = "anon_my_tokens"
    private const val PREFS_NAME = "anon_token_store"
    private const val PREF_CT_PREFIX = "anon_ct_"
    private const val POOL_SIZE = 50
    // 16, not just "some low number" — refilling isn't instant: it takes a round
    // trip (I send my batch → they receive it → THEY reciprocate with a fresh
    // batch of theirs, which is what actually replenishes my supply). Needs
    // enough headroom that typing + a couple of messages don't outrun that
    // round trip before it completes.
    private const val REFILL_THRESHOLD = 16
    private const val BATCH_TO_SHARE = 20
    // Tokens below this count are off-limits to ordinary traffic (text,
    // typing, receipts, video/image/file chunks — everything routed through
    // sendAnonOrDirect). Only the token-resupply message itself
    // (sendAnonTokensTo's own consume call, allowReserve=true) may spend
    // them. Found live: REFILL_THRESHOLD alone doesn't protect against a
    // burst (e.g. a batched video circle) draining the pool to zero faster
    // than the resupply round trip can land — at zero tokens, even the
    // resupply signal itself would have nothing to send with and had to
    // fall back to the much slower ~30s mailbox poll cycle. Reserving a
    // handful exclusively for that one message keeps the fast path alive.
    private const val RESERVE_TOKENS = 3

    private val rng = SecureRandom()

    private fun prefs(ctx: Context) = EncryptedStorage.getEncryptedPrefs(ctx, PREFS_NAME)

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

    fun tokensToShareWith(ctx: Context): List<String> = ensureMyTokenPool(ctx).take(BATCH_TO_SHARE)

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

        val capped = if (existing.size > POOL_SIZE) existing.takeLast(POOL_SIZE) else existing
        prefs(ctx).edit()
            .putString("$PREF_CT_PREFIX$fingerprint", JSONArray(capped).toString())
            .apply()
    }

    fun needsRefill(ctx: Context, fingerprint: String): Boolean =
        getContactTokens(ctx, fingerprint).size < REFILL_THRESHOLD

    /** Wipes any leftover token pool received from [fingerprint] — call on
     * contact deletion. The fingerprint is derived from their public key, so
     * re-adding the same person via a fresh invite reuses the same
     * fingerprint; without this, old tokens (issued under a prior mailbox
     * tag / bootstrap cycle, possibly no longer valid on their end either)
     * would still get consumed as if the relationship had never been reset. */
    fun clearContactTokens(ctx: Context, fingerprint: String) {
        prefs(ctx).edit().remove("$PREF_CT_PREFIX$fingerprint").apply()
    }

    /** [allowReserve] false (the default, used by sendAnonOrDirect for all
     * ordinary traffic) refuses to spend the last RESERVE_TOKENS — those are
     * held back exclusively for sendAnonTokensTo's own resupply message
     * (allowReserve=true), so the pool can never hit true zero for a contact
     * we can still reach: at least one more resupply attempt over the fast
     * anon_message path stays possible instead of always having to fall back
     * to the slower mailbox poll cycle. */
    fun consumeNextContactToken(ctx: Context, fingerprint: String, allowReserve: Boolean = false): String? {
        val tokens = getContactTokens(ctx, fingerprint).toMutableList()
        if (tokens.isEmpty()) return null
        if (!allowReserve && tokens.size <= RESERVE_TOKENS) return null
        val token = tokens.removeAt(0)
        prefs(ctx).edit()
            .putString("$PREF_CT_PREFIX$fingerprint", JSONArray(tokens).toString())
            .apply()
        return token
    }

    private const val PREF_MY_MBOX_TAGS   = "mbox_my_tags"
    private const val PREF_CT_MBOX_PREFIX = "mbox_ct_"
    private const val MBOX_TOTAL = 20

    fun addMyMailboxTag(ctx: Context, tag: String) {
        val tags = getMyMailboxTags(ctx).toMutableList()
        if (tag !in tags) {
            tags.add(tag)
            prefs(ctx).edit().putString(PREF_MY_MBOX_TAGS, JSONArray(tags).toString()).apply()
        }
    }

    fun getMyMailboxTags(ctx: Context): List<String> {
        val json = prefs(ctx).getString(PREF_MY_MBOX_TAGS, "[]") ?: "[]"
        return try { val a = JSONArray(json); (0 until a.length()).map { a.getString(it) } }
        catch (e: Exception) { emptyList() }
    }

    fun removeMyMailboxTag(ctx: Context, tag: String) {
        val tags = getMyMailboxTags(ctx).toMutableList()
        if (tags.remove(tag))
            prefs(ctx).edit().putString(PREF_MY_MBOX_TAGS, JSONArray(tags).toString()).apply()
    }

    fun setContactMailboxTag(ctx: Context, fingerprint: String, tag: String) {
        prefs(ctx).edit().putString("$PREF_CT_MBOX_PREFIX$fingerprint", tag).apply()
    }

    fun getContactMailboxTag(ctx: Context, fingerprint: String): String? =
        prefs(ctx).getString("$PREF_CT_MBOX_PREFIX$fingerprint", null)

    fun clearContactMailboxTag(ctx: Context, fingerprint: String) {
        prefs(ctx).edit().remove("$PREF_CT_MBOX_PREFIX$fingerprint").apply()
    }

    private const val PREF_MY_PERSISTENT_TAG = "mbox_my_persistent_tag"

    /** A mailbox tag generated once per install and reused indefinitely —
     * independent of any invite code's TTL. Exchanged with a contact
     * alongside normal token reciprocation (see sendAnonTokensTo) so that
     * contact's copy of getContactMailboxTag(me) gets refreshed to this tag
     * instead of going stale — see docs/ISSUE_backup_identity_hijack.md,
     * health-check "tag freshness" (item 5). */
    fun getOrCreateMyPersistentMailboxTag(ctx: Context): String {
        val existing = prefs(ctx).getString(PREF_MY_PERSISTENT_TAG, null)
        if (existing != null) return existing
        val tag = generateToken()
        prefs(ctx).edit().putString(PREF_MY_PERSISTENT_TAG, tag).apply()
        addMyMailboxTag(ctx, tag)
        return tag
    }

    /** Forces PREF_MY_PERSISTENT_TAG to match [tag] — the tag actually embedded
     * in the currently active/displayed invite code. Found live: a device with
     * an invite code cached from before this "persistent tag" concept existed
     * (still within its 7-day TTL, so ensureMyMailboxTagRegistered() just
     * reused it as-is) never called getOrCreateMyPersistentMailboxTag() to
     * seed the pref — so the first read of it (e.g. from
     * removeMailboxTagIfEphemeral()'s "is this the tag I should never prune"
     * check) minted an unrelated fresh value instead of matching the tag
     * actually in use, and the real tag got pruned anyway on first use.
     * Call this every time the active invite code is resolved (cached or
     * fresh) so the two can never diverge again. */
    fun syncMyPersistentMailboxTag(ctx: Context, tag: String) {
        prefs(ctx).edit().putString(PREF_MY_PERSISTENT_TAG, tag).apply()
        addMyMailboxTag(ctx, tag)
    }

    /** Wipes all token/tag state for every contact — used when replacing the
     * device's active identity with a different one from a backup, see
     * BackupManager.wipeCurrentIdentityData(). Tokens/tags are meaningless
     * once the identity they were bound to is gone. */
    fun clearAll(ctx: Context) {
        prefs(ctx).edit().clear().apply()
    }

    fun buildFetchTagList(ctx: Context): List<String> {
        val real = getMyMailboxTags(ctx)
        val fakeCount = maxOf(MBOX_TOTAL - real.size, 0)
        val fakes = (1..fakeCount).map { generateToken() }
        return (real + fakes).shuffled(java.util.Random(rng.nextLong()))
    }

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
