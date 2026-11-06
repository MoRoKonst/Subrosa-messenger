package com.subrosa.messenger

import android.content.Context
import android.util.Log
import org.json.JSONArray
import java.security.SecureRandom

object AnonTokenManager {

    // DEBUG-TOKENLIFE prefix on every log line here — grep-able tag for the
    // 2026-08-17 "messages queued as offline despite a supposedly stable
    // connection" investigation (docs/ISSUE_backup_identity_hijack.md).
    // Suffix-only token logging (last 6 chars, "…abc123") matches the
    // convention server.py already uses in its own [ANON] logs, so a
    // client/server log pair can be matched by eye without exposing the
    // full token value in either log.
    private const val TAG = "AnonTokenManager"
    private fun short(token: String) = "…${token.takeLast(6)}"

    private const val PREF_MY_TOKENS = "anon_my_tokens"
    // Tokens delivered and processed locally, ack sent, but not yet confirmed
    // durable by the server (anon_delivery_ack_ok) — see markMyTokenAckPending()/
    // confirmMyTokenAcked(). A separate state from full removal specifically so
    // these stay in the subscribe_tokens list across a reconnect: if the ack
    // itself was lost in flight, the server's token_pending fallback copy is
    // still there, and re-subscribing is what lets it redeliver so the whole
    // deliver→ack→ack_ok cycle can complete for real.
    private const val PREF_MY_TOKENS_ACK_PENDING = "anon_my_tokens_ack_pending"
    private const val PREFS_NAME = "anon_token_store"
    private const val PREF_CT_PREFIX = "anon_ct_"
    private const val PREF_CT_SPENT_PREFIX = "anon_ct_spent_"
    // Which values from MY_TOKENS were handed to which contact — purely
    // local bookkeeping, never sent to the server (server never learns
    // "which contact" a token belongs to, that invariant is untouched). See
    // recordTokensGivenTo()/getTokensGivenTo() — exists so a compromised
    // contact's still-outstanding tokens can be identified and revoked via
    // unsubscribe_tokens, instead of the only lever being "wipe my entire
    // pool and resupply everyone else too".
    private const val PREF_CT_GIVEN_PREFIX = "anon_ct_given_"
    // Same reasoning as SPENT_HISTORY_CAP — bounded so a long-lived contact
    // relationship doesn't grow this forever.
    private const val GIVEN_HISTORY_CAP = 300
    // Generous relative to POOL_SIZE/BATCH_TO_SHARE — a stale duplicate
    // resupply batch keeps resending the same tokensToShareWith() slice
    // (that function doesn't rotate on its own, only consumeMyToken() on the
    // OTHER end shrinks it) for as long as the sender hasn't had those
    // specific tokens actually used against it, which live testing showed
    // can be many resupply cycles. Capped, not unbounded, purely so this
    // doesn't grow forever for a long-lived contact.
    private const val SPENT_HISTORY_CAP = 300
    private const val POOL_SIZE = 50
    // Safety valve only — see freshTokensToShare()'s comment. Used to be
    // pinned at exactly server.py's MAX_TOKENS_PER_SUBSCRIBE (100) so a full
    // pool still fit in one subscribe_tokens call — but that call is now
    // chunked (see MessengerService.sendSubscribeTokens()), so a pool bigger
    // than 100 no longer risks the server silently truncating a subscribe
    // and dropping outstanding tokens. Raised to 500 (found live 2026-09-20,
    // real cross-device call+chat session): a single contact's resupply can
    // legitimately land 2-3 BATCH_TO_SHARE=20 batches within a few minutes
    // whenever consumption lags behind (exactly what a post-call reconnect
    // plus active chat produces) — the old 100 cap was being hit repeatedly
    // in completely normal use, not just the "essentially never" runaway
    // case it was meant to guard against, and every trim silently drops
    // still-outstanding, still-good tokens (freshTokensToShare()'s own log
    // line literally says so). This is now purely a local-storage runaway
    // guard (a SharedPrefs string list — 500 tokens is a few KB), not a
    // wire-protocol constraint.
    private const val MAX_POOL_HARD_CAP = 500
    // Refilling isn't instant: it takes a round trip (I send my batch → they
    // receive it → THEY reciprocate with a fresh batch of theirs, which is
    // what actually replenishes my supply). Lowered from 16 to 8 — RESERVE_TOKENS
    // already guarantees the resupply message itself can always fire even at
    // zero ordinary-traffic tokens, so this only needs headroom for ordinary
    // traffic during the round trip, not a safety margin against starving the
    // resupply signal too.
    private const val REFILL_THRESHOLD = 8
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

    // Every mutating function below does a plain read-modify-write against
    // SharedPreferences with no atomicity of its own. Found live: MessengerService
    // fires multiple sends concurrently on Dispatchers.IO's thread pool (a text
    // message, a batched ICE signal, a contact_ping/pong can all land within
    // milliseconds of each other for the same contact) — two concurrent calls to
    // consumeNextContactToken() could both read the same token list before either
    // wrote back, both pop index 0 (the SAME token string), and both believe they
    // got a fresh one. The server accepts whichever arrives first (tokens are
    // single-use by design) and rejects the second as "офлайн" — exactly the
    // symptom from a live server log: known-good tokens repeatedly reported
    // unrecognized despite the server never having restarted. Every function that
    // reads-then-writes any of this object's prefs now holds this lock for the
    // whole operation.
    private val lock = Any()

    private fun prefs(ctx: Context) = EncryptedStorage.getEncryptedPrefs(ctx, PREFS_NAME)

    fun getMyTokens(ctx: Context): List<String> {
        val json = prefs(ctx).getString(PREF_MY_TOKENS, "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    fun ensureMyTokenPool(ctx: Context): List<String> = synchronized(lock) {
        val existing = getMyTokens(ctx)
        if (existing.size >= POOL_SIZE / 2) return@synchronized existing
        val needed = POOL_SIZE - existing.size
        val newTokens = (1..needed).map { generateToken() }
        val combined = existing + newTokens
        prefs(ctx).edit().putString(PREF_MY_TOKENS, JSONArray(combined).toString()).apply()
        // These new tokens only become known to the server once subscribe_tokens
        // actually goes out with them included — both call sites (connect()'s
        // initial subscribe and sendAnonTokensTo()'s resupply-triggered one)
        // already re-send the FULL current pool every time, so this alone
        // shouldn't desync anything — logged to confirm that's really true in
        // practice, not just in theory.
        Log.d(TAG, "DEBUG-TOKENLIFE ensureMyTokenPool: топ-ап +${newTokens.size} новых токенов (было ${existing.size}, стало ${combined.size})")
        combined
    }

    /** The list to actually send in a "subscribe_tokens" message — the
     *  active pool PLUS anything still in ACK_PENDING (see
     *  PREF_MY_TOKENS_ACK_PENDING's comment). Deliberately NOT the same
     *  list as ensureMyTokenPool()'s return value alone: an ACK_PENDING
     *  token must still route to this device on reconnect (in case its
     *  original ack was lost), but must never be handed out to a contact
     *  again — tokensToShareWith()/freshTokensToShare() intentionally keep
     *  reading only the active pool, not this. */
    fun tokensToSubscribe(ctx: Context): List<String> =
        (ensureMyTokenPool(ctx) + getMyTokensAckPending(ctx)).distinct()

    fun consumeMyToken(ctx: Context, token: String) = synchronized(lock) {
        val tokens = getMyTokens(ctx).toMutableList()
        if (tokens.remove(token)) {
            prefs(ctx).edit().putString(PREF_MY_TOKENS, JSONArray(tokens).toString()).apply()
        }
    }

    fun getMyTokensAckPending(ctx: Context): List<String> {
        val json = prefs(ctx).getString(PREF_MY_TOKENS_ACK_PENDING, "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    /** Moves [token] out of the active pool (so it's never handed out again —
     *  it's already been used to deliver this message) and into the
     *  ACK_PENDING set, WITHOUT fully forgetting it — see PREF_MY_TOKENS_ACK_PENDING's
     *  comment for why. Call after handleMessage() has actually succeeded and
     *  right before sending anon_delivery_ack; confirmMyTokenAcked() is the
     *  only thing that fully removes it, once the server confirms via
     *  anon_delivery_ack_ok. */
    fun markMyTokenAckPending(ctx: Context, token: String) = synchronized(lock) {
        val tokens = getMyTokens(ctx).toMutableList()
        tokens.remove(token)
        prefs(ctx).edit().putString(PREF_MY_TOKENS, JSONArray(tokens).toString()).apply()
        val pending = getMyTokensAckPending(ctx).toMutableList()
        if (token !in pending) {
            pending.add(token)
            prefs(ctx).edit().putString(PREF_MY_TOKENS_ACK_PENDING, JSONArray(pending).toString()).apply()
        }
    }

    /** Final removal, once the server has confirmed (anon_delivery_ack_ok)
     *  that our ack actually landed and its own pending/spent bookkeeping is
     *  durable. See markMyTokenAckPending(). */
    fun confirmMyTokenAcked(ctx: Context, token: String) = synchronized(lock) {
        val pending = getMyTokensAckPending(ctx).toMutableList()
        if (pending.remove(token)) {
            prefs(ctx).edit().putString(PREF_MY_TOKENS_ACK_PENDING, JSONArray(pending).toString()).apply()
        }
    }

    /** Overwrites MY_TOKENS with values restored from a backup — see
     *  BackupManager.importBackup(). Found live 2026-08-30: a contact who
     *  wasn't backed up keeps whatever tokens THIS device handed them
     *  before the backup was taken (see PREF_CT_PREFIX from their side).
     *  wipeCurrentIdentityData() clears PREF_MY_TOKENS on restore, and
     *  ensureMyTokenPool()/freshTokensToShare() only ever mint brand-new
     *  random values — so a restored device used to re-subscribe a
     *  completely different token pool than the one it had when the
     *  backup was made, permanently orphaning that contact's still-valid
     *  stash (server reports "is_known=False" for tokens this device
     *  itself issued, just before this device forgot they existed).
     *  Restoring the exact same strings here means connect()'s normal
     *  subscribe_tokens call re-registers them with the server exactly as
     *  they were, and that contact's pre-backup tokens work again with no
     *  resupply round-trip required. */
    fun restoreMyTokens(ctx: Context, tokens: List<String>) = synchronized(lock) {
        if (tokens.isEmpty()) return@synchronized
        prefs(ctx).edit().putString(PREF_MY_TOKENS, JSONArray(tokens).toString()).apply()
    }

    fun tokensToShareWith(ctx: Context): List<String> = ensureMyTokenPool(ctx).take(BATCH_TO_SHARE)

    /** Always generates BATCH_TO_SHARE brand-new tokens and prepends them to
     *  my own pool, instead of reusing whatever tokensToShareWith() would
     *  have handed out from the existing (possibly already-exhausted, from
     *  the recipient's point of view) pool.
     *
     *  Found live 2026-08-29 (user's own insight, working through the
     *  mechanics live): ensureMyTokenPool() only tops up once my pool drops
     *  below POOL_SIZE/2 — and it only drops when someone actually spends
     *  one of my tokens by messaging me with it. If a contact's every send
     *  attempt is failing (the exact moment sendAnonTokensTo() is needed
     *  most), nothing is spending my tokens either, so the pool never tops
     *  up, and tokensToShareWith() keeps reoffering the same already-spent
     *  (per the recipient's own spent-history, see addContactTokens())
     *  first 20 forever — a resupply that can never actually resupply
     *  anything, both sides stuck in the same deadlock simultaneously.
     *
     *  Called specifically at the moment a contact needs tokens *now* — not
     *  a substitute for ensureMyTokenPool()'s normal lazy top-up, which
     *  still runs everywhere else (connect()'s subscribe, etc.) and is
     *  fine for the non-emergency case. The caller is responsible for
     *  actually subscribing the returned tokens with the server
     *  (subscribe_tokens) before handing them to the contact, same as
     *  tokensToShareWith() always required.
     *
     *  Found live 2026-08-29 (second bug, same day): this used to cap the
     *  combined list at POOL_SIZE via `.take(POOL_SIZE)`, silently dropping
     *  whichever existing tokens fell off the tail — regardless of whether
     *  a contact had already been handed one of them and hadn't spent it
     *  yet. Unlike ensureMyTokenPool() (which only ever grows the pool,
     *  never truncates), this blind cap meant: every resupply round could
     *  evict up to BATCH_TO_SHARE still-outstanding tokens from MY OWN
     *  subscribed set. A contact holding one of those evicted values gets
     *  permanently stuck — server.py correctly reports "офлайн, сообщение в
     *  очереди" (is_known=True, token_to_ws empty) forever, because I never
     *  re-subscribe that exact value again (freshTokensToShare() always
     *  mints brand-new random ones). Confirmed live via server-side
     *  diagnostic logging: two tokens ("2ad192", "f14fb7") were consumed by
     *  a contact from its locally-cached stash but never appeared in ANY
     *  subscribe_tokens batch their owner sent — genuinely evicted, not a
     *  timing race (a third case, "dd191e", WAS a real race — present in
     *  the very next subscribe batch, self-healed a few seconds later via
     *  the existing token_pending flush-on-resubscribe mechanism; that part
     *  was always working correctly and needs no fix). Now: only spending
     *  (consumeMyToken(), on actual use) ever shrinks the pool. A generous
     *  hard ceiling (MAX_POOL_HARD_CAP) still exists purely as a runaway-
     *  growth safety valve for a pathological repeated-resupply scenario —
     *  it should essentially never be hit in normal use, and hitting it is
     *  logged as a warning since it means real outstanding tokens are being
     *  dropped again, just far less often. */
    fun freshTokensToShare(ctx: Context): List<String> = synchronized(lock) {
        val fresh = (1..BATCH_TO_SHARE).map { generateToken() }
        var combined = fresh + getMyTokens(ctx)
        if (combined.size > MAX_POOL_HARD_CAP) {
            Log.w(TAG, "DEBUG-TOKENLIFE freshTokensToShare: пул превысил аварийный потолок " +
                "($MAX_POOL_HARD_CAP), обрезаю — часть ещё не потраченных токенов может стать недоступной")
            combined = combined.take(MAX_POOL_HARD_CAP)
        }
        prefs(ctx).edit().putString(PREF_MY_TOKENS, JSONArray(combined).toString()).apply()
        Log.d(TAG, "DEBUG-TOKENLIFE freshTokensToShare: +${fresh.size} гарантированно новых токенов (пул стал ${combined.size})")
        fresh
    }

    fun getContactTokens(ctx: Context, fingerprint: String): List<String> {
        val key = "$PREF_CT_PREFIX$fingerprint"
        val json = prefs(ctx).getString(key, "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    private fun getSpentContactTokens(ctx: Context, fingerprint: String): List<String> {
        val json = prefs(ctx).getString("$PREF_CT_SPENT_PREFIX$fingerprint", "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    fun addContactTokens(ctx: Context, fingerprint: String, tokens: List<String>) = synchronized(lock) {
        val existing = getContactTokens(ctx, fingerprint).toMutableList()
        val originalSize = existing.size
        val valid = tokens.filter { it.isNotBlank() && it.length == 32 }.distinct()
        // A duplicate here (a token we already have in this contact's pool
        // arriving again) would explain a token getting reused after it was
        // already legitimately spent once — logged as a warning since it
        // shouldn't normally happen, not just informational noise. Found
        // live (external review): this used to log the duplicate and add it
        // anyway, letting the same token string occupy two slots — two
        // later, unrelated consumeNextContactToken() calls could then each
        // pop one slot and hand out the identical token twice, a genuine
        // local double-spend with no race required. Deduped against both
        // the existing pool and the incoming batch itself before adding.
        val duplicates = valid.filter { it in existing }
        if (duplicates.isNotEmpty()) {
            Log.w(TAG, "DEBUG-TOKENLIFE addContactTokens($fingerprint): ${duplicates.size} токен(ов) уже были в пуле — ${duplicates.map { short(it) }}")
        }
        // Found live 2026-08-29 via server-side DEVLOG-DIAG: "already in the
        // current pool" isn't the whole story — once a token is consumed by
        // consumeNextContactToken(), it's gone from `existing`, so a STALE
        // duplicate resupply batch (the peer resending the same
        // tokensToShareWith() slice because it hasn't rotated yet) looked
        // indistinguishable from a genuinely new token and got re-inserted —
        // resurrecting an already-spent token, which the server then
        // silently drops (spent_tokens check) the next time it's handed out,
        // with the message vanishing and zero client-side error. Filtering
        // against a persistent per-contact spent-history, not just the live
        // pool, is what actually closes this.
        val spent = getSpentContactTokens(ctx, fingerprint)
        val resurrected = valid.filter { it in spent }
        if (resurrected.isNotEmpty()) {
            Log.w(TAG, "DEBUG-TOKENLIFE addContactTokens($fingerprint): ${resurrected.size} токен(ов) уже были потрачены ранее, отброшены — ${resurrected.map { short(it) }}")
        }
        existing.addAll(valid.filterNot { it in existing || it in spent })

        // Found live 2026-08-29 (same root cause as freshTokensToShare()'s
        // fix — see its comment): capping at POOL_SIZE via takeLast() drops
        // entries from the FRONT of the list, but consumeNextContactToken()
        // also consumes from the front (tokens.removeAt(0), oldest-first) —
        // so this used to specifically discard the tokens that were next in
        // line to be spent, before they ever got a chance to be used. Less
        // severe than the other bug (this doesn't leave a message stuck
        // server-side, since consumeNextContactToken() only ever hands out
        // what's actually still in local storage — it just wastes perfectly
        // good already-received tokens and forces more frequent resupply
        // than necessary), but same anti-pattern, fixed the same way: only
        // trim under the same generous hard-cap safety valve, not routinely.
        val capped = if (existing.size > MAX_POOL_HARD_CAP) {
            Log.w(TAG, "DEBUG-TOKENLIFE addContactTokens($fingerprint): пул превысил аварийный потолок " +
                "($MAX_POOL_HARD_CAP), обрезаю — часть ещё не использованных токенов может быть потеряна")
            existing.takeLast(MAX_POOL_HARD_CAP)
        } else existing
        prefs(ctx).edit()
            .putString("$PREF_CT_PREFIX$fingerprint", JSONArray(capped).toString())
            .apply()
        Log.d(TAG, "DEBUG-TOKENLIFE addContactTokens($fingerprint): +${valid.size} (было $originalSize, стало ${capped.size})")
    }

    fun needsRefill(ctx: Context, fingerprint: String): Boolean =
        getContactTokens(ctx, fingerprint).size < REFILL_THRESHOLD

    /** Wipes any leftover token pool received from [fingerprint] — call on
     * contact deletion. The fingerprint is derived from their public key, so
     * re-adding the same person via a fresh invite reuses the same
     * fingerprint; without this, old tokens (issued under a prior mailbox
     * tag / bootstrap cycle, possibly no longer valid on their end either)
     * would still get consumed as if the relationship had never been reset. */
    fun clearContactTokens(ctx: Context, fingerprint: String) = synchronized(lock) {
        prefs(ctx).edit()
            .remove("$PREF_CT_PREFIX$fingerprint")
            .remove("$PREF_CT_SPENT_PREFIX$fingerprint")
            .remove("$PREF_CT_GIVEN_PREFIX$fingerprint")
            .apply()
    }

    /** Records that [tokens] (a batch just handed to [fingerprint] via
     *  anon_message/mailbox) came from MY_TOKENS — call right after every
     *  freshTokensToShare() that actually gets sent. Purely local; the
     *  server never sees this mapping. Used by getTokensGivenTo() to know
     *  what to list in an unsubscribe_tokens call if this contact is later
     *  revoked (see revokeContactTokens() in MessengerService.kt). */
    fun recordTokensGivenTo(ctx: Context, fingerprint: String, tokens: List<String>) = synchronized(lock) {
        if (tokens.isEmpty()) return@synchronized
        val key = "$PREF_CT_GIVEN_PREFIX$fingerprint"
        val existing = getTokensGivenTo(ctx, fingerprint)
        val combined = (existing + tokens).distinct().takeLast(GIVEN_HISTORY_CAP)
        prefs(ctx).edit().putString(key, JSONArray(combined).toString()).apply()
    }

    fun getTokensGivenTo(ctx: Context, fingerprint: String): List<String> {
        val json = prefs(ctx).getString("$PREF_CT_GIVEN_PREFIX$fingerprint", "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    fun clearTokensGivenTo(ctx: Context, fingerprint: String) = synchronized(lock) {
        prefs(ctx).edit().remove("$PREF_CT_GIVEN_PREFIX$fingerprint").apply()
    }

    /** Wipes MY OWN token pool (the tokens I generated and handed out for
     *  others to reach me) — call on chat deletion, alongside
     *  clearContactTokens(). Found live 2026-08-29: deleting a chat only
     *  ever cleared the OTHER side's bookkeeping; my own pool (PREF_MY_TOKENS)
     *  was untouched, and a token I'd shared can have an undelivered message
     *  sitting in the server's token_pending queue (recipient offline, or
     *  they deleted the chat before it ever got acked). The server has no
     *  concept of "which contact" a token belongs to (that's the whole
     *  point — see AnonTokenManager's anonymous-routing design), so it can't
     *  selectively drop just that one queued message. The only clean client
     *  fix is to stop ever re-subscribing that specific token again — since
     *  ensureMyTokenPool()/subscribe_tokens() always resend my FULL current
     *  pool, wiping it here forces a completely fresh batch on next use,
     *  guaranteeing the stale queued delivery can never resurface into a
     *  freshly re-added version of the same contact. Costs a one-time
     *  resupply churn for any OTHER still-active contacts too (their next
     *  message just triggers a normal resupply round-trip) — an acceptable
     *  trade for correctness, since this only runs on an explicit,
     *  infrequent user action. */
    fun wipeMyTokenPool(ctx: Context) = synchronized(lock) {
        prefs(ctx).edit().remove(PREF_MY_TOKENS).apply()
    }

    /** [allowReserve] false (the default, used by sendAnonOrDirect for all
     * ordinary traffic) refuses to spend the last RESERVE_TOKENS — those are
     * held back exclusively for sendAnonTokensTo's own resupply message
     * (allowReserve=true), so the pool can never hit true zero for a contact
     * we can still reach: at least one more resupply attempt over the fast
     * anon_message path stays possible instead of always having to fall back
     * to the slower mailbox poll cycle. */
    fun consumeNextContactToken(ctx: Context, fingerprint: String, allowReserve: Boolean = false): String? = synchronized(lock) {
        val tokens = getContactTokens(ctx, fingerprint).toMutableList()
        if (tokens.isEmpty()) {
            Log.d(TAG, "DEBUG-TOKENLIFE consumeNextContactToken($fingerprint): пул пуст")
            return@synchronized null
        }
        if (!allowReserve && tokens.size <= RESERVE_TOKENS) {
            Log.d(TAG, "DEBUG-TOKENLIFE consumeNextContactToken($fingerprint): остались только резервные (${tokens.size})")
            return@synchronized null
        }
        val token = tokens.removeAt(0)
        val spent = (getSpentContactTokens(ctx, fingerprint) + token).takeLast(SPENT_HISTORY_CAP)
        prefs(ctx).edit()
            .putString("$PREF_CT_PREFIX$fingerprint", JSONArray(tokens).toString())
            .putString("$PREF_CT_SPENT_PREFIX$fingerprint", JSONArray(spent).toString())
            .apply()
        Log.d(TAG, "DEBUG-TOKENLIFE consumeNextContactToken($fingerprint): взят ${short(token)}, осталось ${tokens.size}")
        token
    }

    // restoreContactToken() (undoes consumeNextContactToken() when a send
    // never actually left the device) was removed entirely — external
    // review 2026-08-23 flagged it as concept-level unsafe for a single-use
    // token: it re-added the token unconditionally even when already
    // present, a direct double-spend path independent of any race. It was
    // already dead code by that point — see MessengerService.kt's three
    // (commented-out) call sites and the "handed out again is worse than
    // one that's simply lost" reasoning there — so removed rather than
    // fixed, per the reviewer's own suggestion, to close off a future
    // caller accidentally reintroducing it. A token lost to a failed send
    // is a pure availability cost; the message itself is still queued and
    // retried through the normal path regardless.

    private const val PREF_MY_MBOX_TAGS   = "mbox_my_tags"
    private const val PREF_CT_MBOX_PREFIX = "mbox_ct_"
    private const val MBOX_TOTAL = 20

    fun addMyMailboxTag(ctx: Context, tag: String) = synchronized(lock) {
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

    fun removeMyMailboxTag(ctx: Context, tag: String) = synchronized(lock) {
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
    fun getOrCreateMyPersistentMailboxTag(ctx: Context): String = synchronized(lock) {
        val existing = prefs(ctx).getString(PREF_MY_PERSISTENT_TAG, null)
        if (existing != null) return@synchronized existing
        val tag = generateToken()
        prefs(ctx).edit().putString(PREF_MY_PERSISTENT_TAG, tag).apply()
        addMyMailboxTag(ctx, tag)
        tag
    }

    /** Forces PREF_MY_PERSISTENT_TAG to match [tag]. Superseded by
     * syncMyInviteMailboxTag() for invite codes specifically (see
     * PREF_MY_INVITE_TAG below) — kept for any other caller still relying on
     * the persistent tag itself being force-synced to a known value. */
    fun syncMyPersistentMailboxTag(ctx: Context, tag: String) = synchronized(lock) {
        prefs(ctx).edit().putString(PREF_MY_PERSISTENT_TAG, tag).apply()
        addMyMailboxTag(ctx, tag)
    }

    private const val PREF_MY_INVITE_TAG = "mbox_my_invite_tag"

    /** The tag embedded in invite codes — deliberately NOT the same value as
     * getOrCreateMyPersistentMailboxTag(). Anyone who merely sees an invite
     * code (without ever becoming a real contact) learns only this
     * throwaway tag, not the one actually used for ongoing communication:
     * removeMailboxTagIfEphemeral() already prunes any tag that isn't the
     * persistent one after its first use, so once someone redeems the code
     * and completes the first mailbox deposit, this tag is spent and stops
     * being polled — a leaked/observed invite code becomes useless the
     * moment it's actually used once, or whenever the user manually
     * regenerates it (see regenerateMyInviteMailboxTag(), wired to
     * ProfileScreen's "Copy" button). The real ongoing tag
     * (getOrCreateMyPersistentMailboxTag) is never published anywhere — a
     * contact only ever learns it via the mailbox_tag field piggybacked on
     * an already-encrypted deposit/token exchange, after the invite tag did
     * its one job of getting the two sides talking. */
    fun getOrCreateMyInviteMailboxTag(ctx: Context): String = synchronized(lock) {
        val existing = prefs(ctx).getString(PREF_MY_INVITE_TAG, null)
        if (existing != null) return@synchronized existing
        regenerateMyInviteMailboxTag(ctx)
    }

    /** Mints a fresh invite tag and immediately stops polling the old one —
     * closing the exposure window is the whole point of regenerating (see
     * ProfileScreen's "Copy" button), so an old value left lingering in
     * getMyMailboxTags() would defeat that. A redeemer holding a
     * just-invalidated code simply needs a fresh one; this is a deliberate
     * trade of a small "regenerated right as someone was redeeming" edge
     * case for closing the window fast. */
    fun regenerateMyInviteMailboxTag(ctx: Context): String = synchronized(lock) {
        val old = prefs(ctx).getString(PREF_MY_INVITE_TAG, null)
        val tag = generateToken()
        prefs(ctx).edit().putString(PREF_MY_INVITE_TAG, tag).apply()
        if (old != null) removeMyMailboxTag(ctx, old)
        addMyMailboxTag(ctx, tag)
        tag
    }

    /** Forces PREF_MY_INVITE_TAG to match [tag] — the tag actually embedded
     * in the currently active/displayed invite code. Mirrors the old
     * syncMyPersistentMailboxTag() fix (see git history): a device with an
     * invite code cached from before this pref existed (still within its
     * TTL, reused as-is) would otherwise never seed PREF_MY_INVITE_TAG, so
     * the first unrelated read of it would mint a value that doesn't match
     * what's actually embedded in the displayed code. Call this every time
     * the active invite code is resolved (cached or fresh). */
    fun syncMyInviteMailboxTag(ctx: Context, tag: String) = synchronized(lock) {
        prefs(ctx).edit().putString(PREF_MY_INVITE_TAG, tag).apply()
        addMyMailboxTag(ctx, tag)
    }

    /** Wipes all token/tag state for every contact — used when replacing the
     * device's active identity with a different one from a backup, see
     * BackupManager.wipeCurrentIdentityData(). Tokens/tags are meaningless
     * once the identity they were bound to is gone. */
    fun clearAll(ctx: Context) = synchronized(lock) {
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
