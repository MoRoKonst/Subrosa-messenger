package com.subrosa.desktop

import org.json.JSONArray
import java.security.SecureRandom

/**
 * Desktop port of Android's AnonTokenManager.
 * Storage backend swapped from EncryptedSharedPreferences to DesktopStorage
 * (AES-256-GCM at rest) — same key layout and constants otherwise.
 */
object AnonTokenManager {

    // Every mutating function below does a plain read-modify-write against
    // DesktopStorage with no atomicity of its own otherwise. Mirrors
    // Android's AnonTokenManager.kt lock exactly (same live-found race:
    // WebSocketClient fires multiple sends concurrently — a text message, a
    // batched ICE signal, a contact_ping/pong can all land within
    // milliseconds of each other for the same contact — two concurrent
    // calls to consumeNextContactToken() could both read the same token
    // list before either wrote back, both pop the SAME token, and both
    // believe they got a fresh one). Was missing entirely on Desktop before
    // this fix (2026-09-13 single-component audit) — every mutating
    // function here ran fully unsynchronized.
    private val lock = Any()

    private const val TAG = "AnonTokenManager"
    private const val PREF_MY_TOKENS = "anon_my_tokens"
    // Tokens delivered and processed locally, ack sent, but not yet confirmed
    // durable by the server (anon_delivery_ack_ok) — see
    // markMyTokenAckPending()/confirmMyTokenAcked(). A separate state from
    // full removal specifically so these stay in the subscribe_tokens list
    // across a reconnect: if the ack itself was lost in flight, the
    // server's token_pending fallback copy is still there, and
    // re-subscribing is what lets it redeliver so the whole
    // deliver→ack→ack_ok cycle can complete for real. Mirrors Android's
    // AnonTokenManager.kt exactly — was missing entirely on Desktop, along
    // with every call site that uses it (WebSocketClient never even called
    // the plain consumeMyToken() this replaces, so a spent "my" token never
    // left PREF_MY_TOKENS at all: Desktop kept re-subscribing to, and even
    // handing OUT via tokensToShareWith(), tokens the server already
    // considered spent). Found live, 2026-09-13, via the exact symptom this
    // was built to prevent: unexplained message loss plus tokens churning
    // far more than necessary.
    private const val PREF_MY_TOKENS_ACK_PENDING = "anon_my_tokens_ack_pending"
    private const val PREF_CT_PREFIX = "anon_ct_"
    // Per-contact spent-token history — was missing entirely on Desktop
    // before this fix. Mirrors Android's AnonTokenManager.kt exactly: once
    // consumeNextContactToken() spends a token, it's recorded here so a
    // later addContactTokens() call can recognize and drop a "resurrected"
    // duplicate — a stale resupply batch the peer resends because their own
    // tokensToShareWith()-equivalent hasn't rotated yet. Without this,
    // Desktop could re-admit an already-spent token into a contact's active
    // pool, hand it out again via consumeNextContactToken(), and have the
    // server silently drop it (spent_tokens check) with zero client-visible
    // error — the message just vanishes. Found live, 2026-09-13.
    private const val PREF_CT_SPENT_PREFIX = "anon_ct_spent_"
    private const val POOL_SIZE = 50
    // Safety-valve ceiling for a contact's incoming token pool — routine
    // top-ups (addContactTokens) never truncate below this. Mirrors
    // Android's AnonTokenManager.kt MAX_POOL_HARD_CAP
    // (SECURITY_INVARIANTS.md #8): blind position-based truncation at a low
    // cap can silently evict a token a contact is still holding, producing
    // a permanent "offline, message queued" state with no self-healing
    // path. Desktop's own cap used to be POOL_SIZE (50), applied
    // unconditionally on every top-up — found via a desktop/Android
    // symmetry audit, 2026-09-03.
    //
    // Raised from 100 to 500 (found live 2026-09-20, real cross-device
    // call+chat session): 100 used to be pinned to server.py's own
    // MAX_TOKENS_PER_SUBSCRIBE so MY_TOKENS always fit one subscribe_tokens
    // call — no longer needed now that WebSocketClient.sendSubscribeTokens()
    // chunks. Under real call+chat traffic a single contact's resupply can
    // legitimately land 2-3 BATCH_TO_SHARE=20 batches within a few minutes
    // whenever consumption lags behind — 100 was being hit repeatedly in
    // completely normal use (not just the "essentially never" runaway case
    // this guards against), each hit silently dropping still-good,
    // still-outstanding tokens. This is now purely a local-storage runaway
    // guard, not a wire-protocol constraint.
    private const val MAX_POOL_HARD_CAP = 500
    // Same cap as Android's SPENT_HISTORY_CAP — generous relative to
    // POOL_SIZE/BATCH_TO_SHARE (a stale duplicate resupply batch can keep
    // resending the same tokensToShareWith()-equivalent slice for many
    // cycles), bounded only so a long-lived contact relationship doesn't
    // grow this forever.
    private const val SPENT_HISTORY_CAP = 300
    // 8, not just "some low number" — refilling isn't instant: it takes a round
    // trip (I send my batch → they receive it → THEY reciprocate with a fresh
    // batch of theirs, which is what actually replenishes my supply).
    // RESERVE_TOKENS already guarantees the resupply message itself can
    // always fire even at zero ordinary-traffic tokens, so this only needs
    // headroom for ordinary traffic during the round trip, not a safety
    // margin against starving the resupply signal too. Was 16 on Desktop —
    // mismatched against Android's own tuned value with no documented
    // reason; corrected to match, 2026-09-13.
    private const val REFILL_THRESHOLD = 8
    private const val BATCH_TO_SHARE = 20
    // Tokens below this count are off-limits to ordinary traffic (text,
    // typing, receipts, image/file chunks — everything routed through
    // sendAnonOrDirect). Only the token-resupply message itself
    // (sendAnonTokensToLocked's own consume call, allowReserve=true) may
    // spend them — without this reserve, a burst could drain a contact's
    // pool to true zero, and at zero tokens even the resupply signal itself
    // has nothing to send with, forcing a fall back to the much slower
    // mailbox poll cycle. Was missing entirely on Desktop before this fix
    // — consumeNextContactToken() had no reserve concept at all. Mirrors
    // Android's AnonTokenManager.kt exactly.
    private const val RESERVE_TOKENS = 3

    private val rng = SecureRandom()

    private fun short(token: String) = "…${token.takeLast(6)}"

    fun getMyTokens(): List<String> {
        val json = DesktopStorage.get(PREF_MY_TOKENS) ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    /** Restores MY_TOKENS exactly as they were at backup time — must be
     *  called right after a restore wipe, before the next subscribe_tokens
     *  call picks up whatever's here. Mirrors Android's
     *  AnonTokenManager.restoreMyTokens(): without this, a contact who
     *  deposited tokens for this device before the restore keeps holding
     *  tokens this device would otherwise forget entirely. */
    fun restoreMyTokens(tokens: List<String>) = synchronized(lock) {
        if (tokens.isEmpty()) return@synchronized
        DesktopStorage.put(PREF_MY_TOKENS, JSONArray(tokens).toString())
    }

    fun ensureMyTokenPool(): List<String> = synchronized(lock) {
        val existing = getMyTokens()
        if (existing.size >= POOL_SIZE / 2) return@synchronized existing
        val needed = POOL_SIZE - existing.size
        val newTokens = (1..needed).map { generateToken() }
        val combined = existing + newTokens
        DesktopStorage.put(PREF_MY_TOKENS, JSONArray(combined).toString())
        combined
    }

    fun consumeMyToken(token: String) = synchronized(lock) {
        val tokens = getMyTokens().toMutableList()
        if (tokens.remove(token)) {
            DesktopStorage.put(PREF_MY_TOKENS, JSONArray(tokens).toString())
        }
    }

    fun getMyTokensAckPending(): List<String> {
        val json = DesktopStorage.get(PREF_MY_TOKENS_ACK_PENDING) ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    /** The list to actually send in a "subscribe_tokens" message — the
     *  active pool PLUS anything still in ACK_PENDING. Deliberately NOT the
     *  same list as ensureMyTokenPool()'s return value alone: an
     *  ACK_PENDING token must still route to this device on reconnect (in
     *  case its original ack was lost), but must never be handed out to a
     *  contact again — tokensToShareWith() intentionally keeps reading only
     *  the active pool, not this. */
    fun tokensToSubscribe(): List<String> =
        (ensureMyTokenPool() + getMyTokensAckPending()).distinct()

    /** Moves [token] out of the active pool (so it's never handed out again
     *  — it's already been used to deliver this message) and into the
     *  ACK_PENDING set, WITHOUT fully forgetting it. Call after the
     *  "anon_delivery" payload has actually been processed and right before
     *  sending anon_delivery_ack; confirmMyTokenAcked() is the only thing
     *  that fully removes it, once the server confirms via
     *  anon_delivery_ack_ok. */
    fun markMyTokenAckPending(token: String) = synchronized(lock) {
        val tokens = getMyTokens().toMutableList()
        tokens.remove(token)
        DesktopStorage.put(PREF_MY_TOKENS, JSONArray(tokens).toString())
        val pending = getMyTokensAckPending().toMutableList()
        if (token !in pending) {
            pending.add(token)
            DesktopStorage.put(PREF_MY_TOKENS_ACK_PENDING, JSONArray(pending).toString())
        }
    }

    /** Final removal, once the server has confirmed (anon_delivery_ack_ok,
     *  or a per-token "spent" entry in subscribe_tokens_result) that our
     *  ack actually landed and its own pending/spent bookkeeping is
     *  durable. See markMyTokenAckPending(). */
    fun confirmMyTokenAcked(token: String) = synchronized(lock) {
        val pending = getMyTokensAckPending().toMutableList()
        if (pending.remove(token)) {
            DesktopStorage.put(PREF_MY_TOKENS_ACK_PENDING, JSONArray(pending).toString())
        }
    }

    fun tokensToShareWith(): List<String> = ensureMyTokenPool().take(BATCH_TO_SHARE)

    /** Always generates BATCH_TO_SHARE brand-new tokens and prepends them to
     *  my own pool, instead of reusing whatever tokensToShareWith() would
     *  have handed out from the existing (possibly already-exhausted, from
     *  the recipient's point of view) pool. Mirrors Android's
     *  AnonTokenManager.freshTokensToShare() exactly — this is the function
     *  every actual resupply call site (sendAnonTokensToLocked,
     *  depositTokensViaMailbox, sendViaMailbox) must use, NOT
     *  tokensToShareWith(). Was missing from Desktop entirely: all three
     *  call sites used tokensToShareWith() instead, reproducing the exact
     *  "resupply deadlock" Android found and fixed live 2026-08-29 —
     *  ensureMyTokenPool() only tops up once someone actually spends one of
     *  my tokens, so if every send attempt to a contact is failing (the
     *  exact moment a resupply is needed most), the pool never tops up and
     *  tokensToShareWith() keeps reoffering the same already-spent (per the
     *  recipient's own spent-history) slice forever — both sides stuck in
     *  the same deadlock simultaneously. Found live, 2026-09-13.
     *
     *  Caps the combined list at MAX_POOL_HARD_CAP as a runaway-growth
     *  safety valve only (should essentially never be hit in normal use) —
     *  NOT via a blind takeLast/take on a POOL_SIZE-scale cap, which would
     *  silently evict still-outstanding tokens a contact hasn't spent yet. */
    fun freshTokensToShare(): List<String> = synchronized(lock) {
        val fresh = (1..BATCH_TO_SHARE).map { generateToken() }
        var combined = fresh + getMyTokens()
        if (combined.size > MAX_POOL_HARD_CAP) {
            println("$TAG: freshTokensToShare: pool exceeded emergency cap ($MAX_POOL_HARD_CAP), trimming — some still-unspent tokens may become unreachable")
            combined = combined.take(MAX_POOL_HARD_CAP)
        }
        DesktopStorage.put(PREF_MY_TOKENS, JSONArray(combined).toString())
        fresh
    }

    private const val PREF_CT_GIVEN_PREFIX = "anon_ct_given_"
    // Was 200 — mismatched against Android's own tuned value (300) with no
    // documented reason; corrected to match, 2026-09-13.
    private const val GIVEN_HISTORY_CAP = 300

    /** Tracks which of MY OWN tokens I've handed to [fingerprint] — mirrors
     *  Android's AnonTokenManager.recordTokensGivenTo(). Needed so contact
     *  deletion can explicitly revoke them server-side (see
     *  WebSocketClient.revokeContactTokens()) instead of leaving them
     *  subscribed until they're naturally spent. */
    fun recordTokensGivenTo(fingerprint: String, tokens: List<String>) = synchronized(lock) {
        if (tokens.isEmpty()) return@synchronized
        val key = "$PREF_CT_GIVEN_PREFIX$fingerprint"
        val existing = getTokensGivenTo(fingerprint)
        val combined = (existing + tokens).distinct().takeLast(GIVEN_HISTORY_CAP)
        DesktopStorage.put(key, JSONArray(combined).toString())
    }

    fun getTokensGivenTo(fingerprint: String): List<String> {
        val json = DesktopStorage.get("$PREF_CT_GIVEN_PREFIX$fingerprint") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    fun clearTokensGivenTo(fingerprint: String) = synchronized(lock) {
        DesktopStorage.remove("$PREF_CT_GIVEN_PREFIX$fingerprint")
    }

    fun getContactTokens(fingerprint: String): List<String> {
        val key = "$PREF_CT_PREFIX$fingerprint"
        val json = DesktopStorage.get(key) ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    private fun getSpentContactTokens(fingerprint: String): List<String> {
        val json = DesktopStorage.get("$PREF_CT_SPENT_PREFIX$fingerprint") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: Exception) { emptyList() }
    }

    /** Mirrors Android's AnonTokenManager.addContactTokens() exactly,
     *  including the two live-found bugs it fixes:
     *  1. A duplicate already in the active pool (a token we already have
     *     arriving again) used to get re-inserted, letting the same string
     *     occupy two slots — two later, unrelated consumeNextContactToken()
     *     calls could then each pop one slot and hand out the identical
     *     token twice, a genuine local double-spend with no race required.
     *  2. "Already in the active pool" isn't the whole story — once a token
     *     is consumed, it's gone from the active pool, so a STALE duplicate
     *     resupply batch (the peer resending the same slice because it
     *     hasn't rotated) looked indistinguishable from a genuinely new
     *     token and got re-admitted — resurrecting an already-spent token,
     *     which the server then silently drops (spent_tokens check) the
     *     next time it's handed out, the message vanishing with zero
     *     client-side error. Filtering against the persistent per-contact
     *     spent-history (not just the live pool) is what actually closes
     *     this — both checks were entirely absent on Desktop before this
     *     fix, along with the spent-history store itself.
     *  Caps at MAX_POOL_HARD_CAP via takeLast() (drops from the FRONT,
     *  oldest-first) — consumeNextContactToken() also consumes from the
     *  front, so this preserves whatever's next in line to be spent rather
     *  than discarding it before it ever gets a chance. */
    fun addContactTokens(fingerprint: String, tokens: List<String>) = synchronized(lock) {
        val existing = getContactTokens(fingerprint).toMutableList()
        val originalSize = existing.size
        val valid = tokens.filter { it.isNotBlank() && it.length == 32 }.distinct()

        val duplicates = valid.filter { it in existing }
        if (duplicates.isNotEmpty()) {
            println("$TAG: addContactTokens($fingerprint): ${duplicates.size} token(s) already in the pool — ${duplicates.map { short(it) }}")
        }
        val spent = getSpentContactTokens(fingerprint)
        val resurrected = valid.filter { it in spent }
        if (resurrected.isNotEmpty()) {
            println("$TAG: addContactTokens($fingerprint): ${resurrected.size} token(s) already spent earlier, discarded — ${resurrected.map { short(it) }}")
        }
        existing.addAll(valid.filterNot { it in existing || it in spent })

        val capped = if (existing.size > MAX_POOL_HARD_CAP) {
            println("$TAG: addContactTokens($fingerprint): pool exceeded emergency cap ($MAX_POOL_HARD_CAP), trimming — some still-unused tokens may be lost")
            existing.takeLast(MAX_POOL_HARD_CAP)
        } else existing
        DesktopStorage.put("$PREF_CT_PREFIX$fingerprint", JSONArray(capped).toString())
        println("$TAG: addContactTokens($fingerprint): +${valid.size} (was $originalSize, now ${capped.size})")
    }

    fun needsRefill(fingerprint: String): Boolean =
        getContactTokens(fingerprint).size < REFILL_THRESHOLD

    /** Wipes any leftover token pool received from [fingerprint] — call on
     *  contact deletion. The fingerprint is derived from their public key,
     *  so re-adding the same person via a fresh invite reuses the same
     *  fingerprint; without this, old tokens (issued under a prior mailbox
     *  tag/bootstrap cycle, possibly no longer valid on their end either)
     *  would still get consumed as if the relationship had never been
     *  reset. Mirrors Android's AnonTokenManager.clearContactTokens()
     *  exactly (also clears the now-added spent-history key). Was missing
     *  entirely from Desktop — nothing called it, and it didn't exist to
     *  call. Found live, 2026-09-13. */
    fun clearContactTokens(fingerprint: String) = synchronized(lock) {
        DesktopStorage.remove("$PREF_CT_PREFIX$fingerprint")
        DesktopStorage.remove("$PREF_CT_SPENT_PREFIX$fingerprint")
        DesktopStorage.remove("$PREF_CT_GIVEN_PREFIX$fingerprint")
    }

    /** Wipes MY OWN token pool (the tokens I generated and handed out for
     *  others to reach me) — call on chat deletion, alongside
     *  clearContactTokens(). A token I'd shared can have an undelivered
     *  message sitting in the server's token_pending queue (recipient
     *  offline, or they deleted the chat before it ever got acked); the
     *  server has no concept of "which contact" a token belongs to, so it
     *  can't selectively drop just that one queued message. The only clean
     *  fix is to stop ever re-subscribing that specific token again —
     *  wiping here forces a completely fresh batch on next use. Mirrors
     *  Android's AnonTokenManager.wipeMyTokenPool() exactly. Was missing
     *  entirely from Desktop. Found live, 2026-09-13. */
    fun wipeMyTokenPool() = synchronized(lock) {
        DesktopStorage.remove(PREF_MY_TOKENS)
    }

    /** [allowReserve] false (the default, used by sendAnonOrDirect for all
     *  ordinary traffic) refuses to spend the last RESERVE_TOKENS — those
     *  are held back exclusively for sendAnonTokensToLocked's own resupply
     *  message (allowReserve=true), so the pool can never hit true zero for
     *  a contact we can still reach. Also records the spent token into
     *  per-contact spent-history (capped at SPENT_HISTORY_CAP), so a later
     *  addContactTokens() call can recognize and reject a resurrected
     *  duplicate. Both allowReserve and spent-history recording were
     *  entirely absent from Desktop's version before this fix. Mirrors
     *  Android's AnonTokenManager.consumeNextContactToken() exactly. */
    fun consumeNextContactToken(fingerprint: String, allowReserve: Boolean = false): String? = synchronized(lock) {
        val tokens = getContactTokens(fingerprint).toMutableList()
        if (tokens.isEmpty()) {
            println("$TAG: consumeNextContactToken($fingerprint): pool empty")
            return@synchronized null
        }
        if (!allowReserve && tokens.size <= RESERVE_TOKENS) {
            println("$TAG: consumeNextContactToken($fingerprint): only reserve tokens left (${tokens.size})")
            return@synchronized null
        }
        val token = tokens.removeAt(0)
        val spent = (getSpentContactTokens(fingerprint) + token).takeLast(SPENT_HISTORY_CAP)
        DesktopStorage.put("$PREF_CT_PREFIX$fingerprint", JSONArray(tokens).toString())
        DesktopStorage.put("$PREF_CT_SPENT_PREFIX$fingerprint", JSONArray(spent).toString())
        println("$TAG: consumeNextContactToken($fingerprint): took ${short(token)}, remaining ${tokens.size}")
        token
    }

    private const val PREF_MY_MBOX_TAGS   = "mbox_my_tags"
    private const val PREF_CT_MBOX_PREFIX = "mbox_ct_"
    private const val MBOX_TOTAL = 20

    fun addMyMailboxTag(tag: String) = synchronized(lock) {
        val tags = getMyMailboxTags().toMutableList()
        if (tag !in tags) {
            tags.add(tag)
            DesktopStorage.put(PREF_MY_MBOX_TAGS, JSONArray(tags).toString())
        }
    }

    fun getMyMailboxTags(): List<String> {
        val json = DesktopStorage.get(PREF_MY_MBOX_TAGS) ?: "[]"
        return try { val a = JSONArray(json); (0 until a.length()).map { a.getString(it) } }
        catch (e: Exception) { emptyList() }
    }

    fun removeMyMailboxTag(tag: String) = synchronized(lock) {
        val tags = getMyMailboxTags().toMutableList()
        if (tags.remove(tag))
            DesktopStorage.put(PREF_MY_MBOX_TAGS, JSONArray(tags).toString())
    }

    // Ported from Android's AnonTokenManager.kt (desktop/Android symmetry
    // audit, 2026-09-03) — two separate tags, not one:
    //   - persistent: minted once, reused forever, never published in any
    //     shareable invite code. A contact only ever learns it later, via
    //     the mailbox_tag field piggybacked on an already-encrypted
    //     deposit/token exchange, after the invite tag did its one job.
    //   - invite: the tag actually embedded in the shareable invite
    //     code/QR. Deliberately disposable — pruned after first use
    //     (removeMailboxTagIfEphemeral in WebSocketClient.kt) or
    //     explicitly rotated on "Copy"/"Share" (regenerateMyInviteMailboxTag),
    //     so a leaked/observed code stops working the moment it's used
    //     once, or whenever the user asks for a fresh one.
    private const val PREF_MY_PERSISTENT_TAG = "mbox_my_persistent_tag"

    /** A mailbox tag generated once per install and reused indefinitely —
     *  independent of any invite code's TTL. Exchanged with a contact
     *  alongside normal token reciprocation (see WebSocketClient.sendAnonTokensTo)
     *  so that contact's copy of getContactMailboxTag(me) gets refreshed to
     *  this tag instead of going stale. */
    fun getOrCreateMyPersistentMailboxTag(): String = synchronized(lock) {
        val existing = DesktopStorage.get(PREF_MY_PERSISTENT_TAG)
        if (existing != null) return@synchronized existing
        val tag = generateToken()
        DesktopStorage.put(PREF_MY_PERSISTENT_TAG, tag)
        addMyMailboxTag(tag)
        tag
    }

    /** Forces PREF_MY_PERSISTENT_TAG to match [tag]. Superseded by
     *  syncMyInviteMailboxTag() for invite codes specifically — kept for any
     *  other caller still relying on the persistent tag itself being
     *  force-synced to a known value. */
    fun syncMyPersistentMailboxTag(tag: String) = synchronized(lock) {
        DesktopStorage.put(PREF_MY_PERSISTENT_TAG, tag)
        addMyMailboxTag(tag)
    }

    private const val PREF_MY_INVITE_TAG = "mbox_my_invite_tag"

    /** The tag embedded in invite codes — deliberately NOT the same value as
     *  getOrCreateMyPersistentMailboxTag(). Anyone who merely sees an invite
     *  code (without ever becoming a real contact) learns only this
     *  throwaway tag, not the one actually used for ongoing communication. */
    fun getOrCreateMyInviteMailboxTag(): String = synchronized(lock) {
        val existing = DesktopStorage.get(PREF_MY_INVITE_TAG)
        if (existing != null) return@synchronized existing
        regenerateMyInviteMailboxTag()
    }

    /** Mints a fresh invite tag and immediately stops polling the old one —
     *  closing the exposure window is the whole point of regenerating (see
     *  the invite dialogs' "Copy"/"Share" actions), so an old value left
     *  lingering in getMyMailboxTags() would defeat that. */
    fun regenerateMyInviteMailboxTag(): String = synchronized(lock) {
        val old = DesktopStorage.get(PREF_MY_INVITE_TAG)
        val tag = generateToken()
        DesktopStorage.put(PREF_MY_INVITE_TAG, tag)
        if (old != null) removeMyMailboxTag(old)
        addMyMailboxTag(tag)
        tag
    }

    /** Forces PREF_MY_INVITE_TAG to match [tag] — the tag actually embedded
     *  in the currently active/displayed invite code. Call this every time
     *  the active invite code is resolved (cached or fresh), so a device
     *  with a code cached from before this pref existed still seeds it
     *  correctly instead of minting a value that doesn't match what's
     *  actually embedded in the displayed code. */
    fun syncMyInviteMailboxTag(tag: String) = synchronized(lock) {
        DesktopStorage.put(PREF_MY_INVITE_TAG, tag)
        addMyMailboxTag(tag)
    }

    fun setContactMailboxTag(fingerprint: String, tag: String) {
        DesktopStorage.put("$PREF_CT_MBOX_PREFIX$fingerprint", tag)
    }

    fun getContactMailboxTag(fingerprint: String): String? =
        DesktopStorage.get("$PREF_CT_MBOX_PREFIX$fingerprint")

    fun clearContactMailboxTag(fingerprint: String) {
        DesktopStorage.remove("$PREF_CT_MBOX_PREFIX$fingerprint")
    }

    /** Wipes all token/tag state for every contact — used when replacing
     * this device's active identity with a different one from a backup,
     * see BackupManager.wipeCurrentIdentityData(). Mirrors Android's
     * AnonTokenManager.clearAll(). */
    fun clearAll() = synchronized(lock) {
        // PREF_MY_TOKENS_ACK_PENDING was missing from this explicit-keys
        // list — an identity wipe left orphaned ACK_PENDING tokens behind,
        // referencing an identity that no longer exists. PREF_CT_SPENT_
        // PREFIX/PREF_CT_GIVEN_PREFIX need no separate entry: both already
        // start with PREF_CT_PREFIX ("anon_ct_"), so the existing prefix
        // filter below already catches them. Found live, 2026-09-13.
        val prefixes = listOf(PREF_CT_PREFIX, PREF_CT_MBOX_PREFIX)
        DesktopStorage.getAllKeys()
            .filter {
                it == PREF_MY_TOKENS || it == PREF_MY_TOKENS_ACK_PENDING ||
                it == PREF_MY_MBOX_TAGS ||
                it == PREF_MY_PERSISTENT_TAG || it == PREF_MY_INVITE_TAG ||
                prefixes.any { p -> it.startsWith(p) }
            }
            .forEach { DesktopStorage.remove(it) }
    }

    fun buildFetchTagList(): List<String> {
        val real = getMyMailboxTags()
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
