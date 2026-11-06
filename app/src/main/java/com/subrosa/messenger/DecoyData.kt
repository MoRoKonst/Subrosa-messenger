package com.subrosa.messenger

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale
import kotlin.random.Random

/**
 * The dataset behind duress mode ("decoy"): a plausible working inbox for a
 * commercial law firm, derived entirely from a per-install 32-byte seed
 * (UserStorage.getOrCreateDecoySeed).
 *
 * Why generated rather than written out as literals, which is what
 * DecoyScreen used to do:
 *
 *  - The old `chatPool` was a compile-time constant. Every install of a given
 *    APK showed the same "Sarah"/"Mike" threads about pasta sauce and CS2, so
 *    anyone who had seen one device — or simply decompiled the APK, which is
 *    source-available anyway — recognised the decoy on sight. Seeding per
 *    install means two phones never show the same names, companies, matter
 *    numbers or history, and there is no reference copy to compare against.
 *  - Nothing generated here is ever written to disk. Only the seed is stored,
 *    so an offline image of app storage contains no fake conversations at all,
 *    where a persisted decoy store would have been a readable artefact sitting
 *    next to the (password-wrapped) real one.
 *
 * Residual leak, stated plainly rather than glossed over: the seed is
 * keystore-backed, not password-backed. An attacker with live root on an
 * unlocked device can read it and, because this generator is source-available,
 * replay it to demonstrate that the dataset is synthetic. This defeats someone
 * holding the phone and scrolling it, and it defeats offline inspection of the
 * storage image. It does not defeat full forensics on a live, unlocked device,
 * and nothing short of a duress-password design (two independent SMKs, each
 * decrypting a different real dataset) would.
 *
 * Determinism contract: everything except message timestamps derives from the
 * seed alone, so content is stable across launches and app updates. Timestamps
 * derive from seed + UserStorage.getDecoyAnchor(), which only advances on a
 * normal (non-duress) launch — see that function for why the timeline has to
 * freeze while the decoy is on screen.
 */
object DecoyData {

    data class DecoyMsg(
        val id: String,
        val text: String,
        val isOwn: Boolean,
        val timestamp: Long,
        val isRead: Boolean,
        val isDelivered: Boolean,
        val replyToId: String? = null,
        val reactions: Map<String, String> = emptyMap(),
        val fileName: String? = null,
        val filePath: String? = null
    )

    data class DecoyThread(
        val id: String,
        val name: String,
        val messages: List<DecoyMsg>
    ) {
        val lastTimestamp: Long get() = messages.lastOrNull()?.timestamp ?: 0L
        val lastMessage: String get() = messages.lastOrNull()?.text ?: ""
        val unreadCount: Int get() = messages.count { !it.isOwn && !it.isRead }
    }

    // ── Public API ──────────────────────────────────────────────────────────

    fun threads(context: Context): List<DecoyThread> = cached(context).threads

    /** Records a message typed into the decoy by whoever is holding the phone.
     *  Kept in memory *and* persisted: the in-memory copy is what the UI reads
     *  (see sessionState below — storage can vanish underneath us mid-session),
     *  the persisted copy is so a send survives process death, which a
     *  `mutableStateListOf` did not. */
    fun appendSent(context: Context, threadId: String, text: String) {
        val entry = Sent(text, System.currentTimeMillis())
        session(context).sent.getOrPut(threadId) { mutableListOf() }.add(entry)
        try {
            val root = try { JSONObject(UserStorage.getDecoySentJson(context)) } catch (_: Exception) { JSONObject() }
            val arr = root.optJSONArray(threadId) ?: JSONArray().also { root.put(threadId, it) }
            arr.put(JSONObject().apply {
                put("t", entry.text)
                put("ts", entry.ts)
            })
            UserStorage.setDecoySentJson(context, root.toString())
        } catch (_: Exception) {}
        invalidate()
    }

    fun deleteThread(context: Context, threadId: String) {
        session(context).hidden.add(threadId)
        try { UserStorage.addDecoyDeleted(context, threadId) } catch (_: Exception) {}
        invalidate()
    }

    /** Filename the canary blob presents itself under, and the content it
     *  actually holds — both seed-derived and therefore stable for the life of
     *  the install, which matters because the blob is written exactly once
     *  (HoneyTokenManager.init) while the surrounding timeline keeps moving. */
    fun honeyDocFileName(context: Context): String = cached(context).honeyDocName

    fun honeyDocBytes(context: Context): ByteArray = cached(context).honeyDocBytes

    /** Timestamp of the decoy message carrying the canary. The blob's mtime is
     *  realigned to this on every normal launch so that "received at" in the
     *  fake chat and the file's own mtime never contradict each other. */
    fun honeyAttachmentTimestamp(context: Context): Long = cached(context).honeyTimestamp

    fun invalidate() {
        mutationVersion++
        cache = null
    }

    // ── Cache ───────────────────────────────────────────────────────────────

    internal class Generated(
        val threads: List<DecoyThread>,
        val honeyDocName: String,
        val honeyDocBytes: ByteArray,
        val honeyTimestamp: Long
    )

    internal class Sent(val text: String, val ts: Long)

    /**
     * Everything the dataset is derived from, snapshotted into process memory
     * on first use and never re-read from storage afterwards.
     *
     * This is load-bearing, not an optimisation. The panic-password path shows
     * the decoy *first* and then wipes real data underneath it 400ms later
     * (MainActivity.onPanicMode -> WipeManager.wipeForDecoyKeepAlive), and that
     * wipe deletes the whole `shared_prefs` directory — including `user_prefs`,
     * where the seed, the timeline anchor and the canary's blob id live.
     *
     * Re-reading them after the wipe hands back a freshly minted seed, so the
     * next recomposition regenerates the entire inbox: whoever is holding the
     * phone taps a conversation and every contact name, company and message in
     * the list changes in front of them. That is a far louder tell than any of
     * the cosmetic ones this module was written to remove. Pinning the session
     * makes the decoy survive its own wipe.
     */
    internal class Session(
        val seed: ByteArray,
        val anchor: Long,
        val honeyFileName: String,
        val sent: MutableMap<String, MutableList<Sent>>,
        val hidden: MutableSet<String>
    )

    @Volatile private var sessionState: Session? = null
    @Volatile private var cache: Generated? = null
    @Volatile private var cacheVersion: Int = -1
    @Volatile private var mutationVersion: Int = 0

    private fun session(context: Context): Session {
        sessionState?.let { return it }
        return synchronized(this) {
            sessionState ?: run {
                val sent = HashMap<String, MutableList<Sent>>()
                try {
                    val root = JSONObject(UserStorage.getDecoySentJson(context))
                    for (threadId in root.keys()) {
                        val arr = root.optJSONArray(threadId) ?: continue
                        val list = mutableListOf<Sent>()
                        for (i in 0 until arr.length()) {
                            val o = arr.optJSONObject(i) ?: continue
                            list.add(Sent(o.optString("t"), o.optLong("ts")))
                        }
                        sent[threadId] = list
                    }
                } catch (_: Exception) {}
                Session(
                    seed = UserStorage.getOrCreateDecoySeed(context),
                    anchor = UserStorage.getDecoyAnchor(context),
                    honeyFileName = UserStorage.getHoneyFileName(context),
                    sent = sent,
                    hidden = UserStorage.getDecoyDeleted(context).toMutableSet()
                ).also { sessionState = it }
            }
        }
    }

    /** Drops the pinned session so the next access re-reads storage. Called by
     *  HoneyTokenManager once it has minted the canary's blob id, which happens
     *  after a decoy may already have been rendered without an attachment. */
    fun resetSession() {
        sessionState = null
        cache = null
        cacheVersion = -1
    }

    private fun cached(context: Context): Generated {
        val s = session(context)
        val version = mutationVersion
        cache?.let { if (cacheVersion == version) return it }
        val built = generate(context, s)
        cache = built
        cacheVersion = version
        return built
    }

    // ── Deterministic randomness ────────────────────────────────────────────

    /** Independent RNG stream per label, so adding a thread or changing one
     *  scenario cannot shift the content of any other — without this, the
     *  whole dataset reshuffles on every edit to this file and a user's decoy
     *  history silently rewrites itself on app update. */
    private fun subRandom(seed: ByteArray, label: String): Random {
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(seed)
            update(label.toByteArray(Charsets.UTF_8))
        }.digest()
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (digest[i].toLong() and 0xFF)
        return Random(v)
    }

    private fun <T> Random.pick(list: List<T>): T = list[nextInt(list.size)]

    // ── Vocabulary ──────────────────────────────────────────────────────────
    //
    // Deliberately consistent with one jurisdiction (England & Wales
    // commercial practice): disclosure not discovery, claim form and
    // particulars not complaint, Part 36 not Rule 68, solicitor/counsel split,
    // Companies House. A mixed-jurisdiction vocabulary is the sort of thing a
    // lawyer reading over someone's shoulder would notice immediately.

    private val firstNames = listOf(
        "James", "Margaret", "David", "Catherine", "Robert", "Helen", "Andrew",
        "Priya", "Michael", "Elizabeth", "Thomas", "Claire", "Jonathan",
        "Rebecca", "Stephen", "Alison", "Richard", "Victoria", "Daniel",
        "Louise", "Peter", "Fiona", "Charles", "Natalie", "Simon", "Amanda",
        "Mark", "Gillian", "Nicholas", "Rachel", "Oliver", "Harriet",
        "Adeola", "Martin", "Siobhan", "Hugh", "Yusuf", "Eleanor", "Patrick",
        "Anneke"
    )

    private val lastNames = listOf(
        "Whitfield", "Harrington", "Crowley", "Maddox", "Fairbanks",
        "Lockhart", "Ashworth", "Pennington", "Rutherford", "Caldwell",
        "Hargreaves", "Thornbury", "Beaumont", "Kingsley", "Donnelly",
        "Ferreira", "Okonkwo", "Novak", "Keller", "Lindqvist", "Albright",
        "Sandoval", "Bramwell", "Haverfield", "Mortimer", "Easterbrook",
        "Ravensworth", "Chaudhry", "Gillingham", "Strachan"
    )

    private val clients = listOf(
        "Arden Holdings", "Northgate Logistics", "Kesler Pharma",
        "Veritas Mining", "Brightwater Capital", "Orrin Industrial",
        "Halbrook Energy", "Meridian Freight", "Stanfield Retail Group",
        "Lysander Technologies", "Ridgeway Construction", "Thorne Maritime",
        "Avanti Foods", "Pellworth Insurance", "Calder Aggregates",
        "Wrenfield Estates"
    )

    private val opposingFirms = listOf(
        "Hale & Mornay", "Bricknell LLP", "Draycott Finch", "Salter Rowe",
        "Ibbotson & Vance", "Krauss Lehmann", "Ferrers Walsh", "Tamworth Legal"
    )

    private val courts = listOf(
        "the Commercial Court", "the Chancery Division",
        "the County Court at Central London", "the Employment Tribunal",
        "the TCC"
    )

    private val agreements = listOf(
        "the SPA", "the share purchase agreement", "the SHA",
        "the services agreement", "the settlement agreement",
        "the facility agreement", "the asset purchase agreement",
        "the licence"
    )

    /** Deliberately topic-free, so one can follow any scenario without the
     *  incoherence the `answersPrevious` linking exists to remove. Used only to
     *  give an otherwise-outgoing thread something to leave unread. */
    private val followUps = listOf(
        "Any update on this?",
        "Sorry to chase — where did we get to?",
        "Did that go out in the end?",
        "Have you had a chance to look at this?",
        "Just checking you got my last message.",
        "Can we pick this up first thing tomorrow?",
        "Could you send me the file reference when you get a moment?"
    )

    private val docKinds = listOf(
        "Advice note", "Letter of advice", "Memorandum", "Instructions to counsel",
        "Draft witness statement", "Heads of terms", "Disclosure review note",
        "Completion checklist"
    )

    // ── Scenario grammar ────────────────────────────────────────────────────

    private enum class Party { COLLEAGUE, PARALEGAL, CLIENT, OPPOSING, COUNSEL, ACCOUNTS }

    /**
     * One turn in a conversation.
     *
     * `variants` are interchangeable phrasings. `optional` beats are dropped
     * about a third of the time to vary thread length and rhythm.
     *
     * `answersPrevious` is the important one. Variants are written *positionally
     * aligned*: variant N of a reply is the reply to variant N of the question
     * above it. The first version of this generator picked every beat's variant
     * independently, which produced a steady stream of answers to questions
     * nobody asked — "Who's chasing the client?" / "The loss of profit
     * calculation. Their finance team owes me the management accounts.", or a
     * thread ending "13:45 works." when no time had been proposed. Roughly one
     * exchange in three was incoherent, which is precisely what a careful
     * reader notices even when every individual line is idiomatic. Marking a
     * beat as answering the previous one forces it to reuse that beat's chosen
     * index.
     *
     * Consequence accepted deliberately: linking cuts the number of distinct
     * combinations, so two installs that draw the same scenario now share more
     * exact message text. That is a trade of cross-install uniqueness (visible
     * only to someone holding a corpus of decoys) for internal coherence
     * (visible to anyone reading the phone). The second matters far more under
     * this threat model.
     *
     * Invariant: a beat marked `optional` must never be immediately followed by
     * one marked `answersPrevious` — dropping the question would orphan its
     * answer. Enforced by construction in the scenario list below.
     */
    private class Beat(
        val own: Boolean,
        val variants: List<String>,
        val optional: Boolean = false,
        val answersPrevious: Boolean = false
    )

    private class Scenario(val party: Party, val beats: List<Beat>)

    private fun scenarios(): List<Scenario> = listOf(

        // Draft turnaround on a transaction document.
        Scenario(Party.COLLEAGUE, listOf(
            Beat(false, listOf(
                "Have you had a chance to look at {agreement} on {matter}?",
                "Any progress on {agreement} for {client}?",
                "Where are we on the {agreement} draft for {matter}?"
            )),
            Beat(true, listOf(
                "Working through it now. Clause 9 is the problem.",
                "Halfway. The indemnity cap doesn't match the heads of terms.",
                "Nearly there — a few points on the warranties to resolve."
            )),
            Beat(false, listOf(
                "What's wrong with it?",
                "In what way?",
                "Go on."
            ), optional = true),
            Beat(true, listOf(
                "They've drafted the cap at {amount} but we agreed it was per claim, not aggregate.",
                "As drafted the seller gets a {days}-day cure period on every breach. Not what was agreed.",
                "The definition of Material Contracts picks up everything over {amount}, which is far too low."
            )),
            Beat(false, listOf(
                "Push back on that. Mark it up and I'll take it to the client.",
                "Agreed, that needs to change. Can you turn comments by tomorrow?",
                "Flag it in the issues list and we'll raise it on the call."
            )),
            Beat(true, listOf(
                "Will do. I'll have a marked-up version across by {time}.",
                "Fine. Comments with you before {time}.",
                "Yes — I'll circulate a revised draft this afternoon."
            )),
            Beat(false, listOf(
                "Thanks.",
                "Perfect, thank you.",
                "Great, thanks."
            ), optional = true)
        )),

        // Court deadline / limitation.
        Scenario(Party.COLLEAGUE, listOf(
            Beat(false, listOf(
                "The deadline for particulars on {matter} is {date}. Are we on track?",
                "Reminder: particulars of claim on {matter} due {date}.",
                "We're up against it on {matter} — {date} for the particulars."
            )),
            Beat(true, listOf(
                "Drafted. I want counsel to see it before we serve.",
                "Yes. Draft is done, I'm waiting on the client's comments.",
                "On track. One quantum figure still to confirm."
            )),
            // Not optional: its answer below is index-linked to it, so dropping
            // the question would orphan the reply (see Beat).
            Beat(false, listOf(
                "Which figure?",
                "Who's chasing the client?",
                "Have we got counsel's availability?"
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "The loss of profit calculation. Their finance team owes me the management accounts.",
                "I've chased twice. I'll call rather than email.",
                "{person} is checking. Should be back today."
            )),
            Beat(false, listOf(
                "Don't let it slip. We cannot ask {court} for an extension twice.",
                "Keep an eye on limitation — it expires six weeks after that.",
                "If it's going to be tight, tell me now rather than on {date}."
            )),
            Beat(true, listOf(
                "Understood. It will be filed in good time.",
                "Noted. I'll confirm once it's issued.",
                "It won't slip."
            ))
        )),

        // Disclosure / document review.
        Scenario(Party.PARALEGAL, listOf(
            Beat(false, listOf(
                "First pass on the {client} disclosure is done — {count} documents after de-duplication.",
                "I've finished the initial review on {matter}. {count} documents in scope.",
                "Review set for {matter} is loaded. {count} documents."
            )),
            Beat(true, listOf(
                "How many are flagged privileged?",
                "Anything problematic in there?",
                "What's the hit rate on the keywords?"
            )),
            Beat(false, answersPrevious = true, variants = listOf(
                "About {pct}% privileged. I've started the privilege log.",
                "{pct}% privileged, and a handful I'd like a second opinion on.",
                "Roughly {pct}%. Two chains involving in-house counsel need a decision."
            )),
            Beat(true, listOf(
                "Put the doubtful ones in a separate folder and I'll go through them with you.",
                "Leave those for me. Don't release anything you're unsure about.",
                "Flag them and we'll review together before the list goes out."
            )),
            Beat(false, listOf(
                "Done. Also found a chain from {pastdate} that contradicts their timeline.",
                "Will do. There's one email thread you should see — it helps us on causation.",
                "Separated out. One document is going to be awkward for them."
            )),
            Beat(true, listOf(
                "Send it over.",
                "Good find. Let me see it.",
                "That could matter. Pull it out for me."
            ), optional = true)
        )),

        // Hearing logistics with counsel.
        Scenario(Party.COUNSEL, listOf(
            Beat(false, listOf(
                "Listed for {date} in {court}. Can you get me the bundle by the Friday before?",
                "I have the hearing on {date}. When can I expect the bundle?",
                "{date} is confirmed in {court}. Bundle timing?"
            )),
            Beat(true, listOf(
                "Bundle is being paginated now. You'll have it well before.",
                "Yes — index agreed with the other side, pagination tomorrow.",
                "It's with the print room. Electronic copy across today."
            )),
            Beat(false, listOf(
                "Is the skeleton still due two days before?",
                "Any authorities you want included?",
                "Has the other side served their evidence?"
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "Yes, and {opposing} have asked to exchange simultaneously.",
                "I'll send a short list — the three on implied terms are the important ones.",
                "Served yesterday. Nothing we hadn't anticipated."
            )),
            Beat(false, listOf(
                "Fine. I'd like a short call with the client beforehand.",
                "Good. Let's have a conference the day before.",
                "Understood. Keep me posted if anything changes."
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "I'll set it up for {time} on the Wednesday.",
                "I'll arrange it and confirm the time.",
                "Will do."
            ))
        )),

        // Client onboarding.
        Scenario(Party.COLLEAGUE, listOf(
            Beat(false, listOf(
                "New enquiry from {client}. Can you run the conflict check?",
                "{client} have been in touch about a dispute. Conflict check please.",
                "Potential instruction from {client} — can you clear conflicts?"
            )),
            Beat(true, listOf(
                "Running it now.",
                "On it. I'll also need their ID for AML.",
                "Started. Nothing obvious so far."
            )),
            Beat(false, listOf(
                "Good. If it's clear, draft the engagement letter.",
                "Thanks. Scope should be limited to the contractual claim for now.",
                "Once clear, send the engagement letter and our standard terms."
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "Clear. Engagement letter drafted — cost estimate at {amount} for the first stage.",
                "No conflict. I've put the estimate at {amount} up to exchange of pleadings.",
                "All clear. Letter ready for your signature."
            )),
            // Linked too: variants 0 and 1 refer to "the estimate", which only
            // exists in the correspondingly-indexed reply above. Free choice
            // here produced "Add a line that the estimate excludes counsel and
            // court fees" after a reply that never mentioned an estimate.
            Beat(false, answersPrevious = true, variants = listOf(
                "Make the estimate stage-limited and say so expressly.",
                "Add a line that the estimate excludes counsel and court fees.",
                "Looks right. I'll sign it this afternoon."
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "Amended and ready to go out.",
                "Added. Sending once you've signed.",
                "Thanks — I'll send it today."
            ))
        )),

        // Billing / WIP.
        Scenario(Party.ACCOUNTS, listOf(
            Beat(false, listOf(
                "WIP on {matter} is at {amount}. Can we bill this month?",
                "{matter} has unbilled time of {amount}. Shall I raise an invoice?",
                "Month end on Friday — {matter} is carrying {amount} of WIP."
            )),
            Beat(true, listOf(
                "Yes, bill to the end of last month.",
                "Hold until the hearing is out of the way.",
                "Bill it, but write off the duplicated review time."
            )),
            Beat(false, listOf(
                "Any disbursements to add?",
                "Do you want counsel's fee note on the same invoice?",
                "Narrative as usual?"
            )),
            // Reordered to line up with the question above it: these were
            // crossed by one, so "Do you want counsel's fee note on the same
            // invoice?" was answered with "Separate the disbursements out".
            Beat(true, answersPrevious = true, variants = listOf(
                "Separate the disbursements out — the client prefers it that way.",
                "Counsel's fee note and the court fee, yes.",
                "Keep the narrative detailed. They query everything."
            )),
            Beat(false, listOf(
                "Understood. Draft invoice with you shortly.",
                "Noted. I'll put it in the run for Friday.",
                "Fine, I'll prepare it for your approval."
            ))
        )),

        // Settlement posture.
        Scenario(Party.COLLEAGUE, listOf(
            Beat(false, listOf(
                "{opposing} have made a Part 36 offer on {matter}. {amount}.",
                "Offer in on {matter} — {amount}, Part 36.",
                "{opposing} have gone in at {amount}. Part 36, {days} days to accept."
            )),
            Beat(true, listOf(
                "That's well short. What's our best case on quantum?",
                "Below our worst case. Have you told the client?",
                "Too low, but it tells us they're worried about costs."
            )),
            Beat(false, answersPrevious = true, variants = listOf(
                "Best case is roughly double that. Costs risk is the issue.",
                "Not yet. I wanted your view first.",
                "Agreed. Their costs budget was approved at {amount} so they're exposed."
            )),
            Beat(true, listOf(
                "We should advise rejection but put in a counter-offer.",
                "Let's take instructions properly — in writing, with the costs consequences spelled out.",
                "Advise them to reject and we'll come back at a realistic figure."
            )),
            Beat(false, listOf(
                "I'll draft the advice. Without prejudice save as to costs?",
                "Agreed. I'll put it in a letter today.",
                "Fine. Call with the client at {time} tomorrow?"
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "Yes, and make the costs consequences explicit.",
                "Please — and keep it off email until it's been read.",
                "{time} works."
            ))
        )),

        // Due diligence.
        Scenario(Party.COLLEAGUE, listOf(
            Beat(false, listOf(
                "DD report on {client} is nearly done. Two red flags.",
                "Due diligence on the {client} acquisition — I've found two issues.",
                "Data room review for {matter} complete. Two things to raise."
            )),
            Beat(true, listOf(
                "What are they?",
                "Go on.",
                "Serious?"
            )),
            Beat(false, listOf(
                "Change of control in the main customer contract, and the lease has {days} days to run.",
                "An unregistered charge, and no written assignment of the IP.",
                "The pension scheme has a deficit, and three employees have no written contracts."
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "The change of control needs a consent or a price adjustment. Flag it as a deal issue.",
                "Both go in the report as red. The IP point may need a warranty and an indemnity.",
                "That's a retention, not a warranty. Put it to the client that way."
            )),
            Beat(false, listOf(
                "Will do. I've drafted the warranty wording already.",
                "Agreed. I'll put the disclosure requests to {opposing}.",
                "Understood. Report across by {time}."
            )),
            Beat(true, listOf(
                "Good. Keep the executive summary to one page.",
                "Thanks. Send me the draft before it goes to the client.",
                "Noted."
            ), optional = true)
        )),

        // Client-facing update.
        Scenario(Party.CLIENT, listOf(
            Beat(false, listOf(
                "Morning — any news on our matter?",
                "Hello, could you update me on where things stand?",
                "Any movement since last week?"
            )),
            Beat(true, listOf(
                "Good morning. We served last week and their response is due {date}.",
                "Yes — we've had the first round of documents and I'm reviewing them now.",
                "We're waiting on {opposing}. They have until {date} to respond."
            )),
            Beat(false, listOf(
                "And if they don't respond?",
                "What happens then?",
                "How long is this likely to take overall?"
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "We can apply for judgment in default. I'd rather not — it's usually set aside.",
                "We'd move to the next stage. I'll write to you with the options and the costs of each.",
                "Realistically {weeks} weeks to the next hearing, assuming no further delay."
            )),
            Beat(false, listOf(
                "Understood. Keep the costs in mind — we're not open-ended on this.",
                "Thank you. Please keep me posted.",
                "That's helpful, thank you. Could you put it in writing?"
            )),
            Beat(true, listOf(
                "Of course. I'll confirm in writing today.",
                "Noted — I'll send a short update letter this afternoon.",
                "Understood. We're within the estimate at present."
            ), optional = true)
        )),

        // Opposing side correspondence.
        Scenario(Party.OPPOSING, listOf(
            Beat(false, listOf(
                "We'd be grateful for a {days}-day extension to serve our defence.",
                "Our client is abroad until the end of the month. Can you agree an extension?",
                "Would you consent to an extension of {days} days for the defence?"
            )),
            Beat(true, listOf(
                "We can agree {days} days, on the basis that it's the only extension.",
                "I'll need to take instructions. In principle we won't be unreasonable.",
                "Agreed, provided a consent order is filed and costs are reserved."
            )),
            Beat(false, listOf(
                "That's acceptable. We'll draft the consent order.",
                "Thank you. I'll send a draft order across today.",
                "Understood. Shall we deal with it by consent?"
            )),
            Beat(true, listOf(
                "Please send it over and I'll check the wording.",
                "Yes. Send the draft and I'll revert by {time}.",
                "Fine. Do include a provision on costs."
            )),
            Beat(false, listOf(
                "Will do. Separately — is your client open to a without prejudice discussion?",
                "Noted. We may come back to you on settlement in due course.",
                "Thank you for being sensible about it."
            ), optional = true)
        )),

        // Witness statement.
        Scenario(Party.COLLEAGUE, listOf(
            Beat(false, listOf(
                "I've drafted {person}'s witness statement. It needs tightening.",
                "First draft of the witness statement for {matter} is ready.",
                "Witness statement drafted. It's rather long."
            )),
            Beat(true, listOf(
                "How long?",
                "Does it stick to the facts?",
                "Has the witness seen it?"
            )),
            Beat(false, answersPrevious = true, variants = listOf(
                "{count} paragraphs. There's a lot of argument in it that shouldn't be.",
                "Mostly, but there's comment on the law in the middle section.",
                "Not yet — I wanted it right first."
            )),
            Beat(true, listOf(
                "Strip out anything that reads as submission. It's evidence, not a skeleton.",
                "Cut the legal commentary. Counsel can deal with that.",
                "Good. Take them through it in person, not by email."
            )),
            Beat(false, listOf(
                "Agreed. I'll also check the exhibits are properly referenced.",
                "Will do. Exhibit numbering needs sorting too.",
                "Understood. I'll arrange a meeting to go through it."
            )),
            Beat(true, listOf(
                "And make sure the statement of truth is in the current form.",
                "Thanks. Send me the revised version when it's done.",
                "Good."
            ), optional = true)
        )),

        // Employment advice to a client.
        Scenario(Party.CLIENT, listOf(
            Beat(false, listOf(
                "We need to let someone go. {months} months' service. How exposed are we?",
                "Can we dismiss an employee with under two years' service?",
                "We have a performance issue and want to move quickly. What's the risk?"
            )),
            Beat(true, listOf(
                "Under two years the unfair dismissal risk is limited, but discrimination has no qualifying period.",
                "Short service helps, but you still need to be careful about the reason.",
                "The exposure depends on the reason rather than the length of service."
            )),
            Beat(false, listOf(
                "The reason is genuinely performance.",
                "There's no protected characteristic involved as far as I know.",
                "What would you recommend?"
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "Then a settlement agreement is usually cleanest. Expect to pay around {amount}.",
                "Document the performance concerns first, even if briefly.",
                "A short process and a settlement agreement. I can draft it."
            )),
            Beat(false, listOf(
                "Please draft it. How long does it take?",
                "That's within what we expected. Go ahead.",
                "Understood. Can we have it by {date}?"
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "I can have a draft with you by {date}. They'll need independent advice on it.",
                "Yes. Note they must take independent legal advice for it to bind.",
                "By {date}, yes."
            ))
        )),

        // Corporate housekeeping.
        Scenario(Party.PARALEGAL, listOf(
            Beat(false, listOf(
                "Companies House filing for {client} is due {date}. I have the confirmation statement ready.",
                "The share allotment for {client} needs filing within {days} days.",
                "Board minutes for {client} are drafted — can you review?"
            )),
            Beat(true, listOf(
                "File it. Check the PSC register is up to date first.",
                "Yes. Make sure the SH01 reflects the correct nominal value.",
                "Send them over. Check the quorum provisions in the articles."
            )),
            Beat(false, answersPrevious = true, variants = listOf(
                "Already checked — one director resigned in {month} and wasn't filed.",
                "The nominal value is right but we're missing a signed written resolution.",
                "The articles require two directors. Only one signed."
            )),
            Beat(true, answersPrevious = true, variants = listOf(
                "Then file the TM01 as well, and note the late filing.",
                "Get it signed before we file anything.",
                "Get the second signature. Don't file until it's complete."
            )),
            Beat(false, listOf(
                "Understood. I'll chase and come back to you.",
                "Will do.",
                "Noted — I'll have it sorted today."
            ))
        )),

        // Office admin — short, different register, keeps the inbox from
        // reading like it was written entirely by one person on one topic.
        Scenario(Party.COLLEAGUE, listOf(
            Beat(false, listOf(
                "Are you in the office on {date}? I need cover for the {client} call.",
                "Who's covering reception on {date}? I'm at {court}.",
                "Can you take the {client} call at {time}? I'm double booked."
            )),
            Beat(true, listOf(
                "Yes, I can do that.",
                "I'm in, yes. Send me the papers beforehand.",
                "Can do, as long as it's not longer than half an hour."
            )),
            Beat(false, listOf(
                "Thank you. I'll forward the file note.",
                "Appreciated. Papers across shortly.",
                "Thanks, that's a help."
            )),
            Beat(true, listOf(
                "No problem.",
                "Fine.",
                "Any time."
            ), optional = true)
        ))
    )

    // ── Slot binding ────────────────────────────────────────────────────────

    /** Everything a thread's text can refer to, bound once per thread so that
     *  the matter number, client, counterparty and figures stay consistent
     *  from the first message to the last. Incoherent slots across a thread
     *  ("the SPA" in one line, an employment tribunal in the next) is what
     *  makes generated dialogue read as generated. */
    private class Slots(
        val contactName: String,
        val party: Party,
        val client: String,
        val matter: String,
        val opposing: String,
        val court: String,
        val agreement: String,
        val amount: String,
        val person: String,
        val count: Int,
        val pct: Int,
        val days: Int,
        // Separate slots because `days` (7–35) was being substituted into
        // templates whose unit was not days. "Realistically {days} weeks to the
        // next hearing" rendered as 35 weeks, and "{days} months' service"
        // rendered as 35 months — which flatly contradicted the reply it was
        // linked to ("Under two years the unfair dismissal risk is limited").
        val weeks: Int,
        val serviceMonths: Int,
        val docName: String,
        // Dates and times are bound per thread, not per message. They used to
        // be generated inside fill() on each substitution, which meant a
        // proposed time and its acceptance were different times — threads ended
        // "Call with the client at 14:30 tomorrow?" / "13:45 works." — and a
        // deadline quoted twice in one thread was two different deadlines.
        val deadline: String,
        val pastDate: String,
        val meetTime: String,
        val month: String
    )

    private fun bindSlots(rnd: Random, scenario: Scenario, referenceMs: Long): Slots {
        val client = rnd.pick(clients)
        val initials = client.split(" ").filter { it.isNotBlank() }
            .joinToString("") { it.first().uppercase() }
            .take(3)
            .padEnd(3, 'X')
        val contactFirst = rnd.pick(firstNames)
        val contactLast = rnd.pick(lastNames)
        val contactName = when (scenario.party) {
            // Clients and the other side are stored under a name that says
            // who they are, the way a solicitor's phone actually looks.
            Party.CLIENT -> "$contactFirst $contactLast ($client)"
            Party.OPPOSING -> "$contactFirst $contactLast - ${rnd.pick(opposingFirms)}"
            Party.COUNSEL -> "$contactFirst $contactLast (Counsel)"
            Party.ACCOUNTS -> "$contactFirst - Accounts"
            else -> "$contactFirst $contactLast"
        }
        return Slots(
            contactName = contactName,
            party = scenario.party,
            client = client,
            matter = "$initials-${1000 + rnd.nextInt(8999)}",
            opposing = rnd.pick(opposingFirms),
            court = rnd.pick(courts),
            agreement = rnd.pick(agreements),
            amount = formatAmount(rnd),
            person = "${rnd.pick(firstNames)} ${rnd.pick(lastNames)}",
            count = listOf(60, 120, 240, 480, 900, 1400, 2600, 4100)[rnd.nextInt(8)] + rnd.nextInt(90),
            pct = 4 + rnd.nextInt(16),
            days = listOf(7, 14, 14, 21, 28, 28, 35)[rnd.nextInt(7)],
            weeks = 6 + rnd.nextInt(17),
            // Under two years, so the "short service helps" advice it is linked
            // to stays true.
            serviceMonths = 4 + rnd.nextInt(19),
            docName = "${rnd.pick(docKinds)} - $initials-${1000 + rnd.nextInt(8999)}.pdf",
            // A deadline sits ahead of the conversation discussing it; a
            // referenced document sits behind it. The first version used one
            // forward-dated slot for both, which produced lines like "found a
            // chain from 21 November" in a message timestamped 28 October —
            // a document from three weeks in the future.
            deadline = offsetDate(referenceMs, 4 + rnd.nextInt(22)),
            pastDate = offsetDate(referenceMs, -(5 + rnd.nextInt(90))),
            meetTime = String.format(
                Locale.UK, "%d:%02d",
                9 + rnd.nextInt(9),
                listOf(0, 15, 30, 45)[rnd.nextInt(4)]
            ),
            month = SimpleDateFormat("MMMM", Locale.UK).format(
                Calendar.getInstance().apply {
                    timeInMillis = referenceMs
                    add(Calendar.MONTH, -(1 + rnd.nextInt(8)))
                }.time
            )
        )
    }

    private fun offsetDate(fromMs: Long, days: Int): String =
        SimpleDateFormat("d MMMM", Locale.UK).format(
            Calendar.getInstance().apply {
                timeInMillis = fromMs
                add(Calendar.DAY_OF_MONTH, days)
            }.time
        )

    private fun formatAmount(rnd: Random): String {
        val scale = rnd.nextInt(3)
        val n = when (scale) {
            0 -> (15 + rnd.nextInt(85)) * 1_000L
            1 -> (120 + rnd.nextInt(780)) * 1_000L
            else -> (1 + rnd.nextInt(9)) * 1_000_000L + rnd.nextInt(9) * 100_000L
        }
        return "£" + String.format(Locale.UK, "%,d", n)
    }

    private fun fill(template: String, s: Slots): String {
        var out = template
        if (out.contains("{client}")) out = out.replace("{client}", s.client)
        if (out.contains("{matter}")) out = out.replace("{matter}", s.matter)
        if (out.contains("{opposing}")) out = out.replace("{opposing}", s.opposing)
        if (out.contains("{court}")) out = out.replace("{court}", s.court)
        if (out.contains("{agreement}")) out = out.replace("{agreement}", s.agreement)
        if (out.contains("{amount}")) out = out.replace("{amount}", s.amount)
        if (out.contains("{person}")) out = out.replace("{person}", s.person)
        if (out.contains("{count}")) out = out.replace("{count}", s.count.toString())
        if (out.contains("{pct}")) out = out.replace("{pct}", s.pct.toString())
        if (out.contains("{days}")) out = out.replace("{days}", s.days.toString())
        if (out.contains("{weeks}")) out = out.replace("{weeks}", s.weeks.toString())
        if (out.contains("{months}")) out = out.replace("{months}", s.serviceMonths.toString())
        // All thread-bound (see Slots): a deadline mentioned twice in one
        // conversation is the same deadline, and a time that gets accepted is
        // the time that was proposed.
        if (out.contains("{date}")) out = out.replace("{date}", s.deadline)
        if (out.contains("{pastdate}")) out = out.replace("{pastdate}", s.pastDate)
        if (out.contains("{month}")) out = out.replace("{month}", s.month)
        if (out.contains("{time}")) out = out.replace("{time}", s.meetTime)
        return out
    }

    // ── Timeline ────────────────────────────────────────────────────────────

    private const val MINUTE = 60_000L
    private const val HOUR = 60 * MINUTE
    private const val DAY = 24 * HOUR

    /** Pulls a timestamp back into working hours on a working day. Messages
     *  landing at 03:40 on a Sunday in a solicitor's inbox is the kind of
     *  detail that reads wrong without anyone being able to say why. A small
     *  share of genuinely out-of-hours traffic is kept — lawyers do work late
     *  — but it is late evening, not the small hours. */
    // internal, not private, so DecoyDataTest can exercise it directly — the
    // rest of this object needs a Context and Keystore-backed prefs, which a
    // JVM unit test has no sensible way to provide.
    internal fun businessify(ts: Long, rnd: Random): Long {
        val cal = Calendar.getInstance().apply { timeInMillis = ts }
        val hour = cal.get(Calendar.HOUR_OF_DAY)
        if (hour < 8) {
            cal.add(Calendar.DAY_OF_MONTH, -1)
            cal.set(Calendar.HOUR_OF_DAY, if (rnd.nextInt(10) == 0) 21 else 16 + rnd.nextInt(4))
            cal.set(Calendar.MINUTE, rnd.nextInt(60))
        } else if (hour > 21) {
            cal.set(Calendar.HOUR_OF_DAY, 19 + rnd.nextInt(3))
            cal.set(Calendar.MINUTE, rnd.nextInt(60))
        }
        while (cal.get(Calendar.DAY_OF_WEEK) == Calendar.SATURDAY ||
            cal.get(Calendar.DAY_OF_WEEK) == Calendar.SUNDAY
        ) {
            cal.add(Calendar.DAY_OF_MONTH, -1)
            cal.set(Calendar.HOUR_OF_DAY, 10 + rnd.nextInt(8))
            cal.set(Calendar.MINUTE, rnd.nextInt(60))
        }
        return cal.timeInMillis
    }

    /** Walks backwards from the end of a thread, so the newest message lands
     *  exactly where the thread's recency says it should and the list ordering
     *  is driven by real timestamps rather than a hardcoded "Yesterday". */
    internal fun layoutTimestamps(endAt: Long, n: Int, rnd: Random): List<Long> {
        val out = ArrayList<Long>(n)
        var t = businessify(endAt, rnd)
        out.add(t)
        for (i in 1 until n) {
            // Conversation rhythm: mostly quick back-and-forth inside a burst,
            // with the occasional "picked this up the next morning" gap.
            val gap = when (rnd.nextInt(10)) {
                0, 1 -> (4 + rnd.nextInt(10)) * HOUR
                2 -> (26 + rnd.nextInt(20)) * HOUR
                else -> (2 + rnd.nextInt(40)) * MINUTE
            }
            t = businessify(t - gap, rnd)
            out.add(t)
        }
        return out.reversed()
    }

    // ── Generation ──────────────────────────────────────────────────────────

    // internal so DecoyDataTest can drive a known seed through the real
    // generator and assert on the actual output rather than a transcription.
    internal fun generate(context: Context, s: Session): Generated {
        val seed = s.seed
        val anchor = s.anchor
        val all = scenarios()
        val layoutRnd = subRandom(seed, "layout")
        val threadCount = 6 + layoutRnd.nextInt(3)
        val scenarioOrder = all.indices.shuffled(layoutRnd)

        // Thread recency, newest first: one live conversation, a couple from
        // today, the rest trailing off over the last few weeks.
        val ages = ArrayList<Long>()
        ages.add((12 + layoutRnd.nextInt(90)) * MINUTE)
        ages.add((3 + layoutRnd.nextInt(6)) * HOUR)
        ages.add((20 + layoutRnd.nextInt(10)) * HOUR)
        while (ages.size < threadCount) {
            ages.add((2 + ages.size + layoutRnd.nextInt(5)).toLong() * DAY + layoutRnd.nextInt(8) * HOUR)
        }

        // Which thread carries the canary, decided from its own RNG stream so
        // the choice does not move when scenarios are edited.
        val honeyRnd = subRandom(seed, "honeydoc")
        val honeyThread = honeyRnd.nextInt(threadCount)

        // Which threads are left with unread messages. Drawn from the three
        // most recent, because unread mail that is a fortnight old and has not
        // been opened reads less like a busy inbox than like a generated one.
        val unreadRnd = subRandom(seed, "unread")
        val unreadTargets = (0 until minOf(3, threadCount))
            .shuffled(unreadRnd)
            .take(1 + unreadRnd.nextInt(2))
            .toSet()

        // All three come from the pinned session, never from storage: by the
        // time a decoy recomposes, `shared_prefs` may already have been deleted
        // out from under it. See Session's doc comment.
        val honeyFileName = s.honeyFileName
        val honeyPath = if (honeyFileName.isEmpty()) null
        else SecureFileStorage.blobFile(context.filesDir, honeyFileName).absolutePath

        val sent = s.sent
        val hidden = s.hidden

        var honeyDocName = "Advice note.pdf"
        var honeySlots: Slots? = null
        var honeyTimestamp = anchor

        val threads = ArrayList<DecoyThread>()

        for (i in 0 until threadCount) {
            val scenario = all[scenarioOrder[i % scenarioOrder.size]]
            val slotRnd = subRandom(seed, "slots:$i")
            val timeRnd = subRandom(seed, "time:$i")
            val slots = bindSlots(slotRnd, scenario, anchor - ages[i])
            val threadId = hexId(seed, "thread:$i")
            if (threadId in hidden) continue

            // Beat selection: drop some optional beats, and occasionally clip
            // the tail so not every thread ends on the same note. Variant
            // indices are resolved here, not per-beat, so a reply marked
            // answersPrevious reuses its question's index (see Beat).
            val picked = ArrayList<Pair<Beat, Int>>()
            var lastIndex = 0
            scenario.beats.forEach { beat ->
                if (beat.optional && slotRnd.nextInt(3) == 0) return@forEach
                val index = if (beat.answersPrevious) {
                    lastIndex.coerceAtMost(beat.variants.size - 1)
                } else {
                    slotRnd.nextInt(beat.variants.size)
                }
                picked.add(beat to index)
                lastIndex = index
            }
            // Clip only when it does not strand a question whose answer was the
            // line being removed.
            val beats = if (slotRnd.nextInt(4) == 0 && picked.size > 3 && !picked.last().first.answersPrevious) {
                picked.dropLast(1)
            } else picked

            val carriesHoney = i == honeyThread && honeyPath != null
            val total = beats.size + if (carriesHoney) 1 else 0
            val times = layoutTimestamps(anchor - ages[i], total, timeRnd)

            val msgs = ArrayList<DecoyMsg>()
            beats.forEachIndexed { bi, (beat, variantIndex) ->
                val at = times[bi]
                val text = fill(beat.variants[variantIndex], slots)
                val id = hexId(seed, "msg:$i:$bi")
                // A reply-to on the occasional message: the real MessageBubble
                // renders a quoted header for these, so a decoy that never has
                // one looks subtly flatter than a real conversation.
                val replyTo = if (bi >= 2 && slotRnd.nextInt(7) == 0) msgs[bi - 2].id else null
                msgs.add(
                    DecoyMsg(
                        id = id,
                        text = text,
                        isOwn = beat.own,
                        timestamp = at,
                        isRead = true,
                        isDelivered = true,
                        replyToId = replyTo,
                        reactions = if (slotRnd.nextInt(12) == 0)
                            mapOf(threadId to listOf("👍", "✅", "🙏")[slotRnd.nextInt(3)])
                        else emptyMap()
                    )
                )
            }

            if (carriesHoney) {
                // Mirrors exactly how a received file is recorded by the real
                // client (MessengerService -> ChatScreen.onFileReceived): the
                // message id *is* the blob id, and the message text is the
                // filename. A decoy attachment that broke that invariant would
                // be distinguishable from a real one on inspection.
                honeyDocName = slots.docName
                honeySlots = slots
                honeyTimestamp = times.last()
                msgs.add(
                    DecoyMsg(
                        id = honeyFileName,
                        text = slots.docName,
                        isOwn = false,
                        timestamp = honeyTimestamp,
                        isRead = true,
                        isDelivered = true,
                        fileName = slots.docName,
                        filePath = honeyPath
                    )
                )
            }

            // Unread tail — the blue badge the real list always has.
            //
            // This used to be "if the thread happens to end on an incoming
            // message, roll 1-in-3". Most scenarios end on an outgoing line, so
            // in practice the whole generated inbox came out with zero unread on
            // every thread, which is itself wrong for a working inbox at 17:40
            // — and the badge support was added precisely because its absence
            // was a tell. Now a fixed couple of the most recent threads are
            // chosen up front, and if such a thread ends on our own message a
            // short topic-free chaser is appended so there is something to be
            // unread.
            if (i in unreadTargets) {
                if (msgs.isNotEmpty() && msgs.last().isOwn) {
                    val followAt = businessify(
                        minOf(msgs.last().timestamp + (9 + timeRnd.nextInt(150)) * MINUTE, anchor),
                        timeRnd
                    ).coerceAtLeast(msgs.last().timestamp + MINUTE)
                    msgs.add(
                        DecoyMsg(
                            id = hexId(seed, "chase:$i"),
                            text = timeRnd.pick(followUps),
                            isOwn = false,
                            timestamp = followAt,
                            isRead = false,
                            isDelivered = true
                        )
                    )
                }
                var k = msgs.size - 1
                while (k >= 0 && !msgs[k].isOwn) {
                    msgs[k] = msgs[k].copy(isRead = false)
                    k--
                }
            }
            // The newest outgoing message is sometimes delivered but not yet
            // read — the real UI distinguishes those two tick states.
            if (msgs.isNotEmpty() && msgs.last().isOwn && timeRnd.nextInt(3) == 0) {
                msgs[msgs.size - 1] = msgs[msgs.size - 1].copy(isRead = false)
            }

            sent[threadId]?.forEachIndexed { j, entry ->
                msgs.add(
                    DecoyMsg(
                        id = "s$i-$j-${entry.ts}",
                        text = entry.text,
                        isOwn = true,
                        timestamp = entry.ts,
                        isRead = false,
                        isDelivered = true
                    )
                )
            }

            threads.add(DecoyThread(id = threadId, name = slots.contactName, messages = msgs))
        }

        threads.sortByDescending { it.lastTimestamp }

        return Generated(
            threads = threads,
            honeyDocName = honeyDocName,
            honeyDocBytes = buildAdviceNote(honeySlots, subRandom(seed, "pdf")),
            honeyTimestamp = honeyTimestamp
        )
    }

    private fun hexId(seed: ByteArray, label: String): String {
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(seed)
            update(label.toByteArray(Charsets.UTF_8))
        }.digest()
        return digest.joinToString("") { "%02x".format(it) }
    }

    // ── Canary payload ──────────────────────────────────────────────────────

    /** Content of the canary blob: a short, real, openable PDF consistent with
     *  the filename it is attached under. The previous canary was 256 bytes of
     *  raw SecureRandom, which (a) could not be opened at all if anyone tapped
     *  it and (b) was a size no genuine attachment in this app can ever have.
     *  No absolute dates appear in it — the blob is written once and the
     *  surrounding timeline keeps moving, so a date here would eventually
     *  contradict the chat it sits in. */
    private fun buildAdviceNote(slots: Slots?, rnd: Random): ByteArray {
        val client = slots?.client ?: "the Client"
        val matter = slots?.matter ?: "GEN-1000"
        val opposing = slots?.opposing ?: "the other side"
        val agreement = slots?.agreement ?: "the agreement"
        val amount = slots?.amount ?: "£100,000"

        val body = mutableListOf(
            "",
            "Client: $client",
            "Matter reference: $matter",
            "Privileged and confidential - prepared for the purpose of advising the client",
            "",
            "1. Summary",
            "",
            "    1.1 This note sets out our preliminary view on the issues arising on",
            "        $agreement and the position we recommend taking in correspondence",
            "        with $opposing.",
            "",
            "    1.2 Our view is that the client's position is defensible on the",
            "        construction point, but that the quantum exposure is material and",
            "        should be provided for at not less than $amount.",
            "",
            "2. Background",
            "",
            "    2.1 We are instructed in relation to a dispute arising out of",
            "        $agreement. The relevant provisions are the limitation of",
            "        liability clause and the notice requirements.",
            "",
            "    2.2 The factual chronology set out in the client's file note has been",
            "        taken as read for the purposes of this note and has not been",
            "        independently verified.",
            "",
            "3. Analysis",
            "",
            "    3.1 Construction. On the natural reading of the clause, the cap applies",
            "        per claim rather than in the aggregate. That reading is supported by",
            "        the commercial context and by the structure of the surrounding",
            "        provisions.",
            "",
            "    3.2 Notice. The notice served was arguably defective in that it did not",
            "        specify the clause relied upon. We do not consider that this is",
            "        fatal, but it is a point that will be taken against us.",
            "",
            "    3.3 Quantum. The loss of profit claim is the largest single element and",
            "        is the most vulnerable to challenge on causation. We would expect a",
            "        significant discount to be applied on any assessment.",
            "",
            "4. Recommendation",
            "",
            "    4.1 We recommend that the client responds substantively within the time",
            "        allowed, reserving its position on the notice point.",
            "",
            "    4.2 We further recommend that instructions be taken on settlement",
            "        parameters before any without prejudice discussion takes place.",
            "",
            "5. Next steps and costs",
            "",
            "    5.1 We will prepare a draft response for the client's approval and",
            "        revert with a costs estimate for the next stage.",
            "",
            "    5.2 This note is provided on the basis of our standard terms of",
            "        business and is for the client's use only. It should not be",
            "        disclosed to any third party without our prior written consent.",
            "",
            "",
            "This note is subject to legal professional privilege. If you have received",
            "it in error please notify us immediately and delete it.",
            ""
        )
        // Light per-install variation in length so the blob size is not a
        // constant across installs either.
        repeat(rnd.nextInt(6)) { body.add("") }

        return buildPdf("${slots?.docName?.substringBeforeLast('.') ?: "Advice note"}", body)
    }

    private fun escapePdf(s: String): String =
        s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    /** Minimal single-page PDF writer. Hand-rolled rather than pulled in as a
     *  dependency: this is the only PDF this app ever produces, and adding a
     *  PDF library to an APK in order to generate a decoy document would
     *  itself be a conspicuous thing to find in the dependency list. */
    internal fun buildPdf(title: String, lines: List<String>): ByteArray {
        val out = ByteArrayOutputStream()
        val offsets = ArrayList<Int>()
        fun w(s: String) = out.write(s.toByteArray(Charsets.ISO_8859_1))
        fun mark() = offsets.add(out.size())

        w("%PDF-1.4\n")
        mark(); w("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        mark(); w("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
        mark(); w(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] " +
                "/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj\n"
        )
        mark(); w("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
        mark(); w("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

        val content = StringBuilder()
        content.append("BT\n/F2 12 Tf\n56 790 Td\n13.5 TL\n(")
            .append(escapePdf(title)).append(") Tj\nT*\n/F1 9.5 Tf\n")
        lines.forEach { content.append("(").append(escapePdf(it)).append(") Tj\nT*\n") }
        content.append("ET\n")
        val stream = content.toString()
        val streamBytes = stream.toByteArray(Charsets.ISO_8859_1)

        mark()
        w("6 0 obj\n<< /Length ${streamBytes.size} >>\nstream\n")
        out.write(streamBytes)
        w("\nendstream\nendobj\n")

        val xref = out.size()
        w("xref\n0 ${offsets.size + 1}\n")
        w("0000000000 65535 f \n")
        offsets.forEach { w(String.format(Locale.ROOT, "%010d 00000 n \n", it)) }
        w("trailer\n<< /Size ${offsets.size + 1} /Root 1 0 R >>\nstartxref\n$xref\n%%EOF\n")
        return out.toByteArray()
    }
}
