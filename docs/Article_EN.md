# Hiding the Social Graph in a Messenger: Tokens, Cover Traffic, and Tor

End-to-end encryption is great technology. But E2EE has a fundamental blind spot: it protects the **content** of messages, but not the **fact of communication**. The server still sees who talks to whom, when, and how often. That's enough for a metadata attack.

In this article we'll look at how to close this vector at the architecture level, using a concrete open-source implementation as an example.

## The Metadata Problem

A standard packet in most messengers looks like this:

```json
{
  "type": "message",
  "from": "A1B2C3D4E5F6A7B8",
  "to":   "9F8E7D6C5B4A3210",
  "text": "<encrypted>"
}
```

Even if the content is perfectly encrypted, the server sees the `from → to` pair on every send. Accumulate enough logs and you can reconstruct the **social graph** — a map of who communicates with whom.

For a journalist connected to a source, or an activist coordinating an action, this is a critical vulnerability even with perfect E2EE.

The server knows:

- Who communicates with whom (`fingerprint` of sender → `fingerprint` of recipient)
- Exactly when communication happens
- How often and what volume

## Anonymous Token Routing

The solution: route messages not by user fingerprint, but by **single-use random tokens**.

### How It Works

On connection, the client generates a pool of 50 random 128-bit tokens and registers them with the server:

```kotlin
fun ensureMyTokenPool(ctx: Context): List<String> {
    val existing = getMyTokens(ctx)
    if (existing.size >= POOL_SIZE / 2) return existing
    val needed = POOL_SIZE - existing.size
    val newTokens = (1..needed).map { generateToken() }
    // ...save and return
}

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
```

The server stores only the mapping `token → WebSocket`, with no binding to user identity:

```python
token_to_ws:  dict = {}   # token → websocket
ws_to_tokens: dict = {}   # websocket → set[str]
known_tokens: set  = set() # tokens that have been registered at least once
```

Clients exchange tokens over E2EE — they send each other their pool as an encrypted system message. After the exchange, a packet looks like this:

```json
{
  "type": "anon_message",
  "token": "e39f013483715c300e9a7db2b601709c",
  "payload": "<encrypted>"
}
```

The server knows who sent the packet — sending requires an authenticated connection, like any server-mediated messenger — but has no idea who the recipient is; it simply finds the WebSocket by token and delivers. The token is single-use: it's removed from the table after delivery.

### The First Contact Problem

The classic problem with token routing is the **first message**. To exchange tokens, you need to make contact first. In most messengers this means the server sees `A → B` at least once.

The solution: an **anonymous mailbox** embedded in the invite code.

The invite code contains not just a public key and fingerprint, but also a random 16-byte `mailbox_tag`:

```
[version][timestamp][nonce][mailbox_tag(16b)][fingerprint][ec_point][name][sig]
```

How it works:

```
Alice creates an invite → it contains mailbox_tag T
Bob receives the invite → encrypts the first message with Alice's key → puts it in mailbox[T]
Alice connects → asks the server: "do you have anything for tags [T, X, Y, Z, ...]?"
Server → returns blobs for matching tags
Alice → decrypts, receives message + Bob's tokens
```

The key point: Alice always requests **exactly 20 tags** — her real one plus random fakes. The server doesn't know which one is real:

```kotlin
fun buildFetchTagList(ctx: Context): List<String> {
    val real = getMyMailboxTags(ctx)
    val fakeCount = maxOf(MBOX_TOTAL - real.size, 0)  // always 20 total
    val fakes = (1..fakeCount).map { generateToken() }
    return (real + fakes).shuffled()
}
```

When the server receives `mailbox_fetch`, it returns only tags that have blobs, and immediately deletes them. Blobs that are never fetched are automatically deleted after 48 hours.

As a result, **the first message no longer reveals the `A → B` pair**. The server sees an anonymous blob and a request for 20 tags — it can see Alice fetching mailboxes, but has no idea whose blob she's collecting or who deposited it.

### Key Trust

On first contact, clients exchange public keys. How do you know you received your contact's key and not a man-in-the-middle key? A hostile server could theoretically substitute the key and read everything (MITM).

The solution is a **fingerprint**: a SHA-256 hash of the public key, which users verify **out-of-band** — showing each other their screens, reading it over the phone, comparing it in another messenger. The same concept as Signal's "Safety numbers."

```
Verified fingerprint out-of-band
    → key is authentic
    → encryption is secure
    → tokens and mailbox messages are protected
    → all further communication is anonymous
```

### What the Server Sees After This

Before: `A1B2C3D4 → 9F8E7D6C (message)`  
After: `anon_message → token e39f0134... (delivered)`

The social graph is not available from **leaked logs**. An important caveat: the server still holds the `token → WebSocket` mapping, so an actively malicious server operator can still reconstruct who talks to whom — from the internal routing table. Tokens protect against passive log leaks, not against a deliberately dishonest server. That's exactly why self-hosting matters.

## Cover Traffic: Hiding Timing

Even without fingerprints, a **timing attack** remains. If an observer controls traffic at both endpoints, they can statistically correlate: "Alice sent a packet at 14:23:01.337, Bob received a packet at 14:23:01.891 — delta 554ms, matches 1000 times out of 1000 → they're communicating."

### Why Random Noise Doesn't Help

The first idea is to send fake messages randomly, once every 30–120 seconds. This creates noise, but doesn't solve the problem. On a traffic graph, this looks like occasional packets with no response — against a background of steady exchange between two users, they're easy to filter out statistically.

### Constant-Rate Cover Traffic

The right solution — and this is exactly how the academic Loopix protocol works. The client **always** sends a stream at a fixed interval. When a real message is ready, it takes the place of the next noise packet:

```
Without protection:  ────M──────────M──M──────────  (M = message, pattern visible)
With protection:     N─N─M─N─N─N─N─M─NM─N─N─N─N─  (N = noise, everything looks the same)
```

Implementation: real messages go into a queue, a coroutine on a fixed interval takes the next packet from it — or sends noise if the queue is empty:

```kotlin
private val outboundQueue = LinkedBlockingQueue<String>()

private fun startCoverTraffic() {
    val intervalMs = if (mode == AGGRESSIVE) 1_000L else 5_000L
    coverTrafficJob = scope.launch(Dispatchers.IO) {
        val rng = SecureRandom()
        while (isActive) {
            delay(intervalMs)
            if (!isConnected) continue
            val packet = outboundQueue.poll()
            if (packet != null) {
                webSocket?.send(packet)            // real message
            } else {
                webSocket?.send(buildNoisePacket(rng))  // noise
            }
        }
    }
}
```

The noise packet is intentionally indistinguishable from a real one by structure — same `anon_message` type, random token, random payload padded to one of several fixed sizes.

The server silently drops packets with unknown tokens, without logging:

```python
async with lock:
    is_known = token in known_tokens
if not is_known:
    # cover traffic — drop without logging
    if msg_id:
        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
    continue
```

Available modes:

| Mode | Interval | Traffic |
|---|---|---|
| Off | — | real messages only |
| Moderate | 1 packet / 5 sec | ~2–3 MB/hour |
| Aggressive | 1 packet / sec | ~20–30 MB/hour |

This is an explicitly optional feature with a warning about battery and data usage — not for everyday use.

### Honest About the Limits

Constant-rate traffic hides timing when observed **from one side** (e.g., only the sender's ISP). If an observer controls traffic at both endpoints simultaneously, statistical correlation is still possible, just significantly harder. Fully solving this without a mix network (Nym, Loopix) with intentional delays and packet shuffling is not possible. But that's the level of a targeted operation against a specific individual — not mass passive surveillance.

## Tor Hidden Service: Hiding the IP

Anonymous tokens hide the social graph from the server. But the server still sees the client's IP address on connection. For use cases where anonymity matters, this is unacceptable.

The solution is a **Tor Hidden Service**. Regular Tor through exit nodes has a problem: Cloudflare and many hosting providers block exit nodes. An `.onion` address solves this: traffic travels entirely inside the Tor network, with no exit nodes and no Cloudflare in the chain.

Server configuration is minimal:

```
HiddenServiceDir /var/lib/tor/Subrosa/
HiddenServicePort 80 127.0.0.1:9000
```

One Android-specific implementation detail: Orbot runs in two modes — SOCKS proxy (port 9050) and system VPN. In VPN mode, an explicit SOCKS proxy creates a double-tunneling conflict. For `.onion` addresses, use a plain HTTP client — Orbot will intercept the traffic at the system level on its own:

```kotlin
// Onion via Orbot VPN — don't use explicit SOCKS proxy
val client = if (wsUrl.contains(".onion")) plainWsClient else socksWsClient()
webSocket = client.newWebSocket(request, listener)
```

## Threat Model Summary

| Observer | Sees without protection | Sees with this architecture |
|---|---|---|
| Honest server / leaked logs | `from → to` graph, content | Only anonymous blobs and tokens, no identity binding |
| Malicious server | `from → to` graph, content | Token routing table (solution: self-hosting) |
| Sender's ISP | Server IP, timing, volume | Encrypted Tor traffic |
| Recipient's ISP | Server IP, timing, volume | Encrypted Tor traffic |
| Both ISPs simultaneously | Timing correlation | Statistically much harder (constant-rate) |
| Targeted operation (MITM, device) | Everything | Content protected by E2EE |

## Conclusion

Four layers, each closing its own attack vector:

1. **Anonymous mailbox** — first contact doesn't reveal the `A → B` pair; the server sees only blobs indexed by random tags
2. **Single-use tokens** — all subsequent messages are routed without fingerprints
3. **Constant-rate cover traffic** — timing correlation is significantly harder; the observer sees a uniform stream
4. **Tor hidden service** — IP address is hidden; no exit nodes, no Cloudflare blocks

This is not a mix network and not absolute anonymity. But for protection against passive mass surveillance and operator log leaks — it's practically sufficient.

---

*Reference implementation: [github.com/MoRoKonst/Subrosa-messenger](https://github.com/MoRoKonst/Subrosa-messenger) — open-source Android messenger with self-hosting support.*
