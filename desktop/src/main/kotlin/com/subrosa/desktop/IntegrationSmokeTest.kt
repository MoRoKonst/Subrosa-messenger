package com.subrosa.desktop

import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.File
import java.util.Base64

/**
 * Headless smoke test for the full crypto/network path — no GUI. Verifies
 * an actual, end-to-end run of: connect, register, publish a PQ-hybrid
 * prekey bundle, X3DH handshake between two independent processes, message
 * decrypt, and a reply on the resulting Double Ratchet session.
 *
 * This exists because none of this session's protocol/wire-format work
 * (anon routing, PQ-hybrid X3DH, binary format changes) had ever been run
 * against a real second process before — only compiled. Run two instances
 * (each needs its own APPDATA so they get separate identities):
 *
 *   set APPDATA=C:\temp\Subrosa_alice
 *   java -cp <classpath> com.subrosa.desktop.IntegrationSmokeTestKt alice out_alice.json in_alice.json
 *
 *   set APPDATA=C:\temp\Subrosa_bob
 *   java -cp <classpath> com.subrosa.desktop.IntegrationSmokeTestKt bob   out_bob.json   in_bob.json
 *
 * where in_alice.json == out_bob.json and in_bob.json == out_alice.json
 * (each side's output file is the other side's input file) — bypasses the
 * invite-code/mailbox UI flow entirely to isolate the core crypto path.
 */
fun main(args: Array<String>): Unit = runBlocking {
    val role = args.getOrNull(0) ?: error("usage: <role> <myInfoOutFile> <peerInfoInFile>")
    val myInfoOut = File(args.getOrNull(1) ?: error("missing myInfoOutFile"))
    val peerInfoIn = File(args.getOrNull(2) ?: error("missing peerInfoInFile"))

    fun log(msg: String) = println("[$role] $msg")

    log("starting, APPDATA=${System.getenv("APPDATA")}")
    DesktopStorage.init()
    DesktopStorage.put("server_url", System.getenv("Subrosa_TEST_SERVER_URL") ?: "ws://127.0.0.1:9000/ws")
    DesktopCryptoManager.init()
    CryptoManager.init()
    SessionKeyManager.init()

    var passed = false
    var replyReceived = false
    val expectedFirstMessage = "PQ-HANDSHAKE-TEST-FROM-ALICE"
    val expectedReply = "PQ-HANDSHAKE-TEST-REPLY-FROM-BOB"

    WebSocketClient.onMessageReceived = { from, text, _, _ ->
        log("RECEIVED from=$from text=$text")
        if (role == "bob" && text == expectedFirstMessage) {
            log("bob: replying")
            WebSocketClient.sendText(from, expectedReply, java.util.UUID.randomUUID().toString())
        }
        if (role == "alice" && text == expectedReply) {
            log("alice: reply matches — ROUND TRIP OK")
            passed = true
            replyReceived = true
        }
    }

    WebSocketClient.connect(role)

    withTimeoutOrNull(20_000) {
        while (!WebSocketClient.connected.value) delay(200)
    } ?: run { log("FAILED — could not connect within 20s"); kotlin.system.exitProcess(1) }
    log("connected, fingerprint=${WebSocketClient.myFingerprint}")

    delay(1500) // let handshake_ok's publishPrekeyBundle() land on the server

    val myInfo = JSONObject().apply {
        put("fp", WebSocketClient.myFingerprint)
        put("pubkey", DesktopCryptoManager.getPublicKeyBase64())
    }
    myInfoOut.writeText(myInfo.toString())
    log("wrote identity to ${myInfoOut.absolutePath}")

    log("waiting for peer identity at ${peerInfoIn.absolutePath}")
    withTimeoutOrNull(30_000) {
        while (!peerInfoIn.exists() || peerInfoIn.readText().isBlank()) delay(300)
    } ?: run { log("FAILED — peer identity never appeared"); kotlin.system.exitProcess(1) }

    val peerInfo = JSONObject(peerInfoIn.readText())
    val peerFp = peerInfo.getString("fp")
    val peerPubKey = peerInfo.getString("pubkey")
    log("peer fingerprint=$peerFp")

    ChatStorage.addContact(peerFp)
    ChatStorage.saveContactPublicKey(peerFp, peerPubKey)
    DesktopCryptoManager.storePeerPublicKey(peerFp, peerPubKey)

    if (role == "alice") {
        // Fake (non-existent) decoy contacts, added purely so
        // enqueueAndRequestBundle() sees >0 contacts and takes the batched
        // anonymous-fetch path (get_prekey_bundles_batch) instead of the
        // direct one — exercises the new decoy-padding + bootstrap-token
        // mechanism end-to-end. The server will just return null bundles
        // for these (they don't exist), which is a normal, handled case.
        repeat(3) { i ->
            val fakeFp = (1..16).map { "0123456789ABCDEF".random() }.joinToString("")
            ChatStorage.addContact(fakeFp)
            log("added decoy contact #$i = $fakeFp")
        }

        delay(2000) // give bob time to also register the contact
        log("sending first message (triggers ANONYMOUS BATCHED prekey bundle fetch + PQ-hybrid X3DH)")
        WebSocketClient.sendText(peerFp, expectedFirstMessage, java.util.UUID.randomUUID().toString())

        withTimeoutOrNull(30_000) {
            while (!replyReceived) delay(300)
        }
        if (passed) {
            log("TEST PASSED")
            kotlin.system.exitProcess(0)
        } else {
            log("TEST FAILED — no reply within timeout")
            kotlin.system.exitProcess(1)
        }
    } else {
        // bob just waits and reacts via the onMessageReceived callback above
        delay(40_000)
        log("bob exiting")
        kotlin.system.exitProcess(0)
    }
}
