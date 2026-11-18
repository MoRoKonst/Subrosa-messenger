package com.subrosa.desktop

import kotlinx.coroutines.*
import java.io.File

/**
 * KL-13 live run, DESKTOP side — headless: it drives the real desktop client code
 * (InviteCodeManager, ChatStorage, AnonTokenManager, WebSocketClient) against a real
 * server, but there is NO GUI. It plays "the person at the laptop":
 *   1. connects, writes ITS invite code to <outFile>
 *   2. waits for the phone's invite code in <inFile>, accepts it (acceptInvite)
 *   3. sends a message to the phone and logs every message it receives.
 * Args: <outFile> <inFile> <textToSend> [waitSeconds]
 * Env:  APPDATA (separate identity), Subrosa_TEST_SERVER_URL (default ws://127.0.0.1:9000/ws)
 */
fun main(args: Array<String>): Unit = runBlocking {
    val out = File(args.getOrNull(0) ?: error("usage: <outFile> <inFile> <text> [waitSec]"))
    val inp = File(args.getOrNull(1) ?: error("missing inFile"))
    val text = args.getOrNull(2) ?: "hello from desktop"
    val waitSec = args.getOrNull(3)?.toLong() ?: 240
    fun log(m: String) = println("[desktop] $m")

    DesktopStorage.init()
    DesktopStorage.put("server_url", System.getenv("Subrosa_TEST_SERVER_URL") ?: "ws://127.0.0.1:9000/ws")
    DesktopCryptoManager.init()
    CryptoManager.init()
    SessionKeyManager.init()

    WebSocketClient.onMessageReceived = { from, t, _, _ -> log("RECEIVED from=$from text=$t") }
    WebSocketClient.connect("laptop")
    withTimeoutOrNull(20_000) { while (!WebSocketClient.connected.value) delay(200) }
        ?: run { log("FAILED: could not connect"); kotlin.system.exitProcess(1) }
    log("connected, fingerprint=${WebSocketClient.myFingerprint}")
    delay(1500)

    val mine = InviteCodeManager.generateInviteLink()
    out.writeText(mine)
    val parsedMine = InviteCodeManager.parseInviteCode(mine)
    log("my invite written to ${out.absolutePath} (len=${mine.length}); self-verify=${parsedMine?.let { InviteCodeManager.verifyInviteCode(it) }}")

    log("waiting for the phone's invite code in ${inp.absolutePath}")
    withTimeoutOrNull(waitSec * 1000) { while (!inp.exists() || inp.readText().isBlank()) delay(500) }
        ?: run { log("FAILED: no phone invite within ${waitSec}s"); kotlin.system.exitProcess(2) }
    val phoneCode = inp.readText().trim()
    val data = InviteCodeManager.parseInviteCode(phoneCode)
    log("phone invite parsed=${data != null} len=${phoneCode.length} name=${data?.displayName} fp=${data?.fingerprint} tag=${data?.mailboxTag?.take(8)}…")
    if (data == null) { log("FAILED: desktop parser rejected the Android-generated code"); kotlin.system.exitProcess(3) }
    log("verifyInviteCode=${InviteCodeManager.verifyInviteCode(data)}")
    val name = InviteCodeManager.acceptInvite(phoneCode)
    log("acceptInvite -> ${name ?: "NULL (rejected)"}")
    if (name == null) kotlin.system.exitProcess(4)

    delay(5000) // let the anonymous token bootstrap run
    log("sending: $text")
    WebSocketClient.sendText(data.fingerprint, text, java.util.UUID.randomUUID().toString())
    delay(waitSec * 1000)
    log("done waiting")
    kotlin.system.exitProcess(0)
}
