# Desktop вЂ” Manual Test Plan: Local Interception Protections

Covers features added across this session: crash dump suppression, clipboard
history/cloud exclusion, clipboard auto-clear, DLL search-order hardening,
POSIX storage-directory permissions, and secure deletion of attachment temp
files. Most of these are Windows-only (no-ops on macOS/Linux вЂ” see
"Cross-platform" section); the POSIX permissions and temp-file checks are
the other way around (Linux/macOS-only or cross-platform).

Run on a real Windows 10 (2004+) or Windows 11 machine вЂ” these APIs cannot
be verified in a VM snapshot or a headless CI runner.

---

## 0. Setup

- [ ] Build and run the release/debug jar on Windows (not `gradlew run` inside an IDE вЂ” some IDEs override `SetErrorMode`/clipboard hooks for their own debugger).
- [ ] Enable **Clipboard History**: Settings в†’ System в†’ Clipboard в†’ "Clipboard history" ON (Win+V must show history for the test to be meaningful).
- [ ] Enable **Cloud Clipboard sync** (if you have a second Windows PC signed into the same Microsoft account, or at least toggle "Sync across devices" ON) вЂ” without this the cloud-exclusion half of the test can't be verified end-to-end, only locally.
- [ ] Have a second, unrelated app open (e.g. Notepad) to test clipboard interaction from outside Beacon.

---

## 1. Clipboard auto-clear (message copy)

File: `ui/ChatScreen.kt` вЂ” copies a message's text, clears it again after 30s if untouched.

- [ ] Open a chat with at least one received/sent text message.
- [ ] Right-click (or long-press) a message в†’ **Copy**.
- [ ] Immediately paste into Notepad вЂ” text should paste correctly.
- [ ] Wait 30+ seconds without copying anything else.
- [ ] Try pasting into Notepad again вЂ” **clipboard should now be empty** (paste does nothing, or pastes empty string).
- [ ] **Negative case**: Copy a message, then within the 30s window copy something *different* (e.g. select and copy text in Notepad). Wait out the remaining timer. Confirm the **Notepad text is NOT cleared** вЂ” the auto-clear must only fire if the clipboard still holds exactly what Beacon put there (it must not clobber unrelated clipboard activity from other apps).
- [ ] Copy two different messages back-to-back (< 30s apart). Confirm only the *second* copy's 30s timer matters вЂ” the app doesn't wipe the second copy early because of the first timer still running.

## 2. Clipboard excluded from History & Cloud Sync

File: `NativeProtection.kt::excludeClipboardFromHistoryAndCloud()` вЂ” registers `CanIncludeInClipboardHistory` / `CanUploadToCloudClipboard` = 0 right after the copy.

- [ ] Copy a message's text from Beacon (as in step 1).
- [ ] Open Clipboard History (**Win+V**). **The copied message text should NOT appear** in the history list (most recent entry should be whatever you copied before, or empty).
- [ ] Copy something ordinary from Notepad afterward вЂ” confirm it *does* show up in Win+V (sanity check that history itself isn't globally broken).
- [ ] If you have Cloud Clipboard sync set up across two PCs: copy a message on PC A, check PC B's clipboard (Win+V or paste) вЂ” the Beacon text should **not** have synced over. Copy something from Notepad on PC A as a control вЂ” it **should** sync.
- [ ] Confirm the copied text still pastes normally in the *same* session immediately after copying (exclusion must not break the base copy/paste functionality вЂ” only history/cloud persistence).

## 3. Crash dump suppression

File: `NativeProtection.kt::disableCrashDumps()`, called first thing in `main.kt`.

- [ ] Trigger an unhandled crash. Easiest repeatable way: temporarily add a button or menu item that throws (e.g. `throw RuntimeException("test crash")`) on a background thread, run it, then **remove the test hook before committing**. Alternatively force a real crash path if one is known (do not ship the crash hook).
- [ ] Confirm the standard Windows **"Program has stopped working"** dialog does **not** appear (or appears without the "Debug"/"Send report" prompt that normally lets Windows collect a memory dump).
- [ ] Check `%LOCALAPPDATA%\CrashDumps\` вЂ” confirm no new dump file was created for this crash (this folder is populated by WER `LocalDumps` if configured; absence of a new file here is a pass).
- [ ] Check Windows Event Viewer в†’ Windows Logs в†’ Application, for a "Windows Error Reporting" event tied to the crash timestamp вЂ” ideally no interactive-report event was generated.
- [ ] Regression: confirm the app still exits/logs the crash to `System.err`/console as before вЂ” `SetErrorMode` should only suppress the UI dialog, not your own error handling.

## 4. Cross-platform no-op check (if you have access to macOS/Linux)

- [ ] Run the app on macOS or Linux. Confirm no crash/exception at startup from the new `NativeProtection.disableCrashDumps()` and `NativeProtection.restrictDllSearchToSystem32()` calls (both should silently return `false`).
- [ ] Copy a message on macOS/Linux вЂ” confirm copy/paste still works normally, auto-clear-after-30s still functions (that part is pure Kotlin/Compose, not Windows-specific), only the history/cloud-exclusion marker call is skipped.

## 5. DLL search-order hardening (Windows)

File: `NativeProtection.kt::restrictDllSearchToSystem32()`, called first thing in `main.kt`, before any other native library loads.

- [ ] Fresh run of the app on Windows вЂ” confirm it still starts normally and `user32`/`kernel32` calls (screen-capture protection, clipboard exclusion) still work. This is the main regression risk: if this call breaks JNA's own native stub loading, screen-capture/clipboard protection would silently stop working.
- [ ] **Planting test**: drop a harmless decoy DLL with the name of a library the app might legitimately probe for (do NOT use a real malicious payload) into the same directory as the jar/exe, restart the app, confirm it is not loaded (no unexpected behavior, no crash referencing the decoy file). This is a sanity check, not a full pentest.

## 6. POSIX storage-directory permissions (Linux/macOS only)

File: `DesktopStorage.kt::restrictToOwnerIfPosix()`, applied to `~/.config/BeaconMessenger` (Linux) / `~/Library/Application Support/BeaconMessenger` (macOS) on first run.

- [ ] Delete/rename any existing `BeaconMessenger` data dir (back it up first!), start the app fresh so the directory is recreated.
- [ ] Run `ls -ld ~/.config/BeaconMessenger` (Linux) or the macOS equivalent path вЂ” permissions should show `drwx------` (700), owner-only.
- [ ] Confirm normal app operation is unaffected (login, send/receive messages, restart the app and confirm data persisted).
- [ ] If you have a second local OS user account on the same machine, confirm that user gets "Permission denied" trying to `cat`/`ls` into the Beacon data directory.

## 7. Secure deletion of attachment temp files

File: `ui/ChatScreen.kt` (`FileRow` composable) вЂ” decrypts a received attachment to a temp file, opens it externally, then overwrites it via `DesktopStorage.secureDelete()` after a 5-minute timer *and* on JVM shutdown (instead of a plain `deleteOnExit()`).

- [ ] Receive/open a non-image file attachment (e.g. a PDF or .txt) in a chat вЂ” confirm it opens correctly in the default external viewer.
- [ ] Find the temp file while the viewer still has it open: check `%TEMP%` (Windows) or `/tmp` (Linux/macOS) for a file named `beacon_*`. Confirm it exists and contains the decrypted content while you're still viewing it (expected вЂ” the external app needs to read it).
- [ ] Close the app (clean exit) shortly after opening the attachment вЂ” confirm the `beacon_*` temp file is gone afterward (shutdown-hook secure-delete fired).
- [ ] Alternative: leave the app running and wait 5+ minutes after opening the attachment вЂ” confirm the temp file is gone (timer-based secure-delete fired), even without closing the app.
- [ ] **Known gap, not a bug**: force-kill the app (Task Manager "End task" / `kill -9`) within the 5-minute window вЂ” confirm (as expected, and as documented in `SECURITY.md` item 10) the temp file is *not* cleaned up in this case. This is a documented residual limitation, not a regression вЂ” just confirming the doc matches reality.

## 8. Sign-off

- [ ] All boxes above checked on a real Windows machine, and (where applicable) on macOS/Linux.
- [ ] No regression in normal copy/paste of messages, invite links, or channel links.
- [ ] No regression in opening/viewing file attachments.
- [ ] Remove any temporary crash-test hook (section 3) or decoy DLL (section 5) added for testing before merging.

---

# Part 2 вЂ” Anonymous Transmission-Layer Routing (Desktop parity with Android)

Covers this session's port of Android's anonymous token routing / mailbox / cover
traffic to Desktop (`AnonTokenManager.kt`, `WebSocketClient.kt` changes,
`InviteCodeManager.kt` mailbox tag, `ProfileScreen.kt` cover-traffic toggle),
plus the server-side console log redaction in `ForEXP/server.py`. Needs a real
server instance and two Desktop clients вЂ” cannot be verified by reading code
or a single-client smoke test.

## 9. Setup

- [ ] Run `ForEXP/server.py --dev` locally.
- [ ] Run two separate Desktop client instances against it, each with its own
      data directory so they act as independent identities (e.g. set
      `APPDATA`/`XDG_CONFIG_HOME` differently per launch, or run on two machines/VMs).
- [ ] Keep the server's console visible throughout вЂ” this is what you're checking.

## 10. First contact via anonymous mailbox (Desktopв†”Desktop only)

- [ ] On Client A, generate an invite link (Profile в†’ invite). Confirm the link
      contains an `&mbox=<32-hex-chars>` parameter.
- [ ] Paste/accept the invite on Client B.
- [ ] Send the first message from B to A (before any other messages have been
      exchanged). Confirm it delivers and A can read it.
- [ ] Watch the server console during that first send: confirm you see
      `mailbox_put`/`mailbox_fetch` activity and **no** `[MSG] message delivered`
      or similar line carrying this pair's fingerprints for that first message.
- [ ] Confirm A can reply to B normally afterward (tokens should now be
      established both ways).

## 11. Anonymous routing for ongoing 1:1 traffic

- [ ] After first contact (section 10) is established, send several more text
      messages both directions. Confirm the server console shows only
      `[ANON]`-style lines (no `[MSG] message delivered` naming this pair) вЂ”
      i.e. messages are now routed via `anon_message`/token, not fingerprint.
- [ ] Send a typing indicator, a read receipt (open the chat), an edit, and a
      delete. None of these should produce a `[MSG]`/fingerprint-identifying
      server log line for this pair either.
- [ ] Send an image and a file. Confirm both arrive intact and decrypt
      correctly (chunk reassembly still works end-to-end through the anon path).
- [ ] Exhaust the token pool deliberately (send enough messages to run past
      the 50-token pool without a refill window) and confirm the client
      recovers gracefully вЂ” falls back to a direct send rather than silently
      dropping the message, and resumes anon routing after `sendAnonTokensTo`
      replenishes the pool.

## 12. Groups and calls

- [ ] Create a group with both clients as members (after they already have an
      established token pool with each other). Send a group message. Confirm
      no `[MSG]`/fingerprint-identifying line for this pair appears for the
      per-member deliveries.
- [ ] Remove a member / rotate the group key. Confirm delivery still works.
- [ ] Place a 1:1 call (audio or video) between the two clients. Confirm the
      call connects, media flows, and hangs up cleanly. Confirm the server
      console shows only `[CALL] call_offer relayed`-style lines (type only,
      no fingerprint pair) instead of the old `{username} в†’ {target}` format.

## 13. Cover traffic

- [ ] In Profile settings, cycle the new "РњР°СЃРєРёСЂРѕРІРєР° С‚СЂР°С„РёРєР°" setting through
      Off в†’ Moderate в†’ Aggressive and confirm the label updates each time.
- [ ] With Aggressive selected and no active conversation, confirm periodic
      `anon_message` noise packets are still being sent (observable via a
      local proxy/packet capture, or by the server's per-connection traffic
      continuing to tick over with no real activity).
- [ ] Confirm cover traffic stops when the client disconnects (check it
      doesn't keep sending after `disconnect()` / on connection drop) and
      resumes after reconnecting.

## 14. Cross-platform invite compatibility (now fixed вЂ” verify it actually works)

`InviteCodeManager.kt` on Desktop was rewritten to use the exact same binary
`bc:<...>` wire format as Android (was previously an incompatible
`beacon://invite?key=...` URL format). This was a code-level port done without
a live cross-platform test вЂ” the byte layout, DERв†”raw signature conversion,
and EC-point reconstruction were mirrored field-for-field from Android's
`InviteCodeManager.kt`, and Desktop compiles and round-trips against its own
invites, but an actual Androidв†”Desktop exchange has **not** been run yet.

- [ ] Generate an invite on Android, accept it on Desktop. Confirm the contact
      is added with the correct name and fingerprint, and that
      `verifyInviteCode` doesn't reject a genuine Android-signed invite
      (this exercises the DERв†”raw signature conversion both ways).
- [ ] Generate an invite on Desktop, accept it on Android. Same checks.
- [ ] Confirm the `mbox` mailbox tag round-trips too: send the very first
      message across platforms right after accepting the invite, and confirm
      via the server console (section 10 above) that it goes through
      `mailbox_put`/`mailbox_fetch` rather than a fingerprint-addressed
      `message`.
- [ ] If any of the above fails, the most likely culprits are: byte order in
      the timestamp/nonce fields, the EC point extraction (last 65 bytes of
      the X.509 key), or the DERв†”raw ECDSA signature conversion вЂ” compare the
      raw invite bytes from both platforms for the same key/timestamp to
      isolate which field diverges.

## 15. Automated headless smoke test (PQ-hybrid X3DH + message round-trip)

`IntegrationSmokeTest.kt` + the `smokeTest` Gradle task exist specifically
because, until this was written, **nothing** in this project's protocol/
wire-format work had ever been run against a real second process вЂ” only
compiled. It runs the actual production classes (`WebSocketClient`,
`SessionKeyManager`, `CryptoManager`) headlessly (no GUI), bypassing only the
invite-code UI (it exchanges identities via two small JSON files instead).

**Already run once (2026) вЂ” passed**: two independent JVM processes, each
with its own `APPDATA` (own identity, own encrypted storage), connected to a
local `--dev` server, exchanged prekey bundles carrying the ML-KEM key,
completed a PQ-hybrid X3DH handshake (confirmed by an OPK being consumed on
the receiving side), exchanged a message and a reply on the resulting Double
Ratchet session, and both decrypted correctly. Server console showed only
the redacted `[MSG] session_init delivered` / `[MSG] message delivered` вЂ”
no fingerprint pairs вЂ” confirming the logging fix works in practice too.

**To re-run** (e.g. after touching `SessionKeyManager.kt`/`CryptoManager.kt`/
`PqCrypto.kt`, or before a release):

```powershell
# Terminal 1 вЂ” local dev server (no TLS)
cd ForEXP
python server.py --dev

# Terminal 2 вЂ” get the classpath once
cd desktop
./gradlew.bat -q printRuntimeClasspath > cp.txt

# Terminal 3 вЂ” Alice
$env:APPDATA = "C:\temp\beacon_alice"
$cp = (Get-Content cp.txt) -join ";"
java -cp $cp com.subrosa.desktop.IntegrationSmokeTestKt alice C:\temp\alice.json C:\temp\bob.json

# Terminal 4 вЂ” Bob (separate window/terminal, same cp)
$env:APPDATA = "C:\temp\beacon_bob"
java -cp $cp com.subrosa.desktop.IntegrationSmokeTestKt bob C:\temp\bob.json C:\temp\alice.json
```

Alice prints `TEST PASSED` and exits 0 on success, or `TEST FAILED` and
exits 1 on timeout/mismatch. This only covers the core 1:1 text path вЂ” it
does **not** substitute for the manual sections above (groups, calls, cover
traffic, cross-platform invites, channels-disabled UI checks).

## 16. Sign-off

- [ ] All boxes above checked with a live server + two Desktop clients.
- [ ] No regression in plain 1:1 messaging, groups, channels, or calls when
      no token pool exists yet (i.e. the direct-fallback path still works).
- [ ] Server console reviewed end-to-end during a full test pass вЂ” confirm no
      `{username} в†’ {to}`-style fingerprint pair ever appears for `message`,
      `session_init`, or `call_*` types (only for `channel_post`, which is a
      documented, deferred gap).

