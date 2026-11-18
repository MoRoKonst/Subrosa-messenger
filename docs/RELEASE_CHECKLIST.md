# Release checklist

Every item is a command and an expected result. The outputs shown were produced
on 2026-11-19 at `HEAD` = `d45c623` (v1.1.2 + the desktop-installers workflow),
on the maintainer's Windows 11 machine. Nothing in this list signs anything;
signing stays on the maintainer's machine (see `release-checksums.yml`).

Run from the repository root in Git Bash. Paths in this repository contain
Cyrillic and a space, so **always quote them**.

## 1. Clean Android build under F-Droid conditions

F-Droid builds from source with its own key and without `local.properties`,
keystore or `app/google-services.json`. Reproduce that in a worktree:

```bash
git worktree add /tmp/fdroid-check HEAD
cd /tmp/fdroid-check
export ANDROID_HOME="<path of your Android SDK>"   # no local.properties here, so say where the SDK is
./gradlew assembleFossRelease -PsubrosaAllowUnpinnedRelease=true
```

Expected: `BUILD SUCCESSFUL` and
`app/build/outputs/apk/foss/release/app-foss-release-unsigned.apk`.

Result on 2026-11-19: `BUILD SUCCESSFUL in 1m 54s`, `48 actionable tasks: 48 executed`.

Clean-up note (Windows): `git worktree remove` can fail with *Filename too long*
on the build tree. Empty the directory with `robocopy <empty-dir> <worktree> /MIR`
first, then remove it and run `git worktree prune`.

## 2. No leaked log strings in the release APK (S14-1)

The v1.1.0 release APK wrote "who messaged whom, when" to the device log
(`S14-1`); it was found by searching the *published artifact* for strings, not by
reading source. Repeat that search on every release candidate, and run the same
search on a debug build to prove the search can see anything:

```bash
python tools/check_apk_strings.py <release.apk> --absent "ОТПРАВЛЕНО" "ПОЛУЧЕНО" "соответствует отпечатку (получено"
python tools/check_apk_strings.py <debug.apk>   --present "ОТПРАВЛЕНО" "ПОЛУЧЕНО" "соответствует отпечатку (получено"
```

Tool choice: `tools/check_apk_strings.py` reads `classes*.dex` straight out of the
APK with Python's `zipfile`; it needs no Android tooling. (This machine also has
`dexdump.exe` in `build-tools/`, and no `strings`; the Python tool is the one that
was actually used.)

Result on 2026-11-19 (release = worktree build from step 1, debug =
`app-foss-debug.apk`):

```
release: 3 dex file(s)
  [OK] expected absent: 'ОТПРАВЛЕНО' -> 0 occurrence(s)
  [OK] expected absent: 'ПОЛУЧЕНО' -> 0 occurrence(s)
  [OK] expected absent: 'соответствует отпечатку (получено' -> 0 occurrence(s)
debug: 7 dex file(s)
  [OK] expected present: 'ОТПРАВЛЕНО' -> 3 occurrence(s)
  [OK] expected present: 'ПОЛУЧЕНО' -> 3 occurrence(s)
  [OK] expected present: 'соответствует отпечатку (получено' -> 1 occurrence(s)
```

Release and debug give different results, so the check works.

**Two strings are deliberately NOT in the search list.** An earlier version of
this task also listed `anon_token` and `отпечат`. In the release APK they match
legitimate content, so they would fail every release:
`anon_token` occurs in the SharedPreferences key `anon_token_store` and the JSON
field `anon_tokens`; `отпечат` occurs in UI text ("Ваш отпечаток", "сравните
отпечаток при личной встрече…"). They appear in debug and release alike
(`anon_token`: 2 and 2), so they cannot distinguish the two. A check that fails
on every build gets ignored, which is worse than not having it.

Not a discriminator either: `Landroid/util/Log;` is present in the release dex
(2 occurrences, library code), so "no `Log` class" cannot be asserted.

## 3. Version numbers agree

```bash
grep -nE 'versionCode = |versionName = ' app/build.gradle.kts
grep -nE 'versionName:|versionCode:|commit:|CurrentVersion' fdroid/com.subrosa.messenger.yml
git rev-parse 'v1.1.2^{commit}'
git show "$(git rev-parse 'v1.1.2^{commit}')":app/build.gradle.kts | grep -nE 'versionCode = |versionName = '
```

Result on 2026-11-19: `versionCode = 6`, `versionName = "1.1.2"` in
`app/build.gradle.kts:156-157`; the recipe says `versionName: 1.1.2`,
`versionCode: 6`, `commit: f2fd0fef695eaf27d174e91d23cc8d6e1a694db4`,
`CurrentVersion: 1.1.2`, `CurrentVersionCode: 6`; and
`git rev-parse 'v1.1.2^{commit}'` is `f2fd0fef695eaf27d174e91d23cc8d6e1a694db4`,
the same commit, whose `app/build.gradle.kts` also says 6 / 1.1.2.

For the next release: bump `versionCode`/`versionName`, tag, then point the
recipe's `commit:` at the tag's commit. The recipe is checked against the tag by
the `git rev-parse` line above.

## 4. foss has no Google code, gms has

```bash
python tools/check_apk_strings.py <foss-release.apk> --absent com/google/firebase com/google/android/gms
python tools/check_apk_strings.py <gms-release.apk>  --present com/google/firebase com/google/android/gms
```

Result on 2026-11-19: foss worktree build: both absent (0 and 0). gms:
`com/google/firebase` 503, `com/google/android/gms` 939. (The gms APK here is the
existing `app-gms-release.apk` from 2026-11-11, not rebuilt at this `HEAD`;
rebuild it for a real release.)

## 5. Desktop installers

On a machine of the target OS, or via the workflow
`.github/workflows/desktop-installers.yml` (`workflow_dispatch` or a `v*` tag;
unsigned; artifacts are uploaded with a `SHA256SUMS`):

```bash
cd desktop && ./gradlew packageDistributionForCurrentOS
grep -n '^version = ' desktop/build.gradle.kts
```

Result on 2026-11-19, Windows, local run: `BUILD SUCCESSFUL in 58s`;
`Subrosa-1.0.2.exe` (329 394 176 bytes) and `Subrosa-1.0.2.msi` (328 778 376 bytes)
written to `C:\subrosa_desktop_build\compose\binaries\main\{exe,msi}\`;
`desktop/build.gradle.kts` says `version = "1.0.2"`, matching both file names.
`packageDeb` and `packageDmg` are skipped on Windows by design.

The installer's version is the **desktop** version (`1.0.2` today), which is a
separate number from the Android `versionName`.

Known: the Windows build declares the WebRTC native only for `windows-x86_64`
(`desktop/build.gradle.kts`); Linux and macOS installers are built from the same
code but this has never been run on those systems, so **calls on Linux/macOS are
unverified**.

## 6. Checksums before upload

```bash
sha256sum <every artifact you are about to upload> > SHA256SUMS
```

Result on 2026-11-19:

```
58fbe3a1a6bfc849dfc32cd3fc60566d87edaa9a4e1eeea49f947f82cf30597f  app-foss-release-unsigned.apk
a25da3cd7855c64d294b7da7d9000e94ee7b9df7bd46fc7ac0d8e001b9057520  Subrosa-1.0.2.exe
7a4ec34e2dd1559b83fa2e5ccba9cfe7075b2bde9d1ee910f732b58fcf98d74f  Subrosa-1.0.2.msi
```

`release-checksums.yml` attaches `checksums.txt` after publishing; computing it
before upload means you can compare. These hashes are of this one build only:
the project does not claim reproducible builds, and a second build is not
expected to produce the same bytes.

## 7. Manual device check: disappearing messages keep their age (S13-1)

Not automatable here. On a device with the release build:

1. In a chat, set a short disappearing-message timer (e.g. 1 hour), send a message.
2. Open and close the chat every few minutes, and note the displayed time of
   the **older** messages.
3. The timestamps of older messages must stay different from each other and must
   not change when the chat is reopened; the message must disappear on schedule
   even though the chat was opened many times meanwhile.

The regression: `storedToMessage()` did not pass `timestamp`, so the default
`System.currentTimeMillis()` restarted every message's timer on every open.

Status: **not performed** as part of this checklist run (no device attached).

## What is not solved, and the customer must be told

- **The Windows installer is not code-signed.** Without a code-signing
  certificate SmartScreen will warn the user at install time ("Windows protected
  your PC" / unknown publisher). A certificate costs on the order of $200–400 a
  year and is the owner's decision. Tell the customer before they install; do
  not describe the warning as normal for all software.
- **The build is not reproducible**, and CI builds are unsigned.
- **No external security audit has been done.** An F-Droid listing is not one.
