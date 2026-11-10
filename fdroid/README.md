# F-Droid packaging

`com.subrosa.messenger.yml` is the build recipe for [F-Droid](https://f-droid.org).
F-Droid does **not** accept a prebuilt APK: it compiles the app from this
repository on its own servers and signs the result with its own key. That is the
point of being there. A user then does not have to trust that the maintainer's
machine is clean, or that the published APK corresponds to the published source
— which a SHA-256 on a release page cannot establish, since it only proves the
file was not altered in transit.

F-Droid reads this file from its own repository, `fdroid/fdroiddata`, not from
here. The copy is kept in-tree so it is versioned alongside the code it builds,
and so the next release can be prepared by editing a tracked file rather than
reconstructing it.

## Updating it for a new release

1. Add a new entry under `Builds:` with the new `versionName`, `versionCode`
   and `commit:` (the tag).
2. Update `CurrentVersion` and `CurrentVersionCode`.
3. Open a merge request against `fdroid/fdroiddata` with the file placed at
   `metadata/com.subrosa.messenger.yml`.

`AutoUpdateMode: Version` with `UpdateCheckMode: Tags` means F-Droid picks up
future tags matching `^v[0-9.]+$` on its own, so steps 1–3 are usually only
needed when the build recipe itself has to change.

## Two things the recipe depends on, which must keep working

Both are verified by building in a clean `git worktree` with no
`local.properties`, no keystore and no `app/google-services.json` — the same
conditions F-Droid's builder has. Do this before any release that touches the
build files:

```sh
git worktree add /tmp/fdroid-check HEAD
cd /tmp/fdroid-check
./gradlew assembleFossRelease -PsubrosaAllowUnpinnedRelease=true
```

Expected: `BUILD SUCCESSFUL`, and the artifact named
`app-foss-release-unsigned.apk`.

1. **Release signing is optional.** `app/build.gradle.kts` only installs a
   signing config when the keystore and both passwords are present; otherwise
   the APK is produced unsigned. An unconditional signing config fails on a
   null password and would make the app unbuildable here.

2. **The `-PsubrosaAllowUnpinnedRelease=true` flag is required.** A release
   build with an empty certificate-pin list is refused by design, so that
   "pinning configured but inert" cannot ship. Pinning cannot currently be used
   for the project's own server at all — its TLS is terminated by a CDN whose
   certificate key rotates roughly every 90 days without reuse, so a pin would
   disconnect every installed copy within months. See
   [docs/SECURITY.md](../docs/SECURITY.md#certificate-pinning). Upstream
   releases are built with the same flag; the recipe is not working around a
   check, it is recording the same accepted limitation.

## What inclusion does and does not mean

It establishes that the binary corresponds to this source. It is **not** a
security audit: nobody at F-Droid reviews whether the cryptography is correct.
This project has had no external audit, and the full description shipped to
F-Droid says so in those words.
