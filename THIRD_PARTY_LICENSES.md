# Third-Party Licenses

*Covers both bundled UI assets (icons, fonts) and the code dependencies compiled into the shipped
Android/Desktop binaries and the server. Added 2026-09-25 — this file previously covered only
assets; the code-dependency section below closes that gap. All license classifications were
verified against the actual `implementation(...)` declarations in `app/build.gradle.kts` /
`desktop/build.gradle.kts` and `Server/requirements.txt` — not reconstructed from memory — and,
where installed locally, against each package's own `License-Expression` metadata
(`pip show <package>`).*

## Assets

### Tabler Icons

The app icon set (`app/src/main/res/drawable/ic_*.xml` and
`desktop/src/main/resources/icons/*.svg`) is derived from
[Tabler Icons](https://tabler.io/icons) (outline style).

- Source: https://github.com/tabler/tabler-icons
- License: MIT

```
MIT License

Copyright (c) 2020-2026 Paweł Kuna

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Phosphor Icons

Additional app icons (`app/src/main/res/drawable/ic_*.xml` and
`desktop/src/main/resources/icons/*.svg`, `fill` weight — converted alongside
the Tabler-derived set above) are derived from
[Phosphor Icons](https://phosphoricons.com/).

- Source: https://github.com/phosphor-icons/homepage
- License: MIT

```
MIT License

Copyright (c) 2020-2024 Phosphor Icons

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Inter

Body/UI typeface (`inter_variable.ttf`, bundled on both Android and
Desktop — `app/src/main/res/font/inter_variable.ttf` and
`desktop/src/main/resources/font/inter_variable.ttf`).

- Source: https://github.com/rsms/inter
- License: SIL Open Font License 1.1
- Copyright 2020 The Inter Project Authors

### Noto Serif JP

Display/heading typeface (`noto_serif_jp_variable.ttf`, bundled on both
Android and Desktop — `app/src/main/res/font/noto_serif_jp_variable.ttf`
and `desktop/src/main/resources/font/noto_serif_jp_variable.ttf`).

- Source: https://fonts.google.com/noto/specimen/Noto+Serif+JP
- License: SIL Open Font License 1.1
- Copyright 2012 Google Inc. All Rights Reserved.

Both fonts are licensed under the same SIL Open Font License 1.1 text
reproduced above for Tabler Icons — see https://scripts.sil.org/OFL for
the canonical license text and FAQ.

## Code Dependencies

Every third-party library compiled into a shipped Android/Desktop binary or installed by the
server, with its license. All entries below are permissive or weak-copyleft and compatible with
distributing this AGPL-3.0 project — see the per-item notes for the two cases (`jave-all-deps`,
Google Play services/Firebase) that need a caveat rather than a flat "compatible."

### Android (`app/build.gradle.kts`)

| Dependency | License | Notes |
|---|---|---|
| AndroidX (`core-ktx`, `lifecycle-runtime-ktx`, `activity-compose`, `appcompat`, `security-crypto`, `biometric`, `exifinterface`, `camera-camera2`/`-lifecycle`/`-view`/`-video`) | Apache-2.0 | Google |
| Jetpack Compose (BOM, `ui`, `ui-graphics`, `ui-tooling-preview`, `material3`, `material-icons-core`) | Apache-2.0 | Google |
| `org.jetbrains.kotlinx:kotlinx-coroutines-android` | Apache-2.0 | JetBrains |
| `com.squareup.okhttp3:okhttp` | Apache-2.0 | Square |
| `com.google.zxing:core` | Apache-2.0 | ZXing project |
| `com.journeyapps:zxing-android-embedded` | Apache-2.0 | wraps ZXing above |
| `org.bouncycastle:bcprov-jdk18on` | Bouncy Castle Licence (MIT-style) | PQ/ML-KEM crypto — see [License texts](#license-texts) below |
| `org.osmdroid:osmdroid-android` | Apache-2.0 | map rendering |
| `io.getstream:stream-webrtc-android` | Apache-2.0 | wraps Google's WebRTC (itself BSD-3-Clause plus per-codec licenses — see the WebRTC project's own `LICENSE_THIRD_PARTY`) |
| `com.google.android.gms:play-services-location` | Google Play Services SDK terms | **Not an OSI license** — this is Google's proprietary Play Services SDK, distributed under the [Play Services SDK Terms of Service](https://developer.android.com/develop/android-services), not a redistributable open-source license. Used only for the optional location-sharing feature. |
| `com.google.firebase:firebase-bom` / `firebase-messaging-ktx` | Firebase Terms of Service | Same category as Play Services above — Google's own SDK terms, not an OSS license. Used only for the optional push-notification path. |
| `app/libs/tor-android-0.4.9.5.aar` | BSD-3-Clause (The Tor Project) | Bundled Tor binary for the opt-in Tor-routing feature (`TorManager.kt`) — packaged by the Guardian Project's `tor-android` build |

### Desktop (`desktop/build.gradle.kts`)

| Dependency | License | Notes |
|---|---|---|
| JetBrains Compose Multiplatform (`compose.desktop.currentOs`, `compose.material3`, `compose.materialIconsExtended`) | Apache-2.0 | JetBrains |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core`/`-swing`, `kotlinx-serialization-json` | Apache-2.0 | JetBrains |
| `com.squareup.okhttp3:okhttp` | Apache-2.0 | Square |
| `org.bouncycastle:bcprov-jdk18on`, `bcpkix-jdk18on` | Bouncy Castle Licence (MIT-style) | same as Android — see [License texts](#license-texts) below |
| `org.json:json` | The JSON License | Permissive, but non-standard — includes the well-known "shall be used for Good, not Evil" clause. Not OSI-approved, but imposes no practical redistribution obligation beyond the standard permissive terms; noted here rather than glossed over. |
| `net.java.dev.jna:jna`, `jna-platform` | Apache-2.0 OR LGPL-2.1 (dual, user's choice) | This project relies on the Apache-2.0 option, consistent with everything else here |
| `dev.onvoid.webrtc:webrtc-java` (+ `windows-x86_64` native classifier) | MIT | Wraps Google's WebRTC (BSD-3-Clause plus per-codec licenses, same as `stream-webrtc-android` above) |
| `ws.schild:jave-all-deps` | LGPL-3.0 (JAVE2 itself) + bundled FFmpeg binaries | **Needs a one-time manual verification, not asserted with full confidence here**: JAVE2 states it ships LGPL-only FFmpeg builds (no GPL-only codecs like `libx264`) specifically to keep the whole artifact LGPL-compatible, but this wasn't independently confirmed by inspecting the actual bundled binary in this pass. LGPL is compatible with combining into an AGPL-3.0 work either way (LGPL is strictly more permissive than GPL for this purpose); the only reason to verify is to get the *exact* attribution right, not because of a distribution blocker. |
| `com.google.zxing:core`, `javase` | Apache-2.0 | ZXing project |

### Server (`Server/requirements.txt`)

| Dependency | License | Notes |
|---|---|---|
| `websockets` | BSD-3-Clause | verified via package metadata (`License-Expression: BSD-3-Clause`) |
| `cryptography` | Apache-2.0 OR BSD-3-Clause (dual, user's choice) | verified via package metadata |
| `miniupnpc` | BSD-style (MiniUPnP project license) | optional — only used for UPnP port forwarding |
| `sqlcipher3-binary` | BSD-style (Zetetic LLC, SQLCipher community edition) | optional — only installed/used when `DB_ENCRYPTION_KEY_HEX` is configured |

Two commented-out-by-default optional extras in `requirements.txt` (`firebase-admin`, `qrcode[pil]`)
are not installed unless an operator explicitly uncomments them, and are not covered here — add them
if either is ever enabled by default.

### License texts

Full text for each license type referenced by name only in the tables above, so every entry has a
retrievable canonical copy without repeating multi-hundred-line blocks per dependency (Apache-2.0
§4(a) and the BSD/MIT family all consider a single reproduced copy sufficient for a work that
bundles multiple same-licensed components).

**Apache License 2.0** — canonical text: https://www.apache.org/licenses/LICENSE-2.0

**BSD-3-Clause** — canonical text: https://opensource.org/license/bsd-3-clause

**Bouncy Castle Licence** (MIT-style, used by `org.bouncycastle:*`) — canonical text:
https://www.bouncycastle.org/licence.html

**The JSON License** (`org.json:json`) — canonical text: https://www.json.org/license.html

**GNU Lesser General Public License v2.1 / v3.0** (JNA's LGPL option, JAVE2's own license) —
canonical text: https://www.gnu.org/licenses/lgpl-3.0.html
