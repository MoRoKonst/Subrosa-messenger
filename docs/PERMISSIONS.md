# Every permission this app asks for, and why

Written 2026-11-19, prompted by the F-Droid submission report, which lists
nine of these as "Minor" findings — that is, things a reviewer wants explained
rather than things that are wrong. A messenger whose whole claim is metadata
protection should be able to answer for each one, so here they are, all of
them, not only the flagged ones.

Checked against the **merged** manifest of a built `fossRelease` APK, not only
against this project's own manifest file — a library can add a permission, and
the merged list is what a user is shown. Each entry was traced to the code
that uses it,
not taken from memory. Two permissions were removed in the same pass, because
nothing used them (see the end).

## The four a reviewer asks about first

| Permission | Why it is here |
|---|---|
| **An accessibility service** (`android.accessibilityservice.AccessibilityService`) | The emergency wipe. Pressing volume-down several times in a row wipes the device's data, and catching a hardware key when the app is not in the foreground is the only thing an accessibility service is used for here. `EmergencyService.onAccessibilityEvent()` is an empty method — the service reads no screen content and no other app's UI. Its configuration was narrowed from `typeAllMask` to a single event type on 2026-11-19, and it declares `canRequestFilterKeyEvents` plus `packageNames="com.subrosa.messenger"`. The wipe itself is off until the user turns it on (`UserStorage.isEmergencyWipeEnabled`). |
| **`QUERY_ALL_PACKAGES`** | One feature: the stalkerware check in `MainActivity`, which looks for other installed apps that hold an accessibility service, device-admin rights, or a granted "draw over other apps" permission, and warns the user about them by name. On Android 11+ the package list is filtered without this permission, which would make the check quietly useless rather than merely incomplete. Nothing about the installed-app list leaves the device: the result is text on a screen. Orbot, the one package looked up by name, is declared separately in a `<queries>` element so it does not depend on this permission at all. |
| **`ACCESS_FINE_LOCATION` / `ACCESS_COARSE_LOCATION`** | Sharing your location in a chat, and nothing else. It is requested at the moment the user taps that button (`ChatScreen`, `GroupChatScreen`) and the app has no background location permission, so it cannot read your position while it is not open. `PlatformLocation` is the project's own replacement for Google's fused provider, written so this build links no Play Services. |
| **`WRITE_EXTERNAL_STORAGE`** | Saving a received photo to the gallery on old Android. It is capped at `android:maxSdkVersion="32"`: on Android 13 and later the app writes through `MediaStore` and the permission is not requested at all. |

## The rest

| Permission | Why |
|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | It is a messenger. The second one is used to notice when connectivity returns. |
| `RECORD_AUDIO` | Voice messages and calls. |
| `CAMERA` | Photos, video messages and video calls. |
| `FOREGROUND_SERVICE` + `_DATA_SYNC`, `_MICROPHONE`, `_CAMERA`, `_PHONE_CALL` | Android 14 requires a declared type per foreground service. Data sync is the message connection, the other three are calls. |
| `POST_NOTIFICATIONS` | Message and call notifications. |
| `USE_FULL_SCREEN_INTENT` | An incoming call has to be able to light up the screen rather than appear as a silent banner. |
| `WAKE_LOCK` | Holding the device awake during a call and while the emergency-wipe service runs. |
| `RECEIVE_BOOT_COMPLETED` | Reconnecting after a reboot (`BootReceiver`). |
| `SCHEDULE_EXACT_ALARM` | Disappearing messages expire at a time, not "sometime soon". |
| `MODIFY_AUDIO_SETTINGS` | Switching between earpiece and speaker during a call. |
| `USE_BIOMETRIC`, `USE_FINGERPRINT` | Unlocking the app with a fingerprint. These two are not in this project's manifest at all — they arrive from `androidx.biometric` and appear in the merged manifest of the built APK, which is why they are listed here: what a user sees on the install screen is the merged list, not ours. |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Offered, not demanded: a screen in the app explains that aggressive battery management kills the connection, and lets the user exempt it. The app works without it, less reliably. |

## Removed in this pass

`DISABLE_KEYGUARD` and `MANAGE_OWN_CALLS` were both declared and used by
nothing: no `KeyguardManager`, no `FLAG_DISMISS_KEYGUARD`, no `TelecomManager`,
no `ConnectionService`, and no manifest attribute that needs either. They are
gone as of 2026-11-19. An unused permission costs a user exactly as much trust
as a used one and buys nothing.

## What is deliberately not here

No `READ_CONTACTS` — the app never reads the device address book; contacts are
added by invite code. No `READ_PHONE_STATE`, no `READ_SMS`, no advertising or
analytics identifiers, and no background location. The `foss` build links no
Google Play Services at all, so the permissions those libraries usually bring
do not appear either; the `gms` build adds Firebase messaging and is not the
one published on F-Droid.
