# Known issue: session hijack via stolen backup + password

Status: **not fixed, not started**. Written down so it isn't lost during the
domain/rebrand/website work.

## Идея (не реализовано): взаимный health-check контактов через N времени тишины

Найдено при разборе дерева "Первый контакт": `sendAnonTokensTo()` чисто
реактивна — срабатывает только сразу после отправки/получения реального
сообщения. Если оба телефона какое-то время молчат (оба офлайн, у обоих
кончились токены, произошла десинхронизация) — ничего не происходит ни с
одной стороны, никто не "спохватывается". `bootstrapChannelFor()` с
ретраями через mailbox существует, но запускается только один раз, в
момент добавления контакта, и никогда больше не срабатывает повторно для
уже установленного канала.

**Логика, уточнённая пользователем** (записано как есть, дизайн, не
реализация):

**Триггер** — не просто "время N без входящих", а конкретнее: входящие
сообщения от контакта прекратились, **и** перестали приходить
подтверждения доставки (`delivered`) на мои собственные исходящие. Это и
есть сигнал "что-то не так" — "связист умер под обстрелом", реагировать
надо, а не молча ждать.

1. По истечении N я, используя свой текущий токен, отправляю контакту
   служебный вопрос-пинг — "у тебя есть токены?" Пинг **тратит токен из
   пула так же, как обычное сообщение** — никакого особого исключения из
   антизлоупотребительных ограничений даже в этой аварийной ситуации
   ("мы всё ещё не можем устраивать день открытых дверей, если автомат
   заклинило").
2. Паддинг под сам пинг — да, добавить; цена копеечная, а сервер не
   должен по размеру/частоте отличать служебный пинг от обычного текста.
3. Если ответа на пинг нет — **одна-единственная** попытка (не цикл):
   через анонимную почту (mailbox) пробуем передать контакту новую
   пачку токенов.
4. Симметрично, сторона с "погибшим связистом" (токены кончились, сама
   отправить `anon_message` не может в принципе, включая ответ на чужой
   пинг): спрашивает у сервера, нет ли для неё пакета токенов — как
   обычно, 20 штук — сверяясь по своему тегу. Если пакета нет — проверяет
   ещё раз через минуту, потом ещё раз через минуту, и на этом
   **сдаётся** (жёсткий лимит попыток, не бесконечный retry).
5. Отдельное требование — **свежесть тега**: mailbox-тег, под которым мы
   ждём этот аварийный депозит, не должен быть тем самым старым тегом из
   изначального инвайт-кода, у которого может истекать TTL. Пока
   обычная (токенная) связь ещё жива, стороны должны периодически
   сообщать друг другу свежий тег заранее — "когда TTL почти сгорел,
   надо по токену сказать свежий", — чтобы к моменту, когда токенная
   связь оборвётся, у обеих сторон уже был актуальный тег для аварийного
   mailbox-обмена, а не протухший.

**Оба открытых вопроса закрыты**:

- **N = 15 минут.** В UI должно быть чётко donесено пользователю: связь
  может сама себя починить, если возникла проблема — подождите (то есть
  не пугать пользователя немедленно при первой же паузе в переписке,
  15 минут — это порог именно для внутреннего механизма, а не сигнал
  тревоги пользователю).
- **Полинг не палит пару.** Рассуждение: сервер в принципе не знает,
  какой тег кому принадлежит и какая пара тегов "разговаривает" друг с
  другом — это и есть весь смысл анонимного mailbox с decoy-паддингом.
  Сервер видит только общий факт "устройство X чаще запрашивает пакеты
  токенов", но не может связать это ни с конкретным контактом, ни даже с
  тем, что "что-то не так" — с его стороны учащённый polling неотличим
  от множества других легитимных причин. К тому же это не постоянный,
  видимый всегда паттерн — это редкий, разовый обходной манёвр для
  проблемы, которая у конкретной пары вообще может ни разу не
  возникнуть за всё время переписки, а не хроническое поведение.

Дизайн эпизода в целом зафиксирован. К реализации не приступали — ждёт
отдельного решения, когда браться.

**Отдельное, но связанное решение** (внесено пользователем прямо в
`SCENARIOS.md`, сценарий "Первый контакт", шаг 4): если канал при первом
контакте не устанавливается спустя 5 минут — повторная попытка депозита
через анонимную почту, не просто бесконечное ожидание исходного. Если и
это не решает проблему автоматически — не бесконечный тихий retry, а
тикет разработчику плюс видимый пользователю сигнал "что-то не так".
Тоже не реализовано, только дизайн.

## Идея (не реализовано): decoy-контакты с реальным трафиком, опциональный модуль

Из пометок в `SCENARIOS.md`, сценарий "Первое сообщение", шаг 1. Проблема
исходной идеи "генерировать поддельные контакты для decoy": фейковый
контакт, за которым никого нет, никогда не участвует в настоящей
переписке — а значит со временем сервер статистически отличает его от
настоящих (см. `SECURITY.md`, пункт 11, "self-created ghost accounts…
rejected as decoys").

**Уточнённое предложение пользователя**: не единичные фейковые контакты
без активности, а **отдельная инфраструктура ботов, которые реально
обмениваются данными друг с другом** — то есть у decoy-аккаунтов
появляется настоящий трафик, и аргумент "никогда не участвует в
переписке" перестаёт работать. **Не обязательный механизм для всех, а
опциональный модуль защиты** — специально для инсталляций, где у
пользователя объективно мало реальных контактов для естественного
прикрытия (классический случай: два журналиста, у каждого из них — по
факту только один реальный собеседник, батч вырождается в размер 1, и
существующая схема "decoy из реальных контактов" защиты не даёт вообще).

**Обсуждение, доведено до финального понимания**:

1. **Реалистичность имитации** — снято с повестки как архитектурная
   проблема. Пользователь: "это вопрос качества реализации, а не
   проблема." Согласен — переносится в разряд "сделать хорошо при
   реализации" (подобрать распределение пауз под живого человека), не
   блокер дизайна.
2. **От кого защищает — два РАЗНЫХ вопроса, важно не путать**:
   - **Структурный уровень**: боты — это просто клиенты, которые
     регистрируют аккаунты и пишут друг другу через **тот же основной
     сервер**, на котором и настоящие пользователи (иначе их fingerprint
     не попадёт в базу, которую опрашивает `get_prekey_bundles_batch`).
     Значит вся переписка ботов **всё равно лежит в базе основного
     сервера** — оператор этого сервера видит её ровно так же, как видит
     переписку настоящих людей. Физическое место, откуда бот
     *подключается* (отдельная VPS, другая юрисдикция — пользователь
     предложил, ~$12/мес), этого не меняет: база одна.
   - **Юридический/операционный уровень**: то, что решает VPS в другой
     юрисдикции — это **не** "видит ли оператор сервера разницу",
     а "можно ли доказать и привлечь к ответственности того, кто
     организовал эту схему." Разделение инфраструктуры по юрисдикциям —
     реальная, рабочая мера операционной безопасности против судебного
     преследования/атрибуции, просто это другой слой защиты, чем
     "видимость на уровне БД".
   - Итог: для self-hosted инсталляции, где пользователь сам себе
     оператор сервера, структурный вопрос не критичен (он и так доверяет
     себе), а юридический уровень (VPS в другой юрисдикции) добавляет
     реальную ценность именно как защита организатора от преследования.
     Оба уровня стоит явно описать в документации по отдельности, не
     смешивая их в одну фразу "защищено".

Дизайн зафиксирован с этими оговорками. К реализации не приступали —
нужно отдельное решение по масштабу задачи (как минимум: где физически
крутятся боты, как включается/выключается модуль, как калибруется
"реалистичность" трафика).

## "Behavior scenarios" — now a real file, see docs/SCENARIOS.md

The idea, explained: holding the full extent of the messenger's behavior
in your head to audit it for holes doesn't scale (first contact, code
exchange, calls, etc. all interacting). Instead: one scenario per user
action, written at the code level (not UI), short, in a file — read it and
try to break it by asking "what if step N fails / is attacker-controlled /
what does the server see here."

Started `docs/SCENARIOS.md` with three fully-traced scenarios (First
contact/invite exchange, First message/X3DH handshake, Voice-video call —
each with numbered code-level steps, failure modes, and known-gap
pointers back to `SECURITY.md`) plus a stub list of the ones still needed:
group create/add/remove, sending photo/file/voice, **backup export/restore
(this file's own namesake issue — probably the single most valuable one to
write out fully next)**, panic wipe/dead man's switch, session hijack /
`session_conflict`, SPK/OPK rotation, and restoring a backup onto a
still-active second device.

### First real find from SCENARIOS.md, fixed same day: legacy invite-code fallback

Building the "First contact" scenario as a branching tree (not a linear
happy path) surfaced a branch that had never been documented: invite codes
in the old pre-mailbox-tag format (`0x02`) fell back to a **direct,
server-visible `get_key`/`request_key`** lookup naming the target
fingerprint explicitly — silently dropping the anonymous-mailbox
guarantee, with zero warning to the user. User's call on seeing it:
**cut the fallback entirely, don't try to preserve it.**

Fixed on both platforms:
- `InviteCodeManager.parseInviteCode()` now rejects anything that isn't
  `FORMAT_VERSION` (0x03) outright — legacy `0x02` codes just fail with
  "invalid or expired," same as any other bad code. `verifyInviteCode()`
  simplified accordingly (mailbox tag is now always present, no more
  dual-version preSign construction).
- Android: removed the `request_key`-branch in `ChatsScreen.kt`'s
  add-contact flow and the corresponding `request_key` intent-extra
  handler in `MessengerService.kt` (dead code once the branch that wrote
  it was gone).
- **Desktop turned out worse than Android**: `InviteCodeManager.acceptInvite()`
  called `WebSocketClient.requestPublicKey()` — the same direct `get_key`
  request — **unconditionally, on every single contact add**, not only
  when a mailbox tag was missing. Removed that call entirely (the invite
  code's embedded, signature-verified public key is already sufficient —
  there was never a real need to also ask the server) and deleted the
  now-unused `requestPublicKey()` function along with the same
  legacy-format parsing/verification code as Android.

Both platforms compile clean. `SCENARIOS.md`'s "First contact" scenario
updated to reflect the removal.

## Quick reference — genuinely still open (as of this pass)

Everything else lower in this file that's marked "done" is done but not
yet live-tested. These are the ones actually unresolved:

- **The original backup-hijack problem itself** (this file's title) — no
  fix started, see "Candidate fixes" below.
- ~~**SMK double-encryption gap**~~ — **fixed** (Android only). SPK, OPK
  pool, PQ KEM private keys, and Double Ratchet session state (whole JSON
  blob per contact) now wrap under SMK the same way the EC identity key
  already did — same `wrapBytes`/`unwrapBytes` pattern, same graceful
  legacy fallback when locked. The stated old reason for not doing this
  ("needed at cold start before login") turned out to be inconsistent —
  the EC identity key has the identical requirement and was already
  wrapped, so the gap was really just an oversight. Handled the real risk
  (a process cold start — reboot, or OS killing the background service —
  landing before the user unlocks in the new process) by making unwrap
  failures degrade gracefully (`tryUnwrapKeyBytes` returns null instead of
  throwing, so `SessionKeyManager.initialize()` can't crash on it) plus a
  `reloadSessionsIfNeeded()` hook wired into both unlock paths in
  `StorageKeyManager.kt` to retry once the user unlocks. Compiles clean.
  **Desktop checked and fixed the same day** — its `SessionKeyManager.kt`
  mirrors Android's almost exactly (same SPK/OPK/PQ-KEM/session-state
  shape via `DesktopStorage.get/put`), and Desktop's `StorageKeyManager`
  already had the same `wrapBytes`/`unwrapBytes` primitives, already used
  for group keys and messages — just never extended to session keys,
  identical oversight. Same fix applied. Note: Desktop's own identity key
  uses a different, intentional mechanism (machine-bound PKCS12 keystore,
  `DesktopKeyStore`) rather than SMK wrapping — not part of this gap, not
  changed. Compiles clean.
- **Identity-rotation ("I think I've been compromised") flow** — no design
  yet, only the notification piece (timestamp + FCM push) is done.
- Tier 5 items (Cloudflare bypass, palette unification, access-list) —
  explicitly deferred, see that section.
- **16 KB page-size native-library compatibility** — Android showed
  "App Compatibility" dialog: 4 bundled `.so` libs aren't 16 KB aligned,
  app runs in compat mode (not broken, just non-compliant for future Play
  Store submissions). Offending libs: `libtor.so` (from the manually
  bundled `app/libs/tor-android-0.4.9.5.aar`, not a maven dep),
  `libjingle_peerconnection_so.so` (from `io.getstream:stream-webrtc-android:1.3.10`),
  `libimage_processing_util_jni.so` (from `androidx.camera:*:1.3.4`),
  `libandroidx.graphics.path.so` (transitive, likely via Compose/Camera).
  Fix = update each dependency to a version built with 16 KB-aligned
  segments (NDK r27+/r28 default); the Tor aar specifically needs a newer
  upstream build or manual repack since it's not pulled from maven. Not
  investigated yet — user's reaction: "какой-то херней андроид заставляет
  заниматься" (not a priority right now, revisit later).

Tier 4 (casing bug, dead man's switch minute tiers) is now done too —
see that section for details. Everything through Tier 4 has been
implemented and compiles; none of it has been live-tested on a device yet.

## Testing checklist — everything from Tiers 1-4 that needs a live device/server pass

Nothing below is a code problem — it's all implemented and compiles. This
is the list of things that were never actually exercised outside the
compiler.

- [ ] **Redeploy `server.py`** to the live server — the `[DEBUG-MAILBOX]`
      log removal only exists in the local repo so far.
- [ ] **Panic-wipe activation flow** — walk through it fresh on a real
      device (App info → restricted settings → Accessibility → enable →
      back to app) and confirm the switch auto-flips on return, and that
      the name shown in Android's Accessibility list now actually matches
      "Subrosa Emergency Wipe" as printed in the in-app instructions.
- [ ] **`sendAnonOrDirect` queue-and-retry** — force a contact's token pool
      to run dry (or catch it naturally) and confirm queued
      reactions/edits/typing/calls actually get delivered once
      `flushPendingAnon` fires, rather than silently disappearing.
- [ ] **Android↔Desktop token exchange** — this was actively broken by the
      `__Subrosa_tokens__` vs `__beacon_tokens__` mismatch before today's
      fix. Confirm a fresh Android↔Desktop pairing successfully bootstraps
      anon tokens now.
- [ ] **Session-hijack FCM push** — log in on a second device, confirm the
      first device receives a visible system notification even fully
      backgrounded/killed, and that the timestamp in the WS-delivered
      notification (when foregrounded) is correct.
- [ ] **New "add server" single-address field** — try a bare host, a
      `host:port`, and a full `wss://host:port` string, confirm all three
      parse to the right host/port.
- [ ] **Dead man's switch 15/30-minute tiers** — confirm the alarm
      actually fires at the shorter interval and triggers a real wipe, not
      just that the UI accepts the selection.
- [ ] **Visual sanity check on `SubrosaColors` rename** — purely a rename,
      but worth confirming the app still renders with the correct
      NAVY/DARK/LIGHT theme colors after touching 19 files by find-replace.
- [ ] **Wipe audit re-confirmation** — no code changed here, but given how
      critical this is, worth an actual panic/dead-man wipe on a real
      device to visually confirm nothing survives, not just trusting the
      code-read audit.

## The problem

Identity in this system is entirely defined by possession of the account's
EC private key (`fingerprint = SHA-256(public_key)[:8]`, proven via ECDSA
challenge-response on connect — see `server.py` register handler). The
backup export contains that private key, encrypted with AES-256-GCM under a
key derived via PBKDF2 (100,000 iterations) from a user-chosen password.

If someone obtains **both** the backup file and its password, they can
restore the identity on their own device and use it exactly as the real
owner would — send messages as them, receive messages meant for them, and
so on. There is no second factor; the key *is* the identity.

Realistic ways this happens without any sophisticated attack:

- A trusted person (partner, colleague) who already knows the backup
  password (shared devices, told out loud, written down) copies the backup
  file.
- A password manager left unlocked on a shared/work PC.
- Physical access to the device while the owner is asleep, unavailable,
  hospitalized, etc. — no exotic attacker required.

## What currently happens (server.py, register handler)

Only one `device_id` may be registered for a given fingerprint at a time.
When a second device registers under the same identity:

1. The server sends `{"type": "session_conflict"}` to the **previously
   connected** WebSocket and force-closes it.
2. The new device becomes the active session.

This is symmetric — whoever registers most recently wins. If the real owner
opens the app again after being kicked, *they* re-take the session and kick
the intruder back out. No knowledge of who the intruder was is required to
do this.

## Why this doesn't actually solve the problem

- It's a tug-of-war, not a fix. As long as the intruder still holds the
  private key, they can re-register at any time.
- The only real remedy once a key is suspected compromised is full identity
  rotation (new keypair → new fingerprint), which breaks verification with
  every existing contact — comparable to Signal's "safety number changed"
  flow. There is no way to "revoke" a private key that's already out in the
  wild; you can only replace the identity built on it.
- `session_conflict` currently carries no information — no timestamp, no
  device/network hint. The legitimate user has no way to tell *when* it
  happened or whether it might have been an innocent explanation (a second
  install of their own).
- The notification only reaches the client over an already-open WebSocket.
  If the app isn't in the foreground/connected when the conflict happens
  (asleep, phone off, hospital, etc.), the user may not learn about it for
  a long time.

## Candidate fixes (none implemented yet)

1. **Push the `session_conflict` event, not just WebSocket-deliver it.**
   `MyFirebaseMessagingService` already exists for push — mirror the kick
   notification through FCM so it reaches the user even when the app isn't
   open or connected.
2. **Attach minimal context to the conflict event** — at least a timestamp,
   ideally coarse device/network info (not enough to be its own privacy
   leak, but enough that the user isn't reasoning in a total vacuum).
3. **Build an explicit "I think I've been compromised" flow** in-app that
   walks the user through identity rotation (generate new keypair, notify
   contacts their fingerprint changed) rather than expecting them to
   improvise that response on their own.
4. Open question, not yet designed: is there a lower-cost intermediate step
   between "do nothing" and "rotate your entire identity" — e.g. some way
   to invalidate a specific backup export without regenerating the identity
   key itself? Worth exploring before defaulting to full rotation as the
   only answer. **Candidate answer, already sketched below (line ~361 in
   this file, old note): TOTP 2FA on top of the backup password** — the
   file+password alone stops being sufficient to import, closing exactly
   this gap without touching identity rotation at all. See that note.

## Найдено при разборе сценария "Экспорт/восстановление бэкапа" (SCENARIOS.md)

Полное дерево — в `SCENARIOS.md`. Кратко, что нового нашли, читая код
`BackupManager.kt`/`BackupScreen.kt` построчно (раньше эта часть кода не
разбиралась так подробно):

1. **Функциональный баг, не только дизайн-вопрос**: бэкап переносит
   identity-ключ, но не переносит состояние Double Ratchet-сессий
   (`SessionKeyManager`), анон-токены, mailbox-теги. После восстановления
   бэкапа на новом устройстве входящие сообщения от контактов, у которых
   сессия ещё привязана к состоянию *старого* устройства, скорее всего не
   расшифруются, пока не пройдёт свежий handshake. Не проверено вживую —
   надо протестировать реальным восстановлением и посмотреть, что
   происходит на первом сообщении после.
   **Предложенное решение**: в проекте уже есть готовый паттерн для
   ровно такой ситуации — `consumePendingPqMigrationContacts()`
   (используется при PQ-апгрейде): удаляет локальные сессии со всеми
   контактами и возвращает их список, чтобы вызывающий код разослал им
   `session_reset`. Применить тот же паттерн сразу после успешного
   импорта бэкапа — разослать `session_reset` всем восстановленным
   контактам, чтобы следующее сообщение автоматически инициировало
   свежий handshake вместо тихой потери. Не реализовано, только план.
2. **Смешение identity при импорте на уже используемое устройство**:
   экран бэкапа доступен только уже залогиненному устройству (из Profile,
   не из онбординга). Импорт перезаписывает `UserStorage.userId` на
   identity из бэкапа, но не трогает уже сохранённые контакты/сообщения
   старой identity этого устройства (`addContact` и т.п. только
   добавляют, не заменяют). Не продумано, что видит пользователь после
   такого импорта.
3. **UX при заблокированном SMK во время экспорта**: `unwrapBytes()`
   бросает сырое исключение ("StorageKeyManager is locked"), которое
   долетает до пользователя как есть, без понятной подсказки "сначала
   разблокируйте приложение" (в отличие от аналогичного отказа на
   импорте, где сообщение уже человекочитаемое).
   **Предложенное решение**: явная проверка `StorageKeyManager.isUnlocked`
   в начале `exportBackup()`, до попытки развернуть ключ, с тем же
   понятным сообщением, что уже показывается на импорте. Дёшево
   чинится, не реализовано.
4. Повторный импорт того же файла бэкапа, вероятно, дублирует всю
   переписку — ID сообщений в бэкап не попадают, при восстановлении
   генерируются заново.

## Найдено при разборе сценария "Группы" (SCENARIOS.md) — реальный, воспроизводимый баг

Не гипотеза, не дизайн-вопрос — построчно прочитан код
`GroupManager.kt`/`MessengerService.kt`/`CreateGroupScreen.kt`/
`GroupInfoScreen.kt` и прослежено, что реально уходит по сети.

**Суть**: пакет `group_create` (и при создании группы, и при
добавлении нового участника позже) **не содержит поля `members` вообще**
— только `group_id`/`group_name`/`group_avatar`/`encrypted_group_key`/
`signature`. Получатель, у которого такой группы ещё нет, создаёт её
локально с `members = listOf(from, username)` — то есть **только
пригласивший + сам получатель**, что бы ни было на самом деле в группе.

**Только у создателя группы есть полный и правильный список
участников** — он единственный, кто изначально сохраняет
`members = allMembers.toList()` (`CreateGroupScreen.kt:224-234`). Все
остальные видят группу как разговор вдвоём "я и тот, кто позвал".

**Как это ломает реальную переписку**: `sendGroupMessage`/
`sendGroupReaction`/`rotateGroupKey` рассылают по **локальному**
`group.members` отправителя. Значит: сообщение от создателя доходит
всем (у него список полный); сообщение от любого другого участника
доходит **только создателю** — остальные участники никогда его не
получат, хотя формально состоят в группе. Асимметрично и воспроизводимо
для любой группы из 3+ человек.

**При добавлении нового участника позже** (`GroupInfoScreen.kt:455`,
`addGroupMember`) — рассылка `group_create` уходит **только новому
участнику**. Существующие участники не уведомляются о пополнении
состава вообще никаким пакетом — их локальные списки остаются как были,
теперь ещё и без нового человека.

**При удалении участника** (`notifyMemberRemoved`) — этот путь **уже
устроен правильно**: рассылка идёт всем оставшимся участникам, не
только удаляемому (это и есть то, что чинили раньше как "баг ротации
ключа при удалении", `SECURITY.md`). Именно поэтому баг с добавлением
не поймали тогда — правили ветку удаления, а не добавления, это разные
куски кода с разной (и на поверку разной по качеству) логикой рассылки.

**Предложенное решение, не реализовано**:
1. Включить подписанный полный `members`/`admins` прямо в пакет
   `group_create`, чтобы получатель сразу инициализировал правильный
   ростер, а не собирал его как `[from, username]`.
2. При добавлении участника — разослать уведомление о пополнении
   **всем существующим участникам**, симметрично тому, как уже
   работает удаление.
3. На будущее — периодическая идемпотентная сверка полного ростера
   от создателя/админа, на случай потери отдельных уведомлений
   (то же rationale, что у health-check идеи для 1:1 контактов выше).

Побочно найдено: `group_reaction` не проверяет подпись отправителя
вообще (в отличие от `group_message`/`group_create`) — не исследовано,
осознанное это решение или недосмотр.

## Найдено при разборе сценария "Panic wipe / dead man's switch" (SCENARIOS.md)

Полное дерево — в `SCENARIOS.md`. Главное новое: `WipeManager.Level.SOFT`
подтверждён как **мёртвый код** — существует в `enum`/`when`, но ни один
из трёх триггеров panic wipe и ни dead man's switch на него не выходят
(только `HARD`/`wipeForDecoyKeepAlive`/`NUCLEAR`). Не решено, оставлять
как задел или выпилить.

Подтверждена (уже была отмечена раньше в этом файле как личный опыт
разработчика — "я сам запутался, включая это") — многошаговая активация
триггера 5×громкость-вниз: Android 13+ по умолчанию блокирует
Accessibility для сайдлоуженных приложений через "restricted settings",
поэтому включение требует: настройки приложения → снять ограничение →
назад → настройки Accessibility → включить сервис → назад в мессенджер
→ включить тумблер. У тумблера в Profile есть защита от рассинхрона
(сверяется с реальным системным состоянием при каждом возврате на
экран), но сам процесс включения остаётся многошаговым — в основном
из-за ограничений ОС, не только дизайна приложения.

Не решено (тоже в дереве): что происходит с dead man's switch, если
телефон выключен дольше, чем интервал + grace period — сработает ли
будильник после включения, или защита полагается только на резервную
проверку при следующем открытии приложения (`MainActivity.onResume()`).

## Найдено при разборе сценария "Фото/файл/голосовое" (SCENARIOS.md) — новая утечка метаданных

Полное дерево — в `SCENARIOS.md`. Главная находка, не задокументированная
нигде раньше: в каждом пакете `file_chunk` (`MessengerService.kt:2861`)
поле **`file_name` передаётся в открытом виде**, отдельно от
зашифрованного поля `data`. Пакет заворачивается в `anon_message` (это
даёт анонимность по маршруту/токену), но сам JSON-payload шифруется не
целиком — только содержимое файла. Значит сервер, даже при полностью
анонимной доставке, видит **оригинальное имя файла в чистом виде** на
каждой передаче — а имя файла само по себе может быть чувствительным
("compromat_source_ivanov.pdf"). Обфускация имени на диске (сделанная в
этой же сессии раньше) защищает только локальное хранение — не сам факт,
что имя ушло по сети открытым текстом.

Для сравнения: у `image_chunk` такой утечки нет (у фото нет имени файла
как атрибута), у `voice`-пакета есть похожая, но менее чувствительная
утечка — `duration` (секунды записи) тоже в открытом виде.

**Предложенное решение, не реализовано**: либо не посылать оригинальное
имя вообще (заменить на generic-плейсхолдер + расширение, выводимое из
MIME — аналогично уже сделанной обфускации имени на диске), либо
шифровать это поле тем же гибридным ключом, что и `data`.

Также подтверждена (уже была известна из более раннего аудита,
`SECURITY.md`) незакрытая проблема: `sendVoice` при отсутствии ключа
получателя кладёт неудавшуюся отправку в **текстовую** очередь ретраев
(`pendingSessionMessages`), закодировав как строку
`"__voice__|id|duration|base64"` — при повторной отправке получатель
увидит этот текст как обычное сообщение, не голосовое. Нужна отдельная
voice-очередь по аналогии с `pendingImages`/`pendingFileSends`.

## Найдено при разборе сценария "Ротация SPK/OPK" (SCENARIOS.md) — асимметрия платформ

Полное дерево — в `SCENARIOS.md`. Главная находка: сервер, когда у
пользователя на сервере остаётся меньше `OPK_LOW_WATERMARK` (5)
одноразовых prekey'ев, сам проактивно шлёт владельцу
`{"type": "prekey_bundle_request"}`, чтобы тот republish'нул бандл со
свежими OPK. **Desktop обрабатывает это правильно**
(`WebSocketClient.kt:1375` — republish сразу). **Android не обрабатывает
этот тип сообщения вообще** — ни одного вхождения `prekey_bundle_request`
в Android-коде проекта. Сигнал сервера тихо падает в default-ветку
диспетчера входящих сообщений.

Практическое следствие: на Android бандл republish'ится только при
новом WS-подключении (`publishPrekeyBundle()` вызывается один раз сразу
после коннекта, не периодически), так что окно между "OPK на сервере
кончились" и "следующий реконнект" — это окно, где новые X3DH-рукопожатия
с этим пользователем идут по уже существующему в протоколе fallback
"без OPK" (деградация одного DH-компонента forward secrecy, не потеря
шифрования). Не катастрофа, но однозначно не то поведение, которое
сервер пытается вызвать сигналом, и не то, что уже правильно работает на
Desktop.

**Предложенное решение, дёшево, не реализовано**: добавить в диспетчер
`MessengerService.kt` ветку `"prekey_bundle_request" ->
publishPrekeyBundle()`, зеркально уже существующей Desktop-реализации.
Минимальное, локализованное изменение — правильный код-образец уже есть
в проекте, просто скопировать паттерн.

Второстепенно отмечено: и ротация SPK (раз в 7 дней), и republish
бандла проверяются только в момент событий подключения/инициализации
(`initialize()`/`reloadSessionsIfNeeded()`), не на независимом фоновом
таймере — работает на практике благодаря частым реконнектам мобильной
сети, но это не спроектированная гарантия, а побочный эффект.

## Найдено при разборе сценария "Угон сессии" (SCENARIOS.md) — "война переподключений"

Полное дерево — в `SCENARIOS.md`. Главная находка: `connect()` в
`MessengerService.kt` — самоподдерживающийся цикл, который при потере
`isConnected` безусловно переподключается через 3 секунды, **не
различая причину разрыва**. Обычный обрыв связи и получение
`session_conflict` (вытеснение сервером из-за другого устройства с тем
же fingerprint) обрабатываются этим циклом одинаково.

Следствие: если устройство A вытесняет устройство B (кража
identity/бэкапа, восстановление на другом телефоне и т.п.), B через
~3 секунды автоматически переподключается тем же кодом — и, поскольку
сервер отдаёт слот тому, кто подключился последним, без понятия
"легитимный владелец", **B тут же вытесняет A обратно**. Если A тоже
настроено на автопереподключение — цикл повторяется бесконечно,
устройства попеременно выбивают друг друга, пока один из них не
перестанет пытаться (закрытие приложения, выключение телефона).

Это не ухудшает саму компрометацию (атакующий, получивший identity, уже
имеет полный доступ независимо от исхода войны переподключений) — но
не спроектировано, создаёт шум/нагрузку без предела попыток. Побочный
плюс, тоже случайный, а не задуманный: повторяющиеся уведомления
`session_conflict` — более заметный сигнал тревоги для легитимного
пользователя, чем один разовый кик.

**Предложенное решение, не реализовано**: при получении именно
`session_conflict` (не при обычном разрыве связи) — не переподключаться
автоматически тем же путём; вместо этого требовать явного действия
пользователя (экран "кто-то ещё вошёл в ваш аккаунт") прежде чем снова
слать `register`.

Также подтверждено (уже отмечено раньше в этом файле, "Candidate
fixes", пункт 3): у вытесненного устройства нет никакого управляемого
флоу "я думаю, меня скомпрометировали" — только уведомление, без
кнопки отзыва identity/вынужденной ротации ключа.

## Найдено при разборе сценария "Восстановление бэкапа на втором активном устройстве" (SCENARIOS.md) — восьмой и последний сценарий этого раунда

Полное дерево — в `SCENARIOS.md`. Главная находка: импорт бэкапа меняет
identity на диске (`UserStorage.setUserId`, приватный ключ в
`EncryptedSharedPreferences`) синхронно и сразу, но если
`MessengerService` уже запущен в момент импорта (устройство было активно
залогинено) — **сервис ничего не знает об изменении**. `username`
(поле `from` в каждом исходящем пакете, идентичность текущего
WS-соединения) кэшируется один раз за вызов `onStartCommand()` и не
пересчитывается импортом. При этом `CryptoManager.sign()`/`encrypt()`
читают ключ из хранилища без кэширования при каждом вызове — то есть
сразу начинают использовать **новый** импортированный ключ.

Результат — окно рассинхрона: исходящие пакеты несут `from: <старый
fingerprint>`, но подписаны **новым** ключом. Получатель, проверяя
подпись против публичного ключа старого fingerprint'а, должен получить
несовпадение — сообщения в этом окне, вероятно, либо не проходят
проверку подписи на приёме, либо создают путаницу с тем, кто реальный
отправитель. Не проверено вживую, только прослежено по коду.

**Предложенное решение, не реализовано**: после успешного импорта
бэкапа — принудительно перезапустить `MessengerService` (или хотя бы
форсировать повторную идентити-инициализацию), не полагаться на то, что
пользователь сам когда-нибудь перезапустит приложение.

Также отмечено, не продумано: судьба старых Double Ratchet-сессий этого
устройства (под identity, что была ДО импорта) — `importBackup()` их
не трогает вообще, они просто продолжают висеть в памяти под identity,
которой формально больше нет в хранилище.

**Этим восьмым сценарием список-заглушка в `SCENARIOS.md` закрыт
полностью** — все запланированные сценарии написаны (первый контакт,
первое сообщение, звонок, бэкап/восстановление, группы, panic
wipe/dead man's switch, фото/файл/голосовое, ротация SPK/OPK, угон
сессии, восстановление на активном устройстве).

## Not in scope for this note

Local device compromise (someone unlocks your phone directly) is a
different, mostly-already-covered threat — see the panic wipe / dead man's
switch mechanisms in SECURITY.md. This note is specifically about the
backup-export path, where the "device" the attacker acts from is their own,
not the victim's.

Пишу по русски
Я задумался о том, как защитить условный клиент впс, что если добавить 2FA с работой по TOTP, секрет хранить в KeyPass или подобном, наверное с указанием, что не через онлайн менеджеры
Для чего? Я допустим захожу по файлу и паролю примера ( не реальный пароль) 9et;hWC{07rxo;?KA<c'BR}*|*zn+Pr3o}_jWF+,9YQLo!FeB!*jq~pe{N4l4:j$}Mp*vy:Ha!w~#\{.~!O-%Lo-bx.oS=&}9fkFxMq|eNXtvmiOv>u^Og7fVvKBi1QV. Храню в шифрованном файле keypass, вот, но как доп защита TOTP

я ещё думал про допуск только по привязке к железу, но это добавляет точек отказа, что сильно бьет по всей идее, думал добавить опционально доступ к серверу, в смысле доступ клиента телефона только по допуску и списку, но это добавит геморроя и не будет просто, по сути сейчас что надо - это прописать адрес сервера, что вообще то тоже муторно, потому что ты пишешь в окно из трех форм, куда что писать ещё подумать надо

В клиенте на андроиде есть функция удаления при нажатии 5 раз кнопку убавить и через трансляцию аудио мы считываем нажатия даже на заблокированном экране, но для включения функции надо зайти в настройки по ссылке или напрямую, ссылка из приложения, дальше включить заблокированный функционал, дальше зайти обратно,  перейти по другйо ссылке в настрйоки и включить доступ к этой функции, потом зайти в мессенджер и окончательно включить функцию
но знаешь что? я пока включал сам запутался, а я автор этой идеи, в смысле я придумал эту функцию добавить. Вот, пока не забыл, надо проверить все типы вайпов, что они стирают и стирают ли то, что должны, в основном все экстренные меры должны тереть приложение до уровня "никогда не было данных" только сам мессенджер остается, как новенький

И добавить новые таймеры поменьше в функции уровня dead man switch
Ещё надо проверить шифрование на телефоне, раз у нас двойной уровень, то мне надо понять, защищает ли оно все данные или есть утечки

## Server-side cleanup still pending (from the rebrand/domain session)

- `ForEXP/server.py` still has active `[DEBUG-MAILBOX]` `print()` statements
  (mailbox put/fetch handlers) that log the caller's fingerprint in plaintext
  to server logs on disk. Leftover from call-flow debugging earlier this
  project; promised removal once live testing was confirmed done — still
  not removed.
- Cloudflare WebSocket-proxying is still broken for `subrosamessenger.com`
  (every real WS upgrade gets rejected with a generic Cloudflare-branded 400
  before reaching origin — root cause not found, see the troubleshooting
  section added to `docs/DEPLOY.md`). Currently bypassed with `api.` on
  DNS-only/grey-cloud + relaxed nginx `allow` list — this **exposes the real
  origin IP directly and drops Cloudflare's WAF/DDoS layer for that
  endpoint**. `ServerManager.kt` also has a temporary `:8443` direct-port
  override (task #52) that needs reverting once Cloudflare proxying works
  again.

## Docs vs. code have diverged on call-signaling anonymization

`docs/SECURITY.md` item 18 currently says real SDP/ICE signaling
(`call_offer`/`answer`/`ice`) was reverted to direct addressing after live
testing showed anonymized delivery couldn't tolerate the packet loss, and
that only the `call_request_audio/video`/`call_response` ring phase stays
anonymized.

The actual code (`MessengerService.kt`, the `call_signal` intent handler,
~line 685) does not match that description: every non-group-call signal
type — including `call_offer`, `call_answer`, `call_ice`, and `call_end` —
is routed through the same `sendAnonOrDirect()` call as everything else.
There is no special-cased direct-only path for SDP/ICE. Only
`call_group_*` types are unconditionally direct (`sendWs`, no anon
attempt).

So in the shipped code, 1:1 call signaling (including the real SDP/ICE
exchange, not just the ring phase) **is** anonymized when a token is
available, with `sendAnonOrDirect`'s null-token fallback to direct as the
only path where the server actually sees the real fingerprint pair for a
call. `call_end` additionally has a P2P DataChannel "bye" as its true
primary path, bypassing the server entirely when available.

**To do**: rewrite `docs/SECURITY.md` item 18 to describe what the code
actually does, not the earlier revert-then-re-fix history that no longer
reflects the final state.

## Decided: remove `sendAnonOrDirect`'s direct fallback entirely

`sendAnonOrDirect()` (`MessengerService.kt:2618`) is the single shared
send path for nearly everything — reactions, edits, typing, read receipts,
voice notes, `session_reset`, `group_invite_accepted`, and all 1:1 call
signaling. Its logic:

```kotlin
val token = AnonTokenManager.consumeNextContactToken(this, to)
if (token != null) {
    // wrap in anon_message, send anonymized
} else {
    sendWs(packet.toString())  // <-- falls back to DIRECT, fingerprint-addressed
}
```

**Decision: the `else` branch (direct/fingerprint-addressed fallback) gets
cut, full stop.** Rationale (verbatim reasoning from the person who owns
this call): if the product's whole premise is a threat model with no
trusted party on the wire — the server is the first suspect, not a
friend — then a code path that quietly says "fine, come through
unprotected" whenever the anonymization layer runs dry isn't a pragmatic
compromise, it's a self-inflicted hole in the wall we're supposed to be
building. An anonymity system with an unconditional non-anonymous fallback
provides an *illusion* of the property it claims, not the property itself.

**Replacement, when the token pool is empty**: retry via the anonymous
mailbox (`mailbox_put`/`mailbox_fetch`) instead of falling back to direct
addressing — reusing the same anonymous bootstrap mechanism the app
already relies on elsewhere (invite-code mailbox tags, decoy-padded
fetches), rather than inventing a new mechanism. Concretely: when
`consumeNextContactToken` returns null, don't send at all yet — queue the
packet and retry through the mailbox path (or wait for the token pool to
refill and retry `sendAnonOrDirect`, whichever is more natural given how
`AnonTokenManager`'s refill logic already works), instead of the current
unconditional `sendWs(packet.toString())`.

**Not yet implemented** — this is a real code change across every call
site of `sendAnonOrDirect` (reactions, edits, typing, read receipts, voice,
session_reset, group_invite_accepted, and all 1:1 call signaling), needs
its own pass when we get to it. Same change applies to the Desktop client's
mirror of this logic in `WebSocketClient.kt`.

## Casing bug from the Beacon→Subrosa rename: `subrosaColors` should be `SubrosaColors`

In `app/src/main/java/com/example/test/ui/theme/SubrosaColors.kt`, the data
class and several `val`s ended up lowercase-first after the rename pass —
`subrosaColors` (data class), `NavysubrosaColors`, `DarksubrosaColors`,
`LightsubrosaColors`, `LocalsubrosaColors`, `subrosaColorsFor` — should all
be PascalCase (`SubrosaColors`, `NavySubrosaColors`, etc.). Root cause: an
earlier PowerShell rename script ran a lowercase-first replace
(`'beaconColors' -replace 'subrosaColors'`) before the PascalCase one
(`'BeaconColors' -replace 'SubrosaColors'`), and PowerShell's `-replace` is
case-insensitive by default — so the lowercase rule silently consumed the
PascalCase occurrences too, leaving nothing for the second rule to fix.
Compiles fine (Kotlin doesn't enforce class-name casing), so it wasn't
caught by the build — purely a naming-convention violation, cosmetic, no
functional impact. Low priority, batch with other cleanup later.

## App icon: new wax-seal/rose mark, plus a broader palette question

Decided: replace the Android launcher icon (and do the same for Desktop)
with the new wax-seal/rose emblem the user designed — burgundy/maroon with
a detailed rose center and a geometric star border. Not yet applied to
either client.

Raised alongside it: the app currently has **three unrelated accent
colors floating around** with nothing tying them together —
- Website (`docs`/`v3` site): teal `#55B5A8`
- App UI (`SubrosaColors.kt`, all three built-in themes — NAVY/DARK/LIGHT):
  cyan `#00E5FF` accent on a navy/gray/white base respectively (this
  predates even the Beacon name, inherited as-is through the rename, never
  matched "Beacon" branding either)
- New app icon: burgundy/rose

Decided **for now**: leave the in-app theme colors (`NavySubrosaColors` /
`DarkSubrosaColors` / `LightSubrosaColors`) untouched, ship the new icon on
its own — icon-vs-in-app-chrome mismatch is normal practice, not a
blocker. A full palette unification (icon + in-app theme + website all
sharing one accent direction, presumably something in the wax-seal/rose
family) is a real reskin — 3 themes × ~18 colors each, needs a contrast/
accessibility pass on every screen since text/border colors are tuned
against the current cyan-on-navy base, not a drop-in swap. Deliberately
deferred to its own pass, not bundled with the icon swap.

**To do, in order, whenever this gets picked back up**:
1. Fix the `subrosaColors` casing bug above (cheap, do first, unrelated to
   the rest but touches the same file)
2. Swap the Android launcher icon + Desktop app icon to the new rose mark
3. Decide on and execute the full palette unification (icon + in-app theme
   + website), including the accessibility/contrast re-check this implies

## Full prioritized plan (everything in this file, sorted: critical+easy → harder/less critical)

Written up so the order doesn't have to be held in memory across sessions.
Re-derived from every item above plus the loose notes further up this
file.

### Tier 1 — critical, easy, do first

1. ~~**Remove `[DEBUG-MAILBOX]` print statements from `server.py`.**~~ —
   **done**. All four print statements removed from the `mailbox_put`/
   `mailbox_fetch` handlers. Verified no `DEBUG-MAILBOX`/`DEBUG-BOOTSTRAP`
   strings remain in `server.py`, syntax-checked clean. Needs redeploying
   to the live server to take effect (edit was made locally in the repo).
2. ~~**Audit every wipe type**~~ — **done, no gaps found in reachable
   paths**. `WipeManager.kt` has three levels: `SOFT` (sessions + cache
   only — but it's dead code, never actually invoked anywhere in the app,
   confirmed by grep), `HARD` (wipes `shared_prefs/`, `filesDir`,
   `cacheDir`, `databases/`, `app_webview/`, `no_backup/`, external files,
   plus AndroidKeyStore aliases and `CryptoManager`'s own key via its
   dedicated `deleteKeys()` — comprehensive since `shared_prefs/` is wiped
   as a whole directory rather than an enumerated file list), and
   `NUCLEAR` (calls the OS-level `ActivityManager.clearApplicationUserData()`,
   falling back to `HARD` if that fails). Confirmed trigger mapping: dead
   man's switch fires → `NUCLEAR`; panic button → `HARD` (or
   `wipeForDecoyKeepAlive`, same coverage, if decoy mode is on — the
   decoy variant intentionally *keeps* the username/password-hash/
   calculator-disguise flags to drive the fake login screen, which is
   correct, not a leak of actual message content). No missing-data gap
   found in the paths that are actually reachable.
3. ~~**Fix the panic-wipe activation UX flow**~~ — **partially fixed,
   root cause found**. The confusion wasn't just "too many screens" — two
   real bugs were causing it:
   - `accessibility_service_config.xml` still had
     `android:packageNames="com.bcon.messenger"` from before the rebrand —
     stale, didn't match the actual current applicationId
     (`com.subrosa.messenger`). Fixed.
   - The in-app instructions told the user to look for **"B-CON
     Emergency"** in Android's system Accessibility settings list — but
     the service had no explicit `android:label`, so Android was actually
     displaying it under the generic app name instead. The name the user
     was told to find literally didn't appear anywhere in the real system
     UI. Added `android:label="@string/emergency_service_label"` ("Subrosa
     Emergency Wipe") to the service in the manifest, and updated the
     dialog instructions (RU and EN) to reference that same name, so
     what's printed in-app now matches what actually shows up in Android's
     Accessibility list.
   - The dialog's step-by-step instructions (App info → "Allow restricted
     settings" via the overflow menu → Accessibility settings → enable,
     specific to Android 13+'s restricted-settings requirement) were
     already accurate and reasonably clear — that part didn't need a
     rewrite, just the name mismatch was actively misleading. The
     multi-hop nature itself (App Info → Accessibility settings → back to
     the app) is an Android OS requirement for accessibility services,
     not something we can shortcut.
   - Build verified (`compileDebugKotlin` succeeded) after these changes.
   - Not done: no live-device retest yet that the full flow now works
     end-to-end without confusion — worth doing before considering this
     fully closed.

### Tier 2 — critical, harder, do next

4. ~~**Remove `sendAnonOrDirect`'s direct fallback**~~ — **done, both
   platforms**. Implementation ended up simpler than a bespoke
   generic-mailbox payload format for every packet type: when
   `consumeNextContactToken` returns null, the packet is now queued
   in-memory (`pendingAnonPackets`, per-contact) and `sendAnonTokensTo(to)`
   is kicked off, which already cascades to mailbox bootstrap internally
   when needed (existing code, unchanged). The queue drains via
   `flushPendingAnon(to)`, called right after both places that call
   `AnonTokenManager.addContactTokens` (token-exchange message handler and
   mailbox-result handler) on each platform. No more unconditional
   `sendWs(packet.toString())` fallback on either client. Both
   `compileDebugKotlin` (Android) and `compileKotlin` (Desktop) verified
   green.

   **Found and fixed a real cross-platform protocol bug while doing this**:
   Desktop's `WebSocketClient.kt` had the token-exchange wire marker as
   `"__Subrosa_tokens__:"` — a casing-bug leftover from the same
   rename-script issue as the `subrosaColors` bug above, except this one
   is **not cosmetic** — it's a wire-protocol string, and Android sends/
   expects `"__beacon_tokens__:"` (deliberately left untouched during the
   rename, since it's on-the-wire, not display text). Desktop would never
   have recognized a token-exchange message from Android, and Android
   would never have recognized one from Desktop, silently breaking anon
   token bootstrap between the two clients. Fixed to `"__beacon_tokens__:"`
   on both read and write sides in `WebSocketClient.kt`, plus one stray
   log-message string referencing the wrong name.

   **Not yet done**: no live two-device test that the queue-and-retry
   behavior actually recovers correctly once tokens refill (build success
   only confirms it compiles, not that the runtime behavior is right) —
   worth testing before considering this fully closed, same caveat as
   item 3 above.
5. ~~**Audit double-encryption-at-rest (SMK layer) coverage.**~~ — **done,
   real gap confirmed**. Checked every call site of
   `StorageKeyManager.wrapBytes`/`unwrapBytes` (the `"smk1:"` second layer,
   AES-256-GCM under a PBKDF2-300k-password-derived or AndroidKeyStore-
   derived key). Only three files use it: `CryptoManager.kt` (EC identity
   private key), `GroupManager.kt` (group AES keys), `BackupManager.kt`
   (backup re-wrap). **`SessionKeyManager.kt`'s Double Ratchet session
   state and SPK/OPK private keys are not SMK-wrapped at all** — they sit
   in plain `EncryptedSharedPreferences` (single layer: AndroidX Security,
   AES-256-GCM, master key in AndroidKeyStore), the same underlying
   mechanism, but without the second password/keystore-derived layer that
   protects identity and group keys.

   Practical effect: if the underlying AndroidKeyStore protection is ever
   bypassed (rooted device forensics, an OS-level vulnerability, an ADB
   backup exploit depending on device config), session/ratchet keys and
   prekey private keys come out with *no* password required, while
   identity and group keys would still need the SMK password (or a working
   on-device KeyStore path) on top. Partial mitigation: ratchet keys are
   ephemeral and rotate per message, so a leaked *current* chain key only
   exposes messages from that point forward, not retroactively — smaller
   blast radius than an identity-key leak, but still an inconsistency
   worth closing. **Not fixed yet** — wrapping live session state safely
   (without breaking in-flight sessions, and handling the reality that
   session state needs to be readable before the user has necessarily
   unlocked via password, similar to the existing SPK/OPK "not currently
   protected" carve-out noted elsewhere) needs its own design pass, not a
   quick patch.
6. **Session-hijack notification gaps** (task #53 in the tracker) —
   **partially done**. What's fixed:
   - `server.py`: `session_conflict` now carries a `ts` (unix timestamp)
     over the WebSocket, and — new — a **visible FCM push**
     (`send_fcm_session_conflict`) fires to the kicked device's stored
     `fcm_token` at the same time, using an FCM `notification` payload
     (not silent data), so Android auto-displays it via the system tray
     even when the app is backgrounded or not running at all — this was
     the main gap (WS-only delivery meant nothing reached an
     asleep/closed-app user).
   - Android (`MessengerService.kt`): parses `ts` from the WS
     `session_conflict` message and appends a formatted local time to the
     existing notification text, so the foregrounded/connected case also
     shows *when* it happened, not just that it happened.
   - Desktop (`WebSocketClient.kt`): still just disconnects on
     `session_conflict`, no notification UI at all, and no equivalent push
     path (FCM is Android-only) — left as-is since the original problem
     (asleep/backgrounded mobile user) is Android-specific; desktop is a
     smaller, lower-priority gap for the same issue.
   - Build verified (`compileDebugKotlin` green). Not live-tested — worth
     confirming an actual kicked device receives the FCM notification
     while backgrounded before considering this closed.

   **Not done, deliberately deferred**: the explicit in-app "I think I've
   been compromised" → identity-rotation flow. This is a real feature (new
   keypair generation, re-broadcasting the new identity/fingerprint to
   every contact, some equivalent of Signal's "safety number changed" UX)
   that needs its own design pass, not something to improvise as a
   drive-by addition to this fix.

### Tier 3 — important, moderate effort

7. **TOTP 2FA for VPS/server admin access** — guide written below, **not
   yet executed** (needs to be run on the actual server, no shell access
   to it from this session). Secret goes in a local vault (KeePass-style),
   explicitly not an online password manager, per the original ask.

   ```bash
   # 1. Install the PAM module
   sudo apt install libpam-google-authenticator -y

   # 2. Generate a secret for your own admin user (run as that user, not root)
   google-authenticator
   # Answer "y" to time-based tokens. Save the secret + the printed QR/URL
   # into your offline vault now — this is the only time it's shown.
   # "y" to update ~/.google_authenticator, "y" to disallow multiple uses
   # of the same token, "y" to allow the default 1m30s clock-skew window,
   # "y" to rate-limit login attempts.

   # 3. Require it in sshd's PAM stack — edit /etc/pam.d/sshd, add near the top:
   #    auth required pam_google_authenticator.so

   # 4. In /etc/ssh/sshd_config, ensure:
   #    KbdInteractiveAuthentication yes
   #    UsePAM yes
   #    AuthenticationMethods publickey,keyboard-interactive
   # (the last line is what actually forces BOTH your SSH key AND the TOTP
   # code — without it, PAM alone can be satisfied by password OR TOTP,
   # not both together)

   # 5. Restart sshd
   sudo systemctl restart sshd
   ```

   **Test in a second terminal before closing your current session** —
   getting this wrong can lock you out of the box. Keep the first
   authenticated session open until a fresh `ssh` connection in a new
   window successfully prompts for and accepts the TOTP code.
8. ~~**Simplify the server-address-entry UX**~~ — **done**. Collapsed the
   "Add server" dialog in `ServersScreen.kt` from three fields (host, port,
   name) to two (address, optional name). The address field now accepts a
   bare host, `host:port`, or a full `wss://...` URL, parsed on confirm by
   a new `parseServerAddress()` helper (defaults to port 9000 when none is
   given, matching every default server entry elsewhere in the file). No
   Desktop equivalent exists — Desktop has no server-management screen at
   all, so nothing to mirror there. Build verified.
9. ~~**Rewrite `docs/SECURITY.md` item 18**~~ — **done**. Rewrote items 12
   and 18 to describe the current architecture (call signaling anonymized
   like everything else, no fingerprint-addressed fallback for anything)
   instead of the superseded revert-then-refix history, while keeping the
   original reproduction details as historical context for *why* the
   two-phase design exists. RU version doesn't have these specific items
   yet (not translated), left alone.

### Tier 4 — low priority, cosmetic/easy

10. ~~Fix the `subrosaColors` → `SubrosaColors` casing bug.~~ — **done**.
    Fixed across 19 files: the type name itself, plus `NavySubrosaColors`/
    `DarkSubrosaColors`/`LightSubrosaColors`/`LocalSubrosaColors` (compound
    identifiers a `\b`-anchored regex can't match mid-word, since there's
    no word boundary between e.g. "Navy" and "subrosaColors" — had to use
    plain substring replacement for those instead). Legitimate lowercase
    local/parameter variables named `subrosaColors` (not type references)
    were deliberately left alone. `compileDebugKotlin` verified green;
    several confusing unrelated-looking errors in `SecurityDiagnosticsScreen.kt`
    and `SubrosaButtons.kt` turned out to be cascading failures from this
    same bug and disappeared once it was fixed.
11. ~~Add smaller/additional dead man's switch timer tiers.~~ — **done**.
    Added 15-minute and 30-minute tiers alongside the existing
    2/5/12/24/48/72-hour ones (now 1h replaces bare "2h" as the next step
    up — full list: 15min, 30min, 1h, 2h, 5h, 12h, 24h, 48h, 72h).
    Implementation note: the interval was stored as whole hours
    (`dms_interval_hours`, `Int`) — reinterpreting that same stored number
    as minutes for existing users would have silently made their dead
    man's switch 60x more aggressive (a stored "24" meaning 24 minutes
    instead of 24 hours) without them changing anything, so a **separate**
    `dms_interval_minutes` key was added instead, explicitly derived from
    the hours-based value (`hours * 60`) the first time it's read if unset,
    never reinterpreted. `DeadMansSwitchManager` now schedules alarms off
    the minutes value; `enable(hours)` is kept as a thin wrapper over the
    new `enableMinutes()` for any other caller. UI chip row now
    horizontally scrolls (9 chips no longer fit one screen width) and
    labels switch between "min"/"h" units depending on tier. Build
    verified.
12c. **Filename obfuscation** — after the padding self-audit, also checked
    whether attachment filenames on disk leak metadata by themselves.
    Android used type-revealing names (`image_<uuid>.jpg.enc`, `voice_<id>.3gp.enc`,
    `videos/<id>.mp4.enc`, `files/<id>/<real filename>.enc`); Desktop was
    worse — file attachments kept the literal original filename in the path
    (`<fileId>-<original name>.enc`). Fixed both platforms: single flat
    `blobs/` directory, opaque `<id>.enc` naming, no type prefix, no real
    filename in the path (already tracked separately as message metadata,
    so display name is unaffected). Compiles clean on both platforms.
    **Decoy files were considered and explicitly rejected** — real content
    is already protected by SMK, so hiding "a file exists" has little value
    without a full deniable-encryption architecture (hidden volumes), which
    this isn't; `DecoyScreen`'s fake-chat-UI is the more coherent existing
    answer to plausible deniability.
12d. **EXIF/GPS stripping** — closed the gap noted above the same day.
    The dedicated photo picker was already safe (decode-to-Bitmap +
    re-encode to WebP carries no EXIF forward regardless). The real leak
    was the generic "attach as file" picker: picking a photo through it
    sent the original bytes untouched, GPS included. Added `stripExif()`
    in `ChatScreen.kt` (new `androidx.exifinterface:exifinterface:1.3.7`
    dependency) — clears GPS + device-ID + timestamp tags, keeps
    orientation, applied only to `image/*` MIME types on that one path.
    Falls back to original bytes on failure rather than blocking send.
    **Desktop checked and fixed the same day, turned out worse than Android's
    gap**: Desktop's single attach dialog routes by file extension rather
    than having separate "photo"/"file" pickers, and unlike Android it never
    decoded/re-encoded images at all — so *every* image sent from Desktop
    (not just ones attached as a generic file) shipped raw, EXIF included.
    Fixed with `stripImageMetadata()` in Desktop's `ChatScreen.kt`: decodes
    via `javax.imageio.ImageIO` and re-encodes in the same format
    (jpg/png/bmp/gif — `webp` isn't writable by the JDK's built-in `ImageIO`,
    sent unmodified same as any decode/encode failure). No new dependency
    needed, `ImageIO` is part of the JDK. Compiles clean.
12b. **Path-traversal fix in file transfer** — `file_chunk` handler used
    a peer-supplied `file_id`/`file_name` unsanitized to build the write
    path (`File(filesDir, "files/$fileId/${fileName}.enc")` on Android,
    `File(fileDir, "$fileId-$safeName.enc")` on Desktop). A malicious/
    compromised contact (signature check already restricts this to an
    actual trusted contact, not a stranger or the server) could send
    e.g. `file_id = "../../../shared_prefs"` to write decrypted attacker
    bytes outside the intended `files/<id>/` directory, anywhere inside
    the app's own private storage — could clobber EncryptedSharedPreferences,
    SMK config, DMS config, message DB. Fixed both platforms: added
    `sanitizePathComponent()` (strips `/\:*?"<>|` and any `..` sequence)
    applied to `file_id` (both platforms) and `file_name` (Android; Desktop
    already had partial filename sanitization in ChatScreen.kt but was
    missing it on `file_id`). Applied right after JSON parsing, before any
    path construction or signature check, so legitimate transfers (UUID-based
    file_id) are unaffected. Compiles clean on both platforms.
    **Noted but not fixed**: Desktop's `handleFileChunk` doesn't verify a
    chunk signature at all (Android's does via `CryptoManager.verifyChunk`)
    — a separate, smaller gap, not touched this pass.
12a. Leftover "B-CON" brand-string tail from the rebrand, found while
    looking at ChatsScreen — fixed: header text on ChatsScreen ("B-CON"→
    "SUBROSA"), theme name ("Синяя"/"Navy" → "Бордовая"/"Burgundy" to match
    the new palette), plus all other stragglers found via grep: root-danger/
    biometric-lock/spy-detection dialog text (RU+EN) in AppStrings.kt,
    DecoyScreen.kt, saved-photo folder path in ChatScreen.kt, notification
    channel/title strings in MessengerService.kt, app titles in
    MainActivity.kt/LoginScreen.kt, and the honeytoken decoy file's fake
    content in HoneyTokenManager.kt. Compiles clean.
12. Swap the Android launcher icon + Desktop icon to the new rose mark.
    **Android done this pass**: cropped `Сургуч_Иконка.png` to a centered
    1400x1400 square (`icon_work/square_master.png`), generated legacy
    launcher icons (5 densities) + adaptive foreground layers (5 densities,
    68% content ratio) as `.png`, deleted the old `.webp` files (both
    legacy and adaptive foreground — would otherwise collide as duplicate
    resources), set `ic_launcher_background` to `#641D17`. Compiles clean.
    **Desktop icon still not done** — user explicitly wants one too.

### Tier 5 — deferred, bigger or still underspecified

13. Cloudflare WebSocket-proxying root cause, reverting the temporary
    `api.` DNS-only bypass + relaxed nginx `allow` list + `ServerManager.kt`
    `:8443` override (task #52) — explicitly deprioritized: this only
    affects the personal dev/test server, not any real client deployment,
    since every client stands up their own infrastructure.
14. Full palette unification (icon + in-app theme + website) — real reskin,
    3 themes × ~18 colors each plus a contrast/accessibility re-check.
    **In-app Android theme done this pass**: recolored all 3 themes in
    `SubrosaColors.kt` from the old navy/cyan scheme to a burgundy/gold
    family (accent `#D9A566` antique gold on dark themes, `#8A2A2A`
    burgundy accent on the cream light theme — gold reads poorly on white).
    Also swept ~10 screen files for hardcoded old-palette hex literals
    (`#141e4a`/`#0d1238`/`#091a66`/`#1F2B5E`/`#1A2550`/`#2A3B8F` navy tones,
    `#2481CC` blue, `#00E5FF` cyan) that bypassed the theme system entirely
    and replaced them with the new burgundy/copper/gold equivalents,
    including the first entry of the decorative multi-color avatar-palette
    lists (the other 5 avatar colors were left alone — intentional variety,
    not brand color). Compiles clean. **Not yet done**: Desktop app theme
    colors, website accent color (still teal `#55B5A8`), no live-device
    visual/contrast check yet.
15. Optional server-side client access-list/allowlist — explicitly
    "needs more thought," not yet concretely scoped. Noted tradeoff: adds
    a failure point/friction that cuts against the product's own
    self-hosting-should-be-easy goal.

---

## План: приоритизация находок из раунда SCENARIOS.md (8 сценариев)

Написано, пока пользователь отошёл поесть, по его просьбе — "подумать,
что как решать". Ничего из этого не реализовано, план для последующего
обсуждения и реализации. Сортировка: сначала критично+дёшево, затем
дороже/менее критично, в конце — то, что требует отдельного дизайн-
решения перед тем, как вообще садиться писать код.

### Тир 1 — тривиально, стоит сделать первым (минуты, не часы)

Все четыре пункта этого тира сделаны в одной сессии, `compileDebugKotlin`
проверен зелёным после каждого. Ничего не тестировалось вживую на
устройстве — только компиляция.

1. ~~**Android: добавить обработчик `prekey_bundle_request`**~~ — **done**.
   Добавлена ветка `"prekey_bundle_request" -> publishPrekeyBundle()` в
   диспетчер `MessengerService.kt`, зеркально уже рабочему коду на Desktop
   (`WebSocketClient.kt:1375`). `publishPrekeyBundle()` — обычная (не
   suspend) функция, сама запускает `scope.launch`, так что вызов прямо
   из диспетчера безопасен.
2. ~~**Экспорт бэкапа при заблокированном SMK**~~ — **done**. Добавлена
   проверка `StorageKeyManager.isUnlocked` в начало `exportBackup()`
   (`BackupManager.kt`), бросает понятное `IllegalStateException` вместо
   того, чтобы дать сырой exception из `unwrapBytes()` долететь до UI —
   тот же принцип понятного сообщения, что уже был на импорте. Desktop не
   тронут — там приватный ключ идёт через `DesktopCryptoManager`
   (machine-bound PKCS12 keystore), не через SMK-обёртку, так что этот
   конкретный гэп на Desktop структурно не существует.
3. ~~**`WipeManager.Level.SOFT`**~~ — **done, выпилено**. Решение: раз
   уровень нигде не достижим ни одним триггером, но при этом **показывался
   пользователю** как рабочая опция защиты в `WipeSettingsScreen.kt`
   ("Мягкий (SOFT)" с описанием "Очищает кеш и оперативную память") — это
   не просто мёртвый код, а вводящая в заблуждение информация в
   security-критичном UI. Удалены: `Level.SOFT` из enum, `softWipe()`,
   ветка `when` в `wipe()`, карточка в `WipeSettingsScreen.kt`, строки
   `wipeLevelSoft`/`wipeSoftDesc` (RU+EN) в `AppStrings.kt`. `HARD`/
   `NUCLEAR` не тронуты.
4. ~~**`group_reaction` без проверки подписи`**~~ — **done, добавлена
   проверка**. Отправитель (`sendGroupReaction()`) уже подписывал `emoji`
   и клал `signature` в пакет — получатель просто никогда её не читал.
   Добавлена та же проверка, что и у `group_message`: без ключа
   отправителя или при неверной подписи `emoji` — пакет отбрасывается
   молча (лог + `return`), колбэк `onGroupReactionReceived` не вызывается.
   Desktop-клиент группы вообще не поддерживает (`group_reaction` не
   найден в проекте `desktop/`) — нечего зеркалить.

### Тир 2 — весомая находка, но чуть больше работы (часы, не дни)

5. ~~**Групповой ростер не рассылается при добавлении участника**~~ —
   **done, обе платформы**. Оба изменения из плана реализованы:
   - `group_create` теперь несёт подписанный полный ростер: новые поля
     `members`/`admins` (JSON-массивы) + `roster_signature` — подпись
     над канонической строкой `"$groupId|member1,member2,...|admin1,..."`
     (`rosterPayload()`, общая функция и для подписи на отправке, и для
     проверки на приёме). Получатель, у которого такой группы ещё нет,
     теперь инициализирует ростер из пакета вместо `[from, я]`, но
     только после проверки `roster_signature` тем же публичным ключом,
     что и `encrypted_group_key` — подделать состав группы, не владея
     ключом пригласившего, нельзя. Есть проверка "получатель обязан
     присутствовать в присланном ростере" (защита от тривиальной
     подмены). Если пакет пришёл без этих полей (старый непропатченный
     пир) — тихий откат на прежнее поведение `[from, я]`/`[from]`, не
     жёсткий отказ.
   - Добавление участника (`addGroupMember()`, Android) теперь не только
     шлёт `group_create` новичку (с полным пост-добавочным ростером), но
     и **новый тип пакета `group_member_added`** всем уже существующим
     участникам (кроме себя и новичка) — подписан над
     `"$groupId:add:$newMemberId"`, получатель проверяет, что отправитель
     — админ (`GroupManager.isAdmin`), симметрично уже работавшей
     рассылке `group_member_removed`. `GroupInfoScreen.kt` перечитывает
     группу из хранилища после `GroupManager.addMember()` перед сборкой
     ростера для отправки — та же причина, что и в уже почищенном пути
     удаления (иначе ушёл бы устаревший Compose-стейт до персиста).
   - **Desktop проверен — та же архитектура групп есть** (`GroupManager.kt`,
     `WebSocketClient.kt`), баг был идентичный в `createGroup()`/
     `handleGroupCreate()`. Пофикшено тем же паттерном (roster_signature,
     тот же canonical-string формат, тот же fallback на legacy-пакеты).
     **У Desktop нет функции добавления участника в существующую группу
     вообще** (только создание и удаление) — так что вторая половина
     бага (рассылка при добавлении) на Desktop структурно не
     существовала, нечего было чинить.
   - Побочно не тронуто (уже отмечено раньше в этом файле): подпись
     `group_reaction` — эта отдельная находка **уже закрыта в Tier 1**;
     `createdBy` в пакете `group_create` по-прежнему = "кто прислал этот
     конкретный `group_create`", не обязательно исходный создатель
     группы (актуально, когда админ, не создатель, добавляет участника)
     — не в скоупе этой находки, не тронуто.
   - Compiles clean: `compileDebugKotlin` (Android) и Desktop's
     `compileKotlin` (свой gradlew, отдельный проект) оба зелёные.
     Live-тест (реальная группа из 3+ человек, реальные два клиента) не
     проводился.
6. **`file_name` в открытом виде в `file_chunk`** — весомая находка для
   аудитории проекта (журналисты). Либо генерик-плейсхолдер + MIME-
   расширение вместо реального имени, либо шифровать поле тем же
   гибридным ключом, что и `data`. Второй вариант чище архитектурно
   (не теряет отображаемое оригинальное имя для получателя), но требует
   отдельного шифрования небольшого поля до/после основного файла.
7. **`sendVoice` ломает воспроизведение при отсутствии ключа** —
   отдельная voice-очередь ретраев по образцу уже существующих
   `pendingImages`/`pendingFileSends`. Паттерн уже есть в коде дважды,
   просто повторить для voice.
8. **`MessengerService` не перезапускается после импорта бэкапа на уже
   активном устройстве** — принудительный рестарт сервиса (или форс
   переинициализации identity) сразу после успешного `importBackup()`.
   Закрывает реальное окно рассинхрона `from`-поля и ключа подписи.
9. **`session_init` тихо откатывается на прямую адресацию** — заменить
   на `mailbox_put` в уже сохранённый тег контакта (тот же паттерн,
   что уже используется для bootstrap токенов). Согласовано с
   пользователем ранее в этой сессии.
10. **Session_reset после восстановления бэкапа** — разослать
    `session_reset` всем восстановленным контактам сразу после импорта,
    используя уже существующий паттерн
    `consumePendingPqMigrationContacts()`.

### Тир 3 — нужно решение по дизайну до того, как писать код

11. **"Война переподключений" при `session_conflict`** — нужно решить:
    останавливать ли автопереподключение специально для этого случая
    (не для обычного разрыва связи), и что показывать пользователю
    вместо автоматического реконнекта (экран "кто-то ещё вошёл").
12. **Health-check контактов через 15 минут тишины** — логика уже
    полностью согласована с пользователем (см. секцию выше в этом
    файле) — это уже не дизайн-вопрос, а вопрос реализации: новый тип
    сообщения-пинга, таймер тишины на контакт, интеграция с mailbox.
    По объёму — не Тир 1/2, отдельная фича, но дизайн готов, можно
    начинать когда будет время.
13. **5-минутный ретрай + тикет разработчику при первом контакте** —
    тоже уже согласовано (см. секцию про сценарий "Первый контакт"),
    готово к реализации.
14. **Смешение identity при импорте бэкапа на уже используемое
    устройство** — нужно решение по продукту: что видит пользователь,
    удалять ли старые контакты/сообщения старой identity, или оставлять
    как есть с явным предупреждением. Не приступать к коду, пока не
    решено.

### Тир 4 — большое/опциональное, не срочно

15. ~~**TOTP 2FA на бэкап**~~ — **MVP сделан, Android-only**. Новый
    `TotpManager.kt` — RFC 6238 (HMAC-SHA1, 30с шаг, 6 цифр), секрет
    генерируется на устройстве (`generateSecret()`), хранится
    SMK-обёрнутым (`StorageKeyManager.wrapBytes`, тот же паттерн, что у
    identity-ключа) в отдельных `totp_prefs`, **никогда не кладётся внутрь
    самого бэкапа** — только булевый флаг `totp_enabled` уходит в JSON
    бэкапа. Это осознанный выбор: если бы секрет лежал внутри
    зашифрованного бэкапа, пароль к бэкапу автоматически открывал бы и
    секрет, и второй фактор ничего бы не добавлял. Пользователь должен
    сам сохранить секрет отдельно (KeePass и т.п.), как и предлагал
    изначально.

    Настройка — новый экран `TotpSettingsScreen.kt` (Profile → 🔐
    Двухфакторная защита бэкапа): генерирует секрет, показывает его и
    `otpauth://` URI (для ручного ввода в любое TOTP-приложение), просит
    ввести текущий код для подтверждения перед включением — стандартный
    TOTP-enrollment UX. Выключение — сразу, без повторного подтверждения
    кодом (пользователь уже аутентифицирован в разблокированном
    приложении).

    Импорт (`BackupManager.importBackup()`) — если у бэкапа
    `totp_enabled=true`, требует непустые `totpSecret`+`totpCode`
    (новые опциональные параметры функции), проверяет код
    (`TotpManager.verifyCode`, окно ±1 шаг на дрейф часов) до какой-либо
    замены identity, и при успехе сохраняет тот же секрет на
    принимающем устройстве, чтобы защита не терялась при переносе.
    Если SMK заблокирован в момент импорта — понятная ошибка, а не
    сырое исключение (тот же принцип, что и у фикса экспорта из Tier 1).
    `BackupScreen.kt` получил два новых опциональных текстовых поля
    (секрет/код) в разделе импорта.

    **Не сделано в этой сессии**: Desktop-клиент не тронут (там свой
    `BackupManager.kt`, приватный ключ идёт через machine-bound PKCS12
    keystore, а не SMK — гэп нужно оценивать отдельно, не факт что тот же
    паттерн подходит один в один). Также не реализовано: восстановление
    при утере TOTP-секрета (сейчас это тупик — секрет не в бэкапе, значит
    его больше негде взять, кроме как «плохо было бы жёстко», это
    сознательный компромисс безопасности, а не забытый кейс, но
    пользователю стоит явно об этом сказать в UI, что пока не сделано).
    Live-тест на реальном устройстве не проводился, только
    `compileDebugKotlin` зелёный.

    **Второй, отдельный слой добавлен в той же сессии — но после того, как
    первая попытка ("TOTP-код на каждый `register`") оказалась в корне не
    тем, что просилось.** Уточнение пользователя дважды подряд:
    1. Первая формулировка ("TOTP для сервера, один секрет на главный
       аккаунт") была реализована буквально — код на каждый `register` —
       и это оказалось неверно: пользователь указал, что реальная цель —
       **защита чтения логов сервера**, а не логина/регистрации аккаунта,
       и что требовать код на каждое подключение убило бы UX (мобильная
       сеть переподключается постоянно).
    2. Уточняющий вопрос закрыл, что именно защищаем: **доступ админа к
       самим файлам/процессу логов на сервере** — не SSH-вход (это
       отдельный, ещё не выполненный Tier 3 п.7) и не шифрование логов на
       диске, а возможность **прочитать логи прямо из приложения, без
       shell/SSH-доступа к машине вообще**, с TOTP как условием.

    Реализация полностью переделана под это понимание:
    - **Gating `register()` убран целиком** — обычный логин/реконнект
      аккаунта никогда не требует и не отправляет TOTP-код, поведение то
      же, что было до этой сессии.
    - `server.py`: `ADMIN_FINGERPRINT` — новая переменная окружения
      (`.env.example` обновлён), называет **ровно один** аккаунт-мессенджер
      (сам оператор сервера) как admin-аккаунт. Только он может дергать
      `totp_setup`/`totp_disable`/`admin_get_logs` — для любого другого
      username эти три типа сообщений тихо игнорируются
      (`continue`), даже с валидной подписью текущего приватного ключа.
      `totp_setup` — одноразовая привязка секрета (таблица SQLite
      `user_totp`, переживает рестарт): если у admin-аккаунта уже есть
      секрет, второй попытке — безусловный отказ, нет пути перезаписи
      через протокол вообще. `totp_disable` требует текущий валидный код,
      не только принадлежность аккаунту. Новый `admin_get_logs` —
      возвращает последние строки лога (см. ниже), тоже требует текущий
      валидный код, с защитой от replay (`user_totp_last_counter`, тот же
      механизм, что уже был).
    - **Источник логов**: не трогая ни один из ~150 существующих
      `print()`-вызовов по всему файлу, `sys.stdout` обёрнут в
      `_RingBufferTee` — каждая строка, уходящая в консоль/`docker-compose
      logs` (это по-прежнему работает как раньше, ничего не сломано),
      дополнительно копируется в `log_ring_buffer` (`collections.deque`,
      последние 2000 строк, в памяти, не персистентно — переживает не
      рестарт сервера, а просто отдельный путь чтения того же вывода).
      `admin_get_logs` отдаёт хвост этого буфера (последние ~100KB).
    - Android: `TotpManager.kt` — второй неймспейс `server_totp_prefs`
      сохранён (секрет отдельно от backup-TOTP), но теперь используется
      только для admin-функций, не для `register`. `MessengerService.kt`:
      `register()` больше не кладёт `totp_code` (откат); новый
      `sendAdminGetLogs(code)`, обработчики `admin_logs`/
      `admin_get_logs_failed` → колбэк `onAdminLogsResult` для UI.
      Обработчик `totp_required` и сопутствующий `totpRequiredNotified`
      убраны как мёртвый код (сервер больше никогда не шлёт этот тип).
      `ServerTotpSettingsScreen.kt` (Profile → 🔒 TOTP-доступ к логам
      сервера) переименован по смыслу и получил третий блок — поле для
      кода + кнопка "Загрузить логи" + прокручиваемый текстовый вывод
      результата. Текст экрана явно предупреждает, что работает только
      для аккаунта, совпадающего с `ADMIN_FINGERPRINT` — для всех
      остальных пользователей нажатие кнопок просто вернёт отказ, без
      побочных эффектов.

    **Не сделано**: если `ADMIN_FINGERPRINT` не задан в `.env` — фича
    структурно недостижима для всех (сервер печатает это явно при
    старте), это осознанное поведение по умолчанию, не баг. Desktop не
    тронут (у Desktop нет своего `server.py`, эта находка чисто
    серверная + Android-UI). Live-тест (реальный сервер,
    `ADMIN_FINGERPRINT` реального аккаунта, реальный authenticator) не
    проводился — только `ast.parse` и `compileDebugKotlin` зелёные.
16. **Decoy-боты с реальным трафиком** — опциональный модуль, дизайн
    зафиксирован с оговорками (см. секцию выше), но это отдельная
    инфраструктурная задача (боты, VPS, поведенческая реалистичность) —
    не для быстрой реализации.
17. **Explicit "я думаю, меня скомпрометировали" флоу** — старый пункт
    из "Candidate fixes", завязан на решение по Тиру 3 пункт 11 (война
    переподключений) — логично делать вместе с ним, не раньше.