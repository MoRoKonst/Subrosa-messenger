# Known issue: session hijack via stolen backup + password

Status: **not fixed, not started**. Written down so it isn't lost during the
domain/rebrand/website work.

## Полная опись: где сообщение может уйти прямой адресацией, не через анон-токен

Составлено после фикса item 9 (session_init mailbox fallback) по прямому
запросу — "вынеси все места, которые ломаются или могут сломаться, будем
искать обход". **Обновление: все 4 пункта закрыты в следующем же
проходе** — см. "Реализация обхода" в конце раздела.

**Контекст**: `sendAnonOrDirect()` (и его Desktop-зеркало) — общий путь для
реакций/edit/delete/typing/read/voice/фото/файлов/видео-кружков/звонков —
уже полностью починен в более раннем проходе этой сессии: прямого fallback
там нет вообще, при пустом пуле токенов пакет становится в очередь
(`pendingAnonPackets`) и ждёт `sendAnonTokensTo()`. Все находки ниже — это
**отдельные, не затронутые тем фиксом** пути, каждый со своей причиной.

### Android (`MessengerService.kt`)

1. ~~**`sendWithForwardSecrecy()`, обычные (не первые) сообщения**~~ —
   **done**. Обход — не queue-and-retry, а по прямому указанию: реализован
   уже давно спроектированный, но не реализованный протокол "взаимный
   health-check контактов через N времени тишины" (секция выше в этом
   файле) — он и есть предназначенное решение именно для этой ситуации
   ("токены кончились у уже установленной пары"), а не отдельный патч.
   См. "Реализация обхода" ниже.
2. ~~**`sendWithForwardSecrecy()`, `session_init` без токена И без
   mailbox-тега**~~ — **done, и это оказалось не редким хвостом, а
   постоянной проблемой**. При ближайшем рассмотрении выяснилось:
   `getContactMailboxTag()` **безусловно очищался** сразу после первого
   успешного обмена токенами — то есть тег, на который опирается и этот
   фикс, и весь health-check, реально жил только до первого бутстрапа
   контакта, а дальше пропадал навсегда для *любого* уже давно
   переписывающегося контакта, не только "редкого legacy-случая". Это и
   есть недостающая "свежесть тега" (шаг 5 дизайна health-check) — чинится
   вместе с item 1, см. ниже.
3. ~~**`sendEncrypted()` — легаси-протокол**~~ — **done**. Последняя
   строка (`sendWs(addPadding(packet)...)`) заменена на
   `sendAnonOrDirect(to, packet)` — то же самое, что уже происходит в
   остальных местах, оказалось буквально однострочным изменением: пакет
   уже был полностью собран, просто раньше уходил в обход общего пути.
   Автоматически закрывает все 7 мест, где `sendEncrypted` вызывается как
   fallback (включая все error-пути, самое неприятное место из всей
   описи).
4. ~~**Парсинг сигнала звонка не удался**~~ — **done, fail closed**.
   Вместо `sendWs(signalJson)` в catch-блоке теперь просто лог и отказ от
   отправки — раз JSON не распарсился, у нас даже нет надёжного `to`,
   чтобы куда-то маршрутизировать, а сервер/получатель всё равно не
   разберут битый сигнал звонка ни при каком варианте доставки. "Молчать"
   вместо "отправить как есть, но хуже".

### Desktop (`WebSocketClient.kt`)

Desktop структурно в лучшем состоянии — и `sendAnonOrDirect()`, и
`sendLegacy()` (аналог Android-`sendEncrypted`) в итоге всегда идут через
`sendAnonOrDirect()`, то есть уже унаследовали queue-and-retry без
дополнительных изменений. Осознанно проверено и не найдено ни одного
прямого fallback вне `sendAnonOrDirect`, кроме уже задокументированных
раньше исключений (`call_group_*` — всегда прямые по дизайну, не через
анонимную маршрутизацию, см. `SECURITY.md` п.18).

### Не входит в эту опись (уже принятые, отдельные исключения по дизайну)

- `call_group_*` (групповые звонки) — намеренно всегда прямые на обеих
  платформах, не баг.
- Каналы (`channel_*`) — фича отключена на уровне UI, метаданные никогда
  не анонимизировались, отдельная, давно известная и принятая
  оговорка (см. `MEMORY.md`/`ARCHITECTURE.md`).
- Протокольный трафик к самому серверу без контактного адресата
  (`register`, `challenge_response`, `ping`/`pong`, `chunk_ack`,
  `subscribe_tokens`, `register_fcm`, `get_prekey_bundle*`) — сервер и
  так участник этого обмена, "анонимизировать" тут нечего, хотя
  `get_key`/`get_prekey_bundle` (не batch) действительно раскрывает
  серверу, кем интересуется отправитель — известная, отдельно
  задокументированная оговорка (`SECURITY.md`, п.11).

### Реализация обхода — все 4 пункта закрыты, Android

**Фундамент — сначала тег, потом всё остальное.** Прежде чем реализовывать
health-check (пункт 1), пришлось сначала починить пункт 2 по-настоящему:
`getContactMailboxTag()` очищался безусловно после первого успешного
обмена токенами (`handleIncomingDecryptedMessage`'s `__beacon_tokens__:`-
ветка). Заменено на **обновление**, а не очистку: `AnonTokenManager`
получил `getOrCreateMyPersistentMailboxTag()` — тег, сгенерированный один
раз на инсталляцию, независимый от TTL инвайт-кода, живёт бессрочно.
Теперь при каждом обмене токенами (и через `anon_message`, и через
mailbox-депозит — оба пути) отправитель прикладывает этот свой
персистентный тег; получатель вызывает `setContactMailboxTag()` вместо
`clearContactMailboxTag()`. Итог: `getContactMailboxTag(contact)` **больше
никогда не становится null** для контакта, с которым хоть раз был
успешный обмен токенами — ровно то, что и просил шаг 5 исходного дизайна
("свежесть тега"), просто оказалось, что без него не работали ни item 2,
ни item 1 для давних контактов, только для только что добавленных.

**Пункт 1 — реализован протокол "Забота о собеседнике" целиком**, новый
файл `ContactHealthManager.kt`:
- `recordIncoming(contactId)` — вызывается при любом входящем сообщении
  (`handleIncomingDecryptedMessage`, откуда идёт и `processSessionInit`) и
  при получении `contact_ping`/`contact_pong`. Сбрасывает таймер молчания
  и состояние пинга.
- `recordDelivered(contactId)` — при получении `delivered`-подтверждения.
- `recordOutgoingAttempt(contactId)` — при каждом вызове `send()`
  (отличает "никогда не переписывались" от "молчание после переписки").
- `isSilent(contactId)` — true, только когда **и** входящие, **и**
  `delivered`-подтверждения молчат дольше `SILENCE_THRESHOLD_MS` (15
  минут) — ровно триггер из дизайна, не просто "нет входящих".

Новый цикл `checkContactSilence()` в `MessengerService`, раз в минуту,
пока подключены (тот же паттерн, что уже есть у `pollMailbox()`):
- **Стадия PINGED** (первое обнаружение молчания): шлёт `contact_ping`
  через `sendAnonOrDirect()` — **без всякого исключения из
  антизлоупотребительных лимитов**, как и требовал дизайн: если
  персональный токен для контакта ещё есть — пинг уходит нормально; если
  токенов уже нет вообще, `sendAnonOrDirect`'s собственный
  queue-and-bootstrap каскад (уже существовавший код, не новый) сам
  скатывается в депозит токенов через mailbox — это и есть "я тот, у кого
  кончился воздух" ветка дизайна, реализовалась бесплатно как побочный
  эффект уже написанной логики, не потребовала отдельного кода.
- Получатель `contact_ping` отвечает `contact_pong` (тем же
  `sendAnonOrDirect`, тоже тратит токен) — если у него есть чем ответить.
  Если нечем — ответа не будет, и это само по себе сигнал.
- **Стадия MAILBOX_TRIED** (пинг ушёл, но за `MAILBOX_RETRY_WAIT_MS` = 5
  минут ответа не было): **одна-единственная** дополнительная попытка —
  прямой `depositTokensViaMailbox()` на mailbox-тег контакта (теперь
  живой благодаря фиксу выше). После этого — тишина, никаких дальнейших
  попыток до реального возобновления переписки, ровно "one-off, not a
  loop" из дизайна.
- Симметричная "мёртвый связист" сторона (шаг 4 дизайна — сверка своего
  тега с лимитом попыток) реализована **не отдельным кодом**, а через
  уже существующий постоянно работающий `pollMailbox()` (раз в 30 секунд,
  пока есть свои mailbox-теги) — он и так уже эффективно покрывает
  "проверяй раз в N времени, есть ли для меня пакет", просто без
  верхнего предела попыток (что скорее лучше, чем "сдаться после трёх
  раз", раз это фоновый процесс, а не активное действие).

Специально **не сделано** явное UI-предупреждение про 15 минут — по
дизайну весь механизм должен быть тихим, не пугать пользователя.

**Пункты 2-4** — детали см. выше по каждому пункту.

**Desktop не тронут** этим проходом — вся находка и её обход были
Android-специфичны (пользователь фокусировался на мобильном клиенте в
этой сессии); при необходимости зеркалить `ContactHealthManager` и
tag-freshness фикс на Desktop нужно отдельным проходом.

Compiles clean (`compileDebugKotlin`). Live-тест (два реальных устройства,
реальное 15-минутное молчание) не проводился — это самая сложная по
времени часть аудита в этой сессии протестировать вручную.

## Идея — реализована как `ContactHealthManager.kt`, Android

**Обновление**: реализовано (см. "Реализация обхода" в разделе "Полная
опись" выше, item 1) — исходный дизайн ниже сохранён как есть, для
справки, что было решено и почему. `SILENCE_THRESHOLD_MS`/сама структура
ping→wait→одна попытка mailbox соответствуют пунктам 1-4 этого дизайна
почти дословно; пункт 5 ("свежесть тега") тоже закрыт, но другим
механизмом (постоянный персистентный тег вместо периодического обновления
перед истечением TTL исходного) — см. детали в новом разделе.

## Идея (изначальный дизайн, до реализации): взаимный health-check контактов через N времени тишины

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

- **The original backup-hijack problem itself** (this file's title) —
  substantially mitigated by now, though never framed as "fully solved"
  since there's no way to truly revoke a private key someone else holds a
  copy of, only to replace the identity built on it (see "Why this
  doesn't actually solve the problem" below, still accurate). What's
  landed since this was last true: TOTP 2FA closes the "file+password
  alone is sufficient" gap (Tier 4 item 15, with recovery codes for a
  lost TOTP secret added 2026-08-13); `session_conflict` is now pushed
  via FCM with a timestamp (Candidate fixes #1-2); the explicit "I think
  I've been compromised" flow exists (#3) and, as of 2026-08-13, also
  revokes the fingerprint server-side, with the Dead Man's Switch NUCLEAR
  wipe doing the same, plus a client-side warning when a contact fetches
  a revoked identity's prekey bundle — see the Тир 5 section further down
  for the full writeup. Closes the specific hole where a stolen key still
  worked after a "reset", and where a contact starting a fresh session
  had no way to find out. Remaining gap: only Android has any of this —
  Desktop has neither the revocation button nor the warning UI.
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
- **Identity-rotation ("I think I've been compromised") flow — DONE.** User's
  design, deliberately cheap: no attempt to figure out which device is
  legitimate, no notification to old contacts via the (possibly-compromised)
  old key, no data/history migration. New button "Меня скомпрометировали"
  in `ProfileScreen.kt` (separate from the existing "!Это не я!" duress
  panic-wipe button — that one calls `WipeManager.hardWipe()`, which nukes
  *everything* including device-level settings like TOTP secret, panic
  password, wipe/dead-man's-switch config, calculator disguise; this new
  flow deliberately does not touch those, since a compromised messenger
  identity key doesn't imply the device's local settings are compromised
  too). On confirm: `BackupManager.resetCompromisedIdentity()` — new
  `UserStorage.resetIdentityFields()` clears only identity-scoped prefs
  (username, user_id, password hash, display name, invite code, avatar) plus
  contacts/messages, then `GroupManager.clearAll`/`AnonTokenManager.clearAll`/
  `SessionKeyManager.deleteAllSessions`/`CryptoManager.deleteKeys`, then
  clears the SMK wrap (`smk_config` prefs + AndroidKeyStore alias) so
  `StorageKeyManager.isSetup()` goes false and the existing `RegisterScreen`
  flow re-wraps SMK with whatever new password the user picks — avoids a
  landmine where the old SMK stayed wrapped with the old password after a
  surgical reset. Process is killed after the reset (same pattern as
  `WipeManager.hardWipe`) to guarantee no stale in-memory identity state
  survives in `MessengerService`/session managers; next cold start lands on
  `RegisterScreen` since `UserStorage.isRegistered()` is now false, same
  code path as a fresh install. Compiles clean, not yet live-tested on a
  device. **Update, 2026-08-13**: this local-only reset used to be the
  whole story — a stolen key still worked after the "reset" since the
  server had no concept of revocation. Now also revokes the fingerprint
  server-side before the local wipe (and the Dead Man's Switch NUCLEAR
  wipe does the same) — see the Тир 5 section further down for the full
  writeup.
- ~~Tier 5 items (Cloudflare bypass, palette unification, access-list)~~ —
  **all done now**, this line was stale. Cloudflare turned out to not be
  a Cloudflare problem at all (see that section); palette unification and
  the access-list/one-time-code system are both marked done in their own
  Tier 5 entries.
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

## Найдено вживую 2026-08-13 — токены гибли при ЛЮБОМ дисконнекте, не только при исчерпании пула

Живое тестирование (два реальных устройства, полная переустановка,
свежий сервер): установили связь, всё работало, через ~23 минуты у
**обеих** сторон разом сообщения перестали доходить — при этом
отправитель видел "Отправлено", получатель ничего не получал, сервер
логировал "токен офлайн". Через 15-30 минут сработал health-check
(`ContactHealthManager`) и связь сама восстановилась через mailbox — то
есть защитный механизм отработал штатно, но сам факт, что до него
дошло, указывал на более базовую проблему.

**Корень**: `server.py`'s `handle_client()`, `finally`-блок при
дисконнекте. При **любом** обрыве соединения (включая совершенно
безобидный short-lived реконнект — например, ровно ту причину, что чинили
прошлым проходом, `Broken pipe` от `pingInterval(0)`) сервер удалял
токены отключившегося клиента не только из `token_to_ws` (это
оправданно — сокет и правда мёртв, доставлять некуда), но и из
`known_tokens` и `token_pending`. `known_tokens` — это не "куда
доставить", а "существует ли вообще такой токен" (защита от
спуфинга/анализа трафика), у этого свойства нет причины зависеть от
живости конкретного сокета — токен привязывался к websocket-объекту,
хотя логически должен быть привязан к аккаунту.

Практическое следствие: пока токен не был в `known_tokens`, любое
сообщение по нему сервер трактовал как "фейковый/decoy-токен" —
**молча дропал и отправлял отправителю поддельный `ack`** (это
намеренное поведение анти-фингерпринтинга — сервер не должен уметь
отличать протухший настоящий токен от намеренного мусора). Отсюда и
"Отправлено" при полном отсутствии доставки — сервер в буквальном
смысле врал клиенту.

**Исправлено**: `known_tokens.discard(t)` и `token_pending.pop(t, None)`
убраны из `finally`-блока, остался только `token_to_ws.pop(t, None)`.
`token_pending` и так самоограничен (10 сообщений на токен, см.
`anon_message`-хендлер), утечки памяти не будет; при реконнекте+
`subscribe_tokens` токен снова привязывается к новому сокету, а всё,
что успело накопиться в `token_pending`, штатно флашится — этот путь
уже существовал и работал, просто раньше до него редко доходило, так
как `known_tokens` стирался раньше, чем контакт успевал попробовать
отправить.

**Не сделано**: не добавлен TTL/периодическая чистка `known_tokens` для
по-настоящему брошенных аккаунтов (удалённых, отозванных через
identity-ревокацию) — теоретически такие токены теперь могут висеть в
`known_tokens` бессрочно вместо мгновенной чистки. Не блокирует (рост
ограничен количеством уникальных когда-либо выданных токенов на
аккаунт, не растёт от трафика), но стоит вернуться, если когда-нибудь
станет заметно на реальном масштабе. `py_compile` зелёный, не
задеплоено на боевой сервер, живой повторный тест (специально
разорвать/восстановить соединение и убедиться, что сообщения теперь не
теряются) не проводился.

## Найдено вживую 2026-08-13 (тот же раунд) — сворачивание приложения тихо душит фоновое соединение

Живьём: пока телефон был на переднем плане, всё работало (в том числе
после фикса `pingInterval`/`known_tokens` выше). Свернул приложение —
сначала входящие сообщения ещё доходили, а исходящие квитанции перестали
уходить; чуть позже перестало отвечать вообще; в итоге соединение
разорвалось целиком (снова офлайн по токенам) — и всё это **без единого
исключения в логе**.

**Причина**: `MessengerService` — корректный foreground-сервис
(`startForeground(..., FOREGROUND_SERVICE_TYPE_DATA_SYNC)`), но нигде в
проекте не запрашивалось исключение из battery optimization
(`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` — не было ни в манифесте, ни в
коде, подтверждено grep'ом по всему `app/`). Официальный
foreground-service-иммунитет от Doze/App Standby не всегда уважается
собственными батарейными менеджерами OEM-прошивок (в первую очередь
MIUI/Xiaomi) поверх стокового Android — без отдельного вайтлистинга
оболочка вправе придушивать фоновую сетевую активность процесса. Именно
поэтому не было исключений: запись в сокет просто зависала на уровне ОС
(не долетала до радиомодуля), а не падала с ошибкой на уровне Kotlin.

**Исправлено**: добавлен `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` в
манифест; в `ProfileScreen.kt` (секция "Общие", рядом с Tor) — новый
переключатель `profileBatteryUnrestricted`, открывающий системный диалог
`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` (одно окно
Разрешить/Отклонить, без многошаговой навигации по Settings, в отличие
от accessibility-сервиса для аварийного стирания). Состояние читается
через `PowerManager.isIgnoringBatteryOptimizations()` и пересинхронизируется
при возврате в приложение (`ON_RESUME`), тем же паттерном, что уже
использован для accessibility-тумблера. Обратного пути (программно
отозвать разрешение) у Android нет — при попытке выключить тумблер
пользователя отправляют в системный экран управления списком, руками.

## Найдено вживую 2026-08-16 — PQ-ключ контакта терялся при каждом рестарте сервиса

Живьём: свежая регистрация двух устройств, первый обмен сообщениями —
и почти сразу `sendEncrypted: нет PQ-ключа для <contact>, запрашиваем
бандл и откладываем`. Не разовая заминка бутстрапа — воспроизводится
регулярно ("постоянно теряется").

**Причина**: `publicKeysPq` (`MessengerService.kt`) — чисто in-memory
`mutableMapOf<String, ByteArray>()`, заполняется **только** в одном
месте (`handleFetchedPrekeyBundle()`, при получении prekey bundle от
сервера), и нигде не сохранялся на диск. Для сравнения — классический
EC-ключ (`publicKeys`) всегда падает назад на
`ChatStorage.getContactPublicKey()` при чтении. У PQ-ключа такого
резерва не было вообще ни у одного из ~11 мест чтения
(`sendEncrypted`, `sendVoice`, `sendReaction`, `sendEdit`, `sendImage`,
`sendFile`, `sendVideoCircle`, `sendAnonTokensTo`, три места раздачи
группового ключа). Значит **любой** рестарт `MessengerService`
(смерть процесса, OOM-килл, ребут телефона, ручной рестарт при
тестировании) обнулял кэш PQ-ключей для вообще всех контактов — даже
для тех, с кем переписка идёт давно — и заставлял заново гонять
prekey-bundle перед любой гибридно-шифрованной отправкой.

**Исправлено**: добавлены `ChatStorage.saveContactPqPublicKey()`/
`getContactPqPublicKey()` (base64, тот же паттерн, что у классического
ключа). Новый `MessengerService.resolvePqKey(contactId)` — читает
in-memory кэш, при промахе падает на персистентное хранилище и
досыпает кэш обратно; заменил собой все ~11 прямых чтений
`publicKeysPq[...]`. `handleFetchedPrekeyBundle()` теперь сохраняет
PQ-ключ на диск сразу же, как получает.

~~**Побочно найдено, не исправлено**: `processSessionInit()` не кэширует
PQ-ключ отправителя~~ — **done, тот же день, вторым проходом**.
Проверено по коду `SessionKeyManager.initiateSession()`: `x3dh_header`
несёт только `pq_kem_ciphertext` — PQ KEM-шифротекст, инкапсулированный
инициатором **против ключа получателя** (то есть против нас самих),
собственный публичный PQ-ключ инициатора в `x3dh_header` в принципе не
передаётся, доставать оттуда нечего. Единственный способ получить
PQ-ключ отправителя первого контакта — самим явно запросить его bundle.

Добавлено: `processSessionInit()` на успешном пути (после установки
сессии, там же, где уже был аналогичный проактивный прогрев —
`sendAnonTokensTo`, если у контакта нет токенов) теперь сам вызывает
`requestPrekeyBundle(from)`, если `resolvePqKey(from) == null` — не
дожидаясь, пока PQ-ключ понадобится для чего-то ещё (ответ через
`sendEncrypted`, реакция, раздача группового ключа) и пользователь
будет ждать лишний round-trip именно в этот момент. Функция общая для
прямой доставки `session_init` и для варианта через
`handleMailboxResult`'s `session_init_packet` — фикс автоматически
покрывает оба пути, второй caller ничего дополнительно менять не
потребовалось.

Desktop (`WebSocketClient.kt`, не в гите) имеет структурно тот же
паттерн (`peerPqPublicKeys`, in-memory) — не проверялся и не трогался в
этом проходе.

Compiles clean (`compileDebugKotlin`). Не тестировалось вживую
(специально убить/перезапустить сервис между двумя устройствами и
убедиться, что PQ-ключ не запрашивается заново; и отдельно — свежий
первый контакт и убедиться, что PQ-ключ отправителя появляется в кэше
сразу после session_init, а не только при первой попытке легаси-пути
отправки).

## Найдено вживую 2026-08-16 (тот же раунд) — токены безвозвратно терялись при обрыве связи в момент отправки

Живьём: 60-90 секунд без интернета — сообщения не доходят, хотя должны
были встать в очередь `token_pending` и прилететь при реконнекте (см.
находку про серверный `ping_interval=15`/`ping_timeout=30` чуть выше).
На практике — не долетает вообще ничего, и связь поднимается только
15-минутным health-check (`ContactHealthManager`), а не обычным
реконнектом.

**Причина — гонка в `sendAnonOrDirect()`/`sendWithForwardSecrecy()`/
`sendAnonTokensTo()`**: во всех трёх местах `AnonTokenManager.
consumeNextContactToken()` **необратимо** удаляет одноразовый токен из
локального пула **до** попытки отправки, а `sendWs()` до этой правки
была `Unit`-функцией — результат `webSocket?.send(json)` (тот самый
`Boolean`, которым OkHttp сообщает "сокет уже закрыт, кадр точно не
ушёл") нигде не проверялся. Если соединение уже мертво в момент вызова
(типичная ситуация во время обрыва) — токен списан локально, а пакет
никогда не покидает устройство. Сервер это сообщение вообще не видел —
значит, оно даже не попадает в ветку "офлайн, в очередь"
(`token_pending`), просто исчезает без следа с обеих сторон. Токен
потрачен впустую, повторной попытки с ним не будет.

**Исправлено**:
- `sendWs()` теперь возвращает `Boolean` — `true`, только если кадр
  реально ушёл (`webSocket?.send(json) ?: false`, либо `true` при
  постановке в `outboundQueue` для агрессивного cover-traffic — тот
  путь гарантированно досылает сам).
- `AnonTokenManager.restoreContactToken()` — новая функция, обратная
  `consumeNextContactToken()`: возвращает токен обратно в начало
  локального пула.
- `sendAnonOrDirect()` — если `!isConnected`, токен вообще не
  расходуется, пакет сразу уходит в уже существующую очередь
  `pendingAnonPackets` (общий helper `queuePendingAnon()`, вынесенный
  из дублировавшегося кода). Если соединение было живым, но `sendWs()`
  вернул `false` (гонка — умерло между проверкой и записью) — токен
  восстанавливается и пакет тоже уходит в очередь.
- `sendWithForwardSecrecy()` (свой отдельный inline `anon_message` для
  `session_init`/обычных сообщений с токеном) и `sendAnonTokensTo()`
  (сама функция дозаправки, тратит резервный токен) получили
  идентичную проверку — восстанавливают токен при `sendWs() == false`.

Compiles clean. Не тестировалось вживую (специально оборвать интернет
на 60-90 секунд во время активной переписки и убедиться, что пул
токенов не проседает и сообщения долетают после реконнекта, не дожидаясь
health-check).

## Найдено вживую 2026-08-16 (тот же раунд) — onLost() рвал только что восстановленное соединение

Живьём: выключил сеть на телефоне на 30 секунд, включил обратно. По
серверному логу — полный успешный реконнект (`register`/
`subscribe_tokens`/republish bundle), а через ~10 секунд после этого —
повторный дисконнект, без единой ошибки на клиенте. "Всё сломалось"
сразу после видимо успешного восстановления.

**Причина**: `MessengerService.registerNetworkCallback()`'s `onLost()`
безусловно закрывал WebSocket при потере **любой** отдельной сети
(`Network` — конкретный транспорт: WiFi ИЛИ мобильные данные), не
проверяя, есть ли вообще связь. `onLost()` в Android вызывается на
уровне конкретного `Network`-объекта, а не "интернета вообще" — при
переключении WiFi↔мобильные (обычное дело при включении/выключении сети
телефоном) система может сначала поднять один транспорт, а через
секунды — уронить другой, ранее активный, породив `onLost()` для
транспорта, который уже не главный, хотя реальная связь не
прерывалась ни на миг. Ровно тот же класс ошибки, что уже был найден и
исправлен для звонков (`CallManager`'s более терпеливый callback,
комментарий прямо над этим кодом) — просто фикс никогда не
зеркалился на основной WebSocket.

**Исправлено**: `onLost()` теперь проверяет `cm.activeNetwork != null`
перед закрытием сокета — если есть хоть какая-то активная сеть (пусть и
другая), соединение не трогается; реальный обрыв всё равно поймает
собственный ping/pong сокета (`pingInterval`, см. более раннюю правку в
этом же файле). Закрывает только если `activeNetwork == null` —
действительно нет сети вообще ни по одному транспорту.

Compiles clean. Не тестировалось вживую (повторить точно тот же
сценарий — выключить/включить сеть на 30 секунд — и убедиться, что
после успешного реконнекта соединение больше не рвётся само по себе
через несколько секунд).

## Найдено вживую 2026-08-17 — SessionKeyManager.initialize() гонялся на каждом реконнекте вместо одного раза за жизнь процесса

Живьём, с добавленным `DEBUG-TOKENLIFE`-логированием: сообщение не
дошло, а на принимающей стороне в логе — `session_init error: OPK 18
уже использован или не существует`. Отправитель при этом честно
показывал `X3DH сессия ... инициирована` с `isFirst=true` — то есть
устройство-отправитель почему-то решило, что сессии с давним контактом
ещё не существует, и завело новую, потратив чужой OPK.

**Побочно найдено при разборе**: в `MessengerService.kt`, в обработчике
успешного handshake'а —

```kotlin
if (!SessionKeyManager.hasSession("__init_check__")) {
    SessionKeyManager.initialize(this@MessengerService)
    ...
}
```

`"__init_check__"` — фейковый sentinel-fingerprint, под которым нигде в
`SessionKeyManager.kt` никогда не создаётся сессия (проверено grep'ом).
Значит условие постоянно истинно, и `initialize()` (проверка ротации
SPK, перезагрузка+дозаправка OPK-пула, полная перезагрузка всех сессий
с диска) гонялся **на каждом успешном реконнекте**, а не один раз за
жизнь процесса, как явно задумывалось по структуре кода (и как
подтверждает многократное повторение "SessionKeyManager
переинициализирован" в логах этой же сессии тестирования).

Не доказано на 100%, что это единственная причина конкретно этой
потери OPK 18 — `loadAllSessions()` при беглом чтении выглядит
идемпотентной (просто перечитывает персистентные сессии в map), но
раз сам факт "полная переинициализация чаще, чем задумано" — в любом
случае неправильный и лишний, независимо от того, объясняет ли он
целиком этот конкретный кейс.

**Исправлено**: заменил на настоящий флаг —
`private var sessionManagerInitialized = false`, выставляется в `true`
перед первым (и единственным) вызовом `initialize()`.
`reloadSessionsIfNeeded()` (отдельный механизм в
`SessionKeyManager.kt`/`StorageKeyManager.kt`, вызывается при
разблокировке приложения) не затронут — это независимый путь, не
завязанный на этот конкретный guard.

Compiles clean. Не тестировалось вживую — нужно повторить тот же
сценарий (реконнект/потеря сети у одной стороны, затем отправка
сообщения) и убедиться, что "SessionKeyManager переинициализирован"
теперь появляется в логе только один раз за всю жизнь процесса, а не
на каждом реконнекте, и что OPK-конфликт больше не воспроизводится.

**Доп. правка, тот же день**: разрешение теперь **запрашивается
проактивно** — новый одноразовый онбординг-шаг `BatteryOptimizationScreen.kt`
(`screen = "battery_optimization_prompt"`), встроен в цепочку регистрации
сразу после обязательной настройки TOTP, перед первым попаданием в
чаты: `register` → `totp_setup_required` (обязательный) →
`battery_optimization_prompt` (можно пропустить) → `chats`. В отличие от
TOTP — не блокирует: кнопка "Пропустить" ведёт дальше сразу, "Разрешить"
открывает системный диалог `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`
и продолжает при возврате в приложение (`ON_RESUME`) независимо от
выбора пользователя в диалоге — это подсказка, а не гейт. Добавлен в
списки исключений `lockVisible`/`RecoveryCodeGate` в `MainActivity.kt`
(тот же список, что и у `totp_setup_required`), чтобы поверх этого шага
не всплывали экран блокировки или recovery-code гейт. Существующим
пользователям (не через свежую регистрацию) шаг не показывается — доступ
только через Profile, как и было.

**Не сделано**: Desktop не тронут — там нет концепции Doze/battery
optimization. Compiles clean, не тестировалось вживую (специально
свернуть приложение на реальном MIUI-устройстве и убедиться, что
квитанции продолжают уходить после включения тумблера; и отдельно —
пройти полный онбординг с нуля и убедиться, что новый шаг показывается
в нужном месте и корректно пропускается/подтверждается).

**Доп. находка и правка, тот же день**: сервисное уведомление
(`CHANNEL_ID_SERVICE`, держит foreground-статус `MessengerService`) с
самого первого коммита создаётся с `IMPORTANCE_MIN` — без значка в
статус-баре, без звука. Это не баг сам по себе (осмысленный выбор:
не выдавать посторонним, что Subrosa вообще запущен), но `IMPORTANCE_MIN`
— это ещё и сигнал ОС "неважно", а по таким сигналам батарейные
менеджеры некоторых прошивок (MIUI и подобные) охотнее прибивают
фоновый процесс — тот же класс проблемы, что и с battery optimization
выше, просто другой рычаг.

**Решение — выбор пользователя, не смена дефолта.** Добавлен второй
канал `CHANNEL_ID_SERVICE_VISIBLE` (`IMPORTANCE_LOW`, тот же
беззвучный/безбейджевый набор флагов, отличается только важность —
значит, только видимость в статус-баре). `buildNotification()` выбирает
канал по `UserStorage.isServiceNotificationVisible()` (по умолчанию
`false` — сохраняет прежнее скрытое поведение для всех, не только для
новых установок). Новый тумблер в `ProfileScreen.kt` (General, сразу
под battery-optimization) — при переключении шлёт
`refresh_notification`-intent-extra уже запущенному сервису, который
тут же перевыпускает уведомление на новом канале (`notify()`), без
перезапуска приложения. Compiles clean, не тестировалось вживую.

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

- `ForEXP/server.py`'s `[DEBUG-MAILBOX]` `print()` statements were removed
  from the repo (Tier 1 item 1, above) — **not yet confirmed redeployed**
  to the live server, since this repo has no way to check that from here.
- ~~Cloudflare WebSocket-proxying is still broken~~ — **fixed** (commit
  `922c41a`). Root cause was never Cloudflare — a dead, pre-rebrand nginx
  block silently broke every reload, including for the correct
  `api.subrosamessenger.com:8443` vhost. `ServerManager.kt` now correctly
  points at `:8443` (Cloudflare-proxied), no override left to revert. See
  the updated troubleshooting note in `docs/DEPLOY.md` for the full
  explanation. Worth a one-time check that the DNS-only/grey-cloud bypass
  and relaxed nginx `allow` list from the old workaround were actually
  reverted on the live server — not verifiable from this repo.

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

   **Update — DONE** (see "Identity-rotation" entry in the Tier 2 item 6
   write-up above): user's final design skipped the "re-broadcast new
   fingerprint to every contact" / Signal-style safety-number UX entirely —
   deliberately cheap instead, just burn the identity and start over as a
   new account, no migration.

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
    ~~**Noted but not fixed**: Desktop's `handleFileChunk` doesn't verify a
    chunk signature at all~~ — **done, both `file_chunk` and
    `image_chunk`**. Added the same `senderKey`/`CryptoManager.verifyChunk(...)`
    check Android already had, right at the top of each handler before any
    chunk is buffered/decrypted — a malicious or compromised contact could
    previously inject arbitrary chunk data attributed to themselves with no
    valid signature required at all. Worth noting: the sending side signs
    via `DesktopCryptoManager.signChunk()` while verification uses
    `CryptoManager.verifyChunk()` — different class facades, but both
    ultimately resolve to the exact same `DesktopKeyStore`-backed keypair
    (`CryptoManager.getSoftwareKeyPair()` and `DesktopCryptoManager.keyPair`
    are the same key on disk), confirmed by reading through both before
    trusting the cross-class check. `video_chunk` has no handler on Desktop
    at all — that feature (video circles) doesn't exist there, nothing to
    fix. Compiles clean. Desktop isn't tracked in this repo.
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

13. ~~Cloudflare WebSocket-proxying root cause~~ — **done, was never
    actually a Cloudflare problem**. Commit `922c41a`: nginx's
    `api.subrosamessenger.com:8443` block was correct and working the
    whole time — the real breakage was an unrelated dead
    `api.beacon-app.org:4430` block earlier in the same
    `sites-available` file (stale from before the rebrand, cert path long
    gone), which failed `nginx -t` and silently blocked every reload from
    taking effect. `:4430` also isn't even one of Cloudflare's supported
    proxied HTTPS ports (443/2053/2083/2087/2096/8443) regardless of the
    cert issue. `ServerManager.kt` now correctly points at `:8443`
    (Cloudflare-proxied, orange-cloud) — the earlier DNS-only/grey-cloud
    bypass and relaxed nginx `allow` list are no longer needed and should
    be reverted if still active on the live server (not verified from
    this repo whether that cleanup happened server-side).
14. ~~Full palette unification (icon + in-app theme + website)~~ — **done**.
    **In-app Android theme (earlier pass)**: recolored all 3 themes in
    `SubrosaColors.kt` from the old navy/cyan scheme to a burgundy/gold
    family (accent `#D9A566` antique gold on dark themes, `#8A2A2A`
    burgundy accent on the cream light theme — gold reads poorly on white).
    Also swept ~10 screen files for hardcoded old-palette hex literals
    (`#141e4a`/`#0d1238`/`#091a66`/`#1F2B5E`/`#1A2550`/`#2A3B8F` navy tones,
    `#2481CC` blue, `#00E5FF` cyan) that bypassed the theme system entirely
    and replaced them with the new burgundy/copper/gold equivalents,
    including the first entry of the decorative multi-color avatar-palette
    lists (the other 5 avatar colors were left alone — intentional variety,
    not brand color).

    **Desktop (`BeaconTheme.kt`, defines the `SubrosaTheme` object — file
    itself was never renamed off the old brand)**: turned out to be an
    entirely separate, untouched **purple** ("Amethyst") palette that
    predated even the OLD navy/cyan Android scheme it was supposedly
    matching — never updated through either rebrand pass. Recolored to
    the same values as Android's `NavySubrosaColors` field-for-field where
    the fields match; the handful of Desktop-only fields with no Android
    equivalent (`textSecondary`, `divider`, `unreadBadge`, `readTick`,
    `sentTick`) got new values picked within the same burgundy/gold family
    rather than left purple. Single flat object, not a 3-theme enum like
    Android — Desktop has no theme switching. Grepped for stray hardcoded
    hex from the old purple palette bypassing `SubrosaTheme.*` — none
    found, everything already routed through the object. Compiles clean.
    Desktop isn't tracked in this repo (local-only, per project memory).

    **Website (`D:\website\v3`, separate, non-git directory)**: accent was
    still teal `#55B5A8` — every rule already routed through 4 CSS custom
    properties (`--accent`/`--accent-bright`/`--accent-soft`/
    `--accent-border`), so recoloring those to the gold family
    (`#D9A566`/`#E8C68F`/matching rgba) propagated everywhere in one edit.
    Found and fixed two more hardcoded `rgba(85,181,168,...)` teal values
    in a background radial-gradient that bypassed the variables, plus the
    `::selection` text color (was a dark teal-tinted `#061312`, now a dark
    warm brown `#1A1006` to match the new selection-background hue).
    Grepped for any other stray teal hex across all 6 HTML pages + CSS —
    none found.

    **Not done**: no live-device/browser visual or contrast-accessibility
    check on any of the three surfaces — this was a mechanical value swap,
    not a redesign pass.
15. ~~Optional server-side client access-list/allowlist~~ — **done**.
    Original note said "needs more thought" — turned out the real blocker
    was that a fingerprint-based allowlist is a chicken-and-egg problem
    (the operator has no way to learn someone's fingerprint before they've
    even installed the app). Reframed as **one-time access codes handed
    out by the operator**, distributed as a scannable QR/link, closes the
    same gap (private/business server rejects registration from anyone
    the operator didn't explicitly invite) without needing to know
    anything about the person in advance.

    **Server (`server.py`)**: off by default (`SERVER_ACCESS_PROTECTED`),
    personal self-hosting is entirely unaffected. When on, a fingerprint's
    **very first-ever** `register()` on this server (tracked in a new
    `registered_fingerprints` table, not the in-memory `clients` dict, so
    it survives restarts) must include a valid, unused `access_code` —
    never checked again on later reconnects, so it doesn't add friction to
    normal use once an account exists. Codes: `server_access_codes` SQLite
    table, one-time (consumed on first successful use), generated at
    startup (`SERVER_ACCESS_CODE_COUNT`) or any time later via new
    **`ForEXP/admin_gen_codes.py`** — writes straight into the same DB
    file, `register()` always reads it live, so no restart needed to add
    more (same "separate admin script" pattern as `admin_logs.py`). Both
    the startup printout and the script build a ready `subrosa://server?
    host=...&port=...&code=...` link via `SERVER_URL`, not just the bare
    code — the operator has something to turn into a QR immediately.
    Found one real bug only by actually running `admin_gen_codes.py`
    instead of just `ast.parse`-checking it: an arrow character in the
    printed output broke on a Windows console using a non-UTF-8 codepage.
    Fixed there and added the same UTF-8 stdout reconfiguration `server.py`
    already had to `admin_logs.py` too, which had the identical latent
    risk and was never actually run to catch it.

    **Client (Android only)**: `ServerManager.Server` gained an optional
    `accessCode` field, sent with every `register()` when present (client
    never decides whether it's required — that's entirely the server's
    call, matching the same principle as `totp_code`). "Add server"
    dialog (`ServersScreen.kt`) gained two new entry points alongside the
    existing manual text field: **scan with camera** and **upload a QR
    image file** (for someone who only has a phone and received the QR as
    a picture, not something to point a camera at) — both already
    possible with existing dependencies (`zxing-android-embedded` for the
    camera scanner, already used for contact invite codes; `zxing:core`
    for decoding an uploaded bitmap directly, no new library needed for
    either). Explicit error shown if no QR is found in an uploaded photo,
    or if a scanned/uploaded code isn't a recognizable `subrosa://server`
    link. Server-side rejection (`access_code_required`) surfaces as a
    visible Toast, not just a log line — unlike the device-gated TOTP's
    silent `totp_required` (an *existing* account being denied a new
    device), this is typically a brand-new user staring at the register
    screen right now.

    **Follow-up, same session**: pointed out that pasting the link into a
    third-party online QR generator would itself be a metadata leak (the
    code + server address handed to some random website). Fixed —
    optional `qrcode[pil]` dependency (commented out by default in
    `requirements.txt`, not needed for personal self-hosting), imported
    with a graceful `try/except` fallback in both `server.py` and
    `admin_gen_codes.py`. When available, every generated code gets a
    PNG rendered **entirely offline, locally, on the server itself** — no
    network call, nothing leaves the machine — saved to `access_codes_qr/`
    (path overridable via `ACCESS_CODE_QR_DIR` for `server.py`'s own
    startup generation, `--out-dir` for the script) and gitignored.
    Without the dependency installed, behavior is unchanged — text link
    only, with a one-line hint about how to enable images. Verified live
    (not just `ast.parse`): loaded `server.py` as a module, called
    `build_access_link()` + `save_access_code_qr()` directly, confirmed a
    real PNG got written to disk — same for `admin_gen_codes.py`'s
    equivalent path, both with `qrcode[pil]` actually installed in this
    session to test, then removed again afterward (optional dependency,
    not meant to be always-installed).

    **Not done**: Desktop (no camera-scan UI there, out of scope this
    pass); the client's manual-entry field doesn't currently parse the
    `subrosa://` URI form, only bare host/host:port/wss:// — a gap worth
    closing later so the raw text link alone is enough without a QR image
    at all, for someone who'd rather just paste text. `compileDebugKotlin`
    + `ast.parse` + several live functional runs (code generation, link
    building, SQLite persistence, and now local QR-PNG rendering) all
    green. No live two-device registration test against a running
    protected server.

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
6. ~~**`file_name` в открытом виде в `file_chunk`**~~ — **done, обе
   платформы**. Реализован второй вариант из двух предложенных: имя
   файла теперь шифруется тем же гибридным (classic+PQ) `CryptoManager.encrypt`,
   что уже применялся для текста сообщений (самодостаточная схема — не
   требует существующей Double Ratchet-сессии, только ключи получателя),
   вычисляется **один раз** до цикла чанков и одно и то же значение
   `encrypted_file_name` кладётся в каждый чанк (не пересчитывается
   заново на чанк). Получатель расшифровывает при получении первого
   чанка передачи, кладёт результат в `FileMeta`, санитизирует
   (`sanitizePathComponent`) уже после расшифровки. Легаси-фоллбек:
   если пакет пришёл без `encrypted_file_name` (старый пир), берём
   старое поле `file_name` как есть, а если и его нет — родовое `"file"`.
   `image_chunk` не тронут (у фото нет имени файла как атрибута, утечки
   там не было и раньше).
7. ~~**`sendVoice` ломает воспроизведение при отсутствии ключа**~~ —
   **done, но нашлась не там, где искали**. Оказалось, что три из четырёх
   мест, где `pendingSessionMessages` разбирается на отправку
   (`handleFetchedPrekeyBundle`, все три ветки — success/`SecurityException`/
   generic `catch`), **уже** правильно распознают префикс `__voice__|` и
   вызывают `sendVoice()` заново, а не шлют как текст — это, видимо, было
   починено в более ранней сессии, документация просто не была обновлена.
   Реальный, всё ещё живой баг был в **четвёртом** месте — обработчике
   входящего `session_init` (когда контакт сам инициирует сессию, пока у
   нас есть что-то в очереди в его адрес): там `pendingSessionMessages`
   разбирался без проверки префикса и шёл прямиком в
   `sendWithForwardSecrecy` как обычный текст. Починено тем же паттерном,
   что и в остальных трёх местах. Desktop голосовые сообщения по сети
   вообще не отправляет (только локальная запись, `VoiceRecorder.kt`) —
   нечего чинить.
8. ~~**`MessengerService` не перезапускается после импорта бэкапа на уже
   активном устройстве**~~ — **done**. `BackupScreen.kt` после успешного
   `importBackup()` теперь делает `stopService`+`startForegroundService`
   для `MessengerService` — тот же паттерн, что уже используется в
   `ServersScreen.kt` при смене сервера. `onStartCommand()` пересчитывает
   `username` из (уже нового) ключа с нуля, закрывает окно рассинхрона
   `from`-поля и ключа подписи.
9. ~~**`session_init` тихо откатывается на прямую адресацию**~~ —
   **done, Android**. Прямой недокументированный обработчик `"session_init"`
   вынесен в переиспользуемую `processSessionInit()` — то же самое, что
   было, без изменений в логике, только форма. В `sendWithForwardSecrecy()`
   ветка `isFirst` без анон/bootstrap-токена больше не шлёт пакет прямо —
   вместо этого `depositSessionInitViaMailbox()` кладёт **весь** пакет
   session_init (x3dh-заголовок + forward-secrecy шифротекст) как
   `session_init_packet` внутрь обычного mailbox-депозита (тот же
   классический ECDH-слой, что уже используется для депозита токенов).
   `handleMailboxResult()` теперь распознаёт это поле и прогоняет
   вложенный пакет через тот же `processSessionInit()`, что и прямая
   доставка — получатель заканчивает с идентичным состоянием сессии
   независимо от пути доставки. Если нет ни токена, ни mailbox-тега
   (редкий legacy-случай — контакт добавлен без инвайт-кода/тега, до
   введения текущей схемы) — остаётся прямая адресация как последний
   резерв, с явным warning в логе; не решалось строить полноценную
   очередь-до-появления-тега для этого редкого случая, отмечено как
   осознанно нерешённый хвост.

   **Desktop уже был в порядке** — там `session_init` (`initiateAndSend()`)
   и так шёл через `sendAnonOrDirect()`, а не через отдельную инлайн-копию
   логики, как на Android — а `sendAnonOrDirect`'s прямой fallback был
   убран ещё в более раннем проходе этой же сессии (см. "Decided: remove
   sendAnonOrDirect's direct fallback entirely" выше в этом файле).
   Ничего чинить не пришлось.

   **Побочно найдено, не в скоупе этого пункта — но починено позже,
   отдельным проходом**: та же функция `sendWithForwardSecrecy()` на
   Android имела **симметричный** прямой fallback и для обычных,
   не-первых сообщений — если анон-токены заканчивались у уже
   установленной сессии, туда тоже тихо уходила прямая адресация, тем же
   классом проблемы, что и у `session_init`, просто чаще (на любое
   сообщение, не только первое). ~~Не решено при этом проходе~~ —
   **исправлено**: `else`-ветка теперь вызывает `sendAnonOrDirect(to,
   packet)` вместо прямого `sendWs(...)`, то есть при пустом пуле токенов
   пакет встаёт в очередь (`pendingAnonPackets`) и уходит через тот же
   queue-and-retry путь, что и всё остальное — комментарий в коде
   (`MessengerService.kt`, конец `sendWithForwardSecrecy`) подтверждает,
   что это было найдено вживую по логу сервера ("[MSG] message delivered"
   при пустом пуле токенов), не просто теоретически. Эта заметка была
   единственной оставшейся стале-версией — код давно починен, просто
   запись в этом файле не была обновлена.
10. ~~**Session_reset после восстановления бэкапа**~~ — **done**.
    `consumePendingPqMigrationContacts()`, упомянутая в исходной заметке,
    в коде не нашлась (похоже, была из более ранней идеи, так и не
    реализованной под этим именем) — вместо неё написан похожий, но
    новый паттерн: `BackupManager.importBackup()` при восстановлении
    контактов сохраняет их список через новую
    `UserStorage.setPendingSessionResetContacts()`; `MessengerService`
    подхватывает и чистит этот список **один раз**, на первом же успешном
    `handshake_ok` после (форсированного тем же фиксом item 8) рестарта —
    удаляет локальную сессию (если есть) и рассылает `session_reset`
    каждому восстановленному контакту.

### Тир 3 — нужно решение по дизайну до того, как писать код

11. ~~**"Война переподключений" при `session_conflict`"**~~ — **done, но
    решено принципиально иначе, чем вопрос был поставлен**. Вместо UX-
    решения "что показывать при конфликте" — закрыт сам источник
    конфликта. Пользователь заметил: клиентская backup-import TOTP-
    защита (Tier 4, п.15) не закрывает вектор до конца — атакующий с
    файлом бэкапа и паролем может расшифровать его **своим скриптом**,
    вытащить сырой приватный ключ и зарегистрироваться **напрямую**,
    в обход приложения и его проверки кода. Единственный способ закрыть
    это по-настоящему — проверка на сервере при `register()`. Но
    предыдущая попытка такой проверки (Tier 4 текст ниже, "MVP") требовала
    код на **каждый** `register()`, что ломает обычные реконнекты.

    Решение: сервер сравнивает `device_id` с уже активной сессией
    fingerprint'а (это и есть условие, при котором и так рождался бы
    `session_conflict`) и требует TOTP-код **только когда `device_id`
    новый**. Реконнект с уже известного устройства кода не спрашивает
    вообще — обычный UX не затронут. Новое устройство (включая
    самодельный клиент атакующего в обход приложения) зарегистрироваться
    без кода не может — а значит войны переподключений просто не
    возникает, вытеснять нечем.

    Один и тот же секрет, что у backup-import TOTP (`TotpManager.kt`) —
    легитимное новое устройство уже знает его, если бэкап был
    восстановлен через приложение (`BackupManager.importBackup()` уже
    вызывает `TotpManager.enable()` при успехе), отдельного UI вводить
    код не потребовалось. `MessengerService.register()` теперь
    безусловно кладёт `totp_code`, если секрет есть локально — сервер
    сам решает, актуален ли он в данный момент (реконнект — игнорирует,
    новое устройство — проверяет).

    **`server.py`**: `user_totp_secrets`/`user_totp_last_counter` (та же
    RFC 6238 математика, что уже была), таблица SQLite `user_totp`,
    `totp_setup` (одноразовая привязка, без пути перезаписи) /
    `totp_disable` (нужен текущий код) — восстановлено почти дословно из
    более раннего (неверно заскоупленного) захода, только условие
    проверки в `register()` изменено с "всегда" на "только при новом
    `device_id`".

    **Побочно найдено и исправлено**: `git checkout ce007a7 --
    ForEXP/server.py`, которым в одной из прошлых сессий откатывались
    неверные попытки TOTP, случайно уничтожил **другую**, не связанную
    с TOTP и никогда не закоммиченную фичу — видимый FCM-пуш при
    `session_conflict` (`send_fcm_session_conflict`, `ts` в пейлоаде),
    написанную ещё до начала этой сессии. `ce007a7` никогда не касался
    `server.py` (первый коммит этой сессии, Tier 1, чисто Android), то
    есть чек-аут откатил файл к состоянию **до** этой несохранённой
    работы, не просто до "чистого" TOTP-состояния. Восстановлено вручную
    из истории git (сохранялось в коммитах e101223/ed2f443 по пути,
    прежде чем было потеряно) — `send_fcm_session_conflict()` на месте,
    `register()` снова передаёт `ts` и триггерит пуш при вытеснении.
    Android-сторона (`MessengerService.kt`) эту часть уже поддерживала
    (парсинг `ts` из WS-сообщения) — не пострадала, там правился только
    `server.py`.

    Compiles clean (`compileDebugKotlin` + `ast.parse`). Live-тест не
    проводился.
12. ~~**Health-check контактов через 15 минут тишины**~~ — **done**,
    реализован как часть фикса item 1 в разделе "прямая адресация, не
    через анон-токен" выше (`ContactHealthManager.kt`).
13. ~~**5-минутный ретрай + тикет разработчику при первом контакте**~~ —
    **done**. Проверка текущего кода перед реализацией показала: retry
    уже был — `bootstrapChannelFor()` ретраит бесконечно (3×30с, потом
    каждые 90с без верхней границы), сильнее исходного дизайна ("сдаться
    через 5 минут"). Решили **не сдаваться** (бесконечный retry остаётся
    как задел на случай самовосстановления), а на отметке 5 минут без
    успеха добавить то, чего не было вообще: (а) уведомление пользователю
    ("Не удаётся установить связь", тап открывает чат) и (б) "тикет" —
    не автосвязь с разработчиком (пользователь прямо сказал, что
    хардкодить это плохая идея), а просто чётко помеченная строка в логе
    сервера (`[TICKET] ...`), которую разработчик (он же оператор
    сервера) найдёт сам через уже готовый `ForEXP/admin_logs.py`, когда
    будет разбираться. Пакет `bootstrap_diagnostic` намеренно не несёт
    ни контакта, ни любого таргет-идентификатора — только сам факт "у
    этого аккаунта завис первый контакт", иначе тикет стал бы утечкой
    ровно той метаданных, которую весь mailbox-механизм должен скрывать.
    Rate-limit на сервере (5/60с) на случай спама. Срабатывает один раз
    на контакт (`channelStuckNotified`), сбрасывается при
    `markChannelReady()`. Compiles clean.
14. ~~**Смешение identity при импорте бэкапа на уже используемое
    устройство**~~ — **done, обе платформы**. Решение по продукту:
    вся логика бэкапов отвечает на вопрос "потерял телефон/сделал сброс —
    могу я вернуть данные", не "откатиться к старой истории поверх уже
    активной identity" — последнее осознанно решили не поддерживать.
    Реализован **полный автовайп перед импортом, с предупреждением**:
    новая `BackupManager.wipeCurrentIdentityData()` чистит контакты,
    сообщения, группы, Double Ratchet-сессии и анон-токены/mailbox-теги
    текущей identity **перед** записью данных из бэкапа — но не трогает
    настройки уровня устройства (тема, язык, dead man's switch и т.п.),
    это не security-вайп (`WipeManager`), а замена identity. UI (`BackupScreen.kt`
    на Android, диалог в `ProfileScreen.kt` на Desktop) требует явного
    подтверждения предупреждения перед запуском импорта.

    **Побочно найден и исправлен реальный баг, не только дизайн-вопрос**:
    в `BackupManager.importBackup()` (обе платформы) `username`/`userId`
    захватывался **до** перезаписи identity из бэкапа, а не после —
    восстановленные сообщения/группы сохранялись под ключом storage,
    завязанным на **старую** identity (`ChatStorage.chatKey()` включает
    `myUserId`), и становились невидимыми после того, как приложение
    начинало работать под новой. Перенёс захват после блока
    `ec_private_key`/`ec_public_key`.

    **Desktop**: тот же паттерн — `wipeCurrentIdentityData()` (новые
    `ChatStorage.clearAll()`/`GroupManager.clearAll()`/
    `AnonTokenManager.clearAll()`/`SessionKeyManager.deleteAllSessions()`),
    тот же порядок фикс для `userId`. Desktop не в гите (см. память
    проекта), эта часть работы осталась локальной.

    Compiles clean на обеих платформах. Live-тест не проводился.

### Тир 4 — большое/опциональное, не срочно

15. ~~**TOTP 2FA на бэкап**~~ — **MVP сделан, Android-only изначально;
    проверка на импорте теперь есть и на Desktop** (см. п.14 выше) — до
    этого перетаскивание TOTP-защищённого бэкапа на Desktop **полностью
    пропускало проверку кода**, `importBackup()` там вообще не смотрел на
    `totp_enabled` — файла+пароля было достаточно, второй фактор не
    действовал. Новый `desktop/TotpManager.kt` (тот же RFC 6238) закрывает
    это конкретно для импорта; полноценного UI для *включения* TOTP на
    Desktop (аналог `TotpSettingsScreen.kt`) по-прежнему нет — секрет для
    Desktop-проверки нужно вводить вручную (то же поле, что уже есть для
    импорта). Оригинальный текст ниже — про Android. Новый
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
    паттерн подходит один в один).

    ~~Восстановление при утере TOTP-секрета (сейчас это тупик...)~~ —
    **done, 2026-08-13**. Решение: переиспользовать те же 8 резервных
    кодов, что сервер и так выдаёт при включении TOTP (`totp_setup`,
    `generate_recovery_codes()` в `server.py`) — раньше они годились
    только для обхода device-gated `register()`, теперь их хэши (не сами
    коды — тот же принцип, что и с секретом) дополнительно сохраняются
    локально (`TotpManager.saveRecoveryCodeHashes`, SMK-обёрнуто) и
    кладутся в сам экспортируемый бэкап (`totp_recovery_hashes`, только
    хэши). `BackupManager.importBackup()` получил новый опциональный
    параметр `recoveryCode` — если секрет+код не сработали, но код
    совпадает с одним из хэшей внутри бэкапа, импорт продолжается без
    секрета, но TOTP-защита на новом устройстве остаётся выключенной
    (не включается вслепую со старым, возможно скомпрометированным
    секретом) — сообщение об успехе явно просит включить TOTP заново, тот
    же принцип, что и в серверном device-gated recovery-flow. UI:
    `BackupScreen.kt` получил третье, опциональное поле "резервный код"
    рядом с секретом/кодом. Compiles clean. Desktop не тронут (см. выше).
    Live-тест на реальном устройстве не проводился, только
    `compileDebugKotlin` зелёный.

    **Живой тест, 2026-08-10 — найден и исправлен UX-баг в
    `TotpSettingsScreen.kt`.** Секрет создавался и включался на сервере
    успешно, но экран не показывал вообще никакой индикации ожидания
    (`busy` только гасил кнопку, без текста/спиннера) — после ввода кода
    подтверждения экран выглядел зависшим, пользователь решил, что код не
    принят, хотя `sendTotpSetup()` уже ушёл и сервер его в итоге принял
    (`onTotpSetupResult` обновляет состояние асинхронно, по round-trip
    через WebSocket). Только при повторном заходе на экран
    (`TotpManager.isEnabled()` читается заново при открытии) стало видно
    "включено". **Исправлено**: добавлен явный индикатор
    (`CircularProgressIndicator` + текст "Подтверждаем с сервером —
    подождите...") при `busy == true`, и на включении, и на отключении.
    Не исправлена (и не была целью) сама асинхронность — это ожидаемо,
    раз подтверждение требует round-trip до сервера; закрыт именно
    UX-пробел "непонятно, что происходит", а не сама задержка. Compiles
    clean, повторного живого теста фикса пока не было.

    **Опциональное шифрование TOTP-секрета в БД сервера — сделано,
    2026-08-10.** Пользователь спросил, что именно хранит сервер и есть
    ли тут проблема с защитой. Ответ: сервер обязан держать сырой
    (не хешированный) секрет — иначе не сможет сам считать код для
    сверки, это неотъемлемое свойство TOTP, не недосмотр. До этой правки
    он лежал открытым текстом и в памяти (`user_totp_secrets`), и в
    SQLite (`user_totp.secret`). Полный компромисс живого сервера всё
    равно обесценивает шифрование (проверку можно просто выпилить из
    кода), но узкий сценарий — утечка **именно файла БД** (украденный
    бэкап/снапшот диска) без контроля над живым процессом — шифрование
    закрывает. `server.py`: новая опциональная `TOTP_SECRET_ENCRYPTION_KEY`
    (Fernet-ключ), функции `_totp_encrypt_for_storage`/
    `_totp_decrypt_from_storage`, префикс `"fernet1:"` для прозрачной
    миграции (тот же принцип, что `StorageKeyManager.SMK_PREFIX` на
    клиенте) — старые открытые строки в БД продолжают читаться, попутно
    перешифровываются при следующем сохранении этого аккаунта. Без
    переменной — поведение не меняется (открытый текст, как раньше).
    Задокументировано в `.env.example`, с явным предупреждением держать
    ключ отдельно от того, что бэкапит саму БД. `ast.parse` +
    живой sanity-тест `Fernet` зелёные, полноценный live-тест на VPS не
    проводился.

    **Второй, отдельный слой — заняло три захода, каждый следующий ближе к
    реальной цели, записано как есть для будущих сессий:**
    1. Первая формулировка ("TOTP для сервера, один секрет на главный
       аккаунт") реализована буквально — TOTP-код на каждый `register()`
       мессенджер-аккаунта. **Неверно**: пользователь указал, что цель —
       защита чтения логов, а требовать код на каждое подключение убило
       бы UX (мобильная сеть переподключается постоянно).
    2. Уточняющий вопрос (что именно защищаем в "чтении логов") — ответ
       "доступ админа к самим файлам/процессу логов на сервере". Реализован
       **второй** заход — тоже через мессенджер-протокол: специальный
       `ADMIN_FINGERPRINT`-аккаунт, WebSocket-команда `admin_get_logs`,
       экран в приложении. **Тоже неверно** — пользователь прямым текстом:
       "человек админ заходит на впс, дальше чтобы ввести команду на чтение
       логов ему нужен TOTP... в самом мессенджере нет TOTP нигде". То есть
       весь функционал должен жить **вне мессенджера полностью** — ни в
       клиенте, ни в `server.py`/WebSocket-протоколе.
    3. **Финальная, реализованная версия**: отдельный, ничем не связанный с
       мессенджером инструмент **`ForEXP/admin_logs.py`** — админ заходит
       на VPS как обычно (SSH/консоль, это НЕ защищено этим инструментом,
       см. отдельный, ещё не выполненный Tier 3 п.7 про SSH), и вместо
       `docker-compose logs` напрямую запускает этот скрипт, который
       требует TOTP-код перед тем, как выполнить чтение. Угроза, от
       которой защищает: не "чужой человек без доступа к машине", а
       "у кого-то есть shell-доступ (украденный SSH-ключ, оставленная
       сессия, физический доступ к уже открытому терминалу), но нет
       TOTP-устройства админа" — тогда логи всё равно недостижимы.

    Что откачено обратно из заходов 1 и 2 (полностью, до состояния "как
    было до этой сессии"): `server.py` (`git checkout` на коммит с Tier 1
    фиксами, где ни один из TOTP-заходов ещё не существовал — проверено,
    diff пустой), `.env.example` (убран `ADMIN_FINGERPRINT`),
    `MessengerService.kt` (убраны `sendTotpSetup`/`sendTotpDisable`/
    `sendAdminGetLogs`, все соответствующие обработчики и колбэки,
    `totp_required`/`totpRequiredNotified`), `TotpManager.kt` (убран
    весь `server_totp_prefs`-неймспейс, остался только backup-import
    TOTP из исходного, подтверждённого фикса), `ServerTotpSettingsScreen.kt`
    (файл удалён целиком), `ProfileScreen.kt`/`MainActivity.kt` (убрана
    вся навигация к удалённому экрану), строки в `AppStrings.kt`.
    **Backup-import TOTP (первый, подтверждённый Tier 4 фикс) не тронут
    вообще** — это отдельная, уже согласованная защита, никак не связана
    с этой находкой.

    Финальная реализация (`ForEXP/admin_logs.py`, ~200 строк, без внешних
    зависимостей — тот же ручной RFC 6238, что уже был в `TotpManager.kt`/
    `server.py`, просто на этот раз в отдельном скрипте):
    - `setup` — генерирует секрет, печатает его + `otpauth://` URI,
      просит текущий код для подтверждения перед сохранением (защита от
      сохранения опечатки). Секрет — в `~/.subrosa_admin_totp` (права
      600, путь переопределяется `SUBROSA_ADMIN_TOTP_FILE`), **не** в
      репозитории. Повторный `setup` без `--force` — отказ; `--force`
      требует текущий код (тот же принцип "нельзя перевыпустить втихую",
      что был в предыдущих заходах, просто теперь локально, не через
      сеть).
    - `logs` — просит текущий код, при совпадении выполняет либо
      `docker-compose logs --tail=N <service>` (по умолчанию, дефолтный
      сервис `subrosa-server` из `docker-compose.yml`), либо чтение
      хвоста произвольного файла (`--source file --log-file PATH`) —
      оба варианта явно запрошены пользователем ("сделай и там и там").
      Простая защита от подбора кода — после 3 неверных попыток подряд
      скрипт сам ждёт 30 секунд перед следующей попыткой (локальный
      файл `<secret>.fails`, не связан с сервером).
    - Задокументировано в `docs/DEPLOY.md`, новый раздел "Reading logs
      with a TOTP gate", рядом с существующим "View Logs".

    Проверено: чистый Python-модуль импортируется и запускается,
    сгенерированный код проходит собственную проверку (`totp_code_matches`)
    вживую (не только `ast.parse`) — единственная часть этой находки,
    которая реально исполнялась, а не только компилировалась. Полный
    CLI-флоу (`setup`/`logs` с реальным вводом, реальный
    `docker-compose logs`) не прогонялся.

    **Не сделано**: восстановление при утере секрета — `setup --force`
    сам требует текущий код, так что если и секрет, и доступ к текущему
    коду потеряны одновременно — восстановления нет, это осознанный
    компромисс (тот же принцип, что и у backup-import TOTP), но нигде не
    предупреждён явно при первом `setup`. Desktop не тронут (не имеет
    отношения — это чисто серверный инструмент).
16. **Decoy-боты с реальным трафиком** — опциональный модуль, дизайн
    зафиксирован с оговорками (см. секцию выше), но это отдельная
    инфраструктурная задача (боты, VPS, поведенческая реалистичность) —
    не для быстрой реализации.
17. **Explicit "я думаю, меня скомпрометировали" флоу** — старый пункт
    из "Candidate fixes", завязан на решение по Тиру 3 пункт 11 (война
    переподключений) — логично делать вместе с ним, не раньше.

---

## Триаж оставшихся `❓` из SCENARIOS.md — известное решение vs неизвестное, по возрастанию сложности

Снимок на 2026-08-09, после ревизии `docs/SCENARIOS.md`. Каждый пункт —
ссылка на конкретную ветку сценария, не абстрактная идея.

### A. Знаем, как чинить — от простого к сложному

**A0 — не баги, уже реализовано, подтверждено перепроверкой кода
(не путать с "не начато"):**
- Судьба старых Double Ratchet-сессий устройства при восстановлении
  бэкапа на уже активном устройстве — **подтверждено закрытым**,
  SCENARIOS.md поправлен. `wipeCurrentIdentityData()` безусловно вызывает
  `SessionKeyManager.deleteAllSessions()` перед импортом на любом
  устройстве.
- "Бэкап не переносит состояние сессий → входящие не расшифруются" —
  **подтверждено закрытым**. `setPendingSessionResetContacts`/
  `getAndClearPendingSessionResetContacts` рассылают `session_reset`
  восстановленным контактам после импорта.

~~**A1 — тривиально: `group_reaction` без подписи, `Level.SOFT`**~~ —
**оба пункта ложная тревога, уже были закрыты раньше этой же сессии
документации** (см. п.3/п.4 выше в этом файле — `Level.SOFT` выпилен
вместе с вводящей в заблуждение карточкой в `WipeSettingsScreen.kt`,
`group_reaction` проверяет подпись в `MessengerService.kt:2083`).
Продублировал их сюда по невнимательности — не перечитал середину этого
же файла перед тем, как писать триаж. Оставлено как урок: перепроверять
код, а не полагаться на память о более раннем прогоне SCENARIOS.md.

~~**A2 — `file_name` открытым текстом, голосовые через чужую очередь,
дубли при повторном импорте бэкапа**~~ — **перепроверено 2026-08-10, все
три пункта ложная тревога, уже были закрыты раньше этой же сессии
документации** (тот же урок, что с A1 — не перечитал код перед тем, как
писать триаж):
- `file_name` уже уходит как `encrypted_file_name`, зашифрованный тем же
  гибридным ключом, что и `data` (`MessengerService.kt:3131`). Открытое
  поле `file_name` — только legacy-fallback для пакетов от клиентов до
  фикса.
- Голосовые сообщения — все точки flush `pendingSessionMessages` уже
  проверяют префикс `"__voice__|"` и вызывают `sendVoice()`, а не
  проталкивают текст напрямую. Дизайн всё ещё немного хрупкий
  (дублированная проверка в нескольких местах, а не отдельная очередь),
  но сам баг не воспроизводится.
- Повторный импорт того же бэкапа не дублирует историю — `wipeCurrentIdentityData()`
  стирает предыдущие сообщения перед КАЖДЫМ импортом, включая повторный
  импорт одного и того же файла.

**A3 (было "средняя сложность", теперь — тоже перепроверено и закрыто)**:
- ~~Групповой чат: при добавлении участника остальные не узнают о нём~~
  — **закрыто**. `group_create` несёт полный подписанный
  `members`/`admins`/`roster_signature` (`MessengerService.kt:4440`),
  плюс широковещательный `group_member_added` существующим участникам
  (`MessengerService.kt:4460`), с проверкой, что отправитель —
  админ группы. См. правку в SCENARIOS.md, сценарий "создание группы".
- ~~Война переподключений для аккаунтов без TOTP~~ — **закрыто иначе,
  чем планировалось, 2026-08-10**. Вместо того чтобы чинить сам
  `session_conflict`-обработчик (путь решения из предыдущей ревизии
  всё ещё технически валиден и не сделан), пользователь предпочёл
  убрать саму предпосылку — **TOTP теперь обязателен для каждого нового
  аккаунта**, не опционален. См. новый раздел "Обязательный TOTP при
  регистрации + recovery-коды" ниже — closes this по факту (аккаунт без
  TOTP просто больше не может существовать, если создан после этой
  правки), но не по методу, которым изначально предполагалось (сам
  `connect()`-цикл всё ещё безусловно переподключается после
  `session_conflict` — это по-прежнему технически верно для **уже
  существующих** аккаунтов без TOTP, созданных до этой правки).

~~**A4 — конкурентность на сервере: OPK может быть выдан дважды**~~ —
**тоже ложная тревога, перепроверено.** `get_prekey_bundle` и
`federated_get_bundle` оба читают и `pop(0)` внутри одного и того же
`async with lock:` (`server.py:35`, единственный глобальный
`asyncio.Lock()`), без единого `await` внутри критической секции — в
asyncio с одним потоком это значит настоящую атомарность, второй
"одновременный" запрос физически не может увидеть тот же OPK. Никакой
`get_prekey_bundle`-race в текущем коде нет.

  Найден при перепроверке куда более узкий, отдельный момент, ниже
  приоритетом: сохранение обновлённого состояния OPK в БД
  (`db_save_bundle`) запускается **после** выхода из лока, фоновой
  `asyncio.create_task` — если сервер упадёт в окне между "OPK убран из
  памяти" и "записано на диск", после рестарта этот же OPK может
  оказаться выдан повторно. Это durability-гэп при падении/рестарте, не
  concurrency-баг под нагрузкой — низкий приоритет, не требует
  архитектурных изменений, только сделать запись в БД синхронной
  (внутри того же лока) вместо fire-and-forget задачи, если вообще
  когда-нибудь понадобится.

  **Ещё более узко, чем казалось**: даже если этот durability-гэп
  сработает и сервер повторно выдаст уже использованный OPK — клиент
  уже сам это ловит. `SessionKeyManager.consumeOpk()` возвращает `null`
  для уже потреблённого локально OPK, `receiveSession()` синхронно
  бросает `SecurityException` прямо в момент handshake (не позже, не
  "ошибкой расшифровки"), а `processSessionInit()` в `MessengerService.kt`
  уже ловит это и самовосстанавливается — запрашивает свежий bundle и
  шлёт `session_reset` отправителю. Никакой новой "сверки на клиенте" не
  нужно писать — она уже есть и уже реагирует правильно.

### B. Не знаем, как чинить полностью — нужно исследование или решение по продукту

~~**B1 — `WipeManager.Level.SOFT`**~~ — **снято, вопрос не стоит**:
`Level.SOFT` уже удалён из кодовой базы целиком (см. правку в категории
A1 выше) — решение по продукту "он нам не нужен" уже принято и
реализовано раньше, нового решения принимать не о чем.

**B2 — зависит от поведения ОС, решение, скорее всего, "жить с
ограничением", а не фикс кода:**

Перепроверил код перед тем, как писать это заново: `scheduleFireAlarm()`
(`DeadMansSwitchManager.kt:77`) считает `triggerAt = lastCheckin +
intervalMinutes` — **не** "сейчас + интервал". Значит если устройство
было выключено дольше интервала, на момент включения `triggerAt` уже в
прошлом, и `setExactAndAllowWhileIdle` в этом случае должен сработать
почти сразу после загрузки, а не через ещё один полный интервал. Логика
в коде уже правильная — просто не прогонялась вживую.

То, что реально не гарантировано кодом (ограничения ОС, не наш баг):
1. **`BOOT_COMPLETED` может не дойти вообще** — если приложение когда-
   либо было force-stop'нуто (пользователем или системой), Android с
   3.1 намеренно блокирует доставку `BOOT_COMPLETED` этому приложению,
   пока пользователь не откроет его вручную хотя бы раз. Обойти нельзя,
   это защита ОС от автозапуска вредоносного ПО.
2. **OEM-специфичные "диспетчеры автозапуска"** (MIUI/Xiaomi, Huawei,
   часть Samsung) могут убивать фоновые будильники/приёмники, даже
   когда голый AOSP API это разрешает — системного API проверить или
   обойти это нет, только просить пользователя вручную разрешить
   автозапуск (не в этом приложении сделано).
3. **Android 12+ требует `SCHEDULE_EXACT_ALARM`** — код уже откатывается
   на `setAndAllowWhileIdle`, если разрешения нет (`scheduleExact()`),
   но неточный вариант система может отложить непредсказуемо в Doze.

Путь вперёд: либо живое исследование на нескольких прошивках (дорого,
не гарантирует покрытия всех OEM), либо явно задокументировать для
пользователя как известное ограничение — "сработает почти сразу после
включения телефона при штатных настройках, но не гарантированно на
агрессивно урезающих фон прошивках без вручную выданных разрешений".

### Не из SCENARIOS.md, но тоже открыто (для полноты)
- 16 KB page-size совместимость нативных библиотек — известно, что
  делать (обновить зависимости на NDK r27+/r28 сборки), но не начато,
  осознанно не приоритет.
- Desktop: `onChannelError` — не глобальный баннер, только диалог
  создания канала подписан на него — известно, что делать (завести
  подписку пошире), не начато, не приоритет по сравнению с остальным.

**Главный вывод, обновлено 2026-08-10 после сплошной перепроверки кода**:
почти весь список категории A оказался ложной тревогой — 5 из 7 пунктов
уже были реализованы раньше, я просто не перечитал код перед тем, как
писать/пересказывать триаж. Реально оставшееся в категории A —
**один-единственный пункт: война переподключений для аккаунтов без
TOTP**. Категория B (`Level.SOFT` — снят с повестки, реально удалён;
dead man's switch при долгом выключенном состоянии — упирается в ОС, не
в код) не изменилась. Урок на будущее, а не разовая случайность —
это уже третий-четвёртый раз в этой сессии, когда пересказ по памяти
расходится с кодом: **перед тем как заявлять "не сделано", грепать
код, а не полагаться на предыдущий проход документации.**

---

## Живое тестирование, 2026-08-10 — первый реальный прогон на устройствах

Android↔Android, `.onion`-сервер, Orbot в системном VPN-режиме. Итог:

1. **Утечек памяти нет** — `dumpsys meminfo` каждые 15-20с на протяжении
   ~10 минут под нагрузкой (звонки, переключение Wi-Fi/Tor, security-
   тесты, включение TOTP): `TOTAL PSS` колеблется в одной полосе
   (125-180 тыс. КБ, один всплеск до 231К во время звонка), к концу
   прогона ниже, чем в начале. Не растёт монотонно — не похоже на утечку.
2. **Переподключение после обрыва Wi-Fi/Tor работает** — само поднялось
   обратно, сессия не потерялась. Отдельно фиксировать нечего, ведёт
   себя как спроектировано.
3. **`SecurityDiagnosticsScreen.kt` (встроенная самопроверка)** — не
   показала проблем при живом прогоне.
4. **Найдено и исправлено — TOTP-настройка не показывала статус
   ожидания**, см. правку в п.15 (Tier 4, TOTP) выше.
5. **Найдено и исправлено — сильно запоздавший `call_request` звонит по
   уже неактуальному звонку**, см. правку в сценарии "голосовой/
   видеозвонок" в `SCENARIOS.md`.
6. **Подтверждено, не чинится в этой сессии — звонки не работают через
   Tor VPN-режим**, см. тот же сценарий в `SCENARIOS.md`, `❓ НЕ РЕШЕНО`.

Первый живой перепроверочный заход после фиксов п.4/п.5 выявил ещё две
находки:

7. **TOTP-подтверждение реально зависало навсегда, не просто выглядело
   так** — после добавления индикатора ожидания (п.4) стало видно: экран
   "Подтверждаем с сервером..." не сменяется вообще ничем. Причина
   глубже, чем UX: `TotpManager.enable(context, secret)` вызывался
   **сразу**, до ответа сервера ("чтобы `register()` уже мог включать
   `totp_code`"), а откат назад (`TotpManager.disable()`) был только в
   явном `onTotpSetupResult(false, ...)` — если ответ от сервера не
   приходит вообще (мёртвое соединение, реконнект в процессе — как раз
   то, чем пользователь активно занимался в этом же тесте), откат никогда
   не срабатывает. Получалась опасная тихая рассинхронизация: клиент
   считает TOTP включённым и начинает слать `totp_code` в `register()`,
   а сервер про секрет не знает вообще ничего — device-gated защита не
   просто не работает, а работает **тихо**, без всякого сигнала об этом.
   **Исправлено**: обе кнопки (включение и выключение) в
   `TotpSettingsScreen.kt` теперь запускают таймаут 15с — если `busy`
   всё ещё `true`, локальное состояние откатывается
   (`TotpManager.disable()`/`enabled = false`) и показывается понятная
   ошибка вместо вечного "Подтверждаем...". Compiles clean, живой
   повторный тест не проводился.
8. **Найдено и исправлено — беззвучный `AudioTrack` (8kHz, "volume
   guard" для 5×громкость-вниз панической кнопки) молотит логом
   AudioFlinger даже там, где реальная фича не настроена.**
   `startSilentAudio()` в `MessengerService.kt` был завязан только на
   `UserStorage.isEmergencyWipeEnabled()` — эта настройка **по умолчанию
   `true`** для всех аккаунтов и не отражает, прошёл ли пользователь
   многошаговый флоу реального включения Accessibility-сервиса
   (`EmergencyService.kt`, см. сценарий "panic wipe" в `SCENARIOS.md`).
   Получалось, что почти у всех пользователей этот трек тихо крутится
   постоянно, независимо от того, включена ли реально сама фича.
   **Исправлено**: гейт теперь дополнительно проверяет
   `isEmergencyServiceEnabled()` (та же проверка реального системного
   состояния сервиса, что уже использовалась в `ProfileScreen.kt` для
   синхронизации UI-переключателя — вынесена в неприватную функцию и
   переиспользована). Трек стартует только когда фича и включена в
   настройках, и реально активна в системе. Compiles clean, живой
   повторный тест не проводился.

---

## Обязательный TOTP при регистрации + recovery-коды, 2026-08-10

Пользователь, аналогия с ПВО: если защита есть, но выключена по
умолчанию — какой в ней смысл. Решение: TOTP для device-gated регистрации
(защита от войны переподключений/угона identity) больше не опция —
обязательный шаг сразу после регистрации, до входа в чаты.

**Компромисс, который обсуждался явно перед реализацией**: обязательный
TOTP для всех означает, что каждый новый пользователь по умолчанию несёт
риск "потерял секрет — и всё, новое устройство под этим ключом
зарегистрировать нельзя". Решение — **recovery-коды**, тот же принцип,
что у GitHub/Google 2FA: одноразовые коды, выдаваемые один раз при
включении TOTP, которые можно предъявить вместо кода из аутентификатора,
если он потерян.

**Сервер (`server.py`)**:
- Новая таблица `totp_recovery_codes(username, code_hash, used,
  created_at)` — хранятся только хеши (SHA-256; коды генерируются
  сервером со случайной высокой энтропией, не пользовательский пароль,
  так что быстрый хеш тут не риск перебора).
- `generate_recovery_codes()` — 8 кодов формата `XXXXX-XXXXX` (10 hex
  символов, для читаемости с разделителем).
- `totp_setup` теперь генерирует и возвращает коды один раз в
  `totp_setup_ok.recovery_codes` — сервер их больше никогда не покажет,
  только хеши остаются в БД.
- Гейт в `register()` — если `totp_code` не подошёл, проверяется
  `recovery_code`: `db_check_and_consume_recovery_code_sync()`
  атомарно помечает код использованным в том же `UPDATE ... WHERE used =
  0`, чтобы два одновременных предъявления одного кода не прошли оба.
  При успехе — **TOTP-секрет и все остальные recovery-коды этого
  аккаунта сразу отзываются** (`user_totp_secrets.pop`,
  `db_delete_recovery_codes`), логируется `[SECURITY]`-строкой. Логика
  осознанная: раз человек предъявил recovery-код, значит доступа к
  аутентификатору у него больше нет — оставлять старый секрет и
  оставшиеся коды рабочими не имеет смысла, аккаунт возвращается к
  состоянию "TOTP выключен" и требует сознательной новой настройки с
  нового доверенного устройства.
- `totp_disable` тоже чистит recovery-коды (`db_delete_recovery_codes`).

**Клиент (Android + Desktop, обе платформы синхронно)**:
- `RegisterScreen` → сразу `TotpSettingsScreen(mandatory = true)` (новый
  screen-state `totp_setup_required`) → только после этого `chats`. Кнопки
  "назад" нет — шаг нельзя пропустить.
- После успешного `totp_setup_ok` recovery-коды показываются **один
  раз**, в отдельной карточке с чекбоксом "я сохранил(а) эти коды" —
  кнопка "Продолжить" неактивна, пока чекбокс не отмечен.
- Новый путь на случай `totp_required` (устройство без секрета —
  восстановленный бэкап без сохранённого TOTP-секрета, или прямо
  потерянный аутентификатор): `MessengerService`/`WebSocketClient`
  получили `onTotpRequired` колбэк + `submitRecoveryCode()`
  (`pendingRecoveryCode`, одноразовый, включается в следующий
  `register()` и сбрасывается сразу после отправки). На Android —
  глобальный `RecoveryCodeGate()`, смонтированный поверх всех экранов
  после логина (не завязан на конкретный экран, потому что реконнект
  может случиться в любой момент); на Desktop — тот же принцип в
  `AppNavigation.kt`. Диалог сам закрывается, когда соединение
  восстанавливается (polling `isOnline()`/`connected.value` раз в
  секунду — не завязано на общий слот `onStatusChanged`, который уже
  используют другие экраны, чтобы не конфликтовать с ними).
  **Важно**: обработчик `totp_required` больше не вызывает полный
  `disconnect()` (который на Desktop выставляет `userDisconnected = true`
  и блокирует авто-реконнект) — иначе `submitRecoveryCode()` было бы
  неоткуда переподключиться.

**Не сделано в этой сессии**:
- Существующие аккаунты, созданные до этой правки, не переведены на
  обязательный TOTP задним числом — это применяется только к новым
  регистрациям. Миграция старых аккаунтов — отдельное решение, не
  затронуто.
- Live-тест самого recovery-флоу (реальная потеря доступа → ввод
  recovery-кода → успешная регистрация нового устройства) не проводился,
  только `compileDebugKotlin`/`compileKotlin` зелёные на обеих
  платформах.
- Экран показа кодов не даёт скачать/распечатать их файлом — только
  выделение текста руками (`SelectionContainer`) и копирование.

---

## Живое развёртывание и тестирование обязательного TOTP, 2026-08-11

Первый реальный прогон новой фичи на настоящем ВПС + телефоне (не эмулятор,
хотя часть диагностики шла и через эмулятор). Нашли и закрыли пять
отдельных проблем, разного уровня — от инфраструктуры до логики.

1. **Copy-button вместо ручного выделения текста**: на эмуляторе `long-press`
   через мышь не давал выделить секрет/recovery-коды для копирования —
   блокировало прохождение обязательной настройки полностью. **Исправлено**:
   явная кнопка "Копировать" рядом с секретом и рядом с кодами (обе
   платформы), не завязанная на выделение вообще.
2. **`:4430` в nginx не поддерживается Cloudflare для проксируемого HTTPS**
   (список: 443, 2053, 2083, 2087, 2096, 8443) — обход через прямой TLS на
   `server.py` тоже не подошёл: TLS у этого деплоя терминируется на nginx
   (Let's Encrypt сертификат), а `server.py` за ним общается по localhost
   обычным HTTP — второй слой TLS на `server.py` не нужен и **ломает**
   `proxy_pass http://` (502, nginx не умеет распаковать TLS как HTTP).
   `server.py` в проде для этого конкретного деплоя должен работать в
   `--dev` (без TLS) — это не костыль, а корректная архитектура, раз TLS
   уже терминирован снаружи.
3. **Два мёртвых nginx-блока под старое имя проекта** (`api.beacon-app.org`,
   `beacon-app.org`) с несуществующими сертификатами валили `nginx -t`
   целиком, блокируя вообще любые правки конфига — найдены и удалены
   (`/etc/nginx/sites-available/api`, `/etc/nginx/sites-available/beacon-ws`,
   в обоих файлах рабочий блок под новый домен уже был рядом, просто не
   мог применяться из-за соседнего битого).
4. **`ServerManager.kt`'s дефолтный сервер** держал временный обход `:8443`
   ещё с тех времён, когда Cloudflare WS-проксирование было сломано —
   комментарий сам предписывал вернуть на `443`, что и попытались сделать,
   но по факту у этого деплоя `api.subrosamessenger.com` реально настроен
   на `8443` (не `443`) — откатили обратно на `8443`, ориентируясь на
   реальный `nginx -T`, а не на старый комментарий.
5. **Обязательный TOTP реально можно было тихо обойти**: `UserStorage.register()`
   фиксирует `isRegistered() == true` **до** экрана `totp_setup_required` —
   если закрыть приложение посреди настройки, при следующем запуске
   `LoginScreen.onLoggedIn` (обе платформы) смотрел только на
   `isRegistered()`, не на статус TOTP, и пускал прямо в чаты с TOTP так и
   не включённым. Найдено живьём самим пользователем. **Исправлено**:
   `onLoggedIn` теперь дополнительно проверяет `TotpManager.isEnabled()` и
   при необходимости отправляет обратно на `totp_setup_required` вместо
   `chats` — на Android это означает, что отложенный deep-link
   (`pendingChatId`) в этом случае осознанно теряется, завершение
   настройки важнее.

Итог: TOTP реально включён и протестирован на живом аккаунте, recovery-коды
выданы и подтверждены пользователем. Сама повторная регистрация нового
устройства через recovery-код всё ещё не тестировалась вживую (см. пункт
выше, "Не сделано в этой сессии").

## Тир 5 — "Смена identity" теперь отзывает старый ключ на сервере (ключевая часть сделана 2026-08-13)

Найдено при написании гида по функциям безопасности (`SecurityGuideScreen.kt`) —
пользователь сам заметил дыру, спросив прямым текстом. Было: `BackupManager.
resetCompromisedIdentity()` (вызывается из ProfileScreen.kt по кнопке
"Я скомпрометирован") — **чисто локальная операция**: чистит identity-поля,
группы, токены, сессии, приватный ключ на этом устройстве, ничего не
отправляя на сервер. `server.py` вообще не имел понятия "отозванный ключ".

Реальное следствие: если сценарий — "ключ реально украли" (а не просто
паранойя), сброс identity защищал только *владельца* (у него новый ключ),
но никак не мешал *атакующему*, у которого есть копия старого приватного
ключа — тот всё ещё проходил challenge-response под старым fingerprint,
мог выдавать себя за жертву, заводить новые X3DH-сессии и т.п.

**Реализовано (ядро проблемы — п.1 списка последствий выше)**:
- `server.py`: новая персистентная SQLite-таблица `revoked_fingerprints`
  (переживает рестарт сервера — в отличие от `known_tokens`/`token_to_ws`,
  которые остаются in-memory намеренно, это другой класс данных). Новый
  тип сообщения `revoke_identity` — **не несёт отдельной подписи**: сервер
  берёт `username` уже аутентифицированного соединения (тот самый
  fingerprint, доказанный challenge-response-хендшейком при коннекте), а
  не то, что прислал клиент — то есть отозвать чужую identity через этот
  путь невозможно. При получении: помечает fingerprint отозванным в БД,
  шлёт `identity_revoked_ack`, закрывает соединение. Register-хендлер
  теперь проверяет `db_is_fingerprint_revoked()` до пропуска регистрации
  и отвечает `{"type": "identity_revoked"}`, если fingerprint в списке —
  challenge-response всё ещё технически проходит (ключ у атакующего
  реальный), но регистрация после него — нет.
- Android: `ProfileScreen.kt`'s "Меня скомпрометировали" перед вызовом
  `resetCompromisedIdentity()` шлёт `revoke_identity` через уже открытое
  (аутентифицированное под старой identity) соединение и ждёт 400мс —
  fire-and-forget, без ожидания ack, тот же принцип "дёшево", что и весь
  остальной flow. `MessengerService.kt` обрабатывает и отправку
  (intent-extra `revoke_identity`), и приём `identity_revoked` при
  попытке зарегистрироваться отозванным ключом (Toast с понятным текстом
  вместо тихого зависания).

~~**Dead Man's Switch mirror**~~ — **done, 2026-08-13, same session**. The
send+wait logic was extracted into a shared
`MessengerService.requestIdentityRevocation(context)` (companion object
function) so it isn't duplicated between callers — `ProfileScreen.kt` now
calls it too instead of building the intent inline. `WipeReceiver.kt`'s
`ACTION_DMS_WIPE` branch calls it before `WipeManager.wipe(context,
WipeManager.Level.NUCLEAR)`, wrapped in `CoroutineScope(Dispatchers.IO +
SupervisorJob()).launch { ... }` since `BroadcastReceiver.onReceive()`
isn't itself a coroutine scope (same pattern already used a few lines down
for the panic-button decoy delay). DMS specifically can fire while the
device is online but its owner unreachable (confiscated, not unlocked,
timer ticking on its own) — a real chance this reaches the server before
the wipe destroys the key.

~~**Пометка prekey bundle как "revoked"**~~ — **done, 2026-08-13**. `server.py`'s
`get_prekey_bundle` and `get_prekey_bundles_batch` now check
`db_is_fingerprint_revoked(target)` (outside the `clients`/`prekey_bundles`
lock — SQLite lookups shouldn't serialize behind it, same reasoning as the
register-time check) and set `bundle["revoked"] = True` when true. For the
batched/anonymous fetch, the check runs concurrently via `asyncio.gather`
for every target that actually had a bundle — flagging a decoy target's
bundle doesn't leak which one in the batch is real, since the server can't
tell that either way. The always-unused legacy `request_prekey` handler
was deliberately left untouched (no client, Android or Desktop, sends this
message type — confirmed by grep — so there was nothing to protect there).

Android: new `MessengerService.onContactRevoked: ((String) -> Unit)?`
callback, fired from `handleFetchedPrekeyBundle()` when the fetched
bundle's `revoked` field is set — mirrors the existing TOFU key-change
callback (`onKeyChanged`) exactly: a warning, not a hard block on
establishing the session (same "не критично, register теперь блокирован
для будущих подключений" reasoning as before — the goal is making sure
the *contact* finds out, not stopping delivery). `ChatScreen.kt` wires it
to a new `showRevokedWarning` `AlertDialog`, styled and structured like
the existing key-change warning dialog, dismiss-or-leave-chat. Desktop not
touched — no `onKeyChanged`-equivalent warning UI exists there either, so
this isn't a regression relative to what Desktop already had.

**Не реализовано, осталось на потом**:
- **Desktop** не тронут — там нет ни кнопки "Я скомпрометирован", ни
  `BackupManager`-аналога вообще (Android-only фича с самого начала).
  Desktop-клиенты автоматически защищены на серверной стороне (register
  проверяет revoked-список независимо от платформы), просто у них нет
  своей кнопки, чтобы инициировать отзыв, и никакого UI-предупреждения
  при получении revoked-бандла.

Затронуло: Android (`MessengerService.kt`/`ProfileScreen.kt`/
`WipeReceiver.kt`/`ChatScreen.kt`/`AppStrings.kt`), `server.py` на ВПС
(новый тип сообщения + персистентная таблица + revoked-флаг в двух
prekey-bundle хендлерах). Compiles clean (`compileDebugKotlin`,
`py_compile`). Не задеплоено на боевой сервер, не протестировано вживую
(два реальных
устройства — одно отзывает, второе пытается зайти старым ключом; и
отдельно — реальное срабатывание DMS с последующей проверкой, что отзыв
успел уйти до вайпа).