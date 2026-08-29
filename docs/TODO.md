# TODO

Рабочий список задач между сессиями. Не changelog (готовые изменения — туда), это то, что ещё не сделано.

## CI/SAST — реализация `docs/CI_SAST_PLAN.md`

Сделано (файлы в репо): `.github/workflows/build.yml` (Android build+lint,
Python syntax-check, pip-audit, security regression tests),
`.github/workflows/secrets-scan.yml` (Gitleaks в CI, push/PR/еженедельно по
расписанию), `.github/dependabot.yml` (gradle/pip/github-actions/docker),
`.github/workflows/dependency-review.yml`, `.github/workflows/semgrep.yml`
(`p/security-audit` + `p/secrets`), `.github/workflows/codeql.yml`
(java-kotlin + python, matrix, еженедельно + push/PR), `githooks/pre-push`
(локальный Gitleaks-хук, требует ручной установки), `Server/tests/`
(8 security regression tests, все проходят локально, прогнано 3 раза без
флаки). Все сторонние Actions запинены на commit SHA (не тег), `permissions:
contents: read` по умолчанию везде (кроме CodeQL analyze — там нужен
`security-events: write` для загрузки результатов).

- [x] Secret scanning + Push protection — включено через `gh api`
  (secret scanning уже было включено ранее, push protection тоже).
- [x] Dependabot alerts + Dependabot security updates — включено через
  `gh api` (`vulnerability-alerts`, `automated-security-fixes`).
- [x] Semgrep (`p/security-audit`, `p/secrets`) — `.github/workflows/semgrep.yml`.
- [x] CodeQL — `.github/workflows/codeql.yml`.
- [x] Первые 8 security regression tests — `Server/tests/test_security_invariants.py`,
  все 8 инвариантов из `docs/CI_SAST_PLAN.md` покрыты, реальный
  `websockets.serve(server.handle_client, ...)` в тестах (не переписанная
  логика), только сама recovery-code атомарность продублирована и через
  прямой вызов DB-функции, и через полный register()-путь.
  По ходу нашлась и подтверждена (не починена, уже задокументированный
  trade-off) тонкость: после того как ЛЮБАЯ конкурентная попытка выигрывает
  recovery-код, TOTP-гейтинг для аккаунта отключается целиком — остальные
  параллельные попытки после этого момента тоже проходят, просто уже без
  кода. Не баг теста — сам код так и работает (см. пункт ниже "recovery-code
  takeover window").
- [ ] **Локально (на этой машине и любой другой, с которой пушат):**
    `git config core.hooksPath githooks` + установить бинарник gitleaks
    (https://github.com/gitleaks/gitleaks#installing) — без него хук молча
    пропускает скан и просто предупреждает.
- [x] Branch protection на `main` — включена через `gh api`, 7 required
  status checks (Semgrep SAST, CodeQL x2, Android build + lint, Server
  syntax check, Server security regression tests, Gitleaks), PR обязателен
  (0 approvals — соло-разработка), force-push/удаление ветки запрещены,
  `enforce_admins: false` (у владельца остаётся обход на экстренный случай,
  осознанное решение — не вредит audit-readiness, стандартная практика для
  соло-мейнтейнера).

**Весь план `docs/CI_SAST_PLAN.md` реализован и подтверждён на реальном
CI** (не только локально) — 5 живых итераций правок по логам настоящих
прогонов на GitHub Actions, не только "выглядит похожим на правду":
- google-services.json гитигнорится → плагин ломал сборку без него →
  применение плагина сделано условным (`app/build.gradle.kts`)
- codeql-action v3.37.9 успела устареть за часы до пуша (вышел v4) —
  перепроверено и перепинено на v4.37.9
- CodeQL Autobuild не видел наш JDK 21 toolchain (дефолтная JDK17) —
  заменено на явную сборку тем же способом, что в build.yml
- Semgrep нашёл 1 реальный (но false-positive) finding — добавлен точечный
  `nosemgrep` с обоснованием в комментарии, ОШИБСЯ с rule-id/расположением
  комментария с первого раза — поймано локальным прогоном semgrep, не
  ещё одним циклом CI
- lint ни разу не гонялся в CI раньше — 3 pre-existing ошибки заблокировали
  бы вообще любой PR; заведён `lint-baseline.xml`, а не правка
  несвязанного медиа-кода без контекста

**Dependabot: разобраны все 20 первых PR (19/20 слито).** okhttp/compose-bom/
core-ktx синхронно упирались в старый AGP 9.0.1/compileSdk 34 — поднято до
AGP 9.1.1/Gradle 9.3.1/compileSdk 37 (попутно найдена и починена реальная
поломка компиляции: `ApplicationInfo?` стал nullable на SDK 37). Новый
compose-bom дополнительно потребовал явной зависимости `material-icons-core`
(раньше подтягивалась транзитивно через material3) и поймал новый lint-чек
`NonObservableLocale` в `ChatScreen.kt` (реальный, поправлен на
`LocalLocale.current`). Пользователь вручную проверил приложение после
мержа compose-bom — связь работает, security-тесты проходят, поломок не
найдено.
- [ ] **#10 (`websockets` 12→17) — единственный оставшийся открытый PR.**
  Прод-VPS (`beacon.service`) гонял `/usr/bin/python3` напрямую через
  systemd без venv — был Python 3.10.12, `websockets` 17.x требует ≥3.11.
  **Python на VPS обновлён до 3.11.15 (2026-08-29)** — блокер снят, можно
  мержить PR (сам мерж и повторный runtime-смоук после него ещё не сделаны).
- Dependabot `docker`-ecosystem не умеет отслеживать образ, запиненный в
  `container:` воркфлоу — убрана нерабочая секция после живой ошибки

Отдельно: включение Dependabot сразу открыло ~20 PR с обновлениями
зависимостей (ожидаемо для первого запуска на устоявшемся репо) — не
мержил без решения пользователя, это отдельная задача на потом.

- [ ] Bandit, Detekt, custom Semgrep-правила — низкий приоритет, после
  основного.
- [ ] Разобрать ~20 Dependabot PR (gradle/pip/github-actions) — по одному,
  не пачкой; часть — мажорные бампы (`cryptography` >=42→>=50,
  `compose-bom` 2024.09→2026.08), нужно тестирование, не слепой merge.

## Android/Server security audit — сессия 2026-08-23

Полный построчно-верифицированный журнал — `docs/ANDROID_AUDIT.md`. Файлы
пройдены: `AnonTokenManager.kt`, `SessionKeyManager.kt`, `MessengerService.kt`
(ACK-семантика + fallback), `BackupManager.kt`+`TotpManager.kt`,
`GroupManager.kt`, `server.py`. Ниже — только то, что осталось открытым.

- [ ] **Продуктовое решение: recovery-code takeover window на сервере.**
  После использования recovery-кода TOTP-гейтинг для аккаунта отключается
  полностью и навсегда, пока пользователь не настроит защиту заново
  вручную — значит любое второе устройство с тем же identity private key
  (например, украденный бэкап) может зайти без кода в любой момент после
  этого. Осознанный дизайн, не баг, но решение принято молча — стоит
  явно решить, вводить ли ограниченное `RECOVERY_PENDING_REENROLLMENT`-
  состояние (детали — `docs/ANDROID_AUDIT.md`, секция `server.py`).
- [ ] **`GroupManager` — авторизация внутри менеджера, не только у
  caller'ов.** `addMember`/`removeMember`/`promoteToAdmin`/`deleteGroup`
  не проверяют, что actor — админ; сейчас это забота каждого вызывающего
  кода. Нужно решить: (a) self-removal исключение (участник должен мочь
  сам выйти из группы, не будучи админом), (b) что делать с прямыми
  вызовами `saveGroup()` в обход мутаторов (минимум 4 места).
- [ ] **`server.py` — полный runtime smoke-test.** Сегодняшние правки
  (`db_connect()` recursion fix, token ownership/spent state, атомарная
  регистрация/access-code) проверены только `ast.parse`, не запускались.
  Сделать перед следующим деплоем на VPS.
- [ ] **`message_delete`/`disappear_timer`/`group_message_delete`** — тот
  же паттерн "неверная подпись → `return` вместо `throw`", что чинили в
  `session_init`/`reaction`/`file_chunk`, но эти три не проверялись.
- [ ] **Backup/identity recovery как отдельный тестируемый security-flow**
  (живое тестирование, не код-ревью) — потерянный телефон, украденный
  бэкап, потерянный authenticator, restore на новое устройство, revoke
  старого. Код починили, сценарии живьём не гоняли.

## Desktop

- [ ] Статический аудит desktop-кода на те же классы багов, что нашли на Android в сессии 2026-08-23 (см. `docs/ANDROID_AUDIT.md`): race conditions при биндинге сервиса/подключении, гонки при инициализации, хардкод-секреты/коды разблокировки, потеря состояния при вайпе/decoy-восстановлении, слабая проверка пароля при регистрации, поля ввода за клавиатурой, атомарность мутаторов. Ориентир — `SECURITY.md`, там уже отмечены места "Desktop had a worse version of this bug" (item 13, 20 и др.) — начать с них.
- [ ] После статики — живой кросс-платформенный тест: Android ↔ Desktop invite-код обмен (SECURITY_CHANGELOG.md item 13 отмечает, что порт формата `bc:` на Desktop сделан, но ни разу не проверен вживую).

## Протокольное тестирование сервера ("хакер")

- [ ] Поднять локальный тестовый `server.py`, написать Python-скрипт, атакующий протокол напрямую (без UI/эмуляторов): повторное использование anon-токена (теперь должно давать `is_spent` дроп — проверить, что фикс реально работает), обход rate-limit, попытка регистрации под чужим fingerprint без приватного ключа, SQL-инъекции по всем входным точкам, флуд регистраций без PoW, невалидные/битые payload'ы, попытка обойти invite-код TTL/подпись, конкурентная регистрация двух fingerprint у cap (проверить атомарность фикса).
- [ ] По желанию, отдельным шагом: живое тестирование через два эмулятора/два desktop-клиента одновременно — уже после протокольного прогона, если останутся вопросы, не закрытые статикой и протокольными атаками.

## Документация

- [x] `SECURITY.md` vs `ARCHITECTURE.md` — расхождение по SMK-wrapping SPK/OPK/PQ-ключей и Double Ratchet state — исправлено, `ARCHITECTURE.md` был устаревшим.
- [x] `SECURITY.md` vs `ARCHITECTURE.md` — расхождение по backward-compat инвайт-кода `0x02` — исправлено, `ARCHITECTURE.md` был устаревшим.
- [x] Ослаблены overclaiming-формулировки по итогам внешнего ревью клиентских/маркетинговых доков — README ("server never has access to user identities", "Full Signal Protocol"), `Subrosa_Architecture_Overview.md` ("fully open-source" без оговорки про desktop, "unlocked device" без RAM-caveat, Signal Protocol claim), `Article_EN.md` (Loopix-сравнение, "practically sufficient"), `PRICING.md` ("accountable party" → "named support/security contact", "security review" → "Deployment Security Review" с явным scope), `DOCKER.md` (performance-цифры помечены как ненагруженные/indicative). Перед правкой сверялся с кодом — Threat Detection claim (Frida/Xposed/emulator/debugger) подтверждён как реально реализованный, не тронут.
- [ ] Периодически перепроверять `ARCHITECTURE.md`/`SECURITY.md`/клиентские доки на новые расхождения — за 25k+ строк кода документация неизбежно будет отставать от изменений, если не сверять целенаправленно.
- [x] README.md — таблица Threat Model Summary конфлировала "privacy from server" и "privacy from malicious operator": строка "mitigated by self-hosting" звучала как будто самохостинг криптографически убирает риск malicious operator. Поправлено: самохостинг не убирает видимость метаданных, а меняет, кто ей обладает (сама фирма вместо третьей стороны) — это плюс контроля, не крипто-фикс.
- [x] "Plausible deniability" (decoy-режим) в `SECURITY.md` и `ARCHITECTURE.md` — заявление стояло без соседней оговорки про forensic examiner (она была в другом месте, Known Limitations item 7). Поправлено: явно разделено "deniability того, что на экране" vs "undetectability самого факта вайпа" в обоих местах.
- [x] README.md — устаревший формат инвайт-кода `beacon://invite?...` (реальный формат — `bc:<base64url>`) — исправлено в README и DOCKER.md.
- [x] **Реальный инфраструктурный баг, не только доки** — `deploy/docker-compose.yml`: volume монтировался в `/app/data`, но `DB_PATH` нигде не был выставлен → сервер писал БД по дефолтному относительному пути `messages.db`, что резолвилось в `/app/messages.db` (вне volume, в writable-слое контейнера). При пересоздании контейнера база терялась бы молча. Добавлен `DB_PATH: /app/data/messages.db` в environment.
- [x] `DOCKER.md`/`DEPLOY.md`/`CHECKLIST.md` — устаревшие имена `Subrosa-server`/`Subrosa-data`/`Subrosa.db`, не совпадающие с реальными именами в `docker-compose.yml` (`subrosa-server`/`subrosa-data`/`messages.db`) — исправлено везде, плюс поломанные относительные ссылки `../SECURITY.md`/`../ARCHITECTURE.md` (они в той же папке `docs/`, не на уровень выше).
- [x] `ARCHITECTURE.md` — заявление про `handleDeepLink()`, обрабатывающий `beacon://invite`/`beacon://channel`, было полностью неверным: такой функции не существует, `beacon://invite` вообще нигде не обрабатывается в коде, а `handleChannelDeepLink()` целиком закомментирован (Channels отключены). Поправлено на точное описание текущего (нерабочего) состояния обеих deep-link схем.
- [x] "Desktop client is in development" в `Subrosa_Architecture_Overview.md` конфликтовало с тем, что `SECURITY.md` описывает desktop как зрелого клиента с десятком собственных механизмов защиты (39 Kotlin-файлов, ~600 КБ кода). Поправлено на точную формулировку: функционально готов, но не опубликован в репозитории (подтверждено — `/desktop/` в `.gitignore`).
- [x] Добавлена строка `Last verified against commit: ...` в начало `SECURITY.md`, `ARCHITECTURE.md`, `Subrosa_Architecture_Overview.md`.
- [ ] Дубль идеи "вынести историю расследований из SECURITY.md в отдельный файл" (реви­ьюер во втором заходе предложил имя `SECURITY_HISTORY.md`, в первом — `SECURITY_CHANGELOG.md`) — уже занесено выше, тут просто отметка, что оба раза это один и тот же пункт, имя файла ещё не выбрано.

## Из внешнего ревью (по крупному, требует приоритизации, не сделано)

- [ ] **FCM как отдельный deployment-профиль.** Сейчас честно описан как компромисс в overview/agreement, но в deploy-доках (`DOCKER.md`/`DEPLOY.md`) не выделен явно. Предложение ревьюера: сделать "strict no-third-party" отдельным профилем деплоя с явным предупреждением про потерю background-reliability, а не просто переменной окружения без акцента.
- [ ] **Anonymous routing — главная цель для аудита, не AES-GCM/PBKDF2.** Именно token lifecycle, mailbox, retry/ack, bootstrap, prekey-batching и downgrade/fallback paths давали большую часть багов в сессиях. Предложение: подготовить отдельно protocol state machine / спецификацию для будущего аудитора, не полагаться на то, что аудитор реконструирует её из кода.
- [ ] **Документ "Security Invariants".** Формальный список инвариантов протокола (например: "1:1-пакет НИКОГДА не должен становиться fingerprint-addressed после установления токенов", "старый удалённый участник группы НИКОГДА не должен получить новый ротированный ключ", "отсутствие PQ-компонента должно ронять handshake, никогда не даунгрейдить"). Сейчас эти правила разбросаны по тексту `SECURITY.md`. Ценно именно для аудита — сверять код против явного списка инвариантов, а не вылавливать их из прозы.
- [x] **Разделить `SECURITY.md` на текущее состояние + историю — сделано 2026-08-29.** 15 полностью закрытых пунктов (4, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 28) перенесены в новый `SECURITY_CHANGELOG.md`, в `SECURITY.md` остались только реально актуальные 16 пунктов. **Номера НЕ перенумерованы** — сознательное решение, чтобы не ловить каскад правок по всем файлам, которые ссылаются на конкретные номера (`README`/`ARCHITECTURE.md`/`KNOWN_SECURITY_ISSUES.md`'s `KL-N` и т.д.) — вместо этого в списке остались "дыры", с явным пояснением наверху раздела. Все найденные живые ссылки на переехавшие номера (в `SECURITY.md` самом на себя, `ARCHITECTURE.md`, `ANDROID_AUDIT.md`, этом файле) перенаправлены на новый файл; `docs/KNOWN_SECURITY_ISSUES.md` обновлён (добавлены KL-30/KL-31, пояснение про два файла). Не тронуты: `AUDIT_SETUP.md`/`SCOPE.md`/`THREAT_MODEL.md`/`AUDIT_TARGET.md` — они привязаны к конкретному git-тегу (`audit-2026-08`) для внешнего аудита, непонятно, должны ли отражать сегодняшнее состояние или состояние на тег — нужно отдельное решение, не трогал вслепую. `ISSUE_backup_identity_hijack.md` — исторический журнал-нарратив, ссылки там корректно описывают прошлое состояние, не трогал намеренно.
- [ ] **Формальный security release process.** Сейчас есть общие слова "security updates as new threats emerge" (PRICING.md), но нет политики: формат CVE/advisory, embargo-период, severity levels, какие версии поддерживаются, срок поддержки старых релизов, процедура на случай компрометации ключа. Для платной поддержки (реальный источник дохода проекта) это станет важнее многих новых фич.
- [ ] **Backup/identity recovery как отдельный тестируемый security-flow.** Бэкап сохраняет identity, TOTP блокирует захват аккаунта через бэкап — сильная идея, но сценарии не протестированы системно: потерянный телефон, украденный бэкап, потерянный authenticator, повторное использование recovery-кода, restore на новое устройство, revoke старого устройства.
- [ ] **`subrosa doctor` — диагностический скрипт для деплоя.** Реальный прецедент был сегодня (порт 9000 открыт всему интернету при неактивном `ufw`). Предложение: скрипт, проверяющий exposed ports, TLS, firewall, шифрование БД, бэкапы, FCM-конфиг, TURN, права доступа файлов — сразу усиливает коммерческую ценность тарифов Firm/Managed (меньше шанс, что клиент задеплоит с дырой, как было у нас самих).
- [ ] **Бан по железу/фингерпринту вместо IP.** Подтверждено 2026-08-28: `server.py` стоит за reverse-proxy, сам процесс видит только `127.0.0.1` в `websocket.remote_address`. Задокументировано как формальный инвариант в `SECURITY.md` (item 30, 2026-08-29): `server.py` не должен читать реальный IP клиента, `deploy/nginx.conf` больше не пробрасывает `X-Real-IP`/`X-Forwarded-For` на бэкенд (раньше пробрасывал — сама production-конфигурация в `docs/nginx-subrosamessenger.conf.snippet` этим не страдала). Заодно поправлен `real_ip_header CF-Connecting-IP` в production-сниппете, чтобы **собственный** access-лог nginx для fail2ban видел реального клиента, а не edge-IP Cloudflare — это не противоречит инварианту, IP по-прежнему не идёт дальше nginx. **Не сделано:** сам бан по device fingerprint / крипто-fingerprint аккаунта вместо IP для обычных клиентов — это отдельная задача на реализацию (существующий `dynamic_peer_strikes`/`FED_BUNDLE_BAN_SEC` для федерации не трогать, те бьют напрямую, не через прокси).
- [x] **`anon_message.payload` содержал `from`/`to` в открытом виде — исправлено 2026-08-29.** Был недосмотр: федерация появилась раньше токенов, поля не перенесли внутрь шифрования при внедрении анонимной маршрутизации. Осознанное решение с пользователем: `from`/`to` теперь запечатываются вместе с остальным пакетом ещё одним слоем гибридного шифрования на identity-ключ получателя (`sealPacketForRecipient()` в `MessengerService.kt`, используется в `sendAnonOrDirect()`/`sendWithForwardSecrecy()`) — тем же механизмом, что уже был у `sendAnonTokensTo()`/`__beacon_tokens__`. Получатель расшифровывает своим приватным ключом без необходимости заранее знать отправителя. **Trade-off:** federation-fallback по `payload.get("to")` для таких сообщений больше не работает — принято сознательно, утечка метаданных признана худшим злом. Обратная совместимость на приём есть (если `blob` нет — старый формат), но старый непропатченный получатель не поймёт новый формат (нет `type`/`from`/`text` на верхнем уровне) — обе стороны нужно обновить одновременно.
- [ ] **Federation-fallback сломан для запечатанных сообщений — нужно осознанное решение, не забыть.** Прямое следствие пункта выше: `server.py`'s `payload.get("to")` (используется когда токен не известен локально — пересылка на федеративный сервер по fingerprint) теперь всегда `None` для сообщений, идущих через `sendAnonOrDirect()`/`sendWithForwardSecrecy()`, потому что `to` больше не лежит в открытом JSON. Если федерация реально используется (не только `sendAnonTokensTo()`/`__beacon_tokens__`, для которых так было всегда) — нужно либо (a) принять как есть и явно закрыть эту фичу для non-local получателей, либо (b) придумать способ маршрутизировать между серверами без раскрытия fingerprint получателя серверу-отправителю (например, зашифровать `to` отдельно на публичный ключ федеративного сервера-партнёра, если такая схема доверия вообще применима). Пока никакого кода под это не написано — решение чисто продуктовое/архитектурное.
