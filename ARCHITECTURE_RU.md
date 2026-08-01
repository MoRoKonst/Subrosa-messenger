# Архитектура

Этот документ описывает системное устройство, структуру модулей и потоки данных Beacon Messenger.

> **Примечание:** Фича «Каналы» (broadcast-каналы: `ChannelManager`, `ChannelFeedScreen`, типы сообщений и таблицы БД `channel_*`, упомянутые ниже) сейчас **отключена на уровне UI** на обоих клиентах — она не вписывалась в назначение продукта как устойчивого инструмента приватной связи, а не broadcast/социальной фичи, и её метаданные не были анонимизированы. Код оставлен как есть, недостижимым — на случай, если к этому решению вернутся.

---

## Содержание

- [Общая схема](#общая-схема)
- [Архитектура клиента](#архитектура-клиента)
  - [Слоёвая модель](#слоёвая-модель)
  - [Навигация](#навигация)
  - [Описание модулей](#описание-модулей)
- [Архитектура сервера](#архитектура-сервера)
  - [Модель состояния](#модель-состояния)
  - [Протокол сообщений](#протокол-сообщений)
  - [Ограничение частоты запросов](#ограничение-частоты-запросов)
- [Потоки данных](#потоки-данных)
  - [Регистрация](#регистрация)
  - [Переписка один-на-один](#переписка-один-на-один)
  - [Групповая переписка](#групповая-переписка)
  - [Передача файлов](#передача-файлов)
  - [WebRTC-звонки](#webrtc-звонки)
  - [Handshake аутентификации](#handshake-аутентификации)
- [Хранилище данных](#хранилище-данных)
- [Зависимости](#зависимости)

---

## Общая схема

```
┌─────────────────────────────────────┐
│          Android-клиент             │
│  ┌──────────┐   ┌────────────────┐  │
│  │ Compose  │   │MessengerService│  │
│  │   UI     │◄──│  (фон. служба) │  │
│  └──────────┘   └───────┬────────┘  │
│                         │ WSS       │
└─────────────────────────┼───────────┘
                          │
               ┌──────────▼──────────┐
               │  Python WebSocket   │
               │       сервер        │
               │ (ретрансляция +     │
               │  сигнализация)      │
               └──────────┬──────────┘
                          │ WebRTC
               ┌──────────▼──────────┐
               │    TURN-сервер      │
               │    (coturn)         │
               └─────────────────────┘
```

Сервер является ретранслятором сообщений. Он никогда не имеет доступа к открытому тексту: все сообщения шифруются на устройстве отправителя перед передачей и расшифровываются только на устройстве получателя. Медиапоток звонков является peer-to-peer (TURN используется только при блокировке прямого UDP).

---

## Архитектура клиента

### Слоёвая модель

```
┌────────────────────────────────────────────────┐
│  Слой UI (экраны Jetpack Compose)               │
│  LoginScreen, ChatsScreen, ChatScreen,          │
│  GroupChatScreen, ChannelFeedScreen,            │
│  ActiveCallScreen, ProfileScreen, ...           │
├────────────────────────────────────────────────┤
│  Слой приложения / ViewModel                    │
│  MainActivity (состояние навигации)             │
│  MessengerService (WebSocket, уведомления)      │
│  CallManager (WebRTC)                           │
├────────────────────────────────────────────────┤
│  Слой домена / менеджеров                       │
│  CryptoManager    — EC-ключи, ECDH, ECDSA       │
│  GroupManager     — групповые ключи, участники  │
│  ChannelManager   — каналы вещания              │
│  SessionKeyManager — сессии Double Ratchet      │
│  BackupManager    — экспорт / импорт            │
│  DeadMansSwitchManager — таймер DMS             │
│  IntrusionDetector — сканирование угроз         │
│  RootDetector     — целостность устройства      │
│  HoneyTokenManager — обнаружение подделки       │
│  WipeManager      — уничтожение данных          │
│  ParanoidMode     — режим антифорензики         │
│  StorageKeyManager — слой SMK на устройстве     │
│  InviteCodeManager — подписанные инвайты        │
├────────────────────────────────────────────────┤
│  Слой хранилища                                 │
│  UserStorage      — учётные данные, настройки   │
│  ChatStorage      — сообщения 1-to-1, контакты  │
│  GroupManager     — сообщения групп             │
│  ChannelManager   — посты каналов               │
│  SecureFileStorage — зашифрованные файлы        │
│  EncryptedStorage — EncryptedSharedPreferences  │
├────────────────────────────────────────────────┤
│  Слой платформы                                 │
│  AndroidKeyStore  — оборачивание ключей         │
│  BiometricPrompt  — биометрия                   │
│  NotificationManager — системные уведомления    │
│  ConnectivityManager — состояние сети           │
└────────────────────────────────────────────────┘
```

### Навигация

Навигация управляется полностью в `MainActivity` через единственную Compose-переменную `mutableStateOf<String>` с именем `screen`. Корневой composable `AppNavigation()` рендерит нужный экран через выражение `when`:

```
"login"          → LoginScreen       (вход)
"register"       → RegisterScreen    (регистрация)
"chats"          → ChatsScreen       (главный хаб)
"chat"           → ChatScreen        (чат 1-to-1)
"group_chat"     → GroupChatScreen   (групповой чат)
"channel_feed"   → ChannelFeedScreen (лента канала)
"call"           → ActiveCallScreen  (активный звонок)
"incoming_call"  → IncomingCallScreen (входящий звонок)
"profile"        → ProfileScreen     (профиль)
"backup"         → BackupScreen      (бэкап)
"wipe_settings"  → WipeSettingsScreen (настройки уничтожения)
"verify_key"     → VerifyKeyScreen   (верификация ключа)
"servers"        → ServersScreen     (серверы)
"security_diag"  → SecurityDiagnosticsScreen (диагностика)
"decoy"          → DecoyScreen       (режим-приманка)
```

Deep links (`beacon://invite`, `beacon://channel`) обрабатываются в `handleDeepLink()` до маршрутизации.

---

### Описание модулей

#### `MessengerService.kt`
Фоновый `Service` (foreground, тип `dataSync`). Владеет жизненным циклом WebSocket-соединения. Все исходящие сообщения проходят через эту службу (через `Intent`-экстры или прямой binder-вызов). Все входящие WebSocket-сообщения диспетчеризируются здесь — сохраняются в хранилище или передаются в UI через `SharedFlow`.

Ответственность:
- Подключение / переподключение к WebSocket (экспоненциальная задержка)
- Heartbeat-keepalive
- Чанкованная загрузка файлов и сборка фрагментов
- Создание уведомлений (сообщения, звонки, обновления каналов)
- Обработка конфликтов сессий

#### `CryptoManager.kt`
Stateless-синглтон для всей EC-криптографии. Ключи хранятся в `EncryptedSharedPreferences("beacon_ec_keys_enc")` — никогда напрямую в `AndroidKeyStore`, чтобы разрешить программный экспорт и ротацию ключей.

| Операция | Алгоритм |
|---|---|
| Ключевая пара | EC P-256 (secp256r1) |
| ECDH | `KeyAgreement("ECDH")` |
| Симметричное шифрование | AES-256-GCM, 12-байтный IV, 128-битный тег |
| Цифровая подпись | ECDSA с SHA-256 |
| Выведение ключа | HKDF-схема через HMAC-SHA256 |

Приватный ключ хранится обёрнутым Storage Master Key (SMK) при авторизованном пользователе (см. `StorageKeyManager`).

#### `SessionKeyManager.kt`
Управляет состоянием сессий Double Ratchet для каждого контакта. Инициализируется при старте приложения (до входа пользователя) из сохранённого состояния. Обрабатывает:
- Начальное согласование ключей X3DH: identity key + signed prekey + one-time prekeys (OPK)
- Шаг ratchet на каждую отправку/получение
- Сериализацию состояния сессии

> SPK- и OPK-приватные ключи намеренно **не** оборачиваются слоем SMK — они необходимы при холодном старте до входа пользователя.

#### `GroupManager.kt`
Управляет зашифрованным состоянием групп.

Жизненный цикл ключа:
1. Создатель группы вызывает `generateGroupKey()` → 32 случайных байта AES.
2. Для каждого участника M: `encryptGroupKeyForMember(groupKey, memberPublicKey)` через ECDH + AES-GCM.
3. Зашифрованные блобы ключей отправляются на сервер; сервер доставляет каждый `encKey` только соответствующему участнику.
4. Участник вызывает `decryptGroupKey(encKey, myPriv)` → `groupKey`.
5. Групповой ключ хранится обёрнутым SMK в преференциях `"groups"`.

Шифрование сообщений: `AES/GCM/NoPadding`, 12-байтный IV предшествует шифртексту.

Ротация ключа запускается при исключении участника.

#### `StorageKeyManager.kt`
Второй слой шифрования данных на устройстве. Storage Master Key (SMK) — 256-битный случайный ключ, живёт только в памяти и обнуляется при блокировке или уничтожении данных.

Два экземпляра SMK хранятся в `EncryptedSharedPreferences("smk_config")`:

| Ключ | Защита | Назначение |
|---|---|---|
| `enc_smk_pwd` | PBKDF2-SHA256(пароль, соль, 300 000 итераций) → AES-256-GCM | Защита от офлайн-извлечения |
| `enc_smk_ks` | AndroidKeyStore AES-256 → AES-256-GCM | Биометрия / быстрая повторная блокировка |

Значения, защищённые SMK, получают префикс `"smk1:"` для прозрачной обратно-совместимой миграции. Подробности — в [SECURITY_RU.md](SECURITY_RU.md).

#### `WipeManager.kt`
Три уровня уничтожения данных:

| Уровень | Действие |
|---|---|
| `SOFT` | Очистить только ключи и состояния сессий в памяти |
| `HARD` | Удалить все преференции, файлы, базы данных, данные WebView, ключи AndroidKeyStore; опционально — создать состояние-приманку |
| `NUCLEAR` | `HARD` + `ActivityManager.clearApplicationUserData()` (атомарная системная очистка, процесс завершается) |

Режим-приманка: перед уничтожением HARD сохраняет `username`, `password_hash`, `user_id` во временный открытый файл. При следующем запуске приложение выглядит как имеющее легитимный аккаунт с фиктивными чатами — правдоподобное отрицание при принуждении.

#### `IntrusionDetector.kt`
Сканирует активные инструменты перехвата в рантайме. Вызывается в `onResume()` в Параноидном режиме (вне Main-потока через `Dispatchers.IO`).

| Угроза | Метод обнаружения |
|---|---|
| `PROXY` | `System.getProperty("http.proxyHost")` |
| `USER_CA` | Псевдонимы AndroidCAStore начинающиеся с `"user:"` |
| `VPN` | `ConnectivityManager.TRANSPORT_VPN` |
| `ADB` | `Settings.Global.ADB_ENABLED` |
| `DEV_OPTIONS` | `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` |

PROXY + USER_CA одновременно — критическая угроза (вероятный MITM-прокси).

#### `ParanoidMode.kt`
Переключатель режима антифорензики. Когда включён:
- Подавляет весь вывод `Log.d / .i / .w` через обёртку `BLog`.
- Очищает буфер logcat при активации.
- При обнаружении угрозы: отправляет HTTP POST на настроенный пользователем URL, затем запускает уничтожение данных или переключается в режим-приманку.

HTTP-оповещения выполняются в `CoroutineScope(Dispatchers.IO + SupervisorJob())` — fire-and-forget, структурированный параллелизм.

#### `HoneyTokenManager.kt`
Обнаружение подделки через сигнальные значения. HMAC от известного набора значений сохраняется при настройке. При каждом вызове `checkIntegrity()` HMAC пересчитывается. Несовпадение означает, что базовое хранилище было изменено вне приложения.

#### `DeadMansSwitchManager.kt`
Запланированное уничтожение данных, если пользователь не выходит на связь в течение настроенного интервала. Использует `AlarmManager.setExactAndAllowWhileIdle`. При срабатывании будильника `WipeReceiver` вызывает `WipeManager.wipe()`.

#### `InviteCodeManager.kt`
Генерирует и верифицирует ECDSA-подписанные deep links для приглашения контактов:
```
beacon://invite?key=<pubKeyB64>&fp=<fingerprint>&nonce=<nonce>&name=<nameB64>&ts=<timestamp>&sig=<sigB64>
```
Подпись охватывает все поля. TTL: 7 дней от `ts`. Обратная совместимость с кодами без поля `ts`.

#### `BackupManager.kt`
Экспортирует все данные пользователя в зашифрованный бинарный блоб:
- Выведение ключа: PBKDF2-SHA256, 100 000 итераций
- Шифрование: AES-256-GCM
- Включает: сообщения, контакты, групповые ключи, подписки на каналы, настройки

#### `CallManager.kt`
Обёртка WebRTC поверх `stream-webrtc-android:1.3.10`:
- `Camera1Enumerator(false)` — YUV/NV21 захват (совместим с MIUI)
- `DefaultVideoEncoderFactory(eglBase, false, false)` — VP8 + H264 Baseline HW
- `SurfaceViewRenderer` с общим EGL-контекстом
- Все колбэки удалённых треков и завершения звонка диспетчеризируются в Main-поток через `Handler(Looper.getMainLooper()).post{}` — запись в Compose `mutableStateMapOf` из нативных потоков WebRTC вызывала `IllegalStateException`

#### `EncryptedStorage.kt`
Тонкая обёртка над `EncryptedSharedPreferences`. Возвращает именованный экземпляр преференций, защищённый master-ключом AndroidKeyStore. Всё постоянное состояние приложения (кроме открытого блоба восстановления) проходит через это хранилище.

#### `UserStorage.kt`
Хранит учётные данные пользователя и настройки устройства в `EncryptedSharedPreferences("user_prefs")`.

Хеширование пароля:
- Устаревшее: `SHA-256(password)` (только чтение, мигрируется при входе)
- Текущее: `"v2:<saltB64>:<hashB64>"` — PBKDF2-SHA256, 16-байтная соль, 100 000 итераций
- Пароль-паника использует ту же схему; совпадение при входе запускает уничтожение данных

---

## Архитектура сервера

### Модель состояния

Сервер хранит состояние в памяти (без базы данных). Всё состояние теряется при перезапуске.

```
authenticated_users: {ws → username}
clients:            {username → {ws, name, public_key}}
prekey_bundles:     {username → [OPK-пакеты]}
active_calls:       {username → {peer, call_id}}
pending_messages:   {username → [сообщения]}
rate_limits:        {username → {message, reaction, typing, prekey_fetch, ...}}
banned_users:       {username → ban_info}
banned_ips:         {ip → ban_info}
channels:           {channel_id → {name, avatar, admin_id, posts: [...]}}
channel_subscribers: {channel_id → {username}}
```

### Протокол сообщений

Все сообщения — JSON-объекты через WebSocket. Каждое сообщение имеет поле `type`.

**Клиент → Сервер (выборочно):**

| Тип | Описание |
|---|---|
| `register` | Начальная аутентификация с ответом на ECDSA-challenge |
| `message` | Зашифрованное сообщение 1-на-1 |
| `group_message` | Зашифрованное групповое сообщение |
| `channel_post` | Пост администратора в канал |
| `call_invite` | WebRTC offer к пиру |
| `call_answer` | WebRTC answer |
| `ice_candidate` | WebRTC ICE-кандидат |
| `call_end` | Завершение звонка |
| `fetch_prekey_bundle` | Запрос OPK-пакета для X3DH |
| `upload_prekeys` | Загрузка нового OPK-пакета на сервер |
| `typing` | Индикатор набора текста |
| `reaction` | Реакция на сообщение |
| `checkin` | Отметка о присутствии (Dead Man's Switch) |

**Сервер → Клиент (выборочно):**

| Тип | Описание |
|---|---|
| `challenge` | Случайные байты для ECDSA-handshake |
| `auth_ok` | Аутентификация подтверждена |
| `auth_fail` | Аутентификация отклонена |
| `message` | Ретранслированное зашифрованное сообщение |
| `group_message` | Ретранслированное групповое сообщение |
| `channel_update` | Новый пост в канале |
| `call_invite` | Входящий звонок от пира |
| `turn_config` | TURN-учётные данные (после аутентификации) |
| `session_conflict` | Вход с другого устройства |
| `prekey_bundle` | OPK-пакет для X3DH |
| `opk_low` | Напоминание загрузить новые OPK |

### Ограничение частоты запросов

Серверные ограничения применяются к каждому пользователю:

| Действие | Ограничение |
|---|---|
| Сообщения | Настраиваемый burst в минуту |
| Реакции | Настраиваемый |
| Индикаторы набора | Настраиваемый |
| Запросы prekey | Настраиваемый |

Нарушения приводят к временной блокировке.

---

## Потоки данных

### Регистрация

```
Клиент                              Сервер
  │                                   │
  │──── connect (WSS) ───────────────►│
  │◄─── challenge {bytes} ────────────│
  │                                   │
  │  1. Генерация ключевой пары       │
  │     EC P-256                      │
  │  2. ECDSA подпись(challenge)      │
  │  3. PBKDF2 хеш(пароля)           │
  │  4. Генерация OPK-пакета          │
  │  5. StorageKeyManager.setup()     │
  │                                   │
  │──── register {username, pubkey,   │
  │              signature, opks} ───►│
  │◄─── auth_ok ──────────────────────│
  │◄─── turn_config ──────────────────│
```

### Переписка один-на-один

**Первое сообщение (согласование ключей X3DH):**

```
Отправитель                         Сервер                Получатель
  │                                   │                         │
  │── fetch_prekey_bundle(recipient) ►│                         │
  │◄─ prekey_bundle {IK, SPK, OPK} ──│                         │
  │                                   │                         │
  │  1. ECDH(mySK, recipientIK)       │                         │
  │  2. ECDH(ephemeral, recipientSPK) │                         │
  │  3. ECDH(ephemeral, recipientOPK) │                         │
  │  4. KDF → сессионный ключ         │                         │
  │  5. AES-256-GCM(plaintext)        │                         │
  │                                   │                         │
  │── message {ciphertext, ephPub} ──►│── message ─────────────►│
  │                                   │                         │
  │                                   │         1. Восстановить │
  │                                   │            ключ         │
  │                                   │         2. AES-256-GCM  │
  │                                   │            расшифровать │
```

**Последующие сообщения:** Double Ratchet продвигает сессионный ключ. Каждое сообщение использует новый симметричный ключ, выведенный из состояния ratchet.

### Групповая переписка

```
Создатель                           Сервер               Участник N
  │                                   │                      │
  │  1. generateGroupKey() → 32 байта │                      │
  │  2. Для каждого участника:        │                      │
  │     encryptGroupKeyForMember()    │                      │
  │  3. Создать объект группы         │                      │
  │                                   │                      │
  │── create_group {members,          │                      │
  │     encKeyForEachMember} ────────►│── group_invite ─────►│
  │                                   │                      │
  │                          (участник сохраняет расшифрованный groupKey)
  │                                   │                      │
  │  encryptGroupMessage(text, key)   │                      │
  │── group_message {groupId, ct} ───►│── group_message ────►│
  │                                   │  (широковещательно)  │
```

### Передача файлов

Файлы разбиваются на фрагменты (до 6 МБ на пакет). Каждый фрагмент отправляется как сообщение `file_chunk`. Получатель собирает фрагменты по порядку и расшифровывает полный файл.

```
Отправитель                    Сервер                   Получатель
  │                               │                           │
  │  1. AES-256-GCM зашифровать   │                           │
  │  2. Разбить на фрагменты      │                           │
  │                               │                           │
  │─ file_chunk {id, n, total, data} ─►│─ file_chunk ────────►│
  │  (повторить для каждого фрагмента) │                      │
  │                               │                           │
  │                               │          1. Собрать       │
  │                               │          2. Расшифровать  │
```

### WebRTC-звонки

```
Звонящий            Сервер              Получатель
  │                   │                   │
  │── call_invite ───►│── call_invite ───►│
  │◄── call_answer ───│◄── call_answer ───│
  │── ice_candidate ─►│── ice_candidate ─►│
  │◄─ ice_candidate ──│◄─ ice_candidate ──│
  │                   │                   │
  │◄═══════ P2P медиапоток (WebRTC) ═════►│
  │       (через TURN если прямой UDP заблокирован)
```

TURN-учётные данные доставляются сервером после аутентификации (сообщение `turn_config`). Медиа никогда не проходит через сервер сигнализации.

### Handshake аутентификации

```
Клиент                          Сервер
  │                               │
  │── connect ───────────────────►│
  │◄── challenge {32 случайных байта}
  │                               │
  │  ECDSA.sign(challenge,        │
  │             privateKey)       │
  │                               │
  │── register/login {username,   │
  │     pubKey, signature} ──────►│
  │                               │
  │                    ECDSA.verify(
  │                      signature,
  │                      challenge,
  │                      pubKey)
  │                               │
  │◄── auth_ok ───────────────────│
```

Таймаут: 15 секунд. Если аутентификация не завершена вовремя, сервер закрывает соединение.

---

## Хранилище данных

Все постоянные данные хранятся в именованных экземплярах `EncryptedSharedPreferences`, защищённых Android Keystore. Каждый логический домен использует отдельный файл преференций.

| Файл преференций | Владелец | Содержимое |
|---|---|---|
| `user_prefs` | `UserStorage` | Имя пользователя, хеш пароля, device_id, настройки |
| `beacon_ec_keys_enc` | `CryptoManager` | EC identity key pair |
| `chat_storage_encrypted` | `ChatStorage` | Сообщения, контакты, ключи, аватары |
| `groups` | `GroupManager` | Метаданные и ключи групп |
| `group_messages_*` | `GroupManager` | История сообщений по группам |
| `subscribed_channels` | `ChannelManager` | Список каналов |
| `ch_posts_*` | `ChannelManager` | История постов по каналам |
| `smk_config` | `StorageKeyManager` | Зашифрованные экземпляры SMK |
| `dms_prefs` | `DeadMansSwitchManager` | Интервал DMS и время последней отметки |
| `honey_prefs` | `HoneyTokenManager` | Контрольный HMAC (canary) |

Файлы бэкапа — бинарные блобы (AES-256-GCM), передаются через системный диалог выбора файлов. Облако не используется.

---

## Зависимости

### Android-клиент

| Библиотека | Версия | Назначение |
|---|---|---|
| Jetpack Compose BOM | 2024.x | UI-фреймворк |
| AndroidX Security Crypto | 1.1.0-alpha06 | EncryptedSharedPreferences |
| AndroidX Biometric | 1.1.0 | Биометрическая разблокировка |
| OkHttp3 | 4.12.0 | WebSocket-клиент |
| Kotlin Coroutines | 1.7.3 | Асинхронность / IO |
| stream-webrtc-android | 1.3.10 | WebRTC |
| Firebase Messaging | latest | Push-уведомления |
| CameraX | 1.3.4 | Превью камеры |
| osmdroid | 6.1.18 | Карты |
| ZXing | 3.5.1 | QR-коды |
| Play Services Location | 21.2.0 | GPS |

### Сервер

| Библиотека | Назначение |
|---|---|
| `websockets` | Асинхронный WebSocket-сервер |
| `cryptography` | Верификация ECDSA |
