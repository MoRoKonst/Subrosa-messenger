package com.subrosa.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf

/** Desktop's localization system — mirrors the shape of Android's
 *  AppStrings.kt (interface + one object per language), but starts with a
 *  much smaller, curated key set covering the highest-traffic screens
 *  (chat list, profile/settings, chat input bar, common dialog actions)
 *  rather than a 1:1 port of Android's ~500 keys. Desktop had NO
 *  localization system at all before this — every string was hardcoded
 *  Russian across ~20 files. UserStorage.getLanguage()/setLanguage()
 *  already existed (default "ru") but were never wired to anything.
 *  Screens not yet migrated to `LocalStrings.current` keep their existing
 *  hardcoded Russian text — this is a first pass, not full coverage; see
 *  the language toggle in ProfileScreen for what's actually translated
 *  today. */
interface Strings {
    // Common actions, reused across many dialogs
    val cancel: String
    val close: String
    val save: String
    val saved: String
    val copy: String
    val copied: String
    val profileShareCode: String
    val delete: String
    val send: String
    val confirm: String
    val paste: String

    // Chats list
    val chatsMyId: String
    val chatsProfile: String
    val chatsAddContact: String
    val chatsNoContacts: String
    val chatsSearch: String
    val chatsGroupMembers: (Int) -> String
    val chatsAddContactTitle: String
    val chatsAddContactHint: String
    val chatsInviteLinkLabel: String
    val chatsLoadQrFromFile: String
    val chatsQrDecodeFailed: String
    val chatsInvalidLinkFormat: String
    val chatsInvalidOrExpiredLink: String
    val chatsMyInviteTitle: String
    val chatsCreateGroup: String

    // Profile / settings
    val profileTitle: String
    val profileChangePhoto: String
    val profileSectionIdentity: String
    val profileMyInvite: String
    val profileFingerprint: String
    val profileSectionServer: String
    val profileServers: String
    val profileServerUrl: String
    val profileServerUrlHint: String
    val profileAccessCode: String
    val profileAccessCodeHint: String
    val profileSectionBackup: String
    val profileBackupItem: String
    val profileBackupHint: String
    val profileSectionSecurity: String
    val profileChangePassword: String
    val profileTotp: String
    val profileTotpEnabled: String
    val profileTotpDisabled: String
    val profileAutoLock: String
    val profileAutoLockOff: String
    val profileAutoLock5min: String
    val profileAutoLock15min: String
    val profileAutoLock30min: String
    val profileAutoLock1h: String
    val profileExitOnDebugger: String
    val profileExitOnDebuggerHint: String
    val profileCoverTraffic: String
    val profileCoverTrafficOff: String
    val profileCoverTrafficModerate: String
    val profileCoverTrafficAggressive: String
    val profileTorToggle: String
    val profileTorToggleHint: String
    val profileHideIpCalls: String
    val profileHideIpCallsHint: String
    val profileHideIpCallsFailedNoTurn: String
    val profileDiagnostics: String
    val profileDiagnosticsHint: String
    val profileSectionNotifications: String
    val profileNotificationsEnabled: String
    val profileNotificationsEnabledHint: String
    val profileNotificationSound: String
    val profileNotificationSoundHint: String
    val profileSectionAbout: String
    val profileSecurityGuide: String
    val profileSecurityGuideHint: String
    val profileSourceCode: String
    val profileLanguage: String
    val profileNotMe: String
    val profileCompromised: String

    // Chat screen input bar
    val chatMessagePlaceholder: String
    val chatConnectingPlaceholder: String
    val chatAttach: String
    val chatVoiceOrVideo: String
    val chatKeyboard: String
    val chatMenu: String
    val chatVerifyKey: String
    val chatRestoreConnection: String
    val chatAutoDeleteMenu: String
    val chatDisappearMenu: String

    // Per-chat mute (ChatsScreen right-click "chat actions" dialog)
    val chatsActionsTitle: String
    val chatsActionMute: String
    val chatsActionInfo: String
    val chatsActionDelete: String
    val muteDialogTitle: String
    val muteOff: String
    val mute1h: String
    val mute2h: String
    val mute5h: String
    val mute8h: String
    val muteForever: String
    val muteStatusOff: String
    val muteStatusForever: String
    val muteStatusUntil: (String) -> String
    val contactInfoTitle: String
    val chatsDeleteTitle: String
    val chatsDeleteText: (String) -> String
    val contactInfoNotifications: String
    val muteSoundOnly: String
    val contactInfoSearch: String

    // Panic password
    val profilePanicPassword: String
    val profilePanicPasswordHint: String
    val profilePanicSetTitle: String
    val profilePanicSetInstruction: String
    val profilePanicSetLabel: String
    val profilePanicFieldLabel: String
}

object RuStrings : Strings {
    override val cancel = "Отмена"
    override val close = "Закрыть"
    override val save = "Сохранить"
    override val saved = "Сохранено"
    override val copy = "Копировать"
    override val copied = "Скопировано"
    override val profileShareCode = "Поделиться кодом"
    override val delete = "Удалить"
    override val send = "Отправить"
    override val confirm = "Подтвердить"
    override val paste = "Вставить"

    override val chatsMyId = "Мой ID"
    override val chatsProfile = "Профиль"
    override val chatsAddContact = "Добавить контакт"
    override val chatsNoContacts = "Нет контактов"
    override val chatsSearch = "Поиск"
    override val chatsGroupMembers = { n: Int -> "$n участников" }
    override val chatsAddContactTitle = "Добавить контакт"
    override val chatsAddContactHint = "Вставь инвайт-код (bc:…), полученный от другого пользователя."
    override val chatsInviteLinkLabel = "Ссылка-приглашение"
    override val chatsLoadQrFromFile = "Загрузить QR из файла…"
    override val chatsQrDecodeFailed = "Не удалось распознать QR-код в файле"
    override val chatsInvalidLinkFormat = "Неверный формат ссылки"
    override val chatsInvalidOrExpiredLink = "Подпись неверна или код устарел"
    override val chatsMyInviteTitle = "Мой инвайт-код"
    override val chatsCreateGroup = "Создать группу"

    override val profileTitle = "Профиль"
    override val profileChangePhoto = "Нажмите, чтобы изменить фото"
    override val profileSectionIdentity = "Идентификатор"
    override val profileMyInvite = "Мой инвайт-код"
    override val profileFingerprint = "Fingerprint"
    override val profileSectionServer = "Сервер"
    override val profileServers = "Серверы"
    override val profileServerUrl = "URL сервера"
    override val profileServerUrlHint = "Перезапустите приложение для применения"
    override val profileAccessCode = "Код доступа (если сервер требует)"
    override val profileAccessCodeHint = "Нужен только для регистрации первого аккаунта на защищённом сервере — одноразовый"
    override val profileSectionBackup = "Резервное копирование"
    override val profileBackupItem = "Экспорт / импорт бэкапа"
    override val profileBackupHint = "Зашифрованная копия переписки и ключа"
    override val profileSectionSecurity = "Безопасность"
    override val profileChangePassword = "Сменить пароль"
    override val profileTotp = "Двухфакторная защита (TOTP)"
    override val profileTotpEnabled = "Включено"
    override val profileTotpDisabled = "Выключено"
    override val profileAutoLock = "Автоблокировка"
    override val profileAutoLockOff = "Выключено"
    override val profileAutoLock5min = "5 минут"
    override val profileAutoLock15min = "15 минут"
    override val profileAutoLock30min = "30 минут"
    override val profileAutoLock1h = "1 час"
    override val profileExitOnDebugger = "Выход при обнаружении отладчика"
    override val profileExitOnDebuggerHint = "Завершить процесс при JDWP / Frida"
    override val profileCoverTraffic = "Маскировка трафика (cover traffic)"
    override val profileCoverTrafficOff = "Выключено"
    override val profileCoverTrafficModerate = "Умеренно (1 пакет / 5 сек)"
    override val profileCoverTrafficAggressive = "Агрессивно (1 пакет / сек)"
    override val profileTorToggle = "Маршрутизировать через Tor"
    override val profileTorToggleHint = "Перезапустите приложение для применения. Требует запущенный Tor (демон или Tor Browser) — иначе соединение не установится"
    override val profileHideIpCalls = "Скрывать IP во время звонков"
    override val profileHideIpCallsHint = "Звонок идёт только через relay-сервер — собеседник не увидит ваш IP. Может увеличить задержку"
    override val profileHideIpCallsFailedNoTurn = "Не удалось начать звонок: relay-сервер недоступен, а в этом режиме прямое соединение запрещено"
    override val profileDiagnostics = "Диагностика безопасности"
    override val profileDiagnosticsHint = "Проверка криптографии и окружения"
    override val profileSectionNotifications = "Уведомления"
    override val profileNotificationsEnabled = "Уведомления"
    override val profileNotificationsEnabledHint = "Всплывающее окно при новом сообщении, если приложение свёрнуто или не в фокусе"
    override val profileNotificationSound = "Звук уведомлений"
    override val profileNotificationSoundHint = "Короткий сигнал вместе со всплывающим окном"
    override val profileSectionAbout = "О приложении"
    override val profileSecurityGuide = "Гид по защите"
    override val profileSecurityGuideHint = "Как работают функции безопасности"
    override val profileSourceCode = "Исходный код (AGPL-3.0)"
    override val profileLanguage = "Язык"
    override val profileNotMe = "Это не я — экстренная очистка"
    override val profileCompromised = "Меня скомпрометировали"

    override val chatMessagePlaceholder = "Сообщение…"
    override val chatConnectingPlaceholder = "Устанавливаем защищённый канал…"
    override val chatAttach = "Прикрепить"
    override val chatVoiceOrVideo = "Голосовое / видео (зажать — запись, тап — сменить режим)"
    override val chatKeyboard = "Экранная клавиатура"
    override val chatMenu = "Меню"
    override val chatVerifyKey = "Проверить ключ"
    override val chatRestoreConnection = "Восстановить связь"
    override val chatAutoDeleteMenu = "Автоудаление (только на этом устройстве)"
    override val chatDisappearMenu = "Исчезающие сообщения (синхронизировано с собеседником)"

    override val chatsActionsTitle = "Чат"
    override val chatsActionMute = "Отключить звук"
    override val chatsActionInfo = "Открыть профиль"
    override val chatsActionDelete = "Удалить чат"
    override val muteDialogTitle = "Отключить уведомления"
    override val muteOff = "Не отключать"
    override val mute1h = "На 1 час"
    override val mute2h = "На 2 часа"
    override val mute5h = "На 5 часов"
    override val mute8h = "На 8 часов"
    override val muteForever = "Навсегда"
    override val muteStatusOff = "Не отключены"
    override val muteStatusForever = "Отключены навсегда"
    override val muteStatusUntil: (String) -> String = { "Отключены до $it" }
    override val contactInfoTitle = "Профиль"
    override val chatsDeleteTitle = "Удалить чат?"
    override val chatsDeleteText: (String) -> String = { "«$it» будет удалён. История переписки также будет удалена." }
    override val contactInfoNotifications = "Уведомления"
    override val muteSoundOnly = "Отключить звук уведомлений"
    override val contactInfoSearch = "Поиск по чату"

    override val profilePanicPassword = "Panic password"
    override val profilePanicPasswordHint = "Пароль для экстренного удаления всех данных"
    override val profilePanicSetTitle = "Panic password"
    override val profilePanicSetInstruction = "Сценарий использования:\n① В экстренной ситуации введите этот пароль вместо обычного — все данные будут безвозвратно уничтожены, приложение покажет фейковый мессенджер.\n② После перезапуска и обычный, и panic-пароль будут показывать фейковый мессенджер — обратного пути нет."
    override val profilePanicSetLabel = "Введите пароль для экстренного удаления данных"
    override val profilePanicFieldLabel = "Panic password"
}

object EnStrings : Strings {
    override val cancel = "Cancel"
    override val close = "Close"
    override val save = "Save"
    override val saved = "Saved"
    override val copy = "Copy"
    override val copied = "Copied"
    override val profileShareCode = "Share code"
    override val delete = "Delete"
    override val send = "Send"
    override val confirm = "Confirm"
    override val paste = "Paste"

    override val chatsMyId = "My ID"
    override val chatsProfile = "Profile"
    override val chatsAddContact = "Add contact"
    override val chatsNoContacts = "No contacts"
    override val chatsSearch = "Search"
    override val chatsGroupMembers = { n: Int -> "$n members" }
    override val chatsAddContactTitle = "Add contact"
    override val chatsAddContactHint = "Paste the invite code (bc:…) you got from another user."
    override val chatsInviteLinkLabel = "Invite link"
    override val chatsLoadQrFromFile = "Load QR from file…"
    override val chatsQrDecodeFailed = "Couldn't read a QR code in that file"
    override val chatsInvalidLinkFormat = "Invalid link format"
    override val chatsInvalidOrExpiredLink = "Signature invalid or code expired"
    override val chatsMyInviteTitle = "My invite code"
    override val chatsCreateGroup = "Create group"

    override val profileTitle = "Profile"
    override val profileChangePhoto = "Tap to change photo"
    override val profileSectionIdentity = "Identity"
    override val profileMyInvite = "My invite code"
    override val profileFingerprint = "Fingerprint"
    override val profileSectionServer = "Server"
    override val profileServers = "Servers"
    override val profileServerUrl = "Server URL"
    override val profileServerUrlHint = "Restart the app to apply"
    override val profileAccessCode = "Access code (if the server requires one)"
    override val profileAccessCodeHint = "Only needed to register the first account on a protected server — one-time use"
    override val profileSectionBackup = "Backup"
    override val profileBackupItem = "Export / import backup"
    override val profileBackupHint = "Encrypted copy of your messages and keys"
    override val profileSectionSecurity = "Security"
    override val profileChangePassword = "Change password"
    override val profileTotp = "Two-factor protection (TOTP)"
    override val profileTotpEnabled = "Enabled"
    override val profileTotpDisabled = "Disabled"
    override val profileAutoLock = "Auto-lock"
    override val profileAutoLockOff = "Off"
    override val profileAutoLock5min = "5 minutes"
    override val profileAutoLock15min = "15 minutes"
    override val profileAutoLock30min = "30 minutes"
    override val profileAutoLock1h = "1 hour"
    override val profileExitOnDebugger = "Exit on debugger detection"
    override val profileExitOnDebuggerHint = "Terminate the process on JDWP / Frida"
    override val profileCoverTraffic = "Traffic masking (cover traffic)"
    override val profileCoverTrafficOff = "Off"
    override val profileCoverTrafficModerate = "Moderate (1 packet / 5s)"
    override val profileCoverTrafficAggressive = "Aggressive (1 packet / s)"
    override val profileTorToggle = "Route via Tor"
    override val profileTorToggleHint = "Restart the app to apply. Requires Tor to be running (daemon or Tor Browser) — otherwise the connection won't be established"
    override val profileHideIpCalls = "Hide IP during calls"
    override val profileHideIpCallsHint = "Route calls only through the relay server. This hides your IP address from the other participant, but may increase latency"
    override val profileHideIpCallsFailedNoTurn = "Couldn't start the call: the relay server is unavailable, and this mode doesn't allow a direct connection"
    override val profileDiagnostics = "Security diagnostics"
    override val profileDiagnosticsHint = "Checks cryptography and environment"
    override val profileSectionNotifications = "Notifications"
    override val profileNotificationsEnabled = "Notifications"
    override val profileNotificationsEnabledHint = "Pop up a toast for a new message when the app is minimized or unfocused"
    override val profileNotificationSound = "Notification sound"
    override val profileNotificationSoundHint = "Short chime alongside the toast"
    override val profileSectionAbout = "About"
    override val profileSecurityGuide = "Security guide"
    override val profileSecurityGuideHint = "How the security features work"
    override val profileSourceCode = "Source code (AGPL-3.0)"
    override val profileLanguage = "Language"
    override val profileNotMe = "This isn't me — emergency wipe"
    override val profileCompromised = "I've been compromised"

    override val chatMessagePlaceholder = "Message…"
    override val chatConnectingPlaceholder = "Establishing secure channel…"
    override val chatAttach = "Attach"
    override val chatVoiceOrVideo = "Voice / video (hold to record, tap to switch mode)"
    override val chatKeyboard = "On-screen keyboard"
    override val chatMenu = "Menu"
    override val chatVerifyKey = "Verify key"
    override val chatRestoreConnection = "Restore connection"
    override val chatAutoDeleteMenu = "Auto-delete (this device only)"
    override val chatDisappearMenu = "Disappearing messages (synced with contact)"

    override val chatsActionsTitle = "Chat"
    override val chatsActionMute = "Mute"
    override val chatsActionInfo = "Open info"
    override val chatsActionDelete = "Delete chat"
    override val muteDialogTitle = "Mute notifications"
    override val muteOff = "Don't mute"
    override val mute1h = "For 1 hour"
    override val mute2h = "For 2 hours"
    override val mute5h = "For 5 hours"
    override val mute8h = "For 8 hours"
    override val muteForever = "Forever"
    override val muteStatusOff = "Not muted"
    override val muteStatusForever = "Muted forever"
    override val muteStatusUntil: (String) -> String = { "Muted until $it" }
    override val contactInfoTitle = "Profile"
    override val chatsDeleteTitle = "Delete chat?"
    override val chatsDeleteText: (String) -> String = { "\"$it\" will be deleted. The message history will be deleted too." }
    override val contactInfoNotifications = "Notifications"
    override val muteSoundOnly = "Mute notification sound"
    override val contactInfoSearch = "Search in chat"

    override val profilePanicPassword = "Panic password"
    override val profilePanicPasswordHint = "Password for emergency data deletion"
    override val profilePanicSetTitle = "Panic password"
    override val profilePanicSetInstruction = "How it works:\n① In an emergency, enter this password instead of your real one — all data is permanently destroyed and the app shows a fake messenger.\n② After that, both your real password and the panic password will show the fake messenger — there's no way back."
    override val profilePanicSetLabel = "Enter a password for emergency data deletion"
    override val profilePanicFieldLabel = "Panic password"
}

/** Backed by UserStorage.getLanguage()/setLanguage() (already existed,
 *  default "ru", just never wired to anything before this). */
object AppLanguage {
    var code by mutableStateOf(UserStorage.getLanguage())
        private set

    val strings: Strings
        get() = if (code == "en") EnStrings else RuStrings

    fun set(newCode: String) {
        code = newCode
        UserStorage.setLanguage(newCode)
    }

    fun toggle() = set(if (code == "en") "ru" else "en")
}

val LocalStrings = staticCompositionLocalOf<Strings> { RuStrings }
