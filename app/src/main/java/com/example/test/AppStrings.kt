package com.bcon.messenger

import androidx.compose.runtime.compositionLocalOf

// ─── AppStrings split across 8 interfaces ─────────────────────────────────────
//
// Kotlin data class с 323 параметрами вызывает VerifyError на Android ART,
// потому что DEX-верификатор ограничивает число регистров аргументов (~68).
// Решение: разбиваем строки на 8 интерфейсов; data class AppStrings делегирует
// каждый интерфейс отдельному параметру — итого 9 параметров в конструкторе.
// Все вызовы вида `s.cancel`, `s.loginGreeting(name)` и т.д. работают как прежде.

// ─── Part 1: Common + Login ───────────────────────────────────────────────────
interface IStr1 {
    val cancel: String; val back: String; val save: String; val add: String
    val delete: String; val create: String; val next: String; val write: String
    val close: String; val change: String; val setAction: String
    val yes: String; val ok: String
    val error: (String) -> String
    val loginGreeting: (String) -> String
    val loginPassword: String
    val loginTooManyAttempts: (Long, Long) -> String
    val loginEnterPassword: String; val loginWrongPassword: String
    val loginButton: String; val loginBiometric: String
    val loginWaitingBiometric: String
    val loginNotMe: String; val loginNotMeTitle: String
    val loginNotMeText: String; val loginNotMeConfirm: String
}

// ─── Part 2: Register + Chats ─────────────────────────────────────────────────
interface IStr2 {
    val registerTitle: String; val registerSubtitle: String
    val registerUsername: String; val registerUsernamePlaceholder: String
    val registerPassword: String; val registerRepeatPassword: String
    val registerGeneratingKeys: String
    val registerErrorEnterUsername: String; val registerErrorPasswordLength: String
    val registerErrorPasswordMatch: String; val registerButton: String
    val registerImportBackup: String; val registerImportTitle: String
    val registerImportHint: String; val registerImportPassword: String
    val registerImportChooseFile: String
    val chatsNoMessages: String; val chatsNoPosts: String
    val chatsEmpty: String; val chatsEmptyHint: String
    val chatsDeleteTitle: String; val chatsDeleteText: (String) -> String
    val chatsAddContact: String; val chatsInviteCode: String
    val chatsContactAdded: (String) -> String; val chatsCreateTitle: String
    val chatsCreateContact: String; val chatsCreateGroup: String
    val chatsSubscribeChannel: String; val chatsCreateChannel: String
    val chatsChannelSubscribeTitle: String; val chatsChannelLinkLabel: String
    val chatsChannelCreateTitle: String
    val chatsChannelNameLabel: String
    val chatsChannelDescLabel: String; val chatsChannelFillFields: String
    val chatsChannelBadLink: String; val chatsChannelBadge: String
    val chatsSupportWrite: String
}

// ─── Part 3: Profile + Backup ─────────────────────────────────────────────────
interface IStr3 {
    val profileTitle: String; val profileFingerprint: String
    val profileFingerprintHint: String; val profileInviteCode: String
    val profileShareCode: String; val profileHideQr: String
    val profileShowQr: String; val profileScanQr: String
    val profileQrHint: String; val profileCodeCopied: String
    val profileSendHint: String; val profileServers: String
    val profileSupport: String; val profileBackup: String
    val profileSectionSecurity: String; val profileSectionGeneral: String
    val profileHideNotif: String; val profileHideNotifSub: String
    val profileAutoLock: String; val profileAutoLockAfter: (String) -> String
    val profileLockOff: String; val profileLock1min: String
    val profileLock5min: String; val profileLock15min: String
    val profileLock30min: String; val profileEmergencyBtn: String
    val profileEmergencyBtnSub: String; val profileNotMe: String
    val profileNotMeTitle: String; val profileNotMeText: String
    val profileNotMeConfirm: String; val profileDiagnostics: String
    val profilePanicTitle: String; val profilePanicSub: String
    val profilePanicSetStatus: String; val profilePanicEnterLabel: String
    val profilePanicInstruction: String
    val profilePanicFieldLabel: String; val profileLanguageToggle: String
    val profileThemeLabel: String; val profileThemeNavy: String
    val profileThemeDark: String; val profileThemeLight: String
    val profileInvalidCodeFormat: String; val profileInvalidOrExpiredCode: String
    val profileCameraPermReq: String; val profileQrScanPrompt: String
    val backupTitle: String; val backupSubtitle: String
    val backupSecurityTitle: String; val backupSecurityText: String
    val backupSecurityTips: String; val backupPassword: String
    val backupRepeatPassword: String; val backupExport: String
    val backupImport: String; val backupSaveChooser: String
    val backupCreated: String; val backupErrEnterPassword: String
    val backupErrPasswordMatch: String; val backupErrPasswordLength: String
    val backupErrEnterForDecrypt: String
}

// ─── Part 4: Servers + Group Info + Create Group ──────────────────────────────
interface IStr4 {
    val serversTitle: String; val serversAdd: String
    val serversSwitch: String; val serversSwitching: String
    val serversDefault: (Int) -> String; val serversConnected: String
    val serversConnecting: String; val serversAddTitle: String
    val serversName: String; val serversHost: String; val serversPort: String
    val groupInfoTitle: String; val groupInfoNotFound: String
    val groupInfoMembersCount: (Int) -> String; val groupInfoDescription: String
    val groupInfoAddDescription: String; val groupInfoNoDescription: String
    val groupInfoMembersSection: String; val groupInfoCreator: String
    val groupInfoAdmin: String; val groupInfoPromoteAdmin: String
    val groupInfoRemoveMember: String; val groupInfoLeave: String
    val groupInfoDeleteGroup: String; val groupInfoAddMemberTitle: String
    val groupInfoAddMemberHint: String; val groupInfoAddMemberLabel: String
    val groupInfoAlreadyMember: String; val groupInfoBadInvite: String
    val groupInfoLeaveTitle: String; val groupInfoLeaveText: (String) -> String
    val groupInfoLeaveConfirm: String; val groupInfoDeleteTitle: String
    val groupInfoDeleteText: (String) -> String; val groupInfoEmojiTitle: String
    val groupInfoDescTitle: String; val groupInfoDescLabel: String
    val groupInfoChangeAvatar: String
    val createGroupTitle: String; val createGroupTapAvatar: String
    val createGroupNameLabel: String
    val createGroupMembersTitle: (Int) -> String
    val createGroupButton: String; val createGroupAvatarTitle: String
}

// ─── Part 5: Channel Feed + Calls + Diagnostics ───────────────────────────────
interface IStr5 {
    val channelDefault: String; val channelCopyLink: String
    val channelUnsubscribe: String; val channelPostPlaceholder: String
    val channelLinkCopied: String; val channelLoadImageError: String
    val channelWriteFirst: String; val channelSubscribeConfirm: String
    val channelSubscribeBtn: String
    val channelMute: String; val channelUnmute: String
    val channelSubscribers: (Int) -> String
    val channelSearchPlaceholder: String
    val channelPinPost: String; val channelUnpinPost: String; val channelPinned: String
    val channelDeletePost: String
    val channelForwardPost: String; val channelForwardTitle: String; val channelForwardSent: String
    val channelDeleteChannelTitle: String; val channelDeleteChannelText: String
    val channelEditTitle: String; val channelSaved: String
    val incomingGroupCall: String; val incomingVideoCall: String
    val incomingAudioCall: String; val incomingGroupCallHint: String
    val incomingCallHint: String; val incomingDecline: String
    val incomingAccept: String; val incomingNoCameraPermission: String
    val activeGroupCallLabel: String; val activeGroupLabel: String
    val activeWaitingPeers: String; val activeConnecting: String
    val activeMute: String; val activeUnmute: String
    val activeCamOff: String; val activeCamOn: String
    val activeSpeaker: String; val activeEarpiece: String; val activeHangUp: String
    val diagTitle: String; val diagInitText: String
    val diagRunning: String; val diagBasic: String; val diagStress: String; val diagAdvanced: String
}

// ─── Part 6: Chat Screen ──────────────────────────────────────────────────────
interface IStr6 {
    val chatSearchPlaceholder: String; val chatOnline: String; val chatOffline: String
    val chatKeyWarningTitle: String; val chatKeyWarningText: String
    val chatKeyWarningConfirm: String; val chatKeyWarningLeave: String
    val chatTyping: String; val chatMenu: String
    val chatAudioCall: String; val chatVideoCall: String
    val chatVerifyAction: String; val chatDirectConnection: String
    val chatContextReply: String; val chatContextCopy: String
    val chatContextReaction: String; val chatContextEdit: String
    val chatContextDeleteOwn: String; val chatContextDeleteAll: String
    val chatPickReaction: String; val chatDisappearTitle: String
    val chatDisappearOff: String; val chatDisappear1h: String
    val chatDisappear24h: String; val chatDisappear7d: String
    val chatDisappear1hShort: String; val chatDisappear24hShort: String
    val chatDisappear7dShort: String; val chatReplyPreview: String
    val chatEditing: String; val chatAttach: String
    val chatAttachPhoto: String; val chatAttachMedia: String; val chatAttachFile: String
    val chatGeo: String; val chatGeoPermission: String
    val chatGeoFail: String; val chatGeoTap: String; val chatGeoDisabled: String
    val chatEditHint: String; val chatInputHint: String
    val chatPhotoTooBig: String; val chatFileTooBig: String
    val chatMediaOffline: String
    val chatFileSending: (String, Int) -> String
    val chatVerifyTitle: String; val chatVerifyFingerprintLabel: String
    val chatVerifyHint: String; val chatVerifyKeyError: String
    val chatVerifyUnknown: String; val chatReplyLabel: String
    val chatPhotoDesc: String; val chatFileNotFound: String
    val chatFileDecryptError: String; val chatFileOpenError: (String) -> String
    val chatEdited: String
    val verifyScreenTitle: String; val verifyCheckKey: String
    val verifyContact: (String) -> String; val verifyKeyNotFound: String
    val verifyEmojiLabel: String; val verifyEmojiHint: (String) -> String
    val verifyHexLabel: String; val verifyHint: String
    val verifyMarkVerified: String; val verifyAlreadyVerified: String
    val chatLoadEarlier: String
    val chatSavePhoto: String; val chatPhotoSaved: String
}

// ─── Part 7: MainActivity / TorManager / MessengerService / Notifications ──────
interface IStr7 {
    val torConnecting: String; val torIpHidden: String; val torConnected: String
    val torStartingOrbot: String; val torConnectingNetwork: String
    val torAlmostReady: String; val serviceConnecting: String
    val serviceConnected: (String) -> String
    val rootDangerTitle: String; val rootDangerText: String
    val rootDangerReasons: (String) -> String; val rootDangerRecommend: String
    val rootDangerContinue: String; val rootWarningTitle: String
    val rootWarningText: String; val rootWarningConfirm: String
    val lockTitle: String; val lockUnlock: String
    val lockBiometricTitle: String; val lockBiometricSubtitle: String
    val lockBiometricCancel: String
    val noCameraPermissionVoiceOnly: String; val torStatusStarting: String
    val emergencyInfoTitle: String; val emergencyInfoMessage: String
    val emergencyInfoOpenSettings: String; val emergencyInfoOpenAppSettings: String
    val spyAppsAccessibilitySection: String; val spyAppsAdminsSection: String
    val spyAppsOverlaySection: String
    val spyAppsTitle: String; val spyAppsMessage: (String) -> String
    val spyAppsSettings: String; val groupCallPeerName: String
    val systemSender: String; val groupMemberLeft: (String) -> String
    val groupKeyUpdated: String; val groupMemberJoined: (String) -> String
    val channelCreatedToast: (String) -> String; val channelFallbackName: String
    val channelNoConnection: String
    val recipientOffline: String; val notifChannelDesc: String
    val notifSessionTitle: String; val notifSessionText: String
    val notifNewMessage: String; val notifTapToRead: String
    val notifMessageCount: (Int) -> String; val notifGroupFallback: String
    val notifNewGroupMessage: String; val notifMissedVideoCall: String
    val notifMissedCall: String; val notifFromCaller: (String) -> String
    val notifEmergencyText: String; val notifEmergencyAction: String
    val tamperTitle: String; val tamperText: String; val tamperClose: String
    val paranoidModeTitle: String; val paranoidModeSub: String
    val paranoidModeConfirmTitle: String; val paranoidModeConfirmText: String
    val paranoidModeConfirmBtn: String; val paranoidModeActive: String
    val idsTitle: String; val idsScanBtn: String
    val idsClean: String; val idsThreatFound: String; val idsHoneyTampered: String
    val alertUrlLabel: String; val alertUrlHint: String; val alertUrlSave: String
}

// ─── Part 8: Group Chat Screen ────────────────────────────────────────────────
interface IStr8 {
    val groupChatNoMessages: String; val groupChatMessageHint: String
    val groupChatEditHint: String; val groupChatInfo: String
    val groupChatReply: String; val groupChatCopy: String
    val groupChatReactionLabel: String; val groupChatEditAction: String
    val groupChatDeleteOwn: String; val groupChatDeleteAll: String
    val groupChatPickReaction: String; val groupChatEditing: String
    val groupChatAttach: String; val groupChatAttachPhoto: String
    val groupChatAttachFile: String; val groupChatGeo: String
    val groupChatGeoPermission: String; val groupChatGeoFail: String
}

interface IStr9 {
    val wipeSettingsTitle: String
    val dmsTitle: String; val dmsSubtitle: String; val dmsCheckinBtn: String
    val dmsNotifTitle: String; val dmsNotifText: String; val dmsNotifGraceText: String
    val dmsIntervalLabel: String; val dmsIntervalHours: String
    val dmsEnabledLabel: String
    val timeoutWipeTitle: String; val timeoutWipeSubtitle: String
    val wipeOnBreachTitle: String; val wipeOnBreachSubtitle: String
    val wipeLevelLabel: String
    val wipeLevelSoft: String; val wipeLevelHard: String; val wipeLevelNuclear: String
    val wipeSoftDesc: String; val wipeHardDesc: String; val wipeNuclearDesc: String
    val wipeSettingsWarning: String
    val panicButtonLabel: String; val panicButtonSubtitle: String
    val panicButtonDecoyLabel: String; val panicButtonDecoySubtitle: String
    val panicNotifTitle: String; val panicNotifText: String; val panicNotifButton: String
    val calcDisguiseLabel: String; val calcDisguiseSubtitle: String
}

// ─── Основной класс: 10 параметров, делегирует доступ 9 интерфейсам ───────────
data class AppStrings(
    val langCode: String,
    private val p1: IStr1,
    private val p2: IStr2,
    private val p3: IStr3,
    private val p4: IStr4,
    private val p5: IStr5,
    private val p6: IStr6,
    private val p7: IStr7,
    private val p8: IStr8,
    private val p9: IStr9,
) : IStr1 by p1, IStr2 by p2, IStr3 by p3, IStr4 by p4,
    IStr5 by p5, IStr6 by p6, IStr7 by p7, IStr8 by p8, IStr9 by p9

// ─── Русский (по умолчанию) ───────────────────────────────────────────────────

private val ru1 = object : IStr1 {
    override val cancel = "Отмена"
    override val back = "Назад"
    override val save = "Сохранить"
    override val add = "Добавить"
    override val delete = "Удалить"
    override val create = "Создать"
    override val next = "Далее"
    override val write = "Написать"
    override val close = "Закрыть"
    override val change = "Изменить"
    override val setAction = "Установить"
    override val yes = "Да"
    override val ok = "Понятно"
    override val error: (String) -> String = { "Ошибка: $it" }
    override val loginGreeting: (String) -> String = { "Привет, $it" }
    override val loginPassword = "Пароль"
    override val loginTooManyAttempts: (Long, Long) -> String = { m, s -> "Слишком много попыток. Попробуйте через ${m}м ${s}с" }
    override val loginEnterPassword = "Введите пароль"
    override val loginWrongPassword = "Неверный пароль"
    override val loginButton = "Войти"
    override val loginBiometric = "🔐 Биометрия"
    override val loginWaitingBiometric = "Ожидание биометрии..."
    override val loginNotMe = "Это не я — сбросить"
    override val loginNotMeTitle = "⚠️ Сбросить всё?"
    override val loginNotMeText = "Это удалит ВСЕ данные навсегда!"
    override val loginNotMeConfirm = "Да, удалить всё"
}

private val ru2 = object : IStr2 {
    override val registerTitle = "Создать аккаунт"
    override val registerSubtitle = "Все данные хранятся только на устройстве"
    override val registerUsername = "Имя пользователя"
    override val registerUsernamePlaceholder = "например: alice"
    override val registerPassword = "Пароль"
    override val registerRepeatPassword = "Повторите пароль"
    override val registerGeneratingKeys = "Генерация ключей шифрования..."
    override val registerErrorEnterUsername = "Введите имя"
    override val registerErrorPasswordLength = "Пароль минимум 6 символов"
    override val registerErrorPasswordMatch = "Пароли не совпадают"
    override val registerButton = "Создать аккаунт"
    override val registerImportBackup = "📥 Восстановить из бэкапа"
    override val registerImportTitle = "Восстановить из бэкапа"
    override val registerImportHint = "Введите пароль которым был зашифрован бэкап, затем выберите файл .backup"
    override val registerImportPassword = "Пароль бэкапа"
    override val registerImportChooseFile = "Выбрать файл"
    override val chatsNoMessages = "Нет сообщений"
    override val chatsNoPosts = "Нет записей"
    override val chatsEmpty = "Нет чатов"
    override val chatsEmptyHint = "Нажми ➕ чтобы добавить контакт\nили создать группу"
    override val chatsDeleteTitle = "Удалить чат?"
    override val chatsDeleteText: (String) -> String = { "Удалить переписку с $it? Все сообщения и медиафайлы будут удалены безвозвратно." }
    override val chatsAddContact = "Добавить контакт"
    override val chatsInviteCode = "Invite-код"
    override val chatsContactAdded: (String) -> String = { "Контакт добавлен: $it" }
    override val chatsCreateTitle = "Создать"
    override val chatsCreateContact = "👤 Добавить контакт"
    override val chatsCreateGroup = "👥 Создать группу"
    override val chatsSubscribeChannel = "📢 Подписаться на канал"
    override val chatsCreateChannel = "📡 Создать канал"
    override val chatsChannelSubscribeTitle = "Подписаться на канал"
    override val chatsChannelLinkLabel = "Ссылка beacon://channel?..."
    override val chatsChannelCreateTitle = "Создать канал"
    override val chatsChannelNameLabel = "Название канала"
    override val chatsChannelDescLabel = "Описание (необязательно)"
    override val chatsChannelFillFields = "Укажите название канала"
    override val chatsChannelBadLink = "Неверная ссылка"
    override val chatsChannelBadge = "канал"
    override val chatsSupportWrite = "Написать"
}

private val ru3 = object : IStr3 {
    override val profileTitle = "Профиль"
    override val profileFingerprint = "Ваш отпечаток"
    override val profileFingerprintHint = "Попросите собеседника сравнить эти эмодзи со своим экраном"
    override val profileInviteCode = "Ваш Invite-код"
    override val profileShareCode = "Поделиться кодом"
    override val profileHideQr = "Скрыть QR"
    override val profileShowQr = "📷 Показать QR-код"
    override val profileScanQr = "🔍 Сканировать QR"
    override val profileQrHint = "Пусть собеседник отсканирует этот код"
    override val profileCodeCopied = "✓ код скопирован"
    override val profileSendHint = "Отправьте этот код другу, чтобы он мог добавить вас в контакты"
    override val profileServers = "🌐 Серверы"
    override val profileSupport = "❓ Поддержка"
    override val profileBackup = "📦 Резервное копирование"
    override val profileSectionSecurity = "Безопасность"
    override val profileSectionGeneral  = "Основное"
    override val profileHideNotif = "🔔 Скрывать текст в уведомлениях"
    override val profileHideNotifSub = "Показывать только «Новое сообщение»"
    override val profileAutoLock = "🔒 Автоблокировка"
    override val profileAutoLockAfter: (String) -> String = { "Блокировать через: $it" }
    override val profileLockOff = "Выкл"
    override val profileLock1min = "1 мин"
    override val profileLock5min = "5 мин"
    override val profileLock15min = "15 мин"
    override val profileLock30min = "30 мин"
    override val profileEmergencyBtn = "🚨 Тревожная кнопка"
    override val profileEmergencyBtnSub = "5 нажатий кнопки убавления громкости"
    override val profileNotMe = "❗ Это не я!"
    override val profileNotMeTitle = "⚠️ Это не я!"
    override val profileNotMeText = "Вы уверены? Это удалит ВСЕ данные, чаты, ключи и сбросит приложение!"
    override val profileNotMeConfirm = "Да, сбросить всё"
    override val profileDiagnostics = "🔐 Диагностика безопасности"
    override val profilePanicTitle = "🔑 Panic Password"
    override val profilePanicSub = "Пароль для экстренного удаления всех данных"
    override val profilePanicSetStatus = "✅ Установлен"
    override val profilePanicEnterLabel = "Введите пароль для экстренного удаления:"
    override val profilePanicInstruction = "⚠️ Сценарий использования:\n① В экстренной ситуации введите этот пароль один раз — все данные сотрутся.\n② После перезапуска войдите своим обычным паролем."
    override val profilePanicFieldLabel = "Panic пароль"
    override val profileLanguageToggle = "🌐 English"
    override val profileThemeLabel = "🎨 Тема"
    override val profileThemeNavy = "Синяя"
    override val profileThemeDark = "Тёмная"
    override val profileThemeLight = "Светлая"
    override val profileInvalidCodeFormat = "Неверный формат кода"
    override val profileInvalidOrExpiredCode = "Недействительный или устаревший код"
    override val profileCameraPermReq = "Необходимо разрешение камеры"
    override val profileQrScanPrompt = "Наведите камеру на QR-код"
    override val backupTitle = "Резервное копирование"
    override val backupSubtitle = "Создайте резервную копию серверов, контактов и истории сообщений"
    override val backupSecurityTitle = "⚠️ Безопасность бэкапа"
    override val backupSecurityText = "Бэкап содержит все ключи и переписку. Защищён паролем — если файл и пароль окажутся вместе у злоумышленника, аккаунт будет скомпрометирован."
    override val backupSecurityTips = "• Используйте надёжный пароль (12+ символов)\n• Не храните файл и пароль в одном месте\n• Храните на зашифрованном диске или в password manager"
    override val backupPassword = "Пароль"
    override val backupRepeatPassword = "Повторите пароль"
    override val backupExport = "📦 Экспорт резервной копии"
    override val backupImport = "📥 Импорт резервной копии"
    override val backupSaveChooser = "Сохранить резервную копию"
    override val backupCreated = "✓ Резервная копия создана"
    override val backupErrEnterPassword = "Введите пароль"
    override val backupErrPasswordMatch = "Пароли не совпадают"
    override val backupErrPasswordLength = "Пароль должен быть минимум 8 символов"
    override val backupErrEnterForDecrypt = "Введите пароль для расшифровки"
}

private val ru4 = object : IStr4 {
    override val serversTitle = "Серверы"
    override val serversAdd = "Добавить"
    override val serversSwitch = "🔄 Переключить сервер"
    override val serversSwitching = "Переподключение к следующему серверу..."
    override val serversDefault: (Int) -> String = { "Сервер $it" }
    override val serversConnected = "Подключено"
    override val serversConnecting = "Подключение..."
    override val serversAddTitle = "Добавить сервер"
    override val serversName = "Название"
    override val serversHost = "Хост (IP или домен)"
    override val serversPort = "Порт"
    override val groupInfoTitle = "Информация о группе"
    override val groupInfoNotFound = "Группа не найдена"
    override val groupInfoMembersCount: (Int) -> String = { "$it участников" }
    override val groupInfoDescription = "Описание"
    override val groupInfoAddDescription = "Нажмите ✏️ чтобы добавить описание"
    override val groupInfoNoDescription = "Нет описания"
    override val groupInfoMembersSection = "Участники"
    override val groupInfoCreator = "👑 Создатель"
    override val groupInfoAdmin = "⭐ Администратор"
    override val groupInfoPromoteAdmin = "Сделать админом"
    override val groupInfoRemoveMember = "Удалить из группы"
    override val groupInfoLeave = "Покинуть группу"
    override val groupInfoDeleteGroup = "Удалить группу"
    override val groupInfoAddMemberTitle = "Добавить участника"
    override val groupInfoAddMemberHint = "Попросите участника поделиться своим invite-кодом из профиля"
    override val groupInfoAddMemberLabel = "Invite-код"
    override val groupInfoAlreadyMember = "Этот участник уже в группе"
    override val groupInfoBadInvite = "Неверный формат invite-кода"
    override val groupInfoLeaveTitle = "Покинуть группу?"
    override val groupInfoLeaveText: (String) -> String = { "Вы уверены, что хотите покинуть группу \"$it\"?" }
    override val groupInfoLeaveConfirm = "Выйти"
    override val groupInfoDeleteTitle = "Удалить группу?"
    override val groupInfoDeleteText: (String) -> String = { "Вы уверены, что хотите удалить группу \"$it\"? Это действие необратимо!" }
    override val groupInfoEmojiTitle = "Выбрать аватар"
    override val groupInfoDescTitle = "Описание группы"
    override val groupInfoDescLabel = "Описание (до 300 символов)"
    override val groupInfoChangeAvatar = "✏️ сменить"
    override val createGroupTitle = "Создать группу"
    override val createGroupTapAvatar = "Нажми для выбора аватара"
    override val createGroupNameLabel = "Название группы"
    override val createGroupMembersTitle: (Int) -> String = { "Участники ($it)" }
    override val createGroupButton = "Создать группу"
    override val createGroupAvatarTitle = "Выбери аватар группы"
}

private val ru5 = object : IStr5 {
    override val channelDefault = "Канал"
    override val channelCopyLink = "🔗 Ссылка"
    override val channelUnsubscribe = "Отписаться"
    override val channelPostPlaceholder = "Написать в канал..."
    override val channelLinkCopied = "Ссылка скопирована"
    override val channelLoadImageError = "Не удалось загрузить изображение"
    override val channelWriteFirst = "Напишите первую запись ниже"
    override val channelSubscribeConfirm = "Подписаться на этот канал?"
    override val channelSubscribeBtn = "Подписаться"
    override val channelMute = "🔕 Выключить уведомления"
    override val channelUnmute = "🔔 Включить уведомления"
    override val channelSubscribers: (Int) -> String = { "$it подписчиков" }
    override val channelSearchPlaceholder = "Поиск по постам..."
    override val channelPinPost = "📌 Закрепить"
    override val channelUnpinPost = "📌 Открепить"
    override val channelPinned = "Закреплено"
    override val channelDeletePost = "🗑 Удалить пост"
    override val channelForwardPost = "↗ Переслать"
    override val channelForwardTitle = "Переслать в чат..."
    override val channelForwardSent = "Переслано"
    override val channelDeleteChannelTitle = "Удалить канал?"
    override val channelDeleteChannelText = "Все посты будут удалены, все подписчики отключены. Действие необратимо."
    override val channelEditTitle = "Настройки канала"
    override val channelSaved = "Сохранено"
    override val incomingGroupCall = "Групповой звонок"
    override val incomingVideoCall = "Входящий видеозвонок"
    override val incomingAudioCall = "Входящий аудиозвонок"
    override val incomingGroupCallHint = "Ответить и присоединиться к группе"
    override val incomingCallHint = "Ответить?"
    override val incomingDecline = "Отклонить"
    override val incomingAccept = "Принять"
    override val incomingNoCameraPermission = "Разрешение камеры не дано — только аудио"
    override val activeGroupCallLabel = "Групповой звонок"
    override val activeGroupLabel = "Группа"
    override val activeWaitingPeers = "Ожидание участников..."
    override val activeConnecting = "Соединение..."
    override val activeMute = "Без\nзвука"
    override val activeUnmute = "Включить\nмик"
    override val activeCamOff = "Выкл.\nкамеру"
    override val activeCamOn = "Включить\nкамеру"
    override val activeSpeaker = "Динамик"
    override val activeEarpiece = "Наушники"
    override val activeHangUp = "Завер-\nшить"
    override val diagTitle = "🔐 Диагностика безопасности"
    override val diagInitText = "Нажмите кнопку для запуска диагностики..."
    override val diagRunning = "⏳ Выполняется..."
    override val diagBasic = "▶️ Базовая диагностика"
    override val diagStress = "💣 Стресс-тесты (должны провалиться)"
    override val diagAdvanced = "🔬 Расширенные тесты (сессии + группы)"
}

private val ru6 = object : IStr6 {
    override val chatSearchPlaceholder = "Поиск в чате..."
    override val chatOnline = "онлайн"
    override val chatOffline = "не в сети"
    override val chatKeyWarningTitle = "⚠️ ВНИМАНИЕ!"
    override val chatKeyWarningText = "Ключ шифрования собеседника изменился!\n\nЭто может означать:\n• Переустановку приложения\n• Новое устройство\n• MITM атаку\n\nСвяжитесь с собеседником другим способом!"
    override val chatKeyWarningConfirm = "Я проверил(а), всё ОК"
    override val chatKeyWarningLeave = "Выйти из чата"
    override val chatTyping = "печатает..."
    override val chatMenu = "Меню"
    override val chatAudioCall = "📞  Аудиозвонок"
    override val chatVideoCall = "🎥  Видеозвонок"
    override val chatVerifyAction = "🔐  Верификация"
    override val chatDirectConnection = "Прямое подключение — без Tor. Установите Orbot для анонимности."
    override val chatContextReply = "↩️  Ответить"
    override val chatContextCopy = "📋  Копировать"
    override val chatContextReaction = "😊  Реакция"
    override val chatContextEdit = "✏️  Редактировать"
    override val chatContextDeleteOwn = "🗑  Удалить у себя"
    override val chatContextDeleteAll = "🗑  Удалить у всех"
    override val chatPickReaction = "Выбери реакцию"
    override val chatDisappearTitle = "⏱ Исчезающие сообщения"
    override val chatDisappearOff = "Выкл"
    override val chatDisappear1h = "1 час"
    override val chatDisappear24h = "24 часа"
    override val chatDisappear7d = "7 дней"
    override val chatDisappear1hShort = " · ⏱1ч"
    override val chatDisappear24hShort = " · ⏱1д"
    override val chatDisappear7dShort = " · ⏱7д"
    override val chatReplyPreview = "Ответ на сообщение"
    override val chatEditing = "✏️ Редактирование"
    override val chatAttach = "Прикрепить"
    override val chatAttachPhoto = "📷 Фото"
    override val chatAttachMedia = "📸 Медиа"
    override val chatAttachFile = "📄 Файл"
    override val chatGeo = "📍 Геопозиция"
    override val chatGeoPermission = "Разрешите доступ к геопозиции"
    override val chatGeoFail = "Не удалось определить позицию"
    override val chatGeoTap = "📍 Геопозиция (нажми для просмотра)"
    override val chatGeoDisabled = "Включи геолокацию в настройках телефона"
    override val chatEditHint = "Изменить..."
    override val chatInputHint = "Сообщение..."
    override val chatPhotoTooBig = "Фото слишком большое для обработки"
    override val chatFileTooBig = "Файл слишком большой (макс 20 МБ)"
    override val chatMediaOffline = "Нет соединения — медиафайл не отправлен"
    override val chatFileSending: (String, Int) -> String = { name, kb -> "Отправка: $name (${kb}KB)" }
    override val chatVerifyTitle = "🔐 Верификация контакта"
    override val chatVerifyFingerprintLabel = "Fingerprint контакта:"
    override val chatVerifyHint = "Попросите собеседника назвать эмодзи из своего профиля."
    override val chatVerifyKeyError = "Ошибка чтения ключа"
    override val chatVerifyUnknown = "Неизвестно"
    override val chatReplyLabel = "↩️ Ответить"
    override val chatPhotoDesc = "Фото"
    override val chatFileNotFound = "Файл не найден"
    override val chatFileDecryptError = "Ошибка расшифровки файла"
    override val chatFileOpenError: (String) -> String = { "Не удалось открыть файл: $it" }
    override val chatEdited = "(изменено)"
    override val verifyScreenTitle = "Верификация ключа"
    override val verifyCheckKey = "Проверьте ключ безопасности"
    override val verifyContact: (String) -> String = { "Собеседник: $it" }
    override val verifyKeyNotFound = "Ключ собеседника не найден"
    override val verifyEmojiLabel = "Отпечаток эмодзи"
    override val verifyEmojiHint: (String) -> String = { "Попросите $it назвать эмодзи из своего профиля.\nЕсли совпадают — соединение безопасно." }
    override val verifyHexLabel = "Отпечаток ключа (hex):"
    override val verifyHint = "Для максимальной безопасности сравните отпечаток при личной встрече или по голосовому звонку."
    override val verifyMarkVerified = "✅ Пометить как проверенный"
    override val verifyAlreadyVerified = "✅ Ключ проверен"
    override val chatLoadEarlier = "↑ Загрузить ранее"
    override val chatSavePhoto = "💾  Сохранить фото"
    override val chatPhotoSaved = "Фото сохранено в галерею"
}

private val ru7 = object : IStr7 {
    override val torConnecting = "Подключение через Tor..."
    override val torIpHidden = "Ваш IP скрыт"
    override val torConnected = "Подключено"
    override val torStartingOrbot = "Запуск Orbot..."
    override val torConnectingNetwork = "Подключение к сети Tor..."
    override val torAlmostReady = "Почти готово..."
    override val serviceConnecting = "Подключение..."
    override val serviceConnected: (String) -> String = { "Подключено: $it" }
    override val rootDangerTitle = "🚨 Root обнаружен"
    override val rootDangerText = "На устройстве обнаружен root-доступ. Шифрование B-CON может быть скомпрометировано — ключи и сообщения доступны другим приложениям."
    override val rootDangerReasons: (String) -> String = { "Признаки:\n$it" }
    override val rootDangerRecommend = "Рекомендуется использовать устройство без root."
    override val rootDangerContinue = "Всё равно продолжить"
    override val rootWarningTitle = "⚠️ Подозрительное устройство"
    override val rootWarningText = "Обнаружен подозрительный признак. Возможно, устройство модифицировано."
    override val rootWarningConfirm = "Понятно"
    override val lockTitle = "Приложение заблокировано"
    override val lockUnlock = "🔓  Разблокировать"
    override val lockBiometricTitle = "Разблокировать B-CON"
    override val lockBiometricSubtitle = "Подтвердите личность"
    override val lockBiometricCancel = "Отмена"
    override val noCameraPermissionVoiceOnly = "Разрешение камеры не дано — голосовой звонок"
    override val torStatusStarting = "Запуск..."
    override val emergencyInfoTitle = "🚨 Экстренное удаление"
    override val emergencyInfoMessage = "Нажмите 5 раз УБАВИТЬ ГРОМКОСТЬ за 3 секунды — " +
        "приложение немедленно удалит все ключи и переписки.\n\n" +
        "⚠️ БЕЗ ПОДТВЕРЖДЕНИЯ!\n\n" +
        "📲 Android 13+: требуется 2 шага:\n" +
        "① Нажмите «Настройки приложения»\n" +
        "② В правом верхнем углу ⋮ → «Доступ к огр. настройкам»\n" +
        "③ Затем вернитесь: Настройки → Спец. возможности → B-CON Emergency → Вкл\n\n" +
        "📱 Android 12 и старше:\n" +
        "Настройки → Спец. возможности → B-CON Emergency → Вкл"
    override val emergencyInfoOpenSettings = "Спец. возможности"
    override val emergencyInfoOpenAppSettings = "Настройки приложения"
    override val spyAppsAccessibilitySection = "🔍 Службы Accessibility:\n"
    override val spyAppsAdminsSection = "⚠️ Администраторы устройства:\n"
    override val spyAppsOverlaySection = "🪟 Право рисовать поверх экрана:\n"
    override val spyAppsTitle = "⚠️ Подозрительные приложения"
    override val spyAppsMessage: (String) -> String = { "Обнаружены приложения, которые могут перехватывать экран или касания:\n\n$it\n\nРекомендуем отозвать их права или удалить.\nКасания поверх B-CON заблокированы автоматически." }
    override val spyAppsSettings = "Accessibility настройки"
    override val groupCallPeerName = "Группа"
    override val systemSender = "Система"
    override val groupMemberLeft: (String) -> String = { "$it покинул(а) группу" }
    override val groupKeyUpdated = "🔐 Ключ шифрования обновлён"
    override val groupMemberJoined: (String) -> String = { "$it присоединился(лась) к группе" }
    override val channelCreatedToast: (String) -> String = { "Канал «$it» создан!" }
    override val channelFallbackName = "Канал"
    override val channelNoConnection = "Нет соединения с сервером"
    override val recipientOffline = "Получатель не в сети"
    override val notifChannelDesc = "Экстренное удаление данных"
    override val notifSessionTitle = "⚠️ Сессия завершена"
    override val notifSessionText = "Ваш аккаунт был открыт на другом устройстве"
    override val notifNewMessage = "💬 Новое сообщение"
    override val notifTapToRead = "Нажмите, чтобы прочитать"
    override val notifMessageCount: (Int) -> String = { "$it сообщений" }
    override val notifGroupFallback = "Группа"
    override val notifNewGroupMessage = "👥 Новое сообщение в группе"
    override val notifMissedVideoCall = "Пропущенный видеозвонок"
    override val notifMissedCall = "Пропущенный звонок"
    override val notifFromCaller: (String) -> String = { "От: $it" }
    override val notifEmergencyText = "Нажмите для экстренного удаления"
    override val notifEmergencyAction = "🚨 УДАЛИТЬ ВСЁ"
    override val tamperTitle = "⛔ Приложение повреждено"
    override val tamperText = "Подпись APK не совпадает с оригиналом. Возможно, приложение было перепаковано или модифицировано злоумышленником. Использование небезопасно — ключи шифрования могут быть скомпрометированы."
    override val tamperClose = "Закрыть"
    override val paranoidModeTitle = "🔴 Режим паранойи"
    override val paranoidModeSub = "Root/Frida → немедленный выход, блокировка внешних интентов, очистка логов"
    override val paranoidModeConfirmTitle = "Включить режим паранойи?"
    override val paranoidModeConfirmText = "После включения переключатель исчезнет — режим нельзя отключить без полного сброса данных приложения.\n\nПри обнаружении Root, Frida или эмулятора приложение немедленно закроется без предупреждения.\n\nВключить только если уверен."
    override val paranoidModeConfirmBtn = "Включить"
    override val paranoidModeActive = "🔒 Активен"
    override val idsTitle = "IDS — Детектор вторжений"
    override val idsScanBtn = "Сканировать"
    override val idsClean = "✓ Угроз не обнаружено"
    override val idsThreatFound = "⚠ Обнаружены угрозы"
    override val idsHoneyTampered = "⚠ Файл-приманка изменён"
    override val alertUrlLabel = "Alert URL (необязательно)"
    override val alertUrlHint = "https://your-server/alert"
    override val alertUrlSave = "Сохранить"
}

private val ru8 = object : IStr8 {
    override val groupChatNoMessages = "Нет сообщений"
    override val groupChatMessageHint = "Сообщение..."
    override val groupChatEditHint = "Изменить..."
    override val groupChatInfo = "Инфо"
    override val groupChatReply = "↩️  Ответить"
    override val groupChatCopy = "📋  Копировать"
    override val groupChatReactionLabel = "😊  Реакция"
    override val groupChatEditAction = "✏️  Редактировать"
    override val groupChatDeleteOwn = "🗑  Удалить у себя"
    override val groupChatDeleteAll = "🗑  Удалить у всех"
    override val groupChatPickReaction = "Выбери реакцию"
    override val groupChatEditing = "✏️ Редактирование"
    override val groupChatAttach = "Прикрепить"
    override val groupChatAttachPhoto = "📷 Фото (скоро)"
    override val groupChatAttachFile = "📄 Файл (скоро)"
    override val groupChatGeo = "📍 Геопозиция"
    override val groupChatGeoPermission = "Разрешите доступ к геопозиции"
    override val groupChatGeoFail = "Не удалось определить позицию"
}

private val ru9 = object : IStr9 {
    override val wipeSettingsTitle = "⚠️ Уничтожение данных"
    override val dmsTitle = "Dead Man's Switch"
    override val dmsSubtitle = "Уничтожить данные если не подтверждена безопасность в срок"
    override val dmsCheckinBtn = "✅ Я в безопасности"
    override val dmsNotifTitle = "⚠️ Dead Man's Switch"
    override val dmsNotifText = "Нажмите «Я в безопасности» или данные будут уничтожены"
    override val dmsNotifGraceText = "Нажмите «Я в безопасности» или данные будут уничтожены через 15 минут"
    override val dmsIntervalLabel = "Интервал проверки"
    override val dmsIntervalHours = "ч"
    override val dmsEnabledLabel = "Включить Dead Man's Switch"
    override val timeoutWipeTitle = "Таймаут пароля"
    override val timeoutWipeSubtitle = "Уничтожить данные если нет входа в приложение дольше заданного времени"
    override val wipeOnBreachTitle = "Wipe при взломе"
    override val wipeOnBreachSubtitle = "Уничтожить данные при обнаружении критической угрозы IDS"
    override val wipeLevelLabel = "Уровень уничтожения"
    override val wipeLevelSoft = "Мягкий (SOFT)"
    override val wipeLevelHard = "Жёсткий (HARD)"
    override val wipeLevelNuclear = "Ядерный (NUCLEAR)"
    override val wipeSoftDesc = "Очищает кеш и оперативную память"
    override val wipeHardDesc = "Удаляет все ключи, файлы и данные приложения"
    override val wipeNuclearDesc = "HARD + полный сброс приложения (системный уровень)"
    override val wipeSettingsWarning = "⚠️ Эти настройки необратимы. После срабатывания все данные будут уничтожены без возможности восстановления."
    override val panicButtonLabel = "Кнопка паники на экране блокировки"
    override val panicButtonSubtitle = "Показывает уведомление с кнопкой вайпа, доступной без разблокировки"
    override val panicButtonDecoyLabel = "Режим Decoy после вайпа"
    override val panicButtonDecoySubtitle = "После нажатия кнопки — показать фейковый экран чатов вместо немедленного закрытия"
    override val panicNotifTitle = "🔴 Beacon — Экстренный вайп"
    override val panicNotifText = "Нажмите «УНИЧТОЖИТЬ» для немедленного стирания всех данных"
    override val panicNotifButton = "УНИЧТОЖИТЬ"
    override val calcDisguiseLabel = "Маскировка под калькулятор"
    override val calcDisguiseSubtitle = "Иконка и название заменяются на «Калькулятор». Для входа в мессенджер введите 4 + 20 ="
}

val ruStrings = AppStrings("ru", ru1, ru2, ru3, ru4, ru5, ru6, ru7, ru8, ru9)

// ─── English ──────────────────────────────────────────────────────────────────

private val en1 = object : IStr1 {
    override val cancel = "Cancel"
    override val back = "Back"
    override val save = "Save"
    override val add = "Add"
    override val delete = "Delete"
    override val create = "Create"
    override val next = "Next"
    override val write = "Write"
    override val close = "Close"
    override val change = "Change"
    override val setAction = "Set"
    override val yes = "Yes"
    override val ok = "OK"
    override val error: (String) -> String = { "Error: $it" }
    override val loginGreeting: (String) -> String = { "Hello, $it" }
    override val loginPassword = "Password"
    override val loginTooManyAttempts: (Long, Long) -> String = { m, sec -> "Too many attempts. Try again in ${m}m ${sec}s" }
    override val loginEnterPassword = "Enter password"
    override val loginWrongPassword = "Wrong password"
    override val loginButton = "Log In"
    override val loginBiometric = "🔐 Biometrics"
    override val loginWaitingBiometric = "Waiting for biometrics..."
    override val loginNotMe = "Not me — reset"
    override val loginNotMeTitle = "⚠️ Reset everything?"
    override val loginNotMeText = "This will permanently delete ALL data!"
    override val loginNotMeConfirm = "Yes, delete all"
}

private val en2 = object : IStr2 {
    override val registerTitle = "Create account"
    override val registerSubtitle = "All data is stored only on your device"
    override val registerUsername = "Username"
    override val registerUsernamePlaceholder = "e.g.: alice"
    override val registerPassword = "Password"
    override val registerRepeatPassword = "Repeat password"
    override val registerGeneratingKeys = "Generating encryption keys..."
    override val registerErrorEnterUsername = "Enter username"
    override val registerErrorPasswordLength = "Password must be at least 6 characters"
    override val registerErrorPasswordMatch = "Passwords don't match"
    override val registerButton = "Create account"
    override val registerImportBackup = "📥 Restore from backup"
    override val registerImportTitle = "Restore from backup"
    override val registerImportHint = "Enter the password used to encrypt the backup, then choose the .backup file"
    override val registerImportPassword = "Backup password"
    override val registerImportChooseFile = "Choose file"
    override val chatsNoMessages = "No messages"
    override val chatsNoPosts = "No posts"
    override val chatsEmpty = "No chats"
    override val chatsEmptyHint = "Tap ➕ to add a contact\nor create a group"
    override val chatsDeleteTitle = "Delete chat?"
    override val chatsDeleteText: (String) -> String = { "Delete conversation with $it? All messages and media will be permanently removed." }
    override val chatsAddContact = "Add contact"
    override val chatsInviteCode = "Invite code"
    override val chatsContactAdded: (String) -> String = { "Contact added: $it" }
    override val chatsCreateTitle = "Create"
    override val chatsCreateContact = "👤 Add contact"
    override val chatsCreateGroup = "👥 Create group"
    override val chatsSubscribeChannel = "📢 Subscribe to channel"
    override val chatsCreateChannel = "📡 Create channel"
    override val chatsChannelSubscribeTitle = "Subscribe to channel"
    override val chatsChannelLinkLabel = "Link beacon://channel?..."
    override val chatsChannelCreateTitle = "Create channel"
    override val chatsChannelNameLabel = "Channel name"
    override val chatsChannelDescLabel = "Description (optional)"
    override val chatsChannelFillFields = "Enter a channel name"
    override val chatsChannelBadLink = "Invalid link"
    override val chatsChannelBadge = "channel"
    override val chatsSupportWrite = "Write"
}

private val en3 = object : IStr3 {
    override val profileTitle = "Profile"
    override val profileFingerprint = "Your fingerprint"
    override val profileFingerprintHint = "Ask your contact to compare these emojis with their screen"
    override val profileInviteCode = "Your Invite code"
    override val profileShareCode = "Share code"
    override val profileHideQr = "Hide QR"
    override val profileShowQr = "📷 Show QR code"
    override val profileScanQr = "🔍 Scan QR"
    override val profileQrHint = "Let your contact scan this code"
    override val profileCodeCopied = "✓ code copied"
    override val profileSendHint = "Send this code to a friend so they can add you as a contact"
    override val profileServers = "🌐 Servers"
    override val profileSupport = "❓ Support"
    override val profileBackup = "📦 Backup"
    override val profileSectionSecurity = "Security"
    override val profileSectionGeneral  = "General"
    override val profileHideNotif = "🔔 Hide text in notifications"
    override val profileHideNotifSub = "Show only \"New message\""
    override val profileAutoLock = "🔒 Auto-lock"
    override val profileAutoLockAfter: (String) -> String = { "Lock after: $it" }
    override val profileLockOff = "Off"
    override val profileLock1min = "1 min"
    override val profileLock5min = "5 min"
    override val profileLock15min = "15 min"
    override val profileLock30min = "30 min"
    override val profileEmergencyBtn = "🚨 Emergency button"
    override val profileEmergencyBtnSub = "5 volume-down button presses"
    override val profileNotMe = "❗ Not me!"
    override val profileNotMeTitle = "⚠️ Not me!"
    override val profileNotMeText = "Are you sure? This will delete ALL data, chats, keys and reset the app!"
    override val profileNotMeConfirm = "Yes, reset everything"
    override val profileDiagnostics = "🔐 Security diagnostics"
    override val profilePanicTitle = "🔑 Panic Password"
    override val profilePanicSub = "Password for emergency data deletion"
    override val profilePanicSetStatus = "✅ Set"
    override val profilePanicEnterLabel = "Enter password for emergency deletion:"
    override val profilePanicInstruction = "⚠️ How it works:\n① In an emergency, enter this password once — all data will be wiped.\n② After restart, log in with your regular password — fake chats will appear."
    override val profilePanicFieldLabel = "Panic password"
    override val profileLanguageToggle = "🌐 Русский"
    override val profileThemeLabel = "🎨 Theme"
    override val profileThemeNavy = "Navy"
    override val profileThemeDark = "Dark"
    override val profileThemeLight = "Light"
    override val profileInvalidCodeFormat = "Invalid code format"
    override val profileInvalidOrExpiredCode = "Invalid or expired code"
    override val profileCameraPermReq = "Camera permission required"
    override val profileQrScanPrompt = "Point the camera at the QR code"
    override val backupTitle = "Backup"
    override val backupSubtitle = "Create a backup of servers, contacts and message history"
    override val backupSecurityTitle = "⚠️ Backup security"
    override val backupSecurityText = "The backup contains all keys and messages. It is password-protected — if the file and password end up together with an attacker, your account will be compromised."
    override val backupSecurityTips = "• Use a strong password (12+ characters)\n• Don't store the file and password in the same place\n• Store on an encrypted drive or in a password manager"
    override val backupPassword = "Password"
    override val backupRepeatPassword = "Repeat password"
    override val backupExport = "📦 Export backup"
    override val backupImport = "📥 Import backup"
    override val backupSaveChooser = "Save backup"
    override val backupCreated = "✓ Backup created"
    override val backupErrEnterPassword = "Enter password"
    override val backupErrPasswordMatch = "Passwords don't match"
    override val backupErrPasswordLength = "Password must be at least 8 characters"
    override val backupErrEnterForDecrypt = "Enter password for decryption"
}

private val en4 = object : IStr4 {
    override val serversTitle = "Servers"
    override val serversAdd = "Add"
    override val serversSwitch = "🔄 Switch server"
    override val serversSwitching = "Reconnecting to next server..."
    override val serversDefault: (Int) -> String = { "Server $it" }
    override val serversConnected = "Connected"
    override val serversConnecting = "Connecting..."
    override val serversAddTitle = "Add server"
    override val serversName = "Name"
    override val serversHost = "Host (IP or domain)"
    override val serversPort = "Port"
    override val groupInfoTitle = "Group info"
    override val groupInfoNotFound = "Group not found"
    override val groupInfoMembersCount: (Int) -> String = { "$it members" }
    override val groupInfoDescription = "Description"
    override val groupInfoAddDescription = "Tap ✏️ to add a description"
    override val groupInfoNoDescription = "No description"
    override val groupInfoMembersSection = "Members"
    override val groupInfoCreator = "👑 Creator"
    override val groupInfoAdmin = "⭐ Admin"
    override val groupInfoPromoteAdmin = "Make admin"
    override val groupInfoRemoveMember = "Remove from group"
    override val groupInfoLeave = "Leave group"
    override val groupInfoDeleteGroup = "Delete group"
    override val groupInfoAddMemberTitle = "Add member"
    override val groupInfoAddMemberHint = "Ask the member to share their invite code from their profile"
    override val groupInfoAddMemberLabel = "Invite code"
    override val groupInfoAlreadyMember = "This member is already in the group"
    override val groupInfoBadInvite = "Invalid invite code format"
    override val groupInfoLeaveTitle = "Leave group?"
    override val groupInfoLeaveText: (String) -> String = { "Are you sure you want to leave the group \"$it\"?" }
    override val groupInfoLeaveConfirm = "Leave"
    override val groupInfoDeleteTitle = "Delete group?"
    override val groupInfoDeleteText: (String) -> String = { "Are you sure you want to delete the group \"$it\"? This action is irreversible!" }
    override val groupInfoEmojiTitle = "Choose avatar"
    override val groupInfoDescTitle = "Group description"
    override val groupInfoDescLabel = "Description (up to 300 characters)"
    override val groupInfoChangeAvatar = "✏️ change"
    override val createGroupTitle = "Create group"
    override val createGroupTapAvatar = "Tap to choose avatar"
    override val createGroupNameLabel = "Group name"
    override val createGroupMembersTitle: (Int) -> String = { "Members ($it)" }
    override val createGroupButton = "Create group"
    override val createGroupAvatarTitle = "Choose group avatar"
}

private val en5 = object : IStr5 {
    override val channelDefault = "Channel"
    override val channelCopyLink = "🔗 Link"
    override val channelUnsubscribe = "Unsubscribe"
    override val channelPostPlaceholder = "Write to channel..."
    override val channelLinkCopied = "Link copied"
    override val channelLoadImageError = "Failed to load image"
    override val channelWriteFirst = "Write the first post below"
    override val channelSubscribeConfirm = "Subscribe to this channel?"
    override val channelSubscribeBtn = "Subscribe"
    override val channelMute = "🔕 Mute notifications"
    override val channelUnmute = "🔔 Unmute notifications"
    override val channelSubscribers: (Int) -> String = { "$it subscribers" }
    override val channelSearchPlaceholder = "Search posts..."
    override val channelPinPost = "📌 Pin"
    override val channelUnpinPost = "📌 Unpin"
    override val channelPinned = "Pinned"
    override val channelDeletePost = "🗑 Delete post"
    override val channelForwardPost = "↗ Forward"
    override val channelForwardTitle = "Forward to chat..."
    override val channelForwardSent = "Forwarded"
    override val channelDeleteChannelTitle = "Delete channel?"
    override val channelDeleteChannelText = "All posts will be deleted and all subscribers removed. This cannot be undone."
    override val channelEditTitle = "Channel settings"
    override val channelSaved = "Saved"
    override val incomingGroupCall = "Group call"
    override val incomingVideoCall = "Incoming video call"
    override val incomingAudioCall = "Incoming audio call"
    override val incomingGroupCallHint = "Answer and join the group"
    override val incomingCallHint = "Answer?"
    override val incomingDecline = "Decline"
    override val incomingAccept = "Accept"
    override val incomingNoCameraPermission = "Camera permission denied — audio only"
    override val activeGroupCallLabel = "Group call"
    override val activeGroupLabel = "Group"
    override val activeWaitingPeers = "Waiting for participants..."
    override val activeConnecting = "Connecting..."
    override val activeMute = "Mute"
    override val activeUnmute = "Unmute"
    override val activeCamOff = "Off\ncam"
    override val activeCamOn = "On\ncam"
    override val activeSpeaker = "Speaker"
    override val activeEarpiece = "Earpiece"
    override val activeHangUp = "End\ncall"
    override val diagTitle = "🔐 Security diagnostics"
    override val diagInitText = "Press the button to run diagnostics..."
    override val diagRunning = "⏳ Running..."
    override val diagBasic = "▶️ Basic diagnostics"
    override val diagStress = "💣 Stress tests (should fail)"
    override val diagAdvanced = "🔬 Advanced tests (sessions + groups)"
}

private val en6 = object : IStr6 {
    override val chatSearchPlaceholder = "Search in chat..."
    override val chatOnline = "online"
    override val chatOffline = "offline"
    override val chatKeyWarningTitle = "⚠️ WARNING!"
    override val chatKeyWarningText = "The contact's encryption key has changed!\n\nThis may indicate:\n• App reinstallation\n• New device\n• MITM attack\n\nContact this person through another channel!"
    override val chatKeyWarningConfirm = "I verified, it's OK"
    override val chatKeyWarningLeave = "Leave chat"
    override val chatTyping = "typing..."
    override val chatMenu = "Menu"
    override val chatAudioCall = "📞  Audio call"
    override val chatVideoCall = "🎥  Video call"
    override val chatVerifyAction = "🔐  Verify"
    override val chatDirectConnection = "Direct connection — no Tor. Install Orbot for anonymity."
    override val chatContextReply = "↩️  Reply"
    override val chatContextCopy = "📋  Copy"
    override val chatContextReaction = "😊  Reaction"
    override val chatContextEdit = "✏️  Edit"
    override val chatContextDeleteOwn = "🗑  Delete for me"
    override val chatContextDeleteAll = "🗑  Delete for everyone"
    override val chatPickReaction = "Pick a reaction"
    override val chatDisappearTitle = "⏱ Disappearing messages"
    override val chatDisappearOff = "Off"
    override val chatDisappear1h = "1 hour"
    override val chatDisappear24h = "24 hours"
    override val chatDisappear7d = "7 days"
    override val chatDisappear1hShort = " · ⏱1h"
    override val chatDisappear24hShort = " · ⏱1d"
    override val chatDisappear7dShort = " · ⏱7d"
    override val chatReplyPreview = "Replying to"
    override val chatEditing = "✏️ Editing"
    override val chatAttach = "Attach"
    override val chatAttachPhoto = "📷 Photo"
    override val chatAttachMedia = "📸 Media"
    override val chatAttachFile = "📄 File"
    override val chatGeo = "📍 Location"
    override val chatGeoPermission = "Grant location access"
    override val chatGeoFail = "Could not determine location"
    override val chatGeoTap = "📍 Location (tap to view)"
    override val chatGeoDisabled = "Enable location in phone settings"
    override val chatEditHint = "Edit message..."
    override val chatInputHint = "Message..."
    override val chatPhotoTooBig = "Photo is too large to process"
    override val chatFileTooBig = "File too large (max 20MB)"
    override val chatMediaOffline = "No connection — media not sent"
    override val chatFileSending: (String, Int) -> String = { name, kb -> "Sending: $name (${kb}KB)" }
    override val chatVerifyTitle = "🔐 Contact verification"
    override val chatVerifyFingerprintLabel = "Contact fingerprint:"
    override val chatVerifyHint = "Ask your contact to read their emoji from their profile."
    override val chatVerifyKeyError = "Key read error"
    override val chatVerifyUnknown = "Unknown"
    override val chatReplyLabel = "↩️ Reply"
    override val chatPhotoDesc = "Photo"
    override val chatFileNotFound = "File not found"
    override val chatFileDecryptError = "File decryption error"
    override val chatFileOpenError: (String) -> String = { "Could not open file: $it" }
    override val chatEdited = "(edited)"
    override val verifyScreenTitle = "Key verification"
    override val verifyCheckKey = "Check security key"
    override val verifyContact: (String) -> String = { "Contact: $it" }
    override val verifyKeyNotFound = "Contact's key not found"
    override val verifyEmojiLabel = "Emoji fingerprint"
    override val verifyEmojiHint: (String) -> String = { "Ask $it to read their emojis from their profile.\nIf they match — the connection is secure." }
    override val verifyHexLabel = "Key fingerprint (hex):"
    override val verifyHint = "For maximum security, compare the fingerprint in person or via a voice call."
    override val verifyMarkVerified = "✅ Mark as verified"
    override val verifyAlreadyVerified = "✅ Key verified"
    override val chatLoadEarlier = "↑ Load earlier"
    override val chatSavePhoto = "💾  Save photo"
    override val chatPhotoSaved = "Photo saved to gallery"
}

private val en7 = object : IStr7 {
    override val torConnecting = "Connecting via Tor..."
    override val torIpHidden = "Your IP is hidden"
    override val torConnected = "Connected"
    override val torStartingOrbot = "Starting Orbot..."
    override val torConnectingNetwork = "Connecting to Tor network..."
    override val torAlmostReady = "Almost ready..."
    override val serviceConnecting = "Connecting..."
    override val serviceConnected: (String) -> String = { "Connected: $it" }
    override val rootDangerTitle = "🚨 Root detected"
    override val rootDangerText = "Root access detected on this device. B-CON's encryption may be compromised — keys and messages may be accessible to other apps."
    override val rootDangerReasons: (String) -> String = { "Indicators:\n$it" }
    override val rootDangerRecommend = "It is recommended to use a device without root."
    override val rootDangerContinue = "Continue anyway"
    override val rootWarningTitle = "⚠️ Suspicious device"
    override val rootWarningText = "A suspicious indicator was detected. The device may be modified."
    override val rootWarningConfirm = "Got it"
    override val lockTitle = "App locked"
    override val lockUnlock = "🔓  Unlock"
    override val lockBiometricTitle = "Unlock B-CON"
    override val lockBiometricSubtitle = "Confirm your identity"
    override val lockBiometricCancel = "Cancel"
    override val noCameraPermissionVoiceOnly = "Camera permission denied — voice call"
    override val torStatusStarting = "Starting..."
    override val emergencyInfoTitle = "🚨 Emergency deletion"
    override val emergencyInfoMessage = "Press VOLUME DOWN 5 times within 3 seconds — " +
        "the app will immediately delete all keys and messages.\n\n" +
        "⚠️ WITHOUT CONFIRMATION!\n\n" +
        "📲 Android 13+: 2 steps required:\n" +
        "① Tap 'App settings'\n" +
        "② Top-right ⋮ → 'Allow restricted settings'\n" +
        "③ Then: Settings → Accessibility → B-CON Emergency → Enable\n\n" +
        "📱 Android 12 and below:\n" +
        "Settings → Accessibility → B-CON Emergency → Enable"
    override val emergencyInfoOpenSettings = "Accessibility"
    override val emergencyInfoOpenAppSettings = "App settings"
    override val spyAppsAccessibilitySection = "🔍 Accessibility services:\n"
    override val spyAppsAdminsSection = "⚠️ Device administrators:\n"
    override val spyAppsOverlaySection = "🪟 Draw over other apps:\n"
    override val spyAppsTitle = "⚠️ Suspicious apps"
    override val spyAppsMessage: (String) -> String = { "Apps found that may intercept screen or touches:\n\n$it\n\nWe recommend revoking their rights or uninstalling them.\nTouches over B-CON are blocked automatically." }
    override val spyAppsSettings = "Accessibility settings"
    override val groupCallPeerName = "Group"
    override val systemSender = "System"
    override val groupMemberLeft: (String) -> String = { "$it left the group" }
    override val groupKeyUpdated = "🔐 Encryption key updated"
    override val groupMemberJoined: (String) -> String = { "$it joined the group" }
    override val channelCreatedToast: (String) -> String = { "Channel «$it» created!" }
    override val channelFallbackName = "Channel"
    override val channelNoConnection = "No server connection"
    override val recipientOffline = "Recipient is offline"
    override val notifChannelDesc = "Emergency data deletion"
    override val notifSessionTitle = "⚠️ Session ended"
    override val notifSessionText = "Your account was opened on another device"
    override val notifNewMessage = "💬 New message"
    override val notifTapToRead = "Tap to read"
    override val notifMessageCount: (Int) -> String = { "$it messages" }
    override val notifGroupFallback = "Group"
    override val notifNewGroupMessage = "👥 New group message"
    override val notifMissedVideoCall = "Missed video call"
    override val notifMissedCall = "Missed call"
    override val notifFromCaller: (String) -> String = { "From: $it" }
    override val notifEmergencyText = "Tap for emergency deletion"
    override val notifEmergencyAction = "🚨 DELETE ALL"
    override val tamperTitle = "⛔ App integrity violated"
    override val tamperText = "The APK signature does not match the original. The app may have been repackaged or modified by a third party. It is not safe to use — encryption keys may be compromised."
    override val tamperClose = "Close"
    override val paranoidModeTitle = "🔴 Paranoia Mode"
    override val paranoidModeSub = "Root/Frida → immediate exit, block external intents, clear logs"
    override val paranoidModeConfirmTitle = "Enable Paranoia Mode?"
    override val paranoidModeConfirmText = "Once enabled, the toggle will disappear — the mode cannot be disabled without a full app data reset.\n\nIf Root, Frida, or an emulator is detected, the app will close immediately without warning.\n\nEnable only if you are sure."
    override val paranoidModeConfirmBtn = "Enable"
    override val paranoidModeActive = "🔒 Active"
    override val idsTitle = "IDS — Intrusion Detector"
    override val idsScanBtn = "Scan"
    override val idsClean = "✓ No threats detected"
    override val idsThreatFound = "⚠ Threats detected"
    override val idsHoneyTampered = "⚠ Honey file tampered"
    override val alertUrlLabel = "Alert URL (optional)"
    override val alertUrlHint = "https://your-server/alert"
    override val alertUrlSave = "Save"
}

private val en8 = object : IStr8 {
    override val groupChatNoMessages = "No messages"
    override val groupChatMessageHint = "Message..."
    override val groupChatEditHint = "Edit message..."
    override val groupChatInfo = "Info"
    override val groupChatReply = "↩️  Reply"
    override val groupChatCopy = "📋  Copy"
    override val groupChatReactionLabel = "😊  Reaction"
    override val groupChatEditAction = "✏️  Edit"
    override val groupChatDeleteOwn = "🗑  Delete for me"
    override val groupChatDeleteAll = "🗑  Delete for everyone"
    override val groupChatPickReaction = "Pick a reaction"
    override val groupChatEditing = "✏️ Editing"
    override val groupChatAttach = "Attach"
    override val groupChatAttachPhoto = "📷 Photo (coming soon)"
    override val groupChatAttachFile = "📄 File (coming soon)"
    override val groupChatGeo = "📍 Location"
    override val groupChatGeoPermission = "Grant location access"
    override val groupChatGeoFail = "Could not determine location"
}

private val en9 = object : IStr9 {
    override val wipeSettingsTitle = "⚠️ Data Destruction"
    override val dmsTitle = "Dead Man's Switch"
    override val dmsSubtitle = "Destroy data if safety check-in is missed"
    override val dmsCheckinBtn = "✅ I'm safe"
    override val dmsNotifTitle = "⚠️ Dead Man's Switch"
    override val dmsNotifText = "Tap \"I'm safe\" or data will be destroyed"
    override val dmsNotifGraceText = "Tap \"I'm safe\" or data will be destroyed in 15 minutes"
    override val dmsIntervalLabel = "Check-in interval"
    override val dmsIntervalHours = "h"
    override val dmsEnabledLabel = "Enable Dead Man's Switch"
    override val timeoutWipeTitle = "Password timeout"
    override val timeoutWipeSubtitle = "Destroy data if the app has not been unlocked for the specified time"
    override val wipeOnBreachTitle = "Wipe on breach"
    override val wipeOnBreachSubtitle = "Destroy data when a critical IDS threat is detected"
    override val wipeLevelLabel = "Destruction level"
    override val wipeLevelSoft = "Soft (SOFT)"
    override val wipeLevelHard = "Hard (HARD)"
    override val wipeLevelNuclear = "Nuclear (NUCLEAR)"
    override val wipeSoftDesc = "Clears cache and in-memory sessions"
    override val wipeHardDesc = "Deletes all keys, files and app data"
    override val wipeNuclearDesc = "HARD + full app reset (system-level)"
    override val wipeSettingsWarning = "⚠️ These settings are irreversible. Once triggered, all data will be permanently destroyed with no recovery possible."
    override val panicButtonLabel = "Panic button on lock screen"
    override val panicButtonSubtitle = "Shows a notification with a wipe button accessible without unlocking"
    override val panicButtonDecoyLabel = "Decoy mode after wipe"
    override val panicButtonDecoySubtitle = "After tapping — show fake chat screen instead of closing immediately"
    override val panicNotifTitle = "🔴 Beacon — Emergency Wipe"
    override val panicNotifText = "Tap DESTROY to immediately erase all data"
    override val panicNotifButton = "DESTROY"
    override val calcDisguiseLabel = "Calculator disguise"
    override val calcDisguiseSubtitle = "Replaces the icon and name with «Calculator». Enter 4 + 20 = to access the messenger"
}

val enStrings = AppStrings("en", en1, en2, en3, en4, en5, en6, en7, en8, en9)

// ─── CompositionLocal ─────────────────────────────────────────────────────────
val LocalStrings = compositionLocalOf<AppStrings> { ruStrings }
