package com.subrosa.messenger

import androidx.compose.runtime.compositionLocalOf

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

interface IStr2 {
    val registerTitle: String; val registerSubtitle: String
    val registerUsername: String; val registerUsernamePlaceholder: String
    val registerPassword: String; val registerRepeatPassword: String
    val registerGeneratingKeys: String
    val registerErrorEnterUsername: String; val registerErrorPasswordLength: String
    val registerErrorPasswordCommon: String
    val registerErrorPasswordMatch: String; val registerButton: String
    val registerImportBackup: String; val registerImportTitle: String
    val registerImportHint: String; val registerImportPassword: String
    val registerImportChooseFile: String
    val registerImportTotpHint: String
    val chatsNoMessages: String; val chatsNoPosts: String
    val chatsEmpty: String; val chatsEmptyHint: String
    val chatsSearchPlaceholder: String; val chatsSearchNoResults: String
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
    val chatsActionsTitle: String; val chatsActionMute: String
    val chatsActionInfo: String; val chatsActionDelete: String
    val muteDialogTitle: String; val muteOff: String
    val mute1h: String; val mute2h: String
    val mute5h: String; val mute8h: String; val muteForever: String
    val muteStatusOff: String; val muteStatusForever: String
    val muteStatusUntil: (String) -> String
    val contactInfoNotifications: String
    val muteSoundOnly: String
    val contactInfoSearch: String
}

interface IStr3 {
    val profileTitle: String; val profileFingerprint: String
    val profileFingerprintHint: String; val profileInviteCode: String
    val profileShareCode: String; val profileHideQr: String
    val profileShowQr: String; val profileScanQr: String
    val profileQrHint: String; val profileCodeCopied: String
    val profileSendHint: String; val profileServers: String
    val profileBackup: String
    val profileSectionSecurity: String; val profileSectionGeneral: String
    val profileSecurityGuide: String; val profileSecurityGuideSub: String
    // Trailing button label for Security-settings rows that open their own
    // full screen, replacing a bare arrow icon.
    val profileConfigureBtn: String
    val profileInviteCodeOneTimeWarning: String
    val profileHideNotif: String; val profileHideNotifSub: String
    val profileHideIpCalls: String; val profileHideIpCallsSub: String
    val profileHideIpCallsFailedNoTurn: String
    val profileAutoLock: String; val profileAutoLockAfter: (String) -> String
    val profileBiometricTitle: String; val profileBiometricSub: String
    val profileBiometricWarningTitle: String; val profileBiometricWarningText: String
    val profileBiometricWarningConfirm: String
    val profileChangePassword: String
    val changePasswordTitle: String; val changePasswordDesc: String
    val changePasswordCurrent: String; val changePasswordNew: String; val changePasswordRepeat: String
    val changePasswordSubmit: String; val changePasswordSuccess: String
    val changePasswordErrCurrentWrong: String; val changePasswordErrSameAsOld: String
    val profileLockOff: String; val profileLock1min: String
    val profileLock5min: String; val profileLock15min: String
    val profileLock30min: String; val profileEmergencyBtn: String
    val profileEmergencyBtnSub: String; val profileNotMe: String
    val profileNotMeTitle: String; val profileNotMeText: String
    val profileNotMeConfirm: String; val profileDiagnostics: String
    val profileSourceCode: String
    val profileTorEnabled: String; val profileTorEnabledSub: String
    val profileBatteryUnrestricted: String; val profileBatteryUnrestrictedSub: String
    val batteryPromptTitle: String; val batteryPromptText: String
    val batteryPromptAllow: String; val batteryPromptSkip: String
    val profileServiceNotifVisible: String; val profileServiceNotifVisibleSub: String
    val profileCompromised: String
    val profileCompromisedTitle: String; val profileCompromisedText: String
    val profileCompromisedConfirm: String
    val identityRevokedError: String
    val profilePanicTitle: String; val profilePanicSub: String
    val profilePanicSetStatus: String; val profilePanicEnterLabel: String
    val profilePanicInstruction: String
    val profilePanicFieldLabel: String; val profileLanguageToggle: String
    // Panic password must never collide with the login password: whichever is
    // checked first wins, and the panic check runs first, so an identical pair
    // turns every normal login into an irreversible duress wipe.
    val profilePanicErrSameAsLogin: String; val changePasswordErrSameAsPanic: String
    val profileThemeLabel: String; val profileThemeNavy: String
    val profileThemeDark: String; val profileThemeLight: String
    val profileInvalidCodeFormat: String; val profileInvalidOrExpiredCode: String
    val profileCameraPermReq: String; val profileQrScanPrompt: String
    val backupTitle: String; val backupSubtitle: String
    val backupSecurityTitle: String; val backupSecurityText: String
    val backupSecurityTips: String; val backupPassword: String
    val backupRepeatPassword: String; val backupExport: String
    val backupImport: String; val backupSaveChooser: String
    val backupImportWipeTitle: String; val backupImportWipeText: String
    val backupCreated: String; val backupErrEnterPassword: String
    val backupErrPasswordMatch: String; val backupErrPasswordLength: String
    val backupErrTotpRequired: String
    val backupErrEnterForDecrypt: String
    // Read-only offline archive viewer (BackupArchive/ArchiveScreen) — lets a
    // backup be read without importing it, so history stays reachable after
    // the server is gone.
    val archiveTitle: String; val archiveSubtitle: String
    val archiveNoticeTitle: String; val archiveNoticeText: String
    val archivePick: String; val archiveOpen: String
    val archiveOpening: String; val archiveBadPassword: String
    val archiveUnreadable: (String) -> String
    val archiveSummary: (Int, Int) -> String
    val archiveCreatedAt: (String) -> String
    val archiveEmpty: String; val archiveAttachmentMissing: String
    val archiveNoAttachmentsNote: String; val archiveClose: String
    val archiveGroupTag: String; val archiveNotAvailableInDecoy: String
    val archiveFileTooLarge: String
    // Version-8 attachment export (BackupContainer) + attachment display in
    // the read-only viewer.
    val backupToFiles: String
    val backupIncludeAttachments: String
    val backupIncludeAttachmentsOn: String; val backupIncludeAttachmentsOff: String
    val backupShareDisabledWithAttachments: String
    val backupCreatedWithAttachments: (Int, String, Int) -> String
    val backupExportFailed: (String) -> String
    val archiveAttachmentImage: String; val archiveAttachmentVoice: String
    val archiveAttachmentVideo: String; val archiveAttachmentFile: String
    val archiveAttachmentOpen: String; val archiveAttachmentSave: String
    val archiveAttachmentSaved: String; val archiveAttachmentUnavailable: String
    val archiveAttachmentLoading: String
}

interface IStr4 {
    val serversTitle: String; val serversAdd: String
    val serversSwitch: String; val serversSwitching: String
    val serversDefault: (Int) -> String; val serversConnected: String
    val serversConnecting: String; val serversAddTitle: String
    val serversName: String; val serversHost: String; val serversPort: String
    val serversScanQrButton: String; val serversUploadQrButton: String
    val serversScanQrPrompt: String; val serversQrInvalid: String; val serversQrNotFound: String
    val serversAccessCodeRequired: String
    val serversRegistrationFull: String
    val serversDeviceAuthFailed: String
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
    val incomingNoAudioPermission: String
    val activeGroupCallLabel: String; val activeGroupLabel: String
    val activeWaitingPeers: String; val activeConnecting: String
    val activeMute: String; val activeUnmute: String
    val activeCamOff: String; val activeCamOn: String
    val activeSpeaker: String; val activeEarpiece: String; val activeHangUp: String
    val diagTitle: String; val diagInitText: String
    val diagRunning: String; val diagBasic: String; val diagStress: String; val diagAdvanced: String
}

interface IStr6 {
    val chatSearchPlaceholder: String; val chatOnline: String; val chatOffline: String
    val chatKeyWarningTitle: String; val chatKeyWarningText: String
    val chatKeyWarningConfirm: String; val chatKeyWarningLeave: String
    val chatRevokedWarningTitle: String; val chatRevokedWarningText: String
    val chatRevokedWarningConfirm: String
    val chatSendBlockedTitle: String; val chatSendBlockedText: String
    val chatSendBlockedConfirm: String
    val chatTyping: String; val chatMenu: String
    val contactInfoTitle: String
    val chatAudioCall: String; val chatVideoCall: String
    val chatVerifyAction: String; val chatDirectConnection: String
    val chatRestoreConnection: String; val chatRestoreConnectionStarted: String
    val chatRestoreConnectionCooldown: (Int) -> String
    val chatContextReply: String; val chatContextCopy: String
    val chatContextReaction: String; val chatContextEdit: String
    val chatContextDeleteOwn: String; val chatContextDeleteAll: String
    val chatContextResend: String
    val chatPickReaction: String; val chatDisappearTitle: String
    val chatDisappearOff: String; val chatDisappear1h: String
    val chatDisappear24h: String; val chatDisappear7d: String
    val chatDisappear1hShort: String; val chatDisappear24hShort: String
    val chatDisappear7dShort: String; val chatReplyPreview: String
    val chatAutoDeleteMenu: String; val chatAutoDeleteTitle: String
    val chatAutoDeleteDescription: String; val chatDisappearSyncedNote: String
    val chatEditing: String; val chatAttach: String
    val chatAttachPhoto: String; val chatAttachMedia: String; val chatAttachFile: String
    val chatGeo: String; val chatGeoPermission: String
    val chatGeoFail: String; val chatGeoTap: String; val chatGeoDisabled: String
    val chatGeoConfirmTitle: String; val chatGeoConfirmText: String
    val chatEditHint: String; val chatInputHint: String; val chatEstablishingChannel: String
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

interface IStr7 {
    val torConnecting: String; val torIpHidden: String; val torConnected: String
    val torStartingOrbot: String; val torConnectingNetwork: String
    val torAlmostReady: String; val serviceConnecting: String
    val serviceConnected: (String) -> String
    val rootDangerTitle: String; val rootDangerText: String
    val rootDangerReasons: (String) -> String; val rootDangerRecommend: String
    val rootDangerContinue: String; val rootWarningTitle: String
    val rootWarningText: String; val rootWarningConfirm: String
    val rootReasonText: (RootDetector.RootReason) -> String
    val lockTitle: String; val lockUnlock: String
    val lockBiometricTitle: String; val lockBiometricSubtitle: String
    val lockBiometricCancel: String
    val noCameraPermissionVoiceOnly: String; val torStatusStarting: String
    val emergencyInfoTitle: String
    val emergencyInfoOpenSettings: String; val emergencyInfoOpenAppSettings: String
    val emergencyInfoWarning: String
    val emergencyInfoStepLabel: (Int) -> String
    val emergencyInfoStep1Desc: String; val emergencyInfoStep2Desc: String
    val emergencyInfoLegacyDesc: String; val emergencyInfoDone: String
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
    val notifChannelStuckTitle: String; val notifChannelStuckText: (String) -> String
    val notifEmergencyText: String; val notifEmergencyAction: String
    val tamperTitle: String; val tamperText: String; val tamperClose: String
    val paranoidModeTitle: String; val paranoidModeSub: String
    val paranoidModeConfirmTitle: String; val paranoidModeConfirmText: String
    val paranoidModeConfirmBtn: String; val paranoidModeActive: String
    val idsTitle: String; val idsScanBtn: String
    val idsClean: String; val idsThreatFound: String; val idsHoneyTampered: String
    val alertUrlLabel: String; val alertUrlHint: String; val alertUrlSave: String
    val alertUrlInvalid: String; val alertUrlTestBtn: String
    val alertUrlTestOk: String; val alertUrlTestFail: String
}

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
    val dmsIntervalLabel: String; val dmsIntervalHours: String; val dmsIntervalMinutes: String
    val dmsEnabledLabel: String
    val dmsRemainingText: (Long, Long) -> String
    val timeoutWipeTitle: String; val timeoutWipeSubtitle: String
    val timeoutWipeThresholdLabel: String
    val wipeOnBreachTitle: String; val wipeOnBreachSubtitle: String
    val wipeLevelLabel: String
    val wipeLevelHard: String; val wipeLevelNuclear: String
    val wipeHardDesc: String; val wipeNuclearDesc: String
    val wipeSettingsWarning: String
    val panicButtonLabel: String; val panicButtonSubtitle: String
    val panicButtonDecoyLabel: String; val panicButtonDecoySubtitle: String
    val panicNotifTitle: String; val panicNotifText: String; val panicNotifButton: String
    val calcDisguiseLabel: String; val calcDisguiseSubtitle: String
    val calcUnlockCodeLabel: String; val calcUnlockCodeHint: String; val calcUnlockCodeSave: String
    val profileTotp: String
    val totpTitle: String; val totpDescription: String
    val totpStatusEnabled: String; val totpStatusDisabled: String
    val totpSetupButton: String; val totpDisableButton: String; val totpDisableHint: String
    val totpSecretLabel: String; val totpCodeLabel: String; val totpConfirmButton: String
    val totpErrInvalidCode: String; val totpEnabledSuccess: String
    val serverTotpErrNotConnected: String
    val totpConfirmingWithServer: String
    val totpErrTimeout: String
    val totpCopySecret: String
    val totpMandatoryTitle: String; val totpMandatoryIntro: String
    val totpRecoveryCodesTitle: String; val totpRecoveryCodesHint: String
    val totpRecoveryCodesConfirm: String; val totpRecoveryCodesContinue: String
    val totpRecoveryCodesDone: String
    val totpRecoveryPrompt: String; val totpRecoveryFieldLabel: String
    val totpRecoverySubmit: String; val totpRecoveryErr: String
    val totpReenrollPrompt: String
    val backupTotpSecretLabel: String; val backupTotpCodeLabel: String
    val backupTotpRecoveryOr: String; val backupTotpRecoveryLabel: String
}

/** Security guide screen — one title+description pair per protection
 * feature, shown as expandable cards. See SecurityGuideScreen.kt. */
interface IStr10 {
    val guideTitle: String
    val guideInviteTitle: String; val guideInviteDesc: String
    val guideKeyVerifyTitle: String; val guideKeyVerifyDesc: String
    val guideTotpTitle: String; val guideTotpDesc: String
    val guidePanicTitle: String; val guidePanicDesc: String
    val guideEmergencyTitle: String; val guideEmergencyDesc: String
    val guideAutoLockTitle: String; val guideAutoLockDesc: String
    val guideBackupTitle: String; val guideBackupDesc: String
    val guideTorTitle: String; val guideTorDesc: String
    val guideCoverTitle: String; val guideCoverDesc: String
    val guideCompromisedTitle: String; val guideCompromisedDesc: String
    val guideDeleteContactTitle: String; val guideDeleteContactDesc: String
    val guideSelfHealTitle: String; val guideSelfHealDesc: String
    val guideParanoidTitle: String; val guideParanoidDesc: String
    val guideDmsTitle: String; val guideDmsDesc: String
    val guideTimeoutWipeTitle: String; val guideTimeoutWipeDesc: String
    val guidePanicButtonTitle: String; val guidePanicButtonDesc: String
    val guideWipeLevelsTitle: String; val guideWipeLevelsDesc: String
    // Added so every item in the Security settings screen has a matching
    // guide article — these 6 previously had none. See SecuritySettingsScreen.
    val guideHideNotifTitle: String; val guideHideNotifDesc: String
    val guideHideIpCallsTitle: String; val guideHideIpCallsDesc: String
    val guideBiometricTitle: String; val guideBiometricDesc: String
    val guideChangePasswordTitle: String; val guideChangePasswordDesc: String
    val guideDiagnosticsTitle: String; val guideDiagnosticsDesc: String
    val guideServiceNotifTitle: String; val guideServiceNotifDesc: String
    // Added so the two remaining ungrouped items in WipeSettingsScreen
    // (wipe-on-breach, calculator disguise) also have a guide article.
    val guideWipeOnBreachTitle: String; val guideWipeOnBreachDesc: String
    val guideCalcDisguiseTitle: String; val guideCalcDisguiseDesc: String
    // Added 2026-11-06: the read-only archive viewer had no article, and
    // nothing in the guide explained what a wipe actually reaches (or, just as
    // importantly, what it deliberately does not — an exported backup file).
    val guideArchiveTitle: String; val guideArchiveDesc: String
    val guideWipeScopeTitle: String; val guideWipeScopeDesc: String
    // Added 2026-11-06 with the version-8 container: the attachments export
    // option is a real trade-off (archive completeness vs file size and
    // cross-platform import), so it gets its own article rather than a
    // sentence buried in the backup one.
    val guideAttachmentsBackupTitle: String; val guideAttachmentsBackupDesc: String
}

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
    private val p10: IStr10,
) : IStr1 by p1, IStr2 by p2, IStr3 by p3, IStr4 by p4,
    IStr5 by p5, IStr6 by p6, IStr7 by p7, IStr8 by p8, IStr9 by p9, IStr10 by p10

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
    override val loginBiometric = "Биометрия"
    override val loginWaitingBiometric = "Ожидание биометрии..."
    override val loginNotMe = "Это не я — сбросить"
    override val loginNotMeTitle = "Сбросить всё?"
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
    override val registerErrorPasswordLength = "Пароль минимум 8 символов"
    override val registerErrorPasswordCommon = "Этот пароль слишком предсказуем (например, простая последовательность цифр) — выберите менее очевидный"
    override val registerErrorPasswordMatch = "Пароли не совпадают"
    override val registerButton = "Создать аккаунт"
    override val registerImportBackup = "Восстановить из бэкапа"
    override val registerImportTitle = "Восстановить из бэкапа"
    override val registerImportHint = "Файл выбран. Введите пароль, которым он был зашифрован"
    override val registerImportPassword = "Пароль бэкапа"
    override val registerImportChooseFile = "Импортировать"
    override val registerImportTotpHint = "Если бэкап защищён TOTP — введите секрет и текущий код из приложения-аутентификатора, либо один из резервных кодов ниже. Не обязательно, если TOTP не был включён на исходном устройстве."
    override val chatsNoMessages = "Нет сообщений"
    override val chatsNoPosts = "Нет записей"
    override val chatsEmpty = "Нет чатов"
    override val chatsEmptyHint = "Нажми + чтобы добавить контакт\nили создать группу"
    override val chatsSearchPlaceholder = "Поиск по всем чатам..."
    override val chatsSearchNoResults = "Ничего не найдено"
    override val chatsDeleteTitle = "Удалить чат?"
    override val chatsDeleteText: (String) -> String = { "Удалить переписку с $it? Все сообщения и медиафайлы будут удалены безвозвратно." }
    override val chatsAddContact = "Добавить контакт"
    override val chatsInviteCode = "Invite-код"
    override val chatsContactAdded: (String) -> String = { "Контакт добавлен: $it" }
    override val chatsCreateTitle = "Создать"
    override val chatsCreateContact = "Добавить контакт"
    override val chatsCreateGroup = "Создать группу"
    override val chatsSubscribeChannel = "Подписаться на канал"
    override val chatsCreateChannel = "Создать канал"
    override val chatsChannelSubscribeTitle = "Подписаться на канал"
    override val chatsChannelLinkLabel = "Ссылка beacon://channel?..."
    override val chatsChannelCreateTitle = "Создать канал"
    override val chatsChannelNameLabel = "Название канала"
    override val chatsChannelDescLabel = "Описание (необязательно)"
    override val chatsChannelFillFields = "Укажите название канала"
    override val chatsChannelBadLink = "Неверная ссылка"
    override val chatsChannelBadge = "канал"
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
    override val contactInfoNotifications = "Уведомления"
    override val muteSoundOnly = "Отключить звук уведомлений"
    override val contactInfoSearch = "Поиск по чату"
}

private val ru3 = object : IStr3 {
    override val profileTitle = "Профиль"
    override val profileFingerprint = "Ваш отпечаток"
    override val profileFingerprintHint = "Попросите собеседника сравнить эти эмодзи с экраном в верификации чата"
    override val profileInviteCode = "Ваш Invite-код"
    override val profileShareCode = "Поделиться кодом"
    override val profileHideQr = "Скрыть QR"
    override val profileShowQr = "Показать QR-код"
    override val profileScanQr = "Сканировать QR"
    override val profileQrHint = "Пусть собеседник отсканирует этот код"
    override val profileCodeCopied = "код скопирован"
    override val profileSendHint = "Отправьте этот код другу, чтобы он мог добавить вас в контакты"
    override val profileServers = "Серверы"
    override val profileBackup = "Резервное копирование"
    override val profileSectionSecurity = "Безопасность"
    override val profileSectionGeneral  = "Основное"
    override val profileSecurityGuide = "Гид по защите"
    override val profileSecurityGuideSub = "Что делает каждая функция безопасности"
    override val profileConfigureBtn = "Настроить"
    override val profileInviteCodeOneTimeWarning = "Код полностью одноразовый: он действует до активации либо до повторного нажатия «Копировать», «Поделиться» или «Показать QR»"
    override val profileHideNotif = "Скрывать текст в уведомлениях"
    override val profileHideNotifSub = "Показывать только «Новое сообщение»"
    override val profileHideIpCalls = "Скрывать IP во время звонков"
    override val profileHideIpCallsSub = "Звонок только через relay-сервер"
    override val profileHideIpCallsFailedNoTurn = "Не удалось начать звонок: relay-сервер недоступен, а в этом режиме прямое соединение запрещено"
    override val profileAutoLock = "Автоблокировка"
    override val profileAutoLockAfter: (String) -> String = { "Блокировать через: $it" }
    override val profileBiometricTitle = "Разблокировка по биометрии"
    override val profileBiometricSub = "Отпечаток/лицо вместо пароля при входе"
    override val profileBiometricWarningTitle = "Прежде чем включить"
    override val profileBiometricWarningText = "Заставить человека приложить палец или показать лицо физически проще, чем заставить назвать пароль — а в ряде юрисдикций принудительная биометрия юридически защищена слабее, чем принудительное раскрытие пароля. Если для тебя актуален сценарий с физическим/юридическим принуждением — оставь только пароль. Пароль как способ входа остаётся доступен всегда, даже если включишь биометрию."
    override val profileBiometricWarningConfirm = "Понимаю, включить"
    override val profileChangePassword = "Сменить пароль"
    override val changePasswordTitle = "Смена пароля"
    override val changePasswordDesc = "Этот пароль защищает всё зашифрованное локально на устройстве. Смена пароля не трогает уже сохранённые данные — только пересохраняет ключ доступа к ним под новым паролем."
    override val changePasswordCurrent = "Текущий пароль"
    override val changePasswordNew = "Новый пароль"
    override val changePasswordRepeat = "Повторите новый пароль"
    override val changePasswordSubmit = "Сменить пароль"
    override val changePasswordSuccess = "Пароль изменён"
    override val changePasswordErrCurrentWrong = "Текущий пароль неверен"
    override val changePasswordErrSameAsOld = "Новый пароль совпадает со старым — выберите другой"
    override val profileLockOff = "Выкл"
    override val profileLock1min = "1 мин"
    override val profileLock5min = "5 мин"
    override val profileLock15min = "15 мин"
    override val profileLock30min = "30 мин"
    override val profileEmergencyBtn = "Тревожная кнопка"
    override val profileEmergencyBtnSub = "5 нажатий кнопки убавления громкости"
    override val profileNotMe = "!Это не я!"
    override val profileNotMeTitle = "!Это не я!"
    override val profileNotMeText = "Вы уверены? Это удалит ВСЕ данные, чаты, ключи и сбросит приложение!"
    override val profileNotMeConfirm = "Да, сбросить всё"
    override val profileSourceCode = "Исходный код (AGPL-3.0)"
    override val profileCompromised = "Меня скомпрометировали"
    override val profileCompromisedTitle = "Смена identity"
    override val profileCompromisedText = "Текущий ключ, контакты, чаты и сессии будут уничтожены безвозвратно. Вы получите новый ключ и сможете зарегистрироваться заново — контактам нужно будет заново обменяться с вами кодом приглашения. Пароль и настройки безопасности устройства (TOTP, паника, автовайп) не затрагиваются."
    override val profileCompromisedConfirm = "Да, сменить identity"
    override val identityRevokedError = "Этот аккаунт был отозван (после «Меня скомпрометировали»). Войти с этим ключом больше нельзя — зарегистрируйтесь заново."
    override val profileDiagnostics = "Диагностика безопасности"
    override val profileTorEnabled = "Использовать Tor"
    override val profileTorEnabledSub = "Соединение через Orbot вместо прямого. Запуск Orbot при старте может занять до 10-15 секунд"
    override val profileBatteryUnrestricted = "Игнорировать оптимизацию батареи"
    override val profileBatteryUnrestrictedSub = "Помогает фоновому соединению работать стабильнее"
    override val batteryPromptTitle = "Не дайте оболочке душить связь"
    override val batteryPromptText = "На многих телефонах (особенно MIUI и подобных) при сворачивании приложения фоновое соединение тихо глушится — сообщения и квитанции перестают доходить без единой ошибки. Разрешите приложению игнорировать оптимизацию батареи, чтобы связь оставалась надёжной даже в фоне. Это можно включить позже в Профиле."
    override val batteryPromptAllow = "Разрешить"
    override val batteryPromptSkip = "Пропустить"
    override val profileServiceNotifVisible = "Показывать значок сервиса"
    override val profileServiceNotifVisibleSub = "Скрыть значок сервиса из строки состояния"
    override val profilePanicTitle = "Panic Password"
    override val profilePanicSub = "Пароль для экстренного удаления всех данных"
    override val profilePanicSetStatus = "Установлен"
    override val profilePanicEnterLabel = "Введите пароль для экстренного удаления:"
    override val profilePanicInstruction = "Сценарий использования:\n① В экстренной ситуации введите этот пароль один раз — все данные сотрутся.\n② После перезапуска войдите своим обычным паролем."
    override val profilePanicFieldLabel = "Panic пароль"
    override val profilePanicErrSameAsLogin = "Panic-пароль не должен совпадать с обычным паролем входа — иначе каждый ваш вход будет стирать данные"
    override val changePasswordErrSameAsPanic = "Новый пароль совпадает с panic-паролем — выберите другой"
    override val profileLanguageToggle = "English"
    override val profileThemeLabel = "Тема"
    override val profileThemeNavy = "Изумрудная"
    override val profileThemeDark = "Тёмная"
    override val profileThemeLight = "Светлая"
    override val profileInvalidCodeFormat = "Неверный формат кода"
    override val profileInvalidOrExpiredCode = "Недействительный или устаревший код"
    override val profileCameraPermReq = "Необходимо разрешение камеры"
    override val profileQrScanPrompt = "Наведите камеру на QR-код"
    override val backupTitle = "Резервное копирование"
    override val backupSubtitle = "Создайте резервную копию серверов, контактов и истории сообщений"
    override val backupSecurityTitle = "Безопасность бэкапа"
    override val backupSecurityText = "Бэкап содержит все ключи и переписку. Защищён паролем, а импорт дополнительно требует TOTP-секрет и текущий код — одного файла и пароля к нему недостаточно, чтобы восстановить identity. Но если у злоумышленника окажутся файл, пароль и TOTP-секрет вместе, аккаунт будет скомпрометирован — относитесь к бэкапу серьёзно."
    override val backupSecurityTips = "• Используйте надёжный пароль (12+ символов)\n• Не храните файл, пароль и TOTP-секрет в одном месте\n• Храните на зашифрованном диске или в password manager"
    override val backupPassword = "Пароль"
    override val backupRepeatPassword = "Повторите пароль"
    override val backupExport = "Экспорт резервной копии"
    override val backupImport = "Импорт резервной копии"
    override val backupImportWipeTitle = "Внимание"
    override val backupImportWipeText = "Импорт полностью заменит данные этого устройства новой identity из бэкапа: текущие контакты, сообщения и группы будут безвозвратно удалены. Это не откат к старой истории переписки — старые данные не сохранятся ни в каком виде. Возможны сбои при первой синхронизации после импорта. Продолжить?"
    override val backupSaveChooser = "Сохранить резервную копию"
    override val backupCreated = "Резервная копия создана"
    override val backupErrEnterPassword = "Введите пароль"
    override val backupErrPasswordMatch = "Пароли не совпадают"
    override val backupErrPasswordLength = "Пароль должен быть минимум 8 символов"
    override val backupErrTotpRequired = "Сначала включите TOTP-защиту (Профиль → Двухфакторная защита) — без неё файл бэкапа и пароль дают полный доступ к identity, второго фактора нет"
    override val backupErrEnterForDecrypt = "Введите пароль для расшифровки"
    override val archiveTitle = "Чтение бэкапа"
    override val archiveSubtitle = "Открыть файл бэкапа только для чтения — без восстановления и без сервера"
    override val archiveNoticeTitle = "Что делает этот режим"
    override val archiveNoticeText = "Файл расшифровывается в памяти и показывается как текст. Ничего не записывается на устройство, текущая identity не затрагивается, ключи из бэкапа не восстанавливаются — отправлять сообщения от этого аккаунта по-прежнему нельзя. Сервер не нужен: расшифровка полностью локальная. При выходе с экрана или сворачивании приложения расшифрованная копия сбрасывается, и пароль нужно будет ввести заново."
    override val archivePick = "Выбрать файл бэкапа"
    override val archiveOpen = "Открыть для чтения"
    override val archiveOpening = "Расшифровка…"
    override val archiveBadPassword = "Неверный пароль или файл повреждён"
    override val archiveUnreadable: (String) -> String = { d -> "Файл расшифрован, но прочитать содержимое не удалось: $d" }
    override val archiveSummary: (Int, Int) -> String = { threads, messages -> "Переписок: $threads · Сообщений: $messages" }
    override val archiveCreatedAt: (String) -> String = { d -> "Бэкап от $d" }
    override val archiveEmpty = "В этом бэкапе нет сообщений"
    override val archiveAttachmentMissing = "[вложение не входит в бэкап]"
    override val archiveNoAttachmentsNote = "Вложения доступны только если при экспорте была включена опция «Включить вложения». В бэкапах без неё хранится один текст, и сообщения с фото, видео, голосовыми или файлами будут помечены как недоступные."
    override val archiveClose = "Закрыть и очистить"
    override val archiveGroupTag = "группа"
    override val archiveNotAvailableInDecoy = "Недоступно"
    override val archiveFileTooLarge = "Файл слишком большой для чтения в памяти"
    override val backupToFiles = "В файлы"
    override val backupIncludeAttachments = "Включить вложения"
    override val backupIncludeAttachmentsOn = "Фото, видео, голосовые и файлы войдут в бэкап. Файл будет значительно больше, и его не сможет прочитать настольный клиент (новый формат)."
    override val backupIncludeAttachmentsOff = "Только текст переписки — как раньше. Такой файл читается и настольным клиентом."
    override val backupShareDisabledWithAttachments = "С вложениями доступно только сохранение «В файлы»: отправка через другие приложения делает вторую копию файла, что недопустимо при большом размере."
    override val backupCreatedWithAttachments: (Int, String, Int) -> String = { count, size, missing ->
        val base = "Резервная копия создана. Вложений: $count ($size)."
        if (missing > 0) "$base Не удалось прочитать: $missing — эти файлы уже отсутствовали на устройстве." else base
    }
    override val backupExportFailed: (String) -> String = { d ->
        "Экспорт не завершён: $d. НЕ используйте созданный файл — он записан не полностью. Удалите его и попробуйте снова."
    }
    override val archiveAttachmentImage = "Фото"
    override val archiveAttachmentVoice = "Голосовое сообщение"
    override val archiveAttachmentVideo = "Видео"
    override val archiveAttachmentFile = "Файл"
    override val archiveAttachmentOpen = "Показать"
    override val archiveAttachmentSave = "Сохранить"
    override val archiveAttachmentSaved = "Сохранено"
    override val archiveAttachmentUnavailable = "Вложение недоступно в этом файле"
    override val archiveAttachmentLoading = "Извлечение…"
}

private val ru4 = object : IStr4 {
    override val serversTitle = "Серверы"
    override val serversAdd = "Добавить"
    override val serversSwitch = "Переключить сервер"
    override val serversSwitching = "Переподключение к следующему серверу..."
    override val serversDefault: (Int) -> String = { "Сервер $it" }
    override val serversConnected = "Подключено"
    override val serversConnecting = "Подключение..."
    override val serversAddTitle = "Добавить сервер"
    override val serversName = "Название"
    override val serversHost = "Хост (IP или домен)"
    override val serversScanQrButton = "Сканировать QR"
    override val serversUploadQrButton = "Загрузить QR-файл"
    override val serversScanQrPrompt = "Наведи камеру на QR-код сервера"
    override val serversQrInvalid = "Это не похоже на код сервера Subrosa"
    override val serversQrNotFound = "QR-код не найден на фото"
    override val serversAccessCodeRequired = "Этот сервер требует код доступа для регистрации — попроси у оператора QR-код или ссылку"
    override val serversRegistrationFull = "Этот сервер достиг лимита аккаунтов и сейчас не принимает новые регистрации"
    override val serversDeviceAuthFailed = "Не удалось подтвердить это устройство. Попробуй перезайти или обратись в поддержку"
    override val serversPort = "Порт"
    override val groupInfoTitle = "Информация о группе"
    override val groupInfoNotFound = "Группа не найдена"
    override val groupInfoMembersCount: (Int) -> String = { "$it участников" }
    override val groupInfoDescription = "Описание"
    override val groupInfoAddDescription = "Нажмите чтобы добавить описание"
    override val groupInfoNoDescription = "Нет описания"
    override val groupInfoMembersSection = "Участники"
    override val groupInfoCreator = "Создатель"
    override val groupInfoAdmin = "Администратор"
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
    override val groupInfoChangeAvatar = "сменить"
    override val createGroupTitle = "Создать группу"
    override val createGroupTapAvatar = "Нажми для выбора аватара"
    override val createGroupNameLabel = "Название группы"
    override val createGroupMembersTitle: (Int) -> String = { "Участники ($it)" }
    override val createGroupButton = "Создать группу"
    override val createGroupAvatarTitle = "Выбери аватар группы"
}

private val ru5 = object : IStr5 {
    override val channelDefault = "Канал"
    override val channelCopyLink = "Ссылка"
    override val channelUnsubscribe = "Отписаться"
    override val channelPostPlaceholder = "Написать в канал..."
    override val channelLinkCopied = "Ссылка скопирована"
    override val channelLoadImageError = "Не удалось загрузить изображение"
    override val channelWriteFirst = "Напишите первую запись ниже"
    override val channelSubscribeConfirm = "Подписаться на этот канал?"
    override val channelSubscribeBtn = "Подписаться"
    override val channelMute = "Выключить уведомления"
    override val channelUnmute = "Включить уведомления"
    override val channelSubscribers: (Int) -> String = { "$it подписчиков" }
    override val channelSearchPlaceholder = "Поиск по постам..."
    override val channelPinPost = "Закрепить"
    override val channelUnpinPost = "Открепить"
    override val channelPinned = "Закреплено"
    override val channelDeletePost = "Удалить пост"
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
    override val incomingNoAudioPermission = "Без доступа к микрофону звонок принять нельзя"
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
    override val diagTitle = "Диагностика безопасности"
    override val diagInitText = "Нажмите кнопку для запуска диагностики..."
    override val diagRunning = "Выполняется..."
    override val diagBasic = "Базовая диагностика"
    override val diagStress = "Стресс-тесты (попытка сломать защиту)"
    override val diagAdvanced = "Расширенные тесты (сессии + группы)"
}

private val ru6 = object : IStr6 {
    override val chatSearchPlaceholder = "Поиск в чате..."
    override val chatOnline = "онлайн"
    override val chatOffline = "не в сети"
    override val chatKeyWarningTitle = "ВНИМАНИЕ!"
    override val chatKeyWarningText = "Ключ шифрования собеседника изменился!\n\nЭто может означать:\n• Переустановку приложения\n• Новое устройство\n• MITM атаку\n\nСвяжитесь с собеседником другим способом!"
    override val chatKeyWarningConfirm = "Я проверил(а), всё ОК"
    override val chatKeyWarningLeave = "Выйти из чата"
    override val chatRevokedWarningTitle = "ВНИМАНИЕ!"
    override val chatRevokedWarningText = "Identity этого собеседника была отозвана владельцем (через «Меня скомпрометировали» или Dead Man's Switch) — это может означать, что его ключ был скомпрометирован.\n\nСвяжитесь с ним другим способом и попросите новый код приглашения."
    override val chatRevokedWarningConfirm = "Понятно"
    override val chatSendBlockedTitle = "Собеседник не получает сообщения"
    override val chatSendBlockedText = "Уже 10 сообщений подряд ушли без единого подтверждения о доставке. Похоже, собеседник давно не в сети.\n\nОтправка временно приостановлена — дождитесь, пока он выйдет в сеть. Сообщения, которые вы уже написали, никуда не делись и уйдут автоматически."
    override val chatSendBlockedConfirm = "Понятно"
    override val chatTyping = "печатает..."
    override val chatMenu = "Меню"
    override val contactInfoTitle = "Профиль"
    override val chatAudioCall = "Аудиозвонок"
    override val chatVideoCall = "Видеозвонок"
    override val chatVerifyAction = "Верификация"
    override val chatRestoreConnection = "Восстановить связь"
    override val chatRestoreConnectionStarted = "Отправлен запрос на восстановление связи — попросите собеседника нажать то же самое"
    override val chatRestoreConnectionCooldown = { min: Int -> "Подождите ещё ${min} мин перед повторной попыткой" }
    override val chatDirectConnection = "Прямое подключение — без Tor. Установите Orbot для анонимности."
    override val chatContextReply = "Ответить"
    override val chatContextCopy = "Копировать"
    override val chatContextReaction = "Реакция"
    override val chatContextEdit = "Редактировать"
    override val chatContextDeleteOwn = "Удалить у себя"
    override val chatContextDeleteAll = "Удалить у всех"
    override val chatContextResend = "Отправить снова"
    override val chatPickReaction = "Выбери реакцию"
    override val chatDisappearTitle = "Исчезающие сообщения"
    override val chatDisappearOff = "Выкл"
    override val chatDisappear1h = "1 час"
    override val chatDisappear24h = "24 часа"
    override val chatDisappear7d = "7 дней"
    override val chatDisappear1hShort = " · ⏱1ч"
    override val chatDisappear24hShort = " · ⏱1д"
    override val chatDisappear7dShort = " · ⏱7д"
    override val chatReplyPreview = "Ответ на сообщение"
    override val chatAutoDeleteMenu = "Автоудаление (только на этом устройстве)"
    override val chatAutoDeleteTitle = "Автоудаление сообщений"
    override val chatAutoDeleteDescription = "Сообщения старше выбранного времени будут удалены только с этого устройства. Собеседник и его копия переписки не затрагиваются — это не то же самое, что «Исчезающие сообщения»."
    override val chatDisappearSyncedNote = "Синхронизировано с собеседником — удаляет у обеих сторон"
    override val chatEditing = "Редактирование"
    override val chatAttach = "Прикрепить"
    override val chatAttachPhoto = "Фото"
    override val chatAttachMedia = "Медиа"
    override val chatAttachFile = "Файл"
    override val chatGeo = "Геопозиция"
    override val chatGeoPermission = "Разрешите доступ к геопозиции"
    override val chatGeoFail = "Не удалось определить позицию"
    override val chatGeoTap = "Геопозиция (нажми для просмотра)"
    override val chatGeoDisabled = "Включи геолокацию в настройках телефона"
    override val chatGeoConfirmTitle = "Отправить геопозицию?"
    override val chatGeoConfirmText = "Собеседник увидит ваше текущее местоположение на карте."
    override val chatEditHint = "Изменить..."
    override val chatInputHint = "Сообщение..."
    override val chatEstablishingChannel = "Устанавливаем защищённый канал..."
    override val chatPhotoTooBig = "Фото слишком большое для обработки"
    override val chatFileTooBig = "Файл слишком большой (макс 20 МБ)"
    override val chatMediaOffline = "Нет соединения — медиафайл не отправлен"
    override val chatFileSending: (String, Int) -> String = { name, kb -> "Отправка: $name (${kb}KB)" }
    override val chatVerifyTitle = "Верификация контакта"
    override val chatVerifyFingerprintLabel = "Fingerprint контакта:"
    override val chatVerifyHint = "Попросите собеседника назвать эмодзи из своего профиля — обязательно по другому каналу связи (лично, по телефону, в другом мессенджере), не через этот чат: если канал скомпрометирован, сверка внутри него ничего не докажет."
    override val chatVerifyKeyError = "Ошибка чтения ключа"
    override val chatVerifyUnknown = "Неизвестно"
    override val chatReplyLabel = "Ответить"
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
    override val verifyEmojiHint: (String) -> String = { "Попросите $it назвать эмодзи из своего профиля — по другому каналу связи (лично, по телефону, в другом мессенджере), не через этот чат.\nЕсли совпадают — соединение безопасно. Сверка через сам чат ничего не доказывает, если этот канал скомпрометирован." }
    override val verifyHexLabel = "Отпечаток ключа (hex):"
    override val verifyHint = "Для максимальной безопасности сравните отпечаток при личной встрече или по голосовому звонку."
    override val verifyMarkVerified = "Пометить как проверенный"
    override val verifyAlreadyVerified = "Ключ проверен"
    override val chatLoadEarlier = "↑ Загрузить ранее"
    override val chatSavePhoto = "Сохранить фото"
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
    override val rootDangerTitle = "Root обнаружен"
    override val rootDangerText = "На устройстве обнаружен root-доступ. Шифрование Subrosa может быть скомпрометировано — ключи и сообщения доступны другим приложениям."
    override val rootDangerReasons: (String) -> String = { "Признаки:\n$it" }
    override val rootDangerRecommend = "Рекомендуется использовать устройство без root."
    override val rootDangerContinue = "Всё равно продолжить"
    override val rootWarningTitle = "Подозрительное устройство"
    override val rootWarningText = "Обнаружен подозрительный признак. Возможно, устройство модифицировано."
    override val rootWarningConfirm = "Понятно"
    override val rootReasonText: (RootDetector.RootReason) -> String = {
        when (it) {
            RootDetector.RootReason.ROOT_BINARY -> "Найден su-бинарник"
            RootDetector.RootReason.TEST_KEYS_BUILD -> "Сборка с test-keys"
            RootDetector.RootReason.ROOT_PACKAGE -> "Установлено root-приложение"
            RootDetector.RootReason.WHICH_SU -> "Команда which su вернула результат"
            RootDetector.RootReason.SYSTEM_WRITABLE -> "Раздел /system доступен на запись"
            RootDetector.RootReason.DEBUGGER_CONNECTED -> "Подключён отладчик (adb/Android Studio)"
            RootDetector.RootReason.TRACER_PID -> "Процесс трассируется (GDB/strace/LLDB)"
            RootDetector.RootReason.FRIDA_PORT -> "Активен сервер Frida"
            RootDetector.RootReason.FRIDA_MAPS -> "В памяти процесса найден агент Frida"
            RootDetector.RootReason.FRIDA_PROCESS -> "Обнаружен процесс Frida"
            RootDetector.RootReason.XPOSED_BRIDGE -> "Активен Xposed/LSPosed"
            RootDetector.RootReason.XPOSED_PACKAGE -> "Установлен менеджер Xposed/LSPosed"
            RootDetector.RootReason.XPOSED_MAPS -> "В памяти процесса найден XposedBridge.jar"
            RootDetector.RootReason.EMULATOR_HIGH_CONFIDENCE -> "Похоже на эмулятор"
            RootDetector.RootReason.EMULATOR_POSSIBLE -> "Возможно, эмулятор"
        }
    }
    override val lockTitle = "Приложение заблокировано"
    override val lockUnlock = "Разблокировать"
    override val lockBiometricTitle = "Разблокировать Subrosa"
    override val lockBiometricSubtitle = "Подтвердите личность"
    override val lockBiometricCancel = "Отмена"
    override val noCameraPermissionVoiceOnly = "Разрешение камеры не дано — голосовой звонок"
    override val torStatusStarting = "Запуск..."
    override val emergencyInfoTitle = "Экстренное удаление"
    override val emergencyInfoOpenSettings = "Спец. возможности"
    override val emergencyInfoOpenAppSettings = "Настройки приложения"
    override val emergencyInfoWarning = "Нажмите 5 раз УБАВИТЬ ГРОМКОСТЬ за 3 секунды — " +
        "приложение немедленно удалит все ключи и переписки.\nБез подтверждения!"
    override val emergencyInfoStepLabel: (Int) -> String = { n -> "Шаг $n" }
    override val emergencyInfoStep1Desc = "Откройте настройки приложения, затем ⋮ (вверху справа) → «Доступ к огр. настройкам»"
    override val emergencyInfoStep2Desc = "Спец. возможности → Subrosa Emergency Wipe → включить"
    override val emergencyInfoLegacyDesc = "Спец. возможности → Subrosa Emergency Wipe → включить"
    override val emergencyInfoDone = "Служба уже включена"
    override val spyAppsAccessibilitySection = "Службы Accessibility:\n"
    override val spyAppsAdminsSection = "Администраторы устройства:\n"
    override val spyAppsOverlaySection = "Право рисовать поверх экрана:\n"
    override val spyAppsTitle = "Подозрительные приложения"
    override val spyAppsMessage: (String) -> String = { "Обнаружены приложения, которые могут перехватывать экран или касания:\n\n$it\n\nРекомендуем отозвать их права или удалить.\nКасания поверх Subrosa заблокированы автоматически." }
    override val spyAppsSettings = "Accessibility настройки"
    override val groupCallPeerName = "Группа"
    override val systemSender = "Система"
    override val groupMemberLeft: (String) -> String = { "$it покинул(а) группу" }
    override val groupKeyUpdated = "Ключ шифрования обновлён"
    override val groupMemberJoined: (String) -> String = { "$it присоединился(лась) к группе" }
    override val channelCreatedToast: (String) -> String = { "Канал «$it» создан!" }
    override val channelFallbackName = "Канал"
    override val channelNoConnection = "Нет соединения с сервером"
    override val recipientOffline = "Получатель не в сети"
    override val notifChannelDesc = "Экстренное удаление данных"
    override val notifSessionTitle = "Сессия завершена"
    override val notifSessionText = "Ваш аккаунт был открыт на другом устройстве"
    override val notifNewMessage = "Новое сообщение"
    override val notifTapToRead = "Нажмите, чтобы прочитать"
    override val notifMessageCount: (Int) -> String = { "$it сообщений" }
    override val notifGroupFallback = "Группа"
    override val notifNewGroupMessage = "Новое сообщение в группе"
    override val notifMissedVideoCall = "Пропущенный видеозвонок"
    override val notifMissedCall = "Пропущенный звонок"
    override val notifFromCaller: (String) -> String = { "От: $it" }
    override val notifChannelStuckTitle = "Не удаётся установить связь"
    override val notifChannelStuckText: (String) -> String = { "Первое сообщение для $it всё ещё не доставлено. Попробуйте позже или обменяйтесь кодом ещё раз." }
    override val notifEmergencyText = "Нажмите для экстренного удаления"
    override val notifEmergencyAction = "УДАЛИТЬ ВСЁ"
    override val tamperTitle = "Приложение повреждено"
    override val tamperText = "Подпись APK не совпадает с оригиналом. Возможно, приложение было перепаковано или модифицировано злоумышленником. Использование небезопасно — ключи шифрования могут быть скомпрометированы."
    override val tamperClose = "Закрыть"
    override val paranoidModeTitle = "Режим паранойи"
    override val paranoidModeSub = "Root/Frida → немедленный выход, блокировка внешних интентов, очистка логов"
    override val paranoidModeConfirmTitle = "Включить режим паранойи?"
    override val paranoidModeConfirmText = "После включения переключатель исчезнет — режим нельзя отключить без полного сброса данных приложения.\n\nПри обнаружении Root, Frida или эмулятора приложение немедленно закроется без предупреждения.\n\nВключить только если уверен."
    override val paranoidModeConfirmBtn = "Включить"
    override val paranoidModeActive = "Активен"
    override val idsTitle = "IDS — Детектор вторжений"
    override val idsScanBtn = "Сканировать"
    override val idsClean = "Угроз не обнаружено"
    override val idsThreatFound = "Обнаружены угрозы"
    override val idsHoneyTampered = "Файл-приманка изменён"
    override val alertUrlLabel = "Alert URL (необязательно)"
    override val alertUrlHint = "https://your-server/alert"
    override val alertUrlSave = "Сохранить"
    override val alertUrlInvalid = "Нужен адрес по HTTPS (http:// не пройдёт из-за политики шифрования трафика)"
    override val alertUrlTestBtn = "Тест"
    override val alertUrlTestOk = "Доставлено"
    override val alertUrlTestFail = "Не доставлено — проверьте адрес и сеть"
}

private val ru8 = object : IStr8 {
    override val groupChatNoMessages = "Нет сообщений"
    override val groupChatMessageHint = "Сообщение..."
    override val groupChatEditHint = "Изменить..."
    override val groupChatInfo = "Инфо"
    override val groupChatReply = "Ответить"
    override val groupChatCopy = "Копировать"
    override val groupChatReactionLabel = "Реакция"
    override val groupChatEditAction = "Редактировать"
    override val groupChatDeleteOwn = "Удалить у себя"
    override val groupChatDeleteAll = "Удалить у всех"
    override val groupChatPickReaction = "Выбери реакцию"
    override val groupChatEditing = "Редактирование"
    override val groupChatAttach = "Прикрепить"
    override val groupChatAttachPhoto = "Фото"
    override val groupChatAttachFile = "Файл"
    override val groupChatGeo = "Геопозиция"
    override val groupChatGeoPermission = "Разрешите доступ к геопозиции"
    override val groupChatGeoFail = "Не удалось определить позицию"
}

private val ru9 = object : IStr9 {
    override val wipeSettingsTitle = "Уничтожение данных"
    override val dmsTitle = "Dead Man's Switch"
    override val dmsSubtitle = "Уничтожить данные если не подтверждена безопасность в срок"
    override val dmsCheckinBtn = "Я в безопасности"
    override val dmsNotifTitle = "Dead Man's Switch"
    override val dmsNotifText = "Нажмите «Я в безопасности» или данные будут уничтожены"
    override val dmsNotifGraceText = "Нажмите «Я в безопасности» или данные будут уничтожены через 15 минут"
    override val dmsIntervalLabel = "Интервал проверки"
    override val dmsIntervalHours = "ч"
    override val dmsIntervalMinutes = "мин"
    override val dmsEnabledLabel = "Включить Dead Man's Switch"
    override val dmsRemainingText: (Long, Long) -> String = { h, m -> "Осталось: ${h}ч ${m}м" }
    override val timeoutWipeTitle = "Таймаут пароля"
    override val timeoutWipeSubtitle = "Уничтожить данные если нет входа в приложение дольше заданного времени"
    override val timeoutWipeThresholdLabel = "Уничтожить если нет входа более:"
    override val wipeOnBreachTitle = "Wipe при взломе"
    override val wipeOnBreachSubtitle = "Уничтожить данные при обнаружении критической угрозы IDS"
    override val wipeLevelLabel = "Уровень уничтожения"
    override val wipeLevelHard = "Жёсткий (HARD)"
    override val wipeLevelNuclear = "Ядерный (NUCLEAR)"
    override val wipeHardDesc = "Удаляет все ключи, файлы и данные приложения — но специально сохраняет хеш пароля в скрытом месте, чтобы после уничтожения приложение всё ещё узнавало владельца (нужно для сценария с decoy-паролем)"
    override val wipeNuclearDesc = "То же самое, что Hard, но без всяких исключений — системный вызов Android «Очистить данные», гарантированно стирающий вообще всё, включая ту служебную запись, которую Hard специально оставляет. Восстановить доступ через decoy-пароль после этого будет уже нельзя"
    override val wipeSettingsWarning = "Эти настройки необратимы. После срабатывания все данные будут уничтожены без возможности восстановления."
    override val panicButtonLabel = "Кнопка паники на экране блокировки"
    override val panicButtonSubtitle = "Показывает уведомление с кнопкой вайпа, доступной без разблокировки. Одного нажатия достаточно — срабатывает сразу, без подтверждения."
    override val panicButtonDecoyLabel = "Режим Decoy после вайпа"
    override val panicButtonDecoySubtitle = "После срабатывания кнопки паники в уведомлении или 5 нажатий громкости (Тревожная кнопка) — показать фейковый экран чатов вместо немедленного закрытия. Общая настройка на оба способа."
    override val panicNotifTitle = "Subrosa — Экстренный вайп"
    override val panicNotifText = "Нажмите «УНИЧТОЖИТЬ» для немедленного стирания всех данных"
    override val panicNotifButton = "УНИЧТОЖИТЬ"
    override val calcDisguiseLabel = "Маскировка под калькулятор"
    override val calcDisguiseSubtitle = "Иконка и название заменяются на «Калькулятор». Задай ниже свой код разблокировки — результат любого выражения, равный этому числу, открывает мессенджер"
    override val calcUnlockCodeLabel = "Код разблокировки (число-результат)"
    override val calcUnlockCodeHint = "Например: 42"
    override val calcUnlockCodeSave = "Сохранить и включить"
    override val profileTotp = "Двухфакторная защита (TOTP)"
    override val totpTitle = "Двухфакторная защита (TOTP)"
    override val totpDescription = "Дополнительный фактор защиты аккаунта: код потребуется и при восстановлении бэкапа на новом устройстве, и при попытке зайти под этим же fingerprint'ом с нового устройства (device_id), которое сервер раньше не видел — это перекрывает риск, что кто-то с украденным бэкапом или ключом просто зарегистрируется от вашего имени. Секрет нужно сохранить отдельно (например, в KeePass) — он не хранится внутри самого бэкапа, поэтому одного файла бэкапа и пароля к нему будет недостаточно, чтобы угнать identity. Если сменили аутентификатор или подозреваете утечку секрета — здесь же можно выпустить новый (нужен текущий код)."
    override val totpStatusEnabled = "Включено"
    override val totpStatusDisabled = "Выключено"
    override val totpSetupButton = "Настроить"
    override val totpDisableButton = "Сменить секрет"
    override val totpDisableHint = "Понадобится текущий код из аутентификатора. Сразу после подтверждения откроется настройка нового секрета — окно без защиты займёт лишь пару шагов, а не останется висеть выключенным."
    override val totpSecretLabel = "Секрет (сохраните его отдельно, не рядом с бэкапом)"
    override val totpCodeLabel = "Код из приложения-аутентификатора"
    override val totpConfirmButton = "Подтвердить и включить"
    override val totpErrInvalidCode = "Неверный код"
    override val totpEnabledSuccess = "TOTP-защита включена"
    override val serverTotpErrNotConnected = "Нет соединения с сервером"
    override val totpConfirmingWithServer = "Подтверждаем с сервером — подождите..."
    override val totpErrTimeout = "Сервер не ответил вовремя — попробуйте ещё раз"
    override val totpCopySecret = "Копировать"
    override val totpMandatoryTitle = "Защита аккаунта"
    override val totpMandatoryIntro = "Прежде чем продолжить — настройте TOTP-защиту. Это обязательный шаг: без него сервер не сможет отличить вас от того, кто украдёт ваш ключ."
    override val totpRecoveryCodesTitle = "Резервные коды — сохраните их сейчас"
    override val totpRecoveryCodesHint = "Каждый код можно использовать один раз, если вы потеряете доступ к приложению-аутентификатору. Больше эти коды нигде не показываются — сохраните их отдельно (например, в KeePass), не рядом с бэкапом."
    override val totpRecoveryCodesConfirm = "Я сохранил(а) эти коды в надёжном месте"
    override val totpRecoveryCodesContinue = "Продолжить"
    override val totpRecoveryCodesDone = "Готово"
    override val totpRecoveryPrompt = "Этому устройству нужен код для входа в аккаунт, защищённый TOTP. У этого устройства нет приложения-аутентификатора — введите один из резервных кодов, полученных при включении защиты."
    override val totpRecoveryFieldLabel = "Резервный код"
    override val totpRecoverySubmit = "Отправить"
    override val totpRecoveryErr = "Код не принят — проверьте и попробуйте снова"
    override val totpReenrollPrompt = "На этом аккаунте уже настроена TOTP-защита с другого устройства. Если вы только что вошли по резервному коду — введите ещё один резервный код ниже, чтобы заменить защиту на эту новую."
    override val backupTotpSecretLabel = "TOTP-секрет (если был включён на исходном устройстве)"
    override val backupTotpCodeLabel = "Текущий TOTP-код"
    override val backupTotpRecoveryOr = "— или, если секрет утерян —"
    override val backupTotpRecoveryLabel = "Резервный код (из тех, что показывались при включении TOTP)"
}

private val ru10 = object : IStr10 {
    override val guideTitle = "Гид по защите"
    override val guideInviteTitle = "Invite-код"
    override val guideInviteDesc = "Способ анонимно познакомиться с человеком, не раскрывая серверу пару отправитель-получатель. Код одноразовый: после того как кто-то его отсканирует, зашитый в нём тег «умирает» и перестаёт работать. На устройстве в любой момент активен только один такой тег — повторное нажатие «Копировать»/«Поделиться»/QR тоже его меняет, даже если предыдущий получатель ещё не подключился, и молча ломает его код. Добавляешь нескольких людей — дожидайся подключения текущего, прежде чем генерировать код для следующего."
    override val guideKeyVerifyTitle = "Верификация пользователя"
    override val guideKeyVerifyDesc = "Последовательность из 5 эмодзи, полученная из хэша публичного ключа собеседника. Сверьте её с собеседником лично или по другому каналу — если совпадает, вы точно говорите с ним, а не с кем-то, кто подменил ключ (атака «человек посередине»)."
    override val guideTotpTitle = "Двухфакторная защита (TOTP)"
    override val guideTotpDesc = "Обязательный код из приложения-аутентификатора (как Google Authenticator), без которого этот аккаунт нельзя зарегистрировать на новом устройстве, даже если ключи и пароль украдены. Сохраните резервные коды, выданные при настройке, отдельно от телефона. Резервный код пускает на новое устройство, если аутентификатор потерян, но не отключает защиту сам по себе — сразу после входа настройте TOTP заново на этом устройстве (для этого понадобится ещё один резервный код)."
    override val guidePanicTitle = "Panic password"
    override val guidePanicDesc = "Второй пароль для входа, отличный от основного. Введённый вместо основного, он показывает правдоподобный фейковый мессенджер с выдуманными чатами, а настоящие ключи и переписка в это время безвозвратно удаляются в фоне — используйте, если вас заставляют разблокировать Subrosa. Две детали, на которые он рассчитан: приложение после этого не закрывается и не перезапускается (резкое закрытие само выдало бы подмену), а ограничение на число попыток входа к нему не применяется — он сработает даже если вы перед этим несколько раз ошиблись в основном пароле и вход временно заблокирован. Фейковые переписки генерируются один раз при настройке и дальше не меняются, поэтому при повторном открытии будут те же чаты, что и в первый раз."
    override val guideEmergencyTitle = "Тревожная кнопка"
    override val guideEmergencyDesc = "5 нажатий кнопки громкости вниз за 3 секунды — мгновенное удаление ключей и переписки без единого подтверждения, работает даже с заблокированным экраном. По умолчанию просто удаляет данные; тумблер «Режим Decoy после вайпа» (тот же, что и у кнопки паники в уведомлении — настройка общая на обе) включает вместо этого показ фейкового мессенджера, как у пароля под принуждением. Требует включения через Спец. возможности Android (см. инструкцию в Профиле)."
    override val guideAutoLockTitle = "Автоблокировка"
    override val guideAutoLockDesc = "Приложение блокируется паролем/биометрией через заданное время бездействия. Чем короче интервал, тем меньше окно, в течение которого кто-то может взять разблокированный телефон и открыть переписку."
    override val guideBackupTitle = "Резервное копирование"
    override val guideBackupDesc = "Зашифрованный файл со всеми ключами и историей сообщений. Защищён паролем (Argon2id), а восстановление на новом устройстве дополнительно требует TOTP-секрет — одного файла и пароля к нему недостаточно. Храните файл, пароль и TOTP-секрет в разных местах. Два важных свойства файла: он переживает любой уровень экстренного удаления, потому что лежит вне приложения — если вы делаете вайп, удалите копию бэкапа отдельно; и его можно прочитать без сервера и без восстановления, см. «Чтение бэкапа без восстановления». По умолчанию в бэкап попадает только текст; вложения включаются отдельной опцией при экспорте — см. «Вложения в бэкапе»."
    override val guideTorTitle = "Tor"
    override val guideTorDesc = "Маршрутизация соединения с сервером через сеть Tor (нужен установленный Orbot), скрывает ваш IP-адрес от самого сервера. Выключен по умолчанию — включение добавляет 10-15 секунд к запуску приложения.\n\nВажно: это касается только соединения с сервером (вход, сообщения, сигнализация звонков — кто кому звонит). Сама аудио/видео-передача звонка через Tor не идёт: WebRTC не умеет ходить через SOCKS-прокси Orbot и соединяется напрямую или через relay-сервер в обход него. За IP именно во время звонка отвечает отдельная настройка «Скрывать IP во время звонков» — Tor и она не мешают друг другу, но и не заменяют одна другую: включайте обе, если нужна защита и там, и там."
    override val guideCoverTitle = "Постоянный трафик"
    override val guideCoverDesc = "Приложение шлёт пакеты-пустышки через равные интервалы, даже когда вы ничего не отправляете, — так внешний наблюдатель не может по паттерну трафика понять, переписываетесь вы сейчас или нет. Расходует немного батареи и интернета."
    override val guideCompromisedTitle = "Смена identity"
    override val guideCompromisedDesc = "Если подозреваете, что ваш ключ украли — это полностью уничтожает текущие ключи, контакты и переписку на этом устройстве и выдаёт новые. Перед удалением приложение также сообщает серверу отозвать старую identity — старый ключ больше не сможет пройти регистрацию, даже если он попал в чужие руки. Контактам нужно будет заново обменяться с вами свежим инвайт-кодом, чтобы перейти на новую identity. Необратимо."
    override val guideDeleteContactTitle = "Удаление контакта"
    override val guideDeleteContactDesc = "Удаление контакта — не просто очистка списка. Приложение сразу отзывает у него все ещё не потраченные токены (писать вам старыми уже не получится) и блокирует новые попытки связаться с этим человеком — даже если он пришлёт новый запрос на сессию, устройство молча его проигнорирует. Блокировка снимается сама, если вы позже добавите тот же контакт заново по свежему инвайт-коду. Это быстрый способ отрезать контакта, чьё устройство вы считаете скомпрометированным."
    override val guideSelfHealTitle = "Самовосстановление связи"
    override val guideSelfHealDesc = "Приложение специально не раскрывает серверу, кто с кем переписывается — это сильно повышает приватность, но иногда означает, что после сбоя (например, долгого отсутствия сети) переписка или звонок восстанавливаются не мгновенно, а через какое-то время. Это не значит, что что-то сломано: канал связи умеет чиниться сам. Если сообщение не идёт — обычно достаточно подождать. Мы продолжаем тестировать и сокращать эти задержки."
    override val guideParanoidTitle = "Режим паранои и Alert URL"
    override val guideParanoidDesc = "Включает постоянную проверку устройства на слежку (шпионские Accessibility-сервисы, подозрительные права администратора, оверлеи поверх экрана и вмешательство в honey-токен). При обнаружении угрозы: если задан «тревожный URL» (Диагностика безопасности → поле URL) — на него молча уходит POST-запрос с ID устройства и списком угроз, в обход обычного канала мессенджера (если вас раскрыли, ему нельзя доверять). Дальше — либо автоматическое удаление данных (если включён «вайп при взломе»), либо стелс-режим с фейковым экраном, как у пароля под принуждением.\n\nКакая ссылка нужна: обычный HTTPS-адрес (http:// заблокирован политикой трафика и просто не уйдёт, кроме localhost/эмулятора/.onion), принимающий POST-запрос с телом вида {\"device_id\":\"...\",\"threats\":\"...\",\"ts\":1234567890} — без заголовков авторизации, значит принимающая сторона должна просто уметь принять POST и как-то показать вам этот JSON.\n\nМинимальный принимающий вариант без своего сервера: приложение ntfy (ntfy.sh) — поставьте его на телефон или откройте web-версию, подпишитесь на приватную тему с непредсказуемым именем (например ntfy.sh/xk7q-мойличныйканал) и укажите этот адрес как Alert URL. ntfy не разбирает чужой JSON — просто покажет его текстом как push-уведомление, этого достаточно, чтобы увидеть ID устройства, список угроз и время. Кнопкой «Тест» на экране диагностики можно сразу проверить доставку, не дожидаясь реальной угрозы."
    override val guideDmsTitle = "Мёртвая рука (Dead Man's Switch)"
    override val guideDmsDesc = "Таймер самопроверки: от 15 минут до 3 суток. Если вы не нажали «Я на связи» до истечения интервала — приложение считает, что с вами что-то случилось, отзывает вашу identity на сервере (старый ключ перестаёт проходить регистрацию) и уничтожает данные максимально жёстким уровнем (Nuclear), без дополнительных подтверждений. Полезно, если вас могут задержать/лишить доступа к телефону надолго и вы не сможете сами инициировать удаление."
    override val guideTimeoutWipeTitle = "Таймаут пароля"
    override val guideTimeoutWipeDesc = "Похоже на «мёртвую руку», но проще: если приложение просто не открывали 24/48/72 часа (неважно, по какой причине) — срабатывает та же самая цепочка, что и у «мёртвой руки»: сначала предупреждающее уведомление, затем 15 минут на то, чтобы просто открыть приложение и отменить, и только потом — отзыв identity на сервере и удаление максимально жёстким уровнем (Nuclear). Хорошо подходит как фоновая защита на случай, если телефон украли и не пытаются его разблокировать сразу."
    override val guidePanicButtonTitle = "Кнопка паники в уведомлении"
    override val guidePanicButtonDesc = "Третий, отдельный способ экстренного удаления (помимо пароля под принуждением и кнопок громкости) — постоянное уведомление с кнопкой «Удалить всё», видной сразу, без разворачивания, в том числе на заблокированном экране. Всё равно требует хотя бы одного касания экрана — кнопки громкости остаются единственным способом сработать полностью вслепую, вообще не глядя на экран. Можно включить тот же фейковый экран вместо мгновенного закрытия приложения — настраивается отдельно."
    override val guideWipeLevelsTitle = "Уровни уничтожения (Hard / Nuclear)"
    override val guideWipeLevelsDesc = "Hard удаляет все ключи, файлы и данные приложения. Единственное исключение — если включён декой-режим: тогда Hard сохраняет минимальный профиль (имя и хеш пароля) в заново созданном зашифрованном хранилище, чтобы после удаления приложение могло узнать владельца и показать фейковый мессенджер. Без декой-режима не сохраняется ничего. Nuclear исключений не делает вообще: это системный вызов Android «Очистить данные», который стирает весь каталог приложения целиком, включая запись, которую мог бы оставить Hard — поэтому Nuclear и декой-режим несовместимы в принципе, после Nuclear приложение не отличит владельца от любого другого человека. Разные функции экстренного удаления используют разные уровни по умолчанию (например, «мёртвая рука» всегда бьёт максимально жёстко — Nuclear, ей компромисс с decoy-восстановлением не нужен). Подробный список того, что именно стирается, — в статье «Что именно удаляет вайп»."
    override val guideHideNotifTitle = "Скрывать текст в уведомлениях"
    override val guideHideNotifDesc = "Уведомление о новом сообщении показывает только «Новое сообщение» без имени отправителя и текста — если кто-то посмотрит на экран заблокированного телефона или уведомление увидят на умных часах/в шторке, содержимое переписки не раскроется. Сами сообщения по-прежнему приходят и сохраняются как обычно — скрывается только то, что показывается в уведомлении."
    override val guideHideIpCallsTitle = "Скрывать IP во время звонков"
    override val guideHideIpCallsDesc = "По умолчанию звонок пытается соединиться напрямую (P2P) для минимальной задержки — но для этого оба устройства обмениваются реальными IP-адресами напрямую друг с другом. С этой опцией звонок идёт только через relay-сервер: собеседник видит адрес сервера, а не ваш. Плата — более высокая задержка и нагрузка на relay, особенно на слабом канале.\n\nЭто скрывает IP от собеседника, но не от самого relay-сервера — он видит оба реальных адреса, так как пересылает трафик между вами. Включённый Tor эту часть не усиливает: он прикрывает только сигнальный канал (запрос на звонок), а сама медиа-часть идёт напрямую, в обход Tor."
    override val guideBiometricTitle = "Разблокировка по биометрии"
    override val guideBiometricDesc = "Отпечаток или лицо вместо пароля при входе — быстрее, но физически проще получить принудительно: заставить приложить палец или показать лицо проще, чем заставить назвать пароль, а в ряде юрисдикций принудительная биометрия юридически защищена слабее принудительного раскрытия пароля. Если в вашей модели угроз есть физическое или юридическое принуждение — оставьте только пароль; он остаётся рабочим способом входа даже при включённой биометрии."
    override val guideChangePasswordTitle = "Смена пароля"
    override val guideChangePasswordDesc = "Пароль защищает не только вход в приложение, но и шифрование всех ключей и переписки на диске (storage-encryption) — со сменой пароля это шифрование перешифровывается новым паролем, старый пароль перестаёт подходить. Меняйте пароль, если подозреваете, что его мог увидеть кто-то посторонний, или просто периодически как гигиену."
    override val guideDiagnosticsTitle = "Диагностика безопасности"
    override val guideDiagnosticsDesc = "Набор живых проверок устройства и приложения: root/tamper-детекция, целостность хранилища ключей, состояние TLS-пиннинга и другие сигналы компрометации — каждая проверка возвращает pass/fail с пояснением. Здесь же живут режим паранои (постоянный мониторинг слежки) и разовое IDS-сканирование на аномалии — если что-то не проходит проверку, стоит разобраться, прежде чем продолжать переписку с этого устройства."
    override val guideServiceNotifTitle = "Значок фонового сервиса"
    override val guideServiceNotifDesc = "Android требует постоянное уведомление, пока фоновый сервис Subrosa поддерживает соединение и принимает сообщения, — само уведомление убрать нельзя. Эта настройка скрывает только его значок из строки состояния: уведомление становится беззвучным и уходит в свёрнутый раздел «Тихие уведомления» шторки, не привлекая внимания на первый взгляд."
    override val guideWipeOnBreachTitle = "Wipe при взломе"
    override val guideWipeOnBreachDesc = "Если система обнаружения вторжений (IDS) фиксирует критическую угрозу — например, срабатывание режима паранои или взлом honey-токена — приложение автоматически уничтожает данные без дополнительного подтверждения, тем же уровнем (Hard или Nuclear), который вы выбрали заранее. Это последняя линия защиты на случай, если у вас физически не будет возможности нажать кнопку паники самостоятельно."
    override val guideCalcDisguiseTitle = "Маскировка под калькулятор"
    override val guideCalcDisguiseDesc = "Меняет иконку и название приложения на «Калькулятор» — при беглом осмотре телефона мессенджер не бросается в глаза среди других приложений. Открывается вводом заданного вами числового выражения, результат которого равен вашему секретному коду; обычный калькулятор при этом продолжает работать как обычно для любых других вычислений."
    override val guideArchiveTitle = "Чтение бэкапа без восстановления"
    override val guideArchiveDesc = "Открывает файл бэкапа только для чтения: расшифровка идёт локально, в памяти, сервер для этого не нужен — переписку можно прочитать, даже если сервер выключен навсегда. Этот режим намеренно умеет меньше, чем импорт: он не записывает ничего на устройство, не затрагивает текущую identity и не восстанавливает ключи из файла, поэтому открытие архива не даёт возможности отправлять сообщения от того аккаунта. Нужен только пароль бэкапа; TOTP-код не требуется, потому что ничего не восстанавливается. При сворачивании приложения расшифрованная копия сбрасывается. Вложения видны, только если бэкап делали с включённой опцией «Включить вложения»; иначе такие сообщения помечаются как недоступные. Фото открываются прямо в читалке, любое вложение можно сохранить в отдельный файл — это единственный способ что-то вынести с этого экрана, и он требует явного действия."
    override val guideWipeScopeTitle = "Что именно удаляет вайп"
    override val guideWipeScopeDesc = "Любой уровень экстренного удаления делает одно и то же, разница только в том, остаётся ли приложение живым. Удаляются: ключ шифрования хранилища (сначала перезаписывается в оперативной памяти, потом уничтожается), ключ личности, все ключи сессий и переписок, включая постквантовые, записи в защищённом хранилище Android (Keystore), все настройки, файлы, кэш, базы данных и вложения приложения. Декой-режим оставляет приложение запущенным, чтобы показать фейковый мессенджер вместо резкого закрытия, Nuclear отдаёт удаление самой системе Android. Чего вайп НЕ удаляет, и об этом важно знать заранее: файл бэкапа, который вы сами сохранили — он лежит вне приложения (в Загрузках, на карте, в облаке), и ни один уровень вайпа до него не дотянется, удалять его нужно самостоятельно. Также вайп не может удалить сообщения, которые уже доставлены на устройства ваших собеседников. Облачный бэкап Android для приложения отключён, поэтому восстановить данные через Google-аккаунт нельзя."
    override val guideAttachmentsBackupTitle = "Вложения в бэкапе"
    override val guideAttachmentsBackupDesc = "При экспорте можно включить опцию «Включить вложения» — тогда в файл попадут фото, видео, голосовые и документы, а не только текст. Включайте её, если бэкап нужен как настоящий архив: без неё сообщение с вложением восстановится как пустое, и прочитать документ из переписки потом будет невозможно. Цена: файл становится в десятки раз больше, и его пока не умеет читать настольный клиент — для переноса на компьютер делайте отдельный бэкап без вложений. Вложения внутри файла зашифрованы тем же паролем, что и переписка, и при восстановлении заново зашифровываются ключом нового устройства — то есть восстановленное вложение защищено ровно так же, как полученное обычным путём. Экспорт с вложениями доступен только через «В файлы»: отправка через другие приложения сделала бы вторую копию файла целиком."
}

val ruStrings = AppStrings("ru", ru1, ru2, ru3, ru4, ru5, ru6, ru7, ru8, ru9, ru10)

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
    override val loginBiometric = "Biometrics"
    override val loginWaitingBiometric = "Waiting for biometrics..."
    override val loginNotMe = "Not me — reset"
    override val loginNotMeTitle = "Reset everything?"
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
    override val registerErrorPasswordLength = "Password must be at least 8 characters"
    override val registerErrorPasswordCommon = "This password is too predictable (e.g. a simple digit sequence) — choose a less obvious one"
    override val registerErrorPasswordMatch = "Passwords don't match"
    override val registerButton = "Create account"
    override val registerImportBackup = "Restore from backup"
    override val registerImportTitle = "Restore from backup"
    override val registerImportHint = "File selected. Enter the password it was encrypted with"
    override val registerImportPassword = "Backup password"
    override val registerImportChooseFile = "Import"
    override val registerImportTotpHint = "If the backup is protected by TOTP — enter the secret and current code from your authenticator app, or one of the recovery codes below. Not required if TOTP wasn't enabled on the original device."
    override val chatsNoMessages = "No messages"
    override val chatsNoPosts = "No posts"
    override val chatsEmpty = "No chats"
    override val chatsEmptyHint = "Tap + to add a contact\nor create a group"
    override val chatsSearchPlaceholder = "Search all chats..."
    override val chatsSearchNoResults = "No results"
    override val chatsDeleteTitle = "Delete chat?"
    override val chatsDeleteText: (String) -> String = { "Delete conversation with $it? All messages and media will be permanently removed." }
    override val chatsAddContact = "Add contact"
    override val chatsInviteCode = "Invite code"
    override val chatsContactAdded: (String) -> String = { "Contact added: $it" }
    override val chatsCreateTitle = "Create"
    override val chatsCreateContact = "Add contact"
    override val chatsCreateGroup = "Create group"
    override val chatsSubscribeChannel = "Subscribe to channel"
    override val chatsCreateChannel = "Create channel"
    override val chatsChannelSubscribeTitle = "Subscribe to channel"
    override val chatsChannelLinkLabel = "Link beacon://channel?..."
    override val chatsChannelCreateTitle = "Create channel"
    override val chatsChannelNameLabel = "Channel name"
    override val chatsChannelDescLabel = "Description (optional)"
    override val chatsChannelFillFields = "Enter a channel name"
    override val chatsChannelBadLink = "Invalid link"
    override val chatsChannelBadge = "channel"
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
    override val contactInfoNotifications = "Notifications"
    override val muteSoundOnly = "Mute notification sound"
    override val contactInfoSearch = "Search in chat"
}

private val en3 = object : IStr3 {
    override val profileTitle = "Profile"
    override val profileFingerprint = "Your fingerprint"
    override val profileFingerprintHint = "Ask your contact to compare these emojis with chats's verification screen"
    override val profileInviteCode = "Your Invite code"
    override val profileShareCode = "Share code"
    override val profileHideQr = "Hide QR"
    override val profileShowQr = "Show QR code"
    override val profileScanQr = "Scan QR"
    override val profileQrHint = "Let your contact scan this code"
    override val profileCodeCopied = "code copied"
    override val profileSendHint = "Send this code to a friend so they can add you as a contact"
    override val profileServers = "Servers"
    override val profileBackup = "Backup"
    override val profileSectionSecurity = "Security"
    override val profileSectionGeneral  = "General"
    override val profileSecurityGuide = "Security guide"
    override val profileSecurityGuideSub = "What each security feature actually does"
    override val profileConfigureBtn = "Configure"
    override val profileInviteCodeOneTimeWarning = "This code is fully one-time: it's valid until activation, or until you tap Copy, Share, or Show QR again."
    override val profileHideNotif = "Hide text in notifications"
    override val profileHideNotifSub = "Show only \"New message\""
    override val profileHideIpCalls = "Hide IP during calls"
    override val profileHideIpCallsSub = "Call only through the relay server"
    override val profileHideIpCallsFailedNoTurn = "Couldn't start the call: the relay server is unavailable, and this mode doesn't allow a direct connection"
    override val profileAutoLock = "Auto-lock"
    override val profileAutoLockAfter: (String) -> String = { "Lock after: $it" }
    override val profileBiometricTitle = "Biometric unlock"
    override val profileBiometricSub = "Fingerprint/face instead of a password at login"
    override val profileBiometricWarningTitle = "Before you enable this"
    override val profileBiometricWarningText = "It's physically easier to force someone to press a finger or show their face than to force them to reveal a password — and in several jurisdictions, compelled biometric unlock has weaker legal protection than compelled password disclosure. If physical or legal coercion is part of your threat model, keep password-only. Your password remains a valid way to unlock even after enabling biometrics."
    override val profileBiometricWarningConfirm = "I understand, enable"
    override val profileChangePassword = "Change password"
    override val changePasswordTitle = "Change Password"
    override val changePasswordDesc = "This password protects everything encrypted locally on the device. Changing it doesn't touch already-saved data — it only re-wraps the access key to it under the new password."
    override val changePasswordCurrent = "Current password"
    override val changePasswordNew = "New password"
    override val changePasswordRepeat = "Repeat new password"
    override val changePasswordSubmit = "Change password"
    override val changePasswordSuccess = "Password changed"
    override val changePasswordErrCurrentWrong = "Current password is incorrect"
    override val changePasswordErrSameAsOld = "New password is the same as the old one — choose a different one"
    override val profileLockOff = "Off"
    override val profileLock1min = "1 min"
    override val profileLock5min = "5 min"
    override val profileLock15min = "15 min"
    override val profileLock30min = "30 min"
    override val profileEmergencyBtn = "Emergency button"
    override val profileEmergencyBtnSub = "5 volume-down button presses"
    override val profileNotMe = "!Not me!"
    override val profileNotMeTitle = "!Not me!"
    override val profileNotMeText = "Are you sure? This will delete ALL data, chats, keys and reset the app!"
    override val profileNotMeConfirm = "Yes, reset everything"
    override val profileSourceCode = "Source code (AGPL-3.0)"
    override val profileCompromised = "I've been compromised"
    override val profileCompromisedTitle = "Identity reset"
    override val profileCompromisedText = "Your current key, contacts, chats and sessions will be destroyed permanently. You'll get a new key and can register again — contacts will need to exchange a new invite code with you. Your password and device security settings (TOTP, panic, auto-wipe) are not affected."
    override val profileCompromisedConfirm = "Yes, reset identity"
    override val identityRevokedError = "This account was revoked (after \"I've been compromised\"). This key can no longer log in — register again."
    override val profileDiagnostics = "Security diagnostics"
    override val profileTorEnabled = "Use TOR"
    override val profileTorEnabledSub = "Route through Orbot instead of a direct connection. Starting Orbot can take up to 10-15 seconds"
    override val profileBatteryUnrestricted = "Ignore battery optimization"
    override val profileBatteryUnrestrictedSub = "Helps the background connection stay reliable"
    override val batteryPromptTitle = "Don't let the shell choke your connection"
    override val batteryPromptText = "On many phones (especially MIUI and similar), backgrounding the app silently throttles the background connection — messages and receipts stop arriving with no error at all. Allow the app to ignore battery optimization so the connection stays reliable even in the background. You can also turn this on later from Profile."
    override val batteryPromptAllow = "Allow"
    override val batteryPromptSkip = "Skip"
    override val profileServiceNotifVisible = "Show service icon"
    override val profileServiceNotifVisibleSub = "Hide the service icon from the status bar"
    override val profilePanicTitle = "Panic Password"
    override val profilePanicSub = "Password for emergency data deletion"
    override val profilePanicSetStatus = "Set"
    override val profilePanicEnterLabel = "Enter password for emergency deletion:"
    override val profilePanicInstruction = "How it works:\n① In an emergency, enter this password once — all data will be wiped.\n② After restart, log in with your regular password — fake chats will appear."
    override val profilePanicFieldLabel = "Panic password"
    override val profilePanicErrSameAsLogin = "The panic password must differ from your normal login password — otherwise every login would wipe your data"
    override val changePasswordErrSameAsPanic = "That matches your panic password — choose a different one"
    override val profileLanguageToggle = "Русский"
    override val profileThemeLabel = "Theme"
    override val profileThemeNavy = "Emerald"
    override val profileThemeDark = "Dark"
    override val profileThemeLight = "Light"
    override val profileInvalidCodeFormat = "Invalid code format"
    override val profileInvalidOrExpiredCode = "Invalid or expired code"
    override val profileCameraPermReq = "Camera permission required"
    override val profileQrScanPrompt = "Point the camera at the QR code"
    override val backupTitle = "Backup"
    override val backupSubtitle = "Create a backup of servers, contacts and message history"
    override val backupSecurityTitle = "Backup security"
    override val backupSecurityText = "The backup contains all keys and messages. It's password-protected, and importing also requires the TOTP secret and current code — the file and password alone aren't enough to restore the identity. But if an attacker gets the file, password, and TOTP secret together, your account will be compromised — treat the backup seriously."
    override val backupSecurityTips = "• Use a strong password (12+ characters)\n• Don't store the file, password, and TOTP secret in the same place\n• Store on an encrypted drive or in a password manager"
    override val backupPassword = "Password"
    override val backupRepeatPassword = "Repeat password"
    override val backupExport = "Export backup"
    override val backupImport = "Import backup"
    override val backupImportWipeTitle = "Warning"
    override val backupImportWipeText = "Importing will completely replace this device's data with the new identity from the backup: current contacts, messages and groups will be permanently deleted. This is not a rollback to old chat history - old data won't survive in any form. Some hiccups are possible during the first sync after import. Continue?"
    override val backupSaveChooser = "Save backup"
    override val backupCreated = "Backup created"
    override val backupErrEnterPassword = "Enter password"
    override val backupErrPasswordMatch = "Passwords don't match"
    override val backupErrPasswordLength = "Password must be at least 8 characters"
    override val backupErrTotpRequired = "Enable TOTP protection first (Profile → Two-factor protection) — without it, the backup file and password alone give full access to the identity, there's no second factor"
    override val backupErrEnterForDecrypt = "Enter password for decryption"
    override val archiveTitle = "Read a backup"
    override val archiveSubtitle = "Open a backup file read-only — no restore, no server needed"
    override val archiveNoticeTitle = "What this mode does"
    override val archiveNoticeText = "The file is decrypted in memory and shown as text. Nothing is written to the device, your current identity is untouched, and no keys are restored from the file — you still can't send messages as that account. No server is involved: decryption is entirely local. Leaving this screen or backgrounding the app discards the decrypted copy, so the password has to be entered again."
    override val archivePick = "Choose a backup file"
    override val archiveOpen = "Open read-only"
    override val archiveOpening = "Decrypting…"
    override val archiveBadPassword = "Wrong password, or the file is damaged"
    override val archiveUnreadable: (String) -> String = { d -> "The file decrypted, but its contents couldn't be read: $d" }
    override val archiveSummary: (Int, Int) -> String = { threads, messages -> "$threads conversations · $messages messages" }
    override val archiveCreatedAt: (String) -> String = { d -> "Backup from $d" }
    override val archiveEmpty = "This backup contains no messages"
    override val archiveAttachmentMissing = "[attachment not included in the backup]"
    override val archiveNoAttachmentsNote = "Attachments are available only if \"Include attachments\" was enabled during export. Backups made without it store text only, and messages carrying a photo, video, voice note or file will be marked as unavailable."
    override val archiveClose = "Close and clear"
    override val archiveGroupTag = "group"
    override val archiveNotAvailableInDecoy = "Unavailable"
    override val archiveFileTooLarge = "File is too large to read in memory"
    override val backupToFiles = "To files"
    override val backupIncludeAttachments = "Include attachments"
    override val backupIncludeAttachmentsOn = "Photos, videos, voice notes and files will be in the backup. The file will be much larger, and the desktop client cannot read it (new format)."
    override val backupIncludeAttachmentsOff = "Message text only, as before. This file can also be read by the desktop client."
    override val backupShareDisabledWithAttachments = "With attachments, only \"To files\" is available: sharing through another app makes a second copy of the file, which isn't acceptable at this size."
    override val backupCreatedWithAttachments: (Int, String, Int) -> String = { count, size, missing ->
        val base = "Backup created. Attachments: $count ($size)."
        if (missing > 0) "$base Couldn't read $missing — those files were already gone from the device." else base
    }
    override val backupExportFailed: (String) -> String = { d ->
        "Export did not finish: $d. Do NOT use the file that was created — it is incomplete. Delete it and try again."
    }
    override val archiveAttachmentImage = "Photo"
    override val archiveAttachmentVoice = "Voice message"
    override val archiveAttachmentVideo = "Video"
    override val archiveAttachmentFile = "File"
    override val archiveAttachmentOpen = "Show"
    override val archiveAttachmentSave = "Save"
    override val archiveAttachmentSaved = "Saved"
    override val archiveAttachmentUnavailable = "Attachment not available in this file"
    override val archiveAttachmentLoading = "Extracting…"
}

private val en4 = object : IStr4 {
    override val serversTitle = "Servers"
    override val serversAdd = "Add"
    override val serversSwitch = "Switch server"
    override val serversSwitching = "Reconnecting to next server..."
    override val serversDefault: (Int) -> String = { "Server $it" }
    override val serversConnected = "Connected"
    override val serversConnecting = "Connecting..."
    override val serversAddTitle = "Add server"
    override val serversName = "Name"
    override val serversHost = "Host (IP or domain)"
    override val serversScanQrButton = "Scan QR"
    override val serversUploadQrButton = "Upload QR file"
    override val serversScanQrPrompt = "Point the camera at the server's QR code"
    override val serversQrInvalid = "This doesn't look like a Subrosa server code"
    override val serversQrNotFound = "No QR code found in the photo"
    override val serversAccessCodeRequired = "This server requires an access code to register — ask the operator for a QR code or link"
    override val serversRegistrationFull = "This server has reached its account limit and isn't accepting new registrations right now"
    override val serversDeviceAuthFailed = "Couldn't verify this device. Try reconnecting or contact support"
    override val serversPort = "Port"
    override val groupInfoTitle = "Group info"
    override val groupInfoNotFound = "Group not found"
    override val groupInfoMembersCount: (Int) -> String = { "$it members" }
    override val groupInfoDescription = "Description"
    override val groupInfoAddDescription = "Tap to add a description"
    override val groupInfoNoDescription = "No description"
    override val groupInfoMembersSection = "Members"
    override val groupInfoCreator = "Creator"
    override val groupInfoAdmin = "Admin"
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
    override val groupInfoChangeAvatar = "change"
    override val createGroupTitle = "Create group"
    override val createGroupTapAvatar = "Tap to choose avatar"
    override val createGroupNameLabel = "Group name"
    override val createGroupMembersTitle: (Int) -> String = { "Members ($it)" }
    override val createGroupButton = "Create group"
    override val createGroupAvatarTitle = "Choose group avatar"
}

private val en5 = object : IStr5 {
    override val channelDefault = "Channel"
    override val channelCopyLink = "Link"
    override val channelUnsubscribe = "Unsubscribe"
    override val channelPostPlaceholder = "Write to channel..."
    override val channelLinkCopied = "Link copied"
    override val channelLoadImageError = "Failed to load image"
    override val channelWriteFirst = "Write the first post below"
    override val channelSubscribeConfirm = "Subscribe to this channel?"
    override val channelSubscribeBtn = "Subscribe"
    override val channelMute = "Mute notifications"
    override val channelUnmute = "Unmute notifications"
    override val channelSubscribers: (Int) -> String = { "$it subscribers" }
    override val channelSearchPlaceholder = "Search posts..."
    override val channelPinPost = "Pin"
    override val channelUnpinPost = "Unpin"
    override val channelPinned = "Pinned"
    override val channelDeletePost = "Delete post"
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
    override val incomingNoAudioPermission = "Can't accept the call without microphone access"
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
    override val diagTitle = "Security diagnostics"
    override val diagInitText = "Press the button to run diagnostics..."
    override val diagRunning = "Running..."
    override val diagBasic = "Basic diagnostics"
    override val diagStress = "Stress tests (attempting to break the protections)"
    override val diagAdvanced = "Advanced tests (sessions + groups)"
}

private val en6 = object : IStr6 {
    override val chatSearchPlaceholder = "Search in chat..."
    override val chatOnline = "online"
    override val chatOffline = "offline"
    override val chatKeyWarningTitle = "WARNING!"
    override val chatKeyWarningText = "The contact's encryption key has changed!\n\nThis may indicate:\n• App reinstallation\n• New device\n• MITM attack\n\nContact this person through another channel!"
    override val chatKeyWarningConfirm = "I verified, it's OK"
    override val chatKeyWarningLeave = "Leave chat"
    override val chatRevokedWarningTitle = "WARNING!"
    override val chatRevokedWarningText = "This contact's identity was revoked by its owner (via \"I've been compromised\" or Dead Man's Switch) — this may mean their key was compromised.\n\nContact them through another channel and ask for a new invite code."
    override val chatRevokedWarningConfirm = "Got it"
    override val chatSendBlockedTitle = "This contact isn't receiving messages"
    override val chatSendBlockedText = "10 messages in a row went out with no delivery confirmation at all. This contact appears to have been offline for a while.\n\nSending is paused until they come back online. Messages you've already sent haven't gone anywhere — they'll go through automatically once the connection recovers."
    override val chatSendBlockedConfirm = "Got it"
    override val chatTyping = "typing..."
    override val chatMenu = "Menu"
    override val contactInfoTitle = "Profile"
    override val chatAudioCall = "Audio call"
    override val chatVideoCall = "Video call"
    override val chatVerifyAction = "Verify"
    override val chatRestoreConnection = "Restore connection"
    override val chatRestoreConnectionStarted = "Restore request sent — ask your contact to press the same button"
    override val chatRestoreConnectionCooldown = { min: Int -> "Please wait ${min} more min before trying again" }
    override val chatDirectConnection = "Direct connection — no Tor. Install Orbot for anonymity."
    override val chatContextReply = "↩Reply"
    override val chatContextCopy = "Copy"
    override val chatContextReaction = "Reaction"
    override val chatContextEdit = "Edit"
    override val chatContextDeleteOwn = "Delete for me"
    override val chatContextDeleteAll = "Delete for everyone"
    override val chatContextResend = "Send again"
    override val chatPickReaction = "Pick a reaction"
    override val chatDisappearTitle = "Disappearing messages"
    override val chatDisappearOff = "Off"
    override val chatDisappear1h = "1 hour"
    override val chatDisappear24h = "24 hours"
    override val chatDisappear7d = "7 days"
    override val chatDisappear1hShort = " · ⏱1h"
    override val chatDisappear24hShort = " · ⏱1d"
    override val chatDisappear7dShort = " · ⏱7d"
    override val chatReplyPreview = "Replying to"
    override val chatAutoDeleteMenu = "Auto-delete (this device only)"
    override val chatAutoDeleteTitle = "Auto-delete messages"
    override val chatAutoDeleteDescription = "Messages older than the selected time will be deleted only from this device. The other party and their copy of the conversation are not affected — this is not the same as \"Disappearing messages\"."
    override val chatDisappearSyncedNote = "Synced with the other party — deletes on both sides"
    override val chatEditing = "Editing"
    override val chatAttach = "Attach"
    override val chatAttachPhoto = "Photo"
    override val chatAttachMedia = "Media"
    override val chatAttachFile = "File"
    override val chatGeo = "Location"
    override val chatGeoPermission = "Grant location access"
    override val chatGeoFail = "Could not determine location"
    override val chatGeoTap = "Location (tap to view)"
    override val chatGeoDisabled = "Enable location in phone settings"
    override val chatGeoConfirmTitle = "Send your location?"
    override val chatGeoConfirmText = "The other person will see your current location on the map."
    override val chatEditHint = "Edit message..."
    override val chatInputHint = "Message..."
    override val chatEstablishingChannel = "Establishing secure channel..."
    override val chatPhotoTooBig = "Photo is too large to process"
    override val chatFileTooBig = "File too large (max 20MB)"
    override val chatMediaOffline = "No connection — media not sent"
    override val chatFileSending: (String, Int) -> String = { name, kb -> "Sending: $name (${kb}KB)" }
    override val chatVerifyTitle = "Contact verification"
    override val chatVerifyFingerprintLabel = "Contact fingerprint:"
    override val chatVerifyHint = "Ask your contact to read their emoji from their profile — over a different channel (in person, by phone, another messenger), not through this chat: if this channel is compromised, comparing within it proves nothing."
    override val chatVerifyKeyError = "Key read error"
    override val chatVerifyUnknown = "Unknown"
    override val chatReplyLabel = "Reply"
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
    override val verifyEmojiHint: (String) -> String = { "Ask $it to read their emojis from their profile — over a different channel (in person, by phone, another messenger), not through this chat.\nIf they match — the connection is secure. Comparing through this chat itself proves nothing if this channel is compromised." }
    override val verifyHexLabel = "Key fingerprint (hex):"
    override val verifyHint = "For maximum security, compare the fingerprint in person or via a voice call."
    override val verifyMarkVerified = "Mark as verified"
    override val verifyAlreadyVerified = "Key verified"
    override val chatLoadEarlier = "↑ Load earlier"
    override val chatSavePhoto = "Save photo"
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
    override val rootDangerTitle = "Root detected"
    override val rootDangerText = "Root access detected on this device. Subrosa's encryption may be compromised — keys and messages may be accessible to other apps."
    override val rootDangerReasons: (String) -> String = { "Indicators:\n$it" }
    override val rootDangerRecommend = "It is recommended to use a device without root."
    override val rootDangerContinue = "Continue anyway"
    override val rootWarningTitle = "Suspicious device"
    override val rootWarningText = "A suspicious indicator was detected. The device may be modified."
    override val rootWarningConfirm = "Got it"
    override val rootReasonText: (RootDetector.RootReason) -> String = {
        when (it) {
            RootDetector.RootReason.ROOT_BINARY -> "su binary found"
            RootDetector.RootReason.TEST_KEYS_BUILD -> "test-keys build"
            RootDetector.RootReason.ROOT_PACKAGE -> "Root management app installed"
            RootDetector.RootReason.WHICH_SU -> "'which su' returned a result"
            RootDetector.RootReason.SYSTEM_WRITABLE -> "/system is writable"
            RootDetector.RootReason.DEBUGGER_CONNECTED -> "Debugger attached (adb/Android Studio)"
            RootDetector.RootReason.TRACER_PID -> "Process is being traced (GDB/strace/LLDB)"
            RootDetector.RootReason.FRIDA_PORT -> "Frida server is active"
            RootDetector.RootReason.FRIDA_MAPS -> "Frida agent found in process memory"
            RootDetector.RootReason.FRIDA_PROCESS -> "Frida process detected"
            RootDetector.RootReason.XPOSED_BRIDGE -> "Xposed/LSPosed active at runtime"
            RootDetector.RootReason.XPOSED_PACKAGE -> "Xposed/LSPosed manager installed"
            RootDetector.RootReason.XPOSED_MAPS -> "XposedBridge.jar found in process memory"
            RootDetector.RootReason.EMULATOR_HIGH_CONFIDENCE -> "This looks like an emulator"
            RootDetector.RootReason.EMULATOR_POSSIBLE -> "This might be an emulator"
        }
    }
    override val lockTitle = "App locked"
    override val lockUnlock = "Unlock"
    override val lockBiometricTitle = "Unlock Subrosa"
    override val lockBiometricSubtitle = "Confirm your identity"
    override val lockBiometricCancel = "Cancel"
    override val noCameraPermissionVoiceOnly = "Camera permission denied — voice call"
    override val torStatusStarting = "Starting..."
    override val emergencyInfoTitle = "Emergency button"
    override val emergencyInfoOpenSettings = "Accessibility"
    override val emergencyInfoOpenAppSettings = "App settings"
    override val emergencyInfoWarning = "Press VOLUME DOWN 5 times within 3 seconds — " +
        "the app will immediately delete all keys and messages.\nWithout confirmation!"
    override val emergencyInfoStepLabel: (Int) -> String = { n -> "Step $n" }
    override val emergencyInfoStep1Desc = "Open app settings, then ⋮ (top right) → \"Allow restricted settings\""
    override val emergencyInfoStep2Desc = "Accessibility → Subrosa Emergency Wipe → enable"
    override val emergencyInfoLegacyDesc = "Accessibility → Subrosa Emergency Wipe → enable"
    override val emergencyInfoDone = "Service already enabled"
    override val spyAppsAccessibilitySection = "Accessibility services:\n"
    override val spyAppsAdminsSection = "Device administrators:\n"
    override val spyAppsOverlaySection = "Draw over other apps:\n"
    override val spyAppsTitle = "Suspicious apps"
    override val spyAppsMessage: (String) -> String = { "Apps found that may intercept screen or touches:\n\n$it\n\nWe recommend revoking their rights or uninstalling them.\nTouches over Subrosa are blocked automatically." }
    override val spyAppsSettings = "Accessibility settings"
    override val groupCallPeerName = "Group"
    override val systemSender = "System"
    override val groupMemberLeft: (String) -> String = { "$it left the group" }
    override val groupKeyUpdated = "Encryption key updated"
    override val groupMemberJoined: (String) -> String = { "$it joined the group" }
    override val channelCreatedToast: (String) -> String = { "Channel «$it» created!" }
    override val channelFallbackName = "Channel"
    override val channelNoConnection = "No server connection"
    override val recipientOffline = "Recipient is offline"
    override val notifChannelDesc = "Emergency data deletion"
    override val notifSessionTitle = "Session ended"
    override val notifSessionText = "Your account was opened on another device"
    override val notifNewMessage = "New message"
    override val notifTapToRead = "Tap to read"
    override val notifMessageCount: (Int) -> String = { "$it messages" }
    override val notifGroupFallback = "Group"
    override val notifNewGroupMessage = "New group message"
    override val notifMissedVideoCall = "Missed video call"
    override val notifMissedCall = "Missed call"
    override val notifFromCaller: (String) -> String = { "From: $it" }
    override val notifChannelStuckTitle = "Can't establish connection"
    override val notifChannelStuckText: (String) -> String = { "The first message to $it still hasn't been delivered. Try again later or exchange invite codes once more." }
    override val notifEmergencyText = "Tap for emergency deletion"
    override val notifEmergencyAction = "DELETE ALL"
    override val tamperTitle = "App integrity violated"
    override val tamperText = "The APK signature does not match the original. The app may have been repackaged or modified by a third party. It is not safe to use — encryption keys may be compromised."
    override val tamperClose = "Close"
    override val paranoidModeTitle = "Paranoia Mode"
    override val paranoidModeSub = "Root/Frida → immediate exit, block external intents, clear logs"
    override val paranoidModeConfirmTitle = "Enable Paranoia Mode?"
    override val paranoidModeConfirmText = "Once enabled, the toggle will disappear — the mode cannot be disabled without a full app data reset.\n\nIf Root, Frida, or an emulator is detected, the app will close immediately without warning.\n\nEnable only if you are sure."
    override val paranoidModeConfirmBtn = "Enable"
    override val paranoidModeActive = "Active"
    override val idsTitle = "IDS — Intrusion Detector"
    override val idsScanBtn = "Scan"
    override val idsClean = "No threats detected"
    override val idsThreatFound = "Threats detected"
    override val idsHoneyTampered = "Honey file tampered"
    override val alertUrlLabel = "Alert URL (optional)"
    override val alertUrlHint = "https://your-server/alert"
    override val alertUrlSave = "Save"
    override val alertUrlInvalid = "Needs an HTTPS address (http:// is blocked by the cleartext-traffic policy)"
    override val alertUrlTestBtn = "Test"
    override val alertUrlTestOk = "Delivered"
    override val alertUrlTestFail = "Not delivered — check the address and network"
}

private val en8 = object : IStr8 {
    override val groupChatNoMessages = "No messages"
    override val groupChatMessageHint = "Message..."
    override val groupChatEditHint = "Edit message..."
    override val groupChatInfo = "Info"
    override val groupChatReply = "Reply"
    override val groupChatCopy = "Copy"
    override val groupChatReactionLabel = "Reaction"
    override val groupChatEditAction = "Edit"
    override val groupChatDeleteOwn = "Delete for me"
    override val groupChatDeleteAll = "Delete for everyone"
    override val groupChatPickReaction = "Pick a reaction"
    override val groupChatEditing = "Editing"
    override val groupChatAttach = "Attach"
    override val groupChatAttachPhoto = "Photo"
    override val groupChatAttachFile = "File"
    override val groupChatGeo = "Location"
    override val groupChatGeoPermission = "Grant location access"
    override val groupChatGeoFail = "Could not determine location"
}

private val en9 = object : IStr9 {
    override val wipeSettingsTitle = "Data Destruction"
    override val dmsTitle = "Dead Man's Switch"
    override val dmsSubtitle = "Destroy data if safety check-in is missed"
    override val dmsCheckinBtn = "I'm safe"
    override val dmsNotifTitle = "Dead Man's Switch"
    override val dmsNotifText = "Tap \"I'm safe\" or data will be destroyed"
    override val dmsNotifGraceText = "Tap \"I'm safe\" or data will be destroyed in 15 minutes"
    override val dmsIntervalLabel = "Check-in interval"
    override val dmsIntervalHours = "h"
    override val dmsIntervalMinutes = "min"
    override val dmsEnabledLabel = "Enable Dead Man's Switch"
    override val dmsRemainingText: (Long, Long) -> String = { h, m -> "Remaining: ${h}h ${m}m" }
    override val timeoutWipeTitle = "Password timeout"
    override val timeoutWipeSubtitle = "Destroy data if the app has not been unlocked for the specified time"
    override val timeoutWipeThresholdLabel = "Destroy if not opened for more than:"
    override val wipeOnBreachTitle = "Wipe on breach"
    override val wipeOnBreachSubtitle = "Destroy data when a critical IDS threat is detected"
    override val wipeLevelLabel = "Destruction level"
    override val wipeLevelHard = "Hard (HARD)"
    override val wipeLevelNuclear = "Nuclear (NUCLEAR)"
    override val wipeHardDesc = "Deletes all keys, files and app data — but deliberately keeps a hidden password hash so the app can still recognize its owner afterward (needed for the decoy-password scenario)"
    override val wipeNuclearDesc = "Same as Hard, but with no exceptions — the Android system's own \"clear data\" call, guaranteed to erase absolutely everything, including the one record Hard deliberately keeps. Recovering access via the decoy password won't be possible after this"
    override val wipeSettingsWarning = "These settings are irreversible. Once triggered, all data will be permanently destroyed with no recovery possible."
    override val panicButtonLabel = "Panic button on lock screen"
    override val panicButtonSubtitle = "Shows a notification with a wipe button accessible without unlocking. A single tap is enough — it fires immediately, with no confirmation."
    override val panicButtonDecoyLabel = "Decoy mode after wipe"
    override val panicButtonDecoySubtitle = "After the notification panic button fires, or after 5 volume-down presses (Emergency button) — show a fake chat screen instead of closing immediately. One shared setting for both."
    override val panicNotifTitle = "Subrosa — Emergency Wipe"
    override val panicNotifText = "Tap DESTROY to immediately erase all data"
    override val panicNotifButton = "DESTROY"
    override val calcDisguiseLabel = "Calculator disguise"
    override val calcDisguiseSubtitle = "Replaces the icon and name with «Calculator». Set your own unlock code below — any expression whose result equals that number opens the messenger"
    override val calcUnlockCodeLabel = "Unlock code (result number)"
    override val calcUnlockCodeHint = "e.g. 42"
    override val calcUnlockCodeSave = "Save & enable"
    override val profileTotp = "Two-factor protection (TOTP)"
    override val totpTitle = "Two-factor protection (TOTP)"
    override val totpDescription = "An extra layer of account protection: a code is required both when restoring a backup on a new device and when this fingerprint tries to log in from a new device (device_id) the server hasn't seen before — closing the gap where someone with a stolen backup or key could just register as you. Save the secret separately (e.g. in KeePass) — it isn't stored inside the backup itself, so the backup file and its password alone won't be enough to hijack the identity. Switched authenticators or suspect the secret leaked? You can issue a new one right here (needs your current code)."
    override val totpStatusEnabled = "Enabled"
    override val totpStatusDisabled = "Disabled"
    override val totpSetupButton = "Set up"
    override val totpDisableButton = "Change secret"
    override val totpDisableHint = "Needs your current authenticator code. Setting up a new secret opens right after you confirm — the unprotected window is a couple of taps, not a state you're left in."
    override val totpSecretLabel = "Secret (save it separately, not next to the backup)"
    override val totpCodeLabel = "Code from your authenticator app"
    override val totpConfirmButton = "Confirm and enable"
    override val totpErrInvalidCode = "Invalid code"
    override val totpEnabledSuccess = "TOTP protection enabled"
    override val serverTotpErrNotConnected = "No connection to the server"
    override val totpConfirmingWithServer = "Confirming with the server — please wait..."
    override val totpErrTimeout = "The server didn't respond in time — please try again"
    override val totpCopySecret = "Copy"
    override val totpMandatoryTitle = "Account protection"
    override val totpMandatoryIntro = "Before you continue — set up TOTP protection. This step is required: without it, the server can't tell you apart from someone who steals your key."
    override val totpRecoveryCodesTitle = "Recovery codes — save them now"
    override val totpRecoveryCodesHint = "Each code works once, if you lose access to your authenticator app. These codes won't be shown again — save them separately (e.g. in KeePass), not next to the backup."
    override val totpRecoveryCodesConfirm = "I saved these codes somewhere safe"
    override val totpRecoveryCodesContinue = "Continue"
    override val totpRecoveryCodesDone = "Done"
    override val totpRecoveryPrompt = "This device needs a code to log into an account protected by TOTP. This device has no authenticator app for it — enter one of the recovery codes you got when you enabled protection."
    override val totpRecoveryFieldLabel = "Recovery code"
    override val totpRecoverySubmit = "Submit"
    override val totpRecoveryErr = "Code not accepted — check it and try again"
    override val totpReenrollPrompt = "This account already has TOTP protection set up from another device. If you just logged in with a recovery code, enter one more recovery code below to replace it with this new one."
    override val backupTotpSecretLabel = "TOTP secret (if it was enabled on the source device)"
    override val backupTotpCodeLabel = "Current TOTP code"
    override val backupTotpRecoveryOr = "— or, if the secret is lost —"
    override val backupTotpRecoveryLabel = "Recovery code (one of the ones shown when TOTP was enabled)"
}

private val en10 = object : IStr10 {
    override val guideTitle = "Security guide"
    override val guideInviteTitle = "Invite code"
    override val guideInviteDesc = "A way to anonymously meet someone without the server ever seeing the sender-recipient pair. The code is single-use: once someone scans it, the tag embedded inside it dies and stops working. Only one such tag is ever active on your device — tapping Copy/Share/QR again also replaces it, even if the previous recipient hasn't connected yet, silently breaking their code. Adding several people — wait for the current one to connect before generating a code for the next."
    override val guideKeyVerifyTitle = "Key verification"
    override val guideKeyVerifyDesc = "A sequence of 5 emoji derived from a hash of your contact's public key. Compare it with them in person or over another channel — if it matches, you're really talking to them, not someone who swapped in a different key (man-in-the-middle attack)."
    override val guideTotpTitle = "Two-factor protection (TOTP)"
    override val guideTotpDesc = "A mandatory code from an authenticator app (like Google Authenticator), without which this account can't be registered on a new device even if the keys and password are stolen. Save the recovery codes shown during setup somewhere separate from the phone. A recovery code gets you into a new device if you lose the authenticator, but it doesn't turn protection off by itself — set TOTP up again right away on the device you just logged into (that takes one more recovery code)."
    override val guidePanicTitle = "Panic password"
    override val guidePanicDesc = "A second login password, different from your real one. Entering it instead of the real password shows a convincing fake messenger full of made-up chats, while your real keys and messages are irreversibly wiped in the background — use it if you're being forced to unlock your phone. Two details it relies on: the app does not close or restart afterwards (an abrupt exit would give the substitution away by itself), and the login rate limit does not apply to it — it works even if you've just mistyped your real password several times and logins are temporarily locked out. The fake conversations are generated once during setup and never change, so reopening shows the same chats as the first time."
    override val guideEmergencyTitle = "Emergency deletion"
    override val guideEmergencyDesc = "5 presses of Volume Down within 3 seconds — instantly deletes keys and messages with zero confirmation, works even on a locked screen. By default it just deletes; the \"Decoy mode after wipe\" toggle (the same one used by the notification panic button — it's a single shared setting for both) makes it show the fake messenger instead, same as the duress password. Requires enabling through Android's Accessibility settings (see the instructions in Profile)."
    override val guideAutoLockTitle = "Auto-lock"
    override val guideAutoLockDesc = "The app locks with a password/biometric prompt after a set period of inactivity. The shorter the interval, the smaller the window during which someone could pick up an unlocked phone and read your messages."
    override val guideBackupTitle = "Backup"
    override val guideBackupDesc = "An encrypted file with all your keys and message history. Password-protected (Argon2id), and restoring on a new device also requires the TOTP secret — the file and password alone aren't enough. Store the file, password, and TOTP secret in different places. Two properties of the file worth knowing: it survives every level of emergency deletion, because it lives outside the app — if you wipe, delete your backup copy separately; and it can be read without a server and without restoring anything, see \"Reading a backup without restoring\". By default a backup carries message text only; attachments are added by a separate export option — see \"Attachments in a backup\"."
    override val guideTorTitle = "Tor"
    override val guideTorDesc = "Routes your connection to the server through the Tor network (requires Orbot installed), hiding your IP address even from the server itself. Off by default — enabling it adds 10-15 seconds to app startup.\n\nImportant: this only covers the connection to the server (login, messages, call signaling — who's calling whom). The actual audio/video of a call does NOT go through Tor: WebRTC can't route through Orbot's SOCKS proxy, and connects directly or via the relay server instead. IP protection specifically during a call is a separate setting, \"Hide IP during calls\" — Tor and it don't conflict, but they don't substitute for each other either: turn both on if you want coverage for both."
    override val guideCoverTitle = "Cover traffic"
    override val guideCoverDesc = "The app sends dummy packets at a steady interval even when you're not sending anything — so an outside observer can't tell from traffic patterns whether you're actively messaging or not. Uses a bit of battery and data."
    override val guideCompromisedTitle = "Identity reset"
    override val guideCompromisedDesc = "If you suspect your key was stolen — this permanently destroys your current keys, contacts, and messages on this device and issues new ones. Before deleting anything, the app also tells the server to revoke the old identity — the old key can no longer register, even if it ended up in someone else's hands. Contacts will need to exchange a fresh invite code with you to move to the new identity. Irreversible."
    override val guideDeleteContactTitle = "Deleting a contact"
    override val guideDeleteContactDesc = "Deleting a contact isn't just a list cleanup. The app immediately revokes every still-unspent token you gave them (they can't message you with old ones anymore) and blocks any new attempt to reach you from that person — even a fresh session request from them is silently ignored. The block lifts on its own if you later re-add the same contact via a fresh invite code. Use this as a quick way to cut off a contact whose device you believe is compromised."
    override val guideSelfHealTitle = "Self-healing connections"
    override val guideSelfHealDesc = "The app deliberately never tells the server who's talking to whom — great for privacy, but it means that after a disruption (like a long stretch offline), a chat or call can take a little while to reconnect instead of instantly. That's not a sign anything's broken — the channel is designed to repair itself. If a message isn't going through, usually just waiting a bit is enough. We keep testing to shrink these delays further."
    override val guideParanoidTitle = "Paranoid mode & alert URL"
    override val guideParanoidDesc = "Turns on continuous scanning for surveillance on the device (spyware Accessibility services, suspicious device-admin grants, screen overlays, and honey-token tampering). On detection: if an \"alert URL\" is set (Security Diagnostics → URL field), a silent POST request with the device ID and threat list is sent there, bypassing the messenger's own channel entirely (if you've been exposed, that channel can't be trusted). After that — either automatic data wipe (if \"wipe on breach\" is on), or a stealth mode showing a fake screen, same idea as the duress password.\n\nWhat the URL needs to be: a plain HTTPS address (http:// is blocked by the traffic policy and will just silently fail to send, except for localhost/emulator/.onion) that accepts a POST with a body like {\"device_id\":\"...\",\"threats\":\"...\",\"ts\":1234567890} — no auth header, so the receiving side just needs to accept a POST and show you that JSON somehow.\n\nMinimal receiver with no server of your own: the ntfy app (ntfy.sh) — install it on a phone or use the web app, subscribe to a private topic with an unguessable name (e.g. ntfy.sh/xk7q-my-own-channel), and put that address in as the alert URL. ntfy doesn't parse unrecognized JSON — it just shows it as plain text in the push notification, which is enough to see the device ID, threat list, and timestamp. Use the \"Test\" button on the diagnostics screen to confirm delivery without waiting for a real threat."
    override val guideDmsTitle = "Dead Man's Switch"
    override val guideDmsDesc = "A check-in timer from 15 minutes to 3 days. If you don't tap \"I'm okay\" before it runs out, the app assumes something happened to you, revokes your identity on the server (the old key stops being able to register), and wipes everything at the harshest level (Nuclear), no further confirmation. Useful if you might be detained or lose access to your phone for a while and can't trigger a wipe yourself."
    override val guideTimeoutWipeTitle = "Inactivity wipe"
    override val guideTimeoutWipeDesc = "Similar to the dead man's switch but simpler: if the app just hasn't been opened for 24/48/72 hours, for whatever reason, it triggers the exact same chain as the dead man's switch — a warning notification first, then a 15-minute window to just open the app and cancel it, and only then server-side identity revocation and a wipe at the harshest level (Nuclear). Good as a background safeguard in case a stolen phone isn't unlocked right away."
    override val guidePanicButtonTitle = "Panic button notification"
    override val guidePanicButtonDesc = "A third, separate emergency-deletion method (besides the duress password and the volume buttons) — a persistent notification with a \"Delete everything\" action, visible right away with no need to expand it, including from the lock screen. Still needs at least one tap on the screen, though — the volume buttons remain the only fully blind option, no need to even look at the screen. Can be set to show the same fake screen instead of just closing the app — configured separately."
    override val guideWipeLevelsTitle = "Destruction levels (Hard / Nuclear)"
    override val guideWipeLevelsDesc = "Hard deletes all keys, files, and app data. The single exception applies only when decoy mode is on: Hard then keeps a minimal profile (name and password hash) in freshly created encrypted storage, so the app can still recognize its owner afterwards and show the fake messenger. With decoy mode off, nothing is kept. Nuclear makes no exceptions at all: it's the Android system's own \"clear data\" call, which erases the entire app directory including the record Hard might keep — which is why Nuclear and decoy mode are fundamentally incompatible, and why after Nuclear the app can't tell its owner from anyone else. Different emergency-deletion features default to different levels (the dead man's switch, for example, always goes straight to Nuclear, since it doesn't need the decoy trade-off). For the exact list of what gets erased, see \"What a wipe actually erases\"."
    override val guideHideNotifTitle = "Hide text in notifications"
    override val guideHideNotifDesc = "A new-message notification shows only \"New message\", with no sender name or text — so if someone glances at your locked phone's screen, or the notification shows up on a smartwatch or in the shade, the conversation's content stays private. Messages still arrive and get stored normally; only what the notification displays is hidden."
    override val guideHideIpCallsTitle = "Hide IP during calls"
    override val guideHideIpCallsDesc = "By default a call tries to connect directly (P2P) for the lowest latency — but that means both devices exchange real IP addresses with each other. With this on, the call only ever routes through the relay server: your contact sees the server's address, not yours. The trade-off is higher latency and load on the relay, especially on a weak connection.\n\nThis hides your IP from your contact, but not from the relay server itself — it sees both real addresses since it's forwarding the traffic between you. Having Tor on doesn't add coverage here: Tor only wraps the signaling channel (the call request), the media itself travels directly, bypassing Tor."
    override val guideBiometricTitle = "Biometric unlock"
    override val guideBiometricDesc = "Fingerprint or face instead of a password at login — faster, but physically easier to compel: it's easier to force someone to press a finger or show their face than to force them to reveal a password, and in several jurisdictions compelled biometric unlock has weaker legal protection than compelled password disclosure. If physical or legal coercion is part of your threat model, keep password-only — your password stays a valid way to unlock even with biometrics enabled."
    override val guideChangePasswordTitle = "Changing your password"
    override val guideChangePasswordDesc = "Your password doesn't just gate the login screen — it also protects the on-disk encryption of every key and message (storage encryption). Changing it re-encrypts that storage under the new password; the old password stops working. Change it if you suspect someone else may have seen it, or just periodically as hygiene."
    override val guideDiagnosticsTitle = "Security diagnostics"
    override val guideDiagnosticsDesc = "A set of live checks on the device and app: root/tamper detection, key-storage integrity, TLS-pinning status, and other compromise signals — each check reports pass/fail with an explanation. This is also where paranoid mode (continuous surveillance monitoring) and a one-off IDS scan for anomalies live. If something fails, it's worth investigating before continuing to use this device for messaging."
    override val guideServiceNotifTitle = "Background service icon"
    override val guideServiceNotifDesc = "Android requires a persistent notification for as long as Subrosa's background service keeps your connection alive and receives messages — the notification itself can't be removed. This setting only hides its icon from the status bar: the notification goes silent and moves into the shade's collapsed \"Silent notifications\" section, so it doesn't draw attention at a glance."
    override val guideWipeOnBreachTitle = "Wipe on breach"
    override val guideWipeOnBreachDesc = "If the intrusion-detection system (IDS) flags a critical threat — for example paranoid mode triggering, or a honey-token being tampered with — the app automatically wipes your data with no further confirmation, at whichever level (Hard or Nuclear) you preselected. This is a last line of defense for when you physically can't reach a panic button yourself."
    override val guideCalcDisguiseTitle = "Calculator disguise"
    override val guideArchiveTitle = "Reading a backup without restoring"
    override val guideArchiveDesc = "Opens a backup file read-only: decryption happens locally, in memory, with no server involved — so you can read your history even if the server is shut down permanently. This mode deliberately does less than an import: it writes nothing to the device, leaves your current identity alone, and does not restore keys from the file, so opening an archive never gives you the ability to send messages as that account. Only the backup password is needed; no TOTP code, because nothing is being restored. Backgrounding the app discards the decrypted copy. Attachments are visible only if the backup was made with \"Include attachments\" enabled; otherwise such messages are marked unavailable. Photos open inside the viewer, and any attachment can be saved to a file — the only route out of this screen, and it takes an explicit action."
    override val guideWipeScopeTitle = "What a wipe actually erases"
    override val guideWipeScopeDesc = "Every level of emergency deletion does the same thing; the only difference is whether the app stays alive. Erased: the storage encryption key (first overwritten in RAM, then destroyed), the identity key, all session and conversation keys including the post-quantum ones, entries in Android's hardware-backed Keystore, and every setting, file, cache, database and attachment belonging to the app. Decoy mode keeps the app running so it can show the fake messenger instead of closing abruptly; Nuclear hands the deletion to Android itself. What a wipe does NOT erase, and this is worth knowing in advance: a backup file you saved yourself — it lives outside the app (in Downloads, on a card, in the cloud), no wipe level can reach it, and you have to delete it yourself. A wipe also can't delete messages already delivered to your contacts' devices. Android's cloud backup is disabled for this app, so your data can't be restored through a Google account."
    override val guideAttachmentsBackupTitle = "Attachments in a backup"
    override val guideAttachmentsBackupDesc = "Export has an \"Include attachments\" option — with it on, photos, videos, voice notes and documents go into the file instead of text alone. Turn it on if you need the backup to be a real archive: without it, a message that carried an attachment is restored empty, and a document from a conversation can never be read again. The cost: the file becomes tens of times larger, and the desktop client can't read it yet — make a separate backup without attachments if you need one on a computer. Attachments inside the file are encrypted with the same password as the conversations, and on restore they are re-encrypted under the new device's key — so a restored attachment is protected exactly like one received normally. Exporting with attachments is only offered through \"To files\": sharing via another app would make a second full copy of the file."
    override val guideCalcDisguiseDesc = "Swaps the app's icon and name for \"Calculator\" — a quick glance at your phone won't reveal the messenger among your other apps. It opens when you enter a numeric expression whose result equals your chosen code; the calculator otherwise keeps working normally for any other calculation."
}

val enStrings = AppStrings("en", en1, en2, en3, en4, en5, en6, en7, en8, en9, en10)

val LocalStrings = compositionLocalOf<AppStrings> { ruStrings }
