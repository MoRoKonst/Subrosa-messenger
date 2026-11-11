# ═══════════════════════════════════════════════════════════════════════════════
# Beacon Messenger — ProGuard rules
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Атрибуты (оставить для рефлексии и stacktrace) ──────────────────────────
-keepattributes *Annotation*, InnerClasses, EnclosingMethod
-keepattributes Signature, Exceptions
-keepattributes SourceFile, LineNumberTable
-renamesourcefileattribute SourceFile

# ─── Kotlin ───────────────────────────────────────────────────────────────────
-keep class kotlin.** { *; }
-keep class kotlin.Metadata { *; }
-dontwarn kotlin.**

# ─── Kotlin Coroutines ────────────────────────────────────────────────────────
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}
-dontwarn kotlinx.coroutines.**

# ─── Compose ──────────────────────────────────────────────────────────────────
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# ─── Все классы приложения (сохраняем полностью) ──────────────────────────────
-keep class com.subrosa.messenger.** { *; }
-keepclassmembers class com.subrosa.messenger.** { *; }

# ─── OkHttp & WebSocket ───────────────────────────────────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep class okio.** { *; }

# ─── WebRTC (stream-webrtc-android + нативные классы) ────────────────────────
-keep class org.webrtc.** { *; }
-keepclassmembers class org.webrtc.** { *; }
-dontwarn org.webrtc.**
-keep class io.getstream.webrtc.** { *; }
-dontwarn io.getstream.webrtc.**
# JNI — обязательно, иначе нативные методы не найдут свои Java-классы
-keepclasseswithmembernames class * {
    native <methods>;
}

# ─── Firebase / FCM ───────────────────────────────────────────────────────────
-keep class com.google.firebase.** { *; }
-dontwarn com.google.firebase.**
-keep class com.google.android.gms.** { *; }
-dontwarn com.google.android.gms.**

# ─── Crypto (Android Keystore + javax.crypto) ─────────────────────────────────
-keep class java.security.** { *; }
-keep class javax.** { *; }
-keep class javax.crypto.** { *; }
-keep class android.security.keystore.** { *; }

# ─── JSON ─────────────────────────────────────────────────────────────────────
-keep class org.json.** { *; }
-keepclassmembers class org.json.** { *; }

# ─── Tor ──────────────────────────────────────────────────────────────────────
-keep class net.freehaven.tor.control.** { *; }
-dontwarn net.freehaven.tor.control.**
-keep class org.torproject.** { *; }
-dontwarn org.torproject.**

# ─── ZXing (QR-сканер) ────────────────────────────────────────────────────────
-keep class com.google.zxing.** { *; }
-dontwarn com.google.zxing.**
-keep class com.journeyapps.** { *; }
-dontwarn com.journeyapps.**

# ─── OSMDroid (карты) ─────────────────────────────────────────────────────────
-keep class org.osmdroid.** { *; }
-dontwarn org.osmdroid.**

# ─── Biometric ────────────────────────────────────────────────────────────────
-keep class androidx.biometric.** { *; }
-dontwarn androidx.biometric.**

# ─── Security Crypto (EncryptedSharedPreferences) ─────────────────────────────
-keep class androidx.security.crypto.** { *; }
-dontwarn androidx.security.crypto.**

# ─── Общие паттерны ───────────────────────────────────────────────────────────

# Parcelable
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# Enum
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Serializable
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ─── BouncyCastle (EC + ML-KEM/postquantum — PqCrypto.kt relies on this
#     directly, not just via javax.crypto provider lookup; R8 must not
#     strip/rename any of it) ────────────────────────────────────────────────
-keep class org.bouncycastle.** { *; }
-keepclassmembers class org.bouncycastle.** { *; }
-keepnames class org.bouncycastle.** { *; }

# ─── Вырезание логов из релиза ────────────────────────────────────────────────
#
# Найдено 2026-11-11. Приложение писало в logcat строки вида
#
#     ОТПРАВЛЕНО message <id> → <отпечаток получателя> @ <время>
#     ПОЛУЧЕНО voice <id> ← <отпечаток отправителя> @ <время>
#
# то есть ровно тот граф «кто с кем и когда», ради сокрытия которого проект и
# существует — открытым текстом, на самом устройстве. Проверено в УЖЕ
# ОПУБЛИКОВАННОМ APK v1.1.0: строки присутствуют в dex, правила вырезания не
# было, все 592 вызова Log.* попадали в релиз.
#
# Насколько это достижимо для атакующего, без преувеличения: чужой logcat
# нельзя прочитать из обычного приложения (Android запрещает это с 4.1).
# Доступ дают отладка по USB, отчёты об ошибках (dumpstate), root и
# криминалистические инструменты. Буфер кольцевой, поэтому утекает недавняя
# история, а не вся переписка. Но изъятие устройства прямо входит в модель
# угроз (docs/THREAT_MODEL.md), так что это внутри области, а не рядом с ней.
#
# Вырезаются ВСЕ уровни, включая w/e: предупреждения здесь тоже содержат
# отпечатки (например «member_keys: ключ для <fp> не соответствует»).
# Отладка при этом не страдает — debug-сборка не минифицируется, логи в ней
# остаются полностью.
#
# -assumenosideeffects убирает только вызовы, чей результат не используется.
# Log.* возвращает int, который нигде не читается, поэтому удаляются все.
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
    public static *** println(...);
}

# ─── Подавление предупреждений (сторонние библиотеки) ─────────────────────────
-dontwarn org.bouncycastle.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
