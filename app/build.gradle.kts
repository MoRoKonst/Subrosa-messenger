import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    id("com.google.gms.google-services") apply false
}

// google-services.json is gitignored (per-deployment Firebase project, not
// committed -- see DOCKER.md/DEPLOY.md on the FCM opt-in). Applying the
// plugin unconditionally makes any build without that file (CI, or a fresh
// no-FCM checkout) fail outright even though FCM push is optional
// everywhere else in this codebase.
if (file("google-services.json").exists()) {
    apply(plugin = "com.google.gms.google-services")
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(localPropertiesFile.inputStream())
}

android {
    namespace = "com.subrosa.messenger"
    compileSdk = 34


    signingConfigs {
        create("release") {
            storeFile = file("../beacon-release.jks")
            storePassword = localProperties.getProperty("KEYSTORE_PASSWORD")
                ?: System.getenv("KEYSTORE_PASSWORD")
            keyAlias = "messenger"
            keyPassword = localProperties.getProperty("KEY_PASSWORD")
                ?: System.getenv("KEY_PASSWORD")
        }
    }

    defaultConfig {
        applicationId = "com.subrosa.messenger"
        minSdk = 26
        versionCode = 3
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }

    // Lint had never been run in CI before (docs/CI_SAST_PLAN.md, Phase 0) --
    // baseline captures whatever pre-existing issues already exist so CI
    // starts clean and only fails on genuinely new lint errors from here on,
    // rather than blocking on unrelated legacy findings this change didn't
    // introduce. Regenerate with `./gradlew updateLintBaseline` if it drifts.
    lint {
        baseline = file("lint-baseline.xml")
    }
}

dependencies {
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("com.google.zxing:core:3.5.1")
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))
    implementation(platform("com.google.firebase:firebase-bom:33.0.0"))
    implementation("com.google.firebase:firebase-messaging-ktx")

    // QR сканирование
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // Шифрование хранилища
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // Корутины
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // Биометрия
    implementation("androidx.biometric:biometric:1.1.0")
    // EXIF-стриппинг (GPS/устройство/даты) для фото, отправленных как файл
    implementation("androidx.exifinterface:exifinterface:1.4.2")
    // WebSocket
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79") // 1.79+ required for org.bouncycastle.pqc.crypto.mlkem (ML-KEM)

    // Тесты
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)

    // Debug
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    // Геолокация (Fused Location Provider)
    implementation("com.google.android.gms:play-services-location:21.2.0")
    // OpenStreetMap
    implementation("org.osmdroid:osmdroid-android:6.1.18")
    // WebRTC (P2P звонки)
    implementation("io.getstream:stream-webrtc-android:1.3.10")
    // CameraX (видеокружки)
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")
    implementation("androidx.camera:camera-video:1.3.4")
}