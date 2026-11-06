import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    id("com.google.gms.google-services") apply false
}

// A project path containing non-ASCII characters silently breaks the Gradle
// test worker on Windows, and the failure looks nothing like its cause: every
// single test class dies with ClassNotFoundException before a line of test
// code runs ("Could not execute test class ...").
//
// Why: Gradle passes the worker's ~42KB classpath in a JVM @argfile, which it
// writes as UTF-8. The java launcher expands that argfile using the platform
// encoding (sun.jnu.encoding), which is Cp1251 on a Russian-locale Windows, so
// "E:\Диск Д\..." is read back as "E:\Р”РёСЃРє Р”\...". Every classpath entry
// under the project directory then points at a path that does not exist, the
// compiled test classes among them. Gradle still *finds* the test classes
// (Test.testClassesDirs is a normal Gradle property and encodes fine), which
// is why the task gets far enough to name the class it then cannot load.
// Verified by dumping the argfile: UTF-8 on disk, and the worker is launched
// with -Dfile.encoding=UTF-8 but sun.jnu.encoding stays Cp1251 — -D cannot fix
// it, because the argfile is expanded before VM properties take effect.
//
// Same root cause as the jlink packaging failure already fixed for :desktop
// (see desktop/build.gradle.kts). The fix is the same: keep build outputs on an
// ASCII path. Conditional, unlike the desktop one, so CI and ASCII checkouts
// keep the documented app/build/outputs/... layout untouched; the directory is
// tagged with a hash of the project path so two checkouts cannot collide.
//
// It has to stay on the *same drive* as the project: parts of AGP relativise
// output paths against the project directory, and a build dir on another drive
// fails outright with "this and base files have different roots".
run {
    val projectPath = rootDir.absolutePath
    if (projectPath.any { it.code > 127 }) {
        val driveRoot = rootDir.toPath().root?.toString()
        if (driveRoot == null || driveRoot.any { it.code > 127 }) {
            logger.warn(
                "Project path contains non-ASCII characters and its drive root is not " +
                    "ASCII-safe — unit tests will fail with ClassNotFoundException. " +
                    "Move the checkout to an ASCII path."
            )
        } else {
            val tag = Integer.toHexString(projectPath.hashCode())
            val redirected = File(driveRoot, ".subrosa-build/app-$tag")
            logger.lifecycle(
                "Non-ASCII project path detected — build directory redirected to " +
                    "$redirected (see app/build.gradle.kts for why)."
            )
            layout.buildDirectory.set(redirected)
        }
    }
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
    compileSdk = 37


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

    /**
     * TLS certificate pinning, configured out of band rather than hardcoded.
     *
     * Previously `NetworkConfig.CERT_PIN` was an empty `const val`, so the
     * pinning branch in MessengerService was unreachable and the app silently
     * fell back to the system CA store — while a second, never-called pinning
     * implementation sat in the tree holding a real-looking pin. Both halves of
     * that were worse than having no pinning at all, because the code read as
     * though pinning was in effect.
     *
     * Pins are SPKI hashes in OkHttp's `sha256/BASE64` form, comma-separated,
     * supplied as `SUBROSA_CERT_PINS` in `local.properties` or the environment
     * — the same pattern as the signing credentials above, and for the same
     * reason: it is per-deployment and does not belong in a public repository.
     *
     * Pin your own key, not the certificate: generate the server keypair once,
     * renew with `certbot --reuse-key` (or equivalent), and the SPKI hash never
     * changes across renewals. Always ship at least two pins, the second from
     * an offline backup keypair — a single pin turns the loss of one key into a
     * permanent outage for every installed copy.
     */
    val certPins: List<String> = (
        localProperties.getProperty("SUBROSA_CERT_PINS")
            ?: System.getenv("SUBROSA_CERT_PINS")
            ?: ""
        ).split(",").map { it.trim() }.filter { it.isNotEmpty() }

    certPins.forEach {
        require(it.startsWith("sha256/")) {
            "SUBROSA_CERT_PINS entries must be OkHttp SPKI pins of the form sha256/BASE64, got: $it"
        }
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
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
            buildConfigField("String", "CERT_PINS", "\"${certPins.joinToString(",")}\"")
        }
        debug {
            // Empty on purpose: debug builds talk to localhost, the emulator
            // host and a test server whose certificate is not the pinned one.
            buildConfigField("String", "CERT_PINS", "\"\"")
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

/**
 * A release build with no pins fails here rather than shipping.
 *
 * This is the whole point of the rework: "pinning is configured but inert" has
 * to be an impossible state to publish, not something a person has to remember
 * to check. Debug builds are unaffected — the check only fires once a release
 * task is actually in the graph, so day-to-day development against localhost
 * does not need the production pins present.
 *
 * To build a release without pinning anyway (don't, unless you know why):
 * `-PsubrosaAllowUnpinnedRelease=true`.
 */
gradle.taskGraph.whenReady {
    val pins = (
        localProperties.getProperty("SUBROSA_CERT_PINS")
            ?: System.getenv("SUBROSA_CERT_PINS")
            ?: ""
        ).split(",").map { it.trim() }.filter { it.isNotEmpty() }

    val releaseInGraph = allTasks.any {
        it.project.path == project.path && it.name.contains("Release")
    }
    val override = project.findProperty("subrosaAllowUnpinnedRelease") == "true"

    if (releaseInGraph && pins.isEmpty() && !override) {
        throw GradleException(
            """
            Release build blocked: SUBROSA_CERT_PINS is empty, so the shipped app
            would fall back to the system CA store with no certificate pinning.

            Set it in local.properties or the environment, comma-separated:
                SUBROSA_CERT_PINS=sha256/PRIMARY=,sha256/BACKUP=

            Compute a pin from the server's public key:
                openssl x509 -in cert.pem -pubkey -noout \
                  | openssl pkey -pubin -outform der \
                  | openssl dgst -sha256 -binary | openssl enc -base64

            Or, before the certificate exists, straight from the private key:
                openssl pkey -in server.key -pubout -outform der \
                  | openssl dgst -sha256 -binary | openssl enc -base64

            Ship two: the live key and an offline backup key. One pin means
            losing that key bricks every installed copy permanently.

            Override (and understand why you are): -PsubrosaAllowUnpinnedRelease=true
            """.trimIndent()
        )
    }

    if (releaseInGraph && pins.size == 1) {
        logger.warn(
            "WARNING: only one certificate pin is configured. Add a backup pin from an " +
            "offline keypair — with a single pin, losing that key is an unrecoverable " +
            "outage for every installed copy."
        )
    }
}

dependencies {
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("com.google.zxing:core:3.5.4")
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    // Was pulled in transitively via material3 on compose-bom 2024.09.00 --
    // no longer implicit as of 2026.08.00, so Icons.Filled.* etc. across
    // the app stopped resolving. Declared explicitly now (version comes
    // from the compose-bom platform() above, same as the other compose
    // artifacts here).
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))
    implementation(platform("com.google.firebase:firebase-bom:33.0.0"))
    implementation("com.google.firebase:firebase-messaging-ktx")

    // QR сканирование
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // Шифрование хранилища
    implementation("androidx.security:security-crypto:1.1.0")
    // Корутины
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // Биометрия
    implementation("androidx.biometric:biometric:1.1.0")
    // EXIF-стриппинг (GPS/устройство/даты) для фото, отправленных как файл
    implementation("androidx.exifinterface:exifinterface:1.4.2")
    // WebSocket
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79") // 1.79+ required for org.bouncycastle.pqc.crypto.mlkem (ML-KEM)

    // Тесты
    testImplementation(libs.junit)
    // Robolectric -- lets Android-dependent unit tests (Context, SharedPreferences)
    // run on the plain JVM instead of needing a real device/emulator.
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("androidx.test:core:1.6.1")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)

    // Debug
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    // Геолокация (Fused Location Provider)
    implementation("com.google.android.gms:play-services-location:21.4.0")
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