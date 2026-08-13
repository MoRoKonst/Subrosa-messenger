package com.subrosa.messenger

import android.os.Build
import com.subrosa.messenger.BuildConfig
import java.io.File

object RootDetector {

    enum class RootLevel {
        NONE,
        WARNING,
        DANGER
    }

    /** Machine-readable indicator codes — RootDetector itself stays language-
     *  agnostic; AppStrings.rootReasonText(code) maps each to the localized
     *  label shown in MainActivity's root-warning dialogs. The emulator
     *  codes deliberately don't carry the raw emulatorScore() number — that
     *  score is an internal confidence heuristic, not something a user can
     *  act on or make sense of. */
    enum class RootReason {
        ROOT_BINARY, TEST_KEYS_BUILD, ROOT_PACKAGE, WHICH_SU, SYSTEM_WRITABLE,
        DEBUGGER_CONNECTED, TRACER_PID,
        FRIDA_PORT, FRIDA_MAPS, FRIDA_PROCESS,
        XPOSED_BRIDGE, XPOSED_PACKAGE, XPOSED_MAPS,
        EMULATOR_HIGH_CONFIDENCE, EMULATOR_POSSIBLE
    }

    data class RootCheckResult(
        val level: RootLevel,
        val reasons: List<RootReason>
    )

    fun isDeviceRooted(): Boolean {
        return checkResult().level != RootLevel.NONE
    }

    fun checkResult(): RootCheckResult {
        val reasons = mutableListOf<RootReason>()

        if (checkRootBinaries())    reasons.add(RootReason.ROOT_BINARY)
        if (checkBuildTags())       reasons.add(RootReason.TEST_KEYS_BUILD)
        if (checkRootPackages())    reasons.add(RootReason.ROOT_PACKAGE)
        if (checkWhichSu())         reasons.add(RootReason.WHICH_SU)
        if (checkSystemWritable())  reasons.add(RootReason.SYSTEM_WRITABLE)

        if (!BuildConfig.DEBUG) {
            if (checkDebuggerConnected()) reasons.add(RootReason.DEBUGGER_CONNECTED)
            if (checkTracerPid())         reasons.add(RootReason.TRACER_PID)
        }

        if (checkFridaPort())       reasons.add(RootReason.FRIDA_PORT)
        if (checkFridaMaps())       reasons.add(RootReason.FRIDA_MAPS)
        if (checkFridaProcesses())  reasons.add(RootReason.FRIDA_PROCESS)

        if (checkXposedBridge())    reasons.add(RootReason.XPOSED_BRIDGE)
        if (checkXposedPackages())  reasons.add(RootReason.XPOSED_PACKAGE)
        if (checkXposedMaps())      reasons.add(RootReason.XPOSED_MAPS)

        val emuScore = emulatorScore()
        if (emuScore >= 4)          reasons.add(RootReason.EMULATOR_HIGH_CONFIDENCE)
        else if (emuScore >= 2)     reasons.add(RootReason.EMULATOR_POSSIBLE)

        val level = when {
            reasons.isEmpty()  -> RootLevel.NONE
            reasons.size == 1  -> RootLevel.WARNING
            else               -> RootLevel.DANGER
        }

        return RootCheckResult(level, reasons)
    }

    private fun checkRootBinaries(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkRootPackages(): Boolean {
        val packages = arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk",
            "io.github.vvb2060.magisk",
            "com.fox2code.mmm"
        )
        return packages.any { isPackageInstalled(it) }
    }

    private fun checkWhichSu(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.destroy()
            result.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }

    private fun checkSystemWritable(): Boolean {
        return try {
            val testFile = File("/system/.beacon_rw_test")
            if (testFile.createNewFile()) { testFile.delete(); true } else false
        } catch (e: Exception) {
            false
        }
    }

    private fun checkDebuggerConnected(): Boolean =
        android.os.Debug.isDebuggerConnected()

    private fun checkTracerPid(): Boolean = try {
        File("/proc/self/status").readLines()
            .firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter("TracerPid:")
            ?.trim()
            ?.toIntOrNull()
            ?.let { it > 0 }
            ?: false
    } catch (e: Exception) {
        false
    }

    private fun checkFridaPort(): Boolean {
        return try {
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 80)
            socket.close()
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun checkFridaMaps(): Boolean {
        return try {
            File("/proc/self/maps").readText().let { maps ->
                maps.contains("frida", ignoreCase = true) ||
                maps.contains("gum-js", ignoreCase = true) ||
                maps.contains("linjector", ignoreCase = true)
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun checkFridaProcesses(): Boolean {
        return try {
            File("/proc").listFiles()?.any { dir ->
                if (!dir.isDirectory) return@any false
                try {
                    File(dir, "cmdline").readText()
                        .contains("frida", ignoreCase = true)
                } catch (e: Exception) { false }
            } == true
        } catch (e: Exception) {
            false
        }
    }

    private fun checkXposedBridge(): Boolean {
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            true
        } catch (e: ClassNotFoundException) {
            false
        } catch (e: Exception) {
            false
        }
    }

    private fun checkXposedPackages(): Boolean {
        val packages = arrayOf(
            "de.robv.android.xposed.installer",
            "io.github.lsposed.manager",
            "org.lsposed.manager",
            "com.solohsu.android.edxp.manager",
            "me.weishu.exp"
        )
        return packages.any { isPackageInstalled(it) }
    }

    private fun checkXposedMaps(): Boolean {
        return try {
            File("/proc/self/maps").readText().contains("XposedBridge.jar")
        } catch (e: Exception) {
            false
        }
    }

    private fun emulatorScore(): Int {
        var score = 0

        val fp = Build.FINGERPRINT.lowercase()
        if (fp.startsWith("generic"))            score += 2
        if (fp.contains(":sdk_gphone"))          score += 2
        if (fp.contains("generic/sdk"))          score += 2
        if (fp.contains("emulator"))             score++

        val hw = Build.HARDWARE.lowercase()
        if (hw == "goldfish" || hw == "ranchu")  score += 2

        val model = Build.MODEL.lowercase()
        if (model.contains("emulator"))          score += 2
        if (model.contains("android sdk built")) score += 2
        if (model.contains("google_sdk"))        score += 2

        if (Build.MANUFACTURER.equals("unknown", ignoreCase = true)) score++

        val product = Build.PRODUCT.lowercase()
        if (product.startsWith("sdk") ||
            product.contains("_sdk") ||
            product.contains("sdk_") ||
            product.contains("emulator"))        score++

        if (Build.BOARD.equals("unknown", ignoreCase = true)) score++

        val brand = Build.BRAND.lowercase()
        if (brand.startsWith("generic") ||
            brand == "android")                  score++

        val emuFiles = arrayOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )
        if (emuFiles.any { File(it).exists() })  score += 2

        return score
    }

    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("pm", "list", "packages", packageName))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.destroy()
            result.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
}
