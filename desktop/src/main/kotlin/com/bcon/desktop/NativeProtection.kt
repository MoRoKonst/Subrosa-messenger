package com.subrosa.desktop

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.WinDef.HWND
import java.awt.Window

/**
 * Native OS protections via JNA.
 *
 * Screen capture prevention:
 *   Windows  — SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE = 0x11)
 *   macOS    — NSWindow sharingType = NSWindowSharingNone (via objc bridge)
 *   Linux    — no reliable compositor API; reports WARN
 *
 * Memory locking (prevent SMK being paged to swap):
 *   Windows  — VirtualLock / VirtualUnlock
 *   POSIX    — mlock / munlock (libc)
 */
object NativeProtection {

    @Volatile var screenCaptureProtected: Boolean = false
        private set

    @Volatile var memoryLockSupported: Boolean = false
        private set

    // ── JNA interface definitions ────────────────────────────────────────────

    private interface User32Ex : Library {
        fun SetWindowDisplayAffinity(hwnd: Pointer, dwAffinity: Int): Boolean
        fun OpenClipboard(hWndNewOwner: Pointer?): Boolean
        fun CloseClipboard(): Boolean
        fun SetClipboardData(uFormat: Int, hMem: Pointer?): Pointer?
        fun RegisterClipboardFormatW(lpszFormat: WString): Int
        companion object { const val WDA_EXCLUDE_FROM_CAPTURE = 0x00000011 }
    }

    private interface Kernel32Ex : Library {
        fun VirtualLock(lpAddress: Pointer, dwSize: Long): Boolean
        fun VirtualUnlock(lpAddress: Pointer, dwSize: Long): Boolean
        fun GlobalAlloc(uFlags: Int, dwBytes: Long): Pointer?
        fun GlobalLock(hMem: Pointer): Pointer?
        fun GlobalUnlock(hMem: Pointer): Boolean
        fun SetErrorMode(uMode: Int): Int
        fun SetDefaultDllDirectories(directoryFlags: Int): Boolean
        companion object {
            const val GMEM_MOVEABLE = 0x0002
            const val SEM_NOGPFAULTERRORBOX = 0x0002
            const val LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
        }
    }

    private interface LibC : Library {
        fun mlock(addr: Pointer, len: Long): Int
        fun munlock(addr: Pointer, len: Long): Int
    }

    // Lazy-load native libraries; null if unavailable on this OS
    private val user32: User32Ex? by lazy {
        try { Native.load("user32", User32Ex::class.java) } catch (_: Throwable) { null }
    }
    private val kernel32: Kernel32Ex? by lazy {
        try { Native.load("kernel32", Kernel32Ex::class.java) } catch (_: Throwable) { null }
    }
    private val libc: LibC? by lazy {
        try { Native.load("c", LibC::class.java) } catch (_: Throwable) { null }
    }

    // ── Screen capture prevention ────────────────────────────────────────────

    /**
     * Call once from the main Window composable via DisposableEffect.
     *
     * Returns true on Windows when the affinity was set successfully.
     * On other platforms the function always returns false — callers should
     * check [screenCaptureProtected] to know whether it actually worked.
     */
    fun enableScreenCaptureProtection(window: Window): Boolean {
        val os = System.getProperty("os.name", "").lowercase()
        return when {
            os.contains("win") -> enableOnWindows(window)
            os.contains("mac") -> enableOnMac(window)
            else -> false   // Linux: no reliable compositor-agnostic API
        }.also { screenCaptureProtected = it }
    }

    private fun enableOnWindows(window: Window): Boolean {
        return try {
            val hwnd = Native.getComponentPointer(window)
            val u32  = user32 ?: return false
            u32.SetWindowDisplayAffinity(hwnd, User32Ex.WDA_EXCLUDE_FROM_CAPTURE)
        } catch (_: Throwable) { false }
    }

    private fun enableOnMac(window: Window): Boolean {
        // macOS: call [NSWindow setSharingType: NSWindowSharingNone] via
        // the Foundation/AppKit Objective-C bridge bundled in JNA-platform.
        // Requires JNA >= 5.13 and macOS 10.13+.
        return try {
            val clsNSApplication = Class.forName("com.sun.jna.platform.mac.AppKit\$NSApplication")
            // Walk peer hierarchy to get NSWindow handle
            val peerField = window.javaClass.getDeclaredField("peer")
            peerField.isAccessible = true
            val peer = peerField.get(window) ?: return false
            val nativeViewMethod = peer.javaClass.getMethod("getNSWindowPtr")
            nativeViewMethod.isAccessible = true
            val nsWindowPtr = nativeViewMethod.invoke(peer) as? Long ?: return false

            // NSWindowSharingNone = 0
            val foundation = Class.forName("com.sun.jna.platform.mac.Foundation")
            val objcSendMethod = foundation.getMethod("invoke",
                Long::class.java, String::class.java, Array<Any>::class.java)
            // [nsWindow setSharingType: 0]
            objcSendMethod.invoke(null, nsWindowPtr, "setSharingType:", arrayOf<Any>(0L))
            true
        } catch (_: Throwable) {
            false
        }
    }

    // ── Clipboard protection ─────────────────────────────────────────────────

    /**
     * Marks the current clipboard contents as excluded from Windows Clipboard
     * History (Win+V) and Cloud Clipboard sync, by attaching the two special
     * marker formats Windows checks for. No-op on non-Windows platforms.
     *
     * Must be called right after the AWT/Compose clipboard write, in a
     * separate Open/SetClipboardData/Close cycle — this only *adds* marker
     * formats and does not call EmptyClipboard, so the text already placed
     * on the clipboard is left untouched.
     */
    fun excludeClipboardFromHistoryAndCloud() {
        val os = System.getProperty("os.name", "").lowercase()
        if (!os.contains("win")) return
        try {
            val u32 = user32 ?: return
            val k32 = kernel32 ?: return
            if (!u32.OpenClipboard(null)) return
            try {
                for (formatName in arrayOf("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")) {
                    val format = u32.RegisterClipboardFormatW(WString(formatName))
                    if (format == 0) continue
                    val hMem = k32.GlobalAlloc(Kernel32Ex.GMEM_MOVEABLE, 4L) ?: continue
                    val ptr = k32.GlobalLock(hMem)
                    if (ptr != null) {
                        ptr.setInt(0, 0) // 0 = excluded
                        k32.GlobalUnlock(hMem)
                    }
                    u32.SetClipboardData(format, hMem)
                }
            } finally {
                u32.CloseClipboard()
            }
        } catch (_: Throwable) { /* best-effort — clipboard still works without the markers */ }
    }

    // ── DLL search-order hardening ───────────────────────────────────────────

    /**
     * Restricts native library loading (used by our own JNA calls, and by the
     * JVM's own native dependencies) to System32, closing the classic local
     * DLL-planting attack: a malicious DLL dropped next to the jar/exe that
     * would otherwise be picked up by the default search order, which used to
     * include the application directory and CWD. Must be called before any
     * other native library is loaded. No-op on non-Windows platforms.
     */
    fun restrictDllSearchToSystem32(): Boolean {
        val os = System.getProperty("os.name", "").lowercase()
        if (!os.contains("win")) return false
        return try {
            val k32 = kernel32 ?: return false
            k32.SetDefaultDllDirectories(Kernel32Ex.LOAD_LIBRARY_SEARCH_SYSTEM32)
        } catch (_: Throwable) { false }
    }

    // ── Crash dump suppression ───────────────────────────────────────────────

    /**
     * Suppresses the Windows "program has stopped working" WER dialog on an
     * unhandled crash, reducing the chance that decrypted message content
     * still resident in the JVM heap ends up captured in a crash dump shown
     * to, or collected from, the machine. No-op on non-Windows platforms.
     */
    fun disableCrashDumps(): Boolean {
        val os = System.getProperty("os.name", "").lowercase()
        if (!os.contains("win")) return false
        return try {
            val k32 = kernel32 ?: return false
            k32.SetErrorMode(Kernel32Ex.SEM_NOGPFAULTERRORBOX)
            true
        } catch (_: Throwable) { false }
    }

    // ── LockedBuffer ─────────────────────────────────────────────────────────

    /**
     * A fixed-size buffer in native (off-heap) memory, locked against paging.
     *
     * Use this to hold the Storage Master Key. When done, call [clear] + [free].
     *
     * If mlock/VirtualLock is unavailable the buffer still works, but the OS
     * may page the bytes to disk. [isLocked] reflects whether locking succeeded.
     */
    class LockedBuffer internal constructor(
        private val mem: Memory,
        val size: Int,
        val isLocked: Boolean
    ) {
        /** Write [bytes] into the buffer (must be <= [size]). */
        fun write(bytes: ByteArray) {
            require(bytes.size <= size) { "LockedBuffer overflow: ${bytes.size} > $size" }
            mem.write(0, bytes, 0, bytes.size)
        }

        /** Read [size] bytes from the buffer. Caller must wipe the result after use. */
        fun read(): ByteArray {
            val out = ByteArray(size)
            mem.read(0, out, 0, size)
            return out
        }

        /** Zero-fill the buffer (call before [free]). */
        fun clear() {
            val zeros = ByteArray(size)
            mem.write(0, zeros, 0, size)
        }

        /** Unlock + release native memory. Always call this when done. */
        fun free() {
            if (isLocked) unlock(mem, size.toLong())
            // JNA Memory is GC'd, but we help it along
        }
    }

    /**
     * Allocate a page-aligned native buffer of [size] bytes and attempt to lock it.
     *
     * Returns null only if native Memory allocation itself fails.
     * [LockedBuffer.isLocked] will be false if the OS denied locking (e.g. quota exhausted).
     */
    fun allocateLockedBuffer(size: Int): LockedBuffer? {
        return try {
            val mem    = Memory(size.toLong())
            val locked = lock(mem, size.toLong())
            if (locked) memoryLockSupported = true
            LockedBuffer(mem, size, locked)
        } catch (_: Throwable) { null }
    }

    // ── Private lock/unlock helpers ──────────────────────────────────────────

    private fun lock(ptr: Pointer, size: Long): Boolean {
        val os = System.getProperty("os.name", "").lowercase()
        return if (os.contains("win")) {
            kernel32?.VirtualLock(ptr, size) ?: false
        } else {
            (libc?.mlock(ptr, size) ?: -1) == 0
        }
    }

    private fun unlock(ptr: Pointer, size: Long) {
        val os = System.getProperty("os.name", "").lowercase()
        if (os.contains("win")) kernel32?.VirtualUnlock(ptr, size)
        else libc?.munlock(ptr, size)
    }
}
