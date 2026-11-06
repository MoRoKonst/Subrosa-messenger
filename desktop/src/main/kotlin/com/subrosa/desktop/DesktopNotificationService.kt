package com.subrosa.desktop

import java.awt.SystemTray
import java.awt.TrayIcon
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.imageio.ImageIO
import javax.sound.sampled.AudioFormat
import javax.sound.sampled.AudioSystem
import javax.sound.sampled.LineEvent
import kotlin.math.PI
import kotlin.math.exp
import kotlin.math.sin

/** Desktop had no OS-level signal for an incoming message at all before this
 *  — confirmed live, zero SystemTray/TrayIcon usage anywhere in the codebase.
 *  Adds a toast (via a single persistent TrayIcon, the only way to get
 *  displayMessage() balloons) and a short procedurally-synthesized chime (no
 *  bundled audio asset, so no licensing question) for 1:1 messages, group
 *  messages, and incoming calls.
 *
 *  Gated by three independent things: UserStorage's notifications-enabled /
 *  sound-enabled toggles (ProfileScreen), per-chat mute via
 *  UserStorage.getContactMuteUntil/getGroupMuteUntil (calls are
 *  intentionally NOT mute-gated — a live ring shouldn't be silenced by a
 *  chat-mute setting, same convention as every mainstream messenger), and
 *  window-focus + current-screen suppression (no toast for a chat already
 *  open and focused — mirrors Telegram Desktop). */
object DesktopNotificationService {

    private var trayIcon: TrayIcon? = null
    private val chime: Pair<AudioFormat, ByteArray> by lazy { synthesizeChime() }

    fun init() {
        if (trayIcon != null) return
        try {
            if (!SystemTray.isSupported()) return
            val image = javaClass.classLoader.getResourceAsStream("icons/app_icon.png")?.use {
                ImageIO.read(it)
            } ?: return
            val icon = TrayIcon(image, "Subrosa Messenger")
            icon.isImageAutoSize = true
            SystemTray.getSystemTray().add(icon)
            trayIcon = icon
        } catch (e: Exception) {
            System.err.println("DesktopNotificationService: tray init failed — ${e.message}")
        }
    }

    fun notifyIncomingMessage(from: String, text: String) {
        if (!UserStorage.getNotificationsEnabled()) return
        if (UserStorage.getContactMuteUntil(from) > System.currentTimeMillis()) return
        if (isViewingScreen("chat:$from")) return
        val name = ChatStorage.getContactName(from).ifBlank { from }
        val body = if (UserStorage.getHideNotificationContent()) "" else text.take(80)
        show(name, body, muteSound = UserStorage.getContactMuteSound(from))
    }

    fun notifyGroupMessage(groupId: String, senderName: String, text: String) {
        if (!UserStorage.getNotificationsEnabled()) return
        if (UserStorage.getGroupMuteUntil(groupId) > System.currentTimeMillis()) return
        if (isViewingScreen("group:$groupId")) return
        val groupName = GroupManager.getGroup(groupId)?.name ?: senderName
        val body = if (UserStorage.getHideNotificationContent()) "" else "$senderName: ${text.take(70)}"
        show(groupName, body, muteSound = UserStorage.getGroupMuteSound(groupId))
    }

    fun notifyIncomingCall(from: String, isVideo: Boolean) {
        if (!UserStorage.getNotificationsEnabled()) return
        val name = ChatStorage.getContactName(from).ifBlank { from }
        show(name, if (isVideo) "Видеозвонок" else "Звонок", muteSound = false)
    }

    private fun isViewingScreen(screen: String): Boolean =
        AppFocusTracker.isFocused && AppFocusTracker.currentScreen == screen

    private fun show(title: String, body: String, muteSound: Boolean) {
        try {
            trayIcon?.displayMessage(title, body, TrayIcon.MessageType.NONE)
        } catch (_: Exception) {}
        if (UserStorage.getNotificationSoundEnabled() && !muteSound) playChime()
    }

    private fun playChime() {
        try {
            val (format, bytes) = chime
            val clip = AudioSystem.getClip()
            clip.open(format, bytes, 0, bytes.size)
            clip.addLineListener { event -> if (event.type == LineEvent.Type.STOP) clip.close() }
            clip.start()
        } catch (_: Exception) {}
    }

    /** Short two-tone ascending chime (A5 -> E6, a perfect fifth — a
     *  deliberately soft, non-jarring interval) with an exponential-decay
     *  envelope on each tone so there's no harsh click at the tail.
     *  Synthesized once and cached rather than bundling an audio asset —
     *  sidesteps sourcing/licensing a sound file entirely. */
    private fun synthesizeChime(): Pair<AudioFormat, ByteArray> {
        val sampleRate = 44100
        val format = AudioFormat(sampleRate.toFloat(), 16, 1, true, false)
        val toneMs = 170
        val toneSamples = sampleRate * toneMs / 1000
        val amplitude = 0.28 * Short.MAX_VALUE
        val tones = doubleArrayOf(880.0, 1318.51)
        val out = ByteArrayOutputStream()
        val buf = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN)
        for (freq in tones) {
            for (i in 0 until toneSamples) {
                val t = i.toDouble() / sampleRate
                val decay = exp(-4.0 * i / toneSamples)
                val sample = (amplitude * decay * sin(2.0 * PI * freq * t)).toInt().toShort()
                buf.clear()
                buf.putShort(sample)
                out.write(buf.array())
            }
        }
        return format to out.toByteArray()
    }
}
