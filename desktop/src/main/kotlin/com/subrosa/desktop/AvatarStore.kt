package com.subrosa.desktop

import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.res.loadImageBitmap
import java.io.ByteArrayInputStream
import java.util.Base64

/** Mirrors Android's AvatarStore.kt — in-memory, Compose-observable cache of
 *  decoded avatar bitmaps, keyed by contact fingerprint (or own userId for
 *  the local user's own avatar). Populated from network avatar_data frames
 *  (WebSocketClient) and lazily from ChatStorage's persisted base64 on first
 *  read (loadIfMissing), so a contact whose avatar arrived in a previous
 *  session still shows up without waiting for a fresh network push. */
object AvatarStore {

    val avatars = mutableStateMapOf<String, ImageBitmap>()

    fun decodeAndStore(id: String, base64: String) {
        try {
            val bytes = Base64.getDecoder().decode(base64)
            avatars[id] = loadImageBitmap(ByteArrayInputStream(bytes))
        } catch (_: Exception) {
        }
    }

    /** Lazily decodes from persisted storage the first time a given
     *  contact's avatar is looked up — avoids decoding every avatar for
     *  every contact up front on app start. */
    fun loadIfMissing(contactId: String): ImageBitmap? {
        avatars[contactId]?.let { return it }
        val b64 = ChatStorage.getContactAvatar(contactId) ?: return null
        decodeAndStore(contactId, b64)
        return avatars[contactId]
    }
}
