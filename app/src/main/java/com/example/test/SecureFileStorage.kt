package com.subrosa.messenger

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import java.io.File

object SecureFileStorage {

    private fun masterKeyAlias(): String =
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    /** Opaque on-disk path for a received/sent attachment blob — a flat
     *  `blobs/` directory with no type-revealing prefix (`image_`, `voice_`,
     *  `videos/`) or fake original extension (`.jpg`, `.3gp`, `.mp4`), so
     *  browsing the app's private storage (e.g. an ADB backup or a rooted
     *  device before the EncryptedFile key is compromised) doesn't reveal
     *  attachment type by filename alone. The real filename is already
     *  tracked separately as message metadata (`ChatStorage.fileName`), so
     *  nothing is lost by making the path itself meaningless. */
    fun blobFile(baseDir: File, id: String): File = File(baseDir, "blobs/$id.enc")

    fun write(context: Context, file: File, bytes: ByteArray) {
        file.parentFile?.mkdirs()
        if (file.exists()) file.delete()
        EncryptedFile.Builder(
            file,
            context,
            masterKeyAlias(),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build().openFileOutput().use { it.write(bytes) }
    }

    fun read(context: Context, file: File): ByteArray =
        EncryptedFile.Builder(
            file,
            context,
            masterKeyAlias(),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build().openFileInput().use { it.readBytes() }

    fun decryptToTemp(context: Context, encFile: File, tempFileName: String): File {
        val bytes = read(context, encFile)
        val temp = File(context.cacheDir, "tmp_$tempFileName")
        temp.writeBytes(bytes)
        return temp
    }

    fun cleanupTemp(context: Context) {
        context.cacheDir.listFiles()?.forEach { file ->
            if (file.name.startsWith("tmp_")) file.delete()
        }
    }
}
