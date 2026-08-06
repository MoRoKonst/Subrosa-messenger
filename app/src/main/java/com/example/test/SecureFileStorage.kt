package com.subrosa.messenger

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import java.io.File

object SecureFileStorage {

    private fun masterKeyAlias(): String =
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

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
