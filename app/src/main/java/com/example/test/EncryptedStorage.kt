package com.bcon.messenger

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object EncryptedStorage {

    private const val TAG = "EncryptedStorage"

    fun getEncryptedPrefs(context: Context, name: String): SharedPreferences {
        fun tryCreate(): SharedPreferences {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            return EncryptedSharedPreferences.create(
                context,
                name,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }

        try {
            return tryCreate()
        } catch (e: Exception) {
            Log.w(TAG, "[$name] Попытка 1 не удалась: ${e.message}")
        }

        try {
            Thread.sleep(300)
            return tryCreate()
        } catch (e: Exception) {
            Log.w(TAG, "[$name] Попытка 2 не удалась: ${e.message}")
        }

        Log.e(TAG, "[$name] Устойчивая ошибка — пересоздаём (данные недоступны в любом случае)")
        try {
            context.deleteSharedPreferences(name)
            return tryCreate()
        } catch (e: Exception) {

            Log.e(TAG, "[$name] Зашифрованное хранилище недоступно: ${e.message}")
            throw SecurityException("Зашифрованное хранилище '$name' недоступно. Возможно, AndroidKeyStore повреждён.", e)
        }
    }
}
