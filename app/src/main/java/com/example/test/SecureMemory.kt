package com.bcon.messenger

object SecureMemory {

    fun wipe(data: ByteArray) {
        data.fill(0)
    }

    fun wipe(data: CharArray) {
        data.fill('\u0000')
    }

    fun wipe(data: String) {
        try {
            val valueField = String::class.java.getDeclaredField("value")
            valueField.isAccessible = true
            when (val value = valueField.get(data)) {
                is ByteArray -> value.fill(0)
                is CharArray -> value.fill('\u0000')
            }
        } catch (_: Exception) {

        }
    }
}
