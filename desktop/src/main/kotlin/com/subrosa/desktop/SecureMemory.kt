package com.subrosa.desktop

/**
 * Утилиты для безопасного зануления чувствительных данных в памяти.
 *
 * Правило: пароли и секреты храни как CharArray или ByteArray, а не String.
 * Java String — неизменяемый объект: его нельзя надёжно занулить, JVM может
 * создавать копии в intern-пуле, JIT может оставить значение в регистрах.
 */
object SecureMemory {

    /** Зануляет массив байтов. Работает надёжно. */
    fun wipe(data: ByteArray) {
        data.fill(0)
    }

    /**
     * Зануляет массив символов.
     * Пароли следует хранить как [CharArray], а не [String] — это позволяет
     * явно занулить их после использования.
     */
    fun wipe(data: CharArray) {
        data.fill('\u0000')
    }

    /**
     * Попытка зануления строки через рефлексию.
     *
     * **ВНИМАНИЕ:** Работает ненадёжно в Java 9+ из-за модульной системы
     * и может быть неэффективной из-за intern-пула и JIT-оптимизаций.
     * Для чувствительных данных используй [CharArray] или [ByteArray].
     */
    fun wipe(data: String) {
        try {
            val valueField = String::class.java.getDeclaredField("value")
            valueField.isAccessible = true
            when (val value = valueField.get(data)) {
                is ByteArray -> value.fill(0)        // Java 9+ compact strings (Latin-1)
                is CharArray -> value.fill('\u0000') // Java 8
            }
        } catch (_: Exception) {
            // Недоступно в Java 9+ с включёнными модульными ограничениями — это ожидаемо.
        }
    }
}
