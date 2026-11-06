package com.subrosa.desktop

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Backspace
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.KeyboardCapslock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.random.Random

/**
 * Password-style field with an optional on-screen keyboard.
 *
 * A hardware keylogger (USB inline device, or an OS-level low-level keyboard
 * hook such as Windows' WH_KEYBOARD_LL) intercepts real key-press events
 * before any application — including this one — ever sees them. There is no
 * userspace defense against that. Clicking a randomized on-screen layout with
 * the mouse sidesteps it entirely, since no keystroke is ever generated.
 *
 * While the on-screen keyboard is open, the field becomes read-only so a user
 * can't accidentally type the secret on the physical keyboard and lose the
 * protection they just turned on.
 */
@Composable
fun SecureTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    isError: Boolean = false,
    colors: TextFieldColors = profileFieldColors()
) {
    var showKeyboard by remember { mutableStateOf(false) }
    var layoutSeed by remember { mutableStateOf(0) }

    Column(modifier) {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            label = { Text(label) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            isError = isError,
            readOnly = showKeyboard,
            trailingIcon = {
                IconButton(onClick = {
                    if (!showKeyboard) layoutSeed++
                    showKeyboard = !showKeyboard
                }) {
                    Icon(
                        AppIcons.get("KEYBOARD"),
                        contentDescription = "Экранная клавиатура",
                        tint = if (showKeyboard) SubrosaTheme.accent else SubrosaTheme.textSecondary
                    )
                }
            },
            modifier = Modifier.fillMaxWidth(),
            colors = colors
        )
        if (showKeyboard) {
            Spacer(Modifier.height(6.dp))
            VirtualKeyboard(
                seed = layoutSeed,
                onChar = { c -> onValueChange(value + c) },
                onBackspace = { if (value.isNotEmpty()) onValueChange(value.dropLast(1)) }
            )
        }
    }
}

@Composable
fun VirtualKeyboard(seed: Int, onChar: (Char) -> Unit, onBackspace: () -> Unit) {
    var shifted by remember(seed) { mutableStateOf(false) }

    // Randomized each time the keyboard is (re)opened — defeats position-based
    // shoulder-surfing / screen-capture attacks that rely on a fixed layout.
    val rng = remember(seed) { Random(seed * 7919 + 17) }
    val digits  = remember(seed) { "1234567890".toList().shuffled(rng) }
    val letters = remember(seed) { ('a'..'z').toList().shuffled(rng) }
    val symbols = remember(seed) { "!@#\$%^&*()-_=+.,".toList().shuffled(rng) }
    val row1 = letters.subList(0, 10)
    val row2 = letters.subList(10, 19)
    val row3 = letters.subList(19, 26)

    Surface(
        shape = RoundedCornerShape(10.dp),
        color = SubrosaTheme.card,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            KeyRow(digits) { onChar(it) }
            KeyRow(row1) { c -> onChar(if (shifted) c.uppercaseChar() else c) }
            KeyRow(row2) { c -> onChar(if (shifted) c.uppercaseChar() else c) }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                KeyButton(
                    label = "⇧",
                    highlighted = shifted,
                    onClick = { shifted = !shifted },
                    modifier = Modifier.weight(1.3f)
                )
                row3.forEach { c ->
                    KeyButton(
                        label = (if (shifted) c.uppercaseChar() else c).toString(),
                        onClick = { onChar(if (shifted) c.uppercaseChar() else c) },
                        modifier = Modifier.weight(1f)
                    )
                }
                KeyButton(
                    icon = AppIcons.get("BACKSPACE"),
                    onClick = onBackspace,
                    modifier = Modifier.weight(1.3f)
                )
            }
            KeyRow(symbols) { onChar(it) }
            KeyButton(
                label = "пробел",
                onClick = { onChar(' ') },
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
private fun KeyRow(chars: List<Char>, onClick: (Char) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        chars.forEach { c ->
            KeyButton(label = c.toString(), onClick = { onClick(c) }, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun KeyButton(
    label: String? = null,
    icon: androidx.compose.ui.graphics.painter.Painter? = null,
    highlighted: Boolean = false,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(6.dp),
        color = if (highlighted) SubrosaTheme.accent.copy(alpha = 0.3f) else SubrosaTheme.cardAlt,
        modifier = modifier.height(36.dp)
    ) {
        TextButton(
            onClick = onClick,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(0.dp)
        ) {
            if (icon != null) {
                Icon(icon, contentDescription = null, tint = SubrosaTheme.textPrimary, modifier = Modifier.size(16.dp))
            } else {
                Text(label ?: "", fontSize = 15.sp, color = SubrosaTheme.textPrimary)
            }
        }
    }
}
