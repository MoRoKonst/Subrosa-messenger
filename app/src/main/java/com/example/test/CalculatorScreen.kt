package com.bcon.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun CalculatorScreen(onUnlock: () -> Unit) {

    var display      by remember { mutableStateOf("0") }
    var pendingOp    by remember { mutableStateOf<String?>(null) }
    var pendingVal   by remember { mutableStateOf(0.0) }
    var pendingStr   by remember { mutableStateOf("") }
    var isNewInput   by remember { mutableStateOf(true) }

    val bgColor      = Color(0xFF000000)
    val topRowColor  = Color(0xFFA5A5A5)
    val opColor      = Color(0xFFFF9F0A)
    val digitColor   = Color(0xFF333333)
    val textDark     = Color(0xFF000000)
    val textLight    = Color(0xFFFFFFFF)

    fun fmt(v: Double): String {
        if (v.isNaN()) return "Ошибка"
        if (v.isInfinite()) return if (v > 0) "∞" else "-∞"
        return if (v == v.toLong().toDouble()) v.toLong().toString()
        else v.toBigDecimal().stripTrailingZeros().toPlainString()
    }

    fun compute(): Double {
        val b = display.toDoubleOrNull() ?: 0.0
        return when (pendingOp) {
            "+" -> pendingVal + b
            "−" -> pendingVal - b
            "×" -> pendingVal * b
            "÷" -> if (b != 0.0) pendingVal / b else Double.NaN
            else -> b
        }
    }

    fun onDigit(d: String) {
        if (isNewInput) {
            display = d; isNewInput = false
        } else {
            if (display == "0" && d != ".") display = d
            else if (d == "." && display.contains(".")) return
            else if (display.length >= 12) return
            else display += d
        }
    }

    fun onOperator(op: String) {
        if (pendingOp != null && !isNewInput) {
            val result = compute()
            pendingVal = result; pendingStr = fmt(result); display = fmt(result)
        } else {
            pendingVal = display.toDoubleOrNull() ?: 0.0; pendingStr = display
        }
        pendingOp = op; isNewInput = true
    }

    fun onEquals() {
        if (pendingOp == null) return

        if (pendingStr == "4" && pendingOp == "+" && display == "20") {
            onUnlock()
            return
        }

        val result = compute()
        display = fmt(result)
        pendingOp = null; pendingStr = ""; isNewInput = true
    }

    fun onClear() {
        display = "0"; pendingOp = null
        pendingVal = 0.0; pendingStr = ""; isNewInput = true
    }

    fun onSign() {
        val v = display.toDoubleOrNull() ?: return; display = fmt(-v)
    }

    fun onPercent() {
        val v = display.toDoubleOrNull() ?: return; display = fmt(v / 100.0)
    }

    data class CalcBtn(val label: String, val weight: Float = 1f, val bg: Color, val fg: Color)

    val rows = listOf(
        listOf(
            CalcBtn("C",   bg = topRowColor, fg = textDark),
            CalcBtn("+/−", bg = topRowColor, fg = textDark),
            CalcBtn("%",   bg = topRowColor, fg = textDark),
            CalcBtn("÷",   bg = opColor,     fg = textLight)
        ),
        listOf(
            CalcBtn("7", bg = digitColor, fg = textLight),
            CalcBtn("8", bg = digitColor, fg = textLight),
            CalcBtn("9", bg = digitColor, fg = textLight),
            CalcBtn("×", bg = opColor,    fg = textLight)
        ),
        listOf(
            CalcBtn("4", bg = digitColor, fg = textLight),
            CalcBtn("5", bg = digitColor, fg = textLight),
            CalcBtn("6", bg = digitColor, fg = textLight),
            CalcBtn("−", bg = opColor,    fg = textLight)
        ),
        listOf(
            CalcBtn("1", bg = digitColor, fg = textLight),
            CalcBtn("2", bg = digitColor, fg = textLight),
            CalcBtn("3", bg = digitColor, fg = textLight),
            CalcBtn("+", bg = opColor,    fg = textLight)
        ),
        listOf(
            CalcBtn("0", weight = 2f, bg = digitColor, fg = textLight),
            CalcBtn(".", bg = digitColor, fg = textLight),
            CalcBtn("=", bg = opColor,    fg = textLight)
        )
    )

    Column(
        Modifier
            .fillMaxSize()
            .background(bgColor)
            .systemBarsPadding()
            .padding(bottom = 12.dp),
        verticalArrangement = Arrangement.Bottom
    ) {

        Column(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.End
        ) {
            if (pendingOp != null) {
                Text(
                    "$pendingStr $pendingOp",
                    fontSize = 20.sp,
                    color = Color.White.copy(alpha = 0.45f),
                    textAlign = TextAlign.End
                )
            }
            val fs = when {
                display.length > 11 -> 34.sp
                display.length > 8  -> 46.sp
                else                -> 64.sp
            }
            Text(
                display,
                fontSize = fs,
                fontWeight = FontWeight.Light,
                color = Color.White,
                textAlign = TextAlign.End,
                maxLines = 1
            )
        }

        Spacer(Modifier.height(4.dp))

        Column(
            Modifier.padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            rows.forEach { row ->
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    row.forEach { btn ->
                        val isWide = btn.weight > 1f
                        val shape  = if (isWide) RoundedCornerShape(50) else CircleShape
                        Box(
                            Modifier
                                .weight(btn.weight)
                                .aspectRatio(if (isWide) 2.1f else 1f)
                                .clip(shape)
                                .background(btn.bg)
                                .clickable {
                                    when (btn.label) {
                                        "C"   -> onClear()
                                        "+/−" -> onSign()
                                        "%"   -> onPercent()
                                        "="   -> onEquals()
                                        "÷", "×", "−", "+" -> onOperator(btn.label)
                                        else  -> onDigit(btn.label)
                                    }
                                },
                            contentAlignment = if (isWide) Alignment.CenterStart else Alignment.Center
                        ) {
                            Text(
                                btn.label,
                                fontSize = 28.sp,
                                color = btn.fg,
                                fontWeight = FontWeight.Normal,
                                modifier = if (isWide) Modifier.padding(start = 34.dp) else Modifier
                            )
                        }
                    }
                }
            }
        }
    }
}
