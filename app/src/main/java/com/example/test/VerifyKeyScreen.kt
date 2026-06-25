package com.bcon.messenger

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bcon.messenger.ui.theme.LocalBeaconColors
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifyKeyScreen(contactId: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val c = LocalBeaconColors.current
    val s = LocalStrings.current
    val contactName = ChatStorage.getContactName(context, contactId)

    val contactPublicKey = remember {
        ChatStorage.getContactPublicKey(context, contactId) ?: "unknown"
    }

    // contactId — это уже SHA-256(pubkey) первые 8 байт в hex uppercase (16 символов)
    val fingerprintHex = remember {
        contactId.chunked(2).joinToString(" ").lowercase()
    }

    // Emoji fingerprint через ту же функцию что на ProfileScreen
    val fingerprintEmoji = remember { fingerprintToEmoji(contactId) }

    val qrBitmap = remember { generateQRCode(fingerprintHex, 512) }
    var isVerified by remember { mutableStateOf(KeyHistoryManager.getHistory(context, contactId).lastOrNull()?.verified == true) }

    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        topBar = {
            TopAppBar(
                title = { Text(s.verifyScreenTitle, color = androidx.compose.ui.graphics.Color.White, fontFamily = JetBrainsMono) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, s.back, tint = androidx.compose.ui.graphics.Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd)))
                .padding(padding)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    s.verifyCheckKey,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = c.textPrimary,
                    fontFamily = JetBrainsMono,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                Text(
                    s.verifyContact(contactName),
                    fontSize = 16.sp,
                    color = c.accent,
                    fontFamily = JetBrainsMono,
                    modifier = Modifier.padding(bottom = 24.dp)
                )

                // ─── QR-код ───────────────────────────────────────────────────
                if (qrBitmap != null) {
                    Surface(
                        shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                        color = androidx.compose.ui.graphics.Color.White,
                        modifier = Modifier.size(272.dp)
                    ) {
                        Image(
                            bitmap = qrBitmap.asImageBitmap(),
                            contentDescription = "QR",
                            modifier = Modifier.size(256.dp).padding(8.dp)
                        )
                    }
                } else {
                    Text(s.verifyKeyNotFound, color = c.error, fontFamily = JetBrainsMono, fontSize = 14.sp)
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ─── Emoji fingerprint ────────────────────────────────────────
                Surface(
                    shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                    color = c.card,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            s.verifyEmojiLabel,
                            fontSize = 12.sp,
                            color = c.textPrimary.copy(alpha = 0.6f),
                            fontFamily = JetBrainsMono
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(fingerprintEmoji, fontSize = 32.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            s.verifyEmojiHint(contactName),
                            fontSize = 12.sp,
                            color = c.textPrimary.copy(alpha = 0.6f),
                            fontFamily = JetBrainsMono,
                            lineHeight = 18.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // ─── Hex fingerprint ──────────────────────────────────────────
                Text(s.verifyHexLabel, fontSize = 13.sp, color = c.textPrimary.copy(alpha = 0.6f), fontFamily = JetBrainsMono)
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
                    color = c.card,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                ) {
                    Text(
                        fingerprintHex,
                        fontSize = 12.sp,
                        fontFamily = JetBrainsMono,
                        color = c.accent,
                        modifier = Modifier.padding(16.dp),
                        lineHeight = 20.sp
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Text(
                    s.verifyHint,
                    fontSize = 13.sp,
                    color = c.textPrimary.copy(alpha = 0.6f),
                    fontFamily = JetBrainsMono,
                    modifier = Modifier.padding(horizontal = 16.dp),
                    lineHeight = 20.sp
                )

                Spacer(modifier = Modifier.height(16.dp))

                if (isVerified) {
                    Surface(
                        shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
                        color = c.accent.copy(alpha = 0.12f),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                    ) {
                        Text(
                            s.verifyAlreadyVerified,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = JetBrainsMono,
                            color = c.accent,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                } else {
                    Button(
                        onClick = {
                            KeyHistoryManager.markAsVerified(context, contactId)
                            isVerified = true
                        },
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = c.accent)
                    ) {
                        Text(s.verifyMarkVerified, fontFamily = JetBrainsMono, color = c.gradientStart)
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

fun generateQRCode(text: String, size: Int): Bitmap? {
    return try {
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(text, BarcodeFormat.QR_CODE, size, size)
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
            }
        }
        bitmap
    } catch (e: Exception) {
        null
    }
}
