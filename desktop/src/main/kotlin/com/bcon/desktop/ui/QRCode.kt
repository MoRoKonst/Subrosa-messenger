package com.subrosa.desktop

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.client.j2se.BufferedImageLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import java.awt.image.BufferedImage
import java.io.File

/** Desktop port of Android's generateQRCode() (VerifyKeyScreen.kt) — same
 *  ZXing QRCodeWriter, same black/white pixel encoding, adapted to produce
 *  a Compose ImageBitmap instead of an android.graphics.Bitmap. */
fun generateQRCode(text: String, size: Int): ImageBitmap? {
    return try {
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(text, BarcodeFormat.QR_CODE, size, size)
        val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until size) {
            for (y in 0 until size) {
                image.setRGB(x, y, if (bitMatrix[x, y]) 0x000000 else 0xFFFFFF)
            }
        }
        image.toComposeImageBitmap()
    } catch (e: Exception) {
        null
    }
}

/** Add-contact-by-QR without a camera: the user loads an image file
 *  (screenshot or photo of a QR code shown on another device) instead of
 *  scanning it live, since most desktops don't have a convenient camera
 *  flow the way phones do. Returns the decoded text (the invite link), or
 *  null if no QR code could be found in the image. */
fun decodeQrFromFile(file: File): String? {
    return try {
        val image = javax.imageio.ImageIO.read(file) ?: return null
        val source = BufferedImageLuminanceSource(image)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        MultiFormatReader().decode(bitmap).text
    } catch (e: Exception) {
        null
    }
}
