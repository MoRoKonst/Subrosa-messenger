package com.subrosa.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.osmdroid.config.Configuration
import org.osmdroid.tileprovider.tilesource.TileSourceFactory
import org.osmdroid.util.GeoPoint
import org.osmdroid.views.MapView
import org.osmdroid.views.overlay.Marker

@Composable
fun GeoLocationMap(
    latitude: Double,
    longitude: Double,
    modifier: Modifier = Modifier,
    isInteractive: Boolean = true,
    onClose: (() -> Unit)? = null
) {
    val context = LocalContext.current

    DisposableEffect(Unit) {
        Configuration.getInstance().userAgentValue = context.packageName
        onDispose { }
    }

    AndroidView(
        factory = { ctx ->
            MapView(ctx).apply {
                setTileSource(TileSourceFactory.MAPNIK)
                setMultiTouchControls(isInteractive)
                controller.setZoom(15.0)
                controller.setCenter(GeoPoint(latitude, longitude))
                val marker = Marker(this).apply {
                    position = GeoPoint(latitude, longitude)
                    setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_BOTTOM)
                    title = "📍"
                }
                overlays.add(marker)
            }
        },
        modifier = modifier
    )
}

@Composable
fun MapDialog(
    latitude: Double,
    longitude: Double,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current

    DisposableEffect(Unit) {
        Configuration.getInstance().userAgentValue = context.packageName
        onDispose { }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = true,
            dismissOnClickOutside = false
        )
    ) {
        Box(modifier = Modifier.fillMaxSize()) {

            AndroidView(
                factory = { ctx ->
                    MapView(ctx).apply {
                        setTileSource(TileSourceFactory.MAPNIK)
                        setMultiTouchControls(true)
                        controller.setZoom(15.0)
                        controller.setCenter(GeoPoint(latitude, longitude))
                        val marker = Marker(this).apply {
                            position = GeoPoint(latitude, longitude)
                            setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_BOTTOM)
                            title = "📍"
                            snippet = "${"%.5f".format(latitude)}, ${"%.5f".format(longitude)}"
                        }
                        overlays.add(marker)
                    }
                },
                modifier = Modifier.fillMaxSize()
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .align(Alignment.TopStart)
                    .background(Color(0xCC0A0A0A))
                    .statusBarsPadding()
                    .padding(horizontal = 4.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onDismiss) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = null,
                        tint = Color.White
                    )
                }
                Text(
                    "📍 Геопозиция",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontFamily = JetBrainsMono,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = {
                    val uri = android.net.Uri.parse("geo:$latitude,$longitude?q=$latitude,$longitude")
                    val intent = android.content.Intent(android.content.Intent.ACTION_VIEW, uri)
                    try {
                        context.startActivity(intent)
                        onDismiss()
                    } catch (e: Exception) {
                        android.util.Log.e("MapDialog", "Не удалось открыть карты: ${e.message}")
                    }
                }) {
                    Text("В картах", color = Color(0xFF00E5FF), fontFamily = JetBrainsMono, fontSize = 14.sp)
                }
            }
        }
    }
}
