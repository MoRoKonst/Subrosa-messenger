package com.subrosa.messenger

import android.graphics.Bitmap
import androidx.compose.runtime.mutableStateMapOf

object AvatarStore {

    val avatars = mutableStateMapOf<String, Bitmap>()
}
