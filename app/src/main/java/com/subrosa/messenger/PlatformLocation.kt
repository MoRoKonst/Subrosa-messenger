package com.subrosa.messenger

import android.content.Context
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Looper
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Location via the Android platform only, with no Google Play Services.
 *
 * Replaces FusedLocationProviderClient, which was the app's last dependency on
 * `com.google.android.gms`. Dropping it is what actually makes an F-Droid build
 * possible: removing Firebase alone was not enough, because
 * play-services-location pulled play-services-basement (and with it a handful
 * of Firebase classes) into the APK regardless of the flavour.
 *
 * Deliberately the same two-step shape the fused client was used with, so
 * behaviour stays recognisable:
 *   1. any cached fix, newest-provider-first, which is instant when available;
 *   2. failing that, one live fix, abandoned after [timeoutMs].
 *
 * Honest trade-off: the fused provider fuses GPS, wifi and cell signals and is
 * usually faster and more accurate indoors. The platform API picks a single
 * provider. For attaching a location to a message that is an acceptable loss;
 * for turn-by-turn navigation it would not be.
 *
 * Every call is wrapped in runCatching because the caller may lack
 * ACCESS_FINE_LOCATION / ACCESS_COARSE_LOCATION, in which case the platform
 * throws SecurityException. A missing permission yields null rather than a
 * crash, matching how the fused client's failure listener was handled.
 */
object PlatformLocation {

    // PASSIVE last: it only ever returns a fix some other app already
    // requested, so it is a free bonus rather than something to rely on.
    private val PROVIDERS = listOf(
        LocationManager.GPS_PROVIDER,
        LocationManager.NETWORK_PROVIDER,
        LocationManager.PASSIVE_PROVIDER,
    )

    suspend fun lastOrFresh(context: Context, timeoutMs: Long = 30_000L): Location? {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return null

        for (provider in PROVIDERS) {
            runCatching { lm.getLastKnownLocation(provider) }.getOrNull()?.let { return it }
        }

        val live = PROVIDERS.firstOrNull { p ->
            // PASSIVE is excluded here: requesting updates from it can wait
            // forever, since it never activates any hardware of its own.
            p != LocationManager.PASSIVE_PROVIDER &&
                runCatching { lm.isProviderEnabled(p) }.getOrDefault(false)
        } ?: return null

        return withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine { cont ->
                val listener = object : LocationListener {
                    override fun onLocationChanged(location: Location) {
                        runCatching { lm.removeUpdates(this) }
                        if (cont.isActive) cont.resume(location, null)
                    }

                    // Required on API < 30; no-ops here. A provider going away
                    // mid-request is covered by the timeout rather than by
                    // resuming null, so a second provider still has a chance.
                    override fun onProviderEnabled(provider: String) {}
                    override fun onProviderDisabled(provider: String) {}

                    @Deprecated("Required by LocationListener below API 30")
                    override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) {}
                }

                cont.invokeOnCancellation { runCatching { lm.removeUpdates(listener) } }

                val requested = runCatching {
                    lm.requestLocationUpdates(live, 0L, 0f, listener, Looper.getMainLooper())
                }.isSuccess

                if (!requested && cont.isActive) cont.resume(null, null)
            }
        }
    }
}
