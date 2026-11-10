package com.subrosa.messenger

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Looper
import androidx.core.content.ContextCompat
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
 */
object PlatformLocation {

    // PASSIVE last: it only ever returns a fix some other app already
    // requested, so it is a free bonus rather than something to rely on.
    private val PROVIDERS = listOf(
        LocationManager.GPS_PROVIDER,
        LocationManager.NETWORK_PROVIDER,
        LocationManager.PASSIVE_PROVIDER,
    )

    /**
     * True when either location permission is granted.
     *
     * Checked explicitly rather than relying on catching SecurityException.
     * The first version of this file wrapped every platform call in
     * runCatching, which silently turned "the user denied location" into the
     * same null as "no fix available yet" -- and lint was right to reject it
     * (MissingPermission): a caught exception is not a permission check, and
     * the two cases deserve different handling by the caller if it ever wants
     * to prompt.
     */
    fun hasPermission(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

    /**
     * A cached fix if one exists, otherwise one live fix, otherwise null.
     *
     * Returns null without touching the platform when permission is missing.
     * SecurityException is still caught around the calls themselves: a
     * permission can be revoked between the check and the call, and on some
     * OEM builds a provider can refuse even with permission granted.
     */
    suspend fun lastOrFresh(context: Context, timeoutMs: Long = 30_000L): Location? {
        if (!hasPermission(context)) return null

        val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return null

        for (provider in PROVIDERS) {
            val cached = try {
                lm.getLastKnownLocation(provider)
            } catch (_: SecurityException) {
                return null
            } catch (_: IllegalArgumentException) {
                // Provider not present on this device (common for GPS on
                // tablets and emulators) -- try the next one.
                null
            }
            if (cached != null) return cached
        }

        val live = PROVIDERS.firstOrNull { p ->
            // PASSIVE is excluded here: requesting updates from it can wait
            // forever, since it never activates any hardware of its own.
            p != LocationManager.PASSIVE_PROVIDER &&
                try {
                    lm.isProviderEnabled(p)
                } catch (_: IllegalArgumentException) {
                    false
                }
        } ?: return null

        return withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine { cont ->
                val listener = object : LocationListener {
                    override fun onLocationChanged(location: Location) {
                        try {
                            lm.removeUpdates(this)
                        } catch (_: SecurityException) {
                            // Nothing useful to do; the fix is already in hand.
                        }
                        if (cont.isActive) cont.resume(location, null)
                    }

                    // Required on API < 30; no-ops here. A provider going away
                    // mid-request is covered by the timeout rather than by
                    // resuming null, so the caller still gets its 30s.
                    override fun onProviderEnabled(provider: String) {}
                    override fun onProviderDisabled(provider: String) {}

                    @Deprecated("Required by LocationListener below API 30")
                    override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) {}
                }

                cont.invokeOnCancellation {
                    try {
                        lm.removeUpdates(listener)
                    } catch (_: SecurityException) {
                        // Permission revoked while waiting; nothing to clean up.
                    }
                }

                try {
                    lm.requestLocationUpdates(live, 0L, 0f, listener, Looper.getMainLooper())
                } catch (_: SecurityException) {
                    if (cont.isActive) cont.resume(null, null)
                } catch (_: IllegalArgumentException) {
                    if (cont.isActive) cont.resume(null, null)
                }
            }
        }
    }
}
