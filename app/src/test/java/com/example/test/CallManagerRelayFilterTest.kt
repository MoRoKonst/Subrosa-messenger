package com.subrosa.messenger

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Focused test for CallManager.isRelayCandidate() — the "Hide IP during
 * calls" defense-in-depth check (see createPeerConnection()'s
 * iceTransportsType=RELAY and queueIceCandidate()'s own comment) that
 * decides whether an outgoing ICE candidate is allowed to be signaled to the
 * peer while relay-only mode is active. The rest of CallManager needs a real
 * native PeerConnectionFactory and camera/mic access, so it isn't
 * practically unit-testable without much larger mocking infrastructure —
 * this is deliberately scoped to just the pure string-matching logic.
 */
@Config(sdk = [34])
@RunWith(RobolectricTestRunner::class)
class CallManagerRelayFilterTest {

    @Test
    fun `relay candidate is recognized`() {
        val sdp = "candidate:1 1 udp 41885439 34.203.116.144 54320 typ relay raddr 0.0.0.0 rport 0"
        assertTrue(CallManager.isRelayCandidate(sdp))
    }

    @Test
    fun `host candidate is rejected`() {
        val sdp = "candidate:1 1 udp 2122260223 192.168.1.5 54320 typ host generation 0"
        assertFalse(CallManager.isRelayCandidate(sdp))
    }

    @Test
    fun `server-reflexive candidate is rejected`() {
        val sdp = "candidate:2 1 udp 1686052607 203.0.113.9 54321 typ srflx raddr 192.168.1.5 rport 54320"
        assertFalse(CallManager.isRelayCandidate(sdp))
    }

    @Test
    fun `peer-reflexive candidate is rejected`() {
        val sdp = "candidate:3 1 udp 1685987071 203.0.113.9 54322 typ prflx raddr 192.168.1.5 rport 54321"
        assertFalse(CallManager.isRelayCandidate(sdp))
    }

    @Test
    fun `a candidate whose raddr happens to contain the word relay is not falsely matched`() {
        // Guards against a naive substring check (".contains("relay")")
        // instead of matching the actual "typ <token>" SDP attribute.
        val sdp = "candidate:4 1 udp 2122260223 relay.example.com 54320 typ host generation 0"
        assertFalse(CallManager.isRelayCandidate(sdp))
    }

    @Test
    fun `blank input is rejected`() {
        assertFalse(CallManager.isRelayCandidate(""))
    }
}
