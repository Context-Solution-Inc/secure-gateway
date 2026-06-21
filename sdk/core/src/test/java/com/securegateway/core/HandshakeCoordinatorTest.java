package com.securegateway.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class HandshakeCoordinatorTest {

    @Test
    void exchangeBuildsSessionsThatInterop() {
        KeyPair mobile = Crypto.generateKeyPair();
        KeyPair desktop = Crypto.generateKeyPair();

        HandshakeCoordinator m = new HandshakeCoordinator(mobile.privateKey(), desktop.publicKey(), Role.MOBILE);
        HandshakeCoordinator d = new HandshakeCoordinator(desktop.privateKey(), mobile.publicKey(), Role.DESKTOP);

        assertFalse(m.isComplete());
        assertFalse(d.isComplete());

        // Exchange handshake frames (cleartext nonces).
        assertNull(d.onFrame(m.handshakeFrame(), "h", 0));
        assertNull(m.onFrame(d.handshakeFrame(), "h", 0));

        assertTrue(m.isComplete());
        assertTrue(d.isComplete());

        // mobile -> desktop application frame round-trips through the framing.
        byte[] plain = "hello from mobile".getBytes(StandardCharsets.UTF_8);
        byte[] frame = m.sealFrame("id-md", 100L, plain);
        assertEquals(HandshakeCoordinator.TAG_DATA, frame[0]);
        byte[] opened = d.onFrame(frame, "id-md", 100L);
        assertArrayEquals(plain, opened);

        // desktop -> mobile, other direction.
        byte[] plain2 = "ack from desktop".getBytes(StandardCharsets.UTF_8);
        byte[] opened2 = m.onFrame(d.sealFrame("id-dm", 200L, plain2), "id-dm", 200L);
        assertArrayEquals(plain2, opened2);
    }

    // SG-15 regression: a replayed handshake frame must NOT reset the per-session
    // anti-replay window (SG-02). The handshake is one-shot, so re-feeding the peer's
    // original handshake frame is ignored and a replayed data frame is still rejected.
    @Test
    void handshakeIsOneShotAndPreservesReplayGuard() {
        KeyPair mobile = Crypto.generateKeyPair();
        KeyPair desktop = Crypto.generateKeyPair();
        HandshakeCoordinator m = new HandshakeCoordinator(mobile.privateKey(), desktop.publicKey(), Role.MOBILE);
        HandshakeCoordinator d = new HandshakeCoordinator(desktop.privateKey(), mobile.publicKey(), Role.DESKTOP);

        byte[] mHandshake = m.handshakeFrame();
        assertNull(d.onFrame(mHandshake, "h", 0));
        assertNull(m.onFrame(d.handshakeFrame(), "h", 0));
        assertTrue(d.isComplete());
        Session established = d.session();

        // Deliver an application frame once.
        byte[] plain = "command-1".getBytes(StandardCharsets.UTF_8);
        byte[] data = m.sealFrame("id-1", 1_000L, plain);
        assertArrayEquals(plain, d.onFrame(data, "id-1", 1_000L));

        // A malicious relay re-injects the peer's original handshake frame. It must be
        // ignored: the session (and its replay guard) is unchanged, not rebuilt.
        assertNull(d.onFrame(mHandshake, "h", 0));
        assertSame(established, d.session(), "handshake must not rebuild the session");

        // Replaying the already-delivered data frame must now be rejected.
        assertThrows(Session.ReplayException.class, () -> d.onFrame(data, "id-1", 1_000L));
    }

    private static void assertSame(Object expected, Object actual, String msg) {
        org.junit.jupiter.api.Assertions.assertSame(expected, actual, msg);
    }

    private static void assertEquals(byte expected, byte actual) {
        org.junit.jupiter.api.Assertions.assertEquals(expected, actual);
    }
}
