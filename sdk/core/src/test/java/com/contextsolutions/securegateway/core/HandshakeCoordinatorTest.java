package com.contextsolutions.securegateway.core;

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

    // Peer-reconnect re-key: when the peer reconnects with a FRESH ephemeral (a genuinely new
    // handshake, not a replay), the survivor must rebuild its session to match — otherwise it
    // keeps stale keys and silently drops every subsequent data frame (the "green-but-hung after
    // reconnect" bug). The SG-15 replay guard is unaffected: the new ephemeral derives new keys,
    // so no frame captured under the old session decrypts under the new one.
    @Test
    void newPeerEphemeralRebuildsSession() {
        KeyPair mobile = Crypto.generateKeyPair();
        KeyPair desktop = Crypto.generateKeyPair();
        HandshakeCoordinator m = new HandshakeCoordinator(mobile.privateKey(), desktop.publicKey(), Role.MOBILE);
        HandshakeCoordinator d = new HandshakeCoordinator(desktop.privateKey(), mobile.publicKey(), Role.DESKTOP);

        assertNull(d.onFrame(m.handshakeFrame(), "h", 0));
        assertNull(m.onFrame(d.handshakeFrame(), "h", 0));
        Session established = d.session();

        // Original session works.
        byte[] p1 = "command-1".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(p1, d.onFrame(m.sealFrame("id-1", 1_000L, p1), "id-1", 1_000L));

        // Mobile genuinely reconnects: a fresh HandshakeCoordinator (new ephemeral, same identity).
        HandshakeCoordinator m2 = new HandshakeCoordinator(mobile.privateKey(), desktop.publicKey(), Role.MOBILE);
        // Survivor (desktop) re-keys on the new ephemeral...
        assertNull(d.onFrame(m2.handshakeFrame(), "h2", 0));
        assertNotSame(established, d.session(), "a new peer ephemeral must rebuild the session");
        // ...and the reconnected peer builds its session against the desktop's (unchanged) ephemeral.
        assertNull(m2.onFrame(d.handshakeFrame(), "h2", 0));

        // The re-keyed session interops.
        byte[] p2 = "command-2".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(p2, d.onFrame(m2.sealFrame("id-2", 2_000L, p2), "id-2", 2_000L));

        // A frame sealed under the OLD session no longer opens on the desktop (keys changed).
        byte[] stale = m.sealFrame("id-3", 3_000L, p2);
        assertThrows(RuntimeException.class, () -> d.onFrame(stale, "id-3", 3_000L));
    }

    private static void assertSame(Object expected, Object actual, String msg) {
        org.junit.jupiter.api.Assertions.assertSame(expected, actual, msg);
    }

    private static void assertNotSame(Object unexpected, Object actual, String msg) {
        org.junit.jupiter.api.Assertions.assertNotSame(unexpected, actual, msg);
    }

    private static void assertEquals(byte expected, byte actual) {
        org.junit.jupiter.api.Assertions.assertEquals(expected, actual);
    }
}
