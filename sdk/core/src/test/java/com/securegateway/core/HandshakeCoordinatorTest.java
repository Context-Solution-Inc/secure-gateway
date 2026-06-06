package com.securegateway.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    private static void assertEquals(byte expected, byte actual) {
        org.junit.jupiter.api.Assertions.assertEquals(expected, actual);
    }
}
