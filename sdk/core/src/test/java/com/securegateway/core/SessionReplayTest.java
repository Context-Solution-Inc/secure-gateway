package com.securegateway.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * SG-02 regression: the JVM Session must reject duplicate delivery of an
 * authenticated envelope, matching the Go reference behaviour.
 */
class SessionReplayTest {

    private static Session[] pair() {
        KeyPair m = Crypto.generateKeyPair();  // mobile identity
        KeyPair d = Crypto.generateKeyPair();  // desktop identity
        KeyPair me = Crypto.generateKeyPair(); // mobile ephemeral
        KeyPair de = Crypto.generateKeyPair(); // desktop ephemeral
        Session mobile = Session.create(m.privateKey(), d.publicKey(), me.privateKey(), de.publicKey(), Role.MOBILE);
        Session desktop = Session.create(d.privateKey(), m.publicKey(), de.privateKey(), me.publicKey(), Role.DESKTOP);
        return new Session[] {mobile, desktop};
    }

    @Test
    void replayOfSameEnvelopeIsRejected() {
        Session[] s = pair();
        Session mobile = s[0], desktop = s[1];
        byte[] plain = "deliver once".getBytes(StandardCharsets.UTF_8);
        byte[] wire = mobile.seal("id-1", 1_765_432_100_123L, plain);

        assertArrayEquals(plain, desktop.open("id-1", 1_765_432_100_123L, wire));
        assertThrows(Session.ReplayException.class,
                () -> desktop.open("id-1", 1_765_432_100_123L, wire));
    }

    @Test
    void staleTimestampIsRejected() {
        Session[] s = pair();
        Session mobile = s[0], desktop = s[1];
        // Advance the receive high-water mark.
        byte[] recent = mobile.seal("id-new", 10_000_000L, "recent".getBytes(StandardCharsets.UTF_8));
        desktop.open("id-new", 10_000_000L, recent);
        // A far-older authenticated message (outside the window) is refused.
        byte[] old = mobile.seal("id-old", 1L, "ancient".getBytes(StandardCharsets.UTF_8));
        assertThrows(Session.ReplayException.class, () -> desktop.open("id-old", 1L, old));
    }
}
