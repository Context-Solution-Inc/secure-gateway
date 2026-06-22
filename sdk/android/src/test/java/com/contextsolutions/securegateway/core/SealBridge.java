package com.contextsolutions.securegateway.core;

/**
 * Test-only bridge that exposes {@link Session}'s package-private deterministic
 * {@code sealWith} (explicit nonce) to the Kotlin conformance test, which lives in a
 * different package. Production code uses {@link Session#seal} (random nonce); this
 * class exists solely to reproduce the fixed-nonce interop vectors.
 */
public final class SealBridge {

    private SealBridge() {
    }

    public static byte[] sealWith(Session session, byte[] nonce, String id, long ts, byte[] plaintext) {
        return session.sealWith(nonce, id, ts, plaintext);
    }
}
