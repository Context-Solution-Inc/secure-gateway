package com.securegateway.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Holds the two directional session keys for one connection session, built after
 * both handshake nonces have been exchanged. Mirrors the Go reference
 * {@code e2ee.Session}: keys are derived with HKDF-SHA256 over the X25519 shared
 * secret, with {@code salt = mobileNonce || desktopNonce} (mobile first, fixed by
 * role) and {@code info = "secure-gateway/e2ee/v1|" + dir}. Mobile seals with
 * K_m2d and opens with K_d2m; desktop is the reverse.
 */
public final class Session {

    /**
     * Envelope ts is unix-milliseconds (the relay protocol's ts unit); an inbound
     * envelope older than this many ms behind the highest seen ts is rejected.
     * Mirrors the Go reference {@code defaultReplayWindowMillis} (5 minutes).
     */
    static final long DEFAULT_REPLAY_WINDOW_MILLIS = 5L * 60L * 1000L;

    /** Thrown by {@link #open} when an envelope is a replay or outside the window (SG-02). */
    public static final class ReplayException extends RuntimeException {
        ReplayException(String message) {
            super(message);
        }
    }

    private final byte[] sendKey; // seals outbound (this device -> peer)
    private final byte[] recvKey; // opens inbound (peer -> this device)

    // Anti-replay state for inbound envelopes (SG-02), advanced only with id/ts
    // the AEAD has authenticated.
    private final long replayWindowMillis = DEFAULT_REPLAY_WINDOW_MILLIS;
    private final Map<String, Long> seen = new HashMap<>();
    private long lastTs;
    private boolean primed;

    private Session(byte[] sendKey, byte[] recvKey) {
        this.sendKey = sendKey;
        this.recvKey = recvKey;
    }

    /**
     * Derive the directional session keys. {@code mobileNonce}/{@code desktopNonce}
     * must each be {@link Crypto#HANDSHAKE_NONCE_SIZE} bytes and identical on both
     * devices.
     */
    public static Session create(byte[] myPriv, byte[] peerPub, Role role,
                                 byte[] mobileNonce, byte[] desktopNonce) {
        if (mobileNonce.length != Crypto.HANDSHAKE_NONCE_SIZE
                || desktopNonce.length != Crypto.HANDSHAKE_NONCE_SIZE) {
            throw new IllegalArgumentException(
                    "handshake nonces must be " + Crypto.HANDSHAKE_NONCE_SIZE + " bytes");
        }
        byte[] shared = Crypto.deriveSharedSecret(myPriv, peerPub);
        byte[] keyM2D = deriveKey(shared, mobileNonce, desktopNonce, Crypto.DIR_M2D);
        byte[] keyD2M = deriveKey(shared, mobileNonce, desktopNonce, Crypto.DIR_D2M);
        Arrays.fill(shared, (byte) 0);
        if (role == Role.MOBILE) {
            return new Session(keyM2D, keyD2M);
        }
        return new Session(keyD2M, keyM2D);
    }

    private static byte[] deriveKey(byte[] shared, byte[] mobileNonce, byte[] desktopNonce, String dir) {
        byte[] salt = new byte[mobileNonce.length + desktopNonce.length];
        System.arraycopy(mobileNonce, 0, salt, 0, mobileNonce.length);
        System.arraycopy(desktopNonce, 0, salt, mobileNonce.length, desktopNonce.length);
        byte[] info = (Crypto.INFO_PREFIX + dir).getBytes(StandardCharsets.UTF_8);
        return Hkdf.derive(shared, salt, info, Crypto.KEY_SIZE);
    }

    /**
     * Encrypt {@code plaintext} for the peer, binding {@code id}/{@code ts} as AEAD
     * associated data. Returns {@code nonce(24) || ciphertext}, ready to carry
     * verbatim as the envelope payload.
     */
    public byte[] seal(String id, long ts, byte[] plaintext) {
        return sealWith(Crypto.randomNonce(), id, ts, plaintext);
    }

    /** Seal with an explicit nonce — for deterministic interop vectors/tests. */
    byte[] sealWith(byte[] nonce, String id, long ts, byte[] plaintext) {
        byte[] ct = Crypto.aeadEncrypt(sendKey, nonce, Crypto.aad(id, ts), plaintext);
        byte[] wire = new byte[nonce.length + ct.length];
        System.arraycopy(nonce, 0, wire, 0, nonce.length);
        System.arraycopy(ct, 0, wire, nonce.length, ct.length);
        return wire;
    }

    /**
     * Decrypt a wire payload {@code nonce(24) || ciphertext} from the peer, checking
     * it against {@code id}/{@code ts}. Fails if the ciphertext, id, or ts was
     * tampered with.
     */
    public byte[] open(String id, long ts, byte[] wire) {
        if (wire.length < Crypto.NONCE_SIZE) {
            throw new IllegalArgumentException("ciphertext too short");
        }
        byte[] nonce = Arrays.copyOfRange(wire, 0, Crypto.NONCE_SIZE);
        byte[] ct = Arrays.copyOfRange(wire, Crypto.NONCE_SIZE, wire.length);
        byte[] pt = Crypto.aeadDecrypt(recvKey, nonce, Crypto.aad(id, ts), ct);
        // Reject duplicate delivery only after the AEAD has authenticated id/ts, so
        // forged metadata cannot advance the replay window (SG-02, FR-5.1).
        checkReplay(id, ts);
        return pt;
    }

    private synchronized void checkReplay(String id, long ts) {
        if (primed && ts < lastTs - replayWindowMillis) {
            throw new ReplayException("e2ee: timestamp outside replay window");
        }
        if (seen.containsKey(id)) {
            throw new ReplayException("e2ee: replay detected");
        }
        seen.put(id, ts);
        if (!primed || ts > lastTs) {
            lastTs = ts;
        }
        primed = true;
        long floor = lastTs - replayWindowMillis;
        for (Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator(); it.hasNext(); ) {
            if (it.next().getValue() < floor) {
                it.remove();
            }
        }
    }
}
