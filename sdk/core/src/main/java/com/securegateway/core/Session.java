package com.securegateway.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Holds the two directional session keys for one connection session, built after
 * both ephemeral public keys have been exchanged. Mirrors the Go reference
 * {@code e2ee.Session}: keys are derived with HKDF-SHA256 over
 * {@code ikm = ss || ee || md || dm} (four X25519 shared secrets, Noise-KK style;
 * the ephemeral DH gives forward secrecy), with
 * {@code salt = mobileEphemeralPub || desktopEphemeralPub} (mobile first, fixed by
 * role) and {@code info = "secure-gateway/e2ee/v2|" + dir}. Mobile seals with
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
     * Derive the directional session keys for one connection. {@code idPriv}/
     * {@code peerIdPub} are this device's long-term identity private key and the
     * peer's long-term identity public key (exchanged at pairing); {@code ephPriv}/
     * {@code peerEphPub} are this session's ephemeral private key and the peer's
     * ephemeral public key (exchanged in the handshake). Mixing the ephemeral DH
     * into the keying material gives forward secrecy (FR-5.2); the identity DH
     * authenticates the peer. Mirrors the Go reference {@code e2ee.NewSession}.
     */
    public static Session create(byte[] idPriv, byte[] peerIdPub, byte[] ephPriv, byte[] peerEphPub, Role role) {
        byte[] myEphPub = Crypto.publicFromPrivate(ephPriv);
        // Four X25519 shared secrets (Noise-KK style):
        byte[] ss = Crypto.deriveSharedSecret(idPriv, peerIdPub);   // identity<->identity (auth)
        byte[] ee = Crypto.deriveSharedSecret(ephPriv, peerEphPub); // ephemeral<->ephemeral (FS)
        byte[] md;
        byte[] dm;
        if (role == Role.MOBILE) {
            md = Crypto.deriveSharedSecret(idPriv, peerEphPub);  // mobileIdentity <-> desktopEphemeral
            dm = Crypto.deriveSharedSecret(ephPriv, peerIdPub);  // desktopIdentity <-> mobileEphemeral
        } else {
            md = Crypto.deriveSharedSecret(ephPriv, peerIdPub);  // == DH(mobileIdentity, desktopEphemeral)
            dm = Crypto.deriveSharedSecret(idPriv, peerEphPub);  // == DH(desktopIdentity, mobileEphemeral)
        }
        byte[] ikm = concat(ss, ee, md, dm);

        byte[] mobileEphPub = role == Role.MOBILE ? myEphPub : peerEphPub;
        byte[] desktopEphPub = role == Role.MOBILE ? peerEphPub : myEphPub;
        byte[] salt = concat(mobileEphPub, desktopEphPub);

        byte[] keyM2D = deriveKey(ikm, salt, Crypto.DIR_M2D);
        byte[] keyD2M = deriveKey(ikm, salt, Crypto.DIR_D2M);
        Arrays.fill(ss, (byte) 0);
        Arrays.fill(ee, (byte) 0);
        Arrays.fill(md, (byte) 0);
        Arrays.fill(dm, (byte) 0);
        Arrays.fill(ikm, (byte) 0);
        if (role == Role.MOBILE) {
            return new Session(keyM2D, keyD2M);
        }
        return new Session(keyD2M, keyM2D);
    }

    private static byte[] deriveKey(byte[] ikm, byte[] salt, String dir) {
        byte[] info = (Crypto.INFO_PREFIX + dir).getBytes(StandardCharsets.UTF_8);
        return Hkdf.derive(ikm, salt, info, Crypto.KEY_SIZE);
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
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
