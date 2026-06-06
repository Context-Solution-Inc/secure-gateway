package com.securegateway.core;

import java.util.Arrays;

/**
 * Drives the per-session handshake (PRD FR-5.2): each side generates a fresh 32-byte
 * handshake nonce and exchanges it in the first frame of the session, then both derive
 * the directional {@link Session} keys.
 *
 * <p>The Go reference {@code e2ee} package only <em>models</em> this exchange (its tests
 * hand both nonces to both sides); the SDK implements the actual in-band exchange. Because
 * the relay payload is opaque, the SDK carries its own self-describing frame inside the
 * {@code msg} payload: a 1-byte tag distinguishes a cleartext handshake nonce
 * ({@link #TAG_HANDSHAKE}) from an encrypted application frame ({@link #TAG_DATA}). The
 * handshake nonce is not secret, so it travels in cleartext before the session exists.
 */
public final class HandshakeCoordinator {

    /** First payload byte: cleartext 32-byte handshake nonce follows. */
    public static final byte TAG_HANDSHAKE = 0x01;
    /** First payload byte: encrypted application frame (sealed wire bytes) follows. */
    public static final byte TAG_DATA = 0x02;

    private final byte[] myPriv;
    private final byte[] peerPub;
    private final Role myRole;
    private final byte[] myNonce;

    private byte[] peerNonce;
    private Session session;

    public HandshakeCoordinator(byte[] myPriv, byte[] peerPub, Role myRole) {
        this.myPriv = myPriv.clone();
        this.peerPub = peerPub.clone();
        this.myRole = myRole;
        this.myNonce = Crypto.newHandshakeNonce();
    }

    /** The frame to send first: {@code [TAG_HANDSHAKE] || myNonce(32)}. */
    public byte[] handshakeFrame() {
        return tagged(TAG_HANDSHAKE, myNonce);
    }

    /**
     * Feed a received frame's payload. If it is the peer's handshake nonce, the session
     * is built (once both nonces are known) and {@code null} is returned. If it is an
     * application frame, the decrypted plaintext is returned (requires an established
     * session and the envelope's {@code id}/{@code ts} for AEAD binding).
     */
    public byte[] onFrame(byte[] payload, String id, long ts) {
        if (payload.length == 0) {
            throw new IllegalArgumentException("empty session frame");
        }
        byte tag = payload[0];
        byte[] body = Arrays.copyOfRange(payload, 1, payload.length);
        if (tag == TAG_HANDSHAKE) {
            acceptPeerNonce(body);
            return null;
        }
        if (tag == TAG_DATA) {
            if (session == null) {
                throw new IllegalStateException("data frame before handshake complete");
            }
            return session.open(id, ts, body);
        }
        throw new IllegalArgumentException("unknown session frame tag: " + tag);
    }

    /** Seal application plaintext into a {@code [TAG_DATA] || sealed} frame. */
    public byte[] sealFrame(String id, long ts, byte[] plaintext) {
        if (session == null) {
            throw new IllegalStateException("cannot seal before handshake complete");
        }
        return tagged(TAG_DATA, session.seal(id, ts, plaintext));
    }

    public boolean isComplete() {
        return session != null;
    }

    public Session session() {
        return session;
    }

    private void acceptPeerNonce(byte[] nonce) {
        if (nonce.length != Crypto.HANDSHAKE_NONCE_SIZE) {
            throw new IllegalArgumentException("peer handshake nonce must be "
                    + Crypto.HANDSHAKE_NONCE_SIZE + " bytes");
        }
        this.peerNonce = nonce.clone();
        // Salt is always mobile-nonce-first, fixed by role (not by who initiated).
        byte[] mobileNonce = myRole == Role.MOBILE ? myNonce : peerNonce;
        byte[] desktopNonce = myRole == Role.MOBILE ? peerNonce : myNonce;
        this.session = Session.create(myPriv, peerPub, myRole, mobileNonce, desktopNonce);
    }

    private static byte[] tagged(byte tag, byte[] body) {
        byte[] out = new byte[1 + body.length];
        out[0] = tag;
        System.arraycopy(body, 0, out, 1, body.length);
        return out;
    }
}
