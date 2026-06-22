package com.contextsolutions.securegateway.core;

import java.util.Arrays;

/**
 * Drives the per-session handshake (PRD FR-5.2): each side generates a fresh
 * ephemeral X25519 keypair and exchanges its public half in the first frame of the
 * session, then both derive the directional {@link Session} keys (mixing the
 * ephemeral DH into the keying material for forward secrecy).
 *
 * <p>The Go reference {@code e2ee} package only <em>models</em> this exchange (its tests
 * hand both ephemeral keys to both sides); the SDK implements the actual in-band exchange.
 * Because the relay payload is opaque, the SDK carries its own self-describing frame inside
 * the {@code msg} payload: a 1-byte tag distinguishes a cleartext ephemeral public key
 * ({@link #TAG_HANDSHAKE}) from an encrypted application frame ({@link #TAG_DATA}). The
 * ephemeral public key is not secret, so it travels in cleartext before the session exists.
 */
public final class HandshakeCoordinator {

    /** First payload byte: cleartext 32-byte ephemeral public key follows. */
    public static final byte TAG_HANDSHAKE = 0x01;
    /** First payload byte: encrypted application frame (sealed wire bytes) follows. */
    public static final byte TAG_DATA = 0x02;

    private final byte[] idPriv;
    private final byte[] peerIdPub;
    private final Role myRole;
    private final byte[] ephPriv;
    private final byte[] ephPub;

    private Session session;
    /** The peer ephemeral public key that built {@link #session}; {@code null} until the first handshake. */
    private byte[] sessionPeerEphPub;

    public HandshakeCoordinator(byte[] idPriv, byte[] peerIdPub, Role myRole) {
        this.idPriv = idPriv.clone();
        this.peerIdPub = peerIdPub.clone();
        this.myRole = myRole;
        KeyPair eph = Crypto.generateKeyPair();
        this.ephPriv = eph.privateKey();
        this.ephPub = eph.publicKey();
    }

    /** The frame to send first: {@code [TAG_HANDSHAKE] || myEphemeralPublic(32)}. */
    public byte[] handshakeFrame() {
        return tagged(TAG_HANDSHAKE, ephPub);
    }

    /**
     * Feed a received frame's payload. If it is the peer's ephemeral public key, the
     * session is built and {@code null} is returned. If it is an application frame, the
     * decrypted plaintext is returned (requires an established session and the envelope's
     * {@code id}/{@code ts} for AEAD binding).
     */
    public byte[] onFrame(byte[] payload, String id, long ts) {
        if (payload.length == 0) {
            throw new IllegalArgumentException("empty session frame");
        }
        byte tag = payload[0];
        byte[] body = Arrays.copyOfRange(payload, 1, payload.length);
        if (tag == TAG_HANDSHAKE) {
            acceptPeerEphemeral(body);
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

    private void acceptPeerEphemeral(byte[] peerEphPub) {
        if (peerEphPub.length != Crypto.KEY_SIZE) {
            throw new IllegalArgumentException("peer ephemeral public key must be "
                    + Crypto.KEY_SIZE + " bytes");
        }
        // SG-15: an *identical* (replayed) peer handshake must be ignored, so a malicious/
        // compromised relay cannot re-inject the peer's original cleartext handshake frame to
        // mint a fresh Session with an empty anti-replay window (SG-02) and then replay
        // previously delivered data frames. We keep the established session + its replay state.
        if (session != null && Arrays.equals(peerEphPub, sessionPeerEphPub)) {
            return;
        }
        // A *different* ephemeral means the peer genuinely reconnected and re-keyed with a fresh
        // ephemeral (ConnectionManager.handleOpen builds a new HandshakeCoordinator on the peer's
        // side). We must rebuild to match — otherwise this side keeps stale session keys and every
        // subsequent data frame fails to AEAD-open and is silently dropped (the "green-but-hung
        // after reconnect" bug). A new ephemeral derives new keys, so no captured frame from the
        // old session decrypts under the new one — the SG-15 replay vector stays closed.
        this.sessionPeerEphPub = peerEphPub.clone();
        this.session = Session.create(idPriv, peerIdPub, ephPriv, sessionPeerEphPub, myRole);
    }

    private static byte[] tagged(byte tag, byte[] body) {
        byte[] out = new byte[1 + body.length];
        out[0] = tag;
        System.arraycopy(body, 0, out, 1, body.length);
        return out;
    }
}
