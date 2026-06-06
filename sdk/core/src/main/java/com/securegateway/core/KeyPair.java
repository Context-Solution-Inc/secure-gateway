package com.securegateway.core;

/**
 * An X25519 keypair. The 32-byte private key never leaves the device (FR-2.3);
 * only the public key is exchanged during pairing.
 */
public final class KeyPair {

    private final byte[] privateKey;
    private final byte[] publicKey;

    public KeyPair(byte[] privateKey, byte[] publicKey) {
        if (privateKey.length != Crypto.KEY_SIZE || publicKey.length != Crypto.KEY_SIZE) {
            throw new IllegalArgumentException("X25519 keys must be " + Crypto.KEY_SIZE + " bytes");
        }
        this.privateKey = privateKey.clone();
        this.publicKey = publicKey.clone();
    }

    public byte[] privateKey() {
        return privateKey.clone();
    }

    public byte[] publicKey() {
        return publicKey.clone();
    }
}
