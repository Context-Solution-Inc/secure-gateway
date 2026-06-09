package com.securegateway.core;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.interfaces.AEAD;
import com.goterl.lazysodium.interfaces.DiffieHellman;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.ServiceLoader;

/**
 * The E2EE crypto primitives (PRD FR-5), matching the Go reference
 * {@code internal/e2ee/e2ee.go} byte-for-byte. The interop vectors in
 * {@code internal/e2ee/testdata/vectors.json} are the cross-platform contract.
 *
 * <p>Scheme: X25519 ECDH (raw {@code crypto_scalarmult}, low-order points rejected)
 * &rarr; HKDF-SHA256 directional keys (see {@link Session}) &rarr; XChaCha20-Poly1305
 * IETF (24-byte nonce) with {@code wire = nonce(24) || ciphertext+tag(16)} and
 * {@code aad = utf8(id) || bigEndianUint64(ts)}.
 *
 * <p>X25519 and the AEAD come from native libsodium via lazysodium (the only
 * widely-available true 24-byte-nonce XChaCha20-Poly1305). HKDF is done with
 * {@link Hkdf} (RFC 5869 over HmacSHA256), since libsodium has no HKDF.
 */
public final class Crypto {

    /** X25519 key length and derived AEAD key length. */
    public static final int KEY_SIZE = 32;
    /** Per-session handshake nonce length each side contributes to the HKDF salt. */
    public static final int HANDSHAKE_NONCE_SIZE = 32;
    /** XChaCha20-Poly1305 nonce length, prepended to the ciphertext. */
    public static final int NONCE_SIZE = 24;
    /** Poly1305 authentication tag length. */
    public static final int TAG_SIZE = 16;

    static final String INFO_PREFIX = "secure-gateway/e2ee/v1|";
    static final String DIR_M2D = "m2d"; // mobile -> desktop
    static final String DIR_D2M = "d2m"; // desktop -> mobile

    // lazysodium is thread-safe (stateless native calls); share one instance. The
    // concrete binding (LazySodiumJava on the JVM, LazySodiumAndroid on device) is
    // supplied by the platform's registered SodiumProvider (see that interface).
    private static final LazySodium SODIUM = ServiceLoader.load(SodiumProvider.class)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException(
                    "crypto: no SodiumProvider registered on the classpath "
                            + "(META-INF/services/com.securegateway.core.SodiumProvider)"))
            .get();
    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {
    }

    static LazySodium sodium() {
        return SODIUM;
    }

    /** Generate a fresh X25519 keypair. */
    public static KeyPair generateKeyPair() {
        byte[] priv = new byte[KEY_SIZE];
        RANDOM.nextBytes(priv);
        return new KeyPair(priv, publicFromPrivate(priv));
    }

    /** Derive the X25519 public key for {@code priv} (== Go {@code PublicFromPrivate}). */
    public static byte[] publicFromPrivate(byte[] priv) {
        requireLen(priv, KEY_SIZE, "private key");
        byte[] pub = new byte[KEY_SIZE];
        if (!((DiffieHellman.Native) SODIUM).cryptoScalarMultBase(pub, priv)) {
            throw new IllegalStateException("crypto: scalarmult_base failed");
        }
        return pub;
    }

    /** Fresh 32-byte session handshake nonce. */
    public static byte[] newHandshakeNonce() {
        byte[] n = new byte[HANDSHAKE_NONCE_SIZE];
        RANDOM.nextBytes(n);
        return n;
    }

    /**
     * X25519 ECDH shared secret. Mirrors Go's low-order-point rejection: an
     * all-zero result (low-order peer public key) is rejected.
     */
    public static byte[] deriveSharedSecret(byte[] myPriv, byte[] peerPub) {
        requireLen(myPriv, KEY_SIZE, "private key");
        requireLen(peerPub, KEY_SIZE, "peer public key");
        byte[] shared = new byte[KEY_SIZE];
        boolean ok = ((DiffieHellman.Native) SODIUM).cryptoScalarMult(shared, myPriv, peerPub);
        if (!ok || isAllZero(shared)) {
            throw new IllegalArgumentException("crypto: ecdh failed (low-order point)");
        }
        return shared;
    }

    /**
     * XChaCha20-Poly1305 seal with an explicit nonce. Returns the AEAD ciphertext
     * (with appended tag) only — callers prepend the nonce to form the wire bytes.
     */
    static byte[] aeadEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        requireLen(key, KEY_SIZE, "key");
        requireLen(nonce, NONCE_SIZE, "nonce");
        byte[] pt = plaintext == null ? new byte[0] : plaintext;
        byte[] ct = new byte[pt.length + TAG_SIZE];
        long[] ctLen = new long[1];
        boolean ok = ((AEAD.Native) SODIUM).cryptoAeadXChaCha20Poly1305IetfEncrypt(
                ct, ctLen, pt, pt.length, aad, aad.length, null, nonce, key);
        if (!ok) {
            throw new IllegalStateException("crypto: aead encrypt failed");
        }
        if (ctLen[0] != ct.length) {
            ct = Arrays.copyOf(ct, (int) ctLen[0]);
        }
        return ct;
    }

    /** XChaCha20-Poly1305 open. {@code ct} is ciphertext+tag (no nonce). */
    static byte[] aeadDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ct) {
        requireLen(key, KEY_SIZE, "key");
        requireLen(nonce, NONCE_SIZE, "nonce");
        if (ct.length < TAG_SIZE) {
            throw new IllegalArgumentException("crypto: ciphertext too short");
        }
        byte[] pt = new byte[ct.length - TAG_SIZE];
        long[] ptLen = new long[1];
        boolean ok = ((AEAD.Native) SODIUM).cryptoAeadXChaCha20Poly1305IetfDecrypt(
                pt, ptLen, null, ct, ct.length, aad, aad.length, nonce, key);
        if (!ok) {
            throw new IllegalArgumentException("crypto: aead open failed (tampered or wrong key)");
        }
        if (ptLen[0] != pt.length) {
            pt = Arrays.copyOf(pt, (int) ptLen[0]);
        }
        return pt;
    }

    /** AEAD associated data: utf8(id) followed by big-endian uint64(ts). */
    static byte[] aad(String id, long ts) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(idBytes.length + 8)
                .order(ByteOrder.BIG_ENDIAN)
                .put(idBytes)
                .putLong(ts)
                .array();
    }

    static byte[] randomNonce() {
        byte[] n = new byte[NONCE_SIZE];
        RANDOM.nextBytes(n);
        return n;
    }

    private static boolean isAllZero(byte[] b) {
        int acc = 0;
        for (byte x : b) {
            acc |= x;
        }
        return acc == 0;
    }

    private static void requireLen(byte[] b, int len, String what) {
        if (b == null || b.length != len) {
            throw new IllegalArgumentException("crypto: " + what + " must be " + len + " bytes");
        }
    }
}
