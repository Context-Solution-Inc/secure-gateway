package com.contextsolutions.securegateway.core;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA256 (RFC 5869), implemented on {@code javax.crypto.Mac("HmacSHA256")}.
 *
 * <p>This is deliberately <em>not</em> routed through libsodium: libsodium has no
 * HKDF, and its {@code crypto_kdf} is a BLAKE2b construction that would not match
 * the Go reference's {@code golang.org/x/crypto/hkdf}. This class reproduces Go's
 * {@code hkdf.New(sha256.New, ikm, salt, info)} byte-for-byte, validated against the
 * {@code key_m2d}/{@code key_d2m} fields of the interop vectors.
 */
final class Hkdf {

    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32;

    private Hkdf() {
    }

    /** Derive {@code length} bytes from input keying material per RFC 5869. */
    static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            byte[] prk = extract(salt, ikm);
            return expand(prk, info, length);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("hkdf: " + e.getMessage(), e);
        }
    }

    // PRK = HMAC-SHA256(key = salt, msg = ikm). Go uses an all-zero salt when none
    // is supplied, but the relay scheme always supplies the 64-byte handshake salt.
    private static byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        byte[] key = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key, HMAC));
        return mac.doFinal(ikm);
    }

    // T(n) = HMAC(PRK, T(n-1) || info || n), output = T(1) || T(2) || ... truncated.
    private static byte[] expand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(prk, HMAC));
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        byte counter = 1;
        while (pos < length) {
            mac.update(t);
            if (info != null) {
                mac.update(info);
            }
            mac.update(counter);
            t = mac.doFinal();
            int n = Math.min(t.length, length - pos);
            System.arraycopy(t, 0, out, pos, n);
            pos += n;
            counter++;
        }
        Arrays.fill(t, (byte) 0);
        return out;
    }
}
