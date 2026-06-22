package com.contextsolutions.securegateway.core;

/** Lowercase hex encode/decode, used for the interop vectors. */
public final class Hex {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0f];
        }
        return new String(out);
    }

    public static byte[] decode(String s) {
        int len = s.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("odd-length hex string");
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex character");
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
