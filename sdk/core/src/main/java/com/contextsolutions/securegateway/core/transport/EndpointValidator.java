package com.contextsolutions.securegateway.core.transport;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Validates relay/auth endpoints taken from the (untrusted) pairing QR before they are used to
 * open a connection. Transport security is mandatory — relay endpoints must be {@code wss://} and
 * auth endpoints must be {@code https://} — UNLESS the host is loopback or an RFC1918 private
 * address, the LAN-development carve-out where plaintext {@code ws://}/{@code http://} is allowed.
 *
 * <p>Without this a malicious QR could point the SDK at a {@code ws://} (or attacker-controlled)
 * endpoint, leaking the connection JWT (carried as an {@code Authorization: Bearer} header on the
 * upgrade) in cleartext. See security findings SG-14 (no {@code wss://} enforcement) and SG-19
 * (force-unwrapped URL on iOS). The Swift SDK mirrors this logic in {@code EndpointValidator.swift}.
 */
public final class EndpointValidator {

    private EndpointValidator() {
    }

    /** Returns {@code url} if it is a usable relay endpoint, else throws {@link IllegalArgumentException}. */
    public static String requireSecureRelay(String url) {
        return require(url, "ws", "wss", "relay");
    }

    /** Returns {@code url} if it is a usable auth endpoint, else throws {@link IllegalArgumentException}. */
    public static String requireSecureAuth(String url) {
        return require(url, "http", "https", "auth");
    }

    private static String require(String url, String plain, String secure, String what) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("missing " + what + " endpoint");
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("invalid " + what + " endpoint URL: " + url, e);
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null) {
            throw new IllegalArgumentException("invalid " + what + " endpoint URL: " + url);
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (scheme.equals(secure)) {
            return url;
        }
        if (scheme.equals(plain) && isPrivateOrLoopback(host)) {
            return url;
        }
        throw new IllegalArgumentException(
            "insecure " + what + " endpoint: " + url + " (require " + secure + ":// for non-private hosts)");
    }

    /** True for localhost, 127.0.0.0/8, ::1, and the RFC1918 ranges (10/8, 172.16/12, 192.168/16). */
    static boolean isPrivateOrLoopback(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        String h = host;
        if (h.startsWith("[") && h.endsWith("]")) { // bracketed IPv6 literal
            h = h.substring(1, h.length() - 1);
        }
        if (h.equalsIgnoreCase("localhost") || h.equals("::1")) {
            return true;
        }
        String[] parts = h.split("\\.");
        if (parts.length != 4) {
            return false; // not a dotted-quad IPv4 literal => treat as public
        }
        int[] o = new int[4];
        for (int i = 0; i < 4; i++) {
            try {
                o[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                return false;
            }
            if (o[i] < 0 || o[i] > 255) {
                return false;
            }
        }
        if (o[0] == 127) {
            return true; // 127.0.0.0/8 loopback
        }
        if (o[0] == 10) {
            return true; // 10.0.0.0/8
        }
        if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) {
            return true; // 172.16.0.0/12
        }
        return o[0] == 192 && o[1] == 168; // 192.168.0.0/16
    }
}
