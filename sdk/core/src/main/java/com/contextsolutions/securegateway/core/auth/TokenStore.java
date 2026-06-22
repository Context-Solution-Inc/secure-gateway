package com.contextsolutions.securegateway.core.auth;

import java.time.Instant;

/**
 * Holds the current connection token and the rotating refresh token. The auth service
 * rotates the refresh token on every {@code /v1/token/refresh}, so {@link #update} must be
 * called with each fresh result to avoid reusing a consumed refresh token.
 */
public final class TokenStore {

    private String token;
    private String refreshToken;
    private Instant expiresAt = Instant.EPOCH;

    public synchronized void update(AuthClient.TokenResult r) {
        this.token = r.token;
        this.refreshToken = r.refreshToken;
        this.expiresAt = Instant.now().plusSeconds(Math.max(0, r.expiresIn));
    }

    public synchronized String token() {
        return token;
    }

    public synchronized String refreshToken() {
        return refreshToken;
    }

    public synchronized Instant expiresAt() {
        return expiresAt;
    }

    /** Whether the token is within {@code skewSeconds} of expiry (time to refresh). */
    public synchronized boolean needsRefresh(long skewSeconds) {
        return Instant.now().isAfter(expiresAt.minusSeconds(skewSeconds));
    }
}
