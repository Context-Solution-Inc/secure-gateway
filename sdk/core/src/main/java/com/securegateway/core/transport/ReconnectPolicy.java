package com.securegateway.core.transport;

import java.util.Random;

/**
 * Exponential backoff with full jitter (PRD FR-1.5): {@code delay = random(0,
 * min(cap, base * 2^attempt))}, base 1s, cap 60s, reset on a successful connect.
 */
public final class ReconnectPolicy {

    private final long baseMillis;
    private final long capMillis;
    private final Random random = new Random();

    public ReconnectPolicy() {
        this(1_000L, 60_000L);
    }

    public ReconnectPolicy(long baseMillis, long capMillis) {
        this.baseMillis = baseMillis;
        this.capMillis = capMillis;
    }

    /** Backoff delay for a zero-based attempt count. */
    public long nextDelayMillis(int attempt) {
        long exp = capMillis;
        if (attempt < 32) {
            long shifted = baseMillis << attempt;
            exp = (shifted <= 0) ? capMillis : Math.min(capMillis, shifted);
        }
        // full jitter: uniform in [0, exp]
        return Math.floorMod(random.nextLong(), exp + 1);
    }
}
