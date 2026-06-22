package com.contextsolutions.securegateway.core;

/**
 * The device's role on a pairing. Determines the E2EE key direction and the
 * connection-token {@code role} claim, exactly as in the Go reference
 * ({@code internal/token}): mobile seals with K_m2d, desktop seals with K_d2m.
 */
public enum Role {
    MOBILE("mobile"),
    DESKTOP("desktop");

    private final String wire;

    Role(String wire) {
        this.wire = wire;
    }

    /** The wire string used in JSON/JWT claims ("mobile" / "desktop"). */
    public String wire() {
        return wire;
    }

    public static Role fromWire(String s) {
        for (Role r : values()) {
            if (r.wire.equals(s)) {
                return r;
            }
        }
        throw new IllegalArgumentException("unknown role: " + s);
    }
}
