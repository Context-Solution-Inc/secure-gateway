package com.contextsolutions.securegateway.core.transport;

/**
 * The connection states surfaced to the host app via {@code onStateChange} (PRD §8).
 * {@link #SUPERSEDED} and {@link #REVOKED} are terminal (do not auto-reconnect, per
 * Appendix B close codes 4001/4004); {@link #PEER_OFFLINE} is a sub-state of an otherwise
 * live connection.
 */
public enum ConnectionState {
    CONNECTED,
    RECONNECTING,
    PEER_OFFLINE,
    REVOKED,
    SUPERSEDED
}
