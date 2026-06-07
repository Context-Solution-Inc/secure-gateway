package com.securegateway.core.transport;

/** A {@code send()} failed because the relay reported the peer is offline (FR-4.4). */
public final class PeerOfflineException extends RuntimeException {
    public PeerOfflineException() {
        super("peer is offline");
    }
}
