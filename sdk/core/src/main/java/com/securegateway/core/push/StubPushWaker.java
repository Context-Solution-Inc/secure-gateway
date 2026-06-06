package com.securegateway.core.push;

import java.util.concurrent.CompletableFuture;

/**
 * Test {@link PushWaker} whose wake can be fired manually, standing in for FCM/APNs in the
 * cross-platform E2E (the host app + push services are out of this repo).
 */
public final class StubPushWaker implements PushWaker {

    private volatile String registeredToken;
    private volatile CompletableFuture<Void> wake = new CompletableFuture<>();

    @Override
    public void register(String deviceToken) {
        this.registeredToken = deviceToken;
    }

    public String registeredToken() {
        return registeredToken;
    }

    @Override
    public CompletableFuture<Void> awaitWake() {
        return wake;
    }

    /** Simulate a wake push arriving. */
    public synchronized void fire() {
        wake.complete(null);
        wake = new CompletableFuture<>();
    }
}
