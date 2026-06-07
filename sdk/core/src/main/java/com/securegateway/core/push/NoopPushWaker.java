package com.securegateway.core.push;

import java.util.concurrent.CompletableFuture;

/**
 * Default {@link PushWaker} for the always-on desktop side and for hosts that keep the
 * socket alive: registration is a no-op and {@link #awaitWake()} never fires.
 */
public final class NoopPushWaker implements PushWaker {

    @Override
    public void register(String deviceToken) {
    }

    @Override
    public CompletableFuture<Void> awaitWake() {
        return new CompletableFuture<>(); // never completes
    }
}
