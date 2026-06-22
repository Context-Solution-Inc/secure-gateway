package com.contextsolutions.securegateway.core.push;

import java.util.concurrent.CompletableFuture;

/**
 * Push-to-wake seam (PRD §8.1/§8.2). When a mobile app is backgrounded its socket is
 * released; a desktop message attempt returns {@code peer_offline} and a data push (FCM on
 * Android, APNs on iOS) wakes the app to reconnect. The SDK models this so host apps can
 * plug in their platform push; real FCM/APNs wiring lives in the host app.
 */
public interface PushWaker {

    /** Register the platform push token with the backend (host-app responsibility to deliver). */
    void register(String deviceToken);

    /** Completes when a wake push arrives, signaling the SDK to (re)connect. */
    CompletableFuture<Void> awaitWake();
}
