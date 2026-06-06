package com.securegateway.mobile

import com.securegateway.core.push.PushWaker
import java.util.concurrent.CompletableFuture

/**
 * STUB for the JVM build. On a real Android build this registers the device's FCM token with
 * the backend and completes [awaitWake] when a data push (sent because the desktop's message
 * attempt returned `peer_offline`) is received, so the SDK reconnects (PRD §8.1). Doze/App
 * Standby constraints apply.
 *
 * TODO(android): wire to FirebaseMessaging + a FirebaseMessagingService that calls [onPush].
 */
class FcmPushWaker : PushWaker {

    @Volatile
    private var token: String? = null

    @Volatile
    private var wake = CompletableFuture<Void>()

    override fun register(deviceToken: String) {
        token = deviceToken
    }

    override fun awaitWake(): CompletableFuture<Void> = wake

    /** Called by the host's FirebaseMessagingService when a wake push arrives. */
    @Synchronized
    fun onPush() {
        wake.complete(null)
        wake = CompletableFuture()
    }
}
