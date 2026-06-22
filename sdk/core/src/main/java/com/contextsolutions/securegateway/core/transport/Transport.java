package com.contextsolutions.securegateway.core.transport;

/**
 * A WebSocket transport seam, so the platform-agnostic {@link ConnectionManager} can use
 * {@code java.net.http.WebSocket} on desktop and OkHttp on Android. Implementations attach
 * the connection JWT as the {@code Authorization: Bearer} header on the upgrade request
 * (FR-1.2) and deliver complete relay frames (reassembling any partial frames).
 */
public interface Transport {

    /** Connect and block until the WebSocket is open, or throw on failure. */
    void connect(String wsUrl, String bearerToken, Listener listener) throws Exception;

    /** Send a complete text frame (the JSON envelope bytes). */
    void send(byte[] frame);

    /** Best-effort liveness ping; default no-op for transports that ping internally. */
    default void sendPing() {
    }

    /**
     * Whether the transport detects dead connections itself (e.g. OkHttp's pingInterval
     * fails the socket and calls {@code onError}). When true, {@link ConnectionManager}
     * skips its silence-based watchdog to avoid false reconnects on healthy idle links.
     */
    default boolean selfManagesLiveness() {
        return false;
    }

    /** Initiate a close with the given code/reason. */
    void close(int code, String reason);

    /** Connection lifecycle callbacks. May be invoked on transport-owned threads. */
    interface Listener {
        void onOpen();

        /** A complete relay frame (JSON envelope bytes). */
        void onMessage(byte[] data);

        /** Any signal of liveness from the peer/relay (ping, pong, data). */
        default void onActivity() {
        }

        void onClosed(int code, String reason);

        void onError(Throwable error);
    }
}
