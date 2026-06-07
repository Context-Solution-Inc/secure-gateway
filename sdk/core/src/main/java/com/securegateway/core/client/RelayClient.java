package com.securegateway.core.client;

import com.securegateway.core.transport.ConnectionManager;
import com.securegateway.core.transport.ConnectionState;
import com.securegateway.core.transport.Credentials;
import com.securegateway.core.transport.Transport;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * The shared, platform-agnostic relay session exposing the common SDK surface (PRD §8):
 * {@code connect}, {@code send(bytes) -> ack}, {@code onMessage}, {@code onStateChange}.
 * Platform facades ({@code DesktopClient}, {@code MobileClient}) handle pairing/token
 * acquisition and then drive one of these with the right transport.
 */
public final class RelayClient {

    private final ConnectionManager manager;

    public RelayClient(Credentials credentials, Supplier<Transport> transportFactory) {
        this.manager = new ConnectionManager(credentials, transportFactory);
    }

    public RelayClient onMessage(Consumer<byte[]> handler) {
        manager.setOnMessage(handler);
        return this;
    }

    public RelayClient onStateChange(Consumer<ConnectionState> handler) {
        manager.setOnStateChange(handler);
        return this;
    }

    /** Open and maintain the relay connection (reconnects automatically per FR-1.5). */
    public void connect() {
        manager.start();
    }

    /** Encrypt and send plaintext to the peer; the future completes on the peer's ack. */
    public CompletableFuture<Void> send(byte[] plaintext) {
        return manager.send(plaintext);
    }

    public ConnectionState state() {
        return manager.state();
    }

    public void close() {
        manager.close();
    }
}
