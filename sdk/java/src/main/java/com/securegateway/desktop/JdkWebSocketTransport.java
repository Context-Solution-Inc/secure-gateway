package com.securegateway.desktop;

import com.securegateway.core.transport.Transport;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Desktop {@link Transport} on {@code java.net.http.WebSocket} (JDK 11+, zero added
 * dependency). The connection JWT is set as the {@code Authorization: Bearer} header on the
 * upgrade request (FR-1.2); partial text frames are reassembled before delivery.
 */
public final class JdkWebSocketTransport implements Transport {

    private final HttpClient httpClient;
    // Diagnostics sink (defaults no-op). The wss dial happens here, and the relay state
    // machine swallows connect failures into a silent reconnect — so this is where the real
    // cause (refused/TLS/401/relay close code) is visible. Mirrors the mobile transport.
    private final Consumer<String> logger;
    private volatile WebSocket webSocket;
    private final StringBuilder textBuffer = new StringBuilder();
    // Serializes outbound WebSocket operations (the API forbids overlapping sends).
    private CompletableFuture<WebSocket> sendChain = new CompletableFuture<>();

    public JdkWebSocketTransport() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(), s -> { });
    }

    public JdkWebSocketTransport(Consumer<String> logger) {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(), logger);
    }

    public JdkWebSocketTransport(HttpClient httpClient) {
        this(httpClient, s -> { });
    }

    public JdkWebSocketTransport(HttpClient httpClient, Consumer<String> logger) {
        this.httpClient = httpClient;
        this.logger = logger;
    }

    @Override
    public void connect(String wsUrl, String bearerToken, Listener listener) throws Exception {
        logger.accept("wss: dialing " + wsUrl + " (token=" + bearerToken.length() + "B)");
        WebSocket ws;
        try {
            ws = httpClient.newWebSocketBuilder()
                    .header("Authorization", "Bearer " + bearerToken)
                    .connectTimeout(Duration.ofSeconds(15))
                    .buildAsync(URI.create(wsUrl), new Adapter(listener))
                    .get(20, TimeUnit.SECONDS);
        } catch (Exception e) {
            Throwable c = e.getCause() != null ? e.getCause() : e;
            logger.accept("wss: dial FAILED " + c.getClass().getSimpleName() + ": " + c.getMessage());
            throw e;
        }
        logger.accept("wss: connected");
        this.webSocket = ws;
        this.sendChain.complete(ws);
        ws.request(Long.MAX_VALUE);
    }

    @Override
    public void send(byte[] frame) {
        String text = new String(frame, StandardCharsets.UTF_8);
        chain(ws -> ws.sendText(text, true));
    }

    @Override
    public void sendPing() {
        chain(ws -> ws.sendPing(ByteBuffer.allocate(0)));
    }

    @Override
    public void close(int code, String reason) {
        WebSocket ws = webSocket;
        if (ws != null) {
            // JDK only allows 1000 or 3000-4999 on send; clamp the reason to 123 bytes.
            int c = (code == 1000 || (code >= 3000 && code <= 4999)) ? code : 1000;
            ws.sendClose(c, truncate(reason)).exceptionally(t -> null);
        }
    }

    private synchronized void chain(java.util.function.Function<WebSocket, CompletionStage<WebSocket>> op) {
        sendChain = sendChain.thenCompose(op::apply);
        // Swallow failures so one failed send doesn't poison the chain.
        sendChain = sendChain.exceptionally(t -> webSocket);
    }

    private static String truncate(String reason) {
        if (reason == null) {
            return "";
        }
        return reason.length() <= 120 ? reason : reason.substring(0, 120);
    }

    private final class Adapter implements WebSocket.Listener {
        private final Listener listener;

        Adapter(Listener listener) {
            this.listener = listener;
        }

        @Override
        public void onOpen(WebSocket ws) {
            logger.accept("wss: onOpen");
            listener.onOpen();
            ws.request(Long.MAX_VALUE);
        }

        @Override
        public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
            textBuffer.append(data);
            if (last) {
                byte[] frame = textBuffer.toString().getBytes(StandardCharsets.UTF_8);
                textBuffer.setLength(0);
                listener.onMessage(frame);
            }
            ws.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onPing(WebSocket ws, ByteBuffer message) {
            listener.onActivity();
            ws.request(1);
            return WebSocket.Listener.super.onPing(ws, message); // auto-pong
        }

        @Override
        public CompletionStage<?> onPong(WebSocket ws, ByteBuffer message) {
            listener.onActivity();
            ws.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket ws, int statusCode, String reason) {
            logger.accept("wss: onClose code=" + statusCode + " reason='" + reason + "'");
            listener.onClosed(statusCode, reason);
            return null;
        }

        @Override
        public void onError(WebSocket ws, Throwable error) {
            logger.accept("wss: onError " + error.getClass().getSimpleName() + ": " + error.getMessage());
            listener.onError(error);
        }
    }
}
