package com.securegateway.core.transport;

import com.securegateway.core.HandshakeCoordinator;
import com.securegateway.core.auth.AuthClient;
import com.securegateway.core.protocol.Envelope;
import com.securegateway.core.protocol.Protocol;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * The platform-agnostic relay client engine: it owns the {@link Transport}, the per-session
 * E2EE handshake, the connection state machine, reconnect-with-backoff (FR-1.5), a liveness
 * watchdog (FR-1.4), token refresh over the live socket (FR-3.5), and {@code send()}/{@code ack}
 * correlation (FR-4.3). Host apps see only plaintext bytes and {@link ConnectionState}.
 *
 * <p>All mutable state is confined to a single-thread scheduler; transport callbacks (which may
 * arrive on transport-owned threads) post work onto it, so the state machine is race-free.
 */
public final class ConnectionManager {

    private static final long PING_INTERVAL_MS = 25_000;
    private static final long LIVENESS_TIMEOUT_MS = 2 * PING_INTERVAL_MS; // 2 missed heartbeats
    private static final long REFRESH_SKEW_SECONDS = 120; // refresh ahead of expiry

    private final Credentials cred;
    private final Supplier<Transport> transportFactory;
    private final ReconnectPolicy policy = new ReconnectPolicy();
    private final ScheduledExecutorService exec =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "sg-relay-conn");
                t.setDaemon(true);
                return t;
            });

    private final Map<String, CompletableFuture<Void>> pendingAcks = new ConcurrentHashMap<>();
    private final Deque<PendingSend> sendQueue = new ArrayDeque<>();
    private final Deque<Envelope> bufferedData = new ArrayDeque<>(); // data frames before handshake

    private Consumer<byte[]> onMessage = b -> { };
    private Consumer<ConnectionState> onState = s -> { };

    // scheduler-thread-confined state:
    private boolean running;
    private boolean terminal;
    private int attempt;
    private Transport active;
    private HandshakeCoordinator handshake;
    private ConnectionState state;
    private ScheduledFuture<?> watchdog;
    private ScheduledFuture<?> refreshTask;
    private volatile long lastActivityMs;

    public ConnectionManager(Credentials cred, Supplier<Transport> transportFactory) {
        this.cred = cred;
        this.transportFactory = transportFactory;
    }

    public void setOnMessage(Consumer<byte[]> onMessage) {
        this.onMessage = onMessage;
    }

    public void setOnStateChange(Consumer<ConnectionState> onState) {
        this.onState = onState;
    }

    public ConnectionState state() {
        return state;
    }

    /** Begin connecting and maintaining the session. */
    public void start() {
        exec.execute(() -> {
            if (running) {
                return;
            }
            running = true;
            scheduleConnect(0);
            scheduleRefresh();
        });
    }

    /**
     * Encrypt and send {@code plaintext} to the peer. The returned future completes when the
     * peer acks the message id, or fails if the peer is offline or the connection is lost.
     */
    public CompletableFuture<Void> send(byte[] plaintext) {
        String id = UUID.randomUUID().toString();
        CompletableFuture<Void> future = new CompletableFuture<>();
        pendingAcks.put(id, future);
        try {
            exec.execute(() -> {
                PendingSend ps = new PendingSend(id, plaintext.clone(), future);
                if (terminal || !running) {
                    pendingAcks.remove(id);
                    future.completeExceptionally(new IllegalStateException("session is not active"));
                } else if (isLiveForData()) {
                    writeData(ps);
                } else {
                    sendQueue.addLast(ps); // flush once handshake completes
                }
            });
        } catch (RejectedExecutionException e) {
            // close() already shut the scheduler down — fail the future, don't throw to the
            // caller (a late send during teardown must not crash the host).
            pendingAcks.remove(id);
            future.completeExceptionally(new IllegalStateException("session is not active"));
        }
        return future;
    }

    /** Stop maintaining the connection and release resources. */
    public void close() {
        safeExec(() -> {
            running = false;
            cancelTimers();
            if (active != null) {
                active.close(Protocol.CLOSE_NORMAL, "client closing");
                active = null;
            }
            failAllPending(new IllegalStateException("connection closed"));
        });
        exec.shutdown();
    }

    /**
     * Submit to the scheduler, dropping the task if it's already shut down. After
     * {@link #close()} the transport can still fire {@code onClosed}/{@code onError}/late
     * sends on its own threads; those callbacks must not throw {@link RejectedExecutionException}
     * (it would be uncaught on the transport thread and crash the host app).
     */
    private void safeExec(Runnable r) {
        try {
            exec.execute(r);
        } catch (RejectedExecutionException ignored) {
            // executor shut down by close(); the late callback is safe to drop.
        }
    }

    // --- connect loop ---

    private void scheduleConnect(long delayMs) {
        if (!running || terminal) {
            return;
        }
        try {
            exec.schedule(this::attemptConnect, delayMs, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException ignored) {
            // raced with close()'s shutdown; nothing to reconnect to.
        }
    }

    private void attemptConnect() {
        if (!running || terminal) {
            return;
        }
        Transport t = transportFactory.get();
        String token = cred.tokens.token();
        try {
            t.connect(cred.wsUrl, token, new ManagerListener(t));
            // onOpen drives the rest; connect() returned without throwing.
        } catch (Exception e) {
            scheduleReconnect();
        }
    }

    private void scheduleReconnect() {
        if (!running || terminal) {
            return;
        }
        teardownActive();
        setState(ConnectionState.RECONNECTING);
        long delay = policy.nextDelayMillis(attempt++);
        scheduleConnect(delay);
    }

    private void teardownActive() {
        cancelWatchdog();
        if (active != null) {
            try {
                active.close(Protocol.CLOSE_NORMAL, "reconnecting");
            } catch (RuntimeException ignored) {
                // already closing
            }
            active = null;
        }
        handshake = null;
        bufferedData.clear();
        failPendingAcks(new IllegalStateException("connection lost"));
    }

    // --- inbound handling (all on scheduler thread) ---

    private void handleOpen(Transport t) {
        active = t;
        attempt = 0;
        lastActivityMs = now();
        handshake = new HandshakeCoordinator(cred.myPrivateKey, cred.peerPublicKey, cred.role);
        sendFrame(Protocol.msg(UUID.randomUUID().toString(), now(), handshake.handshakeFrame()));
        setState(ConnectionState.CONNECTED);
        startWatchdog();
    }

    private void handleMessage(byte[] data) {
        lastActivityMs = now();
        Envelope env;
        try {
            env = Protocol.decode(data);
        } catch (RuntimeException e) {
            return; // ignore malformed frames
        }
        switch (env.type) {
            case Protocol.TYPE_MSG:
                handleMsg(env);
                break;
            case Protocol.TYPE_ACK:
                completeAck(env.id);
                break;
            case Protocol.TYPE_SYS:
                handleSys(env);
                break;
            case Protocol.TYPE_ERROR:
                handleError(env);
                break;
            default:
                // auth_refresh is client->relay only; ignore anything else.
        }
    }

    private void handleMsg(Envelope env) {
        byte[] payload;
        try {
            payload = Protocol.ciphertext(env);
        } catch (RuntimeException e) {
            return;
        }
        if (payload.length == 0) {
            return;
        }
        byte tag = payload[0];
        if (tag == HandshakeCoordinator.TAG_HANDSHAKE) {
            try {
                handshake.onFrame(payload, env.id, env.ts); // builds/rebuilds the session
            } catch (RuntimeException e) {
                return;
            }
            if (handshake.isComplete()) {
                flushSendQueue();
                drainBufferedData();
            }
            return;
        }
        // Data frame. If our session isn't ready yet (handshakes can race across the
        // relay), buffer the raw frame and replay it once the handshake completes.
        if (!handshake.isComplete()) {
            bufferedData.addLast(env);
            return;
        }
        deliverData(env, payload);
    }

    private void deliverData(Envelope env, byte[] payload) {
        byte[] plaintext;
        try {
            plaintext = handshake.onFrame(payload, env.id, env.ts);
        } catch (RuntimeException e) {
            return; // tampered/undecryptable; drop
        }
        if (plaintext == null) {
            return;
        }
        // Real application message: deliver and ack by id (FR-4.3).
        sendFrame(Protocol.ack(env.id, now()));
        try {
            onMessage.accept(plaintext);
        } catch (RuntimeException ignored) {
            // host handler errors must not break the read loop
        }
    }

    private void drainBufferedData() {
        while (!bufferedData.isEmpty()) {
            Envelope env = bufferedData.pollFirst();
            try {
                deliverData(env, Protocol.ciphertext(env));
            } catch (RuntimeException ignored) {
                // drop unparseable buffered frame
            }
        }
    }

    private void handleSys(Envelope env) {
        String kind;
        try {
            kind = Protocol.sys(env).kind;
        } catch (RuntimeException e) {
            return;
        }
        if (Protocol.SYS_PEER_ONLINE.equals(kind)) {
            setState(ConnectionState.CONNECTED);
            // The handshake we sent on open was dropped if the peer wasn't connected yet.
            // Resend unconditionally now that the peer is present. Our ephemeral is unchanged
            // since we last (re)connected, so if the peer already holds a session built from it
            // the resend is an idempotent no-op (HandshakeCoordinator ignores an identical
            // ephemeral). If the peer reconnected with a fresh ephemeral, ITS resend carries the
            // new key and we re-key to match; this resend lets a peer that missed our handshake
            // (re)build a session against our current ephemeral.
            if (handshake != null) {
                sendFrame(Protocol.msg(UUID.randomUUID().toString(), now(), handshake.handshakeFrame()));
            }
        } else if (Protocol.SYS_PEER_OFFLINE.equals(kind)) {
            setState(ConnectionState.PEER_OFFLINE);
        } else if (Protocol.SYS_SHUTDOWN.equals(kind)) {
            scheduleReconnect(); // relay draining; reconnect with jitter (Appendix B 1001)
        }
    }

    private void handleError(Envelope env) {
        String code;
        try {
            code = Protocol.error(env).code;
        } catch (RuntimeException e) {
            return;
        }
        if (Protocol.ERR_PEER_OFFLINE.equals(code)) {
            setState(ConnectionState.PEER_OFFLINE);
            // The error carries a fresh id (not the message id), so fail in-flight sends.
            failPendingAcks(new PeerOfflineException());
        }
    }

    private void handleClosed(int code, String reason) {
        cancelWatchdog();
        active = null;
        handshake = null;
        failPendingAcks(new IllegalStateException("connection closed: " + code));
        switch (code) {
            case Protocol.CLOSE_SUPERSEDED:
                terminate(ConnectionState.SUPERSEDED);
                break;
            case Protocol.CLOSE_REVOKED:
                terminate(ConnectionState.REVOKED);
                break;
            case Protocol.CLOSE_TOKEN_EXPIRED:
                refreshNow();          // get a fresh token, then reconnect
                scheduleReconnect();
                break;
            default:
                scheduleReconnect();   // 1000/1001/4005/network
        }
    }

    // --- outbound helpers ---

    private boolean isLiveForData() {
        return active != null && handshake != null && handshake.isComplete();
    }

    private void writeData(PendingSend ps) {
        try {
            // The AEAD binds (id, ts) as associated data, so the ts used to seal MUST equal
            // the ts on the envelope the peer opens with — compute it once.
            long ts = now();
            byte[] frame = handshake.sealFrame(ps.id, ts, ps.plaintext);
            sendFrame(Protocol.msg(ps.id, ts, frame));
        } catch (RuntimeException e) {
            CompletableFuture<Void> f = pendingAcks.remove(ps.id);
            if (f != null) {
                f.completeExceptionally(e);
            }
        }
    }

    private void flushSendQueue() {
        List<PendingSend> drained = new ArrayList<>(sendQueue);
        sendQueue.clear();
        for (PendingSend ps : drained) {
            if (pendingAcks.containsKey(ps.id)) {
                writeData(ps);
            }
        }
    }

    private void sendFrame(Envelope env) {
        if (active != null) {
            active.send(Protocol.encode(env));
        }
    }

    private void completeAck(String id) {
        CompletableFuture<Void> f = pendingAcks.remove(id);
        if (f != null) {
            f.complete(null);
        }
    }

    // --- token refresh (FR-3.5) ---

    private void scheduleRefresh() {
        if (cred.auth == null) {
            return;
        }
        cancelRefresh();
        long delay = Math.max(1, cred.tokens.expiresAt().getEpochSecond()
                - REFRESH_SKEW_SECONDS - java.time.Instant.now().getEpochSecond());
        refreshTask = exec.schedule(() -> {
            refreshNow();
            scheduleRefresh();
        }, delay, TimeUnit.SECONDS);
    }

    private void refreshNow() {
        if (cred.auth == null) {
            return;
        }
        try {
            AuthClient.TokenResult r = cred.auth.refreshToken(cred.tokens.refreshToken());
            cred.tokens.update(r);
            if (active != null) {
                sendFrame(Protocol.authRefresh(UUID.randomUUID().toString(), now(), r.token));
            }
        } catch (RuntimeException e) {
            // Refresh failed (e.g. license lapsed). The relay will close 4003/4004 and the
            // close handler will reconnect or terminate accordingly.
        }
    }

    // --- liveness watchdog (FR-1.4 mirror check) ---

    private void startWatchdog() {
        cancelWatchdog();
        if (active != null && active.selfManagesLiveness()) {
            return; // transport (e.g. OkHttp) detects dead connections itself
        }
        watchdog = exec.scheduleAtFixedRate(() -> {
            if (active != null) {
                active.sendPing();
                if (now() - lastActivityMs > LIVENESS_TIMEOUT_MS) {
                    scheduleReconnect(); // peer/relay silent for 2 heartbeats
                }
            }
        }, PING_INTERVAL_MS, PING_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    // --- state + cleanup ---

    private void setState(ConnectionState s) {
        if (s != state) {
            state = s;
            try {
                onState.accept(s);
            } catch (RuntimeException ignored) {
                // host handler errors are non-fatal
            }
        }
    }

    private void terminate(ConnectionState terminalState) {
        terminal = true;
        running = false;
        cancelTimers();
        failAllPending(new IllegalStateException("session terminated: " + terminalState));
        setState(terminalState);
    }

    private void cancelTimers() {
        cancelWatchdog();
        cancelRefresh();
    }

    private void cancelWatchdog() {
        if (watchdog != null) {
            watchdog.cancel(false);
            watchdog = null;
        }
    }

    private void cancelRefresh() {
        if (refreshTask != null) {
            refreshTask.cancel(false);
            refreshTask = null;
        }
    }

    private void failPendingAcks(Throwable cause) {
        for (Map.Entry<String, CompletableFuture<Void>> e : pendingAcks.entrySet()) {
            e.getValue().completeExceptionally(cause);
        }
        pendingAcks.clear();
    }

    private void failAllPending(Throwable cause) {
        failPendingAcks(cause);
        for (PendingSend ps : sendQueue) {
            ps.future.completeExceptionally(cause);
        }
        sendQueue.clear();
    }

    private static long now() {
        return System.currentTimeMillis();
    }

    private final class ManagerListener implements Transport.Listener {
        private final Transport owner;

        ManagerListener(Transport owner) {
            this.owner = owner;
        }

        @Override
        public void onOpen() {
            safeExec(() -> handleOpen(owner));
        }

        @Override
        public void onMessage(byte[] data) {
            safeExec(() -> handleMessage(data));
        }

        @Override
        public void onActivity() {
            lastActivityMs = now();
        }

        @Override
        public void onClosed(int code, String reason) {
            safeExec(() -> {
                if (active == owner || active == null) {
                    handleClosed(code, reason);
                }
            });
        }

        @Override
        public void onError(Throwable error) {
            safeExec(() -> {
                if (active == owner || active == null) {
                    scheduleReconnect();
                }
            });
        }
    }

    private static final class PendingSend {
        final String id;
        final byte[] plaintext;
        final CompletableFuture<Void> future;

        PendingSend(String id, byte[] plaintext, CompletableFuture<Void> future) {
            this.id = id;
            this.plaintext = plaintext;
            this.future = future;
        }
    }
}
