package com.contextsolutions.securegateway.desktop;

import com.contextsolutions.securegateway.core.KeyPair;
import com.contextsolutions.securegateway.core.Role;
import com.contextsolutions.securegateway.core.auth.AuthClient;
import com.contextsolutions.securegateway.core.auth.QrPayload;
import com.contextsolutions.securegateway.core.auth.TokenStore;
import com.contextsolutions.securegateway.core.client.RelayClient;
import com.contextsolutions.securegateway.core.transport.ConnectionState;
import com.contextsolutions.securegateway.core.transport.Credentials;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Desktop SDK facade (PRD §8.3) — the always-on side. It generates the pairing QR
 * ({@code generatePairingQr}), waits for the mobile to complete pairing, then connects to
 * the relay and exposes the common {@code send}/{@code onMessage}/{@code onStateChange}
 * surface. Uses {@link JdkWebSocketTransport} ({@code java.net.http.WebSocket}).
 *
 * <p>Obtain one via {@link SecureGateway#desktop(DesktopConfig)}.
 */
public final class DesktopClient {

    private final DesktopConfig config;
    private final AuthClient auth;
    private final KeyPair identity;
    private final String publicKeyB64;

    private String deviceId;
    private String pairingToken;
    private String pairId;
    private byte[] peerPublicKey;

    private Consumer<byte[]> onMessage = b -> { };
    private Consumer<ConnectionState> onStateChange = s -> { };
    private RelayClient client;

    DesktopClient(DesktopConfig config) {
        this.config = config;
        this.auth = new AuthClient(config.authUrl);
        this.identity = config.keyStore.loadOrCreateIdentity();
        this.publicKeyB64 = Base64.getEncoder().encodeToString(identity.publicKey());
        this.deviceId = config.deviceId;
        // Seed restore state to support reconnect-without-repair (the QR's pairing token is
        // single-use; a restored pairId + mobile public key let connect() run on its own).
        // Mirrors MobileClient's config-seeded pairId/peerPublicKey.
        this.pairId = config.pairId;
        this.peerPublicKey = config.mobilePublicKeyB64 == null
                ? null : Base64.getDecoder().decode(config.mobilePublicKeyB64);
    }

    public DesktopClient onMessage(Consumer<byte[]> handler) {
        this.onMessage = handler;
        return this;
    }

    public DesktopClient onStateChange(Consumer<ConnectionState> handler) {
        this.onStateChange = handler;
        return this;
    }

    /** Register the desktop device if needed, then request a pairing token + QR payload. */
    public QrPayload generatePairingQr() {
        config.logger.accept("qr: auth=" + config.authUrl + " relay=" + config.relayUrl
                + " secret=" + (config.accountSecret == null || config.accountSecret.isBlank() ? "MISSING" : "present"));
        ensureDevice();
        config.logger.accept("qr: device registered id=" + deviceId + "; creating pairing token");
        AuthClient.PairingTokenResult r =
                auth.createPairingToken(config.accountSecret, config.licenseId, deviceId, publicKeyB64);
        this.pairingToken = r.pairingToken;
        // Embed the account secret client-side so the scanned QR conveys the
        // credential the mobile needs to issue tokens (it has no subscription of
        // its own). Not minted by the gateway — it never leaves the QR path.
        r.qr.accountSecret = config.accountSecret;
        config.logger.accept("qr: ready (pairing token minted); waiting for the phone to scan + pair");
        return r.qr;
    }

    /** Poll until the mobile completes pairing (learns pair_id + the mobile public key). */
    public void awaitPairing(Duration timeout) {
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() < deadline) {
            AuthClient.PollResult p = auth.pollPairingToken(config.accountSecret, pairingToken);
            if (AuthClient.PollResult.COMPLETED.equals(p.status)) {
                this.pairId = p.pairId;
                this.peerPublicKey = Base64.getDecoder().decode(p.mobilePublicKey);
                config.logger.accept("pair: completed pairId=" + pairId + " peerPubKey=" + peerPublicKey.length + "B");
                return;
            }
            if (AuthClient.PollResult.EXPIRED.equals(p.status)) {
                config.logger.accept("pair: token EXPIRED before the phone completed pairing");
                throw new IllegalStateException("pairing token expired before completion");
            }
            sleep(250);
        }
        config.logger.accept("pair: timed out waiting for the phone to pair");
        throw new IllegalStateException("timed out awaiting pairing");
    }

    /** Issue a connection token and open the relay session. Requires pairing to be complete. */
    public void connect() {
        if (pairId == null || peerPublicKey == null) {
            throw new IllegalStateException("call generatePairingQr() + awaitPairing() first");
        }
        config.logger.accept("connect: issuing token for pairId=" + pairId + " device=" + deviceId);
        TokenStore tokens = new TokenStore();
        tokens.update(auth.issueToken(config.accountSecret, deviceId, pairId));
        config.logger.accept("connect: token issued; opening relay session at " + config.relayUrl
                + " (wss dial is async — watch for state/wss lines)");
        Credentials cred = new Credentials(
                config.relayUrl, Role.DESKTOP, identity.privateKey(), peerPublicKey, tokens, auth);
        client = new RelayClient(cred, () -> new JdkWebSocketTransport(config.logger))
                .onMessage(onMessage)
                .onStateChange(onStateChange);
        client.connect();
    }

    public CompletableFuture<Void> send(byte[] plaintext) {
        return client.send(plaintext);
    }

    public ConnectionState state() {
        return client == null ? null : client.state();
    }

    public String pairId() {
        return pairId;
    }

    /** Base64-std of the mobile peer's X25519 public key learned at {@link #awaitPairing} (null before pairing). */
    public String mobilePublicKeyB64() {
        return peerPublicKey == null ? null : Base64.getEncoder().encodeToString(peerPublicKey);
    }

    /**
     * True once paired — in this process via {@link #generatePairingQr()} + {@link #awaitPairing},
     * or restored from a prior pairing via {@link DesktopConfig#pairId} +
     * {@link DesktopConfig#mobilePublicKeyB64}. When true, {@link #connect()} can run on its own
     * (no QR mint / no {@link #awaitPairing}). Persist {@link #deviceId()}/{@link #pairId()}/
     * {@link #mobilePublicKeyB64()} after a successful pairing and feed them back via
     * {@link DesktopConfig} to reconnect after a restart. Mirrors {@code MobileClient.isPaired()}.
     */
    public boolean isPaired() {
        return pairId != null && peerPublicKey != null;
    }

    /**
     * The desktop device id — null until {@link #generatePairingQr()} registers it (or it was
     * supplied via {@link DesktopConfig#deviceId}). Persist it and feed it back through
     * {@code DesktopConfig.deviceId} on the next launch so a re-mint reuses the SAME device:
     * the gateway then treats it as a re-pair (reusing the max_pairs slot, FR-2.2) instead of
     * registering a new device and rejecting the pairing token with {@code capacity_exceeded}.
     */
    public String deviceId() {
        return deviceId;
    }

    /**
     * Revoke this pairing at the gateway (FR-2.5): the phone's relay session is cut and the
     * pair slot freed. No-op if pairing never completed. Call {@link #close()} afterward to
     * drop the local session. Blocking HTTP — call off the UI thread.
     */
    public void unpair() {
        if (pairId == null) {
            return;
        }
        config.logger.accept("unpair: revoking pairId=" + pairId);
        auth.unpair(config.accountSecret, pairId);
        pairId = null;
        peerPublicKey = null;
    }

    public void close() {
        if (client != null) {
            client.close();
        }
    }

    private void ensureDevice() {
        if (deviceId == null) {
            deviceId = auth.registerDevice(config.accountSecret, Role.DESKTOP, publicKeyB64);
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted");
        }
    }
}
