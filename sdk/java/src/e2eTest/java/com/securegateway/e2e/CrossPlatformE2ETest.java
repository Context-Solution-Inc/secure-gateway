package com.securegateway.e2e;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.securegateway.core.auth.AuthClient;
import com.securegateway.core.auth.QrPayload;
import com.securegateway.core.transport.ConnectionState;
import com.securegateway.desktop.DesktopClient;
import com.securegateway.desktop.DesktopConfig;
import com.securegateway.mobile.MobileClient;
import com.securegateway.mobile.MobileConfig;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * The M4 exit criterion (PRD §11): cross-platform E2E — the Kotlin (mobile) SDK and the Java
 * (desktop) SDK exchange encrypted messages through the real Go relay + auth binaries. The
 * desktop drives {@code java.net.http.WebSocket}; the mobile drives OkHttp. This exercises
 * the full path: pair (QR) → token issue → wss connect → handshake → bidirectional
 * encrypted send/ack, and verifies the relay only ever sees ciphertext.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CrossPlatformE2ETest {

    private GoBackend backend;
    private String accountSecret;

    @BeforeAll
    void setUp() throws Exception {
        backend = new GoBackend();
        backend.start();
        // The account is created via the admin endpoint; its secret authorizes device
        // registration and token issuance. The license was seeded via AUTH_DEV_SEED.
        AuthClient admin = new AuthClient(backend.authUrl());
        AuthClient.AccountResult acct = admin.createAccount(GoBackend.ADMIN_KEY, GoBackend.ACCOUNT_ID);
        accountSecret = acct.secret;
    }

    @AfterAll
    void tearDown() {
        if (backend != null) {
            backend.close();
        }
    }

    @Test
    void androidKotlinToJavaDesktopThroughRealRelay() throws Exception {
        BlockingQueue<byte[]> desktopInbox = new ArrayBlockingQueue<>(8);
        BlockingQueue<byte[]> mobileInbox = new ArrayBlockingQueue<>(8);
        CompletableFuture<Void> desktopConnected = new CompletableFuture<>();
        CompletableFuture<Void> mobileConnected = new CompletableFuture<>();

        // --- Desktop (Java SDK) ---
        DesktopConfig dcfg = new DesktopConfig();
        dcfg.authUrl = backend.authUrl();
        dcfg.relayUrl = backend.wsUrl();
        dcfg.accountSecret = accountSecret;
        dcfg.licenseId = GoBackend.LICENSE_ID;
        DesktopClient desktop = com.securegateway.desktop.SecureGateway.desktop(dcfg)
                .onMessage(desktopInbox::add)
                .onStateChange(s -> {
                    if (s == ConnectionState.CONNECTED) {
                        desktopConnected.complete(null);
                    }
                });

        // --- Mobile (Kotlin SDK) ---
        MobileConfig mcfg = new MobileConfig();
        mcfg.setAuthUrl(backend.authUrl());
        mcfg.setAccountSecret(accountSecret);
        MobileClient mobile = com.securegateway.mobile.SecureGateway.INSTANCE.mobile(mcfg);
        mobile.onMessage(b -> {
            mobileInbox.add(b);
            return null;
        });
        mobile.onStateChange(s -> {
            if (s == ConnectionState.CONNECTED) {
                mobileConnected.complete(null);
            }
            return null;
        });

        // --- Pair via the QR flow (FR-2), then connect both ends ---
        try {
            QrPayload qr = desktop.generatePairingQr();
            mobile.pair(qr);
            desktop.awaitPairing(Duration.ofSeconds(10));

            desktop.connect();
            mobile.connect();

            desktopConnected.get(15, TimeUnit.SECONDS);
            mobileConnected.get(15, TimeUnit.SECONDS);

            // --- mobile (Kotlin) -> desktop (Java) ---
            byte[] m2d = "hello desktop from the kotlin mobile sdk".getBytes(StandardCharsets.UTF_8);
            mobile.send(m2d).get(10, TimeUnit.SECONDS);
            assertArrayEquals(m2d, desktopInbox.poll(10, TimeUnit.SECONDS), "desktop got mobile plaintext");

            // --- desktop (Java) -> mobile (Kotlin) ---
            byte[] d2m = "ack and reply from the java desktop sdk".getBytes(StandardCharsets.UTF_8);
            desktop.send(d2m).get(10, TimeUnit.SECONDS);
            assertArrayEquals(d2m, mobileInbox.poll(10, TimeUnit.SECONDS), "mobile got desktop plaintext");

            // --- The relay must only ever see ciphertext (FR-5.4) ---
            String relayLog = backend.relayLog();
            assertFalse(relayLog.contains("hello desktop from the kotlin"), "plaintext leaked to relay log");
            assertFalse(relayLog.contains("ack and reply from the java"), "plaintext leaked to relay log");
            assertTrue(desktop.pairId() != null && desktop.pairId().equals(mobile.pairId()),
                    "both ends share the same pair_id");
        } finally {
            // Free the single licensed pair slot so the other test in this class can pair
            // regardless of execution order (seeded license is max_pairs=1).
            mobile.unpair();
            mobile.close();
            desktop.close();
        }
    }

    /**
     * Peer-reconnect re-key (the "green-but-hung after reconnect" regression). The mobile toggles
     * its connection OFF then ON ({@code close()} + {@code connect()}) while the desktop stays up,
     * so the mobile rebuilds with a FRESH ephemeral and the desktop is the stale survivor. Before
     * the 0.2.3 re-key fix the desktop ignored the new handshake (SG-15 one-shot guard), kept its
     * old session keys, and silently dropped every subsequent frame — sockets green, prompt hung.
     * With the fix the desktop re-keys on the new ephemeral and delivery resumes.
     */
    @Test
    void peerReconnectReKeysAndStillDelivers() throws Exception {
        BlockingQueue<byte[]> desktopInbox = new ArrayBlockingQueue<>(8);
        BlockingQueue<ConnectionState> mobileStates = new LinkedBlockingQueue<>();
        CompletableFuture<Void> desktopConnected = new CompletableFuture<>();

        DesktopConfig dcfg = new DesktopConfig();
        dcfg.authUrl = backend.authUrl();
        dcfg.relayUrl = backend.wsUrl();
        dcfg.accountSecret = accountSecret;
        dcfg.licenseId = GoBackend.LICENSE_ID;
        DesktopClient desktop = com.securegateway.desktop.SecureGateway.desktop(dcfg)
                .onMessage(desktopInbox::add)
                .onStateChange(s -> {
                    if (s == ConnectionState.CONNECTED) {
                        desktopConnected.complete(null);
                    }
                });

        MobileConfig mcfg = new MobileConfig();
        mcfg.setAuthUrl(backend.authUrl());
        mcfg.setAccountSecret(accountSecret);
        MobileClient mobile = com.securegateway.mobile.SecureGateway.INSTANCE.mobile(mcfg);
        mobile.onMessage(b -> null);
        mobile.onStateChange(s -> {
            mobileStates.add(s);
            return null;
        });

        try {
            QrPayload qr = desktop.generatePairingQr();
            mobile.pair(qr);
            desktop.awaitPairing(Duration.ofSeconds(10));

            desktop.connect();
            mobile.connect();
            desktopConnected.get(15, TimeUnit.SECONDS);
            awaitConnected(mobileStates);

            // Baseline: delivery works on the original session.
            byte[] first = "first turn before reconnect".getBytes(StandardCharsets.UTF_8);
            byte[] gotFirst = sendUntilDelivered(mobile, first, desktopInbox, Duration.ofSeconds(15));
            assertArrayEquals(first, gotFirst, "baseline delivery");

            // Mobile toggles OFF then ON: a fresh ConnectionManager → new ephemeral handshake.
            mobile.close();
            mobileStates.clear();
            mobile.connect(); // isPaired() still true → reconnect, no re-pair
            awaitConnected(mobileStates);

            // The desktop (stale survivor) must re-key on the mobile's new ephemeral and deliver.
            byte[] after = "turn after reconnect".getBytes(StandardCharsets.UTF_8);
            byte[] gotAfter = sendUntilDelivered(mobile, after, desktopInbox, Duration.ofSeconds(20));
            assertArrayEquals(after, gotAfter,
                    "desktop must re-key on the peer's new ephemeral and deliver after reconnect");
        } finally {
            // Free the single licensed pair slot for the other test (seeded license is max_pairs=1).
            mobile.unpair();
            mobile.close();
            desktop.close();
        }
    }

    /** Await the next CONNECTED transition on the mobile state stream. */
    private static void awaitConnected(BlockingQueue<ConnectionState> states) throws InterruptedException {
        long deadlineNs = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (System.nanoTime() < deadlineNs) {
            ConnectionState s = states.poll(15, TimeUnit.SECONDS);
            if (s == ConnectionState.CONNECTED) {
                return;
            }
        }
        throw new AssertionError("mobile did not reach CONNECTED");
    }

    /**
     * Send {@code payload} and wait for it on {@code inbox}, retrying within {@code budget}.
     * Tolerates the brief window after (re)connect where the per-session handshake has not yet
     * completed (so {@code send} throws) — each retry mints a fresh frame id, so a delivered
     * duplicate is harmless. Returns the delivered bytes, or fails the test on timeout.
     */
    private static byte[] sendUntilDelivered(MobileClient mobile, byte[] payload,
            BlockingQueue<byte[]> inbox, Duration budget) throws InterruptedException {
        long deadlineNs = System.nanoTime() + budget.toNanos();
        while (System.nanoTime() < deadlineNs) {
            try {
                mobile.send(payload).get(2, TimeUnit.SECONDS);
            } catch (Exception retryable) {
                // not-yet-handshaked / no ack yet — fall through and retry
            }
            byte[] got = inbox.poll(1, TimeUnit.SECONDS);
            if (got != null) {
                return got;
            }
        }
        throw new AssertionError("payload was not delivered within " + budget);
    }
}
