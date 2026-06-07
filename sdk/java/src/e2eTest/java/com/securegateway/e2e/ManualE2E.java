package com.securegateway.e2e;

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
import java.util.concurrent.TimeUnit;

/**
 * Manual end-to-end verification driver: drives the Kotlin (mobile) and Java (desktop) SDKs
 * through an <em>already-running</em> relay + auth (unlike {@link CrossPlatformE2ETest}, which
 * boots its own backend). Start the Go services by hand per the README, then run:
 *
 * <pre>  ./gradlew :java:manualE2E  [-DauthUrl=... -DwsUrl=...]</pre>
 *
 * It creates the seeded account, prints the pairing QR, pairs, connects both ends, exchanges
 * an encrypted message each way, and prints what each side decrypts.
 */
public final class ManualE2E {

    public static void main(String[] args) throws Exception {
        String authUrl = System.getProperty("authUrl", "http://127.0.0.1:8080");
        String wsUrl = System.getProperty("wsUrl", "ws://127.0.0.1:8443/v1/connect");
        log("auth = " + authUrl + "   relay = " + wsUrl);

        // The account is created via the admin endpoint; the license is seeded by AUTH_DEV_SEED.
        AuthClient admin = new AuthClient(authUrl);
        String secret = admin.createAccount(GoBackend.ADMIN_KEY, GoBackend.ACCOUNT_ID).secret;
        log("created account " + GoBackend.ACCOUNT_ID);

        BlockingQueue<byte[]> desktopInbox = new ArrayBlockingQueue<>(8);
        BlockingQueue<byte[]> mobileInbox = new ArrayBlockingQueue<>(8);
        CompletableFuture<Void> desktopConnected = new CompletableFuture<>();
        CompletableFuture<Void> mobileConnected = new CompletableFuture<>();

        DesktopConfig dcfg = new DesktopConfig();
        dcfg.authUrl = authUrl;
        dcfg.relayUrl = wsUrl;
        dcfg.accountSecret = secret;
        dcfg.licenseId = GoBackend.LICENSE_ID;
        DesktopClient desktop = com.securegateway.desktop.SecureGateway.desktop(dcfg)
                .onMessage(desktopInbox::add)
                .onStateChange(s -> {
                    log("desktop state -> " + s);
                    if (s == ConnectionState.CONNECTED) {
                        desktopConnected.complete(null);
                    }
                });

        MobileConfig mcfg = new MobileConfig();
        mcfg.setAuthUrl(authUrl);
        mcfg.setAccountSecret(secret);
        MobileClient mobile = com.securegateway.mobile.SecureGateway.INSTANCE.mobile(mcfg);
        mobile.onMessage(b -> {
            mobileInbox.add(b);
            return null;
        });
        mobile.onStateChange(s -> {
            log("mobile state -> " + s);
            if (s == ConnectionState.CONNECTED) {
                mobileConnected.complete(null);
            }
            return null;
        });

        QrPayload qr = desktop.generatePairingQr();
        log("desktop QR payload: " + qr.toJson());

        mobile.pair(qr);
        desktop.awaitPairing(Duration.ofSeconds(10));
        log("paired: pair_id = " + desktop.pairId());

        desktop.connect();
        mobile.connect();
        desktopConnected.get(15, TimeUnit.SECONDS);
        mobileConnected.get(15, TimeUnit.SECONDS);
        log("both ends connected");

        byte[] m2d = "hello desktop, from the mobile SDK".getBytes(StandardCharsets.UTF_8);
        mobile.send(m2d).get(10, TimeUnit.SECONDS);
        log("desktop received: \"" + new String(desktopInbox.poll(10, TimeUnit.SECONDS), StandardCharsets.UTF_8) + "\"");

        byte[] d2m = "reply from the desktop SDK".getBytes(StandardCharsets.UTF_8);
        desktop.send(d2m).get(10, TimeUnit.SECONDS);
        log("mobile received:  \"" + new String(mobileInbox.poll(10, TimeUnit.SECONDS), StandardCharsets.UTF_8) + "\"");

        log("OK — bidirectional encrypted exchange succeeded (the relay only saw ciphertext)");
        mobile.close();
        desktop.close();
        System.exit(0);
    }

    private static void log(String msg) {
        System.out.println("[manual-e2e] " + msg);
    }
}
