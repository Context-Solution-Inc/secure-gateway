package com.securegateway.e2e;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Boots the real Go relay + auth binaries as subprocesses (memory backplane/store, no Redis
 * or Stripe) to serve as the cross-platform E2E backend. It builds the binaries with the
 * project's Go toolchain, generates an ES256 signing key with {@code cmd/devtoken}, wires the
 * auth signer to the relay verifier via the auth JWKS endpoint, and seeds a deterministic
 * account/license through {@code AUTH_DEV_SEED}.
 */
final class GoBackend implements AutoCloseable {

    static final String ACCOUNT_ID = "acct_e2e";
    static final String LICENSE_ID = "lic_e2e";
    static final String SUBSCRIPTION_ID = "sub_e2e";
    static final String ADMIN_KEY = "admin-e2e-key";
    private static final String ISSUER = "https://e2e.local";

    private final Path repoRoot;
    private final Path goBin;
    private final Path workDir;
    private final List<Process> processes = new ArrayList<>();

    private int authPort;
    private int relayPort;
    private Path relayLog;

    GoBackend() throws IOException {
        String root = System.getProperty("sdk.repoRoot");
        if (root == null) {
            throw new IllegalStateException("sdk.repoRoot system property not set");
        }
        this.repoRoot = Path.of(root);
        Path candidate = Path.of(System.getProperty("user.home"), ".local", "go-sdk", "go", "bin", "go");
        this.goBin = Files.isExecutable(candidate) ? candidate : Path.of("go");
        this.workDir = Files.createTempDirectory("sg-e2e");
    }

    String authUrl() {
        return "http://127.0.0.1:" + authPort;
    }

    String wsUrl() {
        return "ws://127.0.0.1:" + relayPort + "/v1/connect";
    }

    String relayLog() throws IOException {
        return Files.exists(relayLog) ? Files.readString(relayLog) : "";
    }

    void start() throws Exception {
        Path bin = workDir.resolve("bin");
        Files.createDirectories(bin);
        Path keys = workDir.resolve("keys");

        Path auth = build(bin, "auth", "./cmd/auth");
        Path relay = build(bin, "relay", "./cmd/relay");
        Path devtoken = build(bin, "devtoken", "./cmd/devtoken");

        run(devtoken.toString(), "-gen-keys", "-alg", "ES256", "-out-dir", keys.toString(), "-kid", "e2e-1")
                .waitFor();

        authPort = freePort();
        relayPort = freePort();

        Path authLog = workDir.resolve("auth.log");
        relayLog = workDir.resolve("relay.log");

        startProcess(authLog, auth.toString(), Map.ofEntries(
                Map.entry("AUTH_LISTEN_ADDR", "127.0.0.1:" + authPort),
                Map.entry("AUTH_STORE", "memory"),
                Map.entry("AUTH_BACKPLANE", "memory"),
                Map.entry("AUTH_JWT_ISSUER", ISSUER),
                Map.entry("AUTH_JWT_AUDIENCE", "relay"),
                Map.entry("AUTH_JWT_ALG", "ES256"),
                Map.entry("AUTH_JWT_KID", "e2e-1"),
                Map.entry("AUTH_JWT_SIGNING_KEY_FILE", keys.resolve("relay.key.json").toString()),
                // No Stripe in the E2E backend; the license is seeded via AUTH_DEV_SEED.
                // Stripe config is all-or-none, so run ungated rather than set a lone
                // webhook secret (which the auth service rejects at boot).
                Map.entry("AUTH_BILLING_DISABLED", "true"),
                Map.entry("AUTH_ADMIN_KEY", ADMIN_KEY),
                // The cross-platform e2e exercises functional pairing/connect across several tests
                // on one seeded account; per-account rate limiting (default burst 10) is covered by
                // the Go service's own tests, so disable it here to keep these runs deterministic.
                Map.entry("AUTH_RATELIMIT_ENABLED", "false"),
                Map.entry("AUTH_DEV_SEED", ACCOUNT_ID + "," + LICENSE_ID + "," + SUBSCRIPTION_ID),
                Map.entry("AUTH_RELAY_URL", wsUrl()),
                Map.entry("AUTH_PUBLIC_URL", authUrl()),
                Map.entry("AUTH_PAIRING_TOKEN_TTL", "5m")));
        waitForHealth(authUrl() + "/healthz");

        startProcess(relayLog, relay.toString(), Map.of(
                "RELAY_LISTEN_ADDR", "127.0.0.1:" + relayPort,
                "RELAY_BACKPLANE", "memory",
                "RELAY_JWT_ISSUER", ISSUER,
                "RELAY_JWT_AUDIENCE", "relay",
                "RELAY_JWT_ALGS", "ES256",
                "RELAY_JWKS_URL", authUrl() + "/.well-known/jwks.json"));
        waitForHealth("http://127.0.0.1:" + relayPort + "/healthz");
    }

    private Path build(Path binDir, String name, String pkg) throws Exception {
        Path out = binDir.resolve(name);
        int code = run(goBin.toString(), "build", "-o", out.toString(), pkg).waitFor();
        if (code != 0) {
            throw new IllegalStateException("go build " + pkg + " failed (exit " + code + ")");
        }
        return out;
    }

    private Process run(String... cmd) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(repoRoot.toFile()).inheritIO();
        pb.environment().put("GOCACHE", workDir.resolve("gocache").toString());
        return pb.start();
    }

    private void startProcess(Path logFile, String exe, Map<String, String> env) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(exe)
                .directory(repoRoot.toFile())
                .redirectErrorStream(true)
                .redirectOutput(logFile.toFile());
        pb.environment().putAll(env);
        processes.add(pb.start());
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        }
    }

    private static void waitForHealth(String url) throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(2)).GET().build();
        long deadline = System.currentTimeMillis() + 20_000;
        Exception last = null;
        while (System.currentTimeMillis() < deadline) {
            try {
                HttpResponse<Void> r = http.send(req, HttpResponse.BodyHandlers.discarding());
                if (r.statusCode() == 200) {
                    return;
                }
            } catch (Exception e) {
                last = e;
            }
            Thread.sleep(100);
        }
        throw new IllegalStateException("service not ready: " + url, last);
    }

    @Override
    public void close() {
        for (Process p : processes) {
            p.destroy();
        }
        for (Process p : processes) {
            try {
                if (!p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                p.destroyForcibly();
            }
        }
    }
}
