package com.securegateway.core.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securegateway.core.Role;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * HTTPS client for the Auth &amp; License Service pairing/token API (PRD FR-2/FR-3),
 * matching {@code internal/authservice}. All public keys are base64-std of raw 32 bytes;
 * service errors ({@code {"error":"<code>"}}) surface as {@link AuthException}.
 *
 * <p>Built on the JDK {@link HttpClient} (zero added dependency, JDK 11+), so it is shared
 * unchanged by the desktop (Java) and mobile (Kotlin/JVM) SDKs.
 */
public final class AuthClient {

    private final URI baseUrl;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthClient(String baseUrl) {
        this(baseUrl, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public AuthClient(String baseUrl, HttpClient http) {
        // Normalize trailing slash so path joins are predictable.
        this.baseUrl = URI.create(baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl);
        this.http = http;
    }

    // --- Account / device (admin + account-authenticated seams) ---

    /** Admin-only: create/rotate an account credential. */
    public AccountResult createAccount(String adminKey, String accountId) {
        ObjectMapperBody body = body("account_id", accountId);
        return send("/v1/accounts", adminKey, body, AccountResult.class);
    }

    /** Register a device under the account; {@code publicKeyB64} may be null (filled at pairing). */
    public String registerDevice(String accountSecret, Role role, String publicKeyB64) {
        ObjectMapperBody body = body("role", role.wire());
        if (publicKeyB64 != null) {
            body.put("public_key", publicKeyB64);
        }
        return send("/v1/devices", accountSecret, body, DeviceResult.class).deviceId;
    }

    // --- Pairing (FR-2) ---

    /** Desktop: request a one-time pairing token and the QR payload to render. */
    public PairingTokenResult createPairingToken(String accountSecret, String licenseId,
                                                 String desktopDeviceId, String desktopPublicKeyB64) {
        ObjectMapperBody body = body("license_id", licenseId).put("desktop_device_id", desktopDeviceId);
        if (desktopPublicKeyB64 != null) {
            body.put("desktop_public_key", desktopPublicKeyB64);
        }
        return send("/v1/pairing-tokens", accountSecret, body, PairingTokenResult.class);
    }

    /** Mobile: complete pairing with its X25519 public key (the pairing token authorizes). */
    public CompletePairingResult completePairing(String pairingToken, String mobileDeviceId,
                                                 String mobilePublicKeyB64) {
        ObjectMapperBody body = body("pairing_token", pairingToken)
                .put("mobile_device_id", mobileDeviceId)
                .put("mobile_public_key", mobilePublicKeyB64);
        return send("/v1/pairings", null, body, CompletePairingResult.class);
    }

    /** Desktop: poll for the mobile completing the pairing (learns pair_id + mobile pubkey). */
    public PollResult pollPairingToken(String accountSecret, String pairingToken) {
        return send("/v1/pairing-tokens/poll", accountSecret, body("pairing_token", pairingToken), PollResult.class);
    }

    // --- Tokens (FR-3) ---

    /** Issue a connection JWT + refresh token for a (device, pair). */
    public TokenResult issueToken(String accountSecret, String deviceId, String pairId) {
        ObjectMapperBody body = body("device_id", deviceId).put("pair_id", pairId);
        return send("/v1/token", accountSecret, body, TokenResult.class);
    }

    /** Refresh a connection JWT. The refresh token is single-use; persist the returned one. */
    public TokenResult refreshToken(String refreshToken) {
        return send("/v1/token/refresh", null, body("refresh_token", refreshToken), TokenResult.class);
    }

    // --- transport ---

    private <T> T send(String path, String bearer, ObjectMapperBody body, Class<T> type) {
        try {
            HttpRequest.Builder req = HttpRequest.newBuilder()
                    .uri(baseUrl.resolve(path))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(body.node)));
            if (bearer != null) {
                req.header("Authorization", "Bearer " + bearer);
            }
            HttpResponse<byte[]> resp = http.send(req.build(), HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() / 100 != 2) {
                throw error(resp);
            }
            return mapper.readValue(resp.body(), type);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new AuthException(0, "transport_error", path + ": " + e.getMessage());
        }
    }

    private AuthException error(HttpResponse<byte[]> resp) {
        String code = "http_" + resp.statusCode();
        try {
            JsonNode n = mapper.readTree(resp.body());
            if (n.hasNonNull("error")) {
                code = n.get("error").asText();
            }
        } catch (IOException ignored) {
            // non-JSON error body; keep the http_<status> code.
        }
        return new AuthException(resp.statusCode(), code, "auth service returned " + resp.statusCode() + " (" + code + ")");
    }

    private ObjectMapperBody body(String k, String v) {
        ObjectMapperBody b = new ObjectMapperBody(mapper);
        b.put(k, v);
        return b;
    }

    /** Tiny fluent JSON object builder. */
    private static final class ObjectMapperBody {
        private final com.fasterxml.jackson.databind.node.ObjectNode node;

        ObjectMapperBody(ObjectMapper mapper) {
            this.node = mapper.createObjectNode();
        }

        ObjectMapperBody put(String k, String v) {
            node.put(k, v);
            return this;
        }
    }

    // --- result models ---

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class AccountResult {
        @JsonProperty("account_id")
        public String accountId;
        @JsonProperty("secret")
        public String secret;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class DeviceResult {
        @JsonProperty("device_id")
        public String deviceId;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class PairingTokenResult {
        @JsonProperty("pairing_token")
        public String pairingToken;
        @JsonProperty("expires_in")
        public int expiresIn;
        @JsonProperty("qr")
        public QrPayload qr;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class CompletePairingResult {
        @JsonProperty("pair_id")
        public String pairId;
        @JsonProperty("desktop_public_key")
        public String desktopPublicKey;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class PollResult {
        public static final String PENDING = "pending";
        public static final String COMPLETED = "completed";
        public static final String EXPIRED = "expired";

        @JsonProperty("status")
        public String status;
        @JsonProperty("pair_id")
        public String pairId;
        @JsonProperty("mobile_public_key")
        public String mobilePublicKey;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class TokenResult {
        @JsonProperty("token")
        public String token;
        @JsonProperty("refresh_token")
        public String refreshToken;
        @JsonProperty("expires_in")
        public int expiresIn;
    }
}
