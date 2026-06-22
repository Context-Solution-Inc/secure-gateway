package com.contextsolutions.securegateway.core.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.contextsolutions.securegateway.core.Role;
import com.contextsolutions.securegateway.core.transport.EndpointValidator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

/**
 * HTTPS client for the Auth &amp; License Service pairing/token API (PRD FR-2/FR-3),
 * matching {@code internal/authservice}. All public keys are base64-std of raw 32 bytes;
 * service errors ({@code {"error":"<code>"}}) surface as {@link AuthException}.
 *
 * <p>Built on {@link HttpURLConnection} so it is shared unchanged by the desktop (Java) and
 * mobile (Android) SDKs. NOTE: {@code java.net.http.HttpClient} (JDK 11+) is NOT on Android —
 * using it here threw {@code NoClassDefFoundError} on-device.
 */
public final class AuthClient {

    private final URI baseUrl;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthClient(String baseUrl) {
        // Enforce https:// (except loopback/RFC1918 for LAN dev) before any request,
        // so a malicious QR cannot send account/connection secrets in cleartext (SG-14).
        EndpointValidator.requireSecureAuth(baseUrl);
        // Normalize trailing slash so path joins are predictable.
        this.baseUrl = URI.create(baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl);
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

    /**
     * Revoke a pairing (FR-2.5): the peer's live session is cut and the pair slot freed,
     * so a new device can pair. Account-authenticated.
     */
    public void unpair(String accountSecret, String pairId) {
        send("/v1/pairings/unpair", accountSecret, body("pair_id", pairId), JsonNode.class);
    }

    // --- transport ---

    private <T> T send(String path, String bearer, ObjectMapperBody body, Class<T> type) {
        HttpURLConnection conn = null;
        try {
            URL url = baseUrl.resolve(path).toURL();
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(10_000);
            conn.setReadTimeout(15_000);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            if (bearer != null) {
                conn.setRequestProperty("Authorization", "Bearer " + bearer);
            }
            conn.setDoOutput(true);
            byte[] payload = mapper.writeValueAsBytes(body.node);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload);
            }
            int status = conn.getResponseCode();
            if (status / 100 != 2) {
                throw error(status, readAll(conn.getErrorStream()));
            }
            return mapper.readValue(readAll(conn.getInputStream()), type);
        } catch (IOException e) {
            throw new AuthException(0, "transport_error", path + ": " + e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        if (in == null) {
            return new byte[0];
        }
        try (InputStream s = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = s.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private AuthException error(int status, byte[] respBody) {
        String code = "http_" + status;
        try {
            JsonNode n = mapper.readTree(respBody);
            if (n != null && n.hasNonNull("error")) {
                code = n.get("error").asText();
            }
        } catch (IOException ignored) {
            // non-JSON error body; keep the http_<status> code.
        }
        return new AuthException(status, code, "auth service returned " + status + " (" + code + ")");
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
