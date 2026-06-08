package com.securegateway.core.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

/**
 * The versioned QR pairing payload (PRD FR-2.1), matching the Go reference
 * {@code internal/authservice.qrPayload}. The desktop emits it via
 * {@code generatePairingQr()}; the mobile scans and parses it via {@code pair(qrPayload)}.
 *
 * <p>A QR with {@code v} absent or unknown should fall back to legacy local-sync
 * behavior in the host app (FR-2.x backward compatibility).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class QrPayload {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @JsonProperty("v")
    public int v;

    @JsonProperty("pairing_token")
    public String pairingToken;

    /** Desktop X25519 public key, base64-std of raw 32 bytes. */
    @JsonProperty("desktop_pubkey")
    public String desktopPubkey;

    @JsonProperty("desktop_device_id")
    public String desktopDeviceId;

    /** Endpoint URLs: keys {@code relay} (wss) and {@code auth} (https). */
    @JsonProperty("endpoints")
    public Map<String, String> endpoints;

    /**
     * The desktop's account secret, injected client-side by
     * {@code DesktopClient.generatePairingQr} (NOT minted by the gateway). The
     * mobile has no subscription of its own, so the in-person QR scan conveys the
     * credential the phone needs to issue connection tokens. Optional for backward
     * compatibility with legacy (gateway-only) QR payloads.
     */
    @JsonProperty("account_secret")
    public String accountSecret;

    public QrPayload() {
    }

    /** Serialize to the JSON string that is embedded in the QR code. */
    public String toJson() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (Exception e) {
            throw new IllegalArgumentException("encode qr payload: " + e.getMessage(), e);
        }
    }

    /** Parse the JSON string scanned from a QR code. */
    public static QrPayload fromJson(String json) {
        try {
            return MAPPER.readValue(json, QrPayload.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("decode qr payload: " + e.getMessage(), e);
        }
    }

    public String relayEndpoint() {
        return endpoints == null ? null : endpoints.get("relay");
    }

    public String authEndpoint() {
        return endpoints == null ? null : endpoints.get("auth");
    }
}
