package com.securegateway.core.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.Base64;

/**
 * Wire vocabulary and codec for the relay envelope (PRD FR-4, Appendix B), matching
 * the Go reference {@code internal/relay/protocol}. Encodes/decodes envelopes and
 * builds/parses the typed payloads.
 */
public final class Protocol {

    public static final int VERSION = 1;

    // Message types (FR-4.1).
    public static final String TYPE_MSG = "msg";
    public static final String TYPE_ACK = "ack";
    public static final String TYPE_AUTH_REFRESH = "auth_refresh";
    public static final String TYPE_ERROR = "error";
    public static final String TYPE_SYS = "sys";

    // sys kinds (FR-4.2).
    public static final String SYS_PEER_ONLINE = "peer_online";
    public static final String SYS_PEER_OFFLINE = "peer_offline";
    public static final String SYS_SHUTDOWN = "shutdown";

    // error codes.
    public static final String ERR_PEER_OFFLINE = "peer_offline";
    public static final String ERR_PROTOCOL = "protocol_error";
    public static final String ERR_UNAUTHORIZED = "unauthorized";

    // WebSocket close codes (Appendix B). 1000/1001 standard; 4001-4005 app-specific.
    public static final int CLOSE_NORMAL = 1000;
    public static final int CLOSE_GOING_AWAY = 1001;
    public static final int CLOSE_SUPERSEDED = 4001;   // do not auto-reconnect
    public static final int CLOSE_TOKEN_EXPIRED = 4003; // refresh token, reconnect
    public static final int CLOSE_REVOKED = 4004;       // do not reconnect
    public static final int CLOSE_PROTOCOL = 4005;      // protocol error / oversize

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getEncoder();      // std, padded
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private Protocol() {
    }

    public static byte[] encode(Envelope env) {
        try {
            return MAPPER.writeValueAsBytes(env);
        } catch (IOException e) {
            throw new IllegalArgumentException("encode envelope: " + e.getMessage(), e);
        }
    }

    public static Envelope decode(byte[] raw) {
        try {
            Envelope env = MAPPER.readValue(raw, Envelope.class);
            if (env.v != VERSION) {
                throw new IllegalArgumentException("unsupported envelope version " + env.v);
            }
            if (env.id == null || env.id.isEmpty()) {
                throw new IllegalArgumentException("envelope missing id");
            }
            return env;
        } catch (IOException e) {
            throw new IllegalArgumentException("malformed envelope: " + e.getMessage(), e);
        }
    }

    /**
     * Build a {@code msg} envelope carrying opaque ciphertext. The bytes are encoded
     * as a base64-std JSON string, exactly as the Go reference test client does
     * ({@code json.Marshal([]byte)}).
     */
    public static Envelope msg(String id, long ts, byte[] ciphertext) {
        return new Envelope(TYPE_MSG, id, ts, MAPPER.getNodeFactory().textNode(B64.encodeToString(ciphertext)));
    }

    /** Build an {@code ack} envelope referencing the message {@code id} being acked. */
    public static Envelope ack(String id, long ts) {
        return new Envelope(TYPE_ACK, id, ts, null);
    }

    /** Build an {@code auth_refresh} envelope carrying a fresh JWT over the live socket. */
    public static Envelope authRefresh(String id, long ts, String token) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("token", token);
        return new Envelope(TYPE_AUTH_REFRESH, id, ts, body);
    }

    /** Decode the opaque ciphertext from a {@code msg}/{@code ack} payload (base64-std string). */
    public static byte[] ciphertext(Envelope env) {
        JsonNode p = env.payload;
        if (p == null || !p.isTextual()) {
            throw new IllegalArgumentException("envelope payload is not a base64 string");
        }
        return B64D.decode(p.asText());
    }

    /** Parse a {@code sys} payload. */
    public static SysBody sys(Envelope env) {
        return convert(env.payload, SysBody.class);
    }

    /** Parse an {@code error} payload. */
    public static ErrorBody error(Envelope env) {
        return convert(env.payload, ErrorBody.class);
    }

    private static <T> T convert(JsonNode node, Class<T> type) {
        if (node == null) {
            throw new IllegalArgumentException("missing payload for " + type.getSimpleName());
        }
        return MAPPER.convertValue(node, type);
    }
}
