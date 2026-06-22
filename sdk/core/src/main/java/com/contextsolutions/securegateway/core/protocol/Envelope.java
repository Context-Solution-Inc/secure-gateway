package com.contextsolutions.securegateway.core.protocol;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * The v1 relay wire frame (PRD FR-4.1), matching the Go reference
 * {@code internal/relay/protocol.Envelope}. The relay reads only {@code v}/{@code type}/
 * {@code id}; {@code payload} is opaque end-to-end.
 *
 * <p>For {@code msg}/{@code ack} the payload is the ciphertext bytes encoded as a
 * base64-std JSON string (matching Go's {@code json.Marshal([]byte)}); for
 * {@code sys}/{@code error}/{@code auth_refresh} it is a JSON object. See {@link Protocol}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"v", "type", "id", "ts", "payload"})
public final class Envelope {

    @JsonProperty("v")
    public int v = Protocol.VERSION;

    @JsonProperty("type")
    public String type;

    @JsonProperty("id")
    public String id;

    @JsonProperty("ts")
    public long ts;

    @JsonProperty("payload")
    public JsonNode payload;

    public Envelope() {
    }

    public Envelope(String type, String id, long ts, JsonNode payload) {
        this.v = Protocol.VERSION;
        this.type = type;
        this.id = id;
        this.ts = ts;
        this.payload = payload;
    }
}
