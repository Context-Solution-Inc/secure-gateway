package com.contextsolutions.securegateway.core.protocol;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Structured payload of a relay-originated {@code sys} message (presence/lifecycle). */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class SysBody {

    @JsonProperty("kind")
    public String kind;

    @JsonProperty("detail")
    public String detail;

    public SysBody() {
    }
}
