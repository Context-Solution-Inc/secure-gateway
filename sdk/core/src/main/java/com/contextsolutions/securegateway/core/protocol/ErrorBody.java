package com.contextsolutions.securegateway.core.protocol;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Structured payload of a relay-originated {@code error} message. */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class ErrorBody {

    @JsonProperty("code")
    public String code;

    @JsonProperty("detail")
    public String detail;

    public ErrorBody() {
    }
}
