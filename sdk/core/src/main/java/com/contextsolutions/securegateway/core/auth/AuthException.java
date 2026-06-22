package com.contextsolutions.securegateway.core.auth;

/**
 * A typed auth-service error. {@link #code} is the machine-readable reason from the
 * service's {@code {"error":"<code>"}} body (e.g. {@code license_invalid},
 * {@code capacity_exceeded}, {@code unauthorized}); {@link #httpStatus} is the HTTP code.
 */
public final class AuthException extends RuntimeException {

    private final String code;
    private final int httpStatus;

    public AuthException(int httpStatus, String code, String message) {
        super(message);
        this.httpStatus = httpStatus;
        this.code = code;
    }

    public String code() {
        return code;
    }

    public int httpStatus() {
        return httpStatus;
    }
}
