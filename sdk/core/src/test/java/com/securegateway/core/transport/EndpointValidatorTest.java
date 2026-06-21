package com.securegateway.core.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Covers the SG-14/SG-19 wss/https enforcement and the loopback/RFC1918 carve-out. */
class EndpointValidatorTest {

    @Test
    void secureSchemesAlwaysAccepted() {
        assertEquals("wss://relay.example.com/v1/connect",
            EndpointValidator.requireSecureRelay("wss://relay.example.com/v1/connect"));
        assertEquals("https://auth.example.com",
            EndpointValidator.requireSecureAuth("https://auth.example.com"));
    }

    @Test
    void plaintextRejectedForPublicHosts() {
        assertThrows(IllegalArgumentException.class,
            () -> EndpointValidator.requireSecureRelay("ws://relay.example.com/v1/connect"));
        assertThrows(IllegalArgumentException.class,
            () -> EndpointValidator.requireSecureAuth("http://auth.example.com"));
        // A public IP literal is not in any private range.
        assertThrows(IllegalArgumentException.class,
            () -> EndpointValidator.requireSecureRelay("ws://8.8.8.8:8443/v1/connect"));
    }

    @Test
    void plaintextAllowedForLoopbackAndPrivateRanges() {
        assertEquals("ws://127.0.0.1:8443/v1/connect",
            EndpointValidator.requireSecureRelay("ws://127.0.0.1:8443/v1/connect"));
        assertEquals("ws://localhost:8443/v1/connect",
            EndpointValidator.requireSecureRelay("ws://localhost:8443/v1/connect"));
        assertEquals("http://192.168.1.10:8080",
            EndpointValidator.requireSecureAuth("http://192.168.1.10:8080"));
        assertEquals("ws://10.0.0.5/v1/connect",
            EndpointValidator.requireSecureRelay("ws://10.0.0.5/v1/connect"));
        assertEquals("ws://172.16.0.9/v1/connect",
            EndpointValidator.requireSecureRelay("ws://172.16.0.9/v1/connect"));
        assertEquals("ws://[::1]:8443/v1/connect",
            EndpointValidator.requireSecureRelay("ws://[::1]:8443/v1/connect"));
    }

    @Test
    void nullEmptyAndMalformedRejected() {
        assertThrows(IllegalArgumentException.class, () -> EndpointValidator.requireSecureRelay(null));
        assertThrows(IllegalArgumentException.class, () -> EndpointValidator.requireSecureRelay(""));
        assertThrows(IllegalArgumentException.class, () -> EndpointValidator.requireSecureRelay("not a url"));
        assertThrows(IllegalArgumentException.class, () -> EndpointValidator.requireSecureRelay("wss://"));
    }

    @Test
    void privateRangeBoundaries() {
        // 172.16/12 only covers second octet 16..31; 172.32 is public.
        assertTrue(EndpointValidator.isPrivateOrLoopback("172.31.255.254"));
        assertFalse(EndpointValidator.isPrivateOrLoopback("172.32.0.1"));
        assertFalse(EndpointValidator.isPrivateOrLoopback("172.15.0.1"));
        // 192.168/16 only; 192.169 is public.
        assertTrue(EndpointValidator.isPrivateOrLoopback("192.168.255.1"));
        assertFalse(EndpointValidator.isPrivateOrLoopback("192.169.0.1"));
        // Hostnames that are not loopback are treated as public.
        assertFalse(EndpointValidator.isPrivateOrLoopback("relay.internal"));
    }
}
