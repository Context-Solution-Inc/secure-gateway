package com.contextsolutions.securegateway.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The M4 exit gate (PRD §11): the Java SDK reproduces the committed interop vectors
 * (internal/e2ee/testdata/vectors.json) byte-for-byte and decrypts them. vectors.json
 * is copied fresh from the Go reference at build time; the SHA-256 sidecar guards
 * against in-transit corruption.
 */
class VectorsConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TestFactory
    List<DynamicTest> vectors() throws Exception {
        byte[] raw = readResource("vectors.json");

        String expectedSha = new String(readResource("vectors.sha256")).trim();
        String actualSha = sha256Hex(raw);
        assertEquals(expectedSha, actualSha, "vectors.json checksum drift");

        JsonNode root = MAPPER.readTree(raw);
        JsonNode vectors = root.get("vectors");
        assertNotNull(vectors, "vectors array");
        assertTrue(vectors.size() >= 4, "expected >= 4 vectors");

        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : vectors) {
            tests.add(DynamicTest.dynamicTest(v.get("name").asText(), () -> checkVector(v)));
        }
        return tests;
    }

    private void checkVector(JsonNode v) {
        byte[] mobilePriv = Hex.decode(v.get("mobile_private").asText());
        byte[] mobilePub = Hex.decode(v.get("mobile_public").asText());
        byte[] desktopPriv = Hex.decode(v.get("desktop_private").asText());
        byte[] desktopPub = Hex.decode(v.get("desktop_public").asText());
        byte[] mobileEphPriv = Hex.decode(v.get("mobile_ephemeral_private").asText());
        byte[] mobileEphPub = Hex.decode(v.get("mobile_ephemeral_public").asText());
        byte[] desktopEphPriv = Hex.decode(v.get("desktop_ephemeral_private").asText());
        byte[] desktopEphPub = Hex.decode(v.get("desktop_ephemeral_public").asText());
        byte[] messageNonce = Hex.decode(v.get("message_nonce").asText());
        String id = v.get("id").asText();
        long ts = v.get("ts").asLong();
        byte[] plaintext = Hex.decode(v.get("plaintext").asText());
        byte[] wire = Hex.decode(v.get("wire_ciphertext").asText());
        Role sender = Role.fromWire(v.get("sender").asText());

        // 1. Public keys (identity + ephemeral) derive from the committed private keys.
        assertArrayEquals(mobilePub, Crypto.publicFromPrivate(mobilePriv), "mobile public");
        assertArrayEquals(desktopPub, Crypto.publicFromPrivate(desktopPriv), "desktop public");
        assertArrayEquals(mobileEphPub, Crypto.publicFromPrivate(mobileEphPriv), "mobile ephemeral public");
        assertArrayEquals(desktopEphPub, Crypto.publicFromPrivate(desktopEphPriv), "desktop ephemeral public");

        // 2. Re-seal via the sender's session with the fixed message nonce; the wire
        // bytes must match byte-for-byte (exercises the full key derivation + AEAD).
        Session senderSession = sender == Role.MOBILE
                ? Session.create(mobilePriv, desktopPub, mobileEphPriv, desktopEphPub, Role.MOBILE)
                : Session.create(desktopPriv, mobilePub, desktopEphPriv, mobileEphPub, Role.DESKTOP);
        byte[] produced = senderSession.sealWith(messageNonce, id, ts, plaintext);
        assertArrayEquals(wire, produced, "wire ciphertext");

        // 3. The peer opens the wire payload back to the plaintext.
        Session receiverSession = sender == Role.MOBILE
                ? Session.create(desktopPriv, mobilePub, desktopEphPriv, mobileEphPub, Role.DESKTOP)
                : Session.create(mobilePriv, desktopPub, mobileEphPriv, desktopEphPub, Role.MOBILE);
        byte[] opened = receiverSession.open(id, ts, wire);
        assertArrayEquals(plaintext, opened, "decrypted plaintext");
    }

    private static byte[] readResource(String name) throws Exception {
        try (InputStream in = VectorsConformanceTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "missing test resource: " + name);
            return in.readAllBytes();
        }
    }

    private static String sha256Hex(byte[] b) throws Exception {
        return Hex.encode(MessageDigest.getInstance("SHA-256").digest(b));
    }
}
