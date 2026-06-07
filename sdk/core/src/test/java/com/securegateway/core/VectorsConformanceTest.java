package com.securegateway.core;

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
        byte[] mobileNonce = Hex.decode(v.get("mobile_handshake_nonce").asText());
        byte[] desktopNonce = Hex.decode(v.get("desktop_handshake_nonce").asText());
        byte[] keyM2D = Hex.decode(v.get("key_m2d").asText());
        byte[] keyD2M = Hex.decode(v.get("key_d2m").asText());
        byte[] messageNonce = Hex.decode(v.get("message_nonce").asText());
        String id = v.get("id").asText();
        long ts = v.get("ts").asLong();
        byte[] plaintext = Hex.decode(v.get("plaintext").asText());
        byte[] wire = Hex.decode(v.get("wire_ciphertext").asText());
        Role sender = Role.fromWire(v.get("sender").asText());

        // 1. Public keys derive from the committed private keys.
        assertArrayEquals(mobilePub, Crypto.publicFromPrivate(mobilePriv), "mobile public");
        assertArrayEquals(desktopPub, Crypto.publicFromPrivate(desktopPriv), "desktop public");

        // 2. Directional keys match (validates X25519 ECDH + HKDF-SHA256).
        Session mobileSelf = Session.create(mobilePriv, desktopPub, Role.MOBILE, mobileNonce, desktopNonce);
        // Re-seal via the sender's own session with the fixed message nonce and
        // assert the wire bytes match byte-for-byte; this exercises seal + AEAD.
        byte[] senderPriv = sender == Role.MOBILE ? mobilePriv : desktopPriv;
        byte[] peerPub = sender == Role.MOBILE ? desktopPub : mobilePub;
        Session senderSession = Session.create(senderPriv, peerPub, sender, mobileNonce, desktopNonce);
        byte[] produced = senderSession.sealWith(messageNonce, id, ts, plaintext);
        assertArrayEquals(wire, produced, "wire ciphertext");

        // 3. The peer opens the wire payload back to the plaintext.
        Role peerRole = sender == Role.MOBILE ? Role.DESKTOP : Role.MOBILE;
        byte[] receiverPriv = sender == Role.MOBILE ? desktopPriv : mobilePriv;
        byte[] receiverPeerPub = sender == Role.MOBILE ? mobilePub : desktopPub;
        Session receiverSession = Session.create(receiverPriv, receiverPeerPub, peerRole, mobileNonce, desktopNonce);
        byte[] opened = receiverSession.open(id, ts, wire);
        assertArrayEquals(plaintext, opened, "decrypted plaintext");

        // Sanity: keys in the vector are reproducible (m2d derived independent of role).
        assertArrayEquals(keyM2D, deriveDirect(mobilePriv, desktopPub, mobileNonce, desktopNonce, Crypto.DIR_M2D));
        assertArrayEquals(keyD2M, deriveDirect(mobilePriv, desktopPub, mobileNonce, desktopNonce, Crypto.DIR_D2M));
        // mobileSelf is referenced to ensure construction succeeds for the mobile role too.
        assertNotNull(mobileSelf);
    }

    // Derive a directional key the same way Session does, for the key_m2d/key_d2m asserts.
    private static byte[] deriveDirect(byte[] myPriv, byte[] peerPub, byte[] mobileNonce, byte[] desktopNonce, String dir) {
        byte[] shared = Crypto.deriveSharedSecret(myPriv, peerPub);
        byte[] salt = new byte[mobileNonce.length + desktopNonce.length];
        System.arraycopy(mobileNonce, 0, salt, 0, mobileNonce.length);
        System.arraycopy(desktopNonce, 0, salt, mobileNonce.length, desktopNonce.length);
        byte[] info = (Crypto.INFO_PREFIX + dir).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return Hkdf.derive(shared, salt, info, Crypto.KEY_SIZE);
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
