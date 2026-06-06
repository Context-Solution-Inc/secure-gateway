package com.securegateway.mobile

import com.fasterxml.jackson.databind.ObjectMapper
import com.securegateway.core.Crypto
import com.securegateway.core.Hex
import com.securegateway.core.Role
import com.securegateway.core.SealBridge
import com.securegateway.core.Session
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.security.MessageDigest

/**
 * The M4 exit gate for the Kotlin SDK: it must reproduce the same interop vectors
 * as the Java SDK and the Go reference, byte-for-byte. It shares the [Crypto]/[Session]
 * implementation from :core, so passing here proves the single-sourced crypto works
 * identically when driven from Kotlin.
 */
class VectorsConformanceKtTest {

    private val mapper = ObjectMapper()

    @TestFactory
    fun vectors(): List<DynamicTest> {
        val raw = readResource("vectors.json")
        val expectedSha = String(readResource("vectors.sha256")).trim()
        assertEquals(expectedSha, sha256Hex(raw), "vectors.json checksum drift")

        val root = mapper.readTree(raw)
        val vectors = root.get("vectors")
        assertNotNull(vectors, "vectors array")
        assertTrue(vectors.size() >= 4, "expected >= 4 vectors")

        return vectors.map { v ->
            DynamicTest.dynamicTest(v.get("name").asText()) { checkVector(v) }
        }
    }

    private fun checkVector(v: com.fasterxml.jackson.databind.JsonNode) {
        val mobilePriv = Hex.decode(v.get("mobile_private").asText())
        val mobilePub = Hex.decode(v.get("mobile_public").asText())
        val desktopPriv = Hex.decode(v.get("desktop_private").asText())
        val desktopPub = Hex.decode(v.get("desktop_public").asText())
        val mobileNonce = Hex.decode(v.get("mobile_handshake_nonce").asText())
        val desktopNonce = Hex.decode(v.get("desktop_handshake_nonce").asText())
        val messageNonce = Hex.decode(v.get("message_nonce").asText())
        val id = v.get("id").asText()
        val ts = v.get("ts").asLong()
        val plaintext = Hex.decode(v.get("plaintext").asText())
        val wire = Hex.decode(v.get("wire_ciphertext").asText())
        val sender = Role.fromWire(v.get("sender").asText())

        assertArrayEquals(mobilePub, Crypto.publicFromPrivate(mobilePriv), "mobile public")
        assertArrayEquals(desktopPub, Crypto.publicFromPrivate(desktopPriv), "desktop public")

        val senderPriv = if (sender == Role.MOBILE) mobilePriv else desktopPriv
        val peerPub = if (sender == Role.MOBILE) desktopPub else mobilePub
        val senderSession = Session.create(senderPriv, peerPub, sender, mobileNonce, desktopNonce)
        // sealWith is package-private in :core; the test bridge below exposes it.
        val produced = SealBridge.sealWith(senderSession, messageNonce, id, ts, plaintext)
        assertArrayEquals(wire, produced, "wire ciphertext")

        val peerRole = if (sender == Role.MOBILE) Role.DESKTOP else Role.MOBILE
        val receiverPriv = if (sender == Role.MOBILE) desktopPriv else mobilePriv
        val receiverPeerPub = if (sender == Role.MOBILE) mobilePub else desktopPub
        val receiverSession = Session.create(receiverPriv, receiverPeerPub, peerRole, mobileNonce, desktopNonce)
        assertArrayEquals(plaintext, receiverSession.open(id, ts, wire), "decrypted plaintext")
    }

    private fun readResource(name: String): ByteArray =
        javaClass.classLoader.getResourceAsStream(name).use {
            assertNotNull(it, "missing test resource: $name")
            it!!.readBytes()
        }

    private fun sha256Hex(b: ByteArray): String =
        Hex.encode(MessageDigest.getInstance("SHA-256").digest(b))
}
