package com.securegateway.core.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securegateway.core.Role;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Validates AuthClient request shaping (bearer header, JSON bodies) and response/error mapping. */
class AuthClientTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HttpServer server;
    private AuthClient client;
    private volatile String lastPath;
    private volatile String lastAuthHeader;
    private volatile JsonNode lastBody;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
        client = new AuthClient("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void registerDeviceSendsBearerAndRole() {
        respondWith = "{\"device_id\":\"dev_1\"}";
        String id = client.registerDevice("acct.secret", Role.MOBILE, "cHVia2V5");
        assertEquals("dev_1", id);
        assertEquals("/v1/devices", lastPath);
        assertEquals("Bearer acct.secret", lastAuthHeader);
        assertEquals("mobile", lastBody.get("role").asText());
        assertEquals("cHVia2V5", lastBody.get("public_key").asText());
    }

    @Test
    void completePairingHasNoBearerAndParsesResult() {
        respondWith = "{\"pair_id\":\"pair_X\",\"desktop_public_key\":\"ZGtwdWI=\"}";
        AuthClient.CompletePairingResult r = client.completePairing("ptok", "dev_m", "bW9icHVi");
        assertEquals("pair_X", r.pairId);
        assertEquals("ZGtwdWI=", r.desktopPublicKey);
        assertEquals(null, lastAuthHeader); // pairing token authorizes; no bearer
        assertEquals("ptok", lastBody.get("pairing_token").asText());
    }

    @Test
    void createPairingTokenParsesQr() {
        respondWith = "{\"pairing_token\":\"pt\",\"expires_in\":300,\"qr\":{\"v\":1,"
                + "\"pairing_token\":\"pt\",\"desktop_pubkey\":\"ZGs=\",\"desktop_device_id\":\"dev_d\","
                + "\"endpoints\":{\"relay\":\"wss://r/v1/connect\",\"auth\":\"https://a\"}}}";
        AuthClient.PairingTokenResult r = client.createPairingToken("acct.s", "lic_1", "dev_d", "ZGs=");
        assertEquals(300, r.expiresIn);
        assertEquals(1, r.qr.v);
        assertEquals("wss://r/v1/connect", r.qr.relayEndpoint());
        assertEquals("https://a", r.qr.authEndpoint());
    }

    @Test
    void refreshRotatesAndTokenStoreTracks() {
        respondWith = "{\"token\":\"jwt2\",\"refresh_token\":\"rt2\",\"expires_in\":600}";
        TokenStore store = new TokenStore();
        store.update(client.refreshToken("rt1"));
        assertEquals("jwt2", store.token());
        assertEquals("rt2", store.refreshToken());
        assertEquals("rt1", lastBody.get("refresh_token").asText());
    }

    @Test
    void mapsErrorBodyToAuthException() {
        respondStatus = 403;
        respondWith = "{\"error\":\"license_invalid\"}";
        AuthException ex = assertThrows(AuthException.class,
                () -> client.issueToken("acct.s", "dev_d", "pair_X"));
        assertEquals(403, ex.httpStatus());
        assertEquals("license_invalid", ex.code());
    }

    @Test
    void qrPayloadJsonRoundTrips() {
        String json = "{\"v\":1,\"pairing_token\":\"pt\",\"desktop_pubkey\":\"ZGs=\","
                + "\"desktop_device_id\":\"dev_d\",\"endpoints\":{\"relay\":\"wss://r\",\"auth\":\"https://a\"}}";
        QrPayload p = QrPayload.fromJson(json);
        assertEquals("dev_d", p.desktopDeviceId);
        assertTrue(p.toJson().contains("\"pairing_token\":\"pt\""));
    }

    // --- fake server ---

    private volatile String respondWith = "{}";
    private volatile int respondStatus = 200;

    private void handle(HttpExchange ex) throws IOException {
        lastPath = ex.getRequestURI().getPath();
        lastAuthHeader = ex.getRequestHeaders().getFirst("Authorization");
        byte[] reqBytes = ex.getRequestBody().readAllBytes();
        lastBody = reqBytes.length > 0 ? MAPPER.readTree(reqBytes) : MAPPER.createObjectNode();
        byte[] out = respondWith.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(respondStatus, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }
}
