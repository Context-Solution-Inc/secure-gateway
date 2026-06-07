package com.securegateway.mobile

import com.securegateway.core.Role
import com.securegateway.core.auth.AuthClient
import com.securegateway.core.auth.QrPayload
import com.securegateway.core.auth.TokenStore
import com.securegateway.core.client.RelayClient
import com.securegateway.core.transport.ConnectionState
import com.securegateway.core.transport.Credentials
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.function.Consumer

/**
 * Mobile SDK facade (PRD §8.1). It scans the desktop's QR ([pair]), completes pairing and
 * key exchange, then connects to the relay and exposes the common
 * `send`/`onMessage`/`onStateChange` surface over [OkHttpWebSocketTransport]. The Android
 * Keystore and FCM seams are injected via [MobileConfig] (stubbed on the JVM build).
 *
 * Obtain one via [SecureGateway.mobile].
 */
class MobileClient internal constructor(private val config: MobileConfig) {

    private val auth = AuthClient(config.authUrl)
    private val identity = config.keyStore.loadOrCreateIdentity()
    private val publicKeyB64: String = Base64.getEncoder().encodeToString(identity.publicKey())

    private var deviceId: String? = config.deviceId
    private var pairId: String? = null
    private var peerPublicKey: ByteArray? = null
    private var relayUrl: String? = config.relayUrl

    private var onMessage: Consumer<ByteArray> = Consumer { }
    private var onStateChange: Consumer<ConnectionState> = Consumer { }
    private var client: RelayClient? = null

    fun onMessage(handler: (ByteArray) -> Unit): MobileClient {
        onMessage = Consumer { handler(it) }
        return this
    }

    fun onStateChange(handler: (ConnectionState) -> Unit): MobileClient {
        onStateChange = Consumer { handler(it) }
        return this
    }

    /** Scan a QR payload: register this device, complete pairing, and exchange public keys. */
    fun pair(qr: QrPayload) {
        config.pushWaker.register("mobile-push-token") // host supplies the real FCM token
        ensureDevice()
        val result = auth.completePairing(qr.pairingToken, deviceId, publicKeyB64)
        pairId = result.pairId
        peerPublicKey = Base64.getDecoder().decode(result.desktopPublicKey)
        relayUrl = qr.relayEndpoint() ?: relayUrl
    }

    /** Parse a scanned QR JSON string and pair. */
    fun pair(qrJson: String) = pair(QrPayload.fromJson(qrJson))

    /** Issue a connection token and open the relay session. Requires [pair] to have run. */
    fun connect() {
        val pid = pairId ?: error("call pair(qr) first")
        val peer = peerPublicKey ?: error("missing desktop public key")
        val url = relayUrl ?: error("missing relay endpoint")
        val tokens = TokenStore()
        tokens.update(auth.issueToken(config.accountSecret, deviceId, pid))
        val cred = Credentials(url, Role.MOBILE, identity.privateKey(), peer, tokens, auth)
        client = RelayClient(cred) { OkHttpWebSocketTransport() }
            .onMessage(onMessage)
            .onStateChange(onStateChange)
            .also { it.connect() }
    }

    fun send(plaintext: ByteArray): CompletableFuture<Void> =
        client?.send(plaintext) ?: error("not connected")

    fun state(): ConnectionState? = client?.state()

    fun pairId(): String? = pairId

    fun close() {
        client?.close()
    }

    private fun ensureDevice() {
        if (deviceId == null) {
            deviceId = auth.registerDevice(config.accountSecret, Role.MOBILE, publicKeyB64)
        }
    }
}
