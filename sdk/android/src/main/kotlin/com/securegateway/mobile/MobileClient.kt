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
    // Seeded from config to support reconnect-without-repair (the QR's pairing token is
    // single-use; a restored pairId + desktop public key let connect() run on its own).
    private var pairId: String? = config.pairId
    private var peerPublicKey: ByteArray? = config.desktopPublicKeyB64?.let { Base64.getDecoder().decode(it) }
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
        // The relay QR carries the desktop's account secret (the phone has no
        // subscription of its own) — adopt it before any authed call.
        qr.accountSecret?.takeIf { it.isNotBlank() }?.let { config.accountSecret = it }
        val log = config.logger
        log("pair: auth=${config.authUrl} relay=${qr.relayEndpoint() ?: config.relayUrl} secret=${if (config.accountSecret.isNullOrBlank()) "MISSING" else "present"}")
        config.pushWaker.register("mobile-push-token") // host supplies the real FCM token
        ensureDevice()
        log("pair: device registered id=$deviceId; completing pairing token=${qr.pairingToken.take(8)}…")
        val result = auth.completePairing(qr.pairingToken, deviceId, publicKeyB64)
        pairId = result.pairId
        peerPublicKey = Base64.getDecoder().decode(result.desktopPublicKey)
        relayUrl = qr.relayEndpoint() ?: relayUrl
        log("pair: ok pairId=$pairId peerPubKey=${peerPublicKey?.size}B relay=$relayUrl")
    }

    /** Parse a scanned QR JSON string and pair. */
    fun pair(qrJson: String) = pair(QrPayload.fromJson(qrJson))

    /** Issue a connection token and open the relay session. Requires [pair] to have run. */
    fun connect() {
        val log = config.logger
        val pid = pairId ?: error("call pair(qr) first")
        val peer = peerPublicKey ?: error("missing desktop public key")
        val url = relayUrl ?: error("missing relay endpoint")
        log("connect: issuing token (account secret) for pairId=$pid device=$deviceId")
        val tokens = TokenStore()
        tokens.update(auth.issueToken(accountSecret(), deviceId, pid))
        log("connect: token issued; opening relay session at $url (the wss dial runs async — watch for state/onFailure below)")
        val cred = Credentials(url, Role.MOBILE, identity.privateKey(), peer, tokens, auth)
        client = RelayClient(cred) { OkHttpWebSocketTransport(logger = log) }
            .onMessage(onMessage)
            .onStateChange(onStateChange)
            .also { it.connect() }
    }

    fun send(plaintext: ByteArray): CompletableFuture<Void> =
        client?.send(plaintext) ?: error("not connected")

    fun state(): ConnectionState? = client?.state()

    fun pairId(): String? = pairId

    fun deviceId(): String? = deviceId

    /** Base64-std of the desktop's X25519 public key learned at [pair] (null before pairing). */
    fun desktopPublicKeyB64(): String? = peerPublicKey?.let { Base64.getEncoder().encodeToString(it) }

    /**
     * True once paired — in this process via [pair], or restored from a prior pairing via
     * [MobileConfig.pairId] + [MobileConfig.desktopPublicKeyB64]. When true, [connect] can run
     * on its own (no [pair], so no spent-pairing-token 401). Persist [deviceId]/[pairId]/
     * [desktopPublicKeyB64] after a successful [pair] and feed them back via [MobileConfig] to
     * reconnect after a toggle/relaunch.
     */
    fun isPaired(): Boolean = pairId != null && peerPublicKey != null

    /**
     * Revoke this pairing at the gateway (FR-2.5): the relay session is cut and the pair
     * slot freed, so the desktop can pair a new phone. No-op if pairing never completed.
     * Blocking HTTP — call off the main thread. Call [close] afterward to drop the session.
     */
    fun unpair() {
        val pid = pairId ?: return
        config.logger("unpair: revoking pairId=$pid")
        auth.unpair(accountSecret(), pid)
        pairId = null
        peerPublicKey = null
    }

    fun close() {
        client?.close()
    }

    private fun ensureDevice() {
        if (deviceId == null) {
            deviceId = auth.registerDevice(accountSecret(), Role.MOBILE, publicKeyB64)
        }
    }

    private fun accountSecret(): String =
        config.accountSecret ?: error("no account secret (scan a relay QR, or set MobileConfig.accountSecret)")
}
