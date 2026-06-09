package com.securegateway.mobile

import com.securegateway.core.keystore.InMemoryKeyStore
import com.securegateway.core.keystore.KeyStore
import com.securegateway.core.push.NoopPushWaker
import com.securegateway.core.push.PushWaker

/**
 * Configuration for [MobileClient]. The host app supplies the auth endpoint and account
 * credential (the signed-in app session), plus the Android Keystore and FCM seams. These
 * default to in-memory/no-op stubs ([InMemoryKeyStore]/[NoopPushWaker]); the host injects
 * a real implementation (e.g. an Android-Keystore-backed [KeyStore] and an FCM-backed
 * [PushWaker]). The relay endpoint normally comes from the scanned QR, so [relayUrl] may
 * stay null.
 */
class MobileConfig {
    lateinit var authUrl: String

    /**
     * The account credential. May be left null and supplied by the scanned relay
     * QR ([MobileClient.pair] reads [com.securegateway.core.auth.QrPayload.accountSecret]),
     * since the phone has no subscription of its own.
     */
    var accountSecret: String? = null
    var relayUrl: String? = null
    var deviceId: String? = null
    var keyStore: KeyStore = InMemoryKeyStore()
    var pushWaker: PushWaker = NoopPushWaker()

    /**
     * Optional diagnostics sink for pairing/connect/wss progress + errors. The host wires
     * this to its platform log (e.g. `android.util.Log`); defaults to a no-op so the JVM
     * build and e2e tests stay quiet. Kept as a plain `(String) -> Unit` so these sources
     * remain platform-agnostic (no `android.util.Log` in the shared mobile SDK).
     */
    var logger: (String) -> Unit = {}
}
