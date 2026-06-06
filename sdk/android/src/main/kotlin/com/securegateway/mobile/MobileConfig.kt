package com.securegateway.mobile

import com.securegateway.core.keystore.InMemoryKeyStore
import com.securegateway.core.keystore.KeyStore
import com.securegateway.core.push.NoopPushWaker
import com.securegateway.core.push.PushWaker

/**
 * Configuration for [MobileClient]. The host app supplies the auth endpoint and account
 * credential (the signed-in app session), plus the Android Keystore and FCM seams. On the
 * JVM build these default to in-memory/no-op stubs; a real Android build injects
 * [AndroidKeystoreKeyStore] and an FCM-backed [PushWaker]. The relay endpoint normally
 * comes from the scanned QR, so [relayUrl] may stay null.
 */
class MobileConfig {
    lateinit var authUrl: String
    lateinit var accountSecret: String
    var relayUrl: String? = null
    var deviceId: String? = null
    var keyStore: KeyStore = InMemoryKeyStore()
    var pushWaker: PushWaker = NoopPushWaker()
}
