package com.securegateway.mobile

import com.securegateway.core.KeyPair
import com.securegateway.core.keystore.KeyStore

/**
 * STUB for the JVM build. On a real Android build this backs the device X25519 private key
 * with the Android Keystore. The Android Keystore cannot hold X25519 keys directly, so the
 * production design generates a hardware-backed AES key in the Keystore (StrongBox where
 * available) and uses it to wrap/unwrap the X25519 private key at rest (e.g. stored via
 * EncryptedSharedPreferences); the unwrapped private key lives only transiently in memory.
 *
 * Here it simply delegates to a provided fallback so the SDK compiles, unit-tests, and runs
 * the cross-platform E2E on Linux without an Android runtime.
 *
 * TODO(android): replace with the AndroidKeyStore-backed implementation when building the
 * real Android library (`com.android.library` + lazysodium-android).
 */
class AndroidKeystoreKeyStore(private val delegate: KeyStore) : KeyStore {
    override fun loadOrCreateIdentity(): KeyPair = delegate.loadOrCreateIdentity()
}
