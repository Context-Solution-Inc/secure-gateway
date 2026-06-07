package com.securegateway.core.keystore;

import com.securegateway.core.KeyPair;

/**
 * Where this device's X25519 identity private key lives (FR-2.3: private keys never leave
 * the device). Platform implementations back this with the Android Keystore, the iOS
 * Keychain/Secure Enclave, or an OS keystore / encrypted file on desktop. The SDK only
 * needs to load (or create on first use) the device keypair.
 */
public interface KeyStore {

    /** Return the device's persistent X25519 keypair, generating and storing it on first use. */
    KeyPair loadOrCreateIdentity();
}
