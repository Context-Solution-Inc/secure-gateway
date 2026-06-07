package com.securegateway.core.keystore;

import com.securegateway.core.Crypto;
import com.securegateway.core.KeyPair;

/** A non-persistent {@link KeyStore} for tests and ephemeral sessions. */
public final class InMemoryKeyStore implements KeyStore {

    private KeyPair identity;

    public InMemoryKeyStore() {
    }

    /** Seed with a fixed keypair (e.g. interop vectors). */
    public InMemoryKeyStore(KeyPair identity) {
        this.identity = identity;
    }

    @Override
    public synchronized KeyPair loadOrCreateIdentity() {
        if (identity == null) {
            identity = Crypto.generateKeyPair();
        }
        return identity;
    }
}
