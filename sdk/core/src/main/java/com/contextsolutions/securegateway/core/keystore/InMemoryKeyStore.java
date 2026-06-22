package com.contextsolutions.securegateway.core.keystore;

import com.contextsolutions.securegateway.core.Crypto;
import com.contextsolutions.securegateway.core.KeyPair;

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
