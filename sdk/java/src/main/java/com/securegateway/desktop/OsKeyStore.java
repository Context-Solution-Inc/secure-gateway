package com.securegateway.desktop;

import com.securegateway.core.KeyPair;
import com.securegateway.core.keystore.FileKeyStore;
import com.securegateway.core.keystore.KeyStore;
import java.nio.file.Path;

/**
 * Desktop OS-keystore seam (PRD §8.3: "OS keystore or encrypted file"). This default
 * delegates to a {@link FileKeyStore} (owner-only file), which is portable across
 * Linux/Windows/macOS. Where stronger protection is required, replace the delegate with a
 * platform secret store (macOS Keychain, Windows DPAPI/Credential Manager, GNOME Keyring)
 * that wraps the X25519 private key.
 */
public final class OsKeyStore implements KeyStore {

    private final KeyStore delegate;

    public OsKeyStore(Path file) {
        this.delegate = new FileKeyStore(file);
    }

    public OsKeyStore(KeyStore delegate) {
        this.delegate = delegate;
    }

    @Override
    public KeyPair loadOrCreateIdentity() {
        return delegate.loadOrCreateIdentity();
    }
}
