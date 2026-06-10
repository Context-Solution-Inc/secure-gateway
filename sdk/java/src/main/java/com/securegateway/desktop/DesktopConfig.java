package com.securegateway.desktop;

import com.securegateway.core.keystore.FileKeyStore;
import com.securegateway.core.keystore.KeyStore;
import java.nio.file.Path;

/**
 * Configuration for {@link DesktopClient}. The host app supplies the auth/relay endpoints,
 * the account credential and license key (PRD §6.2 activation), and where the X25519
 * identity key is stored. {@code deviceId} may be null to auto-register on first pairing.
 */
public final class DesktopConfig {

    public String authUrl;
    public String relayUrl;
    public String accountSecret;
    public String licenseId;
    public String deviceId;        // nullable: auto-register if absent
    public KeyStore keyStore;

    /**
     * Optional diagnostics sink for pairing/connect/wss progress + errors (mirrors
     * {@code MobileConfig.logger}). The host wires this to its log; defaults to a no-op so
     * normal runs and the e2e tests stay quiet.
     */
    public java.util.function.Consumer<String> logger = s -> { };

    public DesktopConfig() {
    }

    /** Convenience: file-backed keystore at the given path. */
    public DesktopConfig keyStoreFile(Path path) {
        this.keyStore = new FileKeyStore(path);
        return this;
    }
}
