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
     * Restore a prior pairing so {@link DesktopClient#connect()} can run WITHOUT re-pairing
     * (no fresh {@link DesktopClient#generatePairingQr()}/{@link DesktopClient#awaitPairing}).
     * The QR's pairing token is single-use, so a reconnect (desktop restart) must reuse the
     * {@code deviceId}/{@code pairId}/{@code mobilePublicKeyB64} learned at first pairing instead
     * of minting a new token (which rotates the QR and forces the phone to re-scan). Leave null
     * for a first-time pairing. Set all of {@code deviceId}, {@code pairId} and
     * {@code mobilePublicKeyB64} together — {@link DesktopClient#isPaired()} gates on the latter two.
     * Mirrors {@code MobileConfig.pairId}/{@code MobileConfig.desktopPublicKeyB64}.
     */
    public String pairId;

    /** Base64-std of the mobile's raw 32-byte X25519 public key, learned at first pairing. See {@link #pairId}. */
    public String mobilePublicKeyB64;

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
