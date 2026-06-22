package com.contextsolutions.securegateway.desktop;

import com.contextsolutions.securegateway.core.keystore.InMemoryKeyStore;

/**
 * Entry point for the desktop SDK — the single seam the host app toggles behind its relay
 * feature flag (PRD §8.3/§8.4). When the flag is off the app keeps its legacy local-sync
 * path; when on, it calls {@link #desktop(DesktopConfig)} and uses the returned client.
 * The QR payload is versioned ({@code v:1}), so a legacy QR (no {@code v}) routes to the
 * old behavior.
 */
public final class SecureGateway {

    private SecureGateway() {
    }

    public static DesktopClient desktop(DesktopConfig config) {
        if (config.keyStore == null) {
            config.keyStore = new InMemoryKeyStore();
        }
        return new DesktopClient(config);
    }
}
