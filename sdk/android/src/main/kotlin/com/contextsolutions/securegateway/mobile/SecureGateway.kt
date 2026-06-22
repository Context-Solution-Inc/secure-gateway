package com.contextsolutions.securegateway.mobile

/**
 * Entry point for the mobile SDK — the single seam the host app toggles behind its relay
 * feature flag (PRD §8.1/§8.4). When off, the app keeps its legacy local QR-sync; when on,
 * it builds a [MobileClient] here. The QR is versioned, so a legacy QR (no `v`) falls back
 * to the old pairing path in the host app.
 */
object SecureGateway {

    fun mobile(config: MobileConfig): MobileClient = MobileClient(config)

    /** Kotlin DSL convenience: `SecureGateway.mobile { authUrl = ...; accountSecret = ... }`. */
    fun mobile(block: MobileConfig.() -> Unit): MobileClient =
        MobileClient(MobileConfig().apply(block))
}
