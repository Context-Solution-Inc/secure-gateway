package com.contextsolutions.securegateway.core.transport;

import com.contextsolutions.securegateway.core.Role;
import com.contextsolutions.securegateway.core.auth.AuthClient;
import com.contextsolutions.securegateway.core.auth.TokenStore;

/**
 * Everything {@link ConnectionManager} needs for one paired session: the relay URL, this
 * device's role and X25519 private key, the peer's public key, and the token state. The
 * {@link TokenStore} must already hold a freshly issued connection token; {@code auth} (if
 * present) is used to refresh it before expiry.
 */
public final class Credentials {

    public final String wsUrl;
    public final Role role;
    public final byte[] myPrivateKey;
    public final byte[] peerPublicKey;
    public final TokenStore tokens;
    public final AuthClient auth; // nullable: no refresh if absent

    public Credentials(String wsUrl, Role role, byte[] myPrivateKey, byte[] peerPublicKey,
                       TokenStore tokens, AuthClient auth) {
        // Enforce wss:// (except loopback/RFC1918 for LAN dev) before the relay dial, so a
        // malicious QR cannot downgrade the connection JWT (Bearer header) to cleartext (SG-14).
        EndpointValidator.requireSecureRelay(wsUrl);
        this.wsUrl = wsUrl;
        this.role = role;
        this.myPrivateKey = myPrivateKey.clone();
        this.peerPublicKey = peerPublicKey.clone();
        this.tokens = tokens;
        this.auth = auth;
    }
}
