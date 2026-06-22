package com.contextsolutions.securegateway.core.keystore;

import com.contextsolutions.securegateway.core.Crypto;
import com.contextsolutions.securegateway.core.Hex;
import com.contextsolutions.securegateway.core.KeyPair;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * Desktop {@link KeyStore} that persists the X25519 identity private key to an owner-only
 * file (chmod 0600 where the filesystem supports POSIX permissions). The public key is
 * re-derived on load. For production, wrap this with an OS keystore where available; this
 * file backing is the portable default across Linux/Windows/macOS.
 */
public final class FileKeyStore implements KeyStore {

    private final Path file;
    private KeyPair identity;

    public FileKeyStore(Path file) {
        this.file = file;
    }

    @Override
    public synchronized KeyPair loadOrCreateIdentity() {
        if (identity != null) {
            return identity;
        }
        try {
            if (Files.exists(file)) {
                byte[] priv = Hex.decode(Files.readString(file).trim());
                identity = new KeyPair(priv, Crypto.publicFromPrivate(priv));
            } else {
                identity = Crypto.generateKeyPair();
                write(identity.privateKey());
            }
            return identity;
        } catch (IOException e) {
            throw new IllegalStateException("keystore: " + e.getMessage(), e);
        }
    }

    private void write(byte[] priv) throws IOException {
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        Files.writeString(file, Hex.encode(priv));
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(file, perms);
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX filesystem (e.g. Windows); rely on default ACLs
        }
    }
}
