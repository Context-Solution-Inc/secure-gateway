package com.contextsolutions.securegateway.desktop;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.contextsolutions.securegateway.core.SodiumProvider;

/**
 * Desktop/JVM {@link SodiumProvider} — the production binding for the desktop SDK and the
 * one the cross-platform {@code :java:e2eTest} uses to drive both endpoints on the JVM.
 * Registered via {@code META-INF/services} in {@code :java} main resources, so it ships on
 * the desktop runtime classpath (and, transitively, the e2e classpath). The Android AAR
 * registers its own {@code LazySodiumAndroid}-backed provider instead.
 */
public final class JvmSodiumProvider implements SodiumProvider {

    @Override
    public LazySodium get() {
        return new LazySodiumJava(new SodiumJava());
    }
}
