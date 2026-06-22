package com.contextsolutions.securegateway.core;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;

/**
 * Desktop/JVM {@link SodiumProvider} for {@code :core}'s own unit tests (which exercise
 * {@link Crypto} directly). Registered via {@code META-INF/services} in test resources
 * only — never in {@code :core} main, so the Android AAR's classpath never sees it.
 */
public final class JvmSodiumProvider implements SodiumProvider {

    @Override
    public LazySodium get() {
        return new LazySodiumJava(new SodiumJava());
    }
}
