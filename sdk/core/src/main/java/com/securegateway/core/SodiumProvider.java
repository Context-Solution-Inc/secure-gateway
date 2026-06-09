package com.securegateway.core;

import com.goterl.lazysodium.LazySodium;

/**
 * Platform seam for the native libsodium binding. {@link Crypto} types against the
 * base {@link LazySodium} (it only ever casts to the {@code DiffieHellman.Native} /
 * {@code AEAD.Native} interfaces, which both the desktop and Android flavors
 * implement); this provider supplies the concrete instance.
 *
 * <p>Resolved at class-init via {@link java.util.ServiceLoader}, so each platform's
 * runtime classpath registers exactly one provider in
 * {@code META-INF/services/com.securegateway.core.SodiumProvider}:
 * <ul>
 *   <li>JVM (desktop {@code :java}, {@code :core}/{@code :android} unit tests, and the
 *       cross-platform {@code :java:e2eTest}) &rarr; {@code LazySodiumJava(SodiumJava())};
 *   <li>Android AAR &rarr; {@code LazySodiumAndroid(SodiumAndroid())}.
 * </ul>
 *
 * <p>The provider impls deliberately live in the leaf modules, never in {@code :core}
 * main: a JVM impl shipped in {@code :core} would reference {@code LazySodiumJava} and
 * crash ServiceLoader on Android (and the converse for an Android impl on the JVM).
 */
public interface SodiumProvider {

    /** The shared, thread-safe libsodium binding for this platform. */
    LazySodium get();
}
