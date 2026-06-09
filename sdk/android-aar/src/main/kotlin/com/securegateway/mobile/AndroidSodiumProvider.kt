package com.securegateway.mobile

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.securegateway.core.SodiumProvider

/**
 * The Android [SodiumProvider]: binds [com.securegateway.core.Crypto] to the native arm64
 * libsodium bundled by lazysodium-android. Discovered via `META-INF/services` (this module
 * is the only one on the device classpath, so it's the sole provider). The JVM modules
 * register a `LazySodiumJava`-backed provider instead.
 */
class AndroidSodiumProvider : SodiumProvider {
    override fun get(): LazySodium = LazySodiumAndroid(SodiumAndroid())
}
