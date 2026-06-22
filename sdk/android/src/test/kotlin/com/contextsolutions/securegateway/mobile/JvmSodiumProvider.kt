package com.contextsolutions.securegateway.mobile

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.contextsolutions.securegateway.core.SodiumProvider

/**
 * Desktop/JVM [SodiumProvider] for the mobile SDK's JVM unit tests
 * (`VectorsConformanceKtTest` runs the shared [com.contextsolutions.securegateway.core.Crypto]). Registered
 * via `META-INF/services` in test resources only — the real Android binding ships in the
 * `:android-aar` module, never here.
 */
class JvmSodiumProvider : SodiumProvider {
    override fun get(): LazySodium = LazySodiumJava(SodiumJava())
}
