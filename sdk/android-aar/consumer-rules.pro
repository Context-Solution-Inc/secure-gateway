# Crypto's ServiceLoader.load(SodiumProvider) must survive R8 in the consuming app: keep
# the SPI interface, the registered impl, and the META-INF/services file that names it.
# Without this a release (minified) build resolves no provider and Crypto throws at init.
-keep class com.securegateway.core.SodiumProvider { *; }
-keep class * implements com.securegateway.core.SodiumProvider { *; }
-keepclassmembers class * implements com.securegateway.core.SodiumProvider {
    <init>();
}
