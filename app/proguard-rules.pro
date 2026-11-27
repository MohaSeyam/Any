# Preserve native JNI method signatures (SQLCipher)
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
-keep,includedescriptorclasses class net.zetetic.database.** { *; }
-keep interface net.zetetic.database.** { *; }

# BouncyCastle cryptographic primitives
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ZXing QR generator & scanner
-keep class com.google.zxing.** { *; }
-keep class com.journeyapps.barcodescanner.** { *; }
-dontwarn com.google.zxing.**

# Strip verbose/debug logs in release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
