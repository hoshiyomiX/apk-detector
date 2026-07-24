# =========================================================================
# APK Detector — R8 / ProGuard keep rules
# =========================================================================
# Build type: release (isMinifyEnabled = true, isShrinkResources = true)
# R8 full mode is the AGP 8.x default — renaming + dead-code + resource
# stripping are all active. The rules below protect everything R8 must NOT
# touch: JNI surface, Room-generated DAOs, reflection entry points.
# =========================================================================

# -------------------------------------------------------------------------
# 1. JNI bridge — NativeBridge.kt
# -------------------------------------------------------------------------
# The Rust side calls JNI methods by their exact Java names (scanApk,
# diffApks, listSignatures, engineVersion). If R8 renames them, the
# JNIEnv::GetStaticMethodID call in jni-bridge/src/api.rs returns null and
# the app crashes with NoSuchMethodError at first scan.
-keep class id.zai.apkdetector.data.NativeBridge { *; }
-keepclassmembers class id.zai.apkdetector.data.NativeBridge {
    public static ** scanApk(java.lang.String);
    public static ** diffApks(java.lang.String, java.lang.String);
    public static ** listSignatures();
    public static ** engineVersion();
}

# -------------------------------------------------------------------------
# 2. Room — KSP-generated DAO implementations
# -------------------------------------------------------------------------
# Room's KSP processor generates *Dao_Impl classes referenced at runtime
# via reflection from RoomDatabase.Builder. R8 would otherwise strip them
# as "unused" since no source-level reference exists.
-keep class id.zai.apkdetector.data.** { *; }
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }
-keepclassmembers class * {
    @androidx.room.Query <methods>;
    @androidx.room.Insert <methods>;
    @androidx.room.Delete <methods>;
    @androidx.room.Update <methods>;
}

# -------------------------------------------------------------------------
# 3. Kotlin metadata — preserve reflection entry points
# -------------------------------------------------------------------------
-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
-keepattributes RuntimeInvisibleAnnotations, RuntimeInvisibleParameterAnnotations

# Keep Kotlin Companion objects (R8 sometimes strips the Companion class
# while keeping the enclosing class — JNI reflection from Kotlin code can
# then fail).
-keepclassmembers class **$Companion { *; }

# -------------------------------------------------------------------------
# 4. Compose runtime — safety net
# -------------------------------------------------------------------------
# Compose ships its own consumer-rules, but material-icons-extended pulls
# in thousands of icon classes; R8 strips unused ones automatically. Keep
# the @Composable invoker infrastructure just in case.
-dontwarn androidx.compose.**
-keep class androidx.compose.runtime.** { *; }

# -------------------------------------------------------------------------
# 5. Coroutines — internal state machine
# -------------------------------------------------------------------------
# Kotlin coroutines use reflection to resume continuations. R8 strips
# unreferenced StateMachine classes if not kept.
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# -------------------------------------------------------------------------
# 6. App entry points
# -------------------------------------------------------------------------
-keep class id.zai.apkdetector.ApkDetectorApp { *; }
-keep class id.zai.apkdetector.MainActivity { *; }
-keep class id.zai.apkdetector.ui.** { *; }

# -------------------------------------------------------------------------
# 7. R8 optimization hints
# -------------------------------------------------------------------------
# Allow R8 to optimize third-party code aggressively, but never warn about
# missing classes from optional dependencies (e.g., Kotlin metadata).
-dontwarn org.jetbrains.annotations.**
-dontwarn javax.annotation.**

# Keep source file names + line numbers for crash stacktraces.
-keepattributes SourceFile, LineNumberTable
