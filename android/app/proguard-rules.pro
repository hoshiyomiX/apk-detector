# Add project-specific ProGuard rules here.
# By default, do not minify our app (see app/build.gradle.kts isMinifyEnabled=false).
# If you enable R8 in the future, keep the JNI native-method names intact:

-keep class id.zai.apkdetector.NativeBridge { *; }
-keepclassmembers class id.zai.apkdetector.** { *; }
