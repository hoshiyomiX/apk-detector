plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

android {
    namespace = "id.zai.apkdetector"
    compileSdk = 34

    defaultConfig {
        applicationId = "id.zai.apkdetector"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = true }

        // ── Play Integrity API configuration ─────────────────────────────
        // The Cloud Project Number linked to this app in Google Play Console.
        // Required for the Standard Play Integrity flow (warm-up → token request).
        //
        // Set via the PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER env var (CI secrets
        // or local ~/.gradle/gradle.properties). Default 0L means "not
        // configured" — PlayIntegrityClient.requestVerdict() short-circuits
        // to NotConfigured without making any IPC call to Play services.
        //
        // To configure for local development:
        //   1. Create a Google Cloud project (https://console.cloud.google.com/).
        //   2. Link your app in Play Console → Setup → App integrity → Cloud project.
        //   3. Note the Cloud Project Number (NOT the project ID — the numeric ID).
        //   4. Add to ~/.gradle/gradle.properties:
        //        PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER=1234567890123
        //   5. Rebuild the app.
        buildConfigField(
            "long",
            "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
            "${System.getenv("PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER")?.toLongOrNull() ?: 0L}L",
        )
    }

    // ── Release signing ───────────────────────────────────────────────
    // The keystore path + credentials are read from environment variables
    // (set by CI). If any of the four env vars is missing, we fall back to
    // the debug signing config so local dev builds still work.
    //
    // CI generates a keystore via `keytool` and caches it across runs
    // (see .github/workflows/ci.yml). To use a real release keystore,
    // set these as GitHub Actions secrets:
    //   SIGNING_KEYSTORE_PATH  (path to the .jks file on the runner)
    //   SIGNING_KEYSTORE_PASS  (keystore password)
    //   SIGNING_KEY_ALIAS      (key alias)
    //   SIGNING_KEY_PASS       (key password)
    val signingKeystorePath = System.getenv("SIGNING_KEYSTORE_PATH")
    val signingKeystorePass = System.getenv("SIGNING_KEYSTORE_PASS")
    val signingKeyAlias = System.getenv("SIGNING_KEY_ALIAS")
    val signingKeyPass = System.getenv("SIGNING_KEY_PASS")
    val hasSigningConfig = !signingKeystorePath.isNullOrEmpty()
        && !signingKeystorePass.isNullOrEmpty()
        && !signingKeyAlias.isNullOrEmpty()
        && !signingKeyPass.isNullOrEmpty()

    signingConfigs {
        if (hasSigningConfig) {
            create("release") {
                storeFile = file(signingKeystorePath!!)
                storePassword = signingKeystorePass
                keyAlias = signingKeyAlias
                keyPassword = signingKeyPass
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Sign the release APK with the release keystore if env vars
            // are set; otherwise fall back to debug signing so the APK is
            // still installable (just with the debug cert).
            signingConfig = if (hasSigningConfig) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.documentfile)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.google.play.integrity)
}
