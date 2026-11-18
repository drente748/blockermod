import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
}

// Signing secrets live in a git-ignored keystore.properties at the project root. When it is absent
// (CI, fresh clone) release builds stay unsigned instead of failing, and debug builds are unaffected.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) FileInputStream(keystorePropertiesFile).use { load(it) }
}
val hasReleaseKeystore = keystorePropertiesFile.exists() &&
    keystoreProperties.getProperty("storeFile")?.let { rootProject.file(it).exists() } == true

android {
    namespace = "com.blockermod"
    compileSdk = 37
    compileSdkMinor = 0

    defaultConfig {
        applicationId = "com.blockermod"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        // First stable release (production/sale-ready). Bump versionCode for every subsequent APK.
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    androidResources {
        // The packed blocklist is mapped into the memory, so it must stay uncompressed.
        noCompress += "bin"
    }

    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
                // Decision (final): APK Signature Scheme v2 only. minSdk is 26 (Android 8.0),
                // where v2 is fully supported; AGP omits v1 for such apps and v1 adds no value here.
                isV2SigningEnabled = true
            }
        }
    }

    buildTypes {
        getByName("release") {
            if (hasReleaseKeystore) signingConfig = signingConfigs.getByName("release")
            // Decision (final): no R8 minification. The APK is already ~5.8 MB, the code uses no
            // reflection and no DI, and a shrink cannot be runtime-verified without a device;
            // correctness is preferred over a marginal size gain. This decision is not reopened.
            isMinifyEnabled = false
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":core"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(kotlin("test-junit"))

    androidTestImplementation(kotlin("test-junit"))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
