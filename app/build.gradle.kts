plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.blockermod"
    compileSdk = 37
    compileSdkMinor = 0

    defaultConfig {
        applicationId = "com.blockermod"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)
}
