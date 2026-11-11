plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.ghostlock.honorfne"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.ghostlock.honorfne"
        minSdk = 24
        targetSdk = 34
        versionCode = 2
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
        debug {
            isMinifyEnabled = false
        }
    }

    // 不再需要 AIDL：改用 Shizuku.newProcess 直接在 shell 权限下执行命令。
    buildFeatures {
        viewBinding = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Prebuilt binaries (kernelsu.ko, ksud, ... ) must NOT be compressed or
    // aapt would try to align/strip them. Keep assets uncompressed.
    androidResources {
        noCompress += listOf("ko", "zip", "apk", "bin")
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    // Shizuku API: lets this app obtain `shell` (uid 2000) privilege, which is
    // exactly what `adb shell` provides. The exploit self-escalates to root.
    // provider is REQUIRED for Shizuku (not Sui): it delivers the binder to us.
    implementation("rikka.shizuku:api:11.0.2")
    implementation("rikka.shizuku:provider:11.0.2")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
