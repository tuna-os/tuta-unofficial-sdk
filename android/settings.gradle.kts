// The Android packaging of tuta-unofficial-sdk: the uniffi bindings of
// crates/tuta-ffi plus a typed Kotlin layer, as org.tunaos.tuta:tuta-sdk-android.
//
//   :tuta-sdk-android  the AAR (needs the Android SDK and NDK, cargo-ndk)
//   :tuta-sdk-jvm      the same Kotlin sources tested on the host JVM against
//                      a host-built libtuta_ffi (needs only a JDK and cargo)
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "tuta-sdk"

include(":tuta-sdk-jvm")

// The AAR needs an Android SDK; without one (a JDK-only host running the JVM
// tests) the module is left out instead of failing the whole build.
val localSdkDir = file("local.properties").takeIf { it.isFile }
    ?.readLines()
    ?.firstOrNull { it.startsWith("sdk.dir=") }
    ?.substringAfter("=")
val androidSdk = listOfNotNull(System.getenv("ANDROID_HOME"), System.getenv("ANDROID_SDK_ROOT"), localSdkDir)
    .any { file(it).isDirectory }
if (androidSdk) {
    include(":tuta-sdk-android")
} else {
    logger.lifecycle("No Android SDK (ANDROID_HOME, ANDROID_SDK_ROOT or local.properties): skipping :tuta-sdk-android")
}
