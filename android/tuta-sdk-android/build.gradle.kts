// org.tunaos.tuta:tuta-sdk-android: libtuta_ffi for arm64-v8a and x86_64
// (cargo-ndk), its uniffi Kotlin bindings, and the typed Kotlin layer in
// src/main/kotlin. `./gradlew :tuta-sdk-android:dist` writes the release
// assets to build/dist: the AAR and a zipped Maven repository.
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

val repoRoot: File = rootDir.parentFile

// The one version: the Cargo workspace's.
val sdkVersion: String = Regex("""(?m)^version = "([^"]+)"""")
    .find(repoRoot.resolve("Cargo.toml").readText())
    ?.groupValues?.get(1)
    ?: error("no version in Cargo.toml")

group = "org.tunaos.tuta"
version = sdkVersion

/** The ABIs shipped, as Android names them; cargo-ndk maps them to Rust targets. */
val abis = listOf("arm64-v8a", "x86_64")
val minSdkVersion = 24

/** libtuta_ffi for every ABI, laid out as jniLibs; cargo decides what is stale. */
abstract class CargoNdk : Exec() {
    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty
}

val cargoNdk = tasks.register<CargoNdk>("cargoNdk") {
    description = "Builds libtuta_ffi for ${abis.joinToString()} with cargo-ndk"
    workingDir = repoRoot
    executable = "cargo"
    outputDir.set(layout.buildDirectory.dir("generated/jniLibs"))
    argumentProviders.add(
        CommandLineArgumentProvider {
            listOf("ndk") + abis.flatMap { listOf("-t", it) } + listOf(
                "-P", minSdkVersion.toString(), "-o", outputDir.get().asFile.path,
                "build", "--locked", "--profile", "android", "-p", "tuta-ffi",
            )
        },
    )
    outputs.upToDateWhen { false }
}

/** The uniffi Kotlin bindings, generated from the arm64 library. */
abstract class UniffiBindings : Exec() {
    @get:InputDirectory
    abstract val libraries: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty
}

val uniffiBindings = tasks.register<UniffiBindings>("uniffiBindings") {
    description = "Generates the Kotlin bindings of libtuta_ffi"
    libraries.set(cargoNdk.flatMap { it.outputDir })
    outputDir.set(layout.buildDirectory.dir("generated/uniffi"))
    workingDir = repoRoot
    executable = "cargo"
    argumentProviders.add(
        CommandLineArgumentProvider {
            val library = libraries.get().asFile.resolve("arm64-v8a/libtuta_ffi.so")
            listOf(
                "run", "--locked", "--release", "--quiet", "-p", "tuta-ffi-bindgen", "--",
                "generate", "--library", library.path, "--crate", "tuta_ffi",
                "--language", "kotlin", "--no-format", "--out-dir", outputDir.get().asFile.path,
            )
        },
    )
}

android {
    namespace = "org.tunaos.tuta"
    compileSdk = 37
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = minSdkVersion
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += abis
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoNdk, CargoNdk::outputDir)
        variant.sources.kotlin?.addGeneratedSourceDirectory(uniffiBindings, UniffiBindings::outputDir)
    }
}

dependencies {
    // JNA's Android build: its own libjnidispatch for every ABI.
    implementation(libs.jna) {
        artifact { type = "aar" }
    }
    api(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "org.tunaos.tuta"
            artifactId = "tuta-sdk-android"
            version = sdkVersion
            afterEvaluate {
                from(components["release"])
            }
            pom {
                name.set("tuta-sdk-android")
                description.set(
                    "Unofficial Tuta (Tutanota) SDK for Android: tuta-unofficial-sdk through uniffi, with a typed Kotlin API",
                )
                url.set("https://github.com/tuna-os/tuta-unofficial-sdk")
                licenses {
                    license {
                        name.set("GPL-3.0-or-later")
                        url.set("https://www.gnu.org/licenses/gpl-3.0.html")
                    }
                }
                scm {
                    url.set("https://github.com/tuna-os/tuta-unofficial-sdk")
                }
            }
        }
    }
    repositories {
        maven {
            name = "dist"
            url = uri(layout.buildDirectory.dir("maven"))
        }
    }
}

val mavenDir = layout.buildDirectory.dir("maven")

tasks.matching { it.name == "publishReleasePublicationToDistRepository" }.configureEach {
    // Only this version goes in the zip.
    doFirst { mavenDir.get().asFile.deleteRecursively() }
}

val mavenZip = tasks.register<Zip>("mavenZip") {
    description = "Zips the Maven repository holding this release"
    dependsOn("publishReleasePublicationToDistRepository")
    from(mavenDir)
    archiveFileName.set("tuta-sdk-android-$sdkVersion-maven.zip")
    destinationDirectory.set(layout.buildDirectory.dir("dist"))
}

tasks.register<Copy>("dist") {
    description = "Writes the release assets (AAR, zipped Maven repository) to build/dist"
    dependsOn(mavenZip)
    from(tasks.named("bundleReleaseAar"))
    rename { "tuta-sdk-android-$sdkVersion.aar" }
    into(layout.buildDirectory.dir("dist"))
}
