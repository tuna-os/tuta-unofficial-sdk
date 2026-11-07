// The Kotlin layer and the generated bindings of :tuta-sdk-android, compiled
// for the host JVM and tested against a host-built libtuta_ffi through JNA.
// Nothing here is published.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

val repoRoot: File = rootDir.parentFile
val hostLibraryDir: File = repoRoot.resolve("target/release")
val hostLibrary: File = hostLibraryDir.resolve(System.mapLibraryName("tuta_ffi"))

/** `cargo build` of the host library; cargo decides what is stale. */
val cargoBuildHost = tasks.register<Exec>("cargoBuildHost") {
    description = "Builds libtuta_ffi for the host"
    workingDir = repoRoot
    commandLine("cargo", "build", "--locked", "--release", "-p", "tuta-ffi")
    outputs.upToDateWhen { false }
}

/** The uniffi Kotlin bindings, generated from the host library. */
abstract class UniffiBindings : Exec() {
    @get:InputFile
    abstract val library: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty
}

val uniffiBindings = tasks.register<UniffiBindings>("uniffiBindings") {
    description = "Generates the Kotlin bindings of libtuta_ffi"
    dependsOn(cargoBuildHost)
    library.set(hostLibrary)
    outputDir.set(layout.buildDirectory.dir("generated/uniffi"))
    workingDir = repoRoot
    executable = "cargo"
    argumentProviders.add(
        CommandLineArgumentProvider {
            listOf(
                "run", "--locked", "--release", "--quiet", "-p", "tuta-ffi-bindgen", "--",
                "generate", "--library", library.get().asFile.path, "--crate", "tuta_ffi",
                "--language", "kotlin", "--no-format", "--out-dir", outputDir.get().asFile.path,
            )
        },
    )
}

kotlin {
    jvmToolchain(21)
    sourceSets.named("main") {
        kotlin.srcDir(rootDir.resolve("tuta-sdk-android/src/main/kotlin"))
        kotlin.srcDir(uniffiBindings.flatMap { it.outputDir })
    }
}

dependencies {
    implementation(libs.jna)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}

tasks.test {
    dependsOn(cargoBuildHost)
    useJUnit()
    // JNA loads libtuta_ffi from here; a rebuilt library reruns the tests.
    systemProperty("jna.library.path", hostLibraryDir.path)
    inputs.file(hostLibrary).withPropertyName("hostLibrary").withPathSensitivity(PathSensitivity.NONE)
    // The live test reads TUTA_LIVE* from the environment the test JVM
    // inherits; they are never written to the build's configuration.
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}
