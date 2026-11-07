//! Export only this crate's own symbols from `libtuta_ffi`.
//!
//! A cdylib exports every `#[no_mangle]` symbol of every crate it links, and
//! the pinned Tuta SDK has its own uniffi bindings: some 700 exported
//! functions and metadata statics that nothing here calls, but that keep
//! much of the SDK alive past the linker's section GC. `--exclude-libs ALL`
//! makes the symbols of the static archives (the dependencies' rlibs) local,
//! so the GC drops what this crate does not reach. This crate's own uniffi
//! scaffolding and metadata are in its own objects, not an archive, and stay
//! exported; uniffi-bindgen reads its metadata as before. ELF linkers only
//! (Android, Linux).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "android" || os == "linux" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-libs,ALL");
    }
}
