use std::env;

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo sets target architecture");
    assert_eq!(
        target_arch, "x86_64",
        "the vendored SaBRe plugin API currently supports only x86_64"
    );

    println!("cargo:rerun-if-changed=src/ffi/recursion_protector.c");
    println!("cargo:rerun-if-changed=src/ffi/vfork_syscall.S");

    cc::Build::new()
        .file("src/ffi/recursion_protector.c")
        .file("src/ffi/vfork_syscall.S")
        .compile("reverie_sabre_plugin_api");
}
