#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;

#[test]
fn actual_loader_maps_restore_original_protections() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::env::temp_dir().join(format!("reverie-map-protections-{}", std::process::id()));
    std::fs::create_dir(&out).unwrap();
    let binary = out.join("map-protections");
    let compiler = cc::Build::new()
        .cargo_metadata(false)
        .opt_level(2)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler();
    let output = compiler
        .to_command()
        // Compile the real parser and static rewrite helper; discarded loader
        // functions need not link the rest of the SaBRe runtime. Keep the C
        // assertions active even when the caller supplies -DNDEBUG.
        .args([
            "-std=gnu99",
            "-UNDEBUG",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
        ])
        .arg("-I")
        .arg(source.join("vendor/sabre/includes"))
        .arg("-I")
        .arg(source.join("vendor/sabre/includes/loader"))
        .arg("-I")
        .arg(source.join("vendor/libelf"))
        .arg(source.join("tests/loader_map_protections.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    for case in [
        "private-rx",
        "private-r",
        "private-rw",
        "shared-rx",
        "shared-r",
        "shared-rw",
        "unmapped",
    ] {
        let output = Command::new(&binary).arg(case).arg(&out).output().unwrap();
        assert!(output.status.success(), "case={case}: {output:?}");
        assert!(
            output.stdout.ends_with(format!("PASS {case}\n").as_bytes()),
            "case={case}: {output:?}"
        );
    }
    std::fs::remove_file(&binary).unwrap();
    std::fs::remove_dir(&out).unwrap();
}
