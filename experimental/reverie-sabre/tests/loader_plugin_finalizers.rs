#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;

#[test]
fn plugin_finalizers_preserve_order_domain_and_other_maps() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out =
        std::env::temp_dir().join(format!("reverie-plugin-finalizers-{}", std::process::id()));
    std::fs::create_dir(&out).unwrap();
    let binary = out.join("plugin-finalizers");
    let output = cc::Build::new()
        .cargo_metadata(false)
        .opt_level(2)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler()
        .to_command()
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
        .arg(source.join("tests/loader_plugin_finalizers.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    for case in [
        "array-fini",
        "prior-plugin",
        "array-only",
        "fini-only",
        "empty",
        "zero-array",
    ] {
        let output = Command::new(&binary).arg(case).output().unwrap();
        assert!(output.status.success(), "case={case}: {output:?}");
        assert_eq!(output.stdout, format!("PASS {case}\n").as_bytes());
    }
    for (case, reason) in [
        ("bad-size", "invalid plugin finalizer array"),
        ("missing-size", "invalid plugin finalizer array"),
        ("missing-map", "missing plugin finalizer map"),
        ("duplicate-map", "ambiguous plugin finalizer map"),
    ] {
        let output = Command::new(&binary).arg(case).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "case={case}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains(reason));
    }
    std::fs::remove_file(&binary).unwrap();
    std::fs::remove_dir(&out).unwrap();
}
