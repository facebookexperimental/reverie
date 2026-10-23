#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;

#[test]
fn actual_loader_bootstrap_protocol_is_supervised_and_once_only() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::env::temp_dir().join(format!("reverie-loader-bootstrap-{}", std::process::id()));
    std::fs::create_dir(&out).unwrap();
    let binary = out.join("protocol");
    let compiler = cc::Build::new()
        .cargo_metadata(false)
        .opt_level(2)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler();
    let output = compiler
        .to_command()
        // Appended after cc's inherited CFLAGS: native assertions are the
        // control's oracle and must remain enabled even with -DNDEBUG.
        .args([
            "-std=gnu99",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-UNDEBUG",
            "-pthread",
        ])
        .arg("-I")
        .arg(source.join("vendor/sabre/includes/loader"))
        .arg(source.join("vendor/sabre/loader/bootstrap.c"))
        .arg(source.join("tests/loader_bootstrap.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let output = Command::new(&binary).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    use reverie_sabre::bootstrap;
    let contract = format!(
        "protocol={} version={} ops={},{},{} max={}\n",
        bootstrap::PRCTL_OPTION,
        bootstrap::VERSION,
        bootstrap::IMAGE,
        bootstrap::GETRANDOM,
        bootstrap::TAKE_STATE,
        bootstrap::MAX_STATE_BYTES,
    );
    assert!(output.stdout.starts_with(contract.as_bytes()), "{output:?}");
    std::fs::remove_file(&binary).unwrap();
    std::fs::remove_dir(&out).unwrap();
}
