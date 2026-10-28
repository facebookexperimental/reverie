#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! The loader must leave no vDSO entry point running the kernel's code
//! outside the router. `__vdso_clock_getres`, which it used to leave native,
//! must reach the plugin as a syscall, and `__vdso_sgx_enter_enclave`, which
//! has no syscall equivalent, must return -ENOSYS.

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

#[test]
fn every_vdso_entry_point_is_routed_or_stubbed() {
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vdso_fail_closed");
    let out = tempfile::tempdir().unwrap();
    let compiler = cc::Build::new()
        .cargo_metadata(false)
        .opt_level(1)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler();
    checked(
        compiler
            .to_command()
            .arg(fixtures.join("client.c"))
            .args(["-ldl", "-o"])
            .arg(out.path().join("client"))
            .arg("-UNDEBUG"),
    );
    checked(
        compiler
            .to_command()
            .args(["-fPIC", "-shared", "-D__NX_INTERCEPT_RDTSC", "-I"])
            .arg(source.join("includes/plugins"))
            .arg(fixtures.join("plugin.c"))
            .arg(source.join("plugin_api/recursion_protector.c"))
            .arg(loader.parent().unwrap().join("plugin_api/libplugin_api.a"))
            .args(["-Wl,-z,now", "-o"])
            .arg(out.path().join("plugin.so"))
            .args(["-UNDEBUG", "-Wl,-Bsymbolic-functions"]),
    );

    let output = Command::new("timeout")
        .args(["--kill-after=2s", "20s"])
        .arg(loader)
        .arg(out.path().join("plugin.so"))
        .arg("--")
        .arg(out.path().join("client"))
        .output()
        .unwrap();
    eprintln!("vDSO fail-closed under SaBRe: {output:?}");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("VDSO_FAIL_CLOSED_OK ") || stdout == "VDSO_ABSENT\n",
        "{stdout}"
    );
}
