#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Under post-arm routing the loader calls a plugin's optional
//! `reverie_sabre_routed_syscall_v1` with the route each syscall took: 0 for
//! a rewritten site's jump trampoline, 1 for the SIGILL handler of a UD0
//! marker, and the call's six arguments and frame pointer after it. Without
//! post-arm routing, or without the symbol, the plugin's
//! `sbr_init` handler is called as before.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

fn compiler() -> cc::Tool {
    cc::Build::new()
        .cargo_metadata(false)
        .opt_level(1)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler()
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn build_plugin(out: &Path, name: &str, define: Option<&str>) -> PathBuf {
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let plugin = out.join(name);
    let mut command = compiler().to_command();
    command
        .args(["-fPIC", "-shared", "-D__NX_INTERCEPT_RDTSC", "-I"])
        .arg(source.join("includes/plugins"));
    if let Some(define) = define {
        command.arg(define);
    }
    checked(
        command
            .arg(fixtures().join("routed_syscall/plugin.c"))
            .arg(source.join("plugin_api/recursion_protector.c"))
            .arg(loader.parent().unwrap().join("plugin_api/libplugin_api.a"))
            .args(["-Wl,-z,now", "-o"])
            .arg(&plugin)
            .args(["-UNDEBUG", "-Wl,-Bsymbolic-functions"]),
    );
    plugin
}

#[test]
fn post_arm_routing_passes_each_syscalls_route_to_a_plugin_that_takes_it() {
    let out = tempfile::tempdir().unwrap();
    let client = out.path().join("client");
    checked(
        compiler()
            .to_command()
            .arg(fixtures().join("routed_syscall/client.c"))
            .arg(fixtures().join("routed_syscall/probe.S"))
            .arg("-o")
            .arg(&client),
    );
    let run = |plugin: &Path| -> String {
        let output = checked(
            Command::new("timeout")
                .args(["--kill-after=2s", "20s"])
                .arg(reverie_sabre::bundled_sabre_path())
                .arg(plugin)
                .arg("--")
                .arg(&client),
        );
        String::from_utf8(output.stdout).unwrap()
    };

    assert_eq!(
        String::from_utf8(checked(&mut Command::new(&client)).stdout).unwrap(),
        "jump=NATIVE marker=NATIVE \n"
    );
    // Armed, with the routed handler: each call carries its route, and all
    // six arguments and the frame pointer arrive in place (otherwise +100).
    let routed = build_plugin(out.path(), "routed.so", None);
    assert_eq!(run(&routed), "jump=0 marker=1 \n");
    // Not armed: the sbr_init handler, as before; the routed handler is unused.
    let unarmed = build_plugin(out.path(), "unarmed.so", Some("-DUNARMED"));
    assert_eq!(run(&unarmed), "jump=7 marker=7 \n");
    // Armed, without the routed handler: the sbr_init handler.
    let plain = build_plugin(out.path(), "plain.so", Some("-DOMIT_ROUTED"));
    assert_eq!(run(&plain), "jump=7 marker=7 \n");
}
