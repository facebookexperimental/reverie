#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! A plugin that reports arming its own trap path takes every rewritten-site
//! call from post_load on, including its own calls and ARCH_SET_FS: the loader
//! must not run a syscall natively once that trap path would catch it. Without
//! the report, or with a zero report, routing stays as it was. A static client
//! cannot take post-arm routing and is refused by name.

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

#[test]
fn post_arm_routing_sends_every_call_to_the_plugin_only_when_reported() {
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/post_arm_routing");
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
            .arg("-o")
            .arg(out.path().join("client"))
            .arg("-UNDEBUG"),
    );
    checked(
        compiler
            .to_command()
            .args(["-nostdlib", "-static-pie", "-Wl,-E,--no-dynamic-linker"])
            .arg(fixtures.join("client-static.S"))
            .arg("-o")
            .arg(out.path().join("client-static")),
    );
    for (name, define) in [
        ("plugin.so", None),
        ("plugin-without.so", Some("-DOMIT_POST_ARM_SYMBOL")),
    ] {
        let mut command = compiler.to_command();
        command
            .args(["-fPIC", "-shared", "-D__NX_INTERCEPT_RDTSC", "-I"])
            .arg(source.join("includes/plugins"));
        if let Some(define) = define {
            command.arg(define);
        }
        checked(
            command
                .arg(fixtures.join("plugin.c"))
                .arg(source.join("plugin_api/recursion_protector.c"))
                .arg(loader.parent().unwrap().join("plugin_api/libplugin_api.a"))
                .args(["-Wl,-z,now", "-o"])
                .arg(out.path().join(name))
                .args(["-UNDEBUG", "-Wl,-Bsymbolic-functions"]),
        );
    }

    let run = |plugin: &str, args: &[&str], client: &str| -> Output {
        Command::new("timeout")
            .args(["--kill-after=2s", "20s"])
            .arg(loader)
            .arg(out.path().join(plugin))
            .args(args)
            .arg("--")
            .arg(out.path().join(client))
            .output()
            .unwrap()
    };
    let routed = |plugin: &str, args: &[&str]| -> String {
        let output = run(plugin, args, "client");
        assert!(output.status.success(), "{plugin} {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    // Without the symbol, and with a zero report, the plugin's own calls and
    // ARCH_SET_FS run natively, as before.
    assert_eq!(routed("plugin-without.so", &["armed"]), "ROUTED=0\n");
    assert_eq!(routed("plugin.so", &[]), "ROUTED=0\n");
    // A reported arming routes the plugin's nested getuid (1), its getpid from
    // post_load (10) and the client's ARCH_SET_FS (100), and keeps the
    // plugin's domain across the nested call (otherwise -1000).
    assert_eq!(routed("plugin.so", &["armed"]), "ROUTED=111\n");

    let refused = run("plugin.so", &["armed"], "client-static");
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("post-arm routing does not support static clients"),
        "{refused:?}"
    );
    // The same static client without the report still runs.
    let unarmed = run("plugin.so", &[], "client-static");
    assert!(unarmed.status.success(), "{unarmed:?}");
    assert_eq!(unarmed.stdout, b"STATIC_OK\n", "{unarmed:?}");
}
