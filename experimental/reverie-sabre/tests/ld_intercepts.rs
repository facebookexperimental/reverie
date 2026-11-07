#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! The loader refuses a client, by name and before it runs, when it cannot
//! install the dynamic-linker intercepts that start its plugin in the
//! client's own dynamic linker. Without them the client would run with no
//! plugin at all.

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

/// Builds a stand-in dynamic linker (`no_text` puts its code outside .text)
/// and a client that names it as its interpreter.
fn build(out: &Path, no_text: bool) -> PathBuf {
    let interpreter = out.join("ld-linux-fake.so.2");
    let mut command = compiler().to_command();
    if no_text {
        command.arg("-DNO_TEXT");
    }
    checked(
        command
            .args(["-nostdlib", "-static-pie"])
            .arg(fixtures().join("ld_intercepts/fake_ld.S"))
            .arg("-o")
            .arg(&interpreter),
    );
    let client = out.join("client");
    checked(
        compiler()
            .to_command()
            .arg(format!("-Wl,--dynamic-linker={}", interpreter.display()))
            .arg(fixtures().join("ld_intercepts/client.c"))
            .arg("-o")
            .arg(&client),
    );
    client
}

/// Builds, in `out/real`, the same decoy client with the system's own dynamic
/// linker as its interpreter.
fn build_decoy_under_real_interpreter(out: &Path) -> PathBuf {
    let dir = out.join("real");
    std::fs::create_dir_all(&dir).unwrap();
    let client = dir.join("ld-linux-decoy.so.2");
    checked(
        compiler()
            .to_command()
            .arg("-rdynamic")
            .arg(fixtures().join("ld_intercepts/decoy_client.c"))
            .arg("-o")
            .arg(&client),
    );
    client
}

/// Builds a client named like a dynamic linker that defines the three
/// intercepted functions, with a stand-in interpreter whose name the loader
/// does not treat as a dynamic linker's.
fn build_decoy(out: &Path) -> PathBuf {
    let interpreter = out.join("fake-interp.so");
    checked(
        compiler()
            .to_command()
            .args(["-nostdlib", "-static-pie"])
            .arg(fixtures().join("ld_intercepts/fake_ld.S"))
            .arg("-o")
            .arg(&interpreter),
    );
    let client = out.join("ld-linux-decoy.so.2");
    checked(
        compiler()
            .to_command()
            .arg("-rdynamic")
            .arg(format!("-Wl,--dynamic-linker={}", interpreter.display()))
            .arg(fixtures().join("ld_intercepts/decoy_client.c"))
            .arg("-o")
            .arg(&client),
    );
    client
}

fn build_plugin(out: &Path) -> PathBuf {
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let plugin = out.join("plugin.so");
    checked(
        compiler()
            .to_command()
            .args(["-fPIC", "-shared", "-D__NX_INTERCEPT_RDTSC", "-I"])
            .arg(source.join("includes/plugins"))
            .arg(fixtures().join("prefixed_syscall/plugin.c"))
            .arg(source.join("plugin_api/recursion_protector.c"))
            .arg(loader.parent().unwrap().join("plugin_api/libplugin_api.a"))
            .args(["-Wl,-z,now", "-o"])
            .arg(&plugin)
            .args(["-UNDEBUG", "-Wl,-Bsymbolic-functions"]),
    );
    plugin
}

fn under_loader(plugin: &Path, client: &Path) -> Output {
    Command::new("timeout")
        .args(["--kill-after=2s", "20s"])
        .arg(reverie_sabre::bundled_sabre_path())
        .arg(plugin)
        .arg("--")
        .arg(client)
        .output()
        .unwrap()
}

fn refuses(no_text: bool, message: &str, detail: &str) {
    let out = tempfile::tempdir().unwrap();
    let client = build(out.path(), no_text);
    refuses_client(out.path(), &client, message, detail);
}

fn refuses_client(out: &Path, client: &Path, message: &str, detail: &str) {
    let plugin = build_plugin(out);

    // Natively the stand-in linker runs in place of the client's own start.
    let native = checked(&mut Command::new(client));
    assert_eq!(native.stdout, b"UNMONITORED\n");

    let output = under_loader(&plugin, client);
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(message) && stderr.contains(detail),
        "{output:?}"
    );
}

#[test]
fn a_dynamic_linker_without_text_is_refused_before_the_client_runs() {
    refuses(
        true,
        "refused: SaBRe could not install its dynamic-linker intercepts \
         (_dl_init, _dl_map_object_deps, _dl_map_object)",
        "so its plugin would never start",
    );
}

#[test]
fn a_dynamic_linker_without_the_intercepted_symbols_is_refused_by_name() {
    refuses(
        false,
        "refused: SaBRe cannot find _dl_init in the dynamic linker",
        "it is not in its symbol table, and it has no external debug information",
    );
}

#[test]
fn intercepts_in_another_object_named_like_a_dynamic_linker_do_not_count() {
    let out = tempfile::tempdir().unwrap();
    let client = build_decoy(out.path());
    refuses_client(
        out.path(),
        &client,
        "refused: SaBRe could not install its dynamic-linker intercepts \
         (_dl_init, _dl_map_object_deps, _dl_map_object)",
        "fake-interp.so, so its plugin would never start",
    );
}

#[test]
fn a_client_named_like_a_dynamic_linker_does_not_take_its_intercepts() {
    // Under the real dynamic linker the intercepts go into that file only, so
    // the plugin starts and the decoy's own functions are never called.
    let out = tempfile::tempdir().unwrap();
    let client = build_decoy_under_real_interpreter(out.path());
    let plugin = build_plugin(out.path());
    assert_eq!(checked(&mut Command::new(&client)).stdout, b"NATIVE\n");
    let output = under_loader(&plugin, &client);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ROUTED\n", "{output:?}");
}
