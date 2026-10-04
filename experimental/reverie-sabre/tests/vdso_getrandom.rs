/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! The loader must replace the vDSO's getrandom so that glibc 2.41+'s
//! parameter query fails with -ENOSYS (keeping glibc on its rewritten syscall
//! path) and every remaining draw reaches the plugin as a getrandom syscall,
//! rather than being served from in-process ChaCha state that re-keys on host
//! time.

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

#[test]
fn vdso_getrandom_refuses_the_query_and_routes_draws_to_the_plugin() {
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vdso_getrandom");
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
    eprintln!("vDSO getrandom under SaBRe: {output:?}");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout == "VDSO_GETRANDOM_OK draws=5\n" || stdout == "VDSO_GETRANDOM_ABSENT\n",
        "{stdout}"
    );
}
