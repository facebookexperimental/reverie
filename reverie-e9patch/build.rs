/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=runtime/syscall_trap.c");
    println!("cargo:rerun-if-env-changed=CC");

    let output_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let output = output_dir.join("reverie-e9patch-syscall-trap");
    let dispatch_page = 0x0000_0001_e900_0000_u64;
    let dispatch_magic = 0x7265_7665_3961_6f74_u64;
    let trap_entry = 0x0000_0000_7000_1000_u64;
    std::fs::write(
        output_dir.join("aot_dispatch_constants.rs"),
        format!(
            "pub(crate) const AOT_DISPATCH_PAGE_ADDRESS: u64 = {dispatch_page:#x};\n\
             pub(crate) const AOT_DISPATCH_MAGIC: u64 = {dispatch_magic:#x};\n\
             #[cfg(test)]\n\
             pub(crate) const AOT_FALLBACK_TRAP_ENTRY: u64 = {trap_entry:#x};\n"
        ),
    )
    .expect("failed to write e9patch AOT dispatch constants");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        std::fs::write(output, []).expect("failed to create unsupported-target payload");
        return;
    }

    let compiler = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let source = Path::new("runtime/syscall_trap.c");
    let object = output.with_extension("o");

    run(
        Command::new(&compiler)
            .args([
                "-fno-stack-protector",
                "-fno-builtin",
                "-fno-exceptions",
                "-fpie",
                "-O2",
                "-mno-mmx",
                "-mno-sse",
                "-mno-avx",
                "-msoft-float",
                "-fomit-frame-pointer",
                "-c",
                "-Wall",
            ])
            .arg(format!("-DREVERIE_E9PATCH_AOT_PAGE={dispatch_page:#x}"))
            .arg(format!("-DREVERIE_E9PATCH_AOT_MAGIC={dispatch_magic:#x}"))
            .arg(format!("-DREVERIE_E9PATCH_TRAP_ENTRY={trap_entry:#x}"))
            .arg(source)
            .arg("-o")
            .arg(&object),
        "compile e9patch syscall trampoline",
    );
    run(
        Command::new(&compiler)
            .arg(&object)
            .arg("-o")
            .arg(&output)
            .args([
                "-pie",
                "-nostdlib",
                "-Wl,-z",
                "-Wl,max-page-size=4096",
                "-Wl,-z",
                "-Wl,norelro",
                "-Wl,-z",
                "-Wl,stack-size=0",
                "-Wl,--export-dynamic",
                "-Wl,--entry=0x0",
                "-Wl,--sort-section=name",
                "-Wl,--strip-all",
            ]),
        "link e9patch syscall trampoline",
    );
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {description}: {error}"));
    assert!(status.success(), "failed to {description}: {status}");
}
