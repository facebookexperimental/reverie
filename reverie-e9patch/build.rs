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
    println!("cargo:rerun-if-changed=runtime/syscall_trap.S");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=NM");

    let output_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let output = output_dir.join("reverie-e9patch-syscall-trap");
    let handoff_page = 0x0000_0001_e900_0000_u64;
    // Version 2: the callback returns an explicit dispatch outcome (1=handled,
    // 2=tail-execute rt_sigreturn). A different magic makes mixed payload/DSO
    // versions fail closed instead of interpreting an undefined return value.
    let dispatch_magic = 0x7265_7665_3961_6f32_u64;
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        write_constants(&output_dir, handoff_page, 0, dispatch_magic, 0);
        std::fs::write(output, []).expect("failed to create unsupported-target payload");
        return;
    }

    let compiler = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let source = Path::new("runtime/syscall_trap.S");
    let object = output.with_extension("o");

    run(
        Command::new(&compiler)
            .args(["-c", "-Wall"])
            .arg(format!("-DREVERIE_E9PATCH_HANDOFF_PAGE={handoff_page:#x}"))
            .arg(format!("-DREVERIE_E9PATCH_AOT_MAGIC={dispatch_magic:#x}"))
            .arg(source)
            .arg("-o")
            .arg(&object),
        "assemble e9patch syscall trampoline",
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

    const PAYLOAD_RUNTIME_BASE: u64 = 0x7000_0000;
    let dispatch_page =
        PAYLOAD_RUNTIME_BASE + dynamic_symbol_address(&output, "reverie_e9patch_aot_page");
    let trap_entry =
        PAYLOAD_RUNTIME_BASE + dynamic_symbol_address(&output, "reverie_e9patch_syscall");
    write_constants(
        &output_dir,
        handoff_page,
        dispatch_page,
        dispatch_magic,
        trap_entry,
    );
}

fn dynamic_symbol_address(binary: &Path, symbol: &str) -> u64 {
    let nm = env::var_os("NM").unwrap_or_else(|| OsString::from("nm"));
    let output = Command::new(nm)
        .args(["-D", "--defined-only"])
        .arg(binary)
        .output()
        .unwrap_or_else(|error| panic!("failed to inspect e9patch payload symbols: {error}"));
    assert!(
        output.status.success(),
        "failed to inspect e9patch payload symbols: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            let _kind = fields.next()?;
            (fields.next()? == symbol)
                .then(|| u64::from_str_radix(address, 16).expect("invalid symbol address"))
        })
        .unwrap_or_else(|| panic!("e9patch payload does not export {symbol}"))
}

fn write_constants(
    output_dir: &Path,
    handoff_page: u64,
    dispatch_page: u64,
    dispatch_magic: u64,
    trap_entry: u64,
) {
    std::fs::write(
        output_dir.join("aot_dispatch_constants.rs"),
        format!(
            "pub(crate) const AOT_HANDOFF_PAGE_ADDRESS: u64 = {handoff_page:#x};\n\
             #[cfg(test)]\n\
             pub(crate) const AOT_DISPATCH_PAGE_ADDRESS: u64 = {dispatch_page:#x};\n\
             pub(crate) const AOT_DISPATCH_MAGIC: u64 = {dispatch_magic:#x};\n\
             #[cfg(test)]\n\
             pub(crate) const AOT_FALLBACK_TRAP_ENTRY: u64 = {trap_entry:#x};\n"
        ),
    )
    .expect("failed to write e9patch AOT dispatch constants");
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {description}: {error}"));
    assert!(status.success(), "failed to {description}: {status}");
}
