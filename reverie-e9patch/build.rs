/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use goblin::elf::Elf;
use goblin::elf::program_header::PF_X;
use goblin::elf::program_header::PT_LOAD;

fn main() {
    println!("cargo:rerun-if-changed=runtime/syscall_trap.S");
    println!("cargo:rerun-if-changed=vendor/e9patch");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=NM");

    let output_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not set manifest dir"));
    let source_dir = manifest_dir.join("vendor/e9patch");
    let revision = fs::read_to_string(source_dir.join("REVISION"))
        .expect("the vendored e9patch source is missing its REVISION marker");
    assert_eq!(
        revision.trim(),
        "6c2c03c1da74b14daf1788a9f8dccfa354ce04a6",
        "the vendored e9patch revision marker changed"
    );
    for required in [
        "Makefile",
        "src/e9tool/e9tool.cpp",
        "src/e9patch/e9patch.cpp",
        "contrib/zydis/Makefile",
        "contrib/libdw/Makefile",
    ] {
        assert!(
            source_dir.join(required).is_file(),
            "the vendored e9patch source is incomplete: missing {required}"
        );
    }
    let output = output_dir.join("reverie-e9patch-syscall-trap");
    let handoff_page = 0x0000_0001_e900_0000_u64;
    // Version 2: the callback returns an explicit dispatch outcome (1=handled,
    // 2=tail-execute rt_sigreturn). A different magic makes mixed payload/DSO
    // versions fail closed instead of interpreting an undefined return value.
    let dispatch_magic = 0x7265_7665_3961_6f32_u64;
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        write_constants(&output_dir, handoff_page, 0, dispatch_magic, 0, 0, 0);
        std::fs::write(output, []).expect("failed to create unsupported-target payload");
        return;
    }

    let (e9tool, e9patch) = build_e9patch_tools(&source_dir, &output_dir.join("e9patch-build"));
    println!("cargo:rustc-env=REVERIE_E9TOOL={}", e9tool.display());
    println!(
        "cargo:rustc-env=REVERIE_E9PATCH_BACKEND={}",
        e9patch.display()
    );
    println!(
        "cargo:rustc-env=REVERIE_E9PATCH_SOURCE={}",
        source_dir.display()
    );

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
    let (payload_text_start, payload_text_end) = payload_executable_range(&output);
    let dispatch_page =
        PAYLOAD_RUNTIME_BASE + dynamic_symbol_address(&output, "reverie_e9patch_aot_page");
    let trap_entry =
        PAYLOAD_RUNTIME_BASE + dynamic_symbol_address(&output, "reverie_e9patch_syscall");
    let payload_text_start = PAYLOAD_RUNTIME_BASE + payload_text_start;
    let payload_text_end = PAYLOAD_RUNTIME_BASE + payload_text_end;
    assert!(
        (payload_text_start..payload_text_end).contains(&trap_entry),
        "e9patch trap entry is outside the executable payload segment"
    );
    write_constants(
        &output_dir,
        handoff_page,
        dispatch_page,
        dispatch_magic,
        trap_entry,
        payload_text_start,
        payload_text_end,
    );
}

fn build_e9patch_tools(source: &Path, build: &Path) -> (PathBuf, PathBuf) {
    let started = Instant::now();
    if build.exists() {
        fs::remove_dir_all(build).expect("failed to reset the e9patch build directory");
    }
    copy_tree(source, build);
    let jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|jobs| jobs.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, 16);
    run(
        Command::new("make")
            .arg("-C")
            .arg(build)
            .arg(format!("--jobs={jobs}"))
            .arg("release"),
        "build e9patch tools",
    );
    let e9tool = build.join("e9tool");
    let e9patch = build.join("e9patch");
    assert!(e9tool.is_file(), "e9patch build did not produce e9tool");
    assert!(e9patch.is_file(), "e9patch build did not produce e9patch");
    println!(
        "cargo:warning=e9patch source build completed in {:.2}s (jobs={jobs})",
        started.elapsed().as_secs_f64()
    );
    (e9tool, e9patch)
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", destination.display()));
    let mut entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()))
        .map(|entry| entry.expect("failed to read vendored source entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let target = destination.join(path.file_name().expect("source entry has no name"));
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap_or_else(|error| {
                panic!(
                    "failed to copy {} to {}: {error}",
                    path.display(),
                    target.display()
                )
            });
        }
    }
}

fn payload_executable_range(binary: &Path) -> (u64, u64) {
    let bytes = std::fs::read(binary)
        .unwrap_or_else(|error| panic!("failed to read e9patch payload: {error}"));
    let elf = Elf::parse(&bytes)
        .unwrap_or_else(|error| panic!("failed to parse e9patch payload: {error}"));
    let mut executable = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD && header.p_flags & PF_X != 0);
    let segment = executable
        .next()
        .expect("e9patch payload has no executable load segment");
    assert!(
        executable.next().is_none(),
        "e9patch payload has more than one executable load segment"
    );
    let end = segment
        .p_vaddr
        .checked_add(segment.p_memsz)
        .expect("e9patch executable segment overflows its address space");
    assert!(segment.p_vaddr < end, "e9patch executable segment is empty");
    (segment.p_vaddr, end)
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
    payload_text_start: u64,
    payload_text_end: u64,
) {
    std::fs::write(
        output_dir.join("aot_dispatch_constants.rs"),
        format!(
            "pub(crate) const AOT_HANDOFF_PAGE_ADDRESS: u64 = {handoff_page:#x};\n\
             #[cfg(test)]\n\
             pub(crate) const AOT_DISPATCH_PAGE_ADDRESS: u64 = {dispatch_page:#x};\n\
             pub(crate) const AOT_DISPATCH_MAGIC: u64 = {dispatch_magic:#x};\n\
             pub(crate) const AOT_PAYLOAD_TEXT_START: u64 = {payload_text_start:#x};\n\
             pub(crate) const AOT_PAYLOAD_TEXT_END: u64 = {payload_text_end:#x};\n\
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
