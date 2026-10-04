/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Relocation of RIP-relative instructions that a detour moves out of a
//! function prologue. glibc 2.39's getrandom begins with
//! `cmpb $0x0,disp32(%rip)` (opcode 0x80); before 0x80 was handled, every
//! SaBRe run that detoured getrandom on Ubuntu 24.04 exited 127 during plugin
//! initialization (https://github.com/rrnewton/reverie/issues/741).

use std::process::Command;

#[test]
fn copy_postamble_relocates_rip_relative_group1_instructions() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sabre = source.join("vendor/sabre");
    // A uniquely named directory, removed on drop even when an assertion
    // below fails.
    let out = tempfile::Builder::new()
        .prefix("reverie-copy-postamble-")
        .tempdir()
        .unwrap();
    let binary = out.path().join("copy-postamble");
    let output = cc::Build::new()
        .cargo_metadata(false)
        .opt_level(2)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler()
        .to_command()
        // Compile the real rewriter and decoder; the unused detour entry
        // points are discarded so the rest of the SaBRe runtime need not
        // link. Keep the C assertions active even under -DNDEBUG.
        .args([
            "-std=gnu99",
            "-UNDEBUG",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
        ])
        .arg("-I")
        .arg(sabre.join("includes"))
        .arg("-I")
        .arg(sabre.join("includes/loader"))
        .arg("-I")
        .arg(sabre.join("includes/arch"))
        .arg("-I")
        .arg(sabre.join("arch/x86_64"))
        .arg("-I")
        .arg(source.join("vendor/libelf"))
        .arg(source.join("tests/copy_postamble_rip_relative.c"))
        .arg(sabre.join("arch/x86_64/x86_decoder.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    for case in [
        "getrandom-2.39",
        "cmpb-negative",
        "cmpb-borrow",
        "cmpl-imm8",
        "cmpl-imm32",
    ] {
        let output = Command::new(&binary).arg(case).output().unwrap();
        assert!(output.status.success(), "case={case}: {output:?}");
        assert_eq!(output.stdout, format!("PASS {case}\n").as_bytes());
    }
    // The group-1 relocation assumes the displacement is at offset 2, which a
    // prefix moves. These must refuse through SaBRe's fatal path (exit 127)
    // rather than emit an instruction that addresses the wrong location.
    for (case, opcode) in [
        ("cmpq-rex", "0x83"),
        ("cmpw-opsize", "0x81"),
        ("cmpb-segment", "0x80"),
    ] {
        let output = Command::new(&binary).arg(case).output().unwrap();
        assert_eq!(output.status.code(), Some(127), "case={case}: {output:?}");
        assert!(output.stdout.is_empty(), "case={case}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "prefixed RIP relative group-1 instruction not supported: {opcode}"
            )),
            "case={case}: {output:?}"
        );
    }
    out.close().unwrap();
}
