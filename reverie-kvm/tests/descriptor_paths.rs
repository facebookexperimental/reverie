/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The random devices opened through every pathname spelling, a dup alias and
//! /proc/self/fd and /dev/fd reopens read like Linux's, while Linux lookup
//! errors and unrelated objects remain unchanged. The native run of the same
//! program is the oracle.

#![cfg(target_arch = "x86_64")]

use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use kvm_ioctls::Kvm;
use reverie_kvm::KvmBackend;
use reverie_kvm::StraceTool;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

const DEVICES: [&str; 2] = ["random", "urandom"];
const VARIANTS: [&str; 6] = [
    "literal",
    "double-slash",
    "component-slash",
    "dot",
    "dotdot",
    "symlink",
];
const CONTROLS: &[u8] = b"controls ok\n";

struct Fixture {
    directory: PathBuf,
    executable: PathBuf,
    retain: bool,
}

impl Fixture {
    fn new() -> Self {
        // An explicit artifact directory retains the exact native/KVM binary
        // for hashing by the validation runner. Default runs clean up fully.
        let artifact_root = std::env::var_os("REVERIE_KVM_DESCRIPTOR_PATHS_ARTIFACT_DIR");
        let retain = artifact_root.is_some();
        let root = artifact_root.map_or_else(std::env::temp_dir, PathBuf::from);
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let directory = root.join(format!(
            "reverie-kvm-descriptor-paths-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let executable = directory.join("descriptor-paths");
        let fixture = Self {
            directory,
            executable,
            retain,
        };
        let source = fixture.directory.join("descriptor-paths.c");
        std::fs::write(&source, include_str!("fixtures/descriptor_paths.c")).unwrap();
        let output = std::process::Command::new("/usr/bin/gcc")
            .args(["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&fixture.executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "gcc failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for device in DEVICES {
            symlink(
                format!("/dev/{device}"),
                fixture.directory.join(format!("{device}-link")),
            )
            .unwrap();
        }
        symlink("/dev/null", fixture.directory.join("null-link")).unwrap();
        symlink(
            "/proc/self/root/dev/urandom",
            fixture.directory.join("magic-link"),
        )
        .unwrap();
        std::fs::write(
            fixture.directory.join("urandom"),
            b"ordinary-file-control\n",
        )
        .unwrap();
        fixture
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.retain {
            eprintln!("retained random path fixture: {}", self.directory.display());
        } else {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }
}

fn case_headers() -> Vec<String> {
    let mut headers = Vec::new();
    for device in DEVICES {
        for variant in VARIANTS {
            for call in ["open", "openat"] {
                headers.push(format!("{device} {variant} {call} bytes=106\n"));
            }
        }
        headers.push(format!("{device} dirfd openat bytes=106\n"));
    }
    headers
}

/// Every case reads all 106 requested bytes through every spelling, a dup
/// alias and a /proc/self/fd and /dev/fd reopen; the output reports the
/// counts (the bytes are the host's entropy without a Tool that answers
/// them), then the pathname controls.
fn expected_output(headers: &[String]) -> Vec<u8> {
    let mut expected = Vec::new();
    for header in headers {
        expected.extend_from_slice(header.as_bytes());
    }
    expected.extend_from_slice(CONTROLS);
    expected
}

fn run_paths(with_tool: bool) {
    Kvm::new().expect("descriptor pathname test requires usable /dev/kvm");
    let fixture = Fixture::new();
    let headers = case_headers();
    let native = std::process::Command::new(&fixture.executable)
        .arg("native")
        .current_dir(&fixture.directory)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "native exit={:?}, stderr={}",
        native.status.code(),
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(native.stderr.is_empty(), "native: {native:?}");
    let expected = expected_output(&headers);
    assert_eq!(native.stdout, expected, "native");

    for repetition in 0..2 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&fixture.executable).unwrap(),
                &[fixture.executable.to_str().unwrap(), "kvm"],
                &[],
                &fixture.directory,
            )
            .unwrap();
        let (code, stdout, stderr) = if with_tool {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            let calls = log.syscalls();
            for name in ["dup", "readv"] {
                let count = calls.iter().filter(|call| call.as_str() == name).count();
                assert_eq!(
                    count,
                    headers.len(),
                    "each path must deliver its {name} call to the Tool"
                );
            }
            for (name, minimum) in [
                ("open", DEVICES.len() * VARIANTS.len()),
                ("openat", DEVICES.len() * (VARIANTS.len() + 1)),
                ("read", headers.len() * 3),
            ] {
                let count = calls.iter().filter(|call| call.as_str() == name).count();
                assert!(
                    count >= minimum,
                    "{name}: expected at least {minimum} Tool callbacks, observed {count}"
                );
            }
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code,
            0,
            "tool={with_tool} repetition={repetition} stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(
            stdout, expected,
            "tool={with_tool} repetition={repetition}: every path, alias and reopen must read as natively"
        );
    }
}

#[test]
fn descriptor_paths_direct() {
    run_paths(false);
}

#[test]
fn descriptor_paths_tool() {
    run_paths(true);
}
