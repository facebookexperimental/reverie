/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use kvm_ioctls::Kvm;
use reverie_kvm::KvmBackend;
use reverie_kvm::StraceTool;
static NEXT: AtomicU64 = AtomicU64::new(0);
const EXPECTED: &[u8] = b"random carrier access, identity, flags, faults and bytes ok\n";

fn run_carrier(tool: bool) {
    Kvm::new().expect("random carrier access regression requires usable /dev/kvm");
    let artifact_root = std::env::var_os("REVERIE_KVM_RANDOM_CARRIER_ARTIFACT_DIR");
    let retain = artifact_root.is_some();
    let root = artifact_root.map_or_else(std::env::temp_dir, PathBuf::from);
    std::fs::create_dir_all(&root).unwrap();
    let directory = std::fs::canonicalize(root).unwrap().join(format!(
        "random-carrier-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    let source = directory.join("random_device_carrier.c");
    let binary = directory.join("random_device_carrier");
    std::fs::write(&source, include_str!("fixtures/random_device_carrier.c")).unwrap();
    let compiled = std::process::Command::new("/usr/bin/gcc")
        .args(["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "gcc: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    // Native comparison checks open/access/status/type/error semantics, never
    // compares host entropy to canonical bytes and never writes host entropy.
    let native_started = std::time::Instant::now();
    let native = std::process::Command::new(&binary)
        .arg("native")
        .output()
        .unwrap();
    if retain {
        std::fs::write(
            directory.join("native.argv.txt"),
            format!("{:?}\n", [binary.to_str().unwrap(), "native"]),
        )
        .unwrap();
        std::fs::write(directory.join("native.stdout"), &native.stdout).unwrap();
        std::fs::write(directory.join("native.stderr"), &native.stderr).unwrap();
        std::fs::write(
            directory.join("native.result.txt"),
            format!(
                "status={:?} elapsed_seconds={}\n",
                native.status,
                native_started.elapsed().as_secs_f64()
            ),
        )
        .unwrap();
    }
    assert!(
        native.status.success(),
        "native: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, EXPECTED);
    assert!(native.stderr.is_empty());
    for repetition in 0..2 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&binary).unwrap(),
                &[binary.to_str().unwrap(), "kvm"],
                &[],
                &directory,
            )
            .unwrap();
        let started = std::time::Instant::now();
        let mut callbacks = Vec::new();
        let (code, stdout, stderr) = if tool {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            callbacks = log.syscalls().to_vec();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        if retain {
            let label = format!("kvm-tool-{tool}-run-{repetition}");
            std::fs::write(
                directory.join(format!("{label}.argv.txt")),
                format!("{:?}\n", [binary.to_str().unwrap(), "kvm"]),
            )
            .unwrap();
            std::fs::write(directory.join(format!("{label}.stdout")), &stdout).unwrap();
            std::fs::write(directory.join(format!("{label}.stderr")), &stderr).unwrap();
            std::fs::write(
                directory.join(format!("{label}.result.txt")),
                format!(
                    "guest_exit={code} tool={tool} elapsed_seconds={}\n",
                    started.elapsed().as_secs_f64()
                ),
            )
            .unwrap();
        }
        // Retain the actual executor result even when an early guest failure
        // prevents a later required Tool callback from occurring.
        if tool {
            for name in [
                "openat", "read", "readv", "write", "writev", "fcntl", "fstat", "mmap",
            ] {
                assert!(
                    callbacks.iter().any(|call| call == name),
                    "missing Tool callback {name}"
                );
            }
        }
        assert_eq!(
            code,
            0,
            "tool={tool} repetition={repetition}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(stdout, EXPECTED);
    }
    if !retain {
        std::fs::remove_dir_all(directory).unwrap();
    }
}
#[test]
fn random_carrier_direct() {
    run_carrier(false);
}
#[test]
fn random_carrier_subscribed_tool() {
    run_carrier(true);
}
