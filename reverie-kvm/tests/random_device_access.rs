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

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "reverie-kvm-random-access-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run_case(case: &str, with_tool: bool) {
    Kvm::new()
        .unwrap_or_else(|error| panic!("random access test requires usable /dev/kvm: {error}"));
    let directory = TestDirectory::new();
    let source = directory.0.join("random-access.c");
    let executable = directory.0.join("random-access");
    std::fs::write(&source, include_str!("fixtures/random_device_access.c")).unwrap();
    let compile = std::process::Command::new("/usr/bin/gcc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "fixture compile failed: {compile:?}"
    );
    let native = std::process::Command::new(&executable)
        .arg(case)
        .output()
        .unwrap();
    assert!(native.status.success(), "native {case}: {native:?}");
    assert!(native.stderr.is_empty(), "native {case}: {native:?}");
    let expected = if case == "write-stream" || case == "downstream-resolver" {
        assert_eq!(
            native.stdout.len(),
            164,
            "native writes must preserve successful reads"
        );
        // Native bytes are entropy, while the backend uses the established
        // seed-zero deterministic contract. This oracle is independent of the
        // carrier and Rust byte generator and checks all bytes after writes.
        (0..2)
            .flat_map(|_| (0..82u64).map(|index| ((index * 73 + 41) & 255) as u8))
            .collect::<Vec<_>>()
    } else {
        let expected = format!("random-access {case} ok\n").into_bytes();
        assert_eq!(native.stdout, expected, "native {case}");
        expected
    };
    eprintln!("native {case} passed exact syscall assertions for both random devices");
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&executable).unwrap(),
            &[executable.to_str().unwrap(), case],
            &[],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = if with_tool {
        let (log, code, stdout, stderr) =
            futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
                .unwrap();
        assert!(log.syscalls().iter().any(|call| call == "openat"));
        (code, stdout, stderr)
    } else {
        backend.run_static_elf_captured().unwrap()
    };
    assert_eq!(
        code,
        0,
        "KVM case={case} tool={with_tool} stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, expected, "KVM case={case} tool={with_tool}");
}

macro_rules! cases {
    ($($name:ident: $case:literal, $tool:literal;)*) => {
        $(#[test] fn $name() { run_case($case, $tool); })*
    };
}

cases! {
    random_access_readonly_direct: "readonly", false;
    random_access_readonly_tool: "readonly", true;
    random_access_writeonly_direct: "writeonly", false;
    random_access_writeonly_tool: "writeonly", true;
    random_access_readwrite_direct: "readwrite", false;
    random_access_readwrite_tool: "readwrite", true;
    random_access_mode3_direct: "access3", false;
    random_access_mode3_tool: "access3", true;
    random_access_path_direct: "path", false;
    random_access_path_tool: "path", true;
    random_access_write_faults_direct: "write-faults", false;
    random_access_write_faults_tool: "write-faults", true;
    random_access_write_stream_direct: "write-stream", false;
    random_access_write_stream_tool: "write-stream", true;
}

cases! {
    random_access_downstream_mmap_direct: "downstream-mmap", false;
    random_access_downstream_mmap_tool: "downstream-mmap", true;
    random_access_downstream_resolver_direct: "downstream-resolver", false;
    random_access_downstream_resolver_tool: "downstream-resolver", true;
}
