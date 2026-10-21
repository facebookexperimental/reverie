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
            "reverie-kvm-descriptor-access-{}-{id}",
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
        .unwrap_or_else(|error| panic!("descriptor access test requires usable /dev/kvm: {error}"));
    let directory = TestDirectory::new();
    let source = directory.0.join("descriptor-access.c");
    let executable = directory.0.join("descriptor-access");
    std::fs::write(&source, include_str!("fixtures/descriptor_access.c")).unwrap();
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
    // The fixture asserts Linux's answers for the random devices itself and
    // prints every result for /dev/random, /dev/urandom and an ordinary file
    // (no entropy). The native run is the oracle for the backend's output.
    let native = std::process::Command::new(&executable)
        .arg(case)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(native.status.success(), "native {case}: {native:?}");
    assert!(native.stderr.is_empty(), "native {case}: {native:?}");
    eprintln!(
        "native {case}:\n{}",
        String::from_utf8_lossy(&native.stdout)
    );
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
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&native.stdout),
        "KVM case={case} tool={with_tool}"
    );
}

macro_rules! cases {
    ($($name:ident: $case:literal, $tool:literal;)*) => {
        $(#[test] fn $name() { run_case($case, $tool); })*
    };
}

cases! {
    descriptor_access_readonly_direct: "readonly", false;
    descriptor_access_readonly_tool: "readonly", true;
    descriptor_access_writeonly_direct: "writeonly", false;
    descriptor_access_writeonly_tool: "writeonly", true;
    descriptor_access_readwrite_direct: "readwrite", false;
    descriptor_access_readwrite_tool: "readwrite", true;
    descriptor_access_mode3_direct: "access3", false;
    descriptor_access_mode3_tool: "access3", true;
    descriptor_access_path_direct: "path", false;
    descriptor_access_path_tool: "path", true;
    descriptor_access_write_faults_direct: "write-faults", false;
    descriptor_access_write_faults_tool: "write-faults", true;
    descriptor_access_write_stream_direct: "write-stream", false;
    descriptor_access_write_stream_tool: "write-stream", true;
}

cases! {
    descriptor_access_downstream_mmap_direct: "downstream-mmap", false;
    descriptor_access_downstream_mmap_tool: "downstream-mmap", true;
    descriptor_access_downstream_resolver_direct: "downstream-resolver", false;
    descriptor_access_downstream_resolver_tool: "downstream-resolver", true;
}
