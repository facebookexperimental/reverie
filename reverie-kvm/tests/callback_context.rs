/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A thread keeps its syscall-callback state from one callback to the next.
//! Each case crosses one event that changes the task (exec, a thread or
//! process clone, fork, vfork, exit, a descriptor-table change, a signal
//! delivery) with bursts of callbacks on both sides, under a Tool that
//! subscribes to every syscall, and requires the native run's exit status and
//! output.

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
            "reverie-kvm-callback-context-{}-{id}",
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
        .unwrap_or_else(|error| panic!("callback context test requires usable /dev/kvm: {error}"));
    let directory = TestDirectory::new();
    let source = directory.0.join("callback-context.c");
    let executable = directory.0.join("callback-context");
    std::fs::write(&source, include_str!("fixtures/callback_context.c")).unwrap();
    let compile = std::process::Command::new("/usr/bin/gcc")
        .args(["-std=c11", "-O2", "-pthread", "-Wall", "-Wextra", "-Werror"])
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
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(native.stderr.is_empty(), "native {case}: {native:?}");
    let native_code = native.status.code().expect("native run exited");
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
        // Every burst syscall was a Tool callback.
        let callbacks = log
            .syscalls()
            .iter()
            .filter(|call| *call == "getppid")
            .count();
        assert!(callbacks >= 128, "{case}: {callbacks} getppid callbacks");
        (code, stdout, stderr)
    } else {
        backend.run_static_elf_captured().unwrap()
    };
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&native.stdout),
        "KVM case={case} tool={with_tool}"
    );
    assert_eq!(code, native_code, "KVM case={case} tool={with_tool}");
}

macro_rules! cases {
    ($($name:ident: $case:literal, $tool:literal;)*) => {
        $(#[test] fn $name() { run_case($case, $tool); })*
    };
}

cases! {
    callback_context_exec_tool: "exec", true;
    callback_context_exec_direct: "exec", false;
    callback_context_thread_clone_tool: "thread", true;
    callback_context_thread_clone_direct: "thread", false;
    callback_context_fork_tool: "fork", true;
    callback_context_fork_direct: "fork", false;
    callback_context_process_clone_tool: "clone-process", true;
    callback_context_process_clone_direct: "clone-process", false;
    callback_context_vfork_tool: "vfork", true;
    callback_context_vfork_direct: "vfork", false;
    callback_context_exit_tool: "exit", true;
    callback_context_exit_direct: "exit", false;
    callback_context_descriptor_table_tool: "descriptors", true;
    callback_context_descriptor_table_direct: "descriptors", false;
    callback_context_signal_delivery_tool: "signal", true;
    callback_context_signal_delivery_direct: "signal", false;
}
