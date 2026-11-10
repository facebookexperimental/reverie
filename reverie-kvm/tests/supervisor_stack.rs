/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A Tool whose callbacks need more stack than Rust's 2 MiB default for a
//! spawned thread runs on the KVM backend without `RUST_MIN_STACK`: the host
//! threads that drive forked processes and guest threads (supervisor threads)
//! are spawned with their own stack size.
//!
//! The guest runs in a re-executed copy of this test binary with
//! `RUST_MIN_STACK` removed from its environment. A test runner or validation
//! harness may set that variable for every thread, which would hide a
//! supervisor thread spawned at the default.

#![cfg(target_arch = "x86_64")]
#![allow(clippy::disallowed_methods, reason = "tests may make threads freely")]

use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;

use kvm_ioctls::Kvm;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie_kvm::KvmBackend;

const TEST: &str = "deep_tool_callbacks_run_on_supervisor_threads_without_rust_min_stack";

/// Set in the re-executed child, which runs the guest, to the parent's test
/// directory. The child works only inside it, so the parent removes what the
/// child left even when the child aborts.
const CHILD_ENV: &str = "REVERIE_KVM_SUPERVISOR_STACK_CHILD";

/// The stack each deep callback uses: twice the deepest Tool callback path
/// measured on a supervisor thread (about 2 MiB, in a debug build), and more
/// than Rust's 2 MiB default, so it overflows any supervisor thread spawned at
/// the default.
const DEEP_CALLBACK_STACK_BYTES: usize = 4 << 20;

/// The test runs the guest's first process on its own thread with the stack a
/// Linux main thread gets by default. That process runs on the embedder's
/// thread, not on a supervisor thread, and this keeps it independent of the
/// stack the test harness gives its own threads.
const ROOT_STACK_BYTES: usize = 8 << 20;

const MEMORY_SIZE: usize = 64 * 1024 * 1024;

/// A fork tree of 7 processes, three levels deep. Each process takes a signal
/// whose handler calls getppid, and starts a thread that calls getppid. So 6
/// forked processes and 7 guest threads each make one Tool callback on a
/// supervisor thread, and the first process makes one on the embedder's thread.
const FORK_TREE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t handled;

static void on_usr1(int signal) {
    (void)signal;
    syscall(SYS_getppid);
    handled = 1;
}

static void *worker(void *unused) {
    (void)unused;
    syscall(SYS_getppid);
    return NULL;
}

static int node(int depth) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    if (sigaction(SIGUSR1, &action, NULL)) return 90;
    handled = 0;
    if (raise(SIGUSR1) || !handled) return 91;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) || pthread_join(thread, NULL)) return 92;
    for (int i = 0; depth > 0 && i < 2; i++) {
        pid_t child = fork();
        if (child < 0) return 93;
        if (child == 0) _exit(node(depth - 1));
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 94;
        if (WEXITSTATUS(status)) return WEXITSTATUS(status);
    }
    return 0;
}

int main(void) {
    int status = node(2);
    printf("fork tree: %d\n", status);
    return status;
}
"#;

/// The thread names deep callbacks ran on.
static DEEP_CALLBACK_THREADS: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[derive(Debug, Default)]
struct DeepStackTool;

#[reverie::tool]
impl Tool for DeepStackTool {
    type GlobalState = ();
    /// Whether this guest thread is driven by a supervisor thread: every
    /// thread except the first process's first thread.
    type ThreadState = bool;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::getppid]);
        subscriptions
    }

    fn init_thread_state(&self, _child: Tid, parent: Option<(Tid, &bool)>) -> bool {
        parent.is_some()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if *guest.thread_state() {
            std::hint::black_box(use_stack(DEEP_CALLBACK_STACK_BYTES));
            DEEP_CALLBACK_THREADS
                .lock()
                .unwrap()
                .push(std::thread::current().name().unwrap_or_default().to_owned());
        }
        guest.tail_inject(syscall).await
    }
}

/// Uses `bytes` of stack through a chain of 64 KiB frames, as a deep
/// synchronous call chain inside a callback would.
#[inline(never)]
fn use_stack(bytes: usize) -> u8 {
    const FRAME: usize = 64 * 1024;
    let mut frame = [0u8; FRAME];
    std::hint::black_box(&mut frame);
    let below = if bytes > FRAME {
        use_stack(bytes - FRAME)
    } else {
        0
    };
    std::hint::black_box(frame[usize::from(below) % FRAME]) ^ below
}

fn kvm_available() -> bool {
    match Kvm::new() {
        Ok(_) => true,
        Err(error) if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) => {
            eprintln!("skipping {TEST}: cannot open /dev/kvm: {error}");
            false
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "reverie-kvm-supervisor-stack-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn compile_fork_tree(directory: &Path) -> PathBuf {
    let source = directory.join("fork_tree.c");
    let program = directory.join("fork_tree");
    std::fs::write(&source, FORK_TREE).unwrap();
    let output = std::process::Command::new("/usr/bin/gcc")
        .args(["-O2", "-pthread"])
        .arg(&source)
        .arg("-o")
        .arg(&program)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gcc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    program
}

/// The child's half: runs the fork tree under the deep Tool, in `directory`.
fn run_fork_tree(directory: PathBuf) {
    let program = compile_fork_tree(&directory);
    let cwd = directory;
    let (code, stdout, stderr) = std::thread::Builder::new()
        .name("supervisor-stack-root".to_owned())
        .stack_size(ROOT_STACK_BYTES)
        .spawn(move || {
            let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
            backend
                .install_static_elf_file_with_context(
                    std::fs::File::open(&program).unwrap(),
                    &[program.to_str().unwrap()],
                    &["PATH=/usr/bin:/bin"],
                    &cwd,
                )
                .unwrap();
            let (_global, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<DeepStackTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        })
        .unwrap()
        .join()
        .unwrap();
    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);
    assert_eq!(
        (code, stdout.as_ref()),
        (0, "fork tree: 0\n"),
        "guest stderr: {stderr}"
    );
    let threads = DEEP_CALLBACK_THREADS.lock().unwrap().clone();
    let count = |prefix: &str| {
        threads
            .iter()
            .filter(|name| name.starts_with(prefix))
            .count()
    };
    // Every deep callback ran on a supervisor thread: one per forked process,
    // one per guest thread.
    assert_eq!(
        (
            count("reverie-kvm-process-"),
            count("reverie-kvm-guest-"),
            threads.len()
        ),
        (6, 7, 13),
        "deep callbacks ran on {threads:?}"
    );
}

#[test]
fn deep_tool_callbacks_run_on_supervisor_threads_without_rust_min_stack() {
    if !kvm_available() {
        return;
    }
    if let Some(directory) = std::env::var_os(CHILD_ENV) {
        run_fork_tree(PathBuf::from(directory));
        return;
    }
    // libtest's log shows the child really ran this one test, and passed.
    let directory = TestDirectory::new();
    let log = directory.0.join("libtest.log");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=5s", "60s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--logfile"])
        .arg(&log)
        .env(CHILD_ENV, &directory.0)
        .env_remove("RUST_MIN_STACK")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child without RUST_MIN_STACK failed: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        format!("ok {TEST}\n"),
        "the child did not run exactly this test\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
