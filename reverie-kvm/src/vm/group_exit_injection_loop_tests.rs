/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A group exit ends a thread whose Tool callback keeps injecting.
//!
//! A Tool may turn one guest syscall into a loop of injections, for example
//! by retrying a non-blocking poll until the event the guest waits for
//! arrives. If that event never comes and another thread of the group calls
//! `exit_group`, Linux kills the polling thread inside its next syscall, so
//! the loop ends and the process exits. The backend must do the same: an
//! injection made after the group's exit never returns to the callback. Both
//! victims are covered, a worker polling while the root exits and the root
//! polling while a worker exits. Each test runs in a child process with a
//! deadline, so a regression fails instead of hanging.

use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use reverie::Errno;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;

use super::*;

const PROGRAM: &str = r#"#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
/* The Tool answers this getpid only once the other thread is polling. */
#define POLLING_MARKER 0x706f6c6cL
static sigset_t waited;
static void say(const char *text) {
  if (write(1, text, strlen(text)) < 0) _exit(9);
}
/* Natively this returns EAGAIN at once. The Tool retries it until a signal
   arrives, and none ever does. */
static void poll_for_signal(void) {
  struct timespec zero = {0, 0};
  sigtimedwait(&waited, NULL, &zero);
}
static void *poller(void *unused) {
  (void)unused;
  poll_for_signal();
  say("poller returned\n");
  return NULL;
}
static void *exiter(void *unused) {
  (void)unused;
  syscall(SYS_getpid, POLLING_MARKER);
  say("worker exiting\n");
  exit(0);
}
int main(int argc, char **argv) {
  pthread_t thread;
  sigemptyset(&waited);
  sigaddset(&waited, SIGUSR2);
  if (pthread_sigmask(SIG_BLOCK, &waited, NULL)) return 2;
  if (argc == 2 && strcmp(argv[1], "worker-polls") == 0) {
    if (pthread_create(&thread, NULL, poller, NULL)) return 3;
    syscall(SYS_getpid, POLLING_MARKER);
    say("main exiting\n");
    exit(0);
  }
  if (argc == 2 && strcmp(argv[1], "main-polls") == 0) {
    if (pthread_create(&thread, NULL, exiter, NULL)) return 3;
    poll_for_signal();
    say("main returned\n");
    return 4;
  }
  return 5;
}
"#;

const POLLING_MARKER: u64 = 0x706f6c6c;
/// Polls the other thread must have made before the marker returns, so the
/// group exit lands while the poll loop is running.
const POLLS_BEFORE_EXIT: u64 = 100;

/// Injections made by the poll loop, in this (child) process.
static POLLS: AtomicU64 = AtomicU64::new(0);
/// Poll results other than EAGAIN, which would end the loop by themselves.
static UNEXPECTED: Mutex<Vec<i64>> = Mutex::new(Vec::new());
/// Every `on_exit_thread`, as (tid, status).
static THREAD_EXITS: Mutex<Vec<(i32, ExitStatus)>> = Mutex::new(Vec::new());

#[derive(Default)]
struct PollingGlobal;

#[reverie::global_tool]
impl GlobalTool for PollingGlobal {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, _request: ()) {}
}

/// Turns the guest's zero-timeout signal wait into a retry loop that polls
/// until the wait stops answering EAGAIN, and holds the marker getpid until
/// that loop has polled `POLLS_BEFORE_EXIT` times.
#[derive(Default)]
struct PollingTool;

#[reverie::tool]
impl Tool for PollingTool {
    type GlobalState = PollingGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> std::result::Result<i64, reverie::Error> {
        match syscall {
            Syscall::RtSigtimedwait(_) => loop {
                let result = guest.inject(syscall).await;
                POLLS.fetch_add(1, Ordering::SeqCst);
                if result != Err(Errno::EAGAIN) {
                    let raw = match result {
                        Ok(value) => value,
                        Err(errno) => -i64::from(errno.into_raw()),
                    };
                    UNEXPECTED.lock().unwrap().push(raw);
                    return Ok(raw);
                }
            },
            Syscall::Getpid(_) if syscall.into_parts().1.arg0 as u64 == POLLING_MARKER => {
                let deadline = Instant::now() + Duration::from_secs(10);
                while POLLS.load(Ordering::SeqCst) < POLLS_BEFORE_EXIT {
                    assert!(
                        Instant::now() < deadline,
                        "the other thread never polled {POLLS_BEFORE_EXIT} times"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(i64::from(guest.pid().as_raw()))
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _global_state: &G,
        _thread_state: Self::ThreadState,
        status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        THREAD_EXITS.lock().unwrap().push((tid.as_raw(), status));
        Ok(())
    }
}

/// Runs `test` in a child process with a deadline. Returns true in the child,
/// which then runs the test body; the parent returns false after checking
/// that the child ran exactly this test and passed.
fn in_bounded_child(test: &str) -> bool {
    let name = format!(
        "{}::{test}",
        module_path!()
            .split_once("::")
            .expect("module path below the crate")
            .1
    );
    if std::env::var("REVERIE_GROUP_EXIT_LOOP_CHILD").as_deref() == Ok(name.as_str()) {
        return true;
    }
    let output = Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env("REVERIE_GROUP_EXIT_LOOP_CHILD", &name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{name} failed or hung (timeout exits 124): status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed; 0 failed;"),
        "{name}: the child must run exactly this test: {output:?}"
    );
    false
}

/// Runs the program in `mode` under `PollingTool` and checks that the group
/// exit ended the poll loop: the process exits 0 with the exiting thread's
/// line, the loop polled, and the poll never returned.
fn run_mode(mode: &str, expected_stdout: &str) {
    let directory = std::env::temp_dir().join(format!(
        "reverie-group-exit-injection-loop-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("group-exit-injection-loop.c");
    let executable = directory.join("group-exit-injection-loop");
    std::fs::write(&source, PROGRAM).unwrap();
    let output = Command::new("/usr/bin/gcc")
        .args([
            "-O2",
            "-pthread",
            "-fno-pie",
            "-no-pie",
            "-std=gnu11",
            "-Wall",
            "-Werror",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(output.status.success(), "gcc failed: {output:?}");
    let image = std::fs::read(&executable).unwrap();
    let program = executable.to_str().unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).expect("this test requires /dev/kvm");
    backend
        .install_static_elf_with_context(&image, &[program, mode], &[], &directory)
        .unwrap();
    let result =
        futures::executor::block_on(backend.run_static_elf_with_tool::<PollingTool>((), true));
    let _ = std::fs::remove_dir_all(&directory);
    let (_, status, stdout, stderr) = result.unwrap();
    assert_eq!(
        (status, String::from_utf8_lossy(&stdout).as_ref()),
        (0, expected_stdout),
        "mode={mode} stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        POLLS.load(Ordering::SeqCst) >= POLLS_BEFORE_EXIT,
        "mode={mode}: the poll loop must have run before the group exit"
    );
    assert_eq!(
        *UNEXPECTED.lock().unwrap(),
        Vec::<i64>::new(),
        "mode={mode}: a poll returned something other than EAGAIN"
    );
    let exits = THREAD_EXITS.lock().unwrap().clone();
    assert_eq!(
        exits.len(),
        2,
        "mode={mode}: both threads exit exactly once: {exits:?}"
    );
    assert!(
        exits
            .iter()
            .all(|&(_, status)| status == ExitStatus::Exited(0)),
        "mode={mode}: both threads end with the group's exit status: {exits:?}"
    );
}

/// The root exits while a worker's callback polls.
#[test]
fn a_worker_polling_in_its_callback_ends_when_the_root_exits() {
    if in_bounded_child("a_worker_polling_in_its_callback_ends_when_the_root_exits") {
        run_mode("worker-polls", "main exiting\n");
    }
}

/// A worker exits while the root's callback polls. The root is never marked
/// cancelled; it sees only the group's committed exit status.
#[test]
fn the_root_polling_in_its_callback_ends_when_a_worker_exits() {
    if in_bounded_child("the_root_polling_in_its_callback_ends_when_a_worker_exits") {
        run_mode("main-polls", "worker exiting\n");
    }
}
