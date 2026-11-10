/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! What a thread does in the gap between another thread's committed group
//! exit and this backend's publication of it, and after an exec cancels a
//! worker whose signal hook is still running.
//!
//! LinuxEmu commits a group exit when the exiting thread's exit is taken;
//! this backend publishes it, which ends every other thread at its run loop's
//! next iteration, only after the exiting thread's own bookkeeping. Linux's
//! get_signal takes a group exit before every dequeue, a fault's signal
//! included, under siglock: a thread that reaches a signal selection in the
//! gap must find the commit there, select nothing and end before it runs
//! another guest instruction. A worker held in the gap (see
//! `group_exit_publication_gap`) lets the tests put the other thread there,
//! at the one selection each test is about; the worker commits only once the
//! root has passed every earlier one (`guarded_selection_observation` records
//! which selection found the commit):
//! - `a_selection_in_the_gap_ends_the_thread_before_it_runs_on`: the root's
//!   call that unblocks a pending SIGUSR1 has run, and its return's dequeue
//!   finds the commit;
//! - `a_fault_in_the_gap_ends_the_thread_before_its_handler`: the root's fault
//!   is held at its admission, which then finds the commit.
//!
//! `an_exec_cancelled_worker_whose_hook_returns_a_fatal_signal_leaves_the_exec_whole`:
//! Linux's do_group_exit starts no group exit while another thread's exec is
//! under way (group_exec_task), so a worker's fatal signal that commits after
//! the root's exec cancelled the worker must not end the exec's process.
//!
//! Each test runs in a child process with a deadline, so a regression fails
//! instead of hanging.

use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Errno;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Signal;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;

use super::*;

const PROGRAM: &str = r#"#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
/* The Tool holds these getpid calls until the moment each test needs. */
#define MARKER 0x67617021L
#define WORKER_MARKER 0x67617022L
static pid_t root_tid;
static void say(const char *text) {
  if (write(1, text, strlen(text)) < 0) _exit(9);
}
static void on_usr1(int signo) {
  (void)signo;
  say("handler\n");
}
static void on_segv(int signo) {
  (void)signo;
  say("segv handler\n");
  _exit(7);
}
static void *signal_then_exit(void *unused) {
  (void)unused;
  syscall(SYS_tgkill, getpid(), root_tid, SIGUSR1);
  syscall(SYS_getpid, WORKER_MARKER);
  syscall(SYS_exit_group, 42);
  return NULL;
}
static void *exit_after_marker(void *unused) {
  (void)unused;
  syscall(SYS_getpid, WORKER_MARKER);
  syscall(SYS_exit_group, 42);
  return NULL;
}
static void *terminate_self(void *unused) {
  (void)unused;
  syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGTERM);
  for (;;) syscall(SYS_sched_yield);
  return NULL;
}
int main(int argc, char **argv) {
  pthread_t thread;
  root_tid = (pid_t)syscall(SYS_gettid);
  if (argc != 2) return 2;
  if (strcmp(argv[1], "signal") == 0) {
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &usr1, NULL)) return 3;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    if (sigaction(SIGUSR1, &action, NULL)) return 3;
    if (pthread_create(&thread, NULL, signal_then_exit, NULL)) return 3;
    /* The Tool holds this call's return until the worker has committed. */
    sigprocmask(SIG_UNBLOCK, &usr1, NULL);
    say("root continued\n");
    for (;;) syscall(SYS_sched_yield);
  }
  if (strcmp(argv[1], "fault") == 0) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_segv;
    if (sigaction(SIGSEGV, &action, NULL)) return 4;
    if (pthread_create(&thread, NULL, exit_after_marker, NULL)) return 4;
    /* The test holds this fault at its admission until the worker has
       committed. */
    *(volatile int *)16 = 1;
    say("root continued\n");
    for (;;) syscall(SYS_sched_yield);
  }
  if (strcmp(argv[1], "exec") == 0) {
    if (pthread_create(&thread, NULL, terminate_self, NULL)) return 5;
    syscall(SYS_getpid, MARKER);
    char *child_argv[] = {argv[0], "child", NULL};
    execv(argv[0], child_argv);
    say("exec failed\n");
    return 5;
  }
  if (strcmp(argv[1], "child") == 0) {
    pid_t child = fork();
    if (child == 0) _exit(0);
    if (child < 0) {
      printf("fork failed %d\n", errno);
      return 6;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 6;
    printf("fork ok %d\n", WEXITSTATUS(status));
    return 0;
  }
  return 2;
}
"#;

const MARKER: u64 = 0x6761_7021;
const WORKER_MARKER: u64 = 0x6761_7022;

/// Which test runs, in this (child) process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Signal,
    Fault,
    Exec,
}

static MODE: Mutex<Option<Mode>> = Mutex::new(None);
/// Every signal hook, in order.
static HOOKS: Mutex<Vec<i32>> = Mutex::new(Vec::new());
/// Every `on_exit_thread`, as (tid, status).
static THREAD_EXITS: Mutex<Vec<(i32, ExitStatus)>> = Mutex::new(Vec::new());
/// Whether the worker's SIGTERM hook has begun (exec mode).
static HOOK_BEGUN: AtomicBool = AtomicBool::new(false);
/// Whether the root's unblocking call has run (signal mode).
static ROOT_UNBLOCKED: AtomicBool = AtomicBool::new(false);

fn mode() -> Mode {
    MODE.lock().unwrap().expect("a test mode")
}

/// Waits for `ready`, for at most ten seconds.
fn wait_for(what: &str, ready: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(std::time::Instant::now() < deadline, "never: {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[derive(Default)]
struct GapGlobal;

#[reverie::global_tool]
impl GlobalTool for GapGlobal {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, _request: ()) {}
}

/// Holds the worker's marker getpid until the root's unblocking call has run
/// (signal mode) or the root's fault is held at its admission (fault mode);
/// holds that call's return until the worker is held in the publication gap;
/// holds the root's marker getpid until the worker's SIGTERM hook has begun,
/// and that hook until the root's exec has cancelled its workers (exec mode);
/// records every signal hook; delivers every signal.
#[derive(Default)]
struct GapTool;

#[reverie::tool]
impl Tool for GapTool {
    type GlobalState = GapGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> std::result::Result<i64, reverie::Error> {
        let args = syscall.into_parts().1;
        match syscall {
            Syscall::Getpid(_) if args.arg0 as u64 == MARKER => {
                assert_eq!(mode(), Mode::Exec);
                wait_for("the worker's SIGTERM hook", || {
                    HOOK_BEGUN.load(Ordering::SeqCst)
                });
                Ok(i64::from(guest.pid().as_raw()))
            }
            Syscall::Getpid(_) if args.arg0 as u64 == WORKER_MARKER => {
                match mode() {
                    Mode::Signal => wait_for("the root's unblocking call", || {
                        ROOT_UNBLOCKED.load(Ordering::SeqCst)
                    }),
                    Mode::Fault => assert!(
                        guarded_selection_observation::wait_fault_reached(Duration::from_secs(10)),
                        "the root's fault never reached its admission"
                    ),
                    Mode::Exec => unreachable!("no worker marker in exec mode"),
                }
                Ok(i64::from(guest.pid().as_raw()))
            }
            Syscall::RtSigprocmask(_)
                if mode() == Mode::Signal
                    && args.arg0 == libc::SIG_UNBLOCK as usize
                    && guest.tid() == guest.pid() =>
            {
                // The root's call that unblocks SIGUSR1, not glibc's own
                // unblocking of its internal signals: the call runs, and its
                // return, where the selection finds the commit, waits until
                // the worker is held after it.
                let set: u64 = guest
                    .memory()
                    .read_value(Addr::<u64>::from_raw(args.arg1).ok_or(Errno::EFAULT)?)?;
                if set & (1 << (libc::SIGUSR1 - 1)) == 0 {
                    guest.tail_inject(syscall).await
                } else {
                    let result = guest.inject(syscall).await;
                    ROOT_UNBLOCKED.store(true, Ordering::SeqCst);
                    assert!(
                        group_exit_publication_gap::wait_held(Duration::from_secs(10)),
                        "the worker never reached the publication gap"
                    );
                    Ok(result?)
                }
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        signal: Signal,
    ) -> std::result::Result<Option<Signal>, Errno> {
        HOOKS.lock().unwrap().push(signal as i32);
        if mode() == Mode::Exec && signal == Signal::SIGTERM {
            HOOK_BEGUN.store(true, Ordering::SeqCst);
            assert!(
                exec_cancellation_observation::wait_cancelled(Duration::from_secs(10)),
                "the root's exec never cancelled its workers"
            );
        }
        Ok(Some(signal))
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
    if std::env::var("REVERIE_GROUP_EXIT_GAP_CHILD").as_deref() == Ok(name.as_str()) {
        return true;
    }
    let output = Command::new("timeout")
        .args(["--kill-after=2s", "60s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env("REVERIE_GROUP_EXIT_GAP_CHILD", &name)
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

/// Builds the program and runs it in `mode` under `GapTool`; returns the
/// guest's exit status, stdout and stderr.
fn run(mode: Mode) -> (i32, String, String) {
    *MODE.lock().unwrap() = Some(mode);
    let directory = std::env::temp_dir().join(format!(
        "reverie-group-exit-gap-{}-{mode:?}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("group-exit-gap.c");
    let executable = directory.join("group-exit-gap");
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
    let argument = match mode {
        Mode::Signal => "signal",
        Mode::Fault => "fault",
        Mode::Exec => "exec",
    };
    let mut backend = KvmBackend::new(256 * 1024 * 1024).expect("this test requires /dev/kvm");
    backend
        .install_static_elf_with_context(&image, &[program, argument], &[], &directory)
        .unwrap();
    let result = futures::executor::block_on(backend.run_static_elf_with_tool::<GapTool>((), true));
    let _ = std::fs::remove_dir_all(&directory);
    let (_, status, stdout, stderr) = result.unwrap();
    (
        status,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// The root's call that unblocks a pending SIGUSR1 has run, and the worker
/// that sent it commits its exit_group(42) and is held before the
/// publication. The dequeue at the call's return, with SIGUSR1 eligible,
/// finds the commit, selects nothing and publishes it, and the root ends at
/// its run loop's next iteration: no SIGUSR1 hook or handler, and no guest
/// instruction after that return (it would write "root continued"). The
/// held worker is released by the root's publication, well before its
/// deadline.
#[test]
fn a_selection_in_the_gap_ends_the_thread_before_it_runs_on() {
    if !in_bounded_child("a_selection_in_the_gap_ends_the_thread_before_it_runs_on") {
        return;
    }
    group_exit_publication_gap::arm();
    let (status, stdout, stderr) = run(Mode::Signal);
    assert_eq!((status, stdout.as_str()), (42, ""), "stderr={stderr}");
    assert_eq!(*HOOKS.lock().unwrap(), Vec::<i32>::new(), "no signal hook");
    assert_eq!(
        guarded_selection_observation::found(),
        [guarded_selection_observation::Site::Dequeue { eligible: true }],
        "the unblocking call's return found the commit, with SIGUSR1 eligible"
    );
    assert!(
        group_exit_publication_gap::released_by_publication(),
        "the root published the committed exit before the worker's deadline"
    );
    let exits = THREAD_EXITS.lock().unwrap().clone();
    assert_eq!(
        exits.iter().map(|&(_, status)| status).collect::<Vec<_>>(),
        [ExitStatus::Exited(42); 2],
        "{exits:?}"
    );
}

/// The root's fault is held at its admission while the worker commits its
/// exit_group(42) and is held before the publication; the worker's commit
/// waits for that hold, so no earlier selection of the root can find it. The
/// fault's admission finds the commit: no SIGSEGV hook, no handler (it would
/// write "segv handler"), and the root ends with the group's status.
#[test]
fn a_fault_in_the_gap_ends_the_thread_before_its_handler() {
    if !in_bounded_child("a_fault_in_the_gap_ends_the_thread_before_its_handler") {
        return;
    }
    group_exit_publication_gap::arm();
    guarded_selection_observation::arm_fault_hold();
    let (status, stdout, stderr) = run(Mode::Fault);
    assert_eq!((status, stdout.as_str()), (42, ""), "stderr={stderr}");
    assert_eq!(*HOOKS.lock().unwrap(), Vec::<i32>::new(), "no signal hook");
    assert_eq!(
        guarded_selection_observation::fault_admissions(),
        [true],
        "the fault's admission ran once and found the commit"
    );
    assert_eq!(
        guarded_selection_observation::found(),
        [guarded_selection_observation::Site::FaultAdmission]
    );
    assert!(
        group_exit_publication_gap::released_by_publication(),
        "the root published the committed exit before the worker's deadline"
    );
}

/// A worker's SIGTERM hook (default action) begins; the root then execs, and
/// once the exec has cancelled the worker the hook returns SIGTERM. The
/// worker's fatal signal commits after the exec froze its death, which
/// Linux's do_group_exit turns into the thread's exit with status 0, no
/// group exit. So the exec completes and its replacement image can fork.
#[test]
fn an_exec_cancelled_worker_whose_hook_returns_a_fatal_signal_leaves_the_exec_whole() {
    if !in_bounded_child(
        "an_exec_cancelled_worker_whose_hook_returns_a_fatal_signal_leaves_the_exec_whole",
    ) {
        return;
    }
    let (status, stdout, stderr) = run(Mode::Exec);
    assert_eq!(
        (status, stdout.as_str()),
        (0, "fork ok 0\n"),
        "stderr={stderr}"
    );
    assert_eq!(*HOOKS.lock().unwrap(), [libc::SIGTERM], "the worker's hook");
    let exits = THREAD_EXITS.lock().unwrap().clone();
    assert!(
        exits.contains(&(2, ExitStatus::Exited(0))),
        "the worker exits with status 0: {exits:?}"
    );
}
