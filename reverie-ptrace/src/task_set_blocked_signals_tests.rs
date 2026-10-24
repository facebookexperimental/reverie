/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::set_blocked_signals` at real ptrace stops of a real child, through
//! the call site's own wiring: refused outside a syscall callback, in a
//! frame-mode event, in a signal callback and on a tracer thread a seccomp
//! filter may restrict, each with the mask unchanged; `Gone` for a dead
//! thread; and, as the positive control, an exact block and restore.
//!
//! Each cell runs in a new libtest process, as `stack_owner_tests.rs` does: a
//! real seccomp filter is confined to that cell's ptracer thread, and the
//! shared runner stays unfiltered.

#![cfg(target_arch = "x86_64")]

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use reverie::Guest;
use reverie::MaskChangeRefused;
use reverie::Pid;
use reverie::Subscription;
use safeptrace::Stopped;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use super::NEVER_SHIELDED;
use super::TracedTask;
use super::TracedTaskOptions;

const CELL_ENV: &str = "REVERIE_SET_BLOCKED_SIGNALS_CELL";
const TEST_NAME: &str = "task::set_blocked_signals_tests::set_blocked_signals_at_real_ptrace_stops";

#[test]
fn set_blocked_signals_at_real_ptrace_stops() {
    if let Ok(cell) = std::env::var(CELL_ENV) {
        assert!(cell == "stops" || cell == "seccomp");
        run_cell(cell == "seccomp");
        println!("SET_BLOCKED_SIGNALS_CELL_PASSED {cell}");
        return;
    }
    let mut all_passed = true;
    for cell in ["stops", "seccomp"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([TEST_NAME, "--exact", "--nocapture"])
            .env(CELL_ENV, cell)
            .env("RUST_LOG", "warn")
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                // Only this freshly spawned owned process group is signaled.
                // SAFETY: kill takes plain values.
                assert_eq!(
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                    0
                );
                let status = child.wait().unwrap();
                eprintln!("set_blocked_signals cell {cell} exceeded its 15s bound: {status}");
                break status;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(65537)
            .read_to_end(&mut stdout)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .take(65537)
            .read_to_end(&mut stderr)
            .unwrap();
        let stdout = String::from_utf8_lossy(&stdout);
        println!("set_blocked_signals cell {cell}, status {status}:\n{stdout}");
        eprintln!("{}", String::from_utf8_lossy(&stderr));
        all_passed &= status.success()
            && stdout
                .lines()
                .filter(|line| *line == format!("SET_BLOCKED_SIGNALS_CELL_PASSED {cell}"))
                .count()
                == 1;
    }
    assert!(all_passed, "both cells must pass");
}

/// Reaps the traced child on every exit from the cell.
struct Child(libc::pid_t);

impl Drop for Child {
    fn drop(&mut self) {
        if self.0 > 0 {
            // SAFETY: kill and waitpid take plain values and a local status.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                loop {
                    let mut status = 0;
                    let actual = libc::waitpid(self.0, &mut status, libc::__WALL);
                    if actual == self.0 && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                        break;
                    }
                    if actual < 0 && *libc::__errno_location() != libc::EINTR {
                        break;
                    }
                }
            }
        }
    }
}

fn run_cell(seccomp: bool) {
    // The alarm is confined to this re-executed cell, never the shared runner.
    // SAFETY: alarm takes a plain value.
    unsafe { libc::alarm(10) };
    // SAFETY: the child only calls async-signal-safe functions before _exit.
    let raw = unsafe { libc::fork() };
    assert!(raw >= 0);
    if raw == 0 {
        // SAFETY: async-signal-safe calls in the forked child.
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 || libc::raise(libc::SIGSTOP) != 0 {
                libc::_exit(2);
            }
            libc::_exit(0);
        }
    }
    let _child = Child(raw);
    let mut status = 0;
    // SAFETY: waitpid on our own child with a local status.
    assert_eq!(unsafe { libc::waitpid(raw, &mut status, 0) }, raw);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    if seccomp {
        // A filter that allows every call: it restricts nothing, but the
        // tracer thread is now seccomp-filtered (procfs `Seccomp: 2`).
        let allow = [libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        }];
        let program = libc::sock_fprog {
            len: allow.len() as u16,
            filter: allow.as_ptr().cast_mut(),
        };
        // SAFETY: prctl with a valid filter program.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(libc::prctl(libc::PR_SET_SECCOMP, 2, &program), 0);
        }
    }
    let pid = Pid::from_raw(raw);
    let original = Stopped::new_unchecked_on_ptracer_thread(pid).unwrap();
    let events = Subscription::none();
    let (orphanage, _orphans) = mpsc::channel(1);
    let (daemon_kill, _) = broadcast::channel(1);
    let mut traced = TracedTask::<()>::new(
        pid,
        (),
        Arc::new(()),
        TracedTaskOptions {
            command_bootstrap: false,
            events: &events,
            injected_syscall_trap: None,
            backend_stats: None,
            final_resume_signal_for_test: None,
            pre_syscall_for_test: None,
            preinit_point_for_test: None,
        },
        orphanage,
        daemon_kill,
        None,
    );
    traced.ptracer_waits.bind_stopped(&original);
    let mask = || original.getsigmask().unwrap();
    let set = |traced: &mut TracedTask<()>, mask: u64| {
        futures::executor::block_on(traced.set_blocked_signals(mask))
    };
    let before = mask();

    if seccomp {
        traced.in_syscall_callback = true;
        assert_eq!(set(&mut traced, !0), Err(MaskChangeRefused::Unsupported));
        assert_eq!(
            mask(),
            before,
            "a seccomp-filtered tracer thread changes nothing"
        );
        return;
    }

    // Outside any callback.
    assert_eq!(set(&mut traced, !0), Err(MaskChangeRefused::Unsupported));
    assert_eq!(mask(), before);

    traced.in_syscall_callback = true;

    // A frame-mode event.
    traced.injected_syscall_frame = Some(0x7000_0000);
    assert_eq!(set(&mut traced, !0), Err(MaskChangeRefused::Unsupported));
    assert_eq!(mask(), before, "a frame-mode event changes nothing");
    traced.injected_syscall_frame = None;

    // A signal callback, delivery-stop or held.
    traced.in_signal_callback = true;
    assert_eq!(set(&mut traced, !0), Err(MaskChangeRefused::Unsupported));
    assert_eq!(mask(), before, "a signal callback changes nothing");
    traced.in_signal_callback = false;
    traced.in_held_signal_callback = true;
    assert_eq!(set(&mut traced, !0), Err(MaskChangeRefused::Unsupported));
    assert_eq!(mask(), before, "a held-signal callback changes nothing");
    traced.in_held_signal_callback = false;

    // The positive control: an exact block and restore.
    let full = !NEVER_SHIELDED | (before & NEVER_SHIELDED);
    assert_eq!(set(&mut traced, !0), Ok(before));
    assert_eq!(mask(), full);
    assert_eq!(set(&mut traced, before), Ok(full));
    assert_eq!(mask(), before);

    // A dead thread: a fatal signal is pending, so every ptrace request on it
    // fails with ESRCH.
    // SAFETY: kill takes plain values; the child is ours.
    assert_eq!(unsafe { libc::kill(raw, libc::SIGKILL) }, 0);
    assert_eq!(set(&mut traced, !0), Err(MaskChangeRefused::Gone));
}
