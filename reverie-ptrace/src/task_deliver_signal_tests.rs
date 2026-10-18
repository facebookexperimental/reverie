/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::deliver_signal` at a real SIGUSR1 signal-delivery stop of a real
//! child, with the callback state set up as `report_signal` sets it:
//! - unavailable outside a signal callback, for another signal, without a
//!   siginfo record, in a frame-mode event, after an injection left a stop
//!   that is not a signal-delivery stop, and on a tracer thread a seccomp
//!   filter may restrict;
//! - unavailable for a delivery that leaves its own signal unchecked, and
//!   for a signal the kernel's current mask blocks;
//! - accepted at the signal's own stop (and with the held flag set, which
//!   changes no check), and refused a second time in one callback;
//! - voided by an injection and by a register write;
//! - a mismatch for each mutated field, as the negative controls, after
//!   which the callback approves nothing more;
//! - `Gone` for a dead thread.
//!
//! Each cell runs in a new libtest process, as `task_set_blocked_signals_tests.rs`
//! does: a real seccomp filter is confined to that cell's ptracer thread, and
//! the shared runner stays unfiltered.

#![cfg(target_arch = "x86_64")]

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use reverie::Guest;
use reverie::Interruption;
use reverie::Pid;
use reverie::SignalAction;
use reverie::SignalDelivery;
use reverie::SignalDeliveryField;
use reverie::SignalDeliveryOutcome;
use reverie::SignalDeliveryUnavailable;
use reverie::Subscription;
use reverie::signal_set_bit;
use safeptrace::AnySignal;
use safeptrace::ExitStatus;
use safeptrace::Stopped;
use safeptrace::Wait;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use super::SignalApproval;
use super::TracedTask;
use super::TracedTaskOptions;
use super::approval_violation;

const CELL_ENV: &str = "REVERIE_DELIVER_SIGNAL_CELL";
const TEST_NAME: &str = "task::deliver_signal_tests::deliver_signal_at_a_real_delivery_stop";

#[test]
fn deliver_signal_at_a_real_delivery_stop() {
    if let Ok(cell) = std::env::var(CELL_ENV) {
        assert!(cell == "stops" || cell == "seccomp");
        run_cell(cell == "seccomp");
        println!("DELIVER_SIGNAL_CELL_PASSED {cell}");
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
                eprintln!("deliver_signal cell {cell} exceeded its 15s bound: {status}");
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
        println!("deliver_signal cell {cell}, status {status}:\n{stdout}");
        eprintln!("{}", String::from_utf8_lossy(&stderr));
        all_passed &= status.success()
            && stdout
                .lines()
                .filter(|line| *line == format!("DELIVER_SIGNAL_CELL_PASSED {cell}"))
                .count()
                == 1;
    }
    assert!(all_passed, "both cells must pass");
}

/// An approval is enforced when the callback returns: voided by a later
/// injection, or broken by a verdict that is not the approved signal.
#[test]
fn an_approval_holds_only_for_its_own_signal_and_stop() {
    let usr1 = AnySignal::new(libc::SIGUSR1).unwrap();
    let usr2 = AnySignal::new(libc::SIGUSR2).unwrap();
    let kept = SignalApproval {
        signal: usr1,
        voided: false,
    };
    assert_eq!(approval_violation(kept, Some(usr1)), None);
    assert!(approval_violation(kept, Some(usr2)).is_some());
    assert!(approval_violation(kept, None).is_some());
    let voided = SignalApproval {
        voided: true,
        ..kept
    };
    assert!(approval_violation(voided, Some(usr1)).is_some());
    assert!(approval_violation(voided, None).is_some());
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
        // The child blocks SIGINT, so the masks are not empty, then raises
        // SIGUSR1, which stops it at that signal's delivery stop at the exit
        // of its tgkill.
        // SAFETY: async-signal-safe calls in the forked child.
        unsafe {
            let mut set = std::mem::zeroed::<libc::sigset_t>();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0
                || libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0
                || libc::raise(libc::SIGSTOP) != 0
                || libc::raise(libc::SIGUSR1) != 0
            {
                libc::_exit(2);
            }
            libc::_exit(0);
        }
    }
    let _child = Child(raw);
    let mut status = 0;
    // SAFETY: waitpid and ptrace on our own child with a local status.
    unsafe {
        assert_eq!(libc::waitpid(raw, &mut status, 0), raw);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        assert_eq!(libc::ptrace(libc::PTRACE_CONT, raw, 0, 0), 0);
        assert_eq!(libc::waitpid(raw, &mut status, 0), raw);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGUSR1);
    }
    let pid = Pid::from_raw(raw);
    let original = Stopped::new_unchecked_on_ptracer_thread(pid).unwrap();
    // Taken before any filter, as `TakenSignal::at_stop` takes it.
    let record = original.getsiginfo_bytes().unwrap();
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

    let usr1 = AnySignal::new(libc::SIGUSR1).unwrap();
    let mask = original.getsigmask().unwrap();
    assert_eq!(
        mask & signal_set_bit(libc::SIGINT),
        signal_set_bit(libc::SIGINT)
    );
    let regs = original.getregs().unwrap();
    assert_eq!(regs.orig_rax as i64, libc::SYS_tgkill);
    let action = SignalAction {
        handler: 0x40_1000,
        flags: libc::SA_RESTART as u64,
        restorer: 0,
        mask: signal_set_bit(libc::SIGUSR2),
    };
    let good = SignalDelivery {
        signal: libc::SIGUSR1,
        action,
        frame_mask: mask,
        current_mask: mask,
        handler_mask: action.handler_mask(mask, libc::SIGUSR1),
        unchecked_mask: 0,
        interruption: Interruption::Return {
            syscall: libc::SYS_tgkill,
            result: regs.rax as i64,
        },
    };
    let deliver = |traced: &mut TracedTask<()>, d: SignalDelivery| {
        futures::executor::block_on(traced.deliver_signal(d))
    };
    let unavailable = SignalDeliveryOutcome::Unavailable;

    if seccomp {
        traced.in_signal_callback = true;
        traced.reported_signal = Some((usr1, Some(record)));
        assert_eq!(
            deliver(&mut traced, good),
            unavailable(SignalDeliveryUnavailable::TracerFiltered)
        );
        assert!(traced.signal_approval.is_none());
        return;
    }

    // Outside any signal callback.
    assert_eq!(
        deliver(&mut traced, good),
        unavailable(SignalDeliveryUnavailable::NotInSignalCallback)
    );

    traced.in_signal_callback = true;
    traced.reported_signal = Some((usr1, Some(record)));

    // Another signal than the reported one.
    assert_eq!(
        deliver(
            &mut traced,
            SignalDelivery {
                signal: libc::SIGUSR2,
                ..good
            }
        ),
        unavailable(SignalDeliveryUnavailable::NotTheReportedSignal {
            reported: libc::SIGUSR1
        })
    );

    // No record of how the signal was taken.
    traced.reported_signal = Some((usr1, None));
    assert_eq!(
        deliver(&mut traced, good),
        unavailable(SignalDeliveryUnavailable::NoSignalRecord)
    );
    traced.reported_signal = Some((usr1, Some(record)));

    // A frame-mode event.
    traced.injected_syscall_frame = Some(0x7000_0000);
    assert_eq!(
        deliver(&mut traced, good),
        unavailable(SignalDeliveryUnavailable::FrameModeStop)
    );
    traced.injected_syscall_frame = None;

    // An injection left the thread at a stop that is not a signal-delivery
    // stop.
    traced.latest_injection_stop = Some(None);
    assert_eq!(
        deliver(&mut traced, good),
        unavailable(SignalDeliveryUnavailable::NotADeliveryStop)
    );
    traced.latest_injection_stop = None;
    assert!(traced.signal_approval.is_none(), "nothing was approved");

    // The delivery leaves its own signal unchecked.
    assert_eq!(
        deliver(
            &mut traced,
            SignalDelivery {
                unchecked_mask: signal_set_bit(libc::SIGUSR1),
                ..good
            }
        ),
        unavailable(SignalDeliveryUnavailable::UncheckedSignal)
    );

    // The kernel's current mask blocks the reported signal (SIGINT, which
    // the child blocks): resuming with it would requeue it.
    let int = AnySignal::new(libc::SIGINT).unwrap();
    traced.reported_signal = Some((int, Some(record)));
    assert_eq!(
        deliver(
            &mut traced,
            SignalDelivery {
                signal: libc::SIGINT,
                handler_mask: action.handler_mask(mask, libc::SIGINT),
                ..good
            }
        ),
        unavailable(SignalDeliveryUnavailable::BlockedAtResume)
    );
    traced.reported_signal = Some((usr1, Some(record)));
    assert!(traced.signal_approval.is_none(), "nothing was approved");

    // The negative controls: each mutated field is a mismatch naming it, and
    // approves nothing. After a mismatch the callback can approve nothing
    // more, so each control starts a new callback.
    let mismatch = |traced: &mut TracedTask<()>, d: SignalDelivery| {
        let field = match deliver(traced, d) {
            SignalDeliveryOutcome::Mismatch(mismatch) => mismatch.field,
            outcome => panic!("expected a mismatch, got {outcome:?}"),
        };
        assert_eq!(
            deliver(traced, good),
            unavailable(SignalDeliveryUnavailable::AfterMismatch),
            "a mismatch ends the callback's approvals"
        );
        traced.signal_delivery_mismatched = false;
        field
    };
    let unblocked = mask & !signal_set_bit(libc::SIGINT);
    assert_eq!(
        mismatch(
            &mut traced,
            SignalDelivery {
                frame_mask: unblocked,
                ..good
            }
        ),
        SignalDeliveryField::FrameMask
    );
    assert_eq!(
        mismatch(
            &mut traced,
            SignalDelivery {
                current_mask: unblocked,
                handler_mask: action.handler_mask(unblocked, libc::SIGUSR1),
                ..good
            }
        ),
        SignalDeliveryField::CurrentMask
    );
    assert_eq!(
        mismatch(
            &mut traced,
            SignalDelivery {
                handler_mask: mask,
                ..good
            }
        ),
        SignalDeliveryField::HandlerMask
    );
    assert_eq!(
        mismatch(
            &mut traced,
            SignalDelivery {
                interruption: Interruption::NotInSyscall,
                ..good
            }
        ),
        SignalDeliveryField::InterruptedSyscall
    );
    assert_eq!(
        mismatch(
            &mut traced,
            SignalDelivery {
                interruption: Interruption::Return {
                    syscall: libc::SYS_tgkill,
                    result: -514,
                },
                ..good
            }
        ),
        SignalDeliveryField::InterruptedResult
    );
    assert!(traced.signal_approval.is_none(), "no mismatch approves");
    assert_eq!(
        original.getsigmask().unwrap(),
        mask,
        "no check changes the mask"
    );

    // The positive control at the signal's own delivery stop, then a second
    // approval in the same callback.
    assert_eq!(deliver(&mut traced, good), SignalDeliveryOutcome::Accepted);
    let approval = traced.signal_approval.unwrap();
    assert_eq!(approval.signal, usr1);
    assert!(!approval.voided);
    assert_eq!(
        deliver(&mut traced, good),
        unavailable(SignalDeliveryUnavailable::AlreadyApproved)
    );
    // A later injection voids it.
    traced
        .note_injection_stop(&Wait::Exited(pid, ExitStatus::Exited(0)))
        .unwrap();
    assert!(traced.signal_approval.unwrap().voided);

    // So does a register write, even of the same registers.
    traced.signal_approval = None;
    assert_eq!(deliver(&mut traced, good), SignalDeliveryOutcome::Accepted);
    futures::executor::block_on(traced.set_regs(regs)).unwrap();
    assert!(traced.signal_approval.unwrap().voided);

    // A held report runs the same checks at its own stop; the held flag
    // changes none of them. The end-to-end held case is
    // `tests/deliver_signal.rs`'s `a_held_signal_is_approved_at_its_report`.
    traced.signal_approval = None;
    traced.in_held_signal_callback = true;
    assert_eq!(deliver(&mut traced, good), SignalDeliveryOutcome::Accepted);
    traced.signal_approval = None;
    traced.in_held_signal_callback = false;

    // A dead thread: a fatal signal is pending, so every ptrace request on it
    // fails with ESRCH.
    // SAFETY: kill takes plain values; the child is ours.
    assert_eq!(unsafe { libc::kill(raw, libc::SIGKILL) }, 0);
    assert_eq!(
        deliver(&mut traced, good),
        unavailable(SignalDeliveryUnavailable::Gone)
    );
}
