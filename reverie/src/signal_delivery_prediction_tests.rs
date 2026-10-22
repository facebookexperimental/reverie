/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! [`predict_deliveries`]: pure rows, then rows checked against a native
//! child, which queues the same instances, unblocks them, and reports what
//! the kernel did.
//!
//! The mutation of the prediction each row catches (native rows unless
//! noted):
//! - synchronous first dropped: `sigtrap_before_sighup`;
//! - shared before private: `private_then_shared_under_sa_nodefer`;
//! - `SA_NODEFER` or `SA_RESETHAND` ignored:
//!   `private_then_shared_under_sa_nodefer` and `sa_resethand_makes_the_second_instance_fatal`;
//! - `sa_mask` ignored: `a_caught_signal_before_a_fatal_one_its_mask_blocks`;
//! - SIGKILL treated as an ordinary signal:
//!   `a_pending_sigkill_is_refused_as_a_group_exit_in_progress` (a pure row:
//!   a native child dies at its own SIGKILL's send);
//! - the death's core flag taken from the default action:
//!   `a_core_dumping_default_leaves_wcoredump_to_the_kernel`;
//! - a default stop treated as ignored: `a_default_sigtstp_ahead_of_sigxcpu_is_refused`.

use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use super::*;
use crate::ExitStatus;

const NODEFER: u64 = libc::SA_NODEFER as u64;
const RESETHAND: u64 = libc::SA_RESETHAND as u32 as u64;
/// A handler address; any value other than `SIG_DFL` (0) and `SIG_IGN` (1).
const HANDLER: u64 = 0x40_1000;

fn bits(signals: &[i32]) -> u64 {
    signals
        .iter()
        .fold(0, |set, &signal| set | signal_set_bit(signal))
}

fn caught(flags: u64, mask: u64) -> SignalAction {
    SignalAction {
        handler: HANDLER,
        flags,
        restorer: 0,
        mask,
    }
}

fn ignored() -> SignalAction {
    SignalAction {
        handler: SIG_IGN,
        ..SignalAction::default()
    }
}

fn actions(set: &[(i32, SignalAction)]) -> [SignalAction; 64] {
    let mut actions = [SignalAction::default(); 64];
    for &(signal, action) in set {
        actions[signal as usize - 1] = action;
    }
    actions
}

fn delivery(
    signal: i32,
    queue: SignalQueue,
    action: PredictedAction,
    mask: u64,
) -> PredictedDelivery {
    PredictedDelivery {
        signal,
        queue,
        action,
        mask,
    }
}

use PredictedAction::Caught;
use PredictedAction::Ignored;
use SignalQueue::Private;
use SignalQueue::Shared;

#[test]
fn nothing_deliverable_returns_under_the_mask_without_sigkill_and_sigstop() {
    let mask = bits(&[libc::SIGUSR1, libc::SIGKILL, libc::SIGSTOP]);
    let prediction = predict_deliveries(
        bits(&[libc::SIGUSR1]),
        bits(&[libc::SIGUSR1]),
        mask,
        &actions(&[]),
        false,
    );
    assert_eq!(
        prediction,
        DeliveryPrediction {
            deliveries: vec![],
            end: PredictionEnd::Return {
                mask: bits(&[libc::SIGUSR1]),
            },
        }
    );
}

#[test]
fn a_synchronous_signal_goes_first_within_a_queue_only() {
    let both = actions(&[(libc::SIGHUP, caught(0, 0)), (libc::SIGTRAP, caught(0, 0))]);
    let trap = bits(&[libc::SIGTRAP]);
    let hup = bits(&[libc::SIGHUP]);
    assert_eq!(
        predict_deliveries(trap | hup, 0, 0, &both, false).deliveries,
        vec![
            delivery(libc::SIGTRAP, Private, Caught, 0),
            delivery(libc::SIGHUP, Private, Caught, trap),
        ]
    );
    // The thread's own queue goes first, whatever the group's holds.
    assert_eq!(
        predict_deliveries(hup, trap, 0, &both, false).deliveries,
        vec![
            delivery(libc::SIGHUP, Private, Caught, 0),
            delivery(libc::SIGTRAP, Shared, Caught, hup),
        ]
    );
}

#[test]
fn the_handler_mask_holds_back_what_sa_mask_names() {
    let term = bits(&[libc::SIGTERM]);
    let usr1 = bits(&[libc::SIGUSR1]);
    let prediction = predict_deliveries(
        usr1 | term,
        0,
        0,
        &actions(&[(libc::SIGUSR1, caught(0, term))]),
        false,
    );
    assert_eq!(
        prediction,
        DeliveryPrediction {
            deliveries: vec![delivery(libc::SIGUSR1, Private, Caught, 0)],
            end: PredictionEnd::Return { mask: usr1 | term },
        }
    );
}

#[test]
fn one_signal_pending_in_both_queues() {
    let usr1 = bits(&[libc::SIGUSR1]);
    // Without SA_NODEFER the handler blocks the group's instance.
    let plain = predict_deliveries(
        usr1,
        usr1,
        0,
        &actions(&[(libc::SIGUSR1, caught(0, 0))]),
        false,
    );
    assert_eq!(
        plain.deliveries,
        vec![delivery(libc::SIGUSR1, Private, Caught, 0)]
    );
    assert_eq!(plain.end, PredictionEnd::Return { mask: usr1 });
    // SA_NODEFER takes it as well.
    let nodefer = predict_deliveries(
        usr1,
        usr1,
        0,
        &actions(&[(libc::SIGUSR1, caught(NODEFER, 0))]),
        false,
    );
    assert_eq!(
        nodefer.deliveries,
        vec![
            delivery(libc::SIGUSR1, Private, Caught, 0),
            delivery(libc::SIGUSR1, Shared, Caught, 0),
        ]
    );
    assert_eq!(nodefer.end, PredictionEnd::Return { mask: 0 });
    // SA_RESETHAND makes the second instance take the default, fatal.
    let reset = predict_deliveries(
        usr1,
        usr1,
        0,
        &actions(&[(libc::SIGUSR1, caught(NODEFER | RESETHAND, 0))]),
        false,
    );
    assert_eq!(
        reset.deliveries,
        vec![
            delivery(libc::SIGUSR1, Private, Caught, 0),
            delivery(
                libc::SIGUSR1,
                Shared,
                PredictedAction::Fatal { core_dump: false },
                0
            ),
        ]
    );
    assert_eq!(
        reset.end,
        PredictionEnd::Death(ExitStatus::Signaled(crate::Signal::SIGUSR1, false))
    );
}

#[test]
fn ignored_instances_are_discarded_and_the_order_goes_on() {
    let prediction = predict_deliveries(
        bits(&[libc::SIGHUP, libc::SIGCHLD, libc::SIGQUIT]),
        0,
        0,
        &actions(&[(libc::SIGHUP, ignored())]),
        false,
    );
    // SIGQUIT (3) comes before SIGCHLD (17), so SIGCHLD is never reached.
    assert_eq!(
        prediction,
        DeliveryPrediction {
            deliveries: vec![
                delivery(libc::SIGHUP, Private, Ignored, 0),
                delivery(
                    libc::SIGQUIT,
                    Private,
                    PredictedAction::Fatal { core_dump: true },
                    0
                ),
            ],
            end: PredictionEnd::Death(ExitStatus::Signaled(crate::Signal::SIGQUIT, false)),
        }
    );
    // A default-ignored signal is discarded too.
    let chld = predict_deliveries(
        bits(&[libc::SIGCHLD, libc::SIGURG]),
        0,
        0,
        &actions(&[]),
        false,
    );
    assert_eq!(
        chld.deliveries,
        vec![
            delivery(libc::SIGCHLD, Private, Ignored, 0),
            delivery(libc::SIGURG, Private, Ignored, 0),
        ]
    );
    assert_eq!(chld.end, PredictionEnd::Return { mask: 0 });
}

#[test]
fn a_default_stop_is_refused_and_a_handled_or_ignored_one_is_not() {
    let tstp = bits(&[libc::SIGTSTP]);
    assert_eq!(
        predict_deliveries(tstp, 0, 0, &actions(&[]), false),
        DeliveryPrediction {
            deliveries: vec![],
            end: PredictionEnd::Refuse(PredictionRefusal::Stop {
                signal: libc::SIGTSTP,
                queue: Private,
            }),
        }
    );
    assert_eq!(
        predict_deliveries(0, tstp, 0, &actions(&[(libc::SIGTSTP, ignored())]), false).deliveries,
        vec![delivery(libc::SIGTSTP, Shared, Ignored, 0)]
    );
    assert_eq!(
        predict_deliveries(
            tstp,
            0,
            0,
            &actions(&[(libc::SIGTSTP, caught(0, 0))]),
            false
        )
        .deliveries,
        vec![delivery(libc::SIGTSTP, Private, Caught, 0)]
    );
    // SIGSTOP cannot be blocked, ignored or caught.
    let stop = bits(&[libc::SIGSTOP]);
    assert_eq!(
        predict_deliveries(
            0,
            stop,
            stop,
            &actions(&[(libc::SIGSTOP, caught(0, 0))]),
            false
        )
        .end,
        PredictionEnd::Refuse(PredictionRefusal::Stop {
            signal: libc::SIGSTOP,
            queue: Shared,
        })
    );
}

/// A pending SIGKILL means the group's exit is already in progress, with an
/// exit code the bits cannot carry: refused by name, before any other
/// signal, whatever its number, queue, action or the mask. No delivery is
/// predicted, so no frame either. Mutation it catches: SIGKILL treated as an
/// ordinary signal.
#[test]
fn a_pending_sigkill_is_refused_as_a_group_exit_in_progress() {
    let kill = bits(&[libc::SIGKILL]);
    let hup = bits(&[libc::SIGHUP]);
    let refused = |queue| DeliveryPrediction {
        deliveries: vec![],
        end: PredictionEnd::Refuse(PredictionRefusal::GroupExitInProgress { queue }),
    };
    assert_eq!(
        predict_deliveries(hup | kill, 0, 0, &actions(&[]), false),
        refused(Private)
    );
    for signal in 1..=8 {
        if signal == libc::SIGKILL {
            continue;
        }
        let caught_first = actions(&[(signal, caught(0, 0))]);
        assert_eq!(
            predict_deliveries(bits(&[signal]), kill, 0, &caught_first, false),
            refused(Shared),
            "{signal}"
        );
    }
    // Whatever the mask and SIGKILL's recorded action say.
    assert_eq!(
        predict_deliveries(
            kill,
            0,
            kill,
            &actions(&[(libc::SIGKILL, ignored())]),
            false
        ),
        refused(Private)
    );
}

#[test]
fn a_realtime_signal_next_in_order_is_refused() {
    let rt = signal_set_bit(40);
    let usr1 = bits(&[libc::SIGUSR1]);
    let prediction = predict_deliveries(
        usr1 | rt,
        0,
        0,
        &actions(&[(libc::SIGUSR1, caught(0, 0))]),
        false,
    );
    assert_eq!(
        prediction,
        DeliveryPrediction {
            deliveries: vec![delivery(libc::SIGUSR1, Private, Caught, 0)],
            end: PredictionEnd::Refuse(PredictionRefusal::Realtime {
                signal: 40,
                queue: Private,
            }),
        }
    );
    // A blocked one is never next.
    assert_eq!(
        predict_deliveries(rt, rt, rt, &actions(&[]), false).end,
        PredictionEnd::Return { mask: rt }
    );
}

#[test]
fn phase1_marks_only_a_caught_sigalrm_in_its_window() {
    let alrm = bits(&[libc::SIGALRM]);
    let handled = actions(&[(libc::SIGALRM, caught(0, 0))]);
    assert_eq!(
        predict_deliveries(0, alrm, 0, &handled, true).deliveries,
        vec![delivery(
            libc::SIGALRM,
            Shared,
            PredictedAction::Phase1Alarm,
            0
        )]
    );
    assert_eq!(
        predict_deliveries(0, alrm, 0, &handled, false).deliveries,
        vec![delivery(libc::SIGALRM, Shared, Caught, 0)]
    );
    assert_eq!(
        predict_deliveries(0, alrm, 0, &actions(&[]), true).end,
        PredictionEnd::Death(ExitStatus::Signaled(crate::Signal::SIGALRM, false))
    );
}

// Native rows.

/// The descriptor a native child's handler writes its records to.
static RECORD_FD: AtomicI32 = AtomicI32::new(-1);

/// One record per handler run: the signal, its `si_code`, and the mask its
/// frame saved.
const RECORD: usize = 16;

extern "C" fn record_delivery(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: the kernel passes a valid siginfo and ucontext to an
    // SA_SIGINFO handler; the first word of `uc_sigmask` is the kernel's
    // mask.
    let (code, mask) = unsafe {
        let context = context as *const libc::ucontext_t;
        (
            (*info).si_code,
            std::ptr::read_unaligned(std::ptr::addr_of!((*context).uc_sigmask).cast::<u64>()),
        )
    };
    let mut record = [0_u8; RECORD];
    record[0..4].copy_from_slice(&signal.to_ne_bytes());
    record[4..8].copy_from_slice(&code.to_ne_bytes());
    record[8..16].copy_from_slice(&mask.to_ne_bytes());
    // SAFETY: write is async-signal-safe and the buffer is valid.
    unsafe {
        libc::write(
            RECORD_FD.load(Ordering::Relaxed),
            record.as_ptr().cast(),
            RECORD,
        )
    };
}

/// What a native child is set up with.
struct Row {
    /// Each signal's action: the default one is left as it is, `SIG_IGN`
    /// ignores the signal, and any other handler installs `record_delivery`
    /// with the action's flags and mask.
    actions: [SignalAction; 64],
    /// Queued to the thread itself (`tgkill`), so to its own queue.
    private: Vec<i32>,
    /// Queued to the process (`kill`), so to its group's queue.
    shared: Vec<i32>,
    /// The mask the child then sets, at whose return the kernel delivers.
    mask: u64,
}

/// How a native child ended, as `waitpid` saw it.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Exited(i32),
    /// Killed by the signal, with the wait status's `WCOREDUMP`.
    Killed(i32, bool),
    Stopped(i32),
}

/// What a native child reported.
#[derive(Debug)]
struct Observed {
    private: u64,
    shared: u64,
    /// Handler runs, in the order they ran: (signal, si_code, frame mask).
    runs: Vec<(i32, i32, u64)>,
    /// The child came back from the unblocking call.
    returned: bool,
    ended: Ended,
}

fn raw_set_mask(mask: u64) {
    // SAFETY: a valid 8-byte kernel mask and no old-mask pointer.
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &mask as *const u64,
            std::ptr::null_mut::<u64>(),
            8,
        )
    };
}

/// The native child: only async-signal-safe calls, since the test process
/// may have other threads.
unsafe fn native_child(row: &Row, fd: libc::c_int) -> ! {
    unsafe {
        // Its own process group, whose parent is in another group of the
        // same session: not orphaned, so a job-control stop stops it.
        libc::setpgid(0, 0);
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        // Not dumpable either, so that no core is written whatever the
        // host's core_pattern (a piped pattern ignores RLIMIT_CORE), and a
        // core-dumping default leaves WCOREDUMP clear (fs/coredump.c v6.12
        // line 557).
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // Set in this process, after the fork, for its handler.
        RECORD_FD.store(fd, Ordering::Relaxed);
        raw_set_mask(!0);
        for signal in 1..32 {
            let action = row.actions[signal as usize - 1];
            if signal == libc::SIGKILL
                || signal == libc::SIGSTOP
                || action == SignalAction::default()
            {
                continue;
            }
            let mut new: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut new.sa_mask);
            for blocked in 1..32 {
                if action.mask & signal_set_bit(blocked) != 0 {
                    libc::sigaddset(&mut new.sa_mask, blocked);
                }
            }
            if action.handler == SIG_IGN {
                new.sa_sigaction = libc::SIG_IGN;
            } else {
                new.sa_sigaction = record_delivery as *const () as usize;
                new.sa_flags = libc::SA_SIGINFO | action.flags as u32 as libc::c_int;
            }
            if libc::sigaction(signal, &new, std::ptr::null_mut()) != 0 {
                libc::_exit(120);
            }
        }
        let pid = libc::getpid();
        let tid = libc::syscall(libc::SYS_gettid) as libc::pid_t;
        for &signal in &row.private {
            libc::syscall(libc::SYS_tgkill, pid, tid, signal);
        }
        for &signal in &row.shared {
            libc::kill(pid, signal);
        }
        let mut status = [0_u8; 4096];
        let file = libc::open(c"/proc/self/status".as_ptr(), libc::O_RDONLY);
        let length = libc::read(file, status.as_mut_ptr().cast(), status.len());
        if file < 0 || length <= 0 {
            libc::_exit(121);
        }
        let length = length as u32;
        libc::write(fd, length.to_ne_bytes().as_ptr().cast(), 4);
        libc::write(fd, status.as_ptr().cast(), length as usize);
        raw_set_mask(row.mask);
        // Back from the unblocking call, after every handler ran.
        libc::write(fd, [0_u8; RECORD].as_ptr().cast(), RECORD);
        libc::_exit(0)
    }
}

fn status_field(status: &str, field: &str) -> u64 {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap_or_else(|| panic!("no {field} in {status}"));
    u64::from_str_radix(line.trim(), 16).unwrap()
}

fn run_native(row: &Row) -> Observed {
    let mut fds = [0; 2];
    // SAFETY: plain descriptor and process calls; the child runs only
    // async-signal-safe code before it exits.
    unsafe {
        assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC), 0);
        let child = libc::fork();
        assert!(child >= 0, "fork failed");
        if child == 0 {
            libc::close(fds[0]);
            native_child(row, fds[1]);
        }
        libc::close(fds[1]);
        // The reports fit in a pipe's minimum buffer, so the child never
        // waits on its writes; a stopped child keeps the pipe open, so it
        // is waited for first.
        let mut wait = 0;
        assert_eq!(libc::waitpid(child, &mut wait, libc::WUNTRACED), child);
        let ended = if libc::WIFSTOPPED(wait) {
            let stopped = libc::WSTOPSIG(wait);
            libc::kill(child, libc::SIGKILL);
            assert_eq!(libc::waitpid(child, &mut wait, 0), child);
            Ended::Stopped(stopped)
        } else if libc::WIFSIGNALED(wait) {
            Ended::Killed(libc::WTERMSIG(wait), libc::WCOREDUMP(wait))
        } else {
            Ended::Exited(libc::WEXITSTATUS(wait))
        };
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let n = libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len());
            assert!(n >= 0, "read failed");
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..n as usize]);
        }
        libc::close(fds[0]);
        let length = u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let status = std::str::from_utf8(&bytes[4..4 + length]).unwrap();
        let (private, shared) = (
            status_field(status, "SigPnd:"),
            status_field(status, "ShdPnd:"),
        );
        let mut runs = Vec::new();
        let mut returned = false;
        for record in bytes[4 + length..].chunks(RECORD) {
            let signal = i32::from_ne_bytes(record[0..4].try_into().unwrap());
            if signal == 0 {
                returned = true;
                continue;
            }
            runs.push((
                signal,
                i32::from_ne_bytes(record[4..8].try_into().unwrap()),
                u64::from_ne_bytes(record[8..16].try_into().unwrap()),
            ));
        }
        Observed {
            private,
            shared,
            runs,
            returned,
            ended,
        }
    }
}

/// Runs `row` natively and checks the prediction from what the child's
/// queues held against what the kernel did: the handlers that ran (the last
/// frame's first, each with its `si_code` naming the queue and its frame's
/// saved mask), and how the child ended. Returns the prediction.
fn check_against_native(row: &Row, phase1_window: bool) -> DeliveryPrediction {
    let observed = run_native(row);
    assert_eq!(
        (observed.private, observed.shared),
        (bits(&row.private), bits(&row.shared)),
        "the child queued what the row says: {observed:?}"
    );
    let prediction = predict_deliveries(
        observed.private,
        observed.shared,
        row.mask,
        &row.actions,
        phase1_window,
    );
    let caught_runs = |prediction: &DeliveryPrediction| -> Vec<(i32, i32, u64)> {
        let mut runs: Vec<_> = prediction
            .deliveries
            .iter()
            .filter(|d| matches!(d.action, Caught | PredictedAction::Phase1Alarm))
            .map(|d| {
                let code = match d.queue {
                    Private => libc::SI_TKILL,
                    Shared => libc::SI_USER,
                };
                (d.signal, code, d.mask)
            })
            .collect();
        // The last frame's handler runs first.
        runs.reverse();
        runs
    };
    let killed = |status: ExitStatus| match status {
        ExitStatus::Signaled(signal, core) => Ended::Killed(signal as i32, core),
        ExitStatus::SignaledRaw(signal, core) => Ended::Killed(signal, core),
        ExitStatus::Exited(code) => panic!("a predicted death exits with {code}"),
    };
    let (expected_runs, returned, expected_end) = match prediction.end {
        PredictionEnd::Return { .. } => {
            let runs = caught_runs(&prediction);
            let (mut private, mut shared) = (observed.private, observed.shared);
            for d in &prediction.deliveries {
                match d.queue {
                    Private => private &= !signal_set_bit(d.signal),
                    Shared => shared &= !signal_set_bit(d.signal),
                }
            }
            if private | shared == 0 {
                (runs, true, Ended::Exited(0))
            } else {
                // What the handler's rt_sigreturn delivers, under the mask
                // its frame saved: one frame only, so that mask is the
                // whole story.
                assert_eq!(runs.len(), 1, "a row with signals left over has one frame");
                let after = predict_deliveries(private, shared, runs[0].2, &row.actions, false);
                assert!(caught_runs(&after).is_empty(), "{after:?}");
                match after.end {
                    PredictionEnd::Death(status) => (runs, false, killed(status)),
                    PredictionEnd::Return { .. } => (runs, true, Ended::Exited(0)),
                    PredictionEnd::Refuse(refusal) => panic!("no native row refuses {refusal:?}"),
                }
            }
        }
        PredictionEnd::Death(status) => (Vec::new(), false, killed(status)),
        PredictionEnd::Refuse(PredictionRefusal::Stop { signal, .. }) => {
            (Vec::new(), false, Ended::Stopped(signal))
        }
        PredictionEnd::Refuse(refusal) => panic!("no native row refuses {refusal:?}"),
    };
    assert_eq!(
        (observed.runs.clone(), observed.returned, observed.ended),
        (expected_runs, returned, expected_end),
        "native outcome against the prediction {prediction:?}"
    );
    prediction
}

/// SIGUSR1 pending in both queues under `SA_NODEFER`: the thread's own
/// instance is taken first, then the group's, so the group's handler runs
/// first. Catches "shared before private" and "SA_NODEFER ignored".
#[test]
fn private_then_shared_under_sa_nodefer() {
    let row = Row {
        actions: actions(&[(libc::SIGUSR1, caught(NODEFER, 0))]),
        private: vec![libc::SIGUSR1],
        shared: vec![libc::SIGUSR1],
        mask: 0,
    };
    let prediction = check_against_native(&row, false);
    assert_eq!(prediction.deliveries.len(), 2);
}

/// The same under `SA_NODEFER | SA_RESETHAND`: the second instance takes the
/// default action and the child dies of SIGUSR1 before any handler runs.
/// Catches "SA_RESETHAND ignored" and "SA_NODEFER ignored".
#[test]
fn sa_resethand_makes_the_second_instance_fatal() {
    let row = Row {
        actions: actions(&[(libc::SIGUSR1, caught(NODEFER | RESETHAND, 0))]),
        private: vec![libc::SIGUSR1],
        shared: vec![libc::SIGUSR1],
        mask: 0,
    };
    let prediction = check_against_native(&row, false);
    assert!(matches!(prediction.end, PredictionEnd::Death(_)));
}

/// An ignored SIGHUP ahead of a default SIGTERM is discarded, and SIGTERM
/// kills.
#[test]
fn a_fatal_signal_behind_an_ignored_one() {
    let row = Row {
        actions: actions(&[(libc::SIGHUP, ignored())]),
        private: vec![libc::SIGHUP, libc::SIGTERM],
        shared: vec![],
        mask: 0,
    };
    let prediction = check_against_native(&row, false);
    assert_eq!(prediction.deliveries[0].action, Ignored);
}

/// SIGTRAP is synchronous, so it is taken before SIGHUP from the same
/// queue. Catches "synchronous first dropped".
#[test]
fn sigtrap_before_sighup() {
    let row = Row {
        actions: actions(&[(libc::SIGHUP, caught(0, 0)), (libc::SIGTRAP, caught(0, 0))]),
        private: vec![libc::SIGHUP, libc::SIGTRAP],
        shared: vec![],
        mask: 0,
    };
    let prediction = check_against_native(&row, false);
    assert_eq!(prediction.deliveries[0].signal, libc::SIGTRAP);
}

/// Phase 1's SIGALRM, whose handler does not block SIGTERM, is taken before
/// SIGTERM (14 before 15), and SIGTERM then kills before the handler runs.
#[test]
fn a_phase1_sigalrm_before_sigterm() {
    let row = Row {
        actions: actions(&[(libc::SIGALRM, caught(0, 0))]),
        private: vec![],
        shared: vec![libc::SIGALRM, libc::SIGTERM],
        mask: 0,
    };
    let prediction = check_against_native(&row, true);
    assert_eq!(
        prediction.deliveries[0].action,
        PredictedAction::Phase1Alarm
    );
}

/// A default SIGTSTP ahead of SIGXCPU would stop the child: refused by name.
/// Catches "a default stop treated as ignored", under which SIGXCPU would be
/// predicted to kill.
#[test]
fn a_default_sigtstp_ahead_of_sigxcpu_is_refused() {
    let row = Row {
        actions: actions(&[]),
        private: vec![libc::SIGTSTP, libc::SIGXCPU],
        shared: vec![],
        mask: 0,
    };
    let prediction = check_against_native(&row, false);
    assert_eq!(
        prediction.end,
        PredictionEnd::Refuse(PredictionRefusal::Stop {
            signal: libc::SIGTSTP,
            queue: Private,
        })
    );
}

/// SIGQUIT's default action dumps core, but whether a core is written is
/// the kernel's outcome: in this non-dumpable child, with a zero core
/// limit, none is, and WCOREDUMP is clear. The prediction says the default
/// dumps core and leaves the death's core flag false, as it always does.
#[test]
fn a_core_dumping_default_leaves_wcoredump_to_the_kernel() {
    let row = Row {
        actions: actions(&[]),
        private: vec![libc::SIGQUIT],
        shared: vec![],
        mask: 0,
    };
    let prediction = check_against_native(&row, false);
    assert_eq!(
        prediction.deliveries[0].action,
        PredictedAction::Fatal { core_dump: true }
    );
    assert_eq!(
        prediction.end,
        PredictionEnd::Death(ExitStatus::Signaled(crate::Signal::SIGQUIT, false))
    );
}

/// A caught SIGHUP whose `sa_mask` blocks SIGTERM is taken before the
/// default SIGTERM: its handler visibly runs (with its frame's mask), and
/// SIGTERM kills only after the handler's rt_sigreturn puts the frame's
/// mask back. Catches a prediction that ignores `sa_mask`, which would have
/// SIGTERM kill before any handler runs.
#[test]
fn a_caught_signal_before_a_fatal_one_its_mask_blocks() {
    let row = Row {
        actions: actions(&[(libc::SIGHUP, caught(0, bits(&[libc::SIGTERM])))]),
        private: vec![libc::SIGHUP, libc::SIGTERM],
        shared: vec![],
        mask: 0,
    };
    let prediction = check_against_native(&row, false);
    assert_eq!(
        prediction,
        DeliveryPrediction {
            deliveries: vec![delivery(libc::SIGHUP, Private, Caught, 0)],
            end: PredictionEnd::Return {
                mask: bits(&[libc::SIGHUP, libc::SIGTERM]),
            },
        }
    );
}
