/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use kvm_ioctls::VcpuExit;

use super::*;
use crate::clock::RunProbe;
use crate::vm::KvmBackend;

const WAIT: Duration = Duration::from_secs(5);
const CHILD: &str = "REVERIE_KVM_ENTRY_CLEANUP_CHILD";
const ENTRY: u64 = 0x1000;
const SENTINEL: u64 = 0x2000;

type CloseFuture = Pin<Box<dyn Future<Output = GateResult<Closed>> + Send>>;

fn mask_bits() -> u64 {
    unsafe {
        let mut mask = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
            0
        );
        (1..=64).fold(0, |bits, signal| {
            let member = libc::sigismember(&mask, signal);
            assert!(matches!(member, 0 | 1));
            bits | ((member as u64) << (signal - 1))
        })
    }
}

fn pending_reserved() -> bool {
    unsafe {
        let mut pending = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut pending), 0);
        match libc::sigismember(&pending, 64) {
            0 => false,
            1 => true,
            _ => panic!("invalid pending mask"),
        }
    }
}

struct RestoreMask(libc::sigset_t);
impl RestoreMask {
    fn install(blocked: bool) -> Self {
        unsafe {
            let mut saved = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut saved),
                0
            );
            let restore = Self(saved);
            let mut selected = saved;
            assert_eq!(libc::sigaddset(&mut selected, libc::SIGUSR2), 0);
            assert_eq!(libc::sigaddset(&mut selected, libc::SIGURG), 0);
            assert_eq!(
                if blocked {
                    libc::sigaddset(&mut selected, 64)
                } else {
                    libc::sigdelset(&mut selected, 64)
                },
                0
            );
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &selected, std::ptr::null_mut()),
                0
            );
            restore
        }
    }
}
impl Drop for RestoreMask {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) },
            0
        );
    }
}

fn isolated(name: &str, body: impl Fn(bool)) {
    if let Some(value) = std::env::var_os(CHILD) {
        let blocked = match value.to_str().unwrap() {
            "blocked" => true,
            "unblocked" => false,
            other => panic!("unknown child mask {other}"),
        };
        body(blocked);
        println!(
            "\nentry-cleanup-complete:{name}:{}",
            if blocked { "blocked" } else { "unblocked" }
        );
        return;
    }
    for mask in ["blocked", "unblocked"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD, mask)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{mask}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let marker = format!("entry-cleanup-complete:{name}:{mask}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| *line == marker)
                .count(),
            1,
            "successful child omitted its exact completion marker: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

fn make_backend(tracked: bool) -> (KvmBackend, Arc<EntryGate>, Arc<RunProbe>) {
    let mut backend = KvmBackend::new(0x10000).expect("entry cleanup controls require /dev/kvm");
    // Real-mode INC byte [0x2000]; HLT, with no conditional branches.
    backend
        .install_real_mode_program(ENTRY, &[0xfe, 0x06, 0x00, 0x20, 0xf4])
        .unwrap();
    backend.memory.write_raw(SENTINEL, &[0]).unwrap();
    if tracked {
        backend.vcpu.track_clock().unwrap();
    }
    let gate = backend.memory.entry_gate();
    let probe = Arc::new(RunProbe::default());
    backend.vcpu.set_run_probe(probe.clone());
    probe.arm();
    (backend, gate, probe)
}

fn assert_runs(probe: &RunProbe, tracked: bool, runs: usize, masks: usize) {
    let read = |value: &AtomicUsize| value.load(Ordering::SeqCst);
    assert_eq!(read(&probe.prepare.mask_installs), masks);
    assert_eq!(read(&probe.untracked_runs), if tracked { 0 } else { runs });
    assert_eq!(read(&probe.tracked_runs), if tracked { runs } else { 0 });
    assert_eq!(read(&probe.clock_begins), if tracked { runs } else { 0 });
    assert_eq!(
        read(&probe.intervals_created),
        if tracked { runs } else { 0 }
    );
}

fn sentinel(backend: &KvmBackend) -> u8 {
    let mut byte = [0xff];
    backend.memory.read_raw(SENTINEL, &mut byte).unwrap();
    byte[0]
}

fn rewind(backend: &mut KvmBackend) {
    let mut regs = backend.vcpu.get_regs().unwrap();
    regs.rip = ENTRY;
    backend.vcpu.set_regs(&regs).unwrap();
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl futures::task::ArcWake for WakeCount {
    fn wake_by_ref(arc: &Arc<Self>) {
        arc.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct PendingClose {
    future: Mutex<Option<CloseFuture>>,
    wake: Arc<WakeCount>,
    before_ack_wakes: AtomicUsize,
}
impl PendingClose {
    fn store(&self, closing: Closing) {
        assert!(
            self.future
                .lock()
                .unwrap()
                .replace(Box::pin(closing.finish()))
                .is_none()
        );
        self.assert_pending();
    }
    fn assert_pending(&self) {
        let waker = futures::task::waker(self.wake.clone());
        assert!(
            self.future
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending(),
            "withdrawal or mask restoration was mistaken for final acknowledgement"
        );
    }
    fn complete(&self) -> Closed {
        assert!(
            self.wake.0.load(Ordering::SeqCst) > self.before_ack_wakes.load(Ordering::SeqCst),
            "actual acknowledgement lost its waiter wake"
        );
        self.future
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .now_or_never()
            .expect("real cleanup failed to release close")
            .unwrap()
    }
}

fn assert_member(gate: &EntryGate, id: CleanupIdentity, activity: Activity) {
    let state = gate.state.lock().unwrap();
    assert_eq!(state.members.len(), 1);
    let member = &state.members[&id.participant];
    assert_eq!(member.run, id.run);
    assert_eq!(member.activity, activity);
}

fn send_three(thread: libc::pthread_t, sends: &AtomicUsize) -> std::io::Result<()> {
    for _ in 0..3 {
        let result = unsafe { libc::pthread_kill(thread, 64) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        sends.fetch_add(1, Ordering::SeqCst);
    }
    Ok(())
}

struct SenderRescue(Arc<Mutex<Option<std::thread::JoinHandle<()>>>>);
impl Drop for SenderRescue {
    fn drop(&mut self) {
        let handle = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(handle) = handle
            && let Err(payload) = handle.join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(payload);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Race {
    LateSend,
    Withdrawn,
    Serialized,
}

fn race_case(kind: Race, blocked: bool, tracked: bool) {
    let restore = RestoreMask::install(blocked);
    let original = mask_bits();
    let pthread = unsafe { libc::pthread_self() };
    let (mut backend, gate, probe) = make_backend(tracked);
    let pending = Arc::new(PendingClose::default());
    let phases = Arc::new(Mutex::new(Vec::new()));
    let sends = Arc::new(AtomicUsize::new(0));
    let contentions = Arc::new(AtomicUsize::new(0));
    let sender_handle = Arc::new(Mutex::new(None));
    let _sender_rescue = SenderRescue(sender_handle.clone());
    let (closing_sender, closing_receiver) = mpsc::channel();
    let (attempt_sender, attempt_receiver) = mpsc::channel();
    if kind == Race::Serialized {
        let contentions = contentions.clone();
        probe.prepare.on_withdraw_contention(move || {
            assert_eq!(contentions.fetch_add(1, Ordering::SeqCst), 0);
            attempt_sender.send(()).unwrap();
        });
    }
    let before_gate = gate.clone();
    let before_pending = pending.clone();
    let before_phases = phases.clone();
    let before_sends = sends.clone();
    let before_handle = sender_handle.clone();
    let before_probe = Arc::downgrade(&probe);
    probe
        .prepare
        .on_cleanup(CleanupPhase::BeforeWithdraw, move |id| {
            assert_eq!(id.run, 1);
            assert_eq!(mask_bits(), original | (1_u64 << 63));
            assert!(
                !pending_reserved(),
                "the explicit early pending observation must be empty"
            );
            assert_eq!(signal::HANDLER_ENTRIES.load(Ordering::Relaxed), 0);
            assert_runs(&before_probe.upgrade().unwrap(), tracked, 1, 1);
            assert_member(&before_gate, id, Activity::Running(pthread));
            before_phases
                .lock()
                .unwrap()
                .push((CleanupPhase::BeforeWithdraw, id));
            match kind {
                Race::LateSend => {
                    let close = before_gate
                        .try_close_with(|target| {
                            assert_eq!(target, pthread);
                            send_three(target, &before_sends)
                        })
                        .unwrap()
                        .unwrap();
                    assert!(pending_reserved());
                    before_pending.store(close);
                }
                Race::Withdrawn => {}
                Race::Serialized => {
                    let (entered_sender, entered_receiver) = mpsc::channel();
                    let sender_gate = before_gate.clone();
                    let sends = before_sends.clone();
                    let handle = std::thread::spawn(move || {
                        let close = sender_gate
                            .try_close_with(|target| {
                                assert_eq!(target, pthread);
                                // This is intentionally inside the production sender's
                                // actual gate lock. Wait only for the armed real
                                // withdrawal try_lock to report WouldBlock.
                                entered_sender.send(()).unwrap();
                                attempt_receiver.recv_timeout(WAIT).expect(
                                    "real withdrawal did not encounter the held sender mutex",
                                );
                                send_three(target, &sends)
                            })
                            .unwrap()
                            .unwrap();
                        closing_sender
                            .send(close)
                            .unwrap_or_else(|_| panic!("cleanup lost its real closer"));
                    });
                    assert!(before_handle.lock().unwrap().replace(handle).is_none());
                    entered_receiver
                        .recv_timeout(WAIT)
                        .expect("serialized sender did not hold the gate mutex");
                }
            }
        });
    let after_gate = gate.clone();
    let after_pending = pending.clone();
    let after_phases = phases.clone();
    let after_sends = sends.clone();
    let after_contentions = contentions.clone();
    probe
        .prepare
        .on_cleanup(CleanupPhase::AfterWithdraw, move |id| {
            assert_member(&after_gate, id, Activity::Retiring);
            assert_eq!(mask_bits(), original | (1_u64 << 63));
            after_phases
                .lock()
                .unwrap()
                .push((CleanupPhase::AfterWithdraw, id));
            match kind {
                Race::Withdrawn => {
                    let close = after_gate
                        .try_close_with(|_| {
                            after_sends.fetch_add(1, Ordering::SeqCst);
                            panic!("withdrawn generation remained a send target")
                        })
                        .unwrap()
                        .unwrap();
                    after_pending.store(close);
                    assert!(!pending_reserved());
                    assert_eq!(after_sends.load(Ordering::SeqCst), 0);
                }
                Race::Serialized => {
                    assert_eq!(after_contentions.load(Ordering::SeqCst), 1);
                    after_pending.store(
                        closing_receiver
                            .recv_timeout(WAIT)
                            .expect("sender did not finish after actual withdrawal contention"),
                    );
                    assert!(pending_reserved());
                    assert_eq!(after_sends.load(Ordering::SeqCst), 3);
                }
                Race::LateSend => {
                    assert!(pending_reserved());
                }
            }
            after_pending.assert_pending();
        });
    let ack_gate = gate.clone();
    let ack_pending = pending.clone();
    let ack_phases = phases.clone();
    probe
        .prepare
        .on_cleanup(CleanupPhase::BeforeAcknowledge, move |id| {
            assert_member(&ack_gate, id, Activity::Retiring);
            assert_eq!(mask_bits(), original);
            assert!(
                !pending_reserved(),
                "mandatory final drain left a queued signal"
            );
            assert_eq!(
                signal::HANDLER_ENTRIES.load(Ordering::Relaxed),
                0,
                "restoring an unblocked mask delivered a control signal instead of draining it"
            );
            ack_phases
                .lock()
                .unwrap()
                .push((CleanupPhase::BeforeAcknowledge, id));
            ack_pending.assert_pending();
            ack_pending
                .before_ack_wakes
                .store(ack_pending.wake.0.load(Ordering::SeqCst), Ordering::SeqCst);
        });
    assert!(matches!(backend.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
    assert_eq!(mask_bits(), original);
    assert_eq!(signal::HANDLER_ENTRIES.load(Ordering::Relaxed), 0);
    let expected_id = phases.lock().unwrap()[0].1;
    assert_eq!(
        *phases.lock().unwrap(),
        vec![
            (CleanupPhase::BeforeWithdraw, expected_id),
            (CleanupPhase::AfterWithdraw, expected_id),
            (CleanupPhase::BeforeAcknowledge, expected_id),
        ]
    );
    assert_member(&gate, expected_id, Activity::Stopped);
    let closed = pending.complete();
    assert_eq!(
        gate.state.lock().unwrap().admission,
        Admission::Closed(closed.id)
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        if kind == Race::Withdrawn { 0 } else { 3 }
    );
    if let Some(sender) = sender_handle.lock().unwrap().take() {
        sender.join().unwrap();
    }
    assert_runs(&probe, tracked, 1, 1);
    drop(closed);
    // A fresh close after the old generation is acknowledged cannot target it.
    let old_target_calls = AtomicUsize::new(0);
    let closed = gate
        .try_close_with(|_| {
            old_target_calls.fetch_add(1, Ordering::SeqCst);
            panic!("acknowledged generation was reused by a sender")
        })
        .unwrap()
        .unwrap()
        .finish()
        .now_or_never()
        .unwrap()
        .unwrap();
    assert_eq!(old_target_calls.load(Ordering::SeqCst), 0);
    drop(closed);
    assert_eq!(sentinel(&backend), 1);
    if tracked {
        assert_eq!(backend.vcpu.read_clock().unwrap(), 0);
    }

    rewind(&mut backend);
    assert!(matches!(backend.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
    assert_eq!(sentinel(&backend), 2);
    assert_eq!(mask_bits(), original);
    assert!(!pending_reserved());
    assert_runs(&probe, tracked, 2, 2);
    assert_member(
        &gate,
        CleanupIdentity {
            run: 2,
            ..expected_id
        },
        Activity::Stopped,
    );
    // Keep the original host thread alive while moving the stopped backend.
    // No signal-mask/entry guard crosses this transfer. The second host has
    // the opposite saved signal-64 state and must observe no stale kick.
    let other = std::thread::spawn(move || {
        assert_ne!(unsafe { libc::pthread_self() }, pthread);
        let restore = RestoreMask::install(!blocked);
        let other_mask = mask_bits();
        assert_ne!(other_mask & (1_u64 << 63), original & (1_u64 << 63));
        rewind(&mut backend);
        assert!(matches!(backend.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
        assert_eq!(sentinel(&backend), 3);
        if tracked {
            assert_eq!(backend.vcpu.read_clock().unwrap(), 0);
        }
        assert_eq!(mask_bits(), other_mask);
        assert!(!pending_reserved());
        drop(restore);
        backend
    });
    let backend = other.join().unwrap();
    assert_eq!(mask_bits(), original);
    assert_runs(&probe, tracked, 3, 3);
    assert_member(
        &gate,
        CleanupIdentity {
            run: 3,
            ..expected_id
        },
        Activity::Stopped,
    );
    assert_eq!(signal::HANDLER_ENTRIES.load(Ordering::Relaxed), 0);
    assert_eq!(
        contentions.load(Ordering::SeqCst),
        usize::from(kind == Race::Serialized)
    );
    drop(backend);
    assert!(gate.state.lock().unwrap().members.is_empty());
    drop(restore);
}

fn count_identity(error: &Error, target: &Arc<Error>) -> usize {
    let arc = |error: &Arc<Error>| {
        usize::from(Arc::ptr_eq(error, target)) + count_identity(error, target)
    };
    match error {
        Error::SharedFailure(error)
        | Error::Cleanup { error, .. }
        | Error::WorkerFailure { error, .. } => arc(error),
        Error::WithCleanup { primary, cleanup } => {
            arc(primary) + cleanup.iter().map(arc).sum::<usize>()
        }
        _ => 0,
    }
}

fn error_case(blocked: bool, tracked: bool, selected: [bool; 3]) {
    let restore = RestoreMask::install(blocked);
    let original = mask_bits();
    let (mut backend, gate, probe) = make_backend(tracked);
    let errors = [
        Arc::new(failure(
            "install KVM temporary signal mask",
            std::io::Error::from_raw_os_error(libc::EACCES),
        )),
        Arc::new(failure(
            "drain reserved host signal",
            std::io::Error::from_raw_os_error(libc::EIO),
        )),
        Arc::new(failure(
            "restore host signal mask",
            std::io::Error::from_raw_os_error(libc::EPERM),
        )),
    ];
    let configured = std::array::from_fn(|index| selected[index].then(|| errors[index].clone()));
    let guard = signal::fault::Guard::arm(configured);
    let phases = Arc::new(Mutex::new(Vec::new()));
    let before_phases = phases.clone();
    probe
        .prepare
        .on_cleanup(CleanupPhase::BeforeWithdraw, move |id| {
            assert_eq!(mask_bits(), original | (1_u64 << 63));
            assert!(!pending_reserved());
            // The fault-control producer queues real signals while masked. The
            // sender/withdrawal authorization is covered by the separate race
            // controls; this case isolates safe drain despite a reported error.
            if selected[1] || selected[2] {
                let sends = AtomicUsize::new(0);
                send_three(unsafe { libc::pthread_self() }, &sends).unwrap();
                assert_eq!(sends.load(Ordering::SeqCst), 3);
                assert!(pending_reserved());
            }
            before_phases
                .lock()
                .unwrap()
                .push((CleanupPhase::BeforeWithdraw, id));
        });
    let after_gate = gate.clone();
    let after_phases = phases.clone();
    probe
        .prepare
        .on_cleanup(CleanupPhase::AfterWithdraw, move |id| {
            assert_member(&after_gate, id, Activity::Retiring);
            after_phases
                .lock()
                .unwrap()
                .push((CleanupPhase::AfterWithdraw, id));
        });
    let ack_gate = gate.clone();
    let ack_phases = phases.clone();
    probe
        .prepare
        .on_cleanup(CleanupPhase::BeforeAcknowledge, move |id| {
            assert_member(&ack_gate, id, Activity::Retiring);
            assert_eq!(
                mask_bits(),
                original,
                "fault seam must retain actual safe restoration"
            );
            assert!(
                !pending_reserved(),
                "fault seam must retain actual complete drain"
            );
            assert_eq!(signal::HANDLER_ENTRIES.load(Ordering::Relaxed), 0);
            assert_eq!(ack_gate.pending_failure().is_some(), selected[0]);
            ack_phases
                .lock()
                .unwrap()
                .push((CleanupPhase::BeforeAcknowledge, id));
        });
    let wake = Arc::new(WakeCount::default());
    let waker = futures::task::waker(wake.clone());
    let mut changed = Box::pin(gate.subscribe());
    assert!(
        changed
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let error = match backend.vcpu.run() {
        Err(error) => error,
        Ok(_) => panic!("reported mask failure admitted a successful exit"),
    };
    assert!(wake.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        changed.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Ok(()))
    ));
    let id = phases.lock().unwrap()[0].1;
    assert_eq!(id.run, 1);
    assert_eq!(
        *phases.lock().unwrap(),
        vec![
            (CleanupPhase::BeforeWithdraw, id),
            (CleanupPhase::AfterWithdraw, id),
            (CleanupPhase::BeforeAcknowledge, id),
        ]
    );
    assert_member(&gate, id, Activity::Stopped);
    let pending = gate.pending_failure().unwrap();
    let retained = pending.error();
    for index in 0..3 {
        assert_eq!(
            count_identity(&error, &errors[index]),
            usize::from(selected[index]),
            "returned error cause {index}"
        );
        assert_eq!(
            count_identity(&retained, &errors[index]),
            usize::from(selected[index]),
            "retained gate cause {index}"
        );
        assert_eq!(
            guard.probe.consumed[index].load(Ordering::SeqCst),
            usize::from(selected[index])
        );
    }
    let primary = selected.iter().position(|enabled| *enabled).unwrap();
    assert!(error.retains_primary(&errors[primary]));
    let expected_errno = [libc::EACCES, libc::EIO, libc::EPERM][primary];
    assert!(
        matches!(error.primary(), Error::EntryControl { source, .. } if source.raw_os_error() == Some(expected_errno))
    );
    assert_eq!(mask_bits(), original);
    assert!(!pending_reserved());
    assert_runs(&probe, tracked, usize::from(!selected[0]), 1);
    // The failed gate cannot be reopened by an apparent successful retirement.
    assert!(backend.vcpu.run().is_err());
    assert_runs(&probe, tracked, usize::from(!selected[0]), 1);
    assert!(gate.admit_operation().is_err());
    assert!(gate.register().is_err());
    assert!(gate.try_copy(None).is_err());
    assert!(gate.try_close().is_err());
    // Read only after actual entry return, through retained backing: poisoned
    // production memory access correctly refuses. Only KVM wrote this byte.
    let physical = backend.memory.host_address() + SENTINEL - backend.memory.guest_base();
    assert_eq!(unsafe { *(physical as *const u8) }, u8::from(!selected[0]));
    drop(guard);
    drop(backend);
    assert!(gate.state.lock().unwrap().members.is_empty());
    // A separate actual vCPU on this host thread must not find a stale signal
    // or a stranded mask, even though the old Mapping remains terminal.
    let (mut fresh, fresh_gate, fresh_probe) = make_backend(tracked);
    assert!(matches!(fresh.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
    assert_eq!(sentinel(&fresh), 1);
    assert_runs(&fresh_probe, tracked, 1, 1);
    assert_eq!(mask_bits(), original);
    assert!(!pending_reserved());
    assert_eq!(signal::HANDLER_ENTRIES.load(Ordering::Relaxed), 0);
    drop(fresh);
    assert!(fresh_gate.state.lock().unwrap().members.is_empty());
    drop(restore);
}

#[test]
fn late_kick_after_successful_exit_is_drained_before_acknowledgement() {
    isolated(
        "entry::cleanup_tests::late_kick_after_successful_exit_is_drained_before_acknowledgement",
        |blocked| {
            for tracked in [false, true] {
                race_case(Race::LateSend, blocked, tracked);
            }
        },
    );
}

#[test]
fn withdrawn_real_entry_has_no_sender_until_final_cleanup_acknowledges() {
    isolated(
        "entry::cleanup_tests::withdrawn_real_entry_has_no_sender_until_final_cleanup_acknowledges",
        |blocked| {
            for tracked in [false, true] {
                race_case(Race::Withdrawn, blocked, tracked);
            }
        },
    );
}

#[test]
fn real_withdrawal_waits_for_serialized_sender_and_drains_its_kick() {
    isolated(
        "entry::cleanup_tests::real_withdrawal_waits_for_serialized_sender_and_drains_its_kick",
        |blocked| {
            for tracked in [false, true] {
                race_case(Race::Serialized, blocked, tracked);
            }
        },
    );
}

#[test]
fn mask_operation_errors_poison_after_safe_real_cleanup_and_preserve_causes() {
    isolated(
        "entry::cleanup_tests::mask_operation_errors_poison_after_safe_real_cleanup_and_preserve_causes",
        |blocked| {
            for tracked in [false, true] {
                for selected in [
                    [true, false, false],
                    [false, true, false],
                    [false, false, true],
                    [false, true, true],
                    [true, true, true],
                ] {
                    error_case(blocked, tracked, selected);
                }
            }
        },
    );
}
