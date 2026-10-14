/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::time::Duration;
use std::time::Instant;

use super::*;

const PROGRAM: u64 = 0x1000;
const MARKER: u64 = 0x2000;
type CloseFuture = Pin<
    Box<
        dyn Future<
                Output = std::result::Result<
                    crate::entry::Closed,
                    Arc<crate::entry::PendingFailure>,
                >,
            > + Send,
    >,
>;

fn pending(future: &mut CloseFuture) {
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(future.as_mut().poll(&mut cx).is_pending());
}

fn mask_bits() -> u64 {
    // SAFETY: query initialized writable storage without changing the mask.
    unsafe {
        let mut mask = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
            0
        );
        (1..=64).fold(0, |bits, signal| {
            bits | ((libc::sigismember(&mask, signal) as u64) << (signal - 1))
        })
    }
}

fn reserved_pending() -> bool {
    // SAFETY: query initialized writable storage for this thread only.
    unsafe {
        let mut mask = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut mask), 0);
        libc::sigismember(&mask, 64) == 1
    }
}

#[test]
fn reserved_signal_after_activation_prevents_actual_ioctl_guest_progress() {
    for tracked in [false, true] {
        let saved_mask = mask_bits();
        let saved_affinity = affinity().unwrap();
        let mut backend =
            crate::KvmBackend::new(0x10000).expect("pending entry control requires /dev/kvm");
        // inc byte ptr [0x2000]; hlt. A successful neighbor changes it once.
        backend
            .install_real_mode_program(PROGRAM, &[0xfe, 0x06, 0x00, 0x20, 0xf4])
            .unwrap();
        backend.memory.write_raw(MARKER, &[0]).unwrap();
        if tracked {
            backend.vcpu.track_clock().unwrap();
        }
        let gate = backend.memory.entry_gate();
        let closing: Arc<Mutex<Option<CloseFuture>>> = Arc::new(Mutex::new(None));
        let hook_closing = closing.clone();
        let hook_gate = gate.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        let probe = Arc::new(RunProbe::default());
        *probe.after_prepare.lock().unwrap() = Some(Box::new(move || {
            assert_eq!(hook_calls.fetch_add(1, Ordering::SeqCst), 0);
            assert!(!reserved_pending());
            // prepare already published the actual Running pthread and its
            // temporary KVM mask. Sending to self queues the blocked signal.
            let mut future: CloseFuture =
                Box::pin(hook_gate.try_close().unwrap().unwrap().finish());
            assert!(reserved_pending());
            pending(&mut future);
            *hook_closing.lock().unwrap() = Some(future);
        }));
        backend.vcpu.set_run_probe(probe.clone());
        probe.arm();
        let registers = backend.vcpu.get_regs().unwrap();
        let result = backend.vcpu.run();
        assert!(matches!(result, Err(Error::Kvm(error)) if error.errno() == libc::EINTR));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.prepare.mask_installs.load(Ordering::SeqCst), 1);
        assert_eq!(
            probe.tracked_runs.load(Ordering::SeqCst),
            usize::from(tracked)
        );
        assert_eq!(
            probe.untracked_runs.load(Ordering::SeqCst),
            usize::from(!tracked)
        );
        assert_eq!(backend.vcpu.get_regs().unwrap(), registers);
        // Signal 64 stays blocked after an entry; nothing else moves.
        assert_eq!(mask_bits(), saved_mask | (1 << 63));
        assert!(same_affinity(&affinity().unwrap(), &saved_affinity));
        assert!(!reserved_pending());
        assert!(gate.pending_failure().is_none());
        if tracked {
            assert_eq!(backend.vcpu.read_clock().unwrap(), 0);
            // Only an event that follows its task stays enabled between entries.
            assert_eq!(
                backend.vcpu.clock.binding.as_ref().unwrap().enabled,
                backend.vcpu.clock.placement == CounterPlacement::FollowTask
            );
        }
        let closed = futures::executor::block_on(closing.lock().unwrap().take().unwrap()).unwrap();
        // Guest memory copies correctly wait while closed; observe only after
        // reopening, before any guest can execute the successful neighbor.
        assert!(backend.vcpu.run().unwrap().is_none());
        drop(closed);
        let mut byte = [0];
        backend.memory.read_raw(MARKER, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        assert!(matches!(backend.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
        backend.memory.read_raw(MARKER, &mut byte).unwrap();
        assert_eq!(byte, [1]);
        if tracked {
            assert_eq!(backend.vcpu.read_clock().unwrap(), 0);
        }
    }
}

fn finite_program(branches: u32) -> Vec<u8> {
    // The production event excludes guest kernel work, so this fixture must
    // execute at CPL3. One taken JNZ precedes the stack marker, then exactly
    // branches-1 loop JNZs, followed by a real getpid syscall transport exit.
    let mut code = vec![0xb9]; // mov ecx, branches
    code.extend_from_slice(&branches.to_le_bytes());
    code.extend_from_slice(&[
        0xff, 0xc9, 0x75, 0x00, // dec ecx; jnz next
        0xc6, 0x44, 0x24, 0xf8, 0x01, // mov byte [rsp-8], 1
        0xff, 0xc9, 0x75, 0xfc, // dec ecx; jnz loop
        0xb8, 39, 0, 0, 0, // mov eax, SYS_getpid
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2 (must not reach)
    ]);
    code
}

fn install_counted_program(backend: &mut crate::KvmBackend, code: &[u8]) -> u64 {
    backend
        .install_static_elf(
            &crate::vm::minimal_test_elf(code),
            "/bin/counted-entry-kick",
        )
        .unwrap();
    assert_eq!(backend.vcpu.get_sregs().unwrap().cs.dpl, 3);
    // The guest names the marker at rsp - 8; the host reads it physically.
    let marker = backend
        .memory
        .user_range_to_guest(backend.vcpu.get_regs().unwrap().rsp - 8, 1)
        .unwrap();
    backend.memory.write_raw(marker, &[0]).unwrap();
    backend.vcpu.track_clock().unwrap();
    marker
}

fn reaches_getpid(vcpu: &mut CountedVcpu) {
    let memory = vcpu.memory.clone();
    match vcpu.run().unwrap() {
        Some(VcpuExit::Hypercall(exit)) => {
            assert_eq!(exit.nr, crate::vm::VMCALL_SYSCALL_TRANSPORT);
            let request = crate::SyscallRequest::read_from(&memory, exit.args[0]).unwrap();
            assert_eq!(request.number(), libc::SYS_getpid as u64);
        }
        exit => panic!("finite user program did not reach getpid: {exit:?}"),
    }
}

#[test]
fn running_reserved_kick_retains_exact_finite_program_branch_total() {
    const BRANCHES: u32 = 1 << 28;
    let program = finite_program(BRANCHES);
    let saved_affinity = affinity().unwrap();
    let saved_mask = mask_bits();
    let mut baseline =
        crate::KvmBackend::new(16 * 1024 * 1024).expect("counted kick control requires /dev/kvm");
    install_counted_program(&mut baseline, &program);
    reaches_getpid(&mut baseline.vcpu);
    assert_eq!(baseline.vcpu.read_clock().unwrap(), u64::from(BRANCHES));
    assert!(same_affinity(&affinity().unwrap(), &saved_affinity));

    let mut backend = crate::KvmBackend::new(16 * 1024 * 1024).unwrap();
    let marker = install_counted_program(&mut backend, &program);
    let gate = backend.memory.entry_gate();
    let memory = backend.memory.clone();
    let closing: Arc<Mutex<Option<CloseFuture>>> = Arc::new(Mutex::new(None));
    let hook_closing = closing.clone();
    let probe = Arc::new(RunProbe::default());
    let observed = Arc::new(Mutex::new(None));
    let hook_observed = observed.clone();
    *probe.after_interval.lock().unwrap() = Some(Box::new(move |clock| {
        // This hook is after the real closing read and any affinity
        // restoration, and before RunEntry withdraws or acknowledges. No fake
        // perf value or EINTR. Only an event that follows its task stays enabled.
        assert_eq!(
            clock.binding.as_ref().unwrap().enabled,
            clock.placement == CounterPlacement::FollowTask
        );
        assert!(same_affinity(&affinity().unwrap(), &saved_affinity));
        let count = clock.read().unwrap();
        assert!(count >= 1 && count < u64::from(BRANCHES));
        pending(hook_closing.lock().unwrap().as_mut().unwrap());
        *hook_observed.lock().unwrap() = Some(count);
    }));
    backend.vcpu.set_run_probe(probe.clone());
    probe.arm();
    std::thread::scope(|scope| {
        let controller_closing = closing.clone();
        let controller = scope.spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            // The Mapping owner is retained and only KVM writes the marker.
            // Volatile observes that external writer, not a snapshot guarantee.
            while unsafe { std::ptr::read_volatile((memory.host_address() + marker) as *const u8) }
                == 0
            {
                assert!(
                    Instant::now() < deadline,
                    "finite guest never reached marker"
                );
                std::thread::yield_now();
            }
            // Hold this mutex through the send so after_interval cannot race
            // ahead of recording the actual close future.
            let mut slot = controller_closing.lock().unwrap();
            *slot = Some(Box::pin(gate.try_close().unwrap().unwrap().finish()));
        });
        let result = backend.vcpu.run();
        controller.join().unwrap();
        assert!(matches!(result, Err(Error::Kvm(error)) if error.errno() == libc::EINTR));
    });
    let retained = observed.lock().unwrap().unwrap();
    assert_eq!(backend.vcpu.read_clock().unwrap(), retained);
    assert_eq!(mask_bits(), saved_mask | (1 << 63));
    assert!(same_affinity(&affinity().unwrap(), &saved_affinity));
    assert!(!reserved_pending());
    let closed = futures::executor::block_on(closing.lock().unwrap().take().unwrap()).unwrap();
    assert!(backend.vcpu.run().unwrap().is_none());
    assert_eq!(backend.vcpu.read_clock().unwrap(), retained);
    drop(closed);
    reaches_getpid(&mut backend.vcpu);
    assert_eq!(backend.vcpu.read_clock().unwrap(), u64::from(BRANCHES));
    assert_eq!(
        backend.vcpu.read_clock().unwrap(),
        baseline.vcpu.read_clock().unwrap()
    );
    assert_eq!(
        backend.vcpu.clock.binding.as_ref().unwrap().enabled,
        backend.vcpu.clock.placement == CounterPlacement::FollowTask
    );
    assert!(same_affinity(&affinity().unwrap(), &saved_affinity));
    assert_eq!(
        backend.vcpu.get_regs().unwrap().rip,
        baseline.vcpu.get_regs().unwrap().rip
    );
    assert_eq!(probe.tracked_runs.load(Ordering::SeqCst), 2);
}

/// The CPU a host task last ran on: field 39 of `/proc/self/task/<tid>/stat`.
fn last_cpu(tid: libc::pid_t) -> Option<usize> {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
    // Fields after the parenthesised command start at field 3 (state).
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(36)?
        .parse()
        .ok()
}

#[test]
fn migrating_host_task_keeps_exact_finite_program_branch_total() {
    const BRANCHES: u32 = 1 << 28;
    let original = affinity().unwrap();
    let permitted: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &original) })
        .take(4)
        .collect();
    let mut backend =
        crate::KvmBackend::new(16 * 1024 * 1024).expect("counted migration requires /dev/kvm");
    if backend.vcpu.clock.placement != CounterPlacement::FollowTask || permitted.len() < 2 {
        println!(
            "clock migration: NOT EXECUTED; placement {:?}, permitted CPUs {permitted:?}",
            backend.vcpu.clock.placement
        );
        return;
    }
    install_counted_program(&mut backend, &finite_program(BRANCHES));
    let tid = host_tid();
    let done = AtomicBool::new(false);
    let observed = Mutex::new(BTreeSet::new());
    let moves = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            // Move the vCPU task between CPUs while it is inside KVM_RUN. The
            // event is opened for any CPU, so the kernel carries its count.
            let mut next = 0;
            while !done.load(Ordering::SeqCst) {
                let mut set = unsafe { std::mem::zeroed() };
                unsafe { libc::CPU_SET(permitted[next % permitted.len()], &mut set) };
                let moved = unsafe {
                    libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set)
                };
                assert_eq!(moved, 0, "{}", std::io::Error::last_os_error());
                moves.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1));
                if let Some(cpu) = last_cpu(tid) {
                    observed.lock().unwrap().insert(cpu);
                }
                next += 1;
            }
        });
        // Stop the mover even if the entry panics, so a failure cannot hang.
        struct StopMover<'a>(&'a AtomicBool);
        impl Drop for StopMover<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _stop = StopMover(&done);
        reaches_getpid(&mut backend.vcpu);
    });
    set_affinity(&original).unwrap();
    let observed = observed.into_inner().unwrap();
    println!(
        "clock migration: {} affinity moves; vCPU task observed on CPUs {observed:?}",
        moves.load(Ordering::SeqCst)
    );
    assert!(
        observed.len() >= 2,
        "the vCPU task never ran on a second CPU: {observed:?}"
    );
    assert_eq!(backend.vcpu.read_clock().unwrap(), u64::from(BRANCHES));
    assert!(same_affinity(&affinity().unwrap(), &original));
}

#[test]
fn pinned_entries_keep_exact_finite_program_branch_total() {
    // The path every non-AMD or hybrid host takes, exercised on any KVM host:
    // each entry is pinned, the CPU-bound event is enabled for that entry only,
    // and the affinity is restored afterwards.
    const BRANCHES: u32 = 1 << 26;
    let original = affinity().unwrap();
    let mut backend =
        crate::KvmBackend::new(16 * 1024 * 1024).expect("pinned counting requires /dev/kvm");
    install_counted_program(&mut backend, &finite_program(BRANCHES));
    // Installing the image builds the clock with this host's placement; select
    // the pinned path before the first counted entry. Its binding is reopened
    // for the pinned CPU, with no guest work counted yet.
    backend.vcpu.clock.placement = CounterPlacement::PinEachEntry;
    reaches_getpid(&mut backend.vcpu);
    assert_eq!(backend.vcpu.read_clock().unwrap(), u64::from(BRANCHES));
    let binding = backend.vcpu.clock.binding.as_ref().unwrap();
    assert_ne!(binding.identity.cpu, FOLLOWS_TASK);
    assert!(!binding.enabled);
    assert!(same_affinity(&affinity().unwrap(), &original));
}

#[test]
fn synced_registers_match_kvm_and_never_go_stale() {
    let mut backend =
        crate::KvmBackend::new(16 * 1024 * 1024).expect("synced registers require /dev/kvm");
    install_counted_program(&mut backend, &finite_program(1 << 10));
    reaches_getpid(&mut backend.vcpu);
    if !backend.vcpu.sync_regs {
        println!("synced registers: NOT EXECUTED; KVM lacks KVM_CAP_SYNC_REGS here");
        return;
    }
    // After the exit the reads come from kvm_run, and reading keeps them current.
    assert!(backend.vcpu.synced_exit.load(Ordering::Relaxed));
    let synced = backend.vcpu.get_regs().unwrap();
    let synced_special = backend.vcpu.get_sregs().unwrap();
    assert!(backend.vcpu.synced_exit.load(Ordering::Relaxed));
    // The ioctl agrees. Borrowing the raw fd retires the synced copy.
    let raw: &kvm_ioctls::VcpuFd = &backend.vcpu;
    assert_eq!(raw.get_regs().unwrap(), synced);
    assert_eq!(raw.get_sregs().unwrap(), synced_special);
    assert!(!backend.vcpu.synced_exit.load(Ordering::Relaxed));
    // A write through the raw fd is what a later read returns, not the
    // stale synced copy of the exit.
    let mut changed = synced;
    changed.rax = 0x1234_5678;
    backend.vcpu.set_regs(&changed).unwrap();
    assert_eq!(backend.vcpu.get_regs().unwrap().rax, 0x1234_5678);
    // This backend injects no interrupt, so KVM synced an empty bitmap here.
    // a_nonzero_synced_interrupt_bitmap_is_read_from_kvm covers a stale bit.
    assert!(
        synced_special
            .interrupt_bitmap
            .iter()
            .all(|word| *word == 0)
    );
    println!("synced registers: matched KVM_GET_REGS/SREGS and followed a raw write");
}

#[test]
fn a_nonzero_synced_interrupt_bitmap_is_read_from_kvm() {
    let mut backend =
        crate::KvmBackend::new(16 * 1024 * 1024).expect("synced registers require /dev/kvm");
    install_counted_program(&mut backend, &finite_program(1 << 10));
    reaches_getpid(&mut backend.vcpu);
    if !backend.vcpu.sync_regs {
        println!("synced bitmap: NOT EXECUTED; KVM lacks KVM_CAP_SYNC_REGS here");
        return;
    }
    // KVM sets bits in the synced interrupt bitmap at an exit and never clears
    // them. Leave a stale bit there while the synced copy is still current:
    // the field is reached directly, so no Deref retires the copy.
    backend.vcpu.fd.sync_regs_mut().sregs.interrupt_bitmap[0] = 1;
    assert!(backend.vcpu.synced_exit.load(Ordering::Relaxed));
    // The read must come from KVM_GET_SREGS, which reports no pending
    // interrupt, rather than return the stale synced bit.
    let special = backend.vcpu.get_sregs().unwrap();
    assert_eq!(special.interrupt_bitmap, [0; 4]);
    assert_eq!(special.cs, backend.vcpu.fd.sync_regs().sregs.cs);
    backend.vcpu.fd.sync_regs_mut().sregs.interrupt_bitmap[0] = 0;
    println!("synced bitmap: a stale nonzero bitmap was read from KVM");
}

fn change_sigurg(how: libc::c_int) {
    // SAFETY: the set is initialized before pthread_sigmask reads it, and the
    // change affects only this test thread.
    unsafe {
        let mut set = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGURG);
        assert_eq!(libc::pthread_sigmask(how, &set, std::ptr::null_mut()), 0);
    }
}

#[test]
fn kvm_signal_mask_is_reissued_only_when_the_thread_mask_changes() {
    const SIGURG_BIT: u64 = 1 << (libc::SIGURG - 1);
    let saved_mask = mask_bits();
    let mut backend =
        crate::KvmBackend::new(0x10000).expect("entry mask control requires /dev/kvm");
    // inc byte ptr [0x2000]; hlt. Each entry restarts it on the same vCPU,
    // whose installed KVM mask is what this test observes.
    backend
        .install_real_mode_program(PROGRAM, &[0xfe, 0x06, 0x00, 0x20, 0xf4])
        .unwrap();
    backend.memory.write_raw(MARKER, &[0]).unwrap();
    let start = backend.vcpu.get_regs().unwrap();
    let mut entries = 0u8;
    let mut enter = |backend: &mut crate::KvmBackend| {
        backend.vcpu.set_regs(&start).unwrap();
        assert!(matches!(backend.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
        entries += 1;
        let mut marker = [0];
        backend.memory.read_raw(MARKER, &mut marker).unwrap();
        assert_eq!(marker[0], entries);
    };
    let probe = Arc::new(RunProbe::default());
    backend.vcpu.set_run_probe(probe.clone());
    probe.arm();
    let ioctls = || probe.prepare.mask_ioctls.load(Ordering::SeqCst);
    change_sigurg(libc::SIG_UNBLOCK);
    // The first entry installs this vCPU's mask; unchanged entries reuse it.
    for _ in 0..3 {
        enter(&mut backend);
        assert_eq!(ioctls(), 1);
    }
    assert_eq!(probe.prepare.mask_installs.load(Ordering::SeqCst), 3);
    // Signal 64 stays blocked between entries; nothing else changed.
    assert_eq!(mask_bits(), (saved_mask & !SIGURG_BIT) | (1 << 63));
    // A changed thread mask reaches KVM before the next KVM_RUN. A pending
    // SIGURG that the thread blocks stays out of the entry; with the stale
    // installed mask it would end KVM_RUN with EINTR instead.
    change_sigurg(libc::SIG_BLOCK);
    // SAFETY: a thread-directed signal to this live test thread.
    assert_eq!(
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGURG) },
        0
    );
    enter(&mut backend);
    assert_eq!(ioctls(), 2);
    enter(&mut backend);
    assert_eq!(ioctls(), 2);
    // Unblocking delivers or discards the pending SIGURG on this thread only.
    change_sigurg(libc::SIG_UNBLOCK);
    // SAFETY: restore this thread's complete original mask.
    unsafe {
        let mut mask = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        for signal in 1..=64 {
            if saved_mask & (1 << (signal - 1)) != 0 {
                libc::sigaddset(&mut mask, signal);
            }
        }
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()),
            0
        );
    }
}
