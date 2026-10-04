/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
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
        assert_eq!(mask_bits(), saved_mask);
        assert!(same_affinity(&affinity().unwrap(), &saved_affinity));
        assert!(!reserved_pending());
        assert!(gate.pending_failure().is_none());
        if tracked {
            assert_eq!(backend.vcpu.read_clock().unwrap(), 0);
            assert!(!backend.vcpu.clock.binding.as_ref().unwrap().enabled);
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
    let marker = backend.vcpu.get_regs().unwrap().rsp - 8;
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
        // This hook is after real disable/read/affinity restoration and before
        // RunEntry withdraws or acknowledges. No fake perf value or EINTR.
        assert!(!clock.binding.as_ref().unwrap().enabled);
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
    assert_eq!(mask_bits(), saved_mask);
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
    assert!(!backend.vcpu.clock.binding.as_ref().unwrap().enabled);
    assert!(same_affinity(&affinity().unwrap(), &saved_affinity));
    assert_eq!(
        backend.vcpu.get_regs().unwrap().rip,
        baseline.vcpu.get_regs().unwrap().rip
    );
    assert_eq!(probe.tracked_runs.load(Ordering::SeqCst), 2);
}
