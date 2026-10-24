/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! Actual failed-kernel-leaf and genuine signal-frame component controls.
//! Issue/immutable-successor/protected mapping authority is explicitly modeled;
//! Tool and guest FS are the same actual FS in this fixture. No admission,
//! successful exec, runtime statistics transfer or split-FS isolation is proved.

use std::sync::Mutex;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::*;
use crate::guest::context::RegisterContext;
use crate::guest::continuation::ContinuationHandlers;
use crate::guest::continuation::NativeExecResumeReceipt;
use crate::guest::continuation::{self};
use crate::guest::event::InstructionEventKind;
use crate::trap::frame::SignalFrame;

static HANDLER_MASK: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicU64 = AtomicU64::new(0);
static FINAL_CHECKS: AtomicU64 = AtomicU64::new(0);
static EXPECTED_NUMBER: AtomicI64 = AtomicI64::new(0);
static EXPECTED_ARGS: Mutex<[u64; 6]> = Mutex::new([0; 6]);
static PREVIOUS: Mutex<Option<NativeExecResumeReceipt>> = Mutex::new(None);
const RESUME_MASK: u64 = 1_u64 << (libc::SIGUSR1 - 1);
const MISSING: &[u8] = b"/proc/self/fd/-1\0";
const COMPLETE: &[u8] = b"NATIVE_EXEC_LEAF_ENOENT_COMPONENT_OK\n";

unsafe extern "C" fn kernel_signal(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    assert_eq!(signal, libc::SIGSYS);
    assert_eq!(unsafe { (*info).si_code }, 1); // SYS_SECCOMP, never user SIGSYS
    let mut frame = unsafe { SignalFrame::native_exec_test_sigsys_frame(context, info) }.unwrap();
    if continuation::complete(&mut frame).unwrap() {
        return;
    }
    let number = frame.register(libc::REG_RAX as usize);
    if matches!(number, libc::SYS_execve | libc::SYS_execveat) {
        let mut physical = 0;
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut physical)) }
            .unwrap();
        HANDLER_MASK.store(physical, Ordering::Relaxed);
        let instruction = (frame.register(libc::REG_RIP as usize) as u64)
            .checked_sub(2)
            .unwrap();
        let entry = unsafe { continuation::prepare_signal(instruction, &mut frame) }
            .unwrap()
            .unwrap();
        frame.set_register(libc::REG_RIP as usize, entry as i64);
    } else {
        // Component setup/assertion libc calls, not guest instrumentation or
        // coverage credit. Their physical effect uses the exact private gate.
        let args = [
            libc::REG_RDI,
            libc::REG_RSI,
            libc::REG_RDX,
            libc::REG_R10,
            libc::REG_R8,
            libc::REG_R9,
        ]
        .map(|r| frame.register(r as usize) as u64);
        let result = unsafe { crate::trap::raw_syscall6(number, args) };
        frame.set_register(libc::REG_RAX as usize, result);
    }
}

unsafe fn continued_exec(context: *mut RegisterContext, pkru: &mut Option<u32>) {
    let c = unsafe { &mut *context };
    let event = SyscallEvent {
        number: c.rax as i64,
        args: [c.rdi, c.rsi, c.rdx, c.r10, c.r8, c.r9],
        instruction_pointer: c.instruction_pointer,
        result: 0,
        context: context as usize,
        dispatch: SyscallDispatch::Fallback,
        guest_pkru: *pkru,
    };
    assert_eq!(event.number, EXPECTED_NUMBER.load(Ordering::Relaxed));
    assert_eq!(event.args, *EXPECTED_ARGS.lock().unwrap());
    let receipt = continuation::native_exec_resume_receipt(&event).unwrap();
    assert_eq!(receipt.signal_mask(), RESUME_MASK);
    assert_eq!(
        HANDLER_MASK.load(Ordering::Relaxed),
        RESUME_MASK | (1_u64 << (libc::SIGUSR2 - 1)) | (1_u64 << (libc::SIGSYS - 1))
    );
    assert_ne!(receipt.signal_mask(), HANDLER_MASK.load(Ordering::Relaxed));
    continuation::native_exec_test_binding_controls(&event);
    if let Some(previous) = PREVIOUS.lock().unwrap().replace(receipt) {
        assert!(!previous.recheck(&event));
        assert_eq!(
            receipt.generation(),
            previous.generation().checked_add(1).unwrap()
        );
    }
    let tid = crate::guest::exec_private::callback_native_tid().unwrap();
    let mut site = ExecSite {
        tid,
        pid: tid,
        main_tid: tid,
        in_handler: true,
        staged_signals: false,
        ending: false,
        signal_delivery: false,
        guest_filter: false,
        guest_signal_mode: false,
        fork_state: false,
    };
    let cut = ExecCut::capture(&event, &site).unwrap();
    assert_eq!(cut.native().physical_mask, receipt.signal_mask());
    site.staged_signals = true;
    assert!(ExecCut::capture(&event, &site).is_err());
    site.staged_signals = false;
    site.guest_signal_mode = true;
    assert!(ExecCut::capture(&event, &site).is_err());
    for changed_mask in [
        RESUME_MASK | (1_u64 << (libc::SIGUSR2 - 1)),
        RESUME_MASK | (1_u64 << (libc::SIGSYS - 1)),
    ] {
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&changed_mask), None) }
            .unwrap();
        // SAFETY: explicitly modeled Issue only; no exec is reached on refusal.
        assert!(matches!(
            unsafe { exec_private::IssuedNativeExecLeaf::after_issue(&cut) },
            Err(NativeExecFailure::Refused(_))
        ));
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&RESUME_MASK), None) }
            .unwrap();
    }
    // Model one separate cancelled Issue: mandatory final-check refusal must
    // remain a named refusal rather than turn into genuine ENOENT.
    let refused = unsafe { exec_private::IssuedNativeExecLeaf::after_issue(&cut) }.unwrap();
    assert!(matches!(
        unsafe {
            refused.call(|| {
                Err(NativeExecFailure::Refused(refusal(
                    "component final exact check refused",
                )))
            })
        },
        Err(NativeExecFailure::Refused(_))
    ));
    let leaf = unsafe { exec_private::IssuedNativeExecLeaf::after_issue(&cut) }.unwrap();
    let before = *cut.native();
    // SAFETY: this fixture models trusted Issue/bootstrap authority solely to
    // reach a missing path. Genuine kernel frame/continuation/physical facts
    // are used. No production installer, successful target or native admission
    // proof is supplied or credited. The concrete driver's sealed-runtime
    // check is absent; this callback proves mandatory ordering only.
    let returned = unsafe {
        leaf.call(|| {
            assert_eq!(
                continuation::native_exec_resume_receipt(&event),
                Some(receipt)
            );
            FINAL_CHECKS.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
    .unwrap();
    assert_eq!(returned.errno, Errno::ENOENT);
    assert_eq!(returned.pkru, *pkru); // actual ENOENT preserves guest permissions
    assert_eq!(exec_private::native_exec_callback_facts(), Some(before));
    assert_eq!(
        continuation::native_exec_resume_receipt(&event),
        Some(receipt)
    );
    *pkru = returned.pkru;
    c.rax = -i64::from(returned.errno.into_raw()) as u64;
    CALLS.fetch_add(1, Ordering::Relaxed);
}
unsafe fn no_instruction(_: *mut RegisterContext, _: InstructionEventKind) {
    panic!("component never dispatches an instruction");
}

unsafe fn guest_exec(number: i64, args: [u64; 6]) -> i64 {
    let result;
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") number => result,
        in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
        in("r10") args[3], in("r8") args[4], in("r9") args[5],
        lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}

fn run_actual_missing_path() {
    assert_eq!(
        unsafe { libc::access(MISSING.as_ptr().cast(), libc::F_OK) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOENT)
    );
    let mut control = exec_private::native_exec_mock_callback();
    let clear = Box::new(std::sync::atomic::AtomicI32::new(1));
    let mut robust = Box::new([0_usize; 3]);
    robust[0] = robust.as_ptr() as usize; // empty, genuine robust-list head
    let tid = exec_private::callback_native_tid().unwrap();
    // Legitimate fixture registrations: setters are never used as queries.
    assert_eq!(
        unsafe {
            exec_private::physical_syscall(
                libc::SYS_set_tid_address,
                [(&*clear as *const _) as u64, 0, 0, 0, 0, 0],
                None,
            )
        }
        .result,
        i64::from(tid)
    );
    assert_eq!(
        unsafe {
            exec_private::physical_syscall(
                libc::SYS_set_robust_list,
                [
                    robust.as_ptr() as u64,
                    core::mem::size_of_val(&*robust) as u64,
                    0,
                    0,
                    0,
                    0,
                ],
                None,
            )
        }
        .result,
        0
    );
    let registrations = exec_private::callback_kernel_registrations().unwrap();
    assert_eq!(registrations.clear_tid, (&*clear as *const _) as u64);
    assert_eq!(registrations.robust_head, robust.as_ptr() as u64);
    crate::trap::prepare_private_signal_features().unwrap();
    unsafe {
        continuation::register_handlers(ContinuationHandlers {
            syscall: continued_exec,
            instruction: no_instruction,
        })
    }
    .unwrap();
    continuation::initialize().unwrap();
    let action = crate::signal::KernelSigaction {
        handler: kernel_signal as *const () as u64,
        flags: (libc::SA_SIGINFO | crate::signal::SA_RESTORER) as u64,
        restorer: crate::signal::signal_restorer(),
        mask: 1_u64 << (libc::SIGUSR2 - 1),
    };
    unsafe { crate::signal::raw_sigaction(libc::SIGSYS, Some(&action), None) }.unwrap();
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&RESUME_MASK), None) }.unwrap();
    exec_private::native_exec_test_enter_guest(&mut control);
    let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates_with_signal_return(
        crate::trap::trusted_gate(),
        crate::trap::guest_syscall_gate(),
        Some(crate::signal::signal_restorer_return_ip()),
    )
    .unwrap();
    unsafe { filter.install() }.unwrap();
    let argv = [MISSING.as_ptr() as u64, 0];
    let env = [0_u64];
    let execve = [
        MISSING.as_ptr() as u64,
        argv.as_ptr() as u64,
        env.as_ptr() as u64,
        0x77,
        0x88,
        0x99,
    ];
    let execveat = [
        libc::AT_FDCWD as i64 as u64,
        MISSING.as_ptr() as u64,
        argv.as_ptr() as u64,
        env.as_ptr() as u64,
        0,
        0x99,
    ];
    for (number, args) in [
        (libc::SYS_execve, execve),
        (libc::SYS_execve, execve),
        (libc::SYS_execveat, execveat),
    ] {
        EXPECTED_NUMBER.store(number, Ordering::Relaxed);
        *EXPECTED_ARGS.lock().unwrap() = args;
        assert_eq!(
            unsafe { guest_exec(number, args) },
            -i64::from(libc::ENOENT)
        );
        let mut mask = 0;
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }
            .unwrap();
        assert_eq!(mask, RESUME_MASK);
    }
    assert_eq!(CALLS.load(Ordering::Relaxed), 3);
    assert_eq!(FINAL_CHECKS.load(Ordering::Relaxed), 3);
    assert_eq!(continuation::owned_observation(0), 3);
    assert_eq!(continuation::owned_observation(1), 3);
    assert_eq!(continuation::owned_observation(2), 3);
    // Retain real kernel registration storage and published control to exit.
    Box::leak(clear);
    Box::leak(robust);
    Box::leak(control);
    assert_eq!(
        unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_write,
                [
                    libc::STDOUT_FILENO as u64,
                    COMPLETE.as_ptr() as u64,
                    COMPLETE.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
        },
        COMPLETE.len() as i64
    );
}

#[test]
fn actual_enoent_leaf_keeps_genuine_resume_mask_fs_and_kernel_registrations() {
    const CHILD: &str = "REVERIE_NATIVE_EXEC_LEAF_COMPONENT";
    if std::env::var_os(CHILD).is_none() {
        // Fresh exact-test process avoids inherited process-wide handlers and
        // latches; direct child fork is still needed for actual PID == TID.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "guest::native_exec::native_exec_leaf_tests::actual_enoent_leaf_keeps_genuine_resume_mask_fs_and_kernel_registrations",
                "--nocapture", "--test-threads=1"])
            .env(CHILD,"1").output().unwrap();
        assert!(
            status.status.success(),
            "isolated component failed: {}; stdout={}; stderr={}",
            status.status,
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr)
        );
        assert_eq!(
            status
                .stdout
                .windows(COMPLETE.len())
                .filter(|item| *item == COMPLETE)
                .count(),
            1,
            "exact-test child must actually finish the physical component control"
        );
        return;
    }
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Wall bound on the actual leaf/fork child; SIGALRM stays unblocked.
        unsafe {
            crate::signal::raw_sigaction(
                libc::SIGALRM,
                Some(&crate::signal::KernelSigaction::default()),
                None,
            )
            .unwrap();
            libc::alarm(10);
        }
        let status = if std::panic::catch_unwind(run_actual_missing_path).is_ok() {
            0
        } else {
            125
        };
        unsafe { crate::trap::raw_syscall6(libc::SYS_exit_group, [status, 0, 0, 0, 0, 0]) };
        unreachable!();
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "child wait status {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
