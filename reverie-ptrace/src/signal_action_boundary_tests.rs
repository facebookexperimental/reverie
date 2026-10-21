/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Original-entry characterization using the existing ptrace injection API.
//! This does not exercise an owned action's private syscall-entry machinery.

use std::sync::Mutex;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Signal;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

use crate::testing::test_fn_with_config;

const QUEUED_VALUE: i32 = 0x51a7_1301;

// Linux x86-64's kernel action ABI, independent of any proposed owned API.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RawAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Observation {
    OriginalEntry,
    Queued(Vec<u8>),
    Injected(Result<i64, i32>),
    Signal(Vec<u8>),
}

#[derive(Default)]
struct Log(Mutex<Vec<Observation>>);

#[async_trait]
impl GlobalTool for Log {
    type Request = Observation;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, request: Observation) {
        self.0.lock().unwrap().push(request);
    }
}

#[derive(Clone, Debug, Default)]
struct BoundaryTool;

#[reverie::tool]
impl Tool for BoundaryTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::rt_sigaction]);
        subscriptions
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        if nr != Sysno::rt_sigaction
            || args.arg0 != libc::SIGALRM as usize
            || args.arg1 == 0
            || args.arg2 == 0
        {
            guest.tail_inject(syscall).await;
        }
        assert_eq!(guest.signal_info(), None, "not a held-signal callback");
        guest.send_rpc(Observation::OriginalEntry).await;
        let info = queued_info();
        // The actual tracee is stopped at its original entry throughout this
        // send. No timing guess or test-only backend hook selects the arrival.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_tgsigqueueinfo,
                    guest.pid().as_raw(),
                    guest.tid().as_raw(),
                    libc::SIGUSR1,
                    info.as_ptr(),
                )
            },
            0,
            "queue to this stopped task"
        );
        guest.send_rpc(Observation::Queued(info.to_vec())).await;
        // Identical syscall and arguments: execute the pending original once,
        // without an injection retry helper or a second action installation.
        let steps = crate::task::step_count_for_test(guest.tid());
        let result = guest.inject(syscall).await;
        assert_eq!(
            crate::task::step_count_for_test(guest.tid()),
            steps,
            "the exact original must not step a private syscall"
        );
        guest
            .send_rpc(Observation::Injected(
                result.map_err(|errno| errno.into_raw()),
            ))
            .await;
        assert_eq!(result, Ok(0), "the original action must run without retry");
        Ok(result?)
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        assert_eq!(signal, Signal::SIGUSR1, "only the causally queued signal");
        guest
            .send_rpc(Observation::Signal(
                guest
                    .signal_info()
                    .expect("actual delivery siginfo")
                    .to_vec(),
            ))
            .await;
        Ok(Some(signal))
    }
}

fn queued_info() -> [u8; 128] {
    let mut info = [0; 128];
    info[0..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
    info[16..20].copy_from_slice(&std::process::id().to_ne_bytes());
    info[20..24].copy_from_slice(&unsafe { libc::getuid() }.to_ne_bytes());
    info[24..28].copy_from_slice(&QUEUED_VALUE.to_ne_bytes());
    info
}

// Written only in the forked guest; the tracer's copy remains untouched.
static HANDLERS: AtomicUsize = AtomicUsize::new(0);
static HANDLER_INFO: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static HANDLER_MASK: AtomicU64 = AtomicU64::new(0);
static HANDLER_MASK_RESULT: AtomicI64 = AtomicI64::new(i64::MIN);

extern "C" fn handler(signal: i32, info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
    if signal == libc::SIGUSR1 && !info.is_null() {
        for (index, word) in HANDLER_INFO.iter().enumerate() {
            word.store(
                unsafe { std::ptr::read_unaligned(info.cast::<u64>().add(index)) },
                Ordering::Relaxed,
            );
        }
        let mut mask = 0u64;
        let result =
            unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK, 0, &mut mask, 8) };
        HANDLER_MASK.store(mask, Ordering::Relaxed);
        HANDLER_MASK_RESULT.store(result, Ordering::Relaxed);
    }
    HANDLERS.fetch_add(1, Ordering::Relaxed);
}

fn bit(signal: i32) -> u64 {
    1u64 << (signal - 1)
}

fn signal_mask() -> u64 {
    let mut mask = 0u64;
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK, 0, &mut mask, 8) },
        0
    );
    mask
}

fn raw_action() -> RawAction {
    let mut action = RawAction::default();
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_rt_sigaction, libc::SIGALRM, 0, &mut action, 8) },
        0
    );
    action
}

#[test]
fn original_rt_sigaction_entry_preserves_queued_signal_and_one_commit() {
    assert_eq!(std::mem::size_of::<libc::siginfo_t>(), 128);
    let expected_info = queued_info();
    let (output, log) = test_fn_with_config::<BoundaryTool, _>(
        move || {
            HANDLERS.store(0, Ordering::Relaxed);
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = handler as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
            assert_eq!(
                unsafe { libc::sigaddset(&mut action.sa_mask, libc::SIGWINCH) },
                0
            );
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) },
                0
            );
            let original_mask =
                (signal_mask() | bit(libc::SIGUSR2)) & !bit(libc::SIGUSR1) & !bit(libc::SIGWINCH);
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_rt_sigprocmask,
                        libc::SIG_SETMASK,
                        &original_mask,
                        0,
                        8,
                    )
                },
                0
            );
            assert_eq!(signal_mask(), original_mask);
            let mut pending = 0u64;
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_rt_sigpending, &mut pending, 8) },
                0
            );
            assert_eq!(pending & bit(libc::SIGUSR1), 0, "no pre-existing instance");
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_rt_sigaction,
                        libc::SIGALRM,
                        &RawAction::default(),
                        0,
                        8,
                    )
                },
                0
            );
            let initial = raw_action();
            let replacement = RawAction {
                handler: libc::SIG_IGN as u64,
                flags: libc::SA_RESTART as u64,
                restorer: 0,
                mask: bit(libc::SIGUSR2),
            };
            assert_ne!(initial, replacement);
            let mut previous = RawAction::default();
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_rt_sigaction,
                        libc::SIGALRM,
                        &replacement,
                        &mut previous,
                        8,
                    )
                },
                0
            );
            // A repeated installation would overwrite `previous` with the
            // replacement, so this also checks the real action ran only once.
            assert_eq!(previous, initial, "atomic previous action");
            assert_eq!(raw_action(), replacement, "actual installed action");
            assert_eq!(HANDLERS.load(Ordering::Relaxed), 1, "one real handler");
            let mut actual_info = [0u8; 128];
            for (index, word) in HANDLER_INFO.iter().enumerate() {
                actual_info[index * 8..index * 8 + 8]
                    .copy_from_slice(&word.load(Ordering::Relaxed).to_ne_bytes());
            }
            assert_eq!(
                actual_info, expected_info,
                "handler receives exact queued siginfo"
            );
            assert_eq!(HANDLER_MASK_RESULT.load(Ordering::Relaxed), 0);
            assert_eq!(
                HANDLER_MASK.load(Ordering::Relaxed),
                original_mask | bit(libc::SIGUSR1) | bit(libc::SIGWINCH),
                "real handler temporary mask"
            );
            assert_eq!(signal_mask(), original_mask, "mask restored after handler");
        },
        (),
        true,
    )
    .expect("normal ptrace completion without hidden fatal cleanup");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "guest assertions: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        log.0.into_inner().unwrap(),
        [
            Observation::OriginalEntry,
            Observation::Queued(expected_info.to_vec()),
            Observation::Injected(Ok(0)),
            Observation::Signal(expected_info.to_vec()),
        ],
        "one exact original exit precedes the sole Tool signal callback"
    );
}
