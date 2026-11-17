/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live guests for the unknown-syscall policy: a guest issues a raw syscall
//! number the syscall table cannot name, and each policy's guest-visible
//! result (and, for `TrapToTool`, the Tool callback) is checked end to end.

#![cfg(target_arch = "x86_64")]

use std::sync::Mutex;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::UnknownSyscallPolicy;
use reverie::syscalls::RawSyscall;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::check_fn;

/// No `Sysno` in the x86_64 table this crate was built with, one past
/// its last entry, whatever the host kernel implements there.
const UNKNOWN_NR: i64 = Sysno::last().id() as i64 + 1;

/// The unknown numbers the Tool was asked about, in order.
#[derive(Default)]
struct Observed(Mutex<Vec<u64>>);

#[reverie::global_tool]
impl GlobalTool for Observed {
    type Config = ();
    type Request = u64;
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, nr: u64) {
        self.0.lock().unwrap().push(nr);
    }
}

fn none_with(policy: UnknownSyscallPolicy) -> Subscription {
    let mut subscriptions = Subscription::none();
    subscriptions.set_unknown_syscall_policy(policy);
    subscriptions
}

/// Answers unknown numbers with `-ENOSYS` at a backend-handled stop.
#[derive(Default)]
struct EnosysTool;

#[reverie::tool]
impl Tool for EnosysTool {
    type GlobalState = Observed;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        none_with(UnknownSyscallPolicy::Enosys)
    }
}

/// Answers unknown numbers with `-ENOSYS` in the kernel filter. Its
/// unknown-syscall hook records any call, so a test can prove none ran.
#[derive(Default)]
struct FastTool;

#[reverie::tool]
impl Tool for FastTool {
    type GlobalState = Observed;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        none_with(UnknownSyscallPolicy::EnosysFast)
    }

    async fn handle_unknown_syscall<G: Guest<Self>>(
        &self,
        guest: &mut G,
        raw: RawSyscall,
    ) -> Result<i64, Error> {
        guest.send_rpc(raw.nr).await;
        Ok(0)
    }
}

/// Decides unknown numbers itself: records the number and answers
/// `arg0 + 1`, so the guest sees that number and arguments arrived intact.
#[derive(Default)]
struct TrapTool;

#[reverie::tool]
impl Tool for TrapTool {
    type GlobalState = Observed;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        none_with(UnknownSyscallPolicy::TrapToTool)
    }

    async fn handle_unknown_syscall<G: Guest<Self>>(
        &self,
        guest: &mut G,
        raw: RawSyscall,
    ) -> Result<i64, Error> {
        guest.send_rpc(raw.nr).await;
        Ok(raw.args.arg0 as i64 + 1)
    }
}

/// The guest half of the `ENOSYS` policies: a known but unsubscribed
/// syscall still runs, and the unknown number fails with `ENOSYS` without
/// executing.
fn guest_expects_enosys() {
    assert!(unsafe { libc::getpid() } > 0, "getpid must still run");
    let ret = unsafe { libc::syscall(UNKNOWN_NR) };
    assert_eq!(ret, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOSYS),
        "the unknown number must fail with ENOSYS"
    );
}

#[test]
fn enosys_policy_answers_enosys_without_a_callback() {
    let observed = check_fn::<EnosysTool, _>(guest_expects_enosys);
    assert!(observed.0.lock().unwrap().is_empty());
}

#[test]
fn enosys_fast_answers_enosys_without_a_stop() {
    // FastTool records any unknown-syscall callback; under EnosysFast the
    // kernel answers inline, so there is no stop and no callback.
    let observed = check_fn::<FastTool, _>(guest_expects_enosys);
    assert!(observed.0.lock().unwrap().is_empty());
}

#[test]
fn trap_to_tool_lets_the_tool_answer() {
    let observed = check_fn::<TrapTool, _>(|| {
        let ret = unsafe { libc::syscall(UNKNOWN_NR, 41_i64) };
        assert_eq!(ret, 42, "the Tool answers arg0 + 1");
    });
    assert_eq!(
        observed.0.lock().unwrap().as_slice(),
        [UNKNOWN_NR as u64],
        "the Tool must be asked about the unknown number exactly once"
    );
}
