/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! DynamoRIO backend prototype for in-process Reverie tools.
//!
//! The native client performs hot-path instruction rewriting while this crate
//! adapts DynamoRIO events to Reverie's shared [`reverie::Tool`] and
//! [`reverie::Guest`] contracts.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::ffi::c_void;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use reverie::Error;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_memory::LocalMemory;
use serde::Deserialize;
use serde::Serialize;

/// Native callback used to issue a syscall with DynamoRIO bookkeeping.
pub type SyscallInvoker = unsafe extern "C" fn(usize, i64, *const u64) -> i64;

/// Native callback used to translate DynamoRIO's machine context.
pub type RegisterReader = unsafe extern "C" fn(usize, *mut libc::user_regs_struct) -> i32;

/// In-process guest state passed to a Reverie tool handler.
pub struct DbiGuest<'a, T>
where
    T: Tool,
{
    context: usize,
    tid: Pid,
    pid: Pid,
    ppid: Option<Pid>,
    branch_count: u64,
    thread_state: &'a mut T::ThreadState,
    global_state: &'a T::GlobalState,
    config: &'a <T::GlobalState as GlobalTool>::Config,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
}

impl<'a, T> DbiGuest<'a, T>
where
    T: Tool,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        context: usize,
        tid: Pid,
        pid: Pid,
        ppid: Option<Pid>,
        branch_count: u64,
        thread_state: &'a mut T::ThreadState,
        global_state: &'a T::GlobalState,
        config: &'a <T::GlobalState as GlobalTool>::Config,
        invoke_syscall: SyscallInvoker,
        read_registers: RegisterReader,
    ) -> Self {
        Self {
            context,
            tid,
            pid,
            ppid,
            branch_count,
            thread_state,
            global_state,
            config,
            invoke_syscall,
            read_registers,
        }
    }
}

#[reverie::tool]
impl<T> GlobalRPC<T::GlobalState> for DbiGuest<'_, T>
where
    T: Tool,
{
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        self.global_state.receive_rpc(self.tid, message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.config
    }
}

#[reverie::tool]
impl<T> Guest<T> for DbiGuest<'_, T>
where
    T: Tool,
{
    type Memory = LocalMemory;
    type Stack = UnsupportedStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
        self.ppid
    }

    fn memory(&self) -> Self::Memory {
        LocalMemory::new()
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.thread_state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.thread_state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        let mut regs = unsafe { std::mem::zeroed() };
        let read = unsafe { (self.read_registers)(self.context, &mut regs) };
        assert_ne!(read, 0, "DynamoRIO failed to translate the guest registers");
        regs
    }

    async fn stack(&mut self) -> Self::Stack {
        UnsupportedStack
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        let (number, args) = syscall.into_parts();
        let args = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        let result =
            unsafe { (self.invoke_syscall)(self.context, number.id() as i64, args.as_ptr()) };
        Errno::from_ret(result as usize).map(|value| value as i64)
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, _syscall: S) -> Never {
        panic!("tail injection is not implemented by the DynamoRIO prototype")
    }

    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(Errno::ENOSYS.into())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(Errno::ENOSYS.into())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        Ok(self.branch_count)
    }
}

/// Placeholder stack implementation for the initial backend prototype.
pub struct UnsupportedStack;

/// Guard returned by [`UnsupportedStack`].
pub struct UnsupportedStackGuard;

impl Drop for UnsupportedStackGuard {
    fn drop(&mut self) {}
}

impl Stack for UnsupportedStack {
    type StackGuard = UnsupportedStackGuard;

    fn size(&self) -> usize {
        0
    }

    fn capacity(&self) -> usize {
        0
    }

    fn push<'stack, T>(&mut self, _value: T) -> Addr<'stack, T> {
        panic!("guest stack allocation is not implemented by the DynamoRIO prototype")
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        panic!("guest stack allocation is not implemented by the DynamoRIO prototype")
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Err(Errno::ENOSYS)
    }
}

/// Per-thread state used by the prototype tool.
#[repr(C)]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrototypeCounters {
    /// Branches observed by inline DynamoRIO instrumentation.
    pub branches: u64,
    /// Syscall entry events observed by DynamoRIO.
    pub observed_syscalls: u64,
    /// Syscalls executed through [`Guest::inject`] and suppressed at entry.
    pub rewritten_syscalls: u64,
}

/// Tool used by the standalone prototype client.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrototypeTool;

#[reverie::tool]
impl Tool for PrototypeTool {
    type GlobalState = ();
    type ThreadState = PrototypeCounters;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.thread_state_mut().rewritten_syscalls += 1;
        Ok(guest.inject(syscall).await?)
    }
}

fn run_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the prototype tool handler must not suspend"),
    }
}

static PROTOTYPE_TOOL: PrototypeTool = PrototypeTool;
static GLOBAL_STATE: () = ();
static CONFIG: () = ();
static TOTAL_BRANCHES: AtomicU64 = AtomicU64::new(0);
static TOTAL_SYSCALLS: AtomicU64 = AtomicU64::new(0);
static TOTAL_REWRITTEN: AtomicU64 = AtomicU64::new(0);

/// Initializes the prototype state for the current application thread.
///
/// # Safety
///
/// `counters` must point to aligned, writable storage for one counter value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_thread_init(counters: *mut PrototypeCounters) {
    unsafe { counters.write(PrototypeCounters::default()) };
}

/// Handles a DynamoRIO pre-syscall event.
///
/// Returning one asks the native client to suppress the original syscall and
/// install `result`; returning zero leaves the syscall unchanged.
///
/// # Safety
///
/// The context and callback pointers must remain valid for the call. `counters`
/// and `result` must be writable, and `args` must address six syscall arguments.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_pre_syscall(
    context: *mut c_void,
    counters: *mut PrototypeCounters,
    tid: i32,
    pid: i32,
    sysnum: i64,
    args: *const u64,
    branches: u64,
    result: *mut i64,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> i32 {
    let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let counters = unsafe { &mut *counters };
        counters.branches = branches;
        counters.observed_syscalls += 1;
        TOTAL_BRANCHES.store(branches, Ordering::Relaxed);
        TOTAL_SYSCALLS.fetch_add(1, Ordering::Relaxed);

        if sysnum != libc::SYS_write {
            return false;
        }

        let raw_args = unsafe { std::slice::from_raw_parts(args, 6) };
        let syscall = Syscall::from_raw(
            Sysno::write,
            SyscallArgs::new(
                raw_args[0] as usize,
                raw_args[1] as usize,
                raw_args[2] as usize,
                raw_args[3] as usize,
                raw_args[4] as usize,
                raw_args[5] as usize,
            ),
        );
        let mut guest = DbiGuest::new(
            context as usize,
            Pid::from_raw(tid),
            Pid::from_raw(pid),
            None,
            branches,
            counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke_syscall,
            read_registers,
        );
        let value = match run_ready(PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall)) {
            Ok(value) => value,
            Err(Error::Errno(errno)) => -(errno.into_raw() as i64),
            Err(_) => -(Errno::EIO.into_raw() as i64),
        };
        unsafe { result.write(value) };
        TOTAL_REWRITTEN.fetch_add(1, Ordering::Relaxed);
        true
    }));

    match handled {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

/// Returns process-wide prototype counters accumulated at syscall boundaries.
///
/// # Safety
///
/// Each output pointer must be aligned and writable for one `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_totals(
    branches: *mut u64,
    syscalls: *mut u64,
    rewritten: *mut u64,
) {
    unsafe {
        branches.write(TOTAL_BRANCHES.load(Ordering::Relaxed));
        syscalls.write(TOTAL_SYSCALLS.load(Ordering::Relaxed));
        rewritten.write(TOTAL_REWRITTEN.load(Ordering::Relaxed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn invoke(_context: usize, sysnum: i64, args: *const u64) -> i64 {
        assert_eq!(sysnum, libc::SYS_write);
        unsafe { *args.add(2) as i64 }
    }

    unsafe extern "C" fn read_regs(_context: usize, regs: *mut libc::user_regs_struct) -> i32 {
        unsafe { (*regs).rip = 0x1234 };
        1
    }

    #[test]
    fn prototype_tool_uses_shared_guest_contract() {
        let mut counters = PrototypeCounters::default();
        let syscall = Syscall::from_raw(Sysno::write, SyscallArgs::new(1, 0x1000, 7, 0, 0, 0));
        let mut guest = DbiGuest::new(
            0,
            Pid::from_raw(10),
            Pid::from_raw(10),
            None,
            99,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs,
        );

        assert_eq!(
            run_ready(PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall)).unwrap(),
            7
        );
        assert_eq!(guest.thread_state().rewritten_syscalls, 1);
        assert_eq!(guest.read_clock().unwrap(), 99);
        assert_eq!(run_ready(guest.regs()).rip, 0x1234);
    }
}
