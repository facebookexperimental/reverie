/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Adapter from SaBRe callbacks to Reverie's shared tool interface.

use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use parking_lot::Mutex;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool as ReverieTool;
use reverie_memory::LocalMemory;
use reverie_syscalls::Addr;
use reverie_syscalls::AddrMut;
use reverie_syscalls::Errno;
use reverie_syscalls::Syscall;
use reverie_syscalls::SyscallInfo;
use syscalls::SyscallArgs;
use syscalls::Sysno;

use crate::SyscallExt;

thread_local! {
    static TAIL_INJECT_RESULT: std::cell::Cell<Option<i64>> =
        const { std::cell::Cell::new(None) };
}

/// Runs one shared Reverie tool inside a SaBRe plugin process.
///
/// SaBRe callbacks are synchronous. A handler must complete during its first
/// poll, except for [`Guest::tail_inject`], whose result is recorded before
/// its future intentionally suspends. Other pending futures fail closed with
/// `EIO` instead of blocking the guest in the plugin callback.
// AUTONOMOUS-BOT-IMPLEMENTED
pub struct ReverieAdapter<T>
where
    T: ReverieTool,
{
    tool: T,
    global_state: T::GlobalState,
    config: <T::GlobalState as GlobalTool>::Config,
    thread_states: Mutex<HashMap<i32, Arc<Mutex<T::ThreadState>>>>,
}

impl<T> ReverieAdapter<T>
where
    T: ReverieTool,
{
    /// Creates an adapter from already-initialized shared tool state.
    pub fn new(
        tool: T,
        global_state: T::GlobalState,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Self {
        Self {
            tool,
            global_state,
            config,
            thread_states: Mutex::new(HashMap::new()),
        }
    }

    /// Forwards an intercepted syscall to [`ReverieTool::handle_syscall_event`].
    pub fn handle_syscall(&self, syscall: Syscall) -> Result<usize, Errno> {
        self.dispatch_syscall(syscall, None)
    }

    /// Forwards a runtime-bookkept syscall through the shared tool.
    pub fn handle_syscall_with_inject<F>(
        &self,
        syscall: Syscall,
        mut inject: F,
    ) -> Result<usize, Errno>
    where
        F: FnMut() -> usize + Send + Sync,
    {
        self.dispatch_syscall(syscall, Some(&mut inject))
    }

    fn dispatch_syscall(
        &self,
        syscall: Syscall,
        special_inject: Option<&mut (dyn FnMut() -> usize + Send + Sync)>,
    ) -> Result<usize, Errno> {
        let original = Some(syscall.into_parts());
        let tid = current_tid();
        let pid = current_pid();
        let state = self.thread_state(tid);
        let mut state = state.lock();
        let mut guest = SabreGuest::new(
            tid,
            pid,
            &mut *state,
            &self.global_state,
            &self.config,
            original,
            special_inject,
        );

        TAIL_INJECT_RESULT.with(|slot| slot.set(None));
        match poll_once(self.tool.handle_syscall_event(&mut guest, syscall)) {
            Poll::Ready(result) => shared_result(result),
            Poll::Pending => TAIL_INJECT_RESULT.with(|slot| {
                slot.take().map_or_else(
                    || {
                        crate::eprintln!(
                            "reverie-sabre: Tool::handle_syscall_event suspended; only immediately-ready handlers and tail_inject are supported"
                        );
                        Err(Errno::EIO)
                    },
                    |result| Ok(result as usize),
                )
            }),
        }
    }

    /// Allocates the shared tool's state for a newly observed guest thread.
    pub fn handle_thread_start(&self, thread_id: u32) {
        let tid = Pid::from_raw(thread_id as i32);
        let state = self.thread_state(tid);
        let mut state = state.lock();
        let mut guest = SabreGuest::new(
            tid,
            current_pid(),
            &mut *state,
            &self.global_state,
            &self.config,
            None,
            None,
        );
        match poll_once(self.tool.handle_thread_start(&mut guest)) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: Tool::handle_thread_start failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!(
                    "reverie-sabre: Tool::handle_thread_start suspended and was dropped"
                );
            }
        }
    }

    /// Delivers the shared tool's thread-exit callback and releases its state.
    pub fn handle_thread_exit(&self, thread_id: u32) {
        let tid = Pid::from_raw(thread_id as i32);
        let state = self.thread_states.lock().remove(&tid.as_raw());
        let Some(state) = state else {
            return;
        };
        // exit/exit_group can re-enter here from Guest::inject while the
        // handler still owns this state. Blocking would deadlock a terminating
        // thread, so omit its destructor callback in that case.
        let Some(mut state_guard) = state.try_lock() else {
            return;
        };
        let state = std::mem::take(&mut *state_guard);
        drop(state_guard);

        let rpc: SabreRpc<'_, T> = SabreRpc {
            tid,
            global_state: &self.global_state,
            config: &self.config,
        };
        match poll_once(
            self.tool
                .on_exit_thread(tid, &rpc, state, ExitStatus::Exited(0)),
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: Tool::on_exit_thread failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!("reverie-sabre: Tool::on_exit_thread suspended and was dropped");
            }
        }
    }

    fn thread_state(&self, tid: Pid) -> Arc<Mutex<T::ThreadState>> {
        self.thread_states
            .lock()
            .entry(tid.as_raw())
            .or_insert_with(|| Arc::new(Mutex::new(self.tool.init_thread_state(tid, None))))
            .clone()
    }
}

fn shared_result(result: Result<i64, Error>) -> Result<usize, Errno> {
    result.map(|value| value as usize).map_err(|error| {
        error.into_errno().unwrap_or_else(|error| {
            crate::eprintln!("reverie-sabre: shared tool failed: {error}");
            Errno::EIO
        })
    })
}

fn current_pid() -> Pid {
    let pid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::getpid) };
    Pid::from_raw(pid as i32)
}

fn current_tid() -> Pid {
    let tid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::gettid) };
    Pid::from_raw(tid as i32)
}

fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    pin!(future).as_mut().poll(&mut context)
}

struct SabreRpc<'a, T>
where
    T: ReverieTool,
{
    tid: Pid,
    global_state: &'a T::GlobalState,
    config: &'a <T::GlobalState as GlobalTool>::Config,
}

#[reverie::tool]
impl<T> GlobalRPC<T::GlobalState> for SabreRpc<'_, T>
where
    T: ReverieTool,
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

/// In-process guest view used while a SaBRe syscall callback is active.
pub struct SabreGuest<'state, 'inject, T>
where
    T: ReverieTool,
{
    tid: Pid,
    pid: Pid,
    thread_state: &'state mut T::ThreadState,
    global_state: &'state T::GlobalState,
    config: &'state <T::GlobalState as GlobalTool>::Config,
    original: Option<(Sysno, SyscallArgs)>,
    special_inject: Option<&'inject mut (dyn FnMut() -> usize + Send + Sync)>,
}

impl<'state, 'inject, T> SabreGuest<'state, 'inject, T>
where
    T: ReverieTool,
{
    fn new(
        tid: Pid,
        pid: Pid,
        thread_state: &'state mut T::ThreadState,
        global_state: &'state T::GlobalState,
        config: &'state <T::GlobalState as GlobalTool>::Config,
        original: Option<(Sysno, SyscallArgs)>,
        special_inject: Option<&'inject mut (dyn FnMut() -> usize + Send + Sync)>,
    ) -> Self {
        Self {
            tid,
            pid,
            thread_state,
            global_state,
            config,
            original,
            special_inject,
        }
    }
}

#[reverie::tool]
impl<T> GlobalRPC<T::GlobalState> for SabreGuest<'_, '_, T>
where
    T: ReverieTool,
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
impl<T> Guest<T> for SabreGuest<'_, '_, T>
where
    T: ReverieTool,
{
    type Memory = LocalMemory;
    type Stack = SabreStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
        None
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
        // The legacy callback omits the trampoline register frame. Syscall
        // arguments remain available in the typed Syscall passed to the tool.
        unsafe { std::mem::zeroed() }
    }

    async fn stack(&mut self) -> Self::Stack {
        SabreStack::new()
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        let (number, args) = syscall.into_parts();
        if self.original == Some((number, args)) {
            if let Some(inject) = self.special_inject.take() {
                return Errno::from_ret(inject()).map(|value| value as i64);
            }
        }
        if matches!(
            number,
            Sysno::clone
                | Sysno::clone3
                | Sysno::fork
                | Sysno::vfork
                | Sysno::exit
                | Sysno::exit_group
        ) {
            return Err(Errno::ENOSYS);
        }

        let syscall = Syscall::from_raw(number, args);
        unsafe { syscall.call() }.map(|value| value as i64)
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        let result = match self.inject(syscall).await {
            Ok(value) => value,
            Err(errno) => -(errno.into_raw() as i64),
        };
        TAIL_INJECT_RESULT.with(|slot| slot.set(Some(result)));
        std::future::pending::<Never>().await
    }

    fn set_timer(&mut self, _schedule: TimerSchedule) -> Result<(), Error> {
        Err(Errno::ENOSYS.into())
    }

    fn set_timer_precise(&mut self, _schedule: TimerSchedule) -> Result<(), Error> {
        Err(Errno::ENOSYS.into())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        Err(Errno::ENOSYS.into())
    }
}

const STACK_CAPACITY: usize = 4096;

/// In-process scratch storage for arguments to injected syscalls.
pub struct SabreStack {
    arena: Box<[u8]>,
    offset: usize,
}

impl SabreStack {
    fn new() -> Self {
        Self {
            arena: vec![0; STACK_CAPACITY].into_boxed_slice(),
            offset: 0,
        }
    }

    fn allocation<T>(&mut self) -> *mut T {
        let base = self.arena.as_ptr() as usize;
        let align = std::mem::align_of::<T>();
        let start = align_up(base + self.offset, align) - base;
        let end = start + std::mem::size_of::<T>();
        assert!(
            end <= self.arena.len(),
            "SaBRe guest scratch stack overflow"
        );
        self.offset = end;
        unsafe { self.arena.as_mut_ptr().add(start) }.cast()
    }
}

/// Guard retaining a committed [`SabreStack`] allocation arena.
pub struct SabreStackGuard {
    _arena: Box<[u8]>,
}

impl Drop for SabreStackGuard {
    fn drop(&mut self) {}
}

impl Stack for SabreStack {
    type StackGuard = SabreStackGuard;

    fn size(&self) -> usize {
        self.offset
    }

    fn capacity(&self) -> usize {
        self.arena.len()
    }

    fn push<'stack, T>(&mut self, value: T) -> Addr<'stack, T> {
        let pointer = self.allocation::<T>();
        unsafe { pointer.write(value) };
        Addr::from_raw(pointer as usize).expect("scratch pointer must be non-null")
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        let pointer = self.allocation::<T>();
        unsafe {
            pointer
                .cast::<u8>()
                .write_bytes(0, std::mem::size_of::<T>())
        };
        AddrMut::from_raw(pointer as usize).expect("scratch pointer must be non-null")
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(SabreStackGuard { _arena: self.arena })
    }
}

fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use reverie_syscalls::SyscallArgs;
    use syscalls::Sysno;

    use super::*;

    static HANDLED: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct FixedTool;

    #[reverie::tool]
    impl ReverieTool for FixedTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            _guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            HANDLED.fetch_add(1, Ordering::Relaxed);
            Ok(123)
        }
    }

    #[test]
    fn forwards_syscalls_to_shared_tool_handler() {
        HANDLED.store(0, Ordering::Relaxed);
        let adapter = ReverieAdapter::new(FixedTool, (), ());
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(123));
        assert_eq!(HANDLED.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn default_tail_inject_executes_the_syscall() {
        #[derive(Default)]
        struct TailTool;

        #[reverie::tool]
        impl ReverieTool for TailTool {
            type GlobalState = ();
            type ThreadState = ();
        }

        let adapter = ReverieAdapter::new(TailTool, (), ());
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(
            adapter.handle_syscall(syscall),
            Ok(std::process::id() as usize)
        );
    }

    #[test]
    fn runtime_special_injector_reaches_guest_inject() {
        #[derive(Default)]
        struct TailTool;

        #[reverie::tool]
        impl ReverieTool for TailTool {
            type GlobalState = ();
            type ThreadState = ();
        }

        let adapter = ReverieAdapter::new(TailTool, (), ());
        let invoked = AtomicBool::new(false);
        let syscall = Syscall::from_raw(Sysno::exit_group, SyscallArgs::new(7, 0, 0, 0, 0, 0));
        let result = adapter.handle_syscall_with_inject(syscall, || {
            invoked.store(true, Ordering::SeqCst);
            456
        });
        assert_eq!(result, Ok(456));
        assert!(invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn runtime_special_injector_cannot_be_reused() {
        #[derive(Default)]
        struct DoubleInjectTool;

        #[reverie::tool]
        impl ReverieTool for DoubleInjectTool {
            type GlobalState = ();
            type ThreadState = ();

            async fn handle_syscall_event<G: Guest<Self>>(
                &self,
                guest: &mut G,
                syscall: Syscall,
            ) -> Result<i64, Error> {
                let first = guest.inject(syscall).await?;
                assert_eq!(guest.inject(syscall).await, Err(Errno::ENOSYS));
                Ok(first)
            }
        }

        let adapter = ReverieAdapter::new(DoubleInjectTool, (), ());
        let invoked = AtomicBool::new(false);
        let syscall = Syscall::from_raw(Sysno::clone3, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        let result = adapter.handle_syscall_with_inject(syscall, || {
            invoked.store(true, Ordering::SeqCst);
            456
        });

        assert_eq!(result, Ok(456));
        assert!(invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn rewritten_process_control_syscall_is_rejected() {
        #[derive(Default)]
        struct RewriteTool;

        #[reverie::tool]
        impl ReverieTool for RewriteTool {
            type GlobalState = ();
            type ThreadState = ();

            async fn handle_syscall_event<G: Guest<Self>>(
                &self,
                guest: &mut G,
                _syscall: Syscall,
            ) -> Result<i64, Error> {
                let clone = Syscall::from_raw(Sysno::clone, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                Ok(guest.inject(clone).await?)
            }
        }

        let adapter = ReverieAdapter::new(RewriteTool, (), ());
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Err(Errno::ENOSYS));
    }

    struct BlockingTool {
        first_entered: Arc<Barrier>,
        release_first: Arc<Barrier>,
        calls: AtomicUsize,
    }

    impl Default for BlockingTool {
        fn default() -> Self {
            Self {
                first_entered: Arc::new(Barrier::new(1)),
                release_first: Arc::new(Barrier::new(1)),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[reverie::tool]
    impl ReverieTool for BlockingTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            _guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first_entered.wait();
                self.release_first.wait();
            }
            Ok(123)
        }
    }

    #[test]
    fn blocked_handler_does_not_serialize_other_threads() {
        let first_entered = Arc::new(Barrier::new(2));
        let release_first = Arc::new(Barrier::new(2));
        let adapter = Arc::new(ReverieAdapter::new(
            BlockingTool {
                first_entered: first_entered.clone(),
                release_first: release_first.clone(),
                calls: AtomicUsize::new(0),
            },
            (),
            (),
        ));

        let first_adapter = adapter.clone();
        let first = thread::spawn(move || {
            let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
            first_adapter.handle_syscall(syscall)
        });
        first_entered.wait();

        let (tx, rx) = mpsc::channel();
        let second = thread::spawn(move || {
            let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
            tx.send(adapter.handle_syscall(syscall)).unwrap();
        });
        let second_result = rx.recv_timeout(Duration::from_secs(1));
        release_first.wait();

        assert_eq!(first.join().unwrap(), Ok(123));
        second.join().unwrap();
        assert_eq!(second_result.unwrap(), Ok(123));
    }
}
