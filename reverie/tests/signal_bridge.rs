/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::pin::pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use reverie::Error;
use reverie::GlobalRPC;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Signal;
use reverie::SignalEvent;
use reverie::SignalTarget;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::LocalMemory;
use reverie::syscalls::SyscallInfo;

#[derive(Default)]
struct TestStack;

#[derive(Default)]
struct TestStackGuard;

impl Drop for TestStackGuard {
    fn drop(&mut self) {}
}

impl Stack for TestStack {
    type StackGuard = TestStackGuard;

    fn size(&self) -> usize {
        0
    }

    fn capacity(&self) -> usize {
        0
    }

    fn push<'stack, T>(&mut self, _value: T) -> Addr<'stack, T> {
        panic!("test stack is never used")
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        panic!("test stack is never used")
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(TestStackGuard)
    }
}

#[derive(Default)]
struct TestGuest {
    thread_state: (),
}

#[reverie::tool]
impl GlobalRPC<()> for TestGuest {
    async fn send_rpc(&self, _message: ()) {}

    fn config(&self) -> &() {
        &()
    }
}

#[reverie::tool]
impl<T: Tool<GlobalState = (), ThreadState = ()>> Guest<T> for TestGuest {
    type Memory = LocalMemory;
    type Stack = TestStack;

    fn tid(&self) -> Pid {
        Pid::from_raw(2)
    }

    fn pid(&self) -> Pid {
        Pid::from_raw(2)
    }

    fn ppid(&self) -> Option<Pid> {
        None
    }

    // A test fake with no backend runtime.
    fn is_backend_runtime_bootstrap(&self) -> bool {
        false
    }

    fn memory(&self) -> Self::Memory {
        LocalMemory::new()
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        &mut self.thread_state
    }

    fn thread_state(&self) -> &T::ThreadState {
        &self.thread_state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        // SAFETY: all-zero general registers are sufficient for this callback-only test.
        unsafe { std::mem::zeroed() }
    }

    async fn stack(&mut self) -> Self::Stack {
        TestStack
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, _syscall: S) -> Result<i64, Errno> {
        Err(Errno::ENOSYS)
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, _syscall: S) -> Never {
        panic!("test guest cannot tail-inject")
    }

    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Ok(())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Ok(())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        Ok(0)
    }
}

struct LegacyTool {
    response: Option<Signal>,
    calls: AtomicUsize,
}

impl Default for LegacyTool {
    fn default() -> Self {
        Self {
            response: Some(Signal::SIGUSR1),
            calls: AtomicUsize::new(0),
        }
    }
}

#[reverie::tool]
impl Tool for LegacyTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        _signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.response)
    }
}

#[derive(Default)]
struct StructuredTool;

#[reverie::tool]
impl Tool for StructuredTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        let mut info = event.siginfo();
        info[0..4].copy_from_slice(&libc::SIGUSR2.to_ne_bytes());
        info[127] ^= 0xff;
        Ok(Some(SignalEvent::new(libc::SIGUSR2, info, event.target())?))
    }
}

fn event(signal: i32) -> SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&signal.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_USER.to_ne_bytes());
    info[127] = 0x5a;
    SignalEvent::new(
        signal,
        info,
        SignalTarget::Thread {
            pid: Pid::from_raw(2),
            tid: Pid::from_raw(2),
        },
    )
    .unwrap()
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test callback unexpectedly yielded"),
    }
}

#[test]
fn legacy_bridge_preserves_unchanged_event_bytes_and_suppression() {
    let input = event(libc::SIGUSR1);
    let mut guest = TestGuest::default();
    let tool = LegacyTool::default();
    assert_eq!(
        ready(tool.handle_structured_signal_event(&mut guest, input)),
        Ok(Some(input)),
    );
    assert_eq!(tool.calls.load(Ordering::SeqCst), 1);

    let suppressor = LegacyTool {
        response: None,
        calls: AtomicUsize::new(0),
    };
    assert_eq!(
        ready(suppressor.handle_structured_signal_event(&mut guest, input)),
        Ok(None),
    );
    assert_eq!(suppressor.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn legacy_bridge_refuses_incoherent_replacement_and_raw_realtime_signal() {
    let mut guest = TestGuest::default();
    let replacer = LegacyTool {
        response: Some(Signal::SIGUSR2),
        calls: AtomicUsize::new(0),
    };
    assert_eq!(
        ready(replacer.handle_structured_signal_event(&mut guest, event(libc::SIGUSR1))),
        Err(Errno::ENOSYS),
    );
    assert_eq!(replacer.calls.load(Ordering::SeqCst), 1);

    let realtime = LegacyTool::default();
    assert_eq!(
        ready(realtime.handle_structured_signal_event(&mut guest, event(64))),
        Err(Errno::ENOSYS),
    );
    assert_eq!(realtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn structured_hook_can_replace_signal_with_coherent_explicit_siginfo() {
    let input = event(libc::SIGUSR1);
    let mut guest = TestGuest::default();
    let output = ready(StructuredTool.handle_structured_signal_event(&mut guest, input))
        .unwrap()
        .unwrap();

    assert_eq!(output.signal(), libc::SIGUSR2);
    assert_eq!(
        i32::from_ne_bytes(output.siginfo()[0..4].try_into().unwrap()),
        libc::SIGUSR2,
    );
    assert_eq!(output.siginfo()[127], input.siginfo()[127] ^ 0xff);
    assert_eq!(output.target(), input.target());
}

#[test]
fn child_exit_signal_default_refuses_before_publication() {
    let mut guest = TestGuest::default();
    let mut info = event(libc::SIGCHLD).siginfo();
    info[8..12].copy_from_slice(&libc::CLD_EXITED.to_ne_bytes());
    info[16..20].copy_from_slice(&41_i32.to_ne_bytes());
    info[24..28].copy_from_slice(&37_i32.to_ne_bytes());
    let input = SignalEvent::new(
        libc::SIGCHLD,
        info,
        SignalTarget::Process {
            pid: Pid::from_raw(2),
        },
    )
    .unwrap();
    assert_eq!(
        ready(<TestGuest as Guest<StructuredTool>>::queue_child_exit_signal(&mut guest, input)),
        reverie::ChildExitSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ChildExitSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    );
}
