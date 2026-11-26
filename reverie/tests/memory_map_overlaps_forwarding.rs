/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::memory_map_overlaps` through the Guest wrappers (`IntoGuest` and
//! `NativeOperationGuest`) reaches the wrapped guest's own answer, not the
//! trait's default read from `memory_map`: a guest whose list is not
//! provided but whose overlap answer is tells the two apart, so a wrapper
//! that dropped its forward fails here.

use reverie::Error;
use reverie::FactError;
use reverie::GlobalRPC;
use reverie::Guest;
use reverie::IntoGuest;
use reverie::NativeOperationGuest;
use reverie::Never;
use reverie::Pid;
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

/// A thread state that is its own view (`AsRef` and `AsMut` of itself), as
/// `IntoGuest` asks of the state of the Tool it adapts.
type State = Vec<u8>;

/// A Tool that is its own view, as `IntoGuest` asks of the Tool it adapts.
#[derive(Default)]
struct OverlapTool;

impl AsMut<OverlapTool> for OverlapTool {
    fn as_mut(&mut self) -> &mut OverlapTool {
        self
    }
}

#[reverie::tool]
impl Tool for OverlapTool {
    type GlobalState = ();
    type ThreadState = State;
}

/// A guest that does not provide its list of mappings but answers whether
/// one overlaps a range: true for every range that is not empty.
#[derive(Default)]
struct AnsweringGuest {
    thread_state: State,
}

#[reverie::tool]
impl GlobalRPC<()> for AnsweringGuest {
    async fn send_rpc(&self, _message: ()) {}

    fn config(&self) -> &() {
        &()
    }
}

#[reverie::tool]
impl Guest<OverlapTool> for AnsweringGuest {
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

    fn thread_state_mut(&mut self) -> &mut State {
        &mut self.thread_state
    }

    fn thread_state(&self) -> &State {
        &self.thread_state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        // SAFETY: all-zero general registers are sufficient for this
        // callback-only test.
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

    fn memory_map_overlaps(&self, _tid: Pid, start: u64, end: u64) -> Result<bool, FactError> {
        Ok(start < end)
    }
}

/// The fake itself: its list is not provided, its answer is, so the default
/// (read from the list) and its own answer differ.
#[test]
fn the_fake_tells_the_default_from_its_own_answer() {
    let guest = AnsweringGuest::default();
    let tid = Pid::from_raw(2);
    assert_eq!(
        <AnsweringGuest as Guest<OverlapTool>>::memory_map(&guest, tid),
        Err(FactError::NotProvided)
    );
    assert_eq!(
        <AnsweringGuest as Guest<OverlapTool>>::memory_map_overlaps(&guest, tid, 0x1000, 0x2000),
        Ok(true)
    );
}

/// `IntoGuest` forwards the query to the guest it adapts.
#[test]
fn into_guest_forwards_the_overlap_query() {
    let mut guest = AnsweringGuest::default();
    let wrapper = IntoGuest::<AnsweringGuest, OverlapTool>::new(&mut guest);
    let tid = Pid::from_raw(2);
    assert_eq!(
        <IntoGuest<'_, AnsweringGuest, OverlapTool> as Guest<OverlapTool>>::memory_map_overlaps(
            &wrapper, tid, 0x1000, 0x2000
        ),
        Ok(true)
    );
}

/// `NativeOperationGuest`, with no operation bound, forwards the query to
/// the guest it wraps.
#[test]
fn native_operation_guest_forwards_the_overlap_query() {
    let mut guest = AnsweringGuest::default();
    let wrapper = NativeOperationGuest::<AnsweringGuest, OverlapTool>::optional(&mut guest, None)
        .unwrap_or_else(|_| panic!("a wrapper with no operation needs no support"));
    let tid = Pid::from_raw(2);
    assert_eq!(
        <NativeOperationGuest<'_, AnsweringGuest, OverlapTool> as Guest<OverlapTool>>::memory_map_overlaps(
            &wrapper, tid, 0x1000, 0x2000
        ),
        Ok(true)
    );
}
