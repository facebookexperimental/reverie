/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::marker::PhantomData;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;
use core::sync::atomic::Ordering::*;
use core::time::Duration;
use std::time::Instant;

use atomic::Atomic;
use lazy_static::lazy_static;
use syscalls::raw::syscall0;
use syscalls::Sysno;

use crate::signal::guard;
use crate::slot_map::SlotKey;
use crate::slot_map::SlotMap;

lazy_static! {
    static ref SLOT_MAP: SlotMap<ThreadRepr> = SlotMap::new();
}

thread_local! {
    pub static THREAD_SLOT_KEY: Option<SlotKey> = generate_thread_and_slot_key();
}

/// We are serializing the state information directly to the bits of an unsigned
/// integer type. The layout of the bits is
///
/// 0b_xxFEDCBA
///      543210
///
/// A => New <- 1 means this is the first time this thread was seen
/// B => 1 indicates Guest state and 0 indicates Handler state
/// C => Needs to exit
/// D => Exiting (Supersedes A)
/// E => Exited (Supersedes A & B)
/// F => Forking - Indicates or clonging or vforking (Only valid in Guest state)
///
/// This pattern enables lets us update the thread's state (in the allowed ways)
/// and the thread's `needs_to_exit` flag independently and atomically
type StateRepr = u8;
type AtomicStateRepr = AtomicU8;
type ThreadRepr = (Atomic<PidTid>, AtomicStateRepr);

// We want to make sure PidTid actually fits into the the Atomic type, so here
// we check its size and that its alignment divides evenly into 8
const _: () = assert!(core::mem::size_of::<PidTid>() == 8);
const _: () = assert!(8 % core::mem::align_of::<PidTid>() == 0);

// Constants to describe the bit pattern above
const NEW_SHIFT: u8 = 0;
const NEW_MASK: u8 = 1 << NEW_SHIFT;
const HANDLER_GUEST_SHIFT: u8 = 1;
const HANDLER_GUEST_MASK: u8 = 1 << HANDLER_GUEST_SHIFT;
const NEEDS_TO_EXIT_SHIFT: u8 = 2;
const NEEDS_TO_EXIT_MASK: u8 = 1 << NEEDS_TO_EXIT_SHIFT;
const EXITED_SHIFT: u8 = 3;
const EXITED_MASK: u8 = 1 << EXITED_SHIFT;
const EXITING_SHIFT: u8 = 4;
const EXITING_MASK: u8 = 1 << EXITING_SHIFT;
const FORKING_SHIFT: u8 = 5;
const FORKING_MASK: u8 = 1 << FORKING_SHIFT;

/// Gets the value of the `needs_to_exit` flag from the thread representation.
const fn needs_to_exit(thread_repr: StateRepr) -> bool {
    (thread_repr & NEEDS_TO_EXIT_MASK) > 0
}

/// Gets the inverted value of the `not_new` flag from the thread
/// representation.
const fn is_new(thread_repr: StateRepr) -> bool {
    (thread_repr & NEW_MASK) > 0
}

/// Sets the `needs_to_exit` flag in the given representation to true.
fn store_needs_to_exit(atomic_repr: &AtomicStateRepr, ordering: Ordering) -> StateRepr {
    atomic_repr.fetch_or(NEEDS_TO_EXIT_MASK, ordering) | NEEDS_TO_EXIT_MASK
}

/// Constructs a representation of a thread from its components.
const fn build_repr(thread_state: ThreadState, needs_to_exit: bool) -> StateRepr {
    thread_state.as_u8() + (((needs_to_exit as u8) << NEEDS_TO_EXIT_SHIFT) & NEEDS_TO_EXIT_MASK)
}

/// Return the value of the forking flag in the given state
const fn is_forking(thread_rep: StateRepr) -> bool {
    thread_rep & FORKING_MASK > 0 && thread_rep & HANDLER_GUEST_MASK > 0
}

/// Set the forking flag to false in the atomic repr and return the result
fn clear_forking_flag(atomic_repr: &AtomicStateRepr, order: Ordering) -> StateRepr {
    atomic_repr.fetch_and(!FORKING_MASK, order) & !FORKING_MASK
}

/// Convenience function for getting the current thread id via a syscall
fn thread_id_syscall() -> u32 {
    // Unsafe unwrap is okay here because this syscall is guaranteed not to fail
    unsafe { syscall0(Sysno::gettid) as u32 }
}

/// Convenience function for getting the current process id via a syscall
fn process_id_syscall() -> u32 {
    // Unsafe unwrap is okay here because this syscall is guaranteed not to fail
    unsafe { syscall0(Sysno::getpid) as u32 }
}

/// Called by the `thread_local` macro (during TLS initialization) to add the
/// calling thread's metadata to the static map of all threads and store its key
/// as a thread-local variable. If the thread metadata slotmap has had inputs
/// disabled, the slotkey stored in this variable will be None
fn generate_thread_and_slot_key() -> Option<SlotKey> {
    let pid_tid = PidTid::current();
    SLOT_MAP
        .try_insert(
            pid_tid.pid,
            (
                Atomic::new(pid_tid),
                AtomicStateRepr::new(NEW_MASK | HANDLER_GUEST_MASK),
            ),
        )
        .ok()
}

#[derive(Debug, Default, Clone, Copy, Hash, PartialEq, Eq)]
pub struct PidTid {
    pub pid: u32,
    pub tid: u32,
}

impl PidTid {
    fn current() -> Self {
        PidTid {
            pid: process_id_syscall(),
            tid: thread_id_syscall(),
        }
    }
}

/// Possible error responses during a transition to/from guest execution.
#[derive(Debug, Clone, Copy)]
pub enum GuestTransitionErr {
    /// This thread needs to exit, and the caller is responsible.
    ExitNow,

    /// This thread is exiting/exited but the caller is not responsible.
    ExitingElsewhere,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ThreadState {
    Guest(bool),
    Handler,
    Exiting,
    Exited,
}

impl From<StateRepr> for ThreadState {
    fn from(state_repr: StateRepr) -> Self {
        if (state_repr & EXITED_MASK) > 0 {
            ThreadState::Exited
        } else if (state_repr & EXITING_MASK) > 0 {
            ThreadState::Exiting
        } else if (state_repr & HANDLER_GUEST_MASK) > 0 {
            ThreadState::Guest(is_forking(state_repr))
        } else {
            ThreadState::Handler
        }
    }
}

impl ThreadState {
    const fn as_u8(&self) -> u8 {
        use ThreadState::*;
        match self {
            Guest(false) => HANDLER_GUEST_MASK,
            Guest(true) => HANDLER_GUEST_MASK | FORKING_MASK,
            Handler => 0,
            Exiting => EXITING_MASK,
            Exited => EXITED_MASK,
        }
    }

    /// Writes this thread state to the given atomic thread representation and
    /// return the resulting representation.
    fn store(&self, atomic_repr: &AtomicStateRepr, ordering: Ordering) -> StateRepr {
        if *self == ThreadState::Handler {
            let handle_mask = !(HANDLER_GUEST_MASK | FORKING_MASK);
            atomic_repr.fetch_and(handle_mask, ordering) & handle_mask
        } else {
            let state_u8 = self.as_u8();
            atomic_repr.fetch_or(state_u8, ordering) | state_u8
        }
    }
}

/// Trait representing the notifications that can be raised from a thread
/// during its lifecycle
pub trait EventSink {
    fn on_new_thread(_pid_tid: PidTid) {}

    fn on_thread_exit(_pid_tid: PidTid) {}
}

#[derive(Debug, Clone, Copy)]
pub struct Thread<E: EventSink> {
    slot_key: SlotKey,

    /// True if this is the first time the thread was seen.
    new: bool,

    forking: bool,

    /// Raw representation of the thread as a unsigned integer.
    repr: StateRepr,

    /// All the fields contained in the repr.
    state: ThreadState,
    needs_to_exit: bool,

    /// Funny phantom here to let the drop checker know it doesn't need to
    /// worry about `E`
    _phantom: PhantomData<dyn Fn(E) + Send + Sync>,
}

fn get_threads_for_process<'a>(
    process_id: u32,
) -> impl Iterator<Item = (SlotKey, PidTid, &'a AtomicStateRepr)> {
    SLOT_MAP
        .entries()
        .map(|(slot_key, (atomic_pid_tid, atomic_repr))| {
            (slot_key, atomic_pid_tid.load(Relaxed), atomic_repr)
        })
        .filter(move |(_, pid_tid, _)| pid_tid.pid == process_id)
}

/// Indicates to all threads that they need to exit, and wait for all
/// threads to confirm they are exited. The closure given is a way to signal
/// to a thread by id to trigger a critical section transition which will
/// observe and handle the need to exit.
pub fn exit_all<F>(signal_guest_thread: F) -> Option<u32>
where
    F: Fn(SlotKey, PidTid),
{
    let exiting_pid = process_id_syscall();

    // Only go through the motions of exiting all threads if the disallow
    // flag is successfully set
    disallow_new_threads().then(|| {
        // Iterate through all the slots and mark each thread as
        // `needs_to_exit`. Collect the PidTids of threads that aren't
        // already exited, so we "exit_waiters" can wait for the
        get_threads_for_process(exiting_pid)
            .map(|(slot_key, pid_tid, atomic_repr)| {
                // Read each thread's state and mark it as needing to exit.
                // Marking this flag is safe even on threads that have
                // already exited because the exiting and exited flages
                // take precenence
                let state: ThreadState = store_needs_to_exit(atomic_repr, SeqCst).into();
                (slot_key, pid_tid, state)
            })
            .for_each(|(slot_key, pid_tid, state)| {
                // Signal any threads in guest state in case they are in a
                // blocking syscall, so they can exit
                if state == ThreadState::Guest(false) {
                    signal_guest_thread(slot_key, pid_tid)
                }
            });

        exiting_pid
    })
}

/// Waits for all threads to exit or for the given optional timeout to
/// expire. The boolean returned will be true if all threads exited before
/// the timeout and false if the timeout elapsed before all threads exited
pub fn wait_for_all_to_exit(process_id: u32, timeout_opt: Option<Duration>) -> bool {
    let start_time = Instant::now();

    // Spin until all the given keyed threads have exited or timeout has expired
    loop {
        if !get_threads_for_process(process_id)
            .map(|(_, _, atomic_repr)| atomic_repr.load(Relaxed))
            .map(ThreadState::from)
            .any(|state| state != ThreadState::Exited)
        {
            return true;
        }

        if let Some(timeout) = timeout_opt {
            if timeout > start_time.elapsed() {
                return false;
            }
        }
    }
}

/// Checks the slotmap to see if new inserts are allowed. This is done as an
/// atomic operation with `Acquire` ordering
fn new_threads_allowed() -> bool {
    SLOT_MAP.inserts_allowed_for_partition(process_id_syscall())
}

/// Set the slotmap to stop allowing inserts. This will instantly stop
/// new threads from being inserted into the slot map. The returned boolean
/// indicates whether the property was changed by this call or not
fn disallow_new_threads() -> bool {
    SLOT_MAP.stop_inserts_for_partition(process_id_syscall())
}

impl<E: EventSink> Thread<E> {
    /// Gets the thread data associated with the current thread. If no data is
    /// associated with the current thread, then a new instance will be created
    /// and returned associated with the current thread's id
    pub fn current() -> Option<Thread<E>> {
        let thread_slot_key = THREAD_SLOT_KEY
            .try_with(|v| *v)
            .expect("Slot key should always be readable in TLS (Even if it's None)")?;

        let (_, atomic_thread_repr) = SLOT_MAP.get(thread_slot_key)?;

        let mut result = Thread::new_with_repr(thread_slot_key, atomic_thread_repr.load(Acquire));

        // If the thread is marked as new, we need to mark the repr as no longer
        // new but keep the new field marked in the returned instance.
        if result.new {
            let _guard = guard::enter_implicit_signal_exclusion_zone();
            E::on_new_thread(PidTid::current());

            // Unset the `new` flag in the atomic repr, so no other calls to
            // current can return a "new" thread
            let mut final_repr = atomic_thread_repr.fetch_and(!NEW_MASK, Relaxed) & !NEW_MASK;

            // Lastly check the flag that indicates whether we are allowing
            // new threads. If it is true, we need to mark this new thread
            // as `needs_to_exit`.
            if !new_threads_allowed() {
                final_repr = store_needs_to_exit(atomic_thread_repr, Release);
            }

            result.update_from_repr(final_repr);
        } else if result.forking {
            let _guard = guard::enter_implicit_signal_exclusion_zone();
            // Read the actual pid-tid through syscalls
            let actual_pid_tid = PidTid::current();
            let stored_pid_tid = result.get_process_and_thread_ids();

            E::on_new_thread(actual_pid_tid);

            // Fix the stored state for this thread to match the current thread.
            // A new pid-tid here means the thread (and likely the process) is
            // new
            if actual_pid_tid != stored_pid_tid {
                result.fix_stored_state_after_fork(actual_pid_tid);
                result.new = true;
            }

            clear_forking_flag(atomic_thread_repr, SeqCst);
            result.forking = false;
        }

        Some(result)
    }

    /// Creates a new thread with the given id and representation.
    fn new_with_repr(slot_key: SlotKey, repr: StateRepr) -> Self {
        Thread {
            slot_key,
            new: is_new(repr),
            forking: is_forking(repr),
            state: repr.into(),
            needs_to_exit: needs_to_exit(repr),
            repr,
            _phantom: Default::default(),
        }
    }

    /// Get the process and thread ids associated with this thread
    pub fn get_process_and_thread_ids(&self) -> PidTid {
        unsafe { SLOT_MAP.get_unchecked(self.slot_key).0.load(Relaxed) }
    }

    fn get_atomic_repr(&self) -> &AtomicStateRepr {
        // This is safe because we are using the slot key for the thread that
        // must have been created by inserting into the slotmap.
        unsafe { &SLOT_MAP.get_unchecked(self.slot_key).1 }
    }

    /// Updates the thread state to the give value in both this object and the
    /// storage map.
    ///
    /// NOTE: This function has the side effect of updating the other fields in
    /// this instance associated with the storage representation. Specifically
    /// if the `needs_to_exit` flag gets set externally, that change will be
    /// reflected in this thread
    fn set_state(&mut self, new_thread_state: ThreadState, ordering: Ordering) -> ThreadState {
        self.update_from_repr(new_thread_state.store(self.get_atomic_repr(), ordering))
    }

    /// Attempts to set the whole representation of the thread at once, but only
    /// if the existing repr matches the one in this instance. Returns true if
    /// the cas succeeds.
    ///
    /// NOTE: The fields for this instance will be updated based on the new repr
    /// state regardless of whether the compare and swap succeeds or not.
    fn compare_and_swap_repr(&mut self, new_repr: StateRepr, ordering: Ordering) -> bool {
        let cas_result = self
            .get_atomic_repr()
            .compare_exchange(self.repr, new_repr, ordering, Relaxed);

        // Regardless of what the final state was, update this instance to match it
        match cas_result {
            Ok(new_repr) | Err(new_repr) => self.update_from_repr(new_repr),
        };

        cas_result.is_ok()
    }

    /// Updates the fields in this thread instance based on the given
    /// representation.
    fn update_from_repr(&mut self, new_repr: StateRepr) -> ThreadState {
        self.repr = new_repr;
        self.forking = is_forking(new_repr);
        self.state = new_repr.into();
        self.needs_to_exit = needs_to_exit(new_repr);
        self.state
    }

    /// Set the thread's state to indicate it is leaving the guest's execution and
    /// entering Reverie's.
    /// Note - If at any point the `need_to_exit` flag is set, this function will
    ///        start the thread exit progress
    pub fn leave_guest_execution(&mut self) -> Result<(), GuestTransitionErr> {
        self.checked_state_transition(ThreadState::Handler)
    }

    /// Set the thread's state to indicate it is leaving Reverie's control and re-entering
    /// the guest's execution
    /// Note - If at any point the `need_to_exit` flag is set, this function will
    ///        start the thread exit progress
    pub fn enter_guest_execution(&mut self) -> Result<(), GuestTransitionErr> {
        self.checked_state_transition(ThreadState::Guest(false))
    }

    /// Set the thread's state atomically to the given state, and if the needs_to_exit flag
    /// has been set before or after the change, attempt to exit and return and Result::Err
    /// indicating if the exit was successful
    fn checked_state_transition(
        &mut self,
        new_state: ThreadState,
    ) -> Result<(), GuestTransitionErr> {
        if self.needs_to_exit {
            Err(self.try_exit_during_transistion())
        } else {
            self.set_state(new_state, Release);
            if self.needs_to_exit {
                Err(self.try_exit_during_transistion())
            } else {
                Ok(())
            }
        }
    }

    /// Run the given closure with this thread's state set to guest by switching
    /// in and out of guest execution before and after running the closure
    pub fn execute_as_guest<F, R>(&mut self, to_run: F) -> Result<R, GuestTransitionErr>
    where
        F: FnOnce() -> R,
    {
        let _anti_guard = guard::reenter_signal_inclusion_zone();
        self.enter_guest_execution()?;
        let result = to_run();
        self.leave_guest_execution()?;
        Ok(result)
    }

    /// Convenience method that calls try_exit, but wraps the resulting boolean in
    /// the correct error response based on whether the state was successfully set
    /// to `Exited`
    fn try_exit_during_transistion(&mut self) -> GuestTransitionErr {
        if self.try_exit() {
            GuestTransitionErr::ExitNow
        } else {
            GuestTransitionErr::ExitingElsewhere
        }
    }

    /// Attempts to start the exiting process by
    ///  1. Verify ownership of the thread by being the first set the state to
    ///     `Exiting`.
    ///  2. Set the state to Exited.
    ///
    /// Returning `true` informs the caller that this operation successfully put
    /// the thread into `Exited` state; it's then the caller's responsibility to
    /// actually exit the thread.
    pub fn try_exit(&mut self) -> bool {
        let exiting_state = build_repr(ThreadState::Exiting, true);
        if self.compare_and_swap_repr(exiting_state, SeqCst) {
            let _guard = guard::enter_signal_exclusion_zone();
            self.set_state(ThreadState::Exited, Acquire);
            E::on_thread_exit(self.get_process_and_thread_ids());
            true
        } else {
            false
        }
    }

    /// Fix the stored pid-tid and thread states after a fork which could have
    /// corrupted both (from the point of view of this process).
    fn fix_stored_state_after_fork(&self, actual_pid_tid: PidTid) {
        // This is safe because a thread cannot have an invalid slot key
        let (pid_tid, atomic_repr) = unsafe { SLOT_MAP.get_unchecked(self.slot_key) };

        // Override whatever the guest state was with a forking guest state
        let new_state = ThreadState::Guest(true).as_u8();

        atomic_repr.store(new_state, SeqCst);

        // Override the pid-tid with the actual pid-tid is
        pid_tid.store(actual_pid_tid, SeqCst);

        // If new threads are not allowed in this process, it means this thread
        // needs to exit. If this flag was orignally set in the parent, then
        // we overwrote it above, and need to set it to exit manually
        if !new_threads_allowed() {
            store_needs_to_exit(atomic_repr, SeqCst);
        }
    }

    /// This function is designed to wrap a function that might fork the current
    /// thread into a new thread in a new process. It indicates that it is in
    /// the process of forking, and special care should be taken not to assume
    /// the thread's stored id is valid.
    ///
    /// It is valid for the given function not to return in the child's
    /// execution context. Any cleanup that needs to happen in the child's
    /// execution related to forking state will be cleaned up on the child's
    /// first syscall.
    pub fn maybe_fork_as_guest<F>(
        &mut self,
        maybe_forking_fn: F,
    ) -> Result<usize, GuestTransitionErr>
    where
        F: FnOnce() -> usize,
    {
        if new_threads_allowed() {
            // Keep track of the starting thread id here. There is the
            // possibility with something like vfork that the thread id could be
            // changed, but when we change it back below, we don't want to tell
            // the user it's a new thread
            let starting_pid_tid = self.get_process_and_thread_ids();

            self.checked_state_transition(ThreadState::Guest(true))?;

            // It is possible that this function might not return, but that's ok
            let fork_result = maybe_forking_fn();

            // If there was no fork or this is the parent of the fork, we need
            // to make sure the thread id is still correct

            // Get the pid-tid stored in the slotmap for this thread
            let ending_pid_tid = self.get_process_and_thread_ids();
            // Read the actual pid-tid through syscalls
            let actual_pid_tid = PidTid::current();

            // If the pid-tid combo changed during start and finish, it means
            // there was a fork or a vfork and we need to fix the stored ids
            if ending_pid_tid != actual_pid_tid {
                self.fix_stored_state_after_fork(actual_pid_tid);

                // If the actual pid is not the same as the starting pid, then
                // likely we are in the child of a fork. That means the thread
                // is new.
                if starting_pid_tid != actual_pid_tid {
                    E::on_new_thread(actual_pid_tid);
                }
            }

            // Leave the guest state which, and clear the forking flag
            self.leave_guest_execution()?;
            Ok(fork_result)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::mem;
    use std::sync::atomic::fence;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread::spawn;

    use super::*;

    /// Each of these unit tests is mutating the global slotmap, so they
    /// can't interfere with each other
    static UNIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    lazy_static! {
        /// Keep track of the process and thread ids raised in start and exit
        /// events
        static ref THREADS_STARTED: Mutex<HashSet<PidTid>> = Mutex::new(HashSet::default());
        static ref THREADS_EXITED: Mutex<HashSet<PidTid>> = Mutex::new(HashSet::default());
    }

    struct TestEventSink;

    impl EventSink for TestEventSink {
        fn on_new_thread(pid_tid: PidTid) {
            assert!(
                THREADS_STARTED.lock().unwrap().insert(pid_tid),
                "Already started {:?}",
                pid_tid
            );
        }

        fn on_thread_exit(pid_tid: PidTid) {
            assert!(
                THREADS_EXITED.lock().unwrap().insert(pid_tid),
                "Already exited {:?}",
                pid_tid
            );
        }
    }

    fn current_test_thread() -> Option<Thread<TestEventSink>> {
        Thread::<TestEventSink>::current()
    }

    #[allow(clippy::cast_ref_to_mut)]
    pub fn run_test_in_new_thread<T>(t: T)
    where
        T: 'static + Send + FnOnce(),
    {
        let guard = UNIT_TEST_LOCK.lock().unwrap();

        // Here we are replacing the global slot map with a new one for every
        // test run. This is safe because each test is running inside a single
        // mutex, so only one test will be accessing the static variable at once
        unsafe {
            let slot_map_mut = &mut *((&*SLOT_MAP as *const _) as *mut _);

            *slot_map_mut = SlotMap::<ThreadRepr>::new();
        }

        THREADS_STARTED.lock().unwrap().clear();
        THREADS_EXITED.lock().unwrap().clear();

        fence(SeqCst);

        let test_result = spawn(t).join();
        mem::drop(guard);

        // A test failure inside the closure won't cause the actual test to
        // fail, so we panic here to propogate the error
        if let Err(e) = test_result {
            panic!("This test failed - {:?}", e);
        }
    }

    /// Panic if the given thread's id wasn't provided in a notification as a
    /// thread that exited
    fn assert_exit_signal_received<E: EventSink>(thread: &Thread<E>) {
        assert!(
            THREADS_EXITED
                .lock()
                .unwrap()
                .contains(&thread.get_process_and_thread_ids())
        );
    }

    /// Panic if the given thread's id wasn't provided in a notification as a
    /// thread that started
    fn assert_start_signal_received<E: EventSink>(thread: &Thread<E>) {
        assert!(
            THREADS_STARTED
                .lock()
                .unwrap()
                .contains(&thread.get_process_and_thread_ids())
        );
    }

    #[test]
    pub fn test_thread_lifecycle() {
        run_test_in_new_thread(|| {
            let mut thread = current_test_thread().expect("A thread should have been created here");
            assert!(thread.new);

            let _guard = guard::enter_signal_exclusion_zone();

            assert_start_signal_received(&thread);

            // Threads should always be in guest state upon loading.
            assert_eq!(thread.state, ThreadState::Guest(false));

            assert!(thread.leave_guest_execution().is_ok());

            // Threads should always be in guest state upon loading.
            assert_eq!(thread.state, ThreadState::Handler);

            // Make sure executing as guest has the right state in and out of
            // execution.
            assert!(
                thread
                    .execute_as_guest(|| {
                        assert_eq!(
                            current_test_thread()
                                .expect("Should be able to get thread more than once")
                                .state,
                            ThreadState::Guest(false)
                        );
                    })
                    .is_ok()
            );

            assert_eq!(thread.state, ThreadState::Handler);

            store_needs_to_exit(thread.get_atomic_repr(), SeqCst);

            // Once needs to exit is set, transitions should fail and cause the
            // thread to go to an error state.
            assert!(matches!(
                thread.enter_guest_execution(),
                Err(GuestTransitionErr::ExitNow)
            ));

            assert_eq!(thread.state, ThreadState::Exited);
            assert_exit_signal_received(&thread);

            // Once exited a thread cannot return to guest or handler state even
            // if you set the state directly (which clients can't).
            thread.set_state(ThreadState::Guest(false), Acquire);
            assert_eq!(thread.state, ThreadState::Exited);
            thread.set_state(ThreadState::Handler, Acquire);
            assert_eq!(thread.state, ThreadState::Exited);
            thread.set_state(ThreadState::Exiting, Acquire);
            assert_eq!(thread.state, ThreadState::Exited);
        })
    }

    #[test]
    fn test_new_thread_beahvior() {
        run_test_in_new_thread(|| {
            // This thread should be new
            let thread = current_test_thread().expect("A thread should have been created here");
            assert!(thread.new);
            assert_start_signal_received(&thread);

            // But now it's shouldn't be
            let thread = current_test_thread().expect("A thread should have been created here");
            assert!(!thread.new);
        })
    }

    #[test]
    fn test_disallow_new_threads() {
        run_test_in_new_thread(|| {
            // Check that the flag is not set at first
            assert!(
                spawn(|| current_test_thread().is_some())
                    .join()
                    .expect("Join error")
            );

            // This will exit all the threads (we don't actually know how many)
            exit_all(|_, _| {});

            // Now new threads should not be allowed
            assert!(
                spawn(|| current_test_thread().is_none())
                    .join()
                    .expect("Join error")
            );
        })
    }

    #[test]
    fn test_exit_all() {
        run_test_in_new_thread(|| {
            let guest = current_test_thread().expect("This thread should be present");
            let mut handler = spawn(|| current_test_thread().expect("This one too"))
                .join()
                .expect("Failed to join");
            assert_start_signal_received(&guest);
            assert_start_signal_received(&handler);

            assert!(handler.leave_guest_execution().is_ok());

            let guest_notified = Arc::new(AtomicBool::new(false));
            let gn_clone = Arc::clone(&guest_notified);

            let handler_notified = Arc::new(AtomicBool::new(false));
            let hn_clone = Arc::clone(&handler_notified);

            // This thread is new and should be in guest state, so it should get
            // notified.
            exit_all(move |slot_key, _| {
                if slot_key == guest.slot_key {
                    gn_clone.store(true, SeqCst);
                } else if slot_key == handler.slot_key {
                    hn_clone.store(true, SeqCst);
                }
            });

            // But only the guest should get notified
            assert!(guest_notified.load(Acquire));
            assert!(!handler_notified.load(Acquire));

            // Both threads should be marked as needs to exit
            assert!(needs_to_exit(guest.get_atomic_repr().load(Relaxed)));
            assert!(needs_to_exit(handler.get_atomic_repr().load(Relaxed)));
        })
    }
}
