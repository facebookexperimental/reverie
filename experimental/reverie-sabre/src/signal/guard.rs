/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::*;

use heapless::mpmc::Q64;

/// These constants describe the format of the combined queued and guard
/// counter. These counters are coupled to
///  1. Allow for single atomic writes when creating and dropping signal guards
///  2. Ensuring consistency between the counters at any given time. This
///     simplifies the logic in proving the correctness of the operations
///
/// The format of the counters is:
///
/// |<---------------------- 64 Bits ---------------------->|
/// |<-= 32 Bits Queued Count ->|<-- 32 Bits Guard Count -->|
///
const GUARD_COUNT_BITS: u8 = 32;
const GUARD_COUNT_UNIT: u64 = 1;
const GUARD_COUNT_MASK: u64 = (1 << GUARD_COUNT_BITS) - 1;
const QUEUED_COUNT_SHIFT: u8 = GUARD_COUNT_BITS;
const QUEUED_COUNT_UNIT: u64 = 1 << QUEUED_COUNT_SHIFT;
const QUEUED_COUNT_MASK: u64 = !GUARD_COUNT_MASK;

type Invocation<T> = (fn(T), T);
pub type SignalHandlerInput = libc::siginfo_t;

pub type SignalGuard = SequencerGuard<'static, SignalHandlerInput>;
pub type SignalAntiGuard = SequencerAntiGuard<'static, SignalHandlerInput>;

thread_local! {
    pub(crate) static SIGNAL_HANLDER_SEQUENCER: GuardedSequencer<SignalHandlerInput>
        = GuardedSequencer::with_initial_guard_count(1);
}

/// Marker struct that triggers "run-on-drop" behavior for defered invocations.
/// The phantom data here is to make the guard `!Send`
pub struct SequencerGuard<'a, T> {
    owner: &'a GuardedSequencer<T>,
    _phantom: PhantomData<UnsafeCell<()>>,
}

/// Marker struct that is the like the particle opposite of the signal guard.
/// When it is created, the count of guards decreases by one. If the new guard
/// count is zero, defered execitions will be evaluated and signals will not be
/// blocked. When this struct is dropped, the count of guards will be increased
/// by one guarding against signal interuptions again. The phantom data here is
/// to make the anti guard `!Send`
pub struct SequencerAntiGuard<'a, T> {
    owner: &'a GuardedSequencer<T>,
    _phantom: PhantomData<UnsafeCell<()>>,
}

impl<'a, T> SequencerGuard<'a, T> {
    fn new(owner: &'a GuardedSequencer<T>) -> Self {
        SequencerGuard {
            owner,
            _phantom: Default::default(),
        }
    }
}

impl<'a, T> SequencerAntiGuard<'a, T> {
    fn new(owner: &'a GuardedSequencer<T>) -> Self {
        SequencerAntiGuard {
            owner,
            _phantom: Default::default(),
        }
    }
}

impl<'a, T> Drop for SequencerGuard<'a, T> {
    /// When the guard is dropped, we decrement the counter for guards, and if
    /// this was the last one, we run any invocations that were added while the
    /// guard(s) were active
    fn drop(&mut self) {
        self.owner.decrement_guard_count()
    }
}

impl<'a, T> Drop for SequencerAntiGuard<'a, T> {
    /// When an anti guard is dropped, we increment the guard count to return
    /// the thread to a state that cannot be interrupted
    fn drop(&mut self) {
        self.owner.increment_guard_count()
    }
}

pub(crate) struct GuardedSequencer<T> {
    queue: Q64<Invocation<T>>,
    guard_state: AtomicU64,
}

impl<T> GuardedSequencer<T> {
    const fn with_initial_guard_count(guard_count: u32) -> Self {
        GuardedSequencer {
            queue: Q64::new(),
            guard_state: AtomicU64::new(guard_count as u64),
        }
    }

    // Enqueue the given invocation to be run when no guards are active.
    fn enqueue_invocation(&self, invocation: Invocation<T>) {
        self.queue.enqueue(invocation).ok().expect("Buffer full");
    }

    /// Drain the invocation. When a invocation is "drained", it is:
    /// 1. Removed from the buffer
    /// 2. Evaluated
    /// 3. Counted as handled in the queued count
    fn drain_one_invocation(&self) -> bool {
        if let Some((handler, argument)) = self.queue.dequeue() {
            handler(argument);

            // Decrement the queued count stored with guard count
            self.guard_state.fetch_sub(QUEUED_COUNT_UNIT, SeqCst);

            true
        } else {
            false
        }
    }

    /// Execute the invocations that are currently stored in the queue.
    fn drain_invocations(&self) {
        // While invocations are successfully being drained, keep draining. If
        // draining one invocation is not successful, either there are no more
        // or drain was interrupted and completed elsewhere. Either way there's
        // nothing more to do here.
        while self.drain_one_invocation() {}
    }

    /// Execute the given handler with the given argument when the current
    /// thread has no active signal guards. If there are no guards, this
    /// invocation will be run synchronously, otherwise, the invocation will be
    /// stored and run asynchronously when guard count reaches zero
    pub fn invoke(&self, handler: fn(T), argument: T) {
        // Increment the guard and queued count in one atomic step
        self.guard_state
            .fetch_add(QUEUED_COUNT_UNIT + GUARD_COUNT_UNIT, SeqCst);

        self.enqueue_invocation((handler, argument));

        // decrementing the guard count here will either run the invocation
        // that was just added or defer it depending respectively on whether
        // this was the only guard or not
        self.decrement_guard_count();
    }

    /// Increment the number of active guards by one
    fn increment_guard_count(&self) {
        self.guard_state.fetch_add(GUARD_COUNT_UNIT, Acquire);
    }

    /// Decrement the counter for guards, and if the count goes to zero, we run
    /// any invocations that were added while the guard(s) were active
    fn decrement_guard_count(&self) {
        let prev_guard_state = self.guard_state.fetch_sub(GUARD_COUNT_UNIT, Release);

        let prev_guard_count = prev_guard_state & GUARD_COUNT_MASK;

        assert!(
            prev_guard_count > 0,
            "Signal guard count went negative indicating a bug"
        );

        // If this wasn't the last guard or if there were no invocations added,
        // we are done
        if prev_guard_count > 1 || prev_guard_state & QUEUED_COUNT_MASK == 0 {
            return;
        }

        // Now it's our responsibility to execute all invocations
        self.drain_invocations();
    }

    /// Create a guard on this sequencer. Invocations performed on this
    /// sequencer will be deferred until the returned guard (and any others)
    /// are dropped
    fn guard<'a>(&'a self) -> SequencerGuard<'a, T> {
        self.increment_guard_count();
        SequencerGuard::new(self)
    }

    /// Create a guard on this sequencer without incrementing the guard count.
    /// Think of this as taking ownership of a guard that someone else forgot.
    /// Invocations performed on this sequencer will be deferred until the
    /// returned guard (and any others) are dropped.
    fn implicit_guard<'a>(&'a self) -> SequencerGuard<'a, T> {
        assert!(
            self.guard_state.load(Acquire) > 0,
            "No implicit signal guard in place"
        );
        SequencerGuard::new(self)
    }

    /// Create a an anti guard on this sequencer. Until it is dropped, the
    /// returned anti guard cancels out exactly one guard meaning if a single
    /// guard exists and has defered invocations, those invocations will be
    /// executed as soon as this anti guard is created, and any subsequent
    /// invocations will be run immediately
    fn anti_guard<'a>(&'a self) -> SequencerAntiGuard<'a, T> {
        self.decrement_guard_count();
        SequencerAntiGuard::new(self)
    }
}

/// Get a static pointer to the the guarded sequencer for this thread
fn signal_handler_sequencer() -> &'static GuardedSequencer<SignalHandlerInput> {
    // We are using some unsafe code here to convert the lifetime provided for
    // the thread-local `.with` function into a static lifetime. This is safe
    // because we are not passing the returned value to any other thread
    SIGNAL_HANLDER_SEQUENCER.with(|sequencer| unsafe { mem::transmute::<_, &'static _>(sequencer) })
}

/// Execute the given handler with the given argument when the current
/// thread has no active signal guards. If there are no guards, this
/// invocation will be run synchronously, otherwise, the invocation will be
/// stored and run asynchronously when guard count reaches zero
pub fn invoke_guarded(handler: fn(SignalHandlerInput), siginfo: SignalHandlerInput) {
    signal_handler_sequencer().invoke(handler, siginfo);
}

/// Enter a region where signals cannot interrupt invocation of the current
/// thread. This operation should be thought to have atomic-aquire ordering.
/// The exclusion zone will last until the returned guard is dropped
#[must_use]
pub fn enter_signal_exclusion_zone() -> SignalGuard {
    signal_handler_sequencer().guard()
}

/// Enter an already-exiting region where signals cannot interrupt execution of
/// the current thread. The exclusion zone will last until the returned guard is
/// dropped
#[must_use]
pub fn enter_implicit_signal_exclusion_zone() -> SignalGuard {
    signal_handler_sequencer().implicit_guard()
}

/// Re-enter an execution phase where signals can interrupt the current thread.
/// When the returned anti guard is dropped, a signal exclusion zone will be
/// resumed
#[must_use]
pub fn reenter_signal_inclusion_zone() -> SignalAntiGuard {
    signal_handler_sequencer().anti_guard()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::mem;
    use std::rc::Rc;

    use super::*;

    macro_rules! assert_interrupts_eq {
         ($received:ident, [$($v:ident),*]) => {
             {
                 let to_compare : Vec<&'static str> = vec![$(stringify!($v)),*];
                 assert_eq!(&*$received.borrow(), &to_compare);
             }
         }
     }

    macro_rules! make_handlers {
         ($($handler:ident),*$(,)?) => {
             $(
                 fn $handler(input: HandlerInput) {
                     let HandlerInput(_, log) = input;
                     log.borrow_mut().push(stringify!($handler));
                 }

                 macro_rules! $handler {
                     ($sched:ident, $log:ident) => {
                         $sched.invoke($handler, HandlerInput($sched.clone(), $log.clone()))
                     }
                 }
             )*
         }
     }

    // Define the handlers we are goning to call
    make_handlers! {
        h1,
        h2,
        h3,
        h4,
        h5,
        h6,
    }

    type InvocationLog = Rc<RefCell<Vec<&'static str>>>;

    #[derive(Clone)]
    struct HandlerInput(Rc<GuardedSequencer<HandlerInput>>, InvocationLog);

    /// Test wrapper to do the cleanup we need and run each test in serial
    fn run_guarded_sequencer_test<T>(t: T)
    where
        T: FnOnce(Rc<GuardedSequencer<HandlerInput>>, InvocationLog),
    {
        let handler_log = Rc::new(RefCell::new(Vec::new()));
        let sequencer = Rc::new(GuardedSequencer::with_initial_guard_count(0));

        t(sequencer.clone(), handler_log);

        // Make sure if the test exits normally that all handlers were run
        // and the guard/handler counts are returned to zero
        assert_eq!(0, sequencer.guard_state.load(SeqCst));
        assert!(sequencer.queue.dequeue().is_none());
    }

    #[test]
    fn test_basic_handler_defer() {
        run_guarded_sequencer_test(|sequencer, log| {
            assert_interrupts_eq!(log, []);

            // Running ungaurded should work immediately
            h1!(sequencer, log);
            assert_interrupts_eq!(log, [h1]);

            // Running with one guard should defer the handler
            {
                let _g1 = sequencer.guard();
                h2!(sequencer, log);
                assert_interrupts_eq!(log, [h1]);
            }

            // until after the guard goes out of scope
            assert_interrupts_eq!(log, [h1, h2]);
        });
    }

    #[test]
    fn test_defer_with_multiple_guards() {
        run_guarded_sequencer_test(|sequencer, log| {
            // Running with one guard should defer the handler
            {
                let _g1 = sequencer.guard();
                h1!(sequencer, log);
                assert_interrupts_eq!(log, []);

                // Running with another guard should do the same
                {
                    let _g2 = sequencer.guard();
                    h2!(sequencer, log);
                    assert_interrupts_eq!(log, []);
                }

                // Nothing should change when the first guard is dropped
                assert_interrupts_eq!(log, []);
            }

            // When both guards are dropped, the handlers should run in the
            // order they were received
            assert_interrupts_eq!(log, [h1, h2]);
        });
    }

    #[test]
    fn test_defer_with_anti_guard() {
        run_guarded_sequencer_test(|sequencer, log| {
            // Running with one guard should defer the handler
            {
                let _g1 = sequencer.guard();
                h1!(sequencer, log);
                assert_interrupts_eq!(log, []);

                // Running with an anti guard allows defered signals to run,
                // and allow new new handlers to run immediately
                {
                    let _ag = sequencer.anti_guard();

                    assert_interrupts_eq!(log, [h1]);
                    h2!(sequencer, log);
                    assert_interrupts_eq!(log, [h1, h2]);
                }

                // When the anti guard is gone, we return to a state where
                // handlers are defered
                h3!(sequencer, log);
                assert_interrupts_eq!(log, [h1, h2]);
            }

            // When the guard is dropped, the handlers should run in the
            // order they were received
            assert_interrupts_eq!(log, [h1, h2, h3]);
        });
    }

    #[test]
    fn test_defer_with_implicit_guard() {
        run_guarded_sequencer_test(|sequencer, log| {
            // Create a guard and drop it without calling the destructor;
            mem::forget(sequencer.guard());

            h1!(sequencer, log);
            assert_interrupts_eq!(log, []);

            //To release that implicit guard, we enter an implicitly guarded
            // zone
            {
                let _implicit_guard = sequencer.implicit_guard();

                // Handlers are still deferred
                h2!(sequencer, log);
                assert_interrupts_eq!(log, []);
            }

            // Once the guard is dropped, deferred signals are run
            assert_interrupts_eq!(log, [h1, h2]);

            //and new handlers are run immediately
            h3!(sequencer, log);
            assert_interrupts_eq!(log, [h1, h2, h3]);
        });
    }

    #[test]
    fn test_nested_handling() {
        run_guarded_sequencer_test(|sequencer, log| {
            // Nothing prevents guards from being created and dropped within
            // handler functions

            fn nested_1(input_1: HandlerInput) {
                let HandlerInput(sequencer, log) = input_1.clone();

                h2!(sequencer, log);
                let _g = sequencer.guard();
                h3!(sequencer, log);
                {
                    let _ag = sequencer.anti_guard();
                    h4!(sequencer, log);
                }

                sequencer.invoke(nested_2, input_1);

                h5!(sequencer, log);
                assert_interrupts_eq!(log, [h1, h2, h3, h4]);
            }

            fn nested_2(input_2: HandlerInput) {
                let HandlerInput(sequencer, log) = input_2;

                h6!(sequencer, log);
            }

            {
                let _g = sequencer.guard();
                h1!(sequencer, log);
                sequencer.invoke(nested_1, HandlerInput(sequencer.clone(), log.clone()));
            }

            assert_interrupts_eq!(log, [h1, h2, h3, h4, h5, h6]);
        });
    }

    #[test]
    #[should_panic]
    fn test_invalid_implicit_guard() {
        run_guarded_sequencer_test(|sequencer, _| {
            // Entering an implicit guard when one doesn't exist is an error
            let _g = sequencer.implicit_guard();
        })
    }

    #[test]
    #[should_panic]
    fn test_anti_guard_without_guard() {
        run_guarded_sequencer_test(|sequencer, _| {
            // Creating an anti guard outside of a guard is an error
            let _ag = sequencer.anti_guard();
        })
    }

    thread_local! {
        static INVOKE_COUNT: AtomicU64 = AtomicU64::new(0);
    }

    fn test_signal_handler(_: SignalHandlerInput) {
        INVOKE_COUNT.with(|counter| counter.fetch_add(1, SeqCst));
    }

    pub(crate) const DUMMY_SIGINFO: SignalHandlerInput = unsafe {
        mem::transmute::<_, SignalHandlerInput>([0u8; mem::size_of::<SignalHandlerInput>()])
    };

    #[test]
    fn test_signal_handling_guard() {
        SIGNAL_HANLDER_SEQUENCER.with(|sequencer| {
            // Reinitialize the guard state and queue just in case
            sequencer.guard_state.store(1, SeqCst);
            while sequencer.queue.dequeue().is_some() {}

            INVOKE_COUNT.with(|counter| counter.store(0, SeqCst));

            // Run through the functions just to check that we have our sanity
            invoke_guarded(test_signal_handler, DUMMY_SIGINFO);

            // We initialized the sequencer with an implicit guard, so
            assert_eq!(0, INVOKE_COUNT.with(|count| count.load(SeqCst)));

            {
                let _g1 = enter_implicit_signal_exclusion_zone();
                invoke_guarded(test_signal_handler, DUMMY_SIGINFO);
                assert_eq!(0, INVOKE_COUNT.with(|count| count.load(SeqCst)));
            }

            assert_eq!(2, INVOKE_COUNT.with(|count| count.load(SeqCst)));

            {
                let _g2 = enter_signal_exclusion_zone();
                invoke_guarded(test_signal_handler, DUMMY_SIGINFO);
                assert_eq!(2, INVOKE_COUNT.with(|count| count.load(SeqCst)));

                {
                    let _ag1 = reenter_signal_inclusion_zone();
                    assert_eq!(3, INVOKE_COUNT.with(|count| count.load(SeqCst)));
                    invoke_guarded(test_signal_handler, DUMMY_SIGINFO);
                    assert_eq!(4, INVOKE_COUNT.with(|count| count.load(SeqCst)));
                }

                invoke_guarded(test_signal_handler, DUMMY_SIGINFO);
                assert_eq!(4, INVOKE_COUNT.with(|count| count.load(SeqCst)));
            }

            assert_eq!(5, INVOKE_COUNT.with(|count| count.load(SeqCst)));
        })
    }
}
