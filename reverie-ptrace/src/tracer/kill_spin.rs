/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The kill spin, shared by the fixtures whose Tool callback waits, on the
// tracer thread, until a guest thread that something else kills is seen
// dead: a parent's SIGKILL of its child (fatal_parent_kill_tests), or the zap
// of a leader by its sibling's exec (fatal_callback_owner_tests). Included,
// as bare items, into the tracer tests module.

thread_local! {
    // While a fixture runs: the tasks its session registered, held weakly
    // so that no task outlives its owners because of this readback.
    static KILL_SPIN_TASKS: std::cell::RefCell<Option<Vec<std::sync::Weak<FatalTaskStop>>>> = const { std::cell::RefCell::new(None) };
}

// How a kill spin saw the death (its fixture's `seen` word).
/// A read of the dying thread failed with ESRCH: it was between the kill and
/// its PTRACE_EVENT_EXIT stop.
const SEEN_BY_READ: usize = 1;
/// The exit-stop probe found the thread dead: in its PTRACE_EVENT_EXIT stop,
/// where reads succeed again, or out of its stop on the way there.
const SEEN_BY_PROBE: usize = 2;
/// Not seen: the spin used up its CPU budget, or the probe could not observe
/// the thread. The spin's stderr line says which.
const NOT_SEEN: usize = 3;

/// The livelock cap of one kill spin, in CPU time of the tracer thread that
/// runs it. It is not wall time, which load stretches, and not a latency
/// gate. Once the kill is sent, the thread reaches its exit stop in a few
/// scheduled steps, and the spin ends there. Each spin's own CPU time is
/// recorded in its fixture's `cpu_ns` word.
const KILL_SPIN_CPU_BUDGET_NS: u64 = 5_000_000_000;

/// The calling thread's CPU time (CLOCK_THREAD_CPUTIME_ID), in nanoseconds.
fn thread_cpu_ns() -> u64 {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) },
        0
    );
    u64::try_from(now.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(now.tv_nsec).unwrap()
}

/// Where a kill spin finds its fixture's shared words, and what a read of
/// the dying thread must return. The indices are the fixture's own.
#[derive(Clone, Copy)]
struct KillSpinWords {
    /// The fixture's shared mapping.
    address: usize,
    /// The value every successful read must return.
    magic: usize,
    /// The word counting successful reads.
    reads: usize,
    /// The word set to SEEN_BY_READ, SEEN_BY_PROBE or NOT_SEEN at the end.
    seen: usize,
    /// The word set to the spin's CPU time on the tracer thread, in
    /// nanoseconds.
    cpu_ns: usize,
}

impl KillSpinWords {
    fn word(&self, index: usize) -> &'static std::sync::atomic::AtomicUsize {
        // The fixture owns the shared mapping for its whole run. No
        // guest-supplied pointer is used.
        unsafe { &*(self.address as *const std::sync::atomic::AtomicUsize).add(index) }
    }
}

/// Test-only readback of a task the session registered
/// (`record_fatal_task_for_test`), never a second owner.
pub(super) fn record_kill_spin_task(task: &Arc<FatalTaskStop>) {
    KILL_SPIN_TASKS.with(|slot| {
        if let Some(tasks) = slot.borrow_mut().as_mut() {
            tasks.push(Arc::downgrade(task));
        }
    });
}

/// Collects the registered tasks while it lives.
struct RegisteredTasksScope;
impl RegisteredTasksScope {
    fn new() -> Self {
        KILL_SPIN_TASKS.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Vec::new());
        });
        Self
    }
}
impl Drop for RegisteredTasksScope {
    fn drop(&mut self) {
        KILL_SPIN_TASKS.with(|slot| *slot.borrow_mut() = None);
    }
}

/// The capability for the stop that the callback of `tid` holds, from the
/// original generation the task's run loop uses (the registered task's wait
/// owner). A Tool callback is generic over its `Guest`, so it cannot reach
/// that capability through the guest itself.
fn held_stop(tid: Pid) -> Stopped {
    KILL_SPIN_TASKS.with(|slot| {
        slot.borrow()
            .as_ref()
            .expect("the fixture collects registered tasks")
            .iter()
            .rev()
            .filter_map(std::sync::Weak::upgrade)
            .find(|task| task.tid == tid)
            .expect("the callback's task is registered")
            .waits
            .stopped()
    })
}

/// Spins on the tracer thread until it sees `child`, which something else is
/// killing, dead. Records how in `words.seen` and the CPU time used in
/// `words.cpu_ns`, and returns whether it saw the death.
///
/// Each turn reads the thread's MAGIC word through `read`, then probes the
/// held stop. Reverie sets PTRACE_O_TRACEEXIT, so a read fails with ESRCH
/// only in the short window between the kill and the thread's arrival at its
/// PTRACE_EVENT_EXIT stop: once the thread is in that stop, reads succeed
/// again, and a spin that missed the window would never end on reads alone
/// (the same post-kill exit stop showed up in a hosted-CI vfork-test flake, as
/// a stale queued stop). The probe,
/// [`Stopped::died_into_exit_stop_before_resume`], sees the death either way,
/// by PF_SIGNALED or by an ESRCH of its own, and it tells a real exit stop
/// from a forged exit siginfo (fatal_parent_kill_tests' FORGED_KILL).
///
/// The spin never awaits: its callback must return its errno while it alone
/// holds the stop, before an exit future can claim the exit stop. Each turn
/// yields the CPU instead, so that the threads it waits for run on a loaded
/// host. The spin is bounded by KILL_SPIN_CPU_BUDGET_NS alone. When that runs
/// out, or the probe cannot observe, the spin says so and returns false
/// rather than panicking on the tracer thread, so that the fixture retires
/// its sentinel before it fails.
///
/// `hold` is the regression seam: before the first read, the spin waits until
/// the thread is in its exit stop ([`in_exit_stop`]), so that the ESRCH window
/// has passed and only the probe can see the death.
fn spin_until_killed(
    child: &Stopped,
    words: KillSpinWords,
    hold: bool,
    mut read: impl FnMut() -> Result<usize, Errno>,
) -> bool {
    let start = thread_cpu_ns();
    let over_budget = || thread_cpu_ns() - start >= KILL_SPIN_CPU_BUDGET_NS;
    let pid = child.pid();
    let seen = 'spin: {
        if hold {
            while !in_exit_stop(pid, pid) {
                if over_budget() {
                    eprintln!("kill spin: thread {pid} reached no exit stop within the CPU budget");
                    break 'spin NOT_SEEN;
                }
                std::thread::yield_now();
            }
        }
        loop {
            match read() {
                Ok(value) => {
                    assert_eq!(value, words.magic);
                    words.word(words.reads).fetch_add(1, Ordering::SeqCst);
                }
                Err(errno) => {
                    assert_eq!(errno, Errno::ESRCH);
                    break 'spin SEEN_BY_READ;
                }
            }
            match child.died_into_exit_stop_before_resume() {
                Some(TraceError::Died(_)) => break 'spin SEEN_BY_PROBE,
                Some(error) => {
                    eprintln!("kill spin: the exit-stop probe of thread {pid} failed: {error}");
                    break 'spin NOT_SEEN;
                }
                None => {}
            }
            if over_budget() {
                eprintln!(
                    "kill spin: the death of thread {pid} was not seen within the CPU budget"
                );
                break 'spin NOT_SEEN;
            }
            std::thread::yield_now();
        }
    };
    words
        .word(words.cpu_ns)
        .store((thread_cpu_ns() - start) as usize, Ordering::SeqCst);
    words.word(words.seen).store(seen, Ordering::SeqCst);
    seen != NOT_SEEN
}
