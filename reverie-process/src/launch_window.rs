/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Keeps the tracer's transient descriptors out of guest launches on other
//! host threads of the same process.
//!
//! A *transient open* is a descriptor a tracer thread opens and closes inside
//! one synchronous call, such as a procfs read. A *launch* is the parent-side
//! sequence that allocates a new child's descriptors (pipes) and forks it. If
//! a transient open overlaps another thread's launch, the descriptor takes a
//! number from the launch's descriptor budget (its pipe can fail with EMFILE
//! under a tight `RLIMIT_NOFILE`), and the forked child inherits it. A no-exec
//! guest (`spawn_fn_with_config`) closes only descriptors 3 to 255, so it keeps
//! a numbered-256-or-above copy for its whole run
//! (<https://github.com/rrnewton/reverie/issues/912>, rows 25 and 26 of
//! <https://github.com/rrnewton/reverie/issues/845>).
//!
//! One process-wide lock excludes the two across threads: [`Launch`] is held
//! exclusively from a launch's first descriptor allocation until `clone`
//! returns in the parent (for a launch through libc's `fork`, until its
//! descriptors exist; see below), and [`TransientOpen`] is held shared from a
//! transient open to its close. Transient opens of different threads never
//! wait for each other, only for another thread's launch in progress, and for
//! that at most [`OPEN_WAIT_LIMIT`] (below). A launch waits until no other
//! thread holds a transient open. Neither guard may be held across an
//! `.await`.
//!
//! A thread never waits for its own guards. An open inside the thread's own
//! launch, or a launch nested inside it, proceeds and leaves the outer launch
//! held. So does a launch inside the thread's own open, which then becomes
//! part of the launch until the launch ends; that open's descriptor reaches
//! the child, as it would without the lock. Two threads that each hold a transient open
//! and each begin a launch inside it would wait for each other's open; no
//! Reverie launch site begins a launch under its own open.
//!
//! A guarded scope must therefore not wait for another thread: that thread
//! may be launching, or may wait for a launch, which waits for the guard. A
//! scope makes system calls on its descriptor and computes, and nothing else:
//! - It does not log. A log subscriber may block on a launching thread, for
//!   example one that writes through a launched child. Code that may run under
//!   a guard and needs to log hands the event to [`run_after_guards`], which
//!   runs it once the thread holds no guard.
//! - It takes no lock, and no cache initializer that another thread may be
//!   running.
//! - It may allocate. A thread that holds an allocator's lock and waits on
//!   this lock waits only for a launch in progress, which allocates nothing
//!   (below), and for at most [`OPEN_WAIT_LIMIT`].
//!
//! Only system calls run under [`Launch`]: the ones that make the child's
//! descriptors, and the `clone`; [`Launch::allocate`] (below) may also spin
//! for a bounded number of checks. Nothing under it allocates or frees memory,
//! takes a lock, or calls code from outside Reverie. What a launch needs that
//! allocates is built before the guard begins. A launch that waits holds
//! nothing: other threads' opens keep beginning until it takes the lock,
//! which it does only once none is in progress.
//!
//! A system call can still wait for another thread of this process: a
//! seccomp filter on the launching thread can hand its `pipe2` to a
//! user-notification supervisor here, and that supervisor may need a
//! transient open before it answers. So a transient open waits for another
//! thread's launch for at most [`OPEN_WAIT_LIMIT`], and then proceeds while
//! the launch is still held, as it would without the lock: its descriptor can
//! then take a number from that launch, or reach its child. A launch that
//! nothing outside it holds up runs only system calls and typically ends
//! well within the limit, though scheduling delay can stretch it. The limit
//! is checked between bounded futex waits of 10 ms, so an open can wait
//! somewhat longer than the limit before it gives up.
//!
//! An open that proceeds that way can hold a descriptor the launch needs. If
//! a descriptor allocation made through [`Launch::allocate`] then fails with
//! EMFILE or ENFILE while such an open is still held, the launch waits for
//! those opens to close, for a bounded number of checks, and allocates once
//! more (<https://github.com/rrnewton/reverie/issues/930>). That wait is the
//! one place a launch waits for another thread. It is bounded for the same
//! reason as the open's: the open's close may itself wait on a supervisor
//! that waits for the launch. It makes no system call: a supervisor could
//! hold any call made while the launch is held until the launch ends, and
//! neither could then end. So it spins instead of sleeping in `futex`, an
//! open's release does not wake it (a release's wake while a launch is held
//! would likewise wait for the launch), and it counts checks instead of
//! reading a clock, which falls back to a system call on some clock sources.
//!
//! A launch through libc's `fork` (`spawn_fn_with_config`) ends its guard
//! once its pipes exist, before it calls `fork`: `fork` runs the process's
//! `pthread_atfork` handlers, which may run any code, including code that
//! waits for another thread that waits for the guard. A transient open of
//! another thread that begins after the guard ends and is still open at the
//! `fork` therefore reaches that child, as it did without the lock
//! (<https://github.com/rrnewton/reverie/issues/927>).
//!
//! A launch must not hold [`Launch`] while it waits for the new child to start
//! (an exec-error pipe, a seccomp-notification handoff): the child's setup can
//! wait on another tracer thread, and that thread may need a transient open.
//! Descriptors a launch keeps open after `clone` returns, such as its
//! exec-error reader, are therefore not excluded from other threads' launches
//! while the child starts.
//!
//! A child forked through libc runs a `pthread_atfork` handler, and a child of
//! this crate's raw `clone` resets the lock at entry, so neither inherits a
//! guard another thread held, or work the forking thread deferred to
//! [`run_after_guards`]. After the reset the child's copies of the forking
//! thread's [`Launch`] guards release nothing, provided they are dropped before
//! the child begins a launch of its own: a copy dropped during the child's own
//! launch would end that launch. A child made by a raw `clone`/`clone3`
//! elsewhere must not take either guard.
//!
//! The lock lives here, below `reverie-core`, `safeptrace` and
//! `reverie-ptrace`, so that the transient opens in all three take the same
//! lock. It is not part of Reverie's tool API.
//!
//! Descriptors held beyond one call (pidfds, perf counters, a gdb client's
//! files) and forks outside Reverie are not covered.

use std::cell::Cell;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Once;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

/// Set while a launch holds the lock. The other bits count transient opens,
/// including any that began during the launch after [`OPEN_WAIT_LIMIT`].
const LAUNCHING: u32 = 1 << 31;

/// How long a transient open waits for another thread's launch before it
/// proceeds without excluding it (see the module documentation).
pub const OPEN_WAIT_LIMIT: std::time::Duration = std::time::Duration::from_millis(100);

static STATE: AtomicU32 = AtomicU32::new(0);

static CHILD_RESET: Once = Once::new();

thread_local! {
    /// Transient opens this thread holds that `STATE` counts.
    static OPENS_HELD: Cell<u32> = const { Cell::new(0) };
    /// How many [`Launch`] guards this thread holds, nested.
    static LAUNCH_DEPTH: Cell<u32> = const { Cell::new(0) };
    /// Transient opens this thread holds while it holds the launch. `STATE`
    /// does not count them; they move to `OPENS_HELD` when the launch ends.
    static OPENS_IN_LAUNCH: Cell<u32> = const { Cell::new(0) };
    /// Work [`run_after_guards`] put off until this thread holds no guard.
    static AFTER_GUARDS: RefCell<Vec<Box<dyn FnOnce()>>> = const { RefCell::new(Vec::new()) };
    /// Whether `AFTER_GUARDS` may hold work. Until it is set, this thread has
    /// not touched `AFTER_GUARDS`, whose first use may allocate.
    static DEFERRED: Cell<bool> = const { Cell::new(false) };
}

/// Whether this thread holds a guard of either kind.
fn holds_a_guard() -> bool {
    OPENS_HELD.with(Cell::get) > 0
        || LAUNCH_DEPTH.with(Cell::get) > 0
        || OPENS_IN_LAUNCH.with(Cell::get) > 0
}

/// Runs `work` now if this thread holds no guard, and otherwise right after
/// its last guard ends, in the order the work was handed over. Code that may
/// run under a guard logs through this (see the module documentation).
pub fn run_after_guards(work: impl FnOnce() + 'static) {
    if holds_a_guard() {
        AFTER_GUARDS.with(|queue| queue.borrow_mut().push(Box::new(work)));
        DEFERRED.with(|deferred| deferred.set(true));
    } else {
        work();
    }
}

/// Runs the work deferred by [`run_after_guards`] once the thread's last
/// guard has ended, including work deferred by that work.
fn run_deferred_work() {
    while DEFERRED.with(Cell::get) && !holds_a_guard() {
        DEFERRED.with(|deferred| deferred.set(false));
        let queue = AFTER_GUARDS.with(|queue| queue.take());
        if queue.is_empty() {
            return;
        }
        for work in queue {
            work();
        }
    }
}

/// Runs in the child of every `fork` that goes through libc, where only the
/// forking thread survives: the lock keeps that thread's transient opens and
/// nothing else, so a guard the child inherited from another thread cannot
/// block it forever. A launch the forking thread held is over in the child;
/// the child's copy of its guard releases nothing. Work the forking thread
/// deferred to [`run_after_guards`] belongs to the parent: the child forgets
/// it, without running or freeing it.
extern "C" fn reset_in_child() {
    let held = OPENS_HELD.try_with(Cell::get).unwrap_or(0)
        + OPENS_IN_LAUNCH
            .try_with(|opens| opens.replace(0))
            .unwrap_or(0);
    let _ = OPENS_HELD.try_with(|opens| opens.set(held));
    let _ = LAUNCH_DEPTH.try_with(|depth| depth.set(0));
    if matches!(
        DEFERRED.try_with(|deferred| deferred.replace(false)),
        Ok(true)
    ) {
        let _ = AFTER_GUARDS.try_with(|queue| {
            if let Ok(mut queue) = queue.try_borrow_mut() {
                std::mem::forget(std::mem::take(&mut *queue));
            }
        });
    }
    STATE.store(held, Ordering::Relaxed);
}

fn register_child_reset() {
    CHILD_RESET.call_once(|| {
        // SAFETY: `reset_in_child` only touches an atomic and
        // constant-initialized thread-locals, without allocating or freeing,
        // which is async-signal-safe: it touches `AFTER_GUARDS` only if the
        // thread already used it, and `mem::take` leaves an empty `Vec`, which
        // owns no memory, and forgets the old one.
        let rc = unsafe { libc::pthread_atfork(None, None, Some(reset_in_child)) };
        assert_eq!(rc, 0, "pthread_atfork failed: {rc}");
    });
}

/// Resets the lock in a child of a raw `clone` without `CLONE_VM`, which runs
/// no `pthread_atfork` handler. Allocation-free and async-signal-safe.
pub(crate) fn reset_after_raw_clone() {
    reset_in_child();
}

/// How long a waiter sleeps before it rechecks the lock without a wake.
///
/// A release's `FUTEX_WAKE` can fail: a host seccomp filter on the releasing
/// thread may deny it, and the tracer cannot see or fix that. A bounded wait
/// makes every waiter recheck on its own, so a lost wake costs at most this
/// long instead of blocking the waiter forever.
const RECHECK_AFTER: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 10_000_000,
};

fn wait_while(observed: u32) {
    // SAFETY: STATE is an aligned u32 that lives for the whole process, and
    // the timeout is a valid relative timespec.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            STATE.as_ptr(),
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            observed,
            &RECHECK_AFTER as *const libc::timespec,
        )
    };
}

fn wake_all() {
    // SAFETY: as in `wait_while`.
    let _woken = unsafe {
        libc::syscall(
            libc::SYS_futex,
            STATE.as_ptr(),
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX,
        )
    };
    #[cfg(test)]
    LAST_WAKE.with(|last| {
        last.set(Some(match _woken {
            -1 => Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)),
            woken => Ok(woken),
        }))
    });
}

#[cfg(test)]
thread_local! {
    /// What this thread's last release wake returned: how many waiters it
    /// woke, or its errno.
    static LAST_WAKE: Cell<Option<Result<libc::c_long, i32>>> = const { Cell::new(None) };
}

/// Whether this thread holds a [`Launch`]. Allocation-free, so an allocator
/// may call it.
pub fn held_by_this_thread() -> bool {
    LAUNCH_DEPTH.try_with(Cell::get).unwrap_or(0) > 0
}

/// Whether some thread of this process holds a [`Launch`]. Allocation-free.
pub fn launching() -> bool {
    STATE.load(Ordering::Relaxed) & LAUNCHING != 0
}

/// Exclusive hold for one guest launch's descriptor allocation and fork.
#[must_use]
pub struct Launch {
    _not_send: PhantomData<*const ()>,
}

impl Launch {
    /// Waits until no other thread holds a transient open or a launch.
    pub fn begin() -> Self {
        register_child_reset();
        let depth = LAUNCH_DEPTH.with(Cell::get);
        if depth == 0 {
            // This thread's own opens stay counted until the launch takes
            // them over; only other threads' opens are waited for.
            let own = OPENS_HELD.with(Cell::get);
            loop {
                match STATE.compare_exchange_weak(
                    own,
                    LAUNCHING,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) if observed == own => {}
                    Err(observed) => wait_while(observed),
                }
            }
            OPENS_HELD.with(|opens| opens.set(0));
            OPENS_IN_LAUNCH.with(|opens| opens.set(own));
        }
        LAUNCH_DEPTH.with(|launches| launches.set(depth + 1));
        Launch {
            _not_send: PhantomData,
        }
    }

    /// Runs `allocate`, which makes descriptors for this launch. If it fails
    /// with EMFILE or ENFILE (`errno` reads the error's number) while another
    /// thread still holds an open that began during the launch, spins until
    /// those opens close, for at most [`LATE_OPEN_CHECKS`] checks, and runs
    /// `allocate` once more. Allocates nothing, takes no lock, reads no
    /// clock, and makes no system call besides `allocate`'s.
    pub fn allocate<T, E: Copy>(
        &self,
        mut allocate: impl FnMut() -> Result<T, E>,
        errno: fn(E) -> i32,
    ) -> Result<T, E> {
        match allocate() {
            Err(err) if matches!(errno(err), libc::EMFILE | libc::ENFILE) => {
                if wait_for_late_opens() {
                    allocate()
                } else {
                    Err(err)
                }
            }
            result => result,
        }
    }
}

impl Drop for Launch {
    /// Ends the launch when the thread's outermost guard drops. In a forked
    /// child the fork handler has already ended it, so this does nothing.
    fn drop(&mut self) {
        let depth = LAUNCH_DEPTH.with(Cell::get);
        if depth == 0 {
            return;
        }
        LAUNCH_DEPTH.with(|launches| launches.set(depth - 1));
        if depth > 1 {
            return;
        }
        let own = OPENS_IN_LAUNCH.with(|opens| opens.replace(0));
        OPENS_HELD.with(|opens| opens.set(own));
        // Other threads' opens that began during the launch, after
        // `OPEN_WAIT_LIMIT`, stay counted.
        STATE.fetch_sub(LAUNCHING - own, Ordering::Release);
        wake_all();
        run_deferred_work();
    }
}

/// The transient opens `state` counts. While a thread holds the launch, these
/// are only other threads' opens that began during it.
fn counted_opens(state: u32) -> u32 {
    state & !LAUNCHING
}

/// How many times [`Launch::allocate`] checks for late opens before it
/// allocates again anyway. Each check is one atomic load and one spin-wait
/// hint ([`std::hint::spin_loop`]), whose cost depends on the processor: on
/// an AMD EPYC 9D85 a check took 23 ns, so the bound is about 100 ms there;
/// on processors with a cheaper hint it is shorter.
const LATE_OPEN_CHECKS: u32 = 1 << 22;

/// Spins, for at most [`LATE_OPEN_CHECKS`] checks, until no other thread holds
/// an open that began during this thread's launch. Returns whether one was
/// held when it was called.
///
/// It makes no system call and reads no clock, so a seccomp supervisor cannot
/// hold or deny anything it does while the launch is held (see the module
/// documentation).
fn wait_for_late_opens() -> bool {
    if counted_opens(STATE.load(Ordering::Acquire)) == 0 {
        return false;
    }
    for _ in 0..LATE_OPEN_CHECKS {
        if counted_opens(STATE.load(Ordering::Acquire)) == 0 {
            break;
        }
        #[cfg(test)]
        SPINS_WHILE_HELD.fetch_add(1, Ordering::Relaxed);
        std::hint::spin_loop();
    }
    true
}

/// Checks that [`wait_for_late_opens`] found a late open still held, so a test
/// can tell that the wait ran without a system call or a clock.
#[cfg(test)]
static SPINS_WHILE_HELD: AtomicU32 = AtomicU32::new(0);

/// Shared hold for one transient descriptor, from its open to its close.
#[must_use]
pub struct TransientOpen {
    _not_send: PhantomData<*const ()>,
}

impl TransientOpen {
    /// Waits only while another thread's launch is in progress, and for at
    /// most [`OPEN_WAIT_LIMIT`].
    pub fn begin() -> Self {
        register_child_reset();
        if LAUNCH_DEPTH.with(Cell::get) > 0 {
            OPENS_IN_LAUNCH.with(|opens| opens.set(opens.get() + 1));
            return TransientOpen {
                _not_send: PhantomData,
            };
        }
        let mut observed = STATE.load(Ordering::Relaxed);
        let mut give_up_at = None;
        loop {
            if observed & LAUNCHING != 0
                && std::time::Instant::now()
                    < *give_up_at.get_or_insert_with(|| std::time::Instant::now() + OPEN_WAIT_LIMIT)
            {
                wait_while(observed);
                observed = STATE.load(Ordering::Relaxed);
                continue;
            }
            match STATE.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(now) => observed = now,
            }
        }
        OPENS_HELD.with(|held| held.set(held.get() + 1));
        TransientOpen {
            _not_send: PhantomData,
        }
    }
}

impl Drop for TransientOpen {
    fn drop(&mut self) {
        // While this thread holds the launch, every open it holds is one the
        // launch took over or one opened inside it.
        if LAUNCH_DEPTH.with(Cell::get) > 0 {
            OPENS_IN_LAUNCH.with(|opens| opens.set(opens.get() - 1));
            return;
        }
        OPENS_HELD.with(|held| held.set(held.get() - 1));
        // The last open wakes a launch waiting to begin. While a launch is
        // held it wakes nobody: `Launch::allocate` spins rather than waits,
        // and a supervisor could hold the wake until the launch ends.
        if STATE.fetch_sub(1, Ordering::Release) == 1 {
            wake_all();
        }
        run_deferred_work();
    }
}

/// [`std::fs::read_to_string`] as one transient open.
pub fn read_to_string<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<String> {
    let _open = TransientOpen::begin();
    std::fs::read_to_string(path)
}

/// [`std::fs::read`] as one transient open.
pub fn read<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let _open = TransientOpen::begin();
    std::fs::read(path)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    // These tests share the process-wide lock with every other test in this
    // binary, so they only assert orderings that hold whatever else runs. A
    // test that needs the lock to itself runs alone in its own process (see
    // `running_alone`).

    fn gettid() -> libc::pid_t {
        // SAFETY: gettid has no preconditions.
        unsafe { libc::gettid() }
    }

    /// Returns once thread `tid` is seen asleep in this lock's futex wait
    /// (`FUTEX_WAIT_PRIVATE` on `STATE`), and fails after 10 s. A contender
    /// that has not reached the wait yet, or waits on anything else, does not
    /// count.
    fn wait_until_asleep_on_the_lock(tid: libc::pid_t) {
        wait_until_asleep_on_the_lock_or_proceeded(tid, &AtomicBool::new(false));
    }

    /// As above, but also returns once `proceeded` is set: an open can stop
    /// waiting after [`OPEN_WAIT_LIMIT`] before this thread samples it.
    fn wait_until_asleep_on_the_lock_or_proceeded(tid: libc::pid_t, proceeded: &AtomicBool) {
        let expected = format!(
            "{} {:#x} {:#x} ",
            libc::SYS_futex,
            STATE.as_ptr() as usize,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let syscall = std::fs::read_to_string(format!("/proc/self/task/{tid}/syscall"))
                .unwrap_or_default();
            if syscall.starts_with(&expected) || proceeded.load(Ordering::SeqCst) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "thread {tid} was not seen waiting on the lock within 10 s (last: {syscall:?})"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn transient_opens_nest_on_one_thread() {
        let outer = TransientOpen::begin();
        let inner = TransientOpen::begin();
        assert_eq!(OPENS_HELD.with(Cell::get), 2);
        drop(inner);
        drop(outer);
        assert_eq!(OPENS_HELD.with(Cell::get), 0);
    }

    #[test]
    fn a_launch_waits_for_a_transient_open_to_close() {
        let open = TransientOpen::begin();
        let launched = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = mpsc::channel();
        let launcher = {
            let launched = Arc::clone(&launched);
            std::thread::spawn(move || {
                tid_tx.send(gettid()).unwrap();
                let _launch = Launch::begin();
                launched.store(true, Ordering::SeqCst);
            })
        };
        wait_until_asleep_on_the_lock(tid_rx.recv().unwrap());
        assert!(
            !launched.load(Ordering::SeqCst),
            "launch ran during a transient open"
        );
        drop(open);
        launcher.join().unwrap();
        assert!(launched.load(Ordering::SeqCst));
    }

    #[test]
    fn a_transient_open_waits_for_a_launch_to_finish() {
        let launch = Launch::begin();
        let opened = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = mpsc::channel();
        let reader = {
            let opened = Arc::clone(&opened);
            std::thread::spawn(move || {
                tid_tx.send(gettid()).unwrap();
                let began = Instant::now();
                let _open = TransientOpen::begin();
                let during = launching();
                opened.store(true, Ordering::SeqCst);
                (began.elapsed(), during)
            })
        };
        wait_until_asleep_on_the_lock_or_proceeded(tid_rx.recv().unwrap(), &opened);
        drop(launch);
        let (waited, during) = reader.join().unwrap();
        assert!(opened.load(Ordering::SeqCst));
        // On a loaded host the release can come after the reader's limit has
        // run out; an open during the launch must still have waited the whole
        // limit.
        assert!(
            !during || waited >= OPEN_WAIT_LIMIT,
            "transient open ran during a launch after {waited:?}, before {OPEN_WAIT_LIMIT:?}"
        );
    }

    #[test]
    fn a_transient_open_proceeds_after_the_limit_and_a_later_launch_waits_for_it() {
        let launch = Launch::begin();
        let (tid_tx, tid_rx) = mpsc::channel();
        let (opened_tx, opened_rx) = mpsc::channel();
        let (close_tx, close_rx) = mpsc::channel::<()>();
        let proceeded = Arc::new(AtomicBool::new(false));
        let reader = {
            let proceeded = Arc::clone(&proceeded);
            std::thread::spawn(move || {
                tid_tx.send(gettid()).unwrap();
                let began = Instant::now();
                let open = TransientOpen::begin();
                proceeded.store(true, Ordering::SeqCst);
                opened_tx.send(began.elapsed()).unwrap();
                close_rx.recv().unwrap();
                drop(open);
            })
        };
        wait_until_asleep_on_the_lock_or_proceeded(tid_rx.recv().unwrap(), &proceeded);
        let waited = opened_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a transient open still waited for a launch 10 s later");
        assert!(launching(), "the launch ended before the open proceeded");
        assert!(
            waited >= OPEN_WAIT_LIMIT,
            "the open proceeded after {waited:?}, before {OPEN_WAIT_LIMIT:?}"
        );
        // The open stays counted when the launch it outlasted ends.
        drop(launch);
        let launched = Arc::new(AtomicBool::new(false));
        let (launcher_tx, launcher_rx) = mpsc::channel();
        let launcher = {
            let launched = Arc::clone(&launched);
            std::thread::spawn(move || {
                launcher_tx.send(gettid()).unwrap();
                let _launch = Launch::begin();
                launched.store(true, Ordering::SeqCst);
            })
        };
        wait_until_asleep_on_the_lock(launcher_rx.recv().unwrap());
        assert!(
            !launched.load(Ordering::SeqCst),
            "a launch ran while an open that began during the previous launch was held"
        );
        close_tx.send(()).unwrap();
        reader.join().unwrap();
        launcher.join().unwrap();
        assert!(launched.load(Ordering::SeqCst));
    }

    /// Installs a filter on the calling thread only that fails this module's
    /// `FUTEX_WAKE` with EPERM, as a host sandbox might.
    fn deny_wake_on_this_thread() {
        const fn stmt(code: u32, k: u32) -> libc::sock_filter {
            libc::sock_filter {
                code: code as u16,
                jt: 0,
                jf: 0,
                k,
            }
        }
        const fn jeq_else_allow(k: u32, to_allow: u8) -> libc::sock_filter {
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: to_allow,
                k,
            }
        }
        let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        // struct seccomp_data: nr at 0, args[1] at 24, args[2] at 32; the low
        // halves come first on little-endian hosts.
        let filter = [
            stmt(load, 0),
            jeq_else_allow(libc::SYS_futex as u32, 5),
            stmt(load, 24),
            jeq_else_allow((libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG) as u32, 3),
            stmt(load, 32),
            jeq_else_allow(i32::MAX as u32, 1),
            stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ),
            stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: plain prctl calls; the program outlives the install call.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &prog as *const libc::sock_fprog,
                ),
                0,
                "installing the test filter failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    /// Names the variable that tells a process of this test binary to run
    /// one test alone, and which.
    const ALONE: &str = "REVERIE_LAUNCH_WINDOW_TEST_ALONE";

    /// Whether this process is the one that runs `test` alone. If it is not,
    /// runs `test` alone in a new process of this test binary, asserts that it
    /// passed there, and returns false. No other test shares that process's
    /// lock, so nothing else holds an open or wakes its waiters.
    fn running_alone(test: &str) -> bool {
        let (_crate, module) = module_path!().split_once("::").unwrap();
        let name = format!("{module}::{test}");
        if std::env::var_os(ALONE).is_some_and(|alone| alone == name.as_str()) {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--test-threads=1", "--nocapture"])
            .env(ALONE, &name)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{name} failed when run alone ({}):\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    #[test]
    fn a_waiting_launch_proceeds_when_the_release_wake_is_denied() {
        if !running_alone("a_waiting_launch_proceeds_when_the_release_wake_is_denied") {
            return;
        }
        let opened = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let holder = {
            let (opened, release) = (Arc::clone(&opened), Arc::clone(&release));
            std::thread::spawn(move || {
                let open = TransientOpen::begin();
                opened.store(true, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                deny_wake_on_this_thread();
                let before = STATE.load(Ordering::SeqCst);
                LAST_WAKE.with(|last| last.set(None));
                drop(open);
                (before, LAST_WAKE.with(Cell::get))
            })
        };
        while !opened.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let launched = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = mpsc::channel();
        let launcher = {
            let launched = Arc::clone(&launched);
            std::thread::spawn(move || {
                tid_tx.send(gettid()).unwrap();
                let _launch = Launch::begin();
                launched.store(true, Ordering::SeqCst);
            })
        };
        // The release below must find the launcher already asleep on the
        // lock, so that only a timed-out wait can let it proceed.
        wait_until_asleep_on_the_lock(tid_rx.recv().unwrap());
        assert!(
            !launched.load(Ordering::SeqCst),
            "launch ran during a transient open"
        );
        release.store(true, Ordering::SeqCst);
        let (before, wake) = holder.join().unwrap();
        // The holder's open was the only one, so its drop was the last
        // reader's release, and the release's own wake was denied. Nothing
        // else in this process wakes the launcher.
        assert_eq!(before, 1, "the holder's open was not the only one");
        assert_eq!(
            wake,
            Some(Err(libc::EPERM)),
            "the release did not issue a wake that the filter denied"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !launched.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            launched.load(Ordering::SeqCst),
            "the launch was still waiting 5 s after a release whose wake was denied"
        );
        launcher.join().unwrap();
    }

    #[test]
    fn a_failed_allocation_waits_for_an_open_that_began_during_the_launch_and_retries() {
        if !running_alone(
            "a_failed_allocation_waits_for_an_open_that_began_during_the_launch_and_retries",
        ) {
            return;
        }
        // The open closes only once the launch has begun to wait for it, as
        // one whose close a supervisor holds would. The retry succeeds only
        // if no open is held when it runs, so a retry that did not wait
        // fails. A reader starved past the wait's bound makes one attempt
        // fail, so a few are allowed; an allocation that does not wait fails
        // every one.
        let mut outcomes = Vec::new();
        for _ in 0..5 {
            SPINS_WHILE_HELD.store(0, Ordering::SeqCst);
            let launch = Launch::begin();
            let done = Arc::new(AtomicBool::new(false));
            let (opened_tx, opened_rx) = mpsc::channel();
            let reader = std::thread::spawn({
                let done = done.clone();
                move || {
                    let open = TransientOpen::begin();
                    opened_tx.send(launching()).unwrap();
                    while SPINS_WHILE_HELD.load(Ordering::SeqCst) == 0
                        && !done.load(Ordering::SeqCst)
                    {
                        std::thread::yield_now();
                    }
                    drop(open);
                }
            });
            assert!(
                opened_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("a transient open still waited for a launch 10 s later"),
                "the open did not begin during the launch"
            );
            let mut calls = 0;
            let mut at_retry = None;
            let allocated = launch.allocate(
                || {
                    calls += 1;
                    if calls == 1 {
                        return Err(libc::EMFILE);
                    }
                    let held = counted_opens(STATE.load(Ordering::SeqCst));
                    at_retry = Some((SPINS_WHILE_HELD.load(Ordering::SeqCst), held));
                    if held == 0 {
                        Ok(calls)
                    } else {
                        Err(libc::EMFILE)
                    }
                },
                |errno| errno,
            );
            drop(launch);
            done.store(true, Ordering::SeqCst);
            reader.join().unwrap();
            if allocated == Ok(2) {
                return;
            }
            outcomes.push((allocated, calls, at_retry));
            // A retry that ran without a single check while the open was held
            // did not wait at all: no scheduling explains that away.
            if matches!(at_retry, None | Some((0, _))) {
                break;
            }
        }
        panic!(
            "the allocation was not retried once after the open closed; per attempt \
             (result, calls, (checks while the open was held, opens held) at the \
             retry): {outcomes:?}"
        );
    }

    #[test]
    fn a_failed_allocation_is_not_retried_without_an_open_that_began_during_the_launch() {
        if !running_alone(
            "a_failed_allocation_is_not_retried_without_an_open_that_began_during_the_launch",
        ) {
            return;
        }
        let launch = Launch::begin();
        for errno in [libc::EMFILE, libc::ENFILE, libc::EINVAL] {
            let mut calls = 0;
            let allocated: Result<(), i32> = launch.allocate(
                || {
                    calls += 1;
                    Err(errno)
                },
                |errno| errno,
            );
            assert_eq!((allocated, calls), (Err(errno), 1), "errno {errno}");
        }

        // An open that began during the launch does not make other failures
        // retried.
        let (opened_tx, opened_rx) = mpsc::channel();
        let (close_tx, close_rx) = mpsc::channel::<()>();
        let reader = std::thread::spawn(move || {
            let open = TransientOpen::begin();
            opened_tx.send(()).unwrap();
            close_rx.recv().unwrap();
            drop(open);
        });
        opened_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let mut calls = 0;
        let allocated: Result<(), i32> = launch.allocate(
            || {
                calls += 1;
                Err(libc::EINVAL)
            },
            |errno| errno,
        );
        assert_eq!((allocated, calls), (Err(libc::EINVAL), 1));
        close_tx.send(()).unwrap();
        reader.join().unwrap();
        drop(launch);
    }

    #[test]
    fn work_handed_over_under_a_guard_runs_after_the_last_guard() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let ran = Rc::new(RefCell::new(Vec::new()));
        let note = |name: &'static str| {
            let ran = Rc::clone(&ran);
            move || ran.borrow_mut().push(name)
        };
        run_after_guards(note("unguarded"));
        assert_eq!(*ran.borrow(), ["unguarded"]);

        let outer = TransientOpen::begin();
        let inner = TransientOpen::begin();
        run_after_guards(note("first"));
        let (second, third) = (note("second"), note("third"));
        run_after_guards(move || {
            second();
            run_after_guards(third);
        });
        drop(inner);
        assert_eq!(*ran.borrow(), ["unguarded"], "ran under the outer open");
        drop(outer);
        assert_eq!(*ran.borrow(), ["unguarded", "first", "second", "third"]);

        let launch = Launch::begin();
        run_after_guards(note("launch"));
        assert_eq!(ran.borrow().len(), 4, "ran under the launch");
        drop(launch);
        assert_eq!(ran.borrow().last(), Some(&"launch"));
    }

    #[test]
    fn a_thread_never_waits_for_its_own_guards() {
        let open = TransientOpen::begin();
        // A launch inside the thread's own open, an open inside its launch,
        // and a launch nested in that.
        let launch = Launch::begin();
        let inner_open = TransientOpen::begin();
        let inner_launch = Launch::begin();
        drop(inner_launch);
        drop(inner_open);
        // Other tests' opens that outwaited the limit may be counted too.
        assert!(
            launching() && held_by_this_thread(),
            "the outer launch must stay held after the nested one ends"
        );
        assert_eq!(OPENS_IN_LAUNCH.with(Cell::get), 1);

        // Another thread's open still waits for the outer launch.
        let opened = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = mpsc::channel();
        let reader = {
            let opened = Arc::clone(&opened);
            std::thread::spawn(move || {
                tid_tx.send(gettid()).unwrap();
                let began = Instant::now();
                let _open = TransientOpen::begin();
                let during = launching();
                opened.store(true, Ordering::SeqCst);
                (began.elapsed(), during)
            })
        };
        wait_until_asleep_on_the_lock_or_proceeded(tid_rx.recv().unwrap(), &opened);
        drop(launch);
        let (waited, during) = reader.join().unwrap();
        assert!(opened.load(Ordering::SeqCst));
        assert!(
            !during || waited >= OPEN_WAIT_LIMIT,
            "another thread's open ran during the outer launch after {waited:?}"
        );
        // The first open outlived the launch and is counted again.
        assert_eq!(OPENS_HELD.with(Cell::get), 1);
        drop(open);
        assert_eq!(OPENS_HELD.with(Cell::get), 0);
    }
}
