/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The in-guest retired-conditional-branch (RCB) clock: a per-thread
//! performance counter read in-process, with the branches retired inside Tool
//! callbacks subtracted, so a Tool reads the guest's own progress. A forked or
//! cloned thread binds a fresh counter on first use.

use core::cell::Cell;
use core::ptr;
use std::io;

use crate::trap::raw_syscall6;

// Preserve the existing one-byte availability TLS slot. Disabled is a
// deliberate no-RCB policy, distinct from a real optional PMU setup failure.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClockAvailability {
    Available,
    Unavailable,
    #[cfg(feature = "exec-private-init")]
    Disabled,
}

thread_local! {
    static RCB_CLOCK: Cell<*mut reverie::InGuestRcbCounter> =
        const { Cell::new(ptr::null_mut()) };
    static RCB_CLOCK_OWNER: Cell<libc::pid_t> = const { Cell::new(0) };
    static RCB_CLOCK_AVAILABILITY: Cell<ClockAvailability> =
        const { Cell::new(ClockAvailability::Available) };
    static RCB_HANDLER_ENTRY: Cell<u64> = const { Cell::new(0) };
    static RCB_HANDLER_DEDUCTION: Cell<u64> = const { Cell::new(0) };
    static RCB_HANDLER_DEPTH: Cell<u32> = const { Cell::new(0) };
    static RCB_COUNTER_ORIGIN: Cell<u64> = const { Cell::new(0) };
    static RCB_CLOCK_OFFSET: Cell<u64> = const { Cell::new(0) };
    static RCB_CLOCK_RESTORED: Cell<bool> = const { Cell::new(false) };
}

/// The guest counter value at a saved accounting boundary.
///
/// This is only the runtime counter portion of a continuation. Its owner must
/// separately carry logical time and every other Tool state field. No runtime
/// exec path consumes this snapshot today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RcbClockSnapshot {
    /// Count returned by the actual guest clock at the saved boundary.
    pub guest_count: u64,
}

/// Install the current thread's in-guest RCB clock before seccomp is active.
/// A host without a usable branch counter leaves the clock unavailable, which
/// is not an error; [`read_guest_rcb_clock`] then reports `Unsupported`.
pub fn initialize_rcb_clock() -> io::Result<()> {
    initialize_rcb_clock_with(
        || unsafe { reverie::InGuestRcbCounter::current_thread_with_syscall_gate(raw_syscall6) },
        true,
    )
}

/// Bind an explicitly disabled clock for the authenticated no-RCB private image.
/// This does not probe hardware or pretend that a PMU setup attempt failed.
///
/// # Safety
/// The caller must qualify the actual image/config as requiring neither RCB
/// time nor preemption, on its exclusive initializing thread before Guest or
/// any callback runs. This is not a fallback for a requested RCB feature.
#[cfg(feature = "exec-private-init")]
pub unsafe fn disable_rcb_clock_for_current_thread() -> io::Result<()> {
    if !RCB_CLOCK.get().is_null() || RCB_HANDLER_DEPTH.get() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot disable an existing counter or active RCB handler",
        ));
    }
    let owner = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as libc::pid_t;
    if owner <= 0 {
        return Err(io::Error::other(
            "cannot bind disabled RCB clock to current thread",
        ));
    }
    RCB_CLOCK_OWNER.set(owner);
    RCB_CLOCK_AVAILABILITY.set(ClockAvailability::Disabled);
    RCB_HANDLER_ENTRY.set(0);
    RCB_HANDLER_DEDUCTION.set(0);
    RCB_COUNTER_ORIGIN.set(0);
    RCB_CLOCK_OFFSET.set(0);
    RCB_CLOCK_RESTORED.set(false);
    Ok(())
}

/// Bind an already-created counter to the current thread's clock.
///
/// This narrow input seam lets a caller retain the counter's actual reader and
/// syscall gate; it does not install instrumentation or admit an exec mode.
/// There is no production caller. The usual initializer remains unchanged.
///
/// # Safety
///
/// The counter must belong to this calling thread and its syscall gate must
/// remain valid. The caller must exclude guest execution and reentrant clock
/// reads while replacing the binding.
pub unsafe fn initialize_rcb_clock_with_counter(
    counter: reverie::InGuestRcbCounter,
) -> io::Result<()> {
    // The caller may already hold the counter's number (its boundary
    // controls), so it keeps it; the runtime still records it as its own.
    initialize_rcb_clock_with(|| Ok(counter), false)
}

/// Binds the counter `create` returns to the calling thread. With `place`, the
/// counter's descriptor first moves to the runtime's range
/// ([`crate::guest::protect::runtime_fd_minimums`]) where a number there is free;
/// either way the runtime records it as its own
/// ([`crate::guest::protect::record_runtime_fd`]), so the guest cannot close,
/// duplicate onto or otherwise reach it.
fn initialize_rcb_clock_with(
    create: impl FnOnce() -> Result<reverie::InGuestRcbCounter, reverie::Errno>,
    place: bool,
) -> io::Result<()> {
    // Whatever binding allocates (the counter's box, and the PMU builder's
    // and environment overrides' own buffers) comes from the private Tool
    // heap, never the guest's malloc: a fork child binds its counter from the
    // syscall hook's exit path, outside any Tool callback, and whether binding
    // succeeds depends on the host's PMU, so an allocation through the guest's
    // malloc there would make the child's heap layout depend on the host.
    let _private_allocations = crate::guest::alloc::enter_dispatch();
    let owner = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as libc::pid_t;
    if owner <= 0 {
        return Err(io::Error::last_os_error());
    }
    // A fork child can first discover that its inherited counter has the wrong
    // owner from inside the still-active fork callback. Preserve that callback
    // depth while replacing the counter; resetting it would make the outer
    // leave underflow after child reconstruction completes.
    let active_depth = RCB_HANDLER_DEPTH.get();
    // Publish an unavailable sentinel before creating the perf event. When a
    // fork child first initializes after seccomp is active, the builder's own
    // syscalls can re-enter an already-patched syscall hook; that nested hook
    // must observe this owner as initialized instead of recursively creating
    // another counter.
    RCB_CLOCK.set(ptr::null_mut());
    RCB_CLOCK_OWNER.set(owner);
    RCB_CLOCK_AVAILABILITY.set(ClockAvailability::Unavailable);
    RCB_HANDLER_ENTRY.set(0);
    RCB_HANDLER_DEDUCTION.set(0);
    RCB_HANDLER_DEPTH.set(active_depth);
    RCB_COUNTER_ORIGIN.set(0);
    RCB_CLOCK_OFFSET.set(0);
    RCB_CLOCK_RESTORED.set(false);
    let mut clock = match create() {
        Ok(clock) => clock,
        // The in-guest clock is optional. CPU discovery, perf-event setup,
        // mmap, reset, and enable failures all mean unavailable, not a failed
        // Tool installation.
        Err(_) => return Ok(()),
    };
    if place {
        // Signals stay blocked from the move's close of the first number to
        // the check of that number (protect::record_if_open).
        let _blocked = crate::guest::protect::block_all_signals()?;
        let created = clock.descriptor();
        for minimum in crate::guest::protect::runtime_fd_minimums() {
            // SAFETY: the counter was just created on this thread and nothing
            // borrows its descriptor. Where no number is free in the runtime's
            // range it keeps the one perf_event_open gave it.
            let moved = unsafe { clock.move_descriptor_at_least(minimum) };
            if moved.is_ok() || clock.descriptor() != created {
                break;
            }
        }
        if clock.descriptor() != created {
            // The counter moved. Its first number is the same perf event, so
            // if it did not close (a seccomp filter the guest installed can
            // fail close, or report success without running it), the runtime
            // keeps it as its own too rather than leave it reachable.
            crate::guest::protect::record_if_open(created)?;
        }
        // Recorded before the guard restores the mask: a signal held during
        // the move is delivered then, and its handler must already find the
        // counter protected.
        crate::guest::protect::record_runtime_fd(clock.descriptor())?;
    } else {
        crate::guest::protect::record_runtime_fd(clock.descriptor())?;
    }
    let active_entry = if active_depth == 0 {
        0
    } else {
        clock
            .read()
            .map_err(|error| io::Error::from_raw_os_error(error.into_raw()))?
    };
    RCB_CLOCK.set(Box::into_raw(Box::new(clock)));
    RCB_CLOCK_OWNER.set(owner);
    RCB_CLOCK_AVAILABILITY.set(ClockAvailability::Available);
    RCB_HANDLER_ENTRY.set(active_entry);
    RCB_HANDLER_DEDUCTION.set(0);
    RCB_HANDLER_DEPTH.set(active_depth);
    Ok(())
}

/// Moves this thread's own performance-counter descriptor off `fd`, a number a
/// guest `dup2`, `dup3` or `F_DUPFD` is about to take
/// (protect::make_room_for_guest_descriptor), to a free number in the
/// runtime's range, closing `fd` and recording the new number in its place.
/// Returns the new number, or `None` when `fd` is not this thread's bound
/// counter (an inherited copy in a fork child that has not re-bound yet is
/// not). Fails, moving nothing, when no number is free. The caller blocks
/// every signal (protect::block_all_signals); every syscall here goes through
/// the counter's own syscall gate.
pub fn relocate_rcb_counter(fd: libc::c_int) -> io::Result<Option<libc::c_int>> {
    let owner = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as libc::pid_t;
    let current = RCB_CLOCK.get();
    if current.is_null() || RCB_CLOCK_OWNER.get() != owner {
        return Ok(None);
    }
    // SAFETY: the bound counter belongs to this thread (threads are refused
    // on these backends), and no borrow of it is live while the runtime
    // dispatches a guest syscall: rcb_clock's callers read through it and
    // return before the dispatch reaches the descriptor protections.
    let clock = unsafe { &mut *current };
    if clock.descriptor() != fd {
        return Ok(None);
    }
    for minimum in crate::guest::protect::runtime_fd_minimums() {
        // SAFETY: as above; no boundary_fd borrow is held outside tests.
        let moved = unsafe { clock.move_descriptor_at_least(minimum) };
        if moved.is_ok() || clock.descriptor() != fd {
            break;
        }
    }
    let moved = clock.descriptor();
    if moved == fd {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    crate::guest::protect::replace_recorded_fd(fd, moved)?;
    Ok(Some(moved))
}

/// Capture the actual guest-only counter value for an inactive continuation.
pub fn snapshot_rcb_clock() -> io::Result<RcbClockSnapshot> {
    Ok(RcbClockSnapshot {
        guest_count: read_guest_rcb_clock()?,
    })
}

/// Continue a saved count using the newly bound counter's current origin.
///
/// The caller must run this at its accounting boundary before resuming guest
/// work, after binding a fresh counter. Restoration is allowed once per binding
/// and neither resets nor reprograms the perf event. If a Tool callback is
/// active, its remaining branches are still excluded by the existing handler
/// accounting. Subsequent guest branches advance one tick at a time from the
/// saved count. Tool logical-time restoration remains the owner's obligation.
/// No production exec path calls this function.
pub fn restore_rcb_clock(snapshot: RcbClockSnapshot) -> io::Result<()> {
    let Some(clock) = rcb_clock()? else {
        return Err(unavailable_clock());
    };
    if RCB_CLOCK_RESTORED.get() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "LiteInst RCB clock was already restored for this binding",
        ));
    }
    let sample = clock
        .read()
        .map_err(|error| io::Error::from_raw_os_error(error.into_raw()))?;
    RCB_COUNTER_ORIGIN.set(sample);
    RCB_CLOCK_OFFSET.set(snapshot.guest_count);
    RCB_HANDLER_ENTRY.set(if RCB_HANDLER_DEPTH.get() == 0 {
        0
    } else {
        sample
    });
    RCB_HANDLER_DEDUCTION.set(0);
    RCB_CLOCK_RESTORED.set(true);
    Ok(())
}

fn unavailable_clock() -> io::Error {
    #[cfg(feature = "exec-private-init")]
    if RCB_CLOCK_AVAILABILITY.get() == ClockAvailability::Disabled {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            "RCB clock is explicitly disabled for this no-RCB image",
        );
    }
    io::Error::new(
        io::ErrorKind::Unsupported,
        "LiteInst in-guest RCB clock is unavailable on this host",
    )
}

fn rcb_clock() -> io::Result<Option<&'static reverie::InGuestRcbCounter>> {
    let owner = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as libc::pid_t;
    #[cfg(feature = "exec-private-init")]
    if RCB_CLOCK_AVAILABILITY.get() == ClockAvailability::Disabled && RCB_CLOCK_OWNER.get() != owner
    {
        // A different birth/thread is outside this binding, never permission
        // to lazily allocate a PMU behind the authenticated no-RCB contract.
        return Err(unavailable_clock());
    }
    if RCB_CLOCK_OWNER.get() != owner {
        // A fork/clone child inherits the parent's TLS bytes, including an fd
        // that still measures the parent thread. Close a fork child's copy of
        // that descriptor (leaving the handle's memory leaked, as before) and
        // bind a fresh PMU event to this calling thread. Binding is the
        // runtime's own code, not the guest's: it reads CPUID (PMU discovery),
        // which must run natively, as inside a Tool callback, rather than be
        // emulated through the fallback continuation, which a fork child can
        // still be running when it first gets here.
        let _runtime_code = crate::guest::support::ToolCallbackGuard::enter();
        crate::guest::protect::close_inherited_runtime_fds()?;
        initialize_rcb_clock()?;
    }
    let current = RCB_CLOCK.get();
    if current.is_null() {
        debug_assert_ne!(RCB_CLOCK_AVAILABILITY.get(), ClockAvailability::Available);
        Ok(None)
    } else {
        Ok(Some(unsafe { &*current }))
    }
}

/// Mark entry into an ordinary-context tool callback: branches retired until
/// the matching [`leave_rcb_handler`] are the Tool's, not the guest's.
pub fn enter_rcb_handler() -> io::Result<()> {
    let Some(clock) = rcb_clock()? else {
        RCB_HANDLER_DEPTH.set(RCB_HANDLER_DEPTH.get().saturating_add(1));
        return Ok(());
    };
    let sample = clock
        .read()
        .map_err(|error| io::Error::from_raw_os_error(error.into_raw()))?;
    if RCB_HANDLER_DEPTH.get() == 0 {
        RCB_HANDLER_ENTRY.set(sample);
    }
    RCB_HANDLER_DEPTH.set(RCB_HANDLER_DEPTH.get().saturating_add(1));
    Ok(())
}

/// Deduct all RCBs retired while the outermost tool callback was active.
pub fn leave_rcb_handler() -> io::Result<()> {
    let depth = RCB_HANDLER_DEPTH.get();
    if depth == 0 {
        return Err(io::Error::other("LiteInst RCB handler depth underflow"));
    }
    RCB_HANDLER_DEPTH.set(depth - 1);
    if depth != 1 {
        return Ok(());
    }
    let Some(clock) = rcb_clock()? else {
        return Ok(());
    };
    let sample = clock
        .read()
        .map_err(|error| io::Error::from_raw_os_error(error.into_raw()))?;
    RCB_HANDLER_DEDUCTION.set(
        RCB_HANDLER_DEDUCTION
            .get()
            .saturating_add(sample.saturating_sub(RCB_HANDLER_ENTRY.get())),
    );
    RCB_HANDLER_ENTRY.set(0);
    Ok(())
}

/// Return guest-only RCB time, excluding all completed and currently-active
/// LiteInst handler branches.
pub fn read_guest_rcb_clock() -> io::Result<u64> {
    let Some(clock) = rcb_clock()? else {
        return Err(unavailable_clock());
    };
    let sample = clock
        .read()
        .map_err(|error| io::Error::from_raw_os_error(error.into_raw()))?;
    let active = if RCB_HANDLER_DEPTH.get() == 0 {
        0
    } else {
        sample.saturating_sub(RCB_HANDLER_ENTRY.get())
    };
    sample
        .saturating_sub(RCB_COUNTER_ORIGIN.get())
        .saturating_sub(RCB_HANDLER_DEDUCTION.get())
        .saturating_sub(active)
        .checked_add(RCB_CLOCK_OFFSET.get())
        .ok_or_else(|| io::Error::other("LiteInst continued RCB clock overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_optional_rcb_setup_error_takes_the_real_unavailable_path() {
        let owner = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as libc::pid_t;
        assert!(owner > 0);
        for error in [
            reverie::Errno::EACCES,
            reverie::Errno::EPERM,
            reverie::Errno::ENODEV,
            reverie::Errno::EOPNOTSUPP,
            reverie::Errno::EINVAL,
            reverie::Errno::EMFILE,
            reverie::Errno::ENFILE,
            reverie::Errno::EBUSY,
            reverie::Errno::EIO,
        ] {
            initialize_rcb_clock_with(|| Err(error), true).unwrap();
            assert!(RCB_CLOCK.get().is_null());
            assert_eq!(RCB_CLOCK_AVAILABILITY.get(), ClockAvailability::Unavailable);
            assert_eq!(RCB_CLOCK_OWNER.get(), owner);
            assert_eq!(RCB_COUNTER_ORIGIN.get(), 0);
            assert_eq!(RCB_CLOCK_OFFSET.get(), 0);
            assert!(!RCB_CLOCK_RESTORED.get());
            assert_eq!(
                snapshot_rcb_clock().unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                restore_rcb_clock(RcbClockSnapshot { guest_count: 73 })
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[test]
    #[cfg(feature = "exec-private-init")]
    fn explicit_no_rcb_binding_survives_real_handler_accounting() {
        std::thread::spawn(|| {
            let owner = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as libc::pid_t;
            // SAFETY: fresh isolated thread, no active handler or guest work.
            unsafe { disable_rcb_clock_for_current_thread() }.unwrap();
            assert_eq!(RCB_CLOCK_OWNER.get(), owner);
            assert_eq!(RCB_CLOCK_AVAILABILITY.get(), ClockAvailability::Disabled);
            assert_eq!(
                core::mem::size_of::<ClockAvailability>(),
                core::mem::size_of::<bool>()
            );
            assert!(RCB_CLOCK.get().is_null());
            enter_rcb_handler().unwrap();
            enter_rcb_handler().unwrap();
            assert_eq!(RCB_HANDLER_DEPTH.get(), 2);
            assert_eq!(
                unsafe { disable_rcb_clock_for_current_thread() }
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(
                read_guest_rcb_clock().unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                snapshot_rcb_clock().unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                restore_rcb_clock(RcbClockSnapshot { guest_count: 1 })
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            leave_rcb_handler().unwrap();
            leave_rcb_handler().unwrap();
            assert_eq!(RCB_HANDLER_DEPTH.get(), 0);
            assert!(RCB_CLOCK.get().is_null());
            assert_eq!(RCB_CLOCK_OWNER.get(), owner);
            RCB_CLOCK_OWNER.set(0);
            assert_eq!(
                read_guest_rcb_clock().unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                RCB_CLOCK_OWNER.get(),
                0,
                "wrong-owner lookup rebound a counter"
            );
            // An explicit ordinary setup still calls its real creation seam;
            // disabled mode is not a permanent global change to the initializer.
            let mut attempts = 0;
            initialize_rcb_clock_with(
                || {
                    attempts += 1;
                    Err(reverie::Errno::EACCES)
                },
                true,
            )
            .unwrap();
            assert_eq!(attempts, 1);
            assert_eq!(RCB_CLOCK_AVAILABILITY.get(), ClockAvailability::Unavailable);
        })
        .join()
        .unwrap();
    }

    /// When a counter's first number survives its close after the move to the
    /// runtime's range (a guest seccomp filter can fake that close), the
    /// runtime records the first number too, so neither name for the perf
    /// event is reachable or unreported. Needs a usable branch counter: on a
    /// host without one there is no counter to move, and the test says so.
    #[test]
    fn a_counter_number_that_survives_its_close_is_recorded_too() {
        use crate::guest::protect::RUNTIME_FD_MIN;
        use crate::guest::protect::is_runtime_owned_fd;
        use crate::guest::protect::tests::in_child_with_soft_nofile;
        use crate::guest::protect::tests::is_open;
        use crate::guest::protect::tests::suppress_close_of;
        in_child_with_soft_nofile(2048, || {
            // SAFETY: a fresh forked child; this thread owns the counter.
            let counter = match unsafe {
                reverie::InGuestRcbCounter::current_thread_with_syscall_gate(raw_syscall6)
            } {
                Ok(counter) => counter,
                Err(error) => {
                    eprintln!("no usable branch counter on this host ({error:?}); nothing to move");
                    return;
                }
            };
            let created = counter.descriptor();
            assert!(created < RUNTIME_FD_MIN, "created at {created}");
            suppress_close_of(created);
            initialize_rcb_clock_with(|| Ok(counter), true).unwrap();
            let bound = unsafe { &*RCB_CLOCK.get() }.descriptor();
            assert!(bound >= RUNTIME_FD_MIN, "moved to {bound}");
            assert!(is_open(created), "the filter kept the first number open");
            assert!(is_runtime_owned_fd(created));
            assert!(is_runtime_owned_fd(bound));
        });
    }

    /// A guest `dup2` onto this thread's counter number goes ahead as on
    /// Linux: the runtime first moves the counter to another number, records
    /// that one instead, and keeps counting through it; so does a guest
    /// `F_DUPFD` whose answer is the counter's number. Needs a usable branch
    /// counter: on a host without one there is no counter to move, and the
    /// test says so.
    #[test]
    fn a_guest_dup2_onto_the_counter_moves_it_and_it_keeps_counting() {
        use crate::guest::protect::is_runtime_owned_fd;
        use crate::guest::protect::protect_runtime_descriptors;
        use crate::guest::protect::tests::event;
        use crate::guest::protect::tests::in_child_with_soft_nofile;
        use crate::guest::protect::tests::is_open;
        in_child_with_soft_nofile(2048, || {
            // SAFETY: a fresh forked child; this thread owns the counter.
            let counter = match unsafe {
                reverie::InGuestRcbCounter::current_thread_with_syscall_gate(raw_syscall6)
            } {
                Ok(counter) => counter,
                Err(error) => {
                    eprintln!("no usable branch counter on this host ({error:?}); nothing to move");
                    return;
                }
            };
            initialize_rcb_clock_with(|| Ok(counter), true).unwrap();
            let before = unsafe { &*RCB_CLOCK.get() }.descriptor();
            let first = read_guest_rcb_clock().unwrap();
            let mut dup = event(libc::SYS_dup2, [0, before as u64, 0, 0, 0, 0]);
            assert!(!unsafe { protect_runtime_descriptors(&mut dup, true) });
            let after = unsafe { &*RCB_CLOCK.get() }.descriptor();
            assert_ne!(after, before);
            assert!(is_runtime_owned_fd(after));
            assert!(!is_runtime_owned_fd(before));
            assert!(!is_open(before), "the old number is free for the guest");
            let mut spin = 0_u64;
            for step in 0..100_000_u64 {
                spin = std::hint::black_box(spin.wrapping_add(step ^ spin));
            }
            let second = read_guest_rcb_clock().unwrap();
            assert!(second > first, "the counter stopped: {first} -> {second}");

            let mut f_dupfd = event(
                libc::SYS_fcntl,
                [0, libc::F_DUPFD_CLOEXEC as u64, after as u64, 0, 0, 0],
            );
            assert!(!unsafe { protect_runtime_descriptors(&mut f_dupfd, true) });
            let last = unsafe { &*RCB_CLOCK.get() }.descriptor();
            assert_ne!(last, after);
            assert!(is_runtime_owned_fd(last));
            assert!(!is_runtime_owned_fd(after));
            let got = unsafe {
                raw_syscall6(
                    libc::SYS_fcntl,
                    [0, libc::F_DUPFD_CLOEXEC as u64, after as u64, 0, 0, 0],
                )
            };
            assert_eq!(
                got,
                i64::from(after),
                "the guest gets the counter's old number"
            );
            for step in 0..100_000_u64 {
                spin = std::hint::black_box(spin.wrapping_add(step ^ spin));
            }
            let third = read_guest_rcb_clock().unwrap();
            assert!(third > second, "the counter stopped: {second} -> {third}");
        });
    }
}
