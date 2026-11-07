/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The runtime mask and the guest's saved mask, under the in-guest
//! signal-delivery gate.
//!
//! The gate is the Tool's configuration predicate
//! [`reverie::Tool::in_guest_signal_delivery`], read once, when the runtime is
//! installed in a process ([`enable`]), into a process-global flag that a fork
//! child inherits with the rest of the process's memory. With it false nothing
//! here runs and nothing changes. With it true:
//!
//! - every runtime context runs under [`runtime_mask`]: every blockable signal
//!   except the runtime's reserved ones (SIGSYS, which the completion marker
//!   and every trapped syscall need; SIGSEGV while an instruction is
//!   subscribed; SIGTRAP while a guard router is installed, which the gate
//!   refuses). It is the `sa_mask` of the SIGSYS and SIGSEGV actions, so the
//!   kernel installs it as it builds the trap frame, before any runtime
//!   instruction, and the frame that enters the fallback continuation carries
//!   it as `uc_sigmask`;
//! - the guest's own mask is the one its trap frame carried, saved in the
//!   thread's continuation and installed again by the completion
//!   (`guest::continuation`), so the kernel delivers what that mask lets in as
//!   the completion returns to guest code, and never inside the runtime;
//! - every call on the blocked set is decided on that saved mask
//!   ([`saved_mask_call`]), in Linux's order, since the kernel's mask is the
//!   runtime's while the call is handled;
//! - a raw forward of a call that would install a mask of its own in the
//!   kernel is refused by name ([`installs_signal_mask`]): it would let guest
//!   signals in while the runtime runs.
//!
//! The premise is the gate's: the in-guest runtime runs one guest thread per
//! process (a non-fork clone is refused) and no exec while it is on, so the
//! process's state here is that thread's.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::guest::sigalrm::GuestRights;
use crate::guest::support::KernelSigaction;
use crate::trap::raw_syscall6;

const fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}

/// Linux never blocks these (`sigdelsetmask(.., SIGKILL|SIGSTOP)`).
const UNBLOCKABLE: u64 = bit(libc::SIGKILL) | bit(libc::SIGSTOP);

/// The kernel's sigset size on x86-64.
const SIGSET_SIZE: u64 = core::mem::size_of::<u64>() as u64;

/// The default action of these is to ignore (`sig_kernel_ignore`,
/// include/linux/signal.h `SIG_KERNEL_IGNORE_MASK` at v6.12).
const DEFAULT_IGNORED: u64 =
    bit(libc::SIGCONT) | bit(libc::SIGCHLD) | bit(libc::SIGWINCH) | bit(libc::SIGURG);

static DELIVERS: AtomicBool = AtomicBool::new(false);
static RUNTIME_MASK: AtomicU64 = AtomicU64::new(0);
static CACHED_TID: AtomicI32 = AtomicI32::new(0);
static CACHED_PID: AtomicI32 = AtomicI32::new(0);

/// Whether this process's runtime delivers signals itself: the Tool's
/// [`reverie::Tool::in_guest_signal_delivery`], read once at installation.
pub fn delivers_signals() -> bool {
    DELIVERS.load(Ordering::Acquire)
}

/// The runtime mask for the reserved set `reserved`: every blockable signal
/// except the reserved ones.
pub const fn runtime_mask_for(reserved: u64) -> u64 {
    !(reserved | UNBLOCKABLE)
}

/// The signals the runtime reserves in a process whose instruction
/// subscriptions are `instructions_subscribed` (SIGSEGV then carries CPUID
/// and RDTSC faults) and whose guard router is `router` (a signal number, or
/// 0 for none).
pub const fn reserved_for(instructions_subscribed: bool, router: i32) -> u64 {
    let mut reserved = bit(libc::SIGSYS);
    if instructions_subscribed {
        reserved |= bit(libc::SIGSEGV);
    }
    if router > 0 {
        reserved |= bit(router);
    }
    reserved
}

/// The runtime mask in force in this process; meaningful only while
/// [`delivers_signals`].
pub fn runtime_mask() -> u64 {
    RUNTIME_MASK.load(Ordering::Acquire)
}

/// The `sa_mask` of the runtime's SIGSYS and SIGSEGV actions: the runtime
/// mask under the gate, and no signal otherwise (today's action).
pub fn runtime_action_mask() -> u64 {
    if delivers_signals() {
        runtime_mask()
    } else {
        0
    }
}

/// Records the gate for this process, once, during installation and before
/// any runtime signal action is installed: with `delivers` the runtime mask
/// for `reserved` is in force from here on, and the calling thread's id and
/// process id are cached, so that an event costs no `gettid` or `getpid`
/// (one thread per process and no exec under the gate; a fork child rebinds
/// them, [`rebind_identity`]). With `delivers` false nothing is recorded, and
/// every event reads both as before.
///
/// # Safety
///
/// Call once per process image, on the installing thread, before the
/// runtime's signal actions are installed and before any trap.
pub unsafe fn enable(delivers: bool, reserved: u64) {
    if !delivers {
        return;
    }
    RUNTIME_MASK.store(runtime_mask_for(reserved), Ordering::Release);
    rebind_identity();
    DELIVERS.store(true, Ordering::Release);
}

/// Caches the calling thread's id and process id again; called in a fork
/// child before any of its callbacks, under the gate only.
pub fn rebind_identity() {
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    CACHED_TID.store(tid as i32, Ordering::Release);
    CACHED_PID.store(pid as i32, Ordering::Release);
}

/// The cached thread id and process id of the one guest thread of this
/// process; meaningful only while [`delivers_signals`].
pub fn cached_identity() -> (i32, i32) {
    (
        CACHED_TID.load(Ordering::Acquire),
        CACHED_PID.load(Ordering::Acquire),
    )
}

/// Why a call on the blocked set cannot be decided on the saved mask: there
/// is no running continuation on this thread, so no saved mask. Under the
/// gate every guest event arrives through the continuation, so this is a
/// runtime defect, and the caller ends the process by name.
pub const NO_SAVED_MASK: &str = "a call on the signal mask under the in-guest signal-delivery gate \
outside a running continuation has no saved guest mask to act on";

/// The status with which the runtime ends the process when it cannot keep
/// the gate's mask contract ([`refuse`]).
pub const REFUSAL_STATUS: i32 = 125;

/// Ends the process by name for `reason`, a runtime defect under the gate:
/// the message goes to standard error and the process exits with
/// [`REFUSAL_STATUS`], before any guest-visible effect.
pub fn refuse(reason: &str) -> ! {
    let mut message = [0_u8; 512];
    let mut length = 0;
    for part in [
        b"reverie-inguest: ".as_slice(),
        reason.as_bytes(),
        b"; the process ends\n".as_slice(),
    ] {
        let take = part.len().min(message.len() - length);
        message[length..length + take].copy_from_slice(&part[..take]);
        length += take;
    }
    unsafe {
        let _ = raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                message.as_ptr() as u64,
                length as u64,
                0,
                0,
                0,
            ],
        );
        crate::guest::support::exit_now(REFUSAL_STATUS)
    }
}

/// Decides `number(args)` on the guest's saved mask when it is a call on the
/// blocked set: `rt_sigprocmask` or `rt_sigpending`. `None` for any other
/// call; `Some(Ok(result))` is the call's result (a value or a negated errno),
/// and the call must not be forwarded; `Some(Err(reason))` means the call
/// cannot be decided ([`NO_SAVED_MASK`]).
///
/// Linux's order is kept (kernel/signal.c at v6.12):
/// - `rt_sigprocmask` (`:3202-3230`): a size other than 8 is `EINVAL`; an
///   unreadable set is `EFAULT`; SIGKILL and SIGSTOP are dropped; an invalid
///   `how` with a set is `EINVAL`, after the set is read and before anything
///   changes (`sigprocmask`, `:3119-3144`); a null set changes nothing and
///   checks no `how`; the old mask is copied out last, after the change, so an
///   unwritable old set is `EFAULT` with the change kept. The reserved
///   signals are dropped from a new mask as the forwarded call dropped them
///   (<https://github.com/rrnewton/reverie/issues/915>). Before a change, the
///   ignored instances pending outside the old mask are discarded
///   (`discard_ignored_outside`).
/// - `rt_sigpending` (`:3274-3288`, `do_sigpending` `:3257-3266`): a size
///   over 8 is `EINVAL`; the answer is the pending set (the thread's and its
///   process's) within the saved mask; `size` bytes of it are copied out, so a
///   size of 0 writes nothing.
///
/// `rights` are the guest's protection-key rights for its own buffers
/// ([`GuestRights`]), as for signal phase 1's virtual calls.
///
/// # Safety
///
/// Only from the runtime's forwarding of a guest or Tool call, on the guest
/// thread's own syscall path, under the gate.
pub unsafe fn saved_mask_call(
    rights: GuestRights,
    reserved: u64,
    number: i64,
    args: [u64; 6],
) -> Option<Result<i64, &'static str>> {
    let decided = match number {
        libc::SYS_rt_sigprocmask => sigprocmask(rights, reserved, args),
        libc::SYS_rt_sigpending => sigpending(rights, args),
        _ => return None,
    };
    Some(decided.map(|result| match result {
        Ok(value) => value,
        Err(errno) => -i64::from(errno),
    }))
}

fn sigprocmask(
    rights: GuestRights,
    reserved: u64,
    args: [u64; 6],
) -> Result<Result<i64, i32>, &'static str> {
    let Some(old) = super::continuation::saved_guest_mask() else {
        return Err(NO_SAVED_MASK);
    };
    Ok((|| {
        if args[3] != SIGSET_SIZE {
            return Err(libc::EINVAL);
        }
        if args[1] != 0 {
            let set = super::sigalrm::read_guest::<u64>(rights, args[1])?;
            let next = super::sigalrm::next_mask(old, args[0] as i32, set)? & !reserved;
            discard_ignored_outside(old, reserved);
            super::continuation::set_saved_guest_mask(next);
        }
        if args[2] != 0 {
            super::sigalrm::write_guest(rights, args[2], &old)?;
        }
        Ok(0)
    })())
}

fn sigpending(rights: GuestRights, args: [u64; 6]) -> Result<Result<i64, i32>, &'static str> {
    let Some(mask) = super::continuation::saved_guest_mask() else {
        return Err(NO_SAVED_MASK);
    };
    Ok((|| {
        let size = args[1];
        if size > SIGSET_SIZE {
            return Err(libc::EINVAL);
        }
        let visible = kernel_pending()? & mask;
        if size != 0 {
            if !rights.may_write(args[0]) {
                return Err(libc::EFAULT);
            }
            // The set is little-endian: its first `size` bytes are the prefix.
            super::sigalrm::copy_within_process(
                (&raw const visible) as u64,
                args[0],
                size as usize,
            )?;
        }
        Ok(0)
    })())
}

/// The calling thread's pending signals, its own and its process's, through
/// the trusted gate. In a runtime context the kernel reports them within the
/// runtime mask, which leaves out only the reserved signals.
fn kernel_pending() -> Result<u64, i32> {
    let mut pending = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigpending,
            [(&raw mut pending) as u64, SIGSET_SIZE, 0, 0, 0, 0],
        )
    };
    if result < 0 {
        Err(-result as i32)
    } else {
        Ok(pending)
    }
}

/// Whether Linux ignores `signal` at send for a task whose action for it is
/// `handler` (`SIG_DFL`, `SIG_IGN` or a handler address): `sig_task_ignored`
/// (kernel/signal.c:79-97 at v6.12): `SIG_IGN`, or `SIG_DFL` with a default
/// action of ignore (`sig_kernel_ignore`); and, for the init of a PID
/// namespace (`SIGNAL_UNKILLABLE`, `namespace_init`), `SIG_DFL` of any
/// signal, since a send from inside its own namespace is never forced
/// (`force && sig_kernel_only` is false). A blocked signal is never ignored at send (`sig_ignored`,
/// `:104-120`); the caller passes only signals the guest's mask does not
/// block.
pub fn ignored_at_send(signal: i32, handler: u64, namespace_init: bool) -> bool {
    if handler == libc::SIG_IGN as u64 {
        return true;
    }
    handler == libc::SIG_DFL as u64
        && (namespace_init || (signal <= 64 && DEFAULT_IGNORED & bit(signal) != 0))
}

/// Before an `rt_sigprocmask` changes the saved mask from `old`: discards, through trusted zero-timeout `rt_sigtimedwait`
/// calls, every pending instance of a signal that `old` does not block and
/// that the guest ignores ([`ignored_at_send`], with the guest's own action
/// where the runtime routes a signal, `guest::signal::guest_action`).
///
/// With one guest thread per process, such an instance can only have arrived
/// while this thread was in its runtime, under the runtime mask, since its last return to guest
/// code: there Linux discarded it at send, because the guest's mask `old` let
/// it in and its action ignores it. Left queued, a change that now blocks it
/// would show it to `rt_sigpending` and keep it past the return. The pending
/// set is read once; the actions only when it holds a candidate. A process
/// whose SIGALRM handler is virtual (signal phase 1) has the runtime's
/// trampoline as its physical action, which is never ignored.
pub(crate) fn discard_ignored_outside(old: u64, reserved: u64) {
    let Ok(pending) = kernel_pending() else {
        return;
    };
    let candidates = pending & !old & !reserved & !UNBLOCKABLE;
    if candidates == 0 {
        return;
    }
    let namespace_init = cached_identity().1 == 1;
    let mut ignored = 0_u64;
    for signal in 1..=64 {
        if candidates & bit(signal) == 0 {
            continue;
        }
        let mut action = KernelSigaction::default();
        let queried = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigaction,
                [
                    signal as u64,
                    0,
                    (&raw mut action) as u64,
                    SIGSET_SIZE,
                    0,
                    0,
                ],
            )
        };
        let handler = super::signal::guest_action(signal, action.handler);
        if queried == 0 && ignored_at_send(signal, handler, namespace_init) {
            ignored |= bit(signal);
        }
    }
    discard_pending(ignored);
}

/// Dequeues every pending instance of the signals in `set`, the thread's
/// queue first and then its process's, as `dequeue_signal` takes them,
/// through the trusted gate, until none is left. A zero timeout installs no
/// mask (`do_sigtimedwait`, kernel/signal.c:3653).
fn discard_pending(set: u64) {
    if set == 0 {
        return;
    }
    let zero = [0_i64; 2];
    // A real-time signal can have many instances queued; each call takes one.
    loop {
        let taken = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigtimedwait,
                [
                    (&raw const set) as u64,
                    0,
                    zero.as_ptr() as u64,
                    SIGSET_SIZE,
                    0,
                    0,
                ],
            )
        };
        if taken <= 0 {
            return;
        }
    }
}

/// x86-64's `SYS_io_pgetevents` (the libc crate does not export it).
const SYS_IO_PGETEVENTS: i64 = 333;

/// io_uring_enter's flag that waits for completions
/// (include/uapi/linux/io_uring.h).
const IORING_ENTER_GETEVENTS: u64 = 1 << 0;

/// Prepares a raw forward of `number(args)` under the gate: whether the
/// runtime must refuse it ([`installs_signal_mask`], `Ok(true)`), after making
/// an `rt_sigtimedwait` see only the instances Linux would have kept. Before
/// such a call, which dequeues straight from the kernel's queue, the ignored
/// instances pending outside the guest's saved mask are discarded
/// (`discard_ignored_outside`): they arrived while the runtime ran, under
/// the runtime mask, and Linux discarded them at send (`sig_ignored`,
/// kernel/signal.c:104-120 at v6.12), so the call must not return one. The
/// kernel's pending set is then read again, once, for the refusal's decision.
/// `rights` are those the forward runs under. `Err` when the call cannot be
/// decided ([`NO_SAVED_MASK`]).
pub fn prepare_forward(
    rights: GuestRights,
    reserved: u64,
    number: i64,
    args: [u64; 6],
) -> Result<bool, &'static str> {
    let mut pending = 0;
    if number == libc::SYS_rt_sigtimedwait {
        let Some(saved) = super::continuation::saved_guest_mask() else {
            return Err(NO_SAVED_MASK);
        };
        discard_ignored_outside(saved, reserved);
        pending = kernel_pending().unwrap_or(0);
    }
    Ok(installs_signal_mask(rights, number, args, pending))
}

/// Whether `number(args)`, run by the kernel now, could install a signal mask
/// of its own on the calling thread, so that the kernel could deliver a guest
/// signal while the runtime runs: under the gate the runtime refuses to
/// forward it, by name. It follows Linux's order where that is cheap to read,
/// so that a call that fails first with `EINVAL` or `EFAULT` installs nothing
/// and is not refused (a Tool may forward such a call to let Linux answer it);
/// neither is a zero-timeout `rt_sigtimedwait` (a Tool's removal of pending
/// signals, or its poll of the guest's own call), one that a pending signal
/// ends at once (`pending`: the thread's and its process's pending set), or
/// `signalfd`, which never changes the mask. Where reading more would be
/// costly it errs on the side of refusing: `io_uring_enter` is refused
/// whenever it would wait for completions with a signal argument, without
/// reading that argument. At v6.12:
/// - `rt_sigsuspend` (kernel/signal.c:4716-4727): size 8 and a readable set;
/// - `rt_sigtimedwait` (`:3688-3710`, `do_sigtimedwait` `:3629-3662`): size 8,
///   a readable set, no waited-for signal pending (`dequeue_signal` takes one
///   without changing the mask, `:3652-3653`), and no timeout, or a readable,
///   valid, nonzero one: then it sleeps with the set's signals unblocked;
/// - `ppoll` (fs/select.c:1101-1119), `pselect6` (`:794-803`, `do_pselect`
///   `:729-758`), `epoll_pwait` and `epoll_pwait2` (fs/eventpoll.c:2479-2527),
///   and `io_pgetevents` (fs/aio.c:2276-2297, whose timeout is only read): a
///   readable, valid timeout where one is read first, then a non-null mask of
///   size 8 that is readable (`set_user_sigmask`, kernel/signal.c:3156-3172);
/// - `io_uring_enter` (io_uring/io_uring.c:3279) with `IORING_ENTER_GETEVENTS`
///   (`:3361`) and a non-null argument: the argument is the mask itself, or,
///   with `IORING_ENTER_EXT_ARG`, a structure naming it (`io_get_ext_arg`,
///   `:3249-3277`), which `io_cqring_wait` installs (`:2555-2563`).
///
/// Memory is read with `rights` ([`GuestRights`]): the rights the forward
/// runs under, so that the decision reads what the kernel would read.
pub fn installs_signal_mask(
    rights: GuestRights,
    number: i64,
    args: [u64; 6],
    pending: u64,
) -> bool {
    let readable_set = |address: u64, size: u64| {
        address != 0
            && size == SIGSET_SIZE
            && super::sigalrm::read_guest::<u64>(rights, address).is_ok()
    };
    // A timeout read before the mask: absent, or readable and valid.
    let timeout_admits = |address: u64| address == 0 || read_timespec(rights, address).is_some();
    match number {
        libc::SYS_rt_sigsuspend => readable_set(args[0], args[1]),
        libc::SYS_rt_sigtimedwait => {
            let waits_for = (args[0] != 0 && args[3] == SIGSET_SIZE)
                .then(|| super::sigalrm::read_guest::<u64>(rights, args[0]).ok())
                .flatten();
            waits_for.is_some_and(|set| set & !UNBLOCKABLE & pending == 0)
                && (args[2] == 0
                    || read_timespec(rights, args[2]).is_some_and(|(sec, nsec)| sec | nsec != 0))
        }
        libc::SYS_ppoll => timeout_admits(args[2]) && readable_set(args[3], args[4]),
        libc::SYS_pselect6 => {
            let Some([mask, size]) = read_pair(rights, args[5]) else {
                return false;
            };
            timeout_admits(args[4]) && readable_set(mask, size)
        }
        libc::SYS_epoll_pwait => readable_set(args[4], args[5]),
        libc::SYS_epoll_pwait2 => timeout_admits(args[3]) && readable_set(args[4], args[5]),
        SYS_IO_PGETEVENTS => {
            // The timeout is only read (EFAULT), not validated, first.
            let timeout_readable =
                args[4] == 0 || super::sigalrm::read_guest::<[i64; 2]>(rights, args[4]).is_ok();
            let Some([mask, size]) = read_pair(rights, args[5]) else {
                return false;
            };
            timeout_readable && readable_set(mask, size)
        }
        libc::SYS_io_uring_enter => args[3] & IORING_ENTER_GETEVENTS != 0 && args[4] != 0,
        _ => false,
    }
}

/// A `struct __kernel_timespec` at `address` that Linux would accept
/// (`get_timespec64`, then `timespec64_valid`: a nonnegative second count and
/// nanoseconds below one second), as `(tv_sec, tv_nsec)`.
fn read_timespec(rights: GuestRights, address: u64) -> Option<(i64, i64)> {
    let [sec, nsec] = super::sigalrm::read_guest::<[i64; 2]>(rights, address).ok()?;
    (sec >= 0 && (0..1_000_000_000).contains(&nsec)).then_some((sec, nsec))
}

/// A mask pointer and its size (`struct sigset_argpack`, `struct
/// __aio_sigset`) at `address`, or `None` when it is absent (no mask) or
/// unreadable (`EFAULT`).
fn read_pair(rights: GuestRights, address: u64) -> Option<[u64; 2]> {
    if address == 0 {
        return None;
    }
    super::sigalrm::read_guest::<[u64; 2]>(rights, address).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_mask_leaves_only_the_reserved_and_unblockable_signals_out() {
        let reserved = reserved_for(false, 0);
        assert_eq!(reserved, bit(libc::SIGSYS));
        let mask = runtime_mask_for(reserved);
        for signal in 1..=64 {
            let expected = !matches!(signal, libc::SIGSYS | libc::SIGKILL | libc::SIGSTOP);
            assert_eq!(mask & bit(signal) != 0, expected, "signal {signal}");
        }
        let reserved = reserved_for(true, libc::SIGTRAP);
        assert_eq!(
            reserved,
            bit(libc::SIGSYS) | bit(libc::SIGSEGV) | bit(libc::SIGTRAP)
        );
        let mask = runtime_mask_for(reserved);
        assert_eq!(mask & (bit(libc::SIGSEGV) | bit(libc::SIGTRAP)), 0);
        assert_ne!(mask & bit(libc::SIGALRM), 0);
        assert_ne!(mask & bit(libc::SIGRTMAX()), 0);
    }

    #[test]
    fn the_action_mask_is_none_while_the_gate_is_off() {
        // No test in this binary enables the gate (`enable` is called only by
        // an installation), so the action keeps today's empty mask.
        assert!(!delivers_signals());
        assert_eq!(runtime_action_mask(), 0);
    }

    #[test]
    fn ignored_at_send_follows_sig_task_ignored() {
        let dfl = libc::SIG_DFL as u64;
        let ign = libc::SIG_IGN as u64;
        let handler = 0x1000_u64;
        for signal in [libc::SIGCHLD, libc::SIGURG, libc::SIGWINCH, libc::SIGCONT] {
            assert!(ignored_at_send(signal, dfl, false), "{signal}");
            assert!(!ignored_at_send(signal, handler, false), "{signal}");
        }
        for signal in [
            libc::SIGTERM,
            libc::SIGUSR1,
            libc::SIGRTMIN(),
            libc::SIGQUIT,
        ] {
            assert!(!ignored_at_send(signal, dfl, false), "{signal}");
            assert!(ignored_at_send(signal, ign, false), "{signal}");
            // A PID namespace's init ignores every SIG_DFL signal.
            assert!(ignored_at_send(signal, dfl, true), "{signal}");
            assert!(!ignored_at_send(signal, handler, true), "{signal}");
        }
    }

    fn rights() -> GuestRights {
        GuestRights::default()
    }

    #[test]
    fn only_calls_that_reach_set_user_sigmask_install_a_mask() {
        let set: u64 = bit(libc::SIGUSR1);
        let set_at = (&raw const set) as u64;
        let zero = [0_i64; 2];
        let zero_at = zero.as_ptr() as u64;
        let second = [1_i64, 0];
        let second_at = second.as_ptr() as u64;
        let invalid = [0_i64, 1_000_000_000];
        let invalid_at = invalid.as_ptr() as u64;
        // An address no process maps (the top of the user range).
        let unmapped = 0x7fff_ffff_f000_u64;
        let pack = [set_at, 8];
        let pack_at = pack.as_ptr() as u64;
        let null_pack = [0_u64, 8];
        let null_pack_at = null_pack.as_ptr() as u64;
        let rows: &[(&str, i64, [u64; 6], bool)] = &[
            (
                "rt_sigsuspend",
                libc::SYS_rt_sigsuspend,
                [set_at, 8, 0, 0, 0, 0],
                true,
            ),
            (
                "rt_sigsuspend size 4",
                libc::SYS_rt_sigsuspend,
                [set_at, 4, 0, 0, 0, 0],
                false,
            ),
            (
                "rt_sigsuspend unreadable",
                libc::SYS_rt_sigsuspend,
                [unmapped, 8, 0, 0, 0, 0],
                false,
            ),
            (
                "rt_sigtimedwait no timeout",
                libc::SYS_rt_sigtimedwait,
                [set_at, 0, 0, 8, 0, 0],
                true,
            ),
            (
                "rt_sigtimedwait 1s",
                libc::SYS_rt_sigtimedwait,
                [set_at, 0, second_at, 8, 0, 0],
                true,
            ),
            (
                "rt_sigtimedwait zero",
                libc::SYS_rt_sigtimedwait,
                [set_at, 0, zero_at, 8, 0, 0],
                false,
            ),
            (
                "rt_sigtimedwait invalid",
                libc::SYS_rt_sigtimedwait,
                [set_at, 0, invalid_at, 8, 0, 0],
                false,
            ),
            (
                "rt_sigtimedwait unreadable timeout",
                libc::SYS_rt_sigtimedwait,
                [set_at, 0, unmapped, 8, 0, 0],
                false,
            ),
            (
                "ppoll masked",
                libc::SYS_ppoll,
                [0, 0, zero_at, set_at, 8, 0],
                true,
            ),
            (
                "ppoll masked, no timeout",
                libc::SYS_ppoll,
                [0, 0, 0, set_at, 8, 0],
                true,
            ),
            (
                "ppoll unmasked",
                libc::SYS_ppoll,
                [0, 0, zero_at, 0, 8, 0],
                false,
            ),
            (
                "ppoll invalid timeout",
                libc::SYS_ppoll,
                [0, 0, invalid_at, set_at, 8, 0],
                false,
            ),
            (
                "ppoll size 4",
                libc::SYS_ppoll,
                [0, 0, 0, set_at, 4, 0],
                false,
            ),
            (
                "pselect6 masked",
                libc::SYS_pselect6,
                [0, 0, 0, 0, zero_at, pack_at],
                true,
            ),
            (
                "pselect6 null pack",
                libc::SYS_pselect6,
                [0, 0, 0, 0, zero_at, 0],
                false,
            ),
            (
                "pselect6 null mask",
                libc::SYS_pselect6,
                [0, 0, 0, 0, zero_at, null_pack_at],
                false,
            ),
            (
                "pselect6 unreadable pack",
                libc::SYS_pselect6,
                [0, 0, 0, 0, zero_at, unmapped],
                false,
            ),
            (
                "pselect6 invalid timeout",
                libc::SYS_pselect6,
                [0, 0, 0, 0, invalid_at, pack_at],
                false,
            ),
            (
                "epoll_pwait masked",
                libc::SYS_epoll_pwait,
                [0, 0, 1, 0, set_at, 8],
                true,
            ),
            (
                "epoll_pwait unmasked",
                libc::SYS_epoll_pwait,
                [0, 0, 1, 0, 0, 8],
                false,
            ),
            (
                "epoll_pwait2 masked",
                libc::SYS_epoll_pwait2,
                [0, 0, 1, zero_at, set_at, 8],
                true,
            ),
            (
                "epoll_pwait2 invalid timeout",
                libc::SYS_epoll_pwait2,
                [0, 0, 1, invalid_at, set_at, 8],
                false,
            ),
            (
                "io_pgetevents masked",
                SYS_IO_PGETEVENTS,
                [0, 0, 1, 0, 0, pack_at],
                true,
            ),
            (
                "io_pgetevents unmasked",
                SYS_IO_PGETEVENTS,
                [0, 0, 1, 0, 0, 0],
                false,
            ),
            (
                "signalfd4",
                libc::SYS_signalfd4,
                [u64::MAX, set_at, 8, 0, 0, 0],
                false,
            ),
            (
                "rt_sigprocmask",
                libc::SYS_rt_sigprocmask,
                [libc::SIG_SETMASK as u64, set_at, 0, 8, 0, 0],
                false,
            ),
            (
                "io_uring_enter getevents sigset",
                libc::SYS_io_uring_enter,
                [3, 0, 1, IORING_ENTER_GETEVENTS, set_at, 8],
                true,
            ),
            (
                "io_uring_enter getevents ext arg",
                libc::SYS_io_uring_enter,
                [3, 0, 1, IORING_ENTER_GETEVENTS | 8, pack_at, 24],
                true,
            ),
            (
                "io_uring_enter getevents no arg",
                libc::SYS_io_uring_enter,
                [3, 0, 1, IORING_ENTER_GETEVENTS, 0, 0],
                false,
            ),
            (
                "io_uring_enter submit only",
                libc::SYS_io_uring_enter,
                [3, 1, 0, 0, set_at, 8],
                false,
            ),
        ];
        for (name, number, args, expected) in rows {
            assert_eq!(
                installs_signal_mask(rights(), *number, *args, 0),
                *expected,
                "{name}"
            );
        }
        // A waited-for signal already pending is dequeued at once, with no
        // mask installed, whatever the timeout; another pending one is not.
        let other = bit(libc::SIGUSR2);
        for timeout in [0, second_at] {
            let waits = [set_at, 0, timeout, 8, 0, 0];
            assert!(!installs_signal_mask(
                rights(),
                libc::SYS_rt_sigtimedwait,
                waits,
                set
            ));
            assert!(!installs_signal_mask(
                rights(),
                libc::SYS_rt_sigtimedwait,
                waits,
                set | other
            ));
            assert!(installs_signal_mask(
                rights(),
                libc::SYS_rt_sigtimedwait,
                waits,
                other
            ));
        }
    }
}
