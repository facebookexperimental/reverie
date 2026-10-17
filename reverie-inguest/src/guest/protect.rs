/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! What the in-guest runtime keeps the guest from: the descriptors it owns
//! (the coordinator connection and the Tool's reserved output socket) and the
//! process controls it relies on (forking when the launcher forbids it, signal
//! actions and alternate stacks). A guest syscall that would reach one fails
//! as Linux would fail it on a descriptor or control the guest does not have
//! (`close` included, with `EBADF`), and a `close_range` over one closes the
//! rest of its range without touching it.

use std::io;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::dispatch::is_fork_like;
use crate::guest::event::SyscallEvent;
use crate::guest::signal::signal_action_supported;
use crate::reserved_fds;
use crate::trap::raw_syscall6;

static COORDINATOR_FD: AtomicI32 = AtomicI32::new(-1);

#[cfg(feature = "exec-native-injection")]
pub(super) fn coordinator_fd() -> Option<libc::c_int> {
    let fd = COORDINATOR_FD.load(Ordering::Acquire);
    (fd >= 0).then_some(fd)
}

/// An output descriptor the in-guest Tool owns; see [`reserve_tool_output_fd`].
static TOOL_OUTPUT_FD: AtomicI32 = AtomicI32::new(-1);
/// The lowest number the Tool output socket takes. The coordinator connection,
/// which connects after the socket is reserved, keeps 1024 as it always has.
const TOOL_OUTPUT_FD_MIN: u64 = 1025;
/// The message the runtime sends on the Tool output socket if it ever has to
/// give the socket up; see [`reserve_tool_output_fd`].
static TOOL_OUTPUT_RETIREMENT: OnceLock<&'static [u8]> = OnceLock::new();
static PROCESS_FORKS_ALLOWED: AtomicBool = AtomicBool::new(true);

/// Whether the guest may fork. Recorded once at installation from the
/// launcher's setting; [`protect_runtime_control`] refuses fork-like calls when
/// it is false.
pub fn set_process_forks_allowed(allowed: bool) {
    PROCESS_FORKS_ALLOWED.store(allowed, Ordering::Release);
}

/// Records `fd` as the coordinator connection, which the runtime then keeps
/// the guest away from (see [`protect_runtime_descriptors`]). Fails with
/// `AlreadyExists` if one is already recorded.
pub fn reserve_coordinator_fd(fd: libc::c_int) -> io::Result<()> {
    COORDINATOR_FD
        .compare_exchange(-1, fd, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "coordinator FD reserved twice",
            )
        })
}

/// Rebinds the protected coordinator descriptor after a fork child reconnects.
///
/// The recorded descriptor is process-local after fork, so this changes only the
/// child's protection slot; the parent's connection and descriptor are intact.
pub fn replace_coordinator_fd(old: libc::c_int, new: libc::c_int) -> io::Result<()> {
    COORDINATOR_FD
        .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|actual| {
            io::Error::other(format!(
                "coordinator FD changed concurrently: expected {old}, observed {actual}"
            ))
        })
}

/// Moves `fd`, a socket the in-guest Tool owns for its own output (for example
/// one end of a socket pair its log records go to), to a reserved number at or
/// above 1025 (1024 stays the coordinator connection's), closes `fd`, and
/// returns the reserved number. From then on the runtime keeps the guest
/// away from it exactly as it does from the coordinator connection: a
/// `close_range` over it spares it, and a guest `close`, `read`, `write`,
/// `shutdown`, `send`, `setsockopt` or other descriptor operation on it fails
/// with `EBADF`, as on a number the guest does not have open. A guest `dup2`/`dup3`
/// onto its number succeeds as it would if the number were free: the runtime
/// first moves the socket to another free number at or above 1025, so the Tool
/// must read the current number from [`tool_output_fd`] for each use. Tool code
/// writes to it through its own syscalls, which the runtime does not dispatch
/// to the guest's protections. A forked child inherits the descriptor and its
/// protection.
///
/// A guest dup onto the number needs one more free descriptor at or above 1025
/// to move the socket to. When there is none (the descriptor table is full),
/// the runtime gives the socket up so the guest's call keeps its native
/// outcome: it sends `retirement` on the socket, closes the socket, and
/// [`tool_output_fd`] then returns `None`. The Tool chooses a message its
/// reader treats as "output incomplete". The send waits for room, as a
/// blocking write of any Tool record does, and finishes a partial send, so a
/// reader that keeps reading always receives the whole message, even when a
/// forked child still holds the socket open and no end-of-file comes.
///
/// Only a socket is accepted (`InvalidInput` otherwise, leaving `fd` open), as
/// for the coordinator connection: the guest can reach a regular file, pipe or
/// FIFO through other names, such as `/proc/self/fd/<n>`, and truncate, map or
/// reopen it, none of which a descriptor protection can stop; a socket cannot
/// be reopened, truncated or mapped.
///
/// # Safety
///
/// Call at most once per process, before the runtime is installed (for
/// LiteInst, before `reverie_liteinst::install_tool`), while the process is
/// still single-threaded.
pub unsafe fn reserve_tool_output_fd(
    fd: libc::c_int,
    retirement: &'static [u8],
) -> io::Result<libc::c_int> {
    // Raw syscalls throughout: this runs inside the guest, whose program or
    // preloaded libraries may define libc's wrappers.
    let mut metadata: libc::stat = unsafe { core::mem::zeroed() };
    crate::guest::support::raw_zero_result(unsafe {
        raw_syscall6(
            libc::SYS_fstat,
            [fd as u64, (&raw mut metadata) as u64, 0, 0, 0, 0],
        )
    })?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a Tool output descriptor must be a socket",
        ));
    }
    let reserved = crate::guest::support::raw_result(unsafe {
        raw_syscall6(
            libc::SYS_fcntl,
            [
                fd as u64,
                libc::F_DUPFD_CLOEXEC as u64,
                TOOL_OUTPUT_FD_MIN,
                0,
                0,
                0,
            ],
        )
    })? as libc::c_int;
    if let Err(actual) =
        TOOL_OUTPUT_FD.compare_exchange(-1, reserved, Ordering::AcqRel, Ordering::Acquire)
    {
        unsafe { raw_syscall6(libc::SYS_close, [reserved as u64, 0, 0, 0, 0, 0]) };
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("a Tool output descriptor is already reserved ({actual})"),
        ));
    }
    let _ = TOOL_OUTPUT_RETIREMENT.set(retirement);
    unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    Ok(reserved)
}

/// The Tool output socket's current number, if one is reserved
/// ([`reserve_tool_output_fd`]). It can change when the guest `dup2`s onto it,
/// so the Tool reads it for each use.
pub fn tool_output_fd() -> Option<libc::c_int> {
    let fd = TOOL_OUTPUT_FD.load(Ordering::Acquire);
    (fd >= 0).then_some(fd)
}

/// Sends all of `message` on `socket`, waiting for room as a blocking write
/// does (also when the socket was made non-blocking) and resuming a partial
/// send. It stops early only when the socket cannot take the message at all,
/// such as when its reader has gone; `MSG_NOSIGNAL` keeps that from raising
/// SIGPIPE in the guest.
fn send_retirement(socket: libc::c_int, message: &[u8]) {
    let mut rest = message;
    while !rest.is_empty() {
        let sent = unsafe {
            raw_syscall6(
                libc::SYS_sendto,
                [
                    socket as u64,
                    rest.as_ptr() as u64,
                    rest.len() as u64,
                    libc::MSG_NOSIGNAL as u64,
                    0,
                    0,
                ],
            )
        };
        if sent > 0 {
            rest = &rest[sent as usize..];
        } else if sent == -i64::from(libc::EAGAIN) {
            let mut writable = libc::pollfd {
                fd: socket,
                events: libc::POLLOUT,
                revents: 0,
            };
            let polled = unsafe {
                raw_syscall6(
                    libc::SYS_poll,
                    [(&raw mut writable) as u64, 1, -1i64 as u64, 0, 0, 0],
                )
            };
            if polled < 0 && polled != -i64::from(libc::EINTR) {
                return;
            }
        } else if sent != -i64::from(libc::EINTR) {
            return;
        }
    }
}

/// The signals whose new action [`protect_runtime_control`] refused since the
/// Tool last took them ([`take_refused_signal_controls`]), bit `n - 1` for
/// signal `n`.
static REFUSED_SIGNAL_ACTIONS: AtomicU64 = AtomicU64::new(0);

/// Whether [`protect_runtime_control`] refused an alternate signal stack since
/// the Tool last took the refusals.
static REFUSED_ALTERNATE_STACK: AtomicBool = AtomicBool::new(false);

/// The guest signal controls [`protect_runtime_control`] refused with `EPERM`,
/// which the Tool never sees as calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefusedSignalControls {
    /// The signals whose new action was refused, bit `n - 1` for signal `n`.
    pub actions: u64,
    /// Whether an alternate signal stack was refused.
    pub alternate_stack: bool,
}

/// Takes the guest signal controls refused in this process since the last
/// call, so that the Tool can report them (each refusal is reported once:
/// taking clears them). A forked child starts with its parent's record.
pub fn take_refused_signal_controls() -> RefusedSignalControls {
    // The Tool asks at every syscall; almost always nothing was refused.
    if REFUSED_SIGNAL_ACTIONS.load(Ordering::Acquire) == 0
        && !REFUSED_ALTERNATE_STACK.load(Ordering::Acquire)
    {
        return RefusedSignalControls::default();
    }
    RefusedSignalControls {
        actions: REFUSED_SIGNAL_ACTIONS.swap(0, Ordering::AcqRel),
        alternate_stack: REFUSED_ALTERNATE_STACK.swap(false, Ordering::AcqRel),
    }
}

/// Records the refusal of the guest signal control `event` asked for.
fn record_refused_signal_control(event: &SyscallEvent) {
    if event.number == libc::SYS_sigaltstack {
        REFUSED_ALTERNATE_STACK.store(true, Ordering::Release);
        return;
    }
    // Linux reads the signal argument as a C int. A number that is not a
    // signal is never refused (`signal_action_supported`).
    let signal = event.args[0] as i32;
    if (1..=64).contains(&signal) {
        REFUSED_SIGNAL_ACTIONS.fetch_or(1 << (signal - 1), Ordering::AcqRel);
    }
}

// TODO-HUMAN-REVIEW(PR-127): Review process-global preload safety guards.
/// Refuses a guest syscall that would take control from the runtime: a
/// fork-like call when process forks are not allowed (`ENOTSUP`), and a
/// signal action [`signal_action_supported`] refuses or an alternate signal
/// stack (`EPERM`). Returns whether `event` was refused, with its result set.
/// A refused signal control is recorded for the Tool to report
/// ([`take_refused_signal_controls`]).
pub fn protect_runtime_control(event: &mut SyscallEvent) -> bool {
    let unsupported_process =
        is_fork_like(event.number) && !PROCESS_FORKS_ALLOWED.load(Ordering::Acquire);
    let protected_signal =
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-133): Review fail-closed guest signal-handler policy.
        (!signal_action_supported(event.number, event.args)
            && !crate::guest::sigalrm::decides_action(event.number, event.args))
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (event.number == libc::SYS_sigaltstack && event.args[0] != 0);

    if unsupported_process {
        event.result = -i64::from(libc::ENOTSUP);
    } else if protected_signal {
        record_refused_signal_control(event);
        event.result = -i64::from(libc::EPERM);
    } else {
        return false;
    }
    true
}

/// The runtime-owned descriptors a syscall is kept from, sorted: the
/// coordinator connection, and for guest syscalls also the Tool output socket.
/// Returns the array and how many of its leading entries are in use.
#[cfg(feature = "exec-native-injection")]
const PROTECTED_FD_CAPACITY: usize = 9;
#[cfg(not(feature = "exec-native-injection"))]
const PROTECTED_FD_CAPACITY: usize = 2;

fn protected_descriptors(guest_syscall: bool) -> ([u64; PROTECTED_FD_CAPACITY], usize) {
    let mut protected = [u64::MAX; PROTECTED_FD_CAPACITY];
    let mut count = 0;
    let slots: &[&AtomicI32] = if guest_syscall {
        &[&COORDINATOR_FD, &TOOL_OUTPUT_FD]
    } else {
        &[&COORDINATOR_FD]
    };
    for slot in slots {
        let fd = slot.load(Ordering::Acquire);
        if fd >= 0 {
            protected[count] = fd as u64;
            count += 1;
        }
    }
    #[cfg(feature = "exec-native-injection")]
    if guest_syscall {
        super::native_exec_fds::append_protected(&mut protected, &mut count);
    }
    protected[..count].sort_unstable();
    (protected, count)
}

/// Keeps the guest away from the descriptors the runtime owns in Tool mode:
/// the coordinator connection and, for a guest syscall, the Tool's reserved
/// output descriptor. A syscall the Tool itself makes (`guest_syscall` false)
/// may use the output descriptor, which is the Tool's.
///
/// Returns whether `event` was handled here, with its result set.
///
/// # Safety
///
/// `event` must be the syscall being dispatched, not yet run. A guest
/// `close_range` over a protected descriptor is run here, closing the rest
/// of its range, and a guest `dup2`/`dup3` onto the Tool output socket moves
/// that socket: both act on the process's descriptor table as the guest's
/// own call would.
/// The caller must hold no live owner or borrow (`OwnedFd`, `File`,
/// `BorrowedFd` and the like) of a descriptor the call closes or moves, other
/// than the runtime's own protected descriptors, which it spares or moves
/// through their slots; a descriptor the guest closes is the guest's to close.
pub unsafe fn protect_runtime_descriptors(event: &mut SyscallEvent, guest_syscall: bool) -> bool {
    unsafe { protect_runtime_descriptors_inner(event, guest_syscall, false) }
}

/// [`protect_runtime_descriptors`] for a guest syscall that a Tool dispatches
/// next: a `close` or `close_range` is left to the Tool, so the Tool accounts
/// for the guest descriptors it closes (Detcore's descriptor table, holders
/// and port release). The Tool forwards the call through `inject` or
/// `tail_inject`, which apply [`protect_forwarded_descriptor_change`] at
/// physical execution, so the guest-visible result is the same as when this
/// function handled the call itself. Every other protection is unchanged.
///
/// # Safety
///
/// As [`protect_runtime_descriptors`].
pub unsafe fn protect_runtime_descriptors_before_tool(event: &mut SyscallEvent) -> bool {
    unsafe { protect_runtime_descriptors_inner(event, true, true) }
}

/// A guest `close` or `close_range` that a Tool forwards after
/// [`protect_runtime_descriptors_before_tool`] left it to the Tool: the same
/// protection, applied at physical execution. A `close` of a protected
/// descriptor fails with `EBADF` without closing it; a `close_range` over one
/// closes the rest of its range. Returns the result to give the Tool instead of
/// running the call, or `None` to run the call as asked.
///
/// # Safety
///
/// As [`close_range_preserving_fds`]: `number` and `args` are a `close` or
/// `close_range` the Tool runs for the guest, in the guest's own descriptor
/// table, whether the guest's call forwarded unchanged or one the Tool issues
/// on the guest's behalf. Every descriptor it closes, other than the
/// runtime's own (which are spared), is the guest's to close, and the caller
/// holds no live owner or borrow of one.
pub unsafe fn protect_forwarded_descriptor_change(number: i64, args: [u64; 6]) -> Option<i64> {
    if !is_descriptor_change_left_to_tool(number) {
        return None;
    }
    let (mut protected, count) = protected_descriptors(true);
    let protected = &mut protected[..count];
    if protected.is_empty() {
        return None;
    }
    if number == libc::SYS_close && protected.contains(&reserved_fds::descriptor_arg(&args, 0)) {
        Some(-i64::from(libc::EBADF))
    } else if number == libc::SYS_close_range && reserved_fds::close_range_covers(&args, protected)
    {
        Some(unsafe { close_range_preserving_args(args, protected) })
    } else {
        None
    }
}

/// The descriptor-closing calls a Tool must see (see
/// [`protect_runtime_descriptors_before_tool`]).
fn is_descriptor_change_left_to_tool(number: i64) -> bool {
    matches!(number, libc::SYS_close | libc::SYS_close_range)
}

unsafe fn protect_runtime_descriptors_inner(
    event: &mut SyscallEvent,
    guest_syscall: bool,
    leave_descriptor_changes_to_tool: bool,
) -> bool {
    if leave_descriptor_changes_to_tool && is_descriptor_change_left_to_tool(event.number) {
        return false;
    }
    let (mut protected, count) = protected_descriptors(guest_syscall);
    let protected = &mut protected[..count];
    if protected.is_empty() {
        return false;
    }
    if guest_syscall {
        match unsafe { relocate_tool_output_for_dup(event, protected) } {
            DupOntoToolOutput::NotThis => {}
            DupOntoToolOutput::Proceed => return false,
            DupOntoToolOutput::Refuse(result) => {
                event.result = result;
                return true;
            }
        }
    }
    if event.number == libc::SYS_close && protected.contains(&fd_arg(event, 0)) {
        event.result = -i64::from(libc::EBADF);
    } else if event.number == libc::SYS_close_range
        && reserved_fds::close_range_covers(&event.args, protected)
    {
        event.result = unsafe { close_range_preserving_fds(event, protected) };
    } else if let Some(result) = protected
        .iter()
        .find_map(|&fd| reserved_fds::epoll_wait_result(event.number, &event.args, fd))
    {
        event.result = result;
    } else if protected.iter().any(|&fd| {
        syscall_targets_event_fd(event, fd)
            || (guest_syscall
                && reserved_fds::socket_call_names_descriptor(event.number, &event.args, fd))
    }) {
        event.result = -i64::from(libc::EBADF);
    } else {
        return false;
    }
    true
}

/// What to do with a guest syscall that may be a `dup2`/`dup3` onto the Tool
/// output socket's number.
enum DupOntoToolOutput {
    /// Not such a call: protect as usual.
    NotThis,
    /// The socket's number is free now; run the guest's call.
    Proceed,
    /// The call fails as Linux would fail it, before anything moved.
    Refuse(i64),
}

/// A guest `dup2`/`dup3` onto the Tool output socket's number is an ordinary
/// operation the guest is entitled to: that number is free as far as the guest
/// knows. First applies the kernel's own checks, in its order, without moving
/// anything: `dup3` flags other than `O_CLOEXEC` (`EINVAL`), a target at or
/// above `RLIMIT_NOFILE`, and a source that is not open (`EBADF`). Then moves
/// the socket to another free number at or above 1025 and closes the old one,
/// so the guest's call runs on a free number with its native outcome. When no
/// descriptor is free to move it to, gives the socket up instead (see
/// [`reserve_tool_output_fd`]). No unprotected copy of the socket is left
/// behind on any path.
unsafe fn relocate_tool_output_for_dup(
    event: &SyscallEvent,
    protected: &[u64],
) -> DupOntoToolOutput {
    if !matches!(event.number, libc::SYS_dup2 | libc::SYS_dup3) {
        return DupOntoToolOutput::NotThis;
    }
    let tool = TOOL_OUTPUT_FD.load(Ordering::Acquire);
    let source = fd_arg(event, 0);
    if tool < 0 || fd_arg(event, 1) != tool as u64 || protected.contains(&source) {
        return DupOntoToolOutput::NotThis;
    }
    if event.number == libc::SYS_dup3 && fd_arg(event, 2) & !(libc::O_CLOEXEC as u64) != 0 {
        return DupOntoToolOutput::Refuse(-i64::from(libc::EINVAL));
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let queried = unsafe {
        raw_syscall6(
            libc::SYS_prlimit64,
            [
                0,
                libc::RLIMIT_NOFILE as u64,
                0,
                (&raw mut limit) as u64,
                0,
                0,
            ],
        )
    };
    if queried == 0 && tool as u64 >= limit.rlim_cur {
        return DupOntoToolOutput::Refuse(-i64::from(libc::EBADF));
    }
    if unsafe { raw_syscall6(libc::SYS_fcntl, [source, libc::F_GETFD as u64, 0, 0, 0, 0]) } < 0 {
        return DupOntoToolOutput::Refuse(-i64::from(libc::EBADF));
    }
    let moved = unsafe {
        raw_syscall6(
            libc::SYS_fcntl,
            [
                tool as u64,
                libc::F_DUPFD_CLOEXEC as u64,
                TOOL_OUTPUT_FD_MIN,
                0,
                0,
                0,
            ],
        )
    };
    let replacement = if moved >= 0 { moved as i32 } else { -1 };
    if TOOL_OUTPUT_FD
        .compare_exchange(tool, replacement, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        if moved >= 0 {
            unsafe { raw_syscall6(libc::SYS_close, [moved as u64, 0, 0, 0, 0, 0]) };
        }
        return DupOntoToolOutput::NotThis;
    }
    if moved < 0 {
        // No descriptor to move the socket to: tell its reader the output is
        // incomplete, then give it up.
        if let Some(message) = TOOL_OUTPUT_RETIREMENT.get() {
            send_retirement(tool, message);
        }
    }
    // The socket lives on as `moved`, or not at all; the guest's call gets the
    // old number.
    unsafe { raw_syscall6(libc::SYS_close, [tool as u64, 0, 0, 0, 0, 0]) };
    DupOntoToolOutput::Proceed
}

/// Runs a guest `close_range` without closing any of `preserved`, which is sorted.
///
/// # Safety
///
/// `event` must be a `close_range` the guest asked for: the descriptors in its
/// range other than `preserved` are closed.
/// The caller must hold no live owner or borrow (`OwnedFd`, `File`,
/// `BorrowedFd` and the like) of a descriptor the call closes, other than
/// those in `preserved`; a descriptor the guest closes is the guest's to
/// close.
pub unsafe fn close_range_preserving_fds(event: &SyscallEvent, preserved: &[u64]) -> i64 {
    unsafe { close_range_preserving_args(event.args, preserved) }
}

/// [`close_range_preserving_fds`] on the call's raw argument registers.
///
/// # Safety
///
/// As [`close_range_preserving_fds`].
unsafe fn close_range_preserving_args(args: [u64; 6], preserved: &[u64]) -> i64 {
    unsafe {
        reserved_fds::close_range_sparing(&args, preserved, |number, args| {
            raw_syscall6(number, args)
        })
    }
}

/// Syscall argument `index` as the kernel reads a descriptor, `close_range`
/// bound or flags argument: the low 32 bits of the register. Comparing the full
/// register would let `fd | 1 << 32` reach the descriptor past a protection.
pub fn fd_arg(event: &SyscallEvent, index: usize) -> u64 {
    reserved_fds::descriptor_arg(&event.args, index)
}

/// Whether `event` operates on descriptor `event_fd` through one of its
/// descriptor arguments, by the shared rule
/// [`reserved_fds::names_descriptor`]. It does not cover the socket calls,
/// close, close_range or epoll readiness; [`protect_runtime_descriptors`]
/// checks all of those for the runtime's own descriptors.
pub fn syscall_targets_event_fd(event: &SyscallEvent, event_fd: u64) -> bool {
    reserved_fds::names_descriptor(event.number, &event.args, event_fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::event::SyscallDispatch;

    fn event(number: i64, args: [u64; 6]) -> SyscallEvent {
        SyscallEvent {
            number,
            args,
            instruction_pointer: 0x1234,
            result: 0,
            context: 0,
            dispatch: SyscallDispatch::Trap,
            guest_pkru: None,
        }
    }

    /// A refused handler or alternate stack is recorded for the Tool, once:
    /// taking the record clears it. A query, a default action and an
    /// alternate-stack query are not refused and not recorded.
    #[test]
    fn refused_signal_controls_are_recorded_for_the_tool_once() {
        // A struct sigaction whose handler is an address, read from this
        // process's own memory as the runtime reads the guest's.
        let handler: [u64; 4] = [0x4000, 0, 0, 0];
        let default: [u64; 4] = [libc::SIG_DFL as u64, 0, 0, 0];
        let stack = [0u64; 3];
        let _ = take_refused_signal_controls();

        let mut install = event(
            libc::SYS_rt_sigaction,
            [libc::SIGUSR1 as u64, handler.as_ptr() as u64, 0, 8, 0, 0],
        );
        assert!(protect_runtime_control(&mut install));
        assert_eq!(install.result, -i64::from(libc::EPERM));
        let mut alternate = event(
            libc::SYS_sigaltstack,
            [stack.as_ptr() as u64, 0, 0, 0, 0, 0],
        );
        assert!(protect_runtime_control(&mut alternate));
        for allowed in [
            event(
                libc::SYS_rt_sigaction,
                [libc::SIGUSR2 as u64, 0, 0, 8, 0, 0],
            ),
            // Not signals: Linux refuses them (EINVAL), so the runtime does
            // not, and there is nothing to record.
            event(
                libc::SYS_rt_sigaction,
                [0, handler.as_ptr() as u64, 0, 8, 0, 0],
            ),
            event(
                libc::SYS_rt_sigaction,
                [65, handler.as_ptr() as u64, 0, 8, 0, 0],
            ),
            event(
                libc::SYS_rt_sigaction,
                [libc::SIGUSR2 as u64, default.as_ptr() as u64, 0, 8, 0, 0],
            ),
            event(
                libc::SYS_sigaltstack,
                [0, stack.as_ptr() as u64, 0, 0, 0, 0],
            ),
        ] {
            let mut allowed = allowed;
            assert!(!protect_runtime_control(&mut allowed), "{:?}", allowed.args);
        }
        assert_eq!(
            take_refused_signal_controls(),
            RefusedSignalControls {
                actions: 1 << (libc::SIGUSR1 - 1),
                alternate_stack: true,
            }
        );
        assert_eq!(
            take_refused_signal_controls(),
            RefusedSignalControls::default(),
            "taken once"
        );
    }

    /// The Tool's own signal controls are refused on their own path, before
    /// `protect_runtime_control`, and are not the guest's: nothing is
    /// recorded for them.
    #[test]
    fn the_tools_own_signal_controls_are_not_recorded() {
        let handler: [u64; 4] = [0x4000, 0, 0, 0];
        let stack = [0u64; 3];
        let _ = take_refused_signal_controls();
        for (number, args) in [
            (
                libc::SYS_rt_sigaction,
                [libc::SIGUSR1 as u64, handler.as_ptr() as u64, 0, 8, 0, 0],
            ),
            (
                libc::SYS_sigaltstack,
                [stack.as_ptr() as u64, 0, 0, 0, 0, 0],
            ),
        ] {
            let mut nested = event(number, args);
            // SAFETY: both calls are refused before anything is forwarded.
            unsafe {
                crate::guest::trap_dispatch::forward_nested_tool_syscall(&mut nested, |_| {})
            };
            assert_eq!(nested.result, -i64::from(libc::EPERM), "{number}");
        }
        assert_eq!(
            take_refused_signal_controls(),
            RefusedSignalControls::default()
        );
    }
}
