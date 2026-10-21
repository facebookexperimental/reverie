/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The guest process's signal state under the in-guest runtime: which
//! signals must stay unblocked, the reset of inherited handlers at
//! installation, and which `rt_sigaction` calls the guest may make.

use std::io;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::guest::instruction::InstructionSubscriptions;
use crate::guest::instruction::any_instruction_subscribed;
use crate::guest::support::KernelSigaction;
use crate::guest::support::SignalInstallGuard;
use crate::trap::raw_syscall6;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-913): Review the reserved-signal set kept unblocked.
/// Signals the runtime receives as forced signals and so must never be
/// blocked: SIGSYS for every trapped system call, and SIGSEGV for CPUID or
/// RDTSC faulting while an instruction is subscribed. Linux resets a blocked
/// forced signal to its default action, which kills the process.
pub fn reserved_signal_mask() -> u64 {
    let mut reserved = 1_u64 << (libc::SIGSYS - 1);
    if any_instruction_subscribed() {
        reserved |= 1_u64 << (libc::SIGSEGV - 1);
    }
    reserved
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review atomic signal-state preparation.
/// Prepares this process's signal state for the runtime: blocks every signal
/// and returns a guard that restores the caller's mask with SIGSYS (and
/// SIGSEGV when an instruction is subscribed) removed, so those forced
/// signals stay deliverable. Every inherited handler other than `SIG_DFL` or
/// `SIG_IGN` is reset to `SIG_DFL` while the mask is held, so no handler
/// installed before the runtime can run guest code it would not observe.
pub fn prepare_guest_signal_state(
    instructions: InstructionSubscriptions,
) -> io::Result<SignalInstallGuard> {
    let sigsys = 1_u64 << (libc::SIGSYS - 1);
    let sigsegv = if instructions.cpuid || instructions.rdtsc {
        1_u64 << (libc::SIGSEGV - 1)
    } else {
        0
    };
    let install_mask = u64::MAX;
    let mut previous_mask = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_SETMASK as u64,
                (&raw const install_mask) as u64,
                (&raw mut previous_mask) as u64,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error((-result) as i32));
    }
    let guard = SignalInstallGuard::restoring(previous_mask & !(sigsys | sigsegv));

    for signal in 1..=64 {
        if matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
            continue;
        }
        let mut action = KernelSigaction::default();
        let result = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigaction,
                [
                    signal as u64,
                    0,
                    (&raw mut action) as u64,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error((-result) as i32));
        }
        if action.handler != libc::SIG_DFL as u64 && action.handler != libc::SIG_IGN as u64 {
            let default_action = KernelSigaction::default();
            let result = unsafe {
                raw_syscall6(
                    libc::SYS_rt_sigaction,
                    [
                        signal as u64,
                        (&raw const default_action) as u64,
                        0,
                        core::mem::size_of::<u64>() as u64,
                        0,
                        0,
                    ],
                )
            };
            if result < 0 {
                return Err(io::Error::from_raw_os_error((-result) as i32));
            }
        }
    }
    Ok(guard)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review fault-safe guest signal-action decoding.
/// Whether the runtime can let the guest's `rt_sigaction(number, args)` run.
/// Any other syscall, and a query without a new action, is supported. A new
/// action for SIGSYS (or SIGSEGV while an instruction is subscribed) is not;
/// for any other signal only `SIG_DFL` and `SIG_IGN` are, because a guest
/// handler would run outside the Tool's view. The handler is read from the
/// guest's `struct sigaction` with `process_vm_readv`, so an unreadable
/// pointer is refused rather than faulting. A new action for SIGKILL or
/// SIGSTOP, or for a number that is not a signal (0, or above 64), is
/// supported whatever it holds: Linux refuses it (EINVAL, or EFAULT for an
/// unreadable action) without changing anything, and a program may make that
/// call to validate its signal handling.
pub fn signal_action_supported(number: i64, args: [u64; 6]) -> bool {
    if number != libc::SYS_rt_sigaction || args[1] == 0 {
        return true;
    }
    // Linux reads the signal argument as a C int.
    let signal = args[0] as i32;
    if signal == libc::SIGKILL || signal == libc::SIGSTOP || !(1..=64).contains(&signal) {
        return true;
    }
    if signal == libc::SIGSYS || (signal == libc::SIGSEGV && any_instruction_subscribed()) {
        return false;
    }

    let mut handler = 0_u64;
    let local = libc::iovec {
        iov_base: (&raw mut handler).cast(),
        iov_len: core::mem::size_of::<u64>(),
    };
    let remote = libc::iovec {
        iov_base: args[1] as usize as *mut libc::c_void,
        iov_len: core::mem::size_of::<u64>(),
    };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let read = unsafe {
        raw_syscall6(
            libc::SYS_process_vm_readv,
            [
                pid as u64,
                (&raw const local) as u64,
                1,
                (&raw const remote) as u64,
                1,
                0,
            ],
        )
    };
    read == core::mem::size_of::<u64>() as i64
        && matches!(handler, value if value == libc::SIG_DFL as u64 || value == libc::SIG_IGN as u64)
}

/// Whether Linux's default action for the standard signal `signal` (1 to 31)
/// ends the process: "terminate" or "core" in signal(7). The ignored-by-default
/// signals (SIGCHLD, SIGCONT, SIGURG, SIGWINCH) and the stop signals
/// (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU) do not, and neither does a number
/// outside 1 to 31. Realtime signals are left out on purpose: a Reverie Tool's
/// `Signal` cannot name them, so a death by one cannot be reported to it.
pub fn default_action_ends_process(signal: i32) -> bool {
    (1..=31).contains(&signal)
        && !matches!(
            signal,
            libc::SIGCHLD
                | libc::SIGCONT
                | libc::SIGURG
                | libc::SIGWINCH
                | libc::SIGSTOP
                | libc::SIGTSTP
                | libc::SIGTTIN
                | libc::SIGTTOU
        )
}

/// The signal a `kill`, `tkill` or `tgkill` call sends to the calling thread
/// `tid` of process `pid` itself, read as Linux reads the arguments (C ints),
/// or `None` for any other call or target. `kill` names the calling process
/// with its exact process id; process-group and broadcast targets
/// (`pid <= 0`) are not the caller alone and are left out. Signal 0 sends
/// nothing.
pub fn signal_sent_to_caller(number: i64, args: [u64; 6], pid: i32, tid: i32) -> Option<i32> {
    let (signal, targets_caller) = match number {
        libc::SYS_tgkill => (
            args[2] as i32,
            args[0] as i32 == pid && args[1] as i32 == tid,
        ),
        libc::SYS_tkill => (args[1] as i32, args[0] as i32 == tid),
        libc::SYS_kill => (args[1] as i32, args[0] as i32 == pid),
        _ => return None,
    };
    (targets_caller && signal != 0).then_some(signal)
}

/// Whether `signal`, sent to the calling thread now, is delivered as the
/// sending call returns and ends the process, given the calling thread's
/// blocked set `blocked` and the process's action for `signal`, `handler`
/// (`SIG_DFL`, `SIG_IGN` or a handler address).
///
/// SIGKILL always ends it. Any other signal ends it only when it is a standard
/// signal whose default action ends the process
/// ([`default_action_ends_process`]), the thread does not block it, and the
/// action is `SIG_DFL`. A blocked signal stays pending, an ignored one is
/// discarded, and a caught one runs a handler, which only the runtime itself
/// installs in-guest (guest handlers are refused, see
/// [`signal_action_supported`]). SIGSYS is the runtime's own (a handler is
/// installed), and is never classified as a death here either way.
pub fn self_signal_ends_process(signal: i32, blocked: u64, handler: u64) -> bool {
    if signal == libc::SIGKILL {
        return true;
    }
    if crate::signal::is_reserved(signal) || !default_action_ends_process(signal) {
        return false;
    }
    let bit = 1_u64 << (signal - 1);
    blocked & bit == 0 && handler == libc::SIG_DFL as u64
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-self-signal-death): Review the prediction that a
// self-directed signal ends the process.
/// The signal with which the guest's `number(args)` would end its own
/// process as the call returns, if it is one: a `kill`, `tkill` or `tgkill`
/// naming the calling thread or process ([`signal_sent_to_caller`]) with a
/// signal whose delivery now ends the process
/// ([`signal_ends_process_now`]). This is what `abort(3)`, `raise(3)` and
/// `assert(3)` do.
///
/// Such a death happens at a point of the guest's own program order, in its
/// own turn, so the runtime can report it to the Tool before it happens, as
/// it reports an `exit_group`, instead of leaving the process to die without
/// deregistering. Linux delivers a signal the caller sends itself before the
/// sending call returns to user space when the caller does not block it: the
/// signal is pending on the caller (or, for `kill`, on its process, where
/// `complete_signal` picks the caller first because it wants the signal),
/// and the return path delivers it. A fatal default action then ends every
/// thread of the group.
///
/// This classification is made when the call is made. The runtime makes the
/// final decision only after the Tool has seen the signal, by reading the
/// state again (see `ToolHost::dispatch`), because the Tool's own callbacks
/// can change the action or the mask.
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate, so it must run on the guest
/// thread's own syscall path (a trap, a hook or the fallback continuation).
pub unsafe fn self_directed_fatal_signal(number: i64, args: [u64; 6]) -> Option<i32> {
    if !matches!(number, libc::SYS_kill | libc::SYS_tkill | libc::SYS_tgkill) {
        return None;
    }
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    if pid <= 0 || tid <= 0 {
        return None;
    }
    let signal = signal_sent_to_caller(number, args, pid as i32, tid as i32)?;
    unsafe { signal_ends_process_now(signal) }.then_some(signal)
}

/// A handler the runtime installed for one signal on the guest's behalf: the
/// signal, the handler's address, and the guest's own action for the signal
/// (`SIG_DFL` or `SIG_IGN`), which the handler applies to every delivery that
/// is not the runtime's own. 0 for the signal while none is registered.
static ROUTED_SIGNAL: AtomicI32 = AtomicI32::new(0);
static ROUTER_HANDLER: AtomicU64 = AtomicU64::new(0);
static ROUTED_GUEST_ACTION: AtomicU64 = AtomicU64::new(0);

/// Registers `router`, the handler the runtime has just installed for
/// `signal`, which routes the runtime's own deliveries of it and gives every
/// other delivery the guest's action `guest_action` (`SIG_DFL` or `SIG_IGN`):
/// the action `signal` had when the runtime replaced it. LiteInst's SIGTRAP
/// guard router is one: it takes the breakpoints the runtime plants while it
/// patches a syscall site, and for any other SIGTRAP (a guest's `raise`)
/// restores `guest_action` and sends the signal again.
///
/// While the kernel's action for `signal` is still `router`,
/// [`signal_ends_process_now`] judges the signal by `guest_action`, as Linux
/// would act on it for the guest. Once the guest installs an action of its
/// own (which replaces the router), the kernel's action is the guest's again.
/// Call once, before the runtime's seccomp filter is installed; a later call
/// replaces the registration.
pub fn register_routing_handler(signal: i32, router: u64, guest_action: u64) {
    ROUTER_HANDLER.store(router, Ordering::Relaxed);
    ROUTED_GUEST_ACTION.store(guest_action, Ordering::Relaxed);
    ROUTED_SIGNAL.store(signal, Ordering::Release);
}

/// The guest's own action for `signal` when the kernel's is `kernel_handler`:
/// the registered guest action while `kernel_handler` is the registered
/// router of `signal` ([`register_routing_handler`]), and `kernel_handler`
/// otherwise.
pub fn guest_action(signal: i32, kernel_handler: u64) -> u64 {
    let routed = ROUTED_SIGNAL.load(Ordering::Acquire);
    guest_action_with(
        (routed != 0).then(|| {
            (
                routed,
                ROUTER_HANDLER.load(Ordering::Relaxed),
                ROUTED_GUEST_ACTION.load(Ordering::Relaxed),
            )
        }),
        signal,
        kernel_handler,
    )
}

/// [`guest_action`] for the registration `(signal, router, guest action)`.
fn guest_action_with(routing: Option<(i32, u64, u64)>, signal: i32, kernel_handler: u64) -> u64 {
    match routing {
        Some((routed, router, action)) if routed == signal && router == kernel_handler => action,
        _ => kernel_handler,
    }
}

/// Whether `signal`, sent to the calling thread now, would be delivered at
/// once and end the process ([`self_signal_ends_process`]), read from the
/// kernel: the thread's current blocked set and the signal's current action,
/// taken as the guest's own action where the runtime routes the signal for
/// the guest ([`guest_action`]).
///
/// On the installed-hook path the runtime runs with the guest's own mask. On
/// the SIGSYS path the handler mask adds only SIGSYS, which this never
/// classifies, and with the virtual SIGALRM of signal phase 1 a handled
/// SIGALRM's physical action is the runtime's trampoline, so it is not
/// `SIG_DFL` and not classified. A failed read classifies nothing.
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate, so it must run on the guest
/// thread's own syscall path.
pub unsafe fn signal_ends_process_now(signal: i32) -> bool {
    if signal == libc::SIGKILL {
        return true;
    }
    if !default_action_ends_process(signal) || crate::signal::is_reserved(signal) {
        return false;
    }
    let Some(blocked) = (unsafe { current_blocked_set() }) else {
        return false;
    };
    let mut action = KernelSigaction::default();
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigaction,
            [
                signal as u64,
                0,
                (&raw mut action) as u64,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
    };
    result == 0 && self_signal_ends_process(signal, blocked, guest_action(signal, action.handler))
}

/// The calling thread's blocked set, through the trusted gate.
unsafe fn current_blocked_set() -> Option<u64> {
    let mut blocked = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_BLOCK as u64,
                0,
                (&raw mut blocked) as u64,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
    };
    (result == 0).then_some(blocked)
}

/// The signals pending for the calling thread (its own and its process's),
/// through the trusted gate.
///
/// # Safety
///
/// Issues a raw syscall through the trusted gate, so it must run on the guest
/// thread's own syscall path.
pub unsafe fn current_pending_set() -> Option<u64> {
    let mut pending = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigpending,
            [
                (&raw mut pending) as u64,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
                0,
                0,
            ],
        )
    };
    (result == 0).then_some(pending)
}

/// Whether Linux's default action for `signal` is "core" in signal(7):
/// terminate and dump core.
pub fn default_action_dumps_core(signal: i32) -> bool {
    matches!(
        signal,
        libc::SIGQUIT
            | libc::SIGILL
            | libc::SIGTRAP
            | libc::SIGABRT
            | libc::SIGBUS
            | libc::SIGFPE
            | libc::SIGSEGV
            | libc::SIGXCPU
            | libc::SIGXFSZ
            | libc::SIGSYS
    )
}

/// The kind of destination `/proc/sys/kernel/core_pattern` names, by its
/// first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorePattern {
    /// `|program`: the kernel pipes the core to a helper.
    Pipe,
    /// `/path`: an absolute file name.
    AbsolutePath,
    /// Any other file name, relative to the dying process's directory.
    RelativePath,
    /// Unreadable, empty, or a form this does not model (such as a leading
    /// `@`, a socket on newer kernels).
    Unknown,
}

impl CorePattern {
    /// Classifies a pattern by its first byte.
    pub fn from_first_byte(byte: Option<u8>) -> Self {
        match byte {
            Some(b'|') => Self::Pipe,
            Some(b'/') => Self::AbsolutePath,
            Some(b'@') | Some(b'\n') | None => Self::Unknown,
            Some(_) => Self::RelativePath,
        }
    }
}

/// `SUID_DUMP_ROOT`, the `PR_GET_DUMPABLE` value with which Linux dumps only
/// to a pipe or an absolute path.
const SUID_DUMP_ROOT: i64 = 2;

/// Whether Linux's `do_coredump` would write a core when `signal` ends a
/// process whose dumpable mode (`PR_GET_DUMPABLE`) is `dumpable`, whose soft
/// `RLIMIT_CORE` is `core_limit`, under `pattern`, on a system with page size
/// `page_size`. These are the checks `fs/coredump.c` makes before it writes
/// anything: the signal's default action must be "core"; the process must be
/// dumpable; a `SUID_DUMP_ROOT` process dumps only to a pipe or an absolute
/// path; a pipe dumps unless the limit is exactly 1 (the kernel's documented
/// opt-out for pipes); a file needs a limit of at least one page (the ELF
/// format's `min_coredump`). An `Unknown` pattern predicts no core.
pub fn core_dump_attempted(
    signal: i32,
    dumpable: i64,
    core_limit: u64,
    pattern: CorePattern,
    page_size: u64,
) -> bool {
    if !default_action_dumps_core(signal) || dumpable <= 0 {
        return false;
    }
    match pattern {
        CorePattern::Pipe => core_limit != 1,
        CorePattern::AbsolutePath => core_limit >= page_size,
        CorePattern::RelativePath => dumpable != SUID_DUMP_ROOT && core_limit >= page_size,
        CorePattern::Unknown => false,
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-self-signal-death): Review the core-dump
// prediction reported to the Tool's exit callbacks.
/// The core-dump flag to report with a death by `signal` that has not
/// happened yet ([`core_dump_attempted`], from this process's dumpable mode,
/// its soft `RLIMIT_CORE`, the system's `core_pattern` and page size, all read
/// now).
///
/// This is a prediction, and the one input it cannot see is whether the
/// kernel's write then succeeds (a pipe helper that is gone, a full disk, an
/// unwritable directory). The in-guest runtime reports the exit callbacks
/// before the death because the Tool runs inside the dying process, so no
/// authoritative status exists yet; a backend that observes the death from
/// outside reports the kernel's status instead.
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate, so it must run on the guest
/// thread's own syscall path.
pub unsafe fn core_dump_expected(signal: i32) -> bool {
    if !default_action_dumps_core(signal) {
        return false;
    }
    let dumpable = unsafe {
        raw_syscall6(
            libc::SYS_prctl,
            [libc::PR_GET_DUMPABLE as u64, 0, 0, 0, 0, 0],
        )
    };
    let mut limit = libc::rlimit64 {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe {
        raw_syscall6(
            libc::SYS_prlimit64,
            [
                0,
                libc::RLIMIT_CORE as u64,
                0,
                (&raw mut limit) as u64,
                0,
                0,
            ],
        )
    };
    if result != 0 {
        return false;
    }
    let Ok(page_size) = crate::guest::support::page_size() else {
        return false;
    };
    let pattern = CorePattern::from_first_byte(unsafe { core_pattern_first_byte() });
    core_dump_attempted(signal, dumpable, limit.rlim_cur, pattern, page_size)
}

/// The first byte of `/proc/sys/kernel/core_pattern`, read through the
/// trusted gate into a stack buffer, or `None` if it cannot be read.
unsafe fn core_pattern_first_byte() -> Option<u8> {
    let path = c"/proc/sys/kernel/core_pattern";
    let fd = unsafe {
        raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                path.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return None;
    }
    let mut byte = 0_u8;
    let read = unsafe {
        raw_syscall6(
            libc::SYS_read,
            [fd as u64, (&raw mut byte) as u64, 1, 0, 0, 0],
        )
    };
    let _ = unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    (read == 1).then_some(byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_actions_that_end_the_process() {
        let ending: Vec<i32> = (0..=40)
            .filter(|signal| default_action_ends_process(*signal))
            .collect();
        assert_eq!(
            ending,
            vec![
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGILL,
                libc::SIGTRAP,
                libc::SIGABRT,
                libc::SIGBUS,
                libc::SIGFPE,
                libc::SIGKILL,
                libc::SIGUSR1,
                libc::SIGSEGV,
                libc::SIGUSR2,
                libc::SIGPIPE,
                libc::SIGALRM,
                libc::SIGTERM,
                libc::SIGSTKFLT,
                libc::SIGXCPU,
                libc::SIGXFSZ,
                libc::SIGVTALRM,
                libc::SIGPROF,
                libc::SIGIO,
                libc::SIGPWR,
                libc::SIGSYS,
            ]
        );
    }

    #[test]
    fn only_a_kill_family_call_naming_the_caller_targets_it() {
        let (pid, tid) = (40, 41);
        let sig = libc::SIGABRT as u64;
        let high = 0x1_0000_0000_u64;
        // tgkill: both ids must name the caller; the arguments are C ints.
        assert_eq!(
            signal_sent_to_caller(libc::SYS_tgkill, [40, 41, sig, 0, 0, 0], pid, tid),
            Some(libc::SIGABRT)
        );
        assert_eq!(
            signal_sent_to_caller(
                libc::SYS_tgkill,
                [high | 40, high | 41, high | sig, 0, 0, 0],
                pid,
                tid
            ),
            Some(libc::SIGABRT)
        );
        assert_eq!(
            signal_sent_to_caller(libc::SYS_tgkill, [40, 42, sig, 0, 0, 0], pid, tid),
            None
        );
        assert_eq!(
            signal_sent_to_caller(libc::SYS_tgkill, [39, 41, sig, 0, 0, 0], pid, tid),
            None
        );
        // tkill names the thread.
        assert_eq!(
            signal_sent_to_caller(libc::SYS_tkill, [41, sig, 0, 0, 0, 0], pid, tid),
            Some(libc::SIGABRT)
        );
        assert_eq!(
            signal_sent_to_caller(libc::SYS_tkill, [40, sig, 0, 0, 0, 0], pid, tid),
            None
        );
        // kill names the process exactly; groups and broadcast are not the
        // caller alone.
        assert_eq!(
            signal_sent_to_caller(libc::SYS_kill, [40, sig, 0, 0, 0, 0], pid, tid),
            Some(libc::SIGABRT)
        );
        for group in [0_u64, (-1_i64) as u64, (-40_i64) as u64] {
            assert_eq!(
                signal_sent_to_caller(libc::SYS_kill, [group, sig, 0, 0, 0, 0], pid, tid),
                None
            );
        }
        // Signal 0 sends nothing; other calls send nothing.
        assert_eq!(
            signal_sent_to_caller(libc::SYS_kill, [40, 0, 0, 0, 0, 0], pid, tid),
            None
        );
        assert_eq!(
            signal_sent_to_caller(libc::SYS_rt_sigqueueinfo, [40, sig, 0, 0, 0, 0], pid, tid),
            None
        );
    }

    #[test]
    fn a_self_signal_ends_the_process_only_unblocked_with_its_default_action() {
        let dfl = libc::SIG_DFL as u64;
        let ign = libc::SIG_IGN as u64;
        let abrt = 1_u64 << (libc::SIGABRT - 1);
        assert!(self_signal_ends_process(libc::SIGABRT, 0, dfl));
        assert!(!self_signal_ends_process(libc::SIGABRT, abrt, dfl));
        assert!(!self_signal_ends_process(libc::SIGABRT, 0, ign));
        assert!(!self_signal_ends_process(libc::SIGABRT, 0, 0x1000));
        // SIGKILL can be neither blocked nor caught.
        assert!(self_signal_ends_process(libc::SIGKILL, u64::MAX, 0x1000));
        // Not fatal by default, reserved, realtime, or out of range.
        assert!(!self_signal_ends_process(libc::SIGCHLD, 0, dfl));
        assert!(!self_signal_ends_process(libc::SIGTSTP, 0, dfl));
        assert!(!self_signal_ends_process(libc::SIGSYS, 0, dfl));
        assert!(!self_signal_ends_process(libc::SIGRTMIN(), 0, dfl));
        assert!(!self_signal_ends_process(0, 0, dfl));
        assert!(!self_signal_ends_process(65, 0, dfl));
    }

    /// While the kernel's action for a routed signal is the runtime's router,
    /// the guest's own action stands in for it; any other action, or another
    /// signal, is taken as the kernel has it. So a guest `raise(SIGTRAP)`
    /// under LiteInst's guard router is a death when the guest's SIGTRAP is
    /// `SIG_DFL`, and not when it is `SIG_IGN`.
    #[test]
    fn a_routed_signal_is_judged_by_the_guests_own_action() {
        let dfl = libc::SIG_DFL as u64;
        let ign = libc::SIG_IGN as u64;
        let router = 0x7000_u64;
        let trap = libc::SIGTRAP;
        for action in [dfl, ign] {
            let routing = Some((trap, router, action));
            assert_eq!(guest_action_with(routing, trap, router), action);
            // The guest replaced the router with an action of its own.
            assert_eq!(guest_action_with(routing, trap, ign), ign);
            assert_eq!(guest_action_with(routing, trap, dfl), dfl);
            // Another signal, or no registration: the kernel's action.
            assert_eq!(guest_action_with(routing, libc::SIGABRT, router), router);
            assert_eq!(guest_action_with(None, trap, router), router);
        }
        assert!(self_signal_ends_process(
            trap,
            0,
            guest_action_with(Some((trap, router, dfl)), trap, router)
        ));
        assert!(!self_signal_ends_process(
            trap,
            0,
            guest_action_with(Some((trap, router, ign)), trap, router)
        ));
        // Without the registration the router reads as a caught signal.
        assert!(!self_signal_ends_process(trap, 0, router));
    }

    /// Read against this test thread's real signal state: a caught or blocked
    /// signal is not a death, and a call naming another process is not
    /// either. (Nothing here sends a signal.)
    #[test]
    fn the_prediction_reads_the_threads_real_mask_and_action() {
        let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) } as u64;
        let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
        let usr2 = libc::SIGUSR2 as u64;
        let mut previous = KernelSigaction::default();
        unsafe { crate::signal::raw_sigaction(libc::SIGUSR2, None, Some(&mut previous)) }.unwrap();
        // SIG_DFL and unblocked: a death.
        let default = KernelSigaction::default();
        unsafe { crate::signal::raw_sigaction(libc::SIGUSR2, Some(&default), None) }.unwrap();
        let mut old_mask = 0_u64;
        let usr2_bit = 1_u64 << (libc::SIGUSR2 - 1);
        unsafe {
            crate::signal::raw_sigprocmask(libc::SIG_UNBLOCK, Some(&usr2_bit), Some(&mut old_mask))
        }
        .unwrap();
        let tgkill = [pid, tid, usr2, 0, 0, 0];
        assert_eq!(
            unsafe { self_directed_fatal_signal(libc::SYS_tgkill, tgkill) },
            Some(libc::SIGUSR2)
        );
        assert_eq!(
            unsafe { self_directed_fatal_signal(libc::SYS_kill, [pid, usr2, 0, 0, 0, 0]) },
            Some(libc::SIGUSR2)
        );
        // Another process: not the caller.
        assert_eq!(
            unsafe { self_directed_fatal_signal(libc::SYS_kill, [pid + 1, usr2, 0, 0, 0, 0]) },
            None
        );
        // Blocked: it would stay pending.
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_BLOCK, Some(&usr2_bit), None) }.unwrap();
        assert_eq!(
            unsafe { self_directed_fatal_signal(libc::SYS_tgkill, tgkill) },
            None
        );
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_UNBLOCK, Some(&usr2_bit), None) }
            .unwrap();
        // Ignored: it would be discarded.
        let ignore = KernelSigaction {
            handler: libc::SIG_IGN as u64,
            ..KernelSigaction::default()
        };
        unsafe { crate::signal::raw_sigaction(libc::SIGUSR2, Some(&ignore), None) }.unwrap();
        assert_eq!(
            unsafe { self_directed_fatal_signal(libc::SYS_tgkill, tgkill) },
            None
        );
        unsafe { crate::signal::raw_sigaction(libc::SIGUSR2, Some(&previous), None) }.unwrap();
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&old_mask), None) }
            .unwrap();
    }

    #[test]
    fn the_core_pattern_is_classified_by_its_first_byte() {
        assert_eq!(CorePattern::from_first_byte(Some(b'|')), CorePattern::Pipe);
        assert_eq!(
            CorePattern::from_first_byte(Some(b'/')),
            CorePattern::AbsolutePath
        );
        assert_eq!(
            CorePattern::from_first_byte(Some(b'c')),
            CorePattern::RelativePath
        );
        for unknown in [Some(b'@'), Some(b'\n'), None] {
            assert_eq!(CorePattern::from_first_byte(unknown), CorePattern::Unknown);
        }
    }

    /// The checks `fs/coredump.c` makes before writing a core.
    #[test]
    fn a_core_is_predicted_only_where_the_kernel_would_write_one() {
        let page = 4096;
        let abrt = libc::SIGABRT;
        // Only "core" default actions dump.
        assert!(!core_dump_attempted(
            libc::SIGTERM,
            1,
            u64::MAX,
            CorePattern::Pipe,
            page
        ));
        assert!(!core_dump_attempted(
            libc::SIGKILL,
            1,
            u64::MAX,
            CorePattern::Pipe,
            page
        ));
        for signal in [libc::SIGQUIT, libc::SIGSEGV, libc::SIGFPE, libc::SIGILL] {
            assert!(core_dump_attempted(
                signal,
                1,
                u64::MAX,
                CorePattern::Pipe,
                page
            ));
        }
        // Not dumpable: no core.
        assert!(!core_dump_attempted(
            abrt,
            0,
            u64::MAX,
            CorePattern::Pipe,
            page
        ));
        // A pipe dumps whatever the limit, except exactly 1.
        assert!(core_dump_attempted(abrt, 1, 0, CorePattern::Pipe, page));
        assert!(!core_dump_attempted(abrt, 1, 1, CorePattern::Pipe, page));
        // A file needs at least one page.
        assert!(!core_dump_attempted(
            abrt,
            1,
            0,
            CorePattern::RelativePath,
            page
        ));
        assert!(!core_dump_attempted(
            abrt,
            1,
            page - 1,
            CorePattern::AbsolutePath,
            page
        ));
        assert!(core_dump_attempted(
            abrt,
            1,
            page,
            CorePattern::AbsolutePath,
            page
        ));
        assert!(core_dump_attempted(
            abrt,
            1,
            page,
            CorePattern::RelativePath,
            page
        ));
        // SUID_DUMP_ROOT dumps only to a pipe or an absolute path.
        assert!(core_dump_attempted(
            abrt,
            2,
            page,
            CorePattern::AbsolutePath,
            page
        ));
        assert!(core_dump_attempted(abrt, 2, 0, CorePattern::Pipe, page));
        assert!(!core_dump_attempted(
            abrt,
            2,
            page,
            CorePattern::RelativePath,
            page
        ));
        // An unknown pattern predicts no core.
        assert!(!core_dump_attempted(
            abrt,
            1,
            u64::MAX,
            CorePattern::Unknown,
            page
        ));
    }

    /// With RLIMIT_CORE set to 1, which disables cores for every pattern,
    /// the prediction reads that and predicts none; a signal whose default
    /// action does not dump never predicts one.
    #[test]
    fn the_core_prediction_reads_this_processs_core_limit() {
        assert!(!unsafe { core_dump_expected(libc::SIGTERM) });
        let prlimit = |new: Option<&libc::rlimit64>, old: Option<&mut libc::rlimit64>| unsafe {
            raw_syscall6(
                libc::SYS_prlimit64,
                [
                    0,
                    libc::RLIMIT_CORE as u64,
                    new.map_or(0, |limit| limit as *const libc::rlimit64 as u64),
                    old.map_or(0, |limit| limit as *mut libc::rlimit64 as u64),
                    0,
                    0,
                ],
            )
        };
        let mut previous = libc::rlimit64 {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(prlimit(None, Some(&mut previous)), 0);
        if previous.rlim_max == 0 {
            // A hard limit of 0 forbids a soft limit of 1 (and cannot be
            // raised unprivileged), so this process cannot take the opt-out
            // this test checks.
            return;
        }
        // A soft limit of 1 under the existing hard limit, which needs no
        // privilege.
        let one = libc::rlimit64 {
            rlim_cur: 1,
            rlim_max: previous.rlim_max,
        };
        assert_eq!(prlimit(Some(&one), None), 0);
        let predicted = unsafe { core_dump_expected(libc::SIGABRT) };
        assert_eq!(prlimit(Some(&previous), None), 0);
        assert!(!predicted);
    }

    #[test]
    fn the_pending_set_is_read_from_the_kernel() {
        assert!(unsafe { current_pending_set() }.is_some());
    }

    #[test]
    fn signal_action_supported_allows_only_default_and_ignore_handlers() {
        let action = |handler: u64| [handler, 0_u64, 0, 0];
        let ignore = action(libc::SIG_IGN as u64);
        let default = action(libc::SIG_DFL as u64);
        let handler = action(0x1000);
        let args = |signal: i32, act: &[u64; 4]| [signal as u64, act.as_ptr() as u64, 0, 8, 0, 0];

        // Other syscalls and queries without a new action are always allowed.
        assert!(signal_action_supported(libc::SYS_getpid, [0; 6]));
        assert!(signal_action_supported(
            libc::SYS_rt_sigaction,
            [libc::SIGUSR1 as u64, 0, 0, 8, 0, 0]
        ));
        // SIGSYS is the runtime's own, whatever the action.
        assert!(!signal_action_supported(
            libc::SYS_rt_sigaction,
            args(libc::SIGSYS, &default)
        ));
        // Only SIG_DFL and SIG_IGN are allowed for another signal.
        assert!(signal_action_supported(
            libc::SYS_rt_sigaction,
            args(libc::SIGUSR1, &ignore)
        ));
        assert!(signal_action_supported(
            libc::SYS_rt_sigaction,
            args(libc::SIGUSR1, &default)
        ));
        assert!(!signal_action_supported(
            libc::SYS_rt_sigaction,
            args(libc::SIGUSR1, &handler)
        ));
        // An unreadable action is refused, not dereferenced.
        assert!(!signal_action_supported(
            libc::SYS_rt_sigaction,
            [libc::SIGUSR1 as u64, 8, 0, 8, 0, 0]
        ));
        // Linux refuses any new action for SIGKILL and SIGSTOP, and for a
        // number that is not a signal, itself, so the call runs and the guest
        // sees the kernel's error.
        for signal in [libc::SIGKILL, libc::SIGSTOP, 0, 65, -1] {
            assert!(signal_action_supported(
                libc::SYS_rt_sigaction,
                args(signal, &handler)
            ));
            assert!(signal_action_supported(
                libc::SYS_rt_sigaction,
                [signal as u64, 8, 0, 8, 0, 0]
            ));
        }
    }

    /// The signal argument is read as a C int, as Linux reads it, whether or
    /// not SIGALRM handlers are admitted: an alias with high bits set is that
    /// signal. (Before, a SIGKILL alias with a handler got EPERM where Linux
    /// returns EINVAL, and a SIGSYS alias passed the guard.)
    #[test]
    fn the_guard_reads_the_signal_as_a_c_int() {
        let handler = [0x1000_u64, 0, 0, 0];
        let args = |signal: u64| [signal, handler.as_ptr() as u64, 0, 8, 0, 0];
        let high = 0x1_0000_0000_u64;
        assert!(signal_action_supported(
            libc::SYS_rt_sigaction,
            args(high | libc::SIGKILL as u64)
        ));
        assert!(!signal_action_supported(
            libc::SYS_rt_sigaction,
            args(high | libc::SIGSYS as u64)
        ));
        assert!(!signal_action_supported(
            libc::SYS_rt_sigaction,
            args(high | libc::SIGUSR1 as u64)
        ));
    }

    /// The kernel's answer the guest sees for the SIGKILL and SIGSTOP calls
    /// the guard admits: EINVAL for a readable action, EFAULT for an
    /// unreadable one, and the action is unchanged.
    #[test]
    fn linux_refuses_a_new_sigkill_or_sigstop_action_itself() {
        let handler = KernelSigaction {
            handler: 0x1000,
            ..KernelSigaction::default()
        };
        for signal in [libc::SIGKILL, libc::SIGSTOP] {
            let readable = unsafe {
                raw_syscall6(
                    libc::SYS_rt_sigaction,
                    [signal as u64, (&raw const handler) as u64, 0, 8, 0, 0],
                )
            };
            assert_eq!(readable, -i64::from(libc::EINVAL));
            let unreadable =
                unsafe { raw_syscall6(libc::SYS_rt_sigaction, [signal as u64, 8, 0, 8, 0, 0]) };
            assert_eq!(unreadable, -i64::from(libc::EFAULT));
            let mut current = KernelSigaction::default();
            let query = unsafe {
                raw_syscall6(
                    libc::SYS_rt_sigaction,
                    [signal as u64, 0, (&raw mut current) as u64, 8, 0, 0],
                )
            };
            assert_eq!(query, 0);
            assert_eq!(current.handler, libc::SIG_DFL as u64);
        }
    }
}
