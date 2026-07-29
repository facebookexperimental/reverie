/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The dispatcher seam: how a backend or tool handles a trapped syscall.
//!
//! Every ld-preload backend (e9patch, liteinst) and every hosted tool plugs in
//! by implementing [`SyscallDispatcher`]. The runtime owns the seccomp/SIGSYS
//! plumbing; the dispatcher owns the *policy* — emulate, forward, rewrite the
//! result, or route to a coordinator over RPC.

use crate::signal;
use crate::trap;

// TODO-HUMAN-REVIEW(PR-264): Review the public dispatch-origin contract used by
// direct binary-rewriter trampolines.
// AUTONOMOUS-BOT-IMPLEMENTED
/// How a syscall reached the shared preload dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SyscallEventSource {
    /// The seccomp filter delivered the syscall through the `SIGSYS` handler.
    SignalTrap,
    /// An instrumentation trampoline called the dispatcher in ordinary context.
    DirectInstrumentation,
}

/// A trapped syscall, as reconstructed from the SIGSYS `ucontext`.
///
/// The dispatcher inspects [`number`](Self::number)/[`args`](Self::args) and
/// sets [`result`](Self::set_result); the runtime writes `result` back into the
/// guest's `RAX` before resuming it.
#[derive(Clone, Copy, Debug)]
pub struct SyscallEvent {
    number: i64,
    args: [u64; 6],
    instruction_pointer: u64,
    source: SyscallEventSource,
    result: Option<i64>,
    resume_address: Option<u64>,
}

impl SyscallEvent {
    pub(crate) fn new(number: i64, args: [u64; 6], instruction_pointer: u64) -> Self {
        Self::with_source(
            number,
            args,
            instruction_pointer,
            SyscallEventSource::SignalTrap,
        )
    }

    pub(crate) fn direct(number: i64, args: [u64; 6], instruction_pointer: u64) -> Self {
        Self::with_source(
            number,
            args,
            instruction_pointer,
            SyscallEventSource::DirectInstrumentation,
        )
    }

    fn with_source(
        number: i64,
        args: [u64; 6],
        instruction_pointer: u64,
        source: SyscallEventSource,
    ) -> Self {
        Self {
            number,
            args,
            instruction_pointer,
            source,
            result: None,
            resume_address: None,
        }
    }

    /// The syscall number (`SYS_*`).
    pub fn number(&self) -> i64 {
        self.number
    }

    /// The six raw syscall arguments (rdi, rsi, rdx, r10, r8, r9).
    pub fn args(&self) -> [u64; 6] {
        self.args
    }

    /// The guest instruction pointer that issued the syscall.
    pub fn instruction_pointer(&self) -> u64 {
        self.instruction_pointer
    }

    // TODO-HUMAN-REVIEW(PR-264): Review dispatch-origin exposure to backend
    // dispatchers.
    // AUTONOMOUS-BOT-IMPLEMENTED
    /// Returns how this syscall entered the shared dispatcher.
    pub fn source(&self) -> SyscallEventSource {
        self.source
    }

    /// The result the dispatcher has chosen, if any.
    pub fn result(&self) -> Option<i64> {
        self.result
    }

    /// Set the syscall's return value (a negative value is `-errno`).
    pub fn set_result(&mut self, result: i64) {
        self.result = Some(result);
    }

    /// Set the result to `-errno`.
    pub fn fail(&mut self, errno: i32) {
        self.result = Some(-i64::from(errno));
    }

    // TODO-HUMAN-REVIEW(PR-127): Review deferred post-SIGSYS control transfer.
    /// Resume at `address` after the signal handler returns without changing RAX.
    ///
    /// Dynamic instrumentation backends use this to publish a replacement
    /// trampoline on the SIGSYS slow path and run the tool callback later in
    /// ordinary guest context.
    pub fn defer_to(&mut self, address: u64) {
        self.resume_address = Some(address);
    }

    /// Returns the deferred resume address selected by the dispatcher.
    pub fn resume_address(&self) -> Option<u64> {
        self.resume_address
    }

    /// Execute the real syscall through the trusted gate and record its result.
    ///
    /// This is the async-signal-safe way for a dispatcher to forward a syscall:
    /// the gate's instruction pointer is whitelisted in the seccomp filter, so
    /// it does not re-trap.
    pub fn forward(&mut self) -> i64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        let result = unsafe { trap::raw_syscall6(self.number, self.args) };
        self.result = Some(result);
        result
    }

    pub(crate) fn resolved_result(&self) -> i64 {
        self.result.unwrap_or(-i64::from(libc::ENOSYS))
    }
}

/// The plug-in seam implemented by every backend/tool.
///
/// # Async-signal safety
///
/// [`dispatch`](Self::dispatch) runs inside the SIGSYS handler. It must not
/// allocate, take locks that guest threads may hold, or make syscalls except
/// through [`SyscallEvent::forward`] / [`crate::trap::raw_syscall6`]. Any other
/// direct syscall would re-trap and recurse.
pub trait SyscallDispatcher: Send + Sync {
    /// Handle one trapped syscall, setting `event`'s result.
    fn dispatch(&self, event: &mut SyscallEvent);
}

/// Whether `number` creates a new process/thread that must inherit the filter.
///
/// `fork`/`vfork` and `clone`/`clone3` all produce a child that returns from
/// the same trapped syscall; the seccomp filter is inherited atomically by the
/// kernel, so the child needs no re-installation — only per-process runtime
/// state (for example a coordinator connection) must be re-established. See
/// [`crate::fork`].
pub fn is_fork_like(number: i64) -> bool {
    number == libc::SYS_fork
        || number == libc::SYS_vfork
        || number == libc::SYS_clone
        || number == libc::SYS_clone3
}

/// The default dispatcher: forward every syscall to the kernel, applying the
/// fail-closed guards that the ld-preload derisking work proved mandatory.
///
/// This is the shared correctness policy reused by every backend that does not
/// need custom emulation. A backend that *does* emulate wraps or replaces it.
#[derive(Debug, Default)]
pub struct PassthroughDispatcher {
    /// Optional child-side fork hook (see [`crate::fork`]).
    fork_hook: Option<crate::fork::ForkHook>,
}

impl PassthroughDispatcher {
    /// A passthrough dispatcher with no fork hook.
    pub const fn new() -> Self {
        Self { fork_hook: None }
    }

    /// Attach a hook invoked in the child after a successful fork-like syscall.
    pub fn with_fork_hook(mut self, hook: crate::fork::ForkHook) -> Self {
        self.fork_hook = Some(hook);
        self
    }

    /// Apply the shared fail-closed guards. Returns `true` if the guard set a
    /// result and the caller must stop.
    ///
    /// These mirror the boundaries established by `research-ldpreload-derisking`:
    /// an inherited TRAP filter cannot safely cross `execve`, cannot resume a
    /// non-null-stack `clone`, and must keep `SIGSYS` reserved.
    pub(crate) fn apply_guards(event: &mut SyscallEvent) -> bool {
        let number = event.number();
        let args = event.args();

        // AUTONOMOUS-BOT-IMPLEMENTED
        // exec cannot safely cross an inherited trap filter: the filter survives
        // but the handler, altstack, and mappings do not.
        if number == libc::SYS_execve || number == libc::SYS_execveat {
            event.fail(libc::ENOTSUP);
            return true;
        }

        // AUTONOMOUS-BOT-IMPLEMENTED
        // Keep SIGSYS reserved for the runtime until disposition is virtualized.
        if number == libc::SYS_rt_sigaction && signal::is_reserved(args[0] as i32) {
            event.fail(libc::EPERM);
            return true;
        }

        // The SIGSYS trap depends on the runtime-owned alternate stack and on
        // SIGSYS remaining unblocked. Queries are harmless, as is explicitly
        // unblocking signals; reject mutations that could displace either.
        if number == libc::SYS_sigaltstack && args[0] != 0 {
            event.fail(libc::EPERM);
            return true;
        }
        if number == libc::SYS_rt_sigprocmask && args[1] != 0 && args[0] as i32 != libc::SIG_UNBLOCK
        {
            event.fail(libc::EPERM);
            return true;
        }

        // AUTONOMOUS-BOT-IMPLEMENTED
        // A non-null clone child stack cannot resume this signal frame safely;
        // clone3/vfork need a controller-owned child bootstrap.
        if number == libc::SYS_clone && args[1] != 0 {
            event.fail(libc::ENOTSUP);
            return true;
        }
        if number == libc::SYS_clone3 || number == libc::SYS_vfork {
            event.fail(libc::ENOTSUP);
            return true;
        }

        false
    }
}

impl SyscallDispatcher for PassthroughDispatcher {
    fn dispatch(&self, event: &mut SyscallEvent) {
        if Self::apply_guards(event) {
            return;
        }

        let fork_like = is_fork_like(event.number());
        let result = event.forward();

        // In the child of a successful fork-like syscall, re-establish
        // per-process runtime state.
        if fork_like
            && result == 0
            && let Some(hook) = self.fork_hook
        {
            hook.run_in_child();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_like_classification() {
        assert!(is_fork_like(libc::SYS_fork));
        assert!(is_fork_like(libc::SYS_vfork));
        assert!(is_fork_like(libc::SYS_clone));
        assert!(is_fork_like(libc::SYS_clone3));
        assert!(!is_fork_like(libc::SYS_write));
        assert!(!is_fork_like(libc::SYS_getpid));
    }

    #[test]
    fn deferred_dispatch_preserves_result_and_records_resume_address() {
        let mut event = SyscallEvent::new(libc::SYS_getpid, [0; 6], 0x1000);
        event.defer_to(0x2000);

        assert_eq!(event.result(), None);
        assert_eq!(event.resume_address(), Some(0x2000));
    }

    #[test]
    fn direct_events_are_distinct_from_signal_traps() {
        let signal = SyscallEvent::new(libc::SYS_getpid, [0; 6], 0x1000);
        let direct = SyscallEvent::direct(libc::SYS_getpid, [0; 6], 0x1000);

        assert_eq!(signal.source(), SyscallEventSource::SignalTrap);
        assert_eq!(direct.source(), SyscallEventSource::DirectInstrumentation);
    }

    #[test]
    fn exec_is_guarded_enotsup() {
        let mut event = SyscallEvent::new(libc::SYS_execve, [0; 6], 0);
        assert!(PassthroughDispatcher::apply_guards(&mut event));
        assert_eq!(event.result(), Some(-i64::from(libc::ENOTSUP)));
    }

    #[test]
    fn sigsys_reservation_is_guarded_eperm() {
        let mut args = [0; 6];
        args[0] = libc::SIGSYS as u64;
        let mut event = SyscallEvent::new(libc::SYS_rt_sigaction, args, 0);
        assert!(PassthroughDispatcher::apply_guards(&mut event));
        assert_eq!(event.result(), Some(-i64::from(libc::EPERM)));
    }

    #[test]
    fn signal_mask_mutation_is_guarded_but_unblock_and_query_are_not() {
        let mut mutation_args = [0; 6];
        mutation_args[0] = libc::SIG_BLOCK as u64;
        mutation_args[1] = 0xdead_beef;
        let mut mutation = SyscallEvent::new(libc::SYS_rt_sigprocmask, mutation_args, 0);
        assert!(PassthroughDispatcher::apply_guards(&mut mutation));
        assert_eq!(mutation.result(), Some(-i64::from(libc::EPERM)));

        let mut unblock_args = mutation_args;
        unblock_args[0] = libc::SIG_UNBLOCK as u64;
        let mut unblock = SyscallEvent::new(libc::SYS_rt_sigprocmask, unblock_args, 0);
        assert!(!PassthroughDispatcher::apply_guards(&mut unblock));

        let mut query_args = mutation_args;
        query_args[1] = 0;
        let mut query = SyscallEvent::new(libc::SYS_rt_sigprocmask, query_args, 0);
        assert!(!PassthroughDispatcher::apply_guards(&mut query));
    }

    #[test]
    fn alternate_stack_mutation_is_guarded_but_query_is_not() {
        let mut mutation_args = [0; 6];
        mutation_args[0] = 0xdead_beef;
        let mut mutation = SyscallEvent::new(libc::SYS_sigaltstack, mutation_args, 0);
        assert!(PassthroughDispatcher::apply_guards(&mut mutation));
        assert_eq!(mutation.result(), Some(-i64::from(libc::EPERM)));

        let mut query = SyscallEvent::new(libc::SYS_sigaltstack, [0; 6], 0);
        assert!(!PassthroughDispatcher::apply_guards(&mut query));
    }

    #[test]
    fn ordinary_syscall_is_not_guarded() {
        let mut event = SyscallEvent::new(libc::SYS_getpid, [0; 6], 0);
        assert!(!PassthroughDispatcher::apply_guards(&mut event));
        assert_eq!(event.result(), None);
    }

    #[test]
    fn clone_with_stack_is_guarded_but_plain_clone_is_not() {
        let mut with_stack = [0; 6];
        with_stack[1] = 0xdead_beef;
        let mut event = SyscallEvent::new(libc::SYS_clone, with_stack, 0);
        assert!(PassthroughDispatcher::apply_guards(&mut event));

        let mut plain = SyscallEvent::new(libc::SYS_clone, [0; 6], 0);
        assert!(!PassthroughDispatcher::apply_guards(&mut plain));
    }
}
