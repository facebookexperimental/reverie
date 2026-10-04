/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Pure decisions for restarting a LiteInst host-hybrid syscall trap.
//!
//! A host-hybrid syscall is served while the controller thread is stopped at
//! the runtime's `int3`, with `orig_rax == -1`. Linux therefore never applies
//! its own syscall-restart rule to that stop, and writing a private
//! `-ERESTART*` code into the guest frame would leak it to the guest. Instead
//! the tracer rewinds the controller to the `int3`: signal work happens on the
//! resume, and the re-executed `int3` re-traps and re-dispatches the syscall.
//! When a signal is delivered to a guest handler, whether Linux restarts or
//! returns `-EINTR` depends on the code and on the handler's `SA_RESTART`; the
//! tracer lets the kernel decide by presenting a restartable syscall at a
//! private-page landing (`landing_regs`). The helpers here are pure.
//!
//! Only the x86_64 host-hybrid path uses them; `landing_regs` and
//! `changed_landing_register` name x86_64 registers and exist only there.

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use nix::sys::signal::Signal;
use reverie::Errno;

/// How a restartable syscall result rewrites the frame before the re-trap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestartAction {
    /// Re-dispatch the same syscall number with the same arguments.
    Same,
    /// Re-dispatch as `restart_syscall`, keeping the argument registers, as
    /// Linux does for `-ERESTART_RESTARTBLOCK`.
    RestartSyscall,
}

/// Classifies a final syscall result as a Linux-private restart request.
///
/// Only the four codes Linux itself restarts return an action. Every other
/// result, including an ordinary errno such as `EINTR`, is delivered as is.
pub(crate) fn liteinst_restart_action(result: Result<i64, Errno>) -> Option<RestartAction> {
    match result {
        Err(Errno::ERESTARTSYS) | Err(Errno::ERESTARTNOINTR) | Err(Errno::ERESTARTNOHAND) => {
            Some(RestartAction::Same)
        }
        Err(Errno::ERESTART_RESTARTBLOCK) => Some(RestartAction::RestartSyscall),
        _ => None,
    }
}

/// What a single step of the private-page `syscall` instruction observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivateStep {
    /// The stop is still at the `syscall` instruction: a signal was already
    /// pending when the step began, so the syscall never executed.
    NotRun,
    /// The single-step report after the `syscall` instruction. Its `rax` is
    /// the raw kernel result, which may itself be a restart code whose
    /// interrupting signal is still kernel-pending.
    Ran,
    /// A non-SIGTRAP stop after the instruction: the syscall ran, and the
    /// step returned a signal it could not requeue (after a syscall that
    /// swaps in a temporary signal mask). `rax` is the kernel's result; the
    /// signal is held for delivery and the step's own SIGTRAP stays queued,
    /// to be discarded as stale by its siginfo.
    Held,
    /// A stop anywhere else, which no private-page step can produce.
    Unexpected,
}

/// Classifies the signal-delivery stop that ended a private-page step.
pub(crate) fn classify_private_step(
    ip: u64,
    signal: Signal,
    private_syscall: u64,
    syscall_len: u64,
) -> PrivateStep {
    if ip == private_syscall {
        PrivateStep::NotRun
    } else if Some(ip) == private_syscall.checked_add(syscall_len) {
        if signal == Signal::SIGTRAP {
            PrivateStep::Ran
        } else {
            PrivateStep::Held
        }
    } else {
        PrivateStep::Unexpected
    }
}

/// The single-byte x86 `int3` opcode.
pub(crate) const INT3: u8 = 0xcc;

/// Checks that the controller is stopped immediately after the runtime `int3`
/// with the syscall marker still in `rax`, so rewinding one byte re-executes
/// exactly that `int3` and nothing else.
pub(crate) fn check_rewind_preconditions(
    ip: u64,
    rax: u64,
    restart_rip: u64,
    syscall_marker: u64,
    restart_byte: u8,
) -> Result<(), String> {
    if Some(ip) != restart_rip.checked_add(1) {
        return Err(format!(
            "controller RIP {ip:#x} is not immediately after the runtime int3 at {restart_rip:#x}"
        ));
    }
    if rax != syscall_marker {
        return Err(format!(
            "controller RAX {rax:#x} no longer holds the syscall marker {syscall_marker:#x}"
        ));
    }
    if restart_byte != INT3 {
        return Err(format!(
            "byte {restart_byte:#04x} at {restart_rip:#x} is not the runtime int3"
        ));
    }
    Ok(())
}

/// Whether the kernel's handler rule can turn this restart code into `EINTR`.
///
/// Linux restarts every restart code when the delivered signal has no handler.
/// With a handler, `-ERESTARTSYS` restarts only under `SA_RESTART`, and
/// `-ERESTARTNOHAND` and `-ERESTART_RESTARTBLOCK` always become `-EINTR`;
/// `-ERESTARTNOINTR` restarts regardless. So only the first three need the
/// kernel's decision when a signal is delivered (see [`landing_regs`]).
pub(crate) fn restart_depends_on_handler(errno: Errno) -> bool {
    matches!(
        errno,
        Errno::ERESTARTSYS | Errno::ERESTARTNOHAND | Errno::ERESTART_RESTARTBLOCK
    )
}

/// The `/proc` mask bit for one signal number.
pub(crate) const fn signal_bit(signal: i32) -> u64 {
    1u64 << (signal - 1)
}

/// Signals whose kernel disposition the host-hybrid runtime owns.
///
/// `initialize_host_runtime` calls `liteinst2::patcher::prepare_live_patching`,
/// which installs the SIGTRAP guard router over a `SIG_DFL` or `SIG_IGN`
/// disposition, and a guest can later replace the router with its own
/// handler. The tracer cannot tell those apart at a signal-delivery stop, so
/// the landing cannot present a SIGTRAP delivery to the kernel's restart rule:
/// the router's `SA_RESTART` would decide in place of the disposition a plain
/// ptrace run has. A handler-dependent restart that a SIGTRAP delivery would
/// decide therefore fails closed (`arm_liteinst_restart_landing`).
pub(crate) const RUNTIME_OWNED_HANDLERS: u64 = signal_bit(libc::SIGTRAP);

/// Offset, within the private page, of the restart landing: three `int3`
/// bytes in the page's all-`int3` padding (`cp::mmap::populate_mmap_page`
/// writes only the first eight bytes).
pub(crate) const LANDING_OFFSET: usize = 0x100;

/// The number of `int3` bytes the landing needs.
pub(crate) const LANDING_LEN: usize = 3;

/// Registers that make the kernel's own signal-delivery restart rule decide a
/// host-hybrid restart.
///
/// The controller is stopped in `get_signal` (at a signal-delivery stop, or
/// at the runtime `int3` stop) with `orig_rax == -1`, so after the signal is
/// delivered the kernel would apply no restart rule at all. These registers
/// present a syscall that returned `errno` at `landing + 2`: `orig_rax` is
/// not `-1` and `rax` holds the restart code. x86 `handle_signal` then
/// either restarts (`rip -= 2`, `rax = orig_rax`) or writes `-EINTR` and
/// leaves `rip`, using the exact disposition and `SA_RESTART` of the signal
/// it delivers, and with no handler the no-signal path restarts. The handler
/// runs and returns there, and the `int3` at `landing` (restart) or at
/// `landing + 2` (interrupted) reports the outcome; see
/// [`classify_landing_trap`].
///
/// `syscall_number` is the injected frame's syscall number. It is not `-1`,
/// so it marks "in a syscall", and on a restart the kernel copies it to `rax`,
/// where a handler sees it as it would under plain ptrace and the landing
/// reads back the number to re-dispatch.
#[cfg(target_arch = "x86_64")]
pub(crate) fn landing_regs(
    controller: &libc::user_regs_struct,
    landing: u64,
    errno: Errno,
    syscall_number: u64,
) -> libc::user_regs_struct {
    let mut regs = *controller;
    regs.rip = landing + 2;
    regs.orig_rax = syscall_number;
    regs.rax = (-(errno.into_raw() as i64)) as u64;
    regs
}

/// Names the first controller register a signal handler changed between the
/// armed landing and the landing trap, if any.
///
/// The kernel's restart rule writes only `rax` and `rip`, the landing `int3`
/// advances `rip`, and `orig_rax` and `eflags` are not restored as the
/// handler left them. Every other general-purpose register returns exactly as
/// armed unless the handler edited its `ucontext`. Those registers belong to
/// the runtime's trap context rather than to the guest's syscall, so an edit
/// has no plain-ptrace meaning the tracer could apply.
#[cfg(target_arch = "x86_64")]
pub(crate) fn changed_landing_register(
    armed: &libc::user_regs_struct,
    trapped: &libc::user_regs_struct,
) -> Option<&'static str> {
    [
        ("r15", armed.r15, trapped.r15),
        ("r14", armed.r14, trapped.r14),
        ("r13", armed.r13, trapped.r13),
        ("r12", armed.r12, trapped.r12),
        ("rbp", armed.rbp, trapped.rbp),
        ("rbx", armed.rbx, trapped.rbx),
        ("r11", armed.r11, trapped.r11),
        ("r10", armed.r10, trapped.r10),
        ("r9", armed.r9, trapped.r9),
        ("r8", armed.r8, trapped.r8),
        ("rcx", armed.rcx, trapped.rcx),
        ("rdx", armed.rdx, trapped.rdx),
        ("rsi", armed.rsi, trapped.rsi),
        ("rdi", armed.rdi, trapped.rdi),
        ("rsp", armed.rsp, trapped.rsp),
    ]
    .into_iter()
    .find(|(_, armed, trapped)| armed != trapped)
    .map(|(name, _, _)| name)
}

/// The kernel's restart decision, as reported by the landing `int3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LandingOutcome {
    /// The kernel restarted (`rip -= 2`): re-dispatch the syscall.
    Restart,
    /// The kernel wrote `-EINTR`: complete the syscall with it.
    Interrupted,
}

/// Classifies a SIGTRAP stop against an armed landing. The `int3` at
/// `landing` reports at `landing + 1`, the one at `landing + 2` at
/// `landing + 3`.
pub(crate) fn classify_landing_trap(ip: u64, landing: u64) -> Option<LandingOutcome> {
    if Some(ip) == landing.checked_add(1) {
        Some(LandingOutcome::Restart)
    } else if Some(ip) == landing.checked_add(3) {
        Some(LandingOutcome::Interrupted)
    } else {
        None
    }
}

/// Checks that the landing bytes are all `int3`.
pub(crate) fn check_landing_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() == LANDING_LEN && bytes.iter().all(|byte| *byte == INT3) {
        Ok(())
    } else {
        Err(format!(
            "private-page restart landing holds {bytes:02x?}, not {LANDING_LEN} int3 bytes"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: u64 = 0x7000_0000;

    #[test]
    fn restart_action_covers_every_linux_restart_code() {
        assert_eq!(
            liteinst_restart_action(Err(Errno::ERESTARTSYS)),
            Some(RestartAction::Same)
        );
        assert_eq!(
            liteinst_restart_action(Err(Errno::ERESTARTNOINTR)),
            Some(RestartAction::Same)
        );
        assert_eq!(
            liteinst_restart_action(Err(Errno::ERESTARTNOHAND)),
            Some(RestartAction::Same)
        );
        assert_eq!(
            liteinst_restart_action(Err(Errno::ERESTART_RESTARTBLOCK)),
            Some(RestartAction::RestartSyscall)
        );
    }

    #[test]
    fn restart_action_rejects_ordinary_results() {
        for errno in [Errno::EINTR, Errno::EAGAIN, Errno::EBADF, Errno::ENOSYS] {
            assert_eq!(liteinst_restart_action(Err(errno)), None, "{errno:?}");
        }
        for value in [0, 1, 4243, -1, -512, i64::MAX] {
            assert_eq!(liteinst_restart_action(Ok(value)), None, "{value}");
        }
    }

    #[test]
    fn private_step_distinguishes_not_run_ran_held_and_unexpected() {
        assert_eq!(
            classify_private_step(PRIVATE, Signal::SIGURG, PRIVATE, 2),
            PrivateStep::NotRun
        );
        // An external SIGTRAP pending before the step still stops before the
        // instruction; it is not a single-step report.
        assert_eq!(
            classify_private_step(PRIVATE, Signal::SIGTRAP, PRIVATE, 2),
            PrivateStep::NotRun
        );
        assert_eq!(
            classify_private_step(PRIVATE + 2, Signal::SIGTRAP, PRIVATE, 2),
            PrivateStep::Ran
        );
        assert_eq!(
            classify_private_step(PRIVATE + 2, Signal::SIGSYS, PRIVATE, 2),
            PrivateStep::Held
        );
        assert_eq!(
            classify_private_step(PRIVATE + 7, Signal::SIGTRAP, PRIVATE, 2),
            PrivateStep::Unexpected
        );
        assert_eq!(
            classify_private_step(u64::MAX, Signal::SIGTRAP, u64::MAX - 1, 2),
            PrivateStep::Unexpected
        );
    }

    #[test]
    fn rewind_preconditions_require_the_exact_int3_stop() {
        let marker = 0x7265_766c_6900_0004;
        assert_eq!(
            check_rewind_preconditions(0x1001, marker, 0x1000, marker, INT3),
            Ok(())
        );
        assert!(check_rewind_preconditions(0x1000, marker, 0x1000, marker, INT3).is_err());
        assert!(check_rewind_preconditions(0x1002, marker, 0x1000, marker, INT3).is_err());
        assert!(check_rewind_preconditions(0x1001, 0, 0x1000, marker, INT3).is_err());
        assert!(check_rewind_preconditions(0x1001, marker, 0x1000, marker, 0x90).is_err());
        assert!(check_rewind_preconditions(0, marker, u64::MAX, marker, INT3).is_err());
    }

    #[test]
    fn only_handler_dependent_codes_need_the_kernel_decision() {
        assert!(restart_depends_on_handler(Errno::ERESTARTSYS));
        assert!(restart_depends_on_handler(Errno::ERESTARTNOHAND));
        assert!(restart_depends_on_handler(Errno::ERESTART_RESTARTBLOCK));
        assert!(!restart_depends_on_handler(Errno::ERESTARTNOINTR));
        assert!(!restart_depends_on_handler(Errno::EINTR));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn landing_regs_present_a_restartable_syscall_at_the_landing() {
        let mut controller: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        controller.rip = 0x1000;
        controller.rax = 0x7265_766c_6900_0004;
        controller.orig_rax = u64::MAX;
        controller.rdi = 0x1234;
        controller.rsp = 0x7fff_0000;
        let regs = landing_regs(&controller, PRIVATE + 0x100, Errno::ERESTARTSYS, 0);
        assert_eq!(regs.rip, PRIVATE + 0x102);
        assert_eq!(regs.rax as i64, -512);
        // The kernel's syscall_get_nr() is an int; anything but -1 enables the
        // restart rule, and read is syscall 0.
        assert_eq!(regs.orig_rax, 0);
        assert_eq!(regs.rdi, controller.rdi);
        assert_eq!(regs.rsp, controller.rsp);
        let block = landing_regs(
            &controller,
            PRIVATE + 0x100,
            Errno::ERESTART_RESTARTBLOCK,
            libc::SYS_restart_syscall as u64,
        );
        assert_eq!(block.rax as i64, -516);
        assert_eq!(block.orig_rax, libc::SYS_restart_syscall as u64);
        assert_eq!(changed_landing_register(&controller, &regs), None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn changed_landing_register_ignores_only_what_the_kernel_writes() {
        let mut armed: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        armed.rsp = 0x7fff_0000;
        armed.r12 = 0x1234;
        let mut trapped = armed;
        trapped.rax = 777;
        trapped.rip = PRIVATE + 0x103;
        trapped.orig_rax = u64::MAX;
        trapped.eflags = 0x246;
        assert_eq!(changed_landing_register(&armed, &trapped), None);
        let mut edited = trapped;
        edited.r12 = 0;
        assert_eq!(changed_landing_register(&armed, &edited), Some("r12"));
        let mut moved = trapped;
        moved.rsp -= 8;
        assert_eq!(changed_landing_register(&armed, &moved), Some("rsp"));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn landing_trap_reports_restart_and_interrupted_outcomes() {
        let landing = PRIVATE + 0x100;
        let presented = landing_regs_rip(landing);
        // Restart: the kernel moves rip back two bytes, onto the first int3,
        // which reports one byte later.
        assert_eq!(
            classify_landing_trap(presented - 2 + 1, landing),
            Some(LandingOutcome::Restart)
        );
        // EINTR: rip is left on the third int3.
        assert_eq!(
            classify_landing_trap(presented + 1, landing),
            Some(LandingOutcome::Interrupted)
        );
        for ip in [landing, landing + 2, landing + 4, 0] {
            assert_eq!(classify_landing_trap(ip, landing), None, "{ip:#x}");
        }
        assert_eq!(classify_landing_trap(0, u64::MAX), None);
    }

    #[cfg(target_arch = "x86_64")]
    fn landing_regs_rip(landing: u64) -> u64 {
        let controller: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        landing_regs(&controller, landing, Errno::ERESTARTSYS, 0).rip
    }

    #[test]
    fn landing_bytes_must_be_three_int3() {
        assert_eq!(check_landing_bytes(&[INT3; LANDING_LEN]), Ok(()));
        assert!(check_landing_bytes(&[INT3, 0x90, INT3]).is_err());
        assert!(check_landing_bytes(&[INT3, INT3]).is_err());
    }
}
