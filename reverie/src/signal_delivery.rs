/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! One caught signal that a tool approves for delivery to a stopped guest
//! thread ([`crate::Guest::deliver_signal`]), with what Linux will do with
//! it, and the backend's answer.
//!
//! The tool decides; the backend carries the decision out, or checks it
//! against the kernel where the kernel carries it out (ptrace), or refuses by
//! name. Masks are kernel signal sets: bit `n - 1` stands for signal `n`.

use crate::Errno;
use crate::UnsupportedRefusal;

/// The bit of signal `signal` in a kernel signal set, or 0 for a number
/// outside 1 to 64.
pub const fn signal_set_bit(signal: i32) -> u64 {
    if signal >= 1 && signal <= 64 {
        1 << (signal - 1)
    } else {
        0
    }
}

/// SIGKILL and SIGSTOP. Linux never blocks them and strips them from every
/// mask it is given, so no comparison of masks counts them.
const UNBLOCKABLE: u64 = signal_set_bit(libc::SIGKILL) | signal_set_bit(libc::SIGSTOP);

/// A signal's action, as x86-64's `struct kernel_sigaction` lays it out.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalAction {
    /// The handler's address (`sa_handler`).
    pub handler: u64,
    /// `sa_flags`, for example `SA_RESTART`, `SA_ONSTACK`, `SA_NODEFER` and
    /// `SA_RESETHAND`.
    pub flags: u64,
    /// `sa_restorer`.
    pub restorer: u64,
    /// `sa_mask`: what the handler blocks besides the thread's mask.
    pub mask: u64,
}

impl SignalAction {
    /// The mask Linux runs `signal`'s handler under when this is its action
    /// and the thread's mask at delivery is `current` (`handle_signal` in
    /// `arch/x86/kernel/signal.c`): `current | sa_mask`, plus the signal
    /// itself unless `SA_NODEFER` is set.
    pub const fn handler_mask(&self, current: u64, signal: i32) -> u64 {
        let own = if self.flags & libc::SA_NODEFER as u64 != 0 {
            0
        } else {
            signal_set_bit(signal)
        };
        current | self.mask | own
    }
}

/// What the thread was doing when the signal stopped it, as the tool knows
/// it from its own record (A5 design, section 15.12). It is checked against
/// the syscall registers the kernel will act on: `orig_ax`, which names the
/// syscall the thread is in or is -1, and `rax`, its return value.
///
/// The tool keeps one record per thread, describing the guest, and updates
/// it at each guest event it sees: [`Interruption::Return`] or
/// [`Interruption::KernelRun`] when a guest syscall ends,
/// [`Interruption::NotInSyscall`] at a preemption, a trapped instruction or
/// another stop the guest makes, and [`Interruption::AfterFrame`] whenever a
/// caught delivery goes ahead, approved or not, since the kernel then builds
/// that handler's frame as the guest resumes. When the backend answers that
/// the kernel will not deliver the signal at this resume
/// ([`crate::SignalDeliveryUnavailable::BlockedAtResume`] or
/// [`crate::SignalDeliveryUnavailable::NotADeliveryStop`]), no frame follows
/// and the record stays as it was. The tool's own
/// injections inside a callback are not guest events and leave the record as
/// it is. Between events the guest runs unseen, so a record can be stale: the
/// guest may have returned to user code since. A tool can tell from the
/// registers alone (`orig_ax` -1 after a syscall record; a frame record at a
/// stop that does not show the registers Linux leaves for that frame, see
/// [`Interruption::AfterFrame`]) and should then send what the
/// registers show instead, which the check then verifies only as far as the
/// registers themselves.
///
/// The check reads the registers the kernel acts on at resume, so they must
/// still be the guest's. On ptrace, a syscall the tool injects inside the
/// signal callback before it approves leaves `orig_ax` as the guest's at
/// both valid points, and `rax` as the guest's at a held signal's report;
/// but at the signal's own delivery stop it leaves the injection's result in
/// `rax`, as Reverie always has. A tool that injects there must put the
/// guest's registers back ([`crate::Guest::set_regs`]) before it approves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interruption {
    /// The thread is not in a syscall: `orig_ax` is -1.
    NotInSyscall,
    /// The tool finished syscall `syscall` with raw result `result` (an
    /// errno as its negative, `-ERESTART*` included). Valid only at the first
    /// stop after that syscall's exit: `orig_ax` is `syscall` and `rax` is
    /// `result`.
    Return {
        /// The syscall number.
        syscall: i64,
        /// The raw return value.
        result: i64,
    },
    /// The kernel ran syscall `syscall`, and the tool has no result of its own
    /// for it. `orig_ax` is `syscall`; `rax` is not checked.
    KernelRun {
        /// The syscall number.
        syscall: i64,
    },
    /// A caught delivery already went ahead at this stop, and the kernel
    /// takes a further signal before any guest instruction runs. The
    /// registers then describe the first frame, so they are not checked.
    ///
    /// The backend offers no token that names the stop itself. A tool can
    /// narrow it to the first frame by what Linux leaves when it has just
    /// built one, but cannot prove it. On x86-64 (Linux v6.12
    /// `x64_setup_rt_frame` and `get_sigframe`, `arch/x86/kernel/signal_64.c`
    /// and `signal.c`): `rip` is the handler, `rdi` the signal, `rdx` the
    /// frame's ucontext at `rsp + 8`, `rsi` its siginfo right after that
    /// ucontext (304 bytes), and `rsp` is 8 below a 16-byte boundary. Neither
    /// writes `orig_ax`, which every later entry other than by a syscall sets
    /// to -1, so it is still the first frame's stop's. A fault an
    /// instruction raised needs the thread back in user code and is never
    /// chained. A tool that tells it by a synchronous signal with a positive
    /// `si_code` also sends the registers' answer for two chained ones: a
    /// SIGSEGV for a frame Linux failed to build after an earlier one
    /// (`SI_KERNEL`), and a signal the guest queued to itself with a positive
    /// code. `rax`, which Linux sets to 0, holds an injection's result
    /// after a syscall the tool injects at the stop.
    ///
    /// What still matches without being chained: an asynchronous signal at
    /// the handler's first instruction after the handler's own code came back
    /// to it with those registers unchanged, when the first frame's stop had
    /// `orig_ax` -1. An address-only test would also match a handler that
    /// changed those registers, and a fault there.
    AfterFrame,
}

/// One caught signal a tool approves for delivery to a stopped thread, with
/// what Linux will do with it: the action, the mask the frame saves and
/// `rt_sigreturn` restores, the mask in effect now, and the mask the handler
/// runs under. Built by the tool from its own copy of the thread's signal
/// state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalDelivery {
    /// The signal, 1 to 64 (realtime signals included).
    pub signal: i32,
    /// The signal's action, which the tool must only approve for a caught
    /// handler: ignored and default signals are not delivered through this.
    /// A backend whose kernel delivers (ptrace) uses the kernel's own action
    /// and cannot read it without an injection, so it checks the action only
    /// through `handler_mask`'s arithmetic; the tool's copy of the action is
    /// checked against the kernel where the tool records it.
    pub action: SignalAction,
    /// The frame's `uc_sigmask`: the mask the handler's `rt_sigreturn`
    /// restores (Linux's `sigmask_to_save()`). Inside a mask-swapping syscall
    /// (`rt_sigsuspend`, `ppoll`, `pselect6`, `epoll_pwait`) whose restore is
    /// pending, that is the mask saved before the call.
    pub frame_mask: u64,
    /// The thread's mask now: the temporary mask inside such a syscall, and
    /// `frame_mask` otherwise.
    pub current_mask: u64,
    /// The mask the handler runs under:
    /// `action.handler_mask(current_mask, signal)`.
    pub handler_mask: u64,
    /// Signals whose bits the tool does not claim to know, left out of every
    /// mask comparison, for example a signal the backend reserves for itself.
    /// SIGKILL and SIGSTOP are always left out.
    pub unchecked_mask: u64,
    /// Signals whose bits the tool does not claim to know in the frame's mask
    /// only, left out of the [`SignalDeliveryField::FrameMask`] comparison
    /// besides `unchecked_mask`; the other comparisons still check them.
    pub unchecked_frame_mask: u64,
    /// Signals whose bits the tool does not claim to know in the current mask
    /// only, left out of the [`SignalDeliveryField::CurrentMask`] comparison
    /// besides `unchecked_mask`; the other comparisons still check them. The
    /// [`SignalDeliveryField::HandlerMask`] comparison is arithmetic over the
    /// delivery's own current mask and action, which a tool knows whatever
    /// the kernel holds, so it keeps them.
    pub unchecked_current_mask: u64,
    /// What the thread was doing when the signal stopped it.
    pub interruption: Interruption,
}

/// The kernel's side of a delivery, as a backend that lets the kernel deliver
/// reads it at the stop with no injection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelDeliveryState {
    /// The mask the kernel's frame will save (on ptrace, `PTRACE_GETSIGMASK`,
    /// which reports the saved mask while a restore is pending).
    pub frame_mask: u64,
    /// The mask the kernel dequeues under now (procfs `SigBlk`).
    pub current_mask: u64,
    /// `orig_ax`: the syscall the thread is in, or -1.
    pub orig_syscall: i64,
    /// `rax`: the syscall's return value, if the thread is in one.
    pub ret: i64,
}

/// Which part of a [`SignalDelivery`] the kernel contradicted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDeliveryField {
    /// [`SignalDelivery::frame_mask`] against the mask the frame will save.
    FrameMask,
    /// [`SignalDelivery::current_mask`] against the mask in effect.
    CurrentMask,
    /// [`SignalDelivery::handler_mask`] against Linux's rule applied to the
    /// delivery's own action and current mask.
    HandlerMask,
    /// The interrupted syscall's number against `orig_ax`.
    InterruptedSyscall,
    /// The interrupted syscall's result against `rax`.
    InterruptedResult,
}

/// A check of a [`SignalDelivery`] that failed: the field, the delivery's
/// value and the kernel's (masks as compared, with the unchecked bits
/// cleared).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalDeliveryMismatch {
    /// The field that differs.
    pub field: SignalDeliveryField,
    /// The delivery's value.
    pub expected: u64,
    /// The kernel's value.
    pub actual: u64,
}

impl SignalDelivery {
    /// Checks the delivery against the kernel's state at its stop, in a fixed
    /// order: frame mask, current mask, handler mask, then the interrupted
    /// syscall. Returns the first field that differs. Pure: it reads nothing
    /// and changes nothing.
    pub fn check(&self, kernel: &KernelDeliveryState) -> Result<(), SignalDeliveryMismatch> {
        let compare = |field, expected: u64, actual: u64| {
            let only = match field {
                SignalDeliveryField::FrameMask => self.unchecked_frame_mask,
                SignalDeliveryField::CurrentMask => self.unchecked_current_mask,
                _ => 0,
            };
            let checked = !(self.unchecked_mask | only | UNBLOCKABLE);
            if expected & checked == actual & checked {
                Ok(())
            } else {
                Err(SignalDeliveryMismatch {
                    field,
                    expected: expected & checked,
                    actual: actual & checked,
                })
            }
        };
        compare(
            SignalDeliveryField::FrameMask,
            self.frame_mask,
            kernel.frame_mask,
        )?;
        compare(
            SignalDeliveryField::CurrentMask,
            self.current_mask,
            kernel.current_mask,
        )?;
        compare(
            SignalDeliveryField::HandlerMask,
            self.handler_mask,
            self.action.handler_mask(self.current_mask, self.signal),
        )?;
        let register = |field, expected: i64, actual: i64| {
            if expected == actual {
                Ok(())
            } else {
                Err(SignalDeliveryMismatch {
                    field,
                    expected: expected as u64,
                    actual: actual as u64,
                })
            }
        };
        match self.interruption {
            Interruption::NotInSyscall => register(
                SignalDeliveryField::InterruptedSyscall,
                -1,
                kernel.orig_syscall,
            ),
            Interruption::Return { syscall, result } => {
                register(
                    SignalDeliveryField::InterruptedSyscall,
                    syscall,
                    kernel.orig_syscall,
                )?;
                register(SignalDeliveryField::InterruptedResult, result, kernel.ret)
            }
            Interruption::KernelRun { syscall } => register(
                SignalDeliveryField::InterruptedSyscall,
                syscall,
                kernel.orig_syscall,
            ),
            Interruption::AfterFrame => Ok(()),
        }
    }
}

/// Why a backend could not check a delivery at this point, where it can
/// check deliveries elsewhere. Nothing was approved or changed; the tool's
/// existing path applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDeliveryUnavailable {
    /// Not inside [`crate::Tool::handle_signal_event`] (or its raw-signal
    /// form) for a signal the backend reported.
    NotInSignalCallback,
    /// The delivery names another signal than the one being reported.
    NotTheReportedSignal {
        /// The signal being reported.
        reported: i32,
    },
    /// The backend has no record of how the reported signal was taken from
    /// the kernel (its siginfo could not be read), so it cannot tie the
    /// approval to that instance.
    NoSignalRecord,
    /// The thread is at a stop that is not a signal-delivery stop, after an
    /// injection: resuming with a signal from it would not deliver this
    /// instance.
    NotADeliveryStop,
    /// The event's registers live in a binary rewriter's frame (e9patch's
    /// injected trap), not in the stopped thread.
    FrameModeStop,
    /// The backend's own requests could be refused at this stop (on ptrace, a
    /// seccomp filter may restrict the tracer thread).
    TracerFiltered,
    /// A delivery was already approved in this callback.
    AlreadyApproved,
    /// A check already failed in this callback ([`SignalDeliveryOutcome::Mismatch`]).
    /// The callback cannot try again with other values: a mismatch reports
    /// the kernel's values, and resubmitting them would check nothing.
    AfterMismatch,
    /// The delivery leaves its own signal's bit out of a comparison
    /// (`unchecked_mask`, `unchecked_frame_mask` or
    /// `unchecked_current_mask`), so no check could tell whether it is
    /// blocked.
    UncheckedSignal,
    /// The kernel's current mask blocks the signal, so resuming with it puts
    /// it back in the queue instead of delivering it (Linux's
    /// `ptrace_signal`). That happens, for example, after an injection inside
    /// a mask-swapping syscall lets the kernel restore the saved mask.
    BlockedAtResume,
    /// The thread is gone.
    Gone,
    /// The kernel's state could not be read.
    Unreadable(Errno),
    /// The backend checks deliveries only on another architecture.
    UnsupportedArchitecture,
}

/// How a backend reports a signal to [`crate::Tool::handle_signal_event`]
/// ([`crate::Guest::signal_report_path`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SignalReportPath {
    /// At the signal's own stop.
    Direct,
    /// Held: the signal stopped a Tool's injection, and the backend reports
    /// it after the callback that held it returns.
    Held,
}

/// A backend's answer to [`crate::Guest::deliver_signal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDeliveryOutcome {
    /// The kernel will deliver exactly this signal instance when the guest
    /// resumes, with masks equal to the delivery's on every checked bit
    /// (all but `unchecked_mask`, SIGKILL and SIGSTOP, and in the frame's or
    /// the current mask the bits unchecked for that mask): every check against
    /// the kernel passed (ptrace). The handler's mask is checked only as
    /// arithmetic over the tool's action, which the kernel's own action
    /// equals only as far as the tool's copy is kept right where the tool
    /// records it. The kernel still builds the frame with its own action; if
    /// it cannot write the frame, it raises SIGSEGV, which the thread's next
    /// stop reports. The tool's callback returns the signal to be
    /// delivered.
    Accepted,
    /// The backend built the handler's frame itself (a frame-building
    /// backend). The tool's callback returns no signal, so nothing is
    /// delivered twice.
    Installed,
    /// The backend could not write the frame and raised SIGSEGV, as Linux
    /// does (a frame-building backend).
    FrameFault,
    /// A check against the kernel failed: the tool's state contradicts the
    /// kernel's where both are certain. Nothing was approved.
    Mismatch(SignalDeliveryMismatch),
    /// The backend cannot check a delivery at this point. Nothing was
    /// approved.
    Unavailable(SignalDeliveryUnavailable),
    /// The backend does not deliver signals this way at all.
    Refused(UnsupportedRefusal),
}

#[cfg(test)]
mod tests {
    use super::*;

    const USR1: i32 = libc::SIGUSR1;

    fn delivery(interruption: Interruption) -> SignalDelivery {
        let action = SignalAction {
            handler: 0x40_1000,
            flags: (libc::SA_SIGINFO | libc::SA_RESTART) as u64,
            restorer: 0x40_2000,
            mask: signal_set_bit(libc::SIGUSR2),
        };
        let current = signal_set_bit(libc::SIGINT);
        SignalDelivery {
            signal: USR1,
            action,
            frame_mask: current,
            current_mask: current,
            handler_mask: action.handler_mask(current, USR1),
            unchecked_mask: 0,
            unchecked_frame_mask: 0,
            unchecked_current_mask: 0,
            interruption,
        }
    }

    fn kernel(d: &SignalDelivery, orig_syscall: i64, ret: i64) -> KernelDeliveryState {
        KernelDeliveryState {
            frame_mask: d.frame_mask,
            current_mask: d.current_mask,
            orig_syscall,
            ret,
        }
    }

    #[test]
    fn handler_mask_follows_linux() {
        let action = SignalAction {
            mask: signal_set_bit(libc::SIGUSR2),
            ..SignalAction::default()
        };
        let current = signal_set_bit(libc::SIGINT);
        assert_eq!(
            action.handler_mask(current, USR1),
            current | signal_set_bit(libc::SIGUSR2) | signal_set_bit(USR1)
        );
        let nodefer = SignalAction {
            flags: libc::SA_NODEFER as u64,
            ..action
        };
        assert_eq!(
            nodefer.handler_mask(current, USR1),
            current | signal_set_bit(libc::SIGUSR2)
        );
        // A realtime signal has its own bit.
        assert_eq!(
            SignalAction::default().handler_mask(0, 35),
            signal_set_bit(35)
        );
        assert_eq!(signal_set_bit(64), 1 << 63);
        assert_eq!(signal_set_bit(0), 0);
        assert_eq!(signal_set_bit(65), 0);
    }

    #[test]
    fn a_matching_delivery_passes_every_check() {
        let d = delivery(Interruption::Return {
            syscall: libc::SYS_read,
            result: -514,
        });
        assert_eq!(d.check(&kernel(&d, libc::SYS_read, -514)), Ok(()));
        let d = delivery(Interruption::NotInSyscall);
        assert_eq!(d.check(&kernel(&d, -1, 0x1234)), Ok(()));
        let d = delivery(Interruption::KernelRun {
            syscall: libc::SYS_wait4,
        });
        assert_eq!(d.check(&kernel(&d, libc::SYS_wait4, -512)), Ok(()));
        let d = delivery(Interruption::AfterFrame);
        assert_eq!(d.check(&kernel(&d, libc::SYS_read, 0)), Ok(()));
    }

    /// Each field has its own negative control: one mutated value fails the
    /// check, naming that field.
    #[test]
    fn each_mutated_field_fails_its_own_check() {
        let d = delivery(Interruption::Return {
            syscall: libc::SYS_read,
            result: -512,
        });
        let good = kernel(&d, libc::SYS_read, -512);
        let field = |d: &SignalDelivery, k: &KernelDeliveryState| d.check(k).unwrap_err().field;

        let frame = KernelDeliveryState {
            frame_mask: good.frame_mask | signal_set_bit(libc::SIGTERM),
            ..good
        };
        assert_eq!(field(&d, &frame), SignalDeliveryField::FrameMask);
        let current = KernelDeliveryState {
            current_mask: 0,
            ..good
        };
        assert_eq!(field(&d, &current), SignalDeliveryField::CurrentMask);
        let handler = SignalDelivery {
            handler_mask: d.handler_mask & !signal_set_bit(USR1),
            ..d
        };
        assert_eq!(field(&handler, &good), SignalDeliveryField::HandlerMask);
        assert_eq!(
            field(
                &d,
                &KernelDeliveryState {
                    orig_syscall: libc::SYS_write,
                    ..good
                }
            ),
            SignalDeliveryField::InterruptedSyscall
        );
        assert_eq!(
            field(&d, &KernelDeliveryState { ret: -4, ..good }),
            SignalDeliveryField::InterruptedResult
        );
        // A user-code stop whose rax happens to hold -512 is not in a syscall.
        let user = delivery(Interruption::NotInSyscall);
        assert_eq!(
            field(&user, &kernel(&user, libc::SYS_read, -512)),
            SignalDeliveryField::InterruptedSyscall
        );
        let kernel_run = delivery(Interruption::KernelRun {
            syscall: libc::SYS_wait4,
        });
        assert_eq!(
            field(&kernel_run, &kernel(&kernel_run, -1, -512)),
            SignalDeliveryField::InterruptedSyscall
        );
    }

    #[test]
    fn a_mismatch_reports_both_values_as_compared() {
        let d = SignalDelivery {
            unchecked_mask: signal_set_bit(libc::SIGTRAP),
            ..delivery(Interruption::NotInSyscall)
        };
        let k = KernelDeliveryState {
            frame_mask: d.frame_mask | signal_set_bit(libc::SIGTRAP) | signal_set_bit(libc::SIGHUP),
            ..kernel(&d, -1, 0)
        };
        assert_eq!(
            d.check(&k),
            Err(SignalDeliveryMismatch {
                field: SignalDeliveryField::FrameMask,
                expected: d.frame_mask,
                actual: d.frame_mask | signal_set_bit(libc::SIGHUP),
            })
        );
    }

    #[test]
    fn unchecked_and_unblockable_bits_are_left_out() {
        let d = SignalDelivery {
            unchecked_mask: signal_set_bit(libc::SIGTRAP),
            ..delivery(Interruption::NotInSyscall)
        };
        let k = KernelDeliveryState {
            frame_mask: d.frame_mask
                | signal_set_bit(libc::SIGTRAP)
                | signal_set_bit(libc::SIGKILL),
            current_mask: d.current_mask | signal_set_bit(libc::SIGSTOP),
            ..kernel(&d, -1, 0)
        };
        assert_eq!(d.check(&k), Ok(()));
    }

    /// A bit unchecked in one mask is left out of that mask's comparison
    /// only: the frame's exemption leaves the current mask checked, and the
    /// current mask's leaves the frame checked.
    #[test]
    fn a_per_mask_exemption_covers_its_own_mask_only() {
        let trap = signal_set_bit(libc::SIGTRAP);
        let frame_only = SignalDelivery {
            unchecked_frame_mask: trap,
            ..delivery(Interruption::NotInSyscall)
        };
        let good = kernel(&frame_only, -1, 0);
        let frame_differs = KernelDeliveryState {
            frame_mask: good.frame_mask | trap,
            ..good
        };
        let current_differs = KernelDeliveryState {
            current_mask: good.current_mask | trap,
            ..good
        };
        assert_eq!(frame_only.check(&frame_differs), Ok(()));
        assert_eq!(
            frame_only.check(&current_differs),
            Err(SignalDeliveryMismatch {
                field: SignalDeliveryField::CurrentMask,
                expected: good.current_mask,
                actual: good.current_mask | trap,
            })
        );
        let current_only = SignalDelivery {
            unchecked_frame_mask: 0,
            unchecked_current_mask: trap,
            ..frame_only
        };
        assert_eq!(current_only.check(&current_differs), Ok(()));
        assert_eq!(
            current_only.check(&frame_differs),
            Err(SignalDeliveryMismatch {
                field: SignalDeliveryField::FrameMask,
                expected: good.frame_mask,
                actual: good.frame_mask | trap,
            })
        );
        // Neither exemption covers the handler's mask, which is arithmetic
        // over the delivery's own current mask: a handler mask off Linux's
        // rule in an exempt bit still fails.
        for exempt in [frame_only, current_only] {
            let handler_differs = SignalDelivery {
                handler_mask: exempt.handler_mask | trap,
                ..exempt
            };
            assert_eq!(
                handler_differs.check(&good).unwrap_err().field,
                SignalDeliveryField::HandlerMask
            );
        }
    }
}
