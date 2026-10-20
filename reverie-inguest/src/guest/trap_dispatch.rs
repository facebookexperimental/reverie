/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The shared SIGSYS dispatcher of the in-guest runtime. A trapped syscall is
//! one of three things: a Tool callback's own syscall, which runs natively
//! after the runtime's protections; a trap the backend patches into a hook,
//! which the trap defers to; or a trap no hook takes, which the fallback
//! continuation runs in ordinary context (or which is refused with
//! `EOPNOTSUPP` where the continuation cannot run). The backend supplies its
//! part through a [`TrapSeam`]. The default methods are a backend that
//! patches nothing: every trap goes to the continuation.

use crate::dispatch::SyscallDispatcher;
use crate::dispatch::SyscallEvent as TrapEvent;
use crate::dispatch::SyscallEventSource;
use crate::guest::continuation;
use crate::guest::event::SyscallDispatch;
use crate::guest::event::SyscallEvent;
use crate::guest::protect::protect_runtime_control;
use crate::guest::protect::protect_runtime_descriptors;
use crate::guest::support::exit_now;
use crate::guest::support::tool_callback_active;
use crate::trap::NativeSyscallResult;
use crate::trap::frame::SignalFrame;

const SYS_IO_PGETEVENTS: i64 = 333;
/// The result a forwarded event starts with, before the syscall runs.
const UNSET_RESULT: i64 = i64::MIN;

/// The dispatch paths the shared dispatcher reports through
/// [`TrapSeam::record_path`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapPath {
    /// A Tool callback's own syscall, run natively.
    NestedSigsys,
    /// A trapped guest syscall.
    Sigsys,
    /// A SIGSYS checked for a fallback-continuation completion.
    PhysicalSigsys,
    /// A fallback-continuation completion.
    FallbackCompletion,
    /// A trap refused with `EOPNOTSUPP`.
    FallbackRefusal,
}

/// What the backend did with a trap's syscall site.
pub enum SitePatch {
    /// The site has a hook or unpublished adapter: defer to this entry.
    Defer(u64),
    /// No hook: run the trap through the fallback continuation.
    NotPatched,
    /// The runtime's state is unsafe for the continuation: refuse the trap.
    Refuse,
}

/// The backend's part of the shared SIGSYS dispatcher. Every method is called
/// from the SIGSYS handler (or the hook that dispatches like it) and must be
/// async-signal-safe.
///
/// [`syscall_site`](Self::syscall_site) and [`patch_site`](Self::patch_site)
/// are unsafe: the dispatcher calls them only for an event delivered by the
/// SIGSYS trap handler (never for a direct event from
/// [`crate::trap::dispatch_direct`]), with the resume address it had on
/// arrival, and they may rely on what [`InGuestDispatcher::new`]'s caller
/// promises about such events.
///
/// # Safety
///
/// An implementation whose [`intercept`](Self::intercept) returns `false` must
/// not have run the event's syscall (or a copy of it): the dispatcher then
/// treats the trap as not yet run.
pub unsafe trait TrapSeam: Send + Sync {
    /// Records a dispatch path in the backend's statistics.
    fn record_path(&self, _path: TrapPath) {}

    /// Sees a Tool callback's own syscall after it ran natively.
    fn observe_nested(&self, _event: &SyscallEvent) {}

    /// Handles a trapped or direct syscall entirely, before the shared path,
    /// and returns whether it did (with `event`'s result set). It is safe, so it
    /// must be sound for any event; it may run the event's syscall natively, as
    /// the safe [`TrapEvent::forward`] may.
    fn intercept(&self, _event: &mut TrapEvent) -> bool {
        false
    }

    /// The address of the trapped `syscall` instruction, given the address the
    /// trap resumes at (just past it).
    ///
    /// # Safety
    ///
    /// `resume_address` is the arrival resume address of a SIGSYS-delivered
    /// trap that has not run, so the code just before it was executing.
    unsafe fn syscall_site(&self, resume_address: u64) -> u64 {
        resume_address.saturating_sub(2)
    }

    /// Patches the trap's syscall site, if the backend patches.
    ///
    /// # Safety
    ///
    /// `instruction_pointer` is what [`syscall_site`](Self::syscall_site)
    /// returned for a SIGSYS-delivered trap that has not run.
    unsafe fn patch_site(&self, _instruction_pointer: u64) -> SitePatch {
        SitePatch::NotPatched
    }

    /// Selects a site's hook or unpublished adapter for this actual syscall.
    /// A backend with number-specific admission must check every trap, even
    /// when an earlier syscall at this address already created an adapter.
    ///
    /// # Safety
    ///
    /// The address has the same genuine-trap provenance as [`Self::patch_site`].
    /// `number` is the number of that trap, before any guest syscall ran.
    unsafe fn patch_syscall_site(&self, instruction_pointer: u64, _number: i64) -> SitePatch {
        // SAFETY: this method preserves patch_site's address provenance.
        unsafe { self.patch_site(instruction_pointer) }
    }

    /// Whether the fallback continuation may run an unpatched trap.
    fn continuation_allowed(&self) -> bool {
        true
    }

    /// Counts a trap that no hook takes, before the continuation or refusal.
    fn record_fallback(&self, _number: i64) {}

    /// Counts a trap the continuation will run, by its syscall instruction.
    fn record_continuation(&self, _instruction_pointer: u64) {}

    /// Counts a refused trap.
    fn record_refusal(&self, _number: i64) {}
}

/// The shared SIGSYS dispatcher, with the backend's [`TrapSeam`].
pub struct InGuestDispatcher<S> {
    seam: S,
}

impl<S: TrapSeam> InGuestDispatcher<S> {
    /// A dispatcher using `seam`.
    ///
    /// # Safety
    ///
    /// Every SIGSYS-sourced event the dispatcher receives must be a genuine
    /// syscall trap that has not run, as the trap handler of
    /// `reverie_inguest::install` delivers (so do not hand its methods a copy
    /// of a trap event obtained elsewhere), unless `seam`'s unsafe methods rely
    /// on nothing (they read and change nothing at the addresses they are
    /// given). Direct events, from [`crate::trap::dispatch_direct`], never
    /// reach those methods and need no promise.
    pub unsafe fn new(seam: S) -> Self {
        Self { seam }
    }

    fn refuse(&self, event: &mut TrapEvent) {
        self.seam.record_refusal(event.number());
        self.seam.record_path(TrapPath::FallbackRefusal);
        event.fail(libc::EOPNOTSUPP);
    }

    fn dispatch_with_frame(&self, event: &mut TrapEvent, frame: Option<&mut SignalFrame<'_>>) {
        // Taken on arrival, before the backend's intercept can change the event.
        let trapped = event.source() == SyscallEventSource::SignalTrap;
        let resume_address = event.instruction_pointer();
        let trapped_number = event.number();
        #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
        let mapped_callback = super::exec_private::mapped_callback_candidate()
            || (tool_callback_active() && super::exec_private::mapped_callback_origin());
        #[cfg(not(all(feature = "loader-private-runtime", target_env = "musl")))]
        let mapped_callback = false;
        if tool_callback_active() || mapped_callback {
            continuation::enable_nested_runtime_access();
            self.seam.record_path(TrapPath::NestedSigsys);
            let mut nested = SyscallEvent {
                number: event.number(),
                args: event.args(),
                instruction_pointer: event.instruction_pointer(),
                result: UNSET_RESULT,
                context: 0,
                dispatch: SyscallDispatch::Trap,
                guest_pkru: event.guest_pkru(),
            };
            // SAFETY: a trapped event is genuine (`new`'s contract) and made
            // while a Tool callback is active on this thread: the callback's
            // own syscall, which may run natively. A direct event comes from the
            // safe dispatch_direct, whose caller may already run any syscall
            // through the safe TrapEvent::forward.
            unsafe {
                #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
                if mapped_callback {
                    // The candidate classification grants no permission. A
                    // direct event or missing actual frame is terminal.
                    if !trapped {
                        crate::private_runtime::abort()
                    }
                    let Some(frame) = frame else {
                        crate::private_runtime::abort()
                    };
                    super::exec_private::forward_mapped_callback(&mut nested, frame, |event| {
                        self.seam.observe_nested(event)
                    });
                } else {
                    forward_nested_tool_syscall(&mut nested, |event| {
                        self.seam.observe_nested(event)
                    });
                }
                #[cfg(not(all(feature = "loader-private-runtime", target_env = "musl")))]
                forward_nested_tool_syscall(&mut nested, |event| self.seam.observe_nested(event));
            };
            event.set_native_result(NativeSyscallResult {
                result: nested.result,
                pkru: nested.guest_pkru,
            });
            return;
        }
        self.seam.record_path(TrapPath::Sigsys);
        if self.seam.intercept(event) {
            return;
        }

        // A direct event has no trap site to locate or patch, and no frame for
        // the continuation: it is refused below.
        let instruction_pointer = if trapped {
            // SAFETY: a SIGSYS-delivered trap (`new`'s contract) that has not
            // run (the seam's intercept declined it without running it, the
            // trait's contract), with its arrival resume address; patch_site
            // gets what syscall_site returned for it.
            let instruction_pointer = unsafe { self.seam.syscall_site(resume_address) };
            match unsafe {
                self.seam
                    .patch_syscall_site(instruction_pointer, trapped_number)
            } {
                SitePatch::Defer(entry) => {
                    event.defer_to(entry);
                    return;
                }
                SitePatch::Refuse => {
                    self.seam.record_fallback(event.number());
                    self.refuse(event);
                    return;
                }
                SitePatch::NotPatched => {}
            }
            instruction_pointer
        } else {
            resume_address.saturating_sub(2)
        };

        self.seam.record_fallback(event.number());
        if self.seam.continuation_allowed()
            && let Some(frame) = frame
        {
            // SAFETY: this is the SIGSYS handler's dispatch with the trap's own
            // frame for the syscall at `instruction_pointer`; on Ok(Some) the
            // event is deferred to the entry, and on Err the process ends.
            match unsafe { continuation::prepare_signal(instruction_pointer, frame) } {
                Ok(Some(entry)) => {
                    self.seam.record_continuation(instruction_pointer);
                    event.defer_to(entry);
                    return;
                }
                Ok(None) => {}
                Err(_) => unsafe { exit_now(126) },
            }
        }
        self.refuse(event);
    }
}

impl<S: TrapSeam> SyscallDispatcher for InGuestDispatcher<S> {
    fn dispatch(&self, event: &mut TrapEvent) {
        self.dispatch_with_frame(event, None);
    }

    fn dispatch_private_signal(&self, frame: &mut SignalFrame<'_>) -> bool {
        self.seam.record_path(TrapPath::PhysicalSigsys);
        match continuation::complete(frame) {
            Ok(true) => {
                self.seam.record_path(TrapPath::FallbackCompletion);
                true
            }
            Ok(false) => false,
            Err(_) => unsafe { exit_now(126) },
        }
    }

    fn dispatch_signal(&self, event: &mut TrapEvent, frame: &mut SignalFrame<'_>) {
        self.dispatch_with_frame(event, Some(frame));
    }
}

// Pure shared refusal inventory; this grants no execution authority. The
// mapped startup owner and ordinary callback route choose their own gate.
pub(crate) fn nested_tool_control_result(number: i64, private_registrations: bool) -> Option<i64> {
    if private_registrations
        && matches!(
            number,
            libc::SYS_set_tid_address | libc::SYS_set_robust_list
        )
    {
        return Some(-i64::from(libc::EPERM));
    }
    let unsupported_process =
        // AUTONOMOUS-BOT-IMPLEMENTED
        number == libc::SYS_clone
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_clone3
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_fork
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_vfork
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_execve
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_execveat;
    let unsupported_signal_state =
        // AUTONOMOUS-BOT-IMPLEMENTED
        number == libc::SYS_rt_sigaction
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_rt_sigprocmask
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_sigaltstack
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_rt_sigsuspend
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_pselect6
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_ppoll
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_epoll_pwait
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == libc::SYS_epoll_pwait2
        // AUTONOMOUS-BOT-IMPLEMENTED
        || number == SYS_IO_PGETEVENTS;
    if unsupported_process {
        Some(-i64::from(libc::ENOTSUP))
    } else if unsupported_signal_state {
        Some(-i64::from(libc::EPERM))
    } else {
        None
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review nested Tool syscall guards and raw forwarding.
/// Runs a syscall a Tool callback makes itself (reached while the callback is
/// active) natively, after the runtime's own protections: process creation
/// and exec fail with `ENOTSUP`, signal-state and signal-mask-taking calls
/// with `EPERM`, and [`protect_runtime_control`] and
/// [`protect_runtime_descriptors`] apply as for a Tool syscall. After a
/// syscall that ran, `observe` sees it (LiteInst marks patch sites in a
/// remapped range stale).
///
/// With a published native private-loader control, Tool calls to
/// `set_tid_address` and `set_robust_list` also fail with `EPERM`: their
/// per-thread kernel registrations belong to the guest.
///
/// # Safety
///
/// The caller must be entitled to run `event`'s syscall natively with its own
/// arguments, through the trusted gate: for the runtime, a genuine trap or
/// hook entry made while a Tool callback is active on this thread (the
/// callback's own syscall). Apart from the refusals above, it can do anything
/// that syscall does, including closing descriptors and changing mappings.
pub unsafe fn forward_nested_tool_syscall(
    event: &mut SyscallEvent,
    observe: impl FnOnce(&SyscallEvent),
) {
    // Preserve the legacy/GNU execution leaf exactly. The private mapped
    // callback supplies its Tool-FS gate only after its own owner validation.
    unsafe {
        forward_nested_tool_syscall_with(event, observe, |event| {
            event.result = event.forward();
        })
    };
}

// Shared protections/order, private execution leaf: no Guest dispatch or second
// syscall-policy table. Caller owns its authentic event and native authority.
pub(super) unsafe fn forward_nested_tool_syscall_with(
    event: &mut SyscallEvent,
    observe: impl FnOnce(&SyscallEvent),
    execute: impl FnOnce(&mut SyscallEvent),
) {
    #[cfg(feature = "exec-private-init")]
    let private_registrations = super::exec_private::active();
    #[cfg(not(feature = "exec-private-init"))]
    let private_registrations = false;
    if let Some(result) = nested_tool_control_result(event.number, private_registrations) {
        event.result = result;
    } else if !(protect_runtime_control(event)
        || unsafe { protect_runtime_descriptors(event, false) })
    {
        if let Some(result) = super::restorer::owner_mapping_change_result(event.number, event.args)
        {
            event.result = result;
            return;
        }
        execute(event);
        observe(event);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A backend that patches nothing: every default method.
    struct TrapOnly;

    // SAFETY: the default intercept declines without running anything.
    unsafe impl TrapSeam for TrapOnly {}

    /// A seam that answers `patch` and records every call. Its unsafe methods
    /// only log, so they rely on nothing.
    struct Recording {
        intercept: bool,
        /// When set, `intercept` replaces the whole event with a trap at
        /// another address before declining it.
        replace: bool,
        patch: fn() -> SitePatch,
        calls: Mutex<Vec<String>>,
    }

    impl Recording {
        fn new(intercept: bool, patch: fn() -> SitePatch) -> Self {
            Self {
                intercept,
                replace: false,
                patch,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn log(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }
    }

    // SAFETY: intercept only logs, and may replace the event, but never runs a
    // syscall.
    unsafe impl TrapSeam for Recording {
        fn record_path(&self, path: TrapPath) {
            self.log(format!("path {path:?}"));
        }
        fn intercept(&self, event: &mut TrapEvent) -> bool {
            self.log(format!("intercept {}", event.number()));
            if self.replace {
                *event = TrapEvent::new(libc::SYS_getpid, [0; 6], 0x9002);
            }
            if self.intercept {
                event.set_result(4242);
            }
            self.intercept
        }
        unsafe fn syscall_site(&self, resume_address: u64) -> u64 {
            self.log(format!("site {resume_address:#x}"));
            resume_address - 2
        }
        unsafe fn patch_site(&self, instruction_pointer: u64) -> SitePatch {
            self.log(format!("patch {instruction_pointer:#x}"));
            (self.patch)()
        }
        fn continuation_allowed(&self) -> bool {
            self.log("continuation?".to_string());
            true
        }
        fn record_fallback(&self, number: i64) {
            self.log(format!("fallback {number}"));
        }
        fn record_continuation(&self, instruction_pointer: u64) {
            self.log(format!("continuation {instruction_pointer:#x}"));
        }
        fn record_refusal(&self, number: i64) {
            self.log(format!("refusal {number}"));
        }
    }

    /// A dispatcher over a [`Recording`] seam, which relies on nothing: the
    /// tests' direct events are not traps.
    fn recording(intercept: bool, patch: fn() -> SitePatch) -> InGuestDispatcher<Recording> {
        // SAFETY: the recording seam's unsafe methods rely on nothing (they
        // only log), the case `new`'s contract allows for non-genuine traps.
        unsafe { InGuestDispatcher::new(Recording::new(intercept, patch)) }
    }

    fn trap() -> TrapEvent {
        TrapEvent::new(libc::SYS_getpid, [0; 6], 0x1002)
    }

    fn calls(dispatcher: &InGuestDispatcher<Recording>) -> Vec<String> {
        dispatcher.seam.calls.lock().unwrap().clone()
    }

    struct NumberAdmission {
        seen: Mutex<Vec<(u64, i64)>>,
        replace: bool,
    }

    // SAFETY: these methods only observe and edit test events; no syscall or
    // memory access at a supplied instruction address is performed.
    unsafe impl TrapSeam for NumberAdmission {
        fn intercept(&self, event: &mut TrapEvent) -> bool {
            if self.replace {
                *event = TrapEvent::new(libc::SYS_getpid, [0; 6], 0x9002);
            }
            false
        }

        unsafe fn patch_syscall_site(&self, address: u64, number: i64) -> SitePatch {
            self.seen.lock().unwrap().push((address, number));
            if matches!(number, libc::SYS_read | libc::SYS_write) {
                SitePatch::Defer(0x5000)
            } else {
                SitePatch::Refuse
            }
        }
    }

    #[test]
    fn number_admission_runs_for_every_trap_at_the_same_site() {
        // SAFETY: the test seam neither dereferences nor executes the address.
        let dispatcher = unsafe {
            InGuestDispatcher::new(NumberAdmission {
                seen: Mutex::new(Vec::new()),
                replace: false,
            })
        };
        for number in [libc::SYS_read, libc::SYS_getpid, libc::SYS_write] {
            let mut event = TrapEvent::new(number, [0; 6], 0x1002);
            dispatcher.dispatch(&mut event);
            if number == libc::SYS_getpid {
                assert_eq!(event.result(), Some(-i64::from(libc::EOPNOTSUPP)));
                assert_eq!(event.resume_address(), None);
            } else {
                assert_eq!(event.result(), None);
                assert_eq!(event.resume_address(), Some(0x5000));
            }
        }
        assert_eq!(
            *dispatcher.seam.seen.lock().unwrap(),
            [
                (0x1000, libc::SYS_read),
                (0x1000, libc::SYS_getpid),
                (0x1000, libc::SYS_write)
            ]
        );
    }

    #[test]
    fn number_admission_uses_the_arrival_number_and_address() {
        // SAFETY: the test seam neither dereferences nor executes the address.
        let dispatcher = unsafe {
            InGuestDispatcher::new(NumberAdmission {
                seen: Mutex::new(Vec::new()),
                replace: true,
            })
        };
        let mut event = TrapEvent::new(libc::SYS_read, [0; 6], 0x1002);
        dispatcher.dispatch(&mut event);
        assert_eq!(
            *dispatcher.seam.seen.lock().unwrap(),
            [(0x1000, libc::SYS_read)]
        );
        assert_eq!(event.resume_address(), Some(0x5000));
    }

    #[test]
    fn a_trap_only_backend_refuses_a_trap_without_a_signal_frame() {
        // Without a frame (a direct dispatch) the continuation cannot run.
        let mut event = trap();
        // SAFETY: the default seam's unsafe methods read and change nothing,
        // the case `new`'s contract allows for non-genuine traps.
        unsafe { InGuestDispatcher::new(TrapOnly) }.dispatch(&mut event);
        assert_eq!(event.result(), Some(-i64::from(libc::EOPNOTSUPP)));
        assert_eq!(event.resume_address(), None);
    }

    #[test]
    fn a_patched_site_defers_the_trap_to_its_hook() {
        let dispatcher = recording(false, || SitePatch::Defer(0x5000));
        let mut event = trap();
        dispatcher.dispatch(&mut event);
        assert_eq!(event.resume_address(), Some(0x5000));
        assert_eq!(event.result(), None);
        assert_eq!(
            calls(&dispatcher),
            ["path Sigsys", "intercept 39", "site 0x1002", "patch 0x1000"]
        );
    }

    #[test]
    fn an_unpatched_trap_without_a_frame_counts_a_fallback_then_a_refusal() {
        let dispatcher = recording(false, || SitePatch::NotPatched);
        let mut event = trap();
        dispatcher.dispatch(&mut event);
        assert_eq!(event.result(), Some(-i64::from(libc::EOPNOTSUPP)));
        assert_eq!(
            calls(&dispatcher),
            [
                "path Sigsys",
                "intercept 39",
                "site 0x1002",
                "patch 0x1000",
                "fallback 39",
                "continuation?",
                "refusal 39",
                "path FallbackRefusal",
            ]
        );
    }

    #[test]
    fn a_refused_site_skips_the_continuation() {
        let dispatcher = recording(false, || SitePatch::Refuse);
        let mut event = trap();
        dispatcher.dispatch(&mut event);
        assert_eq!(event.result(), Some(-i64::from(libc::EOPNOTSUPP)));
        assert_eq!(
            calls(&dispatcher),
            [
                "path Sigsys",
                "intercept 39",
                "site 0x1002",
                "patch 0x1000",
                "fallback 39",
                "refusal 39",
                "path FallbackRefusal",
            ]
        );
    }

    #[test]
    fn an_intercepted_trap_takes_no_shared_step() {
        let dispatcher = recording(true, || SitePatch::Defer(0x5000));
        let mut event = trap();
        dispatcher.dispatch(&mut event);
        assert_eq!(
            event.result(),
            Some(4242),
            "the interceptor's result stands"
        );
        assert_eq!(event.resume_address(), None);
        assert_eq!(calls(&dispatcher), ["path Sigsys", "intercept 39"]);
    }
    #[test]
    fn a_direct_event_never_reaches_the_site_methods() {
        let dispatcher = recording(false, || SitePatch::Defer(0x5000));
        let mut event = TrapEvent::direct(libc::SYS_getpid, [0; 6], 0x1002);
        dispatcher.dispatch(&mut event);
        assert_eq!(event.result(), Some(-i64::from(libc::EOPNOTSUPP)));
        assert_eq!(event.resume_address(), None);
        assert_eq!(
            calls(&dispatcher),
            [
                "path Sigsys",
                "intercept 39",
                "fallback 39",
                "continuation?",
                "refusal 39",
                "path FallbackRefusal",
            ]
        );
    }

    #[test]
    fn a_declining_intercept_cannot_move_the_site_the_seam_is_given() {
        let mut seam = Recording::new(false, || SitePatch::NotPatched);
        seam.replace = true;
        // SAFETY: as for `recording`: the seam's unsafe methods only log.
        let dispatcher = unsafe { InGuestDispatcher::new(seam) };
        let mut event = trap();
        dispatcher.dispatch(&mut event);
        let calls = calls(&dispatcher);
        assert_eq!(calls[2], "site 0x1002", "{calls:?}");
        assert_eq!(calls[3], "patch 0x1000", "{calls:?}");
    }

    #[test]
    fn shared_nested_process_refusal_never_reaches_chosen_native_leaf() {
        let mut event = SyscallEvent {
            number: libc::SYS_clone,
            args: [0; 6],
            instruction_pointer: 0,
            result: UNSET_RESULT,
            context: 0,
            dispatch: SyscallDispatch::Trap,
            guest_pkru: None,
        };
        let executed = core::cell::Cell::new(false);
        let observed = core::cell::Cell::new(false);
        // SAFETY: the real shared process guard refuses before either closure;
        // no fabricated event is ever executed by a kernel or Guest path.
        unsafe {
            forward_nested_tool_syscall_with(
                &mut event,
                |_| observed.set(true),
                |_| executed.set(true),
            )
        };
        assert_eq!(event.result, -i64::from(libc::ENOTSUP));
        assert!(!executed.get() && !observed.get());
    }
}
