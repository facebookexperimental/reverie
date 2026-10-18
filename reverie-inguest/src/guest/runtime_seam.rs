/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The shared runtime's side of the patcher seam: its SIGSYS dispatcher seam
//! ([`RuntimeSeam`]) and its instruction-fault bridge
//! ([`install_instruction_handler`]). Both own what the runtime decides
//! (statistics paths, nested-syscall observation, the continuation) and ask
//! the registered [`Patcher`] only about sites and its own accounting.

use std::io;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::guest::event::InstructionEventKind;
use crate::guest::event::SyscallEvent;
use crate::guest::instruction::FaultSite;
use crate::guest::instruction::InstructionFaultSeam;
use crate::guest::instruction::InstructionSubscriptions;
use crate::guest::instruction::PatchOutcome;
use crate::guest::patcher::NoPatcher;
use crate::guest::patcher::Patcher;
use crate::guest::trap_dispatch::SitePatch;
use crate::guest::trap_dispatch::TrapPath;
use crate::guest::trap_dispatch::TrapSeam;
use crate::stats::GuestStatsHooks;
use crate::stats::LiteinstDispatchPath;

/// The shared runtime's [`TrapSeam`]: the runtime's statistics and
/// nested-syscall observation, with site location, patching and per-syscall
/// accounting delegated to `patcher`. A patcher that declines leaves every
/// trap on the fallback continuation.
pub struct RuntimeSeam {
    patcher: &'static dyn Patcher,
    stats: GuestStatsHooks,
}

impl RuntimeSeam {
    /// The seam for `patcher`, recording dispatch paths in `stats`.
    pub fn new(patcher: &'static dyn Patcher, stats: GuestStatsHooks) -> Self {
        Self { patcher, stats }
    }

    /// The patcher this seam asks about sites.
    pub fn patcher(&self) -> &'static dyn Patcher {
        self.patcher
    }
}

/// The statistics path a dispatch path is recorded as.
fn dispatch_path(path: TrapPath) -> LiteinstDispatchPath {
    match path {
        TrapPath::NestedSigsys => LiteinstDispatchPath::InGuestNestedSigsys,
        TrapPath::Sigsys => LiteinstDispatchPath::InGuestSigsys,
        TrapPath::PhysicalSigsys => LiteinstDispatchPath::InGuestPhysicalSigsys,
        TrapPath::FallbackCompletion => LiteinstDispatchPath::FallbackCompletionSigsys,
        TrapPath::FallbackRefusal => LiteinstDispatchPath::FallbackRefusal,
    }
}

// SAFETY: `intercept` keeps its default (false), so this seam never runs an
// event's syscall itself.
unsafe impl TrapSeam for RuntimeSeam {
    fn record_path(&self, path: TrapPath) {
        self.stats.record_path(dispatch_path(path));
    }

    fn observe_nested(&self, event: &SyscallEvent) {
        self.patcher.observe_mapping(event);
    }

    unsafe fn syscall_site(&self, resume_address: u64) -> u64 {
        // SAFETY: the dispatcher's provenance promise is passed on unchanged.
        unsafe { self.patcher.syscall_site(resume_address) }
    }

    unsafe fn patch_syscall_site(&self, instruction_pointer: u64, number: i64) -> SitePatch {
        // SAFETY: the dispatcher's provenance promise is passed on unchanged.
        unsafe { self.patcher.patch_syscall_site(instruction_pointer, number) }
    }

    fn record_fallback(&self, number: i64) {
        self.patcher.record_fallback(number);
    }

    fn record_continuation(&self, instruction_pointer: u64) {
        // The classification can read the patcher's site state; it runs only
        // when the run collects statistics.
        if self.stats.is_enabled() {
            self.stats
                .record_path(self.patcher.fallback_path(instruction_pointer));
        }
    }

    fn record_refusal(&self, number: i64) {
        self.patcher.record_refusal(number);
    }
}

/// A `'static` handle to a patcher, which the instruction-fault bridge stores
/// as a thin pointer (a `&dyn Patcher` is two words wide).
pub struct PatcherRef(pub &'static dyn Patcher);

static NO_PATCHER: NoPatcher = NoPatcher;
static NO_PATCHER_REF: PatcherRef = PatcherRef(&NO_PATCHER);
static INSTRUCTION_PATCHER: AtomicPtr<PatcherRef> = AtomicPtr::new(std::ptr::null_mut());

/// The patcher the instruction-fault bridge asks, or [`NoPatcher`] when none
/// was registered.
fn instruction_patcher() -> &'static dyn Patcher {
    // SAFETY: only `&'static PatcherRef`s are stored.
    unsafe { INSTRUCTION_PATCHER.load(Ordering::Acquire).as_ref() }
        .unwrap_or(&NO_PATCHER_REF)
        .0
}

unsafe fn bridge_locate(
    address: u64,
    info: *const libc::siginfo_t,
    context: *const libc::ucontext_t,
) -> FaultSite {
    // SAFETY: the handler's promises for `locate` are the patcher's for
    // `locate_instruction`.
    unsafe { instruction_patcher().locate_instruction(address, info, context) }
}

unsafe fn bridge_patch(
    address: u64,
    kind: InstructionEventKind,
    encoding: &'static [u8],
) -> PatchOutcome {
    // SAFETY: the handler's promises for `patch` are the patcher's for
    // `patch_instruction`.
    unsafe { instruction_patcher().patch_instruction(address, kind, encoding) }
}

static INSTRUCTION_BRIDGE: InstructionFaultSeam = InstructionFaultSeam {
    locate: bridge_locate,
    patch: bridge_patch,
};

/// Sets the instruction-fault bridge's patcher, once per process: a second
/// registration of the same patcher is accepted (a retried installation), and
/// of a different one refused, so one fault's location and patch questions
/// always reach the same patcher.
fn set_instruction_patcher(patcher: &'static PatcherRef) -> io::Result<()> {
    let new = std::ptr::from_ref(patcher).cast_mut();
    match INSTRUCTION_PATCHER.compare_exchange(
        std::ptr::null_mut(),
        new,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Ok(()),
        Err(current) if current == new => Ok(()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the instruction-fault bridge already has a different patcher",
        )),
    }
}

/// Registers `patcher` for instruction faults (once per process; see
/// `set_instruction_patcher`) and installs the runtime's instruction fault
/// handler for `subscriptions` (on the alternate signal stack when
/// `on_alt_stack`). With [`NoPatcher`], every subscribed instruction is
/// emulated through the fallback continuation.
///
/// # Safety
///
/// As [`crate::guest::instruction::install_instruction_signal_handler`]: the
/// handler replaces any `SIGSEGV` action the process had. `patcher`'s
/// instruction methods must meet [`Patcher`]'s contract.
pub unsafe fn install_instruction_handler(
    patcher: &'static PatcherRef,
    subscriptions: InstructionSubscriptions,
    on_alt_stack: bool,
) -> io::Result<()> {
    set_instruction_patcher(patcher)?;
    // SAFETY: the bridge's functions forward to the registered patcher, whose
    // contract matches the seam's; the caller accepts the SIGSEGV replacement.
    unsafe {
        crate::guest::instruction::install_instruction_signal_handler(
            &INSTRUCTION_BRIDGE,
            subscriptions,
            on_alt_stack,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;

    struct CountingPatcher {
        classified: AtomicU64,
    }

    // SAFETY: declines everything; counts classifications only.
    unsafe impl Patcher for CountingPatcher {
        fn fallback_path(&self, _instruction_pointer: u64) -> LiteinstDispatchPath {
            self.classified.fetch_add(1, Ordering::Relaxed);
            LiteinstDispatchPath::UnpatchableOrOtherFallback
        }
    }

    static COUNTING: CountingPatcher = CountingPatcher {
        classified: AtomicU64::new(0),
    };

    #[test]
    fn disabled_statistics_never_classify_a_continuation() {
        let seam = RuntimeSeam::new(&COUNTING, GuestStatsHooks::DISABLED);
        let before = COUNTING.classified.load(Ordering::Relaxed);
        seam.record_continuation(0xdead_beef);
        assert_eq!(COUNTING.classified.load(Ordering::Relaxed), before);
    }

    #[test]
    fn every_dispatch_path_keeps_its_statistics_name() {
        assert_eq!(
            dispatch_path(TrapPath::NestedSigsys),
            LiteinstDispatchPath::InGuestNestedSigsys
        );
        assert_eq!(
            dispatch_path(TrapPath::Sigsys),
            LiteinstDispatchPath::InGuestSigsys
        );
        assert_eq!(
            dispatch_path(TrapPath::PhysicalSigsys),
            LiteinstDispatchPath::InGuestPhysicalSigsys
        );
        assert_eq!(
            dispatch_path(TrapPath::FallbackCompletion),
            LiteinstDispatchPath::FallbackCompletionSigsys
        );
        assert_eq!(
            dispatch_path(TrapPath::FallbackRefusal),
            LiteinstDispatchPath::FallbackRefusal
        );
    }

    /// Records every question the seam passes on, and answers with values a
    /// default would not give, so a seam that answered for itself is caught.
    struct RecordingPatcher {
        calls: std::sync::Mutex<Vec<String>>,
    }

    // SAFETY: test-only; nothing is installed and no guest code runs, so the
    // non-declining answers below change no code.
    unsafe impl Patcher for RecordingPatcher {
        unsafe fn syscall_site(&self, resume_address: u64) -> u64 {
            self.calls
                .lock()
                .unwrap()
                .push(format!("site {resume_address:#x}"));
            resume_address - 7
        }

        unsafe fn patch_syscall_site(&self, instruction_pointer: u64, number: i64) -> SitePatch {
            self.calls
                .lock()
                .unwrap()
                .push(format!("patch {instruction_pointer:#x} {number}"));
            SitePatch::Defer(0x5000)
        }

        fn observe_mapping(&self, event: &SyscallEvent) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("mapping {}", event.number));
        }

        fn record_fallback(&self, number: i64) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("fallback {number}"));
        }

        fn record_refusal(&self, number: i64) {
            self.calls.lock().unwrap().push(format!("refusal {number}"));
        }
    }

    #[test]
    fn the_runtime_seam_passes_site_mapping_and_accounting_questions_to_its_patcher() {
        static RECORDING: RecordingPatcher = RecordingPatcher {
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let seam = RuntimeSeam::new(&RECORDING, GuestStatsHooks::DISABLED);
        // SAFETY: the recording patcher reads nothing at these addresses.
        unsafe {
            assert_eq!(seam.syscall_site(0x1009), 0x1002);
            assert!(matches!(
                seam.patch_syscall_site(0x1002, libc::SYS_getpid),
                SitePatch::Defer(0x5000)
            ));
        }
        seam.observe_nested(&crate::guest::event::SyscallEvent {
            number: libc::SYS_munmap,
            args: [0x1000, 0x1000, 0, 0, 0, 0],
            instruction_pointer: 0x2000,
            result: 0,
            context: 0,
            dispatch: crate::guest::event::SyscallDispatch::Fallback,
            guest_pkru: None,
        });
        seam.record_fallback(libc::SYS_getpid);
        seam.record_refusal(libc::SYS_getpid);
        assert_eq!(
            *RECORDING.calls.lock().unwrap(),
            [
                "site 0x1009".to_string(),
                format!("patch 0x1002 {}", libc::SYS_getpid),
                format!("mapping {}", libc::SYS_munmap),
                format!("fallback {}", libc::SYS_getpid),
                format!("refusal {}", libc::SYS_getpid),
            ]
        );
    }

    #[test]
    fn no_patcher_declines_every_site() {
        let seam = RuntimeSeam::new(&NO_PATCHER, GuestStatsHooks::DISABLED);
        // SAFETY: NoPatcher reads nothing at these addresses.
        unsafe {
            assert_eq!(seam.syscall_site(0x1002), 0x1000);
            assert!(matches!(
                seam.patch_syscall_site(0x1000, libc::SYS_getpid),
                SitePatch::NotPatched
            ));
        }
        assert!(seam.continuation_allowed());
    }

    #[test]
    fn an_unregistered_instruction_bridge_declines() {
        // No test in this crate registers a patcher, so the bridge asks
        // NoPatcher: the instruction is emulated, never a missing-seam death.
        assert!(INSTRUCTION_PATCHER.load(Ordering::Acquire).is_null());
        // SAFETY: NoPatcher reads nothing.
        let site = unsafe { bridge_locate(0x1000, std::ptr::null(), std::ptr::null()) };
        assert!(matches!(site, FaultSite::Unpatchable));
        // SAFETY: as above.
        let outcome = unsafe { bridge_patch(0x1000, InstructionEventKind::Cpuid, &[0x0f, 0xa2]) };
        assert!(matches!(outcome, PatchOutcome::Emulate));
    }
}
