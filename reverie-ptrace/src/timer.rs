/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Timers monitor a specified thread using the PMU and deliver a signal
//! after a specified number of events occur. The signal is then identified
//! and transformed into a reverie timer event. This is intended to allow
//! tools to break busywaits or other spins in a reliable manner. Timers
//! are ideally deterministic so that `detcore` can use them.
//!
//! Due to PMU skid, precise timer events normally must be driven to completion
//! via single stepping. This means the PMI is scheduled early, and events with
//! very short timeouts require immediate single stepping. Immediate stepping is
//! acheived by artificially generating a signal that will then be delivered
//! immediately upon resumption of the guest. If delivery is already past the
//! target, the overshoot is recorded and the event is delivered at the observed
//! counter because single stepping cannot move the guest backward. If another
//! Tool-observable stop arrives first with the delivery point already reached,
//! that stop cancels the event and the overshoot is recorded there. A stop
//! that `Timer::disregard_stop()` hands back to the event does not cancel it
//! and records nothing; whatever decides the event later finds the delivery
//! point reached too, and the disregarded stop's own finding is recorded
//! only if the thread exits before anything decides the event. A disregarded
//! stop that cannot hand the event back (one within
//! `PmuConfig::keep_margin()` of the target without overflow records, or one
//! that finds the steps' notification lost) cancels it and records the
//! overshoot as a Tool-observable stop does. `Timer::retire()` records one
//! only for an event that no stop has decided (still Scheduled) whose
//! delivery point the guest has reached; an event already delivered, or
//! cancelled by a stop, is not recorded by it. Each of these records only
//! an undecided event and leaves it decided, so a single event is recorded
//! at most once. An event still undecided when its thread exits
//! (`Timer::settle_at_exit()`) is recorded if the guest reached its delivery
//! point. An event that ends with a non-leader exec without a stop having
//! found its delivery point reached, or that is overtaken by a stop of the
//! timer signal's own type, including a forged one, is not recorded.
//!
//! Where nothing continues an event across a stop that the Tool does not
//! see, the stop keeps the event only while the guest is more than
//! `PmuConfig::keep_margin()` RCBs short of its target. That margin is the
//! largest skid margin of any processor in the PMU table, plus the single
//! steps of an artificial notification, so the same guest clock keeps or
//! cancels the event on every supported processor; only a skid margin
//! override above the table's largest moves it.
//!
//! Proper use of timers requires that all delivered signals of type
//! `Timer::signal_type()` be passed through `Timer::handle_signal`, and that
//! `Timer::observe_event()` be called whenever a Tool-observable reverie event
//! occurs. A caller that observes a stop before it knows whether the Tool
//! observes it must pass a stop that the Tool does not observe to
//! `Timer::disregard_stop()`, and finish what of the active event this
//! returns with `Timer::continue_stepping()`. Additionally,
//! `Timer::finalize_requests()` must be called
//!  - after the end of the tool callback in which the user could have
//!    requested a timer event, i.e. those with `&mut guest` access.
//!  - after any reverie-critical single-stepping occurs (e.g. in syscall
//!    injections),
//!  - before resumption of the guest,
//!    which _usually_ means immediately after the tool callback returns.

use std::cmp::Ordering::Equal;
use std::cmp::Ordering::Greater;
use std::cmp::Ordering::Less;
use std::sync::OnceLock;

use reverie::Errno;
use reverie::Pid;
use reverie::RegDisplay;
use reverie::RegDisplayOptions;
use reverie::Signal;
use reverie::Tid;
#[cfg(target_arch = "x86_64")]
use reverie::syscalls::Addr;
#[cfg(target_arch = "x86_64")]
use reverie::syscalls::AddrMut;
#[cfg(target_arch = "x86_64")]
use reverie::syscalls::MemoryAccess;
use safeptrace::Error as TraceError;
use safeptrace::Event as TraceEvent;
#[cfg(target_arch = "x86_64")]
use safeptrace::Regs;
use safeptrace::Running;
use safeptrace::Stopped;
use safeptrace::Wait;
use thiserror::Error;
use tracing::debug;
use tracing::trace;
use tracing::warn;

use crate::perf::*;
use crate::tracer::PtracerWaitOwner;
use crate::tracer::WaitOnPtracer;

// This signal is unused, in that the kernel will never send it to a process.
const MARKER_SIGNAL: Signal = reverie::PERF_EVENT_SIGNAL;

/// We refuse to schedule a "perf timeout" for this or fewer RCBs, instead
/// choosing to directly single step. This is because I am somewhat paranoid
/// about perf event throttling, which isn't well-documented.
const SINGLESTEP_TIMEOUT_RCBS: u64 = 5;

/// The largest default skid margin of any processor in the PMU table
/// (`reverie::pmu::PmuProfile`, and 1000 on aarch64): that of the AMD Zen
/// processors without a measured 1K entry. A unit test checks it against the
/// whole table.
pub const LARGEST_TABLE_SKID_MARGIN: u64 = 10_000;

/// The single, greppable marker emitted to stderr whenever this backend detects
/// the RCB fallback overshooting its target. Re-exported from the
/// backend-agnostic `reverie` crate so that this precise single-step guard and
/// hermit's detcore log-and-continue path emit the *same* token — one marker,
/// one source. See [`reverie::SKID_OVERSHOOT_MARKER`] for the full contract and
/// the retry-harness safety property.
pub use reverie::SKID_OVERSHOOT_MARKER;

/// Fault-injection knob: when set to a parseable `u64`, this env var overrides
/// the processor-detected skid margin for the whole process. Setting it to `0`
/// programs the precise timer's overflow interrupt *at* the target RCB instead
/// of `skid_margin` RCBs early, so any natural positive skid pushes the fallback
/// single-step past the target and deterministically triggers the
/// [`SKID_OVERSHOOT_MARKER`] path. This exists to exercise the skid overshoot +
/// retry harness on demand; it is not a tuning knob for normal runs. A value
/// that does not parse as `u64` is ignored (processor default retained).
pub const SKID_MARGIN_OVERRIDE_ENV: &str = "REVERIE_SKID_MARGIN_OVERRIDE";

/// Supervisor-only witness nonce. When the consuming harness (the hermit
/// *supervisor*) sets this env var, its exact value is stamped into every
/// [`SKID_OVERSHOOT_MARKER`] line as a ` witness=<value>` field. A downstream
/// retry gate uses it to distinguish a genuine supervisor-emitted overshoot from
/// guest-printed marker text: hermit strips this var from the guest environment,
/// so the guest can neither read nor forge the value. Unset or empty leaves the
/// marker in its plain (unauthenticated) shape.
pub const WITNESS_TOKEN_ENV: &str = "HERMIT_SKID_WITNESS_TOKEN";

static PMU_CONFIG: OnceLock<PmuConfig> = OnceLock::new();

/// Overflow records forgotten because their notification had left the
/// thread's pending queue, for tests.
pub(crate) static OVERFLOW_RECORDS_EXPIRED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Timers created while this is set map no overflow records, as on a kernel
/// that is or may be `PREEMPT_RT`, for tests.
pub(crate) static OVERFLOW_RECORDS_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Precise events recorded as skid overshoots because a stop other than
/// their notification's decided them past their delivery point although the
/// notification was already queued for the thread, for tests. See
/// [`MissedTarget::notification_queued`].
pub(crate) static OVERTAKEN_WITH_NOTIFICATION_QUEUED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The target and the overtaking clock of the first events counted in
/// [`OVERTAKEN_WITH_NOTIFICATION_QUEUED`], at most
/// [`OVERTAKEN_WITH_NOTIFICATION_QUEUED_KEPT`] of them since the list was
/// last taken, for tests.
pub(crate) static OVERTAKEN_WITH_NOTIFICATION_QUEUED_EVENTS: std::sync::Mutex<Vec<(u64, u64)>> =
    std::sync::Mutex::new(Vec::new());

/// How many events [`OVERTAKEN_WITH_NOTIFICATION_QUEUED_EVENTS`] keeps.
const OVERTAKEN_WITH_NOTIFICATION_QUEUED_KEPT: usize = 1024;

/// Timer signals whose signal-delivery stop found their event cancelled, and
/// which were discarded there, for tests.
pub(crate) static CANCELLED_TIMER_SIGNALS_DISCARDED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Whether timers check, at each disregarded stop that keeps a scheduled
/// event, that the stop left the event's PMU programming as its request made
/// it (see [`TimerImpl::check_kept_programming`]), and check again at the
/// thread's next stop that nothing programmed the counter while the stop was
/// handled (see [`TimerImpl::recheck_kept_programming`]), for tests. Unit
/// tests of this crate always check.
pub(crate) static KEPT_PROGRAMMING_CHECKS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Disregarded stops at which a check (see [`KEPT_PROGRAMMING_CHECKS`])
/// found that the kept event's programming was the one its request made, or
/// not, for tests.
pub(crate) static KEPT_PROGRAMMINGS_CHECKED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Disregarded stops of [`KEPT_PROGRAMMINGS_CHECKED`] whose check found the
/// kept programming unchanged and that handed nothing on, whose programming
/// was checked again at the thread's next stop, or when the event was next
/// requested, cancelled or retired, or the thread exited, whichever came
/// first (see [`TimerImpl::recheck_kept_programming`]), for tests.
pub(crate) static KEPT_PROGRAMMINGS_RECHECKED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Disregarded stops of [`KEPT_PROGRAMMINGS_CHECKED`] that handed the kept
/// event on, as single steps or a lost notification for
/// [`Timer::continue_stepping`] to finish, or that failed, and so were not
/// checked again at the thread's next stop, which the finishing reaches by
/// programming the counter, for tests.
pub(crate) static KEPT_PROGRAMMINGS_HANDED_ON: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Checks of [`KEPT_PROGRAMMINGS_CHECKED`] and rechecks of
/// [`KEPT_PROGRAMMINGS_RECHECKED`] that found the kept event's counter
/// programmed since its request (see [`KeptProgramming::reprogrammed`]), or,
/// at the stop itself, overflowing at a clock other than the one its request
/// programmed, or not at all, for tests.
pub(crate) static KEPT_PROGRAMMINGS_CHANGED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The first checks counted in [`KEPT_PROGRAMMINGS_CHANGED`], at most
/// [`KEPT_PROGRAMMINGS_CHANGED_KEPT`] of them since the list was last taken,
/// for tests.
pub(crate) static KEPT_PROGRAMMINGS_CHANGED_EVENTS: std::sync::Mutex<Vec<KeptProgramming>> =
    std::sync::Mutex::new(Vec::new());

/// How many checks [`KEPT_PROGRAMMINGS_CHANGED_EVENTS`] keeps.
const KEPT_PROGRAMMINGS_CHANGED_KEPT: usize = 1024;

/// What a check of a kept event's programming found (see
/// `TimerImpl::check_kept_programming` and
/// `TimerImpl::recheck_kept_programming`). The programming is unchanged
/// only if `reprogrammed` is zero and, at the stop itself, `found` is
/// `armed`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct KeptProgramming {
    /// The event's target clock (for an imprecise event, its least clock).
    pub target: u64,
    /// The clock at which the event's request programmed its counter to
    /// overflow: the target less the skid margin, for a precise event.
    pub armed: u64,
    /// The clock at which the counter overflows after the stop, as inferred
    /// from its count and its last programmed period, or `None` if its
    /// programming has ended or cannot be read. A recheck at the next stop
    /// does not read it, and leaves it `None`.
    pub found: Option<u64>,
    /// The calls that changed the counter's programming (enable, disable,
    /// refresh, reset, period or signal delivery) made since the event's
    /// request programmed it. A period change re-arms the counter without
    /// moving its count, so `found` alone cannot show one.
    pub reprogrammed: u64,
    /// Whether this is the recheck at the thread's next stop, or at the
    /// event's next request, cancellation or retirement, or the thread's
    /// exit, rather than the check at the stop that kept the event.
    pub at_next_stop: bool,
}

impl KeptProgramming {
    /// Whether the check found the programming changed.
    pub fn changed(&self) -> bool {
        self.reprogrammed != 0 || (!self.at_next_stop && self.found != Some(self.armed))
    }
}

/// The programming a request made for a timer event (see
/// [`KEPT_PROGRAMMING_CHECKS`]).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ArmedProgramming {
    /// The clock at which `timer` overflows.
    overflow_point: u64,
    /// [`PerfCounter::programmings`] of `timer` once the request programmed
    /// it.
    programmings: u64,
}

/// Counts a check of a kept programming, and records it if it found the
/// programming changed.
fn count_kept_programming_check(check: KeptProgramming) {
    let counter = if check.at_next_stop {
        &KEPT_PROGRAMMINGS_RECHECKED
    } else {
        &KEPT_PROGRAMMINGS_CHECKED
    };
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if check.changed() {
        warn!(
            "The programming of a timer event that a disregarded stop kept was changed: \
             {check:?}"
        );
        KEPT_PROGRAMMINGS_CHANGED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut changed = KEPT_PROGRAMMINGS_CHANGED_EVENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if changed.len() < KEPT_PROGRAMMINGS_CHANGED_KEPT {
            changed.push(check);
        }
    }
}

/// Whether timers check kept programmings (see [`KEPT_PROGRAMMING_CHECKS`]).
fn kept_programming_checks() -> bool {
    cfg!(test) || KEPT_PROGRAMMING_CHECKS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Whether the running kernel may be built with `PREEMPT_RT`. A kernel whose
/// version cannot be read counts as one.
fn kernel_is_preempt_rt() -> bool {
    static PREEMPT_RT: OnceLock<bool> = OnceLock::new();
    *PREEMPT_RT.get_or_init(|| {
        let mut uts = core::mem::MaybeUninit::<libc::utsname>::zeroed();
        // SAFETY: `uts` is valid for writes, and on success the kernel
        // NUL-terminates `version`.
        let version = (unsafe { libc::uname(uts.as_mut_ptr()) } == 0).then(|| {
            unsafe { std::ffi::CStr::from_ptr(uts.assume_init_ref().version.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        });
        version.is_none_or(|version| version_is_preempt_rt(&version))
            || crate::launch_window::read_to_string("/sys/kernel/realtime")
                .is_ok_and(|value| value.trim() == "1")
    })
}

/// Whether a `uname` version string names a kernel that is or may be
/// `PREEMPT_RT`. Mainline adds the word `PREEMPT_RT` for `CONFIG_PREEMPT_RT`
/// (`init/Makefile`, `UTS_VERSION`), and `/sys/kernel/realtime` exists only in
/// some distributions' kernels. The version is cut to 64 bytes, after the
/// build version and flags, so a version of that length may have lost the
/// word and counts as `PREEMPT_RT`.
fn version_is_preempt_rt(version: &str) -> bool {
    const UTS_VERSION_MAX: usize = 64;
    version.len() >= UTS_VERSION_MAX || version.split_whitespace().any(|word| word == "PREEMPT_RT")
}

pub(crate) fn get_pmu_config() -> &'static PmuConfig {
    PMU_CONFIG.get_or_init(PmuConfig::new)
}

/// Processor-specific PMU event settings used by precise ptrace timers.
// TODO-HUMAN-REVIEW(PR-186): Review the programmatic PMU skid-margin override API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PmuConfig {
    rcb_event: u64,
    skid_margin: u64,
    skid_margin_override: Option<u64>,
}

impl PmuConfig {
    /// Attempts to configure the PMU without assuming that this CPU has a
    /// measured deterministic-timer profile.
    ///
    /// In-guest clocks can treat an unknown CPU as an unavailable optional
    /// capability. Precise ptrace timers retain [`Self::new`]'s fail-fast
    /// contract because they also require a measured skid margin.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn try_new() -> Option<Self> {
        let features = raw_cpuid::CpuId::new().get_feature_info()?;
        Self::try_from_family_model(features.family_id(), features.model_id())
            .map(Self::with_env_overrides)
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn try_new() -> Option<Self> {
        Some(Self::new())
    }

    /// Creates / initializes the PMU config.
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Self {
        let c = raw_cpuid::CpuId::new();
        let fi = c
            .get_feature_info()
            .expect("CPUID feature information is required to configure the PMU");
        Self::from_cpuid_features(fi).with_env_overrides()
    }

    /// Creates / initializes the PMU config.
    #[cfg(target_arch = "aarch64")]
    pub fn new() -> Self {
        // TODO:
        //  1. Compute the microarchitecture from
        //     `/sys/devices/system/cpu/cpu*/regs/identification/midr_el1`
        //  2. Look up the microarchitecture in a table to determine what features
        //     we can enable.
        // References:
        //  - https://github.com/rr-debugger/rr/blob/master/src/PerfCounters.cc#L156
        const BR_RETIRED: u64 = 0x21;

        // For now, always assume that we can get retired branch events.
        Self {
            rcb_event: BR_RETIRED,
            skid_margin: 1000,
            skid_margin_override: None,
        }
        .with_env_overrides()
    }

    #[cfg(target_arch = "x86_64")]
    fn from_cpuid_features(fi: raw_cpuid::FeatureInfo) -> Self {
        Self::from_family_model(fi.family_id(), fi.model_id())
    }

    #[cfg(target_arch = "x86_64")]
    fn from_family_model(family_id: u8, model_id: u8) -> Self {
        Self::try_from_family_model(family_id, model_id).unwrap_or_else(|| match family_id {
            0x06 => panic!("Unsupported Intel processor model: {:#x}", model_id),
            family => panic!(
                "Unsupported processor family, model: ({:#x},{:#x})",
                family, model_id
            ),
        })
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn try_from_family_model(family_id: u8, model_id: u8) -> Option<Self> {
        reverie::pmu::PmuProfile::for_family_model(family_id, model_id).map(|profile| Self {
            rcb_event: profile.raw_rcb_event(),
            skid_margin: profile.default_skid_margin(),
            skid_margin_override: None,
        })
    }

    /// Overrides the processor-specific skid margin while preserving the detected PMU event.
    pub fn with_skid_margin_override(mut self, skid_margin: u64) -> Self {
        self.skid_margin_override = Some(skid_margin);
        self
    }

    /// Applies the [`SKID_MARGIN_OVERRIDE_ENV`] fault-injection override, if the
    /// env var is present and parses as a `u64`. A missing var leaves the
    /// processor default untouched; a present-but-unparseable value is ignored
    /// with a warning rather than aborting startup. When the override is applied
    /// it is announced loudly on stderr, because it deliberately degrades timer
    /// precision to force the overshoot path.
    fn with_env_overrides(self) -> Self {
        match std::env::var(SKID_MARGIN_OVERRIDE_ENV) {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(v) => {
                    eprintln!(
                        "[reverie-ptrace] {}={} active: skid margin forced to {} RCBs \
                         (fault injection; not for production runs)",
                        SKID_MARGIN_OVERRIDE_ENV, raw, v
                    );
                    self.with_skid_margin_override(v)
                }
                Err(_) => {
                    eprintln!(
                        "[reverie-ptrace] ignoring {}={:?}: not a u64; using processor default",
                        SKID_MARGIN_OVERRIDE_ENV, raw
                    );
                    self
                }
            },
            Err(_) => self,
        }
    }

    /// This is the experimentally determined maximum number of RCBs an overflow
    /// interrupt is delivered after the originating RCB.
    ///
    /// If this number is too small, timer event delivery can pass its target and
    /// will be reported at the observed counter. If this number is too big, we
    /// degrade performance from excessive single stepping.
    pub fn skid_margin(&self) -> u64 {
        self.skid_margin_override.unwrap_or(self.skid_margin)
    }

    /// The maximum single step count we expect can occur when a precise timer
    /// event is requested that leaves less than the minimum perf timeout
    /// remaining.
    pub fn max_single_step_count(&self) -> u64 {
        self.skid_margin().saturating_add(SINGLESTEP_TIMEOUT_RCBS)
    }

    /// How many RCBs short of a precise event's target a stop that nothing
    /// continues must come to keep the event: a stop without a Tool callback
    /// across which the event cannot be continued (an rt_sigreturn LiteInst
    /// hook trap, or any such stop without overflow records) keeps the event
    /// only while the guest's clock is more than this short of the target,
    /// and cancels it otherwise.
    ///
    /// Short of the target by more than the processor's skid margin plus the
    /// single steps of an artificial notification
    /// ([`Self::max_single_step_count`]), the programming has not passed its
    /// period, and no notification can be pending, taken or lost. Closer, one
    /// of those holds as host interrupt timing decides. Using the largest
    /// margin of any processor in the PMU table,
    /// `LARGEST_TABLE_SKID_MARGIN`, instead of this processor's own gives a
    /// stop the same outcome on every supported processor, since each
    /// processor's own point lies at or after it. A skid margin override
    /// above the table's largest raises it, so that the point still comes
    /// before the period.
    pub fn keep_margin(&self) -> u64 {
        self.skid_margin()
            .max(LARGEST_TABLE_SKID_MARGIN)
            .saturating_add(SINGLESTEP_TIMEOUT_RCBS)
    }

    /// Emits the single canonical [`SKID_OVERSHOOT_MARKER`] line to stderr.
    ///
    /// This is called at every site that detects the RCB-fallback preemption
    /// landing past its programmed target, so the overshoot signal has exactly
    /// one greppable shape regardless of which layer noticed it. It reports the
    /// counter value actually observed, the intended target, the skid margin in
    /// effect (the CPU-specific constant whose tuning determines how often this
    /// fires), and the resulting overshoot.
    pub fn emit_skid_overshoot_marker(&self, rcb_actual: u64, rcb_target: u64) {
        eprintln!(
            "{}",
            self.format_skid_overshoot_marker(rcb_actual, rcb_target)
        );
    }

    /// Single decision-and-record site for a skid overshoot: iff the interrupt
    /// was delivered *past* the programmed target (`rcb_actual > rcb_target`),
    /// emit the canonical [`SKID_OVERSHOOT_MARKER`] line **and** increment the
    /// process-global witness counter via [`reverie::record_skid_overshoot`],
    /// then return `true`. A non-overshoot (`rcb_actual <= rcb_target`) records
    /// nothing and returns `false`.
    ///
    /// `TimerImpl::attempt_single_step`'s late-delivery guard is the sole runtime
    /// caller, so a unit test that drives real `(actual, target)` pairs through
    /// this method exercises exactly the behaviour the supervisor runs — a
    /// genuine overshoot causes exactly one witness record — without needing a
    /// live guest or PMU. The boolean return is what makes that behaviour
    /// (not merely the marker arithmetic) observable in a test.
    pub fn record_overshoot_if_past_target(&self, rcb_actual: u64, rcb_target: u64) -> bool {
        if rcb_actual > rcb_target {
            self.emit_skid_overshoot_marker(rcb_actual, rcb_target);
            // Structural, in-process signal (a guest cannot forge it) so an
            // in-process classifier can causally attribute a divergence to skid.
            reverie::record_skid_overshoot();
            true
        } else {
            false
        }
    }

    /// Single decision-and-record site for a precise event that another
    /// Tool-observable stop overtook: iff the guest had already reached the
    /// event's delivery point, emit the canonical [`SKID_OVERSHOOT_MARKER`]
    /// line, increment the process-global witness counter, and return `true`.
    ///
    /// Unlike a late delivery, the event itself is lost here, so reaching the
    /// delivery point exactly already counts: the event was due before the
    /// stop. With an instruction offset the delivery point lies `instr_offset`
    /// instructions past the target branch, and those instructions may include
    /// further branches (see `ClockCounter::single_step_with_clock`). The
    /// counter alone cannot show instruction progress, but every branch past
    /// the target is at least one instruction, so `rcb_actual - rcb_target >=
    /// instr_offset` proves the guest got there. A stop with fewer branches
    /// past the target is not recorded, even if the delivery point was in fact
    /// reached. `TimerImpl::commit_missed`, for a stop that retires the event,
    /// is the sole runtime caller.
    pub fn record_missed_if_target_reached(
        &self,
        rcb_actual: u64,
        rcb_target: u64,
        instr_offset: u64,
    ) -> bool {
        let reached = target_reached(rcb_actual, rcb_target, instr_offset);
        if reached {
            self.emit_skid_overshoot_marker(rcb_actual, rcb_target);
            reverie::record_skid_overshoot();
        }
        reached
    }

    /// Formats the canonical [`SKID_OVERSHOOT_MARKER`] line. Split out from
    /// [`Self::emit_skid_overshoot_marker`] so the exact shape is unit-testable
    /// without capturing process stderr.
    pub fn format_skid_overshoot_marker(&self, rcb_actual: u64, rcb_target: u64) -> String {
        let overshoot = rcb_actual.saturating_sub(rcb_target);
        let mut line = format!(
            "{} rcb_actual={} rcb_target={} skid_margin={} overshoot={}",
            SKID_OVERSHOOT_MARKER,
            rcb_actual,
            rcb_target,
            self.skid_margin(),
            overshoot,
        );
        // Supervisor-only witness nonce (see [`WITNESS_TOKEN_ENV`]): stamps the
        // marker so a downstream retry gate can authenticate it as genuinely
        // supervisor-emitted rather than guest-printed. Read from the env at emit
        // time; the emit path is rare, so the lookup cost is irrelevant.
        if let Ok(token) = std::env::var(WITNESS_TOKEN_ENV)
            && !token.is_empty()
        {
            line.push_str(" witness=");
            line.push_str(&token);
        }
        line
    }

    /// The event needed to configure the PMU and observe RCBs.
    pub fn rcb_event(&self) -> Event {
        Event::Raw(self.rcb_event)
    }

    /// Returns the raw perf event selector for retired conditional branches.
    pub fn raw_rcb_event(&self) -> u64 {
        self.rcb_event
    }
}

impl Default for PmuConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Installs the PMU configuration used by subsequently created ptrace timers.
///
/// Returns the supplied configuration if a timer has already initialized the process-wide
/// configuration. Callers should install overrides before spawning a [`crate::Tracer`].
pub fn set_pmu_config(config: PmuConfig) -> Result<(), PmuConfig> {
    PMU_CONFIG.set(config)
}

/// Whether a stop at `rcb_actual` has reached the delivery point of a precise
/// event `instr_offset` instructions past `rcb_target`, as far as the counter
/// can show. See [`PmuConfig::record_missed_if_target_reached`].
fn target_reached(rcb_actual: u64, rcb_target: u64, instr_offset: u64) -> bool {
    rcb_actual
        .checked_sub(rcb_target)
        .is_some_and(|past| past >= instr_offset)
}

/// Returns true if the current CPU supports precise_ip.
#[cfg(target_arch = "x86_64")]
pub(crate) fn has_precise_ip() -> bool {
    let cpu = raw_cpuid::CpuId::new();
    let feature_info = cpu.get_feature_info();
    let has_debug_store = feature_info.as_ref().is_some_and(|info| info.has_ds());

    // Identify the CPU by vendor and model only. Debug-printing the whole
    // `CpuId` (or a whole `FeatureInfo`) also dumps per-core topology --
    // `initial_local_apic_id`, `x2apic_id`, `core_id` -- which reflects
    // whichever core this thread happens to be scheduled on, not any property
    // of the machine. That made this line differ between otherwise identical
    // runs even though the decision below is a pure function of `has_ds()`.
    debug!(
        "Setting precise_ip to {} for cpu vendor {} family {:?} model {:?} stepping {:?}",
        has_debug_store,
        cpu.get_vendor_info()
            .map_or_else(|| "unknown".to_string(), |v| v.as_str().to_string()),
        feature_info.as_ref().map(|i| i.family_id()),
        feature_info.as_ref().map(|i| i.model_id()),
        feature_info.as_ref().map(|i| i.stepping_id()),
    );

    has_debug_store
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn has_precise_ip() -> bool {
    // Assume, for now, that aarch64 can use precise_ip.
    true
}

/// A timer monitoring a single thread. The underlying implementation is eagerly
/// initialized, but left empty if perf is not supported. In that case, any
/// methods with semantics that require a functioning clock or timer will panic.
#[derive(Debug)]
pub struct Timer {
    inner: Option<TimerImpl>,
}

/// Data requires to request a timer event
#[derive(Debug, Copy, Clone)]
pub enum TimerEventRequest {
    /// Event should fire after precisely this many RCBs.
    Precise(u64),

    /// Event should fire after at least this many RCBs.
    Imprecise(u64),

    /// Event should fire after precisely this many RCBS and this many instructions
    PreciseInstruction(u64, u64),
}

/// The possible results of handling a timer signal.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum HandleFailure {
    #[error(transparent)]
    TraceError(#[from] TraceError),

    #[error("Unexpected event while single stepping")]
    Event(Wait),

    /// A single step ended at a seccomp stop: the stepped instruction entered
    /// a traced syscall. The caller classifies it (trap-only refuses a patched
    /// site carrying an allowed number, P2 spec O4 rule 4) and otherwise
    /// dispatches it like [`HandleFailure::Event`].
    #[error("Single step ended at a seccomp stop")]
    SeccompStop(Stopped),

    /// The timer signal was for a timer event that was otherwise cancelled. The
    /// task is returned unchanged.
    #[error("Timer event was cancelled and should not fire")]
    Cancelled(Stopped),

    /// The signal causing the signal-delivery stop was not actually meant for
    /// this timer. The task is returned unchanged.
    #[error("Pending signal was not for this timer")]
    ImproperSignal(Stopped),
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecTimerIdentity {
    pub clock_fd: i32,
    pub timer_fd: i32,
    pub clock_event_id: u64,
    pub timer_event_id: u64,
    pub artificial_pending: bool,
    pub artificial_signal_sent: bool,
    pub cancelled: bool,
    pub guest_pid: Pid,
    pub guest_tid: Tid,
    pub kernel_owner_tid: Tid,
}

impl Timer {
    /// Create a new timer monitoring the specified thread.
    pub fn new(guest_pid: Pid, guest_tid: Tid) -> Self {
        Self::with_initial_command(guest_pid, guest_tid, false)
    }

    pub(crate) fn for_initial_command(guest_pid: Pid, guest_tid: Tid) -> Self {
        Self::with_initial_command(guest_pid, guest_tid, true)
    }

    fn with_initial_command(guest_pid: Pid, guest_tid: Tid, initial_command: bool) -> Self {
        // No errors are exposed here, as the construction should be
        // bullet-proof, and if it wasn't, consumers wouldn't be able to
        // meaningfully handle the error anyway.
        Self {
            inner: if is_perf_supported() {
                Some(
                    TimerImpl::new(guest_pid, guest_tid, initial_command).unwrap_or_else(|err| {
                        panic!(
                            "failed to initialize perf timer for tracee {guest_tid} \
                         in process {guest_pid}: {err}"
                        )
                    }),
                )
            } else {
                None
            },
        }
    }

    fn inner(&self) -> &TimerImpl {
        self.inner.as_ref().expect("Perf support required")
    }

    fn inner_noinit(&self) -> Option<&TimerImpl> {
        self.inner.as_ref()
    }

    fn inner_mut_noinit(&mut self) -> Option<&mut TimerImpl> {
        self.inner.as_mut()
    }

    /// Both ordinary and injected initial exec stops use this transition.
    /// The kernel has already started the clock, but notifications remain held
    /// through the backend's existing post-exec initialization.
    pub(crate) fn begin_initial_exec(&mut self) {
        if let Some(timer) = self.inner_mut_noinit() {
            timer.begin_initial_exec();
        }
    }

    /// Release the notification hold before the first Tool post-exec callback.
    /// No pre-exec request is replayed or physically armed here.
    pub(crate) fn finish_initial_exec(&mut self) {
        if let Some(timer) = self.inner_mut_noinit() {
            timer.finish_initial_exec();
        }
    }

    /// Read the thread-local deterministic clock. Represents total elapsed RCBs
    /// on this thread since the timer was constructed, which should be at or
    /// near thread creation time.
    pub fn read_clock(&self) -> u64 {
        self.inner().read_clock()
    }

    /// Approximately convert a duration to the internal notion of timer ticks.
    pub fn as_ticks(dur: core::time::Duration) -> u64 {
        // assumptions: 10% conditional branches, 3 GHz, avg 2 IPC
        // this gives: 0.6B branch / sec = 0.6 branch / ns
        (dur.as_secs() * 600_000_000) + (u64::from(dur.subsec_nanos()) * 6 / 10)
    }

    /// Whether `signal` is an unconsumed overflow notification of this timer's
    /// counter, and if so, record that it has been consumed.
    ///
    /// Such a signal belongs to Reverie and is never guest-visible. An overflow
    /// interrupt can arrive after the guest has reached its next event, which
    /// cancels the timer event, so this can match at stops where the timer
    /// has nothing left to deliver. Artificial timer signals carry no overflow
    /// siginfo and do not match.
    ///
    /// Matching siginfo alone does not prove provenance: a guest file with
    /// `F_SETSIG` set to the timer signal reports its own descriptor number,
    /// which can equal the timer's. The kernel must also have recorded an
    /// overflow whose notification has not been consumed. A counter that
    /// passed its period is not enough, because the overflow interrupt can be
    /// lost. Without overflow records nothing matches. A match while the
    /// current programming has passed its period disables the counter, which
    /// only prevents notifications of a timer event that has already been
    /// cancelled.
    ///
    /// A notification of an event that no stop has decided yet, which
    /// [`Timer::take_overflow_signal`] takes, does not match.
    pub(crate) fn consume_overflow_signal(
        &mut self,
        signal: &libc::siginfo_t,
    ) -> Result<bool, Errno> {
        match self.inner_mut_noinit() {
            Some(timer) => timer.consume_overflow_signal(signal),
            None => Ok(false),
        }
    }

    /// Takes this thread's own overflow notification `signal` at a stop inside
    /// an injected syscall, which must never reach the guest.
    ///
    /// A notification of the active event is live if no stop has decided the
    /// event: it is still scheduled because the stop that led to the injection
    /// was disregarded (see [`Timer::disregard_stop`]), and the current
    /// programming has passed its period with an overflow the kernel recorded.
    /// Such a notification is recorded as taken, without ending the
    /// programming, and [`Timer::take_notification`] then hands the event on
    /// to be delivered. Any other notification this timer owns is late, and is
    /// consumed as by [`Timer::consume_overflow_signal`]. Returns `None` for a
    /// signal that is not this timer's notification, including every signal
    /// when no overflow records are mapped.
    pub(crate) fn take_overflow_signal(
        &mut self,
        signal: &libc::siginfo_t,
    ) -> Result<Option<OwnNotification>, Errno> {
        match self.inner_mut_noinit() {
            Some(timer) => timer.take_overflow_signal(signal),
            None => Ok(None),
        }
    }

    /// Hands on the active event whose live notification
    /// [`Timer::take_overflow_signal`] took, to be finished with
    /// [`Timer::continue_stepping`] before the guest is resumed.
    pub(crate) fn take_notification(&mut self) -> Option<Unfinished> {
        self.inner_mut_noinit()
            .and_then(|timer| timer.take_notification())
    }

    /// Cancels the active event, and ends the programming, where what
    /// [`Timer::disregard_stop`] or [`Timer::take_notification`] handed on
    /// cannot be finished, or where a stop that the Tool does not see must
    /// end the event whatever was handed on (a hook trap whose injected
    /// syscall held a guest signal for the resume). A precise event that no stop has decided yet, and
    /// whose delivery point the guest has reached, is recorded as a skid
    /// overshoot, as a stop that cancels it is. An event already delivered,
    /// or already decided by a stop, is not recorded again, whatever the
    /// guest's clock.
    pub(crate) fn retire(&mut self) -> Result<(), Errno> {
        match self.inner_mut_noinit() {
            Some(timer) => timer.retire(),
            None => Ok(()),
        }
    }

    /// Ends the handling of the latest observed stop. If it was not
    /// disregarded, it decided the active event, and the event is recorded as
    /// a skid overshoot if the stop cancelled it past its delivery point.
    pub(crate) fn settle_stop(&mut self) {
        if let Some(timer) = self.inner_mut_noinit() {
            timer.settle_stop();
        }
    }

    /// Ends the handling of a thread that has exited. Settles the latest
    /// observed stop (see [`Timer::settle_stop`]). If the latest stop was
    /// disregarded (see [`Timer::disregard_stop`]) and found the precise
    /// event's delivery point reached, and nothing has decided the event
    /// since, the event ends with the thread and is recorded as a skid
    /// overshoot. So is a precise event that no stop has decided at all, if
    /// the guest reached its delivery point before it exited.
    pub(crate) fn settle_at_exit(&mut self) {
        if let Some(timer) = self.inner_mut_noinit() {
            timer.settle_at_exit();
        }
    }

    /// Forget recorded overflows whose notification the kernel no longer
    /// holds for the stopped thread `task`. Called at each stop and before
    /// each injected syscall.
    ///
    /// A notification can leave the thread's pending queue without a stop
    /// that consumes it: the guest can dequeue it with `sigtimedwait` or a
    /// signalfd, flush it by ignoring the signal, or receive it where a guest
    /// signal was expected. Its records would then authorize discarding a
    /// later guest signal with the same siginfo. Nothing is read unless
    /// records are unconsumed.
    ///
    /// The whole queue is read: real-time signals queue one entry each, so the
    /// notification can sit behind any number of them. If the queue cannot be
    /// read, the records are kept. For a stopped thread that happens only when
    /// the thread has died, and then no discard follows.
    pub(crate) fn expire_overflow_records(&mut self, task: &Stopped) {
        if let Some(timer) = self.inner_mut_noinit()
            && timer.has_overflow_records()
        {
            // The notification is sent to the thread, not the process.
            match task.peeksiginfo_all(None) {
                Ok(pending) => timer.expire_overflow_records(&pending),
                Err(err) => debug!("Could not read pending signals of {}: {err}", task.pid()),
            }
        }
    }

    /// Return the signal type sent by the timer. This is intended to allow
    /// pre-filtering signals without the full overhead of gathering signal info
    /// to pass to ['Timer::generated_signal`].
    pub fn signal_type() -> Signal {
        MARKER_SIGNAL
    }

    /// Request a timer event to occur in the future at a time specified by
    /// `evt`.
    ///
    /// This is *not* idempotent and will replace the outstanding request. If it
    /// is called repeatedly no events will be delivered.
    pub fn request_event(&mut self, evt: TimerEventRequest) -> Result<(), Errno> {
        self.inner_mut_noinit()
            .ok_or(Errno::ENODEV)?
            .request_event(evt)
    }

    /// Must be called whenever a Tool-observable reverie event occurs, with the
    /// ptrace event of that stop. This ensures proper cancellation semantics
    /// are observed. See the internal `timer::EventStatus` type for details.
    /// A precise event whose delivery point the guest already reached is
    /// recorded as a skid overshoot when this stop cancels it: when the stop
    /// is settled (see [`Timer::settle_stop`]), a request or finalization
    /// follows it, or the next stop is observed. A stop passed to
    /// [`Timer::disregard_stop`] that hands the event back records nothing
    /// unless the thread exits before anything decides the event (see
    /// [`Timer::settle_at_exit`]); one that cancels the event instead records
    /// it at once, as does [`Timer::retire`].
    pub fn observe_event(&mut self, event: &TraceEvent) {
        if let Some(t) = self.inner_mut_noinit() {
            t.observe_event(event);
        }
    }

    /// Undoes what the latest [`Timer::observe_event`] did to the active
    /// event, for a stop that turns out to be one the Tool does not observe,
    /// such as a trap that Reverie consumes without a Tool callback. Such a
    /// stop neither cancels the event nor ends its single steps.
    ///
    /// Returns what of the event no timer signal is left to drive: the single
    /// steps toward it that the stop interrupted, or the whole event if the
    /// stop found that the kernel lost its PMU notification. It must be
    /// finished with [`Timer::continue_stepping`] before the guest is resumed,
    /// or cancelled with [`Timer::retire`]. Returns `None` if there is nothing
    /// to finish, or if the event has been requested or cancelled since the
    /// stop was observed.
    ///
    /// Without overflow records a lost notification cannot be told from a
    /// pending one, so a stop within [`PmuConfig::keep_margin`] of a precise
    /// event's target, which includes every stop at which the programming has
    /// passed its period and every stop during the single steps, cancels the
    /// event as any stop does, and returns `None`.
    ///
    /// A stop that keeps a scheduled event leaves its PMU programming as the
    /// request made it, so that the notification still comes a skid margin
    /// before the target. Once a test has called
    /// [`crate::testing::check_kept_timer_programming`], and always in this
    /// crate's unit tests, each such stop checks and counts that (see
    /// [`TimerImpl::check_kept_programming`]), and, if it hands nothing on,
    /// the thread's next stop checks and counts that nothing programmed the
    /// counter in between (see [`TimerImpl::recheck_kept_programming`]).
    pub(crate) fn disregard_stop(&mut self) -> Result<Option<Unfinished>, Errno> {
        match self.inner_mut_noinit() {
            Some(timer) => {
                let unfinished = timer.disregard_stop();
                timer.check_kept_programming(matches!(unfinished, Ok(None)));
                unfinished
            }
            None => Ok(None),
        }
    }

    /// Disregards the latest observed stop, as [`Timer::disregard_stop`]
    /// does, where nothing that it hands on can be finished, and keeps the
    /// active precise event only if the guest's clock at the stop is more
    /// than [`PmuConfig::keep_margin`] short of its target. Otherwise the
    /// event is cancelled (see [`Timer::retire`]). An imprecise event is kept
    /// only if its programming has not passed its period, which is its
    /// target.
    ///
    /// Past the period the notification may already be pending, may have
    /// been taken as single steps began, or may have been lost, and which of
    /// these holds at the stop is decided by host timing. The period is the
    /// target less this processor's skid margin, so it too depends on the
    /// host. The keep margin is the same on every supported processor and
    /// places the decision at or before every processor's period, so the
    /// guest's clock alone gives the stop its outcome. A kept event's
    /// programming is checked as [`Timer::disregard_stop`] describes.
    pub(crate) fn disregard_stop_before_period(&mut self) -> Result<(), Errno> {
        match self.inner_mut_noinit() {
            Some(timer) => {
                let result = timer.disregard_stop_before_period();
                timer.check_kept_programming(result.is_ok());
                result
            }
            None => Ok(()),
        }
    }

    /// Cancel pending timer notifications. This is idempotent.
    ///
    /// If there was a previous call to [`Timer::enable_interval'], this
    /// will prevent the delivery of that notification. This also has the effect
    /// of reseting the "elapsed ticks." That is, if the current notification
    /// duration is `N` ticks, then a full `N` ticks must elapse after the next
    /// call to [`enable_interval`](Timer::enable_interval) before a
    /// notification is delivered.
    ///
    /// While [`Timer::cancel`] actually disables the counting of RCBs, this
    /// method simply sets a flag to subsequent delivered signals until
    /// [`Timer::request_event`] is called again. Thus, this method is lighter
    /// if called multiple times, but still results in a signal delivery, while
    /// [`Timer::cancel`] must perform a syscall, but will actually cancel the
    /// signal.
    #[allow(dead_code)]
    pub fn schedule_cancellation(&mut self) {
        if let Some(t) = self.inner_mut_noinit() {
            t.schedule_cancellation();
        }
    }

    /// Cancel pending timer notifications. This is idempotent.
    ///
    /// If there was a previous call to [`Timer::enable_interval'], this
    /// will prevent the delivery of that notification. This also has the effect
    /// of reseting the "elapsed ticks." That is, if the current notification
    /// duration is `N` ticks, then a full `N` ticks must elapse after the next
    /// call to [`enable_interval`](Timer::enable_interval) before a
    /// notification is delivered.
    ///
    /// See [`Timer::schedule_cancellation`] for a comparison with this
    /// method.
    #[allow(dead_code)]
    pub fn cancel(&self) -> Result<(), Errno> {
        self.inner_noinit().map(|t| t.cancel()).unwrap_or(Ok(()))
    }

    /// Consume both counters after failed-run physical cleanup has settled.
    /// The caller publishes the failure and cancels notifications before that
    /// cleanup. This only releases resources; it never finalizes a request,
    /// re-arms a counter, or sends an artificial timer signal. Taking the inner
    /// owner also makes repeated terminal closure a no-op, including on error.
    pub(crate) fn close_after_failure(&mut self) -> Vec<(&'static str, Errno)> {
        let Some(timer) = self.inner.take() else {
            return Vec::new();
        };
        let mut errors = timer
            .clock
            .close_after_failure("ptrace clock munmap", "ptrace clock close");
        errors.extend(
            timer
                .timer
                .close_after_failure("ptrace timer munmap", "ptrace timer close"),
        );
        errors
    }

    #[cfg(test)]
    pub(crate) fn exec_test_identity(&self) -> Result<Option<ExecTimerIdentity>, Errno> {
        self.inner
            .as_ref()
            .map(|timer| {
                Ok(ExecTimerIdentity {
                    clock_fd: timer.clock.exec_test_fd(),
                    timer_fd: timer.timer.exec_test_fd(),
                    clock_event_id: timer.clock.id()?,
                    timer_event_id: timer.timer.id()?,
                    artificial_pending: timer.send_artificial_signal,
                    artificial_signal_sent: timer.artificial_signal_sent,
                    cancelled: timer.timer_status == EventStatus::Cancelled,
                    guest_pid: timer.guest_pid,
                    guest_tid: timer.guest_tid,
                    kernel_owner_tid: timer.timer.exec_test_signal_owner()?,
                })
            })
            .transpose()
    }

    /// Retarget the surviving thread's counters at an observed nonleader exec.
    /// The caller owns the actual replacement Exec stop and has transferred
    /// these counters with that former thread's state. This never reopens a
    /// counter against a numeric PID, resets its clock, or finalizes requests.
    pub(crate) fn retarget_after_exec(&mut self, pid: Pid, tid: Tid) -> Vec<(&'static str, Errno)> {
        let Some(timer) = self.inner.as_mut() else {
            return Vec::new();
        };
        let mut errors = Vec::new();
        // Disabling/retargeting cannot drain a previously queued perf signal.
        // Retire the old logical request as well. Existing signal handling
        // rejects cancelled or premature notifications before Tool delivery.
        timer.schedule_cancellation();
        timer.send_artificial_signal = false;
        if let Err(error) = timer.cancel() {
            errors.push(("ptrace exec timer cancellation", error));
        }
        // perf's task attachment survives exec, while F_OWNER_TID and the
        // artificial tgkill target still name the former numeric TID.
        if let Err(error) = timer.timer.set_signal_delivery(tid, MARKER_SIGNAL) {
            errors.push(("ptrace exec timer signal owner", error));
        }
        timer.guest_pid = pid;
        timer.guest_tid = tid;
        errors
    }

    /// Perform finalization actions on requests for timer events before guest
    /// resumption. See the module-level documentation for rules about when this can and
    /// should be called.
    ///
    /// Currently, this will, if necessary, `tgkill` a timer signal to the guest
    /// thread.
    pub fn finalize_requests(&mut self) {
        if let Some(t) = self.inner_mut_noinit() {
            t.finalize_requests();
        }
    }

    /// When a signal is received, this method drives the timer event to
    /// completion via single stepping, after checking that the signal was meant
    /// for this specific timer. This *must* be called when a timer signal is
    /// received for correctness.
    ///
    /// Preconditions: task is in signal-delivery-stop.
    /// Postconditions: if a signal meant for this timer was the cause of the
    /// stop, the tracee will be at the precise instruction the timer event
    /// should fire at, unless signal delivery was already past the target. In
    /// that case the overshoot is recorded and the event fires at the observed
    /// counter.
    /// Drives a timer signal using caller-owned stopped-state transitions.
    ///
    /// LiteInst uses this hook to keep its exact-generation root-stop lease
    /// synchronized across the precise timer's internal single steps. The
    /// non-LiteInst caller supplies the historical raw transition.
    pub(crate) async fn handle_signal(
        &mut self,
        task: Stopped,
        step: &mut (dyn FnMut(Stopped) -> Result<Running, TraceError> + Send),
        observe: &mut (dyn FnMut(&Wait) -> Result<(), TraceError> + Send),
        waits: &std::sync::Arc<PtracerWaitOwner>,
    ) -> Result<Stopped, HandleFailure> {
        match self.inner_mut_noinit() {
            Some(t) => t.handle_signal(task, step, observe, waits).await,
            None => {
                warn!("Stray SIGSTKFLT indicates a bug!");
                Err(HandleFailure::ImproperSignal(task))
            }
        }
    }

    /// Finishes what of the active event a disregarded stop left unfinished,
    /// as [`Timer::handle_signal`] would have finished it. The task is in the
    /// disregarded stop, and the result is as for [`Timer::handle_signal`].
    pub(crate) async fn continue_stepping(
        &mut self,
        task: Stopped,
        unfinished: Unfinished,
        step: &mut (dyn FnMut(Stopped) -> Result<Running, TraceError> + Send),
        observe: &mut (dyn FnMut(&Wait) -> Result<(), TraceError> + Send),
        waits: &std::sync::Arc<PtracerWaitOwner>,
    ) -> Result<Stopped, HandleFailure> {
        match self.inner_mut_noinit() {
            Some(t) => {
                t.continue_stepping(task, unfinished, step, observe, waits)
                    .await
            }
            // Only an initialized timer leaves anything unfinished.
            None => Err(HandleFailure::ImproperSignal(task)),
        }
    }
}

// Raw observations from the actual delivered marker signal, for finite exec
// controls. This neither consumes a wait status nor changes classification.
#[cfg(test)]
type ExecSignalObservation = (i32, i32, i32, i32, u64, bool, bool);
#[cfg(test)]
type ExecSignalObservations = std::sync::Arc<std::sync::Mutex<Vec<ExecSignalObservation>>>;
#[cfg(test)]
type ControllerQueryHook = Box<dyn FnOnce(&Stopped)>;
#[cfg(test)]
type ControllerQueryLog = std::sync::Arc<std::sync::Mutex<Vec<String>>>;
#[cfg(test)]
thread_local! {
    pub(crate) static EXEC_SIGNAL_OBSERVATIONS: std::cell::RefCell<Option<ExecSignalObservations>> = const { std::cell::RefCell::new(None) };
    pub(crate) static CONTROLLER_NAMESPACE_PATH: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
    pub(crate) static CONTROLLER_QUERY_EDGE: std::cell::RefCell<Option<ControllerQueryHook>> = const { std::cell::RefCell::new(None) };
    pub(crate) static CONTROLLER_QUERY_LOG: std::cell::RefCell<Option<ControllerQueryLog>> = const { std::cell::RefCell::new(None) };
    static HOST_TIMED_TIMER_EVENTS: std::cell::Cell<HostTimedTimerEvents> = const {
        std::cell::Cell::new(HostTimedTimerEvents {
            overshoot: 0,
            unstepped_at_target: 0,
            preempted_overflow: 0,
        })
    };
}

/// Precise-timer outcomes whose place in the guest depends on when the host
/// delivered the perf overflow signal, not on the guest, counted on the
/// thread that runs the tracer. A test that compares independent runs can
/// tell such a run from a divergence the guest or a backend caused.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct HostTimedTimerEvents {
    /// The signal was handled past the target, which also prints
    /// [`SKID_OVERSHOOT_MARKER`]: the event fires at the observed counter.
    pub overshoot: u64,
    /// The signal was handled exactly at the target count with no
    /// instruction offset, so no single-step placed the event: it fires
    /// wherever the guest was stopped between the target branch and the next
    /// one.
    pub unstepped_at_target: u64,
    /// A stop other than the timer's own signal stop ended the timer's one
    /// allowed stop after the counter had passed the programmed overflow, and
    /// that overflow's signal was not handled first. The stop cancels a timer
    /// that an earlier delivery would have fired, or that would have been
    /// stepped onto the stop.
    pub preempted_overflow: u64,
}

#[cfg(test)]
impl HostTimedTimerEvents {
    /// The number of host-timed outcomes of every kind.
    pub fn total(&self) -> u64 {
        self.overshoot + self.unstepped_at_target + self.preempted_overflow
    }
}

/// Takes, and resets to zero, the host-timed timer outcomes counted on this
/// thread.
#[cfg(test)]
pub(crate) fn take_host_timed_timer_events() -> HostTimedTimerEvents {
    HOST_TIMED_TIMER_EVENTS.with(|events| events.take())
}

#[cfg(test)]
fn count_host_timed(update: impl FnOnce(&mut HostTimedTimerEvents)) {
    HOST_TIMED_TIMER_EVENTS.with(|cell| {
        let mut events = cell.get();
        update(&mut events);
        cell.set(events);
    });
}

/// The lazy-initialized part of a `Timer` that holds the functionality.
#[derive(Debug)]
struct TimerImpl {
    /// A non-resetting counter functioning as a thread-local clock.
    clock: PerfCounter,

    /// A separate counter used to generate signals for timer events
    timer: PerfCounter,

    /// Information about the active timer event, including expected counter
    /// values.
    event: ActiveEvent,

    /// The cancellation status of the active timer event.
    timer_status: EventStatus,

    /// Whether or not the active timer event requires an artificial signal
    send_artificial_signal: bool,

    /// A successful controller tgkill has not yet been consumed at a signal
    /// stop. Standard signals coalesce, so this is ownership of a possible
    /// queued signal, not a count. Logical cancellation, disable and exec do
    /// not flush kernel queues and must not clear this record.
    artificial_signal_sent: bool,

    /// The sample period `timer` was last programmed with after a reset,
    /// while that programming may still be enabled. A count at or beyond it
    /// shows that the programming has passed its period, not that an
    /// overflow notification exists.
    overflow_period: Option<u64>,

    /// Whether the kernel has recorded an overflow whose notification has not
    /// been consumed. Records survive reprogramming.
    overflow_recorded: bool,

    /// Whether the kernel has recorded an overflow since `timer` was last
    /// programmed. Consuming notifications does not clear it.
    programming_overflowed: bool,

    initial_command: InitialCommand,

    /// Requests made before the first post-exec callback have no physical
    /// notification. Taking this record retires each request once.
    held_initial_event: Option<ActiveEvent>,

    /// The single steps toward the active event that a stop other than a
    /// step's report has interrupted, until that stop is observed.
    interrupted: Option<Interruption>,

    /// What observing the latest stop did to the active event, until the stop
    /// is disregarded or settled, or the event is requested or cancelled.
    observed: Option<ObservedStop>,

    /// A live notification of the active event has been taken at an injected
    /// syscall, and the event has not yet been handed on to be delivered.
    notification_taken: bool,

    /// The delivery point of the active event that the latest disregarded
    /// stop found already reached. No stop has decided the event since, so
    /// the thread's exit records it (see [`TimerImpl::settle_at_exit`]).
    disregarded_missed: Option<MissedTarget>,

    /// The programming the active event's request made, if it programmed a
    /// notification while kept programmings are checked (see
    /// [`KEPT_PROGRAMMING_CHECKS`]).
    armed_programming: Option<ArmedProgramming>,

    /// The programming, as in `armed_programming`, of the event that the
    /// latest disregarded stop kept, until
    /// [`TimerImpl::check_kept_programming`] checks it.
    kept_programming: Option<ArmedProgramming>,

    /// The programming, as in `armed_programming`, of the event that a
    /// disregarded stop kept and found unchanged, until
    /// [`TimerImpl::recheck_kept_programming`] checks it again at the
    /// thread's next stop.
    resumed_programming: Option<ArmedProgramming>,

    /// Every check of a kept event's programming this timer made.
    #[cfg(test)]
    kept_programming_log: Vec<KeptProgramming>,

    #[cfg(test)]
    fail_next_notification: Option<Errno>,

    /// This request's one allowed stop was counted as a
    /// [`HostTimedTimerEvents::preempted_overflow`] before its signal
    /// stop could be told apart from another stop; handling the signal takes
    /// the count back.
    #[cfg(test)]
    preempted_overflow_counted: bool,

    /// Pid (tgid) of the monitored thread
    guest_pid: Pid,

    /// Tid of the monitored thread
    guest_tid: Tid,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum InitialCommand {
    WaitingForExec,
    InitializingExec,
    Ordinary,
}

/// Tracks cancellation status of a timer event in response to other reverie
/// events.
///
/// Whenever a reverie event occurs, this should tick "forward" once. If the
/// timer signal is first to occur, then the cancellation will be pending, and
/// the event will fire. If instead some other event occured, the tick will
/// result in `Cancelled` and the event will not fire.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum EventStatus {
    Scheduled,
    Armed,
    Cancelled,
}

/// How far the single steps toward a precise event had come when a stop other
/// than a step's report ended them.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
enum Interruption {
    At(InterruptedSteps),
    /// The step's cleanup failed, so what it ran is unknown.
    Lost,
}

/// The timer's state before it observed a stop.
#[derive(Debug, Clone)]
struct ObservedStop {
    before: EventStatus,
    interrupted: Option<Interruption>,
    /// The delivery point of the scheduled precise event that the stop found
    /// already reached, recorded as a skid overshoot unless the stop is
    /// disregarded.
    missed: Option<MissedTarget>,
    /// The stop counted a [`HostTimedTimerEvents::preempted_overflow`].
    #[cfg(test)]
    preempted_overflow_counted: bool,
}

/// A precise event whose delivery point a stop found already reached.
#[derive(Debug, Clone)]
struct MissedTarget {
    clock: u64,
    clock_target: u64,
    offset: u64,
    stop: String,
    /// Whether the event's own PMU notification was already queued for the
    /// thread when the stop decided the event: the kernel had recorded an
    /// overflow of the current programming whose notification nothing had
    /// consumed, and the thread's pending signals, where they were read,
    /// held it. The notification was then not lost but held back: by the
    /// guest's signal mask, or, with the signal unblocked, by an overflow
    /// interrupt late enough that the stop's own signal was queued too and
    /// dequeued first, as a lower-numbered signal is. `false` without
    /// overflow records, where a queued notification cannot be told from a
    /// lost one.
    notification_queued: bool,
}

/// An overflow notification of this thread's timer, taken at an injected
/// syscall. See [`Timer::take_overflow_signal`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum OwnNotification {
    /// The notification of the active event, which no stop has decided.
    Live,
    /// A notification that nothing is left to deliver.
    Late,
}

/// Single steps toward a precise timer event that a stop interrupted, which
/// continue from where they stopped. See [`Timer::disregard_stop`].
#[derive(Debug, Copy, Clone)]
pub(crate) struct InterruptedSteps {
    steps: ClockCounter,
    target_instr: u64,
}

/// What of the active timer event a disregarded stop leaves for
/// [`Timer::continue_stepping`] to finish. See [`Timer::disregard_stop`].
#[derive(Debug, Copy, Clone)]
pub(crate) enum Unfinished {
    /// The single steps toward the event that the stop interrupted.
    Steps(InterruptedSteps),
    /// The whole event, whose PMU notification the kernel lost before the
    /// stop.
    Notification,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ActiveEvent {
    Precise {
        /// Expected clock value when event fires.
        clock_target: u64,
        /// Instruction offset from clock target
        offset: u64,
    },
    Imprecise {
        /// Expected minimum clock value when event fires.
        clock_min: u64,
    },
}

impl ActiveEvent {
    /// Given the current clock, determine if another event is required to get the
    /// clock to its expected state
    fn reschedule_if_spurious_wakeup(&self, curr_clock: u64) -> Option<TimerEventRequest> {
        match self {
            ActiveEvent::Precise {
                clock_target,
                offset: _,
            } => {
                if clock_target.saturating_sub(curr_clock)
                    > get_pmu_config().max_single_step_count()
                {
                    Some(TimerEventRequest::Precise(*clock_target - curr_clock))
                } else {
                    None
                }
            }
            ActiveEvent::Imprecise { clock_min } => {
                if *clock_min > curr_clock {
                    Some(TimerEventRequest::Imprecise(*clock_min - curr_clock))
                } else {
                    None
                }
            }
        }
    }
}

impl EventStatus {
    pub fn next(self) -> Self {
        match self {
            EventStatus::Scheduled => EventStatus::Armed,
            EventStatus::Armed => EventStatus::Cancelled,
            EventStatus::Cancelled => EventStatus::Cancelled,
        }
    }

    pub fn tick(&mut self) {
        *self = self.next()
    }
}

/// This ClockCounter represents a pair in a form of (rcb, instr) that gets increased
/// while single-stepping to reach target (target_rcb, target_instr)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct ClockCounter {
    rcbs: u64,
    instr: u64,
    target_rcb: u64,
}

impl std::fmt::Display for ClockCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rcb: {}, instr: {}", self.rcbs, self.instr)
    }
}

impl ClockCounter {
    pub fn new(rcb: u64, instr: u64, target_rcb: u64) -> Self {
        Self {
            rcbs: rcb,
            instr,
            target_rcb,
        }
    }

    /// This method counts instructions & rcbs together in an attempt to reach target_rcb
    ///
    /// With each attempt we either increment rcb or instruction counter based on the read clock value.
    /// If we reach target_rcb we no longer increase rcb counter and allow to meet at the target instruction counter
    pub fn single_step_with_clock(&mut self, rcbs: u64) {
        match (self.rcbs.cmp(&self.target_rcb), self.rcbs.cmp(&rcbs)) {
            (Less, Less) => {
                self.instr = 0;
                self.rcbs = rcbs;
            }

            (Less | Equal, Equal) => {
                self.instr += 1;
            }

            (Equal, Less) => {
                self.instr += 1;
            }

            (_, Greater) => panic!(
                "current counter rcb value {} is greater than privided rcb value {}",
                self.rcbs, rcbs
            ),
            (Greater, _) => panic!(
                "current counter rcb value {} is greater than target rcb value {}",
                self.rcbs, self.target_rcb
            ),
        }
    }

    /// If a counter behind a given (rcb, instr) pair.
    ///
    /// Note: this is not always comparable. [None] will be returned in this case
    fn is_behind(&self, rcbs: u64, instr: u64) -> Option<bool> {
        match self.target_rcb.cmp(&rcbs) {
            Less => None,
            Greater | Equal => match self.rcbs.cmp(&rcbs) {
                Less => Some(true),
                Equal => Some(self.instr < instr),
                Greater => Some(false),
            },
        }
    }

    fn rcbs(&self) -> u64 {
        self.rcbs
    }
}

impl TimerImpl {
    pub fn new(guest_pid: Pid, guest_tid: Tid, initial_command: bool) -> Result<Self, Errno> {
        let evt = get_pmu_config().rcb_event();

        // measure the target tid irrespective of CPU
        let mut builder = Builder::new(guest_tid.as_raw(), -1);
        builder
            .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .event(evt);

        if has_precise_ip() {
            // set precise_ip to lowest value to enable PEBS (TODO: AMD?)
            builder.precise_ip(1);
        }

        let mut timer = builder.check_for_pmu_bugs().create()?;
        timer.set_signal_delivery(guest_tid, MARKER_SIGNAL)?;
        timer.reset()?;
        // measure the target tid irrespective of CPU
        let mut clock_builder = Builder::new(guest_tid.as_raw(), -1);
        clock_builder
            // counting event
            .sample_period(0)
            .event(evt)
            .fast_reads(true);
        if initial_command {
            clock_builder.enable_on_exec();
        }
        // Each thread locks up to three pages of perf buffer: the clock's
        // fast-read page and the timer's metadata and record pages. The kernel
        // charges them to a per-user budget of `perf_event_mlock_kb` per online
        // CPU, then to RLIMIT_MEMLOCK. The record pages make that budget run out
        // three times as soon, so a clock that cannot map its page falls back to
        // read(2), which returns the same count.
        let clock = match clock_builder.create() {
            Ok(clock) => clock,
            Err(errno) => {
                // A failure of the counter itself fails again here.
                let clock = clock_builder.fast_reads(false).create()?;
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    warn!(
                        %errno,
                        "Could not map a clock for fast reads; reading clocks with read(2)"
                    )
                });
                clock
            }
        };
        // Mapped after the clock, so that it never takes this thread's clock
        // page.
        if OVERFLOW_RECORDS_DISABLED.load(std::sync::atomic::Ordering::Relaxed) {
            debug!("Timer overflow records disabled for a test");
        } else if kernel_is_preempt_rt() {
            // PREEMPT_RT sends the notification from a kernel thread some time
            // after the record is written, so a record does not show that the
            // notification is pending.
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                warn!(
                    "PREEMPT_RT kernel; timer signals at injected syscalls, late or not, will be delivered to the guest, a timer signal in the LiteInst patch helper fails the run, and a stop without a Tool callback within the keep margin of a precise timer event's target cancels the event (https://github.com/rrnewton/reverie/issues/747)"
                )
            });
        } else if let Err(errno) = timer.map_sample_records() {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                warn!(
                    %errno,
                    "Could not map timer overflow records; timer signals at injected syscalls, late or not, will be delivered to the guest, a timer signal in the LiteInst patch helper fails the run, and a stop without a Tool callback within the keep margin of a precise timer event's target cancels the event (https://github.com/rrnewton/reverie/issues/747)"
                )
            });
        }
        clock.reset()?;
        if !initial_command {
            clock.enable()?;
        }

        Ok(Self {
            timer,
            clock,
            event: ActiveEvent::Precise {
                clock_target: 0,
                offset: 0,
            },
            timer_status: EventStatus::Cancelled,
            send_artificial_signal: false,
            artificial_signal_sent: false,
            overflow_period: None,
            overflow_recorded: false,
            programming_overflowed: false,
            initial_command: if initial_command {
                InitialCommand::WaitingForExec
            } else {
                InitialCommand::Ordinary
            },
            held_initial_event: None,
            interrupted: None,
            observed: None,
            notification_taken: false,
            disregarded_missed: None,
            armed_programming: None,
            kept_programming: None,
            resumed_programming: None,
            #[cfg(test)]
            kept_programming_log: Vec::new(),
            #[cfg(test)]
            fail_next_notification: None,
            #[cfg(test)]
            preempted_overflow_counted: false,
            guest_pid,
            guest_tid,
        })
    }

    pub fn request_event(&mut self, evt: TimerEventRequest) -> Result<(), Errno> {
        let (delivery, notification) = match evt {
            TimerEventRequest::Precise(ticks) | TimerEventRequest::PreciseInstruction(ticks, _) => {
                (ticks, ticks.saturating_sub(get_pmu_config().skid_margin()))
            }
            TimerEventRequest::Imprecise(ticks) => (ticks, ticks),
        };
        if delivery == 0 {
            return Err(Errno::EINVAL); // bail before setting timer
        }
        #[cfg(test)]
        {
            self.preempted_overflow_counted = false;
        }
        self.recheck_kept_programming();
        self.armed_programming = None;
        if self.initial_command != InitialCommand::Ordinary {
            self.event = Self::event_at(evt, self.read_clock() + delivery);
            self.held_initial_event = Some(self.event);
            self.set_status(EventStatus::Scheduled);
            debug_assert!(!self.send_artificial_signal);
            return Ok(());
        }
        self.prepare_notification(notification)?;
        self.event = Self::event_at(evt, self.read_clock() + delivery);
        self.set_status(EventStatus::Scheduled);
        if kept_programming_checks() {
            // The thread is stopped, so the clock is the request's.
            self.armed_programming = self.overflow_period.map(|period| ArmedProgramming {
                overflow_point: self.read_clock() + period,
                programmings: self.timer.programmings(),
            });
        }
        Ok(())
    }

    /// Sets the status of a new or cancelled event. Earlier stops and steps
    /// concern the event it replaces. A stop observed before the request or
    /// cancellation was not disregarded, so it decided the old event.
    fn set_status(&mut self, status: EventStatus) {
        self.settle_stop();
        self.timer_status = status;
        self.interrupted = None;
        self.notification_taken = false;
        self.disregarded_missed = None;
        self.kept_programming = None;
        self.resumed_programming = None;
    }

    fn prepare_notification(&mut self, notification: u64) -> Result<(), Errno> {
        #[cfg(test)]
        if let Some(error) = self.fail_next_notification.take() {
            return Err(error);
        }
        // Keep the record buffer from filling. The records it collects belong
        // to earlier programmings: the thread is stopped, so none of their
        // overflows is still to be handled.
        self.collect_overflow_records();
        self.programming_overflowed = false;
        self.send_artificial_signal = if notification <= SINGLESTEP_TIMEOUT_RCBS {
            // If there's an existing event making use of the timer counter,
            // we need to "overwrite" it the same way setting an actual RCB
            // notification does.
            self.timer.disable()?;
            self.overflow_period = None;
            true
        } else {
            self.timer.reset()?;
            self.overflow_period = None;
            self.timer.set_period(notification)?;
            self.timer.enable()?;
            self.overflow_period = Some(notification);
            false
        };
        Ok(())
    }

    /// Whether the current programming of `timer` has passed its period.
    fn current_overflow(&self) -> Result<bool, Errno> {
        match self.overflow_period {
            Some(period) => Ok(self.timer.ctr_value()? >= period),
            None => Ok(false),
        }
    }

    /// Note the overflows the kernel has recorded since the last call.
    /// Returns `false` if no records are mapped.
    fn collect_overflow_records(&mut self) -> bool {
        match self.timer.take_sample_records() {
            Some(samples) => {
                if samples > 0 {
                    self.overflow_recorded = true;
                    self.programming_overflowed = true;
                }
                true
            }
            None => false,
        }
    }

    /// Whether the kernel lost the notification of the current programming of
    /// `timer`, so that none will come: the count has passed the period, but
    /// the kernel has recorded no overflow since the programming. It writes
    /// an overflow's record before it queues the notification, and handles no
    /// overflow of a counter that is not scheduled in, so for a thread in a
    /// stop that a ptrace request has waited on, neither can follow. `false`
    /// if no records are mapped, since an overflow cannot then be told from a
    /// lost one.
    ///
    /// Linux x86 loses an overflow when the thread is switched out with one
    /// event left in the period and switched in again after exactly one more:
    /// it programs the counter for at least two events, and wraps a period
    /// that ran out while the thread was switched out into the next, without
    /// an overflow. The stops of a guest that traps in every round of a loop
    /// with one conditional branch per round do this.
    fn notification_lost(&mut self) -> Result<bool, Errno> {
        let Some(period) = self.overflow_period else {
            return Ok(false);
        };
        if !self.collect_overflow_records() || self.programming_overflowed {
            return Ok(false);
        }
        Ok(self.timer.ctr_value()? >= period)
    }

    /// Record that the notification of every overflow recorded so far has
    /// been consumed. Standard signals coalesce, so one notification accounts
    /// for all of them.
    fn mark_overflows_consumed(&mut self) {
        self.collect_overflow_records();
        self.overflow_recorded = false;
    }

    /// Whether the kernel has recorded an overflow whose notification has not
    /// been consumed.
    fn has_overflow_records(&mut self) -> bool {
        self.collect_overflow_records();
        self.overflow_recorded
    }

    /// Whether the notification of the current programming is queued for
    /// the thread, as far as the overflow records show: the kernel recorded
    /// an overflow of this programming, and nothing has consumed its
    /// notification (see [`MissedTarget::notification_queued`]).
    fn own_notification_queued(&mut self) -> bool {
        self.has_overflow_records() && self.programming_overflowed
    }

    /// Forget the recorded overflows unless `pending`, the stopped thread's
    /// private pending signals, holds a notification with this timer's
    /// siginfo. The thread is stopped, so no overflow can be recorded between
    /// reading `pending` and this call.
    fn expire_overflow_records(&mut self, pending: &[libc::siginfo_t]) {
        if self.overflow_recorded && !pending.iter().any(|s| self.owns_overflow_signal(s)) {
            self.mark_overflows_consumed();
            OVERFLOW_RECORDS_EXPIRED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // The records now show whether the notification is in `pending`.
        let queued = self.overflow_recorded && self.programming_overflowed;
        if let Some(missed) = self
            .observed
            .as_mut()
            .and_then(|observed| observed.missed.as_mut())
        {
            missed.notification_queued = queued;
        }
    }

    fn event_at(evt: TimerEventRequest, clock: u64) -> ActiveEvent {
        match evt {
            TimerEventRequest::Precise(_) => ActiveEvent::Precise {
                clock_target: clock,
                offset: 0,
            },
            TimerEventRequest::PreciseInstruction(_, instr_offset) => ActiveEvent::Precise {
                clock_target: clock,
                offset: instr_offset,
            },
            TimerEventRequest::Imprecise(_) => ActiveEvent::Imprecise { clock_min: clock },
        }
    }

    fn retire_initial_event(&mut self) {
        let _ = self.held_initial_event.take();
        self.set_status(EventStatus::Cancelled);
        self.send_artificial_signal = false;
    }

    fn begin_initial_exec(&mut self) {
        if self.initial_command == InitialCommand::WaitingForExec {
            self.retire_initial_event();
            self.initial_command = InitialCommand::InitializingExec;
        }
    }

    fn finish_initial_exec(&mut self) {
        if self.initial_command == InitialCommand::InitializingExec {
            // Current setup makes no Tool callback in this interval. Retire
            // any new internal request as well, without revisiting a taken one.
            self.retire_initial_event();
            self.initial_command = InitialCommand::Ordinary;
        }
    }

    pub fn observe_event(&mut self, event: &TraceEvent) {
        // The first stop after a request decides the event: a stop by this
        // timer's signal delivers it, and any other stop cancels it. When that
        // other stop comes after the guest already reached the delivery point,
        // the overflow interrupt was late and the event was due first. That is
        // recorded once the stop is known to cancel the event, since a stop
        // that `disregard_stop` hands back to the event does not. Stops with
        // the timer's signal number are left to `handle_signal`, which records
        // a late delivery itself. Held initial-command requests have no
        // physical notification to be late.
        let missed = match self.event {
            ActiveEvent::Precise {
                clock_target,
                offset,
            } if self.timer_status == EventStatus::Scheduled
                && self.initial_command == InitialCommand::Ordinary
                && !matches!(event, TraceEvent::Signal(signal) if *signal == MARKER_SIGNAL) =>
            {
                let clock = self.read_clock();
                target_reached(clock, clock_target, offset).then(|| MissedTarget {
                    clock,
                    clock_target,
                    offset,
                    stop: format!("{:?} stop", event),
                    // Refined against the thread's pending signals by
                    // `expire_overflow_records`, which follows.
                    notification_queued: self.own_notification_queued(),
                })
            }
            _ => None,
        };
        // This stop is the request's one allowed stop, unless it is
        // disregarded, which takes this count back. If the counter has
        // already passed the programmed overflow, either this is the timer's
        // own signal stop, and `handle_signal` takes the count back, or
        // another stop came first although the overflow was due.
        #[cfg(test)]
        let preempted = self.timer_status == EventStatus::Scheduled
            && self.initial_command == InitialCommand::Ordinary
            && self.current_overflow().unwrap_or(false);
        #[cfg(test)]
        if preempted {
            count_host_timed(|events| events.preempted_overflow += 1);
            self.preempted_overflow_counted = true;
        }
        self.tick_observed();
        if let Some(observed) = self.observed.as_mut() {
            observed.missed = missed;
            #[cfg(test)]
            {
                observed.preempted_overflow_counted = preempted;
            }
        }
    }

    /// Records the event's status and any interrupted steps before a stop,
    /// then ticks the status, as every stop does. The previous stop, if not
    /// disregarded, decided the event.
    fn tick_observed(&mut self) {
        self.recheck_kept_programming();
        self.settle_stop();
        // A taken notification is handed on before the next stop, except on a
        // path that fails before it; the stop then decides the event.
        self.notification_taken = false;
        // This stop decides the event unless it is disregarded too, and finds
        // for itself whether the delivery point was reached.
        self.disregarded_missed = None;
        self.observed = Some(ObservedStop {
            before: self.timer_status,
            interrupted: self.interrupted.take(),
            missed: None,
            #[cfg(test)]
            preempted_overflow_counted: false,
        });
        self.timer_status.tick()
    }

    /// Ends the latest observed stop, which decided the event.
    fn settle_stop(&mut self) {
        if let Some(observed) = self.observed.take() {
            Self::commit_missed(observed.missed);
        }
    }

    /// Records a precise event that a stop retired past its delivery point as
    /// a skid overshoot.
    fn commit_missed(missed: Option<MissedTarget>) {
        let Some(missed) = missed else {
            return;
        };
        if get_pmu_config().record_missed_if_target_reached(
            missed.clock,
            missed.clock_target,
            missed.offset,
        ) {
            warn!(
                "Precise timer target {} + {} instructions reached before its interrupt \
                 was handled; {} at counter {} cancels the event",
                missed.clock_target, missed.offset, missed.stop, missed.clock
            );
            if missed.notification_queued {
                OVERTAKEN_WITH_NOTIFICATION_QUEUED
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut events = OVERTAKEN_WITH_NOTIFICATION_QUEUED_EVENTS
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if events.len() < OVERTAKEN_WITH_NOTIFICATION_QUEUED_KEPT {
                    events.push((missed.clock_target, missed.clock));
                }
            }
        }
    }

    /// Ends the handling of a thread that has exited. The latest observed
    /// stop decided the event, and so did a disregarded stop that found the
    /// delivery point reached if nothing has decided the event since: the
    /// event ends with the thread, undelivered past its delivery point.
    ///
    /// An event that no stop has decided at all is still Scheduled. It too
    /// ends with the thread, and is recorded if the guest had reached its
    /// delivery point: its notification was held back, by the guest's signal
    /// mask or by interrupt latency, past the target, and the thread exited
    /// with no stop after the target that could decide the event.
    fn settle_at_exit(&mut self) {
        self.recheck_kept_programming();
        self.settle_stop();
        let missed = self.disregarded_missed.take().or_else(|| {
            let ActiveEvent::Precise {
                clock_target,
                offset,
            } = self.event
            else {
                return None;
            };
            if self.timer_status != EventStatus::Scheduled
                || self.initial_command != InitialCommand::Ordinary
            {
                return None;
            }
            let clock = match self.clock.ctr_value_fast() {
                Ok(clock) => clock,
                Err(errno) => {
                    warn!(
                        %errno,
                        "Could not read the clock of an exited thread; its undecided precise \
                         timer event is not checked for a skid overshoot"
                    );
                    return None;
                }
            };
            target_reached(clock, clock_target, offset).then(|| MissedTarget {
                clock,
                clock_target,
                offset,
                stop: "the thread's exit".to_owned(),
                // The exited thread's pending signals cannot be read, and no
                // stop overtook the event.
                notification_queued: false,
            })
        });
        Self::commit_missed(missed);
    }

    fn disregard_stop(&mut self) -> Result<Option<Unfinished>, Errno> {
        let Some(observed) = self.observed.take() else {
            return Ok(None);
        };
        match observed.interrupted {
            None => {
                if !self.timer.has_sample_records() && self.past_keep_point()? {
                    // Without overflow records the notification of a
                    // programming past its period may be pending or lost, as
                    // host scheduling decides, and a pending one may arrive
                    // only after the guest has run past the target. Either
                    // way the event would fire, if at all, at a clock that
                    // depends on the host, so the stop cancels it as a stop
                    // the Tool observes does. A pending notification then
                    // finds it cancelled. The period itself depends on the
                    // processor's skid margin, so the stop is decided at the
                    // keep point, which lies at or before the period on every
                    // supported processor.
                    self.cancel_at_disregarded_stop(observed.missed);
                    return Ok(None);
                }
                self.restore_before(&observed);
                self.disregarded_missed = observed.missed;
                if observed.before == EventStatus::Scheduled {
                    self.kept_programming = self.armed_programming;
                }
            }
            // Steps under way show that the notification came, and so that
            // the programming passed its period and the guest its keep point.
            // Without overflow records a stop past the keep point cancels the
            // event (above), whether or not the notification came before it,
            // which host timing decides.
            Some(Interruption::At(_)) if !self.timer.has_sample_records() => {
                self.cancel_at_disregarded_stop(observed.missed);
                return Ok(None);
            }
            // Steps run only for an Armed event, and a missed target is found
            // only at a Scheduled one's stop, so there is none to keep.
            Some(Interruption::At(steps)) => {
                self.restore_before(&observed);
                return Ok(Some(Unfinished::Steps(steps)));
            }
            // The event cannot be taken to its target, so it stays cancelled.
            Some(Interruption::Lost) => {
                self.cancel_at_disregarded_stop(observed.missed);
                return Ok(None);
            }
        }
        // Nothing else will take up an event whose notification was lost,
        // even to cancel it.
        Ok(self
            .notification_lost()?
            .then_some(Unfinished::Notification))
    }

    /// Hands the event back from a disregarded stop, which did not decide
    /// it.
    fn restore_before(&mut self, observed: &ObservedStop) {
        self.timer_status = observed.before;
        #[cfg(test)]
        if observed.preempted_overflow_counted {
            self.preempted_overflow_counted = false;
            count_host_timed(|events| {
                events.preempted_overflow = events.preempted_overflow.saturating_sub(1)
            });
        }
    }

    /// Cancels the event at a disregarded stop that cannot hand it back, as
    /// a stop the Tool observes cancels it, and records its delivery point as
    /// a skid overshoot if the stop found it reached. The status is set to
    /// `Cancelled` outright rather than left at the stop's tick, which leaves
    /// an event that was Scheduled Armed, as a stop that decided it; a later
    /// [`TimerImpl::retire`], which records only a Scheduled event, does not
    /// record it again either way.
    fn cancel_at_disregarded_stop(&mut self, missed: Option<MissedTarget>) {
        Self::commit_missed(missed);
        self.timer_status = EventStatus::Cancelled;
    }

    fn disregard_stop_before_period(&mut self) -> Result<(), Errno> {
        // Read before the stop is disregarded, which leaves the programming
        // as it is, like every step of the decision.
        let past_keep_point = self.past_keep_point()?;
        match self.disregard_stop()? {
            None if !past_keep_point => Ok(()),
            // Single steps under way, or a lost notification, also show that
            // the programming passed its period, and so the guest its keep
            // point: steps end the programming.
            _ => self.retire(),
        }
    }

    /// Checks, if the stop just disregarded kept a scheduled event whose
    /// request programmed a notification while kept programmings are
    /// checked (see [`KEPT_PROGRAMMING_CHECKS`]), that the stop left that
    /// programming as the request made it, and counts the check. The check
    /// requires both that no call changed the programming of `timer` since
    /// the request (see [`PerfCounter::programmings`]), and that `timer`
    /// overflows at the clock at which the request programmed it to, its
    /// period short of the clock at the request. The first shows a
    /// re-programming that the second cannot, such as a period change,
    /// which re-arms the counter without moving its count, or a disable that
    /// leaves its period recorded. The second shows a change made other than
    /// through `timer`'s calls. Both counters count the same event for the
    /// same thread, which is stopped, so the clock less the count is the
    /// clock at which `timer` was last reset, exactly.
    ///
    /// If the check finds the programming unchanged and `resumed` holds,
    /// which is when the stop hands nothing on, the thread's next stop checks
    /// it again (see [`TimerImpl::recheck_kept_programming`]). If `resumed`
    /// does not hold, the stop is counted as handing the event on (see
    /// [`KEPT_PROGRAMMINGS_HANDED_ON`]).
    fn check_kept_programming(&mut self, resumed: bool) {
        let Some(armed) = self.kept_programming.take() else {
            return;
        };
        let found = self.overflow_period.and_then(|period| {
            let count = self.timer.ctr_value().ok()?;
            Some(self.read_clock().checked_sub(count)? + period)
        });
        let check = self.kept_programming_check(armed, found, false);
        if !resumed {
            KEPT_PROGRAMMINGS_HANDED_ON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if check.reprogrammed == 0 && found == Some(armed.overflow_point) {
            self.resumed_programming = Some(armed);
        }
        #[cfg(test)]
        self.kept_programming_log.push(check);
        count_kept_programming_check(check);
    }

    /// Checks again, at the first stop of the thread after a disregarded
    /// stop that kept an event and found its programming unchanged, or at
    /// the event's next request, cancellation or retirement, or the thread's
    /// exit if one of those comes first, that nothing has changed the
    /// programming of `timer` since the event's request (see
    /// [`PerfCounter::programmings`]), and counts the check. This covers
    /// what the rest of the disregarded stop's handling did, after
    /// [`TimerImpl::check_kept_programming`], until the guest ran. It does
    /// not read the overflow point.
    fn recheck_kept_programming(&mut self) {
        let Some(armed) = self.resumed_programming.take() else {
            return;
        };
        let check = self.kept_programming_check(armed, None, true);
        #[cfg(test)]
        self.kept_programming_log.push(check);
        count_kept_programming_check(check);
    }

    fn kept_programming_check(
        &self,
        armed: ArmedProgramming,
        found: Option<u64>,
        at_next_stop: bool,
    ) -> KeptProgramming {
        let target = match self.event {
            ActiveEvent::Precise { clock_target, .. } => clock_target,
            ActiveEvent::Imprecise { clock_min } => clock_min,
        };
        KeptProgramming {
            target,
            armed: armed.overflow_point,
            found,
            reprogrammed: self.timer.programmings() - armed.programmings,
            at_next_stop,
        }
    }

    /// Whether a stop that nothing continues must cancel the active event
    /// (see [`Timer::disregard_stop_before_period`]): for a precise event,
    /// whether the guest's clock is within [`PmuConfig::keep_margin`] of its
    /// target, which does not depend on the processor; otherwise, whether
    /// the programming has passed its period.
    fn past_keep_point(&self) -> Result<bool, Errno> {
        match self.event {
            ActiveEvent::Precise { clock_target, .. }
                if self.initial_command == InitialCommand::Ordinary =>
            {
                Ok(
                    self.read_clock()
                        >= clock_target.saturating_sub(get_pmu_config().keep_margin()),
                )
            }
            _ => self.current_overflow(),
        }
    }

    /// Whether a notification of this timer's, received while no stop has
    /// decided the active event, is the event's own. See
    /// [`Timer::take_overflow_signal`]. The caller collects the overflow
    /// records first.
    fn live_notification(&self) -> Result<bool, Errno> {
        Ok(self.timer_status == EventStatus::Scheduled
            && self.overflow_recorded
            && self.programming_overflowed
            && self.current_overflow()?)
    }

    fn take_overflow_signal(
        &mut self,
        signal: &libc::siginfo_t,
    ) -> Result<Option<OwnNotification>, Errno> {
        self.recheck_kept_programming();
        if !self.owns_overflow_signal(signal) {
            return Ok(None);
        }
        self.collect_overflow_records();
        if self.live_notification()? {
            self.mark_overflows_consumed();
            self.notification_taken = true;
            return Ok(Some(OwnNotification::Live));
        }
        Ok(self
            .consume_overflow_signal(signal)?
            .then_some(OwnNotification::Late))
    }

    fn take_notification(&mut self) -> Option<Unfinished> {
        std::mem::take(&mut self.notification_taken).then_some(Unfinished::Notification)
    }

    fn retire(&mut self) -> Result<(), Errno> {
        self.recheck_kept_programming();
        // Only an event that no stop has decided is recorded here, as at the
        // thread's exit. An Armed one was decided: delivered (its stale
        // target stays in `event` until the next request), or cancelled by
        // a stop that recorded any overshoot itself, or being stepped to its
        // target, which the steps have not passed. A Cancelled one was
        // decided too. As in `observe_event` and `settle_at_exit`, a held
        // initial-command request has no physical notification to be late,
        // so it is never recorded. That clause is defensive: no test retires
        // an event before the first post-exec callback, and removing it
        // fails none.
        if self.timer_status == EventStatus::Scheduled
            && self.initial_command == InitialCommand::Ordinary
            && let ActiveEvent::Precise {
                clock_target,
                offset,
            } = self.event
        {
            let clock = self.read_clock();
            if target_reached(clock, clock_target, offset) {
                Self::commit_missed(Some(MissedTarget {
                    clock,
                    clock_target,
                    offset,
                    stop: "a stop that cannot finish it".to_owned(),
                    // What the overflow records show at the retire, after
                    // anything injected for the stop, not when the stop was
                    // observed: the stop's pending signals were read then
                    // (`expire_overflow_records`), and before each injected
                    // syscall, and a notification taken or discarded at an
                    // injection since has consumed its records. No test
                    // checks this attribution: `false` here (mutant r1b in
                    // the review of https://github.com/rrnewton/reverie/pull/665)
                    // fails none. That errs in the safe direction: the
                    // event is witnessed either way, and only whether it
                    // is counted as overtaken differs. It belongs with the
                    // untested witness code in
                    // https://github.com/rrnewton/reverie/issues/748.
                    notification_queued: self.own_notification_queued(),
                }));
            }
        }
        self.set_status(EventStatus::Cancelled);
        self.send_artificial_signal = false;
        self.cancel()?;
        self.overflow_period = None;
        Ok(())
    }

    async fn continue_stepping(
        &mut self,
        task: Stopped,
        unfinished: Unfinished,
        step: &mut (dyn FnMut(Stopped) -> Result<Running, TraceError> + Send),
        observe: &mut (dyn FnMut(&Wait) -> Result<(), TraceError> + Send),
        waits: &std::sync::Arc<PtracerWaitOwner>,
    ) -> Result<Stopped, HandleFailure> {
        match unfinished {
            Unfinished::Steps(steps) => {
                // Steps are only interrupted, and so only continued, once the
                // event has been decided on.
                debug_assert_eq!(self.timer_status, EventStatus::Armed);
                self.attempt_single_step(
                    task,
                    steps.steps,
                    steps.target_instr,
                    step,
                    observe,
                    waits,
                )
                .await
            }
            Unfinished::Notification => {
                // The stop stands in for the notification's, which the guest
                // would have taken on resuming, before running another
                // instruction, so the steps start from the same clock.
                self.tick_observed();
                match self.timer_status {
                    EventStatus::Armed => self.deliver(task, step, observe, waits).await,
                    _ => {
                        self.disable_timer_before_stepping();
                        Err(HandleFailure::Cancelled(task))
                    }
                }
            }
        }
    }

    pub fn schedule_cancellation(&mut self) {
        self.recheck_kept_programming();
        self.set_status(EventStatus::Cancelled);
    }

    pub fn cancel(&self) -> Result<(), Errno> {
        if self.initial_command == InitialCommand::Ordinary {
            self.timer.disable()
        } else {
            Ok(())
        }
    }

    fn is_timer_generated_signal(signal: &libc::siginfo_t) -> bool {
        // The signal that gets sent is SIGPOLL. We reconfigured the signal
        // number, but the struct info is the same. Per the perf manpage, signal
        // notifications will come indicating either POLL_IN or POLL_HUP.
        signal.si_signo == MARKER_SIGNAL as i32
            && (signal.si_code == i32::from(libc::POLLIN)
                || signal.si_code == i32::from(libc::POLLHUP))
    }

    fn controller_artificial_signal(&self, signal: &libc::siginfo_t) -> Result<bool, TraceError> {
        if !self.artificial_signal_sent
            || signal.si_signo != MARKER_SIGNAL as i32
            || signal.si_code != libc::SI_TKILL
        {
            return Ok(false);
        }
        let sender = unsafe { signal.si_pid() };
        let controller = unsafe { libc::getpid() };
        if sender != 0 && sender != controller {
            return Ok(false);
        }
        // This runs while handle_signal owns the tracee's actual stop, before
        // any resumption. A task visible to this ptracer is in the same PID
        // namespace or a descendant. Linux translates an ancestor's tgkill
        // sender to zero; a positive numerical match alone is insufficient
        // because a descendant's local PID can equal our PID.
        let guest_path = format!("/proc/{}/ns/pid", self.guest_tid);
        #[cfg(test)]
        let guest_path = CONTROLLER_NAMESPACE_PATH.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or(guest_path)
        });
        let ours = nix::sys::stat::stat("/proc/thread-self/ns/pid")?;
        let theirs = nix::sys::stat::stat(guest_path.as_str());
        #[cfg(test)]
        CONTROLLER_QUERY_LOG.with(|slot| {
            if let Some(log) = slot.borrow().as_ref() {
                log.lock().unwrap().push(format!(
                    "actual namespace stat: tid={}, result={:?}",
                    self.guest_tid,
                    theirs.as_ref().map(|stat| (stat.st_dev, stat.st_ino))
                ));
            }
        });
        let theirs = theirs?;
        let same_namespace = (ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino);
        // Namespace lookup failure propagates through the held-stop error
        // path; it neither accepts an unknown sender nor makes construction
        // newly fallible. This discriminates accidental guest markers under
        // the existing reserved-signal convention, not hostile forgery:
        // another ancestor also maps to zero and self rt_tgsigqueueinfo can
        // supply SI_TKILL with a forged sender in either namespace.
        Ok(sender == if same_namespace { controller } else { 0 })
    }

    fn generated_signal(&self, signal: &libc::siginfo_t, controller: bool) -> bool {
        self.initial_command == InitialCommand::Ordinary
            && signal.si_signo == MARKER_SIGNAL as i32
            && (controller
                // Existing backend convention reserves this marker for perf.
                // Numeric fd equality alone is not a global signal identity:
                // an external sender can reuse a fd number. The controller
                // kick path above also checks the namespace-translated sender
                // and code, subject to the same reserved-signal convention.
                || (Self::is_timer_generated_signal(signal)
                    && get_si_fd(signal) == self.timer.raw_fd()))
    }

    fn owns_overflow_signal(&self, signal: &libc::siginfo_t) -> bool {
        self.initial_command == InitialCommand::Ordinary
            && Self::is_timer_generated_signal(signal)
            // The guest can produce the same siginfo: an `F_SETSIG`
            // descriptor of its own with this number sends the timer's signal
            // and code. Delivery of timer signals assumes it does not.
            // `consume_overflow_signal`, which discards signals at injected
            // syscalls, also requires a recorded overflow.
            && get_si_fd(signal) == self.timer.raw_fd()
    }

    fn consume_overflow_signal(&mut self, signal: &libc::siginfo_t) -> Result<bool, Errno> {
        self.recheck_kept_programming();
        if !self.owns_overflow_signal(signal) {
            return Ok(false);
        }
        self.collect_overflow_records();
        if !self.overflow_recorded || self.live_notification()? {
            return Ok(false);
        }
        if self.current_overflow()? {
            // The notification can be this programming's, whose timer event
            // the stop has ended. A programming that has not passed its
            // period stays armed.
            self.timer.disable()?;
            self.overflow_period = None;
        }
        self.mark_overflows_consumed();
        Ok(true)
    }

    pub fn read_clock(&self) -> u64 {
        self.clock.ctr_value_fast().expect("Failed to read clock")
    }

    pub fn finalize_requests(&mut self) {
        self.settle_stop();
        if self.initial_command != InitialCommand::Ordinary {
            debug_assert!(!self.send_artificial_signal);
            return;
        }
        if self.send_artificial_signal {
            debug!("Sending artificial timer signal");

            // Give the guest a kick via an "artificial signal".  This gives us something
            // to handle in `handle_signal` and thus drives single-stepping.
            Errno::result(unsafe {
                libc::syscall(
                    libc::SYS_tgkill,
                    self.guest_pid.as_raw(),
                    self.guest_tid.as_raw(),
                    MARKER_SIGNAL as i32,
                )
            })
            .expect("Timer tgkill error indicates a bug");
            self.artificial_signal_sent = true;
        }
    }

    async fn handle_signal(
        &mut self,
        task: Stopped,
        step: &mut (dyn FnMut(Stopped) -> Result<Running, TraceError> + Send),
        observe: &mut (dyn FnMut(&Wait) -> Result<(), TraceError> + Send),
        waits: &std::sync::Arc<PtracerWaitOwner>,
    ) -> Result<Stopped, HandleFailure> {
        self.recheck_kept_programming();
        // From libc 0.2.190 `siginfo_t` is not `Send`, so it must not be
        // alive at the `.await` below; this block owns it.
        let controller = {
            let signal = task.getsiginfo()?;
            #[cfg(test)]
            EXEC_SIGNAL_OBSERVATIONS.with(|slot| {
                if let Some(observed) = slot.borrow().as_ref() {
                    observed.lock().unwrap().push((
                        self.guest_tid.as_raw(),
                        signal.si_signo,
                        signal.si_code,
                        unsafe { signal.si_pid() },
                        self.read_clock(),
                        self.timer_status == EventStatus::Cancelled,
                        self.send_artificial_signal,
                    ));
                }
            });
            #[cfg(test)]
            if let Some(hook) = CONTROLLER_QUERY_EDGE.with(|slot| slot.borrow_mut().take()) {
                hook(&task);
            }
            let controller = self.controller_artificial_signal(&signal)?;
            if !self.generated_signal(&signal, controller) {
                warn!(
                    ?signal,
                    "Passed a signal that wasn't for this timer, likely indicating a bug!",
                );
                return Err(HandleFailure::ImproperSignal(task));
            }
            if self.owns_overflow_signal(&signal) {
                // Otherwise a later injected syscall could mistake a guest signal
                // for this notification.
                self.mark_overflows_consumed();
            }
            controller
        };

        if controller {
            self.artificial_signal_sent = false;
        }
        match self.timer_status {
            EventStatus::Scheduled => panic!(
                "Timer event status should tick at least once before the signal \
                is handled. This is a bug!"
            ),
            EventStatus::Armed => {
                // This signal stop was the request's one allowed stop.
                #[cfg(test)]
                if std::mem::take(&mut self.preempted_overflow_counted) {
                    count_host_timed(|events| {
                        events.preempted_overflow = events.preempted_overflow.saturating_sub(1)
                    });
                }
            }
            EventStatus::Cancelled => {
                debug!("Delivered timer signal cancelled due to status");
                CANCELLED_TIMER_SIGNALS_DISCARDED
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.disable_timer_before_stepping();
                return Err(HandleFailure::Cancelled(task));
            }
        };

        // At this point, we've decided that a timer event is to be delivered.
        self.deliver(task, step, observe, waits).await
    }

    /// Delivers the active event, whose notification the guest has taken or
    /// the kernel has lost, by single stepping the guest to its target if it
    /// is precise.
    async fn deliver(
        &mut self,
        task: Stopped,
        step: &mut (dyn FnMut(Stopped) -> Result<Running, TraceError> + Send),
        observe: &mut (dyn FnMut(&Wait) -> Result<(), TraceError> + Send),
        waits: &std::sync::Arc<PtracerWaitOwner>,
    ) -> Result<Stopped, HandleFailure> {
        // Ensure any new timer signals don't mess with us while single-stepping
        self.disable_timer_before_stepping();

        // Last check to see if this an unexpected wakeup (a signal before the minimum expected)
        let ctr = self.read_clock();

        if let Some(additional_timer_request) = self.event.reschedule_if_spurious_wakeup(ctr) {
            debug!("Spurious wakeup - rescheduling new timer event");
            if let Err(errno) = self.request_event(additional_timer_request) {
                warn!(
                    "Attempted to reschedule a timer signal after an early wakeup, but failed with - {:?}. A panic will likely follow",
                    errno
                );
            } else {
                return Err(HandleFailure::Cancelled(task));
            };
        }

        // Before we drive the event to completion, clear `send_artificial_signal` flag so that:
        // - another signal isn't generated anytime Timer::finalize_requests() is called
        // - spurious SIGSTKFLTs aren't let errantly let through
        // Cancellations should prevent spurious timer events in any case.
        self.send_artificial_signal = false;

        match self.event {
            ActiveEvent::Precise {
                clock_target,
                offset,
            } => {
                // No single step places an event that the notification finds
                // exactly at its target count with no instruction offset.
                #[cfg(test)]
                if ctr == clock_target && offset == 0 {
                    count_host_timed(|events| events.unstepped_at_target += 1);
                }
                let current = ClockCounter::new(ctr, 0, clock_target);
                self.attempt_single_step(task, current, offset, step, observe, waits)
                    .await
            }
            ActiveEvent::Imprecise { clock_min } => {
                debug!(
                    "Imprecise timer event delivered. Ctr val: {}, min val: {}",
                    ctr, clock_min
                );
                assert!(ctr >= clock_min, "ctr = {}, clock_min = {}", ctr, clock_min);
                Ok(task)
            }
        }
    }

    /// Single steps from `current` to the event's target. `current` is where
    /// the timer signal found the guest, or where a disregarded stop
    /// interrupted earlier steps.
    async fn attempt_single_step(
        &mut self,
        task: Stopped,
        mut current: ClockCounter,
        target_instr: u64,
        step: &mut (dyn FnMut(Stopped) -> Result<Running, TraceError> + Send),
        observe: &mut (dyn FnMut(&Wait) -> Result<(), TraceError> + Send),
        waits: &std::sync::Arc<PtracerWaitOwner>,
    ) -> Result<Stopped, HandleFailure> {
        let target_rcb = current.target_rcb;
        // The perf interrupt can arrive *past* the target when descheduling or
        // migration delays signal handling long enough for the actual skid to
        // exceed the margin. Single stepping cannot move the guest backward, so
        // record the overshoot and deliver the timer event at the observed
        // counter. The Tool can then account for the late event and either end
        // the timeslice or re-arm the next timer through its normal callback.
        if get_pmu_config().record_overshoot_if_past_target(current.rcbs(), target_rcb) {
            warn!(
                "Precise timer interrupt arrived after target: actual {} > target {}; \
                 delivering timer event at the observed counter",
                current.rcbs(),
                target_rcb
            );
            #[cfg(test)]
            count_host_timed(|events| events.overshoot += 1);
            return Ok(task);
        }
        let max_single_step_count = get_pmu_config().max_single_step_count();
        assert!(
            target_rcb - current.rcbs() <= max_single_step_count,
            "Single steps from {} to {} requested ({} steps), but that exceeds the skid margin + minimum perf timer steps ({}). \
                This probably indicates a bug",
            current.rcbs(),
            target_rcb,
            (target_rcb - current.rcbs()),
            max_single_step_count
        );
        debug!(
            "Timer will single-step from ctr {} to {}",
            current, target_rcb
        );
        let mut task = task;
        // The registers before each step. A step's cleanup reads them back
        // afterwards, so they carry over to the next step.
        #[cfg(target_arch = "x86_64")]
        let mut regs = task.getregs()?;
        // Whether the guest itself has set TF. Either no step of this sequence
        // has run yet, or the cleanup of the step that a disregarded stop
        // interrupted has run, so a TF that Linux set for stepping is hidden.
        #[cfg(target_arch = "x86_64")]
        let mut guest_trap_flag = regs.eflags & TRAP_FLAG != 0;
        loop {
            if !current
                .is_behind(target_rcb, target_instr)
                .expect("counter should increase monotonically and stay at target_rcb until equal. This is most likely a BUG with counter tracking")
            {
                break;
            }
            #[cfg(target_arch = "x86_64")]
            trace!(
                "[instruction]\n{}\n{}",
                crate::decoder::decode_instruction(&task)?,
                regs.display_with_options(RegDisplayOptions { multiline: true })
            );
            #[cfg(target_arch = "x86_64")]
            let start = StepStart {
                instruction: stepped_instruction(&task, &regs),
                rip: regs.rip,
                rsp: regs.rsp,
                rax: regs.rax,
                clock: self.read_clock(),
            };
            let wait = step(task)?.next_state_with_owner(waits).await?;
            observe(&wait)?;
            task = match wait {
                // a successful single step results in SIGTRAP stop
                #[cfg(target_arch = "x86_64")]
                Wait::Stopped(new_task, TraceEvent::Signal(Signal::SIGTRAP))
                    if matches!(is_step_report(&new_task, &start), Ok(true)) =>
                {
                    new_task
                }
                #[cfg(not(target_arch = "x86_64"))]
                Wait::Stopped(new_task, TraceEvent::Signal(Signal::SIGTRAP)) => new_task,
                // Any other stop ends the stepping, and so does a SIGTRAP that
                // the step did not report, such as an `int3`'s, or one whose
                // siginfo cannot be read. The step's instruction may still
                // have run: a `syscall` stops at its seccomp stop after
                // loading r11, for example. The stop is passed on even if the
                // cleanup fails, because it can be an event, such as a new
                // child or a trap that Reverie handles, that must be handled.
                // A seccomp stop is passed on separately, for the caller to
                // classify.
                //
                // How far the steps have come is kept for the stop's handler,
                // which continues them if the Tool does not observe the stop
                // (`Timer::disregard_stop`). The instruction ran if the stop
                // moved rip or the clock. A SIGTRAP from elsewhere that
                // arrives before the step leaves both, and one that arrives
                // during it replaces the step's report, so a step whose
                // instruction moves neither is then not counted, and the event
                // lands one instruction late. A `rep` string instruction does
                // that on every iteration but its last, as does a jump to
                // itself.
                #[cfg(target_arch = "x86_64")]
                Wait::Stopped(mut new_task, event) => {
                    self.interrupted = Some(
                        match remove_stepping_trap_flag(&mut new_task, &start, guest_trap_flag) {
                            Ok((_, regs)) => {
                                let clock = self.read_clock();
                                if regs.rip != start.rip || clock != start.clock {
                                    current.single_step_with_clock(clock);
                                }
                                Interruption::At(InterruptedSteps {
                                    steps: current,
                                    target_instr,
                                })
                            }
                            Err(err) => {
                                warn!(
                                    "Could not remove the single-step trap flag at {:?}: {:?}",
                                    event, err
                                );
                                Interruption::Lost
                            }
                        },
                    );
                    if matches!(event, TraceEvent::Seccomp) {
                        return Err(HandleFailure::SeccompStop(new_task));
                    }
                    return Err(HandleFailure::Event(Wait::Stopped(new_task, event)));
                }
                #[cfg(not(target_arch = "x86_64"))]
                Wait::Stopped(new_task, TraceEvent::Seccomp) => {
                    return Err(HandleFailure::SeccompStop(new_task));
                }
                wait => return Err(HandleFailure::Event(wait)),
            };
            #[cfg(target_arch = "x86_64")]
            {
                (guest_trap_flag, regs) =
                    remove_stepping_trap_flag(&mut task, &start, guest_trap_flag)?;
            }
            current.single_step_with_clock(self.read_clock());
        }
        Ok(task)
    }

    /// Imagine our skid margin is 50 RCBs, and we set the timer for 5 RCBs.
    /// Since we step for 50, the timer will trigger multiple times unless we
    /// disable it before stepping. This would count as a state machine
    /// transition and errantly cancel the delivery of the timer event.
    ///
    /// This ends the programming, so that no later stop takes the event,
    /// delivered or cancelled, for one whose notification was lost.
    fn disable_timer_before_stepping(&mut self) {
        self.timer
            .disable()
            .expect("Must be able to disable timer before stepping");
        self.overflow_period = None;
    }
}

/// The x86 trap flag (TF) in RFLAGS.
#[cfg(target_arch = "x86_64")]
const TRAP_FLAG: u64 = 0x100;

/// TF in the second byte of a flags image in memory.
#[cfg(target_arch = "x86_64")]
const TRAP_FLAG_HIGH_BYTE: u8 = (TRAP_FLAG >> 8) as u8;

/// Where `rt_sigreturn` reads the RFLAGS it restores, relative to the stack
/// pointer at its `syscall`. The signal frame's `ucontext` starts there, just
/// past the return address that the handler's `ret` popped.
#[cfg(target_arch = "x86_64")]
const SIGRETURN_FLAGS_OFFSET: u64 = (core::mem::offset_of!(libc::ucontext_t, uc_mcontext)
    + core::mem::offset_of!(libc::mcontext_t, gregs)
    + libc::REG_EFL as usize * core::mem::size_of::<libc::greg_t>())
    as u64;

/// The instruction a single step runs, as far as the step can leave the TF
/// that stepping sets where the guest sees it. `at` is the address of the
/// instruction, with its prefixes, `end` the address just past it, where a
/// step that completes it stops, and `loads` the loads of SS that the step
/// runs before it.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlagsInstruction {
    /// `pushf` stores RFLAGS, including the stepping TF, on the stack.
    Pushf {
        end: u64,
    },
    /// `popf` loads RFLAGS from the stack, and Linux then treats TF as the
    /// guest's.
    Popf {
        end: u64,
    },
    /// `popf` in the same step as the loads of SS before it. Linux looks only
    /// at the first instruction of a step, so it can hide the TF this loads.
    PopfAfterMovSs {
        end: u64,
    },
    /// `iret` loads RFLAGS like `popf`, and rip and rsp from the stack too.
    Iret {
        at: u64,
        loads: SsLoads,
    },
    /// `syscall` saves RFLAGS in r11, and the kernel returns it there.
    Syscall {
        at: u64,
        end: u64,
        loads: SsLoads,
    },
    Other,
}

/// The most consecutive loads of SS before an instruction that the decoder
/// follows.
///
/// A step that starts at a longer chain decodes as `Other`. Should the
/// processor run the whole chain and the `pushf`, `popf`, `iret` or `syscall`
/// after it in that one step, the stepping's TF is not removed from where
/// that instruction leaves it, the guest's stack, RFLAGS or r11, and the
/// guest sees TF set; a stepped `syscall`'s report is then also taken for a
/// trap of the guest's.
#[cfg(target_arch = "x86_64")]
const MAX_SS_LOADS: usize = 4;

/// The addresses of the loads of SS that a step runs before its instruction.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SsLoads {
    addrs: [u64; MAX_SS_LOADS],
    len: usize,
}

#[cfg(target_arch = "x86_64")]
impl SsLoads {
    const NONE: Self = Self {
        addrs: [0; MAX_SS_LOADS],
        len: 0,
    };

    fn contains(&self, addr: u64) -> bool {
        self.addrs[..self.len].contains(&addr)
    }
}

/// What a single step starts from.
#[cfg(target_arch = "x86_64")]
struct StepStart {
    instruction: FlagsInstruction,
    rip: u64,
    rsp: u64,
    rax: u64,
    clock: u64,
}

/// Reads guest code in aligned words with PTRACE_PEEKDATA, which also reads
/// execute-only pages and never reads past the word holding the last byte
/// examined.
#[cfg(target_arch = "x86_64")]
struct CodeReader<'a> {
    task: &'a Stopped,
    word_addr: Option<u64>,
    word: [u8; 8],
}

#[cfg(target_arch = "x86_64")]
impl CodeReader<'_> {
    fn byte(&mut self, addr: u64) -> Option<u8> {
        if self.word_addr != Some(addr & !7) {
            self.word = read_aligned_word(self.task, addr & !7).ok()?.to_ne_bytes();
            self.word_addr = Some(addr & !7);
        }
        Some(self.word[(addr & 7) as usize])
    }
}

/// The errors with which a syscall asks Linux to restart it when no handler
/// runs: ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND and
/// ERESTART_RESTARTBLOCK (include/linux/errno.h).
#[cfg(target_arch = "x86_64")]
const RESTART_ERRORS: [i64; 4] = [-512, -513, -514, -516];

/// The instruction that the next step of a guest with `regs` runs.
///
/// That is the instruction at rip, unless the guest is stopped at the end of
/// a syscall that asks to be restarted, which a signal or task work has
/// interrupted. Resuming it without a signal, as a step does, makes Linux move
/// rip back over the `syscall` and run it again (arch_do_signal_or_restart).
/// Linux reads the syscall number from the low 32 bits of orig_rax, and
/// orig_rax is -1 if the stop was not in a syscall.
#[cfg(target_arch = "x86_64")]
fn stepped_instruction(task: &Stopped, regs: &Regs) -> FlagsInstruction {
    if regs.orig_rax as i32 != -1 && RESTART_ERRORS.contains(&(regs.rax as i64)) {
        let restarted = flags_instruction(task, regs.rip.wrapping_sub(2));
        if matches!(restarted, FlagsInstruction::Syscall { end, .. } if end == regs.rip) {
            return restarted;
        }
    }
    flags_instruction(task, regs.rip)
}

/// Decodes enough of the instruction at `ip` to tell whether it is `pushf`,
/// `popf`, `iret` or `syscall`, with any prefixes.
///
/// A `mov` to SS holds back the debug trap until the next instruction has
/// run, so a step that starts there runs both, and the second decides what
/// the step leaks. Code that cannot be read is `Other`; the step itself then
/// reports the fault.
#[cfg(target_arch = "x86_64")]
fn flags_instruction(task: &Stopped, ip: u64) -> FlagsInstruction {
    let mut code = CodeReader {
        task,
        word_addr: None,
        word: [0; 8],
    };
    decode_flags_instruction(ip, &mut |addr| code.byte(addr))
}

/// [`flags_instruction`] for the code that `byte` reads.
#[cfg(target_arch = "x86_64")]
fn decode_flags_instruction(ip: u64, byte: &mut dyn FnMut(u64) -> Option<u8>) -> FlagsInstruction {
    /// The longest x86 instruction, in bytes.
    const MAX_INSTRUCTION_LEN: u64 = 15;
    let mut start = ip;
    let mut loads = SsLoads::NONE;
    let mut addr = ip;
    while addr < start.saturating_add(MAX_INSTRUCTION_LEN) {
        let Some(opcode) = byte(addr) else {
            return FlagsInstruction::Other;
        };
        match opcode {
            0x9c => return FlagsInstruction::Pushf { end: addr + 1 },
            0x9d if loads.len > 0 => return FlagsInstruction::PopfAfterMovSs { end: addr + 1 },
            0x9d => return FlagsInstruction::Popf { end: addr + 1 },
            0xcf => return FlagsInstruction::Iret { at: start, loads },
            0x0f if byte(addr + 1) == Some(0x05) => {
                return FlagsInstruction::Syscall {
                    at: start,
                    end: addr + 2,
                    loads,
                };
            }
            // `mov ss, r/m16`. Of consecutive loads of SS, Intel documents
            // only the first as sure to hold the trap back, but an AMD EPYC
            // runs two and the `syscall` after them in one step, which then
            // reports the syscall's return. The step's instruction is the
            // first after the chain.
            0x8e if loads.len < MAX_SS_LOADS => {
                let Some(modrm) = byte(addr + 1) else {
                    return FlagsInstruction::Other;
                };
                if (modrm >> 3) & 7 != 2 {
                    return FlagsInstruction::Other;
                }
                let Some(len) = modrm_len(byte, addr + 1, modrm) else {
                    return FlagsInstruction::Other;
                };
                loads.addrs[loads.len] = start;
                loads.len += 1;
                addr += 1 + len;
                start = addr;
                continue;
            }
            // Legacy prefixes, then REX.
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 => {}
            0x40..=0x4f => {}
            _ => return FlagsInstruction::Other,
        }
        addr += 1;
    }
    FlagsInstruction::Other
}

/// The length, in 64-bit mode, of the ModRM byte `modrm` at `addr` together
/// with the SIB byte and displacement that follow it.
#[cfg(target_arch = "x86_64")]
fn modrm_len(byte: &mut dyn FnMut(u64) -> Option<u8>, addr: u64, modrm: u8) -> Option<u64> {
    let (mode, rm) = (modrm >> 6, modrm & 7);
    if mode == 3 {
        return Some(1);
    }
    let mut len = 1;
    if rm == 4 {
        let sib = byte(addr + 1)?;
        len += 1;
        // No base register: a 32-bit displacement instead.
        if mode == 0 && sib & 7 == 5 {
            len += 4;
        }
    } else if mode == 0 && rm == 5 {
        // RIP-relative.
        len += 4;
    }
    len += match mode {
        1 => 1,
        2 => 4,
        _ => 0,
    };
    Some(len)
}

/// Removes the TF that a single step left where the guest can see it, unless
/// the guest set TF itself. Returns whether the guest's own TF is set after
/// the step, and the registers the guest now has.
///
/// Whether the step ran its instruction is read from where it stopped, and
/// for an instruction that loads rsp from where the stack is, not from the
/// stop: a SIGTRAP can come from elsewhere, and a stop other than the step's
/// SIGTRAP (a group stop, or a seccomp stop at a `syscall`) can follow an
/// instruction that ran.
///
/// PTRACE_SINGLESTEP runs one instruction with TF set. Linux normally hides
/// that TF from PTRACE_GETREGS and clears it when the tracee is next resumed,
/// but it leaks in three ways (arch/x86/kernel/step.c):
///
/// - A stepped `pushf` stores RFLAGS as it is, so the guest's stack receives
///   TF=1 although the guest never set it. When the guest restores that image
///   with `popf`, as LiteInst's trampolines do, TF stays set.
/// - Stepping `popf` or `iret` makes Linux treat TF as the guest's own
///   (`is_setting_trap_flag`). It still sets TF for every later step in the
///   sequence, but never takes it back as its own, so TF shows in the
///   registers and stays set when the tracee is resumed.
/// - A stepped `syscall` saves RFLAGS, TF included, in r11, where the guest
///   finds it when the syscall returns. It does so before any seccomp stop,
///   so a step that ends at one leaks it too, and again when a step restarts
///   an interrupted syscall.
///
/// In the first two ways the guest then runs with TF set and every
/// instruction traps.
///
/// An instruction that loads the guest's flags decides the guest's TF for
/// later steps. Linux notices a stepped `popf` or `iret`, and shows the TF it
/// loads. It does not notice a `popf` that runs in the same step as a
/// `mov ss`, or the RFLAGS that `rt_sigreturn` restores from a signal frame,
/// and hides a TF these load while it has set TF itself (TIF_FORCED_TF).
/// Those are read from memory, and set again through PTRACE_SETREGS, which
/// makes them the guest's.
#[cfg(target_arch = "x86_64")]
fn remove_stepping_trap_flag(
    task: &mut Stopped,
    start: &StepStart,
    guest_trap_flag: bool,
) -> Result<(bool, Regs), TraceError> {
    let mut regs = task.getregs()?;
    match start.instruction {
        // The flags just loaded are the guest's own.
        FlagsInstruction::Popf { end } if regs.rip == end => {
            return Ok((regs.eflags & TRAP_FLAG != 0, regs));
        }
        FlagsInstruction::Iret { at, loads } if returned(&regs, start, at, &loads) => {
            return Ok((regs.eflags & TRAP_FLAG != 0, regs));
        }
        FlagsInstruction::PopfAfterMovSs { end } if regs.rip == end => {
            let image = read_byte(task, start.rsp + 1).map_err(|err| memory_error(task, err))?;
            return adopt_trap_flag(task, regs, image & TRAP_FLAG_HIGH_BYTE != 0);
        }
        // A completed `rt_sigreturn` restores every register from the signal
        // frame, r11 and RFLAGS included, and sets orig_rax to -1. Linux takes
        // the syscall number from the low 32 bits of rax. The frame may send
        // rip back to the `syscall` with another syscall number in rax.
        FlagsInstruction::Syscall { at, loads, .. }
            if start.rax as u32 == libc::SYS_rt_sigreturn as u32
                && regs.orig_rax as i64 == -1
                && (returned(&regs, start, at, &loads) || regs.rax != start.rax) =>
        {
            let restored = regs.eflags & TRAP_FLAG != 0 || {
                let addr = start.rsp + SIGRETURN_FLAGS_OFFSET + 1;
                let image = read_byte(task, addr).map_err(|err| memory_error(task, err))?;
                image & TRAP_FLAG_HIGH_BYTE != 0
            };
            return adopt_trap_flag(task, regs, restored);
        }
        _ => {}
    }
    if guest_trap_flag {
        return Ok((true, regs));
    }
    let mut changed = false;
    match start.instruction {
        // pushfq stores 8 bytes and pushfw 2.
        FlagsInstruction::Pushf { end }
            if regs.rip == end && matches!(start.rsp.wrapping_sub(regs.rsp), 2 | 8) =>
        {
            // TF is bit 0 of the image's second byte, in either size.
            let addr = regs.rsp + 1;
            let byte = read_byte(task, addr).map_err(|err| memory_error(task, err))?;
            if byte & TRAP_FLAG_HIGH_BYTE != 0 {
                let addr = AddrMut::from_raw(addr as usize).ok_or(Errno::EFAULT)?;
                task.write_exact(addr, &[byte & !TRAP_FLAG_HIGH_BYTE])
                    .map_err(|err| memory_error(task, err))?;
            }
        }
        // The `syscall` ran if the step ended just past it, whether the
        // syscall completed or stopped at its entry.
        FlagsInstruction::Syscall { end, .. } if regs.rip == end && regs.r11 & TRAP_FLAG != 0 => {
            regs.r11 &= !TRAP_FLAG;
            changed = true;
        }
        _ => {}
    }
    // Linux sets TF for every step but has lost track of it, so it shows here
    // and would stay set when the guest resumes.
    if regs.eflags & TRAP_FLAG != 0 {
        regs.eflags &= !TRAP_FLAG;
        changed = true;
    }
    if changed {
        task.setregs(&regs)?;
    }
    Ok((false, regs))
}

/// Whether a SIGTRAP stop that ends a single step from `start` is the step's
/// own report, rather than a trap that the guest raised in the step and would
/// have raised without it, such as an `int3`'s.
///
/// Linux reports a step with TRAP_TRACE, except that a stepped `syscall` that
/// no seccomp stop interrupts reports it as the syscall returns, with
/// TRAP_BRKPT (user_single_step_report, in arch/x86/kernel/ptrace.c). `int3`
/// raises SI_KERNEL, and kill and tgkill SI_USER and SI_TKILL. `icebp` raises
/// TRAP_BRKPT as long as the processor sets no DR6 status bit for it. seccomp
/// kills the other ways into the kernel, `int 0x80` and `sysenter`, so
/// `syscall` is the only instruction that a step reports with TRAP_BRKPT. A
/// guest that has set TF itself raises TRAP_TRACE too, and that trap counts as
/// the step.
///
/// A step that starts at loads of SS runs the instruction after them too (an
/// AMD EPYC runs two loads and a `syscall` in one step), so
/// `start.instruction` is the first instruction after the loads.
#[cfg(target_arch = "x86_64")]
fn is_step_report(task: &Stopped, start: &StepStart) -> Result<bool, TraceError> {
    Ok(match task.getsiginfo()?.si_code {
        libc::TRAP_TRACE => true,
        libc::TRAP_BRKPT => matches!(start.instruction, FlagsInstruction::Syscall { .. }),
        _ => false,
    })
}

/// Whether a step from `start` ran the instruction at `at`, which loads rip
/// and rsp from memory. A step that stops before the instruction or faults in
/// it leaves rsp as it was and rip at `at`, or at one of the `loads` of SS
/// before it, where the step starts, a later load faults, or a processor that
/// holds the trap back only for the first load traps. The instruction may
/// return to any of these addresses too, but it then also moves rsp, unless it
/// has loaded the rip and rsp that run it again, on the same stack.
#[cfg(target_arch = "x86_64")]
fn returned(regs: &Regs, start: &StepStart, at: u64, loads: &SsLoads) -> bool {
    (regs.rip != start.rip && regs.rip != at && !loads.contains(regs.rip)) || regs.rsp != start.rsp
}

/// Makes `own` the guest's TF after a step loaded flags that Linux did not
/// notice. Linux hides the TF it sets for stepping, and clears it on resume;
/// a TF set through PTRACE_SETREGS is the guest's, and a clear one leaves
/// only Linux's own.
#[cfg(target_arch = "x86_64")]
fn adopt_trap_flag(
    task: &mut Stopped,
    mut regs: Regs,
    own: bool,
) -> Result<(bool, Regs), TraceError> {
    if (regs.eflags & TRAP_FLAG != 0) != own {
        regs.eflags ^= TRAP_FLAG;
        task.setregs(&regs)?;
    }
    Ok((own, regs))
}

/// Guest memory access reports a tracee that has died with a plain ESRCH.
/// PTRACE_GETREGS reports it as `Died`, which the caller reaps.
#[cfg(target_arch = "x86_64")]
fn memory_error(task: &Stopped, err: Errno) -> TraceError {
    if err == Errno::ESRCH
        && let Err(died @ TraceError::Died(_)) = task.getregs()
    {
        return died;
    }
    TraceError::Errno(err)
}

/// Reads the guest byte at `addr`.
#[cfg(target_arch = "x86_64")]
fn read_byte(task: &Stopped, addr: u64) -> Result<u8, Errno> {
    Ok(read_aligned_word(task, addr & !7)?.to_ne_bytes()[(addr & 7) as usize])
}

/// Reads the aligned word at `addr` with PTRACE_PEEKDATA.
#[cfg(target_arch = "x86_64")]
fn read_aligned_word(task: &Stopped, addr: u64) -> Result<u64, Errno> {
    debug_assert_eq!(addr % 8, 0);
    let addr = Addr::<u64>::from_raw(addr as usize).ok_or(Errno::EFAULT)?;
    task.read_value(addr)
}

#[cfg(target_os = "linux")]
fn get_si_fd(signal: &libc::siginfo_t) -> libc::c_int {
    // This almost certainly broken for anything other than linux (glibc?).
    //
    // The `libc` crate doesn't expose these fields properly, because the
    // current version was released before union support, and `siginfo_t` is a
    // messy enum/union, making this super fragile.
    //
    // `libc` has an accessor system in place, but only for a few particular
    // signal types as of right now. We could submit a PR for SIGPOLL/SIGIO, but
    // until then, this is copies the currently used accessor idea.

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct sifields_sigpoll {
        si_band: libc::c_long,
        si_fd: libc::c_int,
    }
    #[repr(C)]
    union sifields {
        _align_pointer: *mut libc::c_void,
        sigpoll: sifields_sigpoll,
    }
    #[repr(C)]
    struct siginfo_f {
        _siginfo_base: [libc::c_int; 3],
        sifields: sifields,
        padding: [libc::c_int; 24],
    }

    // These compile to no-op or unconditional runtime panic, which is good,
    // because code not using timers continues to work.
    assert_eq!(
        core::mem::size_of::<siginfo_f>(),
        core::mem::size_of_val(signal),
    );
    assert_eq!(
        core::mem::align_of::<siginfo_f>(),
        core::mem::align_of_val(signal),
    );

    unsafe {
        (*(signal as *const _ as *const siginfo_f))
            .sifields
            .sigpoll
            .si_fd
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::ClockCounter;
    #[cfg(target_arch = "x86_64")]
    use super::PmuConfig;

    #[test]
    fn terminal_close_attempts_both_counters_after_cancellation_error() {
        use super::*;
        use crate::perf::terminal_close_tests;

        terminal_close_tests::reset_releases();
        let clock = terminal_close_tests::counter(terminal_close_tests::release_with_errors);
        let counter = terminal_close_tests::counter(terminal_close_tests::release_with_errors);
        let clock_fd = clock.raw_fd();
        let timer_fd = counter.raw_fd();
        let event = ActiveEvent::Precise {
            clock_target: 1,
            offset: 0,
        };
        let mut timer = Timer {
            inner: Some(TimerImpl {
                clock,
                timer: counter,
                event,
                timer_status: EventStatus::Scheduled,
                send_artificial_signal: true,
                artificial_signal_sent: false,
                overflow_period: None,
                overflow_recorded: false,
                programming_overflowed: false,
                initial_command: InitialCommand::Ordinary,
                held_initial_event: Some(event),
                interrupted: None,
                observed: None,
                notification_taken: false,
                disregarded_missed: None,
                armed_programming: None,
                kept_programming: None,
                resumed_programming: None,
                kept_programming_log: Vec::new(),
                fail_next_notification: None,
                preempted_overflow_counted: false,
                // A terminal close must not try to finalize the pending kick.
                guest_pid: Pid::from_raw(0),
                guest_tid: Tid::from_raw(0),
            }),
        };
        // The fixture owns real eventfds, not PMU fds. Their failed disable
        // produces a real cancellation error without interfering with release.
        assert_eq!(timer.cancel(), Err(Errno::ENOTTY));
        assert_eq!(
            timer.close_after_failure(),
            vec![
                ("ptrace clock munmap", Errno::EIO),
                ("ptrace clock close", Errno::EINTR),
                ("ptrace timer munmap", Errno::EIO),
                ("ptrace timer close", Errno::EINTR),
            ]
        );
        assert!(timer.inner.is_none());
        let releases = terminal_close_tests::releases();
        assert_eq!(releases.len(), 4);
        assert_eq!(releases[0].0, libc::SYS_munmap);
        assert_eq!(releases[1], (libc::SYS_close, clock_fd as u64));
        assert_eq!(releases[2].0, libc::SYS_munmap);
        assert_ne!(releases[0].1, releases[2].1);
        assert_eq!(releases[3], (libc::SYS_close, timer_fd as u64));
        assert!(timer.close_after_failure().is_empty());
        drop(timer);
        assert_eq!(terminal_close_tests::releases(), releases);
    }

    #[test]
    fn terminal_close_without_perf_resources_is_idempotent() {
        let mut timer = super::Timer { inner: None };
        assert!(timer.close_after_failure().is_empty());
        assert!(timer.close_after_failure().is_empty());
    }

    #[test]
    fn initial_command_requests_retire_without_physical_notification() {
        use reverie::Errno;
        use reverie::Pid;

        use super::ActiveEvent;
        use super::EventStatus;
        use super::InitialCommand;
        use super::TimerEventRequest;
        use super::TimerImpl;

        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let mut timer = TimerImpl::new(pid, tid, true).expect("control requires a working PMU");
        timer.fail_next_notification = Some(Errno::EIO);
        for (request, expected) in [
            (
                TimerEventRequest::Precise(1),
                ActiveEvent::Precise {
                    clock_target: 1,
                    offset: 0,
                },
            ),
            (
                TimerEventRequest::PreciseInstruction(4, 7),
                ActiveEvent::Precise {
                    clock_target: 4,
                    offset: 7,
                },
            ),
            (
                TimerEventRequest::Imprecise(1_000_000),
                ActiveEvent::Imprecise {
                    clock_min: 1_000_000,
                },
            ),
        ] {
            timer.request_event(request).unwrap();
            assert_eq!(timer.held_initial_event, Some(expected));
            assert_eq!(timer.event, expected);
            assert_eq!(timer.timer_status, EventStatus::Scheduled);
            timer.finalize_requests();
            assert!(!timer.send_artificial_signal);
            assert_eq!(timer.fail_next_notification, Some(Errno::EIO));
        }
        let retained = timer.held_initial_event;
        assert_eq!(
            timer.request_event(TimerEventRequest::Precise(0)),
            Err(Errno::EINVAL)
        );
        assert_eq!(timer.held_initial_event, retained);
        assert_eq!(timer.timer_status, EventStatus::Scheduled);
        timer.observe_event(&safeptrace::Event::Seccomp);
        assert_eq!(timer.timer_status, EventStatus::Armed);
        timer.begin_initial_exec();
        assert_eq!(timer.initial_command, InitialCommand::InitializingExec);
        assert_eq!(timer.held_initial_event, None);
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
        timer.begin_initial_exec();
        assert_eq!(timer.held_initial_event, None);
        // An internal request in backend initialization is a new held record,
        // not permission to reactivate the request just retired at exec.
        timer
            .request_event(TimerEventRequest::Imprecise(9))
            .unwrap();
        timer.finalize_requests();
        timer.finish_initial_exec();
        assert_eq!(timer.initial_command, InitialCommand::Ordinary);
        assert_eq!(timer.held_initial_event, None);
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
        assert!(!timer.send_artificial_signal);
        assert_eq!(timer.fail_next_notification, Some(Errno::EIO));
        assert_eq!(
            timer.request_event(TimerEventRequest::Precise(1)),
            Err(Errno::EIO)
        );
        assert_eq!(timer.fail_next_notification, None);
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
    }

    /// Takes the pending timer signal of the calling thread, which must have
    /// blocked it.
    fn take_timer_signal() -> Option<libc::siginfo_t> {
        let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, super::MARKER_SIGNAL as i32);
        }
        let signo = unsafe { libc::sigtimedwait(&set, &mut info, &timeout) };
        (signo == super::MARKER_SIGNAL as i32).then_some(info)
    }

    #[test]
    fn overflow_signal_provenance_requires_a_recorded_overflow() {
        use reverie::Pid;

        use super::TimerImpl;
        use crate::perf::do_branches;

        // The timer signals this thread; keep its notifications pending so the
        // test can take their real siginfo.
        let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, super::MARKER_SIGNAL as i32);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, core::ptr::null_mut()),
                0
            );
        }
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let mut timer = TimerImpl::new(pid, tid, false).expect("control requires a working PMU");
        assert_eq!(timer.timer.take_sample_records(), Some(0));
        const PERIOD: u64 = 10_000;

        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        let notification = take_timer_signal().expect("the counter overflowed");
        assert!(timer.owns_overflow_signal(&notification));
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(true));
        // A guest signal can have identical siginfo. With every overflow
        // consumed, it is not the timer's.
        assert!(timer.owns_overflow_signal(&notification));
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));

        // A new programming that has not overflowed owns nothing.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD / 2);
        timer.timer.disable().unwrap();
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));
        assert!(take_timer_signal_now().is_none());

        // An overflow whose notification is still pending survives both kinds
        // of reprogramming, and consuming it leaves the new programming armed.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        timer
            .prepare_notification(super::SINGLESTEP_TIMEOUT_RCBS)
            .unwrap();
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(true));
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));
        assert!(take_timer_signal().is_some());

        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        timer.prepare_notification(PERIOD).unwrap();
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(true));
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));
        assert!(take_timer_signal().is_some());
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(take_timer_signal().is_some());
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(true));

        // Consumption ends a programming that has passed its period, so no
        // notification of its cancelled timer event follows. This includes
        // consuming late, after several overflows, and with a period the
        // kernel may restart.
        for period in [PERIOD, PERIOD / 10] {
            timer.prepare_notification(period).unwrap();
            do_branches(period * 7 / 2);
            // The counter keeps running, so unlike a stopped tracee's, its
            // overflow interrupt can still be in flight. The kernel writes the
            // record before it queues the notification.
            assert!(wait_for_timer_signal_pending());
            assert_eq!(timer.consume_overflow_signal(&notification), Ok(true));
            let stopped_at = timer.timer.ctr_value().unwrap();
            do_branches(PERIOD * 3);
            assert_eq!(timer.timer.ctr_value(), Ok(stopped_at));
            assert!(take_timer_signal().is_some());
            assert!(take_timer_signal_now().is_none());
            assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));
        }

        // A counter can pass its period without the kernel handling the
        // overflow interrupt, for example when the interrupt arrives after the
        // thread is scheduled out. No notification exists. Raising the
        // hardware period produces the same counter state.
        timer.prepare_notification(PERIOD).unwrap();
        timer
            .timer
            .set_period(crate::perf::PerfCounter::DISABLE_SAMPLE_PERIOD)
            .unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(timer.timer.ctr_value().unwrap() >= PERIOD);
        assert!(take_timer_signal_now().is_none());
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));

        // Records expire unless the thread's pending signals hold a
        // notification with the timer's siginfo: signal number, code and
        // descriptor.
        let mut other_signo = notification;
        other_signo.si_signo = libc::SIGUSR1;
        // `tgkill` sends the timer's signal number with this code.
        let mut other_code = notification;
        other_code.si_code = libc::SI_TKILL;
        let mut other_fd = notification;
        set_si_fd(&mut other_fd, super::get_si_fd(&notification) + 1);
        assert!(!timer.owns_overflow_signal(&other_signo));
        assert!(!timer.owns_overflow_signal(&other_code));
        assert!(!timer.owns_overflow_signal(&other_fd));
        let others = [other_signo, other_code, other_fd];
        for pending in [&[other_signo][..], &[other_code], &[other_fd], &others, &[]] {
            timer.prepare_notification(PERIOD).unwrap();
            do_branches(PERIOD * 3);
            timer.timer.disable().unwrap();
            assert!(timer.has_overflow_records());
            timer.expire_overflow_records(&[other_signo, other_code, other_fd, notification]);
            assert!(timer.has_overflow_records());
            timer.expire_overflow_records(pending);
            assert!(!timer.has_overflow_records());
            assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));
            assert!(take_timer_signal().is_some());
        }

        // Without records, even a real notification is not consumed.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        let unrecorded = take_timer_signal().expect("the counter overflowed");
        timer.timer.unmap_sample_records();
        assert_eq!(timer.timer.take_sample_records(), None);
        assert!(timer.owns_overflow_signal(&unrecorded));
        assert_eq!(timer.consume_overflow_signal(&unrecorded), Ok(false));

        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, core::ptr::null_mut());
        }
    }

    #[test]
    fn a_notification_of_an_undecided_event_is_taken_not_discarded() {
        use reverie::Pid;

        use super::EventStatus;
        use super::OwnNotification;
        use super::TimerImpl;
        use super::Unfinished;
        use crate::perf::do_branches;

        let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, super::MARKER_SIGNAL as i32);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, core::ptr::null_mut()),
                0
            );
        }
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let mut timer = TimerImpl::new(pid, tid, false).expect("control requires a working PMU");
        assert_eq!(timer.timer.take_sample_records(), Some(0));
        const PERIOD: u64 = 10_000;

        // No stop has decided the event, as after a disregarded stop: the
        // notification is the event's own. It is not discarded as late, and
        // it is handed on exactly once.
        timer.timer_status = EventStatus::Scheduled;
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        let notification = take_timer_signal().expect("the counter overflowed");
        assert_eq!(timer.consume_overflow_signal(&notification), Ok(false));
        assert_eq!(
            timer.take_overflow_signal(&notification),
            Ok(Some(OwnNotification::Live))
        );
        assert!(matches!(
            timer.take_notification(),
            Some(Unfinished::Notification)
        ));
        assert!(timer.take_notification().is_none());
        // Taking it did not end the programming, which delivery does.
        assert_eq!(timer.overflow_period, Some(PERIOD));
        // Its overflow is consumed, so a guest signal with identical siginfo
        // is not the timer's.
        assert_eq!(timer.take_overflow_signal(&notification), Ok(None));
        assert!(timer.take_notification().is_none());

        // A new request or cancellation drops a notification taken for the
        // event it replaces.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(take_timer_signal().is_some());
        assert_eq!(
            timer.take_overflow_signal(&notification),
            Ok(Some(OwnNotification::Live))
        );
        timer.set_status(EventStatus::Scheduled);
        assert!(timer.take_notification().is_none());

        // Once a stop has decided the event, the notification is late: it is
        // consumed, which ends the programming, and nothing is handed on.
        for decided in [EventStatus::Armed, EventStatus::Cancelled] {
            timer.timer_status = decided;
            timer.prepare_notification(PERIOD).unwrap();
            do_branches(PERIOD * 3);
            timer.timer.disable().unwrap();
            assert!(take_timer_signal().is_some());
            assert_eq!(
                timer.take_overflow_signal(&notification),
                Ok(Some(OwnNotification::Late))
            );
            assert_eq!(timer.overflow_period, None);
            assert!(timer.take_notification().is_none());
        }

        // A programming that has not passed its period has no live
        // notification, and an overflow of an earlier programming is late.
        timer.timer_status = EventStatus::Scheduled;
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        timer.prepare_notification(PERIOD).unwrap();
        assert_eq!(
            timer.take_overflow_signal(&notification),
            Ok(Some(OwnNotification::Late))
        );
        assert!(take_timer_signal().is_some());
        assert!(timer.take_notification().is_none());

        // Nor does a programming that passed its period without an overflow
        // interrupt, even while an earlier programming's overflow is recorded
        // and unconsumed: the notification is the earlier programming's.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        timer.prepare_notification(PERIOD).unwrap();
        timer
            .timer
            .set_period(crate::perf::PerfCounter::DISABLE_SAMPLE_PERIOD)
            .unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert_eq!(timer.current_overflow(), Ok(true));
        let earlier = take_timer_signal().expect("the earlier programming overflowed");
        assert_eq!(
            timer.take_overflow_signal(&earlier),
            Ok(Some(OwnNotification::Late))
        );
        assert!(take_timer_signal_now().is_none());
        assert!(timer.take_notification().is_none());

        // Without records nothing is the timer's, so nothing is taken.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(take_timer_signal().is_some());
        timer.timer.unmap_sample_records();
        assert_eq!(timer.take_overflow_signal(&notification), Ok(None));
        assert!(timer.take_notification().is_none());

        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, core::ptr::null_mut());
        }
    }

    #[test]
    fn a_notification_is_lost_when_its_programming_passes_its_period_unrecorded() {
        use reverie::Pid;

        use super::EventStatus;
        use super::TimerImpl;
        use super::Unfinished;
        use crate::perf::PerfCounter;
        use crate::perf::do_branches;

        // Real overflows signal this thread; keep their notifications
        // pending rather than let them kill it.
        let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, super::MARKER_SIGNAL as i32);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, core::ptr::null_mut()),
                0
            );
        }
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let mut timer = TimerImpl::new(pid, tid, false).expect("control requires a working PMU");
        const PERIOD: u64 = 10_000;

        // Nothing is programmed.
        assert_eq!(timer.notification_lost(), Ok(false));

        // Raising the hardware period makes the counter pass its period
        // without an overflow, as the kernel's loss does. The notification is
        // lost only once the count has passed the period.
        timer.prepare_notification(PERIOD).unwrap();
        timer
            .timer
            .set_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .unwrap();
        do_branches(PERIOD / 2);
        timer.timer.disable().unwrap();
        assert!(timer.timer.ctr_value().unwrap() < PERIOD);
        assert_eq!(timer.notification_lost(), Ok(false));
        timer.tick_observed();
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        timer.timer.enable().unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(timer.timer.ctr_value().unwrap() >= PERIOD);
        assert_eq!(timer.notification_lost(), Ok(true));
        assert_eq!(timer.notification_lost(), Ok(true));
        // A disregarded stop hands such an event on, as it was before the
        // stop, to be taken up.
        timer.set_status(EventStatus::Scheduled);
        timer.tick_observed();
        assert_eq!(timer.timer_status, EventStatus::Armed);
        assert!(matches!(
            timer.disregard_stop(),
            Ok(Some(Unfinished::Notification))
        ));
        assert_eq!(timer.timer_status, EventStatus::Scheduled);
        // Taking it up ends the programming.
        timer.disable_timer_before_stepping();
        assert_eq!(timer.notification_lost(), Ok(false));
        timer.tick_observed();
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        assert!(take_timer_signal_now().is_none());

        // An overflow the kernel recorded is not lost, even once its
        // notification is consumed.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(take_timer_signal().is_some());
        assert_eq!(timer.notification_lost(), Ok(false));
        timer.mark_overflows_consumed();
        assert_eq!(timer.notification_lost(), Ok(false));

        // An earlier programming's overflow, recorded but not yet collected,
        // does not stand for the next programming's.
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(take_timer_signal().is_some());
        timer.prepare_notification(PERIOD).unwrap();
        timer
            .timer
            .set_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert_eq!(timer.notification_lost(), Ok(true));

        // A programming too short to program a notification loses none.
        timer
            .prepare_notification(super::SINGLESTEP_TIMEOUT_RCBS)
            .unwrap();
        assert_eq!(timer.notification_lost(), Ok(false));

        // Without records, an overflow cannot be told from a lost one.
        timer.prepare_notification(PERIOD).unwrap();
        timer
            .timer
            .set_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        timer.timer.unmap_sample_records();
        assert_eq!(timer.timer.take_sample_records(), None);
        assert_eq!(timer.notification_lost(), Ok(false));
        assert!(take_timer_signal_now().is_none());

        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, core::ptr::null_mut());
        }
    }

    #[test]
    fn a_stop_that_nothing_continues_keeps_the_event_only_before_the_period() {
        use reverie::Pid;

        use super::ClockCounter;
        use super::EventStatus;
        use super::InterruptedSteps;
        use super::Interruption;
        use super::MissedTarget;
        use super::TimerImpl;
        use crate::perf::do_branches;

        let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, super::MARKER_SIGNAL as i32);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, core::ptr::null_mut()),
                0
            );
        }
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let mut timer = TimerImpl::new(pid, tid, false).expect("control requires a working PMU");
        assert_eq!(timer.timer.take_sample_records(), Some(0));
        // The clock counts this thread, which runs while it is read; an
        // imprecise event keeps cancellation from reading it for a witness.
        timer.event = super::ActiveEvent::Imprecise { clock_min: 0 };
        const PERIOD: u64 = 10_000;
        // Short of its target, so that committing it records no skid
        // overshoot in the process-wide count other tests read.
        let missed = || MissedTarget {
            clock: PERIOD - 1,
            clock_target: PERIOD,
            offset: 0,
            stop: "test".into(),
            notification_queued: false,
        };

        // Before the period the stop leaves the event and its programming as
        // they were, and it remembers the delivery point it found reached
        // until something decides the event.
        timer.set_status(EventStatus::Scheduled);
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD / 2);
        timer.timer.disable().unwrap();
        assert!(timer.timer.ctr_value().unwrap() < PERIOD);
        timer.tick_observed();
        timer.observed.as_mut().unwrap().missed = Some(missed());
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        assert_eq!(timer.timer_status, EventStatus::Scheduled);
        assert_eq!(timer.overflow_period, Some(PERIOD));
        assert!(timer.disregarded_missed.is_some());
        // The next observed stop decides the event, and finds for itself
        // whether the delivery point was reached; so does a new request.
        timer.tick_observed();
        assert!(timer.disregarded_missed.is_none());
        timer.observed = None;
        timer.set_status(EventStatus::Scheduled);
        timer.tick_observed();
        timer.observed.as_mut().unwrap().missed = Some(missed());
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        timer.set_status(EventStatus::Scheduled);
        assert!(timer.disregarded_missed.is_none());
        // The thread's exit decides it, if nothing has.
        timer.tick_observed();
        timer.observed.as_mut().unwrap().missed = Some(missed());
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        timer.settle_at_exit();
        assert!(timer.disregarded_missed.is_none());

        // Past the period, whether or not the notification has arrived, the
        // event is cancelled and the programming ended.
        timer.set_status(EventStatus::Scheduled);
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(take_timer_signal().is_some());
        timer.tick_observed();
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
        assert_eq!(timer.overflow_period, None);
        assert!(timer.disregarded_missed.is_none());

        // So is an event whose single steps the stop interrupted, although
        // the steps have ended the programming. Steps run toward an event a
        // stop has armed.
        let steps = InterruptedSteps {
            steps: ClockCounter::new(PERIOD - 10, 0, PERIOD),
            target_instr: 0,
        };
        timer.set_status(EventStatus::Armed);
        timer.interrupted = Some(Interruption::At(steps));
        timer.tick_observed();
        assert_eq!(timer.current_overflow(), Ok(false));
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        assert_eq!(timer.timer_status, EventStatus::Cancelled);

        // With records, a stop during the steps hands them on; without
        // records it cancels the event, as a stop past the period does.
        timer.set_status(EventStatus::Armed);
        timer.interrupted = Some(Interruption::At(steps));
        timer.tick_observed();
        assert!(matches!(
            timer.disregard_stop(),
            Ok(Some(super::Unfinished::Steps(_)))
        ));
        assert_eq!(timer.timer_status, EventStatus::Armed);
        timer.timer.unmap_sample_records();
        timer.interrupted = Some(Interruption::At(steps));
        timer.tick_observed();
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
        // Without records a stop past the period, with no steps under way,
        // cancels a Scheduled event outright rather than leave it Armed as
        // the stop's tick does, so that retiring the event afterwards does
        // not record its delivery point a second time.
        timer.set_status(EventStatus::Scheduled);
        timer.prepare_notification(PERIOD).unwrap();
        do_branches(PERIOD * 3);
        timer.timer.disable().unwrap();
        assert!(take_timer_signal().is_some());
        timer.tick_observed();
        assert_eq!(timer.timer_status, EventStatus::Armed);
        timer.observed.as_mut().unwrap().missed = Some(missed());
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
        assert!(timer.disregarded_missed.is_none());

        // A precise event is decided by the guest's clock against its target
        // and the keep margin, which is the same on every processor, not by
        // the programming's period, which this processor's skid margin sets.
        // The programming here is far from its period at every stop. The
        // clock stops counting this thread, so that it can be read for the
        // precise event: a counter read while it counts can change between
        // the two reads a debug build compares.
        timer.clock.disable().unwrap();
        let keep_margin = super::get_pmu_config().keep_margin();
        let far = 1_000 * keep_margin;
        let precise = |timer: &TimerImpl, short: u64| super::ActiveEvent::Precise {
            clock_target: timer.read_clock() + short,
            offset: 0,
        };
        // Without records, a stop more than the keep margin short of the
        // target keeps the event; one within it cancels the event, although
        // the programming has not passed its period.
        timer.set_status(EventStatus::Scheduled);
        timer.prepare_notification(far).unwrap();
        timer.event = precise(&timer, keep_margin + 100_000);
        timer.tick_observed();
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        assert_eq!(timer.timer_status, EventStatus::Scheduled);
        timer.event = precise(&timer, keep_margin - 1_000);
        timer.tick_observed();
        assert_eq!(timer.current_overflow(), Ok(false));
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
        // So does a stop that nothing continues, with records too.
        assert_eq!(timer.timer.map_sample_records(), Ok(()));
        timer.set_status(EventStatus::Scheduled);
        timer.prepare_notification(far).unwrap();
        timer.event = precise(&timer, keep_margin + 100_000);
        timer.tick_observed();
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        assert_eq!(timer.timer_status, EventStatus::Scheduled);
        assert_eq!(timer.overflow_period, Some(far));
        timer.event = precise(&timer, keep_margin - 1_000);
        timer.tick_observed();
        assert_eq!(timer.current_overflow(), Ok(false));
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        assert_eq!(timer.timer_status, EventStatus::Cancelled);
        assert_eq!(timer.overflow_period, None);
        timer.event = super::ActiveEvent::Imprecise { clock_min: 0 };
        timer.timer.unmap_sample_records();

        assert!(take_timer_signal_now().is_none());
        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, core::ptr::null_mut());
        }
    }

    /// A thread of this process that retires the conditional branches it is
    /// asked for, and otherwise waits blocked in a `read`, where its counters
    /// hold still, as a stopped guest thread's do.
    struct BranchThread {
        tid: reverie::Tid,
        requests: libc::c_int,
        done: libc::c_int,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl BranchThread {
        /// Starts the thread, which inherits the caller's signal mask.
        fn spawn() -> Self {
            let pipe = || {
                let mut fds = [0; 2];
                assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
                fds
            };
            let ([requests_read, requests], [done, done_write]) = (pipe(), pipe());
            let (sender, receiver) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                sender
                    .send(unsafe { libc::syscall(libc::SYS_gettid) } as i32)
                    .unwrap();
                loop {
                    let mut request = [0u8; 8];
                    let read = unsafe { libc::read(requests_read, request.as_mut_ptr().cast(), 8) };
                    assert_eq!(read, 8);
                    let branches = u64::from_ne_bytes(request);
                    if branches == 0 {
                        break;
                    }
                    crate::perf::do_branches(branches);
                    assert_eq!(
                        unsafe { libc::write(done_write, [1u8].as_ptr().cast(), 1) },
                        1
                    );
                }
                unsafe {
                    libc::close(requests_read);
                    libc::close(done_write);
                }
            });
            let this = Self {
                tid: reverie::Tid::from_raw(receiver.recv().unwrap()),
                requests,
                done,
                thread: Some(thread),
            };
            this.wait_until_blocked();
            this
        }

        /// Waits until the thread is blocked in its `read` (syscall 0 on
        /// x86-64), after which it retires no branch until it is asked to.
        fn wait_until_blocked(&self) {
            let path = format!("/proc/self/task/{}/syscall", self.tid);
            for _ in 0..10_000 {
                let syscall = std::fs::read_to_string(&path).unwrap();
                if syscall.starts_with(&format!("{} ", libc::SYS_read)) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            panic!("the branch thread did not block in its read");
        }

        /// Makes the thread retire `branches` (at least 1) conditional
        /// branches, and a few of its loop's, and waits until it is blocked
        /// again.
        fn run(&self, branches: u64) {
            assert!(branches > 0);
            let request = branches.to_ne_bytes();
            assert_eq!(
                unsafe { libc::write(self.requests, request.as_ptr().cast(), 8) },
                8
            );
            let mut done = [0u8; 1];
            assert_eq!(
                unsafe { libc::read(self.done, done.as_mut_ptr().cast(), 1) },
                1
            );
            self.wait_until_blocked();
        }
    }

    impl Drop for BranchThread {
        fn drop(&mut self) {
            let stop = 0u64.to_ne_bytes();
            unsafe { libc::write(self.requests, stop.as_ptr().cast(), 8) };
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            unsafe {
                libc::close(self.requests);
                libc::close(self.done);
            }
        }
    }

    // A disregarded stop that keeps a scheduled precise event leaves the
    // event's PMU programming as the request made it: no call has changed
    // the counter's programming since the request, and the counter overflows
    // at the clock at which the request programmed it to, the target less
    // the skid margin, so the notification still comes a skid margin before
    // the target. Both ways a Timer disregards a stop check this and count
    // the check (`TimerImpl::check_kept_programming`), and the thread's next
    // stop, or the event's next request or retirement, checks again that no
    // call changed the programming (`TimerImpl::recheck_kept_programming`).
    // The checks tell a stop that re-programmed the counter, reset it,
    // changed only its period, disabled it or ended its programming, or
    // whose later handling did any of these, from one that did not. The
    // guest is a thread of this process blocked in a read between steps, so
    // its counters hold still whenever they are read, and every clock here
    // is exact.
    #[test]
    fn a_kept_event_keeps_the_overflow_point_its_request_programmed() {
        use reverie::Pid;

        use super::ArmedProgramming;
        use super::EventStatus;
        use super::KeptProgramming;
        use super::Timer;
        use super::TimerEventRequest;
        use super::TimerImpl;

        // A notification is not expected, but one must not kill the process.
        let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, super::MARKER_SIGNAL as i32);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, core::ptr::null_mut()),
                0
            );
        }
        let guest = BranchThread::spawn();
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let mut timer = Timer {
            inner: Some(
                TimerImpl::new(pid, guest.tid, false).expect("control requires a working PMU"),
            ),
        };
        guest.run(1_000);
        const TARGET: u64 = 1_000_000;
        let config = super::get_pmu_config();
        let period = TARGET - config.skid_margin();
        fn inner(timer: &mut Timer) -> &mut TimerImpl {
            timer.inner.as_mut().unwrap()
        }
        fn take_log(timer: &mut Timer) -> Vec<KeptProgramming> {
            std::mem::take(&mut inner(timer).kept_programming_log)
        }
        // Requests the event, and returns what a check of its programming
        // finds after a stop that leaves it as it is.
        let request = |timer: &mut Timer| {
            let before = inner(timer).timer.programmings();
            timer
                .request_event(TimerEventRequest::Precise(TARGET))
                .unwrap();
            let timer = inner(timer);
            let clock = timer.read_clock();
            assert_eq!(timer.overflow_period, Some(period));
            // A reset, a period and an enable.
            assert_eq!(timer.timer.programmings(), before + 3);
            assert_eq!(
                timer.armed_programming,
                Some(ArmedProgramming {
                    overflow_point: clock + period,
                    programmings: before + 3,
                })
            );
            KeptProgramming {
                target: clock + TARGET,
                armed: clock + period,
                found: Some(clock + period),
                reprogrammed: 0,
                at_next_stop: false,
            }
        };
        // What a recheck finds when nothing changed the programming.
        let rechecked = |armed: KeptProgramming| KeptProgramming {
            found: None,
            at_next_stop: true,
            ..armed
        };

        // A stop that nothing continues keeps the event short of its keep
        // point, and so does a stop whose unfinished work is handed on. The
        // next stop checks each again, and so does the next request.
        let armed = request(&mut timer);
        guest.run(TARGET / 4);
        inner(&mut timer).tick_observed();
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        assert_eq!(inner(&mut timer).timer_status, EventStatus::Scheduled);
        assert_eq!(take_log(&mut timer), [armed]);
        guest.run(TARGET / 4);
        inner(&mut timer).tick_observed();
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        assert_eq!(inner(&mut timer).timer_status, EventStatus::Scheduled);
        assert_eq!(take_log(&mut timer), [rechecked(armed), armed]);
        assert!(!armed.changed() && !rechecked(armed).changed());
        request(&mut timer);
        assert_eq!(take_log(&mut timer), [rechecked(armed)]);

        // The check sees a keeping stop that re-programs the counter for its
        // period: the event would then fire that period after the stop.
        let armed = request(&mut timer);
        guest.run(1_000);
        let stop_clock = inner(&mut timer).read_clock();
        inner(&mut timer).tick_observed();
        assert!(matches!(inner(&mut timer).disregard_stop(), Ok(None)));
        inner(&mut timer).prepare_notification(period).unwrap();
        inner(&mut timer).check_kept_programming(true);
        let check = KeptProgramming {
            found: Some(stop_clock + period),
            reprogrammed: 3,
            ..armed
        };
        assert_eq!(take_log(&mut timer), [check]);
        assert!(check.changed());
        assert_ne!(stop_clock + period, armed.armed);
        // A changed programming is not checked again.
        assert_eq!(inner(&mut timer).resumed_programming, None);
        // And one that resets it.
        let armed = request(&mut timer);
        guest.run(1_000);
        let stop_clock = inner(&mut timer).read_clock();
        inner(&mut timer).tick_observed();
        assert!(matches!(inner(&mut timer).disregard_stop(), Ok(None)));
        inner(&mut timer).timer.reset().unwrap();
        inner(&mut timer).check_kept_programming(true);
        let check = KeptProgramming {
            found: Some(stop_clock + period),
            reprogrammed: 1,
            ..armed
        };
        assert_eq!(take_log(&mut timer), [check]);
        assert!(check.changed());
        // And one that only changes its period, which re-arms the counter
        // without moving its count, so the overflow point read from the count
        // is the one the request programmed: only the calls show it.
        let armed = request(&mut timer);
        guest.run(1_000);
        inner(&mut timer).tick_observed();
        assert!(matches!(inner(&mut timer).disregard_stop(), Ok(None)));
        inner(&mut timer).timer.set_period(period).unwrap();
        inner(&mut timer).check_kept_programming(true);
        let check = KeptProgramming {
            reprogrammed: 1,
            ..armed
        };
        assert_eq!(take_log(&mut timer), [check]);
        assert_eq!(check.found, Some(check.armed));
        assert!(check.changed());
        // And one that disables it but leaves its period recorded, which the
        // count cannot show either.
        let armed = request(&mut timer);
        inner(&mut timer).tick_observed();
        assert!(matches!(inner(&mut timer).disregard_stop(), Ok(None)));
        inner(&mut timer).timer.disable().unwrap();
        inner(&mut timer).check_kept_programming(true);
        let check = KeptProgramming {
            reprogrammed: 1,
            ..armed
        };
        assert_eq!(take_log(&mut timer), [check]);
        assert!(check.changed());
        // And one that ends it.
        let armed = request(&mut timer);
        inner(&mut timer).tick_observed();
        assert!(matches!(inner(&mut timer).disregard_stop(), Ok(None)));
        inner(&mut timer).timer.disable().unwrap();
        inner(&mut timer).overflow_period = None;
        inner(&mut timer).check_kept_programming(true);
        let check = KeptProgramming {
            found: None,
            reprogrammed: 1,
            ..armed
        };
        assert_eq!(take_log(&mut timer), [check]);
        assert!(check.changed());

        // The next stop sees what the stop's handling did to the counter
        // after the stop was disregarded and checked, here a disable.
        let armed = request(&mut timer);
        guest.run(1_000);
        inner(&mut timer).tick_observed();
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        assert_eq!(take_log(&mut timer), [armed]);
        assert_eq!(timer.cancel(), Ok(()));
        guest.run(1_000);
        inner(&mut timer).tick_observed();
        let recheck = KeptProgramming {
            reprogrammed: 1,
            ..rechecked(armed)
        };
        assert_eq!(take_log(&mut timer), [recheck]);
        assert!(recheck.changed());

        // Retiring a kept event checks it again first, so the retirement's
        // own disable is not taken for a change.
        let armed = request(&mut timer);
        guest.run(1_000);
        inner(&mut timer).tick_observed();
        assert!(matches!(timer.disregard_stop(), Ok(None)));
        inner(&mut timer).retire().unwrap();
        assert_eq!(take_log(&mut timer), [armed, rechecked(armed)]);
        assert_eq!(inner(&mut timer).resumed_programming, None);

        // A stop at the keep point cancels the event, and checks nothing.
        request(&mut timer);
        guest.run(TARGET - config.keep_margin());
        inner(&mut timer).tick_observed();
        assert_eq!(timer.disregard_stop_before_period(), Ok(()));
        assert_eq!(inner(&mut timer).timer_status, EventStatus::Cancelled);
        assert_eq!(take_log(&mut timer), []);
        assert_eq!(inner(&mut timer).kept_programming, None);
        assert_eq!(inner(&mut timer).resumed_programming, None);

        assert_eq!(timer.cancel(), Ok(()));
        drop(timer);
        drop(guest);
        // A notification of an overflow at the keep point, if any, went to
        // the branch thread, which has exited.
        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, core::ptr::null_mut());
        }
    }

    // A stop that finds a precise event's delivery point reached notes
    // whether the event's own notification was queued at the stop: only if
    // the kernel recorded an overflow of the current programming, and the
    // pending signals read at the stop hold its notification. A programming
    // that has not overflowed, a notification that has left the queue, and
    // an overflow without records are never noted as queued, so a lost
    // notification is never taken for one held back.
    #[test]
    fn a_stop_past_the_target_notes_whether_the_notification_is_queued() {
        use reverie::Pid;

        use super::EventStatus;
        use super::TimerImpl;
        use crate::perf::do_branches;

        let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, super::MARKER_SIGNAL as i32);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, core::ptr::null_mut()),
                0
            );
        }
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let mut timer = TimerImpl::new(pid, tid, false).expect("control requires a working PMU");
        assert_eq!(timer.timer.take_sample_records(), Some(0));
        // The clock stops counting this thread, so that it can be read for
        // the precise event (see
        // `a_stop_that_nothing_continues_keeps_the_event_only_before_the_period`).
        timer.clock.disable().unwrap();
        const PERIOD: u64 = 10_000;
        let stop = super::TraceEvent::Signal(super::Signal::SIGUSR1);
        // Programs the timer for `PERIOD`, runs `branches`, and observes a
        // stop at the event's target. Returns what the stop noted.
        let observe = |timer: &mut TimerImpl, branches: u64| {
            timer.set_status(EventStatus::Scheduled);
            timer.prepare_notification(PERIOD).unwrap();
            do_branches(branches);
            timer.timer.disable().unwrap();
            timer.event = super::ActiveEvent::Precise {
                clock_target: timer.read_clock(),
                offset: 0,
            };
            timer.observe_event(&stop);
            queued(timer)
        };
        fn queued(timer: &TimerImpl) -> bool {
            timer
                .observed
                .as_ref()
                .and_then(|observed| observed.missed.as_ref())
                .expect("the stop must find the delivery point reached")
                .notification_queued
        }

        // The counter overflowed, and its notification is pending.
        assert!(observe(&mut timer, PERIOD * 3));
        let notification = take_timer_signal().expect("the counter overflowed");
        assert!(timer.owns_overflow_signal(&notification));
        // The stop's pending signals hold the notification: it stays queued.
        timer.expire_overflow_records(&[notification]);
        assert!(queued(&timer));
        // They do not, as when the guest dequeued it: it is not.
        timer.expire_overflow_records(&[]);
        assert!(!queued(&timer));
        // Nothing may commit the missed target, which would count a skid
        // overshoot in the process-wide count that other tests read.
        timer.observed = None;

        // The programming has not overflowed, so nothing is queued, whatever
        // the pending signals hold.
        assert!(!observe(&mut timer, PERIOD / 2));
        timer.expire_overflow_records(&[notification]);
        assert!(!queued(&timer));
        timer.observed = None;

        // An earlier programming overflowed, and its record survives the
        // reprogramming unconsumed, with its notification still pending.
        // The current programming has not overflowed, so its own
        // notification is not queued: neither at the stop, nor once the
        // pending signals, which hold the earlier one, are read.
        assert!(observe(&mut timer, PERIOD * 3));
        timer.observed = None;
        assert!(!observe(&mut timer, PERIOD / 2));
        assert!(timer.overflow_recorded, "the earlier record is unconsumed");
        assert!(!timer.programming_overflowed);
        let earlier = take_timer_signal().expect("the earlier programming overflowed");
        timer.expire_overflow_records(&[earlier]);
        assert!(
            timer.overflow_recorded,
            "the earlier notification is pending"
        );
        assert!(!queued(&timer));
        timer.expire_overflow_records(&[]);
        timer.observed = None;

        // Without records an overflow cannot be told from a lost one.
        timer.timer.unmap_sample_records();
        assert!(!observe(&mut timer, PERIOD * 3));
        assert!(take_timer_signal().is_some(), "the counter overflowed");
        timer.observed = None;
        timer.set_status(EventStatus::Cancelled);
        timer.event = super::ActiveEvent::Imprecise { clock_min: 0 };

        assert!(take_timer_signal_now().is_none());
        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, core::ptr::null_mut());
        }
    }

    /// Overwrite `si_fd`, at the offset `get_si_fd` reads.
    fn set_si_fd(signal: &mut libc::siginfo_t, fd: libc::c_int) {
        // Three `int`s, then the pointer-aligned union whose SIGPOLL member
        // is `{ long si_band; int si_fd; }`.
        let offset =
            core::mem::size_of::<*const libc::c_void>() * 2 + core::mem::size_of::<libc::c_long>();
        unsafe {
            (signal as *mut libc::siginfo_t)
                .cast::<u8>()
                .add(offset)
                .cast::<libc::c_int>()
                .write_unaligned(fd);
        }
        assert_eq!(super::get_si_fd(signal), fd);
    }

    #[test]
    fn preempt_rt_is_read_from_the_kernel_version() {
        use super::version_is_preempt_rt;
        assert!(version_is_preempt_rt(
            "#1 SMP PREEMPT_RT Mon Aug 24 01:30:09 PDT 2026"
        ));
        assert!(version_is_preempt_rt("#1 PREEMPT_RT"));
        assert!(!version_is_preempt_rt(
            "#1 SMP PREEMPT Mon Aug 24 01:30:09 PDT 2026"
        ));
        assert!(!version_is_preempt_rt(
            "#1 SMP PREEMPT_DYNAMIC Mon Aug 24 01:30:09 PDT 2026"
        ));
        assert!(!version_is_preempt_rt("#1 SMP PREEMPT_RTX"));
        assert!(!version_is_preempt_rt(""));
        // A build version of 49 digits cuts the word of a PREEMPT_RT kernel
        // at the 64-byte limit.
        let cut = format!("#{} SMP PREEMPT_R", "1".repeat(49));
        assert_eq!(cut.len(), 64);
        assert!(version_is_preempt_rt(&cut));
        // One digit less keeps the word.
        let whole = format!("#{} SMP PREEMPT_RT", "1".repeat(48));
        assert_eq!(whole.len(), 64);
        assert!(version_is_preempt_rt(&whole));
        let short = format!("#{} SMP PREEMPT_DYNAMIC", "1".repeat(42));
        assert_eq!(short.len(), 63);
        assert!(!version_is_preempt_rt(&short));
    }

    /// Wait up to five seconds for a timer notification to be pending,
    /// without taking it.
    fn wait_for_timer_signal_pending() -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(5) {
            let mut pending: libc::sigset_t = unsafe { core::mem::zeroed() };
            unsafe { libc::sigpending(&mut pending) };
            if unsafe { libc::sigismember(&pending, super::MARKER_SIGNAL as i32) } == 1 {
                return true;
            }
            std::hint::spin_loop();
        }
        false
    }

    fn take_timer_signal_now() -> Option<libc::siginfo_t> {
        let mut pending: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe { libc::sigpending(&mut pending) };
        if unsafe { libc::sigismember(&pending, super::MARKER_SIGNAL as i32) } == 1 {
            take_timer_signal()
        } else {
            None
        }
    }

    // The keep margin must be the same on every processor in the table, and
    // cover each one's own skid margin and artificial single steps, so that a
    // stop that nothing continues keeps or cancels an event at the same guest
    // clock on every host, and never keeps it past a host's period.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_keep_margin_is_the_same_on_every_processor_in_the_table() {
        use super::LARGEST_TABLE_SKID_MARGIN;
        use super::SINGLESTEP_TIMEOUT_RCBS;

        let mut margins = std::collections::BTreeSet::new();
        for family in 0..=u8::MAX {
            for model in 0..=u8::MAX {
                let Some(config) = PmuConfig::try_from_family_model(family, model) else {
                    continue;
                };
                margins.insert(config.skid_margin());
                assert_eq!(
                    config.keep_margin(),
                    LARGEST_TABLE_SKID_MARGIN + SINGLESTEP_TIMEOUT_RCBS,
                    "family {family:#x} model {model:#x}"
                );
                assert!(config.keep_margin() >= config.max_single_step_count());
                for skid in [0, 1, 100, 1_000, LARGEST_TABLE_SKID_MARGIN] {
                    assert_eq!(
                        config.clone().with_skid_margin_override(skid).keep_margin(),
                        LARGEST_TABLE_SKID_MARGIN + SINGLESTEP_TIMEOUT_RCBS,
                        "family {family:#x} model {model:#x} override {skid}"
                    );
                }
                // Only an override above the table's largest moves it, to
                // stay at or before the period.
                let over = config.with_skid_margin_override(2 * LARGEST_TABLE_SKID_MARGIN);
                assert_eq!(
                    over.keep_margin(),
                    2 * LARGEST_TABLE_SKID_MARGIN + SINGLESTEP_TIMEOUT_RCBS
                );
                assert_eq!(over.keep_margin(), over.max_single_step_count());
            }
        }
        assert_eq!(
            margins.last().copied(),
            Some(LARGEST_TABLE_SKID_MARGIN),
            "the largest margin in the table: {margins:?}"
        );
        assert!(margins.len() > 1, "{margins:?}");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn amd_epyc_9d85_uses_reduced_skid_margin() {
        let config = PmuConfig::from_family_model(0x1A, 0x11);
        assert_eq!(config.raw_rcb_event(), 0x5100d1);
        assert_eq!(config.skid_margin(), 1_000);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn amd_family_19h_model_a0h_uses_reduced_skid_margin() {
        let config = PmuConfig::from_family_model(0x19, 0xA0);
        assert_eq!(config.raw_rcb_event(), 0x5100d1);
        assert_eq!(config.skid_margin(), 1_000);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn unknown_cpu_is_unavailable_to_fallible_in_guest_clock() {
        assert_eq!(PmuConfig::try_from_family_model(0x06, 0xCF), None);
        assert_eq!(PmuConfig::try_from_family_model(0xFF, 0x01), None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn other_amd_cpus_keep_default_skid_margin() {
        for (family, model) in [
            (0x17, 0x71),
            (0x19, 0x61),
            (0x19, 0x9F),
            (0x19, 0xA1),
            (0x1A, 0x20),
        ] {
            let config = PmuConfig::from_family_model(family, model);
            assert_eq!(config.raw_rcb_event(), 0x5100d1);
            assert_eq!(config.skid_margin(), 10_000);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn explicit_skid_margin_overrides_processor_default() {
        let config = PmuConfig::from_family_model(0x1A, 0x11).with_skid_margin_override(500);

        assert_eq!(config.raw_rcb_event(), 0x5100d1);
        assert_eq!(config.skid_margin(), 500);
        assert_eq!(config.max_single_step_count(), 505);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn zero_skid_margin_forces_interrupt_at_target() {
        // The force-skid witness sets REVERIE_SKID_MARGIN_OVERRIDE=0. That path
        // runs through `with_skid_margin_override(0)`; assert the invariant it
        // relies on: a zero margin schedules the overflow interrupt *at* the
        // target RCB (request_event uses `ticks - skid_margin()`), so any
        // natural positive skid overshoots and trips the marker. Kept
        // env-free because process env is not thread-safe under the parallel
        // test runner.
        let config = PmuConfig::from_family_model(0x1A, 0x11).with_skid_margin_override(0);
        assert_eq!(config.skid_margin(), 0);
        // max_single_step_count() == skid_margin() + SINGLESTEP_TIMEOUT_RCBS (5).
        assert_eq!(config.max_single_step_count(), 5);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn skid_overshoot_marker_has_canonical_shape() {
        use super::SKID_OVERSHOOT_MARKER;
        // EPYC 9D85: skid margin 1000. Overshoot of 33_500 (the measured
        // baseline outlier) landing 500 RCB past a target of 33_000.
        let config = PmuConfig::from_family_model(0x1A, 0x11);
        let line = config.format_skid_overshoot_marker(33_500, 33_000);
        assert_eq!(
            line,
            format!(
                "{} rcb_actual=33500 rcb_target=33000 skid_margin=1000 overshoot=500",
                SKID_OVERSHOOT_MARKER
            )
        );
        // The token is what a retry harness greps for; keep it stable.
        assert!(line.starts_with(SKID_OVERSHOOT_MARKER));
        assert_eq!(SKID_OVERSHOOT_MARKER, "HERMIT_SKID_OVERSHOOT");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn skid_overshoot_marker_overshoot_is_saturating() {
        // A non-overshoot call (actual <= target) must never underflow.
        let config = PmuConfig::from_family_model(0x1A, 0x11);
        let line = config.format_skid_overshoot_marker(100, 200);
        assert!(line.contains("overshoot=0"));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn overshoot_decision_records_witness_counts_and_attributes_per_run() {
        // Drives real (rcb_actual, rcb_target) pairs through the *same*
        // decision-and-record method the supervisor calls in
        // `attempt_single_step`, and observes the process-global witness
        // counter — proving the behaviour (a genuine overshoot is recorded),
        // not merely the marker arithmetic. This test is the only direct
        // writer of the witness counter in this test binary, so draining
        // residue first makes it order-independent; env is untouched, so it is
        // parallel-safe. The real-guest precise timer tests here write it only
        // if an interrupt arrives beyond the skid margin, which none provokes.
        let _ = reverie::take_skid_overshoot_count();

        // The exact CPU is irrelevant to the decision, which keys only on
        // `actual > target`; use EPYC 9D85 (default margin 1000).
        let config = PmuConfig::from_family_model(0x1A, 0x11);

        // --- Negative bracket: a non-overshoot must record nothing. ---
        // Interrupt delivered *at* the target, and *before* it.
        assert!(!config.record_overshoot_if_past_target(33_000, 33_000));
        assert!(!config.record_overshoot_if_past_target(32_500, 33_000));
        assert_eq!(
            reverie::take_skid_overshoot_count(),
            0,
            "no overshoot occurred, so the witness must be empty"
        );

        // --- Positive bracket: a genuine overshoot records exactly once. ---
        // 500 RCB past target: a real skid past the margin.
        assert!(config.record_overshoot_if_past_target(33_500, 33_000));
        assert_eq!(
            reverie::take_skid_overshoot_count(),
            1,
            "one real overshoot must record exactly one witness event"
        );

        // --- Counting: N genuine overshoots in one run count to N, and only
        // genuine ones are counted. Models the heavy-tailed skid (p99 < 1000
        // RCB, rare outliers into the tens of thousands). ---
        let overshoots = [1u64, 500, 10_000, 47_311];
        for &past in &overshoots {
            assert!(config.record_overshoot_if_past_target(33_000 + past, 33_000));
        }
        // Interleave a non-overshoot to prove it is not counted.
        assert!(!config.record_overshoot_if_past_target(33_000, 33_000));
        assert_eq!(
            reverie::take_skid_overshoot_count(),
            overshoots.len() as u64,
            "every genuine overshoot in run A must be counted, and only those"
        );

        // --- Per-run attribution: `take` reset makes runs disjoint, so a
        // second verify run sees only its own overshoots and run A's count does
        // not leak in. ---
        assert!(config.record_overshoot_if_past_target(33_001, 33_000));
        assert!(config.record_overshoot_if_past_target(90_000, 33_000));
        assert_eq!(
            reverie::take_skid_overshoot_count(),
            2,
            "run B is attributed only its own two overshoots"
        );
        // A run with zero overshoots (the common case) is attributed zero.
        assert_eq!(reverie::take_skid_overshoot_count(), 0);

        // --- An event overtaken by another stop is lost, so reaching the
        // delivery point exactly already counts. It stays in this test so the
        // witness counter keeps a single direct writer. ---
        assert!(!config.record_missed_if_target_reached(32_999, 33_000, 0));
        assert_eq!(reverie::take_skid_overshoot_count(), 0);
        assert!(config.record_missed_if_target_reached(33_000, 33_000, 0));
        assert_eq!(reverie::take_skid_overshoot_count(), 1);
        assert!(config.record_missed_if_target_reached(33_001, 33_000, 0));
        assert_eq!(reverie::take_skid_overshoot_count(), 1);
        // With an instruction offset, the branches past the target must
        // cover the offset: each is at least one instruction, while one
        // branch past the target may be far short of the delivery point.
        assert!(!config.record_missed_if_target_reached(32_999, 33_000, 7));
        assert!(!config.record_missed_if_target_reached(33_000, 33_000, 7));
        assert!(!config.record_missed_if_target_reached(33_001, 33_000, 7));
        assert!(!config.record_missed_if_target_reached(33_006, 33_000, 7));
        assert_eq!(reverie::take_skid_overshoot_count(), 0);
        assert!(config.record_missed_if_target_reached(33_007, 33_000, 7));
        assert_eq!(reverie::take_skid_overshoot_count(), 1);
        assert!(config.record_missed_if_target_reached(66_000, 33_000, 7));
        assert_eq!(reverie::take_skid_overshoot_count(), 1);
        // The comparison cannot wrap at the top of the range.
        assert!(!config.record_missed_if_target_reached(33_001, 33_000, u64::MAX));
        assert_eq!(reverie::take_skid_overshoot_count(), 0);
        assert!(config.record_missed_if_target_reached(u64::MAX, 0, u64::MAX));
        assert_eq!(reverie::take_skid_overshoot_count(), 1);
    }

    #[test_case(ClockCounter::new(0, 0, 10), 0, 1, Some(true))]
    #[test_case(ClockCounter::new(2, 100, 200), 3, 0, Some(true))]
    #[test_case(ClockCounter::new(1, 10, 200), 1, 11, Some(true))]
    #[test_case(ClockCounter::new(2, 100, 2), 3, 0, None)]
    #[test_case(ClockCounter::new(4, 4, 4), 4, 5, Some(true))]
    #[test_case(ClockCounter::new(4, 4, 4), 4, 3, Some(false))]
    #[test_case(ClockCounter::new(4, 4, 4), 4, 4, Some(false))]
    fn test_clock_counter_is_behind(
        counter: ClockCounter,
        target_rcb: u64,
        target_instr: u64,
        expected: Option<bool>,
    ) {
        assert_eq!(counter.is_behind(target_rcb, target_instr), expected);
    }

    #[test_case(ClockCounter::new(0, 0, 0), 0, (0, 1))]
    #[test_case(ClockCounter::new(0, 1, 0), 1, (0, 2))]
    #[test_case(ClockCounter::new(0, 1, 0), 2, (0, 2))]
    #[test_case(ClockCounter::new(0, 1, 1), 0, (0, 2))]
    #[test_case(ClockCounter::new(0, 1, 1), 1, (1, 0))]
    #[test_case(ClockCounter::new(0, 1, 1), 2, (2, 0))]
    #[test_case(ClockCounter::new(0, 1, 1), 3, (3, 0))]
    #[test_case(ClockCounter::new(10, 0, 11), 10, (10, 1))]
    #[test_case(ClockCounter::new(10, 1, 11), 10, (10, 2))]
    #[test_case(ClockCounter::new(10, 1, 11), 11, (11, 0))]
    #[test_case(ClockCounter::new(10, 1, 11), 12, (12, 0))]
    fn test_increment_counter_with_clock(
        mut counter: ClockCounter,
        new_clock: u64,
        expected: (u64, u64),
    ) {
        counter.single_step_with_clock(new_clock);
        assert_eq!((counter.rcbs, counter.instr), expected);
    }

    /// Where the decoder tests place their code.
    #[cfg(target_arch = "x86_64")]
    const BASE: u64 = 0x1000;

    #[cfg(target_arch = "x86_64")]
    fn decode(code: &[u8]) -> super::FlagsInstruction {
        super::decode_flags_instruction(BASE, &mut |addr| {
            let offset = usize::try_from(addr.checked_sub(BASE)?).ok()?;
            code.get(offset).copied()
        })
    }

    /// The loads of SS at the given offsets from `BASE`.
    #[cfg(target_arch = "x86_64")]
    fn loads(offsets: &[u64]) -> super::SsLoads {
        let mut loads = super::SsLoads::NONE;
        for offset in offsets {
            loads.addrs[loads.len] = BASE + offset;
            loads.len += 1;
        }
        loads
    }

    /// `mov ss, bx`.
    #[cfg(target_arch = "x86_64")]
    const MOV_SS: [u8; 2] = [0x8e, 0xd3];

    #[cfg(target_arch = "x86_64")]
    fn after_loads(count: usize, instruction: &[u8]) -> Vec<u8> {
        let mut code = MOV_SS.repeat(count);
        code.extend_from_slice(instruction);
        code
    }

    // One step runs a chain of loads of SS and the instruction after it, which
    // decides what the step leaks and how it reports.
    #[cfg(target_arch = "x86_64")]
    #[test_case(0, &[0x0f, 0x05] => (0, 2); "syscall")]
    #[test_case(1, &[0x0f, 0x05] => (2, 4); "syscall after one load")]
    #[test_case(2, &[0x0f, 0x05] => (4, 6); "syscall after two loads")]
    #[test_case(4, &[0x0f, 0x05] => (8, 10); "syscall after four loads")]
    #[test_case(2, &[0x48, 0x0f, 0x05] => (4, 7); "syscall with REX after two loads")]
    fn decodes_syscall_after_loads_of_ss(count: usize, instruction: &[u8]) -> (u64, u64) {
        match decode(&after_loads(count, instruction)) {
            super::FlagsInstruction::Syscall { at, end, loads: l } => {
                let offsets: Vec<u64> = (0..count as u64).map(|i| 2 * i).collect();
                assert_eq!(l, loads(&offsets));
                (at - BASE, end - BASE)
            }
            other => panic!("decoded {other:?}"),
        }
    }

    // A guest's own trap after the loads is not a `syscall`, so its SIGTRAP is
    // not taken for the step's report. Neither is a chain the decoder does
    // not follow to its end.
    #[cfg(target_arch = "x86_64")]
    #[test_case(&after_loads(2, &[0xcc]); "int3 after two loads")]
    #[test_case(&after_loads(2, &[0xf1]); "icebp after two loads")]
    #[test_case(&after_loads(2, &[0xcd, 0x03]); "int 3 after two loads")]
    #[test_case(&after_loads(5, &[0x0f, 0x05]); "syscall after five loads")]
    #[test_case(&[0x8e, 0xdb, 0x0f, 0x05]; "syscall after a load of DS")]
    #[test_case(&[0x8e]; "a load of SS cut short")]
    #[test_case(&[0x8e, 0xd3, 0x0f]; "a syscall cut short")]
    fn decodes_other_after_loads_of_ss(code: &[u8]) {
        assert_eq!(decode(code), super::FlagsInstruction::Other);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn decodes_popf_and_iret_after_loads_of_ss() {
        assert_eq!(
            decode(&after_loads(2, &[0x9d])),
            super::FlagsInstruction::PopfAfterMovSs { end: BASE + 5 }
        );
        assert_eq!(
            decode(&after_loads(2, &[0x48, 0xcf])),
            super::FlagsInstruction::Iret {
                at: BASE + 4,
                loads: loads(&[0, 2]),
            }
        );
        // `mov ss, [rsp + 8]`: ModRM, SIB and an 8-bit displacement.
        assert_eq!(
            decode(&[0x8e, 0x54, 0x24, 0x08, 0x0f, 0x05]),
            super::FlagsInstruction::Syscall {
                at: BASE + 4,
                end: BASE + 6,
                loads: loads(&[0]),
            }
        );
    }

    // With no load of SS, or the one load at which the step starts, whether
    // the instruction returned is decided as it was before chains of loads
    // were followed. The first load is always at the step's start.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn returned_is_unchanged_without_a_chain_of_loads() {
        let start = super::StepStart {
            instruction: super::FlagsInstruction::Other,
            rip: BASE,
            rsp: 0x8000,
            rax: 0,
            clock: 0,
        };
        let at = BASE + 2;
        for chain in [loads(&[]), loads(&[0])] {
            for rip in [BASE, BASE + 2, BASE + 4, 0x2000] {
                for rsp in [0x8000, 0x8008] {
                    // SAFETY: user_regs_struct has only integer fields.
                    let mut regs: super::Regs = unsafe { core::mem::zeroed() };
                    regs.rip = rip;
                    regs.rsp = rsp;
                    let before = (regs.rip != start.rip && regs.rip != at) || regs.rsp != start.rsp;
                    assert_eq!(
                        super::returned(&regs, &start, at, &chain),
                        before,
                        "rip {rip:#x}, rsp {rsp:#x}, loads {chain:?}"
                    );
                }
            }
        }
    }

    // A step that stops at the second load, because it faulted there or the
    // processor held the trap back only for the first, has not returned.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_stop_at_a_later_load_of_ss_has_not_returned() {
        let start = super::StepStart {
            instruction: super::FlagsInstruction::Other,
            rip: BASE,
            rsp: 0x8000,
            rax: 0,
            clock: 0,
        };
        // SAFETY: user_regs_struct has only integer fields.
        let mut regs: super::Regs = unsafe { core::mem::zeroed() };
        regs.rsp = 0x8000;
        for (rip, returned) in [(BASE + 2, false), (BASE + 4, false), (BASE + 6, true)] {
            regs.rip = rip;
            assert_eq!(
                super::returned(&regs, &start, BASE + 4, &loads(&[0, 2])),
                returned,
                "rip {rip:#x}"
            );
        }
    }
}
