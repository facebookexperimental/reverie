//! Shared PMU configuration mechanics. One process configuration and override.
use std::sync::OnceLock;

use thiserror::Error;

use crate::Errno;
use crate::perf::Event;
// Used by both the preserved validation diagnostic and its ptrace probe.
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub const RETIRED_LOCK_INSTRUCTIONS_EVENT: u64 = 0x510f25;
/// Why this host's performance counters failed validation. See
/// `reverie_ptrace::pmu_validation`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PmuValidationError {
    /// A counter could not be opened.
    #[error("Failed to create timer: {errno:?} - {msg}")]
    CouldNotCreateTimer {
        /// The `perf_event_open` error.
        errno: Errno,
        /// What to check.
        msg: &'static str,
    },

    /// A system call on a counter failed.
    #[error("Unexpected error while checking for pmu bugs: {errno:?} - {msg}")]
    UnexpectedTestingErrnoError {
        /// The system call's error.
        errno: Errno,
        /// Which call failed.
        msg: &'static str,
    },

    /// A counter read returned something unexpected.
    #[error("Unexpected error while checking for pmu bugs: {0}")]
    UnexpectedTestingError(String),

    /// A period change took effect only after the next rollover.
    #[error("The ioc-period bug was detected")]
    IocPeriodBugDetected,

    /// The CPU vendor is neither AMD nor Intel, so Reverie knows none of its
    /// counting bugs.
    #[cfg(target_arch = "x86_64")]
    #[error("Unknown CPU vendor {0:?}: Reverie has no performance-counter checks for it")]
    UnknownCpuVendor(String),

    /// No PMU configuration was set and Reverie has no performance-counter
    /// profile for this CPU, so it cannot choose a branch event.
    #[cfg(target_arch = "x86_64")]
    #[error(
        "Unsupported CPU family {family:#x}, model {model:#x}: Reverie has no \
        performance-counter profile for it"
    )]
    UnsupportedCpu {
        /// The CPUID family.
        family: u8,
        /// The CPUID model.
        model: u8,
    },

    #[cfg(target_arch = "x86_64")]
    /// CPUID did not report the vendor or features.
    #[error("Could not read cpu info")]
    CouldNotReadCpuInfo,

    /// The branch counter counted fewer branches than were executed.
    #[error(
        "Got {actual_events} branch events, expected at least {expected_min_events}. \
        The hardware performance counter seems to not be working. Check \
        that hardware performance counters are working by running \
        \n`perf stat -e r{config:x} true`\n\
        and checking that it reports a nonzero number of events. \
        If performance counters seem to be working with 'perf', file a \
        reverie issue, otherwise check your hardware/OS/VM configuration. Also \
        check that other software is not using performance counters on \
        this CPU."
    )]
    HardwareCountersNotWorking {
        /// Branches counted.
        actual_events: i64,
        /// Branches executed.
        expected_min_events: u64,
        /// The raw event.
        config: u64,
    },

    /// A second counter counted nothing.
    #[error("Your CPU only supports one performance counter in its current configuration")]
    OnlyOnePerformanceCounter,

    /// AMD Zen SpecLockMap is enabled, so locked instructions can be miscounted.
    #[cfg(target_arch = "x86_64")]
    #[error(
        "On AMD Zen CPUs, reverie timers will not work reliably unless you disable the \
        hardware SpecLockMap optimization ({speclockmap_commits} of \
        {locked_instructions} locked instructions were SpecLockMap commits). For \
        instructions on how to do this, see https://github.com/rr-debugger/rr/wiki/Zen"
    )]
    AmdSpecLockMapShouldBeDisabled {
        /// How many SpecLockMap commits the check counted.
        speclockmap_commits: i64,
        /// How many locked instructions the check counted.
        locked_instructions: i64,
    },

    /// The SpecLockMap check counted no SpecLockMap commits, but fewer locked
    /// instructions than it executed, so its zero shows nothing. This happens
    /// when the retired-lock event (AMD PMCx025) counts nothing, as under a
    /// hypervisor that filters it, and could happen on a Zen part whose
    /// PMCx025 does not count every locked instruction.
    #[cfg(target_arch = "x86_64")]
    #[error(
        "The AMD Zen SpecLockMap check is inconclusive: it executed {executed} locked \
        instructions but the retired-lock counter (perf event r{RETIRED_LOCK_INSTRUCTIONS_EVENT:x}) \
        counted {counted}, so it cannot show that SpecLockMap is disabled. See \
        https://github.com/rr-debugger/rr/wiki/Zen"
    )]
    SpecLockMapCheckInconclusive {
        /// How many locked instructions the retired-lock counter counted.
        counted: i64,
        /// How many locked instructions the check executed.
        executed: usize,
    },

    #[cfg(target_arch = "x86_64")]
    /// An `IN_TXCP` counter under KVM counted too few branches.
    #[error("Intel Kvm-In-Txcp bug found")]
    IntelKvmInTxcpBugDetected,
}

/// We refuse to schedule a "perf timeout" for this or fewer RCBs, instead
/// choosing to directly single step. This is because I am somewhat paranoid
/// about perf event throttling, which isn't well-documented.
#[doc(hidden)]
pub const SINGLESTEP_TIMEOUT_RCBS: u64 = 5;

/// The largest default skid margin of any processor in the PMU table
/// (`crate::pmu::PmuProfile`, and 1000 on aarch64): that of the AMD Zen
/// processors without a measured 1K entry. A unit test checks it against the
/// whole table.
pub const LARGEST_TABLE_SKID_MARGIN: u64 = 10_000;

/// The single, greppable marker emitted to stderr whenever this backend detects
/// the RCB fallback overshooting its target. Re-exported from the
/// backend-agnostic `reverie` crate so that this precise single-step guard and
/// hermit's detcore log-and-continue path emit the *same* token — one marker,
/// one source. See [`crate::SKID_OVERSHOOT_MARKER`] for the full contract and
/// the retry-harness safety property.
pub use crate::SKID_OVERSHOOT_MARKER;

/// Fault-injection knob: when set to a parseable `u64`, this env var overrides
/// the processor-detected skid margin for the whole process. Setting it to `0`
/// programs the precise timer's overflow interrupt *at* the target RCB instead
/// of `skid_margin` RCBs early, so any natural positive skid pushes the fallback
/// single-step past the target and deterministically triggers the
/// [`SKID_OVERSHOOT_MARKER`] path. This exists to exercise the skid overshoot +
/// retry harness on demand; it is not a tuning knob for normal runs. A value
/// that does not parse as `u64` is ignored (processor default retained).
pub const SKID_MARGIN_OVERRIDE_ENV: &str = "REVERIE_SKID_MARGIN_OVERRIDE";

/// The overflow interrupt latency, in nanoseconds, that the second stage of a
/// staged precise timer event leaves room for by default (see
/// [`PmuConfig::stages`]). Measured on AMD family 1Ah, the latency was 43 ns
/// at the median and 185 ns at the 99th percentile, and reached about 590 ns
/// in a noisy hour (<https://github.com/rrnewton/hermit/issues/3810>). The
/// tail grows with contention for the guest's core. For a loop retiring
/// about 2.9 RCBs per ns, the largest second-stage skid in 64 to 96
/// notifications was 134 RCBs (about 45 ns) unloaded, 823 (about 280 ns)
/// with the SMT sibling thrashing memory, and 1,631 (about 560 ns) with three
/// such tasks sharing the guest's CPU. In a full validation (Hermit
/// 856eaf1e, 2026-10-17) the same guest overran the 2,000-RCB margin three
/// times by 41 to 837 RCBs: notifications 0.7 to 0.95 µs late. 2,000 ns is
/// about twice that. Only a guest retiring more than 1 RCB per ns
/// (the skid margin over this budget) gets a margin above the skid margin.
pub const DEFAULT_SKID_LATENCY_BUDGET_NS: u64 = 2_000;

/// When set to a parseable `u64`, this env var replaces
/// [`DEFAULT_SKID_LATENCY_BUDGET_NS`] for the whole process. `0` stages no
/// precise event, so that each is programmed at the skid margin. A value that
/// does not parse as `u64` is ignored (default retained).
pub const SKID_LATENCY_BUDGET_ENV: &str = "REVERIE_SKID_LATENCY_BUDGET_NS";

/// Supervisor-only witness nonce. When the consuming harness (the hermit
/// *supervisor*) sets this env var, its exact value is stamped into every
/// [`SKID_OVERSHOOT_MARKER`] line as a ` witness=<value>` field. A downstream
/// retry gate uses it to distinguish a genuine supervisor-emitted overshoot from
/// guest-printed marker text: hermit strips this var from the guest environment,
/// so the guest can neither read nor forge the value. Unset or empty leaves the
/// marker in its plain (unauthenticated) shape.
pub const WITNESS_TOKEN_ENV: &str = "HERMIT_SKID_WITNESS_TOKEN";

static PMU_CONFIG: OnceLock<PmuConfig> = OnceLock::new();

/// The skid margin [`set_skid_margin_override`] recorded, applied to the PMU
/// configuration when it is first built.
static SKID_MARGIN_OVERRIDE: OnceLock<u64> = OnceLock::new();

/// The process's PMU configuration, which must already exist: every caller
/// runs after `reverie_ptrace::timer::TimerImpl::new` or `reverie_ptrace::validation` has built it through
/// [`try_get_pmu_config`], which refuses a CPU with no profile.
#[doc(hidden)]
pub fn get_pmu_config() -> &'static PmuConfig {
    try_get_pmu_config().expect("the PMU configuration is read only after it was built")
}

/// The process's PMU configuration, built on first use, or `None` when no
/// configuration was set and this CPU has no profile.
#[doc(hidden)]
pub fn try_get_pmu_config() -> Option<&'static PmuConfig> {
    match PMU_CONFIG.get() {
        Some(config) => Some(config),
        None => PmuConfig::try_new().map(|config| PMU_CONFIG.get_or_init(|| config)),
    }
}

/// Processor-specific PMU event settings used by precise ptrace timers.
// TODO-HUMAN-REVIEW(PR-186): Review the programmatic PMU skid-margin override API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PmuConfig {
    rcb_event: u64,
    skid_margin: u64,
    skid_margin_override: Option<u64>,
    skid_latency_budget_ns: u64,
}

impl PmuConfig {
    /// Attempts to configure the PMU without assuming that this CPU has a
    /// measured deterministic-timer profile.
    ///
    /// In-guest clocks can treat an unknown CPU as an unavailable optional
    /// capability. Precise ptrace timers retain [`Self::new`]'s fail-fast
    /// contract because they also require a measured skid margin.
    #[cfg(target_arch = "x86_64")]
    #[doc(hidden)]
    pub fn try_new() -> Option<Self> {
        Self::new().ok()
    }

    #[cfg(target_arch = "aarch64")]
    #[doc(hidden)]
    pub fn try_new() -> Option<Self> {
        Self::new().ok()
    }

    /// The PMU configuration for this CPU, with the environment's overrides and
    /// the margin [`set_skid_margin_override`] recorded.
    ///
    /// Refuses, rather than guessing an event, a CPU that is not in the
    /// profile table ([`PmuValidationError::UnsupportedCpu`]) or whose CPUID
    /// cannot be read ([`PmuValidationError::CouldNotReadCpuInfo`]).
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Result<Self, PmuValidationError> {
        let features = raw_cpuid::CpuId::new()
            .get_feature_info()
            .ok_or(PmuValidationError::CouldNotReadCpuInfo)?;
        Ok(
            Self::for_family_model(features.family_id(), features.model_id())?
                .with_env_overrides()
                .with_recorded_skid_margin(),
        )
    }

    /// The PMU configuration of an x86 CPU with this family and model, without
    /// any override, or [`PmuValidationError::UnsupportedCpu`] for one that is
    /// not in the profile table. It does not read this host's CPUID.
    #[cfg(target_arch = "x86_64")]
    pub fn for_family_model(family_id: u8, model_id: u8) -> Result<Self, PmuValidationError> {
        Self::try_from_family_model(family_id, model_id).ok_or(PmuValidationError::UnsupportedCpu {
            family: family_id,
            model: model_id,
        })
    }

    /// Creates / initializes the PMU config.
    #[cfg(target_arch = "aarch64")]
    pub fn new() -> Result<Self, PmuValidationError> {
        // TODO:
        //  1. Compute the microarchitecture from
        //     `/sys/devices/system/cpu/cpu*/regs/identification/midr_el1`
        //  2. Look up the microarchitecture in a table to determine what features
        //     we can enable.
        // References:
        //  - https://github.com/rr-debugger/rr/blob/master/src/PerfCounters.cc#L156
        const BR_RETIRED: u64 = 0x21;

        // For now, always assume that we can get retired branch events.
        Ok(Self {
            rcb_event: BR_RETIRED,
            skid_margin: 1000,
            skid_margin_override: None,
            skid_latency_budget_ns: DEFAULT_SKID_LATENCY_BUDGET_NS,
        }
        .with_env_overrides()
        .with_recorded_skid_margin())
    }

    /// [`Self::for_family_model`] for a model these tests know is in the table.
    #[cfg(all(any(test, feature = "perf-fixture"), target_arch = "x86_64"))]
    #[doc(hidden)]
    pub fn from_family_model(family_id: u8, model_id: u8) -> Self {
        Self::for_family_model(family_id, model_id).expect("a model in the profile table")
    }

    #[cfg(target_arch = "x86_64")]
    #[doc(hidden)]
    pub fn try_from_family_model(family_id: u8, model_id: u8) -> Option<Self> {
        crate::pmu::PmuProfile::for_family_model(family_id, model_id).map(|profile| Self {
            rcb_event: profile.raw_rcb_event(),
            skid_margin: profile.default_skid_margin(),
            skid_margin_override: None,
            skid_latency_budget_ns: DEFAULT_SKID_LATENCY_BUDGET_NS,
        })
    }

    /// Overrides the processor-specific skid margin while preserving the detected PMU event.
    pub fn with_skid_margin_override(mut self, skid_margin: u64) -> Self {
        self.skid_margin_override = Some(skid_margin);
        self
    }

    /// Replaces the interrupt latency that staged precise events leave room
    /// for (see [`Self::stages`]). `0` stages no event.
    pub fn with_skid_latency_budget_ns(mut self, budget_ns: u64) -> Self {
        self.skid_latency_budget_ns = budget_ns;
        self
    }

    /// Applies the env overrides: [`SKID_MARGIN_OVERRIDE_ENV`] and
    /// [`SKID_LATENCY_BUDGET_ENV`].
    fn with_env_overrides(self) -> Self {
        self.with_skid_margin_env().with_skid_latency_budget_env()
    }

    /// Applies the margin [`set_skid_margin_override`] recorded, if any. It is
    /// applied after [`Self::with_env_overrides`], so it wins over
    /// [`SKID_MARGIN_OVERRIDE_ENV`], as an explicit override built from
    /// [`Self::new`] always did.
    fn with_recorded_skid_margin(self) -> Self {
        match SKID_MARGIN_OVERRIDE.get() {
            Some(&margin) => self.with_skid_margin_override(margin),
            None => self,
        }
    }

    /// Applies the [`SKID_LATENCY_BUDGET_ENV`] override, if the env var is
    /// present and parses as a `u64`, as [`Self::with_skid_margin_env`] does.
    fn with_skid_latency_budget_env(self) -> Self {
        match std::env::var(SKID_LATENCY_BUDGET_ENV) {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(v) => {
                    eprintln!(
                        "[reverie-ptrace] {}={} active: staged precise timer events leave \
                         room for {} ns of interrupt latency{}",
                        SKID_LATENCY_BUDGET_ENV,
                        raw,
                        v,
                        if v == 0 { " (staging off)" } else { "" }
                    );
                    self.with_skid_latency_budget_ns(v)
                }
                Err(_) => {
                    eprintln!(
                        "[reverie-ptrace] ignoring {}={:?}: not a u64; using {} ns",
                        SKID_LATENCY_BUDGET_ENV, raw, DEFAULT_SKID_LATENCY_BUDGET_NS
                    );
                    self
                }
            },
            Err(_) => self,
        }
    }

    /// Applies the [`SKID_MARGIN_OVERRIDE_ENV`] fault-injection override, if the
    /// env var is present and parses as a `u64`. A missing var leaves the
    /// processor default untouched; a present-but-unparseable value is ignored
    /// with a warning rather than aborting startup. When the override is applied
    /// it is announced loudly on stderr, because it deliberately degrades timer
    /// precision to force the overshoot path.
    fn with_skid_margin_env(self) -> Self {
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
    /// across which the event cannot be continued (an injected rt_sigreturn
    /// trap, or any such stop without overflow records) keeps the event
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
        self.first_stage_margin()
            .saturating_add(SINGLESTEP_TIMEOUT_RCBS)
    }

    /// The interrupt latency, in nanoseconds, that the second stage of a
    /// staged precise event leaves room for (see [`Self::stages`]), or `0` if
    /// no event is staged.
    pub fn skid_latency_budget_ns(&self) -> u64 {
        self.skid_latency_budget_ns
    }

    /// How many RCBs short of its target the first stage of a staged precise
    /// event is programmed (see [`Self::stages`]): the base of
    /// [`Self::keep_margin`], so that the keep point still lies at or before
    /// the programming's period.
    pub fn first_stage_margin(&self) -> u64 {
        self.skid_margin().max(LARGEST_TABLE_SKID_MARGIN)
    }

    /// Whether a precise event requested `ticks` RCBs ahead is staged.
    ///
    /// The overflow interrupt arrives a short time after the overflow, and
    /// the guest retires branches at its own rate meanwhile, so the skid in
    /// RCBs is that rate times the interrupt latency. The skid margin is a
    /// count, which a guest retiring branches fast enough can overrun.
    /// A staged event is first programmed [`Self::first_stage_margin`] RCBs
    /// short of its target. At that notification's stop, the guest's branch
    /// rate since the programming sizes the margin of the second
    /// programming (see [`Self::second_stage_margin`]), whose notification
    /// is then delivered as an unstaged event's is: by single stepping to the
    /// target.
    ///
    /// Staging changes how far short of the target the last notification
    /// comes, and so how many single steps reach the target. It never
    /// changes the requested target or instruction offset, and an event
    /// whose last notification arrives short of its target is still
    /// delivered exactly there. The first stage's stop resumes the guest
    /// with no Tool callback, as a stop that reschedules a spurious wakeup
    /// does, and stops add no RCBs. The measured rate is a past average: it
    /// bounds neither a faster suffix nor the interrupt latency's tail, so
    /// a notification can still arrive past the target. That case keeps the
    /// existing overshoot contract (see `TimerImpl::attempt_single_step`):
    /// the overshoot is recorded and the event is delivered at the observed
    /// counter. A mismeasured rate changes the cost and how likely that is,
    /// not where an on-target event is delivered.
    ///
    /// An event is staged only if the first stage programs a notification,
    /// rather than sending an artificial signal, and if a second stage can
    /// come closer than the first: the first stage margin is larger than the
    /// skid margin, which is not overridden, and the latency budget is not
    /// zero.
    pub fn stages(&self, ticks: u64) -> bool {
        self.skid_latency_budget_ns != 0
            && self.skid_margin_override.is_none()
            && self.first_stage_margin() > self.skid_margin()
            && ticks > self.first_stage_margin() + SINGLESTEP_TIMEOUT_RCBS
    }

    /// The margin of the second stage of a staged precise event (see
    /// [`Self::stages`]), whose first stage's notification came `rcbs` RCBs
    /// and `elapsed_ns` nanoseconds after its programming: the RCBs retired
    /// in [`Self::skid_latency_budget_ns`] at that rate, but at least the
    /// skid margin and at most the first stage margin. Without an elapsed
    /// time, as when the notification's sample record is missing, it is the
    /// skid margin.
    ///
    /// The elapsed time runs from the programming, before the guest resumed,
    /// to the interrupt, so it can only overstate the time the guest ran,
    /// and the rate can only be understated, to the skid margin at least.
    pub fn second_stage_margin(&self, rcbs: u64, elapsed_ns: Option<u64>) -> u64 {
        let floor = self.skid_margin();
        let Some(elapsed_ns) = elapsed_ns.filter(|&elapsed_ns| elapsed_ns > 0) else {
            return floor;
        };
        let margin = (u128::from(rcbs) * u128::from(self.skid_latency_budget_ns))
            .div_ceil(u128::from(elapsed_ns));
        u64::try_from(margin)
            .unwrap_or(u64::MAX)
            .clamp(floor, self.first_stage_margin().max(floor))
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
    /// process-global witness counter via [`crate::record_skid_overshoot`],
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
            crate::record_skid_overshoot();
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
            crate::record_skid_overshoot();
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

/// Installs the PMU configuration used by subsequently created ptrace timers.
///
/// Returns the supplied configuration if a timer has already initialized the process-wide
/// configuration. Callers should install overrides before spawning a `reverie_ptrace::Tracer`.
pub fn set_pmu_config(config: PmuConfig) -> Result<(), PmuConfig> {
    PMU_CONFIG.set(config)
}

/// Records `skid_margin` as the margin of the PMU configuration this process
/// builds on first use, without reading this host's CPUID: a tool can accept
/// a margin before it knows whether the host has a profile, and a host with
/// none is refused only when a timer needs one.
///
/// Returns `skid_margin` back, recording nothing, once a margin was recorded
/// or the configuration was built or set, because it would then be lost.
/// Record it before spawning a `reverie_ptrace::Tracer`.
pub fn set_skid_margin_override(skid_margin: u64) -> Result<(), u64> {
    record_skid_margin(
        &SKID_MARGIN_OVERRIDE,
        PMU_CONFIG.get().is_some(),
        skid_margin,
    )
}

/// Whether this host's CPU has a PMU profile, the precondition for a ptrace
/// timer. It only reads CPUID and the profile table: it builds no
/// configuration, applies no override and writes nothing, so a tool can ask
/// before it starts and disable or refuse its timeslice rather than run
/// without the timer it asked for.
#[cfg(target_arch = "x86_64")]
pub fn host_pmu_profile() -> Result<(), PmuValidationError> {
    let features = raw_cpuid::CpuId::new()
        .get_feature_info()
        .ok_or(PmuValidationError::CouldNotReadCpuInfo)?;
    PmuConfig::for_family_model(features.family_id(), features.model_id()).map(drop)
}

/// Every aarch64 CPU gets a configuration ([`PmuConfig::new`]).
#[cfg(target_arch = "aarch64")]
pub fn host_pmu_profile() -> Result<(), PmuValidationError> {
    Ok(())
}

/// [`set_skid_margin_override`] against `slot`, with `config_built` saying
/// whether the configuration it would change exists already.
#[doc(hidden)]
pub fn record_skid_margin(
    slot: &OnceLock<u64>,
    config_built: bool,
    skid_margin: u64,
) -> Result<(), u64> {
    if config_built {
        return Err(skid_margin);
    }
    slot.set(skid_margin)
}

/// Whether a stop at `rcb_actual` has reached the delivery point of a precise
/// event `instr_offset` instructions past `rcb_target`, as far as the counter
/// can show. See [`PmuConfig::record_missed_if_target_reached`].
#[doc(hidden)]
pub fn target_reached(rcb_actual: u64, rcb_target: u64, instr_offset: u64) -> bool {
    rcb_actual
        .checked_sub(rcb_target)
        .is_some_and(|past| past >= instr_offset)
}
