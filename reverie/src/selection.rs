/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Requirements, implemented-cell admission, and typed refusals.
//!
//! A tool states what it needs ([`ToolRequirements`], via
//! [`Tool::requirements`](crate::Tool::requirements)); the host states what
//! it will run ([`GuestProfile`]) and what the environment proved
//! ([`EnvironmentSnapshot`]); [`admit`] filters the *implemented* cells
//! ([`implemented_cells`]) by those facts and returns either an
//! [`AdmissionReport`] or a typed [`AdmissionRefusal`] with a full
//! [`FilterTrace`]. Admission is pure: it starts no guest and mutates
//! nothing.
//!
//! # Implemented cells, not design cells
//!
//! A *design cell* (see [`design_cells`]) is an obligation: a combination
//! that could honour the tool contract. Only an [`ImplementedCell`] — an
//! activation/mechanism/placement/configuration that exists, with its
//! tested [`TestedEnvelope`] — is selectable. [`BackendCapabilities`]
//! constants are one input to a cell (and each registered cell must cite
//! its constant exactly), but a backend-wide constant alone never certifies
//! a composition: three constants exist for backends with no implementation
//! in this repository, and none of them registers a cell.
//!
//! # Unknown means unproved
//!
//! Environment facts are [`Knowledge`]: `Proved`, `Disproved`, or `Unknown`.
//! `Unknown` never stands in for a value (unknown tracer ownership is not
//! "no tracer"). A cell whose admission predicate depends on an `Unknown`
//! fact is not admitted, and if that is what empties the set the refusal is
//! [`RefusalCode::REnvUnknown`]. Observations made on throwaway children
//! are advisory: the retained [`ExecutionPlan`] re-validates the *actual*
//! guest's facts at the backend's controlled handoff
//! ([`ExecutionPlan::validate_handoff`]), and a failure there is terminal —
//! the host must not retry another backend under a weaker reading. The
//! existing admission hooks ([`Tool::facility_admission`](crate::Tool::facility_admission)
//! and the `install_*` hooks) stay authoritative on that same path: an
//! `Err` from one aborts the launch, never re-runs admission.
//!
//! # Interests are not restrictions
//!
//! [`Subscription`] is the tool's *event interest*.
//! [`LifecycleRequirements`] are *guest-behaviour guarantees* the run must
//! survive. Declining `execve` events does not prove the guest cannot exec,
//! so subscriptions never relax lifecycle requirements; they only add
//! instruction-mediation demands (see [`EffectiveRequirements`]).
//!
//! # Ranking is a heuristic over eligible cells only
//!
//! Explicit selection ([`ExplicitSelection`]) is honoured exactly or
//! refused by name; it is never silently replaced. Automatic ranking picks
//! among already-eligible cells by a cost-class *heuristic*
//! (patch < gate+patch < trap < ptrace < translation), tie-broken toward
//! stronger guarantees. The order is a shape, not a benchmark.
//!
//! # Fork and exec retain the plan
//!
//! Children and successors re-admit the *same* cell
//! ([`ExecutionPlan::readmit_on_fork`], [`ExecutionPlan::readmit_on_exec`]);
//! they never inherit a weaker one. Changing cells would require an
//! explicit transfer of tool state, RPC, and signal ownership, which this
//! module deliberately does not provide.
//!
//! Admission refusals are values of their own type, distinct from both
//! [`Error`](crate::Error) and the per-operation
//! [`UnsupportedRefusal`](crate::UnsupportedRefusal); a refusal is never
//! encoded as a guest errno.

use serde::Deserialize;
use serde::Serialize;

use crate::BackendCapabilities;
use crate::Subscription;
use crate::ThreadOwnership;

/// How much unmonitored execution before instrumentation a tool accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WindowRequirement {
    /// The tool must be armed before the guest's first instruction
    /// (including across exec). The strict default.
    Zero,
    /// The tool accepts a declared pre-initialisation window (dynamic
    /// loader, IFUNC resolvers, early constructors) such as a preload
    /// activation necessarily has. `pre_init_ok: false` declares the
    /// window exists in principle but still requires a zero-window cell.
    Declared {
        /// Whether execution before the instrumentation initialises may
        /// run unmonitored.
        pre_init_ok: bool,
    },
}

/// Nondeterministic-instruction classes that must be mediated.
///
/// Syscalls are not here; they come from
/// [`Subscription`]. `cpuid`/`rdtsc` demands are
/// normally raised from the subscription (see [`EffectiveRequirements`]);
/// the wider classes can only be stated here. No implemented cell mediates
/// the wider classes: stating one yields [`RefusalCode::RInstr`], which is
/// the honest answer instead of silent non-coverage. Hardware faulting
/// support (CPUID faulting, `PR_SET_TSC`) may be a cell's prerequisite; its
/// absence yields a named refusal or another fully adequate cell, never
/// lost instruction coverage.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize
)]
pub struct InstructionRequirements {
    /// `CPUID` must be mediated.
    pub cpuid: bool,
    /// `RDTSC`/`RDTSCP` must be mediated.
    pub rdtsc: bool,
    /// `RDRAND`/`RDSEED` must be mediated.
    pub rdrand_rdseed: bool,
    /// `XGETBV` must be mediated.
    pub xgetbv: bool,
}

/// Whether dynamically created code (dlopen, JIT, self-modification) must
/// be covered, or may instead meet a named runtime refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DynamicCodeNeed {
    /// New code must be covered by the mechanism (trap, gate, or
    /// translation). The strict default.
    MustCover,
    /// The tool's guests are declared not to create code the cell cannot
    /// cover; uncovered new code may refuse by name at runtime.
    NotRequired,
}

/// Guest-behaviour guarantees a run must survive.
///
/// Each `true` field demands that the cell *follows* that behaviour with
/// the tool contract intact. Relaxing a field (setting it `false`) is an
/// explicit declaration that the tool's guests do not need it, accepting
/// the backend's named runtime refusal (for example
/// [`UnsupportedOperation::Exec`](crate::UnsupportedOperation::Exec))
/// instead of coverage. These are restrictions on the guest, not event
/// interests: they are never derived from syscall subscriptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LifecycleRequirements {
    /// Guest may create threads (`clone` with `CLONE_THREAD`), each
    /// observed from its first instruction.
    pub threads: bool,
    /// Guest may `fork`; children are followed.
    pub fork: bool,
    /// Guest may `vfork`; children are followed.
    pub vfork: bool,
    /// Guest may `execve`; successor images are re-armed under the same
    /// cell with no window beyond the tool's [`WindowRequirement`].
    pub exec_successor: bool,
    /// Guest signal behaviour must match the reference contract (handler
    /// verdicts are what the guest experiences).
    pub signal_fidelity: bool,
    /// Dynamically created code must be covered.
    pub dynamic_code: DynamicCodeNeed,
}

impl Default for LifecycleRequirements {
    fn default() -> Self {
        // Strictest: the guest may do all of it, and all of it is covered.
        Self {
            threads: true,
            fork: true,
            vfork: true,
            exec_successor: true,
            signal_fidelity: true,
            dynamic_code: DynamicCodeNeed::MustCover,
        }
    }
}

/// Where the tool's code may run relative to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlacementRequirement {
    /// Either placement. The default.
    Any,
    /// The tool must run inside the guest process.
    InGuestOnly,
    /// The tool must run outside the guest process.
    OutOfProcessOnly,
}

/// Whether an external debugger (another tracer) may coexist with the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerRequirement {
    /// The run owns its tracing relationship. The default.
    Exclusive,
    /// An external tracer must be able to coexist (the run must not
    /// require ptrace seizure of the guest). No implemented cell provides
    /// this today.
    CoexistWithExternal,
}

/// How densely the guest must be instrumented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Density {
    /// Event-level instrumentation (syscalls, named instructions,
    /// signals, lifecycle). The default.
    EventLevel,
    /// Every branch/instruction must be mediated. Only a translation cell
    /// can provide this; none is implemented today, so this yields
    /// [`RefusalCode::RDense`].
    Dense,
}

/// What a tool needs from whichever cell runs it. Data only, like
/// [`Subscription`]; computed once per guest tree via
/// [`Tool::requirements`](crate::Tool::requirements).
///
/// The default is the strictest reading: a tool that says nothing gets
/// reference semantics or a refusal — never a preload window it did not
/// declare. Relaxation is explicit and visible in source and in every
/// [`AdmissionReport`]. (Instruction demands default to none *beyond the
/// subscription*: demanding mediation of an instruction the tool never
/// subscribed to would refuse tools that never asked, which is not
/// strictness but a different, wrong requirement.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRequirements {
    /// Unmonitored-window tolerance.
    pub window: WindowRequirement,
    /// Instruction classes that must be mediated.
    pub instructions: InstructionRequirements,
    /// Guest-behaviour guarantees.
    pub lifecycle: LifecycleRequirements,
    /// Tool placement.
    pub placement: PlacementRequirement,
    /// External-debugger coexistence.
    pub debugger: DebuggerRequirement,
    /// Instrumentation density.
    pub density: Density,
}

impl Default for ToolRequirements {
    fn default() -> Self {
        Self {
            window: WindowRequirement::Zero,
            instructions: InstructionRequirements::default(),
            lifecycle: LifecycleRequirements::default(),
            placement: PlacementRequirement::Any,
            debugger: DebuggerRequirement::Exclusive,
            density: Density::EventLevel,
        }
    }
}

impl ToolRequirements {
    /// Whether `self` is weaker than or equal to `other` on every axis:
    /// any cell satisfying `other` also satisfies `self`. Relaxing a
    /// requirement (moving to a weaker value) therefore never removes
    /// eligible cells — the monotonicity property admission relies on.
    pub fn is_relaxation_of(&self, other: &Self) -> bool {
        let window_ok = match (self.window, other.window) {
            (a, b) if a == b => true,
            (WindowRequirement::Declared { pre_init_ok: true }, WindowRequirement::Zero) => true,
            (
                WindowRequirement::Declared { pre_init_ok: true },
                WindowRequirement::Declared { pre_init_ok: false },
            ) => true,
            (WindowRequirement::Declared { pre_init_ok: false }, WindowRequirement::Zero) => true,
            _ => false,
        };
        let instr = &self.instructions;
        let oinstr = &other.instructions;
        let instr_ok = (!instr.cpuid || oinstr.cpuid)
            && (!instr.rdtsc || oinstr.rdtsc)
            && (!instr.rdrand_rdseed || oinstr.rdrand_rdseed)
            && (!instr.xgetbv || oinstr.xgetbv);
        let life = &self.lifecycle;
        let olife = &other.lifecycle;
        let life_ok = (!life.threads || olife.threads)
            && (!life.fork || olife.fork)
            && (!life.vfork || olife.vfork)
            && (!life.exec_successor || olife.exec_successor)
            && (!life.signal_fidelity || olife.signal_fidelity)
            && (life.dynamic_code == DynamicCodeNeed::NotRequired
                || olife.dynamic_code == DynamicCodeNeed::MustCover);
        let placement_ok =
            self.placement == PlacementRequirement::Any || self.placement == other.placement;
        let debugger_ok =
            self.debugger == DebuggerRequirement::Exclusive || self.debugger == other.debugger;
        let density_ok = self.density == Density::EventLevel || self.density == other.density;
        window_ok && instr_ok && life_ok && placement_ok && debugger_ok && density_ok
    }
}
/// A fact that admission may depend on: proved, disproved, or unknown.
///
/// `Unknown` means the predicate is unproved; it is never a stand-in for
/// either value. Admission fails closed on any load-bearing `Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Knowledge<T> {
    /// The fact was observed and holds this value.
    Proved(T),
    /// The fact was observed and does not hold.
    Disproved,
    /// The fact could not be observed; `why` names the obstacle for logs.
    Unknown {
        /// Why the observation could not be performed.
        why: &'static str,
    },
}

impl<T> Knowledge<T> {
    /// The value, if proved.
    pub fn proved(&self) -> Option<&T> {
        match self {
            Self::Proved(value) => Some(value),
            _ => None,
        }
    }

    /// Whether this fact is unknown.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }
}

impl<T> Default for Knowledge<T> {
    fn default() -> Self {
        Self::Unknown { why: "not probed" }
    }
}

/// Seccomp facts relevant to installing one more filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SeccompState {
    /// `PR_GET_SECCOMP` mode of the probing context.
    pub mode: u64,
    /// Number of filters already installed (`Seccomp_filters`).
    pub filters: u64,
    /// Whether `no_new_privs` is set.
    pub no_new_privs: bool,
    /// Whether a throwaway-child trial actually installed a filter (via
    /// setting `no_new_privs` on itself first, as a guest runtime does).
    /// Mode/capability metadata alone does not prove installation or
    /// nesting is permitted; strict mode (`mode == 1`) forbids it.
    pub install_proved: bool,
}

/// W^X / mapping-policy facts relevant to in-guest arenas and gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WxPolicy {
    /// Dual-mapped RW/RX arenas and `mprotect`-to-exec are permitted.
    DualMapAllowed,
    /// The policy forbids the dual-mapped arena shape (strict W^X).
    StrictWx,
}

/// Observable shape of the program image. Advisory only: binary shape and
/// JIT indicators cannot prove future code coverage, so this may only ever
/// tighten admission (toward [`RefusalCode::RCode`]), never certify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CodeShape {
    /// The image is dynamically linked.
    pub dynamic: bool,
    /// The image is position-independent.
    pub pie: bool,
    /// Indicators of runtime code creation (`dlopen`, JIT libraries) were
    /// seen. Absence proves nothing about the future.
    pub jit_indicators: bool,
}

/// Architecture/kernel floor facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArchFloor {
    /// The host is Linux on x86-64.
    pub linux_x86_64: bool,
    /// CET/IBT is present (recorded for trampoline shape; not gated).
    pub cet_ibt: bool,
}

/// Pure host/loader observations (probes P1–P10), gathered before any
/// guest instruction. No probe mutates the guest. Observations made on a
/// throwaway child are advisory for the actual guest; the load-bearing
/// re-check happens in [`ExecutionPlan::validate_handoff`] with facts the
/// backend observes at its own controlled stop — this struct never claims
/// guest facts it did not observe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnvironmentSnapshot {
    /// P1: ptrace seizure is usable.
    pub p1_ptrace_usable: Knowledge<bool>,
    /// P2: an existing tracer owns the relevant process. `Proved(false)`
    /// is the only "no tracer" answer; anything else is not.
    pub p2_existing_tracer: Knowledge<bool>,
    /// P3: seccomp filter installation and nesting.
    pub p3_seccomp: Knowledge<SeccompState>,
    /// P4: Syscall User Dispatch is available and permitted. Optional
    /// acceleration inside trap cells only; never gates eligibility.
    pub p4_sud: Knowledge<bool>,
    /// P5: CPUID faulting can be armed.
    pub p5_cpuid_faulting: Knowledge<bool>,
    /// P6: `PR_SET_TSC` can be armed.
    pub p6_pr_set_tsc: Knowledge<bool>,
    /// P7: W^X / mapping policy.
    pub p7_wx: Knowledge<WxPolicy>,
    /// P8: required signal ownership (SIGTRAP/SIGSYS/SIGSEGV) is
    /// available. Guest dispositions are largely unobservable before the
    /// guest runs, so this is honestly `Unknown` in most snapshots;
    /// cells that need ownership validate it at handoff.
    pub p8_signal_ownership: Knowledge<bool>,
    /// P9: program-image shape (advisory; see [`CodeShape`]).
    pub p9_code_shape: Knowledge<CodeShape>,
    /// P10: architecture/kernel floor.
    pub p10_arch: Knowledge<ArchFloor>,
}

impl Default for EnvironmentSnapshot {
    /// Every fact unknown: admission from this snapshot alone can only
    /// ever refuse with [`RefusalCode::REnvUnknown`] (fail closed).
    fn default() -> Self {
        Self {
            p1_ptrace_usable: Knowledge::default(),
            p2_existing_tracer: Knowledge::default(),
            p3_seccomp: Knowledge::default(),
            p4_sud: Knowledge::default(),
            p5_cpuid_faulting: Knowledge::default(),
            p6_pr_set_tsc: Knowledge::default(),
            p7_wx: Knowledge::default(),
            p8_signal_ownership: Knowledge::default(),
            p9_code_shape: Knowledge::default(),
            p10_arch: Knowledge::default(),
        }
    }
}

/// What the host intends to run, at the granularity tested envelopes
/// distinguish. Stated by the launcher, which knows how it will start the
/// program; never guessed from the image alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuestProfile {
    /// An arbitrary host process (static or dynamic, secure-execution
    /// mode unknown). Only cells whose envelope covers any host process
    /// qualify.
    HostProcessAny,
    /// A dynamically linked host process the launcher will start without
    /// secure-execution mode (`AT_SECURE` off), so a preload activation
    /// can run. The facts are re-validated at handoff.
    HostProcessDynamicPreloadable,
    /// A static ELF image run on the virtual-machine substrate (no host
    /// process exists).
    StaticElfVm,
}

/// The tool's config-static query answers that admission consumes.
///
/// Populated from the existing query methods beside
/// [`Tool::requirements`](crate::Tool::requirements); those methods keep
/// their meanings and their backends keep consulting them — this struct is
/// how their answers reach the pure admission function. Nothing is folded
/// away: an `Err` from any install/admission hook remains an authoritative
/// launch failure on top of admission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolQueries {
    /// [`Tool::requires_signal_control`](crate::Tool::requires_signal_control):
    /// the run cannot proceed without process signal control. A cell
    /// satisfies this only if its capabilities provide that control; a
    /// backend that never offered the control does not silently qualify.
    pub requires_signal_control: bool,
    /// [`Tool::observes_sigreturns`](crate::Tool::observes_sigreturns):
    /// the cell must report guest `rt_sigreturn`s.
    pub observes_sigreturns: bool,
    /// [`Tool::may_observe_signal_dequeues`](crate::Tool::may_observe_signal_dequeues):
    /// an upper bound only; recorded, never an admission gate, and never
    /// implies `requires_signal_control`.
    pub may_observe_signal_dequeues: bool,
    /// [`Tool::in_guest_signal_delivery`](crate::Tool::in_guest_signal_delivery):
    /// the tool takes the in-guest two-phase signal protocol, so only an
    /// in-guest cell can host it.
    pub in_guest_signal_delivery: bool,
    /// [`Tool::enforces_serialized_execution`](crate::Tool::enforces_serialized_execution),
    /// or `None` when the retaining boundary did not collect it (its
    /// implementations may re-enter `subscriptions`, so
    /// [`ToolConfiguration`](crate::ToolConfiguration) deliberately does
    /// not evaluate it). `None` is not `Some(false)`: admission fails
    /// closed where this answer is load-bearing (the reserved-input
    /// joint prerequisite), and backends keep consulting the method at
    /// their documented points regardless.
    pub enforces_serialized_execution: Option<bool>,
    /// [`Tool::reserved_input_requirement`](crate::Tool::reserved_input_requirement)
    /// returned `Some`: satisfiable only jointly with
    /// `enforces_serialized_execution == Some(true)` on a cell whose
    /// envelope includes reserved input — that is the installer's
    /// actual prerequisite, not an unconditional backend fact.
    pub reserved_input: bool,
    /// The *effective* thread ownership for the run (the tool's
    /// [`Tool::thread_ownership`](crate::Tool::thread_ownership) answer
    /// after any caller override), or `None` when not collected.
    /// Admission gates it only for cells whose envelope honors the
    /// setting, and there `None` fails closed: monitored-threads
    /// coverage is unproved until ownership is known not to be `Host`.
    /// A default must never pose as this answer.
    pub thread_ownership: Option<ThreadOwnership>,
}

/// Requirements after merging the tool's stated requirements with its
/// subscriptions and query answers. This is the value admission filters
/// on, the value logged for every run, and the value an
/// [`ExecutionPlan`] retains across fork/exec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveRequirements {
    /// The tool's stated requirements, unmodified.
    pub stated: ToolRequirements,
    /// The tool's event interests, unmodified.
    #[serde(skip)]
    pub subscriptions: Subscription,
    /// The tool's query answers, unmodified.
    pub queries: ToolQueries,
    /// Instruction demands after merging stated demands with the
    /// subscription's CPUID/RDTSC interests.
    pub instructions: InstructionRequirements,
}

impl EffectiveRequirements {
    /// Merge stated requirements, subscriptions, and query answers.
    ///
    /// Subscriptions only ever *add* instruction-mediation demands; they
    /// never relax window, lifecycle, placement, debugger, or density
    /// requirements (interests are not restrictions).
    pub fn compute(
        stated: ToolRequirements,
        subscriptions: Subscription,
        queries: ToolQueries,
    ) -> Self {
        let mut instructions = stated.instructions;
        instructions.cpuid |= subscriptions.has_cpuid();
        instructions.rdtsc |= subscriptions.has_rdtsc();
        Self {
            stated,
            subscriptions,
            queries,
            instructions,
        }
    }
}
/// A design cell: one row of the combination matrix (activation ×
/// mechanism × placement). A design cell is an obligation, not a
/// selectable implementation; see [`ImplementedCell`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DesignCell {
    /// V1: ptrace exec-stop × ptrace stops × out-of-process (reference).
    V1,
    /// V2: exec-stop loader × seccomp trap × in-guest.
    V2,
    /// V3: exec-stop loader × in-place patching × in-guest.
    V3,
    /// V4: preload × seccomp trap × in-guest (declared window).
    V4,
    /// V5: preload × in-place patching × in-guest (declared window).
    V5,
    /// V6: page-fault gate, then patch/trap inside admitted pages.
    V6,
    /// V7: offline-rewritten image × in-guest runtime.
    V7,
    /// V8: custom no-ptrace loader × trap/patch/gate × in-guest.
    V8,
    /// V9: V8 with an external tracer present (debugger coexistence).
    V9,
    /// V10: translation (discovery by execution) × in-guest.
    V10,
    /// V11: virtual-machine substrate (VM exits replace host
    /// interception; lifecycle is emulated by the backend).
    V11,
}

impl DesignCell {
    /// Every design cell, in matrix order.
    pub const ALL: [Self; 11] = [
        Self::V1,
        Self::V2,
        Self::V3,
        Self::V4,
        Self::V5,
        Self::V6,
        Self::V7,
        Self::V8,
        Self::V9,
        Self::V10,
        Self::V11,
    ];

    /// Short matrix name (`"V1"` … `"V11"`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::V1 => "V1",
            Self::V2 => "V2",
            Self::V3 => "V3",
            Self::V4 => "V4",
            Self::V5 => "V5",
            Self::V6 => "V6",
            Self::V7 => "V7",
            Self::V8 => "V8",
            Self::V9 => "V9",
            Self::V10 => "V10",
            Self::V11 => "V11",
        }
    }
}

impl core::fmt::Display for DesignCell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether a design cell exists as running code anywhere (as opposed to
/// being an implementable obligation or a design only). Recorded for
/// refusal traces; *selectability* in this repository is decided solely
/// by [`implemented_cells`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Existence {
    /// The combination runs today.
    Runs,
    /// The combination is implementable from existing parts but is not an
    /// implemented, selectable cell.
    Buildable,
    /// Design only; not built.
    Unbuilt,
}

/// One design-cell row, for explainability (which unregistered rows would
/// have satisfied a refused request).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignCellInfo {
    /// The design cell.
    pub design: DesignCell,
    /// Whether the combination exists anywhere today.
    pub existence: Existence,
    /// The window the design provides.
    pub window: WindowGuarantee,
    /// Where the tool runs in this design.
    pub placement: Placement,
}

/// The design matrix. Existence here never grants selectability; only
/// [`implemented_cells`] does.
pub fn design_cells() -> &'static [DesignCellInfo] {
    use Existence::*;
    use Placement::*;
    use WindowGuarantee::*;
    &[
        DesignCellInfo {
            design: DesignCell::V1,
            existence: Runs,
            window: Zero,
            placement: OutOfProcess,
        },
        DesignCellInfo {
            design: DesignCell::V2,
            existence: Buildable,
            window: Zero,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V3,
            existence: Buildable,
            window: Zero,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V4,
            existence: Runs,
            window: DeclaredPreInit,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V5,
            existence: Runs,
            window: DeclaredPreInit,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V6,
            existence: Buildable,
            window: Zero,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V7,
            existence: Buildable,
            window: Zero,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V8,
            existence: Unbuilt,
            window: Zero,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V9,
            existence: Unbuilt,
            window: Zero,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V10,
            existence: Unbuilt,
            window: Zero,
            placement: InGuest,
        },
        DesignCellInfo {
            design: DesignCell::V11,
            existence: Runs,
            window: Zero,
            placement: OutOfProcess,
        },
    ]
}

/// How the guest is first brought under control (first-instruction axis).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Activation {
    /// A1: ptrace stop at exec, before the first guest instruction.
    PtraceExecStop,
    /// A2: `LD_PRELOAD` late activation (declared pre-init window).
    PreloadLate,
    /// A3: custom loader, no ptrace.
    CustomLoaderNoPtrace,
    /// A4: attach to a running process (absent).
    Attach,
    /// A5: coexist with an external ptrace debugger.
    ExternalDebuggerCoexist,
    /// Virtual-machine substrate: the guest starts inside the VM.
    VmSubstrate,
}

/// How events are intercepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mechanism {
    /// B1: seccomp trap (`RET_TRAP`/`SIGSYS`).
    SeccompTrap,
    /// B3: in-place patching of known sites, over a completeness trap.
    InPlacePatching,
    /// B4: page-fault gating before patch/trap inside admitted pages.
    PageFaultGate,
    /// B5: ahead-of-time/offline rewriting.
    OfflineRewrite,
    /// B6: out-of-place translation (discovery by execution).
    Translation,
    /// B7: ptrace stops.
    PtraceStops,
    /// VM exits / hypercalls.
    VmExits,
}

/// Where the tool's code runs in a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Placement {
    /// Inside the guest process (shares its descriptor table).
    InGuest,
    /// Outside the guest process.
    OutOfProcess,
}

/// The concrete configuration of an implemented cell. Two configurations
/// of one backend (for example site patching on vs off) are different
/// cells with different envelopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CellConfig {
    /// ptrace backend, default configuration.
    PtraceDefault,
    /// Preload in-guest runtime with site patching off: every syscall
    /// traps.
    PreloadTrapOnly,
    /// Preload in-guest runtime with site patching on, over the trap.
    PreloadPatching,
    /// KVM substrate running a static ELF image.
    KvmStaticElf,
}

/// The unmonitored window a cell guarantees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WindowGuarantee {
    /// Armed before the first guest instruction, including successors.
    Zero,
    /// Loader/IFUNC/early-constructor execution before initialisation
    /// runs unmonitored. Structural for preload activation; no mechanism
    /// choice removes it.
    DeclaredPreInit,
}

/// Steady-state cost shape, used only to rank already-eligible cells.
/// This ordering is a heuristic, not a benchmark; no cell may be quoted
/// as a performance result from it.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize
)]
pub enum CostClass {
    /// Patched sites run near-natively.
    Patch = 0,
    /// First-touch gate fault per page, then patched/trap cost.
    GateThenPatch = 1,
    /// In-guest trap per event.
    Trap = 2,
    /// Out-of-process ptrace stop per event.
    Ptrace = 3,
    /// Translated code-cache execution.
    Translation = 4,
    /// VM-exit substrate (not comparable to host interception costs;
    /// ranked last among eligible cells).
    VmExit = 5,
}

/// How strongly one lifecycle axis is guaranteed by a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifecycleLevel {
    /// Same as the reference (ptrace) behaviour.
    Reference,
    /// Followed with the tool contract intact.
    Followed,
    /// Weaker in a way the tool must have declared (see
    /// [`LifecycleRequirements`]).
    DeclaredWeaker,
    /// Refused by name at runtime; the guest behaviour does not proceed
    /// unmonitored, but it does not proceed.
    Refuses,
    /// Implemented by the backend's own emulation, not the host kernel.
    Emulated,
    /// Not proven for this cell; counts as not provided.
    Unproven,
}

impl LifecycleLevel {
    /// Whether this level satisfies a `true` lifecycle requirement.
    fn satisfies(self) -> bool {
        matches!(self, Self::Reference | Self::Followed | Self::Emulated)
    }

    /// Strength for tie-breaking (higher is stronger).
    fn strength(self) -> u32 {
        match self {
            Self::Reference => 4,
            Self::Followed => 3,
            Self::Emulated => 2,
            Self::DeclaredWeaker => 1,
            Self::Refuses | Self::Unproven => 0,
        }
    }
}

/// Per-axis lifecycle guarantees of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LifecycleGuarantees {
    /// New threads observed from their first instruction.
    pub threads: LifecycleLevel,
    /// `fork` children followed.
    pub fork: LifecycleLevel,
    /// `vfork` children followed.
    pub vfork: LifecycleLevel,
    /// Successor images re-armed under the same cell.
    pub exec_successor: LifecycleLevel,
    /// Signal fidelity versus the reference contract.
    pub signals: LifecycleLevel,
}

/// How a cell covers code it did not census ahead of time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CodeCoverage {
    /// A per-process trap catches events from any code, censused or not.
    AnyCodeByTrap,
    /// Known sites are patched; anything unpatched falls into the trap.
    /// New code is therefore covered (at trap cost) rather than missed.
    CensusPatchPlusTrapFallback,
    /// Only censused sites are covered; unknown code would run
    /// unmonitored. Never satisfies [`DynamicCodeNeed::MustCover`]: a
    /// patch-only path cannot promise a fault it never causes.
    CensusPatchOnly,
    /// Only certified, gate-admitted code runs; arbitrary new code
    /// refuses.
    GatedCertifiedOnly,
    /// Code is discovered by executing it under translation.
    TranslationDiscovery,
    /// The backend emulates execution; coverage is by construction.
    Emulated,
}

impl CodeCoverage {
    /// Whether dynamically created code is covered rather than missed.
    fn covers_dynamic(self) -> bool {
        matches!(
            self,
            Self::AnyCodeByTrap
                | Self::CensusPatchPlusTrapFallback
                | Self::TranslationDiscovery
                | Self::Emulated
        )
    }
}

/// How one instruction class is mediated by a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum InstructionMediation {
    /// Mediated unconditionally by the mechanism.
    Mediated,
    /// Mediated only when the named environment support is proved
    /// (`"P5"` CPUID faulting, `"P6"` `PR_SET_TSC`). Its absence removes
    /// the cell; it never degrades to unmediated execution.
    RequiresEnv(&'static str),
    /// Not mediated by this cell.
    Absent,
}

/// Per-class instruction mediation of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct InstructionGuarantees {
    /// `CPUID` mediation.
    pub cpuid: InstructionMediation,
    /// `RDTSC` mediation.
    pub rdtsc: InstructionMediation,
    /// `RDRAND`/`RDSEED` mediation.
    pub rdrand_rdseed: InstructionMediation,
    /// `XGETBV` mediation.
    pub xgetbv: InstructionMediation,
}

/// The boundaries inside which a cell has actually been tested. Admission
/// outside the envelope is a refusal, however plausible success looks;
/// widening an envelope is a code change with tests, not a runtime hope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct TestedEnvelope {
    /// Which guest profiles the cell covers.
    pub guest: GuestShape,
    /// Thread bound the cell was tested to.
    pub threads: ThreadsBound,
    /// How the cell treats a guest `execve`.
    pub exec: ExecBound,
    /// Whether reserved input (see [`ToolQueries::reserved_input`]) is
    /// part of the tested envelope. Unproven is `false`.
    pub reserved_input: bool,
    /// Whether required signal ownership is (re)validated at handoff
    /// rather than at admission (guest dispositions are not observable
    /// before the guest runs).
    pub signal_ownership_at_handoff: bool,
    /// Whether this backend acts on [`ThreadOwnership`]: under
    /// `ThreadOwnership::Host` its child threads run *unmonitored*, so a
    /// monitored-threads requirement cannot be met in that configuration.
    /// Backends that route every thread through the tool ignore the
    /// setting and answer `false`.
    pub honors_thread_ownership: bool,
    /// One line naming the envelope's evidence/boundary, for logs.
    pub notes: &'static str,
}

/// Guest shapes a tested envelope covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuestShape {
    /// Any host process.
    AnyHostProcess,
    /// Dynamically linked, non-secure-execution host processes only.
    DynamicPreloadableOnly,
    /// Static ELF images on the VM substrate only.
    StaticElfVmOnly,
}

impl GuestShape {
    /// Whether this envelope covers the stated guest profile.
    fn covers(self, profile: GuestProfile) -> bool {
        matches!(
            (self, profile),
            (Self::AnyHostProcess, GuestProfile::HostProcessAny)
                | (
                    Self::AnyHostProcess,
                    GuestProfile::HostProcessDynamicPreloadable
                )
                | (
                    Self::DynamicPreloadableOnly,
                    GuestProfile::HostProcessDynamicPreloadable
                )
                | (Self::StaticElfVmOnly, GuestProfile::StaticElfVm)
        )
    }
}

/// Thread bound of a tested envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadsBound {
    /// Multi-threaded guests are in the envelope.
    MultiThread,
    /// Only single-threaded guests are in the envelope; thread creation
    /// refuses by name at runtime.
    SingleThread,
}

/// Exec bound of a tested envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecBound {
    /// Successors are re-armed under the same cell.
    RearmedSameCell,
    /// Guest `execve` refuses by name at runtime.
    Refused,
    /// Successors are carried by the backend's emulation.
    Emulated,
}

/// Whether a cell can run while an external tracer owns the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerSupport {
    /// The cell needs exclusive tracing control of the guest.
    ExclusiveOnly,
    /// The cell never requires ptrace and never disturbs an existing
    /// tracer relationship.
    Coexists,
}

/// Stable identifier of an implemented cell, for logs, explicit
/// selection, and test assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct CellId(pub &'static str);

impl core::fmt::Display for CellId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// Stable identifier of the implementing backend, for invocation and
/// explainability. (Behavioural facts belong in the cell's guarantees and
/// capabilities, never inferred from this name.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct BackendId(pub &'static str);

impl core::fmt::Display for BackendId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// One implemented, selectable cell: an exact
/// activation/mechanism/placement/configuration, its guarantees, and the
/// envelope it was tested in. Only cells returned by
/// [`implemented_cells`] may be chosen by [`admit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ImplementedCell {
    /// Stable cell identifier.
    pub id: CellId,
    /// The design cell this implements.
    pub design: DesignCell,
    /// How the guest is brought under control.
    pub activation: Activation,
    /// How events are intercepted.
    pub mechanism: Mechanism,
    /// Where the tool runs.
    pub placement: Placement,
    /// The exact configuration.
    pub config: CellConfig,
    /// The unmonitored window.
    pub window: WindowGuarantee,
    /// Heuristic cost shape (ranking only).
    pub cost: CostClass,
    /// Lifecycle guarantees.
    pub lifecycle: LifecycleGuarantees,
    /// Coverage of uncensused code.
    pub code: CodeCoverage,
    /// Instruction mediation per class.
    pub instructions: InstructionGuarantees,
    /// External-debugger coexistence.
    pub debugger: DebuggerSupport,
    /// The tested envelope.
    pub envelope: TestedEnvelope,
    /// The backend's static run facts. Must equal the
    /// [`BackendCapabilities`] constant for this implementation (pinned
    /// by test); necessary, never sufficient, for admission.
    pub capabilities: BackendCapabilities,
    /// The implementing backend.
    pub backend: BackendId,
}

/// The implemented cells, and the *only* selectable set for [`admit`].
///
/// Registration is deliberately explicit and small. Design cells whose
/// implementation is buildable-from-parts, feature-gated off, or present
/// only as a capabilities constant are absent — satisfying requirements
/// only through such a row yields [`RefusalCode::RUnbuilt`], not a silent
/// substitution. The KVM cell is registered for admission and
/// explainability: its lifecycle is the backend's emulation, not host
/// interception, and hosts still invoke it through its own entry points.
pub fn implemented_cells() -> &'static [ImplementedCell] {
    use InstructionMediation as M;
    use LifecycleLevel as L;
    &[
        ImplementedCell {
            id: CellId("V1-ptrace"),
            design: DesignCell::V1,
            activation: Activation::PtraceExecStop,
            mechanism: Mechanism::PtraceStops,
            placement: Placement::OutOfProcess,
            config: CellConfig::PtraceDefault,
            window: WindowGuarantee::Zero,
            cost: CostClass::Ptrace,
            lifecycle: LifecycleGuarantees {
                threads: L::Reference,
                fork: L::Reference,
                vfork: L::Reference,
                exec_successor: L::Reference,
                signals: L::Reference,
            },
            code: CodeCoverage::AnyCodeByTrap,
            instructions: InstructionGuarantees {
                cpuid: M::RequiresEnv("P5"),
                rdtsc: M::RequiresEnv("P6"),
                rdrand_rdseed: M::Absent,
                xgetbv: M::Absent,
            },
            debugger: DebuggerSupport::ExclusiveOnly,
            envelope: TestedEnvelope {
                guest: GuestShape::AnyHostProcess,
                threads: ThreadsBound::MultiThread,
                exec: ExecBound::RearmedSameCell,
                reserved_input: true,
                signal_ownership_at_handoff: false,
                honors_thread_ownership: false,
                notes: "reference backend; kernel follows fork/exec; CPUID/RDTSC via faulting prerequisites P5/P6",
            },
            capabilities: BackendCapabilities::PTRACE,
            backend: BackendId("reverie-ptrace"),
        },
        ImplementedCell {
            id: CellId("V4-preload-trap"),
            design: DesignCell::V4,
            activation: Activation::PreloadLate,
            mechanism: Mechanism::SeccompTrap,
            placement: Placement::InGuest,
            config: CellConfig::PreloadTrapOnly,
            window: WindowGuarantee::DeclaredPreInit,
            cost: CostClass::Trap,
            lifecycle: LifecycleGuarantees {
                threads: L::Refuses,
                fork: L::Followed,
                vfork: L::DeclaredWeaker,
                exec_successor: L::Refuses,
                signals: L::DeclaredWeaker,
            },
            code: CodeCoverage::AnyCodeByTrap,
            instructions: InstructionGuarantees {
                cpuid: M::RequiresEnv("P5"),
                rdtsc: M::RequiresEnv("P6"),
                rdrand_rdseed: M::Absent,
                xgetbv: M::Absent,
            },
            debugger: DebuggerSupport::ExclusiveOnly,
            envelope: TestedEnvelope {
                guest: GuestShape::DynamicPreloadableOnly,
                threads: ThreadsBound::SingleThread,
                exec: ExecBound::Refused,
                reserved_input: false,
                signal_ownership_at_handoff: true,
                honors_thread_ownership: false,
                notes: "preload in-guest trap; dynamic non-AT_SECURE single-thread envelope; thread creation and exec refuse by name",
            },
            capabilities: BackendCapabilities::LITEINST_IN_GUEST,
            backend: BackendId("reverie-liteinst-preload"),
        },
        ImplementedCell {
            id: CellId("V5-preload-patch"),
            design: DesignCell::V5,
            activation: Activation::PreloadLate,
            mechanism: Mechanism::InPlacePatching,
            placement: Placement::InGuest,
            config: CellConfig::PreloadPatching,
            window: WindowGuarantee::DeclaredPreInit,
            cost: CostClass::Patch,
            lifecycle: LifecycleGuarantees {
                threads: L::Refuses,
                fork: L::Followed,
                vfork: L::DeclaredWeaker,
                exec_successor: L::Refuses,
                signals: L::DeclaredWeaker,
            },
            code: CodeCoverage::CensusPatchPlusTrapFallback,
            instructions: InstructionGuarantees {
                cpuid: M::RequiresEnv("P5"),
                rdtsc: M::RequiresEnv("P6"),
                rdrand_rdseed: M::Absent,
                xgetbv: M::Absent,
            },
            debugger: DebuggerSupport::ExclusiveOnly,
            envelope: TestedEnvelope {
                guest: GuestShape::DynamicPreloadableOnly,
                threads: ThreadsBound::SingleThread,
                exec: ExecBound::Refused,
                reserved_input: false,
                signal_ownership_at_handoff: true,
                honors_thread_ownership: false,
                notes: "preload site patching over the in-guest completeness trap; same envelope as V4-preload-trap",
            },
            capabilities: BackendCapabilities::LITEINST_IN_GUEST,
            backend: BackendId("reverie-liteinst-preload"),
        },
        ImplementedCell {
            id: CellId("V11-kvm"),
            design: DesignCell::V11,
            activation: Activation::VmSubstrate,
            mechanism: Mechanism::VmExits,
            placement: Placement::OutOfProcess,
            config: CellConfig::KvmStaticElf,
            window: WindowGuarantee::Zero,
            cost: CostClass::VmExit,
            lifecycle: LifecycleGuarantees {
                threads: L::Emulated,
                fork: L::Emulated,
                vfork: L::Emulated,
                // Leader exec is emulated; non-leader exec refuses by name
                // at runtime, so strict successor coverage is not met.
                exec_successor: L::DeclaredWeaker,
                // Stop-signal delivery refuses by name at runtime, so
                // reference signal fidelity is not met.
                signals: L::DeclaredWeaker,
            },
            code: CodeCoverage::Emulated,
            instructions: InstructionGuarantees {
                cpuid: M::Mediated,
                rdtsc: M::Mediated,
                rdrand_rdseed: M::Absent,
                xgetbv: M::Absent,
            },
            debugger: DebuggerSupport::ExclusiveOnly,
            envelope: TestedEnvelope {
                guest: GuestShape::StaticElfVmOnly,
                threads: ThreadsBound::MultiThread,
                exec: ExecBound::Emulated,
                reserved_input: false,
                signal_ownership_at_handoff: false,
                honors_thread_ownership: true,
                notes: "VM substrate with backend-emulated Linux lifecycle; static ELF images; non-leader exec and stop signals refuse by name; registered for admission/explainability, invoked via its own entry points",
            },
            capabilities: BackendCapabilities::KVM,
            backend: BackendId("reverie-kvm"),
        },
    ]
}
/// Why admission refused. Every refusal is a typed value surfaced before
/// the guest runs (or, for handoff/re-admission, with the guest stopped);
/// "unsupported" without a name is a bug.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RefusalCode {
    /// `R-ARCH`: not Linux x86-64 / kernel floor unmet (P10).
    RArch,
    /// `R-PTRACE`: ptrace required but denied, or the guest is already
    /// traced (P1, P2).
    RPtrace,
    /// `R-WINDOW`: only a windowed activation is available; the tool
    /// requires zero window.
    RWindow,
    /// `R-CODE`: code cannot be censused/gated for the mechanism (JIT,
    /// interior entries, unpatchable sites with no fallback).
    RCode,
    /// `R-SIGNAL`: required signal ownership/control is unavailable.
    RSignal,
    /// `R-WX`: mapping policy forbids the arena/gate shape (P7).
    RWx,
    /// `R-INSTR`: a required instruction class cannot be mediated in any
    /// admitted cell.
    RInstr,
    /// `R-EXEC`: a successor image cannot be re-armed under the retained
    /// plan.
    RExec,
    /// `R-LIFECYCLE`: required thread/fork/signal behaviour is unproven
    /// in every admitted cell.
    RLifecycle,
    /// `R-DENSE`: dense instrumentation required; no translation cell is
    /// implemented.
    RDense,
    /// `R-UNBUILT`: the only satisfying cells are valid designs with no
    /// implemented, registered cell.
    RUnbuilt,
    /// `R-ENV-UNKNOWN`: a load-bearing environment fact could not be
    /// proved or disproved.
    REnvUnknown,
}

impl RefusalCode {
    /// The hyphenated taxonomy name (`"R-WINDOW"` etc.).
    pub const fn name(self) -> &'static str {
        match self {
            Self::RArch => "R-ARCH",
            Self::RPtrace => "R-PTRACE",
            Self::RWindow => "R-WINDOW",
            Self::RCode => "R-CODE",
            Self::RSignal => "R-SIGNAL",
            Self::RWx => "R-WX",
            Self::RInstr => "R-INSTR",
            Self::RExec => "R-EXEC",
            Self::RLifecycle => "R-LIFECYCLE",
            Self::RDense => "R-DENSE",
            Self::RUnbuilt => "R-UNBUILT",
            Self::REnvUnknown => "R-ENV-UNKNOWN",
        }
    }
}

impl core::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Why one cell was removed by one filter stage. Keep the set
/// meaningful — every variant must be a claim a log reader can act on,
/// never a catch-all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum RemovalReason {
    /// The cell's window exceeds the tool's tolerance.
    WindowMismatch,
    /// The cell's placement violates the placement requirement.
    PlacementMismatch,
    /// The cell cannot coexist with an external debugger.
    DebuggerMismatch,
    /// Dense instrumentation required; this is not a translation cell.
    DenseUnsupported,
    /// The named instruction class is not mediated by this cell.
    InstructionUnmediated(&'static str),
    /// The named instruction class needs environment support (the named
    /// probe) that was disproved.
    InstructionEnvDisproved(&'static str),
    /// The named lifecycle guarantee is not provided at the required
    /// strength.
    LifecycleUnproven(&'static str),
    /// Successor images are not re-armed by this cell.
    ExecUnproven,
    /// Dynamically created code would not be covered.
    CodeUncovered,
    /// The named signal facility is unavailable in this cell.
    SignalUnavailable(&'static str),
    /// The stated guest profile is outside the tested envelope.
    GuestShapeMismatch,
    /// Reserved input is outside the tested envelope.
    ReservedInputUnsupported,
    /// A required environment fact (named probe) was disproved.
    EnvDisproved(&'static str),
    /// A required environment fact (named probe) is unknown; the
    /// admission predicate is unproved.
    EnvUnknown(&'static str),
    /// An explicit selection named a different cell/backend.
    NotExplicitlySelected,
}

impl RemovalReason {
    /// The refusal code this reason maps to when it is the blocker.
    fn code(self) -> RefusalCode {
        match self {
            Self::WindowMismatch => RefusalCode::RWindow,
            Self::PlacementMismatch
            | Self::LifecycleUnproven(_)
            | Self::GuestShapeMismatch
            | Self::ReservedInputUnsupported => RefusalCode::RLifecycle,
            Self::DebuggerMismatch => RefusalCode::RUnbuilt,
            Self::DenseUnsupported => RefusalCode::RDense,
            Self::InstructionUnmediated(_) | Self::InstructionEnvDisproved(_) => {
                RefusalCode::RInstr
            }
            Self::ExecUnproven => RefusalCode::RExec,
            Self::CodeUncovered => RefusalCode::RCode,
            Self::SignalUnavailable(_) => RefusalCode::RSignal,
            Self::EnvDisproved("P1") | Self::EnvDisproved("P2") => RefusalCode::RPtrace,
            Self::EnvDisproved("P8") => RefusalCode::RSignal,
            Self::EnvDisproved("P7") => RefusalCode::RWx,
            Self::EnvDisproved("P10") => RefusalCode::RArch,
            Self::EnvDisproved(_) => RefusalCode::RLifecycle,
            Self::EnvUnknown(_) => RefusalCode::REnvUnknown,
            Self::NotExplicitlySelected => RefusalCode::RLifecycle,
        }
    }

    /// Whether this removal rests on an unknown (not proved/disproved)
    /// fact. A cell removed only for such reasons is not definitively
    /// ineligible.
    fn is_unknown(self) -> bool {
        matches!(self, Self::EnvUnknown(_))
    }
}

/// One named filter stage and every cell it removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilterStage {
    /// Stage name (`"requirements"`, `"environment"`,
    /// `"explicit-selection"`).
    pub name: &'static str,
    /// Cells removed here, each with every reason found.
    pub removed: Vec<(CellId, Vec<RemovalReason>)>,
}

/// The full record of how a candidate set was filtered: which cells each
/// stage removed and why. "Why won't it run?" is answered here, not by
/// reading source.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FilterTrace {
    /// Stages in application order.
    pub stages: Vec<FilterStage>,
    /// Design cells (registered or not) whose design-level guarantees
    /// would satisfy the requirements; names the obligation behind an
    /// [`RefusalCode::RUnbuilt`] refusal.
    pub satisfying_designs: Vec<DesignCell>,
}

impl FilterTrace {
    /// Every removal reason recorded for one cell, across stages.
    pub fn reasons_for(&self, id: CellId) -> Vec<RemovalReason> {
        let mut out = Vec::new();
        for stage in &self.stages {
            for (cell, reasons) in &stage.removed {
                if *cell == id {
                    out.extend(reasons.iter().copied());
                }
            }
        }
        out
    }
}

/// A typed admission refusal. Distinct from any guest errno and from
/// per-operation [`UnsupportedRefusal`](crate::UnsupportedRefusal)s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmissionRefusal {
    /// The named refusal.
    pub code: RefusalCode,
    /// One-line human detail (never the only signal; `code` is).
    pub detail: String,
    /// Which cells each stage removed and why.
    pub trace: FilterTrace,
    /// `true` when the failure was discovered after irreversible
    /// installation (handoff / re-admission): the host must stop, never
    /// retry another backend under a weaker reading.
    pub terminal: bool,
}

impl core::fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "REFUSED: {}: {}", self.code, self.detail)
    }
}

impl std::error::Error for AdmissionRefusal {}

/// An explicit host selection, honoured exactly or refused by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum ExplicitSelection {
    /// Rank the eligible cells automatically (heuristic; see module docs).
    Auto,
    /// Exactly this cell.
    Cell(CellId),
    /// Exactly this backend's cell(s); ranked among themselves if more
    /// than one configuration is registered, never widened beyond it.
    Backend(BackendId),
}

/// One admission request: tool + guest + environment + selection policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmissionRequest {
    /// Merged tool requirements.
    pub requirements: EffectiveRequirements,
    /// What the host will run.
    pub guest: GuestProfile,
    /// Pure environment observations.
    pub env: EnvironmentSnapshot,
    /// Explicit selection policy.
    pub explicit: ExplicitSelection,
}

/// A successful admission: everything a run must log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmissionReport {
    /// The requirements that were filtered on.
    pub requirements: EffectiveRequirements,
    /// The guest profile that was filtered on.
    pub guest: GuestProfile,
    /// The environment snapshot that was filtered on.
    pub env: EnvironmentSnapshot,
    /// Every eligible cell, in ranking order (heuristic; see `cost_note`).
    pub eligible: Vec<CellId>,
    /// The chosen cell (first eligible under the selection policy).
    pub chosen: CellId,
    /// The chosen cell's tested-envelope note.
    pub envelope_notes: &'static str,
    /// Reminder, in every report, that ranking is a heuristic cost shape,
    /// not a performance claim.
    pub cost_note: &'static str,
    /// Which cells each stage removed and why.
    pub trace: FilterTrace,
}

/// Note carried in every [`AdmissionReport`].
pub const COST_HEURISTIC_NOTE: &str =
    "cost order is a heuristic (patch < gate+patch < trap < ptrace < translation), not a benchmark";

/// Whether a window requirement accepts a cell's guarantee.
fn window_accepts(req: WindowRequirement, cell: WindowGuarantee) -> bool {
    matches!(
        (req, cell),
        (_, WindowGuarantee::Zero)
            | (
                WindowRequirement::Declared { pre_init_ok: true },
                WindowGuarantee::DeclaredPreInit
            )
    )
}

/// Requirements-stage reasons for one cell (empty = passes this stage).
fn requirement_reasons(
    req: &EffectiveRequirements,
    guest: GuestProfile,
    cell: &ImplementedCell,
) -> Vec<RemovalReason> {
    use RemovalReason as R;
    let mut out = Vec::new();
    let stated = &req.stated;
    if !window_accepts(stated.window, cell.window) {
        out.push(R::WindowMismatch);
    }
    let placement_ok = match stated.placement {
        PlacementRequirement::Any => true,
        PlacementRequirement::InGuestOnly => cell.placement == Placement::InGuest,
        PlacementRequirement::OutOfProcessOnly => cell.placement == Placement::OutOfProcess,
    } && (!req.queries.in_guest_signal_delivery
        || cell.placement == Placement::InGuest);
    if !placement_ok {
        out.push(R::PlacementMismatch);
    }
    if stated.debugger == DebuggerRequirement::CoexistWithExternal
        && cell.debugger == DebuggerSupport::ExclusiveOnly
    {
        out.push(R::DebuggerMismatch);
    }
    if stated.density == Density::Dense && cell.mechanism != Mechanism::Translation {
        out.push(R::DenseUnsupported);
    }
    let life = &stated.lifecycle;
    if life.threads && !cell.lifecycle.threads.satisfies() {
        out.push(R::LifecycleUnproven("threads"));
    }
    // Host-owned threads run unmonitored on backends that honor the
    // setting: demanding monitored threads in that configuration is a
    // contradiction, not a satisfiable requirement. Uncollected
    // ownership (`None`) likewise fails closed there: coverage is
    // unproved until ownership is known not to be Host.
    if life.threads
        && cell.envelope.honors_thread_ownership
        && req.queries.thread_ownership != Some(ThreadOwnership::Tool)
        && !out.contains(&R::LifecycleUnproven("threads"))
    {
        out.push(R::LifecycleUnproven("threads"));
    }
    // Joint installer prerequisite: in-guest signal delivery refuses a
    // runtime with site patching on (a patched site reaches the tool
    // without the fallback continuation the delivery protocol needs).
    if req.queries.in_guest_signal_delivery && cell.config == CellConfig::PreloadPatching {
        out.push(R::SignalUnavailable(
            "in-guest signal delivery with site patching",
        ));
    }
    if life.fork && !cell.lifecycle.fork.satisfies() {
        out.push(R::LifecycleUnproven("fork"));
    }
    if life.vfork && !cell.lifecycle.vfork.satisfies() {
        out.push(R::LifecycleUnproven("vfork"));
    }
    if life.exec_successor && !cell.lifecycle.exec_successor.satisfies() {
        out.push(R::ExecUnproven);
    }
    if life.signal_fidelity && !cell.lifecycle.signals.satisfies() {
        out.push(R::LifecycleUnproven("signals"));
    }
    if life.dynamic_code == DynamicCodeNeed::MustCover && !cell.code.covers_dynamic() {
        out.push(R::CodeUncovered);
    }
    // Static instruction mediation (environment prerequisites are checked
    // in the environment stage; Absent is already definitive here).
    let instr = &req.instructions;
    for (wanted, got, name) in [
        (instr.cpuid, cell.instructions.cpuid, "CPUID"),
        (instr.rdtsc, cell.instructions.rdtsc, "RDTSC"),
        (
            instr.rdrand_rdseed,
            cell.instructions.rdrand_rdseed,
            "RDRAND/RDSEED",
        ),
        (instr.xgetbv, cell.instructions.xgetbv, "XGETBV"),
    ] {
        if wanted && got == InstructionMediation::Absent {
            out.push(R::InstructionUnmediated(name));
        }
    }
    if req.queries.requires_signal_control && !cell.capabilities.provides_process_signal_control {
        out.push(R::SignalUnavailable("process signal control"));
    }
    if req.queries.observes_sigreturns && !cell.capabilities.reports_sigreturns {
        out.push(R::SignalUnavailable("sigreturn reports"));
    }
    // Joint installer prerequisite: the facility behind the envelope
    // fact is constructed only for a tool that also enforces serialized
    // execution — and an uncollected (`None`) answer cannot prove it.
    if req.queries.reserved_input
        && !(cell.envelope.reserved_input
            && req.queries.enforces_serialized_execution == Some(true))
    {
        out.push(R::ReservedInputUnsupported);
    }
    if !cell.envelope.guest.covers(guest) {
        out.push(R::GuestShapeMismatch);
    }
    out
}

/// Whether a `Knowledge<bool>` probe gating `name` admits, as a reason.
fn bool_probe(fact: &Knowledge<bool>, name: &'static str) -> Option<RemovalReason> {
    match fact {
        Knowledge::Proved(true) => None,
        Knowledge::Proved(false) | Knowledge::Disproved => Some(RemovalReason::EnvDisproved(name)),
        Knowledge::Unknown { .. } => Some(RemovalReason::EnvUnknown(name)),
    }
}

/// Environment-stage reasons for one cell (empty = passes this stage).
///
/// P4 (SUD) is never consulted: it is optional acceleration only. P9 only
/// tightens: proved JIT indicators remove a patch-only cell when dynamic
/// coverage is required; P9 can never admit anything. P2 is deliberately
/// not consulted here: for a fresh exec this backend *becomes* the
/// tracer, so existing-tracer ownership of the actual guest is a
/// handoff fact ([`HandoffFacts::tracer_pid`]), checked terminally
/// there. P8 is consulted only when actually observed disproved —
/// guest dispositions are otherwise handoff facts too.
fn environment_reasons(
    req: &EffectiveRequirements,
    env: &EnvironmentSnapshot,
    cell: &ImplementedCell,
) -> Vec<RemovalReason> {
    use RemovalReason as R;
    let mut out = Vec::new();
    // P10 gates everything.
    match &env.p10_arch {
        Knowledge::Proved(floor) if floor.linux_x86_64 => {}
        Knowledge::Proved(_) | Knowledge::Disproved => out.push(R::EnvDisproved("P10")),
        Knowledge::Unknown { .. } => out.push(R::EnvUnknown("P10")),
    }
    match cell.activation {
        Activation::PtraceExecStop => {
            if let Some(reason) = bool_probe(&env.p1_ptrace_usable, "P1") {
                out.push(reason);
            }
        }
        Activation::PreloadLate => match &env.p3_seccomp {
            // Strict mode forbids installing another filter outright.
            Knowledge::Proved(state) if state.mode == 1 => out.push(R::EnvDisproved("P3")),
            // Only an actual install trial proves installation/nesting;
            // mode and no_new_privs metadata do not.
            Knowledge::Proved(state) if state.install_proved => {}
            Knowledge::Proved(_) => out.push(R::EnvUnknown("P3")),
            Knowledge::Disproved => out.push(R::EnvDisproved("P3")),
            Knowledge::Unknown { .. } => out.push(R::EnvUnknown("P3")),
        },
        _ => {}
    }
    // P8 early refusal only on an actually observed denial; the usual
    // Unknown remains a handoff check, not an admission gate.
    if cell.envelope.signal_ownership_at_handoff
        && matches!(
            env.p8_signal_ownership,
            Knowledge::Proved(false) | Knowledge::Disproved
        )
    {
        out.push(R::EnvDisproved("P8"));
    }
    if cell.mechanism == Mechanism::InPlacePatching {
        match &env.p7_wx {
            Knowledge::Proved(WxPolicy::DualMapAllowed) => {}
            Knowledge::Proved(WxPolicy::StrictWx) | Knowledge::Disproved => {
                out.push(R::EnvDisproved("P7"))
            }
            Knowledge::Unknown { .. } => out.push(R::EnvUnknown("P7")),
        }
    }
    // Instruction environment prerequisites: absence removes the cell,
    // never degrades coverage.
    let instr = &req.instructions;
    for (wanted, got) in [
        (instr.cpuid, cell.instructions.cpuid),
        (instr.rdtsc, cell.instructions.rdtsc),
        (instr.rdrand_rdseed, cell.instructions.rdrand_rdseed),
        (instr.xgetbv, cell.instructions.xgetbv),
    ] {
        if !wanted {
            continue;
        }
        if let InstructionMediation::RequiresEnv(probe) = got {
            let fact = match probe {
                "P5" => &env.p5_cpuid_faulting,
                "P6" => &env.p6_pr_set_tsc,
                // An unknown prerequisite name is unproved, never a
                // free pass (admit_over candidates may name future ones).
                other => {
                    out.push(R::EnvUnknown(other));
                    continue;
                }
            };
            match fact {
                Knowledge::Proved(true) => {}
                Knowledge::Proved(false) | Knowledge::Disproved => {
                    out.push(R::InstructionEnvDisproved(probe))
                }
                Knowledge::Unknown { .. } => out.push(R::EnvUnknown(probe)),
            }
        }
    }
    // P9 advisory tightening only.
    if req.stated.lifecycle.dynamic_code == DynamicCodeNeed::MustCover
        && cell.code == CodeCoverage::CensusPatchOnly
        && matches!(&env.p9_code_shape, Knowledge::Proved(shape) if shape.jit_indicators)
    {
        out.push(R::CodeUncovered);
    }
    out
}

/// Coarse design-level check used only to name the obligation behind an
/// `R-UNBUILT` refusal (window, placement, density, debugger, and the
/// wider instruction classes, which only the translation design claims).
/// Never used to admit anything.
fn design_satisfies(info: &DesignCellInfo, req: &EffectiveRequirements) -> bool {
    let stated = &req.stated;
    if !window_accepts(stated.window, info.window) {
        return false;
    }
    let placement_ok = match stated.placement {
        PlacementRequirement::Any => true,
        PlacementRequirement::InGuestOnly => info.placement == Placement::InGuest,
        PlacementRequirement::OutOfProcessOnly => info.placement == Placement::OutOfProcess,
    };
    if !placement_ok {
        return false;
    }
    if stated.density == Density::Dense && info.design != DesignCell::V10 {
        return false;
    }
    if stated.debugger == DebuggerRequirement::CoexistWithExternal && info.design != DesignCell::V9
    {
        return false;
    }
    if (req.instructions.rdrand_rdseed || req.instructions.xgetbv) && info.design != DesignCell::V10
    {
        return false;
    }
    true
}

/// Guarantee strength for tie-breaking among eligible cells.
fn guarantee_rank(cell: &ImplementedCell) -> u32 {
    let life = &cell.lifecycle;
    let mut rank = life.threads.strength()
        + life.fork.strength()
        + life.vfork.strength()
        + life.exec_successor.strength()
        + life.signals.strength();
    if cell.window == WindowGuarantee::Zero {
        rank += 2;
    }
    if cell.code.covers_dynamic() {
        rank += 1;
    }
    rank
}

/// Choose the refusal code for an empty eligible set.
///
/// Precedence: architecture floor disproved in the snapshot itself;
/// dense demand with no translation candidate; unknown-tainted emptiness
/// (some cell's eligibility is merely unproved — the set is not proved
/// empty); ptrace disproved under a zero-window demand (the only
/// remaining designs would be windowed or unbuilt); then the dominating
/// code at the stage that actually emptied the set; with one guard — a
/// dominating lifecycle code with no single lifecycle sub-axis behind it,
/// while an unregistered design satisfies the requirements, is really
/// "the satisfying combination is unbuilt". Explicit-selection failures
/// do not come here; they name the selected cell's own failed predicate.
fn refusal_code(
    request: &AdmissionRequest,
    cells: &[ImplementedCell],
    trace: &FilterTrace,
) -> RefusalCode {
    match &request.env.p10_arch {
        Knowledge::Proved(floor) if !floor.linux_x86_64 => return RefusalCode::RArch,
        Knowledge::Disproved => return RefusalCode::RArch,
        _ => {}
    }
    if request.requirements.stated.density == Density::Dense
        && cells.iter().all(|c| c.mechanism != Mechanism::Translation)
    {
        return RefusalCode::RDense;
    }
    let per_cell: Vec<Vec<RemovalReason>> = cells.iter().map(|c| trace.reasons_for(c.id)).collect();
    if per_cell
        .iter()
        .any(|rs| !rs.is_empty() && rs.iter().all(|r| r.is_unknown()))
    {
        return RefusalCode::REnvUnknown;
    }
    if request.requirements.stated.window == WindowRequirement::Zero
        && matches!(
            request.env.p1_ptrace_usable,
            Knowledge::Proved(false) | Knowledge::Disproved
        )
    {
        return RefusalCode::RPtrace;
    }

    // Find the stage that emptied the set, and the reasons it used.
    let mut alive: Vec<CellId> = cells.iter().map(|c| c.id).collect();
    let mut emptying: &[(CellId, Vec<RemovalReason>)] = &[];
    for stage in &trace.stages {
        alive.retain(|id| !stage.removed.iter().any(|(c, _)| c == id));
        if alive.is_empty() {
            emptying = &stage.removed;
            break;
        }
    }
    // Dominating code: present in the most cells removed at that stage;
    // ties broken by this precedence order.
    const PRECEDENCE: [RefusalCode; 10] = [
        RefusalCode::RWindow,
        RefusalCode::RInstr,
        RefusalCode::RCode,
        RefusalCode::RExec,
        RefusalCode::RWx,
        RefusalCode::RPtrace,
        RefusalCode::RSignal,
        RefusalCode::RDense,
        RefusalCode::RLifecycle,
        RefusalCode::RUnbuilt,
    ];
    let mut best: Option<(RefusalCode, usize)> = None;
    for code in PRECEDENCE {
        let count = emptying
            .iter()
            .filter(|(_, reasons)| reasons.iter().any(|r| r.code() == code))
            .count();
        if count > 0 && best.is_none_or(|(_, n)| count > n) {
            best = Some((code, count));
        }
    }
    let dominating = best
        .map(|(code, _)| code)
        .unwrap_or(RefusalCode::RLifecycle);
    if dominating == RefusalCode::RLifecycle && !trace.satisfying_designs.is_empty() {
        // "Lifecycle" here is several different axes each removing
        // different cells. If no single sub-axis removed every cell at
        // this stage, the honest name is the unbuilt combination.
        let sub_axes: [&dyn Fn(RemovalReason) -> bool; 5] = [
            &|r| matches!(r, RemovalReason::LifecycleUnproven("threads")),
            &|r| matches!(r, RemovalReason::LifecycleUnproven("fork")),
            &|r| matches!(r, RemovalReason::LifecycleUnproven("vfork")),
            &|r| r == RemovalReason::PlacementMismatch,
            &|r| r == RemovalReason::GuestShapeMismatch,
        ];
        let single_axis = sub_axes.iter().any(|pred| {
            !emptying.is_empty()
                && emptying
                    .iter()
                    .all(|(_, reasons)| reasons.iter().any(|r| pred(*r)))
        });
        if !single_axis {
            return RefusalCode::RUnbuilt;
        }
    }
    dominating
}

/// Admit against an explicit candidate set. This is the engine of
/// [`admit`]; it is public so that candidate cells (a future backend, a
/// refusal oracle's synthetic patch-only cell) can be pre-flighted
/// through exactly the same rules before anyone registers them.
///
/// Explicit selection is applied last and exactly: a named cell/backend
/// that failed any stage refuses with that stage's reason; it is never
/// replaced by another cell.
pub fn admit_over(
    request: &AdmissionRequest,
    cells: &[ImplementedCell],
) -> Result<AdmissionReport, AdmissionRefusal> {
    let req = &request.requirements;
    let mut trace = FilterTrace {
        stages: Vec::new(),
        satisfying_designs: design_cells()
            .iter()
            .filter(|info| design_satisfies(info, req))
            .map(|info| info.design)
            .collect(),
    };
    fn run_stage<'a>(
        name: &'static str,
        alive: Vec<&'a ImplementedCell>,
        reasons: &dyn Fn(&ImplementedCell) -> Vec<RemovalReason>,
        trace: &mut FilterTrace,
    ) -> Vec<&'a ImplementedCell> {
        let mut removed = Vec::new();
        let mut next = Vec::new();
        for cell in alive {
            let found = reasons(cell);
            if found.is_empty() {
                next.push(cell);
            } else {
                removed.push((cell.id, found));
            }
        }
        trace.stages.push(FilterStage { name, removed });
        next
    }

    let alive: Vec<&ImplementedCell> = cells.iter().collect();
    let alive = run_stage(
        "requirements",
        alive,
        &|cell| requirement_reasons(req, request.guest, cell),
        &mut trace,
    );
    let alive = run_stage(
        "environment",
        alive,
        &|cell| environment_reasons(req, &request.env, cell),
        &mut trace,
    );

    // Ranking (heuristic cost, stronger guarantees first on ties).
    let mut ranked = alive;
    ranked.sort_by(|a, b| {
        a.cost
            .cmp(&b.cost)
            .then_with(|| guarantee_rank(b).cmp(&guarantee_rank(a)))
            .then_with(|| a.id.0.cmp(b.id.0))
    });

    let chosen = match request.explicit {
        ExplicitSelection::Auto => ranked.first().copied(),
        ExplicitSelection::Cell(id) => {
            match ranked.iter().find(|c| c.id == id) {
                Some(cell) => Some(*cell),
                None => {
                    // Name the selected cell's own first failed predicate,
                    // or its absence from the candidate set.
                    let (code, detail) = match cells.iter().find(|c| c.id == id) {
                        Some(_) => {
                            let reasons = trace.reasons_for(id);
                            let code = reasons
                                .first()
                                .map(|r| r.code())
                                .unwrap_or(RefusalCode::RLifecycle);
                            (
                                code,
                                format!("explicitly selected cell {id} is not eligible"),
                            )
                        }
                        None => (
                            RefusalCode::RUnbuilt,
                            format!("explicitly selected cell {id} is not an implemented cell"),
                        ),
                    };
                    return Err(AdmissionRefusal {
                        code,
                        detail,
                        trace,
                        terminal: false,
                    });
                }
            }
        }
        ExplicitSelection::Backend(backend) => match ranked.iter().find(|c| c.backend == backend) {
            Some(cell) => Some(*cell),
            None => {
                let candidates: Vec<&ImplementedCell> =
                    cells.iter().filter(|c| c.backend == backend).collect();
                let (code, detail) = match candidates.first() {
                    Some(first) => {
                        let reasons = trace.reasons_for(first.id);
                        let code = reasons
                            .first()
                            .map(|r| r.code())
                            .unwrap_or(RefusalCode::RLifecycle);
                        (
                            code,
                            format!("explicitly selected backend {backend} has no eligible cell"),
                        )
                    }
                    None => (
                        RefusalCode::RUnbuilt,
                        format!("explicitly selected backend {backend} has no implemented cell"),
                    ),
                };
                return Err(AdmissionRefusal {
                    code,
                    detail,
                    trace,
                    terminal: false,
                });
            }
        },
    };

    match chosen {
        Some(cell) => {
            if request.explicit != ExplicitSelection::Auto {
                trace.stages.push(FilterStage {
                    name: "explicit-selection",
                    removed: ranked
                        .iter()
                        .filter(|c| c.id != cell.id)
                        .map(|c| (c.id, vec![RemovalReason::NotExplicitlySelected]))
                        .collect(),
                });
            }
            Ok(AdmissionReport {
                requirements: request.requirements.clone(),
                guest: request.guest,
                env: request.env.clone(),
                eligible: ranked.iter().map(|c| c.id).collect(),
                chosen: cell.id,
                envelope_notes: cell.envelope.notes,
                cost_note: COST_HEURISTIC_NOTE,
                trace,
            })
        }
        None => {
            let code = refusal_code(request, cells, &trace);
            Err(AdmissionRefusal {
                code,
                detail: "no implemented cell satisfies the requirements in this environment"
                    .to_string(),
                trace,
                terminal: false,
            })
        }
    }
}

/// Admit against the registered implemented cells ([`implemented_cells`]).
pub fn admit(request: &AdmissionRequest) -> Result<AdmissionReport, AdmissionRefusal> {
    admit_over(request, implemented_cells())
}

/// Convenience wrapper around [`admit`] returning the chosen cell.
pub fn select_cell(request: &AdmissionRequest) -> Result<CellId, AdmissionRefusal> {
    admit(request).map(|report| report.chosen)
}
/// Facts about the *actual* guest, observed by the backend at its own
/// controlled stop (never read by this crate from the guest directly).
/// A backend that cannot observe a fact reports `Unknown`, and admission
/// predicates depending on it fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct HandoffFacts {
    /// A tracer of the guest *other than this backend* (`TracerPid`
    /// after the backend's own seizure is accounted for): `Proved(0)` is
    /// the only "no other tracer" answer. A backend that seized the
    /// guest reports `Proved(0)`; a backend that did not, reports what
    /// it observed — and `Unknown` when it did not observe.
    pub tracer_pid: Knowledge<i32>,
    /// Whose seccomp filter lineage the guest carries at handoff. A
    /// filter *count* cannot establish compatibility, so the backend
    /// reports installation provenance instead.
    pub seccomp_lineage: Knowledge<SeccompLineage>,
    /// Whether the guest runs in secure-execution mode (`AT_SECURE`).
    pub at_secure: Knowledge<bool>,
    /// Threads in the guest at handoff.
    pub threads_at_handoff: Knowledge<u32>,
    /// Whether the signal ownership the cell needs is available.
    pub signal_ownership: Knowledge<bool>,
    /// Whether no guest instruction of the (successor) image has run yet.
    /// Required `Proved(true)` for any zero-window claim.
    pub first_instruction_pending: Knowledge<bool>,
}

impl Default for HandoffFacts {
    /// Every fact unknown (fail closed).
    fn default() -> Self {
        Self {
            tracer_pid: Knowledge::default(),
            seccomp_lineage: Knowledge::default(),
            at_secure: Knowledge::default(),
            threads_at_handoff: Knowledge::default(),
            signal_ownership: Knowledge::default(),
            first_instruction_pending: Knowledge::default(),
        }
    }
}

/// Provenance of the seccomp filters on the actual guest at handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeccompLineage {
    /// The admitting backend installed its filter on this guest (and
    /// accounts for every filter present).
    BackendInstalled,
    /// Filters predate the backend (inherited lineage); their
    /// compatibility with the cell's trap is not established by a count.
    Preexisting,
    /// No seccomp filter is installed on the guest.
    NoneInstalled,
}

/// Which succession a retained plan is re-admitted across.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuccessionKind {
    /// A `fork`/`vfork` child, same image.
    Fork,
    /// A successful `execve` successor image.
    Exec,
}

/// Facts about a child/successor, observed by the backend as in
/// [`HandoffFacts`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SuccessionFacts {
    /// Fork child or exec successor.
    pub kind: SuccessionKind,
    /// For preload activation: the preload is still present in the
    /// successor (not scrubbed from its environment).
    pub preload_present: Knowledge<bool>,
    /// Whether the successor runs in secure-execution mode.
    pub at_secure: Knowledge<bool>,
    /// Whether no successor instruction has run yet.
    pub first_instruction_pending: Knowledge<bool>,
    /// Threads in the successor at re-admission.
    pub threads: Knowledge<u32>,
}

/// A retained, admitted execution plan: one cell plus the requirements it
/// was admitted under. The plan — not a fresh admission — crosses fork
/// and exec. Re-admission re-validates the *same* cell against successor
/// facts; there is deliberately no API to change cells here (that would
/// require an explicit transfer of tool state, RPC, and signal ownership).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutionPlan {
    cell: ImplementedCell,
    requirements: EffectiveRequirements,
}

impl ExecutionPlan {
    /// Retain the chosen cell of a successful admission. Returns `None`
    /// if the report's chosen cell is not in `cells` (a report only
    /// retains against the set it was admitted over).
    pub fn from_report(report: &AdmissionReport, cells: &[ImplementedCell]) -> Option<Self> {
        cells
            .iter()
            .find(|c| c.id == report.chosen)
            .map(|cell| Self {
                cell: *cell,
                requirements: report.requirements.clone(),
            })
    }

    /// Retain the chosen cell of an admission over the registered cells.
    pub fn from_admission(report: &AdmissionReport) -> Option<Self> {
        Self::from_report(report, implemented_cells())
    }

    /// The retained cell.
    pub fn cell(&self) -> &ImplementedCell {
        &self.cell
    }

    /// The requirements retained across fork/exec.
    pub fn requirements(&self) -> &EffectiveRequirements {
        &self.requirements
    }

    /// Build a terminal refusal carrying a one-stage trace naming the
    /// failed check against the retained cell. (Admission refusals
    /// carry the full multi-stage filter trace; post-installation
    /// checks have exactly one stage.)
    fn terminal(
        &self,
        stage: &'static str,
        reason: RemovalReason,
        code: RefusalCode,
        detail: String,
    ) -> AdmissionRefusal {
        AdmissionRefusal {
            code,
            detail,
            trace: FilterTrace {
                stages: vec![FilterStage {
                    name: stage,
                    removed: vec![(self.cell.id, vec![reason])],
                }],
                satisfying_designs: Vec::new(),
            },
            terminal: true,
        }
    }

    /// Check a load-bearing boolean handoff fact: proved-true passes,
    /// proved-false/disproved refuses with `code`, unknown refuses with
    /// [`RefusalCode::REnvUnknown`] (the predicate is unproved — it is
    /// never read as the convenient value).
    fn check_true(
        &self,
        stage: &'static str,
        reason: RemovalReason,
        fact: &Knowledge<bool>,
        code: RefusalCode,
        what: &'static str,
    ) -> Result<(), AdmissionRefusal> {
        match fact {
            Knowledge::Proved(true) => Ok(()),
            Knowledge::Proved(false) | Knowledge::Disproved => Err(self.terminal(
                stage,
                reason,
                code,
                format!("{stage}: {what} does not hold"),
            )),
            Knowledge::Unknown { .. } => Err(self.terminal(
                stage,
                RemovalReason::EnvUnknown(stage),
                RefusalCode::REnvUnknown,
                format!("{stage}: {what} is unproved"),
            )),
        }
    }

    /// Validate the actual guest at the backend's controlled handoff.
    ///
    /// Throwaway-child observations from admission time prove nothing
    /// about this guest; this is the load-bearing check of its
    /// permissions, filter lineage, and ownership. Every refusal here is
    /// terminal: installation has begun, and the host must not retry
    /// another backend.
    pub fn validate_handoff(&self, facts: &HandoffFacts) -> Result<(), AdmissionRefusal> {
        let cell = &self.cell;
        // Zero-window claims stand or fall here, on the actual image.
        if cell.window == WindowGuarantee::Zero {
            self.check_true(
                "handoff",
                RemovalReason::WindowMismatch,
                &facts.first_instruction_pending,
                RefusalCode::RWindow,
                "no guest instruction has run before arming",
            )?;
        }
        // Exclusive cells must not find another tracer on the guest.
        // Unknown tracer ownership is unproved, never "no tracer".
        if cell.debugger == DebuggerSupport::ExclusiveOnly {
            match &facts.tracer_pid {
                Knowledge::Proved(0) => {}
                Knowledge::Proved(_) | Knowledge::Disproved => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::EnvDisproved("P2"),
                        RefusalCode::RPtrace,
                        "handoff: guest already has a tracer".to_string(),
                    ));
                }
                Knowledge::Unknown { .. } => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::EnvUnknown("P2"),
                        RefusalCode::REnvUnknown,
                        "handoff: guest tracer ownership is unproved".to_string(),
                    ));
                }
            }
        }
        // Host-process cells trap through a backend-installed seccomp
        // filter: the actual guest must carry a lineage the backend
        // accounts for. A backend that installed its filter atop an
        // inherited baseline it fully accounts for reports
        // BackendInstalled; Preexisting is reserved for lineage nobody
        // accounted for, whose compatibility a filter count cannot
        // establish. Admission-time metadata proved nothing here.
        if cell.mechanism != Mechanism::VmExits {
            match &facts.seccomp_lineage {
                Knowledge::Proved(SeccompLineage::BackendInstalled) => {}
                Knowledge::Proved(_) | Knowledge::Disproved => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::LifecycleUnproven("seccomp lineage"),
                        RefusalCode::RLifecycle,
                        "handoff: guest seccomp lineage is not accounted for by the backend"
                            .to_string(),
                    ));
                }
                Knowledge::Unknown { .. } => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::EnvUnknown("seccomp lineage"),
                        RefusalCode::REnvUnknown,
                        "handoff: guest seccomp lineage is unproved".to_string(),
                    ));
                }
            }
        }
        if cell.envelope.guest == GuestShape::DynamicPreloadableOnly {
            match &facts.at_secure {
                Knowledge::Proved(false) => {}
                Knowledge::Proved(true) | Knowledge::Disproved => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::GuestShapeMismatch,
                        RefusalCode::RLifecycle,
                        "handoff: guest is in secure-execution mode, outside the tested envelope"
                            .to_string(),
                    ));
                }
                Knowledge::Unknown { .. } => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::EnvUnknown("handoff"),
                        RefusalCode::REnvUnknown,
                        "handoff: secure-execution mode is unproved".to_string(),
                    ));
                }
            }
        }
        if cell.envelope.threads == ThreadsBound::SingleThread {
            match &facts.threads_at_handoff {
                Knowledge::Proved(n) if *n <= 1 => {}
                Knowledge::Proved(_) | Knowledge::Disproved => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::LifecycleUnproven("threads"),
                        RefusalCode::RLifecycle,
                        "handoff: guest already has more threads than the tested envelope"
                            .to_string(),
                    ));
                }
                Knowledge::Unknown { .. } => {
                    return Err(self.terminal(
                        "handoff",
                        RemovalReason::EnvUnknown("handoff"),
                        RefusalCode::REnvUnknown,
                        "handoff: thread count is unproved".to_string(),
                    ));
                }
            }
        }
        if cell.envelope.signal_ownership_at_handoff {
            self.check_true(
                "handoff",
                RemovalReason::SignalUnavailable("signal ownership"),
                &facts.signal_ownership,
                RefusalCode::RSignal,
                "required signal ownership is available",
            )?;
        }
        Ok(())
    }

    /// Re-admit this same plan for a fork child. Never selects a cell.
    pub fn readmit_on_fork(&self, child: &SuccessionFacts) -> Result<Self, AdmissionRefusal> {
        debug_assert_eq!(child.kind, SuccessionKind::Fork);
        if self.cell.activation == Activation::PreloadLate {
            match &child.preload_present {
                Knowledge::Proved(true) => {}
                Knowledge::Proved(false) | Knowledge::Disproved => {
                    return Err(self.terminal(
                        "readmission",
                        RemovalReason::LifecycleUnproven("fork preload"),
                        RefusalCode::RLifecycle,
                        "fork child does not carry the preload activation".to_string(),
                    ));
                }
                Knowledge::Unknown { .. } => {
                    return Err(self.terminal(
                        "readmission",
                        RemovalReason::EnvUnknown("readmission"),
                        RefusalCode::REnvUnknown,
                        "fork child preload presence is unproved".to_string(),
                    ));
                }
            }
        }
        // A fork child has exactly one thread by construction, but a
        // backend-supplied contrary fact still binds the envelope.
        if self.cell.envelope.threads == ThreadsBound::SingleThread
            && matches!(child.threads, Knowledge::Proved(n) if n > 1)
        {
            return Err(self.terminal(
                "readmission",
                RemovalReason::LifecycleUnproven("threads"),
                RefusalCode::RLifecycle,
                "fork child exceeds the tested single-thread envelope".to_string(),
            ));
        }
        Ok(self.clone())
    }

    /// Re-admit this same plan for an exec successor. A successor image
    /// is a new first-instruction problem: partial re-arming is a window,
    /// so anything short of the same cell fully re-armed refuses
    /// [`RefusalCode::RExec`]. Never selects a (weaker) cell.
    pub fn readmit_on_exec(&self, succ: &SuccessionFacts) -> Result<Self, AdmissionRefusal> {
        debug_assert_eq!(succ.kind, SuccessionKind::Exec);
        match self.cell.envelope.exec {
            ExecBound::Refused => Err(self.terminal(
                "readmission",
                RemovalReason::ExecUnproven,
                RefusalCode::RExec,
                format!("cell {} does not re-arm exec successors", self.cell.id),
            )),
            ExecBound::Emulated => {
                // The substrate carries the successor, but a supplied
                // fact proving instructions already ran still breaks a
                // zero-window plan: emulation is not a blind pass.
                if self.cell.window == WindowGuarantee::Zero
                    && matches!(
                        succ.first_instruction_pending,
                        Knowledge::Proved(false) | Knowledge::Disproved
                    )
                {
                    return Err(self.terminal(
                        "readmission",
                        RemovalReason::ExecUnproven,
                        RefusalCode::RExec,
                        "successor instructions ran before re-admission".to_string(),
                    ));
                }
                Ok(self.clone())
            }
            ExecBound::RearmedSameCell => {
                self.check_true(
                    "readmission",
                    RemovalReason::ExecUnproven,
                    &succ.first_instruction_pending,
                    RefusalCode::RExec,
                    "successor image is re-armed before its first instruction",
                )?;
                match &succ.at_secure {
                    Knowledge::Unknown { .. }
                        if self.cell.envelope.guest == GuestShape::DynamicPreloadableOnly =>
                    {
                        return Err(self.terminal(
                            "readmission",
                            RemovalReason::EnvUnknown("readmission"),
                            RefusalCode::REnvUnknown,
                            "successor secure-execution mode is unproved".to_string(),
                        ));
                    }
                    _ => {}
                }
                Ok(self.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proved_env() -> EnvironmentSnapshot {
        EnvironmentSnapshot {
            p1_ptrace_usable: Knowledge::Proved(true),
            p2_existing_tracer: Knowledge::Proved(false),
            p3_seccomp: Knowledge::Proved(SeccompState {
                mode: 2,
                filters: 1,
                no_new_privs: true,
                install_proved: true,
            }),
            p4_sud: Knowledge::Proved(false),
            p5_cpuid_faulting: Knowledge::Proved(true),
            p6_pr_set_tsc: Knowledge::Proved(true),
            p7_wx: Knowledge::Proved(WxPolicy::DualMapAllowed),
            p8_signal_ownership: Knowledge::Unknown {
                why: "guest dispositions not observable before launch",
            },
            p9_code_shape: Knowledge::Proved(CodeShape {
                dynamic: true,
                pie: true,
                jit_indicators: false,
            }),
            p10_arch: Knowledge::Proved(ArchFloor {
                linux_x86_64: true,
                cet_ibt: false,
            }),
        }
    }

    fn effective(stated: ToolRequirements) -> EffectiveRequirements {
        EffectiveRequirements::compute(stated, Subscription::all_syscalls(), ToolQueries::default())
    }

    fn request(stated: ToolRequirements, guest: GuestProfile) -> AdmissionRequest {
        AdmissionRequest {
            requirements: effective(stated),
            guest,
            env: proved_env(),
            explicit: ExplicitSelection::Auto,
        }
    }

    fn relaxed_preload_tool() -> ToolRequirements {
        // The profiler shape: declares the preload window and drops the
        // lifecycle the in-guest envelope does not cover.
        ToolRequirements {
            window: WindowRequirement::Declared { pre_init_ok: true },
            lifecycle: LifecycleRequirements {
                threads: false,
                vfork: false,
                exec_successor: false,
                signal_fidelity: false,
                ..LifecycleRequirements::default()
            },
            ..ToolRequirements::default()
        }
    }

    #[test]
    fn default_tool_gets_reference_never_preload_window() {
        let report = admit(&request(
            ToolRequirements::default(),
            GuestProfile::HostProcessAny,
        ))
        .expect("reference cell admits the strictest tool");
        assert_eq!(report.chosen, CellId("V1-ptrace"));
        assert_eq!(report.eligible, vec![CellId("V1-ptrace")]);
        // The preload cells were removed by name, not silently skipped.
        let reasons = report.trace.reasons_for(CellId("V5-preload-patch"));
        assert!(
            reasons.contains(&RemovalReason::WindowMismatch),
            "{reasons:?}"
        );
        assert!(report.cost_note.contains("heuristic"));
    }

    #[test]
    fn zero_window_tool_on_preload_path_refuses_r_window_before_launch() {
        let mut req = request(
            ToolRequirements::default(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.explicit = ExplicitSelection::Backend(BackendId("reverie-liteinst-preload"));
        let refusal = admit(&req).expect_err("zero window cannot run on a preload cell");
        assert_eq!(refusal.code, RefusalCode::RWindow);
        assert_eq!(
            refusal.to_string(),
            format!("REFUSED: R-WINDOW: {}", refusal.detail)
        );
        assert!(!refusal.terminal);
    }

    #[test]
    fn explicit_cell_is_honoured_or_refused_never_substituted() {
        // Eligible but not the auto choice: honoured exactly.
        let mut req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.explicit = ExplicitSelection::Cell(CellId("V4-preload-trap"));
        let report = admit(&req).expect("explicit eligible cell");
        assert_eq!(report.chosen, CellId("V4-preload-trap"));
        // Auto would have ranked the patch cell first (heuristic cost).
        assert_eq!(report.eligible[0], CellId("V5-preload-patch"));

        // Ineligible: refused with its own failed predicate.
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.explicit = ExplicitSelection::Cell(CellId("V5-preload-patch"));
        let refusal = admit(&req).expect_err("explicit ineligible cell");
        assert_eq!(refusal.code, RefusalCode::RWindow);

        // Unregistered: R-UNBUILT, not a substitute.
        req.explicit = ExplicitSelection::Cell(CellId("V2-exec-stop-trap"));
        let refusal = admit(&req).expect_err("explicit unbuilt cell");
        assert_eq!(refusal.code, RefusalCode::RUnbuilt);
    }

    #[test]
    fn relaxed_tool_auto_ranks_patch_then_trap_then_ptrace() {
        let report = admit(&request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        ))
        .expect("relaxed tool admits somewhere");
        assert_eq!(
            report.eligible,
            vec![
                CellId("V5-preload-patch"),
                CellId("V4-preload-trap"),
                CellId("V1-ptrace")
            ]
        );
        assert_eq!(report.chosen, report.eligible[0]);
    }

    #[test]
    fn unknown_environment_fails_closed_as_r_env_unknown() {
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.env = EnvironmentSnapshot::default();
        let refusal = admit(&req).expect_err("unknown env admits nothing");
        assert_eq!(refusal.code, RefusalCode::REnvUnknown);

        // One load-bearing unknown (P1) is enough, and reads as unproved,
        // never as denial.
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.env.p1_ptrace_usable = Knowledge::Unknown { why: "no /proc" };
        let refusal = admit(&req).expect_err("P1 unknown blocks the reference cell");
        assert_eq!(refusal.code, RefusalCode::REnvUnknown);
    }

    #[test]
    fn ptrace_denied_zero_window_is_r_ptrace() {
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.env.p1_ptrace_usable = Knowledge::Proved(false);
        let refusal = admit(&req).expect_err("no zero-window cell without ptrace");
        assert_eq!(refusal.code, RefusalCode::RPtrace);
    }

    #[test]
    fn non_x86_64_is_r_arch() {
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.env.p10_arch = Knowledge::Proved(ArchFloor {
            linux_x86_64: false,
            cet_ibt: false,
        });
        let refusal = admit(&req).expect_err("arch floor");
        assert_eq!(refusal.code, RefusalCode::RArch);
    }

    #[test]
    fn dense_is_r_dense_and_wider_instructions_r_instr() {
        let dense = ToolRequirements {
            density: Density::Dense,
            ..ToolRequirements::default()
        };
        let refusal = admit(&request(dense, GuestProfile::HostProcessAny))
            .expect_err("no translation cell implemented");
        assert_eq!(refusal.code, RefusalCode::RDense);
        assert!(
            refusal.trace.satisfying_designs.contains(&DesignCell::V10),
            "{:?}",
            refusal.trace.satisfying_designs
        );

        let mut wide = ToolRequirements::default();
        wide.instructions.rdrand_rdseed = true;
        let refusal = admit(&request(wide, GuestProfile::HostProcessAny))
            .expect_err("no cell mediates RDRAND");
        assert_eq!(refusal.code, RefusalCode::RInstr);
    }

    #[test]
    fn cpuid_without_faulting_support_refuses_never_degrades() {
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.requirements = EffectiveRequirements::compute(
            ToolRequirements::default(),
            {
                let mut sub = Subscription::all_syscalls();
                sub.cpuid();
                sub
            },
            ToolQueries::default(),
        );
        req.env.p5_cpuid_faulting = Knowledge::Proved(false);
        let refusal = admit(&req).expect_err("CPUID demand without its prerequisite");
        assert_eq!(refusal.code, RefusalCode::RInstr);
        // With the prerequisite proved, the same request admits.
        req.env.p5_cpuid_faulting = Knowledge::Proved(true);
        assert_eq!(admit(&req).expect("admitted").chosen, CellId("V1-ptrace"));
    }

    #[test]
    fn subscriptions_raise_instructions_but_never_relax_lifecycle() {
        // Declining execve events must not admit an exec-refusing cell
        // for a tool that still requires exec coverage.
        let mut sub = Subscription::all_syscalls();
        sub.disable_syscall(crate::syscalls::Sysno::execve);
        let req = AdmissionRequest {
            requirements: EffectiveRequirements::compute(
                ToolRequirements::default(),
                sub,
                ToolQueries::default(),
            ),
            guest: GuestProfile::HostProcessDynamicPreloadable,
            env: proved_env(),
            explicit: ExplicitSelection::Cell(CellId("V5-preload-patch")),
        };
        let refusal = admit(&req).expect_err("interest is not a restriction");
        let reasons = refusal.trace.reasons_for(CellId("V5-preload-patch"));
        assert!(
            reasons.contains(&RemovalReason::ExecUnproven),
            "{reasons:?}"
        );
    }

    #[test]
    fn signal_control_and_sigreturns_gate_on_capabilities() {
        // requires_signal_control: only the capabilities constant that
        // provides process signal control satisfies it (the VM cell);
        // ptrace, which never offered the control, does not qualify.
        // Isolate that axis: with every other axis relaxed, signal
        // control is the only reason every host-process cell is removed.
        let mut req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.requirements.queries.requires_signal_control = true;
        let refusal = admit(&req).expect_err("host-process cells offer no signal control");
        assert_eq!(refusal.code, RefusalCode::RSignal);

        // The VM cell's exec/signal guarantees are partial (see the
        // strict-VM regression below), so isolate the signal-control axis
        // by relaxing exactly those two.
        let mut vm_stated = ToolRequirements::default();
        vm_stated.lifecycle.exec_successor = false;
        vm_stated.lifecycle.signal_fidelity = false;
        let mut req = request(vm_stated, GuestProfile::StaticElfVm);
        req.requirements.queries.thread_ownership = Some(ThreadOwnership::Tool);
        req.requirements.queries.requires_signal_control = true;
        assert_eq!(admit(&req).expect("VM cell").chosen, CellId("V11-kvm"));

        // observes_sigreturns follows the capabilities table exactly.
        let mut req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.requirements.queries.observes_sigreturns = true;
        req.explicit = ExplicitSelection::Cell(CellId("V4-preload-trap"));
        let refusal = admit(&req).expect_err("in-guest cells do not report sigreturns");
        assert_eq!(refusal.code, RefusalCode::RSignal);
    }

    #[test]
    fn sud_never_gates_eligibility() {
        let base = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        let eligible = admit(&base).expect("admitted").eligible;
        for sud in [
            Knowledge::Proved(true),
            Knowledge::Proved(false),
            Knowledge::Disproved,
            Knowledge::Unknown { why: "no probe" },
        ] {
            let mut req = base.clone();
            req.env.p4_sud = sud;
            assert_eq!(admit(&req).expect("admitted").eligible, eligible);
        }
    }

    #[test]
    fn strict_wx_removes_only_the_patching_cell() {
        let mut req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.env.p7_wx = Knowledge::Proved(WxPolicy::StrictWx);
        let report = admit(&req).expect("trap and ptrace remain");
        assert_eq!(
            report.eligible,
            vec![CellId("V4-preload-trap"), CellId("V1-ptrace")]
        );
        req.explicit = ExplicitSelection::Cell(CellId("V5-preload-patch"));
        let refusal = admit(&req).expect_err("patching cell under strict W^X");
        assert_eq!(refusal.code, RefusalCode::RWx);
    }

    #[test]
    fn debugger_coexistence_is_r_unbuilt_naming_v9() {
        let stated = ToolRequirements {
            debugger: DebuggerRequirement::CoexistWithExternal,
            ..ToolRequirements::default()
        };
        let refusal = admit(&request(stated, GuestProfile::HostProcessAny))
            .expect_err("no coexisting cell implemented");
        assert_eq!(refusal.code, RefusalCode::RUnbuilt);
        assert_eq!(refusal.trace.satisfying_designs, vec![DesignCell::V9]);
    }

    #[test]
    fn zero_window_in_guest_is_unbuilt_until_a_zero_window_loader_registers() {
        let stated = ToolRequirements {
            placement: PlacementRequirement::InGuestOnly,
            ..ToolRequirements::default()
        };
        let refusal = admit(&request(
            stated,
            GuestProfile::HostProcessDynamicPreloadable,
        ))
        .expect_err("registered in-guest cells are windowed");
        assert_eq!(refusal.code, RefusalCode::RUnbuilt);
        assert!(
            refusal.trace.satisfying_designs.contains(&DesignCell::V2),
            "{:?}",
            refusal.trace.satisfying_designs
        );
    }

    #[test]
    fn patch_only_cell_with_dynamic_demand_is_r_code() {
        // The refusal-oracle case: a synthetic patch-only candidate can
        // never satisfy MustCover — ELF/JIT shape proves nothing, and the
        // coverage class itself is the disqualifier.
        let mut patch_only = implemented_cells()[2];
        patch_only.id = CellId("synthetic-patch-only");
        patch_only.code = CodeCoverage::CensusPatchOnly;
        let req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        let refusal = admit_over(&req, &[patch_only]).expect_err("patch-only, dynamic demand");
        assert_eq!(refusal.code, RefusalCode::RCode);
        // Relaxing dynamic coverage explicitly admits it (declared).
        let mut stated = relaxed_preload_tool();
        stated.lifecycle.dynamic_code = DynamicCodeNeed::NotRequired;
        let req = request(stated, GuestProfile::HostProcessDynamicPreloadable);
        assert!(admit_over(&req, &[patch_only]).is_ok());
    }

    #[test]
    fn relaxation_is_monotone_on_every_axis() {
        let strict = ToolRequirements::default();
        let eligible = |stated: &ToolRequirements| -> Vec<CellId> {
            let req = AdmissionRequest {
                requirements: effective(stated.clone()),
                guest: GuestProfile::HostProcessDynamicPreloadable,
                env: proved_env(),
                explicit: ExplicitSelection::Auto,
            };
            match admit(&req) {
                Ok(report) => report.eligible,
                Err(_) => Vec::new(),
            }
        };
        let base = eligible(&strict);
        let mut relaxations: Vec<(&str, ToolRequirements)> = Vec::new();
        let mut r = strict.clone();
        r.window = WindowRequirement::Declared { pre_init_ok: true };
        relaxations.push(("window", r));
        for (name, f) in [
            (
                "threads",
                &mut (|x: &mut ToolRequirements| x.lifecycle.threads = false)
                    as &mut dyn FnMut(&mut ToolRequirements),
            ),
            (
                "fork",
                &mut (|x: &mut ToolRequirements| x.lifecycle.fork = false),
            ),
            (
                "vfork",
                &mut (|x: &mut ToolRequirements| x.lifecycle.vfork = false),
            ),
            (
                "exec",
                &mut (|x: &mut ToolRequirements| x.lifecycle.exec_successor = false),
            ),
            (
                "signals",
                &mut (|x: &mut ToolRequirements| x.lifecycle.signal_fidelity = false),
            ),
            (
                "dynamic",
                &mut (|x: &mut ToolRequirements| {
                    x.lifecycle.dynamic_code = DynamicCodeNeed::NotRequired
                }),
            ),
        ] {
            let mut r = strict.clone();
            f(&mut r);
            relaxations.push((name, r));
        }
        for (name, relaxed) in &relaxations {
            assert!(
                relaxed.is_relaxation_of(&strict),
                "{name} must be a relaxation"
            );
            let after = eligible(relaxed);
            for cell in &base {
                assert!(
                    after.contains(cell),
                    "relaxing {name} removed {cell}: {after:?}"
                );
            }
        }
        // …and the fully relaxed tool really does gain the windowed cells.
        let after = eligible(&relaxed_preload_tool());
        assert!(after.len() > base.len(), "{base:?} -> {after:?}");
    }

    #[test]
    fn no_silent_downgrade_across_requirement_corners() {
        // Every admitted cell, for a sweep of requirement corners, must
        // re-pass both filter stages against the very request that
        // admitted it.
        let corners = [
            ToolRequirements::default(),
            relaxed_preload_tool(),
            {
                let mut r = relaxed_preload_tool();
                r.placement = PlacementRequirement::InGuestOnly;
                r
            },
            {
                let mut r = ToolRequirements::default();
                r.instructions.cpuid = true;
                r
            },
            {
                let mut r = ToolRequirements::default();
                r.lifecycle.dynamic_code = DynamicCodeNeed::NotRequired;
                r
            },
        ];
        for stated in corners {
            for guest in [
                GuestProfile::HostProcessAny,
                GuestProfile::HostProcessDynamicPreloadable,
                GuestProfile::StaticElfVm,
            ] {
                let req = request(stated.clone(), guest);
                let Ok(report) = admit(&req) else { continue };
                for cell in implemented_cells()
                    .iter()
                    .filter(|c| report.eligible.contains(&c.id))
                {
                    assert!(
                        requirement_reasons(&req.requirements, guest, cell).is_empty(),
                        "{} admitted but fails requirements",
                        cell.id
                    );
                    assert!(
                        environment_reasons(&req.requirements, &req.env, cell).is_empty(),
                        "{} admitted but fails environment",
                        cell.id
                    );
                }
            }
        }
    }

    #[test]
    fn registry_cites_capability_constants_and_covers_design_matrix() {
        let cells = implemented_cells();
        assert_eq!(cells.len(), 4);
        let by_id = |id: &'static str| cells.iter().find(|c| c.id == CellId(id)).unwrap();
        assert_eq!(by_id("V1-ptrace").capabilities, BackendCapabilities::PTRACE);
        assert_eq!(
            by_id("V4-preload-trap").capabilities,
            BackendCapabilities::LITEINST_IN_GUEST
        );
        assert_eq!(
            by_id("V5-preload-patch").capabilities,
            BackendCapabilities::LITEINST_IN_GUEST
        );
        assert_eq!(by_id("V11-kvm").capabilities, BackendCapabilities::KVM);
        // Two configurations of one backend are distinct cells.
        assert_ne!(
            by_id("V4-preload-trap").config,
            by_id("V5-preload-patch").config
        );
        // Constants without an in-tree backend register nothing.
        for cell in cells {
            assert_ne!(cell.capabilities, BackendCapabilities::E9PATCH);
            assert_ne!(cell.capabilities, BackendCapabilities::SABRE);
            assert_ne!(cell.capabilities, BackendCapabilities::DBT);
        }
        // Every design cell is classified exactly once.
        let infos = design_cells();
        assert_eq!(infos.len(), DesignCell::ALL.len());
        for design in DesignCell::ALL {
            assert_eq!(
                infos.iter().filter(|i| i.design == design).count(),
                1,
                "{design}"
            );
        }
        // Registered cells agree with their design row's window/placement.
        for cell in cells {
            let info = infos.iter().find(|i| i.design == cell.design).unwrap();
            assert_eq!(info.window, cell.window, "{}", cell.id);
            assert_eq!(info.placement, cell.placement, "{}", cell.id);
        }
        // Buildable designs are obligations, never registrations.
        for info in infos.iter().filter(|i| i.existence != Existence::Runs) {
            assert!(
                cells.iter().all(|c| c.design != info.design),
                "{} registered but does not run",
                info.design
            );
        }
    }

    fn good_handoff() -> HandoffFacts {
        HandoffFacts {
            tracer_pid: Knowledge::Proved(0),
            seccomp_lineage: Knowledge::Proved(SeccompLineage::BackendInstalled),
            at_secure: Knowledge::Proved(false),
            threads_at_handoff: Knowledge::Proved(1),
            signal_ownership: Knowledge::Proved(true),
            first_instruction_pending: Knowledge::Proved(true),
        }
    }

    #[test]
    fn handoff_validates_actual_guest_and_refuses_terminally() {
        let report = admit(&request(
            ToolRequirements::default(),
            GuestProfile::HostProcessAny,
        ))
        .unwrap();
        let plan = ExecutionPlan::from_admission(&report).unwrap();
        plan.validate_handoff(&good_handoff()).unwrap();

        // Instructions already ran: the zero-window claim is false here,
        // whatever admission-time probes said.
        let mut facts = good_handoff();
        facts.first_instruction_pending = Knowledge::Proved(false);
        let refusal = plan.validate_handoff(&facts).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::RWindow);
        assert!(refusal.terminal, "post-install failures never retry weaker");

        // Unknown tracer ownership is not "no tracer".
        let mut facts = good_handoff();
        facts.tracer_pid = Knowledge::Unknown { why: "no /proc" };
        let refusal = plan.validate_handoff(&facts).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::REnvUnknown);
        assert!(refusal.terminal);

        let mut facts = good_handoff();
        facts.tracer_pid = Knowledge::Proved(4242);
        assert_eq!(
            plan.validate_handoff(&facts).unwrap_err().code,
            RefusalCode::RPtrace
        );
    }

    #[test]
    fn preload_plan_handoff_checks_envelope_facts() {
        let report = admit(&request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        ))
        .unwrap();
        assert_eq!(report.chosen, CellId("V5-preload-patch"));
        let plan = ExecutionPlan::from_admission(&report).unwrap();
        plan.validate_handoff(&good_handoff()).unwrap();

        let mut facts = good_handoff();
        facts.at_secure = Knowledge::Proved(true);
        assert_eq!(
            plan.validate_handoff(&facts).unwrap_err().code,
            RefusalCode::RLifecycle
        );
        let mut facts = good_handoff();
        facts.signal_ownership = Knowledge::Unknown {
            why: "unobservable",
        };
        assert_eq!(
            plan.validate_handoff(&facts).unwrap_err().code,
            RefusalCode::REnvUnknown
        );
        let mut facts = good_handoff();
        facts.signal_ownership = Knowledge::Proved(false);
        assert_eq!(
            plan.validate_handoff(&facts).unwrap_err().code,
            RefusalCode::RSignal
        );
    }

    #[test]
    fn fork_and_exec_retain_the_same_cell_or_refuse() {
        let succ = |kind| SuccessionFacts {
            kind,
            preload_present: Knowledge::Proved(true),
            at_secure: Knowledge::Proved(false),
            first_instruction_pending: Knowledge::Proved(true),
            threads: Knowledge::Proved(1),
        };
        // Reference plan crosses both, unchanged.
        let report = admit(&request(
            ToolRequirements::default(),
            GuestProfile::HostProcessAny,
        ))
        .unwrap();
        let plan = ExecutionPlan::from_admission(&report).unwrap();
        let child = plan.readmit_on_fork(&succ(SuccessionKind::Fork)).unwrap();
        assert_eq!(child.cell().id, CellId("V1-ptrace"));
        let next = plan.readmit_on_exec(&succ(SuccessionKind::Exec)).unwrap();
        assert_eq!(next.cell().id, CellId("V1-ptrace"));
        // …but not across an unarmed successor.
        let mut ran = succ(SuccessionKind::Exec);
        ran.first_instruction_pending = Knowledge::Proved(false);
        assert_eq!(
            plan.readmit_on_exec(&ran).unwrap_err().code,
            RefusalCode::RExec
        );

        // Preload plan: fork follows, exec refuses by name — it never
        // inherits a different (weaker or stronger) cell.
        let report = admit(&request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        ))
        .unwrap();
        let plan = ExecutionPlan::from_admission(&report).unwrap();
        assert_eq!(
            plan.readmit_on_fork(&succ(SuccessionKind::Fork))
                .unwrap()
                .cell()
                .id,
            CellId("V5-preload-patch")
        );
        let refusal = plan
            .readmit_on_exec(&succ(SuccessionKind::Exec))
            .unwrap_err();
        assert_eq!(refusal.code, RefusalCode::RExec);
        assert!(refusal.terminal);
        // Preload scrubbed from a fork child: refused, not inherited bare.
        let mut scrubbed = succ(SuccessionKind::Fork);
        scrubbed.preload_present = Knowledge::Proved(false);
        assert!(plan.readmit_on_fork(&scrubbed).is_err());
    }

    /// Review regression (F1): the VM cell's emulated exec/signal paths
    /// refuse known cases by name at runtime (non-leader exec, stop
    /// signals), so strict requirements must not admit it. Failed on
    /// 640a0add, where `Emulated` satisfied every lifecycle axis.
    #[test]
    fn strict_vm_lifecycle_cannot_include_known_runtime_refusals() {
        let req = request(ToolRequirements::default(), GuestProfile::StaticElfVm);
        let refusal = admit(&req).expect_err("strict exec/signal demands exceed the VM envelope");
        let reasons = refusal.trace.reasons_for(CellId("V11-kvm"));
        assert!(
            reasons.contains(&RemovalReason::ExecUnproven),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&RemovalReason::LifecycleUnproven("signals")),
            "{reasons:?}"
        );
        // Explicit relaxation of exactly those axes (plus collected
        // Tool ownership) admits it again.
        let mut stated = ToolRequirements::default();
        stated.lifecycle.exec_successor = false;
        stated.lifecycle.signal_fidelity = false;
        let mut req = request(stated, GuestProfile::StaticElfVm);
        req.requirements.queries.thread_ownership = Some(ThreadOwnership::Tool);
        assert_eq!(
            admit(&req).expect("relaxed VM request").chosen,
            CellId("V11-kvm")
        );
    }

    /// Review regression (F2): Host-owned threads are unmonitored on a
    /// backend that honors thread ownership, so they cannot satisfy a
    /// monitored-threads requirement there. Failed on 640a0add, which
    /// recorded ownership without gating it.
    #[test]
    fn host_owned_threads_cannot_satisfy_monitored_threads() {
        let mut stated = ToolRequirements::default();
        stated.lifecycle.exec_successor = false;
        stated.lifecycle.signal_fidelity = false;
        let mut req = request(stated.clone(), GuestProfile::StaticElfVm);
        req.requirements.queries.thread_ownership = Some(ThreadOwnership::Host);
        let refusal = admit(&req).expect_err("Host ownership contradicts monitored threads");
        assert!(
            refusal
                .trace
                .reasons_for(CellId("V11-kvm"))
                .contains(&RemovalReason::LifecycleUnproven("threads"))
        );
        // Same request with Tool ownership admits.
        req.requirements.queries.thread_ownership = Some(ThreadOwnership::Tool);
        assert_eq!(
            admit(&req).expect("tool-owned threads").chosen,
            CellId("V11-kvm")
        );
        // And Host ownership does not disturb a backend that routes every
        // thread through the tool anyway.
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.requirements.queries.thread_ownership = Some(ThreadOwnership::Host);
        assert_eq!(
            admit(&req).expect("ptrace ignores ownership").chosen,
            CellId("V1-ptrace")
        );
    }

    /// Review regression (F3a): seccomp metadata is not install proof.
    /// Strict mode forbids installing a filter even with no_new_privs;
    /// filter mode without a proved install trial is unproved, not
    /// permission. Both admitted V4 on 640a0add.
    #[test]
    fn strict_seccomp_metadata_is_not_install_permission() {
        let mut req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.explicit = ExplicitSelection::Cell(CellId("V4-preload-trap"));
        req.env.p3_seccomp = Knowledge::Proved(SeccompState {
            mode: 1,
            filters: 0,
            no_new_privs: true,
            install_proved: false,
        });
        assert!(
            admit(&req).is_err(),
            "strict mode must refuse the trap cell"
        );
        req.env.p3_seccomp = Knowledge::Proved(SeccompState {
            mode: 2,
            filters: 1,
            no_new_privs: true,
            install_proved: false,
        });
        let refusal = admit(&req).expect_err("metadata without an install trial is unproved");
        assert_eq!(refusal.code, RefusalCode::REnvUnknown);
        // The proved install trial admits.
        req.env.p3_seccomp = Knowledge::Proved(SeccompState {
            mode: 0,
            filters: 0,
            no_new_privs: false,
            install_proved: true,
        });
        assert_eq!(
            admit(&req).expect("proved install").chosen,
            CellId("V4-preload-trap")
        );
    }

    /// Review regression (F3b): handoff must consume the actual guest's
    /// seccomp lineage. On 640a0add the field existed but was never
    /// checked, so otherwise-good facts with unknown lineage passed.
    #[test]
    fn handoff_must_not_ignore_unknown_seccomp_lineage() {
        let report = admit(&request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        ))
        .unwrap();
        let plan = ExecutionPlan::from_admission(&report).unwrap();
        let mut facts = good_handoff();
        facts.seccomp_lineage = Knowledge::Unknown {
            why: "not observed",
        };
        let refusal = plan.validate_handoff(&facts).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::REnvUnknown);
        assert!(refusal.terminal);
        facts.seccomp_lineage = Knowledge::Proved(SeccompLineage::Preexisting);
        let refusal = plan.validate_handoff(&facts).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::RLifecycle);
        assert!(refusal.terminal);
        facts.seccomp_lineage = Knowledge::Proved(SeccompLineage::BackendInstalled);
        plan.validate_handoff(&facts).unwrap();
    }

    /// Blocker regression (musereview B1): uncollected ownership must
    /// fail closed where it is load-bearing — a retained default must
    /// never launder Host (or unknown) ownership into "Tool".
    #[test]
    fn uncollected_ownership_fails_closed_where_load_bearing() {
        let mut stated = ToolRequirements::default();
        stated.lifecycle.exec_successor = false;
        stated.lifecycle.signal_fidelity = false;
        // ToolQueries::default(): thread_ownership is None here.
        let req = request(stated.clone(), GuestProfile::StaticElfVm);
        assert_eq!(req.requirements.queries.thread_ownership, None);
        let refusal = admit(&req).expect_err("unknown ownership proves no monitored threads");
        assert!(
            refusal
                .trace
                .reasons_for(CellId("V11-kvm"))
                .contains(&RemovalReason::LifecycleUnproven("threads"))
        );
        // The same None is harmless on a backend that ignores ownership.
        let req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        assert_eq!(admit(&req).expect("ptrace").chosen, CellId("V1-ptrace"));
    }

    /// Blocker regression (musereview B2a): in-guest signal delivery is
    /// refused by the installer when site patching is on, so V5 must
    /// never satisfy a delivery tool; V4 (trap-only) still can.
    #[test]
    fn signal_delivery_refuses_patching_configuration() {
        let mut req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.requirements.queries.in_guest_signal_delivery = true;
        let report = admit(&req).expect("trap configuration remains");
        assert_eq!(report.chosen, CellId("V4-preload-trap"));
        assert!(!report.eligible.contains(&CellId("V5-preload-patch")));
        req.explicit = ExplicitSelection::Cell(CellId("V5-preload-patch"));
        let refusal = admit(&req).expect_err("delivery + patching is installer-refused");
        assert_eq!(refusal.code, RefusalCode::RSignal);
    }

    /// Blocker regression (musereview B2b): reserved input is a joint
    /// prerequisite with serialized execution; the envelope fact alone
    /// (or an uncollected answer) must not promise the facility.
    #[test]
    fn reserved_input_requires_serialized_execution_jointly() {
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.requirements.queries.reserved_input = true;
        // Uncollected (None): cannot prove the joint prerequisite.
        assert!(admit(&req).is_err());
        req.requirements.queries.enforces_serialized_execution = Some(false);
        assert!(admit(&req).is_err());
        req.requirements.queries.enforces_serialized_execution = Some(true);
        assert_eq!(
            admit(&req).expect("jointly satisfied").chosen,
            CellId("V1-ptrace")
        );
    }

    /// Lower-item regressions: an unknown instruction prerequisite is
    /// unproved (never a free pass), an observed P8 denial refuses
    /// early, emulated readmission honors a proved-false first
    /// instruction, and terminal refusals carry their one-stage trace.
    #[test]
    fn unknown_prerequisite_p8_and_successor_facts_fail_closed() {
        // Unknown RequiresEnv name on a synthetic candidate.
        let mut synthetic = implemented_cells()[0];
        synthetic.id = CellId("synthetic-future-prereq");
        synthetic.instructions.cpuid = InstructionMediation::RequiresEnv("P99");
        let mut req = request(ToolRequirements::default(), GuestProfile::HostProcessAny);
        req.requirements.instructions.cpuid = true;
        let refusal = admit_over(&req, &[synthetic]).expect_err("unknown prerequisite");
        assert!(
            refusal
                .trace
                .reasons_for(CellId("synthetic-future-prereq"))
                .contains(&RemovalReason::EnvUnknown("P99"))
        );

        // Observed P8 denial removes handoff-ownership cells early.
        let mut req = request(
            relaxed_preload_tool(),
            GuestProfile::HostProcessDynamicPreloadable,
        );
        req.explicit = ExplicitSelection::Cell(CellId("V4-preload-trap"));
        req.env.p8_signal_ownership = Knowledge::Proved(false);
        let refusal = admit(&req).expect_err("observed signal-ownership denial");
        assert_eq!(refusal.code, RefusalCode::RSignal);

        // Emulated exec still honors a proved-false first instruction,
        // and the terminal refusal carries its stage trace.
        let mut stated = ToolRequirements::default();
        stated.lifecycle.exec_successor = false;
        stated.lifecycle.signal_fidelity = false;
        let mut vm_req = request(stated, GuestProfile::StaticElfVm);
        vm_req.requirements.queries.thread_ownership = Some(ThreadOwnership::Tool);
        let report = admit(&vm_req).unwrap();
        let plan = ExecutionPlan::from_admission(&report).unwrap();
        let ran = SuccessionFacts {
            kind: SuccessionKind::Exec,
            preload_present: Knowledge::Proved(true),
            at_secure: Knowledge::Proved(false),
            first_instruction_pending: Knowledge::Proved(false),
            threads: Knowledge::Proved(1),
        };
        let refusal = plan.readmit_on_exec(&ran).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::RExec);
        assert!(refusal.terminal);
        assert_eq!(refusal.trace.stages.len(), 1);
        assert_eq!(refusal.trace.stages[0].name, "readmission");
    }

    #[test]
    fn refusal_codes_render_taxonomy_names() {
        for (code, name) in [
            (RefusalCode::RArch, "R-ARCH"),
            (RefusalCode::RPtrace, "R-PTRACE"),
            (RefusalCode::RWindow, "R-WINDOW"),
            (RefusalCode::RCode, "R-CODE"),
            (RefusalCode::RSignal, "R-SIGNAL"),
            (RefusalCode::RWx, "R-WX"),
            (RefusalCode::RInstr, "R-INSTR"),
            (RefusalCode::RExec, "R-EXEC"),
            (RefusalCode::RLifecycle, "R-LIFECYCLE"),
            (RefusalCode::RDense, "R-DENSE"),
            (RefusalCode::RUnbuilt, "R-UNBUILT"),
            (RefusalCode::REnvUnknown, "R-ENV-UNKNOWN"),
        ] {
            assert_eq!(code.name(), name);
            assert_eq!(code.to_string(), name);
        }
    }
}
