//! Finite single-thread first-image RCB observation on the original owner.
//! No product clock activation, scheduling change, second tracer or wait owner.
use reverie::perf::Builder;
use reverie::perf::PerfCounter;
use safeptrace::Options;
use safeptrace::SyscallInfo;
use safeptrace::SyscallInfoOp;

use super::*;
use crate::trap::frame::REMOTE_KERNEL_FRAME_BYTES;
use crate::trap::frame::RemoteKernelPrefix;

const LIMIT: usize = 4096;
const STEP_LIMIT: u64 = 131_072;
const COMPLETION_COOKIE: u64 = 0x4c49_4641_4c4c_424b;

/// Actual measured continuation coordinates. These are UNSAFE INPUT DATA, not
/// authority. Caller must bind both to the same image/source as handover.
#[derive(Clone, Copy, Debug)]
pub struct RcbObservationCoordinates {
    /// Actual hidden `fallback_entry` of the unchanged continuation mechanism.
    pub fallback_entry: u64,
    /// Actual hidden `fallback_completion_syscall` (its post-PC is plus two).
    pub completion_syscall: u64,
}
/// A genuine guest trap sampled BEFORE any user signal handler executes.
#[derive(Clone, Debug)]
pub struct RcbGuestBoundary {
    /// One of SIGSYS or kernel instruction-fault SIGSEGV, never a suppressed signal.
    pub signal: i32,
    /// Syscall number, or the exact fault instruction bytes packed little endian.
    pub operation: u64,
    /// Actual interrupted guest PC (post-syscall for SIGSYS).
    pub pc: u64,
    /// Actual interrupted guest SP.
    pub sp: u64,
    /// Cumulative unscaled retired CONDITIONAL branches, excluding Tool/relay.
    pub rcb: u64,
    /// Actual perf scheduling evidence at the disabled stop.
    pub time_enabled: u64,
    /// Must equal time_enabled; no scaling or tolerance is used.
    pub time_running: u64,
}
/// One authenticated kernel signal-return exit observed before user execution.
#[derive(Clone, Debug)]
pub struct RcbReturnBoundary {
    /// Actual address of the copied kernel context prefix.
    pub context: u64,
    /// Decoded remote FP address as DATA only; this observer never follows it.
    pub fp_pointer: u64,
    /// Exact kernel-prefix alternate-stack bounds and flags, not an owner token.
    pub signal_stack: (u64, u64, u32),
    /// Actual restored PC checked against both kernel prefix and stopped registers.
    pub pc: u64,
    /// Actual restored SP checked against both kernel prefix and stopped registers.
    pub sp: u64,
    /// True only for completion restoring guest state, false for Tool continuation.
    pub guest: bool,
    /// Counter remains exactly unchanged throughout the disabled interval.
    pub rcb: u64,
}
/// One completed nested runtime return, never an outer Guest/Tool return.
#[derive(Clone, Debug)]
pub struct RcbNestedReturn {
    /// Actual rt_sigreturn context pointer.
    pub context: u64,
    /// Validated remote FP pointer, recorded without dereferencing FP data.
    pub fp_pointer: u64,
    /// Actual alternate-stack interval and saved flags.
    pub signal_stack: (u64, u64, u32),
    /// Exact restored nested interrupted PC.
    pub pc: u64,
    /// Exact restored nested interrupted SP.
    pub sp: u64,
    /// Actual restored RAX, including a possible negative errno.
    pub result: u64,
    /// Unchanged outer paused counter value.
    pub rcb: u64,
}
/// One actual nested runtime delivery associated with its outer Guest boundary.
#[derive(Clone, Debug)]
pub struct RcbNestedBoundary {
    /// Zero-based index of the still-pending outer Guest delivery.
    pub boundary: usize,
    /// Actual native runtime syscall number.
    pub operation: u64,
    /// Exact interrupted runtime post-syscall PC.
    pub pc: u64,
    /// Exact interrupted runtime SP.
    pub sp: u64,
    /// Actual saved nested signal mask, distinct from the outer Guest mask.
    pub mask: u64,
    /// Unchanged outer paused counter value.
    pub rcb: u64,
    /// Present only after the matching genuine rt_sigreturn EXIT was verified.
    pub returned: Option<RcbNestedReturn>,
}
/// Partial or complete observational data; never product timer/readiness proof.
#[derive(Clone, Debug)]
pub struct RcbObservation {
    /// Literal metric and scope, not Hardware Instructions or logical time.
    pub scope: &'static str,
    /// The SAME shared PmuConfig raw event used by ptrace's branch clock.
    pub raw_event: u64,
    /// Actual retained task identifier; no caller-chosen PID is opened.
    pub tid: i32,
    /// Actual shared perf kernel ID, binding these samples to one event FD.
    pub perf_id: u64,
    /// Actual paused counter at the original held entry, required to be zero.
    pub origin_rcb: u64,
    /// Actual stopped original guest entry PC.
    pub origin_pc: u64,
    /// Actual stopped original guest entry SP.
    pub origin_sp: u64,
    /// Actual origin scheduling telemetry.
    pub origin_time_enabled: u64,
    /// Actual origin running telemetry, required to equal enabled time.
    pub origin_time_running: u64,
    /// Actual genuine delivery samples; the final exit sample is included.
    pub boundaries: Vec<RcbGuestBoundary>,
    /// Both Tool and final Guest sigreturn exits, in actual order.
    pub returns: Vec<RcbReturnBoundary>,
    /// Separately retained runtime deliveries/returns; never Guest samples.
    pub nested: Vec<RcbNestedBoundary>,
    /// Original wait owner's actual terminal status, if it was observed.
    pub terminal: Option<ExitStatus>,
    /// Successful actual counter disable on an error, if needed.
    pub error_pause: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Syscall,
    Cpuid,
    Rdtsc,
    Rdtscp,
}
impl Kind {
    fn advance(self) -> u64 {
        match self {
            Self::Syscall => 0,
            Self::Cpuid | Self::Rdtsc => 2,
            Self::Rdtscp => 3,
        }
    }
    fn may_change(self, index: usize) -> bool {
        match self {
            Self::Syscall => index == libc::REG_RAX as usize,
            Self::Cpuid => [libc::REG_RAX, libc::REG_RBX, libc::REG_RCX, libc::REG_RDX]
                .contains(&(index as i32)),
            Self::Rdtsc => [libc::REG_RAX, libc::REG_RDX].contains(&(index as i32)),
            Self::Rdtscp => [libc::REG_RAX, libc::REG_RDX, libc::REG_RCX].contains(&(index as i32)),
        }
    }
}
#[derive(Clone, Copy)]
struct Pending {
    original: Regs,
    mask: u64,
    kind: Kind,
    delivery: [u8; 128],
    completion_delivery: Option<[u8; 128]>,
    continuation_owner: Option<u64>,
    tool_returned: bool,
    final_exit: Option<i32>,
}
#[derive(Clone, Copy)]
struct NestedPending {
    original: Regs,
    mask: u64,
    delivery: [u8; 128],
    row: usize,
}
#[derive(Clone, Copy)]
struct ReturnEntry {
    context: u64,
    prefix: RemoteKernelPrefix,
    guest: bool,
}
pub(super) struct RetainedRcb {
    counter: PerfCounter,
    live: bool,
    last: u64,
    restorer: u64,
    restorer_post: u64,
    coordinates: RcbObservationCoordinates,
    pending: Option<Pending>,
    returning: Option<ReturnEntry>,
    nested: Option<NestedPending>,
    nested_returning: Option<ReturnEntry>,
    syscall: Option<(u64, u64)>, // actual number and post-PC at ENTRY
    completion_generation: Option<u64>,
    steps: u64,
    data: RcbObservation,
}
impl RetainedRcb {
    fn new(
        task: &safeptrace::Stopped,
        restorer: u64,
        coordinates: RcbObservationCoordinates,
    ) -> Result<Self> {
        let config = reverie::pmu_config::try_get_pmu_config()
            .ok_or("rcb_observer_no_shared_pmu_profile")?;
        let mut builder = Builder::new(task.pid().as_raw(), -1);
        builder
            .sample_period(0)
            .event(config.rcb_event())
            .fast_reads(true);
        let counter = builder.create()?;
        counter.reset()?;
        let origin_sample = counter.observed_paused_sample()?;
        if origin_sample.0 != 0 {
            return Err("rcb_observer_nonzero_origin".into());
        }
        let origin_registers = task.getregs()?;
        let counter_id = counter.id()?;
        Ok(Self {
            counter,
            live: false,
            last: 0,
            restorer,
            restorer_post: restorer
                .checked_add(11)
                .ok_or("rcb_observer_restorer_overflow")?,
            coordinates,
            pending: None,
            returning: None,
            nested: None,
            nested_returning: None,
            syscall: None,
            completion_generation: None,
            steps: 0,
            data: RcbObservation {
                scope: "RCB_MEASUREMENT_OBSERVER_ONLY_NOT_PRODUCT_TIMER_SUPPORT",
                raw_event: config.raw_rcb_event(),
                tid: task.pid().as_raw(),
                perf_id: counter_id,
                origin_rcb: origin_sample.0,
                origin_pc: origin_registers.rip,
                origin_sp: origin_registers.rsp,
                origin_time_enabled: origin_sample.1,
                origin_time_running: origin_sample.2,
                boundaries: Vec::new(),
                returns: Vec::new(),
                nested: Vec::new(),
                terminal: None,
                error_pause: None,
            },
        })
    }
    fn enable(&mut self) -> Result<()> {
        if self.live {
            return Err("rcb_observer_double_enable".into());
        }
        self.verify_paused()?;
        self.counter.enable()?;
        self.live = true;
        Ok(())
    }
    fn pause(&mut self) -> Result<(u64, u64, u64)> {
        if !self.live {
            return Err("rcb_observer_duplicate_guest_boundary".into());
        }
        self.counter.disable()?;
        self.live = false;
        let sample = self.counter.observed_paused_sample()?;
        if sample.0 < self.last {
            return Err("rcb_observer_count_decreased".into());
        }
        self.last = sample.0;
        Ok(sample)
    }
    fn verify_paused(&self) -> Result<()> {
        if self.live || self.counter.observed_paused_sample()?.0 != self.last {
            return Err("rcb_observer_disabled_tool_work_counted".into());
        }
        Ok(())
    }
}

impl PreparedMapping<'_> {
    /// Observe true RCBs on the SAME retained task through a finite hello exit.
    /// Initial restore is exactly the normal handover path; only detach changes
    /// to retained observation. All samples remain in self across cancellation.
    ///
    /// # Safety
    /// All handover_and_wait source/image/real initialization/physical/RPC and
    /// lexical-root requirements apply unchanged. This diagnostic intentionally
    /// retains ptrace, so it is NOT the detached production execution. Caller
    /// must bind these exact continuation labels and the fixed page to the same
    /// actual image; names/coordinates are not authority. The experiment admits
    /// one thread, no clone/exec, no guest handlers/async signals, no redirected
    /// guest syscalls/restarts or alternate frontend. Every unsupported event is
    /// a retained failure, never a successful skipped sample. CPUID/RDTSC/P
    /// genuine faults are forwarded unchanged, and both real signal returns are
    /// checked. Externally bound CPU affinity/profile must match the reference;
    /// runtime/tool work is paused without changing Detcore config or time.
    /// Original ptracer lexical root must poll existing RPC/stats/watch and this
    /// BORROWED future on its original OS thread, and require confirmed cleanup
    /// on timeout/panic/cancellation. No owner/resources move into the future.
    pub async unsafe fn handover_and_observe_rcb(
        &mut self,
        coordinates: &RcbObservationCoordinates,
        deadline: Instant,
    ) -> Result<RcbObservation> {
        let result = self.observe_rcb_inner(*coordinates, deadline).await;
        if result.is_err() {
            self.entry.failed = true;
            if let Some(state) = self.entry.rcb.as_mut()
                && state.live
            {
                match state.counter.disable() {
                    Ok(()) => {
                        state.live = false;
                        state.data.error_pause = Some("disabled_after_failure".into());
                    }
                    Err(error) => {
                        state.data.error_pause = Some(format!("disable_unconfirmed:{error}"))
                    }
                }
            }
        }
        result
    }
    /// Snapshot only retained observational data, including partial failure data.
    /// This grants no resume, task, terminal or counter authority.
    pub fn rcb_observation(&self) -> Option<RcbObservation> {
        self.entry.rcb.as_ref().map(|s| s.data.clone())
    }
    async fn observe_rcb_inner(
        &mut self,
        coordinates: RcbObservationCoordinates,
        deadline: Instant,
    ) -> Result<RcbObservation> {
        if self.entry.rcb.is_some() {
            return Err("rcb_observer_attempt_spent".into());
        }
        // Exactly the existing registration/readback/AT_RANDOM-preserving restore.
        self.restore_guest_for_release(deadline).await?;
        let view = View::parse(self._inputs.handoff_bytes, self._inputs.handoff_address)
            .map_err(|e| format!("rcb_observer_wire:{e:?}"))?;
        let task = self
            .task
            .as_ref()
            .ok_or("rcb_observer_missing_restored_stop")?;
        self.check_entry_generation(task)?;
        let restored = task.getregs()?;
        if super::super::super::register_words(&restored)
            != super::super::super::register_words(self.context.regs())
        {
            return Err("rcb_observer_original_entry_registers".into());
        }
        let mut descriptor = [0; 96];
        exact(task, self._inputs.layout_address, &mut descriptor)?;
        let layout = super::super::decode_target_layout(&descriptor)?;
        let restorer = layout
            .gate
            .checked_add(0x300)
            .ok_or("rcb_observer_restorer_overflow")?;
        let mut bytes = [0; 13];
        exact(task, restorer, &mut bytes)?;
        if bytes
            != [
                0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 15, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
            ]
        {
            return Err("rcb_observer_fixed_restorer_bytes".into());
        }
        if !in_code(view, coordinates.fallback_entry)?
            || !in_code(view, coordinates.completion_syscall)?
            || coordinates.fallback_entry >= coordinates.completion_syscall
        {
            return Err("rcb_observer_continuation_coordinates".into());
        }
        let mut completion = [0; 4];
        exact(task, coordinates.completion_syscall, &mut completion)?;
        if completion != [0x0f, 0x05, 0x0f, 0x0b] {
            return Err("rcb_observer_completion_bytes".into());
        }
        // Retain every process-creation event before refusing it. Do not allow
        // a silent fork/exec to escape the single original cleanup capability.
        task.setoptions(
            Options::PTRACE_O_EXITKILL
                | Options::PTRACE_O_TRACEEXEC
                | Options::PTRACE_O_TRACESYSGOOD
                | Options::PTRACE_O_TRACEFORK
                | Options::PTRACE_O_TRACEVFORK
                | Options::PTRACE_O_TRACECLONE,
        )?;
        self.entry.rcb = Some(RetainedRcb::new(task, restorer, coordinates)?);
        self.entry.rcb.as_mut().unwrap().enable()?;
        self.rcb_resume(None, false, deadline)?;
        loop {
            self.handover_wait_next(deadline).await?;
            // Actual terminal status was observed by the same persistent driver.
            if let Some(status) = self.entry.terminal {
                let state = self
                    .entry
                    .rcb
                    .as_mut()
                    .ok_or("rcb_observer_state_missing")?;
                state.verify_paused()?;
                if state.nested.is_some() || state.nested_returning.is_some() {
                    return Err("rcb_observer_terminal_during_nested_runtime".into());
                }
                let expected = state
                    .pending
                    .and_then(|p| p.final_exit)
                    .ok_or("rcb_observer_terminal_without_guest_exit")?;
                if status != ExitStatus::Exited(expected) {
                    return Err("rcb_observer_terminal_status_differs".into());
                }
                state.data.terminal = Some(status);
                // Existing original-owner receipt setter, after actual same-pid terminal.
                self.owner.record_detached_terminal(status);
                return Ok(self.entry.rcb.as_ref().unwrap().data.clone());
            }
            self.entry_thread()?;
            let task = self
                .task
                .as_ref()
                .ok_or("rcb_observer_missing_returned_stop")?;
            self.check_entry_generation(task)?;
            let regs = task.getregs()?;
            let state = self
                .entry
                .rcb
                .as_mut()
                .ok_or("rcb_observer_state_missing")?;
            state.steps = state
                .steps
                .checked_add(1)
                .ok_or("rcb_observer_step_overflow")?;
            if state.steps > STEP_LIMIT {
                return Err("rcb_observer_step_cap".into());
            }
            let live = state.live;
            if live {
                // Pause BEFORE classification, remote reads or reinjection.
                let sample = state.pause()?;
                let info = task.getsiginfo_bytes()?;
                let control = read_control(task, view)?;
                if !guest_phase(&control, task.pid().as_raw() as u64) {
                    return Err("rcb_observer_not_guest_phase".into());
                }
                let (kind, operation, signal) =
                    classify_guest(&self.entry.event, &info, &regs, task)?;
                if in_code(view, regs.rip)? {
                    return Err("rcb_observer_guest_pc_is_runtime".into());
                }
                if state.data.boundaries.len() >= LIMIT {
                    return Err("rcb_observer_guest_boundary_cap".into());
                }
                state.data.boundaries.push(RcbGuestBoundary {
                    signal: signal as i32,
                    operation,
                    pc: regs.rip,
                    sp: regs.rsp,
                    rcb: sample.0,
                    time_enabled: sample.1,
                    time_running: sample.2,
                });
                let final_exit = if kind == Kind::Syscall && matches!(regs.rax, 60 | 231) {
                    Some((regs.rdi & 255) as i32)
                } else {
                    None
                };
                state.pending = Some(Pending {
                    original: regs,
                    mask: task.getsigmask()?,
                    kind,
                    delivery: info,
                    completion_delivery: None,
                    continuation_owner: None,
                    tool_returned: false,
                    final_exit,
                });
                self.rcb_resume(Some(signal), true, deadline)?;
                continue;
            }
            state.verify_paused()?;
            match self.entry.event.as_ref() {
                Some(Event::Syscall) => {
                    let info = task.getsyscallinfo()?;
                    if info.architecture != 0xc000_003e
                        || info.instruction_pointer != regs.rip
                        || info.stack_pointer != regs.rsp
                    {
                        return Err("rcb_observer_syscall_info_register_mismatch".into());
                    }
                    match info.operation {
                        SyscallInfoOp::Entry { number, .. } => {
                            if state.syscall.replace((number, regs.rip)).is_some()
                                || state.returning.is_some()
                                || state.nested_returning.is_some()
                            {
                                return Err("rcb_observer_duplicate_syscall_entry".into());
                            }
                            if number == libc::SYS_rt_sigreturn as u64 {
                                if !sigreturn_entry(&info, &regs, state.restorer_post) {
                                    return Err("rcb_observer_wrong_sigreturn_site".into());
                                }
                                if let Some(nested) = state.nested {
                                    let mut bytes = [0; REMOTE_KERNEL_FRAME_BYTES];
                                    exact(
                                        task,
                                        regs.rsp
                                            .checked_sub(8)
                                            .ok_or("rcb_observer_nested_frame_underflow")?,
                                        &mut bytes,
                                    )?;
                                    let prefix = RemoteKernelPrefix::decode(
                                        &bytes,
                                        regs.rsp,
                                        state.restorer,
                                        &nested.delivery,
                                    )?;
                                    check_nested_return_prefix(&prefix, &nested)?;
                                    let control = read_control(task, view)?;
                                    if !nested_tool_state(
                                        &control,
                                        &regs,
                                        task.pid().as_raw() as u64,
                                        self.context.regs().gs_base,
                                    ) {
                                        return Err("rcb_observer_nested_return_phase".into());
                                    }
                                    state.nested_returning = Some(ReturnEntry {
                                        context: regs.rsp,
                                        prefix,
                                        guest: false,
                                    });
                                    self.rcb_resume(None, true, deadline)?;
                                    continue;
                                }
                                let pending = state
                                    .pending
                                    .as_ref()
                                    .ok_or("rcb_observer_sigreturn_without_delivery")?;
                                let guest = pending.completion_delivery.is_some();
                                if guest != pending.tool_returned {
                                    return Err("rcb_observer_wrong_return_phase".into());
                                }
                                let expected_info = pending
                                    .completion_delivery
                                    .as_ref()
                                    .unwrap_or(&pending.delivery);
                                let mut bytes = [0; REMOTE_KERNEL_FRAME_BYTES];
                                exact(
                                    task,
                                    regs.rsp
                                        .checked_sub(8)
                                        .ok_or("rcb_observer_frame_underflow")?,
                                    &mut bytes,
                                )?;
                                let prefix = RemoteKernelPrefix::decode(
                                    &bytes,
                                    regs.rsp,
                                    state.restorer,
                                    expected_info,
                                )?;
                                check_return_prefix(&prefix, pending, state.coordinates, guest)?;
                                let control = read_control(task, view)?;
                                if !return_phase(&control, guest, task.pid().as_raw() as u64) {
                                    return Err("rcb_observer_sigreturn_control_phase".into());
                                }
                                if !guest {
                                    state.pending.as_mut().unwrap().continuation_owner =
                                        Some(prefix.registers[libc::REG_RDI as usize]);
                                }
                                state.returning = Some(ReturnEntry {
                                    context: regs.rsp,
                                    prefix,
                                    guest,
                                });
                            } else {
                                // Runtime syscalls only, never a guest PC while paused.
                                if !in_code(
                                    view,
                                    regs.rip.checked_sub(2).ok_or("rcb_observer_syscall_pc")?,
                                )? || matches!(number, 56 | 57 | 58 | 59 | 322)
                                {
                                    return Err("rcb_observer_unqualified_runtime_syscall".into());
                                }
                            }
                        }
                        SyscallInfoOp::Exit { .. } => {
                            let (nr, post) = state
                                .syscall
                                .take()
                                .ok_or("rcb_observer_orphan_syscall_exit")?;
                            if let Some(returned) = state.nested_returning.take() {
                                if nr != libc::SYS_rt_sigreturn as u64
                                    || post != state.restorer_post
                                    || !restored_prefix_matches(&returned.prefix, &regs)
                                    || task.getsigmask()? != returned.prefix.mask
                                {
                                    return Err("rcb_observer_nested_sigreturn_exit_state".into());
                                }
                                let control = read_control(task, view)?;
                                if !nested_tool_state(
                                    &control,
                                    &regs,
                                    task.pid().as_raw() as u64,
                                    self.context.regs().gs_base,
                                ) {
                                    return Err("rcb_observer_nested_restored_phase".into());
                                }
                                let nested = state
                                    .nested
                                    .take()
                                    .ok_or("rcb_observer_nested_return_without_delivery")?;
                                let row = state
                                    .data
                                    .nested
                                    .get_mut(nested.row)
                                    .ok_or("rcb_observer_nested_row_missing")?;
                                if row.returned.is_some() {
                                    return Err("rcb_observer_duplicate_nested_return".into());
                                }
                                row.returned = Some(RcbNestedReturn {
                                    context: returned.context,
                                    fp_pointer: returned.prefix.fp_pointer,
                                    signal_stack: returned.prefix.stack,
                                    pc: regs.rip,
                                    sp: regs.rsp,
                                    result: regs.rax,
                                    rcb: state.last,
                                });
                                // Outer Pending, completion generation and return population
                                // remain untouched. Only the outer Guest return enables PMU.
                                self.rcb_resume(None, true, deadline)?;
                                continue;
                            }
                            if let Some(returned) = state.returning.take() {
                                if nr != libc::SYS_rt_sigreturn as u64
                                    || post != state.restorer_post
                                    || !restored_prefix_matches(&returned.prefix, &regs)
                                    || task.getsigmask()? != returned.prefix.mask
                                {
                                    return Err("rcb_observer_sigreturn_exit_state".into());
                                }
                                let control = read_control(task, view)?;
                                if !return_phase(
                                    &control,
                                    returned.guest,
                                    task.pid().as_raw() as u64,
                                ) {
                                    return Err("rcb_observer_restored_control_phase".into());
                                }
                                if state.data.returns.len() >= 2 * LIMIT {
                                    return Err("rcb_observer_return_cap".into());
                                }
                                state.data.returns.push(RcbReturnBoundary {
                                    context: returned.context,
                                    fp_pointer: returned.prefix.fp_pointer,
                                    signal_stack: returned.prefix.stack,
                                    pc: regs.rip,
                                    sp: regs.rsp,
                                    guest: returned.guest,
                                    rcb: state.last,
                                });
                                if returned.guest {
                                    state.pending = None;
                                    state.enable()?;
                                    self.rcb_resume(None, false, deadline)?;
                                } else {
                                    state.pending.as_mut().unwrap().tool_returned = true;
                                    self.rcb_resume(None, true, deadline)?;
                                }
                                continue;
                            }
                            if nr == libc::SYS_rt_sigreturn as u64 || post != regs.rip {
                                return Err("rcb_observer_wrong_runtime_syscall_exit".into());
                            }
                        }
                        _ => return Err("rcb_observer_wrong_syscall_operation".into()),
                    }
                    self.rcb_resume(None, true, deadline)?;
                }
                Some(Event::Signal(Signal::SIGSYS)) => {
                    let info = task.getsiginfo_bytes()?;
                    // Completion's exact PC is never eligible for the nested route,
                    // even when a bad cookie/owner/generation makes identity fail.
                    if state.coordinates.completion_syscall.checked_add(2) != Some(regs.rip) {
                        let pending = state
                            .pending
                            .as_ref()
                            .ok_or("rcb_observer_nested_without_original")?;
                        let control = read_control(task, view)?;
                        if state.syscall.is_some()
                            || state.returning.is_some()
                            || state.nested.is_some()
                            || state.nested_returning.is_some()
                            || !nested_delivery_state(
                                &info,
                                &regs,
                                pending,
                                state.coordinates,
                                &control,
                                task.pid().as_raw() as u64,
                                self.context.regs().gs_base,
                            )
                        {
                            return Err("rcb_observer_unqualified_nested_delivery".into());
                        }
                        tool_init_site(view, &info, &regs)?;
                        let start = regs
                            .rip
                            .checked_sub(2)
                            .ok_or("rcb_observer_nested_pc_underflow")?;
                        if !in_code(view, start)? || !in_code(view, regs.rip - 1)? {
                            return Err("rcb_observer_nested_instruction_extent".into());
                        }
                        let mut bytes = [0; 2];
                        exact(task, start, &mut bytes)?;
                        if bytes != [0x0f, 0x05] {
                            return Err("rcb_observer_nested_instruction_bytes".into());
                        }
                        if state.data.nested.len() >= LIMIT {
                            return Err("rcb_observer_nested_cap".into());
                        }
                        let mask = task.getsigmask()?;
                        let row = state.data.nested.len();
                        let boundary = state
                            .data
                            .boundaries
                            .len()
                            .checked_sub(1)
                            .ok_or("rcb_observer_nested_missing_boundary")?;
                        state.data.nested.push(RcbNestedBoundary {
                            boundary,
                            operation: regs.rax,
                            pc: regs.rip,
                            sp: regs.rsp,
                            mask,
                            rcb: state.last,
                            returned: None,
                        });
                        state.nested = Some(NestedPending {
                            original: regs,
                            mask,
                            delivery: info,
                            row,
                        });
                        self.rcb_resume(Some(Signal::SIGSYS), true, deadline)?;
                        continue;
                    }
                    let p = state
                        .pending
                        .as_mut()
                        .ok_or("rcb_observer_completion_without_original")?;
                    let generation = regs.rsi;
                    if state.syscall.is_some()
                        || state.nested.is_some()
                        || state.nested_returning.is_some()
                        || !completion_identity(
                            &info,
                            &regs,
                            p,
                            state.coordinates,
                            state.completion_generation,
                        )
                    {
                        return Err(format!(
                            "rcb_observer_wrong_completion_delivery: regs={regs:?}; siginfo={info:02x?}; \
                             pending_syscall={:?}; returning={}; live={}; last={}; \
                             tool_returned={}; completion_seen={}; continuation_owner={:?}; \
                             expected_completion={:#x}; previous_generation={:?}; \
                             original_guest={:?}; actual_syscall_info={:?}; mask={:?}; control={:?}",
                            state.syscall,
                            state.returning.is_some(),
                            state.live,
                            state.last,
                            p.tool_returned,
                            p.completion_delivery.is_some(),
                            p.continuation_owner,
                            state.coordinates.completion_syscall,
                            state.completion_generation,
                            p.original,
                            task.getsyscallinfo(),
                            task.getsigmask(),
                            read_control(task, view),
                        ).into());
                    }
                    let control = read_control(task, view)?;
                    if !return_phase(&control, false, task.pid().as_raw() as u64) {
                        return Err("rcb_observer_completion_phase".into());
                    }
                    state.completion_generation = Some(generation);
                    p.completion_delivery = Some(info);
                    self.rcb_resume(Some(Signal::SIGSYS), true, deadline)?;
                }
                _ => return Err("rcb_observer_unexpected_stop_retained".into()),
            }
        }
    }
    fn rcb_resume(
        &mut self,
        signal: Option<Signal>,
        syscall: bool,
        deadline: Instant,
    ) -> Result<()> {
        self.entry_thread()?;
        if Instant::now() >= deadline {
            return Err("rcb_observer_resume_deadline".into());
        }
        let task = self.task.take().ok_or("rcb_observer_missing_resume_stop")?;
        // Restore the stopped capability before exposing ANY original errno.
        let resumed = if syscall {
            task.syscall_retaining(signal)
        } else {
            task.resume_retaining(signal)
        };
        match resumed {
            Ok(running) => {
                self.entry.wait = Some(running.wait_owned_on_ptracer_thread().into_driver());
                self.entry.event = None;
                Ok(())
            }
            Err((task, error)) => {
                self.task = Some(task);
                Err(error.into())
            }
        }
    }
}
fn sigreturn_entry(info: &SyscallInfo, regs: &Regs, post: u64) -> bool {
    info.architecture == 0xc000_003e
        && info.instruction_pointer == post
        && info.instruction_pointer == regs.rip
        && info.stack_pointer == regs.rsp
        && matches!(info.operation,SyscallInfoOp::Entry {number,..} if number==libc::SYS_rt_sigreturn as u64)
}
fn completion_identity(
    info: &[u8; 128],
    regs: &Regs,
    p: &Pending,
    c: RcbObservationCoordinates,
    previous: Option<u64>,
) -> bool {
    p.tool_returned
        && p.completion_delivery.is_none()
        && sigsys_identity(info, regs.rip, regs.rax)
        && c.completion_syscall.checked_add(2) == Some(regs.rip)
        && regs.rax == libc::SYS_getpid as u64
        && regs.rdi == COMPLETION_COOKIE
        && Some(regs.rdx) == p.continuation_owner
        && regs.rsi != 0
        && previous.is_none_or(|old| old.checked_add(1) == Some(regs.rsi))
}
fn nested_tool_state(c: &[u8; 384], regs: &Regs, tid: u64, gs_base: u64) -> bool {
    return_phase(c, false, tid)
        && control_word(c, 4) != 0
        && regs.fs_base == control_word(c, 4)
        && regs.gs_base == gs_base
        // The source-owned Running callback validates the precise dynamic
        // continuation lease. The observer additionally excludes Guest stacks.
        && reverie_loader::artifact::TOOL_REGION.contains(&regs.rsp)
}
fn nested_delivery_state(
    info: &[u8; 128],
    regs: &Regs,
    p: &Pending,
    c: RcbObservationCoordinates,
    control: &[u8; 384],
    tid: u64,
    gs_base: u64,
) -> bool {
    p.tool_returned
        && p.completion_delivery.is_none()
        && c.completion_syscall.checked_add(2) != Some(regs.rip)
        && sigsys_identity(info, regs.rip, regs.rax)
        && regs.rax & !0x3fff_ffff == 0
        && !matches!(regs.rax, 15 | 56 | 57 | 58 | 59 | 322 | 435)
        && nested_tool_state(control, regs, tid, gs_base)
}
fn check_nested_return_prefix(f: &RemoteKernelPrefix, p: &NestedPending) -> Result<()> {
    if f.mask != p.mask {
        return Err("rcb_observer_nested_frame_mask_changed".into());
    }
    let original = greg(&p.original);
    for (index, value) in f.registers.iter().copied().enumerate() {
        if index != libc::REG_RAX as usize && value != original[index] {
            return Err("rcb_observer_nested_frame_register_changed".into());
        }
    }
    Ok(())
}
fn guest_phase(c: &[u8; 384], tid: u64) -> bool {
    return_phase(c, true, tid)
}
fn return_phase(c: &[u8; 384], guest: bool, tid: u64) -> bool {
    control_word(c, 0) == 1
        && control_word(c, 1) == 3520
        && control_word(c, 2) == if guest { 3 } else { 4 }
        && control_word(c, 9) == 1
        && control_word(c, 15) == tid
        && control_word(c, 40) == 0
        && control_word(c, 41) == u64::MAX
        && control_word(c, 46) == 3
}
fn classify_guest(
    event: &Option<Event>,
    info: &[u8; 128],
    r: &Regs,
    task: &safeptrace::Stopped,
) -> Result<(Kind, u64, Signal)> {
    match event.as_ref() {
        Some(Event::Signal(Signal::SIGSYS)) if sigsys_identity(info, r.rip, r.rax) => {
            if r.rax as u32 == libc::SYS_rt_sigreturn as u32 || r.rax & !0x3fff_ffff != 0 {
                return Err("rcb_observer_guest_sigreturn_or_non_native_abi".into());
            }
            let mut b = [0; 2];
            exact(
                task,
                r.rip
                    .checked_sub(2)
                    .ok_or("rcb_observer_guest_syscall_pc")?,
                &mut b,
            )?;
            if b != [0x0f, 0x05] {
                return Err("rcb_observer_guest_syscall_bytes".into());
            }
            Ok((Kind::Syscall, r.rax, Signal::SIGSYS))
        }
        Some(Event::Signal(Signal::SIGSEGV))
            if i32_at(info, 0) == libc::SIGSEGV
                && i32_at(info, 4) == 0
                && i32_at(info, 8) == libc::SI_KERNEL =>
        {
            let mut b = [0; 2];
            exact(task, r.rip, &mut b)?;
            match b {
                [0x0f, 0xa2] => Ok((Kind::Cpuid, 0xa20f, Signal::SIGSEGV)),
                [0x0f, 0x31] => Ok((Kind::Rdtsc, 0x310f, Signal::SIGSEGV)),
                [0x0f, 0x01] => {
                    let mut b = [0; 3];
                    exact(task, r.rip, &mut b)?;
                    if b == [0x0f, 0x01, 0xf9] {
                        Ok((Kind::Rdtscp, 0xf9010f, Signal::SIGSEGV))
                    } else {
                        Err("rcb_observer_unknown_instruction_fault".into())
                    }
                }
                _ => Err("rcb_observer_unknown_instruction_fault".into()),
            }
        }
        _ => Err("rcb_observer_not_genuine_guest_trap".into()),
    }
}
fn greg(r: &Regs) -> [u64; 19] {
    [
        r.r8,
        r.r9,
        r.r10,
        r.r11,
        r.r12,
        r.r13,
        r.r14,
        r.r15,
        r.rdi,
        r.rsi,
        r.rbp,
        r.rbx,
        r.rdx,
        r.rax,
        r.rcx,
        r.rsp,
        r.rip,
        r.eflags,
        (r.cs & 0xffff)
            | ((r.gs & 0xffff) << 16)
            | ((r.fs & 0xffff) << 32)
            | ((r.ss & 0xffff) << 48),
    ]
}
fn check_return_prefix(
    f: &RemoteKernelPrefix,
    p: &Pending,
    c: RcbObservationCoordinates,
    guest: bool,
) -> Result<()> {
    let original = greg(&p.original);
    if f.mask != p.mask {
        return Err("rcb_observer_frame_mask_changed".into());
    }
    for (index, value) in f.registers.iter().copied().enumerate() {
        let expected = if index == libc::REG_RIP as usize {
            if guest {
                original[index]
                    .checked_add(p.kind.advance())
                    .ok_or("rcb_observer_pc_overflow")?
            } else {
                c.fallback_entry
            }
        } else if !guest && index == libc::REG_EFL as usize {
            original[index] & !(1 << 10)
        } else {
            original[index]
        };
        let changed = if guest {
            p.kind.may_change(index)
        } else {
            [libc::REG_RSP, libc::REG_RDI].contains(&(index as i32))
        };
        // SET_FS may legitimately update only the packed FS selector. The
        // actual resulting FS base is kernel state and is not reconstructed.
        let setfs = guest
            && p.kind == Kind::Syscall
            && p.original.rax == libc::SYS_arch_prctl as u64
            && p.original.rdi == 0x1002;
        if setfs && index == libc::REG_CSGSFS as usize {
            if (value & !(0xffff << 32)) != (expected & !(0xffff << 32)) {
                return Err("rcb_observer_frame_selectors_changed".into());
            }
        } else if !changed && value != expected {
            return Err("rcb_observer_frame_register_changed".into());
        }
    }
    if !guest
        && (f.registers[libc::REG_RSP as usize] & 15 != 0
            || f.registers[libc::REG_RDI as usize] == 0)
    {
        return Err("rcb_observer_tool_frame_shape".into());
    }
    Ok(())
}
fn restored_prefix_matches(f: &RemoteKernelPrefix, r: &Regs) -> bool {
    f.registers == greg(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending() -> Pending {
        let mut r: Regs = unsafe { std::mem::zeroed() };
        r.rip = 0x400002;
        r.rsp = 0x700000;
        r.rax = 1;
        r.cs = 0x33;
        r.ss = 0x2b;
        r.eflags = 0x202;
        Pending {
            original: r,
            mask: 0,
            kind: Kind::Syscall,
            delivery: [0; 128],
            completion_delivery: None,
            continuation_owner: None,
            tool_returned: false,
            final_exit: None,
        }
    }
    fn final_prefix(p: &Pending) -> RemoteKernelPrefix {
        RemoteKernelPrefix {
            registers: greg(&p.original),
            mask: p.mask,
            fp_pointer: 0x8000,
            stack: (0x1000, 0x10000, 0),
        }
    }
    #[test]
    fn only_actual_sigreturn_entry_at_the_bound_restorer_is_accepted() {
        let p = pending();
        let r = p.original;
        let i = SyscallInfo {
            architecture: 0xc000_003e,
            instruction_pointer: r.rip,
            stack_pointer: r.rsp,
            kernel_size: 80,
            operation: SyscallInfoOp::Entry {
                number: 15,
                arguments: [0; 6],
            },
        };
        assert!(sigreturn_entry(&i, &r, r.rip));
        let mut wrong = i;
        wrong.operation = SyscallInfoOp::Entry {
            number: 39,
            arguments: [0; 6],
        };
        assert!(!sigreturn_entry(&wrong, &r, r.rip));
        wrong.operation = SyscallInfoOp::Exit {
            return_value: 0,
            is_error: false,
        };
        assert!(!sigreturn_entry(&wrong, &r, r.rip));
        wrong = i;
        wrong.stack_pointer += 8;
        assert!(!sigreturn_entry(&wrong, &r, r.rip));
        wrong = i;
        wrong.architecture = 0x4000_003e;
        assert!(!sigreturn_entry(&wrong, &r, r.rip));
        assert!(!sigreturn_entry(&i, &r, r.rip + 1));
    }
    #[test]
    fn guest_result_only_changes_rax_and_exact_pc_sp_restore() {
        let p = pending();
        let c = RcbObservationCoordinates {
            fallback_entry: 0x600000,
            completion_syscall: 0x600040,
        };
        let mut f = final_prefix(&p);
        f.registers[libc::REG_RAX as usize] = 99;
        assert!(check_return_prefix(&f, &p, c, true).is_ok());
        for i in [libc::REG_RSP, libc::REG_RIP, libc::REG_RBX] {
            let mut bad = f;
            bad.registers[i as usize] ^= 1;
            assert!(check_return_prefix(&bad, &p, c, true).is_err());
        }
        f.mask = 1;
        assert!(check_return_prefix(&f, &p, c, true).is_err());
    }
    #[test]
    fn first_signal_return_is_tool_not_guest() {
        let p = pending();
        let c = RcbObservationCoordinates {
            fallback_entry: 0x600000,
            completion_syscall: 0x600040,
        };
        let mut f = final_prefix(&p);
        f.registers[libc::REG_RIP as usize] = c.fallback_entry;
        f.registers[libc::REG_RSP as usize] = 0x900000;
        f.registers[libc::REG_RDI as usize] = 0x800000;
        assert!(check_return_prefix(&f, &p, c, false).is_ok());
        assert!(check_return_prefix(&f, &p, c, true).is_err());
        f.registers[libc::REG_RBX as usize] ^= 1;
        assert!(check_return_prefix(&f, &p, c, false).is_err());
    }
    #[test]
    fn instruction_results_and_lengths_are_not_blanket_mutation_permission() {
        let mut p = pending();
        p.kind = Kind::Cpuid;
        let mut f = final_prefix(&p);
        f.registers[libc::REG_RIP as usize] += 2;
        for i in [libc::REG_RAX, libc::REG_RBX, libc::REG_RCX, libc::REG_RDX] {
            f.registers[i as usize] = 42;
        }
        let c = RcbObservationCoordinates {
            fallback_entry: 1,
            completion_syscall: 2,
        };
        assert!(check_return_prefix(&f, &p, c, true).is_ok());
        f.registers[libc::REG_RSI as usize] ^= 1;
        assert!(check_return_prefix(&f, &p, c, true).is_err());
        f.registers[libc::REG_RSI as usize] ^= 1;
        p.kind = Kind::Rdtscp;
        assert!(check_return_prefix(&f, &p, c, true).is_err());
    }
    #[test]
    fn completion_requires_exact_syscall_cookie_owner_generation_and_phase() {
        let mut p = pending();
        p.tool_returned = true;
        p.continuation_owner = Some(0x900000);
        let c = RcbObservationCoordinates {
            fallback_entry: 0x600000,
            completion_syscall: 0x600040,
        };
        let mut r = p.original;
        r.rip = c.completion_syscall + 2;
        r.rax = 39;
        r.rdi = COMPLETION_COOKIE;
        r.rdx = 0x900000;
        r.rsi = 2;
        let mut i = [0; 128];
        i[0..4].copy_from_slice(&libc::SIGSYS.to_le_bytes());
        i[8..12].copy_from_slice(&1_i32.to_le_bytes());
        i[16..24].copy_from_slice(&r.rip.to_le_bytes());
        i[24..28].copy_from_slice(&39_i32.to_le_bytes());
        i[28..32].copy_from_slice(&0xc000_003e_u32.to_le_bytes());
        assert!(completion_identity(&i, &r, &p, c, Some(1)));
        for field in 0..4 {
            let mut bad = r;
            match field {
                0 => bad.rax = 40,
                1 => bad.rdi ^= 1,
                2 => bad.rdx ^= 1,
                _ => bad.rsi = 3,
            };
            assert!(!completion_identity(&i, &bad, &p, c, Some(1)));
        }
        p.tool_returned = false;
        assert!(!completion_identity(&i, &r, &p, c, Some(1)));
        p.tool_returned = true;
        p.completion_delivery = Some(i);
        assert!(!completion_identity(&i, &r, &p, c, Some(1)));
    }
    #[test]
    fn phase_ready_birth_and_failure_are_all_required() {
        let mut c = [0; 384];
        for (i, v) in [
            (0, 1_u64),
            (1, 3520),
            (2, 3),
            (9, 1),
            (15, 7),
            (41, u64::MAX),
            (46, 3),
        ] {
            c[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        assert!(guest_phase(&c, 7));
        assert!(!return_phase(&c, false, 7));
        assert!(!guest_phase(&c, 8));
        for (i, v) in [(2, 4_u64), (9, 0), (40, 1), (41, 3), (46, 1)] {
            let mut bad = c;
            bad[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            assert!(!guest_phase(&bad, 7));
        }
    }
    fn nested_fixture() -> (
        Pending,
        RcbObservationCoordinates,
        Regs,
        [u8; 128],
        [u8; 384],
    ) {
        let mut p = pending();
        p.tool_returned = true;
        p.continuation_owner = Some(0x600000800000);
        let c = RcbObservationCoordinates {
            fallback_entry: 0x6000e1002000,
            completion_syscall: 0x6000e100202c,
        };
        let mut r = p.original;
        r.rip = 0x6000e1601796;
        r.rsp = 0x600000d3b800;
        r.rax = 5;
        r.fs_base = 0x6000002013a0;
        let mut info = [0; 128];
        info[0..4].copy_from_slice(&libc::SIGSYS.to_le_bytes());
        info[8..12].copy_from_slice(&1_i32.to_le_bytes());
        info[16..24].copy_from_slice(&r.rip.to_le_bytes());
        info[24..28].copy_from_slice(&(r.rax as i32).to_le_bytes());
        info[28..32].copy_from_slice(&0xc000003e_u32.to_le_bytes());
        let mut control = [0; 384];
        for (i, value) in [
            (0, 1_u64),
            (1, 3520),
            (2, 4),
            (4, r.fs_base),
            (9, 1),
            (15, 3),
            (41, u64::MAX),
            (46, 3),
        ] {
            control[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        (p, c, r, info, control)
    }
    #[test]
    fn nested_delivery_requires_actual_outer_tool_and_native_identity() {
        let (mut p, c, mut r, mut info, control) = nested_fixture();
        assert!(nested_delivery_state(&info, &r, &p, c, &control, 3, 0));
        r.rax = 186;
        info[24..28].copy_from_slice(&186_i32.to_le_bytes());
        assert!(nested_delivery_state(&info, &r, &p, c, &control, 3, 0));
        p.tool_returned = false;
        assert!(!nested_delivery_state(&info, &r, &p, c, &control, 3, 0));
        p.tool_returned = true;
        p.completion_delivery = Some(info);
        assert!(!nested_delivery_state(&info, &r, &p, c, &control, 3, 0));
        p.completion_delivery = None;
        for number in [15_u64, 56, 57, 58, 59, 322, 435, 0x40000005, u64::MAX] {
            r.rax = number;
            info[24..28].copy_from_slice(&(number as i32).to_le_bytes());
            assert!(!nested_delivery_state(&info, &r, &p, c, &control, 3, 0));
        }
    }
    #[test]
    fn wrong_completion_at_its_exact_pc_cannot_fall_through_as_nested() {
        let (p, c, mut r, mut info, control) = nested_fixture();
        r.rip = c.completion_syscall + 2;
        r.rax = 39;
        r.rdi = 0; // not the completion cookie
        info[16..24].copy_from_slice(&r.rip.to_le_bytes());
        info[24..28].copy_from_slice(&39_i32.to_le_bytes());
        assert!(!completion_identity(&info, &r, &p, c, None));
        assert!(!nested_delivery_state(&info, &r, &p, c, &control, 3, 0));
    }
    #[test]
    fn nested_phase_birth_tool_fs_gs_and_stack_are_not_optional() {
        let (p, c, r, info, control) = nested_fixture();
        assert!(nested_delivery_state(&info, &r, &p, c, &control, 3, 0));
        for (index, value) in [(2, 3_u64), (9, 0), (15, 4), (40, 1), (41, 3), (46, 1)] {
            let mut bad = control;
            bad[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
            assert!(!nested_delivery_state(&info, &r, &p, c, &bad, 3, 0));
        }
        for which in 0..3 {
            let mut bad = r;
            match which {
                0 => bad.fs_base ^= 8,
                1 => bad.gs_base = 8,
                _ => bad.rsp = 0x7fffffff0000,
            }
            assert!(!nested_delivery_state(&info, &bad, &p, c, &control, 3, 0));
        }
        for offset in [0_usize, 8, 16, 24, 28] {
            let mut bad = info;
            bad[offset] ^= 1;
            assert!(!nested_delivery_state(&bad, &r, &p, c, &control, 3, 0));
        }
    }
    #[test]
    fn nested_return_allows_only_rax_and_preserves_its_own_mask() {
        let (_p, _c, r, info, _control) = nested_fixture();
        let p = NestedPending {
            original: r,
            mask: 0x1234,
            delivery: info,
            row: 0,
        };
        let mut f = RemoteKernelPrefix {
            registers: greg(&r),
            mask: p.mask,
            fp_pointer: 0x60000f000800,
            stack: (0x60000f000000, 0x60000f010000, 0),
        };
        for value in [0, 3, u64::MAX - 8] {
            f.registers[libc::REG_RAX as usize] = value;
            assert!(check_nested_return_prefix(&f, &p).is_ok());
        }
        for index in 0..19 {
            if index == libc::REG_RAX as usize {
                continue;
            }
            let mut bad = f;
            bad.registers[index] ^= 1;
            assert!(check_nested_return_prefix(&bad, &p).is_err());
        }
        f.mask ^= 1;
        assert!(check_nested_return_prefix(&f, &p).is_err());
    }
}
