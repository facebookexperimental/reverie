//! Borrowed bootstrap observation, with explicitly selected unsafe ToolInit domain.
//! Domain selection is numeric data, never runtime proof or entry approval.
//! No owned async operation receives a child, FD, backing or source owner.

use std::future::poll_fn;
use std::time::Instant;

use reverie_loader::handoff::Operation;
use reverie_loader::handoff::Site;
use reverie_loader::handoff::View;
use reverie_memory::Addr;
use reverie_memory::MemoryAccess;
use safeptrace::Event;
use safeptrace::ExitStatus;
use safeptrace::PtracerWaitDriver;
use safeptrace::Regs;
use safeptrace::Signal;
use safeptrace::Wait;

use super::PreparedMapping;
use super::Result;

mod handover;
mod observed_rcb;
pub use observed_rcb::RcbGuestBoundary;
pub use observed_rcb::RcbNestedBoundary;
pub use observed_rcb::RcbNestedReturn;
pub use observed_rcb::RcbObservation;
pub use observed_rcb::RcbObservationCoordinates;
pub use observed_rcb::RcbReturnBoundary;
mod startup_auxv;

/// Unauthenticated coordinates for a bootstrap-only unsafe operation.
/// Safe construction does not qualify source, code, admission or entry.
/// These are data, never a Ready token or a substitute for the live source owner.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapEntryCoordinates {
    /// Actual qualified private C entry, with arguments (handoff pointer, length).
    pub entry: u64,
    /// Actual source-qualified INT3 instruction, not its post-RIP.
    /// Recognizing this trap supplies only a stopped observation in this draft.
    pub terminal_int3: u64,
}

/// Explicit observer domain under the caller's real unsafe entry contract.
/// Constructing this value authenticates no source, frontend, child or readiness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObservationDomain {
    /// Preserve the original four-pair phase1 experiment, refusing phase2.
    #[default]
    BootstrapOnly,
    /// Permit same-owner phase2 deliveries only after complete qualification.
    ToolInitialization {
        /// Actual configured AND source-qualified reserved signal set. The
        /// current child mechanism reserves SIGSYS and, if instruction
        /// interception is subscribed, SIGSEGV. Never guess this from a mask.
        reserved_signals: u64,
    },
}

/// Actual terminal trap observed while retaining the SAME stopped child.
/// This is NOT proof that genuine initialization returned or that all ToolInit,
/// exception, async or pre-FS paths were qualified. It grants no release method.
#[derive(Debug)]
pub struct BootstrapTerminalStop {
    /// Actual kernel register image in the existing 27-word order.
    pub registers: [u64; 27],
    /// Original kernel siginfo bytes, without a reconstructed libc union.
    pub siginfo: [u8; 128],
    /// Number of real bootstrap SIGSYS deliveries reinjected by this attempt.
    pub forwarded_sigsys: u64,
    /// Actual phase2 deliveries, zero in the unchanged bootstrap-only domain.
    pub forwarded_tool_init_sigsys: u64,
}

#[derive(Default)]
pub(super) struct RetainedEntry {
    attempted: bool,
    pub(super) failed: bool,
    wait: Option<PtracerWaitDriver>,
    event: Option<Event>,
    terminal: Option<ExitStatus>,
    forwarded: u64,
    forwarded_tool_init: u64,
    initialized_stop: Option<(u64, u64)>, // actual INT3 and actual reserved set
    handover_started: bool,
    // Counter, pending frame state and partial observations stay in the SAME
    // physical owner across every cancellable await.
    rcb: Option<observed_rcb::RetainedRcb>,
    // Bounded observations only; never consulted by admission or resumption.
    recent_tool_syscalls: std::collections::VecDeque<[u64; 8]>,
}
impl RetainedEntry {
    fn begin_attempt(&mut self, deadline: Instant) -> Result<()> {
        if self.attempted || self.failed || Instant::now() >= deadline {
            return Err("mapped_entry_attempt_spent_or_expired".into());
        }
        self.attempted = true;
        Ok(())
    }

    pub(super) fn retains_child(&self) -> bool {
        matches!(self.event, Some(Event::NewChild(_, _)))
    }
}

impl PreparedMapping<'_> {
    /// Borrow this complete owner for bootstrap-only execution and observation.
    /// ToolInit phase and all non-bootstrap stops refuse with the actual stop
    /// retained. This cannot implement the complete genuine initializer observer.
    /// Timeout, error or dropping this future permits only terminal cleanup.
    ///
    /// # Safety
    /// The synchronous, non-cancellable lexical root retains this mapping and
    /// every borrowed request FD/backing/source/admission resource OUTSIDE both
    /// this future and every outer RPC/observation adapter. It creates the child,
    /// polls this future and retries terminal cleanup on the original ptracer OS
    /// thread. Before returning or dropping those resources it must require real
    /// same-generation terminal confirmation; Drop or a kill request is not proof.
    /// This function does not own or replace that root or the existing RPC owner.
    ///
    /// BEFORE this call the real same-source artifact/whole pre-FS and async
    /// closure, kernel signal/gate/PKRU/FS/stack facts, immutable mappings and
    /// same-OFD sealed input plus genuine same-child admission MUST be qualified.
    /// The entry is the actual no-return C entry for the SAME mapped image.
    /// `terminal_int3` must be the actual qualified INT3, not an arbitrary byte.
    /// The complete source/CFG must exclude fork/clone and establish that the
    /// four source-qualified handoff sites execute only in NativeControl phase1
    /// under the existing real handler. Control ABI is the actual retained
    /// 3520-byte NativeControl (existing fixed u64 prefix); no layout from JSON
    /// authenticates it. The complete child handler, FS transition, registration,
    /// secure FD cleanup and publication remain the real implementation.
    ///
    /// The host delivery-mask predicate is coupled to the exact retained
    /// runtime mapped_initial::startup_mask source: all bits except SIGSYS,
    /// SIGKILL and SIGSTOP. It is NOT shared runtime code. Requalify this
    /// coupling if that runtime mechanism changes; never normalize observed
    /// masks or accept the original entry mask during bootstrap delivery.
    ///
    /// No current receipt establishes these prerequisites. This is an UNRUN
    /// implementation draft, not permission to call it. Full ToolInit forwarding
    /// remains missing: this observer refuses phase2 rather than using its sites.
    /// No Guest context restore or original-stack overwrite is performed here.
    pub async unsafe fn observe_bootstrap_until_terminal(
        &mut self,
        coordinates: &BootstrapEntryCoordinates,
        deadline: Instant,
    ) -> Result<BootstrapTerminalStop> {
        // SAFETY: exactly the unchanged bootstrap-only contract above.
        unsafe {
            self.observe_until_terminal(coordinates, ObservationDomain::BootstrapOnly, deadline)
                .await
        }
    }

    /// Observe the SAME retained child in an explicitly selected startup domain.
    /// Returned registers/siginfo/counters are data, never initialization proof.
    /// No Guest restoration or release method is added.
    ///
    /// # Safety
    /// All `observe_bootstrap_until_terminal` physical, source, async, signal,
    /// sole-ptracer and complete outer-owner lifetime requirements apply. This
    /// entry additionally permits the caller to choose ToolInitialization ONLY
    /// after the SAME actual image's full pre-FS/handler/TLS/libc/FD-cleanup,
    /// fixed-gate, C allocator and ToolRegion/M1/adoption proofs close, with real
    /// same-child input/factory and ordinary InitialImage admission binding.
    /// No current observation or numeric domain establishes those prerequisites.
    ///
    /// For ToolInitialization the caller must qualify every immutable table8
    /// post-PC as an exact native syscall instruction on trusted Tool-only
    /// callflow, with no Guest or process creation/exec, phase2/native1/ready0,
    /// and the actual prepared TCB/Tool stack. `reserved_signals` is the actual
    /// configured/source-qualified set of this child, not a caller preference.
    /// The complete child controller/relay must select ONE real frontend under
    /// busy and verify its exact kernel frame/action/altstack/mask; no ordinary
    /// trap can occur in Replacing, and Retired never forwards. Host mask bounds
    /// below are necessary observations, NOT Installed frontend attestation.
    /// Actual Tool syscalls use the unchanged child raw Tool gate and shared
    /// process/signal/descriptor/mapping guards, never Guest event.forward().
    ///
    /// The same existing RPC server, issue/watch monitors and DETLOG service
    /// must be polled concurrently by the retained lexical root without moving
    /// this physical owner from its original OS ptracer thread. On every error,
    /// timeout, panic or future drop, require original-owner confirmed terminal
    /// cleanup before releasing any source/FD/backing/admission resources. Never
    /// replay an uncertain native syscall, initializer, or spent attempt.
    ///
    /// In this domain the exact qualified terminal label is reached ONLY after
    /// genuine shared Detcore initialization/lifecycle/finish returns. Its final
    /// phase2/ready1 readback is necessary data, not proof from a ready scalar.
    /// All earlier trap/exit/signal failures remain failures. Broader phase4
    /// callbacks, Guest restoration and release are outside this operation.
    pub async unsafe fn observe_until_terminal(
        &mut self,
        coordinates: &BootstrapEntryCoordinates,
        domain: ObservationDomain,
        deadline: Instant,
    ) -> Result<BootstrapTerminalStop> {
        let outcome = self.bootstrap_observe(coordinates, domain, deadline).await;
        if let Err(error) = outcome {
            self.entry.failed = true;
            // Failure-only observations of the same retained stop. Never alter
            // its event, siginfo, registers, failure or cleanup requirement.
            let registers = self.task.as_ref().map(|task| task.getregs());
            let siginfo = self.task.as_ref().map(|task| task.getsiginfo_bytes());
            let control = self.task.as_ref().map(|task| {
                View::parse(self._inputs.handoff_bytes, self._inputs.handoff_address)
                    .map_err(|error| format!("{error:?}"))
                    .and_then(|view| read_control(task, view).map_err(|error| error.to_string()))
                    .map(|bytes| {
                        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
                            .map(|word| control_word(&bytes, word))
                    })
            });
            // Best-effort bounded diagnostics cannot replace the original
            // concrete error (including its errno/source/downcast identity).
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "mapped initializer failure: {error}; event={:?}; registers={registers:?}; siginfo={siginfo:?}; control_words_2_to_14={control:?}; bootstrap_sigsys={}; tool_init_sigsys={}; recent_tool_syscalls={:?}",
                self.entry.event,
                self.entry.forwarded,
                self.entry.forwarded_tool_init,
                self.entry.recent_tool_syscalls
            );
            return Err(error);
        }
        outcome
    }

    fn entry_thread(&self) -> Result<()> {
        self.owner
            ._thread
            .as_ref()
            .ok_or("mapped_entry_missing_ptracer")?
            .check_current()?;
        if self.owner.complete {
            return Err("mapped_entry_retired".into());
        }
        Ok(())
    }

    async fn bootstrap_observe(
        &mut self,
        coordinates: &BootstrapEntryCoordinates,
        domain: ObservationDomain,
        deadline: Instant,
    ) -> Result<BootstrapTerminalStop> {
        self.entry_thread()?;
        if let ObservationDomain::ToolInitialization { reserved_signals } = domain
            && !qualified_reserved_set(reserved_signals)
        {
            return Err("mapped_entry_invalid_reserved_set".into());
        }
        // Latch before any mutation. No cancellation point precedes installing
        // a successful Running into the persistent driver below.
        self.entry.begin_attempt(deadline)?;
        let view = View::parse(self._inputs.handoff_bytes, self._inputs.handoff_address)
            .map_err(|e| format!("mapped_entry_wire: {e:?}"))?;
        let task = self.task.as_ref().ok_or("mapped_entry_missing_stop")?;
        self.check_entry_generation(task)?;
        if super::super::register_words(&task.getregs()?)
            != super::super::register_words(self.context.regs())
            || task.getsigmask()? != self.context.signal_mask()
            || task.getxstate()? != *self.context.xstate()
            || self.context.signal_mask() & (1 << (libc::SIGSYS - 1)) != 0
        {
            return Err("mapped_entry_original_context_changed".into());
        }
        let mut wire = vec![0; self._inputs.handoff_bytes.len()];
        exact(task, self._inputs.handoff_address, &mut wire)?;
        if wire != self._inputs.handoff_bytes {
            return Err("mapped_entry_handoff_bytes_changed".into());
        }
        super::sealed_contents(
            self._inputs.runtime_fd,
            self._inputs.runtime_bytes,
            self._inputs.runtime_bytes.len() as u64,
        )?;
        let handoff = super::interior(
            view.role(3)
                .map_err(|e| format!("mapped_entry_handoff: {e:?}"))?,
        )?;
        super::sealed_contents(
            self._inputs.handoff_fd,
            self._inputs.handoff_bytes,
            handoff.end - handoff.start,
        )?;
        if !in_code(view, coordinates.entry)? || !in_code(view, coordinates.terminal_int3)? {
            return Err("mapped_entry_coordinate_not_code".into());
        }
        let mut byte = [0];
        exact(task, coordinates.terminal_int3, &mut byte)?;
        if byte != [0xcc] {
            return Err("mapped_entry_terminal_not_int3".into());
        }
        // The same startup contract as ptrace must hold BEFORE Detcore's
        // thread/post-exec callbacks and before any guest libc instruction.
        // BootstrapOnly and nonexecuting map/cancel keep their old behavior.
        if matches!(domain, ObservationDomain::ToolInitialization { .. }) {
            self.canonicalize_guest_startup(coordinates, deadline)
                .await?;
        }
        let task = self.task.as_ref().ok_or("mapped_entry_missing_stop")?;
        let stack = view
            .role(0)
            .map_err(|e| format!("mapped_entry_stack: {e:?}"))?;
        let rsp = stack
            .end
            .checked_sub(4096 + 8)
            .ok_or("mapped_entry_stack_bounds")?;
        if rsp & 15 != 8 || !stack.contains(rsp, 8) {
            return Err("mapped_entry_stack_alignment".into());
        }
        let mut return_slot = [0; 8];
        exact(task, rsp, &mut return_slot)?;
        if return_slot != [0; 8] {
            return Err("mapped_entry_stack_not_zero".into());
        }
        let mut regs = task.getregs()?;
        regs.rip = coordinates.entry;
        regs.rsp = rsp;
        regs.rdi = self._inputs.handoff_address;
        regs.rsi = self._inputs.handoff_bytes.len() as u64;
        regs.orig_rax = u64::MAX;
        task.setregs(&regs)?;
        if super::super::register_words(&task.getregs()?) != super::super::register_words(&regs)
            || task.getsigmask()? != self.context.signal_mask()
            || task.getxstate()? != *self.context.xstate()
        {
            return Err("mapped_entry_launch_readback".into());
        }
        self.resume_entry(None, deadline)?;
        loop {
            // The adapter borrows a driver that was already installed in self.
            // Dropping timeout/RPC/outer futures cannot take that owner away.
            let waited = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                poll_fn(|cx| match self.entry.wait.as_mut() {
                    Some(driver) => driver.poll_on_ptracer_thread(cx),
                    None => std::task::Poll::Ready(Err(safeptrace::OwnedWaitError::Completed)),
                }),
            )
            .await
            .map_err(|_| "mapped_entry_deadline")?;
            match waited {
                Ok(Wait::Stopped(task, event)) => {
                    // Store BOTH capabilities before any generation/readback/
                    // classification failure. A NewChild event is retained too.
                    self.task = Some(task);
                    self.entry.event = Some(event);
                    self.entry.wait = None;
                }
                Ok(Wait::Exited(_, status)) => {
                    self.entry.terminal = Some(status);
                    self.entry.wait = None;
                    return Err("mapped_entry_early_exit".into());
                }
                Err(error) => return Err(error.into()), // original driver retained
            }
            self.entry_thread()?;
            let task = self
                .task
                .as_ref()
                .ok_or("mapped_entry_missing_returned_stop")?;
            self.check_entry_generation(task)?;
            if !matches!(
                self.entry.event,
                Some(Event::Signal(Signal::SIGSYS | Signal::SIGTRAP))
            ) {
                return Err("mapped_entry_unexpected_event_retained".into());
            }
            let regs = task.getregs()?;
            let info = task.getsiginfo_bytes()?;
            if matches!(self.entry.event, Some(Event::Signal(Signal::SIGTRAP))) {
                if terminal(&info, regs.rip, coordinates.terminal_int3) {
                    if let ObservationDomain::ToolInitialization { reserved_signals } = domain {
                        self.verify_tool_init_stop(task, view, &regs, reserved_signals, 1)?;
                        self.entry.initialized_stop =
                            Some((coordinates.terminal_int3, reserved_signals));
                    }
                    return Ok(BootstrapTerminalStop {
                        registers: super::super::register_words(&regs),
                        siginfo: info,
                        forwarded_sigsys: self.entry.forwarded,
                        forwarded_tool_init_sigsys: self.entry.forwarded_tool_init,
                    });
                }
                return Err("mapped_entry_unexpected_sigtrap".into());
            }
            if let ObservationDomain::ToolInitialization { reserved_signals } = domain {
                let control = read_control(task, view)?;
                if control_word(&control, 2) == 2 {
                    self.verify_tool_init_stop(task, view, &regs, reserved_signals, 0)?;
                    tool_init_site(view, &info, &regs)?;
                    let instruction = regs
                        .rip
                        .checked_sub(2)
                        .ok_or("mapped_entry_tool_init_instruction_underflow")?;
                    if !in_code(view, instruction)? || !in_code(view, regs.rip - 1)? {
                        return Err("mapped_entry_tool_init_instruction_not_code".into());
                    }
                    let mut bytes = [0; 2];
                    exact(task, instruction, &mut bytes)?;
                    if !native_syscall_bytes(bytes) {
                        return Err("mapped_entry_tool_init_opcode".into());
                    }
                    // Actual event and interrupted registers, unchanged. The
                    // child validates its ONE frontend and real kernel frame
                    // only AFTER this original SIGSYS is delivered.
                    task.setsiginfo_bytes(&info)?;
                    if task.getsiginfo_bytes()? != info
                        || super::super::register_words(&task.getregs()?)
                            != super::super::register_words(&regs)
                    {
                        return Err("mapped_entry_siginfo_or_regs_changed".into());
                    }
                    if self.entry.recent_tool_syscalls.len() == 64 {
                        self.entry.recent_tool_syscalls.pop_front();
                    }
                    self.entry.recent_tool_syscalls.push_back([
                        regs.rip, regs.rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8,
                        regs.r9,
                    ]);
                    self.entry.forwarded_tool_init = self
                        .entry
                        .forwarded_tool_init
                        .checked_add(1)
                        .ok_or("mapped_entry_count_overflow")?;
                    self.resume_entry(Some(Signal::SIGSYS), deadline)?;
                    continue;
                }
            }
            let site = bootstrap_site(view, &info, &regs)?;
            // Exact current phase1 prefix is a necessary check, NOT ToolInit
            // publication authority. All phase2 deliveries remain refused.
            let mut control = [0; 384];
            exact(
                task,
                view.scalar(1)
                    .map_err(|e| format!("mapped_entry_control: {e:?}"))?,
                &mut control,
            )?;
            if !bootstrap_control(
                &control,
                self.context.regs().fs_base,
                view.scalar(0)
                    .map_err(|e| format!("mapped_entry_tid: {e:?}"))?,
            ) || !bootstrap_delivery_mask(task.getsigmask()?)
                || regs.gs_base != self.context.regs().gs_base
            {
                return Err("mapped_entry_bootstrap_phase_or_mask".into());
            }
            let tcb = view
                .scalar(8)
                .map_err(|e| format!("mapped_entry_tcb: {e:?}"))?;
            let fs = if site.operation == Operation::SetFs {
                self.context.regs().fs_base
            } else {
                tcb
            };
            if regs.fs_base != fs {
                return Err("mapped_entry_bootstrap_fs".into());
            }
            // Original bytes and original input registers, no simulated syscall,
            // no FS write, no synthesized frame, and NEVER signal suppression.
            task.setsiginfo_bytes(&info)?;
            if task.getsiginfo_bytes()? != info
                || super::super::register_words(&task.getregs()?)
                    != super::super::register_words(&regs)
            {
                return Err("mapped_entry_siginfo_or_regs_changed".into());
            }
            self.entry.forwarded = self
                .entry
                .forwarded
                .checked_add(1)
                .ok_or("mapped_entry_count_overflow")?;
            self.resume_entry(Some(Signal::SIGSYS), deadline)?;
        }
    }

    fn verify_tool_init_stop(
        &self,
        task: &safeptrace::Stopped,
        view: View<'_>,
        regs: &Regs,
        reserved_signals: u64,
        ready: u64,
    ) -> Result<()> {
        let stack = super::interior(
            view.role(0)
                .map_err(|e| format!("mapped_entry_tool_init_stack: {e:?}"))?,
        )?;
        let expected = ToolInitExpected {
            original_fs: self.context.regs().fs_base,
            original_rsp: self.context.regs().rsp,
            tool_fs: view
                .scalar(8)
                .map_err(|e| format!("mapped_entry_tcb: {e:?}"))?,
            tid: view
                .scalar(0)
                .map_err(|e| format!("mapped_entry_tid: {e:?}"))?,
            handler: view
                .scalar(9)
                .map_err(|e| format!("mapped_entry_handler: {e:?}"))?,
            input_fd: view
                .scalar(5)
                .map_err(|e| format!("mapped_entry_input_fd: {e:?}"))?,
            stack_start: stack.start,
            stack_end: stack.end,
        };
        let control = read_control(task, view)?;
        let mask = task.getsigmask()?;
        // ready=1 is checked only after the exact kernel INT3 return event.
        // Linux forcibly unblocks that synchronous SIGTRAP before this stop.
        let mask_matches = if ready == 1 {
            tool_init_terminal_mask(mask, reserved_signals)
        } else {
            tool_init_delivery_mask(mask, reserved_signals)
        };
        if !tool_init_control(&control, expected, ready)
            || regs.fs_base != expected.tool_fs
            || regs.gs_base != self.context.regs().gs_base
            || !(stack.start <= regs.rsp && regs.rsp < stack.end)
            || !mask_matches
        {
            return Err(format!(
                "mapped_entry_tool_init_state_or_mask: control={:#x?}; expected={expected:#x?}; ready={ready}; actual_mask={mask:#x}; reserved={reserved_signals:#x}",
                (0..48).map(|i| control_word(&control, i)).collect::<Vec<_>>()
            ).into());
        }
        Ok(())
    }

    fn check_entry_generation(&self, task: &safeptrace::Stopped) -> Result<()> {
        if task.generation() != self.owner.generation {
            return Err("mapped_entry_foreign_generation".into());
        }
        Ok(())
    }

    fn resume_entry(&mut self, signal: Option<Signal>, deadline: Instant) -> Result<()> {
        self.entry_thread()?;
        if Instant::now() >= deadline {
            return Err("mapped_entry_deadline_before_resume".into());
        }
        let task = self.task.take().ok_or("mapped_entry_missing_resume_stop")?;
        match task.resume_retaining(signal) {
            Ok(running) => {
                self.entry.wait = Some(running.wait_owned_on_ptracer_thread().into_driver());
                self.entry.event = None;
                Ok(())
            }
            Err((task, error)) => {
                self.task = Some(task); // retain BEFORE exposing original errno
                Err(error.into())
            }
        }
    }
}

fn exact(task: &safeptrace::Stopped, address: u64, bytes: &mut [u8]) -> Result<()> {
    let address = usize::try_from(address)?;
    address
        .checked_add(bytes.len())
        .ok_or("mapped_entry_read_overflow")?;
    task.read_exact_with_user_access(
        Addr::from_raw(address).ok_or("mapped_entry_null_read")?,
        bytes,
    )?;
    Ok(())
}
fn in_code(view: View<'_>, address: u64) -> Result<bool> {
    let code = view
        .table(1)
        .map_err(|e| format!("mapped_entry_code: {e:?}"))?;
    for i in 0..code.len() {
        let range = view
            .code(i)
            .map_err(|e| format!("mapped_entry_code: {e:?}"))?;
        if range.start <= address && address < range.end {
            return Ok(true);
        }
    }
    Ok(false)
}
fn i32_at(info: &[u8; 128], offset: usize) -> i32 {
    i32::from_ne_bytes(info[offset..offset + 4].try_into().unwrap())
}
fn u64_at(info: &[u8; 128], offset: usize) -> u64 {
    u64::from_ne_bytes(info[offset..offset + 8].try_into().unwrap())
}
fn bootstrap_site(view: View<'_>, info: &[u8; 128], regs: &Regs) -> Result<Site> {
    if !sigsys_identity(info, regs.rip, regs.rax) {
        return Err("mapped_entry_not_kernel_seccomp_sigsys".into());
    }
    let records = view
        .table(2)
        .map_err(|e| format!("mapped_entry_sites: {e:?}"))?;
    let mut selected = None;
    for i in 0..records.len() {
        let site = view
            .site(i)
            .map_err(|e| format!("mapped_entry_site: {e:?}"))?;
        if site.return_ip == regs.rip && site.number == regs.rax && selected.replace(site).is_some()
        {
            return Err("mapped_entry_ambiguous_bootstrap_site".into());
        }
    }
    selected.ok_or_else(|| "mapped_entry_not_bootstrap_site".into())
}
// Exact frozen runtime startup_mask(), after Linux omits its unmaskable
// SIGKILL/SIGSTOP bits. GNU host cannot call that musl-only private helper.
// This is a coupled scalar observation, NOT normalization or shared code.
const RUNTIME_BOOTSTRAP_MASK: u64 = !((1_u64 << (libc::SIGSYS - 1))
    | (1_u64 << (libc::SIGKILL - 1))
    | (1_u64 << (libc::SIGSTOP - 1)));

fn bootstrap_delivery_mask(observed: u64) -> bool {
    observed == RUNTIME_BOOTSTRAP_MASK
}

// Necessary kernel identity only. A self-consistent x32 number can satisfy
// this predicate; bootstrap_site still requires the exact source-qualified
// four native operation/number pairs decoded by View::site.
fn sigsys_identity(info: &[u8; 128], rip: u64, number: u64) -> bool {
    i32_at(info, 0) == libc::SIGSYS
        && i32_at(info, 4) == 0
        && i32_at(info, 8) == 1
        && i32_at(info, 28) as u32 == 0xc000_003e
        && u64_at(info, 16) == rip
        && i32_at(info, 24) >= 0
        && i32_at(info, 24) as u64 == number
}
fn terminal(info: &[u8; 128], rip: u64, int3: u64) -> bool {
    i32_at(info, 0) == libc::SIGTRAP
        && i32_at(info, 4) == 0
        && i32_at(info, 8) == 128
        && int3.checked_add(1) == Some(rip)
}
fn bootstrap_control(bytes: &[u8; 384], original_fs: u64, tid: u64) -> bool {
    // Existing NativeControl's all-u64 ABI prefix. Exact selected runtime source
    // and target descriptor must bind this layout; these reads mint no authority.
    let word = |i: usize| u64::from_ne_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    word(0) == 1
        && word(1) == 3520
        && word(2) == 1
        && word(3) == original_fs
        && word(9) == 0
        && word(15) == tid
        && word(46) == 1
}

// Necessary native delivery observations only. The actual configured set is
// supplied under the unsafe source/physical contract, never inferred from mask.
fn qualified_reserved_set(reserved: u64) -> bool {
    let syscall = 1_u64 << (libc::SIGSYS - 1);
    reserved == syscall || reserved == (syscall | (1_u64 << (libc::SIGSEGV - 1)))
}
fn tool_init_delivery_mask(observed: u64, reserved: u64) -> bool {
    qualified_reserved_set(reserved)
        && (observed == RUNTIME_BOOTSTRAP_MASK
            || observed
                == !(reserved | (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1))))
}
// This predicate belongs only to the authenticated terminal INT3, after the
// runtime verified its installed mask and published ready=1. It does not admit
// an unblocked SIGTRAP at an ordinary ToolInit syscall-delivery stop.
fn tool_init_terminal_mask(observed: u64, reserved: u64) -> bool {
    qualified_reserved_set(reserved)
        && observed
            == !(reserved
                | (1_u64 << (libc::SIGKILL - 1))
                | (1_u64 << (libc::SIGSTOP - 1))
                | (1_u64 << (libc::SIGTRAP - 1)))
}
fn read_control(task: &safeptrace::Stopped, view: View<'_>) -> Result<[u8; 384]> {
    let mut bytes = [0; 384];
    exact(
        task,
        view.scalar(1)
            .map_err(|e| format!("mapped_entry_control: {e:?}"))?,
        &mut bytes,
    )?;
    Ok(bytes)
}
fn control_word(bytes: &[u8; 384], index: usize) -> u64 {
    u64::from_ne_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
}
#[derive(Clone, Copy, Debug)]
struct ToolInitExpected {
    original_fs: u64,
    original_rsp: u64,
    tool_fs: u64,
    tid: u64,
    handler: u64,
    input_fd: u64,
    stack_start: u64,
    stack_end: u64,
}
fn tool_init_control(bytes: &[u8; 384], expected: ToolInitExpected, ready: u64) -> bool {
    let input = control_word(bytes, 41);
    ready <= 1
        && control_word(bytes, 0) == 1
        && control_word(bytes, 1) == 3520
        && control_word(bytes, 2) == 2
        && control_word(bytes, 3) == expected.original_fs
        && control_word(bytes, 4) == expected.tool_fs
        && control_word(bytes, 5) == expected.original_rsp
        && control_word(bytes, 9) == ready
        && control_word(bytes, 15) == expected.tid
        && control_word(bytes, 19) == expected.stack_start
        && control_word(bytes, 20) == expected.stack_end
        && control_word(bytes, 30) == expected.handler
        && control_word(bytes, 46) == 1
        && (input == u64::MAX || (ready == 0 && input == expected.input_fd))
}
fn native_syscall_bytes(bytes: [u8; 2]) -> bool {
    bytes == [0x0f, 0x05]
}
fn unique_tool_init_post_pc(
    entries: impl IntoIterator<Item = Result<u64>>,
    post: u64,
) -> Result<()> {
    let mut matches = 0usize;
    for entry in entries {
        if entry? == post {
            matches = matches
                .checked_add(1)
                .ok_or("mapped_entry_site_count_overflow")?;
        }
    }
    if matches != 1 {
        return Err("mapped_entry_missing_or_ambiguous_tool_init_site".into());
    }
    Ok(())
}
fn native_tool_sigsys(info: &[u8; 128], rip: u64, number: u64) -> bool {
    number & 0x4000_0000 == 0 && sigsys_identity(info, rip, number)
}
fn tool_init_site(view: View<'_>, info: &[u8; 128], regs: &Regs) -> Result<()> {
    if !native_tool_sigsys(info, regs.rip, regs.rax) {
        return Err("mapped_entry_not_native_tool_init_sigsys".into());
    }
    let records = view
        .table(8)
        .map_err(|e| format!("mapped_entry_tool_init_sites: {e:?}"))?;
    unique_tool_init_post_pc(
        (0..records.len()).map(|i| {
            records
                .field(i, 0)
                .map_err(|e| format!("mapped_entry_tool_init_site: {e:?}").into())
        }),
        regs.rip,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_i32(bytes: &mut [u8; 128], offset: usize, value: i32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    fn put_u64(bytes: &mut [u8; 128], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }

    #[test]
    fn bootstrap_sigsys_identity_requires_kernel_arch_number_and_post_ip() {
        // Data-only classifier control, NOT an actual kernel event positive.
        let mut info = [0; 128];
        put_i32(&mut info, 0, libc::SIGSYS);
        put_i32(&mut info, 8, 1);
        put_i32(&mut info, 24, 158);
        put_i32(&mut info, 28, 0xc000_003e_u32 as i32);
        put_u64(&mut info, 16, 0x1234);
        assert!(sigsys_identity(&info, 0x1234, 158));
        for (offset, value) in [
            (0, libc::SIGTRAP),
            (4, 1),
            (8, 0),
            (8, -6),
            (24, -1),
            (24, 2),
            (28, 0x4000_0003),
        ] {
            let mut bad = info;
            put_i32(&mut bad, offset, value);
            assert!(!sigsys_identity(&bad, 0x1234, 158));
        }
        assert!(!sigsys_identity(&info, 0x1232, 158));
        assert!(!sigsys_identity(&info, 0x1234, 0x4000_009e));
    }

    #[test]
    fn bootstrap_delivery_requires_exact_runtime_mask_not_original_context() {
        // Data-only predicate controls, not an actual SIGSYS delivery.
        assert_eq!(RUNTIME_BOOTSTRAP_MASK, 0xffff_ffff_bffb_feff);
        let original_empty = 0;
        let original_nonempty = 1_u64 << (libc::SIGUSR1 - 1);
        assert!(!bootstrap_delivery_mask(original_empty));
        assert!(!bootstrap_delivery_mask(original_nonempty));
        assert!(bootstrap_delivery_mask(RUNTIME_BOOTSTRAP_MASK));
        for bit in 0..64 {
            assert!(!bootstrap_delivery_mask(
                RUNTIME_BOOTSTRAP_MASK ^ (1_u64 << bit)
            ));
        }
    }

    #[test]
    fn bootstrap_delivery_does_not_normalize_observed_unmaskable_bits() {
        let unmaskable = (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1));
        // The requested all-but-SIGSYS set is not the kernel readback.
        // Only this test models Linux's removal of the two unmaskable bits.
        let requested = !(1_u64 << (libc::SIGSYS - 1));
        assert!(!bootstrap_delivery_mask(requested));
        assert!(bootstrap_delivery_mask(requested & !unmaskable));
        assert!(!bootstrap_delivery_mask(
            RUNTIME_BOOTSTRAP_MASK | (1_u64 << (libc::SIGKILL - 1))
        ));
        assert!(!bootstrap_delivery_mask(
            RUNTIME_BOOTSTRAP_MASK | (1_u64 << (libc::SIGSTOP - 1))
        ));
        assert!(!bootstrap_delivery_mask(
            RUNTIME_BOOTSTRAP_MASK | (1_u64 << (libc::SIGSYS - 1))
        ));
    }

    #[test]
    fn sigsys_identity_alone_is_not_native_site_authorization() {
        let mut info = [0; 128];
        let x32_number = 0x4000_009e;
        put_i32(&mut info, 0, libc::SIGSYS);
        put_i32(&mut info, 8, 1);
        put_i32(&mut info, 24, x32_number);
        put_i32(&mut info, 28, 0xc000_003e_u32 as i32);
        put_u64(&mut info, 16, 0x1234);
        // Matching raw identity is necessary; the unchanged bootstrap_site +
        // exact four native View::site pairs must still reject this number.
        assert!(sigsys_identity(&info, 0x1234, x32_number as u64));
        assert!(!sigsys_identity(&info, 0x1234, 158));
    }

    #[test]
    fn terminal_requires_kernel_int3_post_ip_and_rejects_overflow() {
        let mut info = [0; 128];
        put_i32(&mut info, 0, libc::SIGTRAP);
        put_i32(&mut info, 8, 128);
        assert!(terminal(&info, 0x1235, 0x1234));
        assert!(!terminal(&info, 0x1234, 0x1234));
        assert!(!terminal(&info, 0, u64::MAX));
        for (offset, value) in [(0, libc::SIGSYS), (4, 1), (8, 0), (8, 1), (8, -6)] {
            let mut bad = info;
            put_i32(&mut bad, offset, value);
            assert!(!terminal(&bad, 0x1235, 0x1234));
        }
    }

    #[test]
    fn bootstrap_control_rejects_tool_init_and_wrong_capture_identity() {
        let mut bytes = [0; 384];
        let word = |bytes: &mut [u8; 384], index: usize, value: u64| {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_ne_bytes());
        };
        for (index, value) in [(0, 1), (1, 3520), (2, 1), (3, 0x7770), (15, 55), (46, 1)] {
            word(&mut bytes, index, value);
        }
        assert!(bootstrap_control(&bytes, 0x7770, 55));
        for (index, value) in [
            (0, 2),
            (1, 4096),
            (2, 2),
            (2, 4),
            (9, 1),
            (15, 56),
            (46, 0),
            (46, 2),
        ] {
            let mut bad = bytes;
            word(&mut bad, index, value);
            assert!(!bootstrap_control(&bad, 0x7770, 55));
        }
        assert!(!bootstrap_control(&bytes, 0x7780, 55));
        assert!(!bootstrap_control(&bytes, 0x7770, 56));
    }

    fn tool_control_fixture() -> ([u8; 384], ToolInitExpected) {
        let expected = ToolInitExpected {
            original_fs: 0x7770,
            original_rsp: 0x8800,
            tool_fs: 0x9900,
            tid: 55,
            handler: 0xaa00,
            input_fd: 207,
            stack_start: 0xbb00,
            stack_end: 0xcc00,
        };
        let mut bytes = [0; 384];
        for (index, value) in [
            (0, 1),
            (1, 3520),
            (2, 2),
            (3, expected.original_fs),
            (4, expected.tool_fs),
            (5, expected.original_rsp),
            (9, 0),
            (15, expected.tid),
            (19, expected.stack_start),
            (20, expected.stack_end),
            (30, expected.handler),
            (41, expected.input_fd),
            (46, 1),
        ] {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_ne_bytes());
        }
        (bytes, expected)
    }
    fn control_put(bytes: &mut [u8; 384], index: usize, value: u64) {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_ne_bytes());
    }

    #[test]
    fn tool_init_domain_is_explicit_and_defaults_to_bootstrap_only() {
        assert_eq!(
            ObservationDomain::default(),
            ObservationDomain::BootstrapOnly
        );
        // Numeric construction is not source, child or execution authority.
        assert_ne!(
            ObservationDomain::ToolInitialization {
                reserved_signals: 1 << (libc::SIGSYS - 1),
            },
            ObservationDomain::default()
        );
        let (bytes, _) = tool_control_fixture();
        assert!(!bootstrap_control(&bytes, 0x7770, 55));
    }

    #[test]
    fn tool_init_control_requires_exact_phase_tls_birth_stack_and_handler() {
        let (bytes, expected) = tool_control_fixture();
        assert!(tool_init_control(&bytes, expected, 0));
        for index in [0, 1, 2, 3, 4, 5, 9, 15, 19, 20, 30, 46] {
            let mut bad = bytes;
            control_put(&mut bad, index, control_word(&bytes, index) ^ 1);
            assert!(!tool_init_control(&bad, expected, 0), "word {index}");
        }
        for phase in [0, 1, 3, 4, 6] {
            let mut bad = bytes;
            control_put(&mut bad, 2, phase);
            assert!(!tool_init_control(&bad, expected, 0));
        }
    }

    #[test]
    fn tool_init_input_retirement_is_once_and_required_at_return() {
        let (mut bytes, expected) = tool_control_fixture();
        assert!(tool_init_control(&bytes, expected, 0));
        control_put(&mut bytes, 41, u64::MAX - 1); // actual retiring sentinel
        assert!(!tool_init_control(&bytes, expected, 0));
        control_put(&mut bytes, 41, 208);
        assert!(!tool_init_control(&bytes, expected, 0));
        control_put(&mut bytes, 41, u64::MAX);
        assert!(tool_init_control(&bytes, expected, 0));
        assert!(!tool_init_control(&bytes, expected, 1));
        control_put(&mut bytes, 9, 1);
        assert!(tool_init_control(&bytes, expected, 1));
        assert!(!tool_init_control(&bytes, expected, 0));
        assert!(!tool_init_control(&bytes, expected, 2));
        control_put(&mut bytes, 41, expected.input_fd);
        assert!(!tool_init_control(&bytes, expected, 1));
    }

    #[test]
    fn terminal_int3_has_one_exact_mask_distinct_from_syscall_delivery() {
        let sys = 1_u64 << (libc::SIGSYS - 1);
        let segv = 1_u64 << (libc::SIGSEGV - 1);
        for reserved in [sys, sys | segv] {
            let installed =
                !(reserved | (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
            let terminal = installed & !(1_u64 << (libc::SIGTRAP - 1));
            assert!(tool_init_terminal_mask(terminal, reserved));
            assert!(!tool_init_terminal_mask(installed, reserved));
            assert!(!tool_init_delivery_mask(terminal, reserved));
            for bit in 0..64 {
                assert!(!tool_init_terminal_mask(
                    terminal ^ (1_u64 << bit),
                    reserved
                ));
            }
        }
        assert_eq!(
            !(sys | segv | 0x100 | 0x40000 | 0x10),
            0xffff_ffff_bffb_faef
        );
        for reserved in [0, segv, sys | (1_u64 << (libc::SIGUSR1 - 1))] {
            assert!(!tool_init_terminal_mask(0xffff_ffff_bffb_faef, reserved));
        }
    }

    #[test]
    fn tool_init_mask_uses_declared_actual_reserved_set_without_mode_guess() {
        let sys = 1_u64 << (libc::SIGSYS - 1);
        let instruction = 1_u64 << (libc::SIGSEGV - 1);
        let ordinary = RUNTIME_BOOTSTRAP_MASK & !instruction;
        assert!(tool_init_delivery_mask(RUNTIME_BOOTSTRAP_MASK, sys));
        assert!(!tool_init_delivery_mask(ordinary, sys));
        assert!(tool_init_delivery_mask(
            RUNTIME_BOOTSTRAP_MASK,
            sys | instruction
        ));
        assert!(tool_init_delivery_mask(ordinary, sys | instruction));
        for reserved in [0, instruction, sys | (1 << (libc::SIGUSR1 - 1)), u64::MAX] {
            assert!(!qualified_reserved_set(reserved));
            assert!(!tool_init_delivery_mask(RUNTIME_BOOTSTRAP_MASK, reserved));
        }
        for bit in 0..64 {
            if bit != libc::SIGSEGV - 1 {
                assert!(!tool_init_delivery_mask(
                    RUNTIME_BOOTSTRAP_MASK ^ (1 << bit),
                    sys | instruction
                ));
            }
        }
        // These necessary observations do not construct/select InstalledFacts.
    }

    #[test]
    fn tool_init_native_identity_rejects_matching_x32_and_non_kernel_events() {
        let mut info = [0; 128];
        put_i32(&mut info, 0, libc::SIGSYS);
        put_i32(&mut info, 8, 1);
        put_i32(&mut info, 24, libc::SYS_connect as i32);
        put_i32(&mut info, 28, 0xc000_003e_u32 as i32);
        put_u64(&mut info, 16, 0x1234);
        assert!(native_tool_sigsys(&info, 0x1234, libc::SYS_connect as u64));
        let x32 = 0x4000_0000 | libc::SYS_connect as u64;
        put_i32(&mut info, 24, x32 as i32);
        assert!(sigsys_identity(&info, 0x1234, x32));
        assert!(!native_tool_sigsys(&info, 0x1234, x32));
        put_i32(&mut info, 24, libc::SYS_connect as i32);
        for (offset, value) in [(0, libc::SIGTRAP), (4, 1), (8, -6), (28, 0x4000_0003)] {
            let mut bad = info;
            put_i32(&mut bad, offset, value);
            assert!(!native_tool_sigsys(&bad, 0x1234, libc::SYS_connect as u64));
        }
    }

    #[test]
    fn tool_init_post_pc_must_be_unique_and_keeps_record_errors() {
        assert!(unique_tool_init_post_pc([Ok(0x100), Ok(0x200)], 0x200).is_ok());
        assert_eq!(
            unique_tool_init_post_pc([Ok(0x100), Ok(0x100)], 0x100)
                .unwrap_err()
                .to_string(),
            "mapped_entry_missing_or_ambiguous_tool_init_site"
        );
        assert!(unique_tool_init_post_pc([], 0x100).is_err());
        assert!(unique_tool_init_post_pc([Ok(0x100)], 0x102).is_err());
        assert_eq!(
            unique_tool_init_post_pc([Ok(0x100), Err("actual-record-error".into())], 0x100)
                .unwrap_err()
                .to_string(),
            "actual-record-error"
        );
    }

    #[test]
    fn tool_init_requires_both_actual_syscall_bytes() {
        assert!(native_syscall_bytes([0x0f, 0x05]));
        for wrong in [
            [0x0f, 0x34],
            [0xcd, 0x80],
            [0x05, 0x0f],
            [0x0f, 0x0b],
            [0, 0],
        ] {
            assert!(!native_syscall_bytes(wrong));
        }
    }

    #[test]
    fn retained_attempt_cannot_replay_after_cancellation_boundary() {
        // Actual production begin_attempt transition; data-only state control.
        // This does NOT claim that a kernel wait/reap was exercised.
        let mut entry = RetainedEntry::default();
        entry
            .begin_attempt(Instant::now() + std::time::Duration::from_secs(1))
            .unwrap();
        assert!(entry.attempted);
        assert_eq!(
            entry
                .begin_attempt(Instant::now() + std::time::Duration::from_secs(1))
                .unwrap_err()
                .to_string(),
            "mapped_entry_attempt_spent_or_expired"
        );
        assert!(entry.attempted);
        assert!(entry.wait.is_none() && entry.event.is_none() && entry.terminal.is_none());
    }

    #[test]
    fn retained_attempt_failure_and_deadline_never_create_a_wait_owner() {
        let mut entry = RetainedEntry::default();
        assert!(entry.begin_attempt(Instant::now()).is_err());
        assert!(!entry.attempted);
        entry.failed = true;
        assert!(
            entry
                .begin_attempt(Instant::now() + std::time::Duration::from_secs(1))
                .is_err()
        );
        assert!(entry.wait.is_none() && entry.event.is_none() && entry.terminal.is_none());
    }
}
