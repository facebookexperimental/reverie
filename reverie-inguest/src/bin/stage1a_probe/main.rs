/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Opt-in first-image mechanics probe. This does not initialize Detcore or
//! activate any product backend. Its minimal runtime is an independent test
//! artifact; the safe no_std loader library remains the image authority.

#![deny(unsafe_code)]

mod control;
#[cfg(feature = "loader-private-runtime")]
mod mapped_preparation;
#[path = "../../../tests/fixtures/probe_protocol.rs"]
mod protocol;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use images::Kind;
use images::SealedImage;
use protocol::*;
use reverie_inguest::launcher::exec_stop::ChildOwner;
use reverie_inguest::launcher::exec_stop::CleanupConfirmation;
use reverie_inguest::launcher::exec_stop::CleanupOwner;
use reverie_inguest::launcher::exec_stop::CleanupReceipt;
use reverie_inguest::launcher::exec_stop::CleanupState;
use reverie_inguest::launcher::exec_stop::EntryContext;
use reverie_inguest::launcher::exec_stop::ExecStop;
use reverie_inguest::launcher::exec_stop::PreparedExec;
use reverie_inguest::launcher::exec_stop::images;
use reverie_inguest::launcher::exec_stop::inject as trace;
use reverie_inguest::launcher::exec_stop::register_words;
use reverie_loader::artifact;
use reverie_loader::manifest::COUNTER_RUNTIME_MANIFEST;
use reverie_loader::manifest::Controls;
use reverie_loader::manifest::ToolManifest;
use reverie_loader::stage::Armed;
use reverie_loader::stage::Mapped;
use reverie_loader::stage::ToolReady;
use safeptrace::Event;
use safeptrace::ExitStatus;
use safeptrace::Regs;
use safeptrace::Signal;
use safeptrace::Stopped;
use safeptrace::SyscallInfoOp;
use serde_json::Value;
use serde_json::json;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type CleanupReport = CleanupReceipt;
const REFUSAL_EXIT: i32 = 122;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    CpuidArmEnosys,
}

/// Which test runtime image this run arms. One host serves both: the
/// kind selects the image manifest (through [`Kind`]), the required
/// control word written into the control page, and the ready
/// evidence demanded. The protocol control word is the test-ABI
/// expression of the kind's manifest controls plus the mechanics
/// bits (alternate stack, closed descriptors, self-test probes) that
/// have no manifest counterpart and are mapped by [`armed_controls`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum RuntimeKind {
    /// The mechanics probe runtime: every control, canary self-tests.
    Probe,
    /// The counting runtime: trap filter and SIGSYS handler only.
    Counter,
}

impl RuntimeKind {
    fn image_kind(self) -> Kind {
        match self {
            RuntimeKind::Probe => Kind::Runtime,
            RuntimeKind::Counter => Kind::Custom(&COUNTER_RUNTIME_MANIFEST),
        }
    }

    /// The protocol bits with no manifest counterpart (alternate
    /// stack, closed descriptors, self-test probes) for this kind.
    fn mechanics_controls(self) -> u64 {
        match self {
            RuntimeKind::Probe => {
                CONTROL_ALTSTACK
                    | CONTROL_FDS_CLOSED
                    | CONTROL_CPUID_PROBE
                    | CONTROL_TSC_PROBE
                    | CONTROL_SYSCALL_PROBE
            }
            RuntimeKind::Counter => {
                CONTROL_ALTSTACK | CONTROL_FDS_CLOSED | CONTROL_SYSCALL_PROBE
            }
        }
    }

    /// The required protocol control word, derived from this kind's
    /// manifest controls plus its mechanics bits — never a second
    /// hard-coded table that could drift from the manifest. The
    /// checked-in manifests derive exactly `REQUIRED_CONTROLS` /
    /// `COUNTER_REQUIRED_CONTROLS`, which the fixture images are
    /// built against; the unit tests pin that agreement.
    fn required_controls(self) -> u64 {
        protocol_controls_for(
            self.image_kind().manifest().controls,
            self.mechanics_controls(),
        )
    }

    fn ready_evidence(self) -> control::ReadyEvidence {
        match self {
            RuntimeKind::Probe => control::ReadyEvidence::InstructionProbes,
            RuntimeKind::Counter => control::ReadyEvidence::SyscallTrapOnly,
        }
    }

    fn name(self) -> &'static str {
        match self {
            RuntimeKind::Probe => "probe",
            RuntimeKind::Counter => "counter",
        }
    }
}

struct ProbeControls<'a> {
    fault: Fault,
    pause_checkpoint: Option<&'a Path>,
    runtime_kind: RuntimeKind,
    /// Link-time virtual address of a guest witness slot: an
    /// eight-byte cell the guest's first instruction (or its first
    /// constructor) overwrites. The host resolves it through the
    /// image load bias and reads it at the exec-drain stop and again
    /// at the ready stop; an untouched value at both proves zero
    /// guest instructions ran before arming, independently of the
    /// journal.
    witness: Option<u64>,
}

/// The stopped-task bundle the loader's stage chain carries from
/// mapping to handover: the task itself, its saved entry context and
/// the child owner that waits for it after detach. `task` is an
/// `Option` only so [`bootstrap_until_ready`], which consumes and
/// returns the stop, can run it through [`ProbeStop::run_task`]; it is
/// `Some` at every stage boundary.
struct ProbeStop<'fd> {
    task: Option<Stopped>,
    context: EntryContext,
    owner: ChildOwner<'fd>,
}

impl ProbeStop<'_> {
    fn task(&self) -> &Stopped {
        self.task.as_ref().expect("probe stop retains its task")
    }

    fn task_mut(&mut self) -> &mut Stopped {
        self.task.as_mut().expect("probe stop retains its task")
    }

    fn run_task<T>(&mut self, run: impl FnOnce(Stopped) -> Result<(Stopped, T)>) -> Result<T> {
        let task = self.task.take().expect("probe stop retains its task");
        let (task, value) = run(task)?;
        self.task = Some(task);
        Ok(value)
    }
}

/// Maps the probe runtime's reported control word (probe_protocol
/// `CONTROL_*` bits) onto the manifest's [`Controls`]. The probe has
/// no vDSO-rewrite bit — its runtime performs no vDSO rewrite — so
/// `vdso_rewrite` is always false here, which is exactly why the
/// probe is checked against the separate probe manifest that does
/// not require it. Probe-only bits (altstack, fds-closed and the
/// self-test probes) have no manifest counterpart and are enforced
/// by `control::ready` instead.
fn armed_controls(controls: u64) -> Controls {
    Controls {
        trap_filter: controls & CONTROL_FILTER != 0,
        cpuid_faulting: controls & CONTROL_CPUID != 0,
        rdtsc_trapping: controls & CONTROL_TSC != 0,
        vdso_rewrite: false,
        sigsys_handler: controls & CONTROL_SIGSYS != 0,
        sigsegv_handler: controls & CONTROL_SIGSEGV != 0,
    }
}

/// The inverse of [`armed_controls`]: the protocol word a manifest's
/// controls require, plus `mechanics` bits with no manifest
/// counterpart. There is no vDSO-rewrite protocol bit, so a manifest
/// requiring it can never be reported armed on this lane and is
/// refused by name at [`claim_armed`] — never silently dropped.
fn protocol_controls_for(controls: Controls, mechanics: u64) -> u64 {
    let mut word = mechanics;
    if controls.trap_filter {
        word |= CONTROL_FILTER;
    }
    if controls.cpuid_faulting {
        word |= CONTROL_CPUID;
    }
    if controls.rdtsc_trapping {
        word |= CONTROL_TSC;
    }
    if controls.sigsys_handler {
        word |= CONTROL_SIGSYS;
    }
    if controls.sigsegv_handler {
        word |= CONTROL_SIGSEGV;
    }
    word
}

/// The entry this launcher will launch for `manifest`, or a named
/// refusal. This launcher only ever enters an image at its own
/// entry point, so it reads `manifest.init` and refuses any
/// contract other than `ImageEntry` by name, before anything is
/// spawned or mapped — a `Custom` manifest declaring `Address(x)`
/// or `None` is never run as if it said `ImageEntry`.
fn launcher_entry_for(manifest: &ToolManifest, image_entry: u64) -> Result<u64> {
    manifest.require_image_entry_init().map_err(|refusal| {
        format!("loader refused: unsupported init contract: {refusal:?}")
    })?;
    manifest
        .check_init_entry(image_entry, Some(image_entry))
        .map_err(|refusal| format!("loader refused: init entry mismatch: {refusal:?}"))?;
    Ok(image_entry)
}

/// Refuses by name on any host page size this x86-64/4 KiB loader
/// contract does not support. The size is an input so the refused
/// case is testable without a 64 KiB-page host.
fn refuse_unsupported_page_size(manifest: &ToolManifest, page_size: u64) -> Result<()> {
    manifest.validate_with_page_size(page_size).map_err(|error| {
        format!("loader refused: unsupported host page size {page_size}: {error:?}").into()
    })
}

/// The host page size, from the auxiliary vector (not `sysconf`).
fn host_page_size() -> Result<u64> {
    reverie_inguest::guest::support::page_size()
        .map_err(|error| format!("loader refused: host page size unavailable: {error}").into())
}

/// Claims the `Armed` stage from the reported protocol word: the
/// loader's single armed-transition call site. The evidence is
/// the word mapped through [`armed_controls`]; the stage
/// transition itself performs the manifest `unmet` check and this
/// helper names any unmet control as a total refusal.
fn claim_armed<S>(ready: ToolReady<S>, manifest: &ToolManifest, controls: u64) -> Result<Armed<S>> {
    ready
        .armed(manifest.controls, armed_controls(controls))
        .map_err(|(_stage, unmet)| {
            format!("loader refused: required control not armed: {unmet:?} (controls={controls:#x})")
                .into()
        })
}

fn run(
    loader: &SealedImage,
    runtime: &SealedImage,
    observations: &File,
    arguments: &[std::ffi::OsString],
    controls: ProbeControls<'_>,
    cleanup_evidence: CleanupReport,
    report: &mut Value,
) -> Result<()> {
    let ProbeControls {
        fault,
        pause_checkpoint,
        runtime_kind,
        witness,
    } = controls;
    report["runtime_kind"] = json!(runtime_kind.name());
    let loader_image = loader.checked()?;
    let runtime_image = runtime.checked()?;
    // Refuse before spawning anything: this x86-64 loader contract
    // is 4 KiB-page only, and this launcher only honours
    // ImageEntry init. Both manifests are read here; the entries
    // below are the only entries this run will launch.
    let host_page_size = host_page_size()?;
    refuse_unsupported_page_size(loader.kind().manifest(), host_page_size)?;
    refuse_unsupported_page_size(runtime.kind().manifest(), host_page_size)?;
    let loader_entry = launcher_entry_for(loader.kind().manifest(), loader_image.entry())?;
    let runtime_entry = launcher_entry_for(runtime.kind().manifest(), runtime_image.entry())?;
    let inherited = [loader.fd(), runtime.fd(), observations.as_raw_fd()];
    let environment: Vec<_> = std::env::vars_os().collect();
    let launch = PreparedExec::new(
        Path::new(arguments.first().ok_or("missing guest program")?),
        arguments,
        &environment,
        None,
        vec![loader.as_fd(), runtime.as_fd(), observations.as_fd()],
    )?;
    let stopped = match ExecStop::spawn(launch, cleanup_evidence.clone()) {
        Ok(stopped) => stopped,
        Err(mut failure) => {
            // A failed explicit cleanup keeps the original owner for retry.
            // The outer physical runner must reject an unconfirmed receipt.
            failure.retry_cleanup();
            return Err(failure.to_string().into());
        }
    };
    let (task, context, boundary, owner) = stopped.into_parts();
    let pid = task.pid();
    let entry = *context.regs();
    let at_event = boundary.event_regs;
    report["exec_event"] = json!({
        "event":"exec", "pid":pid.as_raw(), "former_tid":boundary.former_tid.as_raw(),
        "ip":at_event.rip, "sp":at_event.rsp, "rax":at_event.rax, "orig_rax":at_event.orig_rax,
        "syscall_info":syscall_info_json(&boundary.event_info),
    });
    report["exec_exit"] = json!({
        "event":"syscall", "pid":pid.as_raw(), "ip":entry.rip, "sp":entry.rsp,
        "rax":entry.rax, "orig_rax":entry.orig_rax,
        "syscall_info":syscall_info_json(&boundary.exit_info),
    });
    report["entry_ip"] = json!(entry.rip);
    report["entry_sp"] = json!(entry.rsp);
    report["entry_rax"] = json!(entry.rax);
    report["exec_return_drained"] = json!(true);
    // The task is stopped with no guest instruction run since the
    // exec stop: resolve and read the witness slot now, and again at
    // the ready stop below.
    let witness_address = match witness {
        Some(link_vaddr) => {
            let address = resolve_witness(&task, entry.rsp, link_vaddr)?;
            report["witness_address"] = json!(address);
            report["witness_at_exec_drain"] = json!(read_witness(&task, address)?);
            Some(address)
        }
        None => None,
    };
    if let Some(path) = pause_checkpoint {
        return pause_after_exec_drain(task, entry, path, report);
    }
    let mask = context.signal_mask();
    let reserved = (1_u64 << (libc::SIGSYS - 1)) | (1_u64 << (libc::SIGSEGV - 1));
    if mask & reserved != 0 {
        return Err("loader refused: first-image test domain has blocked SIGSYS or SIGSEGV".into());
    }
    task.setsigmask(u64::MAX)?;
    let nonce = control::initialize(
        observations,
        &entry,
        mask,
        runtime_entry,
        &inherited,
        runtime_kind.required_controls(),
    )?;
    let mut injector = trace::Injector::new(task)?;
    let mapped = (|| -> Result<()> {
        injector.reserve()?;
        injector.map_image(loader)?;
        injector.map_image(runtime)?;
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        injector.map_storage(
            CONTROL_ADDRESS,
            CONTROL_BYTES as u64,
            rw,
            libc::MAP_SHARED,
            Some(observations.as_fd()),
            0,
        )?;
        injector.map_storage(
            JOURNAL_ADDRESS,
            JOURNAL_BYTES,
            rw,
            libc::MAP_SHARED,
            Some(observations.as_fd()),
            CONTROL_BYTES as u64,
        )?;
        for (bottom, top) in [(STACK_BOTTOM, STACK_TOP), (ALTSTACK_BOTTOM, ALTSTACK_TOP)] {
            injector.map_storage(
                bottom,
                top - bottom,
                rw,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                None,
                0,
            )?;
        }
        Ok(())
    })();
    report["injected_syscalls"] = json!(
        injector
            .calls
            .iter()
            .map(|(number, args, result)| json!({"number":number,"args":args,"result":result}))
            .collect::<Vec<_>>()
    );
    mapped?;
    let (task, injections) = injector.finish()?;
    report["injected_syscalls"] = json!(
        injections
            .iter()
            .map(|(number, args, result)| json!({"number":number,"args":args,"result":result}))
            .collect::<Vec<_>>()
    );
    report["entry_bytes_restored"] = json!(true);
    // The images are mapped at their fixed addresses and no guest
    // instruction has run since the exec stop: the stop enters the
    // loader's stage chain (Mapped::from_mapped_stop's trust
    // boundary) and is touched only through it until handover.
    let bundle = ProbeStop {
        task: Some(task),
        context,
        owner,
    };
    let mut mapped = Mapped::from_mapped_stop(bundle);
    let mut bootstrap = entry;
    bootstrap.rip = loader_entry;
    bootstrap.rsp = STACK_TOP - 8; // SysV function entry, private zero return slot.
    bootstrap.rdi = CONTROL_ADDRESS;
    bootstrap.orig_rax = u64::MAX;
    mapped.stop_mut().task_mut().setregs(&bootstrap)?;
    let executable: Vec<_> = loader_image
        .segments()
        .chain(runtime_image.segments())
        .filter(|s| s.permissions.execute)
        .map(|s| s.pages())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| format!("executable segment: {e:?}"))?;
    mapped.stop_mut().run_task(|task| {
        bootstrap_until_ready(task, &executable, fault, &mut *report).map(|task| (task, ()))
    })?;
    let started = mapped.runtime_started();
    let ready_regs = started.stop().task().getregs()?;
    // Retain the actual unauthenticated observation on refusal as well.
    report["ready_stop_ip"] = json!(ready_regs.rip);
    report["ready_rax"] = json!(ready_regs.rax);
    if ready_regs.rip != READY_STOP_IP || ready_regs.rax != READY_MAGIC {
        return Err("loader refused: unauthenticated ready breakpoint".into());
    }
    let controls = control::ready(
        observations,
        nonce,
        runtime_kind.required_controls(),
        runtime_kind.ready_evidence(),
    )?;
    // Still stopped at the ready marker, guest not yet released: the
    // second witness read. Equal, untouched values at both stops
    // prove zero guest instructions ran across the arming window.
    if let Some(address) = witness_address {
        report["witness_at_ready"] = json!(read_witness(started.stop().task(), address)?);
    }
    // ToolReady is claimed only with init evidence: the runtime
    // manifest, its image entry, and the entry actually launched
    // above. A mismatch is a named refusal, never a silent pass.
    let ready = match started.tool_ready(
        runtime.kind().manifest(),
        runtime_image.entry(),
        Some(runtime_entry),
    ) {
        Ok(ready) => ready,
        Err((_stage, refusal)) => {
            return Err(format!("loader refused: init entry mismatch: {refusal:?}").into());
        }
    };
    for fd in inherited {
        match std::fs::symlink_metadata(format!("/proc/{pid}/fd/{fd}")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            other => {
                return Err(
                    format!("loader refused: bootstrap fd {fd} was not closed: {other:?}").into(),
                );
            }
        }
    }
    // Armed is claimed only once every control the running runtime's
    // manifest requires is reported armed; an unmet control is a
    // named refusal at this single call site, never a partially
    // armed handoff.
    let armed = claim_armed(ready, runtime.kind().manifest(), controls)?;
    {
        let stop = armed.stop();
        stop.context.restore(stop.task())?;
    }
    report["controls"] = json!(controls);
    report["ready_stop_ip"] = json!(ready_regs.rip);
    report["ready_nonce_matches"] = json!(true);
    report["stack_unchanged"] = json!(true);
    report["stack_bytes"] = json!(armed.stop().context.stack_bytes().len());
    report["bootstrap_fds_closed"] = json!(true);
    // Measured from the committed journal rows at this ready stop, not
    // asserted: `control::ready` already refused a nonzero count, and
    // this reports what the journal actually holds before handover.
    report["pre_arm_guest_syscalls"] = json!(control::pre_arm_guest_events(observations)?);
    let (_handed_off, bundle) = armed.hand_over();
    let ProbeStop { task, owner, .. } = bundle;
    let running = task
        .ok_or("loader refused: probe stop lost its task")?
        .detach(None)?;
    report["detached"] = json!(true);
    report["outcome"] = json!("handoff");
    let terminal = match owner.wait(running) {
        Ok(status) => status,
        Err(mut failure) => {
            failure.retry_cleanup();
            return Err(failure.to_string().into());
        }
    };
    match terminal {
        ExitStatus::Exited(code) => report["guest_status"] = json!(code),
        ExitStatus::Signaled(signal, _) => report["guest_signal"] = json!(signal as i32),
        ExitStatus::SignaledRaw(signal, _) => report["guest_signal"] = json!(signal),
    }

    Ok(())
}

/// Reads the eight witness bytes at `address` from the stopped guest.
fn read_witness(task: &Stopped, address: u64) -> Result<u64> {
    let bytes = trace::read(task, address, 8)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| "short witness read")?,
    ))
}

/// Resolves a guest link-time virtual address through the image load
/// bias, derived from `AT_PHDR` and the `PT_PHDR` segment read from
/// the stopped guest: bias = AT_PHDR - PT_PHDR.vaddr. That is zero
/// for a fixed-address static image and the PIE load bias for a
/// dynamic one, so one rule serves both witness guests.
fn resolve_witness(task: &Stopped, rsp: u64, link_vaddr: u64) -> Result<u64> {
    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHNUM: u64 = 5;
    const PT_PHDR: u32 = 6;
    const MAX_WORDS: u64 = 4096;
    // The initial stack at rsp is argc, the argv pointers and their
    // NULL, the envp pointers and their NULL, then the auxv pairs.
    // Read word at a time so no read crosses the top of the mapping.
    let word = |index: u64| -> Result<u64> {
        if index > MAX_WORDS {
            return Err("loader refused: initial stack scan bound exceeded".into());
        }
        let address = rsp
            .checked_add(index.checked_mul(8).ok_or("witness stack overflow")?)
            .ok_or("witness stack overflow")?;
        read_witness(task, address)
    };
    let argc = word(0)?;
    if argc > MAX_WORDS {
        return Err("loader refused: implausible guest argc at witness resolution".into());
    }
    let mut index = argc + 2; // past argv[0..argc] and its NULL.
    while word(index)? != 0 {
        index += 1;
    }
    index += 1; // past the envp NULL terminator.
    let (mut phdr, mut phnum) = (None, None);
    loop {
        let (key, value) = (word(index)?, word(index + 1)?);
        index += 2;
        match key {
            AT_NULL => break,
            AT_PHDR => phdr = Some(value),
            AT_PHNUM => phnum = Some(value),
            _ => {}
        }
    }
    let phdr = phdr.ok_or("loader refused: no AT_PHDR for witness resolution")?;
    let phnum = phnum.ok_or("loader refused: no AT_PHNUM for witness resolution")?;
    if !(1..=128).contains(&phnum) {
        return Err("loader refused: implausible AT_PHNUM for witness resolution".into());
    }
    let headers = trace::read(task, phdr, (phnum * 56) as usize)?;
    for header in headers.as_chunks::<56>().0 {
        let p_type = u32::from_le_bytes(header[0..4].try_into().expect("phdr type"));
        if p_type == PT_PHDR {
            let p_vaddr = u64::from_le_bytes(header[16..24].try_into().expect("phdr vaddr"));
            let bias = phdr
                .checked_sub(p_vaddr)
                .ok_or("loader refused: AT_PHDR below PT_PHDR vaddr")?;
            return link_vaddr
                .checked_add(bias)
                .ok_or("loader refused: witness address overflow".into());
        }
    }
    Err("loader refused: guest image has no PT_PHDR for witness resolution".into())
}

fn syscall_info_json(info: &safeptrace::SyscallInfo) -> Value {
    let mut result = json!({
        "architecture":info.architecture,
        "ip":info.instruction_pointer, "sp":info.stack_pointer,
        "kernel_size":info.kernel_size,
    });
    match info.operation {
        SyscallInfoOp::None => result["operation"] = json!("none"),
        SyscallInfoOp::Entry { number, arguments } => {
            result["operation"] = json!("entry");
            result["number"] = json!(number);
            result["args"] = json!(arguments);
        }
        SyscallInfoOp::Exit {
            return_value,
            is_error,
        } => {
            result["operation"] = json!("exit");
            result["return_value"] = json!(return_value);
            result["is_error"] = json!(is_error);
        }
        SyscallInfoOp::Seccomp {
            number,
            arguments,
            ret_data,
        } => {
            result["operation"] = json!("seccomp");
            result["number"] = json!(number);
            result["args"] = json!(arguments);
            result["ret_data"] = json!(ret_data);
        }
    }
    result
}

/// An opt-in EXITKILL observation seam, never a runtime/guest handoff.
fn pause_after_exec_drain(
    task: Stopped,
    entry: Regs,
    checkpoint_path: &Path,
    report: &mut Value,
) -> Result<()> {
    let slot = entry.rsp;
    let end = slot
        .checked_add(8)
        .ok_or("loader refused: stack-slot overflow")?;
    if slot & 7 != 0 {
        return Err("loader refused: unaligned PDEATHSIG test slot".into());
    }
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", task.pid()))?;
    let writable_stack = maps.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let Some(span) = fields.next() else {
            return false;
        };
        let Some(perms) = fields.next() else {
            return false;
        };
        let Some((lo, hi)) = span.split_once('-') else {
            return false;
        };
        let (Ok(lo), Ok(hi)) = (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16)) else {
            return false;
        };
        line.ends_with("[stack]")
            && perms.as_bytes().get(1) == Some(&b'w')
            && lo <= slot
            && end <= hi
    });
    if !writable_stack {
        return Err("loader refused: PDEATHSIG test slot is not in a writable guest stack".into());
    }
    let saved_slot = trace::read(&task, slot, 8)?;
    let saved_entry = trace::read(&task, entry.rip, 8)?;
    let saved_mask = task.getsigmask()?;
    let saved_xstate = task.getxstate()?;
    task.setsigmask(u64::MAX)?;
    let mut injector = trace::Injector::new(task)?;
    let observed = (|| -> Result<Vec<u8>> {
        trace::write(injector.stopped_mut()?, slot, &[0xa5; 8])?;
        if injector.syscall(
            libc::SYS_prctl as u64,
            [libc::PR_SET_PDEATHSIG as u64, 0, 0, 0, 0, 0],
        )? != 0
        {
            return Err("loader refused: PR_SET_PDEATHSIG did not return zero".into());
        }
        if injector.syscall(
            libc::SYS_prctl as u64,
            [libc::PR_GET_PDEATHSIG as u64, slot, 0, 0, 0, 0],
        )? != 0
        {
            return Err("loader refused: PR_GET_PDEATHSIG did not return zero".into());
        }
        let observed = trace::read(injector.stopped()?, slot, 8)?;
        // Linux writes one int. Poison distinguishes an actual zero write
        // from an untouched slot; the upper four bytes must remain untouched.
        if observed != [0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5] {
            return Err("loader refused: actual PDEATHSIG readback was not zero".into());
        }
        Ok(observed)
    })();
    report["pdeathsig_injected_syscalls"] = json!(
        injector
            .calls
            .iter()
            .map(|(number, args, result)| json!({"number":number, "args":args, "result":result}))
            .collect::<Vec<_>>()
    );
    let observed = observed?;
    trace::write(injector.stopped_mut()?, slot, &saved_slot)?;
    let restored_slot = trace::read(injector.stopped()?, slot, 8)?;
    if restored_slot != saved_slot {
        return Err("loader refused: PDEATHSIG test slot did not restore".into());
    }
    let (task, _) = injector.finish()?;
    report["pdeathsig_context_before_restore"] = json!({
        "registers_match": register_words(&task.getregs()?) == register_words(&entry),
        "xstate_matches": task.getxstate()? == saved_xstate,
        "signal_mask_matches": task.getsigmask()? == saved_mask,
    });
    // The injected syscalls have crossed kernel/user boundaries. Restore the
    // complete original context, as on the real handoff path, rather than
    // assuming the kernel's opaque XSTATE image is unchanged by those stops.
    task.setxstate(&saved_xstate)?;
    task.setregs(&entry)?;
    task.setsigmask(saved_mask)?;
    if trace::read(&task, entry.rip, saved_entry.len())? != saved_entry
        || register_words(&task.getregs()?) != register_words(&entry)
        || task.getsigmask()? != saved_mask
        || task.getxstate()? != saved_xstate
    {
        return Err("loader refused: PDEATHSIG test changed the entry context".into());
    }
    let starttime = child_starttime(&task)?;
    let checkpoint = json!({
        "schema":"reverie_loader_exec_stop_checkpoint_v1",
        "mode":"pause_after_exec_drain", "tracer_pid":std::process::id(),
        "child_pid":task.pid().as_raw(), "child_starttime_ticks":starttime,
        "exec_event":report["exec_event"], "exec_exit":report["exec_exit"],
        "exec_return_drained":true, "entry_ip":entry.rip, "entry_sp":entry.rsp,
        "entry_rax":entry.rax, "pdeathsig":0, "pdeathsig_checked":true,
        "pdeathsig_injected_syscalls":report["pdeathsig_injected_syscalls"],
        "context_before_restore":report["pdeathsig_context_before_restore"],
        "stack_slot":{"address":slot, "before":saved_slot,
                      "observed":observed, "restored":restored_slot},
        "entry_bytes_restored":true, "registers_restored":true,
        "sigmask_restored":true, "xstate_restored":true,
        "tracee_held_stopped":true, "controls_armed":false, "detached":false,
    });
    publish_checkpoint(checkpoint_path, &checkpoint)?;
    // Keep the stopped capability alive. No resume/detach path exists here.
    // A lost observer eventually becomes a named refusal and normal cleanup;
    // a passing EXITKILL test must kill the tracer before that deadline.
    let _held_task = task;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("loader refused: tracer-death checkpoint observation timed out".into());
        }
        std::thread::park_timeout(remaining);
    }
}

fn child_starttime(task: &Stopped) -> Result<u64> {
    use std::io::Read;
    let mut stat = String::new();
    File::open(format!("/proc/{}/stat", task.pid()))?
        .take(4097)
        .read_to_string(&mut stat)?;
    if stat.len() > 4096 {
        return Err("loader refused: oversized child stat at checkpoint".into());
    }
    let (prefix, fields) = stat.rsplit_once(") ").ok_or("invalid child stat")?;
    let (pid, _) = prefix.split_once('(').ok_or("invalid child stat PID")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    if pid.trim().parse::<i32>()? != task.pid().as_raw()
        || fields.first() != Some(&"t")
        || fields
            .get(1)
            .ok_or("short child stat parent")?
            .parse::<u32>()?
            != std::process::id()
    {
        return Err("loader refused: checkpoint does not name this stopped child".into());
    }
    Ok(fields
        .get(19)
        .ok_or("short child stat starttime")?
        .parse()?)
}

fn publish_checkpoint(path: &Path, checkpoint: &Value) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut pending = path.as_os_str().to_os_string();
    pending.push(".pending");
    let pending = PathBuf::from(pending);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
    file.write_all(&serde_json::to_vec_pretty(checkpoint)?)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    // Atomic complete-file publication, without replacing an existing path.
    // O_EXCL creation also refuses a preexisting staging file or symlink.
    std::fs::hard_link(&pending, path)?;
    std::fs::remove_file(pending)?;
    Ok(())
}

fn gate(task: &Stopped, ip: u64) -> Result<&'static str> {
    let instruction = ip.checked_sub(2).ok_or("invalid syscall return PC")?;
    let name = if artifact::LOADER_GATE.contains(&instruction) && ip <= artifact::LOADER_GATE.end {
        "loader"
    } else if artifact::RUNTIME_GATE.contains(&instruction) && ip <= artifact::RUNTIME_GATE.end {
        "runtime"
    } else {
        return Err(
            format!("loader refused: pre-arm syscall outside an audited gate at {ip:#x}").into(),
        );
    };
    if trace::read(task, instruction, 2)? != [0x0f, 0x05] {
        return Err("loader refused: observed syscall did not use its audited instruction".into());
    }
    Ok(name)
}

fn bootstrap_until_ready(
    mut task: Stopped,
    executable: &[std::ops::Range<u64>],
    fault: Fault,
    report: &mut Value,
) -> Result<Stopped> {
    let mut pending = None;
    let mut signal = None;
    let mut fault_count = 0;
    report["bootstrap_syscalls"] = json!([]);
    // Retain every completed observation even if a later stop is refused.
    // A partial trace is evidence of failure, never readiness.
    let trace = report["bootstrap_syscalls"]
        .as_array_mut()
        .ok_or("invalid trace record")?;
    for _ in 0..100_000 {
        let (stopped, event) =
            trace::stopped(task.syscall(signal.take())?, "Hermit bootstrap stop")?;
        task = stopped;
        match event {
            Event::Syscall => {
                let info = task.getsyscallinfo()?;
                if info.architecture != AUDIT_ARCH_X86_64 {
                    return Err("loader refused: bootstrap syscall changed ABI".into());
                }
                match info.operation {
                    SyscallInfoOp::Entry { number, arguments } => {
                        if pending.is_some() {
                            return Err("loader refused: duplicate bootstrap syscall entry".into());
                        }
                        let name = gate(&task, info.instruction_pointer)?;
                        // The no_std mechanics runtime has no permission to
                        // change per-thread libc state or start another image.
                        if matches!(
                            number as i64,
                            libc::SYS_execve
                                | libc::SYS_execveat
                                | libc::SYS_clone
                                | libc::SYS_clone3
                                | libc::SYS_fork
                                | libc::SYS_vfork
                                | libc::SYS_set_tid_address
                                | libc::SYS_set_robust_list
                                | libc::SYS_rseq
                        ) {
                            return Err(format!("loader refused: bootstrap attempted unsupported state change {number}").into());
                        }
                        let mut effective_number = number;
                        if fault == Fault::CpuidArmEnosys
                            && number == libc::SYS_arch_prctl as u64
                            && arguments[0] == 0x1012
                            && arguments[1] == 0
                        {
                            if fault_count != 0 {
                                return Err(
                                    "loader refused: CPUID arm retried after the injected refusal"
                                        .into(),
                                );
                            }
                            let mut regs = task.getregs()?;
                            regs.orig_rax = u64::MAX;
                            task.setregs(&regs)?;
                            effective_number = u64::MAX;
                            fault_count += 1;
                        }
                        pending = Some((
                            number,
                            effective_number,
                            arguments,
                            info.instruction_pointer,
                            info.stack_pointer,
                        ));
                        trace.push(json!({"phase":"entry", "ip":info.instruction_pointer, "sp":info.stack_pointer, "number":number, "effective_number":effective_number, "args":arguments, "gate":name}));
                    }
                    SyscallInfoOp::Exit {
                        return_value,
                        is_error,
                    } => {
                        let (number, effective_number, arguments, entry_ip, entry_sp) = pending
                            .take()
                            .ok_or("loader refused: bootstrap exit without entry")?;
                        if effective_number != number
                            && (return_value != -i64::from(libc::ENOSYS) || !is_error)
                        {
                            return Err(
                                "loader refused: injected invalid syscall did not return ENOSYS"
                                    .into(),
                            );
                        }
                        let name = if number == libc::SYS_rt_sigreturn as u64 {
                            if !executable
                                .iter()
                                .any(|r| r.contains(&info.instruction_pointer))
                            {
                                return Err(
                                    "loader refused: bootstrap sigreturn would enter guest code"
                                        .into(),
                                );
                            }
                            "sigreturn-context"
                        } else {
                            if info.instruction_pointer != entry_ip
                                || info.stack_pointer != entry_sp
                            {
                                return Err(
                                    "loader refused: bootstrap syscall changed its return context"
                                        .into(),
                                );
                            }
                            gate(&task, info.instruction_pointer)?
                        };
                        trace.push(json!({"phase":"exit", "ip":info.instruction_pointer, "sp":info.stack_pointer, "number":number,"effective_number":effective_number, "args":arguments, "return_value":return_value,"is_error":is_error,"gate":name}));
                    }
                    other => {
                        return Err(format!(
                            "loader refused: unexpected bootstrap syscall observation {other:?}"
                        )
                        .into());
                    }
                }
            }
            Event::Signal(Signal::SIGTRAP) if task.getregs()?.rip == READY_STOP_IP => {
                if fault != Fault::None {
                    return Err(
                        "loader refused: test runtime reached READY with fault injection requested"
                            .into(),
                    );
                }
                if pending.is_some() {
                    return Err("loader refused: ready marker inside an unfinished syscall".into());
                }
                return Ok(task);
            }
            Event::Signal(sig @ (Signal::SIGSYS | Signal::SIGSEGV)) => {
                let regs = task.getregs()?;
                if !executable.iter().any(|r| r.contains(&regs.rip)) {
                    return Err("loader refused: bootstrap signal would run guest code".into());
                }
                let siginfo = task.getsiginfo_bytes()?;
                // Reinject exactly the same siginfo, not a fabricated raise.
                task.setsiginfo_bytes(&siginfo)?;
                signal = Some(sig);
            }
            other => {
                return Err(format!("loader refused: unexpected bootstrap stop {other:?}").into());
            }
        }
    }
    Err("loader refused: bootstrap stop bound exhausted".into())
}

fn cleanup_json(state: &CleanupState) -> Value {
    let status = state.terminal_status.map(|status| match status {
        ExitStatus::Exited(code) => json!({"kind":"exited", "code":code}),
        ExitStatus::Signaled(signal, core_dumped) => {
            if state.confirmation == Some(CleanupConfirmation::PidfdWaitid) {
                json!({"kind":"signaled", "signal":signal as i32, "core_dumped":core_dumped})
            } else {
                json!({"kind":"signaled", "signal":signal as i32})
            }
        }
        ExitStatus::SignaledRaw(signal, _) => json!({"kind":"signaled", "signal":signal}),
    });
    json!({
        "child_created":state.child_created,
        "owner":match state.owner { CleanupOwner::None=>"none", CleanupOwner::PendingPidfd=>"pending_pidfd", CleanupOwner::Ptracer=>"ptracer" },
        "confirmed":state.confirmed,
        "confirmation":state.confirmation.map(|value| match value {
            CleanupConfirmation::PidfdWaitid=>"pidfd_waitid",
            CleanupConfirmation::SafeptraceTerminalWait=>"safeptrace_terminal_wait",
            CleanupConfirmation::NormalWait=>"normal_wait",
        }),
        "kill_requested":state.kill_requested, "kill_errno":state.kill_errno,
        "wait_error":state.wait_error.map(|error| format!("{error:?}")),
        "terminal_status":status,
    })
}

fn main() {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(feature = "loader-private-runtime")]
    if args
        .first()
        .is_some_and(|arg| arg == "--mapped-preparation-only")
    {
        if let Err(error) = mapped_preparation::run(&args) {
            eprintln!("mapped preparation refused: {error}");
            std::process::exit(REFUSAL_EXIT);
        }
        return;
    }
    let pause_checkpoint = if args
        .first()
        .is_some_and(|a| a == "--pause-after-exec-drain")
    {
        if args.len() < 2 {
            eprintln!("loader refused: missing tracer-death checkpoint path");
            std::process::exit(REFUSAL_EXIT);
        }
        args.remove(0);
        Some(PathBuf::from(args.remove(0)))
    } else {
        None
    };
    let fault = if args
        .first()
        .is_some_and(|a| a == "--inject-cpuid-arm-enosys")
    {
        args.remove(0);
        Fault::CpuidArmEnosys
    } else {
        Fault::None
    };
    let runtime_kind = if args.first().is_some_and(|a| a == "--runtime-kind=counter") {
        args.remove(0);
        RuntimeKind::Counter
    } else {
        RuntimeKind::Probe
    };
    let witness = if args.first().is_some_and(|a| a == "--witness") {
        args.remove(0);
        let text = args
            .first()
            .and_then(|a| a.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                eprintln!("loader refused: missing witness link address");
                std::process::exit(REFUSAL_EXIT);
            });
        args.remove(0);
        let parsed = text
            .strip_prefix("0x")
            .map_or_else(|| text.parse::<u64>(), |hex| u64::from_str_radix(hex, 16));
        Some(parsed.unwrap_or_else(|_| {
            eprintln!("loader refused: invalid witness link address {text:?}");
            std::process::exit(REFUSAL_EXIT);
        }))
    } else {
        None
    };
    if (pause_checkpoint.is_some() && fault != Fault::None)
        || (runtime_kind == RuntimeKind::Counter && fault != Fault::None)
        || args.len() < 5
        || args[3] != "--"
    {
        eprintln!(
            "usage: reverie-loader-stage1a-probe [--inject-cpuid-arm-enosys | --pause-after-exec-drain CHECKPOINT] [--runtime-kind=counter] [--witness LINK_VADDR] LOADER RUNTIME REPORT -- PROGRAM [ARGS...]"
        );
        std::process::exit(REFUSAL_EXIT);
    }
    let report_path = Path::new(&args[2]);
    let mut report = json!({"outcome":"refused", "guest_status":null, "guest_signal":null});
    let cleanup_evidence = CleanupReceipt::default();
    report["fault_requested"] = json!(if fault == Fault::None {
        "none"
    } else {
        "cpuid_arm_enosys"
    });
    let mut observation = None;
    let result = (|| -> Result<()> {
        let loader = SealedImage::read(Path::new(&args[0]), Kind::Loader)?;
        let runtime = SealedImage::read(Path::new(&args[1]), runtime_kind.image_kind())?;
        let file = control::observation_file(CONTROL_BYTES as u64 + JOURNAL_BYTES)?;
        observation = Some(file);
        run(
            &loader,
            &runtime,
            observation.as_ref().ok_or("missing observation file")?,
            &args[4..],
            ProbeControls {
                fault,
                pause_checkpoint: pause_checkpoint.as_deref(),
                runtime_kind,
                witness,
            },
            cleanup_evidence.clone(),
            &mut report,
        )
    })();
    // All child guards have dropped before this snapshot, including errors
    // before safeptrace acquired the freshly created child generation.
    report["cleanup"] = cleanup_json(&cleanup_evidence.snapshot());
    if let Err(error) = &result {
        report["refusal"] = json!(error.to_string());
        eprintln!("{error}");
    }
    if let Some(file) = &observation {
        match control::events(file) {
            Ok((events, status)) => {
                report["runtime"] = status;
                report["guest_events"] = json!(
                    events
                        .iter()
                        .filter(|e| e["flags"].as_u64().unwrap_or(0) & FLAG_GUEST as u64 != 0)
                        .collect::<Vec<_>>()
                );
                report["self_test_events"] = json!(
                    events
                        .iter()
                        .filter(|e| e["flags"].as_u64().unwrap_or(0) & FLAG_SELF_TEST as u64 != 0)
                        .collect::<Vec<_>>()
                );
                for event in &events {
                    if event["kind"] == EVENT_REFUSAL {
                        report["refusal"] = json!(match event["results"][0].as_u64() {
                            Some(REFUSAL_CLONE) => "test_domain_clone",
                            Some(REFUSAL_EXEC) => "test_domain_exec",
                            _ => "test_domain_guest_control",
                        });
                    }
                }
            }
            Err(error) => report["journal_error"] = json!(error.to_string()),
        }
    }
    if let Err(error) = std::fs::write(
        report_path,
        serde_json::to_vec_pretty(&report).expect("JSON value serialization"),
    ) {
        eprintln!("writing probe report failed: {error}");
        std::process::exit(REFUSAL_EXIT);
    }
    let status = if result.is_err() || report.get("journal_error").is_some() {
        REFUSAL_EXIT
    } else if let Some(code) = report["guest_status"].as_i64() {
        code as i32
    } else {
        REFUSAL_EXIT
    };
    std::process::exit(status);
}

#[cfg(test)]
mod tests {
    use super::*;
    use reverie_loader::manifest::InitContract;
    use reverie_loader::manifest::PROBE_RUNTIME_MANIFEST;

    fn dummy_ready() -> ToolReady<u32> {
        Mapped::from_mapped_stop(7_u32)
            .runtime_started()
            .tool_ready(&PROBE_RUNTIME_MANIFEST, 0x1000, Some(0x1000))
            .map_err(|(_stage, refusal)| refusal)
            .expect("probe manifest init at its image entry")
    }

    #[test]
    fn required_controls_are_derived_from_the_manifest() {
        // The derived words agree exactly with the protocol
        // constants the fixture images are built against.
        assert_eq!(RuntimeKind::Probe.required_controls(), REQUIRED_CONTROLS);
        assert_eq!(
            RuntimeKind::Counter.required_controls(),
            COUNTER_REQUIRED_CONTROLS
        );
        // Derivation is from the manifest controls, not a constant:
        // dropping the trap filter drops exactly its protocol bit.
        let mut without_filter = PROBE_RUNTIME_MANIFEST.controls;
        without_filter.trap_filter = false;
        assert_eq!(
            protocol_controls_for(without_filter, RuntimeKind::Probe.mechanics_controls()),
            REQUIRED_CONTROLS & !CONTROL_FILTER
        );
        // Round trip: the derived word arms exactly its manifest.
        assert_eq!(
            armed_controls(RuntimeKind::Probe.required_controls()),
            PROBE_RUNTIME_MANIFEST.controls
        );
        assert_eq!(
            armed_controls(RuntimeKind::Counter.required_controls()),
            COUNTER_RUNTIME_MANIFEST.controls
        );
    }

    #[test]
    fn launcher_refuses_at_the_armed_site_when_a_control_is_unmet() {
        // The refused case at the launcher's single armed-transition
        // call site (`claim_armed` in `run`), not a loader-crate
        // unmet() unit: a word missing the trap-filter bit is a
        // named refusal, and the full derived word arms.
        let missing_filter = RuntimeKind::Probe.required_controls() & !CONTROL_FILTER;
        let error = match claim_armed(dummy_ready(), &PROBE_RUNTIME_MANIFEST, missing_filter) {
            Ok(_) => panic!("unarmed trap filter must refuse"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("required control not armed: TrapFilter"),
            "refusal names the unmet control: {error}"
        );
        let error = match claim_armed(dummy_ready(), &COUNTER_RUNTIME_MANIFEST, 0) {
            Ok(_) => panic!("no armed controls must refuse"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("required control not armed: TrapFilter"),
            "counter refusal names the unmet control: {error}"
        );
        let (_handed_off, stop) = claim_armed(
            dummy_ready(),
            &PROBE_RUNTIME_MANIFEST,
            RuntimeKind::Probe.required_controls(),
        )
        .expect("the derived word arms the probe manifest")
        .hand_over();
        assert_eq!(stop, 7);
    }

    #[test]
    fn launcher_refuses_a_manifest_whose_init_is_not_image_entry() {
        let entry = 0x1000_u64;
        assert_eq!(
            launcher_entry_for(&PROBE_RUNTIME_MANIFEST, entry).ok(),
            Some(entry)
        );
        let mut address = PROBE_RUNTIME_MANIFEST.clone();
        address.init = InitContract::Address(entry);
        let error = launcher_entry_for(&address, entry)
            .err()
            .expect("Address init must refuse on this launcher")
            .to_string();
        assert!(
            error.contains("unsupported init contract") && error.contains("Address"),
            "refusal names the init contract: {error}"
        );
        let mut none = PROBE_RUNTIME_MANIFEST.clone();
        none.init = InitContract::None;
        let error = launcher_entry_for(&none, entry)
            .err()
            .expect("None init must refuse on this launcher")
            .to_string();
        assert!(
            error.contains("unsupported init contract") && error.contains("None"),
            "refusal names the init contract: {error}"
        );
    }

    #[test]
    fn launcher_refuses_an_unsupported_host_page_size() {
        assert!(refuse_unsupported_page_size(&PROBE_RUNTIME_MANIFEST, 4096).is_ok());
        let error = refuse_unsupported_page_size(&PROBE_RUNTIME_MANIFEST, 65_536)
            .err()
            .expect("64 KiB pages must refuse")
            .to_string();
        assert!(
            error.contains("unsupported host page size 65536")
                && error.contains("UnsupportedPageSize"),
            "refusal names the page size: {error}"
        );
    }
}
