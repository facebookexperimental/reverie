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
mod images;
#[allow(unsafe_code)]
mod platform;
#[path = "../../../tests/fixtures/probe_protocol.rs"]
mod protocol;
mod trace;

use std::cell::RefCell;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use images::Kind;
use images::SealedImage;
use protocol::*;
use reverie_loader::artifact;
use safeptrace::Event;
use safeptrace::ExitStatus;
use safeptrace::Options;
use safeptrace::Regs;
use safeptrace::Running;
use safeptrace::Signal;
use safeptrace::Stopped;
use safeptrace::SyscallInfoOp;
use safeptrace::Wait;
use serde_json::Value;
use serde_json::json;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type CleanupReport = Rc<RefCell<Value>>;
const REFUSAL_EXIT: i32 = 122;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    CpuidArmEnosys,
}

struct ProbeControls<'a> {
    fault: Fault,
    pause_checkpoint: Option<&'a Path>,
}

struct ChildGuard {
    cleanup: safeptrace::PtracerTerminalCleanup,
    evidence: CleanupReport,
    complete: bool,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.complete {
            // Signal delivery, including ESRCH, is not terminal proof. Only
            // this retained generation's actual terminal wait can confirm it.
            let killed = self.cleanup.shared().request_sigkill();
            {
                let mut evidence = self.evidence.borrow_mut();
                evidence["kill_requested"] = json!(true);
                evidence["kill_errno"] = json!(killed.err().map(safeptrace::Errno::into_raw));
            }
            match self.cleanup.wait(Duration::from_secs(2)) {
                Ok(true) => {
                    let mut evidence = self.evidence.borrow_mut();
                    evidence["confirmed"] = json!(true);
                    evidence["confirmation"] = json!("safeptrace_terminal_wait");
                }
                result => {
                    self.evidence.borrow_mut()["wait_error"] = json!(format!("{result:?}"));
                    eprintln!("loader cleanup refused to confirm child retirement: {result:?}");
                }
            }
        }
    }
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
    } = controls;
    let loader_image = loader.checked()?;
    let runtime_image = runtime.checked()?;
    let inherited = [loader.fd(), runtime.fd(), observations.as_raw_fd()];
    let launch = platform::PreparedChild::new(arguments, inherited.to_vec())?;
    let mut pending_child = launch
        .fork(Rc::clone(&cleanup_evidence))
        .map_err(|error| format!("loader_clone_pidfd_refused: {error}"))?;
    let pid = pending_child.pid();
    let running = Running::new_on_ptracer_thread(pid)?;
    let mut guard = ChildGuard {
        cleanup: running.terminal_cleanup_on_ptracer_thread(),
        evidence: cleanup_evidence,
        complete: false,
    };
    pending_child.transfer_to_ptracer();
    let _ptracer_thread = running.generation().ptracer_thread_guard()?;
    let (initial, event) = trace::stopped(running, "initial TRACEME stop")?;
    if !matches!(event, Event::Signal(Signal::SIGSTOP)) {
        return Err(format!("loader refused: wrong initial stop {event:?}").into());
    }
    initial.setoptions(
        Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEEXEC | Options::PTRACE_O_TRACESYSGOOD,
    )?;
    let (exec, event) = trace::stopped(initial.resume(None)?, "kernel exec event")?;
    let at_event = exec.getregs()?;
    let at_event_info = exec.getsyscallinfo()?;
    report["exec_event"] = json!({
        "event":if matches!(event, Event::Exec(_)) { "exec" } else { "unexpected" },
        "pid":pid.as_raw(),
        "former_tid":match &event { Event::Exec(former) => Some(former.as_raw()), _ => None },
        "ip":at_event.rip, "sp":at_event.rsp,
        "rax":at_event.rax, "orig_rax":at_event.orig_rax,
        "syscall_info":syscall_info_json(&at_event_info),
    });
    if !matches!(event, Event::Exec(former) if former == pid) {
        return Err(format!("loader refused: expected initial exec event, got {event:?}").into());
    }
    if at_event.orig_rax != libc::SYS_execve as u64 {
        return Err("loader refused: exec event did not originate in the launcher's execve".into());
    }
    // Linux reports EVENT_EXEC inside execve, before its C return writes RAX.
    // Drain only that kernel return. Unlike SINGLESTEP, this syscall-exit stop
    // precedes every instruction of the new program and its interpreter.
    let (task, event) = trace::stopped(exec.syscall(None)?, "exec syscall-exit drain")?;
    let info = task.getsyscallinfo()?;
    let entry = task.getregs()?;
    report["exec_exit"] = json!({
        "event":if matches!(event, Event::Syscall) { "syscall" } else { "unexpected" },
        "pid":pid.as_raw(), "ip":entry.rip, "sp":entry.rsp,
        "rax":entry.rax, "orig_rax":entry.orig_rax,
        "syscall_info":syscall_info_json(&info),
    });
    if !matches!(event, Event::Syscall)
        || info.architecture != AUDIT_ARCH_X86_64
        || info.operation
            != (SyscallInfoOp::Exit {
                return_value: 0,
                is_error: false,
            })
        || entry.rip != at_event.rip
        || entry.rsp != at_event.rsp
        || info.instruction_pointer != entry.rip
        || info.stack_pointer != entry.rsp
    {
        return Err(format!(
            "loader refused: exec return did not drain without entry progress: {info:?}"
        )
        .into());
    }
    report["entry_ip"] = json!(entry.rip);
    report["entry_sp"] = json!(entry.rsp);
    report["entry_rax"] = json!(entry.rax);
    report["exec_return_drained"] = json!(true);
    if let Some(path) = pause_checkpoint {
        return pause_after_exec_drain(task, entry, path, report);
    }
    let mask = task.getsigmask()?;
    let reserved = (1_u64 << (libc::SIGSYS - 1)) | (1_u64 << (libc::SIGSEGV - 1));
    if mask & reserved != 0 {
        return Err("loader refused: first-image test domain has blocked SIGSYS or SIGSEGV".into());
    }
    let xstate = task.getxstate()?;
    let (stack_start, stack_bytes) = snapshot_stack(&task, entry.rsp)?;
    task.setsigmask(u64::MAX)?;
    let nonce = control::initialize(
        observations,
        &entry,
        mask,
        runtime_image.entry(),
        &inherited,
    )?;
    let mut injector = trace::Injector::new(task, entry)?;
    let mapped = (|| -> Result<()> {
        injector.reserve()?;
        injector.map_image(&loader_image, loader.fd())?;
        injector.map_image(&runtime_image, runtime.fd())?;
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        injector.map(
            CONTROL_ADDRESS,
            CONTROL_BYTES as u64,
            rw,
            libc::MAP_SHARED,
            observations.as_raw_fd(),
            0,
        )?;
        injector.map(
            JOURNAL_ADDRESS,
            JOURNAL_BYTES,
            rw,
            libc::MAP_SHARED,
            observations.as_raw_fd(),
            CONTROL_BYTES as u64,
        )?;
        for (bottom, top) in [(STACK_BOTTOM, STACK_TOP), (ALTSTACK_BOTTOM, ALTSTACK_TOP)] {
            injector.map(
                bottom,
                top - bottom,
                rw,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
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
    let mut bootstrap = entry;
    bootstrap.rip = loader_image.entry();
    bootstrap.rsp = STACK_TOP - 8; // SysV function entry, private zero return slot.
    bootstrap.rdi = CONTROL_ADDRESS;
    bootstrap.orig_rax = u64::MAX;
    task.setregs(&bootstrap)?;
    let executable: Vec<_> = loader_image
        .segments()
        .chain(runtime_image.segments())
        .filter(|s| s.permissions.execute)
        .map(|s| s.pages())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| format!("executable segment: {e:?}"))?;
    let task = bootstrap_until_ready(task, &executable, fault, report)?;
    let ready_regs = task.getregs()?;
    // Retain the actual unauthenticated observation on refusal as well.
    report["ready_stop_ip"] = json!(ready_regs.rip);
    report["ready_rax"] = json!(ready_regs.rax);
    if ready_regs.rip != READY_STOP_IP || ready_regs.rax != READY_MAGIC {
        return Err("loader refused: unauthenticated ready breakpoint".into());
    }
    let controls = control::ready(observations, nonce)?;
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
    if trace::read(&task, stack_start, stack_bytes.len())? != stack_bytes {
        return Err("loader refused: bootstrap changed the kernel guest stack".into());
    }
    task.setxstate(&xstate)?;
    task.setregs(&entry)?;
    task.setsigmask(mask)?;
    if register_words(&task.getregs()?) != register_words(&entry)
        || task.getxstate()? != xstate
        || task.getsigmask()? != mask
    {
        return Err("loader refused: original kernel entry context did not restore".into());
    }
    report["controls"] = json!(controls);
    report["ready_stop_ip"] = json!(ready_regs.rip);
    report["ready_nonce_matches"] = json!(true);
    report["stack_unchanged"] = json!(true);
    report["stack_bytes"] = json!(stack_bytes.len());
    report["bootstrap_fds_closed"] = json!(true);
    report["pre_arm_guest_syscalls"] = json!(0);
    let running = task.detach(None)?;
    report["detached"] = json!(true);
    report["outcome"] = json!("handoff");
    match trace::wait(running)? {
        Wait::Exited(_, ExitStatus::Exited(code)) => report["guest_status"] = json!(code),
        Wait::Exited(_, ExitStatus::Signaled(signal, _)) => {
            report["guest_signal"] = json!(signal as i32)
        }
        Wait::Exited(_, ExitStatus::SignaledRaw(signal, _)) => {
            report["guest_signal"] = json!(signal)
        }
        other => {
            return Err(format!("loader refused: unexpected post-detach state {other:?}").into());
        }
    }
    {
        let mut evidence = guard.evidence.borrow_mut();
        evidence["confirmed"] = json!(true);
        evidence["confirmation"] = json!("normal_wait");
        evidence["terminal_status"] = if let Some(code) = report["guest_status"].as_i64() {
            json!({"kind":"exited", "code":code})
        } else {
            json!({"kind":"signaled", "signal":report["guest_signal"]})
        };
    }
    guard.complete = true;
    Ok(())
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
    let mut injector = trace::Injector::new(task, entry)?;
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

fn snapshot_stack(task: &Stopped, rsp: u64) -> Result<(u64, Vec<u8>)> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", task.pid()))?;
    let mut selected = None;
    for line in maps.lines().filter(|line| line.ends_with("[stack]")) {
        let span = line
            .split_whitespace()
            .next()
            .ok_or("missing stack range")?;
        let (lo, hi) = span.split_once('-').ok_or("invalid stack range")?;
        let lo = u64::from_str_radix(lo, 16)?;
        let hi = u64::from_str_radix(hi, 16)?;
        if (lo..hi).contains(&rsp) {
            if selected.is_some() || hi - lo > 16 * 1024 * 1024 {
                return Err("loader refused: ambiguous or oversized initial stack".into());
            }
            selected = Some((lo, trace::read(task, lo, (hi - lo) as usize)?));
        }
    }
    selected.ok_or_else(|| "loader refused: initial stack VMA not found".into())
}

fn register_words(r: &Regs) -> [u64; 27] {
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
}

fn main() {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
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
    if (pause_checkpoint.is_some() && fault != Fault::None) || args.len() < 5 || args[3] != "--" {
        eprintln!(
            "usage: reverie-loader-stage1a-probe [--inject-cpuid-arm-enosys | --pause-after-exec-drain CHECKPOINT] LOADER RUNTIME REPORT -- PROGRAM [ARGS...]"
        );
        std::process::exit(REFUSAL_EXIT);
    }
    let report_path = Path::new(&args[2]);
    let mut report = json!({"outcome":"refused", "guest_status":null, "guest_signal":null});
    let cleanup_evidence = Rc::new(RefCell::new(json!({
        "child_created":false, "owner":"none", "confirmed":false,
        "confirmation":null, "kill_requested":false, "kill_errno":null,
        "wait_error":null, "terminal_status":null,
    })));
    report["fault_requested"] = json!(if fault == Fault::None {
        "none"
    } else {
        "cpuid_arm_enosys"
    });
    let mut observation = None;
    let result = (|| -> Result<()> {
        let loader = SealedImage::read(Path::new(&args[0]), Kind::Loader)?;
        let runtime = SealedImage::read(Path::new(&args[1]), Kind::Runtime)?;
        let file = images::observation_file(CONTROL_BYTES as u64 + JOURNAL_BYTES)?;
        observation = Some(file);
        run(
            &loader,
            &runtime,
            observation.as_ref().ok_or("missing observation file")?,
            &args[4..],
            ProbeControls {
                fault,
                pause_checkpoint: pause_checkpoint.as_deref(),
            },
            Rc::clone(&cleanup_evidence),
            &mut report,
        )
    })();
    // All child guards have dropped before this snapshot, including errors
    // before safeptrace acquired the freshly created child generation.
    report["cleanup"] = cleanup_evidence.borrow().clone();
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
