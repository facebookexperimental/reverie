/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Environment probes P1–P10: pure host/loader observations that fill an
//! [`EnvironmentSnapshot`] for [`selection::admit`](crate::selection::admit).
//!
//! Probes run before any guest instruction and never mutate the guest
//! (there is no guest yet). Where a fact can only be learned by trying it,
//! the trial runs in a *throwaway child* of the probing process, never in
//! a process anyone will instrument. Such observations are advisory for
//! the actual guest — a different process may have different permissions,
//! filter lineage, or ownership — so admission treats them as
//! host-context facts and the retained plan re-validates the real guest
//! at handoff ([`ExecutionPlan::validate_handoff`](crate::selection::ExecutionPlan::validate_handoff)).
//!
//! A probe that cannot be performed returns
//! [`Knowledge::Unknown`]; admission
//! fails closed on it. In particular, unknown tracer ownership is never
//! reported as "no tracer", and image shape (P9) is advisory only: it can
//! tighten admission, never certify future code coverage.
//!
//! Call [`probe_environment`] from the host process before it spawns
//! guests or extra threads: the child trials `fork`, and forked children
//! here use only async-signal-safe operations before `_exit`.

use crate::selection::ArchFloor;
use crate::selection::CodeShape;
use crate::selection::EnvironmentSnapshot;
use crate::selection::InstallEvidence;
use crate::selection::Knowledge;
use crate::selection::SeccompState;
use crate::selection::WxPolicy;

/// Run every probe and assemble the snapshot. P9 is left `Unknown`:
/// use [`probe_code_shape`] on the program image and fill
/// [`EnvironmentSnapshot::p9_code_shape`] when one is available.
pub fn probe_environment() -> EnvironmentSnapshot {
    EnvironmentSnapshot {
        p1_ptrace_usable: probe_ptrace_usable(),
        p2_existing_tracer: probe_existing_tracer(),
        p3_seccomp: probe_seccomp(),
        p4_sud: probe_sud(),
        p5_cpuid_faulting: probe_cpuid_faulting(),
        p6_pr_set_tsc: probe_pr_set_tsc(),
        p7_wx: probe_wx_policy(),
        p8_signal_ownership: probe_signal_ownership(),
        p9_code_shape: Knowledge::Unknown {
            why: "no program image supplied; see probe_code_shape",
        },
        p10_arch: probe_arch(),
    }
}

/// P10: architecture/kernel floor. The only probe decidable from the
/// probing process itself.
pub fn probe_arch() -> Knowledge<ArchFloor> {
    let linux_x86_64 = cfg!(all(target_os = "linux", target_arch = "x86_64"));
    Knowledge::Proved(ArchFloor {
        linux_x86_64,
        cet_ibt: cet_ibt_present(),
    })
}

/// CET shadow-stack / indirect-branch-tracking presence (CPUID leaf 7),
/// recorded for trampoline shape; never gated on.
#[cfg(target_arch = "x86_64")]
fn cet_ibt_present() -> bool {
    // CPUID.(EAX=7,ECX=0): ECX bit 7 = CET_SS, EDX bit 20 = CET_IBT.
    let result = raw_cpuid::native_cpuid::cpuid_count(7, 0);
    result.ecx & (1 << 7) != 0 || result.edx & (1 << 20) != 0
}

/// CET/IBT do not apply off x86-64.
#[cfg(not(target_arch = "x86_64"))]
fn cet_ibt_present() -> bool {
    false
}

/// Read a small `/proc` file; any failure is `None` (the caller maps it to
/// `Unknown`, never to a convenient default).
fn read_proc(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Parse `TracerPid:` from a `/proc/<pid>/status` body.
pub fn parse_tracer_pid(status: &str) -> Option<i32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Parse `Seccomp_filters:` from a `/proc/<pid>/status` body.
pub fn parse_seccomp_filters(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Whether `CAP_SYS_PTRACE` (19) is in the effective set (`CapEff:`).
pub fn parse_cap_sys_ptrace(status: &str) -> Option<bool> {
    const CAP_SYS_PTRACE: u32 = 19;
    let hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    let caps = u64::from_str_radix(hex, 16).ok()?;
    Some(caps & (1u64 << CAP_SYS_PTRACE) != 0)
}

/// Parse a `ptrace_scope` file body.
pub fn parse_ptrace_scope(body: &str) -> Option<u64> {
    body.trim().parse().ok()
}

/// P2: whether this process already has a tracer. `Proved(false)` is the
/// only "no tracer" answer; an unreadable `/proc/self/status` is
/// `Unknown`, never `false`.
pub fn probe_existing_tracer() -> Knowledge<bool> {
    match read_proc("/proc/self/status").and_then(|s| parse_tracer_pid(&s)) {
        Some(pid) => Knowledge::Proved(pid != 0),
        None => Knowledge::Unknown {
            why: "TracerPid unreadable",
        },
    }
}

/// Combine P3 metadata readings with the install trial. Any missing
/// metadata is `Unknown` (a partial reading proves nothing); the trial
/// outcome is preserved three-way so metadata can never override a
/// failed or inconclusive installation attempt.
fn seccomp_knowledge(
    mode: Option<u64>,
    no_new_privs: Option<bool>,
    filters: Option<u64>,
    install_trial: Trial,
) -> Knowledge<SeccompState> {
    match (mode, no_new_privs, filters) {
        (Some(mode), Some(no_new_privs), Some(filters)) => Knowledge::Proved(SeccompState {
            mode,
            filters,
            no_new_privs,
            install: match install_trial {
                Trial::Ok => InstallEvidence::Proved,
                Trial::Refused => InstallEvidence::Refused,
                Trial::Inconclusive => InstallEvidence::Unknown,
            },
        }),
        _ => Knowledge::Unknown {
            why: "seccomp metadata incomplete",
        },
    }
}

/// P3: seccomp state of the probing context plus a real install trial.
pub fn probe_seccomp() -> Knowledge<SeccompState> {
    // SAFETY: prctl queries on the calling thread; arguments per prctl(2).
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    // SAFETY: as above.
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    let filters = read_proc("/proc/self/status").and_then(|s| parse_seccomp_filters(&s));
    if mode < 0 || no_new_privs < 0 || filters.is_none() {
        return seccomp_knowledge(None, None, None, Trial::Inconclusive);
    }
    seccomp_knowledge(
        Some(mode as u64),
        Some(no_new_privs != 0),
        filters,
        run_trial(seccomp_install_child),
    )
}

/// P3 trial child: set `no_new_privs` (as a guest runtime does), then
/// install an allow-all filter. Proves installation works from an
/// unprivileged context; proves nothing about an actual guest's filter
/// lineage, which is a handoff fact.
fn seccomp_install_child() -> i32 {
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_RET_K: u16 = 0x06;
    // SAFETY: prctl/seccomp on this throwaway child only. The program
    // (allow everything) outlives the syscall via the statics below.
    static FILTER: [libc::sock_filter; 1] = [libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    }];
    let prog = libc::sock_fprog {
        len: 1,
        filter: FILTER.as_ptr() as *mut libc::sock_filter,
    };
    let nnp = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp != 0 {
        return TRIAL_REFUSED;
    }
    let installed = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0usize,
            &prog as *const libc::sock_fprog,
        )
    };
    if installed != 0 {
        return TRIAL_REFUSED;
    }
    TRIAL_OK
}

/// P8: signal ownership. Guest dispositions are not observable before the
/// guest runs, so this is honestly always `Unknown` pre-launch; cells that
/// need SIGTRAP/SIGSYS/SIGSEGV ownership validate it at handoff against
/// the actual guest.
pub fn probe_signal_ownership() -> Knowledge<bool> {
    Knowledge::Unknown {
        why: "guest signal dispositions are not observable before launch",
    }
}

/// P9 (advisory): observable shape of a program image. ELF/JIT indicators
/// cannot prove future code coverage; admission may only tighten on this.
pub fn probe_code_shape(image: &[u8]) -> Knowledge<CodeShape> {
    let Ok(object) = goblin::Object::parse(image) else {
        return Knowledge::Unknown {
            why: "image is not a parseable object file",
        };
    };
    let goblin::Object::Elf(elf) = object else {
        return Knowledge::Unknown {
            why: "image is not an ELF object",
        };
    };
    let pie = elf.header.e_type == goblin::elf::header::ET_DYN;
    let dynamic = elf.is_lib || !elf.libraries.is_empty() || elf.interpreter.is_some();
    const JIT_LIBRARIES: [&str; 8] = [
        "libv8",
        "libjvm",
        "libluajit",
        "libjavascriptcore",
        "libmozjs",
        "libnode",
        "libpypy",
        "libwasmtime",
    ];
    let jit_indicators = elf
        .libraries
        .iter()
        .any(|lib| JIT_LIBRARIES.iter().any(|jit| lib.contains(jit)));
    Knowledge::Proved(CodeShape {
        dynamic,
        pie,
        jit_indicators,
    })
}

/// [`probe_code_shape`] over a file's contents.
pub fn probe_code_shape_file(path: &std::path::Path) -> Knowledge<CodeShape> {
    match std::fs::read(path) {
        Ok(image) => probe_code_shape(&image),
        Err(_) => Knowledge::Unknown {
            why: "program image unreadable",
        },
    }
}
/// Exit code a trial child uses for "the trial succeeded".
const TRIAL_OK: i32 = 42;
/// Exit code a trial child uses for "the trial was refused".
const TRIAL_REFUSED: i32 = 43;
/// Exit code a trial child uses for "the trial itself could not be
/// performed" (for example a failed state query before any arming
/// attempt): unproved, never a proved-negative capability.
const TRIAL_INCONCLUSIVE: i32 = 44;

/// What a throwaway-child trial concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trial {
    Ok,
    Refused,
    Inconclusive,
}

/// One non-blocking wait observation of a trial child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitReply {
    /// Still running; custody verified (it is our unreaped child).
    Running,
    /// Exited with this status code.
    Exited(i32),
    /// Terminated by a signal.
    Signaled,
    /// Interrupted before any state change; poll again.
    Interrupted,
    /// No such child (ECHILD): custody is lost (auto-reaped or reaped
    /// elsewhere) and the numeric pid must never be signalled again.
    NoChild,
    /// Any other wait failure; custody unverified.
    Failed,
}

/// Custody operations over one trial child. The production
/// implementation wraps a pid; tests script replies to pin the custody
/// discipline without forking.
trait TrialChild {
    /// One non-blocking wait poll.
    fn poll(&mut self) -> WaitReply;
    /// Send SIGKILL. Only ever called while custody is verified
    /// (the immediately preceding poll said `Running`).
    fn kill(&mut self);
    /// Pause between polls (production: a short sleep; tests: no-op).
    fn pause(&mut self);
}

/// Production [`TrialChild`] over a forked pid.
struct PidChild(libc::pid_t);

impl TrialChild for PidChild {
    fn poll(&mut self) -> WaitReply {
        let mut status: libc::c_int = 0;
        // SAFETY: non-blocking wait on our own child by pid.
        let waited = unsafe { libc::waitpid(self.0, &mut status, libc::WNOHANG) };
        if waited == self.0 {
            if libc::WIFEXITED(status) {
                WaitReply::Exited(libc::WEXITSTATUS(status))
            } else {
                WaitReply::Signaled
            }
        } else if waited == 0 {
            WaitReply::Running
        } else {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => WaitReply::Interrupted,
                Some(libc::ECHILD) => WaitReply::NoChild,
                _ => WaitReply::Failed,
            }
        }
    }

    fn kill(&mut self) {
        // SAFETY: killing our own verified-running child (see trait).
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }

    fn pause(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Polls before the deadline kill (~2s at the production pause), and
/// polls to reap after it (~500ms). Both bounds are poll counts so the
/// discipline is testable without wall-clock sleeps.
const TRIAL_POLLS: u32 = 400;
const REAP_POLLS: u32 = 100;

/// Reap one trial child under the custody discipline: retry interrupted
/// polls, kill only a child the previous poll verified as running, and
/// never signal after custody is lost (ECHILD/other errors). Every loop
/// is bounded; a child that cannot be reaped within the reap bound is
/// reported `Inconclusive` with custody retained by the caller of last
/// resort (init reaps it) — never claimed cleaned up.
fn reap_trial(child: &mut dyn TrialChild) -> Trial {
    let mut polls = 0;
    loop {
        match child.poll() {
            WaitReply::Exited(TRIAL_OK) => return Trial::Ok,
            WaitReply::Exited(TRIAL_REFUSED) => return Trial::Refused,
            WaitReply::Exited(_) | WaitReply::Signaled => return Trial::Inconclusive,
            WaitReply::Interrupted => {}
            WaitReply::Running => {
                polls += 1;
                if polls > TRIAL_POLLS {
                    break;
                }
            }
            // Custody lost or unverified: never signal the numeric pid.
            WaitReply::NoChild | WaitReply::Failed => return Trial::Inconclusive,
        }
        child.pause();
    }
    // The immediately preceding poll verified the child is ours and
    // running: this is the only kill site.
    child.kill();
    for _ in 0..REAP_POLLS {
        match child.poll() {
            WaitReply::Exited(_) | WaitReply::Signaled => break,
            WaitReply::Interrupted | WaitReply::Running => child.pause(),
            WaitReply::NoChild | WaitReply::Failed => break,
        }
    }
    Trial::Inconclusive
}

/// Fork a throwaway child running `trial`, returning its pid wrapper.
/// The child must use only async-signal-safe operations: it inherits a
/// possibly multi-threaded parent's locks and must not touch Rust
/// runtime state.
fn fork_trial(trial: fn() -> i32) -> Option<PidChild> {
    // SAFETY: fork per the module contract; the child calls only
    // `trial` (raw syscalls via libc) and `_exit`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return None;
    }
    if pid == 0 {
        let code = trial();
        // SAFETY: terminating the forked child without unwinding.
        unsafe { libc::_exit(code) };
    }
    Some(PidChild(pid))
}

/// Run `trial` in a throwaway child and reap it under the custody
/// discipline in [`reap_trial`].
fn run_trial(trial: fn() -> i32) -> Trial {
    match fork_trial(trial) {
        Some(mut child) => reap_trial(&mut child),
        None => Trial::Inconclusive,
    }
}

/// Map a trial to `Knowledge<bool>`: success/refusal are observations of
/// *this* host context; anything else is unproved.
fn trial_knowledge(trial: Trial, why: &'static str) -> Knowledge<bool> {
    match trial {
        Trial::Ok => Knowledge::Proved(true),
        Trial::Refused => Knowledge::Proved(false),
        Trial::Inconclusive => Knowledge::Unknown { why },
    }
}

/// P1 child body: pause until the parent seizes or kills us.
fn seize_target_child() -> i32 {
    // SAFETY: async-signal-safe wait in the forked child.
    unsafe { libc::pause() };
    TRIAL_REFUSED
}

/// P1: ptrace seizure is usable from this host context. Proven by seizing
/// a throwaway child; the scope/capability readings are kept for logs via
/// the parsers but the trial is the observation admission consumes. Note
/// this proves the *probing* context can seize its own child; the actual
/// guest's seizure is re-validated at handoff.
pub fn probe_ptrace_usable() -> Knowledge<bool> {
    let Some(mut child) = fork_trial(seize_target_child) else {
        return Knowledge::Unknown {
            why: "fork for ptrace trial failed",
        };
    };
    const PTRACE_SEIZE: libc::c_uint = 0x4206;
    // SAFETY: seizing our own child by pid; no data pointer used.
    let seized = unsafe { libc::ptrace(PTRACE_SEIZE, child.0, 0usize, 0usize) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    let result = if seized == 0 {
        Knowledge::Proved(true)
    } else if errno == Some(libc::EPERM) || errno == Some(libc::EACCES) {
        Knowledge::Proved(false)
    } else {
        Knowledge::Unknown {
            why: "PTRACE_SEIZE trial failed inconclusively",
        }
    };
    // Bounded, custody-checked cleanup (the child pauses, so this takes
    // the deadline-kill path by design).
    let _ = reap_trial(&mut child);
    result
}

/// P4 arming sequence, over an injected `prctl` so tests can pin the
/// exact arguments (Linux requires offset, length AND selector to be
/// zero when disabling; passing the selector with OFF is EINVAL, which
/// previously misreported a working SUD facility as unavailable).
fn sud_on_off(
    mut prctl: impl FnMut(libc::c_ulong, usize, usize, *const u8) -> libc::c_int,
    selector: *const u8,
) -> i32 {
    const PR_SYS_DISPATCH_ON: libc::c_ulong = 1;
    const PR_SYS_DISPATCH_OFF: libc::c_ulong = 0;
    if prctl(PR_SYS_DISPATCH_ON, 0, usize::MAX, selector) != 0 {
        return TRIAL_REFUSED;
    }
    if prctl(PR_SYS_DISPATCH_OFF, 0, 0, core::ptr::null()) != 0 {
        return TRIAL_REFUSED;
    }
    TRIAL_OK
}

/// P4 child body: arm Syscall User Dispatch with an allow-all selector,
/// then disarm. Arming itself (kernel support + permission) is the test.
fn sud_trial_child() -> i32 {
    const PR_SET_SYSCALL_USER_DISPATCH: libc::c_int = 59;
    // Selector byte: 0 = allow. A static keeps its address valid without
    // allocation in the forked child.
    static SELECTOR: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    sud_on_off(
        |action, offset, len, selector| {
            // SAFETY: prctl on this throwaway child only.
            unsafe { libc::prctl(PR_SET_SYSCALL_USER_DISPATCH, action, offset, len, selector) }
        },
        SELECTOR.as_ptr(),
    )
}

/// P4: Syscall User Dispatch is available and permitted here. Optional
/// acceleration only; admission never gates correctness on it.
pub fn probe_sud() -> Knowledge<bool> {
    trial_knowledge(run_trial(sud_trial_child), "SUD trial inconclusive")
}

/// GET→SET→restore sequencing shared by the faulting trials. A failed
/// GET performed no arming trial, so it is inconclusive — never a
/// proved-negative capability; only a refused SET is a denial. Restore
/// is best-effort: the throwaway child exits either way, and arming was
/// already proved by the successful SET.
fn arm_sequence(get: impl Fn() -> i64, set: impl Fn(i64) -> i64) -> i32 {
    let previous = get();
    if previous < 0 {
        return TRIAL_INCONCLUSIVE;
    }
    if set(0) != 0 {
        return TRIAL_REFUSED;
    }
    let _ = set(previous);
    TRIAL_OK
}

/// P5 child body: read, disable (fault), and restore CPUID faulting.
#[cfg(target_arch = "x86_64")]
fn cpuid_trial_child() -> i32 {
    const ARCH_GET_CPUID: libc::c_ulong = 0x1011;
    const ARCH_SET_CPUID: libc::c_ulong = 0x1012;
    arm_sequence(
        // SAFETY: arch_prctl on this throwaway child only.
        || unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_CPUID, 0usize) },
        // SAFETY: as above; 0 disables CPUID (faulting on).
        |value| unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, value as usize) },
    )
}

/// P5: CPUID faulting can be armed. A cell may name this as a
/// prerequisite; `Proved(false)` removes such a cell, never its coverage.
pub fn probe_cpuid_faulting() -> Knowledge<bool> {
    #[cfg(target_arch = "x86_64")]
    {
        trial_knowledge(
            run_trial(cpuid_trial_child),
            "CPUID-faulting trial inconclusive",
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Knowledge::Proved(false)
    }
}

/// P6 child body: read, arm `PR_TSC_SIGSEGV`, and restore TSC access.
#[cfg(target_arch = "x86_64")]
fn tsc_trial_child() -> i32 {
    arm_sequence(
        || {
            let mut previous: libc::c_int = 0;
            // SAFETY: prctl on this throwaway child; out-param lives here.
            let got = unsafe {
                libc::prctl(libc::PR_GET_TSC, &mut previous as *mut libc::c_int, 0, 0, 0)
            };
            if got != 0 { -1 } else { previous as i64 }
        },
        |value| {
            // arm_sequence arms with 0; for TSC the arming value is
            // PR_TSC_SIGSEGV, and restore passes the previous mode.
            let mode = if value == 0 {
                libc::PR_TSC_SIGSEGV
            } else {
                value as libc::c_int
            };
            // SAFETY: prctl on this throwaway child only.
            unsafe { libc::prctl(libc::PR_SET_TSC, mode, 0, 0, 0) as i64 }
        },
    )
}

/// P6: `PR_SET_TSC` can be armed (see P5 for the refusal semantics).
pub fn probe_pr_set_tsc() -> Knowledge<bool> {
    #[cfg(target_arch = "x86_64")]
    {
        trial_knowledge(run_trial(tsc_trial_child), "PR_SET_TSC trial inconclusive")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Knowledge::Proved(false)
    }
}

/// P7 dual-map trial: RW and RX views of one memfd (the arena shape).
fn dual_map_trial() -> Trial {
    const PAGE: usize = 4096;
    // SAFETY: anonymous memfd owned by this call.
    let fd = unsafe { libc::memfd_create(c"reverie-wx-probe".as_ptr(), 0) };
    if fd < 0 {
        return Trial::Inconclusive;
    }
    // SAFETY: sizing the memfd just created.
    if unsafe { libc::ftruncate(fd, PAGE as libc::off_t) } != 0 {
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(fd) };
        return Trial::Inconclusive;
    }
    // SAFETY: mapping our own memfd twice (RW and RX views).
    let rw = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if rw == libc::MAP_FAILED {
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(fd) };
        return Trial::Inconclusive;
    }
    // SAFETY: second, executable view of the same memfd.
    let rx = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    let rx_errno = if rx == libc::MAP_FAILED {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    // SAFETY: unmapping/closing only what this call created.
    unsafe {
        libc::munmap(rw, PAGE);
        if rx != libc::MAP_FAILED {
            libc::munmap(rx, PAGE);
        }
        libc::close(fd);
    }
    match rx_errno {
        None => Trial::Ok,
        Some(libc::EPERM) | Some(libc::EACCES) => Trial::Refused,
        Some(_) => Trial::Inconclusive,
    }
}

/// P7 transition trial: `mprotect` an owned RW page to RWX — the exact
/// text transition the patching backend performs. A policy can permit
/// dual mappings yet deny this, so it is trialled separately.
fn mprotect_rwx_trial() -> Trial {
    const PAGE: usize = 4096;
    // SAFETY: anonymous private page owned by this call.
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED {
        return Trial::Inconclusive;
    }
    // SAFETY: reprotecting our own page, then unmapping it.
    let (ret, errno) = unsafe {
        let ret = libc::mprotect(
            page,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        );
        let errno = if ret != 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        libc::munmap(page, PAGE);
        (ret, errno)
    };
    match (ret, errno) {
        (0, _) => Trial::Ok,
        (_, Some(libc::EPERM)) | (_, Some(libc::EACCES)) => Trial::Refused,
        _ => Trial::Inconclusive,
    }
}

/// Combine the P7 trials: `DualMapAllowed` promises both shapes, so
/// both must be proved; a refusal of either is strict W^X for the
/// patching cell's purposes; anything else is unproved.
fn wx_from_trials(dual_map: Trial, mprotect_rwx: Trial) -> Knowledge<WxPolicy> {
    match (dual_map, mprotect_rwx) {
        (Trial::Ok, Trial::Ok) => Knowledge::Proved(WxPolicy::DualMapAllowed),
        (Trial::Refused, _) | (_, Trial::Refused) => Knowledge::Proved(WxPolicy::StrictWx),
        _ => Knowledge::Unknown {
            why: "W^X trial inconclusive",
        },
    }
}

/// P7: whether this host context permits what in-guest patching needs:
/// dual-mapped RW/RX arenas *and* the RW→RWX `mprotect` text transition.
/// Trialled on the probing process's own mappings (created and removed
/// here); a guest's stricter policy is a handoff fact, so this remains a
/// host fact, not a guest promise.
pub fn probe_wx_policy() -> Knowledge<WxPolicy> {
    wx_from_trials(dual_map_trial(), mprotect_rwx_trial())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Subscription;
    use crate::selection::ToolRequirements;
    use crate::selection::*;

    const STATUS: &str = "Name:\tprobe\nTracerPid:\t1234\nCapEff:\t0000000000080000\nSeccomp:\t2\nSeccomp_filters:\t3\n";

    #[test]
    fn status_parsers_read_exact_fields() {
        assert_eq!(parse_tracer_pid(STATUS), Some(1234));
        assert_eq!(parse_seccomp_filters(STATUS), Some(3));
        // CapEff 0x80000 is exactly bit 19 (CAP_SYS_PTRACE).
        assert_eq!(parse_cap_sys_ptrace(STATUS), Some(true));
        assert_eq!(
            parse_cap_sys_ptrace("CapEff:\t0000000000000000\n"),
            Some(false)
        );
        assert_eq!(parse_tracer_pid("Name:\tx\n"), None);
        assert_eq!(parse_tracer_pid("TracerPid:\t0\n"), Some(0));
        assert_eq!(parse_ptrace_scope("1\n"), Some(1));
        assert_eq!(parse_ptrace_scope(""), None);
    }

    #[test]
    fn signal_ownership_is_honestly_unknown_pre_launch() {
        assert!(probe_signal_ownership().is_unknown());
    }

    #[test]
    fn arch_probe_matches_build_target() {
        let Knowledge::Proved(floor) = probe_arch() else {
            panic!("arch is decidable");
        };
        assert_eq!(
            floor.linux_x86_64,
            cfg!(all(target_os = "linux", target_arch = "x86_64"))
        );
    }

    /// Positive ELF coverage over a deterministic fixture that always
    /// exists in a test run: this very test binary. An always-Unknown
    /// `probe_code_shape_file` mutant fails here (it survived the old
    /// /bin/true test, which returned successfully on Unknown).
    #[test]
    fn code_shape_proves_a_real_dynamic_image() {
        let exe = std::env::current_exe().expect("test binary path");
        let Knowledge::Proved(shape) = probe_code_shape_file(&exe) else {
            panic!("own test binary must parse as a proved ELF shape");
        };
        assert!(
            shape.dynamic,
            "test binary is dynamically linked: {shape:?}"
        );
        assert!(shape.pie, "test binary is PIE: {shape:?}");
        assert!(!shape.jit_indicators, "{shape:?}");
    }

    /// Scripted [`TrialChild`] for custody tests: replays wait replies
    /// (repeating the last), records kills.
    struct Scripted {
        replies: std::collections::VecDeque<WaitReply>,
        last: WaitReply,
        kills: usize,
    }

    impl Scripted {
        fn new(replies: &[WaitReply]) -> Self {
            Self {
                last: *replies.last().expect("non-empty script"),
                replies: replies.iter().copied().collect(),
                kills: 0,
            }
        }
    }

    impl TrialChild for Scripted {
        fn poll(&mut self) -> WaitReply {
            self.replies.pop_front().unwrap_or(self.last)
        }
        fn kill(&mut self) {
            self.kills += 1;
        }
        fn pause(&mut self) {}
    }

    /// Custody regressions (1285 findings 2–3): EINTR retries, ECHILD
    /// never signals a possibly-reused pid, deadline kill happens only
    /// with verified custody and is itself reaped boundedly.
    #[test]
    fn reap_trial_custody_discipline() {
        // Interrupted polls retry and reach the verdict, no kill.
        let mut child = Scripted::new(&[
            WaitReply::Interrupted,
            WaitReply::Running,
            WaitReply::Interrupted,
            WaitReply::Exited(TRIAL_OK),
        ]);
        assert_eq!(reap_trial(&mut child), Trial::Ok);
        assert_eq!(child.kills, 0);

        // ECHILD: custody already lost — never kill a numeric pid that
        // may have been reused.
        let mut child = Scripted::new(&[WaitReply::NoChild]);
        assert_eq!(reap_trial(&mut child), Trial::Inconclusive);
        assert_eq!(child.kills, 0, "kill after ECHILD is a PID-reuse hazard");

        // Other wait failures likewise never signal.
        let mut child = Scripted::new(&[WaitReply::Failed]);
        assert_eq!(reap_trial(&mut child), Trial::Inconclusive);
        assert_eq!(child.kills, 0);

        // Deadline: kill exactly once (custody verified Running), then
        // reap within the bounded second phase.
        let mut replies = vec![WaitReply::Running; (TRIAL_POLLS + 2) as usize];
        replies.push(WaitReply::Signaled);
        let mut child = Scripted::new(&replies);
        assert_eq!(reap_trial(&mut child), Trial::Inconclusive);
        assert_eq!(child.kills, 1);

        // Refused verdict passes through.
        let mut child = Scripted::new(&[WaitReply::Exited(TRIAL_REFUSED)]);
        assert_eq!(reap_trial(&mut child), Trial::Refused);
        // Inconclusive exit code stays inconclusive.
        let mut child = Scripted::new(&[WaitReply::Exited(TRIAL_INCONCLUSIVE)]);
        assert_eq!(reap_trial(&mut child), Trial::Inconclusive);
    }

    /// SUD regression (1285 finding 4): OFF must pass zero
    /// offset/length/selector. The old code passed the selector again,
    /// EINVAL turned a working facility into Proved(false).
    #[test]
    fn sud_off_passes_null_selector() {
        let calls = std::cell::RefCell::new(Vec::new());
        let code = sud_on_off(
            |action, offset, len, selector| {
                calls
                    .borrow_mut()
                    .push((action, offset, len, selector.is_null()));
                0
            },
            0x1234 as *const u8,
        );
        assert_eq!(code, TRIAL_OK);
        assert_eq!(
            *calls.borrow(),
            vec![(1, 0, usize::MAX, false), (0, 0, 0, true)]
        );
        // ON refused → refused, no OFF attempted.
        let code = sud_on_off(|_, _, _, _| -1, core::ptr::null());
        assert_eq!(code, TRIAL_REFUSED);
    }

    /// GET-polarity regression (1285 finding 6): a failed state query
    /// performed no arming trial and must be inconclusive, while a
    /// refused SET is the proved denial.
    #[test]
    fn arm_sequence_get_failure_is_inconclusive_set_failure_refused() {
        assert_eq!(arm_sequence(|| -1, |_| 0), TRIAL_INCONCLUSIVE);
        assert_eq!(arm_sequence(|| 1, |_| -1), TRIAL_REFUSED);
        assert_eq!(arm_sequence(|| 1, |_| 0), TRIAL_OK);
        // Restore failure after a proved arm stays proved (the child is
        // throwaway); only the arming SET is load-bearing.
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            arm_sequence(
                || 7,
                |_| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 1 { 0 } else { -1 }
                }
            ),
            TRIAL_OK
        );
    }

    /// W^X combination regression (1285 finding 5): dual mappings alone
    /// do not prove the RW→RWX text transition the backend performs.
    #[test]
    fn wx_requires_both_dual_map_and_mprotect_transition() {
        use Trial::*;
        assert_eq!(
            wx_from_trials(Ok, Ok),
            Knowledge::Proved(WxPolicy::DualMapAllowed)
        );
        assert_eq!(
            wx_from_trials(Ok, Refused),
            Knowledge::Proved(WxPolicy::StrictWx)
        );
        assert_eq!(
            wx_from_trials(Refused, Ok),
            Knowledge::Proved(WxPolicy::StrictWx)
        );
        assert!(wx_from_trials(Ok, Inconclusive).is_unknown());
        assert!(wx_from_trials(Inconclusive, Inconclusive).is_unknown());
    }

    /// Seccomp evidence regression (1285 finding 1): a refused or
    /// inconclusive install trial survives combination with permissive
    /// metadata — it is never collapsed into a boolean metadata can
    /// override — and incomplete metadata is Unknown outright.
    #[test]
    fn seccomp_knowledge_preserves_trial_outcome() {
        let state = |trial| match seccomp_knowledge(Some(2), Some(true), Some(1), trial) {
            Knowledge::Proved(state) => state,
            other => panic!("expected proved state, got {other:?}"),
        };
        assert_eq!(state(Trial::Ok).install, InstallEvidence::Proved);
        assert_eq!(state(Trial::Refused).install, InstallEvidence::Refused);
        assert_eq!(state(Trial::Inconclusive).install, InstallEvidence::Unknown);
        assert!(seccomp_knowledge(None, Some(true), Some(1), Trial::Ok).is_unknown());
        assert!(seccomp_knowledge(Some(2), None, Some(1), Trial::Ok).is_unknown());
        assert!(seccomp_knowledge(Some(2), Some(true), None, Trial::Ok).is_unknown());
    }

    #[test]
    fn code_shape_unknown_for_garbage_and_missing() {
        assert!(probe_code_shape(b"not an object").is_unknown());
        assert!(
            probe_code_shape_file(std::path::Path::new("/nonexistent/reverie-probe")).is_unknown()
        );
    }

    /// The real probes, against this host: they must terminate promptly,
    /// never fabricate, and agree with admission's reading. Forking
    /// trials run serially inside this one test.
    #[test]
    fn probe_environment_is_prompt_honest_and_admissible() {
        let started = std::time::Instant::now();
        let env = probe_environment();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "probes must be bounded: {:?}",
            started.elapsed()
        );
        // P8/P9 are never fabricated by probe_environment.
        assert!(env.p8_signal_ownership.is_unknown(), "{env:?}");
        assert!(env.p9_code_shape.is_unknown(), "{env:?}");
        if let Knowledge::Proved(floor) = env.p10_arch {
            assert_eq!(
                floor.linux_x86_64,
                cfg!(all(target_os = "linux", target_arch = "x86_64"))
            );
        } else {
            panic!("P10 is decidable: {env:?}");
        }
        // Whatever this host proved, admission over a default tool either
        // picks the reference cell or refuses by name — never panics and
        // never admits a preload cell by default.
        let request = AdmissionRequest {
            requirements: EffectiveRequirements::compute(
                ToolRequirements::default(),
                Subscription::all_syscalls(),
                ToolQueries::default(),
            ),
            guest: GuestProfile::HostProcessAny,
            env: env.clone(),
            explicit: ExplicitSelection::Auto,
        };
        match admit(&request) {
            Ok(report) => assert_eq!(report.chosen, CellId("V1-ptrace")),
            Err(refusal) => assert!(
                matches!(
                    refusal.code,
                    RefusalCode::RPtrace | RefusalCode::REnvUnknown | RefusalCode::RArch
                ),
                "this host can only refuse by environment/architecture: {refusal}"
            ),
        }
        // On a host where ptrace proved usable, the default tool admits.
        if env.p1_ptrace_usable == Knowledge::Proved(true)
            && matches!(env.p10_arch, Knowledge::Proved(f) if f.linux_x86_64)
        {
            assert_eq!(
                admit(&request).expect("proved host admits").chosen,
                CellId("V1-ptrace")
            );
        }
    }
}
