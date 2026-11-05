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

/// P3: seccomp mode/filter count/`no_new_privs` of the probing context.
/// All three facts or `Unknown` — a partial reading proves nothing about
/// whether one more filter can be installed.
pub fn probe_seccomp() -> Knowledge<SeccompState> {
    // SAFETY: prctl queries on the calling thread; arguments per prctl(2).
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode < 0 {
        return Knowledge::Unknown {
            why: "PR_GET_SECCOMP failed",
        };
    }
    // SAFETY: as above.
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs < 0 {
        return Knowledge::Unknown {
            why: "PR_GET_NO_NEW_PRIVS failed",
        };
    }
    match read_proc("/proc/self/status").and_then(|s| parse_seccomp_filters(&s)) {
        Some(filters) => Knowledge::Proved(SeccompState {
            mode: mode as u64,
            filters,
            no_new_privs: no_new_privs != 0,
            install_proved: run_trial(seccomp_install_child) == Trial::Ok,
        }),
        None => Knowledge::Unknown {
            why: "Seccomp_filters unreadable",
        },
    }
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

/// What a throwaway-child trial concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trial {
    Ok,
    Refused,
    Inconclusive,
}

/// Run `trial` (returning an exit code) in a throwaway child and reap it,
/// bounded by a 2s deadline after which the child is killed. The child
/// must use only async-signal-safe operations: it inherits a possibly
/// multi-threaded parent's locks and must not touch Rust runtime state.
fn run_trial(trial: fn() -> i32) -> Trial {
    // SAFETY: fork in the probing process per the module contract; the
    // child below calls only `trial` (async-signal-safe by construction:
    // raw syscalls via libc) and `_exit`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Trial::Inconclusive;
    }
    if pid == 0 {
        let code = trial();
        // SAFETY: terminating the forked child without unwinding.
        unsafe { libc::_exit(code) };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: reaping our own child by pid.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return if libc::WIFEXITED(status) {
                match libc::WEXITSTATUS(status) {
                    TRIAL_OK => Trial::Ok,
                    TRIAL_REFUSED => Trial::Refused,
                    _ => Trial::Inconclusive,
                }
            } else {
                Trial::Inconclusive
            };
        }
        if waited < 0 || std::time::Instant::now() >= deadline {
            // SAFETY: killing and reaping our own child.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            return Trial::Inconclusive;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
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
    // SAFETY: fork as in run_trial; child only pauses.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Knowledge::Unknown {
            why: "fork for ptrace trial failed",
        };
    }
    if pid == 0 {
        // SAFETY: terminating the forked child without unwinding.
        unsafe { libc::_exit(seize_target_child()) };
    }
    const PTRACE_SEIZE: libc::c_uint = 0x4206;
    // SAFETY: seizing our own child by pid; no data pointer used.
    let seized = unsafe { libc::ptrace(PTRACE_SEIZE, pid, 0usize, 0usize) };
    let result = if seized == 0 {
        Knowledge::Proved(true)
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES)
    {
        Knowledge::Proved(false)
    } else {
        Knowledge::Unknown {
            why: "PTRACE_SEIZE trial failed inconclusively",
        }
    };
    // SAFETY: killing and reaping our own child.
    unsafe {
        let mut status: libc::c_int = 0;
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
    result
}

/// P4 child body: arm Syscall User Dispatch with an allow-all selector.
fn sud_trial_child() -> i32 {
    const PR_SET_SYSCALL_USER_DISPATCH: libc::c_int = 59;
    const PR_SYS_DISPATCH_ON: libc::c_ulong = 1;
    const PR_SYS_DISPATCH_OFF: libc::c_ulong = 0;
    // Selector byte: 0 = allow. It must outlive the prctl calls below;
    // a static keeps its address valid without allocation.
    static SELECTOR: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    let selector = SELECTOR.as_ptr();
    // SAFETY: arming SUD on this throwaway child only. The full-range
    // dispatch window with an allow selector means arming itself (kernel
    // support + permission) is what is tested; then disarm before exiting.
    let armed = unsafe {
        libc::prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_ON,
            0usize,
            usize::MAX,
            selector,
        )
    };
    if armed != 0 {
        return TRIAL_REFUSED;
    }
    // SAFETY: disarming on this child only.
    let disarmed = unsafe {
        libc::prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_OFF,
            0usize,
            0usize,
            selector,
        )
    };
    if disarmed != 0 {
        return TRIAL_REFUSED;
    }
    TRIAL_OK
}

/// P4: Syscall User Dispatch is available and permitted here. Optional
/// acceleration only; admission never gates correctness on it.
pub fn probe_sud() -> Knowledge<bool> {
    trial_knowledge(run_trial(sud_trial_child), "SUD trial inconclusive")
}

/// P5 child body: read, disable (fault), and restore CPUID faulting.
#[cfg(target_arch = "x86_64")]
fn cpuid_trial_child() -> i32 {
    const ARCH_GET_CPUID: libc::c_ulong = 0x1011;
    const ARCH_SET_CPUID: libc::c_ulong = 0x1012;
    // SAFETY: arch_prctl on this throwaway child only.
    let previous = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_CPUID, 0usize) };
    if previous < 0 {
        return TRIAL_REFUSED;
    }
    // SAFETY: as above; 0 disables CPUID (faulting on).
    let armed = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, 0usize) };
    if armed != 0 {
        return TRIAL_REFUSED;
    }
    // SAFETY: restoring this child's previous state before it exits.
    let restored =
        unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, previous as usize) };
    if restored != 0 {
        return TRIAL_REFUSED;
    }
    TRIAL_OK
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
    let mut previous: libc::c_int = 0;
    // SAFETY: prctl on this throwaway child; `previous` outlives the call.
    let got = unsafe { libc::prctl(libc::PR_GET_TSC, &mut previous as *mut libc::c_int, 0, 0, 0) };
    if got != 0 {
        return TRIAL_REFUSED;
    }
    // SAFETY: as above.
    let armed = unsafe { libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0) };
    if armed != 0 {
        return TRIAL_REFUSED;
    }
    // SAFETY: restoring this child's previous state before it exits.
    let restored = unsafe { libc::prctl(libc::PR_SET_TSC, previous, 0, 0, 0) };
    if restored != 0 {
        return TRIAL_REFUSED;
    }
    TRIAL_OK
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

/// P7: whether this host context permits the dual-mapped RW/RX arena
/// shape in-guest patching uses. Trialled on the probing process's own
/// mappings (created and removed here); a guest's stricter policy is a
/// handoff fact, so `DualMapAllowed` is a host fact, not a guest promise.
pub fn probe_wx_policy() -> Knowledge<WxPolicy> {
    const PAGE: usize = 4096;
    // SAFETY: anonymous memfd owned by this call.
    let fd = unsafe { libc::memfd_create(c"reverie-wx-probe".as_ptr(), 0) };
    if fd < 0 {
        return Knowledge::Unknown {
            why: "memfd_create for W^X trial failed",
        };
    }
    // SAFETY: sizing the memfd just created.
    if unsafe { libc::ftruncate(fd, PAGE as libc::off_t) } != 0 {
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(fd) };
        return Knowledge::Unknown {
            why: "W^X trial memfd could not be sized",
        };
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
        return Knowledge::Unknown {
            why: "W^X trial RW mapping failed",
        };
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
        None => Knowledge::Proved(WxPolicy::DualMapAllowed),
        Some(libc::EPERM) | Some(libc::EACCES) => Knowledge::Proved(WxPolicy::StrictWx),
        Some(_) => Knowledge::Unknown {
            why: "W^X trial RX mapping failed inconclusively",
        },
    }
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

    #[test]
    fn code_shape_reads_a_real_dynamic_image() {
        let shape = probe_code_shape_file(std::path::Path::new("/bin/true"));
        let Knowledge::Proved(shape) = shape else {
            // Restricted test roots may not expose /bin/true; Unknown is
            // the fail-closed answer, not a probe failure.
            return;
        };
        assert!(shape.dynamic, "/bin/true is dynamically linked: {shape:?}");
        assert!(!shape.jit_indicators, "{shape:?}");
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
