/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::mem;

use perf_event_open_sys::bindings as perf;
use reverie::Errno;
use tracing::warn;

use crate::perf::PerfCounter;
use crate::perf::do_branches;
use crate::timer::get_pmu_config;
use crate::timer::has_precise_ip;

const IN_TXCP: u64 = 1 << 33;
const NUM_BRANCHES: u64 = 500;

pub use reverie::pmu_config::PmuValidationError;
fn init_perf_event_attr(
    perf_attr_type: u32,
    config: u64,
    precise_ip: bool,
) -> perf::perf_event_attr {
    let mut result = perf::perf_event_attr {
        type_: perf_attr_type,
        config,
        ..Default::default()
    };
    result.size = mem::size_of_val(&result) as u32;
    result.set_exclude_guest(1);
    result.set_exclude_kernel(1);

    if precise_ip && has_precise_ip() {
        result.set_precise_ip(1);

        // This prevents EINVAL when creating a counter with precise_ip enabled
        result.__bindgen_anon_1.sample_period = PerfCounter::DISABLE_SAMPLE_PERIOD;
    } else {
        // This is the value used for the bug checks which are not originally designed to
        // work with precise_ip
        result.__bindgen_anon_1.sample_period = 0;
    }

    result
}

/// Create a template perf_event_attr for ticks
fn ticks_attr(precise_ip: bool) -> perf::perf_event_attr {
    init_perf_event_attr(
        perf::PERF_TYPE_RAW,
        get_pmu_config().raw_rcb_event(),
        precise_ip,
    )
}

/// Create a template perf_event_attr for cycles
fn cycles_attr(precise_ip: bool) -> perf::perf_event_attr {
    init_perf_event_attr(
        perf::PERF_TYPE_HARDWARE,
        perf::PERF_COUNT_HW_CPU_CYCLES.into(),
        precise_ip,
    )
}

/// A counter's descriptor, a transient open from [`start_counter`] to its
/// close here. Each check builds its counters' attributes before it opens the
/// first one, so only system calls on the counters and the check's own
/// counted work run under the guard; the longest is the SpecLockMap check's
/// locked-instruction loop, about a millisecond.
struct ScopedFd(i32, crate::launch_window::TransientOpen);

impl Drop for ScopedFd {
    fn drop(&mut self) {
        if let Err(errno) = Errno::result(unsafe { libc::close(self.0) }) {
            warn_after_guards(format!("Error while closing file descriptor - {:?}", errno));
        }
    }
}

/// Logs `message` once this thread holds no transient open: a log subscriber
/// may block on a thread that is launching a guest, which waits for the open
/// to close.
fn warn_after_guards(message: String) {
    crate::launch_window::run_after_guards(move || warn!("{message}"));
}

/// This function is a transcription of the function `check_for_bugs` from
/// [Mozilla-RR](https://github.com/rr-debugger/rr/blob/master/src/PerfCounters.cc#L308)
/// It checks for a collection of processor features that ensure that the pmu features
/// required from Reverie to function correctly are available and trustworthy
pub(crate) fn check_for_pmu_bugs() -> Result<(), PmuValidationError> {
    require_pmu_config(crate::timer::try_get_pmu_config().is_some())?;
    check_for_ioc_period_bug(false)?;
    check_working_counters(false)?;
    check_for_ioc_period_bug(true)?;
    check_working_counters(true)?;
    // The architecture checks build their own counters and ignore precise_ip,
    // so one pass covers both settings.
    check_for_arch_bugs(false)
}

/// Refuses a CPU with no PMU configuration, which the checks below would
/// otherwise reach through [`get_pmu_config`] and panic on.
#[cfg(target_arch = "x86_64")]
fn require_pmu_config(configured: bool) -> Result<(), PmuValidationError> {
    if configured {
        return Ok(());
    }
    let features = raw_cpuid::CpuId::new()
        .get_feature_info()
        .ok_or(PmuValidationError::CouldNotReadCpuInfo)?;
    Err(PmuValidationError::UnsupportedCpu {
        family: features.family_id(),
        model: features.model_id(),
    })
}

/// Every aarch64 CPU gets a configuration.
#[cfg(target_arch = "aarch64")]
fn require_pmu_config(_configured: bool) -> Result<(), PmuValidationError> {
    Ok(())
}

/// This function is transcribed from the function with the same name in
/// [Mozilla-RR](https://github.com/rr-debugger/rr/blob/master/src/PerfCounters.cc#L227)
/// Checks for a bug in (supposedly) Linux Kernel < 3.7 where period changes
/// do not happen until after the _next_ rollover.
fn check_for_ioc_period_bug(precise_ip: bool) -> Result<(), PmuValidationError> {
    // Start a cycles counter
    let mut attr = ticks_attr(precise_ip);
    attr.__bindgen_anon_1.sample_period = 0xffffffff;
    attr.set_exclude_callchain_kernel(1);
    let bug_fd = start_counter(0, -1, &mut attr, None)?;

    let mut new_period = 1_u64;

    let _ioctl = ioctl(&bug_fd, perf::PERIOD.into(), &mut new_period)?;

    let mut poll_bug_fd = libc::pollfd {
        fd: bug_fd.0,
        events: libc::POLLIN,
        revents: 0,
    };

    let _poll = Errno::result(unsafe { libc::poll(&mut poll_bug_fd as *mut libc::pollfd, 1, 0) })
        .map_err(|errno| PmuValidationError::UnexpectedTestingErrnoError {
        errno,
        msg: "poll syscall failed  in ioc period bug check",
    })?;

    if poll_bug_fd.revents == 0 {
        Err(PmuValidationError::IocPeriodBugDetected)
    } else {
        Ok(())
    }
}

fn start_counter(
    tid: libc::pid_t,
    group_fd: libc::c_int,
    attr: &mut perf::perf_event_attr,
    mut disabled_txcp: Option<&mut bool>,
) -> Result<ScopedFd, PmuValidationError> {
    attr.set_pinned((group_fd == -1) as u64);

    if let Some(disabled) = disabled_txcp.as_mut() {
        **disabled = false
    }

    let open = crate::launch_window::TransientOpen::begin();
    let fd_result = Errno::result(unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr as *mut perf::perf_event_attr,
            tid,
            -1,
            group_fd,
            perf::PERF_FLAG_FD_CLOEXEC,
        )
    });

    match &fd_result {
        Err(Errno::EINVAL) if attr.config & IN_TXCP > 0 => {
            // The kernel might not support IN_TXCP, so try again without it.
            let mut tmp_attr = *attr;
            tmp_attr.config &= !IN_TXCP;

            let no_txcp_fd = Errno::result(unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    &tmp_attr,
                    tid,
                    -1,
                    group_fd,
                    perf::PERF_FLAG_FD_CLOEXEC,
                )
            });

            if no_txcp_fd.is_ok() {
                if let Some(disabled) = disabled_txcp.as_mut() {
                    **disabled = true
                }
                warn_after_guards("kernel does not support IN_TXCP".to_owned());
            }

            no_txcp_fd
        }
        _ => fd_result,
    }
    .map(|raw_fd| ScopedFd(raw_fd as i32, open))
    .map_err(|errno| match errno {
        Errno::EACCES => PmuValidationError::CouldNotCreateTimer {
            errno,
            msg: "Permission denied to use 'perf_event_open'; are hardware perf events \
                available? See https://github.com/rr-debugger/rr/wiki/Will-rr-work-on-my-system",
        },
        Errno::ENOENT => PmuValidationError::CouldNotCreateTimer {
            errno,
            msg: "Unable to open performance counter with 'perf_event_open'; \
                are hardware perf events available? See \
                https://github.com/rr-debugger/rr/wiki/Will-rr-work-on-my-system",
        },
        _ => PmuValidationError::CouldNotCreateTimer {
            errno,
            msg: "See - https://man7.org/linux/man-pages/man3/errno.3.html",
        },
    })
}

fn ioctl(
    fd: &ScopedFd,
    request: libc::c_ulong,
    argument: &mut u64,
) -> Result<libc::c_int, PmuValidationError> {
    Errno::result(unsafe { libc::ioctl(fd.0, request, argument as *mut u64) }).map_err(|errno| {
        PmuValidationError::UnexpectedTestingErrnoError {
            errno,
            msg: "ioctl syscall failed",
        }
    })
}

/// read from the given file descriptor assuming it is a counter
fn read_counter(fd: &ScopedFd) -> Result<i64, PmuValidationError> {
    let mut val: i64 = 0;
    let val_size = mem::size_of_val(&val);
    let nread = Errno::result(unsafe {
        libc::read(fd.0, &mut val as *mut _ as *mut libc::c_void, val_size)
    })
    .map_err(|errno| PmuValidationError::UnexpectedTestingErrnoError {
        errno,
        msg: "Failed to read from a counter",
    })?;

    if nread != val_size as isize {
        Err(PmuValidationError::UnexpectedTestingError(format!(
            "Expected to read {} bytes from counter, but read {}",
            val_size, nread
        )))
    } else {
        Ok(val)
    }
}

/// Transcription of the function with the same name in mozilla-rr to check
/// for the bug where hardware counters simply don't work or only one hardware
/// counter works
fn check_working_counters(precise_ip: bool) -> Result<(), PmuValidationError> {
    let mut attr = ticks_attr(precise_ip);
    let mut attr2 = cycles_attr(precise_ip);

    let fd = start_counter(0, -1, &mut attr, None)?;
    let fd2 = start_counter(0, -1, &mut attr2, None)?;

    do_branches(NUM_BRANCHES);

    let events = read_counter(&fd)?;
    let events2 = read_counter(&fd2)?;

    if events < NUM_BRANCHES as i64 {
        Err(PmuValidationError::HardwareCountersNotWorking {
            actual_events: events,
            expected_min_events: NUM_BRANCHES,
            config: attr.config,
        })
    } else if events2 == 0 {
        Err(PmuValidationError::OnlyOnePerformanceCounter)
    } else {
        Ok(())
    }
}

/// check the cpu feature id to determine if it is a AMD-Zen vs AmdF15R30
#[cfg(target_arch = "x86_64")]
fn is_amd_zen(fi: raw_cpuid::FeatureInfo) -> bool {
    match fi.family_id() {
        0x17 => true, // Zen 1 / Zen 2
        0x19 => true, // Zen 3 / Zen 4
        0x1A => true, // Zen 5
        _ => false,
    }
}

/// This is a transcription of the function with the same name in Mozilla-RR it will
/// check for bugs specific to cpu architectures
#[cfg(target_arch = "x86_64")]
fn check_for_arch_bugs(_precise_ip: bool) -> Result<(), PmuValidationError> {
    let c = raw_cpuid::CpuId::new();
    let vendor = c
        .get_vendor_info()
        .ok_or(PmuValidationError::CouldNotReadCpuInfo)?;
    let feature_info = c
        .get_feature_info()
        .ok_or(PmuValidationError::CouldNotReadCpuInfo)?;
    let vendor_str = vendor.as_str();

    match vendor_str {
        "AuthenticAMD" if is_amd_zen(feature_info) => check_for_zen_speclockmap(),
        "GenuineIntel" => {
            check_for_kvm_in_txcp_bug()?;
            Ok(())
        }
        s => Err(PmuValidationError::UnknownCpuVendor(s.to_owned())),
    }
}

#[cfg(target_arch = "aarch64")]
fn check_for_arch_bugs(_precise_ip: bool) -> Result<(), PmuValidationError> {
    // TODO: Do some aarch64-specific testing?
    Ok(())
}

/// How many locked instructions [`check_for_zen_speclockmap`] executes. On an
/// AMD EPYC 9D64 (family 0x19, model 0xA0) with SpecLockMap enabled, a single
/// locked instruction left the SpecLockMap counter unchanged in 15 of 16 runs,
/// while 100,000 moved it by 91 to 2,374 in 16 of 16, and the retired-branch
/// counter over-counted by 2 to 4 branches around locked instructions. Where
/// SpecLockMap is disabled the counter stayed at 0 over 100,000. See
/// https://github.com/rrnewton/hermit/issues/3794. The loop takes about a
/// millisecond and runs once per process.
#[cfg(target_arch = "x86_64")]
const SPECLOCKMAP_LOCKED_INSTRUCTIONS: usize = 100_000;
#[cfg(target_arch = "x86_64")]
const _: () = assert!(
    SPECLOCKMAP_LOCKED_INSTRUCTIONS >= 100_000,
    "fewer locked instructions miss SpecLockMap on some Zen CPUs"
);

/// AMD PMCx025, retired locked instructions, with every unit mask. User
/// mode only, as rr's `0x5100xx` events are. With SpecLockMap disabled it
/// counted exactly 100,000 of 100,000 locked instructions on AMD EPYC 9D25
/// (family 0x1A, model 0x11; 186 runs) and 9D85 hosts. With SpecLockMap
/// enabled, an AMD EPYC 9D64 (family 0x19, model 0xA0) counted only 59 to
/// 56,833 (51 runs). It is unmeasured on other Zen 2, 3 and 4 parts, where it
/// may count fewer than every locked instruction even with SpecLockMap
/// disabled; the check then refuses as inconclusive rather than pass.
#[cfg(target_arch = "x86_64")]
use reverie::pmu_config::RETIRED_LOCK_INSTRUCTIONS_EVENT;

/// AMD PMCx025 with unit mask 0x08, SpecLockMapCommit: the locked
/// instructions that retired through SpecLockMap. rr's Zen check uses the
/// same event.
#[cfg(target_arch = "x86_64")]
const SPECLOCKMAP_COMMIT_EVENT: u64 = 0x510825;

/// What [`count_speclockmap_commits`] counted over its locked-instruction loop.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpecLockMapCounts {
    /// Retired locked instructions, [`RETIRED_LOCK_INSTRUCTIONS_EVENT`].
    locked_instructions: i64,
    /// SpecLockMap commits among them, [`SPECLOCKMAP_COMMIT_EVENT`].
    speclockmap_commits: i64,
}

#[cfg(target_arch = "x86_64")]
fn check_for_zen_speclockmap() -> Result<(), PmuValidationError> {
    speclockmap_verdict(count_speclockmap_commits()?)
}

/// Executes [`SPECLOCKMAP_LOCKED_INSTRUCTIONS`] locked instructions and counts
/// them, and the SpecLockMap commits among them, on two counters opened
/// together.
#[cfg(target_arch = "x86_64")]
fn count_speclockmap_commits() -> Result<SpecLockMapCounts, PmuValidationError> {
    // When the SpecLockMap optimization is not disabled, rr will not work
    // reliably (e.g. it would work fine on a single process with a single
    // thread, but not more). When the optimization is disabled, the
    // perf counter for retired lock instructions of type SpecLockMapCommit
    // (on PMC 0x25) stays at 0.
    // See more details at https://github.com/rr-debugger/rr/issues/2034.
    //
    // A locked instruction is not always committed through SpecLockMap, so
    // one locked instruction can leave the counter at 0 on a CPU where the
    // optimization is enabled. Execute many, and count them, so a zero is
    // only believed when the locked instructions were seen.
    let mut locked_attr =
        init_perf_event_attr(perf::PERF_TYPE_RAW, RETIRED_LOCK_INSTRUCTIONS_EVENT, false);
    let mut commit_attr =
        init_perf_event_attr(perf::PERF_TYPE_RAW, SPECLOCKMAP_COMMIT_EVENT, false);

    let locked_fd = start_counter(0, -1, &mut locked_attr, None)?;
    let commit_fd = start_counter(0, -1, &mut commit_attr, None)?;

    let locked_before = read_counter(&locked_fd)?;
    let commits_before = read_counter(&commit_fd)?;
    execute_locked_instructions(SPECLOCKMAP_LOCKED_INSTRUCTIONS);
    let speclockmap_commits = read_counter(&commit_fd)? - commits_before;
    let locked_instructions = read_counter(&locked_fd)? - locked_before;
    Ok(SpecLockMapCounts {
        locked_instructions,
        speclockmap_commits,
    })
}

/// Accepts the host only if none of the loop's locked instructions committed
/// through SpecLockMap and all of them were counted. Commits are checked
/// first: with SpecLockMap enabled, the AMD EPYC 9D64 counted only 59 to
/// 56,833 of the 100,000 locked instructions.
#[cfg(target_arch = "x86_64")]
fn speclockmap_verdict(counts: SpecLockMapCounts) -> Result<(), PmuValidationError> {
    let SpecLockMapCounts {
        locked_instructions,
        speclockmap_commits,
    } = counts;
    if speclockmap_commits > locked_instructions {
        Err(PmuValidationError::UnexpectedTestingError(format!(
            "counted {speclockmap_commits} SpecLockMap commits among only \
             {locked_instructions} locked instructions"
        )))
    } else if speclockmap_commits != 0 {
        Err(PmuValidationError::AmdSpecLockMapShouldBeDisabled {
            speclockmap_commits,
            locked_instructions,
        })
    } else if locked_instructions < SPECLOCKMAP_LOCKED_INSTRUCTIONS as i64 {
        Err(PmuValidationError::SpecLockMapCheckInconclusive {
            counted: locked_instructions,
            executed: SPECLOCKMAP_LOCKED_INSTRUCTIONS,
        })
    } else {
        Ok(())
    }
}

/// Executes `count` locked instructions.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn execute_locked_instructions(count: usize) {
    let word = core::sync::atomic::AtomicUsize::new(0);
    for _ in 0..count {
        // `fetch_add` is a `lock xadd` on x86_64; `black_box` keeps the
        // result, so the compiler can neither drop nor merge the additions.
        core::hint::black_box(word.fetch_add(1, core::sync::atomic::Ordering::SeqCst));
    }
}

#[cfg(target_arch = "x86_64")]
fn check_for_kvm_in_txcp_bug() -> Result<(), PmuValidationError> {
    let mut count: i64 = 0;
    let mut attr = ticks_attr(false);
    attr.config |= IN_TXCP;
    attr.__bindgen_anon_1.sample_period = 0;
    let mut disabled_txcp = false;
    let fd = start_counter(0, -1, &mut attr, Some(&mut disabled_txcp))?;

    let mut arg = 0_u64;

    if !disabled_txcp {
        ioctl(&fd, perf::DISABLE.into(), &mut arg)?;
        ioctl(&fd, perf::ENABLE.into(), &mut arg)?;
        do_branches(NUM_BRANCHES);
        count = read_counter(&fd)?;
    }

    let supports_txcp = count > 0;
    if supports_txcp && count < NUM_BRANCHES as i64 {
        Err(PmuValidationError::IntelKvmInTxcpBugDetected)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::perf::is_perf_supported;

    /// The SpecLockMap check must execute and count its locked instructions;
    /// a single one misses the bug on CPUs where only some locked
    /// instructions commit through SpecLockMap
    /// (https://github.com/rrnewton/hermit/issues/3794).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn speclockmap_check_counts_its_locked_instructions() {
        let c = raw_cpuid::CpuId::new();
        let amd_zen = c.get_vendor_info().map(|v| v.as_str() == "AuthenticAMD") == Some(true)
            && c.get_feature_info().is_some_and(is_amd_zen);
        if !is_perf_supported() || !amd_zen {
            return;
        }
        let counts = count_speclockmap_commits().unwrap();
        assert!(
            (0..=counts.locked_instructions).contains(&counts.speclockmap_commits),
            "{counts:?}"
        );
        // Where SpecLockMap is on, the locked-instruction event can count far
        // fewer than the loop executed (9 to 18,886 of 100,000 on a 9D64), so
        // the full count is required only where nothing committed.
        if counts.speclockmap_commits == 0 {
            assert!(
                counts.locked_instructions >= SPECLOCKMAP_LOCKED_INSTRUCTIONS as i64,
                "{counts:?}: expected at least {SPECLOCKMAP_LOCKED_INSTRUCTIONS} locked instructions"
            );
        }
        // Whatever this host's SpecLockMap setting, the check reports these
        // same counts, not some other verdict.
        match check_for_zen_speclockmap() {
            Ok(()) => assert_eq!(
                counts.speclockmap_commits, 0,
                "{counts:?}: the check passed on a host whose count saw SpecLockMap commits"
            ),
            Err(PmuValidationError::AmdSpecLockMapShouldBeDisabled {
                speclockmap_commits,
                locked_instructions,
            }) => assert!(
                (1..=locked_instructions).contains(&speclockmap_commits),
                "{speclockmap_commits} of {locked_instructions}"
            ),
            Err(error) => panic!("SpecLockMap check failed - {error}"),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn speclockmap_verdict_refuses_any_commit_and_an_uncounted_loop() {
        let n = SPECLOCKMAP_LOCKED_INSTRUCTIONS as i64;
        let counts = |locked_instructions, speclockmap_commits| SpecLockMapCounts {
            locked_instructions,
            speclockmap_commits,
        };
        assert!(speclockmap_verdict(counts(n, 0)).is_ok());
        assert!(speclockmap_verdict(counts(n + 723, 0)).is_ok());
        for commits in [1, 91, n] {
            match speclockmap_verdict(counts(n, commits)) {
                Err(PmuValidationError::AmdSpecLockMapShouldBeDisabled {
                    speclockmap_commits,
                    locked_instructions,
                }) => assert_eq!((speclockmap_commits, locked_instructions), (commits, n)),
                other => panic!("{commits} commits: {other:?}"),
            }
        }
        // Counts seen together on an AMD EPYC 9D64 with SpecLockMap enabled,
        // whose retired-lock counter under-counts.
        for (locked, commits) in [(9, 8), (230, 89), (18886, 15570)] {
            match speclockmap_verdict(counts(locked, commits)) {
                Err(PmuValidationError::AmdSpecLockMapShouldBeDisabled {
                    speclockmap_commits,
                    locked_instructions,
                }) => assert_eq!(
                    (speclockmap_commits, locked_instructions),
                    (commits, locked)
                ),
                other => panic!("{locked} locked, {commits} commits: {other:?}"),
            }
        }
        for locked in [0, 1, n - 1] {
            match speclockmap_verdict(counts(locked, 0)) {
                Err(PmuValidationError::SpecLockMapCheckInconclusive { counted, executed }) => {
                    assert_eq!(
                        (counted, executed),
                        (locked, SPECLOCKMAP_LOCKED_INSTRUCTIONS)
                    )
                }
                other => panic!("{locked} locked: {other:?}"),
            }
        }
        assert!(matches!(
            speclockmap_verdict(counts(n, n + 1)),
            Err(PmuValidationError::UnexpectedTestingError(_))
        ));
    }

    /// A CPU with no profile is refused with its family and model, where the
    /// checks would otherwise panic in `get_pmu_config`.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn unconfigured_cpu_is_refused_not_panicked_on() {
        assert!(require_pmu_config(true).is_ok());
        let features = raw_cpuid::CpuId::new().get_feature_info().unwrap();
        match require_pmu_config(false) {
            Err(PmuValidationError::UnsupportedCpu { family, model }) => {
                assert_eq!((family, model), (features.family_id(), features.model_id()))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_check_for_ioc_period_bug() {
        if !is_perf_supported() {
            return;
        }

        // This assumes the machine running the test will not have this bug
        if let Err(pmu_err) = check_for_ioc_period_bug(false) {
            panic!("Ioc period bug check failed - {}", pmu_err);
        }
    }

    #[test]
    fn test_check_working_counters() {
        if !is_perf_supported() {
            return;
        }

        // This assumes the machine running the test will have working counters
        if let Err(pmu_err) = check_working_counters(false) {
            panic!("Working counters check failed - {}", pmu_err);
        }
    }

    #[test]
    fn test_check_for_arch_bugs() {
        if !is_perf_supported() {
            return;
        }

        // This assumes the machine running the test will not have arch bugs.
        match check_for_arch_bugs(false) {
            Ok(()) => {}
            // Whether the AMD Zen SpecLockMap optimization is disabled is a host
            // BIOS/firmware setting, not a defect in this code. Self-hosted CI
            // runners may leave it enabled, so treat that specific condition as a
            // skip while still failing on any other (unexpected) validation error.
            #[cfg(target_arch = "x86_64")]
            Err(PmuValidationError::AmdSpecLockMapShouldBeDisabled { .. }) => {
                eprintln!(
                    "skipping arch-bug check: host has AMD Zen SpecLockMap enabled \
                     (a firmware setting, not a code bug); see \
                     https://github.com/rr-debugger/rr/wiki/Zen"
                );
            }
            Err(pmu_err) => panic!("Architecture-specific bug check failed - {}", pmu_err),
        }
    }

    #[test]
    fn test_check_for_ioc_period_bug_precise_ip() {
        // This assumes the machine running the test will not have this bug and only runs
        // if precise_ip will be enabled
        if has_precise_ip()
            && let Err(pmu_err) = check_for_ioc_period_bug(true)
        {
            panic!(
                "Ioc period bug check failed when precise_ip was enabled - {}",
                pmu_err
            );
        }
    }

    #[test]
    fn test_check_working_counters_precise_ip() {
        // This assumes the machine running the test will have working counters and only runs
        // if precise_ip will be enabled
        if has_precise_ip()
            && let Err(pmu_err) = check_working_counters(true)
        {
            panic!(
                "Working counters check failed when precise_ip was enabled - {}",
                pmu_err
            );
        }
    }

    #[test]
    fn test_check_for_arch_bugs_precise_ip() {
        // This assumes the machine running the test will not have arch bugs and only runs
        // if precise_ip will be enabled
        if has_precise_ip() {
            match check_for_arch_bugs(true) {
                Ok(()) => {}
                // See test_check_for_arch_bugs: SpecLockMap is a host firmware
                // setting, so tolerate that specific condition here as well.
                #[cfg(target_arch = "x86_64")]
                Err(PmuValidationError::AmdSpecLockMapShouldBeDisabled { .. }) => {
                    eprintln!(
                        "skipping arch-bug check (precise_ip): host has AMD Zen \
                         SpecLockMap enabled (a firmware setting, not a code bug)"
                    );
                }
                Err(pmu_err) => panic!(
                    "Architecture-specific bug check failed when precise_ip was enabled - {}",
                    pmu_err
                ),
            }
        }
    }
}
