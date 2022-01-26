/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::perf::do_branches;
use crate::timer::{get_rcb_perf_config, AMD_VENDOR, INTEL_VENDOR};
use core::mem;
use perf_event_open_sys::bindings as perf;
use raw_cpuid::{CpuId, FeatureInfo};
use reverie::Errno;
use std::hint::black_box;
use thiserror::Error;
use tracing::{error, warn};

const IN_TXCP: u64 = 1 << 33;
const NUM_BRANCHES: u64 = 500;

/// Way to keep track of the validation error when checking for pmu bugs
#[derive(Error, Debug)]
pub(crate) enum PmuValidationError {
    #[error("Failed to create timer: {errno:?} - {msg}")]
    CouldNotCreateTimer { errno: Errno, msg: &'static str },

    #[error("Unexpected error while checking for pmu bugs: {errno:?} - {msg}")]
    UnexpectedTestingErrnoError { errno: Errno, msg: &'static str },

    #[error("Unexpected error while checking for pmu bugs: {0}")]
    UnexpectedTestingError(String),

    #[error("The ioc-period bug was detected")]
    IocPeriodBugDetected,

    #[error("Could not read cpu info")]
    CouldNotReadCpuInfo,

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
        actual_events: i64,
        expected_min_events: u64,
        config: u64,
    },

    #[error("Your CPU only supports one performance counter in its current configuration")]
    OnlyOnePerformanceCounter,

    #[error(
        "On AMD Zen CPUs, reverie timers will not work reliably unless you disable the \
        hardware SpecLockMap optimization. For instructions on how to \
        do this, see https://github.com/rr-debugger/rr/wiki/Zen"
    )]
    AmdSpecLockMapShouldBeDisabled,

    #[error("Intel Kvm-In-Txcp bug found")]
    IntelKvmInTxcpBugDetected,

    #[error("Overcount triggered by PMU interrupts detected due to Xen PMU virtualization bug")]
    IntelXenPmiBugDetected,
}

fn init_perf_event_attr(perf_attr_type: u32, config: u64) -> perf::perf_event_attr {
    let mut result = perf::perf_event_attr {
        type_: perf_attr_type,
        config,
        ..Default::default()
    };
    result.size = mem::size_of_val(&result) as u32;
    result.set_exclude_guest(1);
    result.set_exclude_kernel(1);

    result
}

/// Create a template perf_event_attr for ticks
fn ticks_attr() -> perf::perf_event_attr {
    init_perf_event_attr(perf::perf_type_id_PERF_TYPE_RAW, get_rcb_perf_config())
}

/// Create a template perf_event_attr for cycles
fn cycles_attr() -> perf::perf_event_attr {
    init_perf_event_attr(
        perf::perf_type_id_PERF_TYPE_HARDWARE,
        perf::perf_hw_id_PERF_COUNT_HW_CPU_CYCLES.into(),
    )
}

#[derive(Debug)]
struct ScopedFd(i32);

impl From<i64> for ScopedFd {
    fn from(fd: i64) -> Self {
        ScopedFd(fd as i32)
    }
}

impl Drop for ScopedFd {
    fn drop(&mut self) {
        if let Err(errno) = Errno::result(unsafe { libc::close(self.0) }) {
            warn!("Error while closing file descriptor - {:?}", errno);
        }
    }
}

/// This function is a transcription of the function `check_for_bugs` from
/// [Mozilla-RR](https://github.com/rr-debugger/rr/blob/master/src/PerfCounters.cc#L308)
/// It checks for a collection of processor features that ensure that the pmu features
/// required from Reverie to function correctly are available and trustworthy
pub(crate) fn check_for_pmu_bugs() -> Result<(), PmuValidationError> {
    check_for_ioc_period_bug()
        .and(check_working_counters())
        .and(check_for_arch_bugs())
}

/// This function is transcribed from the function with the same name in
/// [Mozilla-RR](https://github.com/rr-debugger/rr/blob/master/src/PerfCounters.cc#L227)
/// Checks for a bug in (supposedly) Linux Kernel < 3.7 where period changes
/// do not happen until after the _next_ rollover.
fn check_for_ioc_period_bug() -> Result<(), PmuValidationError> {
    // Start a cycles counter
    let mut attr = ticks_attr();
    attr.__bindgen_anon_1.sample_period = 0xffffffff;
    attr.set_exclude_callchain_kernel(1);
    let bug_fd = start_counter(0, -1, &mut attr, None)?;

    let mut new_period = 1_u64;

    let _ioctl = ioctl(
        &bug_fd,
        perf::perf_event_ioctls_PERIOD.into(),
        &mut new_period,
    )?;

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
                warn!("kernel does not support IN_TXCP");
            }

            no_txcp_fd
        }
        _ => fd_result,
    }
    .map(|raw_fd| raw_fd.into())
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
fn check_working_counters() -> Result<(), PmuValidationError> {
    let mut attr = ticks_attr();
    attr.__bindgen_anon_1.sample_period = 0;
    let mut attr2 = cycles_attr();
    attr2.__bindgen_anon_1.sample_period = 0;

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
/// This is much simpler in c++ because eax is available directly
fn is_amd_zen(cpu_feature: FeatureInfo) -> bool {
    let family_id = cpu_feature.family_id(); // 4 bits
    let model_id = cpu_feature.model_id(); // 4 bits
    let ext_model_id = cpu_feature.extended_model_id(); // 4 bits
    let ext_family_id = cpu_feature.extended_family_id(); // 8 bits

    // This is reconstructing cpu_info.eax & 0xf0ff0
    let cpu_type: u32 =
        ((model_id as u32) << 4) + ((family_id as u32) << 8) + ((ext_model_id as u32) << 16);

    // There are lots of magic numbers here. They come  directly from
    // https://github.com/rr-debugger/rr/blob/master/src/PerfCounters_x86.h
    matches!(
        (cpu_type, ext_family_id),
        (
            0x00f10 // Naples, Whitehaven, Summit Ridge, Snowy Owl (Zen), Milan (Zen 3) (UNTESTED)
            | 0x10f10 // Raven Ridge, Great Horned Owl (Zen) (UNTESTED)
            | 0x10f80 // Banded Kestrel (Zen), Picasso (Zen+) (UNTESTED)
            | 0x20f00 // Dali (Zen) (UNTESTED)
            | 0x00f80 // Colfax, Pinnacle Ridge (Zen+) (UNTESTED)
            | 0x30f10 // Rome, Castle Peak (Zen 2)
            | 0x60f00 // Renoir (Zen 2) (UNTESTED)
            | 0x70f10 // Matisse (Zen 2) (UNTESTED)
            | 0x60f80, // Lucienne
            0x8 | 0xa
        ) | (
            0x20f10 // Vermeer (Zen 3)
            | 0x50f00, // Cezanne (Zen 3)
            0xa
        )
    )
}

/// This is a transcription of the function with the same name in Mozilla-RR it will
/// check for bugs specific to cpu architectures
fn check_for_arch_bugs() -> Result<(), PmuValidationError> {
    let c = CpuId::new();
    let vendor = c.get_vendor_info().unwrap();
    let feature_info = c
        .get_feature_info()
        .ok_or(PmuValidationError::CouldNotReadCpuInfo)?;
    let vendor_str = vendor.as_string();

    match vendor_str {
        AMD_VENDOR if is_amd_zen(feature_info) => check_for_zen_speclockmap(),
        INTEL_VENDOR => check_for_kvm_in_txcp_bug().and(check_for_xen_pmi_bug()),
        s => panic!("Unknown CPU vendor: {}", s),
    }
}

fn check_for_zen_speclockmap() -> Result<(), PmuValidationError> {
    // When the SpecLockMap optimization is not disabled, rr will not work
    // reliably (e.g. it would work fine on a single process with a single
    // thread, but not more). When the optimization is disabled, the
    // perf counter for retired lock instructions of type SpecLockMapCommit
    // (on PMC 0x25) stays at 0.
    // See more details at https://github.com/rr-debugger/rr/issues/2034.

    // 0x25 == RETIRED_LOCK_INSTRUCTIONS - Counts the number of retired locked instructions
    // + 0x08 == SPECLOCKMAPCOMMIT
    let mut attr = init_perf_event_attr(perf::perf_type_id_PERF_TYPE_RAW, 0x510825);

    let fd = start_counter(0, -1, &mut attr, None)?;

    let val = 20_usize;
    let to_add = 22_usize;
    let count = read_counter(&fd)?;

    // A lock add is known to increase the perf counter we're looking at.
    #[allow(deprecated)]
    unsafe {
        let _prev: usize;
        llvm_asm!("lock; xaddq $2, $1"
            : "=r" (_prev), "+*m" (&val)
            : "0" (to_add)
            : "memory"
            : "volatile");
    }

    if read_counter(&fd)? != count {
        Err(PmuValidationError::AmdSpecLockMapShouldBeDisabled)
    } else {
        Ok(())
    }
}

fn check_for_kvm_in_txcp_bug() -> Result<(), PmuValidationError> {
    let mut count: i64 = 0;
    let mut attr = ticks_attr();
    attr.config |= IN_TXCP;
    attr.__bindgen_anon_1.sample_period = 0;
    let mut disabled_txcp = false;
    let fd = start_counter(0, -1, &mut attr, Some(&mut disabled_txcp))?;

    let mut arg = 0_u64;

    if !disabled_txcp {
        ioctl(&fd, perf::perf_event_ioctls_DISABLE.into(), &mut arg)?;
        ioctl(&fd, perf::perf_event_ioctls_ENABLE.into(), &mut arg)?;
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

fn check_for_xen_pmi_bug() -> Result<(), PmuValidationError> {
    let mut count: i32;
    let mut attr = ticks_attr();
    attr.__bindgen_anon_1.sample_period = NUM_BRANCHES - 1;
    let fd = start_counter(0, -1, &mut attr, None)?;

    // The original C++ uses `rand()` to make sure this isn't optimized around.
    // We will use black_box to do the same thing without introducing variability

    fn make_accumulator_seed() -> u32 {
        20764791
    }

    let mut accumulator = black_box(make_accumulator_seed());
    let mut expected_accumulator = accumulator;

    // reproduce the assembly here to calculate what the final accumulator value should be
    for _ in 0..(NUM_BRANCHES - 2) {
        let temp_exp_accumulator = expected_accumulator.overflowing_shl(3).0;
        expected_accumulator = temp_exp_accumulator
            .overflowing_sub(expected_accumulator)
            .0
            .overflowing_add(2)
            .0
            & 0xffffff;
    }

    let raw_fd = fd.0;

    #[allow(deprecated)]
    unsafe {
        llvm_asm!(
            "
            mov $2, %rax;
            mov $9, %edi;
            xor %rdx, %rdx;
            mov $4, %rsi;
            syscall;
            cmp $$-4095, %rax;
            jae 2f;
            mov $2, %rax;
            mov $6, %rsi;
            syscall;
            /* From this point on all conditional branches count! */
            cmp $$-4095, %rax;
            jae 2f;
            /* Reset the counter period to the desired value. */
            mov $2, %rax;
            mov $5, %rsi;
            mov $8, %rdx;
            syscall;
            cmp $$-4095, %rax;
            jae 2f;
            mov $7, %rax;
            1: dec %rax;
            /* Multiply by 7. */
            mov $0, %edx;
            shl $$3, $0;
            sub %edx, $0;
            /* Add 2. */
            add $$2, $0;
            /* Mask off bits. */
            and $$0xffffff, $0;
            /* And loop. */
            test %rax, %rax;
            jnz 1b;
            mov $3, %rsi;
            mov $2, %rax;
            xor %rdx, %rdx;
            /* We didn't touch rdi. */
            syscall;
            cmp $$-4095, %rax;
            jae 2f;
            movl $$0, $1;
            2: nop;"
            :
            "+r"(accumulator),
            "=r"(count)
            :
            "i"(libc::SYS_ioctl)
            ,
            "i"(perf::perf_event_ioctls_DISABLE),
            "i"(perf::perf_event_ioctls_ENABLE),
            "i"(perf::perf_event_ioctls_PERIOD),
            "i"(perf::perf_event_ioctls_RESET),
            // The check for the failure of some of our ioctls is in
            // the measured region, so account for that when looping.
            "i"(NUM_BRANCHES - 2),
            "rm"(&attr.__bindgen_anon_1.sample_period), "rm"(raw_fd)
            :
            "rax", "rdx", "rdi", "rsi"
            /* `syscall` clobbers rcx and r11. */
            ,
            "rcx", "r11"
            : "volatile"
        );
    }

    // If things worked above, `count` should have been set to 0.
    if count == 0 {
        count = read_counter(&fd)? as i32;
    }

    // Use 'accumulator' so it can't be optimized out.
    if accumulator != expected_accumulator {
        return Err(PmuValidationError::UnexpectedTestingError(format!(
            "Unexpected accumulator value in xen pmi bug check. Expected {}, but was {}",
            expected_accumulator, accumulator
        )));
    }

    let has_xen_pmi_bug = (count > 0 && count as u64 > NUM_BRANCHES) || count == -1;

    if has_xen_pmi_bug {
        Err(PmuValidationError::IntelXenPmiBugDetected)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_check_for_ioc_period_bug() {
        // This assumes the machine running the test will not have this bug
        if let Err(pmu_err) = check_for_ioc_period_bug() {
            panic!("Ioc period bug check failed - {}", pmu_err);
        }
    }

    #[test]
    fn test_check_working_counters() {
        // This assumes the machine running the test will have working counters
        if let Err(pmu_err) = check_working_counters() {
            panic!("Working counters check failed - {}", pmu_err);
        }
    }

    #[test]
    fn test_check_for_arch_bugs() {
        // This assumes the machine running the test will not have arch bugs
        if let Err(pmu_err) = check_for_arch_bugs() {
            panic!("Architecture-specific bug check failed - {}", pmu_err);
        }
    }
}
