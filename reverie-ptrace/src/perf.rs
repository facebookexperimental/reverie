/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Provides a more rustic interface to a minimal set of `perf` functionality.
//!
//! Explicitly missing (because they are unnecessary) perf features include:
//! * Grouping
//! * Sample type flags
//! * Reading any kind of sample events
//! * BPF
//! * Hardware breakpoints
//!
//! The arguments and behaviors in this module generally correspond exactly to
//! those of `perf_event_open(2)`. No attempts are made to paper over the
//! non-determinism/weirndess of `perf`. For example, counter increments are
//! dropped whenever an event fires on a running thread.
//! [`PerfCounter::DISABLE_SAMPLE_PERIOD`] can be used to avoid this for sampling.
//! events.

use core::ptr::NonNull;
#[allow(unused_imports)] // only used if we have an error
use std::compile_error;
use std::sync::LazyLock;

use nix::sys::signal::Signal;
use nix::unistd::SysconfVar;
use nix::unistd::sysconf;
use perf_event_open_sys::bindings as perf;
use perf_event_open_sys::ioctls;
use reverie::Errno;
use reverie::Tid;
use tracing::error;
use tracing::warn;

use crate::validation::PmuValidationError;
use crate::validation::check_for_pmu_bugs;

static PMU_BUG: LazyLock<Result<(), PmuValidationError>> = LazyLock::new(check_for_pmu_bugs);

// Not available in the libc crate
const F_SETOWN_EX: libc::c_int = 15;
const F_SETSIG: libc::c_int = 10;
const F_OWNER_TID: libc::c_int = 0;
#[repr(C)]
struct f_owner_ex {
    pub type_: libc::c_int,
    pub pid: libc::pid_t,
}

/// An incomplete enumeration of events perf can monitor
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Event {
    #[allow(dead_code)] // used in tests
    /// A perf-supported hardware event.
    Hardware(HardwareEvent),
    /// A perf-supported software event.
    Software(SoftwareEvent),
    /// A raw CPU event. The inner value will have a CPU-specific meaning.
    Raw(u64),
}

/// An incomplete enumeration of hardware events perf can monitor.
#[allow(dead_code)] // used in tests
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HardwareEvent {
    /// Count retired instructions. Can be affected by hardware interrupt counts.
    Instructions,
    /// Count retired branch instructions.
    BranchInstructions,
}

/// An incomplete enumeration of software events perf can monitor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SoftwareEvent {
    /// A placeholder event that counts nothing.
    Dummy,
}

/// A perf counter with a very limited range of configurability.
/// Construct via [`Builder`].
#[derive(Debug)]
pub struct PerfCounter {
    fd: libc::c_int,
    mmap: Option<NonNull<perf::perf_event_mmap_page>>,
    records: Option<SampleRecords>,
    raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
    /// Calls on this counter that change its programming, successful or not
    /// (see [`PerfCounter::programmings`]).
    programmings: std::sync::atomic::AtomicU64,
}

/// A ring buffer mapping that receives the sample records of a counter.
#[derive(Debug)]
struct SampleRecords {
    page: NonNull<perf::perf_event_mmap_page>,
    len: usize,
}

impl Event {
    fn attr_type(self) -> u32 {
        match self {
            Event::Hardware(_) => perf::PERF_TYPE_HARDWARE,
            Event::Software(_) => perf::PERF_TYPE_SOFTWARE,
            Event::Raw(_) => perf::PERF_TYPE_RAW,
        }
    }

    fn attr_config(self) -> u64 {
        match self {
            Event::Raw(x) => x,
            Event::Hardware(HardwareEvent::Instructions) => perf::PERF_COUNT_HW_INSTRUCTIONS.into(),
            Event::Hardware(HardwareEvent::BranchInstructions) => {
                perf::PERF_COUNT_HW_BRANCH_INSTRUCTIONS.into()
            }
            Event::Software(SoftwareEvent::Dummy) => perf::PERF_COUNT_SW_DUMMY.into(),
        }
    }
}

/// Builder for a PerfCounter. Contains only the subset of the attributes that
/// this API allows manipulating set to non-defaults.
#[derive(Debug, Clone)]
pub struct Builder {
    pid: libc::pid_t,
    cpu: libc::c_int,
    evt: Event,
    sample_period: u64,
    precise_ip: u32,
    fast_reads: bool,
    enable_on_exec: bool,
}

impl Builder {
    /// Initialize the builder. The initial configuration is for a software
    /// counting event that never increments.
    ///
    /// `pid` accepts a *TID* from `gettid(2)`. Passing `getpid(2)` will
    /// monitor the main thread of the calling thread group. Passing `0`
    /// monitors the calling thread. Passing `-1` monitors all threads on
    /// the specified CPU.
    ///
    /// `cpu` should almost always be `-1`, which tracks the specified `pid`
    /// across all CPUs. Non-negative integers track only the specified `pid`
    /// on that CPU.
    ///
    /// Passing `-1` for both `pid` and `cpu` will result in an error.
    pub fn new(pid: libc::pid_t, cpu: libc::c_int) -> Self {
        Self {
            pid,
            cpu,
            evt: Event::Software(SoftwareEvent::Dummy),
            sample_period: 0,
            precise_ip: 0,
            fast_reads: false,
            enable_on_exec: false,
        }
    }

    /// Select the event to monitor.
    pub fn event(&mut self, evt: Event) -> &mut Self {
        self.evt = evt;
        self
    }

    /// Set the period for sample collection. Default is 0, which creates a
    /// counting event.
    ///
    /// Because this module always sets `wakeup_events` to 1, this also
    /// specifies after how many events an overflow notification should be
    /// raised. If a signal has been setup with
    /// `PerfCounter::set_signal_delivery`], this corresponds to one sent
    /// signal. Overflow notifications are sent whenever the counter reaches a
    /// multiple of `sample_period`.
    ///
    /// If you only want accurate counts, pass
    /// `DISABLE_SAMPLE_PERIOD`. Passing `0` will also work, but will create a
    /// _counting_ event that cannot become a _sampling event_ via the
    /// `PERF_EVENT_IOC_PERIOD` ioctl.
    pub fn sample_period(&mut self, period: u64) -> &mut Self {
        self.sample_period = period;
        self
    }

    /// Set `precise_ip` on the underlying perf attribute structure. Valid
    /// values are 0-3; the underlying field is 2 bits.
    ///
    /// Non-zero values will cause perf to attempt to lower the skid of *samples*
    /// (but not necessarily notifications), usually via hardware features like
    /// Intel PEBS.
    ///
    /// Use with caution: experiments have shown that counters with non-zero
    /// `precise_ip` can drop events under certain circumstances. See
    /// `experiments/test_consistency.c` for more information.
    pub fn precise_ip(&mut self, precise_ip: u32) -> &mut Self {
        self.precise_ip = precise_ip;
        self
    }

    /// Enable fast reads via shared memory with the kernel for the latest
    /// counter value.
    pub fn fast_reads(&mut self, enable: bool) -> &mut Self {
        self.fast_reads = enable;
        self
    }

    /// Start this disabled counter when its task first commits exec. The
    /// kernel clears the attribute at that transition; later execs keep the
    /// existing continuous count.
    pub(crate) fn enable_on_exec(&mut self) -> &mut Self {
        self.enable_on_exec = true;
        self
    }

    /// Render the builder into a `PerfCounter`. Created counters begin in a
    /// disabled state. Additional initialization steps should be performed,
    /// followed by a call to [`PerfCounter::enable`].
    pub fn create(&self) -> Result<PerfCounter, Errno> {
        self.create_with_optional_raw_syscall(None)
    }

    pub(crate) fn create_with_raw_syscall(
        &self,
        raw_syscall: unsafe fn(i64, [u64; 6]) -> i64,
    ) -> Result<PerfCounter, Errno> {
        self.create_with_optional_raw_syscall(Some(raw_syscall))
    }

    fn create_with_optional_raw_syscall(
        &self,
        raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
    ) -> Result<PerfCounter, Errno> {
        let mut attr = perf::perf_event_attr::default();
        attr.size = core::mem::size_of_val(&attr) as u32;
        attr.type_ = self.evt.attr_type();
        attr.config = self.evt.attr_config();
        attr.__bindgen_anon_1.sample_period = self.sample_period;
        attr.set_disabled(1); // manual enable, or the initial command exec transition
        attr.set_enable_on_exec(u64::from(self.enable_on_exec));
        attr.set_exclude_kernel(1); // we only care about user code
        attr.set_exclude_guest(1);
        attr.set_exclude_hv(1); // unlikely this is supported, but it doesn't hurt
        attr.set_pinned(1); // error state if we are descheduled from the PMU
        attr.set_precise_ip(self.precise_ip.into());
        attr.__bindgen_anon_2.wakeup_events = 1; // generate a wakeup (overflow) after one sample event

        let pid = self.pid;
        let cpu = self.cpu;
        let group_fd: libc::c_int = -1; // always create a new group
        let flags = perf::PERF_FLAG_FD_CLOEXEC; // marginally more safe if we fork+exec

        let fd = if let Some(raw_syscall) = raw_syscall {
            Errno::from_ret(unsafe {
                raw_syscall(
                    libc::SYS_perf_event_open,
                    [
                        (&raw const attr) as u64,
                        pid as i64 as u64,
                        cpu as i64 as u64,
                        group_fd as i64 as u64,
                        flags.into(),
                        0,
                    ],
                ) as usize
            })?
        } else {
            Errno::result(unsafe {
                libc::syscall(libc::SYS_perf_event_open, &attr, pid, cpu, group_fd, flags)
            })? as usize
        };
        let fd = fd as libc::c_int;

        let mmap = if self.fast_reads {
            let res = if let Some(raw_syscall) = raw_syscall {
                Errno::from_ret(unsafe {
                    raw_syscall(
                        libc::SYS_mmap,
                        [
                            0,
                            get_mmap_size() as u64,
                            libc::PROT_READ as u64,
                            libc::MAP_SHARED as u64,
                            fd as u64,
                            0,
                        ],
                    ) as usize
                })
                .map(|address| address as *mut libc::c_void)
            } else {
                Errno::result(unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        get_mmap_size(),
                        libc::PROT_READ, // leaving PROT_WRITE unset lets us passively read
                        libc::MAP_SHARED,
                        fd,
                        0,
                    )
                })
            };
            match res {
                Ok(ptr) => match NonNull::new(ptr as *mut _) {
                    Some(ptr) => Some(ptr),
                    None => {
                        close_perf_fd(fd, raw_syscall);
                        return Err(Errno::ENOMEM);
                    }
                },
                Err(e) => {
                    close_perf_fd(fd, raw_syscall);
                    return Err(e);
                }
            }
        } else {
            None
        };

        Ok(PerfCounter {
            fd,
            mmap,
            records: None,
            raw_syscall,
            programmings: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub(crate) fn check_for_pmu_bugs(&mut self) -> &mut Self {
        if let Err(pmu_error) = &*PMU_BUG {
            error!(
                error = ?pmu_error,
                "PMU validation failed; RCB timers may be unreliable"
            );
        }
        self
    }
}

impl PerfCounter {
    /// Perf counters cannot be switched from sampling to non-sampling, so
    /// setting their period to this large value effectively disables overflows
    /// and sampling.
    pub const DISABLE_SAMPLE_PERIOD: u64 = 1 << 60;

    /// The number of calls on this counter so far that change its
    /// programming: [`PerfCounter::enable`], [`PerfCounter::disable`],
    /// [`PerfCounter::refresh`], [`PerfCounter::reset`],
    /// [`PerfCounter::set_period`] and [`PerfCounter::set_signal_delivery`],
    /// each counted before its syscall, whether or not it succeeds. Two equal
    /// counts show that no such call was made between them. The timer uses
    /// this to check that a stop that keeps a timer event leaves the event's
    /// programming as its request made it.
    pub(crate) fn programmings(&self) -> u64 {
        self.programmings.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn count_programming(&self) {
        self.programmings
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Call the `PERF_EVENT_IOC_ENABLE` ioctl. Enables increments of the
    /// counter and event generation.
    pub fn enable(&self) -> Result<(), Errno> {
        self.count_programming();
        if let Some(raw_syscall) = self.raw_syscall {
            Errno::from_ret(unsafe {
                raw_syscall(
                    libc::SYS_ioctl,
                    [self.fd as u64, perf::ENABLE as u64, 0, 0, 0, 0],
                ) as usize
            })
            .and(Ok(()))
        } else {
            Errno::result(unsafe { ioctls::ENABLE(self.fd, 0) }).and(Ok(()))
        }
    }

    /// Call the `PERF_EVENT_IOC_ENABLE` ioctl. Disables increments of the
    /// counter and event generation.
    pub fn disable(&self) -> Result<(), Errno> {
        self.count_programming();
        Errno::result(unsafe { ioctls::DISABLE(self.fd, 0) }).and(Ok(()))
    }

    /// Corresponds exactly to the `PERF_EVENT_IOC_REFRESH` ioctl.
    #[allow(dead_code)]
    pub fn refresh(&self, count: libc::c_int) -> Result<(), Errno> {
        self.count_programming();
        assert!(count != 0); // 0 is undefined behavior
        Errno::result(unsafe { ioctls::REFRESH(self.fd, 0) }).and(Ok(()))
    }

    /// Call the `PERF_EVENT_IOC_RESET` ioctl. Resets the counter value to 0,
    /// which results in delayed overflow events.
    pub fn reset(&self) -> Result<(), Errno> {
        self.count_programming();
        if let Some(raw_syscall) = self.raw_syscall {
            Errno::from_ret(unsafe {
                raw_syscall(
                    libc::SYS_ioctl,
                    [self.fd as u64, perf::RESET as u64, 0, 0, 0, 0],
                ) as usize
            })
            .and(Ok(()))
        } else {
            Errno::result(unsafe { ioctls::RESET(self.fd, 0) }).and(Ok(()))
        }
    }

    /// Call the `PERF_EVENT_IOC_PERIOD` ioctl. This causes the counter to
    /// behave as if `ticks` was the original argument to `sample_period` in
    /// the builder.
    pub fn set_period(&self, ticks: u64) -> Result<(), Errno> {
        self.count_programming();
        // The bindings are wrong for this ioctl. The method signature takes a
        // u64, but the actual ioctl expects a pointer to a u64. Thus, we use
        // the constant manually.

        // This ioctl shouldn't mutate it's argument per its API. But in case it
        // does, create a mutable copy to avoid Rust UB.
        let mut ticks = ticks;
        Errno::result(unsafe { libc::ioctl(self.fd, perf::PERIOD as _, &mut ticks as *mut u64) })
            .and(Ok(()))
    }

    /// Call the `PERF_EVENT_IOC_ID` ioctl. Returns a unique identifier for this
    /// perf counter.
    #[allow(dead_code)]
    pub fn id(&self) -> Result<u64, Errno> {
        let mut res = 0u64;
        Errno::result(unsafe { ioctls::ID(self.fd, &mut res as *mut u64) })?;
        Ok(res)
    }

    /// Sets up overflow events to deliver a `SIGPOLL`-style signal, with the
    /// signal number specified in `signal`, to the specified `thread`.
    ///
    /// There is no reason this couldn't be called at any point, but typial use
    /// cases will set up signal delivery once or not at all.
    pub fn set_signal_delivery(&self, thread: Tid, signal: Signal) -> Result<(), Errno> {
        self.count_programming();
        let owner = f_owner_ex {
            type_: F_OWNER_TID,
            pid: thread.as_raw(),
        };
        Errno::result(unsafe { libc::fcntl(self.fd, F_SETOWN_EX, &owner as *const _) })?;
        Errno::result(unsafe { libc::fcntl(self.fd, libc::F_SETFL, libc::O_ASYNC) })?;
        Errno::result(unsafe { libc::fcntl(self.fd, F_SETSIG, signal as i32) })?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn exec_test_fd(&self) -> libc::c_int {
        self.fd
    }

    #[cfg(test)]
    pub(crate) fn exec_test_signal_owner(&self) -> Result<Tid, Errno> {
        const F_GETOWN_EX: libc::c_int = 16;
        let mut owner = f_owner_ex { type_: -1, pid: -1 };
        Errno::result(unsafe { libc::fcntl(self.fd, F_GETOWN_EX, &mut owner as *mut _) })?;
        if owner.type_ != F_OWNER_TID {
            return Err(Errno::EINVAL);
        }
        Ok(Tid::from_raw(owner.pid))
    }

    /// Read the current value of the counter.
    pub fn ctr_value(&self) -> Result<u64, Errno> {
        let mut value = 0u64;
        let expected_bytes = std::mem::size_of_val(&value);
        loop {
            let res = if let Some(raw_syscall) = self.raw_syscall {
                match Errno::from_ret(unsafe {
                    raw_syscall(
                        libc::SYS_read,
                        [
                            self.fd as u64,
                            (&raw mut value) as u64,
                            expected_bytes as u64,
                            0,
                            0,
                            0,
                        ],
                    ) as usize
                }) {
                    Ok(value) => value as isize,
                    Err(Errno::EINTR) => continue,
                    Err(error) => return Err(error),
                }
            } else {
                unsafe { libc::read(self.fd, (&raw mut value).cast(), expected_bytes) }
            };
            if res == -1 {
                let errno = Errno::last();
                if errno != Errno::EINTR {
                    return Err(errno);
                }
            }
            if res == 0 {
                // EOF: this only occurs when attr.pinned = 1 and our event was descheduled.
                // This unrecoverably gives us innacurate counts.
                panic!("pinned perf event descheduled!")
            }
            if res == expected_bytes as isize {
                break;
            }
        }
        Ok(value)
    }

    pub(crate) fn ctr_value_paused_once(&self) -> Result<u64, Errno> {
        use std::ptr::addr_of;
        use std::ptr::addr_of_mut;
        use std::ptr::read_volatile;

        let mapping = self.mmap.ok_or(Errno::EOPNOTSUPP)?;
        let gate = self.raw_syscall.ok_or(Errno::EOPNOTSUPP)?;
        let page = mapping.as_ptr();
        let sequence = unsafe { read_once(addr_of_mut!((*page).lock)) };
        if sequence & 1 != 0 {
            return Err(Errno::EAGAIN);
        }
        smp_rmb();
        let (index, enabled, running) = unsafe {
            (
                read_volatile(addr_of!((*page).index)),
                read_volatile(addr_of!((*page).time_enabled)),
                read_volatile(addr_of!((*page).time_running)),
            )
        };
        if index != 0 {
            return Err(Errno::EBUSY);
        }
        if enabled != running {
            return Err(Errno::ENODEV);
        }
        let mut value = 0u64;
        let length = std::mem::size_of_val(&value);
        let result = Errno::from_ret(unsafe {
            gate(
                libc::SYS_read,
                [
                    self.fd as u64,
                    (&raw mut value) as u64,
                    length as u64,
                    0,
                    0,
                    0,
                ],
            ) as usize
        })?;
        smp_rmb();
        if sequence != unsafe { read_once(addr_of_mut!((*page).lock)) } {
            return Err(Errno::EAGAIN);
        }
        if result == 0 {
            return Err(Errno::ENODEV);
        }
        if result != length {
            return Err(Errno::EIO);
        }
        Ok(value)
    }

    /// Perform a fast read, which doesn't involve a syscall in the fast path.
    /// This falls back to a slow syscall read where necessary, including if
    /// fast reads weren't enabled in the `Builder`.
    pub fn ctr_value_fast(&self) -> Result<u64, Errno> {
        match self.mmap {
            Some(ptr) => {
                // SAFETY: self.mmap is constructed as the correct page or not at all
                let res = unsafe { self.ctr_value_fast_loop(ptr) };
                // TODO: remove this assertion after we're confident in correctness
                debug_assert_eq!(res, self.ctr_value_fallback());
                res
            }
            None => self.ctr_value_fallback(),
        }
    }

    #[cold]
    fn ctr_value_fallback(&self) -> Result<u64, Errno> {
        self.ctr_value()
    }

    /// Read the current counter value using the `rdpmc` instruction, with no
    /// syscall on the fast path even when the counter is *currently scheduled*
    /// on the PMU (`index != 0`).
    ///
    /// This is an **additive read primitive** intended for **in-guest,
    /// same-core** use: a guest thread reading its own performance counter from
    /// user space. It changes only *how a counter value is read* — it does not
    /// change how time or ordering is observed, and it does not alter the
    /// behavior of [`ctr_value`](Self::ctr_value) or
    /// [`ctr_value_fast`](Self::ctr_value_fast).
    ///
    /// # Correctness contract
    ///
    /// `rdpmc` reads the hardware PMC of *whatever core executes the
    /// instruction*. It is therefore only correct when the calling thread is
    /// the monitored thread running on the core the counter is scheduled on —
    /// i.e. the guest reading itself in-guest. A cross-core reader (such as the
    /// ptrace supervisor reading a stopped guest on another core) must NOT use
    /// this; that is exactly why [`ctr_value_fast`](Self::ctr_value_fast)
    /// deliberately falls back to the syscall read when `index != 0`.
    ///
    /// When the counter is not currently scheduled on the PMU (`index == 0`)
    /// there is no live hardware counter to read, so this returns the mmap
    /// `offset` via the seqlock read path with no syscall — the same value
    /// [`ctr_value_fast`](Self::ctr_value_fast) returns. `cap_user_rdpmc` does
    /// not matter in that case; it is only consulted when the counter is live.
    ///
    /// Falls back to the [`ctr_value`](Self::ctr_value) syscall read only when:
    /// * fast reads were not enabled on the [`Builder`] (no mmap page), or
    /// * the counter is live (`index != 0`) but the kernel/CPU does not permit
    ///   user-space `rdpmc` (`cap_user_rdpmc` clear).
    ///
    /// On a non-x86-64 target there is no portable `rdpmc`, so the
    /// [`ctr_value`](Self::ctr_value) syscall read is always used.
    // Additive in-guest read primitive; no in-tree caller yet (the in-guest
    // patching backend that will use it is still being built).
    #[allow(dead_code)]
    pub fn ctr_value_rdpmc(&self) -> Result<u64, Errno> {
        match self.mmap {
            Some(ptr) => {
                // SAFETY: self.mmap is constructed as the correct page or not at all
                unsafe { self.ctr_value_rdpmc_loop(ptr) }
            }
            None => self.ctr_value_fallback(),
        }
    }

    /// Safety: `ptr` must refer to the metadata page corresponding to self.fd.
    #[deny(unsafe_op_in_unsafe_fn)]
    #[inline(always)]
    unsafe fn ctr_value_fast_loop(
        &self,
        ptr: NonNull<perf::perf_event_mmap_page>,
    ) -> Result<u64, Errno> {
        // This implements synchronization with the kernel via a seqlock,
        // see https://www.kernel.org/doc/html/latest/locking/seqlock.html.
        // Also see experiments/perf_fast_reads.c for more details on fast reads.
        use std::ptr::addr_of_mut;
        let ptr = ptr.as_ptr();
        let mut seq;
        let mut running;
        let mut enabled;
        let mut count;
        loop {
            // Acquire a lease on the seqlock -- even values are outside of
            // writers' critical sections.
            loop {
                // SAFETY: ptr->lock is valid and aligned
                seq = unsafe { read_once(addr_of_mut!((*ptr).lock)) };
                if seq & 1 == 0 {
                    break;
                }
            }
            smp_rmb(); // force re-reads of other data
            let index;
            // SAFETY: these reads are synchronized by the correct reads of the
            // seqlock. We don't do anything with them until after the outer
            // loop finishing has guaranteed our read was serialized.
            unsafe {
                running = (*ptr).time_running;
                enabled = (*ptr).time_enabled;
                count = (*ptr).offset;
                index = (*ptr).index;
            }
            if index != 0 {
                // `index` being non-zero indicates we need to read from the
                // hardware counter and add it to our count. Instead, we
                // fallback to the slow path for a few reasons:
                // 1. This only works if we're on the same core, which is basically
                //    never true for our usecase.
                // 2. Reads of an active PMU are racy.
                // 3. The PMU should almost never be active, because we should
                //    generally only read from stopped processes.
                return self.ctr_value_fallback();
            }
            smp_rmb();
            // SAFETY: ptr->lock is valid and aligned
            if seq == unsafe { read_once(addr_of_mut!((*ptr).lock)) } {
                // if seq is unchanged, we didn't race with writer
                break;
            }
        }
        // This check must be outside the loop to ensure our reads were actually
        // serialized with any writes.
        if running != enabled {
            // Non-equal running/enabled time indicates the event was
            // descheduled at some point, meaning our counts are inaccurate.
            // This is not recoverable. The slow-read equivalent is getting EOF
            // when attr.pinned = 1.
            panic!("fast-read perf event was probably descheduled!")
        }
        Ok(count as u64)
    }

    /// Safety: `ptr` must refer to the metadata page corresponding to self.fd,
    /// and the calling thread must be the monitored thread running on the core
    /// the counter is scheduled on (see [`ctr_value_rdpmc`](Self::ctr_value_rdpmc)).
    #[cfg(target_arch = "x86_64")]
    #[allow(dead_code)]
    #[deny(unsafe_op_in_unsafe_fn)]
    #[inline(always)]
    unsafe fn ctr_value_rdpmc_loop(
        &self,
        ptr: NonNull<perf::perf_event_mmap_page>,
    ) -> Result<u64, Errno> {
        use std::ptr::addr_of_mut;
        let ptr = ptr.as_ptr();
        // `pmc_width` and the capability bits are fixed for the lifetime of the
        // mapping, so read them once outside the seqlock loop.
        // SAFETY: ptr is a valid, aligned perf metadata page.
        let width = unsafe { (*ptr).pmc_width } as u32;
        // SAFETY: reading the raw `capabilities` word of the capability union.
        let caps = unsafe { (*ptr).__bindgen_anon_1.capabilities };
        // `cap_user_rdpmc` is bit 2 of the capability bitfield (after `cap_bit0`
        // and `cap_bit0_is_deprecated`).
        let cap_user_rdpmc = (caps >> 2) & 1 == 1;

        let mut seq;
        let mut running;
        let mut enabled;
        let mut count: i64;
        // This mirrors the seqlock synchronization in `ctr_value_fast_loop`; see
        // https://www.kernel.org/doc/html/latest/locking/seqlock.html and the
        // rdpmc self-monitoring example in perf_event_open(2).
        loop {
            loop {
                // SAFETY: ptr->lock is valid and aligned
                seq = unsafe { read_once(addr_of_mut!((*ptr).lock)) };
                if seq & 1 == 0 {
                    break;
                }
            }
            smp_rmb();
            let index;
            // SAFETY: these reads are synchronized by the seqlock; nothing is
            // acted upon until the outer loop confirms serialization.
            unsafe {
                running = (*ptr).time_running;
                enabled = (*ptr).time_enabled;
                count = (*ptr).offset;
                index = (*ptr).index;
            }
            if index != 0 {
                if !cap_user_rdpmc {
                    // Counter is live but user-space rdpmc is disabled; the only
                    // correct read is the slow syscall path.
                    return self.ctr_value_fallback();
                }
                // `index != 0` means the counter is scheduled on this core's
                // PMU; read the raw hardware counter and add it to `offset`.
                // Sign-extend the rdpmc result from `pmc_width` bits to 64 bits
                // (arithmetic shifts on a signed value), exactly as the kernel's
                // rdpmc self-monitoring example in perf_event_open(2) does: the
                // hardware counter can wrap, and `offset` is chosen so that
                // `offset + sign_extend(rdpmc)` is the current count mod 2^width.
                // SAFETY: index-1 is the currently-scheduled PMC for this core,
                // and cap_user_rdpmc confirmed user-space rdpmc is permitted.
                let raw = unsafe { rdpmc(index - 1) };
                let pmc = ((raw << (64 - width)) as i64) >> (64 - width);
                count = count.wrapping_add(pmc);
            }
            smp_rmb();
            // SAFETY: ptr->lock is valid and aligned
            if seq == unsafe { read_once(addr_of_mut!((*ptr).lock)) } {
                // Unchanged seq => our reads were not torn by a writer.
                break;
            }
        }
        if running != enabled {
            // Non-equal running/enabled time means the event was descheduled at
            // some point, making counts inaccurate and unrecoverable. Same
            // condition the slow path detects as EOF when attr.pinned = 1.
            panic!("rdpmc perf event was probably descheduled!")
        }
        Ok(count as u64)
    }

    /// Non-x86-64 fallback: there is no portable `rdpmc`, so always use the
    /// syscall read.
    #[cfg(not(target_arch = "x86_64"))]
    #[allow(dead_code)]
    #[inline(always)]
    unsafe fn ctr_value_rdpmc_loop(
        &self,
        _ptr: NonNull<perf::perf_event_mmap_page>,
    ) -> Result<u64, Errno> {
        self.ctr_value_fallback()
    }

    /// Return the underlying perf fd.
    pub fn raw_fd(&self) -> libc::c_int {
        self.fd
    }

    /// Consume terminal resources without allowing a release error to skip the
    /// other release or panic over the run's original failure. Each resource is
    /// taken before the syscall: Linux may have released an fd even when close
    /// reports an error, so neither this path nor Drop may retry its number.
    pub(crate) fn close_after_failure(
        mut self,
        mmap_phase: &'static str,
        fd_phase: &'static str,
    ) -> Vec<(&'static str, Errno)> {
        let mut errors = Vec::new();
        if let Some(records) = self.records.take()
            && let Err(error) = records.close()
        {
            errors.push((mmap_phase, error));
        }
        if let Some(ptr) = self.mmap.take() {
            let result = terminal_mmap_size()
                .and_then(|size| try_close_mmap(ptr.as_ptr(), size, self.raw_syscall));
            if let Err(error) = result {
                errors.push((mmap_phase, error));
            }
        }
        let fd = std::mem::replace(&mut self.fd, -1);
        if fd >= 0
            && let Err(error) = try_close_perf_fd(fd, self.raw_syscall)
        {
            errors.push((fd_phase, error));
        }
        errors
    }

    /// Map a ring buffer that receives a record of each overflow the kernel
    /// handles. The overflow handler writes the record before it queues the
    /// notification signal, so the record is evidence of that signal. An
    /// overflow whose interrupt is never handled has neither. The buffer holds
    /// one page of records; [`PerfCounter::take_sample_records`] must release
    /// them before it fills, or later records are lost.
    pub(crate) fn map_sample_records(&mut self) -> Result<(), Errno> {
        if self.raw_syscall.is_some() || self.records.is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
        let len = 2 * get_mmap_size();
        // A writable mapping lets the reader advance `data_tail`. The kernel
        // then never overwrites a record that has not been taken.
        let ptr = Errno::result(unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.fd,
                0,
            )
        })?;
        let page = NonNull::new(ptr.cast()).ok_or(Errno::ENOMEM)?;
        self.records = Some(SampleRecords { page, len });
        Ok(())
    }

    /// Count the sample records written since the last call and release
    /// their space. Other record types, such as throttling and loss records,
    /// are not counted. Returns `None` if no records are mapped.
    pub(crate) fn take_sample_records(&mut self) -> Option<u64> {
        use core::ptr::addr_of;
        use core::ptr::addr_of_mut;
        use core::sync::atomic::Ordering;
        use core::sync::atomic::fence;

        let records = self.records.as_ref()?;
        let page = records.page.as_ptr();
        let page_size = get_mmap_size() as u64;
        // SAFETY: `page` maps the metadata page followed by the data pages
        // for the lifetime of `records`. Only this method writes `data_tail`,
        // and `&mut self` excludes concurrent calls.
        let samples = unsafe {
            let head = core::ptr::read_volatile(addr_of!((*page).data_head));
            // Pairs with the kernel's barrier before it publishes `data_head`.
            fence(Ordering::Acquire);
            let tail = core::ptr::read_volatile(addr_of!((*page).data_tail));
            // Kernels before 4.1 leave these fields zero and place the data
            // immediately after the metadata page.
            let offset = match core::ptr::read_volatile(addr_of!((*page).data_offset)) {
                0 => page_size,
                offset => offset,
            };
            let size = match core::ptr::read_volatile(addr_of!((*page).data_size)) {
                0 => records.len as u64 - page_size,
                size => size,
            };
            let data = page.cast::<u8>().add(offset as usize);
            // Records are 8-byte aligned and the data size is a multiple of
            // the page size, so a header never wraps.
            let samples = count_sample_records(tail, head, |position| {
                core::ptr::read_volatile(
                    data.add((position % size) as usize)
                        .cast::<perf::perf_event_header>(),
                )
            });
            // The records must be read before their space is released.
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(addr_of_mut!((*page).data_tail), head);
            samples
        };
        Some(samples)
    }

    /// Whether a sample record buffer is mapped, so that
    /// [`PerfCounter::take_sample_records`] reports the overflows the kernel
    /// handles.
    pub(crate) fn has_sample_records(&self) -> bool {
        self.records.is_some()
    }

    /// Remove the sample record mapping, leaving the counter without overflow
    /// evidence.
    #[cfg(test)]
    pub(crate) fn unmap_sample_records(&mut self) {
        self.records = None;
    }
}

/// Count the `PERF_RECORD_SAMPLE` records from `tail` to `head` of a ring
/// buffer, where `read_header` reads the header of the record at a position.
fn count_sample_records(
    tail: u64,
    head: u64,
    mut read_header: impl FnMut(u64) -> perf::perf_event_header,
) -> u64 {
    let header_size = core::mem::size_of::<perf::perf_event_header>() as u64;
    let mut position = tail;
    let mut samples = 0;
    while head.wrapping_sub(position) >= header_size {
        let header = read_header(position);
        let record_size = u64::from(header.size);
        if record_size < header_size || record_size > head.wrapping_sub(position) {
            error!(
                ?header,
                position, head, "Malformed perf sample record; ignoring the rest"
            );
            break;
        }
        if header.type_ == perf::PERF_RECORD_SAMPLE {
            samples += 1;
        }
        position = position.wrapping_add(record_size);
    }
    samples
}

/// Execute the `rdpmc` instruction to read hardware performance counter number
/// `counter`. Returns the raw counter value (the low `pmc_width` bits are
/// meaningful; higher bits are unspecified and must be masked by the caller).
///
/// SAFETY: the caller must ensure `counter` is the currently-scheduled PMC
/// index for the calling core (i.e. `index - 1` from the perf mmap page) and
/// that user-space `rdpmc` is permitted (`cap_user_rdpmc`). Executing `rdpmc`
/// without user-space access enabled raises `#GP`.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
#[inline(always)]
unsafe fn rdpmc(counter: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: rdpmc reads the counter selected by ecx into edx:eax and touches
    // no memory or other registers.
    unsafe {
        core::arch::asm!(
            "rdpmc",
            in("ecx") counter,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn close_perf_fd(fd: libc::c_int, raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>) {
    try_close_perf_fd(fd, raw_syscall).expect("Could not close perf fd");
}

fn try_close_perf_fd(
    fd: libc::c_int,
    raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
) -> Result<(), Errno> {
    if let Some(raw_syscall) = raw_syscall {
        Errno::from_ret(unsafe {
            raw_syscall(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) as usize
        })
        .map(|_| ())
    } else {
        Errno::result(unsafe { libc::close(fd) }).map(|_| ())
    }
}

fn close_mmap(
    ptr: *mut perf::perf_event_mmap_page,
    raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
) {
    try_close_mmap(ptr, get_mmap_size(), raw_syscall).expect("Could not munmap ring buffer");
}

fn try_close_mmap(
    ptr: *mut perf::perf_event_mmap_page,
    size: usize,
    raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
) -> Result<(), Errno> {
    if let Some(raw_syscall) = raw_syscall {
        Errno::from_ret(unsafe {
            raw_syscall(libc::SYS_munmap, [ptr as u64, size as u64, 0, 0, 0, 0]) as usize
        })
        .map(|_| ())
    } else {
        Errno::result(unsafe { libc::munmap(ptr as *mut _, size) }).map(|_| ())
    }
}

impl SampleRecords {
    /// Unmap the records without panicking. Linux may have removed the
    /// mapping even when munmap reports an error, so Drop does not retry it.
    fn close(self) -> Result<(), Errno> {
        let records = core::mem::ManuallyDrop::new(self);
        Errno::result(unsafe { libc::munmap(records.page.as_ptr().cast(), records.len) })
            .map(|_| ())
    }
}

impl Drop for SampleRecords {
    fn drop(&mut self) {
        Errno::result(unsafe { libc::munmap(self.page.as_ptr().cast(), self.len) })
            .expect("Could not munmap sample records");
    }
}

/// Whether descriptor number `fd` has stopped naming the perf event whose
/// `PERF_EVENT_IOC_ID` was `id`.
///
/// A descriptor number is not an identity: once a counter is closed, the
/// kernel hands the lowest free number to the next `open`, `pipe` or
/// `perf_event_open` of any thread in this process, and the parallel unit
/// tests in this binary open descriptors continuously. `F_GETFD` returning
/// `EBADF` therefore cannot be the closure proof. The event ID can: it comes
/// from a global counter and is never reused, and while the old descriptor is
/// open its number cannot be handed to anyone else. So the old event is gone
/// from `fd` exactly when `fd` is free, names a non-perf file, or names a perf
/// event with a different ID.
#[cfg(test)]
pub(crate) fn fd_no_longer_names_event(fd: libc::c_int, id: u64) -> bool {
    match std::fs::read_link(format!("/proc/self/fd/{fd}")) {
        Err(error) => return error.raw_os_error() == Some(libc::ENOENT),
        Ok(target) if target.as_os_str() != "anon_inode:[perf_event]" => return true,
        Ok(_) => {}
    }
    let mut current = 0u64;
    // SAFETY: the pointer names a live, writable u64 for the ioctl's duration.
    if unsafe { ioctls::ID(fd, &mut current as *mut u64) } == 0 {
        return current != id;
    }
    // Closed or replaced by a non-perf file between the two probes.
    matches!(Errno::last(), Errno::EBADF | Errno::ENOTTY)
}

impl Drop for PerfCounter {
    fn drop(&mut self) {
        if let Some(ptr) = self.mmap.take() {
            close_mmap(ptr.as_ptr(), self.raw_syscall);
        }
        let fd = std::mem::replace(&mut self.fd, -1);
        if fd >= 0 {
            close_perf_fd(fd, self.raw_syscall);
        }
    }
}

// Safety:
// The mmap region is never written to through a shared reference. Multiple
// readers then race with the kernel as any single thread would. Though the
// reads are racy, that is the intended behavior of the perf api. Only
// `take_sample_records`, which requires `&mut self`, writes a mapping.
unsafe impl std::marker::Send for PerfCounter {}
unsafe impl std::marker::Sync for PerfCounter {}

fn get_mmap_size() -> usize {
    // Use a single page; we only want the perf metadata
    sysconf(SysconfVar::PAGE_SIZE)
        .expect("failed to query the system page size")
        .expect("the system did not report a page size")
        .try_into()
        .expect("the system page size must fit in usize")
}

// Terminal cleanup must also retain a page-size query failure instead of
// entering get_mmap_size's ordinary invariant panics before closing the fd.
fn terminal_mmap_size() -> Result<usize, Errno> {
    let size = sysconf(SysconfVar::PAGE_SIZE)
        .map_err(|error| Errno::new(error as i32))?
        .ok_or(Errno::EINVAL)?;
    usize::try_from(size).map_err(|_| Errno::EOVERFLOW)
}

/// Force a relaxed atomic load. Like Linux's READ_ONCE.
/// SAFETY: caller must ensure v points to valid data and is aligned
#[inline(always)]
#[deny(unsafe_op_in_unsafe_fn)]
unsafe fn read_once(v: *mut u32) -> u32 {
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering::Relaxed;
    // SAFETY: AtomicU32 is guaranteed to have the same in-memory representation
    // SAFETY: The UnsafeCell inside AtomicU32 allows aliasing with *mut
    // SAFETY: The reference doesn't escape this function, so any lifetime is ok
    let av: &AtomicU32 = unsafe { &*(v as *const AtomicU32) };
    av.load(Relaxed)
}

#[inline(always)]
fn smp_rmb() {
    use core::sync::atomic::Ordering::SeqCst;
    use core::sync::atomic::compiler_fence;
    compiler_fence(SeqCst);
}

fn handle_perf_pmu_error(errno: Errno) -> bool {
    match errno {
        Errno::ENOENT | Errno::EPERM | Errno::EACCES | Errno::ENOSYS => {
            warn!(
                %errno,
                "PMU hardware-event capability probe failed; performance counters are unavailable"
            );
        }
        _ => {
            warn!("Perf feature check failed unexpectedly due to {errno}; assuming unsupported");
        }
    }

    false
}

// Test if we have PMU access by doing a check for a basic hardware event.
fn test_perf_pmu_support() -> bool {
    // Do a raw perf_event_open because our default configuration has flags that
    // might be the actual cause of the error, which we want to catch separately.
    let evt = Event::Hardware(HardwareEvent::Instructions);
    let mut attr = perf::perf_event_attr::default();
    attr.size = core::mem::size_of_val(&attr) as u32;
    attr.type_ = evt.attr_type();
    attr.config = evt.attr_config();
    attr.__bindgen_anon_1.sample_period = PerfCounter::DISABLE_SAMPLE_PERIOD;
    attr.set_exclude_kernel(1); // lowers permission requirements

    let pid: libc::pid_t = 0; // track this thread
    let cpu: libc::c_int = -1; // across any CPU
    let group_fd: libc::c_int = -1;
    let flags = perf::PERF_FLAG_FD_CLOEXEC;
    let res = Errno::result(unsafe {
        libc::syscall(libc::SYS_perf_event_open, &attr, pid, cpu, group_fd, flags)
    });
    match res {
        Ok(fd) => {
            Errno::result(unsafe { libc::close(fd as libc::c_int) })
                .expect("perf feature check: close(fd) failed");
            true
        }
        Err(errno) => handle_perf_pmu_error(errno),
    }
}

static IS_PERF_SUPPORTED: LazyLock<bool> = LazyLock::new(test_perf_pmu_support);

/// Returns true if the current system configuration supports use of perf for
/// hardware events.
pub fn is_perf_supported() -> bool {
    *IS_PERF_SUPPORTED
}

/// Concisely return if `is_perf_supported` is `false`. Useful for guarding
/// tests.
#[macro_export]
macro_rules! ret_without_perf {
    () => {
        if !$crate::is_perf_supported() {
            return;
        }
    };
    (expr:expr) => {
        if !$crate::is_perf_supported() {
            return ($expr);
        }
    };
}

/// Perform exactly `count+1` conditional branch instructions. Useful for
/// testing timer-related code.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub fn do_branches(mut count: u64) {
    // Anything but assembly is unreliable between debug and release
    unsafe {
        // Loop until carry flag is set, indicating underflow
        core::arch::asm!(
            "2:",
            "sub {0}, 1",
            "jnz 2b",
            inout(reg) count,
        )
    }

    assert_eq!(count, 0);
}

/// Perform exactly `count+1` conditional branch instructions. Useful for
/// testing timer-related code.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub fn do_branches(mut count: u64) {
    unsafe {
        core::arch::asm!(
            "2:",
            "subs {0}, {0}, #0x1",
            "b.ne 2b",
            inout(reg) count,
        )
    }

    assert_eq!(count, 0);
}

#[cfg(test)]
mod support_test {
    use super::*;

    /// The closure predicate used by the nonleader-exec counter handoff test
    /// must key on the event, not on the descriptor number. `dup2` replaces a
    /// number atomically, so this reproduces a parallel test reusing a closed
    /// counter's number without ever leaving it free for another thread.
    #[test]
    fn closed_counter_is_recognized_after_its_fd_number_is_reused() {
        ret_without_perf!();
        use std::os::fd::AsRawFd;
        let dummy = || {
            Builder::new(0, -1)
                .event(Event::Software(SoftwareEvent::Dummy))
                .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
                .create()
                .expect("open a software perf event")
        };
        let old = dummy();
        let old_id = old.id().unwrap();
        let fd = old.exec_test_fd();
        assert!(
            !fd_no_longer_names_event(fd, old_id),
            "an open counter was reported closed"
        );
        let other = dummy();
        let other_id = other.id().unwrap();
        assert_ne!(old_id, other_id);
        let devnull = std::fs::File::open("/dev/null").unwrap();
        for (replacement, what) in [
            (devnull.as_raw_fd(), "a non-perf file"),
            (other.exec_test_fd(), "another perf event"),
        ] {
            // Closes whatever `fd` named and reuses its number in one step.
            assert_eq!(unsafe { libc::dup2(replacement, fd) }, fd);
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) },
                -1,
                "the number is open again, so EBADF cannot prove closure"
            );
            assert!(
                fd_no_longer_names_event(fd, old_id),
                "old counter reported open after its number now names {what}"
            );
        }
        assert!(
            !fd_no_longer_names_event(fd, other_id),
            "a live duplicate of another counter was reported closed"
        );
        // `old` owns `fd` again only as a number; its event is already gone.
        drop(old);
        assert!(fd_no_longer_names_event(fd, old_id));
    }

    #[test]
    fn perf_event_open_errors_mean_pmu_is_unsupported() {
        for errno in [
            Errno::ENOENT,
            Errno::EPERM,
            Errno::EACCES,
            Errno::ENOSYS,
            Errno::EINVAL,
        ] {
            assert!(!handle_perf_pmu_error(errno));
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "perf/tests.rs"]
mod paused_tests;

#[cfg(test)]
pub(crate) mod terminal_close_tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::IntoRawFd;
    use std::os::fd::OwnedFd;

    use super::*;

    thread_local! {
        static RELEASES: RefCell<Vec<(i64, u64)>> = const { RefCell::new(Vec::new()) };
        static REPLACEMENT_SOURCE: Cell<libc::c_int> = const { Cell::new(-1) };
        static REPLACED: Cell<bool> = const { Cell::new(false) };
    }

    // Real kernel resources make leaks and descriptor reuse observable without
    // requiring PMU access. These resource tests do not qualify PMU behavior.
    pub(crate) fn counter(raw_syscall: unsafe fn(i64, [u64; 6]) -> i64) -> PerfCounter {
        let fd = Errno::result(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })
            .unwrap();
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mapping = Errno::result(unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                get_mmap_size(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        })
        .unwrap();
        PerfCounter {
            fd: fd.into_raw_fd(),
            mmap: Some(NonNull::new(mapping.cast()).unwrap()),
            records: None,
            raw_syscall: Some(raw_syscall),
            programmings: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(crate) fn reset_releases() {
        RELEASES.with_borrow_mut(Vec::clear);
    }

    pub(crate) fn releases() -> Vec<(i64, u64)> {
        RELEASES.with_borrow(Clone::clone)
    }

    pub(crate) unsafe fn release(number: i64, arguments: [u64; 6]) -> i64 {
        RELEASES.with_borrow_mut(|calls| calls.push((number, arguments[0])));
        let result = match number {
            libc::SYS_munmap => unsafe {
                libc::munmap(arguments[0] as *mut _, arguments[1] as usize)
            },
            libc::SYS_close => unsafe { libc::close(arguments[0] as libc::c_int) },
            _ => panic!("unexpected non-release syscall {number}"),
        };
        assert_eq!(result, 0, "real resource release failed: {}", Errno::last());
        0
    }

    pub(crate) unsafe fn release_with_errors(number: i64, arguments: [u64; 6]) -> i64 {
        // Exercise the ambiguous case: the resource was released, but the
        // caller observes an error and must consume it without retrying.
        unsafe { release(number, arguments) };
        match number {
            libc::SYS_munmap => -(libc::EIO as i64),
            libc::SYS_close => -(libc::EINTR as i64),
            _ => unreachable!(),
        }
    }

    unsafe fn release_with_fd_reuse(number: i64, arguments: [u64; 6]) -> i64 {
        if number != libc::SYS_close || REPLACED.replace(true) {
            return unsafe { release(number, arguments) };
        }
        RELEASES.with_borrow_mut(|calls| calls.push((number, arguments[0])));
        // dup3 releases the original owned fd and replaces it atomically. No
        // interval lets a parallel test acquire the numeric fd being reused.
        let fd = arguments[0] as libc::c_int;
        assert_eq!(
            unsafe { libc::dup3(REPLACEMENT_SOURCE.get(), fd, libc::O_CLOEXEC) },
            fd
        );
        -(libc::EINTR as i64)
    }

    #[test]
    fn terminal_close_retains_both_release_errors_once() {
        reset_releases();
        let counter = counter(release_with_errors);
        let expected = vec![
            (libc::SYS_munmap, counter.mmap.unwrap().as_ptr() as u64),
            (libc::SYS_close, counter.raw_fd() as u64),
        ];
        assert_eq!(
            counter.close_after_failure("mapping", "fd"),
            vec![("mapping", Errno::EIO), ("fd", Errno::EINTR)]
        );
        // The consuming method has returned and Drop has already run.
        assert_eq!(releases(), expected);
    }

    #[test]
    fn terminal_close_and_ordinary_drop_release_the_same_resources() {
        for terminal in [false, true] {
            reset_releases();
            let counter = counter(release);
            let expected = vec![
                (libc::SYS_munmap, counter.mmap.unwrap().as_ptr() as u64),
                (libc::SYS_close, counter.raw_fd() as u64),
            ];
            if terminal {
                assert!(counter.close_after_failure("mapping", "fd").is_empty());
            } else {
                drop(counter);
            }
            assert_eq!(releases(), expected);
        }
    }

    #[test]
    fn terminal_close_does_not_retry_a_reused_descriptor() {
        reset_releases();
        REPLACED.set(false);
        let source =
            Errno::result(unsafe { libc::eventfd(42, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })
                .unwrap();
        let source = unsafe { OwnedFd::from_raw_fd(source) };
        REPLACEMENT_SOURCE.set(source.as_raw_fd());
        let counter = counter(release_with_fd_reuse);
        let fd = counter.raw_fd();
        let expected = vec![
            (libc::SYS_munmap, counter.mmap.unwrap().as_ptr() as u64),
            (libc::SYS_close, fd as u64),
        ];
        let errors = counter.close_after_failure("mapping", "fd");
        // The replacement is now this fixture's resource, not the consumed
        // PerfCounter's. Take ownership only if it survived the counter's Drop.
        let replacement = if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            Some(unsafe { OwnedFd::from_raw_fd(fd) })
        } else {
            None
        };
        assert_eq!(errors, vec![("fd", Errno::EINTR)]);
        assert_eq!(releases(), expected);
        let replacement = replacement.expect("Drop closed the reused descriptor");
        let mut value = 0_u64;
        assert_eq!(
            unsafe {
                libc::read(
                    replacement.as_raw_fd(),
                    (&raw mut value).cast(),
                    std::mem::size_of_val(&value),
                )
            },
            std::mem::size_of_val(&value) as isize
        );
        assert_eq!(value, 42, "the exact replacement eventfd must remain open");
    }
}

// NOTE: aarch64 doesn't work with
// `Event::Hardware(HardwareEvent::BranchInstructions)`, so these tests are
// disabled for that architecture. Most likely, we need to use `Event::Raw`
// instead to enable these tests.
#[cfg(all(test, target_arch = "x86_64"))]
mod test {
    use nix::unistd::gettid;

    use super::*;

    #[test]
    fn test_do_branches() {
        do_branches(1000);
    }

    #[test]
    fn trace_self() {
        ret_without_perf!();
        let pc = Builder::new(gettid().as_raw(), -1)
            .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .event(Event::Hardware(HardwareEvent::BranchInstructions))
            .create()
            .expect("perf test operation should succeed");
        pc.reset().expect("perf test operation should succeed");
        pc.enable().expect("perf test operation should succeed");
        const ITERS: u64 = 10000;
        do_branches(ITERS);
        pc.disable().expect("perf test operation should succeed");
        let ctr = pc.ctr_value().expect("perf test operation should succeed");
        assert!(ctr >= ITERS);
        assert!(ctr <= ITERS + 100); // `.disable()` overhead
    }

    /// The in-guest `rdpmc` read must agree with the syscall read. Because the
    /// counter is live, we can't assert exact equality; instead we bracket the
    /// rdpmc read between two syscall reads on the same (monotonic) thread and
    /// require `before <= rdpmc <= after`.
    #[test]
    fn rdpmc_read_agrees_with_syscall_read() {
        ret_without_perf!();
        let pc = Builder::new(gettid().as_raw(), -1)
            .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .event(Event::Hardware(HardwareEvent::BranchInstructions))
            .fast_reads(true)
            .create()
            .expect("perf test operation should succeed");
        pc.reset().expect("perf test operation should succeed");
        pc.enable().expect("perf test operation should succeed");

        // Repeat so we exercise the live (`index != 0`) case, which requires the
        // counter to be scheduled on this core when we read it.
        for _ in 0..1000 {
            do_branches(1000);
            let before = pc.ctr_value().expect("syscall read");
            let via_rdpmc = pc.ctr_value_rdpmc().expect("rdpmc read");
            let after = pc.ctr_value().expect("syscall read");
            assert!(
                before <= via_rdpmc && via_rdpmc <= after,
                "rdpmc read {via_rdpmc} not in bracket [{before}, {after}]"
            );
        }
    }

    /// Microbenchmark: cost of a single counter read via `rdpmc` (in-guest,
    /// same-core, `index != 0` live case) versus the `read(2)` syscall fallback.
    ///
    /// Ignored by default because it prints timings rather than asserting on
    /// them (timing is host-dependent). Run with:
    ///   `cargo test -p reverie-ptrace --release perf::test::bench_rdpmc_vs_read \
    ///        -- --ignored --nocapture`
    ///
    /// The counter self-monitors this thread, so it stays scheduled on this
    /// core (`index != 0`) throughout — the exact case the ptrace fast path
    /// deliberately punts to the syscall. If rdpmc had silently fallen back to
    /// the syscall, the two timings would be equal; a large gap is itself proof
    /// the rdpmc path was taken.
    #[test]
    #[ignore]
    fn bench_rdpmc_vs_read() {
        use std::time::Instant;
        ret_without_perf!();
        const LOOP: usize = 100_000; // reads per timed sample
        const REPS: usize = 25; // independent timed samples
        const WARMUP: usize = 5;

        let pc = Builder::new(gettid().as_raw(), -1)
            .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .event(Event::Hardware(HardwareEvent::BranchInstructions))
            .fast_reads(true)
            .create()
            .expect("perf create");
        pc.reset().expect("perf reset");
        pc.enable().expect("perf enable");

        let time_loop = |read: &dyn Fn() -> u64| -> Vec<f64> {
            let mut samples = Vec::with_capacity(REPS);
            for rep in 0..(WARMUP + REPS) {
                let start = Instant::now();
                let mut acc = 0u64;
                for _ in 0..LOOP {
                    acc = acc.wrapping_add(std::hint::black_box(read()));
                }
                std::hint::black_box(acc);
                let ns_per_op = start.elapsed().as_nanos() as f64 / LOOP as f64;
                if rep >= WARMUP {
                    samples.push(ns_per_op);
                }
            }
            samples
        };

        let median = |mut v: Vec<f64>| -> f64 {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let min = |v: &[f64]| v.iter().cloned().fold(f64::INFINITY, f64::min);

        let rdpmc_s = time_loop(&|| pc.ctr_value_rdpmc().expect("rdpmc"));
        let read_s = time_loop(&|| pc.ctr_value().expect("read"));

        let rdpmc_med = median(rdpmc_s.clone());
        let read_med = median(read_s.clone());
        eprintln!("=== rdpmc vs read() microbenchmark ===");
        eprintln!("host: self-monitoring thread, BranchInstructions, fast_reads=true");
        eprintln!("loop size (reads/sample): {LOOP}");
        eprintln!("reps (timed samples): {REPS} (+{WARMUP} warmup, discarded)");
        eprintln!(
            "rdpmc  (index!=0 live): min={:.1} ns  median={:.1} ns",
            min(&rdpmc_s),
            rdpmc_med
        );
        eprintln!(
            "read() (syscall fallback): min={:.1} ns  median={:.1} ns",
            min(&read_s),
            read_med
        );
        eprintln!(
            "gap (median read / median rdpmc): {:.1}x",
            read_med / rdpmc_med
        );
    }

    #[test]
    fn trace_other_thread() {
        ret_without_perf!();
        use std::sync::mpsc::sync_channel;
        let (tx1, rx1) = sync_channel(0); // send TID
        let (tx2, rx2) = sync_channel(0); // start guest spinn

        const ITERS: u64 = 100000;

        let handle = std::thread::spawn(move || {
            tx1.send(gettid())
                .expect("perf test operation should succeed");
            rx2.recv().expect("perf test operation should succeed");
            do_branches(ITERS);
        });

        let pc = Builder::new(
            rx1.recv()
                .expect("perf test operation should succeed")
                .as_raw(),
            -1,
        )
        .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
        .event(Event::Hardware(HardwareEvent::BranchInstructions))
        .create()
        .expect("perf test operation should succeed");

        pc.enable().expect("perf test operation should succeed");
        tx2.send(()).expect("perf test operation should succeed"); // tell thread to start
        handle.join().expect("perf test operation should succeed");
        let ctr = pc.ctr_value().expect("perf test operation should succeed");
        assert!(ctr >= ITERS);
        assert!(ctr <= ITERS * 2, "{}", ctr); // overhead from channel operations
    }

    #[test]
    fn deliver_signal() {
        ret_without_perf!();
        use std::mem::MaybeUninit;
        use std::sync::mpsc::sync_channel;
        let (tx1, rx1) = sync_channel(0); // send TID
        let (tx2, rx2) = sync_channel(0); // start guest spinn

        // SIGSTKFLT defaults to TERM, so if any thread but the traced one
        // receives the signal, the test will fail due to process exit.
        const MARKER_SIGNAL: Signal = Signal::SIGSTKFLT;
        const SPIN_BRANCHES: u64 = 50000; // big enough to "absorb" noise from debug/release
        const SPINS_PER_EVENT: u64 = 10;
        const SAMPLE_PERIOD: u64 = SPINS_PER_EVENT * SPIN_BRANCHES + (SPINS_PER_EVENT / 4);

        fn signal_is_pending() -> bool {
            unsafe {
                let mut mask = MaybeUninit::<libc::sigset_t>::zeroed();
                libc::sigemptyset(mask.as_mut_ptr());
                libc::sigpending(mask.as_mut_ptr());
                libc::sigismember(mask.as_ptr(), MARKER_SIGNAL as _) == 1
            }
        }

        let handle = std::thread::spawn(move || {
            unsafe {
                let mut mask = MaybeUninit::<libc::sigset_t>::zeroed();
                libc::sigemptyset(mask.as_mut_ptr());
                libc::sigaddset(mask.as_mut_ptr(), MARKER_SIGNAL as _);
                libc::sigprocmask(libc::SIG_BLOCK, mask.as_ptr(), std::ptr::null_mut());
            }

            tx1.send(gettid())
                .expect("perf test operation should succeed");
            rx2.recv().expect("perf test operation should succeed");

            let mut count = 0;
            loop {
                count += 1;
                do_branches(SPIN_BRANCHES);
                if signal_is_pending() {
                    break;
                }
            }
            assert_eq!(count, SPINS_PER_EVENT);
        });

        let tid = rx1.recv().expect("perf test operation should succeed");
        let pc = Builder::new(tid.as_raw(), -1)
            .sample_period(SAMPLE_PERIOD)
            .event(Event::Hardware(HardwareEvent::BranchInstructions))
            .create()
            .expect("perf test operation should succeed");
        pc.set_signal_delivery(tid.into(), MARKER_SIGNAL)
            .expect("perf test operation should succeed");
        pc.enable().expect("perf test operation should succeed");

        tx2.send(()).expect("perf test operation should succeed"); // tell thread to start
        handle.join().expect("perf test operation should succeed"); // propagate panics
    }
}
