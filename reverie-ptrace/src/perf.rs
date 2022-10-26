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

use lazy_static::lazy_static;
use nix::sys::signal::Signal;
use nix::unistd::sysconf;
use nix::unistd::SysconfVar;
pub use perf::perf_event_header;
use perf_event_open_sys::bindings as perf;
use perf_event_open_sys::ioctls;
use reverie::Errno;
use reverie::Tid;
use tracing::info;
use tracing::warn;

use crate::validation::check_for_pmu_bugs;
use crate::validation::PmuValidationError;

lazy_static! {
    static ref PMU_BUG: Result<(), PmuValidationError> = check_for_pmu_bugs();
}

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
}

impl Event {
    fn attr_type(self) -> u32 {
        match self {
            Event::Hardware(_) => perf::perf_type_id_PERF_TYPE_HARDWARE,
            Event::Software(_) => perf::perf_type_id_PERF_TYPE_SOFTWARE,
            Event::Raw(_) => perf::perf_type_id_PERF_TYPE_RAW,
        }
    }

    fn attr_config(self) -> u64 {
        match self {
            Event::Raw(x) => x,
            Event::Hardware(HardwareEvent::Instructions) => {
                perf::perf_hw_id_PERF_COUNT_HW_INSTRUCTIONS.into()
            }
            Event::Hardware(HardwareEvent::BranchInstructions) => {
                perf::perf_hw_id_PERF_COUNT_HW_BRANCH_INSTRUCTIONS.into()
            }
            Event::Software(SoftwareEvent::Dummy) => perf::perf_sw_ids_PERF_COUNT_SW_DUMMY.into(),
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

    /// Render the builder into a `PerfCounter`. Created counters begin in a
    /// disabled state. Additional initialization steps should be performed,
    /// followed by a call to [`PerfCounter::enable`].
    pub fn create(&self) -> Result<PerfCounter, Errno> {
        let mut attr = perf::perf_event_attr::default();
        attr.size = core::mem::size_of_val(&attr) as u32;
        attr.type_ = self.evt.attr_type();
        attr.config = self.evt.attr_config();
        attr.__bindgen_anon_1.sample_period = self.sample_period;
        attr.set_disabled(1); // user must enable later
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

        let fd = Errno::result(unsafe {
            libc::syscall(libc::SYS_perf_event_open, &attr, pid, cpu, group_fd, flags)
        })?;
        let fd = fd as libc::c_int;

        let mmap = if self.fast_reads {
            let res = Errno::result(unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    get_mmap_size(),
                    libc::PROT_READ, // leaving PROT_WRITE unset lets us passively read
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            });
            match res {
                Ok(ptr) => Some(NonNull::new(ptr as *mut _).unwrap()),
                Err(e) => {
                    close_perf_fd(fd);
                    return Err(e);
                }
            }
        } else {
            None
        };

        Ok(PerfCounter { fd, mmap })
    }

    pub(crate) fn check_for_pmu_bugs(&mut self) -> &mut Self {
        if let Err(pmu_error) = &*PMU_BUG {
            warn!("Pmu bugs detected: {:?}", pmu_error);
        }
        self
    }
}

impl PerfCounter {
    /// Perf counters cannot be switched from sampling to non-sampling, so
    /// setting their period to this large value effectively disables overflows
    /// and sampling.
    pub const DISABLE_SAMPLE_PERIOD: u64 = 1 << 60;

    /// Call the `PERF_EVENT_IOC_ENABLE` ioctl. Enables increments of the
    /// counter and event generation.
    pub fn enable(&self) -> Result<(), Errno> {
        Errno::result(unsafe { ioctls::ENABLE(self.fd, 0) }).and(Ok(()))
    }

    /// Call the `PERF_EVENT_IOC_ENABLE` ioctl. Disables increments of the
    /// counter and event generation.
    pub fn disable(&self) -> Result<(), Errno> {
        Errno::result(unsafe { ioctls::DISABLE(self.fd, 0) }).and(Ok(()))
    }

    /// Corresponds exactly to the `PERF_EVENT_IOC_REFRESH` ioctl.
    #[allow(dead_code)]
    pub fn refresh(&self, count: libc::c_int) -> Result<(), Errno> {
        assert!(count != 0); // 0 is undefined behavior
        Errno::result(unsafe { ioctls::REFRESH(self.fd, 0) }).and(Ok(()))
    }

    /// Call the `PERF_EVENT_IOC_RESET` ioctl. Resets the counter value to 0,
    /// which results in delayed overflow events.
    pub fn reset(&self) -> Result<(), Errno> {
        Errno::result(unsafe { ioctls::RESET(self.fd, 0) }).and(Ok(()))
    }

    /// Call the `PERF_EVENT_IOC_PERIOD` ioctl. This causes the counter to
    /// behave as if `ticks` was the original argument to `sample_period` in
    /// the builder.
    pub fn set_period(&self, ticks: u64) -> Result<(), Errno> {
        // The bindings are wrong for this ioctl. The method signature takes a
        // u64, but the actual ioctl expects a pointer to a u64. Thus, we use
        // the constant manually.

        // This ioctl shouldn't mutate it's argument per its API. But in case it
        // does, create a mutable copy to avoid Rust UB.
        let mut ticks = ticks;
        Errno::result(unsafe {
            libc::ioctl(
                self.fd,
                perf::perf_event_ioctls_PERIOD as _,
                &mut ticks as *mut u64,
            )
        })
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
        let owner = f_owner_ex {
            type_: F_OWNER_TID,
            pid: thread.as_raw(),
        };
        Errno::result(unsafe { libc::fcntl(self.fd, F_SETOWN_EX, &owner as *const _) })?;
        Errno::result(unsafe { libc::fcntl(self.fd, libc::F_SETFL, libc::O_ASYNC) })?;
        Errno::result(unsafe { libc::fcntl(self.fd, F_SETSIG, signal as i32) })?;
        Ok(())
    }

    /// Read the current value of the counter.
    pub fn ctr_value(&self) -> Result<u64, Errno> {
        let mut value = 0u64;
        let expected_bytes = std::mem::size_of_val(&value);
        loop {
            let res =
                unsafe { libc::read(self.fd, &mut value as *mut u64 as *mut _, expected_bytes) };
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

    /// Return the underlying perf fd.
    pub fn raw_fd(&self) -> libc::c_int {
        self.fd
    }
}

fn close_perf_fd(fd: libc::c_int) {
    Errno::result(unsafe { libc::close(fd) }).expect("Could not close perf fd");
}
fn close_mmap(ptr: *mut perf::perf_event_mmap_page) {
    Errno::result(unsafe { libc::munmap(ptr as *mut _, get_mmap_size()) })
        .expect("Could not munmap ring buffer");
}

impl Drop for PerfCounter {
    fn drop(&mut self) {
        if let Some(ptr) = self.mmap {
            close_mmap(ptr.as_ptr());
        }
        close_perf_fd(self.fd);
    }
}

// Safety:
// The mmap region is never written to. Multiple readers then race with the
// kernel as any single thread would. Though the reads are racy, that is the
// intended behavior of the perf api.
unsafe impl std::marker::Send for PerfCounter {}
unsafe impl std::marker::Sync for PerfCounter {}

fn get_mmap_size() -> usize {
    // Use a single page; we only want the perf metadata
    sysconf(SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap()
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
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn smp_rmb() {
    use std::sync::atomic::compiler_fence;
    use std::sync::atomic::Ordering::SeqCst;
    compiler_fence(SeqCst);
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
            return true;
        }
        Err(Errno::ENOENT) => info!("Perf feature check failed due to ENOENT"),
        Err(Errno::EPERM) => info!("Perf feature check failed due to EPERM"),
        Err(Errno::EACCES) => info!("Perf feature check failed due to EACCES"),
        Err(e) => panic!("Unexpected error during perf feature check: {}", e),
    }
    false
}

lazy_static! {
    static ref IS_PERF_SUPPORTED: bool = test_perf_pmu_support();
}

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
#[cfg(not(feature = "llvm_asm"))]
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
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "llvm_asm")]
#[inline(never)]
pub fn do_branches(count: u64) {
    // Anything but assembly is unreliable between debug and release
    #[allow(deprecated)]
    unsafe {
        // Loop until carry flag is set, indicating underflow
        llvm_asm!("
                mov $0, %rax
            perf_test_branch_loop:
                subq $$1, %rax
                jnc perf_test_branch_loop
                "
            : /* no output */
            : "r"(count)
            : "cc", "rax"
        );
    }
}

#[cfg(test)]
mod test {
    use nix::unistd::gettid;

    use super::*;

    #[test]
    fn trace_self() {
        ret_without_perf!();
        let pc = Builder::new(gettid().as_raw(), -1)
            .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .event(Event::Hardware(HardwareEvent::BranchInstructions))
            .create()
            .unwrap();
        pc.reset().unwrap();
        pc.enable().unwrap();
        const ITERS: u64 = 10000;
        do_branches(ITERS);
        pc.disable().unwrap();
        let ctr = pc.ctr_value().unwrap();
        assert!(ctr >= ITERS);
        assert!(ctr <= ITERS + 100); // `.disable()` overhead
    }

    #[test]
    fn trace_other_thread() {
        ret_without_perf!();
        use std::sync::mpsc::sync_channel;
        let (tx1, rx1) = sync_channel(0); // send TID
        let (tx2, rx2) = sync_channel(0); // start guest spinn

        const ITERS: u64 = 100000;

        let handle = std::thread::spawn(move || {
            tx1.send(gettid()).unwrap();
            rx2.recv().unwrap();
            do_branches(ITERS);
        });

        let pc = Builder::new(rx1.recv().unwrap().as_raw(), -1)
            .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .event(Event::Hardware(HardwareEvent::BranchInstructions))
            .create()
            .unwrap();

        pc.enable().unwrap();
        tx2.send(()).unwrap(); // tell thread to start
        handle.join().unwrap();
        let ctr = pc.ctr_value().unwrap();
        assert!(ctr >= ITERS);
        assert!(ctr <= ITERS + 6000, "{}", ctr); // overhead from channel operations
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

            tx1.send(gettid()).unwrap();
            rx2.recv().unwrap();

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

        let tid = rx1.recv().unwrap();
        let pc = Builder::new(tid.as_raw(), -1)
            .sample_period(SAMPLE_PERIOD)
            .event(Event::Hardware(HardwareEvent::BranchInstructions))
            .create()
            .unwrap();
        pc.set_signal_delivery(tid.into(), MARKER_SIGNAL).unwrap();
        pc.enable().unwrap();

        tx2.send(()).unwrap(); // tell thread to start
        handle.join().unwrap(); // propagate panics
    }
}
