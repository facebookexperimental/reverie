//! Narrow PMU clock primitive shared with in-guest Reverie backends.

use reverie::Errno;

use crate::perf::Builder;
use crate::perf::PerfCounter;
use crate::timer::PmuConfig;

/// A retired-conditional-branch counter owned and read by the current thread.
///
/// Unlike the ptrace timer, this counter never delivers a signal and never
/// reads another thread.  The same thread that owns the PMU event reads it via
/// `rdpmc`, which is the binding required by [`PerfCounter::ctr_value_rdpmc`].
/// In-guest backends use it to sample the guest clock at an instrumentation
/// trampoline boundary and then deduct branches retired by their own handler.
#[derive(Debug)]
pub struct InGuestRcbCounter {
    counter: PerfCounter,
}

impl InGuestRcbCounter {
    /// Create and enable an RCB clock for the calling thread.
    pub fn current_thread() -> Result<Self, Errno> {
        Self::current_thread_with_optional_syscall_gate(None)
    }

    /// Create the same current-thread RCB clock through a caller-supplied raw
    /// syscall gate. In-guest backends use this after installing seccomp so the
    /// counter's perf-event, mmap, and ioctl setup cannot recursively enter the
    /// Tool that is currently rebuilding fork-child state.
    ///
    /// # Safety
    ///
    /// The gate must preserve Linux x86-64 syscall argument/result semantics
    /// and remain callable for the lifetime of the returned counter.
    pub unsafe fn current_thread_with_syscall_gate(
        raw_syscall: unsafe fn(i64, [u64; 6]) -> i64,
    ) -> Result<Self, Errno> {
        Self::current_thread_with_optional_syscall_gate(Some(raw_syscall))
    }

    fn current_thread_with_optional_syscall_gate(
        raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
    ) -> Result<Self, Errno> {
        let config = PmuConfig::try_new().ok_or(Errno::ENODEV)?;
        let mut builder = Builder::new(0, -1);
        builder
            .sample_period(0)
            .event(config.rcb_event())
            .fast_reads(true);
        let counter = if let Some(raw_syscall) = raw_syscall {
            builder.create_with_raw_syscall(raw_syscall)?
        } else {
            builder.create()?
        };
        counter.reset()?;
        counter.enable()?;
        Ok(Self { counter })
    }

    /// Read the calling thread's current RCB count without a syscall whenever
    /// the kernel exposes the live PMU counter to user space.
    #[inline(always)]
    pub fn read(&self) -> Result<u64, Errno> {
        self.counter.ctr_value_rdpmc()
    }
}
