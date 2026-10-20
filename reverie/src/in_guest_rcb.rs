//! Narrow PMU clock primitive shared with in-guest Reverie backends.

use crate::Errno;
use crate::perf::Builder;
use crate::perf::PerfCounter;
use crate::pmu_config::PmuConfig;

/// A retired-conditional-branch counter owned and read by the current thread.
///
/// The enabled constructors support ordinary current-thread sampling through
/// `read()`, using RDPMC when available and the existing syscall fallback
/// otherwise. In-guest users of that mode account for handler branches
/// separately.
///
/// The disabled constructor supports trusted enable/disable boundaries that
/// exclude runtime work. `read_paused_once()` reads the cumulative count with
/// one trusted syscall while the event is disabled, without resetting it or
/// subtracting handler branches. This counter does not deliver timer signals.
#[derive(Debug)]
pub struct InGuestRcbCounter {
    counter: PerfCounter,
}

impl InGuestRcbCounter {
    /// Create an initially disabled clock using the ordinary shared PMU builder.
    /// Enable it only at an accounted guest boundary; never reset it thereafter.
    /// Existing enabled constructors and ordinary reads are unaffected.
    ///
    /// # Safety
    ///
    /// The gate must preserve raw Linux syscall semantics and remain callable
    /// for the counter's lifetime, including cleanup and Drop. It must satisfy
    /// Builder::create_with_raw_syscall's mapping/descriptor contract. Boundary controls and reads must run on the
    /// owning thread with exclusive control of the event.
    /// Asynchronous reads additionally require a gate that does not allocate,
    /// lock, initialize TLS, panic or retry, and is safe in that signal context.
    pub unsafe fn current_thread_disabled_with_syscall_gate(
        raw_syscall: unsafe fn(i64, [u64; 6]) -> i64,
    ) -> Result<Self, Errno> {
        // SAFETY: this public unsafe constructor requires the retained gate contract.
        unsafe { Self::create_with_config(PmuConfig::try_new(), Some(raw_syscall)) }
    }

    /// Borrow this clock's descriptor for trusted assembly boundary controls.
    ///
    /// # Safety
    ///
    /// Use only on the owning thread. The caller must protect the descriptor
    /// from guest access, never close, duplicate, reset or reconfigure it, and
    /// exclusively coordinate disable/read/enable with every guest transition.
    /// Keeping the descriptor does not make a Rust control path branch-free.
    pub unsafe fn boundary_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.counter.raw_fd()) }
    }

    /// Read a disabled clock once through its trusted gate, without retrying,
    /// allocating, panicking or changing its cumulative value in this wrapper.
    /// The supplied gate must independently satisfy these requirements.
    ///
    /// Returns EBUSY for a scheduled event, ENODEV for lost PMU availability,
    /// EAGAIN for changing metadata, EIO for a short read, or the syscall error.
    /// A missing mapping or trusted gate returns EOPNOTSUPP.
    ///
    /// # Safety
    ///
    /// The owning thread must have successfully disabled this event and must
    /// exclude concurrent or reentrant controls until this read completes.
    pub unsafe fn read_paused_once(&self) -> Result<u64, Errno> {
        self.counter.ctr_value_paused_once()
    }

    /// Create and enable an RCB clock for the calling thread.
    pub fn current_thread() -> Result<Self, Errno> {
        // SAFETY: None uses the ordinary native implementation, with no unsafe gate.
        unsafe { Self::current_thread_with_optional_syscall_gate(None) }
    }

    /// Create the same current-thread RCB clock through a caller-supplied raw
    /// syscall gate. In-guest backends use this after installing seccomp so the
    /// counter's perf-event, mmap, and ioctl setup cannot recursively enter the
    /// Tool that is currently rebuilding fork-child state.
    ///
    /// # Safety
    ///
    /// The gate must preserve Linux x86-64 syscall argument/result semantics
    /// and remain callable for the lifetime of the returned counter, including
    /// cleanup and Drop. Its mappings/descriptors must satisfy
    /// Builder::create_with_raw_syscall's complete resource contract.
    pub unsafe fn current_thread_with_syscall_gate(
        raw_syscall: unsafe fn(i64, [u64; 6]) -> i64,
    ) -> Result<Self, Errno> {
        // SAFETY: the public unsafe caller guarantees the gate through teardown.
        unsafe { Self::current_thread_with_optional_syscall_gate(Some(raw_syscall)) }
    }

    /// # Safety
    /// Any supplied gate must satisfy Builder::create_with_raw_syscall's contract
    /// throughout setup, use, failure cleanup and Drop. None uses native libc.
    unsafe fn current_thread_with_optional_syscall_gate(
        raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
    ) -> Result<Self, Errno> {
        // SAFETY: the caller guarantees the optional gate's retained contract.
        unsafe { Self::current_thread_with_config(PmuConfig::try_new(), raw_syscall) }
    }

    /// # Safety
    /// Any supplied gate must satisfy Builder::create_with_raw_syscall's contract
    /// throughout setup, use, failure cleanup and Drop. None uses native libc.
    unsafe fn current_thread_with_config(
        config: Option<PmuConfig>,
        raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
    ) -> Result<Self, Errno> {
        // SAFETY: the optional gate contract is propagated from this unsafe caller.
        let clock = unsafe { Self::create_with_config(config, raw_syscall) }?;
        clock.counter.reset()?;
        clock.counter.enable()?;
        Ok(clock)
    }

    /// # Safety
    /// Any supplied gate must satisfy Builder::create_with_raw_syscall's contract
    /// throughout setup, use, failure cleanup and Drop. None uses native libc.
    unsafe fn create_with_config(
        config: Option<PmuConfig>,
        raw_syscall: Option<unsafe fn(i64, [u64; 6]) -> i64>,
    ) -> Result<Self, Errno> {
        let config = config.ok_or(Errno::ENODEV)?;
        let mut builder = Builder::new(0, -1);
        builder
            .sample_period(0)
            .event(config.rcb_event())
            .fast_reads(true);
        let counter = if let Some(raw_syscall) = raw_syscall {
            // SAFETY: the constructor chain guarantees this gate's full contract.
            unsafe { builder.create_with_raw_syscall(raw_syscall) }?
        } else {
            builder.create()?
        };
        Ok(Self { counter })
    }

    /// Read the calling thread's current RCB count without a syscall whenever
    /// the kernel exposes the live PMU counter to user space.
    #[inline(always)]
    pub fn read(&self) -> Result<u64, Errno> {
        self.counter.ctr_value_rdpmc()
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "in_guest_rcb/tests.rs"]
mod boundary_tests;

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_model_is_refused_before_perf_event_open() {
        let config = PmuConfig::try_from_family_model(0x06, 0x01);
        // SAFETY: None selects native libc; unknown configuration refuses before use.
        let error =
            unsafe { InGuestRcbCounter::current_thread_with_config(config, None) }.unwrap_err();
        assert_eq!(error, Errno::ENODEV);
    }
}
