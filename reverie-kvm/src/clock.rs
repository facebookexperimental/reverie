/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Retired conditional branches belonging to one guest thread.
//!
//! A guest-only perf event (`exclude_host`) belongs to a host task, not to a
//! vCPU. It counts only while that task executes guest user mode, so an event
//! that follows its task stays enabled across Tool code. A host task can still
//! enter another guest between two entries of this one, so every entry is
//! bracketed by two reads and only that delta is added to this guest's clock.
//! This module owns the only mutable VcpuFd and enforces that interval for
//! every entry, including syscall-return parking. This is a clock, not a
//! precise timer.
//!
//! On an AMD host with one core PMU the event follows its task across CPUs
//! (`perf_event_open(tid, -1, ..)`); the kernel carries the count across
//! migrations. Every other host keeps the original path: each entry is pinned
//! to the CPU whose CPUID selected the raw encoding, and the CPU-bound event is
//! enabled for that entry only.

use std::marker::PhantomData;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::rc::Rc;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use kvm_ioctls::VcpuExit;
use kvm_ioctls::VcpuFd;
use perf_event_open_sys::bindings as perf;
use perf_event_open_sys::ioctls;
use reverie::pmu::PmuProfile;

use crate::Error;
use crate::Result;
use crate::entry::Participant;
use crate::entry::RunEntry;
use crate::entry::owner::OperationOrigin;
use crate::failure::FailureContext;
use crate::memory::GuestMemory;

fn failure(message: impl Into<String>) -> Error {
    Error::GuestClock(message.into())
}

fn host_failure(operation: &str) -> Error {
    failure(format!("{operation}: {}", std::io::Error::last_os_error()))
}

#[cfg(test)]
type BeforeRunHook = Box<dyn FnOnce(&RunProbe) + Send>;

#[cfg(test)]
type AfterIntervalHook = Box<dyn FnOnce(&GuestClock) + Send>;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RunProbe {
    pub(crate) prepare: std::sync::Arc<crate::entry::PrepareProbe>,
    pub(crate) shared_fd_accesses: std::sync::atomic::AtomicUsize,
    pub(crate) untracked_runs: std::sync::atomic::AtomicUsize,
    pub(crate) tracked_runs: std::sync::atomic::AtomicUsize,
    pub(crate) clock_begins: std::sync::atomic::AtomicUsize,
    pub(crate) intervals_created: std::sync::atomic::AtomicUsize,
    before_run: std::sync::Mutex<Option<BeforeRunHook>>,
    after_prepare: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    after_interval: std::sync::Mutex<Option<AfterIntervalHook>>,
}

#[cfg(test)]
impl RunProbe {
    pub(crate) fn before_run(&self, hook: impl FnOnce(&RunProbe) + Send + 'static) {
        let previous = self.before_run.lock().unwrap().replace(Box::new(hook));
        assert!(previous.is_none(), "entry control replaced an armed hook");
    }

    pub(crate) fn arm(&self) {
        self.prepare
            .armed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn run_hook(&self) {
        let hook = self.before_run.lock().unwrap().take();
        if let Some(hook) = hook {
            hook(self);
        }
    }
}

/// Read-only test observation of the actual private hypercall response slot.
/// The handle does not own the KVM_RUN mapping or retain a VcpuFd reference.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct HypercallProbe {
    run_address: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HypercallSnapshot {
    pub(crate) number: u64,
    pub(crate) return_address: usize,
    pub(crate) return_value: u64,
}

#[cfg(test)]
impl HypercallProbe {
    /// # Safety
    /// The originating CountedVcpu must still own this mapping and be stopped
    /// at an actual Hypercall exit. Call on its driver thread, or after physical
    /// join has transferred exclusive backend ownership to the calling thread.
    /// There must be no concurrent KVM_RUN, response write, or mutable mapping
    /// access. The observer performs no ioctl and never changes the response.
    pub(crate) unsafe fn snapshot(self) -> HypercallSnapshot {
        let run = self.run_address as *const kvm_bindings::kvm_run;
        // SAFETY: the caller establishes lifetime, exit kind and exclusion;
        // check the kind before interpreting the active union field.
        unsafe {
            assert_eq!((*run).exit_reason, kvm_bindings::KVM_EXIT_HYPERCALL);
            let hypercall = std::ptr::addr_of!((*run).__bindgen_anon_1.hypercall);
            HypercallSnapshot {
                number: (*hypercall).nr,
                return_address: std::ptr::addr_of!((*hypercall).ret) as usize,
                return_value: (*hypercall).ret,
            }
        }
    }
}

/// Shared-fd configuration and register APIs remain available, but mutable fd
/// access does not: VcpuFd::run can only be called inside this module.
pub(crate) struct CountedVcpu {
    fd: VcpuFd,
    /// KVM copies the general and special registers into the shared
    /// `kvm_run` page on every exit (`KVM_CAP_SYNC_REGS`).
    sync_regs: bool,
    /// The synced copy is current: the last `KVM_RUN` returned an exit and
    /// nothing has borrowed the raw fd since. Every [`Deref`] clears it,
    /// because the raw fd can change registers (`set_regs`, `set_sregs`,
    /// `set_msrs`, ...). `run` takes `&mut self`, so no raw borrow taken before
    /// an exit can still be alive after it.
    synced_exit: std::sync::atomic::AtomicBool,
    /// `fd`'s `kvm_run.immediate_exit` byte, which the kick handler sets.
    immediate_exit: crate::entry::ImmediateExit,
    participant: Participant,
    // Keep the Mapping alive independently of the backend field's drop order.
    memory: GuestMemory,
    clock: GuestClock,
    image_is_elf: bool,
    initial_elf_ran: bool,
    #[cfg(test)]
    run_probe: Option<std::sync::Arc<RunProbe>>,
}

impl Deref for CountedVcpu {
    type Target = VcpuFd;

    fn deref(&self) -> &Self::Target {
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.prepare.increment(&probe.shared_fd_accesses);
        }
        self.synced_exit
            .store(false, std::sync::atomic::Ordering::Relaxed);
        &self.fd
    }
}

impl CountedVcpu {
    pub(crate) fn new(mut fd: VcpuFd, memory: GuestMemory, sync_regs: bool) -> Result<Self> {
        let participant = memory
            .entry_gate()
            .register()
            .map_err(|failure| failure.error())?;
        if sync_regs {
            fd.set_sync_valid_reg(kvm_ioctls::SyncReg::Register);
            fd.set_sync_valid_reg(kvm_ioctls::SyncReg::SystemRegister);
        }
        // SAFETY: this struct owns fd, whose kvm_run mapping therefore
        // outlives every entry `run` prepares; moving fd does not move it.
        let immediate_exit = unsafe { crate::entry::ImmediateExit::new(&mut fd) };
        Ok(Self {
            fd,
            sync_regs,
            synced_exit: std::sync::atomic::AtomicBool::new(false),
            immediate_exit,
            participant,
            memory,
            clock: GuestClock::default(),
            image_is_elf: false,
            initial_elf_ran: false,
            #[cfg(test)]
            run_probe: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_run_probe(&mut self, probe: std::sync::Arc<RunProbe>) {
        self.participant.set_prepare_probe(probe.prepare.clone());
        self.clock.run_probe = Some(probe.clone());
        self.run_probe = Some(probe);
    }

    #[cfg(test)]
    pub(crate) fn hypercall_probe(&mut self) -> HypercallProbe {
        HypercallProbe {
            run_address: std::ptr::from_mut(self.fd.get_kvm_run()) as usize,
        }
    }

    /// The guest's general registers. After an exit this reads KVM's synced
    /// copy without an ioctl; otherwise, or after any raw fd access, it asks
    /// KVM (`KVM_GET_REGS`).
    pub(crate) fn get_regs(
        &self,
    ) -> std::result::Result<kvm_bindings::kvm_regs, kvm_ioctls::Error> {
        // Both paths read the fd's register state (its kvm_run page or an
        // ioctl), so the probe counts them as shared-fd accesses, as a raw
        // `Deref` read was counted before.
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.prepare.increment(&probe.shared_fd_accesses);
        }
        if self.synced_exit.load(std::sync::atomic::Ordering::Relaxed) {
            Ok(self.fd.sync_regs().regs)
        } else {
            self.fd.get_regs()
        }
    }

    /// The guest's special registers, from the synced copy as for
    /// [`Self::get_regs`] (`KVM_GET_SREGS` otherwise).
    pub(crate) fn get_sregs(
        &self,
    ) -> std::result::Result<kvm_bindings::kvm_sregs, kvm_ioctls::Error> {
        // Both paths read the fd's register state (its kvm_run page or an
        // ioctl), so the probe counts them as shared-fd accesses, as a raw
        // `Deref` read was counted before.
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.prepare.increment(&probe.shared_fd_accesses);
        }
        if self.synced_exit.load(std::sync::atomic::Ordering::Relaxed) {
            let special = self.fd.sync_regs().sregs;
            // KVM sets bits in the synced interrupt bitmap but never clears
            // them (measured on Linux 7.1.3), while KVM_GET_SREGS reports the
            // pending bitmap. This backend injects no interrupt, so the bitmap
            // is zero; should one ever be set, ask KVM rather than return it.
            if special.interrupt_bitmap.iter().all(|word| *word == 0) {
                return Ok(special);
            }
        }
        self.fd.get_sregs()
    }

    pub(crate) fn set_failure_context(&mut self, origin: Option<FailureContext>) {
        self.memory.set_failure_context(origin);
        self.participant.set_origin(self.memory.entry_origin());
    }

    pub(crate) fn set_operation_origin(&mut self, origin: Option<OperationOrigin>) {
        self.memory.set_operation_origin(origin);
        self.participant.set_origin(self.memory.entry_origin());
    }

    /// Only initial installation creates a new thread lifetime. Exec retains
    /// this vCPU and must not call this method.
    pub(crate) fn new_guest(&mut self) {
        self.clock = GuestClock::default();
        #[cfg(test)]
        {
            self.clock.run_probe = self.run_probe.clone();
        }
        self.image_is_elf = false;
    }

    pub(crate) fn new_elf_guest(&mut self) {
        self.new_guest();
        self.image_is_elf = true;
    }

    pub(crate) fn check_initial_elf_install(&self) -> Result<()> {
        if self.initial_elf_ran {
            return Err(Error::InitialElfReinstallationUnsupported);
        }
        Ok(())
    }

    pub(crate) fn track_clock(&mut self) -> Result<()> {
        if self.clock.poison.is_some() {
            return self.clock.read().map(|_| ());
        }
        if self.clock.tracking {
            return Ok(());
        }
        if self.clock.ran_untracked {
            return Err(failure(
                "cannot start a clock after untracked guest execution",
            ));
        }
        self.clock.tracking = true;
        // Admit the pinned event before the first lifecycle callback. No guest
        // has run yet, and excluded host work must not contribute to its clock.
        self.clock.begin()?.finish()?;
        if self.clock.total != 0 {
            return Err(self.clock.poison("counter counted outside KVM_RUN"));
        }
        Ok(())
    }

    pub(crate) fn read_clock(&self) -> Result<u64> {
        self.clock.read()
    }

    /// None means admission was closed: no clock interval or KVM_RUN occurred.
    /// The caller retains its prepared continuation and waits outside this
    /// method, with no entry, CPU-affinity or borrowed-exit guard alive.
    pub(crate) fn run(&mut self) -> Result<Option<VcpuExit<'_>>> {
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.run_hook();
        }
        // The synced copy describes the previous exit only until this entry.
        self.synced_exit
            .store(false, std::sync::atomic::Ordering::Relaxed);
        // Declare entry first: unwinding must retire the clock and restore CPU
        // affinity before entry withdraws its target and checks its signals.
        let Some(entry) = self
            .participant
            .prepare(Some(self.immediate_exit))
            .map_err(|failure| failure.error())?
        else {
            return Ok(None);
        };
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            let hook = probe.after_prepare.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        if !self.clock.tracking {
            self.clock.ran_untracked = true;
            self.initial_elf_ran |= self.image_is_elf;
            #[cfg(test)]
            if let Some(probe) = &self.run_probe {
                probe.prepare.increment(&probe.untracked_runs);
            }
            let exit = finish_entry(self.fd.run().map_err(Error::Kvm), entry);
            if exit.is_ok() && self.sync_regs {
                self.synced_exit
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            return exit.map(Some);
        }
        let interval = match self.clock.begin() {
            Ok(interval) => interval,
            Err(error) => return finish_entry(Err(error), entry),
        };
        self.initial_elf_ran |= self.image_is_elf;
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.prepare.increment(&probe.tracked_runs);
        }
        let result = self.fd.run();
        // VcpuExit borrows only fd. Always finish the separate clock interval,
        // including EINTR and other KVM errors, before exposing that exit.
        let result = finish_run(result, interval);
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            let hook = probe.after_interval.lock().unwrap().take();
            if let Some(hook) = hook {
                hook(&self.clock);
            }
        }
        let exit = finish_entry(result, entry);
        if exit.is_ok() && self.sync_regs {
            self.synced_exit
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        exit.map(Some)
    }
}

fn finish_entry<T>(result: Result<T>, entry: RunEntry<'_>) -> Result<T> {
    match result {
        // An actual ioctl error, including EINTR, retains the caller's existing
        // policy when clock and entry cleanup succeeded. Do not poison a whole
        // address space merely because KVM_RUN was interrupted.
        Err(Error::Kvm(error)) => match entry.finish(Ok(())) {
            Ok(()) => Err(Error::Kvm(error)),
            Err(failure) => Err(failure.error().with_cleanup(vec![Error::Kvm(error)])),
        },
        // A failed clock interval cannot publish trustworthy guest progress.
        // Stop every participant and callback copy in this Mapping while the
        // issuing owner retains and publishes the typed terminal failure.
        Err(error) => match entry.finish(Err(error)) {
            Err(failure) => Err(failure.error()),
            Ok(()) => unreachable!("failed clock setup or cleanup admitted success"),
        },
        Ok(exit) => {
            entry.finish(Ok(())).map_err(|failure| failure.error())?;
            Ok(exit)
        }
    }
}

fn finish_run<T>(
    result: std::result::Result<T, kvm_ioctls::Error>,
    interval: CountInterval<'_>,
) -> Result<T> {
    match (result, interval.finish()) {
        (result, Ok(())) => result.map_err(Error::Kvm),
        (Ok(_), Err(error)) => Err(error),
        (Err(kvm), Err(clock)) => Err(failure(format!("{clock}; KVM_RUN also failed: {kvm}"))),
    }
}

/// Where a counted entry may run; see the module documentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CounterPlacement {
    /// One encoding for every CPU: the per-task event follows migrations.
    FollowTask,
    /// Hybrid core PMUs: pin each entry to one CPU and bind the event to it.
    PinEachEntry,
}

impl Default for CounterPlacement {
    fn default() -> Self {
        static PLACEMENT: std::sync::OnceLock<CounterPlacement> = std::sync::OnceLock::new();
        *PLACEMENT.get_or_init(|| {
            // Linux names a single core PMU `cpu`; hybrid hosts expose
            // `cpu_core` and `cpu_atom` instead. Anything else stays pinned.
            // FollowTask is measured only on AMD (devbig014, EPYC 9D85); every
            // other vendor keeps the pinned path until it is measured there.
            let vendor = std::arch::x86_64::__cpuid(0);
            let amd = (vendor.ebx, vendor.edx, vendor.ecx)
                == (
                    u32::from_le_bytes(*b"Auth"),
                    u32::from_le_bytes(*b"enti"),
                    u32::from_le_bytes(*b"cAMD"),
                );
            let pmus = std::path::Path::new("/sys/bus/event_source/devices");
            if amd
                && pmus.join("cpu").exists()
                && !pmus.join("cpu_core").exists()
                && !pmus.join("cpu_atom").exists()
            {
                CounterPlacement::FollowTask
            } else {
                CounterPlacement::PinEachEntry
            }
        })
    }
}

#[derive(Default)]
struct GuestClock {
    placement: CounterPlacement,
    tracking: bool,
    ran_untracked: bool,
    total: u64,
    binding: Option<CounterBinding>,
    poison: Option<String>,
    #[cfg(test)]
    run_probe: Option<std::sync::Arc<RunProbe>>,
}

impl GuestClock {
    fn read(&self) -> Result<u64> {
        if let Some(reason) = &self.poison {
            return Err(failure(format!("clock cannot resume after: {reason}")));
        }
        if !self.tracking {
            return Err(failure("guest clock is not active"));
        }
        Ok(self.total)
    }

    fn poison(&mut self, reason: impl ToString) -> Error {
        let reason = reason.to_string();
        // Closing is the only disable: the event otherwise stays enabled.
        // Never leave it open while an error unwinds into another task.
        self.binding.take();
        self.poison = Some(reason.clone());
        failure(reason)
    }

    fn begin(&mut self) -> Result<CountInterval<'_>> {
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.prepare.increment(&probe.clock_begins);
        }
        self.begin_with_raw_event(current_raw_event)
    }

    fn begin_with_raw_event(
        &mut self,
        raw_event: impl FnOnce() -> Result<u64>,
    ) -> Result<CountInterval<'_>> {
        self.read()?;
        let mut affinity = match self.placement {
            CounterPlacement::FollowTask => None,
            CounterPlacement::PinEachEntry => match CpuAffinity::enter() {
                Ok(affinity) => Some(affinity),
                Err(error) => return Err(self.poison(error)),
            },
        };
        let admission = (|| {
            let identity = CounterIdentity {
                tid: host_tid(),
                thread: std::thread::current().id(),
                cpu: affinity
                    .as_ref()
                    .map_or(FOLLOWS_TASK, |affinity| affinity.cpu),
                raw_event: raw_event()?,
            };
            if self.binding.as_ref().map(|b| b.identity) != Some(identity) {
                self.binding.take();
                self.binding = Some(CounterBinding::open(identity)?);
            }
            self.binding.as_mut().unwrap().start_interval()
        })();
        if let Err(error) = admission {
            // No guest instruction ran. Closing even an ambiguously enabled
            // event must precede affinity restoration and error propagation.
            self.binding.take();
            let reason = match affinity.as_mut().map_or(Ok(()), CpuAffinity::restore) {
                Ok(()) => error.to_string(),
                Err(cleanup) => format!("{error}; cleanup also failed: {cleanup}"),
            };
            return Err(self.poison(reason));
        }
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.prepare.increment(&probe.intervals_created);
        }
        Ok(CountInterval {
            clock: self,
            affinity,
            finished: false,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterIdentity {
    tid: libc::pid_t,
    // Linux can reuse a numeric TID after thread exit; ThreadId is never reused.
    thread: std::thread::ThreadId,
    cpu: usize,
    raw_event: u64,
}

/// `CounterIdentity::cpu` of an event that follows its task across CPUs.
const FOLLOWS_TASK: usize = usize::MAX;

/// The process epoch of the cached task IDs below lives in one anonymous page
/// marked `MADV_WIPEONFORK`. The kernel zeroes that page in every child that
/// gets its own copy of the address space: a `fork()` child and a raw
/// `clone()` child without `CLONE_VM` alike. That child's only thread is a new
/// task whose inherited thread-local still names its parent's thread, and a
/// zero epoch makes it read its task ID afresh. pthread_atfork would cover
/// only `fork()`, and Hermit starts KVM runs in a raw `clone()` child.
static TID_EPOCH_PAGE: AtomicPtr<AtomicU64> = AtomicPtr::new(std::ptr::null_mut());

/// The source of fresh epochs, in ordinary memory: a child inherits it, so
/// every epoch it draws is larger than any epoch its parent cached.
static NEXT_TID_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Whether the epoch page is set up: 0 not yet, 1 a thread is setting it up,
/// 2 ready, 3 unavailable. Nothing ever waits on this. A child of a process
/// that was mid-setup inherits 1 with no thread to finish it, and like an
/// unavailable page, only reads its task ID uncached, which is always correct.
static TID_EPOCH_STATE: AtomicU8 = AtomicU8::new(0);

const TID_EPOCH_PAGE_BYTES: usize = 4096;

/// The epoch page, set up on first use; None while it is not (yet) usable.
fn tid_epoch_page() -> Option<&'static AtomicU64> {
    match TID_EPOCH_STATE.load(Ordering::Acquire) {
        2 => {}
        0 if TID_EPOCH_STATE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok() =>
        {
            // SAFETY: a fresh private anonymous mapping; no existing memory is
            // affected. It is never unmapped once published.
            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    TID_EPOCH_PAGE_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if page == libc::MAP_FAILED {
                TID_EPOCH_STATE.store(3, Ordering::Release);
                return None;
            }
            // SAFETY: `page` is the mapping just created, of this length.
            if unsafe { libc::madvise(page, TID_EPOCH_PAGE_BYTES, libc::MADV_WIPEONFORK) } != 0 {
                // SAFETY: unmapping the unpublished mapping created above.
                unsafe { libc::munmap(page, TID_EPOCH_PAGE_BYTES) };
                TID_EPOCH_STATE.store(3, Ordering::Release);
                return None;
            }
            TID_EPOCH_PAGE.store(page.cast(), Ordering::Relaxed);
            TID_EPOCH_STATE.store(2, Ordering::Release);
        }
        _ => return None,
    }
    // SAFETY: state 2 was stored (Release) after the pointer to a live,
    // zero-initialized, never-unmapped page; AtomicU64 is valid for zeroes.
    Some(unsafe { &*TID_EPOCH_PAGE.load(Ordering::Relaxed) })
}

/// This process's epoch, drawn afresh when the page reads zero (new, or wiped
/// in a child). Threads racing to draw it agree on the first stored value.
fn current_tid_epoch(page: &AtomicU64) -> u64 {
    let epoch = page.load(Ordering::Acquire);
    if epoch != 0 {
        return epoch;
    }
    let fresh = NEXT_TID_EPOCH.fetch_add(1, Ordering::Relaxed);
    match page.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(winner) => winner,
    }
}

fn gettid_uncached() -> libc::pid_t {
    // SAFETY: gettid has no pointer arguments and returns this Linux task ID.
    unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
}

/// This thread's Linux task ID, read once per thread and process. Every
/// counted entry names it in the counter identity, so caching it removes a
/// `gettid` from each guest syscall. A thread's task ID never changes; only a
/// child created without `CLONE_VM` sees a different one, and its wiped epoch
/// page retires every inherited cached value. (A `vfork()` or other
/// `CLONE_VM` child shares the page; it must only exec or exit, and never
/// enters KVM.)
fn host_tid() -> libc::pid_t {
    let Some(page) = tid_epoch_page() else {
        return gettid_uncached();
    };
    thread_local! {
        static CACHED: std::cell::Cell<Option<(u64, libc::pid_t)>> =
            const { std::cell::Cell::new(None) };
    }
    let epoch = current_tid_epoch(page);
    if let Some((cached_epoch, tid)) = CACHED.get()
        && cached_epoch == epoch
    {
        return tid;
    }
    let tid = gettid_uncached();
    CACHED.set(Some((epoch, tid)));
    tid
}

fn current_raw_event() -> Result<u64> {
    // CPUID is supported on x86-64. Under PinEachEntry the calling thread is
    // restricted to one permitted CPU for this entire counted interval; under
    // FollowTask every CPU has the same core PMU, so any CPU answers for all.
    let vendor = std::arch::x86_64::__cpuid(0);
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&vendor.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&vendor.edx.to_le_bytes());
    bytes[8..].copy_from_slice(&vendor.ecx.to_le_bytes());
    if bytes != *b"GenuineIntel" && bytes != *b"AuthenticAMD" {
        return Err(failure(format!("unsupported CPU vendor {bytes:?}")));
    }
    let signature = std::arch::x86_64::__cpuid(1).eax;
    let base_family = (signature >> 8) & 0xf;
    let family = base_family
        + if base_family == 0xf {
            (signature >> 20) & 0xff
        } else {
            0
        };
    let model = ((signature >> 4) & 0xf)
        | if matches!(base_family, 6 | 0xf) {
            (signature >> 12) & 0xf0
        } else {
            0
        };
    let vendor_matches_family = if bytes == *b"GenuineIntel" {
        family == 6
    } else {
        matches!(family, 0x17 | 0x19 | 0x1a)
    };
    if !vendor_matches_family {
        return Err(failure(format!(
            "unsupported CPU vendor/family combination {bytes:?}/{family:#x}"
        )));
    }
    PmuProfile::for_family_model(family as u8, model as u8)
        .map(|profile| profile.raw_rcb_event())
        .ok_or_else(|| {
            failure(format!(
                "unsupported CPU family {family:#x} model {model:#x}"
            ))
        })
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CounterRead {
    value: u64,
    enabled: u64,
    running: u64,
}

impl CounterRead {
    /// The guest work since `start`, after checking that the event ran for all
    /// of the time it was enabled since `last_end`, the previous interval's
    /// closing read.
    ///
    /// Residency is judged between two closing reads, never against `start`.
    /// While an event stays enabled across Tool code, a read taken as the task
    /// begins an entry can report `running` ahead of `enabled` (measured on
    /// devbig014: 2,965,191 against 2,957,590 ns, with both equal again at the
    /// closing read). Closing reads follow a completed KVM_RUN, and between two
    /// of them the event is never disabled, so any shortfall of `running` is a
    /// real residency gap. For a disabled-between-entries event the two bases
    /// coincide in time, because neither field advances while disabled.
    fn checked_interval(self, start: Self, last_end: Self) -> Result<u64> {
        let enabled = self.enabled.checked_sub(last_end.enabled);
        let running = self.running.checked_sub(last_end.running);
        if enabled.is_none() || running.is_none() || enabled != running {
            return Err(failure(format!(
                "counter lost CPU residency: {last_end:?} -> {self:?}"
            )));
        }
        self.value
            .checked_sub(start.value)
            .ok_or_else(|| failure("counter moved backwards"))
    }
}

/// A torn closing read is resampled at most this many times; see
/// [`CounterBinding::finish`].
const RESIDENCY_RESAMPLES: usize = 3;

thread_local! {
    /// The one event that follows this host task and was left enabled, with the
    /// flag that tells its binding it was disabled by another binding. A pinned
    /// per-task event occupies a hardware counter whenever its task runs, so
    /// two enabled events on one task would hold two counters, and enough of
    /// them would push later ones into the error state. A binding that enables
    /// its event first disables the one recorded here.
    static ENABLED_FOLLOWING_EVENT: std::cell::RefCell<
        Option<(std::sync::Weak<OwnedFd>, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
    > = const { std::cell::RefCell::new(None) };
}

struct CounterBinding {
    fd: std::sync::Arc<OwnedFd>,
    identity: CounterIdentity,
    /// The read that opened the current interval: the value baseline.
    previous: CounterRead,
    /// The previous interval's closing read: the residency baseline.
    last_end: CounterRead,
    enabled: bool,
    /// Set by another binding on this host task that disabled this event.
    displaced: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The event's user page, when Linux maps one: reads then take no syscall.
    page: Option<UserPage>,
}

/// An event's first mmap page. While the event is on a hardware counter, Linux
/// publishes the counter's index and the offset from its raw value there, with
/// the enabled and running times, under a sequence lock. The calling task then
/// reads the count with `rdpmc` and the times from the TSC, exactly as the
/// kernel's own read would report them, without a `read` syscall.
///
/// One limitation is inherited from the documented recipe. If root changes
/// `/sys/bus/event_source/devices/cpu/rdpmc` from 1 to 0 while a run is in
/// progress, Linux revokes user `rdpmc` at once but leaves `cap_user_rdpmc`
/// set on existing events, so the next `rdpmc` faults and the process dies
/// with SIGSEGV. It fails loudly; it never returns a wrong count.
struct UserPage(std::ptr::NonNull<perf::perf_event_mmap_page>);

// SAFETY: the page is a read-only shared mapping with no thread affinity. This
// process only reads it, through volatile loads that take no reference, and
// unmaps it once when dropped; sharing `&UserPage` therefore races nothing
// but Linux's own writes, which the sequence lock covers.
unsafe impl Send for UserPage {}
unsafe impl Sync for UserPage {}

const USER_PAGE_BYTES: usize = 4096;

/// A read that keeps racing an update of the page falls back to `read`.
const USER_READ_ATTEMPTS: usize = 8;

/// `perf_event_mmap_page::capabilities` bits (include/uapi/linux/perf_event.h).
const CAP_USER_RDPMC: u64 = 1 << 2;
const CAP_USER_TIME: u64 = 1 << 3;
const CAP_USER_TIME_SHORT: u64 = 1 << 5;

impl UserPage {
    fn map(fd: &OwnedFd) -> Option<Self> {
        // SAFETY: a fresh read-only shared mapping of this live perf event's
        // first page; no existing memory is affected.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                USER_PAGE_BYTES,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if page == libc::MAP_FAILED {
            return None;
        }
        std::ptr::NonNull::new(page.cast()).map(Self)
    }

    /// The event's current count and times, read in user space, or None when
    /// Linux does not allow that right now: the event is not on a hardware
    /// counter (disabled, displaced, or not yet scheduled), the page lacks the
    /// rdpmc or time capability, or every attempt raced an update. The caller
    /// then reads through the syscall, which is always exact.
    ///
    /// This is the algorithm documented for `perf_event_mmap_page` in
    /// include/uapi/linux/perf_event.h. A torn snapshot is never returned: the
    /// sequence lock must be unchanged across all loads and the `rdpmc`.
    fn read(&self) -> Option<CounterRead> {
        let page = self.0.as_ptr();
        // SAFETY (all loads below): `page` is this live mapping, and Linux
        // writes these fields concurrently, so each is a volatile load.
        macro_rules! load {
            ($field:ident) => {
                unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*page).$field)) }
            };
        }
        for _ in 0..USER_READ_ATTEMPTS {
            let sequence = load!(lock);
            std::sync::atomic::compiler_fence(Ordering::SeqCst);
            let capabilities = unsafe {
                std::ptr::read_volatile(std::ptr::addr_of!((*page).__bindgen_anon_1.capabilities))
            };
            let index = load!(index);
            let width = u32::from(load!(pmc_width));
            if capabilities & CAP_USER_RDPMC == 0
                || capabilities & CAP_USER_TIME == 0
                || index == 0
                || !(1..=64).contains(&width)
            {
                return None;
            }
            let offset = load!(offset);
            let enabled = load!(time_enabled);
            let running = load!(time_running);
            let shift = u32::from(load!(time_shift));
            let mult = u64::from(load!(time_mult));
            let time_offset = load!(time_offset);
            // SAFETY: rdtsc has no preconditions.
            let mut cycles = unsafe { std::arch::x86_64::_rdtsc() };
            if capabilities & CAP_USER_TIME_SHORT != 0 {
                let base = load!(time_cycles);
                cycles = base.wrapping_add(cycles.wrapping_sub(base) & load!(time_mask));
            }
            if shift >= 64 {
                return None;
            }
            let quotient = cycles >> shift;
            let remainder = cycles & ((1u64 << shift) - 1);
            let delta = time_offset
                .wrapping_add(quotient.wrapping_mul(mult))
                .wrapping_add(remainder.wrapping_mul(mult) >> shift);
            let (low, high): (u32, u32);
            // SAFETY: Linux reported user rdpmc for counter `index - 1` under
            // this sequence; a counter that moved is caught by the recheck.
            unsafe {
                std::arch::asm!(
                    "rdpmc",
                    in("ecx") index - 1,
                    out("eax") low,
                    out("edx") high,
                    options(nostack, preserves_flags),
                );
            }
            let raw = (u64::from(high) << 32) | u64::from(low);
            // Sign-extend the counter's `width` bits, as the kernel does.
            let pmc = ((raw << (64 - width)) as i64) >> (64 - width);
            std::sync::atomic::compiler_fence(Ordering::SeqCst);
            if load!(lock) == sequence {
                return Some(CounterRead {
                    value: offset.wrapping_add(pmc) as u64,
                    enabled: enabled.wrapping_add(delta),
                    running: running.wrapping_add(delta),
                });
            }
        }
        None
    }
}

#[cfg(test)]
impl UserPage {
    /// Whether Linux grants this page user `rdpmc` and user time.
    fn allows_user_read(&self) -> bool {
        let page = self.0.as_ptr();
        // SAFETY: a volatile load from this live mapping.
        let capabilities = unsafe {
            std::ptr::read_volatile(std::ptr::addr_of!((*page).__bindgen_anon_1.capabilities))
        };
        capabilities & CAP_USER_RDPMC != 0 && capabilities & CAP_USER_TIME != 0
    }
}

impl Drop for UserPage {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly the mapping created by `map`.
        unsafe { libc::munmap(self.0.as_ptr().cast(), USER_PAGE_BYTES) };
    }
}

impl CounterBinding {
    fn open(identity: CounterIdentity) -> Result<Self> {
        let mut attr = perf::perf_event_attr {
            type_: perf::PERF_TYPE_RAW,
            size: std::mem::size_of::<perf::perf_event_attr>() as u32,
            config: identity.raw_event,
            read_format: (perf::PERF_FORMAT_TOTAL_TIME_ENABLED
                | perf::PERF_FORMAT_TOTAL_TIME_RUNNING) as u64,
            ..Default::default()
        };
        attr.set_disabled(1);
        attr.set_pinned(1);
        attr.set_exclude_host(1);
        attr.set_exclude_guest(0);
        attr.set_exclude_kernel(1);
        attr.set_exclude_user(0);
        attr.set_exclude_hv(1);
        attr.set_inherit(0);
        // SAFETY: attr describes a non-sampling event for this actual host task,
        // on its enforced CPU or on any CPU. The returned descriptor is newly
        // owned.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr,
                identity.tid,
                if identity.cpu == FOLLOWS_TASK {
                    -1
                } else {
                    identity.cpu as libc::c_int
                },
                -1,
                perf::PERF_FLAG_FD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(host_failure(&format!("perf_event_open {identity:?}")));
        }
        let mut binding = Self {
            fd: std::sync::Arc::new(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) }),
            identity,
            previous: CounterRead::default(),
            last_end: CounterRead::default(),
            enabled: false,
            displaced: Default::default(),
            page: None,
        };
        binding.page = UserPage::map(&binding.fd);
        binding.previous = binding.read()?;
        binding.last_end = binding.previous;
        if binding.previous.value != 0 {
            return Err(failure("new disabled counter is not zero"));
        }
        Ok(binding)
    }

    /// An event that follows its task counts only guest user mode, so it stays
    /// enabled across Tool code after the first entry. A pinned event is
    /// re-enabled here, because between entries its task runs on other CPUs.
    /// The fresh baseline excludes guest work this host task ran for another
    /// guest since this guest's last entry.
    fn start_interval(&mut self) -> Result<()> {
        if self
            .displaced
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            self.enabled = false;
        }
        if !self.enabled {
            if self.identity.cpu == FOLLOWS_TASK {
                self.displace_other_following_event();
            }
            self.enable()?;
        }
        self.previous = self.read()?;
        Ok(())
    }

    /// Keeps at most one following event enabled on this host task (see
    /// [`ENABLED_FOLLOWING_EVENT`]). The displaced binding is idle, because
    /// entries on one host task never overlap; it re-enables at its next entry
    /// and re-reads its baseline there, so no count is lost or misattributed.
    fn displace_other_following_event(&self) {
        ENABLED_FOLLOWING_EVENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some((other, displaced)) = slot.take()
                && !std::sync::Arc::ptr_eq(&displaced, &self.displaced)
            {
                if let Some(other) = other.upgrade() {
                    // A failure leaves the other event enabled, which costs a
                    // counter but cannot miscount: it counts only guest mode
                    // and its own entries re-read their baselines.
                    // SAFETY: the descriptor is a live perf event.
                    let _ = unsafe { ioctls::DISABLE(other.as_raw_fd(), 0) };
                }
                displaced.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            *slot = Some((std::sync::Arc::downgrade(&self.fd), self.displaced.clone()));
        });
    }

    fn enable(&mut self) -> Result<()> {
        // Mark before the ioctl so even an ambiguous failure is cleaned up.
        self.enabled = true;
        if unsafe { ioctls::ENABLE(self.fd.as_raw_fd(), 0) } < 0 {
            return Err(host_failure("enable guest counter"));
        }
        Ok(())
    }

    fn read(&self) -> Result<CounterRead> {
        if let Some(read) = self.page.as_ref().and_then(UserPage::read) {
            return Ok(read);
        }
        self.read_syscall()
    }

    fn read_syscall(&self) -> Result<CounterRead> {
        let mut value = CounterRead::default();
        // SAFETY: the event's read_format is exactly these three native u64s.
        let count = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                std::ptr::from_mut(&mut value).cast(),
                std::mem::size_of::<CounterRead>(),
            )
        };
        if count < 0 {
            return Err(host_failure("read guest counter"));
        }
        if count as usize != std::mem::size_of::<CounterRead>() {
            return Err(failure(format!(
                "guest counter read returned {count} bytes, expected 24"
            )));
        }
        Ok(value)
    }

    fn disable(&mut self) -> Result<()> {
        if self.enabled {
            if unsafe { ioctls::DISABLE(self.fd.as_raw_fd(), 0) } < 0 {
                return Err(host_failure("disable guest counter"));
            }
            self.enabled = false;
        }
        Ok(())
    }

    fn finish(&mut self, total: u64) -> Result<u64> {
        if self.identity.cpu != FOLLOWS_TASK {
            // A CPU-bound event must not stay enabled once affinity is restored.
            self.disable()?;
        }
        let mut current = self.read()?;
        // Linux copies an event's enabled and running times one after the
        // other while the event stays live, so a reader preempted between the
        // two copies can see one updated and not the other. A residency gap
        // never closes (enabled - running only grows), so resampling cannot
        // turn a real gap into a match; it only retries a torn sample. The
        // value does not move between samples: no guest runs on this task.
        for _ in 0..RESIDENCY_RESAMPLES {
            if current.enabled.checked_sub(self.last_end.enabled)
                == current.running.checked_sub(self.last_end.running)
            {
                break;
            }
            current = self.read()?;
        }
        let delta = current.checked_interval(self.previous, self.last_end)?;
        let total = total
            .checked_add(delta)
            .ok_or_else(|| failure("guest clock overflow"))?;
        self.previous = current;
        self.last_end = current;
        Ok(total)
    }
}

struct CountInterval<'a> {
    clock: &'a mut GuestClock,
    /// Present only under `CounterPlacement::PinEachEntry`.
    affinity: Option<CpuAffinity>,
    finished: bool,
}

impl CountInterval<'_> {
    fn finish(mut self) -> Result<()> {
        let counted = self
            .clock
            .binding
            .as_mut()
            .map_or(Ok(self.clock.total), |b| b.finish(self.clock.total));
        if counted.is_err() {
            // A failed read leaves no trustworthy baseline. Close the event
            // while still pinned, before any affinity restoration can move us.
            self.clock.binding.take();
        }
        let resident = self.affinity.as_ref().map_or(Ok(()), CpuAffinity::check);
        let restored = self.affinity.as_mut().map_or(Ok(()), CpuAffinity::restore);
        self.finished = true;
        let mut errors = Vec::new();
        for error in [
            counted.as_ref().err(),
            resident.as_ref().err(),
            restored.as_ref().err(),
        ]
        .into_iter()
        .flatten()
        {
            errors.push(error.to_string());
        }
        if !errors.is_empty() {
            return Err(self.clock.poison(errors.join("; ")));
        }
        self.clock.total = counted?;
        Ok(())
    }
}

impl Drop for CountInterval<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Unwinding cannot report a trustworthy completed interval. Close
            // the event before restoring affinity; later clock reads fail.
            self.clock.poison("unwound during counted KVM_RUN");
        }
    }
}

/// Never held across an await or moved to another host task.
struct CpuAffinity {
    saved: libc::cpu_set_t,
    cpu: usize,
    active: bool,
    #[cfg(test)]
    closed_fd_before_restore: Option<libc::c_int>,
    _same_thread: PhantomData<Rc<()>>,
}

fn affinity() -> Result<libc::cpu_set_t> {
    let mut set = unsafe { std::mem::zeroed() };
    // EINVAL on hosts exceeding cpu_set_t capacity is an explicit unsupported
    // configuration, not permission to use a truncated CPU set.
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) } < 0 {
        return Err(host_failure("read host CPU affinity"));
    }
    Ok(set)
}

fn set_affinity(set: &libc::cpu_set_t) -> Result<()> {
    if unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), set) } < 0 {
        return Err(host_failure("set host CPU affinity"));
    }
    Ok(())
}

fn same_affinity(left: &libc::cpu_set_t, right: &libc::cpu_set_t) -> bool {
    (0..libc::CPU_SETSIZE as usize)
        .all(|cpu| unsafe { libc::CPU_ISSET(cpu, left) == libc::CPU_ISSET(cpu, right) })
}

impl CpuAffinity {
    fn enter() -> Result<Self> {
        let saved = affinity()?;
        let current = unsafe { libc::sched_getcpu() };
        let cpu = if current >= 0 && unsafe { libc::CPU_ISSET(current as usize, &saved) } {
            current as usize
        } else {
            (0..libc::CPU_SETSIZE as usize)
                .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &saved) })
                .ok_or_else(|| failure("no permitted CPU"))?
        };
        let mut guard = Self {
            saved,
            cpu,
            active: true,
            #[cfg(test)]
            closed_fd_before_restore: None,
            _same_thread: PhantomData,
        };
        let mut singleton = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_SET(cpu, &mut singleton) };
        let entered = set_affinity(&singleton).and_then(|()| guard.check());
        if let Err(error) = entered {
            return match guard.restore() {
                Ok(()) => Err(error),
                Err(restore) => Err(failure(format!("{error}; {restore}"))),
            };
        }
        Ok(guard)
    }

    fn check(&self) -> Result<()> {
        let allowed = affinity()?;
        if unsafe { libc::sched_getcpu() } != self.cpu as libc::c_int
            || (0..libc::CPU_SETSIZE as usize)
                .any(|cpu| unsafe { libc::CPU_ISSET(cpu, &allowed) } != (cpu == self.cpu))
        {
            return Err(failure(format!(
                "guest counter escaped enforced CPU {}",
                self.cpu
            )));
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        #[cfg(test)]
        if let Some(fd) = self.closed_fd_before_restore {
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) },
                -1,
                "counter must be closed before affinity restoration"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        }
        set_affinity(&self.saved)?;
        if !same_affinity(&affinity()?, &self.saved) {
            return Err(failure("original host affinity could not be restored"));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for CpuAffinity {
    fn drop(&mut self) {
        if self.active {
            // Explicit restoration is checked above. This is only an unwind
            // fallback; failures never become a successful guest clock.
            let _ = set_affinity(&self.saved);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn counted_vcpu_closed_admission_and_clock_failure_preserve_state() {
        let original_affinity = affinity().unwrap();
        let mut backend = crate::KvmBackend::new(0x10000).expect("this control requires /dev/kvm");
        backend.install_real_mode_program(0, &[0xf4]).unwrap();
        backend.vcpu.track_clock().unwrap();
        let original_registers = backend.vcpu.get_regs().unwrap();
        let gate = backend.memory.entry_gate();
        let closed =
            futures::executor::block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        assert!(backend.vcpu.run().unwrap().is_none());
        assert_eq!(backend.vcpu.get_regs().unwrap(), original_registers);
        assert_eq!(backend.vcpu.read_clock().unwrap(), 0);
        assert!(!backend.vcpu.clock.ran_untracked);
        assert!(same_affinity(&affinity().unwrap(), &original_affinity));
        drop(closed);
        assert!(matches!(backend.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
        assert_eq!(backend.vcpu.get_regs().unwrap().rip, 1);
        assert_eq!(backend.vcpu.read_clock().unwrap(), 0);
        assert!(same_affinity(&affinity().unwrap(), &original_affinity));

        // A refused admission must not even begin the clock. After reopening,
        // the exact clock error becomes the gate cause, not an abandonment
        // error produced by dropping an unacknowledged setup guard.
        let closed =
            futures::executor::block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        backend.vcpu.clock.poison("counted entry setup control");
        let before = backend.vcpu.get_regs().unwrap();
        assert!(backend.vcpu.run().unwrap().is_none());
        assert!(gate.pending_failure().is_none());
        drop(closed);
        let error = backend.vcpu.run().unwrap_err();
        assert!(
            matches!(error.primary(), Error::GuestClock(message) if message.contains("counted entry setup control"))
        );
        assert_eq!(backend.vcpu.get_regs().unwrap(), before);
        assert!(matches!(
            gate.pending_failure().unwrap().error(),
            Error::SharedFailure(_)
        ));
        assert!(same_affinity(&affinity().unwrap(), &original_affinity));
    }

    fn counter_bytes(value: CounterRead) -> Vec<u8> {
        [value.value, value.enabled, value.running]
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .collect()
    }

    // A closed pipe supplies exactly the requested perf read bytes (including
    // EOF/short-read faults) to the production reader without requiring a PMU.
    fn reader(bytes: &[u8]) -> CounterBinding {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let mut writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        writer.write_all(bytes).unwrap();
        drop(writer);
        CounterBinding {
            fd: std::sync::Arc::new(unsafe { OwnedFd::from_raw_fd(fds[0]) }),
            identity: CounterIdentity {
                tid: host_tid(),
                thread: std::thread::current().id(),
                cpu: 0,
                raw_event: 0,
            },
            previous: CounterRead::default(),
            last_end: CounterRead::default(),
            enabled: false,
            displaced: Default::default(),
            page: None,
        }
    }

    /// A pinned host event on this task counting branches, in user mode only
    /// when `count_user`; otherwise it counts nothing, as a guest-only event
    /// does while its host task runs host code.
    fn host_branch_event(count_user: bool) -> OwnedFd {
        let mut attr = perf::perf_event_attr {
            type_: perf::PERF_TYPE_HARDWARE,
            size: std::mem::size_of::<perf::perf_event_attr>() as u32,
            config: perf::PERF_COUNT_HW_BRANCH_INSTRUCTIONS as u64,
            read_format: (perf::PERF_FORMAT_TOTAL_TIME_ENABLED
                | perf::PERF_FORMAT_TOTAL_TIME_RUNNING) as u64,
            ..Default::default()
        };
        attr.set_disabled(1);
        attr.set_pinned(1);
        attr.set_exclude_kernel(1);
        attr.set_exclude_hv(1);
        attr.set_exclude_user(u64::from(!count_user));
        // SAFETY: a non-sampling event for this task on any CPU.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr,
                0,
                -1,
                -1,
                perf::PERF_FLAG_FD_CLOEXEC,
            )
        };
        assert!(
            fd >= 0,
            "perf_event_open: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a newly owned descriptor.
        unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) }
    }

    fn syscall_read(fd: &OwnedFd) -> CounterRead {
        let mut value = CounterRead::default();
        // SAFETY: the event's read_format is exactly these three u64s.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                std::ptr::from_mut(&mut value).cast(),
                std::mem::size_of::<CounterRead>(),
            )
        };
        assert_eq!(count as usize, std::mem::size_of::<CounterRead>());
        value
    }

    #[test]
    fn user_page_reads_agree_with_the_read_syscall() {
        for count_user in [false, true] {
            let fd = host_branch_event(count_user);
            let page = UserPage::map(&fd).expect("perf user page");
            // A disabled event is on no hardware counter: no user read.
            assert!(page.read().is_none());
            // SAFETY: the descriptor is a live perf event.
            assert!(unsafe { ioctls::ENABLE(fd.as_raw_fd(), 0) } >= 0);
            if !page.allows_user_read() {
                // The designed fallback: every read takes read(2).
                println!("user counter read: NOT EXECUTED; this host grants no user rdpmc or time");
                return;
            }
            let mut sink = 0u64;
            for i in 0..10_000u64 {
                if std::hint::black_box(i) % 3 == 0 {
                    sink += 1;
                }
            }
            std::hint::black_box(sink);
            let before = page.read().expect("user read of an active event");
            let syscall = syscall_read(&fd);
            let after = page.read().expect("user read of an active event");
            if count_user {
                // Exact up to the user branches between the three reads.
                assert!(before.value > 10_000, "{before:?}");
                assert!(before.value <= syscall.value, "{before:?} {syscall:?}");
                assert!(syscall.value <= after.value, "{syscall:?} {after:?}");
                assert!(after.value - before.value < 10_000, "{before:?} {after:?}");
            } else {
                assert_eq!(before.value, 0);
                assert_eq!(syscall.value, 0);
                assert_eq!(after.value, 0);
            }
            // The residency check compares enabled - running; both reads
            // must report the same gap (zero for an always-scheduled event).
            assert_eq!(
                before.enabled - before.running,
                syscall.enabled - syscall.running
            );
            assert_eq!(
                after.enabled - after.running,
                syscall.enabled - syscall.running
            );
            // SAFETY: the descriptor is a live perf event.
            assert!(unsafe { ioctls::DISABLE(fd.as_raw_fd(), 0) } >= 0);
            assert!(page.read().is_none());
        }
    }

    #[test]
    fn full_width_deltas_zero_work_and_overflow_are_checked() {
        let first = CounterRead {
            value: 4_294_967_310,
            enabled: 30,
            running: 30,
        };
        let second = CounterRead {
            value: 4_294_967_361,
            enabled: 40,
            running: 40,
        };
        let bytes = [
            counter_bytes(first),
            counter_bytes(first),
            counter_bytes(second),
        ]
        .concat();
        let mut counter = reader(&bytes);
        let total = counter.finish(0).unwrap();
        assert_eq!(total, 4_294_967_310);
        assert_eq!(counter.finish(total).unwrap(), total);
        assert_eq!(counter.finish(total).unwrap(), 4_294_967_361);
        let mut counter = reader(&counter_bytes(CounterRead {
            value: u64::MAX,
            enabled: 1,
            running: 1,
        }));
        assert!(
            counter
                .finish(1)
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
        assert_eq!(counter.previous.value, 0);
    }

    #[test]
    fn rebaselined_intervals_exclude_counts_between_entries() {
        // The event stays enabled between entries; another guest entered by
        // this host task advances it from 15 to 100. Only the two bracketed
        // deltas (15 - 10 and 103 - 100) belong to this guest.
        let at = |value, time| CounterRead {
            value,
            enabled: time,
            running: time,
        };
        let bytes = [
            counter_bytes(at(10, 1)),
            counter_bytes(at(15, 2)),
            counter_bytes(at(100, 9)),
            counter_bytes(at(103, 10)),
        ]
        .concat();
        let mut counter = reader(&bytes);
        counter.identity.cpu = FOLLOWS_TASK;
        counter.enabled = true;
        counter.start_interval().unwrap();
        let total = counter.finish(0).unwrap();
        assert_eq!(total, 5);
        counter.start_interval().unwrap();
        assert_eq!(counter.finish(total).unwrap(), 8);
        assert!(counter.enabled);
    }

    #[test]
    fn residency_is_judged_between_closing_reads() {
        // Measured on devbig014: the read that opens an entry reported running
        // ahead of enabled, and the closing read had both equal. Residency is
        // checked against the previous closing read, so that is no gap...
        let read = |value, enabled, running| CounterRead {
            value,
            enabled,
            running,
        };
        let skewed_start = [
            counter_bytes(read(2182, 2_957_590, 2_965_191)),
            counter_bytes(read(2183, 2_977_339, 2_977_339)),
        ]
        .concat();
        let mut counter = reader(&skewed_start);
        counter.identity.cpu = FOLLOWS_TASK;
        counter.enabled = true;
        counter.previous = read(2182, 2_950_000, 2_950_000);
        counter.last_end = counter.previous;
        counter.start_interval().unwrap();
        assert_eq!(counter.finish(10).unwrap(), 11);
        // ...while a closing read whose running fell behind enabled since the
        // previous closing read is a real gap and is refused.
        let gap = [
            counter_bytes(read(2182, 2_960_000, 2_960_000)),
            counter_bytes(read(2190, 2_977_339, 2_970_000)).repeat(1 + RESIDENCY_RESAMPLES),
        ]
        .concat();
        let mut counter = reader(&gap);
        counter.identity.cpu = FOLLOWS_TASK;
        counter.enabled = true;
        counter.previous = read(2182, 2_950_000, 2_950_000);
        counter.last_end = counter.previous;
        counter.start_interval().unwrap();
        assert!(
            counter
                .finish(10)
                .unwrap_err()
                .to_string()
                .contains("residency")
        );
    }

    #[test]
    fn a_torn_closing_read_is_resampled_and_a_persistent_gap_is_not() {
        let read = |value, enabled, running| CounterRead {
            value,
            enabled,
            running,
        };
        // Opening read, a torn closing read (running copied after an update
        // that enabled missed), then a coherent resample of the same moment.
        let torn = [
            counter_bytes(read(100, 1_000, 1_000)),
            counter_bytes(read(107, 1_990, 2_000)),
            counter_bytes(read(107, 2_000, 2_000)),
        ]
        .concat();
        let mut counter = reader(&torn);
        counter.identity.cpu = FOLLOWS_TASK;
        counter.enabled = true;
        counter.previous = read(100, 1_000, 1_000);
        counter.last_end = counter.previous;
        counter.start_interval().unwrap();
        assert_eq!(counter.finish(0).unwrap(), 7);
        assert_eq!(counter.last_end.enabled, 2_000);
        // A gap is refused after the bounded resamples, never accepted.
        let gapped = [
            counter_bytes(read(100, 1_000, 1_000)),
            counter_bytes(read(107, 2_000, 1_990)).repeat(1 + RESIDENCY_RESAMPLES),
        ]
        .concat();
        let mut counter = reader(&gapped);
        counter.identity.cpu = FOLLOWS_TASK;
        counter.enabled = true;
        counter.previous = read(100, 1_000, 1_000);
        counter.last_end = counter.previous;
        counter.start_interval().unwrap();
        assert!(
            counter
                .finish(0)
                .unwrap_err()
                .to_string()
                .contains("residency")
        );
    }

    #[test]
    fn one_following_event_per_host_task_stays_enabled() {
        if CounterPlacement::default() != CounterPlacement::FollowTask {
            println!("clock placement: FollowTask NOT EXECUTED; this host pins each entry");
            return;
        }
        // More following clocks on one host task than a core PMU has counters.
        // Each entry enables only its own event and displaces the previous
        // one, so every entry still gets a counter and counts no host work.
        let mut clocks: Vec<GuestClock> = (0..16)
            .map(|_| GuestClock {
                tracking: true,
                ..Default::default()
            })
            .collect();
        for round in 0..2 {
            for index in 0..clocks.len() {
                let interval = clocks[index].begin().unwrap();
                for value in 0..10_000 {
                    std::hint::black_box(value);
                }
                interval.finish().unwrap();
                let enabled: Vec<usize> = clocks
                    .iter()
                    .enumerate()
                    .filter(|(_, clock)| {
                        let binding = clock.binding.as_ref();
                        binding.is_some_and(|binding| {
                            binding.enabled
                                && !binding.displaced.load(std::sync::atomic::Ordering::Relaxed)
                        })
                    })
                    .map(|(other, _)| other)
                    .collect();
                assert_eq!(enabled, vec![index], "round {round}");
            }
        }
        for clock in &clocks {
            assert_eq!(clock.read().unwrap(), 0);
        }
        println!("clock placement: 16 following clocks on one task, one enabled at a time");
    }

    #[test]
    fn incomplete_reads_and_residency_gaps_are_not_zero_clocks() {
        for bytes in [vec![], vec![0; 8], vec![0; 23]] {
            assert!(
                reader(&bytes)
                    .finish(123)
                    .unwrap_err()
                    .to_string()
                    .contains("expected 24")
            );
        }
        // A real gap persists in every resample of the closing read.
        let mut gap = reader(
            &counter_bytes(CounterRead {
                value: 17,
                enabled: 20,
                running: 19,
            })
            .repeat(1 + RESIDENCY_RESAMPLES),
        );
        assert!(
            gap.finish(123)
                .unwrap_err()
                .to_string()
                .contains("residency")
        );
        assert_eq!(gap.previous.value, 0);
        let mut backwards = reader(&counter_bytes(CounterRead {
            value: 3,
            enabled: 4,
            running: 4,
        }));
        backwards.previous = CounterRead {
            value: 4,
            enabled: 3,
            running: 3,
        };
        assert!(
            backwards
                .finish(123)
                .unwrap_err()
                .to_string()
                .contains("backwards")
        );
    }

    #[test]
    fn eintr_finishes_count_and_restores_affinity_before_return() {
        let original = affinity().unwrap();
        let mut clock = GuestClock {
            tracking: true,
            total: 100,
            binding: Some(reader(&counter_bytes(CounterRead {
                value: 7,
                enabled: 2,
                running: 2,
            }))),
            ..Default::default()
        };
        let interval = CountInterval {
            clock: &mut clock,
            affinity: Some(CpuAffinity::enter().unwrap()),
            finished: false,
        };
        let result = finish_run::<()>(Err(kvm_ioctls::Error::new(libc::EINTR)), interval);
        assert!(matches!(result, Err(Error::Kvm(error)) if error.errno() == libc::EINTR));
        assert_eq!(clock.read().unwrap(), 107);
        assert!(same_affinity(&affinity().unwrap(), &original));
    }

    #[test]
    fn read_and_disable_errors_poison_even_when_kvm_returns_eintr() {
        const TEST: &str =
            "clock::tests::read_and_disable_errors_poison_even_when_kvm_returns_eintr";
        const CHILD_ENV: &str = "REVERIE_KVM_CLOCK_CLOSE_CHILD";
        const COMPLETE: &str = "clock close observation: read and disable errors both passed";
        if std::env::var(CHILD_ENV).ok().as_deref() != Some(TEST) {
            let output = std::process::Command::new("timeout")
                .args(["--kill-after=2s", "10s"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD_ENV, TEST)
                .output()
                .expect("failed to run isolated clock close observation");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            print!("{stdout}");
            eprint!("{stderr}");
            assert!(
                output.status.success(),
                "isolated clock test: {}",
                output.status
            );
            assert_eq!(
                stdout.lines().filter(|line| *line == COMPLETE).count(),
                1,
                "both close observations must execute in the isolated child"
            );
            return;
        }
        // Allocate after exec: other library tests must not reuse the closed
        // fd number before the real F_GETFD observation in affinity.restore.
        let original = affinity().unwrap();
        for disable_failure in [false, true] {
            let mut binding = reader(&[]);
            // A perf-disable ioctl on a pipe returns ENOTTY. This exercises the
            // actual failed-ioctl cleanup, not a hand-written expected branch.
            binding.enabled = disable_failure;
            let mut clock = GuestClock {
                tracking: true,
                total: 100,
                binding: Some(binding),
                ..Default::default()
            };
            let fd = clock.binding.as_ref().unwrap().fd.as_raw_fd();
            let mut interval = CountInterval {
                clock: &mut clock,
                affinity: Some(CpuAffinity::enter().unwrap()),
                finished: false,
            };
            interval.affinity.as_mut().unwrap().closed_fd_before_restore = Some(fd);
            let error =
                finish_run::<()>(Err(kvm_ioctls::Error::new(libc::EINTR)), interval).unwrap_err();
            assert!(matches!(error, Error::GuestClock(_)));
            let text = error.to_string();
            assert!(text.contains("KVM_RUN also failed"));
            assert!(text.contains(if disable_failure {
                "disable guest counter"
            } else {
                "expected 24"
            }));
            assert!(clock.binding.is_none());
            assert_eq!(clock.total, 100);
            assert!(clock.read().is_err());
            assert!(clock.begin().is_err());
            assert!(same_affinity(&affinity().unwrap(), &original));
        }
        println!("\n{COMPLETE}");
    }

    #[test]
    fn unwind_closes_counter_and_poison_prevents_future_success() {
        let original = affinity().unwrap();
        let mut clock = GuestClock {
            tracking: true,
            binding: Some(reader(&[])),
            ..Default::default()
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _interval = CountInterval {
                clock: &mut clock,
                affinity: Some(CpuAffinity::enter().unwrap()),
                finished: false,
            };
            panic!("simulated vCPU unwinding");
        }));
        assert!(result.is_err());
        assert!(clock.binding.is_none());
        assert!(clock.read().unwrap_err().to_string().contains("unwound"));
        assert!(same_affinity(&affinity().unwrap(), &original));
    }

    fn single_cpu_interval_counts_no_host_work(original: &libc::cpu_set_t) -> usize {
        let mut allocation = CpuAffinity::enter().unwrap();
        let cpu = allocation.cpu;
        assert!(unsafe { libc::CPU_ISSET(cpu, original) });
        allocation.check().unwrap();
        let singleton = affinity().unwrap();
        let mut clock = GuestClock {
            placement: CounterPlacement::PinEachEntry,
            tracking: true,
            ..Default::default()
        };
        let interval = clock.begin().unwrap();
        let pinned = interval.affinity.as_ref().unwrap();
        assert_eq!(pinned.cpu, cpu);
        assert!(same_affinity(&pinned.saved, &singleton));
        pinned.check().unwrap();
        for value in 0..1_000_000 {
            std::hint::black_box(value);
        }
        interval.finish().unwrap();
        assert_eq!(clock.total, 0);
        assert_eq!(clock.read().unwrap(), 0);
        assert_eq!(clock.read().unwrap(), 0);
        assert!(!clock.binding.as_ref().unwrap().enabled);
        assert!(same_affinity(&affinity().unwrap(), &singleton));
        allocation.check().unwrap();
        allocation.restore().unwrap();
        assert!(same_affinity(&affinity().unwrap(), original));
        cpu
    }

    #[test]
    fn following_intervals_count_no_host_work_and_leave_affinity_alone() {
        if CounterPlacement::default() != CounterPlacement::FollowTask {
            println!("clock placement: FollowTask NOT EXECUTED; this host pins each entry");
            return;
        }
        let original = affinity().unwrap();
        let mut clock = GuestClock {
            tracking: true,
            ..Default::default()
        };
        for _ in 0..3 {
            let interval = clock.begin().unwrap();
            assert!(interval.affinity.is_none());
            assert!(same_affinity(&affinity().unwrap(), &original));
            for value in 0..1_000_000 {
                std::hint::black_box(value);
            }
            interval.finish().unwrap();
        }
        let binding = clock.binding.as_ref().unwrap();
        assert_eq!(binding.identity.cpu, FOLLOWS_TASK);
        assert!(binding.enabled);
        assert_eq!(clock.read().unwrap(), 0);
        assert!(same_affinity(&affinity().unwrap(), &original));
        println!("clock placement: FollowTask executed 3 intervals with no affinity change");
    }

    #[test]
    fn counted_intervals_respect_the_permitted_cpu_allocation() {
        let original = affinity().unwrap();
        let permitted: Vec<_> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &original) })
            .collect();
        assert!(!permitted.is_empty());
        let cpu = single_cpu_interval_counts_no_host_work(&original);
        println!("clock residency: single-CPU interval executed on {cpu}; permitted={permitted:?}");
        if permitted.len() > 1 {
            let (cpu, other) = temporary_cpu_escape_is_not_hidden_by_matching_endpoint_checks();
            assert!(permitted.contains(&cpu));
            assert!(permitted.contains(&other));
            println!(
                "clock residency: physical temporary migration executed {cpu}->{other}->{cpu}"
            );
        } else {
            println!(
                "clock residency: physical temporary migration NOT EXECUTED; caller permitted one CPU"
            );
        }
        assert!(same_affinity(&affinity().unwrap(), &original));
    }

    fn temporary_cpu_escape_is_not_hidden_by_matching_endpoint_checks() -> (usize, usize) {
        let original = affinity().unwrap();
        let mut clock = GuestClock {
            placement: CounterPlacement::PinEachEntry,
            tracking: true,
            ..Default::default()
        };
        let interval = clock.begin().unwrap();
        let cpu = interval.affinity.as_ref().unwrap().cpu;
        let other = (0..libc::CPU_SETSIZE as usize)
            .find(|&candidate| candidate != cpu && unsafe { libc::CPU_ISSET(candidate, &original) })
            .expect("CPU residency test requires two permitted CPUs");
        let mut set = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_SET(other, &mut set) };
        set_affinity(&set).unwrap();
        assert!(interval.affinity.as_ref().unwrap().check().is_err());
        for value in 0..1_000_000 {
            std::hint::black_box(value);
        }
        unsafe {
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);
        }
        set_affinity(&set).unwrap();
        assert!(interval.affinity.as_ref().unwrap().check().is_ok());
        let error = interval.finish().unwrap_err();
        assert!(error.to_string().contains("residency"), "{error}");
        assert!(clock.read().is_err());
        assert!(same_affinity(&affinity().unwrap(), &original));
        (cpu, other)
    }

    #[test]
    fn enable_failure_closes_the_event_and_restores_affinity() {
        let original = affinity().unwrap();
        let mut pinned = CpuAffinity::enter().unwrap();
        let mut binding = reader(&[]);
        binding.identity = CounterIdentity {
            tid: host_tid(),
            thread: std::thread::current().id(),
            cpu: pinned.cpu,
            raw_event: 0,
        };
        let mut clock = GuestClock {
            placement: CounterPlacement::PinEachEntry,
            tracking: true,
            total: 9,
            binding: Some(binding),
            ..Default::default()
        };
        let error = match clock.begin_with_raw_event(|| Ok(0)) {
            Err(error) => error,
            Ok(_) => panic!("a pipe cannot enable a perf event"),
        };
        assert!(error.to_string().contains("enable guest counter"));
        assert!(
            error
                .to_string()
                .contains(&std::io::Error::from_raw_os_error(libc::ENOTTY).to_string())
        );
        println!("clock injected enable failure: {error}");
        assert!(clock.binding.is_none());
        assert!(clock.read().is_err());
        assert_eq!(clock.total, 9);
        pinned.check().unwrap();
        pinned.restore().unwrap();
        assert!(same_affinity(&affinity().unwrap(), &original));
    }

    #[test]
    fn failed_affinity_restoration_cannot_publish_a_partial_clock() {
        let original = affinity().unwrap();
        // Keep a separate restoration guard for this deliberately invalid
        // saved mask, so even a failed test assertion cannot leave us pinned.
        let mut rescue = CpuAffinity {
            saved: original,
            cpu: 0,
            active: true,
            #[cfg(test)]
            closed_fd_before_restore: None,
            _same_thread: PhantomData,
        };
        let mut clock = GuestClock {
            tracking: true,
            total: 9,
            binding: Some(reader(&counter_bytes(CounterRead {
                value: 7,
                enabled: 2,
                running: 2,
            }))),
            ..Default::default()
        };
        let mut interval = CountInterval {
            clock: &mut clock,
            affinity: Some(CpuAffinity::enter().unwrap()),
            finished: false,
        };
        // The real sched_setaffinity syscall rejects an empty saved mask.
        unsafe { libc::CPU_ZERO(&mut interval.affinity.as_mut().unwrap().saved) };
        let error = interval.finish().unwrap_err();
        rescue.restore().unwrap();
        assert!(error.to_string().contains("set host CPU affinity"));
        assert!(clock.binding.is_none());
        assert!(clock.read().is_err());
        assert_eq!(clock.total, 9);
        assert!(same_affinity(&affinity().unwrap(), &original));
    }

    fn gettid() -> libc::pid_t {
        // SAFETY: gettid has no pointer arguments.
        unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
    }

    #[test]
    fn cached_host_tid_is_each_threads_own_and_survives_fork() {
        let mine = host_tid();
        assert_eq!(mine, gettid());
        assert_eq!(host_tid(), mine);
        let other = std::thread::spawn(|| (host_tid(), gettid()))
            .join()
            .unwrap();
        assert_eq!(other.0, other.1);
        assert_ne!(other.0, mine);
        // A fork child's only thread is a new task: it must not reuse the
        // parent thread's cached task ID. The child does only async-signal-safe
        // work after one thread-local read, then exits without unwinding.
        // SAFETY: the child calls only host_tid, gettid and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let ok = host_tid() == gettid() && host_tid() != mine;
            // SAFETY: terminate the child immediately with the verdict.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: wait for the exact child created above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "fork child reused a cached tid"
        );
        assert_eq!(host_tid(), mine);
    }

    #[test]
    fn a_fork_child_of_a_process_setting_up_the_epoch_reads_its_tid_without_waiting() {
        // A fork while another thread is setting up the epoch page leaves the
        // child with the setting-up state and no thread to finish it. The
        // child must still get its own task ID, uncached, without waiting.
        let parent = host_tid();
        // SAFETY: the child calls only async-signal-safe operations, an
        // atomic store and host_tid, then _exit; alarm bounds a hang.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::alarm(5) };
            TID_EPOCH_STATE.store(1, Ordering::SeqCst);
            let ok = host_tid() == gettid() && host_tid() != parent;
            // SAFETY: terminate the child immediately with the verdict.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: wait for the exact child created above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status),
            "fork child did not exit normally (status {status:#x}); a hang ends in SIGALRM"
        );
        assert_eq!(libc::WEXITSTATUS(status), 0, "fork child read a wrong tid");
    }

    #[test]
    fn a_raw_clone_child_reads_its_own_tid() {
        // Hermit starts KVM runs in a child of a raw clone() without
        // CLONE_VM, where no pthread_atfork handler runs. Its only thread
        // must not reuse the cloning thread's cached task ID.
        extern "C" fn child(parent: *mut libc::c_void) -> libc::c_int {
            let parent = parent as usize as libc::pid_t;
            let ok = host_tid() == gettid() && host_tid() != parent;
            // SAFETY: terminate the child immediately with the verdict.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) }
        }
        let parent = host_tid();
        assert_eq!(host_tid(), gettid());
        let mut stack = vec![0u8; 256 * 1024];
        // SAFETY: without CLONE_VM the child runs on its own copy of `stack`,
        // which is 16-byte aligned at its top below, and only calls host_tid,
        // gettid and _exit.
        let pid = unsafe {
            let top = stack.as_mut_ptr().add(stack.len()) as usize & !15;
            libc::clone(
                child,
                top as *mut libc::c_void,
                libc::SIGCHLD,
                parent as usize as *mut libc::c_void,
            )
        };
        assert!(pid > 0, "clone failed: {}", std::io::Error::last_os_error());
        let mut status = 0;
        // SAFETY: wait for the exact child created above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "status {status:#x}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "raw clone child reused a cached tid"
        );
        assert_eq!(host_tid(), parent);
    }
}

#[cfg(test)]
mod entry_interrupt_tests;
