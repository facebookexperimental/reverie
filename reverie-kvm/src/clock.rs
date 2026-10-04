/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Retired conditional branches belonging to one guest thread.
//!
//! A guest-only perf event belongs to a host task, not to a vCPU. It must be
//! disabled before returning to a Tool or polling another guest. This module
//! owns the only mutable VcpuFd and enforces that interval for every entry,
//! including syscall-return parking. This is a clock, not a precise timer.

use std::marker::PhantomData;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::rc::Rc;

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
        &self.fd
    }
}

impl CountedVcpu {
    pub(crate) fn new(fd: VcpuFd, memory: GuestMemory) -> Result<Self> {
        let participant = memory
            .entry_gate()
            .register()
            .map_err(|failure| failure.error())?;
        Ok(Self {
            fd,
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
    /// method, with no signal-mask, CPU-affinity or borrowed-exit guard alive.
    pub(crate) fn run(&mut self) -> Result<Option<VcpuExit<'_>>> {
        #[cfg(test)]
        if let Some(probe) = &self.run_probe {
            probe.run_hook();
        }
        // Declare entry first: unwinding must retire the clock and restore CPU
        // affinity before entry withdraws its target and restores the mask.
        let Some(entry) = self
            .participant
            .prepare(&self.fd)
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
            return finish_entry(self.fd.run().map_err(Error::Kvm), entry).map(Some);
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
        finish_entry(result, entry).map(Some)
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

#[derive(Default)]
struct GuestClock {
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
        // Closing is also the last-resort disable if an ioctl failed. Never
        // leave the event active while an error unwinds into another task.
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
        let mut affinity = match CpuAffinity::enter() {
            Ok(affinity) => affinity,
            Err(error) => return Err(self.poison(error)),
        };
        let admission = (|| {
            let identity = CounterIdentity {
                tid: host_tid(),
                thread: std::thread::current().id(),
                cpu: affinity.cpu,
                raw_event: raw_event()?,
            };
            if self.binding.as_ref().map(|b| b.identity) != Some(identity) {
                self.binding.take();
                self.binding = Some(CounterBinding::open(identity)?);
            }
            self.binding.as_mut().unwrap().enable()
        })();
        if let Err(error) = admission {
            // No guest instruction ran. Closing even an ambiguously enabled
            // event must precede affinity restoration and error propagation.
            self.binding.take();
            let reason = match affinity.restore() {
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

fn host_tid() -> libc::pid_t {
    // SAFETY: gettid has no pointer arguments and returns this Linux task ID.
    unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
}

fn current_raw_event() -> Result<u64> {
    // CPUID is supported on x86-64. The calling thread is restricted
    // to one permitted CPU for this entire counted interval.
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
    fn checked_delta(self, previous: Self) -> Result<u64> {
        let enabled = self.enabled.checked_sub(previous.enabled);
        let running = self.running.checked_sub(previous.running);
        if enabled.is_none() || running.is_none() || enabled != running {
            return Err(failure(format!(
                "counter lost CPU residency: {previous:?} -> {self:?}"
            )));
        }
        self.value
            .checked_sub(previous.value)
            .ok_or_else(|| failure("counter moved backwards"))
    }
}

struct CounterBinding {
    fd: OwnedFd,
    identity: CounterIdentity,
    previous: CounterRead,
    enabled: bool,
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
        // SAFETY: attr describes a non-sampling event for this actual host task
        // and its enforced CPU. The returned descriptor is newly owned.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr,
                identity.tid,
                identity.cpu as libc::c_int,
                -1,
                perf::PERF_FLAG_FD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(host_failure(&format!("perf_event_open {identity:?}")));
        }
        let mut binding = Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) },
            identity,
            previous: CounterRead::default(),
            enabled: false,
        };
        binding.previous = binding.read()?;
        if binding.previous.value != 0 {
            return Err(failure("new disabled counter is not zero"));
        }
        Ok(binding)
    }

    fn enable(&mut self) -> Result<()> {
        // Mark before the ioctl so even an ambiguous failure is cleaned up.
        self.enabled = true;
        if unsafe { ioctls::ENABLE(self.fd.as_raw_fd(), 0) } < 0 {
            return Err(host_failure("enable guest counter"));
        }
        Ok(())
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

    fn read(&self) -> Result<CounterRead> {
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

    fn finish(&mut self, total: u64) -> Result<u64> {
        self.disable()?;
        let current = self.read()?;
        let delta = current.checked_delta(self.previous)?;
        let total = total
            .checked_add(delta)
            .ok_or_else(|| failure("guest clock overflow"))?;
        self.previous = current;
        Ok(total)
    }
}

struct CountInterval<'a> {
    clock: &'a mut GuestClock,
    affinity: CpuAffinity,
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
            // A failed disable may leave the event enabled. Close it while
            // still pinned, before any affinity restoration can move us.
            self.clock.binding.take();
        }
        let resident = self.affinity.check();
        let restored = self.affinity.restore();
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
            fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            identity: CounterIdentity {
                tid: host_tid(),
                thread: std::thread::current().id(),
                cpu: 0,
                raw_event: 0,
            },
            previous: CounterRead::default(),
            enabled: false,
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
        let mut gap = reader(&counter_bytes(CounterRead {
            value: 17,
            enabled: 20,
            running: 19,
        }));
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
            affinity: CpuAffinity::enter().unwrap(),
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
                affinity: CpuAffinity::enter().unwrap(),
                finished: false,
            };
            interval.affinity.closed_fd_before_restore = Some(fd);
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
                affinity: CpuAffinity::enter().unwrap(),
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
            tracking: true,
            ..Default::default()
        };
        let interval = clock.begin().unwrap();
        assert_eq!(interval.affinity.cpu, cpu);
        assert!(same_affinity(&interval.affinity.saved, &singleton));
        interval.affinity.check().unwrap();
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
            tracking: true,
            ..Default::default()
        };
        let interval = clock.begin().unwrap();
        let cpu = interval.affinity.cpu;
        let other = (0..libc::CPU_SETSIZE as usize)
            .find(|&candidate| candidate != cpu && unsafe { libc::CPU_ISSET(candidate, &original) })
            .expect("CPU residency test requires two permitted CPUs");
        let mut set = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_SET(other, &mut set) };
        set_affinity(&set).unwrap();
        assert!(interval.affinity.check().is_err());
        for value in 0..1_000_000 {
            std::hint::black_box(value);
        }
        unsafe {
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);
        }
        set_affinity(&set).unwrap();
        assert!(interval.affinity.check().is_ok());
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
            affinity: CpuAffinity::enter().unwrap(),
            finished: false,
        };
        // The real sched_setaffinity syscall rejects an empty saved mask.
        unsafe { libc::CPU_ZERO(&mut interval.affinity.saved) };
        let error = interval.finish().unwrap_err();
        rescue.restore().unwrap();
        assert!(error.to_string().contains("set host CPU affinity"));
        assert!(clock.binding.is_none());
        assert!(clock.read().is_err());
        assert_eq!(clock.total, 9);
        assert!(same_affinity(&affinity().unwrap(), &original));
    }
}

#[cfg(test)]
mod entry_interrupt_tests;
