/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! One `KVM_RUN`, and the decoding of the exit it reports, as two steps.
//!
//! kvm-ioctls' `VcpuFd::run` issues `KVM_RUN` and then decodes the exit
//! through a `&mut kvm_run` over the vCPU's whole mapped page. The reserved
//! signal's handler stores to that page's `immediate_exit` byte while an entry
//! is published ([`super::signal`]), and a kick can land after `KVM_RUN`
//! returned, so the two may overlap. Here the entry issues `KVM_RUN` itself
//! ([`kvm_run`]), takes the byte back from the handler, and only then forms
//! the reference to decode the exit ([`decode_exit`]), which yields the same
//! `VcpuExit` kvm-ioctls would.

use std::os::fd::AsRawFd;

use kvm_bindings::*;
use kvm_ioctls::Error;
use kvm_ioctls::HypercallExit;
use kvm_ioctls::MsrExitReason;
use kvm_ioctls::ReadMsrExit;
use kvm_ioctls::VcpuExit;
use kvm_ioctls::VcpuFd;
use kvm_ioctls::WriteMsrExit;

/// `KVM_RUN`: `_IO(KVMIO, 0x80)`, with `KVMIO` 0xAE
/// (include/uapi/linux/kvm.h).
const KVM_RUN: libc::c_ulong = 0xAE80;

/// What one `KVM_RUN` returned: its return value and, when that is not zero,
/// the errno it left, read before anything else could replace it.
pub(super) struct RawRun {
    ret: libc::c_int,
    errno: Option<Error>,
}

/// Issue `KVM_RUN` on `fd` once. No Rust reference into the `kvm_run` page
/// exists while it runs or after it returns.
pub(super) fn kvm_run(fd: &VcpuFd) -> RawRun {
    // SAFETY: fd is a vCPU descriptor, KVM_RUN takes no argument, and the
    // kvm_run page the kernel writes stays mapped for the descriptor's
    // lifetime.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), KVM_RUN as _, 0) };
    RawRun {
        ret,
        errno: (ret != 0).then(Error::last),
    }
}

/// Decode the exit `raw` reported from the vCPU's `kvm_run` page, as
/// kvm-ioctls' `VcpuFd::run` does for the same kernel ABI: the exit reason
/// selects the union member to read, and an I/O exit's data lies
/// `data_offset` bytes into the page. A failed `KVM_RUN` is its errno, but
/// for the one exit the kernel reports with a failure, a memory fault
/// (`KVM_EXIT_MEMORY_FAULT` with EFAULT or EHWPOISON).
pub(super) fn decode_exit(run: &mut kvm_run, raw: RawRun) -> Result<VcpuExit<'_>, Error> {
    if raw.ret != 0 {
        let errno = raw.errno.unwrap_or_else(|| Error::new(libc::EINVAL));
        if raw.ret == -1
            && (errno == Error::new(libc::EFAULT) || errno == Error::new(libc::EHWPOISON))
            && run.exit_reason == KVM_EXIT_MEMORY_FAULT
        {
            // SAFETY: the exit reason names the memory_fault member.
            let fault = unsafe { run.__bindgen_anon_1.memory_fault };
            return Ok(VcpuExit::MemoryFault {
                flags: fault.flags,
                gpa: fault.gpa,
                size: fault.size,
            });
        }
        return Err(errno);
    }
    Ok(match run.exit_reason {
        KVM_EXIT_UNKNOWN => VcpuExit::Unknown,
        KVM_EXIT_EXCEPTION => VcpuExit::Exception,
        KVM_EXIT_IO => {
            let start = run as *mut kvm_run as *mut u8;
            // SAFETY: the exit reason names the io member.
            let io = unsafe { run.__bindgen_anon_1.io };
            let length = io.count as usize * io.size as usize;
            // SAFETY: the kernel places the data data_offset bytes into the
            // kvm_run page, which is mapped whole for the vCPU's lifetime, and
            // nothing else refers to those bytes while the exit is held.
            let data = unsafe {
                std::slice::from_raw_parts_mut(start.add(io.data_offset as usize), length)
            };
            match u32::from(io.direction) {
                KVM_EXIT_IO_IN => VcpuExit::IoIn(io.port, data),
                KVM_EXIT_IO_OUT => VcpuExit::IoOut(io.port, data),
                _ => return Err(Error::new(libc::EINVAL)),
            }
        }
        KVM_EXIT_HYPERCALL => {
            // SAFETY: the exit reason names the hypercall member.
            let hypercall = unsafe { &mut run.__bindgen_anon_1.hypercall };
            VcpuExit::Hypercall(HypercallExit {
                nr: hypercall.nr,
                args: hypercall.args,
                // SAFETY: as above; the longmode field is plain data.
                longmode: unsafe { hypercall.__bindgen_anon_1.longmode },
                ret: &mut hypercall.ret,
            })
        }
        KVM_EXIT_DEBUG => {
            // SAFETY: the exit reason names the debug member.
            VcpuExit::Debug(unsafe { run.__bindgen_anon_1.debug }.arch)
        }
        KVM_EXIT_HLT => VcpuExit::Hlt,
        KVM_EXIT_MMIO => {
            // SAFETY: the exit reason names the mmio member.
            let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
            let address = mmio.phys_addr;
            let length = mmio.len as usize;
            let write = mmio.is_write != 0;
            let data = &mut mmio.data[..length];
            if write {
                VcpuExit::MmioWrite(address, data)
            } else {
                VcpuExit::MmioRead(address, data)
            }
        }
        KVM_EXIT_X86_RDMSR => {
            // SAFETY: the exit reason names the msr member.
            let msr = unsafe { &mut run.__bindgen_anon_1.msr };
            VcpuExit::X86Rdmsr(ReadMsrExit {
                reason: MsrExitReason::from_bits_truncate(msr.reason),
                index: msr.index,
                error: &mut msr.error,
                data: &mut msr.data,
            })
        }
        KVM_EXIT_X86_WRMSR => {
            // SAFETY: the exit reason names the msr member.
            let msr = unsafe { &mut run.__bindgen_anon_1.msr };
            VcpuExit::X86Wrmsr(WriteMsrExit {
                reason: MsrExitReason::from_bits_truncate(msr.reason),
                index: msr.index,
                data: msr.data,
                error: &mut msr.error,
            })
        }
        KVM_EXIT_IRQ_WINDOW_OPEN => VcpuExit::IrqWindowOpen,
        KVM_EXIT_SHUTDOWN => VcpuExit::Shutdown,
        KVM_EXIT_FAIL_ENTRY => {
            // SAFETY: the exit reason names the fail_entry member.
            let fail = unsafe { run.__bindgen_anon_1.fail_entry };
            VcpuExit::FailEntry(fail.hardware_entry_failure_reason, fail.cpu)
        }
        KVM_EXIT_INTR => VcpuExit::Intr,
        KVM_EXIT_SET_TPR => VcpuExit::SetTpr,
        KVM_EXIT_TPR_ACCESS => VcpuExit::TprAccess,
        KVM_EXIT_S390_SIEIC => VcpuExit::S390Sieic,
        KVM_EXIT_S390_RESET => VcpuExit::S390Reset,
        KVM_EXIT_DCR => VcpuExit::Dcr,
        KVM_EXIT_NMI => VcpuExit::Nmi,
        KVM_EXIT_INTERNAL_ERROR => VcpuExit::InternalError,
        KVM_EXIT_OSI => VcpuExit::Osi,
        KVM_EXIT_PAPR_HCALL => VcpuExit::PaprHcall,
        KVM_EXIT_S390_UCONTROL => VcpuExit::S390Ucontrol,
        KVM_EXIT_WATCHDOG => VcpuExit::Watchdog,
        KVM_EXIT_S390_TSCH => VcpuExit::S390Tsch,
        KVM_EXIT_EPR => VcpuExit::Epr,
        KVM_EXIT_SYSTEM_EVENT => {
            // SAFETY: the exit reason names the system_event member.
            let event = unsafe { &mut run.__bindgen_anon_1.system_event };
            let count = event.ndata as usize;
            // SAFETY: the kernel filled the first ndata entries.
            let data = unsafe { &event.__bindgen_anon_1.data[..count] };
            VcpuExit::SystemEvent(event.type_, data)
        }
        KVM_EXIT_S390_STSI => VcpuExit::S390Stsi,
        KVM_EXIT_IOAPIC_EOI => {
            // SAFETY: the exit reason names the eoi member.
            VcpuExit::IoapicEoi(unsafe { run.__bindgen_anon_1.eoi }.vector)
        }
        KVM_EXIT_HYPERV => VcpuExit::Hyperv,
        reason => VcpuExit::Unsupported(reason),
    })
}

#[cfg(test)]
thread_local! {
    /// Run once on this thread between a test's `KVM_RUN` and the decoding of
    /// its exit, after the entry took its `immediate_exit` byte back.
    static AFTER_RUN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

// Its one caller, a_kick_after_kvm_run_returned_stores_nothing_into_the_decoded_page,
// needs native-test-support; without it the setter is dead code.
#[cfg(all(test, feature = "native-test-support"))]
pub(super) fn set_after_run_for_test(hook: impl FnOnce() + 'static) {
    AFTER_RUN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(super) fn after_run_for_test() {
    if let Some(hook) = AFTER_RUN.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
