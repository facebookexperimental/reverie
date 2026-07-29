/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Direct-dispatch bridge for e9patch's ahead-of-time syscall trampolines.

use std::io;

use reverie::syscalls::SyscallInfo;
use reverie_ptrace::InjectedSyscallFrame;

include!(concat!(env!("OUT_DIR"), "/aot_dispatch_constants.rs"));

const PAGE_SIZE: usize = 4096;

#[repr(C)]
struct DispatchPage {
    magic: u64,
    callback: unsafe extern "C" fn(*mut InjectedSyscallFrame, u64),
}

/// An AOT dispatch page that is removed unless its runtime installation commits.
// AUTONOMOUS-BOT-IMPLEMENTED
pub(crate) struct PendingDispatchPage {
    address: *mut libc::c_void,
    committed: bool,
}

impl PendingDispatchPage {
    /// Publish the callback at the fixed address consumed by the AOT payload.
    pub(crate) fn prepare() -> io::Result<Self> {
        let requested = AOT_DISPATCH_PAGE_ADDRESS as usize as *mut libc::c_void;
        let address = unsafe {
            libc::mmap(
                requested,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        if address != requested {
            unsafe {
                libc::munmap(address, PAGE_SIZE);
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "kernel ignored fixed e9patch dispatch-page address",
            ));
        }

        let page = DispatchPage {
            magic: AOT_DISPATCH_MAGIC,
            callback: reverie_e9patch_dispatch_aot,
        };
        unsafe {
            address.cast::<DispatchPage>().write(page);
        }
        if unsafe { libc::mprotect(address, PAGE_SIZE, libc::PROT_READ) } != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::munmap(address, PAGE_SIZE);
            }
            return Err(error);
        }

        Ok(Self {
            address,
            committed: false,
        })
    }

    /// Keep the page mapped for the lifetime of the installed runtime.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingDispatchPage {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                libc::munmap(self.address, PAGE_SIZE);
            }
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-pending): Review the AOT callback and shared e9tool frame
// mutation.
/// Routes one e9tool state frame through the registered shared dispatcher.
///
/// # Safety
///
/// `frame` must point to the writable e9tool `state` frame for the duration of
/// this call. The AOT trampoline is the intended caller.
unsafe extern "C" fn reverie_e9patch_dispatch_aot(
    frame: *mut InjectedSyscallFrame,
    trap_rflags: u64,
) {
    let frame = unsafe { &mut *frame };
    let syscall = frame.syscall();
    let (number, _) = syscall.into_parts();
    let args = frame.raw_args();
    let instruction_pointer = frame.instruction_pointer();

    frame.emulate_syscall_entry(trap_rflags);
    let result =
        reverie_preload::trap::dispatch_direct(number.id() as i64, args, instruction_pointer);
    frame.set_result(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_page_abi_matches_the_payload() {
        assert_eq!(AOT_DISPATCH_PAGE_ADDRESS % PAGE_SIZE as u64, 0);
        assert_ne!(AOT_DISPATCH_MAGIC, 0);
        assert_eq!(
            AOT_FALLBACK_TRAP_ENTRY,
            crate::E9PATCH_SYSCALL_TRAP_RIP - 11
        );
        assert_eq!(core::mem::offset_of!(DispatchPage, callback), 8);
        assert!(core::mem::size_of::<DispatchPage>() <= PAGE_SIZE);
    }

    #[test]
    fn prepared_page_publishes_the_exact_callback_and_unmaps_on_drop() {
        let page = PendingDispatchPage::prepare().unwrap();
        let published = unsafe { &*page.address.cast::<DispatchPage>() };
        assert_eq!(published.magic, AOT_DISPATCH_MAGIC);
        assert_eq!(
            published.callback as *const () as usize,
            reverie_e9patch_dispatch_aot as *const () as usize
        );

        let address = page.address;
        drop(page);
        let mut residency = 0_u8;
        let result = unsafe { libc::mincore(address, PAGE_SIZE, &mut residency) };
        assert_eq!(result, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM)
        );
    }

    #[test]
    fn callback_fails_closed_without_a_registered_dispatcher() {
        let rip = 0x401000;
        let mut words = [0_u64; 18];
        words[15] = libc::SYS_getpid as u64;
        words[17] = rip;

        unsafe {
            reverie_e9patch_dispatch_aot(words.as_mut_ptr().cast(), 0x202);
        }

        assert_eq!(words[15] as i64, -i64::from(libc::ENOSYS));
        assert_eq!(words[14], rip + 2);
        assert_eq!(words[5], 0x202);
    }
}
