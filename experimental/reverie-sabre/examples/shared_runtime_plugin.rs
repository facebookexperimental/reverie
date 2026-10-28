/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A shared in-guest runtime library loaded by the SaBRe loader as its
//! plugin (`shared_runtime_plugin!`), for tests/shared_runtime_plugin.rs.
//!
//! Its Tool answers `getpid` with the coordinator's running count plus
//! [`ROUTED`] for a call from a rewritten site, which reached it through the
//! plugin's routed entry, or plus [`TRAPPED`] for a call from a site the
//! loader left as it was, which reached it through the armed filter. So a
//! client's output shows each call's path, that it reached the Tool through
//! the shared runtime, and that the Tool reached its coordinator. It answers
//! 2 instead if the Tool's allocation is not in the runtime's private Tool
//! heap, every RDTSC with [`TSC`], and every `clock_gettime` with an error:
//! [`VDSO_CLOCK_ERRNO`] for one from the vDSO's trapping stub, which the
//! install body wrote over the vDSO's entry point, [`CLOCK_ERRNO`] for any
//! other.
//!
//! The path is read from the call's own site: the runtime reports the
//! instruction pointer of the `syscall` instruction's final two bytes, which
//! are `0f 05` where the instruction is still there, and the jump that
//! replaced it or the jump's NOP padding at a rewritten site. A routed call
//! could misread as trapped only if those bytes were the jump's displacement
//! and happened to be `0f 05`, never the reverse, and the test's exact
//! expectation would then fail rather than pass.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_inguest::guest::alloc::PrivateToolAllocator;
use reverie_inguest::guest::alloc::tool_heap_contains;
use reverie_inguest::guest::tool_install::TrapHost;
use reverie_inguest::guest::tool_install::TrapOptions;
use reverie_inguest::guest::tool_install::install_tool_with;
use reverie_sabre::shared_runtime::Settings;

// Every Rust allocation of the runtime, installation and Tool callbacks
// included, comes from the private Tool heap, never the guest's malloc.
#[global_allocator]
static ALLOCATOR: PrivateToolAllocator = PrivateToolAllocator;

/// The Tool's answer to every RDTSC.
pub const TSC: u64 = 0x0005_AB1E_0000_0001;

/// The plugin setting naming the coordinator socket.
const COORDINATOR_SETTING: &[u8] = b"SHARED_RUNTIME_PLUGIN_COORDINATOR";

/// The error the Tool answers a `clock_gettime` from the vDSO with.
pub const VDSO_CLOCK_ERRNO: i32 = libc::EOWNERDEAD;

/// The error the Tool answers any other `clock_gettime` with.
pub const CLOCK_ERRNO: i32 = libc::ENOTRECOVERABLE;

/// Added to the count for a call from a rewritten site.
pub const ROUTED: i64 = 4_000_000;

/// Added to the count for a call from a site the loader did not rewrite.
pub const TRAPPED: i64 = 5_000_000;

#[derive(Default)]
pub struct CountGlobal {
    calls: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for CountGlobal {
    type Request = u64;
    type Response = u64;
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, amount: u64) -> u64 {
        self.calls.fetch_add(amount, Ordering::Relaxed) + amount
    }
}

#[derive(Default)]
pub struct GetpidTool;

#[reverie::tool]
impl Tool for GetpidTool {
    type GlobalState = CountGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut subscription: Subscription =
            [Sysno::getpid, Sysno::clock_gettime].into_iter().collect();
        subscription.rdtsc();
        subscription
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        _request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        Ok(RdtscResult {
            tsc: TSC,
            aux: None,
        })
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            let site = guest.regs().await.rip;
            // SAFETY: the instruction pointer of the guest's own syscall, in
            // its mapped, readable code.
            let instruction = unsafe { core::ptr::read_unaligned(site as *const [u8; 2]) };
            let path = if instruction == [0x0f, 0x05] {
                TRAPPED
            } else {
                ROUTED
            };
            let allocation = Box::new(0u64);
            let total = guest.send_rpc(1).await;
            if !tool_heap_contains((&*allocation as *const u64).cast()) {
                return Ok(2);
            }
            return Ok(path + total as i64);
        }
        if syscall.number() == Sysno::clock_gettime {
            let site = guest.regs().await.rip;
            let errno = if in_vdso(site) {
                VDSO_CLOCK_ERRNO
            } else {
                CLOCK_ERRNO
            };
            return Ok(-i64::from(errno));
        }
        Ok(guest.inject(syscall).await?)
    }
}

/// Whether `address` is in the vDSO's loaded image, found from the auxiliary
/// vector and the image's own program headers.
fn in_vdso(address: u64) -> bool {
    // SAFETY: getauxval only reads the saved auxiliary vector.
    let base = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) };
    if base == 0 {
        return false;
    }
    // SAFETY: the kernel maps the vDSO's ELF image, header and program
    // headers included, readable at that address.
    unsafe {
        let header = &*(base as *const libc::Elf64_Ehdr);
        let headers = core::slice::from_raw_parts(
            (base + header.e_phoff) as *const libc::Elf64_Phdr,
            usize::from(header.e_phnum),
        );
        headers
            .iter()
            .filter(|program| program.p_type == libc::PT_LOAD)
            .any(|program| {
                // The vDSO is linked at 0, so its addresses are offsets.
                let start = base + program.p_vaddr;
                (start..start + program.p_memsz).contains(&address)
            })
    }
}

/// The install body: the shared runtime's typed installer with no patcher;
/// SaBRe's loader is the patcher. The coordinator socket's path is the
/// `SHARED_RUNTIME_PLUGIN_COORDINATOR` setting.
unsafe fn install(settings: &Settings) -> io::Result<()> {
    let Some(coordinator) = settings.get(COORDINATOR_SETTING) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no SHARED_RUNTIME_PLUGIN_COORDINATOR setting",
        ));
    };
    let coordinator = Path::new(std::ffi::OsStr::from_bytes(coordinator.to_bytes()));
    // SAFETY: the loader calls post_load on the initial thread before the
    // client's constructors, with no seccomp filter installed.
    unsafe {
        install_tool_with::<GetpidTool, _>(
            coordinator,
            false,
            TrapHost::new(TrapOptions::default()),
        )
    }
}

reverie_sabre::shared_runtime_plugin!(install);
