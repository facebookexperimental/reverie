/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![allow(non_snake_case)]

pub use libc::sock_filter;
use syscalls::Errno;
use syscalls::Sysno;

use crate::fd::Fd;

// See: /include/uapi/linux/bpf_common.h

// Instruction classes
pub const BPF_LD: u16 = 0x00;
pub const BPF_ST: u16 = 0x02;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;

// ld/ldx fields
pub const BPF_W: u16 = 0x00;

pub const BPF_ABS: u16 = 0x20;
pub const BPF_MEM: u16 = 0x60;

pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_K: u16 = 0x00;

/// Maximum number of instructions.
pub const BPF_MAXINSNS: usize = 4096;

/// Defined in `/include/uapi/linux/seccomp.h`.
const SECCOMP_SET_MODE_FILTER: u32 = 1;

/// Offset of `seccomp_data::nr` in bytes.
const SECCOMP_DATA_OFFSET_NR: u32 = 0;

/// Offset of `seccomp_data::arch` in bytes.
const SECCOMP_DATA_OFFSET_ARCH: u32 = 4;

/// Offset of `seccomp_data::instruction_pointer` in bytes.
const SECCOMP_DATA_OFFSET_IP: u32 = 8;

/// Offset of `seccomp_data::args` in bytes.
#[allow(unused)]
const SECCOMP_DATA_OFFSET_ARGS: u32 = 16;

#[cfg(target_endian = "little")]
const SECCOMP_DATA_OFFSET_IP_HI: u32 = SECCOMP_DATA_OFFSET_IP + 4;
#[cfg(target_endian = "little")]
const SECCOMP_DATA_OFFSET_IP_LO: u32 = SECCOMP_DATA_OFFSET_IP;

#[cfg(target_endian = "big")]
const SECCOMP_DATA_OFFSET_IP_HI: u32 = SECCOMP_DATA_OFFSET_IP;
#[cfg(target_endian = "big")]
const SECCOMP_DATA_OFFSET_IP_LO: u32 = SECCOMP_DATA_OFFSET_IP + 4;

// These are defined in `/include/uapi/linux/elf-em.h`.
const EM_386: u32 = 3;
const EM_MIPS: u32 = 8;
const EM_PPC: u32 = 20;
const EM_PPC64: u32 = 21;
const EM_ARM: u32 = 40;
const EM_X86_64: u32 = 62;
const EM_AARCH64: u32 = 183;

// These are defined in `/include/uapi/linux/audit.h`.
const __AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
const __AUDIT_ARCH_LE: u32 = 0x4000_0000;

// These are defined in `/include/uapi/linux/audit.h`.
pub const AUDIT_ARCH_X86: u32 = EM_386 | __AUDIT_ARCH_LE;
pub const AUDIT_ARCH_X86_64: u32 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
pub const AUDIT_ARCH_ARM: u32 = EM_ARM | __AUDIT_ARCH_LE;
pub const AUDIT_ARCH_AARCH64: u32 = EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
pub const AUDIT_ARCH_MIPS: u32 = EM_MIPS;
pub const AUDIT_ARCH_PPC: u32 = EM_PPC;
pub const AUDIT_ARCH_PPC64: u32 = EM_PPC64 | __AUDIT_ARCH_64BIT;

bitflags::bitflags! {
    #[derive(Default)]
    struct FilterFlags: u32 {
        const TSYNC = 1 << 0;
        const LOG = 1 << 1;
        const SPEC_ALLOW = 1 << 2;
        const NEW_LISTENER = 1 << 3;
        const TSYNC_ESRCH = 1 << 4;
    }
}

/// Seccomp-BPF program byte code.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Filter {
    // Since the limit is 4096 instructions, we *could* use a static array here
    // instead. However, that would require bounds checks each time an
    // instruction is appended and complicate the interface with `Result` types
    // and error handling logic. It's cleaner to just check the size when the
    // program is loaded.
    filter: Vec<sock_filter>,
}

impl Filter {
    /// Creates a new, empty seccomp program. Note that empty BPF programs are not
    /// valid and will fail to load.
    pub const fn new() -> Self {
        Self { filter: Vec::new() }
    }

    /// Appends a single instruction to the seccomp-BPF program.
    pub fn push(&mut self, instruction: sock_filter) {
        self.filter.push(instruction);
    }

    /// Returns the number of instructions in the BPF program.
    pub fn len(&self) -> usize {
        self.filter.len()
    }

    /// Returns true if the program is empty. Empty seccomp filters will result
    /// in an error when loaded.
    pub fn is_empty(&self) -> bool {
        self.filter.is_empty()
    }

    fn install(&self, flags: FilterFlags) -> Result<i32, Errno> {
        let len = self.filter.len();

        if len == 0 || len > BPF_MAXINSNS {
            return Err(Errno::EINVAL);
        }

        let prog = libc::sock_fprog {
            // Note: length is guaranteed to be less than `u16::MAX` because of
            // the above check.
            len: len as u16,
            filter: self.filter.as_ptr() as *mut _,
        };

        let ptr = &prog as *const libc::sock_fprog;

        let value = Errno::result(unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                flags.bits(),
                ptr,
            )
        })?;

        Ok(value as i32)
    }

    /// Loads the program via seccomp into the current process.
    ///
    /// Once loaded, the seccomp filter can never be removed. Additional seccomp
    /// filters can be loaded, however, and they will chain together and be
    /// executed in reverse order.
    ///
    /// NOTE: The maximum size of any single seccomp-bpf filter is 4096
    /// instructions. The overall limit is 32768 instructions across all loaded
    /// filters.
    ///
    /// See [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
    /// for more details.
    pub fn load(&self) -> Result<(), Errno> {
        self.install(FilterFlags::empty())?;
        Ok(())
    }

    /// This is the same as [`Filter::load`] except that it returns a file
    /// descriptor. This is meant to be used with
    /// [`seccomp_unotify(2)`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).
    pub fn load_and_listen(&self) -> Result<Fd, Errno> {
        let fd = self.install(FilterFlags::NEW_LISTENER)?;
        Ok(Fd::new(fd))
    }
}

impl Extend<sock_filter> for Filter {
    fn extend<T: IntoIterator<Item = sock_filter>>(&mut self, iter: T) {
        self.filter.extend(iter)
    }
}

/// Trait for types that can emit BPF byte code.
pub trait ByteCode {
    /// Accumulates BPF instructions into the given filter.
    fn into_bpf(self, filter: &mut Filter);
}

impl<F> ByteCode for F
where
    F: FnOnce(&mut Filter),
{
    fn into_bpf(self, filter: &mut Filter) {
        self(filter)
    }
}

impl ByteCode for sock_filter {
    fn into_bpf(self, filter: &mut Filter) {
        filter.push(self)
    }
}

/// Returns a seccomp-bpf filter containing the given list of instructions.
///
/// This can be concatenated with other seccomp-BPF programs.
///
/// Note that this is not a true BPF program. Seccomp-bpf is a subset of BPF and
/// so many instructions are not available.
///
/// When executing instructions, the BPF program operates on the syscall
/// information made available as a (read-only) buffer of the following form:
///
/// ```no_compile
/// struct seccomp_data {
///     // The syscall number.
///     nr: u32,
///     // `AUDIT_ARCH_*` value (see `<linux/audit.h`).
///     arch: u32,
///     // CPU instruction pointer.
///     instruction_pointer: u64,
///     // Up to 6 syscall arguments.
///     args: [u64; 8],
/// }
/// ```
///
/// # Example
///
/// This filter will allow only the specified syscalls.
/// ```
/// let _filter = seccomp_bpf![
///     // Make sure the target process is using the x86-64 syscall ABI.
///     VALIDATE_ARCH(AUDIT_ARCH_X86_64),
///     // Load the current syscall number into `seccomp_data.nr`.
///     LOAD_SYSCALL_NR,
///     // Check if `seccomp_data.nr` matches the given syscalls. If so, then return
///     // from the seccomp filter early, allowing the syscall to continue.
///     SYSCALL(Sysno::open, ALLOW),
///     SYSCALL(Sysno::close, ALLOW),
///     SYSCALL(Sysno::write, ALLOW),
///     SYSCALL(Sysno::read, ALLOW),
///     // Deny all other syscalls by having the kernel kill the current thread with
///     // `SIGSYS`.
///     DENY,
/// ];
/// ```
#[cfg(test)]
macro_rules! seccomp_bpf {
    ($($inst:expr),+ $(,)?) => {
        {
            let mut filter = Filter::new();
            $(
                $inst.into_bpf(&mut filter);
            )+
            filter
        }
    };
}

// See: /include/uapi/linux/filter.h
pub const fn BPF_STMT(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// A BPF jump instruction.
///
/// # Arguments
///
/// * `code` is the operation code.
/// * `k` is the value operated on for comparisons.
/// * `jt` is the relative offset to jump to if the comparison is true.
/// * `jf` is the relative offset to jump to if the comparison is false.
///
/// # Example
///
/// ```no_compile
/// // Jump to the next instruction if the loaded value is equal to 42.
/// BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 42, 1, 0);
/// ```
pub const fn BPF_JUMP(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Loads the syscall number into `seccomp_data.nr`.
pub const LOAD_SYSCALL_NR: sock_filter = BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_OFFSET_NR);

/// Returns from the seccomp filter, allowing the syscall to pass through.
#[allow(unused)]
pub const ALLOW: sock_filter = BPF_STMT(BPF_RET + BPF_K, libc::SECCOMP_RET_ALLOW);

/// Returns from the seccomp filter, instructing the kernel to kill the calling
/// thread with `SIGSYS` before executing the syscall.
#[allow(unused)]
pub const DENY: sock_filter = BPF_STMT(BPF_RET + BPF_K, libc::SECCOMP_RET_KILL_THREAD);

/// Returns from the seccomp filter, causing a `SIGSYS` to be sent to the calling
/// thread skipping over the syscall without executing it. Unlike [`DENY`], this
/// signal can be caught.
#[allow(unused)]
pub const TRAP: sock_filter = BPF_STMT(BPF_RET + BPF_K, libc::SECCOMP_RET_TRAP);

/// Returns from the seccomp filter, causing `PTRACE_EVENT_SECCOMP` to be
/// generated for this syscall (if `PTRACE_O_TRACESECCOMP` is enabled). If no
/// tracer is present, the syscall will not be executed and returns a `ENOSYS`
/// instead.
///
/// `data` is made available to the tracer via `PTRACE_GETEVENTMSG`.
#[allow(unused)]
pub fn TRACE(data: u16) -> sock_filter {
    BPF_STMT(
        BPF_RET + BPF_K,
        libc::SECCOMP_RET_TRACE | (data as u32 & libc::SECCOMP_RET_DATA),
    )
}

/// Returns from the seccomp filter, returning the given error instead of
/// executing the syscall.
#[allow(unused)]
pub fn ERRNO(err: Errno) -> sock_filter {
    BPF_STMT(
        BPF_RET + BPF_K,
        libc::SECCOMP_RET_ERRNO | (err.into_raw() as u32 & libc::SECCOMP_RET_DATA),
    )
}

macro_rules! instruction {
    (
        $(
            $(#[$attrs:meta])*
            $vis:vis fn $name:ident($($args:tt)*) {
                $($instruction:expr;)*
            }
        )*
    ) => {
        $(
            $vis fn $name($($args)*) -> impl ByteCode {
                move |filter: &mut Filter| {
                    $(
                        $instruction.into_bpf(filter);
                    )*
                }
            }
        )*
    };
}

instruction! {
    /// Checks that architecture matches our target architecture. If it does not
    /// match, kills the current process. This should be the first step for every
    /// seccomp filter to ensure we're working with the syscall table we're
    /// expecting. Each architecture has a slightly different syscall table and
    /// we need to make sure the syscall numbers we're using are the right ones
    /// for the architecture.
    pub fn VALIDATE_ARCH(target_arch: u32) {
        // Load `seccomp_data.arch`
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_OFFSET_ARCH);
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, target_arch, 1, 0);
        BPF_STMT(BPF_RET + BPF_K, libc::SECCOMP_RET_KILL_PROCESS);
    }

    pub fn LOAD_SYSCALL_IP() {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_OFFSET_IP_LO);
        // M[0] = lo
        BPF_STMT(BPF_ST, 0);
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_OFFSET_IP_HI);
        // M[1] = hi
        BPF_STMT(BPF_ST, 1);
    }

    /// Checks if `seccomp_data.nr` matches the given syscall. If so, then jumps
    /// to `action`.
    ///
    /// # Example
    /// ```no_compile
    /// SYSCALL(Sysno::socket, DENY);
    /// ```
    pub fn SYSCALL(nr: Sysno, action: sock_filter) {
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr as i32 as u32, 0, 1);
        action;
    }

    fn IP_RANGE64(blo: u32, bhi: u32, elo: u32, ehi: u32, action: sock_filter) {
        // Most of the complexity below is caused by seccomp-bpf only being able
        // to operate on `u32` values. We also can't reuse `JGE64` and `JLE64`
        // because the jump offsets would be incorrect.

        // STEP1: if !(begin > arg) goto NOMATCH;

        // if (begin_hi > arg.hi) goto Step2; */
        BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, bhi, 4 /* goto STEP2 */, 0);
        // if (begin_hi != arg.hi) goto NOMATCH;
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, bhi, 0, 9 /* goto NOMATCH */);
        // Load M[0] to operate on the low bits of the IP.
        BPF_STMT(BPF_LD + BPF_MEM, 0);
        // if (begin_lo >= arg.lo) goto MATCH;
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, blo, 0, 7 /* goto NOMATCH */);
        // Load M[1] because the next instruction expects the high bits of the
        // IP.
        BPF_STMT(BPF_LD + BPF_MEM, 1);

        // STEP2: if !(arg > end) goto NOMATCH;

        // if (end_hi < arg.hi) goto MATCH;
        BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, ehi, 0, 4 /* goto MATCH */);
        // if (end_hi != arg.hi) goto NOMATCH;
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ehi, 0, 5 /* goto NOMATCH */);
        BPF_STMT(BPF_LD + BPF_MEM, 0);
        // if (end_lo < arg.lo) goto MATCH;
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, elo, 2 /* goto NOMATCH */, 0);
        BPF_STMT(BPF_LD + BPF_MEM, 1);

        // MATCH: Take the action.
        action;

        // NOMATCH: Load M[1] again after we loaded M[0].
        BPF_STMT(BPF_LD + BPF_MEM, 1);
    }
}

/// Checks if the instruction pointer is between a certain range. If so, executes
/// `action`. Otherwise, fall through.
///
/// Note that if `ip == end`, this will not match. That is, the interval closed
/// at the end.
///
/// Precondition: The instruction pointer must be loaded with [`LOAD_SYSCALL_IP`]
/// first.
pub fn IP_RANGE(begin: u64, end: u64, action: sock_filter) -> impl ByteCode {
    let begin_lo = begin as u32;
    let begin_hi = (begin >> 32) as u32;
    let end_lo = end as u32;
    let end_hi = (end >> 32) as u32;

    IP_RANGE64(begin_lo, begin_hi, end_lo, end_hi, action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let filter = seccomp_bpf![
            VALIDATE_ARCH(AUDIT_ARCH_X86_64),
            LOAD_SYSCALL_NR,
            SYSCALL(Sysno::openat, DENY),
            SYSCALL(Sysno::close, DENY),
            SYSCALL(Sysno::write, DENY),
            SYSCALL(Sysno::read, DENY),
            ALLOW,
        ];

        assert_eq!(filter.len(), 13);
    }
}
