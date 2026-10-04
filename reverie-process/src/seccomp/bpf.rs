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
    #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
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

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
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

    /// Returns the program's instructions, in order, exactly as they would be
    /// loaded.
    pub fn instructions(&self) -> &[sock_filter] {
        &self.filter
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

    /// Like [`VALIDATE_ARCH`], except that a syscall of `alternate_arch` takes
    /// `action` (which should be a `BPF_RET`) instead of killing the process.
    /// A syscall of `target_arch` continues with the next instruction, and any
    /// other architecture still kills the process.
    pub fn VALIDATE_ARCH_OR_ALTERNATE(target_arch: u32, alternate_arch: u32, action: sock_filter) {
        // Load `seccomp_data.arch`
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_OFFSET_ARCH);
        // if (arch == target_arch) goto CONTINUE;
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, target_arch, 3, 0);
        // if (arch != alternate_arch) goto KILL;
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, alternate_arch, 0, 1);
        action;
        // KILL:
        BPF_STMT(BPF_RET + BPF_K, libc::SECCOMP_RET_KILL_PROCESS);
        // CONTINUE: the next instruction.
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
        //
        // On entry the accumulator holds `ip.hi` (see `LOAD_SYSCALL_IP`), and
        // M[0] and M[1] hold `ip.lo` and `ip.hi`. Every exit restores
        // `ip.hi` to the accumulator for the next rule. The instructions are
        // numbered in the comments; a jump offset `n` from instruction `i`
        // lands on `i + 1 + n`.

        // STEP1: if (ip < begin) goto NOMATCH;

        // 0: if (ip.hi > begin.hi) goto STEP2;
        BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, bhi, 4 /* goto STEP2 */, 0);
        // 1: if (ip.hi != begin.hi) goto NOMATCH; (ip.hi < begin.hi)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, bhi, 0, 9 /* goto NOMATCH */);
        // 2: Load M[0] to operate on the low bits of the IP.
        BPF_STMT(BPF_LD + BPF_MEM, 0);
        // 3: if (ip.lo < begin.lo) goto NOMATCH;
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, blo, 0, 7 /* goto NOMATCH */);
        // 4: Load M[1] because STEP2 expects the high bits of the IP.
        BPF_STMT(BPF_LD + BPF_MEM, 1);

        // STEP2: if (ip >= end) goto NOMATCH;

        // 5: if (ip.hi > end.hi) goto NOMATCH;
        BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, ehi, 5 /* goto NOMATCH */, 0);
        // 6: if (ip.hi != end.hi) goto MATCH; (ip.hi < end.hi)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ehi, 0, 3 /* goto MATCH */);
        // 7: Load M[0]: the high halves are equal, so compare the low halves.
        BPF_STMT(BPF_LD + BPF_MEM, 0);
        // 8: if (ip.lo >= end.lo) goto NOMATCH;
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, elo, 2 /* goto NOMATCH */, 0);
        // 9: Load M[1] again after we loaded M[0].
        BPF_STMT(BPF_LD + BPF_MEM, 1);

        // 10: MATCH: Take the action.
        action;

        // 11: NOMATCH: Load M[1], the high bits of the IP, for the next rule.
        BPF_STMT(BPF_LD + BPF_MEM, 1);
    }
}

/// Checks if the instruction pointer equals `ip`. If so, executes `action`.
/// Otherwise, falls through with the high 32 bits of the instruction pointer
/// in the accumulator again.
///
/// Precondition: The instruction pointer must be loaded with [`LOAD_SYSCALL_IP`]
/// first (so the accumulator holds its high 32 bits).
pub fn IP_EQ(ip: u64, action: sock_filter) -> impl ByteCode {
    IP_EQ64(ip as u32, (ip >> 32) as u32, action)
}

instruction! {
    fn IP_EQ64(lo: u32, hi: u32, action: sock_filter) {
        // if (arg.hi != hi) goto NOMATCH;
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, hi, 0, 3 /* goto NOMATCH */);
        // Load M[0] to operate on the low bits of the IP.
        BPF_STMT(BPF_LD + BPF_MEM, 0);
        // if (arg.lo != lo) goto NOMATCH;
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, lo, 0, 1 /* goto NOMATCH */);
        // MATCH: Take the action.
        action;
        // NOMATCH: Load M[1], the high bits of the IP, for the next rule.
        BPF_STMT(BPF_LD + BPF_MEM, 1);
    }
}

/// Checks if the instruction pointer is in the half-open interval
/// `[begin, end)`, that is `begin <= ip && ip < end`, comparing all 64 bits.
/// If so, executes `action`. Otherwise, falls through with the high 32 bits of
/// the instruction pointer in the accumulator again.
///
/// Note that if `ip == end`, this will not match: the interval is open at the
/// end, so `IP_RANGE(a, a + 1, ..)` matches only `a`.
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

    const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const RET_MATCH: u32 = libc::SECCOMP_RET_TRACE | 1;

    /// Runs a seccomp-BPF program in user space on
    /// `seccomp_data { nr, arch, instruction_pointer }` and returns its
    /// verdict. Only the instructions this module emits are modelled; anything
    /// else, and running off the end of the program, panics.
    fn run(filter: &Filter, nr: u32, arch: u32, ip: u64) -> u32 {
        const LD_ABS: u16 = BPF_LD + BPF_W + BPF_ABS;
        const LD_MEM: u16 = BPF_LD + BPF_MEM;
        const JEQ: u16 = BPF_JMP + BPF_JEQ + BPF_K;
        const JGT: u16 = BPF_JMP + BPF_JGT + BPF_K;
        const JGE: u16 = BPF_JMP + BPF_JGE + BPF_K;
        const RET: u16 = BPF_RET + BPF_K;
        let (mut acc, mut mem, mut pc) = (0u32, [0u32; 16], 0usize);
        loop {
            let insn = filter
                .filter
                .get(pc)
                .unwrap_or_else(|| panic!("fell off the program at {pc}"));
            pc += 1;
            let jump = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
            match insn.code {
                LD_ABS => {
                    acc = match insn.k {
                        SECCOMP_DATA_OFFSET_NR => nr,
                        SECCOMP_DATA_OFFSET_ARCH => arch,
                        SECCOMP_DATA_OFFSET_IP_LO => ip as u32,
                        SECCOMP_DATA_OFFSET_IP_HI => (ip >> 32) as u32,
                        k => panic!("load of unmodelled seccomp_data offset {k}"),
                    }
                }
                BPF_ST => mem[insn.k as usize] = acc,
                LD_MEM => acc = mem[insn.k as usize],
                JEQ => pc += jump(acc == insn.k),
                JGT => pc += jump(acc > insn.k),
                JGE => pc += jump(acc >= insn.k),
                RET => return insn.k,
                code => panic!("unmodelled opcode {code:#x} at {}", pc - 1),
            }
        }
    }

    /// `LOAD_SYSCALL_IP; IP_RANGE(begin, end, RET_MATCH); ALLOW`.
    fn range_filter(begin: u64, end: u64) -> Filter {
        seccomp_bpf![
            LOAD_SYSCALL_IP(),
            IP_RANGE(begin, end, BPF_STMT(BPF_RET + BPF_K, RET_MATCH)),
            ALLOW,
        ]
    }

    fn matches(filter: &Filter, ip: u64) -> bool {
        match run(filter, 0, AUDIT_ARCH_X86_64, ip) {
            RET_MATCH => true,
            RET_ALLOW => false,
            other => panic!("unexpected verdict {other:#x} for ip {ip:#x}"),
        }
    }

    /// The probe points named for this defect, for one range.
    fn probes(begin: u64, end: u64) -> Vec<u64> {
        let mut ips = vec![
            begin.wrapping_sub(1),
            begin,
            end.wrapping_sub(1),
            end,
            end.wrapping_add(1),
            0x7fff_ffff,
            0xffff_ffff,
            0x1_0000_0000u64.wrapping_add(begin),
        ];
        // The first and last addresses sharing the high half of each bound.
        for bound in [begin, end] {
            ips.push(bound & !0xffff_ffff);
            ips.push(bound | 0xffff_ffff);
        }
        ips
    }

    /// `IP_RANGE(begin, end)` matches exactly `begin <= ip < end`, for ranges
    /// inside one 4 GiB half and ranges crossing one or more 4 GiB
    /// boundaries. The first row is the ptrace backend's untraced window.
    #[test]
    fn ip_range_matches_exactly_the_half_open_interval() {
        let ranges: &[(u64, u64)] = &[
            // Inside the low 4 GiB, the end's high half is zero.
            (0x7100_0002, 0x7100_0003),
            (0x1000, 0x2000),
            (0x7fff_f000, 0x8000_1000),
            (0xffff_f000, 0xffff_ffff),
            // Inside a higher 4 GiB half.
            (0x5_7100_0002, 0x5_7100_0003),
            (0x7fff_0000_0000, 0x7fff_ffff_ffff),
            // Crossing one 4 GiB boundary.
            (0xffff_f000, 0x1_0000_1000),
            (0x7100_0002, 0x1_7100_0003),
            (0x1_ffff_ffff, 0x2_0000_0001),
            // Crossing several.
            (0x1000, 0x7_0000_0000),
            (0x3_8000_0000, 0x7fff_ffff_f000),
        ];
        let mut wrong = Vec::new();
        for &(begin, end) in ranges {
            let filter = range_filter(begin, end);
            for ip in probes(begin, end) {
                let expected = begin <= ip && ip < end;
                if matches(&filter, ip) != expected {
                    wrong.push(format!(
                        "[{begin:#x}, {end:#x}) ip {ip:#x}: expected match={expected}"
                    ));
                }
            }
        }
        assert!(
            wrong.is_empty(),
            "{} wrong verdicts:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    /// The same property over every range whose bounds come from a grid of
    /// high and low halves chosen at the comparison edges.
    #[test]
    fn ip_range_matches_the_half_open_interval_over_a_bound_grid() {
        let his = [0u64, 1, 2, 0x7fff, 0xffff_fffe, 0xffff_ffff];
        let los = [
            0u64,
            1,
            0x7100_0002,
            0x7100_0003,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            0xffff_ffff,
        ];
        let points: Vec<u64> = his
            .iter()
            .flat_map(|hi| los.iter().map(move |lo| (hi << 32) | lo))
            .collect();
        let (mut checked, mut wrong) = (0usize, Vec::new());
        for &begin in &points {
            for &end in points.iter().filter(|&&end| end > begin) {
                let filter = range_filter(begin, end);
                for &ip in points.iter().chain(&probes(begin, end)) {
                    checked += 1;
                    let expected = begin <= ip && ip < end;
                    if matches(&filter, ip) != expected {
                        wrong.push((begin, end, ip, expected));
                    }
                }
            }
        }
        assert!(checked > 60_000, "grid shrank to {checked} verdicts");
        assert!(
            wrong.is_empty(),
            "{} of {checked} verdicts wrong; first: {:x?}",
            wrong.len(),
            &wrong[..wrong.len().min(8)]
        );
    }

    /// Consecutive ranges and the syscall rules after them still see the
    /// instruction pointer's high half after a range does not match.
    #[test]
    fn ip_ranges_chain_into_later_ranges_and_syscall_rules() {
        use crate::seccomp::Action;
        use crate::seccomp::FilterBuilder;

        let filter = FilterBuilder::new()
            .default_action(Action::Allow)
            .target_arch(crate::seccomp::TargetArch::x86_64)
            .ip_range(0x7100_0002, 0x7100_0003, Action::Trace(1))
            .ip_range(0x1_0000_0000, 0x1_0000_1000, Action::Trace(2))
            .syscall(Sysno::getppid, Action::Trace(3))
            .build();
        let nr = Sysno::getppid as u32;
        let other = Sysno::getpid as u32;
        let verdict = |nr, ip| run(&filter, nr, AUDIT_ARCH_X86_64, ip);
        let trace = |data: u32| libc::SECCOMP_RET_TRACE | data;
        for (nr, ip, expected) in [
            (nr, 0x7100_0002, trace(1)),
            (other, 0x7100_0002, trace(1)),
            (nr, 0x7100_0003, trace(3)),
            (nr, 0x7200_0002, trace(3)),
            (other, 0x7200_0002, RET_ALLOW),
            (nr, 0x1_0000_0000, trace(2)),
            (nr, 0x1_0000_0fff, trace(2)),
            (nr, 0x1_0000_1000, trace(3)),
            (other, 0x1_0000_1000, RET_ALLOW),
            (nr, 0x2_7100_0002, trace(3)),
        ] {
            assert_eq!(verdict(nr, ip), expected, "nr {nr} ip {ip:#x}");
        }
        assert_eq!(
            run(&filter, nr, AUDIT_ARCH_X86_64 ^ 1, 0x7100_0002),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    /// The kernel agrees with `run` and with `begin <= ip < end`: a child
    /// maps a `syscall; ret` stub so that the syscall's return address is
    /// exactly `ip`, installs `ip_range(begin, end, Errno(EXDEV))` and calls
    /// `getppid` through the stub.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn kernel_ip_range_verdicts_match_the_interpreter() {
        use crate::seccomp::Action;
        use crate::seccomp::FilterBuilder;

        const MATCHED: i32 = 10;
        const UNMATCHED: i32 = 11;
        const MAP_FAILED: i32 = 12;
        const OTHER: i32 = 13;

        fn kernel_matches(filter: &Filter, ip: u64) -> bool {
            let page = 0x1000u64;
            let first = (ip - 2) & !(page - 1);
            let len = ((ip + 1 + page - 1) & !(page - 1)) - first;
            // SAFETY: the child only makes raw syscalls on memory it maps
            // itself, then exits without returning to the test harness.
            match unsafe { libc::fork() } {
                0 => unsafe {
                    let base = libc::mmap(
                        first as *mut libc::c_void,
                        len as usize,
                        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    );
                    if base as u64 != first {
                        libc::_exit(MAP_FAILED);
                    }
                    // syscall; ret
                    let stub = [0x0f, 0x05, 0xc3u8];
                    std::ptr::copy_nonoverlapping(stub.as_ptr(), (ip - 2) as *mut u8, 3);
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        || filter.load().is_err()
                    {
                        libc::_exit(OTHER);
                    }
                    let ret: i64;
                    std::arch::asm!(
                        "call {stub}",
                        stub = in(reg) ip - 2,
                        inlateout("rax") libc::SYS_getppid => ret,
                        out("rcx") _,
                        out("r11") _,
                    );
                    libc::_exit(if ret == -(libc::EXDEV as i64) {
                        MATCHED
                    } else if ret > 0 {
                        UNMATCHED
                    } else {
                        OTHER
                    });
                },
                -1 => panic!("fork failed: {}", std::io::Error::last_os_error()),
                pid => {
                    let mut status = 0;
                    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                    assert!(libc::WIFEXITED(status), "child status {status:#x}");
                    match libc::WEXITSTATUS(status) {
                        MATCHED => true,
                        UNMATCHED => false,
                        MAP_FAILED => panic!("could not map a stub page at {first:#x}"),
                        code => panic!("child for ip {ip:#x} failed with {code}"),
                    }
                }
            }
        }

        let (mut unfaithful, mut wrong) = (Vec::new(), Vec::new());
        for (begin, end, ips) in [
            (
                0x7100_0002u64,
                0x7100_0003u64,
                &[
                    0x7100_0001u64,
                    0x7100_0002,
                    0x7100_0003,
                    0x7200_0002,
                    0x7fff_ffff,
                    0xffff_ffff,
                    0x1_7100_0002,
                ][..],
            ),
            (
                0xffff_f000,
                0x1_0000_1000,
                &[0xffff_efff, 0xffff_f000, 0x1_0000_0fff, 0x1_0000_1000][..],
            ),
        ] {
            let built = FilterBuilder::new()
                .default_action(Action::Allow)
                .ip_range(begin, end, Action::Errno(Errno::EXDEV))
                .build();
            for &ip in ips {
                let expected = begin <= ip && ip < end;
                let interpreted = run(&built, Sysno::getppid as u32, AUDIT_ARCH_X86_64, ip)
                    == (libc::SECCOMP_RET_ERRNO | libc::EXDEV as u32);
                let kernel = kernel_matches(&built, ip);
                let row = format!("[{begin:#x}, {end:#x}) ip {ip:#x}: kernel match={kernel}");
                if kernel != interpreted {
                    unfaithful.push(format!("{row}, interpreter match={interpreted}"));
                }
                if kernel != expected {
                    wrong.push(format!("{row}, interval match={expected}"));
                }
            }
        }
        assert!(
            unfaithful.is_empty(),
            "interpreter disagrees with the kernel:\n{}",
            unfaithful.join("\n")
        );
        assert!(
            wrong.is_empty(),
            "kernel verdicts outside the interval:\n{}",
            wrong.join("\n")
        );
    }
}
