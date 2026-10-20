/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Every function the Linux vDSO exports, with what it reads and what a
//! backend does with it.
//!
//! A vDSO function runs the kernel's code inside the guest, without a syscall,
//! so a tool never sees the call. [`VdsoSymbol`] names every entry point the
//! kernel exports and [`VdsoSymbol::class`] classifies each one with an
//! exhaustive match, so a variant added for a new kernel does not compile
//! until it is classified. Backends that patch the vDSO derive their plan from
//! this classification, and treat an exported name that is not a variant as
//! unknown: they replace it with an -ENOSYS stub and report it.
//!
//! The variants are the global symbols of the kernel's vDSO linker scripts in
//! Linux v7.2 (commit 8d3ae59288f1; v7.3-rc1 is the same):
//! - x86_64: `arch/x86/entry/vdso/vdso64/vdso64.lds.S` and its x32 variant
//!   `vdsox32.lds.S`, whose names are a subset. The 32-bit compat vDSO
//!   (`vdso32/vdso32.lds.S`) is mapped only into 32-bit processes, which no
//!   Reverie backend runs.
//! - aarch64: `arch/arm64/kernel/vdso/vdso.lds.S`.
//!
//! `reverie/tests/vdso/` holds those lists as text, and the `vdso_symbols` test
//! requires every name in them, and every name the running kernel's vDSO
//! exports, to be a variant. To audit a new kernel release, regenerate the
//! lists with `reverie/tests/vdso/linux-vdso-symbols.sh` and run that test.

use core::fmt;

use reverie_syscalls::Sysno;

#[cfg(target_arch = "x86_64")]
mod canonical;
mod image;

#[cfg(target_arch = "x86_64")]
pub use canonical::*;
pub use image::*;

/// One function exported by the Linux vDSO, named as in the kernel's linker
/// script. [`VdsoSymbol::name`] and [`Display`](fmt::Display) give that name.
///
/// The x86_64 vDSO exports most functions twice, as `__vdso_<name>` and as
/// `<name>`, at one address. Both are variants, with the same class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VdsoSymbol {
    /// `clock_gettime`, an alias of `__vdso_clock_gettime`.
    #[cfg(target_arch = "x86_64")]
    ClockGettime,
    /// `__vdso_clock_gettime`.
    #[cfg(target_arch = "x86_64")]
    VdsoClockGettime,
    /// `gettimeofday`, an alias of `__vdso_gettimeofday`.
    #[cfg(target_arch = "x86_64")]
    Gettimeofday,
    /// `__vdso_gettimeofday`.
    #[cfg(target_arch = "x86_64")]
    VdsoGettimeofday,
    /// `getcpu`, an alias of `__vdso_getcpu`.
    #[cfg(target_arch = "x86_64")]
    Getcpu,
    /// `__vdso_getcpu`.
    #[cfg(target_arch = "x86_64")]
    VdsoGetcpu,
    /// `time`, an alias of `__vdso_time`.
    #[cfg(target_arch = "x86_64")]
    Time,
    /// `__vdso_time`.
    #[cfg(target_arch = "x86_64")]
    VdsoTime,
    /// `clock_getres`, an alias of `__vdso_clock_getres`.
    #[cfg(target_arch = "x86_64")]
    ClockGetres,
    /// `__vdso_clock_getres`.
    #[cfg(target_arch = "x86_64")]
    VdsoClockGetres,
    /// `__vdso_sgx_enter_enclave` (`CONFIG_X86_SGX`).
    #[cfg(target_arch = "x86_64")]
    VdsoSgxEnterEnclave,
    /// `getrandom`, an alias of `__vdso_getrandom`.
    #[cfg(target_arch = "x86_64")]
    Getrandom,
    /// `__vdso_getrandom`.
    #[cfg(target_arch = "x86_64")]
    VdsoGetrandom,
    /// `__vdso_futex_robust_list64_try_unlock` (`CONFIG_FUTEX_ROBUST_UNLOCK`,
    /// new in Linux v7.2).
    #[cfg(target_arch = "x86_64")]
    VdsoFutexRobustList64TryUnlock,
    /// `__vdso_futex_robust_list32_try_unlock` (`CONFIG_FUTEX_ROBUST_UNLOCK`
    /// and `CONFIG_COMPAT`, new in Linux v7.2).
    #[cfg(target_arch = "x86_64")]
    VdsoFutexRobustList32TryUnlock,
    /// `__kernel_rt_sigreturn`.
    #[cfg(target_arch = "aarch64")]
    KernelRtSigreturn,
    /// `__kernel_gettimeofday`.
    #[cfg(target_arch = "aarch64")]
    KernelGettimeofday,
    /// `__kernel_clock_gettime`.
    #[cfg(target_arch = "aarch64")]
    KernelClockGettime,
    /// `__kernel_clock_getres`.
    #[cfg(target_arch = "aarch64")]
    KernelClockGetres,
    /// `__kernel_getrandom`.
    #[cfg(target_arch = "aarch64")]
    KernelGetrandom,
}

/// What a vDSO function's result depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VdsoInput {
    /// A host clock, read from the kernel's shared data page.
    HostClock,
    /// A host clock's resolution, which depends on the host's timer hardware
    /// and configuration.
    HostClockResolution,
    /// The CPU and NUMA node the host scheduler is running the thread on.
    HostCpu,
    /// Host entropy: the kernel's version keys a userspace ChaCha20 state from
    /// the kernel's random number generator and re-keys it at points that
    /// depend on host time (<https://github.com/rrnewton/reverie/issues/841>).
    HostEntropy,
    /// Only guest memory the caller passes in, so the result is deterministic
    /// whenever the guest's own schedule is.
    GuestMemory,
    /// An SGX enclave, whose computation no tool can observe.
    Enclave,
}

impl VdsoInput {
    /// Is the function's result determined by the guest alone?
    pub const fn is_deterministic(self) -> bool {
        match self {
            Self::GuestMemory => true,
            Self::HostClock
            | Self::HostClockResolution
            | Self::HostCpu
            | Self::HostEntropy
            | Self::Enclave => false,
        }
    }
}

/// What a backend that patches the vDSO does with an entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VdsoHandling {
    /// The function is a userspace fast path of this syscall. When the tool
    /// subscribes to the syscall, it is replaced by a stub that issues the
    /// syscall, so the tool sees the call.
    Syscall(Sysno),
    /// The function has no syscall equivalent. It is replaced by a stub that
    /// returns -ENOSYS without touching memory: by reverie-ptrace whenever the
    /// tool subscribes to any syscall, and by reverie-dbt and reverie-sabre
    /// always. A name that is not a [`VdsoSymbol`] is handled the same way.
    Enosys,
    /// The kernel's code stays in place: the function reads and writes only
    /// guest memory, so running it natively is deterministic.
    Native,
}

/// The classification of a vDSO function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VdsoClass {
    /// What its result depends on.
    pub input: VdsoInput,
    /// What a backend does with it.
    pub handling: VdsoHandling,
}

impl VdsoSymbol {
    /// Every variant, in the order of the kernel's linker script.
    pub const ALL: &'static [Self] = &[
        #[cfg(target_arch = "x86_64")]
        Self::ClockGettime,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoClockGettime,
        #[cfg(target_arch = "x86_64")]
        Self::Gettimeofday,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoGettimeofday,
        #[cfg(target_arch = "x86_64")]
        Self::Getcpu,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoGetcpu,
        #[cfg(target_arch = "x86_64")]
        Self::Time,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoTime,
        #[cfg(target_arch = "x86_64")]
        Self::ClockGetres,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoClockGetres,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoSgxEnterEnclave,
        #[cfg(target_arch = "x86_64")]
        Self::Getrandom,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoGetrandom,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoFutexRobustList64TryUnlock,
        #[cfg(target_arch = "x86_64")]
        Self::VdsoFutexRobustList32TryUnlock,
        #[cfg(target_arch = "aarch64")]
        Self::KernelRtSigreturn,
        #[cfg(target_arch = "aarch64")]
        Self::KernelGettimeofday,
        #[cfg(target_arch = "aarch64")]
        Self::KernelClockGettime,
        #[cfg(target_arch = "aarch64")]
        Self::KernelClockGetres,
        #[cfg(target_arch = "aarch64")]
        Self::KernelGetrandom,
    ];

    /// The symbol name the kernel exports.
    pub const fn name(self) -> &'static str {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::ClockGettime => "clock_gettime",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoClockGettime => "__vdso_clock_gettime",
            #[cfg(target_arch = "x86_64")]
            Self::Gettimeofday => "gettimeofday",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoGettimeofday => "__vdso_gettimeofday",
            #[cfg(target_arch = "x86_64")]
            Self::Getcpu => "getcpu",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoGetcpu => "__vdso_getcpu",
            #[cfg(target_arch = "x86_64")]
            Self::Time => "time",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoTime => "__vdso_time",
            #[cfg(target_arch = "x86_64")]
            Self::ClockGetres => "clock_getres",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoClockGetres => "__vdso_clock_getres",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoSgxEnterEnclave => "__vdso_sgx_enter_enclave",
            #[cfg(target_arch = "x86_64")]
            Self::Getrandom => "getrandom",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoGetrandom => "__vdso_getrandom",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoFutexRobustList64TryUnlock => "__vdso_futex_robust_list64_try_unlock",
            #[cfg(target_arch = "x86_64")]
            Self::VdsoFutexRobustList32TryUnlock => "__vdso_futex_robust_list32_try_unlock",
            #[cfg(target_arch = "aarch64")]
            Self::KernelRtSigreturn => "__kernel_rt_sigreturn",
            #[cfg(target_arch = "aarch64")]
            Self::KernelGettimeofday => "__kernel_gettimeofday",
            #[cfg(target_arch = "aarch64")]
            Self::KernelClockGettime => "__kernel_clock_gettime",
            #[cfg(target_arch = "aarch64")]
            Self::KernelClockGetres => "__kernel_clock_getres",
            #[cfg(target_arch = "aarch64")]
            Self::KernelGetrandom => "__kernel_getrandom",
        }
    }

    /// The variant the kernel exports as `name`, if any.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|symbol| symbol.name() == name)
    }

    /// What the function reads, and what a backend does with it.
    ///
    /// Which replacement is safe depends on how libc calls the function. From
    /// glibc 2.42 source:
    /// - `clock_gettime`: `__clock_gettime64` returns any nonzero vDSO result
    ///   as an error, without trying the syscall
    ///   (`sysdeps/unix/sysv/linux/clock_gettime.c` lines 41-46).
    /// - `gettimeofday`, and x86_64 `time`: IFUNCs that resolve to the vDSO
    ///   function itself, so its return value goes straight to the caller
    ///   (`gettimeofday.c` lines 42-45, `time.c` lines 38-40;
    ///   `x86/gettimeofday.c`, `x86/time.c` and `aarch64/gettimeofday.c`
    ///   select them with `USE_IFUNC_*`).
    /// - `clock_getres` and `getcpu`: `INLINE_VSYSCALL`, which retries with
    ///   the syscall when the vDSO returns -ENOSYS (`sysdep-vdso.h` lines 42
    ///   and 46).
    /// - `getrandom`: the backend's stub answers glibc's parameter query with
    ///   -ENOSYS, so glibc never sizes a userspace state, and issues the
    ///   getrandom syscall for every other call.
    /// - aarch64 `__kernel_rt_sigreturn`: glibc never calls it, but glibc does
    ///   not set `SA_RESTORER` (`aarch64/libc_sigaction.c`), so the kernel
    ///   returns from every signal handler through it.
    ///
    /// An -ENOSYS stub would turn the first two into visible failures and the
    /// last into a crash on every signal return, so every syscall fast path is
    /// [`VdsoHandling::Syscall`]. glibc only calls vDSO functions it names
    /// (`HAVE_*_VSYSCALL` in each architecture's `sysdep.h`), so a future
    /// glibc calling a function added after this table either retries with
    /// the syscall (`INLINE_VSYSCALL`) or fails visibly on the -ENOSYS stub;
    /// it never runs the kernel's code unobserved.
    pub const fn class(self) -> VdsoClass {
        use VdsoHandling::*;
        use VdsoInput::*;

        let (input, handling) = match self {
            #[cfg(target_arch = "x86_64")]
            Self::ClockGettime | Self::VdsoClockGettime => {
                (HostClock, Syscall(Sysno::clock_gettime))
            }
            #[cfg(target_arch = "x86_64")]
            Self::Gettimeofday | Self::VdsoGettimeofday => {
                (HostClock, Syscall(Sysno::gettimeofday))
            }
            #[cfg(target_arch = "x86_64")]
            Self::Getcpu | Self::VdsoGetcpu => (HostCpu, Syscall(Sysno::getcpu)),
            #[cfg(target_arch = "x86_64")]
            Self::Time | Self::VdsoTime => (HostClock, Syscall(Sysno::time)),
            #[cfg(target_arch = "x86_64")]
            Self::ClockGetres | Self::VdsoClockGetres => {
                (HostClockResolution, Syscall(Sysno::clock_getres))
            }
            // SGX enclave entry (`arch/x86/entry/vdso/vsgx.S`). glibc does not
            // call it. The kernel's version already returns negative errnos
            // (-EINVAL for an invalid leaf), so SGX runtimes handle a negative
            // result.
            #[cfg(target_arch = "x86_64")]
            Self::VdsoSgxEnterEnclave => (Enclave, Enosys),
            #[cfg(target_arch = "x86_64")]
            Self::Getrandom | Self::VdsoGetrandom => (HostEntropy, Syscall(Sysno::getrandom)),
            // `__u32 try_unlock(__u32 *lock, __u32 tid, pop)` is one
            // `lock cmpxchg` of TID to 0 on the caller's lock word and, if that
            // succeeds, a store of 0 to `*pop` (`arch/x86/entry/vdso/common/
            // vfutex.c`): guest memory only, like the inline atomics libc uses
            // for every other mutex, so it stays native. A -ENOSYS stub is not
            // needed and would cost a syscall per unlock: the caller compares
            // the result with its TID and, when they differ, unlocks through
            // `futex(op | FUTEX_ROBUST_UNLOCK)`, so every robust unlock would
            // reach the tool as that syscall, which Detcore does not yet
            // handle (https://github.com/rrnewton/hermit/issues/3526). A
            // replacement would also have to end before the critical section
            // the kernel records after the `lock cmpxchg` (at least 8 bytes
            // in): when a signal finds the instruction pointer inside it with
            // ZF set, the kernel clears `*(rdx)` (`futex_fixup_robust_unlock`),
            // which over other code could clear the pending-op pointer of a
            // lock still held.
            #[cfg(target_arch = "x86_64")]
            Self::VdsoFutexRobustList64TryUnlock | Self::VdsoFutexRobustList32TryUnlock => {
                (GuestMemory, Native)
            }
            // Issues rt_sigreturn, which restores the signal frame from guest
            // memory; see above for why it stays a syscall.
            #[cfg(target_arch = "aarch64")]
            Self::KernelRtSigreturn => (GuestMemory, Syscall(Sysno::rt_sigreturn)),
            #[cfg(target_arch = "aarch64")]
            Self::KernelGettimeofday => (HostClock, Syscall(Sysno::gettimeofday)),
            #[cfg(target_arch = "aarch64")]
            Self::KernelClockGettime => (HostClock, Syscall(Sysno::clock_gettime)),
            #[cfg(target_arch = "aarch64")]
            Self::KernelClockGetres => (HostClockResolution, Syscall(Sysno::clock_getres)),
            #[cfg(target_arch = "aarch64")]
            Self::KernelGetrandom => (HostEntropy, Syscall(Sysno::getrandom)),
        };
        VdsoClass { input, handling }
    }
}

impl fmt::Display for VdsoSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The classification as a C header, for the backends whose vDSO patching is
/// written in C. Each keeps a copy, which a test compares with this.
#[cfg(target_arch = "x86_64")]
pub fn c_header() -> String {
    let mut entries = String::new();
    for symbol in VdsoSymbol::ALL {
        let (handling, syscall) = match symbol.class().handling {
            VdsoHandling::Syscall(sysno) => ("REVERIE_VDSO_SYSCALL", i64::from(sysno.id())),
            VdsoHandling::Enosys => ("REVERIE_VDSO_ENOSYS", -1),
            VdsoHandling::Native => ("REVERIE_VDSO_NATIVE", -1),
        };
        entries.push_str(&format!(
            "    {{\"{}\", {handling}, {syscall}}},\n",
            symbol.name()
        ));
    }
    format!(
        r#"/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * @generated by `reverie::vdso::c_header()` from `VdsoSymbol::class` in
 * reverie/src/vdso.rs, which documents each entry. Do not edit: the test that
 * compares this file with the generator rewrites it when run with
 * REVERIE_BLESS=1.
 */

#ifndef REVERIE_VDSO_SYMBOLS_H
#define REVERIE_VDSO_SYMBOLS_H

#include <string.h>

/* What a backend that patches the x86_64 vDSO does with an entry point. */
enum reverie_vdso_handling {{
  /* Replace it with a stub that issues `syscall`. */
  REVERIE_VDSO_SYSCALL,
  /* Replace it with a stub that returns -ENOSYS. */
  REVERIE_VDSO_ENOSYS,
  /* Leave the kernel's code in place. */
  REVERIE_VDSO_NATIVE,
}};

struct reverie_vdso_symbol {{
  const char* name;
  enum reverie_vdso_handling handling;
  /* The syscall for REVERIE_VDSO_SYSCALL, otherwise -1. */
  long syscall;
}};

/* Every function the x86_64 vDSO exports, by its kernel name. */
static const struct reverie_vdso_symbol reverie_vdso_symbols[] = {{
{entries}}};

/*
 * The entry for the vDSO function named `name`, or NULL if it is unknown, in
 * which case it is replaced with -ENOSYS like REVERIE_VDSO_ENOSYS.
 */
static inline const struct reverie_vdso_symbol* reverie_vdso_symbol_lookup(
    const char* name) {{
  for (size_t index = 0;
       index < sizeof(reverie_vdso_symbols) / sizeof(reverie_vdso_symbols[0]);
       index++) {{
    if (strcmp(reverie_vdso_symbols[index].name, name) == 0)
      return &reverie_vdso_symbols[index];
  }}
  return NULL;
}}

#endif /* REVERIE_VDSO_SYMBOLS_H */
"#
    )
}
