/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The patch plan for a vDSO image: which entry points it exports, what each
//! one is, and the stub that replaces it.
//!
//! Every backend that presents a patched vDSO derives it from this plan, so a
//! guest sees the same code under each of them. reverie-ptrace applies it to
//! a traced guest's vDSO in place; reverie-kvm applies it to a copy of the
//! host's vDSO with [`patch_vdso_image`] before the guest starts.

use std::collections::BTreeMap;

use goblin::elf::Elf;
use reverie_syscalls::Sysno;

use super::VdsoHandling;
use super::VdsoSymbol;
use crate::Subscription;

#[repr(align(64))]
struct BufferAligned<const N: usize>([u8; N]);

// Byte code for the new pseudo vdso functions which do the actual syscalls.
// Note: the byte code must be 8 bytes aligned
/// The code that replaces vDSO entry points on x86_64.
#[cfg(target_arch = "x86_64")]
pub mod stubs {
    #![allow(non_upper_case_globals)]

    use super::BufferAligned;

    const time_code: BufferAligned<8> = BufferAligned::<8>([
        0xb8, 0xc9, 0x00, 0x00, 0x00, // mov %SYS_time, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ]);

    /// `time`: issues the time syscall.
    pub const time: &[u8; 8] = &time_code.0;

    const clock_gettime_code: BufferAligned<8> = BufferAligned::<8>([
        0xb8, 0xe4, 0x00, 0x00, 0x00, // mov SYS_clock_gettime, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ]);

    /// `clock_gettime`: issues the clock_gettime syscall.
    pub const clock_gettime: &[u8; 8] = &clock_gettime_code.0;

    const getcpu_code: BufferAligned<8> = BufferAligned::<8>([
        0xb8, 0x35, 0x01, 0x00, 0x00, // mov SYS_getcpu, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ]);

    /// `getcpu`: issues the getcpu syscall.
    pub const getcpu: &[u8; 8] = &getcpu_code.0;

    const gettimeofday_code: BufferAligned<8> = BufferAligned::<8>([
        0xb8, 0x60, 0x00, 0x00, 0x00, // mov SYS_gettimeofday, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ]);

    /// `gettimeofday`: issues the gettimeofday syscall.
    pub const gettimeofday: &[u8; 8] = &gettimeofday_code.0;

    const clock_getres_code: BufferAligned<8> = BufferAligned::<8>([
        0xb8, 0xe5, 0x00, 0x00, 0x00, // mov SYS_clock_getres, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ]);

    /// `clock_getres`: issues the clock_getres syscall.
    pub const clock_getres: &[u8; 8] = &clock_getres_code.0;

    // `__vdso_getrandom(buffer, len, flags, opaque_state, opaque_len)`.
    //
    // The kernel's implementation keys a per-thread ChaCha20 state with one
    // `getrandom(key, 32, 0)` syscall and re-keys whenever the kernel's crng
    // generation changes, i.e. at host-time-dependent points
    // (https://github.com/rrnewton/reverie/issues/841). This replacement never
    // touches the opaque state:
    //
    // * The parameter query `(NULL, 0, 0, params, ~0UL)` returns -ENOSYS
    //   without writing `params`. glibc 2.41+ (`__getrandom_early_init`) then
    //   leaves its state size at zero and serves every getrandom() with the
    //   getrandom syscall.
    // * Any other call is the getrandom syscall on the caller's first three
    //   arguments, which the function ABI already passes in rdi/rsi/rdx. This
    //   is the kernel vDSO's own fallback, and it keeps a libc that queried
    //   the unpatched vDSO before the patch (LiteInst patches from a
    //   constructor, after glibc's early init) working: its draws become
    //   syscalls instead of failing with -ENOSYS.
    const getrandom_code: BufferAligned<40> = BufferAligned::<40>([
        0x49, 0x83, 0xf8, 0xff, // cmp $-1, %r8
        0x75, 0x16, // jne syscall_path
        0x48, 0x85, 0xff, // test %rdi, %rdi
        0x75, 0x11, // jne syscall_path
        0x48, 0x85, 0xf6, // test %rsi, %rsi
        0x75, 0x0c, // jne syscall_path
        0x85, 0xd2, // test %edx, %edx
        0x75, 0x08, // jne syscall_path
        0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff, // mov $-ENOSYS, %rax
        0xc3, // retq
        // syscall_path:
        0xb8, 0x3e, 0x01, 0x00, 0x00, // mov SYS_getrandom, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
        0x90, 0x90, 0x90, 0x90, // padding
    ]);

    /// `getrandom`: answers the parameter query with -ENOSYS and issues the
    /// getrandom syscall for every other call.
    pub const getrandom: &[u8; 40] = &getrandom_code.0;

    /// Offset of the `syscall` instruction within [`getrandom`]. Every branch
    /// in the stub targets an address before it, so an in-guest hook may
    /// overwrite the bytes from here on.
    pub const GETRANDOM_SYSCALL_OFFSET: usize = 33;

    // The replacement for an entry point with no syscall equivalent, or one
    // this module does not know: it returns -ENOSYS without touching memory.
    const enosys_code: BufferAligned<8> = BufferAligned::<8>([
        0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff, // mov $-ENOSYS, %rax
        0xc3, // retq
    ]);

    /// An entry point with no syscall equivalent: returns -ENOSYS.
    pub const enosys: &[u8; 8] = &enosys_code.0;
}

/// The code that replaces vDSO entry points on aarch64.
#[cfg(target_arch = "aarch64")]
pub mod stubs {
    #![allow(non_upper_case_globals)]

    // See this example for how to generate the byte code: https://godbolt.org/z/hbzK7Ydc3
    //
    // Example below:
    // ```
    // __attribute__((noinline)) static int sys_gettimeofday(void) {
    //     register long x0 __asm__("x0");
    //     asm volatile("bti c; mov x8, 169; svc 0" : "=r"(x0) : : "memory", "cc");
    //     return (int)x0;
    // }
    // ```
    //
    // Notes:
    //  * The byte order below may be different from what the disassembler will
    //    show. aarch64 is little-endian by default whereas the 4-byte
    //    instructions are usually displayed in big-endian.
    //  * The aarch64 calling convention matches syscall arguments, so no need
    //    to adjust registers x0-x5 or the stack pointer before calling the
    //    syscall.
    //  * The `bti c` instruction is the "Branch Target Identification"
    //    instruction. This is here because this is the first instruction of the
    //    vdso function and will be the branch target. This also effectively
    //    serves as a NOP instruction to pad out the size of the thunk.
    //    See also
    //    https://developer.arm.com/documentation/ddi0596/2021-06/Base-Instructions/BTI--Branch-Target-Identification-

    use super::BufferAligned;

    const clock_getres_code: BufferAligned<16> = BufferAligned::<16>([
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0x48, 0x0e, 0x80, 0xd2, // mov x8, 114 (#__NR_clock_getres)
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ]);

    /// `__kernel_clock_getres`: issues the clock_getres syscall.
    pub const clock_getres: &[u8; 16] = &clock_getres_code.0;

    const clock_gettime_code: BufferAligned<16> = BufferAligned::<16>([
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0x28, 0x0e, 0x80, 0xd2, // mov x8, 113 (#__NR_clock_gettime)
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ]);

    /// `__kernel_clock_gettime`: issues the clock_gettime syscall.
    pub const clock_gettime: &[u8; 16] = &clock_gettime_code.0;

    const gettimeofday_code: BufferAligned<16> = BufferAligned::<16>([
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0x28, 0x15, 0x80, 0xd2, // mov x8, 169 (#__NR_gettimeofday)
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ]);

    /// `__kernel_gettimeofday`: issues the gettimeofday syscall.
    pub const gettimeofday: &[u8; 16] = &gettimeofday_code.0;

    // On aarch64, the vdso version of rt_sigreturn is only 8 bytes, so our
    // patch can't exceed that size. However, since this syscall doesn't return,
    // we can just call it without the `ret` instruction.
    //
    // NOTE: This is currently *exactly* how the kernel implements the
    // rt_sigreturn vdso, so we could probably get away with not even patching
    // it. See also `linux/arch/arm64/kernel/vdso/sigreturn.S`.
    const rt_sigreturn_code: BufferAligned<8> = BufferAligned::<8>([
        0x68, 0x11, 0x80, 0xd2, // mov x8, 139 (#__NR_rt_sigreturn)
        0x01, 0x00, 0x00, 0xd4, // svc 0
    ]);

    /// `__kernel_rt_sigreturn`: issues the rt_sigreturn syscall.
    pub const rt_sigreturn: &[u8; 8] = &rt_sigreturn_code.0;

    // `__kernel_getrandom`: the same contract as the x86_64 stub (see the
    // comment there). The parameter query `(NULL, 0, 0, params, ~0UL)`
    // returns -ENOSYS; every other call is the getrandom syscall on x0-x2.
    const getrandom_code: BufferAligned<48> = BufferAligned::<48>([
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0x9f, 0x04, 0x00, 0xb1, // cmn x4, #1
        0xc1, 0x00, 0x00, 0x54, // b.ne syscall_path
        0xa0, 0x00, 0x00, 0xb5, // cbnz x0, syscall_path
        0x81, 0x00, 0x00, 0xb5, // cbnz x1, syscall_path
        0x62, 0x00, 0x00, 0x35, // cbnz w2, syscall_path
        0xa0, 0x04, 0x80, 0x92, // mov x0, #-38 (-ENOSYS)
        0xc0, 0x03, 0x5f, 0xd6, // ret
        // syscall_path:
        0xc8, 0x22, 0x80, 0xd2, // mov x8, 278 (#__NR_getrandom)
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
        0x1f, 0x20, 0x03, 0xd5, // nop
    ]);

    /// `__kernel_getrandom`: answers the parameter query with -ENOSYS and
    /// issues the getrandom syscall for every other call.
    pub const getrandom: &[u8; 48] = &getrandom_code.0;

    // See the x86_64 `enosys` stub.
    const enosys_code: BufferAligned<16> = BufferAligned::<16>([
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0xa0, 0x04, 0x80, 0x92, // mov x0, #-38 (-ENOSYS)
        0xc0, 0x03, 0x5f, 0xd6, // ret
        0x1f, 0x20, 0x03, 0xd5, // nop
    ]);

    /// An entry point with no syscall equivalent: returns -ENOSYS.
    pub const enosys: &[u8; 16] = &enosys_code.0;
}

/// What reverie does with a vDSO entry point it knows: its
/// [`VdsoSymbol::class`], with the stub for this architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownEntry {
    /// A userspace fast path for the syscall, replaced by a stub that issues it.
    Syscall(&'static [u8], Sysno),
    /// An entry point with no syscall equivalent, replaced by
    /// [`stubs::enosys`].
    Enosys,
    /// An entry point that keeps the kernel's code.
    Native,
}

impl KnownEntry {
    /// The entry for `symbol`, or why it cannot be patched here.
    pub fn of(symbol: VdsoSymbol) -> Result<Self, String> {
        Ok(match symbol.class().handling {
            VdsoHandling::Syscall(sysno) => Self::Syscall(
                syscall_stub(sysno).ok_or_else(|| {
                    format!(
                        "vDSO entry point {symbol} is a fast path of {sysno}, which has no stub"
                    )
                })?,
                sysno,
            ),
            VdsoHandling::Enosys => Self::Enosys,
            VdsoHandling::Native => Self::Native,
        })
    }
}

/// The stub that replaces a vDSO fast path of `sysno`.
#[cfg(target_arch = "x86_64")]
pub fn syscall_stub(sysno: Sysno) -> Option<&'static [u8]> {
    Some(match sysno {
        Sysno::time => stubs::time,
        Sysno::clock_gettime => stubs::clock_gettime,
        Sysno::getcpu => stubs::getcpu,
        Sysno::gettimeofday => stubs::gettimeofday,
        Sysno::clock_getres => stubs::clock_getres,
        Sysno::getrandom => stubs::getrandom,
        _ => return None,
    })
}

/// The stub that replaces a vDSO fast path of `sysno`.
#[cfg(target_arch = "aarch64")]
pub fn syscall_stub(sysno: Sysno) -> Option<&'static [u8]> {
    Some(match sysno {
        Sysno::clock_getres => stubs::clock_getres,
        Sysno::clock_gettime => stubs::clock_gettime,
        Sysno::gettimeofday => stubs::gettimeofday,
        Sysno::rt_sigreturn => stubs::rt_sigreturn,
        Sysno::getrandom => stubs::getrandom,
        _ => return None,
    })
}

/// Rounds up `value` so that it is a multiple of `alignment`.
pub fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & alignment.wrapping_neg()
}

/// One entry point exported by a vDSO's dynamic symbol table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdsoExport {
    /// The exported name.
    pub name: String,
    /// The symbol's value: its offset into the vDSO, which is linked at 0.
    pub offset: u64,
    /// The symbol's `st_size`.
    pub size: usize,
    /// The end of the section that contains the symbol, if the image has
    /// section headers.
    pub section_end: Option<u64>,
}

/// What a vDSO entry point is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VdsoEntryKind {
    /// A name exported at its address is a [`VdsoSymbol`].
    Known(KnownEntry),
    /// No name exported at its address is a [`VdsoSymbol`].
    Unknown,
}

/// One vDSO entry point, with every name exported at its address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdsoEntry {
    /// The exported names, the known one (if any) first.
    pub names: Vec<String>,
    /// The entry point's offset into the vDSO.
    pub offset: u64,
    /// The bytes a stub must fit in: `st_size` rounded up to 16, the function
    /// alignment of the x86_64 vDSO (not verified for aarch64), cut short at
    /// the next entry point and at the end of the containing section. The rounding is an
    /// assumption about the image, so only a stub longer than `st_size` relies
    /// on it; see [`VdsoEntry::patch_len`].
    pub size: usize,
    /// The symbol's `st_size`.
    pub symbol_size: usize,
    /// What the entry point is.
    pub kind: VdsoEntryKind,
}

impl VdsoEntry {
    /// The stub that replaces this entry point under `subscriptions`, or `None`
    /// to leave it native.
    ///
    /// A syscall fast path is replaced only when its own syscall is subscribed.
    /// Rewriting an entry point nobody subscribed to converts a pure userspace
    /// vDSO call into a real syscall for no gain: the tool never sees it, and
    /// the guest pays the kernel crossing anyway. That cost is not hypothetical
    /// -- QEMU's main loop calls `clock_gettime` continuously *while holding the
    /// Big QEMU Lock*, so every needless crossing is taken with a lock held that
    /// vCPU threads are waiting on.
    ///
    /// Every other entry point, except those [`VdsoHandling::Native`] keeps, is
    /// replaced by [`stubs::enosys`] whenever the tool subscribes to any
    /// syscall, because an unknown entry point could be the fast path of any of
    /// them. A tool that subscribes to no syscall observes nothing a vDSO
    /// function could bypass.
    pub fn replacement(&self, subscriptions: &Subscription) -> Option<&'static [u8]> {
        match self.kind {
            VdsoEntryKind::Known(KnownEntry::Syscall(stub, sysno)) => subscriptions
                .iter_syscalls()
                .any(|syscall| syscall == sysno)
                .then_some(stub),
            VdsoEntryKind::Known(KnownEntry::Enosys) | VdsoEntryKind::Unknown => subscriptions
                .iter_syscalls()
                .next()
                .is_some()
                .then_some(stubs::enosys),
            VdsoEntryKind::Known(KnownEntry::Native) => None,
        }
    }

    /// The bytes a `stub_len`-byte stub and its NOP fill overwrite: the whole
    /// function, and padding only where the stub itself is longer. Filling to
    /// `size` would write over whatever follows the function when the image is
    /// not padded as assumed; on this x86_64 host the last entry point ends 4
    /// bytes before `.altinstructions`, which `size` rounded into.
    pub fn patch_len(&self, stub_len: usize) -> usize {
        debug_assert!(stub_len <= self.size);
        self.symbol_size.max(stub_len)
    }

    /// The entry point's names and offset, for messages.
    pub fn describe(&self) -> String {
        format!("{}@{:#x}", self.names.join("/"), self.offset)
    }
}

/// Every entry point exported by the vDSO image `image`.
///
/// This fails closed on the symbol type: only data (`STT_OBJECT`, `STT_TLS`,
/// `STT_COMMON`) and bookkeeping (`STT_SECTION`, `STT_FILE`) symbols are
/// skipped, so an export of any other type is an entry point. That includes
/// aarch64's `__kernel_rt_sigreturn`, which is `STT_NOTYPE`. Local, undefined
/// and absolute symbols are not exported functions; older vDSOs export their
/// version names, such as `LINUX_2.6`, as absolute symbols.
pub fn vdso_exports(image: &[u8]) -> Result<Vec<VdsoExport>, String> {
    use goblin::elf::section_header::SHN_ABS;
    use goblin::elf::section_header::SHN_UNDEF;
    use goblin::elf::sym::STB_LOCAL;
    use goblin::elf::sym::STT_COMMON;
    use goblin::elf::sym::STT_FILE;
    use goblin::elf::sym::STT_OBJECT;
    use goblin::elf::sym::STT_SECTION;
    use goblin::elf::sym::STT_TLS;

    let elf = Elf::parse(image).map_err(|error| format!("cannot parse the vDSO: {error}"))?;
    let mut exports = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_bind() == STB_LOCAL
            || sym.st_shndx == SHN_UNDEF as usize
            || sym.st_shndx == SHN_ABS as usize
            || matches!(
                sym.st_type(),
                STT_OBJECT | STT_TLS | STT_COMMON | STT_SECTION | STT_FILE
            )
        {
            continue;
        }
        let name = elf.dynstrtab.get_at(sym.st_name).ok_or_else(|| {
            format!(
                "vDSO symbol name offset {} is outside its string table",
                sym.st_name
            )
        })?;
        exports.push(VdsoExport {
            name: name.to_owned(),
            offset: sym.st_value,
            size: sym.st_size as usize,
            section_end: elf
                .section_headers
                .get(sym.st_shndx)
                .map(|section| section.sh_addr + section.sh_size),
        });
    }
    Ok(exports)
}

/// Groups `exports` by address into entry points and classifies each by
/// [`VdsoSymbol::class`].
///
/// Refuses, rather than guess, whenever a stub cannot be placed safely: two
/// known names that need different stubs at one address, names at one address
/// that disagree on the size, entry points that overlap, a stub larger than
/// its entry point, or a syscall fast path this architecture has no stub for.
pub fn classify_vdso_exports(exports: &[VdsoExport]) -> Result<Vec<VdsoEntry>, String> {
    let mut by_offset: BTreeMap<u64, Vec<&VdsoExport>> = BTreeMap::new();
    for export in exports {
        by_offset.entry(export.offset).or_default().push(export);
    }

    let offsets: Vec<u64> = by_offset.keys().copied().collect();
    let mut entries = Vec::new();
    for (index, (offset, group)) in by_offset.into_iter().enumerate() {
        let first = group[0];
        if let Some(other) = group.iter().find(|export| export.size != first.size) {
            return Err(format!(
                "vDSO exports {} ({} bytes) and {} ({} bytes) at one address {offset:#x}",
                first.name, first.size, other.name, other.size
            ));
        }

        let mut names: Vec<String> = Vec::new();
        let mut known: Option<KnownEntry> = None;
        for export in &group {
            match VdsoSymbol::from_name(&export.name) {
                Some(symbol) => {
                    let entry = KnownEntry::of(symbol)?;
                    if let Some(previous) = known
                        && previous != entry
                    {
                        return Err(format!(
                            "vDSO exports {} and {symbol} at one address {offset:#x}, \
                             but they need different stubs",
                            names[0]
                        ));
                    }
                    if known.is_none() {
                        names.insert(0, export.name.clone());
                    } else {
                        names.push(export.name.clone());
                    }
                    known = Some(entry);
                }
                None => names.push(export.name.clone()),
            }
        }

        let next = offsets.get(index + 1).copied();
        if let Some(next) = next
            && offset + first.size as u64 > next
        {
            return Err(format!(
                "vDSO entry point {}@{offset:#x} ({} bytes) overlaps the one at {next:#x}",
                names[0], first.size
            ));
        }
        if let Some(section_end) = first.section_end
            && offset + first.size as u64 > section_end
        {
            return Err(format!(
                "vDSO entry point {}@{offset:#x} ({} bytes) runs past the end of \
                 its section at {section_end:#x}",
                names[0], first.size
            ));
        }
        let mut size = align_up(first.size, 16);
        if let Some(next) = next {
            size = size.min((next - offset) as usize);
        }
        if let Some(section_end) = first.section_end {
            size = size.min((section_end - offset) as usize);
        }

        let kind = known.map_or(VdsoEntryKind::Unknown, VdsoEntryKind::Known);
        let stub_len = match kind {
            VdsoEntryKind::Known(KnownEntry::Syscall(stub, _)) => stub.len(),
            VdsoEntryKind::Known(KnownEntry::Enosys) | VdsoEntryKind::Unknown => {
                stubs::enosys.len()
            }
            VdsoEntryKind::Known(KnownEntry::Native) => 0,
        };
        if stub_len > size {
            return Err(format!(
                "vDSO entry point {}@{offset:#x} has {size} bytes, \
                 too few for its {stub_len}-byte stub",
                names[0]
            ));
        }
        entries.push(VdsoEntry {
            names,
            offset,
            size,
            symbol_size: first.size,
            kind,
        });
    }
    Ok(entries)
}

/// The entry points of the vDSO image `image`: [`vdso_exports`], grouped and
/// classified by [`classify_vdso_exports`].
pub fn classify_vdso_image(image: &[u8]) -> Result<Vec<VdsoEntry>, String> {
    classify_vdso_exports(&vdso_exports(image)?)
}

/// The byte written after a stub, up to [`VdsoEntry::patch_len`]. Execution
/// never reaches it, since every stub ends in a return or a syscall that does
/// not return; it is the x86_64 NOP on every architecture so that the patched
/// bytes are the same wherever they are written.
pub const PATCH_FILL: u8 = 0x90;

/// Writes into `image` the stub [`VdsoEntry::replacement`] selects under
/// `subscriptions` for each of `entries`, then [`PATCH_FILL`] up to
/// [`VdsoEntry::patch_len`]. These are the bytes reverie-ptrace writes into a
/// stopped guest's vDSO, so a copy of the host's vDSO patched here is the image
/// a traced guest runs.
///
/// Refuses an entry point whose patch would not fit in `image`, before
/// writing anything.
pub fn patch_vdso_image(
    image: &mut [u8],
    entries: &[VdsoEntry],
    subscriptions: &Subscription,
) -> Result<(), String> {
    let mut patches = Vec::new();
    for entry in entries {
        let Some(stub) = entry.replacement(subscriptions) else {
            continue;
        };
        let start = usize::try_from(entry.offset)
            .map_err(|_| format!("vDSO entry point {} is out of range", entry.describe()))?;
        let len = entry.patch_len(stub.len());
        if start.checked_add(len).is_none_or(|end| end > image.len()) {
            return Err(format!(
                "vDSO entry point {} needs {len} bytes, past the end of the {}-byte image",
                entry.describe(),
                image.len()
            ));
        }
        patches.push((start, len, stub));
    }
    for (start, len, stub) in patches {
        image[start..start + stub.len()].copy_from_slice(stub);
        image[start + stub.len()..start + len].fill(PATCH_FILL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(15, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
    }

    /// Every [`VdsoSymbol`] that is a syscall fast path, with its stub.
    fn known_syscalls() -> impl Iterator<Item = (&'static str, &'static [u8], Sysno)> {
        VdsoSymbol::ALL
            .iter()
            .filter_map(|symbol| match KnownEntry::of(*symbol).unwrap() {
                KnownEntry::Syscall(stub, sysno) => Some((symbol.name(), stub, sysno)),
                KnownEntry::Enosys | KnownEntry::Native => None,
            })
    }

    /// The first syscall fast path in [`VdsoSymbol::ALL`], so the synthetic
    /// tests run unchanged on every architecture.
    fn a_known_syscall() -> (&'static str, &'static [u8], Sysno) {
        known_syscalls().next().unwrap()
    }

    fn export(name: &str, offset: u64, size: usize) -> VdsoExport {
        VdsoExport {
            name: name.to_owned(),
            offset,
            size,
            section_end: None,
        }
    }

    /// Every [`VdsoSymbol`] has a plan on this architecture: a syscall fast
    /// path has a stub, and aliases agree on it.
    #[test]
    fn every_classified_symbol_has_a_plan() {
        let mut by_function: BTreeMap<&str, Vec<VdsoExport>> = BTreeMap::new();
        for symbol in VdsoSymbol::ALL {
            let function = symbol.name().trim_start_matches("__vdso_");
            by_function
                .entry(function)
                .or_default()
                .push(export(symbol.name(), 0, 64));
        }
        let mut exports = Vec::new();
        for (index, group) in by_function.into_values().enumerate() {
            for mut alias in group {
                alias.offset = 0x800 + 0x100 * index as u64;
                exports.push(alias);
            }
        }
        let entries = classify_vdso_exports(&exports).unwrap();
        for entry in &entries {
            assert_ne!(entry.kind, VdsoEntryKind::Unknown, "{}", entry.describe());
        }
        assert_eq!(
            entries.iter().map(|entry| entry.names.len()).sum::<usize>(),
            VdsoSymbol::ALL.len()
        );
    }

    /// The fail-closed property itself: an entry point this module has never
    /// heard of is replaced whenever the tool observes any syscall, and never
    /// silently left running the kernel's code.
    #[test]
    fn unknown_vdso_entry_point_is_stubbed() {
        let (known, stub, sysno) = a_known_syscall();
        let entries = classify_vdso_exports(&[
            export(known, 0x800, 100),
            export("future_alias", 0x800, 100),
            export("__vdso_future_call", 0x900, 40),
        ])
        .unwrap();

        assert_eq!(entries.len(), 2);
        let known_entry = &entries[0];
        assert_eq!(known_entry.names, vec![known, "future_alias"]);
        assert_eq!(known_entry.offset, 0x800);
        assert_eq!(known_entry.size, 112);
        assert_eq!(
            known_entry.kind,
            VdsoEntryKind::Known(KnownEntry::Syscall(stub, sysno))
        );

        let unknown = &entries[1];
        assert_eq!(unknown.names, vec!["__vdso_future_call"]);
        assert_eq!(unknown.offset, 0x900);
        assert_eq!(unknown.size, 48);
        assert_eq!(unknown.kind, VdsoEntryKind::Unknown);

        let unrelated: Subscription = [if sysno == Sysno::read {
            Sysno::write
        } else {
            Sysno::read
        }]
        .into_iter()
        .collect();
        for subscriptions in [Subscription::all(), unrelated.clone()] {
            assert_eq!(
                unknown.replacement(&subscriptions),
                Some(&stubs::enosys[..]),
                "an unknown vDSO entry point must be replaced by the -ENOSYS stub",
            );
        }
        assert_eq!(unknown.replacement(&Subscription::none()), None);

        assert_eq!(
            known_entry.replacement(&[sysno].into_iter().collect()),
            Some(stub)
        );
        assert_eq!(known_entry.replacement(&Subscription::all()), Some(stub));
        assert_eq!(known_entry.replacement(&unrelated), None);
        assert_eq!(known_entry.replacement(&Subscription::none()), None);
    }

    #[test]
    fn unknown_name_listed_first_at_a_known_address_is_still_known() {
        let (known, stub, sysno) = a_known_syscall();
        let entries =
            classify_vdso_exports(&[export("alias_first", 0x800, 64), export(known, 0x800, 64)])
                .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].names, vec![known, "alias_first"]);
        assert_eq!(
            entries[0].kind,
            VdsoEntryKind::Known(KnownEntry::Syscall(stub, sysno))
        );
    }

    #[test]
    fn last_entry_point_gets_its_aligned_size() {
        let entries = classify_vdso_exports(&[export("__vdso_future_call", 0x900, 9)]).unwrap();
        assert_eq!(entries[0].size, 16);
    }

    #[test]
    fn last_entry_point_stops_at_the_end_of_its_section() {
        let mut last = export("__vdso_future_call", 0x900, 9);
        last.section_end = Some(0x90c);
        let entries = classify_vdso_exports(&[last]).unwrap();
        assert_eq!(entries[0].size, 12);
    }

    #[test]
    fn entry_point_past_the_end_of_its_section_is_refused() {
        let mut last = export("__vdso_future_call", 0x900, 16);
        last.section_end = Some(0x90c);
        let error = classify_vdso_exports(&[last]).unwrap_err();
        assert!(error.contains("past the end of its section"), "{error}");
    }

    /// A stub overwrites the function, and alignment padding only where the
    /// stub is longer than the function.
    #[test]
    fn patch_covers_the_function_and_no_more_of_its_padding_than_the_stub() {
        let entries = classify_vdso_exports(&[
            export("__vdso_future_call", 0x900, 20),
            export("__vdso_other_call", 0x980, 4),
        ])
        .unwrap();
        assert_eq!((entries[0].size, entries[0].patch_len(8)), (32, 20));
        assert_eq!((entries[1].size, entries[1].patch_len(8)), (16, 8));
    }

    #[test]
    fn entry_point_too_small_for_its_stub_is_refused() {
        let (known, stub, _) = a_known_syscall();
        let error = classify_vdso_exports(&[
            export(known, 0x800, 1),
            export("next", 0x800 + stub.len() as u64 - 1, 16),
        ])
        .unwrap_err();
        assert!(error.contains("too few"), "{error}");

        let error = classify_vdso_exports(&[
            export("__vdso_future_call", 0x800, 1),
            export("next", 0x800 + stubs::enosys.len() as u64 - 1, 16),
        ])
        .unwrap_err();
        assert!(error.contains("too few"), "{error}");
    }

    #[test]
    fn overlapping_entry_points_are_refused() {
        let error = classify_vdso_exports(&[
            export("__vdso_future_call", 0x800, 0x40),
            export("__vdso_other_call", 0x820, 0x40),
        ])
        .unwrap_err();
        assert!(error.contains("overlaps"), "{error}");
    }

    #[test]
    fn names_disagreeing_on_size_are_refused() {
        let error = classify_vdso_exports(&[
            export("__vdso_future_call", 0x800, 0x40),
            export("future_alias", 0x800, 0x20),
        ])
        .unwrap_err();
        assert!(error.contains("one address"), "{error}");
    }

    #[test]
    fn known_names_needing_different_stubs_at_one_address_are_refused() {
        let (first, _, first_sysno) = a_known_syscall();
        let (other, _, _) = known_syscalls()
            .find(|(_, _, sysno)| *sysno != first_sysno)
            .unwrap();
        let error =
            classify_vdso_exports(&[export(first, 0x800, 0x40), export(other, 0x800, 0x40)])
                .unwrap_err();
        assert!(error.contains("different stubs"), "{error}");
    }

    #[test]
    fn patching_writes_each_selected_stub_and_its_fill_and_nothing_else() {
        let (known, stub, sysno) = a_known_syscall();
        let entries = classify_vdso_exports(&[
            export(known, 0x20, 4),
            export("__vdso_future_call", 0x40, 20),
        ])
        .unwrap();
        let mut image = vec![0xccu8; 0x80];
        patch_vdso_image(&mut image, &entries, &[sysno].into_iter().collect()).unwrap();
        let known_len = entries[0].patch_len(stub.len());
        assert_eq!(&image[0x20..0x20 + stub.len()], stub);
        assert!(
            image[0x20 + stub.len()..0x20 + known_len]
                .iter()
                .all(|&byte| byte == PATCH_FILL)
        );
        assert_eq!(&image[0x40..0x40 + stubs::enosys.len()], stubs::enosys);
        assert!(
            image[0x40 + stubs::enosys.len()..0x40 + 20]
                .iter()
                .all(|&byte| byte == PATCH_FILL)
        );
        let untouched = (0..0x80).filter(|offset| {
            !(0x20..0x20 + known_len).contains(offset) && !(0x40..0x40 + 20).contains(offset)
        });
        assert!(untouched.into_iter().all(|offset| image[offset] == 0xcc));
    }

    #[test]
    fn patching_with_no_subscription_leaves_the_image_alone() {
        let (known, _, _) = a_known_syscall();
        let entries = classify_vdso_exports(&[export(known, 0x20, 16)]).unwrap();
        let mut image = vec![0xccu8; 0x40];
        patch_vdso_image(&mut image, &entries, &Subscription::none()).unwrap();
        assert!(image.iter().all(|&byte| byte == 0xcc));
    }

    #[test]
    fn a_patch_past_the_end_of_the_image_is_refused_before_any_write() {
        let (known, _, _) = a_known_syscall();
        let entries = classify_vdso_exports(&[
            export(known, 0x10, 16),
            export("__vdso_future_call", 0x38, 16),
        ])
        .unwrap();
        let mut image = vec![0xccu8; 0x40];
        let error = patch_vdso_image(&mut image, &entries, &Subscription::all()).unwrap_err();
        assert!(error.contains("past the end"), "{error}");
        assert!(image.iter().all(|&byte| byte == 0xcc));
    }
}
