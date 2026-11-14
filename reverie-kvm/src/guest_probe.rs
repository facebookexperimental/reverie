/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A runner for the in-guest VM-exit XSAVE qualification probe.
//!
//! A caller, such as a host qualification that compares a guest's XSAVE
//! images across VM exits, supplies a small position-independent blob. The runner installs it with a context page in a
//! fresh [`KvmBackend`](crate::KvmBackend), runs it at CPL3 on a dedicated vCPU
//! thread, and drives `KVM_RUN` one call at a time. Around each call it reads
//! the vCPU's binary statistics, the vCPU thread's context switches and its
//! CPU, so that the caller can certify exactly which kernel transitions a
//! trial took.
//!
//! The blob reaches user space through the CPL0 syscall trampoline, never
//! through a CPL3 `vmcall`/`vmmcall`, which KVM refuses without an exit to
//! user space (`____kvm_emulate_hypercall`, Linux arch/x86/kvm/x86.c). A
//! `syscall` with a probe marker in RAX becomes a `KVM_EXIT_HYPERCALL` of nr 12
//! whose frame word 0 holds the marker.
//!
//! This module runs no Tool. It reports bytes and counters; the caller holds
//! every expectation and comparator, except the pinned form of the syscall
//! trampoline, which this module checks itself before the first `KVM_RUN`.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;

use crate::Error;
use crate::Result;

/// `KVM_GET_STATS_FD`, `_IO(KVMIO, 0xce)` (include/uapi/linux/kvm.h). kvm-ioctls
/// has no stats-fd API, so this is a raw ioctl on the vCPU fd.
const KVM_GET_STATS_FD: libc::c_ulong = (0xae << 8) | 0xce;

/// `struct kvm_stats_header`: six `__u32` words.
const STATS_HEADER_SIZE: usize = 24;

/// The fixed part of `struct kvm_stats_desc` before its name: `flags`,
/// `exponent`, `size`, `offset` and `bucket_size`.
const STATS_DESC_FIXED_SIZE: usize = 16;

/// `KVM_STATS_TYPE_MASK` and `KVM_STATS_TYPE_CUMULATIVE`.
const KVM_STATS_TYPE_MASK: u32 = 0xf;
const KVM_STATS_TYPE_CUMULATIVE: u32 = 0;

/// The vCPU statistics the probe certifies with, in [`VcpuStatsSnapshot`]'s
/// field order. Each is a cumulative x86 vCPU counter (the
/// `kvm_vcpu_stats_desc` table in arch/x86/kvm/x86.c).
const STAT_NAMES: [&str; 7] = [
    "exits",
    "signal_exits",
    "halt_exits",
    "hypercalls",
    "fpu_reload",
    "preemption_reported",
    "preemption_other",
];

/// One reading of the vCPU's binary statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VcpuStatsSnapshot {
    /// Every physical VM exit, whether or not it returned to user space.
    pub exits: u64,
    /// Exits taken because a signal was pending for the vCPU thread.
    pub signal_exits: u64,
    /// HLT exits.
    pub halt_exits: u64,
    /// Vendor hypercall instructions KVM emulated, counted before the CPL
    /// check.
    pub hypercalls: u64,
    /// Guest-FPU puts: one per `KVM_RUN`, and one per load/put pair of an
    /// xstate-managed MSR or register access.
    pub fpu_reload: u64,
    /// Preemptions reported through steal time.
    pub preemption_reported: u64,
    /// Preemptions not reported through steal time.
    pub preemption_other: u64,
}

impl VcpuStatsSnapshot {
    fn from_values(values: [u64; 7]) -> Self {
        let [
            exits,
            signal_exits,
            halt_exits,
            hypercalls,
            fpu_reload,
            preemption_reported,
            preemption_other,
        ] = values;
        Self {
            exits,
            signal_exits,
            halt_exits,
            hypercalls,
            fpu_reload,
            preemption_reported,
            preemption_other,
        }
    }

    /// `later - self`, field by field. The counters only grow, so a smaller
    /// later value is an error, never a wrapped difference.
    pub fn delta_to(&self, later: &Self) -> Result<Self> {
        let sub = |name: &str, before: u64, after: u64| {
            after.checked_sub(before).ok_or_else(|| {
                Error::UnexpectedVcpuExit(format!(
                    "vCPU statistic {name} went backwards: {before} then {after}"
                ))
            })
        };
        Ok(Self {
            exits: sub("exits", self.exits, later.exits)?,
            signal_exits: sub("signal_exits", self.signal_exits, later.signal_exits)?,
            halt_exits: sub("halt_exits", self.halt_exits, later.halt_exits)?,
            hypercalls: sub("hypercalls", self.hypercalls, later.hypercalls)?,
            fpu_reload: sub("fpu_reload", self.fpu_reload, later.fpu_reload)?,
            preemption_reported: sub(
                "preemption_reported",
                self.preemption_reported,
                later.preemption_reported,
            )?,
            preemption_other: sub(
                "preemption_other",
                self.preemption_other,
                later.preemption_other,
            )?,
        })
    }
}

/// Where in the stats file each of [`STAT_NAMES`] lives: the data block's
/// offset plus the descriptor's offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatsLayout {
    offsets: [u64; 7],
}

impl StatsLayout {
    /// Parse the header and descriptors through `read_at(buffer, offset)`,
    /// which fills `buffer` exactly from the stats file at `offset`. Every
    /// named statistic must appear exactly once, as a cumulative counter of one
    /// `__u64`; anything else is refused by name.
    pub(crate) fn parse(read_at: impl Fn(&mut [u8], u64) -> io::Result<()>) -> Result<Self> {
        let refuse = |why: String| Error::UnsupportedHost(format!("KVM vCPU statistics: {why}"));
        let mut header = [0_u8; STATS_HEADER_SIZE];
        read_at(&mut header, 0)?;
        let word = |index: usize| {
            u32::from_ne_bytes(
                header[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("a four-byte slice"),
            )
        };
        let (flags, name_size, num_desc, desc_offset, data_offset) =
            (word(0), word(1), word(2), word(4), word(5));
        if flags != 0 {
            return Err(refuse(format!("header flags {flags:#x}, not 0")));
        }
        let name_size = usize::try_from(name_size).expect("u32 fits usize");
        if name_size == 0 {
            return Err(refuse("descriptor names have size 0".into()));
        }
        let stride = STATS_DESC_FIXED_SIZE + name_size;
        let count = usize::try_from(num_desc).expect("u32 fits usize");
        let total = stride
            .checked_mul(count)
            .filter(|total| *total <= 1 << 20)
            .ok_or_else(|| refuse(format!("{count} descriptors of {stride} bytes")))?;
        let mut descriptors = vec![0_u8; total];
        read_at(&mut descriptors, u64::from(desc_offset))?;
        let mut offsets = [None; 7];
        for descriptor in descriptors.chunks_exact(stride) {
            let name = &descriptor[STATS_DESC_FIXED_SIZE..];
            let name = &name[..name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len())];
            let Some(index) = STAT_NAMES
                .iter()
                .position(|wanted| wanted.as_bytes() == name)
            else {
                continue;
            };
            let field32 = |at: usize| {
                u32::from_ne_bytes(descriptor[at..at + 4].try_into().expect("four bytes"))
            };
            let desc_flags = field32(0);
            let size = u16::from_ne_bytes(descriptor[6..8].try_into().expect("two bytes"));
            let offset = field32(8);
            let label = STAT_NAMES[index];
            if desc_flags & KVM_STATS_TYPE_MASK != KVM_STATS_TYPE_CUMULATIVE {
                return Err(refuse(format!(
                    "{label} has flags {desc_flags:#x}, not a cumulative counter"
                )));
            }
            if size != 1 {
                return Err(refuse(format!("{label} has {size} items, not 1")));
            }
            if offsets[index].is_some() {
                return Err(refuse(format!("{label} is described twice")));
            }
            offsets[index] = Some(u64::from(data_offset) + u64::from(offset));
        }
        let mut found = [0_u64; 7];
        for (index, offset) in offsets.into_iter().enumerate() {
            found[index] =
                offset.ok_or_else(|| refuse(format!("no {} descriptor", STAT_NAMES[index])))?;
        }
        Ok(Self { offsets: found })
    }

    /// Read one snapshot through `read_at`.
    pub(crate) fn read(
        &self,
        read_at: impl Fn(&mut [u8], u64) -> io::Result<()>,
    ) -> Result<VcpuStatsSnapshot> {
        let mut values = [0_u64; 7];
        for (value, offset) in values.iter_mut().zip(self.offsets) {
            let mut bytes = [0_u8; 8];
            read_at(&mut bytes, offset)?;
            *value = u64::from_ne_bytes(bytes);
        }
        Ok(VcpuStatsSnapshot::from_values(values))
    }
}

/// A vCPU's binary statistics file, opened once and read with `pread`, so any
/// thread can take a snapshot without touching the vCPU fd.
pub(crate) struct VcpuStats {
    file: File,
    layout: StatsLayout,
}

impl VcpuStats {
    /// Open the statistics of `vcpu` with `KVM_GET_STATS_FD`.
    pub(crate) fn open(vcpu: &kvm_ioctls::VcpuFd) -> Result<Self> {
        // SAFETY: KVM_GET_STATS_FD takes no argument; it returns a new file
        // descriptor, or -1 with errno.
        let fd = unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_GET_STATS_FD as _) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: the kernel just returned this descriptor, and nothing else
        // owns it.
        let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let layout = StatsLayout::parse(|buffer, offset| file.read_exact_at(buffer, offset))?;
        Ok(Self { file, layout })
    }

    /// One snapshot.
    pub(crate) fn snapshot(&self) -> Result<VcpuStatsSnapshot> {
        self.layout
            .read(|buffer, offset| self.file.read_exact_at(buffer, offset))
    }

    /// The same statistics through a duplicated descriptor, for a helper
    /// thread.
    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            layout: self.layout,
        })
    }
}

/// Why a vCPU keeps IA32_XSS = 0: the public mirror of the crate's private
/// decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XssKeepReason {
    /// The processor supports no IA32_XSS component.
    NoHostComponents,
    /// KVM_GET_SUPPORTED_CPUID has no CPUID.(EAX=0DH,ECX=1) row.
    NoKvmRow,
    /// KVM does not report every component the processor supports.
    Unproven {
        /// The processor's IA32_XSS components.
        hardware: u64,
        /// KVM's.
        kvm: u64,
    },
    /// KVM's row is not exactly the two reviewed CET components.
    Unreviewed {
        /// KVM's IA32_XSS components.
        kvm: u64,
    },
    /// The vCPU's CPUID table lacks XSAVES or a component.
    VcpuTable,
}

/// What the backend actually left in the vCPU's IA32_XSS at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XssOutcomeKind {
    /// The vCPU holds the host's IA32_XSS.
    Set(u64),
    /// The vCPU keeps IA32_XSS = 0, for this reason.
    Kept(XssKeepReason),
    /// Setting the host's value failed, and the vCPU was confirmed to hold 0.
    Failed,
}

/// [`XssOutcomeKind`] with the vCPU's IA32_XSS read back from KVM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XssOutcome {
    /// What construction did.
    pub kind: XssOutcomeKind,
    /// `KVM_GET_MSRS` of IA32_XSS (0xDA0) on the runner's vCPU.
    pub read_back: u64,
}

impl XssOutcomeKind {
    pub(crate) fn from_outcome(outcome: crate::host_xss::Outcome) -> Self {
        use crate::host_xss::Keep;
        use crate::host_xss::Outcome;
        match outcome {
            Outcome::Set(value) => Self::Set(value),
            Outcome::Failed => Self::Failed,
            Outcome::Kept(keep) => Self::Kept(match keep {
                Keep::NoHostComponents => XssKeepReason::NoHostComponents,
                Keep::NoKvmRow => XssKeepReason::NoKvmRow,
                Keep::Unproven { hardware, kvm } => XssKeepReason::Unproven { hardware, kvm },
                Keep::Unreviewed { kvm } => XssKeepReason::Unreviewed { kvm },
                Keep::VcpuTable => XssKeepReason::VcpuTable,
            }),
        }
    }
}

/// The marker a blob puts in EAX for the `syscall` that forces the exit a
/// trial measures. Frame word 0 carries it to the runner.
pub const PROBE_MARKER_FORCE: u32 = 0x0050_5801;
/// The marker of an exit at which the host installs an FPU image before the
/// guest resumes.
pub const PROBE_MARKER_SIG: u32 = 0x0050_5802;
/// The marker of a blob's final exit.
pub const PROBE_MARKER_DONE: u32 = 0x0050_5803;

const PROBE_MARKERS: [u32; 3] = [PROBE_MARKER_FORCE, PROBE_MARKER_SIG, PROBE_MARKER_DONE];

/// The markers' range. The lower bound is far above every x86-64 Linux
/// syscall number, so no marker is a syscall (a test asks Reverie's table for
/// each). The upper bound keeps them clear of the x32 bit (0x4000_0000), so
/// `mov eax, imm32` zero-extends each to the 64-bit value the runner compares.
const PROBE_MARKER_RANGE: std::ops::Range<u32> = 0x0001_0000..0x4000_0000;

// Distinct and inside the range.
const _: () = {
    let mut i = 0;
    while i < PROBE_MARKERS.len() {
        assert!(
            PROBE_MARKERS[i] >= PROBE_MARKER_RANGE.start
                && PROBE_MARKERS[i] < PROBE_MARKER_RANGE.end
        );
        let mut j = i + 1;
        while j < PROBE_MARKERS.len() {
            assert!(PROBE_MARKERS[i] != PROBE_MARKERS[j]);
            j += 1;
        }
        i += 1;
    }
};

/// Where one of a blob's exits returns: `return_offset` is the offset, from
/// the blob's load address, of the instruction right after the `syscall`
/// that carries `marker`.
///
/// A blob declares one site per marker it uses, and only the sites it
/// contains: a declared site that does not follow a `syscall` refuses the
/// blob before it runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitSite {
    /// [`PROBE_MARKER_FORCE`], [`PROBE_MARKER_SIG`] or [`PROBE_MARKER_DONE`].
    pub marker: u32,
    /// From the blob's own symbol offsets.
    pub return_offset: u64,
}

/// `syscall`.
const SYSCALL_INSTRUCTION: [u8; 2] = [0x0f, 0x05];

/// Checks a blob's exit-site table before anything is installed: each marker
/// is a probe marker, declared once, and its return offset follows a
/// `syscall` inside the blob.
pub(crate) fn check_exit_sites(blob: &[u8], sites: &[ExitSite]) -> Result<()> {
    for (index, site) in sites.iter().enumerate() {
        if !PROBE_MARKERS.contains(&site.marker) {
            return Err(exit_site_error(format!(
                "marker {:#x} is not a probe marker",
                site.marker
            )));
        }
        if sites[..index]
            .iter()
            .any(|other| other.marker == site.marker)
        {
            return Err(exit_site_error(format!(
                "marker {:#x} is declared twice",
                site.marker
            )));
        }
        let end = usize::try_from(site.return_offset).ok();
        let before = end
            .and_then(|end| {
                end.checked_sub(SYSCALL_INSTRUCTION.len())
                    .map(|start| (start, end))
            })
            .and_then(|(start, end)| blob.get(start..end));
        if before != Some(&SYSCALL_INSTRUCTION[..]) {
            return Err(exit_site_error(format!(
                "marker {:#x}: offset {:#x} does not follow a syscall in the {}-byte blob",
                site.marker,
                site.return_offset,
                blob.len()
            )));
        }
    }
    Ok(())
}

fn exit_site_error(message: String) -> Error {
    Error::UnexpectedVcpuExit(format!("exit-site table: {message}"))
}

/// The root vCPU's syscall trampoline and frame (reverie-kvm-core's layout),
/// which the pinned forms below assume.
const PINNED_TRAMPOLINE_ADDRESS: u64 = 0x5000;
const PINNED_FRAME_ADDRESS: u64 = 0x6000;

/// The offset of the hypercall instruction in the trampoline.
const TRAMPOLINE_HYPERCALL_OFFSET: usize = 108;

/// VMMCALL and VMCALL.
const VMMCALL: [u8; 3] = [0x0f, 0x01, 0xd9];
const VMCALL: [u8; 3] = [0x0f, 0x01, 0xc1];

/// The trampoline reverie-kvm-core installs at 0x5000 for the frame at
/// 0x6000, transcribed from its emitter (`syscall_trampoline`). It is checked
/// against the installed bytes before every run because it executes inside
/// the windows the probe measures: its integer-only instructions are what
/// keeps it from changing FPU state. A change to it needs a review of that
/// argument before these arrays change.
const PINNED_TRAMPOLINE_VMMCALL: [u8; 242] = [
    0x48, 0x89, 0x04, 0x25, 0x00, 0x60, 0x00, 0x00, 0x48, 0x89, 0x3c, 0x25, 0x08, 0x60, 0x00, 0x00,
    0x48, 0x89, 0x34, 0x25, 0x10, 0x60, 0x00, 0x00, 0x48, 0x89, 0x14, 0x25, 0x18, 0x60, 0x00, 0x00,
    0x4c, 0x89, 0x14, 0x25, 0x20, 0x60, 0x00, 0x00, 0x4c, 0x89, 0x04, 0x25, 0x28, 0x60, 0x00, 0x00,
    0x4c, 0x89, 0x0c, 0x25, 0x30, 0x60, 0x00, 0x00, 0x48, 0x89, 0x0c, 0x25, 0x40, 0x60, 0x00, 0x00,
    0x4c, 0x89, 0x1c, 0x25, 0x48, 0x60, 0x00, 0x00, 0x48, 0x89, 0x1c, 0x25, 0x50, 0x60, 0x00, 0x00,
    0x48, 0xc7, 0xc0, 0x0c, 0x00, 0x00, 0x00, 0x48, 0xbb, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x31, 0xf6, 0x0f, 0x01, 0xd9, 0x48,
    0x8b, 0x04, 0x25, 0x38, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x3c, 0x25, 0x08, 0x60, 0x00, 0x00, 0x48,
    0x8b, 0x34, 0x25, 0x10, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x14, 0x25, 0x18, 0x60, 0x00, 0x00, 0x4c,
    0x8b, 0x14, 0x25, 0x20, 0x60, 0x00, 0x00, 0x4c, 0x8b, 0x04, 0x25, 0x28, 0x60, 0x00, 0x00, 0x4c,
    0x8b, 0x0c, 0x25, 0x30, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x0c, 0x25, 0x40, 0x60, 0x00, 0x00, 0x4c,
    0x8b, 0x1c, 0x25, 0x48, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x1c, 0x25, 0x50, 0x60, 0x00, 0x00, 0x48,
    0x83, 0x3c, 0x25, 0x58, 0x60, 0x00, 0x00, 0x00, 0x75, 0x03, 0x48, 0x0f, 0x07, 0x48, 0xc7, 0x04,
    0x25, 0x58, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x0c, 0x25, 0x60, 0x60, 0x00,
    0x00, 0x4c, 0x8b, 0x1c, 0x25, 0x68, 0x60, 0x00, 0x00, 0x48, 0xc7, 0xc4, 0x70, 0x60, 0x00, 0x00,
    0x48, 0xcf,
];

/// [`PINNED_TRAMPOLINE_VMMCALL`] with VMCALL at the hypercall offset.
const PINNED_TRAMPOLINE_VMCALL: [u8; 242] = [
    0x48, 0x89, 0x04, 0x25, 0x00, 0x60, 0x00, 0x00, 0x48, 0x89, 0x3c, 0x25, 0x08, 0x60, 0x00, 0x00,
    0x48, 0x89, 0x34, 0x25, 0x10, 0x60, 0x00, 0x00, 0x48, 0x89, 0x14, 0x25, 0x18, 0x60, 0x00, 0x00,
    0x4c, 0x89, 0x14, 0x25, 0x20, 0x60, 0x00, 0x00, 0x4c, 0x89, 0x04, 0x25, 0x28, 0x60, 0x00, 0x00,
    0x4c, 0x89, 0x0c, 0x25, 0x30, 0x60, 0x00, 0x00, 0x48, 0x89, 0x0c, 0x25, 0x40, 0x60, 0x00, 0x00,
    0x4c, 0x89, 0x1c, 0x25, 0x48, 0x60, 0x00, 0x00, 0x48, 0x89, 0x1c, 0x25, 0x50, 0x60, 0x00, 0x00,
    0x48, 0xc7, 0xc0, 0x0c, 0x00, 0x00, 0x00, 0x48, 0xbb, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x31, 0xf6, 0x0f, 0x01, 0xc1, 0x48,
    0x8b, 0x04, 0x25, 0x38, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x3c, 0x25, 0x08, 0x60, 0x00, 0x00, 0x48,
    0x8b, 0x34, 0x25, 0x10, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x14, 0x25, 0x18, 0x60, 0x00, 0x00, 0x4c,
    0x8b, 0x14, 0x25, 0x20, 0x60, 0x00, 0x00, 0x4c, 0x8b, 0x04, 0x25, 0x28, 0x60, 0x00, 0x00, 0x4c,
    0x8b, 0x0c, 0x25, 0x30, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x0c, 0x25, 0x40, 0x60, 0x00, 0x00, 0x4c,
    0x8b, 0x1c, 0x25, 0x48, 0x60, 0x00, 0x00, 0x48, 0x8b, 0x1c, 0x25, 0x50, 0x60, 0x00, 0x00, 0x48,
    0x83, 0x3c, 0x25, 0x58, 0x60, 0x00, 0x00, 0x00, 0x75, 0x03, 0x48, 0x0f, 0x07, 0x48, 0xc7, 0x04,
    0x25, 0x58, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x0c, 0x25, 0x60, 0x60, 0x00,
    0x00, 0x4c, 0x8b, 0x1c, 0x25, 0x68, 0x60, 0x00, 0x00, 0x48, 0xc7, 0xc4, 0x70, 0x60, 0x00, 0x00,
    0x48, 0xcf,
];

/// The pinned trampoline for a hypercall instruction, or `None` for an
/// instruction the backend never chooses.
pub(crate) fn pinned_trampoline(hypercall_instruction: [u8; 3]) -> Option<&'static [u8]> {
    match hypercall_instruction {
        VMMCALL => Some(&PINNED_TRAMPOLINE_VMMCALL),
        VMCALL => Some(&PINNED_TRAMPOLINE_VMCALL),
        _ => None,
    }
}

/// How the installed syscall entry compared with what the probe relies on,
/// read before the first `KVM_RUN`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrampolineCheck {
    /// LSTAR, EFER.SCE, the trampoline and frame addresses and the installed
    /// bytes are as pinned.
    Pinned,
    /// LSTAR is not the pinned trampoline address.
    Lstar(u64),
    /// EFER.SCE is clear, so `syscall` would raise #UD.
    SyscallDisabled,
    /// The backend's trampoline or frame address is not the pinned one.
    Layout {
        /// The backend's trampoline address.
        trampoline: u64,
        /// The backend's frame address.
        frame: u64,
    },
    /// The installed trampoline differs from the pinned form at this byte, or
    /// the backend's hypercall instruction has no pinned form (byte 108, the
    /// hypercall offset).
    Bytes(usize),
}

/// Compares the installed syscall entry with the pinned one. Pure, so the
/// refusal of each part is testable without KVM.
pub(crate) fn check_trampoline(
    lstar: u64,
    efer: u64,
    trampoline_address: u64,
    frame_address: u64,
    hypercall_instruction: [u8; 3],
    installed: &[u8],
) -> TrampolineCheck {
    const EFER_SCE: u64 = 1;
    if trampoline_address != PINNED_TRAMPOLINE_ADDRESS || frame_address != PINNED_FRAME_ADDRESS {
        return TrampolineCheck::Layout {
            trampoline: trampoline_address,
            frame: frame_address,
        };
    }
    if lstar != PINNED_TRAMPOLINE_ADDRESS {
        return TrampolineCheck::Lstar(lstar);
    }
    if efer & EFER_SCE == 0 {
        return TrampolineCheck::SyscallDisabled;
    }
    let Some(pinned) = pinned_trampoline(hypercall_instruction) else {
        return TrampolineCheck::Bytes(TRAMPOLINE_HYPERCALL_OFFSET);
    };
    match pinned
        .iter()
        .zip(installed)
        .position(|(want, got)| want != got)
    {
        Some(byte) => TrampolineCheck::Bytes(byte),
        None if installed.len() != pinned.len() => {
            TrampolineCheck::Bytes(installed.len().min(pinned.len()))
        }
        None => TrampolineCheck::Pinned,
    }
}

/// The frame words the identity reads (reverie-kvm-core's syscall frame).
const FRAME_MARKER_WORD: usize = 0;
const FRAME_RETURN_RIP_WORD: usize = 8;
const FRAME_FULL_RETURN_WORD: usize = 11;
/// The frame word the trampoline loads into RAX on return.
pub(crate) const FRAME_RESULT_WORD: usize = 7;
/// Words 0 through 11.
pub(crate) const FRAME_IDENTITY_WORDS: usize = 12;

/// `KVM_HC_MAP_GPA_RANGE`, the one hypercall the backend exits to user space
/// for, and `KVM_EXIT_HYPERCALL_LONG_MODE`.
const MAP_GPA_RANGE: u64 = 12;
const HYPERCALL_LONG_MODE: u32 = 1;

/// What a `KVM_EXIT_HYPERCALL` reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HypercallExit {
    pub(crate) nr: u64,
    pub(crate) args: [u64; 3],
    pub(crate) flags: u32,
}

/// Which item of the exit identity failed. Each is an exit-identity mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMismatch {
    /// The hypercall number is not 12.
    Number(u64),
    /// args[0] is not the backend's frame address.
    Frame(u64),
    /// args[1] is not 1 or args[2] is not 0.
    Arguments(u64, u64),
    /// The exit was not taken in 64-bit mode.
    NotLongMode,
    /// Frame word 0 is not the marker this step expects.
    Marker {
        /// The marker the step expects.
        expected: u32,
        /// All 64 bits of word 0.
        observed: u64,
    },
    /// The return RIP is not the expected site.
    ReturnRip {
        /// The blob's load address plus the declared offset.
        expected: u64,
        /// Frame word 8.
        observed: u64,
    },
    /// The marker has no declared site in this blob.
    NoSite(u32),
    /// The trampoline was told to return by IRETQ.
    FullReturn(u64),
    /// A hypercall exit ended a run that must not end at one; frame word 0.
    NotExpected(u64),
}

/// The identity of one trampoline exit, as the runner records it: frame word
/// 0 and the return RIP, in place of the vCPU's RIP, which is the trampoline's
/// for every such exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrampolineExit {
    /// All 64 bits of frame word 0.
    pub(crate) marker: u64,
    /// Frame word 8: the address after the blob's `syscall`.
    pub(crate) return_rip: u64,
}

/// Checks a hypercall exit against the identity of the trampoline exit that
/// carries `expected`. `frame` is words 0 through 11 of the backend's frame.
pub(crate) fn identify_trampoline_exit(
    exit: HypercallExit,
    frame_address: u64,
    frame: &[u64; FRAME_IDENTITY_WORDS],
    expected: u32,
    load_address: u64,
    sites: &[ExitSite],
) -> std::result::Result<TrampolineExit, IdentityMismatch> {
    if exit.nr != MAP_GPA_RANGE {
        return Err(IdentityMismatch::Number(exit.nr));
    }
    if exit.args[0] != frame_address {
        return Err(IdentityMismatch::Frame(exit.args[0]));
    }
    if exit.args[1] != 1 || exit.args[2] != 0 {
        return Err(IdentityMismatch::Arguments(exit.args[1], exit.args[2]));
    }
    if exit.flags & HYPERCALL_LONG_MODE == 0 {
        return Err(IdentityMismatch::NotLongMode);
    }
    let marker = frame[FRAME_MARKER_WORD];
    if marker != u64::from(expected) {
        return Err(IdentityMismatch::Marker {
            expected,
            observed: marker,
        });
    }
    let site = sites
        .iter()
        .find(|site| site.marker == expected)
        .ok_or(IdentityMismatch::NoSite(expected))?;
    let return_rip = frame[FRAME_RETURN_RIP_WORD];
    let wanted = load_address.wrapping_add(site.return_offset);
    if return_rip != wanted {
        return Err(IdentityMismatch::ReturnRip {
            expected: wanted,
            observed: return_rip,
        });
    }
    if frame[FRAME_FULL_RETURN_WORD] != 0 {
        return Err(IdentityMismatch::FullReturn(frame[FRAME_FULL_RETURN_WORD]));
    }
    Ok(TrampolineExit { marker, return_rip })
}

/// One CPUID leaf's registers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CpuidWords {
    pub(crate) eax: u32,
    pub(crate) ebx: u32,
    pub(crate) ecx: u32,
    pub(crate) edx: u32,
}

/// The host facts a qualification keys on, read on the host (not in the
/// guest) when the runner is built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerFacts {
    /// CPUID leaf 0's vendor string, EBX, EDX, ECX.
    pub vendor: [u8; 12],
    /// The displayed family, model and stepping of CPUID leaf 1.
    pub family: u32,
    /// See `family`.
    pub model: u32,
    /// See `family`.
    pub stepping: u32,
    /// The host's XCR0, by XGETBV(0) on the host.
    pub host_xcr0: u64,
    /// The instruction the backend's trampoline issues: VMCALL or VMMCALL.
    pub hypercall_instruction: [u8; 3],
    /// What the backend left in the vCPU's IA32_XSS, and its read-back.
    pub xss: XssOutcome,
    /// CPUID.1:ECX: XSAVE (bit 26), OSXSAVE (27) and the hypervisor bit (31).
    pub cpuid_1_ecx: u32,
    /// CPUID.(EAX=0DH,ECX=1):EAX: XSAVEOPT (bit 0), XSAVEC (1), XGETBV(1) (2).
    pub cpuid_d_1_eax: u32,
    /// CPUID.(EAX=7,ECX=0):EBX, for the x87 pointer rules (bits 6 and 13).
    pub cpuid_7_0_ebx: u32,
    /// CPUID.80000008H:EBX, for XSAVEERPTR (bit 2) on AMD.
    pub cpuid_8000_0008_ebx: u32,
    /// CPUID.1:ECX[31]: the host itself runs under a hypervisor.
    pub hypervisor: bool,
    /// /sys/kernel/sched_ext/state. A sched_ext scheduler in full-switch mode
    /// schedules SCHED_OTHER threads without changing what
    /// `sched_getscheduler` reports, so P7's class allowlist cannot see it.
    pub sched_ext: SchedExt,
}

/// The state of the host's extensible scheduler class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SchedExt {
    /// The kernel has no sched_ext (no /sys/kernel/sched_ext/state).
    Absent,
    /// The state file reads "disabled".
    Disabled,
    /// The state file reads anything else ("enabled", "enabling", ...).
    NotDisabled,
}

impl SchedExt {
    /// Decodes the state file's contents; `None` is a missing file.
    pub(crate) fn from_state(contents: Option<&str>) -> Self {
        match contents.map(str::trim) {
            None => Self::Absent,
            Some("disabled") => Self::Disabled,
            Some(_) => Self::NotDisabled,
        }
    }

    fn of_host() -> Result<Self> {
        match std::fs::read_to_string("/sys/kernel/sched_ext/state") {
            Ok(contents) => Ok(Self::from_state(Some(&contents))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::Absent),
            Err(error) => Err(Error::HostIo(error)),
        }
    }
}

impl RunnerFacts {
    /// Builds the facts from a CPUID source, so the decoding is testable
    /// without the host's own CPUID.
    pub(crate) fn from_cpuid(
        cpuid: impl Fn(u32, u32) -> CpuidWords,
        host_xcr0: u64,
        hypercall_instruction: [u8; 3],
        xss: XssOutcome,
        sched_ext: SchedExt,
    ) -> Self {
        let leaf0 = cpuid(0, 0);
        let mut vendor = [0; 12];
        vendor[..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
        vendor[8..].copy_from_slice(&leaf0.ecx.to_le_bytes());
        let leaf1 = cpuid(1, 0);
        let base_family = (leaf1.eax >> 8) & 0xf;
        let base_model = (leaf1.eax >> 4) & 0xf;
        let family = if base_family == 0xf {
            base_family + ((leaf1.eax >> 20) & 0xff)
        } else {
            base_family
        };
        let model = if base_family == 0x6 || base_family == 0xf {
            base_model | (((leaf1.eax >> 16) & 0xf) << 4)
        } else {
            base_model
        };
        let extended_max = cpuid(0x8000_0000, 0).eax;
        Self {
            vendor,
            family,
            model,
            stepping: leaf1.eax & 0xf,
            host_xcr0,
            hypercall_instruction,
            xss,
            cpuid_1_ecx: leaf1.ecx,
            cpuid_d_1_eax: if leaf0.eax >= 0xd {
                cpuid(0xd, 1).eax
            } else {
                0
            },
            cpuid_7_0_ebx: if leaf0.eax >= 0x7 { cpuid(7, 0).ebx } else { 0 },
            cpuid_8000_0008_ebx: if extended_max >= 0x8000_0008 {
                cpuid(0x8000_0008, 0).ebx
            } else {
                0
            },
            hypervisor: leaf1.ecx & (1 << 31) != 0,
            sched_ext,
        }
    }
}

/// The host's CPUID.
fn host_cpuid(leaf: u32, subleaf: u32) -> CpuidWords {
    let result = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    CpuidWords {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

/// The host's XCR0, or an error when the OS has not enabled XSAVE.
fn host_xcr0() -> Result<u64> {
    const OSXSAVE: u32 = 1 << 27;
    if host_cpuid(1, 0).ecx & OSXSAVE == 0 {
        return Err(Error::UnsupportedHost(
            "the host OS has not enabled XSAVE (CPUID.1:ECX.OSXSAVE is clear)".to_string(),
        ));
    }
    // SAFETY: CPUID.1:ECX.OSXSAVE is set, so XGETBV is enabled at CPL3 and
    // XCR0 (index 0) always exists.
    Ok(unsafe { core::arch::x86_64::_xgetbv(0) })
}

/// IA32_LSTAR, the 64-bit `syscall` entry point.
const MSR_LSTAR: u32 = 0xc000_0082;

/// The probe VM's memory. `configure_long_mode` needs more than
/// reverie-kvm-core's boot area (`BOOT_RESERVED_END`, 0x1ff000); the blob, its
/// context page and its stack sit above it, inside the identity map, which
/// ends at the memory size.
const PROBE_MEMORY_SIZE: usize = 4 << 20;

/// Where the runner puts the blob, its context page and its stack, all above
/// reverie-kvm-core's boot area (`BOOT_RESERVED_END`, 0x1ff000).
const DEFAULT_LOAD_ADDRESS: u64 = 0x20_0000;

/// A configured probe VM: the backend after `configure_long_mode`, with the
/// blob installed and the syscall entry checked, before its first `KVM_RUN`.
pub(crate) struct ProbeVm {
    pub(crate) backend: crate::KvmBackend,
    pub(crate) stats: VcpuStats,
    pub(crate) facts: RunnerFacts,
    pub(crate) load_address: u64,
    pub(crate) sites: Vec<ExitSite>,
    /// The caller's context size, read back whole after a trial.
    pub(crate) context_len: usize,
    /// The syscall entry against its pinned form (r7-1a §3).
    pub(crate) trampoline: TrampolineCheck,
    /// CS's selector and SS's DPL before the first `KVM_RUN`: sampling point
    /// (a) of the CPL3 invariant (r7-1a §2).
    pub(crate) initial_cs_selector: u16,
    pub(crate) initial_ss_dpl: u8,
}

impl ProbeVm {
    /// Builds the VM: `KvmBackend::new`, then `configure_long_mode` with the
    /// blob's entry and stack and the backend's own hypercall instruction (as
    /// `from_process_snapshot` does), then the blob and the read-backs. Every
    /// read-back happens before the first read point, and none touches an
    /// xstate-managed MSR.
    pub(crate) fn new(
        blob: &[u8],
        entry_offset: u64,
        context: &[u8],
        stack_top: u64,
        sites: &[ExitSite],
    ) -> Result<Self> {
        check_exit_sites(blob, sites)?;
        let load_address = DEFAULT_LOAD_ADDRESS;
        let context_end = CONTEXT_ADDRESS + CONTEXT_MAX_SIZE as u64;
        let fits = load_address
            .checked_add(blob.len() as u64)
            .is_some_and(|end| end <= CONTEXT_ADDRESS)
            && (CONTEXT_DATA_OFFSET as usize..=CONTEXT_MAX_SIZE).contains(&context.len())
            && context_end < stack_top
            && stack_top <= PROBE_MEMORY_SIZE as u64;
        if !fits {
            return Err(Error::UnsupportedHost(format!(
                "a {}-byte blob at {load_address:#x}, a {}-byte context at \
                 {CONTEXT_ADDRESS:#x} and a stack at {stack_top:#x} do not fit the \
                 {PROBE_MEMORY_SIZE:#x}-byte probe VM",
                blob.len(),
                context.len()
            )));
        }
        if entry_offset >= blob.len() as u64 {
            return Err(Error::UnsupportedHost(format!(
                "entry offset {entry_offset:#x} is outside the {}-byte blob",
                blob.len()
            )));
        }
        let mut backend = crate::KvmBackend::new(PROBE_MEMORY_SIZE)?;
        let instruction = backend.hypercall_instruction();
        reverie_kvm_core::bootstrap::configure_long_mode(
            &mut backend.memory,
            &backend.vcpu,
            load_address + entry_offset,
            stack_top,
            instruction,
        )?;
        backend.memory.write_raw(load_address, blob)?;
        backend.memory.write_raw(CONTEXT_ADDRESS, context)?;
        backend
            .memory
            .write_raw(CONTEXT_ADDRESS, &[0; CONTEXT_DATA_OFFSET as usize])?;
        // The blob's entry receives the context's address in RDI.
        let mut regs = backend.vcpu.get_regs()?;
        regs.rdi = CONTEXT_ADDRESS;
        backend.vcpu.set_regs(&regs)?;

        let sregs = backend.vcpu.get_sregs()?;
        let mut msrs = kvm_bindings::Msrs::from_entries(&[kvm_bindings::kvm_msr_entry {
            index: MSR_LSTAR,
            ..Default::default()
        }])
        .expect("one MSR fits");
        let read = backend.vcpu.get_msrs(&mut msrs)?;
        if read != 1 {
            return Err(Error::UnexpectedVcpuExit(format!(
                "KVM_GET_MSRS returned {read} of 1 LSTAR reads"
            )));
        }
        let lstar = msrs.as_slice()[0].data;
        let trampoline_address = backend.syscall_trampoline_address();
        let mut installed = [0; PINNED_TRAMPOLINE_VMMCALL.len()];
        backend
            .memory
            .read_raw(trampoline_address, &mut installed)?;
        let trampoline = check_trampoline(
            lstar,
            sregs.efer,
            trampoline_address,
            backend.syscall_frame_address,
            instruction,
            &installed,
        );

        let xss = XssOutcome {
            kind: XssOutcomeKind::from_outcome(backend.xss_outcome()),
            read_back: crate::host_xss::read_xss(&backend.vcpu)?,
        };
        let facts = RunnerFacts::from_cpuid(
            host_cpuid,
            host_xcr0()?,
            instruction,
            xss,
            SchedExt::of_host()?,
        );
        let stats = VcpuStats::open(&backend.vcpu)?;
        Ok(Self {
            backend,
            stats,
            facts,
            load_address,
            sites: sites.to_vec(),
            context_len: context.len(),
            trampoline,
            initial_cs_selector: sregs.cs.selector,
            initial_ss_dpl: sregs.ss.dpl,
        })
    }

    /// Words 0 through 11 of the backend's syscall frame.
    pub(crate) fn frame_identity_words(&self) -> Result<[u64; FRAME_IDENTITY_WORDS]> {
        let mut bytes = [0; FRAME_IDENTITY_WORDS * 8];
        self.backend
            .memory
            .read_raw(self.backend.syscall_frame_address, &mut bytes)?;
        let mut words = [0; FRAME_IDENTITY_WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        }
        Ok(words)
    }

    /// The whole context, as the guest left it.
    pub(crate) fn read_context(&self) -> Result<Vec<u8>> {
        let mut context = vec![0; self.context_len];
        self.backend
            .memory
            .read_raw(CONTEXT_ADDRESS, &mut context)?;
        Ok(context)
    }

    /// A control word of the context, for a helper thread.
    pub(crate) fn context_word(&self, offset: u64) -> ContextWord {
        ContextWord::of(&self.backend.memory, offset)
    }

    /// Writes the result the trampoline loads into RAX when it returns.
    pub(crate) fn write_result(&self, result: u64) -> Result<()> {
        self.backend.memory.write_raw(
            self.backend.syscall_frame_address + (FRAME_RESULT_WORD * 8) as u64,
            &result.to_le_bytes(),
        )
    }
}

/// A thread's context switches, from /proc/self/task/<tid>/status (`T`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ThreadSwitches {
    pub(crate) voluntary: u64,
    pub(crate) nonvoluntary: u64,
}

/// Reads `voluntary_ctxt_switches` and `nonvoluntary_ctxt_switches`, each of
/// which must appear exactly once.
pub(crate) fn parse_switches(status: &str) -> Result<ThreadSwitches> {
    let field = |name: &str| -> Result<u64> {
        let mut values = status.lines().filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name).then(|| value.trim())
        });
        match (values.next(), values.next()) {
            (Some(value), None) => value.parse().map_err(|_| {
                Error::UnexpectedVcpuExit(format!("thread status: {name} is {value:?}"))
            }),
            (None, _) => Err(Error::UnexpectedVcpuExit(format!(
                "thread status: no {name}"
            ))),
            (Some(_), Some(_)) => Err(Error::UnexpectedVcpuExit(format!(
                "thread status: {name} appears twice"
            ))),
        }
    };
    Ok(ThreadSwitches {
        voluntary: field("voluntary_ctxt_switches")?,
        nonvoluntary: field("nonvoluntary_ctxt_switches")?,
    })
}

/// `T` for a thread of this process; any thread may read it.
pub(crate) fn read_switches(tid: libc::pid_t) -> Result<ThreadSwitches> {
    parse_switches(&std::fs::read_to_string(format!(
        "/proc/self/task/{tid}/status"
    ))?)
}

/// This thread's Linux task ID.
pub(crate) fn current_tid() -> libc::pid_t {
    // SAFETY: gettid has no pointer arguments and returns this Linux task ID.
    unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
}

/// `C`: the CPU this thread runs on.
pub(crate) fn current_cpu() -> Result<u32> {
    // SAFETY: sched_getcpu has no arguments.
    let cpu = unsafe { libc::sched_getcpu() };
    u32::try_from(cpu).map_err(|_| Error::HostIo(io::Error::last_os_error()))
}

/// S, T and C, read together on the vCPU thread.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReadPoint {
    pub(crate) stats: VcpuStatsSnapshot,
    pub(crate) switches: ThreadSwitches,
    pub(crate) cpu: u32,
}

impl ReadPoint {
    pub(crate) fn take(stats: &VcpuStats, tid: libc::pid_t) -> Result<Self> {
        Ok(Self {
            stats: stats.snapshot()?,
            switches: read_switches(tid)?,
            cpu: current_cpu()?,
        })
    }
}

/// How one `KVM_RUN` ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunEnd {
    /// A trampoline exit with the expected identity.
    Trampoline(TrampolineExit),
    /// A hypercall exit that failed the identity.
    Mismatch(IdentityMismatch),
    /// A HLT exit at this RIP: an exception stub's, or any other HLT.
    Halt(u64),
    /// KVM_RUN returned -1 with this errno. The exit reason is not read.
    Failed(i32),
    /// Admission was closed: no KVM_RUN was issued.
    NotAdmitted,
    /// Any other exit; the runner decodes it no further.
    Other,
}

/// One `KVM_RUN` and its read points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RunRecord {
    pub(crate) before: ReadPoint,
    pub(crate) after: ReadPoint,
    pub(crate) end: RunEnd,
}

impl ProbeVm {
    /// Issues one `KVM_RUN` on this thread, bracketed by read points.
    /// `expected` is the marker a trampoline exit of this run must carry;
    /// `None` means the run must not end at a hypercall exit at all.
    pub(crate) fn step(&mut self, tid: libc::pid_t, expected: Option<u32>) -> Result<RunRecord> {
        let before = ReadPoint::take(&self.stats, tid)?;
        // Copy what the exit reported first, so the exit's borrow of the vCPU
        // ends before the frame or the registers are read.
        enum Raw {
            NotAdmitted,
            Hypercall(HypercallExit),
            Halt,
            Failed(i32),
            Other,
        }
        let raw = match self.backend.vcpu.run() {
            Ok(None) => Raw::NotAdmitted,
            Ok(Some(kvm_ioctls::VcpuExit::Hypercall(exit))) => Raw::Hypercall(HypercallExit {
                nr: exit.nr,
                args: [exit.args[0], exit.args[1], exit.args[2]],
                flags: exit.longmode,
            }),
            Ok(Some(kvm_ioctls::VcpuExit::Hlt)) => Raw::Halt,
            Ok(Some(_)) => Raw::Other,
            Err(Error::Kvm(error)) => Raw::Failed(error.errno()),
            Err(error) => return Err(error),
        };
        let end = match raw {
            Raw::NotAdmitted => RunEnd::NotAdmitted,
            Raw::Hypercall(exit) => {
                let frame = self.frame_identity_words()?;
                let identity = match expected {
                    Some(expected) => identify_trampoline_exit(
                        exit,
                        self.backend.syscall_frame_address,
                        &frame,
                        expected,
                        self.load_address,
                        &self.sites,
                    ),
                    None => Err(IdentityMismatch::NotExpected(frame[FRAME_MARKER_WORD])),
                };
                match identity {
                    Ok(identity) => RunEnd::Trampoline(identity),
                    Err(mismatch) => RunEnd::Mismatch(mismatch),
                }
            }
            Raw::Halt => RunEnd::Halt(self.backend.vcpu.get_regs()?.rip),
            Raw::Failed(errno) => RunEnd::Failed(errno),
            Raw::Other => RunEnd::Other,
        };
        let after = ReadPoint::take(&self.stats, tid)?;
        Ok(RunRecord { before, after, end })
    }

    /// P6's `immediate_exit` run, bracketed by read points.
    pub(crate) fn step_immediate_exit(&mut self, tid: libc::pid_t) -> Result<RunRecord> {
        let before = ReadPoint::take(&self.stats, tid)?;
        let end = match self.backend.vcpu.run_with_immediate_exit()? {
            None => RunEnd::NotAdmitted,
            Some(crate::clock::ImmediateExitRun::Failed(error)) => RunEnd::Failed(error.errno()),
            Some(crate::clock::ImmediateExitRun::Returned) => RunEnd::Other,
        };
        let after = ReadPoint::take(&self.stats, tid)?;
        Ok(RunRecord { before, after, end })
    }
}

/// The guest address of the context page block the runner installs for the
/// blob. The blob's entry receives it in RDI.
pub const CONTEXT_ADDRESS: u64 = 0x30_0000;
/// The context's largest size.
pub const CONTEXT_MAX_SIZE: usize = 64 << 10;
/// The context word the blob sets nonzero right after its reference save,
/// before it spins (a `u64`).
pub const CONTEXT_MARKER_OFFSET: u64 = 0x00;
/// The context word the host sets to 1 to end the blob's spin (a `u64`).
pub const CONTEXT_FLAG_OFFSET: u64 = 0x08;
/// The context word the blob increments on each spin iteration (a `u64`).
pub const CONTEXT_SPIN_OFFSET: u64 = 0x10;
/// The first context byte the caller's blob may use freely.
pub const CONTEXT_DATA_OFFSET: u64 = 0x40;

/// One control word of the context, read or written by a helper thread while
/// the guest may run. The address stays valid while the backend's guest
/// memory mapping lives; every helper is joined before the backend can drop.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ContextWord(usize);

impl ContextWord {
    pub(crate) fn of(memory: &crate::GuestMemory, offset: u64) -> Self {
        let address = memory.host_address() + CONTEXT_ADDRESS - memory.guest_base() + offset;
        Self(address as usize)
    }

    pub(crate) fn load(self) -> u64 {
        // SAFETY: an 8-byte-aligned word of the live guest mapping (see the
        // type). The guest's own stores to it are plain aligned stores, which
        // an aligned atomic load observes whole.
        unsafe { std::sync::atomic::AtomicU64::from_ptr(self.0 as *mut u64) }
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn store(self, value: u64) {
        // SAFETY: as for `load`.
        unsafe { std::sync::atomic::AtomicU64::from_ptr(self.0 as *mut u64) }
            .store(value, std::sync::atomic::Ordering::Release);
    }
}

/// What P5's kicker saw and did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct KickRecord {
    /// The guest's marker was seen before the deadline.
    pub(crate) marker_seen: bool,
    /// S0 and T0, read by the kicker after the marker and before the kick.
    pub(crate) s0: VcpuStatsSnapshot,
    pub(crate) t0: ThreadSwitches,
    /// The spin counter when the kick was sent.
    pub(crate) spin_at_kick: u64,
}

/// P5's kicker, on its own thread: wait for the marker, read S0 and T0, kick
/// the vCPU through the entry gate (`try_close`, which signals every running
/// member), wait until the vCPU has left `KVM_RUN` and stopped, set the flag,
/// and reopen admission. With no marker by `deadline`, it kicks anyway, so
/// the vCPU thread never waits forever, and reports `marker_seen = false`.
pub(crate) fn spawn_kicker(
    gate: std::sync::Arc<reverie_kvm_core::entry::EntryGate>,
    stats: VcpuStats,
    vcpu_tid: libc::pid_t,
    marker: ContextWord,
    flag: ContextWord,
    spin: ContextWord,
    deadline: std::time::Instant,
) -> Result<std::thread::JoinHandle<Result<KickRecord>>> {
    note_helper_spawn();
    let handle = crate::supervisor_thread::builder()
        .name("guest-probe-kicker".into())
        .spawn(move || {
            let mut record = KickRecord::default();
            while marker.load() == 0 && std::time::Instant::now() < deadline {
                std::hint::spin_loop();
            }
            record.marker_seen = marker.load() != 0;
            // The kick, the flag and the reopening happen even if a read
            // fails, so the vCPU thread's run always ends.
            let observed = stats.snapshot().and_then(|s0| {
                record.s0 = s0;
                record.t0 = read_switches(vcpu_tid)?;
                Ok(())
            });
            record.spin_at_kick = spin.load();
            // On a failed kick the flag still ends the guest's spin, so the
            // run ends (at a hypercall exit the trial then rejects).
            let attempt = gate.try_close().map_err(|failure| failure.error());
            let closing = match attempt {
                Ok(reverie_kvm_core::entry::CloseAttempt::Closing(closing)) => closing,
                Ok(reverie_kvm_core::entry::CloseAttempt::NotOpen) => {
                    flag.store(1);
                    return Err(Error::UnexpectedVcpuExit(
                        "the probe's kick found admission not open".to_string(),
                    ));
                }
                Ok(reverie_kvm_core::entry::CloseAttempt::SendFailed(error)) => {
                    flag.store(1);
                    return Err(Error::HostIo(error));
                }
                Err(error) => {
                    flag.store(1);
                    return Err(error);
                }
            };
            let closed =
                futures::executor::block_on(closing.finish()).map_err(|failure| failure.error());
            flag.store(1);
            drop(closed?);
            observed?;
            Ok(record)
        })?;
    Ok(handle)
}

/// A helper thread that is joined when this guard drops, so no helper can
/// outlive the backend whose guest memory it reads, also when the vCPU
/// thread unwinds.
pub(crate) struct JoinOnDrop<T>(Option<std::thread::JoinHandle<T>>);

impl<T> JoinOnDrop<T> {
    pub(crate) fn new(handle: std::thread::JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    /// Joins now; a helper's panic becomes an error.
    pub(crate) fn join(mut self) -> Result<T> {
        let handle = self.0.take().expect("joined once");
        handle
            .join()
            .map_err(|_| Error::UnexpectedVcpuExit("a guest-probe helper thread panicked".into()))
    }
}

impl<T> Drop for JoinOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

/// One step of a path's run sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepKind {
    /// A `KVM_RUN` that must end at the trampoline exit carrying this marker,
    /// or, for `None`, at no hypercall exit.
    Run(Option<u32>),
    /// P6's `immediate_exit` run, which must fail with EINTR.
    ImmediateExit,
}

/// What P5's sequence recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct P5Record {
    pub(crate) runs: Vec<RunRecord>,
    pub(crate) kick: KickRecord,
    /// The spin counter after run 1 returned; it must be greater than 0.
    pub(crate) spin_after_run1: u64,
    /// CS's selector and SS's DPL at run 1's EINTR return, where the vCPU
    /// was interrupted in the blob's CPL3 spin: sampling point (b) of the
    /// CPL3 invariant (r7-1a §2).
    pub(crate) cpl_at_kick: Option<(u16, u8)>,
}

impl ProbeVm {
    /// Runs `steps` in order on this thread, writing the result word (0)
    /// after each trampoline exit. It stops after the first step that did not
    /// end as that step must, so a rejected trial runs no further.
    pub(crate) fn run_sequence(&mut self, steps: &[StepKind]) -> Result<Vec<RunRecord>> {
        let tid = current_tid();
        let mut records = Vec::with_capacity(steps.len());
        for step in steps {
            let record = match *step {
                StepKind::Run(expected) => self.step(tid, expected)?,
                StepKind::ImmediateExit => self.step_immediate_exit(tid)?,
            };
            let as_required = match (step, record.end) {
                (StepKind::Run(Some(_)), RunEnd::Trampoline(_)) => {
                    self.write_result(0)?;
                    true
                }
                (StepKind::ImmediateExit, RunEnd::Failed(errno)) => errno == libc::EINTR,
                _ => false,
            };
            records.push(record);
            if !as_required {
                break;
            }
        }
        Ok(records)
    }

    /// P5 (r7 §3.3): the kicker ends run 1 through the entry gate after the
    /// guest's marker; run 1 must fail with EINTR, and run 2 must end at DONE.
    /// The kicker is joined before run 2 and on every path.
    pub(crate) fn run_p5(&mut self, deadline: std::time::Instant) -> Result<P5Record> {
        let tid = current_tid();
        let kicker = JoinOnDrop::new(spawn_kicker(
            self.backend.memory.entry_gate(),
            self.stats.try_clone()?,
            tid,
            self.context_word(CONTEXT_MARKER_OFFSET),
            self.context_word(CONTEXT_FLAG_OFFSET),
            self.context_word(CONTEXT_SPIN_OFFSET),
            deadline,
        )?);
        let run1 = self.step(tid, None);
        let kick = kicker.join()?;
        let run1 = run1?;
        let kick = kick?;
        let spin_after_run1 = self.context_word(CONTEXT_SPIN_OFFSET).load();
        let mut runs = vec![run1];
        let mut cpl_at_kick = None;
        if run1.end == RunEnd::Failed(libc::EINTR) {
            let sregs = self.backend.vcpu.get_sregs()?;
            cpl_at_kick = Some((sregs.cs.selector, sregs.ss.dpl));
            runs.push(self.step(tid, Some(PROBE_MARKER_DONE))?);
        }
        Ok(P5Record {
            runs,
            kick,
            spin_after_run1,
            cpl_at_kick,
        })
    }
}

/// The instruction P3 or P4 makes the host emulate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Emulated {
    /// P3: CPUID under guest CPUID faulting.
    Cpuid,
    /// P4: RDTSC under CR4.TSD.
    Rdtsc,
}

/// P3 or P4's runs, and the faulting instruction's RIP from the exception
/// frame when run 1 ended at the stub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmulatedRecord {
    pub(crate) runs: Vec<RunRecord>,
    pub(crate) instruction_rip: Option<u64>,
}

impl ProbeVm {
    /// Turns on the interception P3 or P4 needs. Called before the first read
    /// point; neither write touches an xstate-managed MSR.
    pub(crate) fn enable_emulation(&mut self, which: Emulated) -> Result<()> {
        match which {
            Emulated::Cpuid => self.backend.set_cpuid_interception(true),
            Emulated::Rdtsc => self.backend.set_rdtsc_interception(true),
        }
    }

    /// P3 or P4 (r7 §3.2): run 1 must end at the exception stub's HLT exit
    /// for the instruction's #GP. The host then emulates the instruction with
    /// its own CPUID or TSC through the backend's resume path, which continues
    /// after the instruction, and run 2 must end at DONE.
    pub(crate) fn run_emulated(&mut self, which: Emulated) -> Result<EmulatedRecord> {
        use crate::vm::ToolInstructionBoundary;
        use crate::vm::ToolInstructionResult;
        let tid = current_tid();
        let run1 = self.step(tid, None)?;
        let mut record = EmulatedRecord {
            runs: vec![run1],
            instruction_rip: None,
        };
        if !matches!(run1.end, RunEnd::Halt(_)) {
            return Ok(record);
        }
        let rip = match which {
            Emulated::Cpuid => {
                let Some(ToolInstructionBoundary::Cpuid(boundary)) =
                    self.backend.tool_instruction_exception()?
                else {
                    return Ok(record);
                };
                let rip = boundary.registers.rip;
                let answer =
                    host_cpuid(boundary.registers.rax as u32, boundary.registers.rcx as u32);
                self.backend.resume_tool_instruction(
                    ToolInstructionBoundary::Cpuid(boundary),
                    ToolInstructionResult::Cpuid(reverie::CpuIdResult {
                        eax: answer.eax,
                        ebx: answer.ebx,
                        ecx: answer.ecx,
                        edx: answer.edx,
                    }),
                )?;
                rip
            }
            Emulated::Rdtsc => {
                let Some(boundary) = self.backend.timestamp_counter_exception()? else {
                    return Ok(record);
                };
                let rip = boundary.registers.rip;
                // SAFETY: RDTSC has no operands and is unprivileged here.
                let tsc = unsafe { core::arch::x86_64::_rdtsc() };
                self.backend
                    .resume_timestamp_counter(boundary, reverie::RdtscResult { tsc, aux: None })?;
                rip
            }
        };
        record.instruction_rip = Some(rip);
        record.runs.push(self.step(tid, Some(PROBE_MARKER_DONE))?);
        Ok(record)
    }
}

/// This thread's CPU affinity.
pub(crate) fn thread_affinity() -> Result<libc::cpu_set_t> {
    // SAFETY: an all-zero cpu_set_t is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a writable cpu_set_t of the size passed.
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) } < 0 {
        return Err(Error::HostIo(io::Error::last_os_error()));
    }
    Ok(set)
}

#[cfg(test)]
thread_local! {
    /// Test witnesses, per thread: the helper threads this thread spawned and
    /// the affinity writes it made.
    pub(crate) static HELPER_SPAWNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    pub(crate) static AFFINITY_WRITES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Counts a helper spawn for the test witness; nothing outside tests.
fn note_helper_spawn() {
    #[cfg(test)]
    HELPER_SPAWNS.with(|count| count.set(count.get() + 1));
}

/// Sets this thread's CPU affinity.
pub(crate) fn set_thread_affinity(set: &libc::cpu_set_t) -> Result<()> {
    #[cfg(test)]
    AFFINITY_WRITES.with(|count| count.set(count.get() + 1));
    // SAFETY: `set` is a cpu_set_t of the size passed.
    if unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), set) } < 0 {
        return Err(Error::HostIo(io::Error::last_os_error()));
    }
    Ok(())
}

/// The CPUs in `set`, in increasing order.
pub(crate) fn cpus_in(set: &libc::cpu_set_t) -> Vec<u32> {
    (0..libc::CPU_SETSIZE as usize)
        // SAFETY: `cpu` is below CPU_SETSIZE, the set's capacity.
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, set) })
        .map(|cpu| cpu as u32)
        .collect()
}

/// The set holding only `cpu`.
pub(crate) fn only_cpu(cpu: u32) -> libc::cpu_set_t {
    // SAFETY: an all-zero cpu_set_t is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: the caller's CPU came from `cpus_in`, so it is below CPU_SETSIZE.
    unsafe { libc::CPU_SET(cpu as usize, &mut set) };
    set
}

/// Restores this thread's CPU affinity when dropped, on every path.
pub(crate) struct AffinityGuard(libc::cpu_set_t);

impl AffinityGuard {
    pub(crate) fn save() -> Result<Self> {
        thread_affinity().map(Self)
    }

    pub(crate) fn saved(&self) -> &libc::cpu_set_t {
        &self.0
    }
}

impl Drop for AffinityGuard {
    fn drop(&mut self) {
        let _ = set_thread_affinity(&self.0);
    }
}

/// P1-Migrate's runs, and the CPU run 2 was moved to; `None` when the
/// allowed set has no second CPU, which leaves the cell inconclusive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MigrateRecord {
    pub(crate) runs: Vec<RunRecord>,
    pub(crate) target: Option<u32>,
}

impl ProbeVm {
    /// P1-Migrate (r7 §3.3): at FORCE's exit, the vCPU thread moves to
    /// another CPU of its allowed set and stays there for run 2, which must
    /// end at DONE. Run 2's read points record `getcpu` before and after it.
    /// The thread's affinity is restored afterwards on every path.
    pub(crate) fn run_p1_migrate(&mut self) -> Result<MigrateRecord> {
        let tid = current_tid();
        let run1 = self.step(tid, Some(PROBE_MARKER_FORCE))?;
        let mut record = MigrateRecord {
            runs: vec![run1],
            target: None,
        };
        if !matches!(run1.end, RunEnd::Trampoline(_)) {
            return Ok(record);
        }
        self.write_result(0)?;
        let guard = AffinityGuard::save()?;
        let Some(target) = cpus_in(guard.saved())
            .into_iter()
            .find(|&cpu| cpu != run1.after.cpu)
        else {
            return Ok(record);
        };
        set_thread_affinity(&only_cpu(target))?;
        record.target = Some(target);
        record.runs.push(self.step(tid, Some(PROBE_MARKER_DONE))?);
        drop(guard);
        Ok(record)
    }
}

/// Patches the frame consumer applies to the signal-frame image of the
/// vCPU's XSAVE state before it decodes the image again: each is a byte
/// offset into the frame image and the bytes written there.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FrameEdit {
    /// (offset, bytes), applied in order.
    pub patches: Vec<(usize, Vec<u8>)>,
}

/// What the frame consumer read, produced and installed at an exit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrameConsumerRecord {
    /// KVM_GET_XSAVE's region, as bytes.
    pub(crate) raw_get: Vec<u8>,
    /// The codec's signal-frame image (`XsaveImage::from_kvm`), after the edit.
    pub(crate) frame: Vec<u8>,
    /// The region the codec decoded from that frame (`restore_from_signal`),
    /// which KVM_SET_XSAVE installed.
    pub(crate) restored: Vec<u8>,
}

fn xsave_bytes(xsave: &kvm_bindings::kvm_xsave) -> Vec<u8> {
    xsave
        .region
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

impl ProbeVm {
    /// The frame consumer at a stopped exit (r7 §3.5): KVM_GET_XSAVE, the
    /// production codec's frame image, the edit, the codec's decode, and
    /// KVM_SET_XSAVE of the result.
    pub(crate) fn consume_frame(&mut self, edit: &FrameEdit) -> Result<FrameConsumerRecord> {
        let xsave = self.backend.vcpu.get_xsave()?;
        let raw_get = xsave_bytes(&xsave);
        let mut frame = crate::signal::XsaveImage::from_kvm(&xsave).bytes().to_vec();
        for (offset, bytes) in &edit.patches {
            let Some(end) = offset
                .checked_add(bytes.len())
                .filter(|&end| end <= frame.len())
            else {
                return Err(Error::UnexpectedVcpuExit(format!(
                    "a frame edit of {} bytes at {offset:#x} leaves the {}-byte frame",
                    bytes.len(),
                    frame.len()
                )));
            };
            frame[*offset..end].copy_from_slice(bytes);
        }
        let restored = crate::signal::XsaveImage::restore_from_signal(&frame).map_err(|error| {
            Error::UnexpectedVcpuExit(format!("the frame decoder refused the frame: {error}"))
        })?;
        // SAFETY: `restored` is a whole kvm_xsave that the production codec
        // built for this backend's fixed components, as the backend's own
        // signal return installs it.
        unsafe { self.backend.vcpu.set_xsave(&restored)? };
        Ok(FrameConsumerRecord {
            raw_get,
            frame,
            restored: xsave_bytes(&restored),
        })
    }

    /// P1 with the frame consumer: run 1 must end at FORCE; the consumer
    /// edits and reinstalls the image; run 2 must end at DONE.
    pub(crate) fn run_p1_frame_consumer(
        &mut self,
        edit: &FrameEdit,
    ) -> Result<(Vec<RunRecord>, Option<FrameConsumerRecord>)> {
        let tid = current_tid();
        let run1 = self.step(tid, Some(PROBE_MARKER_FORCE))?;
        if !matches!(run1.end, RunEnd::Trampoline(_)) {
            return Ok((vec![run1], None));
        }
        let consumed = self.consume_frame(edit)?;
        self.write_result(0)?;
        let run2 = self.step(tid, Some(PROBE_MARKER_DONE))?;
        Ok((vec![run1, run2], Some(consumed)))
    }
}

/// The peer's own FPU use on CPU X (r7 §3.3, P7 step 3): it loads distinct
/// x87, SSE and YMM values, XSAVEs its own state and checks that the save
/// holds them, which shows its FPU state was live on that CPU.
pub(crate) fn peer_fpu_self_check() -> bool {
    if !(std::arch::is_x86_feature_detected!("avx") && std::arch::is_x86_feature_detected!("xsave"))
    {
        return false;
    }
    // SAFETY: AVX and XSAVE are present, as just checked.
    unsafe { peer_fpu_self_check_avx() }
}

/// The values the peer loads: XMM0 is the low half, YMM0's upper half the high.
const PEER_YMM: [u64; 4] = [
    0x0123_4567_89ab_cdef,
    0xfedc_ba98_7654_3210,
    0x0f1e_2d3c_4b5a_6978,
    0x8796_a5b4_c3d2_e1f0,
];

#[target_feature(enable = "avx,xsave")]
unsafe fn peer_fpu_self_check_avx() -> bool {
    #[repr(C, align(64))]
    struct Area([u8; 1024]);
    let mut area = Area([0; 1024]);
    // SAFETY: the code reads 32 bytes at `ymm` and XSAVEs components 0-2
    // (RFBM 0x7 in EDX:EAX; 832 bytes) into the 64-byte-aligned 1024-byte
    // area. It leaves the x87 stack empty (FLD1, then FSTP) and the upper
    // YMM halves zero (VZEROUPPER). FNINIT sets FCW to Linux's default 0x37f.
    // Every register it changes is caller-saved under the C ABI.
    unsafe {
        core::arch::asm!(
            "fninit",
            "fld1",
            "vmovdqu ymm0, ymmword ptr [{ymm}]",
            "xsave [{area}]",
            "fstp st(0)",
            "vzeroupper",
            ymm = in(reg) PEER_YMM.as_ptr(),
            area = in(reg) area.0.as_mut_ptr(),
            in("eax") 7_u32,
            in("edx") 0_u32,
            clobber_abi("C"),
            options(nostack),
        );
    }
    let bytes = &area.0;
    let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let u64_at =
        |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("8 bytes"));
    // XSTATE_BV has x87, SSE and YMM; FSW.TOP is 7 after one push; ST0 is
    // +1.0; XMM0 and YMM0's upper half hold the loaded values.
    u64_at(512) & 0x7 == 0x7
        && (u16_at(2) >> 11) & 0x7 == 7
        && u64_at(32) == 0x8000_0000_0000_0000
        && u16_at(40) == 0x3fff
        && [u64_at(160), u64_at(168), u64_at(576), u64_at(584)] == PEER_YMM
}

/// What the peer reported after its FPU use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerReport {
    /// `getcpu` on the peer right after its self-check.
    pub(crate) cpu: u32,
    pub(crate) fpu_ok: bool,
    /// The peer's own nice value, read back on the peer.
    pub(crate) nice: i32,
}

#[derive(Default)]
struct PeerState {
    /// The peer's own nice value, read back on the peer once it is pinned.
    nice: Option<i32>,
    woken: bool,
    report: Option<PeerReport>,
    quit: bool,
}

#[derive(Default)]
struct PeerShared {
    state: std::sync::Mutex<PeerState>,
    changed: std::sync::Condvar,
}

impl PeerShared {
    /// Waits, with a deadline, until `done` holds for the state.
    fn wait_until(
        &self,
        deadline: std::time::Instant,
        done: impl Fn(&PeerState) -> bool,
    ) -> std::sync::MutexGuard<'_, PeerState> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !done(&state) {
            let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
                break;
            };
            state = match self.changed.wait_timeout(state, left) {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        state
    }

    fn update(&self, change: impl FnOnce(&mut PeerState)) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        change(&mut state);
        self.changed.notify_all();
    }
}

/// This thread's nice value. getpriority returns -1 both for nice -1 and on
/// error, so errno is cleared first and checked after.
pub(crate) fn thread_nice() -> Result<i32> {
    // SAFETY: __errno_location returns this thread's errno; getpriority has no
    // pointer arguments, and who = 0 is the calling thread (Linux nice values
    // are per thread).
    let nice = unsafe {
        *libc::__errno_location() = 0;
        libc::getpriority(libc::PRIO_PROCESS, 0)
    };
    if nice == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error().is_some_and(|errno| errno != 0) {
            return Err(Error::HostIo(error));
        }
    }
    Ok(nice)
}

fn set_thread_nice(nice: i32) -> Result<()> {
    // SAFETY: setpriority has no pointer arguments; who = 0 is this thread.
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) } < 0 {
        return Err(Error::HostIo(io::Error::last_os_error()));
    }
    Ok(())
}

impl P7Record {
    /// A record of a P7 trial before any thread, pin or run.
    pub(crate) fn unstarted(vcpu_nice: i32, peer_nice: i32, refusal: Option<P7Refusal>) -> Self {
        Self {
            refusal,
            run: None,
            cpus: None,
            vcpu_nice,
            peer_nice,
            observed_vcpu_nice: None,
            observed_peer_nice: None,
            vcpu_nice_refused: None,
            nice_established: false,
            marker_seen: false,
            s0: VcpuStatsSnapshot::default(),
            t0: ThreadSwitches::default(),
            s1: VcpuStatsSnapshot::default(),
            t1: ThreadSwitches::default(),
            peer: None,
            kicked: false,
        }
    }
}

/// The highest caller nice value at which P7's vCPU thread can still run 5
/// nice levels below the peer: Linux caps nice at 19.
const P7_MAX_CALLER_NICE: i32 = 19 - 5;

/// Why P7 did not run (a pending plan delta; see the PR text).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum P7Refusal {
    /// p7-caller-nice-too-high: the caller runs above nice 14, so the vCPU
    /// thread cannot run 5 nice levels below the peer, and the peer's wakeup
    /// might not preempt it. `vcpu` is the capped value it would have had.
    CallerNiceTooHigh {
        /// The caller's nice value, which the peer inherits.
        caller: i32,
        /// min(caller + 5, 19).
        vcpu: i32,
    },
    /// p7-caller-policy: the caller's scheduling class is not SCHED_OTHER
    /// (the SCHED_RESET_ON_FORK flag aside). Its threads inherit the class,
    /// and P7's preemption certificate is meaningful only for wakeup
    /// preemption between two SCHED_OTHER threads: SCHED_BATCH and SCHED_IDLE
    /// do not preempt on wakeup, and the real-time, deadline and extensible
    /// classes do not use that rule at all.
    CallerPolicy {
        /// The caller's `sched_getscheduler` value, with any
        /// SCHED_RESET_ON_FORK flag.
        policy: i32,
        /// The caller's `sched_getparam` priority.
        priority: i32,
    },
}

/// The calling thread's scheduling policy and priority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadPolicy {
    /// `sched_getscheduler(0)`, including the SCHED_RESET_ON_FORK flag.
    pub(crate) policy: i32,
    /// `sched_getparam(0)`'s priority.
    pub(crate) priority: i32,
}

/// The calling thread's scheduling policy and priority.
pub(crate) fn thread_policy() -> Result<ThreadPolicy> {
    // SAFETY: sched_getscheduler has no pointer arguments; pid 0 is the
    // calling thread.
    let policy = unsafe { libc::sched_getscheduler(0) };
    if policy < 0 {
        return Err(Error::HostIo(io::Error::last_os_error()));
    }
    let mut param = libc::sched_param { sched_priority: 0 };
    // SAFETY: `param` is a writable sched_param; pid 0 is the calling thread.
    if unsafe { libc::sched_getparam(0, &mut param) } < 0 {
        return Err(Error::HostIo(io::Error::last_os_error()));
    }
    Ok(ThreadPolicy {
        policy,
        priority: param.sched_priority,
    })
}

/// P7's admission for a caller with this policy and nice value: the vCPU
/// thread's intended nice and the refusal, if any. The class is an allowlist
/// of SCHED_OTHER alone: SCHED_RESET_ON_FORK is masked off first (it changes
/// only children's policy and resets only a negative nice, which the
/// nice-established check catches), and every other class, known or not, is
/// refused. The policy is checked before the nice value.
pub(crate) fn p7_admission(policy: ThreadPolicy, caller: i32) -> (i32, Option<P7Refusal>) {
    let (vcpu, refusal) = p7_nice(caller);
    if policy.policy & !libc::SCHED_RESET_ON_FORK != libc::SCHED_OTHER {
        return (
            vcpu,
            Some(P7Refusal::CallerPolicy {
                policy: policy.policy,
                priority: policy.priority,
            }),
        );
    }
    (vcpu, refusal)
}

/// The vCPU thread's nice value for a caller at `caller`, and P7's refusal
/// when that leaves less than the +5 gap.
pub(crate) fn p7_nice(caller: i32) -> (i32, Option<P7Refusal>) {
    let vcpu = (caller + 5).min(19);
    let refusal =
        (caller > P7_MAX_CALLER_NICE).then_some(P7Refusal::CallerNiceTooHigh { caller, vcpu });
    (vcpu, refusal)
}

/// What P7 recorded (r7 §3.3, the bracketed preemption certificate).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct P7Record {
    /// Set when P7 refused before starting any thread or run.
    pub(crate) refusal: Option<P7Refusal>,
    /// The vCPU thread's one `KVM_RUN`; `None` if it never ran.
    pub(crate) run: Option<RunRecord>,
    /// CPU X, where the vCPU thread and the peer are pinned, and the
    /// waker's CPU; `None` when the allowed set has fewer than two CPUs.
    pub(crate) cpus: Option<(u32, u32)>,
    /// The nice values P7 intends: min(caller + 5, 19) for the vCPU thread
    /// and the caller's for the peer.
    pub(crate) vcpu_nice: i32,
    pub(crate) peer_nice: i32,
    /// The nice values read back on the vCPU thread after it set its own, and
    /// on the peer once it was pinned; `None` if a thread never reported.
    pub(crate) observed_vcpu_nice: Option<i32>,
    pub(crate) observed_peer_nice: Option<i32>,
    /// Why the vCPU thread's nice value is not set as intended: a lowering it
    /// skipped, or its setter's error.
    pub(crate) vcpu_nice_refused: Option<String>,
    /// Both observed values equal the intended ones, and the vCPU thread's
    /// nice was not refused ([`p7_nice_established`]). Otherwise the run is not
    /// started (reason 6, "P7 nice not established").
    pub(crate) nice_established: bool,
    pub(crate) marker_seen: bool,
    /// S0 and T0 after the marker; S1 and T1 after the peer's report and
    /// before the flag.
    pub(crate) s0: VcpuStatsSnapshot,
    pub(crate) t0: ThreadSwitches,
    pub(crate) s1: VcpuStatsSnapshot,
    pub(crate) t1: ThreadSwitches,
    pub(crate) peer: Option<PeerReport>,
    /// The run did not end by the deadline, and the waker kicked it.
    pub(crate) kicked: bool,
}

/// P7. The caller's thread is the waker, pinned to a CPU other than X for
/// the trial, with its affinity restored afterwards. A dedicated vCPU thread
/// pinned to X at the caller's nice + 5 (capped at 19) issues the run's only
/// `KVM_RUN`. A peer thread pinned to X at the caller's nice waits until the
/// waker wakes it. Every wait is bounded by `deadline`; a run still in the
/// guest at the deadline is kicked through the entry gate, so every thread is
/// joined.
pub(crate) fn run_p7(vm: ProbeVm, deadline: std::time::Instant) -> Result<(ProbeVm, P7Record)> {
    run_p7_with(vm, deadline, set_thread_nice)
}

/// The vCPU thread's nice value, given the one it inherited: no thread's nice
/// is ever lowered (r7 l.715), so `set_nice` is called only to raise it. A
/// target below the inherited value is never set, and one equal to it needs no
/// call. Returns why the nice value is not set as intended: the skipped
/// lowering, or the setter's error.
pub(crate) fn p7_raise_nice(
    inherited: i32,
    target: i32,
    set_nice: fn(i32) -> Result<()>,
) -> Option<String> {
    match target.cmp(&inherited) {
        std::cmp::Ordering::Less => Some(format!(
            "not lowered: inherited nice {inherited}, intended {target}"
        )),
        std::cmp::Ordering::Equal => None,
        std::cmp::Ordering::Greater => set_nice(target).err().map(|error| error.to_string()),
    }
}

/// The vCPU thread's setup: its pin, then its nice value, raised through
/// `set_nice` from the one it inherited and never lowered ([`p7_raise_nice`]),
/// then the nice value it reads back. Neither a skipped lowering nor a failed
/// `set_nice` is an error. A negative caller nice under SCHED_RESET_ON_FORK
/// leaves the thread at 0, so a target below 0 would be a lowering, and an LSM
/// can refuse even a raise. The read-back then differs from the intended
/// value, and the waker does not start the run (reason 6, "P7 nice not
/// established").
pub(crate) fn p7_vcpu_setup(
    x: u32,
    vcpu_nice: i32,
    set_nice: fn(i32) -> Result<()>,
) -> Result<(i32, Option<String>)> {
    set_thread_affinity(&only_cpu(x))?;
    let refused = p7_raise_nice(thread_nice()?, vcpu_nice, set_nice);
    Ok((thread_nice()?, refused))
}

/// Whether the run may start: both threads reported, each read back the nice
/// value P7 intends, and the vCPU thread's nice was neither left unset (a
/// skipped lowering) nor refused by its setter. The last condition is
/// redundant while `setpriority` is all-or-nothing; it can only refuse.
pub(crate) fn p7_nice_established(
    observed_vcpu: Option<i32>,
    observed_peer: Option<i32>,
    vcpu_nice: i32,
    peer_nice: i32,
    vcpu_refused: bool,
) -> bool {
    !vcpu_refused && observed_vcpu == Some(vcpu_nice) && observed_peer == Some(peer_nice)
}

/// [`run_p7`] with the vCPU thread's nice setter as a seam, so a test can make
/// it fail.
fn run_p7_with(
    vm: ProbeVm,
    deadline: std::time::Instant,
    set_nice: fn(i32) -> Result<()>,
) -> Result<(ProbeVm, P7Record)> {
    // `run_trial` refuses a high caller nice before the whole trial; this is
    // the same decision, taken again before any guard, pin or thread here.
    let peer_nice = thread_nice()?;
    let (vcpu_nice, refusal) = p7_admission(thread_policy()?, peer_nice);
    if refusal.is_some() {
        return Ok((vm, P7Record::unstarted(vcpu_nice, peer_nice, refusal)));
    }
    run_p7_admitted(vm, deadline, vcpu_nice, peer_nice, set_nice)
}

/// P7 after its admission, with the intended nice values given: the caller's
/// for the peer, which inherits it, and the vCPU thread's. Outside tests only
/// [`run_p7_with`] calls it, with the admitted values; a test gives an intended
/// vCPU nice that a failing setter leaves unreached, at any caller nice.
fn run_p7_admitted(
    vm: ProbeVm,
    deadline: std::time::Instant,
    vcpu_nice: i32,
    peer_nice: i32,
    set_nice: fn(i32) -> Result<()>,
) -> Result<(ProbeVm, P7Record)> {
    let mut record = P7Record::unstarted(vcpu_nice, peer_nice, None);
    let caller = AffinityGuard::save()?;
    let allowed = cpus_in(caller.saved());
    let (Some(&x), Some(&waker_cpu)) = (allowed.last(), allowed.first()) else {
        return Ok((vm, record));
    };
    if x == waker_cpu {
        return Ok((vm, record));
    }
    record.cpus = Some((x, waker_cpu));
    set_thread_affinity(&only_cpu(waker_cpu))?;

    let stats = vm.stats.try_clone()?;
    let gate = vm.backend.memory.entry_gate();
    let marker = vm.context_word(CONTEXT_MARKER_OFFSET);
    let flag = vm.context_word(CONTEXT_FLAG_OFFSET);
    let shared = std::sync::Arc::new(PeerShared::default());

    let peer_shared = shared.clone();
    note_helper_spawn();
    let peer = JoinOnDrop::new(
        crate::supervisor_thread::builder()
            .name("guest-probe-peer".into())
            .spawn(move || -> Result<()> {
                set_thread_affinity(&only_cpu(x))?;
                let nice = thread_nice()?;
                peer_shared.update(|state| state.nice = Some(nice));
                let state = peer_shared.wait_until(deadline, |state| state.woken || state.quit);
                let woken = state.woken && !state.quit;
                drop(state);
                if woken {
                    let fpu_ok = peer_fpu_self_check();
                    let cpu = current_cpu()?;
                    let nice = thread_nice()?;
                    peer_shared.update(|state| {
                        state.report = Some(PeerReport { cpu, fpu_ok, nice });
                    });
                    drop(peer_shared.wait_until(deadline, |state| state.quit));
                }
                Ok(())
            })?,
    );

    let (tid_sender, tid_receiver) = std::sync::mpsc::channel();
    let (go_sender, go_receiver) = std::sync::mpsc::channel::<bool>();
    let (done_sender, done_receiver) = std::sync::mpsc::channel();
    note_helper_spawn();
    let vcpu = JoinOnDrop::new(
        crate::supervisor_thread::builder()
            .name("guest-probe-vcpu".into())
            .spawn(move || -> Result<(ProbeVm, Option<RunRecord>)> {
                let mut vm = vm;
                let setup = p7_vcpu_setup(x, vcpu_nice, set_nice);
                let tid = current_tid();
                let _ = tid_sender.send(
                    setup
                        .as_ref()
                        .map(|(nice, refused)| (tid, *nice, refused.clone()))
                        .map_err(|error| error.to_string()),
                );
                setup?;
                // The waker starts the run only once both nice values are
                // established.
                let wait = deadline.saturating_duration_since(std::time::Instant::now());
                if go_receiver.recv_timeout(wait) != Ok(true) {
                    let _ = done_sender.send(());
                    return Ok((vm, None));
                }
                let run = vm.step(tid, Some(PROBE_MARKER_DONE));
                let _ = done_sender.send(());
                Ok((vm, Some(run?)))
            })?,
    );

    let wait = deadline.saturating_duration_since(std::time::Instant::now());
    let vcpu_tid = match tid_receiver.recv_timeout(wait) {
        Ok(Ok((tid, nice, refused))) => {
            record.observed_vcpu_nice = Some(nice);
            record.vcpu_nice_refused = refused;
            Some(tid)
        }
        _ => None,
    };
    // Both threads are spawned from this thread at the caller's nice; the run
    // starts only when what each reads back is what P7 intends.
    record.observed_peer_nice = shared
        .wait_until(deadline, |state| state.nice.is_some())
        .nice;
    record.nice_established = vcpu_tid.is_some()
        && p7_nice_established(
            record.observed_vcpu_nice,
            record.observed_peer_nice,
            vcpu_nice,
            peer_nice,
            record.vcpu_nice_refused.is_some(),
        );
    let _ = go_sender.send(record.nice_established);
    let vcpu_tid = vcpu_tid.filter(|_| record.nice_established);
    // No early return until the flag is set and both threads are joined: a
    // vCPU thread left spinning would block the guards' joins.
    let observed = (|| -> Result<()> {
        let Some(vcpu_tid) = vcpu_tid else {
            return Ok(());
        };
        while marker.load() == 0 && std::time::Instant::now() < deadline {
            std::hint::spin_loop();
        }
        record.marker_seen = marker.load() != 0;
        record.s0 = stats.snapshot()?;
        record.t0 = read_switches(vcpu_tid)?;
        shared.update(|state| state.woken = true);
        record.peer = shared
            .wait_until(deadline, |state| state.report.is_some())
            .report;
        record.s1 = stats.snapshot()?;
        record.t1 = read_switches(vcpu_tid)?;
        Ok(())
    })();
    // The flag ends the guest's spin, on every path.
    flag.store(1);
    // A run still in the guest at the deadline is kicked, and admission stays
    // closed until the vCPU thread is joined, so a run it had not yet begun
    // returns without entering the guest.
    let wait = deadline.saturating_duration_since(std::time::Instant::now());
    let mut closed = None;
    if done_receiver.recv_timeout(wait).is_err() {
        record.kicked = true;
        if let Ok(reverie_kvm_core::entry::CloseAttempt::Closing(closing)) = gate.try_close() {
            closed = futures::executor::block_on(closing.finish()).ok();
        }
    }
    shared.update(|state| state.quit = true);
    let joined = vcpu.join();
    drop(closed);
    let peer_joined = peer.join();
    drop(caller);
    observed?;
    let (vm, run) = joined??;
    record.run = run;
    peer_joined??;
    Ok((vm, record))
}

/// A trial's path (r7 §3.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProbeExitPath {
    /// FORCE through the trampoline, with a host action, then DONE.
    P1,
    /// An in-kernel CPUID exit, then DONE.
    P2,
    /// CPUID under guest CPUID faulting: the stub exit, host emulation, DONE.
    P3,
    /// RDTSC under CR4.TSD: the stub exit, host emulation, DONE.
    P4,
    /// A spin ended by the kicker's signal, then DONE.
    P5,
    /// As P1, plus one `immediate_exit` run before resuming.
    P6,
    /// A spin bracketed by a peer's preemption on the pinned CPU, then DONE.
    P7,
}

/// What the host does at P1's user-space exit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HostAction {
    /// Nothing.
    None,
    /// The frame consumer, with this edit.
    FrameConsumer(FrameEdit),
    /// Move the vCPU thread to another allowed CPU.
    Migrate,
}

/// Everything one trial recorded. The caller certifies it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrialRecord {
    pub(crate) path: ProbeExitPath,
    /// The syscall entry against its pinned form, read before the first run.
    pub(crate) trampoline: TrampolineCheck,
    /// CS's selector and SS's DPL before the first run, and at P5's kick.
    pub(crate) initial_cpl: (u16, u8),
    pub(crate) cpl_at_kick: Option<(u16, u8)>,
    /// The SIG preamble's run and the frame consumer it ran, when the trial
    /// had one (SigreturnInit).
    pub(crate) preamble: Option<(RunRecord, Option<FrameConsumerRecord>)>,
    /// The path's runs, in order, up to the first that did not end as
    /// required.
    pub(crate) runs: Vec<RunRecord>,
    pub(crate) frame: Option<FrameConsumerRecord>,
    pub(crate) migrate_target: Option<u32>,
    pub(crate) emulated_rip: Option<u64>,
    pub(crate) kick: Option<KickRecord>,
    pub(crate) spin_after_run1: Option<u64>,
    pub(crate) p7: Option<P7Record>,
    /// The watchdog was started; false only for a trial refused before it.
    pub(crate) watchdog_started: bool,
    /// The watchdog kicked the trial at the probe deadline.
    pub(crate) watchdog_kicked: bool,
    /// The context as the guest left it.
    pub(crate) context: Vec<u8>,
}

/// Kicks a trial that is still running at the deadline: it closes admission
/// (signalling a vCPU inside `KVM_RUN`) and keeps it closed until the trial's
/// thread finishes its sequence, so no later run of the trial enters the
/// guest. It reopens admission before the trial reads guest memory again.
pub(crate) struct Watchdog {
    finished: std::sync::mpsc::Sender<()>,
    thread: JoinOnDrop<bool>,
}

impl Watchdog {
    pub(crate) fn start(
        gate: std::sync::Arc<reverie_kvm_core::entry::EntryGate>,
        deadline: std::time::Instant,
    ) -> Result<Self> {
        let (finished, until) = std::sync::mpsc::channel::<()>();
        note_helper_spawn();
        let thread = crate::supervisor_thread::builder()
            .name("guest-probe-watchdog".into())
            .spawn(move || {
                let wait = deadline.saturating_duration_since(std::time::Instant::now());
                match until.recv_timeout(wait) {
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    _ => return false,
                }
                let mut closed = None;
                if let Ok(reverie_kvm_core::entry::CloseAttempt::Closing(closing)) =
                    gate.try_close()
                {
                    closed = futures::executor::block_on(closing.finish()).ok();
                }
                // Until the trial's thread drops its sender.
                let _ = until.recv();
                drop(closed);
                true
            })?;
        Ok(Self {
            finished,
            thread: JoinOnDrop::new(thread),
        })
    }

    /// Ends the watchdog; true when it kicked.
    pub(crate) fn finish(self) -> Result<bool> {
        drop(self.finished);
        self.thread.join()
    }
}

impl ProbeVm {
    /// The SIG preamble (SigreturnInit, r7 §3.5): a run that must end at SIG,
    /// then the frame consumer with `edit`.
    pub(crate) fn run_sig_preamble(
        &mut self,
        edit: &FrameEdit,
    ) -> Result<(RunRecord, Option<FrameConsumerRecord>)> {
        let run = self.step(current_tid(), Some(PROBE_MARKER_SIG))?;
        if !matches!(run.end, RunEnd::Trampoline(_)) {
            return Ok((run, None));
        }
        let consumed = self.consume_frame(edit)?;
        self.write_result(0)?;
        Ok((run, Some(consumed)))
    }
}

/// Runs one trial on `vm`: the optional SIG preamble, then `path` with
/// `action`, under a watchdog for `deadline`. Returns the VM, which P7 moves
/// through its own vCPU thread, and the record.
pub(crate) fn run_trial(
    mut vm: ProbeVm,
    path: ProbeExitPath,
    action: &HostAction,
    preamble: Option<&FrameEdit>,
    deadline: std::time::Instant,
) -> Result<(ProbeVm, TrialRecord)> {
    let mut record = TrialRecord {
        path,
        trampoline: vm.trampoline,
        initial_cpl: (vm.initial_cs_selector, vm.initial_ss_dpl),
        cpl_at_kick: None,
        preamble: None,
        runs: Vec::new(),
        frame: None,
        migrate_target: None,
        emulated_rip: None,
        kick: None,
        spin_after_run1: None,
        p7: None,
        watchdog_started: false,
        watchdog_kicked: false,
        context: Vec::new(),
    };
    // P7's caller refusals (nice, and the batch or idle policy) cover the
    // whole trial: they are
    // decided before interception, the watchdog, any helper thread, any
    // affinity guard, the SIG preamble and any KVM_RUN.
    if path == ProbeExitPath::P7 {
        let caller = thread_nice()?;
        let (vcpu, refusal) = p7_admission(thread_policy()?, caller);
        if refusal.is_some() {
            record.p7 = Some(P7Record::unstarted(vcpu, caller, refusal));
            record.context = vm.read_context()?;
            return Ok((vm, record));
        }
    }
    // Interception is set before the first read point; neither write is to an
    // xstate-managed MSR.
    match path {
        ProbeExitPath::P3 => vm.enable_emulation(Emulated::Cpuid)?,
        ProbeExitPath::P4 => vm.enable_emulation(Emulated::Rdtsc)?,
        _ => {}
    }
    let watchdog = Watchdog::start(vm.backend.memory.entry_gate(), deadline)?;
    record.watchdog_started = true;
    let preamble_ok = match preamble {
        Some(edit) => {
            let ran = vm.run_sig_preamble(edit)?;
            let ok = ran.1.is_some();
            record.preamble = Some(ran);
            ok
        }
        None => true,
    };
    if preamble_ok {
        match (path, action) {
            (ProbeExitPath::P1, HostAction::None) => {
                record.runs = vm.run_sequence(&[
                    StepKind::Run(Some(PROBE_MARKER_FORCE)),
                    StepKind::Run(Some(PROBE_MARKER_DONE)),
                ])?;
            }
            (ProbeExitPath::P1, HostAction::FrameConsumer(edit)) => {
                let (runs, frame) = vm.run_p1_frame_consumer(edit)?;
                record.runs = runs;
                record.frame = frame;
            }
            (ProbeExitPath::P1, HostAction::Migrate) => {
                let migrated = vm.run_p1_migrate()?;
                record.runs = migrated.runs;
                record.migrate_target = migrated.target;
            }
            (ProbeExitPath::P2, HostAction::None) => {
                record.runs = vm.run_sequence(&[StepKind::Run(Some(PROBE_MARKER_DONE))])?;
            }
            (ProbeExitPath::P3 | ProbeExitPath::P4, HostAction::None) => {
                let which = if path == ProbeExitPath::P3 {
                    Emulated::Cpuid
                } else {
                    Emulated::Rdtsc
                };
                let emulated = vm.run_emulated(which)?;
                record.runs = emulated.runs;
                record.emulated_rip = emulated.instruction_rip;
            }
            (ProbeExitPath::P5, HostAction::None) => {
                let p5 = vm.run_p5(deadline)?;
                record.runs = p5.runs;
                record.kick = Some(p5.kick);
                record.spin_after_run1 = Some(p5.spin_after_run1);
                record.cpl_at_kick = p5.cpl_at_kick;
            }
            (ProbeExitPath::P6, HostAction::None) => {
                record.runs = vm.run_sequence(&[
                    StepKind::Run(Some(PROBE_MARKER_FORCE)),
                    StepKind::ImmediateExit,
                    StepKind::Run(Some(PROBE_MARKER_DONE)),
                ])?;
            }
            (ProbeExitPath::P7, HostAction::None) => {
                let (moved, p7) = run_p7(vm, deadline)?;
                vm = moved;
                record.p7 = Some(p7);
            }
            (path, action) => {
                return Err(Error::UnexpectedVcpuExit(format!(
                    "the probe has no host action {action:?} on path {path:?}"
                )));
            }
        }
    }
    record.watchdog_kicked = watchdog.finish()?;
    record.context = vm.read_context()?;
    Ok((vm, record))
}

/// Installs a caller's position-independent blob and its context in a fresh
/// [`KvmBackend`](crate::KvmBackend) and runs one trial on it.
///
/// The blob runs at CPL3 from `entry_offset`, with the context's guest
/// address in RDI, and reaches the host only through `syscall` with a probe
/// marker in EAX at the sites it declares. Construction checks the syscall
/// entry against its pinned form and reads the host facts; nothing runs the
/// guest until [`Self::run_trial`].
pub struct GuestProbeRunner {
    vm: ProbeVm,
}

impl GuestProbeRunner {
    /// Builds the probe VM. `context` is at most [`CONTEXT_MAX_SIZE`] bytes
    /// and at least [`CONTEXT_DATA_OFFSET`]; its control words are zeroed.
    pub fn new(
        blob: &[u8],
        entry_offset: u64,
        context: &[u8],
        stack_top: u64,
        sites: &[ExitSite],
    ) -> Result<Self> {
        Ok(Self {
            vm: ProbeVm::new(blob, entry_offset, context, stack_top, sites)?,
        })
    }

    /// The host facts read at construction.
    pub fn facts(&self) -> &RunnerFacts {
        &self.vm.facts
    }

    /// Runs the one trial this VM is for: the SIG preamble with `preamble`'s
    /// edit, when given, then `path` with `action`, all bounded by
    /// `deadline`.
    pub fn run_trial(
        self,
        path: ProbeExitPath,
        action: &HostAction,
        preamble: Option<&FrameEdit>,
        deadline: std::time::Instant,
    ) -> Result<TrialRecord> {
        run_trial(self.vm, path, action, preamble, deadline).map(|(_, record)| record)
    }
}

#[cfg(test)]
#[path = "guest_probe_tests.rs"]
mod tests;
