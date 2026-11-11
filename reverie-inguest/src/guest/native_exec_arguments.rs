/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Bounded inspection of original exec arguments, never replacement operands.
//!
//! Kernel smaps and numeric self-read supply mapping/byte observations. Neither
//! proves writer exclusion, target namespace authority, or saved-PKRU access.
//! The unsafe installer-owned lease supplies the missing quiescent interval;
//! readable private-anonymous key0 VMAs and actual saved key0 AD supply rights.
//! This module grants no Issue, loader, syscall, or successor-image authority.

use core::marker::PhantomData;

use super::native_exec::OriginalExec;

const PAGE: usize = 4096;
/// Pathname bound, congruent with the kernel's PATH_MAX string size
/// including its NUL. The kernel does charge the pathname against
/// its execve stack budget (copy_string_kernel on bprm->filename);
/// it is budgeted separately below (see MAX_SNAPSHOT_BYTES) purely
/// as local accounting, which is a sound over-approximation: this
/// capture may admit a superset of what the kernel admits.
const MAX_PATH_BYTES: usize = 4096;
/// Policy bound on argv entries. The kernel's count limit
/// (MAX_ARG_STRINGS, 2^31-1) is far above anything the byte ceiling
/// admits, so counts here are bounded by policy and the byte
/// ceiling, not by a practical kernel count cap. Named
/// ArgumentRefusal::Bound past this policy limit.
const MAX_ARGV: usize = 4096;
/// Policy bound on envp entries, as MAX_ARGV.
const MAX_ENVP: usize = 4096;
/// Kernel-derived ceiling on total copied argv/envp string bytes
/// including NULs: fs/exec.c bprm_stack_limits caps strings plus
/// their pointer words at min(RLIMIT_STACK / 4, 3/4 * _STK_LIM)
/// with _STK_LIM = 8 MiB, i.e. at most 6 MiB over all rlimits. The
/// pointer words are subtracted from that same budget by the
/// kernel (which also floors that argument limit at ARG_MAX),
/// so charging strings alone here stays a sound
/// over-approximation; a single legitimate string may itself reach
/// MAX_ARG_STRLEN (32 * PAGE_SIZE).
const MAX_STRING_BYTES: usize = 6 * 1024 * 1024;
/// Policy bound on retained mapping spans, sized so the count caps
/// above are actually reachable in a non-crossing layout: each
/// vector entry costs up to two spans (its pointer word and its
/// string's first segment; interleaved reads do not merge), plus
/// the two terminator words and the pathname. Layouts whose strings
/// cross extra VMAs add a span per crossing and can still
/// Bound-refuse below the count caps; that residual is policy, not
/// a kernel limit.
const MAX_SPANS: usize = 2 * (MAX_ARGV + MAX_ENVP) + 3;
/// Policy bound on qualified VMAs retained from one smaps scan.
/// The kernel allows vm.max_map_count VMAs (default 65,530) and
/// beyond; multi-VMA layouts past this bound Bound-refuse.
const MAX_MAPS: usize = 8192;
/// Policy bound on /proc/self/smaps text consumed per scan (the
/// text covers every mapping in the process, not only qualified
/// ones), derived as a per-VMA allowance over MAX_MAPS. The scan
/// retains only a page of scratch, so this bounds parse work, not
/// memory.
const MAX_SMAPS_BYTES: usize = MAX_MAPS * 2048;
/// Exact worst-case retained snapshot bytes: counted string bytes
/// (argv/envp, NULs included) + pathname bytes + every pointer word
/// read, terminators included: (MAX_ARGV + 1 + MAX_ENVP + 1) * 8.
/// This capture bound is local only and is not a wire bound: if any
/// future framer encodes captured argument bytes into an exec
/// ticket (1 MiB) or successor state (1 MiB), that smaller bound
/// must refuse by name at admission/seal, never truncate to fit.
const MAX_SNAPSHOT_BYTES: usize = MAX_STRING_BYTES + MAX_PATH_BYTES + (MAX_ARGV + MAX_ENVP + 2) * 8;

// Tool-arena budget at these caps (derived, not measured): growth
// doubles but is clamped to each cap (reserve_clamped), so the
// worst-case retained capture storage is the snapshot Vec at
// MAX_SNAPSHOT_BYTES (6,361,104 bytes) plus spans (16,387 x 32),
// maps (8,192 x 32), argv/envp (2 x 4,096 x 16) and one scratch
// page, 7,282,800 bytes or about 7.0 MiB. The transient peak is
// higher: an allocator that reallocates by copying holds the old
// and the new clamped snapshot backing at once. The old backing is
// up to 6,291,456 bytes (exact pathname reservations make the
// capacity run 10, 11 or 12 x 2^k for 2-4 byte paths, 2^k
// otherwise), so the peak is about 12.1 MiB for the snapshot alone
// and about 12.9 MiB (13,574,256 bytes) with every other capture
// Vec at its cap, before allocator overhead.
// That fits a 32 MiB fixed Tool arena only if its other occupants
// leave room, which is not bounded here. Every capture allocation,
// the scratch page included, therefore reserves fallibly and maps
// failure to ArgumentRefusal::Bound: running out of Tool arena
// refuses, it never aborts through the allocator error handler.

/// Unsupported inspection/admission domain, never a Linux syscall errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentRefusal {
    /// Only execve and AT_FDCWD/flags-zero execveat are supported.
    UnsupportedOperation,
    /// NULL argv/envp are outside this initial domain, not presumed EFAULT.
    NullVector,
    /// Actual owner, original operation, or image binding changed.
    ChangedOwner,
    /// Saved rights do not grant key0 input reads, or capture is unqualified.
    ReadRights,
    /// Input overlaps protected Tool/control/scratch/continuation storage.
    ProtectedRange,
    /// Input is not fully readable private anonymous key0 memory.
    UnsupportedMapping,
    /// A bounded scan, string, vector, or range cannot be represented.
    Bound,
    /// Kernel metadata/copy/close failed or was incomplete/malformed.
    Inspection,
    /// Exact recorded mapping properties changed.
    ChangedMapping,
    /// Original recorded pointer/string/terminator bytes changed.
    ChangedBytes,
}

/// Half-open excluded address interval, not a mapping or access capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgumentRange {
    pub start: usize,
    pub end: usize,
}

/// Caller-derived equality bindings. mm/epoch are not kernel attestations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgumentImage {
    pub physical_pid: i32,
    pub physical_tid: i32,
    /// Exact original MmId (creator DetTid, generation), before preparation.
    /// This is an equality binding, never a lossy hash or kernel attestation.
    pub mm_id: (i32, u64),
    /// Actual installed image generation; generation zero is valid.
    pub image_epoch: u64,
}

/// Captured frontend policy, meaningful only under the unsafe lease contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadCapture {
    /// The original event contains genuinely captured guest PKRU.
    SavedPkru,
    /// The actual installed scalar frontend qualified its no-PKRU capture.
    ScalarFrontendWithoutPkru,
}

/// Nonserializable lifetime borrow of the genuine retained admission owner.
/// Rust lifetime alone does not establish the unsafe obligations below.
pub struct ArgumentQuiescence<'a> {
    image: ArgumentImage,
    protected: &'a [ArgumentRange],
    capture: ReadCapture,
    _owner: PhantomData<&'a ()>,
}

impl<'a> ArgumentQuiescence<'a> {
    /// Borrow the actual unsafe native admission owner for this entire cut.
    ///
    /// # Safety
    ///
    /// `owner` must be the real retained installed admission, not a boolean,
    /// marker, decoded packet or synthetic authority. `image` must name its
    /// actual physical leader, original mm and admitted image generation.
    /// Through capture, every recheck and the subsequent kernel handoff there
    /// must be one childless guest thread, no delivered guest handler or mapping
    /// mutation, no Tool write to inputs, no outstanding asynchronous/kernel/
    /// userfaultfd writer, no surviving writable shared alias, and no external
    /// ptrace/process_vm writer. Anonymous smaps/equal bytes do not prove this.
    /// `protected` must completely cover actual Tool/control/bootstrap/stack/
    /// continuation storage, including scan syscall metadata and future receipt
    /// moves. The runtime-owned /proc/self/smaps view must name this exact task.
    /// `capture` must describe the actual installed original-event frontend;
    /// ScalarFrontendWithoutPkru is not a claim inferred from absent metadata.
    /// Other code must preserve this closure until genuine exec or cancellation.
    pub unsafe fn new<O: ?Sized>(
        image: ArgumentImage,
        protected: &'a [ArgumentRange],
        capture: ReadCapture,
        _owner: &'a O,
    ) -> Result<Self, ArgumentRefusal> {
        if protected.iter().any(|range| range.start >= range.end) {
            return Err(ArgumentRefusal::ProtectedRange);
        }
        let result = Self {
            image,
            protected,
            capture,
            _owner: PhantomData,
        };
        result.check_owner()?;
        Ok(result)
    }

    fn check_owner(&self) -> Result<(), ArgumentRefusal> {
        let pid = raw(libc::SYS_getpid, [0; 6]);
        let tid = raw(libc::SYS_gettid, [0; 6]);
        if pid <= 0
            || pid != tid
            || pid != i64::from(self.image.physical_pid)
            || tid != i64::from(self.image.physical_tid)
        {
            return Err(ArgumentRefusal::ChangedOwner);
        }
        Ok(())
    }

    fn check_rights(&self, call: Call) -> Result<(), ArgumentRefusal> {
        match (self.capture, call.pkru) {
            (ReadCapture::SavedPkru, Some(value)) if value & 1 == 0 => Ok(()),
            (ReadCapture::ScalarFrontendWithoutPkru, None) => Ok(()),
            _ => Err(ArgumentRefusal::ReadRights),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Call {
    number: i64,
    args: [u64; 6],
    pkru: Option<u32>,
}

impl From<&OriginalExec> for Call {
    fn from(original: &OriginalExec) -> Self {
        Self {
            number: original.number(),
            args: original.args(),
            pkru: original.pkru(),
        }
    }
}

impl Call {
    fn pointers(self) -> Result<[usize; 3], ArgumentRefusal> {
        let positions = if self.number == libc::SYS_execve {
            [0, 1, 2]
        } else if self.number == libc::SYS_execveat
            && self.args[0] == libc::AT_FDCWD as i64 as u64
            && self.args[4] == 0
        {
            [1, 2, 3]
        } else {
            return Err(ArgumentRefusal::UnsupportedOperation);
        };
        let mut pointers = [0; 3];
        for (target, position) in pointers.iter_mut().zip(positions) {
            *target = usize::try_from(self.args[position]).map_err(|_| ArgumentRefusal::Bound)?;
        }
        if pointers[1] == 0 || pointers[2] == 0 {
            return Err(ArgumentRefusal::NullVector);
        }
        Ok(pointers)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnonymousName {
    Unnamed,
    Heap,
    Stack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Mapping {
    range: ArgumentRange,
    permissions: [u8; 4],
    flags: u32,
    name: AnonymousName,
}

#[derive(Clone, Copy)]
struct ObservedMapping {
    range: ArgumentRange,
    permissions: [u8; 4],
    anonymous: Option<AnonymousName>,
    zero_backing: bool,
    key: Option<usize>,
    flags: Option<u32>,
    flags_seen: bool,
}

impl ObservedMapping {
    fn qualified(self) -> Option<Mapping> {
        if !self.zero_backing
            || self.permissions[0] != b'r'
            || self.permissions[3] != b'p'
            || self.key != Some(0)
        {
            return None;
        }
        Some(Mapping {
            range: self.range,
            permissions: self.permissions,
            flags: self.flags?,
            name: self.anonymous?,
        })
    }
}

#[derive(Clone, Copy)]
struct Span {
    address: usize,
    offset: usize,
    len: usize,
    mapping: usize,
}

#[derive(Clone, Copy)]
struct StringBytes {
    offset: usize,
    len: usize,
}

/// Retained original data and its checked mapping spans, not target authority.
/// Allocate/capture before Seal; retain it through kernel handoff/cancellation.
pub struct OriginalExecArguments<'a> {
    authority: ArgumentQuiescence<'a>,
    call: Call,
    image: ArgumentImage,
    maps: Vec<Mapping>,
    spans: Vec<Span>,
    bytes: Vec<u8>,
    argv: Vec<StringBytes>,
    envp: Vec<StringBytes>,
    path: StringBytes,
    string_bytes: usize,
    scratch: Vec<u8>,
}

impl<'a> OriginalExecArguments<'a> {
    /// Snapshot only the actual original syscall, with no normalized operands.
    /// This allocates bounded Tool storage and must precede the frozen cut.
    /// Capture-time allocation must not create or resize memory
    /// mappings: capture snapshots smaps identity and recheck
    /// compares it, so an allocator that mmaps or remaps while the
    /// capture Vecs grow can invalidate the guest mapping ledger it
    /// just recorded (ChangedMapping). A fixed Tool arena, which
    /// never maps during capture, satisfies this contract.
    pub fn capture(
        original: &OriginalExec,
        authority: ArgumentQuiescence<'a>,
    ) -> Result<Self, ArgumentRefusal> {
        Self::capture_call(Call::from(original), authority)
    }

    fn capture_call(
        call: Call,
        authority: ArgumentQuiescence<'a>,
    ) -> Result<Self, ArgumentRefusal> {
        authority.check_owner()?;
        authority.check_rights(call)?;
        let pointers = call.pointers()?;
        let image = authority.image;
        let mut scratch = Vec::new();
        reserve_clamped(&mut scratch, PAGE, PAGE)?;
        scratch.resize(PAGE, 0);
        let mut result = Self {
            authority,
            call,
            image,
            // No Vec is preallocated to its cap: a small capture must
            // not pay the multi-megabyte worst case up front. Every
            // bound below is enforced by an explicit length check
            // before the push/copy it guards, never by capacity;
            // growth is clamped to the same caps (reserve_clamped).
            // Growing backings are safe for overlaps_storage: it
            // re-derives every backing range from current capacities
            // for every read, after that read's own snapshot and span
            // reservations, and again over all spans in recheck. A
            // backing that overlaps a guest range when it is read
            // refuses that read ProtectedRange. A later growth (the
            // argv/envp entry pushed after its string, or the next
            // read's reservations) that moves a backing onto an
            // earlier read's range is refused ProtectedRange (or
            // ChangedMapping if the mapping also changed) at
            // recheck; one that has moved away again by recheck
            // surfaces at most as ChangedBytes or ChangedMapping
            // there, never as a silent alias (the Tool allocator never
            // maps over a live guest VMA without MAP_FIXED). Honest
            // CPU cost of the raised caps: the dominant cost is
            // O(bytes x maps): every captured byte runs
            // overlaps_storage plus a linear maps scan (up to MAX_MAPS
            // entries) and two syscalls (getpid and process_vm_readv),
            // about 12.6M syscalls at the string ceiling. Recheck adds
            // O(spans x smaps entries), every smaps entry of the
            // process and not only qualified ones. Allocator-only
            // means no wire/format change, not no CPU change.
            maps: Vec::new(),
            spans: Vec::new(),
            bytes: Vec::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            path: StringBytes { offset: 0, len: 0 },
            string_bytes: 0,
            scratch,
        };
        scan_smaps(|entry| {
            if let Some(mapping) = entry.qualified() {
                if result.maps.len() == MAX_MAPS {
                    return Err(ArgumentRefusal::Bound);
                }
                reserve_clamped(&mut result.maps, 1, MAX_MAPS)?;
                result.maps.push(mapping);
            }
            Ok(())
        })?;
        result.path = result.string(pointers[0], MAX_PATH_BYTES, false)?;
        if result.path().first() != Some(&b'/') {
            return Err(ArgumentRefusal::UnsupportedOperation);
        }
        result.vector(pointers[1], true)?;
        result.vector(pointers[2], false)?;
        Ok(result)
    }

    /// Original pathname bytes excluding NUL, for caller-owned path admission.
    pub fn path(&self) -> &[u8] {
        self.string_slice(self.path)
    }

    /// Original string bytes, excluding NUL; pointer aliases stay in the receipt.
    pub fn argv(&self) -> impl Iterator<Item = &[u8]> {
        self.argv.iter().map(|value| self.string_slice(*value))
    }

    /// Original environment, without sanitization or runtime activation edits.
    pub fn envp(&self) -> impl Iterator<Item = &[u8]> {
        self.envp.iter().map(|value| self.string_slice(*value))
    }

    /// The caller-derived original image equality binding, not an attestation.
    pub fn image(&self) -> ArgumentImage {
        self.image
    }

    fn string_slice(&self, value: StringBytes) -> &[u8] {
        &self.bytes[value.offset..value.offset + value.len]
    }

    fn overlaps_storage(&self, range: ArgumentRange) -> bool {
        fn backing<T>(values: &Vec<T>) -> ArgumentRange {
            let start = values.as_ptr() as usize;
            ArgumentRange {
                start,
                end: start + values.capacity() * core::mem::size_of::<T>(),
            }
        }
        let start = self as *const Self as usize;
        let owned = [
            ArgumentRange {
                start,
                end: start + core::mem::size_of::<Self>(),
            },
            backing(&self.maps),
            backing(&self.spans),
            backing(&self.bytes),
            backing(&self.argv),
            backing(&self.envp),
            backing(&self.scratch),
        ];
        owned
            .iter()
            .chain(self.authority.protected)
            .any(|protected| overlap(range, *protected))
    }

    fn read(&mut self, address: usize, output: &mut [u8]) -> Result<(), ArgumentRefusal> {
        let end = address
            .checked_add(output.len())
            .ok_or(ArgumentRefusal::Bound)?;
        if self.overlaps_storage(ArgumentRange {
            start: address,
            end,
        }) {
            return Err(ArgumentRefusal::ProtectedRange);
        }
        let offset = self.bytes.len();
        if offset
            .checked_add(output.len())
            .ok_or(ArgumentRefusal::Bound)?
            > MAX_SNAPSHOT_BYTES
        {
            return Err(ArgumentRefusal::Bound);
        }
        reserve_clamped(&mut self.bytes, output.len(), MAX_SNAPSHOT_BYTES)?;
        // Qualify every byte before copying; a word can cross two real VMAs.
        let mut next = address;
        while next < end {
            let index = self
                .maps
                .iter()
                .position(|map| map.range.start <= next && next < map.range.end)
                .ok_or(ArgumentRefusal::UnsupportedMapping)?;
            let len = (end.min(self.maps[index].range.end)) - next;
            let byte_offset = offset + (next - address);
            if let Some(last) = self.spans.last_mut()
                && last.mapping == index
                && last.address + last.len == next
                && last.offset + last.len == byte_offset
            {
                last.len += len;
            } else {
                if self.spans.len() == MAX_SPANS {
                    return Err(ArgumentRefusal::Bound);
                }
                reserve_clamped(&mut self.spans, 1, MAX_SPANS)?;
                self.spans.push(Span {
                    address: next,
                    offset: byte_offset,
                    len,
                    mapping: index,
                });
            }
            next += len;
        }
        // The reservations above may have moved a backing; check the
        // range again against the backings this copy actually uses.
        if self.overlaps_storage(ArgumentRange {
            start: address,
            end,
        }) {
            return Err(ArgumentRefusal::ProtectedRange);
        }
        copy_numeric(address, output)?;
        self.bytes.extend_from_slice(output);
        Ok(())
    }

    // `counted` charges this string's bytes (NUL included) to the
    // argv/envp string budget. The pathname is read uncounted here
    // and budgeted separately in MAX_SNAPSHOT_BYTES; the kernel
    // does charge it, so separate budgeting is a sound
    // over-approximation, not a kernel accounting claim.
    fn string(
        &mut self,
        address: usize,
        limit: usize,
        counted: bool,
    ) -> Result<StringBytes, ArgumentRefusal> {
        let offset = self.bytes.len();
        // Exact one-byte reads avoid even inspecting bytes after the first NUL.
        // Page/VMA splits therefore impose no post-terminator requirement.
        for index in 0..limit {
            if counted && self.string_bytes == MAX_STRING_BYTES {
                return Err(ArgumentRefusal::Bound);
            }
            let at = address.checked_add(index).ok_or(ArgumentRefusal::Bound)?;
            let mut byte = [0];
            self.read(at, &mut byte)?;
            if counted {
                self.string_bytes += 1;
            }
            if byte[0] == 0 {
                return Ok(StringBytes { offset, len: index });
            }
        }
        Err(ArgumentRefusal::Bound)
    }

    fn vector(&mut self, address: usize, argv: bool) -> Result<(), ArgumentRefusal> {
        let limit = if argv { MAX_ARGV } else { MAX_ENVP };
        for index in 0..=limit {
            let at = index
                .checked_mul(8)
                .and_then(|offset| address.checked_add(offset))
                .ok_or(ArgumentRefusal::Bound)?;
            let mut word = [0; 8];
            self.read(at, &mut word)?;
            let pointer =
                usize::try_from(u64::from_ne_bytes(word)).map_err(|_| ArgumentRefusal::Bound)?;
            if pointer == 0 {
                return Ok(());
            }
            // Defense in depth and fail-fast: the loop bound alone
            // would still exit Bound after this iteration, but
            // refusing here avoids reading (and retaining) one more
            // string past the count cap.
            if index == limit {
                return Err(ArgumentRefusal::Bound);
            }
            let value = self.string(pointer, MAX_STRING_BYTES, true)?;
            if argv {
                reserve_clamped(&mut self.argv, 1, MAX_ARGV)?;
                self.argv.push(value);
            } else {
                reserve_clamped(&mut self.envp, 1, MAX_ENVP)?;
                self.envp.push(value);
            }
        }
        Err(ArgumentRefusal::Bound)
    }

    /// Revalidate original data/rights/owner and all actual relevant VMAs.
    /// No allocation/deallocation, encoding, log or RPC. Complete this BEFORE
    /// the caller's final local state/stats/DETLOG/sequence equality checks.
    /// Equality does not close a race; the borrowed unsafe owner must still do so.
    pub fn recheck(&mut self, original: &OriginalExec) -> Result<(), ArgumentRefusal> {
        self.recheck_call(Call::from(original))
    }

    fn recheck_call(&mut self, call: Call) -> Result<(), ArgumentRefusal> {
        if self.call != call || self.image != self.authority.image {
            return Err(ArgumentRefusal::ChangedOwner);
        }
        self.authority.check_owner()?;
        self.authority.check_rights(call)?;
        let mut seen = [false; MAX_MAPS];
        scan_smaps(|entry| {
            for span in &self.spans {
                let range = ArgumentRange {
                    start: span.address,
                    end: span.address + span.len,
                };
                if overlap(range, entry.range) {
                    if entry.qualified() != Some(self.maps[span.mapping]) {
                        return Err(ArgumentRefusal::ChangedMapping);
                    }
                    seen[span.mapping] = true;
                }
            }
            Ok(())
        })?;
        for span in &self.spans {
            if !seen[span.mapping] {
                return Err(ArgumentRefusal::ChangedMapping);
            }
            if self.overlaps_storage(ArgumentRange {
                start: span.address,
                end: span.address + span.len,
            }) {
                return Err(ArgumentRefusal::ProtectedRange);
            }
        }
        for span in &self.spans {
            let mut offset = 0;
            while offset < span.len {
                let len = self.scratch.len().min(span.len - offset);
                copy_numeric(span.address + offset, &mut self.scratch[..len])?;
                if self.scratch[..len]
                    != self.bytes[span.offset + offset..span.offset + offset + len]
                {
                    return Err(ArgumentRefusal::ChangedBytes);
                }
                offset += len;
            }
        }
        self.authority.check_owner()
    }
}

/// Make room for `additional` more entries without ever growing the
/// capacity past `cap`: amortized doubling clamped to the cap, then an
/// exact fallible reservation. A need past `cap` or an allocator
/// failure (a full fixed Tool arena returns null) refuses Bound
/// instead of aborting through the allocator error handler.
fn reserve_clamped<T>(
    values: &mut Vec<T>,
    additional: usize,
    cap: usize,
) -> Result<(), ArgumentRefusal> {
    let need = values
        .len()
        .checked_add(additional)
        .ok_or(ArgumentRefusal::Bound)?;
    if need > cap {
        return Err(ArgumentRefusal::Bound);
    }
    if need <= values.capacity() {
        return Ok(());
    }
    let target = need.max(values.capacity().saturating_mul(2)).min(cap);
    values
        .try_reserve_exact(target - values.len())
        .map_err(|_| ArgumentRefusal::Bound)
}

fn overlap(a: ArgumentRange, b: ArgumentRange) -> bool {
    a.start < b.end && b.start < a.end
}

fn raw(number: i64, args: [u64; 6]) -> i64 {
    // SAFETY: all local metadata/buffers are owned and caller-readable; guest
    // addresses are numeric kernel operands, never Rust guest references.
    unsafe { crate::trap::raw_syscall6(number, args) }
}

fn copy_numeric(address: usize, output: &mut [u8]) -> Result<(), ArgumentRefusal> {
    let pid = raw(libc::SYS_getpid, [0; 6]);
    if pid <= 0 {
        return Err(ArgumentRefusal::Inspection);
    }
    let local = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: output.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut _,
        iov_len: output.len(),
    };
    // This remote self-read deliberately DOES NOT enforce the saved PKRU.
    // Access authority came from observed readable key0 VMA plus saved AD clear.
    let copied = raw(
        libc::SYS_process_vm_readv,
        [
            pid as u64,
            &local as *const _ as u64,
            1,
            &remote as *const _ as u64,
            1,
            0,
        ],
    );
    if copied != output.len() as i64 {
        return Err(ArgumentRefusal::Inspection);
    }
    Ok(())
}

fn number(bytes: &[u8], radix: usize) -> Result<usize, ArgumentRefusal> {
    if bytes.is_empty() {
        return Err(ArgumentRefusal::Inspection);
    }
    let mut value = 0_usize;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => usize::from(byte - b'0'),
            b'a'..=b'f' if radix == 16 => usize::from(byte - b'a' + 10),
            b'A'..=b'F' if radix == 16 => usize::from(byte - b'A' + 10),
            _ => return Err(ArgumentRefusal::Inspection),
        };
        if digit >= radix {
            return Err(ArgumentRefusal::Inspection);
        }
        value = value
            .checked_mul(radix)
            .and_then(|value| value.checked_add(digit))
            .ok_or(ArgumentRefusal::Inspection)?;
    }
    Ok(value)
}

fn field<'b>(line: &'b [u8], at: &mut usize) -> Result<&'b [u8], ArgumentRefusal> {
    while *at < line.len() && line[*at].is_ascii_whitespace() {
        *at += 1;
    }
    let start = *at;
    while *at < line.len() && !line[*at].is_ascii_whitespace() {
        *at += 1;
    }
    if start == *at {
        return Err(ArgumentRefusal::Inspection);
    }
    Ok(&line[start..*at])
}

fn header(line: &[u8]) -> Result<ObservedMapping, ArgumentRefusal> {
    let mut at = 0;
    let range = field(line, &mut at)?;
    let dash = range
        .iter()
        .position(|byte| *byte == b'-')
        .ok_or(ArgumentRefusal::Inspection)?;
    let range = ArgumentRange {
        start: number(&range[..dash], 16)?,
        end: number(&range[dash + 1..], 16)?,
    };
    if range.start >= range.end {
        return Err(ArgumentRefusal::Inspection);
    }
    let permissions: [u8; 4] = field(line, &mut at)?
        .try_into()
        .map_err(|_| ArgumentRefusal::Inspection)?;
    if !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
    {
        return Err(ArgumentRefusal::Inspection);
    }
    let offset = number(field(line, &mut at)?, 16)?;
    let device = field(line, &mut at)?;
    let colon = device
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(ArgumentRefusal::Inspection)?;
    let major = number(&device[..colon], 16)?;
    let minor = number(&device[colon + 1..], 16)?;
    let inode = number(field(line, &mut at)?, 10)?;
    while at < line.len() && line[at].is_ascii_whitespace() {
        at += 1;
    }
    let anonymous = match &line[at..] {
        b"" => Some(AnonymousName::Unnamed),
        b"[heap]" => Some(AnonymousName::Heap),
        b"[stack]" => Some(AnonymousName::Stack),
        _ => None,
    };
    Ok(ObservedMapping {
        range,
        permissions,
        anonymous,
        zero_backing: offset == 0 && major == 0 && minor == 0 && inode == 0,
        key: None,
        flags: None,
        flags_seen: false,
    })
}

fn flags(value: &[u8]) -> Option<u32> {
    // Conservative ordinary anonymous flags only. Unknown, IO/PFN/mixed,
    // shared, userfaultfd, hugetlb, KSM and special flags never qualify.
    const ORDINARY: [&[u8]; 17] = [
        b"rd", b"wr", b"ex", b"mr", b"mw", b"me", b"gd", b"lo", b"ac", b"nr", b"dd", b"sd", b"nh",
        b"hg", b"dc", b"wf", b"de",
    ];
    let mut result = 0;
    for token in value
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
    {
        let index = ORDINARY.iter().position(|known| *known == token)?;
        let bit = 1 << index;
        if result & bit != 0 {
            return None;
        }
        result |= bit;
    }
    (result & 1 != 0).then_some(result)
}

fn scan_line(
    line: &[u8],
    current: &mut Option<ObservedMapping>,
    last_end: &mut usize,
    visit: &mut impl FnMut(ObservedMapping) -> Result<(), ArgumentRefusal>,
) -> Result<(), ArgumentRefusal> {
    let token = line
        .split(|byte| byte.is_ascii_whitespace())
        .next()
        .unwrap_or_default();
    if token.contains(&b'-') {
        let next = header(line)?;
        if next.range.start < *last_end {
            return Err(ArgumentRefusal::Inspection);
        }
        if let Some(previous) = current.take() {
            visit(previous)?;
        }
        *last_end = next.range.end;
        *current = Some(next);
    } else if let Some(value) = line.strip_prefix(b"ProtectionKey:") {
        let entry = current.as_mut().ok_or(ArgumentRefusal::Inspection)?;
        if entry.key.is_some() {
            return Err(ArgumentRefusal::Inspection);
        }
        let mut at = 0;
        let key = number(field(value, &mut at)?, 10)?;
        if key > 15 || value[at..].iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err(ArgumentRefusal::Inspection);
        }
        entry.key = Some(key);
    } else if let Some(value) = line.strip_prefix(b"VmFlags:") {
        let entry = current.as_mut().ok_or(ArgumentRefusal::Inspection)?;
        // Duplicate VmFlags is malformed even if the first flags were unknown.
        if entry.flags_seen {
            return Err(ArgumentRefusal::Inspection);
        }
        entry.flags_seen = true;
        entry.flags = flags(value);
    }
    Ok(())
}

fn scan_smaps(
    mut visit: impl FnMut(ObservedMapping) -> Result<(), ArgumentRefusal>,
) -> Result<(), ArgumentRefusal> {
    let path = b"/proc/self/smaps\0";
    let fd = raw(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as i64 as u64,
            path.as_ptr() as u64,
            (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            0,
            0,
            0,
        ],
    );
    if fd < 0 {
        return Err(ArgumentRefusal::Inspection);
    }
    let result = (|| {
        let mut input = [0; PAGE];
        let mut line = [0; 1024];
        let mut length = 0;
        let mut bytes = 0_usize;
        let mut current = None;
        let mut last_end = 0;
        loop {
            let count = raw(
                libc::SYS_read,
                [
                    fd as u64,
                    input.as_mut_ptr() as u64,
                    input.len() as u64,
                    0,
                    0,
                    0,
                ],
            );
            if count == -i64::from(libc::EINTR) {
                continue;
            }
            if count < 0 || count as usize > input.len() {
                return Err(ArgumentRefusal::Inspection);
            }
            if count == 0 {
                if length != 0 {
                    return Err(ArgumentRefusal::Inspection);
                }
                if let Some(previous) = current {
                    visit(previous)?;
                } else {
                    return Err(ArgumentRefusal::Inspection);
                }
                return Ok(());
            }
            bytes = bytes
                .checked_add(count as usize)
                .ok_or(ArgumentRefusal::Bound)?;
            if bytes > MAX_SMAPS_BYTES {
                return Err(ArgumentRefusal::Bound);
            }
            for byte in &input[..count as usize] {
                if *byte == b'\n' {
                    scan_line(&line[..length], &mut current, &mut last_end, &mut visit)?;
                    length = 0;
                } else {
                    if length == line.len() {
                        return Err(ArgumentRefusal::Bound);
                    }
                    line[length] = *byte;
                    length += 1;
                }
            }
        }
    })();
    let closed = raw(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]);
    if result.is_ok() && closed != 0 {
        return Err(ArgumentRefusal::Inspection);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // OS memory controls, not installed-Tool/namespace/native-exec authority.
    // A libc fork makes the controlled map's child a single-thread leader;
    // the parent never modifies the child's private anonymous argument bytes.
    fn isolated(f: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    struct Map {
        base: usize,
        len: usize,
    }

    impl Map {
        fn new(flags: i32, fd: i32) -> Self {
            let len = 3 * PAGE;
            let pointer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    flags,
                    fd,
                    0,
                )
            };
            assert_ne!(pointer, libc::MAP_FAILED);
            Self {
                base: pointer as usize,
                len,
            }
        }

        fn graph(&self) -> Call {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    c"/arbitrary/exec".as_ptr().cast::<u8>(),
                    self.base as *mut u8,
                    16,
                );
                core::ptr::copy_nonoverlapping(
                    c"payload".as_ptr().cast::<u8>(),
                    (self.base + 256) as *mut u8,
                    8,
                );
                core::ptr::copy_nonoverlapping(
                    c"NAME=value".as_ptr().cast::<u8>(),
                    (self.base + 320) as *mut u8,
                    11,
                );
                let argv = (self.base + 128) as *mut u64;
                argv.write(self.base as u64);
                argv.add(1).write((self.base + 256) as u64);
                argv.add(2).write(0);
                let env = (self.base + 160) as *mut u64;
                env.write((self.base + 320) as u64);
                env.add(1).write(0);
            }
            Call {
                number: libc::SYS_execve,
                args: [
                    self.base as u64,
                    (self.base + 128) as u64,
                    (self.base + 160) as u64,
                    71,
                    72,
                    73,
                ],
                pkru: Some(0),
            }
        }
    }

    impl Drop for Map {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::munmap(self.base as *mut _, self.len) }, 0);
        }
    }

    fn big_map(len: usize) -> Map {
        let pointer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        Map {
            base: pointer as usize,
            len,
        }
    }

    fn exec_call(path: usize, argv: usize, envp: usize) -> Call {
        Call {
            number: libc::SYS_execve,
            args: [path as u64, argv as u64, envp as u64, 71, 72, 73],
            pkru: Some(0),
        }
    }

    fn inspect(
        call: Call,
        excluded: &[ArgumentRange],
        f: impl FnOnce(Result<OriginalExecArguments<'_>, ArgumentRefusal>),
    ) {
        let owner = ();
        let image = ArgumentImage {
            physical_pid: raw(libc::SYS_getpid, [0; 6]) as i32,
            physical_tid: raw(libc::SYS_gettid, [0; 6]) as i32,
            mm_id: (17, 0),
            image_epoch: 0,
        };
        // SAFETY: the isolated child owns this test graph; no Tool or async
        // writer is installed. This proves only the argument-inspection layer.
        let authority =
            unsafe { ArgumentQuiescence::new(image, excluded, ReadCapture::SavedPkru, &owner) }
                .unwrap();
        f(OriginalExecArguments::capture_call(call, authority));
    }

    fn physically_saved_rights(low_bits: u32) -> u32 {
        let features = core::arch::x86_64::__cpuid_count(7, 0);
        assert_ne!(features.ecx & (1 << 4), 0, "native domain requires OSPKE");
        let old: u32;
        unsafe {
            core::arch::asm!("xor ecx, ecx", "rdpkru", lateout("eax") old, out("ecx") _, out("edx") _, options(nostack, nomem));
        }
        let desired = (old & !3) | low_bits;
        let observed: u32;
        // No memory/stack access occurs while key0 is denied or write-disabled.
        // Restore the actual caller value before returning to Rust.
        unsafe {
            core::arch::asm!(
                "mov eax, {desired:e}", "xor ecx, ecx", "xor edx, edx", "wrpkru", "lfence",
                "rdpkru", "mov {observed:e}, eax",
                "mov eax, {old:e}", "xor ecx, ecx", "xor edx, edx", "wrpkru", "lfence",
                desired = in(reg) desired, old = in(reg) old, observed = out(reg) observed,
                out("eax") _, out("ecx") _, out("edx") _, options(nostack, nomem),
            );
        }
        observed
    }

    #[test]
    fn real_private_argument_graph_preserves_aliases_environment_and_registers() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            inspect(call, &[], |result| {
                let mut receipt = result.unwrap();
                assert_eq!(receipt.path(), b"/arbitrary/exec");
                assert_eq!(
                    receipt.argv().collect::<Vec<_>>(),
                    [b"/arbitrary/exec".as_slice(), b"payload".as_slice()]
                );
                assert_eq!(
                    receipt.envp().collect::<Vec<_>>(),
                    [b"NAME=value".as_slice()]
                );
                assert_eq!(receipt.call, call);
                receipt.recheck_call(call).unwrap();
            });
        });
    }

    #[test]
    fn key_zero_access_disable_refuses_despite_successful_remote_copy() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let mut call = map.graph();
            call.pkru = Some(physically_saved_rights(1));
            let mut byte = [0];
            copy_numeric(map.base, &mut byte).unwrap();
            assert_eq!(byte[0], b'/');
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::ReadRights)))
            });
            call.pkru = Some(physically_saved_rights(2));
            inspect(call, &[], |result| {
                result.unwrap().recheck_call(call).unwrap();
            });
        });
    }

    #[test]
    fn prot_none_and_tool_overlap_refuse() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            inspect(
                call,
                &[ArgumentRange {
                    start: map.base,
                    end: map.base + 1,
                }],
                |result| assert!(matches!(result, Err(ArgumentRefusal::ProtectedRange))),
            );
            assert_eq!(
                unsafe { libc::mprotect(map.base as *mut _, PAGE, libc::PROT_NONE) },
                0
            );
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::UnsupportedMapping)))
            });
        });
    }

    #[test]
    fn shared_and_private_file_backed_arguments_refuse() {
        isolated(|| {
            let shared = Map::new(libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1);
            inspect(shared.graph(), &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::UnsupportedMapping)))
            });
            let fd = raw(
                libc::SYS_memfd_create,
                [
                    c"arguments-test".as_ptr() as u64,
                    libc::MFD_CLOEXEC as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            assert!(fd >= 0);
            assert_eq!(
                raw(
                    libc::SYS_ftruncate,
                    [fd as u64, (3 * PAGE) as u64, 0, 0, 0, 0]
                ),
                0
            );
            let file = Map::new(libc::MAP_PRIVATE, fd as i32);
            inspect(file.graph(), &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::UnsupportedMapping)))
            });
            assert_eq!(raw(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]), 0);
        });
    }

    #[test]
    fn other_actual_protection_key_refuses() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            let key = raw(libc::SYS_pkey_alloc, [0; 6]);
            assert!(key > 0);
            assert_eq!(
                raw(
                    libc::SYS_pkey_mprotect,
                    [
                        map.base as u64,
                        PAGE as u64,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        key as u64,
                        0,
                        0
                    ]
                ),
                0
            );
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::UnsupportedMapping)))
            });
            drop(map);
            assert_eq!(raw(libc::SYS_pkey_free, [key as u64, 0, 0, 0, 0, 0]), 0);
        });
    }

    #[test]
    fn boundary_nul_and_pointer_null_do_not_require_following_page() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let mut call = map.graph();
            let path = map.base + 2 * PAGE - 6;
            unsafe {
                core::ptr::copy_nonoverlapping(c"/edge".as_ptr().cast::<u8>(), path as *mut u8, 6);
                ((map.base + 128) as *mut u64).write(path as u64);
            }
            call.args[0] = path as u64;
            assert_eq!(
                unsafe { libc::mprotect((map.base + 2 * PAGE) as *mut _, PAGE, libc::PROT_NONE) },
                0
            );
            inspect(call, &[], |result| {
                result.unwrap().recheck_call(call).unwrap();
            });
            let null_word = map.base + 2 * PAGE - 8;
            unsafe { (null_word as *mut u64).write(0) };
            call.args[0] = map.base as u64;
            call.args[1] = null_word as u64;
            inspect(call, &[], |result| {
                let mut receipt = result.unwrap();
                assert_eq!(receipt.argv().count(), 0);
                receipt.recheck_call(call).unwrap();
            });
        });
    }

    #[test]
    fn pointer_word_crossing_readable_vmas_is_fully_covered() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let mut call = map.graph();
            let pointer = map.base + PAGE - 4;
            unsafe { (pointer as *mut u64).write_unaligned(0) };
            assert_eq!(
                unsafe { libc::mprotect((map.base + PAGE) as *mut _, PAGE, libc::PROT_READ) },
                0
            );
            call.args[1] = pointer as u64;
            inspect(call, &[], |result| {
                result.unwrap().recheck_call(call).unwrap();
            });
        });
    }

    #[test]
    fn unterminated_path_and_vector_refuse_by_domain_bound() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            unsafe { core::ptr::write_bytes(map.base as *mut u8, b'/', MAX_PATH_BYTES) };
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::Bound)))
            });
            let mut call = map.graph();
            let pointer_map = big_map((MAX_ARGV + 2) * 8);
            let pointers = pointer_map.base;
            for i in 0..=MAX_ARGV {
                unsafe { ((pointers + i * 8) as *mut u64).write(map.base as u64) };
            }
            call.args[1] = pointers as u64;
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::Bound)))
            });
        });
    }

    #[test]
    fn cap_values_are_pinned() {
        // Pin every derived/policy VALUE by literal: a mutant
        // restoring any old constant (128/256/64KiB/512/512/8MiB)
        // fails here by name even though boundary tests below are
        // const-driven.
        assert_eq!(MAX_PATH_BYTES, 4096);
        assert_eq!(MAX_ARGV, 4096);
        assert_eq!(MAX_ENVP, 4096);
        assert_eq!(MAX_STRING_BYTES, 6 * 1024 * 1024);
        assert_eq!(MAX_SPANS, 16_387);
        assert_eq!(MAX_MAPS, 8192);
        assert_eq!(MAX_SMAPS_BYTES, 8192 * 2048);
        assert_eq!(MAX_SNAPSHOT_BYTES, 6_361_104);
        assert_eq!(
            MAX_SNAPSHOT_BYTES,
            MAX_STRING_BYTES + MAX_PATH_BYTES + (MAX_ARGV + MAX_ENVP + 2) * 8
        );
    }

    #[test]
    fn vector_counts_at_policy_caps_pass_and_over_refuse() {
        isolated(|| {
            // Layout: "/x" at 0 (path and every entry's string),
            // argv pointers at PAGE, envp pointers after them.
            let argv_at = PAGE;
            let envp_at = argv_at + (MAX_ARGV + 2) * 8;
            let usable = envp_at + (MAX_ENVP + 2) * 8;
            // Guard pages must start on page boundaries; the layout
            // end is not page aligned on its own.
            let usable = usable.div_ceil(PAGE) * PAGE;
            let guard = big_map(usable + 2 * PAGE);
            // PROT_NONE guards keep the fixture VMA from merging
            // with a grown allocator arena between capture and
            // recheck, so recheck compares the mapping it recorded.
            assert_eq!(
                unsafe { libc::mprotect(guard.base as *mut _, PAGE, libc::PROT_NONE) },
                0
            );
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        (guard.base + PAGE + usable) as *mut _,
                        PAGE,
                        libc::PROT_NONE,
                    )
                },
                0
            );
            let map = Map {
                base: guard.base + PAGE,
                len: usable,
            };
            core::mem::forget(guard);
            unsafe {
                (map.base as *mut u8).write(b'/');
                ((map.base + 1) as *mut u8).write(b'x');
                for i in 0..MAX_ARGV {
                    ((map.base + argv_at + i * 8) as *mut u64).write(map.base as u64);
                }
                for i in 0..MAX_ENVP {
                    ((map.base + envp_at + i * 8) as *mut u64).write(map.base as u64);
                }
            }
            let call = exec_call(map.base, map.base + argv_at, map.base + envp_at);
            inspect(call, &[], |result| {
                let mut receipt = result.unwrap();
                assert_eq!(receipt.argv().count(), MAX_ARGV);
                assert_eq!(receipt.envp().count(), MAX_ENVP);
                // Growth is clamped to the cap, not doubled past it.
                assert!(receipt.spans.capacity() <= MAX_SPANS);
                receipt.recheck_call(call).unwrap();
                // The last envp pointer word lies in a span far past
                // index 512; recheck must compare it too.
                let last = map.base + envp_at + (MAX_ENVP - 1) * 8;
                unsafe { (last as *mut u64).write((map.base + 1) as u64) };
                assert_eq!(
                    receipt.recheck_call(call),
                    Err(ArgumentRefusal::ChangedBytes)
                );
                unsafe { (last as *mut u64).write(map.base as u64) };
                receipt.recheck_call(call).unwrap();
            });
            // One entry past each cap refuses by domain Bound.
            unsafe {
                ((map.base + argv_at + MAX_ARGV * 8) as *mut u64).write(map.base as u64);
            }
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::Bound)));
            });
            unsafe {
                ((map.base + argv_at + MAX_ARGV * 8) as *mut u64).write(0);
                ((map.base + envp_at + MAX_ENVP * 8) as *mut u64).write(map.base as u64);
            }
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::Bound)));
            });
        });
    }

    #[test]
    fn single_maximal_string_is_admitted() {
        isolated(|| {
            // One legitimate 128 KiB-class string (MAX_ARG_STRLEN at
            // 4 KiB pages: 131071 chars + NUL), refused by the old
            // 64 KiB total cap.
            const LEN: usize = 128 * 1024 - 1;
            let string_at = 4 * PAGE;
            let map = big_map(string_at + LEN + PAGE);
            unsafe {
                (map.base as *mut u8).write(b'/');
                ((map.base + 1) as *mut u8).write(b'x');
                ((map.base + PAGE) as *mut u64).write(map.base as u64);
                ((map.base + 2 * PAGE) as *mut u64).write((map.base + string_at) as u64);
                core::ptr::write_bytes((map.base + string_at) as *mut u8, b'E', LEN);
            }
            let call = exec_call(map.base, map.base + PAGE, map.base + 2 * PAGE);
            inspect(call, &[], |result| {
                let receipt = result.unwrap();
                assert_eq!(receipt.envp().next().unwrap().len(), LEN);
            });
        });
    }

    #[test]
    fn pathname_is_budgeted_separately_accounting_only() {
        isolated(|| {
            // C1 accounting only: argv/env counted bytes sit just
            // under the ceiling while a near-max pathname is budgeted
            // separately; were the pathname charged to the string
            // budget this capture would Bound-refuse. This is not a
            // kernel-admission claim — the env string below exceeds
            // MAX_ARG_STRLEN, so the kernel refuses this exec for an
            // unrelated reason before any budget question arises.
            const PATH_LEN: usize = 4000;
            const ENV_LEN: usize = MAX_STRING_BYTES - 100;
            let env_at = 8 * PAGE;
            let map = big_map(env_at + ENV_LEN + PAGE);
            unsafe {
                (map.base as *mut u8).write(b'/');
                core::ptr::write_bytes((map.base + 1) as *mut u8, b'p', PATH_LEN - 1);
                ((map.base + PAGE) as *mut u8).write(b'x');
                ((map.base + 2 * PAGE) as *mut u64).write((map.base + PAGE) as u64);
                ((map.base + 3 * PAGE) as *mut u64).write((map.base + env_at) as u64);
                core::ptr::write_bytes((map.base + env_at) as *mut u8, b'E', ENV_LEN);
            }
            let call = exec_call(map.base, map.base + 2 * PAGE, map.base + 3 * PAGE);
            inspect(call, &[], |result| {
                let receipt = result.unwrap();
                assert_eq!(receipt.path().len(), PATH_LEN);
                assert_eq!(receipt.envp().next().unwrap().len(), ENV_LEN);
            });
        });
    }

    #[test]
    fn total_budget_across_strings_admits_exact_and_refuses_one_over() {
        isolated(|| {
            // 24 argv and 24 envp strings of exactly 131_072 counted
            // bytes each (131_071 chars + NUL, MAX_ARG_STRLEN at 4 KiB
            // pages) sum to exactly MAX_STRING_BYTES across both
            // vectors, so the budget is shared, not per vector. Every
            // string stays within the kernel's per-string limit; only
            // the aggregate can refuse. One extra empty envp entry (a
            // lone NUL, one counted byte) makes the total MAX+1.
            const STRIDE: usize = 128 * 1024;
            const PER_VECTOR: usize = 24;
            let argv_at = PAGE;
            let envp_at = 2 * PAGE;
            let strings_at = 4 * PAGE;
            let map = big_map(strings_at + 2 * PER_VECTOR * STRIDE + PAGE);
            unsafe {
                (map.base as *mut u8).write(b'/');
                ((map.base + 1) as *mut u8).write(b'x');
                for i in 0..2 * PER_VECTOR {
                    let at = map.base + strings_at + i * STRIDE;
                    let slot = if i < PER_VECTOR {
                        argv_at + i * 8
                    } else {
                        envp_at + (i - PER_VECTOR) * 8
                    };
                    ((map.base + slot) as *mut u64).write(at as u64);
                    core::ptr::write_bytes(at as *mut u8, b'E', STRIDE - 1);
                }
            }
            let call = exec_call(map.base, map.base + argv_at, map.base + envp_at);
            inspect(call, &[], |result| {
                let receipt = result.unwrap();
                assert_eq!(receipt.argv().count(), PER_VECTOR);
                assert_eq!(receipt.envp().count(), PER_VECTOR);
                assert!(
                    receipt
                        .argv()
                        .chain(receipt.envp())
                        .all(|entry| entry.len() + 1 == STRIDE)
                );
                assert_eq!(
                    receipt
                        .argv()
                        .chain(receipt.envp())
                        .map(|entry| entry.len() + 1)
                        .sum::<usize>(),
                    MAX_STRING_BYTES
                );
                // Growth is clamped to the cap, not doubled past it.
                assert!(receipt.bytes.capacity() <= MAX_SNAPSHOT_BYTES);
            });
            // Append an empty envp string (the NUL ending "/x"):
            // counted total MAX+1.
            unsafe {
                ((map.base + envp_at + PER_VECTOR * 8) as *mut u64).write((map.base + 2) as u64);
            }
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::Bound)));
            });
        });
    }

    #[test]
    fn exhausted_allocator_refuses_bound_instead_of_aborting() {
        isolated(|| {
            // A full fixed Tool arena returns null to Vec growth; under
            // a tight RLIMIT_DATA the libc allocator returns null the
            // same way. RLIMIT_DATA, not RLIMIT_AS: it also charges
            // libc growing an already-reserved arena heap by mprotect.
            // Snapshot growth past the limit must refuse by name, not
            // abort through the allocator error handler (which would
            // kill this child by SIGABRT).
            // 32 envp strings of 131_071 chars + NUL (MAX_ARG_STRLEN,
            // the kernel's per-string shape): 4 MiB counted, so the
            // snapshot must grow past 4 MiB.
            const STRIDE: usize = 128 * 1024;
            const COUNT: usize = 32;
            let strings_at = 4 * PAGE;
            let map = big_map(strings_at + COUNT * STRIDE + PAGE);
            unsafe {
                (map.base as *mut u8).write(b'/');
                ((map.base + 1) as *mut u8).write(b'x');
                for i in 0..COUNT {
                    let at = map.base + strings_at + i * STRIDE;
                    ((map.base + 2 * PAGE + i * 8) as *mut u64).write(at as u64);
                    core::ptr::write_bytes(at as *mut u8, b'E', STRIDE - 1);
                }
            }
            // argv array at PAGE holds an immediate NULL (empty).
            let call = exec_call(map.base, map.base + PAGE, map.base + 2 * PAGE);
            // Control: without the limit the same capture is admitted,
            // so the refusal below comes from allocation alone.
            inspect(call, &[], |result| {
                let receipt = result.unwrap();
                assert_eq!(receipt.envp().count(), COUNT);
                assert!(receipt.envp().all(|entry| entry.len() + 1 == STRIDE));
            });
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let data_kib: usize = status
                .lines()
                .find_map(|line| line.strip_prefix("VmData:"))
                .and_then(|value| value.split_whitespace().next())
                .unwrap()
                .parse()
                .unwrap();
            let mut old = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_DATA, &mut old) }, 0);
            // Room for small growth, far less than the snapshot
            // backing 4 MiB of strings needs.
            let tight = libc::rlimit {
                rlim_cur: (data_kib * 1024 + 1024 * 1024) as libc::rlim_t,
                rlim_max: old.rlim_max,
            };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_DATA, &tight) }, 0);
            inspect(call, &[], |result| {
                let refusal = result.err();
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_DATA, &old) }, 0);
                assert_eq!(refusal, Some(ArgumentRefusal::Bound));
            });
        });
    }

    #[test]
    fn small_capture_does_not_preallocate_the_snapshot_bound() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            inspect(call, &[], |result| {
                let receipt = result.unwrap();
                assert!(
                    receipt.bytes.capacity() < MAX_SNAPSHOT_BYTES / 16,
                    "bytes capacity {} must stay far below the bound",
                    receipt.bytes.capacity()
                );
            });
        });
    }

    #[test]
    fn span_bound_refuses_by_name() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            inspect(call, &[], |result| {
                let mut receipt = result.unwrap();
                // Alternate two distant one-byte reads: each is a new
                // span, so the span cap must Bound-refuse.
                let mut byte = [0];
                let mut refused = None;
                for i in 0..MAX_SPANS + 16 {
                    let address = if i % 2 == 0 {
                        map.base
                    } else {
                        map.base + PAGE
                    };
                    match receipt.read(address, &mut byte) {
                        Ok(()) => {}
                        Err(error) => {
                            refused = Some(error);
                            break;
                        }
                    }
                }
                assert_eq!(refused, Some(ArgumentRefusal::Bound));
                assert_eq!(receipt.spans.len(), MAX_SPANS);
            });
        });
    }

    #[test]
    fn map_bound_refuses_by_name() {
        isolated(|| {
            // One huge mapping punched into MAX_MAPS+64 single-page
            // VMAs (gap page between each) so the capture smaps scan
            // exceeds the qualified-map policy bound.
            let count = MAX_MAPS + 64;
            let len = count * 2 * PAGE;
            let region = big_map(len);
            for i in 0..count {
                assert_eq!(
                    unsafe { libc::munmap((region.base + (2 * i + 1) * PAGE) as *mut _, PAGE) },
                    0
                );
            }
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::Bound)));
            });
            drop(region);
        });
    }

    #[test]
    fn raised_map_and_smaps_caps_admit_and_recheck() {
        isolated(|| {
            // The raised map and smaps caps exercised, not only pinned
            // by literal: single-page RW VMAs split by PROT_NONE pages
            // (so none merge), all below the argument page, push the
            // argument spans to qualified-map index >= 512 (the old
            // MAX_MAPS) and the smaps text past 8 MiB (the old
            // MAX_SMAPS_BYTES), while staying under the raised caps.
            const SINGLES: usize = 6000;
            let args_at = 2 * SINGLES * PAGE;
            let region = big_map(args_at + PAGE);
            for i in 0..SINGLES {
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            (region.base + (2 * i + 1) * PAGE) as *mut _,
                            PAGE,
                            libc::PROT_NONE,
                        )
                    },
                    0
                );
            }
            let base = region.base + args_at;
            unsafe {
                (base as *mut u8).write(b'/');
                ((base + 1) as *mut u8).write(b'x');
                ((base + 64) as *mut u64).write(base as u64);
                ((base + 128) as *mut u64).write(base as u64);
            }
            let smaps = std::fs::read("/proc/self/smaps").unwrap().len();
            assert!(
                smaps > 8 * 1024 * 1024 && smaps < MAX_SMAPS_BYTES,
                "smaps text {smaps} must exceed 8 MiB and stay under the cap"
            );
            let call = exec_call(base, base + 64, base + 128);
            inspect(call, &[], |result| {
                let mut receipt = result.unwrap();
                assert!(receipt.maps.len() > SINGLES);
                assert!(receipt.spans.iter().all(|span| span.mapping >= 512));
                assert_eq!(receipt.argv().collect::<Vec<_>>(), [b"/x".as_slice()]);
                assert_eq!(receipt.envp().collect::<Vec<_>>(), [b"/x".as_slice()]);
                receipt.recheck_call(call).unwrap();
            });
        });
    }

    #[test]
    fn changed_bytes_vma_and_ignored_register_refuse_recheck() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let call = map.graph();
            inspect(call, &[], |result| {
                let mut receipt = result.unwrap();
                // Deliberate negative mutations, not a quiescence proof.
                unsafe { ((map.base + 256) as *mut u8).write(b'X') };
                assert_eq!(
                    receipt.recheck_call(call),
                    Err(ArgumentRefusal::ChangedBytes)
                );
                unsafe { ((map.base + 256) as *mut u8).write(b'p') };
                let mut changed = call;
                changed.args[5] ^= 1;
                assert_eq!(
                    receipt.recheck_call(changed),
                    Err(ArgumentRefusal::ChangedOwner)
                );
                assert_eq!(
                    unsafe { libc::mprotect(map.base as *mut _, PAGE, libc::PROT_READ) },
                    0
                );
                assert_eq!(
                    receipt.recheck_call(call),
                    Err(ArgumentRefusal::ChangedMapping)
                );
            });
        });
    }

    #[test]
    fn execveat_keeps_original_registers_and_refuses_other_dirfd_or_flags() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let old = map.graph();
            let call = Call {
                number: libc::SYS_execveat,
                args: [
                    libc::AT_FDCWD as i64 as u64,
                    old.args[0],
                    old.args[1],
                    old.args[2],
                    0,
                    991,
                ],
                pkru: old.pkru,
            };
            inspect(call, &[], |result| {
                result.unwrap().recheck_call(call).unwrap();
            });
            let mut wrong = call;
            wrong.args[0] = 7;
            inspect(wrong, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::UnsupportedOperation)))
            });
            wrong = call;
            wrong.args[4] = libc::AT_EMPTY_PATH as u64;
            inspect(wrong, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::UnsupportedOperation)))
            });
        });
    }

    #[test]
    fn null_vector_and_unterminated_environment_never_become_guest_errno() {
        isolated(|| {
            let map = Map::new(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
            let mut call = map.graph();
            call.args[2] = 0;
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::NullVector)))
            });
            call = map.graph();
            call.pkru = None;
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::ReadRights)))
            });
            let len = MAX_STRING_BYTES + PAGE;
            let pointer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(pointer, libc::MAP_FAILED);
            let large = Map {
                base: pointer as usize,
                len,
            };
            let call = large.graph();
            unsafe {
                core::ptr::write_bytes((large.base + PAGE) as *mut u8, b'Z', MAX_STRING_BYTES);
                ((large.base + 160) as *mut u64).write((large.base + PAGE) as u64);
            }
            inspect(call, &[], |result| {
                assert!(matches!(result, Err(ArgumentRefusal::Bound)))
            });
        });
    }

    #[test]
    fn incomplete_key_and_ambiguous_special_metadata_never_qualify() {
        let mut entry = header(b"1000-2000 rw-p 00000000 00:00 0").unwrap();
        entry.flags = flags(b"rd wr mr mw me ac sd");
        assert!(entry.qualified().is_none()); // no actual key observation
        entry.key = Some(0);
        assert!(entry.qualified().is_some());
        entry.flags = flags(b"rd wr mr mw me io pf ac sd");
        assert!(entry.qualified().is_none());
        let mut current = Some(entry);
        let mut last_end = 0;
        scan_line(
            b"VmFlags: rd unknown",
            &mut current,
            &mut last_end,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert!(current.unwrap().qualified().is_none());
        assert_eq!(
            scan_line(
                b"VmFlags: rd wr mr mw me ac sd",
                &mut current,
                &mut last_end,
                &mut |_| Ok(())
            ),
            Err(ArgumentRefusal::Inspection)
        );
    }
}
