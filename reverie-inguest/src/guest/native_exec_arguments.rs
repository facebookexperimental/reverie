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
const MAX_PATH_BYTES: usize = 4096;
const MAX_ARGV: usize = 128;
const MAX_ENVP: usize = 256;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_SPANS: usize = 512;
const MAX_MAPS: usize = 512;
const MAX_SMAPS_BYTES: usize = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = MAX_STRING_BYTES + (MAX_ARGV + MAX_ENVP + 2) * 8;

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
        let mut result = Self {
            authority,
            call,
            image,
            maps: Vec::with_capacity(MAX_MAPS),
            spans: Vec::with_capacity(MAX_SPANS),
            bytes: Vec::with_capacity(MAX_SNAPSHOT_BYTES),
            argv: Vec::with_capacity(MAX_ARGV),
            envp: Vec::with_capacity(MAX_ENVP),
            path: StringBytes { offset: 0, len: 0 },
            string_bytes: 0,
            scratch: vec![0; PAGE],
        };
        scan_smaps(|entry| {
            if let Some(mapping) = entry.qualified() {
                if result.maps.len() == MAX_MAPS {
                    return Err(ArgumentRefusal::Bound);
                }
                result.maps.push(mapping);
            }
            Ok(())
        })?;
        result.path = result.string(pointers[0], MAX_PATH_BYTES)?;
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
                self.spans.push(Span {
                    address: next,
                    offset: byte_offset,
                    len,
                    mapping: index,
                });
            }
            next += len;
        }
        copy_numeric(address, output)?;
        self.bytes.extend_from_slice(output);
        Ok(())
    }

    fn string(&mut self, address: usize, limit: usize) -> Result<StringBytes, ArgumentRefusal> {
        let offset = self.bytes.len();
        // Exact one-byte reads avoid even inspecting bytes after the first NUL.
        // Page/VMA splits therefore impose no post-terminator requirement.
        for index in 0..limit {
            if self.string_bytes == MAX_STRING_BYTES {
                return Err(ArgumentRefusal::Bound);
            }
            let at = address.checked_add(index).ok_or(ArgumentRefusal::Bound)?;
            let mut byte = [0];
            self.read(at, &mut byte)?;
            self.string_bytes += 1;
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
            if index == limit {
                return Err(ArgumentRefusal::Bound);
            }
            let value = self.string(pointer, MAX_STRING_BYTES)?;
            if argv {
                self.argv.push(value);
            } else {
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
            let pointers = map.base + PAGE;
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
