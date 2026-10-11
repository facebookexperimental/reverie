/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Dormant native ownership of keyed interiors in one fixed reservation.
//!
//! Nothing selects this owner for a runtime, allocator or registered stack.
//! Its immutable descriptors and publication cell stay on key zero. This is
//! preparation for accidental-memory isolation, not security against code
//! which changes PKRU or replaces mappings in the same process.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use super::BASE;
use super::BYTES;
use super::CONTROL_BYTES;
use super::Control;
use super::END;
use super::PAGE;
use super::ToolRegion;
use super::arena;
use crate::trap::raw_syscall6;

const EMPTY: u8 = 0;
const PREPARING: u8 = 1;
const READY: u8 = 2;
const FAILED: u8 = 3;

/// Half-open physical addresses owned by this reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyedSpan {
    pub bottom: usize,
    pub top: usize,
}

/// The immutable, key-zero address descriptor. It exposes no mutable Control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyedRegionSpans {
    pub reservation: KeyedSpan,
    pub control: KeyedSpan,
    pub tool: KeyedSpan,
    pub patch: KeyedSpan,
}

/// Diagnostic key number; possession of this value cannot adopt an owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedKeyDescriptor(u32);

impl OwnedKeyDescriptor {
    pub fn value(self) -> u32 {
        self.0
    }
}

/// A preparation refusal is never a protected owner or a legacy fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyedPrepareKind {
    Unsupported,
    KeyExhausted,
    Busy,
    Native,
    CreatorChanged,
}

/// Resources conservatively retained after uncertain cleanup, until exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyedQuarantine {
    pub mapping: Option<KeyedSpan>,
    pub key: Option<OwnedKeyDescriptor>,
    pub possibly_tagged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyedPrepareError {
    pub kind: KeyedPrepareKind,
    pub errno: i32,
    pub cleanup_errno: Option<i32>,
    pub quarantine: Option<KeyedQuarantine>,
}

impl KeyedPrepareError {
    fn new(kind: KeyedPrepareKind, errno: i32) -> Self {
        Self {
            kind,
            errno,
            cleanup_errno: None,
            quarantine: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyedLeaseStage {
    ClosedKey,
    Size,
    Claim,
    MakeWritable,
    Reset,
    Discard,
    ReleaseBitmap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyedLeaseError {
    pub stage: KeyedLeaseStage,
    pub errno: i32,
    pub cleanup_errno: Option<i32>,
    pub quarantined: bool,
}

impl KeyedLeaseError {
    fn new(stage: KeyedLeaseStage, errno: i32, quarantined: bool) -> Self {
        Self {
            stage,
            errno,
            cleanup_errno: None,
            quarantined,
        }
    }
}

#[derive(Debug)]
struct Descriptor {
    spans: KeyedRegionSpans,
    key: OwnedKeyDescriptor,
}

/// Process-lifetime owner; deliberately neither Send nor Sync.
#[derive(Debug)]
pub struct KeyedToolRegion {
    region: ToolRegion,
    descriptor: Descriptor,
    _native_thread: PhantomData<*mut ()>,
}

type PrepareResult = Result<KeyedToolRegion, KeyedPrepareError>;

struct Publication {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<PrepareResult>>,
}

// SAFETY: only the successful EMPTY -> PREPARING compare-exchange writes the
// cell, and READY/FAILED release publication makes it permanently immutable.
// A reader obtains a !Sync owner only through the unsafe native-thread API;
// this implementation does not make that owner Send or Sync.
unsafe impl Sync for Publication {}

impl Publication {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn get(&self) -> Option<Result<&KeyedToolRegion, KeyedPrepareError>> {
        match self.state.load(Ordering::Acquire) {
            READY | FAILED => {
                // SAFETY: either terminal state observes the sole completed
                // write. Neither the result nor this storage is ever reset.
                Some(
                    unsafe { &*self.value.get().cast::<PrepareResult>() }
                        .as_ref()
                        .map_err(|e| *e),
                )
            }
            _ => None,
        }
    }

    unsafe fn publish(&self, result: PrepareResult) {
        let state = if result.is_ok() { READY } else { FAILED };
        // SAFETY: the caller exclusively owns PREPARING in this process.
        unsafe { self.value.get().cast::<PrepareResult>().write(result) };
        self.state.store(state, Ordering::Release);
    }
}

// Independent of REGION and INITIALIZING. There is no reset or attach route.
static KEYED: Publication = Publication::new();

pub(super) trait NativeCalls {
    fn ospke(&self) -> bool {
        let maximum = core::arch::x86_64::__cpuid(0).eax;
        maximum >= 7 && core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 4) != 0
    }

    unsafe fn syscall(&self, number: i64, args: [u64; 6]) -> i64;

    // A private, statically selected test backend may fork at this boundary.
    // The production backend has no callbacks, environment selector or hook.
    fn before_publish(&self) {}
}

pub(super) struct Native;

impl NativeCalls for Native {
    unsafe fn syscall(&self, number: i64, args: [u64; 6]) -> i64 {
        unsafe { raw_syscall6(number, args) }
    }
}

unsafe fn read_pkru() -> u32 {
    let value: u32;
    unsafe {
        core::arch::asm!(
            "rdpkru", in("ecx") 0_u32, out("eax") value, out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    value
}

unsafe fn write_pkru(value: u32) {
    unsafe {
        core::arch::asm!(
            "wrpkru", "lfence", in("eax") value, in("ecx") 0_u32, in("edx") 0_u32,
            options(nostack, preserves_flags)
        );
    }
}

fn zero(result: i64) -> Result<(), i32> {
    match result {
        0 => Ok(()),
        value if value < 0 => Err(-value as i32),
        _ => Err(libc::EIO),
    }
}

fn identity(calls: &impl NativeCalls) -> Result<(i64, i64), i32> {
    let pid = unsafe { calls.syscall(libc::SYS_getpid, [0; 6]) };
    let tid = unsafe { calls.syscall(libc::SYS_gettid, [0; 6]) };
    if pid <= 0 || tid <= 0 {
        return Err(if pid < 0 {
            -pid as i32
        } else if tid < 0 {
            -tid as i32
        } else {
            libc::EIO
        });
    }
    Ok((pid, tid))
}

struct Preparing {
    creator: (i64, i64),
    entry_pkru: Option<u32>,
    mapping: Option<usize>,
    key: Option<OwnedKeyDescriptor>,
    possibly_tagged: bool,
}

impl Preparing {
    fn fail(
        &mut self,
        calls: &impl NativeCalls,
        mut error: KeyedPrepareError,
    ) -> KeyedPrepareError {
        // A copied builder must not finish or dismantle its inherited partial
        // owner. Refuse and quarantine in the child; the parent's COW state
        // and mappings remain unchanged.
        let copied = error.kind == KeyedPrepareKind::CreatorChanged;
        if copied {
            error.cleanup_errno = Some(libc::ECHILD);
        } else {
            if let Some(mapping) = self.mapping {
                let result = unsafe {
                    calls.syscall(libc::SYS_munmap, [mapping as u64, BYTES as u64, 0, 0, 0, 0])
                };
                match zero(result) {
                    Ok(()) => self.mapping = None,
                    Err(errno) => error.cleanup_errno = Some(errno),
                }
            }
            // Never free a key while even an unconfirmed tagged mapping may
            // remain. Successful whole-reservation removal is the proof.
            if self.mapping.is_none() {
                if let Some(key) = self.key {
                    let result = unsafe {
                        calls.syscall(libc::SYS_pkey_free, [u64::from(key.0), 0, 0, 0, 0, 0])
                    };
                    match zero(result) {
                        Ok(()) => self.key = None,
                        Err(errno) => error.cleanup_errno = Some(errno),
                    }
                }
            }
        }
        if self.mapping.is_some() || self.key.is_some() {
            error.quarantine = Some(KeyedQuarantine {
                mapping: self.mapping.map(|bottom| KeyedSpan {
                    bottom,
                    top: bottom + BYTES,
                }),
                key: self.key,
                possibly_tagged: self.possibly_tagged,
            });
        }
        if let Some(entry) = self.entry_pkru {
            // Return storage and the original host stack/TLS are key zero.
            unsafe { write_pkru(entry) };
        }
        error
    }

    unsafe fn construct(
        &mut self,
        calls: &impl NativeCalls,
    ) -> Result<KeyedToolRegion, KeyedPrepareError> {
        if !calls.ospke() {
            return Err(KeyedPrepareError::new(
                KeyedPrepareKind::Unsupported,
                libc::EOPNOTSUPP,
            ));
        }
        self.entry_pkru = Some(unsafe { read_pkru() });
        let key = unsafe { calls.syscall(libc::SYS_pkey_alloc, [0; 6]) };
        if key < 0 {
            let errno = -key as i32;
            let kind = match errno {
                libc::ENOSYS => KeyedPrepareKind::Unsupported,
                libc::ENOSPC => KeyedPrepareKind::KeyExhausted,
                _ => KeyedPrepareKind::Native,
            };
            return Err(KeyedPrepareError::new(kind, errno));
        }
        if !(1..=15).contains(&key) {
            return Err(KeyedPrepareError::new(
                KeyedPrepareKind::Native,
                libc::EINVAL,
            ));
        }
        let key = OwnedKeyDescriptor(key as u32);
        self.key = Some(key);
        let mask = 3_u32 << (2 * key.0);
        unsafe { write_pkru(self.entry_pkru.unwrap() & !mask) };
        let mapping = unsafe {
            calls.syscall(
                libc::SYS_mmap,
                [
                    BASE as u64,
                    BYTES as u64,
                    libc::PROT_NONE as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                    u64::MAX,
                    0,
                ],
            )
        };
        if mapping < 0 {
            return Err(KeyedPrepareError::new(
                KeyedPrepareKind::Native,
                -mapping as i32,
            ));
        }
        self.mapping = Some(mapping as usize);
        if mapping as usize != BASE {
            return Err(KeyedPrepareError::new(
                KeyedPrepareKind::Native,
                libc::EOPNOTSUPP,
            ));
        }
        let control = (BASE + PAGE) as *mut Control;
        // Tagging begins BEFORE the first typed Control/bitmap/metadata
        // access. Record even a failing attempt as potentially tagged.
        self.possibly_tagged = true;
        zero(unsafe {
            calls.syscall(
                libc::SYS_pkey_mprotect,
                [
                    control as u64,
                    (CONTROL_BYTES - PAGE) as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    u64::from(key.0),
                    0,
                    0,
                ],
            )
        })
        .map_err(|errno| KeyedPrepareError::new(KeyedPrepareKind::Native, errno))?;
        unsafe { core::ptr::addr_of_mut!((*control).held).write(AtomicBool::new(false)) };
        // The fresh anonymous bitmap and scalar atomics have valid zero
        // representations. Reuse the unchanged permanent-arena initializer
        // only after its Control/metadata storage is accessible on our key.
        unsafe { arena::initialize_fixed_arenas(control) }
            .map_err(|errno| KeyedPrepareError::new(KeyedPrepareKind::Native, errno))?;
        let tool = KeyedSpan {
            bottom: BASE + 0x1000_0000,
            top: BASE + 0x1200_0000,
        };
        let patch = KeyedSpan {
            bottom: BASE + 0x1400_0000,
            top: BASE + 0x1600_0000,
        };
        for span in [tool, patch] {
            zero(unsafe {
                calls.syscall(
                    libc::SYS_pkey_mprotect,
                    [
                        span.bottom as u64,
                        (span.top - span.bottom) as u64,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        u64::from(key.0),
                        0,
                        0,
                    ],
                )
            })
            .map_err(|errno| KeyedPrepareError::new(KeyedPrepareKind::Native, errno))?;
        }
        calls.before_publish();
        if identity(calls) != Ok(self.creator) {
            return Err(KeyedPrepareError::new(
                KeyedPrepareKind::CreatorChanged,
                libc::ECHILD,
            ));
        }
        Ok(KeyedToolRegion {
            region: ToolRegion {
                control,
                bootstrap: None,
            },
            descriptor: Descriptor {
                spans: KeyedRegionSpans {
                    reservation: KeyedSpan {
                        bottom: BASE,
                        top: END,
                    },
                    control: KeyedSpan {
                        bottom: control as usize,
                        top: BASE + CONTROL_BYTES,
                    },
                    tool,
                    patch,
                },
                key,
            },
            _native_thread: PhantomData,
        })
    }
}

pub(super) unsafe fn reserve_with(
    calls: &impl NativeCalls,
) -> Result<&'static KeyedToolRegion, KeyedPrepareError> {
    if let Some(result) = KEYED.get() {
        return result;
    }
    KEYED
        .state
        .compare_exchange(EMPTY, PREPARING, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| KeyedPrepareError::new(KeyedPrepareKind::Busy, libc::EAGAIN))?;
    let result = (|| {
        let creator = identity(calls)
            .map_err(|errno| KeyedPrepareError::new(KeyedPrepareKind::Native, errno))?;
        // Enforced minimum native context; absence of other threads and
        // signal/callback activity is additionally the unsafe caller contract.
        if creator.0 != creator.1 {
            return Err(KeyedPrepareError::new(
                KeyedPrepareKind::Native,
                libc::EINVAL,
            ));
        }
        let filter = unsafe {
            calls.syscall(
                libc::SYS_prctl,
                [libc::PR_GET_SECCOMP as u64, 0, 0, 0, 0, 0],
            )
        };
        if filter != 0 {
            return Err(KeyedPrepareError::new(
                KeyedPrepareKind::Native,
                if filter < 0 {
                    -filter as i32
                } else {
                    libc::EPERM
                },
            ));
        }
        let mut preparing = Preparing {
            creator,
            entry_pkru: None,
            mapping: None,
            key: None,
            possibly_tagged: false,
        };
        match unsafe { preparing.construct(calls) } {
            Ok(owner) => Ok(owner),
            Err(error) => Err(preparing.fail(calls, error)),
        }
    })();
    // SAFETY: this process owns the nonwaiting gate; failure is terminal too.
    unsafe { KEYED.publish(result) };
    KEYED.get().unwrap()
}

impl KeyedToolRegion {
    /// Reserve once, retaining either the complete owner or its failure.
    ///
    /// # Safety
    /// Trusted ordinary single-thread native setup only: no runtime, filter,
    /// signal/callback reentry or fork during construction. The host stack/TLS
    /// must stay on accessible key zero. Keep this owner's key open for all
    /// metadata operations and lease drops; never destructively remap it.
    pub unsafe fn reserve_native() -> Result<&'static Self, KeyedPrepareError> {
        unsafe { reserve_with(&Native) }
    }

    pub fn spans(&self) -> KeyedRegionSpans {
        self.descriptor.spans
    }

    pub fn key_descriptor(&self) -> OwnedKeyDescriptor {
        self.descriptor.key
    }

    fn open(&self) -> Result<(), KeyedLeaseError> {
        // Ready implies the cold OSPKE check succeeded. No Control access is
        // made on refusal; descriptors remain usable with this key closed.
        if unsafe { read_pkru() } & (3 << (2 * self.descriptor.key.0)) != 0 {
            return Err(KeyedLeaseError::new(
                KeyedLeaseStage::ClosedKey,
                libc::EACCES,
                true,
            ));
        }
        Ok(())
    }

    /// Claim a unique unpublished keyed stack and its two unkeyed guards.
    ///
    /// # Safety
    /// Ordinary native owner context with the owned key open; no callback or
    /// signal activity. Keep rights open through metadata access and Drop.
    /// A lease must be retained before any stack registration/publication.
    pub unsafe fn lease_stack(
        &'static self,
        usable: usize,
    ) -> Result<KeyedStackLease, KeyedLeaseError> {
        self.open().map_err(|mut error| {
            // No extent has been claimed on this early refusal.
            error.quarantined = false;
            error
        })?;
        let usable = usable
            .checked_add(PAGE - 1)
            .map(|value| value & !(PAGE - 1))
            .filter(|&value| value != 0)
            .ok_or_else(|| KeyedLeaseError::new(KeyedLeaseStage::Size, libc::EINVAL, false))?;
        let pages = (usable / PAGE)
            .checked_add(2)
            .ok_or_else(|| KeyedLeaseError::new(KeyedLeaseStage::Size, libc::ENOMEM, false))?;
        let start = self.region.claim(pages).map_err(|error| {
            KeyedLeaseError::new(
                KeyedLeaseStage::Claim,
                error.raw_os_error().unwrap_or(libc::EIO),
                false,
            )
        })?;
        let protected = unsafe {
            Native.syscall(
                libc::SYS_pkey_mprotect,
                [
                    (BASE + (start + 1) * PAGE) as u64,
                    usable as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    u64::from(self.descriptor.key.0),
                    0,
                    0,
                ],
            )
        };
        if let Err(errno) = zero(protected) {
            let cleanup = self.release_extent(start, pages);
            let mut error =
                KeyedLeaseError::new(KeyedLeaseStage::MakeWritable, errno, cleanup.is_err());
            error.cleanup_errno = cleanup.err().map(|error| error.errno);
            return Err(error);
        }
        Ok(KeyedStackLease {
            owner: self,
            start,
            pages,
            active: true,
            _native_thread: PhantomData,
        })
    }

    fn release_extent(&self, start: usize, pages: usize) -> Result<(), KeyedLeaseError> {
        self.open()?;
        let base = BASE + start * PAGE;
        let bytes = pages * PAGE;
        // Reset BOTH former interior and guards to key zero, before discard
        // and before any bitmap bit can be reused for a different-sized lease.
        zero(unsafe {
            Native.syscall(
                libc::SYS_pkey_mprotect,
                [base as u64, bytes as u64, libc::PROT_NONE as u64, 0, 0, 0],
            )
        })
        .map_err(|errno| KeyedLeaseError::new(KeyedLeaseStage::Reset, errno, true))?;
        zero(unsafe {
            Native.syscall(
                libc::SYS_madvise,
                [
                    (base + PAGE) as u64,
                    (bytes - 2 * PAGE) as u64,
                    libc::MADV_DONTNEED as u64,
                    0,
                    0,
                    0,
                ],
            )
        })
        .map_err(|errno| KeyedLeaseError::new(KeyedLeaseStage::Discard, errno, true))?;
        let mut guard = self.region.lock().map_err(|error| {
            KeyedLeaseError::new(
                KeyedLeaseStage::ReleaseBitmap,
                error.raw_os_error().unwrap_or(libc::EIO),
                true,
            )
        })?;
        let bitmap = guard.bitmap();
        for page in start..start + pages {
            bitmap[page / 64] &= !(1 << (page % 64));
        }
        Ok(())
    }
}

/// Unique unpublished extent; cannot be converted to a legacy StackLease.
#[derive(Debug)]
pub struct KeyedStackLease {
    owner: &'static KeyedToolRegion,
    start: usize,
    pages: usize,
    active: bool,
    _native_thread: PhantomData<*mut ()>,
}

impl KeyedStackLease {
    pub fn belongs_to(&self, owner: &KeyedToolRegion) -> bool {
        core::ptr::eq(self.owner, owner)
    }

    pub fn base(&self) -> usize {
        BASE + (self.start + 1) * PAGE
    }

    pub fn usable_bytes(&self) -> usize {
        (self.pages - 2) * PAGE
    }

    pub fn top(&self) -> usize {
        self.base() + self.usable_bytes()
    }

    /// Explicit release has the same conservative quarantine rule as Drop.
    ///
    /// # Safety
    /// The extent must never have been registered, running or published. The
    /// ordinary native owner must keep its key open through this operation.
    pub unsafe fn release(mut self) -> Result<(), KeyedLeaseError> {
        self.active = false;
        self.owner.release_extent(self.start, self.pages)
    }

    /// Retain the occupied extent until exit. No runtime accepts this view.
    pub fn retain(mut self) -> KeyedStack {
        self.active = false;
        KeyedStack {
            owner: self.owner,
            span: KeyedSpan {
                bottom: self.base(),
                top: self.top(),
            },
            _native_thread: PhantomData,
        }
    }
}

impl Drop for KeyedStackLease {
    fn drop(&mut self) {
        if self.active {
            // Failure retains every bit and the process-lifetime owner key.
            let _ = self.owner.release_extent(self.start, self.pages);
        }
    }
}

/// Process-lifetime occupied view; no freeing Drop or stack-backing conversion.
#[derive(Debug)]
pub struct KeyedStack {
    owner: &'static KeyedToolRegion,
    span: KeyedSpan,
    _native_thread: PhantomData<*mut ()>,
}

impl KeyedStack {
    pub fn belongs_to(&self, owner: &KeyedToolRegion) -> bool {
        core::ptr::eq(self.owner, owner)
    }

    pub fn base(&self) -> usize {
        self.span.bottom
    }

    pub fn top(&self) -> usize {
        self.span.top
    }
}

// Test-only structural observations do not add a production recovery route.
#[cfg(test)]
pub(super) fn fixture_state() -> u8 {
    KEYED.state.load(Ordering::Acquire)
}

#[cfg(test)]
pub(super) struct FixturePreparingGate {
    creator: (i64, i64),
}

#[cfg(test)]
pub(super) fn fixture_hold_preparing() -> Result<FixturePreparingGate, i32> {
    let creator = identity(&Native)?;
    KEYED
        .state
        .compare_exchange(EMPTY, PREPARING, Ordering::Acquire, Ordering::Relaxed)
        .map(|_| FixturePreparingGate { creator })
        .map_err(|_| libc::EAGAIN)
}

#[cfg(test)]
impl Drop for FixturePreparingGate {
    fn drop(&mut self) {
        // No resources or builder exist in this test-only held-gate control.
        // A copied child cannot release its inherited parent gate.
        if identity(&Native) == Ok(self.creator) {
            let _ = KEYED.state.compare_exchange(
                PREPARING,
                EMPTY,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(test)]
pub(super) fn fixture_hold_allocation(
    owner: &KeyedToolRegion,
) -> std::io::Result<super::ControlGuard<'_>> {
    owner.region.lock()
}
