/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The memory interfaces a Linux syscall provider uses: [`GuestMemoryAccess`]
//! (copies to and from guest user memory) and [`AddressSpace`] (the guest's
//! user address space).
//!
//! These are step U1 of the minimal provider seam
//! (<https://github.com/rrnewton/hermit/issues/4485>, epic
//! <https://github.com/rrnewton/hermit/issues/4492>). Their contracts are
//! stated in Linux terms only, so that any implementation of Linux user-memory
//! semantics could serve them, including a foreign user-space kernel. The KVM
//! backend's guest arena (`reverie_kvm::GuestMemory`) is today's only
//! implementation, and today's syscall executor is generic over them.
//!
//! Common rules for every method:
//!
//! - Addresses and lengths are guest user values, exactly as a syscall
//!   received them. Nothing here takes or returns a host address except the
//!   lent operands, which exist to hand a guest range to a host syscall.
//! - Methods are called on the issuing task's host thread while that task's
//!   syscall is in progress. Callers must not assume that no other guest
//!   thread runs at the same time: calls are serialised only under a Tool
//!   that sequentialises guest threads, and only while the issuing task holds
//!   its scheduler turn; even then, a call the Tool classifies as external
//!   blocking (a blocking read, `rt_sigsuspend`) runs in the background, off
//!   the run queue, and overlaps other tasks. A Tool that does not
//!   sequentialise lets every task call concurrently, and threads the backend
//!   runs outside the Tool access the address space at any time. Each
//!   method's stated atomicity is therefore all a caller may rely on, and
//!   state an implementation shares between tasks is protected against
//!   concurrent guest tasks, Tool-owned tasks and host-owned workers alike. A
//!   method does not wait for other guest threads, and an effect it reports
//!   is visible to every guest thread of the address space when it returns.
//! - Every method, stores and edits included, takes `&self`. Guest memory and
//!   the address space are shared with the guest's other threads, which run
//!   and store concurrently, so no caller can hold exclusive access; an
//!   implementation serializes its own edits. Effects of calls on one thread
//!   happen in call order.
//! - `Err` from a copy is a guest fault: Linux's `-EFAULT` class. An
//!   implementation may also return `Err` for a failure of its own machinery;
//!   such a failure must also be surfaced by the implementation as a run
//!   failure, and callers must never turn it into a different guest-visible
//!   result. Callers therefore only ever map `Err` to the errno Linux uses for
//!   a fault at that point.
//! - Determinism: every result is a function of the guest-visible state of the
//!   address space (its mappings, their protections and contents) and of the
//!   arguments. No method reads host time, host randomness or other
//!   host-varying state, and none chooses an address.

/// The access a lent operand or an accessible-prefix query is checked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// The bytes must be readable user memory.
    Read,
    /// The bytes must be writable user memory.
    Write,
}

/// A guest range lent to a host syscall that reads it in place, such as a
/// futex word.
pub trait LentOperand {
    /// The host address of the range's first byte. It is valid until the
    /// operand is dropped and only as an argument to a host syscall; the
    /// caller must not dereference it.
    fn host_address(&self) -> usize;
}

/// A guest range lent to a host syscall that writes it in place, such as an
/// `epoll_wait` event array or a `getdents64` buffer.
pub trait LentOperandMut {
    /// The host address to pass as the syscall's output buffer. Bytes the
    /// syscall writes land in the guest range exactly as a guest store would;
    /// bytes it would write to a part of the range that is not writable user
    /// memory make the host syscall fault there, as Linux's own copy would.
    /// For a zero-length operand this is a sentinel that must not be accessed.
    fn host_pointer(&self) -> *mut libc::c_void;

    /// The implementation's error type for a loan that could not be retired.
    type Error;

    /// End the loan after the host syscall returned. `Err` reports that the
    /// loan could not be retired cleanly; callers report it as a fault.
    fn finish(self) -> Result<(), Self::Error>;
}

/// Copies between the provider and guest user memory, with Linux's
/// `copy_from_user`, `copy_to_user` and `put_user` semantics.
pub trait GuestMemoryAccess {
    /// The implementation's error type: a guest fault, or a failure of the
    /// implementation's own machinery (see the module rules).
    type Error;
    /// A guest range lent read-only to a host syscall.
    type Lent: LentOperand;
    /// A guest range lent to a host syscall that writes it.
    type LentMut<'a>: LentOperandMut<Error = Self::Error>
    where
        Self: 'a;

    /// Copy `destination.len()` bytes from guest address `address`, all or
    /// nothing: `Err` when any byte is not readable user memory, in which
    /// case `destination`'s contents are unspecified and no guest state
    /// changed. Bytes are read individually; the copy is not atomic with
    /// respect to concurrent guest stores, as on Linux.
    fn read_exact(&self, address: u64, destination: &mut [u8]) -> Result<(), Self::Error>;

    /// Copy the longest readable prefix of `[address, address +
    /// destination.len())` into `destination` and return its length, which is
    /// shorter than requested only at the first byte that is not readable.
    /// The prefix decision and the copy are one observation: no mapping
    /// change can fall between them.
    fn copy_from_user_prefix(
        &self,
        address: u64,
        destination: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// Store all of `source` at guest address `address`. A fault found while
    /// validating the range (a byte that is not user memory) returns `Err`
    /// before any byte is stored. A failure of the backing itself during the
    /// store (for example a file mapping whose file was truncated under it)
    /// also returns `Err`, but bytes stored before the failing chunk stay
    /// stored, as on Linux, where such a failure is a fault at that page.
    fn write_exact(&self, address: u64, source: &[u8]) -> Result<(), Self::Error>;

    /// Linux `copy_to_user`: store the longest writable prefix of `source`,
    /// then `Err` if that prefix is shorter than `source`. Bytes before the
    /// first unwritable byte stay stored even when it returns `Err`.
    fn copy_to_user(&self, address: u64, source: &[u8]) -> Result<(), Self::Error>;

    /// Like [`Self::copy_to_user`], but return the length of the stored
    /// writable prefix instead of failing when it is short. `Err` for a fault
    /// before any byte could be considered, or for a failure of the backing
    /// itself during the store, after which the bytes already stored stay
    /// stored (as for [`Self::write_exact`]).
    fn copy_to_user_prefix(&self, address: u64, source: &[u8]) -> Result<usize, Self::Error>;

    /// Linux `put_user` of a 16-bit value: store both bytes or neither, only
    /// to writable user memory. A failure of the backing itself during the
    /// store is reported as `Err`, as for [`Self::write_exact`].
    fn put_user_i16(&self, address: u64, value: i16) -> Result<(), Self::Error>;

    /// Linux `put_user` of a 32-bit value: store all four bytes or none, only
    /// to writable user memory. A failure of the backing itself during the
    /// store is reported as `Err`, as for [`Self::write_exact`].
    fn put_user_i32(&self, address: u64, value: i32) -> Result<(), Self::Error>;

    /// Linux `put_user` of a 64-bit value, as `gettimeofday(2)` and `time(2)`
    /// use it: store all eight bytes or none, only to writable user memory. A
    /// failure of the backing itself during the store is reported as `Err`,
    /// as for [`Self::write_exact`].
    fn put_user_u64(&self, address: u64, value: u64) -> Result<(), Self::Error>;

    /// The length of the longest prefix of `[address, address + length)`
    /// whose bytes are user memory with `access`, for syscalls whose Linux
    /// result depends on a partial copy. It observes the address space only;
    /// a later copy may see a different answer if a mapping changed between.
    /// `Err` when `address` itself is not a user address.
    fn accessible_prefix(
        &self,
        address: u64,
        length: usize,
        access: Access,
    ) -> Result<usize, Self::Error>;

    /// Atomically compare the aligned 32-bit guest word at `address` with
    /// `current` and, if equal, replace it with `new`; return the value the
    /// word held. The exchange is atomic with respect to every guest thread
    /// that can access the word, as Linux's `futex_atomic_cmpxchg_inatomic`
    /// is. `Err`, with no change, when `address` is not four-byte aligned or
    /// the word is not writable user memory.
    fn compare_exchange_u32(
        &self,
        address: u64,
        current: u32,
        new: u32,
    ) -> Result<u32, Self::Error>;

    /// Lend `[address, address + length)` to a host syscall that reads it in
    /// place. `Err` when any byte is not readable user memory. While the
    /// operand lives, the range keeps its current backing: a concurrent
    /// mapping change cannot redirect the host syscall to other memory.
    fn lend(&self, address: u64, length: usize) -> Result<Self::Lent, Self::Error>;

    /// Lend `[address, address + length)` to a host syscall that writes it in
    /// place. Pages of the range that are not writable user memory are not
    /// made accessible; the host syscall faults on them as Linux's copy-out
    /// would. While the operand lives, the range's mappings and protections
    /// cannot change.
    fn lend_mut(&self, address: u64, length: usize) -> Result<Self::LentMut<'_>, Self::Error>;

    /// The `access_ok` rule the syscall layer applies before any copy: the
    /// end of the user address space and Linux's single-vector clamp.
    fn user_address_limit(&self) -> reverie::UserAddressLimit;
}

/// The mapping state of a guest user range, as [`AddressSpace::query`]
/// reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeState {
    /// The range is not one contiguous range of user addresses.
    Unaddressable,
    /// No page of the range is mapped.
    Unmapped,
    /// Some but not all pages of the range are mapped.
    Mixed,
    /// Every page of the range is mapped.
    Mapped,
}

/// The fixed shape of a guest's user address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserLayout {
    /// User addresses below this are reserved by the implementation: the
    /// guest can neither map nor unmap them.
    pub reserved_end: u64,
}

/// Why an [`AddressSpace`] operation changed nothing, or did not complete.
#[derive(Debug)]
pub enum MapError {
    /// The range is not one contiguous range of user addresses.
    Unaddressable,
    /// A page of the range is not mapped and the operation requires it.
    NotMapped,
    /// The mapping's backing does not permit the requested access, as an
    /// `mprotect(PROT_WRITE)` of a shared mapping of a file opened read-only.
    AccessDenied,
    /// The implementation does not support the operation on this range, and
    /// nothing changed. The caller returns the errno its syscall uses for the
    /// refusal.
    Unsupported,
    /// The operation failed after it was admitted. (The implementation's
    /// cause is not carried: no caller distinguishes causes today.)
    Failed,
}

/// What [`AddressSpace::discard`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Discarded {
    /// Some page of the range was not mapped. Linux applies the advice to
    /// the mapped parts and then reports `ENOMEM`.
    pub had_holes: bool,
}

/// The guest's user address space: queries and the edits whose effects Linux
/// defines on existing mappings. Placement (choosing where a new mapping
/// goes) is the provider's policy and is not part of this interface.
///
/// Every edit takes effect before the guest's next instruction: when it
/// returns `Ok`, every guest thread of the address space observes the new
/// mappings and protections, and every copy through [`GuestMemoryAccess`]
/// agrees with them.
pub trait AddressSpace {
    /// The fixed shape of the user address space.
    fn layout(&self) -> UserLayout;

    /// Whether `[address, address + length)` is one contiguous range of user
    /// addresses, mapped or not.
    fn is_addressable(&self, address: u64, length: u64) -> bool;

    /// The mapping state of `[address, address + length)`.
    fn query(&self, address: u64, length: u64) -> RangeState;

    /// Change the protection of every page of `[address, address + length)`
    /// to `protection` (Linux `PROT_*` bits). All or nothing: on `Err` no
    /// protection changed. Errors, in the order checked: `Unaddressable`;
    /// `NotMapped` when any page is unmapped; `Unsupported`; `AccessDenied`
    /// when `PROT_WRITE` is requested on a shared file mapping whose file was
    /// not opened for writing.
    fn protect(
        &self,
        address: u64,
        length: u64,
        protection: libc::c_int,
    ) -> std::result::Result<(), MapError>;

    /// Remove every mapping in `[address, address + length)`. Afterwards the
    /// range is unmapped: an access faults, and nothing of the removed
    /// mappings' contents is visible through any later mapping placed there
    /// (a later mapping shows its own backing: zeros for fresh anonymous
    /// memory, file data for a file mapping).
    fn unmap(&self, address: u64, length: u64) -> std::result::Result<(), MapError>;

    /// `MADV_DONTNEED` over `[address, address + length)`, with Linux's
    /// semantics: private anonymous pages read as zeros afterwards; private
    /// file pages read the file's current contents again; shared pages
    /// (shared anonymous memory and shared file mappings) keep their
    /// contents. Unmapped pages are skipped and reported in the result. An
    /// implementation that cannot provide this for some kind of mapping
    /// returns `Unsupported` before any page changes; which kinds, if any, is
    /// documented on the implementation.
    fn discard(&self, address: u64, length: u64) -> std::result::Result<Discarded, MapError>;
}
