/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! reverie-kvm's implementation of the provider memory interfaces
//! ([`GuestMemoryAccess`] and [`AddressSpace`], defined with their contracts
//! in Reverie's core as `reverie::provider`) for the KVM guest arena
//! ([`GuestMemory`]).
//!
//! The traits are step U1 of the minimal provider seam
//! (<https://github.com/rrnewton/hermit/issues/4659>), moved to their own
//! crate in step U6a and into Reverie's core in step E1. The syscall
//! executor's handlers are generic over them with the error type fixed to
//! [`crate::Error`].

pub use reverie::provider::Access;
pub use reverie::provider::AddressSpace;
pub use reverie::provider::Discarded;
pub use reverie::provider::GuestMemoryAccess;
pub use reverie::provider::LentOperand;
pub use reverie::provider::LentOperandMut;
pub use reverie::provider::MapError;
pub use reverie::provider::RangeState;
pub(crate) use reverie::provider::UserLayout;

use crate::GuestMemory;
use crate::Result;
use crate::memory::HostMemoryOperand;
use crate::memory::UserWriteAlias;

const PAGE_SIZE: u64 = 4096;

impl LentOperand for HostMemoryOperand {
    fn host_address(&self) -> usize {
        self.address()
    }
}

impl LentOperandMut for UserWriteAlias<'_> {
    type Error = crate::Error;

    fn host_pointer(&self) -> *mut libc::c_void {
        self.address()
    }

    fn finish(self) -> Result<()> {
        UserWriteAlias::finish(self)
    }
}

/// The crate-private view through which reverie-kvm's syscall provider uses
/// the guest arena as provider memory: the provider memory traits are
/// implemented on this view, not on the public [`GuestMemory`]. Code outside
/// reverie-kvm therefore cannot reach [`AddressSpace`]'s edits (or the lent
/// operands), which are only correct inside the executor's layout transaction
/// that dispatch holds. The view is a plain shared borrow, so handlers generic
/// over the traits still monomorphise to direct calls.
#[derive(Clone, Copy)]
pub struct ProviderMemory<'a>(pub &'a GuestMemory);

/// Today's implementation over the KVM guest arena. Each method delegates to
/// the existing `UserMemory` operation, which admits the copy through the
/// arena's entry gate; a gate failure poisons the gate, is returned as `Err`
/// and is raised as the run failure after dispatch, never as an errno.
///
/// Known deviations preserved from before U1:
/// - [`GuestMemoryAccess::write_exact`] checks that every byte is mapped and
///   accessible, not that it is writable, so it can store to a read-only page.
///   Handlers that need Linux's writability rule use
///   [`GuestMemoryAccess::copy_to_user`].
/// - [`GuestMemoryAccess::put_user_i16`] and [`GuestMemoryAccess::put_user_i32`]
///   refuse a destination on an ordinary shared-file page with the arena's
///   typed shared-file capability failure rather than storing.
impl GuestMemoryAccess for ProviderMemory<'_> {
    type Error = crate::Error;
    type Lent = HostMemoryOperand;
    type LentMut<'a>
        = UserWriteAlias<'a>
    where
        Self: 'a;

    fn read_exact(&self, address: u64, destination: &mut [u8]) -> Result<()> {
        self.0.user().read(address, destination)
    }

    /// No executor handler calls this yet.
    fn copy_from_user_prefix(&self, address: u64, destination: &mut [u8]) -> Result<usize> {
        self.0.user().copy_from_user_prefix(address, destination)
    }

    fn write_exact(&self, address: u64, source: &[u8]) -> Result<()> {
        self.0.user().write(address, source)
    }

    fn copy_to_user(&self, address: u64, source: &[u8]) -> Result<()> {
        self.0.user().copy_to_user(address, source)
    }

    fn copy_to_user_prefix(&self, address: u64, source: &[u8]) -> Result<usize> {
        self.0.user().copy_to_user_prefix(address, source)
    }

    fn put_user_i16(&self, address: u64, value: i16) -> Result<()> {
        self.0.user().put_user_i16(address, value)
    }

    fn put_user_i32(&self, address: u64, value: i32) -> Result<()> {
        self.0.user().put_user_i32(address, value)
    }

    fn put_user_u64(&self, address: u64, value: u64) -> Result<()> {
        self.0.user().store_user_u64(address, value)
    }

    fn accessible_prefix(&self, address: u64, length: usize, access: Access) -> Result<usize> {
        match access {
            Access::Read => self.0.user().user_accessible_prefix(address, length),
            Access::Write => self.0.user().user_writable_prefix(address, length),
        }
    }

    /// No executor handler performs a guest compare-exchange yet; futex words
    /// still go to the host kernel.
    fn compare_exchange_u32(&self, address: u64, current: u32, new: u32) -> Result<u32> {
        self.0.user().compare_exchange_u32(address, current, new)
    }

    fn lend(&self, address: u64, length: usize) -> Result<HostMemoryOperand> {
        self.0.user().host_operand(address, length)
    }

    fn lend_mut(&self, address: u64, length: usize) -> Result<UserWriteAlias<'_>> {
        self.0.writable_alias(address, length)
    }

    /// Executor handlers still check the limit through a numeric constant;
    /// `KvmGuest` reports the same constant.
    fn user_address_limit(&self) -> reverie::UserAddressLimit {
        crate::layout::GUEST_USER_ADDRESS_LIMIT
    }
}

/// Today's implementation over the KVM guest arena. User addresses are
/// translated to arena addresses here, and the edits run inside the layout
/// transaction the executor's dispatcher holds for every layout-changing
/// syscall.
///
/// Known deviations preserved from before U1:
/// - [`AddressSpace::protect`]'s `Unsupported` (`PROT_EXEC` on an ordinary
///   shared-file mapping) is recorded as the arena's typed shared-file
///   capability failure, but [`AddressSpace::discard`]'s `Unsupported` (a
///   private file mapping) is not recorded in the arena: `madvise` returns
///   `ENOSYS` with the executor's typed refusal alone.
/// - [`AddressSpace::unmap`] zeroes the range before it removes the mappings,
///   so a failure in the second step leaves the range mapped with zeroed
///   contents.
/// - [`AddressSpace::discard`] zeroes one run of contiguous pages at a time,
///   so a failure part way leaves earlier runs discarded.
///
/// Known deviation of the guard-region edits: a guard page faults every copy
/// through [`GuestMemoryAccess`], but not a direct guest access, since the
/// vCPU's page tables enforce no protection
/// (<https://github.com/rrnewton/hermit/issues/5177>).
impl AddressSpace for ProviderMemory<'_> {
    fn layout(&self) -> UserLayout {
        UserLayout {
            reserved_end: crate::bootstrap::BOOT_RESERVED_END,
        }
    }

    fn is_addressable(&self, address: u64, length: u64) -> bool {
        self.0.user_range_is_addressable(address, length)
    }

    fn query(&self, address: u64, length: u64) -> RangeState {
        let Some(physical) = self.0.user_range_to_guest(address, length) else {
            return RangeState::Unaddressable;
        };
        if self.0.user_range_is_mapped(physical, length) {
            RangeState::Mapped
        } else if self.0.user_range_has_mapping(physical, length) {
            RangeState::Mixed
        } else {
            RangeState::Unmapped
        }
    }

    fn protect(
        &self,
        address: u64,
        length: u64,
        protection: libc::c_int,
    ) -> std::result::Result<(), MapError> {
        // Linux applies mprotect(2) one mapping at a time and keeps what it
        // applied when it then fails (ENOMEM at a hole, EACCES at a mapping it
        // may not change), where this refuses the whole range first: on a
        // refusal, the part the page states lack is recorded.
        let refuse = |error| {
            self.0.note_user_mapping_change(address, length);
            Err(error)
        };
        let Some(address) = self.0.user_range_to_guest(address, length) else {
            return refuse(MapError::Unaddressable);
        };
        if !self.0.user_range_is_mapped(address, length) {
            return refuse(MapError::NotMapped);
        }
        if self.0.shares_parent_address_space()
            && self
                .0
                .range_contains_retained_shared(address, length as usize)
        {
            // On Linux a vfork child's mprotect changes its parent's view
            // too; this copy cannot, so the change is refused whole, by
            // name, a refusal the allocation owner publishes on unlock.
            let _ = self
                .0
                .capture_shared_file_error(GuestMemory::vfork_shared_view_change(
                    "mprotect in a vfork child",
                ));
            return refuse(MapError::Unsupported);
        }
        if protection & libc::PROT_EXEC != 0
            && self.0.range_contains_shared_file(address, length as usize)
        {
            // A metadata-only permission upgrade cannot establish the file's
            // mount noexec policy. Preserve the same named domain as mmap; the
            // allocation owner publishes this cause only after it unlocks.
            let _ = self
                .0
                .capture_shared_file_error(crate::Error::SharedFileCapability {
                    operation: "mprotect",
                    reason: "executable ordinary shared-file mappings are not implemented",
                });
            return refuse(MapError::Unsupported);
        }
        if protection & libc::PROT_WRITE != 0
            && !self.0.file_write_permitted(address, length as usize)
        {
            return refuse(MapError::AccessDenied);
        }
        // The pages keep the protection as declared. The bits were validated
        // by the caller, so they fit a byte.
        match self.0.protect_user_range(address, length, protection as u8) {
            Ok(()) => Ok(()),
            Err(_) => refuse(MapError::Failed),
        }
    }

    fn unmap(&self, address: u64, length: u64) -> std::result::Result<(), MapError> {
        let Some(address) = self.0.user_range_to_guest(address, length) else {
            return Err(MapError::Unaddressable);
        };
        let Ok(byte_length) = usize::try_from(length) else {
            return Err(MapError::Unaddressable);
        };
        self.0
            .zero_lazily(address, byte_length)
            .map_err(|_| MapError::Failed)?;
        self.0
            .unmap_user_range(address, length)
            .map_err(|_| MapError::Failed)
    }

    /// reverie-kvm cannot yet re-read a private file mapping's pages from the
    /// file, so a range holding one is `Unsupported` (KVM answers the guest's
    /// `madvise(MADV_DONTNEED)` with ENOSYS there), before any page changes.
    fn discard(&self, address: u64, length: u64) -> std::result::Result<Discarded, MapError> {
        let plan = self.0.dontneed_plan(address, length);
        if plan.private_file {
            return Err(MapError::Unsupported);
        }
        self.zero_private_pages(plan.private_anonymous)?;
        Ok(Discarded {
            had_holes: plan.unmapped,
        })
    }

    /// `Unsupported`, before any page changes, for a range holding a private
    /// file mapping's page, as [`AddressSpace::discard`] is, and in a vfork
    /// child, which shares its parent's address space on Linux but runs on a
    /// copy here, as `protect` refuses a shared view's change there. The
    /// guard is kept in the page's state, which every copy through
    /// [`GuestMemoryAccess`] consults. The vCPU's page tables do not enforce
    /// it, as they enforce no protection: a direct guest access to a guard
    /// page does not fault (<https://github.com/rrnewton/hermit/issues/5177>).
    fn guard_install(&self, address: u64, length: u64) -> std::result::Result<Discarded, MapError> {
        self.change_guards(address, length, true)
    }

    /// `Unsupported` in a vfork child, as [`AddressSpace::guard_install`] is.
    /// A private file mapping's page is never a guard page here, so a removal
    /// over one leaves it as it is.
    fn guard_remove(&self, address: u64, length: u64) -> std::result::Result<Discarded, MapError> {
        self.change_guards(address, length, false)
    }
}

impl ProviderMemory<'_> {
    /// Zero each run of physically contiguous pages of `pages` (ascending
    /// physical addresses) with zero_lazily, so a large run (node drops its
    /// whole 512 MiB V8 reservation) is discarded rather than written and
    /// made resident (<https://github.com/rrnewton/reverie/issues/1058>).
    fn zero_private_pages(&self, pages: Vec<u64>) -> std::result::Result<(), MapError> {
        let page_size = PAGE_SIZE;
        let mut run: Option<(u64, u64)> = None;
        for page in pages {
            match run {
                Some((start, length)) if start + length == page => {
                    run = Some((start, length + page_size));
                }
                _ => {
                    if let Some((start, length)) = run.replace((page, page_size)) {
                        self.0
                            .zero_lazily(start, length as usize)
                            .map_err(|_| MapError::Failed)?;
                    }
                }
            }
        }
        if let Some((start, length)) = run {
            self.0
                .zero_lazily(start, length as usize)
                .map_err(|_| MapError::Failed)?;
        }
        Ok(())
    }

    /// [`AddressSpace::guard_install`] with `guard`, otherwise
    /// [`AddressSpace::guard_remove`].
    fn change_guards(
        &self,
        address: u64,
        length: u64,
        guard: bool,
    ) -> std::result::Result<Discarded, MapError> {
        if self.0.shares_parent_address_space() {
            return Err(MapError::Unsupported);
        }
        let change = self.0.set_user_guards(address, length, guard);
        if change.private_file {
            return Err(MapError::Unsupported);
        }
        self.zero_private_pages(change.private_anonymous)?;
        Ok(Discarded {
            had_holes: change.unmapped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = PAGE_SIZE as usize;
    /// Three pages at 0x1000: read-write, read-only, then unmapped.
    const RW: u64 = 0x1000;
    const RO: u64 = RW + PAGE_SIZE;
    const UNMAPPED: u64 = RO + PAGE_SIZE;

    fn memory() -> GuestMemory {
        let memory = GuestMemory::new(RW, 3 * PAGE).unwrap();
        memory.write_raw(RW, &vec![0xa5; 3 * PAGE]).unwrap();
        memory
            .map_user_permissions(RW, PAGE_SIZE, true, true)
            .unwrap();
        memory
            .map_user_permissions(RO, PAGE_SIZE, true, false)
            .unwrap();
        memory.enable_user_access();
        memory
    }

    fn bytes(memory: &GuestMemory, address: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        memory.read_raw(address, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn whole_copies_are_all_or_nothing() {
        let memory = memory();
        let mut buffer = [0; 8];
        GuestMemoryAccess::read_exact(&ProviderMemory(&memory), RO - 4, &mut buffer).unwrap();
        assert_eq!(buffer, [0xa5; 8]);
        assert!(
            GuestMemoryAccess::read_exact(&ProviderMemory(&memory), UNMAPPED - 4, &mut buffer)
                .is_err()
        );
        GuestMemoryAccess::write_exact(&ProviderMemory(&memory), RW, b"abcd").unwrap();
        assert_eq!(bytes(&memory, RW, 4), b"abcd");
        assert!(
            GuestMemoryAccess::write_exact(&ProviderMemory(&memory), UNMAPPED - 2, b"wxyz")
                .is_err()
        );
        assert_eq!(bytes(&memory, UNMAPPED - 2, 2), [0xa5; 2]);
    }

    #[test]
    fn copy_to_user_keeps_the_writable_prefix() {
        let memory = memory();
        assert!(
            GuestMemoryAccess::copy_to_user(&ProviderMemory(&memory), RO - 2, b"wxyz").is_err()
        );
        assert_eq!(bytes(&memory, RO - 2, 4), [b'w', b'x', 0xa5, 0xa5]);
        assert_eq!(
            GuestMemoryAccess::copy_to_user_prefix(&ProviderMemory(&memory), RO - 3, b"123456")
                .unwrap(),
            3
        );
        assert_eq!(bytes(&memory, RO - 3, 4), [b'1', b'2', b'3', 0xa5]);
        let mut buffer = [0; 6];
        assert_eq!(
            ProviderMemory(&memory)
                .copy_from_user_prefix(UNMAPPED - 2, &mut buffer)
                .unwrap(),
            2
        );
        assert_eq!(buffer[..2], [0xa5; 2]);
    }

    #[test]
    fn put_user_stores_whole_scalars_on_writable_pages_only() {
        let memory = memory();
        GuestMemoryAccess::put_user_i16(&ProviderMemory(&memory), RW, 0x0102).unwrap();
        GuestMemoryAccess::put_user_i32(&ProviderMemory(&memory), RW + 4, 0x0304_0506).unwrap();
        GuestMemoryAccess::put_user_u64(&ProviderMemory(&memory), RW + 8, 0x0708_090a_0b0c_0d0e)
            .unwrap();
        assert_eq!(bytes(&memory, RW, 2), 0x0102_i16.to_ne_bytes());
        assert_eq!(bytes(&memory, RW + 4, 4), 0x0304_0506_i32.to_ne_bytes());
        assert_eq!(
            bytes(&memory, RW + 8, 8),
            0x0708_090a_0b0c_0d0e_u64.to_ne_bytes()
        );
        assert!(GuestMemoryAccess::put_user_u64(&ProviderMemory(&memory), RO - 4, 0).is_err());
        assert_eq!(bytes(&memory, RO - 4, 8), [0xa5; 8]);
        assert!(GuestMemoryAccess::put_user_i32(&ProviderMemory(&memory), RO, 0).is_err());
        assert!(GuestMemoryAccess::put_user_i16(&ProviderMemory(&memory), RO, 0).is_err());
        assert_eq!(bytes(&memory, RO, 4), [0xa5; 4]);
    }

    #[test]
    fn accessible_prefix_distinguishes_read_and_write() {
        let memory = memory();
        let length = 2 * PAGE + 16;
        assert_eq!(
            GuestMemoryAccess::accessible_prefix(
                &ProviderMemory(&memory),
                RW,
                length,
                Access::Read
            )
            .unwrap(),
            2 * PAGE
        );
        assert_eq!(
            GuestMemoryAccess::accessible_prefix(
                &ProviderMemory(&memory),
                RW,
                length,
                Access::Write
            )
            .unwrap(),
            PAGE
        );
        assert_eq!(
            GuestMemoryAccess::accessible_prefix(&ProviderMemory(&memory), RW, 0, Access::Write)
                .unwrap(),
            0
        );
    }

    #[test]
    fn compare_exchange_is_conditional_and_checked() {
        let memory = memory();
        GuestMemoryAccess::put_user_i32(&ProviderMemory(&memory), RW + 8, 7).unwrap();
        assert_eq!(
            GuestMemoryAccess::compare_exchange_u32(&ProviderMemory(&memory), RW + 8, 7, 9)
                .unwrap(),
            7
        );
        assert_eq!(bytes(&memory, RW + 8, 4), 9_u32.to_ne_bytes());
        assert_eq!(
            GuestMemoryAccess::compare_exchange_u32(&ProviderMemory(&memory), RW + 8, 7, 11)
                .unwrap(),
            9
        );
        assert_eq!(bytes(&memory, RW + 8, 4), 9_u32.to_ne_bytes());
        assert!(
            GuestMemoryAccess::compare_exchange_u32(&ProviderMemory(&memory), RW + 10, 9, 1)
                .is_err()
        );
        assert!(
            GuestMemoryAccess::compare_exchange_u32(&ProviderMemory(&memory), RO, 0xa5a5_a5a5, 1)
                .is_err()
        );
        assert!(
            ProviderMemory(&memory)
                .compare_exchange_u32(UNMAPPED, 0xa5a5_a5a5, 1)
                .is_err()
        );
        assert_eq!(bytes(&memory, RO, 4), [0xa5; 4]);
    }

    #[test]
    fn lent_operands_name_the_guest_bytes() {
        let memory = memory();
        assert!(GuestMemoryAccess::lend(&ProviderMemory(&memory), UNMAPPED, 4).is_err());
        let operand = GuestMemoryAccess::lend(&ProviderMemory(&memory), RW + 16, 4).unwrap();
        assert_ne!(LentOperand::host_address(&operand), 0);
        drop(operand);

        let mut fds = [0; 2];
        // SAFETY: fds is writable for two descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the source is three initialized bytes.
        assert_eq!(unsafe { libc::write(fds[1], b"xyz".as_ptr().cast(), 3) }, 3);
        let view = ProviderMemory(&memory);
        let operand = GuestMemoryAccess::lend_mut(&view, RW + 32, 3).unwrap();
        // SAFETY: the lent operand is a host output buffer of three bytes.
        let read = unsafe { libc::read(fds[0], LentOperandMut::host_pointer(&operand), 3) };
        assert_eq!(read, 3);
        LentOperandMut::finish(operand).unwrap();
        // SAFETY: both descriptors are owned by this test.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert_eq!(bytes(&memory, RW + 32, 3), b"xyz");
        assert_eq!(
            ProviderMemory(&memory).user_address_limit(),
            crate::layout::GUEST_USER_ADDRESS_LIMIT
        );
    }

    #[test]
    fn address_space_queries_and_edits() {
        let memory = memory();
        assert_eq!(
            ProviderMemory(&memory).layout().reserved_end,
            crate::bootstrap::BOOT_RESERVED_END
        );
        assert!(ProviderMemory(&memory).is_addressable(RW, 3 * PAGE_SIZE));
        assert_eq!(
            ProviderMemory(&memory).query(RW, 2 * PAGE_SIZE),
            RangeState::Mapped
        );
        assert_eq!(
            ProviderMemory(&memory).query(RO, 2 * PAGE_SIZE),
            RangeState::Mixed
        );
        assert_eq!(
            ProviderMemory(&memory).query(UNMAPPED, PAGE_SIZE),
            RangeState::Unmapped
        );
        assert_eq!(
            ProviderMemory(&memory).query(u64::MAX - PAGE_SIZE, PAGE_SIZE),
            RangeState::Unaddressable
        );
        assert!(!ProviderMemory(&memory).is_addressable(u64::MAX - PAGE_SIZE, PAGE_SIZE));

        assert!(matches!(
            ProviderMemory(&memory).protect(UNMAPPED, PAGE_SIZE, libc::PROT_READ),
            Err(MapError::NotMapped)
        ));
        ProviderMemory(&memory)
            .protect(RO, PAGE_SIZE, libc::PROT_READ | libc::PROT_WRITE)
            .unwrap();
        GuestMemoryAccess::copy_to_user(&ProviderMemory(&memory), RO, b"ok").unwrap();
        ProviderMemory(&memory)
            .protect(RW, PAGE_SIZE, libc::PROT_READ)
            .unwrap();
        assert!(GuestMemoryAccess::copy_to_user(&ProviderMemory(&memory), RW, b"no").is_err());

        let discarded = ProviderMemory(&memory).discard(RO, 2 * PAGE_SIZE).unwrap();
        assert!(discarded.had_holes);
        assert_eq!(bytes(&memory, RO, 4), [0; 4]);

        ProviderMemory(&memory).unmap(RO, PAGE_SIZE).unwrap();
        assert_eq!(
            ProviderMemory(&memory).query(RO, PAGE_SIZE),
            RangeState::Unmapped
        );
        assert!(matches!(
            ProviderMemory(&memory).unmap(u64::MAX - PAGE_SIZE, PAGE_SIZE),
            Err(MapError::Unaddressable)
        ));
    }

    /// Four declared read-write private anonymous pages from `RW`, filled
    /// with 0xa5, and nothing mapped after them.
    fn guard_memory() -> GuestMemory {
        let memory = GuestMemory::new(RW, 5 * PAGE).unwrap();
        memory.write_raw(RW, &vec![0xa5; 5 * PAGE]).unwrap();
        memory
            .map_user_protection(
                RW,
                4 * PAGE_SIZE,
                (libc::PROT_READ | libc::PROT_WRITE) as u8,
            )
            .unwrap();
        memory.enable_user_access();
        memory
    }

    fn readable(memory: &GuestMemory, address: u64) -> bool {
        let mut byte = [0];
        GuestMemoryAccess::read_exact(&ProviderMemory(memory), address, &mut byte).is_ok()
    }

    fn writable(memory: &GuestMemory, address: u64) -> bool {
        GuestMemoryAccess::accessible_prefix(&ProviderMemory(memory), address, 1, Access::Write)
            .unwrap()
            == 1
    }

    /// A guard page's contents go, every copy to or from it faults, and its
    /// mapping (protection, extent) is unchanged, as with Linux's guard
    /// markers (`madvise_guard_install`, mm/madvise.c in v6.17).
    #[test]
    fn a_guard_discards_the_page_and_faults_every_copy_but_keeps_the_mapping() {
        let memory = guard_memory();
        let declared = memory.declared_mapping(RW + PAGE_SIZE);
        let view = ProviderMemory(&memory);
        assert_eq!(
            view.guard_install(RW + PAGE_SIZE, PAGE_SIZE).unwrap(),
            Discarded { had_holes: false }
        );
        assert!(memory.is_guard_page(RW + PAGE_SIZE));
        assert_eq!(bytes(&memory, RW + PAGE_SIZE, 8), [0; 8]);
        assert!(!readable(&memory, RW + PAGE_SIZE));
        assert!(!writable(&memory, RW + PAGE_SIZE));
        assert!(GuestMemoryAccess::write_exact(&view, RW + PAGE_SIZE, b"x").is_err());
        assert!(GuestMemoryAccess::put_user_i32(&view, RW + PAGE_SIZE, 1).is_err());
        assert!(GuestMemoryAccess::lend(&view, RW + PAGE_SIZE, 4).is_err());
        // A copy that runs into the guard stops at it.
        assert_eq!(
            GuestMemoryAccess::accessible_prefix(&view, RW, 2 * PAGE, Access::Read).unwrap(),
            PAGE
        );
        // The neighbours keep their contents and access.
        assert_eq!(bytes(&memory, RW, 4), [0xa5; 4]);
        assert!(writable(&memory, RW) && writable(&memory, RW + 2 * PAGE_SIZE));
        // The mapping is the same mapping: no split, no protection change.
        assert_eq!(memory.declared_mapping(RW + PAGE_SIZE), declared);
        assert_eq!(view.query(RW, 4 * PAGE_SIZE), RangeState::Mapped);
        // A second install changes nothing.
        view.guard_install(RW + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert!(memory.is_guard_page(RW + PAGE_SIZE));
    }

    /// Install and remove apply to the mapped part of a range with holes and
    /// report the hole, as `madvise_walk_vmas` does (ENOMEM).
    #[test]
    fn a_guard_over_a_hole_applies_to_the_mapped_pages_and_reports_it() {
        let memory = guard_memory();
        let view = ProviderMemory(&memory);
        assert_eq!(
            view.guard_install(RW + 3 * PAGE_SIZE, 2 * PAGE_SIZE)
                .unwrap(),
            Discarded { had_holes: true }
        );
        assert!(memory.is_guard_page(RW + 3 * PAGE_SIZE));
        assert_eq!(
            view.guard_remove(RW + 3 * PAGE_SIZE, 2 * PAGE_SIZE)
                .unwrap(),
            Discarded { had_holes: true }
        );
        assert!(!memory.is_guard_page(RW + 3 * PAGE_SIZE));
        assert!(writable(&memory, RW + 3 * PAGE_SIZE));
    }

    /// A guard stays through `MADV_DONTNEED` and through a protection change,
    /// which sets the access the page gets back when the guard goes
    /// (`change_pte_range` in mm/mprotect.c skips guard markers; a zap without
    /// `ZAP_FLAG_DROP_MARKER` keeps them).
    #[test]
    fn a_guard_survives_discard_and_protect() {
        let memory = guard_memory();
        let view = ProviderMemory(&memory);
        view.guard_install(RW, PAGE_SIZE).unwrap();
        view.discard(RW, 2 * PAGE_SIZE).unwrap();
        assert!(memory.is_guard_page(RW));
        view.protect(RW, 2 * PAGE_SIZE, libc::PROT_READ).unwrap();
        assert!(memory.is_guard_page(RW));
        assert!(!readable(&memory, RW));
        assert_eq!(
            memory.declared_mapping(RW).map(|declared| declared.prot),
            Some(libc::PROT_READ as u8)
        );
        view.guard_remove(RW, PAGE_SIZE).unwrap();
        assert!(readable(&memory, RW));
        assert!(!writable(&memory, RW));
        view.protect(RW, PAGE_SIZE, libc::PROT_NONE).unwrap();
        view.guard_install(RW, PAGE_SIZE).unwrap();
        view.guard_remove(RW, PAGE_SIZE).unwrap();
        assert!(!readable(&memory, RW));
    }

    /// Removing a guard gives a private anonymous page back empty: no access
    /// could fill it on Linux, so whatever reached it here (a direct store,
    /// which this backend's page tables do not stop) is gone.
    #[test]
    fn a_removed_guard_leaves_a_private_page_empty() {
        let memory = guard_memory();
        let view = ProviderMemory(&memory);
        view.guard_install(RW, PAGE_SIZE).unwrap();
        memory.write_raw(RW, b"stray").unwrap();
        view.guard_remove(RW, PAGE_SIZE).unwrap();
        assert_eq!(bytes(&memory, RW, 5), [0; 5]);
        // Removing where there is no guard changes no contents.
        memory.write_raw(RW + PAGE_SIZE, b"kept").unwrap();
        view.guard_remove(RW + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(bytes(&memory, RW + PAGE_SIZE, 4), b"kept");
    }

    /// A shared page keeps its object's contents under a guard and after it,
    /// as Linux zaps only the page-table entry.
    #[test]
    fn a_guard_keeps_shared_contents() {
        let memory = guard_memory();
        memory.record_page_backing(RW, PAGE_SIZE, None, true);
        let view = ProviderMemory(&memory);
        view.guard_install(RW, PAGE_SIZE).unwrap();
        assert_eq!(bytes(&memory, RW, 4), [0xa5; 4]);
        assert!(!readable(&memory, RW));
        view.guard_remove(RW, PAGE_SIZE).unwrap();
        assert_eq!(bytes(&memory, RW, 4), [0xa5; 4]);
        assert!(writable(&memory, RW));
    }

    /// Unmapping a guard page, or mapping over it, ends the guard
    /// (`unmap_vmas` drops markers with `ZAP_FLAG_DROP_MARKER`).
    #[test]
    fn unmap_and_a_new_mapping_end_a_guard() {
        let memory = guard_memory();
        let view = ProviderMemory(&memory);
        view.guard_install(RW, 2 * PAGE_SIZE).unwrap();
        view.unmap(RW, PAGE_SIZE).unwrap();
        assert!(!memory.is_guard_page(RW));
        memory
            .map_user_protection(RW, 2 * PAGE_SIZE, libc::PROT_READ as u8)
            .unwrap();
        assert!(!memory.is_guard_page(RW + PAGE_SIZE));
        assert!(readable(&memory, RW) && readable(&memory, RW + PAGE_SIZE));
    }

    /// A move keeps the guard on the pages it moves, and the pages a grow
    /// adds are new pages without one (`move_ptes` moves markers).
    #[test]
    fn a_remap_moves_the_guard_and_grows_without_it() {
        let memory = guard_memory();
        ProviderMemory(&memory)
            .guard_install(RW + PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        memory
            .remap_user_range(RW, 2 * PAGE_SIZE, RW + 2 * PAGE_SIZE, 3 * PAGE_SIZE)
            .unwrap();
        assert!(!memory.is_guard_page(RW + PAGE_SIZE));
        assert!(memory.is_guard_page(RW + 3 * PAGE_SIZE));
        assert!(!memory.is_guard_page(RW + 4 * PAGE_SIZE));
        assert!(readable(&memory, RW + 4 * PAGE_SIZE));
    }

    /// A fork's copy keeps the guards, on private and on shared pages, as
    /// Linux copies guard markers into the child (`copy_nonpresent_pte`).
    #[test]
    fn a_fork_copies_the_guards() {
        let memory = guard_memory();
        memory.record_page_backing(RW + 2 * PAGE_SIZE, PAGE_SIZE, None, true);
        let view = ProviderMemory(&memory);
        view.guard_install(RW, PAGE_SIZE).unwrap();
        view.guard_install(RW + 2 * PAGE_SIZE, PAGE_SIZE).unwrap();
        let child = memory.snapshot().unwrap();
        for copy in [&memory, &child] {
            assert!(copy.is_guard_page(RW));
            assert!(!copy.is_guard_page(RW + PAGE_SIZE));
            assert!(copy.is_guard_page(RW + 2 * PAGE_SIZE));
            assert!(!readable(copy, RW) && !readable(copy, RW + 2 * PAGE_SIZE));
        }
        ProviderMemory(&child).guard_remove(RW, PAGE_SIZE).unwrap();
        assert!(memory.is_guard_page(RW));
        assert!(!child.is_guard_page(RW));
    }

    /// A vfork child runs on a copy of an address space it shares with its
    /// parent on Linux, so its guard changes are refused before anything
    /// changes, as its changes to a shared view are.
    #[test]
    fn a_vfork_child_cannot_change_guards() {
        let memory = guard_memory();
        let child = memory.snapshot_sharing_address_space().unwrap();
        assert!(matches!(
            ProviderMemory(&child).guard_install(RW, PAGE_SIZE),
            Err(MapError::Unsupported)
        ));
        assert!(matches!(
            ProviderMemory(&child).guard_remove(RW, PAGE_SIZE),
            Err(MapError::Unsupported)
        ));
        assert!(!child.is_guard_page(RW) && !memory.is_guard_page(RW));
        assert_eq!(bytes(&child, RW, 4), [0xa5; 4]);
    }

    /// A private file page cannot be read from its file again when the guard
    /// goes, so an install over a range holding one is refused before
    /// anything changes; such a page is then never a guard page, and a
    /// removal over it leaves it alone.
    #[test]
    fn a_guard_over_a_private_file_page_is_refused_whole() {
        let memory = guard_memory();
        memory.record_file_pages(RW + PAGE_SIZE, PAGE_SIZE, Some(0));
        let view = ProviderMemory(&memory);
        assert!(matches!(
            view.guard_install(RW, 2 * PAGE_SIZE),
            Err(MapError::Unsupported)
        ));
        assert!(!memory.is_guard_page(RW));
        assert_eq!(bytes(&memory, RW, 4), [0xa5; 4]);
        view.guard_install(RW, PAGE_SIZE).unwrap();
        assert_eq!(
            view.guard_remove(RW, 2 * PAGE_SIZE).unwrap(),
            Discarded { had_holes: false }
        );
        assert!(!memory.is_guard_page(RW));
        assert!(readable(&memory, RW + PAGE_SIZE));
    }
}
