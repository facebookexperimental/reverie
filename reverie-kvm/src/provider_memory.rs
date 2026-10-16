/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! reverie-kvm's implementation of the provider memory interfaces
//! ([`GuestMemoryAccess`] and [`AddressSpace`], defined with their contracts
//! in the reverie-linux-provider crate) for the KVM guest arena
//! ([`GuestMemory`]).
//!
//! The traits are step U1 of the minimal provider seam
//! (<https://github.com/rrnewton/hermit/issues/4485>, epic
//! <https://github.com/rrnewton/hermit/issues/4492>) and moved to their own
//! crate in step U6a. The syscall executor's handlers are generic over them
//! with the error type fixed to [`crate::Error`].

pub(crate) use reverie_linux_provider::Access;
pub(crate) use reverie_linux_provider::AddressSpace;
pub(crate) use reverie_linux_provider::Discarded;
pub(crate) use reverie_linux_provider::GuestMemoryAccess;
pub(crate) use reverie_linux_provider::LentOperand;
pub(crate) use reverie_linux_provider::LentOperandMut;
pub(crate) use reverie_linux_provider::MapError;
pub(crate) use reverie_linux_provider::RangeState;
pub(crate) use reverie_linux_provider::UserLayout;

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
pub(crate) struct ProviderMemory<'a>(pub(crate) &'a GuestMemory);

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

    /// No executor handler calls this yet: its only candidate caller, the
    /// random-device write, still needs the arena's copy-failure check.
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
        crate::executor::GUEST_USER_ADDRESS_LIMIT
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
///   private file mapping) is not recorded anywhere: `madvise` returns
///   `ENOSYS` with no typed refusal.
/// - [`AddressSpace::unmap`] zeroes the range before it removes the mappings,
///   so a failure in the second step leaves the range mapped with zeroed
///   contents.
/// - [`AddressSpace::discard`] zeroes one run of contiguous pages at a time,
///   so a failure part way leaves earlier runs discarded.
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
        let Some(address) = self.0.user_range_to_guest(address, length) else {
            return Err(MapError::Unaddressable);
        };
        if !self.0.user_range_is_mapped(address, length) {
            return Err(MapError::NotMapped);
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
            return Err(MapError::Unsupported);
        }
        if protection & libc::PROT_WRITE != 0
            && !self.0.file_write_permitted(address, length as usize)
        {
            return Err(MapError::AccessDenied);
        }
        self.0
            .map_user_permissions(
                address,
                length,
                protection != libc::PROT_NONE,
                protection & libc::PROT_WRITE != 0,
            )
            .map_err(|_| MapError::Failed)
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
        // Zero each run of physically contiguous pages with zero_lazily, so a
        // large run (node drops its whole 512 MiB V8 reservation) is discarded
        // rather than written and made resident
        // (https://github.com/rrnewton/reverie/issues/1058).
        let page_size = PAGE_SIZE;
        let mut run: Option<(u64, u64)> = None;
        for page in plan.private_anonymous {
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
        Ok(Discarded {
            had_holes: plan.unmapped,
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
            crate::executor::GUEST_USER_ADDRESS_LIMIT
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
}
