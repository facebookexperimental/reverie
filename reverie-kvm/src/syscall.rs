/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

use crate::Error;
use crate::GuestMemory;
use crate::Result;

const WORD_SIZE: usize = std::mem::size_of::<u64>();
const REQUEST_WORDS: usize = 7;
pub(crate) const RESULT_WORD: usize = 7;
pub(crate) const RETURN_RIP_WORD: usize = 8;
pub(crate) const RETURN_FLAGS_WORD: usize = 9;
pub(crate) const SAVED_RBX_WORD: usize = 10;
/// Nonzero when the trampoline must return with IRETQ rather than SYSRETQ,
/// because the staged user context has RCX/R11 values that SYSRETQ would
/// replace with RIP/RFLAGS (see `stage_process_signal_return`).
pub(crate) const FULL_RETURN_WORD: usize = 11;
pub(crate) const RETURN_RCX_WORD: usize = 12;
pub(crate) const RETURN_R11_WORD: usize = 13;
/// The five-word IRETQ frame (RIP, CS, RFLAGS, RSP, SS) for a full return.
pub(crate) const IRET_FRAME_WORD: usize = 14;
const FRAME_WORDS: usize = 19;
pub(crate) const FRAME_SIZE: usize = WORD_SIZE * FRAME_WORDS;

/// A Linux syscall request transported from guest to host memory.
///
/// Since step U6a of the provider seam this wraps the provider-neutral
/// [`reverie::provider::SyscallRequest`] (`repr(transparent)`), so the
/// backend hands a request to a provider by reference, with no copy, while
/// reverie-kvm's public API stays inherent and unchanged. `Debug` prints the
/// wrapped request, which has the same name and fields as before.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct SyscallRequest(reverie::provider::SyscallRequest);

impl std::fmt::Debug for SyscallRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, formatter)
    }
}

impl SyscallRequest {
    /// Creates a request from a Linux syscall number and its six ABI arguments.
    pub const fn new(number: u64, args: [u64; 6]) -> Self {
        Self(reverie::provider::SyscallRequest::new(number, args))
    }

    /// Creates a transport request from a shared Reverie syscall.
    pub fn from_syscall<S: SyscallInfo>(syscall: S) -> Self {
        Self(reverie::provider::SyscallRequest::from_syscall(syscall))
    }

    /// Returns the Linux syscall number.
    pub const fn number(&self) -> u64 {
        self.0.number()
    }

    /// Returns the six Linux syscall arguments.
    pub const fn args(&self) -> &[u64; 6] {
        self.0.args()
    }

    /// The provider-neutral request this wraps, for a provider call.
    pub(crate) const fn as_provider(&self) -> &reverie::provider::SyscallRequest {
        &self.0
    }

    /// Views a provider-neutral request as reverie-kvm's request, without a
    /// copy.
    pub(crate) fn from_provider(request: &reverie::provider::SyscallRequest) -> &Self {
        // SAFETY: `SyscallRequest` is `repr(transparent)` over
        // `reverie::provider::SyscallRequest`, so both have the same
        // layout and alignment, and the returned reference borrows `request`.
        unsafe { &*std::ptr::from_ref(request).cast::<Self>() }
    }

    /// Decodes this raw transport frame through Reverie's complete syscall table.
    ///
    /// A number outside the architecture syscall table is rejected instead of
    /// being forwarded as an untyped request.
    pub fn into_syscall(self) -> Result<Syscall> {
        let number = usize::try_from(self.number())
            .ok()
            .and_then(Sysno::new)
            .ok_or(Error::InvalidSyscallNumber(self.number()))?;
        let args = self.args().map(|argument| argument as usize);
        Ok(Syscall::from_raw(
            number,
            SyscallArgs::new(args[0], args[1], args[2], args[3], args[4], args[5]),
        ))
    }

    /// Encodes the request at a guest-physical address.
    pub fn write_to(self, memory: &mut GuestMemory, guest_address: u64) -> Result<()> {
        let mut frame = [0; FRAME_SIZE];
        let words = [
            self.number(),
            self.args()[0],
            self.args()[1],
            self.args()[2],
            self.args()[3],
            self.args()[4],
            self.args()[5],
        ];
        for (index, value) in words.into_iter().enumerate() {
            let start = index * WORD_SIZE;
            frame[start..start + WORD_SIZE].copy_from_slice(&value.to_le_bytes());
        }
        memory.write(guest_address, &frame)
    }

    pub(crate) fn read_from(memory: &GuestMemory, guest_address: u64) -> Result<Self> {
        let mut frame = [0; FRAME_SIZE];
        memory.read_raw(guest_address, &mut frame)?;
        let mut words = [0; REQUEST_WORDS];
        for (index, value) in words.iter_mut().enumerate() {
            let start = index * WORD_SIZE;
            *value = u64::from_le_bytes(frame[start..start + WORD_SIZE].try_into().unwrap());
        }
        Ok(Self::new(
            words[0],
            [words[1], words[2], words[3], words[4], words[5], words[6]],
        ))
    }

    pub(crate) fn write_result(
        memory: &mut GuestMemory,
        guest_address: u64,
        result: i64,
    ) -> Result<()> {
        memory.write_raw(
            guest_address + (RESULT_WORD * WORD_SIZE) as u64,
            &result.to_le_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_syscall_round_trips_through_transport() {
        let typed = reverie::syscalls::Write::new()
            .with_fd(1)
            .with_buf(Some(reverie::syscalls::Addr::from_raw(0x3000).unwrap()))
            .with_len(5);
        let request = SyscallRequest::from_syscall(typed);

        assert_eq!(request.number(), libc::SYS_write as u64);
        assert_eq!(request.into_syscall().unwrap(), typed.into());
    }

    #[test]
    fn syscall_frame_round_trips_through_guest_memory() {
        let request = SyscallRequest::new(1, [1, 0x3000, 5, 4, 5, 6]);
        let mut memory = GuestMemory::new(0, 4096).unwrap();

        request.write_to(&mut memory, 0x100).unwrap();

        assert_eq!(SyscallRequest::read_from(&memory, 0x100).unwrap(), request);
    }

    #[test]
    fn decodes_every_x86_64_syscall_number() {
        for number in Sysno::iter().chain(std::iter::once(Sysno::last())) {
            let syscall = SyscallRequest::new(number.id() as u64, [0; 6])
                .into_syscall()
                .unwrap();
            assert_eq!(syscall.number(), number);
        }
    }

    #[test]
    fn decodes_required_syscall_variants() {
        let decode = |number: Sysno| {
            SyscallRequest::new(number.id() as u64, [0; 6])
                .into_syscall()
                .unwrap()
        };

        assert!(matches!(decode(Sysno::read), Syscall::Read(_)));
        assert!(matches!(decode(Sysno::write), Syscall::Write(_)));
        assert!(matches!(decode(Sysno::open), Syscall::Open(_)));
        assert!(matches!(decode(Sysno::close), Syscall::Close(_)));
        assert!(matches!(decode(Sysno::mmap), Syscall::Mmap(_)));
        assert!(matches!(decode(Sysno::munmap), Syscall::Munmap(_)));
        assert!(matches!(decode(Sysno::brk), Syscall::Brk(_)));
        assert!(matches!(decode(Sysno::ioctl), Syscall::Ioctl(_)));
    }

    #[test]
    fn rejects_unknown_syscall_number() {
        let error = SyscallRequest::new(u64::MAX, [0; 6])
            .into_syscall()
            .unwrap_err();
        assert!(matches!(error, Error::InvalidSyscallNumber(u64::MAX)));
    }
}
