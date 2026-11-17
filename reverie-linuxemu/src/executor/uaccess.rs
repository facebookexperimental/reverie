/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Copying values in and out of guest memory (gVisor: pkg/usermem).

use super::*;

pub(super) fn write_u64<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    address: u64,
    value: u64,
) -> i64 {
    write_bytes(memory, address, &value.to_le_bytes())
}

pub(super) fn write_bytes<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    address: u64,
    bytes: &[u8],
) -> i64 {
    match memory.write_exact(address, bytes) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

mod guest_out_sealed {
    pub trait Sealed {}
}

/// A type whose initialized bytes may be copied verbatim to guest memory
/// (outbound direction only; inbound copies stay on `read_guest_struct`
/// until their own contract lands).
///
/// # Safety
///
/// Implementing this trait asserts all of the following for `Self`:
/// - `Self` has a fixed guest ABI layout on the x86_64 guest: a
///   primitive integer, a `repr(C)` or `repr(C, packed)` struct, or
///   an array of admitted types.
/// - `Self` has no implicit padding: every byte of
///   `size_of::<Self>()` belongs to a named field. Each admitted
///   struct carries a const assert in this module that proves it.
/// - Every value that safe code can construct has all bytes
///   initialised. Fields that may be uninitialised (libc `Padding`
///   or `MaybeUninit`) must be unreachable from safe construction.
///   The unsafe constructor (`zeroed`, `assume_init` after a host
///   fill) must initialise them.
/// - Raw-pointer fields hold guest addresses at every write site.
///   The conversion point (for example `GuestMsghdr::from`) is where
///   review checks provenance.
/// - Outbound only. Admitted types happen to be valid for every bit
///   pattern, but inbound copies get their own contract.
///
/// The trait is sealed: the admitted set is closed and each impl below
/// is the audit point. Widening it takes a new impl here, reviewed
/// against the contract above — never a call-site workaround.
pub(super) unsafe trait GuestOut: guest_out_sealed::Sealed {}

// SAFETY: integer scalars are ABI plain data with no padding and no
// validity invariant beyond their bit patterns.
impl guest_out_sealed::Sealed for u8 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for u8 {}
impl guest_out_sealed::Sealed for i8 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for i8 {}
impl guest_out_sealed::Sealed for u16 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for u16 {}
impl guest_out_sealed::Sealed for i16 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for i16 {}
impl guest_out_sealed::Sealed for u32 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for u32 {}
impl guest_out_sealed::Sealed for i32 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for i32 {}
impl guest_out_sealed::Sealed for u64 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for u64 {}
impl guest_out_sealed::Sealed for i64 {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for i64 {}
impl guest_out_sealed::Sealed for usize {}
// SAFETY: see the scalar contract above. The one production use writes
// a guest-width length on the 64-bit guest this executor serves.
unsafe impl GuestOut for usize {}
impl guest_out_sealed::Sealed for isize {}
// SAFETY: see the scalar contract above.
unsafe impl GuestOut for isize {}

// SAFETY: an array of admitted values is contiguous admitted elements
// with no additional padding, so the contract composes element-wise.
impl<T: GuestOut, const N: usize> guest_out_sealed::Sealed for [T; N] {}
// SAFETY: see the array composition note above.
unsafe impl<T: GuestOut, const N: usize> GuestOut for [T; N] {}

// The libc ABI structs below are repr(C) plain data admitted only
// where every byte is a named field (libc spells its pads as named
// Padding fields) and the const assertions after the impls prove
// size == sum of field sizes, so no hidden padding can carry host
// bytes to the guest. Production sources are zeroed or host-filled,
// so the named pads are initialized too. All fields are integers,
// integer or c_char arrays, raw pointers or libc Padding; every bit
// pattern is valid. Three types have truly
// hidden padding in libc 0.2.186 and are NOT admitted directly:
// flock (gaps 4..8 and 28..32 of 32), msghdr (12..16 and 52..56 of
// 56), mmsghdr (inherits msghdr's gaps, tail 60..64 of 64) — values
// built as stack literals leave those bytes uninitialized, and
// write_struct is a safe fn, so nothing would stop the leak. Those
// three go through the Guest* mirrors below, whose padding fields
// are explicit and zeroed by construction.
impl guest_out_sealed::Sealed for libc::timespec {}
// SAFETY: two i64 fields, no padding (asserted below).
unsafe impl GuestOut for libc::timespec {}
impl guest_out_sealed::Sealed for libc::timeval {}
// SAFETY: two i64 fields, no padding (asserted below).
unsafe impl GuestOut for libc::timeval {}
impl guest_out_sealed::Sealed for libc::itimerspec {}
// SAFETY: two timespecs, no padding (asserted below).
unsafe impl GuestOut for libc::itimerspec {}
impl guest_out_sealed::Sealed for libc::utsname {}
// SAFETY: six [c_char; 65] fields at align 1, no padding (asserted below).
unsafe impl GuestOut for libc::utsname {}
impl guest_out_sealed::Sealed for libc::stat {}
// SAFETY: every gap is a named Padding field (__pad0, __unused),
// zeroed with the value at production sources (asserted below).
unsafe impl GuestOut for libc::stat {}
impl guest_out_sealed::Sealed for libc::statx {}
// SAFETY: every gap is a named Padding field (__statx_pad1,
// per-timestamp pad, __statx_pad3) (asserted below).
unsafe impl GuestOut for libc::statx {}
impl guest_out_sealed::Sealed for libc::statfs {}
// SAFETY: 8-byte fields plus named f_spare tail, no hidden gap
// (asserted below).
unsafe impl GuestOut for libc::statfs {}
impl guest_out_sealed::Sealed for libc::pollfd {}
// SAFETY: i32 + i16 + i16 fills 8 bytes exactly (asserted below).
unsafe impl GuestOut for libc::pollfd {}
impl guest_out_sealed::Sealed for libc::epoll_event {}
// SAFETY: repr(packed) on x86_64: u32 + u64 in 12 bytes, no padding
// (asserted below). The unaligned u64 is copied as bytes, never read
// as a typed value here.
unsafe impl GuestOut for libc::epoll_event {}
impl guest_out_sealed::Sealed for libc::linger {}
// SAFETY: two i32 fields, no padding (asserted below).
unsafe impl GuestOut for libc::linger {}
impl guest_out_sealed::Sealed for libc::sockaddr_in {}
// SAFETY: u16 + u16 + in_addr + named sin_zero[8] fills 16 (asserted below).
unsafe impl GuestOut for libc::sockaddr_in {}
impl guest_out_sealed::Sealed for libc::sockaddr_in6 {}
// SAFETY: u16 + u16 + u32 + [u8; 16] + u32 fills 28 (asserted below).
unsafe impl GuestOut for libc::sockaddr_in6 {}
impl guest_out_sealed::Sealed for libc::sockaddr_un {}
// SAFETY: u16 + [c_char; 108] fills 110 at align 2 (asserted below).
unsafe impl GuestOut for libc::sockaddr_un {}
impl guest_out_sealed::Sealed for libc::sockaddr_nl {}
// SAFETY: u16 + named nl_pad u16 + u32 + u32 fills 12 (asserted below).
unsafe impl GuestOut for libc::sockaddr_nl {}
impl guest_out_sealed::Sealed for libc::cmsghdr {}
// SAFETY: usize + i32 + i32 fills 16 (asserted below).
unsafe impl GuestOut for libc::cmsghdr {}
impl guest_out_sealed::Sealed for libc::signalfd_siginfo {}
// SAFETY: every gap is a named Padding field (_pad2, _pad[28])
// (asserted below).
unsafe impl GuestOut for libc::signalfd_siginfo {}
impl guest_out_sealed::Sealed for libc::iovec {}
// SAFETY: pointer + usize fills 16 with no padding (asserted below).
// The pointer holds a guest address at every write site (read back
// from the guest or staged by tests), never a host pointer.
unsafe impl GuestOut for libc::iovec {}

/// `libc::flock` with its hidden padding made explicit and zeroed.
/// Convert with `GuestFlock::from(&flock)`; never write a raw
/// `libc::flock`. All mirror fields below are integers or
/// guest-address `u64`s; every bit pattern is valid.
#[repr(C)]
pub(super) struct GuestFlock {
    l_type: libc::c_short,
    l_whence: libc::c_short,
    _pad0: u32,
    l_start: libc::off_t,
    l_len: libc::off_t,
    l_pid: libc::pid_t,
    _pad1: u32,
}

impl From<&libc::flock> for GuestFlock {
    fn from(value: &libc::flock) -> Self {
        Self {
            l_type: value.l_type,
            l_whence: value.l_whence,
            _pad0: 0,
            l_start: value.l_start,
            l_len: value.l_len,
            l_pid: value.l_pid,
            _pad1: 0,
        }
    }
}

impl guest_out_sealed::Sealed for GuestFlock {}
// SAFETY: repr(C) mirror of libc::flock with both hidden gaps as
// named fields, zeroed by the only constructor above; layout equality
// with libc::flock asserted below.
unsafe impl GuestOut for GuestFlock {}

/// `libc::msghdr` with its hidden padding made explicit and zeroed.
/// Pointer fields travel as guest-address `u64`s. `From` casts
/// whatever the source header holds, so it is only honest for headers
/// read from the guest (or staged by tests with guest addresses): a
/// caller storing a host pointer in a `libc::msghdr` first would
/// still leak it through this conversion. A guest-address
/// constructor that cannot accept host pointers at all is filed as
/// follow-up work; until then this conversion point is where review
/// checks the provenance.
#[repr(C)]
pub(super) struct GuestMsghdr {
    msg_name: u64,
    msg_namelen: libc::socklen_t,
    _pad0: u32,
    msg_iov: u64,
    msg_iovlen: u64,
    msg_control: u64,
    msg_controllen: u64,
    msg_flags: libc::c_int,
    _pad1: u32,
}

impl From<&libc::msghdr> for GuestMsghdr {
    fn from(value: &libc::msghdr) -> Self {
        Self {
            msg_name: value.msg_name as usize as u64,
            msg_namelen: value.msg_namelen,
            _pad0: 0,
            msg_iov: value.msg_iov as usize as u64,
            msg_iovlen: value.msg_iovlen as u64,
            msg_control: value.msg_control as usize as u64,
            msg_controllen: value.msg_controllen as u64,
            msg_flags: value.msg_flags,
            _pad1: 0,
        }
    }
}

impl guest_out_sealed::Sealed for GuestMsghdr {}
// SAFETY: repr(C) mirror of libc::msghdr with both hidden gaps as
// named fields, zeroed by the only constructor above; layout equality
// with libc::msghdr asserted below.
unsafe impl GuestOut for GuestMsghdr {}

/// `libc::mmsghdr`: a `GuestMsghdr` plus its length, tail padding
/// explicit and zeroed.
#[repr(C)]
pub(super) struct GuestMmsghdr {
    msg_hdr: GuestMsghdr,
    msg_len: libc::c_uint,
    _pad: u32,
}

impl From<&libc::mmsghdr> for GuestMmsghdr {
    fn from(value: &libc::mmsghdr) -> Self {
        Self {
            msg_hdr: GuestMsghdr::from(&value.msg_hdr),
            msg_len: value.msg_len,
            _pad: 0,
        }
    }
}

impl guest_out_sealed::Sealed for GuestMmsghdr {}
// SAFETY: repr(C) mirror of libc::mmsghdr via GuestMsghdr; layout
// equality asserted below.
unsafe impl GuestOut for GuestMmsghdr {}

// SAFETY: repr(C) pair of u64s defined for the pselect6 ABI; no padding.
impl guest_out_sealed::Sealed for Pselect6SigmaskArg {}
// SAFETY: see the Pselect6SigmaskArg note above.
unsafe impl GuestOut for Pselect6SigmaskArg {}

// Compile-time proof that every admitted type has no hidden padding:
// size equals the sum of its field sizes (named libc Padding fields
// counted by their sizes, from the libc 0.2.186 definitions), and the
// mirrors match their libc layouts field for field. If a libc upgrade
// changes a layout, these fail to compile instead of leaking bytes.
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<libc::timespec>() == 8 + 8);
    assert!(size_of::<libc::timeval>() == 8 + 8);
    assert!(size_of::<libc::itimerspec>() == 16 + 16);
    assert!(size_of::<libc::utsname>() == 6 * 65);
    // stat: fields through st_ctime_nsec fill 120, __pad0 (4) sits
    // between st_gid and st_rdev, __unused [i64; 3] tails to 144.
    assert!(offset_of!(libc::stat, st_rdev) == offset_of!(libc::stat, st_gid) + 4 + 4);
    assert!(size_of::<libc::stat>() == offset_of!(libc::stat, st_ctime_nsec) + 8 + 24);
    // statx: __statx_pad1 (2) after stx_mode, per-timestamp pad (4)
    // inside each 16-byte statx_timestamp, __statx_pad3 [u64; 12] tail.
    assert!(offset_of!(libc::statx, stx_ino) == offset_of!(libc::statx, stx_mode) + 2 + 2);
    assert!(size_of::<libc::statx_timestamp>() == 8 + 4 + 4);
    assert!(size_of::<libc::statx>() == offset_of!(libc::statx, stx_dio_offset_align) + 4 + 96);
    assert!(size_of::<libc::statfs>() == 10 * 8 + 40);
    assert!(size_of::<libc::pollfd>() == 4 + 2 + 2);
    assert!(size_of::<libc::epoll_event>() == 4 + 8);
    assert!(size_of::<libc::linger>() == 4 + 4);
    assert!(size_of::<libc::sockaddr_in>() == 2 + 2 + 4 + 8);
    assert!(size_of::<libc::sockaddr_in6>() == 2 + 2 + 4 + 16 + 4);
    assert!(size_of::<libc::sockaddr_un>() == 2 + 108);
    assert!(size_of::<libc::sockaddr_nl>() == 2 + 2 + 4 + 4);
    assert!(size_of::<libc::cmsghdr>() == 8 + 4 + 4);
    // signalfd_siginfo: 12 u32/i32 words, 4 u64s, u16 + _pad2 (2),
    // i32, u64, u32, _pad [u8; 28].
    assert!(size_of::<libc::signalfd_siginfo>() == 48 + 32 + 2 + 2 + 4 + 8 + 4 + 28);
    assert!(size_of::<libc::iovec>() == 8 + 8);
    assert!(size_of::<Pselect6SigmaskArg>() == 8 + 8);
    // Mirrors must match libc size and every field offset.
    assert!(size_of::<GuestFlock>() == size_of::<libc::flock>());
    assert!(offset_of!(GuestFlock, l_start) == offset_of!(libc::flock, l_start));
    assert!(offset_of!(GuestFlock, l_len) == offset_of!(libc::flock, l_len));
    assert!(offset_of!(GuestFlock, l_pid) == offset_of!(libc::flock, l_pid));
    assert!(size_of::<GuestMsghdr>() == size_of::<libc::msghdr>());
    assert!(offset_of!(GuestMsghdr, msg_iov) == offset_of!(libc::msghdr, msg_iov));
    assert!(offset_of!(GuestMsghdr, msg_control) == offset_of!(libc::msghdr, msg_control));
    assert!(offset_of!(GuestMsghdr, msg_flags) == offset_of!(libc::msghdr, msg_flags));
    assert!(size_of::<GuestMmsghdr>() == size_of::<libc::mmsghdr>());
    assert!(offset_of!(GuestMmsghdr, msg_len) == offset_of!(libc::mmsghdr, msg_len));
};

pub(super) fn write_struct<T: GuestOut>(
    memory: &mut impl GuestMemoryAccess<Error = crate::Error>,
    address: u64,
    value: &T,
) -> i64 {
    // SAFETY: `T: GuestOut` restricts `value` to the audited ABI plain-data
    // set above, whose values callers fully initialize (padding included).
    // The byte view is bounded to value and copied into guest memory before value is dropped.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    };
    write_bytes(memory, address, bytes)
}

pub(super) fn read_guest_bytes<const N: usize>(
    memory: &impl GuestMemoryAccess<Error = crate::Error>,
    address: u64,
) -> Result<[u8; N], i64> {
    let mut bytes = [0; N];
    memory
        .read_exact(address, &mut bytes)
        .map_err(|_| negative_errno(libc::EFAULT))?;
    Ok(bytes)
}

pub(super) fn read_guest_struct<T>(
    memory: &impl GuestMemoryAccess<Error = crate::Error>,
    address: u64,
) -> Result<T, i64> {
    let mut value = std::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: value is writable for exactly size_of::<T>() bytes and is not
    // observed until guest memory has initialized the complete byte range.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), std::mem::size_of::<T>())
    };
    memory
        .read_exact(address, bytes)
        .map_err(|_| negative_errno(libc::EFAULT))?;
    // SAFETY: the entire plain-data Linux ABI value was initialized above.
    Ok(unsafe { value.assume_init() })
}

#[cfg(test)]
pub(super) fn struct_bytes<T: GuestOut>(value: &T) -> Vec<u8> {
    // SAFETY: `T: GuestOut` restricts `value` to the same audited ABI
    // plain-data set as `write_struct`, so the test staging path cannot
    // bypass the outbound contract. The returned Vec owns its copy
    // before value can be dropped.
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
        .to_vec()
    }
}

pub(super) fn zero_or_errno(result: libc::c_int) -> i64 {
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

pub(super) enum ReadCStringError {
    Fault,
    NameTooLong,
}

pub(super) fn read_c_string_errno(error: ReadCStringError) -> i64 {
    match error {
        ReadCStringError::Fault => negative_errno(libc::EFAULT),
        ReadCStringError::NameTooLong => negative_errno(libc::ENAMETOOLONG),
    }
}

pub(super) fn read_c_string<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    address: u64,
    limit: usize,
) -> Result<Vec<u8>, ReadCStringError> {
    let mut result = Vec::new();
    for offset in 0..limit {
        let address = address
            .checked_add(offset as u64)
            .ok_or(ReadCStringError::Fault)?;
        let mut byte = [0];
        memory
            .read_exact(address, &mut byte)
            .map_err(|_| ReadCStringError::Fault)?;
        if byte[0] == 0 {
            return Ok(result);
        }
        result.push(byte[0]);
    }
    Err(ReadCStringError::NameTooLong)
}

pub(super) fn read_string_array<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    address: u64,
) -> Result<Vec<String>, i64> {
    const MAX_ENTRIES: usize = 4096;
    const MAX_STRING_BYTES: usize = 128 * 1024;

    if address == 0 {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut total_bytes = 0;
    for index in 0..MAX_ENTRIES {
        let pointer_address = address
            .checked_add((index * std::mem::size_of::<u64>()) as u64)
            .ok_or_else(|| negative_errno(libc::EFAULT))?;
        let mut pointer = [0; 8];
        memory
            .read_exact(pointer_address, &mut pointer)
            .map_err(|_| negative_errno(libc::EFAULT))?;
        let pointer = u64::from_le_bytes(pointer);
        if pointer == 0 {
            return Ok(result);
        }
        let remaining = MAX_STRING_BYTES
            .checked_sub(total_bytes)
            .ok_or_else(|| negative_errno(libc::E2BIG))?;
        let bytes = read_c_string(memory, pointer, remaining).map_err(read_c_string_errno)?;
        total_bytes = total_bytes
            .checked_add(bytes.len() + 1)
            .ok_or_else(|| negative_errno(libc::E2BIG))?;
        result.push(String::from_utf8(bytes).map_err(|_| negative_errno(libc::EINVAL))?);
    }
    Err(negative_errno(libc::E2BIG))
}

#[cfg(test)]
mod tests {
    use super::struct_bytes;

    #[test]
    fn struct_bytes_are_the_value_bytes() {
        // Scalar: little-endian host bytes, exactly size_of::<u32>() long.
        assert_eq!(
            struct_bytes(&0x0102_0304u32),
            vec![0x04, 0x03, 0x02, 0x01],
            "u32 writes must be its 4 value bytes"
        );
        // Array of admitted values composes element-wise.
        assert_eq!(
            struct_bytes(&[1u16, 2u16]),
            vec![1, 0, 2, 0],
            "[u16; 2] writes must be both elements back to back"
        );
    }

    #[test]
    fn struct_bytes_cover_the_whole_abi_struct() {
        let value = libc::timespec { tv_sec: 1, tv_nsec: 2 };
        let bytes = struct_bytes(&value);
        assert_eq!(
            bytes.len(),
            std::mem::size_of::<libc::timespec>(),
            "timespec writes must cover the whole struct"
        );
        assert_eq!(
            &bytes[..8],
            &1i64.to_ne_bytes(),
            "tv_sec must be the first field written"
        );
    }

    #[test]
    fn flock_mirror_zeroes_hidden_padding() {
        // Poison every byte, then set the fields: the hidden padding
        // (4..8 and 28..32) still holds 0xAA in the libc value. The
        // mirror must write zeros there and the field values elsewhere.
        // (Before the mirror, struct_bytes of this flock returned the
        // 0xAA padding verbatim — the leak this test now forbids.)
        let mut raw = [0xAAu8; 32];
        raw[0..2].copy_from_slice(&1i16.to_ne_bytes());
        raw[2..4].copy_from_slice(&2i16.to_ne_bytes());
        raw[8..16].copy_from_slice(&3i64.to_ne_bytes());
        raw[16..24].copy_from_slice(&4i64.to_ne_bytes());
        raw[24..28].copy_from_slice(&5i32.to_ne_bytes());
        // SAFETY: every field byte above is initialized; padding is
        // 0xAA. read_unaligned: the [u8; 32] source has align 1, the
        // flock align 8 - a plain read would be UB.
        let flock: libc::flock = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };
        let bytes = struct_bytes(&super::GuestFlock::from(&flock));
        assert_eq!(&bytes[4..8], &[0; 4], "internal padding must be zero");
        assert_eq!(&bytes[28..32], &[0; 4], "tail padding must be zero");
        assert_eq!(&bytes[0..2], &1i16.to_ne_bytes(), "l_type preserved");
        assert_eq!(&bytes[8..16], &3i64.to_ne_bytes(), "l_start preserved");
        assert_eq!(&bytes[24..28], &5i32.to_ne_bytes(), "l_pid preserved");
    }

    #[test]
    fn zeroed_padded_struct_writes_zero_padding() {
        // stat's pads are NAMED Padding fields (unlike flock's hidden
        // gaps above): a zeroed source - the production pattern -
        // writes them as zeros, byte for byte over the whole struct.
        let value = unsafe { std::mem::zeroed::<libc::stat>() };
        let bytes = struct_bytes(&value);
        assert_eq!(bytes.len(), std::mem::size_of::<libc::stat>());
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "a zeroed stat must write only zero bytes, named pads included"
        );
    }
}
