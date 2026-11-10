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

pub(super) fn write_struct<T>(
    memory: &mut impl GuestMemoryAccess<Error = crate::Error>,
    address: u64,
    value: &T,
) -> i64 {
    // SAFETY: Linux ABI structs are initialized plain data. The byte view is
    // bounded to value and copied into guest memory before value is dropped.
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
pub(super) fn struct_bytes<T>(value: &T) -> Vec<u8> {
    // SAFETY: Linux ABI structs are initialized plain data and the returned
    // Vec owns its copy before value can be dropped.
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
