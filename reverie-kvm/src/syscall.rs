/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::GuestMemory;
use crate::Result;

const WORD_SIZE: usize = std::mem::size_of::<u64>();
const FRAME_WORDS: usize = 7;
const FRAME_SIZE: usize = WORD_SIZE * FRAME_WORDS;

/// A Linux syscall request transported from guest to host memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallRequest {
    number: u64,
    args: [u64; 6],
}

impl SyscallRequest {
    /// Creates a request from a Linux syscall number and its six ABI arguments.
    pub const fn new(number: u64, args: [u64; 6]) -> Self {
        Self { number, args }
    }

    /// Returns the Linux syscall number.
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// Returns the six Linux syscall arguments.
    pub const fn args(&self) -> &[u64; 6] {
        &self.args
    }

    /// Encodes the request at a guest-physical address.
    pub fn write_to(self, memory: &mut GuestMemory, guest_address: u64) -> Result<()> {
        let mut frame = [0; FRAME_SIZE];
        let words = [
            self.number,
            self.args[0],
            self.args[1],
            self.args[2],
            self.args[3],
            self.args[4],
            self.args[5],
        ];
        for (index, value) in words.into_iter().enumerate() {
            let start = index * WORD_SIZE;
            frame[start..start + WORD_SIZE].copy_from_slice(&value.to_le_bytes());
        }
        memory.write(guest_address, &frame)
    }

    pub(crate) fn read_from(memory: &GuestMemory, guest_address: u64) -> Result<Self> {
        let mut frame = [0; FRAME_SIZE];
        memory.read(guest_address, &mut frame)?;
        let mut words = [0; FRAME_WORDS];
        for (index, value) in words.iter_mut().enumerate() {
            let start = index * WORD_SIZE;
            *value = u64::from_le_bytes(frame[start..start + WORD_SIZE].try_into().unwrap());
        }
        Ok(Self::new(
            words[0],
            [words[1], words[2], words[3], words[4], words[5], words[6]],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_frame_round_trips_through_guest_memory() {
        let request = SyscallRequest::new(1, [1, 0x3000, 5, 4, 5, 6]);
        let mut memory = GuestMemory::new(0, 4096).unwrap();

        request.write_to(&mut memory, 0x100).unwrap();

        assert_eq!(SyscallRequest::read_from(&memory, 0x100).unwrap(), request);
    }
}
