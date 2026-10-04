/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Linux single-record seq_file state. `read_pos` belongs to the sequence
/// iterator; `file_pos` is the open file description's shared offset. A pread
/// changes the former without changing the latter.
#[derive(Debug, Default)]
pub(crate) struct FdinfoSequence {
    file_pos: u64,
    read_pos: u64,
    buffer: Vec<u8>,
    from: usize,
    end: bool,
}

impl FdinfoSequence {
    fn reset(&mut self) {
        self.buffer.clear();
        self.from = 0;
        self.end = false;
    }

    fn traverse(
        &mut self,
        offset: u64,
        observe: &mut impl FnMut() -> Result<Vec<u8>, i64>,
    ) -> Result<(), i64> {
        self.reset();
        if offset != 0 {
            self.buffer = observe()?;
            self.from = offset.min(self.buffer.len() as u64) as usize;
            self.end = true;
        }
        Ok(())
    }

    pub(crate) fn read(
        &mut self,
        positioned_offset: Option<u64>,
        count: usize,
        mut observe: impl FnMut() -> Result<Vec<u8>, i64>,
        mut copy: impl FnMut(&[u8]) -> Result<usize, i64>,
    ) -> i64 {
        let offset = positioned_offset.unwrap_or(self.file_pos);
        if offset > i64::MAX as u64 {
            return -i64::from(libc::EINVAL);
        }
        if count == 0 {
            return 0;
        }
        if offset == 0 {
            self.reset();
        }
        if offset != self.read_pos {
            if let Err(error) = self.traverse(offset, &mut observe) {
                self.read_pos = 0;
                self.reset();
                return error;
            }
            self.read_pos = offset;
        }
        if self.from == self.buffer.len() && !self.end {
            match observe() {
                Ok(bytes) => self.buffer = bytes,
                Err(error) => return error,
            }
            self.from = 0;
            self.end = true;
        }
        let available = (self.buffer.len() - self.from).min(count);
        if available == 0 {
            return 0;
        }
        let copied = match copy(&self.buffer[self.from..self.from + available]) {
            Ok(0) => return -i64::from(libc::EFAULT),
            Ok(copied) => copied,
            Err(error) => return error,
        };
        assert!(
            copied <= available,
            "fdinfo copy exceeded the offered bytes"
        );
        self.from += copied;
        self.read_pos += copied as u64;
        if positioned_offset.is_none() {
            self.file_pos = self.read_pos;
        }
        copied as i64
    }

    pub(crate) fn seek(
        &mut self,
        offset: i64,
        whence: libc::c_int,
        mut observe: impl FnMut() -> Result<Vec<u8>, i64>,
    ) -> i64 {
        let offset = match whence {
            libc::SEEK_SET => Some(offset),
            libc::SEEK_CUR => (self.file_pos as i64).checked_add(offset),
            _ => None,
        };
        let Some(offset) = offset.filter(|offset| *offset >= 0) else {
            return -i64::from(libc::EINVAL);
        };
        if offset as u64 != self.read_pos {
            if let Err(error) = self.traverse(offset as u64, &mut observe) {
                self.file_pos = 0;
                self.read_pos = 0;
                self.reset();
                return error;
            }
            self.read_pos = offset as u64;
        }
        self.file_pos = offset as u64;
        offset
    }
}
