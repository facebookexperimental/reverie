/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fmt::{self, Debug};

enum Direction {
    In,
    Out,
}

const MAX_BYTES_DISPLAY: usize = 64;

pub struct PacketLogger<'a> {
    direction: Direction,
    body: &'a [u8],
    checksum: u8,
}

impl<'a> PacketLogger<'a> {
    pub fn incoming<T: 'a + AsRef<[u8]> + ?Sized>(body: &'a T, checksum: u8) -> Self {
        Self {
            direction: Direction::In,
            body: body.as_ref(),
            checksum,
        }
    }

    pub fn outgoing<T: 'a + AsRef<[u8]> + ?Sized>(body: &'a T, checksum: u8) -> Self {
        Self {
            direction: Direction::Out,
            body: body.as_ref(),
            checksum,
        }
    }
}

impl<'a> Debug for PacketLogger<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.direction {
            Direction::In => write!(f, "<-- ")?,
            Direction::Out => write!(f, "--> ")?,
        }

        let nb_left = if self.body.len() > MAX_BYTES_DISPLAY {
            Some(self.body.len() - MAX_BYTES_DISPLAY)
        } else {
            None
        };
        write!(f, "b\"")?;
        for &b in self.body.iter().take(MAX_BYTES_DISPLAY) {
            if b == b'\n' {
                write!(f, "\\n")?;
            } else if b == b'\r' {
                write!(f, "\\r")?;
            } else if b == b'\t' {
                write!(f, "\\t")?;
            } else if b == b'\\' || b == b'"' {
                write!(f, "\\{}", b as char)?;
            } else if b == b'\0' {
                write!(f, "\\0")?;
            // ASCII printable
            } else if b >= 0x20 && b < 0x7f {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        if let Some(nb) = nb_left {
            write!(f, "[{} bytes omitted]", nb)?;
        }
        write!(f, "#{:02x}", self.checksum)?;
        write!(f, "\"")?;
        Ok(())
    }
}
