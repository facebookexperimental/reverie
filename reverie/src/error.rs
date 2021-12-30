/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Error handling.

use thiserror::Error;

pub use reverie_syscalls::Errno;

/// A general error.
#[derive(Error, Debug)]
pub enum Error {
    /// A low-level errno.
    #[error(transparent)]
    Errno(#[from] Errno),

    /// A generic error that may be produced by the tool.
    #[error(transparent)]
    Tool(#[from] anyhow::Error),

    /// An I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Extracts the errno from the error. If this is not an `Error::Errno`, then
    /// returns `Err(Error)`. This is useful for capturing syscall errors and
    /// propagating all other types of errors.
    pub fn into_errno(self) -> Result<Errno, Self> {
        if let Self::Errno(err) = self {
            Ok(err)
        } else {
            Err(self)
        }
    }
}

impl From<nix::errno::Errno> for Error {
    fn from(err: nix::errno::Errno) -> Self {
        Self::Errno(Errno::new(err as i32))
    }
}
