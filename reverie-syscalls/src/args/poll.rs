/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Serialization support for poll-related enums and structs.

use crate::{Displayable, FromToRaw, MemoryAccess};

use core::fmt;
use serde::{Deserialize, Serialize};

/// A serializable version of `libc::pollfd`.
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug, Default)]
#[repr(C)]
#[allow(missing_docs)]
pub struct PollFd {
    pub fd: libc::c_int,
    pub events: PollFlags,
    pub revents: PollFlags,
}

impl From<PollFd> for libc::pollfd {
    fn from(pollfd: PollFd) -> libc::pollfd {
        libc::pollfd {
            fd: pollfd.fd,
            events: pollfd.events.bits(),
            revents: pollfd.revents.bits(),
        }
    }
}

impl From<libc::pollfd> for PollFd {
    fn from(pollfd: libc::pollfd) -> Self {
        Self {
            fd: pollfd.fd,
            events: unsafe { PollFlags::from_bits_unchecked(pollfd.events) },
            revents: unsafe { PollFlags::from_bits_unchecked(pollfd.revents) },
        }
    }
}

impl Displayable for PollFd {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

bitflags! {
    /// Flags for [`PollFd`].
    #[derive(Default, Serialize, Deserialize)]
    pub struct PollFlags: libc::c_short {
        /// There is data to read.
        const POLLIN = libc::POLLIN;
        /// There is some exceptional condition on the file descriptor.
        const POLLPRI = libc::POLLPRI;
        /// Writing is now possible.
        const POLLOUT = libc::POLLOUT;
        /// Equivalent to [`POLLIN`].
        const POLLRDNORM = libc::POLLRDNORM;
        /// Equivalent to [`POLLOUT`].
        const POLLWRNORM = libc::POLLWRNORM;
        /// Priority band can be read (generally unused on Linux).
        const POLLRDBAND = libc::POLLRDBAND;
        /// Priority data may be written.
        const POLLWRBAND = libc::POLLWRBAND;
        /// Error condition.
        const POLLERR = libc::POLLERR;
        /// Hang up.
        const POLLHUP = libc::POLLHUP;
        /// Invalid request.
        const POLLNVAL = libc::POLLNVAL;
    }
}

impl FromToRaw for PollFlags {
    fn from_raw(raw: u64) -> Self {
        Self::from_bits_truncate(raw as libc::c_short)
    }

    fn into_raw(self) -> u64 {
        self.bits() as u64
    }
}

impl Displayable for PollFlags {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        fmt::Display::fmt(&self.bits(), f)
    }
}
