/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Serialization support for timespec structs.

use serde::Deserialize;
use serde::Serialize;

/// A serializable version of `libc::timespec`.
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug, Hash)]
#[repr(C)]
pub struct Timespec {
    /// Seconds
    pub tv_sec: libc::time_t,
    /// Nanoseconds
    pub tv_nsec: libc::c_long,
}

impl From<Timespec> for libc::timespec {
    fn from(ts: Timespec) -> libc::timespec {
        libc::timespec {
            tv_sec: ts.tv_sec,
            tv_nsec: ts.tv_nsec,
        }
    }
}

impl From<libc::timespec> for Timespec {
    fn from(ts: libc::timespec) -> Self {
        Self {
            tv_sec: ts.tv_sec,
            tv_nsec: ts.tv_nsec,
        }
    }
}

impl From<libc::statx_timestamp> for Timespec {
    fn from(tp: libc::statx_timestamp) -> Self {
        Timespec {
            tv_sec: tp.tv_sec as _,
            tv_nsec: tp.tv_nsec as _,
        }
    }
}

impl From<Timespec> for libc::statx_timestamp {
    fn from(tp: Timespec) -> Self {
        libc::statx_timestamp {
            tv_sec: tp.tv_sec as _,
            tv_nsec: tp.tv_nsec as _,
            __statx_timestamp_pad1: [0],
        }
    }
}

impl From<libc::timeval> for Timespec {
    fn from(tv: libc::timeval) -> Self {
        Timespec {
            tv_sec: tv.tv_sec as _,
            tv_nsec: (1000 * tv.tv_usec) as _,
        }
    }
}

impl From<Timespec> for libc::timeval {
    fn from(ts: Timespec) -> Self {
        libc::timeval {
            tv_sec: ts.tv_sec as _,
            tv_usec: (ts.tv_nsec / 1000) as _,
        }
    }
}

impl std::fmt::Display for Timespec {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{{ tv_sec: {}, tv_nsec: {} }}",
            self.tv_sec, self.tv_nsec
        )
    }
}

/// A serializable version of `libc::timeval`.
#[derive(Serialize, Deserialize)]
#[derive(Default, Copy, Clone, Eq, PartialEq, Debug, Hash)]
#[repr(C)]
#[allow(missing_docs)]
pub struct Timeval {
    pub tv_sec: libc::time_t,
    pub tv_usec: libc::suseconds_t,
}

impl std::fmt::Display for Timeval {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{{ tv_sec: {}, tv_usec: {} }}",
            self.tv_sec, self.tv_usec
        )
    }
}

/// A serializable version of `libc::timezone`.
#[derive(Serialize, Deserialize)]
#[derive(Default, Copy, Clone, Eq, PartialEq, Debug, Hash)]
#[repr(C)]
#[allow(missing_docs)]
pub struct Timezone {
    tz_minuteswest: libc::c_int,
    tz_dsttime: libc::c_int,
}

crate::impl_displayable!(Display Timeval);
crate::impl_displayable!(Display Timespec);

crate::displayable_ptr!(TimevalMutPtr, AddrMut<Timeval>);
crate::displayable_ptr!(TimespecMutPtr, AddrMut<Timespec>);
