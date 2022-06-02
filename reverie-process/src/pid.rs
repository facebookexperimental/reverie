/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use core::fmt;
use core::hash::Hash;
use serde::{Deserialize, Serialize};

/// A process ID (PID).
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize
)]
pub struct Pid(libc::pid_t);

impl Pid {
    /// Creates `Pid` from a raw `pid_t`.
    pub fn from_raw(pid: libc::pid_t) -> Self {
        Self(pid)
    }

    /// Returns the PID of the calling process.
    pub fn this() -> Self {
        nix::unistd::Pid::this().into()
    }

    /// Returns the PID of the calling process.
    pub fn parent() -> Self {
        nix::unistd::Pid::parent().into()
    }

    /// Gets the raw `pid_t` from this `Pid`.
    pub fn as_raw(self) -> libc::pid_t {
        self.0
    }

    /// Returns a `Display`able that is color-coded. That is, the same PID will
    /// get the same color. This makes it easy to visually recognize PIDs when
    /// looking through logs.
    ///
    /// Note that while the same PIDs always have the same color, different PIDs
    /// may also have the same color if they fall into the same color bucket.
    pub fn colored(self) -> ColoredPid {
        ColoredPid(self)
    }
}

impl From<nix::unistd::Pid> for Pid {
    fn from(pid: nix::unistd::Pid) -> Pid {
        Self(pid.as_raw())
    }
}

impl From<Pid> for nix::unistd::Pid {
    fn from(pid: Pid) -> nix::unistd::Pid {
        nix::unistd::Pid::from_raw(pid.as_raw())
    }
}

impl From<Pid> for libc::pid_t {
    fn from(pid: Pid) -> libc::pid_t {
        pid.as_raw()
    }
}

impl From<libc::pid_t> for Pid {
    fn from(pid: libc::pid_t) -> Pid {
        Pid::from_raw(pid)
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A colored pid.
pub struct ColoredPid(Pid);

impl ColoredPid {
    /// Gets the ansi color code for the current PID. Returns `None` if not
    /// writing to a terminal.
    fn ansi_code(&self) -> Option<&'static str> {
        if colored::control::SHOULD_COLORIZE.should_colorize() {
            // Why not just use `colored::Colorize` you ask? It allocates a
            // string in order to create the color code. Since we may log a lot
            // of output that may contain a lot of PIDs, we don't want that to
            // slow us down.
            Some(match self.0.as_raw() % 14 {
                0 => "\x1b[0;31m",  // Red
                1 => "\x1b[0;32m",  // Green
                2 => "\x1b[0;33m",  // Yellow
                3 => "\x1b[0;34m",  // Blue
                4 => "\x1b[0;35m",  // Magenta
                5 => "\x1b[0;36m",  // Cyan
                6 => "\x1b[0;37m",  // White
                7 => "\x1b[1;31m",  // Bright red
                8 => "\x1b[1;32m",  // Bright green
                9 => "\x1b[01;33m", // Bright yellow
                10 => "\x1b[1;34m", // Bright blue
                11 => "\x1b[1;35m", // Bright magenta
                12 => "\x1b[1;36m", // Bright cyan
                _ => "\x1b[1;37m",  // Bright white
            })
        } else {
            None
        }
    }
}

impl fmt::Display for ColoredPid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(color) = self.ansi_code() {
            write!(f, "{}{}\x1b[0m", color, self.0)
        } else {
            fmt::Display::fmt(&self.0, f)
        }
    }
}
