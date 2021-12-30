/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use core::fmt;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::io::Read;

use super::Pid;

/// A backtrace is a list of stack frames. These stack frames may have originated
/// from a remote process.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Backtrace {
    /// Thread ID where the backtrace originated. This can be used to get the
    /// name of the thread and the process it came from.
    thread_id: Pid,

    /// The stack frames in the backtrace.
    frames: Vec<Frame>,
}

/// A stack frame.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Frame {
    /// The value of the instruction pointer.
    pub ip: u64,
    /// True if this frame is inside of a signal handler.
    pub is_signal: bool,
    /// The symbol associated with this frame (if known).
    pub symbol: Option<Symbol>,
}

/// A symbol from a frame.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Symbol {
    /// Name of the (mangled) symbol.
    pub name: String,
    /// Offset of the symbol.
    pub offset: u64,
    /// Address of the symbol.
    pub address: u64,
    /// Size of the symbol.
    pub size: u64,
}

impl Symbol {
    /// Returns the demangled name of the symbol. This makes a best-effort guess
    /// about demangling. If the symbol could not be demangled, returns the raw,
    /// original name of the symbol.
    pub fn demangled(&self) -> Cow<str> {
        addr2line::demangle_auto(Cow::from(&self.name), None)
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.symbol {
            Some(symbol) => write!(f, "{:#016x}: {:#}", self.ip, symbol)?,
            None => write!(f, "{:#016x}: ???", self.ip)?,
        }

        if self.is_signal {
            write!(f, " (in signal handler)")?;
        }

        Ok(())
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{} + {:#x}", self.demangled(), self.offset)
        } else {
            write!(f, "{} + {:#x}", self.name, self.offset)
        }
    }
}

impl Backtrace {
    /// Creates a backtrace from a thread ID and frames.
    pub fn new(thread_id: Pid, frames: Vec<Frame>) -> Self {
        Self { thread_id, frames }
    }

    /// Returns an iterator over the frames in the backtrace.
    pub fn iter(&self) -> impl Iterator<Item = &Frame> {
        self.frames.iter()
    }

    /// Returns the thread ID where the backtrace originated.
    pub fn thread_id(&self) -> Pid {
        self.thread_id
    }

    /// Retreives the name of the thread for this backtrace. This will fail if
    /// the thread has already exited since the thread ID is used to look up the
    /// thread name.
    pub fn thread_name(&self) -> io::Result<String> {
        let mut name = String::new();

        let mut f = File::open(format!("/proc/{}/comm", self.thread_id))?;
        f.read_to_string(&mut name)?;

        // Remove trailing newline character
        assert_eq!(name.pop(), Some('\n'));

        Ok(name)
    }
}

impl IntoIterator for Backtrace {
    type Item = Frame;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.frames.into_iter()
    }
}

impl From<Backtrace> for Vec<Frame> {
    fn from(bt: Backtrace) -> Self {
        bt.frames
    }
}

impl fmt::Display for Backtrace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let thread_name = self.thread_name();
        let thread_name = thread_name.as_ref().map(String::as_str);
        let thread_name = thread_name.unwrap_or("<unknown name>");
        writeln!(
            f,
            "Stack trace for thread {} ({:?}):",
            self.thread_id, thread_name
        )?;

        // Ugly formatting with no symbol resolution.
        for frame in &self.frames {
            writeln!(f, "{}", frame)?;
        }

        Ok(())
    }
}
