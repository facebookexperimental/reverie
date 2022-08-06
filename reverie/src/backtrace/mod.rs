/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
mod cache;
mod library;
mod symbols;

use core::fmt;
use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use self::cache::cache;
use self::library::Libraries;
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

/// A backtrace with file and line information. This is more heavy-weight than a
/// normal backtrace.
pub struct PrettyBacktrace {
    thread_id: Pid,
    frames: Vec<PrettyFrame>,
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

/// A stack frame with debugging information.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct PrettyFrame {
    /// The raw stack frame information.
    frame: Frame,
    /// The source file and line where the instruction pointer is located.
    locations: Vec<Location>,
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

/// The location of a symbol.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Location {
    /// The path to the source file.
    file: PathBuf,
    /// The line in the file. 0 if unknown.
    line: u32,
    /// The column in the file. 0 if unknown.
    column: u32,
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

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.column != 0 {
            write!(f, "{}:{}:{}", self.file.display(), self.line, self.column)
        } else {
            write!(f, "{}:{}", self.file.display(), self.line)
        }
    }
}

impl fmt::Display for PrettyFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(location) = self.locations.first() {
            write!(f, "{} at {}", self.frame, location)
        } else {
            write!(f, "{}", self.frame)
        }
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

    /// Generates a pretty backtrace that includes file and line information for each frame.
    pub fn pretty(&self) -> Result<PrettyBacktrace, anyhow::Error> {
        let libraries = Libraries::new(self.thread_id)?;

        let mut frames = Vec::new();
        let mut cache = cache();

        for frame in &self.frames {
            let ip = frame.ip;
            let mut locations = Vec::new();

            if let Some((library, addr)) = libraries.ip_to_vaddr(ip) {
                let symbols = cache.load(library)?;

                let mut source_frames = symbols.find_frames(addr)?;
                while let Some(f) = source_frames.next()? {
                    if let Some(loc) = f.location {
                        locations.push(Location {
                            file: loc.file.unwrap().into(),
                            line: loc.line.unwrap_or(0),
                            column: loc.column.unwrap_or(0),
                        });
                    }
                }
            }

            frames.push(PrettyFrame {
                frame: frame.clone(),
                locations,
            });
        }

        Ok(PrettyBacktrace {
            thread_id: self.thread_id,
            frames,
        })
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
        thread_name(self.thread_id)
    }
}

impl PrettyBacktrace {
    /// Retrieves the name of the thread for this backtrace. This will fail if
    /// the thread has already exited since the thread ID is used to look up the
    /// thread name.
    pub fn thread_name(&self) -> io::Result<String> {
        thread_name(self.thread_id)
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

impl fmt::Display for PrettyBacktrace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let thread_name = self.thread_name();
        let thread_name = thread_name.as_ref().map(String::as_str);
        let thread_name = thread_name.unwrap_or("<unknown name>");
        writeln!(
            f,
            "Stack trace for thread {} ({:?}):",
            self.thread_id, thread_name
        )?;

        for (i, frame) in self.frames.iter().enumerate() {
            if frame.locations.is_empty() {
                writeln!(f, "{:>4}: {}", i, frame)?;
            } else {
                writeln!(f, "{:>4}: {:#}", i, frame.frame)?;
                for location in &frame.locations {
                    writeln!(f, "             at {}", location)?;
                }
            }
        }

        Ok(())
    }
}

fn thread_name(thread_id: Pid) -> io::Result<String> {
    let mut name = String::new();

    let mut f = File::open(format!("/proc/{}/comm", thread_id))?;
    f.read_to_string(&mut name)?;

    // Remove trailing newline character
    assert_eq!(name.pop(), Some('\n'));

    Ok(name)
}
