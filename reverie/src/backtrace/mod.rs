/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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
    /// process it came from.
    thread_id: Pid,

    // Name of the thread where the backtrace originated, or none of the name
    // could not be derived (e.g. because the thread had exited).
    thread_name: Option<String>,

    /// The stack frames in the backtrace.
    frames: Vec<Frame>,
}

/// A backtrace with file and line information. This is more heavy-weight than a
/// normal backtrace.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct PrettyBacktrace {
    thread_id: Pid,
    thread_name: Option<String>,
    frames: Vec<PrettyFrame>,
}

/// A stack frame.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Frame {
    /// The value of the instruction pointer.
    pub ip: u64,
    /// True if this frame is inside of a signal handler.
    pub is_signal: bool,
}

/// A stack frame with debugging information.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct PrettyFrame {
    /// The raw stack frame information.
    frame: Frame,
    /// The symbol as found in the symbol table.
    symbol: Option<Symbol>,
    /// The source file and line where the instruction pointer is located.
    locations: Vec<Location>,
}

/// A symbol from a frame.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Symbol {
    /// Name of the (mangled) symbol.
    pub name: String,
    /// Address of the symbol.
    pub address: u64,
    /// The offset of the instruction pointer from `address`.
    pub offset: u64,
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
        write!(f, "{:#016x}: ???", self.ip)?;

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
        Self {
            thread_id,
            thread_name: thread_name(thread_id).ok(),
            frames,
        }
    }

    /// Generates a pretty backtrace that includes file and line information for
    /// each frame.
    pub fn pretty(&self) -> Result<PrettyBacktrace, anyhow::Error> {
        let libraries = Libraries::new(self.thread_id)?;

        let mut frames = Vec::new();
        let mut cache = cache();

        for frame in &self.frames {
            let ip = frame.ip;
            let mut locations = Vec::new();
            let mut symbol = None;

            if let Some((library, addr)) = libraries.ip_to_vaddr(ip) {
                let symbols = cache.load(library)?;

                // Find the file + line number of the instruction pointer.
                if let Ok(mut source_frames) = symbols.find_frames(addr) {
                    while let Ok(Some(f)) = source_frames.next() {
                        if let Some(loc) = f.location {
                            locations.push(Location {
                                file: loc.file.unwrap().into(),
                                line: loc.line.unwrap_or(0),
                                column: loc.column.unwrap_or(0),
                            });
                        }
                    }
                }

                if symbol.is_none() {
                    // Find symbol using the symbol table.
                    symbol = symbols.find_symbol(addr).map(|sym| Symbol {
                        name: sym.name().to_string(),
                        address: sym.address(),
                        offset: addr + symbols.base_addr() - sym.address(),
                    });
                }
            }

            frames.push(PrettyFrame {
                frame: frame.clone(),
                symbol,
                locations,
            });
        }

        Ok(PrettyBacktrace {
            thread_id: self.thread_id,
            thread_name: self.thread_name.clone(),
            frames,
        })
    }

    /// Generates a pretty backtrace that may includes file and line information
    /// for each frame, if available.
    pub fn force_pretty(&self) -> PrettyBacktrace {
        if let Ok(pretty) = self.pretty() {
            return pretty;
        }

        // Convert to the structure of a pretty backtrace, but without any
        // enrichment
        let frames = self
            .frames
            .iter()
            .map(|frame| PrettyFrame {
                frame: frame.clone(),
                symbol: None,
                locations: Vec::new(),
            })
            .collect();
        PrettyBacktrace {
            thread_id: self.thread_id,
            thread_name: self.thread_name.clone(),
            frames,
        }
    }

    /// Returns an iterator over the frames in the backtrace.
    pub fn iter(&self) -> impl Iterator<Item = &Frame> {
        self.frames.iter()
    }

    /// Returns the thread ID where the backtrace originated.
    pub fn thread_id(&self) -> Pid {
        self.thread_id
    }

    /// Returns the name of the thread for this backtrace.
    pub fn thread_name(&self) -> Option<String> {
        self.thread_name.clone()
    }
}

impl PrettyBacktrace {
    /// Returns an iterator over the frames in the backtrace.
    pub fn iter(&self) -> impl Iterator<Item = &PrettyFrame> {
        self.frames.iter()
    }

    /// Returns the name of the thread for this backtrace.
    pub fn thread_name(&self) -> Option<String> {
        self.thread_name.clone()
    }
}

impl PrettyFrame {
    /// The symbol for this frame, if any.
    pub fn symbol(&self) -> Option<&Symbol> {
        self.symbol.as_ref()
    }
}

impl IntoIterator for Backtrace {
    type Item = Frame;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.frames.into_iter()
    }
}

impl IntoIterator for PrettyBacktrace {
    type Item = PrettyFrame;
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
            // Frame number
            write!(f, "{:>4}: ", i)?;

            match &frame.symbol {
                Some(symbol) => writeln!(f, "{:#016x}: {:#}", frame.frame.ip, symbol)?,
                None => writeln!(f, "{:#}", frame.frame)?,
            }

            for location in &frame.locations {
                writeln!(f, "             at {}", location)?;
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
