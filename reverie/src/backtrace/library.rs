/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use super::Pid;

use std::path::PathBuf;

/// A segment of a memory map for a loaded library.
#[derive(Debug, Copy, Clone)]
pub struct LibrarySegment {
    /// The starting memory address of the library.
    start: u64,
    /// The ending memory address of the library.
    end: u64,
    /// The offset into the real file that this is mapped from.
    #[allow(unused)]
    offset: u64,
}

/// A loaded library. When the library is mapped into memory by the dynamic
/// loader, it consists of multiple segments.
#[derive(Debug, Clone)]
pub struct Library {
    /// The inode of the library.
    pub inode: u64,
    /// The path name of the library.
    pub path: PathBuf,
    /// The segments that are mapped into memory.
    pub segments: Vec<LibrarySegment>,
    /// The base address of the library.
    pub base: u64,
}

impl Library {
    /// Returns true if one of this library's mapped segments contains the given
    /// instruction pointer.
    pub fn contains_ip(&self, ip: u64) -> bool {
        for seg in &self.segments {
            if ip >= seg.start && ip < seg.end {
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Clone)]
pub struct Libraries {
    /// Libraries that have been loaded.
    libraries: Vec<Library>,
}

impl Libraries {
    /// Loads the list of libraries that have been mapped by the given process.
    pub fn new(pid: Pid) -> Result<Self, procfs::ProcError> {
        use procfs::process::MMapPath;
        use std::collections::BTreeMap;

        let process = procfs::process::Process::new(pid.as_raw())?;
        let maps = process.maps()?;

        let mut libraries = BTreeMap::new();

        for map in maps {
            if let MMapPath::Path(p) = map.pathname {
                let library = libraries.entry(map.inode).or_insert_with(|| Library {
                    inode: map.inode,
                    path: p,
                    segments: Vec::new(),
                    base: map.address.0,
                });

                library.segments.push(LibrarySegment {
                    start: map.address.0,
                    end: map.address.1,
                    offset: map.offset,
                });
            }
        }

        Ok(Self {
            libraries: libraries.into_values().collect(),
        })
    }

    /// Converts an instruction pointer to a virtual memory address.
    pub fn ip_to_vaddr(&self, ip: u64) -> Option<(&Library, u64)> {
        for lib in &self.libraries {
            if lib.contains_ip(ip) {
                return Some((lib, ip - lib.base - 1));
            }
        }

        None
    }

    /// Returns an iterator over the libraries.
    #[allow(unused)]
    pub fn iter(&self) -> impl Iterator<Item = &Library> {
        self.libraries.iter()
    }
}
