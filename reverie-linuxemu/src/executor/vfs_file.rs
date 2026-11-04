/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Open file descriptions (gVisor: pkg/sentry/vfs, FileDescription).
//!
//! R2 slice 1 (types only, not yet wired into the fd table): the
//! ownership/lifetime contract in
//! ai_docs/2026-11-04-linuxemu-r2-fd-contract.md distinguishes the
//! open-file-description owner -- this trait object -- from descriptor-entry
//! identity, per-descriptor flags, transient in-flight references, and task
//! ownership. Later slices move one descriptor kind at a time behind this
//! trait without changing publication or retirement semantics.

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::unix::io::AsRawFd;

/// One open file description: the object shared by dup/fork aliases.
pub trait FileDescription: std::fmt::Debug + Send + Sync {
    /// Host descriptor backing this description, if it has one.
    fn raw_fd(&self) -> Option<i32>;
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64>;
    /// Bytes readable without blocking (FIONREAD), where the kind has them.
    fn available(&mut self) -> std::io::Result<i32> {
        Err(std::io::Error::from_raw_os_error(libc::ENOTTY))
    }
}

/// A plain host file (gVisor: fsimpl/host).
#[derive(Debug)]
pub struct HostDescription {
    file: std::fs::File,
}

impl HostDescription {
    pub fn new(file: std::fs::File) -> Self {
        Self { file }
    }

    pub fn into_file(self) -> std::fs::File {
        self.file
    }
}

impl FileDescription for HostDescription {
    fn raw_fd(&self) -> Option<i32> {
        Some(self.file.as_raw_fd())
    }
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_description_roundtrips_through_the_trait() {
        let dir = std::env::temp_dir().join(format!("r2-vfs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut desc: Box<dyn FileDescription> = Box::new(HostDescription::new(file));
        assert!(desc.raw_fd().is_some_and(|fd| fd >= 0));
        assert_eq!(desc.write(b"hello").unwrap(), 5);
        assert_eq!(desc.seek(SeekFrom::Start(0)).unwrap(), 0);
        let mut buf = [0u8; 5];
        assert_eq!(desc.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf, b"hello");
    }
    #[test]
    fn pipe_description_reports_available_and_refuses_seek() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"abc").unwrap();
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(reader));
        let mut desc = PipeDescription::new(file);
        assert_eq!(desc.available().unwrap(), 3);
        assert_eq!(
            desc.seek(SeekFrom::Start(0)).unwrap_err().raw_os_error(),
            Some(libc::ESPIPE)
        );
        let mut buf = [0u8; 3];
        assert_eq!(desc.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"abc");
    }
}

/// A pipe end (gVisor: kernel/pipe). Seeking is ESPIPE, as on Linux.
#[derive(Debug)]
pub struct PipeDescription {
    file: std::fs::File,
}

impl PipeDescription {
    pub fn new(file: std::fs::File) -> Self {
        Self { file }
    }
}

impl FileDescription for PipeDescription {
    fn raw_fd(&self) -> Option<i32> {
        Some(self.file.as_raw_fd())
    }
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ESPIPE))
    }
    fn available(&mut self) -> std::io::Result<i32> {
        let mut count: libc::c_int = 0;
        // SAFETY: count is supervisor storage for one int; the descriptor is live.
        if unsafe { libc::ioctl(self.file.as_raw_fd(), libc::FIONREAD, &mut count) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(count)
    }
}
