/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Owned immutable bytes and their sealed file descriptions. Validation and
//! mapping use this one object; no path is re-opened after validation.

use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::RawFd;
use std::path::Path;

use nix::fcntl::FcntlArg;
use nix::fcntl::SealFlag;
use nix::fcntl::fcntl;
use nix::sys::memfd::MFdFlags;
use nix::sys::memfd::memfd_create;
use reverie_loader::artifact;
use reverie_loader::image::ValidatedImage;

use super::Result;

/// Fixed image contract; neither image may initialize TLS in this slice.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// Fixed loader window and audited gate.
    Loader,
    /// Fixed runtime window and audited gate, with TLS refused.
    Runtime,
}

/// Validated bytes and their immutable source descriptor, inseparable for mapping.
pub struct SealedImage {
    file: File,
    bytes: Vec<u8>,
    kind: Kind,
}

impl SealedImage {
    /// Read a bounded image once, seal its actual memfd, then validate those bytes.
    pub fn read(path: &Path, kind: Kind) -> Result<Self> {
        // The mechanics probe accepts bounded artifacts, not an unbounded
        // allocation controlled by an ELF header or a growing input file.
        let mut input = Vec::new();
        File::open(path)?
            .take(512 * 1024 * 1024 + 1)
            .read_to_end(&mut input)?;
        if input.len() > 512 * 1024 * 1024 {
            return Err("loader refused: image exceeds the 512 MiB probe bound".into());
        }
        let mut file = File::from(memfd_create(
            c"reverie-stage1a-image",
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )?);
        file.write_all(&input)?;
        fcntl(
            &file,
            FcntlArg::F_ADD_SEALS(
                SealFlag::F_SEAL_WRITE
                    | SealFlag::F_SEAL_GROW
                    | SealFlag::F_SEAL_SHRINK
                    | SealFlag::F_SEAL_SEAL,
            ),
        )?;
        file.rewind()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let this = Self { file, bytes, kind };
        this.checked()?;
        Ok(this)
    }

    /// Validate the retained sealed bytes under this fixed image contract.
    pub fn checked(&self) -> Result<ValidatedImage<'_>> {
        match self.kind {
            Kind::Loader => artifact::check_loader(&self.bytes),
            // The generic artifact contract permits a later runtime to own
            // TLS. This mechanics probe deliberately initializes none.
            Kind::Runtime => artifact::check(
                &self.bytes,
                &reverie_loader::image::Policy {
                    window: artifact::RUNTIME_WINDOW,
                    allow_tls: false,
                },
                &[artifact::RUNTIME_GATE],
            ),
        }
        .map_err(|e| {
            let reason = match self.kind {
                Kind::Loader => "invalid_loader_image",
                Kind::Runtime => "invalid_runtime_image",
            };
            format!("{reason}: {e:?}").into()
        })
    }

    /// Exact descriptor inherited by the child and used for image mapping.
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsFd for SealedImage {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
