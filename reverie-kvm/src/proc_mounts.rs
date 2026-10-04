/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io::Read;
use std::io::{self};

/// The namespace used by the backend's ordinary host filesystem operations.
/// Namespace-changing guest syscalls are unsupported, so fork and exec retain
/// this snapshot. The Tool remains responsible for deterministic normalization.
#[derive(Debug)]
pub(crate) struct ProcMountSnapshot {
    pub(crate) mountinfo: Vec<u8>,
    pub(crate) mounts: Vec<u8>,
}

impl ProcMountSnapshot {
    pub(crate) fn capture() -> io::Result<Self> {
        Ok(Self {
            mountinfo: read_snapshot("/proc/self/mountinfo")?,
            mounts: read_snapshot("/proc/self/mounts")?,
        })
    }
}

fn read_snapshot(path: &str) -> io::Result<Vec<u8>> {
    // A backend capacity refusal must not become a truncated mount table.
    const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
    read_snapshot_bytes(std::fs::File::open(path)?, MAX_SNAPSHOT_BYTES, path)
}

fn read_snapshot_bytes(source: impl Read, limit: u64, path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{path} is empty or exceeds the backend mount snapshot capacity"),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_snapshot_retains_exact_bytes_and_refuses_empty_or_oversized_input() {
        let input = b"10 9 0:1 / / rw - tmpfs tmpfs rw\n";
        assert_eq!(
            read_snapshot_bytes(input.as_slice(), input.len() as u64, "fixture").unwrap(),
            input
        );
        for (input, limit) in [(b"".as_slice(), 32), (b"12345".as_slice(), 4)] {
            assert_eq!(
                read_snapshot_bytes(input, limit, "fixture")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn mount_snapshot_propagates_read_error_without_partial_success() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(libc::EACCES))
            }
        }
        assert_eq!(
            read_snapshot_bytes(Broken, 32, "fixture")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
    }
}
