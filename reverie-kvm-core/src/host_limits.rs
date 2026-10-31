/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The host resources this backend's own process can run out of, and the
//! limits it runs out under, as the backend's refusals name them.
//!
//! Every guest process of this backend lives in one host process, so the
//! address space, the memory and the descriptors the backend uses for them
//! are that process's own, governed by its own limits. When the host refuses
//! one of them, the guest asked for nothing Linux would have refused it, and
//! the refusal names the resource and the limit rather than passing the
//! host's errno on as if it were the guest's.

use std::fmt;
use std::io;

/// A host resource of this process's own that the host can refuse it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostResource {
    /// Memory, or address space under `RLIMIT_AS`: ENOMEM from a host call,
    /// or the `OutOfMemory` of a fallible Rust allocation.
    Memory,
    /// This process's descriptors, under `RLIMIT_NOFILE` (EMFILE).
    Descriptors,
    /// The host's system-wide file table (ENFILE).
    FileTable,
}

impl HostResource {
    /// The resource running out, as a refusal says it.
    pub fn ran_out(self) -> &'static str {
        match self {
            Self::Memory => "host memory ran out",
            Self::Descriptors => "host file descriptors ran out",
            Self::FileTable => "the host's file table ran out",
        }
    }
}

/// A host resource this process ran out of, and the limit it ran out under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostResourceExhaustion {
    /// What ran out.
    pub resource: HostResource,
    /// The limit it ran out under, as a refusal names it, for example
    /// `this process's RLIMIT_AS (soft 9663676416 bytes, hard unlimited)`.
    pub limit: String,
}

impl HostResourceExhaustion {
    /// The exhaustion `error` reports, or `None` when `error` is not the host
    /// refusing this process a resource of its own.
    pub fn of(error: &io::Error) -> Option<Self> {
        let resource = if error.raw_os_error() == Some(libc::ENOMEM)
            || error.kind() == io::ErrorKind::OutOfMemory
        {
            HostResource::Memory
        } else {
            match error.raw_os_error() {
                Some(libc::EMFILE) => HostResource::Descriptors,
                Some(libc::ENFILE) => HostResource::FileTable,
                _ => return None,
            }
        };
        let limit = match resource {
            HostResource::Memory => {
                format!("this process's RLIMIT_AS ({})", address_space_limit_text())
            }
            HostResource::Descriptors => {
                format!("this process's RLIMIT_NOFILE ({})", descriptor_limit_text())
            }
            HostResource::FileTable => "the host's system-wide open-file limit".to_owned(),
        };
        Some(Self { resource, limit })
    }
}

impl fmt::Display for HostResourceExhaustion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} under {}", self.resource.ran_out(), self.limit)
    }
}

/// This process's `RLIMIT_AS` as a refusal names it, for example
/// `soft 9663676416 bytes, hard unlimited`.
pub fn address_space_limit_text() -> String {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only `limit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) } != 0 {
        return format!("unreadable ({})", io::Error::last_os_error());
    }
    limit_pair_text(limit, " bytes")
}

/// This process's `RLIMIT_NOFILE` as a refusal names it, for example
/// `soft 1024, hard 524288`.
pub fn descriptor_limit_text() -> String {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only `limit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return format!("unreadable ({})", io::Error::last_os_error());
    }
    limit_pair_text(limit, "")
}

fn limit_pair_text(limit: libc::rlimit, unit: &str) -> String {
    let value = |value: libc::rlim_t| {
        if value == libc::RLIM_INFINITY {
            "unlimited".to_owned()
        } else {
            format!("{value}{unit}")
        }
    };
    format!(
        "soft {}, hard {}",
        value(limit.rlim_cur),
        value(limit.rlim_max)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memory, descriptors and the file table are told apart, each with its
    /// own limit; any other error is not a host resource running out.
    #[test]
    fn each_exhausted_host_resource_is_named_with_its_limit() {
        for error in [
            io::Error::from_raw_os_error(libc::ENOMEM),
            io::Error::from(io::ErrorKind::OutOfMemory),
            io::Error::new(io::ErrorKind::OutOfMemory, "copying 4096 bytes"),
        ] {
            let exhaustion = HostResourceExhaustion::of(&error).expect("memory ran out");
            assert_eq!(exhaustion.resource, HostResource::Memory);
            assert!(
                exhaustion
                    .to_string()
                    .starts_with("host memory ran out under this process's RLIMIT_AS (soft "),
                "{exhaustion}"
            );
        }
        let descriptors =
            HostResourceExhaustion::of(&io::Error::from_raw_os_error(libc::EMFILE)).unwrap();
        assert_eq!(descriptors.resource, HostResource::Descriptors);
        assert!(
            descriptors.to_string().starts_with(
                "host file descriptors ran out under this process's RLIMIT_NOFILE (soft "
            ),
            "{descriptors}"
        );
        assert!(!descriptors.limit.contains("bytes"), "{descriptors}");
        let table =
            HostResourceExhaustion::of(&io::Error::from_raw_os_error(libc::ENFILE)).unwrap();
        assert_eq!(table.resource, HostResource::FileTable);
        assert_eq!(
            table.to_string(),
            "the host's file table ran out under the host's system-wide open-file limit"
        );
        for errno in [
            libc::ENOENT,
            libc::EACCES,
            libc::EIO,
            libc::ENOEXEC,
            libc::EAGAIN,
        ] {
            assert_eq!(
                HostResourceExhaustion::of(&io::Error::from_raw_os_error(errno)),
                None,
                "{errno}"
            );
        }
    }

    #[test]
    fn limits_are_named_in_their_units_or_as_unlimited() {
        let pair = |soft, hard| libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        assert_eq!(
            limit_pair_text(pair(4096, libc::RLIM_INFINITY), " bytes"),
            "soft 4096 bytes, hard unlimited"
        );
        assert_eq!(limit_pair_text(pair(64, 128), ""), "soft 64, hard 128");
    }
}
