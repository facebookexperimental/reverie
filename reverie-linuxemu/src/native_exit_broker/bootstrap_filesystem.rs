//! Kernel filesystem identity before any ambient inode getattr.
//!
//! Linux fs/proc/fd.c reports the held file's actual mount ID; fs/proc/namespace.c
//! reports sb->s_type->name in mountinfo. Neither asks that inode for attributes.
//! Unlike statfs.f_type, this identity cannot be supplied by a 9p server.
//! The launch contract keeps the original descriptor and mount reference alive:
//! its mount ID cannot be recycled while this lookup runs. A detached or hidden
//! mount missing from mountinfo fails closed. Internal shmem is handled through
//! the kernel F_GET_SEALS capability before this path.
//!
//! fdinfo can invoke descriptor-specific metadata hooks; this is not a universal
//! nonblocking-device guarantee. The audited local files and NFS/FUSE/9p regular
//! files have no such hook. Proc queries keep the original owner alive, so their
//! temporary reference cannot trigger its final release. Primary Linux sources:
//! <https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/proc/fd.c>
//! <https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/proc/namespace.c>
//! <https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/mm/memfd.c>

use std::os::fd::RawFd;

use super::AmbientClass;
use super::CoreError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LocalFilesystem {
    Ext,
    Btrfs,
    Tmpfs,
    Devtmpfs,
    Devpts,
}

impl LocalFilesystem {
    pub(super) fn regular_class(self) -> Option<AmbientClass> {
        match self {
            Self::Ext => Some(AmbientClass::Ext2OrExt4Regular),
            Self::Btrfs => Some(AmbientClass::BtrfsRegular),
            Self::Tmpfs => Some(AmbientClass::TmpfsRegular),
            // Shmem-backed devtmpfs regular files already passed F_GET_SEALS.
            // Its CONFIG_TMPFS=n ramfs variant is not an admitted regular class.
            Self::Devtmpfs | Self::Devpts => None,
        }
    }
}

fn read_proc(path: &str, operation: &'static str) -> Result<Vec<u8>, CoreError> {
    std::fs::read(path).map_err(|error| CoreError {
        operation,
        errno: error.raw_os_error().unwrap_or(libc::EIO),
    })
}

fn decimal(bytes: &[u8]) -> Result<u64, CoreError> {
    if bytes.is_empty() {
        return Err(CoreError::protocol("empty bootstrap mount ID"));
    }
    bytes.iter().try_fold(0u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return Err(CoreError::protocol("non-numeric bootstrap mount ID"));
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| CoreError::protocol("bootstrap mount ID overflow"))
    })
}

pub(super) fn mounted(fd: RawFd) -> Result<LocalFilesystem, CoreError> {
    let fdinfo = read_proc(&format!("/proc/self/fdinfo/{fd}"), "bootstrap fdinfo")?;
    let mut ids = fdinfo.split(|byte| *byte == b'\n').filter_map(|line| {
        let mut fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        (fields.next() == Some(b"mnt_id:".as_slice())).then(|| {
            let id = fields
                .next()
                .ok_or_else(|| CoreError::protocol("missing bootstrap mount ID"))?;
            if fields.next().is_some() {
                return Err(CoreError::protocol("extra bootstrap mount ID fields"));
            }
            decimal(id)
        })
    });
    let id = ids
        .next()
        .ok_or_else(|| CoreError::protocol("missing bootstrap fdinfo mount ID"))??;
    if ids.next().is_some() {
        return Err(CoreError::protocol("duplicate bootstrap fdinfo mount ID"));
    }
    let mounts = read_proc("/proc/self/mountinfo", "bootstrap mountinfo")?;
    let mut found = None;
    for line in mounts
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
        if decimal(fields[0])? != id {
            continue;
        }
        if found.is_some() || fields.len() < 10 {
            return Err(CoreError::protocol(
                "ambiguous or short bootstrap mountinfo",
            ));
        }
        let separator = fields
            .iter()
            .enumerate()
            .skip(6)
            .find_map(|(index, field)| (*field == b"-").then_some(index))
            .ok_or_else(|| CoreError::protocol("missing bootstrap mountinfo separator"))?;
        let name = fields
            .get(separator + 1)
            .ok_or_else(|| CoreError::protocol("missing bootstrap filesystem name"))?;
        found = Some(match *name {
            b"ext2" | b"ext3" | b"ext4" => LocalFilesystem::Ext,
            b"btrfs" => LocalFilesystem::Btrfs,
            b"tmpfs" => LocalFilesystem::Tmpfs,
            b"devtmpfs" => LocalFilesystem::Devtmpfs,
            b"devpts" => LocalFilesystem::Devpts,
            _ => {
                return Err(CoreError {
                    operation: "unproved ambient filesystem metadata-query class",
                    errno: libc::EOPNOTSUPP,
                });
            }
        });
    }
    found.ok_or(CoreError {
        operation: "ambient mount absent from bootstrap mountinfo",
        errno: libc::EOPNOTSUPP,
    })
}
