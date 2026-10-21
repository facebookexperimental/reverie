//! Explicit companion endpoint for authenticated private InitialImage setup.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
#[cfg(feature = "launcher")]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

const UNIX_PATH_BYTES: usize = 108;

/// Derive the existing fixed stats companion from an authenticated Tool RPC path.
/// Preserves the parent's raw bytes and the existing Unix-socket bounds.
#[doc(hidden)]
pub fn initial_image_stats_endpoint(tool_rpc: &Path) -> io::Result<PathBuf> {
    let bytes = tool_rpc.as_os_str().as_bytes();
    let parent = bytes
        .strip_suffix(b"/rpc.sock")
        .filter(|parent| !parent.is_empty())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid InitialImage RPC path")
        })?;
    if bytes.contains(&0) || bytes.len() >= UNIX_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "InitialImage RPC pathname exceeds Unix socket bounds",
        ));
    }
    let mut endpoint = parent.to_vec();
    endpoint.extend_from_slice(b"/stats.sock");
    if endpoint.len() >= UNIX_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "InitialImage statistics pathname exceeds Unix socket bounds",
        ));
    }
    Ok(PathBuf::from(OsString::from_vec(endpoint)))
}

#[cfg(feature = "launcher")]
pub(crate) fn check_owned_directory(
    tool_rpc: &Path,
    stats_rpc: &Path,
    owned_run_directory: &Path,
) -> io::Result<()> {
    let directory = std::fs::symlink_metadata(owned_run_directory)?;
    if !directory.is_dir()
        || directory.uid() != unsafe { libc::geteuid() }
        || directory.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "InitialImage run directory must be owned, non-symlink, and mode 0700",
        ));
    }
    let owned = std::fs::canonicalize(owned_run_directory)?;
    for endpoint in [tool_rpc, stats_rpc] {
        let parent = endpoint.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "InitialImage socket lacks parent",
            )
        })?;
        if std::fs::canonicalize(parent)? != owned {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "InitialImage socket parent is not the owned run directory",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(bytes: &[u8]) -> PathBuf {
        PathBuf::from(OsString::from_vec(bytes.to_vec()))
    }

    #[test]
    fn initial_stats_endpoint_preserves_exact_parent_bytes() {
        for (input, expected) in [
            (
                b"../run/rpc.sock".as_slice(),
                b"../run/stats.sock".as_slice(),
            ),
            (b"/a/rpc.sock".as_slice(), b"/a/stats.sock".as_slice()),
            (
                b"../r\xff/rpc.sock".as_slice(),
                b"../r\xff/stats.sock".as_slice(),
            ),
        ] {
            let endpoint = initial_image_stats_endpoint(&path(input)).unwrap();
            assert_eq!(endpoint.as_os_str().as_bytes(), expected);
        }
    }

    #[test]
    fn initial_stats_endpoint_rejects_missing_parent_aliases_and_nul() {
        for input in [
            b"".as_slice(),
            b"rpc.sock".as_slice(),
            b"/rpc.sock".as_slice(),
            b"run/other.sock".as_slice(),
            b"run/rpc.sock/".as_slice(),
            b"run\0/rpc.sock".as_slice(),
        ] {
            assert_eq!(
                initial_image_stats_endpoint(&path(input))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "accepted invalid endpoint bytes {input:?}"
            );
        }
    }

    #[test]
    fn initial_stats_endpoint_checks_both_unix_path_bounds() {
        let mut longest = vec![b'a'; 96];
        longest.extend_from_slice(b"/rpc.sock");
        assert_eq!(
            initial_image_stats_endpoint(&path(&longest))
                .unwrap()
                .as_os_str()
                .as_bytes()
                .len(),
            107
        );
        for parent_length in [97, 99] {
            let mut oversized = vec![b'a'; parent_length];
            oversized.extend_from_slice(b"/rpc.sock");
            assert_eq!(
                initial_image_stats_endpoint(&path(&oversized))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
