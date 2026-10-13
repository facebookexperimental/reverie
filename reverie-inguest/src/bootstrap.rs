//! Sealed inherited bootstrap shared by preload launchers and guest constructors.
//!
//! This module has no dependency on the optional host launcher. The legacy
//! protocol bytes and environment names are retained for existing consumers.

use std::ffi::OsString;
#[cfg(feature = "launcher")]
use std::fs::File;
use std::io;
#[cfg(feature = "launcher")]
use std::io::Write;
use std::mem::MaybeUninit;
#[cfg(feature = "launcher")]
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
#[cfg(feature = "launcher")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
#[cfg(feature = "launcher")]
use std::path::Path;
use std::path::PathBuf;

/// Environment variable naming the tool-specific preload DSO for a backend run.
pub const TOOL_PRELOAD_ENV: &str = "REVERIE_LITEINST_TOOL_PRELOAD";
/// Environment variable passed to legacy tool preloads with the coordinator path.
///
/// The tool-data launcher uses a sealed inherited bootstrap instead.
pub const COORDINATOR_ENV: &str = "REVERIE_LITEINST_COORDINATOR";
/// Environment variable naming the optional, stats-only coordinator socket.
pub const STATS_COORDINATOR_ENV: &str = "REVERIE_LITEINST_STATS_COORDINATOR";

const PRELOAD_BOOTSTRAP_MAGIC: &[u8; 16] = b"REVERIE-LI-V1\0\0\0";
const PRELOAD_BOOTSTRAP_HEADER_BYTES: usize = PRELOAD_BOOTSTRAP_MAGIC.len() + 4;
const PRELOAD_BOOTSTRAP_MAX_BYTES: usize = 4096;

// TODO-HUMAN-REVIEW(PR-139): Review the public inherited preload bootstrap contract.
/// Coordinator path and tool-specific bytes consumed by a preload constructor.
pub struct PreloadBootstrap {
    /// Unix-domain socket path for the generic tool coordinator.
    pub coordinator: PathBuf,
    /// Opaque bytes supplied by the tool-specific coordinator launcher.
    pub tool_data: Vec<u8>,
}

// TODO-HUMAN-REVIEW(PR-139): Review the public inherited preload bootstrap consumer.
/// Consumes the inherited generic-tool bootstrap, if one is present.
///
/// # Safety
///
/// Call only from a preload constructor launched by the shared preload launcher; this scans
/// inherited descriptors and consumes only a sealed, protocol-matching memfd.
pub unsafe fn take_preload_bootstrap() -> io::Result<Option<PreloadBootstrap>> {
    let mut found = Vec::new();
    // Listed with raw syscalls: read_dir's opendir would allocate through the
    // guest's malloc.
    for fd in crate::guest::support::open_descriptors()? {
        if fd <= libc::STDERR_FILENO {
            continue;
        }
        match read_preload_bootstrap(fd) {
            Ok(Some(bootstrap)) => {
                found.push((unsafe { OwnedFd::from_raw_fd(fd) }, bootstrap));
            }
            Ok(None) => {}
            Err(error) => {
                let _matching_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                return Err(error);
            }
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => {
            let (_fd, bootstrap) = found.pop().unwrap();
            Ok(Some(bootstrap))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multiple LiteInst preload bootstraps",
        )),
    }
}

pub(crate) fn read_preload_bootstrap(fd: libc::c_int) -> io::Result<Option<PreloadBootstrap>> {
    let required_seals =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // This runs inside the guest: raw syscalls, not libc's interposable
    // wrappers.
    use crate::trap::raw_syscall6;
    let seals = unsafe {
        raw_syscall6(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GET_SEALS as u64, 0, 0, 0, 0],
        )
    } as libc::c_int;
    if seals < 0 || seals & required_seals != required_seals {
        return Ok(None);
    }

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        raw_syscall6(
            libc::SYS_fstat,
            [fd as u64, stat.as_mut_ptr() as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        return Ok(None);
    }
    let size = match usize::try_from(unsafe { stat.assume_init() }.st_size) {
        Ok(size)
            if (PRELOAD_BOOTSTRAP_HEADER_BYTES..=PRELOAD_BOOTSTRAP_MAX_BYTES).contains(&size) =>
        {
            size
        }
        _ => return Ok(None),
    };
    let mut packet = vec![0_u8; size];
    let read = unsafe {
        raw_syscall6(
            libc::SYS_pread64,
            [
                fd as u64,
                packet.as_mut_ptr() as u64,
                packet.len() as u64,
                0,
                0,
                0,
            ],
        )
    };
    if read != size as i64
        || packet.get(..PRELOAD_BOOTSTRAP_MAGIC.len()) != Some(PRELOAD_BOOTSTRAP_MAGIC)
    {
        return Ok(None);
    }

    let lengths = &packet[PRELOAD_BOOTSTRAP_MAGIC.len()..PRELOAD_BOOTSTRAP_HEADER_BYTES];
    let path_len = u16::from_le_bytes([lengths[0], lengths[1]]) as usize;
    let data_len = u16::from_le_bytes([lengths[2], lengths[3]]) as usize;
    if packet.len() != PRELOAD_BOOTSTRAP_HEADER_BYTES + path_len + data_len || path_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid LiteInst preload bootstrap lengths",
        ));
    }
    let path_end = PRELOAD_BOOTSTRAP_HEADER_BYTES + path_len;
    Ok(Some(PreloadBootstrap {
        coordinator: PathBuf::from(OsString::from_vec(
            packet[PRELOAD_BOOTSTRAP_HEADER_BYTES..path_end].to_vec(),
        )),
        tool_data: packet[path_end..].to_vec(),
    }))
}

#[cfg(feature = "launcher")]
pub(crate) fn create_preload_bootstrap(
    coordinator: &Path,
    tool_data: &[u8],
) -> io::Result<OwnedFd> {
    let path = coordinator.as_os_str().as_bytes();
    let path_len = u16::try_from(path.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "LiteInst coordinator path exceeds the bootstrap limit",
        )
    })?;
    let data_len = u16::try_from(tool_data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "LiteInst tool bootstrap data exceeds the bootstrap limit",
        )
    })?;
    let mut packet =
        Vec::with_capacity(PRELOAD_BOOTSTRAP_HEADER_BYTES + path.len() + tool_data.len());
    packet.extend_from_slice(PRELOAD_BOOTSTRAP_MAGIC);
    packet.extend_from_slice(&path_len.to_le_bytes());
    packet.extend_from_slice(&data_len.to_le_bytes());
    packet.extend_from_slice(path);
    packet.extend_from_slice(tool_data);
    if packet.len() > PRELOAD_BOOTSTRAP_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LiteInst preload bootstrap exceeds its size limit",
        ));
    }

    let fd = unsafe {
        libc::memfd_create(
            c"reverie-liteinst-bootstrap".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&packet)?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(file.into())
}
