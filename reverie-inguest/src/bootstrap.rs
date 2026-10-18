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
use std::sync::OnceLock;

/// Environment variable naming the tool-specific preload DSO for a backend run.
pub const TOOL_PRELOAD_ENV: &str = "REVERIE_LITEINST_TOOL_PRELOAD";
/// Environment variable passed to legacy tool preloads with the coordinator path.
///
/// The tool-data launcher uses a sealed inherited bootstrap instead.
pub const COORDINATOR_ENV: &str = "REVERIE_LITEINST_COORDINATOR";
/// Environment variable naming the optional, stats-only coordinator socket.
pub const STATS_COORDINATOR_ENV: &str = "REVERIE_LITEINST_STATS_COORDINATOR";
/// Environment variable selecting whether an in-guest Tool patches syscall
/// sites (reverie-liteinst's `SITE_PATCHING_ENV`). A launcher that sends tool
/// data moves it from the command into the bootstrap (version 3), so the
/// runtime honors it and the guest does not see it.
pub const SITE_PATCHING_ENV: &str = "REVERIE_LITEINST_SITE_PATCHING";

const PRELOAD_BOOTSTRAP_MAGIC: &[u8; 16] = b"REVERIE-LI-V1\0\0\0";
const PRELOAD_BOOTSTRAP_HEADER_BYTES: usize = PRELOAD_BOOTSTRAP_MAGIC.len() + 4;
/// Version 2 adds the statistics coordinator's path after the Tool
/// coordinator's, so it need not travel in the guest's environment, where the
/// kernel copies it onto the initial stack and into `/proc/self/environ`.
const PRELOAD_BOOTSTRAP_MAGIC_V2: &[u8; 16] = b"REVERIE-LI-V2\0\0\0";
const PRELOAD_BOOTSTRAP_HEADER_BYTES_V2: usize = PRELOAD_BOOTSTRAP_MAGIC_V2.len() + 6;
/// Version 3 adds the site-patching selection, as one byte after the three
/// lengths: 0 unset, 1 on, 2 off. Its statistics path may be empty (none).
const PRELOAD_BOOTSTRAP_MAGIC_V3: &[u8; 16] = b"REVERIE-LI-V3\0\0\0";
const PRELOAD_BOOTSTRAP_HEADER_BYTES_V3: usize = PRELOAD_BOOTSTRAP_MAGIC_V3.len() + 7;
// Version 4 adds a correlation token for the parent-owned initial auxv
// channel. The token itself is not a completed write or its authority.
const PRELOAD_BOOTSTRAP_MAGIC_V4: &[u8; 16] = b"REVERIE-LI-V4\0\0\0";
const PRELOAD_BOOTSTRAP_HEADER_BYTES_V4: usize = PRELOAD_BOOTSTRAP_HEADER_BYTES_V3 + 64;
const PRELOAD_BOOTSTRAP_MAX_BYTES: usize = 4096;

/// The statistics coordinator named by the bootstrap this process image took.
static BOOTSTRAP_STATS_COORDINATOR: OnceLock<PathBuf> = OnceLock::new();

/// The site-patching selection of the bootstrap this process image took.
static BOOTSTRAP_SITE_PATCHING: OnceLock<bool> = OnceLock::new();

/// Whether the bootstrap this process image took with
/// [`take_preload_bootstrap`] selected syscall-site patching on (`true`) or
/// off (`false`); `None` when it said nothing. The Tool host prefers it to
/// [`SITE_PATCHING_ENV`].
pub fn bootstrap_site_patching() -> Option<bool> {
    BOOTSTRAP_SITE_PATCHING.get().copied()
}

/// The statistics coordinator's path from the bootstrap this process image
/// took with [`take_preload_bootstrap`], if the launcher sent one. The Tool
/// host prefers it to [`STATS_COORDINATOR_ENV`].
pub fn bootstrap_stats_coordinator() -> Option<&'static std::path::Path> {
    BOOTSTRAP_STATS_COORDINATOR.get().map(PathBuf::as_path)
}

// TODO-HUMAN-REVIEW(PR-139): Review the public inherited preload bootstrap contract.
/// Coordinator path and tool-specific bytes consumed by a preload constructor.
pub struct PreloadBootstrap {
    /// Unix-domain socket path for the generic tool coordinator.
    pub coordinator: PathBuf,
    /// Opaque bytes supplied by the tool-specific coordinator launcher.
    pub tool_data: Vec<u8>,
    /// Unix-domain socket path for the statistics coordinator, when the run
    /// collects statistics.
    pub stats_coordinator: Option<PathBuf>,
    /// The launcher's site-patching selection, when it made one.
    pub site_patching: Option<bool>,
    /// The initial-image channel to redeem before installing the ordinary
    /// Tool. A token is not state; use `initial_auxv::take_completed`.
    pub initial_auxv: Option<crate::initial_auxv::Token>,
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
            if let Some(stats) = &bootstrap.stats_coordinator {
                let _ = BOOTSTRAP_STATS_COORDINATOR.set(stats.clone());
            }
            if let Some(site_patching) = bootstrap.site_patching {
                let _ = BOOTSTRAP_SITE_PATCHING.set(site_patching);
            }
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
    if read != size as i64 {
        return Ok(None);
    }
    let magic = packet.get(..PRELOAD_BOOTSTRAP_MAGIC.len());
    let (header, version) = if magic == Some(PRELOAD_BOOTSTRAP_MAGIC) {
        (PRELOAD_BOOTSTRAP_HEADER_BYTES, 1)
    } else if magic == Some(PRELOAD_BOOTSTRAP_MAGIC_V2) && size >= PRELOAD_BOOTSTRAP_HEADER_BYTES_V2
    {
        (PRELOAD_BOOTSTRAP_HEADER_BYTES_V2, 2)
    } else if magic == Some(PRELOAD_BOOTSTRAP_MAGIC_V3) && size >= PRELOAD_BOOTSTRAP_HEADER_BYTES_V3
    {
        (PRELOAD_BOOTSTRAP_HEADER_BYTES_V3, 3)
    } else if magic == Some(PRELOAD_BOOTSTRAP_MAGIC_V4) && size >= PRELOAD_BOOTSTRAP_HEADER_BYTES_V4
    {
        (PRELOAD_BOOTSTRAP_HEADER_BYTES_V4, 4)
    } else {
        return Ok(None);
    };

    let lengths = &packet[PRELOAD_BOOTSTRAP_MAGIC.len()..header];
    let length =
        |index: usize| u16::from_le_bytes([lengths[2 * index], lengths[2 * index + 1]]) as usize;
    let path_len = length(0);
    let (stats_len, data_len) = if version == 1 {
        (0, length(1))
    } else {
        (length(1), length(2))
    };
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid LiteInst preload bootstrap lengths",
        )
    };
    let site_patching = match (version, lengths.get(6)) {
        (3 | 4, Some(0)) | (1 | 2, None) => None,
        (3 | 4, Some(1)) => Some(true),
        (3 | 4, Some(2)) => Some(false),
        _ => return Err(invalid()),
    };
    if packet.len() != header + path_len + stats_len + data_len
        || path_len == 0
        || (version == 2 && stats_len == 0)
    {
        return Err(invalid());
    }
    let path_end = header + path_len;
    let stats_end = path_end + stats_len;
    Ok(Some(PreloadBootstrap {
        coordinator: PathBuf::from(OsString::from_vec(packet[header..path_end].to_vec())),
        tool_data: packet[stats_end..].to_vec(),
        stats_coordinator: (stats_len > 0)
            .then(|| PathBuf::from(OsString::from_vec(packet[path_end..stats_end].to_vec()))),
        site_patching,
        initial_auxv: if version == 4 {
            Some(crate::initial_auxv::Token::decode(
                &packet[PRELOAD_BOOTSTRAP_HEADER_BYTES_V3..header],
            )?)
        } else {
            None
        },
    }))
}

/// The sealed bootstrap naming the Tool coordinator, and the statistics
/// coordinator too (version 2) when `stats` is given, and the site-patching
/// selection (version 3) when `site_patching` is given.
#[cfg(feature = "launcher")]
pub(crate) fn create_preload_bootstrap(
    coordinator: &Path,
    stats: Option<&Path>,
    site_patching: Option<bool>,
    tool_data: &[u8],
) -> io::Result<OwnedFd> {
    create_preload_bootstrap_with_auxv(coordinator, stats, site_patching, tool_data, None)
}

#[cfg(feature = "launcher")]
pub(crate) fn create_preload_bootstrap_with_auxv(
    coordinator: &Path,
    stats: Option<&Path>,
    site_patching: Option<bool>,
    tool_data: &[u8],
    initial_auxv: Option<crate::initial_auxv::Token>,
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
    let stats = stats.map(|stats| stats.as_os_str().as_bytes());
    let mut packet = Vec::with_capacity(
        PRELOAD_BOOTSTRAP_HEADER_BYTES_V3
            + path.len()
            + stats.map_or(0, <[u8]>::len)
            + tool_data.len(),
    );
    match (stats, site_patching, initial_auxv) {
        (stats, site_patching, Some(token)) => {
            let stats = stats.unwrap_or_default();
            let stats_len = u16::try_from(stats.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "statistics coordinator path exceeds limit",
                )
            })?;
            packet.extend_from_slice(PRELOAD_BOOTSTRAP_MAGIC_V4);
            packet.extend_from_slice(&path_len.to_le_bytes());
            packet.extend_from_slice(&stats_len.to_le_bytes());
            packet.extend_from_slice(&data_len.to_le_bytes());
            packet.push(match site_patching {
                None => 0,
                Some(true) => 1,
                Some(false) => 2,
            });
            packet.extend_from_slice(&token.encode());
            packet.extend_from_slice(path);
            packet.extend_from_slice(stats);
        }
        (stats, Some(site_patching), None) => {
            let stats = stats.unwrap_or_default();
            let stats_len = u16::try_from(stats.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "LiteInst statistics coordinator path exceeds the bootstrap limit",
                )
            })?;
            packet.extend_from_slice(PRELOAD_BOOTSTRAP_MAGIC_V3);
            packet.extend_from_slice(&path_len.to_le_bytes());
            packet.extend_from_slice(&stats_len.to_le_bytes());
            packet.extend_from_slice(&data_len.to_le_bytes());
            packet.push(if site_patching { 1 } else { 2 });
            packet.extend_from_slice(path);
            packet.extend_from_slice(stats);
        }
        (Some(stats), None, None) => {
            let stats_len = u16::try_from(stats.len())
                .ok()
                .filter(|length| *length > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "LiteInst statistics coordinator path is empty or exceeds the bootstrap limit",
                    )
                })?;
            packet.extend_from_slice(PRELOAD_BOOTSTRAP_MAGIC_V2);
            packet.extend_from_slice(&path_len.to_le_bytes());
            packet.extend_from_slice(&stats_len.to_le_bytes());
            packet.extend_from_slice(&data_len.to_le_bytes());
            packet.extend_from_slice(path);
            packet.extend_from_slice(stats);
        }
        (None, None, None) => {
            packet.extend_from_slice(PRELOAD_BOOTSTRAP_MAGIC);
            packet.extend_from_slice(&path_len.to_le_bytes());
            packet.extend_from_slice(&data_len.to_le_bytes());
            packet.extend_from_slice(path);
        }
    }
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
