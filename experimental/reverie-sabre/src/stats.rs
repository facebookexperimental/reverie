/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed SaBRe patch-shape and slow-path statistics.

use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::BackendStatsRequest;
use reverie::BackendStatsSnapshot;
use reverie::BackendStatsSource;
use reverie::CounterSnapshot;

use crate::paths;
use crate::protected_files;

/// Private descriptor setting shared with the SaBRe loader.
pub const BACKEND_STATS_ENV: &str = "REVERIE_SABRE_BACKEND_STATS_FD";

const BACKEND_STATS_MAGIC: u64 = 0x3154_4154_5352_4253;
const BACKEND_STATS_VERSION: u32 = 1;
const PATCH_BUCKETS: usize = 15;
const PATCH_ROUTE_COUNT: usize = 3;
const SLOW_PATH_COUNT: usize = 10;

/// How SaBRe installed a syscall interception site.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum SabrePatchRoute {
    /// SaBRe installed a direct jump to an out-of-line trampoline.
    JumpTrampoline = 0,
    /// SaBRe's decoder installed a reserved SIGILL marker.
    RewriteSigillMarker = 1,
    /// Hermit's ptrace safety net installed a reserved SIGILL marker.
    PtraceInstalledMarker = 2,
}

impl fmt::Display for SabrePatchRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::JumpTrampoline => "jump_trampoline",
            Self::RewriteSigillMarker => "rewrite_sigill_marker",
            Self::PtraceInstalledMarker => "ptrace_installed_marker",
        })
    }
}

/// A SaBRe path that is materially slower than a rewritten jump trampoline.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum SabreSlowPath {
    /// Host ptracer observed a syscall-entry stop.
    PtraceSyscallEntry = 0,
    /// Host ptracer observed a syscall-exit stop.
    PtraceSyscallExit = 1,
    /// Host ptracer redirected a previously raw syscall site.
    PtraceRawSyscallRedirect = 2,
    /// SaBRe dispatched a decoder-installed SIGILL syscall marker.
    RewriteSigillDispatch = 3,
    /// SaBRe dispatched a ptrace-installed SIGILL syscall marker.
    PtraceInstalledSigillDispatch = 4,
    /// SaBRe dispatched an RDTSC SIGILL marker.
    RdtscSigillDispatch = 5,
    /// SaBRe dispatched an RDTSCP SIGILL marker.
    RdtscpSigillDispatch = 6,
    /// A vfork child executed an allowed syscall natively.
    VforkChildNativeDispatch = 7,
    /// A vfork child rejected a syscall that cannot run natively.
    VforkChildRejected = 8,
    /// Hermit's public-libc getrandom detour handled a call.
    LibcGetrandomDetour = 9,
}

impl fmt::Display for SabreSlowPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PtraceSyscallEntry => "ptrace_syscall_entry",
            Self::PtraceSyscallExit => "ptrace_syscall_exit",
            Self::PtraceRawSyscallRedirect => "ptrace_raw_syscall_redirect",
            Self::RewriteSigillDispatch => "rewrite_sigill_dispatch",
            Self::PtraceInstalledSigillDispatch => "ptrace_installed_sigill_dispatch",
            Self::RdtscSigillDispatch => "rdtsc_sigill_dispatch",
            Self::RdtscpSigillDispatch => "rdtscp_sigill_dispatch",
            Self::VforkChildNativeDispatch => "vfork_child_native_dispatch",
            Self::VforkChildRejected => "vfork_child_rejected",
            Self::LibcGetrandomDetour => "libc_getrandom_detour",
        })
    }
}

const PATCH_ROUTES: [SabrePatchRoute; PATCH_ROUTE_COUNT] = [
    SabrePatchRoute::JumpTrampoline,
    SabrePatchRoute::RewriteSigillMarker,
    SabrePatchRoute::PtraceInstalledMarker,
];

const SLOW_PATHS: [SabreSlowPath; SLOW_PATH_COUNT] = [
    SabreSlowPath::PtraceSyscallEntry,
    SabreSlowPath::PtraceSyscallExit,
    SabreSlowPath::PtraceRawSyscallRedirect,
    SabreSlowPath::RewriteSigillDispatch,
    SabreSlowPath::PtraceInstalledSigillDispatch,
    SabreSlowPath::RdtscSigillDispatch,
    SabreSlowPath::RdtscpSigillDispatch,
    SabreSlowPath::VforkChildNativeDispatch,
    SabreSlowPath::VforkChildRejected,
    SabreSlowPath::LibcGetrandomDetour,
];

#[repr(C)]
struct RawBackendStats {
    magic: u64,
    version: u32,
    size: u32,
    candidate_rips: AtomicU64,
    patched_rips: AtomicU64,
    classified_candidates: AtomicU64,
    cacheline_straddlers: AtomicU64,
    non_straddling: AtomicU64,
    instruction_lengths: [AtomicU64; PATCH_BUCKETS],
    straddle_after: [AtomicU64; PATCH_BUCKETS],
    patch_routes: [AtomicU64; PATCH_ROUTE_COUNT],
    slow_paths: [AtomicU64; SLOW_PATH_COUNT],
}

impl RawBackendStats {
    fn new() -> Self {
        Self {
            magic: BACKEND_STATS_MAGIC,
            version: BACKEND_STATS_VERSION,
            size: u32::try_from(size_of::<Self>()).expect("SaBRe stats page exceeds u32"),
            candidate_rips: AtomicU64::new(0),
            patched_rips: AtomicU64::new(0),
            classified_candidates: AtomicU64::new(0),
            cacheline_straddlers: AtomicU64::new(0),
            non_straddling: AtomicU64::new(0),
            instruction_lengths: std::array::from_fn(|_| AtomicU64::new(0)),
            straddle_after: std::array::from_fn(|_| AtomicU64::new(0)),
            patch_routes: std::array::from_fn(|_| AtomicU64::new(0)),
            slow_paths: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.magic != BACKEND_STATS_MAGIC
            || self.version != BACKEND_STATS_VERSION
            || usize::try_from(self.size).ok() != Some(size_of::<Self>())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incompatible SaBRe backend stats descriptor",
            ));
        }
        Ok(())
    }
}

struct SharedStats {
    page: NonNull<RawBackendStats>,
    fd: Option<OwnedFd>,
}

// The mapping contains only naturally aligned atomics and immutable header fields.
unsafe impl Send for SharedStats {}
unsafe impl Sync for SharedStats {}

impl SharedStats {
    fn map(fd: RawFd, owned_fd: Option<OwnedFd>) -> io::Result<Self> {
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size_of::<RawBackendStats>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            page: NonNull::new(mapping.cast()).expect("mmap returned a null SaBRe stats page"),
            fd: owned_fd,
        })
    }

    fn page(&self) -> &RawBackendStats {
        unsafe { self.page.as_ref() }
    }

    fn raw_fd(&self) -> RawFd {
        self.fd
            .as_ref()
            .expect("guest SaBRe stats mapping does not own its descriptor")
            .as_raw_fd()
    }
}

impl Drop for SharedStats {
    fn drop(&mut self) {
        let result =
            unsafe { libc::munmap(self.page.as_ptr().cast(), size_of::<RawBackendStats>()) };
        debug_assert_eq!(result, 0, "failed to unmap SaBRe backend stats page");
    }
}

/// Shared host-side SaBRe statistics recorder and snapshot source.
#[derive(Clone)]
pub struct SabreStats {
    shared: Arc<SharedStats>,
}

impl SabreStats {
    /// Creates the inherited shared page only when statistics were requested.
    pub fn create(request: BackendStatsRequest) -> io::Result<Option<Self>> {
        if !request.is_enabled() {
            return Ok(None);
        }

        let fd = unsafe {
            libc::memfd_create(
                c"reverie-sabre-backend-stats".as_ptr(),
                libc::MFD_ALLOW_SEALING,
            )
        };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::ftruncate(fd.as_raw_fd(), size_of::<RawBackendStats>() as libc::off_t) }
            == -1
        {
            return Err(io::Error::last_os_error());
        }
        let shared = SharedStats::map(fd.as_raw_fd(), Some(fd))?;
        unsafe { shared.page.as_ptr().write(RawBackendStats::new()) };

        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
        if unsafe { libc::fcntl(shared.raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self {
            shared: Arc::new(shared),
        }))
    }

    /// Returns the non-CLOEXEC descriptor inherited by the SaBRe loader.
    pub fn raw_fd(&self) -> RawFd {
        self.shared.raw_fd()
    }

    /// Records a host-installed syscall patch.
    pub fn record_patch(&self, rip: u64, instruction_length: u8, route: SabrePatchRoute) {
        assert!((1..=PATCH_BUCKETS as u8).contains(&instruction_length));
        let page = self.shared.page();
        page.candidate_rips.fetch_add(1, Ordering::Relaxed);
        page.patched_rips.fetch_add(1, Ordering::Relaxed);
        page.classified_candidates.fetch_add(1, Ordering::Relaxed);
        page.instruction_lengths[usize::from(instruction_length) - 1]
            .fetch_add(1, Ordering::Relaxed);
        let offset = (rip & 63) as u8;
        if offset + instruction_length > 64 {
            let prefix = 64 - offset;
            page.cacheline_straddlers.fetch_add(1, Ordering::Relaxed);
            page.straddle_after[usize::from(prefix) - 1].fetch_add(1, Ordering::Relaxed);
        } else {
            page.non_straddling.fetch_add(1, Ordering::Relaxed);
        }
        page.patch_routes[route as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Increments one host-owned SaBRe slow-path counter.
    pub fn increment_slow_path(&self, path: SabreSlowPath) {
        self.shared.page().slow_paths[path as usize].fetch_add(1, Ordering::Relaxed);
    }
}

/// Aggregate SaBRe patch instruction shapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SabrePatchShapeStats {
    /// Decoded syscall candidates.
    pub candidate_rips: u64,
    /// Successfully patched syscall candidates.
    pub patched_rips: u64,
    /// Candidates with an instruction-length classification.
    pub classified_candidates: u64,
    /// Candidates crossing a 64-byte cache-line boundary.
    pub cacheline_straddlers: u64,
    /// Candidates contained within one 64-byte cache line.
    pub non_straddling: u64,
    /// Exact instruction-length buckets ordered from one through fifteen bytes.
    pub instruction_lengths: [u64; PATCH_BUCKETS],
    /// Cache-line prefix buckets ordered from one through fifteen bytes.
    pub straddle_after: [u64; PATCH_BUCKETS],
}

/// Stable end-of-run SaBRe statistics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SabreStatsSnapshot {
    /// Patch instruction shape distribution.
    pub patch_shapes: SabrePatchShapeStats,
    /// Patch installation routes.
    pub patch_routes: CounterSnapshot<SabrePatchRoute>,
    /// Slow and semi-slow dispatch paths.
    pub slow_paths: CounterSnapshot<SabreSlowPath>,
}

impl fmt::Display for SabreStatsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "patches={{candidates={},patched={},classified={},straddlers={},non_straddling={},instruction_lengths={:?},straddle_after={:?}}} patch_routes={{",
            self.patch_shapes.candidate_rips,
            self.patch_shapes.patched_rips,
            self.patch_shapes.classified_candidates,
            self.patch_shapes.cacheline_straddlers,
            self.patch_shapes.non_straddling,
            self.patch_shapes.instruction_lengths,
            self.patch_shapes.straddle_after,
        )?;
        for (index, (route, count)) in self.patch_routes.counts().iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{route}={count}")?;
        }
        formatter.write_str("} slow_paths={")?;
        for (index, (path, count)) in self.slow_paths.counts().iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{path}={count}")?;
        }
        formatter.write_str("}")
    }
}

impl BackendStatsSnapshot for SabreStatsSnapshot {
    const BACKEND_NAME: &'static str = "sabre";
}

impl BackendStatsSource for SabreStats {
    type Snapshot = SabreStatsSnapshot;

    fn backend_stats(&self) -> Self::Snapshot {
        let page = self.shared.page();
        let patch_shapes = SabrePatchShapeStats {
            candidate_rips: page.candidate_rips.load(Ordering::Relaxed),
            patched_rips: page.patched_rips.load(Ordering::Relaxed),
            classified_candidates: page.classified_candidates.load(Ordering::Relaxed),
            cacheline_straddlers: page.cacheline_straddlers.load(Ordering::Relaxed),
            non_straddling: page.non_straddling.load(Ordering::Relaxed),
            instruction_lengths: std::array::from_fn(|index| {
                page.instruction_lengths[index].load(Ordering::Relaxed)
            }),
            straddle_after: std::array::from_fn(|index| {
                page.straddle_after[index].load(Ordering::Relaxed)
            }),
        };
        let patch_routes = CounterSnapshot::new(PATCH_ROUTES.into_iter().filter_map(|route| {
            let count = page.patch_routes[route as usize].load(Ordering::Relaxed);
            (count != 0).then_some((route, count))
        }));
        let slow_paths = CounterSnapshot::new(SLOW_PATHS.into_iter().filter_map(|path| {
            let count = page.slow_paths[path as usize].load(Ordering::Relaxed);
            (count != 0).then_some((path, count))
        }));
        SabreStatsSnapshot {
            patch_shapes,
            patch_routes,
            slow_paths,
        }
    }
}

static GUEST_STATS: OnceLock<Option<SharedStats>> = OnceLock::new();

pub(crate) fn init_guest_stats() {
    GUEST_STATS.get_or_init(|| {
        let value = unsafe { paths::take_private_env(BACKEND_STATS_ENV) }?;
        let fd = std::str::from_utf8(value.as_os_str().as_bytes())
            .ok()?
            .parse::<RawFd>()
            .ok()?;
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, info.as_mut_ptr()) } == -1
            || usize::try_from(unsafe { info.assume_init() }.st_size).ok()
                != Some(size_of::<RawBackendStats>())
        {
            panic!("invalid SaBRe backend stats descriptor");
        }
        let shared =
            SharedStats::map(fd, None).expect("failed to map SaBRe backend stats descriptor");
        shared
            .page()
            .validate()
            .expect("incompatible SaBRe backend stats descriptor");
        protected_files::protect_raw_fd(fd);
        Some(shared)
    });
}

/// Increments a guest-owned SaBRe slow-path counter when collection is enabled.
pub fn increment_guest_slow_path(path: SabreSlowPath) {
    if let Some(shared) = GUEST_STATS.get().and_then(Option::as_ref) {
        shared.page().slow_paths[path as usize].fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::mem::offset_of;

    use super::*;

    #[test]
    fn disabled_request_allocates_no_stats_page() {
        assert!(
            SabreStats::create(BackendStatsRequest::DISABLED)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn shared_page_layout_matches_sabre_c_abi() {
        assert_eq!(size_of::<RawBackendStats>(), 400);
        assert_eq!(offset_of!(RawBackendStats, candidate_rips), 16);
        assert_eq!(offset_of!(RawBackendStats, instruction_lengths), 56);
        assert_eq!(offset_of!(RawBackendStats, straddle_after), 176);
        assert_eq!(offset_of!(RawBackendStats, patch_routes), 296);
        assert_eq!(offset_of!(RawBackendStats, slow_paths), 320);
    }

    #[test]
    fn snapshot_preserves_process_aware_counts_and_enum_order() {
        let stats = SabreStats::create(BackendStatsRequest::ENABLED)
            .unwrap()
            .unwrap();
        stats.record_patch(0x103f, 2, SabrePatchRoute::PtraceInstalledMarker);
        stats.record_patch(0x103f, 2, SabrePatchRoute::JumpTrampoline);
        stats.increment_slow_path(SabreSlowPath::PtraceRawSyscallRedirect);
        stats.increment_slow_path(SabreSlowPath::PtraceSyscallEntry);

        let snapshot = stats.backend_stats();
        assert_eq!(snapshot.patch_shapes.candidate_rips, 2);
        assert_eq!(snapshot.patch_shapes.cacheline_straddlers, 2);
        assert_eq!(snapshot.patch_shapes.instruction_lengths[1], 2);
        assert_eq!(snapshot.patch_shapes.straddle_after[0], 2);
        assert_eq!(
            snapshot.patch_routes.counts(),
            &[
                (SabrePatchRoute::JumpTrampoline, 1),
                (SabrePatchRoute::PtraceInstalledMarker, 1),
            ]
        );
        assert_eq!(
            snapshot.slow_paths.counts(),
            &[
                (SabreSlowPath::PtraceSyscallEntry, 1),
                (SabreSlowPath::PtraceRawSyscallRedirect, 1),
            ]
        );
    }
}
