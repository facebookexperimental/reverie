//! Explicit early-launch bootstrap. This is not a lazy embedding constructor.
//!
//! Primary no-flush classes are bound in BOOTSTRAP-PRIMARY-ADDENDUM.md. The
//! parent keeps every original alive throughout clone and child close_range;
//! this concerns only duplicate-close, not arbitrary final-release latency.

use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::rc::Rc;
use std::sync::Arc;

use super::BrokerClient;
use super::BrokerIdentity;
use super::BrokerOwner;
use super::CoreError;
use super::raw;

#[path = "bootstrap_filesystem.rs"]
mod filesystem;

/// Exclusive launch authority, deliberately neither Send nor Sync.
///
/// The caller must establish this contract, not infer it from /proc task count:
/// one host thread; no independent CLONE_FILES sharer or descriptor mutator;
/// no concurrent reaper of the new native child; no guest resources yet; all
/// ambient originals stay live until the clean-child acknowledgement; the
/// launcher will not exec while it owns the clone0 child. Catchable host signals
/// are blocked by bootstrap before the census, including signals normally
/// reserved by pthread. This does not prevent external SIGKILL/OOM.
///
/// The original creator thread must remain alive until actual broker reap,
/// with unchanged native credentials/user namespace/signal permission. Raw
/// helpers make no credential transitions. !Send is a local enforcement aid,
/// not permission to abandon the original thread while clients remain alive.
/// The one explicit exception is BrokerOwner::abort_failed_invocation: terminal
/// failure of the entire launcher process, with no normal cleanup receipt and
/// no promise that all clients/descendants have stopped. It can destroy worker
/// holdings before surviving clients retire their originals; it cannot be used
/// to continue this invocation or to claim successful broker settlement.
///
/// The ordinary Rust allocator/libc initialization must already be available.
/// No preinit-array safety is asserted for this constructor. The host's
/// /proc/self/{fd,fdinfo,mountinfo} must remain genuine procfs views, without
/// overmounts or replacement during bootstrap; supplied text is not authority.
pub struct StartupAuthority {
    _same_thread: PhantomData<Rc<()>>,
}

impl StartupAuthority {
    /// # Safety
    /// The full type-level launch contract must hold until bootstrap returns.
    pub unsafe fn assert_exclusive_early_launch() -> Self {
        Self {
            _same_thread: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmbientClass {
    PathOnly,
    Socket,
    Pipe,
    Ext2OrExt4Regular,
    BtrfsRegular,
    TmpfsRegular,
    NullDevice,
    ConventionalTtyAux,
    DevptsSlave,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmbientDescriptor {
    pub fd: RawFd,
    pub class: AmbientClass,
}

/// Setup failure owns any native child and unexpected received descriptors.
/// The caller must retain/reap `child`, if present, before discarding this
/// value. No guest references have been created by bootstrap. Query failures
/// before clone have no child and do not alter any ambient original.
#[must_use = "retain any child/received owners in a failed bootstrap"]
pub struct BootstrapFailure {
    pub cause: CoreError,
    pub descriptor: Option<RawFd>,
    pub child: Option<Box<BrokerOwner>>,
    pub unexpected_rights: Vec<OwnedFd>,
    pub mask_restore_error: Option<CoreError>,
}

impl BootstrapFailure {
    fn before_child(cause: CoreError, descriptor: Option<RawFd>) -> Self {
        Self {
            cause,
            descriptor,
            child: None,
            unexpected_rights: Vec::new(),
            mask_restore_error: None,
        }
    }
}

struct SignalMask {
    old: u64,
    active: bool,
}

impl SignalMask {
    fn block() -> Result<Self, CoreError> {
        let all = u64::MAX;
        let mut old = 0u64;
        let rc = unsafe {
            raw::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                (&all as *const u64) as usize,
                (&mut old as *mut u64) as usize,
                size_of::<u64>(),
                0,
                0,
            )
        };
        if rc < 0 {
            return Err(CoreError {
                operation: "bootstrap block mask",
                errno: -rc as i32,
            });
        }
        Ok(Self { old, active: true })
    }

    fn restore(&mut self) -> Result<(), CoreError> {
        if !self.active {
            return Ok(());
        }
        let rc = unsafe {
            raw::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                (&self.old as *const u64) as usize,
                0,
                size_of::<u64>(),
                0,
                0,
            )
        };
        if rc < 0 {
            return Err(CoreError {
                operation: "bootstrap restore mask",
                errno: -rc as i32,
            });
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for SignalMask {
    fn drop(&mut self) {
        // Unwind cannot leave a silently altered host mask. The supported raw
        // ABI cannot fail this operation with the same valid stack object that
        // block used. An actual restoration failure is a launcher failure, not
        // permission to resume the embedding runtime with changed semantics.
        if self.active && self.restore().is_err() {
            std::process::abort();
        }
    }
}

pub(super) fn start(_authority: StartupAuthority) -> Result<BrokerOwner, BootstrapFailure> {
    let mut mask =
        SignalMask::block().map_err(|cause| BootstrapFailure::before_child(cause, None))?;
    let result = start_masked();
    if let Err(cause) = mask.restore() {
        return Err(match result {
            Ok(child) => BootstrapFailure {
                cause: cause.clone(),
                descriptor: None,
                child: Some(Box::new(child)),
                unexpected_rights: Vec::new(),
                mask_restore_error: Some(cause),
            },
            Err(mut failure) => {
                failure.mask_restore_error = Some(cause);
                failure
            }
        });
    }
    result
}

fn start_masked() -> Result<BrokerOwner, BootstrapFailure> {
    let descriptors = census().map_err(|cause| BootstrapFailure::before_child(cause, None))?;
    let mut ambient = Vec::with_capacity(descriptors.len());
    for fd in descriptors {
        let class =
            classify(fd).map_err(|cause| BootstrapFailure::before_child(cause, Some(fd)))?;
        ambient.push(AmbientDescriptor { fd, class });
    }
    let (parent, child) =
        super::socket_pair().map_err(|cause| BootstrapFailure::before_child(cause, None))?;
    // Reserve all parent bookkeeping before clone. The child branch never runs
    // these Rust owners' destructors or allocator operations.
    let mut unexpected_rights = Vec::with_capacity(raw::MAX_RIGHTS);
    let creator_pid = unsafe { libc::getpid() };
    let creator_tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
    let client = BrokerClient {
        control: Arc::new(parent),
        process: creator_pid,
        identity: None,
    };
    // Separate files/mm/sighand, exit_signal=0. Parent SIGCHLD IGN/NOCLDWAIT is
    // untouched and cannot auto-reap this child. The launch owner waits for this
    // exact PID using __WCLONE, and must not exec while retaining the owner.
    let pid = unsafe { raw::syscall(libc::SYS_clone, 0, 0, 0, 0, 0, 0) };
    if pid == 0 {
        unsafe { raw::broker(child.as_raw_fd(), creator_pid) }
    }
    if pid < 0 {
        return Err(BootstrapFailure::before_child(
            CoreError {
                operation: "bootstrap clone0",
                errno: -pid as i32,
            },
            None,
        ));
    }
    // An internal socket duplicate only; child is already in its syscall-only
    // branch and the parent still owns every ambient original.
    drop(child);
    let mut owner = BrokerOwner {
        pid: pid as libc::pid_t,
        client,
        reaped: false,
        pidfd: None,
        ambient,
        creator_pid,
        creator_tid,
        _creator_thread: PhantomData,
    };
    let pidfd = unsafe { raw::syscall(libc::SYS_pidfd_open, pid as usize, 0, 0, 0, 0, 0) };
    if pidfd < 0 {
        return Err(BootstrapFailure {
            cause: CoreError {
                operation: "bootstrap pidfd",
                errno: -pidfd as i32,
            },
            descriptor: None,
            child: Some(Box::new(owner)),
            unexpected_rights,
            mask_restore_error: None,
        });
    }
    let pidfd = Arc::new(unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) });
    owner.pidfd = Some(pidfd);
    let mut frame = raw::Frame::new(0, 0, 0, 0);
    let mut rights = [-1; raw::MAX_RIGHTS];
    let mut received = 0;
    let rc = loop {
        let rc = unsafe {
            raw::receive_frame(
                owner.client.control.as_raw_fd(),
                &mut frame,
                rights.as_mut_ptr(),
                raw::MAX_RIGHTS,
                &mut received,
                false,
            )
        };
        if rc != -libc::EINTR {
            break rc;
        }
    };
    for fd in rights[..received].iter().copied() {
        unexpected_rights.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let error = if received != 0 {
        Some(CoreError::protocol("bootstrap unexpected rights (owned)"))
    } else if rc != 0 {
        Some(CoreError {
            operation: "bootstrap acknowledgement",
            errno: -rc,
        })
    } else if frame.kind == raw::ERROR
        && frame.job == 0
        && frame.count == 0
        && frame.status > 0
        && frame.status <= 4095
    {
        Some(CoreError {
            operation: "native bootstrap",
            errno: frame.status as i32,
        })
    } else if frame.kind != raw::BOOT
        || frame.job != 0
        || frame.sequence != 0
        || frame.count != 0
        || frame.status != 0
    {
        Some(CoreError::protocol("bootstrap acknowledgement identity"))
    } else {
        None
    };
    if let Some(cause) = error {
        // Return the native wait owner rather than losing an unreaped PID or
        // ordinarily destroying any unexpected received object. Before a good
        // BOOT there is no guest job; the launcher settles this setup failure.
        Err(BootstrapFailure {
            cause,
            descriptor: None,
            child: Some(Box::new(owner)),
            unexpected_rights,
            mask_restore_error: None,
        })
    } else {
        owner.client.identity = Some(Arc::new(BrokerIdentity {
            pid: owner.pid,
            pidfd: Arc::clone(owner.pidfd.as_ref().expect("successful bootstrap pidfd")),
        }));
        Ok(owner)
    }
}

fn census() -> Result<Vec<RawFd>, CoreError> {
    let path = b"/proc/self/fd\0";
    let fd = unsafe {
        raw::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD as usize,
            path.as_ptr() as usize,
            (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as usize,
            0,
            0,
            0,
        )
    };
    if fd < 0 {
        return Err(CoreError {
            operation: "open bootstrap fd census",
            errno: -fd as i32,
        });
    }
    let directory = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut fs) } != 0 {
        return Err(CoreError::last("statfs bootstrap fd census"));
    }
    if fs.f_type as u64 != 0x9fa0 {
        return Err(CoreError::protocol("fd census is not procfs"));
    }
    let mut fds = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let rc = unsafe {
            raw::syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd() as usize,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                0,
                0,
                0,
            )
        };
        if rc == -(libc::EINTR as isize) {
            continue;
        }
        if rc < 0 {
            return Err(CoreError {
                operation: "read bootstrap fd census",
                errno: -rc as i32,
            });
        }
        if rc == 0 {
            break;
        }
        let total = rc as usize;
        if total > buffer.len() {
            return Err(CoreError::protocol("fd census size"));
        }
        let mut offset = 0;
        while offset < total {
            // linux_dirent64 fixed prefix: ino8, off8, reclen2, type1.
            if total - offset < 20 {
                return Err(CoreError::protocol("fd census record prefix"));
            }
            let length = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if length < 20 || length > total - offset {
                return Err(CoreError::protocol("fd census record length"));
            }
            let tail = &buffer[offset + 19..offset + length];
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| CoreError::protocol("fd census name terminator"))?;
            let name = &tail[..end];
            if name != b"." && name != b".." {
                let mut number = 0i32;
                if name.is_empty() {
                    return Err(CoreError::protocol("empty fd census name"));
                }
                for byte in name {
                    if !byte.is_ascii_digit() {
                        return Err(CoreError::protocol("non-numeric fd census name"));
                    }
                    number = number
                        .checked_mul(10)
                        .and_then(|n| n.checked_add((byte - b'0') as i32))
                        .ok_or_else(|| CoreError::protocol("fd census number overflow"))?;
                }
                if number != directory.as_raw_fd() {
                    fds.push(number);
                }
            }
            offset += length;
        }
    }
    fds.sort_unstable();
    if fds.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CoreError::protocol(
            "fd census changed during quiescent launch",
        ));
    }
    Ok(fds)
}

fn classify(fd: RawFd) -> Result<AmbientClass, CoreError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(CoreError::last("bootstrap F_GETFL"));
    }
    if flags & libc::O_PATH != 0 {
        return Ok(AmbientClass::PathOnly);
    }
    if super::is_socket_file(fd)? {
        return Ok(AmbientClass::Socket);
    }
    if unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) } >= 0 {
        return Ok(AmbientClass::Pipe);
    }
    let pipe_error = CoreError::last("bootstrap F_GETPIPE_SZ");
    // The generic fcntl route returns EBADF when this is not one of the two
    // exact pipe fops. Other errors are not permission to continue by guessing.
    if pipe_error.errno != libc::EBADF {
        return Err(pipe_error);
    }
    // F_GET_SEALS identifies the kernel's shmem/hugetlb mapping, not a name or
    // server-reported filesystem magic. This also covers memfd's internal mount,
    // which need not occur in /proc/self/mountinfo. Querying seals changes none.
    if unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } >= 0 {
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(fd, &mut fs) } != 0 {
            return Err(CoreError::last("bootstrap sealed-file statfs"));
        }
        return if fs.f_type as u64 == 0x01021994 {
            Ok(AmbientClass::TmpfsRegular)
        } else {
            Err(CoreError {
                operation: "unproved ambient sealed-file flush class",
                errno: libc::EOPNOTSUPP,
            })
        };
    }
    let seals_error = CoreError::last("bootstrap F_GET_SEALS");
    if seals_error.errno != libc::EINVAL {
        return Err(seals_error);
    }
    // Inode getattr is not a harmless type query: NFS fstat flushes writes,
    // and 9p can do so even for TYPE-only statx with DONT_SYNC. 9p statfs can
    // also return the server's local-filesystem magic. Establish the actual
    // kernel filesystem through the continuously held descriptor first.
    let filesystem = filesystem::mounted(fd)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(CoreError::last("bootstrap fstat"));
    }
    let mode = stat.st_mode & libc::S_IFMT;
    if mode == libc::S_IFCHR {
        let major = libc::major(stat.st_rdev);
        let minor = libc::minor(stat.st_rdev);
        if major == 1 && minor == 3 {
            return Ok(AmbientClass::NullDevice);
        }
        if major == 5 && minor <= 2 {
            return Ok(AmbientClass::ConventionalTtyAux);
        }
        if filesystem == filesystem::LocalFilesystem::Devpts && major == 136 {
            return Ok(AmbientClass::DevptsSlave);
        }
    } else if mode == libc::S_IFREG {
        return filesystem.regular_class().ok_or(CoreError {
            operation: "unproved ambient regular-file flush class",
            errno: libc::EOPNOTSUPP,
        });
    }
    Err(CoreError {
        operation: "unproved ambient duplicate-close class",
        errno: libc::EOPNOTSUPP,
    })
}

impl std::fmt::Debug for BootstrapFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("BootstrapFailure")
            .field("cause", &self.cause)
            .field("descriptor", &self.descriptor)
            .field("child", &self.child)
            .field("unexpected_rights", &self.unexpected_rights.len())
            .field("mask_restore_error", &self.mask_restore_error)
            .finish()
    }
}
