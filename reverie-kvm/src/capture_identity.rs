// Private identities for the in-memory capture streams. An owned anonymous
// pipe endpoint reserves each native inode for the whole capture lifetime.
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use super::OutputAlias;

#[cfg(test)]
thread_local! {
    static PIPES_PREPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RELOCATION_FAILURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn pipes_prepared() -> usize {
    PIPES_PREPARED.get()
}

#[cfg(test)]
pub(super) fn relocation_failures() -> usize {
    RELOCATION_FAILURES.get()
}

#[cfg(test)]
pub(super) type CaptureDropProbe = Box<dyn FnOnce([std::os::fd::RawFd; 2]) + Send>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CaptureObjectIdentity {
    pub(super) device: libc::dev_t,
    pub(super) inode: libc::ino_t,
}

struct CapturePipe {
    identity: CaptureObjectIdentity,
    // Never installed in a guest file table, used for I/O, or exported.
    _keeper: OwnedFd,
}

impl CapturePipe {
    fn try_new() -> std::io::Result<Self> {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors has room for both newly owned endpoints.
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a successful pipe2 created both descriptors exclusively here.
        let keeper = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let unused = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        // A caller may have closed fd 0, 1 or 2. Never retain a private pipe in
        // the executor's implicit host-standard-descriptor namespace. Closing
        // the unused endpoint first bounds this relocation's descriptor peak.
        drop(unused);
        let keeper = if keeper.as_raw_fd() < 3 {
            // SAFETY: keeper is live; the returned descriptor is newly owned.
            let private = unsafe { libc::fcntl(keeper.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if private < 0 {
                let error = std::io::Error::last_os_error();
                #[cfg(test)]
                RELOCATION_FAILURES.set(RELOCATION_FAILURES.get() + 1);
                return Err(error);
            }
            let private = unsafe { OwnedFd::from_raw_fd(private) };
            drop(keeper);
            private
        } else {
            keeper
        };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: keeper is live and stat is writable storage.
        if unsafe { libc::fstat(keeper.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstat initialized stat on success.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err(std::io::Error::other("capture identity is not a pipe"));
        }
        // No writer or buffered data exists. Keep one endpoint to prevent inode
        // reuse; do not retain an extra descriptor merely to reserve its peer.
        #[cfg(test)]
        PIPES_PREPARED.set(PIPES_PREPARED.get() + 1);
        Ok(Self {
            identity: CaptureObjectIdentity {
                device: stat.st_dev,
                inode: stat.st_ino,
            },
            _keeper: keeper,
        })
    }
}

pub(super) struct CapturedPipeIdentities {
    stdout: CapturePipe,
    stderr: CapturePipe,
    #[cfg(test)]
    pub(super) drop_probe: std::sync::Mutex<Option<CaptureDropProbe>>,
}

impl CapturedPipeIdentities {
    pub(super) fn try_new() -> std::io::Result<Self> {
        let stdout = CapturePipe::try_new()?;
        let stderr = CapturePipe::try_new()?;
        Ok(Self {
            stdout,
            stderr,
            #[cfg(test)]
            drop_probe: std::sync::Mutex::new(None),
        })
    }

    pub(super) fn metadata(&self) -> CaptureMetadata {
        CaptureMetadata {
            stdout: self.stdout.identity,
            stderr: self.stderr.identity,
        }
    }

    #[cfg(test)]
    pub(super) fn descriptors(&self) -> [std::os::fd::RawFd; 2] {
        [
            self.stdout._keeper.as_raw_fd(),
            self.stderr._keeper.as_raw_fd(),
        ]
    }
}

#[cfg(test)]
impl Drop for CapturedPipeIdentities {
    fn drop(&mut self) {
        let probe = self.drop_probe.get_mut().unwrap().take();
        if let Some(probe) = probe {
            probe(self.descriptors());
        }
        // The real OwnedFd fields close only after this observation.
    }
}

#[derive(Clone, Copy)]
pub(super) struct CaptureMetadata {
    stdout: CaptureObjectIdentity,
    stderr: CaptureObjectIdentity,
}

impl CaptureMetadata {
    pub(super) fn identity(self, alias: OutputAlias) -> CaptureObjectIdentity {
        match alias {
            OutputAlias::Stdout => self.stdout,
            OutputAlias::Stderr => self.stderr,
        }
    }
}
