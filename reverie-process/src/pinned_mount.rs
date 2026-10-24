/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::fmt;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::fd::IntoRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use syscalls::Errno;

use super::fd::Fd;
use super::mount::BIND_RESTRICTIONS;
use super::mount::MountFlags;

const RETIRED: i32 = -1;
const LEASED: i32 = -2;

/// A source object pinned before a container changes its filesystem view.
///
/// Open this in the parent before cloning. A checked bind reopens the same
/// lexical path in the child's mount namespace and verifies the held object,
/// link bytes and mount policy. Keep a parent handle until the child is reaped.
///
/// After setup, call [`Self::retire`] in the child before starting workers.
/// Retirement affects every local clone, including handles held by [`crate::Mount`].
/// It does not affect the parent's copy when memory and descriptors are private.
#[derive(Clone)]
pub struct PinnedMountSource {
    inner: Arc<PinnedSource>,
}

struct PinnedSource {
    path: CString,
    descriptor: AtomicI32,
    identity: SourceIdentity,
    link: Option<Box<[u8]>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
    kind: libc::mode_t,
    pub(super) flags: libc::c_ulong,
}

impl SourceIdentity {
    pub(super) fn read(descriptor: i32) -> Result<Self, Errno> {
        let mut object = MaybeUninit::<libc::stat>::uninit();
        let mut view = MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: both calls write into their own caller-owned buffers.
        let (object, view) = unsafe {
            Errno::result(libc::fstat(descriptor, object.as_mut_ptr()))?;
            Errno::result(libc::fstatvfs(descriptor, view.as_mut_ptr()))?;
            (object.assume_init(), view.assume_init())
        };
        Ok(Self {
            device: object.st_dev,
            inode: object.st_ino,
            kind: object.st_mode & libc::S_IFMT,
            flags: view.f_flag,
        })
    }

    pub(super) fn is_dir(self) -> bool {
        self.kind == libc::S_IFDIR
    }

    pub(super) fn is_link(self) -> bool {
        self.kind == libc::S_IFLNK
    }

    pub(super) fn same_object(self, actual: Self) -> bool {
        self.device == actual.device && self.inode == actual.inode && self.kind == actual.kind
    }
}

impl PinnedMountSource {
    /// Pins the final source object without following its final symlink.
    ///
    /// The path must be absolute; intermediate symlinks and parent components
    /// retain their Linux meaning. A symlink's referent is a separate declared
    /// input. Paths containing NUL and links exceeding Linux PATH_MAX refuse.
    pub fn open(source: impl AsRef<OsStr>) -> Result<Self, Errno> {
        let source = source.as_ref();
        if !Path::new(source).is_absolute() {
            return Err(Errno::EINVAL);
        }
        let path = CString::new(source.as_bytes()).map_err(|_| Errno::EINVAL)?;
        let descriptor = Fd::open_c(
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        let identity = SourceIdentity::read(descriptor.as_raw_fd())?;
        let link = if identity.is_link() {
            let mut bytes = vec![0; libc::PATH_MAX as usize];
            let used = read_link(descriptor.as_raw_fd(), &mut bytes)?;
            bytes.truncate(used);
            Some(bytes.into_boxed_slice())
        } else {
            None
        };
        Ok(Self {
            inner: Arc::new(PinnedSource {
                path,
                descriptor: AtomicI32::new(descriptor.into_raw_fd()),
                identity,
                link,
            }),
        })
    }

    /// Reports whether the pinned object itself is a directory.
    pub fn is_dir(&self) -> bool {
        self.inner.identity.is_dir()
    }

    /// Retires this process's source capability across every local clone.
    ///
    /// This is idempotent. A concurrent checked mount returns EBUSY here rather
    /// than closing a descriptor it is using. On Linux close is not retried,
    /// including after EINTR, since retrying could close a reused descriptor.
    /// Never use a shared-memory or shared-descriptor clone for pinned mounts.
    pub fn retire(&self) -> Result<(), Errno> {
        let descriptor = self.inner.descriptor.load(Ordering::Acquire);
        match descriptor {
            RETIRED => Ok(()),
            LEASED => Err(Errno::EBUSY),
            descriptor => {
                self.inner
                    .descriptor
                    .compare_exchange(descriptor, RETIRED, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| Errno::EBUSY)?;
                // SAFETY: the successful transition transfers the unique owned
                // descriptor here. No File/OwnedFd also owns this raw number.
                Errno::result(unsafe { libc::close(descriptor) }).map(|_| ())
            }
        }
    }

    pub(super) fn path(&self) -> &CStr {
        &self.inner.path
    }

    pub(super) fn lease(&self) -> Result<SourceLease<'_>, Errno> {
        let descriptor = self.inner.descriptor.load(Ordering::Acquire);
        if descriptor == RETIRED {
            return Err(Errno::EBADF);
        }
        if descriptor == LEASED {
            return Err(Errno::EBUSY);
        }
        self.inner
            .descriptor
            .compare_exchange(descriptor, LEASED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Errno::EBUSY)?;
        Ok(SourceLease {
            source: &self.inner,
            descriptor,
        })
    }
}

impl fmt::Debug for PinnedMountSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedMountSource")
            .field("path", &self.inner.path)
            .field("identity", &self.inner.identity)
            .finish_non_exhaustive()
    }
}

impl PartialEq for PinnedMountSource {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for PinnedMountSource {}

impl Drop for PinnedSource {
    fn drop(&mut self) {
        let descriptor = *self.descriptor.get_mut();
        if descriptor >= 0 {
            // SAFETY: the last owner has exclusive access. A live lease borrows
            // an owner, so LEASED cannot be the last-owner state.
            unsafe { libc::close(descriptor) };
        }
    }
}

pub(super) struct SourceLease<'a> {
    source: &'a PinnedSource,
    descriptor: i32,
}

impl SourceLease<'_> {
    pub(super) fn reopen(&self) -> Result<Fd, Errno> {
        self.validate(self.descriptor, MountFlags::empty())?;
        let reopened = Fd::open_c(
            self.source.path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        self.validate(reopened.as_raw_fd(), MountFlags::empty())?;
        if !current_namespace_contains_mount(mount_id(reopened.as_raw_fd())?)? {
            return Err(Errno::EXDEV);
        }
        Ok(reopened)
    }

    pub(super) fn identity(&self) -> SourceIdentity {
        self.source.identity
    }

    pub(super) fn validate(&self, descriptor: i32, restrictions: MountFlags) -> Result<(), Errno> {
        if !(restrictions - BIND_RESTRICTIONS).is_empty() {
            return Err(Errno::EINVAL);
        }
        let actual = SourceIdentity::read(descriptor)?;
        let mut expected_flags = self.source.identity.flags;
        for (flag, probe) in [
            (MountFlags::MS_RDONLY, libc::ST_RDONLY),
            (MountFlags::MS_NOSUID, libc::ST_NOSUID),
            (MountFlags::MS_NODEV, libc::ST_NODEV),
            (MountFlags::MS_NOEXEC, libc::ST_NOEXEC),
        ] {
            if restrictions.contains(flag) {
                expected_flags |= probe;
            }
        }
        if !self.source.identity.same_object(actual) || actual.flags != expected_flags {
            return Err(Errno::ESTALE);
        }
        if let Some(expected) = &self.source.link {
            let mut bytes = [0; libc::PATH_MAX as usize];
            let used = read_link(descriptor, &mut bytes)?;
            if &bytes[..used] != expected.as_ref() {
                return Err(Errno::ESTALE);
            }
        }
        Ok(())
    }
}

impl Drop for SourceLease<'_> {
    fn drop(&mut self) {
        // Retirement could only observe LEASED and refuse while this lease was
        // alive. Restore the live number after all mount effects/checks finish.
        self.source
            .descriptor
            .store(self.descriptor, Ordering::Release);
    }
}

fn read_link(descriptor: i32, bytes: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: the syscall borrows the empty path and writes into this slice.
    let used = Errno::result(unsafe {
        libc::readlinkat(
            descriptor,
            c"".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    })? as usize;
    if used == bytes.len() {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(used)
}

/// Formats only known procfd prefixes into a caller-owned buffer.
pub(super) fn descriptor_path<'a>(
    prefix: &[u8],
    descriptor: i32,
    bytes: &'a mut [u8; 64],
) -> Result<&'a CStr, Errno> {
    let mut number = u32::try_from(descriptor).map_err(|_| Errno::EBADF)?;
    let mut digits = [0; 10];
    let mut count = 0;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    let end = prefix.len() + count;
    if end >= bytes.len() {
        return Err(Errno::ENAMETOOLONG);
    }
    bytes[..prefix.len()].copy_from_slice(prefix);
    for offset in 0..count {
        bytes[prefix.len() + offset] = digits[count - offset - 1];
    }
    bytes[end] = 0;
    CStr::from_bytes_with_nul(&bytes[..=end]).map_err(|_| Errno::EINVAL)
}

fn read_bytes(path: &CStr, mut consume: impl FnMut(u8) -> Result<(), Errno>) -> Result<(), Errno> {
    let descriptor = Fd::open_c(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)?;
    let mut bytes = [0; 256];
    loop {
        // SAFETY: read writes only into the caller-owned byte buffer.
        let used = unsafe {
            libc::read(
                descriptor.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if used < 0 {
            let error = Errno::last();
            if error == Errno::EINTR {
                continue;
            }
            return Err(error);
        }
        if used == 0 {
            return Ok(());
        }
        for &byte in &bytes[..used as usize] {
            consume(byte)?;
        }
    }
}

fn decimal(number: u64, byte: u8) -> Result<u64, Errno> {
    number
        .checked_mul(10)
        .and_then(|number| number.checked_add(u64::from(byte - b'0')))
        .ok_or(Errno::EOVERFLOW)
}

fn mount_id(descriptor: i32) -> Result<u64, Errno> {
    let mut path = [0; 64];
    let path = descriptor_path(b"/proc/self/fdinfo/", descriptor, &mut path)?;
    const PREFIX: &[u8] = b"mnt_id:";
    let mut prefix = 0;
    let mut number = None;
    let mut ended = false;
    let mut found = None;
    read_bytes(path, |byte| {
        if byte == b'\n' {
            if prefix == PREFIX.len() {
                let number = number.filter(|number| *number != 0).ok_or(Errno::EINVAL)?;
                if found.replace(number).is_some() {
                    return Err(Errno::EINVAL);
                }
            }
            prefix = 0;
            number = None;
            ended = false;
        } else if prefix < PREFIX.len() {
            if byte == PREFIX[prefix] {
                prefix += 1;
            } else {
                prefix = usize::MAX;
            }
        } else if prefix == PREFIX.len() {
            if byte.is_ascii_digit() && !ended {
                number = Some(decimal(number.unwrap_or(0), byte)?);
            } else if byte == b' ' || byte == b'\t' {
                ended |= number.is_some();
            } else {
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    })?;
    // A partial selected line is not accepted as a complete identity field.
    if prefix == PREFIX.len() {
        return Err(Errno::EINVAL);
    }
    found.ok_or(Errno::ENOENT)
}

fn current_namespace_contains_mount(wanted: u64) -> Result<bool, Errno> {
    let mut number = None;
    let mut columns = false;
    let mut found = false;
    read_bytes(c"/proc/self/mountinfo", |byte| {
        if byte == b'\n' {
            if !columns {
                return Err(Errno::EINVAL);
            }
            number = None;
            columns = false;
        } else if !columns {
            if byte.is_ascii_digit() {
                number = Some(decimal(number.unwrap_or(0), byte)?);
            } else if byte == b' ' {
                let id = number.filter(|number| *number != 0).ok_or(Errno::EINVAL)?;
                found |= id == wanted;
                columns = true;
            } else {
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    })?;
    if columns || number.is_some() {
        return Err(Errno::EINVAL);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::Container;
    use crate::Mount;
    use crate::MountFlags;
    use crate::Namespace;
    use crate::RunError;

    fn isolated_mounts() -> Container {
        let mut container = Container::new();
        container
            .map_root()
            .unshare(Namespace::MOUNT)
            .mount(Mount::new("/").rprivate());
        container
    }

    fn mount_error(result: Result<(), RunError>, expected: Errno) {
        match result {
            Err(RunError::Spawn(error)) => assert_eq!(Errno::from(error), expected),
            other => panic!("expected mount refusal {expected:?}, received {other:?}"),
        }
    }

    #[test]
    fn retirement_closes_all_clones_without_closing_a_reused_number() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let backing = tempfile::tempdir_in("/tmp").unwrap();
        let path = backing.path().join("input");
        fs::write(&path, b"input").unwrap();
        let source = PinnedMountSource::open(&path).unwrap();
        let clone = source.clone();
        let descriptor = source.inner.descriptor.load(Ordering::Acquire);
        let lease = source.lease().unwrap();
        let refusal = std::thread::scope(|scope| scope.spawn(|| clone.retire()).join().unwrap());
        assert_eq!(refusal, Err(Errno::EBUSY));
        assert!(SourceIdentity::read(descriptor).is_ok());
        drop(lease);
        source.retire().unwrap();
        assert!(matches!(clone.lease(), Err(Errno::EBADF)));
        assert_eq!(SourceIdentity::read(descriptor), Err(Errno::EBADF));

        let replacement = Fd::open(&path, libc::O_PATH | libc::O_CLOEXEC).unwrap();
        let replacement = if replacement.as_raw_fd() == descriptor {
            replacement
        } else {
            replacement.dup2(descriptor).unwrap()
        };
        clone.retire().unwrap();
        assert!(SourceIdentity::read(replacement.as_raw_fd()).is_ok());
        assert_eq!(
            Mount::bind_pinned(&clone, backing.path().join("target")).mount(),
            Err(Errno::EBADF)
        );
        assert!(SourceIdentity::read(replacement.as_raw_fd()).is_ok());
    }

    #[test]
    fn checked_bind_preserves_directory_file_and_symlink_objects() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let backing = tempfile::tempdir_in("/tmp").unwrap();
        let directory = backing.path().join("directory");
        let file = backing.path().join("file");
        let link = backing.path().join("link");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("marker"), b"directory").unwrap();
        fs::write(&file, b"file").unwrap();
        symlink("file", &link).unwrap();
        let sources = [
            PinnedMountSource::open(&directory).unwrap(),
            PinnedMountSource::open(&file).unwrap(),
            PinnedMountSource::open(&link).unwrap(),
        ];
        assert!(sources[0].is_dir());
        assert!(!sources[1].is_dir());
        assert!(!sources[2].is_dir());
        let descriptors = sources
            .each_ref()
            .map(|source| source.inner.descriptor.load(Ordering::Acquire));
        let parent_mounts = descriptors.map(|descriptor| mount_id(descriptor).unwrap());
        let targets =
            ["directory", "file", "link"].map(|name| backing.path().join("targets").join(name));
        let mut container = isolated_mounts();
        container.mount(
            Mount::bind_pinned(&sources[0], &targets[0])
                .recursive()
                .touch_target(),
        );
        container.mount(
            Mount::bind_pinned(&sources[1], &targets[1])
                .readonly()
                .touch_target(),
        );
        container.mount(
            Mount::bind_pinned(&sources[2], &targets[2])
                .readonly()
                .touch_target(),
        );
        container
            .run(|| {
                // No source capability survives setup, including Mount clones.
                for source in &sources {
                    source.retire().unwrap();
                }
                for descriptor in descriptors {
                    assert_eq!(SourceIdentity::read(descriptor), Err(Errno::EBADF));
                }
                for (index, target) in targets.iter().enumerate() {
                    let target =
                        Fd::open(target, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                            .unwrap();
                    let actual = SourceIdentity::read(target.as_raw_fd()).unwrap();
                    let expected = sources[index].inner.identity;
                    assert!(expected.same_object(actual));
                    assert_eq!(
                        actual.flags,
                        expected.flags | if index == 0 { 0 } else { libc::ST_RDONLY }
                    );
                    let target_mount = mount_id(target.as_raw_fd()).unwrap();
                    assert!(current_namespace_contains_mount(target_mount).unwrap());
                    assert!(!current_namespace_contains_mount(parent_mounts[index]).unwrap());
                }
                assert_eq!(fs::read(targets[0].join("marker")).unwrap(), b"directory");
                assert_eq!(fs::read_link(&targets[2]).unwrap(), Path::new("file"));
            })
            .unwrap();
        // Container::run has completed actual waitpid before returning.
        for (source, descriptor) in sources.iter().zip(descriptors) {
            assert!(SourceIdentity::read(descriptor).is_ok());
            assert!(source.lease().unwrap().reopen().is_ok());
        }
    }

    #[test]
    fn checked_socket_bind_adds_restrictions_without_changing_source_policy() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::io::Read;
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        use std::os::unix::net::UnixStream;

        for source_readonly in [false, true] {
            let backing = tempfile::tempdir_in("/tmp").unwrap();
            let directory = backing.path().join("source");
            fs::create_dir(&directory).unwrap();
            let socket = directory.join("channel");
            let listener = UnixListener::bind(&socket).unwrap();
            let mut outer = isolated_mounts();
            if source_readonly {
                outer.mount(Mount::bind(&directory, &directory).readonly());
            }
            outer
                .run(|| {
                    let source = PinnedMountSource::open(&socket).unwrap();
                    let expected = source.inner.identity;
                    if source_readonly {
                        assert_ne!(expected.flags & libc::ST_RDONLY, 0);
                    }
                    for readonly in [false, true] {
                        let target =
                            backing
                                .path()
                                .join(if readonly { "ro/socket" } else { "rw/socket" });
                        let mut mount = Mount::bind_pinned(&source, &target)
                            .flags(
                                MountFlags::MS_NOSUID
                                    | MountFlags::MS_NODEV
                                    | MountFlags::MS_NOEXEC,
                            )
                            .touch_target();
                        if readonly {
                            mount = mount.readonly();
                        }
                        isolated_mounts()
                            .mount(mount)
                            .run(|| {
                                let destination = Fd::open(
                                    &target,
                                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                                )
                                .unwrap();
                                let actual = SourceIdentity::read(destination.as_raw_fd()).unwrap();
                                assert!(expected.same_object(actual));
                                assert_eq!(
                                    actual.flags,
                                    expected.flags
                                        | libc::ST_NOSUID
                                        | libc::ST_NODEV
                                        | libc::ST_NOEXEC
                                        | if readonly { libc::ST_RDONLY } else { 0 }
                                );
                                let mut stream = UnixStream::connect(&target).unwrap();
                                stream.write_all(b"pinned").unwrap();
                                let (mut accepted, _) = listener.accept().unwrap();
                                let mut bytes = [0; 6];
                                accepted.read_exact(&mut bytes).unwrap();
                                assert_eq!(&bytes, b"pinned");
                                assert_eq!(
                                    SourceIdentity::read(
                                        source.lease().unwrap().reopen().unwrap().as_raw_fd()
                                    )
                                    .unwrap(),
                                    expected
                                );
                            })
                            .unwrap();
                        assert_eq!(
                            SourceIdentity::read(
                                source.lease().unwrap().reopen().unwrap().as_raw_fd()
                            )
                            .unwrap(),
                            expected
                        );
                    }
                })
                .unwrap();
        }
    }

    #[test]
    fn checked_bind_rejects_unsupported_flags_before_creating_target() {
        let backing = tempfile::tempdir_in("/tmp").unwrap();
        let source_path = backing.path().join("source");
        fs::write(&source_path, b"input").unwrap();
        let source = PinnedMountSource::open(&source_path).unwrap();
        for flag in [
            MountFlags::MS_REMOUNT,
            MountFlags::MS_MOVE,
            MountFlags::MS_PRIVATE,
            MountFlags::MS_SHARED,
            MountFlags::MS_SLAVE,
            MountFlags::MS_UNBINDABLE,
            MountFlags::MS_SYNCHRONOUS,
        ] {
            let target = backing.path().join("absent/target");
            assert_eq!(
                Mount::bind_pinned(&source, &target)
                    .readonly()
                    .flags(flag)
                    .touch_target()
                    .mount(),
                Err(Errno::EINVAL)
            );
            assert!(!target.parent().unwrap().exists());
            assert!(source.lease().unwrap().reopen().is_ok());
        }
    }

    #[test]
    fn checked_bind_preserves_recursive_submounts_and_refuses_changed_mount_policy() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let backing = tempfile::tempdir_in("/tmp").unwrap();
        let directory = backing.path().join("directory");
        let nested = directory.join("nested");
        let target = backing.path().join("target");
        fs::create_dir_all(&nested).unwrap();
        let mut outer = isolated_mounts();
        outer.mount(
            Mount::tmpfs(&nested)
                .flags(MountFlags::MS_NODEV | MountFlags::MS_NOSUID | MountFlags::MS_NOEXEC),
        );
        outer
            .run(|| {
                fs::write(nested.join("marker"), b"nested").unwrap();
                let source = PinnedMountSource::open(&directory).unwrap();
                let nested_fd = Fd::open(&nested, libc::O_PATH | libc::O_CLOEXEC).unwrap();
                let nested_identity = SourceIdentity::read(nested_fd.as_raw_fd()).unwrap();
                let mut child = isolated_mounts();
                child.mount(
                    Mount::bind_pinned(&source, &target)
                        .recursive()
                        .touch_target(),
                );
                child
                    .run(|| {
                        source.retire().unwrap();
                        let target_nested =
                            Fd::open(target.join("nested"), libc::O_PATH | libc::O_CLOEXEC)
                                .unwrap();
                        assert_eq!(
                            SourceIdentity::read(target_nested.as_raw_fd()).unwrap(),
                            nested_identity
                        );
                        assert_eq!(fs::read(target.join("nested/marker")).unwrap(), b"nested");
                    })
                    .unwrap();
                let mut policy_control = isolated_mounts();
                policy_control.mount(Mount::bind(&directory, &directory).recursive().readonly());
                policy_control
                    .run(|| {
                        let reopened = Fd::open(
                            &directory,
                            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                        .unwrap();
                        let actual = SourceIdentity::read(reopened.as_raw_fd()).unwrap();
                        let expected = source.inner.identity;
                        assert!(expected.same_object(actual));
                        assert_ne!(actual.flags, expected.flags);
                        assert_eq!(actual.flags, expected.flags | libc::ST_RDONLY);
                        assert!(matches!(
                            source.lease().unwrap().reopen(),
                            Err(Errno::ESTALE)
                        ));
                    })
                    .unwrap();
                let mut changed = isolated_mounts();
                changed.mount(Mount::bind(&directory, &directory).recursive().readonly());
                changed.mount(Mount::bind_pinned(&source, &target));
                mount_error(
                    changed.run(|| panic!("changed mount policy reached workload")),
                    Errno::ESTALE,
                );
                assert!(source.lease().unwrap().reopen().is_ok());
            })
            .unwrap();
    }

    #[test]
    fn checked_bind_refuses_replacement_missing_and_redirected_targets() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let backing = tempfile::tempdir_in("/tmp").unwrap();
        let path = backing.path().join("input");
        let old = backing.path().join("old");
        let target = backing.path().join("target");
        fs::write(&path, b"held").unwrap();
        let source = PinnedMountSource::open(&path).unwrap();
        fs::rename(&path, &old).unwrap();
        let mut missing = isolated_mounts();
        missing.mount(Mount::bind_pinned(&source, &target).touch_target());
        mount_error(
            missing.run(|| panic!("missing input reached workload")),
            Errno::ENOENT,
        );
        fs::write(&path, b"replacement").unwrap();
        let mut replaced = isolated_mounts();
        replaced.mount(Mount::bind_pinned(&source, &target).touch_target());
        mount_error(
            replaced.run(|| panic!("replacement reached workload")),
            Errno::ESTALE,
        );
        assert!(!target.exists());
        assert!(SourceIdentity::read(source.inner.descriptor.load(Ordering::Acquire)).is_ok());

        let live = PinnedMountSource::open(&old).unwrap();
        let outside = backing.path().join("outside");
        let redirect = backing.path().join("redirect");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &redirect).unwrap();
        let mut redirected = isolated_mounts();
        redirected.mount(Mount::bind_pinned(&live, redirect.join("input")).touch_target());
        mount_error(
            redirected.run(|| panic!("redirected target reached workload")),
            Errno::ELOOP,
        );
        assert!(!outside.join("input").exists());
        let mut wrong_type = isolated_mounts();
        wrong_type.mount(Mount::bind_pinned(&live, &outside));
        mount_error(
            wrong_type.run(|| panic!("incompatible target reached workload")),
            Errno::EISDIR,
        );
    }

    #[test]
    fn pinned_sources_refuse_shared_clone_contexts_before_clone() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let backing = tempfile::tempdir_in("/tmp").unwrap();
        let source = PinnedMountSource::open(backing.path()).unwrap();
        for flags in [
            libc::CLONE_VM,
            libc::CLONE_FILES,
            libc::CLONE_VFORK,
            libc::CLONE_THREAD,
        ] {
            let mut container = Container::new();
            container.unshare(Namespace::from_bits_retain(flags));
            assert_eq!(container.validate_pinned_clone(), Ok(()));
            container.mount(Mount::bind_pinned(&source, backing.path().join("target")));
            assert_eq!(container.validate_pinned_clone(), Err(Errno::EINVAL));
            mount_error(
                container.run(|| panic!("shared clone reached workload")),
                Errno::EINVAL,
            );
            let mut command = crate::Command::new("true");
            command
                .container
                .unshare(Namespace::from_bits_retain(flags));
            command
                .container
                .mount(Mount::bind_pinned(&source, backing.path().join("target")));
            assert_eq!(
                Errno::from(command.spawn().expect_err("shared spawn must refuse")),
                Errno::EINVAL
            );
        }
        assert!(source.lease().unwrap().reopen().is_ok());
    }

    #[test]
    fn refused_spawn_drops_callback_captures_before_the_launch_guard() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::sync::atomic::AtomicBool;
        struct Capture<'a> {
            dropped: &'a AtomicBool,
            under_guard: &'a AtomicBool,
            _heap: Vec<u8>,
        }
        impl Drop for Capture<'_> {
            fn drop(&mut self) {
                self.under_guard.store(
                    crate::launch_window::held_by_this_thread(),
                    Ordering::Release,
                );
                self.dropped.store(true, Ordering::Release);
            }
        }
        let backing = tempfile::tempdir_in("/tmp").unwrap();
        let source = PinnedMountSource::open(backing.path()).unwrap();
        let mut command = crate::Command::new("true");
        command
            .container
            .unshare(Namespace::from_bits_retain(libc::CLONE_VM));
        command
            .container
            .mount(Mount::bind_pinned(&source, backing.path().join("target")));
        let dropped = AtomicBool::new(false);
        let under_guard = AtomicBool::new(true);
        let capture = Capture {
            dropped: &dropped,
            under_guard: &under_guard,
            _heap: vec![7; 1024],
        };
        let refusal = command.spawn_with(move |_| {
            std::hint::black_box(&capture);
            panic!("shared clone reached the callback");
        });
        assert_eq!(
            Errno::from(refusal.expect_err("shared spawn must refuse")),
            Errno::EINVAL
        );
        assert!(dropped.load(Ordering::Acquire));
        assert!(!under_guard.load(Ordering::Acquire));
    }
}
