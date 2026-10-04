/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::convert::Infallible;
use core::fmt;
use core::ptr;
use core::str::FromStr;
use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub use nix::mount::MsFlags as MountFlags;
use syscalls::Errno;

use super::fd::FileType;
use super::fd::create_dir_all;
use super::fd::touch_path;

/// A mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mount {
    source: Option<CString>,
    target: CString,
    fstype: Option<CString>,
    flags: MountFlags,
    data: Option<CString>,
    touch_target: bool,
    allow_readonly_fallback: bool,
    /// A path, fstype or data string that could not be represented as a C
    /// string, recorded at BUILD time and reported at [`Mount::mount`] time.
    ///
    /// ⚠️ WHY A FLAG AND NOT A `Result` FROM THE BUILDER. `mount()` runs AFTER
    /// FORK, where this module documents that it cannot allocate -- so the
    /// failure cannot be discovered or described there. And making the builder
    /// fallible would change `Mount::new(..) -> Self` into
    /// `-> Result<Self, _>` for every caller, including hermit, to report a
    /// condition none of them can do anything about except refuse the mount.
    /// Recording one bool costs nothing after fork and turns a panic into the
    /// `Errno` the caller already handles.
    unrepresentable: bool,
}

/// Represents a bind mount. Can be converted into a [`Mount`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bind {
    /// The source path of the bind mount. This path must exist. It can be either
    /// a file or directory.
    pub source: CString,

    /// The target of the bind mount. This does not need to exist and can be
    /// created when performing the bind mount.
    pub target: CString,
}

/// `util::to_cstring` panics on an interior NUL. Every mount path, source,
/// fstype and data string went through it, so a recoverable "this is not a
/// valid C string" was a panic inside the builder. Measured on reverie main
/// 200439dc8de9:
///
/// ```text
/// Mount::new(OsStr::from_bytes(b"/test/work\0dir"))
///   panicked at reverie-process/src/util.rs:17:41:
///   called `Result::unwrap()` on an `Err` value: NulError(10, [...])
/// ```
///
/// This returns the empty string on failure and says so, letting the caller
/// record it and refuse the mount instead of aborting the process.
fn checked_cstring<S: AsRef<OsStr>>(s: S) -> (CString, bool) {
    match CString::new(s.as_ref().as_bytes()) {
        Ok(c) => (c, true),
        Err(_) => (CString::default(), false),
    }
}

impl Mount {
    /// Creates a new mount at the path `target`.
    pub fn new<S: AsRef<OsStr>>(target: S) -> Self {
        let (t, ok) = checked_cstring(target);
        Self {
            unrepresentable: !ok,
            source: None,
            target: t,
            fstype: None,
            flags: MountFlags::empty(),
            data: None,
            touch_target: false,
            allow_readonly_fallback: false,
        }
    }

    /// Creates a bind mount. This effectively creates hardlink of a directory,
    /// making the contents accessible at both places.
    ///
    /// By default, none of the mounts in the `source` directory are visible in
    /// `destination`. To make all mounts recursively visible, combine this with
    /// [`Mount::recursive`]. Can also be used with [`Mount::readonly`] to make
    /// the contents of `destination` read-only.
    pub fn bind<S: AsRef<OsStr>, D: AsRef<OsStr>>(source: S, destination: D) -> Self {
        Self::new(destination)
            .source(source)
            .flags(MountFlags::MS_BIND)
    }

    /// Move/rename a mount.
    pub fn rename<S: AsRef<OsStr>, D: AsRef<OsStr>>(source: S, destination: D) -> Self {
        Self::new(destination)
            .source(source)
            .flags(MountFlags::MS_MOVE)
    }

    /// Mount a fresh devpts file system. The target is usually `/dev/pts`.
    ///
    /// In order for this devpts to be private and independent of other devpts
    /// (i.e., for containers), use:
    /// ```no_compile
    /// Mount::devpts("/dev/pts").data("newinstance,ptmxmode=0666")
    /// ```
    /// And either make `/dev/ptmx` a symlink pointing to `/dev/pts/ptmx` or
    /// bind-mount it.
    ///
    /// See also: <https://www.kernel.org/doc/Documentation/filesystems/devpts.txt>
    pub fn devpts<S: AsRef<OsStr>>(target: S) -> Self {
        Self::new(target).fstype("devpts")
    }

    /// Mount a fresh proc file system at `/proc`.
    pub fn proc() -> Self {
        Self::new("/proc").fstype("proc")
    }

    /// Mount an overlay file system.
    ///
    /// NOTE: This only works in Linux 5.11 or newer when mounted from a user
    /// namespace. Otherwise, you need real root privileges to mount an
    /// overlayfs.
    ///
    /// An overlay filesystem combines two filesystems - an upper filesystem and
    /// a lower filesystem. When a name exists in both filesystems, the object
    /// in the upper filesystem is visible while the object in the lower
    /// filesystem is either hidden or, in the case of directories, merged with
    /// the upper object.
    ///
    /// In other words, the `lowerdir` and `upperdir` are combined into a
    /// directory `merged` using `workdir` as a temporary work area.
    ///
    /// The lower filesystem can be any filesystem supported by Linux and does
    /// not need to be writable. The lower filesystem can even be another
    /// overlayfs. The upper filesystem should be writable.
    ///
    /// See <https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html> for
    /// more information.
    ///
    /// # Arguments
    ///
    /// * `lowerdir` - The lower directory of the overlay. Can be any filesystem
    ///   and does not need to be writable. This directory is never
    ///   modified by writes to `merged`.
    /// * `upperdir` - The upper directory of the overlay. This is where all
    ///   changes to `merged` are collected. Does not need to be
    ///   empty, but should be when starting a new overlay from
    ///   scratch.
    /// * `workdir`  - The work directory. This should always be empty.
    /// * `merged`   - The combination of `lowerdir` and `upperdir`.
    pub fn overlay(lowerdir: &Path, upperdir: &Path, workdir: &Path, merged: &Path) -> Self {
        // TODO: Since there can actually be multiple lowerdirs, it might be
        // more ergonomic to return an `OverlayBuilder` instead.
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lowerdir.display(),
            upperdir.display(),
            workdir.display()
        );

        Self::new(merged)
            .fstype("overlay")
            .source("overlay")
            .data(options)
    }

    /// Creates a temporary file system at the location specified.
    pub fn tmpfs<S: AsRef<OsStr>>(target: S) -> Self {
        Self::new(target).fstype("tmpfs")
    }

    /// Creates a sys file system at the location specified. The target directory
    /// is usually `/sys`. This is useful when creating a network namespace.
    pub fn sysfs<S: AsRef<OsStr>>(target: S) -> Self {
        Self::new(target).fstype("sysfs")
    }

    /// Sets the mount point target.
    pub fn target<S: AsRef<OsStr>>(mut self, target: S) -> Self {
        let (t, ok) = checked_cstring(target);
        self.target = t;
        self.unrepresentable |= !ok;
        self
    }

    /// Returns the mount point target path.
    pub fn get_target(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.target.to_bytes()))
    }

    /// Sets the source of the mount.
    pub fn source<S: AsRef<OsStr>>(mut self, path: S) -> Self {
        let (v, ok) = checked_cstring(path);
        self.source = Some(v);
        self.unrepresentable |= !ok;
        self
    }

    /// Returns the mount point source path (if any).
    pub fn get_source(&self) -> Option<&Path> {
        self.source
            .as_ref()
            .map(|s| Path::new(OsStr::from_bytes(s.to_bytes())))
    }

    /// Indicates that the target of a bind mount should be created
    /// automatically.
    pub fn touch_target(mut self) -> Self {
        self.touch_target = true;
        self
    }

    /// Adds mount flags.
    pub fn flags(mut self, flags: MountFlags) -> Self {
        self.flags |= flags;
        self
    }

    /// Make the file system read-only.
    pub fn readonly(mut self) -> Self {
        self.flags |= MountFlags::MS_RDONLY;
        self
    }

    // TODO-HUMAN-REVIEW(PR-615)
    /// Allows a new writable proc mount that fails with `EPERM` to retry read-only.
    ///
    /// This explicitly permits the resulting mount to be less capable than
    /// requested. It has no effect on non-proc or already-read-only mounts,
    /// remounts, bind mounts, moves, or propagation changes.
    pub fn allow_readonly_fallback(mut self) -> Self {
        self.allow_readonly_fallback = true;
        self
    }

    /// Makes a bind mount recursive.
    pub fn recursive(mut self) -> Self {
        self.flags |= MountFlags::MS_REC;
        self
    }

    /// Makes this mount point private. Mount and unmount events do not propagate
    /// into or out of this mount point.
    pub fn private(mut self) -> Self {
        self.flags |= MountFlags::MS_PRIVATE;
        self
    }

    /// Make this mount point shared. Mount and unmount events immediately under
    /// this mount point will propagate to the other mount points that are
    /// members of this mount's peer group. Propagation here means that the same
    /// mount or unmount will automatically occur under all of the other mount
    /// points in the peer group. Conversely, mount and unmount events that take
    /// place under peer mount points will propagate to this mount point.
    pub fn shared(mut self) -> Self {
        self.flags |= MountFlags::MS_SHARED;
        self
    }

    /// Same as specifying both [`Mount::recursive`] and [`Mount::private`].
    pub fn rprivate(mut self) -> Self {
        self.flags |= MountFlags::MS_REC | MountFlags::MS_PRIVATE;
        self
    }

    /// Same as specifying both [`Mount::recursive`] and [`Mount::shared`].
    pub fn rshared(mut self) -> Self {
        self.flags |= MountFlags::MS_REC | MountFlags::MS_SHARED;
        self
    }

    /// Sets the filesystem type.
    pub fn fstype<S: AsRef<OsStr>>(mut self, fstype: S) -> Self {
        let (v, ok) = checked_cstring(fstype);
        self.fstype = Some(v);
        self.unrepresentable |= !ok;
        self
    }

    /// Sets any additional data required by the mount.
    pub fn data<S: AsRef<OsStr>>(mut self, data: S) -> Self {
        let (v, ok) = checked_cstring(data);
        self.data = Some(v);
        self.unrepresentable |= !ok;
        self
    }

    fn source_ptr(&self) -> *const libc::c_char {
        self.source.as_ref().map_or(ptr::null(), |s| s.as_ptr())
    }

    fn target_ptr(&self) -> *const libc::c_char {
        self.target.as_ptr()
    }

    fn fstype_ptr(&self) -> *const libc::c_char {
        self.fstype.as_ref().map_or(ptr::null(), |s| s.as_ptr())
    }

    fn data_ptr(&self) -> *const libc::c_void {
        self.data
            .as_ref()
            .map_or(ptr::null(), |s| s.as_ptr() as *const libc::c_void)
    }

    /// Performs the mount. For bind-mount operations, the target directory or
    /// file is created if [`touch_target`] was used.
    ///
    /// NOTE: This function *must* not allocate since it is called after `fork`
    /// (or `clone`) and before `execve`. Any allocations could cause deadlocks
    /// (which are hard to track down).
    /// The flags the kernel will not let a read-only bind remount drop, read back
    /// from the mount that now exists at our target.
    ///
    /// ⚠️ WITHOUT THIS, A READ-ONLY BIND OF A `nosuid` OR `nodev` SOURCE FAILS
    /// WITH EPERM AND THE WHOLE CONTAINER NEVER SPAWNS. Inside a user namespace
    /// the kernel locks these flags, and `do_remount` refuses any remount that
    /// would clear one; passing only `MS_RDONLY` asks to clear every other flag
    /// the source had. Re-supplying them asks for exactly what is already there,
    /// which is permitted.
    ///
    /// Measured 2026-08-27: this cost a whole validate arm. Hermit places its
    /// frozen `/etc/group` and empty nscd directory in TMPDIR and binds each
    /// read-only, so a TMPDIR on `/run/user/<uid>` -- `nosuid,nodev` on any
    /// systemd host -- failed every container spawn. 610 of that arm's 612 e2e
    /// rows came from this single mount, each one reading as a test result while
    /// measuring nothing. `nosuid` alone and `nodev` alone were each sufficient.
    ///
    /// ⚠️ `statfs` RATHER THAN `/proc/self/mountinfo` BECAUSE THIS RUNS AFTER
    /// FORK, where the surrounding contract forbids allocation. `statfs` is one
    /// syscall onto a caller-owned buffer and parses nothing.
    ///
    /// ⚠️ AND ONLY THE FLAGS WHOSE `ST_` AND `MS_` VALUES COINCIDE. That is true
    /// for `NOSUID`, `NODEV`, `NOEXEC`, `NOATIME` and `NODIRATIME`, and FALSE for
    /// `RELATIME`: `ST_RELATIME` is 0x1000 while `MS_RELATIME` is 0x200000, so
    /// copying the raw bits across would set `MS_SYNCHRONOUS`-adjacent garbage
    /// rather than the flag intended. Relatime is therefore left out; the kernel
    /// keeps the existing atime policy when a remount names none.
    fn locked_source_flags(&self) -> MountFlags {
        // SAFETY: `statfs` writes only into `buffer`, and `target_ptr` is a
        // NUL-terminated C string owned by `self` for the whole call.
        let mut buffer = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let flags = unsafe {
            if libc::statvfs(self.target_ptr(), buffer.as_mut_ptr()) != 0 {
                // Cannot read the source, so add nothing: the remount then
                // behaves exactly as it did before this function existed.
                return MountFlags::empty();
            }
            buffer.assume_init().f_flag
        };
        let mut preserved = MountFlags::empty();
        for (probe, flag) in [
            (libc::ST_NOSUID, MountFlags::MS_NOSUID),
            (libc::ST_NODEV, MountFlags::MS_NODEV),
            (libc::ST_NOEXEC, MountFlags::MS_NOEXEC),
            (libc::ST_NOATIME, MountFlags::MS_NOATIME),
            (libc::ST_NODIRATIME, MountFlags::MS_NODIRATIME),
        ] {
            if flags & probe != 0 {
                preserved |= flag;
            }
        }
        preserved
    }

    fn mount_with_flags(&self, flags: MountFlags) -> Result<(), Errno> {
        // SAFETY: Every non-null pointer comes from a live `CString` owned by
        // `self`, and `target` is always present. `mount` only borrows these
        // buffers for the duration of the syscall.
        Errno::result(unsafe {
            libc::mount(
                self.source_ptr(),
                self.target_ptr(),
                self.fstype_ptr(),
                flags.bits(),
                self.data_ptr(),
            )
        })?;

        Ok(())
    }

    fn readonly_proc_fallback(&self, error: Errno) -> Option<MountFlags> {
        let is_proc = self
            .fstype
            .as_ref()
            .is_some_and(|fstype| fstype.as_bytes() == b"proc");
        // These operations ignore the filesystem type, so `proc` does not
        // identify the filesystem being changed. Only a new mount can retry.
        let other_operations = MountFlags::MS_REMOUNT
            | MountFlags::MS_BIND
            | MountFlags::MS_MOVE
            | MountFlags::MS_SHARED
            | MountFlags::MS_PRIVATE
            | MountFlags::MS_SLAVE
            | MountFlags::MS_UNBINDABLE;
        (self.allow_readonly_fallback
            && error == Errno::EPERM
            && is_proc
            && !self.flags.intersects(other_operations)
            && !self.flags.contains(MountFlags::MS_RDONLY))
        .then_some(self.flags | MountFlags::MS_RDONLY)
    }

    pub(super) fn mount(&mut self) -> Result<(), Errno> {
        // ⚠️ REFUSE, DO NOT PANIC. A path/fstype/data string that is not a valid
        // C string was recorded at build time (see `unrepresentable`). This is
        // the first point that can report it, and it is a plain flag test
        // because this runs after fork where allocation is not available.
        // EINVAL is what the kernel returns for a malformed mount argument, so
        // the caller's existing error path already knows what to do with it.
        if self.unrepresentable {
            return Err(Errno::EINVAL);
        }
        // NOTE: Although we can't allocate here, we can safely *modify* `self`.
        // When this function is called, we have forked virtual memory and any
        // modifications we make are copy-on-write and lost when `execve` is
        // called. Thus, this function takes `self` by mutable reference.
        if self.flags.contains(MountFlags::MS_BIND) && self.touch_target {
            // Bind mounts will fail unless the destination path exists, so it
            // is convenient to create it automatically.
            //
            // One reason for doing this here instead of the parent process is
            // because the target may not yet exist until we mount it. For
            // example, if we want to create a `/tmp` (tmpfs) folder and then
            // bind-mount some files or directories into it, pre-creating the
            // destination directories won't work because they'll get created in
            // a different tmpfs.
            if let Some(src) = &self.source {
                if FileType::new(src.as_ptr())?.is_dir() {
                    create_dir_all(&self.target, 0o777)?;
                } else {
                    touch_path(&self.target, 0o666, 0o777)?;
                }
            }
        }

        match self.mount_with_flags(self.flags) {
            Err(error) => match self.readonly_proc_fallback(error) {
                Some(flags) => self.mount_with_flags(flags),
                None => Err(error),
            },
            result => result,
        }?;

        // Linux ignores MS_RDONLY on the initial bind mount. Apply per-mount flags with the
        // required bind remount so a read-only bind cannot mutate its source inode.
        if self.flags.contains(MountFlags::MS_BIND) && self.flags.contains(MountFlags::MS_RDONLY) {
            Errno::result(unsafe {
                libc::mount(
                    ptr::null(),
                    self.target_ptr(),
                    ptr::null(),
                    (self.flags | MountFlags::MS_REMOUNT | self.locked_source_flags()).bits(),
                    ptr::null(),
                )
            })?;
        }

        Ok(())
    }
}

impl Bind {
    /// Creates a new bind mount. The `target` is optional because it is often
    /// convenient to use an identical `source` and `target` directory. If
    /// `target` is `None`, then it is interpretted as being the same as
    /// `source`.
    pub fn new<S, T>(source: S, target: T) -> Self
    where
        S: AsRef<OsStr>,
        T: AsRef<OsStr>,
    {
        let (src, src_ok) = checked_cstring(source);
        let (tgt, tgt_ok) = checked_cstring(target);
        debug_assert!(
            src_ok && tgt_ok,
            "Bind path not representable as a C string; the Mount it converts \
             into is marked unrepresentable and its mount() will fail EINVAL"
        );
        Self {
            source: src,
            target: tgt,
        }
    }
}

impl From<Bind> for Mount {
    fn from(b: Bind) -> Self {
        let src_empty = b.source.as_bytes().is_empty();
        let tgt_empty = b.target.as_bytes().is_empty();
        Self {
            source: Some(b.source),
            target: b.target,
            fstype: None,
            flags: MountFlags::MS_BIND,
            data: None,
            touch_target: false,
            allow_readonly_fallback: false,
            // A Bind built from a path that was not representable as a C string
            // holds an EMPTY CString (see `checked_cstring`). Empty source or
            // target is never a valid bind mount, so it carries the refusal
            // forward rather than attempting mount(2) with "".
            unrepresentable: src_empty || tgt_empty,
        }
    }
}

impl From<&str> for Bind {
    fn from(s: &str) -> Self {
        if let Some((source, target)) = s.split_once(':') {
            Self {
                source: checked_cstring(source).0,
                target: checked_cstring(target).0,
            }
        } else {
            // A Rust `&str` may contain an interior NUL, so this path panicked
            // too. An unrepresentable path becomes empty here and the Mount it
            // converts into refuses with EINVAL.
            let source = checked_cstring(s).0;
            let target = source.clone();
            Self { source, target }
        }
    }
}

impl FromStr for Bind {
    type Err = Infallible;

    /// Parses bind mounts of the following forms:
    ///  1. "path/to/source"
    ///  2. "path/to/source:path/to/dest"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

/// An error from parsing a mount.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum MountParseError {
    /// The `target` key is missing. This is always required.
    MissingTarget,

    /// An invalid mount option was specified.
    Invalid(String, Option<String>),
}

impl fmt::Display for MountParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingTarget => write!(f, "missing mount target"),
            Self::Invalid(k, v) => match v {
                Some(v) => write!(f, "invalid mount option '{}={}'", k, v),
                None => write!(f, "invalid mount option '{}'", k),
            },
        }
    }
}

impl FromStr for Mount {
    type Err = MountParseError;

    /// Parses a [`Mount`]. This accepts the same syntax as Docker mounts where
    /// each mount consists of a comma-separated key-value list.
    ///
    /// See <https://docs.docker.com/storage/bind-mounts/> for more information.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut map: HashMap<&str, Option<&str>> = HashMap::new();

        for item in s.split(',') {
            let item = item.trim();

            if item.is_empty() {
                continue;
            }

            let (key, value) = match item.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (item, None),
            };

            map.insert(key, value);
        }

        // The mount target is always required.
        let mut mount = match map
            .remove("target")
            .or_else(|| map.remove("destination"))
            .or_else(|| map.remove("dest"))
            .or_else(|| map.remove("dst"))
            .flatten()
        {
            Some(target) => Mount::new(target),
            None => {
                return Err(MountParseError::MissingTarget);
            }
        };

        if let Some(source) = map.remove("source").or_else(|| map.remove("src")).flatten() {
            mount = mount.source(source);
        }

        let is_bind_mount = if let Some(fstype) = map.remove("type").flatten() {
            if fstype == "bind" {
                true
            } else {
                mount = mount.fstype(fstype);
                false
            }
        } else {
            true
        };

        if is_bind_mount {
            mount = mount.flags(MountFlags::MS_BIND);
        }

        if let Some((key, value)) = map.remove_entry("readonly") {
            if let Some(value) = value {
                // No value should have been specified.
                return Err(MountParseError::Invalid(key.into(), Some(value.to_owned())));
            }

            mount = mount.readonly();
        }

        if let Some(propagation) = map.remove("bind-propagation").flatten() {
            if !is_bind_mount {
                return Err(MountParseError::Invalid(
                    "bind-propagation".into(),
                    Some(propagation.into()),
                ));
            }
            let flags = match propagation {
                "shared" => MountFlags::MS_SHARED,
                "slave" => MountFlags::MS_SLAVE,
                "private" => MountFlags::MS_PRIVATE,
                "rshared" => MountFlags::MS_REC | MountFlags::MS_SHARED,
                "rslave" => MountFlags::MS_REC | MountFlags::MS_SLAVE,
                "rprivate" => MountFlags::MS_REC | MountFlags::MS_PRIVATE,
                _ => {
                    return Err(MountParseError::Invalid(
                        "bind-propagation".into(),
                        Some(propagation.into()),
                    ));
                }
            };

            mount = mount.flags(flags);
        } else if is_bind_mount {
            // Bind mounts are private by default. Propagation flags are a
            // separate mount operation and are invalid on a fresh tmpfs mount.
            mount = mount.flags(MountFlags::MS_REC | MountFlags::MS_PRIVATE);
        }

        // Any left over keys are invalid.
        if let Some((k, v)) = map.into_iter().next() {
            return Err(MountParseError::Invalid(k.into(), v.map(ToOwned::to_owned)));
        }

        Ok(mount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getters_and_setters() {
        let m = Mount::bind("/foo", "/bar");
        assert_eq!(m.get_target(), Path::new("/bar"));
        assert_eq!(m.get_source(), Some(Path::new("/foo")));

        let m = m.target("/baz");
        assert_eq!(m.get_target(), Path::new("/baz"));
    }

    #[test]
    fn proc_mount_retries_readonly_only_after_permission_denial() {
        let proc_mount = Mount::proc();
        assert_eq!(proc_mount.readonly_proc_fallback(Errno::EPERM), None);
        assert_eq!(
            proc_mount
                .clone()
                .allow_readonly_fallback()
                .readonly_proc_fallback(Errno::EPERM),
            Some(MountFlags::MS_RDONLY)
        );
        assert_eq!(
            proc_mount
                .clone()
                .allow_readonly_fallback()
                .readonly_proc_fallback(Errno::ENOENT),
            None
        );
        assert_eq!(
            Mount::proc()
                .readonly()
                .allow_readonly_fallback()
                .readonly_proc_fallback(Errno::EPERM),
            None
        );
        assert_eq!(
            Mount::tmpfs("/tmp")
                .allow_readonly_fallback()
                .readonly_proc_fallback(Errno::EPERM),
            None
        );
    }

    #[test]
    fn proc_mount_readonly_fallback_excludes_other_mount_operations() {
        let mount = Mount::proc().allow_readonly_fallback();
        let ordinary_flags = MountFlags::MS_NOSUID | MountFlags::MS_NODEV | MountFlags::MS_NOEXEC;
        assert_eq!(
            mount
                .clone()
                .flags(ordinary_flags)
                .readonly_proc_fallback(Errno::EPERM),
            Some(ordinary_flags | MountFlags::MS_RDONLY)
        );
        for flags in [
            MountFlags::MS_REMOUNT,
            MountFlags::MS_BIND,
            MountFlags::MS_MOVE,
            MountFlags::MS_SHARED,
            MountFlags::MS_PRIVATE,
            MountFlags::MS_SLAVE,
            MountFlags::MS_UNBINDABLE,
            MountFlags::MS_REMOUNT | MountFlags::MS_BIND,
            MountFlags::MS_BIND | MountFlags::MS_REC,
            MountFlags::MS_SHARED | MountFlags::MS_REC,
            MountFlags::MS_PRIVATE | MountFlags::MS_REC,
            MountFlags::MS_SLAVE | MountFlags::MS_REC,
            MountFlags::MS_UNBINDABLE | MountFlags::MS_REC,
        ] {
            assert_eq!(
                mount
                    .clone()
                    .flags(flags)
                    .readonly_proc_fallback(Errno::EPERM),
                None,
                "must not retry a non-creation mount operation: {flags:?}"
            );
        }
    }

    #[test]
    fn parse_mount() {
        assert_eq!(
            Mount::from_str("type=bind,source=/foo,target=/bar,readonly"),
            Ok(Mount::bind("/foo", "/bar").readonly().rprivate())
        );
        assert_eq!(
            Mount::from_str("src=/foo,target=/bar,readonly"),
            Ok(Mount::bind("/foo", "/bar").readonly().rprivate())
        );
        assert_eq!(
            Mount::from_str("src=/foo,target=/bar,bind-propagation=rshared"),
            Ok(Mount::bind("/foo", "/bar").rshared())
        );
        assert_eq!(
            Mount::from_str("type=tmpfs,target=/tmp"),
            Ok(Mount::tmpfs("/tmp"))
        );
        assert_eq!(
            Mount::from_str("type=tmpfs,target=/tmp,bind-propagation=rprivate"),
            Err(MountParseError::Invalid(
                "bind-propagation".into(),
                Some("rprivate".into())
            ))
        );
        assert_eq!(
            Mount::from_str("target=foo, ,,,"),
            Ok(Mount::new("foo").flags(MountFlags::MS_BIND).rprivate())
        );

        assert_eq!(Mount::from_str(""), Err(MountParseError::MissingTarget));
        assert_eq!(
            Mount::from_str("type=bind,source=/foo,readonly"),
            Err(MountParseError::MissingTarget)
        );
        assert_eq!(
            Mount::from_str("type=tmpfs,target=/foo,wat"),
            Err(MountParseError::Invalid("wat".into(), None))
        );
        assert_eq!(
            Mount::from_str("type=tmpfs,target=/foo,readonly=wat"),
            Err(MountParseError::Invalid(
                "readonly".into(),
                Some("wat".into())
            ))
        );
    }

    #[test]
    fn parse_bind() {
        assert_eq!(Bind::from("source:target"), Bind::new("source", "target"));
        assert_eq!(Bind::from("source"), Bind::new("source", "source"));

        assert_eq!(
            Mount::from(Bind::from("source:target")),
            Mount::bind("source", "target")
        );
    }
}

#[cfg(test)]
mod unrepresentable_paths_are_refused_not_panics {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    use syscalls::Errno;

    use super::Bind;
    use super::Mount;

    /// ⚠️ THIS PANICKED BEFORE, AND THE PANIC WAS THE WHOLE DEFECT. Every mount
    /// path went through `util::to_cstring`, which unwraps `CString::new`.
    /// Measured on reverie main 200439dc8de9:
    ///   panicked at reverie-process/src/util.rs:17:41:
    ///   called `Result::unwrap()` on an `Err` value: NulError(10, [...])
    /// A recoverable "this path is not a valid C string" aborted the process.
    #[test]
    fn a_target_with_an_interior_nul_refuses_instead_of_panicking() {
        let bad = OsStr::from_bytes(b"/test/work\0dir");
        let mut m = Mount::new(bad);
        assert_eq!(m.mount(), Err(Errno::EINVAL));
    }

    #[test]
    fn an_unrepresentable_source_fstype_or_data_also_refuses() {
        let bad = OsStr::from_bytes(b"bad\0value");
        for m in [
            Mount::new("/test").source(bad),
            Mount::new("/test").fstype(bad),
            Mount::new("/test").data(bad),
        ] {
            let mut m = m;
            assert_eq!(m.mount(), Err(Errno::EINVAL));
        }
    }

    /// ⚠️ THE CONTROL, WITHOUT WHICH THE THREE ABOVE PROVE NOTHING. A refusal
    /// that fired on every mount would pass them and break every real mount.
    /// A representable path must NOT be marked unrepresentable -- it must get
    /// past the flag test and fail (or succeed) on the real syscall instead.
    #[test]
    fn a_representable_path_is_not_refused_by_this_check() {
        let mut m = Mount::new("/test/workdir").fstype("tmpfs");
        let got = m.mount();
        assert_ne!(
            got,
            Err(Errno::EINVAL),
            "a valid path must reach mount(2); EINVAL here means the refusal \
             over-fired and no mount would ever work"
        );
    }

    #[test]
    fn a_bind_from_a_str_with_an_interior_nul_refuses() {
        let b = Bind::from("/test/a\0b");
        let mut m: Mount = b.into();
        assert_eq!(m.mount(), Err(Errno::EINVAL));
    }
}
