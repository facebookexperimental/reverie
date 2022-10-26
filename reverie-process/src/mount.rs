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

use super::fd::create_dir_all;
use super::fd::touch_path;
use super::fd::FileType;
use super::util;

/// A mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mount {
    source: Option<CString>,
    target: CString,
    fstype: Option<CString>,
    flags: MountFlags,
    data: Option<CString>,
    touch_target: bool,
}

/// Represents a bind mount. Can be converted into a [`Mount`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bind {
    /// The source path of the bind mount. This path must exist. It can be either
    /// a file or directory.
    source: CString,

    /// The target of the bind mount. This does not need to exist and can be
    /// created when performing the bind mount.
    target: CString,
}

impl Mount {
    /// Creates a new mount at the path `target`.
    pub fn new<S: AsRef<OsStr>>(target: S) -> Self {
        Self {
            source: None,
            target: util::to_cstring(target),
            fstype: None,
            flags: MountFlags::empty(),
            data: None,
            touch_target: false,
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
    ///                and does not need to be writable. This directory is never
    ///                modified by writes to `merged`.
    /// * `upperdir` - The upper directory of the overlay. This is where all
    ///                changes to `merged` are collected. Does not need to be
    ///                empty, but should be when starting a new overlay from
    ///                scratch.
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
        self.target = util::to_cstring(target);
        self
    }

    /// Returns the mount point target path.
    pub fn get_target(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.target.to_bytes()))
    }

    /// Sets the source of the mount.
    pub fn source<S: AsRef<OsStr>>(mut self, path: S) -> Self {
        self.source = Some(util::to_cstring(path));
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
        self.fstype = Some(util::to_cstring(fstype));
        self
    }

    /// Sets any additional data required by the mount.
    pub fn data<S: AsRef<OsStr>>(mut self, data: S) -> Self {
        self.data = Some(util::to_cstring(data));
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
    pub(super) fn mount(&mut self) -> Result<(), Errno> {
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
                    create_dir_all(&mut self.target, 0o777)?;
                } else {
                    touch_path(&mut self.target, 0o666, 0o777)?;
                }
            }
        }

        Errno::result(unsafe {
            libc::mount(
                self.source_ptr(),
                self.target_ptr(),
                self.fstype_ptr(),
                self.flags.bits(),
                self.data_ptr(),
            )
        })?;

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
        Self {
            source: util::to_cstring(source),
            target: util::to_cstring(target),
        }
    }
}

impl From<Bind> for Mount {
    fn from(b: Bind) -> Self {
        Self {
            source: Some(b.source),
            target: b.target,
            fstype: None,
            flags: MountFlags::MS_BIND,
            data: None,
            touch_target: false,
        }
    }
}

impl From<&str> for Bind {
    fn from(s: &str) -> Self {
        if let Some((source, target)) = s.split_once(':') {
            Self {
                source: util::to_cstring(source),
                target: util::to_cstring(target),
            }
        } else {
            let source = util::to_cstring(s);
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
        } else {
            // All mounts get these flags by default.
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
            Ok(Mount::tmpfs("/tmp").rprivate())
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
