/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::fmt;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;
use syscalls::Errno;

/// Context associated with [`Error`]. Useful for knowing which particular part
/// of [`super::Command::spawn`] failed.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Context {
    /// No context provided.
    Unknown,
    /// Setting CPU affinity failed.
    Affinity,
    /// The clone syscall failed.
    Clone,
    /// Setting up the tty failed.
    Tty,
    /// Setting up stdio failed.
    Stdio,
    /// Resetting signals failed.
    ResetSignals,
    /// Changing `/proc/{pid}/uid_map` failed.
    MapUid,
    /// Changing `/proc/{pid}/setgroups` or `/proc/{pid}/gid_map` failed.
    MapGid,
    /// Setting the hostname failed.
    Hostname,
    /// Setting the domainname failed.
    Domainname,
    /// Chroot failed.
    Chroot,
    /// Chdir failed.
    Chdir,
    /// Mounting failed.
    Mount,
    /// Network configuration failed.
    Network,
    /// The pre_exec callback(s) failed.
    PreExec,
    /// Setting the seccomp filter failed.
    Seccomp,
    /// Exec failed.
    Exec,
}

impl Context {
    /// Returns a string representation of the context.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown failure",
            Self::Affinity => "setting cpu affinity failed",
            Self::Clone => "clone failed",
            Self::Tty => "Setting the controlling tty failed",
            Self::Stdio => "Setting up stdio file descriptors failed",
            Self::ResetSignals => "Reseting signal handlers failed",
            Self::MapUid => "Setting UID map failed",
            Self::MapGid => "Setting GID map failed",
            Self::Hostname => "Setting hostname failed",
            Self::Domainname => "Setting domainname failed",
            Self::Chroot => "chroot failed",
            Self::Chdir => "chdir failed",
            Self::Mount => "mount failed",
            Self::Network => "network configuration failed",
            Self::PreExec => "pre_exec callback(s) failed",
            Self::Seccomp => "failed to install seccomp filter",
            Self::Exec => "execvp failed",
        }
    }

    /// The spawn-pipe wire code for this context. This match and
    /// [`Context::from_wire_code`] are the single codec: adding a
    /// variant without a code fails to compile here.
    fn wire_code(self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::Affinity => 1,
            Self::Clone => 2,
            Self::Tty => 3,
            Self::Stdio => 4,
            Self::ResetSignals => 5,
            Self::MapUid => 6,
            Self::MapGid => 7,
            Self::Hostname => 8,
            Self::Domainname => 9,
            Self::Chroot => 10,
            Self::Chdir => 11,
            Self::Mount => 12,
            Self::Network => 13,
            Self::PreExec => 14,
            Self::Seccomp => 15,
            Self::Exec => 16,
        }
    }

    fn from_wire_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => Self::Unknown,
            1 => Self::Affinity,
            2 => Self::Clone,
            3 => Self::Tty,
            4 => Self::Stdio,
            5 => Self::ResetSignals,
            6 => Self::MapUid,
            7 => Self::MapGid,
            8 => Self::Hostname,
            9 => Self::Domainname,
            10 => Self::Chroot,
            11 => Self::Chdir,
            12 => Self::Mount,
            13 => Self::Network,
            14 => Self::PreExec,
            15 => Self::Seccomp,
            16 => Self::Exec,
            _ => return None,
        })
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Write::write_str(f, self.as_str())
    }
}

/// Largest mount target carried by the bounded transports of a
/// [`MountFailure`], in bytes. In memory the name is held in full on
/// the heap (so [`Error`] stays 16 bytes); a longer target is
/// cut to this prefix only for transport, marked truncated (see
/// [`MountFailure::target_truncated`]).
pub const MAX_MOUNT_TARGET_BYTES: usize = 512;

/// Largest filesystem type carried by the bounded transports, in bytes.
pub const MAX_MOUNT_FSTYPE_BYTES: usize = 64;

/// The mount a setup failure came from: its target and filesystem type.
///
/// Heap-held and shared behind an `Arc` inside [`Error`]: the name is
/// built once by the mount's builder before `clone`, so reporting a
/// failure after clone only clones the `Arc`, never allocates. Bytes
/// beyond the transport caps are dropped by the transports (never by
/// construction) and the truncation flags say so; formatting never
/// presents a cut name as whole.
#[derive(Clone, Eq, PartialEq)]
pub struct MountFailure {
    target: Box<[u8]>,
    target_truncated: bool,
    fstype: Option<Box<[u8]>>,
    fstype_truncated: bool,
}

fn capped_wire(bytes: &[u8], cap: usize) -> (&[u8], bool) {
    let kept = bytes.len().min(cap);
    (&bytes[..kept], bytes.len() > kept)
}

impl MountFailure {
    pub(crate) fn new(target: &[u8], fstype: Option<&[u8]>) -> Self {
        Self {
            target: Box::from(target),
            target_truncated: false,
            fstype: fstype.map(Box::from),
            fstype_truncated: false,
        }
    }

    fn from_parts(
        target: &[u8],
        target_truncated: bool,
        fstype: Option<&[u8]>,
        fstype_truncated: bool,
    ) -> Option<Self> {
        if target.len() > MAX_MOUNT_TARGET_BYTES
            || fstype.is_some_and(|bytes| bytes.len() > MAX_MOUNT_FSTYPE_BYTES)
            || (target_truncated && target.len() < MAX_MOUNT_TARGET_BYTES)
            || (fstype_truncated && fstype.is_none_or(|bytes| bytes.len() < MAX_MOUNT_FSTYPE_BYTES))
        {
            return None;
        }
        Some(Self {
            target: Box::from(target),
            target_truncated,
            fstype: fstype.map(Box::from),
            fstype_truncated,
        })
    }

    /// The mount target bytes: the full target in memory, or the
    /// capped prefix a bounded transport carried (see the caps above).
    pub fn target_bytes(&self) -> &[u8] {
        &self.target
    }

    /// The mount target as a path (a truncated prefix if flagged).
    pub fn target(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.target_bytes()))
    }

    /// Whether the carried target was cut to the transport cap.
    pub fn target_truncated(&self) -> bool {
        self.target_truncated
    }

    /// The filesystem-type bytes, if the mount had a filesystem type.
    pub fn fstype_bytes(&self) -> Option<&[u8]> {
        self.fstype.as_deref()
    }

    /// Whether the carried filesystem type was cut to the transport cap.
    pub fn fstype_truncated(&self) -> bool {
        self.fstype_truncated
    }
}

impl fmt::Display for MountFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "target={}", String::from_utf8_lossy(self.target_bytes()))?;
        if self.target_truncated {
            write!(f, " (target truncated)")?;
        }
        match self.fstype_bytes() {
            Some(bytes) => write!(f, " fstype={}", String::from_utf8_lossy(bytes))?,
            None => write!(f, " fstype=<none>")?,
        }
        if self.fstype_truncated {
            write!(f, " (fstype truncated)")?;
        }
        Ok(())
    }
}

impl fmt::Debug for MountFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("MountFailure");
        debug.field("target", &String::from_utf8_lossy(self.target_bytes()));
        match self.fstype_bytes() {
            Some(bytes) => debug.field("fstype", &String::from_utf8_lossy(bytes)),
            None => debug.field("fstype", &Option::<String>::None),
        };
        if self.target_truncated || self.fstype_truncated {
            debug.field("truncated", &true);
        }
        debug.finish()
    }
}

struct SerBytes<'a>(&'a [u8]);

impl Serialize for SerBytes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0)
    }
}

// Compact serde: only the capped name bytes travel.
// This is what keeps a named StartupError inside the startup frame.
impl Serialize for MountFailure {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        let (target, target_cut) = capped_wire(self.target_bytes(), MAX_MOUNT_TARGET_BYTES);
        let (fstype, fstype_cut) = match self.fstype_bytes() {
            Some(bytes) => capped_wire(bytes, MAX_MOUNT_FSTYPE_BYTES),
            None => (&[][..], false),
        };
        let mut tuple = serializer.serialize_tuple(5)?;
        tuple.serialize_element(&SerBytes(target))?;
        tuple.serialize_element(&(self.target_truncated || target_cut))?;
        tuple.serialize_element(&self.fstype.is_some())?;
        tuple.serialize_element(&SerBytes(fstype))?;
        tuple.serialize_element(&(self.fstype_truncated || fstype_cut))?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for MountFailure {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MountFailureVisitor;

        impl<'de> serde::de::Visitor<'de> for MountFailureVisitor {
            type Value = MountFailure;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a bounded mount failure name")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error as _;

                let target: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(0, &self))?;
                let target_truncated: bool = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                let has_fstype: bool = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(2, &self))?;
                let fstype: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(3, &self))?;
                let fstype_truncated: bool = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(4, &self))?;
                if !has_fstype && !fstype.is_empty() {
                    return Err(A::Error::custom("mount failure fstype without has_fstype"));
                }
                MountFailure::from_parts(
                    &target,
                    target_truncated,
                    has_fstype.then_some(fstype.as_slice()),
                    fstype_truncated,
                )
                .ok_or_else(|| A::Error::custom("mount failure name exceeds its bounds"))
            }
        }

        deserializer.deserialize_tuple(5, MountFailureVisitor)
    }
}

/// An error from spawning a process. This is a thin wrapper around
/// [`crate::Errno`], but with more context about what went wrong.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Error {
    errno: Errno,
    context: Context,
    mount: Option<Arc<MountFailure>>,
}

impl Error {
    /// Creates a new `Error`.
    pub fn new(errno: Errno, context: Context) -> Self {
        Self {
            errno,
            context,
            mount: None,
        }
    }

    /// Creates a mount `Error` naming the mount that failed. This
    /// allocates the name; the post-clone setup path uses
    /// [`Error::mount_named`] with a name built before the clone.
    pub(crate) fn mount(errno: Errno, target: &[u8], fstype: Option<&[u8]>) -> Self {
        Self::mount_named(errno, Arc::new(MountFailure::new(target, fstype)))
    }

    /// Creates a mount `Error` from a name built before the clone.
    /// Only the `Arc` is cloned here, so this allocates nothing and
    /// is safe on the allocation-free post-clone setup path.
    pub(crate) fn mount_named(errno: Errno, mount: Arc<MountFailure>) -> Self {
        Self {
            errno,
            context: Context::Mount,
            mount: Some(mount),
        }
    }

    /// Converts a value `S` into an `Error`. Useful for turning `libc` function
    /// return types into a `Result`.
    pub fn result<S>(value: S, context: Context) -> Result<S, Self>
    where
        S: syscalls::ErrnoSentinel + PartialEq<S>,
    {
        Errno::result(value).map_err(|err| Self::new(err, context))
    }

    /// Gets the errno.
    pub fn errno(&self) -> Errno {
        self.errno
    }

    /// Gets the error context.
    pub fn context(&self) -> Context {
        self.context
    }

    /// The mount this error came from, for a mount setup failure.
    pub fn mount_failure(&self) -> Option<&MountFailure> {
        self.mount.as_deref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.mount {
            Some(mount) => writeln!(f, "{} ({}): {}", self.context, mount, self.errno),
            None => writeln!(f, "{}: {}", self.context, self.errno),
        }
    }
}

impl std::error::Error for Error {}

impl From<Errno> for Error {
    fn from(err: Errno) -> Self {
        Self::new(err, Context::Unknown)
    }
}

impl From<Error> for Errno {
    fn from(err: Error) -> Errno {
        err.errno
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        std::io::Error::from(err.errno)
    }
}

/// Longest encoded form [`Error::encode_wire`] can produce: the legacy
/// 8-byte errno+context header, the 4-byte mount-name header, and the
/// capped name bytes. The spawn error pipe carries one such frame.
pub(crate) const MAX_ERROR_WIRE_BYTES: usize = 12 + MAX_MOUNT_TARGET_BYTES + MAX_MOUNT_FSTYPE_BYTES;

impl Error {
    /// Encodes this error for the spawn error pipe into `out`, returning
    /// the used prefix. Explicit layout, no layout transmute: errno and
    /// context first (the old 8-byte header), then for a named mount
    /// failure the name lengths, truncation flags, and name bytes.
    pub(crate) fn encode_wire<'a>(&self, out: &'a mut [u8; MAX_ERROR_WIRE_BYTES]) -> &'a [u8] {
        out[..4].copy_from_slice(&self.errno.into_raw().to_le_bytes());
        out[4..8].copy_from_slice(&self.context.wire_code().to_le_bytes());
        let Some(mount) = &self.mount else {
            return &out[..8];
        };
        let (target, target_cut) = capped_wire(mount.target_bytes(), MAX_MOUNT_TARGET_BYTES);
        let (fstype, fstype_cut) = match mount.fstype_bytes() {
            Some(bytes) => capped_wire(bytes, MAX_MOUNT_FSTYPE_BYTES),
            None => (&[][..], false),
        };
        out[8..10].copy_from_slice(&(target.len() as u16).to_le_bytes());
        out[10] = if mount.fstype.is_some() {
            fstype.len() as u8
        } else {
            u8::MAX
        };
        out[11] = u8::from(mount.target_truncated || target_cut)
            | (u8::from(mount.fstype_truncated || fstype_cut) << 1);
        let mut end = 12;
        out[end..end + target.len()].copy_from_slice(target);
        end += target.len();
        if mount.fstype.is_some() {
            out[end..end + fstype.len()].copy_from_slice(fstype);
            end += fstype.len();
        }
        &out[..end]
    }

    /// Decodes [`Error::encode_wire`] output. A malformed frame (bad
    /// context, bad lengths, trailing or missing bytes) is refused as
    /// `None`, never partially read.
    pub(crate) fn decode_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let errno = Errno::new(i32::from_le_bytes(bytes[..4].try_into().ok()?));
        let context = Context::from_wire_code(u32::from_le_bytes(bytes[4..8].try_into().ok()?))?;
        if bytes.len() == 8 {
            return Some(Self::new(errno, context));
        }
        if context != Context::Mount || bytes.len() < 12 {
            return None;
        }
        let target_len = u16::from_le_bytes(bytes[8..10].try_into().ok()?) as usize;
        if target_len > MAX_MOUNT_TARGET_BYTES {
            return None;
        }
        let has_fstype = bytes[10] != u8::MAX;
        let fstype_len = if has_fstype { bytes[10] as usize } else { 0 };
        if fstype_len > MAX_MOUNT_FSTYPE_BYTES || bytes[11] & !0b11 != 0 {
            return None;
        }
        if bytes.len() != 12 + target_len + fstype_len {
            return None;
        }
        let target = &bytes[12..12 + target_len];
        let fstype = has_fstype.then_some(&bytes[12 + target_len..]);
        let mount =
            MountFailure::from_parts(target, bytes[11] & 0b01 != 0, fstype, bytes[11] & 0b10 != 0)?;
        Some(Self {
            errno,
            context,
            mount: Some(Arc::new(mount)),
        })
    }
}

pub(super) trait AddContext<T> {
    fn context(self, context: Context) -> Result<T, Error>;
}

impl<T> AddContext<T> for Result<T, Errno> {
    fn context(self, context: Context) -> Result<T, Error> {
        self.map_err(move |errno| Error::new(errno, context))
    }
}

impl<T> AddContext<T> for Result<T, nix::errno::Errno> {
    fn context(self, context: Context) -> Result<T, Error> {
        self.map_err(move |errno| Error::new(Errno::new(errno as i32), context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(error: Error) -> Error {
        let mut buffer = [0u8; MAX_ERROR_WIRE_BYTES];
        let used = error.encode_wire(&mut buffer).len();
        assert_eq!(Error::decode_wire(&buffer[..used]), Some(error.clone()));
        error
    }

    #[test]
    fn wire_roundtrips_plain_and_named_errors() {
        roundtrip(Error::new(Errno::ENOENT, Context::Exec));
        roundtrip(Error::new(Errno::ENOENT, Context::Mount));
        let named = roundtrip(Error::mount(Errno::EPERM, b"/sys", Some(b"sysfs")));
        let mount = named.mount_failure().unwrap();
        assert_eq!(mount.target(), Path::new("/sys"));
        assert_eq!(mount.fstype_bytes(), Some(b"sysfs".as_slice()));
        assert!(!mount.target_truncated() && !mount.fstype_truncated());
        assert_eq!(
            format!("{named}"),
            format!(
                "mount failed (target=/sys fstype=sysfs): {}\n",
                Errno::EPERM
            )
        );
        assert!(format!("{named:?}").contains("/sys"));
        assert!(format!("{named:?}").contains("sysfs"));
        let untyped = roundtrip(Error::mount(Errno::EINVAL, b"/test", None));
        assert_eq!(untyped.mount_failure().unwrap().fstype_bytes(), None);
    }

    #[test]
    fn wire_roundtrips_every_context() {
        for context in [
            Context::Unknown,
            Context::Affinity,
            Context::Clone,
            Context::Tty,
            Context::Stdio,
            Context::ResetSignals,
            Context::MapUid,
            Context::MapGid,
            Context::Hostname,
            Context::Domainname,
            Context::Chroot,
            Context::Chdir,
            Context::Mount,
            Context::Network,
            Context::PreExec,
            Context::Seccomp,
            Context::Exec,
        ] {
            roundtrip(Error::new(Errno::EINVAL, context));
        }
    }

    #[test]
    fn wire_rejects_malformed_frames_by_name() {
        let error = Error::mount(Errno::EPERM, b"/sys", Some(b"sysfs"));
        let mut buffer = [0u8; MAX_ERROR_WIRE_BYTES];
        let used = error.encode_wire(&mut buffer).len();
        let frame = &buffer[..used];
        assert_eq!(Error::decode_wire(&frame[..used - 1]), None, "short frame");
        let mut trailing = [0u8; MAX_ERROR_WIRE_BYTES + 1];
        trailing[..used].copy_from_slice(frame);
        trailing[used] = 1;
        assert_eq!(
            Error::decode_wire(&trailing[..used + 1]),
            None,
            "trailing byte"
        );
        let mut bad_context = [0u8; 8];
        bad_context[..4].copy_from_slice(&Errno::ENOENT.into_raw().to_le_bytes());
        bad_context[4..8].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(Error::decode_wire(&bad_context), None, "bad context code");
        let mut bad_length = [0u8; MAX_ERROR_WIRE_BYTES];
        bad_length[..used].copy_from_slice(frame);
        bad_length[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            Error::decode_wire(&bad_length[..used]),
            None,
            "bad target length"
        );
        let mut short_flagged = [0u8; MAX_ERROR_WIRE_BYTES];
        short_flagged[..used].copy_from_slice(frame);
        short_flagged[11] |= 0b01;
        assert_eq!(
            Error::decode_wire(&short_flagged[..used]),
            None,
            "truncation flag on a short target"
        );
    }

    #[test]
    fn mount_name_wire_caps_are_the_approved_values() {
        // Test expectations elsewhere derive from these constants, so
        // pin the approved values independently: a cut to 64/16 (or
        // any other value) must fail here.
        assert_eq!(MAX_MOUNT_TARGET_BYTES, 512);
        assert_eq!(MAX_MOUNT_FSTYPE_BYTES, 64);
    }

    #[test]
    fn mount_names_truncate_at_caps_and_say_so() {
        let mut long_target = b"/head/".to_vec();
        long_target.extend(vec![b'x'; MAX_MOUNT_TARGET_BYTES]);
        long_target.extend_from_slice(b"/leaf");
        let long_fstype = vec![b'y'; MAX_MOUNT_FSTYPE_BYTES + 1];
        let original = Error::mount(Errno::EPERM, &long_target, Some(&long_fstype));
        let held = original.mount_failure().unwrap();
        assert_eq!(held.target_bytes(), long_target.as_slice());
        assert!(!held.target_truncated() && !held.fstype_truncated());

        let mut buffer = [0u8; MAX_ERROR_WIRE_BYTES];
        let used = original.encode_wire(&mut buffer).len();
        let carried = Error::decode_wire(&buffer[..used]).expect("capped frame must decode");
        let mount = carried.mount_failure().unwrap();
        assert_eq!(mount.target_bytes(), &long_target[..MAX_MOUNT_TARGET_BYTES]);
        assert_eq!(
            mount.fstype_bytes().map(<[u8]>::len),
            Some(MAX_MOUNT_FSTYPE_BYTES)
        );
        assert!(mount.target_truncated() && mount.fstype_truncated());
        let shown = format!("{carried}");
        assert!(shown.contains("(target truncated)"), "{shown}");
        assert!(shown.contains("(fstype truncated)"), "{shown}");
        assert!(format!("{carried:?}").contains("truncated"));
    }
}
