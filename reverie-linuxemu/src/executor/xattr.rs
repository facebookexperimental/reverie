/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Extended attributes (gVisor: pkg/sentry/syscalls/linux/sys_xattr.go).

use super::*;

// TODO-HUMAN-REVIEW(PR-116): Review the no-xattr KVM guest model and errors.
//
// The container passes the `user.` namespace through to the host file, as
// Linux and the ptrace backend do: those attributes are ordinary file content
// the guest or the container's stable filesystem put there. The `security.`,
// `trusted.` and `system.` namespaces stay modeled as empty, because their
// host values (SELinux labels, capabilities, ACLs) describe the host rather
// than the guest. Linux still validates the target and attribute name before
// either answer; preserve those observable path/fd/memory errors.
fn validate_xattr_target_and_name(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> Result<XattrTarget, i64> {
    let descriptor_call = number == libc::SYS_fgetxattr as u64
        || number == libc::SYS_fsetxattr as u64
        || number == libc::SYS_fremovexattr as u64;
    let target = if descriptor_call {
        // The descriptor calls import the name before their filtered
        // descriptor lookup, which refuses an unknown or O_PATH descriptor;
        // the namespace is resolved after both.
        let name = read_xattr_name(memory, args[1])?;
        let Ok(guest_fd) = libc::c_int::try_from(args[0]) else {
            return Err(negative_errno(libc::EBADF));
        };
        let Some(fd) = host_fd(state, guest_fd) else {
            return Err(negative_errno(libc::EBADF));
        };
        if fd_status_flags(fd)? & libc::O_PATH != 0 {
            return Err(negative_errno(libc::EBADF));
        }
        return resolve_xattr_name(XattrTarget::Fd(fd), name);
    } else {
        let path = match read_c_string(&ProviderMemory(memory), args[0], 4096) {
            Ok(path) => path,
            Err(error) => return Err(read_c_string_errno(error)),
        };
        if path.is_empty() {
            return Err(negative_errno(libc::ENOENT));
        }
        if synthetic_proc_content(state, &path).is_none() {
            let nofollow = number == libc::SYS_lgetxattr as u64
                || number == libc::SYS_lsetxattr as u64
                || number == libc::SYS_lremovexattr as u64;
            XattrTarget::Path(open_metadata_path(state, libc::AT_FDCWD, &path, nofollow)?)
        } else {
            XattrTarget::Synthetic
        }
    };

    let name = read_xattr_name(memory, args[1])?;
    resolve_xattr_name(target, name)
}

/// Imports an attribute name as Linux's import_xattr_name does: a fault is
/// EFAULT, and an empty or over-long name is ERANGE.
fn read_xattr_name(memory: &GuestMemory, address: u64) -> Result<Vec<u8>, i64> {
    match read_c_string(&ProviderMemory(memory), address, 256) {
        Ok(name) if name.is_empty() => Err(negative_errno(libc::ERANGE)),
        Ok(name) => Ok(name),
        Err(ReadCStringError::Fault) => Err(negative_errno(libc::EFAULT)),
        Err(ReadCStringError::NameTooLong) => Err(negative_errno(libc::ERANGE)),
    }
}

/// Resolves an imported name's namespace for `target`.
fn resolve_xattr_name(target: XattrTarget, name: Vec<u8>) -> Result<XattrTarget, i64> {
    let empty_namespace =
        [b"user.".as_slice(), b"trusted.", b"security."].contains(&name.as_slice());
    if empty_namespace {
        return Err(negative_errno(libc::EINVAL));
    }
    let supported_namespace = [b"user.".as_slice(), b"trusted.", b"security."]
        .iter()
        .any(|prefix| name.starts_with(prefix));
    let supported_system_name = matches!(
        name.as_slice(),
        b"system.posix_acl_access" | b"system.posix_acl_default"
    );
    if !(supported_namespace || supported_system_name) {
        Err(negative_errno(libc::EOPNOTSUPP))
    } else if name.starts_with(b"user.") && !matches!(target, XattrTarget::Synthetic) {
        // A name read from guest memory has no interior NUL.
        let name = CString::new(name).map_err(|_| negative_errno(libc::EINVAL))?;
        Ok(XattrTarget::Host(Box::new(target), name))
    } else {
        Ok(XattrTarget::Modeled)
    }
}

/// What an xattr call operates on once its target and name are valid.
pub(super) enum XattrTarget {
    /// A guest descriptor's host descriptor.
    Fd(RawFd),
    /// A path, held open with `O_PATH` (not followed for the `l` calls).
    Path(std::fs::File),
    /// A synthetic `/proc` file, which has no host file.
    Synthetic,
    /// A `user.` attribute of a host target: passed through.
    Host(Box<XattrTarget>, CString),
    /// Any other valid name: answered from the empty model.
    Modeled,
}

impl XattrTarget {
    /// The host call's result as a syscall return value. An `O_PATH`
    /// descriptor cannot be used with the `f` calls, so a path is reached
    /// through its `/proc/self/fd` link, which names the opened object itself
    /// (a symlink opened without following stays the symlink).
    fn host_call(
        &self,
        on_fd: impl FnOnce(RawFd) -> libc::ssize_t,
        on_path: impl FnOnce(&CStr) -> libc::ssize_t,
    ) -> i64 {
        let result = match self {
            XattrTarget::Fd(fd) => on_fd(*fd),
            XattrTarget::Path(file) => {
                let link = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
                    .expect("descriptor path has no NUL");
                on_path(&link)
            }
            _ => unreachable!("only a host target is called"),
        };
        if result < 0 {
            io_error(std::io::Error::last_os_error())
        } else {
            result as i64
        }
    }
}

pub(super) const XATTR_SIZE_MAX: usize = 65_536;

pub(super) fn getxattr(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> i64 {
    let (target, name) = match validate_xattr_target_and_name(memory, state, number, args) {
        Ok(XattrTarget::Host(target, name)) => (target, name),
        Ok(_) => return negative_errno(libc::ENODATA),
        Err(error) => return error,
    };
    let capacity = usize::try_from(args[3])
        .unwrap_or(usize::MAX)
        .min(XATTR_SIZE_MAX);
    let mut value = vec![0u8; capacity];
    let buffer = value.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: name and value are live for each call; value has `capacity` bytes.
    let length = target.host_call(
        |fd| unsafe { libc::fgetxattr(fd, name.as_ptr(), buffer, capacity) },
        |path| unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), buffer, capacity) },
    );
    if length <= 0 || capacity == 0 {
        return length;
    }
    match memory.user().write(args[2], &value[..length as usize]) {
        Ok(()) => length,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-1017): Review user-namespace xattr pass-through.
pub(super) fn setxattr(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> i64 {
    // fsetxattr validates its flags and imports its name and value
    // (setxattr_copy) before its filtered descriptor lookup.
    if number == libc::SYS_fsetxattr as u64 {
        let flags = args[4] as libc::c_int;
        if flags & !(libc::XATTR_CREATE | libc::XATTR_REPLACE) != 0 {
            return negative_errno(libc::EINVAL);
        }
        if let Err(error) = read_xattr_name(memory, args[1]) {
            return error;
        }
        let Ok(value_length) = usize::try_from(args[3]) else {
            return negative_errno(libc::E2BIG);
        };
        if value_length > XATTR_SIZE_MAX {
            return negative_errno(libc::E2BIG);
        }
        let mut value = vec![0; value_length];
        if value_length != 0 && memory.user().read(args[2], &mut value).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    let target = match validate_xattr_target_and_name(memory, state, number, args) {
        Ok(target) => target,
        Err(error) => return error,
    };
    let flags = args[4] as libc::c_int;
    let allowed_flags = libc::XATTR_CREATE | libc::XATTR_REPLACE;
    if flags & !allowed_flags != 0 || flags == allowed_flags {
        return negative_errno(libc::EINVAL);
    }
    let Ok(value_length) = usize::try_from(args[3]) else {
        return negative_errno(libc::E2BIG);
    };
    if value_length > XATTR_SIZE_MAX {
        return negative_errno(libc::E2BIG);
    }
    let mut value = vec![0; value_length];
    if value_length != 0 && memory.user().read(args[2], &mut value).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let XattrTarget::Host(target, name) = target else {
        return negative_errno(libc::EOPNOTSUPP);
    };
    // SAFETY: name and value are live for each call; value has value_length bytes.
    target.host_call(
        |fd| unsafe {
            libc::fsetxattr(
                fd,
                name.as_ptr(),
                value.as_ptr().cast(),
                value_length,
                flags,
            ) as libc::ssize_t
        },
        |path| unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value_length,
                flags,
            ) as libc::ssize_t
        },
    )
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-1017): Review user-namespace xattr pass-through.
pub(super) fn removexattr(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> i64 {
    match validate_xattr_target_and_name(memory, state, number, args) {
        // SAFETY: name is live for each call.
        Ok(XattrTarget::Host(target, name)) => target.host_call(
            |fd| unsafe { libc::fremovexattr(fd, name.as_ptr()) as libc::ssize_t },
            |path| unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) as libc::ssize_t },
        ),
        Ok(_) => negative_errno(libc::ENODATA),
        Err(error) => error,
    }
}

/// The `user.` names of a host target's attributes, the only ones the guest
/// sees (`validate_xattr_target_and_name`), written to the guest's list buffer
/// with Linux's sizing rules: a zero size asks for the length, and a buffer too
/// small for the list is ERANGE.
pub(super) fn xattr_list(
    memory: &mut GuestMemory,
    target: &XattrTarget,
    address: u64,
    size: u64,
) -> i64 {
    let mut names = vec![0u8; XATTR_SIZE_MAX];
    let buffer = names.as_mut_ptr().cast::<libc::c_char>();
    // SAFETY: names is live for each call and has XATTR_SIZE_MAX bytes.
    let length = target.host_call(
        |fd| unsafe { libc::flistxattr(fd, buffer, XATTR_SIZE_MAX) },
        |path| unsafe { libc::listxattr(path.as_ptr(), buffer, XATTR_SIZE_MAX) },
    );
    if length < 0 {
        return length;
    }
    let visible: Vec<u8> = names[..length as usize]
        .split_inclusive(|byte| *byte == 0)
        .filter(|name| name.starts_with(b"user."))
        .flatten()
        .copied()
        .collect();
    if size == 0 {
        return visible.len() as i64;
    }
    if (visible.len() as u64) > size {
        return negative_errno(libc::ERANGE);
    }
    match memory.user().write(address, &visible) {
        Ok(()) => visible.len() as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}
