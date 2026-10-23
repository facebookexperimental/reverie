/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The launch specification: how a launcher runs a client under SaBRe without
//! putting SaBRe on the client's command line or in its environment.
//!
//! The launcher execs the SaBRe binary with the client's own argv and
//! environment, so the kernel builds the client's initial stack,
//! `/proc/self/cmdline` and `/proc/self/environ` from them, as for an exec of
//! the client itself. Everything SaBRe needs besides travels in an inherited,
//! sealed memfd: the plugin path, the client path and the plugin's settings
//! (`NAME=VALUE`), which the loader puts in SaBRe's own environment
//! (reverie-sabre's `vendor/sabre/loader/loader.c`, `read_launch_spec`). The client path names
//! an ELF image: for a script the launcher passes its interpreter and the argv
//! the kernel would give it ([`resolve_script`]).

use std::ffi::CStr;
use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

/// The memfd's first bytes, NUL included (`SBR_LAUNCH_MAGIC` in the loader).
pub const MAGIC: &[u8] = b"SABRE-LAUNCH-V1\0";
/// The largest specification the loader reads (`SBR_LAUNCH_MAX_BYTES`).
pub const MAX_BYTES: usize = 64 * 1024;

/// The bytes of a specification: [`MAGIC`], the plugin path, the client path
/// and each setting, each NUL-terminated, then an empty string. `None` if a
/// string contains a NUL, a path is empty, a setting is not `NAME=VALUE`, or
/// the result exceeds [`MAX_BYTES`].
pub fn spec_bytes(plugin: &[u8], client: &[u8], settings: &[&[u8]]) -> Option<Vec<u8>> {
    if plugin.is_empty() || client.is_empty() {
        return None;
    }
    let mut bytes = MAGIC.to_vec();
    for value in [plugin, client].into_iter().chain(settings.iter().copied()) {
        if value.contains(&0) {
            return None;
        }
        bytes.extend_from_slice(value);
        bytes.push(0);
    }
    if settings
        .iter()
        .any(|setting| setting.first() == Some(&b'=') || !setting.contains(&b'='))
    {
        return None;
    }
    bytes.push(0);
    (bytes.len() <= MAX_BYTES).then_some(bytes)
}

/// A sealed memfd holding `bytes`, inheritable across exec (no close-on-exec).
/// Raw syscalls only, so the plugin can call it while it runs a guest exec.
pub fn spec_fd(bytes: &[u8]) -> std::io::Result<OwnedFd> {
    let check = |result: libc::c_long| {
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result)
        }
    };
    let fd = check(unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"sabre-launch".as_ptr(),
            libc::MFD_ALLOW_SEALING,
        )
    })? as i32;
    // SAFETY: memfd_create returned a new descriptor this function owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut written = 0;
    while written < bytes.len() {
        let count = check(unsafe {
            libc::syscall(
                libc::SYS_write,
                fd,
                bytes[written..].as_ptr(),
                bytes.len() - written,
            )
        })? as usize;
        if count == 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        written += count;
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    check(unsafe { libc::syscall(libc::SYS_fcntl, fd, libc::F_ADD_SEALS, seals) })?;
    Ok(owned)
}

/// The bytes the loader's `parse_shebang` reads from a script: its first line,
/// at most this many bytes including the newline (`BINPRM_BUF_SIZE`).
const SHEBANG_BYTES: usize = 256;

/// A script's interpreter and its one optional argument, as the loader's
/// `parse_shebang` reads them from `first_bytes`, the start of the file: the
/// first two words, split at spaces, tabs, newlines and carriage returns, of
/// the first line after `#!`. `None` when the file does not start with `#!`
/// or names no interpreter.
pub fn shebang(first_bytes: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let line = first_bytes.get(..first_bytes.len().min(SHEBANG_BYTES - 1))?;
    // The loader reads the line as a C string, which ends at a NUL.
    let line = match line.iter().position(|byte| *byte == 0) {
        Some(end) => &line[..end],
        None => line,
    };
    let line = line.strip_prefix(b"#!")?;
    let line = match line.iter().position(|byte| *byte == b'\n') {
        Some(end) => &line[..=end],
        None => line,
    };
    let mut words = line
        .split(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        .filter(|word| !word.is_empty());
    let interpreter = words.next()?.to_vec();
    Some((interpreter, words.next().map(<[u8]>::to_vec)))
}

/// For a client at `path` invoked with `argv`: the image to load and the argv
/// to exec SaBRe with. A script becomes its interpreter, with argv
/// `[interpreter, optional argument, path, argv[1..]]` as the kernel builds
/// it; any other file is itself, with `argv` unchanged. `first_bytes` is the
/// start of the file at `path`.
pub fn resolve_script(path: &CStr, argv: &[&CStr], first_bytes: &[u8]) -> (CString, Vec<CString>) {
    match shebang(first_bytes) {
        Some((interpreter, argument)) => {
            let interpreter = CString::new(interpreter).expect("words hold no NUL");
            let mut resolved = vec![interpreter.clone()];
            resolved.extend(argument.map(|word| CString::new(word).expect("words hold no NUL")));
            resolved.push(path.to_owned());
            resolved.extend(argv.iter().skip(1).map(|value| (*value).to_owned()));
            (interpreter, resolved)
        }
        None => (
            path.to_owned(),
            argv.iter().map(|value| (*value).to_owned()).collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spec_is_the_magic_then_terminated_strings() {
        let bytes = spec_bytes(b"/p.so", b"/bin/c", &[b"A=1", b"B="]).unwrap();
        assert_eq!(bytes, b"SABRE-LAUNCH-V1\0/p.so\0/bin/c\0A=1\0B=\0\0");
        assert_eq!(spec_bytes(b"", b"/bin/c", &[]), None);
        assert_eq!(spec_bytes(b"/p.so", b"/bin/c", &[b"NOEQUALS"]), None);
        assert_eq!(spec_bytes(b"/p.so", b"/bin/c", &[b"=1"]), None);
        assert_eq!(spec_bytes(b"/p\0.so", b"/bin/c", &[]), None);
    }

    #[test]
    fn a_spec_fd_is_sealed_and_holds_the_bytes() {
        let fd = spec_fd(b"SABRE-LAUNCH-V1\0x\0y\0\0").unwrap();
        use std::os::fd::AsRawFd;
        let raw = fd.as_raw_fd();
        let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
        assert_eq!(seals & libc::F_SEAL_WRITE, libc::F_SEAL_WRITE);
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, 0, "inherited across exec");
        let mut buffer = [0u8; 64];
        let read = unsafe { libc::pread(raw, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        assert_eq!(&buffer[..read as usize], b"SABRE-LAUNCH-V1\0x\0y\0\0");
    }

    #[test]
    fn a_script_becomes_its_interpreter_as_the_loader_reads_it() {
        assert_eq!(
            shebang(b"#!/bin/sh\necho"),
            Some((b"/bin/sh".to_vec(), None))
        );
        assert_eq!(
            shebang(b"#! /usr/bin/env  python3 -u\n"),
            Some((b"/usr/bin/env".to_vec(), Some(b"python3".to_vec())))
        );
        assert_eq!(shebang(b"\x7fELF"), None);
        assert_eq!(shebang(b"#!\n"), None);
        assert_eq!(
            shebang(b"#!/interpreter --op\0ignored later\n"),
            Some((b"/interpreter".to_vec(), Some(b"--op".to_vec())))
        );
        let (image, argv) = resolve_script(c"/s.sh", &[c"name", c"a", c"b"], b"#!/bin/sh -e\n");
        assert_eq!(image.as_c_str(), c"/bin/sh");
        assert_eq!(
            argv.iter().map(CString::as_c_str).collect::<Vec<_>>(),
            [c"/bin/sh", c"-e", c"/s.sh", c"a", c"b"]
        );
        let (image, argv) = resolve_script(c"/bin/c", &[c"name", c"a"], b"\x7fELF");
        assert_eq!(image.as_c_str(), c"/bin/c");
        assert_eq!(
            argv.iter().map(CString::as_c_str).collect::<Vec<_>>(),
            [c"name", c"a"]
        );
    }
}
