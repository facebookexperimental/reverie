/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::ptr;
use std::sync::OnceLock;

/// Path to the sabre executable. Needed for intercepting syscalls after execve.
static mut SABRE_PATH: *const libc::c_char = core::ptr::null();

/// Path to this plugin. Needed for intercepting syscalls after execve.
static mut PLUGIN_PATH: *const libc::c_char = core::ptr::null();

/// Path to the client binary.
static mut CLIENT_PATH: *const libc::c_char = core::ptr::null();

/// Private tool settings preserved across loader-mediated execve.
static TOOL_ENV: OnceLock<Vec<CString>> = OnceLock::new();

unsafe extern "C" {
    static mut environ: *mut *mut libc::c_char;
}

/// Sets the global path to the sabre binary.
#[doc(hidden)]
#[inline]
pub(super) unsafe fn set_sabre_path(path: *const libc::c_char) {
    SABRE_PATH = path;
}

/// Sets the global path to the plugin (aka tool).
#[doc(hidden)]
#[inline]
pub(super) unsafe fn set_plugin_path(path: *const libc::c_char) {
    PLUGIN_PATH = path;
}

/// Sets the global path to the client binary.
#[doc(hidden)]
#[inline]
pub(super) unsafe fn set_client_path(path: *const libc::c_char) {
    CLIENT_PATH = path;
}

/// Takes a reserved private setting and erases its original environment bytes.
///
/// Removing an entry from libc's environment does not remove the bytes exposed by
/// Linux through `/proc/self/environ`. This function removes every matching entry
/// from `environ` and zeroes the backing bytes before the guest can observe them.
///
/// # Safety
/// Call this only during single-threaded plugin initialization, before another
/// thread can read or mutate the process environment.
// TODO-HUMAN-REVIEW(PR-138): Review the private SaBRe environment scrubbing API.
pub unsafe fn take_private_env(key: &str) -> Option<OsString> {
    assert!(
        key.as_bytes().starts_with(b"REVERIE_SABRE_"),
        "private SaBRe settings must use the REVERIE_SABRE_ namespace"
    );
    let value = std::env::var_os(key)?;
    let mut prefix = key.as_bytes().to_vec();
    prefix.push(b'=');

    let mut slot = unsafe { environ };
    while !slot.is_null() && !unsafe { *slot }.is_null() {
        let entry = unsafe { *slot };
        let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
        if bytes.starts_with(&prefix) {
            unsafe { ptr::write_bytes(entry.cast::<u8>(), 0, bytes.len()) };

            let mut destination = slot;
            let mut source = unsafe { slot.add(1) };
            loop {
                let next = unsafe { *source };
                unsafe { *destination = next };
                if next.is_null() {
                    break;
                }
                destination = source;
                source = unsafe { source.add(1) };
            }
        } else {
            slot = unsafe { slot.add(1) };
        }
    }

    Some(value)
}

/// Cache reserved tool settings before a guest can replace its environment.
pub(super) fn cache_tool_env() {
    TOOL_ENV.get_or_init(|| {
        std::env::vars_os()
            .filter(|(key, _)| key.as_os_str().as_bytes().starts_with(b"REVERIE_SABRE_"))
            .map(|(key, value)| {
                let mut entry = key.as_os_str().as_bytes().to_vec();
                entry.push(b'=');
                entry.extend_from_slice(value.as_os_str().as_bytes());
                CString::new(entry).expect("SaBRe tool environment contains an interior NUL")
            })
            .collect()
    });
}

/// Returns private SaBRe tool settings for a loader-mediated execve.
pub(super) fn tool_env() -> &'static [CString] {
    TOOL_ENV
        .get()
        .expect("SaBRe tool environment was not cached")
}

/// Returns the path to the sabre binary.
pub fn sabre_path() -> &'static CStr {
    unsafe { CStr::from_ptr(SABRE_PATH) }
}

/// Returns the path to the plugin.
pub fn plugin_path() -> &'static CStr {
    unsafe { CStr::from_ptr(PLUGIN_PATH) }
}

/// Returns the path to the client binary.
pub fn client_path() -> &'static CStr {
    unsafe { CStr::from_ptr(CLIENT_PATH) }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::process::Command;

    use super::*;

    const CHILD_ENV: &str = "REVERIE_SABRE_TEST_CHILD";
    const SECRET_ENV: &str = "REVERIE_SABRE_TEST_SECRET";
    const SECRET_VALUE: &str = "run-specific-value";

    #[test]
    fn take_private_env_scrubs_proc() {
        if std::env::var_os(CHILD_ENV).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("paths::tests::take_private_env_scrubs_proc")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .env(SECRET_ENV, SECRET_VALUE)
                .status()
                .unwrap();
            assert!(status.success(), "child test failed with {status}");
            return;
        }

        assert_eq!(
            unsafe { take_private_env(SECRET_ENV) }.as_deref(),
            Some(OsStr::new(SECRET_VALUE))
        );
        assert!(std::env::var_os(SECRET_ENV).is_none());

        let proc_environment = std::fs::read("/proc/self/environ").unwrap();
        let secret = format!("{SECRET_ENV}={SECRET_VALUE}");
        assert!(
            !proc_environment
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "private setting remained visible in /proc/self/environ"
        );
    }
}
