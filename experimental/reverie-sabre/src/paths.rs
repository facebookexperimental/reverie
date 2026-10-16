/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::ptr;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Path to the sabre executable. Needed for intercepting syscalls after execve.
static mut SABRE_PATH: *const libc::c_char = core::ptr::null();

/// Path to this plugin. Needed for intercepting syscalls after execve.
static mut PLUGIN_PATH: *const libc::c_char = core::ptr::null();

/// Path to the client binary.
static mut CLIENT_PATH: *const libc::c_char = core::ptr::null();

/// Private tool settings preserved across loader-mediated execve.
static TOOL_ENV: OnceLock<Vec<CString>> = OnceLock::new();

/// Private tool settings the loader passed as plugin arguments, `NAME=VALUE`
/// after the plugin path, from a launch specification. They are read before the
/// environment and never enter it, so the guest cannot see them.
static LAUNCH_SETTINGS: Mutex<Vec<(OsString, OsString)>> = Mutex::new(Vec::new());

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

/// Consumes the leading `REVERIE_SABRE_*=VALUE` plugin arguments, the settings
/// the loader passed from a launch specification.
///
/// # Safety
/// `argc` and `argv` must be the loader's plugin argument count and vector,
/// after the plugin path; call this only during plugin initialization.
pub(super) unsafe fn take_launch_settings(argc: *mut i32, argv: *mut *mut *mut libc::c_char) {
    let mut settings = LAUNCH_SETTINGS.lock().unwrap();
    while unsafe { *argc } > 0 {
        let argument = unsafe { CStr::from_ptr(**argv) }.to_bytes();
        let Some(separator) = argument.iter().position(|byte| *byte == b'=') else {
            break;
        };
        if !argument.starts_with(b"REVERIE_SABRE_") {
            break;
        }
        let (key, value) = (&argument[..separator], &argument[separator + 1..]);
        settings.push((
            OsStr::from_bytes(key).to_os_string(),
            OsStr::from_bytes(value).to_os_string(),
        ));
        unsafe {
            *argc -= 1;
            *argv = (*argv).wrapping_add(1);
        }
    }
}

/// Reads a private setting without consuming it: the launch specification's
/// value, or else the environment's.
pub(super) fn private_env(key: &str) -> Option<OsString> {
    let settings = LAUNCH_SETTINGS.lock().unwrap();
    settings
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
        .or_else(|| std::env::var_os(key))
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
    let launched = {
        let mut settings = LAUNCH_SETTINGS.lock().unwrap();
        settings
            .iter()
            .position(|(name, _)| name == key)
            .map(|index| settings.remove(index).1)
    };
    let Some(value) = std::env::var_os(key) else {
        return launched;
    };
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

    Some(launched.unwrap_or(value))
}

/// Cache reserved tool settings before a guest can replace its environment.
pub(super) fn cache_tool_env() {
    TOOL_ENV.get_or_init(|| {
        let launched = LAUNCH_SETTINGS.lock().unwrap().clone();
        let inherited = std::env::vars_os().filter(|(key, _)| {
            key.as_os_str().as_bytes().starts_with(b"REVERIE_SABRE_")
                && !launched.iter().any(|(name, _)| name == key)
        });
        launched
            .iter()
            .cloned()
            .chain(inherited)
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

    #[test]
    fn launch_settings_reach_the_plugin_and_not_the_environment() {
        const KEY: &str = "REVERIE_SABRE_TEST_LAUNCH_SETTING";
        let arguments = [
            CString::new(format!("{KEY}=launched")).unwrap(),
            CString::new("--plugin-option").unwrap(),
        ];
        let mut pointers: Vec<*mut libc::c_char> = arguments
            .iter()
            .map(|argument| argument.as_ptr().cast_mut())
            .collect();
        pointers.push(ptr::null_mut());
        let mut argc = 2;
        let mut argv = pointers.as_mut_ptr();

        unsafe { take_launch_settings(&mut argc, &mut argv) };

        // Only the setting is consumed; a plugin's own option stays.
        assert_eq!(argc, 1);
        assert_eq!(unsafe { CStr::from_ptr(*argv) }, c"--plugin-option");
        assert!(std::env::var_os(KEY).is_none());
        assert_eq!(private_env(KEY).as_deref(), Some(OsStr::new("launched")));
        assert_eq!(
            unsafe { take_private_env(KEY) }.as_deref(),
            Some(OsStr::new("launched"))
        );
        assert_eq!(private_env(KEY), None);
    }
}
