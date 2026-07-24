/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

/// Path to the sabre executable. Needed for intercepting syscalls after execve.
static mut SABRE_PATH: *const libc::c_char = core::ptr::null();

/// Path to this plugin. Needed for intercepting syscalls after execve.
static mut PLUGIN_PATH: *const libc::c_char = core::ptr::null();

/// Path to the client binary.
static mut CLIENT_PATH: *const libc::c_char = core::ptr::null();

/// Private tool settings preserved across loader-mediated execve.
static TOOL_ENV: OnceLock<Vec<CString>> = OnceLock::new();

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
