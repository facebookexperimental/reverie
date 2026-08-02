/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! In-guest adapter for the shared SaBRe statistics ABI.

use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

pub use reverie_sabre_stats::*;

use crate::paths;
use crate::protected_files;

static GUEST_STATS: OnceLock<Option<SabreGuestStats>> = OnceLock::new();

pub(crate) fn init_guest_stats() {
    GUEST_STATS.get_or_init(|| {
        let value = unsafe { paths::take_private_env(BACKEND_STATS_ENV) }?;
        let fd = std::str::from_utf8(value.as_os_str().as_bytes())
            .ok()?
            .parse::<RawFd>()
            .ok()?;
        let stats = unsafe { SabreGuestStats::from_inherited_fd(fd) }
            .expect("invalid SaBRe backend stats descriptor");
        protected_files::protect_raw_fd(fd);
        Some(stats)
    });
}

/// Increments a guest-owned SaBRe slow-path counter when collection is enabled.
pub fn increment_guest_slow_path(path: SabreSlowPath) {
    if let Some(stats) = GUEST_STATS.get().and_then(Option::as_ref) {
        stats.increment_slow_path(path);
    }
}
