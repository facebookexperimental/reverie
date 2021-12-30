/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;

use syscalls::Errno;

pub fn to_cstring<S: AsRef<OsStr>>(s: S) -> CString {
    CString::new(s.as_ref().as_bytes()).unwrap()
}

pub struct CStringArray {
    items: Vec<CString>,
    ptrs: Vec<*const libc::c_char>,
}

impl CStringArray {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut result = CStringArray {
            items: Vec::with_capacity(capacity),
            ptrs: Vec::with_capacity(capacity + 1),
        };
        result.ptrs.push(core::ptr::null());
        result
    }

    pub fn push(&mut self, item: CString) {
        let l = self.ptrs.len();
        self.ptrs[l - 1] = item.as_ptr();
        self.ptrs.push(core::ptr::null());
        self.items.push(item);
    }

    pub fn as_ptr(&self) -> *const *const libc::c_char {
        self.ptrs.as_ptr()
    }

    pub fn set(&mut self, i: usize, item: CString) {
        self.ptrs[i] = item.as_ptr();
        self.items[i] = item;
    }

    pub fn get(&self, i: usize) -> &CStr {
        self.items[i].as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CStr> {
        self.items.iter().map(|x| x.as_ref())
    }
}

pub unsafe fn reset_signal_handling() -> Result<(), Errno> {
    use core::mem::MaybeUninit;

    // Reset signal handling so the child process starts in a standardized
    // state. libstd ignores SIGPIPE, and signal-handling libraries often set a
    // mask. Child processes inherit ignored signals and the signal mask from
    // their parent, but most UNIX programs do not reset these things on their
    // own, so we need to clean things up now to avoid confusing the program
    // we're about to run.
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    Errno::result(libc::sigemptyset(set.as_mut_ptr()))?;
    Errno::result(libc::pthread_sigmask(
        libc::SIG_SETMASK,
        set.as_ptr(),
        core::ptr::null_mut(),
    ))?;

    let ret = libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    if ret == libc::SIG_ERR {
        return Err(Errno::last());
    }

    Ok(())
}
