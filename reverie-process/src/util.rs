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
use std::os::unix::ffi::OsStrExt;

use syscalls::Errno;

pub fn to_cstring<S: AsRef<OsStr>>(s: S) -> CString {
    CString::new(s.as_ref().as_bytes()).unwrap()
}

#[derive(Clone)]
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

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn get(&self, i: usize) -> &CStr {
        self.items[i].as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CStr> {
        self.items.iter().map(|x| x.as_ref())
    }
}

impl IntoIterator for CStringArray {
    type Item = CString;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl Extend<CString> for CStringArray {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = CString>,
    {
        for item in iter {
            self.push(item);
        }
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

/// This is a value that can be shared between a parent and child process. This
/// is useful for communicating and synchronizing state across process
/// boundaries.
pub struct SharedValue<T> {
    map: *mut T,
}

impl<T> SharedValue<T> {
    pub fn new(value: T) -> Result<Self, Errno> {
        let map = syscalls::Errno::result(unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                core::mem::size_of::<T>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        })? as *mut T;

        // Initialize the inner value
        let inner = unsafe { &mut *map };
        *inner = value;

        Ok(Self { map })
    }
}

impl<T> Drop for SharedValue<T> {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.map as *mut _, core::mem::size_of::<T>()) };
    }
}

impl<T> core::ops::Deref for SharedValue<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.map }
    }
}

impl<T> core::ops::DerefMut for SharedValue<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.map }
    }
}

impl<T> AsRef<T> for SharedValue<T> {
    fn as_ref(&self) -> &T {
        unsafe { &*self.map }
    }
}

impl<T> AsMut<T> for SharedValue<T> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { &mut *self.map }
    }
}
