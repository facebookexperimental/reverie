/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use syscalls::Errno;

use super::Pid;

const CHILD_STACK_SIZE: usize = 2 * 1024 * 1024;

pub(super) fn child_stack() -> Vec<u8> {
    // The clone child performs container setup before exec. Allocate the same
    // 2 MiB minimum that programs expect instead of consuming the caller's
    // remaining stack or relying on a single page.
    vec![0u8; CHILD_STACK_SIZE]
}

pub fn clone<F>(cb: F, flags: libc::c_int) -> Result<Pid, Errno>
where
    F: FnMut() -> i32,
{
    let mut stack = child_stack();
    clone_with_stack(cb, flags, &mut stack)
}

pub fn clone_with_stack<F>(cb: F, flags: libc::c_int, stack: &mut [u8]) -> Result<Pid, Errno>
where
    F: FnMut() -> i32,
{
    type CloneCb<'a> = Box<dyn FnMut() -> i32 + 'a>;

    extern "C" fn callback(data: *mut CloneCb) -> libc::c_int {
        let cb: &mut CloneCb = unsafe { &mut *data };
        (*cb)() as libc::c_int
    }

    let mut cb: CloneCb = Box::new(cb);

    let res = unsafe {
        let stack = stack.as_mut_ptr().add(stack.len());
        let stack = stack.sub(stack as usize % 16);

        libc::clone(
            core::mem::transmute::<
                extern "C" fn(*mut Box<dyn FnMut() -> i32>) -> i32,
                extern "C" fn(*mut libc::c_void) -> libc::c_int,
            >(callback as extern "C" fn(*mut Box<dyn FnMut() -> i32>) -> i32),
            stack as *mut libc::c_void,
            flags,
            &mut cb as *mut _ as *mut libc::c_void,
        )
    };

    Errno::result(res).map(Pid::from_raw)
}
