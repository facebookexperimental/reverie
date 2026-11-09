/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::alloc;

use nix::unistd;
use reverie::syscalls::Sysno;

#[path = "../tool_fixtures/inject_then_tail_constants.rs"]
mod constants;

use constants::RAND_SIZE;

pub fn guest_mode() {
    println!("Running in guest mode (actual test).");
    let tid = unistd::gettid();
    let pid = unistd::getpid();
    let gid = unistd::getgid();
    let ppid = unistd::getppid();
    let pgid = unistd::getpgid(None).unwrap();
    let sid = unistd::getsid(None).unwrap();
    println!(
        "Read IDs: t {}, p {}, g {}, pp {}, pg {}, s{}",
        tid, pid, gid, ppid, pgid, sid,
    );
    // let r = syscalls::syscall!(0, 100, 0);
    let sz = RAND_SIZE;
    let rand_num: u64 = unsafe {
        let layout = alloc::Layout::from_size_align(sz, sz).unwrap();
        let buf = alloc::alloc(layout);
        let no = Sysno::getrandom as i64;
        let rand = libc::syscall(no, buf, sz, 0);
        if rand < 0 {
            panic!("getrandom returned error code {}\n", rand);
        } else if rand != sz as i64 {
            panic!(
                "getrandom did not generate all {} bytes (instead {}\n",
                sz, rand
            );
        }

        #[allow(clippy::cast_ptr_alignment)]
        let num: u64 = *(buf as *mut u64);
        alloc::dealloc(buf, layout);
        num
    };
    println!("Generated random number: {}", rand_num);
}
