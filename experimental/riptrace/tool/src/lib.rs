/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An strace tool meant to be injected and ran by SaBRe.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use reverie_sabre as sabre;
use reverie_syscalls::Displayable;
use reverie_syscalls::LocalMemory;
use reverie_syscalls::Syscall;
use riptrace_rpc::Config;
use riptrace_rpc::MyServiceClient;
use sabre::SyscallExt;
use sabre::Tool;
use syscalls::Errno;
use syscalls::Sysno;

struct Riptrace {
    /// Count of syscalls we've seen so far.
    count: AtomicU64,
    #[allow(dead_code)]
    client: MyServiceClient,
    config: Config,
}

#[sabre::tool]
impl Tool for Riptrace {
    type Client = MyServiceClient;

    #[detour(lib = "libc", func = "malloc")]
    fn malloc(_size: usize) -> *mut libc::c_void {
        todo!()
    }

    #[detour(lib = "libc", func = "free")]
    fn free(_ptr: *mut libc::c_void) {
        todo!()
    }

    fn new(client: Self::Client) -> Self {
        let config = client.config();

        Self {
            count: AtomicU64::new(0),
            client,
            config,
        }
    }

    fn syscall(&self, syscall: Syscall, memory: &LocalMemory) -> Result<usize, Errno> {
        self.count.fetch_add(1, Ordering::Relaxed);
        match syscall {
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                if !self.config.quiet {
                    self.client.print_syscall(&syscall, memory, None);
                }

                // NOTE: execve does not return upon success
                let errno = unsafe { syscall.call() }.unwrap_err();

                self.client
                    .print_syscall(&syscall, memory, Some(Err(errno)));

                Err(errno)
            }
            syscall => {
                let ret = unsafe { syscall.call() };

                if !self.config.quiet && (!self.config.only_failures || ret.is_err()) {
                    self.client.print_syscall(&syscall, memory, Some(ret));
                }

                ret
            }
        }
    }
}

trait MyServiceClientExt {
    fn print_syscall(
        &self,
        syscall: &Syscall,
        memory: &LocalMemory,
        result: Option<Result<usize, Errno>>,
    );
}

impl MyServiceClientExt for MyServiceClient {
    fn print_syscall(
        &self,
        syscall: &Syscall,
        memory: &LocalMemory,
        result: Option<Result<usize, Errno>>,
    ) {
        // TODO: Use a thread-local to avoid this extra syscall.
        let tid = unsafe { syscalls::raw_syscall!(Sysno::gettid) } as u32;

        // TODO: Use a smallvec to allocate this instead.
        let pretty = syscall.display_with_outputs(memory).to_string();

        self.pretty_print(tid, &pretty, result)
    }
}
