/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An strace tool meant to be injected and ran by SaBRe.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use reverie_sabre as sabre;
use reverie_syscalls::Displayable;
use reverie_syscalls::LocalMemory;
use reverie_syscalls::MemoryAccess;
use reverie_syscalls::Syscall;
use reverie_syscalls::SyscallInfo;
use sabre::SyscallExt;
use sabre::Tool;
use syscalls::Errno;
use syscalls::Sysno;
use traceviz_rpc::MyServiceClient;
use traceviz_rpc::SyscallEvent;

struct Traceviz {
    #[allow(dead_code)]
    client: MyServiceClient,
    file_descriptors: Mutex<HashMap<i32, u64>>,
}

#[sabre::tool]
impl Tool for Traceviz {
    type Client = MyServiceClient;

    fn new(client: Self::Client) -> Self {
        // FIXME: Sanitizers don't play well when we do allocations in this
        // function.
        Self {
            client,
            file_descriptors: Mutex::new(HashMap::new()),
        }
    }

    fn syscall(&self, syscall: Syscall, memory: &LocalMemory) -> Result<usize, Errno> {
        match syscall {
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                sabre::eprintln!("{}", syscall.display_with_outputs(memory));

                // NOTE: execve does not return upon success
                let errno = unsafe { syscall.call() }.unwrap_err();

                sabre::eprintln!("{} = {:?}", syscall.number(), errno);

                Err(errno)
            }
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                sabre::eprintln!("{}", syscall.display_with_outputs(memory));

                // Do any final log messages here because once we call exit or
                // exit_group, this thread/process is a goner.

                // NOTE: Never returns...
                unsafe { syscall.call() }
            }
            syscall => {
                let syscall_start = SystemTime::now();

                let syscall_result = unsafe { syscall.call() };

                let syscall_end = SystemTime::now();

                let process_id = unsafe { syscalls::raw::syscall0(Sysno::getpid) } as i32;
                let thread_id = unsafe { syscalls::raw::syscall0(Sysno::gettid) } as i32;

                let syscall_num = syscall.number();
                let pretty = syscall.display_with_outputs(memory).to_string();

                let mut fd_map = self.file_descriptors.lock().unwrap();

                let parent_event_id = match syscall {
                    // These syscalls operate on a single file descriptor
                    Syscall::Read(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Write(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Readv(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Writev(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Preadv(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Preadv2(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Pread64(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Pwritev(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Pwritev2(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Pwrite64(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Accept(s) => {
                        let fd = s.sockfd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Accept4(s) => {
                        let fd = s.sockfd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Dup(s) => {
                        let fd = s.oldfd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Dup2(s) => {
                        let fd = s.oldfd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Recvfrom(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Recvmmsg(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Recvmsg(s) => {
                        let fd = s.sockfd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Sendmmsg(s) => {
                        let fd = s.sockfd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Sendmsg(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Sendto(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Fstat(s) => {
                        let fd = s.fd();
                        fd_map.get(&fd).copied()
                    }
                    Syscall::Newfstatat(s) => {
                        let fd = s.dirfd();
                        fd_map.get(&fd).copied()
                    }
                    // These syscalls close an existing file descriptor
                    Syscall::Close(s) => {
                        let fd = s.fd();
                        fd_map.remove(&fd)
                    }
                    // TODO: These syscalls operate on multiple file descriptors
                    _ => None,
                };

                let event_id = self.client.send_syscall_event(SyscallEvent {
                    syscall_num,
                    process_id,
                    thread_id,
                    event_id: 0,
                    parent_event_id,
                    syscall_start,
                    syscall_result,
                    syscall_end,
                    args: pretty,
                });

                match syscall {
                    // These syscalls open a new file descriptor
                    Syscall::Open(_)
                    | Syscall::Openat(_)
                    | Syscall::Socket(_)
                    | Syscall::Accept(_)
                    | Syscall::Accept4(_)
                    | Syscall::EpollCreate(_)
                    | Syscall::Dup(_)
                    | Syscall::Dup2(_) => {
                        if let Ok(fd) = syscall_result {
                            fd_map.insert(fd as i32, event_id);
                        }
                    }
                    Syscall::Socketpair(s) => {
                        if let Some(usockvec) = s.usockvec() {
                            let fds: [i32; 2] = memory.read_value(usockvec)?;
                            fd_map.insert(fds[0], event_id);
                            fd_map.insert(fds[1], event_id);
                        }
                    }
                    Syscall::Pipe(s) => {
                        if let Some(pipefd) = s.pipefd() {
                            let fds: [i32; 2] = memory.read_value(pipefd)?;
                            fd_map.insert(fds[0], event_id);
                            fd_map.insert(fds[1], event_id);
                        }
                    }
                    _ => {}
                }

                syscall_result
            }
        }
    }
}
