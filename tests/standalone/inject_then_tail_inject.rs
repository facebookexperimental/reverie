/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use nix::unistd;
use reverie::{
    syscalls::{Displayable, MemoryAccess, Syscall, Sysno},
    Error, GlobalTool, Guest, Pid, Tool,
};
use serde::{Deserialize, Serialize};
use std::{alloc, env, mem};
use tracing::warn;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct TestTool {}

type Dupcount = u64;

#[reverie::global_tool]
impl GlobalTool for TestTool {
    type Config = Dupcount;

    async fn receive_rpc(&self, _from: Pid, _message: ()) {}
}

/// How many bytes of randomness to peak at.
const RAND_SIZE: usize = mem::size_of::<u64>();

/// How many times to DUPLICATE select system calls that are intercepted.
const NUM_REPS: Dupcount = 3;

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = TestTool;

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        let reps = guest.config().clone();
        match call {
            Syscall::Gettid(_)
            | Syscall::Getgid(_)
            | Syscall::Getsid(_)
            | Syscall::Getppid(_)
            | Syscall::Getpgid(_)
            | Syscall::Getpid(_) => {
                for i in 1..=reps {
                    let syscall_ret = guest.inject(call).await;
                    warn!(
                        "[pid {}] Duplicated syscall ({}/{})! {} = {}",
                        guest.tid(),
                        i,
                        reps,
                        call.display_with_outputs(&guest.memory()),
                        syscall_ret.unwrap_or_else(|errno| errno.into_raw() as i64)
                    );
                }
            }
            Syscall::Getrandom(r) => {
                if r.buflen() < RAND_SIZE {
                    warn!(
                        "[pid {}] not touching getrandom, buflen too small.",
                        guest.tid()
                    );
                } else {
                    for i in 1..=reps {
                        let syscall_ret = guest.inject(call).await;
                        let bufaddr = r.buf().unwrap();
                        let mut buf: [u8; RAND_SIZE] = [0; RAND_SIZE];
                        guest.memory().read_exact(bufaddr, &mut buf).unwrap();
                        let rand_word: u64 = u64::from_le_bytes(buf);
                        warn!(
                            "[pid {}] Duplicated getrandom syscall ({}/{}): {}, returned {}, first word {}",
                            guest.tid(),
                            i,
                            reps,
                            call.display_with_outputs(&guest.memory()),
                            syscall_ret.unwrap_or_else(|errno| errno.into_raw() as i64),
                            rand_word
                        );
                    }
                }
            }
            _ => {}
        }
        // Irrespective of above, run a tail_inject at the end:
        guest.tail_inject(call).await
    }
}

fn guest_mode() {
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

async fn host_mode(thisprog: &str) -> Result<i32, Error> {
    println!("Running in HOST mode (ReverieTool)");

    let mut command = reverie::process::Command::new(thisprog);
    command.arg("guest");

    let tracer = reverie_ptrace::TracerBuilder::<TestTool>::new(command)
        .config(NUM_REPS)
        .spawn()
        .await?;
    let (status, _) = tracer.wait().await?;

    Ok(status.code().unwrap_or(1))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    match &args[..] {
        [p] => std::process::exit(host_mode(p).await?),
        [_, s] if s == "guest" => guest_mode(),
        _ => panic!(
            "Expected 'guest' or no CLI argument. Got unexpected command line args ({}): {:?}",
            args.len(),
            args
        ),
    }

    Ok(())
}
