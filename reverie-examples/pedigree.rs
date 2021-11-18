/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
//! An example that tracks thread pedigree using local state
use reverie::{syscalls::Syscall, Error, Guest, Pid, Tool};
use reverie_util::{pedigree::Pedigree, CommonToolArguments};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tracing::{debug, trace};

// TODO: Add handle pedigree forking, initialization, etc. to tool.
// This tool is NOT FUNCTIONAL in its current state.

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct PedigreeLocal(Pedigree);

#[reverie::tool]
impl Tool for PedigreeLocal {
    type ThreadState = PedigreeLocal;

    fn new(pid: Pid, _cfg: &()) -> Self {
        debug!("[pedigree] initialize pedigree for pid {}", pid);
        PedigreeLocal(Pedigree::new())
    }

    fn init_thread_state(
        &self,
        _tid: Pid,
        parent: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        if let Some((_, state)) = parent {
            let mut parent = state.clone();
            let child = parent.0.fork_mut();
            trace!("child pedigree: {:?}", child);
            PedigreeLocal(child)
        } else {
            PedigreeLocal(Pedigree::new())
        }
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Fork(_) | Syscall::Vfork(_) | Syscall::Clone(_) => {
                let retval = guest.inject(syscall).await?;
                let pedigree = guest.thread_state_mut().0.fork_mut();
                trace!(
                    "got new pedigree: {:?} => {:x?}",
                    pedigree,
                    nix::unistd::Pid::try_from(&pedigree)
                );
                Ok(retval)
            }
            Syscall::Getpid(_)
            | Syscall::Getppid(_)
            | Syscall::Gettid(_)
            | Syscall::Getpgid(_)
            | Syscall::Getpgrp(_) => {
                let pid = guest.inject(syscall).await?;
                let vpid = nix::unistd::Pid::try_from(&self.0).unwrap();
                trace!("getpid returned {:?} vpid: {:?}", pid, vpid);
                Ok(pid)
            }
            Syscall::Setpgid(_) => {
                panic!("[pedigree] setpgid is not allowed.");
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::from_args();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<PedigreeLocal>::new(args.into())
        .spawn()
        .await?;
    let (status, _global_state) = tracer.wait().await?;
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
