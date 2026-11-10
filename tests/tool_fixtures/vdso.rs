/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::Timespec;

#[derive(Debug, Default, Clone)]
pub struct LocalState;

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::ClockGettime(_gettime) => Err(Errno::EINVAL.into()),
            Syscall::Gettimeofday(gettimeofday) => {
                let retval = guest.inject(syscall).await?;
                if let Some(tod) = gettimeofday.tv() {
                    let mut tv = guest.memory().read_value(tod)?;
                    tv.tv_usec = (tv.tv_usec / 1000) * 1000 + 345;
                    guest.memory().write_value(tod, &tv)?;
                }

                Ok(retval)
            }
            Syscall::Getcpu(getcpu) => {
                if let Some(cpu) = getcpu.cpu() {
                    guest.memory().write_value(cpu, &0)?;
                }
                Ok(0)
            }
            Syscall::ClockGetres(clock_getres) => {
                if let Some(ts) = clock_getres.res() {
                    guest.memory().write_value(
                        ts,
                        &Timespec {
                            tv_sec: 0,
                            tv_nsec: 42,
                        },
                    )?;
                }

                Ok(0)
            }
            otherwise => guest.tail_inject(otherwise).await,
        }
    }
}
