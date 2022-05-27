/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::{
    syscalls::{Errno, MemoryAccess, Syscall, Timespec},
    Error, Guest, Tool,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState;

#[reverie::tool]
impl Tool for LocalState {
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

#[cfg(all(not(sanitized), test))]
mod tests {
    use super::*;
    use reverie_ptrace::testing::check_fn;
    use std::{mem::MaybeUninit, time};

    #[test]
    #[should_panic]
    fn run_guest_vdso_tod_test() {
        check_fn::<LocalState, _>(|| {
            // this calls clock_gettime.
            let _now = time::Instant::now();
        });
    }

    #[test]
    fn run_guest_vdso_getcpu_test() {
        check_fn::<LocalState, _>(|| {
            // this calls getcpu via vdso.
            let cpu = unsafe { libc::sched_getcpu() };
            // NB: getcpu in vdso area always set cpu to 0.
            // see symbol __vdso_getcpu.
            assert_eq!(cpu, 0);
        });
    }

    #[test]
    fn run_guest_vdso_gettimeofday_test() {
        check_fn::<LocalState, _>(|| {
            let mut tod = MaybeUninit::zeroed();
            let mut tz = MaybeUninit::zeroed();
            assert_eq!(
                unsafe { libc::gettimeofday(tod.as_mut_ptr(), tz.as_mut_ptr()) },
                0
            );
            let tod = unsafe { tod.assume_init() };
            assert_eq!(tod.tv_usec % 1000, 345);
        });
    }

    #[test]
    fn run_guest_vdso_clock_getres_test() {
        check_fn::<LocalState, _>(|| {
            let mut res = libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };

            let ret = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC, &mut res as *mut _) };

            assert_eq!(ret, 0);

            assert_eq!(res.tv_sec, 0);
            assert_eq!(res.tv_nsec, 42);
        });
    }
}
