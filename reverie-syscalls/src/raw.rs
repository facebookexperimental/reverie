/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use nix::fcntl::AtFlags;
use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::epoll::EpollCreateFlags;
use nix::sys::eventfd::EfdFlags;
use nix::sys::inotify::InitFlags;
use nix::sys::mman::MapFlags;
use nix::sys::mman::ProtFlags;
use nix::sys::signalfd::SfdFlags;
use nix::sys::socket::SockFlag;
use nix::sys::stat::Mode;
use nix::sys::timerfd::TimerFlags;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;

use crate::Addr;
use crate::AddrMut;
use crate::Errno;

/// Trait representing a raw value. Note that the assertion
/// `assert_eq!(T::from_raw(x).into_raw(), x)` should hold true for every
/// possible value of `T` and `x`. In other words, there should be no loss of
/// information and conversions should never fail. This ensures that adding type
/// information to a value will always be forward compatible.
///
/// This trait is very similar to `From<usize>` and `Into<usize>`. Instead of
/// reusing those existing traits, this separate trait is necessary such that it
/// can be implemented for foreign types.
pub trait FromToRaw: Sized {
    /// Converts a raw value into this type.
    fn from_raw(value: usize) -> Self;

    /// Converts this type into a raw value.
    fn into_raw(self) -> usize;
}

impl FromToRaw for u32 {
    fn from_raw(raw: usize) -> Self {
        raw as Self
    }

    fn into_raw(self) -> usize {
        self as usize
    }
}

impl FromToRaw for i32 {
    fn from_raw(raw: usize) -> Self {
        raw as Self
    }

    fn into_raw(self) -> usize {
        self as usize
    }
}

impl FromToRaw for usize {
    fn from_raw(raw: usize) -> Self {
        raw
    }

    fn into_raw(self) -> usize {
        self
    }
}

impl FromToRaw for u64 {
    fn from_raw(raw: usize) -> Self {
        raw as Self
    }

    fn into_raw(self) -> usize {
        self as usize
    }
}

impl FromToRaw for i64 {
    fn from_raw(raw: usize) -> Self {
        raw as Self
    }

    fn into_raw(self) -> usize {
        self as usize
    }
}

impl<'a, T> FromToRaw for Option<Addr<'a, T>> {
    fn from_raw(raw: usize) -> Self {
        Addr::from_raw(raw as usize)
    }

    fn into_raw(self) -> usize {
        self.map_or(0, |addr| addr.as_raw() as usize)
    }
}

impl<'a, T> FromToRaw for Option<AddrMut<'a, T>> {
    fn from_raw(raw: usize) -> Self {
        AddrMut::from_raw(raw as usize)
    }

    fn into_raw(self) -> usize {
        self.map_or(0, |addr| addr.as_raw() as usize)
    }
}

macro_rules! impl_raw_bits {
    ($t:ty : $inner:ty) => {
        impl $crate::FromToRaw for $t {
            fn from_raw(raw: usize) -> Self {
                unsafe { Self::from_bits_unchecked(raw as $inner) }
            }

            fn into_raw(self) -> usize {
                self.bits() as usize
            }
        }
    };

    ($t:ty) => {
        impl_raw_bits!($t: i32);
    };
}

impl_raw_bits!(AtFlags);
impl_raw_bits!(OFlag);
impl_raw_bits!(CloneFlags);
impl_raw_bits!(Mode: libc::mode_t);
impl_raw_bits!(WaitPidFlag);
impl_raw_bits!(MapFlags);
impl_raw_bits!(ProtFlags);
impl_raw_bits!(EpollCreateFlags);
impl_raw_bits!(EfdFlags);
impl_raw_bits!(InitFlags);
impl_raw_bits!(SockFlag);
impl_raw_bits!(SfdFlags);
impl_raw_bits!(TimerFlags);

impl FromToRaw for Option<Mode> {
    fn from_raw(raw: usize) -> Self {
        if raw == 0 {
            None
        } else {
            Some(Mode::from_raw(raw))
        }
    }

    fn into_raw(self) -> usize {
        match self {
            None => 0,
            Some(mode) => mode.into_raw(),
        }
    }
}

impl FromToRaw for Pid {
    fn from_raw(raw: usize) -> Self {
        Pid::from_raw(raw as i32)
    }

    fn into_raw(self) -> usize {
        self.as_raw() as usize
    }
}

impl<T> FromToRaw for Result<T, Errno>
where
    T: FromToRaw,
{
    fn from_raw(raw: usize) -> Self {
        Errno::from_ret(raw).map(|x| T::from_raw(x as usize))
    }

    fn into_raw(self) -> usize {
        match self {
            Ok(x) => x.into_raw(),
            Err(err) => -err.into_raw() as usize,
        }
    }
}

#[cfg(test)]
mod test {
    use nix::unistd::Pid;

    use super::*;

    #[test]
    fn test_results() {
        assert_eq!(
            Result::<Pid, Errno>::from_raw(-2isize as usize),
            Err(Errno::ENOENT)
        );

        assert_eq!(Result::<Pid, Errno>::from_raw(42), Ok(Pid::from_raw(42)));
    }
}
