/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::fmt;

use nix::fcntl::AtFlags;
use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::epoll::EpollCreateFlags;
use nix::sys::eventfd::EfdFlags;
use nix::sys::inotify::InitFlags;
use nix::sys::mman::MapFlags;
use nix::sys::mman::ProtFlags;
use nix::sys::signalfd::SfdFlags;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockProtocol;
use nix::sys::stat::Mode;
use nix::sys::stat::SFlag;
use nix::sys::timerfd::TimerFlags;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;

use crate::Addr;
use crate::AddrMut;
use crate::Errno;
use crate::MemoryAccess;

/// A wrapper that combines an address space and a syscall. This is useful for
/// displaying the contents of syscall pointer inputs.
pub struct Display<'a, M, T> {
    /// How we access memory.
    memory: &'a M,

    /// The syscall arguments we need to display.
    syscall: &'a T,

    /// Whether or not to display output arguments.
    outputs: bool,
}

impl<'a, M, T> Display<'a, M, T> {
    /// Allocate a new display struct from a memory and a syscall whose
    /// arguments read from that memory.
    pub fn new(memory: &'a M, syscall: &'a T, outputs: bool) -> Self {
        Display {
            memory,
            syscall,
            outputs,
        }
    }
}

impl<'a, M, T> fmt::Display for Display<'a, M, T>
where
    M: MemoryAccess,
    T: Displayable,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.syscall.fmt(self.memory, self.outputs, f)
    }
}

/// Trait that all syscalls and their arguments need to implement in order to be
/// printed out.
pub trait Displayable {
    /// Displays a syscall with all of its arguments.
    fn fmt<M: MemoryAccess>(
        &self,
        memory: &M,
        outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result;

    /// Returns an object that implements `std::fmt::Display` and displays only
    /// syscall inputs.
    fn display<'a, M>(&'a self, memory: &'a M) -> Display<'a, M, Self>
    where
        M: MemoryAccess,
        Self: Sized,
    {
        Display::new(memory, self, false)
    }

    /// Returns an object that implements `std::fmt::Display` and displays
    /// syscall inputs as well as outputs. Useful for displaying pointer
    /// arguments that are only valid after a syscall has been executed.
    fn display_with_outputs<'a, M>(&'a self, memory: &'a M) -> Display<'a, M, Self>
    where
        M: MemoryAccess,
        Self: Sized,
    {
        Display::new(memory, self, true)
    }
}

impl<'a, T> Displayable for Option<Addr<'a, T>> {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            None => write!(f, "NULL"),
            Some(addr) => write!(f, "{:?}", addr),
        }
    }
}

impl<'a, T> Displayable for Option<AddrMut<'a, T>> {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            None => write!(f, "NULL"),
            Some(addr) => write!(f, "{:?}", addr),
        }
    }
}

impl Displayable for OFlag {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        if self.is_empty() {
            // Without this special case, the default Debug implementation will
            // print "O_LARGEFILE | O_RDONLY" because both of those flags are
            // zeros.
            f.write_str("0")
        } else {
            fmt::Debug::fmt(self, f)
        }
    }
}

impl<T> Displayable for Result<T, Errno>
where
    T: fmt::Display,
{
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            Ok(x) => fmt::Display::fmt(x, f),
            Err(err) => fmt::Display::fmt(err, f),
        }
    }
}

/// Macro that implements ['Displayable'] trait for a given type based on
/// another trait implementation e.g. ['Debug'] or ['Display'], etc
#[macro_export]
macro_rules! impl_displayable {
    ($fmt:ident $t:ty) => {
        impl $crate::Displayable for $t {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                _memory: &M,
                _outputs: bool,
                f: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                ::core::fmt::$fmt::fmt(self, f)
            }
        }
    };
}

/// Macro that implements a wrapper for a pointer e.g. ['AddrMut']
/// or ['Addr] with custom ['Displayable'] implementation
#[macro_export]
macro_rules! displayable_ptr {
    ($type:ident, $pointer:ident<$value:ident>) => {
        /// A pointer to a `timeval` buffer.
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[allow(missing_docs)]
        pub struct $type<'a>(pub $crate::$pointer<'a, $value>);

        impl<'a> $crate::FromToRaw for std::option::Option<$type<'a>> {
            fn from_raw(raw: usize) -> Self {
                $crate::$pointer::from_ptr(raw as *const $value).map($type)
            }

            fn into_raw(self) -> usize {
                self.map(|p| p.0).into_raw()
            }
        }

        impl<'a> $crate::ReadAddr for $type<'a> {
            type Target = $value;
            type Error = $crate::Errno;

            fn read<M: $crate::MemoryAccess>(
                &self,
                memory: &M,
            ) -> Result<Self::Target, Self::Error> {
                memory.read_value(self.0)
            }
        }

        impl<'a> $crate::Displayable for std::option::Option<$type<'a>> {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                memory: &M,
                outputs: bool,
                f: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                $crate::fmt_nullable_ptr(f, &self.map(|x| x.0), memory, outputs)
            }
        }

        impl<'a> From<$type<'a>> for $crate::AddrMut<'a, $value> {
            fn from(time_ptr: $type<'a>) -> Self {
                time_ptr.0
            }
        }

        impl<'a> From<$type<'a>> for $crate::Addr<'a, $value> {
            fn from(time_ptr: $type<'a>) -> Self {
                time_ptr.0.into()
            }
        }
    };
}

impl_displayable!(Debug AtFlags);
impl_displayable!(Debug CloneFlags);
impl_displayable!(Debug Mode);
impl_displayable!(Debug SFlag);
impl_displayable!(Debug WaitPidFlag);
impl_displayable!(Debug MapFlags);
impl_displayable!(Debug ProtFlags);
impl_displayable!(Debug EpollCreateFlags);
impl_displayable!(Debug EfdFlags);
impl_displayable!(Debug SfdFlags);
impl_displayable!(Debug InitFlags);
impl_displayable!(Debug SockFlag);
impl_displayable!(Debug AddressFamily);
impl_displayable!(Debug SockProtocol);
impl_displayable!(Debug Option<SockProtocol>);
impl_displayable!(Debug TimerFlags);

impl_displayable!(Display Pid);
impl_displayable!(Display i32);
impl_displayable!(Display u32);
impl_displayable!(Display i64);
impl_displayable!(Display u64);
impl_displayable!(Display isize);
impl_displayable!(Display usize);
