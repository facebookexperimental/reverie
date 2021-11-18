/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use core::fmt;

use crate::memory::{Addr, AddrMut, MemoryAccess};
use crate::Errno;

use nix::{
    fcntl::{AtFlags, OFlag},
    sched::CloneFlags,
    sys::{
        epoll::EpollCreateFlags,
        eventfd::EfdFlags,
        inotify::InitFlags,
        mman::{MapFlags, ProtFlags},
        signalfd::SfdFlags,
        socket::{AddressFamily, SockFlag, SockProtocol},
        stat::{Mode, SFlag},
        timerfd::TimerFlags,
        wait::WaitPidFlag,
    },
    unistd::Pid,
};

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
