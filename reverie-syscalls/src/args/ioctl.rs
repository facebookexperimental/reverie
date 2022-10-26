/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Everything related to ioctl arguments.

use serde::Deserialize;
use serde::Serialize;

use crate::Addr;
use crate::AddrMut;
use crate::Errno;
use crate::FromToRaw;
use crate::MemoryAccess;

/// The type of ioctl from the perspective of userspace. That is, whether
/// userspace is reading, writing, or doing nothing.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Direction {
    /// Userspace is reading.
    Read,
    /// Userspace is writing.
    Write,
    /// There is neither reading nor writing. This is the case for ioctls that
    /// have value parameters instead of pointer parameters.
    None,
}

command_enum! {
    /// An `ioctl` request.
    ///
    /// The `ioctl` syscall is a dumping ground for sending a request to a file
    /// descriptor. This is not a complete list of all the possible requests, but
    /// we try to have the most-commonly used requests listed.
    ///
    /// See [`ioctl_list(2)`][ioctl_list] for a more complete list.
    ///
    /// [ioctl_list]: http://man7.org/linux/man-pages/man2/ioctl_list.2.html
    pub enum Request<'a>: usize {
        // <include/asm-i386/socket.h>
        FIOSETOWN(Option<Addr<'a, libc::c_int>>) = 0x00008901,
        SIOCSPGRP(Option<Addr<'a, libc::c_int>>) = 0x00008902,
        FIOGETOWN(Option<AddrMut<'a, libc::c_int>>) = 0x00008903,
        SIOCGPGRP(Option<AddrMut<'a, libc::c_int>>) = 0x00008904,
        SIOCATMAR(Option<AddrMut<'a, libc::c_int>>) = 0x00008905,
        SIOCGSTAMP(Option<AddrMut<'a, libc::timeval>>) = 0x00008906,

        // <include/asm-i386/termios.h>
        TCGETS(Option<AddrMut<'a, Termios>>) = 0x00005401,
        TCSETS(Option<Addr<'a, Termios>>) = 0x00005402,
        TCSETSW(Option<Addr<'a, Termios>>) = 0x00005403,
        TCSETSF(Option<Addr<'a, Termios>>) = 0x00005404,
        TCGETA(Option<AddrMut<'a, Termios>>) = 0x00005405,
        TCSETA(Option<Addr<'a, Termios>>) = 0x00005406,
        TCSETAW(Option<Addr<'a, Termios>>) = 0x00005407,
        TCSETAF(Option<Addr<'a, Termios>>) = 0x00005408,
        TCSBRK(libc::c_int) = 0x00005409,
        TCXONC(libc::c_int) = 0x0000540A,
        TCFLSH(libc::c_int) = 0x0000540B,
        TIOCEXCL = 0x0000540C,
        TIOCNXCL = 0x0000540D,
        TIOCSCTTY(libc::c_int) = 0x0000540E,
        TIOCGPGRP(Option<AddrMut<'a, libc::pid_t>>) = 0x0000540F,
        TIOCSPGRP(Option<Addr<'a, libc::pid_t>>) = 0x00005410,
        TIOCOUTQ(Option<AddrMut<'a, libc::c_int>>) = 0x00005411,
        TIOCSTI(Option<Addr<'a, libc::c_char>>) = 0x00005412,
        TIOCGWINSZ(Option<AddrMut<'a, Winsize>>) = 0x00005413,
        TIOCSWINSZ(Option<Addr<'a, Winsize>>) = 0x00005414,
        TIOCMGET(Option<AddrMut<'a, libc::c_int>>) = 0x00005415,
        TIOCMBIS(Option<Addr<'a, libc::c_int>>) = 0x00005416,
        TIOCMBIC(Option<Addr<'a, libc::c_int>>) = 0x00005417,
        TIOCMSET(Option<Addr<'a, libc::c_int>>) = 0x00005418,
        TIOCGSOFTCAR(Option<AddrMut<'a, libc::c_int>>) = 0x00005419,
        TIOCSSOFTCAR(Option<Addr<'a, libc::c_int>>) = 0x0000541A,
        FIONREAD(Option<AddrMut<'a, libc::c_int>>) = 0x0000541B,
        // Duplicate of FIONREAD; can't properly match the ID.
        #[cfg(none)]
        TIOCINQ(Option<AddrMut<'a, libc::c_int>>) = 0x0000541B,
        TIOCLINUX(Option<Addr<'a, libc::c_char>>) = 0x0000541C,
        TIOCCONS = 0x0000541D,
        // Disabled because `libc::serial_struct` isn't defined.
        #[cfg(none)]
        TIOCGSERIAL(Option<AddrMut<'a, libc::serial_struct>>) = 0x0000541E,
        // Disabled because `libc::serial_struct` isn't defined.
        #[cfg(none)]
        TIOCSSERIAL(Option<Addr<'a, libc::serial_struct>>) = 0x0000541F,
        TIOCPKT(Option<Addr<'a, libc::c_int>>) = 0x00005420,
        FIONBIO(Option<Addr<'a, libc::c_int>>) = 0x00005421,
        TIOCNOTTY = 0x00005422,
        TIOCSETD(Option<Addr<'a, libc::c_int>>) = 0x00005423,
        TIOCGETD(Option<AddrMut<'a, libc::c_int>>) = 0x00005424,
        TCSBRKP(libc::c_int) = 0x00005425,
        // Disabled because `libc::tty_struct` isn't defined.
        #[cfg(none)]
        TIOCTTYGSTRUCT(Option<AddrMut<'a, libc::tty_struct>>) = 0x00005426,
        TIOCGPTPEER(libc::c_int) = 0x00005441,
        FIONCLEX = 0x00005450,
        FIOCLEX = 0x00005451,
        FIOASYNC(Option<Addr<'a, libc::c_int>>) = 0x00005452,
        TIOCSERCONFIG = 0x00005453,
        TIOCSERGWILD(Option<AddrMut<'a, libc::c_int>>) = 0x00005454,
        TIOCSERSWILD(Option<Addr<'a, libc::c_int>>) = 0x00005455,
        TIOCGLCKTRMIOS(Option<AddrMut<'a, Termios>>) = 0x00005456,
        TIOCSLCKTRMIOS(Option<Addr<'a, Termios>>) = 0x00005457,
        // Disabled because `libc::async_struct` isn't defined.
        #[cfg(none)]
        TIOCSERGSTRUCT(Option<AddrMut<'a, libc::async_struct>>) = 0x00005458,
        TIOCSERGETLSR(Option<AddrMut<'a, libc::c_int>>) = 0x00005459,

        FICLONE(libc::c_int) = 0x40049409,
        FICLONERANGE(Option<Addr<'a, libc::file_clone_range>>) = 0x4020940D,
    }
}

impl<'a> Request<'a> {
    /// Returns the direction of the request. That is, whether it is a read or
    /// write request.
    pub fn direction(&self) -> Direction {
        // TODO: Generate this with a macro.
        match self {
            Self::TCGETS(_) => Direction::Read,
            Self::TCSETS(_) => Direction::Write,
            Self::TIOCGWINSZ(_) => Direction::Read,
            Self::TIOCSWINSZ(_) => Direction::Write,
            Self::TIOCSPGRP(_) => Direction::Write,
            Self::TIOCGPGRP(_) => Direction::Read,
            Self::FIONREAD(_) => Direction::Read,
            other => {
                panic!("ioctl: unsupported request: {:?}", other)
            }
        }
    }

    /// Reads the output associated with this request. If the request has no
    /// outputs, returns `Ok(None)`.
    ///
    /// Panics if this request is unsupported.
    pub fn read_output<M: MemoryAccess>(&self, m: &M) -> Result<Option<Output>, Errno> {
        // TODO: Generate this with a macro.
        Ok(Some(match self {
            Self::TCGETS(p) => Output::TCGETS(m.read_value(p.ok_or(Errno::EFAULT)?)?),
            Self::TCSETS(_) => return Ok(None),
            Self::TIOCGWINSZ(p) => Output::TIOCGWINSZ(m.read_value(p.ok_or(Errno::EFAULT)?)?),
            Self::TIOCSWINSZ(_) => return Ok(None),
            Self::TIOCGPGRP(p) => Output::TIOCGPGRP(m.read_value(p.ok_or(Errno::EFAULT)?)?),
            Self::TIOCSPGRP(_) => return Ok(None),
            Self::FIONREAD(p) => Output::FIONREAD(m.read_value(p.ok_or(Errno::EFAULT)?)?),
            other => {
                panic!("ioctl: unsupported request: {:?}", other);
            }
        }))
    }

    /// Writes the output associated with this request to the provided address
    /// (if any). If the request has no outputs, returns `Ok(())`.
    pub fn write_output<M: MemoryAccess>(&self, m: &mut M, output: &Output) -> Result<(), Errno> {
        match (self, output) {
            (Self::TCGETS(p), Output::TCGETS(output)) => {
                m.write_value(p.ok_or(Errno::EFAULT)?, output)
            }
            (Self::TCSETS(_), _) => Ok(()),
            (Self::TIOCGWINSZ(p), Output::TIOCGWINSZ(output)) => {
                m.write_value(p.ok_or(Errno::EFAULT)?, output)
            }
            (Self::TIOCSWINSZ(_), _) => Ok(()),
            (Self::TIOCGPGRP(p), Output::TIOCGPGRP(output)) => {
                m.write_value(p.ok_or(Errno::EFAULT)?, output)
            }
            (Self::TIOCSPGRP(_), _) => Ok(()),
            (Self::FIONREAD(p), Output::FIONREAD(output)) => {
                m.write_value(p.ok_or(Errno::EFAULT)?, output)
            }
            (other, output) => {
                panic!(
                    "ioctl: unsupported request/output pair: {:?}, {:?}",
                    other, output
                );
            }
        }
    }
}

/// The output after a successful call to `ioctl`. This is only relavent for
/// requests with outputs.
///
/// Note that this is a `union`. The descriminator is the [`Request`] type.
#[allow(missing_docs, non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Output {
    TCGETS(Termios),
    TIOCGWINSZ(Winsize),
    TIOCGPGRP(libc::pid_t),
    FIONREAD(libc::c_int),
}

/// Terminal I/O. This is the same as `termios` as defined in
/// `include/uapi/asm-generic/termbits.h`. Note that this is *different* from the
/// struct exposed by libc (which maps the smaller kernel-defined struct onto a
/// larger libc-defined struct).
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Termios {
    /// input mode flags
    pub c_iflag: libc::tcflag_t,
    /// output mode flags
    pub c_oflag: libc::tcflag_t,
    /// control mode flags
    pub c_cflag: libc::tcflag_t,
    /// local mode flags
    pub c_lflag: libc::tcflag_t,
    /// line discipline
    pub c_line: libc::cc_t,
    /// control characters
    pub c_cc: [libc::cc_t; 19],
}

#[allow(missing_docs)]
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Winsize {
    pub ws_row: libc::c_ushort,
    pub ws_col: libc::c_ushort,
    pub ws_xpixel: libc::c_ushort,
    pub ws_ypixel: libc::c_ushort,
}
