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
    /// have value parameters instead of pointer parameters, and for unknown
    /// requests whose memory effects cannot be decoded.
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
        SIOCGIFINDEX(Option<AddrMut<'a, Ifreq>>) = 0x00008933,
        SIOCETHTOOL(Option<AddrMut<'a, u8>>) = 0x00008946,

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
        #[cfg(any())]
        TIOCINQ(Option<AddrMut<'a, libc::c_int>>) = 0x0000541B,
        TIOCLINUX(Option<Addr<'a, libc::c_char>>) = 0x0000541C,
        TIOCCONS = 0x0000541D,
        // Disabled because `libc::serial_struct` isn't defined.
        #[cfg(any())]
        TIOCGSERIAL(Option<AddrMut<'a, libc::serial_struct>>) = 0x0000541E,
        // Disabled because `libc::serial_struct` isn't defined.
        #[cfg(any())]
        TIOCSSERIAL(Option<Addr<'a, libc::serial_struct>>) = 0x0000541F,
        TIOCPKT(Option<Addr<'a, libc::c_int>>) = 0x00005420,
        FIONBIO(Option<Addr<'a, libc::c_int>>) = 0x00005421,
        TIOCNOTTY = 0x00005422,
        TIOCSETD(Option<Addr<'a, libc::c_int>>) = 0x00005423,
        TIOCGETD(Option<AddrMut<'a, libc::c_int>>) = 0x00005424,
        TCSBRKP(libc::c_int) = 0x00005425,
        // Disabled because `libc::tty_struct` isn't defined.
        #[cfg(any())]
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
        #[cfg(any())]
        TIOCSERGSTRUCT(Option<AddrMut<'a, libc::async_struct>>) = 0x00005458,
        TIOCSERGETLSR(Option<AddrMut<'a, libc::c_int>>) = 0x00005459,

        FICLONE(libc::c_int) = 0x40049409,
        FICLONERANGE(Option<Addr<'a, libc::file_clone_range>>) = 0x4020940D,
    }
}

const IFNAMSIZ: usize = 16;
const ETHTOOL_GSET: u32 = 0x0000_0001;
const ETHTOOL_GLINK: u32 = 0x0000_000a;
const IOC_SIZE_SHIFT: usize = 16;
const IOC_SIZE_MASK: usize = (1 << 14) - 1;
const IOC_DIR_SHIFT: usize = 30;
const IOC_READ: usize = 2;

fn ioctl_output_size(request: usize) -> usize {
    if (request >> IOC_DIR_SHIFT) & IOC_READ != 0 {
        (request >> IOC_SIZE_SHIFT) & IOC_SIZE_MASK
    } else {
        0
    }
}

fn ethtool_data<'a, M: MemoryAccess>(
    ifreq: Option<AddrMut<'a, u8>>,
    memory: &M,
) -> Result<AddrMut<'a, u8>, Errno> {
    let ifreq = ifreq.ok_or(Errno::EFAULT)?;
    let data_field = unsafe { ifreq.add(IFNAMSIZ) }.cast::<usize>();
    let data = memory.read_value(data_field)?;
    AddrMut::from_raw(data).ok_or(Errno::EFAULT)
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
            Self::SIOCGIFINDEX(_) => Direction::Read,
            Self::SIOCETHTOOL(_) => Direction::Read,
            Self::Other(request, _) => {
                if ioctl_output_size(*request) > 0 {
                    Direction::Read
                } else {
                    Direction::None
                }
            }
            other => {
                panic!("ioctl: unsupported request: {:?}", other)
            }
        }
    }

    /// Reads the output associated with this request. If the request has no
    /// outputs, returns `Ok(None)`.
    ///
    /// Unknown requests with an encoded read size capture that many bytes.
    /// Legacy requests without an encoded size are treated as opaque.
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
            Self::SIOCGIFINDEX(p) => Output::SIOCGIFINDEX(m.read_value(p.ok_or(Errno::EFAULT)?)?),
            Self::SIOCETHTOOL(ifreq) => {
                let data = ethtool_data(*ifreq, m)?;
                let command: u32 = m.read_value(data.cast())?;
                let output = match command {
                    ETHTOOL_GSET => EthtoolOutput::Gset(m.read_value(data.cast())?),
                    ETHTOOL_GLINK => EthtoolOutput::Glink(m.read_value(data.cast())?),
                    other => panic!("ioctl: unsupported SIOCETHTOOL command: {other:#x}"),
                };
                Output::SIOCETHTOOL(output)
            }
            Self::Other(request, arg) => {
                let size = ioctl_output_size(*request);
                if size == 0 {
                    return Ok(None);
                }
                let addr = Addr::<u8>::from_raw(*arg).ok_or(Errno::EFAULT)?;
                let mut bytes = vec![0; size];
                m.read_exact(addr, &mut bytes)?;
                Output::Other(bytes)
            }
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
            (Self::SIOCGIFINDEX(p), Output::SIOCGIFINDEX(output)) => {
                m.write_value(p.ok_or(Errno::EFAULT)?, output)
            }
            (Self::SIOCETHTOOL(ifreq), Output::SIOCETHTOOL(output)) => {
                let data = ethtool_data(*ifreq, m)?;
                match output {
                    EthtoolOutput::Gset(output) => m.write_value(data.cast(), output),
                    EthtoolOutput::Glink(output) => m.write_value(data.cast(), output),
                }
            }
            (Self::Other(request, arg), Output::Other(output))
                if output.len() == ioctl_output_size(*request) =>
            {
                let addr = AddrMut::<u8>::from_raw(*arg).ok_or(Errno::EFAULT)?;
                m.write_exact(addr, output)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalMemory;

    #[test]
    fn unknown_request_is_opaque_and_round_trips() {
        let request = Request::from_raw(0xdead, 0x1234);

        assert_eq!(request, Request::Other(0xdead, 0x1234));
        assert_eq!(request.direction(), Direction::None);
        assert_eq!(request.read_output(&LocalMemory::new()), Ok(None));
        assert_eq!(request.into_raw(), (0xdead, 0x1234));
    }

    #[test]
    fn unknown_read_request_captures_encoded_output_size() {
        const UNKNOWN_READ: usize =
            (IOC_READ << IOC_DIR_SHIFT) | (4 << IOC_SIZE_SHIFT) | (b'x' as usize) << 8 | 0x42;
        let recorded = 0x1234_5678_u32;
        let request = Request::from_raw(UNKNOWN_READ, &recorded as *const u32 as usize);

        assert_eq!(request.direction(), Direction::Read);
        assert_eq!(
            request.read_output(&LocalMemory::new()),
            Ok(Some(Output::Other(recorded.to_ne_bytes().to_vec())))
        );

        let mut replayed = 0_u32;
        let request = Request::from_raw(UNKNOWN_READ, &mut replayed as *mut u32 as usize);
        request
            .write_output(
                &mut LocalMemory::new(),
                &Output::Other(recorded.to_ne_bytes().to_vec()),
            )
            .unwrap();
        assert_eq!(replayed, recorded);
    }

    #[test]
    fn siocgifindex_reads_and_writes_ifreq_output() {
        let mut recorded = Ifreq::default();
        recorded.name[..5].copy_from_slice(b"eth0\0");
        recorded.data[..4].copy_from_slice(&7_i32.to_ne_bytes());
        let request = Request::from_raw(0x8933, &mut recorded as *mut Ifreq as usize);

        assert_eq!(request.direction(), Direction::Read);
        assert_eq!(
            request.read_output(&LocalMemory::new()),
            Ok(Some(Output::SIOCGIFINDEX(recorded)))
        );

        let mut replayed = Ifreq::default();
        let request = Request::from_raw(0x8933, &mut replayed as *mut Ifreq as usize);
        request
            .write_output(&mut LocalMemory::new(), &Output::SIOCGIFINDEX(recorded))
            .unwrap();
        assert_eq!(replayed, recorded);
    }

    #[test]
    fn ethtool_gset_reads_and_writes_nested_output() {
        let recorded = EthtoolCmd {
            cmd: ETHTOOL_GSET,
            supported: 0x8000_6440,
            advertising: 0x8000_0440,
            speed: 1000,
            duplex: 1,
            port: 5,
            ..EthtoolCmd::default()
        };
        let mut recorded_ifreq = [0usize; 5];
        recorded_ifreq[2] = &recorded as *const EthtoolCmd as usize;
        let request = Request::from_raw(0x8946, recorded_ifreq.as_mut_ptr() as usize);

        assert_eq!(std::mem::size_of::<Ifreq>(), 40);
        assert_eq!(std::mem::size_of::<EthtoolCmd>(), 44);
        assert_eq!(request.direction(), Direction::Read);
        assert_eq!(
            request.read_output(&LocalMemory::new()),
            Ok(Some(Output::SIOCETHTOOL(EthtoolOutput::Gset(recorded))))
        );

        let mut replayed = EthtoolCmd {
            cmd: ETHTOOL_GSET,
            ..EthtoolCmd::default()
        };
        let mut replayed_ifreq = [0usize; 5];
        replayed_ifreq[2] = &mut replayed as *mut EthtoolCmd as usize;
        let request = Request::from_raw(0x8946, replayed_ifreq.as_mut_ptr() as usize);

        request
            .write_output(
                &mut LocalMemory::new(),
                &Output::SIOCETHTOOL(EthtoolOutput::Gset(recorded)),
            )
            .unwrap();
        assert_eq!(replayed, recorded);
    }

    #[test]
    fn ethtool_glink_reads_and_writes_nested_output() {
        let recorded = EthtoolValue {
            cmd: ETHTOOL_GLINK,
            data: 1,
        };
        let mut recorded_ifreq = [0usize; 5];
        recorded_ifreq[2] = &recorded as *const EthtoolValue as usize;
        let request = Request::from_raw(0x8946, recorded_ifreq.as_mut_ptr() as usize);

        assert_eq!(std::mem::size_of::<EthtoolValue>(), 8);
        assert_eq!(
            request.read_output(&LocalMemory::new()),
            Ok(Some(Output::SIOCETHTOOL(EthtoolOutput::Glink(recorded))))
        );

        let mut replayed = EthtoolValue {
            cmd: ETHTOOL_GLINK,
            data: 0,
        };
        let mut replayed_ifreq = [0usize; 5];
        replayed_ifreq[2] = &mut replayed as *mut EthtoolValue as usize;
        let request = Request::from_raw(0x8946, replayed_ifreq.as_mut_ptr() as usize);
        request
            .write_output(
                &mut LocalMemory::new(),
                &Output::SIOCETHTOOL(EthtoolOutput::Glink(recorded)),
            )
            .unwrap();
        assert_eq!(replayed, recorded);
    }
}

/// The output after a successful call to `ioctl`. This is only relavent for
/// requests with outputs.
///
/// Note that this is a `union`. The descriminator is the [`Request`] type.
#[allow(missing_docs, non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Output {
    TCGETS(Termios),
    TIOCGWINSZ(Winsize),
    TIOCGPGRP(libc::pid_t),
    FIONREAD(libc::c_int),
    SIOCGIFINDEX(Ifreq),
    SIOCETHTOOL(EthtoolOutput),
    Other(Vec<u8>),
}

#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EthtoolOutput {
    Gset(EthtoolCmd),
    Glink(EthtoolValue),
}

/// The payload used by simple ethtool get/set commands.
#[allow(missing_docs)]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthtoolValue {
    pub cmd: u32,
    pub data: u32,
}

/// An interface request with a 24-byte data union on x86-64 Linux.
#[allow(missing_docs)]
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ifreq {
    pub name: [u8; IFNAMSIZ],
    pub data: [u8; 24],
}

/// The payload for the legacy `ETHTOOL_GSET` command.
#[allow(missing_docs)]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthtoolCmd {
    pub cmd: u32,
    pub supported: u32,
    pub advertising: u32,
    pub speed: u16,
    pub duplex: u8,
    pub port: u8,
    pub phy_address: u8,
    pub transceiver: u8,
    pub autoneg: u8,
    pub mdio_support: u8,
    pub maxtxpkt: u32,
    pub maxrxpkt: u32,
    pub speed_hi: u16,
    pub eth_tp_mdix: u8,
    pub eth_tp_mdix_ctrl: u8,
    pub lp_advertising: u32,
    pub reserved: [u32; 2],
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
