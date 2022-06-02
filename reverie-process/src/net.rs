/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::fd::Fd;

use std::ffi::CStr;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;

use syscalls::Errno;

/// Interface name.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct IfName([u8; libc::IFNAMSIZ]);

/// A network interface request.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct IfReq<T> {
    /// The interface name.
    name: IfName,

    /// The request type.
    ///
    /// NOTE: The kernel's `if_req` struct is made up of a `union` of all
    /// possible request types. Thus, the size of `if_req` is not necessarily the
    /// same as the size of `IfReq<T>`. However, there is no danger of a buffer
    /// overrun, since the kernel does not write to the unused parts of the union
    /// when handling the associated ioctls.
    req: T,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ifmap {
    pub mem_start: usize,
    pub mem_end: usize,
    pub base_addr: u16,
    pub irq: u8,
    pub dma: u8,
    pub port: u8,
    /* 3 bytes spare */
}

impl IfName {
    // Many unused functions here. The full set of ioctl's are implemented for
    // `if_req`, but we don't need them yet.
    #![allow(unused)]

    /// The name of the loopback interface.
    pub const LOOPBACK: Self = Self(*b"lo\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

    pub fn new<S: AsRef<OsStr>>(name: S) -> Result<Self, InterfaceNameTooLong> {
        use std::os::unix::ffi::OsStrExt;

        let name = name.as_ref().as_bytes();

        if name.len() + 1 > libc::IFNAMSIZ {
            Err(InterfaceNameTooLong)
        } else {
            let mut arr = [0u8; libc::IFNAMSIZ];
            arr[..name.len()].copy_from_slice(name);
            arr[name.len()] = 0;
            Ok(Self(arr))
        }
    }

    fn ioctl_get<T>(self, ioctl: libc::c_ulong, socket: &Fd) -> Result<T, Errno> {
        let mut req = IfReq::new(self, MaybeUninit::uninit());
        Errno::result(unsafe { libc::ioctl(socket.as_raw_fd(), ioctl, &mut req as *mut _) })?;
        Ok(unsafe { req.into_req().assume_init() })
    }

    fn ioctl_set<T>(self, ioctl: libc::c_ulong, socket: &Fd, value: T) -> Result<(), Errno> {
        let req = IfReq::new(self, value);
        Errno::result(unsafe { libc::ioctl(socket.as_raw_fd(), ioctl, &req as *const _) })?;
        Ok(())
    }

    pub fn get_addr(&self, socket: &Fd) -> Result<libc::sockaddr, Errno> {
        self.ioctl_get(libc::SIOCGIFADDR, socket)
    }

    pub fn set_addr(&self, socket: &Fd, addr: libc::sockaddr) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFADDR, socket, addr)
    }

    pub fn get_dest_addr(&self, socket: &Fd) -> Result<libc::sockaddr, Errno> {
        self.ioctl_get(libc::SIOCGIFDSTADDR, socket)
    }

    pub fn set_dest_addr(&self, socket: &Fd, addr: libc::sockaddr) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFDSTADDR, socket, addr)
    }

    pub fn get_broadcast_addr(&self, socket: &Fd) -> Result<libc::sockaddr, Errno> {
        self.ioctl_get(libc::SIOCGIFBRDADDR, socket)
    }

    pub fn set_broadcast_addr(&self, socket: &Fd, addr: libc::sockaddr) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFBRDADDR, socket, addr)
    }

    pub fn get_netmask(&self, socket: &Fd) -> Result<libc::sockaddr, Errno> {
        self.ioctl_get(libc::SIOCGIFNETMASK, socket)
    }

    pub fn set_netmask(&self, socket: &Fd, addr: libc::sockaddr) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFNETMASK, socket, addr)
    }

    pub fn get_hw_addr(&self, socket: &Fd) -> Result<libc::sockaddr, Errno> {
        self.ioctl_get(libc::SIOCGIFHWADDR, socket)
    }

    pub fn set_hw_addr(&self, socket: &Fd, addr: libc::sockaddr) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFHWADDR, socket, addr)
    }

    pub fn get_flags(&self, socket: &Fd) -> Result<i16, Errno> {
        self.ioctl_get(libc::SIOCGIFFLAGS, socket)
    }

    pub fn set_flags(&self, socket: &Fd, flags: i16) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFFLAGS, socket, flags)
    }

    pub fn get_metric(&self, socket: &Fd) -> Result<i32, Errno> {
        self.ioctl_get(libc::SIOCGIFMETRIC, socket)
    }

    pub fn set_metric(&self, socket: &Fd, value: i32) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFMETRIC, socket, value)
    }

    pub fn get_mtu(&self, socket: &Fd) -> Result<i32, Errno> {
        self.ioctl_get(libc::SIOCGIFMTU, socket)
    }

    pub fn set_mtu(&self, socket: &Fd, value: i32) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFMTU, socket, value)
    }

    /// Gets the device map.
    pub fn get_map(&self, socket: &Fd) -> Result<ifmap, Errno> {
        self.ioctl_get(libc::SIOCGIFMAP, socket)
    }

    /// Sets the device map.
    pub fn set_map(&self, socket: &Fd, map: ifmap) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFMAP, socket, map)
    }

    /// Gets the slave device.
    pub fn get_slave(&self, socket: &Fd) -> Result<Self, Errno> {
        self.ioctl_get(libc::SIOCGIFSLAVE, socket)
    }

    /// Sets the slave device.
    pub fn set_slave(&self, socket: &Fd, name: Self) -> Result<(), Errno> {
        self.ioctl_set(libc::SIOCSIFSLAVE, socket, name)
    }
}

impl AsRef<CStr> for IfName {
    fn as_ref(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.as_ptr() as *const _) }
    }
}

/// An error indicating that the interface name is too long.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InterfaceNameTooLong;

impl<T> IfReq<T> {
    /// Creates a new interface request.
    pub fn new(name: IfName, req: T) -> Self {
        Self { name, req }
    }

    pub fn into_req(self) -> T {
        self.req
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::net::if_::InterfaceFlags;

    #[test]
    fn ifname() {
        assert_eq!(IfName::new("lo"), Ok(IfName::LOOPBACK));
        assert_eq!(
            IfName::new("too loooooooooooooooong"),
            Err(InterfaceNameTooLong)
        );
    }

    #[test]
    fn smoke_tests() {
        let sock = Fd::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP).unwrap();

        let lo = IfName::LOOPBACK;

        let addr = lo.get_addr(&sock).unwrap();
        assert_eq!(addr.sa_family as i32, libc::AF_INET);

        let flags = InterfaceFlags::from_bits_truncate(lo.get_flags(&sock).unwrap() as i32);
        assert!(flags.contains(InterfaceFlags::IFF_LOOPBACK));
    }
}
