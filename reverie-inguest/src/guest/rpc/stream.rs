//! Byte-stream I/O for the existing shared blocking RPC owner.
//! Native initialization retains its exact scalar mechanism through installation.

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
#[cfg(feature = "exec-private-init")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
#[cfg(feature = "exec-private-init")]
use std::path::Path;

#[cfg(feature = "exec-private-init")]
use crate::guest::exec_private::NativeControl;
#[cfg(feature = "exec-private-init")]
use crate::guest::exec_private::NativeGateIoBinding;

/// One socket retained by the shared client; this adds no wire/admission owner.
pub enum GuestRpcStream {
    /// Existing ordinary socket semantics, including all EOF/error distinctions.
    Ordinary(UnixStream),
    /// Qualified physical native I/O; construction alone is not admission.
    #[cfg(feature = "exec-private-init")]
    Native(NativeGateStream),
}

impl From<UnixStream> for GuestRpcStream {
    fn from(stream: UnixStream) -> Self {
        Self::Ordinary(stream)
    }
}

impl GuestRpcStream {
    /// Connect using the inherited scalar gate without publishing its selector.
    /// The same socket must be consumed by the shared Initial/Successor factory.
    ///
    /// # Safety
    /// The actual controlled runner must exclusively own the qualified inherited
    /// page/filter, private Tool FS/stack and protected native control for the
    /// stream's entire lifetime. No Guest or worker may have run. Endpoint
    /// provenance and subsequent one-use admission remain the caller/server's
    /// duty; a packet/path never supplies that authority. The checked mechanism
    /// may not be substituted for `publish_authenticated_control` or a permit.
    #[cfg(feature = "exec-private-init")]
    pub unsafe fn connect_native(path: &Path, control: *mut NativeControl) -> io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { core::mem::zeroed() };
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
            *destination = *source as libc::c_char;
        }
        let binding = unsafe { NativeGateIoBinding::bind_bootstrap_io(control)? };
        let fd = {
            let scope = binding.scope();
            unsafe {
                scope.call(
                    libc::SYS_socket,
                    [
                        libc::AF_UNIX as u64,
                        (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64,
                        0,
                        0,
                        0,
                        0,
                    ],
                )
            }
        };
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(-fd as i32));
        }
        if fd > i64::from(i32::MAX) {
            binding.terminal();
        }
        let stream = NativeGateStream {
            fd: fd as i32,
            binding,
        };
        let length = core::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
        let result = {
            let scope = stream.binding.scope();
            unsafe {
                scope.call(
                    libc::SYS_connect,
                    [
                        stream.fd as u64,
                        (&raw const address) as u64,
                        length as u64,
                        0,
                        0,
                        0,
                    ],
                )
            }
        };
        if result != 0 {
            // No request byte was sent. Drop closes this exact owned fd once;
            // do not retry an interrupted/uncertain connect or send a ticket.
            return Err(if result < 0 {
                io::Error::from_raw_os_error(-result as i32)
            } else {
                io::Error::from(io::ErrorKind::InvalidData)
            });
        }
        Ok(Self::Native(stream))
    }
}

impl AsRawFd for GuestRpcStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Ordinary(stream) => stream.as_raw_fd(),
            #[cfg(feature = "exec-private-init")]
            Self::Native(stream) => stream.fd,
        }
    }
}

impl Read for GuestRpcStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Ordinary(stream) => stream.read(buffer),
            #[cfg(feature = "exec-private-init")]
            Self::Native(stream) => stream.read(buffer),
        }
    }
}

impl Write for GuestRpcStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Ordinary(stream) => stream.write(buffer),
            #[cfg(feature = "exec-private-init")]
            Self::Native(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Ordinary(stream) => stream.flush(),
            #[cfg(feature = "exec-private-init")]
            Self::Native(stream) => stream.flush(),
        }
    }
}

/// Opaque sole fd owner; only the qualified constructor can create this type.
/// No UnixStream/OwnedFd destructor can perform unqualified libc close.
#[cfg(feature = "exec-private-init")]
pub struct NativeGateStream {
    fd: i32,
    binding: NativeGateIoBinding,
}

#[cfg(feature = "exec-private-init")]
impl NativeGateStream {
    fn transfer(&self, pointer: u64, length: usize, sending: bool) -> io::Result<usize> {
        let scope = self.binding.scope();
        if length == 0 {
            return Ok(0);
        }
        let number = if sending {
            libc::SYS_sendto
        } else {
            libc::SYS_recvfrom
        };
        let result = unsafe {
            scope.call(
                number,
                [
                    self.fd as u64,
                    pointer,
                    length as u64,
                    if sending {
                        libc::MSG_NOSIGNAL as u64
                    } else {
                        0
                    },
                    0,
                    0,
                ],
            )
        };
        if result == -i64::from(libc::EINTR) {
            // Shared framing loops retry only the untransferred suffix. This
            // constructs an OS error without querying libc/TLS errno.
            return Err(io::Error::from_raw_os_error(libc::EINTR));
        }
        if result <= 0 || result as u64 > length as u64 {
            // EOF/hard failure must precede request/ACK Vec destruction in the
            // generic factory. A caller guard would run too late.
            self.binding.terminal();
        }
        Ok(result as usize)
    }
}

#[cfg(feature = "exec-private-init")]
impl Read for NativeGateStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.transfer(buffer.as_mut_ptr() as u64, buffer.len(), false)
    }
}

#[cfg(feature = "exec-private-init")]
impl Write for NativeGateStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.transfer(buffer.as_ptr() as u64, buffer.len(), true)
    }

    fn flush(&mut self) -> io::Result<()> {
        // The scope checks and its destructor use direct gate queries only.
        // No allocation or syscall through libc separates final write/read.
        let _scope = self.binding.scope();
        Ok(())
    }
}

#[cfg(feature = "exec-private-init")]
impl Drop for NativeGateStream {
    fn drop(&mut self) {
        let scope = self.binding.scope();
        let result = unsafe { scope.call(libc::SYS_close, [self.fd as u64, 0, 0, 0, 0, 0]) };
        if result != 0 {
            // Never retry close: the descriptor may already have been retired.
            self.binding.terminal();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_adapter_preserves_real_stream_partial_io_and_eof() {
        let (client, mut peer) = UnixStream::pair().unwrap();
        let fd = client.as_raw_fd();
        let mut stream = GuestRpcStream::from(client);
        assert_eq!(stream.as_raw_fd(), fd);
        assert!(matches!(&stream, GuestRpcStream::Ordinary(_)));
        peer.write_all(b"abc").unwrap();
        let mut first = [0; 2];
        assert_eq!(stream.read(&mut first).unwrap(), 2);
        assert_eq!(&first, b"ab");
        let mut second = [0; 4];
        assert_eq!(stream.read(&mut second).unwrap(), 1);
        assert_eq!(second[0], b'c');
        stream.write_all(b"reply").unwrap();
        let mut reply = [0; 5];
        peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
        stream.flush().unwrap();
        drop(peer);
        assert_eq!(stream.read(&mut second).unwrap(), 0);
        assert_eq!(stream.read(&mut []).unwrap(), 0);
    }
}
