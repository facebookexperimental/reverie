/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use reverie_rpc::Channel;
use serde::Deserialize;
use serde::Serialize;
use syscalls::Errno;

use super::protected_files::protect_with;
use super::protected_files::ProtectedFd;

/// The file descriptor that our RPC socket connection should use. We use 100
/// here because many programs or tests expect to use the early file
/// descriptors. Using file descriptor 100 also makes this easier to debug.
const SOCKET_FD: i32 = 100;

struct Inner {
    stream: ProtectedFd<UnixStream>,
}

/// Implements a channel using a UNIX domain socket.
pub struct BaseChannel {
    inner: Mutex<Inner>,
}

impl BaseChannel {
    /// Connects to the global state RPC server.
    pub fn new() -> io::Result<Self> {
        // FIXME: We can't rely on this environment variable existing. Instead,
        // the host should use seccomp-unotify to listen for a special syscall
        // that returns a file descriptor to the socket connection.
        let sock_path = std::env::var_os("REVERIE_SOCK")
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "$REVERIE_SOCK does not exist!"))?;

        let stream = protect_with(|| -> Result<_, io::Error> {
            let sock = UnixStream::connect(sock_path)?;

            // Move the socket to our desired file descriptor and make sure it
            // gets closed when execve is called.
            let fd =
                Errno::result(unsafe { libc::dup3(sock.as_raw_fd(), SOCKET_FD, libc::O_CLOEXEC) })?;

            // Close the old socket file descriptor.
            drop(sock);

            Ok(unsafe { UnixStream::from_raw_fd(fd) })
        })?;

        Ok(Self {
            inner: Mutex::new(Inner { stream }),
        })
    }
}

impl Inner {
    fn try_send<T>(&mut self, item: &T) -> io::Result<()>
    where
        T: Serialize,
    {
        let mut buf = Vec::with_capacity(1024);

        reverie_rpc::encode(item, &mut buf)?;

        self.stream.as_mut().write_all(&buf)?;

        Ok(())
    }

    fn try_recv<T>(&mut self) -> io::Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        let mut buf = Vec::with_capacity(1024);
        reverie_rpc::decode_from(self.stream.as_mut(), &mut buf)
    }
}

impl<Req, Res> Channel<Req, Res> for BaseChannel
where
    Req: Serialize,
    Res: for<'a> Deserialize<'a>,
{
    fn send(&self, item: &Req) {
        let mut inner = self.inner.lock().unwrap();
        inner.try_send(item).expect("Failed to send RPC");
    }

    fn call(&self, item: &Req) -> Res {
        let mut inner = self.inner.lock().unwrap();
        inner.try_send(item).expect("Failed to send RPC");
        inner.try_recv().expect("Failed to recv RPC")
    }
}
