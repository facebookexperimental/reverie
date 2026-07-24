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
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::AcqRel;
use std::sync::atomic::Ordering::Acquire;
use std::sync::atomic::Ordering::Release;

use reverie_rpc::Channel;
use serde::Deserialize;
use serde::Serialize;
use syscalls::Errno;

use super::protected_files::ProtectedFd;
use super::protected_files::protect_with;

/// The file descriptor that our RPC socket connection should use. We use 100
/// here because many programs or tests expect to use the early file
/// descriptors. Using file descriptor 100 also makes this easier to debug.
const SOCKET_FD: i32 = 100;
static CHANNEL_FD: AtomicI32 = AtomicI32::new(-1);

struct Inner {
    stream: ProtectedFd<UnixStream>,
}

fn handoff_owner() -> io::Result<Option<i32>> {
    let flags = unsafe { libc::fcntl(SOCKET_FD, libc::F_GETFD) };
    if flags < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::EBADF) {
            Ok(None)
        } else {
            Err(error)
        };
    }

    let owner = unsafe { libc::fcntl(SOCKET_FD, libc::F_GETOWN) };
    if owner < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Some(owner))
    }
}

fn handoff_peer_path() -> io::Result<std::path::PathBuf> {
    let duplicate = unsafe { libc::fcntl(SOCKET_FD, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let inherited = unsafe { UnixStream::from_raw_fd(duplicate) };
    inherited
        .peer_addr()?
        .as_pathname()
        .ok_or_else(|| io::Error::other("inherited RPC socket has no peer path"))
        .map(std::path::Path::to_owned)
}

fn reserve_exec_handoff(stream: UnixStream) -> io::Result<UnixStream> {
    let handoff = if stream.as_raw_fd() == SOCKET_FD {
        stream
    } else {
        Errno::result(unsafe { libc::dup3(stream.as_raw_fd(), SOCKET_FD, 0) })?;
        drop(stream);
        unsafe { UnixStream::from_raw_fd(SOCKET_FD) }
    };

    let flags = unsafe { libc::fcntl(SOCKET_FD, libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(SOCKET_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(SOCKET_FD, libc::F_SETOWN, std::process::id() as i32) } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(handoff)
}

fn connect_stream(sock_path: Option<&std::ffi::OsStr>) -> io::Result<UnixStream> {
    let current_pid = std::process::id() as i32;
    let (stream, forked) = match handoff_owner()? {
        Some(owner) if owner == current_pid => match handoff_peer_path() {
            Ok(_) => (unsafe { UnixStream::from_raw_fd(SOCKET_FD) }, false),
            Err(error) => match sock_path {
                Some(path) => (UnixStream::connect(path)?, false),
                None => return Err(error),
            },
        },
        Some(_) => {
            let stream = match sock_path {
                Some(path) => UnixStream::connect(path)?,
                None => UnixStream::connect(handoff_peer_path()?)?,
            };
            (stream, true)
        }
        None => {
            let path =
                sock_path.ok_or_else(|| io::Error::other("$REVERIE_SOCK does not exist!"))?;
            (UnixStream::connect(path)?, false)
        }
    };
    if forked {
        let channel_fd = CHANNEL_FD.swap(-1, AcqRel);
        let owner = unsafe { libc::fcntl(channel_fd, libc::F_GETOWN) };
        if channel_fd >= 0 && owner >= 0 && owner != current_pid {
            unsafe { libc::close(channel_fd) };
        }
    }
    Ok(stream)
}

/// Implements a channel using a UNIX domain socket.
pub struct BaseChannel {
    inner: Mutex<Inner>,
}

impl Drop for BaseChannel {
    fn drop(&mut self) {
        let channel_fd = self.inner.get_mut().unwrap().stream.as_ref().as_raw_fd();
        let _ = CHANNEL_FD.compare_exchange(channel_fd, -1, AcqRel, Acquire);
    }
}

impl BaseChannel {
    /// Connects to the global state RPC server.
    pub fn new() -> io::Result<Self> {
        let sock_path = std::env::var_os("REVERIE_SOCK");
        let stream = connect_stream(sock_path.as_deref())?;
        let handoff = reserve_exec_handoff(stream)?;
        let channel = handoff.try_clone()?;
        let channel_fd = channel.as_raw_fd();
        let channel_flags = unsafe { libc::fcntl(channel_fd, libc::F_GETFD) };
        if channel_flags < 0
            || unsafe { libc::fcntl(channel_fd, libc::F_SETFD, channel_flags | libc::FD_CLOEXEC) }
                < 0
            || unsafe { libc::fcntl(channel_fd, libc::F_SETOWN, std::process::id() as i32) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        CHANNEL_FD.store(channel_fd, Release);

        // fd 100 is a process-lifetime exec handoff. The channel uses its own
        // close-on-exec duplicate, while this fixed descriptor is closed by
        // process exit or replaced after fork.
        let handoff = protect_with(|| Ok::<_, io::Error>(handoff))?;
        std::mem::forget(handoff);
        let stream = protect_with(|| Ok::<_, io::Error>(channel))?;

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

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn exec_adopts_but_fork_reconnects_handoff_socket() {
        let saved_fd = unsafe { libc::dup(SOCKET_FD) };
        let socket_path = std::env::temp_dir().join(format!(
            "reverie-sabre-rpc-{}-{}.sock",
            std::process::id(),
            saved_fd
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();

        let stream = UnixStream::connect(&socket_path).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let handoff = reserve_exec_handoff(stream).unwrap();
        assert_eq!(handoff.as_raw_fd(), SOCKET_FD);
        assert_eq!(
            unsafe { libc::fcntl(SOCKET_FD, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        std::mem::forget(handoff);

        let adopted = connect_stream(None).unwrap();
        assert_eq!(adopted.as_raw_fd(), SOCKET_FD);
        std::mem::forget(adopted);

        assert_eq!(
            unsafe { libc::fcntl(SOCKET_FD, libc::F_SETOWN, libc::getppid()) },
            0
        );
        let reconnected = connect_stream(None).unwrap();
        assert_ne!(reconnected.as_raw_fd(), SOCKET_FD);
        let (_fork_server, _) = listener.accept().unwrap();
        drop(reconnected);

        unsafe { libc::close(SOCKET_FD) };
        if saved_fd >= 0 {
            assert_eq!(unsafe { libc::dup2(saved_fd, SOCKET_FD) }, SOCKET_FD);
            unsafe { libc::close(saved_fd) };
        }
        drop(listener);
        std::fs::remove_file(socket_path).unwrap();
    }
}
