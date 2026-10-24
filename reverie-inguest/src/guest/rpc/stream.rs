//! Byte-stream I/O for the existing shared blocking RPC owner.
//! Native initialization retains its exact scalar mechanism through installation.

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
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
use crate::guest::support::raw_result;
use crate::guest::support::tool_callback_active;
use crate::trap::raw_syscall6;

/// Move an owned ordinary coordinator socket above the guest's low descriptors.
///
/// This preserves the same open-file description and connection, setting
/// close-on-exec on its new descriptor. It neither connects nor authenticates a
/// client and does not reserve a protection slot. Call before publishing the
/// coordinator descriptor or wrapping it in an authenticated client. Success
/// drops the original owner exactly once; failure drops it and returns the
/// actual duplication error. Native inherited-gate streams do not use this.
pub fn move_ordinary_coordinator_stream(stream: UnixStream) -> io::Result<UnixStream> {
    // Explicit InitialImage placement; the ordinary connection does not opt in.
    // An occupied high descriptor is skipped, never overwritten.
    let reserved_fd = raw_result(unsafe {
        raw_syscall6(
            libc::SYS_fcntl,
            [
                stream.as_raw_fd() as u64,
                libc::F_DUPFD_CLOEXEC as u64,
                1024,
                0,
                0,
                0,
            ],
        )
    })? as libc::c_int;
    // SAFETY: successful fcntl returned a fresh descriptor owned only here.
    let reserved_stream = unsafe { UnixStream::from_raw_fd(reserved_fd) };
    drop(stream);
    Ok(reserved_stream)
}

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
            Self::Ordinary(stream) if tool_callback_active() => {
                // SAFETY: this is the runtime-owned socket and a live borrowed
                // buffer during a real Tool callback. Use its private gate so
                // the runtime's own I/O does not recursively raise SIGSYS.
                // Preserve one kernel attempt even for an empty buffer.
                let result = unsafe {
                    raw_syscall6(
                        libc::SYS_recvfrom,
                        [
                            stream.as_raw_fd() as u64,
                            buffer.as_mut_ptr() as u64,
                            buffer.len() as u64,
                            0,
                            0,
                            0,
                        ],
                    )
                };
                raw_result(result).map(|count| count as usize)
            }
            Self::Ordinary(stream) => stream.read(buffer),
            #[cfg(feature = "exec-private-init")]
            Self::Native(stream) => stream.read(buffer),
        }
    }
}

impl Write for GuestRpcStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Ordinary(stream) if tool_callback_active() => {
                // SAFETY: the owned socket and borrowed bytes stay live for
                // this synchronous Tool call. Match UnixStream's MSG_NOSIGNAL
                // and short/error results; the shared framing owns retries.
                let result = unsafe {
                    raw_syscall6(
                        libc::SYS_sendto,
                        [
                            stream.as_raw_fd() as u64,
                            buffer.as_ptr() as u64,
                            buffer.len() as u64,
                            libc::MSG_NOSIGNAL as u64,
                            0,
                            0,
                        ],
                    )
                };
                raw_result(result).map(|count| count as usize)
            }
            // Outside a callback, libc must still reach guest interception:
            // a guest cannot use the installed accessor's protected socket.
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

    // Each exact test runs alone in a subprocess: descriptor-number and rlimit
    // checks must not race other tests opening descriptors in the same process.
    fn isolated_coordinator_move_test(name: &str, body: impl FnOnce()) {
        const CHILD: &str = "REVERIE_ORDINARY_COORDINATOR_MOVE_TEST";
        if std::env::var(CHILD).ok().as_deref() == Some(name) {
            body();
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name])
            .env(CHILD, name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                assert!(
                    status.success(),
                    "{status}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .any(|line| line == format!("test {name} ... ok")),
                    "selected relocation control did not execute: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
                return;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let status = child.wait().unwrap();
                panic!("coordinator relocation control exceeded its bound: {status}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[derive(Default)]
    struct OrdinaryConnectionModel;

    #[reverie::tool]
    impl reverie::GlobalTool for OrdinaryConnectionModel {
        type Request = u64;
        type Response = u64;
        type Config = u64;

        async fn receive_rpc(&self, _: reverie::Pid, request: u64) -> u64 {
            request
        }
    }

    #[test]
    fn ordinary_coordinator_connect_and_rpc_do_not_require_high_descriptors() {
        isolated_coordinator_move_test(
            "guest::rpc::stream::tests::ordinary_coordinator_connect_and_rpc_do_not_require_high_descriptors",
            || {
                use std::os::unix::net::UnixListener;
                use std::time::Duration;

                use reverie::GlobalRPC;
                use reverie_rpc_transport::RequestEnvelope;
                use reverie_rpc_transport::codec::encode;

                // The production connection must work below the opt-in move's
                // minimum. The existing high-FD move error control separately
                // requires the real EINVAL under this same soft limit.
                let mut original = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: only this isolated subprocess changes its soft limit.
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut original) },
                    0
                );
                assert!(original.rlim_max >= 1024);
                let restricted = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: original.rlim_max,
                };
                assert_eq!(
                    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &restricted) },
                    0
                );
                let mut actual = original;
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut actual) },
                    0
                );
                assert_eq!(actual.rlim_cur, 1024);
                assert_eq!(actual.rlim_max, original.rlim_max);

                let directory =
                    std::env::temp_dir().join(format!("ordinary-rpc-lowfd-{}", std::process::id()));
                std::fs::create_dir(&directory).unwrap();
                let directory_owner = std::fs::File::open(&directory).unwrap();
                // Keep the socket inside the caller's TMPDIR even when its
                // literal pathname exceeds sockaddr_un's bounded sun_path.
                let path = std::path::PathBuf::from(format!(
                    "/proc/self/fd/{}/socket",
                    directory_owner.as_raw_fd()
                ));
                let listener = UnixListener::bind(&path).unwrap();
                // SAFETY: gettid reads the actual test thread identity.
                let tid = reverie::Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
                let peer = std::thread::spawn(move || {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let config = encode(&73_u64).unwrap();
                    socket
                        .write_all(&(config.len() as u32).to_be_bytes())
                        .unwrap();
                    socket.write_all(&config).unwrap();
                    let expected = encode(&RequestEnvelope {
                        from: tid,
                        request: 19_u64,
                    })
                    .unwrap();
                    let mut prefix = [0; 4];
                    socket.read_exact(&mut prefix).unwrap();
                    assert_eq!(u32::from_be_bytes(prefix) as usize, expected.len());
                    let mut request = vec![0; expected.len()];
                    socket.read_exact(&mut request).unwrap();
                    assert_eq!(request, expected);
                    let response = encode(&91_u64).unwrap();
                    socket
                        .write_all(&(response.len() as u32).to_be_bytes())
                        .unwrap();
                    socket.write_all(&response).unwrap();
                    assert_eq!(socket.read(&mut [0]).unwrap(), 0);
                });
                let rpc = crate::guest::rpc::CoordinatorRpc::<OrdinaryConnectionModel>::connect(
                    &path,
                    |_, _| panic!("ordinary connection unexpectedly reconnected"),
                )
                .unwrap();
                assert!((0..1024).contains(&rpc.raw_fd()));
                assert_eq!(*rpc.config(), 73);
                assert_eq!(rpc.send_blocking_unless_in_flight(19).unwrap(), 91);
                drop(rpc);
                peer.join().unwrap();
                std::fs::remove_file(directory.join("socket")).unwrap();
                drop(directory_owner);
                std::fs::remove_dir(&directory).unwrap();
                assert_eq!(
                    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) },
                    0
                );
            },
        );
    }

    #[test]
    fn ordinary_coordinator_move_preserves_ofd_peer_and_closes_original() {
        isolated_coordinator_move_test(
            "guest::rpc::stream::tests::ordinary_coordinator_move_preserves_ofd_peer_and_closes_original",
            || {
                let (original, mut peer) = UnixStream::pair().unwrap();
                let alias = original.try_clone().unwrap();
                let low = original.as_raw_fd();
                assert!(low < 1024);
                let mut moved = move_ordinary_coordinator_stream(original).unwrap();
                assert!(moved.as_raw_fd() >= 1024);
                // SAFETY: queries do not acquire or close descriptor ownership.
                assert_eq!(
                    unsafe {
                        raw_syscall6(
                            libc::SYS_fcntl,
                            [low as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
                        )
                    },
                    -i64::from(libc::EBADF)
                );
                // CLOEXEC belongs to the new descriptor; O_NONBLOCK belongs to
                // the OFD and therefore changes on the retained alias too.
                assert_ne!(
                    unsafe {
                        raw_syscall6(
                            libc::SYS_fcntl,
                            [moved.as_raw_fd() as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
                        )
                    } & i64::from(libc::FD_CLOEXEC),
                    0
                );
                alias.set_nonblocking(true).unwrap();
                assert_ne!(
                    unsafe {
                        raw_syscall6(
                            libc::SYS_fcntl,
                            [moved.as_raw_fd() as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
                        )
                    } & i64::from(libc::O_NONBLOCK),
                    0
                );
                moved.set_nonblocking(false).unwrap();
                moved.write_all(b"same socket").unwrap();
                let mut bytes = [0; 11];
                peer.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"same socket");
                peer.write_all(b"reply").unwrap();
                let mut reply = [0; 5];
                moved.read_exact(&mut reply).unwrap();
                assert_eq!(&reply, b"reply");
                drop(alias);
                drop(moved);
                assert_eq!(peer.read(&mut reply).unwrap(), 0);
            },
        );
    }

    #[test]
    fn ordinary_coordinator_move_skips_occupied_high_descriptor() {
        isolated_coordinator_move_test(
            "guest::rpc::stream::tests::ordinary_coordinator_move_skips_occupied_high_descriptor",
            || {
                let (first, mut first_peer) = UnixStream::pair().unwrap();
                let mut first = move_ordinary_coordinator_stream(first).unwrap();
                let occupied = first.as_raw_fd();
                let (second, mut second_peer) = UnixStream::pair().unwrap();
                let mut second = move_ordinary_coordinator_stream(second).unwrap();
                assert!(second.as_raw_fd() > occupied);
                first.write_all(b"a").unwrap();
                second.write_all(b"b").unwrap();
                let mut byte = [0];
                first_peer.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [b'a']);
                second_peer.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [b'b']);
                assert_eq!(first.as_raw_fd(), occupied);
            },
        );
    }

    #[test]
    fn ordinary_coordinator_move_returns_real_duplication_error_and_cleans_owner() {
        isolated_coordinator_move_test(
            "guest::rpc::stream::tests::ordinary_coordinator_move_returns_real_duplication_error_and_cleans_owner",
            || {
                let (original, mut peer) = UnixStream::pair().unwrap();
                let low = original.as_raw_fd();
                let mut limits = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: this isolated process owns the soft limit change;
                // both structures are live and the hard limit is unchanged.
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limits) },
                    0
                );
                let restricted = libc::rlimit {
                    rlim_cur: limits.rlim_cur.min(1024),
                    rlim_max: limits.rlim_max,
                };
                assert_eq!(
                    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &restricted) },
                    0
                );
                let result = move_ordinary_coordinator_stream(original);
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
                // Linux rejects an F_DUPFD minimum at/above RLIMIT_NOFILE.
                assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EINVAL));
                assert_eq!(
                    unsafe {
                        raw_syscall6(
                            libc::SYS_fcntl,
                            [low as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
                        )
                    },
                    -i64::from(libc::EBADF)
                );
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).unwrap(), 0);
            },
        );
    }

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

    /// This guard exercises return/error semantics only. The installed
    /// lifecycle fixture separately proves actual callback provenance and
    /// the presence or absence of SIGSYS with the real filter installed.
    fn callback_io<T>(operation: impl FnOnce() -> T) -> T {
        let _callback = crate::guest::support::ToolCallbackGuard::enter();
        operation()
    }

    #[test]
    fn callback_socket_keeps_short_io_empty_calls_and_kernel_errors() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        let fd = socket.as_raw_fd();
        let mut adapter = GuestRpcStream::from(socket);
        assert_eq!(adapter.as_raw_fd(), fd);

        // recvfrom with length zero still reaches the kernel: without input,
        // Linux reports EAGAIN on a nonblocking stream instead of success.
        let empty = callback_io(|| adapter.read(&mut []));
        assert_eq!(empty.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(callback_io(|| adapter.write(&[])).unwrap(), 0);
        peer.write_all(b"abc").unwrap();
        let mut bytes = [0; 8];
        assert_eq!(callback_io(|| adapter.read(&mut [])).unwrap(), 0);
        assert_eq!(callback_io(|| adapter.read(&mut bytes[..2])).unwrap(), 2);
        assert_eq!(&bytes[..2], b"ab");
        assert_eq!(callback_io(|| adapter.read(&mut bytes)).unwrap(), 1);
        assert_eq!(bytes[0], b'c');
        assert_eq!(
            callback_io(|| adapter.read(&mut bytes))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EAGAIN),
        );
        assert_eq!(callback_io(|| adapter.write(b"reply")).unwrap(), 5);
        let mut reply = [0; 5];
        peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
        callback_io(|| adapter.flush()).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(callback_io(|| adapter.read(&mut bytes)).unwrap(), 0);
        drop(peer);
        assert_eq!(
            callback_io(|| adapter.write(&[]))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPIPE),
        );
        assert_eq!(
            callback_io(|| adapter.write(b"x"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPIPE),
        );
        assert_eq!(adapter.as_raw_fd(), fd);
    }

    #[test]
    fn callback_socket_returns_short_writes_without_retrying() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        let buffer_size: libc::c_int = 4096;
        // SAFETY: live socket, valid value and its exact length.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const buffer_size).cast(),
                    core::mem::size_of_val(&buffer_size) as _,
                )
            },
            0
        );
        let mut adapter = GuestRpcStream::from(socket);
        let payload = [42; 65536];
        let written = callback_io(|| adapter.write(&payload)).unwrap();
        assert!(written > 0 && written < payload.len(), "{written}");
        assert_eq!(
            callback_io(|| adapter.write(&payload))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EAGAIN),
        );
        let mut received = vec![0; written];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(&received, &payload[..written]);
    }

    #[test]
    fn callback_socket_does_not_raise_sigpipe() {
        const CHILD: &str = "REVERIE_RPC_SOCKET_SIGPIPE_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // This is an isolated child, not the multi-threaded test runner.
            // SAFETY: setting SIG_DFL does not install a Rust signal handler.
            assert_ne!(
                unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) },
                libc::SIG_ERR
            );
            let (socket, peer) = UnixStream::pair().unwrap();
            let mut adapter = GuestRpcStream::from(socket);
            drop(peer);
            assert_eq!(
                callback_io(|| adapter.write(b"x"))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPIPE),
            );
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "guest::rpc::stream::tests::callback_socket_does_not_raise_sigpipe",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{status}");
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let status = child.wait().unwrap();
                panic!("SIGPIPE control exceeded its bound: {status}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
