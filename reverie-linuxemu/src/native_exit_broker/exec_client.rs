//! Trusted launcher export/adoption. The environment only locates a descriptor;
//! the dedicated registered channel and single-use nonce establish the session.
//! These blocking setup methods must run before guest admission, never in Tool
//! cleanup. They do not bootstrap a broker in the child or transfer reap owner.

use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use super::BrokerClient;
use super::BrokerIdentity;
use super::BrokerOwner;
use super::CoreError;
use super::raw;
use super::socket_pair;

pub struct ExecClientFailure {
    pub cause: CoreError,
    pub channel: Option<OwnedFd>,
    pub retained_rights: Vec<OwnedFd>,
}

impl From<CoreError> for ExecClientFailure {
    fn from(cause: CoreError) -> Self {
        Self {
            cause,
            channel: None,
            retained_rights: Vec::new(),
        }
    }
}

pub struct ExecBrokerClient {
    channel: OwnedFd,
    nonce: [u8; 32],
}

impl ExecBrokerClient {
    pub fn into_parts(self) -> (OwnedFd, [u8; 32]) {
        (self.channel, self.nonce)
    }
}

impl BrokerOwner {
    pub fn export_client_for_exec(&self) -> Result<ExecBrokerClient, ExecClientFailure> {
        self.check_owner()?;
        let (channel, server) = socket_pair()?;
        let (reply, server_reply) = socket_pair()?;
        let mut nonce = [0u8; 32];
        let mut position = 0;
        while position < nonce.len() {
            let rc = unsafe {
                raw::syscall(
                    libc::SYS_getrandom,
                    nonce[position..].as_mut_ptr() as usize,
                    nonce.len() - position,
                    0,
                    0,
                    0,
                    0,
                )
            };
            if rc == -(libc::EINTR as isize) {
                continue;
            }
            if rc <= 0 {
                return Err(CoreError {
                    operation: "export session entropy",
                    errno: if rc == 0 { libc::EIO } else { -rc as i32 },
                }
                .into());
            }
            position += rc as usize;
        }
        let frame = raw::Frame::with_nonce(raw::EXPORT_CLIENT, nonce);
        let rights = [server.as_raw_fd(), server_reply.as_raw_fd()];
        loop {
            let rc = unsafe {
                raw::send_frame(
                    self.client.control.as_raw_fd(),
                    &frame,
                    rights.as_ptr(),
                    rights.len(),
                    false,
                )
            };
            if rc == -libc::EINTR {
                continue;
            }
            if rc != 0 {
                return Err(CoreError {
                    operation: "register exec session",
                    errno: -rc,
                }
                .into());
            }
            break;
        }
        // Only our newly-created internal channel duplicates, never guest fds.
        drop(server);
        drop(server_reply);
        let ack = match receive_internal(reply.as_raw_fd()) {
            Ok(frame) => frame,
            Err((cause, retained_rights)) => {
                return Err(ExecClientFailure {
                    cause,
                    channel: Some(reply),
                    retained_rights,
                });
            }
        };
        if ack.kind == raw::ERROR && ack.status > 0 && ack.status <= 4095 {
            return Err(CoreError {
                operation: "register exec session",
                errno: ack.status as i32,
            }
            .into());
        }
        if ack.kind != raw::EXPORT_READY || ack.nonce() != nonce {
            return Err(CoreError::protocol("exec export registration receipt").into());
        }
        Ok(ExecBrokerClient { channel, nonce })
    }
}

impl BrokerClient {
    /// The caller owns this descriptor through the trusted launch handoff. A
    /// mere numeric environment value is not an ownership constructor. On any
    /// failure the exact owner is returned; no unknown socket is dropped here.
    /// The reap owner remains in the original launcher and never crosses exec.
    pub fn adopt_exec_channel(
        channel: OwnedFd,
        nonce: [u8; 32],
    ) -> Result<Self, ExecClientFailure> {
        let mut retained_rights = Vec::with_capacity(raw::MAX_RIGHTS);
        match authenticate(&channel, nonce, &mut retained_rights) {
            Ok(identity) => Ok(Self {
                control: Arc::new(channel),
                process: unsafe { libc::getpid() },
                identity: Some(Arc::new(identity)),
            }),
            Err(cause) => Err(ExecClientFailure {
                cause,
                channel: Some(channel),
                retained_rights,
            }),
        }
    }
}

fn authenticate(
    channel: &OwnedFd,
    nonce: [u8; 32],
    retained: &mut Vec<OwnedFd>,
) -> Result<BrokerIdentity, CoreError> {
    let fd = channel.as_raw_fd();
    for (option, expected) in [
        (libc::SO_TYPE, libc::SOCK_SEQPACKET),
        (libc::SO_DOMAIN, libc::AF_UNIX),
    ] {
        let mut value = 0i32;
        let mut size = size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut i32).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(CoreError::last("exec client channel class"));
        }
        if size as usize != size_of::<i32>() || value != expected {
            return Err(CoreError::protocol("exec client channel class"));
        }
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(CoreError::last("exec client fd flags"));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(CoreError::last("exec client CLOEXEC restoration"));
    }
    // Never disclose the expected secret to an unauthenticated endpoint. The
    // registered broker must prove its prior nonce before the child accepts.
    let frame = raw::Frame::new(raw::ADOPT_CLIENT, 0, 0, 0);
    loop {
        let rc = unsafe { raw::send_frame(fd, &frame, std::ptr::null(), 0, false) };
        if rc == -libc::EINTR {
            continue;
        }
        if rc != 0 {
            return Err(CoreError {
                operation: "exec client authenticate",
                errno: -rc,
            });
        }
        break;
    }
    let reply = match receive_internal(fd) {
        Ok(frame) => frame,
        Err((cause, mut rights)) => {
            retained.append(&mut rights);
            return Err(cause);
        }
    };
    if reply.kind != raw::ADOPTED_CLIENT || reply.nonce() != nonce {
        return Err(CoreError::protocol("exec client authentication receipt"));
    }
    // This next frame is in the already authenticated, single-use session.
    // The native daemon opened this pidfd on itself and supplies its exact PID;
    // no environment integer or numeric PID reopen can substitute for it.
    let (identity, mut rights) = match receive_packet(fd) {
        Ok(packet) => packet,
        Err((cause, mut rights)) => {
            retained.append(&mut rights);
            return Err(cause);
        }
    };
    let pid = i32::try_from(identity.job).ok().filter(|pid| *pid > 0);
    if identity.kind != raw::BROKER_IDENTITY
        || identity.sequence != 0
        || identity.count != 1
        || identity.status != 0
        || rights.len() != 1
        || pid.is_none()
    {
        retained.append(&mut rights);
        return Err(CoreError::protocol("authenticated broker identity receipt"));
    }
    let pidfd = rights
        .pop()
        .expect("exactly one authenticated identity right");
    Ok(BrokerIdentity {
        pid: pid.expect("positive authenticated PID"),
        pidfd: Arc::new(pidfd),
    })
}

fn receive_internal(fd: i32) -> Result<raw::Frame, (CoreError, Vec<OwnedFd>)> {
    let (frame, retained) = receive_packet(fd)?;
    if !retained.is_empty() {
        return Err((
            CoreError::protocol("unexpected exec-session reply rights (owned)"),
            retained,
        ));
    }
    Ok(frame)
}

fn receive_packet(fd: i32) -> Result<(raw::Frame, Vec<OwnedFd>), (CoreError, Vec<OwnedFd>)> {
    let mut retained = Vec::with_capacity(raw::MAX_RIGHTS);
    let mut frame = raw::Frame::new(0, 0, 0, 0);
    let mut rights = [-1; raw::MAX_RIGHTS];
    let mut received = 0;
    let rc = loop {
        let rc = unsafe {
            raw::receive_frame(
                fd,
                &mut frame,
                rights.as_mut_ptr(),
                raw::MAX_RIGHTS,
                &mut received,
                false,
            )
        };
        if rc != -libc::EINTR {
            break rc;
        }
    };
    for fd in rights[..received].iter().copied() {
        retained.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    if rc > 0 {
        return Err((
            CoreError::protocol("incomplete exec-session reply rights (owned)"),
            retained,
        ));
    }
    if rc < 0 {
        return Err((
            CoreError {
                operation: "exec session reply",
                errno: -rc,
            },
            retained,
        ));
    }
    Ok((frame, retained))
}

impl std::fmt::Debug for ExecClientFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("ExecClientFailure")
            .field("cause", &self.cause)
            .field("channel", &self.channel.as_ref().map(AsRawFd::as_raw_fd))
            .field("retained_rights", &self.retained_rights.len())
            .finish()
    }
}
