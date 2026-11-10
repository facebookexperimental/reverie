/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The shadow sockets that show the readiness of pidfds for other guest
//! processes (gVisor: pkg/sentry/kernel/pidfd.go, whose pidfd reports itself
//! readable once its thread group has exited).
//!
//! In the guest's descriptor table, the supervisor's own pidfd stands in for
//! a pidfd for another guest process (`crate::executor::pidfd_open`), so the
//! kernel answers every call that it answers alike for any pidfd: read,
//! write, `F_GETFL`, the `/proc/self/fd` link and its refused reopen. What the
//! stand-in cannot show is the other process's life: the supervisor outlives
//! every guest process. Linux's `pidfd_poll` (fs/pidfs.c) reports
//! `EPOLLIN | EPOLLRDNORM` once the process has exited, adds `EPOLLHUP` once
//! it has been reaped, and never reports anything else. So each such pidfd
//! has a private connected pair of Unix stream sockets. One socket, the
//! shadow, reports `POLLIN | POLLRDNORM` once the other has sent it one
//! byte, and `POLLHUP` as well once the other has been shut down; poll,
//! select and epoll watch it in the stand-in's place, asking it only for
//! `POLLIN | POLLRDNORM` (`crate::executor::ForeignPidfd`), since a socket
//! also reports that it is writable and, once shut down, `POLLRDHUP`. The
//! registry keeps the other socket, the write end, with the process it
//! shows: it sends the byte once the process has exited and shuts the write
//! end down once the process has been reaped.
//!
//! A shutdown, unlike the close of a pipe's write end, acts on the socket
//! itself, so the hangup shows at the reap even while another copy of the
//! write end's descriptor is open: one that a fork of the supervisor's
//! process took, before the child's exec closes it, holds a pipe's hangup
//! back, but not a socket's.
//!
//! The sockets are the supervisor's alone. Neither is ever in a guest's
//! descriptor table, and both are close-on-exec and above the standard
//! descriptors. Every descriptor of the pidfd holds the shadow, so the shadow
//! closes with the pidfd's last descriptor, which also ends any epoll
//! registration of the pidfd, as Linux ends one when the pidfd's open file
//! description is released. The write end closes when the process is reaped,
//! or once the shadow is gone.
//!
//! The registry decides what each shadow shows under the family lock, from
//! the family's own record of each exit (`ProcessFamilyState::terminal`) and
//! of each wait (`ProcessFamilyState::wait_publications`). The sends,
//! shutdowns and closes that decision calls for run after the lock is
//! released, as every host close of the registry does. Each change of those
//! records ends with `ProcessSignalRegistry::sync_pidfd_shadows`, so a shadow
//! shows an exit before the exiting process's Tool callback runs, which is
//! before any other task can learn of the exit from the Tool.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::sync::Weak;

use reverie::SignalProcessId;

use super::ProcessFamilyExit;
use super::ProcessFamilyState;
use super::ProcessKey;
use super::ProcessSignalRegistry;
use super::WaitPhase;
use super::process_identity;
use super::process_key;

/// What a pidfd shows of the process it names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PidfdTargetState {
    /// The process has not exited: no readiness.
    Running,
    /// The process has exited and has not been reaped:
    /// `EPOLLIN | EPOLLRDNORM`.
    Exited,
    /// The process has been reaped: `EPOLLIN | EPOLLRDNORM | EPOLLHUP`.
    Reaped,
}

/// The write ends of the shadow sockets of the pidfds for one process.
#[derive(Debug, Default)]
pub(super) struct PidfdShadowWriters(Vec<ShadowWriter>);

#[derive(Debug)]
struct ShadowWriter {
    /// The shadow, which every descriptor of the pidfd holds.
    reader: Weak<File>,
    writer: Arc<File>,
    /// Whether the shadow has its byte: it was sent one once the process had
    /// exited.
    written: bool,
}

/// What the registry decided for the shadows, done once the family lock is
/// released.
#[must_use]
pub(super) struct ShadowActions {
    /// Each write end to send its shadow the byte, with the shadow, held so
    /// that the send has a receiver.
    writes: Vec<(Arc<File>, Arc<File>)>,
    /// Write ends to shut down and close.
    closes: Vec<Arc<File>>,
}

impl ShadowActions {
    fn perform(self) {
        for (reader, writer) in self.writes {
            let byte = 1_u8;
            loop {
                // SAFETY: writer owns a live descriptor, and the byte is one
                // byte of readable memory.
                let sent = unsafe {
                    libc::send(
                        writer.as_raw_fd(),
                        std::ptr::from_ref(&byte).cast(),
                        1,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if sent < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                // A connected socket with nothing queued takes one byte
                // without waiting.
                debug_assert_eq!(sent, 1, "pidfd shadow socket refused its byte");
                break;
            }
            drop(reader);
        }
        for writer in self.closes {
            // The shutdown hangs the shadow up whatever other copies of this
            // descriptor exist (see the module documentation).
            // SAFETY: writer owns a live descriptor.
            let shut = unsafe { libc::shutdown(writer.as_raw_fd(), libc::SHUT_RDWR) };
            debug_assert!(
                shut == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTCONN),
                "pidfd shadow socket refused its shutdown"
            );
        }
    }
}

impl ProcessFamilyState {
    /// What a pidfd for the process `key` shows, from the family's records.
    /// A process has exited once its exit is recorded (`terminal`), and has
    /// been reaped once a wait consumed it, or once no traced process will
    /// wait for it: an exit that was not waitable, one whose parent had
    /// already exited, or the root's, which the init outside the run reaps.
    pub(super) fn pidfd_target_state(&self, key: ProcessKey) -> PidfdTargetState {
        let Some(exit) = self.terminal.get(&key) else {
            return PidfdTargetState::Running;
        };
        match (
            exit,
            self.wait_publications
                .get(&key)
                .map(|publication| publication.phase),
        ) {
            (
                ProcessFamilyExit::Root
                | ProcessFamilyExit::ReapedByNamespaceInit { .. }
                | ProcessFamilyExit::RunTeardownChild { .. },
                _,
            )
            | (_, None | Some(WaitPhase::Consumed | WaitPhase::Retired)) => {
                PidfdTargetState::Reaped
            }
            (
                _,
                Some(
                    WaitPhase::Pending
                    | WaitPhase::PublicationFenced
                    | WaitPhase::Ready
                    | WaitPhase::Failed,
                ),
            ) => PidfdTargetState::Exited,
        }
    }

    /// Brings every shadow in line with its process, returning the sends and
    /// shutdowns that takes. The write end of a shadow that is gone is closed.
    // TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/pull/1410): Review when each shadow
    // shows an exit and a reap.
    fn take_pidfd_shadow_actions(&mut self) -> ShadowActions {
        let mut actions = ShadowActions {
            writes: Vec::new(),
            closes: Vec::new(),
        };
        let states: Vec<_> = self
            .pidfd_shadows
            .keys()
            .map(|&key| (key, self.pidfd_target_state(key)))
            .collect();
        for (key, state) in states {
            let writers = &mut self
                .pidfd_shadows
                .get_mut(&key)
                .expect("a listed shadow entry")
                .0;
            let (live, gone): (Vec<_>, Vec<_>) = std::mem::take(writers)
                .into_iter()
                .partition(|writer| writer.reader.strong_count() != 0);
            *writers = live;
            actions
                .closes
                .extend(gone.into_iter().map(|writer| writer.writer));
            if state >= PidfdTargetState::Exited {
                for writer in writers.iter_mut().filter(|writer| !writer.written) {
                    if let Some(reader) = writer.reader.upgrade() {
                        actions.writes.push((reader, writer.writer.clone()));
                    }
                    writer.written = true;
                }
            }
            if state == PidfdTargetState::Reaped {
                actions
                    .closes
                    .extend(writers.drain(..).map(|writer| writer.writer));
            }
            if writers.is_empty() {
                self.pidfd_shadows.remove(&key);
            }
        }
        actions
    }
}

impl ProcessSignalRegistry {
    /// The process that has exited and has not been reaped whose thread group
    /// id is `pid`, if there is one.
    pub(crate) fn unreaped_exited_process(&self, pid: i32) -> Option<SignalProcessId> {
        let family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        family
            .terminal
            .keys()
            .copied()
            .find(|&key| key.0 == pid && family.pidfd_target_state(key) == PidfdTargetState::Exited)
            .map(process_identity)
    }

    /// What a pidfd for `target` shows now.
    pub(crate) fn pidfd_target_state(&self, target: SignalProcessId) -> PidfdTargetState {
        self.family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pidfd_target_state(process_key(target))
    }

    /// A new shadow for a pidfd for `target`, which shows what the pidfd
    /// shows from now on. ESRCH when `target` has been reaped, as Linux's
    /// `pidfd_open` answers for a pid that names no process; the errno of a
    /// failed `socketpair` otherwise.
    pub(crate) fn open_pidfd_shadow(&self, target: SignalProcessId) -> Result<Arc<File>, i32> {
        let (reader, writer) =
            shadow_socket_pair().map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
        let reader = Arc::new(reader);
        let actions = {
            let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
            let key = process_key(target);
            if family.pidfd_target_state(key) == PidfdTargetState::Reaped {
                return Err(libc::ESRCH);
            }
            family
                .pidfd_shadows
                .entry(key)
                .or_default()
                .0
                .push(ShadowWriter {
                    reader: Arc::downgrade(&reader),
                    writer: Arc::new(writer),
                    written: false,
                });
            family.take_pidfd_shadow_actions()
        };
        actions.perform();
        Ok(reader)
    }

    /// Brings every shadow in line with the family's records. Called with no
    /// registry lock held, after each change of those records.
    pub(crate) fn sync_pidfd_shadows(&self) {
        let actions = self
            .family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take_pidfd_shadow_actions();
        actions.perform();
    }

    /// The write ends the registry holds for `target`'s shadows.
    #[cfg(test)]
    pub(crate) fn pidfd_shadow_writers(&self, target: SignalProcessId) -> Vec<Arc<File>> {
        self.family
            .lock()
            .unwrap()
            .pidfd_shadows
            .get(&process_key(target))
            .map_or_else(Vec::new, |writers| {
                writers
                    .0
                    .iter()
                    .map(|writer| writer.writer.clone())
                    .collect()
            })
    }
}

/// A new private pair of connected Unix stream sockets, the shadow and its
/// write end: both nonblocking, close-on-exec, and above the standard
/// descriptors.
fn shadow_socket_pair() -> std::io::Result<(File, File)> {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for the two descriptors socketpair returns.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two new descriptors that nothing else owns.
    let (reader, writer) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    Ok((above_standard(reader)?, above_standard(writer)?))
}

/// `file`, moved above the standard descriptors if it is one of them.
fn above_standard(file: File) -> std::io::Result<File> {
    if file.as_raw_fd() > libc::STDERR_FILENO {
        return Ok(file);
    }
    // SAFETY: file owns a live descriptor; F_DUPFD_CLOEXEC returns a new one.
    let moved = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            libc::STDERR_FILENO + 1,
        )
    };
    if moved < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(moved) })
}
