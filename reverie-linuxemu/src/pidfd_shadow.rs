/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The shadow sockets that show the readiness of pidfds for guest processes
//! (gVisor: pkg/sentry/kernel/pidfd.go, whose pidfd reports itself readable
//! once its thread group has exited).
//!
//! In the guest's descriptor table, the supervisor's own pidfd stands in for
//! a pidfd for a guest process (`crate::executor::pidfd_open`), so the kernel
//! answers every call that it answers alike for any pidfd: read, write,
//! `F_GETFL`, the `/proc/self/fd` link and its refused reopen. What the
//! stand-in cannot show is the guest process's life: the supervisor outlives
//! every guest process. Linux's `pidfd_poll` (fs/pidfs.c) reports
//! `EPOLLIN | EPOLLRDNORM` once the process has exited, adds `EPOLLHUP` once
//! it has been reaped, and never reports anything else. So each such pidfd
//! has a private connected pair of Unix stream sockets. One socket, the
//! shadow, reports `POLLIN | POLLRDNORM` once the other has sent it one
//! byte, and `POLLHUP` as well once the other has been shut down; poll,
//! select and epoll watch it in the stand-in's place, asking it only for
//! `POLLIN | POLLRDNORM` (`crate::executor::GuestPidfd`), since a socket
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
//! descriptors. The pidfd's record holds the shadow, and only the descriptor
//! tables that hold the pidfd, and a call while it uses the pidfd, hold the
//! record (`crate::executor::GuestPidfd`). So the shadow closes with the
//! pidfd's last descriptor, which also ends any epoll registration of the
//! pidfd, as Linux ends one when the pidfd's open file description is
//! released. The write end closes when the process is reaped, or once the
//! shadow is gone.
//!
//! The registry decides what each shadow shows under the family lock, from
//! the family's own record of each exit (`ProcessFamilyState::terminal`) and
//! of each wait (`ProcessFamilyState::wait_publications`). The sends and
//! shutdowns that decision calls for are done once the lock is released, as
//! every host close of the registry is, and in the order they were decided,
//! under a lock of their own ([`ShadowActions::perform`]): whichever task
//! gets there first does every one decided so far, its own and any that
//! another task decided and has not done yet, and waits for any being done.
//! So a sync returns only once every shadow shows what the records it saw
//! call for, and no send ever follows the shutdown of its write end. Each
//! change of those records ends with
//! `ProcessSignalRegistry::sync_pidfd_shadows`, so a shadow shows an exit
//! before the exiting process's Tool callback runs, which is before any other
//! task can learn of the exit from the Tool, and shows a reap before the wait
//! that reaped returns.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::sync::Mutex;
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

/// A family's pidfd shadows: the write ends for each process, and the sends
/// and shutdowns decided for them.
#[derive(Debug, Default)]
pub(super) struct PidfdShadows {
    writers: BTreeMap<ProcessKey, Vec<ShadowWriter>>,
    effects: Arc<ShadowEffects>,
}

#[derive(Debug)]
struct ShadowWriter {
    /// The shadow, which the pidfd's record holds.
    reader: Weak<File>,
    writer: Arc<File>,
    /// Whether the shadow's byte is decided: it is sent once the process has
    /// exited.
    written: bool,
}

/// The sends and shutdowns decided for the shadows, in the order decided,
/// and the lock under which they are done.
#[derive(Debug, Default)]
struct ShadowEffects {
    queue: Mutex<VecDeque<ShadowEffect>>,
    io: Mutex<()>,
}

#[derive(Debug)]
enum ShadowEffect {
    /// The write end sends its shadow the byte, if the shadow is still open.
    /// The shadow is not held meanwhile: holding it would hold the pidfd's
    /// open file description, and with it any epoll registration of the
    /// pidfd, past the pidfd's last close.
    Send {
        reader: Weak<File>,
        writer: Arc<File>,
    },
    /// The write end is shut down, then closed.
    Shutdown(Arc<File>),
}

impl ShadowEffect {
    fn perform(self) {
        match self {
            Self::Send { reader, writer } => {
                if reader.strong_count() == 0 {
                    return;
                }
                let byte = 1_u8;
                loop {
                    // SAFETY: writer owns a live descriptor, and the byte is
                    // one byte of readable memory.
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
                    // without waiting, and its shutdown comes after this send
                    // (`ShadowActions::perform`); only a shadow closed since
                    // the check above refuses it (EPIPE).
                    debug_assert!(
                        sent == 1 || reader.strong_count() == 0,
                        "pidfd shadow socket refused its byte"
                    );
                    break;
                }
            }
            Self::Shutdown(writer) => {
                // The shutdown hangs the shadow up whatever other copies of
                // this descriptor exist (see the module documentation).
                // SAFETY: writer owns a live descriptor.
                let shut = unsafe { libc::shutdown(writer.as_raw_fd(), libc::SHUT_RDWR) };
                debug_assert!(
                    shut == 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTCONN),
                    "pidfd shadow socket refused its shutdown"
                );
            }
        }
    }
}

/// The sends and shutdowns the registry decided under the family lock, for
/// the decider to do once it has released that lock ([`Self::perform`]).
#[must_use]
pub(super) struct ShadowActions(Arc<ShadowEffects>);

impl ShadowActions {
    /// Does every send and shutdown decided so far, in the order decided,
    /// under the family's shadow lock. One that another task decided and has
    /// not done yet is done here, and one being done is waited for, so this
    /// returns only once each shadow shows what the decisions before it
    /// called for, and a write end's send, decided at the exit, is always
    /// done before its shutdown, decided at the reap.
    fn perform(self) {
        let _io = self.0.io.lock().unwrap_or_else(|p| p.into_inner());
        let effects = std::mem::take(&mut *self.0.queue.lock().unwrap_or_else(|p| p.into_inner()));
        for effect in effects {
            effect.perform();
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

    /// Decides what brings every shadow in line with its process, and queues
    /// the sends and shutdowns that takes, for the caller to do once it has
    /// released the family lock. The write end of a shadow that is gone is
    /// closed.
    // TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/pull/1410): Review when each shadow
    // shows an exit and a reap.
    fn take_pidfd_shadow_actions(&mut self) -> ShadowActions {
        let mut effects = Vec::new();
        let states: Vec<_> = self
            .pidfd_shadows
            .writers
            .keys()
            .map(|&key| (key, self.pidfd_target_state(key)))
            .collect();
        for (key, state) in states {
            let writers = self
                .pidfd_shadows
                .writers
                .get_mut(&key)
                .expect("a listed shadow entry");
            let (live, gone): (Vec<_>, Vec<_>) = std::mem::take(writers)
                .into_iter()
                .partition(|writer| writer.reader.strong_count() != 0);
            *writers = live;
            effects.extend(
                gone.into_iter()
                    .map(|writer| ShadowEffect::Shutdown(writer.writer)),
            );
            if state >= PidfdTargetState::Exited {
                for writer in writers.iter_mut().filter(|writer| !writer.written) {
                    effects.push(ShadowEffect::Send {
                        reader: writer.reader.clone(),
                        writer: writer.writer.clone(),
                    });
                    writer.written = true;
                }
            }
            if state == PidfdTargetState::Reaped {
                effects.extend(
                    writers
                        .drain(..)
                        .map(|writer| ShadowEffect::Shutdown(writer.writer)),
                );
            }
            if writers.is_empty() {
                self.pidfd_shadows.writers.remove(&key);
            }
        }
        let shadow_effects = &self.pidfd_shadows.effects;
        shadow_effects
            .queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend(effects);
        ShadowActions(shadow_effects.clone())
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
                .writers
                .entry(key)
                .or_default()
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
            .writers
            .get(&process_key(target))
            .map_or_else(Vec::new, |writers| {
                writers.iter().map(|writer| writer.writer.clone()).collect()
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

/// Sends and shutdowns that one task decided and has not done yet when
/// another task syncs, as the effects of an unrelated sync wait for their
/// decider, who decided them under the family lock, to do them once it has
/// released that lock. Reviewer regressions from
/// https://github.com/rrnewton/reverie/pull/1410.
#[cfg(test)]
mod interleaving_tests {
    use super::super::ChildExitSnapshot;
    use super::super::PublicationDisposition;
    use super::super::child_wait::WaitPublication;
    use super::*;

    /// Records `target`'s waitable exit, with `parent`'s wait for it ready,
    /// and decides what that shows, without doing it.
    fn exit_decided_and_not_done(
        registry: &ProcessSignalRegistry,
        parent: SignalProcessId,
        target: SignalProcessId,
    ) -> ShadowActions {
        let mut family = registry.family.lock().unwrap();
        family.terminal.insert(
            process_key(target),
            ProcessFamilyExit::Child(ChildExitSnapshot {
                completion: reverie::ChildExitCompletion {
                    parent,
                    child: target,
                    status: reverie::ExitStatus::Exited(7),
                    waitable: true,
                    uid: 0,
                    user_ticks: 0,
                    system_ticks: 0,
                },
                disposition: PublicationDisposition::Default,
                pending_generation: 0,
            }),
        );
        family.wait_publications.insert(
            process_key(target),
            WaitPublication {
                parent,
                phase: WaitPhase::Ready,
            },
        );
        family.take_pidfd_shadow_actions()
    }

    /// The exit's send, decided by one task, is not overtaken by the reap's
    /// shutdown: whichever task gets to the queue first does the send first,
    /// and the decider then has nothing left to do, so it never sends on a
    /// shut-down socket.
    #[test]
    fn a_reap_does_not_overtake_an_exit_another_task_decided() {
        let registry = ProcessSignalRegistry::default();
        let parent = SignalProcessId {
            tgid: reverie::Pid::from_raw(1),
            generation: 1,
        };
        let target = SignalProcessId {
            tgid: reverie::Pid::from_raw(2),
            generation: 2,
        };
        let shadow = registry.open_pidfd_shadow(target).unwrap();
        let key = process_key(target);
        let deferred_exit = exit_decided_and_not_done(&registry, parent, target);
        // One unrelated sync selected the exit write and got descheduled
        // after unlocking. The exiting task's own sync can now return.
        registry.sync_pidfd_shadows();
        // Completion becomes waitable; its parent consumes it and syncs.
        registry
            .family
            .lock()
            .unwrap()
            .wait_publications
            .get_mut(&key)
            .unwrap()
            .phase = WaitPhase::Consumed;
        registry.sync_pidfd_shadows();
        let mut pfd = libc::pollfd {
            fd: shadow.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is one initialized pollfd of this frame.
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 1);
        // The earlier sync resumes at its exact post-unlock point.
        // Correct ordering must not send on an already-shutdown socket.
        deferred_exit.perform();
    }

    /// The last close of a pidfd is not held back by a send that another task
    /// decided and has not done: the decision names the shadow without
    /// holding it, so the shadow, and with it the pidfd's open file
    /// description and any epoll registration of the pidfd, goes with the
    /// pidfd's last descriptor, and the late send finds no shadow.
    #[test]
    fn a_last_close_is_not_held_back_by_a_send_another_task_decided() {
        let registry = ProcessSignalRegistry::default();
        let parent = SignalProcessId {
            tgid: reverie::Pid::from_raw(1),
            generation: 1,
        };
        let target = SignalProcessId {
            tgid: reverie::Pid::from_raw(2),
            generation: 2,
        };
        let shadow = registry.open_pidfd_shadow(target).unwrap();
        let closed = Arc::downgrade(&shadow);
        let deferred_exit = exit_decided_and_not_done(&registry, parent, target);
        // The pidfd's last descriptor closes.
        drop(shadow);
        assert!(
            closed.upgrade().is_none(),
            "a decided send held the closed pidfd's shadow open"
        );
        deferred_exit.perform();
        registry.sync_pidfd_shadows();
        assert!(registry.pidfd_shadow_writers(target).is_empty());
    }

    /// The sync of the wait that reaps returns only once the shadow shows the
    /// reap, even when another task decided the shutdown and has not done it.
    #[test]
    fn a_reap_sync_waits_for_a_shutdown_another_task_decided() {
        let registry = ProcessSignalRegistry::default();
        let parent = SignalProcessId {
            tgid: reverie::Pid::from_raw(1),
            generation: 1,
        };
        let target = SignalProcessId {
            tgid: reverie::Pid::from_raw(2),
            generation: 2,
        };
        let shadow = registry.open_pidfd_shadow(target).unwrap();
        let key = process_key(target);
        let deferred_exit = exit_decided_and_not_done(&registry, parent, target);
        deferred_exit.perform();
        // The child is exited and readable before its parent consumes it.
        let deferred_reap = {
            let mut family = registry.family.lock().unwrap();
            family.wait_publications.get_mut(&key).unwrap().phase = WaitPhase::Consumed;
            // An unrelated operation selected this global reap action,
            // then paused after dropping the family lock.
            family.take_pidfd_shadow_actions()
        };
        // The consuming wait's own sync must not return before the effect.
        registry.sync_pidfd_shadows();
        let mut pfd = libc::pollfd {
            fd: shadow.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDNORM,
            revents: 0,
        };
        // SAFETY: pfd is one initialized pollfd of this frame.
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 1);
        assert_eq!(
            pfd.revents,
            libc::POLLIN | libc::POLLRDNORM | libc::POLLHUP,
            "consuming wait's sync returned before the HUP effect"
        );
        deferred_reap.perform();
    }
}
