/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The opt-in parent/base, child-created-leaf startup handoff.

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::os::fd::OwnedFd;

use serde::Deserialize;

use super::*;

const PARENT_DIRECTORY: u8 = 8;
const PARENT_HELD: u8 = 16;
const LEAF_DIRECTORY: u8 = 32;
const LEAF_NAME_SIZE: usize = 18;

/// An absolute Linux `CLOCK_MONOTONIC` deadline in nanoseconds.
///
/// This value is sampled before clone by the native startup API. It is an I/O
/// deadline in the unchanged host clock namespace, not guest virtual time or
/// a representation of [`std::time::Instant`]. Native callers may carry the
/// scalar across exec without reconstructing or renewing its budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxMonotonicDeadline(u64);

impl LinuxMonotonicDeadline {
    /// The original absolute deadline for a native `CLOCK_MONOTONIC` check.
    pub fn as_nanoseconds(self) -> u64 {
        self.0
    }

    fn from_sample(now: u64, timeout: std::time::Duration) -> Result<Self, StartupError> {
        let allowance = u64::try_from(timeout.as_nanos())
            .ok()
            .filter(|value| *value != 0)
            .ok_or(StartupError::InvalidTimeout)?;
        let deadline = now
            .checked_add(allowance)
            .filter(|value| *value != 0)
            .ok_or(StartupError::InvalidTimeout)?;
        Ok(Self(deadline))
    }

    fn remaining_nanoseconds(self) -> Result<u64, StartupError> {
        self.0
            .checked_sub(linux_monotonic_nanoseconds()?)
            .filter(|value| *value != 0)
            .ok_or(StartupError::TimedOut)
    }
}

fn linux_monotonic_nanoseconds() -> Result<u64, StartupError> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    Errno::result(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) })?;
    let seconds = u64::try_from(time.tv_sec).map_err(|_| StartupError::Io(Errno::EOVERFLOW))?;
    let nanos = u64::try_from(time.tv_nsec)
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .ok_or(StartupError::Io(Errno::EOVERFLOW))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(StartupError::Io(Errno::EOVERFLOW))
}

#[derive(Clone, Copy)]
enum ResourceClock {
    Instant,
    LinuxMonotonic,
}

/// The opt-in publication, decoded only after a genuine successful child wait.
///
/// The workload value or original startup refusal is kept separately from
/// additional child endpoint/descriptor errors. A failed child wait still
/// retains only encoded bytes under the existing owned-finalization rules.
#[derive(Debug, Serialize, Deserialize)]
pub struct ParentResourcePublication<T> {
    /// The workload value or original startup/setup error.
    pub value: Result<T, StartupError>,
    /// Additional observed errors, in observation order.
    pub secondary_errors: Vec<StartupError>,
}

/// The new opt-in result, retaining original child ownership on every failure.
pub type ParentResourceStartupResult<T> = Result<
    OwnedDeferredContainerRun<ParentResourcePublication<T>>,
    Box<ParentResourceStartupFailure<T>>,
>;

/// Which actual directory the child is delivering to its original parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentResourceStartupPhase {
    /// The post-setup base directory, before any child leaf creation.
    ParentDirectory,
    /// The actual child-created leaf and its bounded parent-relative name.
    LeafDirectory,
}

impl ParentResourceStartupPhase {
    fn tag(self) -> u8 {
        match self {
            Self::ParentDirectory => PARENT_DIRECTORY,
            Self::LeafDirectory => LEAF_DIRECTORY,
        }
    }
}

/// An opt-in startup refusal retaining the real child and untaken received FDs.
///
/// External owners taken by a callback must accompany this value on every
/// error path. Untaken descriptors are retained here even for partial or
/// malformed frames; they are not proof of a directory name or generation.
/// Settle the child and preserve any uncertain external resource before
/// releasing these descriptors. An ordinary Drop can block through the
/// original owned child and requires outer supervision.
#[derive(Debug)]
#[must_use = "retain the child and actual directory owners through uncertain cleanup"]
pub struct ParentResourceStartupFailure<T> {
    /// The unchanged owned-child/result failure and actual cleanup observations.
    pub failure: StartupOwnedFailure<ParentResourcePublication<T>>,
    /// Received descriptors that the callback did not take.
    pub unclaimed_descriptors: Vec<OwnedFd>,
    /// Additional observed parent callback or endpoint-close errors.
    pub secondary_errors: Vec<StartupError>,
}

impl<T> ParentResourceStartupFailure<T> {
    fn before(cause: StartupError) -> Box<Self> {
        Box::new(Self {
            failure: StartupOwnedFailure::BeforeClone { cause },
            unclaimed_descriptors: Vec::new(),
            secondary_errors: Vec::new(),
        })
    }

    fn before_with_descriptor(cause: StartupError, descriptor: OwnedFd) -> Box<Self> {
        let mut failure = Self::before(cause);
        failure.unclaimed_descriptors.push(descriptor);
        failure
    }

    fn after(
        owned: OwnedFinalization<ParentResourcePublication<T>>,
        cause: StartupError,
        deadline: std::time::Instant,
        descriptors: Vec<OwnedFd>,
        secondary_errors: Vec<StartupError>,
    ) -> Box<Self> {
        Box::new(Self {
            failure: owned.fail(OwnedRunFailure::Startup(cause), deadline),
            unclaimed_descriptors: descriptors,
            secondary_errors,
        })
    }
}

/// One parent callback phase bound to the actual unreaped child and received FDs.
///
/// Take and install each actual descriptor before calling [`Self::validate`]
/// or interpreting [`Self::leaf_name`]. A malformed frame can still carry a
/// real descriptor. Untaken owners return with the failure instead of closing
/// when this borrowed context drops. A successful callback must take all FDs.
pub struct ParentResourceStartContext<'a> {
    child_pid: Pid,
    child_pidfd: BorrowedFd<'a>,
    deadline: std::time::Instant,
    native_deadline: Option<LinuxMonotonicDeadline>,
    phase: ParentResourceStartupPhase,
    frame: &'a mut ResourceFrame,
}

impl ParentResourceStartContext<'_> {
    /// The expected delivery, without trusting received frame bytes.
    pub fn phase(&self) -> ParentResourceStartupPhase {
        self.phase
    }

    /// The owned child's PID in the original parent's namespace.
    pub fn child_pid(&self) -> Pid {
        self.child_pid
    }

    /// Borrows the same actual child generation's pidfd; do not reap separately.
    pub fn child_pidfd(&self) -> BorrowedFd<'_> {
        self.child_pidfd
    }

    /// The original startup deadline, or the native API's cleanup projection.
    ///
    /// When [`Self::native_deadline`] is present, only that raw scalar grants
    /// startup I/O permission. This earlier `Instant` remains available for
    /// the original owned cleanup and finalization APIs.
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline
    }

    /// The native API's one raw deadline, shared by both deliveries and exec.
    /// The original `Instant` startup API returns `None`.
    pub fn native_deadline(&self) -> Option<LinuxMonotonicDeadline> {
        self.native_deadline
    }

    /// Number of received owners, including owners in a malformed frame.
    pub fn descriptor_count(&self) -> usize {
        self.frame.descriptors.len()
    }

    /// Takes one actual received owner exactly once, before validation.
    pub fn take_fd(&mut self, index: usize) -> Option<OwnedFd> {
        self.frame.descriptors.get_mut(index)?.take()
    }

    /// Validates the complete expected frame without granting work permission.
    pub fn validate(&self) -> Result<(), StartupError> {
        self.frame.validate(Some(self.phase.tag()))
    }

    /// The bounded raw child-selected leaf name after complete frame validation.
    /// This is a locator, not proof of object ownership or generation.
    pub fn leaf_name(&self) -> Result<&[u8; LEAF_NAME_SIZE], StartupError> {
        self.validate()?;
        if self.phase != ParentResourceStartupPhase::LeafDirectory {
            return Err(StartupError::Protocol);
        }
        self.frame.bytes[8..26]
            .try_into()
            .map_err(|_| StartupError::Protocol)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ChildPhase {
    Initial,
    ParentHeld,
    LeafSent,
}

/// Child-only context for the opt-in two-delivery directory handoff.
///
/// It runs after namespace/filesystem setup, before seccomp and any workers.
/// The child performs its original directory constructor using its real
/// credentials. Sharing the base does not transfer creation authority to the
/// parent. Keep caller-owned originals at descriptor numbers at least three.
pub struct ChildParentResourceStartContext<'a> {
    socket: &'a ResourceSocket,
    phase: ChildPhase,
    failure: Option<StartupError>,
    secondary_errors: Vec<StartupError>,
    retained_descriptors: Vec<OwnedFd>,
}

impl ChildParentResourceStartContext<'_> {
    /// The original startup deadline, or the native API's cleanup projection.
    /// Native callers must use [`Self::native_deadline`] for permission.
    pub fn deadline(&self) -> std::time::Instant {
        self.socket.inner.deadline
    }

    /// The unchanged raw native deadline to carry into the first exec.
    /// The original `Instant` startup API returns `None`.
    pub fn native_deadline(&self) -> Option<LinuxMonotonicDeadline> {
        self.socket.native_deadline
    }

    /// Delivers the actual base and waits for parent acquisition before creation.
    /// The caller retains the original borrowed owner; no extra duplicate is
    /// allocated to send SCM_RIGHTS. Repetition or an FD below three refuses.
    pub fn share_parent_directory_and_wait(
        &mut self,
        directory: &OwnedFd,
    ) -> Result<(), StartupError> {
        let result = (|| {
            if self.failure.is_some()
                || self.phase != ChildPhase::Initial
                || directory.as_raw_fd() < 3
            {
                return Err(StartupError::Protocol);
            }
            self.socket
                .send(PARENT_DIRECTORY, &[directory.as_fd()], None)?;
            let mut permission = self.socket.receive(Some(PARENT_HELD));
            let result = permission.validate(Some(PARENT_HELD));
            self.secondary_errors
                .append(&mut permission.secondary_errors);
            self.retained_descriptors
                .extend(permission.take_descriptors());
            result?;
            self.phase = ChildPhase::ParentHeld;
            Ok(())
        })();
        if let Err(error) = result {
            append_error(&mut self.failure, &mut self.secondary_errors, Err(error));
        }
        result
    }

    /// Sends and consumes the actual leaf and its current selected raw basename.
    ///
    /// The supplied owner is promoted above numeric stdio if necessary. This
    /// does not create the leaf, choose its name, or change constructor retries.
    /// Disarm any caller path-based cleanup only when its actual resource is
    /// retained by the common custody state. Final work permission is awaited
    /// after the callback returns, and cannot be inferred from this send.
    pub fn transfer_leaf_directory(
        &mut self,
        directory: OwnedFd,
        name: &[u8; LEAF_NAME_SIZE],
    ) -> Result<(), StartupError> {
        let result = (|| {
            if self.failure.is_some()
                || self.phase != ChildPhase::ParentHeld
                || !valid_leaf_name(name)
            {
                self.retained_descriptors.push(directory);
                return Err(StartupError::Protocol);
            }
            let (directory, promotion_error) = promote_received(directory);
            if let Some(error) = promotion_error {
                self.retained_descriptors.push(directory);
                return Err(error);
            }
            let sent = self
                .socket
                .send(LEAF_DIRECTORY, &[directory.as_fd()], Some(name));
            let closed = close_owner(directory);
            let mut cause = sent.err();
            append_error(&mut cause, &mut self.secondary_errors, closed);
            if let Some(error) = cause {
                return Err(error);
            }
            self.phase = ChildPhase::LeafSent;
            Ok(())
        })();
        if let Err(error) = result {
            append_error(&mut self.failure, &mut self.secondary_errors, Err(error));
        }
        result
    }
}

impl Container {
    /// Performs an opt-in parent-base/child-leaf handoff before workload entry.
    ///
    /// This has the pre-thread, no competing reaper, private-clone, fork-safety
    /// and external-owner requirements of [`Self::run_with_startup_owned`].
    /// The original startup method and wire are unchanged. Here the child
    /// shares its actual post-setup base, waits for parent acquisition, creates
    /// its leaf with its original constructor, then transfers that actual leaf
    /// and its raw basename. Parent callbacks must install received owners
    /// before validating bytes. Both deliveries use one absolute deadline.
    ///
    /// Callback code is not preempted. No child worker may start before final
    /// permission and endpoint closure. Result draining, deferred cleanup,
    /// actual wait/status have the same ownership contract as the original
    /// owned API. The opt-in publication carries child secondary errors;
    /// decode it only after a genuine successful wait, then check both its
    /// original value/refusal and those errors. A failed wait retains encoded
    /// bytes and does not authorize generic decoding. Directory cleanup remains the caller's duty,
    /// including uncertain creation, unreceived leaf names and every error.
    pub fn run_with_parent_resource_startup_owned<P, C, F, S, T, U>(
        &mut self,
        timeout: std::time::Duration,
        parent_start: &mut P,
        child_start: &mut C,
        run: &mut F,
    ) -> ParentResourceStartupResult<T>
    where
        P: FnMut(ParentResourceStartContext<'_>) -> Result<(), StartupError>,
        C: FnMut(&mut ChildParentResourceStartContext<'_>) -> Result<S, StartupError>,
        F: FnMut(S) -> (T, U),
        T: Serialize,
    {
        self.run_with_resource_startup_owned(
            timeout,
            ResourceClock::Instant,
            parent_start,
            child_start,
            run,
        )
    }

    /// Performs the same directory handoff with a native monotonic deadline.
    ///
    /// All ownership, callback, wire, wait-before-decode and publication
    /// requirements of [`Self::run_with_parent_resource_startup_owned`] apply.
    /// Before clone, this entry samples one checked absolute Linux
    /// `CLOCK_MONOTONIC` scalar. Both deliveries, acknowledgements and final
    /// permission use that scalar; callbacks may carry it through exec for
    /// the first native lookup. No I/O or retry renews the budget.
    ///
    /// The accompanying `Instant` is sampled immediately before the raw clock
    /// and is only an earlier cleanup projection. It never grants startup
    /// permission. Callbacks are not preempted, and this entry does not impose
    /// a workload timeout or change guest virtual time.
    pub fn run_with_native_parent_resource_startup_owned<P, C, F, S, T, U>(
        &mut self,
        timeout: std::time::Duration,
        parent_start: &mut P,
        child_start: &mut C,
        run: &mut F,
    ) -> ParentResourceStartupResult<T>
    where
        P: FnMut(ParentResourceStartContext<'_>) -> Result<(), StartupError>,
        C: FnMut(&mut ChildParentResourceStartContext<'_>) -> Result<S, StartupError>,
        F: FnMut(S) -> (T, U),
        T: Serialize,
    {
        self.run_with_resource_startup_owned(
            timeout,
            ResourceClock::LinuxMonotonic,
            parent_start,
            child_start,
            run,
        )
    }

    fn run_with_resource_startup_owned<P, C, F, S, T, U>(
        &mut self,
        timeout: std::time::Duration,
        clock: ResourceClock,
        parent_start: &mut P,
        child_start: &mut C,
        run: &mut F,
    ) -> ParentResourceStartupResult<T>
    where
        P: FnMut(ParentResourceStartContext<'_>) -> Result<(), StartupError>,
        C: FnMut(&mut ChildParentResourceStartContext<'_>) -> Result<S, StartupError>,
        F: FnMut(S) -> (T, U),
        T: Serialize,
    {
        let before = ParentResourceStartupFailure::before;
        self.validate_pinned_clone()
            .map_err(|error| before(error.into()))?;
        // In native mode this sample precedes the raw clock sample. The
        // resulting Instant is cleanup-only, never a second I/O authority.
        let cleanup_start = std::time::Instant::now();
        let native_deadline = match clock {
            ResourceClock::Instant => None,
            ResourceClock::LinuxMonotonic => Some(
                LinuxMonotonicDeadline::from_sample(
                    linux_monotonic_nanoseconds().map_err(before)?,
                    timeout,
                )
                .map_err(before)?,
            ),
        };
        let deadline = cleanup_start
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or_else(|| before(StartupError::InvalidTimeout))?;
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        Errno::result(unsafe {
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition)
        })
        .map_err(|error| before(error.into()))?;
        if disposition.sa_sigaction == libc::SIG_IGN
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            return Err(before(StartupError::Io(Errno::ECHILD)));
        }
        let (parent, child) = match native_deadline {
            Some(native) => ResourceSocket::pair_native(deadline, native)?,
            None => ResourceSocket::pair(deadline)?,
        };
        let mut parent = Some(parent);
        let mut child = Some(child);
        let uid_map = &make_id_map(&self.uid_map);
        let gid_map = &make_id_map(&self.gid_map);
        let context = ChildContext {
            stdin: None,
            stdout: None,
            stderr: None,
            uid_map,
            gid_map,
            seccomp_fd: None,
        };
        let (reader, writer) = pipe().map_err(|error| before(error.into()))?;
        let promote = |fd| {
            promote_min3(fd).map_err(|(descriptor, error)| {
                ParentResourceStartupFailure::before_with_descriptor(error, descriptor)
            })
        };
        let mut reader = Some(Fd::from(promote(owned_fd(reader))?));
        let mut writer = Some(Fd::from(promote(owned_fd(writer))?));
        let mut stack = child_stack().map_err(|error| before(error.into()))?;
        #[cfg(feature = "nightly")]
        let output_capture = std::io::set_output_capture(None);
        let namespace = self.namespace;
        let result = crate::clone::clone_with_stack_owned(
            || {
                // These are the actual COW owner slots, not new wrappers over
                // raw numbers whose copied owners would remain live.
                self.parent_resource_child_run(
                    &context,
                    ResourceChildIo {
                        reader: reader.take().unwrap(),
                        writer: writer.take().unwrap(),
                        parent: parent.take().unwrap(),
                        child: child.take().unwrap(),
                    },
                    child_start,
                    run,
                )
            },
            namespace,
            &mut stack,
        );
        #[cfg(feature = "nightly")]
        std::io::set_output_capture(output_capture);
        let cleanup = OwnedContainerCleanup::new(result.map_err(|error| before(error.into()))?);
        let mut owned = OwnedFinalization::new(cleanup, reader.take().unwrap());
        let mut secondary = Vec::new();
        let mut initial_error = None;
        append_error(
            &mut initial_error,
            &mut secondary,
            child.take().unwrap().close(),
        );
        append_error(
            &mut initial_error,
            &mut secondary,
            writer.take().unwrap().close().map_err(Into::into),
        );
        let socket = parent.take().unwrap();
        if owned.cleanup().pidfd.is_none() {
            append_error(
                &mut initial_error,
                &mut secondary,
                Err(StartupError::Protocol),
            );
        }
        let mut retained = Vec::new();
        let exchange = (|| {
            if let Some(error) = initial_error {
                return Err(error);
            }
            for phase in [
                ParentResourceStartupPhase::ParentDirectory,
                ParentResourceStartupPhase::LeafDirectory,
            ] {
                let mut frame = socket.receive(Some(phase.tag()));
                let validation = frame.validate(Some(phase.tag()));
                secondary.append(&mut frame.secondary_errors);
                let callback = parent_start(ParentResourceStartContext {
                    child_pid: owned.cleanup().pid,
                    child_pidfd: owned.cleanup().pidfd.as_ref().unwrap().as_fd(),
                    deadline,
                    native_deadline,
                    phase,
                    frame: &mut frame,
                });
                let untaken = frame.take_descriptors();
                let unclaimed = !untaken.is_empty();
                retained.extend(untaken);
                let mut cause = None;
                append_error(&mut cause, &mut secondary, validation);
                append_error(&mut cause, &mut secondary, callback);
                if unclaimed {
                    append_error(&mut cause, &mut secondary, Err(StartupError::Protocol));
                }
                if let Some(error) = cause {
                    return Err(error);
                }
                if phase == ParentResourceStartupPhase::ParentDirectory {
                    socket.send(PARENT_HELD, &[], None)?;
                }
            }
            let mut eof = socket.receive(None);
            let validation = eof.validate(None);
            secondary.append(&mut eof.secondary_errors);
            retained.extend(eof.take_descriptors());
            validation?;
            socket.send(STARTUP_READY, &[], None)?;
            socket.close_write()?;
            Ok(())
        })();
        let mut cause = exchange.err();
        append_error(&mut cause, &mut secondary, socket.close());
        if let Some(error) = cause {
            return Err(ParentResourceStartupFailure::after(
                owned, error, deadline, retained, secondary,
            ));
        }
        if let Err(error) = owned.drain() {
            return Err(Box::new(ParentResourceStartupFailure {
                failure: owned.fail(error, deadline),
                unclaimed_descriptors: retained,
                secondary_errors: secondary,
            }));
        }
        Ok(OwnedDeferredContainerRun { inner: owned })
    }

    fn parent_resource_child_run<C, F, S, T, U>(
        &mut self,
        context: &ChildContext<'_>,
        io: ResourceChildIo,
        child_start: &mut C,
        run: &mut F,
    ) -> i32
    where
        C: FnMut(&mut ChildParentResourceStartContext<'_>) -> Result<S, StartupError>,
        F: FnMut(S) -> (T, U),
        T: Serialize,
    {
        let ResourceChildIo {
            reader,
            writer,
            parent,
            child: socket,
        } = io;
        let mut failure = None;
        let mut secondary = Vec::new();
        let mut retained = Vec::new();
        append_error(
            &mut failure,
            &mut secondary,
            reader.close().map_err(StartupError::Io),
        );
        append_error(&mut failure, &mut secondary, parent.close());
        let state = (|| {
            if let Some(error) = failure {
                return Err(error);
            }
            self.setup_before_filter(context, &mut [])
                .map_err(StartupError::Setup)?;
            let mut child_context = ChildParentResourceStartContext {
                socket: &socket,
                phase: ChildPhase::Initial,
                failure: None,
                secondary_errors: Vec::new(),
                retained_descriptors: Vec::new(),
            };
            let state = child_start(&mut child_context);
            retained.append(&mut child_context.retained_descriptors);
            secondary.append(&mut child_context.secondary_errors);
            if let Some(error) = child_context.failure {
                // Normal `?` propagation is the same observation. Keep a
                // distinct callback refusal alongside the context failure.
                if let Err(callback_error) = &state
                    && *callback_error != error
                {
                    secondary.push(*callback_error);
                }
                return Err(error);
            }
            let state = state?;
            if child_context.phase != ChildPhase::LeafSent {
                return Err(StartupError::Protocol);
            }
            socket.close_write()?;
            let mut permission = socket.receive(Some(STARTUP_READY));
            let validated = permission.validate(Some(STARTUP_READY));
            secondary.append(&mut permission.secondary_errors);
            retained.extend(permission.take_descriptors());
            validated?;
            let mut eof = socket.receive(None);
            let validated = eof.validate(None);
            secondary.append(&mut eof.secondary_errors);
            retained.extend(eof.take_descriptors());
            validated?;
            Ok(state)
        })();
        if let Err(error) = &state
            && failure != Some(*error)
        {
            append_error(&mut failure, &mut secondary, Err(*error));
        }
        for descriptor in retained {
            append_error(&mut failure, &mut secondary, close_owner(descriptor));
        }
        let state = match state {
            Ok(state) if failure.is_none() => Ok(state),
            _ => Err(failure.unwrap()),
        };
        let state = match state {
            Ok(state) => match socket.close() {
                Ok(()) => Ok(state),
                Err(error) => Err(error),
            },
            Err(error) => {
                append_error(&mut failure, &mut secondary, socket.send_failure(error));
                // No worker exists on this refusal path. The parent retains
                // the real wait and any received directory even if this
                // final endpoint close itself refuses.
                append_error(&mut failure, &mut secondary, socket.close());
                Err(error)
            }
        };
        let (value, deferred, status) = match state {
            Ok(state) => match self.setup_filter(context) {
                Ok(()) => {
                    let (value, deferred) = run(state);
                    (Ok(value), Some(deferred), 0)
                }
                Err(error) => (Err(StartupError::Setup(error)), None, 0),
            },
            Err(error) => (Err(error), None, 1),
        };
        let mut writer = std::io::BufWriter::new(writer);
        let publication = Ok::<_, StartupError>(ParentResourcePublication {
            value,
            secondary_errors: secondary,
        });
        bincode::serde::encode_into_std_write(&publication, &mut writer, bincode::config::legacy())
            .expect("Failed to serialize return value");
        writer.flush().expect("Failed to flush return value");
        let writer = writer.into_inner().expect("Failed to finish return value");
        writer.close().expect("Failed to close return-value writer");
        drop(deferred);
        status
    }
}

fn append_error(
    primary: &mut Option<StartupError>,
    secondary: &mut Vec<StartupError>,
    result: Result<(), StartupError>,
) {
    if let Err(error) = result {
        if primary.is_none() {
            *primary = Some(error);
        } else {
            secondary.push(error);
        }
    }
}

fn owned_fd(fd: Fd) -> OwnedFd {
    // SAFETY: into_raw_fd consumes the one actual Fd owner.
    unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) }
}

fn close_owner(fd: OwnedFd) -> Result<(), StartupError> {
    // Consume once. EINTR never causes a numeric close retry.
    Errno::result(unsafe { libc::close(fd.into_raw_fd()) })?;
    Ok(())
}

fn promote_min3(fd: OwnedFd) -> Result<OwnedFd, (OwnedFd, StartupError)> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    let (promoted, error) = promote_received(fd);
    match error {
        None => Ok(promoted),
        Some(error) => Err((promoted, error)),
    }
}

// A received capability must survive promotion failure. Refuse permission,
// but keep the actual old/new owner rather than losing it through `?`/Drop.
fn promote_received(fd: OwnedFd) -> (OwnedFd, Option<StartupError>) {
    if fd.as_raw_fd() >= 3 {
        return (fd, None);
    }
    let raw = match Errno::result(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) })
    {
        Ok(raw) => raw,
        Err(error) => return (fd, Some(error.into())),
    };
    // SAFETY: fcntl returned a fresh, exclusively owned descriptor.
    let promoted = unsafe { OwnedFd::from_raw_fd(raw) };
    (promoted, close_owner(fd).err())
}

fn valid_leaf_name(name: &[u8]) -> bool {
    name.len() == LEAF_NAME_SIZE
        && &name[..12] == b"reverie-dbt-"
        && name[12..].iter().all(u8::is_ascii_alphanumeric)
}

struct ResourceSocket {
    inner: StartupSocket,
    native_deadline: Option<LinuxMonotonicDeadline>,
}

struct ResourceChildIo {
    reader: Fd,
    writer: Fd,
    parent: ResourceSocket,
    child: ResourceSocket,
}

impl ResourceSocket {
    fn pair<T>(
        deadline: std::time::Instant,
    ) -> Result<(Self, Self), Box<ParentResourceStartupFailure<T>>> {
        Self::pair_with_deadline(deadline, None)
    }

    fn pair_native<T>(
        deadline: std::time::Instant,
        native: LinuxMonotonicDeadline,
    ) -> Result<(Self, Self), Box<ParentResourceStartupFailure<T>>> {
        Self::pair_with_deadline(deadline, Some(native))
    }

    fn pair_with_deadline<T>(
        deadline: std::time::Instant,
        native_deadline: Option<LinuxMonotonicDeadline>,
    ) -> Result<(Self, Self), Box<ParentResourceStartupFailure<T>>> {
        let (parent, child) =
            StartupSocket::pair(deadline).map_err(ParentResourceStartupFailure::before)?;
        let convert =
            |socket: StartupSocket| -> Result<Self, Box<ParentResourceStartupFailure<T>>> {
                let fd = promote_min3(owned_fd(socket.fd)).map_err(|(descriptor, error)| {
                    ParentResourceStartupFailure::before_with_descriptor(error, descriptor)
                })?;
                Ok(Self {
                    inner: StartupSocket {
                        fd: Fd::from(fd),
                        deadline,
                    },
                    native_deadline,
                })
            };
        Ok((convert(parent)?, convert(child)?))
    }

    fn close(self) -> Result<(), StartupError> {
        self.inner.fd.close().map_err(Into::into)
    }

    fn check_native_deadline(&self) -> Result<(), StartupError> {
        match self.native_deadline {
            Some(deadline) => deadline.remaining_nanoseconds().map(|_| ()),
            None => Ok(()),
        }
    }

    fn poll(&self, events: libc::c_short) -> Result<(), StartupError> {
        let Some(deadline) = self.native_deadline else {
            return self.inner.poll(events);
        };
        loop {
            let millis = deadline
                .remaining_nanoseconds()?
                .div_ceil(1_000_000)
                .min(i32::MAX as u64) as i32;
            let mut fd = libc::pollfd {
                fd: self.inner.fd.as_raw_fd(),
                events,
                revents: 0,
            };
            match Errno::result(unsafe { libc::poll(&mut fd, 1, millis) }) {
                Ok(0) | Err(Errno::EINTR) => continue,
                Ok(_) if fd.revents & libc::POLLNVAL != 0 => {
                    return Err(StartupError::Io(Errno::EBADF));
                }
                Ok(_) => return self.check_native_deadline(),
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn close_write(&self) -> Result<(), StartupError> {
        self.check_native_deadline()?;
        self.inner.close_write()?;
        self.check_native_deadline()
    }

    fn send_failure(&self, error: StartupError) -> Result<(), StartupError> {
        if self.native_deadline.is_none() {
            return self
                .inner
                .send(STARTUP_FAILURE, &StartupFds::default(), Some(error));
        }
        let mut frame = [0u8; STARTUP_FRAME_SIZE];
        frame[..4].copy_from_slice(b"RVS1");
        frame[4] = STARTUP_FAILURE;
        frame[6] =
            bincode::serde::encode_into_slice(error, &mut frame[8..], bincode::config::legacy())
                .map_err(|_| StartupError::Protocol)? as u8;
        self.send_frame(&frame, &[])
    }

    fn send(
        &self,
        phase: u8,
        descriptors: &[BorrowedFd<'_>],
        name: Option<&[u8; LEAF_NAME_SIZE]>,
    ) -> Result<(), StartupError> {
        let mut frame = [0u8; STARTUP_FRAME_SIZE];
        frame[..4].copy_from_slice(b"RVS1");
        frame[4] = phase;
        frame[5] = descriptors.len() as u8;
        if let Some(name) = name {
            frame[6] = LEAF_NAME_SIZE as u8;
            frame[8..26].copy_from_slice(name);
        }
        self.send_frame(&frame, descriptors)
    }

    fn send_frame(
        &self,
        frame: &[u8; STARTUP_FRAME_SIZE],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), StartupError> {
        let socket = &self.inner;
        let mut ancillary = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        if !descriptors.is_empty() {
            if descriptors.len() > MAX_STARTUP_FDS {
                return Err(StartupError::Protocol);
            }
            message.msg_control = ancillary.as_mut_ptr().cast();
            let (space, length) = startup_rights_lengths(descriptors.len())?;
            message.msg_controllen = startup_abi_len(space)?;
            assert!(
                startup_abi_len::<_, usize>(message.msg_controllen)?
                    <= std::mem::size_of_val(&ancillary)
            );
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = startup_abi_len(length)?;
                for (index, fd) in descriptors.iter().enumerate() {
                    libc::CMSG_DATA(header)
                        .cast::<i32>()
                        .add(index)
                        .write(fd.as_raw_fd());
                }
            }
        }
        let mut offset = 0;
        while offset < frame.len() {
            self.poll(libc::POLLOUT)?;
            let mut iov = libc::iovec {
                iov_base: frame[offset..].as_ptr().cast_mut().cast(),
                iov_len: frame.len() - offset,
            };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            self.check_native_deadline()?;
            match Errno::result(unsafe {
                libc::sendmsg(socket.fd.as_raw_fd(), &message, libc::MSG_NOSIGNAL)
            }) {
                Ok(0) => return Err(StartupError::Protocol),
                Ok(size) => {
                    offset += size as usize;
                    message.msg_control = std::ptr::null_mut();
                    message.msg_controllen = 0;
                    self.check_native_deadline()?;
                }
                Err(Errno::EINTR | Errno::EAGAIN) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn receive(&self, phase: Option<u8>) -> ResourceFrame {
        let socket = &self.inner;
        let mut frame = ResourceFrame {
            bytes: [0; STARTUP_FRAME_SIZE],
            size: 0,
            descriptors: Vec::new(),
            failure: None,
            eof: false,
            secondary_errors: Vec::new(),
        };
        loop {
            if let Err(error) = self.poll(libc::POLLIN) {
                frame.record_error(error);
                return frame;
            }
            let mut ancillary = [0usize; 16];
            let mut iov = libc::iovec {
                iov_base: frame.bytes[frame.size..].as_mut_ptr().cast(),
                iov_len: STARTUP_FRAME_SIZE - frame.size,
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = ancillary.as_mut_ptr().cast();
            message.msg_controllen = match startup_abi_len(std::mem::size_of_val(&ancillary)) {
                Ok(length) => length,
                Err(error) => {
                    frame.record_error(error);
                    return frame;
                }
            };
            if let Err(error) = self.check_native_deadline() {
                frame.record_error(error);
                return frame;
            }
            let size = match Errno::result(unsafe {
                libc::recvmsg(socket.fd.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC)
            }) {
                Ok(size) => size as usize,
                Err(Errno::EINTR | Errno::EAGAIN) => continue,
                Err(error) => {
                    frame.record_error(error.into());
                    return frame;
                }
            };
            let previous = frame.descriptors.len();
            unsafe {
                let mut header = libc::CMSG_FIRSTHDR(&message);
                while !header.is_null() {
                    let length: usize = match startup_abi_len((*header).cmsg_len) {
                        Ok(length) => length,
                        Err(error) => {
                            frame.record_error(error);
                            break;
                        }
                    };
                    if (*header).cmsg_level == libc::SOL_SOCKET
                        && (*header).cmsg_type == libc::SCM_RIGHTS
                        && length >= libc::CMSG_LEN(0) as usize
                    {
                        let bytes = length - libc::CMSG_LEN(0) as usize;
                        if !bytes.is_multiple_of(std::mem::size_of::<i32>()) {
                            frame.record_error(StartupError::Protocol);
                        }
                        for index in 0..bytes / std::mem::size_of::<i32>() {
                            let raw = libc::CMSG_DATA(header).cast::<i32>().add(index).read();
                            // Own first, validate later, including partial frames.
                            let (fd, promotion_error) = promote_received(OwnedFd::from_raw_fd(raw));
                            frame.descriptors.push(Some(fd));
                            if let Some(error) = promotion_error {
                                frame.record_error(error);
                            }
                        }
                    } else {
                        frame.record_error(StartupError::Protocol);
                    }
                    header = libc::CMSG_NXTHDR(&message, header);
                }
            }
            if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                || (previous != frame.descriptors.len() && (frame.size != 0 || phase.is_none()))
                || frame.descriptors.len() > MAX_STARTUP_FDS
            {
                frame.record_error(StartupError::Protocol);
            }
            // Receive first acquired every actual SCM_RIGHTS owner. An expired
            // raw deadline refuses permission while retaining those owners.
            if let Err(error) = self.check_native_deadline() {
                frame.record_error(error);
            }
            if size == 0 {
                frame.eof = true;
                return frame;
            }
            frame.size += size;
            if frame.size == STARTUP_FRAME_SIZE || frame.failure.is_some() {
                return frame;
            }
        }
    }
}

struct ResourceFrame {
    bytes: [u8; STARTUP_FRAME_SIZE],
    size: usize,
    descriptors: Vec<Option<OwnedFd>>,
    failure: Option<StartupError>,
    eof: bool,
    secondary_errors: Vec<StartupError>,
}

impl ResourceFrame {
    fn record_error(&mut self, error: StartupError) {
        append_error(&mut self.failure, &mut self.secondary_errors, Err(error));
    }
    fn validate(&self, expected: Option<u8>) -> Result<(), StartupError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.size == 0 && self.eof && self.descriptors.is_empty() {
            return if expected.is_none() {
                Ok(())
            } else {
                Err(StartupError::PeerClosed)
            };
        }
        if self.size != STARTUP_FRAME_SIZE || &self.bytes[..4] != b"RVS1" || self.bytes[7] != 0 {
            return Err(StartupError::Protocol);
        }
        if self.bytes[4] == STARTUP_FAILURE && self.descriptors.is_empty() {
            let size = self.bytes[6] as usize;
            if self.bytes[5] != 0
                || size == 0
                || size > STARTUP_FRAME_SIZE - 8
                || self.bytes[8 + size..].iter().any(|byte| *byte != 0)
            {
                return Err(StartupError::Protocol);
            }
            return match bincode::serde::decode_from_slice::<StartupError, _>(
                &self.bytes[8..8 + size],
                bincode::config::legacy(),
            ) {
                Ok((error, used)) if used == size => Err(error),
                _ => Err(StartupError::Protocol),
            };
        }
        if expected.is_none() {
            return Err(StartupError::Protocol);
        }
        if Some(self.bytes[4]) != expected || self.bytes[5] as usize != self.descriptors.len() {
            return Err(StartupError::Protocol);
        }
        match expected.unwrap() {
            PARENT_DIRECTORY
                if self.descriptors.len() == 1 && self.bytes[6..].iter().all(|byte| *byte == 0) =>
            {
                Ok(())
            }
            LEAF_DIRECTORY
                if self.descriptors.len() == 1
                    && self.bytes[6] as usize == LEAF_NAME_SIZE
                    && valid_leaf_name(&self.bytes[8..26])
                    && self.bytes[26..].iter().all(|byte| *byte == 0) =>
            {
                Ok(())
            }
            PARENT_HELD | STARTUP_READY
                if self.descriptors.is_empty() && self.bytes[6..].iter().all(|byte| *byte == 0) =>
            {
                Ok(())
            }
            _ => Err(StartupError::Protocol),
        }
    }

    fn take_descriptors(&mut self) -> Vec<OwnedFd> {
        self.descriptors
            .iter_mut()
            .filter_map(Option::take)
            .collect()
    }
}

#[cfg(test)]
mod focused_controls;
