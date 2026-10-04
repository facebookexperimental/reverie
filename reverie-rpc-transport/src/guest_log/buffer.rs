/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::cell::UnsafeCell;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::Options;

pub mod ordered;

pub const PAYLOAD: usize = 4096;
const PRODUCERS: usize = 64;
const MAGIC: u64 = 0x33474f4c52455652;
pub(super) const RESERVED: u32 = 1;
pub(super) const ACTIVE: u32 = 2;
pub(super) const FINISHED: u32 = 3;
pub(super) const CANCELLED_FORK: u32 = 4;
pub(super) const BEGIN: u32 = 1;
pub(super) const DATA: u32 = 2;
pub(super) const END: u32 = 3;
pub(super) const FINISH: u32 = 4;
pub const FAILURE: u32 = 1;
pub const TRUNCATED: u32 = 2;

#[repr(C, align(64))]
pub(super) struct Channel {
    pub state: AtomicU32,
    pub parent: AtomicU32,
    pub pid: AtomicU64,
    pub fork_result: AtomicU64,
    pub head: AtomicU64,
    pub tail: AtomicU64,
    pub terminal_head: AtomicU64,
    pub terminal_sequence: AtomicU64,
}

impl Channel {
    fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
            parent: AtomicU32::new(0),
            pid: AtomicU64::new(0),
            fork_result: AtomicU64::new(0),
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            terminal_head: AtomicU64::new(0),
            terminal_sequence: AtomicU64::new(0),
        }
    }
}

#[repr(C, align(64))]
struct Header {
    magic: u64,
    slots: u64,
    producers: u64,
    byte_limit: u64,
    allocated: AtomicU32,
    pub failure: AtomicU32,
    pub stop: AtomicU32,
    pub progress: AtomicU32,
    reserved_bytes: AtomicU64,
    channels: [Channel; PRODUCERS],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct Frame {
    pub ordinal: u64,
    pub kind: u32,
    pub length: u32,
    pub sequence: u64,
    pub offset: u64,
    pub total: u64,
    pub payload: [u8; PAYLOAD],
}

#[repr(C, align(64))]
struct Slot(UnsafeCell<Frame>);

/// An attached versioned mapping. Payload access is governed by release/acquire
/// cursors; no reference to concurrently writable payload is exposed.
pub struct SharedBuffer {
    pointer: NonNull<Header>,
    length: usize,
}

/// All shared mutation is atomic or exclusively owned by the cursor protocol.
unsafe impl Send for SharedBuffer {}
/// All shared mutation is atomic or exclusively owned by the cursor protocol.
unsafe impl Sync for SharedBuffer {}

impl Drop for SharedBuffer {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer.as_ptr().cast(), self.length);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishError {
    Full,
    Stopped,
    Invalid,
    Capacity,
    Overflow,
}

fn invalid() -> io::Error {
    io::Error::other("invalid shared guest-log layout/handshake")
}

fn size(options: Options) -> io::Result<usize> {
    if options.producers == 0
        || options.producers > PRODUCERS
        || options.slots == 0
        || options.slots > 64
    {
        return Err(invalid());
    }
    Ok(std::mem::size_of::<Header>()
        + options.producers * options.slots * std::mem::size_of::<Slot>())
}

fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn send_descriptor(socket: &UnixStream, fd: &OwnedFd, mut tag: [u8; 4]) -> io::Result<()> {
    let mut vector = libc::iovec {
        iov_base: tag.as_mut_ptr().cast(),
        iov_len: tag.len(),
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(4) as usize;
        libc::CMSG_DATA(header)
            .cast::<i32>()
            .write_unaligned(fd.as_raw_fd());
        if libc::sendmsg(
            socket.as_raw_fd(),
            &message,
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        ) != 4
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Setup only. Both endpoints receive the same mapping descriptor. The guest
/// endpoint must remain held by every admitted writer until process teardown.
///
/// # Safety
/// Every recipient of either endpoint or any transferred backing descriptor
/// must obey the [module contract](super): initialized layout never changes,
/// all writable aliases cooperate in the frame protocol, each incarnation has
/// one serialized producer, and exactly one collector consumes it. These
/// obligations cover aliases and descendants until every mapping is released.
/// Retain guest lifetime endpoints through all admitted writer activity.
///
/// ```compile_fail,E0133
/// use reverie_rpc_transport::guest_log as g;
/// fn requires_ownership_contract(options: g::Options) {
///     let _ = g::channel_pair(options);
/// }
/// ```
pub unsafe fn channel_pair(options: Options) -> io::Result<(UnixStream, UnixStream)> {
    channel_pair_version(options, None)
}

fn channel_pair_version(
    options: Options,
    ordered: Option<ordered::Limits>,
) -> io::Result<(UnixStream, UnixStream)> {
    let base_length = size(options)?;
    let length = match ordered {
        Some(limits) => ordered::size(limits)?,
        None => base_length,
    };
    let raw = unsafe {
        libc::memfd_create(
            if ordered.is_some() {
                c"reverie-guest-log-v4".as_ptr()
            } else {
                c"reverie-guest-log-v3".as_ptr()
            },
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = above_stdio(unsafe { OwnedFd::from_raw_fd(raw) })?;
    if unsafe { libc::ftruncate(fd.as_raw_fd(), length as i64) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let initialized = Header {
        magic: if ordered.is_some() {
            ordered::MAGIC
        } else {
            MAGIC
        },
        slots: options.slots as u64,
        producers: options.producers as u64,
        byte_limit: options.byte_limit as u64,
        allocated: AtomicU32::new(if ordered.is_some() { 2 } else { 1 }),
        failure: AtomicU32::new(0),
        stop: AtomicU32::new(0),
        progress: AtomicU32::new(0),
        reserved_bytes: AtomicU64::new(0),
        channels: std::array::from_fn(|_| Channel::new()),
    };
    unsafe {
        mapping.cast::<Header>().write(initialized);
        (*mapping.cast::<Header>()).channels[0]
            .state
            .store(RESERVED, Ordering::Relaxed);
        if let Some(limits) = ordered {
            (*mapping.cast::<Header>()).channels[1]
                .state
                .store(RESERVED, Ordering::Relaxed);
            ordered::initialize(mapping.cast::<u8>().add(base_length), limits);
        }
        libc::munmap(mapping, length);
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pair = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let host = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    let guest = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    let host: UnixStream = above_stdio(host)?.into();
    let guest: UnixStream = above_stdio(guest)?.into();
    for socket in [&host, &guest] {
        let enabled = 1i32;
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const i32).cast(),
                4,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let tag = if ordered.is_some() {
        *b"RLG4"
    } else {
        *b"RLG3"
    };
    send_descriptor(&host, &fd, tag)?;
    send_descriptor(&guest, &fd, tag)?;
    Ok((host, guest))
}

impl SharedBuffer {
    /// Setup before producers or the collector run; rejects old wire versions.
    ///
    /// # Safety
    /// `fd` is a live endpoint from a trusted channel. Every peer and backing
    /// alias must obey the [module contract](super) throughout this mapping's
    /// lifetime: immutable initialized layout, coordinated atomic access and
    /// exclusive producer/consumer frame ownership. Size seals do not prevent
    /// writes. The borrowed endpoint is not consumed; retain it as required by
    /// the lifetime protocol. Validation cannot make an untrusted writer safe.
    ///
    /// ```compile_fail,E0133
    /// use reverie_rpc_transport::guest_log as g;
    /// fn requires_ownership_contract(fd: i32) {
    ///     let _ = g::SharedBuffer::receive(fd);
    /// }
    /// ```
    pub unsafe fn receive(fd: i32) -> io::Result<Self> {
        unsafe { Self::receive_version(fd, false) }
    }

    unsafe fn receive_version(fd: i32, ordered: bool) -> io::Result<Self> {
        let mut tag = [0u8; 4];
        let mut vector = libc::iovec {
            iov_base: tag.as_mut_ptr().cast(),
            iov_len: 4,
        };
        let mut control = [0usize; 32];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let result = unsafe {
            libc::recvmsg(
                fd,
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut descriptor = None;
        let mut bad = result != 4
            || tag != if ordered { *b"RLG4" } else { *b"RLG3" }
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let bytes = (*header)
                        .cmsg_len
                        .saturating_sub(libc::CMSG_LEN(0) as usize);
                    for offset in (0..bytes / 4).map(|index| index * 4) {
                        let received = OwnedFd::from_raw_fd(
                            libc::CMSG_DATA(header)
                                .add(offset)
                                .cast::<i32>()
                                .read_unaligned(),
                        );
                        if descriptor.is_some() {
                            bad = true;
                        } else {
                            descriptor = Some(received);
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if bad {
            return Err(invalid());
        }
        let descriptor = descriptor.ok_or_else(invalid)?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let seals = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GET_SEALS) };
        let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
        if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0
            || seals < 0
            || seals & required != required
            || stat.st_size < std::mem::size_of::<Header>() as i64
            || stat.st_size > 32 * 1024 * 1024
        {
            return Err(invalid());
        }
        let length = stat.st_size as usize;
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                descriptor.as_raw_fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mapping = Self {
            pointer: NonNull::new(pointer.cast()).ok_or_else(invalid)?,
            length,
        };
        let header = mapping.header();
        let options = Options {
            byte_limit: usize::try_from(header.byte_limit).map_err(|_| invalid())?,
            producers: header.producers as usize,
            slots: header.slots as usize,
        };
        let base_length = size(options)?;
        if ordered {
            if header.magic != ordered::MAGIC {
                return Err(invalid());
            }
            ordered::validate(&mapping, base_length)?;
        } else if header.magic != MAGIC || base_length != length {
            return Err(invalid());
        }
        Ok(mapping)
    }

    fn header(&self) -> &Header {
        unsafe { self.pointer.as_ref() }
    }
    pub(super) fn channel(&self, index: usize) -> &Channel {
        &self.header().channels[index]
    }
    pub(super) fn allocated(&self) -> usize {
        self.header().allocated.load(Ordering::Acquire) as usize
    }
    pub fn byte_limit(&self) -> usize {
        self.header().byte_limit as usize
    }

    pub fn options(&self) -> Options {
        Options {
            byte_limit: self.byte_limit(),
            producers: self.header().producers as usize,
            slots: self.header().slots as usize,
        }
    }
    pub fn failure(&self) -> u32 {
        self.header().failure.load(Ordering::Acquire)
    }
    pub fn fail(&self, reason: u32) {
        self.header().failure.fetch_or(reason, Ordering::Release);
    }
    pub fn stopped(&self) -> bool {
        self.header().stop.load(Ordering::Acquire) != 0
    }
    pub fn progress(&self) -> u32 {
        self.header().progress.load(Ordering::Acquire)
    }
    pub fn progress_address(&self) -> *const u32 {
        self.header().progress.as_ptr()
    }
    pub fn stop(&self) {
        self.header().stop.store(1, Ordering::Release);
        self.wake();
    }
    pub(super) fn wake(&self) {
        self.header().progress.fetch_add(1, Ordering::Release);
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                self.progress_address(),
                libc::FUTEX_WAKE,
                i32::MAX,
            );
        }
    }

    pub fn reserve_child(&self, parent: usize) -> Result<usize, PublishError> {
        if parent >= self.allocated()
            || self.channel(parent).state.load(Ordering::Acquire) != ACTIVE
        {
            return Err(PublishError::Invalid);
        }
        let index = self
            .header()
            .allocated
            .try_update(Ordering::AcqRel, Ordering::Acquire, |index| {
                (u64::from(index) < self.header().producers).then_some(index + 1)
            })
            .map_err(|_| {
                self.fail(FAILURE);
                PublishError::Capacity
            })? as usize;
        self.channel(index)
            .parent
            .store((parent + 1) as u32, Ordering::Relaxed);
        self.channel(index).state.store(RESERVED, Ordering::Release);
        Ok(index)
    }

    pub fn resolve_fork(&self, index: usize, result: i64) -> Result<(), PublishError> {
        if index == 0 || index >= self.allocated() || result == 0 {
            return Err(PublishError::Invalid);
        }
        let channel = self.channel(index);
        if result < 0 {
            channel
                .state
                .compare_exchange(
                    RESERVED,
                    CANCELLED_FORK,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| PublishError::Invalid)?;
            channel.fork_result.store(u64::MAX, Ordering::Release);
        } else {
            self.bind_pid(channel, result as u64)?;
            channel
                .fork_result
                .compare_exchange(0, result as u64, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| PublishError::Invalid)?;
        }
        Ok(())
    }

    fn bind_pid(&self, channel: &Channel, pid: u64) -> Result<(), PublishError> {
        match channel
            .pid
            .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(previous) if previous == pid => Ok(()),
            _ => Err(PublishError::Invalid),
        }
    }

    /// # Safety
    /// Exactly one process owns this reserved incarnation, with serialized writes.
    /// All writers retain the lifetime endpoint and obey the admitted fork contract.
    /// The mapping must remain attached until this producer is dropped. There is
    /// exactly one consuming collector per mapping; no detached writer survives
    /// endpoint closure, FINISH, or an unsupported image transition.
    /// Independently scheduled producers start only after `LogHandle::ready`.
    /// Synchronous prepopulation instead requires exclusive startup ownership:
    /// the queued collector cannot be cancelled or dropped before `run` takes it.
    ///
    /// ```compile_fail,E0133
    /// use reverie_rpc_transport::guest_log as g;
    /// fn requires_ownership_contract(buffer: &g::SharedBuffer) {
    ///     let _ = buffer.activate(0, 1);
    /// }
    /// ```
    pub unsafe fn activate(&self, index: usize, pid: i64) -> Result<Producer, PublishError> {
        if index >= self.allocated() || pid <= 0 {
            return Err(PublishError::Invalid);
        }
        let channel = self.channel(index);
        self.bind_pid(channel, pid as u64)?;
        channel
            .state
            .compare_exchange(RESERVED, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PublishError::Invalid)?;
        if index == 0 {
            channel.fork_result.store(pid as u64, Ordering::Release);
        }
        Ok(Producer {
            mapping: self.pointer.as_ptr() as usize,
            index,
            sequence: 1,
            broken: false,
            finished: false,
        })
    }

    fn slot(&self, index: usize, ordinal: u64) -> *mut Frame {
        let offset =
            index * self.header().slots as usize + (ordinal % self.header().slots) as usize;
        unsafe {
            (*self
                .pointer
                .as_ptr()
                .cast::<u8>()
                .add(std::mem::size_of::<Header>())
                .cast::<Slot>()
                .add(offset))
            .0
            .get()
        }
    }

    fn publish(&self, index: usize, mut frame: Frame) -> Result<(), PublishError> {
        if self.stopped() {
            return Err(PublishError::Stopped);
        }
        let channel = self.channel(index);
        let head = channel.head.load(Ordering::Relaxed);
        let tail = channel.tail.load(Ordering::Acquire);
        let next = head.checked_add(1).ok_or(PublishError::Overflow)?;
        if head.checked_sub(tail).ok_or(PublishError::Invalid)? >= self.header().slots {
            return Err(PublishError::Full);
        }
        frame.ordinal = head;
        unsafe {
            self.slot(index, head).write(frame);
        }
        channel.head.store(next, Ordering::Release);
        Ok(())
    }

    pub(super) fn read(&self, index: usize) -> Result<Option<Frame>, PublishError> {
        let channel = self.channel(index);
        let tail = channel.tail.load(Ordering::Relaxed);
        let head = channel.head.load(Ordering::Acquire);
        if tail == head {
            return Ok(None);
        }
        if head.checked_sub(tail).ok_or(PublishError::Invalid)? > self.header().slots {
            return Err(PublishError::Invalid);
        }
        let frame = unsafe { self.slot(index, tail).read() };
        if frame.ordinal != tail {
            return Err(PublishError::Invalid);
        }
        Ok(Some(frame))
    }

    pub(super) fn consume(&self, index: usize) {
        self.channel(index).tail.fetch_add(1, Ordering::Release);
        self.wake();
    }
}

/// Process-private progress; never reused by an inherited fork child.
pub struct Producer {
    mapping: usize,
    index: usize,
    sequence: u64,
    broken: bool,
    finished: bool,
}

impl Producer {
    pub fn index(&self) -> usize {
        self.index
    }

    fn frame(&self, kind: u32, total: usize, offset: usize, bytes: &[u8]) -> Frame {
        let mut frame = Frame {
            ordinal: 0,
            kind,
            length: bytes.len() as u32,
            sequence: self.sequence,
            total: total as u64,
            offset: offset as u64,
            payload: [0; PAYLOAD],
        };
        frame.payload[..bytes.len()].copy_from_slice(bytes);
        frame
    }

    fn send(
        &mut self,
        mapping: &SharedBuffer,
        frame: Frame,
        wait: &mut impl FnMut(&SharedBuffer, u32) -> Result<(), PublishError>,
    ) -> Result<(), PublishError> {
        loop {
            let progress = mapping.progress();
            match mapping.publish(self.index, frame) {
                Err(PublishError::Full) => wait(mapping, progress)?,
                result => return result,
            }
        }
    }

    /// Retains exact chunk position across Full. Success requires committed END.
    pub fn write_record(
        &mut self,
        mapping: &SharedBuffer,
        bytes: &[u8],
        mut wait: impl FnMut(&SharedBuffer, u32) -> Result<(), PublishError>,
    ) -> Result<(), PublishError> {
        let result = (|| {
            if self.mapping != mapping.pointer.as_ptr() as usize
                || self.broken
                || self.finished
                || self.sequence == u64::MAX
            {
                return Err(PublishError::Invalid);
            }
            mapping
                .header()
                .reserved_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                    total
                        .checked_add(bytes.len() as u64)
                        .filter(|next| *next <= mapping.header().byte_limit)
                })
                .map_err(|_| {
                    mapping.fail(TRUNCATED);
                    PublishError::Capacity
                })?;
            self.send(mapping, self.frame(BEGIN, bytes.len(), 0, &[]), &mut wait)?;
            for (index, chunk) in bytes.chunks(PAYLOAD).enumerate() {
                self.send(
                    mapping,
                    self.frame(DATA, bytes.len(), index * PAYLOAD, chunk),
                    &mut wait,
                )?;
            }
            self.send(
                mapping,
                self.frame(END, bytes.len(), bytes.len(), &[]),
                &mut wait,
            )?;
            self.sequence += 1;
            Ok(())
        })();
        if result.is_err() {
            self.broken = true;
            mapping.fail(FAILURE);
        }
        result
    }

    pub fn finish(
        &mut self,
        mapping: &SharedBuffer,
        mut wait: impl FnMut(&SharedBuffer, u32) -> Result<(), PublishError>,
    ) -> Result<(), PublishError> {
        if self.mapping != mapping.pointer.as_ptr() as usize
            || self.finished
            || self.broken
            || self.sequence == u64::MAX
        {
            mapping.fail(FAILURE);
            return Err(PublishError::Invalid);
        }
        if let Err(error) = self.send(mapping, self.frame(FINISH, 0, 0, &[]), &mut wait) {
            self.broken = true;
            mapping.fail(FAILURE);
            return Err(error);
        }
        let channel = mapping.channel(self.index);
        channel
            .terminal_sequence
            .store(self.sequence, Ordering::Relaxed);
        channel
            .terminal_head
            .store(channel.head.load(Ordering::Relaxed), Ordering::Relaxed);
        channel.state.store(FINISHED, Ordering::Release);
        self.finished = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_committed_frame_retains_bounded_evidence_and_drains_other_producer() {
        use std::time::Duration;

        use super::super::IssueKind;
        use super::super::Phase;
        use super::super::REJECTED_PAYLOAD_LIMIT;
        use super::super::retained_log_with_drain;

        for (length, keep_endpoint) in [(8, false), (512, false), (512, true)] {
            let options = Options {
                byte_limit: 4096,
                producers: 2,
                slots: 16,
            };
            let (host, guest) = unsafe { channel_pair(options) }.unwrap();
            let writer = unsafe { SharedBuffer::receive(guest.as_raw_fd()) }.unwrap();
            let (sink, handle) = retained_log_with_drain(options, Duration::from_millis(20));
            let collector = unsafe { sink.reader(host) }.unwrap();
            let mut parent = unsafe { writer.activate(0, 123) }.unwrap();
            let child_index = writer.reserve_child(0).unwrap();
            writer.resolve_fork(child_index, 456).unwrap();
            let mut child = unsafe { writer.activate(child_index, 456) }.unwrap();
            parent
                .write_record(&writer, b"accepted\0\xff", |_, _| panic!("unexpected Full"))
                .unwrap();
            writer
                .publish(0, parent.frame(BEGIN, 1024, 0, &[]))
                .unwrap();
            writer
                .publish(0, parent.frame(DATA, 1024, 0, b"pre\0"))
                .unwrap();
            let payload: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let rejected = parent.frame(DATA, 1024, 99, &payload);
            writer.publish(0, rejected).unwrap();
            writer
                .publish(0, parent.frame(END, 1024, 1024, &[]))
                .unwrap();
            child
                .write_record(&writer, b"other\xff\0", |_, _| panic!("unexpected Full"))
                .unwrap();
            child
                .finish(&writer, |_, _| panic!("unexpected Full"))
                .unwrap();
            let endpoint = keep_endpoint.then_some(guest);
            let report = collector.run();
            assert_eq!(report.phase, Phase::Incomplete);
            assert!(!report.qualifies());
            assert_eq!(report.peer_closed, !keep_endpoint);
            let protocol = report
                .issues
                .iter()
                .find(|issue| issue.kind == IssueKind::Protocol)
                .unwrap();
            assert_eq!(
                protocol.message,
                "producer 1: invalid shared guest-log record sequence/length"
            );
            assert_eq!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.kind == IssueKind::Cutoff),
                keep_endpoint
            );
            let parent = &report.streams[0];
            assert_eq!(parent.bytes, b"accepted\0\xff");
            assert_eq!(parent.fragment, b"pre\0");
            assert_eq!(parent.fragment_sequence, Some(2));
            assert_eq!(parent.complete_records, 1);
            assert_eq!(parent.unread_frames, 1);
            let diagnostic = parent.rejected_frame.as_ref().unwrap();
            assert_eq!(
                (
                    diagnostic.ordinal,
                    diagnostic.kind,
                    diagnostic.length,
                    diagnostic.sequence,
                    diagnostic.offset,
                    diagnostic.total
                ),
                (5, DATA, length as u32, 2, 99, 1024)
            );
            assert_eq!(
                diagnostic.payload,
                payload[..length.min(REJECTED_PAYLOAD_LIMIT)]
            );
            assert_eq!(
                diagnostic.omitted_payload_bytes,
                length.saturating_sub(REJECTED_PAYLOAD_LIMIT) as u64
            );
            assert_eq!(report.streams[1].bytes, b"other\xff\0");
            assert!(report.streams[1].finished);
            assert!(report.streams[1].rejected_frame.is_none());
            assert_eq!(handle.snapshot().streams, report.streams);
            drop(endpoint);
        }
    }

    #[test]
    fn copying_slot_is_invisible_until_release_and_wrong_mapping_refuses() {
        let options = Options {
            byte_limit: 1024,
            producers: 1,
            slots: 1,
        };
        let (host, guest) = unsafe { channel_pair(options) }.unwrap();
        let writer = unsafe { SharedBuffer::receive(guest.as_raw_fd()) }.unwrap();
        let reader = unsafe { SharedBuffer::receive(host.as_raw_fd()) }.unwrap();
        let mut producer = unsafe { writer.activate(0, 123) }.unwrap();
        let frame = producer.frame(BEGIN, 3, 0, &[]);
        unsafe {
            writer.slot(0, 0).write(frame);
        }
        assert!(reader.read(0).unwrap().is_none());
        writer.channel(0).head.store(1, Ordering::Release);
        assert_eq!(reader.read(0).unwrap().unwrap().kind, BEGIN);
        reader.consume(0);
        let (other_host, other_guest) = unsafe { channel_pair(options) }.unwrap();
        let other = unsafe { SharedBuffer::receive(other_guest.as_raw_fd()) }.unwrap();
        assert_eq!(
            producer.write_record(&other, b"wrong", |_, _| Ok(())),
            Err(PublishError::Invalid)
        );
        drop(other_host);
    }
}
