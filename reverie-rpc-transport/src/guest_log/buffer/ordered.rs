use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::Frame;
use super::Options;
use super::PAYLOAD;
use super::Producer;
use super::PublishError;
use super::SharedBuffer;

pub(super) const MAGIC: u64 = 0x34474f4c52455652;
const CLOSED: u64 = 1 << 63;
const FREE: u64 = 0;
const RESERVED: u64 = 1;
const COMMITTED: u64 = 2;
const RELEASING: u64 = 3;
const MAX_CREDITS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub producers: usize,
    pub slots: usize,
    pub max_record_bytes: usize,
    pub host_pending_bytes: usize,
    pub guest_pending_bytes: usize,
    pub pending_records: usize,
}

impl Limits {
    fn options(self) -> io::Result<Options> {
        if self.producers < 2
            || self.pending_records < 2
            || self.pending_records > MAX_CREDITS
            || self.max_record_bytes == 0
            || self.max_record_bytes > self.host_pending_bytes
            || self.max_record_bytes > self.guest_pending_bytes
        {
            return Err(super::invalid());
        }
        Ok(Options {
            producers: self.producers,
            slots: self.slots,
            byte_limit: self
                .host_pending_bytes
                .checked_add(self.guest_pending_bytes)
                .ok_or_else(super::invalid)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Host,
    Guest,
}

impl Role {
    fn index(self) -> usize {
        match self {
            Self::Host => 0,
            Self::Guest => 1,
        }
    }
}

#[repr(C, align(64))]
struct Header {
    max_record_bytes: u64,
    host_pending_bytes: u64,
    guest_pending_bytes: u64,
    pending_records: u64,
    admission: [AtomicU64; 2],
    used: [AtomicU64; 2],
    next_order: AtomicU64,
    collector: AtomicU64,
    order_fault: AtomicU64,
    guest_failure: AtomicU64,
}

#[repr(C, align(64))]
struct Credit {
    state: AtomicU64,
    generation: AtomicU64,
    producer: AtomicU64,
    sequence: AtomicU64,
    length: AtomicU64,
    order: AtomicU64,
}

pub(super) fn size(limits: Limits) -> io::Result<usize> {
    super::size(limits.options()?)?
        .checked_add(std::mem::size_of::<Header>())
        .and_then(|length| {
            length.checked_add(
                limits
                    .pending_records
                    .checked_mul(std::mem::size_of::<Credit>())?,
            )
        })
        .filter(|length| *length <= 32 * 1024 * 1024)
        .ok_or_else(super::invalid)
}

pub(super) unsafe fn initialize(pointer: *mut u8, limits: Limits) {
    pointer.cast::<Header>().write(Header {
        max_record_bytes: limits.max_record_bytes as u64,
        host_pending_bytes: limits.host_pending_bytes as u64,
        guest_pending_bytes: limits.guest_pending_bytes as u64,
        pending_records: limits.pending_records as u64,
        admission: std::array::from_fn(|_| AtomicU64::new(0)),
        used: std::array::from_fn(|_| AtomicU64::new(0)),
        next_order: AtomicU64::new(1),
        collector: AtomicU64::new(0),
        order_fault: AtomicU64::new(0),
        guest_failure: AtomicU64::new(0),
    });
    let credits = pointer.add(std::mem::size_of::<Header>()).cast::<Credit>();
    for index in 0..limits.pending_records {
        credits.add(index).write(Credit {
            state: AtomicU64::new(FREE),
            generation: AtomicU64::new(0),
            producer: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            length: AtomicU64::new(0),
            order: AtomicU64::new(0),
        });
    }
}

fn header(mapping: &SharedBuffer) -> &Header {
    let offset = super::size(mapping.options()).expect("validated layout");
    unsafe {
        &*mapping
            .pointer
            .as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<Header>()
    }
}

pub(super) fn validate(mapping: &SharedBuffer, base: usize) -> io::Result<()> {
    if base
        .checked_add(std::mem::size_of::<Header>())
        .ok_or_else(super::invalid)?
        > mapping.length
    {
        return Err(super::invalid());
    }
    let state = header(mapping);
    let limits = Limits {
        producers: mapping.options().producers,
        slots: mapping.options().slots,
        max_record_bytes: state
            .max_record_bytes
            .try_into()
            .map_err(|_| super::invalid())?,
        host_pending_bytes: state
            .host_pending_bytes
            .try_into()
            .map_err(|_| super::invalid())?,
        guest_pending_bytes: state
            .guest_pending_bytes
            .try_into()
            .map_err(|_| super::invalid())?,
        pending_records: state
            .pending_records
            .try_into()
            .map_err(|_| super::invalid())?,
    };
    if size(limits)? != mapping.length || limits.options()? != mapping.options() {
        return Err(super::invalid());
    }
    Ok(())
}

/// Create an ordered channel with two socket lifetime endpoints.
///
/// # Safety
/// All endpoint/descriptor recipients, duplicates, mappings and fork descendants
/// must obey the [shared-memory contract](super::super). Preserve initialized
/// V3/V4 layout fields for every mapping's lifetime and use only the matching
/// exclusive-producer, single-collector credit/publication protocol. The guest
/// endpoint remains live until all admitted guest writers are quiescent.
///
/// ```compile_fail,E0133
/// use reverie_rpc_transport::guest_log as g;
/// fn requires_ownership_contract(limits: g::ordered::Limits) {
///     let _ = g::ordered::channel_pair(limits);
/// }
/// ```
pub unsafe fn channel_pair(limits: Limits) -> io::Result<(UnixStream, UnixStream)> {
    super::channel_pair_version(limits.options()?, Some(limits))
}

pub struct Buffer {
    mapping: SharedBuffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    pub closed: bool,
    pub entrants: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordCommit {
    pub order: u64,
}

#[derive(Clone, Copy, Debug)]
struct Ticket {
    index: usize,
    generation: u64,
}

struct Entrant<'a> {
    buffer: &'a Buffer,
    role: Role,
}

impl Drop for Entrant<'_> {
    fn drop(&mut self) {
        header(&self.buffer.mapping).admission[self.role.index()].fetch_sub(1, Ordering::Release);
        self.buffer.mapping.wake();
    }
}

impl Buffer {
    /// Import a trusted V4 channel without consuming its lifetime endpoint.
    ///
    /// # Safety
    /// The channel and all writable aliases must obey the
    /// [shared-memory contract](super::super) for the full lifetime of this Arc
    /// and all writers, records and collectors derived from it. Layout fields
    /// must remain immutable, and frame/credit access must follow the protocol.
    /// The caller retains the borrowed endpoint according to the socket lifetime
    /// contract. Header validation and size seals do not exclude hostile writes.
    ///
    /// ```compile_fail,E0133
    /// use reverie_rpc_transport::guest_log as g;
    /// fn requires_ownership_contract(fd: i32) {
    ///     let _ = g::ordered::Buffer::receive(fd);
    /// }
    /// ```
    pub unsafe fn receive(fd: i32) -> io::Result<Arc<Self>> {
        unsafe { Self::receive_unshared(fd) }.map(Arc::new)
    }

    /// Import under the same contract without creating process-local sharing.
    /// The setup message is still consumed once; the endpoint remains borrowed.
    pub(crate) unsafe fn receive_unshared(fd: i32) -> io::Result<Self> {
        Ok(Self {
            mapping: unsafe { SharedBuffer::receive_version(fd, true)? },
        })
    }

    pub fn admission(&self, role: Role) -> Admission {
        let state = header(&self.mapping).admission[role.index()].load(Ordering::Acquire);
        Admission {
            closed: state & CLOSED != 0,
            entrants: state & !CLOSED,
        }
    }

    pub fn close(&self, role: Role) -> Admission {
        header(&self.mapping).admission[role.index()].fetch_or(CLOSED, Ordering::AcqRel);
        self.mapping.wake();
        self.admission(role)
    }

    pub fn used_bytes(&self, role: Role) -> u64 {
        header(&self.mapping).used[role.index()].load(Ordering::Acquire)
    }

    pub fn order_failed(&self) -> bool {
        header(&self.mapping).order_fault.load(Ordering::Acquire) != 0
    }

    pub fn guest_stopped(&self) -> bool {
        self.check(Role::Guest).is_err()
    }

    pub fn fail_guest(&self) {
        header(&self.mapping)
            .guest_failure
            .store(1, Ordering::Release);
        self.close(Role::Guest);
    }

    pub fn guest_failed(&self) -> bool {
        header(&self.mapping).guest_failure.load(Ordering::Acquire) != 0
    }

    pub fn unresolved_guest_commit(&self) -> bool {
        let admission = self.admission(Role::Guest);
        if admission.closed && admission.entrants != 0 {
            self.fault();
            true
        } else {
            false
        }
    }

    fn fault(&self) -> PublishError {
        header(&self.mapping)
            .order_fault
            .store(1, Ordering::Release);
        self.mapping.wake();
        PublishError::Invalid
    }

    fn check(&self, role: Role) -> Result<(), PublishError> {
        if self.order_failed() || self.mapping.failure() != 0 {
            Err(PublishError::Invalid)
        } else if self.mapping.stopped()
            || self.admission(role).closed
            || (role == Role::Guest && self.guest_failed())
        {
            Err(PublishError::Stopped)
        } else {
            Ok(())
        }
    }

    fn enter(&self, role: Role) -> Result<Entrant<'_>, PublishError> {
        self.check(role)?;
        header(&self.mapping).admission[role.index()]
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & CLOSED == 0 && state < CLOSED - 1).then(|| state + 1)
            })
            .map_err(|_| PublishError::Stopped)?;
        Ok(Entrant { buffer: self, role })
    }

    fn credit(&self, index: usize) -> Result<&Credit, PublishError> {
        let state = header(&self.mapping);
        if index >= state.pending_records as usize {
            return Err(PublishError::Invalid);
        }
        Ok(unsafe {
            &*(std::ptr::from_ref(state)
                .cast::<u8>()
                .add(std::mem::size_of::<Header>())
                .cast::<Credit>()
                .add(index))
        })
    }

    fn reserve(
        &self,
        role: Role,
        producer: usize,
        sequence: u64,
        length: usize,
    ) -> Result<Ticket, PublishError> {
        self.check(role)?;
        let state = header(&self.mapping);
        if length as u64 > state.max_record_bytes {
            return Err(PublishError::Capacity);
        }
        let middle = state.pending_records as usize / 2;
        let range = match role {
            Role::Host => 0..middle,
            Role::Guest => middle..state.pending_records as usize,
        };
        for index in range {
            let credit = self.credit(index)?;
            if credit
                .state
                .compare_exchange(FREE, RESERVED, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            let limit = match role {
                Role::Host => state.host_pending_bytes,
                Role::Guest => state.guest_pending_bytes,
            };
            if state.used[role.index()]
                .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(length as u64)
                        .filter(|next| *next <= limit)
                })
                .is_err()
            {
                credit.state.store(FREE, Ordering::Release);
                return Err(PublishError::Full);
            }
            let generation = match credit.generation.load(Ordering::Relaxed).checked_add(1) {
                Some(value) => value,
                None => {
                    state.used[role.index()].fetch_sub(length as u64, Ordering::Release);
                    credit.state.store(FREE, Ordering::Release);
                    return Err(PublishError::Overflow);
                }
            };
            credit.generation.store(generation, Ordering::Relaxed);
            credit.producer.store(producer as u64, Ordering::Relaxed);
            credit.sequence.store(sequence, Ordering::Relaxed);
            credit.length.store(length as u64, Ordering::Relaxed);
            credit.order.store(0, Ordering::Relaxed);
            return Ok(Ticket { index, generation });
        }
        Err(PublishError::Full)
    }

    /// Activate one reserved host (0), root guest (1), or fork incarnation.
    ///
    /// # Safety
    /// Exactly one process owns the reserved incarnation and serializes its
    /// writes. All aliases obey the shared-memory contract; only one collector
    /// consumes the mapping. Keep the lifetime endpoint until writers quiesce.
    /// A fork child must use a separately reserved incarnation, never inherited
    /// Writer progress. Coordinate actual parent result resolution and child
    /// activation, and do not write after FINISH or an unsupported image change.
    /// Independently scheduled producers wait for collector readiness; exclusive
    /// startup prepopulation must retain the collector until it takes ownership.
    ///
    /// ```compile_fail,E0133
    /// use reverie_rpc_transport::guest_log as g;
    /// fn requires_ownership_contract(buffer: &std::sync::Arc<g::ordered::Buffer>) {
    ///     let _ = buffer.activate(0, 1);
    /// }
    /// ```
    pub unsafe fn activate(
        self: &Arc<Self>,
        index: usize,
        pid: i64,
    ) -> Result<Writer, PublishError> {
        let role = if index == 0 { Role::Host } else { Role::Guest };
        self.check(role)?;
        let producer = unsafe { self.mapping.activate(index, pid)? };
        if index == 1 {
            self.mapping
                .channel(index)
                .fork_result
                .store(pid as u64, Ordering::Release);
        }
        Ok(Writer {
            buffer: self.clone(),
            producer,
            role,
        })
    }

    pub fn reserve_child(&self, parent: usize) -> Result<usize, PublishError> {
        self.check(Role::Guest)?;
        if parent == 0 {
            return Err(PublishError::Invalid);
        }
        self.mapping.reserve_child(parent)
    }

    pub fn resolve_fork(&self, index: usize, result: i64) -> Result<(), PublishError> {
        if index < 2 {
            return Err(PublishError::Invalid);
        }
        self.mapping.resolve_fork(index, result)
    }

    pub fn collector(self: &Arc<Self>) -> Result<Collector, PublishError> {
        header(&self.mapping)
            .collector
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PublishError::Invalid)?;
        let producers = self.mapping.options().producers;
        Ok(Collector {
            buffer: self.clone(),
            partial: (0..producers).map(|_| None).collect(),
            sequences: vec![1; producers],
            finished: vec![false; producers],
            rejected: vec![None; producers],
            pending: BTreeMap::new(),
            next: 1,
        })
    }
}

pub struct Writer {
    buffer: Arc<Buffer>,
    producer: Producer,
    role: Role,
}

fn metadata(ticket: Ticket, order: Option<u64>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(if order.is_some() { 24 } else { 16 });
    bytes.extend_from_slice(&(ticket.index as u64).to_le_bytes());
    bytes.extend_from_slice(&ticket.generation.to_le_bytes());
    if let Some(order) = order {
        bytes.extend_from_slice(&order.to_le_bytes());
    }
    bytes
}

impl Writer {
    pub fn index(&self) -> usize {
        self.producer.index
    }

    pub fn write_record(
        &mut self,
        bytes: &[u8],
        mut wait: impl FnMut(&SharedBuffer, u32) -> Result<(), PublishError>,
    ) -> Result<RecordCommit, PublishError> {
        let result = self.write_inner(bytes, &mut wait);
        if let Err(error) = result {
            self.producer.broken = true;
            if error != PublishError::Stopped {
                self.buffer.fault();
            }
        }
        result
    }

    fn send(
        &mut self,
        frame: Frame,
        wait: &mut impl FnMut(&SharedBuffer, u32) -> Result<(), PublishError>,
    ) -> Result<(), PublishError> {
        loop {
            let progress = self.buffer.mapping.progress();
            self.buffer.check(self.role)?;
            match self.buffer.mapping.publish(self.producer.index, frame) {
                Err(PublishError::Full) => wait(&self.buffer.mapping, progress)?,
                result => return result,
            }
        }
    }

    fn write_inner(
        &mut self,
        bytes: &[u8],
        wait: &mut impl FnMut(&SharedBuffer, u32) -> Result<(), PublishError>,
    ) -> Result<RecordCommit, PublishError> {
        if self.producer.broken || self.producer.finished || self.producer.sequence == u64::MAX {
            return Err(PublishError::Invalid);
        }
        let ticket = loop {
            let progress = self.buffer.mapping.progress();
            match self.buffer.reserve(
                self.role,
                self.producer.index,
                self.producer.sequence,
                bytes.len(),
            ) {
                Err(PublishError::Full) => wait(&self.buffer.mapping, progress)?,
                result => break result?,
            }
        };
        self.send(
            self.producer
                .frame(super::BEGIN, bytes.len(), 0, &metadata(ticket, None)),
            wait,
        )?;
        for (index, chunk) in bytes.chunks(PAYLOAD).enumerate() {
            self.send(
                self.producer
                    .frame(super::DATA, bytes.len(), index * PAYLOAD, chunk),
                wait,
            )?;
        }
        let mut frame = self.producer.frame(
            super::END,
            bytes.len(),
            bytes.len(),
            &metadata(ticket, Some(0)),
        );
        let mapping = &self.buffer.mapping;
        let channel = mapping.channel(self.producer.index);
        let (head, next) = loop {
            let progress = mapping.progress();
            self.buffer.check(self.role)?;
            let head = channel.head.load(Ordering::Relaxed);
            let next = head.checked_add(1).ok_or(PublishError::Overflow)?;
            let tail = channel.tail.load(Ordering::Acquire);
            if head.checked_sub(tail).ok_or(PublishError::Invalid)? < mapping.header().slots {
                break (head, next);
            }
            wait(mapping, progress)?;
        };
        frame.ordinal = head;
        let slot = mapping.slot(self.producer.index, head);
        let credit = self.buffer.credit(ticket.index)?;
        let entrant = self.buffer.enter(self.role)?;
        self.buffer.check(self.role)?;
        let order = header(mapping)
            .next_order
            .try_update(Ordering::AcqRel, Ordering::Acquire, |order| {
                order.checked_add(1)
            })
            .map_err(|_| PublishError::Overflow)?;
        frame.payload[16..24].copy_from_slice(&order.to_le_bytes());
        credit.order.store(order, Ordering::Relaxed);
        credit.state.store(COMMITTED, Ordering::Relaxed);
        unsafe {
            slot.write(frame);
        }
        channel.head.store(next, Ordering::Release);
        drop(entrant);
        self.producer.sequence += 1;
        Ok(RecordCommit { order })
    }

    pub fn finish(
        &mut self,
        mut wait: impl FnMut(&SharedBuffer, u32) -> Result<(), PublishError>,
    ) -> Result<(), PublishError> {
        self.buffer.check(self.role)?;
        if self.producer.broken || self.producer.finished || self.producer.sequence == u64::MAX {
            return Err(PublishError::Invalid);
        }
        if let Err(error) = self.send(self.producer.frame(super::FINISH, 0, 0, &[]), &mut wait) {
            self.producer.broken = true;
            return Err(error);
        }
        let channel = self.buffer.mapping.channel(self.producer.index);
        channel
            .terminal_sequence
            .store(self.producer.sequence, Ordering::Relaxed);
        channel
            .terminal_head
            .store(channel.head.load(Ordering::Relaxed), Ordering::Relaxed);
        channel.state.store(super::FINISHED, Ordering::Release);
        self.producer.finished = true;
        Ok(())
    }
}

struct Partial {
    ticket: Ticket,
    length: usize,
    bytes: Vec<u8>,
}

pub struct Record {
    buffer: Arc<Buffer>,
    ticket: Ticket,
    order: u64,
    producer: usize,
    bytes: Vec<u8>,
}

impl Record {
    pub fn order(&self) -> u64 {
        self.order
    }
    pub fn producer(&self) -> usize {
        self.producer
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn release(self) -> Result<(), PublishError> {
        let credit = self.buffer.credit(self.ticket.index)?;
        if credit.generation.load(Ordering::Acquire) != self.ticket.generation
            || credit.order.load(Ordering::Acquire) != self.order
            || credit
                .state
                .compare_exchange(COMMITTED, RELEASING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(self.buffer.fault());
        }
        let role = if self.producer == 0 {
            Role::Host
        } else {
            Role::Guest
        };
        let length = credit.length.load(Ordering::Relaxed);
        drop(self.bytes);
        header(&self.buffer.mapping).used[role.index()].fetch_sub(length, Ordering::AcqRel);
        credit.state.store(FREE, Ordering::Release);
        self.buffer.mapping.wake();
        Ok(())
    }
}

pub struct Collector {
    buffer: Arc<Buffer>,
    partial: Vec<Option<Partial>>,
    sequences: Vec<u64>,
    finished: Vec<bool>,
    rejected: Vec<Option<Frame>>,
    pending: BTreeMap<u64, Record>,
    next: u64,
}

fn number(frame: &Frame, offset: usize) -> u64 {
    u64::from_le_bytes(
        frame.payload[offset..offset + 8]
            .try_into()
            .expect("fixed metadata"),
    )
}

impl Collector {
    pub fn guest_drained(&self) -> bool {
        (1..self.buffer.mapping.allocated()).all(|index| {
            let channel = self.buffer.mapping.channel(index);
            channel.head.load(Ordering::Acquire) == channel.tail.load(Ordering::Acquire)
        })
    }
    pub fn guest_complete(&self) -> bool {
        !self.buffer.order_failed()
            && !self.buffer.guest_failed()
            && (1..self.buffer.mapping.allocated()).all(|index| {
                let channel = self.buffer.mapping.channel(index);
                let state = channel.state.load(Ordering::Acquire);
                if index > 1 && state == super::CANCELLED_FORK {
                    return channel.fork_result.load(Ordering::Acquire) == u64::MAX;
                }
                state == super::FINISHED
                    && channel.pid.load(Ordering::Acquire) != 0
                    && channel.fork_result.load(Ordering::Acquire)
                        == channel.pid.load(Ordering::Acquire)
                    && channel.head.load(Ordering::Acquire) == channel.tail.load(Ordering::Acquire)
                    && channel.head.load(Ordering::Acquire)
                        == channel.terminal_head.load(Ordering::Acquire)
                    && self.finished[index]
                    && self.partial[index].is_none()
                    && channel.terminal_sequence.load(Ordering::Acquire) == self.sequences[index]
            })
    }

    /// Split capture requires an actual channel-zero FINISH, unlike the local API.
    pub(crate) fn host_complete(&self) -> bool {
        if self.buffer.order_failed()
            || self.buffer.mapping.failure() != 0
            || self.buffer.mapping.allocated() == 0
        {
            return false;
        }
        let channel = self.buffer.mapping.channel(0);
        channel.state.load(Ordering::Acquire) == super::FINISHED
            && channel.pid.load(Ordering::Acquire) != 0
            && channel.fork_result.load(Ordering::Acquire) == channel.pid.load(Ordering::Acquire)
            && channel.head.load(Ordering::Acquire) == channel.tail.load(Ordering::Acquire)
            && channel.head.load(Ordering::Acquire) == channel.terminal_head.load(Ordering::Acquire)
            && self.finished[0]
            && self.partial[0].is_none()
            && self.rejected[0].is_none()
            && channel.terminal_sequence.load(Ordering::Acquire) == self.sequences[0]
    }

    pub fn host_partial(&self) -> bool {
        self.partial[0].is_some()
    }

    pub fn diagnostics(&self, mut remaining: usize) -> (Vec<super::super::Stream>, u64) {
        let mut omitted = 0;
        let streams = (0..self.buffer.mapping.allocated())
            .map(|index| {
                let channel = self.buffer.mapping.channel(index);
                let mut stream = super::super::Stream {
                    incarnation: index as u64 + 1,
                    pid: channel.pid.load(Ordering::Acquire),
                    parent: channel.parent.load(Ordering::Acquire) as u64,
                    finished: self.finished[index],
                    complete_records: self.sequences[index] - 1,
                    unread_frames: channel
                        .head
                        .load(Ordering::Acquire)
                        .saturating_sub(channel.tail.load(Ordering::Acquire)),
                    rejected_frame: self.rejected[index].map(super::super::RejectedFrame::capture),
                    ..Default::default()
                };
                if let Some(partial) = &self.partial[index] {
                    let retained = remaining.min(partial.bytes.len());
                    stream
                        .fragment
                        .extend_from_slice(&partial.bytes[..retained]);
                    stream.fragment_sequence = Some(self.sequences[index]);
                    remaining -= retained;
                    omitted += (partial.bytes.len() - retained) as u64;
                }
                for record in self
                    .pending
                    .values()
                    .filter(|record| record.producer == index)
                {
                    let retained = remaining.min(record.bytes.len());
                    stream.bytes.extend_from_slice(&record.bytes[..retained]);
                    remaining -= retained;
                    omitted += (record.bytes.len() - retained) as u64;
                }
                stream
            })
            .collect();
        (streams, omitted)
    }

    fn accept(&mut self, index: usize, frame: Frame) -> Result<(), PublishError> {
        if self.finished[index]
            || frame.sequence != self.sequences[index]
            || frame.length as usize > PAYLOAD
        {
            return Err(PublishError::Invalid);
        }
        match frame.kind {
            super::BEGIN => {
                if self.partial[index].is_some() || frame.length != 16 || frame.offset != 0 {
                    return Err(PublishError::Invalid);
                }
                let ticket = Ticket {
                    index: number(&frame, 0)
                        .try_into()
                        .map_err(|_| PublishError::Invalid)?,
                    generation: number(&frame, 8),
                };
                let credit = self.buffer.credit(ticket.index)?;
                if ![RESERVED, COMMITTED].contains(&credit.state.load(Ordering::Acquire))
                    || credit.generation.load(Ordering::Relaxed) != ticket.generation
                    || credit.producer.load(Ordering::Relaxed) != index as u64
                    || credit.sequence.load(Ordering::Relaxed) != frame.sequence
                    || credit.length.load(Ordering::Relaxed) != frame.total
                    || frame.total > header(&self.buffer.mapping).max_record_bytes
                {
                    return Err(PublishError::Invalid);
                }
                self.partial[index] = Some(Partial {
                    ticket,
                    length: frame.total as usize,
                    bytes: Vec::with_capacity(frame.total as usize),
                });
            }
            super::DATA => {
                let partial = self.partial[index].as_mut().ok_or(PublishError::Invalid)?;
                if frame.total != partial.length as u64
                    || frame.offset != partial.bytes.len() as u64
                    || frame.length == 0
                    || (frame.length as usize) > partial.length - partial.bytes.len()
                {
                    return Err(PublishError::Invalid);
                }
                partial
                    .bytes
                    .extend_from_slice(&frame.payload[..frame.length as usize]);
            }
            super::END => {
                let partial = self.partial[index].as_ref().ok_or(PublishError::Invalid)?;
                let order = number(&frame, 16);
                let credit = self.buffer.credit(partial.ticket.index)?;
                if frame.length != 24
                    || frame.total != partial.length as u64
                    || frame.offset != frame.total
                    || partial.bytes.len() != partial.length
                    || number(&frame, 0) != partial.ticket.index as u64
                    || number(&frame, 8) != partial.ticket.generation
                    || order < self.next
                    || self.pending.contains_key(&order)
                    || credit.state.load(Ordering::Acquire) != COMMITTED
                    || credit.order.load(Ordering::Relaxed) != order
                {
                    return Err(PublishError::Invalid);
                }
                let partial = self.partial[index].take().expect("validated partial");
                self.pending.insert(
                    order,
                    Record {
                        buffer: self.buffer.clone(),
                        ticket: partial.ticket,
                        order,
                        producer: index,
                        bytes: partial.bytes,
                    },
                );
                self.sequences[index] = self.sequences[index]
                    .checked_add(1)
                    .ok_or(PublishError::Overflow)?;
            }
            super::FINISH => {
                if self.partial[index].is_some()
                    || frame.length != 0
                    || frame.total != 0
                    || frame.offset != 0
                {
                    return Err(PublishError::Invalid);
                }
                self.finished[index] = true;
            }
            _ => return Err(PublishError::Invalid),
        }
        Ok(())
    }

    pub fn poll(&mut self) -> Result<Option<Record>, PublishError> {
        let mapping = self.buffer.clone();
        let mut error = false;
        if mapping.mapping.allocated() > self.sequences.len() {
            return Err(self.buffer.fault());
        }
        for index in 0..mapping.mapping.allocated() {
            if self.rejected[index].is_some() {
                continue;
            }
            for _ in 0..mapping.mapping.options().slots {
                let frame = match mapping.mapping.read(index) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(_) => {
                        self.buffer.fault();
                        error = true;
                        break;
                    }
                };
                if self.accept(index, frame).is_err() {
                    self.rejected[index] = Some(frame);
                    self.buffer.fault();
                    error = true;
                    break;
                }
                mapping.mapping.consume(index);
            }
        }
        if error || self.buffer.order_failed() {
            return Err(PublishError::Invalid);
        }
        let record = self.pending.remove(&self.next);
        if record.is_some() {
            self.next = self
                .next
                .checked_add(1)
                .ok_or_else(|| self.buffer.fault())?;
        }
        Ok(record)
    }

    pub fn commits_observed(&self) -> Result<bool, PublishError> {
        if self.buffer.order_failed() {
            return Err(PublishError::Invalid);
        }
        for role in [Role::Host, Role::Guest] {
            let admission = self.buffer.admission(role);
            if !admission.closed || admission.entrants != 0 {
                return Ok(false);
            }
        }
        for index in 0..self.buffer.mapping.allocated() {
            let channel = self.buffer.mapping.channel(index);
            if channel.head.load(Ordering::Acquire) != channel.tail.load(Ordering::Acquire) {
                return Ok(false);
            }
        }
        if self.pending.contains_key(&self.next) {
            return Ok(false);
        }
        if !self.pending.is_empty()
            || self.next
                != header(&self.buffer.mapping)
                    .next_order
                    .load(Ordering::Acquire)
        {
            return Err(self.buffer.fault());
        }
        Ok(true)
    }
}

#[cfg(test)]
#[path = "ordered_tests.rs"]
mod tests;

#[cfg(test)]
mod split_host_tests {
    use std::os::fd::AsRawFd;

    use super::*;
    #[test]
    fn split_host_finish_requires_every_terminal_component() {
        let limits = Limits {
            producers: 2,
            slots: 8,
            max_record_bytes: 32,
            host_pending_bytes: 64,
            guest_pending_bytes: 64,
            pending_records: 4,
        };
        let (host, _guest) = unsafe { channel_pair(limits) }.unwrap();
        let buffer = unsafe { Buffer::receive(host.as_raw_fd()) }.unwrap();
        let mut writer = unsafe { buffer.activate(0, 17) }.unwrap();
        let mut collector = buffer.collector().unwrap();
        assert!(!collector.host_complete());
        writer.finish(|_, _| panic!("unexpected wait")).unwrap();
        assert!(!collector.host_complete(), "undecoded FINISH");
        assert!(collector.poll().unwrap().is_none());
        assert!(collector.host_complete());
        let channel = buffer.mapping.channel(0);
        macro_rules! atomic_opposition {
            ($field:expr, $bad:expr) => {{
                let old = $field.swap($bad, Ordering::AcqRel);
                assert!(!collector.host_complete());
                $field.store(old, Ordering::Release);
                assert!(collector.host_complete());
            }};
        }
        atomic_opposition!(channel.state, super::super::CANCELLED_FORK);
        atomic_opposition!(channel.pid, 0);
        atomic_opposition!(channel.fork_result, 18);
        atomic_opposition!(channel.head, 77);
        atomic_opposition!(channel.tail, 77);
        atomic_opposition!(channel.terminal_head, 77);
        atomic_opposition!(channel.terminal_sequence, 77);
        atomic_opposition!(header(&buffer.mapping).order_fault, 1);
        atomic_opposition!(buffer.mapping.header().failure, 1);
        collector.finished[0] = false;
        assert!(!collector.host_complete());
        collector.finished[0] = true;
        collector.sequences[0] += 1;
        assert!(!collector.host_complete());
        collector.sequences[0] -= 1;
        collector.rejected[0] = Some(Frame {
            ordinal: 0,
            kind: 0,
            length: 0,
            sequence: 0,
            offset: 0,
            total: 0,
            payload: [0; PAYLOAD],
        });
        assert!(!collector.host_complete());
        collector.rejected[0] = None;
        collector.partial[0] = Some(Partial {
            ticket: Ticket {
                index: 0,
                generation: 0,
            },
            length: 0,
            bytes: vec![],
        });
        assert!(!collector.host_complete());
        collector.partial[0] = None;
        assert!(collector.host_complete());
    }
}
