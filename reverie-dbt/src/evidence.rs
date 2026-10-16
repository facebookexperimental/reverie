/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Authenticated transport for canonical DBT runtime evidence.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::SocketAddr;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

const CHANNEL_MAGIC: &[u8; 8] = b"RVDBTE3\0";
const CHANNEL_HEADER_LEN: usize = 80;
const CHANNEL_TOKEN_LEN: usize = 32;
const CHANNEL_NAME_LEN: usize = 16;
const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 256 * 1024 * 1024;
const MAX_EVIDENCE_PROCESSES: usize = 8192;

const FRAME_START: u8 = 1;
const FRAME_DATA: u8 = 2;
const FRAME_EXEC: u8 = 3;
const FRAME_EXEC_CANCEL: u8 = 4;
const FRAME_FINAL: u8 = 5;
const FRAME_ERROR: u8 = 6;
const FRAME_CHILD: u8 = 7;
const FINAL_GUEST_COMPLETED: u8 = 0;
const FINAL_BACKEND_FAILURE: u8 = 1;

const FILE_MAGIC: &[u8; 8] = b"RVDBTEF1";
const FILE_VERSION: u16 = 1;
const FILE_HEADER_LEN: usize = 40;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const CANONICAL_RECORD_PREFIX: &[u8] = b"1970-01-01T00:00:00.000000Z ";
const INITIALIZATION_RECORD: &[u8] =
    b"1970-01-01T00:00:00.000000Z INFO reverie_dbt::evidence: protected evidence initialized\n";
/// The initialization record with its length prefix, as it enters the stream.
const ENCODED_INITIALIZATION_LEN: usize = 4 + INITIALIZATION_RECORD.len();
const INITIALIZATION_MESSAGE_PREFIX: &[u8] = b"reverie_dbt::evidence: protected evidence init";
const SESSION_NEW: u8 = 0;
const SESSION_RUNNING: u8 = 1;
const SESSION_FINISHING: u8 = 2;
const SESSION_FINISHED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalOutcome {
    GuestCompleted,
    BackendFailure,
}

impl TryFrom<&[u8]> for FinalOutcome {
    type Error = io::Error;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        match payload {
            [FINAL_GUEST_COMPLETED] => Ok(Self::GuestCompleted),
            [FINAL_BACKEND_FAILURE] => Ok(Self::BackendFailure),
            [_] => Err(invalid_data("DBT evidence FINAL frame outcome is unknown")),
            _ => Err(invalid_data(
                "DBT evidence FINAL frame outcome has the wrong length",
            )),
        }
    }
}

#[derive(Debug)]
struct DbtBackendFailure;

impl std::fmt::Display for DbtBackendFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DBT backend or Tool reported an internal failure")
    }
}

impl std::error::Error for DbtBackendFailure {}

#[derive(Clone, Debug, Default)]
struct AcknowledgementDropControl {
    #[cfg(test)]
    remaining: Arc<AtomicU8>,
}

impl AcknowledgementDropControl {
    #[cfg(test)]
    fn should_drop(&self) -> bool {
        self.remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }

    #[cfg(not(test))]
    fn should_drop(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn drop_next(&self) {
        self.remaining.store(1, Ordering::Release);
    }
}

/// Protected tracing verbosity requested from the external DBT runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum DbtEvidenceLogLevel {
    /// Do not install a structured evidence subscriber.
    Off = 0,
    /// Emit error records.
    Error = 1,
    /// Emit warning and error records.
    Warn = 2,
    /// Emit canonical INFO records (the verification default).
    #[default]
    Info = 3,
    /// Emit INFO plus debug records.
    Debug = 4,
    /// Emit the complete tracing stream.
    Trace = 5,
}

impl DbtEvidenceLogLevel {
    pub(crate) const fn code(self) -> i32 {
        self as i32
    }
}

/// A fully validated framed evidence stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbtEvidence {
    records: Vec<Vec<u8>>,
    initialization_records: usize,
    /// Position in the full authenticated stream of each initialization
    /// record counted by `initialization_records`, in increasing order.
    initialization_positions: Vec<usize>,
}

impl DbtEvidence {
    /// Comparable tracing-callback records in authenticated stream order.
    ///
    /// Process image initialization records remain authenticated in the
    /// artifact but are represented by [`Self::initialization_records`]
    /// instead. [`Self::all_records`] keeps them at their stream positions.
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Every authenticated record in stream order, with each process image
    /// initialization record at its position in the artifact.
    ///
    /// The decoder admits only initialization records that are byte-for-byte
    /// the protocol constant, so this returns the authenticated bytes and
    /// invents no record or position. The collector that wrote the artifact
    /// placed each initialization record immediately before the first
    /// comparable record of its process image, or at the end of the stream
    /// when that image wrote none, so its position does not depend on when
    /// the host accepted the frame that carried it.
    ///
    /// Initialization records prove that the transport started, not that the
    /// guest did anything. A stream holding only initialization records is
    /// returned here while [`Self::records`] is empty, so a consumer that
    /// requires guest evidence must count [`Self::records`] instead.
    pub fn all_records(&self) -> Vec<&[u8]> {
        let mut all = Vec::with_capacity(self.records.len() + self.initialization_positions.len());
        let mut records = self.records.iter().map(Vec::as_slice);
        for &position in &self.initialization_positions {
            // The comparable records that precede this initialization.
            all.extend(records.by_ref().take(position - all.len()));
            all.push(INITIALIZATION_RECORD);
        }
        all.extend(records);
        all
    }

    /// Number of validated process image initialization records in the artifact.
    pub fn initialization_records(&self) -> usize {
        self.initialization_records
    }

    /// Consumes the stream and returns its comparable tracing-callback records.
    pub fn into_records(self) -> Vec<Vec<u8>> {
        self.records
    }
}

/// Decodes the framed artifact produced by [`crate::DbtRunner::evidence_file`].
///
/// Every record must be one bounded tracing record with exactly one terminal
/// newline. Embedded CR/LF bytes are rejected so a guest-controlled field
/// cannot synthesize an additional parser-visible INFO line.
pub fn decode_evidence(bytes: &[u8]) -> io::Result<DbtEvidence> {
    if bytes.len() < FILE_HEADER_LEN
        || bytes.len() > FILE_HEADER_LEN + MAX_EVIDENCE_BYTES
        || &bytes[..8] != FILE_MAGIC
    {
        return Err(invalid_data("DBT evidence has no valid file header"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let header_len = u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    if version != FILE_VERSION || header_len != FILE_HEADER_LEN || reserved != 0 {
        return Err(invalid_data("DBT evidence has an unsupported header"));
    }
    let expected_records = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let expected_payload = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let expected_hash = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    if expected_records > ((bytes.len() - FILE_HEADER_LEN) / 5) as u64 {
        return Err(invalid_data(
            "DBT evidence record count exceeds its file bound",
        ));
    }

    let mut cursor = FILE_HEADER_LEN;
    let mut payload_bytes = 0_u64;
    let mut hash = FNV_OFFSET;
    let mut raw_records = Vec::new();
    while cursor < bytes.len() {
        let length_end = cursor
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid_data("DBT evidence ends inside a record length"))?;
        let encoded_length: [u8; 4] = bytes[cursor..length_end].try_into().unwrap();
        let length = u32::from_le_bytes(encoded_length) as usize;
        if length == 0 || length > MAX_FRAME_PAYLOAD {
            return Err(invalid_data("DBT evidence record length is invalid"));
        }
        let record_end = length_end
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid_data("DBT evidence ends inside a record"))?;
        let record = &bytes[length_end..record_end];
        validate_record(record)?;
        hash = fnv_update(hash, &encoded_length);
        hash = fnv_update(hash, record);
        payload_bytes = payload_bytes
            .checked_add(length as u64)
            .ok_or_else(|| invalid_data("DBT evidence payload length overflowed"))?;
        raw_records.push(record.to_vec());
        cursor = record_end;
    }
    if raw_records.len() as u64 != expected_records
        || payload_bytes != expected_payload
        || hash != expected_hash
    {
        return Err(invalid_data(
            "DBT evidence count, byte length, or digest does not match its header",
        ));
    }

    let mut records = Vec::with_capacity(raw_records.len());
    let mut initialization_records = 0_usize;
    let mut initialization_positions = Vec::new();
    for (position, record) in raw_records.into_iter().enumerate() {
        match classify_initialization_record(&record) {
            InitializationRecord::Exact => {
                initialization_records =
                    initialization_records.checked_add(1).ok_or_else(|| {
                        invalid_data("DBT evidence initialization record count overflowed")
                    })?;
                initialization_positions.push(position);
            }
            InitializationRecord::Lookalike => {
                return Err(invalid_data(
                    "DBT evidence contains a malformed initialization record",
                ));
            }
            InitializationRecord::Other => records.push(record),
        }
    }
    if initialization_records == 0 {
        return Err(invalid_data(
            "DBT evidence contains no process image initialization record",
        ));
    }
    Ok(DbtEvidence {
        records,
        initialization_records,
        initialization_positions,
    })
}

/// The collector the socket worker and the coordinator's in-process appender
/// share. Both absorb under this one lock, so the collected stream is the
/// order in which records were absorbed. `None` once the worker has finished.
#[derive(Clone)]
struct SharedCollector(Arc<Mutex<Option<Collector>>>);

impl SharedCollector {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Some(Collector::new()))))
    }

    fn with<T>(&self, absorb: impl FnOnce(&mut Collector) -> io::Result<T>) -> io::Result<T> {
        match self.0.lock().unwrap().as_mut() {
            Some(collector) => absorb(collector),
            None => Err(io::Error::other(
                "DBT evidence collector was already finished",
            )),
        }
    }

    fn take(&self) -> io::Result<Collector> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| io::Error::other("DBT evidence collector was already finished"))
    }
}

impl std::fmt::Debug for SharedCollector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SharedCollector")
    }
}

/// Appends records emitted by the coordinator, the host process that owns a
/// coordinated DBT run's global state, to that run's protected evidence.
///
/// The coordinator's tool emits records too (under Detcore, the scheduler's),
/// and they belong in the run's stream at the point they happened. Each guest
/// record is absorbed before the guest callback that emitted it returns, and a
/// guest that asks the coordinator for something waits for the reply. So a
/// coordinator record appended when it is emitted lands after every guest
/// record that preceded the request and before every guest record that follows
/// the reply: appending at emission time is the order in which they happened.
#[derive(Clone, Debug)]
pub struct CoordinatorEvidence {
    collector: SharedCollector,
}

impl CoordinatorEvidence {
    /// Appends one record: a canonical tracing record with exactly one
    /// terminal newline, as a guest emits. A record that imitates a process
    /// image initialization record is refused, as is any record after the
    /// run's evidence was finished.
    pub fn append(&self, record: &[u8]) -> io::Result<()> {
        self.collector
            .with(|collector| collector.absorb_coordinator_record(record))
    }
}

#[derive(Debug)]
pub(crate) struct EvidenceSession {
    address_hex: String,
    token_hex: String,
    root_process: Arc<Mutex<Option<ProcessKey>>>,
    stop: Arc<AtomicBool>,
    #[cfg(test)]
    acknowledgement_drops: AcknowledgementDropControl,
    lifecycle: AtomicU8,
    finish_lock: Mutex<()>,
    output: Mutex<Option<File>>,
    worker: Mutex<Option<JoinHandle<io::Result<CollectedEvidence>>>>,
    result: Mutex<Option<Result<(), String>>>,
    collector: SharedCollector,
    /// Set when the run's finish was deferred: whether publication is allowed.
    deferred_publication: Mutex<Option<bool>>,
}

impl EvidenceSession {
    pub(crate) fn new(file: &File) -> io::Result<Self> {
        validate_output_file(file)?;
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;

        let mut randomness = [0_u8; CHANNEL_NAME_LEN + CHANNEL_TOKEN_LEN];
        File::open("/dev/urandom")?.read_exact(&mut randomness)?;
        let address = &randomness[..CHANNEL_NAME_LEN];
        let token: [u8; CHANNEL_TOKEN_LEN] = randomness[CHANNEL_NAME_LEN..]
            .try_into()
            .expect("fixed token length");
        let socket_address = SocketAddr::from_abstract_name(address)?;
        let listener = UnixListener::bind_addr(&socket_address)?;
        listener.set_nonblocking(true)?;

        let root_process = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_root_process = Arc::clone(&root_process);
        let worker_stop = Arc::clone(&stop);
        let acknowledgement_drops = AcknowledgementDropControl::default();
        let worker_acknowledgement_drops = acknowledgement_drops.clone();
        let collector = SharedCollector::new();
        let worker_collector = collector.clone();
        let worker = std::thread::Builder::new()
            .name("reverie-dbt-evidence".into())
            .spawn(move || {
                serve(
                    listener,
                    token,
                    worker_root_process,
                    worker_stop,
                    worker_acknowledgement_drops,
                    worker_collector,
                )
            })?;

        Ok(Self {
            address_hex: encode_hex(address),
            token_hex: encode_hex(&token),
            root_process,
            stop,
            #[cfg(test)]
            acknowledgement_drops,
            lifecycle: AtomicU8::new(SESSION_NEW),
            finish_lock: Mutex::new(()),
            output: Mutex::new(Some(output)),
            worker: Mutex::new(Some(worker)),
            result: Mutex::new(None),
            collector,
            deferred_publication: Mutex::new(None),
        })
    }

    /// The appender for records the coordinator emits into this run.
    pub(crate) fn coordinator_evidence(&self) -> CoordinatorEvidence {
        CoordinatorEvidence {
            collector: self.collector.clone(),
        }
    }

    /// Records the launcher's publication decision for a finish deferred
    /// until [`Self::finish_deferred`].
    pub(crate) fn defer_finish(&self, publication_allowed: bool) {
        *self.deferred_publication.lock().unwrap() = Some(publication_allowed);
    }

    /// Finishes a deferred run with the publication decision recorded by
    /// [`Self::defer_finish`]; a run whose decision was never recorded did not
    /// prove its process-tree cleanup and is not published.
    pub(crate) fn finish_deferred(&self) -> io::Result<()> {
        let publication_allowed = self.deferred_publication.lock().unwrap().unwrap_or(false);
        self.finish(publication_allowed)
    }

    pub(crate) fn client_arguments(&self) -> [String; 4] {
        [
            "-evidence-socket".into(),
            self.address_hex.clone(),
            "-evidence-token".into(),
            self.token_hex.clone(),
        ]
    }

    #[cfg(test)]
    pub(crate) fn drop_next_acknowledgement(&self) {
        self.acknowledgement_drops.drop_next();
    }

    pub(crate) fn claim_run(&self) -> io::Result<()> {
        self.lifecycle
            .compare_exchange(
                SESSION_NEW,
                SESSION_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "DBT evidence collector is one-shot and was already launched",
                )
            })?;
        Ok(())
    }

    pub(crate) fn publish_root(&self, pid: u32) -> io::Result<()> {
        if self.lifecycle.load(Ordering::Acquire) != SESSION_RUNNING {
            return Err(io::Error::other(
                "DBT evidence root was published outside its running lifecycle",
            ));
        }
        let root = ProcessKey {
            pid,
            start_time: process_start_time(pid)?,
        };
        let mut slot = self.root_process.lock().unwrap();
        if slot.replace(root).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "DBT evidence root process was already published",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(&self, publication_allowed: bool) -> io::Result<()> {
        let _finish_guard = self.finish_lock.lock().unwrap();
        if let Some(result) = self.result.lock().unwrap().as_ref() {
            return result
                .as_ref()
                .map_err(|message| io::Error::other(message.clone()))
                .copied();
        }

        if self
            .lifecycle
            .compare_exchange(
                SESSION_RUNNING,
                SESSION_FINISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(io::Error::other(
                "DBT evidence collector was finalized outside its one-run lifecycle",
            ));
        }

        let final_result =
            (|| {
                self.stop.store(true, Ordering::Release);
                let worker = self.worker.lock().unwrap().take();
                let collected = match worker {
                    Some(worker) => worker
                        .join()
                        .map_err(|_| io::Error::other("DBT evidence collector thread panicked"))?,
                    None => Err(io::Error::other(
                        "DBT evidence collector was already consumed without a result",
                    )),
                };
                let mut output =
                    self.output.lock().unwrap().take().ok_or_else(|| {
                        io::Error::other("DBT evidence output was already finalized")
                    })?;
                finalize_output(&mut output, collected, publication_allowed)
            })();
        self.lifecycle.store(SESSION_FINISHED, Ordering::Release);
        let stored = final_result.as_ref().map_err(ToString::to_string).copied();
        *self.result.lock().unwrap() = Some(stored);
        final_result
    }
}

impl Drop for EvidenceSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.get_mut().unwrap().take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProcessKey {
    pid: u32,
    start_time: u64,
}

#[derive(Debug)]
struct ImageState {
    epoch: u64,
    next_sequence: u64,
    pending_exec: bool,
    initialized: bool,
    /// The image's initialization record was accepted but not yet placed in
    /// the stream, because the image has written no comparable record.
    initialization_unplaced: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameReceipt {
    kind: u8,
    sequence: u64,
    digest: [u8; 16],
}

struct CollectedEvidence {
    encoded_records: Vec<u8>,
    record_count: u64,
    payload_bytes: u64,
    hash: u64,
}

/// Collects the run's evidence stream.
///
/// Guest and coordinator records enter the stream in the order they are
/// absorbed. A process image's initialization record is the exception: the
/// image's runtime emits it when it starts, and nothing orders that moment
/// against the records other images are writing, so the host can accept it
/// anywhere among them. The collector holds it back and places it immediately
/// before the image's first comparable record, which the run's own ordering
/// positions. An image that ends, or execs, without writing a
/// comparable record has its initialization record placed at the end of the
/// stream. Every such record is the same protocol constant, so their order
/// there carries nothing.
///
/// A held-back record counts against the memory bound from the moment it is
/// accepted, so the collected stream plus every record still to be placed
/// never exceeds `byte_limit`.
struct Collector {
    images: BTreeMap<ProcessKey, ImageState>,
    expected_processes: BTreeSet<ProcessKey>,
    terminal_processes: BTreeSet<ProcessKey>,
    last_receipts: BTreeMap<ProcessKey, FrameReceipt>,
    /// Initialization records of images that ended without writing a
    /// comparable record; [`Collector::finish`] places them at the end.
    trailing_initializations: u64,
    /// Encoded bytes of the accepted initialization records not yet in
    /// `encoded_records`: those held by live images and the trailing ones.
    held_initialization_bytes: usize,
    byte_limit: usize,
    encoded_records: Vec<u8>,
    record_count: u64,
    payload_bytes: u64,
    hash: u64,
    saw_start: bool,
    backend_failure: bool,
}

impl Collector {
    fn new() -> Self {
        Self::with_byte_limit(MAX_EVIDENCE_BYTES)
    }

    fn with_byte_limit(byte_limit: usize) -> Self {
        Self {
            images: BTreeMap::new(),
            expected_processes: BTreeSet::new(),
            terminal_processes: BTreeSet::new(),
            last_receipts: BTreeMap::new(),
            trailing_initializations: 0,
            held_initialization_bytes: 0,
            byte_limit,
            encoded_records: Vec::new(),
            record_count: 0,
            payload_bytes: 0,
            hash: FNV_OFFSET,
            saw_start: false,
            backend_failure: false,
        }
    }

    fn absorb(
        &mut self,
        kind: u8,
        process: ProcessKey,
        sequence: u64,
        payload: &[u8],
    ) -> io::Result<()> {
        match kind {
            FRAME_START => {
                if sequence != 0 || !payload.is_empty() {
                    return Err(invalid_data("malformed DBT evidence START frame"));
                }
                if self.terminal_processes.contains(&process) {
                    return Err(invalid_data(
                        "DBT evidence process restarted after its FINAL frame",
                    ));
                }
                if !self.has_known_process(process)
                    && self.process_state_count() >= MAX_EVIDENCE_PROCESSES
                {
                    return Err(invalid_data(
                        "DBT evidence exceeded its process/image state bound",
                    ));
                }
                let (epoch, replaced_unplaced) = match self.images.get(&process) {
                    Some(previous) if previous.pending_exec => (
                        previous
                            .epoch
                            .checked_add(1)
                            .ok_or_else(|| invalid_data("DBT evidence image epoch overflowed"))?,
                        previous.initialization_unplaced,
                    ),
                    Some(_) => {
                        return Err(invalid_data(
                            "DBT evidence image restarted without a pending exec",
                        ));
                    }
                    None => (0, false),
                };
                if replaced_unplaced {
                    self.defer_to_end()?;
                }
                self.images.insert(
                    process,
                    ImageState {
                        epoch,
                        next_sequence: 1,
                        pending_exec: false,
                        initialized: false,
                        initialization_unplaced: false,
                    },
                );
                self.saw_start = true;
            }
            FRAME_DATA => {
                {
                    let image = self.image_for(process, sequence)?;
                    if image.pending_exec {
                        return Err(invalid_data("DBT evidence arrived while exec was pending"));
                    }
                }
                self.absorb_records(process, payload)?;
                self.images
                    .get_mut(&process)
                    .expect("validated image remains live")
                    .next_sequence += 1;
            }
            FRAME_EXEC => {
                if !payload.is_empty() {
                    return Err(invalid_data("DBT evidence EXEC frame carried payload"));
                }
                self.require_initialized(process)?;
                let image = self.image_for(process, sequence)?;
                if image.pending_exec {
                    return Err(invalid_data("DBT evidence nested an exec transition"));
                }
                image.pending_exec = true;
                image.next_sequence += 1;
            }
            FRAME_EXEC_CANCEL => {
                if !payload.is_empty() {
                    return Err(invalid_data(
                        "DBT evidence EXEC_CANCEL frame carried payload",
                    ));
                }
                self.require_initialized(process)?;
                let image = self.image_for(process, sequence)?;
                if !image.pending_exec {
                    return Err(invalid_data(
                        "DBT evidence cancelled an exec that was not pending",
                    ));
                }
                image.pending_exec = false;
                image.next_sequence += 1;
            }
            FRAME_FINAL => {
                let outcome = FinalOutcome::try_from(payload)?;
                self.require_initialized(process)?;
                let image = self.image_for(process, sequence)?;
                if image.pending_exec {
                    return Err(invalid_data("DBT evidence finalized with exec pending"));
                }
                let image = self
                    .images
                    .remove(&process)
                    .expect("validated image remains live");
                if image.initialization_unplaced {
                    self.defer_to_end()?;
                }
                self.terminal_processes.insert(process);
                self.backend_failure |= outcome == FinalOutcome::BackendFailure;
            }
            FRAME_ERROR => {
                let detail = String::from_utf8_lossy(payload);
                return Err(io::Error::other(format!(
                    "DBT evidence client reported a transport error: {detail}"
                )));
            }
            FRAME_CHILD => {
                if payload.len() != 12 {
                    return Err(invalid_data("malformed DBT evidence CHILD frame"));
                }
                let child = ProcessKey {
                    pid: u32::from_le_bytes(payload[..4].try_into().unwrap()),
                    start_time: u64::from_le_bytes(payload[4..].try_into().unwrap()),
                };
                if child.pid == 0 || child == process {
                    return Err(invalid_data("DBT evidence CHILD identity is invalid"));
                }
                self.require_initialized(process)?;
                let image = self.image_for(process, sequence)?;
                if image.pending_exec {
                    return Err(invalid_data(
                        "DBT evidence announced a child while exec was pending",
                    ));
                }
                image.next_sequence += 1;
                if self.expected_processes.contains(&child) {
                    return Err(invalid_data("DBT evidence announced a child twice"));
                }
                if !self.has_known_process(child)
                    && self.process_state_count() >= MAX_EVIDENCE_PROCESSES
                {
                    return Err(invalid_data(
                        "DBT evidence exceeded its process/image state bound",
                    ));
                }
                self.expected_processes.insert(child);
            }
            _ => return Err(invalid_data("DBT evidence frame kind is unknown")),
        }
        Ok(())
    }

    fn absorb_or_acknowledge_retry(
        &mut self,
        kind: u8,
        process: ProcessKey,
        sequence: u64,
        digest: [u8; 16],
        payload: &[u8],
    ) -> io::Result<()> {
        let receipt = FrameReceipt {
            kind,
            sequence,
            digest,
        };
        if self.last_receipts.get(&process) == Some(&receipt) {
            return Ok(());
        }
        if self
            .last_receipts
            .get(&process)
            .is_some_and(|previous| previous.sequence == sequence)
        {
            return Err(invalid_data("DBT evidence retry changed an accepted frame"));
        }
        self.absorb(kind, process, sequence, payload)?;
        self.last_receipts.insert(process, receipt);
        Ok(())
    }

    fn image_for(&mut self, process: ProcessKey, sequence: u64) -> io::Result<&mut ImageState> {
        let image = self
            .images
            .get_mut(&process)
            .ok_or_else(|| invalid_data("DBT evidence frame preceded image START"))?;
        if image.next_sequence != sequence {
            return Err(invalid_data("DBT evidence frame sequence diverged"));
        }
        Ok(image)
    }

    fn has_admitted(&self, process: ProcessKey) -> bool {
        self.images.contains_key(&process) || self.terminal_processes.contains(&process)
    }

    fn has_known_process(&self, process: ProcessKey) -> bool {
        self.has_admitted(process) || self.expected_processes.contains(&process)
    }

    fn process_state_count(&self) -> usize {
        self.images
            .keys()
            .chain(&self.expected_processes)
            .chain(&self.terminal_processes)
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn require_initialized(&self, process: ProcessKey) -> io::Result<()> {
        if self
            .images
            .get(&process)
            .is_some_and(|image| image.initialized)
        {
            Ok(())
        } else {
            Err(invalid_data(
                "DBT evidence process image lifecycle preceded its initialization record",
            ))
        }
    }

    /// Counts one held-back initialization record for the end of the stream.
    fn defer_to_end(&mut self) -> io::Result<()> {
        self.trailing_initializations = self
            .trailing_initializations
            .checked_add(1)
            .ok_or_else(|| invalid_data("DBT evidence record count overflowed"))?;
        Ok(())
    }

    fn absorb_records(&mut self, process: ProcessKey, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Err(invalid_data("DBT DATA frame carried no records"));
        }
        let mut cursor = 0;
        let image = self
            .images
            .get(&process)
            .expect("DATA sequence validation requires a live image");
        let mut initialized = image.initialized;
        let mut unplaced = image.initialization_unplaced;
        // The frame's records as they enter the stream: an initialization
        // record is held back until the image's first comparable record.
        let mut placed = Vec::with_capacity(payload.len());
        let mut held_bytes = self.held_initialization_bytes;
        let mut record_count = 0_u64;
        let mut payload_bytes = 0_u64;
        while cursor < payload.len() {
            let length_end = cursor
                .checked_add(4)
                .filter(|end| *end <= payload.len())
                .ok_or_else(|| invalid_data("DBT DATA ends inside a record length"))?;
            let encoded_length: [u8; 4] = payload[cursor..length_end].try_into().unwrap();
            let length = u32::from_le_bytes(encoded_length) as usize;
            if length == 0 || length > MAX_FRAME_PAYLOAD {
                return Err(invalid_data("DBT DATA record length is invalid"));
            }
            let record_end = length_end
                .checked_add(length)
                .filter(|end| *end <= payload.len())
                .ok_or_else(|| invalid_data("DBT DATA ends inside a record"))?;
            let record = &payload[length_end..record_end];
            validate_record(record)?;
            match classify_initialization_record(record) {
                InitializationRecord::Exact if initialized => {
                    return Err(invalid_data(
                        "DBT evidence process image repeated its initialization record",
                    ));
                }
                InitializationRecord::Exact => {
                    initialized = true;
                    unplaced = true;
                    held_bytes = held_bytes
                        .checked_add(ENCODED_INITIALIZATION_LEN)
                        .ok_or_else(|| invalid_data("DBT evidence exceeded its memory bound"))?;
                }
                InitializationRecord::Lookalike => {
                    return Err(invalid_data(
                        "DBT evidence contains a malformed initialization record",
                    ));
                }
                InitializationRecord::Other if !initialized => {
                    return Err(invalid_data(
                        "DBT evidence process image data preceded its initialization record",
                    ));
                }
                InitializationRecord::Other => {
                    if unplaced {
                        unplaced = false;
                        held_bytes -= ENCODED_INITIALIZATION_LEN;
                        encode_initialization_record(&mut placed);
                        record_count = record_count
                            .checked_add(1)
                            .ok_or_else(|| invalid_data("DBT evidence record count overflowed"))?;
                        payload_bytes = payload_bytes
                            .checked_add(INITIALIZATION_RECORD.len() as u64)
                            .ok_or_else(|| {
                                invalid_data("DBT evidence payload length overflowed")
                            })?;
                    }
                    placed.extend_from_slice(&payload[cursor..record_end]);
                    record_count = record_count
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("DBT evidence record count overflowed"))?;
                    payload_bytes = payload_bytes
                        .checked_add(length as u64)
                        .ok_or_else(|| invalid_data("DBT evidence payload length overflowed"))?;
                }
            }
            cursor = record_end;
        }

        self.append_encoded(&placed, record_count, payload_bytes, held_bytes)?;
        let image = self
            .images
            .get_mut(&process)
            .expect("validated DATA process remains live");
        image.initialized = initialized;
        image.initialization_unplaced = unplaced;
        Ok(())
    }

    /// Absorbs one record the coordinator emitted. It belongs to no guest
    /// process image, so it is checked as a record and never as image
    /// lifecycle: it must be one canonical tracing record and must not imitate
    /// an initialization record, which only a guest image may emit.
    fn absorb_coordinator_record(&mut self, record: &[u8]) -> io::Result<()> {
        validate_record(record)?;
        if !matches!(
            classify_initialization_record(record),
            InitializationRecord::Other
        ) {
            return Err(invalid_data(
                "DBT coordinator record imitates a process image initialization record",
            ));
        }
        let length = u32::try_from(record.len())
            .map_err(|_| invalid_data("DBT coordinator record is too long"))?;
        let mut payload = Vec::with_capacity(4 + record.len());
        payload.extend_from_slice(&length.to_le_bytes());
        payload.extend_from_slice(record);
        self.append_encoded(
            &payload,
            1,
            u64::from(length),
            self.held_initialization_bytes,
        )
    }

    /// Appends length-prefixed records to the collected stream, leaving
    /// `held_bytes` of accepted initialization records still to be placed.
    /// The stream and the held records together must fit the memory bound.
    fn append_encoded(
        &mut self,
        payload: &[u8],
        record_count: u64,
        payload_bytes: u64,
        held_bytes: usize,
    ) -> io::Result<()> {
        let new_len = self
            .encoded_records
            .len()
            .checked_add(payload.len())
            .filter(|length| {
                length
                    .checked_add(held_bytes)
                    .is_some_and(|total| total <= self.byte_limit)
            })
            .ok_or_else(|| invalid_data("DBT evidence exceeded its memory bound"))?;
        self.encoded_records
            .reserve(new_len - self.encoded_records.len());
        self.encoded_records.extend_from_slice(payload);
        self.held_initialization_bytes = held_bytes;
        self.hash = fnv_update(self.hash, payload);
        self.record_count = self
            .record_count
            .checked_add(record_count)
            .ok_or_else(|| invalid_data("DBT evidence record count overflowed"))?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(payload_bytes)
            .ok_or_else(|| invalid_data("DBT evidence payload length overflowed"))?;
        Ok(())
    }

    fn finish(mut self) -> io::Result<CollectedEvidence> {
        if !self.saw_start {
            return Err(invalid_data("DBT evidence received no image START"));
        }
        if self.backend_failure {
            return Err(io::Error::other(DbtBackendFailure));
        }
        if self.images.values().any(|image| !image.initialized) {
            return Err(invalid_data(
                "DBT evidence is missing a process image initialization record",
            ));
        }
        if !self.images.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "DBT evidence is missing FINAL frames for process images {:?}",
                    self.images
                ),
            ));
        }
        if !self.expected_processes.is_subset(&self.terminal_processes) {
            return Err(invalid_data(
                "DBT evidence is missing a child process START or FINAL frame",
            ));
        }
        // Every image is final, so the held records are exactly the trailing
        // ones. Size the tail and check it against the bound before
        // allocating it.
        let trailing_len = usize::try_from(self.trailing_initializations)
            .ok()
            .and_then(|count| count.checked_mul(ENCODED_INITIALIZATION_LEN))
            .filter(|length| {
                self.encoded_records
                    .len()
                    .checked_add(*length)
                    .is_some_and(|total| total <= self.byte_limit)
            })
            .ok_or_else(|| invalid_data("DBT evidence exceeded its memory bound"))?;
        let trailing_bytes = self
            .trailing_initializations
            .checked_mul(INITIALIZATION_RECORD.len() as u64)
            .ok_or_else(|| invalid_data("DBT evidence payload length overflowed"))?;
        let mut trailing = Vec::with_capacity(trailing_len);
        for _ in 0..self.trailing_initializations {
            encode_initialization_record(&mut trailing);
        }
        self.append_encoded(&trailing, self.trailing_initializations, trailing_bytes, 0)?;
        Ok(CollectedEvidence {
            encoded_records: self.encoded_records,
            record_count: self.record_count,
            payload_bytes: self.payload_bytes,
            hash: self.hash,
        })
    }
}

/// Appends the length-prefixed initialization record to a collected stream.
fn encode_initialization_record(stream: &mut Vec<u8>) {
    stream.extend_from_slice(&(INITIALIZATION_RECORD.len() as u32).to_le_bytes());
    stream.extend_from_slice(INITIALIZATION_RECORD);
}

fn serve(
    listener: UnixListener,
    token: [u8; CHANNEL_TOKEN_LEN],
    root_process: Arc<Mutex<Option<ProcessKey>>>,
    stop: Arc<AtomicBool>,
    acknowledgement_drops: AcknowledgementDropControl,
    collector: SharedCollector,
) -> io::Result<CollectedEvidence> {
    let mut shutdown_connections = 0_u32;
    loop {
        let stopping = stop.load(Ordering::Acquire);
        match listener.accept() {
            Ok((mut stream, _)) => {
                if stopping {
                    shutdown_connections += 1;
                    if shutdown_connections > 64 {
                        return Err(io::Error::other(
                            "DBT evidence collector shutdown backlog exceeded its bound",
                        ));
                    }
                }
                stream.set_read_timeout(Some(Duration::from_millis(250)))?;
                stream.set_write_timeout(Some(Duration::from_millis(250)))?;
                if let Err(error) = handle_connection(
                    &mut stream,
                    &token,
                    &root_process,
                    &collector,
                    &acknowledgement_drops,
                ) {
                    let _ = stream.write_all(&[1]);
                    return Err(error);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stopping {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    collector.take()?.finish()
}

fn handle_connection(
    stream: &mut UnixStream,
    token: &[u8; CHANNEL_TOKEN_LEN],
    root_process: &Mutex<Option<ProcessKey>>,
    collector: &SharedCollector,
    acknowledgement_drops: &AcknowledgementDropControl,
) -> io::Result<()> {
    let mut header = [0_u8; CHANNEL_HEADER_LEN];
    if stream.read_exact(&mut header).is_err() {
        return Ok(());
    }
    if &header[..8] != CHANNEL_MAGIC || !constant_time_equal(&header[8..40], token) {
        let _ = stream.write_all(&[1]);
        return Ok(());
    }
    let kind = header[40];
    if header[41..48].iter().any(|byte| *byte != 0) || header[52..56].iter().any(|byte| *byte != 0)
    {
        return Err(invalid_data(
            "DBT evidence frame reserved bytes are nonzero",
        ));
    }
    let payload_len = u32::from_le_bytes(header[48..52].try_into().unwrap()) as usize;
    let sequence = u64::from_le_bytes(header[56..64].try_into().unwrap());
    let digest: [u8; 16] = header[64..80].try_into().unwrap();
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(invalid_data("DBT evidence frame payload is too large"));
    }

    let peer = peer_credentials(stream)?;
    if peer.pid <= 0 || peer.uid != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DBT evidence peer credentials are invalid",
        ));
    }
    let pid = peer.pid as u32;
    let root = wait_for_root_process(root_process)?;
    let process = ProcessKey {
        pid,
        start_time: process_start_time(pid)?,
    };
    if !collector.with(|collector| Ok(collector.has_admitted(process)))?
        && !initial_peer_is_admissible(process, root)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DBT evidence peer is outside the launched process tree",
        ));
    }
    let mut payload = vec![0; payload_len];
    if let Err(error) = stream.read_exact(&mut payload) {
        if matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionReset
        ) {
            return Ok(());
        }
        return Err(error);
    }
    let expected_digest = frame_digest(kind, sequence, &payload);
    if !constant_time_equal(&digest, &expected_digest) {
        return Err(invalid_data("DBT evidence frame digest is invalid"));
    }
    collector.with(|collector| {
        collector.absorb_or_acknowledge_retry(kind, process, sequence, digest, &payload)
    })?;
    // The frame is durable in collector state before the ACK. If the peer
    // times out and closes here, its exact retry is acknowledged idempotently.
    if acknowledgement_drops.should_drop() {
        return Ok(());
    }
    let _ = stream.write_all(&[0]);
    Ok(())
}

fn peer_credentials(stream: &UnixStream) -> io::Result<libc::ucred> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(invalid_data(
            "DBT evidence peer credentials have the wrong size",
        ));
    }
    Ok(credentials)
}

fn wait_for_root_process(root_process: &Mutex<Option<ProcessKey>>) -> io::Result<ProcessKey> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(root) = *root_process.lock().unwrap() {
            return Ok(root);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DBT evidence root pid was not published after spawn",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn process_start_time(pid: u32) -> io::Result<u64> {
    Ok(process_stat(pid)?.start_time)
}

struct ProcessStat {
    parent: u32,
    process_group: i32,
    #[cfg(test)]
    session: i32,
    start_time: u64,
}

fn process_stat(pid: u32) -> io::Result<ProcessStat> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_name = stat
        .rsplit_once(')')
        .map(|(_, tail)| tail.trim_start())
        .ok_or_else(|| invalid_data("DBT evidence peer has malformed proc stat data"))?;
    // The tail starts at field 3 (`state`); process starttime is field 22.
    let fields: Vec<_> = after_name.split_ascii_whitespace().collect();
    let parent = fields
        .get(1)
        .ok_or_else(|| invalid_data("DBT evidence peer proc stat lacks a parent"))?
        .parse()
        .map_err(|_| invalid_data("DBT evidence peer parent pid is malformed"))?;
    let process_group = fields
        .get(2)
        .ok_or_else(|| invalid_data("DBT evidence peer proc stat lacks a process group"))?
        .parse()
        .map_err(|_| invalid_data("DBT evidence peer process group is malformed"))?;
    #[cfg(test)]
    let session = fields
        .get(3)
        .ok_or_else(|| invalid_data("DBT evidence peer proc stat lacks a session"))?
        .parse()
        .map_err(|_| invalid_data("DBT evidence peer session is malformed"))?;
    let start_time = fields
        .get(19)
        .ok_or_else(|| invalid_data("DBT evidence peer proc stat lacks starttime"))?
        .parse()
        .map_err(|_| invalid_data("DBT evidence peer starttime is malformed"))?;
    Ok(ProcessStat {
        parent,
        process_group,
        #[cfg(test)]
        session,
        start_time,
    })
}

fn is_process_descendant(mut process: ProcessKey, root: ProcessKey) -> bool {
    for _ in 0..256 {
        let Ok(stat) = process_stat(process.pid) else {
            return false;
        };
        if stat.start_time != process.start_time {
            return false;
        }
        if process == root {
            return true;
        }
        if stat.parent == 0 || stat.parent == process.pid {
            return false;
        }
        let Ok(parent_start_time) = process_start_time(stat.parent) else {
            return false;
        };
        process = ProcessKey {
            pid: stat.parent,
            start_time: parent_start_time,
        };
    }
    false
}

fn is_isolated_process_group_member(process: ProcessKey, root_pid: u32) -> bool {
    let Ok(stat) = process_stat(process.pid) else {
        return false;
    };
    stat.start_time == process.start_time && stat.process_group == root_pid as i32
}

/// Whether `process` is a process of the run that lost its parent and was
/// adopted by this process: where the launcher is its PID namespace's init,
/// the namespace holds only the run, so every orphan of the run becomes its
/// child, whatever process group or session the guest put it in.
fn is_reparented_run_process(process: ProcessKey, root: ProcessKey) -> bool {
    let Ok(stat) = process_stat(process.pid) else {
        return false;
    };
    stat.start_time == process.start_time
        && process.pid != root.pid
        && stat.parent == std::process::id()
        && process.start_time >= root.start_time
}

fn initial_peer_is_admissible(process: ProcessKey, root: ProcessKey) -> bool {
    // A process of the run is the root's descendant. Once its parent exited:
    // where the launcher is its PID namespace's init (as under Hermit), it is
    // the launcher's child, whatever process group or session the guest put
    // it in; elsewhere the launcher put the run in a dedicated process group,
    // which reparenting does not change. pid+starttime prevents reuse from
    // inheriting admission.
    is_process_descendant(process, root)
        || (std::process::id() == 1 && is_reparented_run_process(process, root))
        || is_isolated_process_group_member(process, root.pid)
}

fn publish(output: &mut File, collected: CollectedEvidence) -> io::Result<()> {
    let mut header = [0_u8; FILE_HEADER_LEN];
    header[..8].copy_from_slice(FILE_MAGIC);
    header[8..10].copy_from_slice(&FILE_VERSION.to_le_bytes());
    header[10..12].copy_from_slice(&(FILE_HEADER_LEN as u16).to_le_bytes());
    header[16..24].copy_from_slice(&collected.record_count.to_le_bytes());
    header[24..32].copy_from_slice(&collected.payload_bytes.to_le_bytes());
    header[32..40].copy_from_slice(&collected.hash.to_le_bytes());
    output.write_all(&header)?;
    output.write_all(&collected.encoded_records)?;
    output.flush()
}

fn finalize_output(
    output: &mut File,
    collected: io::Result<CollectedEvidence>,
    publication_allowed: bool,
) -> io::Result<()> {
    // The caller's inode was never authoritative. Erase any guest mutation
    // before considering either the authenticated collector result or the
    // launcher's process-tree cleanup proof.
    output.set_len(0)?;
    output.seek(SeekFrom::Start(0))?;
    let collected = collected?;
    if !publication_allowed {
        return Err(io::Error::other(
            "DBT evidence publication refused because process-tree cleanup was not proven",
        ));
    }
    publish(output, collected)
}

fn validate_output_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 0 || metadata.len() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DBT evidence output must be a fresh, empty, anonymous regular file",
        ));
    }
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DBT evidence output must be opened read-write",
        ));
    }
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if descriptor_flags == -1
        || unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn validate_record(record: &[u8]) -> io::Result<()> {
    if record.is_empty()
        || record.len() > MAX_FRAME_PAYLOAD
        || record.last() != Some(&b'\n')
        || record[..record.len() - 1]
            .iter()
            .any(|byte| matches!(*byte, b'\r' | b'\n'))
    {
        return Err(invalid_data(
            "DBT evidence record is not exactly one terminal-newline tracing record",
        ));
    }
    let tagged = record
        .strip_prefix(CANONICAL_RECORD_PREFIX)
        .ok_or_else(|| invalid_data("DBT evidence record has no canonical timestamp prefix"))?;
    if ![
        b"ERROR ".as_slice(),
        b"WARN ",
        b"INFO ",
        b"DEBUG ",
        b"TRACE ",
    ]
    .iter()
    .any(|prefix| tagged.starts_with(prefix))
    {
        return Err(invalid_data("DBT evidence record has no tracing level tag"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializationRecord {
    Exact,
    Lookalike,
    Other,
}

fn classify_initialization_record(record: &[u8]) -> InitializationRecord {
    if record == INITIALIZATION_RECORD {
        return InitializationRecord::Exact;
    }
    let Some(tagged) = record.strip_prefix(CANONICAL_RECORD_PREFIX) else {
        return InitializationRecord::Other;
    };
    let message = [
        b"ERROR ".as_slice(),
        b"WARN ",
        b"INFO ",
        b"DEBUG ",
        b"TRACE ",
    ]
    .iter()
    .find_map(|level| tagged.strip_prefix(*level));
    if message.is_some_and(|message| message.starts_with(INITIALIZATION_MESSAGE_PREFIX)) {
        InitializationRecord::Lookalike
    } else {
        InitializationRecord::Other
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn fnv_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    hash
}

fn frame_digest(kind: u8, sequence: u64, payload: &[u8]) -> [u8; 16] {
    let length = (payload.len() as u32).to_le_bytes();
    let sequence = sequence.to_le_bytes();
    let mut first = fnv_update(FNV_OFFSET, &[kind]);
    first = fnv_update(first, &length);
    first = fnv_update(first, &sequence);
    first = fnv_update(first, payload);
    let mut second = fnv_update(0x9e37_79b9_7f4a_7c15, &[kind]);
    second = fnv_update(second, &length);
    second = fnv_update(second, &sequence);
    second = fnv_update(second, payload);
    let mut digest = [0; 16];
    digest[..8].copy_from_slice(&first.to_le_bytes());
    digest[8..].copy_from_slice(&second.to_le_bytes());
    digest
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_RECORD: &[u8] = b"1970-01-01T00:00:00.000000Z INFO detcore: first\n";
    const SECOND_RECORD: &[u8] = b"1970-01-01T00:00:00.000000Z DEBUG detcore: second\n";

    fn encode_records(records: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for record in records {
            encoded.extend_from_slice(&(record.len() as u32).to_le_bytes());
            encoded.extend_from_slice(record);
        }
        encoded
    }

    fn encode_artifact(records: &[&[u8]]) -> Vec<u8> {
        let encoded_records = encode_records(records);
        let payload_bytes: u64 = records.iter().map(|record| record.len() as u64).sum();
        let mut bytes = vec![0; FILE_HEADER_LEN];
        bytes[..8].copy_from_slice(FILE_MAGIC);
        bytes[8..10].copy_from_slice(&FILE_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(FILE_HEADER_LEN as u16).to_le_bytes());
        bytes[16..24].copy_from_slice(&(records.len() as u64).to_le_bytes());
        bytes[24..32].copy_from_slice(&payload_bytes.to_le_bytes());
        bytes[32..40].copy_from_slice(&fnv_update(FNV_OFFSET, &encoded_records).to_le_bytes());
        bytes.extend_from_slice(&encoded_records);
        bytes
    }

    fn start_and_initialize(collector: &mut Collector, process: ProcessKey) {
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        collector
            .absorb(
                FRAME_DATA,
                process,
                1,
                &encode_records(&[INITIALIZATION_RECORD]),
            )
            .unwrap();
    }

    #[test]
    fn framed_evidence_round_trips_and_rejects_injected_lines() {
        let raw_records = [INITIALIZATION_RECORD, FIRST_RECORD, SECOND_RECORD];
        let evidence = decode_evidence(&encode_artifact(&raw_records)).unwrap();
        assert_eq!(evidence.initialization_records(), 1);
        assert_eq!(evidence.records(), [FIRST_RECORD, SECOND_RECORD]);

        let injected = b"1970-01-01T00:00:00.000000Z INFO detcore: guest=ok\n1970-01-01T00:00:00.000000Z INFO detcore: forged\n";
        assert!(validate_record(injected).is_err());
    }

    #[test]
    fn decoder_rejects_truncation_and_digest_changes() {
        let mut bytes = encode_artifact(&[INITIALIZATION_RECORD, FIRST_RECORD]);

        assert!(decode_evidence(&bytes[..bytes.len() - 1]).is_err());
        *bytes.last_mut().unwrap() ^= 1;
        assert!(decode_evidence(&bytes).is_err());
    }

    #[test]
    fn decoder_requires_exact_initialization_and_rejects_lookalikes() {
        let debug_lookalike = b"1970-01-01T00:00:00.000000Z DEBUG reverie_dbt::evidence: protected evidence initialized\n";
        let suffixed_lookalike = b"1970-01-01T00:00:00.000000Z INFO reverie_dbt::evidence: protected evidence initialized twice\n";

        let missing = decode_evidence(&encode_artifact(&[FIRST_RECORD])).unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("no process image initialization")
        );
        assert!(decode_evidence(&encode_artifact(&[debug_lookalike])).is_err());
        assert!(
            decode_evidence(&encode_artifact(&[
                INITIALIZATION_RECORD,
                suffixed_lookalike,
            ]))
            .is_err()
        );

        let mut unauthenticated = encode_artifact(&[FIRST_RECORD]);
        unauthenticated[32] ^= 1;
        let error = decode_evidence(&unauthenticated).unwrap_err();
        assert!(
            error.to_string().contains("digest does not match"),
            "raw artifact must be authenticated before semantic decoding: {error}"
        );
    }

    #[test]
    fn decoder_filters_each_authenticated_process_image_initialization_record() {
        let raw_records = [
            INITIALIZATION_RECORD,
            FIRST_RECORD,
            INITIALIZATION_RECORD,
            SECOND_RECORD,
        ];
        let evidence = decode_evidence(&encode_artifact(&raw_records)).unwrap();
        assert_eq!(evidence.initialization_records(), 2);
        assert_eq!(evidence.records(), [FIRST_RECORD, SECOND_RECORD]);
    }

    #[test]
    fn independent_artifacts_return_only_comparable_records() {
        let first = decode_evidence(&encode_artifact(&[
            INITIALIZATION_RECORD,
            FIRST_RECORD,
            SECOND_RECORD,
        ]))
        .unwrap();
        let second = decode_evidence(&encode_artifact(&[
            INITIALIZATION_RECORD,
            FIRST_RECORD,
            SECOND_RECORD,
        ]))
        .unwrap();

        assert_eq!(first.initialization_records(), 1);
        assert_eq!(second.initialization_records(), 1);
        assert_eq!(first.into_records(), second.into_records());
    }

    #[test]
    fn collector_rejects_data_and_lifecycle_before_initialization() {
        let process = ProcessKey {
            pid: 11,
            start_time: 13,
        };
        let ordinary = encode_records(&[FIRST_RECORD]);
        let mut collector = Collector::new();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        assert!(collector.absorb(FRAME_DATA, process, 1, &[]).is_err());
        let error = collector
            .absorb(FRAME_DATA, process, 1, &ordinary)
            .unwrap_err();
        assert!(error.to_string().contains("data preceded"));
        let error = collector.absorb(FRAME_EXEC, process, 1, &[]).unwrap_err();
        assert!(error.to_string().contains("lifecycle preceded"));
        let error = collector.finish().err().unwrap();
        assert!(
            error
                .to_string()
                .contains("missing a process image initialization")
        );

        let mut child_payload = Vec::from(19_u32.to_le_bytes());
        child_payload.extend_from_slice(&23_u64.to_le_bytes());
        for (kind, payload) in [
            (FRAME_EXEC_CANCEL, Vec::new()),
            (FRAME_FINAL, vec![FINAL_GUEST_COMPLETED]),
            (FRAME_CHILD, child_payload),
        ] {
            let mut collector = Collector::new();
            collector.absorb(FRAME_START, process, 0, &[]).unwrap();
            let error = collector.absorb(kind, process, 1, &payload).unwrap_err();
            assert!(
                error.to_string().contains("lifecycle preceded"),
                "frame kind {kind} was not refused for missing initialization: {error}"
            );
        }
    }

    #[test]
    fn collector_rejects_duplicate_malformed_and_truncated_initialization() {
        let process = ProcessKey {
            pid: 13,
            start_time: 17,
        };
        let initialization = encode_records(&[INITIALIZATION_RECORD]);
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, process);
        let duplicate = collector
            .absorb(FRAME_DATA, process, 2, &initialization)
            .unwrap_err();
        assert!(duplicate.to_string().contains("repeated"));

        let debug_lookalike = encode_records(&[
            b"1970-01-01T00:00:00.000000Z DEBUG reverie_dbt::evidence: protected evidence initialized\n",
        ]);
        let mut collector = Collector::new();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        let malformed = collector
            .absorb(FRAME_DATA, process, 1, &debug_lookalike)
            .unwrap_err();
        assert!(malformed.to_string().contains("malformed initialization"));

        let mut truncated = initialization;
        truncated.pop();
        let mut collector = Collector::new();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        assert!(
            collector
                .absorb(FRAME_DATA, process, 1, &truncated)
                .is_err()
        );
    }

    #[test]
    fn collector_retains_process_image_initializations_in_the_raw_artifact() {
        let first_process = ProcessKey {
            pid: 19,
            start_time: 23,
        };
        let second_process = ProcessKey {
            pid: 29,
            start_time: 31,
        };
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, first_process);
        collector
            .absorb(
                FRAME_DATA,
                first_process,
                2,
                &encode_records(&[FIRST_RECORD]),
            )
            .unwrap();
        start_and_initialize(&mut collector, second_process);
        collector
            .absorb(
                FRAME_DATA,
                second_process,
                2,
                &encode_records(&[SECOND_RECORD]),
            )
            .unwrap();
        collector
            .absorb(FRAME_FINAL, first_process, 3, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector
            .absorb(FRAME_FINAL, second_process, 3, &[FINAL_GUEST_COMPLETED])
            .unwrap();

        let collected = collector.finish().unwrap();
        assert_eq!(collected.record_count, 4);
        let mut output = tempfile::tempfile().unwrap();
        publish(&mut output, collected).unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).unwrap();
        let evidence = decode_evidence(&bytes).unwrap();
        assert_eq!(evidence.initialization_records(), 2);
        assert_eq!(evidence.records(), [FIRST_RECORD, SECOND_RECORD]);
    }

    const COORDINATOR_RECORD: &[u8] =
        b"1970-01-01T00:00:00.000000Z INFO detcore::scheduler: [scheduler] guest in queue\n";

    #[test]
    fn coordinator_records_land_where_they_were_absorbed() {
        let process = ProcessKey {
            pid: 41,
            start_time: 43,
        };
        let shared = SharedCollector::new();
        let coordinator = CoordinatorEvidence {
            collector: shared.clone(),
        };
        // Before the guest starts, between two guest records, and after the
        // guest's FINAL frame: each lands at its absorption point.
        coordinator.append(COORDINATOR_RECORD).unwrap();
        shared
            .with(|collector| {
                start_and_initialize(collector, process);
                collector.absorb(FRAME_DATA, process, 2, &encode_records(&[FIRST_RECORD]))
            })
            .unwrap();
        coordinator.append(COORDINATOR_RECORD).unwrap();
        shared
            .with(|collector| {
                collector.absorb(FRAME_DATA, process, 3, &encode_records(&[SECOND_RECORD]))?;
                collector.absorb(FRAME_FINAL, process, 4, &[FINAL_GUEST_COMPLETED])
            })
            .unwrap();
        coordinator.append(COORDINATOR_RECORD).unwrap();

        let collected = shared.take().unwrap().finish().unwrap();
        assert_eq!(collected.record_count, 6);
        let mut output = tempfile::tempfile().unwrap();
        publish(&mut output, collected).unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).unwrap();
        let evidence = decode_evidence(&bytes).unwrap();
        assert_eq!(
            evidence.all_records(),
            [
                COORDINATOR_RECORD,
                INITIALIZATION_RECORD,
                FIRST_RECORD,
                COORDINATOR_RECORD,
                SECOND_RECORD,
                COORDINATOR_RECORD,
            ]
        );
        assert_eq!(evidence.initialization_records(), 1);
    }

    #[test]
    fn coordinator_records_are_refused_unless_canonical_and_comparable() {
        let shared = SharedCollector::new();
        let coordinator = CoordinatorEvidence {
            collector: shared.clone(),
        };
        // Only a guest image may announce an image initialization.
        assert!(coordinator.append(INITIALIZATION_RECORD).is_err());
        let mut lookalike = INITIALIZATION_RECORD.to_vec();
        lookalike.insert(lookalike.len() - 1, b'!');
        assert!(coordinator.append(&lookalike).is_err());
        for malformed in [
            b"".as_slice(),
            b"INFO detcore: no canonical prefix\n",
            b"1970-01-01T00:00:00.000000Z INFO detcore: no newline",
            b"1970-01-01T00:00:00.000000Z INFO detcore: two\nlines\n",
            b"1970-01-01T00:00:00.000000Z NOTICE detcore: unknown level\n",
        ] {
            assert!(coordinator.append(malformed).is_err(), "{malformed:?}");
        }
        // Nothing refused reached the stream.
        assert_eq!(
            shared.with(|collector| Ok(collector.record_count)).unwrap(),
            0
        );
        // After the worker finishes, an append is refused rather than lost.
        let _ = shared.take().unwrap();
        assert!(coordinator.append(COORDINATOR_RECORD).is_err());
    }

    #[test]
    fn all_records_keeps_each_initialization_record_at_its_stream_position() {
        let streams: [&[&[u8]]; 5] = [
            &[INITIALIZATION_RECORD, FIRST_RECORD, SECOND_RECORD],
            &[
                INITIALIZATION_RECORD,
                INITIALIZATION_RECORD,
                FIRST_RECORD,
                SECOND_RECORD,
            ],
            &[
                INITIALIZATION_RECORD,
                FIRST_RECORD,
                INITIALIZATION_RECORD,
                SECOND_RECORD,
            ],
            &[
                INITIALIZATION_RECORD,
                FIRST_RECORD,
                SECOND_RECORD,
                INITIALIZATION_RECORD,
            ],
            // A comparable record before the first initialization record: the
            // collector writes one when the coordinator emits before the guest
            // starts.
            &[FIRST_RECORD, INITIALIZATION_RECORD, SECOND_RECORD],
        ];
        for raw_records in streams {
            let evidence = decode_evidence(&encode_artifact(raw_records)).unwrap();
            assert_eq!(evidence.all_records(), raw_records);
            assert_eq!(evidence.records(), [FIRST_RECORD, SECOND_RECORD]);
            assert_eq!(
                evidence.initialization_records(),
                raw_records
                    .iter()
                    .filter(|record| **record == INITIALIZATION_RECORD)
                    .count()
            );
        }
    }

    #[test]
    fn all_records_returns_an_initialization_only_stream_with_no_comparable_record() {
        for count in 1..=3 {
            let raw_records = vec![INITIALIZATION_RECORD; count];
            let evidence = decode_evidence(&encode_artifact(&raw_records)).unwrap();
            assert_eq!(evidence.all_records(), raw_records);
            assert!(evidence.records().is_empty());
            assert_eq!(evidence.initialization_records(), count);
        }
    }

    #[test]
    fn all_records_distinguishes_initialization_positions_that_the_count_hides() {
        let early = decode_evidence(&encode_artifact(&[
            INITIALIZATION_RECORD,
            INITIALIZATION_RECORD,
            FIRST_RECORD,
            SECOND_RECORD,
        ]))
        .unwrap();
        let late = decode_evidence(&encode_artifact(&[
            INITIALIZATION_RECORD,
            FIRST_RECORD,
            INITIALIZATION_RECORD,
            SECOND_RECORD,
        ]))
        .unwrap();

        assert_eq!(early.records(), late.records());
        assert_eq!(
            early.initialization_records(),
            late.initialization_records()
        );
        assert_ne!(early.all_records(), late.all_records());
        // Equality covers the positions too, so it agrees with all_records.
        assert_ne!(early, late);
    }

    fn published_artifact(collector: Collector) -> Vec<u8> {
        let collected = collector.finish().unwrap();
        let mut output = tempfile::tempfile().unwrap();
        publish(&mut output, collected).unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).unwrap();
        bytes
    }

    /// Where the host accepts a child's initialization frame among the
    /// parent's records, in the parent-and-child run below.
    #[derive(Clone, Copy, Debug)]
    enum ChildInitialization {
        /// Alone, right after the parent announces the child.
        AfterAnnouncement,
        /// Alone, after the parent's next record.
        AfterParentRecord,
        /// In the same frame as the child's first comparable record.
        WithFirstChildRecord,
    }

    const CHILD_RECORD: &[u8] = b"1970-01-01T00:00:00.000000Z INFO detcore: child\n";

    /// A parent writes FIRST, forks a child, and writes SECOND; then the child
    /// writes CHILD_RECORD (or, when `child_first`, before SECOND). Only the
    /// point where the host accepts the child's initialization varies.
    fn parent_and_child_artifact(
        initialization: ChildInitialization,
        child_first: bool,
    ) -> Vec<u8> {
        let parent = ProcessKey {
            pid: 41,
            start_time: 43,
        };
        let child = ProcessKey {
            pid: 47,
            start_time: 53,
        };
        let mut child_payload = Vec::from(child.pid.to_le_bytes());
        child_payload.extend_from_slice(&child.start_time.to_le_bytes());

        let mut collector = Collector::new();
        start_and_initialize(&mut collector, parent);
        collector
            .absorb(FRAME_DATA, parent, 2, &encode_records(&[FIRST_RECORD]))
            .unwrap();
        collector
            .absorb(FRAME_CHILD, parent, 3, &child_payload)
            .unwrap();
        let mut child_sequence = 1;
        let mut child_data = |collector: &mut Collector, records: &[&[u8]]| {
            collector
                .absorb(FRAME_DATA, child, child_sequence, &encode_records(records))
                .unwrap();
            child_sequence += 1;
        };
        if matches!(initialization, ChildInitialization::AfterAnnouncement) {
            collector.absorb(FRAME_START, child, 0, &[]).unwrap();
            child_data(&mut collector, &[INITIALIZATION_RECORD]);
        }
        let parent_second = |collector: &mut Collector| {
            collector
                .absorb(FRAME_DATA, parent, 4, &encode_records(&[SECOND_RECORD]))
                .unwrap();
        };
        if !child_first {
            parent_second(&mut collector);
        }
        match initialization {
            ChildInitialization::AfterAnnouncement => {}
            ChildInitialization::AfterParentRecord => {
                collector.absorb(FRAME_START, child, 0, &[]).unwrap();
                child_data(&mut collector, &[INITIALIZATION_RECORD]);
            }
            ChildInitialization::WithFirstChildRecord => {
                collector.absorb(FRAME_START, child, 0, &[]).unwrap();
            }
        }
        if matches!(initialization, ChildInitialization::WithFirstChildRecord) {
            child_data(&mut collector, &[INITIALIZATION_RECORD, CHILD_RECORD]);
        } else {
            child_data(&mut collector, &[CHILD_RECORD]);
        }
        if child_first {
            parent_second(&mut collector);
        }
        collector
            .absorb(FRAME_FINAL, child, child_sequence, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector
            .absorb(FRAME_FINAL, parent, 5, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        published_artifact(collector)
    }

    #[test]
    fn collector_places_a_child_initialization_wherever_the_host_accepted_it() {
        // Two runs of one guest differ only in where the host accepted the
        // child's initialization frame; see
        // https://github.com/rrnewton/hermit/issues/3838. The artifacts must
        // be identical, with the child's initialization record immediately
        // before the child's first comparable record.
        let canonical = parent_and_child_artifact(ChildInitialization::AfterAnnouncement, false);
        for initialization in [
            ChildInitialization::AfterParentRecord,
            ChildInitialization::WithFirstChildRecord,
        ] {
            assert_eq!(
                parent_and_child_artifact(initialization, false),
                canonical,
                "{initialization:?}"
            );
        }
        let evidence = decode_evidence(&canonical).unwrap();
        assert_eq!(
            evidence.all_records(),
            [
                INITIALIZATION_RECORD,
                FIRST_RECORD,
                SECOND_RECORD,
                INITIALIZATION_RECORD,
                CHILD_RECORD,
            ]
        );
        assert_eq!(evidence.initialization_records(), 2);
    }

    #[test]
    fn collector_keeps_the_order_of_comparable_records_across_images() {
        // Placing initialization records does not hide where the comparable
        // records were written: the child writing before the parent's second
        // record is a different stream.
        let parent_first = parent_and_child_artifact(ChildInitialization::AfterAnnouncement, false);
        let child_first = parent_and_child_artifact(ChildInitialization::AfterAnnouncement, true);
        assert_ne!(parent_first, child_first);
        assert_eq!(
            decode_evidence(&child_first).unwrap().all_records(),
            [
                INITIALIZATION_RECORD,
                FIRST_RECORD,
                INITIALIZATION_RECORD,
                CHILD_RECORD,
                SECOND_RECORD,
            ]
        );
    }

    #[test]
    fn collector_places_initializations_of_images_with_no_comparable_record_at_the_end() {
        let process = ProcessKey {
            pid: 59,
            start_time: 61,
        };
        let silent = ProcessKey {
            pid: 67,
            start_time: 71,
        };
        let mut collector = Collector::new();
        // An image that execs before writing a comparable record, then a
        // second image of the same process that writes one.
        start_and_initialize(&mut collector, process);
        collector.absorb(FRAME_EXEC, process, 2, &[]).unwrap();
        start_and_initialize(&mut collector, process);
        // A process that ends without writing a comparable record.
        start_and_initialize(&mut collector, silent);
        collector
            .absorb(FRAME_FINAL, silent, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector
            .absorb(FRAME_DATA, process, 2, &encode_records(&[FIRST_RECORD]))
            .unwrap();
        collector
            .absorb(FRAME_FINAL, process, 3, &[FINAL_GUEST_COMPLETED])
            .unwrap();

        let evidence = decode_evidence(&published_artifact(collector)).unwrap();
        assert_eq!(
            evidence.all_records(),
            [
                INITIALIZATION_RECORD,
                FIRST_RECORD,
                INITIALIZATION_RECORD,
                INITIALIZATION_RECORD,
            ]
        );
        // Every initialization record is still counted.
        assert_eq!(evidence.initialization_records(), 3);
    }

    #[test]
    fn collector_charges_held_initializations_against_the_memory_bound_when_accepted() {
        const IMAGES: usize = 12;
        let process = ProcessKey {
            pid: 73,
            start_time: 79,
        };
        let initialize = encode_records(&[INITIALIZATION_RECORD]);
        // Images of one process that each exec, and finally exit, without
        // writing a comparable record. The process key stays known, so the
        // process-state bound never limits how many there are.
        let mut collector = Collector::with_byte_limit(IMAGES * ENCODED_INITIALIZATION_LEN);
        for image in 0..IMAGES {
            collector.absorb(FRAME_START, process, 0, &[]).unwrap();
            collector
                .absorb(FRAME_DATA, process, 1, &initialize)
                .unwrap();
            if image + 1 < IMAGES {
                collector.absorb(FRAME_EXEC, process, 2, &[]).unwrap();
            }
        }
        collector
            .absorb(FRAME_FINAL, process, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        let collected = collector.finish().unwrap();
        assert_eq!(collected.record_count, IMAGES as u64);
        assert_eq!(
            collected.encoded_records.len(),
            IMAGES * ENCODED_INITIALIZATION_LEN
        );

        // One byte less: the last image's initialization record is refused
        // when it arrives, not after it was held and the tail was built.
        let mut collector = Collector::with_byte_limit(IMAGES * ENCODED_INITIALIZATION_LEN - 1);
        for _ in 1..IMAGES {
            collector.absorb(FRAME_START, process, 0, &[]).unwrap();
            collector
                .absorb(FRAME_DATA, process, 1, &initialize)
                .unwrap();
            collector.absorb(FRAME_EXEC, process, 2, &[]).unwrap();
        }
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        let refused = collector
            .absorb(FRAME_DATA, process, 1, &initialize)
            .unwrap_err();
        assert!(refused.to_string().contains("memory bound"), "{refused}");
    }

    #[test]
    fn comparable_records_cannot_spend_the_room_held_initializations_reserve() {
        let silent = ProcessKey {
            pid: 83,
            start_time: 89,
        };
        let writer = ProcessKey {
            pid: 97,
            start_time: 101,
        };
        let first = encode_records(&[FIRST_RECORD]);
        // Room for both images' initialization records and the writer's one
        // comparable record.
        let room = 2 * ENCODED_INITIALIZATION_LEN + first.len();

        let mut collector = Collector::with_byte_limit(room);
        start_and_initialize(&mut collector, silent);
        start_and_initialize(&mut collector, writer);
        collector.absorb(FRAME_DATA, writer, 2, &first).unwrap();
        collector
            .absorb(FRAME_FINAL, writer, 3, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector
            .absorb(FRAME_FINAL, silent, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        assert_eq!(collector.finish().unwrap().encoded_records.len(), room);

        // One byte less: the silent image's held record keeps its room, so
        // the writer's record is refused rather than the tail later.
        let mut collector = Collector::with_byte_limit(room - 1);
        start_and_initialize(&mut collector, silent);
        start_and_initialize(&mut collector, writer);
        let refused = collector.absorb(FRAME_DATA, writer, 2, &first).unwrap_err();
        assert!(refused.to_string().contains("memory bound"), "{refused}");

        // A coordinator record is charged against the same reserved room.
        let coordinator_room = ENCODED_INITIALIZATION_LEN + first.len();
        let mut collector = Collector::with_byte_limit(coordinator_room);
        start_and_initialize(&mut collector, silent);
        collector.absorb_coordinator_record(FIRST_RECORD).unwrap();
        let mut collector = Collector::with_byte_limit(coordinator_room - 1);
        start_and_initialize(&mut collector, silent);
        let refused = collector
            .absorb_coordinator_record(FIRST_RECORD)
            .unwrap_err();
        assert!(refused.to_string().contains("memory bound"), "{refused}");
    }

    #[test]
    fn collector_requires_exec_for_restart_and_reinitializes_the_new_image() {
        let process = ProcessKey {
            pid: 17,
            start_time: 23,
        };
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, process);
        assert!(collector.absorb(FRAME_START, process, 0, &[]).is_err());
        collector.absorb(FRAME_EXEC, process, 2, &[]).unwrap();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        collector
            .absorb(
                FRAME_DATA,
                process,
                1,
                &encode_records(&[INITIALIZATION_RECORD]),
            )
            .unwrap();
        collector
            .absorb(FRAME_FINAL, process, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        assert!(collector.absorb(FRAME_START, process, 0, &[]).is_err());
        assert_eq!(collector.finish().unwrap().record_count, 2);
    }

    #[test]
    fn collector_rejects_duplicate_final() {
        let process = ProcessKey {
            pid: 31,
            start_time: 37,
        };
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, process);
        collector
            .absorb(FRAME_FINAL, process, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        assert!(
            collector
                .absorb(FRAME_FINAL, process, 3, &[FINAL_GUEST_COMPLETED])
                .is_err()
        );
    }

    #[test]
    fn collector_requires_exact_final_outcome() {
        let process = ProcessKey {
            pid: 32,
            start_time: 38,
        };
        for (payload, expected) in [
            (Vec::new(), "wrong length"),
            (vec![FINAL_GUEST_COMPLETED, 0], "wrong length"),
            (vec![2], "unknown"),
        ] {
            let mut collector = Collector::new();
            start_and_initialize(&mut collector, process);
            let error = collector
                .absorb(FRAME_FINAL, process, 2, &payload)
                .unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "FINAL payload {payload:?} was refused for the wrong reason: {error}"
            );
        }
    }

    #[test]
    fn collector_refuses_a_backend_failure_from_any_process() {
        let root = ProcessKey {
            pid: 33,
            start_time: 39,
        };
        let child = ProcessKey {
            pid: 34,
            start_time: 40,
        };
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, root);
        start_and_initialize(&mut collector, child);
        collector
            .absorb(FRAME_FINAL, child, 2, &[FINAL_BACKEND_FAILURE])
            .unwrap();
        collector
            .absorb(FRAME_FINAL, root, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();

        let error = collector.finish().err().unwrap();
        assert!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DbtBackendFailure>())
                .is_some(),
            "collector returned the wrong error: {error}"
        );
    }

    #[test]
    fn collector_reports_a_child_backend_failure_before_a_missing_root_final() {
        let root = ProcessKey {
            pid: 35,
            start_time: 41,
        };
        let child = ProcessKey {
            pid: 36,
            start_time: 42,
        };
        let mut child_payload = Vec::from(child.pid.to_le_bytes());
        child_payload.extend_from_slice(&child.start_time.to_le_bytes());
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, root);
        collector
            .absorb(FRAME_CHILD, root, 2, &child_payload)
            .unwrap();
        start_and_initialize(&mut collector, child);
        collector
            .absorb(FRAME_FINAL, child, 2, &[FINAL_BACKEND_FAILURE])
            .unwrap();

        let error = collector.finish().err().unwrap();
        assert!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DbtBackendFailure>())
                .is_some(),
            "collector returned the wrong error: {error}"
        );
    }

    #[test]
    fn collector_retains_backend_failure_across_exec_and_exact_retry() {
        let process = ProcessKey {
            pid: 35,
            start_time: 41,
        };
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, process);
        collector.absorb(FRAME_EXEC, process, 2, &[]).unwrap();
        start_and_initialize(&mut collector, process);

        let payload = [FINAL_BACKEND_FAILURE];
        let digest = frame_digest(FRAME_FINAL, 2, &payload);
        collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 2, digest, &payload)
            .unwrap();
        collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 2, digest, &payload)
            .unwrap();
        let changed_payload = [FINAL_GUEST_COMPLETED];
        let changed_digest = frame_digest(FRAME_FINAL, 2, &changed_payload);
        let changed = collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 2, changed_digest, &changed_payload)
            .unwrap_err();
        assert!(changed.to_string().contains("retry changed"));

        let error = collector.finish().err().unwrap();
        assert!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DbtBackendFailure>())
                .is_some(),
            "collector returned the wrong error: {error}"
        );
    }

    #[test]
    fn collector_acknowledges_only_an_exact_transport_retry() {
        let process = ProcessKey {
            pid: 33,
            start_time: 39,
        };
        let start_digest = frame_digest(FRAME_START, 0, &[]);
        let mut collector = Collector::new();
        collector
            .absorb_or_acknowledge_retry(FRAME_START, process, 0, start_digest, &[])
            .unwrap();
        collector
            .absorb_or_acknowledge_retry(FRAME_START, process, 0, start_digest, &[])
            .unwrap();

        let initialization = encode_records(&[INITIALIZATION_RECORD]);
        let initialization_digest = frame_digest(FRAME_DATA, 1, &initialization);
        collector
            .absorb_or_acknowledge_retry(
                FRAME_DATA,
                process,
                1,
                initialization_digest,
                &initialization,
            )
            .unwrap();
        collector
            .absorb_or_acknowledge_retry(
                FRAME_DATA,
                process,
                1,
                initialization_digest,
                &initialization,
            )
            .unwrap();

        let final_payload = [FINAL_GUEST_COMPLETED];
        let final_digest = frame_digest(FRAME_FINAL, 2, &final_payload);
        collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 2, final_digest, &final_payload)
            .unwrap();
        collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 2, final_digest, &final_payload)
            .unwrap();
        let collected = collector.finish().unwrap();
        assert_eq!(collected.record_count, 1);
        assert_eq!(collected.encoded_records, initialization);
    }

    #[test]
    fn collector_refuses_a_changed_same_sequence_retry() {
        let process = ProcessKey {
            pid: 35,
            start_time: 41,
        };
        let start_digest = frame_digest(FRAME_START, 0, &[]);
        let mut collector = Collector::new();
        collector
            .absorb_or_acknowledge_retry(FRAME_START, process, 0, start_digest, &[])
            .unwrap();

        let changed_payload = [FINAL_GUEST_COMPLETED];
        let changed_digest = frame_digest(FRAME_FINAL, 0, &changed_payload);
        let error = collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 0, changed_digest, &changed_payload)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("retry changed an accepted frame"),
            "unexpected refusal: {error}"
        );
    }

    #[test]
    fn collector_requires_exec_before_cancel_and_accepts_valid_cancel() {
        let process = ProcessKey {
            pid: 41,
            start_time: 43,
        };
        let mut collector = Collector::new();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        assert!(
            collector
                .absorb(FRAME_EXEC_CANCEL, process, 1, &[])
                .is_err()
        );

        let mut collector = Collector::new();
        start_and_initialize(&mut collector, process);
        collector.absorb(FRAME_EXEC, process, 2, &[]).unwrap();
        collector
            .absorb(FRAME_EXEC_CANCEL, process, 3, &[])
            .unwrap();
        collector
            .absorb(FRAME_FINAL, process, 4, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector.finish().unwrap();
    }

    #[test]
    fn collector_accepts_root_final_before_descendant_final() {
        let root = ProcessKey {
            pid: 47,
            start_time: 53,
        };
        let descendant = ProcessKey {
            pid: 59,
            start_time: 61,
        };
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, root);
        start_and_initialize(&mut collector, descendant);
        collector
            .absorb(FRAME_FINAL, root, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        assert!(collector.has_admitted(descendant));
        collector
            .absorb(FRAME_FINAL, descendant, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector.finish().unwrap();
    }

    #[test]
    fn collector_refuses_an_announced_child_without_final_evidence() {
        let root = ProcessKey {
            pid: 67,
            start_time: 71,
        };
        let child = ProcessKey {
            pid: 73,
            start_time: 79,
        };
        let mut child_payload = Vec::from(child.pid.to_le_bytes());
        child_payload.extend_from_slice(&child.start_time.to_le_bytes());

        let mut collector = Collector::new();
        start_and_initialize(&mut collector, root);
        collector
            .absorb(FRAME_CHILD, root, 2, &child_payload)
            .unwrap();
        collector
            .absorb(FRAME_FINAL, root, 3, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        assert!(collector.finish().is_err());
    }

    #[test]
    fn collector_accepts_a_child_announced_after_its_final_frame() {
        let root = ProcessKey {
            pid: 83,
            start_time: 89,
        };
        let child = ProcessKey {
            pid: 97,
            start_time: 101,
        };
        let mut child_payload = Vec::from(child.pid.to_le_bytes());
        child_payload.extend_from_slice(&child.start_time.to_le_bytes());

        let mut collector = Collector::new();
        start_and_initialize(&mut collector, root);
        start_and_initialize(&mut collector, child);
        collector
            .absorb(FRAME_FINAL, child, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector
            .absorb(FRAME_CHILD, root, 2, &child_payload)
            .unwrap();
        collector
            .absorb(FRAME_FINAL, root, 3, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector.finish().unwrap();
    }

    /// A process of the run that left its process group and session and
    /// whose parent exited is recognised as the run's once this process has
    /// adopted it, as a PID namespace init adopts every orphan.
    #[test]
    fn an_adopted_orphan_that_left_its_session_is_the_runs() {
        use std::io::BufRead as _;
        use std::process::Command;
        use std::process::Stdio;

        /// Restores the test process's child-subreaper setting, and kills and
        /// reaps the orphan it adopted, however the test ends.
        struct Adoption {
            previous: libc::c_int,
            orphan: Option<i32>,
        }
        impl Drop for Adoption {
            fn drop(&mut self) {
                if let Some(orphan) = self.orphan {
                    // SAFETY: a positive pid names exactly the orphan, which
                    // this process adopted, so it is this process's child to
                    // reap.
                    unsafe {
                        libc::kill(orphan, libc::SIGKILL);
                        libc::waitpid(orphan, std::ptr::null_mut(), 0);
                    }
                }
                // SAFETY: prctl with integer arguments only.
                unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.previous, 0, 0, 0) };
            }
        }

        let mut previous: libc::c_int = 0;
        // SAFETY: PR_GET_CHILD_SUBREAPER writes one int through the pointer.
        assert_eq!(
            unsafe {
                libc::prctl(
                    libc::PR_GET_CHILD_SUBREAPER,
                    &mut previous as *mut libc::c_int,
                    0,
                    0,
                    0,
                )
            },
            0
        );
        let mut adoption = Adoption {
            previous,
            orphan: None,
        };
        // SAFETY: prctl with integer arguments only. This test's process
        // adopts orphans as an init would, until `adoption` is dropped.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut root_child = Command::new("/bin/sh")
            .args([
                "-c",
                "setsid sleep 30 >/dev/null 2>&1 & echo $!; sleep 0.1; exit 0",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let root = ProcessKey {
            pid: root_child.id(),
            start_time: process_start_time(root_child.id()).unwrap(),
        };
        let mut pid_line = String::new();
        std::io::BufReader::new(root_child.stdout.take().unwrap())
            .read_line(&mut pid_line)
            .unwrap();
        let orphan_pid: u32 = pid_line.trim().parse().unwrap();
        adoption.orphan = Some(orphan_pid as i32);
        let orphan = ProcessKey {
            pid: orphan_pid,
            start_time: process_start_time(orphan_pid).unwrap(),
        };
        root_child.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !is_reparented_run_process(orphan, root) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(is_reparented_run_process(orphan, root));
        assert!(!is_isolated_process_group_member(orphan, root.pid));
        // A process that was not the run's: this one.
        let me = ProcessKey {
            pid: std::process::id(),
            start_time: process_start_time(std::process::id()).unwrap(),
        };
        assert!(!is_reparented_run_process(me, root));
        drop(adoption);
    }

    #[test]
    fn reparented_group_member_can_send_its_first_start_and_data() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;
        use std::process::Command;
        use std::process::Stdio;

        let mut root_child = Command::new("/bin/sh");
        root_child
            .args([
                "-c",
                "trap '' HUP; sleep 30 >/dev/null 2>&1 & echo $!; sleep 0.1; exit 0",
            ])
            .stdout(Stdio::piped())
            .process_group(0);
        let mut root_child = root_child.spawn().unwrap();
        let root = ProcessKey {
            pid: root_child.id(),
            start_time: process_start_time(root_child.id()).unwrap(),
        };
        let mut pid_line = String::new();
        std::io::BufReader::new(root_child.stdout.take().unwrap())
            .read_line(&mut pid_line)
            .unwrap();
        let descendant_pid: u32 = pid_line.trim().parse().unwrap();
        let descendant = ProcessKey {
            pid: descendant_pid,
            start_time: process_start_time(descendant_pid).unwrap(),
        };
        root_child.wait().unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while is_process_descendant(descendant, root) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!is_process_descendant(descendant, root));
        assert_ne!(
            process_stat(descendant.pid).unwrap().session,
            root.pid as i32
        );
        assert!(is_isolated_process_group_member(descendant, root.pid));

        let mut collector = Collector::new();
        assert!(!collector.has_admitted(descendant));
        assert!(initial_peer_is_admissible(descendant, root));
        collector.absorb(FRAME_START, descendant, 0, &[]).unwrap();
        let record = b"1970-01-01T00:00:00.000000Z INFO detcore: reparented child\n";
        let payload = encode_records(&[INITIALIZATION_RECORD, record]);
        collector
            .absorb(FRAME_DATA, descendant, 1, &payload)
            .unwrap();
        collector
            .absorb(FRAME_FINAL, descendant, 2, &[FINAL_GUEST_COMPLETED])
            .unwrap();
        collector.finish().unwrap();

        unsafe {
            libc::kill(-(root.pid as i32), libc::SIGKILL);
        }
    }

    #[test]
    fn collector_process_state_is_bounded() {
        let mut collector = Collector::new();
        for pid in 1..=MAX_EVIDENCE_PROCESSES as u32 {
            collector
                .absorb(
                    FRAME_START,
                    ProcessKey {
                        pid,
                        start_time: u64::from(pid),
                    },
                    0,
                    &[],
                )
                .unwrap();
        }
        assert!(
            collector
                .absorb(
                    FRAME_START,
                    ProcessKey {
                        pid: MAX_EVIDENCE_PROCESSES as u32 + 1,
                        start_time: MAX_EVIDENCE_PROCESSES as u64 + 1,
                    },
                    0,
                    &[],
                )
                .is_err()
        );
    }

    #[test]
    fn denied_publication_truncates_the_output() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"guest-controlled bytes").unwrap();
        let collected = CollectedEvidence {
            encoded_records: Vec::new(),
            record_count: 0,
            payload_bytes: 0,
            hash: FNV_OFFSET,
        };
        assert!(finalize_output(&mut file, Ok(collected), false).is_err());
        assert_eq!(file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn backend_failure_truncates_without_publishing_an_artifact() {
        let process = ProcessKey {
            pid: 107,
            start_time: 109,
        };
        let mut collector = Collector::new();
        start_and_initialize(&mut collector, process);
        collector
            .absorb(FRAME_FINAL, process, 2, &[FINAL_BACKEND_FAILURE])
            .unwrap();

        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"guest-controlled bytes").unwrap();
        let error = finalize_output(&mut file, collector.finish(), true).unwrap_err();
        assert!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DbtBackendFailure>())
                .is_some(),
            "finalization returned the wrong error: {error}"
        );
        assert_eq!(file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn evidence_session_can_be_claimed_only_before_one_run() {
        let file = tempfile::tempfile().unwrap();
        let session = EvidenceSession::new(&file).unwrap();
        session.claim_run().unwrap();
        let error = session.claim_run().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn native_initialization_record_matches_the_decoder_protocol() {
        let source = include_str!("../native/client.c");
        let initialization = source
            .split_once("static void evidence_emit_image_initialization(void) {")
            .unwrap()
            .1
            .split_once("static void evidence_thread_leave")
            .unwrap()
            .0;
        assert!(
            initialization.contains("\"1970-01-01T00:00:00.000000Z INFO reverie_dbt::evidence: \"")
        );
        assert!(initialization.contains("\"protected evidence initialized\\n\""));
        assert!(!initialization.contains("evidence_log_level"));
        assert_eq!(
            classify_initialization_record(INITIALIZATION_RECORD),
            InitializationRecord::Exact
        );

        let thread_init = source
            .split_once("static void thread_init(void* drcontext) {")
            .unwrap()
            .1
            .split_once("static void thread_exit")
            .unwrap()
            .0;
        assert!(
            thread_init
                .find("evidence_emit_image_initialization();")
                .unwrap()
                < thread_init
                    .find("reverie_dbt_runtime_thread_init(")
                    .unwrap()
        );

        let complete_clone = source
            .split_once("static int32_t complete_clone_birth(")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(
            complete_clone.find("} else if (result == 0) {").unwrap()
                < complete_clone
                    .find("evidence_initialize_fork_child_thread(counters);")
                    .unwrap()
        );
    }

    #[test]
    fn native_shutdown_precedes_evidence_background_quiescence() {
        let source = include_str!("../native/client.c");
        let finalizer = source
            .split_once("static void finalize_runtime_process(void) {")
            .unwrap()
            .1
            .split_once("static void report_copied_unsupported_syscall")
            .unwrap()
            .0;
        let event_exit = source
            .split_once("static void event_exit(void) {")
            .unwrap()
            .1
            .split_once("static void runtime_idle(void)")
            .unwrap()
            .0;

        let timeout_refusal = finalizer
            .find("runtime background did not quiesce after shutdown")
            .unwrap();
        let finalization_marker = finalizer
            .find("sender->finalization_started = true;")
            .unwrap();
        let process_exit = finalizer
            .find("reverie_dbt_runtime_process_exit();")
            .unwrap();
        let evidence_gate = finalizer.find("if (!evidence_is_enabled())").unwrap();
        let final_frame = finalizer
            .find("require_evidence_flush(EVIDENCE_FRAME_FINAL);")
            .unwrap();
        let cleanup_guard = event_exit
            .find(
                "if (evidence_is_enabled() && !is_copied_vfork_process() &&\n      evidence_current_process_finalized()) {",
            )
            .unwrap();
        let first_free = event_exit.find("dr_global_free(evidence_buffer").unwrap();
        let mutex_destroy = event_exit.find("dr_mutex_destroy(evidence_lock)").unwrap();

        assert!(finalization_marker < process_exit);
        assert!(process_exit < evidence_gate);
        assert!(evidence_gate < timeout_refusal);
        assert!(timeout_refusal < final_frame);
        assert!(cleanup_guard < first_free);
        assert!(cleanup_guard < mutex_destroy);
    }

    #[test]
    fn native_syscall_exit_defers_final_to_thread_and_process_exit() {
        let source = include_str!("../native/client.c");
        assert!(!source.contains("syscall_exits_process"));

        let invoke_syscall = source
            .split_once("static int64_t\ninvoke_syscall(")
            .unwrap()
            .1
            .split_once("static int32_t read_registers")
            .unwrap()
            .0;
        assert!(!invoke_syscall.contains("finalize_runtime_process();"));

        let pre_syscall = source
            .split_once("static bool pre_syscall(")
            .unwrap()
            .1
            .split_once("static void thread_init")
            .unwrap()
            .0;
        assert!(!pre_syscall.contains("finalize_runtime_process();"));

        let thread_leave = source
            .split_once("static void evidence_thread_leave(")
            .unwrap()
            .1
            .split_once("static void initialize_evidence_transport")
            .unwrap()
            .0;
        assert!(thread_leave.contains("if (last_thread"));
        assert!(thread_leave.contains("finalize_runtime_process();"));

        let event_exit = source
            .split_once("static void event_exit(void) {")
            .unwrap()
            .1
            .split_once("static void runtime_idle(void)")
            .unwrap()
            .0;
        assert!(event_exit.contains("finalize_runtime_process();"));
    }

    #[test]
    fn native_processes_finalize_after_their_runtime_output() {
        let source = include_str!("../native/client.c");
        let event_exit = source
            .split_once("static void event_exit(void) {")
            .unwrap()
            .1
            .split_once("static void runtime_idle(void)")
            .unwrap()
            .0;
        let background = source
            .split_once("static void runtime_background_init(void* argument) {")
            .unwrap()
            .1
            .split_once("static void ensure_runtime_background(void)")
            .unwrap()
            .0;
        let background_initialization = background
            .find("evidence_emit_image_initialization();")
            .unwrap();
        let background_runtime = background
            .find("reverie_dbt_runtime_background_init_v3(\n      &runtime_callbacks_page.value, native_mode);")
            .unwrap();
        let background_callback_leave = background_runtime
            + background[background_runtime..]
                .find("evidence_callback_leave();")
                .unwrap();
        let mode_validation = background
            .find("task_state->magic != TASK_STATE_MAGIC")
            .unwrap();
        let startup_refusal = background.find("if (startup_status != 0)").unwrap();
        let background_final = background
            .find("require_evidence_flush(EVIDENCE_FRAME_FINAL);")
            .unwrap();
        let background_quiescent = background
            .find("atomic_store_explicit(&runtime_background_state, 3")
            .unwrap();
        assert!(background_initialization < background_runtime);
        assert!(mode_validation < background_runtime);
        assert!(background.contains("uint32_t native_mode = runtime_uses_external_global()"));
        assert!(background_runtime < background_callback_leave);
        assert!(background_callback_leave < startup_refusal);
        assert!(startup_refusal < background_final);
        assert!(
            background[startup_refusal..background_final]
                .contains("exit_runtime_tree(CLIENT_THREAD_START_FAILURE_EXIT_CODE);")
        );
        assert!(background_callback_leave < background_final);
        assert!(background_final < background_quiescent);
        assert!(event_exit.contains("finalize_runtime_process();"));
        let finalizer = source
            .split_once("static void finalize_runtime_process(void) {")
            .unwrap()
            .1
            .split_once("static void report_copied_unsupported_syscall")
            .unwrap()
            .0;
        let process_exit = finalizer
            .find("reverie_dbt_runtime_process_exit();")
            .unwrap();
        let final_frame = finalizer
            .find("require_evidence_flush(EVIDENCE_FRAME_FINAL);")
            .unwrap();
        assert!(process_exit < final_frame);
    }

    #[test]
    fn native_runtime_abi_is_checked_before_runtime_callbacks() {
        assert_eq!(
            crate::reverie_dbt_runtime_abi_version(),
            crate::DBT_RUNTIME_ABI_VERSION
        );
        assert_eq!(
            crate::reverie_dbt_runtime_callbacks_size(),
            std::mem::size_of::<crate::DbtRuntimeCallbacks>()
        );
        let source = include_str!("../native/client.c");
        let main = source
            .split_once("DR_EXPORT void dr_client_main")
            .unwrap()
            .1;
        let version_check = main.find("reverie_dbt_runtime_abi_version()").unwrap();
        let first_runtime_callback = main.find("reverie_dbt_runtime_image_init()").unwrap();
        assert!(version_check < first_runtime_callback);
        assert!(source.contains("reverie_dbt_runtime_thread_created_v2("));
        assert!(source.contains("reverie_dbt_runtime_background_init_v3("));
    }

    #[test]
    fn native_internal_exits_mark_the_final_outcome() {
        let source = include_str!("../native/client.c");
        let failure_marker = source
            .split_once("static void mark_backend_failure(void) {")
            .unwrap()
            .1
            .split_once("static bool evidence_flush_locked")
            .unwrap()
            .0;
        assert!(
            failure_marker
                .find("atomic_store_explicit(&runtime_backend_failure")
                .unwrap()
                < failure_marker.find("evidence_sender_locked();").unwrap()
        );

        let evidence_flush = source
            .split_once("static bool evidence_flush_locked(")
            .unwrap()
            .1
            .split_once("static bool evidence_flush(")
            .unwrap()
            .0;
        assert!(evidence_flush.contains(
            "sender->backend_failure |=\n          atomic_load_explicit(&runtime_backend_failure"
        ));

        let exit_runtime_tree = source
            .split_once("static void exit_runtime_tree(int exit_code) {")
            .unwrap()
            .1
            .split_once("#define EVIDENCE_CHANNEL_HEADER_LEN")
            .unwrap()
            .0;
        assert!(
            exit_runtime_tree.find("mark_backend_failure();").unwrap()
                < exit_runtime_tree
                    .find("dr_exit_process(exit_code);")
                    .unwrap()
        );

        let background_start = source
            .split_once("static void ensure_runtime_background(void) {")
            .unwrap()
            .1
            .split_once("DR_EXPORT void dr_client_main")
            .unwrap()
            .0;
        assert!(
            background_start.contains("exit_runtime_tree(CLIENT_THREAD_START_FAILURE_EXIT_CODE);")
        );

        // The other direct call is the ABI refusal before the evidence transport
        // and exit callback exist. It cannot report a terminal outcome and must
        // continue to fail as missing evidence.
        assert_eq!(source.matches("dr_exit_process(").count(), 2);
        let main = source
            .split_once("DR_EXPORT void dr_client_main")
            .unwrap()
            .1;
        let abi_refusal = main.find("dr_exit_process(101);").unwrap();
        let evidence_initialization = main.find("initialize_evidence_transport();").unwrap();
        let exit_registration = main.find("drmgr_register_exit_event(event_exit);").unwrap();
        assert!(abi_refusal < evidence_initialization);
        assert!(abi_refusal < exit_registration);
    }

    #[test]
    fn process_clone_result_callback_runs_after_the_kernel_result() {
        let source = include_str!("../native/client.c");
        let invoke = source
            .rsplit_once("static int64_t\ninvoke_syscall(uintptr_t context")
            .unwrap()
            .1
            .split_once("static int32_t read_registers")
            .unwrap()
            .0;
        assert!(invoke.contains("CLONE_SYSCALL_INJECTED"));
        assert!(!invoke.contains("CLONE_SYSCALL_ORIGINAL"));
        assert_eq!(
            source.matches("pending_process_clone_result = 1;").count(),
            1
        );

        let original = source
            .split_once("static bool prepare_original_task_syscall(")
            .unwrap()
            .1
            .split_once("static void post_syscall")
            .unwrap()
            .0;
        assert!(original.contains("CLONE_SYSCALL_ORIGINAL"));

        let post = source
            .split_once("static void post_syscall(void* drcontext, int sysnum) {")
            .unwrap()
            .1
            .split_once("static bool pre_syscall")
            .unwrap()
            .0;
        let result = post.find("dr_syscall_get_result(drcontext)").unwrap();
        let invariant = post
            .find("if (!is_clone_syscall(sysnum) &&\n      counters->pending_process_clone_result != 0)")
            .unwrap();
        let guard = post
            .find("if (is_clone_syscall(sysnum) && counters->pending_process_clone_result != 0)")
            .unwrap();
        let consumed = post
            .find("counters->pending_process_clone_result = 0;")
            .unwrap();
        let child_initialization = post
            .find("evidence_initialize_fork_child_thread(counters);")
            .unwrap();
        let callback = post
            .find("int32_t registration = reverie_dbt_runtime_process_clone_result(")
            .unwrap();
        let identity = post
            .find("complete_clone_birth(counters, syscall_result)")
            .unwrap();
        assert!(result < invariant);
        assert!(invariant < guard);
        assert!(guard < consumed);
        assert!(consumed < child_initialization);
        assert!(child_initialization < callback);
        assert!(callback < identity);

        let pre = source
            .split_once("static bool pre_syscall(void* drcontext, int sysnum) {")
            .unwrap()
            .1
            .split_once("static void thread_init")
            .unwrap()
            .0;
        let stale = pre
            .find("fail_if_process_clone_result_pending(counters, sysnum)")
            .unwrap();
        let scrub = pre.find("scrub_guest_stack_residue(drcontext)").unwrap();
        let arguments = pre.find("dr_syscall_get_param(drcontext, i)").unwrap();
        let clone_metadata = pre.find("thread_clone_metadata(drcontext").unwrap();
        let callback = pre.find("reverie_dbt_runtime_pre_syscall(").unwrap();
        let suppressed = pre.find("if (action == 1)").unwrap();
        let deferred = pre.find("if (action == 2)").unwrap();
        let original = pre.find("prepare_original_task_syscall(").unwrap();
        assert!(stale < scrub);
        assert!(stale < arguments);
        assert!(stale < clone_metadata);
        assert!(stale < callback);
        assert!(stale < suppressed);
        assert!(stale < deferred);
        assert!(stale < original);

        let prepare = source
            .split_once("static bool prepare_clone_birth(")
            .unwrap()
            .1
            .split_once("static int32_t complete_clone_birth")
            .unwrap()
            .0;
        let defensive_stale = prepare
            .find("fail_if_process_clone_result_pending(counters, sysnum)")
            .unwrap();
        let clone3_decode = prepare.find("clone_identity_flags(sysnum, args").unwrap();
        let original_origin = prepare.find("origin == CLONE_SYSCALL_ORIGINAL").unwrap();
        let arm = prepare.find("pending_process_clone_result = 1;").unwrap();
        assert!(defensive_stale < clone3_decode);
        assert!(clone3_decode < original_origin);
        assert!(original_origin < arm);
    }

    #[test]
    fn native_runtime_callbacks_are_page_isolated_and_sealed_before_use() {
        let source = include_str!("../native/client.c");
        assert!(source.contains(
            "static runtime_callbacks_page_t runtime_callbacks_page\n    __attribute__((aligned(EVIDENCE_CONFIG_PAGE_SIZE)))"
        ));
        assert!(!source.contains("static runtime_callbacks_t runtime_callbacks ="));
        assert!(source.contains(
            "range_overlaps_page(\n             address,\n             length,\n             &runtime_callbacks_page,\n             sizeof(runtime_callbacks_page))"
        ));
        assert!(
            source
                .contains("reverie_dbt_runtime_background_init_v3(\n      &runtime_callbacks_page.value, native_mode);")
        );

        let main = source
            .split_once("DR_EXPORT void dr_client_main")
            .unwrap()
            .1;
        let final_write = main
            .find("runtime_callbacks_page.value.unsupported_report_fd =")
            .unwrap();
        let seal = main
            .find("dr_memory_protect(\n      &runtime_callbacks_page")
            .unwrap();
        let client_registration = main.find("dr_set_client_name(").unwrap();
        assert!(final_write < seal);
        assert!(seal < client_registration);
        assert!(!main[seal..].contains("runtime_callbacks_page.value."));
    }
}
