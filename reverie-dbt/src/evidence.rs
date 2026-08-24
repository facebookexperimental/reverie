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

const CHANNEL_MAGIC: &[u8; 8] = b"RVDBTE2\0";
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

const FILE_MAGIC: &[u8; 8] = b"RVDBTEF1";
const FILE_VERSION: u16 = 1;
const FILE_HEADER_LEN: usize = 40;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const CANONICAL_RECORD_PREFIX: &[u8] = b"1970-01-01T00:00:00.000000Z ";
const SESSION_NEW: u8 = 0;
const SESSION_RUNNING: u8 = 1;
const SESSION_FINISHING: u8 = 2;
const SESSION_FINISHED: u8 = 3;

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
}

impl DbtEvidence {
    /// Exact tracing-callback records in authenticated arrival order.
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Consumes the stream and returns its exact tracing-callback records.
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
    let mut records = Vec::new();
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
        records.push(record.to_vec());
        cursor = record_end;
    }
    if records.len() as u64 != expected_records
        || payload_bytes != expected_payload
        || hash != expected_hash
    {
        return Err(invalid_data(
            "DBT evidence count, byte length, or digest does not match its header",
        ));
    }
    Ok(DbtEvidence { records })
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
        let worker = std::thread::Builder::new()
            .name("reverie-dbt-evidence".into())
            .spawn(move || {
                serve(
                    listener,
                    token,
                    worker_root_process,
                    worker_stop,
                    worker_acknowledgement_drops,
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
        })
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

struct Collector {
    images: BTreeMap<ProcessKey, ImageState>,
    expected_processes: BTreeSet<ProcessKey>,
    terminal_processes: BTreeSet<ProcessKey>,
    last_receipts: BTreeMap<ProcessKey, FrameReceipt>,
    encoded_records: Vec<u8>,
    record_count: u64,
    payload_bytes: u64,
    hash: u64,
    saw_start: bool,
}

impl Collector {
    fn new() -> Self {
        Self {
            images: BTreeMap::new(),
            expected_processes: BTreeSet::new(),
            terminal_processes: BTreeSet::new(),
            last_receipts: BTreeMap::new(),
            encoded_records: Vec::new(),
            record_count: 0,
            payload_bytes: 0,
            hash: FNV_OFFSET,
            saw_start: false,
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
                let epoch = match self.images.get(&process) {
                    Some(previous) if previous.pending_exec => previous
                        .epoch
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("DBT evidence image epoch overflowed"))?,
                    Some(_) => {
                        return Err(invalid_data(
                            "DBT evidence image restarted without a pending exec",
                        ));
                    }
                    None => 0,
                };
                self.images.insert(
                    process,
                    ImageState {
                        epoch,
                        next_sequence: 1,
                        pending_exec: false,
                    },
                );
                self.saw_start = true;
            }
            FRAME_DATA => {
                let image = self.image_for(process, sequence)?;
                if image.pending_exec {
                    return Err(invalid_data("DBT evidence arrived while exec was pending"));
                }
                image.next_sequence += 1;
                self.absorb_records(payload)?;
            }
            FRAME_EXEC => {
                if !payload.is_empty() {
                    return Err(invalid_data("DBT evidence EXEC frame carried payload"));
                }
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
                if !payload.is_empty() {
                    return Err(invalid_data("DBT evidence FINAL frame carried payload"));
                }
                let image = self.image_for(process, sequence)?;
                if image.pending_exec {
                    return Err(invalid_data("DBT evidence finalized with exec pending"));
                }
                self.images.remove(&process);
                self.terminal_processes.insert(process);
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

    fn absorb_records(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut cursor = 0;
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
            let new_len = self
                .encoded_records
                .len()
                .checked_add(4 + length)
                .filter(|length| *length <= MAX_EVIDENCE_BYTES)
                .ok_or_else(|| invalid_data("DBT evidence exceeded its memory bound"))?;
            self.encoded_records
                .reserve(new_len - self.encoded_records.len());
            self.encoded_records.extend_from_slice(&encoded_length);
            self.encoded_records.extend_from_slice(record);
            self.hash = fnv_update(self.hash, &encoded_length);
            self.hash = fnv_update(self.hash, record);
            self.record_count += 1;
            self.payload_bytes += length as u64;
            cursor = record_end;
        }
        Ok(())
    }

    fn finish(self) -> io::Result<CollectedEvidence> {
        if !self.saw_start {
            return Err(invalid_data("DBT evidence received no image START"));
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
        Ok(CollectedEvidence {
            encoded_records: self.encoded_records,
            record_count: self.record_count,
            payload_bytes: self.payload_bytes,
            hash: self.hash,
        })
    }
}

fn serve(
    listener: UnixListener,
    token: [u8; CHANNEL_TOKEN_LEN],
    root_process: Arc<Mutex<Option<ProcessKey>>>,
    stop: Arc<AtomicBool>,
    acknowledgement_drops: AcknowledgementDropControl,
) -> io::Result<CollectedEvidence> {
    let mut collector = Collector::new();
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
                    &mut collector,
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
    collector.finish()
}

fn handle_connection(
    stream: &mut UnixStream,
    token: &[u8; CHANNEL_TOKEN_LEN],
    root_process: &Mutex<Option<ProcessKey>>,
    collector: &mut Collector,
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
    if !collector.has_admitted(process) && !initial_peer_is_admissible(process, root) {
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
    collector.absorb_or_acknowledge_retry(kind, process, sequence, digest, &payload)?;
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

fn initial_peer_is_admissible(process: ProcessKey, root: ProcessKey) -> bool {
    // Evidence mode forces a dedicated process group and the native client
    // rejects setpgid/setsid. Descendants inherit that group, and reparenting
    // does not change it; pid+starttime prevents reuse from inheriting admission.
    is_process_descendant(process, root) || is_isolated_process_group_member(process, root.pid)
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

    #[test]
    fn framed_evidence_round_trips_and_rejects_injected_lines() {
        let records = [
            b"1970-01-01T00:00:00.000000Z INFO detcore: first\n".as_slice(),
            b"1970-01-01T00:00:00.000000Z DEBUG detcore: second\n",
        ];
        let mut encoded_records = Vec::new();
        let mut hash = FNV_OFFSET;
        let mut payload_bytes = 0;
        for record in records {
            let length = (record.len() as u32).to_le_bytes();
            encoded_records.extend_from_slice(&length);
            encoded_records.extend_from_slice(record);
            hash = fnv_update(hash, &length);
            hash = fnv_update(hash, record);
            payload_bytes += record.len() as u64;
        }
        let mut bytes = vec![0; FILE_HEADER_LEN];
        bytes[..8].copy_from_slice(FILE_MAGIC);
        bytes[8..10].copy_from_slice(&FILE_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(FILE_HEADER_LEN as u16).to_le_bytes());
        bytes[16..24].copy_from_slice(&(records.len() as u64).to_le_bytes());
        bytes[24..32].copy_from_slice(&payload_bytes.to_le_bytes());
        bytes[32..40].copy_from_slice(&hash.to_le_bytes());
        bytes.extend_from_slice(&encoded_records);
        assert_eq!(decode_evidence(&bytes).unwrap().records(), records);

        let injected = b"1970-01-01T00:00:00.000000Z INFO detcore: guest=ok\n1970-01-01T00:00:00.000000Z INFO detcore: forged\n";
        assert!(validate_record(injected).is_err());
    }

    #[test]
    fn decoder_rejects_truncation_and_digest_changes() {
        let record = b"1970-01-01T00:00:00.000000Z INFO detcore: one\n";
        let length = (record.len() as u32).to_le_bytes();
        let mut bytes = vec![0; FILE_HEADER_LEN];
        bytes[..8].copy_from_slice(FILE_MAGIC);
        bytes[8..10].copy_from_slice(&FILE_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(FILE_HEADER_LEN as u16).to_le_bytes());
        bytes[16..24].copy_from_slice(&1_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&(record.len() as u64).to_le_bytes());
        let hash = fnv_update(fnv_update(FNV_OFFSET, &length), record);
        bytes[32..40].copy_from_slice(&hash.to_le_bytes());
        bytes.extend_from_slice(&length);
        bytes.extend_from_slice(record);

        assert!(decode_evidence(&bytes[..bytes.len() - 1]).is_err());
        *bytes.last_mut().unwrap() ^= 1;
        assert!(decode_evidence(&bytes).is_err());
    }

    #[test]
    fn collector_requires_exec_for_restart_and_terminalizes_process() {
        let process = ProcessKey {
            pid: 17,
            start_time: 23,
        };
        let mut collector = Collector::new();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        assert!(collector.absorb(FRAME_START, process, 0, &[]).is_err());
        collector.absorb(FRAME_EXEC, process, 1, &[]).unwrap();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        collector.absorb(FRAME_FINAL, process, 1, &[]).unwrap();
        assert!(collector.absorb(FRAME_START, process, 0, &[]).is_err());
    }

    #[test]
    fn collector_rejects_duplicate_final() {
        let process = ProcessKey {
            pid: 31,
            start_time: 37,
        };
        let mut collector = Collector::new();
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        collector.absorb(FRAME_FINAL, process, 1, &[]).unwrap();
        assert!(collector.absorb(FRAME_FINAL, process, 2, &[]).is_err());
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

        let final_digest = frame_digest(FRAME_FINAL, 1, &[]);
        collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 1, final_digest, &[])
            .unwrap();
        collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 1, final_digest, &[])
            .unwrap();
        collector.finish().unwrap();
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

        let changed_digest = frame_digest(FRAME_FINAL, 0, &[]);
        let error = collector
            .absorb_or_acknowledge_retry(FRAME_FINAL, process, 0, changed_digest, &[])
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
        collector.absorb(FRAME_START, process, 0, &[]).unwrap();
        collector.absorb(FRAME_EXEC, process, 1, &[]).unwrap();
        collector
            .absorb(FRAME_EXEC_CANCEL, process, 2, &[])
            .unwrap();
        collector.absorb(FRAME_FINAL, process, 3, &[]).unwrap();
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
        collector.absorb(FRAME_START, root, 0, &[]).unwrap();
        collector.absorb(FRAME_START, descendant, 0, &[]).unwrap();
        collector.absorb(FRAME_FINAL, root, 1, &[]).unwrap();
        assert!(collector.has_admitted(descendant));
        collector.absorb(FRAME_FINAL, descendant, 1, &[]).unwrap();
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
        collector.absorb(FRAME_START, root, 0, &[]).unwrap();
        collector
            .absorb(FRAME_CHILD, root, 1, &child_payload)
            .unwrap();
        collector.absorb(FRAME_FINAL, root, 2, &[]).unwrap();
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
        collector.absorb(FRAME_START, root, 0, &[]).unwrap();
        collector.absorb(FRAME_START, child, 0, &[]).unwrap();
        collector.absorb(FRAME_FINAL, child, 1, &[]).unwrap();
        collector
            .absorb(FRAME_CHILD, root, 1, &child_payload)
            .unwrap();
        collector.absorb(FRAME_FINAL, root, 2, &[]).unwrap();
        collector.finish().unwrap();
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
        let mut payload = Vec::from((record.len() as u32).to_le_bytes());
        payload.extend_from_slice(record);
        collector
            .absorb(FRAME_DATA, descendant, 1, &payload)
            .unwrap();
        collector.absorb(FRAME_FINAL, descendant, 2, &[]).unwrap();
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
    fn evidence_session_can_be_claimed_only_before_one_run() {
        let file = tempfile::tempfile().unwrap();
        let session = EvidenceSession::new(&file).unwrap();
        session.claim_run().unwrap();
        let error = session.claim_run().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
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
            .split_once("static int64_t invoke_syscall(")
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
            .split_once("static void runtime_background_init(void *argument) {")
            .unwrap()
            .1
            .split_once("static void ensure_runtime_background(void)")
            .unwrap()
            .0;
        let background_runtime = background
            .find("reverie_dbt_runtime_background_init_v2(&runtime_callbacks_page.value);")
            .unwrap();
        let background_callback_leave = background.find("evidence_callback_leave();").unwrap();
        let background_final = background
            .find("require_evidence_flush(EVIDENCE_FRAME_FINAL);")
            .unwrap();
        let background_quiescent = background
            .find("atomic_store_explicit(&runtime_background_state, 3")
            .unwrap();
        assert!(background_runtime < background_callback_leave);
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
        assert!(source.contains("reverie_dbt_runtime_background_init_v2("));
    }

    #[test]
    fn process_clone_result_callback_runs_after_the_kernel_result() {
        let source = include_str!("../native/client.c");
        let invoke = source
            .rsplit_once("static int64_t invoke_syscall(uintptr_t context")
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
            .split_once("static bool prepare_original_identity_syscall(")
            .unwrap()
            .1
            .split_once("static void post_syscall")
            .unwrap()
            .0;
        assert!(original.contains("CLONE_SYSCALL_ORIGINAL"));

        let post = source
            .split_once("static void post_syscall(void *drcontext, int sysnum) {")
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
            .find("if (is_clone_syscall(sysnum) &&\n      counters->pending_process_clone_result != 0)")
            .unwrap();
        let consumed = post
            .find("counters->pending_process_clone_result = 0;")
            .unwrap();
        let callback = post
            .find("reverie_dbt_runtime_process_clone_result(counters, (int64_t)sysnum,")
            .unwrap();
        let identity = post
            .find("complete_clone_identity(counters, syscall_result)")
            .unwrap();
        assert!(result < invariant);
        assert!(invariant < guard);
        assert!(guard < consumed);
        assert!(consumed < callback);
        assert!(callback < identity);

        let pre = source
            .split_once("static bool pre_syscall(void *drcontext, int sysnum) {")
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
        let original = pre.find("prepare_original_identity_syscall(").unwrap();
        assert!(stale < scrub);
        assert!(stale < arguments);
        assert!(stale < clone_metadata);
        assert!(stale < callback);
        assert!(stale < suppressed);
        assert!(stale < deferred);
        assert!(stale < original);

        let prepare = source
            .split_once("static bool prepare_clone_identity(")
            .unwrap()
            .1
            .split_once("static int32_t complete_clone_identity")
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
            "range_overlaps_page(address, length, &runtime_callbacks_page,\n                             sizeof(runtime_callbacks_page))"
        ));
        assert!(
            source
                .contains("reverie_dbt_runtime_background_init_v2(&runtime_callbacks_page.value);")
        );

        let main = source
            .split_once("DR_EXPORT void dr_client_main")
            .unwrap()
            .1;
        let final_write = main
            .find("runtime_callbacks_page.value.unsupported_report_fd =")
            .unwrap();
        let seal = main
            .find("dr_memory_protect(&runtime_callbacks_page")
            .unwrap();
        let client_registration = main.find("dr_set_client_name(").unwrap();
        assert!(final_write < seal);
        assert!(seal < client_registration);
        assert!(!main[seal..].contains("runtime_callbacks_page.value."));
    }
}
