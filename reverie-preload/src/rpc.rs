/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Synchronous coordinator RPC client (feature `coordinator-rpc`).
//!
//! An ld-preload guest does not hold the tool's `GlobalState`; that lives in a
//! coordinator process (the hermit CLI, like the ptrace model). This client
//! forwards a guest's tool request to the coordinator and returns the response.
//!
//! # Wire compatibility
//!
//! The frame format is **identical** to the async
//! [`reverie-rpc-transport`](https://github.com/rrnewton/reverie/pull/98)
//! `RpcServer<G>`, so one coordinator serves both async (DBI/SaBRe) and this
//! synchronous (ld-preload) client:
//!
//! * framing: `u32` big-endian length prefix, then a bincode 2
//!   `config::legacy()` payload;
//! * handshake: the coordinator sends one config frame on connect;
//! * per call: the client sends a [`RequestEnvelope`] `{ from, request }` frame
//!   and reads back a bare response frame (one request in flight per
//!   connection, so nothing to correlate).
//!
//! # Why synchronous, not `reverie-rpc-transport` directly
//!
//! `reverie-rpc-transport` is async/`tokio`. The natural ld-preload call site is
//! the SIGSYS handler, which is async-signal context — no executor, no `await`.
//! DRY is therefore achieved at the **wire-format** layer (shared framing/codec
//! contract), not by sharing async code that cannot run in a signal handler.
//!
//! # Async-signal-safety caveat
//!
//! This client uses blocking [`std::os::unix::net::UnixStream`] I/O and is
//! immediately usable from normal context (e.g. a backend whose trap mechanism
//! runs outside a signal handler, or a dedicated servicing thread). Calling it
//! from *inside* the SIGSYS handler additionally requires routing the socket
//! reads/writes through the trusted gate ([`crate::trap::raw_syscall6`]); that
//! raw-gate transport is a documented follow-up and does not change this wire
//! contract.

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;

use bincode::config::legacy;
use reverie::Tid;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Default maximum accepted frame size (16 MiB), matching the async transport.
pub const DEFAULT_MAX_FRAME_LEN: usize = 16 * (1 << 20);

/// A request as it travels from a guest to the coordinator.
///
/// Field order and types mirror `reverie_rpc_transport::RequestEnvelope` so the
/// bincode bytes are identical on both ends.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct RequestEnvelope<Req> {
    /// The originating guest thread id.
    pub from: Tid,
    /// The tool-specific request payload.
    pub request: Req,
}

/// A blocking, wire-compatible coordinator client.
pub struct CoordinatorClient {
    stream: UnixStream,
    config_bytes: Vec<u8>,
    max_frame_len: usize,
}

impl CoordinatorClient {
    /// Connect to the coordinator listening at `path` and read its config
    /// handshake frame.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut stream = UnixStream::connect(path)?;
        let config_bytes = read_frame(&mut stream, DEFAULT_MAX_FRAME_LEN)?;
        Ok(Self {
            stream,
            config_bytes,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
        })
    }

    /// The raw bytes of the coordinator's config handshake.
    pub fn config_bytes(&self) -> &[u8] {
        &self.config_bytes
    }

    /// Decode the coordinator's config as `C`.
    pub fn config<C: DeserializeOwned>(&self) -> io::Result<C> {
        decode(&self.config_bytes)
    }

    /// Send one tool request from thread `from` and await the response.
    pub fn send<Req, Resp>(&mut self, from: Tid, request: Req) -> io::Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let envelope = RequestEnvelope { from, request };
        let payload = encode(&envelope)?;
        write_frame(&mut self.stream, &payload)?;
        let response_bytes = read_frame(&mut self.stream, self.max_frame_len)?;
        decode(&response_bytes)
    }
}

/// Serialize with the shared bincode configuration.
pub fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, legacy())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Deserialize with the shared bincode configuration.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    let (value, _consumed) = bincode::serde::decode_from_slice(bytes, legacy())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(value)
}

fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn read_frame<R: Read>(reader: &mut R, max_len: usize) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0_u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds maximum length",
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;

    #[test]
    fn frame_round_trips_through_a_pipe() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let payload = b"hello frame";
        write_frame(&mut a, payload).unwrap();
        let got = read_frame(&mut b, DEFAULT_MAX_FRAME_LEN).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_frame(&mut a, &[0_u8; 64]).unwrap();
        assert!(read_frame(&mut b, 8).is_err());
    }

    #[test]
    fn encode_decode_are_inverse() {
        let value: (u64, i32) = (42, -7);
        let bytes = encode(&value).unwrap();
        let back: (u64, i32) = decode(&bytes).unwrap();
        assert_eq!(back, value);
    }

    // A tiny coordinator that speaks the exact wire protocol: send a config
    // frame, then echo each request's numeric payload incremented by one,
    // aggregating a running total to model shared GlobalState across
    // connections (the property the DBI backend lacks).
    #[test]
    fn end_to_end_against_a_wire_server() {
        let dir =
            std::env::temp_dir().join(format!("reverie-preload-rpc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("coord.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();

        let server_sock = sock.clone();
        let server = thread::spawn(move || {
            let mut total: u64 = 0;
            // Serve two client connections sequentially.
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                // Config handshake: a config value of 100.
                let config = encode(&100_u64).unwrap();
                write_frame(&mut stream, &config).unwrap();
                while let Ok(bytes) = read_frame(&mut stream, DEFAULT_MAX_FRAME_LEN) {
                    let env: RequestEnvelope<u64> = decode(&bytes).unwrap();
                    total += env.request;
                    let resp = encode(&total).unwrap();
                    write_frame(&mut stream, &resp).unwrap();
                }
            }
            total
        });
        let _ = server_sock;

        let from = Tid::from_raw(4242);

        // Two clients (as if two processes in a fork tree) increment the same
        // coordinator total: 3 + 5 then 7 -> 8, 15.
        {
            let mut c1 = CoordinatorClient::connect(&sock).unwrap();
            assert_eq!(c1.config::<u64>().unwrap(), 100);
            let r1: u64 = c1.send(from, 3_u64).unwrap();
            assert_eq!(r1, 3);
            let r2: u64 = c1.send(from, 5_u64).unwrap();
            assert_eq!(r2, 8);
        }
        {
            let mut c2 = CoordinatorClient::connect(&sock).unwrap();
            assert_eq!(c2.config::<u64>().unwrap(), 100);
            let r3: u64 = c2.send(from, 7_u64).unwrap();
            assert_eq!(r3, 15);
        }

        let total = server.join().unwrap();
        assert_eq!(total, 15, "coordinator aggregated across both connections");
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir(&dir);
    }
}
