/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Blocking guest client for synchronous in-process instrumentation callbacks.

use std::io;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Tid;

use crate::codec::DEFAULT_MAX_FRAME_LEN;
use crate::codec::decode;
use crate::codec::encode;
use crate::envelope::RequestEnvelope;
use crate::error::RpcError;

/// A per-thread blocking connection to a coordinator serving `G`.
///
/// Some in-guest instrumentation runtimes, including SaBRe, invoke the tool
/// through a synchronous callback and poll its async handler exactly once.
/// Tokio socket operations normally return `Pending` on that first poll. This
/// client deliberately performs the request/response exchange synchronously
/// inside `GlobalRPC::send_rpc`, so the enclosing tool future remains
/// immediately ready after the coordinator responds.
///
/// Keep one client per guest thread. A Detcore scheduler response can be
/// delayed until another thread releases resources, so sharing one connection
/// across threads could otherwise deadlock behind the single in-flight request.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-128): Review the blocking transport used by synchronous in-guest backends.
pub struct BlockingRpcClient<G: GlobalTool, S = UnixStream> {
    tid: Tid,
    config: G::Config,
    stream: Mutex<S>,
    _phantom: PhantomData<fn() -> G>,
}

// TODO-HUMAN-REVIEW(PR-212): Review raw descriptor exposure for in-guest
// runtimes that must hide coordinator transport descriptors from the guest.
impl<G: GlobalTool, S: AsRawFd> AsRawFd for BlockingRpcClient<G, S> {
    fn as_raw_fd(&self) -> RawFd {
        self.stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_raw_fd()
    }
}

impl<G: GlobalTool, S> BlockingRpcClient<G, S> {
    /// Consume the client and return its stored TID, config and stream.
    ///
    /// This transfers ownership without acquiring the stream mutex, performing
    /// I/O, cloning the config, or dropping either returned value. Poison does
    /// not prevent extracting the owned stream; a live poisoned client's RPC
    /// requests continue to fail normally.
    ///
    /// The caller controls when the returned values are used or destroyed.
    /// Extraction does not make their callbacks or destructors safe after fork
    /// or repair any separate synchronization in an enclosing runtime.
    pub fn into_parts(self) -> (Tid, G::Config, S) {
        let Self {
            tid,
            config,
            stream,
            _phantom: _,
        } = self;
        let stream = stream
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (tid, config, stream)
    }
}

impl<G> BlockingRpcClient<G>
where
    G: GlobalTool,
{
    /// Connect and synchronously receive the coordinator's config handshake.
    pub fn connect(path: impl AsRef<Path>, tid: Tid) -> Result<Self, RpcError> {
        Self::from_connected_stream(UnixStream::connect(path)?, tid)
    }
}

impl<G, S> BlockingRpcClient<G, S>
where
    G: GlobalTool,
    S: Read + Write + Send,
{
    /// Receive the config handshake from an already connected byte stream.
    ///
    /// Deserialization happens synchronously on the caller. Keep a separate
    /// stream/client for every thread that can have an independent pending RPC.
    pub fn from_connected_stream(mut stream: S, tid: Tid) -> Result<Self, RpcError> {
        let config_bytes = read_message(&mut stream, DEFAULT_MAX_FRAME_LEN)?;
        let config = decode(&config_bytes)?;
        Ok(Self {
            tid,
            config,
            stream: Mutex::new(stream),
            _phantom: PhantomData,
        })
    }

    /// The tid attached to requests on this connection.
    pub fn tid(&self) -> Tid {
        self.tid
    }

    /// Send one request and block until the coordinator returns its response.
    pub fn try_send_rpc(&self, message: G::Request) -> Result<G::Response, RpcError> {
        let request_bytes = encode(&RequestEnvelope {
            from: self.tid,
            request: message,
        })?;
        let mut stream = self.stream.lock().map_err(|_| {
            RpcError::Io(io::Error::other(
                "reverie-rpc-transport: blocking client mutex poisoned",
            ))
        })?;
        write_message(&mut *stream, &request_bytes)?;
        let response_bytes = read_message(&mut *stream, DEFAULT_MAX_FRAME_LEN)?;
        decode(&response_bytes)
    }
}

impl<G: GlobalTool> BlockingRpcClient<G> {
    /// Send a request, entering a caller-owned scope only around stream I/O.
    ///
    /// In-process backends use this to permit access to a private coordinator
    /// descriptor. Request serialization and response deserialization run
    /// outside the scope. Each read or write drops its scope before returning,
    /// including on an I/O error; framing and error handling are unchanged.
    pub fn try_send_rpc_with_io_scope<Scope>(
        &self,
        message: G::Request,
        mut enter: impl FnMut(RawFd) -> Scope,
    ) -> Result<G::Response, RpcError> {
        let request_bytes = encode(&RequestEnvelope {
            from: self.tid,
            request: message,
        })?;
        let mut stream = self.stream.lock().map_err(|_| {
            RpcError::Io(io::Error::other(
                "reverie-rpc-transport: blocking client mutex poisoned",
            ))
        })?;
        let response_bytes = {
            let mut io = ScopedIo {
                stream: &mut stream,
                enter: &mut enter,
            };
            write_message(&mut io, &request_bytes)?;
            read_message(&mut io, DEFAULT_MAX_FRAME_LEN)?
        };
        decode(&response_bytes)
    }
}

#[async_trait]
impl<G, S> GlobalRPC<G> for BlockingRpcClient<G, S>
where
    G: GlobalTool,
    S: Read + Write + Send,
{
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        self.try_send_rpc(message)
            .expect("reverie-rpc-transport: blocking RPC to coordinator failed")
    }

    fn config(&self) -> &G::Config {
        &self.config
    }
}

struct ScopedIo<'a, Enter> {
    stream: &'a mut UnixStream,
    enter: &'a mut Enter,
}

impl<Scope, Enter: FnMut(RawFd) -> Scope> Read for ScopedIo<'_, Enter> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let _scope = (self.enter)(self.stream.as_raw_fd());
        self.stream.read(buffer)
    }
}

impl<Scope, Enter: FnMut(RawFd) -> Scope> Write for ScopedIo<'_, Enter> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let _scope = (self.enter)(self.stream.as_raw_fd());
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        // UnixStream::flush performs no I/O and needs no descriptor exception.
        self.stream.flush()
    }
}

fn write_message(stream: &mut impl Write, payload: &[u8]) -> Result<(), RpcError> {
    let len = u32::try_from(payload.len()).map_err(|_| RpcError::FrameTooLarge {
        len: payload.len(),
        max: u32::MAX as usize,
    })?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_message(stream: &mut impl Read, max_len: usize) -> Result<Vec<u8>, RpcError> {
    // Read the 4-byte length prefix in one `read` on the common path. The loop
    // only re-enters the kernel on a short read or `EINTR`, collapsing the
    // former 1-byte probe + 3-byte remainder into a single syscall per hop.
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match stream.read(&mut header[filled..]) {
            // A clean EOF exactly at a frame boundary is a graceful close;
            // preserve the previous 1-byte-probe semantics.
            Ok(0) if filled == 0 => return Err(RpcError::Closed),
            // EOF partway through the header is a truncated frame.
            Ok(0) => return Err(RpcError::Io(io::Error::from(io::ErrorKind::UnexpectedEof))),
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(RpcError::Io(error)),
        }
    }

    let len = u32::from_be_bytes(header) as usize;
    if len > max_len {
        return Err(RpcError::FrameTooLarge { len, max: max_len });
    }

    let mut payload = vec![0; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod io_scope_tests;

#[cfg(test)]
mod into_parts_tests {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    use serde::Deserialize;
    use serde::Serialize;

    use super::*;

    #[derive(Debug, Default)]
    struct Counts {
        clones: AtomicUsize,
        config_drops: AtomicUsize,
    }

    #[derive(Debug, Default, Serialize, Deserialize)]
    struct Config {
        identity: u64,
        #[serde(skip)]
        counts: Arc<Counts>,
    }
    impl Clone for Config {
        fn clone(&self) -> Self {
            self.counts.clones.fetch_add(1, Ordering::SeqCst);
            Self {
                identity: self.identity,
                counts: self.counts.clone(),
            }
        }
    }
    impl Drop for Config {
        fn drop(&mut self) {
            self.counts.config_drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[derive(Default)]
    struct Global;
    #[async_trait]
    impl GlobalTool for Global {
        type Request = u8;
        type Response = u8;
        type Config = Config;
        async fn receive_rpc(&self, _: Tid, request: u8) -> u8 {
            request
        }
    }
    // Deliberately neither Send nor Read/Write: extraction only moves ownership.
    struct Stream(Rc<Cell<usize>>);
    impl Drop for Stream {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    fn client() -> (
        BlockingRpcClient<Global, Stream>,
        Arc<Counts>,
        Rc<Cell<usize>>,
    ) {
        let counts = Arc::new(Counts::default());
        let drops = Rc::new(Cell::new(0));
        (
            BlockingRpcClient {
                tid: Tid::from_raw(173),
                config: Config {
                    identity: 0x9182_7364,
                    counts: counts.clone(),
                },
                stream: Mutex::new(Stream(drops.clone())),
                _phantom: PhantomData,
            },
            counts,
            drops,
        )
    }
    fn assert_parts(
        client: BlockingRpcClient<Global, Stream>,
        counts: Arc<Counts>,
        drops: Rc<Cell<usize>>,
    ) {
        let (tid, config, stream) = client.into_parts();
        assert_eq!(tid, Tid::from_raw(173));
        assert_eq!(config.identity, 0x9182_7364);
        assert!(Arc::ptr_eq(&config.counts, &counts));
        assert!(Rc::ptr_eq(&stream.0, &drops));
        assert_eq!(counts.clones.load(Ordering::SeqCst), 0, "config was cloned");
        assert_eq!(
            counts.config_drops.load(Ordering::SeqCst),
            0,
            "config was dropped before transfer"
        );
        assert_eq!(drops.get(), 0, "stream was dropped before transfer");
        drop(config);
        assert_eq!(counts.config_drops.load(Ordering::SeqCst), 1);
        assert_eq!(drops.get(), 0);
        drop(stream);
        assert_eq!(drops.get(), 1);
    }
    #[test]
    fn exact_owners_move_without_callbacks_or_stream_bounds() {
        let (client, counts, drops) = client();
        assert_parts(client, counts, drops);
    }
    #[test]
    fn poisoned_owned_stream_is_recovered_without_changing_live_poison_rules() {
        let (client, counts, drops) = client();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = client.stream.lock().unwrap();
            panic!("intentional owned mutex poison");
        }));
        assert!(panic.is_err());
        assert!(client.stream.is_poisoned());
        assert_parts(client, counts, drops);
    }
    #[test]
    fn abandoned_lock_child() {
        if std::env::var_os("RPC_INTO_PARTS_ABANDONED_LOCK_CHILD").is_none() {
            return;
        }
        let (client, counts, drops) = client();
        std::mem::forget(client.stream.lock().unwrap());
        assert_parts(client, counts, drops);
    }
    #[test]
    fn abandoned_lock_is_not_acquired_during_owned_extraction() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "blocking_client::into_parts_tests::abandoned_lock_child",
                "--nocapture",
            ])
            .env("RPC_INTO_PARTS_ABANDONED_LOCK_CHILD", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut exceeded = false;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                exceeded = true;
                child.kill().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            !exceeded,
            "owned extraction tried to acquire the abandoned mutex; child reaped with {:?}",
            output.status
        );
        assert!(
            output.status.success(),
            "owned extraction child failed: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
