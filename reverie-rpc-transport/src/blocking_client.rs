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
pub struct BlockingRpcClient<G: GlobalTool> {
    tid: Tid,
    config: G::Config,
    stream: Mutex<UnixStream>,
    _phantom: PhantomData<fn() -> G>,
}

impl<G> BlockingRpcClient<G>
where
    G: GlobalTool,
{
    /// Connect and synchronously receive the coordinator's config handshake.
    pub fn connect(path: impl AsRef<Path>, tid: Tid) -> Result<Self, RpcError> {
        let mut stream = UnixStream::connect(path)?;
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
        write_message(&mut stream, &request_bytes)?;
        let response_bytes = read_message(&mut stream, DEFAULT_MAX_FRAME_LEN)?;
        decode(&response_bytes)
    }
}

#[async_trait]
impl<G> GlobalRPC<G> for BlockingRpcClient<G>
where
    G: GlobalTool,
{
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        self.try_send_rpc(message)
            .expect("reverie-rpc-transport: blocking RPC to coordinator failed")
    }

    fn config(&self) -> &G::Config {
        &self.config
    }
}

fn write_message(stream: &mut UnixStream, payload: &[u8]) -> Result<(), RpcError> {
    let len = u32::try_from(payload.len()).map_err(|_| RpcError::FrameTooLarge {
        len: payload.len(),
        max: u32::MAX as usize,
    })?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_message(stream: &mut UnixStream, max_len: usize) -> Result<Vec<u8>, RpcError> {
    let mut header = [0u8; 4];
    loop {
        match stream.read(&mut header[..1]) {
            Ok(0) => return Err(RpcError::Closed),
            Ok(1) => break,
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(RpcError::Io(error)),
        }
    }
    stream.read_exact(&mut header[1..])?;

    let len = u32::from_be_bytes(header) as usize;
    if len > max_len {
        return Err(RpcError::FrameTooLarge { len, max: max_len });
    }

    let mut payload = vec![0; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}
