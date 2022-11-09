/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use reverie_rpc::Service;
use tempfile::NamedTempFile;
use tokio::net::UnixListener;

use super::codec;

/// A global state server.
pub struct Server {
    socket: NamedTempFile<UnixListener>,
}

impl Server {
    /// Creates the server, but does not yet listen for incoming connections.
    pub fn new() -> Result<Self> {
        let sock_dir = dirs::runtime_dir().unwrap_or_else(|| PathBuf::from("/tmp"));

        let prefix = format!("reverie-{}-", std::process::id());
        let socket = tempfile::Builder::new()
            .prefix(&prefix)
            .suffix(".sock")
            .make_in(sock_dir, |path| UnixListener::bind(path))?;

        Ok(Self { socket })
    }

    /// Returns the path to the socket.
    pub fn sock_path(&self) -> &Path {
        self.socket.path()
    }

    /// Accepts new socket connections and processes them.
    pub async fn serve<S>(&self, service: S) -> !
    where
        S: Service + Clone + Send + Sync + 'static,
    {
        loop {
            match self.socket.as_file().accept().await {
                Ok((mut stream, _addr)) => {
                    let service = service.clone();

                    tokio::spawn(async move {
                        let mut reader_buf = Vec::with_capacity(1024);
                        let mut writer_buf = Vec::with_capacity(1024);

                        while let Ok(request) = codec::read(&mut stream, &mut reader_buf).await {
                            if let Some(response) = service.call(request).await {
                                // Only send back a response if this request has
                                // an associated response. This lets us have
                                // "send-only" messages, which are useful for
                                // accumulating state.
                                codec::write(&mut stream, &mut writer_buf, response)
                                    .await
                                    .unwrap();
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("connection failed: {}", e);
                }
            }
        }
    }
}
