/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A tool's GlobalState, held by the launcher, for a tool that runs inside
//! each guest process.

use std::path::PathBuf;
use std::sync::Arc;

use reverie::GlobalTool;
use reverie_process::Command;
use reverie_process::ExitStatus;

use crate::TracerBuilder;

/// The environment variable naming the socket a plugin's tool reaches the
/// launcher's GlobalState through ([`run_with_global_state`]).
pub const GLOBAL_STATE_SOCKET_ENV: &str = "REVERIE_SABRE_EXAMPLE_RPC_SOCKET";

/// Run `command` under SaBRe with `plugin`, serving `global`, the GlobalState
/// of the plugin's tool, to every guest process over a socket the plugin
/// finds through [`GLOBAL_STATE_SOCKET_ENV`]. Returns once the program has
/// exited and every guest process has let go of `global`, so the caller then
/// holds the complete state.
pub async fn run_with_global_state<G>(
    mut command: Command,
    sabre: Option<PathBuf>,
    plugin: Option<PathBuf>,
    global: Arc<G>,
    config: G::Config,
) -> anyhow::Result<ExitStatus>
where
    G: GlobalTool + 'static,
{
    let socket_dir = tempfile::Builder::new()
        .prefix("reverie-sabre-counter-")
        .tempdir_in("/tmp")?;
    let socket_path = socket_dir.path().join("coordinator.sock");
    let retained_references = Arc::strong_count(&global);
    let server = reverie_rpc_transport::RpcServer::bind(&socket_path, global.clone(), config)?;
    let server_task = tokio::spawn(async move { server.serve().await });

    command.env(GLOBAL_STATE_SOCKET_ENV, &socket_path);
    let result: anyhow::Result<ExitStatus> = async {
        let mut child = TracerBuilder::new(command)
            .sabre(sabre)
            .plugin(plugin)
            .spawn()?;
        Ok(child.wait().await?)
    }
    .await;

    server_task.abort();
    match server_task.await {
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error.into()),
        Ok(Err(error)) => return Err(error.into()),
        Ok(Ok(())) => {}
    }

    // Accepted connection tasks outlive the listener. Keep their runtime alive
    // until connected descendants finish and release the shared GlobalTool.
    while Arc::strong_count(&global) > retained_references {
        tokio::task::yield_now().await;
    }

    result
}
