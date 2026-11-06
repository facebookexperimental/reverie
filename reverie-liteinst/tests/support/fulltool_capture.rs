//! Run the actual unit-state coordinator beside the existing bounded capture.

use std::path::PathBuf;
use std::process::Command;

use super::liteinst_runtime::contract;

pub fn run(
    command: Command,
    held: contract::HeldInputs,
    socket: PathBuf,
) -> Result<contract::CapturedRun, contract::ContractError> {
    let failure = |message: String| contract::ContractError {
        message,
        captures: Vec::new(),
    };
    let coordinator = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| failure(format!("FullTool coordinator runtime: {error}")))?;
    coordinator.block_on(async {
        let server = reverie_rpc_transport::RpcServer::bind(&socket, std::sync::Arc::new(()), ())
            .map_err(|error| failure(format!("FullTool coordinator bind: {error}")))?;
        let (done, completion) = tokio::sync::oneshot::channel();
        let child = tokio::task::spawn_blocking(move || {
            let captured = contract::run_without_input(command, &held);
            let _ = done.send(());
            captured
        });
        let (serving, captured) = tokio::join!(
            server.serve_until(async {
                let _ = completion.await;
            }),
            child,
        );
        let captured = captured.unwrap_or_else(|error| {
            Err(failure(format!("FullTool bounded child worker: {error}")))
        });
        match (serving, captured) {
            (Ok(()), captured) => captured,
            (Err(error), Ok(captured)) => Err(contract::ContractError {
                message: format!("FullTool coordinator failed: {error}"),
                captures: vec![captured],
            }),
            (Err(error), Err(mut captured)) => {
                captured
                    .message
                    .push_str(&format!("; FullTool coordinator failed: {error}"));
                Err(captured)
            }
        }
    })
}
