//! Coordinator-side implementation of Reverie's backend contract.

use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use reverie::Backend;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;
use reverie_rpc_transport::RpcServer;

/// Environment variable naming the tool-specific preload DSO for a backend run.
pub const TOOL_PRELOAD_ENV: &str = "REVERIE_LITEINST_TOOL_PRELOAD";
/// Environment variable passed to the guest with the coordinator socket path.
pub const COORDINATOR_ENV: &str = "REVERIE_LITEINST_COORDINATOR";

// TODO-HUMAN-REVIEW(PR-127): Review LiteInst Backend lifecycle and preload contract.
/// Online LiteInst backend with a coordinator-owned `GlobalTool`.
pub struct LiteinstBackend;

impl LiteinstBackend {
    /// Runs a tool using an explicit tool-specific preload library.
    pub async fn run_with_preload<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (wait, global) = launch::<T>(command, config, preload.into(), false).await?;
        match wait {
            ChildWait::Status(status) => Ok((status.into(), global)),
            ChildWait::Output(_) => unreachable!("status run returned captured output"),
        }
    }

    /// Runs a tool and captures the guest's stdout and stderr.
    pub async fn run_with_output_and_preload<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        command.stdout(reverie::process::Stdio::piped());
        command.stderr(reverie::process::Stdio::piped());
        let (wait, global) = launch::<T>(command, config, preload.into(), true).await?;
        match wait {
            ChildWait::Output(output) => Ok((output, global)),
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }
}

#[reverie::backend(?Send)]
impl Backend for LiteinstBackend {
    async fn run<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let preload = tool_preload_path()?;
        Self::run_with_preload::<T>(command, config, preload).await
    }
}

enum ChildWait {
    Status(std::process::ExitStatus),
    Output(Output),
}

async fn launch<T>(
    mut command: Command,
    config: <T::GlobalState as GlobalTool>::Config,
    preload: PathBuf,
    capture_output: bool,
) -> Result<(ChildWait, T::GlobalState), Error>
where
    T: Tool + 'static,
{
    if !preload.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("tool preload {} is not a file", preload.display()),
        )
        .into());
    }

    let preload = preload.canonicalize()?;
    let arg0 = command.get_arg0().to_owned();
    let program = command.find_program()?;
    command.program(program).arg0(arg0);

    let directory = tempfile::Builder::new()
        .prefix("reverie-liteinst-")
        .tempdir()?;
    let socket = directory.path().join("coordinator.sock");
    let global = Arc::new(T::GlobalState::init_global_state(&config).await);
    let server = RpcServer::bind(&socket, global.clone(), config)
        .map_err(|error| io::Error::other(error.to_string()))?;

    let mut child_command = command.into_std_lossy();
    let configured_preload = child_command
        .get_envs()
        .find(|(key, _)| *key == OsStr::new("LD_PRELOAD"))
        .map(|(_, value)| value.map(ToOwned::to_owned));
    let mut ld_preload = preload.into_os_string();
    let inherited_preload = match configured_preload {
        Some(value) => value,
        None => std::env::var_os("LD_PRELOAD"),
    };
    if let Some(existing) = inherited_preload.filter(|value| !value.is_empty()) {
        ld_preload.push(OsStr::new(":"));
        ld_preload.push(existing);
    }
    child_command
        .env("LD_PRELOAD", ld_preload)
        .env(COORDINATOR_ENV, &socket);
    let mut child = child_command.spawn()?;
    let mut wait = tokio::task::spawn_blocking(move || {
        if capture_output {
            child.wait_with_output().map(ChildWait::Output)
        } else {
            child.wait().map(ChildWait::Status)
        }
    });
    let mut completed_connections = 0_usize;
    let wait = loop {
        tokio::select! {
            biased;
            result = server.serve_one() => {
                result.map_err(|error| io::Error::other(error.to_string()))?;
                completed_connections += 1;
            }
            result = &mut wait => {
                let wait = result.map_err(|error| io::Error::other(error.to_string()))??;
                if completed_connections == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "LiteInst guest exited before connecting to the coordinator; static executables and loader failures are unsupported",
                    )
                    .into());
                }
                break wait;
            }
        }
    };
    drop(server);
    let global = Arc::try_unwrap(global)
        .map_err(|_| io::Error::other("LiteInst coordinator state still has owners"))?;
    Ok((wait, global))
}

fn tool_preload_path() -> io::Result<PathBuf> {
    let path = std::env::var_os(TOOL_PRELOAD_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, TOOL_PRELOAD_ENV))?;
    if path.is_file() {
        Ok(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{TOOL_PRELOAD_ENV}={} is not a file", path.display()),
        ))
    }
}
