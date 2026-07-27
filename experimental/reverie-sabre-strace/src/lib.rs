/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SaBRe plugin that runs shared Reverie example tools.

mod tools;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Tool as ReverieTool;
use reverie_process::Command;
use reverie_process::ExitStatus;
use reverie_sabre as sabre;
use reverie_syscalls::Displayable;
use reverie_syscalls::LocalMemory;
use reverie_syscalls::MemoryAccess;
use reverie_syscalls::Syscall;
use syscalls::Errno;

// AUTONOMOUS-BOT-IMPLEMENTED
/// Suppress syscall diagnostics while retaining the same shared Tool path.
pub const QUIET_ENV: &str = "REVERIE_SABRE_STRACE_QUIET";
static QUIET: AtomicBool = AtomicBool::new(false);

const COUNTER_RPC_SOCKET_ENV: &str = "REVERIE_SABRE_EXAMPLE_RPC_SOCKET";

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-160): Review the host-side example-counter coordinator API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterTool {
    Counter1,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-190): Review backend-neutral counter coordinator selection.
    Counter1Exact,
    Counter2,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-160): Review the host-side example-counter coordinator lifecycle.
pub async fn run_counter(
    kind: CounterTool,
    command: Command,
    sabre: Option<PathBuf>,
    plugin: Option<PathBuf>,
) -> anyhow::Result<ExitStatus> {
    match kind {
        CounterTool::Counter1 => {
            let global = Arc::new(tools::Counter1Global::default());
            let status = run_coordinated(
                command,
                sabre,
                plugin,
                global.clone(),
                tools::CounterConfig::coordinated(),
            )
            .await?;
            eprintln!(
                " [counter tool] Total system calls in process tree: {}",
                global.total()
            );
            Ok(status)
        }
        CounterTool::Counter1Exact => {
            let global = Arc::new(tools::ExactCounter1Global::default());
            let status = run_coordinated(command, sabre, plugin, global.clone(), ()).await?;
            eprintln!("counter1-global syscalls={}", global.total());
            Ok(status)
        }
        CounterTool::Counter2 => {
            let global = Arc::new(tools::Counter2Global::default());
            let status = run_coordinated(
                command,
                sabre,
                plugin,
                global.clone(),
                tools::CounterConfig::coordinated(),
            )
            .await?;
            let summary = global.summary();
            eprintln!(
                " [counter tool] Total system calls in process tree: {}, from {} processes, {} thread(s).",
                summary.total_syscalls, summary.processes, summary.threads
            );
            Ok(status)
        }
    }
}

async fn run_coordinated<G>(
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
        .tempdir()?;
    let socket_path = socket_dir.path().join("coordinator.sock");
    let retained_references = Arc::strong_count(&global);
    let server = reverie_rpc_transport::RpcServer::bind(&socket_path, global.clone(), config)?;
    let server_task = tokio::spawn(async move { server.serve().await });

    command.env(COUNTER_RPC_SOCKET_ENV, &socket_path);
    let result: anyhow::Result<ExitStatus> = async {
        let mut child = reverie_host::TracerBuilder::new(command)
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

/// Minimal shared Reverie tool that prints every intercepted syscall.
#[derive(Default)]
pub struct StraceTool {
    quiet: bool,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-155): Review exec argument decoding and envp redaction.
fn display_exec_redacted<M: MemoryAccess>(syscall: &Syscall, memory: &M) -> Option<String> {
    match syscall {
        // AUTONOMOUS-BOT-IMPLEMENTED
        Syscall::Execve(execve) => {
            let path = execve.path();
            let argv = execve.argv();
            Some(format!(
                "execve({}, {}, <envp redacted>)",
                path.display(memory),
                argv.display(memory)
            ))
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        Syscall::Execveat(execveat) => {
            let path = execveat.path();
            let argv = execveat.argv();
            Some(format!(
                "execveat({}, {}, {}, <envp redacted>, {})",
                execveat.dirfd(),
                path.display(memory),
                argv.display(memory),
                execveat.flags()
            ))
        }
        _ => None,
    }
}

#[reverie::tool]
impl ReverieTool for StraceTool {
    type GlobalState = ();
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-153): Review decoded syscall memory access and logging.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if self.quiet {
            return guest.inject(syscall).await.map_err(Error::from);
        }

        let tid = guest.tid();
        match syscall {
            // AUTONOMOUS-BOT-IMPLEMENTED
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                nostd_print::eprintln!("[{tid}] {}", syscall.display(&guest.memory()));
                guest.tail_inject(syscall).await
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                // A successful exec replaces the address space, so format its
                // input pointers while the old image is still readable. Do not
                // log envp because it commonly contains credentials.
                let memory = guest.memory();
                let pretty = display_exec_redacted(&syscall, &memory)
                    .expect("exec match arm must contain an exec syscall");
                nostd_print::eprintln!("[{tid}] {pretty}");
                guest.inject(syscall).await.map_err(Error::from)
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            _ => {
                let result = guest.inject(syscall).await;
                let memory = guest.memory();
                let syscall = syscall.display_with_outputs(&memory);
                nostd_print::eprintln!("[{tid}] {syscall} = {result:?}");
                result.map_err(Error::from)
            }
        }
    }
}

struct Plugin {
    adapter: tools::SharedAdapter,
}

#[sabre::tool]
impl sabre::Tool for Plugin {
    type Client = ();

    fn new(_client: Self::Client) -> Self {
        let kind = tools::ToolKind::from_environment();
        // SAFETY: Plugin construction runs before SaBRe starts guest callbacks.
        let quiet = unsafe { reverie_sabre::take_private_env(QUIET_ENV) }.is_some()
            || QUIET.load(Ordering::Acquire);
        QUIET.store(quiet, Ordering::Release);

        Self {
            adapter: tools::SharedAdapter::new(kind, quiet),
        }
    }

    fn syscall(&self, syscall: Syscall, _memory: &LocalMemory) -> Result<usize, Errno> {
        self.adapter.handle_syscall(syscall)
    }
    fn syscall_with_inject<F>(
        &self,
        syscall: Syscall,
        _memory: &LocalMemory,
        inject: F,
    ) -> Result<usize, Errno>
    where
        F: FnMut() -> usize + Send + Sync,
    {
        self.adapter.handle_syscall_with_inject(syscall, inject)
    }

    fn on_thread_start(&self, thread_id: u32) {
        self.adapter.handle_thread_start(thread_id);
    }

    fn on_thread_exit(&self, thread_id: u32) {
        self.adapter.handle_thread_exit(thread_id);
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;

    use reverie_syscalls::SyscallArgs;
    use reverie_syscalls::Sysno;

    use super::*;

    #[test]
    fn exec_displays_path_and_argv_without_environment() {
        let path = CString::new("/bin/echo").unwrap();
        let argument = CString::new("visible-argument").unwrap();
        let secret = CString::new("SECRET_TOKEN=do-not-log").unwrap();
        let argv = [path.as_ptr(), argument.as_ptr(), ptr::null()];
        let envp = [secret.as_ptr(), ptr::null()];
        let memory = LocalMemory::new();

        let execve = Syscall::from_raw(
            Sysno::execve,
            SyscallArgs::new(
                path.as_ptr() as usize,
                argv.as_ptr() as usize,
                envp.as_ptr() as usize,
                0,
                0,
                0,
            ),
        );
        let execveat = Syscall::from_raw(
            Sysno::execveat,
            SyscallArgs::new(
                libc::AT_FDCWD as usize,
                path.as_ptr() as usize,
                argv.as_ptr() as usize,
                envp.as_ptr() as usize,
                0,
                0,
            ),
        );

        for syscall in [execve, execveat] {
            let display = display_exec_redacted(&syscall, &memory).unwrap();
            assert!(display.contains("/bin/echo"));
            assert!(display.contains("visible-argument"));
            assert!(display.contains("<envp redacted>"));
            assert!(!display.contains("SECRET_TOKEN"));
            assert!(!display.contains("do-not-log"));
        }
    }
}
