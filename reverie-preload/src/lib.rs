/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared LD_PRELOAD + seccomp/SIGSYS instrumentation runtime for Reverie's
//! ld-preload backends (e9patch and liteinst).
//!
//! This crate factors the primitives every ld-preload backend needs out of any
//! one backend so they are written and reviewed **once**:
//!
//! * [`seccomp`] — the trap-everything-but-the-trusted-gate BPF filter;
//! * [`trap`] — the trusted syscall gate, the `SIGSYS` handler, and dispatcher
//!   registration;
//! * [`dispatch`] — the [`SyscallDispatcher`](dispatch::SyscallDispatcher) seam
//!   and the shared fail-closed [`PassthroughDispatcher`](dispatch::PassthroughDispatcher);
//! * [`fork`] — fork-following (the filter is inherited atomically; only
//!   per-process state must be reset);
//! * [`signal`] — signal multiplexing / reserved-signal policy;
//! * [`sync`] — the async-signal-safe [`SpinMutex`](sync::SpinMutex) the
//!   in-guest tool hosts use for RPC and per-thread state;
//! * [`lifecycle`] — the [`LifecycleController`](lifecycle::LifecycleController)
//!   seam that makes switching to a hybrid in-process-trap + ptrace backend an
//!   additive change rather than a rewrite;
//! * [`rpc`] (feature `coordinator-rpc`) — a synchronous coordinator RPC client
//!   wire-compatible with the async `reverie-rpc-transport`;
//! * [`tool_host`] (feature `coordinator-rpc`) — the backend-agnostic driver
//!   that polls an in-guest Reverie tool's `async` handlers with a no-op waker
//!   and carries the shared `ERESTARTSYS` restart protocol.
//!
//! # Coverage boundaries
//!
//! Established by the `research-ldpreload-derisking` task and enforced here:
//! this runtime is for **trusted, dynamically linked, non-`AT_SECURE`, no-exec**
//! x86-64 guests. It does not cover vDSO fast paths, the ~40 loader/startup
//! syscalls before the constructor runs, static binaries, or `execve`. `fork`
//! *is* fully covered because the kernel inherits the filter atomically.
//!
//! # Two ways to use it
//!
//! * **As a library (`rlib`):** e9patch/liteinst embed the runtime, register a
//!   custom [`SyscallDispatcher`](dispatch::SyscallDispatcher), and call
//!   [`install`].
//! * **As a standalone `LD_PRELOAD` (`cdylib`):** set `REVERIE_PRELOAD_TOOL` and
//!   preload `libreverie_preload.so`; the constructor installs a built-in tool.

#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("reverie-preload requires Linux x86-64");

pub mod dispatch;
pub mod fmt;
pub mod fork;
pub mod lifecycle;
pub mod seccomp;
pub mod signal;
pub mod sync;
pub mod trap;

#[cfg(feature = "coordinator-rpc")]
pub mod rpc;

#[cfg(feature = "coordinator-rpc")]
pub mod tool_host;

use std::env;
use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use crate::dispatch::PassthroughDispatcher;
use crate::dispatch::SyscallDispatcher;
use crate::dispatch::SyscallEvent;
use crate::lifecycle::InProcessSeccomp;
use crate::lifecycle::LifecycleController;
use crate::lifecycle::RuntimeConfig;

/// Environment variable selecting a built-in tool for the standalone cdylib.
pub const TOOL_ENV: &str = "REVERIE_PRELOAD_TOOL";
/// Environment variable overriding the located preload library path.
pub const LIB_ENV: &str = "REVERIE_PRELOAD_LIB";

/// The built-in tools the standalone `LD_PRELOAD` cdylib can install.
///
/// Real backends register their own [`SyscallDispatcher`]; these exist so the
/// `.so` is useful and testable on its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinTool {
    /// Forward every syscall (with the shared fail-closed guards). Proves the
    /// trap path end to end without altering guest behavior.
    Passthrough,
    /// Forward everything except `getpid`, which returns [`SPOOF_PID`]. Proves
    /// the trap can *mutate* a syscall result.
    SpoofGetpid,
}

/// The value [`BuiltinTool::SpoofGetpid`] returns for `getpid`.
pub const SPOOF_PID: i64 = 424_242;

impl BuiltinTool {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
            Self::SpoofGetpid => "spoof-getpid",
        }
    }

    fn parse(value: &OsStr) -> Option<Self> {
        if value == OsStr::new("passthrough") {
            Some(Self::Passthrough)
        } else if value == OsStr::new("spoof-getpid") {
            Some(Self::SpoofGetpid)
        } else {
            None
        }
    }

    fn into_dispatcher(self) -> Box<dyn SyscallDispatcher> {
        match self {
            Self::Passthrough => Box::new(PassthroughDispatcher::new()),
            Self::SpoofGetpid => Box::new(SpoofGetpidDispatcher),
        }
    }
}

/// A demo dispatcher that spoofs `getpid` and forwards everything else.
struct SpoofGetpidDispatcher;

impl SyscallDispatcher for SpoofGetpidDispatcher {
    fn dispatch(&self, event: &mut SyscallEvent) {
        // AUTONOMOUS-BOT-IMPLEMENTED
        if event.number() == libc::SYS_getpid {
            event.set_result(SPOOF_PID);
            return;
        }
        PassthroughDispatcher::new().dispatch(event);
    }
}

/// Install the runtime with a caller-provided dispatcher and controller.
///
/// This is the library entry point for e9patch/liteinst. Registers `dispatcher`,
/// then installs `controller` (which puts the SIGSYS handler and seccomp filter
/// in place).
///
/// # Safety
///
/// Installs process-global, irreversible state. Call exactly once, before
/// untrusted application threads start.
pub unsafe fn install(
    dispatcher: Box<dyn SyscallDispatcher>,
    controller: &dyn LifecycleController,
    config: &RuntimeConfig,
) -> io::Result<()> {
    trap::set_dispatcher(dispatcher);
    unsafe { controller.install(config) }
}

/// Install a built-in tool with the default in-process controller.
///
/// # Safety
///
/// See [`install`].
pub unsafe fn install_builtin(tool: BuiltinTool) -> io::Result<()> {
    let config = RuntimeConfig::default();
    unsafe { install(tool.into_dispatcher(), &InProcessSeccomp, &config) }
}

/// Read [`TOOL_ENV`] and, if it names a built-in tool, install the runtime.
///
/// Absent env var → the preload is inert (returns `Ok(())`), so an unrelated
/// process that happens to have the `.so` on `LD_PRELOAD` is unaffected.
pub fn initialize_from_environment() -> io::Result<()> {
    let Some(value) = env::var_os(TOOL_ENV) else {
        return Ok(());
    };
    let tool = BuiltinTool::parse(&value).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {TOOL_ENV} value {value:?}"),
        )
    })?;
    unsafe { install_builtin(tool) }
}

/// Locate the preload cdylib beside the current executable, or via [`LIB_ENV`].
pub fn preload_library_path() -> io::Result<PathBuf> {
    if let Some(path) = env::var_os(LIB_ENV) {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{LIB_ENV} is not a file"))
        });
    }

    let executable = env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "current executable has no parent")
    })?;
    [
        parent.join("libreverie_preload.so"),
        parent.join("deps/libreverie_preload.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_preload.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot find libreverie_preload.so beside {}",
                executable.display()
            ),
        )
    })
}

/// Configure `command` to load the runtime and select a built-in `tool`.
///
/// Prepends the located cdylib to `LD_PRELOAD` and sets [`TOOL_ENV`].
pub fn configure_command(command: &mut Command, tool: BuiltinTool) -> io::Result<()> {
    let mut preload = preload_library_path()?.into_os_string();
    if let Some(existing) = env::var_os("LD_PRELOAD").filter(|value| !value.is_empty()) {
        preload.push(OsStr::new(":"));
        preload.push(existing);
    }
    command
        .env("LD_PRELOAD", preload)
        .env(TOOL_ENV, tool.as_str());
    Ok(())
}

// TODO-HUMAN-REVIEW(#100): this constructor installs process-wide
// signal and seccomp state. Only a human reviewer may clear this marker.
/// Constructor entry point invoked by the dynamic loader for the cdylib.
///
/// # Safety
///
/// The loader must call this exactly once before application threads start.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_preload_initialize() {
    if let Err(error) = initialize_from_environment() {
        eprintln!("reverie-preload initialization failed: {error}");
        unsafe {
            libc::_exit(127);
        }
    }
}

#[cfg(feature = "preload-constructor")]
#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_PRELOAD_INIT: unsafe extern "C" fn() = reverie_preload_initialize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_tool_names_round_trip() {
        for tool in [BuiltinTool::Passthrough, BuiltinTool::SpoofGetpid] {
            let name = tool.as_str();
            assert_eq!(BuiltinTool::parse(OsStr::new(name)), Some(tool));
        }
        assert_eq!(BuiltinTool::parse(OsStr::new("nope")), None);
    }

    #[test]
    fn spoof_dispatcher_keeps_shared_fail_closed_guards() {
        let dispatcher = SpoofGetpidDispatcher;
        let mut mask_args = [0; 6];
        mask_args[0] = libc::SIG_BLOCK as u64;
        mask_args[1] = 0xdead_beef;
        let mut mask = SyscallEvent::new(libc::SYS_rt_sigprocmask, mask_args, 0);
        dispatcher.dispatch(&mut mask);
        assert_eq!(mask.result(), Some(-i64::from(libc::EPERM)));

        let mut exec = SyscallEvent::new(libc::SYS_execve, [0; 6], 0);
        dispatcher.dispatch(&mut exec);
        assert_eq!(exec.result(), Some(-i64::from(libc::ENOTSUP)));
    }
}
