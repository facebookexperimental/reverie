/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Preload hosting support for production Reverie example tools.

#![forbid(unsafe_op_in_unsafe_fn)]
// The reused production tool sources each declare the same test-only KVM helper.
#![allow(clippy::duplicate_mod)]

use std::ffi::CStr;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Narrow concrete Tool shared by the e9patch preload and its real-tool test.
pub mod e9patch_smoke;

#[allow(dead_code)]
#[path = "../chaos.rs"]
mod chaos;

#[allow(dead_code)]
#[path = "../chrome-trace/main.rs"]
mod chrome_trace;

#[allow(dead_code)]
#[path = "../chunky_print.rs"]
mod chunky_print;
#[allow(dead_code)]
#[path = "../counter1_tool.rs"]
mod counter1;

#[allow(dead_code)]
#[path = "../counter2_tool.rs"]
mod counter2;
#[allow(dead_code)]
#[path = "../noop.rs"]
mod noop;
#[allow(dead_code)]
#[path = "../strace/main.rs"]
pub(crate) mod strace;
#[allow(dead_code)]
#[path = "../strace_minimal.rs"]
mod strace_minimal;

pub(crate) use strace::config;
pub(crate) use strace::filter;
pub(crate) use strace::global_state;

/// Runs the production Noop Tool through e9patch's direct AOT path.
///
/// The sealed selector and coordinator both use the same concrete `NoopTool`,
/// while the caller supplies the example preload DSO that embeds it. Noop
/// subscribes to no syscalls, so rewritten guest sites retain their native
/// results.
pub async fn run_e9patch_noop_with_preload(
    command: reverie::process::Command,
    preload: impl Into<std::path::PathBuf>,
) -> Result<(reverie::process::Output, ()), reverie::Error> {
    reverie_e9patch::E9patchBackend::run_direct_with_output_and_preload_data::<noop::NoopTool>(
        command,
        (),
        preload,
        b"noop",
    )
    .await
}

/// Runs the production Strace Tool through e9patch's direct AOT path with a
/// single `write` syscall filter.
///
/// The fixed filter keeps unsubscribed guest syscalls native while proving a
/// rewritten root-image write reaches the existing Strace handler and is
/// injected through the direct `Guest` implementation. A subscribed residual
/// write remains outside the direct host boundary and fails closed.
pub async fn run_e9patch_write_strace_with_preload(
    command: reverie::process::Command,
    preload: impl Into<std::path::PathBuf>,
) -> Result<reverie::process::Output, reverie::Error> {
    let config = strace::Config {
        filters: vec![strace::Filter {
            inverse: false,
            syscalls: vec![reverie::syscalls::Sysno::write],
        }],
    };
    let (output, _) = reverie_e9patch::E9patchBackend::run_direct_with_output_and_preload_data::<
        strace::Strace,
    >(command, config, preload, b"strace")
    .await?;
    Ok(output)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the example-tool preload constructor and selector boundary.
#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_EXAMPLE_INIT: unsafe extern "C" fn(
    libc::c_int,
    *mut *mut libc::c_char,
    *mut *mut libc::c_char,
) = initialize;

const E9PATCH_EXAMPLE_TOOL_ENV: &str = "REVERIE_E9PATCH_EXAMPLE_TOOL";

unsafe fn loaded_as_preload() -> bool {
    let mut info = MaybeUninit::<libc::Dl_info>::uninit();
    let found = unsafe {
        libc::dladdr(
            initialize as *const () as *const libc::c_void,
            info.as_mut_ptr(),
        )
    };
    if found == 0 {
        return false;
    }
    let info = unsafe { info.assume_init() };
    if info.dli_fname.is_null() {
        return false;
    }
    let mapped_name = unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes();
    if mapped_name.is_empty() {
        return false;
    }
    let mapped_path = Path::new(OsStr::from_bytes(mapped_name));
    match (mapped_path.canonicalize(), std::env::current_exe()) {
        (Ok(mapped_path), Ok(executable)) => mapped_path != executable,
        _ => false,
    }
}

unsafe extern "C" fn initialize(
    _argc: libc::c_int,
    _argv: *mut *mut libc::c_char,
    _environment: *mut *mut libc::c_char,
) {
    if !unsafe { loaded_as_preload() } {
        return;
    }
    let e9patch_bootstrap = match unsafe { reverie_e9patch::take_preload_bootstrap() } {
        Ok(bootstrap) => bootstrap,
        Err(error) => fail(&format!("invalid e9patch preload bootstrap: {error}")),
    };
    if let Some(bootstrap) = e9patch_bootstrap {
        match unsafe { reverie_e9patch::take_preload_bootstrap() } {
            Ok(None) => {}
            Ok(Some(_)) => fail("e9patch preload bootstrap was not consumed"),
            Err(error) => fail(&format!("invalid residual e9patch bootstrap: {error}")),
        }
        let selected = match String::from_utf8(bootstrap.tool_data) {
            Ok(selected) => selected,
            Err(_) => fail("e9patch example tool selector is not valid UTF-8"),
        };
        let result = match selected.as_str() {
            "e9patch-smoke" => unsafe {
                reverie_e9patch::install_tool_from_bootstrap::<e9patch_smoke::AotCounterTool>(
                    &bootstrap.coordinator,
                )
            },
            "noop" => unsafe {
                reverie_e9patch::install_tool_from_bootstrap::<noop::NoopTool>(
                    &bootstrap.coordinator,
                )
            },
            "strace" => unsafe {
                reverie_e9patch::install_tool_from_bootstrap::<strace::Strace>(
                    &bootstrap.coordinator,
                )
            },
            other => fail(&format!("unknown e9patch bootstrap tool {other:?}")),
        };
        if let Err(error) = result {
            fail(&format!(
                "e9patch bootstrap tool initialization failed: {error}"
            ));
        }
        return;
    }
    if let Some(socket) = std::env::var_os(reverie_e9patch::COORDINATOR_ENV) {
        let selected = std::env::var_os(E9PATCH_EXAMPLE_TOOL_ENV)
            .and_then(|value| value.into_string().ok())
            .unwrap_or_else(|| fail(&format!("missing {E9PATCH_EXAMPLE_TOOL_ENV}")));
        // SAFETY: this constructor runs before application-created threads.
        unsafe { std::env::remove_var(E9PATCH_EXAMPLE_TOOL_ENV) };
        let result = match selected.as_str() {
            // TODO-HUMAN-REVIEW(PR-269): Review the
            // concrete e9patch Tool selection used by the direct AOT proof.
            "e9patch-smoke" => unsafe {
                reverie_e9patch::install_tool::<e9patch_smoke::AotCounterTool>(socket)
            },
            other => fail(&format!("unknown e9patch example tool {other:?}")),
        };
        if let Err(error) = result {
            fail(&format!("e9patch tool initialization failed: {error}"));
        }
        return;
    }
    let bootstrap = match unsafe { reverie_liteinst::take_preload_bootstrap() } {
        Ok(Some(bootstrap)) => bootstrap,
        Ok(None) => return,
        Err(error) => fail(&format!("invalid preload bootstrap: {error}")),
    };
    let selected = match String::from_utf8(bootstrap.tool_data) {
        Ok(selected) => selected,
        Err(_) => fail("example tool selector is not valid UTF-8"),
    };
    let socket = bootstrap.coordinator;

    let result = match selected.as_str() {
        // TODO-HUMAN-REVIEW(PR-157): Review chaos preload tool selection.
        "chaos" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<chaos::ChaosTool>(&socket)
        },
        // TODO-HUMAN-REVIEW(PR-159): Review ChromeTrace preload tool selection.
        "chrome-trace" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<chrome_trace::ChromeTrace>(&socket)
        },
        "counter1" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<counter1::CounterLocal>(&socket)
        },
        // TODO-HUMAN-REVIEW(PR-146): Review counter2 preload tool selection.
        "counter2" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<counter2::CounterLocal>(&socket)
        },
        // TODO-HUMAN-REVIEW(PR-152): Review chunky_print preload tool selection.
        "chunky-print" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<chunky_print::ChunkyPrintLocal>(&socket)
        },
        "strace" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<strace::Strace>(&socket)
        },
        // TODO-HUMAN-REVIEW(PR-193): Review minimal-strace preload selection.
        "strace-minimal" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<strace_minimal::StraceTool>(&socket)
        },
        "noop" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<noop::NoopTool>(&socket)
        },
        other => fail(&format!("unknown example tool {other:?}")),
    };
    if let Err(error) = result {
        fail(&format!("tool initialization failed: {error}"));
    }
}

fn fail(message: &str) -> ! {
    eprintln!("reverie-examples preload: {message}");
    unsafe { libc::_exit(127) }
}
