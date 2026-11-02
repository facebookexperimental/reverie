/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared production example Tools and optional preload hosting support.
//!
//! The default `runtime` selection retains the existing executable/preload
//! behavior. Disable default features to reuse the same Tool implementations
//! without a preload constructor or host runtime.

#![forbid(unsafe_op_in_unsafe_fn)]
// The reused production tool sources each declare the same test-only KVM helper.
#![allow(clippy::duplicate_mod)]

// Shared source modules also compile as standalone example binaries.
extern crate self as reverie_examples;

/// Generic host helpers without a preload constructor or allocator.
#[cfg(feature = "host")]
#[path = "shared_host.rs"]
pub mod host;

// This legacy example cdylib also exports an rlib. Preserve its prior scoped
// allocation policy explicitly, including example binaries that link the rlib.
#[cfg(feature = "runtime")]
reverie_liteinst::declare_legacy_scoped_tool_allocator!();

#[cfg(feature = "runtime")]
use std::ffi::CStr;
#[cfg(feature = "runtime")]
use std::ffi::OsStr;
#[cfg(feature = "runtime")]
use std::mem::MaybeUninit;
#[cfg(feature = "runtime")]
use std::os::unix::ffi::OsStrExt;
#[cfg(feature = "runtime")]
use std::path::Path;

#[allow(dead_code)]
#[path = "../chaos.rs"]
pub mod chaos;

#[allow(dead_code)]
#[path = "../chrome-trace/main.rs"]
pub mod chrome_trace;

#[allow(dead_code)]
#[path = "../chunky_print.rs"]
pub mod chunky_print;
#[allow(dead_code)]
#[path = "../counter1_tool.rs"]
pub mod counter1;

#[allow(dead_code)]
#[path = "../counter2_tool.rs"]
pub mod counter2;
#[allow(dead_code)]
#[path = "../noop.rs"]
pub mod noop;
#[allow(dead_code)]
#[path = "../recorder_tool.rs"]
pub mod recorder_tool;
#[allow(dead_code)]
#[path = "../strace/main.rs"]
pub mod strace;
#[allow(dead_code)]
#[path = "../strace_minimal.rs"]
pub mod strace_minimal;

pub(crate) use strace::config;
pub(crate) use strace::filter;

#[path = "../debug.rs"]
pub mod debug;

/// The same backend-independent production Tools used by the example hosts.
pub mod tools {
    pub use super::chaos;
    pub use super::chrome_trace;
    pub use super::chunky_print;
    pub use super::counter1;
    pub use super::counter2;
    pub use super::debug;
    pub use super::noop;
    pub use super::recorder_tool;
    pub use super::strace;
    pub use super::strace_minimal;
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the example-tool preload constructor and selector boundary.
#[cfg(feature = "runtime")]
#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_EXAMPLE_INIT: unsafe extern "C" fn(
    libc::c_int,
    *mut *mut libc::c_char,
    *mut *mut libc::c_char,
) = initialize;

#[cfg(feature = "runtime")]
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

#[cfg(feature = "runtime")]
unsafe extern "C" fn initialize(
    _argc: libc::c_int,
    _argv: *mut *mut libc::c_char,
    _environment: *mut *mut libc::c_char,
) {
    if !unsafe { loaded_as_preload() } {
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
        recorder_tool::NAME => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<recorder_tool::Recorder>(&socket)
        },
        other => fail(&format!("unknown example tool {other:?}")),
    };
    if let Err(error) = result {
        fail(&format!("tool initialization failed: {error}"));
    }
}

#[cfg(feature = "runtime")]
fn fail(message: &str) -> ! {
    eprintln!("reverie-examples preload: {message}");
    unsafe { libc::_exit(127) }
}
