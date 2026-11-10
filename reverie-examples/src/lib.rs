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

// The conformance callers and core tests compile these same source bodies.
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/basics.rs"]
pub mod conformance_basics;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/exit.rs"]
pub mod conformance_exit;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/inject_then_tail.rs"]
pub mod conformance_inject_then_tail;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/stat.rs"]
pub mod conformance_stat;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/vdso.rs"]
pub mod conformance_vdso;

#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/at_random.rs"]
pub mod conformance_at_random;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/initial_stack_pointer.rs"]
pub mod conformance_initial_stack_pointer;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/stack.rs"]
pub mod conformance_stack;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/suppression.rs"]
pub mod conformance_suppression;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/thread_start.rs"]
pub mod conformance_thread_start;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/thread_start_tail.rs"]
pub mod conformance_thread_start_tail;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/tool_fixtures/thread_start_tail_witness.rs"]
pub mod conformance_thread_start_tail_witness;

/// Backend-independent Tools used by generic conformance callers.
#[cfg(feature = "conformance-tools")]
pub mod conformance_tools {
    pub use super::conformance_at_random as at_random;
    pub use super::conformance_basics as basics;
    pub use super::conformance_exit as exit;
    pub use super::conformance_initial_stack_pointer as initial_stack_pointer;
    pub use super::conformance_inject_then_tail as inject_then_tail;
    pub use super::conformance_stack as stack;
    pub use super::conformance_stat as stat;
    pub use super::conformance_suppression as suppression;
    pub use super::conformance_thread_start as thread_start;
    pub use super::conformance_thread_start_tail as thread_start_tail;
    pub use super::conformance_thread_start_tail_witness as thread_start_tail_witness;
    pub use super::conformance_vdso as vdso;
}

// The same guest bodies are used by the generic tests and command images.
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/at_random_rust_guest.rs"]
pub mod conformance_guest_at_random;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/basics_rust_guest.rs"]
pub mod conformance_guest_basics;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/exit_rust_guest.rs"]
pub mod conformance_guest_exit;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/inject_then_tail_rust_guest.rs"]
pub mod conformance_guest_inject_then_tail;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/stack_rust_guest.rs"]
pub mod conformance_guest_stack;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/stat_rust_guest.rs"]
pub mod conformance_guest_stat;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/suppression_rust_guest.rs"]
pub mod conformance_guest_suppression;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/thread_start_guest.rs"]
pub mod conformance_guest_thread_start;
#[cfg(feature = "conformance-tools")]
#[path = "../../tests/support/vdso_rust_guest.rs"]
pub mod conformance_guest_vdso;

/// Backend-independent guest bodies used by generic conformance commands.
#[cfg(feature = "conformance-tools")]
pub mod conformance_guests {
    pub use super::conformance_guest_at_random as at_random;
    pub use super::conformance_guest_basics as basics;
    pub use super::conformance_guest_exit as exit;
    pub use super::conformance_guest_inject_then_tail as inject_then_tail;
    pub use super::conformance_guest_stack as stack;
    pub use super::conformance_guest_stat as stat;
    pub use super::conformance_guest_suppression as suppression;
    pub use super::conformance_guest_thread_start as thread_start;
    pub use super::conformance_guest_vdso as vdso;
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
