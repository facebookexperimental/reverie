/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The process's one installed in-guest Tool and its coordinator connection.
//!
//! Backends retain interception, installation admission and runtime activation.
//! This owner only publishes the existing ToolHost and delegates real entries.

use std::io;
use std::sync::OnceLock;

use reverie::Tool;

use super::context::RegisterContext;
use super::event::InstructionEventKind;
use super::event::SyscallEvent;
#[cfg(feature = "exec-private-init")]
use super::exec_private::InitialImageAbortGuard;
#[cfg(feature = "exec-private-init")]
use super::exec_private::InitialImageControl;
use super::host::HostRuntime;
use super::host::ToolHost;
use super::rpc::CoordinatorRpc;
use crate::trap::raw_syscall6;

trait ToolHandler: Send + Sync {
    unsafe fn dispatch(&self, event: &mut SyscallEvent);
    unsafe fn dispatch_instruction(
        &self,
        kind: InstructionEventKind,
        context: &mut RegisterContext,
    );
    fn rpc(&self) -> &dyn std::any::Any;
    #[cfg(feature = "exec-private-init")]
    unsafe fn bind_initial_image(&self, control: &InitialImageControl) -> io::Result<()>;
    #[cfg(feature = "exec-private-init")]
    fn initialize_initial_image_lifecycle(&self, control: &InitialImageControl) -> io::Result<()>;
}

impl<T: Tool + 'static, R: HostRuntime> ToolHandler for ToolHost<T, R> {
    unsafe fn dispatch(&self, event: &mut SyscallEvent) {
        // SAFETY: the shared entry retains ToolHost's actual interception,
        // unique context, guest rights and memory-invariant requirements.
        unsafe { ToolHost::dispatch(self, event) };
    }

    unsafe fn dispatch_instruction(
        &self,
        kind: InstructionEventKind,
        context: &mut RegisterContext,
    ) {
        // SAFETY: the caller supplies this guest instruction's real, unique
        // saved context under the existing native/accounting/callback guards.
        unsafe { ToolHost::dispatch_instruction(self, kind, context) };
    }

    fn rpc(&self) -> &dyn std::any::Any {
        ToolHost::rpc(self)
    }

    #[cfg(feature = "exec-private-init")]
    unsafe fn bind_initial_image(&self, control: &InitialImageControl) -> io::Result<()> {
        // SAFETY: only the private publication entry calls this after storing
        // this stable Box, with the same authenticated client/control lineage.
        unsafe { ToolHost::bind_initial_image_control(self, control) }
    }

    #[cfg(feature = "exec-private-init")]
    fn initialize_initial_image_lifecycle(&self, control: &InitialImageControl) -> io::Result<()> {
        ToolHost::initialize_initial_image_lifecycle(self, control)
    }
}

static HANDLER: OnceLock<Box<dyn ToolHandler>> = OnceLock::new();

fn publish<T: Tool + 'static, R: HostRuntime>(host: ToolHost<T, R>) -> io::Result<()> {
    HANDLER
        .set(Box::new(host))
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "Reverie tool installed twice"))
}

/// Publish this process's prepared ToolHost, retaining it at one stable address.
///
/// A duplicate drops the rejected host and retains the first installed host.
/// This neither admits installation nor activates any interception frontend.
///
/// # Safety
/// The caller must have completed the actual allocator preflight and applicable
/// backend setup on the genuine initializing guest thread, before application
/// threads, dispatch or controller activation. Tool, root pid, subscriptions,
/// config and the one live CoordinatorRpc must describe that same guest.
/// Tool memory effects must preserve Rust's memory invariants. Retain the
/// caller's existing installation guard through subsequent activation/errors.
/// An authenticated InitialImage must use publish_initial_tool instead.
pub unsafe fn publish_tool<T: Tool + 'static, R: HostRuntime>(
    host: ToolHost<T, R>,
) -> io::Result<()> {
    publish(host)
}

/// Publish and privately bind the authenticated InitialImage's stable host.
///
/// # Safety
/// All publish_tool premises apply. The same consumed authenticated live client
/// must be in this host. control and fatal must belong to that exact exclusive
/// native image, on its initializing thread and private Tool FS/stack/phase,
/// before controller installation. fatal must be the actual live armed owner
/// retained by the installer across this call, subsequent activation and errors.
/// A borrow witnesses lifetime, not authentication; no typed value alone
/// establishes these premises. Neither owner may be replaced or finished here.
#[cfg(feature = "exec-private-init")]
pub unsafe fn publish_initial_tool<T: Tool + 'static, R: HostRuntime>(
    host: ToolHost<T, R>,
    control: &InitialImageControl,
    _fatal: &InitialImageAbortGuard,
) -> io::Result<()> {
    publish(host)?;
    let handler = HANDLER
        .get()
        .ok_or_else(|| io::Error::other("InitialImage installed handler is absent"))?;
    // SAFETY: publication has stored the stable host; the caller establishes
    // the same genuine live client/control/fatal lineage and native context.
    unsafe { handler.bind_initial_image(control) }
}

/// Run the installed InitialImage Tool's existing eager lifecycle.
///
/// # Safety
/// control and fatal must be borrowed from the same actual live affine installed
/// owner whose host was published and bound by publish_initial_tool. Existing
/// DETLOG/shared-OFD setup and genuine frontend installation must be complete.
/// Stay on that exclusive initializing thread/Tool FS/stack before guest
/// execution or finish, preserving Tool guest-memory invariants. fatal remains
/// armed throughout; an error must not disarm, replace or finish either owner.
/// This lookup creates no authorization, frontend, event, frame or client.
#[cfg(feature = "exec-private-init")]
pub unsafe fn initialize_initial_image_lifecycle(
    control: &InitialImageControl,
    _fatal: &InitialImageAbortGuard,
) -> io::Result<()> {
    let handler = HANDLER
        .get()
        .ok_or_else(|| io::Error::other("InitialImage Tool is not installed"))?;
    handler.initialize_initial_image_lifecycle(control)
}

/// Dispatch an actual intercepted syscall to this process's installed Tool.
///
/// # Safety
/// With an installed handler, this must be the genuine intercepted guest-thread
/// trap/hook/continuation path. event must carry its actual six operands and
/// guest rights; context must be zero or its unique live RegisterContext, never
/// retained or concurrently accessed. The installed Tool must instrument that
/// guest and its effects must preserve Rust's memory invariants. The caller
/// retains all existing RCB accounting, callback guards, native transfers,
/// pre-Tool protections/refusals and completion handling. Lookup supplies none
/// of this provenance and must not be used for pre-activation dispatch.
pub unsafe fn dispatch(event: &mut SyscallEvent) {
    match HANDLER.get() {
        // SAFETY: the caller satisfies the actual ToolHost dispatch contract.
        Some(handler) => unsafe { handler.dispatch(event) },
        None => event.result = -i64::from(libc::ENOSYS),
    }
}

/// Dispatch this guest's actual intercepted instruction to its installed Tool.
///
/// # Safety
/// The caller must supply that intercepted instruction's unique live saved
/// RegisterContext on the genuine guest thread with the correct installed Tool,
/// real guest rights and unchanged native/accounting/callback guards. Tool
/// effects must preserve Rust's memory invariants; no competing access or
/// retention is allowed. This is not a pre-activation or synthetic-frame API.
pub unsafe fn dispatch_instruction(kind: InstructionEventKind, context: &mut RegisterContext) {
    let handler = instruction_handler();
    // SAFETY: the caller establishes this instruction's actual provenance.
    unsafe { handler.dispatch_instruction(kind, context) };
}

fn instruction_handler() -> &'static dyn ToolHandler {
    match HANDLER.get() {
        Some(handler) => handler.as_ref(),
        None => fatal(126),
    }
}

/// Sends `request` to the coordinator's global state and waits for its
/// response, from the installed Tool's own synchronous code running inside a
/// Tool callback but outside the callback's own `send_rpc`: for example from
/// a synchronous method a callback calls, where no [`reverie::Guest`] is at
/// hand. Inside a callback the runtime's own syscalls are not intercepted.
/// Guest code outside a callback cannot use this: its syscalls on the
/// coordinator connection are guest syscalls, which the runtime refuses. It uses the process's one existing
/// coordinator connection, so it reconnects after a fork exactly as callbacks
/// do, and it adds no descriptor.
///
/// Fails, without sending, when no Tool is installed in this process, when
/// `G` is not the installed Tool's global state, or when another request of
/// this process is in flight on the connection (re-entry, which waiting would
/// deadlock). It also fails, with ESRCH, while the running callback has
/// staged an injection that ends the guest (an exit, or a SIGKILL of the
/// guest itself) and goes on regardless, as every effect of such a callback
/// is refused; the exit callbacks that follow can use it.
pub fn blocking_global_rpc<G: reverie::GlobalTool + 'static>(
    request: G::Request,
) -> io::Result<G::Response> {
    if super::host::callback_ending_staged() {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    let handler = HANDLER
        .get()
        .ok_or_else(|| io::Error::other("no in-guest Tool is installed in this process"))?;
    let rpc = handler
        .rpc()
        .downcast_ref::<CoordinatorRpc<G>>()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the requested global state is not the installed Tool's",
            )
        })?;
    rpc.send_blocking_unless_in_flight(request).map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "another coordinator request of this process is in flight",
        )
    })
}

fn fatal(status: i32) -> ! {
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [status as u64, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct UninstalledGlobal;

    #[reverie::global_tool]
    impl reverie::GlobalTool for UninstalledGlobal {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _from: reverie::Tid, _request: ()) {
            panic!("missing-handler lookup cannot send");
        }
    }

    #[test]
    fn missing_handler_rpc_keeps_the_error_without_a_new_connection() {
        assert!(HANDLER.get().is_none());
        let error = blocking_global_rpc::<UninstalledGlobal>(()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error.to_string(),
            "no in-guest Tool is installed in this process"
        );
    }

    #[test]
    fn missing_instruction_owner_terminates_without_a_fabricated_frame() {
        assert!(HANDLER.get().is_none());
        // A missing-owner lookup component control, not native admission or
        // dispatch. The actual instruction entry calls this same private lookup.
        // No ToolHost, syscall event, register frame or frontend is fabricated.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let _ = std::panic::catch_unwind(|| {
                let _ = instruction_handler();
            });
            unsafe { libc::_exit(95) };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            assert!(waited == 0 || waited == child);
            if waited == child {
                break;
            }
            if std::time::Instant::now() >= deadline {
                unsafe { libc::kill(child, libc::SIGKILL) };
                assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                panic!("missing-owner terminal gate did not finish within five seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 126);
    }
}
