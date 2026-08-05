---
name: liteinst-tool-lifecycle
description: "Use when changing LiteInst backend launch, preload bootstrap, tool installation, coordinator RPC, syscall dispatch, injection, signals, or lifecycle callbacks."
---

# LiteInst Tool Lifecycle

## Ownership Boundaries

- `backend.rs` owns the coordinator, preload command construction, sealed-memfd
  bootstrap, child status/output, and recovery of `GlobalTool`.
- `tool_host.rs` owns typed tool installation, subscriptions, per-thread state,
  guest access, injection guards, and exit callbacks.
- `rpc.rs` owns the trusted coordinator connection and wire operations.
- `lib.rs` owns constructor activation and built-in strace/compatibility modes.

Keep protocol or launch changes out of the patching layer unless they alter the
actual trampoline contract.

## Bootstrap And Activation

The tool-specific preload DSO and coordinator must instantiate the same
concrete `Tool` type. The DSO calls `install_tool::<T>` during its constructor.
Before seccomp activation it must:

1. Locate and validate bootstrap data.
2. Connect the Unix-domain coordinator and reserve the protected connection.
3. Decode tool configuration and subscriptions.
4. Initialize the tool and global handler.
5. Consume and close bootstrap resources.

Prefer `run_with_output_and_preload_data` and its sealed, dynamically allocated
memfd. Treat `REVERIE_LITEINST_COORDINATOR` as compatibility-only. Do not leak
control environment variables or descriptors into the guest-visible contract.

## Dispatch Rules

- Unsubscribed syscalls may be hosted directly only after applying all safety
  guards. Subscribed calls build a Reverie `Syscall` and invoke
  `handle_syscall_event`.
- Initialize per-thread tool state and call `handle_thread_start` before its
  first event. Route supported thread/process exits through their callbacks.
- `LiteinstGuest<T>` accesses in-process memory and hook-context registers.
  Register changes must be reflected in the resumed context.
- Injection uses the trusted raw-syscall path. Preserve rejection of unsafe
  clone/fork/exec and protected signal operations.
- Callable guest signal handlers are unsupported. Preserve runtime handlers and
  allow only supported `SIG_DFL`/`SIG_IGN` changes.
- Tool futures are synchronously polled with a no-op waker. Do not await work
  that requires an unrelated executor.
- Fatal bootstrap or activation errors must fail closed; partial activation is
  not a supported mode.

## RPC Rules

Connect before installing seccomp. Attribute requests with the trusted thread
identity, preserve framing compatibility with `RpcServer`, and use the trusted
syscall path for transport I/O. Do not hold the RPC lock across tool operations
that can recursively request coordinator access.

## Unsupported Behavior

LiteInst tool mode is currently one process/thread. General fork/clone/exec,
guest callable signal handlers, timer APIs, deterministic clocks, and PMU
preemption are not implemented. Preserve explicit errors rather than returning
plausible but incorrect values. The compatibility preload has separate limited
fork behavior; do not generalize it to typed tool mode.

## Validation

Choose tests by the changed contract:

```bash
# Coordinator RPC, reentry, signal state, subscriptions, lifecycle, injection
cargo test -p reverie-liteinst --test rpc_tool -- --test-threads=1

# Constructor, built-in modes, descriptors, fork/clone/exec boundaries
cargo test -p reverie-liteinst --test strace -- --test-threads=1

# Public backend and concrete example tools
cargo test -p reverie-examples --test liteinst -- --test-threads=1
```

Then run the full crate suite and clippy. Document the exact command and commit;
direct backend success is L0 evidence, not Hermit record/verify evidence.
