# Reverie LiteInst

`reverie-liteinst` is an experimental Linux x86-64 Reverie backend built on the
standalone `liteinst2` patching library, the shared `reverie-preload` runtime,
and `reverie-rpc-transport`.

## Event path

1. A tool-specific DSO calls `install_tool::<T>` from its preload constructor.
   It connects to the coordinator and receives `T::GlobalState::Config` before
   seccomp is active.
2. `reverie-preload` installs the SIGSYS handler, alternate stack, trusted
   syscall gate, and seccomp filter.
3. The first syscall at an instruction reaches SIGSYS. The LiteInst dispatcher
   installs a replace-first hook and changes the saved signal-context RIP to the
   generated trampoline entry.
4. After `sigreturn`, the trampoline invokes `T::handle_syscall_event` in normal
   guest context. The first invocation and later patched invocations therefore
   use the same tool path; the first site trap is not also a tool execution.
5. `LiteinstGuest<T>` supplies in-process memory/register access and syscall
   injection through the trusted gate. `CoordinatorRpc<G>` serializes
   `GlobalRPC` messages over the same UDS/bincode framing as
   `reverie-rpc-transport::RpcServer<G>`.

The regression proof reports `calls=32 traps=1 hooks=32` and sends a real
Reverie tool RPC for every callback.

## Backend launcher

`LiteinstBackend` implements Reverie's `Backend` trait. It owns the single
`GlobalTool`, starts a UDS coordinator, sets `LD_PRELOAD` and
`REVERIE_LITEINST_COORDINATOR`, runs the guest, and returns its status and final
global state. `REVERIE_LITEINST_TOOL_PRELOAD` must name a DSO that embeds the
same concrete `T` and calls `install_tool::<T>`.

Built-in `strace` and compatibility modes remain available through
`configure_command`. They use the same shared preload and LiteInst hook path
without a coordinator.

## Current boundaries

- Dynamically linked, non-`AT_SECURE` Linux x86-64 guests only.
- One coordinator connection and one process are supported by
  `LiteinstBackend`. Fork/clone process-tree reconnect and exec rebootstrap are
  not implemented.
- Syscalls are hosted. Signal, CPUID, RDTSC/RDTSCP, RDRAND/RDSEED, and tool exit
  callbacks are not routed yet.
- Timer arming currently returns success but no RCB timer or preemption event is
  delivered. This supports the single-thread L0 smoke path; it is not strict
  scheduling or an L1/L2 determinism claim.
- Rust tool futures must make progress synchronously. Coordinator RPC and guest
  syscall injection do so; a tool future that depends on an unrelated executor
  can stall.
- The five-byte patch window and executable mapping must be supported by
  `liteinst2`. Dynamic executable mappings without a prepared reachable arena
  retain the trap fallback.
- `execve` cannot safely cross the inherited filter because the handler and DSO
  mappings disappear. A future exec bootstrap must be controller-owned.
- This is in-process instrumentation, not a security sandbox.

Hermit CLI linkage and a published `liteinst2` revision are separate integration
steps. The direct Backend harness has run Detcore with `/bin/echo`, `/bin/true`,
and `/bin/cat /dev/null`; this does not make `hermit --backend liteinst` real
until that CLI path constructs `LiteinstBackend` and the corresponding Detcore
preload DSO on the same landed revisions.
