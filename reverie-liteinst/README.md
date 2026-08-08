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
   `reverie-rpc-transport::RpcServer<G>`. The launcher accepts concurrent local
   connections against the one coordinator-owned global state and cancels any
   outstanding connection tasks when the guest run ends.

The regression proof reports `calls=32 traps=1 hooks=32` and sends a real
Reverie tool RPC for every callback.

## Backend launcher

`LiteinstBackend` implements Reverie's `Backend` trait. It owns the single
`GlobalTool`, starts a UDS coordinator, sets `LD_PRELOAD`, runs the guest,
and returns its status and final global state. Existing preload APIs retain the
`REVERIE_LITEINST_COORDINATOR` environment contract. The example launcher
uses `run_with_output_and_preload_data` instead, passing the coordinator
path and selector in a sealed, dynamically allocated memfd that the preload
discovers, validates, consumes, and closes before guest `main`.
`REVERIE_LITEINST_TOOL_PRELOAD` must name a DSO that embeds the same concrete
`T` and calls `install_tool::<T>`.

Built-in `strace` and compatibility modes remain available through
`configure_command`. They use the same shared preload and LiteInst hook path
without a coordinator.

### Shared `reverie-preload` built-in tools

The single `REVERIE_LITEINST_TOOL` selector is a superset of the
LiteInst-native `strace`/`compat` modes: it also accepts the shared
`reverie-preload` built-ins `passthrough` and `spoof-getpid`, selected through
`configure_command_builtin(&mut Command, BuiltinTool)`. When one of these values
is set, the runtime installs the built-in verbatim through
`reverie_preload::install_builtin` — it does **not** run the LiteInst patching
dispatcher or prepare instrumentation. This is the LiteInst analog of the
e9patch built-in selector, so the same `BuiltinTool` value installs the same
shared dispatcher in both backends.

`spoof-getpid` proves the fallback/trap path can service **and mutate** a
syscall result: a raw `getpid` returns `reverie_preload::SPOOF_PID` instead of
the real PID, while `passthrough` leaves the result unchanged. The
`reverie-liteinst-spoof-guest` fixture and the
`spoof_getpid_builtin_mutates_getpid_result` /
`passthrough_builtin_preserves_getpid_result` tests in `tests/strace.rs` cover
both.

### Shared `reverie-preload` runtime configuration

The in-guest runtime's `SIGSYS` handler is installed through the shared
`reverie-preload` `RuntimeConfig`, whose `use_alt_stack` knob decides whether the
handler runs on an alternate signal stack. The `RuntimeConfig` and the
controller that honors it live in `reverie-preload` and are reviewed once; both
ld-preload backends install through that same seam. The launcher selects the
knob per guest with `set_guest_alt_stack(&mut Command, bool)`, which sets the
`REVERIE_LITEINST_ALT_STACK` environment variable (`1`/`0`, `true`/`false`,
`on`/`off`, `yes`/`no`; unset means the shared default, alt stack **on**). Only
the env-var spelling is LiteInst's — this is the LiteInst analog of e9patch's
`REVERIE_E9PATCH_ALT_STACK`, so the same `RuntimeConfig` drives both backends.
It applies to the LiteInst-dispatcher install path (the `strace`/`compat`/Detcore
modes); a shared `BuiltinTool` installs through `reverie_preload::install_builtin`
with the shared default. The `alt_stack_from_env_value` parser and the
`set_guest_alt_stack` round-trip are unit-tested in `src/runtime.rs` and
`src/lib.rs`.

## Patch publication modes

The stopped ptrace install helper uses LiteInst2's quiescent entrypoint. The
backend must have every other tracee thread stopped for the complete helper
call; the current single-process, single-thread hybrid satisfies that contract.
Planning and relocation remain unchanged, so this route can patch a cache-line
straddler without registering WordPatch++ traps.

The in-process SIGSYS dispatcher always uses concurrent publication because
other application threads may fetch the site. Single-line patches publish
atomically. Split patches retain the full guarded WordPatch++ protocol and
require `REVERIE_LITEINST_STRADDLER_STALENESS_TICKS` to be set above the
machine's measured `Tmax`; without that calibration they fail closed to the
trap path. Quiescent publication is never selected from this route.

## Current boundaries

- Dynamically linked, non-`AT_SECURE` Linux x86-64 guests only.
- One thread per process is supported by `LiteinstBackend`. Plain `fork` creates
  a fresh child-local `Tool` and reconnects to the shared coordinator. The same
  path accepts process-like `clone3`; `vfork` is translated to a COW child and
  preserves parent suspension through child exit. The coordinator drains
  inherited RPC connections to follow outliving and signaled descendants
  without attaching ptrace. Thread-style clone remains fail closed.
- Patchable syscalls dispatch the Tool in guest, and intercepted normal exits
  route thread and process callbacks on the supported single-threaded path.
  CPUID and RDTSC/RDTSCP route through the Tool; determinized CPUID responses
  hide RDRAND/RDSEED from conforming guests.
- Subscribed vDSO symbols share ptrace's authoritative symbol table, are
  rewritten into syscall entry sites before activation, and use ordinary
  LiteInst Tool hooks.
- Tool mode resets callable signal dispositions before activation, rejects
  later callable handlers, and validates that SIGSYS came from seccomp.
  `SIG_DFL` and `SIG_IGN` remain supported; guest signal handlers remain
  unsupported.
- Timer arming currently returns success without delivery. Clock reads use a
  calling-thread RDPMC RCB counter and deduct branches retired inside active
  LiteInst handlers. Hosts that deny perf-event access report the clock as
  unsupported. This is not PMU preemption or complete scheduling support.
- Rust tool futures must make progress synchronously. Coordinator RPC and guest
  syscall injection do so; a tool future that depends on an unrelated executor
  can stall.
- The five-byte patch window and executable mapping must be supported by
  `liteinst2`. Dynamic executable mappings without a prepared reachable arena
  fail closed.
- `execve` cannot safely cross the inherited filter because the handler and DSO
  mappings disappear. It remains fail closed; completing exec requires a
  non-seccomp in-guest coverage mechanism or another bootstrap that does not
  reintroduce a ptracer.
- This is in-process instrumentation, not a security sandbox.

Hermit CLI linkage and a published `liteinst2` revision are separate integration
steps. The direct Backend harness has run Detcore with `/bin/echo`, `/bin/true`,
and `/bin/cat /dev/null`; this does not make `hermit --backend liteinst` real
until that CLI path constructs `LiteinstBackend` and the corresponding Detcore
preload DSO on the same landed revisions.

## Fallback-surface observability

The runtime exports C-ABI counters that make the size and shape of the residual
fallback surface — the trapped syscalls the runtime could not route to the Tool
— observable from the guest:

- `reverie_liteinst_site_trap_count(address)` / `reverie_liteinst_site_hook_count(address)`
  — the per-**site** breakdown keyed by the un-patched instruction's address.
- `reverie_liteinst_fallback_dispatch_count()` — the process-wide total of
  syscalls that reached the fail-closed escape surface.
- `reverie_liteinst_fallback_syscall_count(number)` — the per-syscall-number
  breakdown, keyed the same way as `reverie_e9patch_fallback_syscall_count` so
  the two ld-preload backends expose a symmetric metric.

These counters are **per-process**: they are process-global statics, so a
`fork`/`clone` child copy-on-write inherits the parent's accumulated values.
Left alone, a child would report the parent's residual surface and hook activity
as its own. In compatibility/strace mode LiteInst forwards a fork-like syscall
itself, so `process_syscall` invokes the shared
[`reverie_preload::fork::ForkHook`] seam in the child (guarded by the shared
`is_fork_like` classifier and a zero return value): immediately after the fork
returns `0` in the child, `reset_fallback_observability` zeroes all three counter
families so the child's attribution starts clean. Only the observability fields
are reset — the site registry's functional patch state (address, hook, mapping
generation) is left intact because the child COW-inherits the installed hooks and
the same executable mappings, so its instrumentation keeps working. The reset is
relaxed-atomic and allocation/lock-free, so it is safe to run in the child from
inside the `SIGSYS` handler. This is the *same* fork-following seam and
reviewed-once mechanism reverie-e9patch uses for its per-process fallback
counters (round 7); LiteInst hosts its own dispatcher rather than the shared
`PassthroughDispatcher`, so it calls the hook directly, but reuses the shared
`ForkHook`/`is_fork_like` API rather than a private fork-detection path.

## Corpus sweep scorecard

A 20-program C corpus was run through `hermit --backend liteinst run --strict
--verify` and compared against native and the ptrace backend (full harness,
CSV, and per-program logs live in the `dev-hermit` parent workspace under
`experiments/liteinst_corpus_sweep_20260728/`, not in this repo). The result
characterizes the supported frontier and each boundary mode:

- **Single-process / single-thread C: 16/16 L2.** Every non-boundary program
  (arithmetic, heap, file I/O, env, libm, clocks, libc `rand`, `argv`,
  recursion, buffered stdio, `getrandom`, anonymous `mmap`, `gmtime`)
  determinized to a bitwise-identical repeat run, matching the ptrace baseline.
  Where a source is non-reproducible, LiteInst determinizes it *correctly*:
  `getpid` (spoofed PID) and `getrandom` (deterministic bytes) both diverge from
  native by design and still verify L2.
- **Boundary programs fail in the four documented modes** listed under *Current
  boundaries*, all shared with e9patch because both ld-preload backends route
  clone/fork through the same `reverie-preload` dispatcher and share this
  crate's signal/timer policy: thread `clone` and `fork` are rejected, a
  callable guest signal handler is rejected (fail-closed, nonzero exit), and an
  armed timer never fires (the guest spins to timeout).

### Caution: `--verify` cannot detect an ignored clone/fork rejection

`--verify` proves run₁ == run₂, **not** run == native. A guest that ignores the
errno from a rejected `clone`/`fork` and keeps running reaches a wrong but
perfectly reproducible result, which `--verify` then reports as "Determinism
verified" with `rc = 0`. In the sweep, the threaded and `fork` programs produced
degraded single-process output that was nonetheless blessed L2. This is a
property of the shared clone/fork policy plus `--verify` semantics, not a
LiteInst-only defect; treat an L2 pass on a program that legitimately uses
threads or child processes as suspect until multi-process support lands. The
rejection itself is covered by `unsafe_clone_is_rejected_in_compatibility_and_strace_modes`
and the compatibility-fork tests in `tests/strace.rs`.
