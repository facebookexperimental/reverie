# Reverie LiteInst Agent Guide

## Scope

This guide applies to `reverie-liteinst/`. It supplements the Reverie root
`AGENTS.md`; the stricter instruction wins. LiteInst is an experimental Linux
x86-64 Reverie backend that instruments a dynamically linked guest in-process.
It is not a security boundary and is not yet a general replacement for the
ptrace backend.

Read the relevant crate-local skill before changing code:

- `.llms/skills/liteinst-binary-instrumentation.md` for patching, trampolines,
  executable mappings, and allocator behavior.
- `.llms/skills/liteinst-tool-lifecycle.md` for coordinator bootstrap, tool
  dispatch, RPC, signal policy, and syscall injection.
- `.llms/skills/liteinst-testing.md` for the test matrix and evidence claims.

`CLAUDE.md`, `.claude/skills`, and `.agents/skills` are symlinks to this guide
and the canonical `.llms/skills` directory. Edit the canonical files only.

## How LiteInst Works

The crate combines `liteinst2`, `reverie-preload`, and
`reverie-rpc-transport`:

1. `LiteinstBackend` starts a Unix-domain coordinator and launches a dynamic,
   non-`AT_SECURE` guest with a tool-specific preload DSO.
2. The preload constructor connects to the coordinator before seccomp is
   installed, receives configuration, and installs the concrete `Tool`.
3. `reverie-preload` installs the SIGSYS handler, alternate signal stack,
   trusted syscall gate, and seccomp filter.
4. A syscall instruction traps on its first execution. The handler identifies
   the site, installs a LiteInst replace-first hook when possible, and changes
   the saved RIP so execution resumes through the hook trampoline.
5. After sigreturn, the trampoline calls `Tool::handle_syscall_event` in normal
   guest context. Later executions enter the same tool path directly through
   the patch. The first trap must not cause two tool events.
6. `LiteinstGuest<T>` exposes in-process memory, registers, stack, and guarded
   trusted-syscall injection. `CoordinatorRpc` uses the same UDS/bincode
   protocol as `RpcServer`.

The expected regression signature for a repeatedly executed syscall site is
`calls=32 traps=1 hooks=32`: one discovery trap, 32 hook/tool invocations.

## Source Map

- `src/backend.rs`: coordinator ownership, command launch, sealed-memfd
  bootstrap, output/status collection, and final `GlobalTool` recovery.
- `src/runtime.rs`: SIGSYS dispatch, executable-map preparation, site registry,
  patch installation, trampoline entry, fallback, and staleness tracking.
- `src/tool_host.rs`: typed tool installation, per-thread tool state,
  subscription dispatch, `LiteinstGuest`, injection guards, and lifecycle
  callbacks.
- `src/rpc.rs`: trusted coordinator connection and synchronous RPC transport.
- `src/patch_alloc.rs`: dedicated patch-install and tool-dispatch allocation
  scopes that avoid guest allocator reentry.
- `src/lib.rs`: preload constructor, built-in strace/compatibility selection,
  command configuration, counters, and crate exports.
- `tests/strace.rs`: direct preload, patching, compatibility-channel, fork,
  clone, and exec behavior.
- `tests/rpc_tool.rs`: coordinator RPC, reentry, SIGSYS state, subscription,
  lifecycle, and injected-exit behavior.
- `../reverie-examples/tests/liteinst.rs`: end-to-end backend/tool examples.

## Safety Invariants

- Never run a Reverie tool, perform coordinator RPC, or use the normal guest
  allocator inside the SIGSYS handler. The handler may prepare a hook and
  redirect saved context; tool dispatch happens after sigreturn.
- Preserve trusted-syscall bypass. Syscalls made by LiteInst, RPC, allocation,
  or the tool must not recursively enter the tool.
- Keep patch installation inside the patch-allocation scope and tool dispatch
  inside the dispatch-allocation scope. Do not introduce blocking or reentrant
  work while either scope is active.
- Validate the instruction and complete patch window before modifying text.
  Maintain near-trampoline reachability, text protection restoration, cache
  coherency, and trap fallback when a site cannot be patched.
- Treat executable mapping changes as site-invalidating events. `mmap`,
  `munmap`, and `mremap` generation changes must not leave a stale patch active.
- Connect and consume bootstrap data before installing seccomp. The preferred
  bootstrap is a validated, sealed memfd; the environment path is legacy.
- Keep the concrete tool type identical in the coordinator and preload DSO.
- Reject unsupported injection paths rather than partly emulating them.
  Clone/fork/exec and callable guest signal handlers have explicit restrictions.
- Tool futures are driven synchronously with a no-op waker. A future that
  depends on an unrelated executor will stall.

## Supported Boundary

Current support is Linux x86-64, dynamically linked non-`AT_SECURE` guests.
Tool mode supports one process/thread. Timer and clock APIs, PMU preemption,
guest callable signal handlers, exec bootstrap, and general clone/fork
injection are not implemented. CPUID, RDTSC/RDTSCP, RDRAND/RDSEED, and signal
death events are not routed as Reverie events.

Do not turn a direct LiteInst smoke test into a Hermit determinism claim.
Reverie-only validation is L0 evidence. L1 or L2 requires the landed Hermit CLI
path, exact compatible revisions, and Hermit's required record/verify evidence.

## Change Discipline

- Keep changes in the owning layer. Patching belongs in `runtime.rs`; typed
  tool behavior belongs in `tool_host.rs`; coordinator launch/bootstrap belongs
  in `backend.rs`; transport framing belongs in `rpc.rs`.
- Add an audit marker when changing the public backend or guest API, following
  the Reverie root guide.
- Add a regression that fails without the fix. Prefer a direct crate test for
  runtime safety and an examples test for public backend behavior.
- Avoid assertions based on incidental syscall counts except where the test is
  specifically proving first-trap/hook installation behavior.

## Validation

Run focused tests serially because they install process-wide signal/seccomp
state and launch instrumented guests:

```bash
cargo test -p reverie-liteinst --all-features -- --test-threads=1
cargo test -p reverie-examples --test liteinst -- --test-threads=1
```

For narrow iteration:

```bash
cargo test -p reverie-liteinst --test strace -- --test-threads=1
cargo test -p reverie-liteinst --test rpc_tool -- --test-threads=1
```

Before handoff, also run:

```bash
cargo fmt --all -- --check
cargo clippy -p reverie-liteinst --all-targets --all-features
```

Record the exact commit, host architecture, commands, and any skipped or
host-limited tests. A hang is a correctness failure: capture the failing test
and process state instead of silently increasing timeouts.
