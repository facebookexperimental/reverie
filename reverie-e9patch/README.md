# reverie-e9patch

`reverie-e9patch` integrates Reverie with the e9patch static binary rewriter
pinned in `third-party/e9patch`.

## Hybrid Backend

`E9patchBackend` implements Reverie's generic `Backend` contract. It prepares
the root x86-64 ELF, replaces every recovered `syscall` instruction with a
freestanding e9patch call trampoline, materializes the sealed result at a stable
named path, and runs it under Reverie's ptrace lifecycle controller.

The replacement trampoline passes e9tool's writable `state` register frame to
the controller through an identifiable `SIGTRAP`. The controller routes that
event to `Tool::handle_syscall_event`, exposes the original registers through
its existing `Guest` implementation, performs injected syscalls through its
trusted page, writes the result into the e9patch frame, and resumes after the
replaced instruction. Thus rewritten sites genuinely originate in e9patch;
this is not preprocessing followed by an unrelated ptrace syscall event.

The ptrace controller filters that boundary against the rewritten executable's
canonical pathname/inode, its `AT_ENTRY` load bias, executable mappings, and
the set of syscall virtual addresses recovered by the same e9tool invocation.
A frame
naming an address that e9tool did not patch is never delivered to the selected
`Tool`; its `SIGTRAP` is delivered normally, which fails closed by default. This
is the ahead-of-time counterpart of LiteInst's registered-hot-site collision
filter. It is deliberately **not** an authentication or isolation boundary
against malicious guest code: code in the same process can name a genuine
patched site and deliberately call the public fallback stub.

Ptrace remains attached for process lifecycle, signals, timers, CPUID/RDTSC,
syscalls in the loader and shared libraries, and complete arbitrary-tool
`Guest` semantics. The current hybrid therefore prioritizes correctness over
the intended in-guest fast path and still incurs a ptrace stop at rewritten
sites.

## Preparation

`E9patchRewriter::prepare` snapshots an x86-64 ET_EXEC or ET_DYN ELF and the
selected e9tool executables, invokes those snapshots with deterministic options,
and validates full recovered-site coverage. The result is a `PreparedBinary`
whose exact output bytes are held in an anonymous file with Linux write, grow,
shrink, and further-seal protections.

The accompanying `RewriteReport` records SHA-256 digests for the input, output,
e9tool, and e9patch executable bytes, plus the reported coverage counts. The
launcher also consumes e9tool's disassembly manifest and verifies that every
reported recovered syscall's virtual address maps its stated file offset and
the `0f 05` bytes in an executable `PT_LOAD` segment. The rewriter rejects
partial or internally inconsistent recovered-site coverage,
signal-based B0 fallback, privilege-bearing inputs, non-executable tools, and
malformed output.

## Shared With LiteInst Versus Different

e9patch is deliberately kept a close sibling of the LiteInst backend
(`reverie-liteinst`). Both are **ld-preload backends** that share the
`reverie-preload` runtime and fall back to the ptrace lifecycle owner for full
`Guest` semantics. The convergence is deliberate: correctness-critical code is
written and reviewed exactly once, in `reverie-preload`, and both backends reuse
it.

**Shared (identical code, from `reverie-preload`):**

- **ld-preload injection substrate.** The crate is now built as a `cdylib`
  (`libreverie_e9patch.so`) plus `rlib`, with a `preload-constructor` feature
  that installs a `.init_array` entry (`reverie_e9patch_initialize`) — exactly
  the shape LiteInst uses. `configure_command` prepends the cdylib to
  `LD_PRELOAD` and selects the shared pass-through built-in via
  `REVERIE_E9PATCH_TOOL`, mirroring LiteInst's
  `preload_library_path`/`configure_command`.
- **Fallback ptracer.** `E9patchBackend` runs the guest under Reverie's ptrace
  lifecycle controller, the same correctness-first owner LiteInst falls back to.
- **The same Reverie hooks.** `E9patchDispatcher` plugs into the shared
  `reverie_preload::dispatch::SyscallDispatcher` seam and reuses LiteInst's
  `PassthroughDispatcher` **verbatim**, so the SIGSYS handler, seccomp filter,
  trusted syscall gate, and fail-closed guard policy (execve, `SIGSYS`
  reservation, `sigaltstack`/`rt_sigprocmask` mutation, non-null `clone` stacks)
  are the same code in both backends.
- **The same lifecycle-controller seam.** Both backends install their runtime
  through reverie-preload's `LifecycleController` seam. Selecting a controller is
  a *config choice on one shared seam*, not a mechanism fork (see `RuntimeMode`).
- **The same shared `RuntimeConfig`.** The in-guest runtime installs through
  reverie-preload's shared `RuntimeConfig` (today the `use_alt_stack` knob that
  governs whether the `SIGSYS` handler runs on an alternate signal stack). The
  config struct and the controller that honors it are shared-crate code reviewed
  once; the e9patch launcher selects a non-default value with `set_guest_alt_stack`
  / `REVERIE_E9PATCH_ALT_STACK`, and unset reproduces the shared default exactly.
  Only the env-var spelling is e9patch's — the same shared-vs-local split as tool
  and controller selection.
- **The same shared built-in tools.** e9patch's in-guest runtime can install
  reverie-preload's shared `BuiltinTool`s (`passthrough`, `spoof-getpid`)
  **verbatim** via the shared `reverie_preload::install_builtin`, selected by
  `REVERIE_E9PATCH_TOOL`. This is the analog of LiteInst's built-in
  `strace`/`compat` selection (`configure_command(cmd, PreloadTool)`), except the
  tool — including the *mutating* `spoof-getpid` demo that returns
  `reverie_preload::SPOOF_PID` from `getpid` — is shared-crate code reviewed
  once, not backend-private. Only the env-var spelling is e9patch's. This proves
  the e9patch direct AOT path can *mutate* a syscall result, while residual
  un-rewritten sites still use the shared signal fallback.
- **The same fork-following seam.** The production dispatcher
  (`E9patchDispatcher::with_fork_reset`) arms reverie-preload's shared
  `fork::ForkHook` through `PassthroughDispatcher::with_fork_hook`, so each
  `fork`/`clone` child re-establishes its per-process runtime state in the child
  immediately after the fork-like syscall returns `0`. This is the *same* seam,
  and the same reviewed-once mechanism, that LiteInst uses for per-process reset
  (there, a fresh coordinator connection). e9patch's per-process state is the
  fallback observability below: the counters are process-global statics, so a
  child would otherwise copy-on-write inherit — and mis-report as its own — the
  parent's accumulated residual surface. What each backend re-establishes in the
  child differs; the mechanism does not. `E9patchDispatcher::new` remains the
  hook-less minimal dispatcher, mirroring `PassthroughDispatcher::new` versus
  `with_fork_hook`.

**Different:**

1. **When patching happens.** e9patch rewrites every recovered syscall
   instruction **ahead of time** with `e9tool`; LiteInst rewrites each site **at
   runtime** on its first `SIGSYS` trap.
2. **Trampoline placement.** e9patch's trampolines are materialized by `e9tool`
   into the rewritten ELF; LiteInst allocates them at runtime in a reachable
   arena.
3. **Which shared controller each selects** — a *consequence* of who owns
   lifecycle, expressed through the shared seam, not a third mechanism.
   LiteInst runs standalone, so it selects `InProcessSeccomp`
   (`RuntimeMode::InProcessFallback`). e9patch runs the guest under the shared
   fallback ptracer, which owns pre-`main` setup, `exec`/`clone` stops, and vDSO
   patching, so its production controller is `HybridPtrace`
   (`RuntimeMode::HybridPtrace`). This *is* the shared fallback ptracer, named
   through the shared seam — `install_runtime` (in-process) and
   `install_hybrid_runtime` (ptrace-hosted) sit side by side and differ only by
   the controller they hand to the identical `reverie_preload::install`.
4. **How a generic tool is selected.** Shared built-ins live in
   `reverie-preload`. A generic `T: Tool` instead lives in a tool-specific DSO,
   matching LiteInst: its constructor calls `install_tool::<T>`, connects to the
   coordinator, and publishes the AOT callback. Tool-data launchers use the
   same sealed inherited-memfd bootstrap pattern as LiteInst, so neither the
   coordinator path nor tool selector is added to the guest environment. The
   production `Backend::run<T>` path remains ptrace-hosted; the direct path is
   an explicit `run_direct_with_preload` family while its lifecycle boundary is
   still single-process and single-thread.

In shared built-in and opt-in generic-tool modes, AOT-rewritten sites dispatch
directly. The shared SIGSYS dispatcher is reached only by residual sites e9patch
could not rewrite (dynamic loader/startup code, vDSO, uncovered or JIT-emitted
code). A generic host forwards residual syscalls outside `T::subscriptions`
through the shared guards and fails a subscribed residual with `EOPNOTSUPP`,
because arbitrary Rust Tool code cannot run safely in signal context. In the
default `E9patchBackend<T>` path, the AOT callback stays null and rewritten
sites retain the marker/int3 ptrace route so the selected `T` remains
authoritative.

### Fallback-Surface Observability

`E9patchDispatcher::dispatch` records every syscall it services before
forwarding it, so the size of that residual fallback surface is observable from
the guest through two C-ABI counters:

- `reverie_e9patch_fallback_dispatch_count()` — total syscalls that reached the
  shared fallback dispatcher.
- `reverie_e9patch_fallback_syscall_count(number)` — the per-syscall-number
  breakdown.
- `reverie_e9patch_fallback_site_count(address)` — the per-**site** breakdown,
  keyed by the un-rewritten instruction's address.
- `reverie_e9patch_fallback_site_overflow()` — fallback services that could not
  be attributed to a per-site slot because the bounded site table was full.

The per-site counter is the **address-keyed** analog of LiteInst's
`reverie_liteinst_site_trap_count(address)`. Earlier the e9patch fallback was
observable only by **syscall number**; the shared
`reverie_preload::dispatch::SyscallEvent` also exposes the trapping
`instruction_pointer()`, so the residual sites e9patch could not rewrite ahead of
time (loader/startup, vDSO, uncovered or JIT-emitted code) *do* have addresses to
key on. There is no `hook`-count analog: the fallback never installs a runtime
hook (that is the AOT-vs-runtime difference), so every execution of an
un-rewritten site traps — making the per-site count the analog of LiteInst's
*trap* count specifically. The per-site table is bounded and async-signal-safe (a
fixed open-addressing table using only relaxed atomics plus one
`compare_exchange`, no allocation or locks); a site that cannot claim a slot is
tallied in the overflow counter rather than dropped, so a bounded table never
masquerades as full coverage.

All counting is relaxed-atomic and async-signal-safe, does not change the shared
forwarding decision, and directly answers the coverage question above: counts
near zero confirm e9tool's ahead-of-time rewriting is carrying the syscall load,
while nonzero counts localize the un-rewritten surface both by syscall number and
by exact instruction address.

These counters are **per-process**. They are process-global statics, so a
`fork`/`clone` child copy-on-write inherits the parent's accumulated values; left
alone, a child would report the parent's residual surface as its own. The
production dispatcher therefore arms the shared `fork::ForkHook` seam (see
*The same fork-following seam* above): immediately after a fork-like syscall
returns `0` in the child, the shared hook runs `reset_fallback_observability`,
zeroing all three counter families so the child's attribution starts clean. The
reset is relaxed-atomic and allocation/lock-free, so it is safe to run in the
child from inside the `SIGSYS` handler. This is the exact per-process-reset
mechanism LiteInst uses on fork, applied to e9patch's per-process state.

## Preload And RPC Boundary

The shared `reverie-preload` runtime and `reverie-rpc-transport` transport are
now wired into the crate: the dispatcher, the `install_runtime`/
`install_hybrid_runtime` paths, and the `.init_array` preload constructor build
as part of the cdylib. The launcher-side injection is also wired into the active
backend path: `E9patchBackend::spawn` calls `configure_guest_command` to prepend
`libreverie_e9patch.so` to the guest's `LD_PRELOAD` and arm the selected
`RuntimeMode` — **opt-in** via `REVERIE_E9PATCH_LDPRELOAD_FALLBACK`
(`hybrid`/`1` → ptrace-hosted controller, `fallback` → isolated in-process
controller). It defaults **off** so the validated ptrace-only path is unchanged
until the in-guest runtime is exercised against a real GPL-toolchain guest; the
`:: Backend:` diagnostic reports the active `ldpreload=` mode. The shared
`HybridPtrace` controller is still a documented skeleton in `reverie-preload`, so
`install_hybrid_runtime` returns `Unsupported` today — correct, because ptrace
still performs all event handling.

The in-guest runtime also exposes reverie-preload's shared **built-in tools**.
`configure_guest_builtin(command, tool)` prepends the cdylib and sets
`REVERIE_E9PATCH_TOOL` (which the constructor reads with priority over
`REVERIE_E9PATCH_RUNTIME`); the constructor then calls the shared
`reverie_preload::install_builtin`, so the dispatcher is shared-crate code. The
`spoof-getpid` built-in returns `reverie_preload::SPOOF_PID` from a rewritten
`getpid`, demonstrating end to end that the direct AOT path can *mutate* a result.
Built-in tools run under the shared isolated in-process controller (the
demo/testing path, matching reverie-preload's standalone cdylib), not the
ptrace-hosted production controller.

Generic Tool dispatch is now available through the same typed-DSO model as
LiteInst. `install_tool::<T>` owns per-thread `ThreadState`, implements an
in-process `Guest<T>` over the e9tool register frame and local memory, routes
`GlobalRPC` over the shared UDS/bincode protocol, runs start/post-exec/exit
callbacks, and protects nested Tool syscalls plus the coordinator descriptor.
`E9patchBackend::run_direct_with_preload` owns the coordinator and rewritten
guest for this opt-in path and returns its exit status without capturing or
overriding the command's stdio, matching LiteInst's explicit-preload launch.
Caller-created stdout and stderr pipes are drained concurrently and discarded,
so output beyond pipe capacity cannot deadlock a status-only launch.
`run_direct` resolves the same launch from `REVERIE_E9PATCH_TOOL_PRELOAD`, which
must name a tool-specific DSO embedding the same concrete `T`. This selector is
distinct from `REVERIE_E9PATCH_PRELOAD`, which locates the shared built-in
runtime rather than an arbitrary Tool DSO.
`run_direct_with_output_and_preload` remains available when the caller needs
captured stdout and stderr. The legacy coordinator environment contract remains
available for existing tool DSOs. New selectors use
`run_direct_with_output_and_preload_data`, which passes the coordinator path
and bounded opaque bytes in a sealed inherited memfd. A constructor consumes
exactly one matching descriptor with `take_preload_bootstrap`, closes it before
guest `main`, and calls `install_tool_from_bootstrap::<T>` without mutating the
environment. The selector must install the same concrete `T` as the
coordinator; unknown selectors fail before connection. Multiple matching or
malformed e9patch bootstraps fail closed and every matching descriptor is
closed. `run_direct_with_inherited_stdio_and_preload_data` uses that same
bootstrap while replacing any caller-configured stdin, stdout, and stderr with
inherited handles. It returns the guest status with empty output buffers, which
matches LiteInst for tools that share the launcher's sink and preserve ordering
between intercepted and pass-through writes. The captured-output launch remains
available as a separate API. The examples preload now also hosts LiteInst's
production Noop Tool through the sealed selector; a rewritten `getpid` retains
its native result because Noop subscribes to no events, complementing the
e9patch smoke Tool's subscribed-result mutation proof.

`E9patchBackend::run` deliberately still drives generic tools through ptrace:
the direct host does not yet cover process trees, exec rebootstrap, guest signal
handlers, timers/RCB events, or subscribed syscalls in residual shared-library
sites; its harness also executes the materialized rewrite path rather than the
original executable identity. The next increment is lifecycle expansion and a
production controller decision, not another Tool ABI.

## Toolchain

The upstream source stays opt-in because it is GPL-3.0 and has system build
dependencies. Activate and build it explicitly:

```bash
scripts/backend-submodule.sh activate e9patch
make -C third-party/e9patch -j8 release
```

Set `REVERIE_E9TOOL` and `REVERIE_E9PATCH_BACKEND` when the executables are
not available as `e9tool` and the adjacent `e9patch` binary.
