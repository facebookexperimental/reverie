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
rewriter rejects partial recovered-site coverage, signal-based B0 fallback,
privilege-bearing inputs, non-executable tools, and malformed output.

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
  `LD_PRELOAD` and arms the runtime via `REVERIE_E9PATCH_RUNTIME`, mirroring
  LiteInst's `preload_library_path`/`configure_command`.
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
  the e9patch fallback trap path can *mutate* a syscall result, not merely
  forward it.
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

**Different (the only intended differences):**

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

Because AOT-rewritten sites never trap, the shared SIGSYS dispatcher is only
reached by the residual sites e9patch cannot rewrite ahead of time (the dynamic
loader and startup code, the vDSO, and any uncovered or JIT-emitted site). For
those the shared fail-closed passthrough policy is exactly correct.

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
`spoof-getpid` built-in returns `reverie_preload::SPOOF_PID` from `getpid`,
demonstrating end to end that the fallback trap path can *mutate* a result.
Built-in tools run under the shared isolated in-process controller (the
demo/testing path, matching reverie-preload's standalone cdylib), not the
ptrace-hosted production controller.

What remains **not yet on the active backend path** is arbitrary-tool in-guest
dispatch — the same constraint LiteInst faces:

- an injected C payload cannot contain the arbitrary Rust `T: Tool` selected
  by `Backend::run`;
- the shared RPC transport carries `GlobalTool` requests, not syscall events
  or remote `Guest` operations.

`E9patchBackend::run` therefore still drives rewritten sites through ptrace
today; the shared preload runtime is installed as the fail-closed fallback for
un-rewritten sites. Moving the arbitrary-tool fast path fully in-guest requires
a type-erased remote-Guest protocol (or a Detcore-specific loadable runtime),
tracked as the next increment. Until then, the ptrace controller remains the
complete slow path and `Guest` owner.

## Toolchain

The upstream source stays opt-in because it is GPL-3.0 and has system build
dependencies. Activate and build it explicitly:

```bash
scripts/backend-submodule.sh activate e9patch
make -C third-party/e9patch
```

Set `REVERIE_E9TOOL` and `REVERIE_E9PATCH_BACKEND` when the executables are
not available as `e9tool` and the adjacent `e9patch` binary.
