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
  are the same code in both backends. `install_runtime` installs the shared
  `InProcessSeccomp` controller identically to LiteInst's `install_runtime`.

**Different (the only two intended differences):**

1. **When patching happens.** e9patch rewrites every recovered syscall
   instruction **ahead of time** with `e9tool`; LiteInst rewrites each site **at
   runtime** on its first `SIGSYS` trap.
2. **Trampoline placement.** e9patch's trampolines are materialized by `e9tool`
   into the rewritten ELF; LiteInst allocates them at runtime in a reachable
   arena.

Because AOT-rewritten sites never trap, the shared SIGSYS dispatcher is only
reached by the residual sites e9patch cannot rewrite ahead of time (the dynamic
loader and startup code, the vDSO, and any uncovered or JIT-emitted site). For
those the shared fail-closed passthrough policy is exactly correct.

## Preload And RPC Boundary

The shared `reverie-preload` runtime and `reverie-rpc-transport` transport are
now wired into the crate: the dispatcher, the `install_runtime` path, and the
`.init_array` preload constructor build as part of the cdylib. What is **not yet
on the active backend path** is arbitrary-tool in-guest dispatch — the same
constraint LiteInst faces:

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
