---
name: liteinst-binary-instrumentation
description: "Use when changing LiteInst syscall discovery, text patching, trampolines, executable-map tracking, trap fallback, or allocator scopes."
---

# LiteInst Binary Instrumentation

## Use This Skill For

- `src/runtime.rs` site discovery, registry, patch, hook, or fallback changes.
- `src/patch_alloc.rs` allocation behavior.
- `liteinst2` API or pinned-revision updates.
- Bugs involving dynamic executable mappings, stale sites, text protections,
  repeated SIGSYS traps, or hook recursion.

## Execution Model

The seccomp SIGSYS event is a discovery mechanism, not the tool execution
context. On the first hit at a syscall instruction:

1. Validate the trap and locate the actual syscall site.
2. Claim the site in the fixed registry.
3. Validate enough complete instructions for LiteInst's patch window.
4. Install a replace-first hook and reachable trampoline, temporarily changing
   text protections only as required.
5. Redirect saved RIP to the hook trampoline and return from the handler.
6. Dispatch the Reverie tool after sigreturn in normal guest context.

If the site cannot be patched safely, retain trap fallback. Never run tool code
or coordinator RPC from the signal handler.

## Invariants Checklist

- One logical syscall produces one tool event on the first trap.
- Installed hooks enter `tool_trampoline`; nested trusted syscalls bypass the
  tool and cannot recursively patch or dispatch.
- Instruction validation covers the full patch window. Do not assume bytes
  after a syscall are readable, executable, or part of the same mapping.
- Trampoline arenas are reachable from their mapping. A newly executable map
  without a prepared arena must fall back safely.
- Text permissions are restored on every success and error path, and modified
  instructions become visible to executing cores.
- Mapping-generation updates for `mmap`, `munmap`, and `mremap` invalidate old
  site assumptions. Stale sites are revalidated or rejected.
- Fixed registry and arena limits fail predictably. Do not allocate through the
  guest allocator during signal-time installation.
- Patch installation uses the patch scope; normal tool dispatch uses the
  reusable dispatch scope. Neither scope may block or reenter itself.

## Investigation Workflow

1. Reproduce with a single focused test and `--test-threads=1`.
2. Determine whether the event used the first-hit trap, installed hook, or trap
   fallback. Use the exported trap/hook counters where possible.
3. Inspect the containing executable mapping and instruction bytes before
   changing scanner or patcher logic.
4. Check mapping generation, site state, and arena reachability.
5. Check trusted-syscall and allocator scope before blaming tool behavior.
6. Add a regression that exercises repeated execution, mapping churn, boundary
   bytes, or fallback as appropriate.

The core regression should preserve `calls=32 traps=1 hooks=32`. A changed
count needs a specific architectural reason and explicit review.

## Validation

```bash
cargo test -p reverie-liteinst --test strace -- --test-threads=1
cargo test -p reverie-liteinst --test rpc_tool -- --test-threads=1
cargo test -p reverie-liteinst --all-features -- --test-threads=1
cargo clippy -p reverie-liteinst --all-targets --all-features
```

Run on Linux x86-64. Report a missing architecture, seccomp, or dynamic-loader
precondition as a limitation; do not weaken the regression to make it pass.
