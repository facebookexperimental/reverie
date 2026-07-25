# reverie-e9patch

`reverie-e9patch` is the integration boundary between Reverie and the e9patch
static binary rewriter pinned in `third-party/e9patch`.

## Current Preparation API

`E9patchRewriter::prepare` snapshots an x86-64 ET_EXEC or ET_DYN ELF and the
selected e9tool executables, invokes those snapshots with deterministic options,
and validates full recovered-site coverage. The result is a `PreparedBinary`
whose exact output bytes are held in an anonymous file with Linux write, grow,
shrink, and further-seal protections. `PreparedBinary::artifact` opens an
independent read-only handle to those sealed bytes for a future runtime to read
and materialize. Patched e9patch output cannot execute directly from an
anonymous memfd because its loader
reopens `/proc/self/exe`; a runtime must provide a stable named image.

The accompanying `RewriteReport` records SHA-256 digests for the input, output,
e9tool, and e9patch executable bytes, plus the reported coverage counts. This is
digest-auditable preparation metadata, not proof of the external tool semantics
or of its dynamic loader and shared libraries.

The rewriter rejects partial recovered-site coverage, reported signal-based B0
fallback, set-ID or file-capability-bearing inputs, non-executable tools, and
malformed output. It invokes e9tool with `tactic-B0=false`; the pinned e9tool
only prints `num_patched_B0` when that tactic is enabled, and any site requiring
B0 while disabled instead fails the full-coverage check. Non-ELF entrypoints are
outside this API. Tool output is drained concurrently with bounded retained
diagnostics, but tool execution does not currently have a timeout.

This crate intentionally does not implement `reverie::Guest` or
`reverie::Backend`. It does not launch a guest or generate Reverie events.

## Native Backend Gap

A ptrace-free e9patch backend still needs an external controller and a real
injected hook ABI. E9Syscall's synchronous seven-register hook is insufficient
for arbitrary Reverie tools. The missing work includes:

- async global RPC and parked-thread transport;
- full register, memory, stack, and injected-syscall round trips;
- clone, fork, exec, thread-start, and destructor lifecycle;
- signal, CPUID, RDTSC, and timer events;
- root ELF, loader, DSO, child-exec, and direct-syscall coverage.

No forwarding `E9patchGuest` is provided: wrapping ptrace's Guest would add no
e9patch behavior and would misrepresent the native gap. Native work is blocked
on the shared preload/controller and cross-process RPC foundation tracked by
the backend roadmap.

## Toolchain

The upstream source stays opt-in because it is GPL-3.0 and has system build
dependencies. Activate and build it explicitly:

```bash
scripts/backend-submodule.sh activate e9patch
make -C third-party/e9patch
```

Set `REVERIE_E9TOOL` and `REVERIE_E9PATCH_BACKEND` when the executables are
not available as `e9tool` and the adjacent `e9patch` binary.
