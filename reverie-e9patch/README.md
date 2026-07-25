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

## Preload And RPC Boundary

The crate depends on the shared `reverie-preload` and
`reverie-rpc-transport` foundations so the event source can move in-process
without changing the backend boundary. They are not used on the active event
path yet:

- the preload coordinator client uses blocking standard-library socket I/O and
  is not async-signal-safe inside the SIGSYS handler;
- an injected C payload cannot contain the arbitrary Rust `T: Tool` selected
  by `Backend::run`;
- the shared RPC transport carries `GlobalTool` requests, not syscall events
  or remote `Guest` operations.

Moving handlers into the guest requires either a signal-safe raw-gate transport
plus a type-erased remote-Guest protocol, or a Detcore-specific loadable runtime.
Until then, the ptrace controller is the complete slow path and Guest owner.

## Toolchain

The upstream source stays opt-in because it is GPL-3.0 and has system build
dependencies. Activate and build it explicitly:

```bash
scripts/backend-submodule.sh activate e9patch
make -C third-party/e9patch
```

Set `REVERIE_E9TOOL` and `REVERIE_E9PATCH_BACKEND` when the executables are
not available as `e9tool` and the adjacent `e9patch` binary.
