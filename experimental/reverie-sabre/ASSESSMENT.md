# reverie-sabre backend assessment

Status as of 2026-07-21: the restored backend builds and runs a syscall-tracing
demo on dynamically linked Linux x86-64 programs. This remains an experimental
backend with a separate synchronous tool API; it is not interchangeable with
`reverie-ptrace`.

## Verified functionality

- `recursion_protector.c` and `vfork_syscall.S` are vendored as regular files
  from the MIT-licensed SaBRe plugin API and compiled through Cargo.
- `reverie-sabre` links on the current Rust toolchain and its 17 library tests
  pass.
- `riptrace-tool` builds both an `rlib` and the
  `libriptrace_plugin.so` cdylib expected by SaBRe.
- The plugin exports `sbr_init` and handles syscalls, including synchronous RPC
  trace output and summary counts.
- The host command launches the pinned SaBRe loader, serves global-state RPC,
  propagates the guest exit status, and accepts explicit or environment-based
  loader and plugin paths.
- End-to-end runs of `/bin/true` and `/bin/echo` complete successfully. The
  `/bin/echo` check produced guest output plus an 86-line syscall trace.
- Successful `exec`, a fork/wait workload, and nonzero guest exit-status
  propagation have also been exercised through the demo.

The opt-in `third-party/sabre` submodule and `SABRE_UPSTREAM.toml` pin
`srg-imperial/SaBRe` commit
`05816ee066a7284bee8afd0e73eeb44455b254b4`. That revision builds with CMake,
Make, and GCC. Its three smoke tests pass. All 72 supported upstream tests pass
after test-only portability adjustments for explicit PIE output and current
`dumpkeys`/`fgconsole` exit codes; three host-dependent tests are unsupported.

See `../riptrace/README.md` for build and run commands.

## Backend model

SaBRe rewrites the guest and loads the tool into the guest process. The tool's
syscall callback is synchronous and operates directly on local guest memory.
Process-global state is hosted out of process and reached through a blocking
Unix-socket RPC client. This is materially different from the async,
out-of-process ptrace backend.

| Capability | `reverie-ptrace` | `reverie-sabre` |
| --- | --- | --- |
| Tool interface | Shared async `reverie::Tool` and `Guest` | Separate synchronous `reverie_sabre::Tool` |
| Syscall execution | Guest injection and tail injection | Direct in-process syscall execution |
| Guest memory | Remote memory abstraction | Direct `LocalMemory` access |
| Registers and stack | Read/write APIs | No tool-facing equivalent |
| Global state | Async typed global tool | Blocking generated RPC client/service |
| Thread state | Typed tool-defined state | Internal runtime records and lifecycle IDs |
| Signals | Tool can influence delivery | Notification only |
| Event selection | Subscription filters | No shared subscription contract |
| CPU and lifecycle events | CPUID, RDTSC, exec, timers, exits | RDTSC, VDSO, function detours, partial lifecycle |
| Architecture | x86-64 and aarch64 paths | x86-64 only |

## Current limitations

- The SaBRe loader is activated and built separately; Cargo only builds the
  Reverie plugin and host command.
- Only the pinned loader revision and dynamically linked x86-64 guests are
  validated. Static executables are unsupported by upstream SaBRe.
- The backend has no adapter for the shared Reverie `Tool`/`Guest`
  abstractions, so ptrace tools cannot switch backends by recompiling.
- Exec is deliberately rejected before image replacement because SaBRe cannot
  yet preserve kernel failure semantics while reinjecting the loader. Signals,
  clone/vfork, VDSO calls, and detours still need broader end-to-end coverage.
- RPC is synchronous and reserves guest file descriptor 100. Trace formatting
  performs allocations and an RPC operation in the injected process.
- The restored runtime should not yet be treated as a production isolation
  boundary.

No shared Reverie core abstractions were changed to make this backend run.
