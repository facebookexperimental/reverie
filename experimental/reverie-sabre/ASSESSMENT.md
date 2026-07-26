# reverie-sabre backend assessment

Status as of 2026-07-24: the restored backend builds and runs a syscall-tracing
demo on dynamically linked Linux x86-64 programs. This remains an experimental
backend with a synchronous native API and a first-poll adapter for shared
`reverie::Tool` implementations; it is not interchangeable with `reverie-ptrace`.

## Verified functionality

- `recursion_protector.c` and `vfork_syscall.S` are vendored as regular files
  from the MIT-licensed SaBRe plugin API and compiled through Cargo.
- `reverie-sabre` links on the current Rust toolchain and its 41 library tests
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
`rrnewton/SaBRe` commit
`34065e7ddae6f1c90db7e0bf5c22a9aa89f9d605`, proposed upstream in
`srg-imperial/SaBRe#93`. That revision builds with CMake, Make, and GCC.
From `third-party/sabre`,
`PATH=/tmp/sabre-lit-venv/bin:$PATH cmake --build build-default --target tests -j2`
produced 70 passes, three unsupported tests, and the same three baseline failures:
`dumpkeys.sh`, `fgconsole.sh`, and `test_sigill.S`. At Hermit
`7ceec9d5263fb8e0af975f1099d098178db54510`, the L0 SaBRe gate (default log
level, no relaxations) passed all 147 strict compatibility probes with:

```bash
cd /home/newton/work/dev-hermit/worktrees/slot126
env HERMIT_SABRE_RUNNER=/home/newton/work/dev-hermit/worktrees_reverie/slot126/target/release/reverie-sabre-strace \
  HERMIT_SABRE_BINARY=/home/newton/work/dev-hermit/worktrees_reverie/slot126/third-party/sabre/build-default/sabre \
  HERMIT_SABRE_PLUGIN=/home/newton/work/dev-hermit/worktrees_reverie/slot126/target/release/libreverie_sabre_strace_plugin.so \
  VALIDATE_GATE_TIMEOUT_SECONDS=1800 with-proxy ./validate.sh --sabre-compat-only
```

See `../riptrace/README.md` for build and run commands.

## Backend model

SaBRe rewrites the guest and loads the tool into the guest process. The tool's
syscall callback is synchronous and operates directly on local guest memory.
Process-global state is hosted out of process and reached through a blocking
Unix-socket RPC client. This is materially different from the async,
out-of-process ptrace backend.

| Capability | `reverie-ptrace` | `reverie-sabre` |
| --- | --- | --- |
| Tool interface | Shared async `reverie::Tool` and `Guest` | Synchronous `reverie_sabre::Tool`, plus a first-poll `ReverieAdapter` subset |
| Syscall execution | Guest injection and tail injection | Direct in-process syscall execution |
| Guest memory | Remote memory abstraction | Direct `LocalMemory` access |
| Registers and stack | Read/write APIs | Syscall-frame GPR and return-IP access in `ReverieAdapter`; in-process scratch stack; no out-of-callback register access |
| Global state | Async typed global tool | Blocking generated RPC client/service |
| Thread state | Typed tool-defined state | Native runtime records; the adapter supplies typed `T::ThreadState` |
| Signals | Tool can influence delivery | Notification only |
| Event selection | Subscription filters | No shared subscription contract |
| CPU and lifecycle events | CPUID, RDTSC, exec, timers, exits | RDTSC, VDSO, function detours, partial lifecycle |
| Architecture | x86-64 and aarch64 paths | x86-64 only |

## Current limitations

- The SaBRe loader is activated and built separately; Cargo only builds the
  Reverie plugin and host command.
- Only the pinned loader revision and dynamically linked x86-64 guests are
  validated. Static executables are unsupported by upstream SaBRe.
- `ReverieAdapter` can run a shared `reverie::Tool` only when each handler
  completes on its first poll. `Guest::tail_inject` is the sole supported
  suspension; other pending futures fail with `EIO`.
- `execve` re-enters the pinned loader, but `execveat`, static executables,
  clone/vfork stress, VDSO calls, and detours need broader coverage.
- RPC is synchronous and reserves guest file descriptor 100. Trace formatting
  performs allocations and an RPC operation in the injected process.
- The restored runtime should not yet be treated as a production isolation
  boundary.

No shared Reverie core abstractions were changed to make this backend run.
