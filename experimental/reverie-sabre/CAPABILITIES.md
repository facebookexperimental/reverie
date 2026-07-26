# reverie-sabre capabilities

Status as of 2026-07-26: experimental Linux x86-64 loader adapter. The restored
runtime can run dynamically linked programs under the pinned SaBRe loader and
shared example tools, but it is not a drop-in replacement for
`reverie-ptrace`.

## Supported runtime behavior

| Area | Current behavior |
| --- | --- |
| Syscalls | Intercepts rewritten syscall instructions and invokes the synchronous in-process `Tool::syscall` callback. The default implementation performs the real syscall. |
| Guest memory | Uses `SabreMemory` with kernel-validated `process_vm_readv` and `process_vm_writev` access to the current guest process. Invalid pointers report `EFAULT` instead of faulting the plugin. |
| Shared-tool guest context | The `ReverieAdapter` exposes the live SaBRe syscall frame through `Guest::regs`, supports writes to saved GPRs and the return IP through `Guest::set_regs`, and returns the current guest IP from `Guest::backtrace`. The fixed trampoline stack pointer, syscall number/result registers, flags, and segment state are read-only. |
| Shared-tool event selection | Both local and remote `ReverieAdapter` paths bypass `Tool::handle_syscall_event` for syscalls excluded by `Tool::subscriptions`. The SaBRe loader still rewrites and enters the plugin for those syscalls. |
| Threads | Creates backend records lazily when an intercepted thread is first observed. Start and exit callbacks are emitted at most once for a tracked thread. Repeated pthread create/return/join waves are covered by the conformance gate. |
| Process exit | `exit_group` requests orderly exit from tracked threads, then issues a real kernel `exit_group` so threads that never reached an interception boundary cannot survive. Configurable timeout handling is supported. |
| Signals | Central handlers mediate standard catchable signals. Guest `rt_sigaction` registration and query are virtualized, including `SA_RESTART`. Linux default ignore, continue, stop, and terminate dispositions are preserved. |
| Signal exclusion | The kernel handler only enqueues fixed-size events. Tool and guest callbacks drain from normal runtime context; bounded-queue overflow coalesces standard signals. |
| Fork and exec | Forked children lazily construct the same selected Tool with new process-local adapter state and RPC transport. Shared example counters reconnect to their host-owned `GlobalTool`. `execve` re-enters the pinned SaBRe loader so the plugin remains active across the new image. `execveat` remains unsupported. |
| Timing and detours | Supports RDTSC callbacks, selected VDSO callbacks, and macro-generated function detours. |
| Global state | Legacy plugins use a synchronous generated RPC client to a host-side service. Shared example counters use `reverie-rpc-transport` to keep one `GlobalTool` in the host; each guest thread opens a process-local connection and reconnects after fork or exec. |
| Loader inputs | Validated with dynamically linked x86-64 guests and the loader revision in `SABRE_UPSTREAM.toml`. |

SIGCHLD keeps children waitable when its guest disposition is `SIG_DFL`.
Default terminating actions are re-raised with `SIG_DFL`, so parent wait status
reports `WIFSIGNALED` and the original terminating signal.

## Conformance gate

The gate compiles two native workloads and runs each unchanged under the
ptrace `counter2` example and the SaBRe `riptrace` tool:

- `thread_lifecycle`: 128 pthread create, syscall, return, and join cycles.
- `signal_forwarding`: installs and queries handlers, forks and waits for a
  child, verifies SIGCHLD, SIGINT, and SIGTERM delivery, then resets SIGCHLD to
  `SIG_DFL` and confirms the next child remains waitable.

Activate and build upstream SaBRe at the pinned revision, then run:

```bash
scripts/backend-submodule.sh activate sabre
cmake -S third-party/sabre -B target/sabre
cmake --build target/sabre
SABRE_BINARY=target/sabre/sabre \
  experimental/reverie-sabre/conformance/run.sh all
```

The ptrace or SaBRe half can be isolated while diagnosing a failure:

```bash
experimental/reverie-sabre/conformance/run.sh ptrace
SABRE_BINARY=/path/to/sabre \
  experimental/reverie-sabre/conformance/run.sh sabre
```

A passing gate requires both workloads to exit zero on both backends before
the 30-second per-run timeout. Set `SABRE_CONFORMANCE_TIMEOUT` to override
that timeout and `SABRE_PLUGIN` to test a non-default plugin path.

Unit-level runtime checks are:

```bash
cargo test -p reverie-sabre
```

## Shared example-tool matrix

The following matrix was observed at Reverie `5b9446b` with release-built
`reverie-sabre-strace` artifacts and the pinned SaBRe loader revision
`34065e7d`. Each cell is one run with default tool logging and no relaxation
flags.

| Shared tool | `/bin/true` | `/bin/echo sabre-TOOL` | `/bin/cat /dev/null` | `/bin/sh -c 'exit 7'` |
| --- | --- | --- | --- | --- |
| `counter1` | PASS, exit 0 (6 syscalls observed) | PASS, exact guest output and exit 0 (87 syscalls observed) | PASS, exit 0 (93 syscalls observed) | PASS, guest exit 7 propagated (138 syscalls observed) |
| `counter2` | PASS, exit 0 (21 syscalls observed) | PASS, exact guest output and exit 0 (102 syscalls observed) | PASS, exit 0 (108 syscalls observed) | PASS, guest exit 7 propagated (153 syscalls observed) |
| `noop` | PASS, exit 0 | PASS, exact guest output and exit 0 | PASS, exit 0 | PASS, guest exit 7 propagated |

The shared `counter2` coordinator also aggregates forked process trees. A
`/bin/sh` workload that starts `/bin/true` in a child and waits for it
produces one summary covering two process identities and two thread
identities.

These are L0 compatibility observations for the synchronous SaBRe adapter.
The example runner does not implement Reverie's generic `Backend` contract and
does not load Detcore, so the matrix makes no Hermit L1/L2 determinism claim.

## Known limitations

- The SaBRe adapter has a synchronous `reverie_sabre::Tool` API and a
  `ReverieAdapter` subset for shared tools whose handlers complete on the first
  poll. Only `Guest::tail_inject` may suspend; other pending futures fail.
- Thread observation is callback-driven. A native thread that never reaches an
  intercepted runtime boundary has no backend record. Join itself is kernel
  behavior, not a distinct SaBRe tool event.
- Signal mediation is not kernel-exact. Handler masks, `SA_NODEFER`,
  `SA_RESETHAND`, alternate stacks, and the original `ucontext_t` are not
  reproduced. `SA_SIGINFO` handlers receive siginfo but a null context.
- Standard signal overflow may be coalesced at the 64-entry deferred queue.
  Realtime-signal ordering and payload guarantees are not implemented.
- Synchronous fault signals such as SIGILL and SIGSEGV, plus SIGKILL and
  SIGSTOP, are not centrally mediated. The SIGSTKFLT disposition is reserved
  as the runtime's controlled-exit signal.
- Tool callbacks can observe signals but cannot replace, suppress, or redirect
  delivery through a shared backend-neutral contract.
- Register access is limited to the live syscall callback frame, backtraces
  contain only the current guest IP, and there is no remote injection, CPUID,
  timer, or PMU interface comparable to `reverie-ptrace`.
- Syscall subscriptions bypass the shared handler after the loader enters the
  plugin; they do not prevent rewriting or plugin-entry overhead. Instruction
  subscriptions remain unsupported.
- `execveat`, static binaries, non-x86-64 guests, loader distribution, and broad
  clone/vfork/exec stress coverage remain unsupported or unverified.
- `execve` validates the pathname and argv pointer list before replacing the
  image, but loader-time failures after SaBRe starts cannot return to the old image.
- RPC is blocking, reserves guest file descriptor 100, and injected-process
  formatting may allocate.

This adapter is an extension under `experimental/`; it does not change shared
Reverie core abstractions. See `ASSESSMENT.md` for provenance and loader
build details.
