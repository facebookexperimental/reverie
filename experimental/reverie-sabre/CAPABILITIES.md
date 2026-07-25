# reverie-sabre capabilities

Status as of 2026-07-21: experimental Linux x86-64 backend. The restored
runtime can run dynamically linked programs under the pinned SaBRe loader and
the riptrace demo, but it is not a drop-in replacement for
`reverie-ptrace`.

## Supported runtime behavior

| Area | Current behavior |
| --- | --- |
| Syscalls | Intercepts rewritten syscall instructions and invokes the synchronous in-process `Tool::syscall` callback. The default implementation performs the real syscall. |
| Guest memory | Exposes direct local-process memory through `LocalMemory`; there is no remote memory or register API. |
| Threads | Creates backend records lazily when an intercepted thread is first observed. Start and exit callbacks are emitted at most once for a tracked thread. Repeated pthread create/return/join waves are covered by the conformance gate. |
| Process exit | `exit_group` requests orderly exit from tracked threads, then issues a real kernel `exit_group` so threads that never reached an interception boundary cannot survive. Configurable timeout handling is supported. |
| Signals | Central handlers mediate standard catchable signals. Guest `rt_sigaction` registration and query are virtualized, including `SA_RESTART`. Linux default ignore, continue, stop, and terminate dispositions are preserved. |
| Signal exclusion | The kernel handler only enqueues fixed-size events. Tool and guest callbacks drain from normal runtime context; bounded-queue overflow coalesces standard signals. |
| Fork and exec | Forked children lazily construct a new Tool and RPC transport. `execve` re-enters the pinned SaBRe loader so the plugin remains active across the new image. `execveat` remains unsupported. |
| Timing and detours | Supports RDTSC callbacks, selected VDSO callbacks, and macro-generated function detours. |
| Global state | Uses a synchronous generated RPC client to a host-side service. The channel is process-local and recreated after fork. |
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

## Known limitations

- The SaBRe backend has a separate synchronous `reverie_sabre::Tool` API.
  Existing async `reverie::Tool` implementations cannot switch backends.
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
- There is no tool-facing register, stack, remote injection, subscription,
  CPUID, timer, or PMU interface comparable to `reverie-ptrace`.
- `execveat`, static binaries, non-x86-64 guests, loader distribution, and broad
  clone/vfork/exec stress coverage remain unsupported or unverified.
- `execve` validates the pathname and argv pointer list before replacing the
  image, but loader-time failures after SaBRe starts cannot return to the old image.
- RPC is blocking, reserves guest file descriptor 100, and injected-process
  formatting may allocate.

This backend is an extension under `experimental/`; it does not change shared
Reverie core abstractions. See `ASSESSMENT.md` for provenance and loader
build details.
