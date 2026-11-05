# The Tool API

A tool is two trait implementations. This chapter tours the surface
your handlers can use; the rustdoc on the [`Tool`] trait is the
authoritative reference, and this chapter is the map to it.

[`Tool`]: https://docs.rs/reverie-core

## Handlers: one per event stream

Each trappable event has a handler with a default implementation, so
you override only what you subscribe to:

| Handler | Event | Default |
|---|---|---|
| `handle_syscall_event` | a syscall at entry | `tail_inject` (perform it unchanged) — override only to do more |
| `handle_thread_start` | a new thread | no-op |
| `handle_post_exec` | after a successful `execve`, in the new image (thread/process state carried across unchanged) | no-op |
| `handle_exec_commit` | *before* the image is replaced, once an injected exec can no longer fail; old image still live; **KVM-family only today**, and injecting a syscall here is refused | no-op |
| `handle_signal_event` (+ raw/structured variants) | an inbound signal | deliver normally |
| `handle_timer_event` | a tool-scheduled timer | no-op |
| `handle_cpuid_event`, `handle_rdtsc_event` | those instructions (x86-64, subscription-gated) | execute natively |
| `on_exit_thread`, `on_exit_process` | teardown | no-op |

Lifecycle points are contractual: backends call `Tool::new` per new
process, `init_thread_state` per new thread, and the exit hooks as
threads and processes wind down. If your accounting depends on a
destructor running, say so in tests on every backend you support —
lifecycle coverage is precisely where backends differ today (see
[Backends](backends.md)).

## The Guest handle: your hands inside the handler

Every handler receives `guest: &mut T` where `T: Guest<Self>`. Through
it a tool can:

* read and write guest memory, and read registers (with typed access
  to syscall arguments — next chapter but one). Writing the full
  register file (`set_regs`) is *not* universal: its default returns
  `Errno::ENOSYS`, and only backends that implement it accept it —
  the fail-closed pattern for every optional `Guest` operation;
* **inject** syscalls: perform this syscall and never come back
  (`tail_inject` → `Never`), perform one and get its result
  (`inject`), or perform none and fabricate the result;
* **send RPC** to global state (`send_rpc`), typed by your
  `GlobalTool::Request`/`Response`;
* schedule timers, query task identity, and — where the backend
  supports it — the richer `Guest` operations documented per-method.

Handlers are `async`: a blocking syscall in one guest thread does not
block the tool's handling of other threads. Write handlers as if they
run concurrently, because on most backends they do.

## Subscriptions: trap only what you need

`Tool::subscriptions` declares what to trap: the specific syscall
numbers, plus (on x86-64) the CPUID and RDTSC instruction classes.
Other events (signals, timers, lifecycle) arrive by their own rules,
not via subscription. The backend turns that
into its cheapest exact filter — a seccomp filter, a patch set, a
hypercall mask. Subscribing to everything when you only need `openat`
is the single most common self-inflicted slowdown; the
[Performance](performance.md) chapter quantifies it. Subscriptions are
also a *correctness* surface: an event you did not subscribe to is an
event whose behaviour you did not specify, and backends are entitled
to let it run natively.

Note what a subscription is *not*: a mechanism choice. A tool declares
*events*, never *mechanisms* — today the embedding binary hard-wires
the backend, and the proposed `ToolRequirements` value (window,
instruction classes, lifecycle, placement; strictest by default —
*proposed, pending owner approval of the architecture contract; no
such type exists in code yet*) is how a tool will state what it needs
without naming a backend. See
[Mechanisms](mechanisms.md#selection-requirements-probes-refusals).

## Errors

Most handlers return `Result<_, Error>` (or `Errno` where the guest
must see a specific errno); a few return `()` and cannot fail
(`handle_timer_event` is one — design timer work accordingly).
Distinguish three intents that novices merge:

* **Guest-visible failure** — you *want* the syscall to fail: return
  the errno as the syscall result. The guest continues, chastened.
* **Tool failure** — your handler itself cannot proceed: return
  `Error`. The run fails; the guest does not continue under a broken
  tool.
* **Backend refusal** — the backend cannot host this tool/program
  combination at all: surfaced before or at launch, by name. Never
  discovered mid-run as silent misbehaviour.

> 🚧 **Under construction — handler cookbook.** TODO: one short,
> runnable recipe per handler beyond syscalls (signal rewriting,
> post-exec re-arming, timer-driven sampling, CPUID spoofing), each
> naming the backends that support it today. <!-- UC: api-cookbook -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`api-cookbook`).
>
> 🚧 **Under construction — Guest capability matrix.** TODO: tabulate
> which `Guest` operations each backend implements vs refuses, sourced
> from the conformance suite rather than from reading four
> implementations by hand. <!-- UC: api-guest-matrix -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`api-guest-matrix`).
