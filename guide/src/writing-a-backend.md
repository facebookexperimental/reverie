# Writing a backend

This chapter is for the smallest audience of the book: people adding a
*backend*, not a tool. A backend is not a tool, and not a bare
mechanism (a VM, a sandbox, a rewriter). It is a complete
implementation of process supervision and event interception that
hosts an **arbitrary** `T: Tool`.

## The ten duties

Given a command and the tool's static configuration, your backend must:

1. **Initialize global state** — call `GlobalTool::init_global_state`
   once for the tree; keep the singleton reachable for RPC for the
   run's lifetime.
2. **Compute subscriptions** — call `Tool::subscriptions` once; trap
   exactly those streams.
3. **Spawn and supervise the guest** — the root process and its whole
   tree across `fork`/`clone`/`vfork`/`execve`, including stdio.
4. **Allocate state** — `Tool::new` per process,
   `init_thread_state` per thread, at the documented points.
5. **Route every subscribed event** — drive the handlers, each with a
   `Guest` handle for inspection, mutation, injection, and RPC.
6. **Run destructors** — `on_exit_thread` / `on_exit_process` as the
   tree winds down.
7. **Return `(ExitStatus, GlobalState)`** — the root's status and the
   now-uniquely-owned final state.
8. **Report real statistics** — a typed snapshot from an actual
   collector; unsupported measurements are absent, never zero.
9. **Capture output on request** — guest stdout/stderr bytes alongside
   status, state, and stats.
10. **Describe itself** — `fn capabilities()` returns your backend's
    static `BackendCapabilities`. It has *no default implementation*
    (deliberately: inheriting another backend's answer would silently
    misinform the tool), and `type Stats: BackendStatsSnapshot` is
    likewise required. A backend built to duties 1–9 alone does not
    compile — this duty is part of the trait, not garnish.

The `reverie::Backend` trait captures duties 1–10 as `run`,
`run_with_stats`, `run_with_output`, `capabilities()`, and
`type Stats`. A real backend also exposes a
richer native builder (ptrace's `TracerBuilder`/`Tracer` adds a GDB
server, function guests, and lifecycle/stdio control) — but the trait
surface is the peer contract, and it is not optional garnish.

## The three design questions, again

Decide explicitly, and document in your backend's page:

* **Hooking** — your fast path, and its site-discovery story.
* **Trapping** — your completeness backstop and its fail-closed
  default. If you cannot name it, you do not have one.
* **RPC** — local, UDS transport, or your own — with its ordering and
  failure semantics.

Then state your **refusals**: binary shapes, lifecycle cases, signal
policies, `Guest` operations you do not implement. A backend whose
boundaries are discovered by its users has failed its main job.

## Proving it

Run the example tools (`noop`, counters, `strace`, `chaos`, …) on the
shared corpus through your backend and diff against ptrace. The
conformance harness is your entrance exam; passing cells you invented
yourself is not. Expect the failures to be lifecycle-shaped first —
that is normal, and narrowing your documented envelope to what passes
is the honest intermediate state.

> 🚧 **Under construction — backend skeleton.** TODO: a minimal,
> compiling skeleton backend (single-threaded, syscall-only, local
> RPC) that passes `noop` and `counter1`, as the chapter's project.
> <!-- UC: backend-skeleton -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`backend-skeleton`).
