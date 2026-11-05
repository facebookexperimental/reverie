# Backends

A backend is a complete implementation of process supervision and
event interception that can host an **arbitrary** `T: Tool` — the tool
type is always a generic parameter, never hard-coded. This chapter
introduces the backends a tool author chooses among. The backend
*author's* contract (what you must build to add one) is
[Writing a backend](writing-a-backend.md); the deep mechanism
comparison is the repository's `BACKENDS.md`, which this chapter
summarizes and must not contradict.

## The backends at a glance

| Backend | Mechanism | Generic `Backend`? | Tool runs… | Status |
|---|---|---|---|---|
| `reverie-ptrace` | seccomp `TRACE` filters + ptrace stops | yes — the reference | in the tracer | full lifecycle following; **signal fidelity Partial with named holes** (held-signal windows — and "same semantics" includes those holes until fixed in the reference first); slowest per event |
| `reverie-liteinst` | shared seccomp `SIGSYS` trap; first use installs a LiteInst patch at the site | yes, with boundaries | in the guest (tool DSO) | dynamically linked x86-64; documented lifecycle limits |
| in-guest-trap | LiteInst runtime with site patching off: every syscall traps | via the same runtime | in the guest | the patching backends' semantic reference |
| `reverie-kvm` (+ `-core`) | VM exits from a KVM guest | specialized runner, not the generic trait | in the host, per-thread state in `KvmGuest` | static-ELF personality, growing. **`reverie-linuxemu` is KVM-internal** — its userspace Linux emulation is a building block of this backend, not a backend or Tool-contract surface of its own, and it gets no column in the conformance matrix |
| e9patch, SaBRe, DynamoRIO | AOT rewrite, load-time rewrite, DBT | e9patch has a generic (ptrace-hosted) mode | varies | external repositories own these |

In architecture vocabulary a **cell** is one activation (A) × one
mechanism (B) × one placement (D) combination — and a single backend
can host more than one cell (`LiteinstBackend` runs both the B3
patching cell and, with patching off, the B1 in-guest-trap cell):
ptrace is A1×B7×out, `InGuestTrap` is A2×B1×in today, and so on
([Mechanisms](mechanisms.md) has the full axis list). Note also that
Reverie's LiteInst binding still pins an October LiteInst revision
(1,971 commits behind `liteinst` 0.2.0): "LiteInst can do X" and "a
Reverie tool gets X" are different claims until that port lands, and
conformance results must name the pin they ran on.

Three independent questions hide inside "which backend":

1. **Hooking** — what makes an event leave normal execution?
2. **Trapping** — what catches an event that was *not* hooked, and
   does it fail closed?
3. **RPC placement** — where does global state live, and how does a
   handler reach it?

[Interception mechanisms](mechanisms.md) takes those one at a time.
For choosing today: start on **ptrace** (the reference semantics,
every lifecycle case), keep it as your correctness oracle, and move
hot tools to in-guest execution when measurement says to.

## Boundaries are part of the API

Each backend publishes what it refuses. Examples from the current
tree: the generic LiteInst backend rejects guest-installed callable
signal handlers and clone/fork injection, within a documented
one-process/one-thread envelope for its generic path; the KVM runner
refuses what its static-ELF personality cannot express; in-guest
direct e9patch mode is single-process/single-thread. A tool that
needs more gets a named refusal at launch — that is the contract
working, not failing.

Backend statistics and captured output are also contractual:
`run_with_stats` returns a typed snapshot from the backend's real
collector (unsupported measurements are never a successful zero), and
`run_with_output` returns guest stdout/stderr bytes with the status
and final state.

> 🚧 **Under construction — per-backend pages.** TODO: one page per
> backend (wasm-bindgen reference style): mechanism, lifecycle
> coverage table, refusal list, stats fields, and the exact example
> commands — kept in sync with `BACKENDS.md` and the conformance
> scorecard. <!-- UC: backends-pages -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`backends-pages`).
>
> 🚧 **Under construction — external backends.** TODO: summarize the
> e9patch / SaBRe / DynamoRIO extension backends from their owning
> repositories at pinned revisions, or link out with a stated reason;
> `docs/BACKEND_SOURCES.md` is the ownership record.
> <!-- UC: backends-external -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`backends-external`).
