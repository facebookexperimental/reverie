# The safety contract and refusals

Reverie runs arbitrary tools against arbitrary guests. The contract
that keeps that honest has three clauses, and this chapter states them
as obligations on *us* (the framework), not as advice to you.

## 1. Same semantics, or a named refusal

A tool's observable behaviour must not depend on which backend ran it.
Where a backend cannot provide the semantics — a lifecycle case, a
`Guest` operation, a binary shape — it refuses, by name, preferably
before the guest starts. Silent approximation (a statistic that reads
zero, an event quietly unobserved, a handler skipped) is a contract
violation, and the conformance suite exists to catch it
([Testing](testing.md)).

## 2. Fail closed at every boundary

* **Trapping:** a syscall no hook covered still reaches the
  dispatcher or fails; it never executes unobserved by accident.
  Unsubscribed syscalls execute only because the tool's subscription
  *declared* them unobserved.
* **Patching:** an unpatchable site becomes a trap or a refusal
  (`EOPNOTSUPP`), never a best-effort patch and never arbitrary Rust
  in signal context.
* **Activation:** a mode with an unmonitored window (preload) must be
  *chosen* with the window declared; selection never downgrades
  silently ([Mechanisms](mechanisms.md)).
* **Statistics:** unsupported measurements are absent, not zero.

## 3. The guest is not trusted; neither is the tool

Guest pointers are claims, validated at use; guest code is data until
a mechanism admits it. Symmetrically, the framework treats tool
handlers as fallible: handler errors fail the run rather than letting
a guest continue under a broken tool, and in-guest runtimes confine
their own syscalls to audited gate ranges so a tool bug cannot become
an unobserved kernel interaction.

## Lifecycle: where contracts go to be tested

Threads (`clone`), signals (including who owns `SIGTRAP`/`SIGSEGV`
against guest handlers), `fork`, `exec` and successor images, `vfork`,
and mapping churn (`dlopen`, JIT code) are where per-backend semantics
diverge first. The current honest state, in brief: the ptrace backend
covers the full lifecycle; in-guest paths cover documented subsets
and refuse outside them (guest-installed callable signal handlers are
the canonical example); KVM's personality is narrower still. Any claim
stronger than the per-backend tables in the repository's
`BACKENDS.md` should be treated as a guide bug.

## The refusal names (`R-*`)

Every refusal is a typed value surfaced *before* the guest runs (or, for
mid-run discoveries, at the fault with the guest stopped). "Unsupported"
without a name is a bug. The taxonomy (architecture §3.4, pending owner
approval as user-visible API):

| Name | Meaning |
|---|---|
| `R-ARCH` | Not Linux x86-64 / kernel floor unmet |
| `R-PTRACE` | ptrace required but denied, or guest already traced |
| `R-WINDOW` | Only windowed activation (A2) available; tool requires zero window |
| `R-CODE` | Code cannot be censused/gated for the mechanism (JIT, interior entries, unpatchable site with no fallback) |
| `R-SIGNAL` | Required signal ownership unavailable (SIGTRAP/SIGSYS/SIGSEGV conflict) |
| `R-WX` | Mapping policy forbids the arena/gate shape (strict W^X) |
| `R-INSTR` | Required nondeterministic-instruction class cannot be mediated in any admitted cell |
| `R-EXEC` | Successor image cannot be re-armed (includes today's pre-stage-1b in-guest gap) |
| `R-LIFECYCLE` | Required thread/fork/signal behaviour unproven in admitted cells |
| `R-DENSE` | Tool requires dense instrumentation; no B6 cell built yet |
| `R-UNBUILT` | Only valid-but-unbuilt cells satisfy (A3/A4/A5/B6 today) |
| `R-ENV-UNKNOWN` | A load-bearing environment probe could not be performed |

Refusals carry their filter trace — which cells each stage removed and
why — so "why won't it run?" is answered by the log, not by reading
source. Invalid combinations have names too (I1–I8 in architecture
§2.3): preload can never serve a zero-window tool (I1); patching alone
cannot cover arbitrary/JIT code (I2); no combination's *correctness*
may require SUD, CPUID faulting, or `PR_SET_TSC` (I6); and so on.

> 🚧 **Under construction — refusal taxonomy (pending owner approval
> of L0).** The `R-*` names above are the architecture's proposal
> ([§3.4](https://github.com/rrnewton/dev-hermit/blob/main/ai_docs/2026-11-04-liteinst-reverie-architecture.md),
> owner decision B in
> [§6.3](https://github.com/rrnewton/dev-hermit/blob/main/ai_docs/2026-11-04-liteinst-reverie-architecture.md#63-decisions-requested-from-the-owner-via-coord7)).
> TODO: on approval, expand to the full catalogue (every public
> refusal, trigger, remedy) as a Bevy-style errors index; today the
> code surfaces a subset of these ideas under older names
> (`ENOSYS`/`EOPNOTSUPP`/`NotProvided`). <!-- UC: safety-taxonomy -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`safety-taxonomy`).
>
> 🚧 **Under construction — lifecycle matrix.** TODO: the
> thread/signal/fork/exec/mapping-churn × backend coverage matrix,
> generated from conformance results so it cannot drift from what
> actually passes. <!-- UC: safety-lifecycle -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`safety-lifecycle`).
