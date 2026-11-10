# Performance

Interception is never free; the question is what you pay, per what,
and whether you chose to. This chapter separates mechanism costs
(physics) from tool costs (your code) and marks what is measured vs
aspiration.

## Where the time goes

Per intercepted event, roughly, from cheapest to dearest mechanism:
an in-place patched site detouring to an in-guest handler; a kernel
trap handled in-guest (`SIGSYS`, ~µs scale); a ptrace stop with the
tool in the tracer (~tens of µs). Literature anchors: ~41 ns for a
statically rewritten call, ~1.2 µs SUD, ~1.3 µs `int3`, ~31 µs ptrace.
A syscall-heavy guest under ptrace therefore slows in proportion to
its intercepted-syscall rate — the workload, not the tool, sets the
bill until your handler adds its own.

On top of mechanism cost, three tool-side costs dominate in practice:

1. **Subscription breadth.** Trapping syscalls you ignore is pure
   overhead. Implement `subscriptions` narrowly — this is the primary
   performance knob the current implementation gives you.
2. **RPC frequency.** One `send_rpc` per event (counter1 style)
   serializes on global state; fold locally and reduce rarely
   (counter2 style) unless the next event needs the global answer.
3. **Handler work.** Guest-memory reads, formatting, and allocation
   in the hot handler dwarf mechanism costs fast. The typed-syscall
   pretty printer is for humans; hot paths should record compactly
   and format later (the `recorder` example's shape).

## Measured here

The repository carries a non-CI **counter2 shootout**
(`benchmarks/counter2-shootout/`): native-normalized overhead across
the available backends on calibrated multi-second workloads. It
correctness-probes the known-green workload intersection *before*
timing anything — steal that ordering for your own benchmarks. A
same-SHA, 200-cell corpus comparison (in `BACKENDS.md`) found
e9patch ≈2.49× faster than SaBRe on the 140 mutually-clean cells by
wall time; treat single-run, concurrent-cell numbers like that as
orientation, not latency truth.

> 🚧 **Under construction — the bake-off table.** TODO: same-machine,
> same-workload overhead for each backend (plus e9patch, lazypoline,
> and a DynamoRIO null client) on syscall-dense, branch-dense, and
> JIT workloads, from the benchmarks lane, replacing the cited
> anchors above with measured ones. Until it lands, this guide makes
> no "fastest" claim for any backend. <!-- UC: perf-bakeoff -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`perf-bakeoff`).
>
> 🚧 **Under construction — precise preemption.** TODO: document the
> mini-JIT/translation path for dense counting and skid-free
> preemption when it exists as a Reverie-selectable mechanism;
> prototype numbers live in design docs, not in this guide's voice.
> <!-- UC: perf-preemption -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`perf-preemption`).
