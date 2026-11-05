# Interception mechanisms: hooking, trapping, RPC

Calling everything "interception" hides the differences that decide
whether a tool is sound. Reverie's architecture separates three
questions; every backend answers each one explicitly.

## 1. Hooking: the fast path you chose

A *hook* is a deliberate detour at a known site: a patched `syscall`
instruction (LiteInst), a rewritten call frame (e9patch), a translated
block (DynamoRIO), a hypercall (KVM). Hooks are fast because they are
specific — and incomplete for the same reason. A hook catches the
sites it was installed on, full stop.

## 2. Trapping: the completeness backstop

A *trap* catches what no hook covered, and its default must fail
closed. The shared in-guest runtime (`reverie-inguest`) is Reverie's
completeness trap for the patching backends: a seccomp filter turns
syscalls into `SIGSYS` — with named exceptions (`rt_sigreturn` must
run, the runtime's own trusted gate sites must not re-trap, and vDSO
fast paths plus the ~40 loader/startup syscalls before the
constructor are outside coverage; the filter documents its boundary
in `reverie-inguest/src/seccomp.rs`) — a common handler owns the
trusted gate and event-origin tagging, and a site with no hook
(`NotPatched`) runs through the dispatcher's *fallback continuation*
in normal context. Only when the backend refuses the site, or no
continuation is available, does the trap fail with `EOPNOTSUPP`
rather than running arbitrary Rust in signal context. Ptrace's completeness boundary is its
subscription-derived seccomp `TRACE` filter: unsubscribed syscalls are
*deliberately* allowed, which is sound only because the subscription
is the tool's own declaration.

The question to ask of any backend is not "is it fast?" but "show me
the trap." A rewriter with fast hooks and no fail-closed trap has a
hole shaped like every site it missed. (One external path is
documented exactly this way in `BACKENDS.md`: load-time rewriting
whose current integration proves no independent completeness trap.
The guide repeats that assessment rather than smoothing it over.)

## 3. RPC: where global state lives

The third axis is independent of the first two. Implementations today:

* **Local call** — ptrace and KVM invoke the singleton directly,
  tagged with the issuing TID.
* **Shared UDS transport** — `reverie-rpc-transport`: length-prefixed
  bincode frames to a multi-connection `RpcServer` holding one
  `Arc<G>`.
* **Preload trusted-gate client** — the in-guest backends' synchronous
  coordinator client over a reserved descriptor.

Two backends can share an RPC protocol while sharing no hook
machinery, and vice versa. When you port a tool, RPC placement is
usually the invisible difference: latency per `send_rpc`, ordering
across processes, and what "global" costs at 10⁶ syscalls/second.

## The mechanism menu: axes A–E

Reverie's goal is a DynamoRIO-class toolkit with *swappable*
mechanisms under one `Tool` semantics. The architecture names the
choices as axes, and a **combination (cell)** is one pick per axis:

* **A — activation / first-instruction control** (Chapter: [Activation
  and loaders](loaders.md)): **A1** ptrace exec-stop + loader,
  **A2** `LD_PRELOAD` late activation (declared window), **A3** custom
  no-ptrace loader, **A4** attach to a running process (absent today),
  **A5** coexist with an external ptrace debugger (A3 + in-guest).
* **B — interception mechanism:** **B1** seccomp `RET_TRAP`/`SIGSYS`,
  **B2** Syscall User Dispatch (SUD), **B3** in-place patching
  (LiteInst), **B4** page-fault gating, **B5** ahead-of-time/offline
  rewriting, **B6** out-of-place translation (mini-JIT → DBT),
  **B7** ptrace syscall stops.
* **C — nondeterministic-instruction control:** CPUID, RDTSC, and the
  wider class (RDRAND/RDSEED/XGETBV…), mediated via B3/B4/B5/B6 or
  kernel faulting where available. Exhaustive mediation is claimed by
  no shipped path today.
* **D — tool placement:** in the guest, or out of process.
* **E — lifecycle coverage:** threads (`clone`), signals (including
  SIGTRAP/SIGSEGV ownership), `fork`, `exec` successors, `vfork`, and
  mapping churn (`dlopen`, JIT). Not a menu pick so much as the axis
  along which cells differ most — and refuse most often.

Two truths about today's tree, stated before any menu: the production
in-guest path has exactly **two selectable modes** — `Liteinst` (B3
site patching on) and `InGuestTrap` (B1 only, patching off) — and
**B2 (SUD) is absent from Reverie and the LiteInst Rust library** (it
exists only in LiteInst's standalone C launchers, which no backend
consumes). **B4 is likewise not yet selectable through Reverie**; the
gates are standalone LiteInst crates awaiting their binding. The full
valid/invalid cell matrix (V1–V11, I1–I8) with per-cell guarantees is
specified in the architecture document (§2); this guide adopts its
names so a cell means the same thing in both places.

## Selection: requirements, probes, refusals

Today a tool declares *events*, never *mechanisms* (`subscriptions()`),
and the embedding binary hard-wires a backend — there is no selector
yet. The proposed addition (architecture §3, pending owner approval)
is deliberately small:

* `ToolRequirements` — one value next to `subscriptions()`: window
  tolerance, nondeterministic-instruction classes, lifecycle needs,
  placement, debugger coexistence, and a `dense` flag (every-branch
  instrumentation, B6-only). **Defaults are the strictest reading**:
  a tool that says nothing gets reference semantics or a refusal,
  never a preload window it did not declare. Relaxation is explicit
  and visible in source and logs.
* **Probes P1–P10** — pure host/loader observations before any guest
  instruction (ptrace usable? existing tracer? seccomp nestable? SUD?
  CPUID faulting? `PR_SET_TSC`? W^X policy? signal ownership? census
  possible? arch/kernel floor?). A probe that cannot run returns
  *Unknown*, and Unknown counts as *absent* — fail closed.
* `select()` — filter the valid cells by requirements, then by probe
  results, then by "actually built"; refuse with the most specific
  `R-*` name if empty; else take the cheapest cell, tie-broken toward
  the stronger guarantee. No silent downgrade, ever: SUD, CPUID
  faulting, and `PR_SET_TSC` may *accelerate* a cell but may never be
  load-bearing for its correctness (rule I6).

The refusal names are catalogued in [Safety](safety.md).

> 🚧 **Under construction — the selection rule (pending owner approval
> of L0).** The matrix, `ToolRequirements`, probes P1–P10, and the
> `R-*` taxonomy above are specified in the
> [architecture document, §2–§3](https://github.com/rrnewton/dev-hermit/blob/main/ai_docs/2026-11-04-liteinst-reverie-architecture.md)
> and await the owner decisions in its
> [§6.3](https://github.com/rrnewton/dev-hermit/blob/main/ai_docs/2026-11-04-liteinst-reverie-architecture.md#63-decisions-requested-from-the-owner-via-coord7)
> (items A, B, D). TODO: on approval, land the per-cell guarantee
> tables here; until then this chapter summarizes, and no selector API
> exists in code. <!-- UC: mech-selection -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`mech-selection`).
>
> 🚧 **Under construction — SUD and page-fault modes.** TODO: document
> B2 (SUD first-use acceleration *inside* B1/B3 cells — never a
> correctness requirement, rule I6) and B4 (LiteInst page gates as a
> selectable Reverie mode) when those lanes land; today the shipped
> in-guest interception is B1 + B3 only. <!-- UC: mech-sud-gates -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`mech-sud-gates`).
