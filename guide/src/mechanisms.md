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

The selector exists: `reverie::selection`, fed by
`reverie::probes`. A tool still declares *events* with
`subscriptions()`, but admission is a separate, explicit question —
can *this* tool, in *this* environment, on *this* guest, be served
without weakening what it asked for? The pieces:

* `ToolRequirements` — returned by `Tool::requirements()`: window
  tolerance, nondeterministic-instruction classes, lifecycle needs,
  placement, debugger coexistence, and instrumentation density
  (`dense` = every-branch, B6-only). **Defaults are the strictest
  reading**: a tool that says nothing gets reference semantics or a
  refusal, never a preload window it did not declare. Relaxation is
  explicit, and `is_relaxation_of` makes "weaker" machine-checkable:
  relaxing never removes eligible cells. Requirements are guest
  behaviour, not event interests — declining `execve` notifications
  does not prove the guest cannot exec, so subscriptions never relax
  lifecycle requirements.
* **Probes P1–P10** — `probe_environment()` fills an
  `EnvironmentSnapshot` of `Knowledge` facts (`Proved` / `Disproved` /
  `Unknown`) before any guest instruction. Trials that must try
  something run in throwaway children of the host, never in a process
  anyone will instrument, so their answers are *advisory* for the
  actual guest. `Unknown` never stands in for a value: unknown tracer
  ownership is not "no tracer", and a cell whose predicate depends on
  an unknown fact is not admitted (`R-ENV-UNKNOWN`).
* `admit()` — pure admission over the *implemented* cells: filter by
  requirements and proven environment facts, then rank the eligible
  remainder. It returns an `AdmissionReport` (the chosen cell plus a
  retained `ExecutionPlan`) or a typed `AdmissionRefusal` carrying
  the full filter trace; `select_cell()` is the convenience wrapper.
  A **design cell** is an obligation; only an *implemented* cell —
  registered with its tested envelope — is selectable, and a
  backend-wide capability constant alone never certifies a
  composition. Today four cells are registered: `V1-ptrace`,
  `V4-preload-trap`, `V5-preload-patch`, and `V11-kvm`. An explicit
  selection is honoured exactly or refused by name. Automatic ranking
  is a cost-class *heuristic* over eligible cells only
  (patch < gate+patch < trap < ptrace < translation), tie-broken
  toward stronger guarantees — a shape, not a benchmark.
* **Handoff is terminal.** The retained plan re-validates the actual
  guest's facts at the backend's controlled stop
  (`validate_handoff`); a failure there ends the launch — the host
  must not retry another backend under a weaker reading. The older
  admission hooks (`facility_admission`, the `install_*` hooks) stay
  authoritative on the same path.

### Guarantees per cell

From architecture §2.2 (approved 2026-11-05 with amendments): **C** =
nondeterministic-instruction coverage, **Thr** = new threads from
their first instruction, **Sig** = signal fidelity, **Fork** =
children followed, **Exec** = successors re-armed window-free,
**Dyn** = new/JIT code. `✓` = reference-grade, `D` = weaker but
declared, `R` = refuses by name. These are the contracts a valid
cell must meet; conformance is how each gets proven.

| Combo | C | Thr | Sig | Fork | Exec | Dyn |
|---|---|---|---|---|---|---|
| V1 ptrace ref | CPUID+RDTSC ✓ | ✓ | reference, holes included | ✓ | ✓ | trap any code |
| V2 A-stop+trap | as V1; wider needs B3/B4 | ✓ | must match V1 verdicts | ✓ | R, then ✓ | trap covers (slow) |
| V3 A-stop+patch | selected; rest trap or R | ✓ | as V2 + SIGTRAP ownership | ✓ | as V2 | gate (→V6) or R |
| V4/V5 preload | D before init | D/R before init | as V2/V3 after init | as V2/V3 | D/R | as V2/V3 |
| V6 page-gate | scan on first fetch | ✓ per-mapping | chain/refuse by name | re-arm before resume | re-gate | certified code; JIT R |
| V7 offline | as scanned | ✓ | runtime-owned | ✓ if runtime in child | R unless rewritten | R/V6 |
| V8/V9 no-ptrace | as chosen B | ✓ | runtime-owned | runtime-owned | runtime-owned | as chosen B |
| V10 translation | total in principle | ✓ | runtime-owned | runtime-owned | retranslate | ✓ by construction |
| V11 KVM | VM-controlled | ✓ | emulated | emulated | emulated | emulated |

Exec is the gating row: until successor re-arming lands, the in-guest
cells refuse `execve` (`R-EXEC`) — honest, shippable, and the reason
execing programs sit outside the early conformance corpus. The
oracle for every cell is Linux semantics plus the `Tool` contract,
not bit-compatibility with ptrace: V1's named signal defects are its
own ledger entries, not behaviour other cells must reproduce.

The refusal names are catalogued in [Safety](safety.md).
>
> 🚧 **Under construction — SUD and page-fault modes.** TODO: document
> B2 (SUD first-use acceleration *inside* B1/B3 cells — never a
> correctness requirement, rule I6) and B4 (LiteInst page gates as a
> selectable Reverie mode) when those lanes land; today the shipped
> in-guest interception is B1 + B3 only. <!-- UC: mech-sud-gates -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`mech-sud-gates`).
