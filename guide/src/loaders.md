# Activation and loaders

Before any mechanism can intercept, the tool's runtime must be
*present and armed* — ideally before the guest executes its first
instruction. How control is first obtained is its own axis, because
each answer leaves a different unmonitored window and a different set
of deployment requirements.

## The activation menu

| Mode | How control starts | Unmonitored window | Needs ptrace? |
|---|---|---|---|
| **A1 — ptrace stop + Reverie loader** | stop at `exec`; the loader maps and arms the tool runtime at fixed addresses; hand over to the guest's `ld.so` | zero guest instructions (the design goal) | yes, for the stop |
| **A2 — `LD_PRELOAD` late activation** | `ld.so` loads a preload DSO hosting the tool | `ld.so` itself, IFUNC resolvers, early constructors | no |
| **A3 — custom userspace loader** | `execve(loader, [loader, prog, …])`: our loader builds the image and arms the runtime itself | zero, if exec-state parity is complete | no — the no-ptrace path |
| **A4 — attach** | join an already-running process | everything before attach | typically yes |
| **A5 — coexist with a debugger** | A3 + in-guest interception, leaving ptrace to the external debugger | per A3 | must not need it |

A2 is what the in-guest examples use today (a preload that compiles
your tool in, selected by name). It is honest about its window:
acceptable exactly when missing `ld.so`-time behaviour is declared
acceptable for the tool's purpose. A1 is the design of record for
zero-window starts. A3 is the documented fallback where ptrace is
unavailable (locked-down containers, no `CAP_SYS_PTRACE`) — and its
long tail is exec-state parity: auxv, stack layout, TLS, and every
other detail a real `execve` + `ld.so` pair establishes.

## What a Reverie loader is (and is not)

A loader at this layer loads **an arbitrary Reverie tool's runtime**:
it validates and maps a runtime image, runs typed initialization
stages in order (so a step can only follow the step before it),
confines the runtime's own syscalls to declared gate ranges by audit,
arms the tool's controls, and only then releases the guest. Tool
*policy* — schedules, determinism, tracing formats — never belongs in
the loader.

The current `reverie-loader` crate contains the `unsafe`-free parts of
that design: image validation (fixed-address `ET_EXEC`, no
interpreter, no dynamic section, W^X, page-aligned segments in an
allowed window), the syscall-gate audit, artifact checks, and the
stage types. It is `no_std` so the loader itself can use it.
`reverie-inguest` integrates loader mechanics in-repo (the
`exec-stop` and `loader-private-runtime` features), and its
stage-1a probe launcher **does** consume the public typestate stage
chain (`Mapped → RuntimeStarted → ToolReady → Armed → HandedOff`),
passing init and armed-controls evidence into the transitions. Note
the remaining gap precisely: that consumer is a mechanics probe with
test runtimes, and the end-to-end production A1 integration that
exists beyond it is still Hermit-private glue — the tool-generic
*interface* has landed in the loader library and the probe lane, not
yet a shipped production A1 lane.

The tool-agnostic contract (L1 design, adopted by the architecture
§4.3) is: a tool provides a data-only **`ToolManifest`** — one
validated runtime image, declared gate ranges, a **`Controls`** set to
arm (trap filter, CPUID faulting, RDTSC trapping, vDSO rewrite,
handlers), and an **`InitContract`** (`ImageEntry`, a fixed
`Address`, or `None`) naming the entry the launcher must launch,
exactly, or refuse by name — readiness itself is the runtime image's
own signal, checked by the launcher before it claims `ToolReady` —
and the loader guarantees **G1** no guest instruction before arm
(typestate `Mapped → RuntimeStarted → ToolReady → Armed → HandedOff`,
consumed by the launcher), **G2** handoff with kernel-built exec
state untouched, **G3** exec parity through the same boundary
(`execve` refused until it lands), **G4** total refusal (never
partially armed), and **G5** isolation of tool windows. The manifest
carries nothing beyond image, gates, controls and init: there is no
tool-requirements or policy payload in it. This loader contract is
x86-64 with 4 KiB pages only; other host page sizes are refused by
name rather than assumed away.

> 🚧 **Under construction — loader generality.** Approval is no
> longer the blocker: architecture §4.3 and its decisions D1–D4 were
> resolved as PROCEED-with-amendments on 2026-11-05
> ([§6.3](https://github.com/rrnewton/dev-hermit/blob/main/ai_docs/plans/2026-11-04-liteinst-reverie-architecture.md),
> item C as amended). L1-a renamed the former consumer-named ready
> stage to `ToolReady`; L1-b landed the data-only `ToolManifest` and
> made the stage chain public and consumed by the stage-1a probe
> launcher, with init and armed-controls evidence checked in the
> transitions; L1-c added a non-Hermit counting runtime on that lane
> (`counter_inguest`), proving zero unarmed guest
> instructions/syscalls and ptrace-lane count parity on its static
> and `/bin/ls` guests. What has *not* shipped is a production
> tool-generic A1 lane: `reverie-inguest`'s exec-stop mechanics are
> a named prototype (`reverie-inguest/STAGE1A.md`) whose production
> interface deliberately exposes no resume path yet — a genuine
> tool-ready release transition is still owed before any production
> caller can proceed, and no runtime-readiness token is granted;
> the production-shaped runtime manifest still has no launcher
> consumer, and production integration remains Hermit-private glue.
> TODO: rewrite this chapter against the landed tool-agnostic loader
> once a production lane ships. Until then, treat A1 as implemented
> in the loader library and probe lane, not shipped end-to-end.
> <!-- UC: loaders-generic -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`loaders-generic`).
>
> 🚧 **Under construction — A3/A4/A5 status.** TODO: per-mode status,
> parity checklist (auxv/stack/TLS/…), and refusal list as the
> no-ptrace launch lane scopes them; A4/A5 are design rows today.
> <!-- UC: loaders-a3 -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`loaders-a3`).
