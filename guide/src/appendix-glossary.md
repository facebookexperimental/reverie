# Appendix B: glossary

**Activation** — how the tool runtime first gains control (ptrace-stop
loader, preload, custom loader, attach). Distinct from the
interception mechanism used afterwards.

**Axes (A/B/D)** — the toolkit choices: activation (A1–A5),
interception mechanism (B1 seccomp trap, B2 SUD, B3 patching, B4 page
gates, B5 offline rewriting, B6 translation, B7 ptrace), tool
placement (D: in-guest / out-of-process). A **cell** (combination,
V1–V11 valid, I1–I8 invalid) is one pick per axis.

**Backend** — a complete, tool-generic implementation of guest
supervision + interception (`reverie::Backend`). Not a bare mechanism.

**Guest** — the instrumented process tree; inside handlers, the
`Guest` handle to the live task.

**Handler** — a tool callback for one event stream
(`handle_syscall_event`, …).

**Hooking** — deliberate per-site detours (patches, rewrites,
translation). Fast and specific.

**Injection** — performing a syscall on the guest's behalf from a
handler: this one (`tail_inject`), another one, or none (fabricated
result = elision).

**Preload (tool DSO)** — a shared library that compiles a tool in and
hosts it inside the guest for in-guest backends.

**Provider** — the syscall-execution layer under a backend's
injection (`LinuxProvider`): the host kernel (ptrace, in-guest) or an
emulated personality (KVM).

**Probes (P1–P10)** — the selector's pure environment observations
(ptrace usable, existing tracer, seccomp, SUD, CPUID faulting, TSC,
W^X policy, signal ownership, census feasibility, arch floor).
Unknown counts as absent.

**Refusal (`R-*`)** — a named declination to run a tool/program/cell
combination (`R-WINDOW`, `R-CODE`, `R-EXEC`, …), carrying its filter
trace. Fail-closed behaviour, not an error to hide.

**Requirements (`ToolRequirements`)** — (proposed) how a tool states
what it needs — window, instruction classes, lifecycle, placement —
without naming a mechanism. Strictest by default; relaxation is
explicit.

**RPC / GlobalRPC** — the typed channel from handlers to the global
singleton; local call or real IPC depending on the backend.

**Subscription** — the tool's declaration of which events it wants
trapped. Unsubscribed = deliberately native.

**Tool** — your policy: `Tool` (per-process) + `GlobalTool`
(per-tree) implementations.

**Trapping** — the completeness backstop that catches unhooked events
and fails closed (`SIGSYS`, ptrace stops, hypercalls).

**Unmonitored window** — guest execution before the runtime is armed
(e.g. `ld.so` under preload activation). Must be declared, never
silent.
