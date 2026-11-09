# Advanced handlers

Beyond syscalls, four handler families cover most sophisticated
tools. Each is subscription-gated and each has backend-dependent
reach; this chapter says what they are for and where the edges are.

## Signals

`handle_signal_event` (with raw and structured variants, and a
dedicated dequeue hook) lets a tool observe, rewrite, delay, or
suppress signal delivery. The hard part is ownership: `SIGTRAP` and
`SIGSEGV` are load-bearing for several mechanisms (guarded patching,
page gates, breakpoints), and a guest's own handlers compete for the
same dispositions. Backends state their signal-ownership rules
explicitly; a tool that installs guest-visible handlers must be
tested against guests that install their own. The in-guest LiteInst
path currently *rejects* guest-installed callable signal handlers —
an honest boundary, and the kind this guide will never quietly drop.

## Timers

`handle_timer_event` delivers tool-scheduled timers, the basis for
sampling profilers and watchdogs. Timer *precision* is
backend-dependent in ways that matter (a ptrace stop is not a
hardware interrupt); tools that need precise preemption should read
the performance chapter's honesty box before designing around timers.

## CPUID and RDTSC

On x86-64, `handle_cpuid_event` and `handle_rdtsc_event` intercept the
instructions determinism and fingerprinting tools care about most.
Mechanisms differ — CPUID faulting, `PR_SET_TSC`, patching, trapping —
with different availability per environment, which is why these are
subscriptions with refusals attached rather than ambient features.
aarch64 lacks both today.

## Injection beyond the current syscall

Handlers may inject *additional* syscalls (open a log file in the
guest, map a scratch page) and must then reason about what the guest
observes: register clobbers, errno visibility, restart semantics.
Clone/fork-family injection is refused by some backends outright.
Keep injections minimal, restore what you borrowed, and test against
a guest that inspects its own register state — the examples' guest
fixtures are good templates.

> 🚧 **Under construction — per-family listings.** TODO: one runnable
> listing per family (signal delay, sampling timer, CPUID leaf
> spoof, scratch-map injection) with its backend support stated.
> <!-- UC: advanced-listings -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`advanced-listings`).
