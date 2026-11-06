# Introduction

Welcome to *The Reverie Guide*, a book about building tools that sit
between a Linux program and its kernel. Reverie is a userspace
system-call interception framework: it lets you intercept, modify, or
elide a syscall before the kernel executes it. You write a **tool** —
a set of callbacks — and Reverie runs a whole **guest** process tree
under it, on the **backend** of your choice.

Tools people build this way include observability tools like `strace`,
failure injectors that test error-handling logic, and schedulers that
expose concurrency bugs. Reverie's largest known tool is Hermit's
determinism engine, but Hermit is a *consumer* of this framework: this
book is about Reverie itself, and every example in it runs without
Hermit.

> **Under-construction regions in this guide: 23.** This guide was
> started early, on purpose: writing it is how we check that our
> concepts are clear and that the layers fit together. Every
> unfinished or unimplemented part is marked with an *Under
> construction* box carrying a TODO. The count above is the number of
> those boxes; project work includes driving it to zero. If this
> guide claims something the code does not do, that is a bug — in the
> guide or in the code.

## The layer model

| Layer | Role | Guide |
|---|---|---|
| **liteinst** | Building blocks: in-place patching, page gates, offline rewriting, decode facts. No process or syscall policy. | The LiteInst guide |
| **Reverie** | Complete solutions: the `Tool` API, backends (ptrace, in-guest, KVM, …), loaders, the guest runtime, conformance tests. | This book |
| **Hermit** | One Reverie tool: deterministic execution. | Hermit's own docs |

Each layer must make sense on its own. In particular, a Reverie
*loader* loads an arbitrary Reverie tool — not one specific tool — and
this book treats any place where that is not yet true as unfinished
work, marked as such.

## The four words this book uses constantly

* A **tool** decides *what* to do when the guest hits a trappable
  event (a syscall, a signal, a timer, …). Tools are stateful and are
  written against the `Tool` and `GlobalTool` traits. This is what
  most readers will write.
* A **guest** is the instrumented process tree. Inside a handler, the
  `Guest` handle is how a tool inspects and mutates the live task and
  talks to global state.
* A **backend** decides *how* events are trapped and how the tool is
  run against a live guest: spawning and supervising the tree,
  intercepting events, hosting global state, tearing down. Backends
  are swappable: the same tool must run unchanged on any backend, or
  be refused by name.
* A **subscription** is the tool's declaration of which syscalls (and,
  on x86-64, which of CPUID/RDTSC) to trap. Backends trap exactly what
  was subscribed — no more (you pay for what you trap), no less
  (silence is not a semantics).

## How to read this book

Read front to back the first time. [Your first tool](first-tool.md)
builds a working syscall counter early and previews the whole API;
concept chapters then take each piece apart; project-flavoured
sections grow the counter into a distributed, multi-process tool.
Project chapters contain commands you can run against
`reverie-examples`; concept chapters point at the example that
exercises the idea (and say so under construction where the runnable
listing does not exist yet).

Boxes you will meet: **Under construction** (unfinished guide or
feature, with its TODO), **Refusal** (a backend declines by name
rather than approximating — a feature), and **Listing** (numbered code
from a real file in this repository).


## Platform and status, up front

* **Linux x86-64** has full support. **Linux aarch64** exists but
  lacks timers and CPUID/RDTSC interception. Other platforms are
  unplanned.
* `reverie-ptrace` is the reference backend. The in-guest LiteInst
  backend also implements the generic `Backend` contract, within
  documented boundaries. KVM exposes a specialized runner rather than
  the generic contract. [Backends](backends.md) states each one's
  status precisely; this book never upgrades a specialized path into a
  general claim.
* The workspace pins an exact stable toolchain for development; the
  published libraries build on stable Rust.
