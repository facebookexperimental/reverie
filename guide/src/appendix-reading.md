# Appendix C: further reading

* This repository: `README.md` (overview + the backend contract),
  `BACKENDS.md` (the mechanism matrix with source-pinned links),
  `docs/BACKEND_SOURCES.md` (external backend ownership),
  `reverie-examples/README.md`, and the counter2 shootout under
  `benchmarks/`.
* The LiteInst guide — the building-block layer beneath the in-guest
  backend.
* API reference: [docs.rs/reverie-core](https://docs.rs/reverie-core)
  and sibling crates.
* Hermit — the largest Reverie tool — for a worked example of a
  production determinism engine written against this API:
  [Hermit: Deterministic Linux for Controlled Testing](https://developers.facebook.com/blog/post/2022/11/22/hermit-deterministic-linux-testing/).

## Neighbouring systems, in this book's vocabulary

* [DynamoRIO](https://dynamorio.org/) — a mature dynamic code
  manipulation system that copies executed blocks into a code cache
  and lets clients transform or instrument them there. In the axes of
  [Mechanisms](mechanisms.md), it is **B6 (out-of-place
  translation)**: code is discovered as it executes, so unknown and
  dynamically generated code needs no advance census. Read it for the
  engineered end of that trade—fragment linking, client API layers,
  and transparency work—and for what a production code cache costs.
  No B6 cell is registered in Reverie's selector today.
* [Intel Pin](https://software.intel.com/sites/landingpage/pintool/docs/99977/Pin/doc/html/index.html)
  — a JIT-based dynamic binary instrumentation framework. Pintools
  insert C/C++ analysis routines at image, routine, trace,
  basic-block, or instruction granularity. It also sits at **B6**,
  but its enduring lesson for Reverie is the tool-facing API:
  several granularities over one execution model, with the JIT hiding
  and recreating control flow underneath. Read the user guide for API
  ergonomics rather than for a mechanism Reverie could reuse
  directly.
* [QEMU TCG](https://git.zx2c4.com/qemu/tree/docs/devel/tcg.rst) —
  QEMU's Tiny Code Generator translates guest blocks through an
  intermediate representation to host code. Mechanistically it is
  B6-like, but its purpose is architecture emulation and virtual
  devices, not delivering a native guest's events to a `Tool`
  implementation. Read TCG for a production translator's block,
  chaining, and invalidation problems; do not mistake that machinery
  for a host-process instrumentation backend.
* [gVisor systrap](https://gvisor.dev/blog/2023/04/28/systrap-release/)
  — the default gVisor platform uses `seccomp` trapping to route
  workload syscalls to the Sentry, a userspace implementation of much
  of the Linux system-call interface. Its nearest axis letter is
  **B1** for trap delivery only. There is no corresponding Reverie
  cell: systrap does not deliver each syscall to an arbitrary tool
  handler and then let the original proceed; the Sentry implements
  the semantics itself. Read it for completeness and compatibility at
  sandbox scale, and for the price of owning the syscall surface.
* [E9Patch](https://dl.acm.org/doi/abs/10.1145/3385412.3385972) —
  static x86-64 binary rewriting without control-flow recovery, using
  instruction punning, padding, and eviction to place trampoline jumps
  without moving other instructions. Its closest Reverie axis is
  **B5 (ahead-of-time/offline rewriting)**, with patch-site techniques
  shared with B3. Read it for what can be proved and patched when the
  complete file is available before execution; live threads,
  successor images, and dynamically generated code remain outside
  that static act.
* [lazypoline](https://people.cs.kuleuven.be/~stijn.volckaert/papers/2024_DSN_Lazypoline.pdf)
  — hybrid syscall interposition: Syscall User Dispatch catches a
  syscall site on first execution, the site is rewritten in zpoline
  style, and later executions use the fast rewritten path. It
  combines **B2** for discovery with **B3-style patching** for the
  steady state. Read it for the completeness problem—statically
  scanning for two-byte syscall instructions can both miss generated
  code and misidentify bytes inside data or immediates—and for a
  fast-path/trap-fallback split restricted to syscalls rather than
  arbitrary program points.
