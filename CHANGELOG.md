# Reverie

## 0.4.1

- Support stable Rust in the public crate graph and fix libunwind/LZMA linking
  on Ubuntu.
- Provide an explicit ptracer-thread interface for older-kernel operation,
  used by Hermit's ptrace path and qualified on Ubuntu 24.04's stock Linux 6.8.
  The generic Safeptrace interface for sibling-thread waits requires
  `PIDFD_THREAD` support from Linux 6.9 or newer and fails clearly below it.
  Linux 5.15 remains a design target, with no qualification claim yet. See the
  [compatibility follow-up](https://github.com/rrnewton/reverie/issues/943).
- Select Native production waits only from an original retained thread pidfd,
  avoiding the strict explicit interface's repeated target checks on that
  path. Linux 6.8 keeps the strict explicit interface. Managed Native waits
  retain the original controller and unfinished capabilities across callback
  refusals and cancellation; Native memory access keeps its existing generic
  semantics. This does not close the existing numeric ptrace exec/reuse
  limitation in [the lifetime issue](https://github.com/rrnewton/reverie/issues/860).
- Eight SDK controls require physical performance counters. Their `EACCES`
  prerequisite failures in a stock VM are expected and do not block this
  release; they do not establish precise-preemption support.
- The unchanged exec/callback regression intermittently misses its
  three-second raw `ESRCH` deadline (three failures in five stock Linux 6.8
  runs). This is a test gating bug; no plain ptrace failure has been
  demonstrated. See
  [the callback issue](https://github.com/rrnewton/reverie/issues/951).
- Nested KVM qualification is deferred; see
  [the nested KVM issue](https://github.com/rrnewton/reverie/issues/940).

## 0.1.0 (December 1, 2021)

 - Initial release
