# Reverie

Versions 0.5.1 and 0.5.3 describe selected development snapshots; 0.5.0
describes the registry release. Backend-specific entries retain the limits
of those execution paths.

## 0.5.7

Release cut for the 2026-11-11 fbsource import, taken at Reverie main. It
summarizes the commits from the 0.5.6 cut (`f2129d99`) to this one, 88 of
them.

- reverie-procfs: a new crate of pure `/proc` helpers. LinuxEmu's path
  classification, single-record `seq_file` positioning, synthetic `stat` and
  `statx` metadata, and the `maps` line and `status` name formats move into
  it, with unchanged output. It also holds strict `mountinfo` and fdinfo
  `mnt_id` parsers, an fdinfo renderer, and the 36 fixed system-wide procfs
  files, rendered from a caller-supplied machine description. A purity guard
  (clippy's disallowed types and methods, and a source scan in
  `tests/purity.rs`) keeps clocks, files, the environment, randomness,
  threads, processes and the network out of the crate.
- LinuxEmu signals: `pidfd_send_signal`, which answered `ENOSYS`, makes
  Linux's checks in Linux's order; a pidfd from outside the run and
  `PIDFD_SIGNAL_PROCESS_GROUP` are refused by name, and the KVM executor
  declares the Linux 6.17 spelling of `PIDFD_SELF_THREAD` and
  `PIDFD_SELF_THREAD_GROUP`, so a Tool forwards them unchanged. A Tool that
  selects recipients can ask for signals between processes
  (`ProcessSignalControl::enable_cross_process_signals`); such a send then
  queues on the target as Linux's `do_send_sig_info` does, choosing and
  waking no thread, and without the request it stays refused. `kill` and
  `rt_sigqueueinfo` accept any live thread's id; a stop signal and
  `SIGCONT` flush each other from a process's queues; and a caller's
  siginfo of unknown layout must be readable (`EFAULT`) and end in zeros
  (`E2BIG`).
- LinuxEmu memory map: a file on overlayfs, as in podman's and docker's
  default container root, gets its `VmFlags` from a probe mapping of the
  same open file on the host kernel, and the new `MappingFact::thp_eligible`
  carries the kernel's `THPeligible` for files on overlayfs and tmpfs. A
  file `mmap` no longer reads the supervisor's whole `/proc/self/mountinfo`:
  the superblock device comes from `statmount(2)` on Linux 6.8 and later,
  and elsewhere from a table read again only after a mount event. Two KVM
  runs of a git workload in a container with 886 mounts had spent 1.81 s of
  their 6.28 s in those reads.
- In-guest runtime on aarch64: exec-stop's capture, drain and restore of a
  stopped entry context, and its `svc` child syscall bridge, build and pass
  their tests natively; the exec-private features still refuse to compile
  there. safeptrace adds aarch64 accessors for `TPIDR_EL0` and for the
  syscall number at an exec stop.
- In-guest launcher: the retention frame and confirmed retirement of a
  mapped first-image launch move from Hermit into reverie-inguest
  (`exec_stop::mapped_launch`), so other embedders can reuse them. A frame
  retains only a spawn made with its own receipt.
- Loader: a mapped successor decodes the coordinator endpoint stamped with
  its packet and refuses an absent, duplicate or empty one by name;
  `valid_mapped_input_range` checks a mapped entry's input bounds.
- LiteInst artifact: the mapped-entry producer picks its consumer (Detcore
  or literoot) once per source transaction, from a closed descriptor. A new
  Cargo git binding requires every Reverie crate at the pinned revision and
  refuses local path patches, forks, registry swaps and stale revisions.
  Detcore's selection, link arguments and refusal texts are unchanged;
  literoot images do not link yet.
- Stable Rust: the LiteInst artifact qualifier accepts what rustc 1.97.1
  builds: the native Detcore runtime, whose `INSTALLATION_DEPTH` TLS cell
  is at 0xf8 (its allocation body and FnOnce thunk), and the release
  LiteInst constructor (cell 0x30). Each new template is copied from the
  real image, and no mask is widened. `scripts/detcore-alloc-recipe.py`
  derives Detcore recipe rows from an ELF, and validation runs its
  `--self-test`.
- safeptrace: before Linux 6.9, a wait built right after a successful
  resume no longer reads `TracerPid` from `/proc/<tid>/status`, so the
  outcome after a non-leader `exec` no longer depends on host timing, and
  the observation worker's wakeup costs about two fewer context switches
  per non-leader stop.
- Build: `cargo check --workspace --all-targets` passes on aarch64, except
  for reverie-liteinst-preload, which refuses aarch64 by design. Reverie's
  BUCK files equal fbsource's copies, and the ten generic conformance tests
  move to `tests/BUCK` (`reverie//:generic-basics` is now
  `reverie//tests:basics`).
- Packaging: the `oss_cargo/` manifest copies are retired. Each crate's
  `Cargo.toml` exists once, at its crate path.
- Align every first-party package and internal requirement at 0.5.7. The
  LiteInst artifact identity checks now require 0.5.7 and still reject
  0.5.6, 0.5.5, 0.5.4, 0.5.1 and older identities. A new reviewed TLS source
  tuple records the version-only change to the two runtime manifests.

## 0.5.6

Release cut for the 2026-11-10 fbsource import, taken at Reverie main. It
summarizes the commits from the 0.5.5 cut (`78d41ebd`) to this one, about 190
of them.

- In-guest runtime: a watched exec supervisor that follows fork trees, stops
  each successor and forwards ordinary execs; static executables and malformed
  ELF files are refused before spawn; `CLONE_THREAD` behind an off-by-default
  capability; a Tool TLS registry at the control publication point; refused
  fork-like calls and signal controls are recorded for the Tool to report.
- Exec-stop producer: the new opt-in `exec-stop-producer` feature of
  reverie-inguest qualifies a mapped first image (one syscall gate, and an
  instruction audit of every executable page), leases the descriptors its
  birth inherits, and fixes its placement.
- LiteInst: mapped successor seams, lazy trap-and-patch promotion on aarch64,
  and the runtime's refusal readers re-exported for Tools. aarch64 builds
  compile, refuse patching by name, and run in their own validation lane.
- Loader: decodes the successor init packet (HLISUC01) with its state digest,
  accepts up to 64 segments, and derives its handoff size bound from the wire
  maxima.
- LinuxEmu: `pidfd_open` for another guest process, with Linux's readiness;
  pidfd epolls and descriptor rights in flight stay inside the run.
- RPC transport: a birth authority routes each stage, and a pending EOF gets a
  terminal verdict.
- ptrace: SIGSEGV trap repair on aarch64.
- Packaging: each oss_cargo manifest twin equals its crate's Cargo.toml, and
  `make check-oss-cargo-twins` keeps them equal.
- Align every first-party package and internal requirement at 0.5.6. The
  LiteInst artifact identity checks now require 0.5.6 and still reject 0.5.5,
  0.5.4, 0.5.1 and older identities. A new reviewed TLS source tuple records
  the version-only change to the two runtime manifests.

## 0.5.5

Release cut for the 2026-11-09 fbsource import, taken at Reverie
`78d41ebd`, the commit Hermit pinned; Reverie main continued past it. It
summarizes the commits from the 0.5.4 alignment to that cut, about 700 of
them.

- Split Reverie into its first-party core: ptrace, KVM, LiteInst and the
  in-guest runtime stay here; DBT, SaBRe, e9patch and their tools live in the
  satellite repositories listed in `docs/BACKEND_SOURCES.md`.
- KVM: a preemption timer with precise and imprecise timer events, signal
  delivery at timer boundaries and at every return to user mode, vfork
  children that share file views with their parent, and named, bounded
  refusals when an exec runs out of host resources.
- LinuxEmu: Linux-faithful answers for signalfd, pidfd, inotify, mincore,
  protection keys and descriptor limits, with tests pinned against the native
  host.
- In-guest runtime: aarch64 trap dispatch, signal frames and SIGSYS handling,
  and groundwork for per-thread Tool TLS.
- gdb stub: guest signals are reported as stops, and signal numbers are
  translated between gdb and Linux.
- safeptrace: register writes stay in a cache until they are needed;
  `set_syscall` writes dirty registers back first.
- Dependencies: tokio 1.54.1.
- Align every first-party package and internal requirement at 0.5.5. The
  LiteInst artifact identity checks now require 0.5.5 and still reject 0.5.4,
  0.5.1 and older identities.

## 0.5.4

- Package-version alignment for the native import
  ([a131082c](https://github.com/rrnewton/reverie/commit/a131082c93759d2666984a639e6d02813cd16e23)).
  Changes made between the 0.5.3 snapshot and this alignment have no entries
  of their own.

## 0.5.3 (Development snapshot)

- Give KVM syscall callbacks the guest's saved instruction pointer, flags and
  argument registers instead of the trampoline's overwritten state. `RAX`
  still contains the transport hypercall number; `orig_rax` names the syscall.
- Complete ordinary KVM syscall injections without a boxed completion future
  when no process action is pending. Exec and other lifecycle operations keep
  their existing completion path.
- Reuse KVM Tool scratch-mapping checks and memory handles while their
  ownership and mapping versions remain valid. Reuse PMU event encodings only
  within a validated CPU domain, preserving fallback checks elsewhere.
- Remove KVM's incomplete `/proc/self/cmdline` copy. Hermit's shared Tool
  supplies contents from guest memory; unsupported standalone paths retain
  their procfs refusals.
- Align package versions and internal dependencies at 0.5.3, extending runtime
  source-identity checks to that manifest set while retaining historical sets
  and rejection of mixed versions.

[Selected source](https://github.com/rrnewton/reverie/commit/befaebe7482ef3fa8becb242bd020ec882963205).

## 0.5.2

- No separate Reverie release. Hermit's
  [0.5.2 compatibility update](https://github.com/rrnewton/hermit/pull/4549)
  changes only `hermit-detcore` and `hermit-replay`; its Reverie dependencies
  remain at 0.5.0.

## 0.5.1 (Development snapshot)

- Add opt-in Tool hooks to announce, commit or withdraw a predicted signal
  delivery, plus predicted-death and resume-mask interfaces. These prepare
  in-guest delivery and require backend opt-in; that protocol is inactive in
  this snapshot.
- Expose separate backend capabilities for kernel signal-state ownership,
  predictable signal targets, host-task access and host-timed signals, so
  Tools can select behaviour from each backend's supported facts.
- Check held ptrace stops before resuming a tracee that may have reached its
  exit stop, and recognize `SIGKILL` at exec return as death. The stop check
  and resume remain non-atomic.
- Extend the experimental exec-stop launcher to initialize private libc, TLS
  and the installed Tool before restoring the program's first instruction.
  Unsupported startup signals and incomplete cleanup remain explicit refusals.
- Leave `SIGTRAP` to the guest on the shared LiteInst Tool path when site
  patching is disabled, and preserve ordinary coordinator sockets' descriptor
  allocation so guest `dup2` behaviour remains stable.
- Correct KVM descriptor access checks and writes through partly unreadable
  buffers. Random devices retain their real host descriptor identity;
  Hermit's Tool supplies deterministic random bytes.
- Add a guarded mapping-capture interface for cooperative DBT observations;
  unsupported runtime domains report a typed unavailable error.
- Clean up DBT namespace descendants by signalling and reaping direct children,
  including adopted descendants. Reject procfs from another PID namespace
  before using its process IDs.

[Selected source](https://github.com/rrnewton/reverie/commit/32cd7a75bd15b0c72e933b41a0ff2cc6aa2f8c14).

## 0.5.0

Ptrace remains the reference path. KVM, DBT and optional rewriting integrations
retain their development or experimental limits.

- Report and deliver realtime signals under ptrace, and deliver a guest's own
  `int3` trap instead of silently continuing past it.
- Preserve guest signal masks and `SIGTRAP` state around injected syscalls and
  single-stepping. Restore `SIGSEGV` state affected by trapped `rdtsc` and
  `cpuid` instructions.
- Let Tools read, replace and filter signal metadata, set a stopped thread's
  signal mask, and request restart-code exposure with
  `Guest::inject_restartable`. Unsupported operations report their limits.
- Make ptrace Tool writes respect guest page protections at every size. Small
  scalar writes spanning a page boundary fail without modifying a prefix.
- Improve KVM's initial stack and interpreted PIE layout, and implement
  `MAP_FIXED_NOREPLACE` and shared anonymous mappings across `fork`.
- Extend KVM descriptor support with `FIONBIO` and socket `SO_ERROR`, retaining
  explicit refusals for unsupported operations.
- Share the in-guest syscall and instruction dispatcher behind an optional
  patcher interface; unpatched sites use the common trap path and Tool.
- Align release packages at 0.5.0. Keep native third-party implementations
  source-only and publish `reverie-loader` for the in-guest launch API. The
  registry release omits native injection and an unpublished LiteInst API.

Known issue: ptrace cleanup after a nonleader replacement exec can still fail
intermittently, as documented in the
[release source](https://github.com/rrnewton/reverie/commit/ee9fbe258e39ca90983b840285f684e1bea1762c).

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
