# Reverie backend architecture

> New to Reverie? Read the [README](README.md) first for the *tool*, *guest*,
> *backend*, and *subscription* vocabulary this document builds on. This guide is
> the backend author's and reviewer's reference for how each backend hooks,
> traps, and routes a guest's events; it assumes those terms are already
> familiar.

Reverie separates a tool's policy from the mechanism that observes a guest.
`Tool` owns process-local and thread-local state, `GlobalTool` owns the singleton
state shared by the guest tree, `Guest<T>` exposes the live task, and
`GlobalRPC<G>` is the typed channel between a task and the singleton. The
`Backend` contract ties those pieces together by running an arbitrary `T: Tool`
from launch through exit. Its event selection is a `Subscription`, not a
backend-specific syscall list
([`Backend`][backend-trait], [`Tool` and `GlobalTool`][tool-traits],
[`Guest`][guest-trait], [`GlobalRPC`][global-rpc],
[`Subscription`][subscription]).

This guide keeps three independent questions separate:

1. **Hooking:** what makes an event leave normal guest execution and reach a
   handler?
2. **Trapping:** what catches a syscall that was not hooked, and does that path
   fail closed?
3. **RPC:** where does global tool state live, and how does a handler reach it?

Calling all three "interception" hides important differences. A rewriter can
have fast hooks but incomplete trapping; two backends can share an RPC protocol
without sharing a hook; and a ptracer can own lifecycle without being the
source of every syscall event.

## Contract status

`PtraceBackend`, `E9patchBackend`, and `LiteinstBackend` currently implement the
generic `Backend` trait
([ptrace implementation][ptrace-backend], [e9patch implementation][e9-backend],
[LiteInst implementation][lite-backend]). `KvmBackend`, the DBI runtime, and
the SaBRe adapter expose real `Tool`/`Guest` execution paths, but do not yet
implement that common launch contract
([KVM runner][kvm-runner], [DBI guest][dbi-guest],
[SaBRe adapter][sabre-adapter]). This is an API-status distinction, not a claim
that the latter paths are simulations.

## Mechanism matrix

| Path | Hooking | Trapping and missed sites | Tool and global-state placement |
| --- | --- | --- | --- |
| **ptrace** | No guest code patch. A subscription-derived seccomp filter returns `TRACE` for selected syscalls, producing ptrace stops ([filter][ptrace-filter], [dispatch][ptrace-dispatch]). | Ptrace owns the subscribed boundary. Unsubscribed syscalls are deliberately allowed, while injected syscalls use a private allowed gate ([filter][ptrace-filter]). | Process/thread tool state and the singleton are in the tracer. `GlobalRPC` becomes a local call tagged with the tracee TID ([RPC implementation][ptrace-rpc]). |
| **KVM** | No host-ELF patching. The prototype guest syscall trampoline emits hypercall 12 with a syscall frame; a KVM exit drives `Tool::handle_syscall_event` for subscribed calls ([transport ABI][kvm-transport], [dispatch loop][kvm-dispatch]). | The static-ELF personality defines the guest syscall ABI, so the hypercall is the boundary rather than a coverage backstop. This is currently a specialized static-ELF runner, not a general Linux guest kernel ([static-ELF runner][kvm-static]). | `KvmGuest` holds real per-thread `T::ThreadState`; children get their own tool/thread state while sharing one `Arc<GlobalState>`. RPC calls `receive_rpc` directly with the issuing TID ([state setup][kvm-static], [KVM RPC][kvm-rpc]). |
| **DBI / DBT** | No persistent ELF patch. DynamoRIO builds translated basic blocks, registers syscall callbacks, and replaces CPUID/RDTSC in its code cache ([event registration][dbi-events], [syscall callback][dbi-syscall], [instruction rewrites][dbi-instructions]). | DynamoRIO's translated execution and pre-syscall callback form the interception boundary. This is not the shared seccomp/SIGSYS completeness trap used by preload backends ([event registration][dbi-events]). | Tool code runs in the DynamoRIO client. Coordinated launches use one `RpcServer`; the guest uses a blocking, wire-compatible client and reconnects after fork. Without a coordinator, DBI falls back to an in-process singleton ([DBI coordinator][dbi-coordinator], [DBI RPC selection][dbi-rpc], [DBI wire client][dbi-wire]). |
| **SaBRe** | SaBRe rewrites mapped executable `.text` at load time. It byte-scans for candidates, decodes candidate functions, relocates safe neighboring instructions into nearby scratch space, and installs a five-byte jump to the plugin handler ([range scan][sabre-scan], [jump trampoline][sabre-jump]). It also supports named-function and vDSO detours through the plugin API ([plugin API][sabre-api]). | If a known site cannot fit a jump, SaBRe writes a reserved instruction and handles the resulting `SIGILL` ([UD fallback][sabre-ud], [SIGILL handler][sabre-sigill]). The current Reverie host launch path itself installs no independent seccomp completeness filter; the loader only installs that SIGILL handler ([host launch][sabre-host], [loader setup][sabre-loader]). Therefore an entirely missed syscall site is not proved fail-closed by the current integration. | The plugin runs the tool in guest context. The remote adapter keeps per-thread state and one protected blocking RPC client per thread; a coordinator serves the shared singleton ([remote state][sabre-remote-state], [child state][sabre-child-state], [coordinator][sabre-coordinator]). Local adapter modes also exist, so SaBRe RPC is a mode choice rather than part of the rewriter itself ([adapter modes][sabre-adapter]). |
| **e9patch, generic `Backend`** | `e9tool` rewrites every recovered syscall in the root ELF ahead of time. Preparation rejects partial coverage and signal-based B0 sites ([rewrite invocation][e9-rewrite]). The replacement frame emits a validated `SIGTRAP` to the ptracer ([hybrid setup][e9-hybrid]). | The ptracer remains attached for loader/shared-library syscalls, lifecycle, signals, timers, and full `Guest` semantics. Thus real e9patch sites still pay a ptrace stop, and residual sites remain ptrace-controlled ([hybrid contract][e9-hybrid]). | The arbitrary tool remains ptrace-hosted, so state and RPC follow the ptrace model ([generic run][e9-generic-run]). |
| **e9patch, direct opt-in** | The same AOT frame calls the shared dispatcher directly in ordinary guest context ([AOT bridge][e9-aot]). | The shared preload seccomp/SIGSYS runtime traps residual post-constructor syscalls and enforces its documented fail-closed guards. Its stated boundary excludes static/`AT_SECURE` guests, early loader calls, and exec ([preload boundary][preload-lib], [trap flow][preload-trap]). | A tool-specific preload hosts `T`; a UDS `RpcServer` owns the singleton and the guest uses the preload coordinator client ([direct launch][e9-direct], [e9 RPC][e9-rpc]). Direct lifecycle coverage is currently single-process and single-thread, so this path does not replace the generic backend yet ([direct boundary][e9-direct-boundary]). |
| **LiteInst, direct `Backend`** (a.k.a. "Mode A": in-guest, no per-syscall ptrace round-trip) | The first execution of a syscall site reaches seccomp/SIGSYS. The dispatcher installs a replace-first LiteInst hook, then changes the saved signal-context RIP to its trampoline. The first and subsequent calls therefore enter the same normal-context tool callback ([dispatcher][lite-dispatch], [patch install][lite-patch]). | The shared trap catches first use and residual sites. An unpatchable generic-tool site fails with `EOPNOTSUPP` instead of running arbitrary Rust in signal context ([LiteInst fallback][lite-fallback], [shared trap][preload-trap]). | A tool DSO hosts process/thread state. `CoordinatorRpc` sends typed requests to the launcher's shared `RpcServer` ([tool host][lite-tool-host], [LiteInst RPC][lite-rpc], [launcher][lite-launcher]). The current generic backend supports one process and one thread ([LiteInst boundaries][lite-readme]). |
| **LiteInst, ptrace-owned hybrid** (a.k.a. "Mode B": ptrace tracer owns the tool; every installed hook returns through the ptrace-host SIGTRAP path) | On a first seccomp stop, ptrace skips the original call, rewrites the tracee RIP/stack to call the in-guest installer, validates the resulting hook footprint, and later accepts injected hot-site traps ([site install][lite-ptrace-site], [helper call][lite-ptrace-helper], [hot-site trap][lite-ptrace-trap]). | If installation cannot produce a validated hook, ptrace remains the slow path. This mode fails closed on fork/thread expansion today ([hybrid API][lite-hybrid-api], [hybrid provenance][lite-hybrid-provenance]). | Ptrace owns the sole tool and singleton; the preload contributes patch installation and the injected event frame ([hybrid API][lite-hybrid-api]). |

## Shared components

### [COMPONENT:RPC]

The common interface is `GlobalRPC<G>` over `GlobalTool::{Request, Response,
Config}`. The contract intentionally permits IPC in one backend and a local
method call in another ([global tool contract][tool-traits],
[RPC interface][global-rpc]).

Existing implementations are:

- **Local:** ptrace and KVM call the singleton directly; DBI also has this as a
  non-coordinated fallback ([ptrace][ptrace-rpc], [KVM][kvm-rpc],
  [DBI][dbi-rpc]).
- **Shared UDS transport:** `reverie-rpc-transport` provides async and blocking
  clients plus a multi-connection `RpcServer` around one `Arc<G>`. Frames are a
  big-endian `u32` length followed by bincode-legacy payload bytes
  ([server][rpc-server], [codec][rpc-codec]). SaBRe uses `BlockingRpcClient`;
  DBI implements the same wire contract for its injected client
  ([SaBRe][sabre-remote-state], [DBI][dbi-wire]).
- **Preload trusted-gate client:** e9patch and LiteInst wrap the shared preload
  `CoordinatorClient`, which reserves a descriptor and performs synchronous
  request/response RPC ([preload client][preload-rpc], [e9patch wrapper][e9-rpc],
  [LiteInst wrapper][lite-rpc]).

The `shmem_exec_obj` experiment is a possible fourth implementation, not a
current backend component. Trusted processes map the same state and executable
method table, transmute a validated entry, and call it with the shared-state
pointer, avoiding request serialization and a server round trip
([experiment overview][shmem-overview], [mapped method calls][shmem-call]). It
would still have to implement `GlobalRPC` semantics, process-tree mapping,
synchronization, ABI/version validation, and failure handling before replacing
the UDS transport.

### [COMPONENT:PTRACER]

`reverie-ptrace` is the one ptracer implementation. Its reusable surface is
`TracerBuilder<T>`/`Tracer<T::GlobalState>`, with `PtraceBackend` as the thin
generic adapter ([ptrace backend][ptrace-backend]). It currently appears in
three distinct roles:

- the reference backend, where seccomp stops run the tool in the ptracer
  ([dispatch][ptrace-dispatch]);
- e9patch's generic lifecycle and event host, where every rewritten root-ELF
  event still becomes a validated ptrace `SIGTRAP` ([e9patch][e9-hybrid]); and
- LiteInst's optional hybrid owner, where ptrace temporarily runs the patch
  helper inside the stopped guest and retains the unpatchable slow path
  ([LiteInst helper][lite-ptrace-helper]).

Consequently, "ptrace as a last resort" is accurate only for the LiteInst
hybrid's successfully patched sites. It is not accurate for the reference
backend or e9patch's generic `Backend`, where ptrace is the normal event host.

### [COMPONENT:TRAPPING]

`reverie-preload` is the shared trapping implementation for the e9patch direct
path and LiteInst. Backends implement `SyscallDispatcher`; the common runtime
owns the seccomp filter, SIGSYS handler, trusted syscall gate, event-origin
tagging, and fail-closed default result ([dispatcher interface][preload-dispatch],
[trap implementation][preload-trap], [missing dispatcher][preload-missing]).

This component does not include ptrace's `SECCOMP_RET_TRACE`, KVM exits,
DynamoRIO callbacks, or SaBRe's SIGILL fallback. Those mechanisms have
different execution contexts and lifecycle owners. SaBRe could eventually
reuse the dispatcher policy interface, but adopting the preload signal runtime
unchanged would conflict with SaBRe's own loader, recursion/TLS routing, and
SIGILL handling ([SaBRe router][sabre-sigill], [preload signal contract][preload-dispatch]).

## e9patch and SaBRe: sharing and performance

The two paths share no backend-private source today. They meet at Reverie's
`Tool`/`Guest` contracts and, in coordinated mode, at
`reverie-rpc-transport`. e9patch additionally shares `reverie-preload` with
LiteInst and `reverie-ptrace` with the reference backend; SaBRe instead owns a
separate loader ABI, callback runtime, thread registry, signal machinery,
memory adapter, and `SabreGuest`
([e9patch dependencies][e9-manifest], [SaBRe dependencies][sabre-manifest],
[SaBRe guest][sabre-guest]).

Their divergence is larger than scan-ahead selection:

- e9patch rewrites an artifact before launch and validates complete recovered
  coverage; SaBRe mutates mapped binaries, libraries, vDSO, and named functions
  in the loader ([e9patch][e9-rewrite], [SaBRe][sabre-loader]).
- e9patch's generic tool runs in ptrace; SaBRe's tool runs in the guest plugin
  ([e9patch][e9-hybrid], [SaBRe][sabre-adapter]).
- e9patch direct mode uses the shared seccomp/SIGSYS completeness trap; SaBRe
  uses per-site jump or UD/SIGILL rewriting and currently has no independent
  integration-level completeness trap ([e9patch][preload-trap],
  [SaBRe][sabre-ud]).
- e9patch direct mode is single-process/single-thread; SaBRe already maintains
  child and per-thread adapter/RPC state, although its overall compatibility is
  still experimental ([e9patch][e9-direct-boundary],
  [SaBRe][sabre-child-state]).

The same-SHA full-corpus run provides a broad wall-time comparison. Of 200
cells, 140 were L2-clean and ptrace-parity-clean in both scorecards. Across
exactly those cells, the geometric means of `duration_ms` are **251.170 ms for
e9patch** and **626.069 ms for SaBRe**: e9patch/SaBRe is **0.4012**, or e9patch
is **2.493x faster**. E9patch is faster in 131 of the 140 cells; SaBRe is faster
in nine, mostly longer thread/process-heavy guests
([harness][perf-harness], [e9patch rows][perf-e9], [SaBRe rows][perf-sabre]).
The aggregate ratio is `exp(mean(ln(e9patch_ms / sabre_ms)))` over that exact
intersection.

These are real release-binary `--strict --verify` runs with the same Hermit and
Reverie SHAs, flags, corpus, and ptrace output reference. Each cell has one
timed verify observation and the harness ran cells concurrently, so the ratio
is a wide-corpus result, not a low-noise latency benchmark
([measurement method][perf-harness]).

**Recommendation:** keep e9patch's AOT preparation and do not replace it with a
SaBRe-style loader or an LD_PRELOAD-only design for performance. Current broad
evidence already favors e9patch. Share typed RPC, fork/connection lifecycle,
and a normal-context tool-host abstraction where their contracts truly match;
do not merge the rewriters, completeness traps, or lifecycle controllers.
Moving the generic e9patch path away from ptrace remains worthwhile only after
the existing direct path reaches equivalent lifecycle and `Guest` coverage,
not as a prerequisite for sharing code ([direct boundary][e9-direct-boundary]).

[backend-trait]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie/src/backend.rs#L135-L165
[tool-traits]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie/src/tool.rs#L112-L225
[guest-trait]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie/src/guest.rs#L55-L85
[global-rpc]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie/src/tool.rs#L430-L440
[subscription]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie/src/subscription.rs#L21-L56
[ptrace-backend]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/backend.rs#L20-L64
[ptrace-filter]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/tracer.rs#L1698-L1759
[ptrace-dispatch]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/task.rs#L3681-L3727
[ptrace-rpc]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/task.rs#L5446-L5470
[kvm-runner]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-kvm/src/runtime.rs#L987-L1008
[kvm-transport]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-kvm/src/vm.rs#L63-L70
[kvm-dispatch]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-kvm/src/runtime.rs#L1051-L1105
[kvm-static]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-kvm/src/runtime.rs#L1140-L1197
[kvm-rpc]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-kvm/src/runtime.rs#L323-L418
[dbi-guest]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-dbi/src/lib.rs#L200-L275
[dbi-events]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-dbi/native/client.c#L2475-L2499
[dbi-syscall]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-dbi/native/client.c#L2010-L2044
[dbi-instructions]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-dbi/native/client.c#L525-L624
[dbi-coordinator]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-dbi/src/launcher.rs#L394-L424
[dbi-rpc]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-dbi/src/lib.rs#L210-L263
[dbi-wire]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-dbi/src/sync_rpc.rs#L9-L32
[sabre-adapter]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/experimental/reverie-sabre/src/reverie_adapter.rs#L80-L169
[sabre-scan]: https://github.com/rrnewton/SaBRe/blob/df1839a129d93b69f47a819a3769c8cbb0b4ec60/arch/x86_64/rewriter.c#L921-L976
[sabre-jump]: https://github.com/rrnewton/SaBRe/blob/df1839a129d93b69f47a819a3769c8cbb0b4ec60/arch/x86_64/rewriter.c#L177-L213
[sabre-ud]: https://github.com/rrnewton/SaBRe/blob/df1839a129d93b69f47a819a3769c8cbb0b4ec60/arch/x86_64/rewriter.c#L252-L273
[sabre-sigill]: https://github.com/rrnewton/SaBRe/blob/df1839a129d93b69f47a819a3769c8cbb0b4ec60/loader/loader.c#L124-L178
[sabre-api]: https://github.com/rrnewton/SaBRe/blob/df1839a129d93b69f47a819a3769c8cbb0b4ec60/plugins/sbr-trace/sbr_api.h#L23-L65
[sabre-loader]: https://github.com/rrnewton/SaBRe/blob/df1839a129d93b69f47a819a3769c8cbb0b4ec60/loader/rewriter.c#L830-L860
[sabre-host]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/experimental/reverie-host/src/tracer.rs#L68-L112
[sabre-remote-state]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/experimental/reverie-sabre/src/reverie_adapter.rs#L340-L365
[sabre-child-state]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/experimental/reverie-sabre/src/reverie_adapter.rs#L1048-L1067
[sabre-coordinator]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/experimental/reverie-sabre-strace/src/lib.rs#L179-L203
[sabre-guest]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/experimental/reverie-sabre/src/reverie_adapter.rs#L1071-L1105
[e9-backend]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/backend.rs#L988-L1005
[e9-rewrite]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/rewrite.rs#L197-L297
[e9-hybrid]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/backend.rs#L375-L412
[e9-generic-run]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/backend.rs#L988-L1005
[e9-aot]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/aot.rs#L162-L195
[e9-direct]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/backend.rs#L810-L931
[e9-direct-boundary]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/backend.rs#L405-L458
[e9-rpc]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/src/rpc.rs#L69-L115
[e9-manifest]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-e9patch/Cargo.toml#L24-L42
[lite-backend]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/backend.rs#L463-L477
[lite-dispatch]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/runtime.rs#L1591-L1650
[lite-patch]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/runtime.rs#L992-L1127
[lite-fallback]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/runtime.rs#L1653-L1665
[lite-tool-host]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/tool_host.rs#L105-L160
[lite-rpc]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/rpc.rs#L67-L114
[lite-launcher]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/backend.rs#L550-L595
[lite-readme]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/README.md#L86-L109
[lite-hybrid-api]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-liteinst/src/backend.rs#L191-L229
[lite-hybrid-provenance]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/tracer.rs#L1868-L1893
[lite-ptrace-site]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/task.rs#L3538-L3578
[lite-ptrace-helper]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/task.rs#L3328-L3507
[lite-ptrace-trap]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-ptrace/src/task.rs#L2330-L2378
[preload-lib]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-preload/src/lib.rs#L9-L43
[preload-dispatch]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-preload/src/dispatch.rs#L9-L30
[preload-trap]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-preload/src/trap.rs#L9-L20
[preload-missing]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-preload/src/trap.rs#L122-L160
[preload-rpc]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-preload/src/rpc.rs#L9-L44
[rpc-server]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-rpc-transport/src/server.rs#L37-L64
[rpc-codec]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/reverie-rpc-transport/src/codec.rs#L9-L31
[sabre-manifest]: https://github.com/rrnewton/reverie/blob/2f812840b718a6ac2a772a56cd05490765465ebf/experimental/reverie-sabre/Cargo.toml#L1-L30
[shmem-overview]: https://github.com/rrnewton/dev-hermit/blob/60be39270bd85fb4a38d31062da2f4073e9effe1/shmem_exec_obj/README.md#L1-L17
[shmem-call]: https://github.com/rrnewton/dev-hermit/blob/60be39270bd85fb4a38d31062da2f4073e9effe1/shmem_exec_obj/v1/pod-loader/src/lib.rs#L203-L237
[perf-harness]: https://github.com/rrnewton/dev-hermit/blob/1490bbbf740d3d7bfb7f3c2703f5ecfa1de1c6df/experiments/ptrace_fullcorpus_scorecard_20260801/sweep-backend.sh#L1-L88
[perf-e9]: https://github.com/rrnewton/dev-hermit/blob/1490bbbf740d3d7bfb7f3c2703f5ecfa1de1c6df/experiments/ptrace_fullcorpus_scorecard_20260801/scorecard-e9patch.csv
[perf-sabre]: https://github.com/rrnewton/dev-hermit/blob/1490bbbf740d3d7bfb7f3c2703f5ecfa1de1c6df/experiments/ptrace_fullcorpus_scorecard_20260801/scorecard-sabre.csv
