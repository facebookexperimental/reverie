---
name: reverie-architecture
description: "Map of the Reverie process-instrumentation framework — the Tool/GlobalTool/Guest/Backend contracts, the crate layout, and how a tool observes and rewrites a guest's syscalls across the ptrace, KVM, and DBT backends. Read this first when working anywhere in reverie."
---

# Reverie Architecture

Reverie is a Linux **process-instrumentation framework**. You write a *tool*
against a small, backend-agnostic contract; a *backend* runs a guest process
tree and routes the guest's syscalls, signals, and CPU events to your tool. The
same tool binary can, in principle, run over any backend (ptrace today; KVM and
DBT are in progress). Hermit's `Detcore` is the flagship tool: it hosts the
determinism engine on top of Reverie.

The four contracts all live in the shared **`reverie`** crate:

| Contract | File | Role |
| --- | --- | --- |
| `Tool` | `reverie/src/tool.rs:118` | Per-process instrumentation logic + event handlers |
| `GlobalTool` | `reverie/src/tool.rs:39` | One cross-process singleton; RPC target for shared state |
| `Guest` | `reverie/src/guest.rs:29` | A handler's view of the guest thread it is servicing |
| `Backend` | `reverie/src/backend.rs:147` | Drives a guest tree and dispatches events to a `Tool` |

## The `Tool` contract (what you implement)

A `Tool` is the **process-level** instrumentation state; one instance exists per
guest process, and it is a factory for **thread-level** state. Associated types
(`reverie/src/tool.rs`):

- `type GlobalState: GlobalTool` — the cross-process singleton (use `()` for none).
- `type ThreadState: Serialize + DeserializeOwned + Default + Send + Sync` —
  per-thread state; must serialize because backends may move it across address
  spaces.

Key methods (all handlers are `async` and receive `&mut impl Guest<Self>`):

- `fn new(pid, cfg) -> Self` (`:146`) — construct per-process state.
- `fn subscriptions(cfg) -> Subscription` (`:153`) — **declare which syscalls /
  events you want trapped**. Everything not subscribed runs untrapped (this is
  the ptrace fast path). See `reverie/src/subscription.rs`.
- `fn init_thread_state(...)` (`:183`) — seed a new thread's state.
- `async fn handle_thread_start` (`:207`), `handle_post_exec` (`:218`).
- `async fn handle_syscall_event` (`:234`) — **the main hook**: called for each
  subscribed syscall; decide to observe, modify, replace, or inject.
- `async fn handle_cpuid_event` (`:250`), `handle_rdtsc_event` (`:267`),
  `handle_signal_event` (`:280`), `handle_timer_event` (`:289`).
- `async fn on_exit_thread` (`:295`), `on_exit_process` (`:311`) — destructors
  that can flush thread/process results into `GlobalState` via `GlobalRPC`.

## The `GlobalTool` contract (cross-process shared state)

`GlobalTool` (`reverie/src/tool.rs:39`) is a **singleton** shared by every
process in the guest tree. It exposes `type Request/Response/Config` and
`async fn receive_rpc(&self, from: Tid, message) -> Response` (`:62`), plus
`init_global_state(cfg)` (`:51`). Tools reach it through the `GlobalRPC` trait
(`:334`): `async fn send_rpc(message) -> Response` (`:337`) and
`fn config()` (`:340`). `Guest` is itself a `GlobalRPC`, so a handler calls
`guest.send_rpc(...)` to talk to the global.

For **ptrace**, the global lives in-process (one address space supervises the
tree). For **out-of-process backends (DBT, KVM)** the global runs in a separate
coordinator process reached over the **`reverie-rpc-transport`** crate (Unix
domain sockets + bincode). `counter1` (in-process RPC) and `counter2`
(UDS coordinator aggregating a fork/exec tree) are the reference examples.

## The `Guest` contract (what a handler is handed)

`Guest<T: Tool>` (`reverie/src/guest.rs:29`) is the handler's live view of the
thread it is servicing. It is `GlobalRPC`, and exposes:

- **Identity:** `tid` (`:37`), `pid` (`:40`), `ppid` (`:45`),
  `is_main_thread`/`is_root_process`/`is_root_thread` (`:49`/`:55`/`:62`),
  `auxv` (`:67`).
- **Memory & regs:** `type Memory: MemoryAccess`, `memory()` (`:73`),
  `async regs()` (`:82`), `async set_regs()` (`:98`), `type Stack`,
  `async stack()` (`:104`).
- **Thread state:** `thread_state()` / `thread_state_mut()` (`:79`/`:76`).
- **Syscall control:** `async inject<S: SyscallInfo>(syscall) -> Result<i64>`
  (`:131`) runs a syscall and returns to the handler; `async tail_inject(syscall)
  -> Never` (`:175`) replaces the guest's syscall and does **not** return to the
  handler (it resumes the guest); `inject_with_retry` (`:184`).
- **Timers/clock:** `set_timer` / `set_timer_precise` (`:215`/`:223`),
  `read_clock()` (`:228`) — the RCB (retired-conditional-branch) logical clock.
- **Misc:** `daemonize` (`:108`), `backtrace` (`:266`),
  `has_cpuid_interception` (`:277`).

> **Footgun:** `tail_inject(exit/exit_group)` is **non-returning**. A tool that
> must record something at exit has to do it **before** the `tail_inject`, not
> after (see the KVM tools' Exit-before-tail_inject rule).

## The `Backend` contract (what runs the guest)

`Backend` (`reverie/src/backend.rs:147`, `#[async_trait(?Send)]`) has one entry:

```rust
async fn run<T>(command: Command,
                config: <T::GlobalState as GlobalTool>::Config)
    -> Result<(ExitStatus, T::GlobalState), Error>
where T: Tool + 'static;
```

`run` performs the whole lifecycle: init global state from `config`, compute
`T::subscriptions`, spawn/supervise the guest tree, route every subscribed event
to `T`'s handlers, run the exit destructors, and return the root `ExitStatus`
plus the final `GlobalState`. The returned future is deliberately **not `Send`**
— the ptrace backend is single-threaded per guest (all ptrace ops on one
thread), so drive `run` on a current-thread `LocalSet` executor.

## Backends (how the guest is driven & syscalls trapped)

| Backend | Crate | Interception mechanism | Status |
| --- | --- | --- | --- |
| **ptrace** | `reverie-ptrace` | ptrace stops + a seccomp-BPF filter that traps only subscribed syscalls (unsubscribed run at native speed) | production |
| **DBT** | `reverie-dbt` | DynamoRIO dynamic binary instrumentation; tool compiled into a client `.so`, run via `drrun`; intercepts *every* syscall | in progress |
| **KVM** | `reverie-kvm` | runs the guest in a KVM VM; syscalls surface as hypercalls | in progress |
| **e9patch / liteinst** | `reverie-e9patch`, `reverie-liteinst`, `reverie-preload` | in-process rewriting (static e9patch / dynamic liteinst) + a shared `LD_PRELOAD` + seccomp/SIGSYS runtime; **hybrid** — ptrace stays the lifecycle/`Guest` controller while rewritten sites originate the events | experimental |

Backend trade-off (see the benchmark memory): ptrace is bimodal — free for
unsubscribed syscalls, ~26–40 µs per *observed* syscall (the ptrace-stop tax);
DBT has a flat ~2 µs interception floor for *every* syscall, so it wins ~10× for
observation-heavy tools (strace, Detcore) and loses for sparse-subscription
tools. See the `syscall-interception` skill for the per-backend detail and the
`adding-a-backend` skill for how to wire a new one.

## Crate map

Contracts & core:
- **`reverie`** — the `Tool`/`GlobalTool`/`Guest`/`Backend` contracts, plus
  `subscription`, `timer`, `regs`, `stack`, `backtrace`, `auxv`, `rdtsc`.
- **`reverie-syscalls`** — typed syscall representation (decode/typed args,
  guest memory read/write helpers). See the `syscall-interception` skill.
- **`reverie-memory`** — guest memory access primitives.
- **`reverie-process`** — process/command spawning + lifecycle.
- **`reverie-util`** — shared utilities.
- **`safeptrace`** — safe ptrace wrappers used by the ptrace backend.

Backends:
- **`reverie-ptrace`** — production ptrace/seccomp backend.
- **`reverie-kvm`**, **`reverie-dbt`**, **`reverie-e9patch`**,
  **`reverie-liteinst`** — alternative backends (see table).
- **`reverie-preload`** — shared LD_PRELOAD + seccomp/SIGSYS runtime for the
  ld-preload backends (e9patch, liteinst).
- **`reverie-rpc-transport`** — cross-process `GlobalTool` RPC (UDS + bincode)
  for the non-ptrace backends.

Examples & tests:
- **`reverie-examples`** — the reference tools (see the `testing-tools` skill):
  `noop`, `strace`/`strace_minimal`, `counter1`/`counter2`, `chunky_print`,
  `chrome_trace`, `chaos`, `debug`, plus KVM (`reverie-kvm-counter1/2`) and
  liteinst variants. Every tool shares a `--runner ptrace|kvm` selector, so the
  same `Tool` binary runs over either backend.

Experimental (`experimental/`, autocargo-generated manifests):
- **`reverie-sabre`** (+ `-macros`, `-strace`) — a SaBRe selective-binary-rewriting
  in-process backend prototype.
- **`reverie-rpc`** (+ `-macros`) — the earlier RPC framework that
  `reverie-rpc-transport` supersedes; still used by the sabre/riptrace stack.
- **`reverie-host`**, **`riptrace`**, **`nostd-print`** — host-side support and an
  experimental strace-like application built on the above.
  Treat these as prototypes, not the supported framework.

## Build & test (quick)

Nightly toolchain (`rust-toolchain.toml`). Canonical gate is `./validate.sh`;
during iteration prefer package-scoped commands. Full commands and the
host-dependent `--skip` list are in the `testing-tools` skill.

## Post-facto human-review criteria

Apply `post-facto-human-review` exactly when a PR contains at least one of
these four triggers:

1. new syscall support, after verifying `AUTONOMOUS-BOT-IMPLEMENTED` at the
   new dispatch/classification entry and `TODO-HUMAN-REVIEW(PR-id)` at the
   implementation or determinization block;
2. a Reverie API/core-abstraction change to the `Tool`, `Guest`, `Backend`,
   or syscall-interception model;
3. a new determinization strategy; or
4. a core DetCore scheduling change affecting how programs are scheduled,
   especially race search. Trigger 4 is always labeled.

Routine backend parity toward the golden ptrace reference implementation is not
a trigger merely because it changes a non-ptrace backend. It is labeled only if
it also meets one of the four triggers.

Every PR description starts with `Plain Language Summary and Project Impact`,
stating the substantive outcome and its connection to the product vision or
owner request. It also requires mandatory `Determinism` (why the
change is deterministic plus its logic or informal proof), and `Validation`.
KVM PRs also require `Relationship to gVisor`. A labeled PR additionally
requires `Human Review Required`, naming the specific numbered trigger rather
than vague prose such as "backend change". The syscall tags above verify trigger
1; they are not blanket backend-change markers. Hermit
[PR #1151](https://github.com/rrnewton/hermit/pull/1151), which moved slowdown
into virtual-time/epoch scheduling, is the canonical good example for trigger 4.

## Related skills

- `syscall-interception` — subscriptions, `handle_syscall_event`,
  inject vs. tail_inject, typed syscalls, per-backend mechanics.
- `adding-a-backend` — implement `Backend::run<T>` + `Guest`, wire RPC transport.
- `testing-tools` — build/test commands, `validate.sh`, example-tool test scripts.
- `repo-cleanliness` — what may enter `reverie/`; pre-commit gate.
