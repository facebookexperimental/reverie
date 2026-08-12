---
name: adding-a-backend
description: "How to add a new Reverie execution backend — implementing Backend::run<T>, providing a Guest<T> view (regs, memory, inject/tail_inject), wiring GlobalState over reverie-rpc-transport for out-of-process backends, and enumerating serviced syscalls. Read when building or extending a backend (ptrace/KVM/DBT/e9patch)."
---

# Adding a Backend

A backend is what actually *runs* the guest and delivers its events to a `Tool`.
Tools are backend-agnostic (see `reverie-architecture`); a backend's job is to
satisfy two contracts — `Backend` and `Guest` — so any existing tool runs over
it unchanged. Study `reverie-ptrace` (production, complete) as the reference and
`reverie-kvm` / `reverie-dbt` (in progress) for the out-of-process pattern.

Concrete entry points to read: `PtraceBackend` (a ZST) in
`reverie-ptrace/src/backend.rs`, which delegates to `TracerBuilder::<T>` +
`Tracer::wait` in `reverie-ptrace/src/tracer.rs`; `KvmBackend` in
`reverie-kvm/src/vm.rs` with `run_static_elf_with_tool::<T>` /
`run_with_tool::<T, F>`; and `DbtGuest<'a, T>` + `DbtRunner` in
`reverie-dbt/src/lib.rs`.

## 1. Implement `Backend::run<T>`

`reverie/src/backend.rs:147` (`#[async_trait(?Send)]`):

```rust
async fn run<T>(command: Command,
                config: <T::GlobalState as GlobalTool>::Config)
    -> Result<(ExitStatus, T::GlobalState), Error>
where T: Tool + 'static;
```

Your `run` owns the full lifecycle:

1. **Init global state** — `T::GlobalState::init_global_state(&config)`.
2. **Compute subscriptions** — `T::subscriptions(&config)`; install whatever
   trap mechanism realizes them (a seccomp filter, a DR client, a VM exit
   handler…). Only subscribed events must stop in the tool.
3. **Spawn & supervise** the guest process tree from `command`, following
   `fork`/`clone`/`exec` so child processes get their own `Tool` instance
   (`T::new`) and threads get `T::init_thread_state`.
4. **Route events** — on each trapped syscall/signal/cpuid/rdtsc/timer, build a
   `Guest` for the current thread and call the matching `T::handle_*`.
5. **Run destructors** — `on_exit_thread` / `on_exit_process` as threads and
   processes end.
6. **Return** the root `ExitStatus` and the final `T::GlobalState`.

**The future is `?Send` on purpose.** ptrace requires all tracee operations on
the one tracer thread, so the backend runs on a current-thread executor
(`tokio::task::LocalSet` / `LocalSet::run_until`). A new backend should assume
the same single-threaded driving model unless it genuinely needs otherwise.

## 2. Provide a `Guest<T>` view

`reverie/src/guest.rs:29` — the per-thread handle passed to every handler. A
backend supplies a concrete `Guest` implementation backed by its transport:

- `type Memory: MemoryAccess` + `memory()` — read/write **guest** address space
  (ptrace: `process_vm_readv`/writev; KVM: guest-physical translation; DBT:
  in-process reads). Handlers dereference pointer args through this.
- `async regs()` / `async set_regs()` — the trapped thread's registers.
- `type Stack` + `async stack()` — guest stack access.
- Identity: `tid/pid/ppid`, `is_root_process/thread`, `is_main_thread`, `auxv`.
- **Syscall control:** `inject` (run & return the result to the handler) and
  `tail_inject` (run & resume the guest, `-> Never`). These are the heart of a
  backend: you must be able to execute an arbitrary syscall on the guest's
  behalf and, for `inject`, capture its return.
- `set_timer[_precise]` + `read_clock` — back these with your clock source (the
  RCB/PMU logical clock in ptrace); if unsupported, be explicit rather than
  silently wrong.
- `daemonize`, `backtrace`, `has_cpuid_interception` — implement or return a
  principled "unsupported".

## 3. Out-of-process `GlobalState` (KVM, DBT)

With ptrace the supervisor shares one address space, so `GlobalState` lives
in-process. **KVM and DBT run guest code in a separate address space**, so the
`GlobalTool` singleton runs in a **coordinator process** and handlers reach it
over **`reverie-rpc-transport`** (Unix domain socket + bincode):

- Keep `GlobalTool::Request`/`Response` and `Tool::ThreadState`
  bincode-serializable; RPC crosses a process boundary.
- Make RPCs coarse — each `send_rpc` is a UDS round-trip.
- `counter2` (a fork/exec tree aggregating counts into a UDS coordinator) is the
  worked example; `reverie#98`/`#99` document the transport and a fork()
  aggregation proof.

## 4. Enumerate serviced syscalls (executor completeness)

The ptrace backend lets unsubscribed syscalls run natively, so it "supports"
everything by default. An **executing** backend (KVM, DBT) must *itself* perform
each syscall it injects, so it needs an explicit dispatch arm per syscall.
Un-enumerated syscalls fall through to a default — typically `ENOSYS` — which
surfaces as a guest failure. Extending such a backend means:

1. Add the syscall to the backend's executor/dispatch (e.g. the KVM
   `executor.rs` if/else chain, or the DBT client dispatch).
2. Add the classification entry if the tool gates on it.
3. Mark bot-authored entries with `// AUTONOMOUS-BOT-IMPLEMENTED` and
   `// TODO-HUMAN-REVIEW(PR-id)` per this repo's Autonomous Bot Audit Tags rule.
4. Add a regression at the narrowest useful layer.

This incremental "ratchet" (add one syscall family, prove it, repeat) is the
established way the KVM and DBT backends grow coverage.

## 5. Backend-specific footguns (from prior work)

- **KVM:** syscalls surface as `VcpuExit::Hypercall` with
  `nr == VMCALL_SYSCALL_TRANSPORT` (`= 12`); the loop reads a `SyscallRequest`
  from guest memory and writes the result back. The hypercall transport
  truncates the return register to 32 bits; `tail_inject(exit/exit_group)` is
  non-returning, so record any Exit **before** the tail_inject. The KVM executor
  ENOSYSes every un-enumerated syscall and had no socket support until added
  incrementally. Needs `/dev/kvm` with `Cap::ExitHypercall`; x86_64 only.
- **DBT (DynamoRIO):** a handler returns its decision as
  `DbtSyscallOutcome::{Suppress(i64), ExecuteOriginal(Syscall)}`; native FFI
  callbacks (`DbtRuntimeCallbacks`) bridge DR ↔ Rust and the async handler future
  is polled on the guest thread. The tool is *compiled into* the client `.so`
  (no runtime tool selection); it must be **release-built** (debug frames
  overflow the DR stack); a Rust `panic!` in a DBT handler `SIGABRT`s (no
  unwind). Tools run only in the traced-tree root; copied children bypass the
  Rust path. `set_regs` maps to `dr_set_mcontext` (returns `EIO` on failure).
- **All out-of-process backends:** correctness must not depend on a shared
  writable cache; keep per-process state serializable.

## 6. Validate

A new/extended backend is floored at **L0** on its own (Reverie suite green). A
determinism claim (L1+) requires an **integrated Hermit run** at the stated
level with the backend named — a Reverie-side change never establishes L1 by
itself (see the Assurance Levels table in `AGENTS.md`). Run the example tools
(`noop`, `counter1/2`, `strace`) over the new backend as smoke tests; see the
`testing-tools` skill for commands and the `reverie-dbt/scripts/` harness.

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

- `reverie-architecture` — the contracts and crate map.
- `syscall-interception` — the handler side (subscriptions, inject, memory).
- `testing-tools` — building and running example tools over a backend.
