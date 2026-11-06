# State at three scales

A Reverie tool keeps state at three scales, and the separation is what
lets the same tool run on a centralized backend (everything in one
tracer process) and a distributed one (handlers inside every guest)
without being rewritten.

| Scale | Type | Lifetime | Accessed via |
|---|---|---|---|
| Thread | `Tool::ThreadState` | one guest thread | the handler's guest handle |
| Process | the `Tool` instance itself | one guest process | `&self` in handlers |
| Global | `Tool::GlobalState: GlobalTool` | the whole guest tree, once | `send_rpc` only |

Rules that follow from the table:

* **Thread state** is created by `init_thread_state` when a thread
  starts. It is the place for per-thread scratch (a partial line
  buffer, a per-thread counter) that no one else may observe
  mid-flight.
* **Process state** is your `Tool` struct: one per guest process,
  created by `Tool::new` on `fork`/`clone`. It is *not* shared with
  the parent after fork — design as if each process gets a fresh,
  identically-configured tool.
* **Global state** is a singleton behind `GlobalRPC`. Handlers never
  touch it directly; they send a `Request` and await a `Response`.
  Whether that is a local method call (ptrace, KVM) or a serialized
  round-trip over a Unix socket to a coordinator (in-guest backends)
  is the backend's business. Your request/response types must
  therefore be serializable, and `receive_rpc` must be written knowing
  it may run in a different process from every handler.

## Project: counter2, counting the distributed way

`counter1` sent one RPC per syscall — simple, and exactly wrong at
scale. `counter2` keeps the count where it happens: each thread
accumulates locally and sends **one** `ThreadReport` RPC at exit
(the global half writes that thread's count to stderr and does *not*
add it to the tree totals), each process folds its threads in, and
the process
contributes its totals to global state **once** at exit
(`ProcessExit`). No double-counting by construction. The launcher
then prints the tree totals it reads back from the returned global
state, so the report survives even a guest that closes stderr.

That is the MapReduce shape most real tools want: *map* in thread
state (cheap, uncontended), *reduce* at process and tree boundaries
(rare, explicit). Reach for per-event RPC only when the global
decision genuinely affects the very next event — a scheduler granting
a turn, a deterministic clock — and expect to pay for it (see
[Performance](performance.md)).

## Common state bugs

* **Counting in the wrong lifetime.** The trait contract is explicit:
  thread *and* process state are **unchanged across the `execve`
  boundary** (`handle_post_exec`'s documentation) — the new image
  inherits your tool state, it does not reset it. Tools that want a
  clean slate per image must reset deliberately in
  `handle_post_exec`; state that must outlive the whole tree belongs
  in global state regardless.
* **Assuming `receive_rpc` ordering across processes.** RPCs from
  different guest processes race exactly as their senders do. If order
  matters, carry sequence information in the request.
* **Leaking guest references.** Thread/process state lives exactly as
  long as its thread/process. Anything that must outlive both goes
  through RPC before the exit hooks complete.

## counter2, annotated at the fold points

The listings are `reverie-examples/counter2_tool.rs` verbatim,
split where the folds happen. Three marks to watch: **[map]** where
a thread accumulates, **[fold 1]** where a thread's count joins its
process, and **[fold 2]** where a process contributes to the tree —
exactly once each.

Listing ST-1 is the state and the whole RPC vocabulary: two
message kinds, one diagnostic and one contribution. Everything else
in the tool is plumbing between them (the output-error types after
`CounterRequest`, elided here, exist so a failed thread report is
an error the lifecycle hook returns — never a silently lost count,
and never folded into the totals as a guess).

<span class="filename">Listing ST-1: counter2_tool.rs — state and messages</span>

```rust,ignore
//! Backend-neutral implementation of the counter2 Reverie tool.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io::Write;
use std::sync::Mutex;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;


/// Global counter2 totals.
#[derive(Debug, Default)]
pub struct GlobalInner {
    pub total_syscalls: u64,
    pub exited_procs: u64,
    pub exited_threads: u64,
}

#[derive(Debug, Default)]
pub struct CounterGlobal {
    pub inner: Mutex<GlobalInner>,
}

impl CounterGlobal {
    /// Returns process-tree syscall, process, and thread totals.
    #[allow(dead_code)]
    pub fn totals(&self) -> (u64, u64, u64) {
        let state = self.inner.lock().unwrap();
        (
            state.total_syscalls,
            state.exited_procs,
            state.exited_threads,
        )
    }
}

/// Local, per-process state for counter2.
#[derive(Debug, Default)]
pub struct CounterLocal {
    proc_syscalls: AtomicU64,
    exited_threads: AtomicU64,
    thread_exit_reporter: Option<fn(Tid, u64)>,
}

impl CounterLocal {
    /// Selects where this backend writes the existing thread-exit diagnostic.
    ///
    /// Injected backends must use their runtime output path because the guest
    /// may close its own stderr before the lifecycle callback runs.
    #[allow(dead_code)]
    pub fn with_thread_exit_reporter(mut self, reporter: fn(Tid, u64)) -> Self {
        self.thread_exit_reporter = Some(reporter);
        self
    }

    /// Returns the process-local syscall and exited-thread totals.
    #[allow(dead_code)]
    pub fn process_totals(&self) -> (u64, u64) {
        (
            self.proc_syscalls.load(Ordering::SeqCst),
            self.exited_threads.load(Ordering::SeqCst),
        )
    }
}

impl Clone for CounterLocal {
    fn clone(&self) -> Self {
        CounterLocal {
            proc_syscalls: AtomicU64::new(self.proc_syscalls.load(Ordering::SeqCst)),
            exited_threads: AtomicU64::new(self.exited_threads.load(Ordering::SeqCst)),
            thread_exit_reporter: self.thread_exit_reporter,
        }
    }
}

/// Process-exit contribution to the global counter2 state.
#[derive(PartialEq, Debug, Eq, Hash, Clone, Serialize, Deserialize, Copy)]
pub struct IncrMsg(pub u64, pub u64);

/// Reports a consumed thread or contributes a completed process's totals.
#[derive(PartialEq, Debug, Eq, Clone, Serialize, Deserialize)]
pub enum CounterRequest {
    ThreadReport { tid: Tid, syscalls: u64 },
    ProcessExit(IncrMsg),
}
```

Listing ST-2 is the *reduce* side, and its asymmetry is the design:
`ThreadReport` is written to stderr and deliberately **not** added
to the totals; only `ProcessExit` folds. That single choice is what
makes double-counting impossible rather than merely unlikely.

<span class="filename">Listing ST-2: counter2_tool.rs — global half</span>

```rust,ignore
#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = CounterRequest;
    type Response = Result<(), CounterOutputError>;
    type Config = ();

    async fn init_global_state(_: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, request: Self::Request) -> Self::Response {
        match request {
            CounterRequest::ThreadReport { tid, syscalls } => {
                // The GlobalState owner completes output before acknowledging.
                // A report does not also contribute to the process-tree totals.
                write_thread_report(&mut std::io::stderr().lock(), tid, syscalls)
            }
            CounterRequest::ProcessExit(IncrMsg(n, t)) => {
                let mut state = self.inner.lock().unwrap();
                state.total_syscalls += n;
                state.exited_threads += t;
                state.exited_procs += 1;
                Ok(())
            }
        }
    }
}
```

Listing ST-3 is the process half. [map] is one increment of
*thread* state per syscall — no RPC, no atomic on the hot path
beyond the thread's own counter. [fold 1] is `on_exit_thread`:
thread total into the process atomics, plus the report. [fold 2]
is `on_exit_process`: both process totals leave in a single
message.

<span class="filename">Listing ST-3: counter2_tool.rs — process/thread half</span>

```rust,ignore
#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    type ThreadState = u64;

    fn new(pid: Pid, _cfg: &()) -> Self {
        debug!(" [counter] initialize counter for pid {}", pid);
        Self::default()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        debug!(
            "thread count at syscall ({:?}): {}, process count: {}",
            call.number(),
            guest.thread_state(),
            self.proc_syscalls.load(Ordering::SeqCst)
        );
        guest.tail_inject(call).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Tid,
        global_state: &G,
        thread_syscalls: u64,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        debug!("count at exit thread {} = {}", tid, thread_syscalls);
        self.proc_syscalls
            .fetch_add(thread_syscalls, Ordering::SeqCst);
        self.exited_threads.fetch_add(1, Ordering::SeqCst);
        if let Some(report) = self.thread_exit_reporter {
            report(tid, thread_syscalls);
        } else {
            global_state
                .send_rpc(CounterRequest::ThreadReport {
                    tid,
                    syscalls: thread_syscalls,
                })
                .await
                .map_err(CounterOutputError::into_error)?;
        }
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        let count = self.proc_syscalls.load(Ordering::SeqCst);
        let threads = self.exited_threads.load(Ordering::SeqCst);
        debug!(
            "At ExitProc (pid {}), contributing {} to global count.",
            pid, count
        );
        global_state
            .send_rpc(CounterRequest::ProcessExit(IncrMsg(count, threads)))
            .await
            .map_err(CounterOutputError::into_error)
    }
}
```

### The RPC difference, measured

Same guest, same ptrace backend, both launchers
(`reverie-examples/counter1.rs`, `counter2.rs`); RPC counts are
arithmetic from the designs (counter1 sends one per syscall;
counter2 sends one per thread exit plus one per process exit) and
the totals printed below are the tools' own stderr lines from one
run each on this tree:

| Workload | Syscalls | counter1 RPCs | counter2 RPCs | Both totals |
|---|---:|---:|---:|---|
| `/bin/echo hello` | 114 | 114 | 2 (1 report + 1 exit) | 114 |
| `/bin/sh -c 'echo parent; /bin/echo child; echo done'` | 315 | 315 | 4 (2 reports + 2 exits) | 315 |

The syscall counts are properties of the guest and host libc, so
yours will differ; the RPC counts are properties of the *designs*
and will not. counter2's per-thread stderr lines for the shell
workload (`…syscalls=123` for the child, `…syscalls=192` for the
shell) sum to the same 315 the global line reports — the fold is
visible, and it is exact.
