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
accumulates locally, each process folds its threads' totals in, and
the process contributes to global state **once**. A thread report
never double-adds what the process already contributed, and the final
report goes through global state, so it survives even a guest that
closes stderr.

That is the MapReduce shape most real tools want: *map* in thread
state (cheap, uncontended), *reduce* at process and tree boundaries
(rare, explicit). Reach for per-event RPC only when the global
decision genuinely affects the very next event — a scheduler granting
a turn, a deterministic clock — and expect to pay for it (see
[Performance](performance.md)).

## Common state bugs

* **Counting in the wrong lifetime.** State that must survive `exec`
  belongs in global state or must be re-established in
  `handle_post_exec`; process state after exec is a design decision
  your tool must make explicitly, per backend contract.
* **Assuming `receive_rpc` ordering across processes.** RPCs from
  different guest processes race exactly as their senders do. If order
  matters, carry sequence information in the request.
* **Leaking guest references.** Thread/process state lives exactly as
  long as its thread/process. Anything that must outlive both goes
  through RPC before the exit hooks complete.

> 🚧 **Under construction — counter2 listing.** TODO: full annotated
> listing of `counter2_tool.rs` with the fold points marked, plus the
> measured RPC-count difference counter1-vs-counter2 on one workload.
> <!-- UC: state-counter2 -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`state-counter2`).
