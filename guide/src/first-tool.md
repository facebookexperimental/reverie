# Project: your first tool

We build a syscall counter, run it, and then break it down. The code
is `reverie-examples/counter1_tool.rs` (the tool) and
`reverie-examples/counter1.rs` (its launcher). Run it first:

```console
$ cargo run --bin counter1 -- /bin/echo hello
```

`echo` prints `hello` as usual, and at exit the launcher prints
`counter1-global syscalls=N` — the total the tool accumulated. Success!
Now let's see what you just ran.

## The tool: two halves

Every Reverie tool is a pair:

* the **local half** (`Tool`) — one instance per guest process, with
  per-thread state, runs the event handlers;
* the **global half** (`GlobalTool`) — one instance for the whole
  guest tree, reached from handlers by RPC.

Listing FT-1 is the whole counter. It is short because the framework
carries the machinery; your code carries only the policy.

<span class="filename">Listing FT-1: reverie-examples/counter1_tool.rs</span>

```rust
#[derive(Debug, Default, Clone)]
pub struct CounterGlobal {
    num_syscalls: Arc<AtomicU64>,
}

#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct IncrMsg(pub Sysno);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    type Config = ();

    async fn init_global_state(_: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, IncrMsg(sysno): IncrMsg) {
        self.num_syscalls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
pub struct CounterLocal {}

#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let _ = guest.send_rpc(IncrMsg(syscall.number())).await;
        guest.tail_inject(syscall).await
    }
}
```

Breaking it down:

* `handle_syscall_event` is the only handler this tool overrides. It
  receives the typed `Syscall`, the live `Guest` handle, and must
  produce the syscall's result (`i64`). Everything a handler may do —
  inspect memory, rewrite arguments, inject *other* syscalls,
  suppress this one — is a variation on this signature.
* `guest.send_rpc(IncrMsg(..))` is the only way local handlers reach
  global state. The request type is yours (`IncrMsg`); it must be
  serializable, because on in-guest backends this really crosses a
  process boundary, while on ptrace it compiles down to a local call.
  The tool doesn't know which — and must not care.
* `guest.tail_inject(syscall)` means "now actually perform the syscall
  I was handed, and return its result." Most observability tools end
  most handlers this way. (Return a value yourself instead, and you
  have *elided* the syscall; return an error, and you have injected a
  failure. `chaos` does both.)
* `init_global_state` runs once for the tree. `Config` is `()` here;
  real tools take their run-time configuration through it.

## The launcher: pick a backend, get state back

Running a tool always has the same shape: hand a backend a command and
the tool's config; receive the guest's exit status together with the
final global state. Through the abstract trait:

```rust
use reverie::Backend;
let (exit_status, global_state) =
    reverie_ptrace::PtraceBackend::run::<MyTool>(command, config).await?;
```

The examples' shared launcher (`reverie-examples/backend.rs`) goes one
step further: `--backend ptrace|liteinst|in-guest-trap|kvm` runs the
*same* `T: Tool` through each backend's public entry point, so one
tool and one program can be compared across mechanisms. A backend
either runs the tool or refuses by name (`RunError::Refused`) — for
example, the in-guest backends refuse when no preload compiling your
tool in can be found, saying so in the error. Keep that distinction in
mind: it is the difference between a toolkit and a pile of backends.

## Summary and next steps

You wrote a two-half tool, counted with RPC, and let the backend own
the guest's lifecycle. [The Tool API](tool-api.md) covers the full
handler surface; [State at three scales](state.md) grows this counter
into `counter2`, where the counting itself is distributed.

> 🚧 **Under construction — grow this project.** TODO: extend the
> counter stage by stage across the next chapters (subscriptions to
> count only `openat`; per-syscall histograms via thread state;
> identical runs on three backends) with a "full code at this step"
> link per stage, Tokio-tutorial style. <!-- UC: ft-grow -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`ft-grow`).
