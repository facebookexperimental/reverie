# reverie-e9patch

`reverie-e9patch` is the integration boundary between Reverie and the e9patch
static binary rewriter pinned in `third-party/e9patch`.

The crate is currently at backend maturity B0: it exists in the Cargo
workspace and compiles, but it does not yet implement `reverie::Guest` or
`reverie::Backend`. Those runtime contracts require syscall-event transport,
guest memory and register access, injected syscalls, global RPC, process-tree
supervision, and tool lifecycle handling. A rewritten binary by itself does
not satisfy those contracts.

The upstream source stays opt-in because it is GPL-3.0 and has system build
dependencies. Activate and build it explicitly:

```bash
scripts/backend-submodule.sh activate e9patch
make -C third-party/e9patch
```
