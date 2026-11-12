# Appendix A: crate map

| Crate | Role | Chapter |
|---|---|---|
| `reverie` (package `reverie-core`) | `Tool`, `GlobalTool`, `Guest`, `Backend`, `Subscription`, provider interfaces | [Tool API](tool-api.md) |
| `reverie-ptrace` + `safeptrace` | the reference backend | [Backends](backends.md) |
| `reverie-syscalls` | typed syscall wrappers + pretty-printing | [Typed syscalls](typed-syscalls.md) |
| `reverie-process`, `reverie-memory`, `reverie-util` | commands, guest memory, shared utilities | throughout |
| `reverie-procfs` | pure `/proc` content formatting and path classification helpers | throughout |
| `reverie-inguest` | shared in-guest runtime: seccomp trap, dispatcher, trusted gate | [Mechanisms](mechanisms.md) |
| `reverie-liteinst` (+ `-artifact`, `-preload`) | in-guest LiteInst patching backend + preload hosting | [Backends](backends.md) |
| `reverie-loader` | image validation, gate audit, init stages | [Loaders](loaders.md) |
| `reverie-kvm`, `reverie-kvm-core` | KVM backend (specialized runner) | [Backends](backends.md) |
| `reverie-linuxemu` | KVM-internal userspace Linux emulation — not a backend or Tool-contract surface | [Backends](backends.md) |
| `reverie-linux-provider` | **Deprecated shim** re-exporting `reverie::provider` for one release. The *core interface* is what the KVM executor implements and the ptrace/in-guest paths call (their provider is the host kernel); this shim crate itself has no in-repo consumer — import from core instead | [Tool API](tool-api.md) |
| `reverie-rpc-transport` | UDS framed RPC (`RpcServer`, blocking/async clients) | [State](state.md) |
| `reverie-examples` | the tool gallery + cross-backend launchers + e2e harness | [First tool](first-tool.md), [Testing](testing.md) |
| `reverie-test-support` | shared test fixtures | [Testing](testing.md) |

External backends (DynamoRIO, SaBRe, e9patch) live in their own
repositories; `docs/BACKEND_SOURCES.md` records ownership and license
notes. The mechanism matrix in `BACKENDS.md` is the deep reference
this guide summarizes.

Scope note: the workspace's `experimental/` members (`nostd-print`,
`reverie-rpc-macros`, `reverie-rpc`, `riptrace/rpc`) are deliberately
omitted above — they are experiments, not part of the surface this
guide teaches.

Published crates (`reverie-core`, `reverie-ptrace`,
`reverie-syscalls`, `reverie-process`, `reverie-memory`,
`safeptrace`) have API documentation on docs.rs. Note that the
crates.io names `reverie` and `reverie-util` belong to unrelated
projects — the framework's core crate is **`reverie-core`**, imported
as `reverie`.
