# Appendix A: crate map

| Crate | Role | Chapter |
|---|---|---|
| `reverie` (package `reverie-core`) | `Tool`, `GlobalTool`, `Guest`, `Backend`, `Subscription`, provider interfaces | [Tool API](tool-api.md) |
| `reverie-ptrace` + `safeptrace` | the reference backend | [Backends](backends.md) |
| `reverie-syscalls` | typed syscall wrappers + pretty-printing | [Typed syscalls](typed-syscalls.md) |
| `reverie-process`, `reverie-memory`, `reverie-util` | commands, guest memory, shared utilities | throughout |
| `reverie-inguest` | shared in-guest runtime: seccomp trap, dispatcher, trusted gate | [Mechanisms](mechanisms.md) |
| `reverie-liteinst` (+ `-artifact`, `-preload`) | in-guest LiteInst patching backend + preload hosting | [Backends](backends.md) |
| `reverie-loader` | image validation, gate audit, init stages | [Loaders](loaders.md) |
| `reverie-kvm`, `reverie-kvm-core` | KVM backend (specialized runner) | [Backends](backends.md) |
| `reverie-linuxemu`, `reverie-linux-provider` | KVM-internal userspace Linux emulation/provider — not a backend or Tool-contract surface | [Backends](backends.md) |
| `reverie-rpc-transport` | UDS framed RPC (`RpcServer`, blocking/async clients) | [State](state.md) |
| `reverie-examples` | the tool gallery + cross-backend launchers + e2e harness | [First tool](first-tool.md), [Testing](testing.md) |
| `reverie-test-support` | shared test fixtures | [Testing](testing.md) |

External backends (DynamoRIO, SaBRe, e9patch) live in their own
repositories; `docs/BACKEND_SOURCES.md` records ownership and license
notes. The mechanism matrix in `BACKENDS.md` is the deep reference
this guide summarizes.

Published crates (`reverie-core`, `reverie-ptrace`,
`reverie-syscalls`, `reverie-process`, `reverie-memory`,
`safeptrace`) have API documentation on docs.rs. Note that the
crates.io names `reverie` and `reverie-util` belong to unrelated
projects — the framework's core crate is **`reverie-core`**, imported
as `reverie`.
