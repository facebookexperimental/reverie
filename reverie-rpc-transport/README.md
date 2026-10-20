# reverie-rpc-transport

Cross-process transport for [Reverie](https://docs.rs/reverie-core)
`GlobalTool` RPC, using Unix-domain sockets and bincode framing. A backend can
use it to keep tool-global state in a coordinator process while guest-side
callbacks run elsewhere.

This is support for backends that explicitly select it. Hermit's default
ptrace and KVM installation does not require this transport.

```toml
[dependencies]
reverie-rpc-transport = "0.4"
```

See the [API documentation](https://docs.rs/reverie-rpc-transport) for the
server, readiness, connection, and shutdown contracts. For the project and
CLI, visit [Hermit](https://hermetic-infra.org) and
[`hermit-run`](https://crates.io/crates/hermit-run).
