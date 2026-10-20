# reverie-core

Reverie is a Linux syscall and signal interception framework, and the
instrumentation layer beneath [Hermit](https://hermetic-infra.org).
This crate defines the `Tool`, `GlobalTool`, `Guest`, and `Backend` contracts.
A tool decides how to handle an event; a backend launches and supervises the
guest and delivers those events to the tool.

The package is named `reverie-core`; its Rust library is named `reverie`:

```toml
[dependencies]
reverie = { package = "reverie-core", version = "0.4" }
```

See the [API documentation](https://docs.rs/reverie-core), and
[`reverie-ptrace`](https://crates.io/crates/reverie-ptrace) for the reference
backend. The core contracts alone do not make a guest deterministic; Hermit's
determinization tool and selected backend provide that behavior.

For the command-line interface and installation guide, use
[`hermit-run`](https://crates.io/crates/hermit-run). For background, read
[Hermit: Deterministic Linux for Controlled Testing and Software Bug-finding](https://developers.facebook.com/blog/post/2022/11/22/hermit-deterministic-linux-testing/).
