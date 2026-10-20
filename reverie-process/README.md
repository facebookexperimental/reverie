# reverie-process

Linux process spawning, namespaces, and asynchronous process management for
[Reverie](https://docs.rs/reverie-core), the instrumentation framework beneath
[Hermit](https://hermetic-infra.org). This crate can also be used independently
of a Reverie tool or backend.

```toml
[dependencies]
reverie-process = "0.4"
```

The default features build on stable Rust. Namespace operations require the
corresponding Linux capabilities or permission to create unprivileged user
namespaces. Ubuntu 24.04's AppArmor policy may restrict user namespaces; follow
the platform setup in the [`hermit-run` README](https://crates.io/crates/hermit-run).

See the [API documentation](https://docs.rs/reverie-process) for `Command`,
`Child`, and namespace configuration. For Hermit's command-line interface,
install [`hermit-run`](https://crates.io/crates/hermit-run).
