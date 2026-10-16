# reverie-linux-provider

Deprecated. The Linux syscall provider interface (the `LinuxProvider` trait,
the raw `SyscallRequest` it executes, and the guest-memory and address-space
traits it uses) now lives in [Reverie](https://docs.rs/reverie-core)'s core as
the `reverie::provider` module. This crate only re-exports that module for one
release; import from `reverie::provider` instead.
