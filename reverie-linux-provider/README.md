# reverie-linux-provider

The provider-neutral interface of the Linux syscall provider beneath a
[Reverie](https://docs.rs/reverie-core) backend: the `LinuxProvider` trait a
syscall provider implements, the raw `SyscallRequest` it executes, and the
guest-memory and address-space traits it uses. It names no backend; the
reverie-kvm backend implements the memory traits for its guest arena.

This is an internal building block of Reverie's KVM backend, not part of the
Reverie `Tool`, `Guest` or backend contract.
