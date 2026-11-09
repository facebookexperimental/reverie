# reverie-kvm-core

The lower layer of [Reverie](https://docs.rs/reverie-core)'s KVM backend: the
machine that LinuxEmu (`reverie-linuxemu`) emulates Linux on. It holds the
guest memory arena and its page tables, the long-mode bootstrap and syscall
trampoline, the guest syscall frame, the entry gate between vCPU entries and
memory operations, run-failure ownership, the backend's error type and the
fixed guest address map. reverie-kvm builds on it and re-exports what its
users need.

This is an internal building block of Reverie's KVM backend, not part of the
Reverie `Tool`, `Guest` or backend contract.
