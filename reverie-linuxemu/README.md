# reverie-linuxemu

LinuxEmu: the Linux syscall emulation that [Reverie](https://docs.rs/reverie-core)'s
KVM backend runs its guests on, in the manner of gVisor's Sentry. It models
tasks and thread groups, the fd table and file descriptions, signals, memory
mappings, ELF loading and exec, and the syscalls over them, on the machine that
`reverie-kvm-core` provides. `reverie-kvm` runs the vCPUs and drives the Tool.

This is an internal building block of Reverie's KVM backend, not part of the
Reverie `Tool`, `Guest` or backend contract.
