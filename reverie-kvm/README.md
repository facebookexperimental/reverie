# reverie-kvm

`reverie-kvm` is an x86-64 research backend for driving small KVM guests. Its
current scope is intentionally narrow: it creates a VM and vCPU, provides
bounded guest-physical memory access, and turns a guest `vmcall`/`vmmcall` into
a host-side Linux syscall request.

The guest places the syscall number and six arguments in a fixed-size frame in
guest memory. The hypercall passes the frame address to the host, which lets
the backend inspect pointer arguments without limiting Linux syscalls to the
five registers left after a transport opcode.

This crate is not yet a Linux execution backend for arbitrary programs. KVM
does not provide Linux syscall semantics, process lifecycle, virtual memory,
signals, or filesystem behavior. Those require a guest kernel or user-space
Linux personality before this prototype can implement the full Reverie
`Guest` contract.
