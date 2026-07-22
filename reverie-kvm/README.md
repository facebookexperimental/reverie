# reverie-kvm

`reverie-kvm` is an x86-64 research backend for driving small KVM guests. It
creates a VM and vCPU, provides bounded guest-physical memory access, and turns
a guest `vmcall`/`vmmcall` into a typed Reverie syscall event.

The guest places the syscall number and six arguments in a fixed-size frame in
guest memory. The hypercall passes the frame address to the host. `run` exposes
the original raw callback, while `run_with_tool` converts the frame to
`reverie::syscalls::Syscall` and dispatches a normal `reverie::Tool`. Its guest
adapter implements the shared `Guest` contracts for memory, registers, stack,
thread state, global RPC, syscall injection, and tail injection. Until a guest
kernel supplies Linux syscall semantics, callers provide a `SyscallExecutor`
for injected and unsubscribed syscalls.

## gVisor model

gVisor's KVM platform keeps syscall policy above the architecture transport:
`pkg/ring0/entry_amd64.s` saves the user register frame and enters its syscall
trampoline, while `pkg/sentry/platform/kvm/bluepill_unsafe.go` classifies KVM
exits before returning control to the sentry. This prototype follows the same
separation on a smaller scale: the VM-exit layer validates and decodes the
transport once, and the runtime layer presents backend-neutral Reverie types to
the tool. Unlike gVisor, the prototype does not yet contain a ring-0 Linux
personality.

## Current limits

This crate is not yet a Linux execution backend for arbitrary ELF programs. It
has one real-mode vCPU and no process lifecycle, virtual memory, signals,
filesystem, or timer implementation beyond the shared single-thread lifecycle
used by the test guest. The `/dev/kvm` integration tests run a minimal
`vmcall; hlt` guest program and verify both direct tool interception and the
default Tool handler's ptrace-compatible `tail_inject` behavior.
