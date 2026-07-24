# reverie-kvm

`reverie-kvm` is an x86-64 research backend for driving small KVM guests. It
creates a VM and vCPU, provides bounded guest-physical memory access, turns a
guest `vmcall`/`vmmcall` into a typed Reverie syscall event, and can run
minimal static ELF executables in a bare long-mode process personality.

The guest places the syscall number and six arguments in a fixed-size frame in
guest memory. The hypercall passes the frame address to the host. `run` exposes
the original raw callback, while `run_with_tool` converts the frame to
`reverie::syscalls::Syscall` and dispatches a normal `reverie::Tool`. Its guest
adapter implements the shared `Guest` contracts for memory, registers, stack,
thread state, global RPC, syscall injection, and tail injection. Until a guest
kernel supplies Linux syscall semantics, callers provide a `SyscallExecutor`
for injected and unsubscribed syscalls.

## ELF execution

`install_static_elf` accepts little-endian x86-64 `ET_EXEC` and `ET_DYN` images. It copies `PT_LOAD` segments, zeros BSS, loads one `PT_INTERP` image when present, creates a Linux-style `argc`/`argv`/`envp`/auxv stack, and installs an identity-mapped long-mode address space. The vCPU starts at CPL3. `EFER.SCE`, `STAR`, `LSTAR`, and
`SFMASK` direct real `SYSCALL` instructions to a ring-0 trampoline that
serializes the Linux ABI register frame, exits KVM, then returns with
`SYSRETQ`.

`run_static_elf` supplies a deliberately small single-process Linux personality. It handles process exit, host-backed filesystem descriptors, stdout/stderr writes, deterministic identity, time and random queries, FS/GS bases, `brk`, anonymous and file-backed `mmap`, and common startup no-ops. Unsupported syscalls return `ENOSYS`.
## Typed syscall decoding

Every valid x86-64 syscall number is decoded through Reverie's complete typed
syscall table before it reaches the host handler; a number outside that table
is rejected instead of being forwarded as an untyped request. `install_syscalls`
builds a small guest program containing consecutive hypercalls, with one
page-aligned frame per request, so a single KVM run can route several syscalls.

## CPUID policy

Every vCPU receives an explicit CPUID table through `KVM_SET_CPUID2` before
its first `KVM_RUN`. The default `CpuidPolicy::deterministic` policy removes
`RDRAND`, `RDSEED`, TSX, AVX-512 feature bits, and the AVX-512 extended
register state. Callers that need KVM's full host-supported table can opt into
`CpuidPolicy::host_supported`.

The KVM integration test executes CPUID inside the VM and copies the resulting
registers to guest memory. This checks the vCPU-visible table rather than only
unit-testing the host-side mask.

This is a static vCPU feature policy, not a per-instruction
`Tool::handle_cpuid_event` callback. The latter still requires the planned
Linux execution bridge to preserve task-local callback context.

## Relationship to gVisor

gVisor routes Linux filesystem syscalls through its Sentry VFS and the filesystem implementations under `pkg/sentry/fsimpl/`. Those layers own mount-namespace traversal, dentries, file descriptions, metadata, and directory iteration without exposing host descriptors directly. The closest syscall-facing paths are `pkg/sentry/syscalls/linux/sys_file.go` and `sys_getdents.go`.

This backend follows the same separation between the architecture transport and syscall policy: the KVM exit path only carries a Linux register frame, while the executor owns guest descriptor allocation, path resolution, and ABI marshalling. The implementation is intentionally much smaller than gVisor: each opened filesystem descriptor owns a host `File`, relative paths resolve against the captured working directory or an owned directory descriptor, and subscribed calls pass through Detcore, whose tail injection invokes this executor before Detcore post-processes returned metadata; unsubscribed calls invoke the executor directly.

No gVisor code is copied. Unlike the gVisor Sentry VFS and `pkg/sentry/fsimpl/` stack, this crate does not provide a virtual mount namespace, dentry cache, or filesystem implementation. Hermit container setup remains the isolation boundary, not this standalone crate, and a changing host-backed filesystem remains outside the determinism guarantee. Host procfs descriptors are rejected because they would identify the Hermit supervisor rather than a separate guest process.

## Current limits

This crate is not a complete Linux execution backend. The ELF path has one vCPU, fixed-address identity mappings, no threads or signals, and no page-permission enforcement. Filesystem access forwards into the host namespace with bounded memory copies and a guest-owned descriptor table; it does not isolate or snapshot host filesystem changes. The current hypercall transport also reuses standardized KVM
hypercall 12 because it is the only hypercall KVM exposes to userspace; that
prototype ABI must be replaced before running a stock guest kernel.

The ELF loader supports one host interpreter and enough file-backed mapping for small dynamically linked programs. General libc coverage remains bounded by the explicit syscall personality; unsupported operations fail with `ENOSYS` rather than silently bypassing the tool.
