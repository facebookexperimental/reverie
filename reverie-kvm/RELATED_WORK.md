# Related Work

This document positions `reverie-kvm` relative to gVisor and to virtual-machine
monitors that also use Linux KVM. The projects use some of the same kernel
mechanisms, but they solve different problems. In particular, using KVM does
not by itself make two systems equivalent in security boundary, Linux ABI
coverage, scheduling, or determinism.

`reverie-kvm` is an x86-64 research backend for running a process personality
through the generic Reverie `Tool` interface. It is not a general-purpose VMM,
does not boot a guest Linux kernel, and is not currently a standalone sandbox
boundary.

## `reverie-kvm` architecture

`reverie-kvm` loads an ELF process directly into KVM guest memory. Application
code runs at CPL3. A real `SYSCALL` enters a small CPL0 trampoline, which writes
the Linux syscall register state to a guest-memory frame and requests a KVM
userspace exit. The host then converts that frame into Reverie's typed
`Syscall` representation.

The root execution path is:

```text
ELF at guest CPL3
  -> SYSCALL
  -> small guest CPL0 trampoline
  -> KVM_EXIT_HYPERCALL
  -> SyscallRequest in shared guest memory
  -> typed reverie::syscalls::Syscall
  -> T: reverie::Tool, when subscribed
  -> ElfExecutor for injection or backend-owned behavior
  -> result frame
  -> SYSRETQ to guest CPL3
```

This separates three concerns:

1. **Architecture transport.** `bootstrap.rs`, `vm.rs`, and `syscall.rs` set up
   long mode, the syscall trampoline, vCPUs, KVM exits, and the transport frame.
2. **Reverie integration.** `runtime.rs` implements memory, register, stack,
   lifecycle, RPC, injection, and tail-injection behavior for a generic
   `T: Tool`.
3. **Linux personality.** `executor.rs` implements the bounded syscall and
   process model used when a syscall is injected or not subscribed by the
   tool.

Guest thread workers use private vCPUs and private syscall transport slots over
shared guest memory. The runtime propagates group exit, interrupts and joins
workers during teardown, and reuses worker transport slots and unmapped address
ranges. This is still narrower than a Linux task model: child and worker
syscalls do not all receive independent Reverie process/thread lifecycle
callbacks, and the executor remains an explicit compatibility surface rather
than a complete kernel.

The loader synthesizes its own initial stack and auxiliary vector and does not
install a guest vDSO. Time reads therefore reach the explicit syscall
personality instead of silently bypassing the syscall transport through a host
vDSO fast path. If a guest vDSO is added later, it must be virtualized or backed
by deterministic shared state.

## gVisor's common model

gVisor implements Linux in the **Sentry**, a userspace kernel shared by its
platforms. The Sentry owns the process model, scheduler-visible task state,
virtual filesystems, network stack, signals, namespaces, and syscall semantics.
The platform beneath it answers a narrower question: how should application
code execute and how should control return to the Sentry on syscalls and
faults?

That distinction matters when comparing `reverie-kvm` with gVisor. The closest
analogy to Reverie's `Tool` plus `ElfExecutor` split is gVisor's platform plus
Sentry split, but the amount of policy on the Sentry side is much larger. A
gVisor platform can rely on a mature userspace kernel. `reverie-kvm` currently
provides a bounded host-backed process personality and delegates subscribed
events to an arbitrary Reverie tool.

No gVisor code is copied into `reverie-kvm`.

## gVisor systrap

Systrap is a gVisor platform for executing sandboxed application code in host
processes without using KVM. Its interception design is layered:

- Syscall User Dispatch (SUD) is the primary syscall trap on supported Linux
  kernels.
- Seccomp `SECCOMP_RET_TRAP` supplies a fallback trap.
- `usertrap` can patch recognized syscall instruction sequences into a faster
  direct path. Patching is an optimization over a complete trap floor, not the
  only interception mechanism.

Systrap decouples the application address space, a shared-memory thread
context, and the host worker that communicates with the Sentry. Shared-memory
queues and spin-then-futex handoffs reduce the number of host context switches
on hot paths. Ptrace remains part of bootstrap and slow-path register handling;
rootless operation obtains the required capability inside a user namespace.

Systrap also supplies a gVisor-controlled vDSO and shared parameter page.
Without that step, common time calls could execute entirely in userspace and
bypass SUD, seccomp, and syscall policy.

### Systrap compared with `reverie-kvm`

| Dimension | gVisor systrap | `reverie-kvm` |
| --- | --- | --- |
| Application execution | Host process address space | KVM guest CPL3 |
| Primary syscall transfer | SUD or seccomp signal | CPL0 trampoline plus KVM userspace exit |
| Optional fast path | In-place `usertrap` patch | None; every guest `SYSCALL` uses the trampoline |
| Shared state | Stub/context/worker shared-memory protocol | KVM userspace memory shared by vCPUs and host runtime |
| Linux semantics | Full gVisor Sentry | Bounded `ElfExecutor` plus subscribed Reverie `Tool` |
| vDSO | gVisor vDSO plus parameter page | No guest vDSO in the synthesized auxv |
| Privilege prerequisite | Ptrace capability, commonly in a user namespace | Access to `/dev/kvm` |
| Scheduling goal | Throughput-oriented multiplexing | Backend compatibility; determinism belongs to the loaded tool |
| Sandbox status | Production gVisor platform | Research backend, not a standalone security boundary |

Both designs keep the event transport separate from Linux policy. Beyond that
high-level separation, their mechanisms are different. Systrap keeps
application execution in host processes and optimizes signal-based trapping;
`reverie-kvm` uses hardware privilege transitions and KVM exits. Systrap's
M:N worker scheduling is not a determinism mechanism and should not be copied
into a deterministic backend without an explicit scheduling policy above it.

## gVisor's KVM platform

gVisor also has a KVM platform. This is a closer architectural relative than
systrap: application code executes in KVM vCPU contexts and returns to the
Sentry on syscalls, exceptions, and faults. The Sentry still supplies gVisor's
Linux semantics; KVM is an execution and isolation mechanism, not the guest
kernel whose system calls are trusted directly.

### gVisor KVM compared with `reverie-kvm`

| Dimension | gVisor KVM platform | `reverie-kvm` |
| --- | --- | --- |
| Primary purpose | Production application sandbox | Generic Reverie backend research |
| Guest payload | Sandboxed application contexts | Directly loaded x86-64 ELF process |
| Guest kernel | Minimal platform machinery; Sentry implements Linux | Minimal syscall/exception trampoline; `ElfExecutor` implements a subset |
| Syscall policy | gVisor Sentry | Generic `T: Tool` plus executor fallback |
| ABI breadth | gVisor's broad Linux compatibility | Explicit and incomplete syscall personality |
| Filesystem | Sentry VFS and filesystem implementations | Guest fd table backed largely by owned host files |
| Networking | Sentry network stack and platform integrations | Explicit host-backed compatibility subset |
| Process model | Mature Sentry task model | Bounded fork/exec/wait and guest-worker model |
| Isolation claim | Designed as a sandbox security boundary | Relies on surrounding isolation; not a standalone boundary |
| Determinism | Not a primary platform guarantee | Possible through a determinism tool; not guaranteed by KVM alone |

The reusable gVisor lesson is the **platform/policy seam**. A KVM exit handler
should carry architectural state, while syscall semantics live above it. In
`reverie-kvm`, typed syscall decoding makes that seam explicit and lets the
same transport host a counter, strace, fault injector, or Detcore rather than
hard-coding one userspace kernel.

The corresponding limitation is also explicit: a generic tool interface does
not replace the work of a complete Linux kernel. Each compatibility addition
must still define descriptor ownership, memory-copy fault behavior, process
lifecycle, signals, and concurrency. gVisor already centralizes those rules in
the Sentry; `reverie-kvm` is building a narrower personality incrementally.

## Other KVM-based systems

Firecracker, Cloud Hypervisor, and QEMU all use KVM, but they sit at a different
layer from `reverie-kvm`. They are VMMs that normally boot a guest kernel and
present virtual hardware. Guest syscalls are handled by that guest kernel and
are not delivered as typed host callbacks.

| Project | Unit of virtualization | Device model | Syscall policy location | Primary goal | Relationship to `reverie-kvm` |
| --- | --- | --- | --- | --- | --- |
| Firecracker | Linux microVM | Deliberately small virtio-oriented model | Guest kernel | Fast, dense, strongly isolated microVMs | Useful security and minimal-VMM reference; not a syscall instrumentation backend |
| Cloud Hypervisor | Cloud workload VM | Modular `rust-vmm` devices, hotplug, modern VM features | Guest kernel | Cloud VM lifecycle and device management | Shares Rust/KVM ecosystem components, but owns a full VM boundary rather than a process personality |
| QEMU with KVM | General system VM | Broad architecture and device emulation; TCG fallback | Guest kernel | Compatibility, emulation, and full-system virtualization | Useful compatibility workload and VMM reference; much broader scope and device surface |
| gVisor KVM | Sandboxed application contexts | Platform-specific minimal machinery, not a conventional guest device model | Sentry userspace kernel | Application sandboxing | Closest production architectural comparison |
| `reverie-kvm` | Direct ELF process personality | No general virtual device model | Reverie `Tool` and `ElfExecutor` | Typed syscall instrumentation and deterministic-backend research | Uses KVM as a controlled execution transport |

Running QEMU *under* `reverie-kvm` as a compatibility workload does not turn
`reverie-kvm` into a QEMU-like VMM. In that arrangement QEMU is application
code exercising the process personality, while `reverie-kvm` still owns only
the outer ELF, syscall, memory, and worker lifecycle model.

## Design relationship to gVisor

Future KVM changes should state how they relate to gVisor rather than using
"similar to gVisor" as an unqualified completion claim. The useful review
questions are:

1. **Transport or policy?** Is the change about vCPU/register/memory transfer,
   or is it adding Linux semantics? Compare transport changes with gVisor's
   platform packages and semantic changes with the Sentry.
2. **Which platform is the analogue?** Systrap is the right comparison for
   fail-closed interception, shared-memory handoff, and vDSO handling. gVisor's
   KVM platform is the right comparison for vCPU execution, faults, and KVM
   exits.
3. **What is intentionally narrower?** Name omitted Sentry facilities such as
   mount namespaces, VFS objects, network stack, asynchronous signals, or full
   task scheduling instead of implying parity.
4. **Where is the security boundary?** A host-backed syscall implementation is
   not equivalent to Sentry isolation. Document which surrounding container or
   host namespace assumptions remain trusted.
5. **Where is determinism enforced?** KVM, SUD, and shared memory are transports.
   Determinism requires the tool's clock, randomness, identity, filesystem, and
   scheduler policies. gVisor's throughput scheduler is not evidence of
   deterministic execution.
6. **Can an event bypass the tool?** Check vDSO calls, worker-owned syscalls,
   child lifecycle paths, direct guest memory access, and unsubscribed calls.

The intended relationship is therefore selective: reuse gVisor's separation
of execution platform from syscall policy, its fail-closed mindset, and its
careful treatment of vDSO and process state. Do not claim Sentry compatibility,
sandbox equivalence, or gVisor scheduling semantics until those properties are
measured directly.

## Current boundaries

The comparison above should be read with these current limits:

- KVM confines guest CPU execution, but the identity-mapped guest page tables
  are not yet a complete in-guest memory-protection model.
- The filesystem personality forwards bounded operations through owned host
  files and does not implement a gVisor-style virtual mount namespace or dentry
  cache.
- Root subscribed syscalls traverse the Reverie `Tool`; worker and child paths
  still include backend-owned behavior and do not provide full per-task tool
  lifecycle parity.
- Signal state is partly modeled, but asynchronous Linux signal delivery is
  not complete.
- The deterministic CPUID profile and explicit time/random/identity handlers
  reduce host leakage, but a generic Reverie tool run is not automatically
  deterministic.
- Unsupported operations fail explicitly rather than silently escaping to an
  untyped host syscall path.

These are engineering scope statements, not comparisons of vulnerability
counts or benchmark performance. Security and performance claims require
separate, reproducible evaluation.

## References

- gVisor architecture guide: <https://gvisor.dev/docs/architecture_guide/>
- gVisor platform guide: <https://gvisor.dev/docs/architecture_guide/platforms/>
- gVisor systrap announcement and design overview:
  <https://gvisor.dev/blog/2023/04/28/systrap-release/>
- gVisor source, systrap platform:
  <https://github.com/google/gvisor/tree/master/pkg/sentry/platform/systrap>
- gVisor source, KVM platform:
  <https://github.com/google/gvisor/tree/master/pkg/sentry/platform/kvm>
- Firecracker design document:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md>
- Cloud Hypervisor project:
  <https://github.com/cloud-hypervisor/cloud-hypervisor>
- QEMU system emulation documentation:
  <https://www.qemu.org/docs/master/system/index.html>
- Linux KVM API documentation:
  <https://docs.kernel.org/virt/kvm/api.html>
