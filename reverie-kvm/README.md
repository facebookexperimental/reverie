# reverie-kvm

`reverie-kvm` is an x86-64 research backend for driving small KVM guests. It
creates a VM and vCPU, provides bounded guest-physical memory access, turns a
guest `vmcall`/`vmmcall` into a typed Reverie syscall event, and can run
minimal static ELF executables in a bare long-mode process personality.

The host must provide x86-64 KVM, procfs, `openat2` (Linux 5.6 or newer),
and `utimensat(AT_EMPTY_PATH)` (Linux 5.8 or newer) for full filesystem
metadata compatibility. Hosts before `fchmodat2` use a held-descriptor procfs
fallback rather than re-resolving guest paths.

The embedding process must reserve Linux real-time signal 64 exclusively for
the backend. On first vCPU entry, the backend installs a process-wide handler;
it does not restore that handler when a backend is dropped. Other libraries
must not send this signal or replace its handler for the rest of the process's
lifetime. An existing handler or `SIG_IGN` prevents entry. A changed handler or
an unexplained pending instance before a later entry also causes an error.
These checks detect visible conflicts; they do not coordinate ownership with
another signal user. Each entry restores the calling thread's original signal
mask after draining its own notifications. The existing `SIGURG` worker
cancellation mechanism remains separate and unchanged.

The private entry gate also stops every participant and callback memory copy
sharing a Mapping when clock-interval setup or cleanup fails. That interval
cannot provide trustworthy guest progress; allowing siblings to continue
would outlive an execution whose accounting has already failed. The issuing
owner retains the typed cause for terminal publication. A plain KVM_RUN error,
including interruption, does not by itself poison the Mapping. This gate is
currently used to test close and cleanup on unchanged mappings; no production
mapping change or global fork snapshot is qualified by it. This clock-failure
rule supersedes the initial accepted design's narrower list of poison causes
(kick, mask/drain restoration, abandoned close, and unwind). Admission and
poison handling already operate in production even without a production closer.

Guest-memory allocation also requires kernel support for `memfd_create` and
permission to call it under the host's seccomp or container policy. Allocation
errors propagate as `Error::MemoryMapping`. Retrying `EINVAL` without
`MFD_NOEXEC_SEAL` supports kernels that reject that newer flag; it does not
provide an anonymous-mapping fallback when `memfd_create` is unavailable or
denied.

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

Architectural exceptions (vectors 0 through 31) enter a ring-0 handler on the
TSS exception stack. The static-ELF direct and Tool loops translate one bounded
class into Linux signal delivery: actual user-mode nonpresent read, write or
instruction-fetch faults in virtual page zero produce `SIGSEGV` with
`SEGV_MAPERR` and the captured fault address. Other exception classes remain
`Error::GuestException`, reporting the vector, saved guest instruction pointer
and `CR2`; this is not general synchronous-fault delivery.

`run_static_elf` supplies a deliberately small Linux personality. It handles process exit, host-backed filesystem descriptors, stdout/stderr writes, deterministic identity, time and random queries, FS/GS bases, `brk`, anonymous and file-backed `mmap`, and common startup no-ops. Unsupported syscalls return `ENOSYS`.

The host-backed filesystem layer includes descriptor duplication, file and
filesystem metadata, permission and timestamp updates, and bounded
create/link/rename/unlink operations. A virtual umask is applied to creation
modes before they are forwarded to the host. The executor retains signal
actions, masks, pending state and alternate-stack configuration and delivers
supported events at explicit execution boundaries, as described below.
`mincore`, `getcpu`,
`sched_getaffinity`, and `membarrier` report the deterministic single-vCPU
topology.

The process personality implements `fork`, `vfork`, process-only `clone`/`clone3`,
`execve`/`execveat`, and `wait4`. Forked children receive an independent guest
RAM snapshot and fresh VM/vCPU, inherit duplicated host file descriptions, and
run to completion before the parent resumes. Legacy process clones support
`CLONE_PARENT_SETTID`, `CLONE_CHILD_SETTID`, and `CLONE_CHILD_CLEARTID`. A
bounded glibc pthread clone profile creates child vCPUs over shared guest RAM;
thread dispatch follows the configured Tool or host ownership. This is not a
general concurrent process scheduler. Forked processes receive independent process/thread
tool state, run subscribed syscall and lifecycle callbacks, and contribute to
the root tool's shared `GlobalState`. Tool-owned workers run the corresponding
Tool lifecycle callbacks; opting into unmonitored threads does not provide that
instrumentation.

## Vectored I/O

`readv`, `writev`, `preadv`, `pwritev`, `preadv2`, and `pwritev2` preserve vector
order and boundaries within one aggregate host operation. Staging preserves
pointer alignment and inaccessible memory ranges so the host endpoint applies
its own partial-transfer and fault rules. Version-two offset -1 selects the
current descriptor position; other supported positioned calls use the full
x86-64 signed offset.

The supervisor stages at most 16 MiB per operation. Larger buffered requests
may complete a bounded prefix. An `O_DIRECT` request whose Linux-clamped
aggregate exceeds 16 MiB returns `EOPNOTSUPP` before data transfer, with no
change to guest buffers, file data or descriptor position. This is an explicit
backend capability limit: shortening such a request could erase a required
alignment failure. Direct requests at or below the limit retain their original
vector shape and alignment checks.

## Bounded signal delivery

Standard-signal state includes shared process and per-thread pending sets,
coalescing, installed actions and blocked masks. `tkill` and `tgkill` can target
supported standard signals at a live thread in the sender's process. The named
receiver owns one private pending queue and its current blocked mask; the
sender cannot consume that event or change its own mask by sending it. Repeated
standard signals retain the first pending siginfo. Task registration and
retirement bind publication to the live TID generation, and exec preserves an
accepted pending event while replacing its queue atomically. Fork receives
independent signal state.

Supported events enter guest handlers at a return-to-user boundary. A newly
created thread also checks events queued before its first instruction; Tool
admission precedes its signal callback. At that initial boundary, ordinary
returning injections are available, while process-action and tail injections
return `ENOSYS` before effects because no consumed syscall continuation exists.
Tool execution observes eligible ignored events before discarding them. Plain
execution discards an unblocked ignored send immediately; a blocked ignored
send remains pending and can be handled if its disposition changes before
unmasking. Raw `rt_sigtimedwait` retains `SI_TKILL`; glibc's `sigtimedwait` wrapper
converts that code to `SI_USER`, as it does natively.

This does not interrupt an arbitrary running vCPU or wake a receiver blocked
in a host syscall, futex, child wait, or other unsupported wait. Enqueuing a
signal does not supply a deterministic scheduler notification or qualify
Hermit's parked-I/O interruption capability. Self-targeted `kill` remains
supported, but process-directed delivery with live siblings, cross-process
nonzero sends and multi-process fanout remain explicitly unsupported. The
backend does not use host scheduling to choose a recipient. Signal-zero
identity probes do not imply delivery support. Sibling `SIGKILL`, stopped-state
transitions, realtime signals, `SIGCHLD`/`SIGPIPE` production and general timer
production remain refused or unimplemented. `rt_sigtimedwait` can consume an
already pending virtual event; it does not implement a timed blocking wait.

`Guest::queue_child_exit_signal` is a separate receiver operation for a
Tool-selected terminal `SIGCHLD` event using `CLD_EXITED`, `CLD_KILLED`, or
`CLD_DUMPED`. It requires a current single-thread parent and an existing
syscall, signal, or captured-fault return boundary. The caller authenticates
the child, its class-specific terminal status and CPU accounting; the backend
validates the receiver and metadata shape, then retains the event in the
process pending set. Repeated standard events keep the first complete siginfo.
Explicit `SIG_IGN` suppresses this child-exit generation even when blocked;
`SIG_DFL` and `SA_NOCLDWAIT` do not suppress Tool observation. Queue acceptance
does not change child wait status or reaping policy and does not promise a
handler or `EINTR`. A typed outcome distinguishes refusal before publication
from a readiness-update failure after publication.

This operation does not create automatic child-exit notifications.
Stopped/continued/trapped child events and multi-thread-parent producers remain
unsupported. Initial thread-start/exec/post-exec callbacks lack the required
transport and refuse before effects. The existing private deferral API keeps
its earlier refusals. Pending events remain private across fork and survive
exec; an outstanding process event prevents creating an unsupported competing
thread consumer. Terminal child signalfd records include status and CPU fields.
Fork with an open virtual signalfd is still refused, including when the
descriptor holds a child event.

Tool-driven execution exposes structured signal events through
`Tool::handle_structured_signal_event`; accepted selected events can be deferred
through `Guest::defer_signal_delivery`. Public deferral validates signal, target
and provenance. It does not admit arbitrary positive-code hardware faults:
page-zero fault delivery depends on the actual captured exception context.
These interfaces do not establish Hermit/Detcore determinism, record/replay or
paired-backend parity, and they do not create a scheduler or host-time producer.

Handler entry supports the bounded x86-64 signal frame, alternate stacks
including `SS_AUTODISARM`, and `rt_sigreturn` restoration of registers, masks,
stack state and the supported XSAVE image. The KVM signal codec uses **832 bytes
of XSAVE state** (512 legacy, 64 header, 256 YMM) and **836 bytes including the
trailing `FP_XSTATE_MAGIC2` in the signal frame**. These are not the total signal
frame size. Header, payload and malformed-frame checks are unchanged; this is
not full native-frame byte equality or support for arbitrary extended CPU state.

The captured page-zero context retains interrupted registers, stack/flags,
selectors, trap/error and `CR2`; KVM selectors are not claimed byte-identical to
native selectors. Supported handlers can inspect and modify that context and
resume through `rt_sigreturn`; default, blocked and ignored page-zero fault
dispositions follow the bounded forced-signal path. Page-zero faults are not a
general mechanism for `HLT`, `UD2`, protection faults or other CPU exceptions.
The full restorer word is retained without a premature address bound: a
nonreturning handler may use a null or high restorer. Returning to null can use
the page-zero fault path, but unsupported high-return CPU fault classes remain
unsupported rather than being relabelled as successful Linux signal delivery.

Virtual `signalfd` consumes supported pending events and models record-stream
reads, descriptor aliases and readiness. Creation requires `SFD_NONBLOCK`;
the model is limited to a single-thread process and refuses unsupported
sibling/fork lifetimes while a signalfd is open. Vectored reads retain the
virtual stream's Linux offset and flag rules, including refusal of unsupported
`RWF_ATOMIC` and `RWF_DONTCACHE` requests with nonzero capacity. Host signal state
is not forwarded; general descriptor-transfer lifetime parity remains outside
this model.

## Task names and prctl state

`PR_SET_NAME` retains up to 15 bytes plus a terminating NUL for each guest
thread. `PR_GET_NAME` returns all 16 bytes, including padding; a failed name
import leaves the previous name intact. Threads inherit then independently
change their names, while the synthetic process status uses the leader's name
with procfs escaping. Exec initializes the name from the executable basename,
not a replacement `argv[0]`.

`PR_SET_THP_DISABLE` and `PR_GET_THP_DISABLE` model per-address-space policy:
0 means enabled, 1 means disabled, and 3 means disabled except when explicitly
advised (`PR_THP_DISABLE_EXCEPT_ADVISED`, flag 2). Threads and `CLONE_VM`
children share this state; fork copies it independently and exec inherits it.
Invalid flags or required-zero arguments fail without changing state. These
are virtual guest policy values, not changes to supervisor THP policy or a
claim that the guest RAM uses physical huge pages.

`PR_SET_PDEATHSIG` accepts zero; nonzero requests return `ENOSYS` because
deterministic parent-death signal delivery is not implemented. The getter
returns a four-byte zero. These two getters check guest writable-page state:
NAME may copy a writable prefix before reporting `EFAULT`, whereas PDEATHSIG
uses a scalar store and leaves the output unchanged when that store faults.
The strict eight-byte NAME boundary control is qualified on the tested x86-64
FSRM host, not a promise about every Linux architecture's partial-copy size.
This does not change privileged Tool/loader writes, repair other syscall
copyouts, or enforce permissions in the vCPU's hardware page tables.

This does not fix ELF overlapping-page contents. The loader still differs
from Linux for split file-backed overlapping pages, split pure-BSS pages,
and readonly partial file tails. The getter permission checks do not repair
those initial bytes; their tests do not establish ELF initial-content or
whole-program parity for those layouts.

## Typed syscall decoding

Every valid x86-64 syscall number is decoded through Reverie's complete typed
syscall table before it reaches the host handler; a number outside that table
is rejected instead of being forwarded as an untyped request. `install_syscalls`
builds a small guest program containing consecutive hypercalls, with one
page-aligned frame per request, so a single KVM run can route several syscalls.

## CPUID policy

Every vCPU receives an explicit CPUID table through `KVM_SET_CPUID2` before
its first `KVM_RUN`. The default `CpuidPolicy::deterministic` policy replaces
the host table with a fixed x86-64-v2 profile based on Detcore's CPUID table,
then removes `RDRAND`, `RDSEED`, TSX, AVX-512 feature bits, and the AVX-512
extended register state. This keeps standard and extended identity, feature,
cache, and topology leaves independent of the KVM host. VM creation fails if
the host lacks an instruction feature required by that baseline. Callers that
need KVM's full host-supported table can opt into
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

Zero-count scalar reads use the actual selected host descriptor, including
inherited stdin, duplicates, and descriptors rebound to fd 0. A zero count does
not guarantee that Linux returns immediately: an empty inotify descriptor can
wait for an event. Until the consumer scheduler can admit that operation safely,
the backend reports `PotentiallyBlockingZeroRead` before starting a host reader.
This ends the run with a named unsupported-operation error; it does not return
a successful zero or a made-up syscall errno. The consumer repair remains
tracked at https://github.com/rrnewton/hermit/issues/3498.

The admitted real endpoints are pipes, sockets, `/dev/null`, `/dev/zero`, positively
identified eventfd/timerfd/signalfd/epoll objects, and regular files/directories on
tmpfs, ext4, or btrfs. Synthetic proc/random/signalfd descriptions keep their
existing routing. Inotify and unknown endpoint/filesystem kinds are
refused even when `O_NONBLOCK` is currently set: another alias can change that
shared flag before injection. Native descriptor/address errors are preserved
within the admitted surface, including invalid-address reads on sockets and
inotify; an invalid address alone does not admit an unknown filesystem.

This is a deliberately reduced support boundary. It relies on the backend's
existing trusted host, procfs, metadata, and ordinary local-filesystem I/O
contract. In particular, zero-count reads on XFS or overlayfs files and terminal
stdin now end the run explicitly, where the previous paths attempted the host
read or answered zero. It is not a guarantee that every host metadata query or
local-file read is wait-free: tmpfs may fault or swap a folio, and btrfs direct I/O may
take an inode lock even for zero bytes. Lifecycle tests use an explicit
`cfg(test)` admission for one owned descriptor to exercise the real dispatcher's
lock release and reader retirement; they do not establish support for a refused
guest operation. The real guest tests instead require the named failure, no reader ever started, no fabricated
result, and completed teardown.

Non-leader `execve` and supported-form `execveat` (`AT_FDCWD`, flags `0`)
preserve safe preflight errors: `EFAULT` for invalid path/argv/envp pointers,
`ENOENT` for missing absolute executable paths, and `ENOEXEC` for malformed
images. Otherwise valid requests return `ENOSYS` without replacing shared
memory or tearing down siblings: promoting the caller to thread-group leader
and completing sibling teardown for worker exec are not implemented. Linux
supports that replacement; this remains a ptrace-versus-KVM capability gap,
not successful worker-exec parity.

This crate is not a complete Linux execution backend. It uses fixed-address
identity mappings and bounded thread/process execution paths; programs requiring
unsupported parent/child or sibling scheduling interleavings can stall. The
signal subset above does not provide arbitrary asynchronous producers, general
fault delivery, complete concurrent process scheduling or general hardware
page-permission enforcement. Explicit user-copy paths consult software mapping,
read/write and `PROT_NONE` metadata; privileged Tool/loader access is separate,
and not every existing copy path enforces all Linux permission/fault semantics.
The identity-mapped vCPU page tables remain permissive for direct guest accesses
except virtual page zero, whose 4-KiB leaf is nonpresent. That exception does not
enforce ELF/mprotect permissions on other pages or restrict privileged raw host
access to guest backing. Filesystem access forwards into the host namespace with bounded
memory copies and a guest-owned descriptor table; it does not isolate or
snapshot host filesystem changes. The current hypercall transport also reuses
standardized KVM hypercall 12 because it is the only hypercall KVM exposes to
userspace; that prototype ABI must be replaced before running a stock guest
kernel.

The deterministic guest procfs surface is currently limited to explicit
synthetic files, descriptor reopen aliases, and guest-owned descriptor link
targets. It does not yet enumerate procfs directories, so proc-inspection tools
that scan the process table remain unsupported.

The synthetic `/proc` directory uses a real proc-root descriptor only as a
kernel pathname anchor. Its enumeration remains empty, metadata is synthesized,
and relative opens still use the deterministic child allowlist. Receiving that
root through `SCM_RIGHTS` restores the same synthetic mapping by comparing its
directory type, procfs type, device/inode and descriptor mount identity against
a live opened `/proc` root. This requires `statx` to return `STATX_MNT_ID` (Linux
5.8 or newer); an unavailable identity is not guessed. Other real-procfs rights,
including nested directories, files and a different mount view, are refused
instead of exposing host proc content. Ordinary non-procfs rights are unchanged.
This does not repair transfer identity for synthetic regular-file memfds.

Mutations resolve their actual parent/target, so a relative `..` from the proc
root can reach an ordinary filesystem directory; mutations within procfs remain
refused. This does not expand the relative-open allowlist or provide a virtual
mount namespace. Procfs working directories and filesystem-stat results remain
unsupported: `fchdir` into the proc root and procfs `statfs`/`fstatfs` return
`EACCES`. The previous synthetic anchor could incorrectly make `fchdir` enter
host `/`; that is not preserved as a supported operation. Unlike Linux, this
backend also continues to reject `fchdir` on ordinary `O_PATH` descriptors with
`EBADF`. Ordinary readable-directory cwd operations remain supported.

The ELF loader supports one host interpreter and enough file-backed mapping for small dynamically linked programs. General libc coverage remains bounded by the explicit syscall personality; unsupported operations fail with `ENOSYS` rather than silently bypassing the tool.
