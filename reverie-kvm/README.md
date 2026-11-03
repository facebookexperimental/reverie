# reverie-kvm

Part of [Hermit](https://hermetic-infra.org) and
[Reverie](https://docs.rs/reverie-core). See the
[API documentation](https://docs.rs/reverie-kvm) for the backend interfaces and
[`hermit-run`](https://crates.io/crates/hermit-run) for the command-line interface
and platform requirements.

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
lifetime. An existing handler or `SIG_IGN` prevents entry. A changed handler is
detected at each thread's first entry (not at that thread's later entries). An
unexplained pending instance before an entry causes an error, and so does an
instance no closer sent that interrupts an entry's `KVM_RUN`, even one queued
alongside a closer's kick.
These checks detect visible conflicts; they do not coordinate ownership with
another signal user. Signal 64 is unblocked on a thread from its first vCPU
entry on, and `KVM_RUN` runs under the thread's own signal mask, or under the
preemption timer's vCPU signal mask, which leaves signal 64 as the thread has
it (see below): the entry signal needs no KVM signal mask of its own, and adds
no host syscall to an entry besides `KVM_RUN` (for the preemption timer's
per-entry cost, see below). While an entry is published on the thread, the
handler sets that vCPU's `kvm_run.immediate_exit` byte, so an instance that
arrives just before `KVM_RUN` still keeps the guest from running, and one that
arrives inside it ends it with `EINTR`. A foreign instance is
therefore not left pending: the handler takes it at once, which can interrupt a
host call the thread is making, and the thread's next entry refuses. Code that
blocks signal 64 again on a vCPU thread breaks prompt interruption; entries
re-check every 1,024 entries that it is still unblocked, and refuse if it is
not. Threads that such a thread creates, and host processes it spawns, inherit
its mask with signal 64 unblocked; exec resets the handler to the default
action. Neither this crate nor Hermit's Detcore spawns a host process from a
vCPU thread.

The backend's preemption timer reserves `SIGSTKFLT` (Reverie's
`PERF_EVENT_SIGNAL`) the same way, at the first timer a thread opens. It
installs a process-wide handler that does nothing, with `SA_RESTART`; refuses
if the signal already has a handler or is ignored; and checks the handler
again at each later timer it opens. Each timer is a sampling perf event that
counts what the thread's branch clock counts and sends `SIGSTKFLT` to the vCPU
thread when it overflows, which ends `KVM_RUN` with `EINTR`. Nothing is
decided from the signal: every decision reads the clock at the exit. Other
libraries must not use `SIGSTKFLT` in the embedding process. A thread that
never requests a timer opens no timer event.

`Guest::set_timer` requests an imprecise timer event under the Reverie
contract, as reverie-ptrace implements it except where
https://github.com/rrnewton/reverie/issues/1176 says. A thread has one request,
and a new one replaces it; `Rcbs(r)` and `RcbsAndInstructions(r, _)` request
`r` RCBs, `Time` is converted at reverie-ptrace's rate of 0.6 RCB per
nanosecond, and a request for 0 RCBs is refused with `EINVAL`. The event is
programmed at the target, with no skid margin. The next event of another kind
decides the request: before a Tool callback for a subscribed syscall, a signal,
CPUID or RDTSC, an exec (including the initial one) or the thread's exit, the
request is cancelled, so a request made inside that callback is a new one. A
syscall the Tool injects is not an event, and an exit with no Tool callback
leaves the request alone. Once an exit has found the clock at or past the
target, the backend calls `Tool::handle_timer_event` once, before the guest
runs on, and the clock read there is at least the target. At a kick that
stopped the guest in user mode, between two instructions, the callback sees the
live registers. At the exit of a syscall with no Tool callback (one the Tool
does not subscribe to, or one the backend owns), it runs once the syscall has
completed, at the syscall's return, and sees the user registers the guest
resumes with (for `rt_sigreturn`, the ones it restores), before any pending
signal is selected there; `orig_rax` reads -1 there, where reverie-ptrace
shows the syscall's number. So a guest that makes such syscalls faster than a
kick lands gets its event within a syscall of the target. A request found due
by a kick that stopped the guest in ring 0, in the syscall trampoline or in an
exception stub, is armed again at its target, and the exit that follows
decides it.

The callback may inject syscalls that return, and exits. Anything else, a
process action (fork, vfork, clone, clone3 or exec), a tail injection other
than an exit, a signal that needs a syscall return frame, or an
`rt_sigprocmask` that would make a pending signal deliverable, is refused
before it has any effect and ends the run with
`Error::TimerCallbackInjectionUnsupported`, so a Tool cannot take the refusal
for an ordinary failure of the syscall. The refusal stays the callback's
outcome: an injection the callback makes afterwards, having dropped the refused
one, never runs, and a later exit or retirement does not replace it. Its writes
to guest memory are not held back (see the limits below). An
`rt_sigprocmask` with invalid arguments still returns its `EINVAL` or `EFAULT`,
and one that makes no pending signal deliverable runs as usual.

After the callback, the pending signals are selected at the same point and
delivered. Linux's return to user mode after a preemption runs `schedule()`
before signal delivery, so the timer event comes first, then the signals;
Linux delivers every eligible signal on the same return, with stacked frames,
and so does this backend, as at its other boundaries
(https://github.com/rrnewton/reverie/issues/1188). Linux's `get_signal` takes
a group exit before every dequeue, so a thread whose group began to exit, or
that was cancelled, while its callback or a signal's hook there ran selects no
further signal there, also after a hook that suppressed its signal or returned
an ignored one, and ends before it runs another instruction; the signal whose
hook was running still gets its frame, which the thread never runs, and a Tool
that controls delivery a `Caught` receipt for it, where Linux requeues it
(https://github.com/rrnewton/reverie/issues/1208). At a user instruction
boundary the signal's frame holds the live registers and nothing restarts, as
after an interrupt, and the signal hook sees the timer event's complete
registers; at a syscall's return the selection is that syscall's own, with its
restart rules; at an `rt_sigreturn` it sees the registers and the mask the
call restores. A signal another thread sends while the callback runs counts,
so a thread that spins without syscalls takes a signal at its next timer
event. A boundary where KVM has yet to inject an exception defers the
selection to the first user boundary with no event left to inject: after a
fault's signal, whose frame the signal's then goes on top of, or after an
intercepted CPUID or RDTSC's callback.

`Guest::set_timer_precise` requests a precise timer event, delivered exactly
when the clock reaches its target, at the instruction boundary right after the
target branch; `RcbsAndInstructions` is refused with an `Unsupported` error.
The request is staged as reverie-ptrace stages one, and within the margin of
the target every entry runs under KVM's guest debugging: one user instruction
at a time (`KVM_GUESTDBG_SINGLESTEP`), so the step that retires the target
branch stops the guest exactly there in every run, or unstepped up to an
execution breakpoint (`KVM_GUESTDBG_USE_HW_BP`), or unstepped to an exit that
comes first. Nothing that saves or loads RFLAGS is stepped, so the guest never
sees the trap flag a step sets; inside the window IRETQ, MOV SS and a guest
that loads its own TF are refused by name, and `src/preemption_timer.rs` says
how each instruction runs. An exit that finds the target passed is late,
recorded with the skid overshoot marker, and delivered at the clock it
found, as reverie-ptrace delivers one. The backend's capabilities report
`delivers_preemption_timer_events`, so a Tool may rely on its timer events
within the limits below; a late precise event is always recorded, never
delivered as on time.

Only a Tool callback for another event cancels a request. A fork, clone or
vfork that the Tool does not subscribe to makes no callback on the parent, so
the parent's request survives it. reverie-ptrace differs from this rule in
three places (https://github.com/rrnewton/reverie/issues/1176): its new-child
and vfork-done stops cancel a request though they make no callback on the
parent; its report of a held signal (`report_signal`) makes a callback without
cancelling; and its ordinary injected exec reaches the post-exec callback
without cancelling.

A kick never interrupts a host call. The interrupt behind a kick can be held
past the exit it would have caused, so its signal can arrive while the vCPU
thread runs host code; there, even the empty handler would make LinuxEmu's
host sleeps and polls return `EINTR`, or a blocking host `read` or `write`
return a short count, to the guest, and on a PREEMPT_RT kernel this would be
routine. So the vCPU thread keeps `SIGSTKFLT` blocked in host code, and only
`KVM_RUN` runs with it unblocked, as in gVisor's KVM platform. Opening a timer
blocks the signal on the thread and sets the vCPU's signal mask
(`KVM_SET_SIGNAL_MASK`) to the thread's mask from before with only `SIGSTKFLT`
unblocked; Linux installs that mask for `KVM_RUN` and restores the thread's own
when it returns, so `KVM_RUN` runs under the thread's mask exactly, signal 64
and `SIGURG` included, except that a kick ends it. The kick is then left
pending, and the `EINTR` exit takes it with one `rt_sigtimedwait` with a zero
timeout. A kick that arrives in host code stays pending, ends the next
`KVM_RUN` at once, before the guest runs, and is taken there: one extra exit,
since the signal does not queue. When reverie-kvm changes the thread's `SIGURG`
state (as for an inline fork child), the vCPU's next counted entry composes the
mask again, and so does an `EINTR` exit that takes no kick. A signal blocked on
the thread since the mask was composed then costs one exit for each kick
pending with it, each of which takes its kick, plus at most one more exit,
which takes no kick and composes the mask again. The empty handler stays
installed: a kick on a thread that unblocked `SIGSTKFLT` again runs it rather
than the default action, which ends the process. A thread that never opens a
timer has no vCPU mask, and its entries issue exactly the syscalls they did
before. Once a timer is armed, an entry adds no host syscall while the target
is unchanged (pinned placement keeps its existing enable and disable of the
CPU-bound events). Opening the timer adds one `KVM_SET_SIGNAL_MASK` to its
event's setup, an `EINTR` exit adds the one `rt_sigtimedwait`, and composing
the mask again adds one `rt_sigprocmask` and one `KVM_SET_SIGNAL_MASK`. A due
request adds at most one `KVM_GET_SREGS`; delivering it at a kick adds one
`KVM_GET_REGS`, and arming it again at most one `PERF_EVENT_IOC_PERIOD`. A
pending signal delivered after it at a user instruction boundary adds one
`KVM_GET_VCPU_EVENTS` before the delivery's own register reads and writes.

The timer has these known limits. Nothing checks that the timer event is
resident on a counter; an uncounted vCPU on the same host task advances an
armed timer, which then kicks late;
nothing refuses PREEMPT_RT kernels or nested virtualization; the parent's
request survives an unsubscribed fork, clone or vfork, where
reverie-ptrace cancels it; and code that unblocks `SIGSTKFLT` on a vCPU thread
lets a late kick interrupt a host call again. A timer callback cannot make a
signal deliverable to its own thread, where reverie-ptrace delivers one that
the callback sends once it returns. After a refused injection, the
timer callback's own guest-memory and stack writes, through handles it already
holds, still reach memory until the callback returns or suspends; the run then
fails with the named reason. A precise event is late when the kick before its
stepping window comes past its target: on an EPYC 9D85, a two-thread spin
loop saw one or two late requests in a thousand, and staging the request
farther short of the target did not reduce them (`src/preemption_timer.rs`;
https://github.com/rrnewton/reverie/issues/1214).
Every other instruction in the window costs a step of its own, with no block
steps yet: in a release build about 3.3 microseconds under following
placement, and about 17 under pinned placement, whose every entry also pins
and restores the CPU and enables and disables the events (about 12 syscalls
per step, against 1). REPE and REPNE CMPS and SCAS, and REP LODS, are stepped
one iteration at a time until measured on Intel (a 256 KiB REPE CMPSB in the
window took 0.93 s). The refusals inside the window depend on when its kick
lands. A peer thread that rewrites the instruction at RIP between its decoding
and the entry that runs it can show the step's TF to a PUSHF (as Linux's
ptrace single step always does) or a SYSCALL, or make the event late; one
rewritten into a stepped POPF or IRETQ whose image sets TF has that TF dropped
when the steps stop, instead of refused by name. An on-time event is never
delivered at another point; a late one is delivered later, and recorded.
Stepping is not byte-stable for a Tool that does not serialize threads, which
sees the races of Linux's ptrace single step (see `src/preemption_timer.rs`).
While the vCPU mask stays installed, a signal that code outside reverie-kvm
unblocks on the vCPU thread does not end `KVM_RUN` until the mask is composed
again; the mask can outlive its timer
event, since a binding reopened on the same thread (on another CPU under pinned
placement, or with another raw encoding) while the request is idle or already
due opens no new timer event and keeps the mask composed before. The existing
`SIGURG` worker cancellation mechanism remains separate and unchanged.

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

`install_static_elf` accepts little-endian x86-64 `ET_EXEC` and `ET_DYN` images. It copies `PT_LOAD` segments, zeros BSS, loads one `PT_INTERP` image when present, creates a Linux-style `argc`/`argv`/`envp`/auxv stack, and installs an identity-mapped long-mode address space. It reads an image's ELF header and program headers only, and accepts a program-header table as Linux 6.17 and later do: 56-byte entries, at least one, at most 64 KiB (1170 entries). A main image's table must also fit the one page the loader copies it to for `AT_PHDR` (73 entries), a limit of this backend's own: Linux runs a main image with more, and an interpreter's table, which is not copied, is accepted up to 64 KiB. The vCPU starts at CPL3. `EFER.SCE`, `STAR`, `LSTAR`, and
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

`run_static_elf` supplies a deliberately small Linux personality. It handles process exit, host-backed filesystem descriptors, stdout/stderr writes, host clock reads and `getrandom`, FS/GS bases, `brk`, anonymous and file-backed `mmap`, and common startup no-ops. Unsupported syscalls return `ENOSYS`. The calls whose answers the Tool (Detcore) decides on every backend (the CPU, scheduling and priority calls, `membarrier`, `prlimit64`, the user and group id calls, `seccomp` and `getpgrp`) also return `ENOSYS`, with the typed refusal `UnsupportedOperation::ToolDecided`.

The host-backed filesystem layer includes descriptor duplication, file and
filesystem metadata, permission and timestamp updates, and bounded
create/link/rename/unlink operations. A virtual umask is applied to creation
modes before they are forwarded to the host. The executor retains signal
actions, masks, pending state and alternate-stack configuration and delivers
supported events at explicit execution boundaries, as described below.
`mincore` validates the range and the residency vector and writes no residency byte; residency is the Tool's decision.

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

A vfork child (`vfork(2)`, or `clone(2)` and `clone3(2)` with
`CLONE_VM|CLONE_VFORK`, as glibc's `posix_spawn(3)` issues it) shares its
parent's whole address space on Linux until it execs or exits, and the
parent's call returns only then. Here the child runs on a copy of its parent's
memory, with a VM and vCPU of its own, and the parent stays inside its call,
as reverie-ptrace's kernel keeps it, until the child's window ends: the child
starts while the call is pending, and registers with the tool before the call
returns. The copy inherits the parent's shared views of ordinary files and of
fork-shared anonymous memory, so a store through one reaches the parent and
the file at once, and it adds no vCPU to the parent's address space, so a
parent that holds such a view can create one. When the window ends, at the
child's successful exec or at its last exit (a death by a signal included),
the child's changes to private memory, its own stores and what the kernel
wrote for it (a `read(2)` into a parent buffer, for example), go back to the
parent before the parent's call returns: glibc's `posix_spawn(3)` child
reports a failed exec this way, through the parent's memory. What Linux's
`mm_release()` does for an mm another task still uses is the Linux
provider's, in this order: the child's `clear_child_tid` word (registered by
`set_tid_address(2)`) is cleared in the copy, the changes go back with that
store among them, one waiter on the parent's word is woken, and then the
parent's call returns. A failed exec keeps the registration for the child's
later exit. The parent's wait is killable, as Linux's is: another thread's
exec or exit of the whole group, or a run failure, ends it with no result,
and the child runs on, handed to the process as the waiting thread retires.
Its changes then go back to nothing if the parent exec'd, and nothing at all
goes back once the parent's process has committed its exit: the child is
then the only user of the address space, so neither its stores nor its
mapping changes are refused for the parent's sake, and its `clear_child_tid`
word is not stored, as Linux stores it only while another task uses the mm.
The decision reads the exit's commit, not whether the waiting thread has
noticed it yet, so a tool that orders the guest's tasks makes it the same in
every run. This holds for threads the tool runs.
A thread run without the tool (no tool at all, or host-owned threads) runs
its fork and vfork children inline, on its own host thread, so it cannot end
its call before the child ends: a child that waits for that thread's exec or
exit then waits forever, a limit of that personality.

The copy carries back contents, not mappings, so the child may change a
mapping only for a while. When the window ends, a mapping still changed (by
`mmap(2)`, `munmap(2)`, `mprotect(2)` or `mremap(2)`) is refused by name,
with the `VforkChildCapability` error for the operation `vfork write-back`,
before anything goes back: on Linux the change would be the parent's too.
Each new mapping has an incarnation of its own, so a page mapped again with
the protection it had is a change as well. A
mapping the child creates and removes again in between, as a tool's scratch
page for an injected call is, leaves nothing to refuse, and the stores to it
do not go back, as Linux discards them with it. A `brk(2)` that moves the
break is refused at the call, since the break is the parent's too even where
it moves within a page. Both apply to vfork children of processes that hold
no shared view as well, which used to change only their copy. A call that
would change an inherited shared view or map a new one is refused at the
call, as before. A vfork child may not create a thread (`clone(2)` or
`clone3(2)` with `CLONE_THREAD`) before it execs, a known limitation refused
by name at the call (`thread creation in a vfork child`): Linux ends the
window when the creating task execs or exits, whatever threads of the child
remain, and a copy cannot go back while another thread still changes it. A
multithreaded parent is not affected.

When the parent has another live thread, the copy keeps a baseline of itself
as the child started, and only the bytes the child changed go back, so the
other thread's stores during the window stay. A byte the child and such a
thread both changed to different values, and a page the child changed whose
mapping such a thread replaced (by any new mapping over it, whatever its
protection) or removed, are refused by name when the window ends: a copy
cannot order those stores. What remains different from Linux is
that during the window the child and the parent's other threads do not see
each other's stores to private memory: a child that reads memory another
thread of its parent changed during the window sees the value from before the
window, a thread that reads memory the child changed sees the value from
before the child's store, and a store that leaves a byte as it was cannot be
told from no store, so the child's change to that byte goes back over it.
Since only the end of the window is compared with its start, three cases are
documented limits rather than refusals: a byte changed and changed back
during the window (an ABA) reads as unchanged, a store of the baseline's
value reads as no store, and the same final value written independently by
the child and another thread merges silently (a counter that both
incremented once ends one short of Linux's value). The write-back compares
every page that holds data, so it costs time in proportion to the memory the
parent has touched, for each vfork-style child. While the changes go back, the parent's other threads run unless the tool
holds them. A tool that serializes the guest's threads, and runs none of them
from the child's exit or exec until the parent's call returns, has the
write-back see no concurrent store; without one, a store another thread makes
while the changes go back, to a byte the child changed, can be overwritten by
the child's value, although on Linux it would come after it. A thread, or a
`CLONE_VM` process clone without `CLONE_VFORK`, is still refused while the
process holds an ordinary shared-file view
(https://github.com/rrnewton/reverie/issues/1108).

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
stack state and the supported XSAVE image. At every delivery point the frame
holds the interrupted FPU state and the handler starts with Linux's initial
one, as `handle_signal` gives it with `fpu__clear_user_states`: x87 control
word 0x37f, an empty x87 stack, MXCSR 0x1f80, and zero XMM and YMM registers.
As on Linux, the frame marks x87 and SSE state present, so a handler's edits to
them take effect, and YMM state only once used; its MXCSR_MASK is the CPU's.
`rt_sigreturn` restores the frame as Linux does: it initializes the components
the frame's features leave out, takes MXCSR from the frame when they include
SSE, also when the frame's header leaves SSE state initial, and accepts any
MXCSR the CPU's mask allows, DAZ included, checking it only when they include
SSE or YMM; a frame without `FP_XSTATE_MAGIC2` is restored as legacy FXSAVE
state, and the software-reserved padding is ignored. The KVM signal codec uses
**832 bytes of XSAVE state** (512 legacy, 64 header, 256 YMM) and **836 bytes
including the trailing `FP_XSTATE_MAGIC2` in the signal frame**. These are not
the total signal frame size. Some other hand-built frames that Linux accepts
are refused (https://github.com/rrnewton/reverie/issues/1191); this is not full
native-frame byte equality or support for arbitrary extended CPU state.

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

By default, `PR_SET_PDEATHSIG` accepts zero and refuses valid nonzero signals
with `ENOSYS` before changing state. Nonzero delivery requires Tool-controlled
signals, explicit `ProcessSignalControl::enable_parent_death_control` adoption,
and native terminal cleanup configured through `KvmBackend::set_native_exit_broker`.
That configuration supports standard signals except `SIGKILL`, `SIGCONT` and
stop signals; realtime signals remain unsupported. Enrollment requires a single
live recipient task and retains a restricted syscall/wait domain until process
retirement, even after SET(0). This is not general blocked-I/O or direct-mode
support. `PR_GET_PDEATHSIG` returns the task's stored signal as four bytes,
initially zero; an out-of-range full-width SET operand returns `EINVAL`.

The early native broker refuses unproved ambient filesystem classes before
querying inode attributes: Linux can flush NFS or 9p data during `fstat`, and
9p can do so even for a type-only `statx` with `DONT_SYNC`. Mount identity comes
from the kernel's procfs records, not a server-reported `statfs` magic. Local
ext2/3/4, btrfs, tmpfs, devtmpfs and devpts retain the audited descriptor classes;
`O_PATH`, sockets and pipes use separate paths, and kernel-identified shmem
(including internal memfd mounts) remains supported. Character-device nodes on
other filesystems and detached or hidden mounts absent from mountinfo are
explicitly refused. This does not promise nonblocking arbitrary device metadata
hooks or unconditional bootstrap progress.

The NAME and PDEATHSIG getters check guest writable-page state:
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

## CPUID

The backend keeps no CPUID profile of its own. A Tool that subscribes to
CPUID answers every guest CPUID: the vCPU's CPL3 CPUID faulting is enabled,
and each fault goes to `Tool::handle_cpuid_event` (under Hermit, Detcore's
machine description, the table its `/proc/cpuinfo` is rendered from).

For a Tool that does not subscribe, the guest reads the vCPU's table, which
`KVM_SET_CPUID2` installs before the first `KVM_RUN`: KVM's host-supported
leaves with the host's own registers, so the guest reads what the same
program reads natively. Two exceptions: KVM's hypervisor leaves stay KVM's,
and leaf 0xd advertises only the x87, SSE and YMM components the backend's
signal frames carry, because KVM sizes the guest's XSAVE state from it. KVM
still computes the fields that describe the vCPU itself, such as OSXSAVE and
the XSAVE sizes.

The KVM integration tests execute CPUID inside the VM and compare the
registers with the host's.

## Relationship to gVisor

gVisor routes Linux filesystem syscalls through its Sentry VFS and the filesystem implementations under `pkg/sentry/fsimpl/`. Those layers own mount-namespace traversal, dentries, file descriptions, metadata, and directory iteration without exposing host descriptors directly. The closest syscall-facing paths are `pkg/sentry/syscalls/linux/sys_file.go` and `sys_getdents.go`.

This backend follows the same separation between the architecture transport and syscall policy: the KVM exit path only carries a Linux register frame, while the executor owns guest descriptor allocation, path resolution, and ABI marshalling. The implementation is intentionally much smaller than gVisor: each opened filesystem descriptor owns a host `File`, relative paths resolve against the captured working directory or an owned directory descriptor, and subscribed calls pass through Detcore, whose tail injection invokes this executor before Detcore post-processes returned metadata; unsubscribed calls invoke the executor directly.

No gVisor code is copied. Unlike the gVisor Sentry VFS and `pkg/sentry/fsimpl/` stack, this crate does not provide a virtual mount namespace, dentry cache, or filesystem implementation. Hermit container setup remains the isolation boundary, not this standalone crate, and a changing host-backed filesystem remains outside the determinism guarantee. Host procfs descriptors are rejected because they would identify the Hermit supervisor rather than a separate guest process.

## Host address space

Each guest process owns a guest memory of the `memory_size` the embedder
gives `KvmBackend::new`: one `MAP_SHARED | MAP_NORESERVE` host mapping of a
memfd. Host memory backs only the pages a guest touches, but the whole size
is reserved host address space, and `RLIMIT_AS` counts every reserved byte.
The backend reserves `memory_size`:

- for each live guest process, since a fork copies the parent's memory into
  a new mapping of the same size;
- once more while an exec validates its new image in a scratch memory before
  it replaces the old image;
- for an exited child until its host thread releases the mapping, which it
  does after the exit is published, so the parent can already be forking or
  execing again.

The peak therefore grows with the guest's process tree, and the order in
which host threads run moves it: a shell running a two-command pipeline
reserves four guest memories at its peak (the shell, both commands and one
exec's validation memory), and an exited earlier command can briefly add a
fifth.

Every guest process of the backend lives in its one host process, so these
reservations are that process's own, and so are the memory it allocates for
the guests and the descriptors it opens for them: an exec, for one, reads its
new image into a buffer as large as the file, and the loader keeps a copy of
every image it loads (an exec of `/proc/self/exe` loads it again).

Run the backend with an unlimited `RLIMIT_AS`, and bound its memory with a
cgroup (`memory.max`) instead. `memory.max` charges the memory a run uses:
the pages guests touch, the backend's own heap, page cache and kernel memory
such as KVM's, but not address space that is only reserved. A run that
reaches it is stopped by the kernel's OOM killer wherever it then is, not
refused by name, so size the bound for the workload.

Under a finite `RLIMIT_AS`, or one lowered while the run goes on, a run fails
at the first reservation or allocation that does not fit, at a point the
process tree and host thread scheduling decide:

- an exec whose validation memory the host refuses, whose image (or its copy
  of `/proc/self/exe`, or the loader's copy) this process cannot allocate, or
  whose program interpreter it cannot open or read for want of a descriptor
  or memory, is answered `ENOMEM` with the typed refusal
  `UnsupportedOperation::HostResources`. Its diagnostic names what ran out,
  the request or the step, and the limit: `RLIMIT_AS`, or `RLIMIT_NOFILE`
  for descriptors. The exec runs none of the new image. A Tool that ends the
  run on the refusal keeps the guest from ever seeing the `ENOMEM`; no exec
  `ENOMEM` is one Linux would give for the guest's own reasons. ENFILE, the
  host's whole file table being full, is one Linux could give an exec; the
  backend refuses it by name too, since it says nothing about the guest;
- an exec that runs out of a host resource past its point of no return, with
  the old image discarded and the new one loading into the live memory,
  ends the run with the named refusal `Error::HostResources`, which carries
  the resource (`HostResource`); the guest sees no errno. That covers the
  loader's fallible allocations, its host calls, and the KVM ioctls that set
  up the new image (`KVM_GET_SREGS`, for one, allocates and can fail with
  ENOMEM). The reload loads the image the preflight read, but it opens the
  program interpreter and the working directory again by path. If either
  changed since the preflight, the reload can fail where the preflight did
  not, which ends the run as a backend failure rather than this refusal, or
  it can load an interpreter the preflight did not check;
- a fork whose child memory the host refuses ends the run with
  `Error::MemoryMapping`;
- the rest of what an exec allocates is bounded, and not fallible: buffers
  of a fixed size; the path (at most 4 KiB); `argv` and `envp` (each at most
  4096 entries and 128 KiB in all); what a `#!` line adds to `argv` (Linux
  reads only the line's first 256 bytes and passes at most one optional
  argument, so each level replaces `argv[0]` with at most two entries made
  from at most 253 bytes of the line each, and the script's path, at each of
  at most four levels); the PT_INTERP path (at most 4 KiB, as Linux bounds
  it); the program-header table (at most 64 KiB, as Linux bounds it since
  6.17; see "ELF execution" for the main image's one-page limit); and the
  initial stack built from these. The loader reads no section header and
  no string table, as Linux's ELF loader does not. When one of these bounded
  allocations fails, the process is out of memory everywhere, and it aborts.

An embedder that needs the same outcome on every run should refuse to start
under a finite `RLIMIT_AS`.

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

`/proc` itself is not served: an open of it, by any spelling, fails with
`EACCES` as an open of any procfs object does, so the backend keeps no procfs
directory descriptor of its own for the guest. A real-procfs right received
through `SCM_RIGHTS` is refused the same way, `/proc` included; ordinary
non-procfs rights are unchanged. This does not repair transfer identity for
synthetic regular-file memfds. Mutations within procfs remain refused, and so
do procfs working directories and filesystem-stat results: `chdir` or `fchdir`
into procfs and procfs `statfs`/`fstatfs` return `EACCES`. Unlike Linux, this
backend also continues to reject `fchdir` on ordinary `O_PATH` descriptors with
`EBADF`. Ordinary readable-directory cwd operations remain supported.

`Guest::descriptor_status` answers from the executor's descriptor table: for a
guest descriptor backed by a host descriptor of the same open file description,
it reports what the host kernel's `fdinfo` shows for that description (an
eventfd's count, a Unix socket's queued `SCM_RIGHTS` descriptors, its locks). It
reads that `fdinfo` while the table is locked and never duplicates or closes a
descriptor of the guest's file, so a query releases no POSIX lock held by the
process the Tool runs in. Two answers differ from Linux. A guest's `F_SETLK` or
`F_SETLKW` record lock is held as an open file description lock on the host, so
it is reported with class `OpenFileDescription` where Linux reports `Posix`. It
also behaves as an open file description lock. Every process that holds a
descriptor of its description, such as a forked child or a receiver through
`SCM_RIGHTS`, shares it: the lock is reported for that descriptor, and an
`F_SETLK` through it changes or releases the lock, where Linux lists a `POSIX`
lock only through its owner's descriptor table and lets only its owner change
it. And it outlives a close that releases a `POSIX` lock on Linux, any close of
the file by the owning process, until the description's last descriptor is
closed. The guest's own `flock(2)` is refused, so a flock lock is reported only
for a description the guest received already locked, such as an inherited
standard input. Objects the executor keeps itself are not provided, however the
guest holds them, including through `SCM_RIGHTS`: signalfds, the executor's own
memfds (such as synthetic `/proc` files), and with captured output the
supervisor's standard output and error. The memfds are recognized by their
reserved names and captured output by device and inode, so a guest memfd given a
reserved name, or a guest's own descriptor of the file the supervisor's output
goes to, is not provided either.

`Guest::signal_sets` answers from the executor's own signal state, for any live
thread of the run, in any of its processes: the thread's pending queue, its
process's shared queue, the thread's mask (a temporary mask while one is
installed), and its process's ignored and caught signals, as Linux shows them in
`/proc/<pid>/task/<tid>/status`. A thread ID that names no live thread of the
run (an exited thread, reaped or not, or a number no task has) is `ESRCH`, and
so is a thread caught between the steps of its process's fork; across an exec
the answer is the process before it or after it, never `ESRCH`. Two differences
from Linux follow from the executor's limits. Because it refuses real-time
signals, no real-time signal is ever pending. And because it keeps no waiting
state (it answers `rt_sigtimedwait` and a masked `ppoll` or `pselect6` at once,
and refuses an `rt_sigsuspend` that would wait), a thread waiting in one of
those calls shows its own mask, where Linux shows the call's mask, or for
`rt_sigtimedwait` the thread's mask without the signals it waits for.

`Guest::link_path` answers with the name Linux's `readlink(2)` gives a thread's
`fd/<fd>`, `exe` or `cwd` link, from the executor's own state: for a guest
descriptor backed by a host descriptor of the same open file description, the
host kernel's name for that description (a file's path, with ` (deleted)` once
it is unlinked, or an object's name such as `pipe:[<inode>]`), read while the
descriptor table is locked and without opening or closing anything of the file;
and the names of the executor's own handles of the process's image and the
thread's working directory, walked at the call. Captured standard output and
error, and descriptors the guest made of them, are named as the pipes their
`fstat` describes, and a signalfd as `anon_inode:[signalfd]`. Objects the
executor keeps itself are not provided, judged as for `Guest::descriptor_status`:
the executor's own memfds (such as synthetic `/proc` files, where Linux names
the `/proc` file), and with captured output the supervisor's standard output
and error however the guest holds them. A closed descriptor is `EBADF`, and a
thread ID that names no live thread of the run is `ESRCH`. The executor keeps a
process's descriptor table, image and each thread's working directory in that
process's own executors, so the fact answers for the asking thread's process
only: the descriptor table and the image for any live thread of it, and the
working directory for the asking thread alone, since the executor keeps one per
thread where Linux shares it between threads created with `CLONE_FS`. A live
thread of another process, and another thread's working directory, are not
provided, where Linux shows them to a reader it lets read them.

`Guest::memory_map` lists only what the executor can establish exactly, and
says that the list is not complete (`MemoryMap::complete` is false). Each
listed entry is exact for the executor's own address space, which differs from
a native process's where this section says so. The guest memory keeps the
address space as pages: what each was reserved for, whether it is accessible
and writable, and the mapping the executor declared for it, which it stores and
copies without deciding anything from it: the protection the guest asked for
(`mmap(2)`, `mprotect(2)`, `brk(2)` and the loader's stack), the mapping flags
of the madvise hints the executor accepts (`MADV_NORMAL`, `MADV_RANDOM`,
`MADV_SEQUENTIAL`, `MADV_HUGEPAGE`, `MADV_NOHUGEPAGE`, `MADV_MERGEABLE`,
`MADV_UNMERGEABLE`), and a lineage. The executor decides from those pages
which mappings Linux would keep. That holds no file identity and none of the
history that decides where Linux splits and merges most mappings
(https://github.com/rrnewton/reverie/issues/1211), but it does for the stack
window: the loader maps it whole as one mapping, no other mapping can be
placed in it, and its pages split and merge only as the guest changes their
protection, mapping and flags. So the list holds the window's mappings, each a
run of adjacent mapped pages with the same protection, flags and lineage, as
Linux splits the stack: a run that holds the initial stack pointer, counting
one that ends or starts at it, is `[stack]` (two runs are when the pointer is
page aligned and a split falls on it, as Linux prints them), the others have
no name, and the lowest starts at the window's start (the loader maps it
whole, 8 MiB less its top page, where Linux maps the stack's arguments and
128 KiB below them and grows the stack on demand). The stack is read-write,
and executable for an image whose last `PT_GNU_STACK` header has `PF_X`, as
Linux maps it; private, with no file. A forked child keeps apart the mappings
it inherited, as Linux does, where each has an `anon_vma` of its own: the
executor gives each run of a forked child's window a lineage of its own, so a
part its parent's split left stays a mapping of its own in the child even once
set back. The whole list is empty when one page of the window has a mapping
that is not known (declared by no call, or reserved for another use, which no
path makes today), and once something changed that the pages do not hold: an
`mprotect(2)` range the executor refuses whole where Linux protects the
mappings before a hole and then fails with `ENOMEM`; or, for a vfork child
(`vfork(2)`, or `clone(2)` and `clone3(2)` with `CLONE_VM|CLONE_VFORK`), which
runs on a copy of its parent's memory and shares a record with it as on Linux
they share the address space, a change the other made, which this copy lacks.
A new image, such as a `posix_spawn(3)` child's, starts it again and leaves its
parent's list. A call the executor refuses where Linux applies it (`mlock(2)`
and `mlock2(2)`, madvise with `MADV_DONTFORK`, `MADV_DONTDUMP` or
`MADV_WIPEONFORK`, `mseal(2)`, `mbind(2)` and
`prctl(PR_SET_VMA)`, `ENOSYS`; `mprotect(2)` with `PROT_GROWSDOWN`,
`mremap(2)` with `MREMAP_DONTUNMAP`, and a same-size `mremap(2)`
move of a range with a hole after its start, which Linux moves, keeping the
hole, `EINVAL`; a `MAP_FIXED` mapping or an `mremap(2)` destination in the
window, `ENOMEM` and `EINVAL`; a `munmap(2)` that crosses the window's start,
`EINVAL`) leaves the window as it was where Linux shows it changed: the list
is exact for the executor's address space, which the call left as it was, and
the refusal is the difference the guest sees. So is a call the executor
applies where Linux refuses it: one on a page of the window below the part
Linux has mapped for the stack, where Linux answers `ENOMEM` (or, for
`munmap(2)`, changes nothing), and an `mremap(2)` that grows a range over two
of the window's mappings, where Linux answers `EFAULT`. A same-size move of
such a range moves every mapping in it, here as on Linux.

glibc's `pthread_getattr_np` takes the main thread's stack size from the
stack's soft rlimit less the part of the `[stack]` line above the page that
holds `__libc_stack_end` (the arguments and environment), in unsigned
arithmetic, and no more than reaches the end of the line before `[stack]`.
Where the list has a line of the window below `[stack]`, that line is Linux's,
and so is the answer at any limit. Where it has none, a reader of the list
finds no line before `[stack]`, where Linux has the mappings below the stack
(about 128 MiB below its top, without address randomization), and Linux's
stack ends there. The answer from the list is then Linux's only while the
limit is at least that argument area and at most that plus the distance to
the mapping below. Outside that, three cases differ, each measured with a
32 KiB argument, where Linux's size is 0x7ff8000 bytes:
- a larger finite limit gives the limit less the argument area, larger than
  Linux's but finite (0xfff8000 at 256 MiB);
- a limit below the argument area, which the subtraction wraps, gives a stack
  that reaches down to address 0 (0x7fffffff7000 at 4 KiB);
- no limit (`RLIM_INFINITY`), or one beyond the stack's top, does too
  (0x7fffffff7000).
Where a Tool lets a guest raise its stack limit, `ulimit -s unlimited` reaches
the third case. A tool that renders the list as `/proc/<pid>/maps` must name the
omitted mappings as a difference of this backend. The guest's page tables map
every user page without the no-execute bit, so a guest can execute on a stack
that Linux maps non-executable. The fact answers for any live thread of the
asking thread's process, whose address space they share, and a live thread of
another process is not provided, where Linux shows its map to a reader it lets
read it.

A Tool can reserve one empty host directory on a read-only file system for its
own use (`KvmBackend::reserve_tool_directory`): the executor hides it from the
guest, answering `ENOENT` for every route to it but an `O_DIRECTORY` open or a
`newfstatat` of its exact path, and a Tool that keeps that path from the guest
can use a descriptor opened there to stand for a directory it serves itself.
The contract, including the answers that are not `ENOENT` and the routes it
does not cover (https://github.com/rrnewton/reverie/issues/1171), is written
once, in the documentation of `KvmBackend::reserve_tool_directory` in
`src/vm.rs`.

The ELF loader supports one host interpreter and enough file-backed mapping for small dynamically linked programs. General libc coverage remains bounded by the explicit syscall personality; unsupported operations fail with `ENOSYS` rather than silently bypassing the tool.
