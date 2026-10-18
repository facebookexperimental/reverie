# Stage 1a exec-stop mechanics prototype

`reverie-loader-stage1a-probe` is an opt-in Linux x86-64 mechanics prototype,
compiled with the `stage1a-probe` Cargo feature. It maps independently checked
Rust loader and test-runtime images before releasing the kernel-created guest
entry. It does not initialize Detcore, select or activate a Hermit backend, or
replace the guest's dynamic linker or libc.

This stage is limited to the test runtime's own fresh reservation. The named
production prerequisite below belongs to the later real Detcore integration;
it is deliberately outside this mechanics prototype.
The executable is in `src/bin/stage1a_probe/`; its separate minimal images and
shared protocol are in `tests/fixtures/probe_*`.

## Entry and release sequence

1. The parent reads bounded image inputs into sealing-capable memfds, seals
   writes and resizing, and validates the bytes read from those descriptors.
   Validation checks the fixed ELF layout, permitted segments and permissions,
   image windows, executable gate pages, and stray `syscall` encodings. The
   probe disallows TLS in both images. Mapping uses these same sealed
   descriptors; it does not reopen the input paths after validation.
2. The launcher creates one child with `clone3(CLONE_PIDFD)`. Before guest exec,
   the child uses the prepared raw-syscall path, sets a parent-death signal,
   checks its parent, sets `NO_NEW_PRIVS`, calls `PTRACE_TRACEME`, and stops.
   The parent installs `PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC |
   PTRACE_O_TRACESYSGOOD` **before the first resume**. The retained pidfd owns
   cleanup until safeptrace assumes the child generation.
3. The first resume reaches the kernel's exec event. The parent verifies the
   event and original `execve`, then uses `PTRACE_SYSCALL` to drain only the
   exec syscall's kernel return. It requires a typed x86-64 syscall-exit
   observation with successful result zero, unchanged entry IP/SP, and matching
   register/syscall-info IP/SP. There is no `PTRACE_SINGLESTEP` and no original
   guest instruction is executed to obtain this stop. Unexpected observations
   are refusals, not permission to run forward until a convenient stop.
4. At the drained stop, the parent saves the original register image, xstate,
   signal mask, and complete selected initial stack VMA. It rejects an absent,
   ambiguous or oversized stack and an initially blocked SIGSYS or SIGSEGV.
   While it holds the child stopped, it temporarily patches the entry with a
   syscall/INT3 injection stub. These mapping calls are **injected tool calls**,
   recorded separately from guest execution. The original entry bytes and
   register image are restored after injection.
5. The first mapping is a fresh `PROT_NONE`, anonymous, private
   `MAP_FIXED_NOREPLACE` reservation of the **whole 4 GiB** range
   `artifact::TOOL_REGION` (`0x6000_0000_0000..0x6001_0000_0000`). Only that
   successful reservation authorizes subsequent fixed mappings inside it.
   An existing guest mapping is not overwritten; an actual `EEXIST` is named
   `tool_region_collision`. The parent maps the validated image segments,
   control/journal storage, private Tool stack and alternate stack inside this
   owned reservation, preserving W^X and leaving unused pages inaccessible.
6. The parent enters the Rust loader on the private Tool stack. The minimal
   runtime closes and checks the child bootstrap descriptors, installs an
   alternate stack and SIGSYS/SIGSEGV handlers, enables and reads back CPUID
   faulting and TSC trapping, and installs its seccomp TRAP filter. Only audited
   tool gates bypass the syscall trap; the loader's deliberate `gettid` probe
   is trapped even though it originates in its gate. This is one-child
   installation, not proof of coverage across guest threads.
7. Readiness requires **real interception self-tests**: faulting CPUID, RDTSC
   and RDTSCP instructions with the expected replies, followed by the loader's
   trapped `gettid` entry and return. The parent retains the bootstrap syscall
   trace and requires entries at an actual `0f 05` instruction inside an audited
   gate. Normal syscall exits preserve their entry IP/SP; a signal-return exit
   must return within owned executable Tool code. Bootstrap process/thread
   creation, exec and unsupported per-thread libc-state changes are refused.
8. The loader stops at its READY INT3. The parent checks the exact stop IP and
   magic register value, the complete required control bits, error-free
   `TestControlsReady` phase, echoed nonce, committed self-test events, and
   absence of guest events. It independently checks that the child bootstrap
   descriptors are closed and the saved guest stack is byte-identical.
9. The parent restores the exact saved register image, including entry IP/SP,
   FS/GS bases, xstate and original signal mask, and reads them back for equality.
   It then detaches at the original kernel entry. The kernel-selected static
   entry or interpreter begins with the test controls already installed.
   The prototype reports the eventual child status and committed observations.

`TestControlsReady` is deliberately **not `DetcoreReady`**. A synthetic reply,
a connected channel, a control-bit claim, or a successful guest exit alone does
not establish the release preconditions. `pre_arm_guest_syscalls = 0` is emitted
only after the validated handoff path. Its evidence is the exec-exit boundary,
separate injection trace, bootstrap gate checks, self-tests and restored entry;
it does not mean that bootstrap performed zero syscalls or measure an
instruction count.

## Test runtime domain and refusals

This runtime is a separate `no_std` Rust fixture with no guest libc dependency,
TLS initialization, Detcore registration, scheduler grant, AT_RANDOM handoff,
or vDSO rewrite. It records trapped syscall entry/return events and generally
forwards supported calls to host Linux through its gate. CPUID at the saved
first entry and the self-test leaf uses the fixture reply; other CPUID requests
can use host CPUID under its guarded test-only forwarding path. TSC replies are
fixture values. These choices are not a deterministic product implementation.

The runtime records a named refusal event and returns `-EOPNOTSUPP` for:

- `clone`, `clone3`, `fork` and `vfork` (`test_domain_clone`);
- `execve` and `execveat` (`test_domain_exec`);
- changes to the reserved SIGSYS/SIGSEGV handlers or alternate stack, guest
  `rt_sigreturn` or seccomp installation, CPUID/TSC control changes, and mapping
  operations that would alter the reserved Tool region
  (`test_domain_guest_control`).

The saved guest signal mask is handled through the signal frame; requests that
would block the reserved signals are recorded and refused. This is a narrow
fixture policy, not a complete implementation of Linux signal semantics.
Refusal does not itself force immediate termination: the guest can observe the
error and choose its exit path. The report can therefore retain
`outcome = handoff` together with a later test-domain refusal. A direct clone3
attempt and a real `std::thread::spawn` attempt are distinct test rows; Rust
startup or thread setup may encounter an earlier reserved-control refusal.
Neither row demonstrates successful multithreading. Unsupported instruction
faults, bad provenance, reentrancy, journal overflow and bootstrap/control
failures follow fatal refusal paths rather than a fallback into guest entry.

The optional `--inject-cpuid-arm-enosys` control substitutes an invalid syscall
number for the actual bootstrap CPUID-arm call and requires the real typed
ENOSYS result. It tests fail-closed handling, not hardware CPUID denial. The
mutually exclusive `--pause-after-exec-drain CHECKPOINT` control holds the child
at the drained entry for a bounded tracer-death observation, after proving
PDEATHSIG is cleared and restoring/read-checking the complete original context,
including opaque XSTATE after the injected kernel/user transitions. It never reports
runtime readiness or detaches. Cleanup evidence distinguishes a kill request
from confirmed terminal waiting on the retained child generation.

## Test execution and evidence

The CLI shape is:

```text
reverie-loader-stage1a-probe [CONTROL] LOADER RUNTIME REPORT -- PROGRAM [ARGS...]
```

The `exec_stop` integration tests require the `stage1a-probe` feature. They
compile real fixture ELFs with the pinned Rust toolchain and system linker,
validate the linked image bytes, and retain unique mode-0700 scratch directories
under an explicitly supplied, existing **bounded `TMPDIR`**, on success and
failure. Static images use `no_std`, fixed linker scripts, static relocation,
large code model, no red zone and no C startup. Dynamic guest rows retain the
kernel-selected interpreter and guest libc.

Run these tests only through an outer recipe that bounds CPU, wall time,
memory, PIDs and disk, with serialized use of the selected build target.
Internal subprocess deadlines do not replace outer containment. Retain the
actual compiler/test executable identities, feature selection, source and lock
bindings, command/status/stdout/stderr, JSON report, journal and any failure.
Use actual listing and complete test summaries to establish executed counts;
selected names and source assertions alone establish no passing count.

## Deferred production prerequisite and limits

Before design **commit 3** can activate real Detcore, production ToolRegion
integration must permanently reserve **both image windows and their guard
pages** in its page bitmap; authenticate adoption of the loader-owned
reservation without replacing live mappings or attempting a second whole-region
reservation; and qualify the changed allocator's actual machine code and source
closure with **M1**. Tests must show stack/arena leases cannot overlap the images
and wrong or partial reservations are refused. The named prerequisite is **production ToolRegion image reservation and
adoption**. The prototype calls no production ToolRegion allocator, so its
fresh reservation does not satisfy it.

This document describes source behavior and required evidence, not a test-pass
receipt. The prototype establishes no successful multithread or successor-exec
support, vDSO coverage, Detcore/scheduler readiness, deterministic run or replay,
cross-backend parity, startup performance, production backend activation, or
hostile-guest security boundary. Its cooperative fixtures must not overwrite
Tool storage or jump into raw gates. Product integration and the design's
remaining acceptance matrix require their own exact-revision evidence.
