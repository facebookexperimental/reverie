# Terminal disposal of inherited stdin zero-byte reads

The inherited stdin path can make a blocking host `read(fd, staging, 0)`.
SIGURG interrupts a read already in the kernel, but a terminal signal sent
before that read enters the kernel does not prevent it from blocking afterward.
A guest group exit can consequently hang while joining the Rust worker.

The repair covers that existing inherited-fd0/count-zero invocation only.
Descriptor routing, access and guest-range checks still run in their original
order. The helper receives the original host descriptor and the empty Vec's
actual staging pointer, not the numeric guest pointer. Ordinary descriptors
keep the existing zero-count handling; nonzero host reads are unchanged.

## Native lifetime

Each invocation owns one joinable pthread whose entry, cleanup handler and
cancellation frames are C. The Rust worker remains synchronous and is never
the target of `pthread_cancel`. The helper establishes public deferred
cancellation, calls public `read`, then disables cancellation before publishing
its return count and saved errno. Its cancellation cleanup publishes Canceled,
which means unknown kernel progress. It is neither an errno nor a promise that
the endpoint was untouched.

The Rust group registry serializes operation registration with sticky group or
worker cancellation. Each operation carries a monotonically increasing ID,
image and guest task identity, original request, and actual host arguments.
The existing owned stdin File moves into the operation; no duplicate descriptor
or endpoint flag mutation is needed.

Cancellation before creation/publication latches. Publication accounts for a
child that already completed. A sender is admitted only while the handle is
callable and the outcome remains Pending. Its lease lasts through the actual
public `pthread_cancel` return. After outcome publication, the sole Rust owner
disarms admission, drains admitted senders, and calls exactly one `pthread_join`
outside registry and operation locks. Only successful join (or proof that no
thread was created) permits endpoint restoration and operation removal.
Late wakers retain the allocation through Arc ownership and cannot cancel it.

Create, cancel, join and synchronization failures are backend control errors,
never guest results. A failed cancel with a pending read is reported without
waiting for unrelated endpoint activity. An unjoined helper keeps its original
endpoint and C allocation in registry ownership; if the group is destroyed,
process-lifetime retained ownership takes over. There is no detach, retry,
rollback, fallback read or fabricated successful retirement. An uninterruptible
kernel driver can still prevent physical teardown from completing.

## Terminal observation and guest disposition

The original worker waits on a C condition/epoch. It polls only existing entry
failure and Tool terminal observers; an ordinary wake does not establish a
terminal cause. Fork-local driver failures retain their existing scope, while
the traced root also observes run-wide failure.

The Tool observer facade keeps the actual user future allocated even after a
terminal notification or poll panic. It catches polling inside an always-pending
driver, then reports selection outside that driver stack. User destruction runs
after local helper retirement or explicit retained-ownership failure. Poll and
destructor panics have separate catches and retain their original payloads and
typed control errors through the backend's existing panic owner.

An exact TerminalReadCancelled disposition is consumed before Direct result
writeback, Tool injection continuation, or backend-owned Tool result handling.
These paths reuse the existing thread/group terminal protocols. Errors carrying
cleanup remain real failures. The merged worker clear_child_tid-before-terminal
receipt ordering is unchanged. Cancellation of C helpers precedes blocked Rust
worker joins; exec rearm refuses any still-owned old-image helper.

Direct execution errors collect worker teardown before returning from the public
run method, while the executor and capture owner remain alive. Inline Direct
child errors collect that child's teardown before its backend is dropped; Tool
children keep their existing deferred cleanup path. The original error remains
primary and reader-control failures are appended. Destructor-only abandonment
retains failed registry state, including its typed causes and unjoined operation
ownership, for process lifetime; it cannot return a new error to an absent caller.

## Focused controls and limits

`tests/terminal_read_protocol.c` uses test-only C gates around creation,
publication, read entry/return, send admission/return, disarm and join. It covers
normal completion, actual inotify blocking, queued-event errno, descriptor reuse
and retained create/cancel/join-error ownership. Compile the C implementation and
test together with `-DRVK_READ_TEST -std=c11 -pthread -fexceptions`; production
builds omit the gates. The delayed-sender controls stop immediately before the
public cancel call and immediately after its return, not inside libc assembly.

The fifteenth control holds the helper before cancellation is enabled and
independently queries both live tasks' `attr/current`, checking each TID and
start generation through collection. It records the exact open/read/close
results, failure errnos and bytes. It also reads the active LSM inventory at
`/sys/kernel/security/lsm` before and after the task queries. Missing,
unreadable, truncated, malformed or changing inventories fail before either
attribute-result branch is considered.

The only inventory that authorizes an unavailable-label result is exactly
`capability,bpf,ima` (18 bytes, without a newline). Its source-grounded error
interpretation accepts only two actual
initial reads returning `-1/EINVAL`, each after a successful open and followed
by successful close. The result is **unavailable-label**, not equal labels or
equivalent security policy. The retained kernel hook evidence supports this
specific rule; kernel release, build and configuration are provenance, not
fixed acceptance keys. The two retained BPF inspection attempts failed with
EPERM: attachments remain unknown, and BPF absence is not claimed. The provider
finding's prose mentions a newline, but the retained 18-byte file is authoritative.

The separate successful-observation rule requires each task's first read at
offset zero to return one nonempty value of L bytes, with 0 < L < 4095, followed
by exactly one EOF read at offset L. Open and close must succeed. Both values
must have identical lengths and all bytes, including embedded NUL suffixes.
Valid, stable provider inventory is required, but its spelling does not restrict
this success branch. Linux `proc_pid_attr_read` exposes the selected
`security_getprocattr` result through `simple_read_from_buffer`. Every read
regenerates the value, so two positive reads could concatenate different values;
empty EOF supplies no label. Both cases fail. Equal accepted values establish
only equality of the exported `attr/current` bytes at their respective first
reads. The later EOF checks completeness under this bound; it does not prove
the value remains stable afterward. Neither branch establishes equality of all
LSM state or security policy. Matching error strings, mixed
success/error results, other errnos and incomplete reads cannot satisfy either
rule. A different inventory with paired EINVAL remains a failure.

The Rust transcript oracle derives these branches from typed task, query and
inventory records, including the exact two-read sequence, byte count and EOF
for successful values. Inventory collection also requires two reads and rejects
empty, split, truncated or malformed records. C decision and PASS lines must
match the independently derived branch. Default qualification requires neither a copied kernel
image nor privileged BPF inspection. There is no fixed-boot gate or ignore
option. Hosts without readable securityfs still fail. Synthetic successful-label
controls do not qualify a real label-producing host or an Ubuntu execution.

Credentials, groups, capabilities, NoNewPrivs, seccomp state, namespaces, cwd,
root, masks and alternate signal stacks retain their separate comparisons.
The expected new-thread differences are a distinct TID and disabled alternate
signal stack. The positive control also requires zero-byte read completion, one
physical join, unchanged endpoint identity and flags, ownership release, and
verified restoration of the creator's mask and alternate signal stack.

The ordinary, unignored Cargo integration test is
`cargo test -p reverie-kvm --test terminal_read_protocol`. Its required coverage
compiles the actual C implementation and test once, runs the full fifteen-control
aggregate without provider arguments, and reuses that executable for all
`--context-mode` classifier controls through the same bounded process owner:

- `equal-labels` is a clearly labeled synthetic positive, separate from the
  actual live query result.
- `equal-labels-nonlegacy` collects a valid nonlegacy inventory and complete
  equal labels from explicitly synthetic memfd fixtures, using the same
  inventory and attribute classifiers as the live path.
- `empty-labels` collects two genuine zero-byte memfds and requires rejection
  of their empty EOF observations.
- `mask-mismatch`, `query-asymmetry`, `query-errors`, `query-eperm`,
  `missing-task`, `truncated-label`, `label-mismatch`, `label-length` and
  `unqualified-provider` reject the specified context or attribute defect.
- `inventory-malformed`, `inventory-changing`, `inventory-missing` and
  `inventory-truncated` reject the specified inventory defect.
- `inventory-unknown` retains its paired-EINVAL premise explicitly: valid
  nonlegacy inventory cannot authorize unavailable-label.

Each mode retains the real task and inventory observations separately from
its explicitly labeled fixture or fault. Attribute fixtures collect explicit
synthetic inventories and values or errors, independent of the live host's
branch. `inventory-unknown` now reaches error authorization after valid inventory
classification; its paired synthetic EINVAL records must be rejected with the
retained `provider-inventory-oracle` diagnostic. Negative modes require their exact
rejection diagnostic and SIGABRT, with no PASS or unexpected-acceptance marker;
an unrelated failure cannot qualify them. Mask mismatch alters the actual
helper's SIGUSR1 mask. Missing-task queries use the invalid task-zero path,
and label/truncation fixtures use the same bounded collector on real memfd
bytes. Compile failure, abort, incomplete transcripts, capture overflow and
timeout/descendant cleanup have separate wrapper controls. Timeout and rescue
remain failures; expected classifier aborts do not excuse failed retirement.
The wrapper runs seventeen context modes: two synthetic positives and fifteen
negatives, retaining all fourteen earlier negatives. In-process synthetic record
controls additionally reject empty values, split or extra positive reads, and
first-read lengths that disagree with the summary through the actual Rust parser.

The test-only compiler recipe explicitly selects non-PIE code and linking with
`-fno-pie -no-pie`, alongside the existing mandatory test, cancellation, warning
and active-assertion flags. Production compiler inputs remain unchanged.
The read-dispatch diagnostic supports the measured x86-64 non-PIE `ET_EXEC`
layout whose canonical `read` address begins with `ff 25 disp32`. It distinguishes
that executable PLT address from the live GOT destination and requires fresh,
unchanged observations before the helper read and after join, matching public
`dlsym(RTLD_NEXT, "read")`, with `dladdr` and maps recorded. Unsupported layouts
fail; explicit non-PIE selection does not authorize another PLT decoder or an
unsupported toolchain. This test-selected layout does not qualify a distribution's
default production code generation. No additional CET flag is selected without
actual hosted evidence. The external qualification additionally binds
the executed ELF's exact public-read `R_X86_64_JUMP_SLOT` and the destination
to the mapped libc's public symbol. Ordinary Cargo execution enforces the
in-process checks; it does not independently perform that external ELF binding.

Historical failures remain failures. Original C15 exited 134 before querying
the helper's attribute. The first corrected aggregate returned native 0/caller 1
because the binding diagnostic captured only the executable PLT address, without
the live GOT destination. The first full Cargo attempt returned 101/caller 1
before the native aggregate: descendant `children`-file access failed with ENOENT
without CONFIG_PROC_CHILDREN. Its outer scope retired, but the wrapper did not
prove its compiler child's status or retirement. Source-bound sealed evidence
retains these statuses and later executions separately. Sealing the qualification
report supplies the input to independent reviews and is separate from approval.

Rust tests cover sticky registration, worker/root scope, spurious wakes,
nonreturning Tool disposition, and actual Tool-observer allocation/panic lifetime.
State-gated Direct/Tool probes additionally bind the executable, public libc
symbols, host arguments, actual cancel targets and physical join order. A
timeout or rescue remains failure. Evidence from the b9 baseline remains
separate from the refreshed-main baseline and implementation.

This increment does not qualify guest SIGUSR1/restart behavior, virtual timers,
scheduling, record/replay, copyout, endpoint policy changes, or the broader
combined Hermit integration tests.
