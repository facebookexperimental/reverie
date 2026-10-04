# Prepared common capture

`unsafe { prepared_capture(options, destination) }` returns a caller-owned `CaptureOwner`,
one `LogSink`, and a cloneable `HostProducer`. It starts the existing shared-ring
collector and sole destination worker on dedicated host threads, and waits for
both before returning. Prepare it before GlobalTool initialization. Keep the
owner outside Tokio, through GlobalState cleanup/Drop and runtime destruction.

This library port does not connect the prepared sink to a current LiteInst
backend adapter or a runtime bootstrap. V3 retained capture and V4 ordered
capture remain distinct socket-lifetime protocols. A prepared sink cannot be
attached to another collector or transferred twice. No default backend capability
is added, and closing a future setup socket must not satisfy lifetime closure.

The host formatter must buffer one complete original event and call
`HostProducer::write_record`; the guest formatter uses
the ordered `Writer::write_record`. V4 rejects arbitrary `io::Write` fragments.
Formatting failure must call `record_failed`, not emit a partial event. Neither an unwinding formatter
Drop nor a detlog RPC forwarder should duplicate the record. H subscriber/filter
and formatter integration is not provided by this crate.

Complete-record credits precede BEGIN. The short END commit assigns a checked
capture-wide order before release-publication and before the emission returns.
The collector emits only contiguous source order, never receive/scan order.
Source order preserves established causal edges but does **not** establish
determinism of concurrently enabled emitters or cross-backend INFO parity.
Host and guest credits are separate reservations in one bounded transport;
consumption/discard recycles them. Unfinished guest reservations remain charged.

Ordinary guest cancellation/init/spawn/RPC failure closes only guest admission.
`guest_finished()` is a guest transport/run report, not a whole-capture verdict.
Root reap, endpoint closure, registration/FINISH, RPC outcomes and capture
publication remain separate facts. Host cleanup can still emit after cancellation.
An unresolved guest commit at cutoff prevents ordered continuation; it is not
cleared or skipped. Host publication/order faults are fatal evidence failures.

`CaptureDestination::progress` reports cumulative **actual** data acknowledgments,
deliberate discards and marker bytes separately, including acknowledgments before
a returned error. Short writes and interrupted writes resume only the observed
unconsumed suffix. The caller owns the one existing output ceiling/marker policy:
transport implements no second clipping algorithm. Output clipping continues
transport consumption without stopping the guest, but cannot qualify a capture.
Fatal transport limits never produce a marker claiming execution was unaffected.

After all enabled host emitters are quiescent, call `finish_until` once (repeated
calls preserve the earlier deadline). Clones do not keep admission open.
Finalization can settle an incomplete guest once its lifetime endpoint is closed,
the rings are drained, all committed source orders are observed, and no record
remains pending publication. Missing FINISH still means Incomplete, not Complete;
it does not require waiting for a cancellation cutoff after these facts hold.
An open lifetime endpoint, unresolved order or pending record retains the existing
cutoff/deadline rules, and a deadline failure remains sticky.
Late host writes reject and remain observable. Owner Drop requests bounded closure;
it does not synchronously join. Blocking Write/flush cannot be interrupted:
deadlines revoke queued output, return `MayAppend`, and retain the uncertain
attempted range/acknowledged cursor. No second writer retries that range. Late
completion cannot promote a frozen failure to `Stable` or success. `Stable`
requires the exclusive destination worker to have actually ended.

Publication registers each accepted mailbox record and its bounded diagnostic
prefix before the receiver can begin it. Revocation accounts all registered,
definitely unattempted bytes immediately, without needing the destination thread
to wake. `unpublished_bytes` and `first_unpublished_order` cover these bytes and
direct collector discards with checked, once-only accounting; the earliest order
is retained even if a later direct discard precedes queued revocation. They do
retain the order of a discarded empty record without inventing payload bytes.
They do
not include deliberate output-ceiling clipping (`progress.discarded_bytes`).
An outstanding/failed `attempt` separately identifies the uncertain suffix after
its observed consumed cursor; that cursor includes data acknowledgments and
deliberate clipping, whose actual totals remain separate in `progress`. A failed
write with a fully consumed cursor has no uncertain bytes left. A successful short
write or resumable Interrupted result returns its unconsumed suffix to the
unattempted reservation until the next invocation begins. Fatal errors never
retry an uncertain suffix. Diagnostic retention/omissions are decided on enqueue
or direct discard, not on delayed receiver execution. Deadline snapshots freeze
all this evidence; late progress cannot change the returned report or its
`MayAppend` status. Source credit remains charged until the owning record is
actually released, independently of publication accounting.

Closing admissions does not turn validated pending records into order holes.
The collector delivers each contiguous next order before reporting completion;
an absent next order after closure/entrant/ring drain still refuses rather than
skipping to a later record.

`capture_snapshot()` returns `Some(CaptureReport)` only for a prepared session.
Its `qualifies()` additionally requires successful guest execution, actual root
reap/lifetime closure, no RPC/transport/order/destination issue, closed/drained
admissions, no late host write, full untruncated publication and stable shutdown.
It is not a deterministic-execution or comparator result. Legacy `snapshot()` /
`finished()` cannot qualify prepared capture: their per-producer byte format is
not the common canonical destination. They become terminal but incomplete at
publication finalization; callers must inspect `capture_snapshot()` instead.

Pure tests cover framing/order/credit, cancellation, generic destination errors,
blocked finalization and fresh native subprocess lifetimes. Native V4 guest
qualification, H shared-subscriber dispatch, exact existing H clipping adapter,
actual Detcore CLI execution and concurrent-emitter parity remain separate work.

Mapping creation/import, collector attachment and producer activation carry
explicit unsafe contracts. All peers, descriptor duplicates, inherited state and
writable mappings must cooperate for the full lifetime of every worker/producer.
Initialized layout fields remain immutable; frame and credit access obeys the
exclusive-incarnation/single-collector publication protocol. Size seals prevent
resizing, not arbitrary writes. The unsafe API does not establish a memory
sandbox, descriptor isolation, process ownership or an F1/F3 runtime repair.

## Split coordinator capture (additive)

`SplitCapturePlan` holds plain inactive mappings/endpoints. Call the unsafe
`run_split_capture` before starting O threads, using borrowed `FnMut` parent and
child factories. O retains both real factories; only C constructs and consumes
its work closure. This deliberately also retains an invoked parent factory's
captures until real cleanup. O starts the collector and output workers during
the owned A2 startup permission exchange; C starts no capture helper worker.
Each branch constructs fresh process-local wrappers and closes its unused peer.

`CoordinatorContext` owns the sole finalizer. Its one guest import and cloneable
emitter use V4's existing ordered records. An adapter must actually wait G,
terminate the serving task, tear down the owned RPC runtime outside async while
logging is open, and retain its real final issue snapshot before returning
`after_teardown`. The API is not a verifier of arbitrary callback claims. It
carries bounded typed failure classifications separately from the adapter's
original detailed diagnostics. Planned cancellation without retained errors
is not clean serving completion. Normal nonzero G exit and caught coordinator
panic are separate nonqualifying facts, even if C itself exits zero.

A2 serializes the result envelope by reference and drains its pipe before wait.
U is then destroyed; the envelope explicitly destroys T before closing emitter
entry and publishing FINISH. Only internal quiescence/locking/ring waits use the
one final-drain deadline. Serialize/Deserialize, arbitrary callbacks/Drop and
blocked destination I/O cannot be preempted by that deadline. Result acquisition
has no finite execution timeout and no added arbitrary T size cap.

`SplitCaptureRun` retains the atomic child capability, exact provisional bytes,
collector/output join ownership, destination escrow and both factories. Explicit
settlement may return `Unjoined`; retry or cancellation preserves the same
owner. Its Drop settles the actual child, joins both workers and then reclaims
factory resources, and may block. There is no detached reaper, leaked factory or
second-clone permission on unknown cleanup. The immutable failure report never
becomes a success because workers subsequently join; `actual_joins` records that
later physical cleanup separately. Decode of generic T occurs only after child
settlement, actual worker joins and factory reclamation.

Split qualification additionally requires actual channel-zero FINISH, exact
terminal cursor/sequence/registration state, checked lifecycle facts, actual C
status and actual joins. Local capture's existing qualifier and activation order
are preserved. Capture-owned quiescence is not global fork safety: user factory
Drop or Deserialize may create unrelated threads. Re-establish the ordinary
threadless/no-competing-reaper contract before another clone. No backend wiring,
root identity policy, loader/fork-exec/signal/TLS implementation, deterministic
scheduler proof, strict parity or harness flip is provided by this API.


`JoinedCapture::integrity` separately reports terminal capture integrity. A
`Complete { guest_status }` retains the genuine standard Unix wait status; it
requires the actual raw collector FINISH/EOF/order/admission witnesses, complete
publication, successful owned joins and matching coordinator facts. A guest
exit of 7 can have complete bytes while every existing success qualifier stays
false and all existing guest-policy failures remain recorded. Integrity is not
verification success, deterministic execution, or proof of arbitrary unsafe
adapter claims.

A bounded sticky fault set is independent of first-error text and bounded issue
retention. Guest policy has one private typed origin; transport, publication,
RPC, lifecycle, decoding and teardown faults never inherit that exception.
Structural integrity freezes with the first settlement report. Later joins are
cleanup facts and cannot repair an earlier deadline or `MayAppend` result; final
decoding can only add faults. Diagnostic-prefix omission is not lost canonical
output, while omitted issues and discarded/unpublished canonical bytes prevent
complete integrity.

The new status representation preserves canonical Linux realtime-signal deaths
as well as named signals. The existing `after_teardown` argument remains
Reverie's narrower `ExitStatus`; widening that producer API is separate work.
No failure text is parsed to distinguish guest outcome from capture integrity.
