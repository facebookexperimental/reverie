# Fixed backing for LiteInst runtime stacks

An active LiteInst runtime reserves the half-open address range
`[0x600000000000, 0x600100000000)` before installing its signal handlers.
The reservation consumes 4 GiB of virtual address space; it does not commit
4 GiB of physical memory. A collision or insufficient address-space limit
refuses initialization. The runtime never overwrites an existing mapping,
searches for a different address, or falls back to the guest allocator.

The first MiB contains allocation metadata behind an outer guard. The last
page is also a guard. Each stack has a writable, page-rounded interior and
one inaccessible page on each side. The actual SIGSYS alternate stack uses
at least 64 KiB. A Tool's existing callback continuation retains its 8 MiB
capacity. Registering a stack retains its lease for process lifetime, even
if a later initialization step fails. An unpublished lease can be reused
only after its entire extent becomes inaccessible and its interior contents
are discarded; failed cleanup quarantines the extent. Plain fork inherits
the metadata and live stack contents through private COW mappings.

The storage choice is explicit at the shared runtime installation seam.
Generic in-guest, e9patch and SaBRe callers retain their existing storage.
An inert LiteInst preload does not reserve the range. Standalone Strace has
an alternate signal stack but does not prepare or enter a Tool continuation.
Its tests report that distinction instead of counting an unused stack as
an executed callback. Disabling the alternate stack preserves that existing
option and earns no alternate-stack placement claim.

FullTool installation also prepares 64 guarded 8 MiB callback stacks and
their guarded ownership metadata before starting the guest branch clock.
Each ordinary installed syscall, CPUID, RDTSC/RDTSCP or vDSO callback reaches
a native entry before its existing Rust body. That entry atomically claims
one exact free stack. Overlapping activations cannot share a claim, including
when they return out of order. Return restores the incoming stack pointer
before releasing the claim. An entry already on the actual registered Tool
alternate stack retains its current position there; it never resets that
stack to its top. This borrowed path claims no callback-pool slot.

Private fork preserves live claims and frames through COW. A nonlocal escape
or vanished worker leaves its claim occupied; the runtime does not reset the
bitmap or infer that a still-occupied stack can be reused. The 65th live or
escaped pool activation attempts to terminate with status 127, before writing
an existing frame or modifying the occupied word. Unprepared entry and an
alternate stack with insufficient native-frame headroom also take this fatal
path. It writes no diagnostic to stderr, so a full blocking output pipe
cannot hold it before the exit attempt. An external filter or supervisor
that denies, fabricates or holds that exit lies outside the termination
guarantee; the native invalid-instruction fallback is only an attempted
fail-stop. These resource failures earn no compatibility or parity credit.

Native Strace/Compat retain their original callback entry addresses. The
unpublished exact-syscall continuation remains a separate path. The new
ordinary callback entry is after LiteInst's register capture: that earlier
trampoline still writes to the interrupted stack. The registered alternate
stack is process-local under the existing thread restrictions; this does
not admit new guest threads.

The standalone preload's active constructor also uses the native bootstrap.
Its register-only selector prefix transfers to a fixed guarded 8 MiB stack
before the first named Tool initialization body runs. The bootstrap retains
that lease for process lifetime and restores the loader's original stack on
return. The runtime initializes before its compatibility resolver, and both
run on that owned stack. A missing raw Tool selector leaves the preload inert;
its compatibility resolver retains its existing placement. Earlier loader,
CRT and lazy compatibility work remain outside this guarantee. Other Tool
roots must explicitly use the bootstrap; exporting a generic initializer does
not place calls to it on an owned stack.

These leases establish placement and boundary guards. Their interiors remain
on protection key zero. They do not prevent a guest from writing an interior
or replacing a mapping, and they do not establish whole caller-byte equality.
Allocator arenas, saved-state owners, other globals, TLS and foreign-library
allocation still need separate treatment. The syscall dispatcher, signal
actions, completion protocol and determinism comparators are unchanged.
