# Reverie LiteInst Preload Prototype

This crate is a deliberately narrow Linux x86-64 proof of concept for
in-process Reverie instrumentation. It is not an implementation of Reverie's
`Backend` trait and cannot host an arbitrary asynchronous `Tool`.

The launcher adds `libreverie_liteinst.so` to `LD_PRELOAD`. The preload
constructor:

1. creates separate writable and executable mappings for a six-byte synthetic
   dispatch function and an in-page tool trampoline;
2. installs a `SIGSYS` handler;
3. installs a seccomp-BPF `SECCOMP_RET_TRAP` filter for application syscalls;
   and
4. activates a one-byte `B8` to `E9` instruction pun on the first trapped
   syscall, routing the event through the in-guest strace trampoline.

Bytes 1 through 4 of the dispatch instruction are simultaneously the immediate
of `mov eax, imm32` and the displacement of `jmp rel32`. Only byte 0 changes.
The executable mapping is never writable and the writable alias is never
executable. A small assembly syscall gate is exempted by exact instruction
pointer so the handler can forward the original syscall without recursively
trapping itself.

## Build and run

```bash
cargo build -p reverie-liteinst
target/debug/reverie-liteinst-strace /bin/echo hello
```

The guest writes its normal output to stdout. The in-process tool writes trace
records like this to stderr:

```text
[liteinst strace pid 1234] syscall(1) = 6
```

Embedding launchers can call `configure_command` with
`PreloadTool::Compatibility`. That mode forwards the same syscall stream but
emits stable syscall-number markers instead of PID- and ASLR-dependent trace
lines:

```text
reverie-liteinst: tool=compat syscall=1
```

Callers can count and compare these markers alongside guest output and exit
status. Arguments and results are omitted because many otherwise compatible
calls contain host-selected addresses and identifiers.

The `preload-constructor` default feature installs the runtime through the
DSO's `.init_array`. Embedders that provide their own cdylib wrapper must
disable default features and install `reverie_liteinst_initialize` exactly once.

`LD_PRELOAD` and the mapped runtime survive `fork`, so fork children remain
instrumented. The integration test runs a parent and child that both issue
trapped syscalls and requires trace records from two PIDs.

## Prototype boundaries

- Linux x86-64 and dynamically linked, non-`AT_SECURE` guests only.
- The built-in synchronous callbacks run in the guest's signal context.
  Reverie's async `Tool`, `Guest`, global RPC, timers, signals, register/memory
  mutation, and destructor contracts are not implemented.
- This prototype puns a synthetic dispatch instruction. It does not yet find
  and rewrite arbitrary two-byte `syscall` instructions in ELF text.
- `fork` and fork-like `clone` with a null child stack inherit instrumentation.
  Thread-creating `clone`, `clone3`, and `vfork` return `ENOTSUP`.
- `execve` and `execveat` return `ENOTSUP`. Seccomp filters survive exec while
  caught signal handlers, preload mappings, and alternate stacks do not; an
  inherited trap filter would otherwise kill the new image before its preload
  constructor could run.
- Applications can still interfere with reserved signals or masks. Replacing
  the `SIGSYS` disposition is rejected, but complete `rt_sigprocmask` and
  `sigaltstack` virtualization is outside this prototype.
- CPUID, RDTSC/RDTSCP, RDRAND/RDSEED, static binaries, secure-execution mode,
  `dlopen`/JIT executable mappings, and arbitrary signal multiplexing are not
  covered.
- The one-byte pun follows the empirical x86 instruction-coherence technique
  used by LiteInst research. A serializing CPUID follows activation, but this
  is not a portable architectural guarantee.

These limits are fail-closed where continuing would corrupt execution. Extending
this into a conforming backend requires an external controller for async tool
execution, complete process-tree and exec lifecycle control, signal
virtualization, short-instruction rewriting, and coverage for nondeterministic
CPU instructions.
