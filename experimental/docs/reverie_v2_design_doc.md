# Reverie v2: in-guest no_std design doc

This is a design document on how to implement an in-guest syscall tracer that
has extremely low overhead, is reliable, and works on all types of binaries.

# Background

The fastest way to intercept system calls is by replacing the syscall with a
CALL/JMP instruction that calls a function that we inject into the guest
process. This might sound rather easy to do, but there are many challenges with
this approach. We’ve had two previous attempts at implementing an in-guest
Reverie backend. They are described below along with their shortcomings.

## Reverie Alpha

Before we wrote `reverie-ptrace`, the very first version of Reverie did binary
rewriting to intercept syscalls.

Shortcomings:

 * Missed early syscalls because of `LD_PRELOAD` usage.
 * Not all syscalls could be patched because they’re at the end of a basic
   block.
 * Conflicts between the plugin’s glibc and the tracee’s glibc.
 * Does not work on static binaries.
 * Does not work well with a chroot environment. Because the plugin is compiled
   as a DSO, it may not be accessible from inside of the chroot.

We also tried to have the plugin use musl libc instead of glibc, but we cannot
mix two different libc implementations because they both have their own ideas of
how to manage thread local storage. It is _very_ difficult to reconcile this
problem.

## Reverie Sabre

Reverie Sabre uses [SaBRe](https://github.com/srg-imperial/SaBRe) to do the
binary rewriting. Since SaBRe is written in C, we wrote a Rust interface for it.
SaBRe works by hijacking the dynamic loader and loads our plugin first before
any other DSOs.

Shortcomings:

 * While we can technically intercept early syscalls, we can’t do it easily in
   practice. To do anything with the early syscalls, we can’t use anything from
   glibc. That means no allocations, no thread local storage, etc.
 * Does not work on static binaries.
 * Does not patch syscalls that are JITed.
 * Does not work well with a chroot environment.
 * Clobbers the result of `readlink /proc/self/exe` because SaBRe replaces its
   own code with the tracee’s.
 * We can get glibc mismatch errors. The tracee’s binary and the plugin’s DSO
   may have been compiled with different versions of glibc. This can lead to
   load-time errors.
 * The plugin can end up blowing through the stack because it reuses the same
   stack that the tracee uses.


# The no_std implementation

Because many of the above problems are caused by fighting with glibc, we can
leverage Rust’s no_std mode to avoid it completely.

## Plugin Loading

Let’s assume we have a statically linked DSO for a plugin with a single exported
function that is to be called instead of the syscall. How do we inject this into
the address space of the tracee process?

The absolute best time to load this is immediately after a successful call to
`execve` and the only way to do this reliably is with ptrace.

The way it shall work is as follows:

 1. From the tracer process, we **spawn the child process and attach to it with
    ptrace**. We then wait for a `PTRACE_EVENT_EXEC` to have the tracee stopped
    immediately after a successful call to `execve`. Note that we are _not_
    interested in intercepting all ptrace events, because that would introduce a
    large slowdown. By only intercepting exec events, the overhead of ptrace
    should be quite minimal.
 2. Now, to actually load our plugin’s DSO into the tracee’s address space, we
    need to inject calls to the tracee to run `mmap`. Instead of mapping it in
    from disk (via `open` + `mmap`), the DSO should be copied over into a
    `MAP_ANONYMOUS` mapping using `process_vm_writev`. Effectively, the tracer
    should be doing the loading of the DSO and loading each of its `PT_LOAD`
    segments. By copying the contents of the DSO over rather than using `open` +
    `mmap`, we bypass the chroot problem.

    We need to do some ELF parsing to figure out where the `PT_LOAD` segments
    are, but this only needs to be done once inside the tracer and it should be
    very fast to do so.

    Ideally, we should map the DSO at fixed addresses to ensure determinism and
    make it easier to identify the plugin while debugging, but this is not
    required. However, it is required if we don't perform relocations.

 3. Perform [relocations](https://en.wikipedia.org/wiki/Relocation_(computing)).
    Just like the dynamic linker, we need to do a pass to fix up addresses so
    that they point to the real place. While relocations are only necessary when
    compiling with `-pic`, this flag is usually the default and it is best not
    to fight the build system.
 4. We need to keep track of the address of our callback function because we
 will need it during the patching phase.

**Notes:**

 * Injecting syscalls is done in the same way that `reverie-ptrace` currently
   does it:
     * Replace the instructions at the current instruction pointer with a
       `syscall` instruction.
     * Use ptrace to set the registers and step through the syscall instruction.
     * Finally, the original instructions that we overwrite with the syscall
       instruction get restored along with the original value of the instruction
       pointer.
 * All of the symbol and debug information of the plugin should still be
   available while debugging. However, we should confirm that the debugger will
   even try to find this in pages not backed by a file on disk.
 * We can use `include_bytes!()` to bake the plugin into the tracer executable.

**Rational**:

 * The main downside of using `ptrace` here is that it makes it harder to debug
   the tracee with gdb. There can only be one ptracer at a time. There are a
   couple of ways we can work around this issue: (1) either implement a gdb
   server in the tracer to allow debugging, or (2) make it possible to detach
   from the tracee when debugging is desired. The first option is certainly more
   robust.
 * We can’t just detach from the tracee immediately after `execve` because we
   need to do the same thing for every child process.
 * Using ptrace may also have other advantages, like observing thread and process
   exits more reliably than we can from within the tracee itself.
 * The overhead of ptrace should be quite minimal since we are only interested
   in intercepting `PTRACE_EVENT_EXEC` events. Thus, the tracee should only be
   in a stopped state once during its lifetime.

**References**:

* Use the `safeptrace` crate to avoid shooting yourself in the foot with ptrace.

## Patching

With the plugin DSO loaded into the address space of the tracee, we need to find
all of the syscall instructions and replace them with a call to our callback
function. This is easier said than done because there are tricky edge cases to
handle here.


### How to patch

Patching generally involves the following:

 1. **Find** syscall instructions in the `.text` section by simply searching for
    its bit pattern. (On x86-64, a syscall instruction is 2 bytes represented by
    0x0f05.) Note that even if we find this bit pattern, there’s no guarantee
    that it is actually a syscall instruction. We need to disassemble further to
    find out for sure.
 2. **Replace** each syscall with a JMP instruction to our trampoline. Since a
    syscall is 2 bytes and our JMP instruction is 5 bytes, the trampoline
    contains any instructions that were overwritten plus a call to our callback
    function.  Moving code around like this isn’t valid because any relative
    addressing needs to be fixed up inside the trampoline. Thus, we need to
    disassemble the instructions that we have overwritten to figure out if they
    need to be fixed up or not.

### Where to patch

There are two places where patching can be done, each with their own advantages
and disadvantages.

#### From the tracer via ptrace

 * Advantages:
     * We can easily use parallelism to do the searching and patching.
     * We can guarantee that a cache of the patched instructions will be
       available because the tracer is guaranteed to be outside of any chroot
       jail.
 * Disadvantages:
     * Doing a fast search could be difficult because the data lives in the
       address space of the tracee process. We might be able to mmap the memory
       into the tracer process, but this isn’t yet clear.
     * It is more tricky to allocate memory in the tracee for constructing
       trampolines.

#### From the tracee itself

 * Advantages:
   * To do patching, we can just have the ptracer jump to a function in our DSO
     that does all of the patching.
 * Disadvantages:
   * Since the DSO must use no_std, finding a disassembler that works with
     no_std could be tricky. (For x86-64, iced-x86 works with `no_std`.)
   * Parallelism will be very difficult to implement with `no_std`.

### When to patch

Patching ultimately needs to be done on everything the `.text` section. The
executable itself has a `.text` section and so do all of the loaded DSOs. Thus,
patching needs to happen in the following scenarios:

 * Immediately after execve (to patch the executable). Here, we’re guaranteed
   that no other threads are running at the same time.
 * Immediately after a PT_LOAD segment is mapped into memory via mmap. There
   might be other threads at this point, but we can be reasonably certain that no
   other threads are accessing this just-mmaped segment.

### Potential Optimizations

 * Cache the locations of the patched instructions for next time. We can store a
   mapping of BuildID -> PatchLocations. As long as the binary’s BuildID is
   different upon subsequent rebuilds, this should work just fine. Note that
   shared libraries loaded at runtime have their own BuildID and can be cached
   separately. For shared libraries that are common to many binaries, this could
   lead to a big performance win.
 * We can use parallelism to simultaneously search through multiple PT_LOAD
   segments at a time.

### References:

 * [SaBRe’s rewriter implementation](https://github.com/srg-imperial/SaBRe/blob/05816ee066a7284bee8afd0e73eeb44455b254b4/arch/x86_64/rewriter.c)


## Catching unpatched syscalls

Patching does not always work in 100% of cases and there may be JITed code that
is not patched, so we should have a fallback in these rare circumstances.

In kernel versions newer than v5.11.0, there is a wonderful new way to intercept
syscalls from within the process itself. It is called
[PR_SET_SYSCALL_USER_DISPATCH](https://lwn.net/Articles/826313/).

It works like this:

```
prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, start, length, selector);
```

 * `start` is the starting address where syscalls _should not_ be intercepted.
 * `length` is the length of the memory region from `start` where syscalls
   shouldn’t be intercepted.
 * `selector` is a pointer to a `u8` that controls whether or not to enable the
   filter. The kernel looks at this memory address whenever a syscall
   instruction is trapped to determine if it should raise a `SIGSYS`. Thus, it
   allows super-fast toggling of the filter.

When the plugin is loaded, we can use `rt_sigaction` to set a signal handler for
`SIGSYS`. When we receive this signal, we should look at `siginfo_t.si_syscall`
to see which syscall was attempted.

The syscall arguments can be retrieved via the `ucontext` parameter to the
signal handler. It has a `uc_mcontext` member that holds all of the registers.

From this signal handler, we can run our syscall callback to handle the syscall.

Finally, after the signal handler is set up, we call this `prctl` to turn on
interception. Since we’re excluding the memory range of our plugin and all
syscalls outside of that range should have been replaced by a JMP instruction,
this should catch only syscalls that we weren’t able to patch.

**Notes**:

* We can use the magic linker variables `__ehdr_start` and `_end` within the
  plugin’s DSO to figure out the section of memory to exclude from interception.
* This is much better than using seccomp to trap syscalls because it doesn’t
  rely on the plugin to be loaded to a fixed address in all child processes.

## Thread-local Storage (TLS)

Thread-local storage is handled entirely by libc. Whenever a new thread is
created, it allocates some new memory to use for thread local storage. The `%fs`
register on x86-64 is a register that is dedicated to holding the offset to this
special region of memory. When a thread needs to access local storage, it will
use an address relative to the one in the `%fs` register.

Since our plugin is a static DSO, we can’t have threads and the compiler won’t
generate any `%fs`-relative addresses. However, we still want our plugin to be
able to store state on a per-thread basis. Since `%fs` shall be unique for each
thread, we can use it as a key into a global hash table where our thread-local
state is stored.

**Notes**:

 * The `%fs` register is not set right away. It doesn’t get set until
   `arch_prctl` is called early on in the execution of the program. We need to
   intercept this call and adjust our hash table accordingly.

**See Also**:

 * The ultimate guide on TLS: [https://www.akkadia.org/drepper/tls.pdf](https://www.akkadia.org/drepper/tls.pdf)


## The Stack

Similar to TLS, each thread has its own stack which gets allocated whenever a
new thread is spawned. It is up to the application to choose the size of the
stack space allocated for a thread. By default, it is only 2MB. Some threads may
even have very small stack sizes. For example, the thread glibc spawns to manage
timers only has a 16KB stack. Therefore, we cannot rely on the stack of the
thread to be large enough for the plugin’s needs. Instead, we need to create our
own stack and switch to it for only the duration of the plugin’s callback
function.

Like with TLS, we can use another global hashmap that translates our `%fs`
register into a `Box<[u8]>` where our stack is located. (Don’t forget that
the stack pointer decreases to grow the stack, so it should initially point to
the last 8 bytes of the allocated memory.)

This can be implemented by using assembly code to change `%rsp` to point to the
top of our stack. We need to store the old value of the previous stack on our
new stack.

This can be extremely tricky to get right as we need to be careful to not
clobber any other registers. All registers should be exactly the same as they
were before. On x86-64, the only two registers that are safe to clobber are
`%rcx` and `%r11`.

## Enforcing no_std in the plugin

Since everything relies on the plugin not having any dependencies and no usage
of libc, we need to be extra careful to ensure this.

The biggest requirement is that we only depend on no_std crates. As soon as we
depend on a crate that uses libc, then the build system will think that our DSO
should link with it too. This can be especially painful when a proc macro crate
uses std at build-time, but not at runtime.

At the very least, our loader should check that our DSO has no interpreter
(i.e., no usage of `ld.so`).

## The Allocator

For `no_std` to be useful, we need to have a global allocator. Without this, we
cannot use `Vec`, `Box`, `HashMap`, etc. It would be incredibly restrictive.

We can’t just use any off the shelf allocator, however. We need to have an
allocator that has the following restrictions:

 * No thread-local storage is used.
 * Does not use glibc in any way. Many allocators use libc’s `malloc` to allocate
   the underlying memory.
 * No mutexes, only atomics.

There exist crates that implement a `no_std` allocator, but they usually rely on
a pre-allocated pool of memory to operate on. There is no way to dynamically
mmap in new memory pages for use. This is fine, however, because we can leverage
the fact that 2TB of virtual memory does not necessarily map to 2TB of physical
memory if the full range of the 2TB has not been touched. All we need to do is
allocate a large pool of memory up front and use it for the lifetime of the
tracee.
