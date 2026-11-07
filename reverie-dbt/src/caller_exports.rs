/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Native exports for a caller-owned concrete Tool, independent of the
//! prototype runtime. The macro belongs in a constructor-free cdylib that
//! depends on reverie-dbt with default-features=false.

/// Export the complete native callback contract for one concrete caller Tool.
///
/// `identity` is a producer-generated `[u8; 32]` digest of declared source/build
/// inputs, paired with the native client. It is not a self-hash or a runtime
/// Tool-name selector. The runtime owns no local GlobalState.
///
/// The initial supported domain is one initial application process/thread,
/// coordinated configuration, no inherited seccomp, and no selected instruction
/// interception. Unsupported lifecycle boundaries refuse before forwarding.
/// The producer must not enable reverie-dbt's prototype-runtime feature.
#[macro_export]
macro_rules! export_caller_tool {
    ($tool:ty, $identity:expr) => {
        static __REVERIE_CALLER_RUNTIME: $crate::caller_runtime::CallerRuntime<$tool> =
            $crate::caller_runtime::CallerRuntime::new($identity);

        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_dbt_runtime_abi_version() -> u32 {
            $crate::DBT_RUNTIME_ABI_VERSION
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_dbt_runtime_callbacks_size() -> usize {
            ::std::mem::size_of::<$crate::DbtRuntimeCallbacks>()
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_dbt_runtime_image_init() -> $crate::caller_abi::ImageDescriptor {
            __REVERIE_CALLER_RUNTIME.image_init()
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// Native must validate this image's exported ABI and exact callback-table
        /// size before calling. `argument` must then point to the complete live
        /// table, uniquely installed for this image; a shorter table cannot be
        /// converted to a reference or copied by this entry.
        pub unsafe extern "C" fn reverie_dbt_runtime_background_init_v3(
            argument: *mut ::std::ffi::c_void,
            mode: u32,
        ) -> i32 {
            unsafe { __REVERIE_CALLER_RUNTIME.background_init(argument, mode) }
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// A non-null `snapshot` must be writable for one ReadySnapshot for the duration of this call.
        pub unsafe extern "C" fn reverie_dbt_runtime_ready(
            image: u64,
            snapshot: *mut $crate::caller_abi::ReadySnapshot,
        ) -> i32 {
            unsafe { __REVERIE_CALLER_RUNTIME.ready(image, snapshot) }
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// Native must validate the allocation prefix, live application context and identities; counters is uniquely borrowed for admission.
        pub unsafe extern "C" fn reverie_dbt_runtime_thread_init(
            counters: *mut $crate::caller_runtime::CallerCounters,
            context: *mut ::std::ffi::c_void,
            tid: i32,
            pid: i32,
            ppid: i32,
            branches: u64,
            defer: i32,
            invoke: $crate::SyscallInvoker,
            read: $crate::RegisterReader,
            write: $crate::RegisterWriter,
        ) -> i32 {
            unsafe {
                __REVERIE_CALLER_RUNTIME.thread_init(
                    counters,
                    context as usize,
                    tid,
                    pid,
                    ppid,
                    branches,
                    defer,
                    invoke,
                    read,
                    write,
                )
            }
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// All pointers must name the current native callback records and writable result buffers; native holds the unique application entry.
        pub unsafe extern "C" fn reverie_dbt_runtime_pre_syscall(
            context: *mut ::std::ffi::c_void,
            counters: *mut $crate::caller_runtime::CallerCounters,
            tid: i32,
            pid: i32,
            image: u64,
            number: i64,
            args: *const u64,
            branches: u64,
            result: *mut i64,
            deferred_number: *mut i64,
            deferred_args: *mut u64,
            invoke: $crate::SyscallInvoker,
            read: $crate::RegisterReader,
            write: $crate::RegisterWriter,
            memory: $crate::MemoryReader,
            _write_memory: $crate::MemoryWriter,
            _emit: $crate::RuntimeEmitter,
        ) -> i32 {
            unsafe {
                __REVERIE_CALLER_RUNTIME.pre_syscall(
                    context as usize,
                    counters,
                    tid,
                    pid,
                    image,
                    number,
                    args,
                    branches,
                    result,
                    deferred_number,
                    deferred_args,
                    invoke,
                    read,
                    write,
                    memory,
                )
            }
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// Native must supply the exact revalidated terminal reservation and unique live counters after all Guest borrows end.
        pub unsafe extern "C" fn reverie_dbt_runtime_thread_exit(
            counters: *mut $crate::caller_runtime::CallerCounters,
            context: *mut ::std::ffi::c_void,
            tid: i32,
            invoke: $crate::SyscallInvoker,
            fact: *const $crate::caller_abi::TerminalFact,
        ) -> i32 {
            unsafe {
                __REVERIE_CALLER_RUNTIME.thread_exit(counters, context as usize, tid, invoke, fact)
            }
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_dbt_runtime_process_exit() {
            __REVERIE_CALLER_RUNTIME.process_exit();
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_dbt_runtime_name() -> *const ::std::ffi::c_char {
            concat!(stringify!($tool), "\0").as_ptr().cast()
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_dbt_runtime_kind_code() -> u8 {
            $crate::backend_stats::DbtRuntimeKind::CallerTool.to_wire()
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// Each output pointer must be non-null and writable for one u64.
        pub unsafe extern "C" fn reverie_dbt_runtime_totals(
            branches: *mut u64,
            syscalls: *mut u64,
            rewritten: *mut u64,
            memory_hash: *mut u64,
        ) {
            unsafe {
                branches.write(__REVERIE_CALLER_RUNTIME.observed_branches());
                syscalls.write(__REVERIE_CALLER_RUNTIME.observed_syscalls());
                rewritten.write(__REVERIE_CALLER_RUNTIME.rewritten_syscalls());
                memory_hash.write(0);
            }
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// This unsupported callback accepts native ABI records but does not dereference them or admit a child.
        pub unsafe extern "C" fn reverie_dbt_runtime_thread_created_v2(
            _counters: *mut $crate::caller_runtime::CallerCounters,
            _context: *mut ::std::ffi::c_void,
            _parent_tid: i32,
            _pid: i32,
            _branches: u64,
            _child_tid: i32,
            _virtual_child_tid: i32,
            _child_tid_addr: u64,
            _flags: u64,
            _invoke: $crate::SyscallInvoker,
            _read: $crate::RegisterReader,
            _write: $crate::RegisterWriter,
        ) -> i32 {
            __REVERIE_CALLER_RUNTIME.unsupported("caller-thread-creation-unsupported")
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// This unsupported callback accepts native ABI records but does not dereference them.
        pub unsafe extern "C" fn reverie_dbt_runtime_exec_failed(
            _counters: *mut $crate::caller_runtime::CallerCounters,
            _pid: i32,
        ) {
            __REVERIE_CALLER_RUNTIME.unsupported("caller-successor-exec-unsupported");
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// This unsupported callback accepts native ABI records but does not dereference them or admit a child.
        pub unsafe extern "C" fn reverie_dbt_runtime_process_clone_result(
            _counters: *mut $crate::caller_runtime::CallerCounters,
            _context: *mut ::std::ffi::c_void,
            _parent_tid: i32,
            _parent_pid: i32,
            _branches: u64,
            _number: i64,
            _result: i64,
            _virtual_child_tid: i32,
            _child_tid_addr: u64,
            _flags: u64,
            _exit_signal: i32,
            _invoke: $crate::SyscallInvoker,
            _read: $crate::RegisterReader,
            _write: $crate::RegisterWriter,
        ) -> i32 {
            __REVERIE_CALLER_RUNTIME.unsupported("caller-process-creation-unsupported")
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_dbt_runtime_copied_syscall(
            _number: i64,
            _args: *const u64,
        ) -> i32 {
            __REVERIE_CALLER_RUNTIME.unsupported("caller-copied-process-unsupported")
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// This unsupported callback accepts native ABI records but never delivers the signal or dereferences them.
        pub unsafe extern "C" fn reverie_dbt_runtime_signal_event(
            _context: *mut ::std::ffi::c_void,
            _counters: *mut ::std::ffi::c_void,
            _tid: i32,
            _pid: i32,
            _image: u64,
            _branches: u64,
            _event: *mut $crate::DbtSignalEvent,
            _invoke: $crate::SyscallInvoker,
            _read: $crate::RegisterReader,
            _write: $crate::RegisterWriter,
            _memory: $crate::MemoryReader,
            _write_memory: $crate::MemoryWriter,
            _emit: $crate::RuntimeEmitter,
        ) -> i32 {
            __REVERIE_CALLER_RUNTIME.unsupported("caller-guest-signal-unsupported")
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// This unsupported callback accepts native ABI records but never reads or writes their buffers.
        pub unsafe extern "C" fn reverie_dbt_runtime_cpuid(
            _context: *mut ::std::ffi::c_void,
            _counters: *mut $crate::caller_runtime::CallerCounters,
            _tid: i32,
            _pid: i32,
            _branches: u64,
            _leaf: u32,
            _subleaf: u32,
            _invoke: $crate::SyscallInvoker,
            _read: $crate::RegisterReader,
            _write: $crate::RegisterWriter,
            _emit: $crate::RuntimeEmitter,
            _registers: *mut [u32; 4],
        ) -> i32 {
            __REVERIE_CALLER_RUNTIME.unsupported("caller-intercepted-cpuid-unsupported")
        }
        #[unsafe(no_mangle)]
        /// Native caller ABI entry.
        ///
        /// # Safety
        /// This unsupported callback accepts native ABI records but never reads or writes their buffers.
        pub unsafe extern "C" fn reverie_dbt_runtime_rdtsc(
            _context: *mut ::std::ffi::c_void,
            _counters: *mut $crate::caller_runtime::CallerCounters,
            _tid: i32,
            _pid: i32,
            _branches: u64,
            _with_aux: i32,
            _invoke: $crate::SyscallInvoker,
            _read: $crate::RegisterReader,
            _write: $crate::RegisterWriter,
            _emit: $crate::RuntimeEmitter,
            _tsc: *mut u64,
            _aux: *mut u32,
        ) -> i32 {
            // Native-only caller instructions must never reach the legacy
            // fixed-stride fallback. A mistaken rewrite fails loudly.
            __REVERIE_CALLER_RUNTIME.unsupported("caller-intercepted-rdtsc-unsupported")
        }
    };
}
