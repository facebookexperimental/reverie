//! Generic in-guest host for Reverie tools on e9patch's direct AOT path.

use core::future::Future;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use reverie::Error;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::LocalMemory;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_preload::dispatch::PassthroughDispatcher;
use reverie_preload::dispatch::SyscallDispatcher;
use reverie_preload::dispatch::SyscallEvent;
use reverie_preload::dispatch::SyscallEventSource;
use reverie_preload::lifecycle::InProcessSeccomp;
use reverie_preload::trap::raw_syscall6;

use crate::aot;
use crate::dispatch::record_fallback_dispatch;
use crate::dispatch::record_fallback_site;
use crate::rewrite::E9PATCH_LOADER_BASE;
use crate::rpc::CoordinatorRpc;
use crate::rpc::SpinMutex;

const STACK_CAPACITY: usize = 4096;
const TAIL_NONE: u8 = 0;
const TAIL_RESULT: u8 = 1;
const TAIL_EXIT: u8 = 2;

static COMMITTED_STACKS: SpinMutex<Vec<Box<[u8]>>> = SpinMutex::new(Vec::new());
static TOOL_INSTALLED: AtomicBool = AtomicBool::new(false);

struct DispatchScratchScope;

impl DispatchScratchScope {
    fn enter() -> Self {
        COMMITTED_STACKS.lock().clear();
        Self
    }
}

impl Drop for DispatchScratchScope {
    fn drop(&mut self) {
        COMMITTED_STACKS.lock().clear();
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review generic in-guest
// Tool hosting on e9patch's direct AOT callback.
/// Installs a concrete Reverie tool and connects it to its coordinator.
///
/// A tool-specific preload DSO normally calls this from its constructor. The
/// function publishes the round-8 AOT callback, installs the shared seccomp
/// controller, and routes direct rewritten sites through `T`. Residuals whose
/// instruction pointer is inside the injected e9patch loader or Reverie payload
/// executable mapping may run natively before the first direct AOT event,
/// outside the Tool lifecycle. Every other subscribed residual fails closed
/// because a Rust tool may allocate, lock, or block and therefore cannot run in
/// signal context.
///
/// # Safety
///
/// Installs process-global signal, seccomp, dispatcher, and AOT callback state.
/// Call exactly once before application-created threads start.
pub unsafe fn install_tool<T>(coordinator: impl AsRef<Path>) -> io::Result<()>
where
    T: Tool + 'static,
{
    unsafe { install_tool_inner::<T>(coordinator.as_ref(), true) }
}

/// Installs a concrete Tool using a consumed bootstrap coordinator path.
///
/// Unlike [`install_tool`], this does not remove the legacy coordinator
/// environment variable because the sealed bootstrap did not introduce one.
///
/// # Safety
///
/// Installs process-global signal, seccomp, dispatcher, and AOT callback state.
/// Call exactly once before application-created threads start.
pub unsafe fn install_tool_from_bootstrap<T>(coordinator: impl AsRef<Path>) -> io::Result<()>
where
    T: Tool + 'static,
{
    unsafe { install_tool_inner::<T>(coordinator.as_ref(), false) }
}

unsafe fn install_tool_inner<T>(
    coordinator: &Path,
    remove_legacy_environment: bool,
) -> io::Result<()>
where
    T: Tool + 'static,
{
    if TOOL_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "e9patch generic Tool installed twice",
        ));
    }
    let startup_runtime_text = startup_runtime_text_ranges()?;
    let signal_state = prepare_guest_signal_state()?;
    let rpc = CoordinatorRpc::<T::GlobalState>::connect(coordinator)?;
    let pid = Pid::from_raw(raw_pid(libc::SYS_getpid).as_raw());
    let subscriptions = T::subscriptions(rpc.config()).iter_syscalls().collect();
    if remove_legacy_environment {
        // SAFETY: installation runs in a preload constructor before guest threads.
        unsafe { std::env::remove_var(crate::COORDINATOR_ENV) };
    }
    let tool = T::new(pid, rpc.config());
    let dispatch_page = aot::PendingDispatchPage::prepare()?;
    let config = crate::runtime::runtime_config_from_env()?;
    let dispatcher = ToolHost::<T> {
        tool: SpinMutex::new(Some(tool)),
        rpc,
        root_pid: pid,
        subscriptions,
        startup_runtime_text,
        direct_dispatch_started: AtomicBool::new(false),
        states: SpinMutex::new(HashMap::new()),
    };
    // SAFETY: the caller provides the once-before-threads contract. The
    // dispatcher is registered before the controller installs its filter.
    let result =
        unsafe { reverie_preload::install(Box::new(dispatcher), &InProcessSeccomp, &config) };
    if result.is_ok() {
        dispatch_page.commit();
    }
    drop(signal_state);
    result
}

struct ToolHost<T: Tool> {
    tool: SpinMutex<Option<T>>,
    rpc: CoordinatorRpc<T::GlobalState>,
    root_pid: Pid,
    subscriptions: HashSet<Sysno>,
    startup_runtime_text: [ExecutableRange; 2],
    direct_dispatch_started: AtomicBool,
    states: SpinMutex<HashMap<i32, T::ThreadState>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableRange {
    start: u64,
    end: u64,
}

impl ExecutableRange {
    fn contains(self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
}

fn executable_mapping_containing(maps: &str, address: u64) -> Option<ExecutableRange> {
    maps.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let (addresses, permissions) = (fields.next()?, fields.next()?);
        if !permissions
            .as_bytes()
            .get(2)
            .is_some_and(|byte| *byte == b'x')
        {
            return None;
        }
        let (start, end) = addresses.split_once('-')?;
        let range = ExecutableRange {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
        };
        (range.start < range.end && range.contains(address)).then_some(range)
    })
}

fn startup_runtime_text_ranges() -> io::Result<[ExecutableRange; 2]> {
    let maps = fs::read_to_string("/proc/self/maps")?;
    let loader = executable_mapping_containing(&maps, E9PATCH_LOADER_BASE).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("executable e9patch loader mapping at {E9PATCH_LOADER_BASE:#x}"),
        )
    })?;
    Ok([
        loader,
        ExecutableRange {
            start: crate::aot::AOT_PAYLOAD_TEXT_START,
            end: crate::aot::AOT_PAYLOAD_TEXT_END,
        },
    ])
}

fn residual_must_fail_closed(
    subscribed: bool,
    direct_dispatch_started: bool,
    from_injected_runtime: bool,
) -> bool {
    subscribed && (direct_dispatch_started || !from_injected_runtime)
}

impl<T> SyscallDispatcher for ToolHost<T>
where
    T: Tool + 'static,
{
    fn dispatch(&self, event: &mut SyscallEvent) {
        // Tool code and allocators can issue their own syscalls while the
        // process-wide filter is active. Those nested calls are implementation
        // activity, not guest events, and must bypass the tool through the
        // trusted gate with the same fail-closed process/signal guards LiteInst
        // applies.
        if aot::dispatch_is_nested()
            || (aot::dispatch_is_active() && event.source() == SyscallEventSource::SignalTrap)
        {
            forward_nested_tool_syscall(event, self.rpc.raw_fd());
            return;
        }

        if protect_coordinator_channel(event, self.rpc.raw_fd()) {
            return;
        }

        if event.source() == SyscallEventSource::SignalTrap {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // Generic Rust Tool code is not async-signal-safe. Make the
            // residual observable, then either pass pre-activation loader
            // setup natively or fail a subscribed post-activation site closed.
            record_fallback_dispatch(event.number());
            record_fallback_site(event.instruction_pointer());
            let subscribed = usize::try_from(event.number())
                .ok()
                .and_then(Sysno::new)
                .is_some_and(|number| self.subscriptions.contains(&number));
            if residual_must_fail_closed(
                subscribed,
                self.direct_dispatch_started.load(Ordering::Acquire),
                self.startup_runtime_text
                    .iter()
                    .any(|range| range.contains(event.instruction_pointer())),
            ) {
                event.fail(libc::EOPNOTSUPP);
            } else if let Some(error) = injected_syscall_guard(event.number(), event.args()) {
                event.fail(error.into_raw());
            } else {
                // Before the first direct event, only the injected e9patch
                // loader and Reverie payload mappings reach this subscribed
                // path. Afterwards, only unsubscribed residuals run natively.
                PassthroughDispatcher::new().dispatch(event);
            }
            return;
        }

        self.direct_dispatch_started.store(true, Ordering::Release);
        let _scratch_scope = DispatchScratchScope::enter();
        let tid = raw_pid(libc::SYS_gettid);
        let pid = raw_pid(libc::SYS_getpid);
        let ppid = (pid != self.root_pid).then(|| raw_pid(libc::SYS_getppid));

        let mut tool_slot = self.tool.lock();
        let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
        let mut states = self.states.lock();
        let is_new = !states.contains_key(&tid.as_raw());
        let pending_exit = {
            let state = states
                .entry(tid.as_raw())
                .or_insert_with(|| tool.init_thread_state(tid, None));
            let tail = TailResult::default();
            let mut guest = E9patchGuest::<T> {
                event,
                tid,
                pid,
                ppid,
                state,
                rpc: &self.rpc,
                tail: &tail,
            };

            if is_new && let Err(error) = drive_ready(tool.handle_thread_start(&mut guest)) {
                tool_fatal(124, &error);
            }
            // The preload host attaches after the kernel has exec'd this image.
            // Emit the root post-exec event once, matching LiteInst's lifecycle
            // contract for its supported single-process direct lane.
            if is_new
                && tid == self.root_pid
                && let Err(error) = drive_ready(tool.handle_post_exec(&mut guest))
            {
                tool_fatal(124, &Error::from(error));
            }

            let Some(number) = usize::try_from(guest.event.number())
                .ok()
                .and_then(Sysno::new)
            else {
                guest.event.fail(libc::ENOSYS);
                return;
            };
            if !self.subscriptions.contains(&number) {
                let raw_number = guest.event.number();
                let args = guest.event.args();
                if is_exit_syscall(raw_number) {
                    Some((raw_number, args))
                } else {
                    if let Some(error) = injected_syscall_guard(raw_number, args) {
                        guest.event.fail(error.into_raw());
                        return;
                    }
                    let result = unsafe { raw_syscall6(raw_number, args) };
                    guest.event.set_result(result);
                    return;
                }
            } else {
                let args = guest.event.args().map(|arg| arg as usize);
                let syscall = Syscall::from_raw(
                    number,
                    SyscallArgs::new(args[0], args[1], args[2], args[3], args[4], args[5]),
                );
                match drive_syscall(tool.handle_syscall_event(&mut guest, syscall), &tail) {
                    SyscallOutcome::Return(result) => {
                        let result = match result {
                            Ok(value) => value,
                            Err(error) => match error.into_errno() {
                                Ok(errno) => -i64::from(errno.into_raw()),
                                Err(error) => tool_fatal(125, &error),
                            },
                        };
                        guest.event.set_result(result);
                        None
                    }
                    SyscallOutcome::Exit { number, args } => Some((number, args)),
                }
            }
        };

        if let Some((number, args)) = pending_exit {
            finish_tool_exit(
                &mut tool_slot,
                &mut states,
                &self.rpc,
                tid,
                pid,
                number,
                args,
            );
            let result = unsafe { raw_syscall6(number, args) };
            event.set_result(result);
        }
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review direct-host exit
// lifecycle ordering before the non-returning exit syscall.
fn finish_tool_exit<T: Tool>(
    tool_slot: &mut Option<T>,
    states: &mut HashMap<i32, T::ThreadState>,
    rpc: &CoordinatorRpc<T::GlobalState>,
    tid: Pid,
    pid: Pid,
    number: i64,
    args: [u64; 6],
) {
    let state = states
        .remove(&tid.as_raw())
        .expect("e9patch thread state disappeared before exit");
    let status = reverie::ExitStatus::Exited((args[0] & 0xff) as i32);
    let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
    if let Err(error) = drive_ready(tool.on_exit_thread(tid, rpc, state, status)) {
        tool_fatal(125, &error);
    }
    if is_process_exit(number, tid, pid) {
        let tool = tool_slot.take().unwrap_or_else(|| fatal(126));
        if let Err(error) = drive_ready(tool.on_exit_process(pid, rpc, status)) {
            tool_fatal(125, &error);
        }
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review exit syscall
// classification for the direct Tool host.
fn is_exit_syscall(number: i64) -> bool {
    // AUTONOMOUS-BOT-IMPLEMENTED
    matches!(number, libc::SYS_exit | libc::SYS_exit_group)
}

fn is_process_exit(number: i64, tid: Pid, pid: Pid) -> bool {
    // AUTONOMOUS-BOT-IMPLEMENTED
    number == libc::SYS_exit_group || tid == pid
}

fn raw_pid(number: i64) -> Pid {
    let value = unsafe { raw_syscall6(number, [0; 6]) };
    if value <= 0 {
        fatal(126);
    }
    Pid::from_raw(value as i32)
}

fn drive_ready<F, T>(future: F) -> T
where
    F: Future<Output = T>,
{
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => core::hint::spin_loop(),
        }
    }
}

enum SyscallOutcome {
    Return(Result<i64, Error>),
    Exit { number: i64, args: [u64; 6] },
}

enum TailAction {
    Result(i64),
    Exit { number: i64, args: [u64; 6] },
}

fn drive_syscall<F>(future: F, tail: &TailResult) -> SyscallOutcome
where
    F: Future<Output = Result<i64, Error>>,
{
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return SyscallOutcome::Return(value),
            Poll::Pending => match tail.take() {
                Some(TailAction::Result(value)) => {
                    return SyscallOutcome::Return(Ok(value));
                }
                Some(TailAction::Exit { number, args }) => {
                    return SyscallOutcome::Exit { number, args };
                }
                None => core::hint::spin_loop(),
            },
        }
    }
}

#[derive(Default)]
struct TailResult {
    action: AtomicU8,
    value: AtomicI64,
    number: AtomicI64,
    args: [AtomicU64; 6],
}

impl TailResult {
    fn set_result(&self, value: i64) {
        self.value.store(value, Ordering::Relaxed);
        self.action.store(TAIL_RESULT, Ordering::Release);
    }

    fn set_exit(&self, number: i64, args: [u64; 6]) {
        self.number.store(number, Ordering::Relaxed);
        for (destination, value) in self.args.iter().zip(args) {
            destination.store(value, Ordering::Relaxed);
        }
        self.action.store(TAIL_EXIT, Ordering::Release);
    }

    fn take(&self) -> Option<TailAction> {
        match self.action.swap(TAIL_NONE, Ordering::AcqRel) {
            TAIL_RESULT => Some(TailAction::Result(self.value.load(Ordering::Relaxed))),
            TAIL_EXIT => Some(TailAction::Exit {
                number: self.number.load(Ordering::Relaxed),
                args: std::array::from_fn(|index| self.args[index].load(Ordering::Relaxed)),
            }),
            _ => None,
        }
    }
}

struct E9patchGuest<'a, T: Tool> {
    event: &'a mut SyscallEvent,
    tid: Pid,
    pid: Pid,
    ppid: Option<Pid>,
    state: &'a mut T::ThreadState,
    rpc: &'a CoordinatorRpc<T::GlobalState>,
    tail: &'a TailResult,
}

#[reverie::tool]
impl<T: Tool> GlobalRPC<T::GlobalState> for E9patchGuest<'_, T> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        self.rpc.send_rpc(message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.rpc.config()
    }
}

#[reverie::tool]
impl<T: Tool> Guest<T> for E9patchGuest<'_, T> {
    type Memory = LocalMemory;
    type Stack = LocalStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
        self.ppid
    }

    fn memory(&self) -> Self::Memory {
        LocalMemory::new()
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        aot::current_regs().unwrap_or_else(|| {
            let mut regs = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
            regs.rax = self.event.number() as u64;
            regs.orig_rax = self.event.number() as u64;
            let args = self.event.args();
            regs.rdi = args[0];
            regs.rsi = args[1];
            regs.rdx = args[2];
            regs.r10 = args[3];
            regs.r8 = args[4];
            regs.r9 = args[5];
            regs.rip = self.event.instruction_pointer();
            regs
        })
    }

    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), Error> {
        aot::update_current_regs(&regs).map_err(Error::from)
    }

    async fn stack(&mut self) -> Self::Stack {
        LocalStack::new()
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        let (number, args) = syscall.into_parts();
        let number = number.id() as i64;
        let raw_args = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        if let Some(error) = injected_syscall_guard(number, raw_args) {
            return Err(error);
        }
        if is_exit_syscall(number) {
            self.tail.set_exit(number, raw_args);
            return std::future::pending().await;
        }
        let result = unsafe { raw_syscall6(number, raw_args) };
        Errno::from_ret(result as usize).map(|value| value as i64)
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        let (number, syscall_args) = syscall.into_parts();
        let args = [
            syscall_args.arg0 as u64,
            syscall_args.arg1 as u64,
            syscall_args.arg2 as u64,
            syscall_args.arg3 as u64,
            syscall_args.arg4 as u64,
            syscall_args.arg5 as u64,
        ];
        let number = number.id() as i64;
        if let Some(error) = injected_syscall_guard(number, args) {
            self.tail.set_result(-i64::from(error.into_raw()));
        } else if is_exit_syscall(number) {
            self.tail.set_exit(number, args);
        } else {
            let value = unsafe { raw_syscall6(number, args) };
            self.tail.set_result(value);
        }
        std::future::pending().await
    }

    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "e9patch direct Tool host does not implement RCB timer delivery",
        )
        .into())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "e9patch direct Tool host does not implement precise RCB timer delivery",
        )
        .into())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "e9patch direct Tool host does not implement an RCB clock",
        )
        .into())
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review injected
// process/signal safety policy.
fn injected_syscall_guard(number: i64, args: [u64; 6]) -> Option<Errno> {
    let unsupported_process =
        // AUTONOMOUS-BOT-IMPLEMENTED
        matches!(number, libc::SYS_clone | libc::SYS_clone3 | libc::SYS_fork | libc::SYS_vfork)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || matches!(number, libc::SYS_execve | libc::SYS_execveat);
    let protected_signal =
        // AUTONOMOUS-BOT-IMPLEMENTED
        !signal_action_supported(number, args)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (number == libc::SYS_sigaltstack && args[0] != 0)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (number == libc::SYS_rt_sigprocmask && args[1] != 0);

    if unsupported_process {
        Some(Errno::EOPNOTSUPP)
    } else if protected_signal {
        Some(Errno::EPERM)
    } else {
        None
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review nested Tool syscall
// guards and trusted-gate forwarding.
fn forward_nested_tool_syscall(event: &mut SyscallEvent, coordinator_fd: libc::c_int) {
    let number = event.number();
    let args = event.args();
    let unsupported_process =
        // AUTONOMOUS-BOT-IMPLEMENTED
        matches!(number, libc::SYS_clone | libc::SYS_clone3 | libc::SYS_fork | libc::SYS_vfork)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || matches!(number, libc::SYS_execve | libc::SYS_execveat);
    let unsupported_signal_state =
        // AUTONOMOUS-BOT-IMPLEMENTED
        matches!(
            number,
            libc::SYS_rt_sigaction
                | libc::SYS_rt_sigprocmask
                | libc::SYS_sigaltstack
                | libc::SYS_rt_sigsuspend
                | libc::SYS_pselect6
                | libc::SYS_ppoll
                | libc::SYS_epoll_pwait
                | libc::SYS_epoll_pwait2
        );
    if unsupported_process {
        event.fail(libc::ENOTSUP);
    } else if unsupported_signal_state {
        event.fail(libc::EPERM);
    } else if !protect_coordinator_channel(event, coordinator_fd) {
        let result = unsafe { raw_syscall6(number, args) };
        event.set_result(result);
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review coordinator-channel
// descriptor virtualization.
fn protect_coordinator_channel(event: &mut SyscallEvent, coordinator_fd: libc::c_int) -> bool {
    let fd = coordinator_fd as u64;
    let number = event.number();
    let args = event.args();
    if number == libc::SYS_close && args[0] == fd {
        event.set_result(0);
    } else if number == libc::SYS_close_range && args[0] <= fd && fd <= args[1] {
        event.set_result(close_range_preserving_fd(args, fd));
    } else if syscall_targets_fd(number, args, fd) {
        event.fail(libc::EBADF);
    } else {
        return false;
    }
    true
}

// TODO-HUMAN-REVIEW(PR-269): Review close_range splitting
// around the reserved coordinator descriptor.
fn close_range_preserving_fd(args: [u64; 6], fd: u64) -> i64 {
    const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
    let first = args[0];
    let last = args[1];
    let mut flags = args[2];
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return -i64::from(libc::EINVAL);
    }
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        let result =
            unsafe { raw_syscall6(libc::SYS_unshare, [libc::CLONE_FILES as u64, 0, 0, 0, 0, 0]) };
        if result < 0 {
            return result;
        }
        flags &= !CLOSE_RANGE_UNSHARE;
    }
    if first < fd {
        let result =
            unsafe { raw_syscall6(libc::SYS_close_range, [first, fd - 1, flags, 0, 0, 0]) };
        if result < 0 {
            return result;
        }
    }
    if fd < last {
        let result = unsafe { raw_syscall6(libc::SYS_close_range, [fd + 1, last, flags, 0, 0, 0]) };
        if result < 0 {
            return result;
        }
    }
    0
}

// TODO-HUMAN-REVIEW(PR-269): Review syscalls classified
// as targeting the reserved coordinator descriptor.
fn syscall_targets_fd(number: i64, args: [u64; 6], fd: u64) -> bool {
    match number {
        // AUTONOMOUS-BOT-IMPLEMENTED
        libc::SYS_read
        | libc::SYS_readv
        | libc::SYS_pread64
        | libc::SYS_preadv
        | libc::SYS_preadv2
        | libc::SYS_write
        | libc::SYS_writev
        | libc::SYS_pwrite64
        | libc::SYS_pwritev
        | libc::SYS_pwritev2
        | libc::SYS_vmsplice
        | libc::SYS_sendfile
        | libc::SYS_fcntl
        | libc::SYS_ioctl
        | libc::SYS_dup => args[0] == fd,
        // AUTONOMOUS-BOT-IMPLEMENTED
        libc::SYS_dup2 | libc::SYS_dup3 => args[0] == fd || args[1] == fd,
        // AUTONOMOUS-BOT-IMPLEMENTED
        libc::SYS_splice | libc::SYS_copy_file_range => args[0] == fd || args[2] == fd,
        // AUTONOMOUS-BOT-IMPLEMENTED
        libc::SYS_tee => args[0] == fd || args[1] == fd,
        _ => false,
    }
}

#[repr(C)]
#[derive(Default)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

struct SignalInstallGuard {
    restore_mask: u64,
}

impl Drop for SignalInstallGuard {
    fn drop(&mut self) {
        let result = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    (&raw const self.restore_mask) as u64,
                    0,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            fatal(126);
        }
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review atomic signal-state
// preparation before installing the shared SIGSYS controller.
fn prepare_guest_signal_state() -> io::Result<SignalInstallGuard> {
    let sigsys = 1_u64 << (libc::SIGSYS - 1);
    let install_mask = u64::MAX;
    let mut previous_mask = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_SETMASK as u64,
                (&raw const install_mask) as u64,
                (&raw mut previous_mask) as u64,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error((-result) as i32));
    }
    let guard = SignalInstallGuard {
        restore_mask: previous_mask & !sigsys,
    };

    for signal in 1..=64 {
        if matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
            continue;
        }
        let mut action = KernelSigaction::default();
        let result = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigaction,
                [
                    signal as u64,
                    0,
                    (&raw mut action) as u64,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error((-result) as i32));
        }
        if action.handler != libc::SIG_DFL as u64 && action.handler != libc::SIG_IGN as u64 {
            let default_action = KernelSigaction::default();
            let result = unsafe {
                raw_syscall6(
                    libc::SYS_rt_sigaction,
                    [
                        signal as u64,
                        (&raw const default_action) as u64,
                        0,
                        core::mem::size_of::<u64>() as u64,
                        0,
                        0,
                    ],
                )
            };
            if result < 0 {
                return Err(io::Error::from_raw_os_error((-result) as i32));
            }
        }
    }
    Ok(guard)
}

// TODO-HUMAN-REVIEW(PR-269): Review fault-safe guest
// signal-action decoding.
fn signal_action_supported(number: i64, args: [u64; 6]) -> bool {
    if number != libc::SYS_rt_sigaction || args[1] == 0 {
        return true;
    }
    if args[0] == libc::SIGSYS as u64 {
        return false;
    }
    let mut handler = 0_u64;
    let local = libc::iovec {
        iov_base: (&raw mut handler).cast(),
        iov_len: core::mem::size_of::<u64>(),
    };
    let remote = libc::iovec {
        iov_base: args[1] as usize as *mut libc::c_void,
        iov_len: core::mem::size_of::<u64>(),
    };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let read = unsafe {
        raw_syscall6(
            libc::SYS_process_vm_readv,
            [
                pid as u64,
                (&raw const local) as u64,
                1,
                (&raw const remote) as u64,
                1,
                0,
            ],
        )
    };
    read == core::mem::size_of::<u64>() as i64
        && matches!(handler, value if value == libc::SIG_DFL as u64 || value == libc::SIG_IGN as u64)
}

pub(crate) struct LocalStack {
    arena: Box<[u8]>,
    offset: usize,
}

impl LocalStack {
    fn new() -> Self {
        Self {
            arena: vec![0; STACK_CAPACITY].into_boxed_slice(),
            offset: 0,
        }
    }

    fn allocate<'stack, V>(&mut self, value: V) -> AddrMut<'stack, V> {
        let align = core::mem::align_of::<V>();
        let base = self.arena.as_ptr() as usize;
        let start = (base + self.offset + align - 1) & !(align - 1);
        let offset = start - base;
        let end = offset + core::mem::size_of::<V>();
        assert!(end <= self.arena.len(), "e9patch guest stack overflow");
        let pointer = unsafe { self.arena.as_mut_ptr().add(offset).cast::<V>() };
        unsafe { pointer.write(value) };
        self.offset = end;
        AddrMut::from_raw(pointer as usize).expect("e9patch stack produced a null address")
    }
}

pub(crate) struct LocalStackGuard {
    arena: Option<Box<[u8]>>,
}

impl Drop for LocalStackGuard {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.take() {
            COMMITTED_STACKS.lock().push(arena);
        }
    }
}

impl Stack for LocalStack {
    type StackGuard = LocalStackGuard;

    fn size(&self) -> usize {
        self.offset
    }

    fn capacity(&self) -> usize {
        self.arena.len()
    }

    fn push<'stack, V>(&mut self, value: V) -> Addr<'stack, V> {
        self.allocate(value).into()
    }

    fn reserve<'stack, V>(&mut self) -> AddrMut<'stack, V> {
        let value = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        self.allocate(value)
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(LocalStackGuard {
            arena: Some(self.arena),
        })
    }
}

fn tool_fatal(status: i32, error: &Error) -> ! {
    let message = format!("reverie-e9patch tool error: {error:?}\n");
    unsafe {
        let _ = raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                message.as_ptr() as u64,
                message.len() as u64,
                0,
                0,
                0,
            ],
        );
    }
    fatal(status)
}

fn fatal(status: i32) -> ! {
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [status as u64, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_host_rejects_process_tree_injection() {
        assert_eq!(
            injected_syscall_guard(libc::SYS_clone, [0; 6]),
            Some(Errno::EOPNOTSUPP)
        );
        assert_eq!(
            injected_syscall_guard(libc::SYS_execve, [0; 6]),
            Some(Errno::EOPNOTSUPP)
        );
    }

    #[test]
    fn direct_host_stack_commits_allocations() {
        let mut stack = LocalStack::new();
        let value = stack.push(41_u64);
        assert_ne!(value.as_raw(), 0);
        assert_eq!(stack.size(), core::mem::size_of::<u64>());
        drop(stack.commit().unwrap());
        COMMITTED_STACKS.lock().clear();
    }

    #[test]
    fn startup_runtime_provenance_is_bounded_to_injected_code() {
        let maps = concat!(
            "00400000-00401000 r-xp 00000000 00:00 0 /tmp/guest\n",
            "20e9e9000-20e9ea000 r-xp 00000000 00:00 0 /tmp/guest\n",
            "7f000000-7f001000 rw-p 00000000 00:00 0\n",
        );
        assert_eq!(
            executable_mapping_containing(maps, E9PATCH_LOADER_BASE),
            Some(ExecutableRange {
                start: E9PATCH_LOADER_BASE,
                end: 0x20e9_ea000,
            })
        );
        assert!(crate::aot::AOT_PAYLOAD_TEXT_START < crate::aot::AOT_PAYLOAD_TEXT_END);
        assert!(
            ExecutableRange {
                start: crate::aot::AOT_PAYLOAD_TEXT_START,
                end: crate::aot::AOT_PAYLOAD_TEXT_END,
            }
            .contains(crate::E9PATCH_SYSCALL_TRAP_RIP)
        );
        assert_eq!(executable_mapping_containing(maps, 0x7f000100), None);
    }

    #[test]
    fn residual_subscription_exempts_only_pre_activation_runtime_code() {
        assert!(!residual_must_fail_closed(true, false, true));
        assert!(residual_must_fail_closed(true, false, false));
        assert!(residual_must_fail_closed(true, true, true));
        assert!(residual_must_fail_closed(true, true, false));
        assert!(!residual_must_fail_closed(false, true, false));
    }
}
