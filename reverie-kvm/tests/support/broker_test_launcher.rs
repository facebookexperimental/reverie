// Ordinary-main launcher for the explicitly broker-routed libtest selectors.
// This private proposal depends on the API contracts listed in API-CONTRACT.md.
// No constructor, libtest worker or lazy backend path may assert startup authority.
use std::ffi::CString;
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

use reverie_kvm::native_exit_broker::BrokerOwner;
use reverie_kvm::native_exit_broker::StartupAuthority;

#[path = "broker_test_protocol.rs"]
mod broker_test_protocol;

#[path = "broker_native_cases.rs"]
mod broker_native_cases;

#[path = "broker_client_death_cases.rs"]
mod broker_client_death_cases;

#[path = "broker_bootstrap_cases.rs"]
mod broker_bootstrap_cases;

#[path = "broker_fatal_abort_cases.rs"]
mod broker_fatal_abort_cases;

fn main() {
    broker_client_death_cases::dispatch_client_child();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--bootstrap-case" {
        std::process::exit(broker_bootstrap_cases::run(&args[1]));
    }
    if args.len() == 2 && args[0] == "--native-case" {
        let mode = match args[1].as_str() {
            "broker-sigchld-ignore" => Some(broker_client_death_cases::ParentSigchldMode::Ignore),
            "broker-sigchld-nocldwait" => {
                Some(broker_client_death_cases::ParentSigchldMode::NoChildWait)
            }
            _ => None,
        };
        if let Some(mode) = mode {
            // SAFETY: only argv parsing ran; no thread, guest descriptor or
            // independent fd/reaper owner exists in this ordinary launcher.
            let authority = unsafe { StartupAuthority::assert_exclusive_early_launch() };
            match broker_client_death_cases::run_unexeced_sigchld_case(authority, mode) {
                Ok(r) => {
                    println!(
                        "SIGCHLD_CASE_RECEIPT mode={:?} broker_pid={} broker_actual_wait_status={} worker_pid={} worker_job={} worker_status={} socket_references={} acknowledged_descriptors={} parent_references_retired={} parent_action_unchanged={} original_action_restored={}",
                        r.mode,
                        r.broker_pid,
                        r.broker_actual_wait_status,
                        r.worker_actual_wait.native_pid,
                        r.worker_actual_wait.job,
                        r.worker_actual_wait.raw_wait_status,
                        r.worker_actual_wait.socket_references,
                        r.worker_actual_wait.acknowledged_descriptors,
                        r.worker_actual_wait.parent_references_retired,
                        r.parent_action_unchanged_during_case,
                        r.original_action_restored
                    );
                    println!(
                        "NATIVE_BROKER_CASE_PASS case={:?} broker_reaped=true",
                        args[1]
                    );
                    return;
                }
                Err(failure) => {
                    eprintln!("SIGCHLD_CASE_FAILURE: {}", failure.message);
                    failure.print_retained_owners();
                    retain_for_outer_guard(failure);
                }
            }
        }
    }
    // SAFETY: this standalone executable's bootstrap precedes all
    // threads, logging, test/native children and guest resources. Its controlled
    // startup must satisfy StartupAuthority's full inherited-fd/reaper contract;
    // it is not a general embedding or injected-constructor entry point.
    let authority = unsafe { StartupAuthority::assert_exclusive_early_launch() };
    let mut owner = match BrokerOwner::bootstrap(authority) {
        Ok(owner) => owner,
        Err(failure) => {
            eprintln!("BROKER_LAUNCH_SETUP_FAILURE: {}", failure.cause);
            if failure.child.is_some() {
                retain_for_outer_guard(failure);
            }
            std::process::exit(125);
        }
    };
    if args.len() == 2 && args[0] == "--fatal-abort-case" {
        std::process::exit(broker_fatal_abort_cases::run(owner, &args[1]));
    }
    if std::env::args().nth(1).as_deref() == Some("--native-case") {
        // The helper owns the actual broker through every return/retention path.
        let code = run_native_case(owner, std::env::args().skip(2).collect());
        std::process::exit(code);
    }
    let outcome = launch_selected(&owner);
    let shutdown = settle_broker(&mut owner);
    if let Err(error) = shutdown {
        eprintln!("BROKER_LAUNCH_INFRASTRUCTURE_FAILURE: {error}");
        // No blocking destructor and no dropped/unconfirmed native wait owner.
        // The existing enclosing timeout owns the entire non-escaped group.
        retain_for_outer_guard(owner);
    }
    let status = match outcome {
        Ok(status) => status,
        Err(error) => {
            eprintln!("BROKER_LAUNCH_SETUP_FAILURE: {error}");
            std::process::exit(125);
        }
    };
    drop(owner); // Already actually reaped. No guest socket owners live here.
    mirror_status(status);
}

#[derive(Clone, Copy)]
struct BrokerWaitReceipt {
    native_pid: libc::pid_t,
    raw_wait_status: i32,
}

fn print_broker_wait(receipt: BrokerWaitReceipt) {
    println!(
        "NATIVE_CASE_BROKER_WAIT native_pid={} raw_wait_status={} actual_wait=true",
        receipt.native_pid, receipt.raw_wait_status
    );
}

fn print_before_drain(before: &broker_native_cases::BeforeDrainRecord) {
    println!(
        "NATIVE_CASE_BEFORE_DRAIN bound_millis={} observed_micros={} completed_before_drain={} receipt_observed_after_bound={} stage_at_deadline={:?} parent_references_retired_at_deadline={} last_owner_case={}",
        before.bound_millis,
        before.observed_micros,
        before.completed_before_drain,
        before.receipt_observed_after_bound,
        before.stage_at_deadline,
        before.parent_references_retired_at_deadline,
        before.last_owner_case
    );
}

fn print_case_receipt(receipt: &broker_native_cases::CaseReceipt) {
    println!(
        "NATIVE_CASE_RECEIPT case={:?} wait_count={} sent={} outq={} notsent={} first_chunk_acknowledged={} fault_present={} before_drain_present={}",
        receipt.case,
        receipt.waits.len(),
        receipt.sent,
        receipt.outq,
        receipt.notsent,
        receipt.first_chunk_acknowledged,
        receipt.fault.is_some(),
        receipt.before_drain.is_some()
    );
    for (index, wait) in receipt.waits.iter().enumerate() {
        println!(
            "NATIVE_CASE_WORKER_WAIT index={} job={} native_pid={} raw_wait_status={} socket_references={} acknowledged_descriptors={} parent_references_retired={} actual_wait=true",
            index,
            wait.job,
            wait.native_pid,
            wait.raw_wait_status,
            wait.socket_references,
            wait.acknowledged_descriptors,
            wait.parent_references_retired
        );
    }
    if let Some(fault) = &receipt.fault {
        println!(
            "NATIVE_CASE_RESOURCE_FAULT limited_worker_pid={} limited_worker_start_ticks={} private_fds={:?} applied_soft={} original_soft={} original_hard={}",
            fault.limited_worker_pid,
            fault.limited_worker_start_ticks,
            fault.private_fds,
            fault.applied_soft,
            fault.original_soft,
            fault.original_hard
        );
    }
    if let Some(before) = &receipt.before_drain {
        print_before_drain(before);
    }
}

fn print_case_failure(failure: &broker_native_cases::CaseFailure) {
    eprintln!(
        "NATIVE_CASE_FAILURE_DETAIL classification={} message={:?}",
        failure.classification(),
        failure.message
    );
    if let Some(before) = &failure.observation {
        print_before_drain(before);
    }
    if let Some(cleanup) = &failure.cleanup {
        println!(
            "NATIVE_CASE_LOCAL_CLEANUP completed_native_waits={} supplied_file_references={} foreign_file_reference={} active_worker_limit={} retained_unexpected_rights={} native_job_complete={} queued_stream_exact_and_eof={} broker_shutdown_still_required={}",
            cleanup.completed_native_waits,
            cleanup.supplied_file_references,
            cleanup.foreign_file_reference,
            cleanup.active_worker_limit,
            cleanup.retained_unexpected_rights,
            cleanup.native_job_complete,
            cleanup.queued_stream_exact_and_eof,
            cleanup.broker_shutdown_still_required
        );
    }
    if let Some(receipt) = &failure.completed_receipt {
        print_case_receipt(receipt);
    }
    failure.resources.print_retained_owners();
}

fn settle_native_broker(owner: &mut BrokerOwner) -> BrokerWaitReceipt {
    match settle_broker(owner) {
        Ok(receipt) => {
            print_broker_wait(receipt);
            receipt
        }
        Err(error) => {
            eprintln!("NATIVE_BROKER_CASE_SETTLEMENT_FAILURE: {error}");
            // The actual owner remains on this live stack. No empty-child claim
            // or successful/nonzero semantic completion is emitted without wait.
            retain_for_outer_guard(owner);
        }
    }
}

fn run_native_case(mut owner: BrokerOwner, args: Vec<String>) -> i32 {
    if args.len() != 1
        || !matches!(
            args[0].as_str(),
            "single"
                | "shared-arc"
                | "nested-scm"
                | "chunk-resource-abort"
                | "exported-client-death"
        )
    {
        eprintln!("NATIVE_BROKER_CASE_SETUP_FAILURE: exactly one known native case required");
        settle_native_broker(&mut owner);
        drop(owner);
        return 125;
    }
    let case = &args[0];
    if case == "exported-client-death" {
        match broker_client_death_cases::run_exported_client_death(&owner) {
            Ok(r) => {
                println!(
                    "EXPORTED_CLIENT_DEATH_RECEIPT launcher_pid={} broker_pid={} client_pid={} client_wait_status={} worker_pid={} worker_job={} worker_wait_status={} complete_acknowledged={} original_references_retired={} worker_error_errno_after_protocol_eof={} broker_live_after_worker_wait={} peer_eof_after_native_wait={}",
                    r.launcher_pid,
                    r.broker_pid,
                    r.client_pid,
                    r.client_wait_status,
                    r.worker_pid,
                    r.worker_job,
                    r.worker_wait_status,
                    r.complete_acknowledged,
                    r.original_references_retired,
                    r.worker_error_errno_after_protocol_eof,
                    r.broker_live_after_worker_wait,
                    r.peer_eof_after_native_wait
                );
                settle_native_broker(&mut owner);
                drop(owner);
                println!("NATIVE_BROKER_CASE_PASS case={case:?} broker_reaped=true");
                return 0;
            }
            Err(failure) => {
                eprintln!("EXPORTED_CLIENT_DEATH_FAILURE: {}", failure.message);
                failure.print_retained_owners();
                retain_for_outer_guard((owner, failure));
            }
        }
    }
    let result = if case == "chunk-resource-abort" {
        broker_native_cases::run_chunk_abort_case(&owner)
    } else {
        broker_native_cases::run_queued_case(case, &owner.client())
    };
    match result {
        Ok(receipt) => {
            print_case_receipt(&receipt);
            settle_native_broker(&mut owner);
            drop(owner);
            println!(
                "NATIVE_BROKER_CASE_PASS case={case:?} worker_receipts={} broker_reaped=true",
                receipt.waits.len()
            );
            0
        }
        Err(failure) => {
            print_case_failure(&failure);
            if failure.cleaned_observation_miss() {
                let causal = failure.causal_last_close_witness();
                let classification = failure.classification();
                // This branch checks the real empty resource state, exact stream
                // and actual worker wait first; it does not format/drop owners.
                drop(failure);
                settle_native_broker(&mut owner);
                drop(owner);
                eprintln!(
                    "NATIVE_BROKER_CASE_FAILED_AFTER_CLEANUP case={case:?} classification={classification} causal_last_close_witness={causal} original_observation_millis=5000 broker_reaped=true"
                );
                101
            } else {
                eprintln!(
                    "NATIVE_BROKER_CASE_INFRASTRUCTURE_FAILURE case={case:?} cleanup_unconfirmed=true causal_mutant_detection=false"
                );
                retain_for_outer_guard((owner, failure));
            }
        }
    }
}

fn launch_selected(owner: &BrokerOwner) -> Result<i32, String> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() != 6 || args[1] != "--exact" || args[3] != "--nocapture" || args[4] != "--logfile"
    {
        return Err("expected exact existing libtest argument shape".into());
    }
    let test = args[2].to_str().ok_or("test name must be UTF-8")?;
    if !broker_test_protocol::selected(test) {
        return Err("test is not an explicitly broker-enrolled selector".into());
    }
    if !std::path::Path::new(&args[0]).is_absolute()
        || !std::path::Path::new(&args[5]).is_absolute()
    {
        return Err("libtest executable/result path must be absolute".into());
    }
    let exported = match owner.export_client_for_exec() {
        Ok(exported) => exported,
        Err(failure) => {
            eprintln!("BROKER_LAUNCH_SETUP_FAILURE: {}", failure.cause);
            // Keep channel and any unexpected SCM_RIGHTS owner, including a
            // received prefix. Formatting an error must not drop those owners.
            retain_for_outer_guard(failure);
        }
    };
    let (channel, nonce) = exported.into_parts();
    let fd = channel.as_raw_fd();
    if fd < 3 {
        return Err("exported client must not alias stdio".into());
    }
    let encoded: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut environment: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(key, _)| {
            key != broker_test_protocol::CHANNEL_ENV
                && key != broker_test_protocol::NONCE_ENV
                && key != broker_test_protocol::CHILD_ENV
        })
        .collect();
    environment.push((
        broker_test_protocol::CHANNEL_ENV.into(),
        fd.to_string().into(),
    ));
    environment.push((broker_test_protocol::NONCE_ENV.into(), encoded.into()));
    environment.push((broker_test_protocol::CHILD_ENV.into(), test.into()));
    let argv: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let env: Vec<CString> = environment
        .into_iter()
        .map(|(key, value)| {
            let mut bytes = key.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            CString::new(bytes).map_err(|e| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|s| s.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());

    let all = u64::MAX;
    let mut old = 0u64;
    let blocked = unsafe {
        raw(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK as usize,
            (&all as *const u64) as usize,
            (&mut old as *mut u64) as usize,
            8,
            0,
            0,
        )
    };
    if blocked < 0 {
        return Err(format!("block clone mask: {}", -blocked));
    }
    // flags0 starts a separate native process with exit_signal0. It is not a
    // thread, vfork, shared fd table or CLONE_PARENT child. The child execs below;
    // Linux exec then resets exit_signal to SIGCHLD. Parent never execs.
    let pid = unsafe { raw(libc::SYS_clone, 0, 0, 0, 0, 0, 0) };
    if pid == 0 {
        // No allocator, Rust Drop, libc TLS errno, panic or callback in child.
        let inherited = unsafe {
            raw(
                libc::SYS_fcntl,
                fd as usize,
                libc::F_SETFD as usize,
                0,
                0,
                0,
                0,
            )
        };
        if inherited < 0 {
            unsafe { exit_raw(125) }
        }
        let restored = unsafe {
            raw(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                (&old as *const u64) as usize,
                0,
                8,
                0,
                0,
            )
        };
        if restored < 0 {
            unsafe { exit_raw(125) }
        }
        unsafe {
            raw(
                libc::SYS_execve,
                argv[0].as_ptr() as usize,
                argv_ptrs.as_ptr() as usize,
                env_ptrs.as_ptr() as usize,
                0,
                0,
                0,
            )
        };
        unsafe { exit_raw(125) }
    }
    let restored = unsafe {
        raw(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK as usize,
            (&old as *const u64) as usize,
            0,
            8,
            0,
            0,
        )
    };
    if restored < 0 {
        eprintln!(
            "BROKER_LAUNCH_INFRASTRUCTURE_FAILURE: parent mask restore {}",
            -restored
        );
        // Even a failed clone does not permit continuing under the wrong mask.
        retain_for_outer_guard((channel, pid));
    }
    if pid < 0 {
        return Err(format!("clone exact libtest child: {}", -pid));
    }
    drop(channel); // Child has its inherited dedicated endpoint; owner stays here.
    let mut status = 0i32;
    // Linux exec changes the clone0 child's exit-signal class to SIGCHLD:
    // https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/exec.c
    // __WALL accepts both pre-exec clone0 failure and the post-exec SIGCHLD
    // child, but the exact positive PID still forbids reaping another child.
    // __WCLONE alone excludes the exec child; ECHILD must remain a failure.
    // BrokerOwner never execs and retains its separate __WCLONE wait contract.
    loop {
        let waited = unsafe {
            raw(
                libc::SYS_wait4,
                pid as usize,
                (&mut status as *mut i32) as usize,
                libc::__WALL as usize,
                0,
                0,
                0,
            )
        };
        if waited == pid {
            return Ok(status);
        }
        if waited == -(libc::EINTR as i64) {
            continue;
        }
        eprintln!("BROKER_LAUNCH_INFRASTRUCTURE_FAILURE: exact child wait {waited}");
        retain_for_outer_guard((pid, status));
    }
}

fn settle_broker(owner: &mut BrokerOwner) -> Result<BrokerWaitReceipt, String> {
    let native_pid = owner.native_pid();
    loop {
        if owner.request_shutdown().map_err(|e| e.to_string())? {
            break;
        }
        wait_interest(owner.shutdown_poll_interest())?;
    }
    loop {
        if let Some(status) = owner.try_wait().map_err(|e| e.to_string())? {
            return if status == 0 {
                Ok(BrokerWaitReceipt {
                    native_pid,
                    raw_wait_status: status,
                })
            } else {
                Err(format!("broker native status {status}"))
            };
        }
        let interest = owner
            .exit_poll_interest()
            .ok_or("unreaped owner has no pidfd")?;
        wait_interest(interest)?;
    }
}

fn wait_interest(mut fd: libc::pollfd) -> Result<(), String> {
    loop {
        let result = unsafe { libc::poll(&mut fd, 1, -1) };
        if result > 0 && fd.revents & libc::POLLNVAL == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if result < 0 && error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(format!(
            "broker progress poll: {result}, revents={}, {error}",
            fd.revents
        ));
    }
}

// This is a terminal infrastructure failure, never an accepted guest/test result.
// Retain owned state without unwinding until the unchanged outer30+kill2 guard
// retires this launcher and its non-escaped children. No new private timeout.
fn retain_for_outer_guard<T>(state: T) -> ! {
    loop {
        std::hint::black_box(&state);
        unsafe {
            libc::pause();
        }
    }
}

fn mirror_status(status: i32) -> ! {
    if libc::WIFEXITED(status) {
        std::process::exit(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        // Only this isolated launcher changes its own final disposition/mask;
        // the caller's ambient SIGCHLD state was never changed.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, signal);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            raw(
                libc::SYS_tgkill,
                libc::getpid() as usize,
                raw(libc::SYS_gettid, 0, 0, 0, 0, 0, 0) as usize,
                signal as usize,
                0,
                0,
                0,
            );
        }
        std::process::exit(128 + signal);
    }
    eprintln!("BROKER_LAUNCH_INFRASTRUCTURE_FAILURE: nonterminal wait status {status}");
    std::process::exit(125);
}

unsafe fn exit_raw(code: usize) -> ! {
    unsafe {
        raw(libc::SYS_exit_group, code, 0, 0, 0, 0, 0);
    }
    loop {
        std::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn raw(
    number: libc::c_long,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!("syscall", inlateout("rax") number => result,
            in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d,
            in("r8") e, in("r9") f, lateout("rcx") _, lateout("r11") _,
            options(nostack));
    }
    result
}
