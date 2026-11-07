//! Native early-main fatal-invocation controls, never a libtest bootstrap.
//! These case bodies reuse the existing launcher startup and 30s/kill2s guard.
//! Exit125 is established only by an external actual wait, not this marker.
use std::mem::ManuallyDrop;

use reverie_kvm::native_exit_broker::BrokerOwner;

struct DropSentinel;
impl Drop for DropSentinel {
    fn drop(&mut self) {
        // Raw owned stderr avoids a second panic masking the sentinel.
        let marker = b"FATAL_ABORT_RUST_DESTRUCTOR_RAN\n";
        unsafe {
            crate::raw(
                libc::SYS_write,
                2,
                marker.as_ptr() as usize,
                marker.len(),
                0,
                0,
                0,
            );
        }
    }
}

pub fn run(mut owner: BrokerOwner, name: &str) -> i32 {
    match name {
        "original-creator" => abort_original(owner),
        "wrong-process" => wrong_process(owner),
        _ => {
            // Unknown argv is setup failure, never a qualifying exit125.
            let waited = crate::settle_native_broker(&mut owner);
            assert_eq!(waited.raw_wait_status, 0);
            eprintln!("FATAL_ABORT_CASE_SETUP_FAILURE unknown_case={name}");
            125
        }
    }
}

fn abort_original(owner: BrokerOwner) -> ! {
    let sentinel = DropSentinel;
    println!(
        "FATAL_ABORT_CASE_READY case=original-creator creator_pid={} creator_tid={} broker_pid={} native_wait=false",
        unsafe { libc::getpid() },
        unsafe { libc::syscall(libc::SYS_gettid) },
        owner.native_pid()
    );
    if let Err(error) = std::io::Write::flush(&mut std::io::stdout()) {
        eprintln!("FATAL_ABORT_CASE_SETUP_FAILURE marker_flush={error}");
        crate::retain_for_outer_guard((owner, sentinel));
    }
    if let Err(error) = install_park_trap() {
        eprintln!("FATAL_ABORT_CASE_SETUP_FAILURE park_trap={error}");
        crate::retain_for_outer_guard((owner, sentinel));
    }
    let marker = b"FATAL_ABORT_FILTER_ARMED futex_and_pause=true\n";
    unsafe {
        crate::raw(
            libc::SYS_write,
            1,
            marker.as_ptr() as usize,
            marker.len(),
            0,
            0,
            0,
        );
    }
    std::hint::black_box(&sentinel);
    // SAFETY: this isolated case explicitly selects failed invocation abort.
    // No guest result, normal shutdown, or cleanup receipt is claimed. The
    // surrounding test supervisor retains native child identities and waits.
    match unsafe { owner.abort_failed_invocation() } {
        Ok(never) => match never {},
        Err((error, owner)) => {
            eprintln!("FATAL_ABORT_CASE_REFUSED exact_creator=true cause={error}");
            crate::retain_for_outer_guard((owner, sentinel, error));
        }
    }
}

fn wrong_process(mut owner: BrokerOwner) -> i32 {
    let original_broker = owner.native_pid();
    let original_pidfd = owner
        .exit_poll_interest()
        .expect("unreaped native owner pidfd")
        .fd;
    // This launcher is still single threaded. The deliberately inherited owner
    // is used only for the negative identity check; no inherited client is
    // adopted, no job starts, and the child executes no Rust Drop.
    let child = unsafe { crate::raw(libc::SYS_clone, 0, 0, 0, 0, 0, 0) };
    if child == 0 {
        match unsafe { owner.abort_failed_invocation() } {
            Ok(never) => match never {},
            Err((error, returned)) => {
                let same_pidfd =
                    returned.exit_poll_interest().map(|p| p.fd) == Some(original_pidfd);
                let inherited_refused = returned
                    .client()
                    .authenticated_broker_identity()
                    .is_err_and(|e| {
                        e.errno == libc::EPROTO && e.operation == "fork-inherited broker identity"
                    });
                let exact = error.errno == libc::EPROTO
                    && error.operation == "native broker owner changed process/thread"
                    && returned.native_pid() == original_broker
                    && same_pidfd
                    && inherited_refused;
                let _retained = ManuallyDrop::new((returned, error));
                let marker: &[u8] = if exact {
                    b"FATAL_ABORT_WRONG_PROCESS_REFUSED same_owner=true inherited_client_refused=true\n"
                } else {
                    b"FATAL_ABORT_WRONG_PROCESS_MISMATCH\n"
                };
                unsafe {
                    crate::raw(
                        libc::SYS_write,
                        1,
                        marker.as_ptr() as usize,
                        marker.len(),
                        0,
                        0,
                        0,
                    );
                    crate::exit_raw(if exact { 0 } else { 101 });
                }
            }
        }
    }
    if child < 0 {
        let waited = crate::settle_native_broker(&mut owner);
        assert_eq!(waited.raw_wait_status, 0);
        eprintln!("FATAL_ABORT_CASE_SETUP_FAILURE clone_errno={}", -child);
        return 125;
    }
    let mut status = 0i32;
    loop {
        let rc = unsafe {
            crate::raw(
                libc::SYS_wait4,
                child as usize,
                (&mut status as *mut i32) as usize,
                libc::__WALL as usize,
                0,
                0,
                0,
            )
        };
        if rc == child {
            break;
        }
        if rc == -(libc::EINTR as i64) {
            continue;
        }
        eprintln!("FATAL_ABORT_CASE_INFRASTRUCTURE_FAILURE exact_child_wait={rc}");
        crate::retain_for_outer_guard((owner, child, status));
    }
    // All actual native ownership is settled BEFORE the semantic assertion.
    let broker_wait = crate::settle_native_broker(&mut owner);
    drop(owner);
    println!(
        "FATAL_ABORT_WRONG_PROCESS_CLEANUP child_pid={child} child_wait_status={status} broker_pid={} broker_wait_status={} actual_waits=2",
        broker_wait.native_pid, broker_wait.raw_wait_status
    );
    assert_eq!(
        status, 0,
        "wrong creator must receive its owner, not abort or succeed"
    );
    assert_eq!(broker_wait.native_pid, original_broker);
    assert_eq!(broker_wait.raw_wait_status, 0);
    0
}

// A causal OLD-PARK mutant detector, not a duration-to-success conversion.
// Installed only at the fatal API call site, after ordinary bootstrap/logging.
// Correct exit does not invoke a userspace parking syscall. The existing
// outer timeout remains an infrastructure safety bound and is NEVER accepted
// as a kill criterion for this control.
extern "C" fn park_trap(_signal: libc::c_int) {
    let marker = b"FATAL_ABORT_PARK_SYSCALL_TRAPPED causal_failure=true\n";
    unsafe {
        crate::raw(
            libc::SYS_write,
            2,
            marker.as_ptr() as usize,
            marker.len(),
            0,
            0,
            0,
        );
        crate::exit_raw(101);
    }
}

fn install_park_trap() -> Result<(), String> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = park_trap as *const () as usize;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
        || unsafe { libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()) } != 0
    {
        return Err(format!(
            "SIGSYS test handler: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut one: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut one);
        libc::sigaddset(&mut one, libc::SIGSYS);
    }
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &one, std::ptr::null_mut()) } != 0 {
        return Err(format!(
            "unblock owned SIGSYS: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let ret = libc::BPF_RET | libc::BPF_K;
    // Exactly x86-64 native syscalls; unknown architecture is setup failure.
    let filter = [
        stmt(load, 4),
        jump(0xc000_003e, 1, 0),
        stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(load, 0),
        jump(libc::SYS_futex as u32, 2, 0),
        jump(libc::SYS_pause as u32, 1, 0),
        stmt(ret, libc::SECCOMP_RET_ALLOW),
        stmt(ret, libc::SECCOMP_RET_TRAP),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "owned NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        return Err(format!(
            "park trap install: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
