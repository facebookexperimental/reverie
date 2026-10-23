//! Real stopped-birth descriptor controls; no runtime entry is released.
use std::os::fd::AsRawFd;

use super::*;

fn stopped() -> InitialExecStop<'static> {
    let request = PreparedExec::new(
        std::path::Path::new("/bin/true"),
        &["held-birth-pidfd-control".into()],
        &[],
        None,
        vec![],
    )
    .unwrap();
    ExecStop::spawn(request, CleanupReceipt::default()).unwrap()
}

#[test]
fn held_birth_pidfd_is_cloexec_and_does_not_change_the_stop() {
    let stop = stopped();
    let before = register_words(&stop.task.getregs().unwrap());
    let duplicate = stop.duplicate_birth_pidfd().unwrap();
    assert_ne!(duplicate.as_raw_fd(), stop.owner.birth_pidfd.as_raw_fd());
    // SAFETY: query only this actual owned descriptor.
    let flags = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    live_birth_pidfd(&duplicate).unwrap();
    assert_eq!(register_words(&stop.task.getregs().unwrap()), before);
    let cleanup = stop.cancel().unwrap();
    assert!(cleanup.confirmed);
    assert_eq!(
        live_birth_pidfd(&duplicate).unwrap_err().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn held_birth_pidfd_refuses_another_real_stopped_generation() {
    let first = stopped();
    let second = stopped();
    let error = first.owner.duplicate_birth_pidfd(&second.task).unwrap_err();
    assert!(error.to_string().contains("foreign_generation"));
    assert!(first.cancel().unwrap().confirmed);
    assert!(second.cancel().unwrap().confirmed);
}

#[test]
fn held_birth_pidfd_refuses_a_different_real_host_thread() {
    let stop = stopped();
    let guard = stop.owner._thread.as_ref().unwrap().clone();
    // The test passes the real retained kernel object to a foreign host thread;
    // only the original-thread predicate may permit the production operation.
    let fd = stop.owner.birth_pidfd.try_clone().unwrap();
    let refused = std::thread::spawn(move || match duplicate_guarded_birth_pidfd(&guard, &fd) {
        Ok(_) => false,
        Err(error) => error.downcast_ref::<safeptrace::Errno>() == Some(&safeptrace::Errno::EPERM),
    })
    .join()
    .unwrap();
    assert!(refused);
    assert!(stop.cancel().unwrap().confirmed);
}

#[test]
fn held_birth_pidfd_refuses_after_actual_owner_retirement() {
    let InitialExecStop {
        task, mut owner, ..
    } = stopped();
    owner.retire();
    assert!(owner.receipt.snapshot().confirmed);
    let error = owner.duplicate_birth_pidfd(&task).unwrap_err();
    assert!(error.to_string().contains("retired_or_foreign_generation"));
}

// Changing a process-wide rlimit is valid only in its own exact test process.
// This ignored body must be explicitly selected with the named opt-in; it is
// never counted as a pass from an ordinary skipped inventory row.
#[test]
#[ignore = "explicit isolated one-body RLIMIT_NOFILE control"]
fn held_birth_pidfd_actual_emfile_keeps_the_original_owner() {
    assert_eq!(
        std::env::var_os("REVERIE_HELD_BIRTH_FD_LIMIT_CONTROL"),
        Some("1".into())
    );
    let stop = stopped();
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: actual process limit query with a fully initialized output.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut original) },
        0
    );
    stop.owner
        ._thread
        .as_ref()
        .unwrap()
        .check_current()
        .unwrap();
    // A zero limit rejects poll(nfds=1) with EINVAL before duplication. Keep
    // poll and F_DUPFD_CLOEXEC's minimum legal, then exhaust real descriptors.
    let ceiling = original.rlim_cur.min(64);
    assert!(
        ceiling >= 4,
        "descriptor-exhaustion control needs four slots"
    );
    let mut retained = Vec::with_capacity(ceiling as usize);
    let limited = libc::rlimit {
        rlim_cur: ceiling,
        rlim_max: original.rlim_max,
    };
    // SAFETY: this explicitly isolated body owns the temporary soft limit.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
    let mut fill_error = None;
    for _ in 0..ceiling {
        match stop.owner.birth_pidfd.try_clone() {
            Ok(fd) => retained.push(fd),
            Err(error) => {
                fill_error = Some(error);
                break;
            }
        }
    }
    // Test the exact private fcntl/liveness operation after actual guard check.
    // Guard rechecks can need procfs FDs on legacy kernels, so a full public
    // preflight under this limit would not isolate the fcntl failure predicate.
    let result = duplicate_live_birth_pidfd(&stop.owner.birth_pidfd);
    // SAFETY: restore before diagnostics, cancellation or any further FD open.
    let restored = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) };
    drop(retained);
    assert_eq!(restored, 0);
    assert_eq!(
        fill_error.and_then(|error| error.raw_os_error()),
        Some(libc::EMFILE)
    );
    let error = result.unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error),
        Some(libc::EMFILE)
    );
    assert!(stop.duplicate_birth_pidfd().is_ok());
    assert!(stop.cancel().unwrap().confirmed);
}

#[test]
fn held_birth_inherited_descriptor_checks_actual_request_before_export() {
    use std::os::fd::AsFd;
    let (inherited, other) = std::os::unix::net::UnixStream::pair().unwrap();
    let alias = inherited.try_clone().unwrap();
    let request = PreparedExec::new(
        std::path::Path::new("/bin/true"),
        &["held-inherited-descriptor-control".into()],
        &[],
        None,
        vec![inherited.as_fd()],
    )
    .unwrap();
    let stop = ExecStop::spawn(request, CleanupReceipt::default()).unwrap();
    let before = register_words(&stop.task.getregs().unwrap());
    let birth = stop
        .duplicate_birth_pidfd_for_inherited(inherited.as_fd())
        .unwrap();
    live_birth_pidfd(&birth).unwrap();
    // Even a same-OFD duplicate is not the descriptor borrowed by this request.
    for fd in [alias.as_fd(), other.as_fd()] {
        assert_eq!(
            stop.duplicate_birth_pidfd_for_inherited(fd)
                .unwrap_err()
                .to_string(),
            "exec_stop_descriptor_not_inherited"
        );
    }
    assert_eq!(register_words(&stop.task.getregs().unwrap()), before);
    assert!(stop.cancel().unwrap().confirmed);
}

#[test]
fn inherited_descriptor_bridge_preserves_original_rule_and_held_context() {
    use std::os::fd::AsFd;
    let inherited = std::fs::File::open("/dev/null").unwrap();
    let alias = inherited.try_clone().unwrap();
    let same_inode = std::fs::File::open("/dev/null").unwrap();
    let request = PreparedExec::new(
        std::path::Path::new("/bin/true"),
        &["inherited-birth-custody-control".into()],
        &[],
        None,
        vec![inherited.as_fd()],
    )
    .unwrap();
    let stop = ExecStop::spawn(request, CleanupReceipt::default()).unwrap();
    let before = register_words(&stop.task.getregs().unwrap());
    let accepted = stop.duplicate_birth_pidfd_for_inherited(inherited.as_fd());
    let alias_error = stop
        .duplicate_birth_pidfd_for_inherited(alias.as_fd())
        .err()
        .map(|e| e.to_string());
    let inode_error = stop
        .duplicate_birth_pidfd_for_inherited(same_inode.as_fd())
        .err()
        .map(|e| e.to_string());
    let after = register_words(&stop.task.getregs().unwrap());
    assert!(stop.cancel().unwrap().confirmed);
    assert!(accepted.is_ok());
    assert_eq!(
        alias_error.as_deref(),
        Some("exec_stop_descriptor_not_inherited")
    );
    assert_eq!(
        inode_error.as_deref(),
        Some("exec_stop_descriptor_not_inherited")
    );
    assert_eq!(before, after);
}

#[test]
fn inherited_descriptor_bridge_checks_actual_generation_before_request() {
    use std::os::fd::AsFd;
    let inherited = std::fs::File::open("/dev/null").unwrap();
    let request = PreparedExec::new(
        std::path::Path::new("/bin/true"),
        &["inherited-generation-control".into()],
        &[],
        None,
        vec![inherited.as_fd()],
    )
    .unwrap();
    let first = ExecStop::spawn(request, CleanupReceipt::default()).unwrap();
    let second = stopped();
    let error = first
        .owner
        .duplicate_birth_pidfd_for_inherited(&second.task, inherited.as_fd())
        .err()
        .map(|e| e.to_string());
    assert!(first.cancel().unwrap().confirmed);
    assert!(second.cancel().unwrap().confirmed);
    assert_eq!(
        error.as_deref(),
        Some("exec_stop_birth_pidfd_retired_or_foreign_generation")
    );
}
