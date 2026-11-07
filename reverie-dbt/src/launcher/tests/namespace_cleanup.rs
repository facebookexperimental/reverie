/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

#[test]
fn vanished_proc_entries_do_not_hide_other_scan_errors() {
    for errno in [libc::ENOENT, libc::ESRCH] {
        assert!(proc_entry_vanished(&io::Error::from_raw_os_error(errno)));
    }
    for errno in [
        libc::EACCES,
        libc::EPERM,
        libc::EIO,
        libc::EINTR,
        libc::ENOTDIR,
    ] {
        assert!(!proc_entry_vanished(&io::Error::from_raw_os_error(errno)));
    }
    assert!(!proc_entry_vanished(&io::Error::new(
        io::ErrorKind::InvalidData,
        "malformed proc entry",
    )));
}

#[test]
fn stat_parser_accepts_unusual_names_and_rejects_incomplete_evidence() {
    assert_eq!(child_stat(b"42 (a b)\xff) S 1 0 0").unwrap(), ('S', 1));
    assert_eq!(child_stat(b"42 (zombie) Z 1 0").unwrap(), ('Z', 1));
    for invalid in [
        b"42 (broken".as_slice(),
        b"42 (x) S",
        b"42 (x) ? 1",
        b"42 (x) S -1",
    ] {
        assert_eq!(
            child_stat(invalid).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn child_scan_requires_namespace_local_proc_and_complete_stats() {
    use std::os::unix::fs::symlink;

    let proc = tempfile::tempdir().unwrap();
    symlink("wrong-namespace", proc.path().join("self")).unwrap();
    assert_eq!(
        own_children(proc.path()).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    std::fs::remove_file(proc.path().join("self")).unwrap();
    symlink(std::process::id().to_string(), proc.path().join("self")).unwrap();
    let pid = std::process::id() + 1;
    let child = proc.path().join(pid.to_string());
    std::fs::create_dir(&child).unwrap();
    // A vanished nonchild can be absent, but malformed or unreadable data
    // cannot silently remove a potentially live child from the result.
    assert!(own_children(proc.path()).unwrap().is_empty());
    std::fs::write(child.join("stat"), b"malformed").unwrap();
    assert_eq!(
        own_children(proc.path()).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    std::fs::remove_file(child.join("stat")).unwrap();
    std::fs::create_dir(child.join("stat")).unwrap();
    assert!(own_children(proc.path()).is_err());
    std::fs::remove_dir(child.join("stat")).unwrap();
    std::fs::write(
        child.join("stat"),
        format!("{pid} (child) S {} 0", std::process::id()),
    )
    .unwrap();
    assert_eq!(own_children(proc.path()).unwrap(), [(pid as i32, 'S')]);
}

#[test]
fn cleanup_rejects_nonpositive_and_init_roots_before_signaling() {
    for root in [-1, 0, 1] {
        assert_eq!(
            terminate_run(root).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
#[ignore = "requires unprivileged user/PID/mount namespaces; run explicitly with --ignored"]
fn namespace_cleanup_kills_adopted_sessions_and_preserves_root_status() {
    if is_namespace_init() {
        namespace_cleanup_fixture();
        return;
    }
    // A process outside the new PID namespace must remain untouched.
    let mut sentinel = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let output = Command::new("timeout")
        .args([
            "--signal=TERM",
            "--kill-after=2s",
            "15s",
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "--mount-proc",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "launcher::tests::namespace_cleanup::namespace_cleanup_kills_adopted_sessions_and_preserves_root_status",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("launch isolated cleanup fixture");
    let untouched = sentinel.try_wait().unwrap().is_none();
    sentinel.kill().unwrap();
    sentinel.wait().unwrap();
    assert!(
        untouched,
        "cleanup affected a process outside its PID namespace"
    );
    assert!(
        output.status.success(),
        "isolated cleanup failed: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("namespace cleanup: 4 descendants reaped, root=37")
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(
        output.stderr.is_empty(),
        "unexpected fixture stderr: {output:?}"
    );
}

/// Entry point selected only by the bounded namespace wrapper above. No
/// broadcast signal is allowed even in this private namespace.
#[cfg(target_arch = "x86_64")]
fn namespace_cleanup_fixture() {
    assert!(
        is_namespace_init(),
        "refuse to run the fixture outside a private PID namespace"
    );
    assert_eq!(std::fs::read_link("/proc/self").unwrap(), Path::new("1"));
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("process-tree");
    let status = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-pthread"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/namespace_cleanup.c"))
        .arg("-o")
        .arg(&fixture)
        .status()
        .unwrap();
    assert!(status.success());
    let pids_path = directory.path().join("pids");
    let mut root = Command::new(fixture).arg(&pids_path).spawn().unwrap();
    wait_for_exit_without_reaping(root.id()).unwrap();
    let descendants: Vec<i32> = std::fs::read_to_string(&pids_path)
        .unwrap()
        .lines()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert_eq!(descendants.len(), 3);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let leaf = std::fs::read(format!("/proc/{}/stat", descendants[2])).unwrap();
        if child_stat(&leaf).unwrap().0 == 'Z' {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "leaf leader never became a zombie with its live thread"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    // Also cover an already exited child created by a different launcher
    // thread. The process-wide proc scan must include it.
    let mut zombie = std::thread::spawn(|| {
        Command::new("/bin/sh")
            .args(["-c", "exit 19"])
            .spawn()
            .unwrap()
    })
    .join()
    .unwrap();
    wait_for_exit_without_reaping(zombie.id()).unwrap();
    reject_nonpositive_kill();
    terminate_run(root.id() as i32).unwrap();
    for pid in descendants.into_iter().chain([zombie.id() as i32]) {
        assert!(
            !Path::new("/proc").join(pid.to_string()).exists(),
            "descendant {pid} was not reaped"
        );
    }
    assert_eq!(
        zombie.wait().unwrap_err().raw_os_error(),
        Some(libc::ECHILD)
    );
    // Cleanup must not steal this wait status or release the retained root PID.
    assert!(Path::new("/proc").join(root.id().to_string()).exists());
    assert_eq!(root.wait().unwrap().code(), Some(37));
    assert!(own_children(Path::new("/proc")).unwrap().is_empty());
    println!("namespace cleanup: 4 descendants reaped, root=37");
}

#[cfg(target_arch = "x86_64")]
fn reject_nonpositive_kill() {
    // x86-64 seccomp_data: nr at 0, arch at 4, args[0] at 16. This
    // diagnostic guard rejects group/broadcast destinations, not positive
    // child kills. The namespace wrapper itself is outside this filter.
    let mut filter = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0xc000003e,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 4,
            k: libc::SYS_kill as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 16,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x80000000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
}
