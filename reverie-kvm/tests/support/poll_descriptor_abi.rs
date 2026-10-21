/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

// Linux 8cd9520d35a6c38db6567e97dd93b1f11f185dc6 fs/select.c:
// do_pollfd/do_poll and do_sys_poll's ordered short revents stores.
fn descriptor_abi_cases(test: &str, modes: &[u8]) {
    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "poll-descriptor-abi",
        include_str!("../fixtures/poll_descriptor_abi.c"),
    );
    let image = std::fs::read(&program).unwrap();
    for &mode in modes {
        let argument = mode.to_string();
        let native = std::process::Command::new(&program)
            .arg(&argument)
            .output()
            .unwrap();
        assert!(native.status.success(), "native mode={mode}: {native:?}");
        assert!(native.stderr.is_empty(), "native mode={mode}: {native:?}");
        assert_eq!(native.stdout.len(), 48 + 8192, "complete report and arena");
        assert_eq!(&native.stdout[12..16], &u32::from(mode).to_ne_bytes());
        for ownership in [
            None,
            Some(ThreadOwnership::Host),
            Some(ThreadOwnership::Tool),
        ] {
            let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
            backend
                .install_static_elf_with_context(
                    &image,
                    &[program.to_str().unwrap(), &argument],
                    &[],
                    &directory.0,
                )
                .unwrap();
            let (code, stdout, stderr) = if let Some(ownership) = ownership {
                backend.set_thread_ownership(ownership);
                let (trace, code, stdout, stderr) = futures::executor::block_on(
                    backend.run_static_elf_with_tool::<StraceTool>((), true),
                )
                .unwrap();
                let ppoll = matches!(mode, 1 | 3 | 4 | 5 | 6 | 8 | 10 | 12 | 13 | 15);
                let callbacks = trace
                    .syscalls()
                    .iter()
                    .filter(|name| name.as_str() == if ppoll { "ppoll" } else { "poll" })
                    .count();
                // ppoll is backend-owned only with host-owned workers; with
                // Tool-owned threads it reaches the Tool like poll.
                let reaches_tool = !ppoll || ownership == ThreadOwnership::Tool;
                assert_eq!(
                    callbacks,
                    usize::from(reaches_tool),
                    "mode={mode} {ownership:?}"
                );
                (code, stdout, stderr)
            } else {
                backend.run_static_elf_captured().unwrap()
            };
            eprintln!("poll descriptor ABI mode={mode} ownership={ownership:?} code={code}");
            assert_eq!(code, 0, "mode={mode} ownership={ownership:?}");
            assert!(
                stderr.is_empty(),
                "mode={mode} ownership={ownership:?}: {stderr:?}"
            );
            assert_eq!(
                stdout, native.stdout,
                "whole arena mode={mode} ownership={ownership:?}"
            );
        }
    }
}

#[test]
fn poll_and_ppoll_use_unsigned_low_word_nfds() {
    descriptor_abi_cases(
        "poll_descriptor_abi::poll_and_ppoll_use_unsigned_low_word_nfds",
        &[0, 1, 2, 3],
    );
}

#[test]
fn ppoll_invalid_fd_is_immediate_and_negative_fd_is_ignored() {
    descriptor_abi_cases(
        "poll_descriptor_abi::ppoll_invalid_fd_is_immediate_and_negative_fd_is_ignored",
        &[4, 5, 6, 13],
    );
}

#[test]
fn poll_and_ppoll_write_only_revents_with_ordered_faults() {
    descriptor_abi_cases(
        "poll_descriptor_abi::poll_and_ppoll_write_only_revents_with_ordered_faults",
        &[7, 8, 9, 10, 11, 12, 14, 15],
    );
}

// Preserved causal Host control from fc3f89f9; only its module path changes.
const HOST_EVENTFD_WAIT: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define EVENT_FD 198
static int ready_pipe[2];

struct report {
    int64_t before, ready, after;
    uint64_t counter;
    int32_t error;
    int16_t before_revents, ready_revents, after_revents;
    uint16_t reserved;
    uint32_t sentinel;
};
_Static_assert(sizeof(struct report) == 48, "complete report layout");

static void *worker(void *argument) {
    int event = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event < 0 || dup2(event, EVENT_FD) != EVENT_FD) _exit(90);
    if (event != EVENT_FD && close(event)) _exit(91);
    int gate = open(argument, O_RDONLY | O_CLOEXEC);
    if (gate < 0 || write(ready_pipe[1], "r", 1) != 1) _exit(92);
    char release = 0;
    if (read(gate, &release, 1) != 1 || release != 'g') _exit(93);
    uint64_t counter = 7;
    if (write(EVENT_FD, &counter, sizeof(counter)) != sizeof(counter)) _exit(94);
    if (close(gate)) _exit(95);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || pipe(ready_pipe)) return 80;
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, argv[1])) return 81;
    char ready = 0;
    if (read(ready_pipe[0], &ready, 1) != 1 || ready != 'r') return 82;
    struct report output;
    memset(&output, 0, sizeof(output));
    output.sentinel = 0xa1b2c3d4;
    struct pollfd descriptor = {.fd = EVENT_FD, .events = POLLIN};
    /* Zero probes use poll, so they cannot satisfy the blocked ppoll witness. */
    output.before = syscall(SYS_poll, &descriptor, 1, 0);
    output.before_revents = descriptor.revents;
    if (output.before != 0 || descriptor.revents != 0) return 83;
    struct timespec timeout = {.tv_sec = 2, .tv_nsec = 0};
    errno = 0;
    output.ready = syscall(SYS_ppoll, &descriptor, 1, &timeout, 0, 8);
    output.error = output.ready == -1 ? errno : 0;
    output.ready_revents = descriptor.revents;
    if (descriptor.fd != EVENT_FD || descriptor.events != POLLIN) return 84;
    if (output.ready != 1 || output.error || descriptor.revents != POLLIN) return 85;
    if (read(EVENT_FD, &output.counter, sizeof(output.counter)) != sizeof(output.counter)
        || output.counter != 7) return 86;
    output.after = syscall(SYS_poll, &descriptor, 1, 0);
    output.after_revents = descriptor.revents;
    if (output.after != 0 || descriptor.revents != 0) return 87;
    void *result = 0;
    if (pthread_join(thread, &result) || result) return 88;
    if (close(EVENT_FD) || close(ready_pipe[0]) || close(ready_pipe[1])) return 89;
    return write(1, &output, sizeof(output)) == sizeof(output) ? 0 : 96;
}
"#;

fn poll_task_start(pid: u32, tid: u32) -> Result<u64, String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat"))
        .map_err(|error| format!("owned task stat: {error}"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|start| start.parse().ok())
        .ok_or_else(|| format!("malformed owned task stat: {stat}"))
}

fn poll_gate(path: &std::path::Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;

    let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: name is a terminated path inside this test's private directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .unwrap()
}

fn observe_poll_then_release(
    pid: u32,
    tid: u32,
    start: u64,
    native: bool,
    mut gate: std::fs::File,
) -> Result<String, String> {
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    let observed = (|| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if poll_task_start(pid, tid)? != start {
                return Err("owned poll task generation changed".to_owned());
            }
            let row = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/syscall"))
                .map_err(|error| format!("owned poll syscall: {error}"))?;
            let fields = row.split_whitespace().collect::<Vec<_>>();
            let argument = |index: usize| {
                fields
                    .get(index)
                    .and_then(|value| value.strip_prefix("0x"))
                    .and_then(|value| u64::from_str_radix(value, 16).ok())
            };
            let number = fields.first().and_then(|value| value.parse::<i64>().ok());
            let expected = if native {
                libc::SYS_ppoll
            } else {
                libc::SYS_poll
            };
            if number == Some(expected)
                && argument(2) == Some(1)
                && (native || argument(3) == Some(2000))
            {
                let address = argument(1).ok_or_else(|| format!("missing pollfds: {row}"))?;
                let memory = std::fs::File::open(format!("/proc/{pid}/mem"))
                    .map_err(|error| format!("owned poll memory: {error}"))?;
                let mut descriptor = [0_u8; 8];
                memory
                    .read_exact_at(&mut descriptor, address)
                    .map_err(|error| format!("owned pollfd: {error}"))?;
                let fd = i32::from_ne_bytes(descriptor[..4].try_into().unwrap());
                let events = i16::from_ne_bytes(descriptor[4..6].try_into().unwrap());
                let revents = i16::from_ne_bytes(descriptor[6..].try_into().unwrap());
                if fd < 0 || (native && fd != 198) || events != libc::POLLIN || revents != 0 {
                    return Err(format!("unexpected blocked pollfd: {descriptor:?}; {row}"));
                }
                let link = std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                    .map_err(|error| format!("owned eventfd link: {error}"))?;
                let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))
                    .map_err(|error| format!("owned eventfd info: {error}"))?;
                let count = info.lines().find_map(|line| {
                    line.strip_prefix("eventfd-count:")
                        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                });
                if link != std::path::Path::new("anon_inode:[eventfd]") || count != Some(0) {
                    return Err(format!(
                        "poll did not block on empty eventfd: {link:?}; {info}"
                    ));
                }
                if poll_task_start(pid, tid)? != start {
                    return Err("owned poll task changed before release".to_owned());
                }
                return Ok(format!(
                    "observed-before-release pid={pid} tid={tid} start={start} native={native} syscall={} pollfd={descriptor:?} eventfd-count=0",
                    row.trim()
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("owned blocking poll was not observed: {row}"));
            }
            // Sampling cadence is not the proof: only the exact kernel row,
            // pollfd and empty eventfd checks above permit a passing witness.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    })();
    // Release on a failed observation too, so failure cannot strand the worker.
    // The retained O_RDWR endpoint makes this single-byte write nonblocking
    // even if the guest already exited. It is never a successful witness.
    let released = gate
        .write(b"g")
        .map_err(|error| format!("poll release: {error}"))?;
    if released != 1 {
        return Err(format!(
            "short poll release: {released}; observation={observed:?}"
        ));
    }
    observed
}

#[test]
fn ppoll_host_owned_worker_eventfd_wakes_without_callback() {
    const TEST: &str =
        "poll_descriptor_abi::ppoll_host_owned_worker_eventfd_wakes_without_callback";
    if !kvm_available(TEST) {
        return;
    }
    if std::env::var("REVERIE_LEADER_EXEC_CHILD").as_deref() != Ok(TEST) {
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "30s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("REVERIE_LEADER_EXEC_CHILD", TEST)
            .output()
            .unwrap();
        // Retain successful inner witnesses as well as failing child output.
        eprintln!(
            "{TEST}: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success());
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(&directory.0, "host-eventfd-wait", HOST_EVENTFD_WAIT);
    let mut expected = [0_u8; 48];
    expected[8..16].copy_from_slice(&1_i64.to_ne_bytes());
    expected[24..32].copy_from_slice(&7_u64.to_ne_bytes());
    expected[38..40].copy_from_slice(&libc::POLLIN.to_ne_bytes());
    expected[44..48].copy_from_slice(&0xa1b2c3d4_u32.to_ne_bytes());

    let path = directory.0.join("native-gate");
    let gate = poll_gate(&path);
    let child = std::process::Command::new(&program)
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let start = poll_task_start(pid, pid).unwrap();
    let (native, observed) = std::thread::scope(|scope| {
        let copy = gate.try_clone().unwrap();
        let observer = scope.spawn(move || observe_poll_then_release(pid, pid, start, true, copy));
        let output = child.wait_with_output().unwrap();
        (output, observer.join().unwrap())
    });
    eprintln!("native Host control: observation={observed:?} output={native:?}");
    assert!(observed.is_ok(), "{observed:?}");
    assert!(native.status.success(), "{native:?}");
    assert!(native.stderr.is_empty());
    assert_eq!(native.stdout, expected);
    drop(gate);

    let path = directory.0.join("kvm-gate");
    let gate = poll_gate(&path);
    let image = std::fs::read(&program).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.set_thread_ownership(ThreadOwnership::Host);
    backend
        .install_static_elf_with_context(
            &image,
            &[program.to_str().unwrap(), path.to_str().unwrap()],
            &[],
            &directory.0,
        )
        .unwrap();
    let pid = std::process::id();
    // SAFETY: gettid has no pointer arguments and identifies this owned thread.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let start = poll_task_start(pid, tid).unwrap();
    let (result, observed) = std::thread::scope(|scope| {
        let copy = gate.try_clone().unwrap();
        let observer = scope.spawn(move || observe_poll_then_release(pid, tid, start, false, copy));
        let result =
            futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true));
        (result, observer.join().unwrap())
    });
    eprintln!("KVM Host control: observation={observed:?}");
    assert!(observed.is_ok(), "{observed:?}");
    let (trace, code, stdout, stderr) = result.unwrap();
    eprintln!("KVM Host control: code={code} stdout={stdout:?} stderr={stderr:?}");
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(stdout, native.stdout);
    let callbacks = trace
        .syscalls()
        .iter()
        .filter(|name| name.as_str() == "ppoll")
        .count();
    eprintln!("KVM Host control: ppoll callbacks={callbacks}");
    assert_eq!(callbacks, 0);
    drop(gate);
}

// Separate mutation falsifier; the archived readiness control above stays intact.
#[test]
fn ppoll_copyout_preserves_worker_changes_to_inputs() {
    const TEST: &str = "poll_descriptor_abi::ppoll_copyout_preserves_worker_changes_to_inputs";
    if !kvm_available(TEST) {
        return;
    }
    if std::env::var("REVERIE_LEADER_EXEC_CHILD").as_deref() != Ok(TEST) {
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "30s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("REVERIE_LEADER_EXEC_CHILD", TEST)
            .output()
            .unwrap();
        // Retain successful inner witnesses as well as failing child output.
        eprintln!(
            "{TEST}: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success());
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "host-eventfd-input-mutation",
        include_str!("../fixtures/poll_descriptor_mutation.c"),
    );
    let mut expected = [0_u8; 64];
    expected[8..16].copy_from_slice(&1_i64.to_ne_bytes());
    expected[24..32].copy_from_slice(&7_u64.to_ne_bytes());
    expected[38..40].copy_from_slice(&libc::POLLIN.to_ne_bytes());
    expected[44..48].copy_from_slice(&0xa1b2c3d4_u32.to_ne_bytes());
    expected[48..52].copy_from_slice(&(-17_i32).to_ne_bytes());
    expected[52..54].copy_from_slice(&libc::POLLOUT.to_ne_bytes());
    expected[56..60].copy_from_slice(&(-17_i32).to_ne_bytes());
    expected[60..62].copy_from_slice(&libc::POLLOUT.to_ne_bytes());

    let path = directory.0.join("native-gate");
    let gate = poll_gate(&path);
    let child = std::process::Command::new(&program)
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let start = poll_task_start(pid, pid).unwrap();
    let (native, observed) = std::thread::scope(|scope| {
        let copy = gate.try_clone().unwrap();
        let observer = scope.spawn(move || observe_poll_then_release(pid, pid, start, true, copy));
        let output = child.wait_with_output().unwrap();
        (output, observer.join().unwrap())
    });
    eprintln!("native Host control: observation={observed:?} output={native:?}");
    assert!(observed.is_ok(), "{observed:?}");
    assert!(native.status.success(), "{native:?}");
    assert!(native.stderr.is_empty());
    assert_eq!(native.stdout, expected);
    drop(gate);

    let path = directory.0.join("kvm-gate");
    let gate = poll_gate(&path);
    let image = std::fs::read(&program).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.set_thread_ownership(ThreadOwnership::Host);
    backend
        .install_static_elf_with_context(
            &image,
            &[program.to_str().unwrap(), path.to_str().unwrap()],
            &[],
            &directory.0,
        )
        .unwrap();
    let pid = std::process::id();
    // SAFETY: gettid has no pointer arguments and identifies this owned thread.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let start = poll_task_start(pid, tid).unwrap();
    let (result, observed) = std::thread::scope(|scope| {
        let copy = gate.try_clone().unwrap();
        let observer = scope.spawn(move || observe_poll_then_release(pid, tid, start, false, copy));
        let result =
            futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true));
        (result, observer.join().unwrap())
    });
    eprintln!("KVM Host control: observation={observed:?}");
    assert!(observed.is_ok(), "{observed:?}");
    let (trace, code, stdout, stderr) = result.unwrap();
    eprintln!("KVM Host control: code={code} stdout={stdout:?} stderr={stderr:?}");
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(stdout, native.stdout);
    let callbacks = trace
        .syscalls()
        .iter()
        .filter(|name| name.as_str() == "ppoll")
        .count();
    eprintln!("KVM Host control: ppoll callbacks={callbacks}");
    assert_eq!(callbacks, 0);
    drop(gate);
}
