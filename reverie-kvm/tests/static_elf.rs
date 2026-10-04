/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::Condvar;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::task::Waker;

use futures::future::poll_fn;
use kvm_ioctls::Kvm;
use reverie::BackendChildWaitEvent;
use reverie::BackendChildWaitState;
use reverie::BackendSignalControl;
use reverie::BackendSignalControlMode;
use reverie::BackendStatsRequest;
use reverie::BackendStatsSource;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::SignalDeliveryPermit;
use reverie::SignalEvent;
use reverie::SignalProcessId;
use reverie::SignalTarget;
use reverie::Stack;
use reverie::Subscription;
use reverie::ThreadOwnership;
use reverie::Tool;
use reverie::syscalls::AddrMut;
use reverie::syscalls::CArrayPtr;
use reverie::syscalls::CStrPtr;
use reverie::syscalls::Clone as CloneSyscall;
use reverie::syscalls::Errno;
use reverie::syscalls::Execve;
use reverie::syscalls::ExitGroup;
use reverie::syscalls::Fork;
use reverie::syscalls::FromToRaw;
use reverie::syscalls::Kill;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::PathPtr;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_kvm::CounterTool;
use reverie_kvm::Error;
use reverie_kvm::HierarchicalCounterTool;
use reverie_kvm::HierarchicalTotals;
use reverie_kvm::KvmBackend;
use reverie_kvm::KvmBackendStats;
use reverie_kvm::KvmExitReason;
use reverie_kvm::StraceTool;

const MEMORY_SIZE: usize = 16 * 1024 * 1024;

#[path = "support/random_device_stream.rs"]
mod random_device_stream;

#[path = "support/poll_descriptor_abi.rs"]
mod poll_descriptor_abi;

#[test]
fn file_script_exec_plain() {
    file_script_exec_control("file_script_exec_plain", "plain");
}

#[test]
fn file_script_exec_unlink_interpreter() {
    file_script_exec_control("file_script_exec_unlink_interpreter", "unlink");
}

#[test]
fn file_script_exec_replace_interpreter() {
    file_script_exec_control("file_script_exec_replace_interpreter", "replace");
}

#[test]
fn file_script_exec_script_nonexecutable() {
    file_script_exec_control("file_script_exec_script_nonexecutable", "script0600");
}

#[test]
fn file_script_exec_interpreter_nonexecutable() {
    file_script_exec_control("file_script_exec_interpreter_nonexecutable", "interp0600");
}

#[test]
fn file_script_exec_interpreter_execute_only() {
    file_script_exec_control("file_script_exec_interpreter_execute_only", "interp0100");
}

#[test]
fn file_script_exec_nested_interpreter() {
    file_script_exec_control("file_script_exec_nested_interpreter", "nested");
}

#[test]
fn file_script_exec_bytes_unknown() {
    file_script_exec_control("file_script_exec_bytes_unknown", "unknown");
}

#[test]
fn file_script_exec_arbitrary_argv0() {
    file_script_exec_control("file_script_exec_arbitrary_argv0", "arbitrary");
}

fn file_script_exec_control(test: &str, case: &str) {
    use std::os::unix::fs::MetadataExt;

    if !leader_self_exec_bounded(test) {
        return;
    }
    for native in [true, false] {
        if native && case == "unknown" {
            continue;
        }
        let directory = TestDirectory::new();
        let interpreter = compile_c_program(
            &directory.0,
            "real-interpreter",
            SCRIPT_EXEC_CONTROL_PROGRAM,
        );
        let replacement =
            compile_c_program(&directory.0, "replacement", "int main(void) { return 77; }");
        let script = directory.0.join("invoked-script");
        let middle = directory.0.join("middle-script");
        std::fs::write(
            &middle,
            format!("#!{} middle argument\n", interpreter.display()),
        )
        .unwrap();
        std::fs::set_permissions(&middle, std::fs::Permissions::from_mode(0o700)).unwrap();
        let nested = case == "nested";
        let target = if nested { &middle } else { &interpreter };
        std::fs::write(&script, format!("#!{} outer argument\n", target.display())).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(&interpreter).unwrap();
        let mut expected_argv = vec![interpreter.to_string_lossy().into_owned()];
        if nested {
            expected_argv.extend([
                "middle argument".to_owned(),
                middle.to_string_lossy().into_owned(),
            ]);
        }
        expected_argv.extend([
            "outer argument".to_owned(),
            script.to_string_lossy().into_owned(),
            "tail-argument".to_owned(),
        ]);
        let mut environment = vec![
            ("SCRIPT_CASE".to_owned(), case.to_owned()),
            ("SCRIPT_DEV".to_owned(), metadata.dev().to_string()),
            ("SCRIPT_INO".to_owned(), metadata.ino().to_string()),
            (
                "SCRIPT_PATH".to_owned(),
                script.to_string_lossy().into_owned(),
            ),
            (
                "INTERPRETER_PATH".to_owned(),
                interpreter.to_string_lossy().into_owned(),
            ),
            (
                "REPLACEMENT_PATH".to_owned(),
                replacement.to_string_lossy().into_owned(),
            ),
            ("SCRIPT_ARGC".to_owned(), expected_argv.len().to_string()),
            ("SCRIPT_ENV".to_owned(), "environment-preserved".to_owned()),
        ];
        for (index, argument) in expected_argv.into_iter().enumerate() {
            environment.push((format!("SCRIPT_ARG{index}"), argument));
        }
        let expected: &[u8] = if case == "unknown" {
            b"script bytes unknown backing exact=PASS\n"
        } else if case == "interp0600" {
            b"script interpreter EACCES and name unchanged exact=PASS\n"
        } else {
            b"script final interpreter identity argv env name selfexec exact=PASS\n"
        };
        if native {
            let start = std::time::Instant::now();
            let mut command = std::process::Command::new("timeout");
            command.args(["--kill-after=2s", "10s"]);
            if case == "arbitrary" {
                command
                    .args([
                        "/bin/bash",
                        "-c",
                        "exec -a not-the-script \"$1\" tail-argument",
                        "--",
                    ])
                    .arg(&script);
            } else {
                command.arg(&script).arg("tail-argument");
            }
            command.envs(environment);
            eprintln!("native command {case}: {command:?}");
            let result = command.output().unwrap();
            eprintln!(
                "native {case}: status={:?} seconds={} stdout={}",
                result.status.code(),
                start.elapsed().as_secs_f64(),
                String::from_utf8_lossy(&result.stdout)
            );
            assert_eq!(result.status.code(), Some(0), "{result:?}");
            assert_eq!(result.stdout, expected);
            assert!(result.stderr.is_empty());
        } else {
            let envp = environment
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>();
            let envp = envp.iter().map(String::as_str).collect::<Vec<_>>();
            let argv = [
                if case == "arbitrary" {
                    "not-the-script"
                } else {
                    script.to_str().unwrap()
                },
                "tail-argument",
            ];
            let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
            if case == "unknown" {
                backend
                    .install_static_elf_with_context(
                        &std::fs::read(&script).unwrap(),
                        &argv,
                        &envp,
                        &directory.0,
                    )
                    .unwrap();
            } else {
                backend
                    .install_static_elf_file_with_context(
                        std::fs::File::open(&script).unwrap(),
                        &argv,
                        &envp,
                        &directory.0,
                    )
                    .unwrap();
            }
            let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
            assert_eq!(
                code,
                0,
                "case={case} stdout={} stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            assert_eq!(stdout, expected);
            assert!(stderr.is_empty());
        }
    }
}

const SCRIPT_EXEC_CONTROL_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;
static volatile int image_value = 42;

int main(int argc, char **argv) {
    const char *mode = getenv("SCRIPT_CASE"), *path = getenv("INTERPRETER_PATH");
    int after = getenv("SCRIPT_AFTER") != NULL, unknown = !strcmp(mode, "unknown");
    if (argc != atoi(getenv("SCRIPT_ARGC")) || strcmp(getenv("SCRIPT_ENV"), "environment-preserved") || image_value != 42) return 10;
    for (int index = 0; index < argc; ++index) {
        char key[64]; snprintf(key, sizeof(key), "SCRIPT_ARG%d", index);
        if (strcmp(argv[index], getenv(key))) return 11;
    }
    unsigned char name[64], expected_name[64], output[4096], expected[4096];
    memset(name, 0x5a, sizeof(name)); memset(expected_name, 0x5a, sizeof(expected_name));
    memset(expected_name, 0, 16); memcpy(expected_name, after ? "exe" : "invoked-script", after ? 3 : 14);
    if (prctl(PR_GET_NAME, name) || (!unknown && memcmp(name, expected_name, sizeof(name)))) return 12;
    if (!after) {
        if (!strcmp(mode, "unlink") && unlink(path)) return 13;
        if (!strcmp(mode, "replace") && rename(getenv("REPLACEMENT_PATH"), path)) return 14;
        if (!strcmp(mode, "script0600") && chmod(getenv("SCRIPT_PATH"), 0600)) return 15;
        if (!strcmp(mode, "interp0600") && chmod(path, 0600)) return 16;
        if (!strcmp(mode, "interp0100") && chmod(path, 0100)) return 17;
    }
    memset(output, 0x5a, sizeof(output)); memset(expected, 0x5a, sizeof(expected));
    errno = 0;
    int result = stat("/proc/self/exe", (struct stat *)output), error = errno;
    if (unknown) {
        if (result != -1 || error != ENOENT || memcmp(output, expected, sizeof(output))) return 18;
    } else {
        struct stat metadata; memcpy(&metadata, output, sizeof(metadata));
        if (result || error || metadata.st_dev != strtoull(getenv("SCRIPT_DEV"), NULL, 10) || metadata.st_ino != strtoull(getenv("SCRIPT_INO"), NULL, 10) || memcmp(output + sizeof(metadata), expected + sizeof(metadata), sizeof(output)-sizeof(metadata))) {
            printf("script identity result=%d errno=%d inode=%llu expected=%s\n", result, error, (unsigned long long)metadata.st_ino, getenv("SCRIPT_INO"));
            return 19;
        }
        char link[4096];
        int length = snprintf(link, sizeof(link), "%s%s", path, !strcmp(mode, "unlink") || !strcmp(mode, "replace") ? " (deleted)" : "");
        if (length < 0 || length >= 4096) return 20;
        memcpy(expected, link, length); memset(output, 0x5a, sizeof(output));
        if (readlink("/proc/self/exe", (char *)output, sizeof(output)) != length || memcmp(output, expected, sizeof(output))) return 21;
    }
    if (after) { puts("script final interpreter identity argv env name selfexec exact=PASS"); return 0; }
    if (prctl(PR_SET_NAME, "before-self") || setenv("SCRIPT_AFTER", "1", 1)) return 22;
    image_value = 99;
    errno = 0; execve("/proc/self/exe", argv, environ); error = errno;
    if (error != (unknown ? ENOENT : EACCES) || (!unknown && strcmp(mode, "interp0600"))) return 23;
    memset(name, 0x5a, sizeof(name)); memset(expected_name, 0x5a, sizeof(expected_name));
    memset(expected_name, 0, 16); memcpy(expected_name, "before-self", 11);
    if (prctl(PR_GET_NAME, name) || memcmp(name, expected_name, sizeof(name)) || image_value != 99) return 24;
    puts(unknown ? "script bytes unknown backing exact=PASS" : "script interpreter EACCES and name unchanged exact=PASS");
    return 0;
}
"###;

#[test]
fn file_script_exec_interpreter_identity() {
    if !leader_self_exec_bounded("file_script_exec_interpreter_identity") {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(&directory.0, "actual-interpreter", SCRIPT_IDENTITY_PROGRAM);
    let script = directory.0.join("input-script");
    std::fs::write(&script, format!("#!{}\n", program.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let setting = format!("EXPECTED_EXE={}", program.display());
    for (kind, input) in [("elf", &program), ("script", &script)] {
        let start = std::time::Instant::now();
        let mut command = std::process::Command::new("timeout");
        command
            .args(["--kill-after=2s", "10s"])
            .arg(input)
            .env("EXPECTED_EXE", &program);
        eprintln!("native command {kind}: {command:?}");
        let native = command.output().unwrap();
        eprintln!(
            "native {kind}: status={:?} seconds={} stdout={}",
            native.status.code(),
            start.elapsed().as_secs_f64(),
            String::from_utf8_lossy(&native.stdout)
        );
        assert_eq!(native.status.code(), Some(0));
        assert_eq!(
            native.stdout,
            b"interpreter_body=1 executable_inode_matches=1 link_full4096_matches=1\n"
        );
        assert!(native.stderr.is_empty());
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(input).unwrap(),
                &[input.to_str().unwrap()],
                &[&setting],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        eprintln!(
            "guest {kind}: code={code} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(code, 0, "{kind}: identity must match loaded interpreter");
        assert_eq!(stdout, native.stdout);
        assert_eq!(stderr, native.stderr);
    }
}

const SCRIPT_IDENTITY_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    const char *path = getenv("EXPECTED_EXE");
    if (!path || strlen(path) >= 4096) return 10;
    struct stat expected_stat, actual_stat;
    if (stat(path, &expected_stat) || stat("/proc/self/exe", &actual_stat)) return 11;
    unsigned char actual[4096], expected[4096];
    memset(actual, 0x5a, sizeof(actual));
    memset(expected, 0x5a, sizeof(expected));
    memcpy(expected, path, strlen(path));
    ssize_t count = readlink("/proc/self/exe", (char *)actual, sizeof(actual));
    int link_equal = count == (ssize_t)strlen(path) && !memcmp(actual, expected, sizeof(actual));
    int identity_equal = actual_stat.st_dev == expected_stat.st_dev && actual_stat.st_ino == expected_stat.st_ino;
    printf("interpreter_body=1 executable_inode_matches=%d link_full4096_matches=%d\n", identity_equal, link_equal);
    return identity_equal && link_equal ? 0 : 21;
}
"###;

#[test]
fn initial_exec_binding_bytes_different_file() {
    initial_exec_binding_control(
        "initial_exec_binding_bytes_different_file",
        false,
        "different",
    );
}

#[test]
fn initial_exec_binding_bytes_identical_file() {
    initial_exec_binding_control(
        "initial_exec_binding_bytes_identical_file",
        false,
        "identical",
    );
}

#[test]
fn initial_exec_binding_bytes_missing_file() {
    initial_exec_binding_control("initial_exec_binding_bytes_missing_file", false, "missing");
}

#[test]
fn initial_exec_binding_bytes_arbitrary_argv() {
    initial_exec_binding_control(
        "initial_exec_binding_bytes_arbitrary_argv",
        false,
        "arbitrary",
    );
}

#[test]
fn initial_exec_binding_bytes_replace_known_binding() {
    initial_exec_binding_control(
        "initial_exec_binding_bytes_replace_known_binding",
        false,
        "after-file",
    );
}

#[test]
fn initial_exec_binding_file_different_file() {
    initial_exec_binding_control(
        "initial_exec_binding_file_different_file",
        true,
        "different",
    );
}

#[test]
fn initial_exec_binding_file_identical_file() {
    initial_exec_binding_control(
        "initial_exec_binding_file_identical_file",
        true,
        "identical",
    );
}

#[test]
fn initial_exec_binding_file_arbitrary_argv() {
    initial_exec_binding_control(
        "initial_exec_binding_file_arbitrary_argv",
        true,
        "arbitrary",
    );
}

#[test]
fn initial_exec_binding_file_unlinked_before_install() {
    initial_exec_binding_control(
        "initial_exec_binding_file_unlinked_before_install",
        true,
        "unlink",
    );
}

#[test]
fn initial_exec_binding_file_replaced_before_install() {
    initial_exec_binding_control(
        "initial_exec_binding_file_replaced_before_install",
        true,
        "replace",
    );
}

#[test]
fn initial_exec_binding_file_failed_read_preserves_image() {
    initial_exec_binding_control(
        "initial_exec_binding_file_failed_read_preserves_image",
        true,
        "read-error",
    );
}

fn initial_exec_binding_control(test: &str, file_backed: bool, case: &str) {
    use std::io::Seek;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;

    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(&directory.0, "image-a", INITIAL_EXEC_BINDING_PROGRAM);
    let other = compile_c_program(&directory.0, "image-b", "int main(void) { return 77; }");
    if case == "identical" {
        std::fs::copy(&program, &other).unwrap();
        assert_eq!(
            std::fs::read(&program).unwrap(),
            std::fs::read(&other).unwrap()
        );
    }
    let file = std::fs::File::open(&program).unwrap();
    let metadata = file.metadata().unwrap();
    assert_ne!(metadata.ino(), std::fs::metadata(&other).unwrap().ino());
    let image = std::fs::read(&program).unwrap();
    let missing = directory.0.join("absent-image");
    let argv0 = match case {
        "missing" => missing.to_str().unwrap(),
        "arbitrary" => "arbitrary-argv0-not-a-path",
        _ => other.to_str().unwrap(),
    };
    let deleted = matches!(case, "unlink" | "replace");
    if case == "unlink" {
        std::fs::remove_file(&program).unwrap();
    } else if case == "replace" {
        std::fs::rename(&other, &program).unwrap();
    }
    let environment = [
        format!("BINDING_KNOWN={}", u8::from(file_backed)),
        format!("BINDING_DEV={}", metadata.dev()),
        format!("BINDING_INO={}", metadata.ino()),
        format!("BINDING_ARGV={argv0}"),
        format!(
            "BINDING_LINK={}{}",
            program.display(),
            if deleted { " (deleted)" } else { "" }
        ),
    ];
    let envp = environment.iter().map(String::as_str).collect::<Vec<_>>();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    if file_backed {
        let mut offset_alias = file.try_clone().unwrap();
        offset_alias.seek(std::io::SeekFrom::Start(7)).unwrap();
        backend
            .install_static_elf_file_with_context(
                file,
                &[argv0, "argument-preserved"],
                &envp,
                &directory.0,
            )
            .unwrap();
        assert_eq!(offset_alias.stream_position().unwrap(), 7);
        if case == "read-error" {
            let unreadable = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH)
                .open(&other)
                .unwrap();
            let error = backend
                .install_static_elf_file_with_context(
                    unreadable,
                    &["wrong-image"],
                    &[],
                    &directory.0,
                )
                .unwrap_err();
            assert!(
                matches!(error, Error::HostIo(ref error) if error.raw_os_error() == Some(libc::EBADF)),
                "{error}"
            );
        }
    } else {
        if case == "after-file" {
            backend
                .install_static_elf_file_with_context(
                    file.try_clone().unwrap(),
                    &[argv0, "argument-preserved"],
                    &envp,
                    &directory.0,
                )
                .unwrap();
        }
        backend
            .install_static_elf_with_context(
                &image,
                &[argv0, "argument-preserved"],
                &envp,
                &directory.0,
            )
            .unwrap();
        drop(file);
    }
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(
        stdout,
        if file_backed {
            b"known object and selfexec exact=PASS\n".as_slice()
        } else {
            b"unknown backing and failed selfexec exact=PASS\n".as_slice()
        }
    );
    assert!(
        stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&stderr)
    );
}

const INITIAL_EXEC_BINDING_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[0], getenv("BINDING_ARGV")) || strcmp(argv[1], "argument-preserved")) return 10;
    int known = !strcmp(getenv("BINDING_KNOWN"), "1");
    unsigned char actual[4096], expected[4096];
    memset(actual, 0x5a, sizeof(actual)); memset(expected, 0x5a, sizeof(expected));
    errno = 0;
    int result = stat("/proc/self/exe", (struct stat *)actual);
    int error = errno;
    if (known) {
        struct stat metadata;
        memcpy(&metadata, actual, sizeof(metadata));
        if (result || error || metadata.st_dev != strtoull(getenv("BINDING_DEV"), NULL, 10) || metadata.st_ino != strtoull(getenv("BINDING_INO"), NULL, 10) || memcmp(actual + sizeof(metadata), expected + sizeof(metadata), sizeof(actual) - sizeof(metadata))) {
            printf("known stat result=%d errno=%d inode=%llu expected=%s\n", result, error, (unsigned long long)metadata.st_ino, getenv("BINDING_INO"));
            return 11;
        }
        memset(actual, 0x5a, sizeof(actual));
        const char *link = getenv("BINDING_LINK");
        size_t length = strlen(link);
        if (length >= sizeof(expected)) return 12;
        memcpy(expected, link, length);
        if (readlink("/proc/self/exe", (char *)actual, sizeof(actual)) != (ssize_t)length || memcmp(actual, expected, sizeof(actual))) return 13;
    } else if (result != -1 || error != ENOENT || memcmp(actual, expected, sizeof(actual))) {
        printf("unknown stat result=%d errno=%d full4096_unchanged=%d\n", result, error, !memcmp(actual, expected, sizeof(actual)));
        return 14;
    }
    unsigned char name[64], expected_name[64];
    memset(name, 0x5a, sizeof(name)); memset(expected_name, 0x5a, sizeof(expected_name));
    if (getenv("BINDING_AFTER")) {
        memset(expected_name, 0, 16); memcpy(expected_name, "exe", 3);
        if (prctl(PR_GET_NAME, name) || memcmp(name, expected_name, sizeof(name))) return 15;
        puts("known object and selfexec exact=PASS");
        return 0;
    }
    if (prctl(PR_SET_NAME, "binding-before") || setenv("BINDING_AFTER", "1", 1)) return 16;
    errno = 0;
    execve("/proc/self/exe", argv, environ);
    error = errno;
    memset(expected_name, 0, 16); memcpy(expected_name, "binding-before", 14);
    if (known || error != ENOENT || prctl(PR_GET_NAME, name) || memcmp(name, expected_name, sizeof(name))) return 17;
    puts("unknown backing and failed selfexec exact=PASS");
    return 0;
}
"###;

#[test]
fn leader_self_exec_output_permissions() {
    if !leader_self_exec_bounded("leader_self_exec_output_permissions") {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "running-image",
        LEADER_SELF_EXEC_OUTPUT_PROGRAM,
    );
    leader_self_exec_guest(
        &directory.0,
        &program,
        &[],
        b"stat/readlink RW/RO/NONE exact errno and full4096=PASS\n",
    );
}

const LEADER_SELF_EXEC_OUTPUT_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 1 || strlen(argv[0]) >= 4096) return 10;
    int failures = 0;
    for (int operation = 0; operation != 2; ++operation) {
        for (int access = 0; access != 3; ++access) {
            unsigned char *actual = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            unsigned char expected[4096];
            if (actual == MAP_FAILED) return 11;
            memset(actual, 0x5a, 4096); memset(expected, 0x5a, sizeof(expected));
            if (!access) {
                if (operation) memcpy(expected, argv[0], strlen(argv[0]));
                else if (syscall(SYS_newfstatat, AT_FDCWD, argv[0], expected, 0)) return 12;
            }
            int protection = access == 0 ? PROT_READ | PROT_WRITE : access == 1 ? PROT_READ : PROT_NONE;
            if (mprotect(actual, 4096, protection)) return 13;
            errno = 0;
            long result = operation ? syscall(SYS_readlink, "/proc/self/exe", actual, 4096) : syscall(SYS_newfstatat, AT_FDCWD, "/proc/self/exe", actual, 0);
            int error = errno;
            if (mprotect(actual, 4096, PROT_READ | PROT_WRITE)) return 14;
            long expected_result = access ? -1 : operation ? (long)strlen(argv[0]) : 0;
            int expected_error = access ? EFAULT : 0;
            int equal = memcmp(actual, expected, sizeof(expected)) == 0;
            if (result != expected_result || error != expected_error || !equal) {
                printf("operation=%d access=%d result=%ld errno=%d full4096=%d expected_result=%ld expected_errno=%d\n", operation, access, result, error, equal, expected_result, expected_error);
                ++failures;
            }
            if (munmap(actual, 4096)) return 15;
        }
    }
    if (!failures) puts("stat/readlink RW/RO/NONE exact errno and full4096=PASS");
    return failures ? 1 : 0;
}
"###;

fn leader_self_exec_lifetime_control(test: &str, mode: &str, method: &str) {
    if !leader_self_exec_bounded(test) {
        return;
    }
    for with_tool in [false, true] {
        let directory = TestDirectory::new();
        let program = compile_c_program(
            &directory.0,
            "running-image",
            LEADER_SELF_EXEC_LIFETIME_PROGRAM,
        );
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&program).unwrap(),
                &[program.to_str().unwrap(), mode, method],
                &[],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if with_tool {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        let expected: &[u8] = if mode == "fork" {
            b"child-exec\nparent-after-child\n"
        } else {
            b"leader-after-thread-exec\n"
        };
        assert_eq!(
            code,
            0,
            "mode={mode} method={method} tool={with_tool} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(
            stdout, expected,
            "mode={mode} method={method} tool={with_tool}"
        );
        assert!(
            stderr.is_empty(),
            "mode={mode} method={method} tool={with_tool} stderr={}",
            String::from_utf8_lossy(&stderr)
        );
    }
}

#[test]
fn leader_self_exec_lifetime_fork_0() {
    leader_self_exec_lifetime_control("leader_self_exec_lifetime_fork_0", "fork", "0");
}

#[test]
fn leader_self_exec_lifetime_fork_1() {
    leader_self_exec_lifetime_control("leader_self_exec_lifetime_fork_1", "fork", "1");
}

#[test]
fn leader_self_exec_lifetime_thread_0() {
    leader_self_exec_lifetime_control("leader_self_exec_lifetime_thread_0", "thread", "0");
}

#[test]
fn leader_self_exec_lifetime_thread_1() {
    leader_self_exec_lifetime_control("leader_self_exec_lifetime_thread_1", "thread", "1");
}

const LEADER_SELF_EXEC_LIFETIME_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned image_value = 0x11223344;
static int ready_pipe[2], stop_pipe[2];
static long old_tid;
static int name_is(const char *name) {
    unsigned char actual[64], expected[64];
    memset(actual, 0x5a, sizeof(actual));
    memset(expected, 0x5a, sizeof(expected));
    memset(expected, 0, 16);
    memcpy(expected, name, strlen(name));
    return prctl(PR_GET_NAME, actual) == 0 && !memcmp(actual, expected, sizeof(actual));
}
static void *sibling(void *unused) {
    (void)unused;
    old_tid = syscall(SYS_gettid);
    if (write(ready_pipe[1], "R", 1) != 1) return (void *)1;
    char stop;
    return read(stop_pipe[0], &stop, 1) == 1 ? NULL : (void *)2;
}
int main(int argc, char **argv) {
    const char *stage = getenv("LIFETIME_STAGE");
    if (stage) {
        if (argc != 2 || strcmp(argv[0], "different-argv-zero") || strcmp(argv[1], "after")) return 30;
        if (image_value != 0x11223344 || !name_is("exe")) return 31;
        if (getpid() != strtol(getenv("SAVED_PID"), NULL, 10) || getppid() != strtol(getenv("SAVED_PPID"), NULL, 10)) return 32;
        struct stat actual;
        if (stat("/proc/self/exe", &actual) || actual.st_dev != strtoull(getenv("SAVED_DEV"), NULL, 10) || actual.st_ino != strtoull(getenv("SAVED_INO"), NULL, 10)) return 33;
        unsigned char link[4096], expected[4096];
        memset(link, 0x5a, sizeof(link)); memset(expected, 0x5a, sizeof(expected));
        const char *path = getenv("SAVED_LINK");
        size_t length = strlen(path);
        if (length >= sizeof(expected)) return 34;
        memcpy(expected, path, length);
        if (readlink("/proc/self/exe", (char *)link, sizeof(link)) != (ssize_t)length || memcmp(link, expected, sizeof(link))) return 35;
        if (prctl(PR_SET_NAME, "changed-after") || !name_is("changed-after")) return 36;
        if (!strcmp(stage, "thread")) {
            errno = 0;
            if (syscall(SYS_tgkill, getpid(), strtol(getenv("OLD_TID"), NULL, 10), 0) != -1 || errno != ESRCH) return 38;
            return write(1, "leader-after-thread-exec\n", 25) == 25 ? 0 : 39;
        }
        return write(1, "child-exec\n", 11) == 11 ? 37 : 40;
    }
    if (argc != 3 || prctl(PR_SET_NAME, "parent-before") || !name_is("parent-before")) return 10;
    int thread_case = !strcmp(argv[1], "thread");
    struct stat original;
    if (stat("/proc/self/exe", &original)) return 11;
    image_value = 0x88776655;
    pthread_t worker;
    if (thread_case) {
        if (pipe(ready_pipe) || pipe(stop_pipe) || pthread_create(&worker, NULL, sibling, NULL)) return 12;
        unsigned char ready[16], expected[16];
        memset(ready, 0x5a, sizeof(ready)); memset(expected, 0x5a, sizeof(expected)); expected[0] = 'R';
        if (read(ready_pipe[0], ready, 1) != 1 || memcmp(ready, expected, sizeof(ready))) return 13;
    } else {
        pid_t child = fork();
        if (child < 0) return 14;
        if (child) {
            int status = 0;
            if (waitpid(child, &status, 0) != child || status != (37 << 8)) return 15;
            if (image_value != 0x88776655 || !name_is("parent-before")) return 16;
            errno = 0;
            if (access(argv[0], F_OK) != -1 || errno != ENOENT) return 17;
            return write(1, "parent-after-child\n", 19) == 19 ? 0 : 18;
        }
        if (unlink(argv[0])) return 19;
    }
    char setting[64], pid[64], parent[64], tid[64], device[64], inode[64], link[4200];
    snprintf(setting, sizeof(setting), "LIFETIME_STAGE=%s", argv[1]);
    snprintf(pid, sizeof(pid), "SAVED_PID=%d", getpid());
    snprintf(parent, sizeof(parent), "SAVED_PPID=%d", getppid());
    snprintf(tid, sizeof(tid), "OLD_TID=%ld", old_tid);
    snprintf(device, sizeof(device), "SAVED_DEV=%llu", (unsigned long long)original.st_dev);
    snprintf(inode, sizeof(inode), "SAVED_INO=%llu", (unsigned long long)original.st_ino);
    if (snprintf(link, sizeof(link), "SAVED_LINK=%s%s", argv[0], thread_case ? "" : " (deleted)") >= (int)sizeof(link)) return 20;
    char *environment[] = {setting, pid, parent, tid, device, inode, link, NULL};
    char *arguments[] = {"different-argv-zero", "after", NULL};
    if (atoi(argv[2])) syscall(SYS_execveat, AT_FDCWD, "/proc/self/exe", arguments, environment, 0);
    else syscall(SYS_execve, "/proc/self/exe", arguments, environment);
    int error = errno;
    if (thread_case) {
        void *result;
        if (write(stop_pipe[1], "S", 1) != 1 || pthread_join(worker, &result) || result) return 21;
    }
    printf("exec returned errno=%d\n", error);
    return 22;
}
"###;

fn compile_assembly_program(directory: &std::path::Path, name: &str, source: &str) -> PathBuf {
    let source_path = directory.join(format!("{name}.S"));
    let executable_path = directory.join(name);
    std::fs::write(&source_path, source).unwrap();
    let output = std::process::Command::new("/usr/bin/gcc")
        .args(["-nostdlib", "-static", "-Wl,--build-id=none"])
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gcc failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    executable_path
}

#[test]
fn self_exec_proc_aliases_use_loaded_image_after_unlink_or_replacement() {
    if !leader_self_exec_bounded(
        "self_exec_proc_aliases_use_loaded_image_after_unlink_or_replacement",
    ) {
        return;
    }

    const ROOT_PID: i32 = 37;
    const ARGV0: &str = "preserved-argv0";
    const ARGV1: &str = "after-exec";
    const ENVP0: &str = "SELF_EXEC_ENV=preserved";
    const IMAGE_MARKER: &str = "same-image\n";

    for (case, (name, path, execveat)) in [
        ("self-exec-proc-self-execve", "/proc/self/exe", false),
        ("self-exec-proc-pid-execve", "/proc/37/exe", false),
        (
            "self-exec-proc-thread-self-execve",
            "/proc/thread-self/exe",
            false,
        ),
        (
            "self-exec-proc-self-task-execve",
            "/proc/self/task/37/exe",
            false,
        ),
        (
            "self-exec-proc-tgid-task-execve",
            "/proc/37/task/37/exe",
            false,
        ),
        ("self-exec-proc-self-execveat", "/proc/self/exe", true),
        ("self-exec-proc-pid-execveat", "/proc/37/exe", true),
    ]
    .into_iter()
    .enumerate()
    {
        let exec = if execveat {
            // execveat(AT_FDCWD, path, argv, envp, 0)
            r#"
                mov %rdx, %r10
                mov %rsi, %rdx
                mov %rdi, %rsi
                mov $-100, %rdi
                xor %r8d, %r8d
                mov $322, %eax
                syscall
            "#
        } else {
            // execve(path, argv, envp)
            r#"
                mov $59, %eax
                syscall
            "#
        };
        let source = format!(
            r#"
                .global _start
                .text
            _start:
                cmpq $2, (%rsp)
                je after_exec

                lea self_path(%rip), %rdi
                lea replacement_argv(%rip), %rsi
                lea replacement_envp(%rip), %rdx
                {exec}
                neg %eax
                mov %eax, %edi
                mov $231, %eax
                syscall

            after_exec:
                lea self_path(%rip), %rdi
                lea link_buffer(%rip), %rsi
                mov $4096, %edx
                mov $89, %eax
                syscall
                test %rax, %rax
                js exit_with_errno
                mov %eax, %edx
                mov $1, %edi
                lea link_buffer(%rip), %rsi
                mov $1, %eax
                syscall
                call write_newline

                mov $1, %edi
                lea image_marker(%rip), %rsi
                mov ${image_marker_len}, %edx
                mov $1, %eax
                syscall

                mov $1, %edi
                mov 8(%rsp), %rsi
                mov ${argv0_len}, %edx
                mov $1, %eax
                syscall
                call write_newline

                mov $1, %edi
                mov 16(%rsp), %rsi
                mov ${argv1_len}, %edx
                mov $1, %eax
                syscall
                call write_newline

                mov $1, %edi
                mov 32(%rsp), %rsi
                mov ${envp0_len}, %edx
                mov $1, %eax
                syscall
                call write_newline

                xor %edi, %edi
                mov $231, %eax
                syscall

            exit_with_errno:
                neg %eax
                mov %eax, %edi
                mov $231, %eax
                syscall

            write_newline:
                mov $1, %edi
                lea newline(%rip), %rsi
                mov $1, %edx
                mov $1, %eax
                syscall
                ret

                .section .rodata
            self_path:
                .asciz "{path}"
            replacement_argv0:
                .asciz "{argv0}"
            replacement_argv1:
                .asciz "{argv1}"
            replacement_envp0:
                .asciz "{envp0}"
            image_marker:
                .ascii "same-image\n"
            newline:
                .ascii "\n"

                .section .data
                .align 8
            replacement_argv:
                .quad replacement_argv0, replacement_argv1, 0
            replacement_envp:
                .quad replacement_envp0, 0

                .section .bss
                .align 8
            link_buffer:
                .skip 4096
            "#,
            image_marker_len = IMAGE_MARKER.len(),
            argv0_len = ARGV0.len(),
            argv1_len = ARGV1.len(),
            envp0_len = ENVP0.len(),
            argv0 = ARGV0,
            argv1 = ARGV1,
            envp0 = ENVP0,
        );

        let root = TestDirectory::new();
        let executable = compile_assembly_program(&root.0, name, &source);
        let executable_name = executable.to_str().unwrap().to_owned();
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend.set_root_pid(ROOT_PID).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable_name.as_str()],
                &["INITIAL=1"],
                &root.0,
            )
            .unwrap();
        let mutation = if case.is_multiple_of(2) {
            std::fs::remove_file(&executable).unwrap();
            "unlinked"
        } else {
            let replacement = root.0.join(format!("{name}-replacement"));
            std::fs::write(
                &replacement,
                static_elf(&[
                    0xbf, 0x63, 0x00, 0x00, 0x00, // mov edi, 99
                    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
                    0x0f, 0x05, // syscall
                    0x0f, 0x0b, // ud2
                ]),
            )
            .unwrap();
            std::fs::rename(replacement, &executable).unwrap();
            "replaced"
        };

        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        let expected = format!(
            "{} (deleted)\n{IMAGE_MARKER}{ARGV0}\n{ARGV1}\n{ENVP0}\n",
            executable.display(),
        );
        assert_eq!(code, 0, "path={path} execveat={execveat} {mutation}");
        assert_eq!(
            stdout,
            expected.as_bytes(),
            "path={path} execveat={execveat} {mutation}"
        );
        assert!(
            stderr.is_empty(),
            "path={path} execveat={execveat} {mutation}"
        );
    }
}

#[test]
fn exec_through_symlink_reports_the_opened_executable_and_preserves_argv0() {
    if !leader_self_exec_bounded(
        "exec_through_symlink_reports_the_opened_executable_and_preserves_argv0",
    ) {
        return;
    }

    const ARGV0: &str = "not-the-path";
    let root = TestDirectory::new();
    let target_source = format!(
        r#"
            .global _start
            .text
        _start:
            lea self_path(%rip), %rdi
            lea link_buffer(%rip), %rsi
            mov $4096, %edx
            mov $89, %eax
            syscall
            test %rax, %rax
            js exit_with_errno

            mov %eax, %edx
            mov $1, %edi
            lea link_buffer(%rip), %rsi
            mov $1, %eax
            syscall
            call write_newline

            mov $1, %edi
            mov 8(%rsp), %rsi
            mov ${argv0_len}, %edx
            mov $1, %eax
            syscall
            call write_newline

            xor %edi, %edi
            mov $231, %eax
            syscall

        write_newline:
            mov $1, %edi
            lea newline(%rip), %rsi
            mov $1, %edx
            mov $1, %eax
            syscall
            ret

        exit_with_errno:
            neg %eax
            mov %eax, %edi
            mov $231, %eax
            syscall

            .section .rodata
        self_path:
            .asciz "/proc/self/exe"
        newline:
            .ascii "\n"

            .section .bss
            .align 8
        link_buffer:
            .skip 4096
        "#,
        argv0_len = ARGV0.len(),
    );
    let target = compile_assembly_program(&root.0, "actual-target", &target_source);
    std::fs::create_dir(root.0.join("components")).unwrap();
    let alias = root.0.join("exec-alias");
    std::os::unix::fs::symlink("components/../actual-target", &alias).unwrap();

    let root_source = format!(
        r#"
            .global _start
            .text
        _start:
            lea exec_path(%rip), %rdi
            lea replacement_argv(%rip), %rsi
            xor %edx, %edx
            mov $59, %eax
            syscall
            neg %eax
            mov %eax, %edi
            mov $231, %eax
            syscall

            .section .rodata
        exec_path:
            .asciz "{alias}"
        replacement_argv0:
            .asciz "{argv0}"

            .section .data
            .align 8
        replacement_argv:
            .quad replacement_argv0, 0
        "#,
        alias = alias.display(),
        argv0 = ARGV0,
    );
    let launcher = compile_assembly_program(&root.0, "symlink-exec-launcher", &root_source);
    let launcher = launcher.to_str().unwrap();
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(launcher).unwrap(),
            &[launcher],
            &[],
            &root.0,
        )
        .unwrap();

    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    let expected = format!("{}\n{ARGV0}\n", target.canonicalize().unwrap().display());
    assert_eq!(code, 0);
    assert_eq!(stdout, expected.as_bytes());
    assert!(stderr.is_empty());
}

#[test]
fn repeated_self_exec_preserves_executable_identity_argv_and_envp() {
    if !leader_self_exec_bounded("repeated_self_exec_preserves_executable_identity_argv_and_envp") {
        return;
    }

    const ROOT_PID: i32 = 37;
    const FIRST_ARGV0: &str = "first-non-path-argv0";
    const FIRST_ARGV1: &str = "stage-one-argument";
    const FIRST_ENVP0: &str = "FIRST_ENV=preserved";
    const SECOND_ARGV0: &str = "second-non-path-argv0";
    const SECOND_ARGV1: &str = "stage-two-argument";
    const SECOND_ARGV2: &str = "final-argument";
    const SECOND_ENVP0: &str = "SECOND_ENV=preserved";
    const STAGE_ONE_MARKER: &str = "stage-one\n";
    const STAGE_TWO_MARKER: &str = "stage-two\n";

    let source = r#"
        .global _start
        .text
    _start:
        cmpq $1, (%rsp)
        je initial_exec
        cmpq $2, (%rsp)
        je after_first_exec
        cmpq $3, (%rsp)
        je after_second_exec
        mov $99, %edi
        jmp exit_with_code

    initial_exec:
        lea self_path(%rip), %rdi
        lea first_argv(%rip), %rsi
        lea first_envp(%rip), %rdx
        mov $59, %eax
        syscall
        jmp exit_with_errno

    after_first_exec:
        lea stage_one_marker(%rip), %rsi
        mov $10, %edx
        call write_buffer
        lea self_path(%rip), %rdi
        call write_link
        lea numeric_path(%rip), %rdi
        call write_link

        mov 8(%rsp), %rsi
        mov $20, %edx
        call write_buffer
        call write_newline
        mov 16(%rsp), %rsi
        mov $18, %edx
        call write_buffer
        call write_newline
        mov 32(%rsp), %rsi
        mov $19, %edx
        call write_buffer
        call write_newline

        lea numeric_path(%rip), %rdi
        lea second_argv(%rip), %rsi
        lea second_envp(%rip), %rdx
        mov %rdx, %r10
        mov %rsi, %rdx
        mov %rdi, %rsi
        mov $-100, %rdi
        xor %r8d, %r8d
        mov $322, %eax
        syscall
        jmp exit_with_errno

    after_second_exec:
        lea stage_two_marker(%rip), %rsi
        mov $10, %edx
        call write_buffer
        lea self_path(%rip), %rdi
        call write_link
        lea numeric_path(%rip), %rdi
        call write_link

        mov 8(%rsp), %rsi
        mov $21, %edx
        call write_buffer
        call write_newline
        mov 16(%rsp), %rsi
        mov $18, %edx
        call write_buffer
        call write_newline
        mov 24(%rsp), %rsi
        mov $14, %edx
        call write_buffer
        call write_newline
        mov 40(%rsp), %rsi
        mov $20, %edx
        call write_buffer
        call write_newline
        xor %edi, %edi
        jmp exit_with_code

    write_link:
        lea link_buffer(%rip), %rsi
        mov $4096, %edx
        mov $89, %eax
        syscall
        test %rax, %rax
        js exit_with_errno
        mov %eax, %edx
        lea link_buffer(%rip), %rsi
        call write_buffer
        jmp write_newline

    write_buffer:
        mov $1, %edi
        mov $1, %eax
        syscall
        ret

    write_newline:
        mov $1, %edi
        lea newline(%rip), %rsi
        mov $1, %edx
        mov $1, %eax
        syscall
        ret

    exit_with_errno:
        neg %eax
        mov %eax, %edi
    exit_with_code:
        mov $231, %eax
        syscall

        .section .rodata
    self_path:
        .asciz "/proc/self/exe"
    numeric_path:
        .asciz "/proc/37/exe"
    first_argv0:
        .asciz "first-non-path-argv0"
    first_argv1:
        .asciz "stage-one-argument"
    first_envp0:
        .asciz "FIRST_ENV=preserved"
    second_argv0:
        .asciz "second-non-path-argv0"
    second_argv1:
        .asciz "stage-two-argument"
    second_argv2:
        .asciz "final-argument"
    second_envp0:
        .asciz "SECOND_ENV=preserved"
    stage_one_marker:
        .ascii "stage-one\n"
    stage_two_marker:
        .ascii "stage-two\n"
    newline:
        .ascii "\n"

        .section .data
        .align 8
    first_argv:
        .quad first_argv0, first_argv1, 0
    first_envp:
        .quad first_envp0, 0
    second_argv:
        .quad second_argv0, second_argv1, second_argv2, 0
    second_envp:
        .quad second_envp0, 0

        .section .bss
        .align 8
    link_buffer:
        .skip 4096
    "#;

    let root = TestDirectory::new();
    let executable = compile_assembly_program(&root.0, "repeated-self-exec", source);
    let executable = executable.to_str().unwrap();
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend.set_root_pid(ROOT_PID).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(executable).unwrap(),
            &[executable],
            &["INITIAL=1"],
            &root.0,
        )
        .unwrap();

    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    let expected = format!(
        "{STAGE_ONE_MARKER}{executable}\n{executable}\n{FIRST_ARGV0}\n{FIRST_ARGV1}\n{FIRST_ENVP0}\n\
         {STAGE_TWO_MARKER}{executable}\n{executable}\n{SECOND_ARGV0}\n{SECOND_ARGV1}\n\
         {SECOND_ARGV2}\n{SECOND_ENVP0}\n"
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, expected.as_bytes());
    assert!(stderr.is_empty());
}

#[test]
fn exec_comm_tracks_the_requested_filename_independently_of_exe_target_and_argv0() {
    if !leader_self_exec_bounded(
        "exec_comm_tracks_the_requested_filename_independently_of_exe_target_and_argv0",
    ) {
        return;
    }

    let root = TestDirectory::new();
    let target = compile_c_program(
        &root.0,
        "actual-name",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static int write_all(const char *bytes, size_t length) {
  while (length != 0) {
    ssize_t written = write(STDOUT_FILENO, bytes, length);
    if (written <= 0) return -1;
    bytes += written;
    length -= (size_t)written;
  }
  return 0;
}

static int print_identity(const char *argv0) {
  char link[4096];
  ssize_t link_length = readlink("/proc/self/exe", link, sizeof(link));
  if (link_length < 0 || write_all(link, (size_t)link_length) != 0 ||
      write_all("\n", 1) != 0) return -1;

  int fd = open("/proc/self/stat", O_RDONLY);
  char stat[4096];
  ssize_t length = fd < 0 ? -1 : read(fd, stat, sizeof(stat) - 1);
  if (fd >= 0) close(fd);
  if (length <= 0) return -1;
  stat[length] = 0;
  char *left = strchr(stat, '(');
  char *right = strrchr(stat, ')');
  if (left == NULL || right == NULL || right <= left ||
      write_all(left + 1, (size_t)(right - left - 1)) != 0 ||
      write_all("\n", 1) != 0 || write_all(argv0, strlen(argv0)) != 0 ||
      write_all("\n", 1) != 0) return -1;
  return 0;
}

int main(int argc, char **argv) {
  if (print_identity(argv[0]) != 0) return 20;
  if (argc == 1) {
    char *next[] = {"second-argv-zero", "after-self-exec", NULL};
    execve("/proc/self/exe", next, environ);
    return errno;
  }
  return argc == 2 && strcmp(argv[1], "after-self-exec") == 0 ? 0 : 21;
}
"#,
    );
    let alias = root.0.join("alias-name");
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let launcher_source = format!(
        r#"
#include <errno.h>
#include <unistd.h>

int main(void) {{
  char *argv[] = {{"not-the-path", NULL}};
  char *envp[] = {{NULL}};
  execve("{}", argv, envp);
  return errno;
}}
"#,
        alias.display(),
    );
    let launcher = compile_c_program(&root.0, "comm-launcher", &launcher_source);
    let launcher = launcher.to_str().unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(launcher).unwrap(),
            &[launcher],
            &["PATH=/usr/bin:/bin"],
            &root.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    let target = target.canonicalize().unwrap();
    let expected = format!(
        "{target}\nalias-name\nnot-the-path\n{target}\nexe\nsecond-argv-zero\n",
        target = target.display(),
    );
    assert_eq!(stdout, expected.as_bytes());
    assert!(stderr.is_empty());
}

fn leader_self_exec_bounded(test: &str) -> bool {
    if !kvm_available(test) {
        return false;
    }
    if std::env::var("REVERIE_LEADER_EXEC_CHILD").as_deref() == Ok(test) {
        return true;
    }
    // Guest writes can share stdout with libtest without a trailing newline.
    // Keep the execution proof on libtest's separate result channel, as the
    // workspace counter does, instead of interpreting guest bytes as records.
    let result_directory = TestDirectory::new();
    std::fs::set_permissions(&result_directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let execution_log = result_directory.0.join("libtest.log");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--logfile"])
        .arg(&execution_log)
        .env("REVERIE_LEADER_EXEC_CHILD", test)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{test}: status={:?} stdout={} stderr={}",
        output.status.code(),
        stdout,
        stderr
    );
    let executions = std::fs::read_to_string(&execution_log).unwrap();
    // Exact equality requires one completed, successful execution of this
    // name. Empty, ignored, failed, duplicate and other-name records all fail.
    assert_eq!(
        executions,
        format!("ok {test}\n"),
        "\n{test}: bounded child execution record mismatch; exit_code={:?}\nexecution records: {executions:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    false
}

#[test]
fn leader_self_exec_bounded_rejects_zero_matched_tests() {
    const TEST: &str = "leader_self_exec_bounded_rejects_zero_matched_tests";
    const MISSING: &str = "__reverie_deliberately_nonexistent_leader_self_exec_test__";
    // Keep strict-KVM failures outside the expected assertion. A permissive
    // run still follows the integration suite's ordinary availability guard.
    if !kvm_available(TEST) {
        return;
    }
    let rejected = std::panic::catch_unwind(|| leader_self_exec_bounded(MISSING))
        .expect_err("the bounded child helper accepted a zero-match child");
    let message = rejected
        .downcast_ref::<String>()
        .expect("the bounded child helper did not emit a diagnostic");
    let expected_diagnostic =
        format!("{MISSING}: bounded child execution record mismatch; exit_code=Some(0)");
    assert!(
        message.lines().any(|line| line == expected_diagnostic),
        "unexpected bounded child refusal: {message}"
    );
    assert!(
        message
            .lines()
            .any(|line| line == "execution records: \"\""),
        "the zero-match child unexpectedly recorded an execution: {message}"
    );
    assert!(
        message.lines().any(|line| line == "running 0 tests"),
        "the rejected child did not report zero matched tests: {message}"
    );
    assert!(
        message
            .lines()
            .any(|line| line
                .starts_with("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; ")),
        "the rejected child did not complete a successful zero-test run: {message}"
    );
}

#[test]
fn leader_self_exec_bounded_rejects_forged_stdout_without_execution_record() {
    const TEST: &str = "leader_self_exec_bounded_rejects_forged_stdout_without_execution_record";
    if !kvm_available(TEST) {
        return;
    }
    if std::env::var("REVERIE_LEADER_EXEC_CHILD").as_deref() == Ok(TEST) {
        // Simulate a child that fabricates the old stdout proof and exits zero
        // before libtest can record a completed test on its separate channel.
        let forged = format!(
            "\ntest {TEST} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        );
        assert_eq!(
            unsafe { libc::write(libc::STDOUT_FILENO, forged.as_ptr().cast(), forged.len()) },
            forged.len() as isize
        );
        std::process::exit(0);
    }
    let rejected = std::panic::catch_unwind(|| leader_self_exec_bounded(TEST))
        .expect_err("the bounded child helper accepted stdout without an execution record");
    let message = rejected
        .downcast_ref::<String>()
        .expect("the bounded child helper did not emit a diagnostic");
    let expected_diagnostic =
        format!("{TEST}: bounded child execution record mismatch; exit_code=Some(0)");
    assert!(
        message.lines().any(|line| line == expected_diagnostic),
        "unexpected bounded child refusal: {message}"
    );
    assert!(
        message
            .lines()
            .any(|line| line == "execution records: \"\""),
        "the prematurely exited child unexpectedly recorded an execution: {message}"
    );
    assert!(
        message.lines().any(|line| line == "running 1 test"),
        "the rejected child did not actually select the named test: {message}"
    );
    let forged_completion = format!("test {TEST} ... ok");
    assert!(
        message.lines().any(|line| line == forged_completion),
        "the rejected child did not produce the forged stdout completion: {message}"
    );
}

fn leader_self_exec_guest(
    directory: &std::path::Path,
    program: &std::path::Path,
    arguments: &[&str],
    expected: &[u8],
) {
    let mut argv = vec![program.to_str().unwrap()];
    argv.extend_from_slice(arguments);
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(program).unwrap(),
            &argv,
            &[],
            directory,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(stdout, expected);
    assert!(
        stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&stderr)
    );
}

fn leader_self_exec_identity_control(test: &str, case: &str) {
    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "running-image",
        LEADER_SELF_EXEC_IDENTITY_PROGRAM,
    );
    compile_c_program(
        &directory.0,
        "running-image.replacement",
        "int main(void) { return 77; }",
    );
    let expected = if case == "noexec" {
        "exec_returned errno=13 comm_full16_preserved=1\n".to_owned()
    } else {
        format!(
            "identity=1 link_full4096=1 argv=1 comm_full16=1 comm=657865{}\n",
            "00".repeat(13)
        )
    };
    leader_self_exec_guest(&directory.0, &program, &[case], expected.as_bytes());
}

fn leader_self_exec_name_control(test: &str, case: &str) {
    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "actual-image-name-longer-than-15",
        LEADER_SELF_EXEC_NAME_PROGRAM,
    );
    let invoked = match case {
        "direct" => program.clone(),
        "alias" => {
            let alias = directory.0.join("chosen-alias");
            std::os::unix::fs::symlink(&program, &alias).unwrap();
            alias
        }
        "script" => {
            use std::os::unix::fs::PermissionsExt;
            let script = directory.0.join("chosen-script");
            std::fs::write(&script, format!("#!{}\n", program.display())).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            script
        }
        _ => unreachable!(),
    };
    let name = invoked.file_name().unwrap().to_str().unwrap();
    let mut expected_name = [0u8; 16];
    let count = name.len().min(15);
    expected_name[..count].copy_from_slice(&name.as_bytes()[..count]);
    let hex = expected_name
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let expected = format!("comm_full16=1 comm={hex}\n");
    leader_self_exec_guest(
        &directory.0,
        &program,
        &[invoked.to_str().unwrap(), name],
        expected.as_bytes(),
    );
}

fn leader_self_exec_mutable_control(test: &str, method: &str, case: &str) {
    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "running-image",
        LEADER_SELF_EXEC_MUTABLE_PROGRAM,
    );
    compile_c_program(&directory.0, "replacement", "int main(void) { return 77; }");
    let alias = directory.0.join("alias\n\\stage");
    std::os::unix::fs::symlink(&program, &alias).unwrap();
    let (mutation, request, name) = if case == "alias" {
        ("normal", alias.to_str().unwrap(), "alias\n\\stage")
    } else {
        (case, "/proc/self/exe", "exe")
    };
    let expected = format!(
        "method={method} mutation={mutation} name-reset argv-env image identity mutable-name thread checks=PASS\n"
    );
    leader_self_exec_guest(
        &directory.0,
        &program,
        &[method, mutation, request, name, program.to_str().unwrap()],
        expected.as_bytes(),
    );
}

#[test]
fn leader_self_exec_identity_plain() {
    leader_self_exec_identity_control("leader_self_exec_identity_plain", "plain");
}

#[test]
fn leader_self_exec_identity_unlink() {
    leader_self_exec_identity_control("leader_self_exec_identity_unlink", "unlink");
}

#[test]
fn leader_self_exec_identity_replace() {
    leader_self_exec_identity_control("leader_self_exec_identity_replace", "replace");
}

#[test]
fn leader_self_exec_identity_noexec() {
    leader_self_exec_identity_control("leader_self_exec_identity_noexec", "noexec");
}

#[test]
fn leader_self_exec_identity_execute_only() {
    leader_self_exec_identity_control("leader_self_exec_identity_execute_only", "execute-only");
}

#[test]
fn leader_self_exec_name_direct() {
    leader_self_exec_name_control("leader_self_exec_name_direct", "direct");
}

#[test]
fn leader_self_exec_name_alias() {
    leader_self_exec_name_control("leader_self_exec_name_alias", "alias");
}

#[test]
fn leader_self_exec_name_script() {
    leader_self_exec_name_control("leader_self_exec_name_script", "script");
}

#[test]
fn leader_self_exec_mutable_0_normal() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_0_normal", "0", "normal");
}

#[test]
fn leader_self_exec_mutable_0_alias() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_0_alias", "0", "alias");
}

#[test]
fn leader_self_exec_mutable_0_unlink() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_0_unlink", "0", "unlink");
}

#[test]
fn leader_self_exec_mutable_0_replace() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_0_replace", "0", "replace");
}

#[test]
fn leader_self_exec_mutable_1_normal() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_1_normal", "1", "normal");
}

#[test]
fn leader_self_exec_mutable_1_alias() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_1_alias", "1", "alias");
}

#[test]
fn leader_self_exec_mutable_1_unlink() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_1_unlink", "1", "unlink");
}

#[test]
fn leader_self_exec_mutable_1_replace() {
    leader_self_exec_mutable_control("leader_self_exec_mutable_1_replace", "1", "replace");
}

const LEADER_SELF_EXEC_IDENTITY_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *stage = getenv("W12_STAGE");
    if (stage) {
        struct stat actual;
        if (stat("/proc/self/exe", &actual)) return 50;
        int identity = (unsigned long long)actual.st_dev == strtoull(getenv("W12_DEV"), NULL, 10)
            && (unsigned long long)actual.st_ino == strtoull(getenv("W12_INO"), NULL, 10);
        unsigned char comm[16], expected_comm[16] = {'e','x','e',0};
        memset(comm, 0x5a, sizeof(comm));
        if (prctl(PR_GET_NAME, comm)) return 51;
        unsigned char actual_link[PATH_MAX], expected_link[PATH_MAX];
        memset(actual_link, 0x5a, sizeof(actual_link));
        memset(expected_link, 0x5a, sizeof(expected_link));
        const char *expected = getenv("W12_LINK");
        size_t length = strlen(expected);
        if (length >= sizeof(expected_link)) return 52;
        memcpy(expected_link, expected, length);
        ssize_t count = readlink("/proc/self/exe", (char *)actual_link, sizeof(actual_link));
        int link_equal = count == (ssize_t)length && !memcmp(actual_link, expected_link, sizeof(actual_link));
        int argv_equal = argc == 2 && !strcmp(argv[0], "not-the-image") && !strcmp(argv[1], "after");
        int comm_equal = !memcmp(comm, expected_comm, sizeof(comm));
        printf("identity=%d link_full4096=%d argv=%d comm_full16=%d comm=", identity, link_equal, argv_equal, comm_equal);
        for (size_t index=0; index<sizeof(comm); ++index) printf("%02x", comm[index]);
        putchar('\n');
        return identity && link_equal && argv_equal && comm_equal ? 0 : 53;
    }
    if (argc != 2) return 10;
    struct stat before;
    if (stat("/proc/self/exe", &before)) return 11;
    int deleted = !strcmp(argv[1], "unlink") || !strcmp(argv[1], "replace");
    char link[PATH_MAX+32], dev[96], inode[96];
    if (snprintf(link,sizeof(link),"W12_LINK=%s%s",argv[0],deleted ? " (deleted)" : "") >= (int)sizeof(link)) return 12;
    snprintf(dev,sizeof(dev),"W12_DEV=%llu",(unsigned long long)before.st_dev);
    snprintf(inode,sizeof(inode),"W12_INO=%llu",(unsigned long long)before.st_ino);
    if (!strcmp(argv[1], "unlink") && unlink(argv[0])) return 13;
    if (!strcmp(argv[1], "replace")) {
        char replacement[PATH_MAX];
        if (snprintf(replacement,sizeof(replacement),"%s.replacement",argv[0]) >= (int)sizeof(replacement)) return 14;
        if (rename(replacement,argv[0])) return 15;
    }
    if (!strcmp(argv[1], "noexec") && chmod(argv[0],0600)) return 16;
    if (!strcmp(argv[1], "execute-only") && chmod(argv[0],0100)) return 22;
    if (prctl(PR_SET_NAME,"before-reexec")) return 17;
    char *arguments[] = {"not-the-image", "after", NULL};
    char *environment[] = {"W12_STAGE=1", dev, inode, link, NULL};
    errno=0;
    execve("/proc/self/exe", arguments, environment);
    int error=errno;
    unsigned char comm[16], expected_comm[16] = "before-reexec";
    memset(comm,0x5a,sizeof(comm));
    if (prctl(PR_GET_NAME,comm)) return 18;
    int preserved=!memcmp(comm,expected_comm,sizeof(comm));
    printf("exec_returned errno=%d comm_full16_preserved=%d\n",error,preserved);
    if (!strcmp(argv[1], "noexec")) return error == EACCES && preserved ? 0 : 19;
    return 20;
}
"###;

const LEADER_SELF_EXEC_NAME_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *expected = getenv("W12_EXPECT_NAME");
    if (expected) {
        unsigned char actual[16], wanted[16] = {0};
        size_t length = strlen(expected);
        if (length > 15) length = 15;
        memcpy(wanted, expected, length);
        memset(actual,0x5a,sizeof(actual));
        if (prctl(PR_GET_NAME,actual)) return 20;
        int equal=!memcmp(actual,wanted,sizeof(actual));
        printf("comm_full16=%d comm=",equal);
        for (size_t index=0; index<sizeof(actual); ++index) printf("%02x",actual[index]);
        putchar('\n');
        return equal ? 0 : 21;
    }
    if (argc != 3) return 10;
    if (prctl(PR_SET_NAME,"mutated-before")) return 11;
    char setting[256];
    if (snprintf(setting,sizeof(setting),"W12_EXPECT_NAME=%s",argv[2]) >= (int)sizeof(setting)) return 12;
    char *arguments[] = {"misleading-argv0", "payload", NULL};
    char *environment[] = {setting,NULL};
    execve(argv[1],arguments,environment);
    perror("execve");
    return 13;
}
"###;

const LEADER_SELF_EXEC_MUTABLE_PROGRAM: &str = r###"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile unsigned image_value = 0x12345678;
static const char renamed[] = "after\n\\name";
static int failures;
static void require(int condition, const char *what) {
    if (!condition) { printf("FAIL %s errno=%d\n", what, errno); ++failures; }
}
static int name_is(const char *name) {
    unsigned char actual[64], expected[64];
    memset(actual, 0x5a, sizeof(actual)); memset(expected, 0x5a, sizeof(expected));
    memset(expected, 0, 16); memcpy(expected, name, strlen(name) < 15 ? strlen(name) : 15);
    return prctl(PR_GET_NAME, actual, 0, 0, 0) == 0 && !memcmp(actual, expected, sizeof(actual));
}
static int status_name_is(const char *name) {
    unsigned char actual[16384]; memset(actual, 0x5a, sizeof(actual));
    char expected[128] = "Name:\t"; size_t expected_length = 6;
    for (size_t index = 0; name[index] && index < 15; ++index) {
        if (name[index] == '\n') { expected[expected_length++] = '\\'; expected[expected_length++] = 'n'; }
        else if (name[index] == '\\') { expected[expected_length++] = '\\'; expected[expected_length++] = '\\'; }
        else expected[expected_length++] = name[index];
    }
    expected[expected_length++] = '\n';
    int descriptor = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return 0;
    ssize_t count = read(descriptor, actual, sizeof(actual)); close(descriptor);
    if (count < (ssize_t)expected_length || memcmp(actual, expected, expected_length)) return 0;
    for (size_t index = (size_t)count; index < sizeof(actual); ++index) if (actual[index] != 0x5a) return 0;
    return 1;
}
static void *thread_name(void *unused) {
    (void)unused;
    if (!name_is(renamed) || prctl(PR_SET_NAME, "worker-private", 0, 0, 0) || !name_is("worker-private") || !status_name_is(renamed)) return (void *)1;
    return NULL;
}
static long execute(int method, const char *path, char **arguments, char **environment) {
    if (method) return syscall(SYS_execveat, AT_FDCWD, path, arguments, environment, 0);
    return syscall(SYS_execve, path, arguments, environment);
}
int main(int argc, char **argv) {
    if (argc == 7 && !strcmp(argv[1], "after")) {
        require(!strcmp(argv[0], "different-argv-zero") && !strcmp(argv[6], "argument-retained"), "argv bytes");
        require(getenv("LEADER_TEST_ENV") && !strcmp(getenv("LEADER_TEST_ENV"), "preserved"), "environment");
        require(image_value == 0x12345678, "new image data reset");
        require(name_is(argv[3]), "native exec filename name reset");
        require(status_name_is(argv[3]), "initial status name");
        unsigned char actual[4096], expected[4096];
        memset(actual, 0x5a, sizeof(actual)); memset(expected, 0x5a, sizeof(expected));
        size_t expected_length = strlen(argv[4]); memcpy(expected, argv[4], expected_length);
        if (strcmp(argv[5], "normal")) { memcpy(expected+expected_length, " (deleted)", 10); expected_length += 10; }
        ssize_t length = readlink("/proc/self/exe", (char *)actual, sizeof(actual));
        require(length == (ssize_t)expected_length && !memcmp(actual, expected, sizeof(actual)), "retained executable identity full4096");
        require(prctl(PR_SET_NAME, renamed, 0, 0, 0) == 0 && name_is(renamed), "mutable name after exec full64");
        require(status_name_is(renamed), "escaped status after exec");
        pthread_t worker; void *result = (void *)1;
        int created = pthread_create(&worker, NULL, thread_name, NULL);
        require(created == 0, "post-exec thread creation");
        if (!created) require(pthread_join(worker, &result) == 0 && result == NULL, "per-thread name and leader status");
        require(name_is(renamed) && status_name_is(renamed), "leader name preserved after thread");
        printf("method=%s mutation=%s name-reset argv-env image identity mutable-name thread checks=%s\n", argv[2], argv[5], failures ? "FAIL" : "PASS");
        return failures ? 1 : 0;
    }
    if (argc != 6) return 90;
    int method = atoi(argv[1]);
    require(prctl(PR_SET_NAME, "before-exec", 0, 0, 0) == 0 && name_is("before-exec"), "pre-exec name");
    image_value = 0x87654321;
    char *environment[] = {"LEADER_TEST_ENV=preserved", "PATH=/usr/bin:/bin", NULL};
    char *arguments[] = {"different-argv-zero", "after", argv[1], argv[4], argv[5], argv[2], "argument-retained", NULL};
    if (!strcmp(argv[2], "unlink")) require(unlink(argv[5]) == 0, "unlink current image");
    if (!strcmp(argv[2], "replace")) require(rename("replacement", argv[5]) == 0, "replace current image");
    if (failures) return 91;
    execute(method, argv[3], arguments, environment);
    printf("FAIL exec returned method=%d errno=%d name-unchanged=%d\n", method, errno, name_is("before-exec"));
    return 92;
}
"###;

#[test]
fn proc_root_retains_fchmodat2_native_control() {
    assert!(kvm_available("proc_root_retains_fchmodat2_native_control"));
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "review-535-fchmodat2",
        PROC_ROOT_FCHMODAT2_PROGRAM,
    );
    let native = std::process::Command::new(&executable)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    println!(
        "NATIVE status={:?} stdout={} stderr={}",
        native.status.code(),
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.status.code(), Some(0));
    assert!(native.stdout.is_empty() && native.stderr.is_empty());
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap()],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "KVM stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(stdout.is_empty() && stderr.is_empty());
}

const PROC_ROOT_FCHMODAT2_PROGRAM: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

static int change(int descriptor, const char *path, unsigned mode, int flags, int expected_errno) {
    errno = 0;
    long result = syscall(SYS_fchmodat2, descriptor, path, mode, flags);
    if (result != (expected_errno ? -1 : 0) || errno != expected_errno) {
        printf("path=%s flags=%d result=%ld errno=%d expected_errno=%d\n", path, flags, result, errno, expected_errno);
        return 1;
    }
    return 0;
}

int main(void) {
    unsigned char expected[128], actual[128];
    for (unsigned index = 0; index < sizeof(expected); ++index) expected[index] = (unsigned char)(index ^ 0xa5);
    int file = open("payload", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (file < 0 || write(file, expected, sizeof(expected)) != sizeof(expected)) return 80;
    if (mkdir("directory", 0700) || symlink("directory", "alias")) return 81;
    if (change(AT_FDCWD, "directory///", 0711, 0, 0)) return 82;
    if (change(AT_FDCWD, "alias///", 0712, AT_SYMLINK_NOFOLLOW, 0)) return 83;
    if (change(AT_FDCWD, "payload///", 0777, 0, ENOTDIR)) return 84;
    if (change(file, "", 0601, 0, ENOENT)) return 85;
    if (change(file, "", 0601, AT_EMPTY_PATH, 0)) return 86;
    if (change(-1, "directory///", 0777, 0, EBADF)) return 87;
    if (change(-1, "directory///", 0777, 0x40000000, EINVAL)) return 88;
    char absolute[8192], cwd[4096];
    if (!getcwd(cwd, sizeof(cwd)) || snprintf(absolute, sizeof(absolute), "%s/directory///", cwd) >= sizeof(absolute)) return 89;
    if (change(-1, absolute, 0713, 0, 0)) return 90;
    struct stat metadata;
    if (fstat(file, &metadata) || (metadata.st_mode & 07777) != 0601) return 91;
    if (lseek(file, 0, SEEK_SET) != 0 || read(file, actual, sizeof(actual)) != sizeof(actual) || memcmp(actual, expected, sizeof(actual))) return 92;
    if (stat("directory", &metadata) || (metadata.st_mode & 07777) != 0713) return 93;
    char link[32] = {0};
    if (readlink("alias", link, sizeof(link)) != 9 || memcmp(link, "directory", 9)) return 94;
    close(file);
    unlink("alias");
    unlink("payload");
    rmdir("directory");
    return 0;
}
"#;

#[test]
fn real_kvm_synthetic_proc_snapshot_is_immutable_and_opath_correct() {
    assert!(kvm_available(
        "real_kvm_synthetic_proc_snapshot_is_immutable_and_opath_correct"
    ));
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "synthetic-proc-snapshot",
        SYNTHETIC_PROC_SNAPSHOT_PROGRAM,
    );
    let native_open_errno = |path: &str, flags: libc::c_int| {
        let path = std::ffi::CString::new(path).unwrap();
        for _ in 0..16 {
            // SAFETY: path is NUL-terminated and live for the call. Mode is
            // supplied for every O_CREAT probe, and each success is closed.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    flags | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if result >= 0 {
                // SAFETY: openat returned a new owned descriptor.
                assert_eq!(unsafe { libc::close(result as libc::c_int) }, 0);
                panic!("native policy probe unexpectedly opened {path:?}");
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap();
            if errno != libc::EINTR {
                return errno;
            }
        }
        panic!("native policy probe exhausted EINTR retry bound for {path:?}");
    };
    let policy_error = native_open_errno(
        "/proc/self/status",
        libc::O_RDONLY | libc::O_CREAT | libc::O_DIRECTORY,
    );
    let create_directory = native_open_errno(
        "/proc/uptime",
        libc::O_RDONLY | libc::O_CREAT | libc::O_DIRECTORY,
    );
    assert_eq!(create_directory, policy_error);
    let (expected_exclusive, expected_mounts_nofollow) = match policy_error {
        libc::EINVAL => (libc::EINVAL, libc::EINVAL),
        libc::ENOTDIR => (libc::EEXIST, libc::ENOTDIR),
        errno => panic!("unsupported native create-directory policy errno {errno}"),
    };
    assert_eq!(
        native_open_errno(
            "/proc/self/status",
            libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_DIRECTORY,
        ),
        expected_exclusive
    );
    assert_eq!(
        native_open_errno(
            "/proc/mounts",
            libc::O_RDONLY | libc::O_CREAT | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        ),
        expected_mounts_nofollow
    );
    let create_directory = create_directory.to_string();
    let expected_exclusive = expected_exclusive.to_string();
    let expected_mounts_nofollow = expected_mounts_nofollow.to_string();
    let (stdout, stderr) = run_host_program_captured(
        executable.to_str().unwrap(),
        &[
            executable.to_str().unwrap(),
            &create_directory,
            &expected_exclusive,
            &expected_mounts_nofollow,
        ],
        &directory.0,
    );
    assert_eq!(stdout, b"synthetic proc snapshot PASS\n");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
}

const SYNTHETIC_PROC_SNAPSHOT_PROGRAM: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(expression) do { \
    if (!(expression)) { \
        dprintf(STDERR_FILENO, "failure line=%d errno=%d\n", __LINE__, errno); \
        return 93; \
    } \
} while (0)

#define EXPECT_ERROR(expression, expected) do { \
    errno = 0; \
    long result = (long)(expression); \
    CHECK(result == -1 && errno == (expected)); \
} while (0)

#define PRIVATE_TMPFILE (O_TMPFILE & ~O_DIRECTORY)

static void *failed_mapping(int descriptor, int protection, int flags) {
    errno = 0;
    return mmap(NULL, 4096, protection, flags, descriptor, 0);
}

int main(int argc, char **argv) {
    static const char expected[] = "0.00 0.00\n";
    char actual[sizeof(expected)] = {0};
    struct stat metadata;

    CHECK(argc == 4);
    int expected_create_directory = atoi(argv[1]);
    int expected_create_directory_exclusive = atoi(argv[2]);
    int expected_mounts_create_directory_nofollow = atoi(argv[3]);
    CHECK(expected_create_directory > 0);
    CHECK(expected_create_directory_exclusive > 0);
    CHECK(expected_mounts_create_directory_nofollow > 0);

    int descriptor = open("/proc/uptime", O_RDONLY | O_CLOEXEC);
    CHECK(descriptor >= 0);
    CHECK((fcntl(descriptor, F_GETFL) & O_ACCMODE) == O_RDONLY);
    CHECK((fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK(fstat(descriptor, &metadata) == 0);
    CHECK(S_ISREG(metadata.st_mode));
    CHECK((metadata.st_mode & 0777) == 0444);
    CHECK(metadata.st_size == (off_t)(sizeof(expected) - 1));
    CHECK(read(descriptor, actual, sizeof(actual)) == (ssize_t)(sizeof(expected) - 1));
    CHECK(memcmp(actual, expected, sizeof(expected) - 1) == 0);

    const char *bad_path = (const char *)(uintptr_t)-1;
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_RDWR | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_ACCMODE | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_WRONLY | O_TMPFILE, 0600), EFAULT);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_ACCMODE | O_TMPFILE, 0600), EFAULT);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_PATH | O_TMPFILE, 0600), EFAULT);
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path, O_RDONLY | O_DIRECTORY, 0600), EFAULT);
    EXPECT_ERROR(open("", O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("", O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("", O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("", O_RDWR | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("", O_ACCMODE | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("", O_WRONLY | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("", O_ACCMODE | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("", O_PATH | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("", O_RDONLY | O_DIRECTORY, 0600), ENOENT);
    EXPECT_ERROR(openat(123456, "missing-open-precedence", O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(openat(123456, "missing-open-precedence", O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(openat(123456, "missing-open-precedence", O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(openat(123456, "missing-open-precedence", O_WRONLY | O_TMPFILE, 0600), EBADF);
    EXPECT_ERROR(openat(123456, "missing-open-precedence", O_ACCMODE | O_TMPFILE, 0600), EBADF);
    EXPECT_ERROR(openat(123456, "missing-open-precedence", O_PATH | O_TMPFILE, 0600), EBADF);
    EXPECT_ERROR(openat(123456, "missing-open-precedence", O_RDONLY | O_DIRECTORY, 0600), EBADF);
    EXPECT_ERROR(open("missing-open-precedence", O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("missing-open-precedence", O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("missing-open-precedence", O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("missing-open-precedence", O_WRONLY | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("missing-open-precedence", O_ACCMODE | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("missing-open-precedence", O_PATH | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("missing-open-precedence", O_RDONLY | O_DIRECTORY, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999", O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999", O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999", O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999", O_WRONLY | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999", O_ACCMODE | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999", O_PATH | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999", O_RDONLY | O_DIRECTORY, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fd/999999", O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/self/fd/999999", O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/self/fd/999999", O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/self/fd/999999", O_WRONLY | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fd/999999", O_ACCMODE | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fd/999999", O_PATH | O_TMPFILE, 0600), ENOENT);
    EXPECT_ERROR(open("/proc/self/fd/999999", O_RDONLY | O_DIRECTORY, 0600), ENOENT);

    int early_create_directory = expected_create_directory == EINVAL;
    EXPECT_ERROR(syscall(SYS_openat, AT_FDCWD, bad_path,
                         O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 early_create_directory ? EINVAL : EFAULT);
    EXPECT_ERROR(open("", O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 early_create_directory ? EINVAL : ENOENT);
    EXPECT_ERROR(openat(123456, "missing-open-precedence",
                        O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 early_create_directory ? EINVAL : EBADF);
    EXPECT_ERROR(open("missing-open-precedence",
                      O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 early_create_directory ? EINVAL : ENOENT);
    EXPECT_ERROR(open("/proc/self/fdinfo/999999",
                      O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 early_create_directory ? EINVAL : ENOENT);
    EXPECT_ERROR(open("/proc/self/fd/999999",
                      O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 early_create_directory ? EINVAL : ENOENT);

    EXPECT_ERROR(write(descriptor, "x", 1), EBADF);
    EXPECT_ERROR(syscall(SYS_pwrite64, descriptor, "x", 1, 0), ESPIPE);
    int cmdline = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    CHECK(cmdline >= 0);
    EXPECT_ERROR(syscall(SYS_pwrite64, cmdline, "x", 1, 0), EBADF);
    EXPECT_ERROR(syscall(SYS_pwrite64, cmdline, "x", 0, (off_t)-1), EINVAL);
    CHECK(close(cmdline) == 0);
    EXPECT_ERROR(ftruncate(descriptor, 0), EINVAL);
    EXPECT_ERROR(syscall(SYS_fallocate, descriptor, 0, 0, 1), EBADF);
    CHECK(getuid() == 0 && geteuid() == 0);
    EXPECT_ERROR(fchmod(descriptor, 0666), EPERM);
    CHECK(fstat(descriptor, &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0444);

    void *mapping = failed_mapping(
        descriptor,
        PROT_READ | PROT_WRITE,
        MAP_SHARED
    );
    CHECK(mapping == MAP_FAILED && errno == EACCES);

    char procfd[64];
    CHECK(snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", descriptor) > 0);
    char unsupported_fdinfo[64];
    CHECK(snprintf(unsupported_fdinfo, sizeof(unsupported_fdinfo),
                   "/proc/self/fdinfo/%d", descriptor) > 0);
    CHECK(stat(unsupported_fdinfo, &metadata) == 0);
    CHECK(S_ISREG(metadata.st_mode));
    EXPECT_ERROR(open(unsupported_fdinfo, O_RDONLY), ENOSYS);
    EXPECT_ERROR(open(unsupported_fdinfo, O_RDONLY | O_DIRECTORY), ENOTDIR);
    EXPECT_ERROR(open(unsupported_fdinfo, O_WRONLY | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(unsupported_fdinfo, O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 expected_create_directory);
    EXPECT_ERROR(open(unsupported_fdinfo,
                      O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY, 0600),
                 expected_create_directory_exclusive);
    EXPECT_ERROR(open(procfd, O_WRONLY), EACCES);
    EXPECT_ERROR(open(procfd, O_RDWR), EACCES);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_TRUNC), EACCES);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_DIRECT), EINVAL);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open(procfd, O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open(procfd, O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open(procfd, O_RDWR | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open(procfd, O_ACCMODE | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open(procfd, O_WRONLY | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_RDWR | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_ACCMODE | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_PATH | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_DIRECTORY), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_PATH | O_DIRECTORY), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_PATH | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_DIRECTORY | O_NOFOLLOW), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_PATH | O_DIRECTORY | O_NOFOLLOW), ENOTDIR);
    EXPECT_ERROR(open(procfd, O_WRONLY | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_TRUNC | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_DIRECT | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open(procfd, O_WRONLY | O_CREAT | O_EXCL, 0600), EEXIST);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_CREAT | O_EXCL | O_TRUNC, 0600), EEXIST);
    EXPECT_ERROR(open(procfd, O_WRONLY | O_CREAT | O_EXCL | O_DIRECT | O_NOFOLLOW, 0600), EEXIST);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 expected_create_directory);
    EXPECT_ERROR(open(procfd, O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY, 0600),
                 expected_create_directory_exclusive);
    int procfd_path = open(procfd, O_PATH | O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_DIRECT, 0600);
    CHECK(procfd_path >= 0 && (fcntl(procfd_path, F_GETFL) & O_PATH) != 0);
    CHECK(close(procfd_path) == 0);
    EXPECT_ERROR(open(procfd, O_PATH | O_CREAT | O_EXCL | O_NOFOLLOW, 0600), ELOOP);
    int reopened = open(procfd, O_RDONLY | O_NONBLOCK | O_APPEND | O_SYNC);
    CHECK(reopened >= 0);
    CHECK((fcntl(reopened, F_GETFL) & (O_NONBLOCK | O_APPEND | O_SYNC)) ==
          (O_NONBLOCK | O_APPEND | O_SYNC));
    CHECK(close(reopened) == 0);

    int ordinary = open("fdinfo-target", O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(ordinary >= 0);
    char fdinfo[64];
    CHECK(snprintf(fdinfo, sizeof(fdinfo), "/proc/self/fdinfo/%d", ordinary) > 0);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_TMPFILE | O_NOFOLLOW, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_TMPFILE | O_TRUNC, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_TMPFILE | O_DIRECT, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_TMPFILE | O_EXCL, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_TMPFILE | O_NOFOLLOW | O_TRUNC | O_DIRECT | O_EXCL, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_RDWR | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_ACCMODE | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open(fdinfo, O_WRONLY | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(fdinfo, O_RDWR | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(fdinfo, O_ACCMODE | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(fdinfo, O_PATH | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open(fdinfo, O_PATH | O_TMPFILE | O_NOFOLLOW | O_TRUNC | O_DIRECT | O_EXCL, 0600), ENOTDIR);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_DIRECTORY), ENOTDIR);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 expected_create_directory);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY, 0600),
                 expected_create_directory_exclusive);
    EXPECT_ERROR(open(fdinfo, O_RDONLY | O_CREAT | O_DIRECTORY | O_NOFOLLOW, 0600),
                 expected_create_directory);
    EXPECT_ERROR(open(fdinfo,
                      O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY | O_NOFOLLOW,
                      0600),
                 expected_create_directory_exclusive);
    int readable_fdinfo = open(fdinfo, O_RDONLY | O_CLOEXEC);
    CHECK(readable_fdinfo >= 0);
    EXPECT_ERROR(syscall(SYS_pwrite64, readable_fdinfo, "x", 1, 0), ESPIPE);
    EXPECT_ERROR(syscall(SYS_pwrite64, readable_fdinfo, "x", 0, 0), ESPIPE);
    EXPECT_ERROR(syscall(SYS_pwrite64, readable_fdinfo, "x", 1, (off_t)-1), EINVAL);
    EXPECT_ERROR(syscall(SYS_pwrite64, readable_fdinfo, "x", 0, (off_t)-1), EINVAL);
    EXPECT_ERROR(syscall(SYS_pwrite64, readable_fdinfo,
                         (const char *)(uintptr_t)-1, 1, 0),
                 ESPIPE);
    CHECK(close(readable_fdinfo) == 0);

    if (expected_create_directory == ENOTDIR) {
        static const char *const missing_fdinfo_paths[] = {
            "/proc/self/fdinfo/999999",
            "/proc/self/fdinfo/not-a-fd",
            "/proc/self/fdinfo/03",
        };
        static const int create_directory_flags[] = {
            O_RDONLY | O_CREAT | O_DIRECTORY,
            O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY,
            O_RDONLY | O_CREAT | O_DIRECTORY | O_NOFOLLOW,
            O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY | O_NOFOLLOW,
        };
        for (size_t path_index = 0;
             path_index < sizeof(missing_fdinfo_paths) / sizeof(missing_fdinfo_paths[0]);
             ++path_index) {
            for (size_t flag_index = 0;
                 flag_index < sizeof(create_directory_flags) / sizeof(create_directory_flags[0]);
                 ++flag_index) {
                EXPECT_ERROR(open(missing_fdinfo_paths[path_index],
                                  create_directory_flags[flag_index], 0600),
                             ENOENT);
            }
        }
        for (size_t flag_index = 0;
             flag_index < sizeof(create_directory_flags) / sizeof(create_directory_flags[0]);
             ++flag_index) {
            EXPECT_ERROR(open("/proc/self/fdinfo/",
                              create_directory_flags[flag_index], 0600),
                         EISDIR);
        }
    }
    CHECK(close(ordinary) == 0);
    CHECK(unlink("fdinfo-target") == 0);

    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_DIRECTORY), ENOTDIR);
    EXPECT_ERROR(open("/proc/uptime", O_PATH | O_DIRECTORY), ENOTDIR);
    EXPECT_ERROR(open("/proc/uptime", O_WRONLY), EACCES);
    EXPECT_ERROR(open("/proc/uptime", O_RDWR), EACCES);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_TRUNC), EACCES);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_DIRECT), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_CREAT | O_EXCL, 0600), EEXIST);
    EXPECT_ERROR(open("/proc/uptime", O_WRONLY | O_CREAT | O_EXCL, 0600), EEXIST);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_CREAT | O_EXCL | O_TRUNC, 0600), EEXIST);
    EXPECT_ERROR(open("/proc/uptime", O_WRONLY | O_CREAT | O_EXCL | O_DIRECT | O_NOFOLLOW, 0600), EEXIST);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_CREAT | O_DIRECTORY, 0600),
                 expected_create_directory);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY, 0600),
                 expected_create_directory_exclusive);
    EXPECT_ERROR(open("/proc/mounts", O_RDONLY | O_CREAT | O_DIRECTORY | O_NOFOLLOW, 0600),
                 expected_mounts_create_directory_nofollow);
    EXPECT_ERROR(open("/proc/mounts",
                      O_RDONLY | O_CREAT | O_EXCL | O_DIRECTORY | O_NOFOLLOW,
                      0600),
                 expected_create_directory_exclusive);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_TMPFILE | O_NOFOLLOW, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_TMPFILE | O_TRUNC, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_TMPFILE | O_DIRECT, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_TMPFILE | O_EXCL, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_RDONLY | O_TMPFILE | O_NOFOLLOW | O_TRUNC | O_DIRECT | O_EXCL, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_WRONLY | PRIVATE_TMPFILE, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_WRONLY | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_RDWR | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_ACCMODE | O_TMPFILE | O_CREAT, 0600), EINVAL);
    EXPECT_ERROR(open("/proc/uptime", O_WRONLY | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open("/proc/uptime", O_RDWR | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open("/proc/uptime", O_ACCMODE | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open("/proc/uptime", O_PATH | O_TMPFILE, 0600), ENOTDIR);
    EXPECT_ERROR(open("/proc/uptime", O_PATH | O_TMPFILE | O_NOFOLLOW | O_TRUNC | O_DIRECT | O_EXCL, 0600), ENOTDIR);
    int ignored_create = open("/proc/uptime", O_PATH | O_CREAT | O_EXCL, 0600);
    CHECK(ignored_create >= 0 && (fcntl(ignored_create, F_GETFL) & O_PATH) != 0);
    CHECK(close(ignored_create) == 0);
    int regular_nofollow = open("/proc/uptime", O_RDONLY | O_NOFOLLOW);
    CHECK(regular_nofollow >= 0);
    CHECK((fcntl(regular_nofollow, F_GETFL) & O_NOFOLLOW) != 0);
    CHECK(close(regular_nofollow) == 0);

    EXPECT_ERROR(open("/proc/mounts", O_RDONLY | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open("/proc/mounts", O_WRONLY | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open("/proc/mounts", O_RDONLY | O_TRUNC | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open("/proc/mounts", O_RDONLY | O_DIRECT | O_NOFOLLOW), ELOOP);
    EXPECT_ERROR(open("/proc/mounts", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600), EEXIST);
    EXPECT_ERROR(open("/proc/mounts", O_RDONLY | O_DIRECTORY | O_NOFOLLOW), ENOTDIR);
    EXPECT_ERROR(open("/proc/mounts", O_PATH | O_DIRECTORY | O_NOFOLLOW), ENOTDIR);
    int status = open("/proc/uptime", O_RDONLY | O_NONBLOCK | O_APPEND | O_SYNC);
    CHECK(status >= 0);
    CHECK((fcntl(status, F_GETFL) & (O_NONBLOCK | O_APPEND | O_SYNC)) ==
          (O_NONBLOCK | O_APPEND | O_SYNC));
    CHECK(close(status) == 0);

    int path = open(
        "/proc/uptime",
        O_PATH | O_CLOEXEC | O_TRUNC | O_DIRECT | O_APPEND | O_SYNC | O_NONBLOCK
    );
    CHECK(path >= 0);
    CHECK((fcntl(path, F_GETFL) & O_PATH) != 0);
    CHECK((fcntl(path, F_GETFL) & (O_TRUNC | O_DIRECT | O_APPEND | O_SYNC | O_NONBLOCK)) == 0);
    CHECK((fcntl(path, F_GETFD) & FD_CLOEXEC) != 0);
    EXPECT_ERROR(read(path, actual, 1), EBADF);
    EXPECT_ERROR(syscall(SYS_pwrite64, path, "x", 1, 0), EBADF);
    EXPECT_ERROR(syscall(SYS_pwrite64, path, "x", 0, (off_t)-1), EINVAL);
    EXPECT_ERROR(ftruncate(path, 0), EBADF);
    EXPECT_ERROR(ftruncate(path, -1), EINVAL);
    EXPECT_ERROR(fchmod(path, 0666), EBADF);
    mapping = failed_mapping(path, PROT_READ, MAP_PRIVATE);
    CHECK(mapping == MAP_FAILED && errno == EBADF);

    int nofollow = open("/proc/uptime", O_PATH | O_NOFOLLOW);
    CHECK(nofollow >= 0);
    CHECK((fcntl(nofollow, F_GETFL) & (O_PATH | O_NOFOLLOW)) == (O_PATH | O_NOFOLLOW));
    CHECK(fstat(nofollow, &metadata) == 0 && S_ISREG(metadata.st_mode));

    CHECK(close(nofollow) == 0);
    CHECK(close(path) == 0);
    CHECK(close(descriptor) == 0);
    CHECK(write(STDOUT_FILENO, "synthetic proc snapshot PASS\n", 29) == 29);
    return 0;
}
"#;

#[test]
fn proc_root_original_mutation_vectors_match_native() {
    assert!(kvm_available(
        "proc_root_original_mutation_vectors_match_native"
    ));
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "proc-root-mutations",
        PROC_ROOT_MUTATION_PROGRAM,
    );
    let native = std::process::Command::new(&executable).output().unwrap();
    println!(
        "native original vectors: {}",
        String::from_utf8_lossy(&native.stdout)
    );
    assert_eq!(
        native.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(native.stderr.is_empty());
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap()],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    println!(
        "guest original vectors: {}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(code, 0);
}

const PROC_ROOT_MUTATION_PROGRAM: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    char directory[] = "/tmp/reverie-proc-mutation-XXXXXX";
    if (!mkdtemp(directory) || chdir(directory)) return 80;
    int file = open("local-source", O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (file < 0 || write(file, "payload", 7) != 7 || close(file) || mkdir("removable", 0700)) return 81;
    int proc = open("/proc", O_RDONLY | O_DIRECTORY);
    if (proc < 0) return 82;
    char missing[4096], single_slash[4096], source[4096], removable[4096];
    if (snprintf(missing, sizeof(missing), "%s/escaped///", directory + 1) >= sizeof(missing)) return 83;
    if (snprintf(single_slash, sizeof(single_slash), "%s/escaped/", directory + 1) >= sizeof(single_slash)) return 83;
    if (snprintf(source, sizeof(source), "%s/local-source", directory + 1) >= sizeof(source)) return 83;
    if (snprintf(removable, sizeof(removable), "%s/removable///", directory + 1) >= sizeof(removable)) return 83;
    struct operation { const char *name; long number; long args[6]; } operations[] = {
        {"mkdirat single slash", SYS_mkdirat, {proc, (long)single_slash, 0755}},
        {"mkdirat", SYS_mkdirat, {proc, (long)missing, 0755}},
        {"unlinkat", SYS_unlinkat, {proc, (long)removable, AT_REMOVEDIR}},
        {"renameat source", SYS_renameat, {proc, (long)source, AT_FDCWD, (long)"local-destination"}},
        {"renameat destination", SYS_renameat, {AT_FDCWD, (long)"local-source", proc, (long)missing}},
        {"renameat2 source", SYS_renameat2, {proc, (long)source, AT_FDCWD, (long)"local-destination"}},
        {"renameat2 destination", SYS_renameat2, {AT_FDCWD, (long)"local-source", proc, (long)missing}},
        {"linkat source", SYS_linkat, {proc, (long)source, AT_FDCWD, (long)"local-destination"}},
        {"linkat destination", SYS_linkat, {AT_FDCWD, (long)"local-source", proc, (long)missing}},
        {"symlinkat", SYS_symlinkat, {(long)"local-source", proc, (long)missing}},
        {"fchmodat", SYS_fchmodat, {proc, (long)source, 0777}},
        {"mknodat", SYS_mknodat, {proc, (long)missing, S_IFIFO | 0600}},
        {"utimensat", SYS_utimensat, {proc, (long)source}},
    };
    int failures = 0;
    for (unsigned index = 0; index < sizeof(operations) / sizeof(operations[0]); ++index) {
        const struct operation *operation = &operations[index];
        errno = 0;
        long result = syscall(operation->number, operation->args[0], operation->args[1], operation->args[2], operation->args[3], operation->args[4], operation->args[5]);
        printf("%s result=%ld errno=%d\n", operation->name, result, errno);
        if (result != -1 || errno != ENOENT) ++failures;
        struct stat metadata;
        if (stat("local-source", &metadata) || (metadata.st_mode & 0777) != 0600 || metadata.st_size != 7) return 84;
        file = open("local-source", O_RDONLY);
        char bytes[16], expected[16];
        memset(bytes, 0xa5, sizeof(bytes));
        memset(expected, 0xa5, sizeof(expected));
        memcpy(expected, "payload", 7);
        if (file < 0 || read(file, bytes, sizeof(bytes)) != 7 || memcmp(bytes, expected, sizeof(bytes)) || close(file)) return 85;
        if (stat("removable", &metadata) || !S_ISDIR(metadata.st_mode)) return 86;
        errno = 0;
        if (lstat("escaped", &metadata) != -1 || errno != ENOENT) return 87;
        errno = 0;
        if (lstat("local-destination", &metadata) != -1 || errno != ENOENT) return 88;
    }
    if (close(proc) || unlink("local-source") || rmdir("removable") || chdir("/") || rmdir(directory)) return 89;
    return failures ? 94 : 0;
}
"#;

fn proc_root_consumer_case(case: usize) {
    assert!(kvm_available("proc_root_consumer_case"));
    let directory = TestDirectory::new();
    let program = format!("#define CASE {case}\n{}", PROC_ROOT_CONSUMER_PROGRAM);
    let executable = compile_c_program(&directory.0, "proc-root-consumer", &program);
    let native = std::process::Command::new(&executable)
        .arg("native")
        .current_dir(&directory.0)
        .output()
        .unwrap();
    println!(
        "native consumer={case}: {:?} {}",
        native.status.code(),
        String::from_utf8_lossy(&native.stdout)
    );
    assert_eq!(
        native.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(native.stderr.is_empty());
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap(), "guest"],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    println!(
        "guest consumer={case}: {code} {}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(code, 0);
}

#[test]
fn proc_root_received_full_metadata() {
    proc_root_consumer_case(0);
}
#[test]
fn proc_root_received_empty_enumeration() {
    proc_root_consumer_case(1);
}
#[test]
fn proc_root_received_allowlisted_contents() {
    proc_root_consumer_case(2);
}
#[test]
fn proc_root_received_aliases_and_reuse() {
    proc_root_consumer_case(3);
}
#[test]
fn proc_root_received_fork_exec() {
    proc_root_consumer_case(4);
}
#[test]
fn proc_root_received_filesystem_stat_refusal() {
    proc_root_consumer_case(5);
}
#[test]
fn proc_root_cwd_restriction_and_ordinary_positive() {
    proc_root_consumer_case(6);
}
#[test]
fn proc_root_received_shared_thread_files() {
    proc_root_consumer_case(7);
}

const PROC_ROOT_CONSUMER_PROGRAM: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression) do { if (!(expression)) { printf("failure line=%d errno=%d\n", __LINE__, errno); return 93; } } while (0)

static int transfer(int descriptor, int cloexec) {
    int sockets[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
    char payload = 'x';
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec vector = {.iov_base = &payload, .iov_len = 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(int));
    CHECK(sendmsg(sockets[0], &message, 0) == 1);
    CHECK(close(descriptor) == 0);
    memset(control, 0, sizeof(control));
    message.msg_controllen = sizeof(control);
    payload = 0;
    CHECK(recvmsg(sockets[1], &message, cloexec ? MSG_CMSG_CLOEXEC : 0) == 1);
    CHECK(payload == 'x' && !(message.msg_flags & MSG_CTRUNC));
    header = CMSG_FIRSTHDR(&message);
    CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(int)));
    memcpy(&descriptor, CMSG_DATA(header), sizeof(int));
    CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    CHECK(fcntl(descriptor, F_GETFD) == (cloexec ? FD_CLOEXEC : 0));
    return descriptor;
}

static int metadata(int descriptor, int baseline, int guest) {
    struct stat actual, expected;
    memset(&actual, 0xa5, sizeof(actual));
    memset(&expected, 0xa5, sizeof(expected));
    CHECK(fstat(descriptor, &actual) == 0 && fstat(baseline, &expected) == 0);
    CHECK(S_ISDIR(actual.st_mode));
    if (guest) CHECK(memcmp(&actual, &expected, sizeof(actual)) == 0);
    struct statx actualx, expectedx;
    memset(&actualx, 0xa5, sizeof(actualx));
    memset(&expectedx, 0xa5, sizeof(expectedx));
    CHECK(statx(descriptor, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &actualx) == 0);
    CHECK(statx(baseline, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &expectedx) == 0);
    if (guest) CHECK(memcmp(&actualx, &expectedx, sizeof(actualx)) == 0);
    struct stat empty;
    memset(&empty, 0xa5, sizeof(empty));
    CHECK(fstatat(descriptor, "", &empty, AT_EMPTY_PATH) == 0);
    if (guest) CHECK(memcmp(&empty, &expected, sizeof(empty)) == 0);
    char path[128], target[1024], wanted[1024];
    CHECK(snprintf(path, sizeof(path), "/proc/self/fd/%d", descriptor) < sizeof(path));
    memset(target, 0xa5, sizeof(target));
    memset(wanted, 0xa5, sizeof(wanted));
    memcpy(wanted, "/proc", 5);
    CHECK(readlink(path, target, sizeof(target)) == 5);
    CHECK(memcmp(target, wanted, sizeof(target)) == 0);
    return 0;
}

static int enumeration(int descriptor, int guest) {
    unsigned char output[16384], before[16384];
    memset(output, 0xa5, sizeof(output));
    memcpy(before, output, sizeof(output));
    long result = syscall(SYS_getdents64, descriptor, output, sizeof(output));
    if (guest) {
        CHECK(result == 0);
        CHECK(memcmp(output, before, sizeof(output)) == 0);
    } else {
        CHECK(result > 0);
    }
    return 0;
}

static int contents(int descriptor, int baseline, int guest) {
    const char *paths[] = {"version", "sys/kernel/osrelease", "self/cmdline"};
    for (unsigned index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        int actual = openat(descriptor, paths[index], O_RDONLY);
        int expected = openat(baseline, paths[index], O_RDONLY);
        CHECK(actual >= 0 && expected >= 0);
        unsigned char actual_bytes[16384], expected_bytes[16384];
        memset(actual_bytes, 0xa5, sizeof(actual_bytes));
        memset(expected_bytes, 0xa5, sizeof(expected_bytes));
        ssize_t actual_size = read(actual, actual_bytes, sizeof(actual_bytes));
        ssize_t expected_size = read(expected, expected_bytes, sizeof(expected_bytes));
        CHECK(actual_size > 0 && actual_size < sizeof(actual_bytes));
        CHECK(actual_size == expected_size && memcmp(actual_bytes, expected_bytes, sizeof(actual_bytes)) == 0);
        CHECK(close(actual) == 0 && close(expected) == 0);
    }
    if (guest) {
        const char *unlisted[] = {"../etc/passwd", "self/environ", "thread-self/environ", "self/task", "self/fd", "1/environ"};
        for (unsigned index = 0; index < sizeof(unlisted) / sizeof(unlisted[0]); ++index) {
            errno = 0;
            CHECK(openat(descriptor, unlisted[index], O_RDONLY) == -1 && errno == ENOENT);
        }
    }
    return 0;
}

struct shared_context { int baseline; int guest; };

static void *shared_worker(void *opaque) {
    struct shared_context *context = opaque;
    if (close(64)) return (void *)(uintptr_t)1;
    int descriptor = open("/proc", O_RDONLY | O_DIRECTORY);
    if (descriptor < 0 || dup2(descriptor, 65) != 65 || close(descriptor)) return (void *)(uintptr_t)2;
    return (void *)(uintptr_t)metadata(65, context->baseline, context->guest);
}

static int filesystem_stats(int descriptor, int guest) {
    char alias[128];
    CHECK(snprintf(alias, sizeof(alias), "/proc/self/fd/%d", descriptor) < sizeof(alias));
    for (int variant = 0; variant < 3; ++variant) {
        unsigned char output[sizeof(struct statfs)], before[sizeof(struct statfs)];
        memset(output, 0xa5, sizeof(output));
        memcpy(before, output, sizeof(output));
        errno = 0;
        int result = variant == 0 ? fstatfs(descriptor, (struct statfs *)output) : statfs(variant == 1 ? alias : "/proc", (struct statfs *)output);
        printf("statfs variant=%d result=%d errno=%d\n", variant, result, errno);
        if (guest) {
            CHECK(result == -1 && errno == EACCES);
            CHECK(memcmp(output, before, sizeof(output)) == 0);
        } else {
            CHECK(result == 0);
        }
    }
    struct statfs ordinary;
    CHECK(statfs(".", &ordinary) == 0);
    int ordinary_fd = open(".", O_RDONLY | O_DIRECTORY);
    CHECK(ordinary_fd >= 0 && fstatfs(ordinary_fd, &ordinary) == 0);
    errno = 0;
    CHECK(syscall(SYS_fstatfs, ordinary_fd, (void *)1) == -1 && errno == EFAULT);
    CHECK(close(ordinary_fd) == 0);
    errno = 0;
    CHECK(syscall(SYS_fstatfs, -1, (void *)1) == -1 && errno == EBADF);
    return 0;
}

int main(int argc, char **argv) {
    CHECK(argc >= 2);
    int guest = strcmp(argv[1], "guest") == 0;
    if (argc == 3) {
        int baseline = open("/proc", O_RDONLY | O_DIRECTORY);
        CHECK(baseline >= 0 && metadata(60, baseline, guest) == 0);
        CHECK(contents(60, baseline, guest) == 0);
        errno = 0;
        CHECK(fcntl(61, F_GETFD) == -1 && errno == EBADF);
        return 0;
    }
    int descriptor = open("/proc", O_RDONLY | O_DIRECTORY);
    CHECK(descriptor >= 0);
    descriptor = transfer(descriptor, 1);
    CHECK(descriptor >= 0 && descriptor != 93);
    descriptor = transfer(descriptor, 0);
    CHECK(descriptor >= 0 && descriptor != 93);
    int baseline = open("/proc", O_RDONLY | O_DIRECTORY);
    CHECK(baseline >= 0);
    if (CASE == 0) CHECK(metadata(descriptor, baseline, guest) == 0);
    if (CASE == 1) CHECK(enumeration(descriptor, guest) == 0);
    if (CASE == 2) CHECK(contents(descriptor, baseline, guest) == 0);
    if (CASE == 3) {
        int copies[3] = {dup(descriptor), fcntl(descriptor, F_DUPFD_CLOEXEC, 20), dup2(descriptor, 24)};
        CHECK(close(descriptor) == 0);
        for (unsigned index = 0; index < 3; ++index) {
            CHECK(copies[index] >= 0 && metadata(copies[index], baseline, guest) == 0);
            CHECK(contents(copies[index], baseline, guest) == 0);
        }
        const char *prefixes[] = {"/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"};
        for (unsigned index = 0; index < 3; ++index) {
            char path[128];
            CHECK(snprintf(path, sizeof(path), "%s%d", prefixes[index], copies[0]) < sizeof(path));
            int reopened = open(path, O_RDONLY | O_DIRECTORY);
            CHECK(reopened >= 0 && metadata(reopened, baseline, guest) == 0);
            CHECK(contents(reopened, baseline, guest) == 0);
            CHECK(close(reopened) == 0);
        }
        char numeric_path[128];
        CHECK(snprintf(numeric_path, sizeof(numeric_path), "/proc/%d/fd/%d", getpid(), copies[0]) < sizeof(numeric_path));
        int numeric = open(numeric_path, O_RDONLY | O_DIRECTORY);
        CHECK(numeric >= 0 && metadata(numeric, baseline, guest) == 0);
        CHECK(contents(numeric, baseline, guest) == 0 && close(numeric) == 0);
        int ordinary = open("/", O_RDONLY | O_DIRECTORY);
        CHECK(ordinary >= 0 && dup2(ordinary, copies[0]) == copies[0]);
        char path[128], target[1024];
        CHECK(snprintf(path, sizeof(path), "/proc/self/fd/%d", copies[0]) < sizeof(path));
        CHECK(readlink(path, target, sizeof(target)) == 1 && target[0] == '/');
    }
    if (CASE == 4) {
        CHECK(dup2(descriptor, 60) == 60 && dup3(descriptor, 61, O_CLOEXEC) == 61);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            execl(argv[0], argv[0], argv[1], "after-exec", (char *)0);
            _exit(94);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(metadata(descriptor, baseline, guest) == 0);
    }
    if (CASE == 5) CHECK(filesystem_stats(descriptor, guest) == 0);
    if (CASE == 6) {
        char before[4096], after[4096];
        CHECK(getcwd(before, sizeof(before)) != NULL);
        int saved = open(".", O_RDONLY | O_DIRECTORY);
        CHECK(saved >= 0);
        errno = 0;
        int result = fchdir(descriptor);
        printf("fchdir result=%d errno=%d\n", result, errno);
        if (guest) {
            CHECK(result == -1 && errno == EACCES);
            CHECK(getcwd(after, sizeof(after)) && strcmp(before, after) == 0);
        } else {
            CHECK(result == 0 && getcwd(after, sizeof(after)) && strcmp(after, "/proc") == 0);
        }
        CHECK(fchdir(saved) == 0);
        CHECK(getcwd(after, sizeof(after)) && strcmp(before, after) == 0);
        int path_fd = open(".", O_PATH | O_DIRECTORY);
        CHECK(path_fd >= 0);
        errno = 0;
        result = fchdir(path_fd);
        printf("O_PATH fchdir result=%d errno=%d\n", result, errno);
        if (guest) CHECK(result == -1 && errno == EBADF);
        else CHECK(result == 0);
        CHECK(close(path_fd) == 0 && close(saved) == 0);
    }
    if (CASE == 7) {
        CHECK(dup2(descriptor, 64) == 64);
        struct shared_context context = {.baseline = baseline, .guest = guest};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, shared_worker, &context) == 0);
        void *result;
        CHECK(pthread_join(thread, &result) == 0 && result == NULL);
        errno = 0;
        CHECK(fcntl(64, F_GETFD) == -1 && errno == EBADF);
        CHECK(metadata(65, baseline, guest) == 0 && contents(65, baseline, guest) == 0);
    }
    return 0;
}
"#;
const LOAD_ADDRESS: u64 = 0x20_0000;
const CODE_OFFSET: usize = 0x1000;
const POST_EXEC_RANDOM: [u8; 16] = *b"kvm-post-exec-ok";
static POST_EXEC_FAILURE_EXITED: AtomicBool = AtomicBool::new(false);
const SIGNAL_EXIT_CHILD_TID: u64 = 0x0800_3000;
const SIGNAL_EXIT_AFTER_CALLBACK: i32 = 0x5a5a_5a5a;
static SIGNAL_EXIT_OBSERVED_TID: AtomicU64 = AtomicU64::new(u64::MAX);
static SIGNAL_EXIT_MEMORY: Mutex<Option<reverie_kvm::GuestMemory>> = Mutex::new(None);
static POST_EXEC_UNMASK_CALLBACKS: AtomicU64 = AtomicU64::new(0);
static POST_EXEC_ENTRY_WRITES: AtomicU64 = AtomicU64::new(0);

fn proc_root_path_case(case: usize) {
    assert!(kvm_available("proc_root_path_case"));
    let directory = TestDirectory::new();
    let program = format!("#define CASE {case}\n{}", PROC_ROOT_PATH_PROGRAM);
    let executable = compile_c_program(&directory.0, "proc-root-path", &program);
    let native = std::process::Command::new(&executable)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    println!(
        "native case={case}: {:?} {}",
        native.status.code(),
        String::from_utf8_lossy(&native.stdout)
    );
    assert_eq!(
        native.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(native.stderr.is_empty());
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap()],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    println!(
        "guest case={case}: {code} {}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(code, 0);
}

#[test]
fn proc_root_local_trailing_positive() {
    proc_root_path_case(0);
}
#[test]
fn proc_root_received_trailing_no_creation() {
    proc_root_path_case(1);
}
#[test]
fn proc_root_received_plain_no_creation() {
    proc_root_path_case(2);
}
#[test]
fn proc_root_direct_trailing_no_creation() {
    proc_root_path_case(3);
}
#[test]
fn proc_root_real_root_trailing_positive() {
    proc_root_path_case(4);
}
#[test]
fn proc_root_direct_parent_exit_positive() {
    proc_root_path_case(5);
}

const PROC_ROOT_PATH_PROGRAM: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char cwd[4096], relative[8192], target[8192];
    if (!getcwd(cwd, sizeof(cwd)) || cwd[0] != '/' || strlen(cwd) < 20) return 80;
    if (snprintf(target, sizeof(target), "%s/private-created", cwd) >= sizeof(target)) return 81;
    struct stat initial;
    errno = 0;
    if (lstat(target, &initial) == 0 || errno != ENOENT) return 82;
    int descriptor = open(CASE == 0 ? cwd : (CASE == 4 ? "/" : "/proc"), O_RDONLY | O_DIRECTORY);
    if (descriptor < 0) return 83;
    if (CASE == 1 || CASE == 2) {
        int sockets[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)) return 84;
        char payload = 'x';
        char control[CMSG_SPACE(sizeof(int))] = {0};
        struct iovec vector = {.iov_base = &payload, .iov_len = 1};
        struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &descriptor, sizeof(int));
        if (sendmsg(sockets[0], &message, 0) != 1 || close(descriptor)) return 85;
        memset(control, 0, sizeof(control));
        message.msg_controllen = sizeof(control);
        payload = 0;
        if (recvmsg(sockets[1], &message, 0) != 1 || payload != 'x' || (message.msg_flags & MSG_CTRUNC)) return 86;
        header = CMSG_FIRSTHDR(&message);
        if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || header->cmsg_len != CMSG_LEN(sizeof(int))) return 87;
        memcpy(&descriptor, CMSG_DATA(header), sizeof(int));
        close(sockets[0]);
        close(sockets[1]);
    }
    if (CASE == 0) {
        if (snprintf(relative, sizeof(relative), "private-created///") >= sizeof(relative)) return 88;
    } else {
        if (snprintf(relative, sizeof(relative), "%s%s/private-created%s", CASE == 5 ? "../" : "", cwd + 1, (CASE == 2 || CASE == 5) ? "" : "///") >= sizeof(relative)) return 89;
    }
    errno = 0;
    int result = mkdirat(descriptor, relative, 0700);
    int saved_errno = errno;
    struct stat after;
    errno = 0;
    int exists = lstat(target, &after) == 0;
    int lookup_errno = errno;
    if (!exists && lookup_errno != ENOENT) return 90;
    printf("case=%d result=%d errno=%d exists=%d directory=%d\n", CASE, result, saved_errno, exists, exists && S_ISDIR(after.st_mode));
    close(descriptor);
    int expected_creation = CASE == 0 || CASE == 4 || CASE == 5;
    int correct = expected_creation ? (result == 0 && exists && S_ISDIR(after.st_mode)) : (result == -1 && !exists);
    if (exists && rmdir(target)) return 91;
    return correct ? 0 : 94;
}
"#;

static NEXT_TEST_EXECUTABLE: AtomicU64 = AtomicU64::new(0);

struct TestExecutable(PathBuf);

struct NativeTestExecutable(std::fs::File);

impl NativeTestExecutable {
    fn writer() -> std::fs::File {
        use std::os::fd::FromRawFd;
        let descriptor = unsafe {
            libc::memfd_create(
                c"native-executable".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(descriptor >= 0, "{}", std::io::Error::last_os_error());
        unsafe { std::fs::File::from_raw_fd(descriptor) }
    }

    fn publish(mut writer: std::fs::File, image: &[u8], mode: u32) -> Self {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        writer.write_all(image).unwrap();
        writer
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .unwrap();
        assert_eq!(
            unsafe {
                libc::fcntl(
                    writer.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        Self(std::fs::File::open(format!("/proc/self/fd/{}", writer.as_raw_fd())).unwrap())
    }

    fn new(image: &[u8], mode: u32) -> Self {
        Self::publish(Self::writer(), image, mode)
    }

    fn path(&self) -> PathBuf {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", self.0.as_raw_fd()))
    }
}

#[test]
fn native_executable_publication_survives_inherited_writer() {
    use std::os::fd::AsRawFd;
    let test = "native_executable_publication_survives_inherited_writer";
    if std::env::var("REVERIE_NATIVE_PUBLICATION_CHILD").as_deref() != Ok(test) {
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "30s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("REVERIE_NATIVE_PUBLICATION_CHILD", test)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let image = static_elf(&[0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
    let writer = NativeTestExecutable::writer();
    let writer_fd = writer.as_raw_fd();
    assert_eq!(
        unsafe { libc::fcntl(writer_fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        libc::FD_CLOEXEC
    );
    let mut release = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(release.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let holder = unsafe { libc::fork() };
    assert!(holder >= 0);
    if holder == 0 {
        unsafe {
            libc::close(release[1]);
            let mut byte = 0_u8;
            let count = libc::read(release[0], (&raw mut byte).cast(), 1);
            let closed = libc::close(writer_fd);
            libc::_exit(if count == 1 && byte == 1 && closed == 0 {
                0
            } else {
                91
            });
        }
    }
    unsafe {
        libc::close(release[0]);
    }
    let executable = NativeTestExecutable::publish(writer, &image, 0o700);
    let held = std::process::Command::new(executable.path()).output();
    assert_eq!(
        unsafe { libc::write(release[1], [1_u8].as_ptr().cast(), 1) },
        1
    );
    unsafe {
        libc::close(release[1]);
    }
    let mut status = -1;
    assert_eq!(unsafe { libc::waitpid(holder, &raw mut status, 0) }, holder);
    assert_eq!(status, 0);
    let released = std::process::Command::new(executable.path())
        .output()
        .unwrap();
    assert_eq!(released.status.code(), Some(0));
    assert!(released.stdout.is_empty());
    assert!(released.stderr.is_empty());
    assert_eq!(std::fs::read(executable.path()).unwrap(), image);
    assert_eq!(
        executable.0.metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );
    let positive = NativeTestExecutable::new(&image, 0o755);
    assert_eq!(
        positive.0.metadata().unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        std::process::Command::new(positive.path())
            .status()
            .unwrap()
            .code(),
        Some(0)
    );
    positive
        .0
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    assert_eq!(
        std::process::Command::new(positive.path())
            .output()
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EACCES)
    );
    assert_eq!(
        unsafe { libc::fcntl(executable.0.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
        libc::O_RDONLY
    );
    assert_eq!(
        unsafe { libc::fcntl(executable.0.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        libc::FD_CLOEXEC
    );
    eprintln!("post-release positive passed; inherited-writer execution: {held:?}");
    let held = held.expect("execution must succeed while inherited CLOEXEC writer remains open");
    assert_eq!(held.status.code(), Some(0));
    assert!(held.stdout.is_empty());
    assert!(held.stderr.is_empty());
    assert_eq!(
        unsafe { libc::fcntl(executable.0.as_raw_fd(), libc::F_GET_SEALS) },
        libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL
    );
    let reopened_writer = std::fs::OpenOptions::new()
        .write(true)
        .open(executable.path())
        .unwrap();
    assert_eq!(
        unsafe { libc::pwrite(reopened_writer.as_raw_fd(), [0_u8].as_ptr().cast(), 1, 0) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(std::fs::read(executable.path()).unwrap(), image);
}

impl TestExecutable {
    fn new(image: &[u8]) -> Self {
        let id = NEXT_TEST_EXECUTABLE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("reverie-kvm-exec-{}-{id}", std::process::id()));
        std::fs::write(&path, image).unwrap();
        Self(path)
    }
}

impl Drop for TestExecutable {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_TEST_EXECUTABLE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("reverie-kvm-coreutils-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run_host_program_captured(
    program: &str,
    argv: &[&str],
    cwd: &std::path::Path,
) -> (Vec<u8>, Vec<u8>) {
    const REAL_PROGRAM_MEMORY_SIZE: usize = 256 * 1024 * 1024;

    let image = std::fs::read(program).unwrap();
    let mut backend = KvmBackend::new(REAL_PROGRAM_MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_context(&image, argv, &["PATH=/usr/bin:/bin"], cwd)
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "{program} {argv:?} exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    (stdout, stderr)
}

fn run_host_program_with_tool_captured(
    program: &str,
    argv: &[&str],
    cwd: &std::path::Path,
) -> (Vec<u8>, Vec<u8>) {
    const REAL_PROGRAM_MEMORY_SIZE: usize = 256 * 1024 * 1024;

    let image = std::fs::read(program).unwrap();
    let mut backend = KvmBackend::new(REAL_PROGRAM_MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_context(&image, argv, &["PATH=/usr/bin:/bin"], cwd)
        .unwrap();
    let (_, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();
    assert_eq!(
        code,
        0,
        "{program} {argv:?} exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    (stdout, stderr)
}

fn run_host_program(program: &str, argv: &[&str], cwd: &std::path::Path) {
    let _ = run_host_program_captured(program, argv, cwd);
}

fn compile_c_program(directory: &std::path::Path, name: &str, source: &str) -> PathBuf {
    compile_c_program_with_args(directory, name, source, &[])
}

fn compile_c_program_with_args(
    directory: &std::path::Path,
    name: &str,
    source: &str,
    extra_args: &[&str],
) -> PathBuf {
    let source_path = directory.join(format!("{name}.c"));
    let executable_path = directory.join(name);
    std::fs::write(&source_path, source).unwrap();
    let output = std::process::Command::new("/usr/bin/gcc")
        .args(["-O2", "-pthread"])
        .args(extra_args)
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gcc failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    executable_path
}

fn set_interrupt_signal_blocked(blocked: bool) -> bool {
    // SAFETY: set and previous are initialized before libc reads or writes them.
    unsafe {
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        let mut previous = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGURG);
        let how = if blocked {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        };
        assert_eq!(libc::pthread_sigmask(how, &set, &mut previous), 0);
        libc::sigismember(&previous, libc::SIGURG) == 1
    }
}

#[derive(Default)]
struct PostExecLog {
    at_random: Mutex<Option<usize>>,
    calls: AtomicU64,
}

impl PostExecLog {
    fn at_random(&self) -> Option<usize> {
        *self.at_random.lock().expect("post-exec log lock poisoned")
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for PostExecLog {
    type Request = usize;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, at_random: usize) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.at_random.lock().expect("post-exec log lock poisoned") = Some(at_random);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PostExecTool;

#[reverie::tool]
impl Tool for PostExecTool {
    type GlobalState = PostExecLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::execve]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        guest.tail_inject(syscall).await
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let auxv = guest.auxv();
        let address = auxv.at_random().ok_or(Errno::EINVAL)?;
        guest.send_rpc(address.as_raw()).await;
        // This lifecycle hook runs before the ELF entry point, matching execve.
        let address = unsafe { address.into_mut() };
        guest.memory().write_value(address, &POST_EXEC_RANDOM)
    }
}

#[derive(Default)]
struct LifecycleSignalLog {
    callbacks: Mutex<Vec<u8>>,
}

#[reverie::global_tool]
impl GlobalTool for LifecycleSignalLog {
    type Request = u8;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, callback: u8) {
        self.callbacks
            .lock()
            .expect("lifecycle signal log lock poisoned")
            .push(callback);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct LifecycleSignalTool;

fn lifecycle_signal(pid: Pid, tid: Pid) -> SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
    SignalEvent::new(libc::SIGUSR1, info, SignalTarget::Thread { pid, tid }).unwrap()
}

#[reverie::tool]
impl Tool for LifecycleSignalTool {
    type GlobalState = LifecycleSignalLog;
    type ThreadState = ();

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let error = guest
            .defer_signal_delivery(lifecycle_signal(guest.pid(), guest.tid()))
            .await
            .expect_err("thread-start delivery without a syscall frame must fail");
        let errno = error.into_errno()?;
        if errno != Errno::ENOSYS {
            return Err(errno.into());
        }
        let error = guest
            .inject(
                Kill::new()
                    .with_pid(guest.pid().as_raw())
                    .with_sig(libc::SIGUSR1),
            )
            .await
            .expect_err("thread-start self-signal without a syscall frame must fail");
        if error != Errno::ENOSYS {
            return Err(error.into());
        }
        guest.send_rpc(1).await;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let error = guest
            .defer_signal_delivery(lifecycle_signal(guest.pid(), guest.tid()))
            .await
            .expect_err("post-exec delivery without a syscall frame must fail");
        let errno = error.into_errno().map_err(|_| Errno::EIO)?;
        if errno != Errno::ENOSYS {
            return Err(errno);
        }
        let error = guest
            .inject(
                Kill::new()
                    .with_pid(guest.pid().as_raw())
                    .with_sig(libc::SIGUSR1),
            )
            .await
            .expect_err("post-exec self-signal without a syscall frame must fail");
        if error != Errno::ENOSYS {
            return Err(error);
        }
        guest.send_rpc(2).await;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PostExecPendingLog;

#[reverie::global_tool]
impl GlobalTool for PostExecPendingLog {
    type Request = u8;
    type Response = ();
    type Config = (bool, String);

    async fn receive_rpc(&self, _from: Pid, event: u8) {
        match event {
            1 => {
                POST_EXEC_UNMASK_CALLBACKS.fetch_add(1, Ordering::SeqCst);
            }
            2 => {
                POST_EXEC_ENTRY_WRITES.fetch_add(1, Ordering::SeqCst);
            }
            _ => panic!("unknown post-exec test event {event}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PostExecPendingTool;

#[reverie::tool]
impl Tool for PostExecPendingTool {
    type GlobalState = PostExecPendingLog;
    type ThreadState = u8;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if matches!(syscall, Syscall::Write(_)) {
            guest.send_rpc(2).await;
        }
        if matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) {
            guest.tail_inject(syscall).await
        }
        Ok(guest.inject(syscall).await?)
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let ordinal = {
            let ordinal = guest.thread_state_mut();
            *ordinal += 1;
            *ordinal
        };
        guest.send_rpc(1).await;
        let (recursive, recursive_path) = guest.config().clone();
        if recursive && ordinal == 2 {
            let path = recursive_path.as_bytes();
            assert!(path.len() < 512);
            let mut path_bytes = [0_u8; 512];
            path_bytes[..path.len()].copy_from_slice(path);
            let mut stack = guest.stack().await;
            let path = stack.push(path_bytes).as_raw();
            let argv = stack.push([path, 0]).as_raw();
            let envp = stack.push([0_usize]).as_raw();
            let _guard = stack.commit()?;
            let exec = Execve::new()
                .with_path(PathPtr::from_ptr(path as *const libc::c_char))
                .with_argv(Option::<CArrayPtr<CStrPtr>>::from_raw(argv))
                .with_envp(Option::<CArrayPtr<CStrPtr>>::from_raw(envp));
            guest.tail_inject(exec).await
        }

        let expected = if recursive { 3 } else { 2 };
        if ordinal != expected {
            return Ok(());
        }
        let mut stack = guest.stack().await;
        let empty_mask = stack.push(0_u64).as_raw() as u64;
        let _guard = stack.commit()?;
        let unmask = reverie_kvm::SyscallRequest::new(
            libc::SYS_rt_sigprocmask as u64,
            [
                libc::SIG_SETMASK as u64,
                empty_mask,
                0,
                std::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
        .into_syscall()
        .expect("rt_sigprocmask is a known syscall");
        let error = guest
            .inject(unmask)
            .await
            .expect_err("post-exec unmask of preserved pending signal must fail");
        Err(error)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CanonicalInitialExecTool;

#[reverie::tool]
impl Tool for CanonicalInitialExecTool {
    type GlobalState = PostExecLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::execve]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let Syscall::Execve(execve) = syscall else {
            unreachable!("tool only subscribes to execve")
        };
        guest
            .tail_inject(reverie::syscalls::Execveat::from(execve))
            .await
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        guest.send_rpc(0).await;
        Ok(())
    }
}

#[derive(Default)]
struct StartExecLog {
    post_exec_calls: AtomicU64,
}

impl StartExecLog {
    fn post_exec_calls(&self) -> u64 {
        self.post_exec_calls.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for StartExecLog {
    type Request = ();
    type Response = ();
    type Config = (usize, usize, usize);

    async fn receive_rpc(&self, _from: Pid, (): ()) {
        self.post_exec_calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct StartExecTool;

#[reverie::tool]
impl Tool for StartExecTool {
    type GlobalState = StartExecLog;
    type ThreadState = ();

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let (path, argv, envp) = *guest.config();
        let execve = Execve::new()
            .with_path(PathPtr::from_ptr(path as *const libc::c_char))
            .with_argv(Option::<CArrayPtr<CStrPtr>>::from_raw(argv))
            .with_envp(Option::<CArrayPtr<CStrPtr>>::from_raw(envp));
        guest.inject(execve).await?;
        Err(Errno::EINVAL.into())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        guest.send_rpc(()).await;
        Ok(())
    }
}

#[derive(Default)]
struct RpcRoundTripLog {
    response_base: u64,
    requests: Mutex<Vec<(Pid, u64)>>,
}

impl RpcRoundTripLog {
    fn requests(&self) -> Vec<(Pid, u64)> {
        self.requests
            .lock()
            .expect("RPC round-trip log lock poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for RpcRoundTripLog {
    type Request = u64;
    type Response = u64;
    type Config = u64;

    async fn init_global_state(response_base: &u64) -> Self {
        Self {
            response_base: *response_base,
            requests: Mutex::default(),
        }
    }

    async fn receive_rpc(&self, from: Pid, ordinal: u64) -> u64 {
        self.requests
            .lock()
            .expect("RPC round-trip log lock poisoned")
            .push((from, ordinal));
        self.response_base + ordinal
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RpcRoundTripTool;

#[reverie::tool]
impl Tool for RpcRoundTripTool {
    type GlobalState = RpcRoundTripLog;
    type ThreadState = u64;

    fn subscriptions(_config: &u64) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscall(Sysno::getpid);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert!(matches!(syscall, Syscall::Getpid(_)));
        let ordinal = {
            let ordinal = guest.thread_state_mut();
            *ordinal += 1;
            *ordinal
        };
        Ok(guest.send_rpc(ordinal).await as i64)
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        global: &G,
        thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        let ordinal = thread_state + 1;
        assert_eq!(global.send_rpc(ordinal).await, *global.config() + ordinal);
        Ok(())
    }
}

struct ConcurrentToolStackLog {
    rendezvous: Barrier,
    tids: Mutex<Vec<Pid>>,
}

impl Default for ConcurrentToolStackLog {
    fn default() -> Self {
        Self {
            rendezvous: Barrier::new(2),
            tids: Mutex::new(Vec::new()),
        }
    }
}

impl ConcurrentToolStackLog {
    fn tids(&self) -> Vec<Pid> {
        self.tids
            .lock()
            .expect("concurrent Tool stack log poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for ConcurrentToolStackLog {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, from: Pid, (): ()) {
        self.tids
            .lock()
            .expect("concurrent Tool stack log poisoned")
            .push(from);
        self.rendezvous.wait();
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ConcurrentToolStackTool;

#[reverie::tool]
impl Tool for ConcurrentToolStackTool {
    type GlobalState = ConcurrentToolStackLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscall(Sysno::getppid);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert!(matches!(syscall, Syscall::Getppid(_)));
        let expected = u64::try_from(guest.tid().as_raw()).unwrap();
        let mut stack = guest.stack().await;
        let address = stack.push(expected);
        let guard = stack.commit()?;
        guest.send_rpc(()).await;
        let observed = guest.memory().read_value(address)?;
        if observed != expected {
            guest.tail_inject(ExitGroup::new().with_status(91)).await
        }
        drop(guard);
        Ok(guest.inject(syscall).await?)
    }
}

struct WorkerExecOverlapLog {
    rendezvous: Barrier,
    worker_errno: Mutex<Option<i32>>,
    worker_ready: Condvar,
    root_value_preserved: AtomicBool,
}

impl Default for WorkerExecOverlapLog {
    fn default() -> Self {
        Self {
            rendezvous: Barrier::new(2),
            worker_errno: Mutex::new(None),
            worker_ready: Condvar::new(),
            root_value_preserved: AtomicBool::new(false),
        }
    }
}

impl WorkerExecOverlapLog {
    fn worker_errno(&self) -> Option<i32> {
        *self
            .worker_errno
            .lock()
            .expect("worker exec result lock poisoned")
    }

    fn root_value_preserved(&self) -> bool {
        self.root_value_preserved.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for WorkerExecOverlapLog {
    type Request = (u8, i64);
    type Response = i64;
    type Config = (usize, usize, usize, bool, i32);

    async fn receive_rpc(&self, _from: Pid, (operation, value): (u8, i64)) -> i64 {
        match operation {
            // Both callbacks hold committed stack guards before either
            // proceeds to the image-replacement attempt.
            0 => {
                self.rendezvous.wait();
                0
            }
            // Publish the worker's observed errno and wake the root callback.
            1 => {
                *self
                    .worker_errno
                    .lock()
                    .expect("worker exec result lock poisoned") =
                    Some(i32::try_from(value).expect("errno must fit i32"));
                self.worker_ready.notify_all();
                0
            }
            // Wait with a bound so the pre-fix successful replacement cannot
            // leave the test blocked indefinitely.
            2 => {
                let result = self
                    .worker_errno
                    .lock()
                    .expect("worker exec result lock poisoned");
                let (result, _) = self
                    .worker_ready
                    .wait_timeout_while(result, std::time::Duration::from_secs(5), |result| {
                        result.is_none()
                    })
                    .expect("worker exec result wait poisoned");
                result.map(i64::from).unwrap_or(-1)
            }
            // Record that the root callback could still read its committed
            // value after the worker's refused image replacement.
            3 => {
                self.root_value_preserved
                    .store(value != 0, Ordering::SeqCst);
                0
            }
            _ => panic!("unexpected worker exec test operation {operation}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct WorkerExecOverlapTool;

#[reverie::tool]
impl Tool for WorkerExecOverlapTool {
    type GlobalState = WorkerExecOverlapLog;
    type ThreadState = ();

    fn subscriptions(_config: &(usize, usize, usize, bool, i32)) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscall(Sysno::getppid);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert!(matches!(syscall, Syscall::Getppid(_)));
        let expected = u64::try_from(guest.tid().as_raw()).unwrap();
        let mut stack = guest.stack().await;
        let address = stack.push(expected);
        let guard = stack.commit()?;
        guest.send_rpc((0, 0)).await;

        if guest.is_main_thread() {
            let worker_errno = guest.send_rpc((2, 0)).await;
            let observed = guest.memory().read_value(address)?;
            let preserved = worker_errno == i64::from(guest.config().4) && observed == expected;
            guest.send_rpc((3, i64::from(preserved))).await;
            if !preserved {
                guest.tail_inject(ExitGroup::new().with_status(92)).await
            }
        } else {
            assert_ne!(guest.tid(), guest.pid());
            let (path, argv, envp, execveat, _) = *guest.config();
            let request = Execve::new()
                .with_path(PathPtr::from_ptr(path as *const libc::c_char))
                .with_argv(Option::<CArrayPtr<CStrPtr>>::from_raw(argv))
                .with_envp(Option::<CArrayPtr<CStrPtr>>::from_raw(envp));
            let result = if execveat {
                guest
                    .inject(reverie::syscalls::Execveat::from(request))
                    .await
            } else {
                guest.inject(request).await
            };
            let error = result.expect_err("worker image replacement unexpectedly succeeded");
            guest.send_rpc((1, i64::from(error.into_raw()))).await;
        }

        drop(guard);
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DoubleForkTool;

#[reverie::tool]
impl Tool for DoubleForkTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::fork]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let Syscall::Fork(fork) = syscall else {
            panic!("expected fork, got {syscall:?}");
        };
        let first = guest.inject(fork).await?;
        let second = guest.inject(Fork::new()).await?;
        assert!(first > 0);
        assert!(second > first);
        Ok(first)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FailingPostExecTool;

#[reverie::tool]
impl Tool for FailingPostExecTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_post_exec<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        _global: &G,
        _thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        POST_EXEC_FAILURE_EXITED.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn kvm_is_unavailable(error: &kvm_ioctls::Error) -> bool {
    matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM)
}

fn kvm_available(test: &str) -> bool {
    match Kvm::new() {
        Ok(_) => true,
        Err(error) if kvm_is_unavailable(&error) => {
            if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                panic!("{test} requires usable /dev/kvm: {error}");
            }
            eprintln!("skipping {test}: cannot open /dev/kvm: {error}");
            false
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
}

// The Tool completion API retains a lone fault in one shared ownership envelope.
// Unwrap only that exact shape: cleanup, worker and signal-effect context must
// still fail these fault-only assertions instead of being hidden by primary().
fn unwrap_shared_guest_exception(error: Error) -> Error {
    match error {
        Error::SharedFailure(cause) => match cause.as_ref() {
            Error::GuestException {
                vector,
                instruction_pointer,
                fault_address,
            } => Error::GuestException {
                vector: *vector,
                instruction_pointer: *instruction_pointer,
                fault_address: *fault_address,
            },
            _ => Error::SharedFailure(cause),
        },
        error => error,
    }
}

fn assert_invalid_opcode(error: Error) {
    match unwrap_shared_guest_exception(error) {
        Error::GuestException {
            vector,
            instruction_pointer,
            ..
        } => {
            assert_eq!(vector, 6);
            assert_eq!(instruction_pointer, LOAD_ADDRESS);
        }
        error => panic!("expected invalid-opcode exception, got {error}"),
    }
}

fn assert_page_fault(error: Error) {
    match unwrap_shared_guest_exception(error) {
        Error::GuestException {
            vector,
            instruction_pointer,
            fault_address,
        } => {
            assert_eq!(vector, 14);
            assert_eq!(instruction_pointer, LOAD_ADDRESS);
            assert_eq!(fault_address, 0x4000_0000);
        }
        error => panic!("expected page-fault exception, got {error}"),
    }
}

fn assert_general_protection(error: Error) {
    match unwrap_shared_guest_exception(error) {
        Error::GuestException {
            vector,
            instruction_pointer,
            ..
        } => {
            assert_eq!(vector, 13);
            assert_eq!(instruction_pointer, LOAD_ADDRESS);
        }
        error => panic!("expected general-protection exception, got {error}"),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FailingFaultExitTool;

#[reverie::tool]
impl Tool for FailingFaultExitTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        _global: &G,
        _thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        Err(Errno::EIO.into())
    }
}

#[test]
fn fault_only_assertion_rejects_actual_tool_exit_cleanup_failure() {
    if !kvm_available("fault_only_assertion_rejects_actual_tool_exit_cleanup_failure") {
        return;
    }
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&[0x0f, 0x0b]), "/bin/fault-with-cleanup")
        .unwrap();
    let error = match futures::executor::block_on(
        backend.run_static_elf_with_tool::<FailingFaultExitTool>((), true),
    ) {
        Ok(_) => panic!("faulting guest and failing exit hook unexpectedly succeeded"),
        Err(error) => error,
    };
    eprintln!("actual fault and exit-hook failure: {error:?}");
    let Error::WithCleanup { primary, cleanup } = &error else {
        panic!("expected execution fault with retained cleanup failure, got {error:?}");
    };
    let Error::SharedFailure(fault) = primary.as_ref() else {
        panic!("expected the shared original execution fault, got {primary:?}");
    };
    assert!(matches!(
        fault.as_ref(),
        Error::GuestException {
            vector: 6,
            instruction_pointer: LOAD_ADDRESS,
            ..
        }
    ));
    assert_eq!(cleanup.len(), 1, "unexpected cleanup causes: {cleanup:?}");
    let Error::SharedFailure(hook) = cleanup[0].as_ref() else {
        panic!("expected the shared exit-hook failure, got {cleanup:?}");
    };
    assert!(matches!(
        hook.as_ref(),
        Error::Reverie(reverie::Error::Errno(errno)) if *errno == Errno::EIO
    ));
    // Only the assertion is caught. The actual run above must retain both
    // failures, and the unchanged vector/RIP oracle is satisfied by its primary.
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_invalid_opcode(error);
    }));
    assert!(
        rejected.is_err(),
        "fault-only helper discarded cleanup failure"
    );
}

#[test]
fn static_elf_faults_are_reported_by_direct_and_tool_runtimes() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM exception test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let image = static_elf(&[0x0f, 0x0b]);

    let mut direct_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    direct_backend
        .install_static_elf(&image, "/bin/fault")
        .unwrap();
    assert_invalid_opcode(direct_backend.run_static_elf().unwrap_err());

    let mut tool_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    tool_backend
        .install_static_elf(&image, "/bin/fault")
        .unwrap();
    let error = match futures::executor::block_on(
        tool_backend.run_static_elf_with_tool::<StraceTool>((), true),
    ) {
        Ok(_) => panic!("tool runtime reported a guest exception as success"),
        Err(error) => error,
    };
    assert_invalid_opcode(error);

    // movabs rax, qword ptr [0x40000000], an address outside the page tables.
    let page_fault_image =
        static_elf(&[0x48, 0xa1, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]);
    let mut page_fault_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    page_fault_backend
        .install_static_elf(&page_fault_image, "/bin/fault")
        .unwrap();
    assert_page_fault(page_fault_backend.run_static_elf().unwrap_err());

    let mut io_fault_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    io_fault_backend
        .install_static_elf(&static_elf(&[0xed]), "/bin/fault")
        .unwrap();
    assert_general_protection(io_fault_backend.run_static_elf().unwrap_err());
}

#[test]
fn static_elf_vmware_probe_reports_non_vmware_in_direct_and_tool_runtimes() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM VMware probe test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xbb, 0x68, 0x58, 0x4d, 0x56, // mov ebx, 0x564d5868
        0xb9, 0x58, 0x56, 0x00, 0x00, // mov ecx, 0x5658
        0x31, 0xd2, // xor edx, edx
        0xed, // in eax, dx
        0x85, 0xdb, // test ebx, ebx
        0x75, 0x09, // jne failure
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, // failure: mov eax, SYS_exit
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x0f, 0x05, // syscall
    ];
    let image = static_elf(&code);

    let mut direct_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    direct_backend
        .install_static_elf(&image, "/bin/vmware-probe")
        .unwrap();
    assert_eq!(direct_backend.run_static_elf().unwrap(), 0);

    let mut tool_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    tool_backend
        .install_static_elf(&image, "/bin/vmware-probe")
        .unwrap();
    let (_, code, stdout, stderr) =
        futures::executor::block_on(tool_backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();
    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn static_elf_cannot_copy_supervisor_bootstrap_memory() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM bootstrap access test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
        0xba, 0x10, 0x00, 0x00, 0x00, // mov edx, 16
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, SYS_write
        0x0f, 0x05, // syscall
        0x48, 0x83, 0xf8, 0xf2, // cmp rax, -EFAULT
        0x74, 0x0e, // je success
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ];

    for with_tool in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/bootstrap-access-test")
            .unwrap();
        let (exit_code, stdout, stderr) = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (exit_code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(exit_code, 0, "with_tool={with_tool}");
        assert!(stdout.is_empty(), "with_tool={with_tool}");
        assert!(stderr.is_empty(), "with_tool={with_tool}");
    }
}

#[test]
fn static_elf_ready_synchronous_runs_preserve_outer_executor_compatibility() {
    if !kvm_available("synchronous runner inside an outer executor") {
        return;
    }
    let image = static_elf(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ]);
    for capture in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend.install_static_elf(&image, "exit-42").unwrap();
        futures::executor::block_on(async {
            if capture {
                let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
                assert_eq!(code, 42);
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());
            } else {
                assert_eq!(backend.run_static_elf().unwrap(), 42);
            }
        });
    }
}

#[test]
fn static_elf_forks_execs_and_waits_for_child() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM multiprocess test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let message = b"hello from fork exec\n";
    let mut target = vec![0xbf, 0x01, 0x00, 0x00, 0x00]; // mov edi, 1
    let message_operand = target.len() + 2;
    target.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, message
    target.push(0xba);
    target.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    target.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // write
    target.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ]); // exit_group(0); ud2
    let message_address = LOAD_ADDRESS + target.len() as u64;
    target[message_operand..message_operand + 8].copy_from_slice(&message_address.to_le_bytes());
    target.extend_from_slice(message);
    let executable = TestExecutable::new(&static_elf(&target));
    let path = executable.0.to_str().unwrap().as_bytes();

    let mut root = vec![
        0x49, 0xc7, 0xc4, 0x78, 0x56, 0x34, 0x12, // mov r12, 0x12345678
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0x66, 0x0f, 0x6e, 0xc0, // movd xmm0, eax
        0xb8, 0x39, 0x00, 0x00, 0x00, // mov eax, SYS_fork
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x74, 0x00, // jz child
    ];
    let child_jump = root.len() - 1;
    root.extend_from_slice(&[
        0x89, 0xc7, // mov edi, eax
        0x48, 0x83, 0xec, 0x10, // sub rsp, 16
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x31, 0xd2, // xor edx, edx
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0x3d, 0x00, 0x00, 0x00, // mov eax, SYS_wait4
        0x0f, 0x05, // syscall
        0x8b, 0x3c, 0x24, // mov edi, dword ptr [rsp]
        0xc1, 0xef, 0x08, // shr edi, 8
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);
    let child_offset = root.len();
    let displacement = child_offset as isize - (child_jump + 1) as isize;
    root[child_jump] = i8::try_from(displacement).unwrap() as u8;

    root.extend_from_slice(&[
        0x49, 0x81, 0xfc, 0x78, 0x56, 0x34, 0x12, // cmp r12, 0x12345678
        0x74, 0x0e, // je callee_saved_ok
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
        0x66, 0x0f, 0x7e, 0xc0, // movd eax, xmm0
        0x3d, 0x78, 0x56, 0x34, 0x12, // cmp eax, 0x12345678
        0x74, 0x0e, // je fpu_ok
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2b, 0x00, 0x00, 0x00, // mov edi, 43
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ]);

    let path_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, path
    let argv_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, argv
    let envp_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdx, envp
    root.extend_from_slice(&[
        0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, // execve
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0xbf, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x0f,
        0x0b, // exit_group(42); ud2
    ]);

    let path_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(path);
    root.push(0);
    while !root.len().is_multiple_of(8) {
        root.push(0);
    }
    let argv_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&path_address.to_le_bytes());
    root.extend_from_slice(&0_u64.to_le_bytes());
    let envp_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&0_u64.to_le_bytes());
    root[path_operand..path_operand + 8].copy_from_slice(&path_address.to_le_bytes());
    root[argv_operand..argv_operand + 8].copy_from_slice(&argv_address.to_le_bytes());
    root[envp_operand..envp_operand + 8].copy_from_slice(&envp_address.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&root), "/bin/fork-exec-test")
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();

    assert_eq!(code, 0);
    assert_eq!(stdout, message);
    assert!(stderr.is_empty());

    let mut tool_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    tool_backend
        .install_static_elf(&static_elf(&root), "/bin/fork-exec-test")
        .unwrap();
    let (_, code, stdout, stderr) =
        futures::executor::block_on(tool_backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();

    assert_eq!(code, 0);
    assert_eq!(stdout, message);
    assert!(stderr.is_empty());
}

#[test]
fn static_elf_self_abort_terminates_instead_of_faulting() {
    // Regression: glibc abort() writes its diagnostic, then raises SIGABRT via
    // tgkill(pid, tid, SIGABRT). Previously SIGABRT was unhandled (ENOSYS), so
    // abort() fell through to its "unreachable" hlt trap and the VM reported a
    // spurious #GP (exception vector 13). A self-directed fatal signal must now
    // terminate the process with the conventional 128 + signo status while
    // preserving output emitted before the signal.
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM self-abort test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let message = b"before abort\n";
    // write(1, message, len)
    let mut code = vec![0xbf, 0x01, 0x00, 0x00, 0x00]; // mov edi, 1
    let message_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, message
    code.push(0xba);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax, SYS_write; syscall
    // pid = getpid(); tgkill(pid, pid, SIGABRT)
    code.extend_from_slice(&[
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall -> rax = pid
        0x89, 0xc7, // mov edi, eax  (tgid)
        0x89, 0xc6, // mov esi, eax  (tid)
        0xba, 0x06, 0x00, 0x00, 0x00, // mov edx, SIGABRT
        0xb8, 0xea, 0x00, 0x00, 0x00, // mov eax, SYS_tgkill
        0x0f, 0x05, // syscall -> must terminate here
        0x0f, 0x0b, // ud2 (only reached if the signal did not terminate us)
    ]);
    let message_address = LOAD_ADDRESS + code.len() as u64;
    code[message_operand..message_operand + 8].copy_from_slice(&message_address.to_le_bytes());
    code.extend_from_slice(message);

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/self-abort")
        .unwrap();
    let (code_result, stdout, stderr) = backend.run_static_elf_captured().unwrap();

    // 128 + SIGABRT(6) == 134, matching the shell/native convention.
    assert_eq!(code_result, 128 + libc::SIGABRT);
    assert_eq!(stdout, message);
    assert!(stderr.is_empty());
}

/// Exercises the kernel-visible frame, handler ABI, mask transition, libc
/// restorer, and backend-owned rt_sigreturn path on a real vCPU.
#[test]
fn static_elf_caught_signal_returns_through_rt_sigreturn() {
    if !kvm_available("signal-frame test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "caught-signal-rt-return",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include <unistd.h>

static volatile sig_atomic_t observed;
static unsigned char alternate_stack[65536];
static unsigned char replacement_stack[65536];

static void handler(int signo, siginfo_t *info, void *raw_context) {
  ucontext_t *context = (ucontext_t *)raw_context;
  sigset_t current;
  if (signo != SIGUSR1) {
    observed = 10;
    return;
  }
  if (info == 0 || info->si_signo != SIGUSR1 || info->si_code != SI_USER) {
    observed = 11;
    return;
  }
  if (context == 0 || (long)context->uc_mcontext.gregs[REG_RAX] != 0) {
    observed = 12;
    return;
  }
  if (sigprocmask(SIG_SETMASK, 0, &current) != 0 ||
      sigismember(&current, SIGUSR1) != 1 ||
      sigismember(&current, SIGUSR2) != 1) {
    observed = 13;
    return;
  }
  stack_t current_stack;
  uintptr_t handler_sp = (uintptr_t)&current_stack;
  if (handler_sp < (uintptr_t)alternate_stack ||
      handler_sp >= (uintptr_t)alternate_stack + sizeof(alternate_stack)) {
    observed = 14;
    return;
  }
  if (sigaltstack(0, &current_stack) != 0 ||
      (current_stack.ss_flags & SS_ONSTACK) == 0) {
    observed = 15;
    return;
  }
  stack_t replacement = {
    .ss_sp = replacement_stack, .ss_size = sizeof(replacement_stack), .ss_flags = 0
  };
  errno = 0;
  if (sigaltstack(&replacement, 0) != -1 || errno != EPERM) {
    observed = 16;
    return;
  }
  context->uc_mcontext.gregs[REG_RAX] = 0x5a;
  __asm__ volatile("pxor %%xmm15, %%xmm15" ::: "xmm15");
  observed = 1;
}

int main(void) {
  stack_t configured = {
    .ss_sp = alternate_stack, .ss_size = sizeof(alternate_stack), .ss_flags = 0
  };
  if (sigaltstack(&configured, 0) != 0) return 19;
  struct sigaction action = {0};
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGUSR2);
  const uint64_t expected_xmm = UINT64_C(0x123456789abcdef0);
  uint64_t restored_xmm = 0;
  __asm__ volatile("movq %0, %%xmm15" :: "r"(expected_xmm) : "xmm15");
  if (sigaction(SIGUSR1, &action, 0) != 0) return 20;
  int kill_result = kill(getpid(), SIGUSR1);
  __asm__ volatile("movq %%xmm15, %0" : "=r"(restored_xmm));
  if (kill_result != 0x5a) return 21;
  if (observed != 1) return observed == 0 ? 22 : observed;
  if (restored_xmm != expected_xmm) return 25;

  sigset_t restored;
  if (sigprocmask(SIG_SETMASK, 0, &restored) != 0) return 23;
  if (sigismember(&restored, SIGUSR1) != 0 ||
      sigismember(&restored, SIGUSR2) != 0) return 24;
  stack_t restored_stack;
  if (sigaltstack(0, &restored_stack) != 0) return 26;
  if ((restored_stack.ss_flags & SS_ONSTACK) != 0) return 27;
  if (restored_stack.ss_sp != alternate_stack ||
      restored_stack.ss_size != sizeof(alternate_stack)) return 28;
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "signal guest failed with code {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
}

#[test]
fn static_elf_altstack_boundaries_match_linux_frame_placement() {
    if !kvm_available("alternate-stack boundary test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "altstack-boundaries",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t nested_seen;
static uintptr_t alt_lower;
static int mode;

__attribute__((naked)) static void nested_handler(void) {
  __asm__ volatile(
      "movl $1, nested_seen(%rip)\n\t"
      "ret\n\t");
}

__attribute__((naked)) static void fresh_handler(void) {
  __asm__ volatile(
      "xorl %edi, %edi\n\t"
      "movl $60, %eax\n\t"
      "syscall\n\t"
      "ud2\n\t");
}

static void outer_handler(int signo) {
  if (signo != SIGUSR1) _exit(40);
  long pid = syscall(SYS_getpid);
  long tid = syscall(SYS_gettid);
  // For lower % 64 == 8, this interrupted RSP makes the nested frame begin
  // exactly at lower: xsave=lower+440, frame=xsave-440, with a 128-byte
  // red zone ending at the chosen RSP.
  uintptr_t target = alt_lower + 1404 - (mode != 1);
  volatile unsigned char *red_zone = (volatile unsigned char *)(target - 128);
  for (unsigned i = 0; i < 128; ++i) red_zone[i] = (unsigned char)(i ^ 0xa5);

  register long nr __asm__("rax") = SYS_tgkill;
  register long arg1 __asm__("rdi") = pid;
  register long arg2 __asm__("rsi") = tid;
  register long arg3 __asm__("rdx") = SIGUSR2;
  register uintptr_t new_sp __asm__("r8") = target;
  __asm__ volatile(
      "mov %%rsp, %%r10\n\t"
      "mov %%r8, %%rsp\n\t"
      "syscall\n\t"
      "mov %%r10, %%rsp\n\t"
      : "+a"(nr), "+r"(new_sp)
      : "D"(arg1), "S"(arg2), "d"(arg3)
      : "rcx", "r11", "r10", "memory");
  if (nr != 0 || nested_seen != 1) _exit(41);
  for (unsigned i = 0; i < 128; ++i) {
    if (red_zone[i] != (unsigned char)(i ^ 0xa5)) _exit(42);
  }
  _exit(0);
}

int main(int argc, char **argv) {
  if (argc != 2) return 20;
  long page = sysconf(_SC_PAGESIZE);
  unsigned char *mapping = mmap(0, (size_t)page * 3,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) return 21;
  unsigned char *middle = mapping + page;

  if (strcmp(argv[1], "fresh") == 0) {
    // The configured stack straddles a PROT_NONE guard, but the exact fresh
    // frame starts at middle+8. Reserving an erroneous second red zone would
    // start the frame 128 bytes lower in the guard.
    if (mprotect(mapping, (size_t)page, PROT_NONE) != 0) return 22;
    stack_t stack = {
      .ss_sp = middle - 764,
      .ss_size = 2048,
      .ss_flags = 0,
    };
    if (sigaltstack(&stack, 0) != 0) return 23;
    struct sigaction action = {0};
    action.sa_handler = fresh_handler;
    action.sa_flags = SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0) != 0) return 24;
    if (kill(getpid(), SIGUSR1) != 0) return 25;
    return 26;
  }

  alt_lower = (uintptr_t)middle + 8;
  stack_t stack = {
    .ss_sp = (void *)alt_lower,
    .ss_size = (size_t)page - 8,
    .ss_flags = 0,
  };
  if (sigaltstack(&stack, 0) != 0) return 27;
  if (strcmp(argv[1], "guard") == 0 &&
      mprotect(mapping, (size_t)page, PROT_NONE) != 0) return 28;

  struct sigaction inner = {0};
  inner.sa_handler = nested_handler;
  inner.sa_flags = SA_ONSTACK;
  sigemptyset(&inner.sa_mask);
  if (sigaction(SIGUSR2, &inner, 0) != 0) return 29;
  struct sigaction outer = {0};
  outer.sa_handler = outer_handler;
  outer.sa_flags = SA_ONSTACK;
  sigemptyset(&outer.sa_mask);
  if (sigaction(SIGUSR1, &outer, 0) != 0) return 30;
  mode = strcmp(argv[1], "exact") == 0 ? 1 : 2;
  if (kill(getpid(), SIGUSR1) != 0) return 31;
  return 32;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    for (mode, expected) in [
        ("fresh", 0),
        ("exact", 0),
        ("underflow", 128 + libc::SIGSEGV),
        ("guard", 128 + libc::SIGSEGV),
    ] {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable, mode],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(
            code,
            expected,
            "altstack mode {mode} failed; stdout={}; stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        );
    }
}

#[test]
fn static_elf_signal_frame_requires_writable_altstack() {
    if !kvm_available("read-only alternate signal stack test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "readonly-altstack",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

static void handler(int signo) {
  (void)signo;
  _exit(77);
}

int main(void) {
  long page = sysconf(_SC_PAGESIZE);
  size_t size = (size_t)SIGSTKSZ;
  size = (size + (size_t)page - 1) & ~((size_t)page - 1);
  void *stack = mmap(0, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED) return 20;
  stack_t configured = { .ss_sp = stack, .ss_size = size, .ss_flags = 0 };
  if (sigaltstack(&configured, 0) != 0) return 21;
  struct sigaction action = {0};
  action.sa_handler = handler;
  action.sa_flags = SA_ONSTACK;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, 0) != 0) return 22;
  if (mprotect(stack, size, PROT_READ) != 0) return 23;
  if (kill(getpid(), SIGUSR1) != 0) return 24;
  return 25;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        128 + libc::SIGSEGV,
        "a handler frame must not be written through a PROT_READ altstack; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
}
#[test]
fn static_elf_rt_sigreturn_accepts_null_and_redirected_fpstate() {
    if !kvm_available("rt_sigreturn fpstate-pointer test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "rt-sigreturn-fpstate",
        include_str!("fixtures/rt_sigreturn_fpregs.c"),
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    for (mode, expected_code) in [
        ("null", 0),
        ("alternate", 0),
        ("legacy", 0),
        ("legacy-guard", 0),
        ("xsave-unaligned", 128 + libc::SIGSEGV),
        ("subset", 0),
        ("uc-stack-invalid", 0),
        ("uc-stack-onstack", 0),
        ("uc-stack-replace", 0),
        ("invalid", 128 + libc::SIGSEGV),
    ] {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable, mode],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(code, expected_code, "mode={mode}");
        assert!(stdout.is_empty(), "mode={mode}");
        assert!(stderr.is_empty(), "mode={mode}");
    }
}

#[test]
fn static_elf_chains_pending_after_sigreturn_before_user_code() {
    if !kvm_available("pending-signal boundary test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "pending-signal-boundaries",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t phase;
static volatile sig_atomic_t between;
static volatile sig_atomic_t failure;

static void first_handler(int signal) {
  if (signal != SIGUSR1 || phase != 0 || between != 0) failure = 10;
  phase = 1;
}

static void second_handler(int signal) {
  if (signal != SIGUSR2 || phase != 1 || between != 0) failure = 11;
  phase = 2;
}

static int install(int signal, void (*handler)(int)) {
  struct sigaction action = {0};
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  return sigaction(signal, &action, 0);
}

int main(void) {
  if (install(SIGUSR1, first_handler) != 0) return 20;
  if (install(SIGUSR2, second_handler) != 0) return 21;
  sigset_t pair;
  sigemptyset(&pair);
  sigaddset(&pair, SIGUSR1);
  sigaddset(&pair, SIGUSR2);
  if (sigprocmask(SIG_BLOCK, &pair, 0) != 0) return 22;
  if (kill(getpid(), SIGUSR1) != 0) return 23;
  if (kill(getpid(), SIGUSR2) != 0) return 24;
  if (sigprocmask(SIG_UNBLOCK, &pair, 0) != 0) return 25;
  between = 1;
  if (failure != 0) return failure;
  return phase == 2 ? 0 : 26;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let code = backend.run_static_elf().unwrap();
    assert_eq!(
        code, 0,
        "pending-signal boundary guest failed with code {code}"
    );
}
#[test]
fn static_elf_clone_tid_side_effects_reach_guest_memory() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM clone TID test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    fn append_exit(code: &mut Vec<u8>, status: u32) {
        code.extend_from_slice(&[0xb8, 0xe7, 0x00, 0x00, 0x00]);
        code.push(0xbf);
        code.extend_from_slice(&status.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    }

    fn patch_jump(code: &mut [u8], operand: usize, target: usize) {
        let displacement = i32::try_from(target as isize - (operand + 4) as isize).unwrap();
        code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
    }

    const PARENT_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1808;
    const REPLACEMENT_CLEAR_TID: u64 = LOAD_ADDRESS + 0x1810;
    const INVALID_TID: u64 = MEMORY_SIZE as u64 - 1;
    let flags = libc::SIGCHLD as u32
        | libc::CLONE_PARENT_SETTID as u32
        | libc::CLONE_CHILD_SETTID as u32
        | libc::CLONE_CHILD_CLEARTID as u32;

    let mut code = Vec::new();
    code.extend_from_slice(&[0xb8, 0x38, 0x00, 0x00, 0x00]); // mov eax, SYS_clone
    code.push(0xbf); // mov edi, flags
    code.extend_from_slice(&flags.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xf6]); // xor esi, esi
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, parent_tid
    code.extend_from_slice(&PARENT_TID.to_le_bytes());
    code.extend_from_slice(&[0x49, 0xba]); // movabs r10, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x84, 0x00, 0x00, 0x00, 0x00]); // syscall; jz child
    let first_child_jump = code.len() - 4;

    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, parent_tid
    code.extend_from_slice(&PARENT_TID.to_le_bytes());
    code.extend_from_slice(&[0x39, 0x01, 0x74, 0x0e]); // cmp [rcx], eax; je parent_tid_ok
    append_exit(&mut code, 61);
    code.extend_from_slice(&[
        0x89, 0xc7, // mov edi, eax
        0x48, 0x83, 0xec, 0x10, // sub rsp, 16
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x31, 0xd2, // xor edx, edx
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0x3d, 0x00, 0x00, 0x00, // mov eax, SYS_wait4
        0x0f, 0x05, // syscall
        0x83, 0x3c, 0x24, 0x00, // cmp dword ptr [rsp], 0
        0x74, 0x0e, // je first_child_ok
    ]);
    append_exit(&mut code, 64);

    // A second clone proves invalid TID stores do not abort child creation.
    code.extend_from_slice(&[0xb8, 0x38, 0x00, 0x00, 0x00]);
    code.push(0xbf);
    code.extend_from_slice(&flags.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xf6]); // xor esi, esi
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, invalid parent_tid
    code.extend_from_slice(&INVALID_TID.to_le_bytes());
    code.extend_from_slice(&[0x49, 0xba]); // movabs r10, invalid child_tid
    code.extend_from_slice(&INVALID_TID.to_le_bytes());
    code.extend_from_slice(&[
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x79, 0x0e, // jns clone_returned_pid_or_child
    ]);
    append_exit(&mut code, 65);
    code.extend_from_slice(&[0x0f, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz child
    let invalid_child_jump = code.len() - 4;
    code.extend_from_slice(&[
        0x89, 0xc7, // mov edi, eax
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x31, 0xd2, // xor edx, edx
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0x3d, 0x00, 0x00, 0x00, // mov eax, SYS_wait4
        0x0f, 0x05, // syscall
        0x39, 0xf8, // cmp eax, edi
        0x74, 0x0e, // je waited_for_second_child
    ]);
    append_exit(&mut code, 66);
    code.extend_from_slice(&[
        0x8b, 0x3c, 0x24, // mov edi, dword ptr [rsp]
        0xc1, 0xef, 0x08, // shr edi, 8
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ]);

    let first_child = code.len();
    patch_jump(&mut code, first_child_jump, first_child);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0x83, 0x39, 0x02, 0x74, 0x0e]); // cmp [rcx], 2; je
    append_exit(&mut code, 62);
    code.extend_from_slice(&[0xb8, 0xda, 0x00, 0x00, 0x00]); // set_tid_address
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, replacement pointer
    code.extend_from_slice(&REPLACEMENT_CLEAR_TID.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x83, 0xf8, 0x02, 0x74, 0x0e]); // syscall; cmp eax, 2; je
    append_exit(&mut code, 63);
    append_exit(&mut code, 0);

    let invalid_store_child = code.len();
    patch_jump(&mut code, invalid_child_jump, invalid_store_child);
    append_exit(&mut code, 0);

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/clone-tid-test")
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn static_elf_runs_glibc_clone3_thread_and_restores_parent_state() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM clone3 thread test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    fn append_exit(code: &mut Vec<u8>, status: u32) {
        code.extend_from_slice(&[0xb8, 0xe7, 0x00, 0x00, 0x00]);
        code.push(0xbf);
        code.extend_from_slice(&status.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    }

    fn patch_jump(code: &mut [u8], operand: usize, target: usize) {
        let displacement = i32::try_from(target as isize - (operand + 4) as isize).unwrap();
        code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
    }

    const PARENT_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1808;
    const CHILD_RESULT: u64 = LOAD_ADDRESS + 0x1810;
    const CHILD_FS: u64 = LOAD_ADDRESS + 0x1818;
    const CHILD_RSP: u64 = LOAD_ADDRESS + 0x1820;
    const TLS: u64 = LOAD_ADDRESS + 0x1880;
    const CHILD_STACK: u64 = LOAD_ADDRESS + 0x1900;
    const CHILD_STACK_SIZE: u64 = 0x600;
    const CHILD_STACK_TOP: u64 = CHILD_STACK + CHILD_STACK_SIZE;
    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_SYSVSEM as u64
        | libc::CLONE_SETTLS as u64
        | libc::CLONE_PARENT_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64;

    let mut code = vec![
        0x49, 0x89, 0xe4, // mov r12, rsp
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0x66, 0x0f, 0x6e, 0xc0, // movd xmm0, eax
    ];
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0xc7, 0x01, 0xff, 0xff, 0xff, 0x7f]); // mov [rcx], sentinel
    code.extend_from_slice(&[0xb8, 0xb3, 0x01, 0x00, 0x00]); // mov eax, SYS_clone3
    let clone_args_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, clone_args
    code.extend_from_slice(&[0xbe, 0x58, 0x00, 0x00, 0x00]); // mov esi, sizeof(clone_args)
    code.extend_from_slice(&[0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x84, 0, 0, 0, 0]); // syscall; jz child
    let child_jump = code.len() - 4;

    code.extend_from_slice(&[0x4c, 0x39, 0xe4, 0x74, 0x0e]); // cmp rsp, r12; je
    append_exit(&mut code, 81);
    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // mov r13d, eax
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[
        0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, FUTEX_WAIT
        0x44, 0x89, 0xea, // mov edx, r13d
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, SYS_futex
        0x0f, 0x05, // syscall
        0x83, 0x3f, 0x00, // cmp dword ptr [rdi], 0
        0x75, 0xe9, // jne FUTEX_WAIT
        0x44, 0x89, 0xe8, // mov eax, r13d
    ]);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, parent_tid
    code.extend_from_slice(&PARENT_TID.to_le_bytes());
    code.extend_from_slice(&[0x39, 0x01, 0x74, 0x0e]); // cmp [rcx], eax; je
    append_exit(&mut code, 82);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_result
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x39, 0x01, 0x74, 0x0e]); // cmp [rcx], eax; je
    append_exit(&mut code, 83);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0x83, 0x39, 0x00, 0x74, 0x0e]); // cmp dword ptr [rcx], 0; je
    append_exit(&mut code, 84);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_fs
    code.extend_from_slice(&CHILD_FS.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, tls
    code.extend_from_slice(&TLS.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x39, 0x11, 0x74, 0x0e]); // cmp [rcx], rdx; je
    append_exit(&mut code, 85);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_rsp
    code.extend_from_slice(&CHILD_RSP.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, child_stack_top
    code.extend_from_slice(&CHILD_STACK_TOP.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x39, 0x11, 0x74, 0x0e]); // cmp [rcx], rdx; je
    append_exit(&mut code, 86);
    code.extend_from_slice(&[
        0x66, 0x0f, 0x7e, 0xc0, // movd eax, xmm0
        0x3d, 0x78, 0x56, 0x34, 0x12, // cmp eax, 0x12345678
        0x74, 0x0e, // je
    ]);
    append_exit(&mut code, 87);
    code.extend_from_slice(&[
        0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, SYS_gettid
        0x0f, 0x05, // syscall
        0x83, 0xf8, 0x01, // cmp eax, 1
        0x74, 0x0e, // je
    ]);
    append_exit(&mut code, 88);
    append_exit(&mut code, 0);

    let child = code.len();
    patch_jump(&mut code, child_jump, child);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_rsp
    code.extend_from_slice(&CHILD_RSP.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x21]); // mov [rcx], rsp
    code.extend_from_slice(&[0xb8, 0x9e, 0x00, 0x00, 0x00]); // mov eax, SYS_arch_prctl
    code.extend_from_slice(&[0xbf, 0x03, 0x10, 0x00, 0x00]); // mov edi, ARCH_GET_FS
    code.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, child_fs
    code.extend_from_slice(&CHILD_FS.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall
    code.extend_from_slice(&[0xb8, 0xba, 0x00, 0x00, 0x00, 0x0f, 0x05]); // gettid
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_result
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x89, 0x01]); // mov [rcx], eax
    code.extend_from_slice(&[
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);

    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let clone_args_address = LOAD_ADDRESS + code.len() as u64;
    code[clone_args_operand..clone_args_operand + 8]
        .copy_from_slice(&clone_args_address.to_le_bytes());
    let mut clone_args = [0_u8; 88];
    clone_args[0..8].copy_from_slice(&flags.to_le_bytes());
    // Linux ignores pidfd without CLONE_PIDFD; glibc aliases this union slot.
    clone_args[8..16].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[16..24].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[24..32].copy_from_slice(&PARENT_TID.to_le_bytes());
    clone_args[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
    clone_args[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
    clone_args[56..64].copy_from_slice(&TLS.to_le_bytes());
    code.extend_from_slice(&clone_args);

    // Exercise every worker-dispatch path so a `pthread_join`-style
    // `FUTEX_WAIT`/`CLEARTID` round trip completes (exit 0, no hang) in each:
    //   * `Direct`: the non-Tool personality (`run_process_action`).
    //   * `ToolDefault`: run a tool with *no* explicit ownership override, so the
    //     backend resolves ownership from `Tool::thread_ownership` — whose
    //     default is Tool-owned "follow children". This locks in the safe
    //     default (worker on the Tool loop, `futex` routed to the Tool) so a KVM
    //     caller no longer has to opt threads in.
    //   * `Tool(ThreadOwnership::Host)`: force the hybrid model, where
    //     `run_process_action_with_tool` falls through to the direct worker path
    //     and `futex` stays host-owned. Both execution and futex ownership are
    //     Host, so the round trip is consistent and cannot deadlock.
    //   * `Tool(ThreadOwnership::Tool)`: force the worker onto the Tool loop with
    //     `futex` routed to the Tool.
    #[derive(Debug, Clone, Copy)]
    enum WorkerDispatch {
        Direct,
        ToolDefault,
        Tool(ThreadOwnership),
    }
    for dispatch in [
        WorkerDispatch::Direct,
        WorkerDispatch::ToolDefault,
        WorkerDispatch::Tool(ThreadOwnership::Host),
        WorkerDispatch::Tool(ThreadOwnership::Tool),
    ] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/clone3-thread-test")
            .unwrap();
        let (exit_code, stdout, stderr) = match dispatch {
            WorkerDispatch::Direct => backend.run_static_elf_captured().unwrap(),
            WorkerDispatch::ToolDefault => {
                // No set_thread_ownership: rely on the resolved default.
                let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                    backend.run_static_elf_with_tool::<StraceTool>((), true),
                )
                .unwrap();
                (exit_code, stdout, stderr)
            }
            WorkerDispatch::Tool(ownership) => {
                backend.set_thread_ownership(ownership);
                let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                    backend.run_static_elf_with_tool::<StraceTool>((), true),
                )
                .unwrap();
                (exit_code, stdout, stderr)
            }
        };
        assert_eq!(exit_code, 0, "dispatch={dispatch:?}");
        assert!(stdout.is_empty(), "dispatch={dispatch:?}");
        assert!(stderr.is_empty(), "dispatch={dispatch:?}");
    }
}

#[test]
fn host_owned_worker_descriptors_keep_read_and_readv_backend_owned() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM Host-owned descriptor test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "host-owned-worker-descriptors",
        r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/uio.h>
#include <unistd.h>

#define EVENT_READ_FD 198
#define VECTOR_READ_FD 199

static _Atomic int ready;

static void *worker(void *unused) {
  (void)unused;
  int event = eventfd(0, EFD_CLOEXEC);
  int pipe_fds[2];
  if (event < 0 || pipe(pipe_fds) != 0 ||
      dup2(event, EVENT_READ_FD) != EVENT_READ_FD ||
      dup2(pipe_fds[0], VECTOR_READ_FD) != VECTOR_READ_FD) {
    atomic_store_explicit(&ready, -1, memory_order_release);
    return (void *)(uintptr_t)1;
  }
  close(event);
  close(pipe_fds[0]);

  uint64_t counter = 7;
  char first = 'v';
  char second = 'r';
  struct iovec vector[2] = {
      {.iov_base = &first, .iov_len = 1},
      {.iov_base = &second, .iov_len = 1},
  };
  if (write(EVENT_READ_FD, &counter, sizeof(counter)) != sizeof(counter) ||
      writev(pipe_fds[1], vector, 2) != 2) {
    atomic_store_explicit(&ready, -1, memory_order_release);
    return (void *)(uintptr_t)1;
  }
  close(pipe_fds[1]);
  atomic_store_explicit(&ready, 1, memory_order_release);
  return NULL;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0) {
    return 10;
  }
  int state;
  while ((state = atomic_load_explicit(&ready, memory_order_acquire)) == 0) {
  }
  if (state < 0) {
    return 11;
  }

  uint64_t counter = 0;
  if (read(EVENT_READ_FD, &counter, sizeof(counter)) != sizeof(counter) || counter != 7) {
    return 12;
  }
  char first = 0;
  char second = 0;
  struct iovec vector[2] = {
      {.iov_base = &first, .iov_len = 1},
      {.iov_base = &second, .iov_len = 1},
  };
  if (readv(VECTOR_READ_FD, vector, 2) != 2 || first != 'v' || second != 'r') {
    return 13;
  }

  void *result = NULL;
  if (pthread_join(thread, &result) != 0 || result != NULL) {
    return 14;
  }
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    backend.set_thread_ownership(ThreadOwnership::Host);
    let (trace, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();

    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    let entries = trace.formatted();
    assert!(
        !entries.iter().any(|entry| entry.starts_with("read(198,")),
        "Host-owned eventfd read unexpectedly reached the Tool: {entries:?}"
    );
    assert!(
        !entries.iter().any(|entry| entry.starts_with("readv(199,")),
        "Host-owned pipe readv unexpectedly reached the Tool: {entries:?}"
    );
}

#[test]
fn real_glibc_get_robust_list_tracks_fork_and_thread_lifecycles() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM robust-list lifecycle test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "robust-list-lifecycle",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int tid_pipe[2];
static int release_pipe[2];

static void *worker(void *unused) {
  (void)unused;
  pid_t tid = (pid_t)syscall(SYS_gettid);
  struct robust_list_head *self_head = NULL;
  struct robust_list_head *leader_head = NULL;
  size_t self_len = 0;
  size_t leader_len = 0;
  char byte = 0;

  if (syscall(SYS_get_robust_list, 0, &self_head, &self_len) != 0 ||
      syscall(SYS_get_robust_list, getpid(), &leader_head, &leader_len) != 0 ||
      self_head == NULL || leader_head == NULL || self_head == leader_head ||
      self_len != sizeof(*self_head) || leader_len != sizeof(*leader_head) ||
      write(tid_pipe[1], &tid, sizeof(tid)) != sizeof(tid) ||
      read(release_pipe[0], &byte, sizeof(byte)) != sizeof(byte)) {
    return (void *)(uintptr_t)1;
  }
  return NULL;
}

int main(void) {
  int ready_pipe[2];
  int child_release_pipe[2];
  if (pipe(ready_pipe) != 0 || pipe(child_release_pipe) != 0) {
    return 10;
  }

  pid_t child = fork();
  if (child < 0) {
    return 11;
  }
  if (child == 0) {
    char byte = 1;
    if (write(ready_pipe[1], &byte, sizeof(byte)) != sizeof(byte) ||
        read(child_release_pipe[0], &byte, sizeof(byte)) != sizeof(byte)) {
      _exit(12);
    }
    _exit(0);
  }

  char byte = 0;
  if (read(ready_pipe[0], &byte, sizeof(byte)) != sizeof(byte)) {
    return 13;
  }
  struct robust_list_head *head = (void *)(uintptr_t)1;
  size_t length = 0;
  if (syscall(SYS_get_robust_list, child, &head, &length) != 0 ||
      length != sizeof(*head)) {
    return 14;
  }
  byte = 1;
  if (write(child_release_pipe[1], &byte, sizeof(byte)) != sizeof(byte)) {
    return 15;
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    return 16;
  }
  errno = 0;
  if (syscall(SYS_get_robust_list, child, &head, &length) != -1 ||
      errno != ESRCH) {
    return 17;
  }

  if (pipe(tid_pipe) != 0 || pipe(release_pipe) != 0) {
    return 18;
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0) {
    return 19;
  }
  pid_t tid = 0;
  if (read(tid_pipe[0], &tid, sizeof(tid)) != sizeof(tid)) {
    return 20;
  }
  head = NULL;
  length = 0;
  if (syscall(SYS_get_robust_list, tid, &head, &length) != 0 ||
      head == NULL || length != sizeof(*head)) {
    return 21;
  }
  byte = 1;
  if (write(release_pipe[1], &byte, sizeof(byte)) != sizeof(byte)) {
    return 22;
  }
  void *result = NULL;
  if (pthread_join(thread, &result) != 0 || result != NULL) {
    return 23;
  }
  errno = 0;
  if (syscall(SYS_get_robust_list, tid, &head, &length) != -1 ||
      errno != ESRCH) {
    return 24;
  }

  puts("robust-list lifecycle ok");
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let (stdout, stderr) =
        run_host_program_with_tool_captured(executable, &[executable], &directory.0);
    assert_eq!(stdout, b"robust-list lifecycle ok\n");
    assert!(
        stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&stderr)
    );
}

#[test]
fn recvmsg_flags_native_and_kvm_match() {
    if !kvm_available("recvmsg_flags_native_and_kvm_match") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "recvmsg-flags",
        include_str!("fixtures/recvmsg_flags.c"),
    );
    let native = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "15s"])
        .arg(&executable)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(0), "{native:?}");
    assert!(native.stderr.is_empty(), "{native:?}");
    assert_eq!(native.stdout, b"recvmsg flags=00000000\nrecvmsg flags=40000000\nrecvmmsg flags=00000000\nrecvmmsg flags=40000000\n");
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&executable).unwrap(),
            &[executable.to_str().unwrap()],
            &[],
            &directory.0,
        )
        .unwrap();
    let (status, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(status, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
}

#[test]
fn real_glibc_scm_rights_translate_across_thread_and_fork_tables() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM SCM_RIGHTS test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "scm-rights-translation",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int sockets[2];
static int received_fds[2] = {-1, -1};

static void *receive_rights(void *unused) {
  (void)unused;
  char payload = 0;
  char control[CMSG_SPACE(2 * sizeof(int))];
  struct iovec iov = {.iov_base = &payload, .iov_len = 1};
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  memset(control, 0, sizeof(control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  if (recvmsg(sockets[1], &message, MSG_CMSG_CLOEXEC) != 1 || payload != 'q' ||
      (message.msg_flags & MSG_CTRUNC) != 0) {
    return (void *)1;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(2 * sizeof(int))) {
    return (void *)2;
  }
  memcpy(received_fds, CMSG_DATA(cmsg), sizeof(received_fds));
  return NULL;
}

static int send_rights(const int fds[2]) {
  char payload = 'q';
  char control[CMSG_SPACE(2 * sizeof(int))];
  struct iovec iov = {.iov_base = &payload, .iov_len = 1};
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  memset(control, 0, sizeof(control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(2 * sizeof(int));
  memcpy(CMSG_DATA(cmsg), fds, 2 * sizeof(int));
  return (int)sendmsg(sockets[0], &message, 0);
}

int main(void) {
  int pipe_fds[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0 || pipe(pipe_fds) != 0 ||
      sockets[0] != 3 || sockets[1] != 4 || pipe_fds[0] != 5 || pipe_fds[1] != 6) {
    return 10;
  }

  int invalid[2] = {pipe_fds[0], 999};
  errno = 0;
  if (send_rights(invalid) != -1 || errno != EBADF) {
    return 11;
  }
  if (send_rights(pipe_fds) != 1) {
    return 12;
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, receive_rights, NULL) != 0) {
    return 13;
  }
  void *thread_result = NULL;
  if (pthread_join(thread, &thread_result) != 0 || thread_result != NULL) {
    return 14;
  }
  if (received_fds[0] != 7 || received_fds[1] != 8 ||
      (fcntl(received_fds[0], F_GETFD) & FD_CLOEXEC) == 0 ||
      (fcntl(received_fds[1], F_GETFD) & FD_CLOEXEC) == 0) {
    return 15;
  }

  close(pipe_fds[0]);
  close(pipe_fds[1]);
  pid_t child = fork();
  if (child < 0) {
    return 16;
  }
  if (child == 0) {
    char byte = 'z';
    _exit(write(received_fds[1], &byte, 1) == 1 ? 0 : 17);
  }
  char byte = 0;
  int status = 0;
  if (read(received_fds[0], &byte, 1) != 1 || byte != 'z' ||
      waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    return 18;
  }

  puts("scm-rights translation ok");
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let (stdout, stderr) =
        run_host_program_with_tool_captured(executable, &[executable], &directory.0);
    assert_eq!(stdout, b"scm-rights translation ok\n");
    assert!(
        stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&stderr)
    );
}

#[test]
fn worker_exit_group_terminates_the_root_with_its_status() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM worker exit_group test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    fn append_exit_group(code: &mut Vec<u8>, status: u32) {
        code.extend_from_slice(&[0xb8, 0xe7, 0x00, 0x00, 0x00]);
        code.push(0xbf);
        code.extend_from_slice(&status.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    }

    fn patch_jump(code: &mut [u8], operand: usize, target: usize) {
        let displacement = i32::try_from(target as isize - (operand + 4) as isize).unwrap();
        code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
    }

    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_STACK: u64 = LOAD_ADDRESS + 0x1900;
    const CHILD_STACK_SIZE: u64 = 0x600;
    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_CHILD_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64;

    let mut code = Vec::new();
    code.extend_from_slice(&[0xb8, 0xb3, 0x01, 0x00, 0x00]); // mov eax, SYS_clone3
    let clone_args_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, clone_args
    code.extend_from_slice(&[0xbe, 0x58, 0x00, 0x00, 0x00]); // mov esi, sizeof(clone_args)
    code.extend_from_slice(&[0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x84, 0, 0, 0, 0]); // syscall; jz child
    let child_jump = code.len() - 4;

    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // mov r13d, eax
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    let wait = code.len();
    code.extend_from_slice(&[
        0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, FUTEX_WAIT
        0x44, 0x89, 0xea, // mov edx, r13d
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, SYS_futex
        0x0f, 0x05, // syscall
        0x83, 0x3f, 0x00, // cmp dword ptr [rdi], 0
        0x0f, 0x85, 0, 0, 0, 0, // jne wait
    ]);
    let wait_jump = code.len() - 4;
    patch_jump(&mut code, wait_jump, wait);
    append_exit_group(&mut code, 0);

    let child = code.len();
    patch_jump(&mut code, child_jump, child);
    append_exit_group(&mut code, 37);

    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let clone_args_address = LOAD_ADDRESS + code.len() as u64;
    code[clone_args_operand..clone_args_operand + 8]
        .copy_from_slice(&clone_args_address.to_le_bytes());
    let mut clone_args = [0_u8; 88];
    clone_args[0..8].copy_from_slice(&flags.to_le_bytes());
    clone_args[16..24].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
    clone_args[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
    code.extend_from_slice(&clone_args);

    for with_tool in [false, true] {
        let was_blocked = set_interrupt_signal_blocked(true);
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/worker-exit-group-test")
            .unwrap();
        let exit_code = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
            exit_code
        } else {
            backend.run_static_elf().unwrap()
        };
        let mut child_tid = [0; std::mem::size_of::<i32>()];
        backend
            .memory()
            .unwrap()
            .read(CHILD_TID, &mut child_tid)
            .unwrap();
        let remained_blocked = set_interrupt_signal_blocked(was_blocked);
        assert!(remained_blocked, "with_tool={with_tool}");
        assert_eq!(exit_code, 37, "with_tool={with_tool}");
        assert_eq!(i32::from_le_bytes(child_tid), 0, "with_tool={with_tool}");
    }
}

#[test]
fn real_bash_redirects_builtin_output_through_f_dupfd() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM Bash redirection test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    let (stdout, stderr) = run_host_program_captured(
        "/bin/bash",
        &[
            "bash",
            "--norc",
            "-c",
            "printf redirected > output; printf visible",
        ],
        &root.0,
    );
    assert_eq!(stdout, b"visible");
    assert!(stderr.is_empty());
    assert_eq!(std::fs::read(root.0.join("output")).unwrap(), b"redirected");
}

#[test]
fn real_bash_small_pipeline_uses_legacy_process_clone_tid_flags() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM Bash pipeline test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    // The child runs to completion before the parent resumes, so this covers a
    // bounded pipeline without claiming concurrent producer/consumer support.
    let (stdout, stderr) = run_host_program_captured(
        "/bin/bash",
        &["bash", "--norc", "-c", "printf abc | /usr/bin/wc -c"],
        &root.0,
    );
    assert_eq!(stdout, b"3\n");
    assert!(
        stderr.is_empty(),
        "unexpected Bash stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
}

#[test]
fn real_coreutils_complete_file_mutation_workflow() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM coreutils test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    std::fs::write(root.0.join("source"), b"payload\n").unwrap();

    run_host_program("/bin/mkdir", &["mkdir", "-p", "directory/nested"], &root.0);
    run_host_program("/usr/bin/touch", &["touch", "touched"], &root.0);
    run_host_program("/bin/chmod", &["chmod", "600", "touched"], &root.0);
    run_host_program("/bin/ln", &["ln", "source", "hard-link"], &root.0);
    run_host_program("/bin/ln", &["ln", "-s", "source", "symbolic-link"], &root.0);
    run_host_program("/bin/mv", &["mv", "hard-link", "renamed"], &root.0);
    run_host_program("/usr/bin/mkfifo", &["mkfifo", "fifo"], &root.0);
    run_host_program(
        "/usr/bin/install",
        &["install", "-m", "700", "source", "installed"],
        &root.0,
    );
    run_host_program("/bin/rm", &["rm", "renamed"], &root.0);
    run_host_program("/bin/rmdir", &["rmdir", "directory/nested"], &root.0);

    assert!(root.0.join("directory").is_dir());
    assert!(!root.0.join("directory/nested").exists());
    assert_eq!(std::fs::read(root.0.join("source")).unwrap(), b"payload\n");
    assert!(root.0.join("touched").is_file());
    assert_eq!(
        std::fs::read_link(root.0.join("symbolic-link")).unwrap(),
        std::path::Path::new("source")
    );
    assert!(
        std::fs::symlink_metadata(root.0.join("fifo"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert_eq!(
        std::fs::read(root.0.join("installed")).unwrap(),
        b"payload\n"
    );
    assert!(!root.0.join("renamed").exists());
}

#[test]
fn static_elf_executes_syscall_and_exits() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM static ELF test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();

    backend
        .memory_mut()
        .unwrap()
        .write(LOAD_ADDRESS + 0x1000, &[0xff])
        .unwrap();

    // Check BSS and argc, then require deterministic getpid == 1 and preserved
    // RBX. Any loader or SYSCALL return-state error takes the exit_group(42)
    // path rather than producing a false pass.
    let code = [
        0x48, 0xb8, 0x00, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x201000
        0x80, 0x38, 0x00, // cmp byte ptr [rax], 0
        0x75, 0x2d, // jne failure
        0x48, 0x83, 0x3c, 0x24, 0x01, // cmp qword ptr [rsp], 1
        0x75, 0x26, // jne failure
        0xbb, 0x78, 0x56, 0x34, 0x12, // mov ebx, 0x12345678
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0x48, 0x83, 0xf8, 0x01, // cmp rax, 1
        0x75, 0x14, // jne failure
        0x48, 0x81, 0xfb, 0x78, 0x56, 0x34, 0x12, // cmp rbx, 0x12345678
        0x75, 0x0b, // jne failure
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
        0xb8, 0xe7, 0x00, 0x00, 0x00, // failure: mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    backend
        .install_static_elf(&static_elf(&code), "/bin/true")
        .unwrap();

    assert_eq!(backend.run_static_elf().unwrap(), 0);
}

#[test]
fn static_elf_host_futex_wait_observes_finite_timeout() {
    if !kvm_available("KVM host futex timeout test") {
        return;
    }

    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, word
    let word_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.push(0xbe); // mov esi, FUTEX_WAIT | FUTEX_PRIVATE_FLAG
    code.extend_from_slice(&(libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG).to_le_bytes());
    code.extend_from_slice(&[0x31, 0xd2]); // xor edx, edx: expected word value
    code.extend_from_slice(&[0x49, 0xba]); // movabs r10, timeout
    let timeout_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.extend_from_slice(&[0x45, 0x31, 0xc0]); // xor r8d, r8d
    code.extend_from_slice(&[0x45, 0x31, 0xc9]); // xor r9d, r9d
    code.push(0xb8); // mov eax, SYS_futex
    code.extend_from_slice(&(libc::SYS_futex as u32).to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall
    code.extend_from_slice(&[0x31, 0xff]); // xor edi, edi: success exit status
    code.extend_from_slice(&[0x48, 0x3d]); // cmp rax, -ETIMEDOUT
    code.extend_from_slice(&(-libc::ETIMEDOUT).to_le_bytes());
    code.extend_from_slice(&[0x40, 0x0f, 0x95, 0xc7]); // setne dil: failure status 1
    code.push(0xb8); // mov eax, SYS_exit_group
    code.extend_from_slice(&(libc::SYS_exit_group as u32).to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]); // syscall; ud2

    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let word_address = LOAD_ADDRESS + code.len() as u64;
    code.extend_from_slice(&0_u32.to_le_bytes());
    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let timeout_address = LOAD_ADDRESS + code.len() as u64;
    code.extend_from_slice(&0_i64.to_le_bytes());
    code.extend_from_slice(&10_000_000_i64.to_le_bytes());
    code[word_operand..word_operand + 8].copy_from_slice(&word_address.to_le_bytes());
    code[timeout_operand..timeout_operand + 8].copy_from_slice(&timeout_address.to_le_bytes());

    // Direct KvmBackend execution owns the futex syscall in ElfExecutor. The
    // zero word matches the expected value, there is no waker, and the guest
    // reports success only after the copied 10 ms timeout returns ETIMEDOUT.
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/futex-timeout")
        .unwrap();
    assert_eq!(backend.run_static_elf().unwrap(), 0);
}

#[test]
fn static_elf_tool_capture_preserves_configured_stdin() {
    if !kvm_available("KVM captured stdin test") {
        return;
    }

    let directory = TestDirectory::new();
    let stdin_path = directory.0.join("stdin");
    std::fs::write(&stdin_path, b"stdin-through-kvm\n").unwrap();
    let stdin = std::fs::File::open(stdin_path).unwrap();

    let image = std::fs::read("/bin/cat").unwrap();
    let mut backend = KvmBackend::new_with_stdin(256 * 1024 * 1024, Some(stdin)).unwrap();
    backend
        .install_static_elf_with_args(&image, &["/bin/cat"], &["PATH=/usr/bin:/bin"])
        .unwrap();

    let (_, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();

    assert_eq!(code, 0);
    assert_eq!(stdout, b"stdin-through-kvm\n");
    assert!(stderr.is_empty());

    let mut backend = KvmBackend::new_with_stdin(256 * 1024 * 1024, None).unwrap();
    backend
        .install_static_elf_with_args(&image, &["/bin/cat"], &["PATH=/usr/bin:/bin"])
        .unwrap();
    let (_, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();

    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn kvm_initial_rbp_and_rflags_match_native_linux_process_entry() {
    if !kvm_available("KVM initial-register parity test") {
        return;
    }

    // Capture rbp and rflags before the guest makes its first syscall. The
    // temporary stack adjustment happens only after both entry values are in
    // callee-saved registers.
    let code = [
        0x9c, // pushfq
        0x5b, // pop rbx
        0x49, 0x89, 0xec, // mov r12, rbp
        0x48, 0x83, 0xec, 0x10, // sub rsp, 16
        0x4c, 0x89, 0x24, 0x24, // mov [rsp], r12
        0x48, 0x89, 0x5c, 0x24, 0x08, // mov [rsp + 8], rbx
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0xba, 0x10, 0x00, 0x00, 0x00, // mov edx, 16
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, SYS_write
        0x0f, 0x05, // syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let image = static_elf(&code);
    let executable = NativeTestExecutable::new(&image, 0o755);
    let native = std::process::Command::new(executable.path())
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "native entry-register fixture failed: {native:?}",
    );

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&image, "/bin/entry-registers")
        .unwrap();
    let (code, kvm_stdout, kvm_stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "KVM entry-register fixture failed; stderr={}",
        String::from_utf8_lossy(&kvm_stderr),
    );

    let decode = |label: &str, bytes: &[u8]| {
        assert_eq!(bytes.len(), 16, "{label} emitted the wrong state size");
        let rbp = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let rflags = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        (rbp, rflags)
    };
    let native_state = decode("native", &native.stdout);
    let kvm_state = decode("KVM", &kvm_stdout);

    assert_eq!(native_state.0, 0, "native Linux did not enter with rbp=0");
    assert_eq!(
        native_state.1, 0x202,
        "native Linux did not enter with reserved bit and IF set",
    );
    assert_eq!(
        kvm_state, native_state,
        "KVM must reproduce native Linux's observed rbp and rflags at _start",
    );
}

#[test]
fn kvm_static_elf_getppid_follows_pid_namespace_contract() {
    if !kvm_available("getppid/getpgrp namespace test") {
        return;
    }

    // A static ELF guest that issues getppid and self-checks the deterministic
    // parent PID. Linux PID-namespace semantics give a conventional root guest
    // (detcore ROOT_DETPID == 3) getppid() == 1, while namespace init (PID 1)
    // has getppid() == 0. KVM synthesizes the guest identity and must reproduce
    // those pinned semantics. Any mismatch takes the exit_group(42) path.
    #[rustfmt::skip]
    fn getppid_probe(expected_ppid: u8) -> [u8; 36] {
        [
            0xb8, 0x6e, 0x00, 0x00, 0x00,   // mov eax, SYS_getppid (110)
            0x0f, 0x05,                     // syscall
            0x48, 0x83, 0xf8, expected_ppid, // cmp rax, expected_ppid
            0x75, 0x09,                     // jne failure (skip the 9-byte success block)
            0xb8, 0xe7, 0x00, 0x00, 0x00,   // mov eax, SYS_exit_group (231)
            0x31, 0xff,                     // xor edi, edi
            0x0f, 0x05,                     // syscall  (exit_group(0))
            0xb8, 0xe7, 0x00, 0x00, 0x00,   // failure: mov eax, SYS_exit_group
            0xbf, 0x2a, 0x00, 0x00, 0x00,   // mov edi, 42
            0x0f, 0x05,                     // syscall  (exit_group(42))
            0x0f, 0x0b,                     // ud2
        ]
    }

    // A second fixture pins the process group after root-PID configuration.
    // Both configuration orderings are production paths and must rebuild the
    // loaded lifecycle table with a PGID distinct from its default value.
    #[rustfmt::skip]
    fn getpgrp_probe(expected_pgid: u8) -> [u8; 52] {
        [
            0xb8, 0x6f, 0x00, 0x00, 0x00,   // mov eax, SYS_getpgrp (111)
            0x0f, 0x05,                     // syscall
            0x48, 0x83, 0xf8, expected_pgid, // cmp rax, expected_pgid
            0x75, 0x19,                     // jne failure
            0x31, 0xff,                     // xor edi, edi (current process group)
            0x31, 0xf6,                     // xor esi, esi (signal 0 probe)
            0xb8, 0x3e, 0x00, 0x00, 0x00,   // mov eax, SYS_kill (62)
            0x0f, 0x05,                     // syscall
            0x48, 0x85, 0xc0,               // test rax, rax
            0x75, 0x09,                     // jne failure
            0xb8, 0xe7, 0x00, 0x00, 0x00,   // mov eax, SYS_exit_group (231)
            0x31, 0xff,                     // xor edi, edi
            0x0f, 0x05,                     // syscall  (exit_group(0))
            0xb8, 0xe7, 0x00, 0x00, 0x00,   // failure: mov eax, SYS_exit_group
            0xbf, 0x2a, 0x00, 0x00, 0x00,   // mov edi, 42
            0x0f, 0x05,                     // syscall  (exit_group(42))
            0x0f, 0x0b,                     // ud2
        ]
    }

    // Conventional root guest: detcore ROOT_DETPID == 3 => getppid() == 1.
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&getppid_probe(1)), "/bin/true")
        .unwrap();
    backend.set_root_pid(3).unwrap();
    assert_eq!(
        backend.run_static_elf().unwrap(),
        0,
        "root guest pid=3 must report getppid()==1 in the PID namespace"
    );

    for set_before_install in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        if set_before_install {
            backend.set_root_pid(3).unwrap();
        }
        backend
            .install_static_elf(&static_elf(&getpgrp_probe(3)), "/bin/true")
            .unwrap();
        if !set_before_install {
            backend.set_root_pid(3).unwrap();
        }
        assert_eq!(
            backend.run_static_elf().unwrap(),
            0,
            "root guest pid=3 must report getpgrp()==3 and make kill(0,0) find its group when \
             set_root_pid runs {} install",
            if set_before_install {
                "before"
            } else {
                "after"
            },
        );
    }

    // Namespace init edge case: a guest that is itself PID 1 has no parent.
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&getppid_probe(0)), "/bin/true")
        .unwrap();
    // Default root_pid is already 1; set it explicitly to document intent.
    backend.set_root_pid(1).unwrap();
    assert_eq!(
        backend.run_static_elf().unwrap(),
        0,
        "namespace-init guest pid=1 must report getppid()==0"
    );
}

fn run_stats_program(code: &[u8], name: &str, request: BackendStatsRequest) -> KvmBackendStats {
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend.set_backend_stats_request(request);
    backend.install_static_elf(&static_elf(code), name).unwrap();
    let (_, exit_code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();
    assert_eq!(exit_code, 0, "{name}");
    assert!(stdout.is_empty(), "{name}");
    assert!(stderr.is_empty(), "{name}");

    let snapshot = backend.backend_stats();
    assert_eq!(
        request.collect(&backend),
        request.is_enabled().then(|| snapshot.clone()),
        "{name} request and snapshot source must agree"
    );
    snapshot
}

fn stats_root_program() -> Vec<u8> {
    vec![
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]
}

fn patch_stats_jump(code: &mut [u8], operand: usize, target: usize) {
    let displacement = i32::try_from(target as isize - (operand + 4) as isize).unwrap();
    code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
}

fn append_stats_exit(code: &mut Vec<u8>, group: bool) {
    let number = if group {
        libc::SYS_exit_group
    } else {
        libc::SYS_exit
    };
    code.push(0xb8); // mov eax, SYS_exit[_group]
    code.extend_from_slice(&(number as u32).to_le_bytes());
    code.extend_from_slice(&[
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);
}

fn stats_fork_program() -> Vec<u8> {
    let mut code = vec![
        0xb8, 0x39, 0x00, 0x00, 0x00, // mov eax, SYS_fork
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x0f, 0x84, 0, 0, 0, 0, // jz child
    ];
    let child_jump = code.len() - 4;

    code.extend_from_slice(&[
        0x89, 0xc7, // mov edi, eax
        0x48, 0x83, 0xec, 0x10, // sub rsp, 16
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x31, 0xd2, // xor edx, edx
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0x3d, 0x00, 0x00, 0x00, // mov eax, SYS_wait4
        0x0f, 0x05, // syscall
    ]);
    append_stats_exit(&mut code, true);

    let child = code.len();
    patch_stats_jump(&mut code, child_jump, child);
    code.extend_from_slice(&[
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
    ]);
    append_stats_exit(&mut code, true);
    code
}

fn clone_thread_program(probe_tool_stacks: bool) -> Vec<u8> {
    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_STACK: u64 = LOAD_ADDRESS + 0x1900;
    const CHILD_STACK_SIZE: u64 = 0x600;

    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_SYSVSEM as u64
        | libc::CLONE_CHILD_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64;

    let mut code = vec![0x48, 0xb9]; // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[
        0xc7, 0x01, 0xff, 0xff, 0xff, 0x7f, // mov dword ptr [rcx], 0x7fffffff
        0xb8, 0xb3, 0x01, 0x00, 0x00, // mov eax, SYS_clone3
        0x48, 0xbf, // movabs rdi, clone_args
    ]);
    let clone_args_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.extend_from_slice(&[
        0xbe, 0x58, 0x00, 0x00, 0x00, // mov esi, sizeof(clone_args)
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x0f, 0x84, 0, 0, 0, 0, // jz child
    ]);
    let child_jump = code.len() - 4;

    if probe_tool_stacks {
        code.extend_from_slice(&[
            0xb8, 0x6e, 0x00, 0x00, 0x00, // mov eax, SYS_getppid
            0x0f, 0x05, // syscall
        ]);
    }
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    let wait = code.len();
    code.extend_from_slice(&[
        0x83, 0x39, 0x00, // cmp dword ptr [rcx], 0
        0x0f, 0x85, 0, 0, 0, 0, // jne wait
    ]);
    let wait_jump = code.len() - 4;
    patch_stats_jump(&mut code, wait_jump, wait);
    append_stats_exit(&mut code, true);

    let child = code.len();
    patch_stats_jump(&mut code, child_jump, child);
    if probe_tool_stacks {
        code.extend_from_slice(&[
            0xb8, 0x6e, 0x00, 0x00, 0x00, // mov eax, SYS_getppid
            0x0f, 0x05, // syscall
        ]);
    }
    code.extend_from_slice(&[
        0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, SYS_gettid
        0x0f, 0x05, // syscall
    ]);
    append_stats_exit(&mut code, false);

    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let clone_args_address = LOAD_ADDRESS + code.len() as u64;
    // The branch target is patched before the trailing clone arguments are
    // appended, so the optional parent/child probes cannot make it point into
    // the data block.
    code[clone_args_operand..clone_args_operand + 8]
        .copy_from_slice(&clone_args_address.to_le_bytes());
    let mut clone_args = [0_u8; 88];
    clone_args[0..8].copy_from_slice(&flags.to_le_bytes());
    clone_args[16..24].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
    clone_args[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
    code.extend_from_slice(&clone_args);
    code
}

fn assert_exact_stats(snapshot: &KvmBackendStats, hypercalls: u64, halts: u64) {
    assert_eq!(snapshot.count(KvmExitReason::Hypercall), hypercalls);
    assert_eq!(snapshot.count(KvmExitReason::Hlt), halts);
    assert_eq!(snapshot.total_exits(), hypercalls + halts, "{snapshot}");
}

#[test]
fn kvm_stats_disabled_run_records_no_exits() {
    if !kvm_available("kvm_stats_disabled_run_records_no_exits") {
        return;
    }

    let snapshot = run_stats_program(
        &stats_root_program(),
        "/bin/kvm-stats-disabled",
        BackendStatsRequest::DISABLED,
    );
    assert_exact_stats(&snapshot, 0, 0);
}

#[test]
fn kvm_stats_root_production_loop_is_exact_and_repeatable() {
    if !kvm_available("kvm_stats_root_production_loop_is_exact_and_repeatable") {
        return;
    }

    let first = run_stats_program(
        &stats_root_program(),
        "/bin/kvm-stats-root",
        BackendStatsRequest::ENABLED,
    );
    let second = run_stats_program(
        &stats_root_program(),
        "/bin/kvm-stats-root",
        BackendStatsRequest::ENABLED,
    );
    assert_exact_stats(&first, 2, 0);
    assert_eq!(first, second);
}

#[test]
fn kvm_stats_fork_process_tree_is_exact_and_repeatable() {
    if !kvm_available("kvm_stats_fork_process_tree_is_exact_and_repeatable") {
        return;
    }

    let first = run_stats_program(
        &stats_fork_program(),
        "/bin/kvm-stats-fork",
        BackendStatsRequest::ENABLED,
    );
    let second = run_stats_program(
        &stats_fork_program(),
        "/bin/kvm-stats-fork",
        BackendStatsRequest::ENABLED,
    );
    // Root: fork + wait4 + exit_group. Child: getpid + exit_group.
    assert_exact_stats(&first, 5, 1);
    assert_eq!(first, second);
}

#[test]
fn kvm_stats_clone_thread_process_tree_is_exact_and_repeatable() {
    if !kvm_available("kvm_stats_clone_thread_process_tree_is_exact_and_repeatable") {
        return;
    }

    let first = run_stats_program(
        &clone_thread_program(false),
        "/bin/kvm-stats-thread",
        BackendStatsRequest::ENABLED,
    );
    let second = run_stats_program(
        &clone_thread_program(false),
        "/bin/kvm-stats-thread",
        BackendStatsRequest::ENABLED,
    );
    // Root: clone3 + exit_group. Child: gettid + exit. The parent waits in
    // guest memory for CLONE_CHILD_CLEARTID, so the child exit is counted first.
    assert_exact_stats(&first, 4, 1);
    assert_eq!(first, second);
}

#[test]
fn tool_owned_threads_keep_independent_stack_guards_live() {
    if !kvm_available("tool_owned_threads_keep_independent_stack_guards_live") {
        return;
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(
            &static_elf(&clone_thread_program(true)),
            "/bin/tool-stack-threads",
        )
        .unwrap();
    let (log, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<ConcurrentToolStackTool>((), true),
    )
    .unwrap();

    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    let tids = log.tids();
    assert_eq!(tids.len(), 2);
    assert_ne!(tids[0], tids[1]);
}

#[test]
fn worker_exec_is_refused_without_replacing_shared_memory() {
    if !kvm_available("worker_exec_is_refused_without_replacing_shared_memory") {
        return;
    }

    let target = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let executable = TestExecutable::new(&static_elf(&target));
    for execveat in [false, true] {
        check_worker_exec_preserves_shared_memory(&executable.0, None, execveat, libc::ENOSYS);
    }
}

#[test]
fn worker_exec_preflight_errors_preserve_shared_memory() {
    if !kvm_available("worker_exec_preflight_errors_preserve_shared_memory") {
        return;
    }

    let executable = TestExecutable::new(&static_elf(&[0x0f, 0x0b]));
    let malformed = TestExecutable::new(b"not an ELF image");
    let missing = executable.0.with_extension("missing");
    assert!(!missing.exists());
    for execveat in [false, true] {
        for index in 0..3 {
            check_worker_exec_preserves_shared_memory(
                &executable.0,
                Some(index),
                execveat,
                libc::EFAULT,
            );
        }
        check_worker_exec_preserves_shared_memory(&missing, None, execveat, libc::ENOENT);
        check_worker_exec_preserves_shared_memory(&malformed.0, None, execveat, libc::ENOEXEC);
    }
}

fn check_worker_exec_preserves_shared_memory(
    path: &std::path::Path,
    invalid_argument: Option<usize>,
    execveat: bool,
    expected_errno: i32,
) {
    eprintln!(
        "execveat={execveat} invalid_argument={invalid_argument:?} expected_errno={expected_errno}"
    );
    let path = path.to_str().unwrap().as_bytes();

    let mut code = clone_thread_program(true);
    let path_address = LOAD_ADDRESS + code.len() as u64;
    code.extend_from_slice(path);
    code.push(0);
    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let argv_address = LOAD_ADDRESS + code.len() as u64;
    code.extend_from_slice(&path_address.to_le_bytes());
    code.extend_from_slice(&0_u64.to_le_bytes());
    let envp_address = LOAD_ADDRESS + code.len() as u64;
    code.extend_from_slice(&0_u64.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(
            &static_elf(&code),
            "/bin/worker-exec-preserves-shared-memory",
        )
        .unwrap();
    let mut pointers = [
        path_address as usize,
        argv_address as usize,
        envp_address as usize,
    ];
    if let Some(index) = invalid_argument {
        pointers[index] = MEMORY_SIZE + 0x1000;
    }
    let [path, argv, envp] = pointers;
    let config = (path, argv, envp, execveat, expected_errno);
    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<WorkerExecOverlapTool>(config, true),
    )
    .unwrap();

    eprintln!(
        "worker_errno={:?} exit_code={exit_code}",
        log.worker_errno()
    );
    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(log.worker_errno(), Some(expected_errno));
    assert!(log.root_value_preserved());
}

#[test]
fn static_elf_executes_avx_instruction() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM AVX test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // The host dynamic linker uses this vmovq encoding unconditionally. KVM's
    // userspace-only guest must initialize OSXSAVE and the YMM register state
    // that a Linux kernel would normally configure before entering userspace.
    let code = [
        0x31, 0xff, // xor edi, edi
        0xc4, 0xe1, 0xf9, 0x6e, 0xcf, // vmovq rdi, xmm1
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/avx-probe")
        .unwrap();

    assert_eq!(backend.run_static_elf().unwrap(), 0);
}

#[test]
fn dynamic_c_guest_observes_indexed_xstate_cpuid_and_lazy_binding() {
    if !kvm_available("dynamic_c_guest_observes_indexed_xstate_cpuid_and_lazy_binding") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program_with_args(
        &directory.0,
        "indexed-xstate-cpuid",
        r#"
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>

struct registers {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
};

static struct registers cpuid_xstate(uint32_t subleaf) {
  struct registers result;
  __cpuid_count(0xd, subleaf, result.eax, result.ebx, result.ecx, result.edx);
  return result;
}

static int matches(struct registers actual, struct registers expected) {
  return actual.eax == expected.eax && actual.ebx == expected.ebx &&
         actual.ecx == expected.ecx && actual.edx == expected.edx;
}

int main(void) {
  struct registers xstate = cpuid_xstate(0);
  /* KVM recomputes subleaf 0 EBX from XCR0 and the host-supported component
     layout. With x87, SSE, and AVX enabled, the guest-visible size is 0x340. */
  if (xstate.eax != 0x00000007 || xstate.ebx != 0x00000340 ||
      xstate.ecx != 0x00000340 || xstate.edx != 0) {
    return 10;
  }

  static const struct {
    uint32_t subleaf;
    struct registers expected;
  } cases[] = {
      {1, {0, 0, 0, 0}},
      {2, {0x00000100, 0x00000240, 0, 0}},
      {17, {0, 0, 0, 0}},
      {18, {0, 0, 0, 0}},
      {19, {0, 0, 0, 0}},
  };

  for (uint32_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    if (!matches(cpuid_xstate(cases[i].subleaf), cases[i].expected)) {
      return 11 + (int)i;
    }
  }

  /* The executable is linked for lazy binding, so this first puts call makes
     the dynamic linker resolve its PLT entry after all CPUID checks pass. */
  if (puts("indexed xstate cpuid ok") < 0) {
    return 20;
  }
  return 0;
}
"#,
        &["-fno-builtin", "-Wl,-z,lazy"],
    );
    let image = std::fs::read(&executable).unwrap();
    let elf = goblin::elf::Elf::parse(&image).unwrap();
    assert!(elf.interpreter.is_some(), "test guest must be dynamic");
    let dynamic = elf
        .dynamic
        .as_ref()
        .expect("test guest must have a dynamic section");
    assert!(
        dynamic
            .dyns
            .iter()
            .all(|entry| entry.d_tag != goblin::elf::dynamic::DT_BIND_NOW),
        "test guest must not contain DT_BIND_NOW"
    );
    assert_eq!(
        dynamic.info.flags & goblin::elf::dynamic::DF_BIND_NOW,
        0,
        "test guest must not contain DF_BIND_NOW"
    );
    assert_eq!(
        dynamic.info.flags_1 & goblin::elf::dynamic::DF_1_NOW,
        0,
        "test guest must not contain DF_1_NOW"
    );
    assert!(
        elf.pltrelocs.iter().any(|relocation| {
            elf.dynsyms
                .get(relocation.r_sym)
                .and_then(|symbol| elf.dynstrtab.get_at(symbol.st_name))
                == Some("puts")
        }),
        "test guest must call puts through a PLT relocation"
    );

    let executable = executable.to_str().unwrap();
    let (stdout, stderr) = run_host_program_captured(executable, &[executable], &directory.0);
    assert_eq!(stdout, b"indexed xstate cpuid ok\n");
    assert!(stderr.is_empty());
}

#[test]
fn static_elf_receives_argv_and_envp() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM argv/envp test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // exit_group(42): the failure path taken by every self-check below. Exactly
    // 12 bytes, so each conditional jump that skips it uses rel8 = 0x0c.
    const FAIL: [u8; 12] = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, // syscall
    ];

    // The guest verifies the System V initial stack that the loader built for
    // argv = ["prog", "second"], envp = ["FOO=bar"]:
    //   [rsp+0]=argc [rsp+8]=argv0 [rsp+16]=argv1 [rsp+24]=NULL
    //   [rsp+32]=envp0 [rsp+40]=NULL
    // Any mismatch takes exit_group(42); success prints and exit_group(0).
    let message = b"hello from kvm m1\n";
    let mut code: Vec<u8> = Vec::new();
    // argc == 2
    code.extend_from_slice(&[0x48, 0x83, 0x3c, 0x24, 0x02, 0x74, 0x0c]); // cmp qword[rsp],2; je +12
    code.extend_from_slice(&FAIL);
    // argv[1] != 0
    code.extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, 0x10, 0x48, 0x85, 0xc0, 0x75, 0x0c]); // mov rax,[rsp+16]; test; jne +12
    code.extend_from_slice(&FAIL);
    // envp[0] != 0
    code.extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, 0x20, 0x48, 0x85, 0xc0, 0x75, 0x0c]); // mov rax,[rsp+32]; test; jne +12
    code.extend_from_slice(&FAIL);
    // envp[1] == 0 (single environment entry, then the NULL terminator)
    code.extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, 0x28, 0x48, 0x85, 0xc0, 0x74, 0x0c]); // mov rax,[rsp+40]; test; je +12
    code.extend_from_slice(&FAIL);
    // write(1, message, message.len())
    code.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
    let movabs_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, <message vaddr>
    code.push(0xba);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax,SYS_write; syscall
    // exit_group(0)
    code.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ]); // mov eax,231; xor edi,edi; syscall; ud2
    let message_offset = code.len();
    code.extend_from_slice(message);
    let message_vaddr = LOAD_ADDRESS + message_offset as u64;
    code[movabs_operand..movabs_operand + 8].copy_from_slice(&message_vaddr.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog", "second"], &["FOO=bar"])
        .unwrap();

    assert_eq!(backend.run_static_elf().unwrap(), 0);
}

#[test]
fn tool_receives_post_exec_with_guest_auxv() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM post-exec test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog"], &[])
        .unwrap();

    let (log, exit_code, _, _) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<PostExecTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 0);
    assert_eq!(log.calls(), 1);
    let address = log
        .at_random()
        .expect("post-exec hook did not observe AT_RANDOM");
    let mut random = [0; 16];
    backend
        .memory()
        .unwrap()
        .read(address as u64, &mut random)
        .unwrap();
    assert_eq!(random, POST_EXEC_RANDOM);
}

#[test]
fn lifecycle_callbacks_refuse_deferred_signal_without_a_syscall_frame() {
    if !kvm_available("lifecycle signal-boundary test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "lifecycle-signal-boundaries",
        r#"
#include <pthread.h>

static void *worker(void *argument) {
  return argument;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) return 10;
  if (pthread_join(thread, 0) != 0) return 11;
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    backend.set_thread_ownership(ThreadOwnership::Tool);

    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<LifecycleSignalTool>((), true),
    )
    .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        *log.callbacks
            .lock()
            .expect("lifecycle signal log lock poisoned"),
        vec![1, 2, 1],
        "root start, initial post-exec, and clone child start refuse both structured deferral and \
         injected self-signals without a return frame",
    );
}

#[test]
fn post_exec_unmask_refuses_preserved_pending_signals_before_entry() {
    if !kvm_available("post-exec pending-signal preflight test") {
        return;
    }

    let directory = TestDirectory::new();
    let target = compile_c_program(
        &directory.0,
        "post-exec-pending-target",
        r#"
#include <unistd.h>
int main(void) {
  if (write(STDOUT_FILENO, "ENTRY", 5) != 5) return 30;
  return 31;
}
"#,
    );
    let launcher = compile_c_program(
        &directory.0,
        "post-exec-pending-launcher",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) return 20;
  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &blocked, 0) != 0) return 21;
  int queued = strcmp(argv[2], "process") == 0
      ? kill(getpid(), SIGUSR1)
      : (int)syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
  if (queued != 0) return 22;
  execl(argv[1], argv[1], (char *)0);
  return 23;
}
"#,
    );
    let launcher = launcher.to_str().unwrap();
    let target = target.to_str().unwrap();
    let image = std::fs::read(launcher).unwrap();

    for (scope, recursive, expected_callbacks) in [
        ("process", false, 2),
        ("thread", false, 2),
        ("process", true, 3),
        ("thread", true, 3),
    ] {
        POST_EXEC_UNMASK_CALLBACKS.store(0, Ordering::SeqCst);
        POST_EXEC_ENTRY_WRITES.store(0, Ordering::SeqCst);
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[launcher, target, scope],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let error =
            futures::executor::block_on(backend.run_static_elf_with_tool::<PostExecPendingTool>(
                (recursive, target.to_owned()),
                true,
            ))
            .expect_err("eligible post-exec signal must stop before running the new image");
        // Shared ownership preserves the same failure. Additional worker or
        // cleanup errors must still fail this exact-cause assertion.
        let cause = match &error {
            Error::SharedFailure(cause) => cause.as_ref(),
            cause => cause,
        };
        assert!(
            matches!(cause, Error::PostExec(Errno::ENOSYS)),
            "scope={scope}, recursive={recursive}, error={error}",
        );
        assert_eq!(
            POST_EXEC_UNMASK_CALLBACKS.load(Ordering::SeqCst),
            expected_callbacks,
            "scope={scope}, recursive={recursive}",
        );
        assert_eq!(
            POST_EXEC_ENTRY_WRITES.load(Ordering::SeqCst),
            0,
            "new image reached its entry write before signal handling; scope={scope}, recursive={recursive}",
        );
    }
}

#[test]
fn canonical_initial_execveat_does_not_reload_installed_image() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM canonical initial exec test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let image = static_elf(&code);
    let executable = TestExecutable::new(&image);
    let executable = executable.0.to_str().unwrap();
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend.install_static_elf(&image, executable).unwrap();

    // A second exec of the same file clears the loaded segment before
    // reloading it. This address is in mapped BSS but outside the file-backed
    // bytes, so it distinguishes forwarding the synthetic initial exec from a
    // real reload.
    const SENTINEL_ADDRESS: u64 = LOAD_ADDRESS + 0x1000;
    const SENTINEL: [u8; 16] = *b"initial-exec-ok!";
    backend
        .memory_mut()
        .unwrap()
        .write(SENTINEL_ADDRESS, &SENTINEL)
        .unwrap();

    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<CanonicalInitialExecTool>((), true),
    )
    .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(log.calls(), 1);
    let mut observed = [0; SENTINEL.len()];
    backend
        .memory()
        .unwrap()
        .read(SENTINEL_ADDRESS, &mut observed)
        .unwrap();
    assert_eq!(observed, SENTINEL);
}

#[test]
fn successful_exec_discards_bytes_outside_replacement_image() {
    if !kvm_available("KVM exec page-discard test") {
        return;
    }

    const SENTINEL_ADDRESS: u64 = LOAD_ADDRESS + 0x1800;
    const SENTINEL: [u8; 16] = *b"old-image-bytes!";

    // Load the replacement at a disjoint address so its segment loader cannot
    // overwrite the sentinel. The replacement directly reads the old image's
    // page through KVM's user identity map and requires the discard to make it
    // demand-zero.
    let mut target = vec![0x48, 0xb8]; // movabs rax, SENTINEL_ADDRESS
    target.extend_from_slice(&SENTINEL_ADDRESS.to_le_bytes());
    target.extend_from_slice(&[
        0x80, 0x38, 0x00, // cmp byte ptr [rax], 0
        0x75, 0x0b, // jne stale_memory
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
        0xb8, 0xe7, 0x00, 0x00, 0x00, // stale_memory: mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);
    let executable = TestExecutable::new(&static_elf_at(&target, LOAD_ADDRESS + 0x4000));
    let path = executable.0.to_str().unwrap().as_bytes();

    let mut root = Vec::new();
    let path_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, path
    let argv_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, argv
    let envp_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdx, envp
    root.extend_from_slice(&[
        0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, // execve
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x4d, 0x00, 0x00, 0x00, // mov edi, 77
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);
    let path_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(path);
    root.push(0);
    while !root.len().is_multiple_of(8) {
        root.push(0);
    }
    let argv_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&path_address.to_le_bytes());
    root.extend_from_slice(&0_u64.to_le_bytes());
    let envp_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&0_u64.to_le_bytes());
    root[path_operand..path_operand + 8].copy_from_slice(&path_address.to_le_bytes());
    root[argv_operand..argv_operand + 8].copy_from_slice(&argv_address.to_le_bytes());
    root[envp_operand..envp_operand + 8].copy_from_slice(&envp_address.to_le_bytes());

    for with_tool in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&root), "/bin/memory-replacement-test")
            .unwrap();
        backend
            .memory_mut()
            .unwrap()
            .write(SENTINEL_ADDRESS, &SENTINEL)
            .unwrap();
        let (exit_code, stdout, stderr) = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (exit_code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };

        assert_eq!(exit_code, 0, "with_tool={with_tool}");
        assert!(stdout.is_empty(), "with_tool={with_tool}");
        assert!(stderr.is_empty(), "with_tool={with_tool}");
    }
}

#[test]
fn tool_receives_post_exec_after_root_execve() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM post-exec replacement test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let target = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let executable = TestExecutable::new(&static_elf(&target));
    let path = executable.0.to_str().unwrap().as_bytes();

    let mut root = Vec::new();
    let path_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, path
    let argv_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, argv
    let envp_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdx, envp
    root.extend_from_slice(&[
        0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, // execve
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0xbf, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x0f,
        0x0b, // exit_group(42); ud2
    ]);

    let path_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(path);
    root.push(0);
    while !root.len().is_multiple_of(8) {
        root.push(0);
    }
    let argv_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&path_address.to_le_bytes());
    root.extend_from_slice(&0_u64.to_le_bytes());
    let envp_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&0_u64.to_le_bytes());
    root[path_operand..path_operand + 8].copy_from_slice(&path_address.to_le_bytes());
    root[argv_operand..argv_operand + 8].copy_from_slice(&argv_address.to_le_bytes());
    root[envp_operand..envp_operand + 8].copy_from_slice(&envp_address.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&root), "/bin/root-exec-test")
        .unwrap();

    let (log, exit_code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<PostExecTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(log.calls(), 2);
    let address = log
        .at_random()
        .expect("replacement post-exec hook did not observe AT_RANDOM");
    let mut random = [0; POST_EXEC_RANDOM.len()];
    backend
        .memory()
        .unwrap()
        .read(address as u64, &mut random)
        .unwrap();
    assert_eq!(random, POST_EXEC_RANDOM);
}

#[test]
fn tool_executes_from_thread_start_before_initial_entry() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM thread-start exec test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let target = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let executable = TestExecutable::new(&static_elf(&target));
    let path = executable.0.to_str().unwrap().as_bytes();

    let mut root = vec![
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let path_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(path);
    root.push(0);
    while !root.len().is_multiple_of(8) {
        root.push(0);
    }
    let argv_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&path_address.to_le_bytes());
    root.extend_from_slice(&0_u64.to_le_bytes());
    let envp_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&0_u64.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&root), "/bin/thread-start-exec-test")
        .unwrap();
    let config = (
        path_address as usize,
        argv_address as usize,
        envp_address as usize,
    );
    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<StartExecTool>(config, true),
    )
    .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(log.post_exec_calls(), 1);
}

#[test]
fn regular_injected_forks_complete_before_return() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM regular fork injection test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xb8, 0x39, 0x00, 0x00, 0x00, // mov eax, SYS_fork
        0x0f, 0x05, // syscall
        0x89, 0xc7, // mov edi, eax
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/double-injected-fork-test")
        .unwrap();

    let (_, exit_code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<DoubleForkTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn malformed_exec_is_rejected_during_preflight_without_resetting_image() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM malformed exec test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // This guest-visible ENOEXEC is decided by ElfExecutor's isolated
    // preflight, before exec_process reaches its fatal point of no return.
    let executable = TestExecutable::new(b"not an ELF image");
    let path = executable.0.to_str().unwrap().as_bytes();
    let mut root = Vec::new();
    let path_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, path
    let argv_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, argv
    let envp_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdx, envp
    root.extend_from_slice(&[
        0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, // execve
        0xf7, 0xd8, // neg eax
        0x89, 0xc7, // mov edi, eax
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05, // exit_group(errno)
        0x0f, 0x0b, // ud2
    ]);
    let path_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(path);
    root.push(0);
    while !root.len().is_multiple_of(8) {
        root.push(0);
    }
    let argv_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&path_address.to_le_bytes());
    root.extend_from_slice(&0_u64.to_le_bytes());
    let envp_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&0_u64.to_le_bytes());
    root[path_operand..path_operand + 8].copy_from_slice(&path_address.to_le_bytes());
    root[argv_operand..argv_operand + 8].copy_from_slice(&argv_address.to_le_bytes());
    root[envp_operand..envp_operand + 8].copy_from_slice(&envp_address.to_le_bytes());

    for with_tool in [false, true] {
        const SENTINEL_ADDRESS: u64 = LOAD_ADDRESS + 0x1800;
        const SENTINEL: [u8; 16] = *b"failed-exec-kept";
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&root), "/bin/malformed-exec-test")
            .unwrap();
        backend
            .memory_mut()
            .unwrap()
            .write(SENTINEL_ADDRESS, &SENTINEL)
            .unwrap();
        let original_memory = backend.memory().unwrap().clone();
        let (exit_code, stdout, stderr) = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (exit_code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(exit_code, libc::ENOEXEC, "with_tool={with_tool}");
        assert!(stdout.is_empty(), "with_tool={with_tool}");
        assert!(stderr.is_empty(), "with_tool={with_tool}");
        let mut observed = [0; SENTINEL.len()];
        backend
            .memory()
            .unwrap()
            .read(SENTINEL_ADDRESS, &mut observed)
            .unwrap();
        assert_eq!(observed, SENTINEL, "with_tool={with_tool}");
        original_memory
            .read(SENTINEL_ADDRESS, &mut observed)
            .unwrap();
        assert_eq!(observed, SENTINEL, "with_tool={with_tool}");
    }
}

#[test]
fn post_exec_failure_runs_tool_exit_lifecycle() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM post-exec failure test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    POST_EXEC_FAILURE_EXITED.store(false, Ordering::SeqCst);
    let code = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog"], &[])
        .unwrap();

    let error = futures::executor::block_on(
        backend.run_static_elf_with_tool::<FailingPostExecTool>((), true),
    )
    .unwrap_err();

    assert!(error.to_string().contains("post-exec hook failed"));
    assert!(POST_EXEC_FAILURE_EXITED.load(Ordering::SeqCst));
}

#[test]
fn strace_tool_logs_syscalls_from_static_elf() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM strace-ELF test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // A static ELF guest that issues getpid, write(1, "hi\n", 3), exit_group(0)
    // via real SYSCALL instructions. Each traps through the ring0 trampoline and
    // must be observed by StraceTool, whose tail_inject is serviced by the ELF
    // guest kernel (so getpid returns 1, the write prints, and exit_group ends
    // the run). The synthetic initial exec is delivered too, but this test tool
    // records only after injection and successful exec does not return.
    let message = b"hi\n";
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax,SYS_getpid; syscall
    code.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
    let movabs_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, <message vaddr>
    code.push(0xba);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax,SYS_write; syscall
    code.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ]); // mov eax,SYS_exit_group; xor edi,edi; syscall; ud2
    let message_offset = code.len();
    code.extend_from_slice(message);
    let message_vaddr = LOAD_ADDRESS + message_offset as u64;
    code[movabs_operand..movabs_operand + 8].copy_from_slice(&message_vaddr.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog"], &[])
        .unwrap();

    let (log, exit_code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 0);
    assert_eq!(stdout, b"hi\n");
    assert!(stderr.is_empty());
    assert_eq!(
        log.syscalls(),
        vec![
            "getpid".to_string(),
            "write".to_string(),
            "exit_group".to_string(),
        ],
    );
}

#[test]
fn tool_rpc_response_reaches_intercepted_static_elf_syscall() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM RPC round-trip test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // Each getpid is intercepted instead of injected. The local tool advances
    // its ThreadState, sends the ordinal to GlobalState, and returns the typed
    // RPC response as the guest-visible syscall result. The exit hook then
    // sends a third typed RPC through the lifecycle GlobalRPC handle. Exit 1
    // if either guest-visible round trip produced an unexpected value.
    let code = [
        0x45, 0x31, 0xe4, // xor r12d, r12d
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0x3d, 0xe9, 0x03, 0x00, 0x00, // cmp eax, 1001
        0x41, 0x0f, 0x95, 0xc4, // setne r12b
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0x3d, 0xea, 0x03, 0x00, 0x00, // cmp eax, 1002
        0x0f, 0x95, 0xc0, // setne al
        0x0f, 0xb6, 0xc0, // movzx eax, al
        0x41, 0x09, 0xc4, // or r12d, eax
        0x44, 0x89, 0xe7, // mov edi, r12d
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/rpc-round-trip")
        .unwrap();

    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<RpcRoundTripTool>(1000, true),
    )
    .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        log.requests(),
        vec![
            (Pid::from_raw(1), 1),
            (Pid::from_raw(1), 2),
            (Pid::from_raw(1), 3),
        ]
    );
}

#[test]
fn counter_tools_aggregate_intercepted_static_elf_syscalls() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM counter-ELF test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, // getpid
        0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, // getpid
        0xb8, 0xe7, 0x00, 0x00, 0x00, // exit_group
        0x31, 0xff, 0x0f, 0x05, // status 0; syscall
        0x0f, 0x0b, // ud2
    ];
    let image = static_elf(&code);

    let mut direct_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    direct_backend
        .install_static_elf(&image, "/bin/counter-rpc")
        .unwrap();
    let (counter, exit_code, stdout, stderr) = futures::executor::block_on(
        direct_backend.run_static_elf_with_tool::<CounterTool>((), true),
    )
    .unwrap();
    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(counter.total(), 4);

    let mut hierarchical_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    hierarchical_backend
        .install_static_elf(&image, "/bin/hierarchical-counter-rpc")
        .unwrap();
    let (counter, exit_code, stdout, stderr) = futures::executor::block_on(
        hierarchical_backend.run_static_elf_with_tool::<HierarchicalCounterTool>((), true),
    )
    .unwrap();
    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        counter.totals(),
        HierarchicalTotals {
            total_syscalls: 4,
            exited_procs: 1,
            exited_threads: 1,
        }
    );
}

#[test]
fn real_make_runs_a_shell_recipe_through_clone3_vfork() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM make test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
    let root = TestDirectory::new();
    std::fs::write(
        root.0.join("Makefile"),
        "all: result.txt\nresult.txt:\n\tprintf 'make:42\\n' > result.txt\n",
    )
    .unwrap();
    run_host_program("/usr/bin/make", &["make", "-s"], &root.0);
    assert_eq!(
        std::fs::read(root.0.join("result.txt")).unwrap(),
        b"make:42\n"
    );
}

#[test]
fn real_gcc_compiles_an_object_through_child_processes() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM gcc test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
    let root = TestDirectory::new();
    std::fs::write(
        root.0.join("fixture.c"),
        b"int hermit_compat(void) { return 42; }\n",
    )
    .unwrap();
    run_host_program(
        "/usr/bin/gcc",
        &[
            "gcc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-fno-ident",
            "-frandom-seed=hermit-gcc",
            "-c",
            "fixture.c",
            "-o",
            "fixture.o",
        ],
        &root.0,
    );
    assert!(root.0.join("fixture.o").is_file());
}

#[test]
fn real_gcc_tool_output_matches_native() {
    if !kvm_available("GCC Tool execution and native object comparison") {
        return;
    }
    let root = TestDirectory::new();
    std::fs::write(
        root.0.join("fixture.c"),
        b"int hermit_compat(void) { return 42; }\n",
    )
    .unwrap();
    let args = [
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-fno-ident",
        "-frandom-seed=hermit-gcc",
        "-c",
        "fixture.c",
        "-o",
        "fixture.o",
    ];
    let native = std::process::Command::new("/usr/bin/gcc")
        .args(args)
        .current_dir(&root.0)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(native.status.success(), "native GCC failed: {native:?}");
    let expected = std::fs::read(root.0.join("fixture.o")).unwrap();
    std::fs::remove_file(root.0.join("fixture.o")).unwrap();
    let argv: Vec<_> = std::iter::once("gcc").chain(args).collect();
    let (stdout, stderr) = run_host_program_with_tool_captured("/usr/bin/gcc", &argv, &root.0);
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
    assert_eq!(std::fs::read(root.0.join("fixture.o")).unwrap(), expected);
}

#[test]
fn real_patch_applies_exact_hunk_with_absent_xattrs() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM patch test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    std::fs::write(root.0.join("file"), b"old\n").unwrap();
    std::fs::write(
        root.0.join("change.patch"),
        b"--- file\n+++ file\n@@ -1 +1 @@\n-old\n+new\n",
    )
    .unwrap();
    let (stdout, stderr) = run_host_program_captured(
        "/usr/bin/patch",
        &["patch", "--quiet", "--input=change.patch", "file"],
        &root.0,
    );
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(std::fs::read(root.0.join("file")).unwrap(), b"new\n");
}

#[test]
fn real_grep_uses_synthetic_process_maps_for_stack_discovery() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM grep test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    std::fs::write(root.0.join("payload"), b"gamma\nbeta\nalpha\nbeta\n").unwrap();
    let (stdout, stderr) =
        run_host_program_captured("/usr/bin/grep", &["grep", "beta", "payload"], &root.0);
    assert_eq!(stdout, b"beta\nbeta\n");
    assert!(stderr.is_empty());
}

fn static_elf(code: &[u8]) -> Vec<u8> {
    static_elf_at(code, LOAD_ADDRESS)
}

fn static_elf_at(code: &[u8], load_address: u64) -> Vec<u8> {
    let mut image = vec![0; CODE_OFFSET + code.len()];

    image[..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    put_u16(&mut image, 16, 2);
    put_u16(&mut image, 18, 62);
    put_u32(&mut image, 20, 1);
    put_u64(&mut image, 24, load_address);
    put_u64(&mut image, 32, 64);
    put_u16(&mut image, 52, 64);
    put_u16(&mut image, 54, 56);
    put_u16(&mut image, 56, 1);

    put_u32(&mut image, 64, 1);
    put_u32(&mut image, 68, 5);
    put_u64(&mut image, 72, CODE_OFFSET as u64);
    put_u64(&mut image, 80, load_address);
    put_u64(&mut image, 88, load_address);
    put_u64(&mut image, 96, code.len() as u64);
    put_u64(&mut image, 104, 0x2000);
    put_u64(&mut image, 112, 0x1000);
    image[CODE_OFFSET..].copy_from_slice(code);
    image
}

fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(image: &mut [u8], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn native_and_kvm_prctl_names_keep_worker_local_and_format_procfs_leader_bytes() {
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "pthread-prctl-name",
        r#"
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static const unsigned char leader_name[5] = {0xff, '\n', '\\', 'L', 0};
static const unsigned char stat_name[6] = {'(', 0xff, '\n', '\\', 'L', ')'};
static const unsigned char status_name[13] = {
    'N', 'a', 'm', 'e', ':', '\t', 0xff, '\\', 'n', '\\', '\\', 'L', '\n'
};

static const unsigned char *find_bytes(const unsigned char *haystack, size_t haystack_len,
                                       const unsigned char *needle, size_t needle_len) {
  if (needle_len > haystack_len) return 0;
  for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
    if (memcmp(haystack + i, needle, needle_len) == 0) return haystack + i;
  }
  return 0;
}

static int read_proc(const char *path, unsigned char *buffer, size_t capacity) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  ssize_t count = read(fd, buffer, capacity);
  close(fd);
  return count < 0 ? -1 : (int)count;
}

static void *worker(void *unused) {
  (void)unused;
  unsigned char worker_name[16] = "worker";
  unsigned char observed[16] = {0};
  unsigned char buffer[1024];
  if (prctl(PR_SET_NAME, worker_name) != 0) return (void *)(uintptr_t)1;
  if (prctl(PR_GET_NAME, observed) != 0) return (void *)(uintptr_t)2;
  if (memcmp(observed, worker_name, sizeof(observed)) != 0)
    return (void *)(uintptr_t)3;
  if (write(1, observed, sizeof(observed)) != sizeof(observed))
    return (void *)(uintptr_t)4;

  int count = read_proc("/proc/self/stat", buffer, sizeof(buffer));
  const unsigned char *found = count < 0 ? 0 : find_bytes(
      buffer, (size_t)count, stat_name, sizeof(stat_name));
  if (!found) return (void *)(uintptr_t)5;
  if (write(1, found, sizeof(stat_name)) != sizeof(stat_name))
    return (void *)(uintptr_t)6;

  count = read_proc("/proc/self/status", buffer, sizeof(buffer));
  found = count < 0 ? 0 : find_bytes(
      buffer, (size_t)count, status_name, sizeof(status_name));
  if (!found) return (void *)(uintptr_t)7;
  if (write(1, found, sizeof(status_name)) != sizeof(status_name))
    return (void *)(uintptr_t)8;
  return 0;
}

int main(void) {
  if (prctl(PR_SET_NAME, leader_name) != 0) return 10;
  pthread_t thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) return 11;
  void *result = 0;
  if (pthread_join(thread, &result) != 0) return 12;
  if (result != 0) return 20 + (int)(uintptr_t)result;

  unsigned char observed[16] = {0};
  if (prctl(PR_GET_NAME, observed) != 0) return 13;
  if (memcmp(observed, leader_name, sizeof(leader_name)) != 0) return 14;
  if (write(1, observed, sizeof(observed)) != sizeof(observed)) return 15;
  return 0;
}
"#,
    );
    let mut expected = b"worker".to_vec();
    expected.resize(16, 0);
    expected.extend_from_slice(&[b'(', 0xff, b'\n', b'\\', b'L', b')']);
    expected.extend_from_slice(b"Name:\t\xff\\n\\\\L\n");
    expected.extend_from_slice(&[0xff, b'\n', b'\\', b'L']);
    expected.resize(51, 0);

    let native = std::process::Command::new(&executable)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "native task-name fixture failed: {native:?}"
    );
    assert_eq!(native.stdout, expected, "native Linux format changed");
    assert!(native.stderr.is_empty());

    if !kvm_available("native_and_kvm_prctl_names_keep_worker_local_and_format_procfs_leader_bytes")
    {
        return;
    }

    let executable = executable.to_str().unwrap();
    let (kvm_stdout, kvm_stderr) =
        run_host_program_captured(executable, &[executable], &directory.0);
    assert_eq!(kvm_stdout, native.stdout, "KVM must match native Linux");
    assert!(kvm_stderr.is_empty());
}

#[test]
fn kvm_direct_and_tool_match_prctl_identity_cell() {
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "prctl-identity",
        r#"
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

int main(void) {
  const char *wanted = "hermit-probe";
  char name[16] = {0};
  int pdeath = -1;

  if (prctl(PR_SET_NAME, wanted, 0, 0, 0) != 0 ||
      prctl(PR_GET_NAME, name, 0, 0, 0) != 0 || strcmp(name, wanted) != 0)
    return 1;
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
    return 2;
  int dumpable_after_clear = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0)
    return 3;
  int dumpable_after_set = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0)
    return 4;
  int keepcaps_after_set = prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
  if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0)
    return 5;
  int keepcaps_after_clear = prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
  if (prctl(PR_GET_PDEATHSIG, &pdeath, 0, 0, 0) != 0)
    return 6;
  if (dumpable_after_clear != 0 || dumpable_after_set != 1 ||
      keepcaps_after_set != 1 || keepcaps_after_clear != 0 || pdeath != 0)
    return 7;

  printf("prctl-identity name=%s dumpable_after_clear=%d dumpable_after_set=%d "
         "keepcaps_after_set=%d keepcaps_after_clear=%d pdeathsig_initial=%d\n",
         name, dumpable_after_clear, dumpable_after_set, keepcaps_after_set,
         keepcaps_after_clear, pdeath);
  return 0;
}
"#,
    );
    let expected = concat!(
        "prctl-identity name=hermit-probe dumpable_after_clear=0 ",
        "dumpable_after_set=1 keepcaps_after_set=1 keepcaps_after_clear=0 ",
        "pdeathsig_initial=0\n",
    )
    .as_bytes();
    let native = std::process::Command::new(&executable)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(native.status.success(), "native fixture failed: {native:?}");
    assert_eq!(native.stdout, expected);
    assert!(native.stderr.is_empty());

    if !kvm_available("kvm_direct_and_tool_match_prctl_identity_cell") {
        return;
    }

    let executable = executable.to_str().unwrap();
    let (direct_stdout, direct_stderr) =
        run_host_program_captured(executable, &[executable], &directory.0);
    assert_eq!(direct_stdout, expected);
    assert!(direct_stderr.is_empty());
    let (tool_stdout, tool_stderr) =
        run_host_program_with_tool_captured(executable, &[executable], &directory.0);
    assert_eq!(tool_stdout, expected);
    assert!(tool_stderr.is_empty());
}

#[test]
fn kvm_direct_and_tool_match_thp_disable_cell() {
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "thp-disable",
        r#"
#include <stdio.h>
#include <sys/prctl.h>

#ifndef PR_SET_THP_DISABLE
#define PR_SET_THP_DISABLE 41
#endif
#ifndef PR_GET_THP_DISABLE
#define PR_GET_THP_DISABLE 42
#endif

int main(void) {
  int set_on = prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0) == 0;
  int get_after_set = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
  int set_off = prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) == 0;
  int get_after_clear = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
  int ok = set_on + (get_after_set == 1) + set_off + (get_after_clear == 0);
  printf("thp ok=%d set_on=%d get_after_set=%d set_off=%d get_after_clear=%d\n",
         ok, set_on, get_after_set, set_off, get_after_clear);
  return ok == 4 ? 0 : 1;
}
"#,
    );
    let expected = b"thp ok=4 set_on=1 get_after_set=1 set_off=1 get_after_clear=0\n";
    let native = std::process::Command::new(&executable)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(native.status.success(), "native fixture failed: {native:?}");
    assert_eq!(native.stdout, expected);
    assert!(native.stderr.is_empty());

    if !kvm_available("kvm_direct_and_tool_match_thp_disable_cell") {
        return;
    }

    let executable = executable.to_str().unwrap();
    let (direct_stdout, direct_stderr) =
        run_host_program_captured(executable, &[executable], &directory.0);
    assert_eq!(direct_stdout, expected);
    assert!(direct_stderr.is_empty());
    let (tool_stdout, tool_stderr) =
        run_host_program_with_tool_captured(executable, &[executable], &directory.0);
    assert_eq!(tool_stdout, expected);
    assert!(tool_stderr.is_empty());
}

/// A LIVE pthread worker exercises the `pid != tid` path end to end.
///
/// ⚠️ THIS IS THE CASE THE REJECTED IMPLEMENTATION COULD NOT SEE. Every earlier
/// signal test ran with `pid == tid`, so validating a thread-directed target
/// against `state.pid` looked correct. Under a real worker it is wrong in both
/// directions at once: the worker's own `tkill(gettid(), 0)` was refused with
/// ESRCH, while a leader-targeted request was evaluated against the worker's
/// state. Signal-zero probes must now succeed for both live identities without
/// mutating either task; nonzero receiver delivery is checked separately.
#[test]
fn real_pthread_worker_signal_probes_use_exact_identity() {
    if !leader_self_exec_bounded("real_pthread_worker_signal_probes_use_exact_identity") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "worker-thread-signal-identity",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <unistd.h>

static atomic_int result;

static void *worker(void *unused) {
  (void)unused;
  pid_t pid = getpid();
  pid_t tid = (pid_t)syscall(SYS_gettid);

  // The premise. If a worker's tid equalled its pid this test would prove
  // nothing, which is exactly how the rejected version passed review's tests.
  if (tid == pid) {
    atomic_store(&result, 20);
    return NULL;
  }
  sigset_t selected, old_mask, before, after, pending;
  sigemptyset(&selected); sigaddset(&selected, SIGUSR1);
  if (pthread_sigmask(SIG_BLOCK, &selected, &old_mask) ||
      pthread_sigmask(SIG_SETMASK, NULL, &before)) return (void *)25;
  // A worker probing ITSELF by tid must succeed.
  if (syscall(SYS_tkill, tid, 0) != 0) {
    atomic_store(&result, 21);
    return NULL;
  }
  // ...and by (tgid, tid).
  if (syscall(SYS_tgkill, pid, tid, 0) != 0) {
    atomic_store(&result, 22);
    return NULL;
  }
  // A live leader is a valid signal-zero target. This must neither enqueue an
  // event in this worker nor change its independent blocked mask.
  if (syscall(SYS_tgkill, pid, pid, 0) != 0) {
    atomic_store(&result, 23);
    return NULL;
  }
  // A non-positive thread id is EINVAL, not ESRCH.
  if (syscall(SYS_tkill, 0, 0) == 0 || errno != EINVAL) {
    atomic_store(&result, 24);
    return NULL;
  }
  errno = 0;
  if (syscall(SYS_tgkill, tid, pid, 0) != -1 || errno != ESRCH) {
    atomic_store(&result, 26); return NULL;
  }
  errno = 0;
  if (syscall(SYS_tkill, INT_MAX, 0) != -1 || errno != ESRCH) {
    atomic_store(&result, 27); return NULL;
  }
  if (pthread_sigmask(SIG_SETMASK, NULL, &after) || sigpending(&pending)) {
    atomic_store(&result, 28); return NULL;
  }
  for (int signal = 1; signal < NSIG; ++signal) {
    if (sigismember(&before, signal) != sigismember(&after, signal) ||
        sigismember(&pending, signal) != 0) {
      atomic_store(&result, 29); return NULL;
    }
  }
  if (pthread_sigmask(SIG_SETMASK, &old_mask, NULL)) {
    atomic_store(&result, 30); return NULL;
  }
  atomic_store(&result, 1);
  return NULL;
}

int main(void) {
  atomic_store(&result, 0);
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0) {
    return 10;
  }
  void *worker_result = NULL;
  if (pthread_join(thread, &worker_result) != 0 || worker_result) {
    return 11;
  }
  sigset_t pending;
  if (sigpending(&pending)) return 12;
  for (int signal = 1; signal < NSIG; ++signal)
    if (sigismember(&pending, signal) != 0) return 13;
  int observed = atomic_load(&result);
  return observed == 1 ? 0 : observed;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let native = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "5s", executable])
        .output()
        .unwrap();
    assert!(native.status.success(), "native probe: {native:?}");
    assert!(native.stdout.is_empty());
    assert!(native.stderr.is_empty());
    for tool_owned in [false, true] {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code, 0,
            "worker identity probe failed: code={code} tool_owned={tool_owned}; \
             20=pid==tid, 21=self tkill refused, 22=self tgkill refused, \
             23=live leader probe refused, 24=tkill(0) not EINVAL, \
             26=wrong TGID accepted, 27=missing TID accepted, 28..30=mask/pending changed"
        );
        assert_eq!(stdout, native.stdout);
        assert_eq!(stderr, native.stderr);
    }
}

#[test]
fn live_sibling_sigignore_invalidates_only_pretransition_pending_signal() {
    if !kvm_available("sibling sigaction generation test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "sibling-sigignore-generation",
        r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>

static _Atomic int phase;
static _Atomic int failure;
static volatile sig_atomic_t handler_calls;

static void fail(int code) {
  int expected = 0;
  atomic_compare_exchange_strong(&failure, &expected, code);
}

static void handler(int signo) {
  if (signo != SIGUSR1) {
    fail(24);
    return;
  }
  ++handler_calls;
}

static int install(void (*disposition)(int)) {
  struct sigaction action = {0};
  action.sa_handler = disposition;
  sigemptyset(&action.sa_mask);
  return sigaction(SIGUSR1, &action, 0);
}

static void *worker(void *unused) {
  (void)unused;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (pthread_sigmask(SIG_BLOCK, &set, 0) != 0) fail(20);

  if (raise(SIGUSR1) != 0) fail(21);
  atomic_store_explicit(&phase, 1, memory_order_release);
  while (atomic_load_explicit(&phase, memory_order_acquire) < 2)
    __asm__ volatile("pause");

  sigset_t pending;
  if (sigpending(&pending) != 0 || sigismember(&pending, SIGUSR1) != 0)
    fail(22);
  atomic_store_explicit(&phase, 3, memory_order_release);
  while (atomic_load_explicit(&phase, memory_order_acquire) < 4)
    __asm__ volatile("pause");

  // Reinstalling a handler must not resurrect the instance that SIG_IGN
  // discarded before this worker's private queue could be reached.
  if (pthread_sigmask(SIG_UNBLOCK, &set, 0) != 0) fail(23);
  if (handler_calls != 0) fail(25);
  handler_calls = 0;
  if (pthread_sigmask(SIG_BLOCK, &set, 0) != 0) fail(26);
  atomic_store_explicit(&phase, 5, memory_order_release);
  while (atomic_load_explicit(&phase, memory_order_acquire) < 6)
    __asm__ volatile("pause");

  // This second instance is generated after SIG_IGN while blocked. Linux
  // retains it because the disposition can change before it is unblocked.
  if (raise(SIGUSR1) != 0 ||
      sigpending(&pending) != 0 ||
      sigismember(&pending, SIGUSR1) != 1)
    fail(27);
  atomic_store_explicit(&phase, 7, memory_order_release);
  while (atomic_load_explicit(&phase, memory_order_acquire) < 8)
    __asm__ volatile("pause");

  if (pthread_sigmask(SIG_UNBLOCK, &set, 0) != 0) fail(28);
  if (handler_calls != 1) fail(29);
  return 0;
}

int main(void) {
  if (install(handler) != 0) return 10;
  pthread_t thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) return 11;
  while (atomic_load_explicit(&phase, memory_order_acquire) < 1)
    __asm__ volatile("pause");

  if (install(SIG_IGN) != 0) return 12;
  atomic_store_explicit(&phase, 2, memory_order_release);
  while (atomic_load_explicit(&phase, memory_order_acquire) < 3)
    __asm__ volatile("pause");

  if (install(handler) != 0) return 13;
  atomic_store_explicit(&phase, 4, memory_order_release);
  while (atomic_load_explicit(&phase, memory_order_acquire) < 5)
    __asm__ volatile("pause");

  if (install(SIG_IGN) != 0) return 14;
  atomic_store_explicit(&phase, 6, memory_order_release);
  while (atomic_load_explicit(&phase, memory_order_acquire) < 7)
    __asm__ volatile("pause");

  if (install(handler) != 0) return 15;
  atomic_store_explicit(&phase, 8, memory_order_release);
  if (pthread_join(thread, 0) != 0) return 16;
  return atomic_load_explicit(&failure, memory_order_acquire);
}
"#,
    );
    let executable = executable.to_str().unwrap();

    let native = std::process::Command::new(executable).output().unwrap();
    assert!(native.status.success(), "native: {native:?}");

    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "sibling sigaction guest failed with code {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
}

type SharedChildWaitEvents = Arc<Mutex<Vec<BackendChildWaitEvent>>>;

static CHILD_WAIT_EVENT_CONFIGS: LazyLock<Mutex<BTreeMap<u64, ChildWaitEventConfig>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static NEXT_CHILD_WAIT_EVENT_CONFIG: AtomicU64 = AtomicU64::new(1);

fn child_wait_event_config(events: &SharedChildWaitEvents) -> u64 {
    child_wait_event_config_with_block(events, None)
}

#[derive(Clone)]
struct ChildWaitEventConfig {
    events: Weak<Mutex<Vec<BackendChildWaitEvent>>>,
    blocked_getpid: Option<i32>,
}

fn child_wait_event_config_with_block(
    events: &SharedChildWaitEvents,
    blocked_getpid: Option<i32>,
) -> u64 {
    let id = NEXT_CHILD_WAIT_EVENT_CONFIG.fetch_add(1, Ordering::SeqCst);
    CHILD_WAIT_EVENT_CONFIGS.lock().unwrap().insert(
        id,
        ChildWaitEventConfig {
            events: Arc::downgrade(events),
            blocked_getpid,
        },
    );
    id
}

#[derive(Debug, Default)]
struct ChildWaitEventLog {
    events: SharedChildWaitEvents,
    control: Mutex<Option<BackendSignalControl>>,
    publications: Mutex<Vec<reverie::ChildExitPublicationResult>>,
    delivery_sequence: AtomicU64,
    failed: AtomicBool,
    failure_waiters: Mutex<Vec<Waker>>,
}

#[reverie::global_tool]
impl GlobalTool for ChildWaitEventLog {
    type Request = ();
    type Response = ();
    type Config = u64;

    async fn init_global_state(events: &Self::Config) -> Self {
        Self {
            events: CHILD_WAIT_EVENT_CONFIGS
                .lock()
                .unwrap()
                .get(events)
                .and_then(|config| config.events.upgrade())
                .expect("child wait event config disappeared"),
            ..Self::default()
        }
    }

    async fn receive_rpc(&self, _from: Pid, (): ()) {}

    fn report_backend_failure(&self, _event: reverie::BackendFailure) {
        self.failed.store(true, Ordering::Release);
        for waiter in std::mem::take(
            &mut *self
                .failure_waiters
                .lock()
                .expect("child failure waiters poisoned"),
        ) {
            waiter.wake();
        }
    }

    async fn wait_for_backend_failure(&self) {
        poll_fn(|context| {
            if self.failed.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            let mut waiters = self
                .failure_waiters
                .lock()
                .expect("child failure waiters poisoned");
            if !waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                waiters.push(context.waker().clone());
            }
            if self.failed.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    fn install_backend_signal_control(
        &self,
        control: Option<BackendSignalControl>,
    ) -> Result<BackendSignalControlMode, reverie::Error> {
        *self.control.lock().expect("child signal control poisoned") =
            Some(control.ok_or(Errno::ENOSYS)?);
        Ok(BackendSignalControlMode::ToolControlled)
    }

    fn authorize_backend_signal_boundary(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Result<Option<SignalDeliveryPermit>, reverie::Error> {
        let control = self
            .control
            .lock()
            .expect("child signal control poisoned")
            .clone()
            .expect("backend signal control was installed");
        let eligible = control
            .process
            .signal_recipients(task.process, libc::SIGCHLD)?
            .into_iter()
            .any(|recipient| recipient.task == task);
        if !eligible {
            return Ok(None);
        }
        let permit = SignalDeliveryPermit {
            task,
            sequence: self.delivery_sequence.fetch_add(1, Ordering::SeqCst) + 1,
            site: None,
        };
        control.process.reserve_delivery(permit)?;
        Ok(Some(permit))
    }

    async fn on_backend_child_wait_event(
        &self,
        event: BackendChildWaitEvent,
    ) -> Result<(), reverie::Error> {
        // Make the binding-lifetime claim observable on the real backend: the
        // callback yields the host thread and then uses the installed weak
        // facade to validate and publish this exact generation-bound event.
        std::thread::yield_now();
        if let Some(completion) = event.child_exit_completion() {
            let publication = self
                .control
                .lock()
                .expect("child signal control poisoned")
                .as_ref()
                .expect("backend signal control was installed")
                .process
                .publish_child_exit(completion);
            self.publications
                .lock()
                .expect("child publication log poisoned")
                .push(publication);
        }
        self.events
            .lock()
            .expect("child wait-event log poisoned")
            .push(event);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ChildWaitEventTool {
    pid: i32,
    blocked_getpid: Option<i32>,
}

#[reverie::tool]
impl Tool for ChildWaitEventTool {
    type GlobalState = ChildWaitEventLog;
    type ThreadState = ();

    fn new(pid: Pid, config: &u64) -> Self {
        Self {
            pid: pid.as_raw(),
            blocked_getpid: CHILD_WAIT_EVENT_CONFIGS
                .lock()
                .unwrap()
                .get(config)
                .expect("child wait event config disappeared")
                .blocked_getpid,
        }
    }

    fn subscriptions(_config: &u64) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([
            Sysno::fork,
            Sysno::getpid,
            Sysno::wait4,
            Sysno::waitid,
            Sysno::rt_sigaction,
        ]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if syscall.number() == Sysno::getpid && self.blocked_getpid == Some(self.pid) {
            std::future::pending().await
        } else {
            Ok(guest.inject(syscall).await?)
        }
    }
}

#[test]
fn child_waitability_callback_and_auto_reap_are_observed_on_real_kvm() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM child-lifecycle test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "child-waitability",
        r#"
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t handled;
static void handler(int signal) { if (signal == SIGCHLD) ++handled; }

static void child_exit(int code) {
  pid_t child = fork();
  if (child < 0) _exit(90);
  if (child == 0) _exit(code);
}

int main(void) {
  struct sigaction action = {0};
  action.sa_handler = handler;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  errno = 0;
  /* Installing and running a real SIGCHLD handler must succeed, as it does
     natively and under ptrace. A caught SIGCHLD does not auto-reap, so the
     child must still be waitable after delivery. */
  if (sigaction(SIGCHLD, &action, 0) != 0) return 10;

  child_exit(7);
  int status = 0;
  if (waitpid(-1, &status, 0) <= 0 || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 7) return 11;
  if (handled != 1) return 16;

  action.sa_handler = SIG_IGN;
  action.sa_flags = 0;
  if (sigaction(SIGCHLD, &action, 0) != 0) return 12;
  child_exit(8);
  if (waitpid(-1, &status, 0) != -1 || errno != ECHILD) return 13;

  action.sa_handler = SIG_DFL;
  action.sa_flags = SA_NOCLDWAIT;
  if (sigaction(SIGCHLD, &action, 0) != 0) return 14;
  child_exit(9);
  if (waitpid(-1, &status, 0) != -1 || errno != ECHILD) return 15;

  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.set_root_pid(17).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();

    let event_log = Arc::new(Mutex::new(Vec::new()));
    let config = child_wait_event_config(&event_log);
    let (global, code, _stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<ChildWaitEventTool>(config, true),
    )
    .unwrap();
    assert_eq!(
        code,
        0,
        "child lifecycle guest failed with code {code}; stderr={}",
        String::from_utf8_lossy(&stderr),
    );

    let events = global
        .events
        .lock()
        .expect("child wait-event log poisoned")
        .clone();
    assert_eq!(
        events,
        vec![
            BackendChildWaitEvent {
                parent: SignalProcessId {
                    tgid: Pid::from_raw(17),
                    generation: 1,
                },
                child: SignalProcessId {
                    tgid: Pid::from_raw(18),
                    generation: 2,
                },
                state: BackendChildWaitState::Exited {
                    status: ExitStatus::Exited(7),
                    waitable: true,
                    uid: 0,
                    user_ticks: 0,
                    system_ticks: 0,
                },
            },
            BackendChildWaitEvent {
                parent: SignalProcessId {
                    tgid: Pid::from_raw(17),
                    generation: 1,
                },
                child: SignalProcessId {
                    tgid: Pid::from_raw(19),
                    generation: 3,
                },
                state: BackendChildWaitState::Exited {
                    status: ExitStatus::Exited(8),
                    waitable: false,
                    uid: 0,
                    user_ticks: 0,
                    system_ticks: 0,
                },
            },
            BackendChildWaitEvent {
                parent: SignalProcessId {
                    tgid: Pid::from_raw(17),
                    generation: 1,
                },
                child: SignalProcessId {
                    tgid: Pid::from_raw(20),
                    generation: 4,
                },
                state: BackendChildWaitState::Exited {
                    status: ExitStatus::Exited(9),
                    waitable: false,
                    uid: 0,
                    user_ticks: 0,
                    system_ticks: 0,
                },
            },
        ],
        "the backend callback must describe every real terminal waitability transition",
    );
    assert!(
        events
            .iter()
            .all(|event| event.child.tgid.as_raw() as u64 != event.child.generation)
    );
    let publications = global
        .publications
        .lock()
        .expect("child publication log poisoned");
    assert_eq!(publications.len(), 3);
    for (publication, event) in publications.iter().zip(events) {
        let reverie::ChildExitPublicationResult::Committed(receipt) = publication else {
            panic!("real callback publication did not commit: {publication:?}");
        };
        assert_eq!(receipt.completion, event.child_exit_completion().unwrap());
    }
    assert_eq!(
        publications
            .iter()
            .map(|publication| match publication {
                reverie::ChildExitPublicationResult::Committed(receipt) => receipt.effect,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>(),
        vec![
            reverie::ChildExitPublicationEffect::Queued,
            reverie::ChildExitPublicationEffect::SuppressedExplicitIgnore,
            reverie::ChildExitPublicationEffect::Queued,
        ]
    );
}

#[test]
fn grandchild_family_transitions_are_causal_on_real_kvm() {
    // Bounded so a family regression that hangs fails the test instead of the
    // suite. An exiting parent joining its adopted child is not such a hang:
    // the root is notified before that join, so mode 9 still passes; the
    // library orphanage tests own that regression.
    if !leader_self_exec_bounded("grandchild_family_transitions_are_causal_on_real_kvm") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "child-grandchild-wait-order",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Reads a procfs record whose descriptor was opened before reparenting. */
static int read_record(int fd, char *buffer, size_t size) {
  ssize_t length = read(fd, buffer, size - 1);
  if (length <= 0) return -1;
  buffer[length] = 0;
  return 0;
}

/* Runs in a grandchild adopted by the outside init. Its descriptors were opened
   under its original parent; both must report the new parent when first read. */
static char adopted_verdict(int stat_fd, int status_fd) {
  if (getppid() != 1) return 'p';
  char buffer[4096];
  if (read_record(stat_fd, buffer, sizeof buffer) != 0) return 's';
  char *end = strrchr(buffer, ')');
  char state = 0;
  int ppid = -1;
  if (end == 0 || sscanf(end + 1, " %c %d", &state, &ppid) != 2 || ppid != 1)
    return 'S';
  if (read_record(status_fd, buffer, sizeof buffer) != 0) return 't';
  char *line = strstr(buffer, "\nPPid:\t");
  if (line == 0 || atoi(line + 7) != 1) return 'T';
  return 'k';
}

int main(int argc, char **argv) {
  if (argc != 2) return 8;
  int mode = atoi(argv[1]);
  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &blocked, 0) != 0) return 9;
  int ready[2] = {-1, -1};
  int verdict[2] = {-1, -1};
  int release[2] = {-1, -1};
  int hold[2] = {-1, -1};
  if ((mode == 0 || (mode >= 6 && mode <= 9)) && pipe(ready) != 0) return 10;
  if (mode == 9 && (pipe(verdict) != 0 || pipe(release) != 0 || pipe(hold) != 0)) return 26;
  pid_t child = fork();
  if (child < 0) return 11;
  if (child == 0) {
    pid_t root = getppid();
    if (mode == 4 || mode == 5 || mode == 7 || mode == 8) {
      struct sigaction action = {0};
      action.sa_handler = (mode == 4 || mode == 7) ? SIG_IGN : SIG_DFL;
      action.sa_flags = (mode == 5 || mode == 8) ? SA_NOCLDWAIT : 0;
      sigemptyset(&action.sa_mask);
      if (sigaction(SIGCHLD, &action, 0) != 0) _exit(12);
    }
    pid_t grandchild = fork();
    if (grandchild < 0) _exit(13);
    if (grandchild == 0) {
      if (mode == 0) {
        char byte = 'x';
        if (write(ready[1], &byte, 1) != 1) _exit(14);
        for (;;) (void)getpid();
      } else if (mode == 9) {
        /* Only the root may release this process; its failure reads as EOF.
           Dropping the hold end leaves the former parent as its last writer. */
        if (close(release[1]) != 0 || close(hold[1]) != 0) _exit(36);
        int stat_fd = open("/proc/self/stat", O_RDONLY);
        int status_fd = open("/proc/self/status", O_RDONLY);
        if (stat_fd < 0 || status_fd < 0) _exit(27);
        if (getppid() == 1) _exit(28);
        char byte = 'x';
        if (write(ready[1], &byte, 1) != 1) _exit(29);
        /* The parent exits after reading the byte; spin until adoption. */
        while (getppid() != 1) (void)getpid();
        byte = adopted_verdict(stat_fd, status_fd);
        if (write(verdict[1], &byte, 1) != 1) _exit(30);
        /* Outlive the former parent until the root has reaped it: its exit
           must not wait for this adopted process. */
        if (read(release[0], &byte, 1) != 1) _exit(34);
      } else if (mode >= 6 && mode <= 8) {
        char byte = 0;
        if (read(ready[0], &byte, 1) != 1 || byte != 'x') _exit(21);
      }
      _exit(9);
    }
    if (mode == 0 || mode == 9) {
      char byte = 0;
      if (read(ready[0], &byte, 1) != 1 || byte != 'x') _exit(15);
    } else if (mode == 1 || mode == 3) {
      siginfo_t info = {0};
      if (waitid(P_PID, grandchild, &info, WEXITED | WNOWAIT) != 0 ||
          info.si_pid != grandchild || info.si_code != CLD_EXITED ||
          info.si_status != 9) _exit(16);
      if (mode == 3) {
        info.si_pid = 0;
        if (waitid(P_PID, grandchild, &info, WEXITED) != 0 ||
            info.si_pid != grandchild || info.si_code != CLD_EXITED ||
            info.si_status != 9) _exit(17);
      }
    } else if (mode == 2) {
      int grandchild_status = 0;
      if (waitpid(grandchild, &grandchild_status, 0) != grandchild ||
          !WIFEXITED(grandchild_status) || WEXITSTATUS(grandchild_status) != 9)
        _exit(18);
    } else if (mode >= 6 && mode <= 8) {
      errno = 0;
      while (kill(root, 0) == 0) (void)getpid();
      if (errno != ESRCH) _exit(22);
      char byte = 'x';
      if (write(ready[1], &byte, 1) != 1) _exit(23);
      int grandchild_status = 0;
      if (mode == 6) {
        if (waitpid(grandchild, &grandchild_status, 0) != grandchild ||
            !WIFEXITED(grandchild_status) || WEXITSTATUS(grandchild_status) != 9)
          _exit(24);
      } else {
        errno = 0;
        if (waitpid(grandchild, &grandchild_status, 0) != -1 || errno != ECHILD)
          _exit(25);
      }
    } else {
      int grandchild_status = 0;
      errno = 0;
      if (waitpid(grandchild, &grandchild_status, 0) != -1 || errno != ECHILD)
        _exit(19);
    }
    _exit(7);
  }
  if (mode >= 6 && mode <= 8) return 0;
  if (mode == 9 && (close(verdict[1]) != 0 || close(release[0]) != 0 ||
                    close(hold[1]) != 0)) return 31;
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 7) return 20;
  if (mode == 9) {
    /* The adopted grandchild was never this process's child, and the outside
       init reaps it; only its verdict comes back. */
    errno = 0;
    if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD) return 32;
    char byte = 0;
    if (read(verdict[0], &byte, 1) != 1) return 33;
    if (byte != 'k') return byte;
    /* Only the reaped parent still held this write end. Its descriptors close
       in its own exit, however long the adopted grandchild lives. */
    if (read(hold[0], &byte, 1) != 0) return 37;
    byte = 'r';
    if (write(release[1], &byte, 1) != 1) return 35;
  }
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let event = |parent: i32, parent_generation, child: i32, child_generation, waitable| {
        BackendChildWaitEvent {
            parent: SignalProcessId {
                tgid: Pid::from_raw(parent),
                generation: parent_generation,
            },
            child: SignalProcessId {
                tgid: Pid::from_raw(child),
                generation: child_generation,
            },
            state: BackendChildWaitState::Exited {
                status: ExitStatus::Exited(if child_generation == 3 { 9 } else { 7 }),
                waitable,
                uid: 0,
                user_ticks: 0,
                system_ticks: 0,
            },
        }
    };

    // A traced root that is itself namespace init (PID 1) cannot adopt
    // orphans, so it stays fail-closed. Beneath an outside init (PID 3) the
    // grandchild is adopted instead; mode 0's grandchild never exits, which
    // would legitimately run forever, so PID 3 runs the finite mode 9.
    for (root_pid, modes) in [(1, 0..=8), (3, 1..=9)] {
        for mode in modes {
            let events = Arc::new(Mutex::new(Vec::new()));
            let config =
                child_wait_event_config_with_block(&events, (mode == 0).then_some(root_pid + 2));
            let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
            backend.set_root_pid(root_pid).unwrap();
            let mode_string = mode.to_string();
            backend
                .install_static_elf_with_context(
                    &image,
                    &[executable, &mode_string],
                    &["PATH=/usr/bin:/bin"],
                    &directory.0,
                )
                .unwrap();
            let result = futures::executor::block_on(
                backend.run_static_elf_with_tool::<ChildWaitEventTool>(config, true),
            );
            let observed = events
                .lock()
                .expect("child wait-event log poisoned")
                .clone();
            let child = root_pid + 1;
            let grandchild = root_pid + 2;
            match (mode, root_pid) {
                (0, 1) => {
                    let rendered = result.unwrap_err().to_string();
                    assert!(
                        rendered.contains("still requiring unsupported reparenting"),
                        "live descendant, root pid {root_pid}: {rendered}"
                    );
                    assert!(
                        observed.is_empty(),
                        "a still-live grandchild has no terminal event: {observed:?}"
                    );
                }
                (1, 1) => {
                    let rendered = result.unwrap_err().to_string();
                    assert!(
                        rendered.contains("still requiring unsupported reparenting"),
                        "zombie descendant, root pid {root_pid}: {rendered}"
                    );
                    assert_eq!(
                        observed,
                        vec![event(child, 2, grandchild, 3, true)],
                        "WNOWAIT must retain the zombie while suppressing only C-to-root publication",
                    );
                }
                (1, 3) => {
                    let (_global, code, _stdout, stderr) = result.unwrap();
                    assert_eq!(
                        code,
                        0,
                        "zombie descendant, root pid {root_pid}: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                    assert_eq!(
                        observed,
                        vec![
                            event(child, 2, grandchild, 3, true),
                            event(root_pid, 1, child, 2, true),
                        ],
                        "a zombie already announced to its parent keeps that callback; \
                         init then reaps it and the parent's exit reaches the root",
                    );
                }
                (9, 3) => {
                    let (_global, code, _stdout, stderr) = result.unwrap();
                    assert_eq!(
                        code,
                        0,
                        "adopted live grandchild, root pid {root_pid}: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                    assert_eq!(
                        observed,
                        vec![event(root_pid, 1, child, 2, true)],
                        "an init-reaped orphan has no traced parent to notify",
                    );
                }
                (2 | 3, _) => {
                    let (_global, code, _stdout, stderr) = result.unwrap();
                    assert_eq!(
                        code,
                        0,
                        "consuming mode {mode}, root pid {root_pid}: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                    assert_eq!(
                        observed,
                        vec![
                            event(child, 2, grandchild, 3, true),
                            event(root_pid, 1, child, 2, true),
                        ],
                    );
                }
                (4 | 5, _) => {
                    let (_global, code, _stdout, stderr) = result.unwrap();
                    assert_eq!(
                        code,
                        0,
                        "auto-reap mode {mode}, root pid {root_pid}: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                    assert_eq!(
                        observed,
                        vec![
                            event(child, 2, grandchild, 3, false),
                            event(root_pid, 1, child, 2, true),
                        ],
                    );
                }
                (6, _) => {
                    let (_global, code, _stdout, stderr) = result.unwrap();
                    assert_eq!(
                        code,
                        0,
                        "terminal-root/live-parent mode, root pid {root_pid}: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                    assert_eq!(
                        observed,
                        vec![event(child, 2, grandchild, 3, true)],
                        "a terminal transitive root cannot steal a grandchild from its live direct parent",
                    );
                }
                (7 | 8, _) => {
                    let (_global, code, _stdout, stderr) = result.unwrap();
                    assert_eq!(
                        code,
                        0,
                        "terminal-root/live-parent auto-reap mode {mode}, root pid {root_pid}: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                    assert_eq!(
                        observed,
                        vec![event(child, 2, grandchild, 3, false)],
                        "the live direct parent's frozen SIGCHLD policy remains authoritative after root exit",
                    );
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn direct_fork_orphaned_by_a_peer_exit_group_completes_detached_on_real_kvm() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM detached direct-fork test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "direct-fork-peer-exit-group",
        r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

static int ready[2];

static void say(const char *message, size_t length) {
  if (write(1, message, length) != (ssize_t)length) _exit(30);
}

/* Ends the whole root process once the inline fork child is running. */
static void *exit_group_peer(void *unused) {
  (void)unused;
  char byte = 0;
  if (read(ready[0], &byte, 1) != 1 || byte != 'x') syscall(SYS_exit_group, 40);
  syscall(SYS_exit_group, 0);
  return 0;
}

int main(void) {
  if (pipe(ready) != 0) return 10;
  pthread_t peer;
  if (pthread_create(&peer, 0, exit_group_peer, 0) != 0) return 11;
  pid_t child = fork();
  if (child < 0) return 12;
  if (child == 0) {
    if (getppid() != 3) _exit(13);
    char byte = 'x';
    if (write(ready[1], &byte, 1) != 1) _exit(14);
    /* The peer's exit_group makes the root terminal while this fork's caller
       is still blocked, so the outside init adopts this process. */
    while (getppid() != 1) (void)getpid();
    say("adopted\n", 8);
    _exit(5);
  }
  /* The root is already terminal when the fork completes; it must not return. */
  say("fork returned\n", 14);
  return 20;
}
"#,
    );
    let image = std::fs::read(&executable).unwrap();
    let executable = executable.to_str().unwrap();
    for attempt in 0..3 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend.set_root_pid(3).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(
            (code, stdout.as_slice()),
            (0, b"adopted\n".as_slice()),
            "attempt {attempt}: stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        );
    }
}

const PRCTL_REVIEW_REGRESSION: &str = r###"#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(expression) do { if (!(expression)) { fprintf(stderr, "line=%d errno=%d: %s\n", __LINE__, errno, #expression); return 91; } } while (0)

static long call(unsigned long option, unsigned long second, unsigned long third,
                 unsigned long fourth, unsigned long fifth, unsigned long sixth) {
    errno = 0;
    return syscall(SYS_prctl, option, second, third, fourth, fifth, sixth);
}

static int check_name(const unsigned char expected[16]) {
    unsigned char actual[48], wanted[48];
    memset(actual, 0xa5, sizeof(actual));
    memset(wanted, 0xa5, sizeof(wanted));
    memcpy(wanted + 16, expected, 16);
    REQUIRE(call(PR_GET_NAME, (uintptr_t)(actual + 16), 17, 18, 19, UINT64_MAX) == 0);
    REQUIRE(memcmp(actual, wanted, sizeof(actual)) == 0);
    return 0;
}

static int names(int inspect_comm) {
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(pages != MAP_FAILED);
    memset(pages, 'x', 8192);
    REQUIRE(mprotect(pages + 4096, 4096, PROT_NONE) == 0);
    memcpy(pages + 4096 - 15, "ABCDEFGHIJKLMNO", 15);
    REQUIRE(call(PR_SET_NAME, (uintptr_t)(pages + 4096 - 15), 17, 18, 19, UINT64_MAX) == 0);
    REQUIRE(check_name((unsigned char[16]){"ABCDEFGHIJKLMNO"}) == 0);
    REQUIRE(call(PR_SET_NAME, (uintptr_t)(pages + 4096 - 14), 0, 0, 0, 0) == -1 && errno == EFAULT);
    REQUIRE(check_name((unsigned char[16]){"ABCDEFGHIJKLMNO"}) == 0);
    REQUIRE(call(PR_SET_NAME, (uintptr_t)(pages + 4096), 0, 0, 0, 0) == -1 && errno == EFAULT);
    REQUIRE(check_name((unsigned char[16]){"ABCDEFGHIJKLMNO"}) == 0);
    REQUIRE(call(PR_SET_NAME, UINT64_MAX, 0, 0, 0, 0) == -1 && errno == EFAULT);
    REQUIRE(check_name((unsigned char[16]){"ABCDEFGHIJKLMNO"}) == 0);
    pages[4095] = 0;
    REQUIRE(call(PR_SET_NAME, (uintptr_t)(pages + 4095), 0, 0, 0, 0) == 0);
    REQUIRE(check_name((unsigned char[16]){0}) == 0);
    const unsigned char special[16] = {0xff, '\n', '\\', '\t', '\r', ')', 0};
    REQUIRE(call(PR_SET_NAME, (uintptr_t)special, 0, 0, 0, 0) == 0);
    REQUIRE(check_name(special) == 0);
    unsigned char status[8192];
    int descriptor = open("/proc/self/status", O_RDONLY);
    REQUIRE(descriptor >= 0);
    ssize_t count = read(descriptor, status, sizeof(status));
    const unsigned char name_line[] = "Name:\t\xff\\n\\\\\t\r)\n";
    REQUIRE(count >= (ssize_t)(sizeof(name_line)-1));
    REQUIRE(memcmp(status, name_line, sizeof(name_line)-1) == 0);
    REQUIRE(close(descriptor) == 0);
    if (!inspect_comm) {
        REQUIRE(munmap(pages, 8192) == 0);
        puts("name truncation/fault atomicity/ignored args/proc escaping: PASS");
        return 0;
    }
    descriptor = open("/proc/self/comm", O_RDONLY);
    REQUIRE(descriptor >= 0);
    unsigned char comm[32], wanted[32];
    memset(comm, 0xa5, sizeof(comm));
    memset(wanted, 0xa5, sizeof(wanted));
    memcpy(wanted, special, 6);
    wanted[6] = '\n';
    REQUIRE(read(descriptor, comm, sizeof(comm)) == 7);
    REQUIRE(memcmp(comm, wanted, sizeof(comm)) == 0);
    REQUIRE(close(descriptor) == 0);
    REQUIRE(mprotect(pages + 4096, 4096, PROT_READ | PROT_WRITE) == 0);
    REQUIRE(munmap(pages, 8192) == 0);
    puts("name truncation/fault atomicity/ignored args/proc escaping: PASS");
    return 0;
}

static int copyout(int selection) {
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(pages != MAP_FAILED);
    unsigned char wanted[8192];
    memset(pages, 0xa5, 8192);
    memset(wanted, 0xa5, sizeof(wanted));
    REQUIRE(call(PR_SET_NAME, (uintptr_t)"ABCDEFGHIJKLMNO", 0, 0, 0, 0) == 0);
    REQUIRE(call(PR_SET_PDEATHSIG, 0, 0, 0, 0, 0) == 0);
    REQUIRE(mprotect(pages, 4096, PROT_READ) == 0);
    for (unsigned option = 0; option < 2; ++option) {
        if (selection >= 0 && option != (unsigned)selection) continue;
        long result = call(option ? PR_GET_PDEATHSIG : PR_GET_NAME, (uintptr_t)(pages+100), 0, 0, 0, 0);
        int saved_errno = errno;
        unsigned changed = 0;
        for (unsigned index = 0; index < sizeof(wanted); ++index) changed += pages[index] != wanted[index];
        printf("copyout option=%u result=%ld errno=%d changed_bytes=%u\n", option ? PR_GET_PDEATHSIG : PR_GET_NAME, result, saved_errno, changed);
        REQUIRE(result == -1 && saved_errno == EFAULT);
        REQUIRE(memcmp(pages, wanted, sizeof(wanted)) == 0);
    }
    REQUIRE(mprotect(pages, 4096, PROT_READ | PROT_WRITE) == 0);
    if (selection == 0 || selection == 1) {
        REQUIRE(munmap(pages, 8192) == 0);
        puts("read-only copyout exact EFAULT/full8192 unchanged: PASS");
        return 0;
    }
    REQUIRE(mprotect(pages + 4096, 4096, PROT_NONE) == 0);
    long result = call(PR_GET_NAME, (uintptr_t)(pages + 4096 - 8), 0, 0, 0, 0);
    int saved = errno;
    REQUIRE(result == -1 && saved == EFAULT);
    REQUIRE(mprotect(pages + 4096, 4096, PROT_READ | PROT_WRITE) == 0);
    printf("GET_NAME cross-page result=%ld errno=%d changed:", result, saved);
    for (unsigned index = 0; index < 8192; ++index) if (pages[index] != wanted[index]) printf(" %u=%02x", index, pages[index]);
    puts("");
    memcpy(wanted + 4088, "ABCDEFGH", 8);
    REQUIRE(memcmp(pages, wanted, sizeof(wanted)) == 0);
    REQUIRE(munmap(pages, 8192) == 0);
    puts("cross-page name copyout exact prefix/full8192 oracle: PASS");
    return 0;
}

static int thp(void) {
    const unsigned long flags[] = {0, 1, 2, 3, 4, 1UL << 32, UINT64_MAX};
    for (unsigned disable = 0; disable < 2; ++disable) {
        for (unsigned index = 0; index < sizeof(flags)/sizeof(flags[0]); ++index) {
            REQUIRE(call(PR_SET_THP_DISABLE, 0, 0, 0, 0, 0) == 0);
            long result = call(PR_SET_THP_DISABLE, disable, flags[index], 0, 0, UINT64_MAX);
            int saved = errno;
            long state = call(PR_GET_THP_DISABLE, 0, 0, 0, 0, UINT64_MAX);
            printf("THP disable=%u flags=%lu result=%ld errno=%d state=%ld\n", disable, flags[index], result, saved, state);
        }
    }
    REQUIRE(call(PR_SET_THP_DISABLE, 2, 0, 0, 0, UINT64_MAX) == 0);
    REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, UINT64_MAX) == 1);
    for (unsigned argument = 1; argument < 5; ++argument) {
        unsigned long args[5] = {PR_GET_THP_DISABLE, 0, 0, 0, 0};
        args[argument] = 1;
        REQUIRE(call(args[0], args[1], args[2], args[3], args[4], UINT64_MAX) == -1 && errno == EINVAL);
        REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, 0) == 1);
    }
    REQUIRE(call(PR_SET_THP_DISABLE, 0, 0, 0, 0, 0) == 0);
    puts("THP ignored sixth/strict GET arguments/nonzero disable: PASS");
    return 0;
}

static int modern_thp(void) {
    REQUIRE(call(PR_SET_THP_DISABLE, 0, 0, 0, 0, 0) == 0);
    REQUIRE(call(PR_SET_THP_DISABLE, 1, 2, 0, 0, UINT64_MAX) == 0);
    REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, UINT64_MAX) == 3);
    REQUIRE(call(PR_SET_THP_DISABLE, 1, 1, 0, 0, 0) == -1 && errno == EINVAL);
    REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, 0) == 3);
    REQUIRE(call(PR_SET_THP_DISABLE, 0, 0, 0, 0, 0) == 0);
    REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, 0) == 0);
    puts("THP EXCEPT_ADVISED flag2 state3 and invalidflag atomicity: PASS");
    return 0;
}

static void *worker(void *unused) {
    (void)unused;
    if (check_name((unsigned char[16]){"leader"}) != 0) return (void *)1;
    if (call(PR_SET_NAME, (uintptr_t)"worker", 0, 0, 0, 0) != 0) return (void *)2;
    if (check_name((unsigned char[16]){"worker"}) != 0) return (void *)3;
    if (call(PR_SET_THP_DISABLE, 0, 0, 0, 0, 0) != 0) return (void *)4;
    return NULL;
}

static int shared_process(void *unused) {
    (void)unused;
    if (check_name((unsigned char[16]){"leader"}) != 0) return 1;
    if (call(PR_SET_NAME, (uintptr_t)"vm-child", 0, 0, 0, 0) != 0) return 2;
    if (call(PR_SET_THP_DISABLE, 0, 0, 0, 0, 0) != 0) return 3;
    return 0;
}

static int lifecycle(const char *executable) {
    REQUIRE(call(PR_SET_NAME, (uintptr_t)"leader", 0, 0, 0, 0) == 0);
    REQUIRE(call(PR_SET_THP_DISABLE, 1, 0, 0, 0, 0) == 0);
    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, worker, NULL) == 0);
    void *thread_result;
    REQUIRE(pthread_join(thread, &thread_result) == 0 && thread_result == NULL);
    REQUIRE(check_name((unsigned char[16]){"leader"}) == 0);
    REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, 0) == 0);
    REQUIRE(call(PR_SET_THP_DISABLE, 1, 0, 0, 0, 0) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) _exit(shared_process(NULL));
    int status;
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, 0) == 1);
    REQUIRE(check_name((unsigned char[16]){"leader"}) == 0);
    void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(stack != MAP_FAILED);
    child = clone(shared_process, (char *)stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    REQUIRE(child >= 0);
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, 0) == 0);
    REQUIRE(check_name((unsigned char[16]){"leader"}) == 0);
    REQUIRE(munmap(stack, 65536) == 0);
    REQUIRE(call(PR_SET_THP_DISABLE, 1, 0, 0, 0, 0) == 0);
    child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        execl(executable, "fake-argv-zero", "after-exec", NULL);
        _exit(92);
    }
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    REQUIRE(check_name((unsigned char[16]){"leader"}) == 0);
    puts("thread-local name/mm THP sharing/fork isolation/exec inheritance: PASS");
    return 0;
}

int main(int argc, char **argv) {
    REQUIRE(argc == 2);
    if (strcmp(argv[1], "names") == 0) return names(1);
    if (strcmp(argv[1], "names-core") == 0) return names(0);
    if (strcmp(argv[1], "copyout") == 0) return copyout(-1);
    if (strcmp(argv[1], "copyout-name") == 0) return copyout(0);
    if (strcmp(argv[1], "copyout-pdeath") == 0) return copyout(1);
    if (strcmp(argv[1], "copyout-partial") == 0) return copyout(2);
    if (strcmp(argv[1], "thp") == 0) return thp();
    if (strcmp(argv[1], "modern-thp") == 0) return modern_thp();
    if (strcmp(argv[1], "lifecycle") == 0) return lifecycle(argv[0]);
    if (strcmp(argv[1], "after-exec") == 0) {
        REQUIRE(check_name((unsigned char[16]){"native-prctl"}) == 0);
        REQUIRE(call(PR_GET_THP_DISABLE, 0, 0, 0, 0, 0) == 1);
        return 0;
    }
    return 93;
}
"###;

fn review_537_case(mode: &str) {
    assert!(kvm_available("review_537_case"));
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "native-prctl", PRCTL_REVIEW_REGRESSION);
    let native = std::process::Command::new(&executable)
        .arg(mode)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    println!(
        "NATIVE mode={mode} status={:?} stdout={} stderr={}",
        native.status.code(),
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.status.code(), Some(0));
    assert!(native.stderr.is_empty());
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap(), mode],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    println!(
        "KVM mode={mode} status={code} stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, native.stdout);
    assert!(stderr.is_empty());
}

#[test]
fn review_537_name_core() {
    review_537_case("names-core");
}
#[test]
fn review_537_get_name_readonly() {
    review_537_case("copyout-name");
}
#[test]
fn review_537_get_pdeath_readonly() {
    review_537_case("copyout-pdeath");
}
#[test]
fn review_537_get_name_partial() {
    review_537_case("copyout-partial");
}
#[test]
fn review_537_modern_thp() {
    review_537_case("modern-thp");
}
#[test]
fn review_537_thread_mm_lifecycle() {
    review_537_case("lifecycle");
}

const PRCTL_EXPANDED_REGRESSION: &str = r###"#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(condition) do { if (!(condition)) { fprintf(stderr, "line %d errno %d: %s\n", __LINE__, errno, #condition); return 91; } } while (0)

static long control(unsigned long option, unsigned long second, unsigned long third, unsigned long fourth, unsigned long fifth) {
    errno = 0;
    return syscall(SYS_prctl, option, second, third, fourth, fifth, UINT64_MAX);
}

static int boundaries(void) {
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(pages != MAP_FAILED);
    REQUIRE(prctl(PR_SET_NAME, "ABCDEFGHIJKLMNO", 0, 0, 0) == 0);
    REQUIRE(prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) == 0);
    unsigned char wanted[8192];
    const int protections[] = {PROT_READ, PROT_NONE};
    const int options[] = {PR_GET_PDEATHSIG, PR_GET_NAME};
    for (unsigned option = 0; option < 2; ++option) {
        for (unsigned protection = 0; protection < 2; ++protection) {
            for (unsigned offset = 4080; offset <= 4097; ++offset) {
                memset(pages, 0xa5, 8192);
                memset(wanted, 0xa5, sizeof(wanted));
                REQUIRE(mprotect(pages + 4096, 4096, protections[protection]) == 0);
                long result = control(options[option], (uintptr_t)(pages + offset), 0, 0, 0);
                int error = errno;
                REQUIRE(mprotect(pages + 4096, 4096, PROT_READ | PROT_WRITE) == 0);
                unsigned length = option ? 16 : 4;
                unsigned prefix = offset >= 4096 ? 0 : 4096 - offset;
                if (prefix > length) prefix = length;
                unsigned copied = option ? prefix : (prefix == length ? length : 0);
                if (option) memcpy(wanted + offset, "ABCDEFGHIJKLMNO", copied);
                else memset(wanted + offset, 0, copied);
                REQUIRE(result == (prefix == length ? 0 : -1));
                REQUIRE(error == (prefix == length ? 0 : EFAULT));
                REQUIRE(memcmp(pages, wanted, sizeof(wanted)) == 0);
            }
        }
    }
    REQUIRE(control(PR_GET_NAME, UINT64_MAX, 0, 0, 0) == -1 && errno == EFAULT);
    REQUIRE(control(PR_GET_PDEATHSIG, UINT64_MAX, 0, 0, 0) == -1 && errno == EFAULT);
    REQUIRE(munmap(pages, 8192) == 0);
    puts("72 scalar/name boundary full-buffer cases: PASS");
    return 0;
}

static int thp_modes(void) {
    const unsigned long disables[] = {0, 1, 2, UINT64_MAX};
    const unsigned long flags[] = {0, 1, 2, 3, 4, 1UL << 32, UINT64_MAX};
    for (unsigned disable = 0; disable < 4; ++disable) {
        for (unsigned flag = 0; flag < 7; ++flag) {
            REQUIRE(control(PR_SET_THP_DISABLE, 1, 2, 0, 0) == 0);
            int valid = flags[flag] == 0 || (disables[disable] != 0 && flags[flag] == 2);
            long result = control(PR_SET_THP_DISABLE, disables[disable], flags[flag], 0, 0);
            REQUIRE(result == (valid ? 0 : -1));
            REQUIRE(errno == (valid ? 0 : EINVAL));
            long wanted = valid ? (disables[disable] ? 1 | flags[flag] : 0) : 3;
            REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == wanted);
        }
    }
    for (unsigned argument = 1; argument < 5; ++argument) {
        unsigned long args[5] = {PR_GET_THP_DISABLE, 0, 0, 0, 0};
        REQUIRE(control(PR_SET_THP_DISABLE, 1, 2, 0, 0) == 0);
        args[argument] = UINT64_MAX;
        REQUIRE(control(args[0], args[1], args[2], args[3], args[4]) == -1 && errno == EINVAL);
        REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 3);
    }
    REQUIRE(control(PR_SET_THP_DISABLE, 0, 0, 1, 0) == -1 && errno == EINVAL);
    REQUIRE(control(PR_SET_THP_DISABLE, 0, 0, 0, 1) == -1 && errno == EINVAL);
    REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 3);
    puts("THP 0/1/3 full-width matrix and ignored sixth: PASS");
    return 0;
}

static int expect_output(unsigned char *pages, size_t length, int writable) {
    unsigned char *wanted = malloc(length);
    REQUIRE(wanted != NULL);
    memcpy(wanted, pages, length);
    long result = control(PR_GET_NAME, (uintptr_t)(pages + 128), 0, 0, 0);
    REQUIRE(result == (writable ? 0 : -1));
    REQUIRE(errno == (writable ? 0 : EFAULT));
    if (writable) memcpy(wanted + 128, "ABCDEFGHIJKLMNO", 16);
    REQUIRE(memcmp(pages, wanted, length) == 0);
    free(wanted);
    return 0;
}

static void *protect_worker(void *pages) {
    if (mprotect(pages, 4096, PROT_READ) != 0) return (void *)1;
    return NULL;
}

static int permissions(void) {
    REQUIRE(prctl(PR_SET_NAME, "ABCDEFGHIJKLMNO", 0, 0, 0) == 0);
    const int protections[] = {PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, PROT_READ | PROT_EXEC, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE | PROT_EXEC};
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(pages != MAP_FAILED);
    unsigned char wanted[8192];
    for (unsigned index = 0; index < sizeof(protections) / sizeof(protections[0]); ++index) {
        memset(pages, 0xa5, 8192);
        memset(wanted, 0xa5, sizeof(wanted));
        REQUIRE(mprotect(pages, 4096, protections[index]) == 0);
        long result = control(PR_GET_NAME, (uintptr_t)(pages + 128), 0, 0, 0);
        int error = errno;
        int writable = (protections[index] & PROT_WRITE) != 0;
        REQUIRE(mprotect(pages, 4096, PROT_READ | PROT_WRITE) == 0);
        REQUIRE(result == (writable ? 0 : -1));
        REQUIRE(error == (writable ? 0 : EFAULT));
        if (writable) memcpy(wanted + 128, "ABCDEFGHIJKLMNO", 16);
        REQUIRE(memcmp(pages, wanted, sizeof(wanted)) == 0);
    }
    REQUIRE(mprotect(pages, 4096, PROT_READ) == 0);
    REQUIRE(expect_output(pages, 8192, 0) == 0);
    REQUIRE(mmap(pages, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == pages);
    REQUIRE(expect_output(pages, 8192, 1) == 0);
    REQUIRE(mmap(pages, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == pages);
    REQUIRE(expect_output(pages, 8192, 0) == 0);
    REQUIRE(mprotect(pages, 4096, PROT_READ | PROT_WRITE) == 0);
    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, protect_worker, pages) == 0);
    void *thread_result = (void *)1;
    REQUIRE(pthread_join(thread, &thread_result) == 0 && thread_result == NULL);
    REQUIRE(expect_output(pages, 8192, 0) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        REQUIRE(expect_output(pages, 8192, 0) == 0);
        REQUIRE(mprotect(pages, 4096, PROT_READ | PROT_WRITE) == 0);
        REQUIRE(expect_output(pages, 8192, 1) == 0);
        _exit(0);
    }
    int status;
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    REQUIRE(expect_output(pages, 8192, 0) == 0);
    REQUIRE(munmap(pages, 8192) == 0);
    REQUIRE(mmap(pages, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == pages);
    REQUIRE(expect_output(pages, 8192, 1) == 0);
    REQUIRE(munmap(pages, 8192) == 0);
    for (unsigned writable = 0; writable < 2; ++writable) {
        pages = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(pages != MAP_FAILED);
        memset(pages, 0xa5, 4096);
        REQUIRE(mprotect(pages, 4096, PROT_READ | (writable ? PROT_WRITE : 0)) == 0);
        pages = mremap(pages, 4096, 8192, MREMAP_MAYMOVE);
        REQUIRE(pages != MAP_FAILED);
        REQUIRE(expect_output(pages, 8192, writable) == 0);
        REQUIRE(expect_output(pages + 4096, 4096, writable) == 0);
        pages = mremap(pages, 8192, 4096, MREMAP_MAYMOVE);
        REQUIRE(pages != MAP_FAILED);
        REQUIRE(expect_output(pages, 4096, writable) == 0);
        REQUIRE(munmap(pages, 4096) == 0);
    }
    puts("mapping/mprotect/replacement/thread/fork/remap copyout: PASS");
    return 0;
}

static void *mode_worker(void *unused) {
    (void)unused;
    if (control(PR_GET_THP_DISABLE, 0, 0, 0, 0) != 3) return (void *)1;
    if (control(PR_SET_THP_DISABLE, 1, 0, 0, 0) != 0) return (void *)2;
    return NULL;
}

static int mode_shared(void *unused) {
    (void)unused;
    if (control(PR_GET_THP_DISABLE, 0, 0, 0, 0) != 3) return 1;
    if (control(PR_SET_THP_DISABLE, 0, 0, 0, 0) != 0) return 2;
    return 0;
}

static int mode_lifetime(const char *executable) {
    REQUIRE(control(PR_SET_THP_DISABLE, 1, 2, 0, 0) == 0);
    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, mode_worker, NULL) == 0);
    void *result = (void *)1;
    REQUIRE(pthread_join(thread, &result) == 0 && result == NULL);
    REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 1);
    REQUIRE(control(PR_SET_THP_DISABLE, 1, 2, 0, 0) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 3);
        REQUIRE(control(PR_SET_THP_DISABLE, 0, 0, 0, 0) == 0);
        _exit(0);
    }
    int status;
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 3);
    unsigned char *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(stack != MAP_FAILED);
    child = clone(mode_shared, stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    REQUIRE(child >= 0);
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 0);
    REQUIRE(munmap(stack, 65536) == 0);
    REQUIRE(control(PR_SET_THP_DISABLE, 1, 2, 0, 0) == 0);
    child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        execl(executable, "unrelated-argv-zero", "mode-after-exec", NULL);
        _exit(92);
    }
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 3);
    puts("THP mode3 thread/VM sharing, fork isolation, exec: PASS");
    return 0;
}

int main(int argc, char **argv) {
    REQUIRE(argc == 2);
    if (strcmp(argv[1], "boundaries") == 0) return boundaries();
    if (strcmp(argv[1], "thp-modes") == 0) return thp_modes();
    if (strcmp(argv[1], "permissions") == 0) return permissions();
    if (strcmp(argv[1], "mode-lifetime") == 0) return mode_lifetime(argv[0]);
    if (strcmp(argv[1], "mode-after-exec") == 0) {
        REQUIRE(control(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 3);
        return 0;
    }
    return 93;
}
"###;

fn run_expanded_prctl(mode: &str) {
    assert!(kvm_available("run_expanded_prctl"));
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "expanded-prctl", PRCTL_EXPANDED_REGRESSION);
    let native = std::process::Command::new(&executable)
        .arg(mode)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert_eq!(
        native.status.code(),
        Some(0),
        "native mode={mode}: {native:?}"
    );
    assert!(native.stderr.is_empty());
    let executable = executable.to_str().unwrap();
    let (stdout, stderr) = run_host_program_captured(executable, &[executable, mode], &directory.0);
    assert_eq!(stdout, native.stdout);
    assert!(stderr.is_empty());
    let (stdout, stderr) =
        run_host_program_with_tool_captured(executable, &[executable, mode], &directory.0);
    assert_eq!(stdout, native.stdout);
    assert!(stderr.is_empty());
}

#[test]
fn repair_prctl_scalar_and_name_boundaries() {
    run_expanded_prctl("boundaries");
}
#[test]
fn repair_prctl_full_thp_modes() {
    run_expanded_prctl("thp-modes");
}
#[test]
fn repair_prctl_permissions_and_lifetime() {
    run_expanded_prctl("permissions");
}
#[test]
fn repair_prctl_mode_three_lifetime() {
    run_expanded_prctl("mode-lifetime");
}

const PRCTL_DENY_KVM: &str = r###"#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

static int open_forward(const char *symbol, const char *path, int flags, va_list arguments) {
    if (strcmp(path, "/dev/kvm") == 0) {
        errno = EACCES;
        return -1;
    }
    int (*next)(const char *, int, ...) = dlsym(RTLD_NEXT, symbol);
    if (!next) {
        errno = ENOSYS;
        return -1;
    }
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        mode_t mode = va_arg(arguments, unsigned int);
        return next(path, flags, mode);
    }
    return next(path, flags);
}

int open(const char *path, int flags, ...) {
    va_list arguments;
    va_start(arguments, flags);
    int result = open_forward("open", path, flags, arguments);
    va_end(arguments);
    return result;
}

int open64(const char *path, int flags, ...) {
    va_list arguments;
    va_start(arguments, flags);
    int result = open_forward("open64", path, flags, arguments);
    va_end(arguments);
    return result;
}
"###;

fn prctl_elf_copyout_image(kind: &str, writable: bool, name: bool, output_offset: u64) -> Vec<u8> {
    fn immediate(code: &mut Vec<u8>, register: u8, value: u64) {
        code.extend_from_slice(&[0x48, register]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn write_page(code: &mut Vec<u8>, address: u64) {
        immediate(code, 0xb8, 1);
        immediate(code, 0xbf, 1);
        immediate(code, 0xbe, address);
        immediate(code, 0xba, 4096);
        code.extend_from_slice(&[0x0f, 0x05]);
    }
    fn write_result(code: &mut Vec<u8>) {
        code.push(0x50);
        immediate(code, 0xb8, 1);
        immediate(code, 0xbf, 1);
        code.extend_from_slice(&[0x48, 0x89, 0xe6]);
        immediate(code, 0xba, 8);
        code.extend_from_slice(&[0x0f, 0x05, 0x58]);
    }
    let address = LOAD_ADDRESS + 0x4000;
    let succeeds = writable || kind.starts_with("bss");
    let mut code = Vec::new();
    write_page(&mut code, address);
    if succeeds {
        immediate(&mut code, 0xbf, address);
        immediate(&mut code, 0xb9, 4096);
        immediate(&mut code, 0xb8, 0x5a);
        code.extend_from_slice(&[0xfc, 0xf3, 0xaa]);
    }
    write_page(&mut code, address);
    immediate(&mut code, 0xb8, libc::SYS_prctl as u64);
    immediate(
        &mut code,
        0xbf,
        if name {
            libc::PR_SET_NAME
        } else {
            libc::PR_SET_PDEATHSIG
        } as u64,
    );
    let name_operand = code.len() + 2;
    immediate(&mut code, 0xbe, 0);
    code.extend_from_slice(&[0x0f, 0x05]);
    write_result(&mut code);
    immediate(&mut code, 0xb8, libc::SYS_prctl as u64);
    immediate(
        &mut code,
        0xbf,
        if name {
            libc::PR_GET_NAME
        } else {
            libc::PR_GET_PDEATHSIG
        } as u64,
    );
    immediate(&mut code, 0xbe, address + output_offset);
    code.extend_from_slice(&[0x0f, 0x05]);
    write_result(&mut code);
    write_page(&mut code, address);
    immediate(&mut code, 0xb8, 60);
    immediate(&mut code, 0xbf, 0);
    code.extend_from_slice(&[0x0f, 0x05]);
    if name {
        let name_address = LOAD_ADDRESS + code.len() as u64;
        code[name_operand..name_operand + 8].copy_from_slice(&name_address.to_le_bytes());
        code.extend_from_slice(b"ABCDEFGHIJKLMNO\0");
    }
    let mut image = static_elf(&code);
    image.resize(0x4000, 0);
    image[0x2000..0x4000].fill(if kind.starts_with("bss") { 0 } else { 0x5a });
    if kind == "file-bss" {
        image[0x3800..0x4000].fill(0);
    }
    let overlap = kind != "single";
    put_u16(&mut image, 56, if overlap { 3 } else { 2 });
    for index in 1..=if overlap { 2 } else { 1 } {
        let second = index == 2;
        let split = second && (kind == "file-split" || kind == "bss-split");
        let bss = second && kind.starts_with("bss");
        let file_tail = second && kind == "file-bss";
        let flags = if second || !overlap {
            writable
        } else {
            !writable
        };
        let offset = if second { 0x3000 } else { 0x2000 } + if split { 0x800 } else { 0 };
        let size = if split { 0x800 } else { 0x1000 };
        let header = 64 + index * 56;
        put_u32(&mut image, header, 1);
        put_u32(&mut image, header + 4, if flags { 6 } else { 4 });
        for (field, value) in [
            (8, offset),
            (16, address + if split { 0x800 } else { 0 }),
            (24, address + if split { 0x800 } else { 0 }),
            (
                32,
                if bss {
                    0
                } else if file_tail {
                    0x800
                } else {
                    size
                },
            ),
            (40, size),
            (48, 0x1000),
        ] {
            put_u64(&mut image, header + field, value);
        }
    }
    image
}

fn check_prctl_elf_copyout(kind: &str, writable: bool, name: bool, output_offset: u64) {
    assert!(kvm_available("check_prctl_elf_copyout"));
    let image = prctl_elf_copyout_image(kind, writable, name, output_offset);
    let executable = NativeTestExecutable::new(&image, 0o700);
    let native = std::process::Command::new(executable.path())
        .output()
        .unwrap();
    assert_eq!(
        native.status.code(),
        Some(0),
        "native {kind}/{writable}/{name}/{output_offset}: {native:?}"
    );
    assert!(native.stderr.is_empty());
    let mut initial = vec![if kind.starts_with("bss") { 0 } else { 0x5a }; 4096];
    if kind == "file-bss" {
        initial[2048..].fill(0);
    }
    let succeeds = writable || kind.starts_with("bss");
    let before = if succeeds {
        vec![0x5a; 4096]
    } else {
        initial.clone()
    };
    let mut after = before.clone();
    let offset = usize::try_from(output_offset).unwrap();
    if succeeds {
        if name {
            after[offset..offset + 16].copy_from_slice(b"ABCDEFGHIJKLMNO\0");
        } else {
            after[offset..offset + 4].fill(0);
        }
        assert_ne!(after, before);
    }
    let mut expected = initial;
    expected.extend_from_slice(&before);
    expected.extend_from_slice(&0_i64.to_le_bytes());
    expected.extend_from_slice(
        &(if succeeds {
            0_i64
        } else {
            -i64::from(libc::EFAULT)
        })
        .to_le_bytes(),
    );
    expected.extend_from_slice(&after);
    assert_eq!(expected.len(), 3 * 4096 + 16);
    assert_eq!(
        native.stdout, expected,
        "fixed native oracle {kind}/{writable}/{name}/{output_offset}"
    );
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&image, "prctl-elf-copyout")
        .unwrap();
    let (status, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    assert_eq!(stdout.len(), expected.len());
    assert!(
        stdout == expected,
        "{kind}/{writable}/{name}/{output_offset} first differing byte {:?}",
        stdout
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected)
    );
}

macro_rules! prctl_elf_copyout_case {
    ($test:ident, $kind:literal, $writable:literal, $name:literal, $offset:literal) => {
        #[test]
        fn $test() {
            check_prctl_elf_copyout($kind, $writable, $name, $offset);
        }
    };
}

prctl_elf_copyout_case!(
    prctl_elf_copyout_single_r_pdeath_lower,
    "single",
    false,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_single_r_pdeath_upper,
    "single",
    false,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_single_r_name_lower,
    "single",
    false,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_single_r_name_upper,
    "single",
    false,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_single_rw_pdeath_lower,
    "single",
    true,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_single_rw_pdeath_upper,
    "single",
    true,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_single_rw_name_lower,
    "single",
    true,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_single_rw_name_upper,
    "single",
    true,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_r_pdeath_lower,
    "file-full",
    false,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_r_pdeath_upper,
    "file-full",
    false,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_r_name_lower,
    "file-full",
    false,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_r_name_upper,
    "file-full",
    false,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_rw_pdeath_lower,
    "file-full",
    true,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_rw_pdeath_upper,
    "file-full",
    true,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_rw_name_lower,
    "file-full",
    true,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_full_rw_name_upper,
    "file-full",
    true,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_r_pdeath_lower,
    "file-split",
    false,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_r_pdeath_upper,
    "file-split",
    false,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_r_name_lower,
    "file-split",
    false,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_r_name_upper,
    "file-split",
    false,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_rw_pdeath_lower,
    "file-split",
    true,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_rw_pdeath_upper,
    "file-split",
    true,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_rw_name_lower,
    "file-split",
    true,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_split_rw_name_upper,
    "file-split",
    true,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_r_pdeath_lower,
    "bss-full",
    false,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_r_pdeath_upper,
    "bss-full",
    false,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_r_name_lower,
    "bss-full",
    false,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_r_name_upper,
    "bss-full",
    false,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_rw_pdeath_lower,
    "bss-full",
    true,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_rw_pdeath_upper,
    "bss-full",
    true,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_rw_name_lower,
    "bss-full",
    true,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_full_rw_name_upper,
    "bss-full",
    true,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_r_pdeath_lower,
    "bss-split",
    false,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_r_pdeath_upper,
    "bss-split",
    false,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_r_name_lower,
    "bss-split",
    false,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_r_name_upper,
    "bss-split",
    false,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_rw_pdeath_lower,
    "bss-split",
    true,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_rw_pdeath_upper,
    "bss-split",
    true,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_rw_name_lower,
    "bss-split",
    true,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_bss_split_rw_name_upper,
    "bss-split",
    true,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_r_pdeath_lower,
    "file-bss",
    false,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_r_pdeath_upper,
    "file-bss",
    false,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_r_name_lower,
    "file-bss",
    false,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_r_name_upper,
    "file-bss",
    false,
    true,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_rw_pdeath_lower,
    "file-bss",
    true,
    false,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_rw_pdeath_upper,
    "file-bss",
    true,
    false,
    2304
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_rw_name_lower,
    "file-bss",
    true,
    true,
    128
);
prctl_elf_copyout_case!(
    prctl_elf_copyout_file_bss_rw_name_upper,
    "file-bss",
    true,
    true,
    2304
);

#[test]
fn repair_prctl_required_kvm_is_not_optional() {
    let directory = TestDirectory::new();
    let library = compile_c_program_with_args(
        &directory.0,
        "deny-kvm.so",
        PRCTL_DENY_KVM,
        &["-shared", "-fPIC", "-ldl"],
    );
    for test in [
        "native_and_kvm_prctl_names_keep_worker_local_and_format_procfs_leader_bytes",
        "kvm_direct_and_tool_match_prctl_identity_cell",
        "kvm_direct_and_tool_match_thp_disable_cell",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--test-threads=1", "--nocapture"])
            .env("LD_PRELOAD", &library)
            .env("REVERIE_REQUIRE_KVM", "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(101),
            "required test {test}: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("requires usable /dev/kvm"),
            "{output:?}"
        );
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SignalExitOrderTool {
    process: i32,
}

#[reverie::tool]
impl Tool for SignalExitOrderTool {
    type GlobalState = ();
    type ThreadState = ();

    fn new(pid: Pid, _config: &()) -> Self {
        Self {
            process: pid.as_raw(),
        }
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        Ok(guest.inject(syscall).await?)
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _global: &G,
        _thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        if tid.as_raw() != self.process {
            let mut bytes = [0; std::mem::size_of::<i32>()];
            let mut memory = SIGNAL_EXIT_MEMORY
                .lock()
                .expect("signal-exit memory lock poisoned");
            let memory = memory
                .as_mut()
                .expect("signal-exit memory was not installed");
            memory
                .read(SIGNAL_EXIT_CHILD_TID, &mut bytes)
                .expect("child TID word must be readable at signal exit");
            SIGNAL_EXIT_OBSERVED_TID.store(i32::from_le_bytes(bytes) as u64, Ordering::SeqCst);
            memory
                .write(
                    SIGNAL_EXIT_CHILD_TID,
                    &SIGNAL_EXIT_AFTER_CALLBACK.to_le_bytes(),
                )
                .expect("callback sentinel must be writable at signal exit");
        }
        Ok(())
    }
}

const SIGNAL_HOOK_MARKER: usize = 0x0800_0000;

#[derive(Default)]
struct SignalHookLog {
    signals: Mutex<Vec<i32>>,
    thread_starts: Mutex<Vec<i32>>,
}

impl SignalHookLog {
    fn signals(&self) -> Vec<i32> {
        self.signals
            .lock()
            .expect("signal hook log lock poisoned")
            .clone()
    }

    fn thread_starts(&self) -> Vec<i32> {
        self.thread_starts
            .lock()
            .expect("signal thread-start log lock poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for SignalHookLog {
    type Request = i64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, request: i64) {
        if request > 0 {
            self.signals
                .lock()
                .expect("signal hook log lock poisoned")
                .push(i32::try_from(request).unwrap());
        } else {
            self.thread_starts
                .lock()
                .expect("signal thread-start log lock poisoned")
                .push(i32::try_from(-request).unwrap());
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SignalHookTool;

#[reverie::tool]
impl Tool for SignalHookTool {
    type GlobalState = SignalHookLog;
    type ThreadState = u64;

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        let ordinal = {
            let calls = guest.thread_state_mut();
            *calls += 1;
            *calls
        };
        guest.send_rpc(i64::from(event.signal())).await;
        match ordinal {
            1 => {
                let mut info = event.siginfo();
                info[0..4].copy_from_slice(&libc::SIGUSR2.to_ne_bytes());
                Ok(Some(SignalEvent::new(libc::SIGUSR2, info, event.target())?))
            }
            2 => {
                let marker = AddrMut::from_raw(SIGNAL_HOOK_MARKER)
                    .expect("the signal-hook marker address is non-null");
                guest.memory().write_value(marker, &0x5a_u8)?;
                Ok(None)
            }
            3 => Ok(Some(event)),
            4 => {
                let marker = AddrMut::from_raw(SIGNAL_HOOK_MARKER + 1)
                    .expect("the second signal-hook marker address is non-null");
                guest.memory().write_value(marker, &0xa5_u8)?;
                Ok(None)
            }
            5 => {
                let mut info = event.siginfo();
                info[0..4].copy_from_slice(&libc::SIGWINCH.to_ne_bytes());
                Ok(Some(SignalEvent::new(
                    libc::SIGWINCH,
                    info,
                    event.target(),
                )?))
            }
            6 => Ok(Some(event)),
            7 => {
                let mut info = event.siginfo();
                info[0..4].copy_from_slice(&libc::SIGTERM.to_ne_bytes());
                Ok(Some(SignalEvent::new(libc::SIGTERM, info, event.target())?))
            }
            8..=9 => Ok(Some(event)),
            10 => {
                let child = guest.inject(Fork::new()).await?;
                assert!(
                    child > 0,
                    "the returning injection must complete before the refusal probe",
                );
                assert_eq!(
                    guest.inject(ExitGroup::new().with_status(77)).await,
                    Err(Errno::ENOSYS),
                    "a returning process action must not escape the signal-hook refusal",
                );
                Ok(Some(event))
            }
            _ => {
                panic!(
                    "unexpected signal-hook call {ordinal} for signal {} pid {} tid {}",
                    event.signal(),
                    guest.pid(),
                    guest.tid()
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SignalBoundaryInjectionTool;

#[reverie::tool]
impl Tool for SignalBoundaryInjectionTool {
    type GlobalState = SignalHookLog;
    type ThreadState = u64;

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        let ordinal = {
            let calls = guest.thread_state_mut();
            *calls += 1;
            *calls
        };
        guest.send_rpc(i64::from(event.signal())).await;

        let inject_clone = matches!(ordinal, 2 | 4 | 6 | 7);
        let child = if inject_clone {
            guest.inject(CloneSyscall::new()).await?
        } else {
            guest.inject(Fork::new()).await?
        };
        assert!(child > 0, "returning action {ordinal} must create a child");

        if ordinal == 3 {
            let second = guest.inject(CloneSyscall::new()).await?;
            assert!(second > 0 && second != child);
        }
        assert_eq!(
            guest.inject(ExitGroup::new().with_status(77)).await,
            Err(Errno::ENOSYS),
            "nonreturning injection must remain refused after action {ordinal}",
        );

        match ordinal {
            1 | 6 => Ok(Some(event)),
            3 | 7 => Ok(None),
            2 | 8 => {
                let mut info = event.siginfo();
                info[0..4].copy_from_slice(&libc::SIGUSR2.to_ne_bytes());
                Ok(Some(SignalEvent::new(libc::SIGUSR2, info, event.target())?))
            }
            4 | 5 => Ok(Some(event)),
            _ => panic!(
                "unexpected boundary-action hook {ordinal} for signal {} pid {} tid {}",
                event.signal(),
                guest.pid(),
                guest.tid(),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ForkWaitSignalTool;

#[reverie::tool]
impl Tool for ForkWaitSignalTool {
    type GlobalState = SignalHookLog;
    type ThreadState = u64;

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert_eq!(event.signal(), libc::SIGWINCH);
        let calls = guest.thread_state_mut();
        assert_eq!(*calls, 0, "the signal boundary must be filtered once");
        *calls = 1;
        guest.send_rpc(i64::from(event.signal())).await;

        let child = guest.inject(Fork::new()).await?;
        assert!(child > 0);
        let wait = Syscall::from_raw(
            Sysno::wait4,
            SyscallArgs::new(child as usize, 0, 0, 0, 0, 0),
        );
        assert_eq!(guest.inject(wait).await?, child);
        Ok(Some(event))
    }
}

#[derive(Debug, Default)]
struct PendingChildRefusalLog;

#[reverie::global_tool]
impl GlobalTool for PendingChildRefusalLog {
    type Request = ();
    type Response = ();
    type Config = bool;

    async fn receive_rpc(&self, _from: Pid, (): ()) {}
}

#[derive(Clone, Copy, Debug, Default)]
struct PendingChildRefusalTool;

#[reverie::tool]
impl Tool for PendingChildRefusalTool {
    type GlobalState = PendingChildRefusalLog;
    type ThreadState = ();

    fn subscriptions(_config: &bool) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::getpid]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        let child = if *guest.config() {
            let flags = (libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD) as usize;
            guest
                .inject(Syscall::from_raw(
                    Sysno::clone,
                    SyscallArgs::new(flags, (LOAD_ADDRESS + 0x1ff0) as usize, 0, 0, 0, 0),
                ))
                .await?
        } else {
            guest.inject(Fork::new()).await?
        };
        assert!(child > 0);
        assert_eq!(
            guest.inject(ExitGroup::new().with_status(77)).await,
            Err(Errno::ENOSYS),
        );
        Err(std::io::Error::other("forced error after pending-child refusal").into())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RtSignalBoundaryInjectionTool;

#[reverie::tool]
impl Tool for RtSignalBoundaryInjectionTool {
    type GlobalState = SignalHookLog;
    type ThreadState = u64;

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        let ordinal = {
            let calls = guest.thread_state_mut();
            *calls += 1;
            *calls
        };
        let registers = guest.regs().await;
        guest.send_rpc(i64::from(event.signal())).await;
        match ordinal {
            1 => {
                assert_eq!(registers.orig_rax, libc::SYS_rt_sigprocmask as u64);
                Ok(Some(event))
            }
            2 => {
                assert_eq!(registers.orig_rax, libc::SYS_rt_sigreturn as u64);
                let fork_child = guest.inject(Fork::new()).await?;
                let clone_child = guest.inject(CloneSyscall::new()).await?;
                assert!(fork_child > 0 && clone_child > 0 && fork_child != clone_child);
                assert_eq!(
                    guest.inject(ExitGroup::new().with_status(77)).await,
                    Err(Errno::ENOSYS),
                );
                Ok(Some(event))
            }
            _ => panic!(
                "unexpected rt_sigreturn hook {ordinal} for signal {} pid {} tid {}",
                event.signal(),
                guest.pid(),
                guest.tid(),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SignalBoundaryThreadInjectionTool;

#[reverie::tool]
impl Tool for SignalBoundaryThreadInjectionTool {
    type GlobalState = SignalHookLog;
    type ThreadState = u64;

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        if guest.tid() != guest.pid() {
            guest.send_rpc(-i64::from(guest.tid().as_raw())).await;
        }
        Ok(())
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert_eq!(event.signal(), libc::SIGWINCH);
        assert_eq!(
            event.target(),
            SignalTarget::Thread {
                pid: guest.pid(),
                tid: guest.tid(),
            }
        );
        let calls = guest.thread_state_mut();
        assert_eq!(*calls, 0, "the root signal boundary must be filtered once");
        *calls = 1;
        guest.send_rpc(i64::from(event.signal())).await;

        let flags = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD) as usize;
        let clone = Syscall::from_raw(
            Sysno::clone,
            SyscallArgs::new(flags, (LOAD_ADDRESS + 0x1ff0) as usize, 0, 0, 0, 0),
        );
        let child_tid = guest.inject(clone).await?;
        assert!(child_tid > 0, "thread injection must return the child tid");
        Ok(Some(event))
    }
}

#[test]
fn structured_tool_replaces_then_suppresses_at_consecutive_return_boundaries() {
    if !kvm_available("structured signal Tool hook test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "structured-signal-tool",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define HOOK_MARKER ((volatile unsigned char *)UINT64_C(0x08000000))

static volatile sig_atomic_t usr1_calls;
static volatile sig_atomic_t usr2_calls;
static volatile sig_atomic_t urg_calls;
static volatile sig_atomic_t handler_failure;

static void usr1_handler(int signo, siginfo_t *info, void *context) {
  (void)info;
  (void)context;
  ++usr1_calls;
  if (signo != SIGUSR1) handler_failure = 10;
}

static void usr2_handler(int signo, siginfo_t *info, void *context) {
  (void)context;
  ++usr2_calls;
  if (signo != SIGUSR2 || info == 0 || info->si_signo != SIGUSR2 ||
      info->si_code != SI_USER) {
    handler_failure = 11;
    return;
  }
  sigset_t current;
  if (sigprocmask(SIG_SETMASK, 0, &current) != 0 ||
      sigismember(&current, SIGUSR2) != 1 ||
      sigismember(&current, SIGTERM) != 1 ||
      sigismember(&current, SIGURG) != 1 ||
      sigismember(&current, SIGUSR1) != 0 ||
      sigismember(&current, SIGWINCH) != 0) {
    handler_failure = 12;
  }
}

static void urg_handler(int signo) {
  ++urg_calls;
  if (signo != SIGURG) handler_failure = 13;
}

static int install(int signo, void (*handler)(int, siginfo_t *, void *),
                   int masked) {
  struct sigaction action = {0};
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  if (masked != 0) sigaddset(&action.sa_mask, masked);
  if (signo == SIGUSR2) sigaddset(&action.sa_mask, SIGURG);
  return sigaction(signo, &action, 0);
}

int main(void) {
  pid_t original_pid = getpid();
  void *mapping = mmap((void *)HOOK_MARKER, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapping != (void *)HOOK_MARKER) return 20;
  if (install(SIGUSR1, usr1_handler, SIGWINCH) != 0) return 21;
  if (install(SIGUSR2, usr2_handler, SIGTERM) != 0) return 22;
  if (signal(SIGURG, urg_handler) == SIG_ERR) return 23;

  sigset_t pending;
  sigemptyset(&pending);
  sigaddset(&pending, SIGUSR1);
  sigaddset(&pending, SIGTERM);
  sigaddset(&pending, SIGURG);
  if (sigprocmask(SIG_BLOCK, &pending, 0) != 0) return 24;
  if (kill(getpid(), SIGUSR1) != 0) return 25;
  if (kill(getpid(), SIGTERM) != 0) return 26;
  if (kill(getpid(), SIGURG) != 0) return 33;
  if (sigprocmask(SIG_UNBLOCK, &pending, 0) != 0) return 27;

  // The second Tool callback runs on the first handler's rt_sigreturn
  // continuation and writes this byte while suppressing SIGTERM. No later
  // syscall is needed to make the marker visible.
  if (*HOOK_MARKER != 0x5a) return 28;
  if (handler_failure != 0) return handler_failure;
  if (usr1_calls != 0) return 29;
  if (usr2_calls != 1) return 30;
  if (urg_calls != 1) return 34;
  // An unblocked default-fatal self-signal must reach the Tool before its
  // disposition is applied, so the Tool can suppress it at this boundary.
  if (kill(getpid(), SIGINT) != 0) return 31;
  if (*(HOOK_MARKER + 1) != 0xa5) return 32;

  // Replacing the first event with a default-ignored signal must not let user
  // code run before the next caught event at the same return boundary.
  sigemptyset(&pending);
  sigaddset(&pending, SIGINT);
  sigaddset(&pending, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &pending, 0) != 0) return 35;
  if (kill(getpid(), SIGINT) != 0) return 36;
  if (kill(getpid(), SIGUSR1) != 0) return 37;
  if (sigprocmask(SIG_UNBLOCK, &pending, 0) != 0) return 38;
  if (usr1_calls != 1) return 39;

  // A replacement that is blocked under its new number stays pending, while
  // the next eligible caught event is selected before user code resumes.
  sigemptyset(&pending);
  sigaddset(&pending, SIGINT);
  sigaddset(&pending, SIGUSR1);
  sigaddset(&pending, SIGTERM);
  if (sigprocmask(SIG_BLOCK, &pending, 0) != 0) return 40;
  if (kill(getpid(), SIGINT) != 0) return 41;
  if (kill(getpid(), SIGUSR1) != 0) return 42;
  sigdelset(&pending, SIGTERM);
  if (sigprocmask(SIG_UNBLOCK, &pending, 0) != 0) return 43;
  if (usr1_calls != 2) return 44;
  sigset_t still_pending;
  if (sigpending(&still_pending) != 0 ||
      sigismember(&still_pending, SIGTERM) != 1) return 45;

  // Like ptrace, the virtual Tool observes an explicit SIG_IGN and a
  // default-ignored signal exactly once before disposition discards them.
  if (signal(SIGUSR2, SIG_IGN) == SIG_ERR) return 46;
  if (kill(getpid(), SIGUSR2) != 0) return 47;
  if (usr2_calls != 1) return 48;
  if (kill(getpid(), SIGWINCH) != 0) return 49;
  // The Tool's final callback injects fork before probing the nonreturning
  // refusal. The injected child leaves without duplicating the parent test.
  if (getpid() != original_pid) _exit(0);
  if (usr1_calls != 2 || usr2_calls != 1 || urg_calls != 1) return 50;
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (log, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<SignalHookTool>((), true))
            .unwrap();
    let signals = log.signals();
    assert_eq!(
        code,
        0,
        "structured signal Tool guest failed with code {code}; signals={signals:?}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(
        signals,
        vec![
            libc::SIGUSR1,
            libc::SIGTERM,
            libc::SIGURG,
            libc::SIGINT,
            libc::SIGINT,
            libc::SIGUSR1,
            libc::SIGINT,
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGWINCH,
        ]
    );
}

#[test]
fn returning_signal_hook_actions_restore_every_delivery_outcome() {
    if !kvm_available("returning signal-hook action boundary test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "signal-hook-return-boundary",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t usr1_calls;
static volatile sig_atomic_t urg_calls;
static volatile sig_atomic_t handler_failure;
static pid_t original_pid;

static void caught(int signo) {
  if (signo == SIGUSR1) ++usr1_calls;
  else if (signo == SIGURG) ++urg_calls;
  else handler_failure = 20;
}

static void leave_injected_child(void) {
  if (getpid() != original_pid) syscall(SYS_exit_group, 0);
}

int main(void) {
  original_pid = getpid();
  if (signal(SIGUSR1, caught) == SIG_ERR) return 21;
  if (signal(SIGURG, caught) == SIG_ERR) return 22;

  sigset_t usr2;
  sigemptyset(&usr2);
  sigaddset(&usr2, SIGUSR2);
  if (sigprocmask(SIG_BLOCK, &usr2, 0) != 0) return 23;

  if (kill(getpid(), SIGWINCH) != 0) return 24;
  leave_injected_child();

  if (kill(getpid(), SIGUSR1) != 0) return 25;
  leave_injected_child();
  if (usr1_calls != 0) return 26;

  // Suppression after two returning actions is followed immediately by the
  // next caught event at the same sigprocmask return boundary.
  sigset_t pair;
  sigemptyset(&pair);
  sigaddset(&pair, SIGUSR1);
  sigaddset(&pair, SIGURG);
  if (sigprocmask(SIG_BLOCK, &pair, 0) != 0) return 27;
  if (kill(getpid(), SIGUSR1) != 0) return 28;
  if (kill(getpid(), SIGURG) != 0) return 29;
  if (sigprocmask(SIG_UNBLOCK, &pair, 0) != 0) return 30;
  leave_injected_child();
  if (usr1_calls != 0 || urg_calls != 1) return 31;

  if (kill(getpid(), SIGUSR1) != 0) return 32;
  leave_injected_child();
  if (usr1_calls != 1) return 33;

  if (kill(getpid(), SIGWINCH) != 0) return 34;
  leave_injected_child();
  if (kill(getpid(), SIGUSR1) != 0) return 35;
  leave_injected_child();
  if (usr1_calls != 1) return 36;

  if (kill(getpid(), SIGUSR1) != 0) return 37;
  leave_injected_child();
  if (usr1_calls != 1) return 38;
  sigset_t pending;
  if (sigpending(&pending) != 0 || sigismember(&pending, SIGUSR2) != 1) return 39;
  if (handler_failure != 0) return handler_failure;
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (log, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<SignalBoundaryInjectionTool>((), true),
    )
    .unwrap();
    assert_eq!(
        code,
        0,
        "signal-boundary action guest failed with code {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(
        log.signals(),
        vec![
            libc::SIGWINCH,
            libc::SIGUSR1,
            libc::SIGUSR1,
            libc::SIGURG,
            libc::SIGUSR1,
            libc::SIGWINCH,
            libc::SIGUSR1,
            libc::SIGUSR1,
        ],
    );
}

#[test]
fn signal_hook_can_fork_and_wait_before_returning() {
    if !kvm_available("same-callback signal-hook fork/wait test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "signal-hook-fork-wait",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  pid_t original_pid = getpid();
  if (kill(original_pid, SIGWINCH) != 0) return 20;
  if (getpid() != original_pid) syscall(SYS_exit_group, 0);
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (log, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<ForkWaitSignalTool>((), true),
    )
    .unwrap();
    assert_eq!(
        code,
        0,
        "same-callback fork/wait guest failed with code {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(log.signals(), vec![libc::SIGWINCH]);
}

#[test]
fn pending_fork_and_thread_refuse_nonreturning_injection_without_teardown_hang() {
    if !kvm_available("pending-child nonreturning-injection refusal test") {
        return;
    }

    let code = [
        0xb8,
        libc::SYS_getpid as u8,
        0,
        0,
        0, // mov eax, SYS_getpid
        0x0f,
        0x05, // syscall
        0x0f,
        0x0b, // ud2: the top-level Tool error must stop before guest re-entry
    ];
    for thread in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(
                &static_elf(&code),
                if thread {
                    "/bin/pending-thread-refusal-test"
                } else {
                    "/bin/pending-fork-refusal-test"
                },
            )
            .unwrap();
        let error = futures::executor::block_on(
            backend.run_static_elf_with_tool::<PendingChildRefusalTool>(thread, true),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("forced error after pending-child refusal"),
            "unexpected pending-child callback error: {error}",
        );
    }
}

#[test]
fn returning_thread_action_at_signal_boundary_restores_parent_continuation() {
    if !kvm_available("returning CLONE_THREAD signal-boundary test") {
        return;
    }

    fn append_exit(code: &mut Vec<u8>, group: bool, status: u32) {
        let number = if group {
            libc::SYS_exit_group as u32
        } else {
            libc::SYS_exit as u32
        };
        code.push(0xb8); // mov eax, syscall number
        code.extend_from_slice(&number.to_le_bytes());
        code.push(0xbf); // mov edi, status
        code.extend_from_slice(&status.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]); // syscall; ud2
    }

    fn patch_jump(code: &mut [u8], operand: usize, target: usize) {
        let displacement = i32::try_from(target as isize - (operand + 4) as isize).unwrap();
        code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
    }

    let mut code = vec![
        0x49, 0x89, 0xe7, // mov r15, rsp
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0x41, 0x89, 0xc6, // mov r14d, eax
        0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, SYS_gettid
        0x0f, 0x05, // syscall
        0x41, 0x89, 0xc5, // mov r13d, eax
        0xb8, 0xea, 0x00, 0x00, 0x00, // mov eax, SYS_tgkill
        0x44, 0x89, 0xf7, // mov edi, r14d
        0x44, 0x89, 0xee, // mov esi, r13d
        0xba, 0x1c, 0x00, 0x00, 0x00, // mov edx, SIGWINCH
        0x0f, 0x05, // syscall
        0x41, 0x89, 0xc4, // mov r12d, eax
        0x4c, 0x39, 0xfc, // cmp rsp, r15
        0x0f, 0x85, 0, 0, 0, 0, // jne child
    ];
    let child_jump = code.len() - 4;
    code.extend_from_slice(&[
        0x45, 0x85, 0xe4, // test r12d, r12d
        0x0f, 0x85, 0, 0, 0, 0, // jne failure
    ]);
    let failure_jump = code.len() - 4;
    append_exit(&mut code, true, 0);

    let child = code.len();
    patch_jump(&mut code, child_jump, child);
    append_exit(&mut code, false, 0);

    let failure = code.len();
    patch_jump(&mut code, failure_jump, failure);
    append_exit(&mut code, true, 91);

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(
            &static_elf(&code),
            "/bin/signal-boundary-thread-injection-test",
        )
        .unwrap();
    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<SignalBoundaryThreadInjectionTool>((), true),
    )
    .unwrap();
    assert_eq!(
        exit_code,
        0,
        "thread boundary guest failed with code {exit_code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(log.signals(), vec![libc::SIGWINCH]);
    let thread_starts = log.thread_starts();
    assert_eq!(
        thread_starts.len(),
        1,
        "the injected Tool thread must pass its start gate exactly once: {thread_starts:?}",
    );
}
#[test]
fn returning_actions_at_rt_sigreturn_restore_the_interrupted_continuation() {
    if !kvm_available("rt_sigreturn returning action boundary test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "rt-signal-hook-return-boundary",
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t usr1_calls;
static volatile sig_atomic_t usr2_calls;
static pid_t original_pid;

static void caught(int signo) {
  if (signo == SIGUSR1) ++usr1_calls;
  else if (signo == SIGUSR2) ++usr2_calls;
  else syscall(SYS_exit_group, 20);
}

int main(void) {
  original_pid = getpid();
  if (signal(SIGUSR1, caught) == SIG_ERR) return 21;
  if (signal(SIGUSR2, caught) == SIG_ERR) return 22;
  sigset_t both;
  sigemptyset(&both);
  sigaddset(&both, SIGUSR1);
  sigaddset(&both, SIGUSR2);
  if (sigprocmask(SIG_BLOCK, &both, 0) != 0) return 23;
  if (kill(getpid(), SIGUSR1) != 0) return 24;
  if (kill(getpid(), SIGUSR2) != 0) return 25;
  if (sigprocmask(SIG_UNBLOCK, &both, 0) != 0) return 26;
  // Both injected children resume from the restored context after the
  // rt_sigreturn-selected second event and leave without replaying this call.
  if (getpid() != original_pid) syscall(SYS_exit_group, 0);
  if (usr1_calls != 1 || usr2_calls != 1) return 27;
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (log, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<RtSignalBoundaryInjectionTool>((), true),
    )
    .unwrap();
    assert_eq!(
        code,
        0,
        "rt_sigreturn boundary guest failed with code {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(log.signals(), vec![libc::SIGUSR1, libc::SIGUSR2]);
}

#[test]
fn fatal_signal_at_rt_sigreturn_clears_child_tid_before_tool_exit() {
    if !kvm_available("fatal rt_sigreturn CHILD_CLEARTID ordering test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "signal-exit-cleartid",
        r#"
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TID_WORD ((int *)UINT64_C(0x08003000))
static _Alignas(16) unsigned char child_stack[1 << 20];

static void usr1_handler(int signo) {
  if (signo != SIGUSR1) syscall(SYS_exit, 41);
  long tid = syscall(SYS_gettid);
  if (syscall(SYS_tgkill, getpid(), tid, SIGTERM) != 0) {
    syscall(SYS_exit, 42);
  }
}

static int child_main(void *unused) {
  (void)unused;
  long tid = syscall(SYS_gettid);
  if (*TID_WORD != tid) syscall(SYS_exit, 43);
  if (syscall(SYS_tgkill, getpid(), tid, SIGUSR1) != 0) {
    syscall(SYS_exit, 44);
  }
  // SIGTERM is queued while the SIGUSR1 handler blocks it. It must terminate
  // this thread group on the rt_sigreturn boundary before this instruction.
  syscall(SYS_exit, 45);
  return 45;
}

int main(void) {
  void *mapped = mmap(TID_WORD, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapped != (void *)TID_WORD) return 20;
  *TID_WORD = 0x7fffffff;

  struct sigaction action = {0};
  action.sa_handler = usr1_handler;
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGTERM);
  if (sigaction(SIGUSR1, &action, 0) != 0) return 21;

  int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
              CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_SETTID |
              CLONE_CHILD_CLEARTID;
  int child = clone(child_main, child_stack + sizeof(child_stack), flags,
                    0, 0, 0, TID_WORD);
  if (child < 0) return 22;
  for (;;) __asm__ volatile("pause");
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    SIGNAL_EXIT_OBSERVED_TID.store(u64::MAX, Ordering::SeqCst);
    *SIGNAL_EXIT_MEMORY
        .lock()
        .expect("signal-exit memory lock poisoned") = Some(backend.memory().unwrap().clone());

    let result = futures::executor::block_on(
        backend.run_static_elf_with_tool::<SignalExitOrderTool>((), true),
    );
    let mut final_bytes = [0; std::mem::size_of::<i32>()];
    SIGNAL_EXIT_MEMORY
        .lock()
        .expect("signal-exit memory lock poisoned")
        .as_ref()
        .expect("signal-exit memory was not installed")
        .read(SIGNAL_EXIT_CHILD_TID, &mut final_bytes)
        .unwrap();
    *SIGNAL_EXIT_MEMORY
        .lock()
        .expect("signal-exit memory lock poisoned") = None;
    let (_, code, stdout, stderr) = result.unwrap();
    assert_eq!(code, 128 + libc::SIGTERM);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(SIGNAL_EXIT_OBSERVED_TID.load(Ordering::SeqCst), 0);
    assert_eq!(i32::from_le_bytes(final_bytes), SIGNAL_EXIT_AFTER_CALLBACK);
}

const TERMINAL_RECEIPT_CHILD_TID: u64 = 0x0800_3000;
static TERMINAL_RECEIPT_MEMORY: Mutex<Option<reverie_kvm::GuestMemory>> = Mutex::new(None);

/// Reserves a permit for a worker's `SYS_exit`, as Detcore does for exit
/// boundaries, and records the worker's CLONE_CHILD_CLEARTID word at the
/// moment its terminal receipt is published.
#[derive(Default)]
struct TerminalReceiptGlobal {
    control: Mutex<Option<reverie::BackendSignalControl>>,
    permit: Mutex<Option<reverie::SignalDeliveryPermit>>,
    receipts: Mutex<Vec<(reverie::SignalBoundaryOutcome, i32)>>,
}

#[reverie::global_tool]
impl GlobalTool for TerminalReceiptGlobal {
    type Request = reverie::SignalTaskIdentity;
    type Response = ();
    type Config = ();

    fn install_backend_signal_control(
        &self,
        control: Option<reverie::BackendSignalControl>,
    ) -> Result<reverie::BackendSignalControlMode, reverie::Error> {
        *self.control.lock().unwrap() = Some(control.expect("real run capability"));
        Ok(reverie::BackendSignalControlMode::ToolControlled)
    }

    async fn receive_rpc(&self, _from: Pid, task: reverie::SignalTaskIdentity) {
        let permit = reverie::SignalDeliveryPermit {
            task,
            sequence: 1,
            site: None,
        };
        assert!(self.permit.lock().unwrap().is_none());
        self.control
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .process
            .reserve_delivery(permit)
            .unwrap();
        *self.permit.lock().unwrap() = Some(permit);
    }

    fn authorize_backend_signal_boundary(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Result<Option<reverie::SignalDeliveryPermit>, reverie::Error> {
        Ok(self
            .permit
            .lock()
            .unwrap()
            .filter(|permit| permit.task == task))
    }

    async fn on_backend_signal_boundary(
        &self,
        receipt: reverie::SignalBoundaryReceipt,
    ) -> Result<(), reverie::Error> {
        assert_eq!(self.permit.lock().unwrap().take(), Some(receipt.permit));
        let mut bytes = [0; std::mem::size_of::<i32>()];
        TERMINAL_RECEIPT_MEMORY
            .lock()
            .expect("terminal-receipt memory lock poisoned")
            .as_ref()
            .expect("terminal-receipt memory was not installed")
            .read(TERMINAL_RECEIPT_CHILD_TID, &mut bytes)
            .expect("child TID word must be readable at the terminal receipt");
        self.receipts
            .lock()
            .unwrap()
            .push((receipt.outcome, i32::from_le_bytes(bytes)));
        Ok(())
    }
}

#[derive(Default)]
struct TerminalReceiptTool;

#[reverie::tool]
impl Tool for TerminalReceiptTool {
    type GlobalState = TerminalReceiptGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, reverie::Error> {
        if call.number() == Sysno::exit && guest.tid() != guest.pid() {
            let task = guest
                .signal_task_identity()
                .expect("a started worker has a task identity");
            guest.send_rpc(task).await;
        }
        guest.tail_inject(call).await
    }
}

/// A Tool can wake a `pthread_join` waiter from a worker's non-group terminal
/// receipt, as Detcore does. Linux clears CLONE_CHILD_CLEARTID in `mm_release`
/// before the exit is observable, so the word must already be zero when that
/// receipt is published. A stale TID there makes glibc's join loop retry
/// `FUTEX_WAIT` a host-timing-dependent number of times.
#[test]
fn worker_exit_clears_child_tid_before_terminal_receipt() {
    if !kvm_available("worker exit CHILD_CLEARTID terminal receipt ordering test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "worker-exit-cleartid-receipt",
        r#"
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TID_WORD ((volatile int *)UINT64_C(0x08003000))
static _Alignas(16) unsigned char child_stack[1 << 20];

static int child_main(void *unused) {
  (void)unused;
  if (*TID_WORD != syscall(SYS_gettid)) syscall(SYS_exit, 43);
  syscall(SYS_exit, 0);
  return 44;
}

int main(void) {
  void *mapped = mmap((void *)TID_WORD, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapped != (void *)TID_WORD) return 20;
  *TID_WORD = 0x7fffffff;

  int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
              CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_SETTID |
              CLONE_CHILD_CLEARTID;
  int child = clone(child_main, child_stack + sizeof(child_stack), flags,
                    0, 0, 0, (int *)TID_WORD);
  if (child < 0) return 22;
  while (*TID_WORD != 0) syscall(SYS_sched_yield);
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    *TERMINAL_RECEIPT_MEMORY
        .lock()
        .expect("terminal-receipt memory lock poisoned") = Some(backend.memory().unwrap().clone());

    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<TerminalReceiptTool>((), true),
    );
    *TERMINAL_RECEIPT_MEMORY
        .lock()
        .expect("terminal-receipt memory lock poisoned") = None;
    let completion = completion.unwrap();
    let global = completion.global_state;
    let (status, stdout, stderr) = completion.result.unwrap();
    assert_eq!(status, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(global.permit.into_inner().unwrap().is_none());
    assert_eq!(
        global.receipts.into_inner().unwrap(),
        vec![(
            reverie::SignalBoundaryOutcome::Terminated {
                group: false,
                wait_status: 0,
            },
            0,
        )],
    );
}

#[derive(Default)]
struct RestartSignalLog {
    callbacks: Mutex<Vec<u8>>,
}

impl RestartSignalLog {
    fn callbacks(&self) -> Vec<u8> {
        self.callbacks
            .lock()
            .expect("restart signal log lock poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for RestartSignalLog {
    type Request = u8;
    type Response = ();
    type Config = u8;

    async fn receive_rpc(&self, _from: Pid, callback: u8) {
        self.callbacks
            .lock()
            .expect("restart signal log lock poisoned")
            .push(callback);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RestartSignalTool;

#[reverie::tool]
impl Tool for RestartSignalTool {
    type GlobalState = RestartSignalLog;
    type ThreadState = (u64, u64);

    fn subscriptions(_config: &u8) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscall(Sysno::getpid);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert!(matches!(syscall, Syscall::Getpid(_)));
        let ordinal = {
            let calls = guest.thread_state_mut();
            calls.0 += 1;
            calls.0
        };
        guest.send_rpc(0).await;
        if ordinal == 1 {
            let mut info = [0; reverie::SIGNAL_INFO_SIZE];
            info[0..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
            info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
            let event = SignalEvent::new(
                libc::SIGUSR1,
                info,
                SignalTarget::Thread {
                    pid: guest.pid(),
                    tid: guest.tid(),
                },
            )?;
            guest.defer_signal_delivery(event).await?;
            if *guest.config() >= 9 {
                let mut info = [0; reverie::SIGNAL_INFO_SIZE];
                info[0..4].copy_from_slice(&libc::SIGUSR2.to_ne_bytes());
                info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
                let event = SignalEvent::new(
                    libc::SIGUSR2,
                    info,
                    SignalTarget::Thread {
                        pid: guest.pid(),
                        tid: guest.tid(),
                    },
                )?;
                guest.defer_signal_delivery(event).await?;
            }
            if *guest.config() == 8 {
                return Ok(3);
            }
            return Err(Errno::ERESTARTSYS.into());
        }
        assert_eq!(ordinal, 2, "a syscall restarted more than once");
        Ok(77)
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        guest.send_rpc(1).await;
        let signal_ordinal = {
            let calls = guest.thread_state_mut();
            calls.1 += 1;
            calls.1
        };
        let replacement = match *guest.config() {
            3 => return Ok(None),
            4 => libc::SIGWINCH,
            5..=7 => libc::SIGUSR2,
            9 | 12 if signal_ordinal == 1 => return Ok(None),
            10 if signal_ordinal == 1 => libc::SIGWINCH,
            11 if signal_ordinal == 1 => libc::SIGTERM,
            _ => return Ok(Some(event)),
        };
        let mut info = event.siginfo();
        info[0..4].copy_from_slice(&replacement.to_ne_bytes());
        Ok(Some(SignalEvent::new(replacement, info, event.target())?))
    }
}

#[test]
fn pending_signal_applies_linux_erestartsys_policy_after_the_tool_hook() {
    if !kvm_available("signal-aware ERESTARTSYS test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "signal-aware-erestartsys",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t usr1_calls;
static volatile sig_atomic_t usr2_calls;

static void usr1_handler(int signo) {
  if (signo == SIGUSR1) ++usr1_calls;
}

static void usr2_handler(int signo) {
  if (signo == SIGUSR2) ++usr2_calls;
}

static int install(int signo, void (*handler)(int), int flags) {
  struct sigaction action = {0};
  action.sa_handler = handler;
  action.sa_flags = flags;
  sigemptyset(&action.sa_mask);
  return sigaction(signo, &action, 0);
}

int main(int argc, char **argv) {
  if (argc != 2) return 20;
  int mode = atoi(argv[1]);
  int usr1_flags = (mode == 2 || mode == 6) ? SA_RESTART : 0;
  int usr2_flags = (mode == 7 || mode == 12) ? SA_RESTART : 0;
  if (install(SIGUSR1, usr1_handler, usr1_flags) != 0) return 21;
  if (install(SIGUSR2, usr2_handler, usr2_flags) != 0) return 22;
  if (mode == 5 || mode == 11) {
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, mode == 5 ? SIGUSR2 : SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blocked, 0) != 0) return 23;
  }

  errno = 0;
  long result = syscall(SYS_getpid);
  int saved_errno = errno;
  if (mode == 1 || mode == 6 || (mode >= 9 && mode <= 11)) {
    if (result != -1 || saved_errno != EINTR) return 24;
  } else if (mode == 8) {
    if (result != 3) return 25;
  } else if (result != 77) {
    return 26;
  }

  if (mode == 1 || mode == 2 || mode == 8) {
    if (usr1_calls != 1 || usr2_calls != 0) return 27;
  } else if (mode == 6 || mode == 7 || (mode >= 9 && mode <= 12)) {
    if (usr1_calls != 0 || usr2_calls != 1) return 28;
  } else if (usr1_calls != 0 || usr2_calls != 0) {
    return 29;
  }
  if (mode == 5 || mode == 11) {
    sigset_t pending;
    int expected = mode == 5 ? SIGUSR2 : SIGTERM;
    if (sigpending(&pending) != 0 || sigismember(&pending, expected) != 1) return 30;
  }
  return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    for (mode, expected_callbacks) in [
        (1_u8, vec![0, 1]),
        (2, vec![0, 1, 0]),
        (3, vec![0, 1, 0]),
        (4, vec![0, 1, 0]),
        (5, vec![0, 1, 0]),
        (6, vec![0, 1]),
        (7, vec![0, 1, 0]),
        (8, vec![0, 1]),
        (9, vec![0, 1, 1]),
        (10, vec![0, 1, 1]),
        (11, vec![0, 1, 1]),
        (12, vec![0, 1, 1, 0]),
    ] {
        let argument = mode.to_string();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable, &argument],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (log, code, stdout, stderr) = futures::executor::block_on(
            backend.run_static_elf_with_tool::<RestartSignalTool>(mode, true),
        )
        .unwrap();
        assert_eq!(
            code,
            0,
            "signal-aware ERESTARTSYS mode {mode} failed; stdout={}; stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        );
        assert_eq!(log.callbacks(), expected_callbacks, "mode {mode}");
    }
}

#[test]
fn static_elf_rt_sigreturn_requires_only_consumed_prefix() {
    if !kvm_available("static_elf_rt_sigreturn_requires_only_consumed_prefix") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "static_elf_rt_sigreturn_requires_only_consumed_prefix",
        r#"#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static unsigned char *mapping;
static size_t accessible;
static volatile sig_atomic_t handled;

static void handler(int signo, siginfo_t *info, void *context_raw) {
    (void)info;
    if (signo != SIGUSR1) _exit(80);
    unsigned char *frame = mapping + 4096 - accessible;
    memcpy(frame, (unsigned char *)context_raw - 8, accessible);
    memset(frame + 232, 0, 8);
    handled = 1;
    __asm__ volatile("mov %0, %%rsp\n\tmov $15, %%rax\n\tsyscall\n\tud2"
                     : : "r"(frame + 8) : "rax", "rcx", "r11", "memory");
    __builtin_unreachable();
}

int main(int argc, char **argv) {
    if (argc != 2 || sysconf(_SC_PAGESIZE) != 4096) return 81;
    accessible = strtoul(argv[1], 0, 10);
    if (accessible != 440 && accessible != 312 && accessible != 311) return 82;
    mapping = mmap(0, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || mprotect(mapping + 4096, 4096, PROT_NONE)) return 83;
    struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0)) return 84;
    long result = syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
    if (result != 0 || handled != 1) return 85;
    puts("resumed result=0 handled=1");
    return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    for (argument, expected_code, expected_stdout) in [
        ("440", 0, "resumed result=0 handled=1\n"),
        ("312", 0, "resumed result=0 handled=1\n"),
        ("311", 128 + libc::SIGSEGV, ""),
    ] {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        let argv = if argument.is_empty() {
            vec![executable]
        } else {
            vec![executable, argument]
        };
        backend
            .install_static_elf_with_context(&image, &argv, &["PATH=/usr/bin:/bin"], &directory.0)
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(
            code, expected_code,
            "case {argument}: stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, expected_stdout.as_bytes(), "case {argument}");
        assert!(stderr.is_empty(), "case {argument}: {stderr:?}");
        let expected_status = if argument == "311" {
            ExitStatus::from_raw(libc::SIGSEGV | 0x80)
        } else {
            ExitStatus::SUCCESS
        };
        check_typed_signal_status(
            &image,
            &argv,
            &directory,
            expected_status,
            expected_stdout.as_bytes(),
        );
    }
}

#[test]
fn static_elf_rt_sigpending_accepts_short_output_sizes() {
    if !kvm_available("static_elf_rt_sigpending_accepts_short_output_sizes") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "static_elf_rt_sigpending_accepts_short_output_sizes",
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &blocked, 0) || kill(getpid(), SIGUSR1)) return 81;
    uintptr_t invalid_addresses[] = {0, 1, UINTPTR_MAX};
    size_t sizes[] = {0, 1, 9};
    for (size_t address_index = 0; address_index < 3; ++address_index) {
        for (size_t size_index = 0; size_index < 3; ++size_index) {
            errno = 0;
            long result = syscall(SYS_rt_sigpending, invalid_addresses[address_index], sizes[size_index]);
            int expected_error = size_index == 0 ? 0 : size_index == 1 ? EFAULT : EINVAL;
            if (result != (size_index == 0 ? 0 : -1) || errno != expected_error) return 83;
        }
    }
    for (size_t size = 0; size <= 9; ++size) {
        unsigned char actual[16], expected[16];
        memset(actual, 0xa5, sizeof(actual));
        memset(expected, 0xa5, sizeof(expected));
        if (size <= 8) {
            memset(expected + 3, 0, size);
            if (size >= 2) expected[4] = 2;
        }
        errno = 0;
        long result = syscall(SYS_rt_sigpending, actual + 3, size);
        int error = errno;
        printf("size=%zu result=%ld errno=%d bytes=", size, result, error);
        for (size_t index = 0; index < sizeof(actual); ++index) printf("%02x", actual[index]);
        puts("");
        if (result != (size <= 8 ? 0 : -1) || error != (size <= 8 ? 0 : EINVAL)
            || memcmp(actual, expected, sizeof(actual))) return 82;
    }
    return 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    {
        let (argument, expected_code, expected_stdout) = (
            "",
            0,
            "size=0 result=0 errno=0 bytes=a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5\nsize=1 result=0 errno=0 bytes=a5a5a500a5a5a5a5a5a5a5a5a5a5a5a5\nsize=2 result=0 errno=0 bytes=a5a5a50002a5a5a5a5a5a5a5a5a5a5a5\nsize=3 result=0 errno=0 bytes=a5a5a5000200a5a5a5a5a5a5a5a5a5a5\nsize=4 result=0 errno=0 bytes=a5a5a500020000a5a5a5a5a5a5a5a5a5\nsize=5 result=0 errno=0 bytes=a5a5a50002000000a5a5a5a5a5a5a5a5\nsize=6 result=0 errno=0 bytes=a5a5a5000200000000a5a5a5a5a5a5a5\nsize=7 result=0 errno=0 bytes=a5a5a500020000000000a5a5a5a5a5a5\nsize=8 result=0 errno=0 bytes=a5a5a50002000000000000a5a5a5a5a5\nsize=9 result=-1 errno=22 bytes=a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5\n",
        );
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        let argv = if argument.is_empty() {
            vec![executable]
        } else {
            vec![executable, argument]
        };
        backend
            .install_static_elf_with_context(&image, &argv, &["PATH=/usr/bin:/bin"], &directory.0)
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(
            code, expected_code,
            "case {argument}: stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, expected_stdout.as_bytes(), "case {argument}");
        assert!(stderr.is_empty(), "case {argument}: {stderr:?}");
    }
}

const RESTORER_ADDRESS_SOURCE: &str = r#"#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int returning;

__attribute__((naked)) static void valid_restorer(void) {
    __asm__ volatile("mov $15, %rax; syscall; ud2");
}

static void handler(int number) {
    if (number != SIGUSR1 || write(1, "handler\n", 8) != 8) _exit(81);
    if (!returning) _exit(42);
}

int main(int argc, char **argv) {
    if (argc != 2) return 82;
    returning = strcmp(argv[1], "valid-return") == 0;
    struct {
        void (*handler)(int);
        uint64_t flags;
        uintptr_t restorer;
        uint64_t mask;
    } action = {handler, UINT64_C(0x04000000),
        returning ? (uintptr_t)valid_restorer : strtoull(argv[1], NULL, 0), 0};
    if (syscall(SYS_rt_sigaction, SIGUSR1, &action, NULL, 8)) return 83;
    if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1)) return 84;
    if (write(1, "resumed\n", 8) != 8) return 85;
    return 0;
}
"#;

fn check_restorer_address(name: &str, argument: &str) {
    if !kvm_available(name) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, name, RESTORER_ADDRESS_SOURCE);
    let image = std::fs::read(&executable).unwrap();
    let argv = [executable.to_str().unwrap(), argument];
    let returning = argument == "valid-return";
    let status = ExitStatus::Exited(if returning { 0 } else { 42 });
    let output: &[u8] = if returning {
        b"handler\nresumed\n"
    } else {
        b"handler\n"
    };
    let mut direct = KvmBackend::new(256 * 1024 * 1024).unwrap();
    direct
        .install_static_elf_with_context(&image, &argv, &["PATH=/usr/bin:/bin"], &directory.0)
        .unwrap();
    let (code, stdout, stderr) = direct.run_static_elf_captured().unwrap();
    assert_eq!(code, status.code().unwrap());
    assert_eq!(stdout, output);
    assert!(stderr.is_empty());
    check_typed_signal_status(&image, &argv, &directory, status, output);
}

#[test]
fn restorer_address_zero() {
    check_restorer_address("restorer_address_zero", "0");
}

#[test]
fn restorer_address_bit47() {
    check_restorer_address("restorer_address_bit47", "0x800000000000");
}

#[test]
fn restorer_address_bit63() {
    check_restorer_address("restorer_address_bit63", "0x8000000000000000");
}

#[test]
fn restorer_address_all_bits() {
    check_restorer_address("restorer_address_all_bits", "0xffffffffffffffff");
}

#[test]
fn restorer_address_valid_return() {
    check_restorer_address("restorer_address_valid_return", "valid-return");
}

const NESTED_NULL_CONTEXT_SOURCE: &str = r#"#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static const char *mode;
static uintptr_t expected_stack;
static _Alignas(16) unsigned char alternate_stack[65536];

__attribute__((naked)) static void restorer(void) {
    __asm__ volatile("mov $15, %rax; syscall; ud2");
}

static void fault_handler(int number, siginfo_t *info, void *context) {
    ucontext_t *frame = context;
    greg_t *registers = frame->uc_mcontext.gregs;
    int matched = number == SIGSEGV && info->si_code == SEGV_MAPERR && info->si_addr == NULL &&
        registers[REG_TRAPNO] == 14 && registers[REG_ERR] == 20 &&
        registers[REG_RIP] == 0 && (uintptr_t)registers[REG_RSP] == expected_stack &&
        (registers[REG_CSGSFS] & 3) == 3;
    int want_match = strcmp(mode, "caught-return") == 0 || strcmp(mode, "caught-resume") == 0 || strcmp(mode, "caught-resume-altstack") == 0;
    if (matched != want_match) _exit(80);
    if (!want_match) {
        int trap = strcmp(mode, "handler-hlt") == 0 ? 13 : strcmp(mode, "handler-ud2") == 0 ? 6 : 14;
        int error = strcmp(mode, "handler-datafault") == 0 ? 4 : 0;
        int expected_signal = trap == 6 ? SIGILL : SIGSEGV;
        if (number != expected_signal || registers[REG_TRAPNO] != trap ||
            registers[REG_ERR] != error || registers[REG_RIP] == 0) _exit(81);
    }
    const char *output = matched ? "matched return context\n" : "different fault context\n";
    size_t length = strlen(output);
    if (write(1, output, length) != (ssize_t)length) _exit(82);
    if (strcmp(mode, "caught-resume") == 0 || strcmp(mode, "caught-resume-altstack") == 0) {
        if (strcmp(mode, "caught-resume-altstack") == 0) {
            uintptr_t local = (uintptr_t)&frame;
            if (local < (uintptr_t)alternate_stack || local >= (uintptr_t)alternate_stack + sizeof(alternate_stack)) _exit(93);
        }
        registers[REG_RIP] = (greg_t)restorer;
        return;
    }
    _exit(43);
}

static void handler(int number, siginfo_t *info, void *context) {
    (void)info;
    if (number != SIGUSR1) _exit(83);
    expected_stack = (uintptr_t)context;
    if (write(1, "handler\n", 8) != 8) _exit(84);
    if (strcmp(mode, "handler-hlt") == 0) __asm__ volatile("hlt");
    if (strcmp(mode, "handler-ud2") == 0) __asm__ volatile("ud2");
    if (strcmp(mode, "handler-datafault") == 0) {
        uintptr_t address = 0;
        __asm__ volatile("mov (%0), %%rax" : : "r"(address) : "rax", "memory");
    }
}

int main(int argc, char **argv) {
    if (argc != 2) return 85;
    mode = argv[1];
    struct {
        void (*handler)(int, siginfo_t *, void *);
        uint64_t flags;
        void (*restorer)(void);
        uint64_t mask;
    } action = {handler, SA_SIGINFO | UINT64_C(0x04000000), NULL, 0};
    if (strcmp(mode, "caught-resume-altstack") == 0) {
        memset(alternate_stack, 0xa5, sizeof(alternate_stack));
        stack_t stack = {.ss_sp = alternate_stack, .ss_size = sizeof(alternate_stack)};
        if (sigaltstack(&stack, NULL)) return 94;
        action.flags |= SA_ONSTACK;
    }
    if (syscall(SYS_rt_sigaction, SIGUSR1, &action, 0, 8)) return 87;
    if (strcmp(mode, "ignored-return") == 0) {
        if (signal(SIGSEGV, SIG_IGN) == SIG_ERR) return 88;
    } else if (strcmp(mode, "blocked-return") == 0) {
        uint64_t mask = UINT64_C(1) << (SIGSEGV - 1);
        if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, &mask, NULL, 8)) return 89;
    } else if (strcmp(mode, "default-return") != 0) {
        action.handler = fault_handler;
        action.restorer = restorer;
        if (syscall(SYS_rt_sigaction, SIGSEGV, &action, 0, 8) ||
            syscall(SYS_rt_sigaction, SIGILL, &action, 0, 8)) return 90;
    }
    if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1)) return 91;
    if (strcmp(mode, "caught-resume") == 0 || strcmp(mode, "caught-resume-altstack") == 0) {
        if (strcmp(mode, "caught-resume-altstack") == 0) {
            for (size_t index = 0; index < 32768; ++index)
                if (alternate_stack[index] != 0xa5) return 95;
            for (size_t index = sizeof(alternate_stack) - 16; index < sizeof(alternate_stack); ++index)
                if (alternate_stack[index] != 0xa5) return 96;
        }
        if (write(1, "resumed\n", 8) != 8) return 97;
        return 0;
    }
    return 92;
}
"#;

#[test]
fn page_zero_nested_null_caught_return() {
    if !kvm_available("page_zero_nested_null_caught_return") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "page_zero_nested_null_caught_return",
        NESTED_NULL_CONTEXT_SOURCE,
    );
    let image = std::fs::read(&executable).unwrap();
    check_typed_signal_status(
        &image,
        &[executable.to_str().unwrap(), "caught-return"],
        &directory,
        ExitStatus::Exited(43),
        b"handler\nmatched return context\n",
    );
}

#[test]
fn page_zero_nested_null_caught_resume() {
    if !kvm_available("page_zero_nested_null_caught_resume") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "page_zero_nested_null_caught_resume",
        NESTED_NULL_CONTEXT_SOURCE,
    );
    let image = std::fs::read(&executable).unwrap();
    check_typed_signal_status(
        &image,
        &[executable.to_str().unwrap(), "caught-resume"],
        &directory,
        ExitStatus::Exited(0),
        b"handler\nmatched return context\nresumed\n",
    );
}

#[test]
fn page_zero_nested_null_caught_resume_altstack() {
    if !kvm_available("page_zero_nested_null_caught_resume_altstack") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "page_zero_nested_null_caught_resume_altstack",
        NESTED_NULL_CONTEXT_SOURCE,
    );
    let image = std::fs::read(&executable).unwrap();
    check_typed_signal_status(
        &image,
        &[executable.to_str().unwrap(), "caught-resume-altstack"],
        &directory,
        ExitStatus::Exited(0),
        b"handler\nmatched return context\nresumed\n",
    );
}

#[test]
fn page_zero_nested_null_ignored() {
    if !kvm_available("page_zero_nested_null_ignored") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "page_zero_nested_null_ignored",
        NESTED_NULL_CONTEXT_SOURCE,
    );
    let image = std::fs::read(&executable).unwrap();
    check_typed_signal_status(
        &image,
        &[executable.to_str().unwrap(), "ignored-return"],
        &directory,
        ExitStatus::from_raw(libc::SIGSEGV | 0x80),
        b"handler\n",
    );
}

#[test]
fn page_zero_nested_null_blocked() {
    if !kvm_available("page_zero_nested_null_blocked") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "page_zero_nested_null_blocked",
        NESTED_NULL_CONTEXT_SOURCE,
    );
    let image = std::fs::read(&executable).unwrap();
    check_typed_signal_status(
        &image,
        &[executable.to_str().unwrap(), "blocked-return"],
        &directory,
        ExitStatus::from_raw(libc::SIGSEGV | 0x80),
        b"handler\n",
    );
}

const PAGE_ZERO_FAULT_CONTEXT_SOURCE: &str = r#"#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <sys/wait.h>
#include <unistd.h>

uintptr_t expected_sp;
uint64_t expected_flags;
unsigned char vector_input[16] = {1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31};
unsigned char vector_output[16];
static int fault_kind;
static int expected_cs;
static int expected_ss;
static volatile sig_atomic_t handled;
extern char read_fault, write_fault, read_resume, write_resume, fetch_resume;
void run_read(void);
void run_write(void);
void run_fetch(void);

#define SAVE "push %rbx; push %rbp; push %r12; push %r13; push %r14; push %r15; "
#define SET_REGS "movdqu vector_input(%rip), %xmm15; " \
    "mov $0x108, %r8; mov $0x109, %r9; mov $0x110, %r10; mov $0x111, %r11; " \
    "mov $0x112, %r12; mov $0x113, %r13; mov $0x114, %r14; mov $0x115, %r15; " \
    "mov $0x101, %rdi; mov $0x102, %rsi; mov $0x103, %rbp; mov $0x104, %rbx; " \
    "mov $0x105, %rdx; mov $0x107, %rcx; xor %eax, %eax; " \
    "pushfq; popq expected_flags(%rip); "
#define RESTORE "movdqu %xmm15, vector_output(%rip); pop %r15; pop %r14; pop %r13; pop %r12; pop %rbp; pop %rbx; ret; "
__asm__(".text; .global run_read, run_write, run_fetch; "
    "run_read: " SAVE SET_REGS "mov %rsp, expected_sp(%rip); "
    ".global read_fault, read_resume; read_fault: mov (%rax), %rax; read_resume: " RESTORE
    "run_write: " SAVE SET_REGS "mov %rsp, expected_sp(%rip); "
    ".global write_fault, write_resume; write_fault: mov %rdx, (%rax); write_resume: " RESTORE
    "run_fetch: " SAVE SET_REGS "push %rax; mov %rsp, expected_sp(%rip); "
    "ret; .global fetch_resume; fetch_resume: " RESTORE);

static void handler(int number, siginfo_t *info, void *context) {
    ucontext_t *frame = context;
    greg_t *registers = frame->uc_mcontext.gregs;
    unsigned char expected_info[128] = {0};
    int signo = SIGSEGV;
    int code = SEGV_MAPERR;
    memcpy(expected_info, &signo, sizeof(signo));
    memcpy(expected_info + 8, &code, sizeof(code));
    if (number != SIGSEGV || memcmp(info, expected_info, sizeof(expected_info))) _exit(81);
    uintptr_t expected_rip = fault_kind == 0 ? (uintptr_t)&read_fault :
        fault_kind == 1 ? (uintptr_t)&write_fault : 0;
    int expected_error = fault_kind == 0 ? 4 : fault_kind == 1 ? 6 : 20;
    uintptr_t stack = expected_sp + (fault_kind == 2 ? 8 : 0);
    if (registers[REG_TRAPNO] != 14 || registers[REG_ERR] != expected_error ||
        registers[REG_CR2] != 0 || (uintptr_t)registers[REG_RIP] != expected_rip ||
        (uintptr_t)registers[REG_RSP] != stack ||
        (uint64_t)registers[REG_EFL] != (expected_flags | (1u << 16)) ||
        (registers[REG_CSGSFS] & 0xffff) != expected_cs ||
        ((registers[REG_CSGSFS] >> 48) & 0xffff) != expected_ss) _exit(82);
    const int indices[15] = {REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13,
        REG_R14, REG_R15, REG_RDI, REG_RSI, REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX};
    const uint64_t values[15] = {0x108,0x109,0x110,0x111,0x112,0x113,0x114,0x115,
        0x101,0x102,0x103,0x104,0x105,0,0x107};
    for (int index = 0; index != 15; ++index)
        if ((uint64_t)registers[indices[index]] != values[index]) _exit(83);
    if (!frame->uc_mcontext.fpregs ||
        memcmp((unsigned char *)frame->uc_mcontext.fpregs + 160 + 15 * 16, vector_input, 16)) _exit(84);
    if (write(1, "caught\n", 7) != 7) _exit(85);
    handled++;
    registers[REG_RIP] = (greg_t)(fault_kind == 0 ? &read_resume :
        fault_kind == 1 ? &write_resume : &fetch_resume);
}

static int run_case(int argc, char **argv) {
    if (argc != 4) return 86;
    fault_kind = !strcmp(argv[1], "read") ? 0 : !strcmp(argv[1], "write") ? 1 : 2;
    expected_cs = !strcmp(argv[3], "native") ? 0x33 : 0x23;
    expected_ss = !strcmp(argv[3], "native") ? 0x2b : 0x1b;
    struct sigaction action = {0};
    if (!strcmp(argv[2], "caught")) {
        action.sa_sigaction = handler;
        action.sa_flags = SA_SIGINFO;
    } else if (!strcmp(argv[2], "ignored")) {
        action.sa_handler = SIG_IGN;
    } else {
        action.sa_handler = SIG_DFL;
    }
    if (sigaction(SIGSEGV, &action, NULL)) return 87;
    if (!strcmp(argv[2], "blocked")) {
        sigset_t blocked;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGSEGV);
        if (sigprocmask(SIG_BLOCK, &blocked, NULL)) return 88;
    }
    if (write(1, "before\n", 7) != 7) return 89;
    if (fault_kind == 0) run_read();
    else if (fault_kind == 1) run_write();
    else run_fetch();
    if (handled != 1 || memcmp(vector_output, vector_input, 16)) return 90;
    if (write(1, "resumed\n", 8) != 8) return 91;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[4], "wait")) {
        pid_t child = fork();
        if (child < 0) return 92;
        if (child == 0) _exit(run_case(4, argv));
        int status = 0x12345678;
        if (waitpid(child, &status, 0) != child) return 93;
        if (!strcmp(argv[2], "caught")) {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 94;
        } else {
            if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSEGV) return 95;
        }
        if (write(1, "waited\n", 7) != 7) return 96;
        return 0;
    }
    return run_case(argc, argv);
}
"#;

#[derive(Default)]
struct PageFaultInjectionLog {
    starts: Mutex<Vec<(u64, u64)>>,
    exits: Mutex<Vec<i32>>,
    faults: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for PageFaultInjectionLog {
    type Request = (u8, u64, u64);
    type Response = bool;
    type Config = bool;

    async fn receive_rpc(&self, _from: Pid, request: Self::Request) -> bool {
        match request {
            (0, pid, tid) => {
                let mut starts = self.starts.lock().unwrap();
                let child = !starts.is_empty();
                starts.push((pid, tid));
                child
            }
            (1, _, _) => {
                assert_eq!(self.faults.fetch_add(1, Ordering::SeqCst), 0);
                false
            }
            (2, status, _) => {
                self.exits.lock().unwrap().push(status as i32);
                false
            }
            _ => panic!("unknown page-fault test request"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PageFaultInjectionTool {
    thread: bool,
}

#[reverie::tool]
impl Tool for PageFaultInjectionTool {
    type GlobalState = PageFaultInjectionLog;
    type ThreadState = ();

    fn new(_pid: Pid, thread: &bool) -> Self {
        Self { thread: *thread }
    }

    fn subscriptions(_config: &bool) -> Subscription {
        Subscription::none()
    }

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let child = guest
            .send_rpc((0, guest.pid().as_raw() as u64, guest.tid().as_raw() as u64))
            .await;
        if child {
            let registers = guest.regs().await;
            assert_eq!(
                [
                    registers.r8,
                    registers.r9,
                    registers.r10,
                    registers.r11,
                    registers.r12,
                    registers.r13,
                    registers.r14,
                    registers.r15,
                    registers.rdi,
                    registers.rsi,
                    registers.rbp,
                    registers.rbx,
                    registers.rdx,
                    registers.rax,
                    registers.rcx
                ],
                [
                    0x108, 0x109, 0x110, 0x111, 0x112, 0x113, 0x114, 0x115, 0x101, 0x102, 0x103,
                    0x104, 0x105, 0, 0x107
                ],
            );
            guest
                .tail_inject(Syscall::from_raw(
                    Sysno::exit,
                    SyscallArgs::new(0, 0, 0, 0, 0, 0),
                ))
                .await;
        }
        Ok(())
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert_eq!(event.signal(), libc::SIGSEGV);
        assert_eq!(
            i32::from_ne_bytes(event.siginfo()[8..12].try_into().unwrap()),
            1
        );
        assert_eq!(&event.siginfo()[16..24], &[0; 8]);
        assert_eq!(
            event.target(),
            SignalTarget::Thread {
                pid: guest.pid(),
                tid: guest.tid()
            }
        );
        let registers = guest.regs().await;
        assert_eq!(registers.orig_rax, u64::MAX);
        assert_eq!((registers.cs, registers.ss), (0x23, 0x1b));
        assert_eq!(registers.eflags & (1 << 16), 1 << 16);
        guest.send_rpc((1, 0, 0)).await;
        let request = if self.thread {
            Syscall::from_raw(
                Sysno::clone,
                SyscallArgs::new(
                    (libc::CLONE_VM
                        | libc::CLONE_FS
                        | libc::CLONE_FILES
                        | libc::CLONE_SIGHAND
                        | libc::CLONE_THREAD) as usize,
                    (registers.rsp - 4096) as usize,
                    0,
                    0,
                    0,
                    0,
                ),
            )
        } else {
            Syscall::from_raw(Sysno::fork, SyscallArgs::new(0, 0, 0, 0, 0, 0))
        };
        assert!(guest.inject(request).await? > 0);
        assert_eq!(guest.regs().await, registers);
        Ok(Some(event))
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        global: &G,
        _state: (),
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        global.send_rpc((2, status.into_raw() as u64, 0)).await;
        Ok(())
    }
}

fn check_page_fault_returning_action(name: &str, thread: bool) {
    if !kvm_available(name) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, name, PAGE_ZERO_FAULT_CONTEXT_SOURCE);
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap(), "read", "caught", "kvm"],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (log, status, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<PageFaultInjectionTool>(thread, true),
    )
    .unwrap();
    assert_eq!(status, 0, "stdout={stdout:?} stderr={stderr:?}");
    assert_eq!(stdout, b"before\ncaught\nresumed\n");
    assert!(stderr.is_empty(), "{stderr:?}");
    assert_eq!(log.faults.load(Ordering::SeqCst), 1);
    assert_eq!(log.starts.lock().unwrap().len(), 2);
    assert_eq!(*log.exits.lock().unwrap(), vec![0, 0]);
}

#[test]
fn page_fault_hook_returning_fork_preserves_context() {
    check_page_fault_returning_action("page_fault_hook_returning_fork_preserves_context", false);
}

#[test]
fn page_fault_hook_returning_thread_preserves_context() {
    check_page_fault_returning_action("page_fault_hook_returning_thread_preserves_context", true);
}

#[derive(Default, Debug)]
struct PageFaultFilterLog {
    events: Mutex<Vec<Vec<u8>>>,
    statuses: Mutex<Vec<i32>>,
}

#[reverie::global_tool]
impl GlobalTool for PageFaultFilterLog {
    type Request = (u8, Vec<u8>);
    type Response = ();
    type Config = u8;

    async fn receive_rpc(&self, _from: Pid, (kind, bytes): Self::Request) {
        if kind == 0 {
            self.events.lock().unwrap().push(bytes);
        } else {
            self.statuses
                .lock()
                .unwrap()
                .push(i32::from_ne_bytes(bytes.try_into().unwrap()));
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PageFaultFilterTool {
    mode: u8,
}

#[reverie::tool]
impl Tool for PageFaultFilterTool {
    type GlobalState = PageFaultFilterLog;
    type ThreadState = u8;

    fn new(_pid: Pid, mode: &u8) -> Self {
        Self { mode: *mode }
    }
    fn subscriptions(_config: &u8) -> Subscription {
        Subscription::none()
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert_eq!(event.signal(), libc::SIGSEGV);
        let mut expected = [0; 128];
        expected[..4].copy_from_slice(&libc::SIGSEGV.to_ne_bytes());
        expected[8..12].copy_from_slice(&1_i32.to_ne_bytes());
        assert_eq!(event.siginfo(), expected);
        assert_eq!(
            event.target(),
            SignalTarget::Thread {
                pid: guest.pid(),
                tid: guest.tid()
            }
        );
        guest.send_rpc((0, event.siginfo().to_vec())).await;
        let count = *guest.thread_state() + 1;
        *guest.thread_state_mut() = count;
        assert!(count <= 2, "suppression did not preserve bounded refault");
        match self.mode {
            1 if count == 1 => Ok(None),
            2 => {
                let mut info = event.siginfo();
                info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
                info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
                Ok(Some(SignalEvent::new(libc::SIGUSR1, info, event.target())?))
            }
            3 => {
                let error = guest.defer_signal_delivery(event).await.unwrap_err();
                assert_eq!(error.into_errno().unwrap(), Errno::ENOSYS);
                Ok(Some(event))
            }
            4 => Err(Errno::EIO),
            _ => Ok(Some(event)),
        }
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        global: &G,
        _state: u8,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        global
            .send_rpc((1, status.into_raw().to_ne_bytes().to_vec()))
            .await;
        Ok(())
    }
}

fn check_page_fault_filter(name: &str, mode: u8) {
    if !kvm_available(name) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, name, PAGE_ZERO_FAULT_CONTEXT_SOURCE);
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap(), "read", "caught", "kvm"],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let result = futures::executor::block_on(
        backend.run_static_elf_with_tool::<PageFaultFilterTool>(mode, true),
    );
    if mode == 4 {
        let error = result.expect_err("the fault filter must retain its injected failure");
        let cause = match &error {
            Error::SharedFailure(cause) => cause.as_ref(),
            cause => cause,
        };
        assert!(
            matches!(cause, Error::Reverie(reverie::Error::Errno(Errno::EIO))),
            "unexpected fault filter error: {error:?}",
        );
        return;
    }
    let (log, code, stdout, stderr) = result.unwrap();
    let status = if mode == 2 {
        ExitStatus::from_raw(libc::SIGUSR1)
    } else {
        ExitStatus::SUCCESS
    };
    assert_eq!(*log.statuses.lock().unwrap(), vec![status.into_raw()]);
    assert_eq!(code, if mode == 2 { 128 + libc::SIGUSR1 } else { 0 });
    assert_eq!(
        stdout,
        if mode == 2 {
            b"before\n".as_slice()
        } else {
            b"before\ncaught\nresumed\n".as_slice()
        }
    );
    assert!(stderr.is_empty(), "{stderr:?}");
    let events = log.events.lock().unwrap();
    assert_eq!(events.len(), if mode == 1 { 2 } else { 1 });
    assert!(events.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn page_fault_filter_suppression_refaults_once() {
    check_page_fault_filter("page_fault_filter_suppression_refaults_once", 1);
}
#[test]
fn page_fault_filter_replacement_keeps_typed_status() {
    check_page_fault_filter("page_fault_filter_replacement_keeps_typed_status", 2);
}
#[test]
fn page_fault_filter_public_defer_rejects_forgery() {
    check_page_fault_filter("page_fault_filter_public_defer_rejects_forgery", 3);
}
#[test]
fn page_fault_filter_preserves_original_error() {
    check_page_fault_filter("page_fault_filter_preserves_original_error", 4);
}

fn check_page_zero_fault_context(name: &str, operation: &str, disposition: &str, with_tool: bool) {
    if !kvm_available(name) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, name, PAGE_ZERO_FAULT_CONTEXT_SOURCE);
    let image = std::fs::read(&executable).unwrap();
    let expected = if disposition == "caught" {
        b"before\ncaught\nresumed\n".as_slice()
    } else {
        b"before\n".as_slice()
    };
    let argv = [executable.to_str().unwrap(), operation, disposition, "kvm"];
    if with_tool {
        check_typed_signal_status(
            &image,
            &argv,
            &directory,
            if disposition == "caught" {
                ExitStatus::SUCCESS
            } else {
                ExitStatus::from_raw(libc::SIGSEGV | 0x80)
            },
            expected,
        );
    } else {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        let mut argv = argv.to_vec();
        argv.push("wait");
        backend
            .install_static_elf_with_context(&image, &argv, &["PATH=/usr/bin:/bin"], &directory.0)
            .unwrap();
        let (status, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(status, 0, "stdout={stdout:?} stderr={stderr:?}");
        let mut expected = expected.to_vec();
        expected.extend_from_slice(b"waited\n");
        assert_eq!(stdout, expected);
        assert!(stderr.is_empty(), "{stderr:?}");
    }
}

#[test]
fn page_zero_fault_read_caught_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_read_caught_direct",
        "read",
        "caught",
        false,
    );
}

#[test]
fn page_zero_fault_read_caught_tool() {
    check_page_zero_fault_context("page_zero_fault_read_caught_tool", "read", "caught", true);
}

#[test]
fn page_zero_fault_read_default_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_read_default_direct",
        "read",
        "default",
        false,
    );
}

#[test]
fn page_zero_fault_read_default_tool() {
    check_page_zero_fault_context("page_zero_fault_read_default_tool", "read", "default", true);
}

#[test]
fn page_zero_fault_read_ignored_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_read_ignored_direct",
        "read",
        "ignored",
        false,
    );
}

#[test]
fn page_zero_fault_read_ignored_tool() {
    check_page_zero_fault_context("page_zero_fault_read_ignored_tool", "read", "ignored", true);
}

#[test]
fn page_zero_fault_read_blocked_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_read_blocked_direct",
        "read",
        "blocked",
        false,
    );
}

#[test]
fn page_zero_fault_read_blocked_tool() {
    check_page_zero_fault_context("page_zero_fault_read_blocked_tool", "read", "blocked", true);
}

#[test]
fn page_zero_fault_write_caught_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_write_caught_direct",
        "write",
        "caught",
        false,
    );
}

#[test]
fn page_zero_fault_write_caught_tool() {
    check_page_zero_fault_context("page_zero_fault_write_caught_tool", "write", "caught", true);
}

#[test]
fn page_zero_fault_write_default_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_write_default_direct",
        "write",
        "default",
        false,
    );
}

#[test]
fn page_zero_fault_write_default_tool() {
    check_page_zero_fault_context(
        "page_zero_fault_write_default_tool",
        "write",
        "default",
        true,
    );
}

#[test]
fn page_zero_fault_write_ignored_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_write_ignored_direct",
        "write",
        "ignored",
        false,
    );
}

#[test]
fn page_zero_fault_write_ignored_tool() {
    check_page_zero_fault_context(
        "page_zero_fault_write_ignored_tool",
        "write",
        "ignored",
        true,
    );
}

#[test]
fn page_zero_fault_write_blocked_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_write_blocked_direct",
        "write",
        "blocked",
        false,
    );
}

#[test]
fn page_zero_fault_write_blocked_tool() {
    check_page_zero_fault_context(
        "page_zero_fault_write_blocked_tool",
        "write",
        "blocked",
        true,
    );
}

#[test]
fn page_zero_fault_fetch_caught_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_fetch_caught_direct",
        "fetch",
        "caught",
        false,
    );
}

#[test]
fn page_zero_fault_fetch_caught_tool() {
    check_page_zero_fault_context("page_zero_fault_fetch_caught_tool", "fetch", "caught", true);
}

#[test]
fn page_zero_fault_fetch_default_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_fetch_default_direct",
        "fetch",
        "default",
        false,
    );
}

#[test]
fn page_zero_fault_fetch_default_tool() {
    check_page_zero_fault_context(
        "page_zero_fault_fetch_default_tool",
        "fetch",
        "default",
        true,
    );
}

#[test]
fn page_zero_fault_fetch_ignored_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_fetch_ignored_direct",
        "fetch",
        "ignored",
        false,
    );
}

#[test]
fn page_zero_fault_fetch_ignored_tool() {
    check_page_zero_fault_context(
        "page_zero_fault_fetch_ignored_tool",
        "fetch",
        "ignored",
        true,
    );
}

#[test]
fn page_zero_fault_fetch_blocked_direct() {
    check_page_zero_fault_context(
        "page_zero_fault_fetch_blocked_direct",
        "fetch",
        "blocked",
        false,
    );
}

#[test]
fn page_zero_fault_fetch_blocked_tool() {
    check_page_zero_fault_context(
        "page_zero_fault_fetch_blocked_tool",
        "fetch",
        "blocked",
        true,
    );
}

#[test]
fn static_elf_null_restorer_preserves_handler_side_effects() {
    if !kvm_available("static_elf_null_restorer_preserves_handler_side_effects") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_null_restorer_control(&directory);
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    for (argument, expected_code, expected_stdout) in [
        ("null-exit", 42, "handler\n"),
        ("null-return", 128 + libc::SIGSEGV, "handler\n"),
        ("valid-return", 0, "handler\nresumed\n"),
    ] {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        let argv = if argument.is_empty() {
            vec![executable]
        } else {
            vec![executable, argument]
        };
        backend
            .install_static_elf_with_context(&image, &argv, &["PATH=/usr/bin:/bin"], &directory.0)
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(
            code, expected_code,
            "case {argument}: stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, expected_stdout.as_bytes(), "case {argument}");
        assert!(stderr.is_empty(), "case {argument}: {stderr:?}");
    }
}

fn compile_null_restorer_control(directory: &TestDirectory) -> PathBuf {
    compile_c_program(
        &directory.0,
        "static_elf_null_restorer_preserves_handler_side_effects",
        r#"#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int returning;
__attribute__((naked)) static void restorer(void) {
    __asm__ volatile("mov $15, %rax; syscall; ud2");
}
static void handler(int signo) {
    if (signo != SIGUSR1 || write(1, "handler\n", 8) != 8) _exit(81);
    if (!returning) _exit(42);
}
int main(int argc, char **argv) {
    if (argc != 2) return 82;
    returning = strcmp(argv[1], "null-exit") != 0;
    struct {
        void (*handler)(int);
        uint64_t flags;
        void (*restorer)(void);
        uint64_t mask;
    } action = {handler, 0x04000000, strcmp(argv[1], "valid-return") ? 0 : restorer, 0};
    if (syscall(SYS_rt_sigaction, SIGUSR1, &action, 0, 8)) return 83;
    if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1)) return 84;
    if (write(1, "resumed\n", 8) != 8) return 85;
    return 0;
}
"#,
    )
}

#[derive(Default)]
struct TypedSignalStatusLog {
    statuses: Mutex<Vec<i32>>,
}

#[reverie::global_tool]
impl GlobalTool for TypedSignalStatusLog {
    type Request = i32;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, status: i32) {
        self.statuses.lock().unwrap().push(status);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TypedSignalStatusTool;

#[reverie::tool]
impl Tool for TypedSignalStatusTool {
    type GlobalState = TypedSignalStatusLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::none()
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        global: &G,
        _thread_state: (),
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        global.send_rpc(status.into_raw()).await;
        Ok(())
    }
}

fn check_typed_signal_status(
    image: &[u8],
    argv: &[&str],
    directory: &TestDirectory,
    expected_status: ExitStatus,
    expected_stdout: &[u8],
) {
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(image, argv, &["PATH=/usr/bin:/bin"], &directory.0)
        .unwrap();
    let (log, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<TypedSignalStatusTool>((), true),
    )
    .unwrap();
    let statuses = log.statuses.lock().unwrap();
    eprintln!(
        "typed signal status: argv={argv:?} raw={statuses:?} code={code} stdout={stdout:?} stderr={stderr:?}"
    );
    assert_eq!(*statuses, vec![expected_status.into_raw()]);
    assert_eq!(ExitStatus::from_raw(statuses[0]), expected_status);
    assert_eq!(stdout, expected_stdout);
    assert!(stderr.is_empty(), "{stderr:?}");
    assert_eq!(
        code,
        expected_status
            .code()
            .unwrap_or_else(|| 128 + expected_status.signal().unwrap())
    );
}

fn check_null_restorer_typed_status(name: &str, argument: &str, status: ExitStatus, stdout: &[u8]) {
    if !kvm_available(name) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_null_restorer_control(&directory);
    let image = std::fs::read(&executable).unwrap();
    check_typed_signal_status(
        &image,
        &[executable.to_str().unwrap(), argument],
        &directory,
        status,
        stdout,
    );
}

#[test]
fn typed_null_restorer_nonreturning_status() {
    check_null_restorer_typed_status(
        "typed_null_restorer_nonreturning_status",
        "null-exit",
        ExitStatus::Exited(42),
        b"handler\n",
    );
}

#[test]
fn typed_null_restorer_returning_status() {
    check_null_restorer_typed_status(
        "typed_null_restorer_returning_status",
        "null-return",
        ExitStatus::from_raw(libc::SIGSEGV | 0x80),
        b"handler\n",
    );
}

#[test]
fn typed_null_restorer_valid_return_status() {
    check_null_restorer_typed_status(
        "typed_null_restorer_valid_return_status",
        "valid-return",
        ExitStatus::SUCCESS,
        b"handler\nresumed\n",
    );
}

#[test]
fn typed_null_restorer_exited139_is_not_sigsegv() {
    if !kvm_available("typed_null_restorer_exited139_is_not_sigsegv") {
        return;
    }
    assert_ne!(
        ExitStatus::Exited(139),
        ExitStatus::from_raw(libc::SIGSEGV | 0x80)
    );
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "typed_exit139",
        "#include <unistd.h>\nint main(void) { if (write(1, \"handler\\n\", 8) != 8) return 81; _exit(139); }\n",
    );
    let image = std::fs::read(&executable).unwrap();
    check_typed_signal_status(
        &image,
        &[executable.to_str().unwrap()],
        &directory,
        ExitStatus::Exited(139),
        b"handler\n",
    );
}

#[test]
fn static_elf_sigaltstack_active_precedes_requested_flags_and_size() {
    if !kvm_available("static_elf_sigaltstack_active_precedes_requested_flags_and_size") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "static_elf_sigaltstack_active_precedes_requested_flags_and_size",
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static unsigned char alternate[65536];
static unsigned char replacement[65536];
static int results[6];
static int errors[6];
static int unchanged[6];
static volatile sig_atomic_t entered;

static void check(int offset) {
    _Alignas(stack_t) unsigned char fault_output[sizeof(stack_t) + 16];
    unsigned char fault_expected[sizeof(fault_output)];
    memset(fault_output, 0xa5, sizeof(fault_output));
    memset(fault_expected, 0xa5, sizeof(fault_expected));
    errno = 0;
    long fault_result = syscall(SYS_sigaltstack, (void *)1, fault_output);
    if (fault_result != -1 || errno != EFAULT ||
        memcmp(fault_output, fault_expected, sizeof(fault_output))) _exit(94);
    for (int index = 0; index < 3; ++index) {
        stack_t requested = {.ss_sp = replacement, .ss_size = sizeof(replacement), .ss_flags = 0};
        if (index == 0) requested.ss_flags = 4;
        if (index == 1) requested.ss_size = 0;
        _Alignas(stack_t) unsigned char output[sizeof(stack_t) + 16];
        unsigned char expected[sizeof(output)];
        memset(output, 0xa5, sizeof(output));
        memset(expected, 0xa5, sizeof(expected));
        errno = 0;
        results[offset + index] = syscall(SYS_sigaltstack, &requested, output);
        errors[offset + index] = errno;
        unchanged[offset + index] = memcmp(output, expected, sizeof(output)) == 0;
    }
}

static void handler(int signal_number) {
    unsigned char local;
    if (signal_number != SIGUSR1 || (uintptr_t)&local < (uintptr_t)alternate ||
        (uintptr_t)&local >= (uintptr_t)alternate + sizeof(alternate)) _exit(90);
    entered = 1;
    check(0);
}

int main(void) {
    stack_t stack = {.ss_sp = alternate, .ss_size = sizeof(alternate), .ss_flags = 0};
    if (sigaltstack(&stack, NULL) != 0) return 91;
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_ONSTACK};
    if (sigemptyset(&action.sa_mask) || sigaction(SIGUSR1, &action, NULL)) return 92;
    if (raise(SIGUSR1) != 0 || entered != 1) return 93;
    check(3);
    int expected_errors[6] = {EPERM, EPERM, EPERM, EINVAL, ENOMEM, 0};
    int failures = 0;
    for (int index = 0; index < 6; ++index) {
        int expected_result = index == 5 ? 0 : -1;
        int correct = results[index] == expected_result && errors[index] == expected_errors[index] &&
                      (index == 5 || unchanged[index] == 1);
        printf("case=%d result=%d errno=%d full_output_unchanged=%d correct=%d\n",
               index, results[index], errors[index], unchanged[index], correct);
        failures += !correct;
    }
    return failures ? 1 : 0;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    {
        let (argument, expected_code, expected_stdout) = (
            "",
            0,
            "case=0 result=-1 errno=1 full_output_unchanged=1 correct=1\ncase=1 result=-1 errno=1 full_output_unchanged=1 correct=1\ncase=2 result=-1 errno=1 full_output_unchanged=1 correct=1\ncase=3 result=-1 errno=22 full_output_unchanged=1 correct=1\ncase=4 result=-1 errno=12 full_output_unchanged=1 correct=1\ncase=5 result=0 errno=0 full_output_unchanged=0 correct=1\n",
        );
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        let argv = if argument.is_empty() {
            vec![executable]
        } else {
            vec![executable, argument]
        };
        backend
            .install_static_elf_with_context(&image, &argv, &["PATH=/usr/bin:/bin"], &directory.0)
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(
            code, expected_code,
            "case {argument}: stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, expected_stdout.as_bytes(), "case {argument}");
        assert!(stderr.is_empty(), "case {argument}: {stderr:?}");
    }
}

#[test]
fn ordinary_worker_exit_preserves_later_tool_owned_threads() {
    const TEST: &str = "ordinary_worker_exit_preserves_later_tool_owned_threads";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "sequential-pthreads",
        r#"#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
static void *enter(void *opaque) {
  int *entered = opaque;
  *entered = 1;
  return (void *)(uintptr_t)37;
}
int main(void) {
  for (int i = 0; i < 3; ++i) {
    int entered = 0;
    pthread_t thread;
    void *result = NULL;
    int created = pthread_create(&thread, NULL, enter, &entered);
    if (created) return 2;
    int joined = pthread_join(thread, &result);
    if (joined || entered != 1 || result != (void *)(uintptr_t)37) {
      fprintf(stderr, "pthread iteration=%d joined=%d entered=%d result=%p expected=0x25\n", i, joined, entered, result);
      return 3;
    }
  }
  puts("three-pthreads-executed-and-joined");
  return 0;
}
"#,
    );
    let native = std::process::Command::new("timeout")
        .args(["--signal=TERM", "--kill-after=2s", "15s"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(native.status.success(), "native fixture failed: {native:?}");
    assert_eq!(native.stdout, b"three-pthreads-executed-and-joined\n");
    assert!(native.stderr.is_empty());
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    for tool_owned in [false, true] {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (counter, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<HierarchicalCounterTool>((), true),
            )
            .unwrap();
            let totals = counter.totals();
            eprintln!(
                "tool_owned={tool_owned} code={code} totals={totals:?} stdout={} stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            assert_eq!(totals.exited_procs, 1);
            assert_eq!(totals.exited_threads, 4);
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code,
            0,
            "tool_owned={tool_owned} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, native.stdout, "tool_owned={tool_owned}");
        assert_eq!(stderr, native.stderr, "tool_owned={tool_owned}");
    }
}

type ProcessToolLifecycleEvent = (u8, i32, i32, u64, u64);

#[derive(Default)]
struct ProcessToolLifecycleLog {
    events: Mutex<Vec<ProcessToolLifecycleEvent>>,
}

#[reverie::global_tool]
impl GlobalTool for ProcessToolLifecycleLog {
    type Request = ProcessToolLifecycleEvent;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, event: Self::Request) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct ProcessToolLifecycle {
    pid: i32,
    started: AtomicU64,
    exited: AtomicU64,
}

#[reverie::tool]
impl Tool for ProcessToolLifecycle {
    type GlobalState = ProcessToolLifecycleLog;
    type ThreadState = (i32, i32);

    fn new(pid: Pid, _config: &()) -> Self {
        Self {
            pid: pid.as_raw(),
            ..Self::default()
        }
    }

    fn init_thread_state(
        &self,
        tid: Pid,
        _parent: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        (self.pid, tid.as_raw())
    }

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        assert_eq!(self.pid, guest.pid().as_raw());
        assert_eq!(*guest.thread_state(), (self.pid, guest.tid().as_raw()));
        self.started.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert_eq!(self.pid, guest.pid().as_raw());
        guest.tail_inject(syscall).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        global: &G,
        state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(state, (self.pid, tid.as_raw()));
        let exited = self.exited.fetch_add(1, Ordering::SeqCst) + 1;
        global
            .send_rpc((
                0,
                self.pid,
                tid.as_raw(),
                self.started.load(Ordering::SeqCst),
                exited,
            ))
            .await;
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global: &G,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(self.pid, pid.as_raw());
        let started = self.started.load(Ordering::SeqCst);
        let exited = self.exited.load(Ordering::SeqCst);
        assert_eq!(
            started, exited,
            "process exit must follow every thread exit callback"
        );
        global
            .send_rpc((1, self.pid, pid.as_raw(), started, exited))
            .await;
        Ok(())
    }
}

#[test]
fn process_tool_state_and_thread_group_exit_lifecycle() {
    const TEST: &str = "process_tool_state_and_thread_group_exit_lifecycle";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "process-tool-lifecycle",
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static _Atomic int entered, release_workers, completed;
static void *waiter(void *opaque) {
  atomic_fetch_add(&entered, 1);
  while (!atomic_load(&release_workers)) sched_yield();
  if ((intptr_t)opaque == 1) syscall(SYS_exit_group, 41);
  atomic_fetch_add(&completed, 1);
  return (void *)(intptr_t)37;
}
static void *finish(void *opaque) { return opaque; }
static int quick_thread(void) {
  pthread_t thread; void *result = NULL;
  if (pthread_create(&thread, NULL, finish, (void *)(intptr_t)37)) return 2;
  if (pthread_join(thread, &result) || result != (void *)(intptr_t)37) return 3;
  return 0;
}
int main(int argc, char **argv) {
  if (argc != 2) return 4;
  if (!strcmp(argv[1], "fork")) {
    if (quick_thread()) return 5;
    pid_t child = fork();
    if (child < 0) return 6;
    if (!child) _exit(quick_thread() || quick_thread() ? 7 : 0);
    int status = -1;
    if (waitpid(child, &status, 0) != child || status != 0) return 8;
    puts("separate-process-tool-state");
    return 0;
  }
  pthread_t first, second;
  if (pthread_create(&first, NULL, waiter, NULL)) return 9;
  while (atomic_load(&entered) != 1) sched_yield();
  if (!strcmp(argv[1], "survive")) {
    if (quick_thread()) return 10;
    if (atomic_load(&completed)) return 11;
    char *args[] = {"missing", NULL};
    char *env[] = {NULL};
    errno = 0;
    if (execve("/reverie-no-such-process-tool-lifecycle-image", args, env) != -1 || errno != ENOENT) return 12;
    if (atomic_load(&completed)) return 13;
    atomic_store(&release_workers, 1);
    void *result = NULL;
    if (pthread_join(first, &result) || result != (void *)(intptr_t)37 || atomic_load(&completed) != 1) return 14;
    puts("sibling-and-tool-state-preserved");
    return 0;
  }
  int worker_group = !strcmp(argv[1], "worker-group");
  if (!worker_group && strcmp(argv[1], "root-group")) return 15;
  if (pthread_create(&second, NULL, waiter, (void *)(intptr_t)worker_group)) return 16;
  while (atomic_load(&entered) != 2) sched_yield();
  if (!worker_group) syscall(SYS_exit_group, 37);
  atomic_store(&release_workers, 1);
  for (;;) sched_yield();
}
"#,
    );
    let image = std::fs::read(&executable).unwrap();
    for (mode, expected_code, expected_stdout, mut expected_threads) in [
        (
            "survive",
            0,
            b"sibling-and-tool-state-preserved\n".as_slice(),
            vec![3],
        ),
        (
            "fork",
            0,
            b"separate-process-tool-state\n".as_slice(),
            vec![2, 3],
        ),
        ("root-group", 37, b"".as_slice(), vec![3]),
        ("worker-group", 41, b"".as_slice(), vec![3]),
    ] {
        let native = std::process::Command::new("timeout")
            .args(["--signal=TERM", "--kill-after=2s", "15s"])
            .arg(&executable)
            .arg(mode)
            .output()
            .unwrap();
        assert_eq!(
            native.status.code(),
            Some(expected_code),
            "native {mode}: {native:?}"
        );
        assert_eq!(native.stdout, expected_stdout, "native {mode}");
        assert!(native.stderr.is_empty(), "native {mode}: {native:?}");
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable.to_str().unwrap(), mode],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (log, code, stdout, stderr) = futures::executor::block_on(
            backend.run_static_elf_with_tool::<ProcessToolLifecycle>((), true),
        )
        .unwrap();
        assert_eq!(
            code, expected_code,
            "{mode}: stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, native.stdout, "{mode}");
        assert_eq!(stderr, native.stderr, "{mode}");
        let events = log.events.lock().unwrap();
        let mut processes = std::collections::BTreeMap::new();
        let mut exits = std::collections::BTreeMap::<i32, std::collections::BTreeSet<i32>>::new();
        for &(kind, pid, tid, started, exited) in events.iter() {
            if kind == 0 {
                assert!(
                    !processes.contains_key(&pid),
                    "late thread callback: {events:?}"
                );
                assert!(
                    exits.entry(pid).or_default().insert(tid),
                    "duplicate thread callback: {events:?}"
                );
            } else {
                assert_eq!(kind, 1);
                assert!(
                    processes.insert(pid, started).is_none(),
                    "duplicate process callback: {events:?}"
                );
                assert_eq!(started, exited, "{events:?}");
                assert_eq!(exits.get(&pid).unwrap().len() as u64, started, "{events:?}");
            }
        }
        let mut actual_threads: Vec<u64> = processes.values().copied().collect();
        actual_threads.sort_unstable();
        expected_threads.sort_unstable();
        assert_eq!(actual_threads, expected_threads, "{mode}: {events:?}");
        eprintln!("{mode}: code={code} lifecycle={events:?}");
    }
}

#[test]
fn ordinary_vectored_endpoints_match_native_linux() {
    if !kvm_available("KVM ordinary vectored endpoint test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "ordinary-vectored-endpoints",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static int check_socket(int type, int base) {
  int fds[2];
  if (socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, fds) != 0) {
    return base;
  }
  char first[4] = "ABC";
  char second[6] = "DEFGH";
  struct iovec output[2] = {
      {.iov_base = first, .iov_len = 3},
      {.iov_base = second, .iov_len = 5},
  };
  if (writev(fds[0], output, 2) != 8) {
    return base + 1;
  }
  memset(first, 0, sizeof(first));
  memset(second, 0, sizeof(second));
  struct iovec input[2] = {
      {.iov_base = first, .iov_len = 3},
      {.iov_base = second, .iov_len = 5},
  };
  if (readv(fds[1], input, 2) != 8 ||
      memcmp(first, "ABC", 3) != 0 || memcmp(second, "DEFGH", 5) != 0) {
    return base + 2;
  }
  close(fds[0]);
  close(fds[1]);
  return 0;
}

int main(void) {
  int event = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (event < 0) {
    return 10;
  }
  uint64_t event_value = 7;
  if (write(event, &event_value, sizeof(event_value)) !=
      (ssize_t)sizeof(event_value)) {
    return 11;
  }
  uint32_t event_low = 0;
  uint32_t event_high = 0;
  struct iovec event_input[2] = {
      {.iov_base = &event_low, .iov_len = sizeof(event_low)},
      {.iov_base = &event_high, .iov_len = sizeof(event_high)},
  };
  if (readv(event, event_input, 2) != (ssize_t)sizeof(event_value)) {
    return 12;
  }
  uint64_t event_result = 0;
  memcpy(&event_result, &event_low, sizeof(event_low));
  memcpy((char *)&event_result + sizeof(event_low), &event_high,
         sizeof(event_high));
  if (event_result != event_value) {
    return 13;
  }

  event_low = 9;
  event_high = 0;
  struct iovec event_output[2] = {
      {.iov_base = &event_low, .iov_len = sizeof(event_low)},
      {.iov_base = &event_high, .iov_len = sizeof(event_high)},
  };
  errno = 0;
  if (writev(event, event_output, 2) != -1 || errno != EINVAL) {
    return 14;
  }
  errno = 0;
  if (read(event, &event_result, sizeof(event_result)) != -1 ||
      errno != EAGAIN) {
    return 15;
  }
  close(event);

  int pipe_fds[2];
  if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
    return 20;
  }
  char pipe_first[4] = "pip";
  char pipe_second[6] = "e-data";
  struct iovec pipe_output[2] = {
      {.iov_base = pipe_first, .iov_len = 3},
      {.iov_base = pipe_second, .iov_len = 5},
  };
  if (writev(pipe_fds[1], pipe_output, 2) != 8) {
    return 21;
  }
  memset(pipe_first, 0, sizeof(pipe_first));
  memset(pipe_second, 0, sizeof(pipe_second));
  struct iovec pipe_input[2] = {
      {.iov_base = pipe_first, .iov_len = 3},
      {.iov_base = pipe_second, .iov_len = 5},
  };
  if (readv(pipe_fds[0], pipe_input, 2) != 8 ||
      memcmp(pipe_first, "pip", 3) != 0 ||
      memcmp(pipe_second, "e-data", 5) != 0) {
    return 22;
  }
  close(pipe_fds[0]);
  close(pipe_fds[1]);

  int result = check_socket(SOCK_STREAM, 30);
  if (result != 0) {
    return result;
  }
  result = check_socket(SOCK_DGRAM, 40);
  if (result != 0) {
    return result;
  }

  puts("ordinary-vectored-endpoints-ok");
  return 0;
}
"#,
    );

    let native = std::process::Command::new(&executable).output().unwrap();
    assert!(
        native.status.success(),
        "native fixture exited {:?}; stdout={}; stderr={}",
        native.status.code(),
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr),
    );
    assert_eq!(native.stdout, b"ordinary-vectored-endpoints-ok\n");
    assert!(native.stderr.is_empty());

    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "KVM fixture exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[test]
fn vectored_fault_shape_matches_native_linux_on_kvm() {
    if !kvm_available("KVM vectored fault-shape test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "vectored-fault-shape",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

enum endpoint_kind { ENDPOINT_EVENTFD, ENDPOINT_PIPE, ENDPOINT_STREAM,
                     ENDPOINT_DGRAM };

struct endpoint {
  int reader;
  int writer;
};

struct fault_buffer {
  unsigned char *mapping;
  size_t length;
  unsigned char *crossing;
  unsigned char *invalid;
  unsigned char *later;
};

static int make_endpoint(enum endpoint_kind kind, struct endpoint *endpoint) {
  if (kind == ENDPOINT_EVENTFD) {
    endpoint->reader = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    endpoint->writer = endpoint->reader;
    return endpoint->reader < 0 ? -1 : 0;
  }
  int fds[2];
  if (kind == ENDPOINT_PIPE) {
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) {
      return -1;
    }
  } else {
    int type = kind == ENDPOINT_STREAM ? SOCK_STREAM : SOCK_DGRAM;
    if (socketpair(AF_UNIX, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds) != 0) {
      return -1;
    }
  }
  endpoint->reader = fds[0];
  endpoint->writer = fds[1];
  return 0;
}

static void close_endpoint(enum endpoint_kind kind, struct endpoint endpoint) {
  close(endpoint.reader);
  if (kind != ENDPOINT_EVENTFD) {
    close(endpoint.writer);
  }
}

static int make_fault_buffer(struct fault_buffer *buffer) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  buffer->length = 2 * page;
  buffer->mapping = mmap(NULL, buffer->length, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer->mapping == MAP_FAILED) {
    return -1;
  }
  buffer->crossing = buffer->mapping + page - 4;
  buffer->invalid = buffer->mapping + page;
  buffer->later = buffer->mapping + 128;
  memcpy(buffer->crossing, "ABCD", 4);
  memcpy(buffer->later, "WXYZ", 4);
  if (mprotect(buffer->mapping + page, page, PROT_NONE) != 0) {
    return -1;
  }
  return 0;
}

static ssize_t fault_read(int positioned, int fd, struct iovec *iov,
                          int count) {
  return positioned ? preadv2(fd, iov, count, (off_t)-1, 0)
                    : readv(fd, iov, count);
}

static ssize_t fault_write(int positioned, int fd, struct iovec *iov,
                           int count) {
  return positioned ? pwritev2(fd, iov, count, (off_t)-1, 0)
                    : writev(fd, iov, count);
}

static int check_read(enum endpoint_kind kind, int positioned, int read_only, int base) {
  struct endpoint endpoint;
  struct fault_buffer buffer;
  uint64_t payload = UINT64_C(0x0807060504030201);
  if (make_endpoint(kind, &endpoint) != 0 ||
      write(endpoint.writer, &payload, sizeof(payload)) != sizeof(payload) ||
      make_fault_buffer(&buffer) != 0) {
    return base;
  }
  if (read_only && mprotect(buffer.mapping, buffer.length / 2, PROT_READ) != 0) {
    return base;
  }
  struct iovec iov = {.iov_base = buffer.crossing, .iov_len = 8};
  errno = 0;
  ssize_t result = fault_read(positioned, endpoint.reader, &iov, 1);
  const void *expected_prefix = read_only ? (const void *)"ABCD" : (const void *)&payload;
  if (result != -1 || errno != EFAULT ||
      memcmp(buffer.crossing, expected_prefix, 4) != 0) {
    return base + 1;
  }
  uint64_t remaining = 0;
  errno = 0;
  ssize_t after = read(endpoint.reader, &remaining, sizeof(remaining));
  if (kind == ENDPOINT_EVENTFD || kind == ENDPOINT_DGRAM) {
    if (after != -1 || errno != EAGAIN) {
      return base + 2;
    }
  } else if (after != sizeof(remaining) || remaining != payload) {
    return base + 3;
  }
  munmap(buffer.mapping, buffer.length);
  close_endpoint(kind, endpoint);
  return 0;
}

static int check_write(enum endpoint_kind kind, int positioned, int base) {
  struct endpoint endpoint;
  struct fault_buffer buffer;
  if (make_endpoint(kind, &endpoint) != 0 || make_fault_buffer(&buffer) != 0) {
    return base;
  }
  struct iovec iov = {.iov_base = buffer.crossing, .iov_len = 8};
  errno = 0;
  ssize_t result = fault_write(positioned, endpoint.writer, &iov, 1);
  if (result != -1 || errno != EFAULT) {
    return base + 1;
  }
  uint64_t received = 0;
  errno = 0;
  if (read(endpoint.reader, &received, sizeof(received)) != -1 ||
      errno != EAGAIN) {
    return base + 2;
  }
  munmap(buffer.mapping, buffer.length);
  close_endpoint(kind, endpoint);
  return 0;
}

static int check_eventfd_later_vector(int positioned, int base) {
  struct endpoint endpoint;
  struct fault_buffer buffer;
  uint64_t payload = 7;
  if (make_endpoint(ENDPOINT_EVENTFD, &endpoint) != 0 ||
      write(endpoint.writer, &payload, sizeof(payload)) != sizeof(payload) ||
      make_fault_buffer(&buffer) != 0) {
    return base;
  }
  struct iovec iov[2] = {
      {.iov_base = buffer.invalid, .iov_len = 4},
      {.iov_base = buffer.later, .iov_len = 4},
  };
  errno = 0;
  ssize_t result = fault_read(positioned, endpoint.reader, iov, 2);
  if (result != -1 || errno != EFAULT ||
      memcmp(buffer.later, "WXYZ", 4) != 0) {
    return base + 1;
  }
  errno = 0;
  if (read(endpoint.reader, &payload, sizeof(payload)) != -1 ||
      errno != EAGAIN) {
    return base + 2;
  }
  munmap(buffer.mapping, buffer.length);
  close_endpoint(ENDPOINT_EVENTFD, endpoint);
  return 0;
}

static int check_null_later_vector(int positioned, int base) {
  struct fault_buffer buffer;
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (fd < 0 || make_fault_buffer(&buffer) != 0) {
    return base;
  }
  struct iovec iov[2] = {
      {.iov_base = buffer.crossing, .iov_len = 8},
      {.iov_base = buffer.later, .iov_len = 4},
  };
  errno = 0;
  if (fault_write(positioned, fd, iov, 2) != 12) {
    return base + 1;
  }
  munmap(buffer.mapping, buffer.length);
  close(fd);
  return 0;
}

int main(void) {
  for (int positioned = 0; positioned <= 1; ++positioned) {
    for (int kind = ENDPOINT_EVENTFD; kind <= ENDPOINT_DGRAM; ++kind) {
      int result = check_read((enum endpoint_kind)kind, positioned, 0,
                              10 + positioned * 80 + kind * 8);
      if (result != 0) {
        return result;
      }
      result = check_write((enum endpoint_kind)kind, positioned,
                           40 + positioned * 80 + kind * 8);
      if (result != 0) {
        return result;
      }
      result = check_read((enum endpoint_kind)kind, positioned, 1,
                          210 + positioned * 16 + kind * 4);
      if (result != 0) {
        return result;
      }
    }
    int result = check_eventfd_later_vector(positioned,
                                            170 + positioned * 10);
    if (result != 0) {
      return result;
    }
    result = check_null_later_vector(positioned, 190 + positioned * 10);
    if (result != 0) {
      return result;
    }
  }
  puts("vectored-fault-shape-ok");
  return 0;
}
"#,
    );

    let native = std::process::Command::new(&executable).output().unwrap();
    assert!(
        native.status.success(),
        "native fixture exited {:?}; stdout={}; stderr={}",
        native.status.code(),
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr),
    );
    assert_eq!(native.stdout, b"vectored-fault-shape-ok\n");
    assert!(native.stderr.is_empty());

    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "KVM fixture exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[test]
fn vectored_iovec_address_validation_uses_four_level_guest_abi_on_kvm() {
    if !kvm_available("KVM vectored iovec address-validation test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "vectored-iovec-address-validation",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#define PAGE_SIZE_BYTES UINT64_C(4096)
#define GUEST_LIMIT ((UINT64_C(1) << 47) - PAGE_SIZE_BYTES)
#define FIRST_NON_FOUR_LEVEL (UINT64_C(1) << 47)
#define FIVE_LEVEL_PROBE (UINT64_C(1) << 55)
#define FIVE_LEVEL_LIMIT ((UINT64_C(1) << 56) - PAGE_SIZE_BYTES)
#define MAX_RW_COUNT_VALUE UINT64_C(0x7ffff000)
#define MAX_HOST_IO_VALUE UINT64_C(0x1000000)

static int is_read_operation(int operation) {
  return operation == 0 || operation == 2 || operation == 4;
}

static ssize_t invoke(int operation, int fd, struct iovec *iov, int count,
                      off_t offset) {
  switch (operation) {
    case 0: return readv(fd, iov, count);
    case 1: return writev(fd, iov, count);
    case 2: return preadv(fd, iov, count, offset);
    case 3: return pwritev(fd, iov, count, offset);
    case 4: return preadv2(fd, iov, count, offset, 0);
    case 5: return pwritev2(fd, iov, count, offset, 0);
    default: return -2;
  }
}

static int expect_result(int operation, int fd, struct iovec *iov, int count,
                         off_t offset, ssize_t expected, int code) {
  errno = 0;
  ssize_t result = invoke(operation, fd, iov, count, offset);
  if (result != expected || (expected == -1 && errno != EFAULT)) {
    fprintf(stderr,
            "case %d: op=%d result=%zd errno=%d expected=%zd/EFAULT\n",
            code, operation, result, errno, expected);
    return code;
  }
  return 0;
}

static int expect_einval(int operation, int fd, struct iovec *iov, int count,
                         off_t offset, int code) {
  errno = 0;
  ssize_t result = invoke(operation, fd, iov, count, offset);
  if (result != -1 || errno != EINVAL) {
    fprintf(stderr, "case %d: op=%d result=%zd errno=%d expected=-1/EINVAL\n",
            code, operation, result, errno);
    return code;
  }
  return 0;
}

static int check_address_matrix(int operation, int guest_mode, int host_high,
                                int base) {
  int reading = is_read_operation(operation);
  int fd = open(reading ? "vectored-address-empty" : "/dev/null",
                reading ? O_RDWR | O_CREAT | O_TRUNC : O_WRONLY, 0600);
  if (fd < 0) return base;
  char byte = 'x';
  struct iovec iov[2];
  int result;

#define EXPECT_ONE(address, length, expected, offset) do {                 \
    iov[0].iov_base = (void *)(uintptr_t)(address);                        \
    iov[0].iov_len = (size_t)(length);                                     \
    result = expect_result(operation, fd, iov, 1, (offset), (expected),    \
                           base + __LINE__ % 89);                           \
    if (result != 0) { close(fd); return result; }                          \
  } while (0)

  iov[0].iov_base = &byte;
  iov[0].iov_len = (size_t)SSIZE_MAX + 1;
  result = expect_einval(operation, fd, iov, 1, 0, base + 10);
  if (result != 0) { close(fd); return result; }
  iov[0].iov_len = SIZE_MAX;
  result = expect_einval(operation, fd, iov, 1, 0, base + 11);
  if (result != 0) { close(fd); return result; }
  iov[0].iov_base = (void *)(uintptr_t)UINT64_MAX;
  iov[0].iov_len = (size_t)SSIZE_MAX + 1;
  result = expect_einval(operation, fd, iov, 1, 0, base + 12);
  if (result != 0) { close(fd); return result; }
  iov[0].iov_base = (void *)(uintptr_t)UINT64_MAX;
  iov[0].iov_len = 1;
  iov[1].iov_base = &byte;
  iov[1].iov_len = (size_t)SSIZE_MAX + 1;
  result = expect_einval(operation, fd, iov, 2, 0, base + 13);
  if (result != 0) { close(fd); return result; }
  iov[0].iov_base = &byte;
  iov[0].iov_len = 1;
  iov[1].iov_base = (void *)(uintptr_t)UINT64_MAX;
  iov[1].iov_len = SIZE_MAX;
  result = expect_einval(operation, fd, iov, 2, 0, base + 14);
  if (result != 0) { close(fd); return result; }

  EXPECT_ONE(UINT64_MAX, 1, -1, 0);
  EXPECT_ONE(UINT64_MAX - 3, 8, -1, 0);
  EXPECT_ONE(GUEST_LIMIT - 4, 4, reading ? 0 : 4, 0);
  EXPECT_ONE(GUEST_LIMIT, 0, 0, 0);
  EXPECT_ONE(UINT64_MAX, 0, -1, 0);

  if (guest_mode) {
    EXPECT_ONE(GUEST_LIMIT - 4, 8, -1, 0);
    EXPECT_ONE(GUEST_LIMIT, 1, -1, 0);
    EXPECT_ONE(FIRST_NON_FOUR_LEVEL, 1, -1, 0);
    EXPECT_ONE(FIRST_NON_FOUR_LEVEL, 0, -1, 0);
    EXPECT_ONE(FIVE_LEVEL_PROBE, 1, -1, 0);
  } else if (host_high) {
    EXPECT_ONE(GUEST_LIMIT - 4, 8, reading ? 0 : 8, 0);
    EXPECT_ONE(GUEST_LIMIT, 1, reading ? 0 : 1, 0);
    EXPECT_ONE(FIRST_NON_FOUR_LEVEL, 1, reading ? 0 : 1, 0);
    EXPECT_ONE(FIRST_NON_FOUR_LEVEL, 0, 0, 0);
    EXPECT_ONE(FIVE_LEVEL_PROBE, 1, reading ? 0 : 1, 0);
  }

  iov[0].iov_base = (void *)(uintptr_t)UINT64_MAX;
  iov[0].iov_len = 0;
  iov[1].iov_base = &byte;
  iov[1].iov_len = 1;
  result = expect_result(operation, fd, iov, 2, 0, -1, base + 1);
  if (result != 0) { close(fd); return result; }
  iov[0].iov_base = &byte;
  iov[0].iov_len = 1;
  iov[1].iov_base = (void *)(uintptr_t)UINT64_MAX;
  iov[1].iov_len = 0;
  result = expect_result(operation, fd, iov, 2, 0, -1, base + 2);
  if (result != 0) { close(fd); return result; }

  iov[0].iov_base = (void *)(uintptr_t)1;
  iov[0].iov_len = MAX_HOST_IO_VALUE;
  iov[1].iov_base = (void *)(uintptr_t)UINT64_MAX;
  iov[1].iov_len = 1;
  result = expect_result(operation, fd, iov, 2, 0, -1, base + 3);
  if (result != 0) { close(fd); return result; }

  iov[0].iov_base = 0;
  iov[0].iov_len = MAX_RW_COUNT_VALUE;
  iov[1].iov_base = (void *)(uintptr_t)GUEST_LIMIT;
  iov[1].iov_len = 1;
  if (guest_mode) {
    result = expect_result(operation, fd, iov, 2, 0, -1, base + 4);
  } else if (host_high) {
    result = expect_result(operation, fd, iov, 2, 0,
                           reading ? 0 : MAX_RW_COUNT_VALUE, base + 4);
  } else {
    result = 0;
  }
  if (result != 0) { close(fd); return result; }

  iov[0].iov_base = (void *)(uintptr_t)(GUEST_LIMIT - MAX_RW_COUNT_VALUE);
  iov[0].iov_len = MAX_RW_COUNT_VALUE + 1;
  result = expect_result(operation, fd, iov, 1, 0,
                         reading ? 0 : (guest_mode ? MAX_HOST_IO_VALUE
                                                  : MAX_RW_COUNT_VALUE),
                         base + 5);
  if (result != 0) { close(fd); return result; }

  errno = 0;
  if (invoke(operation, fd, (struct iovec *)(uintptr_t)UINT64_MAX, 0, 0) != 0) {
    close(fd);
    return base + 6;
  }

  if (host_high) {
    size_t count = (size_t)INT64_MAX / (size_t)FIVE_LEVEL_LIMIT + 1;
    if (count > IOV_MAX) { close(fd); return base + 7; }
    struct iovec *aggregate = calloc(count, sizeof(*aggregate));
    if (aggregate == NULL) { close(fd); return base + 8; }
    for (size_t index = 0; index < count; ++index) {
      aggregate[index].iov_base = 0;
      aggregate[index].iov_len = (size_t)FIVE_LEVEL_LIMIT;
    }
    result = expect_result(operation, fd, aggregate, (int)count, 0,
                           reading ? 0 : (guest_mode ? MAX_HOST_IO_VALUE
                                                  : MAX_RW_COUNT_VALUE),
                           base + 9);
    free(aggregate);
    if (result != 0) { close(fd); return result; }
  }

#undef EXPECT_ONE
  close(fd);
  unlink("vectored-address-empty");
  return 0;
}

static int seed_eventfd(int fd, uint64_t value) {
  return write(fd, &value, sizeof(value)) == sizeof(value) ? 0 : -1;
}

static int eventfd_after(int fd, int expect_preserved, uint64_t expected) {
  uint64_t value = 0;
  errno = 0;
  ssize_t result = read(fd, &value, sizeof(value));
  if (expect_preserved) {
    return result == sizeof(value) && value == expected ? 0 : -1;
  }
  return result == -1 && errno == EAGAIN ? 0 : -1;
}

static int check_eventfd_address(int positioned, void *address,
                                 int expect_preserved, int base) {
  int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  uint64_t value = 7;
  if (fd < 0 || seed_eventfd(fd, value) != 0) return base;
  struct iovec iov = {.iov_base = address, .iov_len = sizeof(value)};
  int operation = positioned ? 4 : 0;
  int result = expect_result(operation, fd, &iov, 1, (off_t)-1, -1, base + 1);
  if (result == 0 && eventfd_after(fd, expect_preserved, value) != 0) {
    result = base + 2;
  }
  close(fd);
  return result;
}

static int check_oversized_file_state(int operation, int base) {
  int fd = open("vectored-ssize-state", O_RDWR | O_CREAT | O_TRUNC, 0600);
  char contents[4] = {0};
  if (fd < 0 || write(fd, "seed", 4) != 4 || lseek(fd, 0, SEEK_SET) != 0) {
    return base;
  }
  struct iovec iov = {
      .iov_base = (void *)(uintptr_t)UINT64_MAX,
      .iov_len = (size_t)SSIZE_MAX + 1,
  };
  int result = expect_einval(operation, fd, &iov, 1, 0, base + 1);
  if (result == 0 && lseek(fd, 0, SEEK_CUR) != 0) result = base + 2;
  if (result == 0 &&
      (pread(fd, contents, sizeof(contents), 0) != sizeof(contents) ||
       memcmp(contents, "seed", sizeof(contents)) != 0)) {
    result = base + 3;
  }
  close(fd);
  unlink("vectored-ssize-state");
  return result;
}

static int check_eventfd_oversized(int positioned, int base) {
  int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  uint64_t value = 13;
  if (fd < 0 || seed_eventfd(fd, value) != 0) return base;
  struct iovec iov = {
      .iov_base = (void *)(uintptr_t)UINT64_MAX,
      .iov_len = (size_t)SSIZE_MAX + 1,
  };
  int operation = positioned ? 4 : 0;
  int result = expect_einval(operation, fd, &iov, 1, (off_t)-1, base + 1);
  if (result == 0 && eventfd_after(fd, 1, value) != 0) result = base + 2;
  close(fd);
  return result;
}

static int check_pipe_oversized(int positioned, int base) {
  int fds[2];
  if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) return base;
  struct iovec iov = {
      .iov_base = (void *)(uintptr_t)UINT64_MAX,
      .iov_len = SIZE_MAX,
  };
  int operation = positioned ? 5 : 1;
  int result = expect_einval(operation, fds[1], &iov, 1, (off_t)-1, base + 1);
  char byte;
  errno = 0;
  if (result == 0 && (read(fds[0], &byte, 1) != -1 || errno != EAGAIN)) {
    result = base + 2;
  }
  close(fds[0]);
  close(fds[1]);
  return result;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  int guest_mode = strcmp(argv[1], "guest") == 0;
  if (!guest_mode && strcmp(argv[1], "native") != 0) return 3;

  void *high_mapping = MAP_FAILED;
  int host_high = 0;
  if (!guest_mode) {
    high_mapping = mmap((void *)(uintptr_t)FIVE_LEVEL_PROBE, PAGE_SIZE_BYTES,
                        PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
                            MAP_FIXED_NOREPLACE,
                        -1, 0);
    if (high_mapping != MAP_FAILED) {
      if ((uintptr_t)high_mapping != FIVE_LEVEL_PROBE) return 4;
      host_high = 1;
    }
  }

  for (int operation = 0; operation < 6; ++operation) {
    int result = check_address_matrix(operation, guest_mode, host_high,
                                      20 + operation * 100);
    if (result != 0) return result;
    result = check_oversized_file_state(operation, 650 + operation * 10);
    if (result != 0) return result;
  }

  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  void *protected = mmap(NULL, page, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (protected == MAP_FAILED) return 700;
  for (int positioned = 0; positioned <= 1; ++positioned) {
    int result = check_eventfd_address(positioned, protected, 0,
                                       710 + positioned * 20);
    if (result != 0) return result;
    result = check_eventfd_address(positioned,
                                   (void *)(uintptr_t)UINT64_MAX, 1,
                                   715 + positioned * 20);
    if (result != 0) return result;
    if (guest_mode) {
      result = check_eventfd_address(positioned,
                                     (void *)(uintptr_t)FIVE_LEVEL_PROBE, 1,
                                     720 + positioned * 20);
      if (result != 0) return result;
    } else if (host_high) {
      result = check_eventfd_address(positioned, high_mapping, 0,
                                     720 + positioned * 20);
      if (result != 0) return result;
    }
    result = check_eventfd_oversized(positioned, 750 + positioned * 20);
    if (result != 0) return result;
    result = check_pipe_oversized(positioned, 755 + positioned * 20);
    if (result != 0) return result;
  }
  munmap(protected, page);
  if (host_high) munmap(high_mapping, PAGE_SIZE_BYTES);

  if (guest_mode) {
    puts("guest-vectored-address-ok");
  } else {
    printf("native-vectored-address-ok high=%d\n", host_high);
  }
  return 0;
}
"#,
    );

    let native = std::process::Command::new(&executable)
        .arg("native")
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "native address fixture exited {:?}; stdout={}; stderr={}",
        native.status.code(),
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr),
    );
    assert!(
        native.stdout == b"native-vectored-address-ok high=0\n"
            || native.stdout == b"native-vectored-address-ok high=1\n",
        "unexpected native stdout: {}",
        String::from_utf8_lossy(&native.stdout)
    );
    assert!(native.stderr.is_empty());

    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable, "guest"],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "KVM address fixture exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(stdout, b"guest-vectored-address-ok\n");
    assert!(stderr.is_empty());
}

fn host_accepts_rwf_nosignal() -> bool {
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let mut byte = 0_u8;
    let vector = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let result = unsafe { libc::preadv2(pipe[0], &vector, 1, -1, 0x100) };
    let error = std::io::Error::last_os_error();
    for fd in pipe {
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }
    assert_eq!(result, -1);
    match error.raw_os_error() {
        Some(libc::EAGAIN) => true,
        Some(libc::EOPNOTSUPP) => false,
        _ => panic!("unexpected RWF_NOSIGNAL probe result: {error}"),
    }
}

#[test]
fn signalfd_positioned_vector_flags_match_native_linux() {
    if !kvm_available("KVM signalfd positioned-vector flags") {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "signalfd-vector-flags",
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/uio.h>
#include <unistd.h>

static int check_record(const struct signalfd_siginfo *info) {
  struct signalfd_siginfo expected = {0};
  expected.ssi_signo = SIGUSR1;
  expected.ssi_pid = getpid();
  expected.ssi_uid = getuid();
  return memcmp(info, &expected, sizeof(expected)) == 0;
}

int main(void) {
  alarm(8);
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &set, 0) != 0) return 2;
  int fd = signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK);
  if (fd < 0) return 3;
  const unsigned flags[] = {
      0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 0x80000000, 16 | 32,
      0x80000000 | 16 | 32};
  int failures = 0;
  for (int shape = 0; shape < 5; shape++) {
    for (unsigned index = 0; index < sizeof(flags) / sizeof(flags[0]); index++) {
      if (kill(getpid(), SIGUSR1) != 0) return 4;
      struct signalfd_siginfo info;
      unsigned char sentinel[sizeof(info)];
      memset(&info, 0xa5, sizeof(info));
      memset(sentinel, 0xa5, sizeof(sentinel));
      struct iovec vector = {shape == 4 ? (void *)(uintptr_t)UINTPTR_MAX : &info,
                             shape >= 2 ? sizeof(info) : 0};
      int count = shape == 0 ? 0 : 1;
      errno = 0;
      struct iovec *array = shape == 3 ? (struct iovec *)(uintptr_t)1 : &vector;
      ssize_t result = preadv2(fd, array, count, -1, flags[index]);
      int error = errno;
      ssize_t expected = shape == 2 ? (ssize_t)sizeof(info) : 0;
      int expected_errno = 0;
      if (shape >= 3) {
        expected = -1;
        expected_errno = EFAULT;
      } else if (shape == 2 && (flags[index] & (64 | 128 | 0x80000000)) != 0) {
        expected = -1;
        expected_errno = EOPNOTSUPP;
      } else if (shape == 2 && (flags[index] & (16 | 32)) == (16 | 32)) {
        expected = -1;
        expected_errno = EINVAL;
      }
      int unchanged = memcmp(&info, sentinel, sizeof(info)) == 0;
      int valid_record = check_record(&info);
      memset(&info, 0xa5, sizeof(info));
      errno = 0;
      ssize_t remaining = read(fd, &info, sizeof(info));
      int remaining_errno = errno;
      if (result != expected || error != expected_errno) {
        fprintf(stderr,
                "shape=%d flags=%u result=%zd/%d expected=%zd/%d "
                "unchanged=%d remaining=%zd/%d\n",
                shape, flags[index], result, error, expected, expected_errno,
                unchanged, remaining, remaining_errno);
        failures++;
        continue;
      }
      if (result <= 0 && !unchanged) return 11;
      if (result > 0 && !valid_record) return 12;
      if (result > 0) {
        if (remaining != -1 || remaining_errno != EAGAIN ||
            memcmp(&info, sentinel, sizeof(info)) != 0) return 13;
      } else {
        if (remaining != sizeof(info) || !check_record(&info)) return 14;
      }
      printf("shape=%d flags=%u result=%zd/%d remaining=%zd/%d\n",
             shape, flags[index], result, error, remaining, remaining_errno);
    }
  }
  close(fd);
  if (failures != 0) return 10;
  puts("signalfd-vector-flags=ok");
  return 0;
}
"#,
    );
    // The KVM backend models Linux 7.1, which accepts RWF_NOSIGNAL (0x100).
    // Older hosts reject it, so they cannot provide the native baseline; the
    // fixture still checks every KVM result against the 7.1 behavior.
    let native = host_accepts_rwf_nosignal().then(|| {
        let native = std::process::Command::new("timeout")
            .args(["--signal=TERM", "--kill-after=2s", "15s"])
            .arg(&executable)
            .output()
            .unwrap();
        assert!(native.status.success(), "native fixture failed: {native:?}");
        native
    });
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "KVM fixture exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(stdout.split(|byte| *byte == b'\n').count(), 67);
    assert!(stdout.ends_with(b"signalfd-vector-flags=ok\n"));
    assert!(stderr.is_empty());
    if let Some(native) = native {
        assert_eq!(stdout, native.stdout);
        assert_eq!(stderr, native.stderr);
    }
}

#[test]
fn direct_vectored_io_preserves_the_supported_boundary_and_refuses_larger_requests() {
    const TEST: &str =
        "direct_vectored_io_preserves_the_supported_boundary_and_refuses_larger_requests";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "direct-vector-cap",
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#define CAP (16UL * 1024 * 1024)
static int all_bytes(const unsigned char *p, size_t count, unsigned char value) {
  for (size_t i = 0; i < count; ++i) if (p[i] != value) return 0;
  return 1;
}
int main(int argc, char **argv) {
  if (argc != 3) return 80;
  int refused = !strcmp(argv[1], "refused");
  if (!refused && strcmp(argv[1], "supported")) return 81;
  unsigned char *data = mmap(NULL, CAP + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  unsigned char *verify = mmap(NULL, CAP + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (data == MAP_FAILED || verify == MAP_FAILED) return 82;
  int fd = open(argv[2], O_CREAT | O_TRUNC | O_RDWR | O_DIRECT, 0600);
  if (fd < 0) return 83;
  const long numbers[] = {SYS_readv, SYS_writev, SYS_preadv, SYS_pwritev, SYS_preadv2, SYS_pwritev2};
  const size_t file_size = refused ? 8192 : CAP;
  for (size_t index = 0; index < sizeof(numbers)/sizeof(numbers[0]); ++index) {
    for (int separate_tail = 0; separate_tail <= refused; ++separate_tail) {
      memset(data, 'f', CAP + 4096);
      struct iovec seed = {data, file_size};
      if (pwritev(fd, &seed, 1, 0) != (ssize_t)file_size) return 84;
      if (ftruncate(fd, file_size)) return 85;
      if (lseek(fd, refused ? 4096 : 0, SEEK_SET) < 0) return 86;
      memset(data, 'm', CAP + 4096);
      struct iovec vectors[2] = {{data, CAP + (refused && !separate_tail)}, {data + CAP, separate_tail ? 1 : 0}};
      struct iovec before[2]; memcpy(before, vectors, sizeof(before));
      errno = 0;
      long result = syscall(numbers[index], fd, vectors, separate_tail ? 2 : 1, 0UL, 0UL, 0UL);
      int error = errno;
      off_t position = lseek(fd, 0, SEEK_CUR);
      struct stat metadata;
      if (fstat(fd, &metadata)) return 87;
      int observer = open(argv[2], O_RDONLY);
      if (observer < 0 || pread(observer, verify, file_size, 0) != (ssize_t)file_size) return 88;
      close(observer);
      int reading = index % 2 == 0;
      int okay = memcmp(before, vectors, sizeof(before)) == 0 && metadata.st_size == (off_t)file_size;
      if (refused) {
        okay &= result == -1 && error == EOPNOTSUPP && position == 4096;
        okay &= all_bytes(data, CAP + 4096, 'm') && all_bytes(verify, file_size, 'f');
      } else {
        okay &= result == CAP && position == (index < 2 ? (off_t)CAP : 0);
        okay &= all_bytes(data, CAP, reading ? 'f' : 'm') && all_bytes(data + CAP, 4096, 'm');
        okay &= all_bytes(verify, file_size, reading ? 'f' : 'm');
      }
      if (!okay) {
        fprintf(stderr, "mode=%s syscall=%ld tail=%d result=%ld errno=%d position=%ld file_size=%ld\n", argv[1], numbers[index], separate_tail, result, error, (long)position, (long)metadata.st_size);
        return 89;
      }
      printf("%s syscall=%ld tail=%d complete=1\n", argv[1], numbers[index], separate_tail);
    }
  }
  return close(fd) ? 90 : 0;
}
"#,
    );
    let native = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "15s"])
        .arg(&executable)
        .arg("supported")
        .arg(directory.0.join("native-direct-cap"))
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "native boundary control: {native:?}"
    );
    let expected_native = [19, 20, 295, 296, 327, 328]
        .into_iter()
        .map(|number| format!("supported syscall={number} tail=0 complete=1\n"))
        .collect::<String>();
    assert_eq!(native.stdout, expected_native.as_bytes());
    assert!(native.stderr.is_empty());
    let image = std::fs::read(&executable).unwrap();
    for mode in ["supported", "refused"] {
        let path = directory.0.join(format!("guest-direct-cap-{mode}"));
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable.to_str().unwrap(), mode, path.to_str().unwrap()],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
        assert_eq!(
            code,
            0,
            "{mode}: stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        let expected = if mode == "supported" {
            expected_native.clone()
        } else {
            [19, 20, 295, 296, 327, 328]
                .into_iter()
                .flat_map(|number| {
                    [0, 1].into_iter().map(move |tail| {
                        format!("refused syscall={number} tail={tail} complete=1\n")
                    })
                })
                .collect::<String>()
        };
        assert_eq!(stdout, expected.as_bytes(), "{mode}");
        assert!(stderr.is_empty(), "{mode}: {stderr:?}");
        eprintln!("{mode}: {}", String::from_utf8_lossy(&stdout));
    }
}

#[test]
fn vectored_io_uses_linux_fd_and_flag_argument_widths() {
    const TEST: &str = "vectored_io_uses_linux_fd_and_flag_argument_widths";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program_with_args(
        &directory.0,
        "vectored-fd-width",
        include_str!("fixtures/vectored_fd_width.c"),
        &["-std=c11", "-Wall", "-Wextra", "-Werror"],
    );
    let native = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "10s"])
        .arg(&executable)
        .arg(directory.0.join("native-fd-width"))
        .output()
        .unwrap();
    assert!(native.status.success(), "native fixture failed: {native:?}");
    let native_stdout = std::str::from_utf8(&native.stdout).unwrap();
    assert_eq!(native_stdout.lines().count(), 38);
    assert!(native.stderr.is_empty());

    let guest_path = directory.0.join("guest-fd-width");
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&executable).unwrap(),
            &[executable.to_str().unwrap(), guest_path.to_str().unwrap()],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "KVM fixture exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

const SIBLING_SIGNAL_PROGRAM: &str = r#"#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
static atomic_int target_tid, phase, handled, handler_tid;
static int mode;
static pthread_t target_pthread;
static sigset_t selected;
static void handler(int number, siginfo_t *info, void *context) {
  (void)context;
  if (number != SIGUSR1 || info->si_signo != SIGUSR1 ||
      info->si_code != SI_TKILL || info->si_pid != getpid() ||
      info->si_uid != getuid()) _exit(81);
  atomic_store(&handler_tid, (int)syscall(SYS_gettid));
  atomic_fetch_add(&handled, 1);
}
static void install_handler(void) {
  struct sigaction action = {0}; action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO; sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL)) _exit(82);
}
static void wait_phase(int expected) {
  while (atomic_load(&phase) < expected) sched_yield();
}
static void send_to_target(void) {
  int target; while (!(target = atomic_load(&target_tid))) sched_yield();
  int result = mode == 0 ? pthread_kill(target_pthread, SIGUSR1) :
    mode == 1 ? (int)syscall(SYS_tkill, target, SIGUSR1) :
    (int)syscall(SYS_tgkill, getpid(), target, SIGUSR1);
  if (result) _exit(83);
}
static void *sender(void *unused) { (void)unused; send_to_target(); return NULL; }
static void *receiver(void *unused) {
  (void)unused;
  int blocked = mode == 3 || mode == 4 || mode == 6 || mode == 7 || mode == 8;
  if (blocked && pthread_sigmask(SIG_BLOCK, &selected, NULL)) _exit(84);
  atomic_store(&target_tid, (int)syscall(SYS_gettid));
  wait_phase(1);
  if (mode == 3 || mode == 8) {
    sigset_t pending; if (sigpending(&pending) || !sigismember(&pending, SIGUSR1)) _exit(85);
    siginfo_t info = {0}; struct timespec zero = {0};
    // glibc folds SI_TKILL to SI_USER; retain exact checks for both APIs.
    int received = mode == 8 ?
      (int)syscall(SYS_rt_sigtimedwait, &selected, &info, &zero, 8) :
      sigtimedwait(&selected, &info, &zero);
    int expected_code = mode == 8 ? SI_TKILL : SI_USER;
    if (received != SIGUSR1 || info.si_signo != SIGUSR1 ||
        info.si_code != expected_code || info.si_pid != getpid() ||
        info.si_uid != getuid()) _exit(86);
    errno = 0;
    if (sigtimedwait(&selected, NULL, &zero) != -1 || errno != EAGAIN) _exit(87);
    if (atomic_load(&handled)) _exit(88);
  } else if (mode == 5) {
    // An actual return boundary after publication precedes handler installation.
    for (int i = 0; i < 3; ++i) sched_yield();
    atomic_store(&phase, 2); wait_phase(3);
    for (int i = 0; i < 3; ++i) sched_yield();
    if (atomic_load(&handled)) _exit(89);
  } else {
    if (blocked) {
      if (atomic_load(&handled)) _exit(90);
      if (pthread_sigmask(SIG_UNBLOCK, &selected, NULL)) _exit(91);
      if (atomic_load(&handled) != 1) _exit(92);
    }
    while (!atomic_load(&handled)) sched_yield();
    if (atomic_load(&handled) != 1 || atomic_load(&handler_tid) != atomic_load(&target_tid)) _exit(93);
  }
  return NULL;
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  mode = atoi(argv[1]);
  sigemptyset(&selected); sigaddset(&selected, SIGUSR1);
  install_handler();
  if (mode == 5 || mode == 6 || mode == 9) {
    struct sigaction ignored = {0}; ignored.sa_handler = mode == 9 ? SIG_DFL : SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    if (sigaction(SIGUSR1, &ignored, NULL)) return 3;
  }
  pthread_t receiver_thread, sender_thread;
  if (mode == 0) {
    target_pthread = pthread_self();
    atomic_store(&target_tid, (int)syscall(SYS_gettid));
    if (pthread_create(&sender_thread, NULL, sender, NULL) || pthread_join(sender_thread, NULL)) return 4;
    if (atomic_load(&handled) != 1 || atomic_load(&handler_tid) != atomic_load(&target_tid)) return 5;
  } else {
    if (pthread_create(&receiver_thread, NULL, receiver, NULL)) return 6;
    while (!atomic_load(&target_tid)) sched_yield();
    if (mode == 2) {
      if (pthread_create(&sender_thread, NULL, sender, NULL) || pthread_join(sender_thread, NULL)) return 7;
    } else {
      send_to_target();
    }
    if (mode == 3 || mode == 8) {
      send_to_target();
      sigset_t pending; if (sigpending(&pending) || sigismember(&pending, SIGUSR1)) return 8;
      struct timespec zero = {0}; errno = 0;
      if (sigtimedwait(&selected, NULL, &zero) != -1 || errno != EAGAIN) return 9;
    }
    if (mode == 6) install_handler();
    if (mode == 7) {
      char *const args[] = {"missing", NULL};
      execve("/no-such-astra-reverie-signal-executable", args, NULL);
      if (errno != ENOENT) return 10;
    }
    atomic_store(&phase, 1);
    if (mode == 5) {
      wait_phase(2); install_handler(); atomic_store(&phase, 3);
    }
    if (pthread_join(receiver_thread, NULL)) return 11;
  }
  puts("sibling-signal-checked");
  return 0;
}
"#;

#[derive(Default)]
struct SiblingSignalLog {
    signals: Mutex<Vec<(i32, i32, i32, i32)>>,
    starts: Mutex<Vec<i32>>,
}

#[reverie::global_tool]
impl GlobalTool for SiblingSignalLog {
    type Request = (i32, i32, i32, i32);
    type Response = ();
    type Config = u8;

    async fn receive_rpc(&self, _from: Pid, event: Self::Request) {
        if event.0 == 0 {
            self.starts.lock().unwrap().push(event.1);
        } else {
            self.signals.lock().unwrap().push(event);
        }
    }
}

#[derive(Default)]
struct SiblingSignalTool;

#[reverie::tool]
impl Tool for SiblingSignalTool {
    type GlobalState = SiblingSignalLog;
    type ThreadState = bool;

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        assert!(!*guest.thread_state());
        *guest.thread_state_mut() = true;
        guest.send_rpc((0, guest.tid().as_raw(), 0, 0)).await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        guest.tail_inject(syscall).await
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert!(
            *guest.thread_state(),
            "receiver signal hook ran before Tool admission"
        );
        let SignalTarget::Thread { pid, tid } = event.target() else {
            panic!("sibling signal entered the process-pending domain");
        };
        assert_eq!((pid, tid), (guest.pid(), guest.tid()));
        let info = event.siginfo();
        assert_eq!(
            i32::from_ne_bytes(info[8..12].try_into().unwrap()),
            libc::SI_TKILL
        );
        assert_eq!(
            i32::from_ne_bytes(info[16..20].try_into().unwrap()),
            pid.as_raw()
        );
        guest
            .send_rpc((1, pid.as_raw(), tid.as_raw(), event.signal()))
            .await;
        let observed_tid = guest.inject(reverie::syscalls::Gettid::new()).await?;
        assert_eq!(observed_tid, i64::from(tid.as_raw()));
        Ok(Some(event))
    }
}

#[test]
fn sibling_signal_delivery_native_plain_and_tool() {
    const TEST: &str = "sibling_signal_delivery_native_plain_and_tool";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "sibling-signal", SIBLING_SIGNAL_PROGRAM);
    let program = executable.to_str().unwrap();
    let image = std::fs::read(&executable).unwrap();
    for mode in 0..=9 {
        let argument = mode.to_string();
        let native = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "5s"])
            .arg(program)
            .arg(&argument)
            .output()
            .unwrap();
        if mode == 9 {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                native.status.signal(),
                Some(libc::SIGUSR1),
                "native mode={mode}: {native:?}"
            );
            assert!(native.stdout.is_empty());
        } else {
            assert!(native.status.success(), "native mode={mode}: {native:?}");
            assert_eq!(native.stdout, b"sibling-signal-checked\n");
        }
        assert!(native.stderr.is_empty());
        for tool_owned in [false, true] {
            let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
            backend
                .install_static_elf_with_context(&image, &[program, &argument], &[], &directory.0)
                .unwrap();
            let (code, stdout, stderr) = if tool_owned {
                let (log, code, stdout, stderr) = futures::executor::block_on(
                    backend.run_static_elf_with_tool::<SiblingSignalTool>(0, true),
                )
                .unwrap();
                let events = log.signals.lock().unwrap();
                assert_eq!(
                    events.len(),
                    if mode == 3 || mode == 8 { 0 } else { 1 },
                    "mode={mode}: {events:?}"
                );
                if let Some(event) = events.first() {
                    assert_eq!(event.1, 1);
                    assert_eq!(event.3, libc::SIGUSR1);
                    assert_eq!(
                        event.2 == 1,
                        mode == 0,
                        "delivery used the wrong receiver: {event:?}"
                    );
                }
                assert_eq!(
                    log.starts.lock().unwrap().len(),
                    if mode == 2 { 3 } else { 2 }
                );
                (code, stdout, stderr)
            } else {
                backend.run_static_elf_captured().unwrap()
            };
            eprintln!("sibling mode={mode} tool_owned={tool_owned} code={code}");
            assert_eq!(
                code,
                if mode == 9 { 128 + libc::SIGUSR1 } else { 0 },
                "mode={mode} tool_owned={tool_owned}: stdout={stdout:?} stderr={stderr:?}"
            );
            assert_eq!(stdout, native.stdout, "mode={mode} tool_owned={tool_owned}");
            assert_eq!(stderr, native.stderr, "mode={mode} tool_owned={tool_owned}");
        }
    }
}

const SIBLING_ENTRY_SIGNAL_PROGRAM: &str = r#"#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
static unsigned char stack[65536] __attribute__((aligned(16)));
static atomic_int handled, done, result;
static int mode;
static void handler(int number, siginfo_t *info, void *context) {
  (void)context;
  if (info->si_signo != number || info->si_code != SI_TKILL ||
      info->si_pid != getpid() || info->si_uid != getuid() ||
      syscall(SYS_gettid) == getpid()) _exit(71);
  if (atomic_exchange(&handled, number)) _exit(72);
}
static int child(void *unused) {
  (void)unused;
  // No syscall precedes this first observation of the new thread's user code.
  int expected = mode == 0 ? SIGUSR1 : mode == 2 ? SIGUSR2 : 0;
  if (atomic_load(&handled) != expected) atomic_store(&result, 73);
  if (mode == 3) {
    unsigned long mask = 1UL << (SIGUSR2 - 1);
    if (syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &mask, NULL, 8) ||
        atomic_load(&handled) != SIGUSR2) atomic_store(&result, 74);
  }
  atomic_store(&done, 1);
  syscall(SYS_exit, 0);
  __builtin_unreachable();
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  mode = atoi(argv[1]);
  struct sigaction action = {0}; action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO; sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) || sigaction(SIGUSR2, &action, NULL)) return 3;
  if (mode == 3) {
    sigset_t selected; sigemptyset(&selected); sigaddset(&selected, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &selected, NULL)) return 4;
  }
  if (clone(child, stack + sizeof(stack), CLONE_VM | CLONE_FS | CLONE_FILES |
      CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM, NULL) < 0) return 5;
  while (!atomic_load(&done)) sched_yield();
  if (atomic_load(&result)) return atomic_load(&result);
  int expected = mode == 1 ? 0 : mode == 0 ? SIGUSR1 : SIGUSR2;
  if (atomic_load(&handled) != expected) return 75;
  puts("sibling-entry-signal-checked");
  return 0;
}
"#;

#[derive(Default)]
struct SiblingEntrySignalTool;

#[reverie::tool]
impl Tool for SiblingEntrySignalTool {
    type GlobalState = SiblingSignalLog;
    type ThreadState = bool;

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        assert!(!*guest.thread_state());
        *guest.thread_state_mut() = true;
        guest.send_rpc((0, guest.tid().as_raw(), 0, 0)).await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if matches!(syscall, Syscall::Clone(_)) {
            let child = guest.inject(syscall).await?;
            assert!(child > 0);
            // The pending child's start gate is released after this parent
            // callback returns; the receiver already has its private queue.
            let sent = guest
                .inject(
                    reverie::syscalls::Tgkill::new()
                        .with_tgid(guest.pid().as_raw())
                        .with_tid(i32::try_from(child).unwrap())
                        .with_sig(libc::SIGUSR1),
                )
                .await?;
            assert_eq!(sent, 0);
            Ok(child)
        } else {
            guest.tail_inject(syscall).await
        }
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert!(
            *guest.thread_state(),
            "entry signal preceded Tool admission"
        );
        assert_ne!(guest.pid(), guest.tid());
        assert_eq!(
            event.target(),
            SignalTarget::Thread {
                pid: guest.pid(),
                tid: guest.tid()
            }
        );
        guest
            .send_rpc((
                1,
                guest.pid().as_raw(),
                guest.tid().as_raw(),
                event.signal(),
            ))
            .await;
        assert_eq!(
            guest.inject(reverie::syscalls::Gettid::new()).await?,
            i64::from(guest.tid().as_raw())
        );
        if event.signal() == libc::SIGUSR1 {
            assert_eq!(
                guest.inject(Fork::new()).await,
                Err(Errno::ENOSYS),
                "entry callback must refuse a process action before effects"
            );
            match *guest.config() {
                1 => return Ok(None),
                2 | 3 => {
                    let mut info = event.siginfo();
                    info[0..4].copy_from_slice(&libc::SIGUSR2.to_ne_bytes());
                    return Ok(Some(SignalEvent::new(libc::SIGUSR2, info, event.target())?));
                }
                _ => {}
            }
        }
        Ok(Some(event))
    }
}

#[test]
fn sibling_signal_before_first_instruction_with_tool() {
    const TEST: &str = "sibling_signal_before_first_instruction_with_tool";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "sibling-entry-signal",
        SIBLING_ENTRY_SIGNAL_PROGRAM,
    );
    let program = executable.to_str().unwrap();
    let image = std::fs::read(&executable).unwrap();
    for mode in 0..=3 {
        let argument = mode.to_string();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(&image, &[program, &argument], &[], &directory.0)
            .unwrap();
        let (log, code, stdout, stderr) = futures::executor::block_on(
            backend.run_static_elf_with_tool::<SiblingEntrySignalTool>(mode, true),
        )
        .unwrap();
        eprintln!("sibling entry mode={mode} code={code}");
        assert_eq!(code, 0, "mode={mode}: stdout={stdout:?} stderr={stderr:?}");
        assert_eq!(stdout, b"sibling-entry-signal-checked\n");
        assert!(stderr.is_empty(), "mode={mode}: {stderr:?}");
        assert_eq!(log.starts.lock().unwrap().len(), 2);
        let events = log.signals.lock().unwrap();
        assert_eq!(
            events.len(),
            if mode == 3 { 2 } else { 1 },
            "mode={mode}: {events:?}"
        );
        assert_eq!(events[0], (1, 1, 2, libc::SIGUSR1));
        if mode == 3 {
            assert_eq!(events[1], (1, 1, 2, libc::SIGUSR2));
        }
    }
}

#[derive(Default)]
struct PipeFionreadLog {
    calls: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for PipeFionreadLog {
    type Request = ();
    type Response = ();
    type Config = ();
    async fn receive_rpc(&self, _from: Pid, _: ()) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Default)]
struct PipeFionreadTool;

#[reverie::tool]
impl Tool for PipeFionreadTool {
    type GlobalState = PipeFionreadLog;
    type ThreadState = ();
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if matches!(syscall, Syscall::Ioctl(_)) {
            guest.send_rpc(()).await;
        }
        guest.tail_inject(syscall).await
    }
}

#[test]
fn pipe_fionread_native_and_kvm_complete_contract() {
    const TEST: &str = "pipe_fionread_native_and_kvm_complete_contract";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    for mode in ["supported", "excluded", "capture"] {
        for runner in ["native", "plain", "tool"] {
            if mode == "capture" && runner == "native" {
                // Capture is a backend capability refusal; its native backing
                // count is measured in the separate subprocess executor test.
                continue;
            }
            let directory = TestDirectory::new();
            let executable = compile_c_program(
                &directory.0,
                "pipe-fionread",
                include_str!("fixtures/pipe_fionread.c"),
            );
            if let Some(artifacts) = std::env::var_os("REVERIE_PIPE_FIONREAD_ARTIFACTS") {
                let artifacts = PathBuf::from(artifacts);
                std::fs::create_dir_all(&artifacts).unwrap();
                std::fs::copy(&executable, artifacts.join(format!("{mode}-{runner}"))).unwrap();
                std::fs::copy(
                    executable.with_extension("c"),
                    artifacts.join(format!("{mode}-{runner}.c")),
                )
                .unwrap();
            }
            let argument = match (mode, runner) {
                ("excluded", "native") => "native-excluded",
                ("excluded", _) => "kvm-excluded",
                _ => mode,
            };
            let expected: &[u8] = match argument {
                "supported" => b"pipe-fionread-supported-checked\n",
                "native-excluded" => b"excluded-native-behavior-checked\n",
                "kvm-excluded" => b"excluded-kvm-refusals-checked\n",
                "capture" => b"",
                _ => unreachable!(),
            };
            if runner == "native" {
                let output = std::process::Command::new("timeout")
                    .args(["--kill-after=2s", "15s"])
                    .arg(&executable)
                    .arg(argument)
                    .current_dir(&directory.0)
                    .output()
                    .unwrap();
                eprintln!(
                    "pipe FIONREAD mode={mode} runner={runner} status={:?}",
                    output.status
                );
                assert!(
                    output.status.success(),
                    "stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(output.stdout, expected);
                assert!(output.stderr.is_empty(), "{output:?}");
                continue;
            }
            let program = executable.to_str().unwrap();
            let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
            backend
                .install_static_elf_file_with_context(
                    std::fs::File::open(&executable).unwrap(),
                    &[program, argument],
                    &[],
                    &directory.0,
                )
                .unwrap();
            let (code, stdout, stderr) = if runner == "plain" {
                backend.run_static_elf_captured().unwrap()
            } else {
                let (log, code, stdout, stderr) = futures::executor::block_on(
                    backend.run_static_elf_with_tool::<PipeFionreadTool>((), true),
                )
                .unwrap();
                let calls = log.calls.load(Ordering::SeqCst);
                let expected_calls = match mode {
                    "supported" => 54,
                    "excluded" => 24,
                    "capture" => 12,
                    _ => unreachable!(),
                };
                eprintln!("pipe FIONREAD mode={mode} actual Tool ioctl callbacks={calls}");
                assert_eq!(calls, expected_calls, "actual ioctl Tool callbacks");
                (code, stdout, stderr)
            };
            eprintln!("pipe FIONREAD mode={mode} runner={runner} code={code}");
            assert_eq!(
                code,
                0,
                "mode={mode} runner={runner} stdout={} stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            assert_eq!(stdout, expected);
            assert!(
                stderr.is_empty(),
                "mode={mode} runner={runner} stderr={}",
                String::from_utf8_lossy(&stderr)
            );
        }
    }
}

#[path = "support/terminal_cancellation.rs"]
mod terminal_cancellation;

#[path = "support/exec_worker_error_diagnostic.rs"]
mod exec_worker_error_diagnostic;

#[path = "support/child_exit_signals.rs"]
mod child_exit_signals;

#[path = "support/terminal_fork.rs"]
mod terminal_fork;

#[path = "support/leader_exit.rs"]
mod leader_exit;

#[path = "support/process_alarm_signals.rs"]
mod process_alarm_signals;

#[path = "support/parked_signals.rs"]
mod parked_signals;

#[path = "support/captured_write_signals.rs"]
mod captured_write_signals;

#[path = "support/timestamp_terminal.rs"]
mod timestamp_terminal;

#[path = "support/capture_identity.rs"]
mod capture_identity;

#[path = "support/cpuid_dispatch.rs"]
mod cpuid_dispatch;

#[path = "support/cpuid_terminal.rs"]
mod cpuid_terminal;

const RDTSC_SENTINEL: u64 = 0x1122_3344_5566_7788;
const RDTSCP_SENTINEL: u64 = 0x99aa_bbcc_ddee_ff00;
const RDTSCP_AUX_SENTINEL: u32 = 0x1357_9bdf;

#[derive(Debug, Default)]
struct TimestampLog {
    calls: Mutex<Vec<(Pid, Rdtsc)>>,
}

impl TimestampLog {
    fn calls(&self) -> Vec<(Pid, Rdtsc)> {
        self.calls
            .lock()
            .expect("timestamp log lock poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for TimestampLog {
    type Request = Rdtsc;
    type Response = ();
    type Config = bool;

    async fn receive_rpc(&self, from: Pid, request: Rdtsc) {
        self.calls
            .lock()
            .expect("timestamp log lock poisoned")
            .push((from, request));
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TimestampTool;

#[reverie::tool]
impl Tool for TimestampTool {
    type GlobalState = TimestampLog;
    type ThreadState = ();

    fn subscriptions(enabled: &bool) -> Subscription {
        let mut subscriptions = Subscription::none();
        if *enabled {
            subscriptions.rdtsc();
        }
        subscriptions
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        guest.send_rpc(request).await;
        Ok(match request {
            Rdtsc::Tsc => RdtscResult {
                tsc: RDTSC_SENTINEL,
                aux: None,
            },
            Rdtsc::Tscp => RdtscResult {
                tsc: RDTSCP_SENTINEL,
                aux: Some(RDTSCP_AUX_SENTINEL),
            },
        })
    }
}

fn append_jne_failure(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
    code.extend_from_slice(&[0x0f, 0x85]);
    patches.push(code.len());
    code.extend_from_slice(&0_i32.to_le_bytes());
}

fn timestamp_assertion_program() -> Vec<u8> {
    let mut code = Vec::new();
    let mut failure_patches = Vec::new();

    code.extend_from_slice(&[0x0f, 0x31]); // rdtsc
    code.push(0x3d); // cmp eax, imm32
    code.extend_from_slice(&(RDTSC_SENTINEL as u32).to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);
    code.extend_from_slice(&[0x81, 0xfa]); // cmp edx, imm32
    code.extend_from_slice(&((RDTSC_SENTINEL >> 32) as u32).to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);

    code.extend_from_slice(&[0x0f, 0x01, 0xf9]); // rdtscp
    code.push(0x3d); // cmp eax, imm32
    code.extend_from_slice(&(RDTSCP_SENTINEL as u32).to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);
    code.extend_from_slice(&[0x81, 0xfa]); // cmp edx, imm32
    code.extend_from_slice(&((RDTSCP_SENTINEL >> 32) as u32).to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);
    code.extend_from_slice(&[0x81, 0xf9]); // cmp ecx, imm32
    code.extend_from_slice(&RDTSCP_AUX_SENTINEL.to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);

    code.extend_from_slice(&[
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
    ]);
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x0f, 0x05, // syscall
    ]);

    for patch in failure_patches {
        let displacement = i32::try_from(failure).unwrap() - i32::try_from(patch + 4).unwrap();
        code[patch..patch + 4].copy_from_slice(&displacement.to_le_bytes());
    }
    code
}

fn run_timestamp_probe(image: &[u8], subscribed: bool) -> (TimestampLog, i32) {
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(image, "/bin/timestamp-probe")
        .unwrap();
    let (log, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<TimestampTool>(subscribed, true),
    )
    .unwrap();
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    (log, code)
}

#[test]
fn static_elf_timestamp_reads_dispatch_exact_tool_results_repeatably() {
    if !kvm_available("KVM timestamp dispatch test") {
        return;
    }

    let image = static_elf(&timestamp_assertion_program());
    for _ in 0..2 {
        let (log, code) = run_timestamp_probe(&image, true);
        assert_eq!(code, 0);
        assert_eq!(
            log.calls(),
            vec![
                (Pid::from_raw(1), Rdtsc::Tsc),
                (Pid::from_raw(1), Rdtsc::Tscp)
            ]
        );
    }
}

#[test]
fn timestamp_dispatch_survives_thread_fork_and_exec_vcpu_lifecycles() {
    if !kvm_available("KVM timestamp lifecycle test") {
        return;
    }

    let directory = TestDirectory::new();
    let source = format!(
        r#"
#include <pthread.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t read_tsc(void) {{
    unsigned int low;
    unsigned int high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32) | low;
}}

static void *thread_main(void *unused) {{
    (void)unused;
    return (void *)(uintptr_t)(read_tsc() != UINT64_C({RDTSC_SENTINEL}));
}}

int main(int argc, char **argv) {{
    if (read_tsc() != UINT64_C({RDTSC_SENTINEL})) return 10;
    if (argc > 1) return 0;

    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_main, NULL) != 0) return 11;
    void *thread_result = NULL;
    if (pthread_join(thread, &thread_result) != 0 || thread_result != NULL) return 12;

    pid_t child = fork();
    if (child < 0) return 13;
    if (child == 0) {{
        if (read_tsc() != UINT64_C({RDTSC_SENTINEL})) _exit(14);
        execl(argv[0], argv[0], "post-exec", NULL);
        _exit(15);
    }}
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 16;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 17;
}}
"#
    );
    let executable = compile_c_program(&directory.0, "timestamp-lifecycle", &source);
    let image = std::fs::read(&executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap()],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let (log, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<TimestampTool>(true, true))
            .unwrap();
    assert_eq!(code, 0, "stdout={stdout:?} stderr={stderr:?}");
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());

    let calls = log.calls();
    let mut senders = calls
        .iter()
        .map(|(sender, _)| sender.as_raw())
        .collect::<Vec<_>>();
    senders.sort_unstable();
    senders.dedup();
    assert!(
        senders.len() >= 3,
        "expected root, pthread, and fork-child timestamp senders; calls={calls:?}"
    );
    let child = *senders.iter().max().unwrap();
    assert!(
        calls
            .iter()
            .filter(|(sender, _)| sender.as_raw() == child)
            .count()
            >= 2,
        "fork child must dispatch timestamps before and after exec; calls={calls:?}"
    );
}

#[test]
fn static_elf_unsubscribed_rdtsc_runs_without_tool_dispatch() {
    if !kvm_available("KVM unsubscribed RDTSC test") {
        return;
    }

    let image = static_elf(&[
        0x0f, 0x31, // rdtsc
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
    ]);
    let (log, code) = run_timestamp_probe(&image, false);
    assert_eq!(code, 0);
    assert!(log.calls().is_empty());
}

#[test]
fn subscribed_timestamp_dispatch_refuses_unrelated_exceptions() {
    if !kvm_available("KVM timestamp exception refusal test") {
        return;
    }

    let mut invalid_opcode_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    invalid_opcode_backend
        .install_static_elf(&static_elf(&[0x0f, 0x0b]), "/bin/fault")
        .unwrap();
    let error = futures::executor::block_on(
        invalid_opcode_backend.run_static_elf_with_tool::<TimestampTool>(true, true),
    )
    .unwrap_err();
    assert_invalid_opcode(error);

    let mut general_protection_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    general_protection_backend
        .install_static_elf(&static_elf(&[0xed]), "/bin/fault")
        .unwrap();
    let error = futures::executor::block_on(
        general_protection_backend.run_static_elf_with_tool::<TimestampTool>(true, true),
    )
    .unwrap_err();
    assert_general_protection(error);
}

#[derive(Clone, Copy, Debug, Default)]
struct EvolvingTimestampTool;

#[reverie::tool]
impl Tool for EvolvingTimestampTool {
    type GlobalState = TimestampLog;
    type ThreadState = u64;

    fn subscriptions(enabled: &bool) -> Subscription {
        let mut subscriptions = Subscription::none();
        if *enabled {
            subscriptions.rdtsc();
        }
        subscriptions
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        let ordinal = *guest.thread_state();
        *guest.thread_state_mut() += 1;
        guest.send_rpc(request).await;
        Ok(RdtscResult {
            tsc: RDTSC_SENTINEL + ordinal,
            aux: (request == Rdtsc::Tscp).then_some(RDTSCP_AUX_SENTINEL + ordinal as u32),
        })
    }
}

fn evolving_timestamp_assertion_program() -> Vec<u8> {
    let mut code = Vec::new();
    let mut failure_patches = Vec::new();

    for expected in [RDTSC_SENTINEL, RDTSC_SENTINEL + 1] {
        code.extend_from_slice(&[0x0f, 0x31]); // rdtsc
        code.push(0x3d); // cmp eax, imm32
        code.extend_from_slice(&(expected as u32).to_le_bytes());
        append_jne_failure(&mut code, &mut failure_patches);
        code.extend_from_slice(&[0x81, 0xfa]); // cmp edx, imm32
        code.extend_from_slice(&((expected >> 32) as u32).to_le_bytes());
        append_jne_failure(&mut code, &mut failure_patches);
    }

    let rdtscp_expected = RDTSC_SENTINEL + 2;
    code.extend_from_slice(&[0x0f, 0x01, 0xf9]); // rdtscp
    code.push(0x3d); // cmp eax, imm32
    code.extend_from_slice(&(rdtscp_expected as u32).to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);
    code.extend_from_slice(&[0x81, 0xfa]); // cmp edx, imm32
    code.extend_from_slice(&((rdtscp_expected >> 32) as u32).to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);
    code.extend_from_slice(&[0x81, 0xf9]); // cmp ecx, imm32
    code.extend_from_slice(&(RDTSCP_AUX_SENTINEL + 2).to_le_bytes());
    append_jne_failure(&mut code, &mut failure_patches);

    code.extend_from_slice(&[
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
    ]);
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x0f, 0x05, // syscall
    ]);

    for patch in failure_patches {
        let displacement = i32::try_from(failure).unwrap() - i32::try_from(patch + 4).unwrap();
        code[patch..patch + 4].copy_from_slice(&displacement.to_le_bytes());
    }
    code
}

#[test]
fn repeated_timestamp_reads_evolve_once_per_instruction() {
    if !kvm_available("KVM evolving timestamp test") {
        return;
    }

    let image = static_elf(&evolving_timestamp_assertion_program());
    for _ in 0..2 {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&image, "/bin/evolving-timestamp-probe")
            .unwrap();
        let (log, code, stdout, stderr) = futures::executor::block_on(
            backend.run_static_elf_with_tool::<EvolvingTimestampTool>(true, true),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(
            log.calls(),
            vec![
                (Pid::from_raw(1), Rdtsc::Tsc),
                (Pid::from_raw(1), Rdtsc::Tsc),
                (Pid::from_raw(1), Rdtsc::Tscp),
            ]
        );
    }
}

#[test]
fn static_elf_unsubscribed_rdtscp_remains_guest_exception() {
    if !kvm_available("KVM unsubscribed RDTSCP test") {
        return;
    }

    let image = static_elf(&[
        0x0f, 0x01, 0xf9, // rdtscp
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
    ]);
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&image, "/bin/unsubscribed-rdtscp")
        .unwrap();
    let error =
        futures::executor::block_on(backend.run_static_elf_with_tool::<TimestampTool>(false, true))
            .unwrap_err();
    assert_invalid_opcode(error);
}

#[derive(Clone, Copy, Debug, Default)]
struct ClockTimestampTool;

#[reverie::tool]
impl Tool for ClockTimestampTool {
    type GlobalState = TimestampLog;
    type ThreadState = (Option<u64>, u64);

    fn subscriptions(enabled: &bool) -> Subscription {
        TimestampTool::subscriptions(enabled)
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        let before = guest
            .read_clock()
            .expect("timestamp clock must be available");
        let (previous, ordinal) = *guest.thread_state();
        if let Some(previous) = previous {
            assert!(
                before > previous,
                "actual guest assertion branches must retire between reads"
            );
        }
        let pid = guest.pid().as_raw() as i64;
        assert_eq!(
            guest
                .inject(Syscall::from_raw(
                    Sysno::getpid,
                    SyscallArgs::new(0, 0, 0, 0, 0, 0),
                ))
                .await?,
            pid,
        );
        assert_eq!(guest.inject(Fork::new()).await, Err(Errno::ENOSYS));
        assert_eq!(
            guest
                .inject(Syscall::from_raw(
                    Sysno::execve,
                    SyscallArgs::new(0, 0, 0, 0, 0, 0),
                ))
                .await,
            Err(Errno::ENOSYS),
        );
        guest.send_rpc(request).await;
        assert_eq!(
            guest.read_clock().unwrap(),
            before,
            "RPC and returning/refused host injections are not guest branch time"
        );
        *guest.thread_state_mut() = (Some(before), ordinal + 1);
        Ok(RdtscResult {
            tsc: RDTSC_SENTINEL + ordinal,
            aux: (request == Rdtsc::Tscp).then_some(RDTSCP_AUX_SENTINEL + ordinal as u32),
        })
    }
}

#[test]
fn timestamp_callbacks_observe_retired_branches_without_counting_rpc_work() {
    if !kvm_available("KVM timestamp callback clock test") {
        return;
    }
    for _ in 0..2 {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(
                &static_elf(&evolving_timestamp_assertion_program()),
                "/bin/timestamp-clock",
            )
            .unwrap();
        let (log, status, stdout, stderr) = futures::executor::block_on(
            backend.run_static_elf_with_tool::<ClockTimestampTool>(true, true),
        )
        .unwrap();
        assert_eq!(status, 0);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(
            log.calls(),
            vec![
                (Pid::from_raw(1), Rdtsc::Tsc),
                (Pid::from_raw(1), Rdtsc::Tsc),
                (Pid::from_raw(1), Rdtsc::Tscp)
            ]
        );
    }
}

fn host_owned_timestamp_program() -> Vec<u8> {
    fn append_root_read(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x31]); // rdtsc
        code.push(0x3d); // cmp eax, expected low word
        code.extend_from_slice(&(RDTSC_SENTINEL as u32).to_le_bytes());
        append_jne_failure(code, failures);
        code.extend_from_slice(&[0x81, 0xfa]); // cmp edx, expected high word
        code.extend_from_slice(&((RDTSC_SENTINEL >> 32) as u32).to_le_bytes());
        append_jne_failure(code, failures);
    }

    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_RESULT: u64 = LOAD_ADDRESS + 0x1808;
    const CHILD_DONE: u64 = LOAD_ADDRESS + 0x1810;
    const CHILD_STACK: u64 = LOAD_ADDRESS + 0x1900;
    const CHILD_STACK_SIZE: u64 = 0x600;
    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_SYSVSEM as u64
        | libc::CLONE_CHILD_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64;
    let mut code = Vec::new();
    let mut failures = Vec::new();
    append_root_read(&mut code, &mut failures);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[
        0xc7, 0x01, 0xff, 0xff, 0xff, 0x7f, // mov [rcx], nonzero sentinel
        0xb8, 0xb3, 0x01, 0x00, 0x00, // mov eax, SYS_clone3
        0x48, 0xbf, // movabs rdi, clone_args
    ]);
    let clone_args_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.extend_from_slice(&[
        0xbe, 0x58, 0x00, 0x00, 0x00, // mov esi, sizeof(clone_args)
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x0f, 0x84, 0, 0, 0, 0, // jz child
    ]);
    let child_jump = code.len() - 4;
    code.extend_from_slice(&[0x0f, 0x88]); // js failure: clone must succeed
    failures.push(code.len());
    code.extend_from_slice(&0_i32.to_le_bytes());
    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // mov r13d, returned child tid
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    let wait = code.len();
    code.extend_from_slice(&[
        0x8b, 0x17, // mov edx, [rdi]
        0x85, 0xd2, // test edx, edx
        0x0f, 0x84, 0, 0, 0, 0, // jz joined
    ]);
    let joined_jump = code.len() - 4;
    code.extend_from_slice(&[
        0x31, 0xf6, // xor esi, esi: FUTEX_WAIT, current nonzero value in edx
        0x45, 0x31, 0xd2, // xor r10d, r10d: no timeout
        0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, SYS_futex
        0x0f, 0x05, // syscall
    ]);
    // A racing clear-TID may win before FUTEX_WAIT. Only Linux's normal
    // successful wake, changed-value refusal or signal interruption can retry.
    for result in [0_i32, -libc::EAGAIN, -libc::EINTR] {
        code.push(0x3d); // cmp eax, result
        code.extend_from_slice(&result.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // je wait
        let operand = code.len() - 4;
        patch_stats_jump(&mut code, operand, wait);
    }
    code.push(0xe9); // jmp failure for any other futex result
    failures.push(code.len());
    code.extend_from_slice(&0_i32.to_le_bytes());
    let joined = code.len();
    patch_stats_jump(&mut code, joined_jump, joined);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_result
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x44, 0x39, 0x29]); // cmp [rcx], r13d
    append_jne_failure(&mut code, &mut failures);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_done
    code.extend_from_slice(&CHILD_DONE.to_le_bytes());
    code.extend_from_slice(&[0x81, 0x39, 0x34, 0x12, 0x00, 0x00]); // cmp [rcx], 0x1234
    append_jne_failure(&mut code, &mut failures);
    append_root_read(&mut code, &mut failures);
    append_stats_exit(&mut code, true);

    let child = code.len();
    patch_stats_jump(&mut code, child_jump, child);
    code.extend_from_slice(&[
        0x0f, 0x31, // actual Host-worker RDTSC: must retire without a Tool callback
        0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, SYS_gettid
        0x0f, 0x05, // syscall
        0x48, 0xb9, // movabs rcx, child_result
    ]);
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x89, 0x01]); // mov [rcx], eax
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_done
    code.extend_from_slice(&CHILD_DONE.to_le_bytes());
    code.extend_from_slice(&[0xc7, 0x01, 0x34, 0x12, 0x00, 0x00]); // mov [rcx], 0x1234
    append_stats_exit(&mut code, false); // clear-TID and wake parent on real exit

    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);
    for operand in failures {
        patch_stats_jump(&mut code, operand, failure);
    }
    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let clone_args_address = LOAD_ADDRESS + code.len() as u64;
    code[clone_args_operand..clone_args_operand + 8]
        .copy_from_slice(&clone_args_address.to_le_bytes());
    let mut clone_args = [0_u8; 88];
    clone_args[0..8].copy_from_slice(&flags.to_le_bytes());
    clone_args[16..24].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
    clone_args[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
    code.extend_from_slice(&clone_args);
    assert!(
        code.len() < 0x1000,
        "code must not overlap the shared data page"
    );
    code
}

#[test]
fn host_owned_timestamp_worker_keeps_native_execution() {
    if !kvm_available("KVM Host-owned timestamp worker test") {
        return;
    }
    // No dynamic loader: only the two root instructions belong to this exact
    // callback oracle. The worker must execute its own RDTSC, publish its TID
    // and completion marker, then clear child_tid before the root can finish.
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend.set_thread_ownership(ThreadOwnership::Host);
    backend
        .install_static_elf(
            &static_elf(&host_owned_timestamp_program()),
            "/bin/timestamp-host-worker",
        )
        .unwrap();
    let (log, status, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<TimestampTool>(true, true))
            .unwrap();
    assert_eq!(status, 0, "stdout={stdout:?} stderr={stderr:?}");
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        log.calls(),
        vec![
            (Pid::from_raw(1), Rdtsc::Tsc),
            (Pid::from_raw(1), Rdtsc::Tsc)
        ]
    );
}

fn prefixed_timestamp_register_program(tsc_prefix: &[u8], tscp_prefix: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    let mut failure_patches = Vec::new();
    for (opcode, tsc, expected_rcx) in [
        (&[0x0f, 0x31][..], RDTSC_SENTINEL, 0xdead_beef_fedc_ba98_u64),
        (
            &[0x0f, 0x01, 0xf9][..],
            RDTSCP_SENTINEL,
            u64::from(RDTSCP_AUX_SENTINEL),
        ),
    ] {
        code.extend_from_slice(&[0x49, 0x89, 0xe4]); // mov r12, rsp
        code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, preserved sentinel
        code.extend_from_slice(&0xdead_beef_fedc_ba98_u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&u64::MAX.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&u64::MAX.to_le_bytes());
        code.extend_from_slice(&[0x68, 0xd7, 0x0e, 0x00, 0x00, 0x9d]); // push flags; popfq
        code.extend_from_slice(if opcode.len() == 2 {
            tsc_prefix
        } else {
            tscp_prefix
        });
        code.extend_from_slice(opcode);
        code.extend_from_slice(&[0x9c, 0x41, 0x5b, 0xfc]); // pushfq; pop r11; cld
        code.extend_from_slice(&[0x4c, 0x39, 0xe4]); // cmp rsp, r12
        append_jne_failure(&mut code, &mut failure_patches);
        code.extend_from_slice(&[0x41, 0x81, 0xfb, 0xd7, 0x0e, 0x00, 0x00]); // cmp r11d, flags
        append_jne_failure(&mut code, &mut failure_patches);
        for (value, compare) in [
            (u64::from(tsc as u32), [0x4c, 0x39, 0xc0]), // cmp rax, r8
            (tsc >> 32, [0x4c, 0x39, 0xc2]),             // cmp rdx, r8
            (expected_rcx, [0x4c, 0x39, 0xc1]),          // cmp rcx, r8
        ] {
            code.extend_from_slice(&[0x49, 0xb8]); // movabs r8, expected full register
            code.extend_from_slice(&value.to_le_bytes());
            code.extend_from_slice(&compare);
            append_jne_failure(&mut code, &mut failure_patches);
        }
    }
    code.extend_from_slice(&[0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
    let failure = code.len();
    code.extend_from_slice(&[0xb8, 0x3c, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05]);
    for patch in failure_patches {
        let displacement = i32::try_from(failure).unwrap() - i32::try_from(patch + 4).unwrap();
        code[patch..patch + 4].copy_from_slice(&displacement.to_le_bytes());
    }
    code
}

#[test]
fn prefixed_timestamp_instructions_preserve_registers_flags_and_stack() {
    if !kvm_available("KVM prefixed timestamp register test") {
        return;
    }
    let mut prefixes = vec![vec![], vec![0x4f, 0x66, 0x67, 0xf3], vec![0x66; 12]];
    prefixes.extend(
        [
            0x66, 0x67, 0xf2, 0xf3, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x40, 0x4f,
        ]
        .into_iter()
        .map(|prefix| vec![prefix]),
    );
    for prefix in prefixes {
        let (log, status) = run_timestamp_probe(
            &static_elf(&prefixed_timestamp_register_program(&prefix, &prefix)),
            true,
        );
        assert_eq!(status, 0, "prefix={prefix:x?}");
        assert_eq!(
            log.calls(),
            vec![
                (Pid::from_raw(1), Rdtsc::Tsc),
                (Pid::from_raw(1), Rdtsc::Tscp)
            ]
        );
    }
    let (log, status) = run_timestamp_probe(
        &static_elf(&prefixed_timestamp_register_program(
            &[0x66; 13],
            &[0x66; 12],
        )),
        true,
    );
    assert_eq!(status, 0, "both maximum-length instructions must complete");
    assert_eq!(
        log.calls(),
        vec![
            (Pid::from_raw(1), Rdtsc::Tsc),
            (Pid::from_raw(1), Rdtsc::Tscp)
        ]
    );
}

#[test]
fn locked_and_overlength_timestamp_encodings_remain_faults() {
    if !kvm_available("KVM timestamp fault-priority test") {
        return;
    }
    for code in [vec![0xf0, 0x0f, 0x31], vec![0xf0, 0x0f, 0x01, 0xf9]] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/locked-timestamp")
            .unwrap();
        let completion = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<TimestampTool>(true, true),
        )
        .unwrap();
        assert_invalid_opcode(completion.result.unwrap_err());
        assert!(completion.global_state.calls().is_empty());
    }
    let mut code = vec![0x66; 14];
    code.extend_from_slice(&[0x0f, 0x31]);
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/overlength-timestamp")
        .unwrap();
    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<TimestampTool>(true, true),
    )
    .unwrap();
    assert_general_protection(completion.result.unwrap_err());
    assert!(completion.global_state.calls().is_empty());
}

#[test]
fn timestamp_tool_preserves_results_with_host_supported_cpuid() {
    if !kvm_available("KVM host-supported timestamp profile test") {
        return;
    }
    let mut backend =
        KvmBackend::new_with_cpuid_policy(MEMORY_SIZE, reverie_kvm::CpuidPolicy::host_supported())
            .unwrap();
    backend
        .install_static_elf(
            &static_elf(&timestamp_assertion_program()),
            "/bin/host-profile-timestamp",
        )
        .unwrap();
    let (log, status, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<TimestampTool>(true, true))
            .unwrap();
    assert_eq!(status, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        log.calls(),
        vec![
            (Pid::from_raw(1), Rdtsc::Tsc),
            (Pid::from_raw(1), Rdtsc::Tscp)
        ]
    );
}

#[test]
fn timestamp_single_step_reports_the_retired_instruction_boundary() {
    if !kvm_available("KVM timestamp single-step boundary test") {
        return;
    }
    for (opcode, request) in [
        (&[0x0f, 0x31][..], Rdtsc::Tsc),
        (&[0x66, 0x0f, 0x01, 0xf9][..], Rdtsc::Tscp),
    ] {
        // POPF's newly enabled TF takes effect after the following instruction.
        let mut code = vec![0x68, 0x02, 0x03, 0x00, 0x00, 0x9d];
        code.extend_from_slice(opcode);
        let expected_ip = LOAD_ADDRESS + code.len() as u64;
        code.push(0x90); // must not execute before the single-step boundary
        code.extend_from_slice(&[0x0f, 0x0b]);
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/single-step-timestamp")
            .unwrap();
        let completion = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<TimestampTool>(true, true),
        )
        .unwrap();
        let error = unwrap_shared_guest_exception(completion.result.unwrap_err());
        assert!(
            matches!(&error, Error::GuestException { vector: 1, instruction_pointer, .. }
                if *instruction_pointer == expected_ip),
            "expected #DB at {expected_ip:#x}, got {error:?}"
        );
        assert_eq!(
            completion.global_state.calls(),
            vec![(Pid::from_raw(1), request)]
        );
    }
}

#[test]
fn close_and_close_range_consume_low_words_on_kvm() {
    if !kvm_available("KVM close low-word argument test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "close-low-word",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HIGH_WORD UINT64_C(0x5a5a5a5a00000000)
#define TEST_CLOSE_RANGE_CLOEXEC (1U << 2)

static int fd_flags_are(int fd, int expected) {
  return fcntl(fd, F_GETFD) == expected;
}

int main(void) {
  int direct = dup(STDOUT_FILENO);
  if (direct < 0) return 1;
  if (syscall(SYS_close, HIGH_WORD | (uint32_t)direct) != 0) return 2;
  errno = 0;
  if (fcntl(direct, F_GETFD) != -1 || errno != EBADF) return 3;

  int low = dup2(STDOUT_FILENO, 100);
  int high = dup3(STDERR_FILENO, 101, O_CLOEXEC);
  if (low != 100 || high != 101) return 4;

  // Bounds are compared after truncation. Raw-u64 ordering is the opposite,
  // and the rejected call must not mutate either descriptor.
  errno = 0;
  if (syscall(SYS_close_range, (uint32_t)high,
              HIGH_WORD | (uint32_t)low, 0) != -1 ||
      errno != EINVAL || !fd_flags_are(low, 0) ||
      !fd_flags_are(high, FD_CLOEXEC)) return 5;

  // Unknown low flag bits remain invalid despite unrelated high bits.
  errno = 0;
  if (syscall(SYS_close_range, HIGH_WORD | (uint32_t)low,
              HIGH_WORD | (uint32_t)high, HIGH_WORD | 1) != -1 ||
      errno != EINVAL || !fd_flags_are(low, 0) ||
      !fd_flags_are(high, FD_CLOEXEC)) return 6;

  // High-only flag bits decode to zero, so the inclusive low-word range closes.
  if (syscall(SYS_close_range, HIGH_WORD | (uint32_t)low,
              HIGH_WORD | (uint32_t)high, HIGH_WORD) != 0) return 7;
  errno = 0;
  if (fcntl(low, F_GETFD) != -1 || errno != EBADF) return 8;
  errno = 0;
  if (fcntl(high, F_GETFD) != -1 || errno != EBADF) return 9;

  int cloexec = fcntl(STDOUT_FILENO, F_DUPFD, 100);
  if (cloexec != 100 || !fd_flags_are(cloexec, 0)) return 10;
  if (syscall(SYS_close_range, HIGH_WORD | (uint32_t)cloexec,
              HIGH_WORD | (uint32_t)cloexec,
              HIGH_WORD | TEST_CLOSE_RANGE_CLOEXEC) != 0) return 11;
  if (fcntl(cloexec, F_GETFD) != FD_CLOEXEC) return 12;

  if (syscall(SYS_close_range, HIGH_WORD | UINT32_MAX, UINT32_MAX,
              HIGH_WORD) != 0 || !fd_flags_are(cloexec, FD_CLOEXEC)) return 13;
  if (close(cloexec) != 0) return 14;

  puts("low-word-close-ok");
  return 0;
}
"#,
    );

    let native = std::process::Command::new(&executable).output().unwrap();
    assert_eq!(
        native.status.code(),
        Some(0),
        "native stdout={} stderr={}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"low-word-close-ok\n");
    assert!(native.stderr.is_empty());

    let image = std::fs::read(&executable).unwrap();
    for (tool_owned, repetition) in [(false, 0), (false, 1), (true, 0), (true, 1)] {
        let executable = executable.to_str().unwrap();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code,
            0,
            "tool_owned={tool_owned} repetition={repetition} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(
            stdout, native.stdout,
            "tool_owned={tool_owned} repetition={repetition}"
        );
        assert_eq!(
            stderr, native.stderr,
            "tool_owned={tool_owned} repetition={repetition}"
        );
    }
}

#[test]
fn sendfile_and_lseek_consume_low_descriptor_words_on_kvm() {
    assert!(kvm_available("KVM sendfile/lseek low-word argument test"));

    const PAYLOAD: &[u8] = b"sendfile-lseek-low-word-ok\n";
    let directory = TestDirectory::new();
    let source = directory.0.join("sendfile-lseek-low-word-source");
    std::fs::write(&source, PAYLOAD).unwrap();
    let executable = compile_c_program(
        &directory.0,
        "sendfile-lseek-low-word",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HIGH_WORD UINT64_C(0x5a5a5a5a00000000)
#define SIGNED_LOW_WORD (HIGH_WORD | UINT64_C(0x80000000))
#define SIGN_EXTENDED_HIGH_WORD UINT64_C(0xffffffff00000000)
#define PAYLOAD "sendfile-lseek-low-word-ok\n"

static int failed_with(long result, int expected) {
  return result == -1 && errno == expected;
}

static int rejected_without_consuming(uint64_t out_fd, int in_fd,
                                      int input_writer,
                                      unsigned char sentinel) {
  if (input_writer >= 0 && write(input_writer, &sentinel, 1) != 1) return 1;
  errno = 0;
  long result = syscall(SYS_sendfile, out_fd, (uint32_t)in_fd, NULL, 1);
  int saved_errno = errno;
  if (input_writer >= 0) {
    unsigned char observed = 0;
    ssize_t count;
    do {
      count = read(in_fd, &observed, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 1 || observed != sentinel) return 2;
  }
  return result == -1 && saved_errno == EBADF ? 0 : 3;
}

int main(int argc, char **argv) {
  if (argc != 2) return 1;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;

  int pipe_fds[2], sockets[2], output_pipe[2];
  if (pipe2(pipe_fds, O_NONBLOCK) != 0) return 20;
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) != 0)
    return 21;
  if (pipe(output_pipe) != 0) return 27;
  int directory = open(".", O_RDONLY | O_DIRECTORY);
  if (directory < 0) return 28;
  int closed_output = dup(fd);
  if (closed_output < 0) return 29;
  if (close(closed_output) != 0) return 30;

  const uint64_t negative_outputs[] = {
      SIGNED_LOW_WORD | UINT64_C(1), UINT64_MAX};
  const int negative_inputs[] = {pipe_fds[0], sockets[0]};
  const int negative_writers[] = {pipe_fds[1], sockets[1]};
  for (unsigned output = 0;
       output < sizeof(negative_outputs) / sizeof(negative_outputs[0]);
       ++output) {
    for (unsigned input = 0;
         input < sizeof(negative_inputs) / sizeof(negative_inputs[0]);
         ++input) {
      int check = rejected_without_consuming(
          negative_outputs[output], negative_inputs[input],
          negative_writers[input], (unsigned char)(1 + output * 2 + input));
      if (check != 0) return 31 + (int)((output * 2 + input) * 3) + check;
    }
  }

  const int routing_inputs[] = {
      pipe_fds[0], sockets[0], directory, STDOUT_FILENO};
  const int routing_writers[] = {pipe_fds[1], sockets[1], -1, -1};
  const uint64_t high_words[] = {HIGH_WORD, SIGN_EXTENDED_HIGH_WORD};
  const int unusable_outputs[] = {closed_output, fd, output_pipe[0]};
  unsigned row = 0;
  for (unsigned encoding = 0;
       encoding < sizeof(high_words) / sizeof(high_words[0]);
       ++encoding) {
    for (unsigned output = 0;
         output < sizeof(unusable_outputs) / sizeof(unusable_outputs[0]);
         ++output) {
      for (unsigned input = 0;
           input < sizeof(routing_inputs) / sizeof(routing_inputs[0]);
           ++input) {
        int check = rejected_without_consuming(
            high_words[encoding] | (uint32_t)unusable_outputs[output],
            routing_inputs[input], routing_writers[input],
            (unsigned char)(16 + row));
        if (check != 0) return 43 + (int)(row * 3) + check;
        ++row;
      }
    }
  }

  off_t offset = 0;
  errno = 0;
  if (!failed_with(syscall(SYS_sendfile,
                           SIGNED_LOW_WORD | (uint32_t)STDOUT_FILENO,
                           (uint32_t)fd, &offset, 1), EBADF) ||
      offset != 0) return 3;
  errno = 0;
  if (!failed_with(syscall(SYS_sendfile, (uint32_t)STDOUT_FILENO,
                           SIGNED_LOW_WORD | (uint32_t)fd,
                           &offset, 1), EBADF) ||
      offset != 0) return 4;

  // Keep whence valid: this assertion discriminates only fd decoding.
  errno = 0;
  if (!failed_with(syscall(SYS_lseek, SIGNED_LOW_WORD | (uint32_t)fd,
                           0, SEEK_SET), EBADF) ||
      lseek(fd, 0, SEEK_CUR) != 0) return 5;
  if (syscall(SYS_lseek, HIGH_WORD | (uint32_t)fd, 3, SEEK_SET) != 3 ||
      lseek(fd, 0, SEEK_CUR) != 3) return 6;

  // Command::output and KVM capture both expose stdout as a pipe.
  errno = 0;
  if (!failed_with(syscall(SYS_lseek,
                           HIGH_WORD | (uint32_t)STDOUT_FILENO,
                           0, SEEK_CUR), ESPIPE)) return 7;

  // Split one exact marker so each sendfile fd decoder is exercised alone.
  offset = 0;
  const size_t length = sizeof(PAYLOAD) - 1;
  const size_t split = (sizeof(PAYLOAD) - 1) / 2;
  if (syscall(SYS_sendfile,
              HIGH_WORD | (uint32_t)STDOUT_FILENO,
              (uint32_t)fd, &offset, split) != (long)split ||
      offset != (off_t)split || lseek(fd, 0, SEEK_CUR) != 3) return 8;
  if (syscall(SYS_sendfile, (uint32_t)STDOUT_FILENO,
              HIGH_WORD | (uint32_t)fd, &offset,
              length - split) != (long)(length - split) ||
      offset != (off_t)length || lseek(fd, 0, SEEK_CUR) != 3) return 9;

  if (close(pipe_fds[0]) != 0 || close(pipe_fds[1]) != 0 ||
      close(sockets[0]) != 0 || close(sockets[1]) != 0 ||
      close(output_pipe[0]) != 0 || close(output_pipe[1]) != 0 ||
      close(directory) != 0) return 26;
  if (close(fd) != 0) return 10;
  return 0;
}
"#,
    );

    let native = std::process::Command::new(&executable)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(
        native.status.code(),
        Some(0),
        "native stdout={} stderr={}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, PAYLOAD);
    assert!(native.stderr.is_empty());

    let image = std::fs::read(&executable).unwrap();
    for (tool_owned, repetition) in [(false, 0), (false, 1), (true, 0), (true, 1)] {
        let executable = executable.to_str().unwrap();
        let source = source.to_str().unwrap();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable, source],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code,
            0,
            "tool_owned={tool_owned} repetition={repetition} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(
            stdout, native.stdout,
            "tool_owned={tool_owned} repetition={repetition}"
        );
        assert_eq!(
            stderr, native.stderr,
            "tool_owned={tool_owned} repetition={repetition}"
        );
    }
}

#[test]
fn sendfile_bad_output_offsets_match_native_on_direct_kvm() {
    sendfile_bad_output_offsets_match_native_on_kvm(false);
}

#[test]
fn sendfile_bad_output_offsets_match_native_on_tool_kvm() {
    sendfile_bad_output_offsets_match_native_on_kvm(true);
}

fn sendfile_bad_output_offsets_match_native_on_kvm(tool_owned: bool) {
    assert!(kvm_available("KVM sendfile bad-output offset precedence"));

    const SOURCE: &[u8] = b"abcdef";
    const DESTINATION: &[u8] = b"unchanged-output\n";
    const MARKER: &[u8] = b"sendfile-bad-output-offsets-ok\n";
    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    let destination = directory.0.join("readonly-output");
    std::fs::write(&source, SOURCE).unwrap();
    std::fs::write(&destination, DESTINATION).unwrap();
    let executable = compile_c_program(
        &directory.0,
        "sendfile-bad-output-offsets",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) return 1;
  int source = open(argv[1], O_RDONLY);
  int readonly_output = open(argv[2], O_RDONLY);
  int output_pipe[2];
  if (source < 0 || readonly_output < 0 ||
      pipe2(output_pipe, O_NONBLOCK) != 0) return 2;
  // Allocate all live descriptors before closing this positive output. No
  // descriptor is allocated during the matrix, so its number stays closed.
  int closed_output = dup(readonly_output);
  if (closed_output <= 2 || close(closed_output) != 0) return 3;
  const struct {
    const char *name;
    int fd;
  } outputs[] = {
      {"closed", closed_output}, {"readonly regular", readonly_output},
      {"pipe read end", output_pipe[0]}, {"negative", -1},
  };
  const uint64_t high_words[] = {
      0, UINT64_C(0x5a5a5a5a00000000), UINT64_C(0xffffffff00000000)};
  const struct {
    const char *name;
    off_t offset;
    size_t count;
    int pointer_kind; // 0: valid; 1: inaccessible; 2: NULL.
    int error;
  } cases[] = {
      {"inaccessible", 2, 2, 1, EFAULT},
      {"inaccessible zero count", 2, 0, 1, EFAULT},
      {"negative", -1, 2, 0, EINVAL},
      {"minimum", INT64_MIN, 2, 0, EINVAL},
      {"maximum overflow", INT64_MAX, 1, 0, EINVAL},
      {"maximum minus one overflow", INT64_MAX - 1, 2, 0, EINVAL},
      {"maximum minus one valid", INT64_MAX - 1, 1, 0, EBADF},
      {"maximum zero count", INT64_MAX, 0, 0, EBADF},
      {"negative zero count", -1, 0, 0, EINVAL},
      {"normal", 2, 2, 0, EBADF},
      {"normal zero count", 2, 0, 0, EBADF},
      {"null", 2, 2, 2, EBADF},
      {"null zero count", 2, 0, 2, EBADF},
      {"above supervisor cap overflow", INT64_MAX - 20000000, 100000000, 0, EINVAL},
      {"above supervisor cap valid", INT64_MAX - 20000000, 20000000, 0, EBADF},
      {"above kernel cap overflow", INT64_MAX - UINT64_C(0x7ffff000),
       UINT64_C(0x7ffff001), 0, EINVAL},
      {"kernel cap boundary valid", INT64_MAX - UINT64_C(0x7ffff000),
       UINT64_C(0x7ffff000), 0, EBADF},
      {"signed count maximum valid", 0, INT64_MAX, 0, EBADF},
      {"signed count bit", 0, UINT64_C(1) << 63, 0, EINVAL},
      {"unsigned count maximum", 0, UINT64_MAX, 0, EINVAL},
      {"inaccessible oversized count", 2, UINT64_MAX, 1, EFAULT},
      {"null oversized valid", 2, 100000000, 2, EBADF},
      {"null signed range overflow", 2, INT64_MAX, 2, EINVAL},
      {"null signed count bit", 2, UINT64_C(1) << 63, 2, EINVAL},
      {"null unsigned count maximum", 2, UINT64_MAX, 2, EINVAL},
  };
  const unsigned char source_bytes[] = "abcdef";
  const unsigned char output_bytes[] = "unchanged-output\n";
  const unsigned char sentinel[] = "pipe-sentinel";
  unsigned rows = 0;
  int failures = 0;
  for (unsigned output = 0; output < sizeof(outputs) / sizeof(outputs[0]); ++output) {
    for (unsigned encoding = 0; encoding < 3; ++encoding) {
      for (unsigned row = 0; row < sizeof(cases) / sizeof(cases[0]); ++row) {
        if (lseek(source, 1, SEEK_SET) != 1 ||
            lseek(readonly_output, 2, SEEK_SET) != 2) return 4;
        if (write(output_pipe[1], sentinel, sizeof(sentinel) - 1) !=
            (ssize_t)(sizeof(sentinel) - 1)) return 5;
        off_t offset = cases[row].offset;
        off_t *pointer = cases[row].pointer_kind == 1
            ? (off_t *)(uintptr_t)UINT64_C(0xfffffffffffff000)
            : cases[row].pointer_kind == 2 ? NULL : &offset;
        uint64_t raw_output = high_words[encoding] | (uint32_t)outputs[output].fd;
        errno = 0;
        long result = syscall(SYS_sendfile, raw_output, (uint32_t)source,
                              pointer, cases[row].count);
        int error = errno;
        off_t source_position = lseek(source, 0, SEEK_CUR);
        off_t output_position = lseek(readonly_output, 0, SEEK_CUR);
        unsigned char observed_source[sizeof(source_bytes) - 1];
        unsigned char observed_output[sizeof(output_bytes) - 1];
        unsigned char observed_sentinel[sizeof(sentinel) - 1];
        unsigned char extra;
        ssize_t source_count = pread(source, observed_source, sizeof(observed_source), 0);
        ssize_t output_count = pread(readonly_output, observed_output, sizeof(observed_output), 0);
        ssize_t source_eof = pread(source, &extra, 1, sizeof(observed_source));
        ssize_t output_eof = pread(readonly_output, &extra, 1, sizeof(observed_output));
        ssize_t pipe_count = read(output_pipe[0], observed_sentinel, sizeof(observed_sentinel));
        errno = 0;
        ssize_t pipe_extra = read(output_pipe[0], &extra, 1);
        int pipe_error = errno;
        errno = 0;
        int closed_result = fcntl(closed_output, F_GETFD);
        int closed_error = errno;
        int unchanged = source_position == 1 && output_position == 2 &&
            offset == cases[row].offset &&
            source_count == (ssize_t)sizeof(observed_source) &&
            memcmp(observed_source, source_bytes, sizeof(observed_source)) == 0 &&
            output_count == (ssize_t)sizeof(observed_output) &&
            memcmp(observed_output, output_bytes, sizeof(observed_output)) == 0 &&
            source_eof == 0 && output_eof == 0 &&
            pipe_count == (ssize_t)sizeof(observed_sentinel) &&
            memcmp(observed_sentinel, sentinel, sizeof(observed_sentinel)) == 0 &&
            pipe_extra == -1 && pipe_error == EAGAIN &&
            closed_result == -1 && closed_error == EBADF;
        if (result != -1 || error != cases[row].error || !unchanged) {
          fprintf(stderr,
                  "output=%s encoding=%u raw=%#" PRIx64 " case=%s count=%zu "
                  "result=%ld errno=%d expected=%d unchanged=%d "
                  "input_pos=%jd output_pos=%jd offset=%jd pipe_count=%zd\n",
                  outputs[output].name, encoding, raw_output, cases[row].name,
                  cases[row].count, result, error, cases[row].error, unchanged,
                  (intmax_t)source_position, (intmax_t)output_position,
                  (intmax_t)offset, pipe_count);
          ++failures;
        }
        ++rows;
      }
    }
  }
  if (rows != 300 || failures) return 6;
  if (close(source) || close(readonly_output) ||
      close(output_pipe[0]) || close(output_pipe[1])) return 7;
  const char marker[] = "sendfile-bad-output-offsets-ok\n";
  if (write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) return 8;
  return 0;
}
"#,
    );
    let native = std::process::Command::new(&executable)
        .arg(&source)
        .arg(&destination)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(0), "native: {native:?}");
    assert_eq!(native.stdout, MARKER);
    assert!(native.stderr.is_empty());
    assert_eq!(std::fs::read(&source).unwrap(), SOURCE);
    assert_eq!(std::fs::read(&destination).unwrap(), DESTINATION);

    // Regular inputs only: nonnull offsets on unsupported inputs keep their
    // separately documented mediated-fallback boundary.
    let image = std::fs::read(&executable).unwrap();
    for repetition in 0..2 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[
                    executable.to_str().unwrap(),
                    source.to_str().unwrap(),
                    destination.to_str().unwrap(),
                ],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code, 0,
            "tool_owned={tool_owned} repetition={repetition} stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, native.stdout);
        assert_eq!(stderr, native.stderr);
        assert_eq!(std::fs::read(&source).unwrap(), SOURCE);
        assert_eq!(std::fs::read(&destination).unwrap(), DESTINATION);
    }
}

#[test]
fn sendfile_input_offset_errors_match_native_on_direct_kvm() {
    sendfile_input_offset_errors_match_native_on_kvm(false);
}

#[test]
fn sendfile_input_offset_errors_match_native_on_tool_kvm() {
    sendfile_input_offset_errors_match_native_on_kvm(true);
}

fn sendfile_input_offset_errors_match_native_on_kvm(tool_owned: bool) {
    assert!(
        kvm_available("KVM sendfile input/offset error precedence"),
        "the complete sendfile input/offset matrix requires usable KVM"
    );

    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    let destination = directory.0.join("readonly-output");
    let input_directory = directory.0.join("input-directory");
    std::fs::create_dir(&input_directory).unwrap();
    std::fs::write(&source, b"abcdef").unwrap();
    std::fs::write(&destination, b"unchanged-output\n").unwrap();
    let executable = compile_c_program(
        &directory.0,
        "sendfile-input-offset-errors",
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
_Static_assert(sizeof(long)==8 && sizeof(off_t)==8,"x86-64 sendfile ABI required");
enum ptrkind { CELL, BAD, NULLPTR };
struct row { const char *name; enum ptrkind kind; int64_t offset; size_t count; };
static const struct row rows[]={
    {"inaccessible-two",BAD,2,2},
    {"inaccessible-zero",BAD,2,0},
    {"valid-two",CELL,2,2},
    {"valid-zero",CELL,2,0},
    {"negative-range-two",CELL,-1,2},
    {"negative-range-zero",CELL,-1,0},
    {"null-two",NULLPTR,2,2},
    {"null-zero",NULLPTR,2,0},
};
static int exact_file(int fd,const char *expected) {
    char bytes[32];
    size_t n=strlen(expected);
    ssize_t got=pread(fd,bytes,sizeof(bytes),0);
    return got==(ssize_t)n && memcmp(bytes,expected,n)==0;
}
static int consume_sentinel(int fd,char expected) {
    char first=0,extra=0;
    ssize_t got=read(fd,&first,1);
    errno=0;
    ssize_t tail=read(fd,&extra,1);
    int saved=errno;
    return got==1 && first==expected && tail==-1 && saved==EAGAIN;
}
static int closed(int fd) {
    errno=0;
    int rc=fcntl(fd,F_GETFD);
    int saved=errno;
    return rc==-1 && saved==EBADF;
}
int main(int argc,char **argv) {
    if(argc!=4) return 90;
    int rd=open(argv[1],O_RDONLY|O_CLOEXEC);
    int wr=open(argv[1],O_WRONLY|O_CLOEXEC);
    int path=open(argv[1],O_PATH|O_CLOEXEC);
    int ro=open(argv[2],O_RDONLY|O_CLOEXEC);
    int directory=open(argv[3],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    int inp[2],outp[2],socks[2];
    if(rd<0||wr<0||path<0||ro<0||directory<0||
       pipe2(inp,O_CLOEXEC|O_NONBLOCK)<0||pipe2(outp,O_CLOEXEC|O_NONBLOCK)<0||
       socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,socks)<0) {
        perror("setup");return 91;
    }
    int badin=dup(rd),badout=dup(ro);
    if(badin<0||badout<0||close(badin)<0||close(badout)<0) return 92;
    int inputs[]={badin,-1,rd,wr,path,inp[0],inp[1],socks[0],directory};
    const char *input_names[]={"closed-positive","negative","readonly-regular","writeonly-regular","opath-regular","pipe-read","pipe-write","socket","directory"};
    int outputs[]={badout,ro,outp[0]};
    const char *output_names[]={"closed-positive","readonly-regular","pipe-read"};
    unsigned total=0,invariant_failures=0;
    for(size_t i=0;i<sizeof(inputs)/sizeof(inputs[0]);i++) {
        for(size_t o=0;o<sizeof(outputs)/sizeof(outputs[0]);o++) {
            for(size_t r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
                const struct row *row=&rows[r];
                int64_t cell=row->offset;
                uintptr_t ptr=row->kind==CELL?(uintptr_t)&cell:row->kind==BAD?2:0;
                if(lseek(rd,1,SEEK_SET)!=1||lseek(wr,1,SEEK_SET)!=1||lseek(ro,2,SEEK_SET)!=2||
                   lseek(directory,0,SEEK_SET)!=0||write(inp[1],"I",1)!=1||
                   write(outp[1],"O",1)!=1||write(socks[1],"S",1)!=1) return 93;
                errno=0;
                long result=syscall(SYS_sendfile,(long)outputs[o],(long)inputs[i],ptr,row->count);
                int saved_errno=errno;
                off_t rdpos=lseek(rd,0,SEEK_CUR),wrpos=lseek(wr,0,SEEK_CUR);
                off_t ropos=lseek(ro,0,SEEK_CUR),dirpos=lseek(directory,0,SEEK_CUR);
                int pipe_input_unchanged=consume_sentinel(inp[0],'I');
                int pipe_output_unchanged=consume_sentinel(outp[0],'O');
                int socket_unchanged=consume_sentinel(socks[0],'S');
                int unchanged=rdpos==1&&wrpos==1&&ropos==2&&dirpos==0&&cell==row->offset&&
                    exact_file(rd,"abcdef")&&exact_file(ro,"unchanged-output\n")&&
                    pipe_input_unchanged&&pipe_output_unchanged&&socket_unchanged&&
                    closed(badin)&&closed(badout);
                total++;
                invariant_failures+=!(result==-1&&unchanged);
                printf("{\"input\":\"%s\",\"output\":\"%s\",\"case\":\"%s\","
                       "\"pointer_kind\":\"%s\",\"offset\":%" PRId64 ",\"count\":%zu,"
                       "\"result\":%ld,\"errno\":%d,\"unchanged\":%s}\n",
                       input_names[i],output_names[o],row->name,
                       row->kind==CELL?"cell":row->kind==BAD?"inaccessible":"null",
                       row->offset,row->count,result,saved_errno,unchanged?"true":"false");
            }
        }
    }
    printf("{\"summary\":true,\"total\":%u,\"invariant_failures\":%u}\n",total,invariant_failures);
    return invariant_failures?1:0;
}
"#,
    );
    let route = if tool_owned { "tool" } else { "direct" };
    let artifacts = std::env::var_os("PR628_F2_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| directory.0.join("observed"));
    std::fs::create_dir_all(&artifacts).unwrap();
    std::fs::copy(&executable, artifacts.join(format!("{route}.elf"))).unwrap();
    std::fs::copy(
        executable.with_extension("c"),
        artifacts.join(format!("{route}.c")),
    )
    .unwrap();
    let save = |name: &str, code: Option<i32>, stdout: &[u8], stderr: &[u8]| {
        std::fs::write(artifacts.join(format!("{route}.{name}.stdout")), stdout).unwrap();
        std::fs::write(artifacts.join(format!("{route}.{name}.stderr")), stderr).unwrap();
        std::fs::write(
            artifacts.join(format!("{route}.{name}.exit-code")),
            format!("{code:?}\n"),
        )
        .unwrap();
    };
    let native = std::process::Command::new(&executable)
        .arg(&source)
        .arg(&destination)
        .arg(&input_directory)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    save(
        "native",
        native.status.code(),
        &native.stdout,
        &native.stderr,
    );
    assert_eq!(native.status.code(), Some(0), "native: {native:?}");
    assert!(native.stderr.is_empty());
    assert_eq!(
        native
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        217
    );
    assert!(
        native
            .stdout
            .ends_with(b"{\"summary\":true,\"total\":216,\"invariant_failures\":0}\n")
    );
    assert_eq!(std::fs::read(&source).unwrap(), b"abcdef");
    assert_eq!(std::fs::read(&destination).unwrap(), b"unchanged-output\n");

    let image = std::fs::read(&executable).unwrap();
    for repetition in 0..2 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[
                    executable.to_str().unwrap(),
                    source.to_str().unwrap(),
                    destination.to_str().unwrap(),
                    input_directory.to_str().unwrap(),
                ],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr, callbacks) = if tool_owned {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            let calls = log
                .syscalls()
                .iter()
                .filter(|name| name.as_str() == "sendfile")
                .count();
            (code, stdout, stderr, Some(calls))
        } else {
            let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
            (code, stdout, stderr, None)
        };
        save(&format!("guest-{repetition}"), Some(code), &stdout, &stderr);
        if let Some(calls) = callbacks {
            std::fs::write(
                artifacts.join(format!("{route}.guest-{repetition}.sendfile-callbacks")),
                format!("{calls}\n"),
            )
            .unwrap();
            assert_eq!(calls, 216, "repetition={repetition}");
        }
        assert_eq!(
            code, 0,
            "{route} repetition={repetition} stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, native.stdout, "{route} repetition={repetition}");
        assert_eq!(stderr, native.stderr, "{route} repetition={repetition}");
        assert_eq!(std::fs::read(&source).unwrap(), b"abcdef");
        assert_eq!(std::fs::read(&destination).unwrap(), b"unchanged-output\n");
    }
}

#[test]
fn sendfile_unsupported_offset_ranges_match_native_on_direct_kvm() {
    sendfile_unsupported_offset_ranges_match_native_on_kvm(false);
}

#[test]
fn sendfile_unsupported_offset_ranges_match_native_on_tool_kvm() {
    sendfile_unsupported_offset_ranges_match_native_on_kvm(true);
}

fn sendfile_unsupported_offset_ranges_match_native_on_kvm(tool_owned: bool) {
    assert!(
        kvm_available("KVM sendfile unsupported-input offset/count precedence"),
        "the complete sendfile unsupported-input range matrix requires usable KVM"
    );

    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    let destination = directory.0.join("readonly-output");
    let input_directory = directory.0.join("input-directory");
    std::fs::create_dir(&input_directory).unwrap();
    std::fs::write(&source, b"abcdef").unwrap();
    std::fs::write(&destination, b"unchanged-output\n").unwrap();
    let executable = compile_c_program(
        &directory.0,
        "sendfile-unsupported-offset-ranges",
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
_Static_assert(sizeof(long) == 8 && sizeof(off_t) == 8 && sizeof(size_t) == 8,
               "64-bit Linux sendfile ABI required");
enum ptrkind { CELL, BAD, NULLPTR };
struct row { const char *name; enum ptrkind kind; int64_t offset; uint64_t count; };
#define FOUR_OFFSETS(label, count_value) \
    {"negative-" label, CELL, -1, count_value}, \
    {"zero-" label, CELL, 0, count_value}, \
    {"two-" label, CELL, 2, count_value}, \
    {"max-" label, CELL, INT64_MAX, count_value}
static const struct row rows[] = {
    FOUR_OFFSETS("count-zero", UINT64_C(0)),
    FOUR_OFFSETS("count-two", UINT64_C(2)),
    FOUR_OFFSETS("count-int64-max", (uint64_t)INT64_MAX),
    FOUR_OFFSETS("count-uint64-max", UINT64_MAX),
    {"null-count-zero", NULLPTR, 2, 0},
    {"null-count-two", NULLPTR, 2, 2},
    {"null-count-int64-max", NULLPTR, 2, (uint64_t)INT64_MAX},
    {"null-count-uint64-max", NULLPTR, 2, UINT64_MAX},
    {"inaccessible-count-zero", BAD, 2, 0},
    {"inaccessible-count-two", BAD, 2, 2},
    {"inaccessible-count-int64-max", BAD, 2, (uint64_t)INT64_MAX},
    {"inaccessible-count-uint64-max", BAD, 2, UINT64_MAX},
};
_Static_assert(sizeof(rows)/sizeof(rows[0]) == 24, "matrix must retain every row");
static int exact_file(int fd, const char *expected) {
    char bytes[32];
    size_t n = strlen(expected);
    ssize_t got = pread(fd, bytes, sizeof(bytes), 0);
    return got == (ssize_t)n && memcmp(bytes, expected, n) == 0;
}
static int consume_sentinel(int fd, char expected) {
    char first = 0, extra = 0;
    ssize_t got = read(fd, &first, 1);
    errno = 0;
    ssize_t tail = read(fd, &extra, 1);
    int saved = errno;
    return got == 1 && first == expected && tail == -1 && saved == EAGAIN;
}
static int closed_fd(int fd) {
    errno = 0;
    int result = fcntl(fd, F_GETFD);
    int saved = errno;
    return result == -1 && saved == EBADF;
}
static const char *truth(int value) { return value ? "true" : "false"; }
int main(int argc, char **argv) {
    if (argc != 4) return 90;
    int rd = open(argv[1], O_RDONLY | O_CLOEXEC);
    int ro = open(argv[2], O_RDONLY | O_CLOEXEC);
    int directory = open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int directory_path = open(argv[3], O_PATH | O_DIRECTORY | O_CLOEXEC);
    int inp[2], outp[2], socks[2];
    if (rd < 0 || ro < 0 || directory < 0 || directory_path < 0 ||
        pipe2(inp, O_CLOEXEC | O_NONBLOCK) < 0 ||
        pipe2(outp, O_CLOEXEC | O_NONBLOCK) < 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socks) < 0) {
        perror("setup"); return 91;
    }
    int badout = dup(ro);
    struct stat path_before;
    int path_flags = fcntl(directory_path, F_GETFL);
    if (badout < 0 || close(badout) < 0 || path_flags < 0 ||
        fstat(directory_path, &path_before) < 0) return 92;
    const int inputs[] = {directory, directory_path, inp[0], socks[0]};
    const char *input_names[] = {"directory-readonly", "directory-opath", "pipe-read", "socket"};
    const int outputs[] = {badout, ro, outp[0]};
    const char *output_names[] = {"closed-positive", "readonly-regular", "pipe-read"};
    unsigned total = 0, invariant_failures = 0;
    for (size_t i = 0; i < sizeof(inputs)/sizeof(inputs[0]); ++i) {
        for (size_t o = 0; o < sizeof(outputs)/sizeof(outputs[0]); ++o) {
            for (size_t r = 0; r < sizeof(rows)/sizeof(rows[0]); ++r) {
                const struct row *row = &rows[r];
                int64_t cell = row->offset;
                uintptr_t ptr = row->kind == CELL ? (uintptr_t)&cell : row->kind == BAD ? 2 : 0;
                if (lseek(rd, 1, SEEK_SET) != 1 || lseek(ro, 2, SEEK_SET) != 2 ||
                    lseek(directory, 0, SEEK_SET) != 0 || write(inp[1], "I", 1) != 1 ||
                    write(outp[1], "O", 1) != 1 || write(socks[1], "S", 1) != 1) return 93;
                errno = 0;
                long result = syscall(SYS_sendfile, (long)outputs[o], (long)inputs[i], ptr, row->count);
                int saved_errno = errno;
                off_t rdpos = lseek(rd, 0, SEEK_CUR), ropos = lseek(ro, 0, SEEK_CUR);
                off_t dirpos = lseek(directory, 0, SEEK_CUR);
                int pipe_input_unchanged = consume_sentinel(inp[0], 'I');
                int pipe_output_unchanged = consume_sentinel(outp[0], 'O');
                int socket_unchanged = consume_sentinel(socks[0], 'S');
                struct stat path_after;
                int path_unchanged = fstat(directory_path, &path_after) == 0 &&
                    path_after.st_dev == path_before.st_dev && path_after.st_ino == path_before.st_ino &&
                    path_after.st_mode == path_before.st_mode && fcntl(directory_path, F_GETFL) == path_flags;
                int files_unchanged = exact_file(rd, "abcdef") && exact_file(ro, "unchanged-output\n");
                int cursors_unchanged = rdpos == 1 && ropos == 2 && dirpos == 0;
                int cell_unchanged = cell == row->offset;
                int closed_unchanged = closed_fd(badout);
                int unchanged = cursors_unchanged && cell_unchanged && files_unchanged && path_unchanged &&
                    pipe_input_unchanged && pipe_output_unchanged && socket_unchanged && closed_unchanged;
                ++total;
                invariant_failures += !(result == -1 && unchanged);
                printf("{\"input\":\"%s\",\"output\":\"%s\",\"case\":\"%s\","
                       "\"pointer_kind\":\"%s\",\"offset\":%" PRId64 ",\"count\":%" PRIu64 ","
                       "\"result\":%ld,\"errno\":%d,\"unchanged\":%s,"
                       "\"cursors_unchanged\":%s,\"cell_unchanged\":%s,\"files_unchanged\":%s,"
                       "\"opath_identity_unchanged\":%s,\"closed_output_unchanged\":%s,"
                       "\"pipe_input_unchanged\":%s,\"pipe_output_unchanged\":%s,\"socket_unchanged\":%s}\n",
                       input_names[i], output_names[o], row->name,
                       row->kind == CELL ? "cell" : row->kind == BAD ? "inaccessible" : "null",
                       row->offset, row->count, result, saved_errno, truth(unchanged),
                       truth(cursors_unchanged), truth(cell_unchanged), truth(files_unchanged),
                       truth(path_unchanged), truth(closed_unchanged), truth(pipe_input_unchanged),
                       truth(pipe_output_unchanged), truth(socket_unchanged));
            }
        }
    }
    printf("{\"summary\":true,\"total\":%u,\"invariant_failures\":%u}\n", total, invariant_failures);
    return invariant_failures || total != 288 ? 1 : 0;
}
"#,
    );
    let route = if tool_owned { "tool" } else { "direct" };
    let artifacts = std::env::var_os("PR628_F2_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| directory.0.join("observed"))
        .join("unsupported-offset-ranges");
    std::fs::create_dir_all(&artifacts).unwrap();
    std::fs::copy(&executable, artifacts.join(format!("{route}.elf"))).unwrap();
    std::fs::copy(
        executable.with_extension("c"),
        artifacts.join(format!("{route}.c")),
    )
    .unwrap();
    let save = |name: &str, code: Option<i32>, stdout: &[u8], stderr: &[u8]| {
        std::fs::write(artifacts.join(format!("{route}.{name}.stdout")), stdout).unwrap();
        std::fs::write(artifacts.join(format!("{route}.{name}.stderr")), stderr).unwrap();
        std::fs::write(
            artifacts.join(format!("{route}.{name}.exit-code")),
            format!("{code:?}\n"),
        )
        .unwrap();
    };
    let native = std::process::Command::new(&executable)
        .arg(&source)
        .arg(&destination)
        .arg(&input_directory)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    save(
        "native",
        native.status.code(),
        &native.stdout,
        &native.stderr,
    );
    assert_eq!(native.status.code(), Some(0), "native: {native:?}");
    assert!(native.stderr.is_empty());
    assert_eq!(
        native
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        289
    );
    assert!(
        native
            .stdout
            .ends_with(b"{\"summary\":true,\"total\":288,\"invariant_failures\":0}\n")
    );
    assert_eq!(std::fs::read(&source).unwrap(), b"abcdef");
    assert_eq!(std::fs::read(&destination).unwrap(), b"unchanged-output\n");

    let image = std::fs::read(&executable).unwrap();
    for repetition in 0..2 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[
                    executable.to_str().unwrap(),
                    source.to_str().unwrap(),
                    destination.to_str().unwrap(),
                    input_directory.to_str().unwrap(),
                ],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr, callbacks) = if tool_owned {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            let calls = log
                .syscalls()
                .iter()
                .filter(|name| name.as_str() == "sendfile")
                .count();
            (code, stdout, stderr, Some(calls))
        } else {
            let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
            (code, stdout, stderr, None)
        };
        save(&format!("guest-{repetition}"), Some(code), &stdout, &stderr);
        if let Some(calls) = callbacks {
            std::fs::write(
                artifacts.join(format!("{route}.guest-{repetition}.sendfile-callbacks")),
                format!("{calls}\n"),
            )
            .unwrap();
            assert_eq!(calls, 288, "repetition={repetition}");
        }
        assert_eq!(
            code, 0,
            "{route} repetition={repetition} stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, native.stdout, "{route} repetition={repetition}");
        assert_eq!(stderr, native.stderr, "{route} repetition={repetition}");
        assert_eq!(std::fs::read(&source).unwrap(), b"abcdef");
        assert_eq!(std::fs::read(&destination).unwrap(), b"unchanged-output\n");
    }
}

#[test]
fn sendfile_readonly_stdin_matches_native_on_kvm() {
    sendfile_stdin_matches_native_on_kvm(false);
}

#[test]
fn sendfile_writable_stdin_matches_native_on_kvm() {
    sendfile_stdin_matches_native_on_kvm(true);
}

fn sendfile_stdin_matches_native_on_kvm(writable: bool) {
    use std::os::fd::AsRawFd;

    let test = if writable {
        "sendfile_writable_stdin_matches_native_on_kvm"
    } else {
        "sendfile_readonly_stdin_matches_native_on_kvm"
    };
    // Pin only this subprocess's raw fd 0. Configured writable guest stdin must
    // be a different descriptor; an accidental host_write(0) must fail safely.
    if std::env::var("REVERIE_SENDFILE_STDIN_CHILD").as_deref() != Ok(test) {
        let mut statuses = Vec::new();
        // Execute both independently even if one fails, retaining each exact
        // native/KVM comparator and its diagnostic in the child output.
        for runtime in ["direct", "tool"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([test, "--exact", "--test-threads=1", "--nocapture"])
                .env("REVERIE_SENDFILE_STDIN_CHILD", test)
                .env("REVERIE_SENDFILE_STDIN_RUNTIME", runtime)
                .stdin(std::fs::File::open("/dev/null").unwrap())
                .output()
                .unwrap();
            eprintln!("{runtime}: {}", String::from_utf8_lossy(&output.stderr));
            print!("{}", String::from_utf8_lossy(&output.stdout));
            statuses.push(output.status.code());
        }
        assert_eq!(statuses, [Some(0), Some(0)], "isolated {test}");
        return;
    }
    let tool_owned = match std::env::var("REVERIE_SENDFILE_STDIN_RUNTIME")
        .unwrap()
        .as_str()
    {
        "direct" => false,
        "tool" => true,
        runtime => panic!("unknown isolated runtime {runtime}"),
    };
    assert!(kvm_available("KVM sendfile modeled stdin test"));
    // SAFETY: F_GETFL only reads the subprocess's inherited descriptor flags.
    assert_eq!(
        unsafe { libc::fcntl(0, libc::F_GETFL) } & libc::O_ACCMODE,
        libc::O_RDONLY
    );
    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    let destination = directory.0.join("stdin");
    std::fs::write(&source, b"abcdef").unwrap();
    let executable = compile_c_program(
        &directory.0,
        "sendfile-stdin",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int readonly_offset_checks(int source, const char *source_path) {
  const uint64_t outputs[] = {
      0, UINT64_C(0x5a5a5a5a00000000), UINT64_C(0xffffffff00000000)};
  const struct {
    const char *name;
    off_t offset;
    size_t count;
    int pointer_kind; // 0: valid; 1: inaccessible; 2: NULL.
    int error;
  } cases[] = {
      {"inaccessible", 2, 2, 1, EFAULT},
      {"inaccessible zero count", 2, 0, 1, EFAULT},
      {"negative", -1, 2, 0, EINVAL},
      {"minimum", INT64_MIN, 2, 0, EINVAL},
      {"maximum overflow", INT64_MAX, 1, 0, EINVAL},
      {"maximum minus one overflow", INT64_MAX - 1, 2, 0, EINVAL},
      {"maximum minus one valid", INT64_MAX - 1, 1, 0, EBADF},
      {"maximum zero count", INT64_MAX, 0, 0, EBADF},
      {"negative zero count", -1, 0, 0, EINVAL},
      {"normal", 0, 2, 0, EBADF},
      {"normal zero count", 2, 0, 0, EBADF},
      {"null", 2, 2, 2, EBADF},
      {"null zero count", 2, 0, 2, EBADF},
  };
  int failures = 0;
  for (unsigned encoding = 0; encoding < 3; ++encoding) {
    for (unsigned row = 0; row < sizeof(cases) / sizeof(cases[0]); ++row) {
      off_t offset = cases[row].offset;
      off_t *pointer = cases[row].pointer_kind == 1
          ? (off_t *)(uintptr_t)UINT64_C(0xfffffffffffff000)
          : cases[row].pointer_kind == 2 ? NULL : &offset;
      if (lseek(source, 1, SEEK_SET) != 1) return 60;
      errno = 0;
      long result = syscall(SYS_sendfile, outputs[encoding], (uint32_t)source,
                            pointer, cases[row].count);
      int error = errno;
      if (lseek(source, 0, SEEK_CUR) != 1 || offset != cases[row].offset) return 61;
      if (result != -1 || error != cases[row].error) {
        fprintf(stderr, "offset encoding=%u case=%s result=%ld errno=%d expected=%d\n",
                encoding, cases[row].name, result, error, cases[row].error);
        ++failures;
      }
    }
  }
  int write_only = open(source_path, O_WRONLY);
  int closed = dup(source);
  if (write_only < 0 || closed < 0 || close(closed)) return 62;
  const int bad_inputs[] = {write_only, closed};
  for (unsigned encoding = 0; encoding < 3; ++encoding) {
    for (unsigned input = 0; input < 2; ++input) {
      // The four negative/overflow rows must not hide invalid input access.
      for (unsigned row = 2; row < 6; ++row) {
        off_t offset = cases[row].offset;
        errno = 0;
        long result = syscall(SYS_sendfile, outputs[encoding],
                              (uint32_t)bad_inputs[input], &offset, cases[row].count);
        int error = errno;
        if (offset != cases[row].offset || lseek(source, 0, SEEK_CUR) != 1 ||
            lseek(write_only, 0, SEEK_CUR) != 0) return 63;
        if (result != -1 || error != EBADF) {
          fprintf(stderr, "input guard encoding=%u input=%u row=%u result=%ld errno=%d\n",
                  encoding, input, row, result, error);
          ++failures;
        }
      }
    }
  }
  if (close(write_only)) return 64;
  return failures ? 65 : 0;
}

int main(int argc, char **argv) {
  if (argc != 3) return 1;
  int writable = argv[2][0] == 'w';
  int access = fcntl(0, F_GETFL);
  if (access < 0 || (access & O_ACCMODE) != (writable ? O_RDWR : O_RDONLY))
    return 2;
  int source = open(argv[1], O_RDONLY);
  if (source < 0) return 3;
  const uint64_t outputs[] = {
      UINT64_C(0x5a5a5a5a00000000), UINT64_C(0xffffffff00000000)};
  if (!writable) {
    int pipes[2], sockets[2];
    if (pipe2(pipes, O_NONBLOCK) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) != 0)
      return 4;
    int directory = open(".", O_RDONLY | O_DIRECTORY);
    int proc = open("/proc/self/status", O_RDONLY);
    if (directory < 0 || proc < 0) return 5;
    const int inputs[] = {pipes[0], sockets[0], directory, STDOUT_FILENO, proc};
    const int writers[] = {pipes[1], sockets[1], -1, -1, -1};
    for (unsigned encoding = 0; encoding < 2; ++encoding) {
      for (unsigned input = 0; input < 5; ++input) {
        unsigned char sentinel = (unsigned char)(1 + encoding * 5 + input);
        if (writers[input] >= 0 && write(writers[input], &sentinel, 1) != 1)
          return 6;
        errno = 0;
        long result = syscall(SYS_sendfile, outputs[encoding],
                              (uint32_t)inputs[input], NULL, 1);
        int error = errno;
        if (writers[input] >= 0) {
          unsigned char observed = 0;
          if (read(inputs[input], &observed, 1) != 1 || observed != sentinel)
            return 7;
        }
        if (result != -1 || error != EBADF) return 20 + encoding * 5 + input;
      }
      for (unsigned explicit_offset = 0; explicit_offset < 2; ++explicit_offset) {
        off_t offset = 2;
        if (lseek(source, 1, SEEK_SET) != 1) return 8;
        errno = 0;
        long result = syscall(SYS_sendfile, outputs[encoding], (uint32_t)source,
                              explicit_offset ? &offset : NULL, 2);
        int error = errno;
        if (lseek(source, 0, SEEK_CUR) != 1 || offset != 2) return 30 + encoding;
        if (result != -1 || error != EBADF) return 32 + encoding;
      }
    }
    if (close(pipes[0]) || close(pipes[1]) || close(sockets[0]) ||
        close(sockets[1]) || close(directory) || close(proc)) return 9;
    int offset_checks = readonly_offset_checks(source, argv[1]);
    if (offset_checks) return offset_checks;
  } else {
    for (unsigned encoding = 0; encoding < 2; ++encoding) {
      off_t offset = 2;
      if (lseek(source, 1, SEEK_SET) != 1) return 10;
      if (syscall(SYS_sendfile, outputs[encoding], (uint32_t)source,
                  &offset, 3) != 3 || offset != 5 ||
          lseek(source, 0, SEEK_CUR) != 1) return 40 + encoding;
      if (syscall(SYS_sendfile, outputs[encoding], (uint32_t)source,
                  NULL, 2) != 2 || lseek(source, 0, SEEK_CUR) != 3)
        return 42 + encoding;
    }
  }
  if (close(source)) return 11;
  const char marker[] = "sendfile-stdin-ok\n";
  if (write(1, marker, sizeof(marker)-1) != sizeof(marker)-1) return 12;
  return 0;
}
"#,
    );
    if let Some(artifacts) = std::env::var_os("PR628_FD0_ARTIFACT_DIR") {
        let artifacts = PathBuf::from(artifacts);
        std::fs::create_dir_all(&artifacts).unwrap();
        let name = format!("{test}-tool-{tool_owned}");
        std::fs::copy(&executable, artifacts.join(&name)).unwrap();
        std::fs::copy(
            executable.with_extension("c"),
            artifacts.join(format!("{name}.c")),
        )
        .unwrap();
    }
    let stdin = || {
        std::fs::write(&destination, b"").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(writable)
            .open(&destination)
            .unwrap();
        assert_ne!(file.as_raw_fd(), libc::STDIN_FILENO);
        file
    };
    let mode = if writable { "writable" } else { "readonly" };
    let expected_destination: &[u8] = if writable { b"cdebccdebc" } else { b"" };
    let native = std::process::Command::new(&executable)
        .arg(&source)
        .arg(mode)
        .current_dir(&directory.0)
        .stdin(stdin())
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(0), "native {mode}: {native:?}");
    assert_eq!(native.stdout, b"sendfile-stdin-ok\n");
    assert!(native.stderr.is_empty());
    assert_eq!(std::fs::read(&destination).unwrap(), expected_destination);
    eprintln!("native {mode} passed");
    let image = std::fs::read(&executable).unwrap();
    for repetition in 0..2 {
        let mut backend = KvmBackend::new_with_stdin(256 * 1024 * 1024, Some(stdin())).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable.to_str().unwrap(), source.to_str().unwrap(), mode],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code, 0,
            "{mode} tool_owned={tool_owned} repetition={repetition} stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(stdout, native.stdout);
        assert_eq!(stderr, native.stderr);
        assert_eq!(std::fs::read(&destination).unwrap(), expected_destination);
        eprintln!("{mode} tool_owned={tool_owned} repetition={repetition} passed");
    }
}

#[test]
fn storage_fd_syscalls_consume_low_words_on_kvm() {
    if !kvm_available("KVM storage fd low-word argument test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "storage-fd-low-word",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HIGH_WORD UINT64_C(0x5a5a5a5a00000000)
#define SIGNED_LOW_WORD (HIGH_WORD | UINT64_C(0x80000000))

static int failed_with(long result, int expected) {
  return result == -1 && errno == expected;
}

int main(int argc, char **argv) {
  if (argc != 2) return 1;
  int fd = open(argv[1], O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (fd < 0 || write(fd, "data", 4) != 4) return 2;

  if (syscall(SYS_fsync, HIGH_WORD | (uint32_t)fd) != 0) return 3;
  if (syscall(SYS_fdatasync, HIGH_WORD | (uint32_t)fd) != 0) return 4;
  if (syscall(SYS_readahead, HIGH_WORD | (uint32_t)fd, 0, 4096) != 0)
    return 5;
  if (syscall(SYS_sync_file_range, HIGH_WORD | (uint32_t)fd, 0, 4096,
              SYNC_FILE_RANGE_WRITE) != 0) return 6;

  errno = 0;
  long allocated = syscall(SYS_fallocate, HIGH_WORD | (uint32_t)fd,
                           0, 0, 4096);
  if (allocated != 0 && !failed_with(allocated, EOPNOTSUPP)) return 7;
  const char *allocation_result = allocated == 0 ? "ok" : "unsupported";

  // These errors occur only after the high-word alias resolves to the live fd.
  errno = 0;
  if (!failed_with(syscall(SYS_fallocate, HIGH_WORD | (uint32_t)fd,
                           0, 0, 0), EINVAL)) return 8;
  errno = 0;
  if (!failed_with(syscall(SYS_readahead, HIGH_WORD | (uint32_t)fd,
                           (int64_t)-1, 1), EINVAL)) return 9;
  errno = 0;
  if (!failed_with(syscall(SYS_sync_file_range,
                           HIGH_WORD | (uint32_t)fd, 0, 1,
                           UINT64_C(1) << 30), EINVAL)) return 10;

  // A set low-word sign bit denotes a negative/invalid int fd, even when
  // unrelated higher bits are also present.
  uint64_t invalid = SIGNED_LOW_WORD | (uint32_t)fd;
  errno = 0;
  if (!failed_with(syscall(SYS_fsync, invalid), EBADF)) return 11;
  errno = 0;
  if (!failed_with(syscall(SYS_fdatasync, invalid), EBADF)) return 12;
  errno = 0;
  if (!failed_with(syscall(SYS_readahead, invalid, 0, 1), EBADF)) return 13;
  errno = 0;
  if (!failed_with(syscall(SYS_sync_file_range, invalid, 0, 1,
                           SYNC_FILE_RANGE_WRITE), EBADF)) return 14;
  errno = 0;
  if (!failed_with(syscall(SYS_fallocate, invalid, 0, 0, 1), EBADF)) return 15;

  if (close(fd) != 0) return 16;
  printf("storage-low-word-ok fallocate=%s\n", allocation_result);
  return 0;
}
"#,
    );

    let native = std::process::Command::new(&executable)
        .arg(directory.0.join("native-storage-low-word"))
        .output()
        .unwrap();
    assert_eq!(
        native.status.code(),
        Some(0),
        "native stdout={} stderr={}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(
        native.stdout == b"storage-low-word-ok fallocate=ok\n"
            || native.stdout == b"storage-low-word-ok fallocate=unsupported\n",
        "unexpected native oracle: {:?}",
        String::from_utf8_lossy(&native.stdout)
    );
    assert!(native.stderr.is_empty());

    let image = std::fs::read(&executable).unwrap();
    for (tool_owned, repetition) in [(false, 0), (false, 1), (true, 0), (true, 1)] {
        let executable = executable.to_str().unwrap();
        let guest_path = directory
            .0
            .join(format!("guest-storage-low-word-{tool_owned}-{repetition}"));
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable, guest_path.to_str().unwrap()],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code,
            0,
            "tool_owned={tool_owned} repetition={repetition} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(
            stdout, native.stdout,
            "tool_owned={tool_owned} repetition={repetition}"
        );
        assert_eq!(
            stderr, native.stderr,
            "tool_owned={tool_owned} repetition={repetition}"
        );
    }
}

#[test]
fn read_and_pread64_consume_low_descriptor_words_on_kvm() {
    if !kvm_available("KVM read and pread64 fd low-word argument test") {
        return;
    }

    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "read-pread-fd-low-word",
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HIGH_WORD UINT64_C(0x5a5a5a5a00000000)
#define BIT31_LOW_WORD (HIGH_WORD | UINT64_C(0x80000000))

static int failed_with(long result, int expected) {
  return result == -1 && errno == expected;
}

int main(int argc, char **argv) {
  if (argc != 2) return 1;
  int fd = open(argv[1], O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (fd < 0 || write(fd, "abcdef", 6) != 6 || lseek(fd, 0, SEEK_SET) != 0)
    return 2;

  char bytes[2];
  if (syscall(SYS_read, HIGH_WORD | (uint32_t)fd, bytes, 2) != 2 ||
      bytes[0] != 'a' || bytes[1] != 'b') return 3;
  if (syscall(SYS_pread64, HIGH_WORD | (uint32_t)fd, bytes, 2, 2) != 2 ||
      bytes[0] != 'c' || bytes[1] != 'd') return 4;
  if (lseek(fd, 0, SEEK_CUR) != 2) return 5;

  errno = 0;
  if (!failed_with(syscall(SYS_read, HIGH_WORD | (uint32_t)fd,
                           (void *)(uintptr_t)UINT64_MAX, 1), EFAULT)) return 6;
  if (syscall(SYS_read, HIGH_WORD | (uint32_t)fd, bytes, 2) != 2 ||
      bytes[0] != 'c' || bytes[1] != 'd') return 7;
  errno = 0;
  if (!failed_with(syscall(SYS_pread64, HIGH_WORD | (uint32_t)fd,
                           (void *)(uintptr_t)UINT64_MAX, 1, 0), EFAULT)) return 8;
  errno = 0;
  if (!failed_with(syscall(SYS_pread64, HIGH_WORD | (uint32_t)fd,
                           bytes, 1, (int64_t)-1), EINVAL)) return 9;

  uint64_t invalid = BIT31_LOW_WORD | (uint32_t)fd;
  errno = 0;
  if (!failed_with(syscall(SYS_read, invalid,
                           (void *)(uintptr_t)UINT64_MAX, 1), EBADF)) return 10;
  errno = 0;
  if (!failed_with(syscall(SYS_pread64, invalid,
                           (void *)(uintptr_t)UINT64_MAX, 1, 0), EBADF)) return 11;

  if (close(fd) != 0) return 12;
  puts("read-pread-low-word-ok");
  return 0;
}
"#,
    );

    let native = std::process::Command::new(&executable)
        .arg(directory.0.join("native-read-pread-low-word"))
        .output()
        .unwrap();
    assert_eq!(
        native.status.code(),
        Some(0),
        "native stdout={} stderr={}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"read-pread-low-word-ok\n");
    assert!(native.stderr.is_empty());

    let image = std::fs::read(&executable).unwrap();
    for (tool_owned, repetition) in [(false, 0), (false, 1), (true, 0), (true, 1)] {
        let executable = executable.to_str().unwrap();
        let guest_path = directory.0.join(format!(
            "guest-read-pread-low-word-{tool_owned}-{repetition}"
        ));
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[executable, guest_path.to_str().unwrap()],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if tool_owned {
            let (_, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code,
            0,
            "tool_owned={tool_owned} repetition={repetition} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(
            stdout, native.stdout,
            "tool_owned={tool_owned} repetition={repetition}"
        );
        assert_eq!(
            stderr, native.stderr,
            "tool_owned={tool_owned} repetition={repetition}"
        );
    }
}

type TurnRequests = futures::channel::mpsc::UnboundedSender<futures::channel::oneshot::Sender<()>>;

/// A scheduler reachable from every guest process's Tool, and the calls those
/// Tools completed.
#[derive(Clone)]
struct CoScheduledConfig {
    turns: TurnRequests,
    calls: Arc<Mutex<Vec<(i32, Sysno, i64)>>>,
}

static CO_SCHEDULED_CONFIGS: LazyLock<Mutex<BTreeMap<u64, CoScheduledConfig>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static NEXT_CO_SCHEDULED_CONFIG: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
struct CoScheduledGlobal;

#[reverie::global_tool]
impl GlobalTool for CoScheduledGlobal {
    type Request = ();
    type Response = ();
    type Config = u64;

    async fn init_global_state(_config: &u64) -> Self {
        Self
    }

    async fn receive_rpc(&self, _from: Pid, (): ()) {}
}

/// Every intercepted call first waits for a turn from a scheduler that only
/// the embedder's own executor polls, as Hermit's Detcore scheduler is.
#[derive(Default)]
struct CoScheduledTool {
    pid: i32,
    config: Option<CoScheduledConfig>,
}

#[reverie::tool]
impl Tool for CoScheduledTool {
    type GlobalState = CoScheduledGlobal;
    type ThreadState = ();

    fn new(pid: Pid, config: &u64) -> Self {
        Self {
            pid: pid.as_raw(),
            config: CO_SCHEDULED_CONFIGS.lock().unwrap().get(config).cloned(),
        }
    }

    fn subscriptions(_config: &u64) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::getpid, Sysno::exit_group]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let config = self
            .config
            .as_ref()
            .expect("co-scheduled config disappeared");
        let (turn, granted) = futures::channel::oneshot::channel();
        config
            .turns
            .unbounded_send(turn)
            .expect("the embedder's scheduler stopped");
        granted
            .await
            .expect("the embedder's scheduler dropped a turn");
        let (number, args) = syscall.into_parts();
        if number == Sysno::exit_group {
            let status = args.arg0 as i64;
            config
                .calls
                .lock()
                .unwrap()
                .push((self.pid, number, status));
            guest.tail_inject(syscall).await
        } else {
            let result = guest.inject(syscall).await?;
            config
                .calls
                .lock()
                .unwrap()
                .push((self.pid, number, result));
            Ok(result)
        }
    }
}

#[test]
fn traced_root_exit_leaves_the_embedders_scheduler_running_for_its_children() {
    const TEST: &str = "traced_root_exit_leaves_the_embedders_scheduler_running_for_its_children";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "root-exit-co-scheduled",
        r#"
#include <unistd.h>

int main(void) {
  int hold[2];
  if (pipe(hold) != 0) return 10;
  pid_t child = fork();
  if (child < 0) return 11;
  if (child == 0) {
    close(hold[1]);
    int parent[2];
    if (pipe(parent) != 0) _exit(14);
    pid_t grandchild = fork();
    if (grandchild < 0) _exit(12);
    /* End of file arrives only once the root has exited and released its
       write end, so both processes still need turns while it exits. */
    char byte;
    if (read(hold[0], &byte, 1) != 0) _exit(13);
    if (grandchild == 0) {
      /* Only the exiting child still holds this write end, so the
         grandchild is always adopted while it runs, then joined by the
         traced root's orphan drain. */
      close(parent[1]);
      if (read(parent[0], &byte, 1) != 0) _exit(15);
      (void)getpid();
      _exit(getppid() == 1 ? 9 : 16);
    }
    (void)getpid();
    _exit(0);
  }
  close(hold[0]);
  return 7;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.set_root_pid(3).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();

    let (turns, mut requests) = futures::channel::mpsc::unbounded();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let config = NEXT_CO_SCHEDULED_CONFIG.fetch_add(1, Ordering::SeqCst);
    CO_SCHEDULED_CONFIGS.lock().unwrap().insert(
        config,
        CoScheduledConfig {
            turns,
            calls: calls.clone(),
        },
    );
    // One thread polls both the run, whose root joins its children when it
    // exits, and the scheduler those children need. Bounded by the 30s
    // self-exec timeout.
    let scheduler = async {
        while let Some(turn) = futures::StreamExt::next(&mut requests).await {
            let _ = turn.send(());
        }
        unreachable!("the config registry holds a turn sender");
    };
    let run = backend.run_static_elf_with_tool::<CoScheduledTool>(config, true);
    let result = match futures::executor::block_on(futures::future::select(
        std::pin::pin!(run),
        std::pin::pin!(scheduler),
    )) {
        futures::future::Either::Left((result, _)) => result,
        futures::future::Either::Right(_) => unreachable!(),
    };
    CO_SCHEDULED_CONFIGS.lock().unwrap().remove(&config);
    let (_, code, _stdout, stderr) = result.unwrap();
    assert_eq!(code, 7, "stderr={}", String::from_utf8_lossy(&stderr));

    let calls = std::mem::take(&mut *calls.lock().unwrap());
    let exits = calls
        .iter()
        .filter(|(_, number, _)| *number == Sysno::exit_group)
        .map(|&(pid, _, status)| (pid, status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        exits,
        BTreeMap::from([(3, 7), (4, 0), (5, 9)]),
        "every process ran to exit after the root: {calls:?}"
    );
    for pid in [4, 5] {
        assert!(
            calls.contains(&(pid, Sysno::getpid, i64::from(pid))),
            "{pid} took its turn after the root's exit began: {calls:?}"
        );
    }
}

/// A turn request from the process `.0` for the call `.1`, granted by `.2`.
/// A turn requested by a dropped-run Tool: the GlobalState's initialization
/// (pid 0, no syscall) or a process's intercepted syscall.
type DroppedRunTurn = (i32, Option<Sysno>, futures::channel::oneshot::Sender<()>);

#[derive(Clone)]
struct DroppedRunConfig {
    turns: std::sync::mpsc::Sender<DroppedRunTurn>,
    calls: Arc<Mutex<Vec<(i32, Sysno, i64)>>>,
    teardown: Arc<DroppedRunTeardown>,
}

/// Holds each child's host thread in its thread-local teardown, after its
/// run has returned and published its result, until released.
struct DroppedRunTeardown {
    // Each held thread owns one strong count until its teardown ends.
    lifetime: Weak<()>,
    state: Mutex<(std::collections::BTreeSet<i32>, bool)>,
    changed: Condvar,
    /// If set, each teardown instead waits for a turn from the test's
    /// scheduler, which only the thread polling the run grants.
    turns: Option<std::sync::mpsc::Sender<DroppedRunTurn>>,
    /// Each thread whose teardown ran to its end, once per teardown.
    finished: Mutex<Vec<i32>>,
}

struct DroppedRunThread {
    pid: i32,
    teardown: Arc<DroppedRunTeardown>,
    _lifetime: Arc<()>,
}

impl Drop for DroppedRunThread {
    fn drop(&mut self) {
        let mut state = self.teardown.state.lock().unwrap();
        state.0.insert(self.pid);
        self.teardown.changed.notify_all();
        if let Some(turns) = &self.teardown.turns {
            drop(state);
            let (turn, granted) = futures::channel::oneshot::channel();
            turns
                .send((self.pid, None, turn))
                .expect("the test's scheduler stopped");
            futures::executor::block_on(granted).expect("the test's scheduler dropped a turn");
        } else {
            while !state.1 {
                state = self.teardown.changed.wait(state).unwrap();
            }
            drop(state);
        }
        // An owner that joins this thread returns only after its lifetime
        // count is released; one that detached it returns while it sleeps.
        std::thread::sleep(std::time::Duration::from_millis(100));
        self.teardown.finished.lock().unwrap().push(self.pid);
    }
}

thread_local! {
    static DROPPED_RUN_THREAD: std::cell::RefCell<Option<DroppedRunThread>> =
        const { std::cell::RefCell::new(None) };
}

static DROPPED_RUN_CONFIGS: LazyLock<Mutex<BTreeMap<u64, DroppedRunConfig>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static DROPPED_RUN_GLOBALS_STARTED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static DROPPED_RUN_GLOBALS_RELEASED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
const DROPPED_RUN_ROOT: i32 = 3;
const DROPPED_RUN_SETUP: i32 = 0;

fn dropped_run_turn(
    config: &DroppedRunConfig,
    pid: i32,
    number: Option<Sysno>,
) -> impl std::future::Future<Output = ()> {
    let (turn, granted) = futures::channel::oneshot::channel();
    config
        .turns
        .send((pid, number, turn))
        .expect("the test's scheduler stopped");
    async move { granted.await.expect("the test's scheduler dropped a turn") }
}

#[derive(Debug, Default)]
struct DroppedRunGlobal {
    config: u64,
}

impl Drop for DroppedRunGlobal {
    fn drop(&mut self) {
        DROPPED_RUN_GLOBALS_RELEASED
            .lock()
            .unwrap()
            .push(self.config);
    }
}

#[reverie::global_tool]
impl GlobalTool for DroppedRunGlobal {
    type Request = ();
    type Response = ();
    type Config = u64;

    async fn init_global_state(config: &u64) -> Self {
        DROPPED_RUN_GLOBALS_STARTED.lock().unwrap().push(*config);
        let run = DROPPED_RUN_CONFIGS.lock().unwrap().get(config).cloned();
        let run = run.expect("dropped-run config disappeared");
        dropped_run_turn(&run, DROPPED_RUN_SETUP, None).await;
        Self { config: *config }
    }

    async fn receive_rpc(&self, _from: Pid, (): ()) {}
}

/// Every intercepted call waits for a turn from the test's scheduler, and the
/// first one on any thread but the root's holds its host thread at teardown.
/// Turns are keyed by thread: a CLONE_VM worker shares its process's Tool.
#[derive(Default)]
struct DroppedRunTool {
    config: Option<DroppedRunConfig>,
}

#[reverie::tool]
impl Tool for DroppedRunTool {
    type GlobalState = DroppedRunGlobal;
    type ThreadState = ();

    fn new(_pid: Pid, config: &u64) -> Self {
        Self {
            config: DROPPED_RUN_CONFIGS.lock().unwrap().get(config).cloned(),
        }
    }

    fn subscriptions(_config: &u64) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::getpid, Sysno::wait4, Sysno::exit_group]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let config = self
            .config
            .as_ref()
            .expect("dropped-run config disappeared");
        let tid = guest.tid().as_raw();
        let (number, mut args) = syscall.into_parts();
        if number == Sysno::wait4 {
            // As Hermit's scheduler does, poll a blocking wait4 between turns,
            // so its caller never blocks the thread that grants them.
            let blocking = args.arg2 & libc::WNOHANG as usize == 0;
            args.arg2 |= libc::WNOHANG as usize;
            loop {
                dropped_run_turn(config, tid, Some(number)).await;
                let result = guest.inject(Syscall::from_raw(number, args)).await?;
                if result != 0 || !blocking {
                    return Ok(result);
                }
            }
        }
        if tid != DROPPED_RUN_ROOT {
            DROPPED_RUN_THREAD.with(|thread| {
                thread.borrow_mut().get_or_insert_with(|| DroppedRunThread {
                    pid: tid,
                    teardown: config.teardown.clone(),
                    _lifetime: config
                        .teardown
                        .lifetime
                        .upgrade()
                        .expect("the test released the child lifetime"),
                });
            });
        }
        dropped_run_turn(config, tid, Some(number)).await;
        if number == Sysno::exit_group {
            let status = args.arg0 as i64;
            config.calls.lock().unwrap().push((tid, number, status));
            guest.tail_inject(syscall).await
        } else {
            let result = guest.inject(syscall).await?;
            config.calls.lock().unwrap().push((tid, number, result));
            Ok(result)
        }
    }
}

/// Where the root is when the embedder drops the run's future.
#[derive(Clone, Copy, Debug)]
enum RunDropPoint {
    /// Its GlobalState is still being initialized: the image is consumed but
    /// no guest has entered KVM, so nothing else refuses a new image.
    Setup,
    /// Its exit is joining a pending child, with a collected child and an
    /// orphan still to join.
    ExitJoin,
    /// It still runs, waiting for a turn, and holds a pipe the orphan reads
    /// until end of file.
    Running,
}

/// The embedder's scheduler, polled only on the thread that polls the run and
/// drops the backend, as on a single-threaded executor.
struct SameThreadScheduler {
    requests: std::sync::mpsc::Receiver<DroppedRunTurn>,
    /// None for a run that is never dropped, which withholds no turn.
    point: Option<RunDropPoint>,
    held: Vec<(i32, Option<Sysno>)>,
    waiting: Vec<(i32, Option<Sysno>, futures::channel::oneshot::Sender<()>)>,
    released: bool,
    /// Withholds every thread's teardown turn, independently of `released`.
    withhold_teardown: bool,
    /// Until released, withholds the root's and its CLONE_VM worker's
    /// getpid turns, for a run with no drop point.
    withhold_worker: bool,
    /// Every Tool, GlobalState initialization, and config released its turn
    /// sender.
    stopped: bool,
}

impl SameThreadScheduler {
    const COLLECTED: i32 = 4;
    const PENDING: i32 = 5;
    const ORPHAN: i32 = 6;
    const WORKER: i32 = 4;

    fn withheld(&self, pid: i32, number: Option<Sysno>) -> bool {
        if self.withhold_teardown && number.is_none() && pid != DROPPED_RUN_SETUP {
            return true;
        }
        !self.released
            && match self.point {
                None => {
                    self.withhold_worker
                        && number == Some(Sysno::getpid)
                        && [DROPPED_RUN_ROOT, Self::WORKER].contains(&pid)
                }
                Some(RunDropPoint::Setup) => pid == DROPPED_RUN_SETUP,
                Some(RunDropPoint::ExitJoin) => pid == Self::ORPHAN,
                // The orphan's getpid follows the drop, which closes the
                // root's pipe.
                Some(RunDropPoint::Running) => {
                    number == Some(Sysno::getpid) && [DROPPED_RUN_ROOT, Self::ORPHAN].contains(&pid)
                }
            }
    }

    fn pump(&mut self) {
        loop {
            match self.requests.try_recv() {
                Ok((pid, number, turn)) if self.withheld(pid, number) => {
                    self.held.push((pid, number));
                    self.waiting.push((pid, number, turn));
                }
                Ok((_, _, turn)) => {
                    let _ = turn.send(());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.stopped = true;
                    break;
                }
            }
        }
        for (pid, number, turn) in std::mem::take(&mut self.waiting) {
            if self.withheld(pid, number) {
                self.waiting.push((pid, number, turn));
            } else {
                let _ = turn.send(());
            }
        }
    }
}

/// This process's host threads, by TID, with their names.
fn host_tasks() -> BTreeMap<u32, String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let tid = entry.file_name().to_str()?.parse().ok()?;
            let name = std::fs::read_to_string(entry.path().join("comm")).ok()?;
            Some((tid, name.trim_end().to_owned()))
        })
        .collect()
}

#[test]
fn dropped_public_run_hands_its_children_to_the_reaper() {
    const TEST: &str = "dropped_public_run_hands_its_children_to_the_reaper";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "dropped-public-run",
        r#"
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int running = argc > 1 && argv[1][0] == 'r';
  int root_held[2];
  if (pipe(root_held) != 0) return 10;
  pid_t collected = fork();
  if (collected < 0) return 11;
  if (collected == 0) _exit(0);
  pid_t parent = fork();
  if (parent < 0) return 12;
  if (parent == 0) {
    pid_t orphan = fork();
    if (orphan < 0) _exit(13);
    if (orphan == 0) {
      close(root_held[1]);
      char byte;
      if (running && read(root_held[0], &byte, 1) != 0) _exit(14);
      (void)getpid();
      _exit(0);
    }
    _exit(0);
  }
  int status;
  if (waitpid(collected, &status, 0) != collected) return 15;
  if (running) (void)getpid();
  return 7;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    for (point, config) in [
        (RunDropPoint::ExitJoin, 1),
        (RunDropPoint::Running, 2),
        (RunDropPoint::Setup, 3),
    ] {
        dropped_public_run_case(&directory, executable, &image, point, config);
    }
    returned_public_run_case(&directory, executable, &image, 4);
    // Each run's reaper exits once it has retired what that run left, and a
    // returned run joins its own before it returns.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let reapers = reaper_tasks(&BTreeMap::new());
        if reapers.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a reaper outlived every run: {reapers:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Reaper threads started since `baseline`.
fn reaper_tasks(baseline: &BTreeMap<u32, String>) -> Vec<u32> {
    host_tasks()
        .into_iter()
        .filter(|(tid, name)| !baseline.contains_key(tid) && name.starts_with("reverie-kvm-rea"))
        .map(|(tid, _)| tid)
        .collect()
}

fn dropped_public_run_case(
    directory: &TestDirectory,
    executable: &str,
    image: &[u8],
    point: RunDropPoint,
    config: u64,
) {
    const COLLECTED: i32 = SameThreadScheduler::COLLECTED;
    const PENDING: i32 = SameThreadScheduler::PENDING;
    const ORPHAN: i32 = SameThreadScheduler::ORPHAN;
    let mode = match point {
        RunDropPoint::Running => "running",
        RunDropPoint::Setup | RunDropPoint::ExitJoin => "exit-join",
    };
    let install = |backend: &mut KvmBackend| {
        backend.install_static_elf_with_context(
            image,
            &[executable, mode],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
    };
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.set_root_pid(DROPPED_RUN_ROOT).unwrap();
    install(&mut backend).unwrap();

    let lifetime = Arc::new(());
    let teardown = Arc::new(DroppedRunTeardown {
        lifetime: Arc::downgrade(&lifetime),
        state: Mutex::new((Default::default(), false)),
        changed: Condvar::new(),
        turns: None,
        finished: Mutex::new(Vec::new()),
    });
    let (turns, requests) = std::sync::mpsc::channel::<DroppedRunTurn>();
    let calls = Arc::new(Mutex::new(Vec::new()));
    DROPPED_RUN_CONFIGS.lock().unwrap().insert(
        config,
        DroppedRunConfig {
            turns,
            calls: calls.clone(),
            teardown: teardown.clone(),
        },
    );
    let mut scheduler = SameThreadScheduler {
        requests,
        point: Some(point),
        held: Vec::new(),
        waiting: Vec::new(),
        released: false,
        withhold_teardown: false,
        withhold_worker: false,
        stopped: false,
    };

    let case = format!("dropped at {point:?}");
    let reached = || teardown.state.lock().unwrap().0.clone();
    // Taken before the run starts its reaper.
    let baseline = host_tasks();
    let mut cx = std::task::Context::from_waker(Waker::noop());
    {
        let mut run =
            Box::pin(backend.run_static_elf_with_tool_completion::<DroppedRunTool>(config, true));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                run.as_mut().poll(&mut cx).is_pending(),
                "{case}: the run returned while its children were held"
            );
            scheduler.pump();
            let ready = match point {
                RunDropPoint::Setup => scheduler.held.contains(&(DROPPED_RUN_SETUP, None)),
                RunDropPoint::ExitJoin => {
                    calls
                        .lock()
                        .unwrap()
                        .contains(&(DROPPED_RUN_ROOT, Sysno::exit_group, 7))
                        && scheduler.held.contains(&(ORPHAN, Some(Sysno::getpid)))
                        && reached() == [COLLECTED, PENDING].into()
                }
                RunDropPoint::Running => {
                    scheduler
                        .held
                        .contains(&(DROPPED_RUN_ROOT, Some(Sysno::getpid)))
                        && reached() == [COLLECTED, PENDING].into()
                }
            };
            if ready {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{case}: never reached the drop point: calls={:?} held={:?} reached={:?}",
                calls.lock().unwrap(),
                scheduler.held,
                reached(),
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        for _ in 0..10 {
            assert!(run.as_mut().poll(&mut cx).is_pending(), "{case}");
            scheduler.pump();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Collected and pending children are held in teardown. In ExitJoin
        // the orphan also waits for its turn; in Running it still blocks
        // reading the root's pipe and has made no call.
        let held_threads = match point {
            RunDropPoint::Setup => 0,
            RunDropPoint::ExitJoin => 3,
            RunDropPoint::Running => 2,
        };
        assert_eq!(
            Arc::strong_count(&lifetime),
            1 + held_threads,
            "{case}: the children held before the drop"
        );
        assert!(
            !scheduler.held.iter().any(|&(pid, _)| pid == ORPHAN)
                || matches!(point, RunDropPoint::ExitJoin),
            "{case}: the orphan ran before the root's pipe closed: {:?}",
            scheduler.held
        );
    }
    DROPPED_RUN_CONFIGS.lock().unwrap().remove(&config);
    if matches!(point, RunDropPoint::Running) {
        // Dropping the run released the root's files, so the orphan reads end
        // of file and requests its getpid turn, now holding a third lifetime.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !scheduler.held.contains(&(ORPHAN, Some(Sysno::getpid))) {
            assert!(
                std::time::Instant::now() < deadline,
                "{case}: the orphan never saw the root's pipe close: held={:?}",
                scheduler.held
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
            scheduler.pump();
        }
    }
    // Every held child still holds its lifetime, and none has been granted
    // the turn it waits for.
    let held_threads = match point {
        RunDropPoint::Setup => 0,
        RunDropPoint::ExitJoin | RunDropPoint::Running => 3,
    };
    let holders = match point {
        RunDropPoint::Setup => [].into(),
        RunDropPoint::ExitJoin | RunDropPoint::Running => [COLLECTED, PENDING].into(),
    };
    let assert_children_held = |when: &str| {
        assert_eq!(
            Arc::strong_count(&lifetime),
            1 + held_threads,
            "{case}: the children held {when}"
        );
        assert_eq!(
            reached(),
            holders,
            "{case}: the children in teardown {when}"
        );
        assert!(
            !DROPPED_RUN_GLOBALS_RELEASED
                .lock()
                .unwrap()
                .contains(&config),
            "{case}: GlobalState was released {when}"
        );
    };
    assert_children_held("with the dropped run");

    // Reusing the backend is refused before any run state is touched: no new
    // image, no GlobalState, no Tool.
    let started = DROPPED_RUN_GLOBALS_STARTED.lock().unwrap().len();
    assert!(
        matches!(
            install(&mut backend),
            Err(reverie_kvm::Error::AbandonedRunNotRetired)
        ),
        "{case}: the backend accepted an image while a dropped run was unretired"
    );
    let image_file = std::fs::File::open(executable).unwrap();
    for (entry, refused) in [
        (
            "a real-mode program",
            backend.install_real_mode_program(0x1000, &[0xf4]),
        ),
        (
            "an image file",
            backend.install_static_elf_file_with_context(
                image_file,
                &[executable, mode],
                &["PATH=/usr/bin:/bin"],
                &directory.0,
            ),
        ),
        ("a raw run", backend.run(|_, _| 0)),
        ("a static ELF run", backend.run_static_elf().map(drop)),
        (
            "a captured static ELF run",
            backend.run_static_elf_captured().map(drop),
        ),
        ("guest memory", backend.memory().map(drop)),
        ("mutable guest memory", backend.memory_mut().map(drop)),
        ("the VM fd", backend.vm_fd().map(drop)),
        ("a root pid", backend.set_root_pid(DROPPED_RUN_ROOT)),
        ("a random seed", backend.set_random_seed(1)),
    ] {
        assert_refused(&case, entry, refused);
    }
    assert_raw_requests_refused(&case, &mut backend);
    {
        let mut reuse =
            Box::pin(backend.run_static_elf_with_tool_completion::<DroppedRunTool>(config, true));
        assert!(
            matches!(
                reuse.as_mut().poll(&mut cx),
                std::task::Poll::Ready(Err(reverie_kvm::Error::AbandonedRunNotRetired))
            ),
            "{case}: the backend admitted a run while a dropped run was unretired"
        );
    }
    {
        let mut reuse = Box::pin(backend.run_with_tool::<DroppedRunTool, _>(
            config,
            |_: &reverie_kvm::SyscallRequest, _: &reverie_kvm::GuestMemory| 0,
        ));
        assert!(
            matches!(
                reuse.as_mut().poll(&mut cx),
                std::task::Poll::Ready(Err(reverie_kvm::Error::AbandonedRunNotRetired))
            ),
            "{case}: the backend admitted a Tool run while a dropped run was unretired"
        );
    }
    assert_eq!(
        DROPPED_RUN_GLOBALS_STARTED.lock().unwrap().len(),
        started,
        "{case}: a refused run initialized GlobalState"
    );

    // The same thread that must grant the children's turns drops the backend
    // before granting any. A drop that waited for them would never return.
    let dropping = std::time::Instant::now();
    drop(backend);
    assert!(
        dropping.elapsed() < std::time::Duration::from_secs(5),
        "{case}: the backend's drop waited {:?}",
        dropping.elapsed()
    );
    assert_children_held("before its turn was granted");
    let children: std::collections::BTreeSet<i32> = match point {
        RunDropPoint::Setup => [].into(),
        RunDropPoint::ExitJoin | RunDropPoint::Running => [COLLECTED, PENDING, ORPHAN].into(),
    };
    if !matches!(point, RunDropPoint::Setup) {
        // The run's own reaper holds its children, rather than the drop.
        assert_eq!(
            reaper_tasks(&baseline).len(),
            1,
            "{case}: the dropped run's reaper exited while its children were held"
        );
    }

    scheduler.released = true;
    teardown.state.lock().unwrap().1 = true;
    teardown.changed.notify_all();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let finished = || {
        let mut finished = teardown.finished.lock().unwrap().clone();
        finished.sort_unstable();
        finished
    };
    let retired = |scheduler: &SameThreadScheduler| {
        // A reaper that joins each child exits only after every child's
        // teardown, which sleeps before releasing its lifetime, has ended.
        // One that detached them exits while they sleep.
        if reaper_tasks(&baseline).is_empty() {
            assert_eq!(
                (Arc::strong_count(&lifetime), finished()),
                (1, children.iter().copied().collect::<Vec<_>>()),
                "{case}: the reaper exited before its children's teardown ended"
            );
        }
        let leftover = host_tasks()
            .into_iter()
            .filter(|(tid, _)| !baseline.contains_key(tid))
            .collect::<BTreeMap<_, _>>();
        let released = DROPPED_RUN_GLOBALS_RELEASED
            .lock()
            .unwrap()
            .contains(&config);
        let state = (
            Arc::strong_count(&lifetime),
            released,
            scheduler.stopped,
            leftover,
        );
        let done = state.0 == 1
            && state.1 == !matches!(point, RunDropPoint::Setup)
            && state.2
            && state.3.is_empty();
        (done, state)
    };
    loop {
        scheduler.pump();
        let (done, state) = retired(&scheduler);
        if done {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{case}: the dropped run's children were never retired: \
             (lifetime, GlobalState released, scheduler stopped, host threads)={state:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    assert_eq!(
        reached(),
        children,
        "{case}: every child's teardown finished"
    );
    assert_eq!(
        finished(),
        children.iter().copied().collect::<Vec<_>>(),
        "{case}: each child's teardown ran exactly once"
    );
    let calls = std::mem::take(&mut *calls.lock().unwrap());
    let exits = calls
        .iter()
        .filter(|(_, number, _)| *number == Sysno::exit_group)
        .map(|&(pid, _, status)| (pid, status))
        .collect::<BTreeMap<_, _>>();
    let mut expected = children
        .iter()
        .map(|&pid| (pid, 0))
        .collect::<BTreeMap<_, _>>();
    if matches!(point, RunDropPoint::ExitJoin) {
        expected.insert(DROPPED_RUN_ROOT, 7);
    }
    assert_eq!(exits, expected, "{case}: {calls:?}");
    if !matches!(point, RunDropPoint::Setup) {
        assert!(
            calls.contains(&(ORPHAN, Sysno::getpid, i64::from(ORPHAN))),
            "{case}: the orphan ran after the drop: {calls:?}"
        );
    }
}

/// A run that returns has reaped each child's host thread: a child's
/// thread-local teardown, which here needs a turn only the thread polling the
/// run grants, has finished, not merely begun.
fn returned_public_run_case(
    directory: &TestDirectory,
    executable: &str,
    image: &[u8],
    config: u64,
) {
    const COLLECTED: i32 = SameThreadScheduler::COLLECTED;
    const PENDING: i32 = SameThreadScheduler::PENDING;
    const ORPHAN: i32 = SameThreadScheduler::ORPHAN;
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.set_root_pid(DROPPED_RUN_ROOT).unwrap();
    backend
        .install_static_elf_with_context(
            image,
            &[executable, "exit-join"],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let lifetime = Arc::new(());
    let (turns, requests) = std::sync::mpsc::channel::<DroppedRunTurn>();
    let teardown = Arc::new(DroppedRunTeardown {
        lifetime: Arc::downgrade(&lifetime),
        state: Mutex::new((Default::default(), false)),
        changed: Condvar::new(),
        turns: Some(turns.clone()),
        finished: Mutex::new(Vec::new()),
    });
    let calls = Arc::new(Mutex::new(Vec::new()));
    DROPPED_RUN_CONFIGS.lock().unwrap().insert(
        config,
        DroppedRunConfig {
            turns,
            calls: calls.clone(),
            teardown: teardown.clone(),
        },
    );
    let mut scheduler = SameThreadScheduler {
        requests,
        point: None,
        held: Vec::new(),
        waiting: Vec::new(),
        released: false,
        withhold_teardown: false,
        withhold_worker: false,
        stopped: false,
    };
    let mut cx = std::task::Context::from_waker(Waker::noop());
    let completion = {
        let mut run =
            Box::pin(backend.run_static_elf_with_tool_completion::<DroppedRunTool>(config, true));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let std::task::Poll::Ready(completion) = run.as_mut().poll(&mut cx) {
                break completion;
            }
            scheduler.pump();
            assert!(
                std::time::Instant::now() < deadline,
                "the returning run never finished: calls={:?} reached={:?}",
                calls.lock().unwrap(),
                teardown.state.lock().unwrap().0,
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    };
    // Checked before this thread grants any further turn.
    assert_eq!(
        Arc::strong_count(&lifetime),
        1,
        "the run returned while a child's teardown still ran"
    );
    assert_eq!(
        teardown.state.lock().unwrap().0,
        [COLLECTED, PENDING, ORPHAN].into(),
        "every child's teardown ran"
    );
    DROPPED_RUN_CONFIGS.lock().unwrap().remove(&config);
    let completion = completion.expect("the returning run failed to start");
    let (status, _, _) = completion.result.expect("the returning run failed");
    assert_eq!(status, 7);
    let calls = std::mem::take(&mut *calls.lock().unwrap());
    let exits = calls
        .iter()
        .filter(|(_, number, _)| *number == Sysno::exit_group)
        .map(|&(pid, _, status)| (pid, status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        exits,
        [
            (DROPPED_RUN_ROOT, 7),
            (COLLECTED, 0),
            (PENDING, 0),
            (ORPHAN, 0)
        ]
        .into(),
        "{calls:?}"
    );
    drop(completion.global_state);
    drop(backend);
}

/// A dropped run's CLONE_VM worker whose thread-local teardown needs a turn
/// only the embedder's thread grants: the backend's drop returns without
/// joining it, and the run's reaper joins it once, after that teardown ends.
#[test]
fn dropped_public_run_hands_its_workers_to_the_reaper() {
    const TEST: &str = "dropped_public_run_hands_its_workers_to_the_reaper";
    const WORKER: i32 = SameThreadScheduler::WORKER;
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "dropped-worker-run",
        r#"
#include <pthread.h>
#include <unistd.h>

static void *worker(void *argument) {
  (void)getpid();
  return argument;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) return 10;
  (void)getpid();
  if (pthread_join(thread, 0) != 0) return 11;
  return 7;
}
"#,
    );
    let executable = executable.to_str().unwrap();
    let image = std::fs::read(executable).unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.set_root_pid(DROPPED_RUN_ROOT).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();

    let config = 5;
    let lifetime = Arc::new(());
    let (turns, requests) = std::sync::mpsc::channel::<DroppedRunTurn>();
    let teardown = Arc::new(DroppedRunTeardown {
        lifetime: Arc::downgrade(&lifetime),
        state: Mutex::new((Default::default(), false)),
        changed: Condvar::new(),
        turns: Some(turns.clone()),
        finished: Mutex::new(Vec::new()),
    });
    let calls = Arc::new(Mutex::new(Vec::new()));
    DROPPED_RUN_CONFIGS.lock().unwrap().insert(
        config,
        DroppedRunConfig {
            turns,
            calls: calls.clone(),
            teardown: teardown.clone(),
        },
    );
    let mut scheduler = SameThreadScheduler {
        requests,
        point: None,
        held: Vec::new(),
        waiting: Vec::new(),
        released: false,
        withhold_teardown: true,
        withhold_worker: true,
        stopped: false,
    };
    let reached = || teardown.state.lock().unwrap().0.clone();
    let finished = || teardown.finished.lock().unwrap().clone();
    let released = || {
        DROPPED_RUN_GLOBALS_RELEASED
            .lock()
            .unwrap()
            .contains(&config)
    };
    // Taken before the run starts its reaper.
    let baseline = host_tasks();
    let mut cx = std::task::Context::from_waker(Waker::noop());
    {
        let mut run =
            Box::pin(backend.run_static_elf_with_tool_completion::<DroppedRunTool>(config, true));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                run.as_mut().poll(&mut cx).is_pending(),
                "the run returned while its worker was held"
            );
            scheduler.pump();
            if scheduler
                .held
                .contains(&(DROPPED_RUN_ROOT, Some(Sysno::getpid)))
                && scheduler.held.contains(&(WORKER, Some(Sysno::getpid)))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "never reached the drop point: calls={:?} held={:?}",
                calls.lock().unwrap(),
                scheduler.held,
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        for _ in 0..10 {
            assert!(run.as_mut().poll(&mut cx).is_pending());
            scheduler.pump();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    DROPPED_RUN_CONFIGS.lock().unwrap().remove(&config);
    let assert_worker_held = |when: &str| {
        assert_eq!(
            Arc::strong_count(&lifetime),
            2,
            "the worker's thread-local state was released {when}"
        );
        assert!(finished().is_empty(), "the worker's teardown ended {when}");
        assert_eq!(
            reaper_tasks(&baseline).len(),
            1,
            "the dropped run's reaper exited {when}"
        );
    };
    assert_worker_held("with the dropped run");
    assert!(!released(), "GlobalState was released with the dropped run");

    // The thread that must grant the worker's turns drops the backend first.
    // A drop that joined the worker would never return.
    let dropping = std::time::Instant::now();
    drop(backend);
    assert!(
        dropping.elapsed() < std::time::Duration::from_secs(5),
        "the backend's drop waited {:?}",
        dropping.elapsed()
    );
    assert_worker_held("before its turn was granted");
    assert!(
        reached().is_empty(),
        "the worker began its teardown unprompted"
    );
    assert!(
        !released(),
        "GlobalState was released before the worker's turn"
    );

    // Its syscall turn lets the worker finish; its host thread then waits in
    // thread-local teardown for a turn only this thread grants.
    scheduler.released = true;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !scheduler.held.contains(&(WORKER, None)) {
        assert!(
            std::time::Instant::now() < deadline,
            "the worker never reached its teardown: held={:?} reached={:?}",
            scheduler.held,
            reached(),
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
        scheduler.pump();
    }
    for _ in 0..50 {
        scheduler.pump();
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_worker_held("while its teardown turn was withheld");
    assert_eq!(reached(), [WORKER].into());

    scheduler.withhold_teardown = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        scheduler.pump();
        // A reaper that joins the worker exits only after its teardown, which
        // sleeps before releasing its lifetime, has ended. One that detached
        // it exits while it sleeps.
        let reaping = !reaper_tasks(&baseline).is_empty();
        if !reaping {
            assert_eq!(
                (Arc::strong_count(&lifetime), finished()),
                (1, vec![WORKER]),
                "the reaper exited before the worker's teardown ended"
            );
        }
        let leftover = host_tasks()
            .into_iter()
            .filter(|(tid, _)| !baseline.contains_key(tid))
            .collect::<BTreeMap<_, _>>();
        // This test's teardown holds a turn sender, so the scheduler never
        // stops; each Tool's config and held thread shares the teardown.
        let state = (
            Arc::strong_count(&lifetime),
            released(),
            Arc::strong_count(&teardown),
            leftover,
        );
        if state.0 == 1 && state.1 && state.2 == 1 && state.3.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the dropped run's worker was never retired: \
             (lifetime, GlobalState released, teardown owners, host threads)={state:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(
        finished(),
        [WORKER],
        "the worker's teardown ran exactly once"
    );
    let calls = std::mem::take(&mut *calls.lock().unwrap());
    assert!(
        !calls
            .iter()
            .any(|&(_, number, _)| number == Sysno::exit_group),
        "the dropped root exited: {calls:?}"
    );
}

fn assert_refused(case: &str, entry: &str, refused: reverie_kvm::Result<()>) {
    assert!(
        matches!(refused, Err(reverie_kvm::Error::AbandonedRunNotRetired)),
        "{case}: the backend accepted {entry} while a dropped run was unretired: {refused:?}"
    );
}

/// The raw syscall-frame installers write guest memory, which a dropped run's
/// guest threads may still use, so each is refused before its first write.
fn assert_raw_requests_refused(case: &str, backend: &mut KvmBackend) {
    let request = reverie_kvm::SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]);
    let refused = backend.install_syscall(0x1000, 0x2000, request);
    assert_refused(case, "a syscall request", refused);
    let refused = backend.install_syscalls(0x1000, 0x2000, &[request, request]);
    assert_refused(case, "syscall requests", refused);
}

/// The public run entries that return a future or may unwind each own their
/// admission: a Tool run whose future the embedder drops, and a raw run whose
/// handler panics, each leave the backend abandoned until it drops, and the
/// run's reaper exits once the backend's drop hands it what the run left.
#[test]
fn every_abandoned_public_run_refuses_its_backend() {
    const TEST: &str = "every_abandoned_public_run_refuses_its_backend";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let request = reverie_kvm::SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]);
    let config = 6;
    let (turns, requests) = std::sync::mpsc::channel::<DroppedRunTurn>();
    DROPPED_RUN_CONFIGS.lock().unwrap().insert(
        config,
        DroppedRunConfig {
            turns,
            calls: Arc::new(Mutex::new(Vec::new())),
            teardown: Arc::new(DroppedRunTeardown {
                lifetime: Weak::new(),
                state: Mutex::new((Default::default(), false)),
                changed: Condvar::new(),
                turns: None,
                finished: Mutex::new(Vec::new()),
            }),
        },
    );
    let mut scheduler = SameThreadScheduler {
        requests,
        point: Some(RunDropPoint::Setup),
        held: Vec::new(),
        waiting: Vec::new(),
        released: false,
        withhold_teardown: false,
        withhold_worker: false,
        stopped: false,
    };
    let baseline = host_tasks();
    let assert_backend_refused = |case: &str, backend: &mut KvmBackend| {
        assert_refused(case, "guest memory", backend.memory().map(drop));
        assert_refused(case, "mutable guest memory", backend.memory_mut().map(drop));
        assert_refused(
            case,
            "a real-mode program",
            backend.install_real_mode_program(0x1000, &[0xf4]),
        );
        assert_raw_requests_refused(case, backend);
        assert_refused(case, "a raw run", backend.run(|_, _| 0));
        assert_eq!(
            reaper_tasks(&baseline).len(),
            1,
            "{case}: the abandoned run's reaper exited before its backend dropped"
        );
    };
    let assert_reaper_exits = |case: &str| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !reaper_tasks(&baseline).is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "{case}: the reaper outlived its backend's drop"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    };

    let case = "a dropped Tool run";
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.install_syscall(0x1000, 0x2000, request).unwrap();
    {
        let mut run = Box::pin(backend.run_with_tool::<DroppedRunTool, _>(
            config,
            |_: &reverie_kvm::SyscallRequest, _: &reverie_kvm::GuestMemory| 0,
        ));
        let mut cx = std::task::Context::from_waker(Waker::noop());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !scheduler.held.contains(&(DROPPED_RUN_SETUP, None)) {
            assert!(
                run.as_mut().poll(&mut cx).is_pending(),
                "{case}: the run returned while its GlobalState was held"
            );
            scheduler.pump();
            assert!(
                std::time::Instant::now() < deadline,
                "{case}: never reached its GlobalState: held={:?}",
                scheduler.held
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    assert_backend_refused(case, &mut backend);
    drop(backend);
    assert_reaper_exits(case);
    DROPPED_RUN_CONFIGS.lock().unwrap().remove(&config);

    let case = "an unwound raw run";
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend.install_syscall(0x1000, 0x2000, request).unwrap();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        backend.run(|_, _| panic!("a raw run's handler panicked"))
    }));
    assert!(
        unwound.is_err(),
        "{case}: the handler's panic was not propagated"
    );
    assert_backend_refused(case, &mut backend);
    drop(backend);
    assert_reaper_exits(case);
}

#[path = "support/natural_retirement.rs"]
mod natural_retirement;

#[path = "support/exit_descriptor_ordering.rs"]
mod exit_descriptor_ordering;
