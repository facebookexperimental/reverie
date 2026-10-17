/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::initial_stack_pointer` under ptrace: the post-exec callback runs at
//! the exec stop, before the new image's first instruction, and the backend
//! reports the stack pointer the image starts with. It is the address of
//! argc, followed by the argument pointers and their NULL, as the kernel laid
//! them out.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::sync::Mutex;

use reverie::Errno;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::MemoryAccess;

/// What the post-exec callback saw: the reported initial stack pointer, the
/// stack pointer in the registers, and the argument strings read from the
/// stack at the reported address.
static SEEN: Mutex<Option<Seen>> = Mutex::new(None);

/// The reported initial stack pointer, the registers' stack pointer, and the
/// argument strings.
type Seen = (Option<u64>, u64, Vec<String>);

#[derive(Debug, Default, Clone)]
struct StackTool;

/// The NUL-terminated string at `address`.
fn read_string<T: Guest<StackTool>>(guest: &T, address: u64) -> Result<String, Errno> {
    let mut bytes = Vec::new();
    loop {
        let at = Addr::<u8>::from_raw(address as usize + bytes.len()).ok_or(Errno::EFAULT)?;
        let byte: u8 = guest.memory().read_value(at)?;
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
}

#[reverie::tool]
impl Tool for StackTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        let reported = guest.initial_stack_pointer();
        let rsp = guest.regs().await.rsp;
        let mut arguments = Vec::new();
        if let Some(stack) = reported {
            let word = |at: u64| -> Result<u64, Errno> {
                guest
                    .memory()
                    .read_value(Addr::<u64>::from_raw(at as usize).ok_or(Errno::EFAULT)?)
            };
            let argc = word(stack)?;
            for index in 0..argc {
                arguments.push(read_string(guest, word(stack + 8 * (1 + index))?)?);
            }
            assert_eq!(word(stack + 8 * (1 + argc))?, 0, "argv ends with NULL");
        }
        *SEEN.lock().unwrap() = Some((reported, rsp, arguments));
        Ok(())
    }
}

#[test]
fn post_exec_reports_the_initial_stack_pointer_at_argc() {
    let (output, ()) =
        reverie_ptrace::testing::test_cmd::<StackTool>("/bin/true", &["first", "second"]).unwrap();
    assert!(output.status.success(), "{output:?}");
    let (reported, rsp, arguments) = SEEN.lock().unwrap().take().expect("post-exec ran");
    // At the exec stop no instruction of the image has run, so the registers
    // hold the same stack pointer.
    assert_eq!(reported, Some(rsp));
    assert_eq!(&arguments[1..], ["first", "second"]);
    assert!(arguments[0].ends_with("true"), "{arguments:?}");
}

/// Each post-exec callback of `ExecTool`'s run: the reported initial stack
/// pointer, the registers' stack pointer, and argv[0] read at the reported
/// address.
static EXECS: Mutex<Vec<(Option<u64>, u64, String)>> = Mutex::new(Vec::new());

#[derive(Debug, Default, Clone)]
struct ExecTool;

#[reverie::tool]
impl Tool for ExecTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        let reported = guest.initial_stack_pointer();
        let rsp = guest.regs().await.rsp;
        let argv0 = match reported {
            Some(stack) => {
                let pointer: u64 = guest
                    .memory()
                    .read_value(Addr::<u64>::from_raw(stack as usize + 8).ok_or(Errno::EFAULT)?)?;
                let mut bytes = Vec::new();
                loop {
                    let at = Addr::<u8>::from_raw(pointer as usize + bytes.len())
                        .ok_or(Errno::EFAULT)?;
                    let byte: u8 = guest.memory().read_value(at)?;
                    if byte == 0 {
                        break;
                    }
                    bytes.push(byte);
                }
                String::from_utf8_lossy(&bytes).into_owned()
            }
            None => String::new(),
        };
        EXECS.lock().unwrap().push((reported, rsp, argv0));
        Ok(())
    }
}

/// Each image reports its own initial stack pointer: a shell that execs
/// another program gives two post-exec callbacks, each at its own image's
/// argc, with that image's argv[0] there.
#[test]
fn each_exec_reports_its_own_initial_stack_pointer() {
    let (output, ()) =
        reverie_ptrace::testing::test_cmd::<ExecTool>("/bin/sh", &["-c", "exec /bin/true second"])
            .unwrap();
    assert!(output.status.success(), "{output:?}");
    let execs = std::mem::take(&mut *EXECS.lock().unwrap());
    assert_eq!(execs.len(), 2, "{execs:?}");
    for (reported, rsp, _) in &execs {
        assert_eq!(*reported, Some(*rsp), "{execs:?}");
    }
    assert!(execs[0].2.ends_with("sh"), "{execs:?}");
    assert_eq!(execs[1].2, "/bin/true", "{execs:?}");
}

/// The root image's initial stack pointer from its post-exec callback, and
/// the one each process reported at its first syscall after that callback.
static FORKS: Mutex<Forks> = Mutex::new((None, BTreeMap::new()));

/// See [`FORKS`].
type Forks = (Option<u64>, BTreeMap<i32, Option<u64>>);

#[derive(Debug, Default, Clone)]
struct ForkTool;

#[reverie::tool]
impl Tool for ForkTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        FORKS.lock().unwrap().0 = guest.initial_stack_pointer();
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        // Before the root's exec (its own execve) no image was observed.
        let reported = guest.initial_stack_pointer();
        {
            let mut forks = FORKS.lock().unwrap();
            if forks.0.is_some() {
                forks.1.entry(guest.pid().as_raw()).or_insert(reported);
            }
        }
        guest.tail_inject(syscall).await
    }
}

/// A forked process runs its creator's image, so it reports its creator's
/// initial stack pointer until it execs: a shell's subshell (a fork that
/// runs a builtin and exits) reports the shell's.
#[test]
fn a_forked_process_reports_its_creators_initial_stack_pointer() {
    let (output, ()) =
        reverie_ptrace::testing::test_cmd::<ForkTool>("/bin/sh", &["-c", "(:); :"]).unwrap();
    assert!(output.status.success(), "{output:?}");
    let (root, processes) = std::mem::take(&mut *FORKS.lock().unwrap());
    assert!(
        root.is_some(),
        "the post-exec callback saw no initial stack pointer"
    );
    assert!(
        processes.len() >= 2,
        "no forked process made a syscall: {processes:?}"
    );
    for (pid, reported) in &processes {
        assert_eq!(*reported, root, "process {pid}: {processes:?}");
    }
}
