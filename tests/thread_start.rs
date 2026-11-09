/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(not(sanitized))]

#[path = "support/thread_start_guest.rs"]
mod thread_start_guest;
#[path = "tool_fixtures/thread_start_tail.rs"]
mod thread_start_tail_tool;
#[path = "tool_fixtures/thread_start_tail_witness.rs"]
mod thread_start_tail_witness;
#[path = "tool_fixtures/thread_start.rs"]
mod thread_start_tool;

use std::sync::atomic::Ordering;

use thread_start_tool::TestTool;

#[test]
fn thread_start_inject() {
    let state = reverie_ptrace::testing::check_fn::<TestTool, _>(thread_start_guest::guest);
    let observed = state.observed.load(Ordering::SeqCst);
    eprintln!("thread-start function: observed={observed}");
    assert!(observed);

    rust_command_test();
}

#[test]
fn thread_start_tail_inject() {
    use thread_start_tail_tool::TestTool;

    reverie_ptrace::testing::check_fn::<TestTool, _>(|| {});
}

fn assert_command_output(
    label: &str,
    output: &reverie::process::Output,
    state: &thread_start_tool::StartupObserved,
) {
    let observed = state.observed.load(Ordering::SeqCst);
    eprintln!(
        "thread-start Rust command {label}: status={:?} stdout={:02x?} stderr={:02x?} observed={observed}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(observed);
}

fn rust_command_test() {
    let program = env!("CARGO_BIN_EXE_thread-start-rust-command-guest");
    eprintln!("thread-start Rust command image={program}");

    let native = std::process::Command::new(program).output().unwrap();
    eprintln!(
        "thread-start Rust command native: status={:?} stdout={:02x?} stderr={:02x?}",
        native.status, native.stdout, native.stderr,
    );
    assert_eq!(native.status.code(), Some(0));
    assert!(native.stdout.is_empty());
    assert!(native.stderr.is_empty());

    let (output, state) =
        reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], ()).unwrap();
    assert_command_output("ptrace", &output, &state);
}

#[test]
fn rust_thread_start_tail_command() {
    use thread_start_tail_tool::TestTool;

    let program = env!("CARGO_BIN_EXE_thread-start-rust-command-guest");
    eprintln!("thread-start tail Rust command image={program}");
    let (output, ()) =
        reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], ()).unwrap();
    eprintln!(
        "thread-start tail Rust command ptrace: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

struct ReturningRun {
    output: reverie::process::Output,
    rows: Vec<(reverie::Pid, thread_start_tail_witness::ReturningRecord)>,
}

fn returning_output(
    backend: &str,
    mode: u8,
    output: reverie::process::Output,
    state: thread_start_tail_witness::Witness,
) -> ReturningRun {
    // Keep the actual streams and every record available even if a later frame
    // assertion fails. In particular, an errno may prevent the launcher's exec.
    eprintln!(
        "returning-injection {backend} mode={mode}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    let rows = state.returning_rows.into_inner().unwrap();
    let legacy = state.rows.into_inner().unwrap();
    for (index, (sender, record)) in rows.iter().enumerate() {
        let (phase, kind, ordinal, call_ordinal, pid, tid, call, frames, byte) = record;
        let syscall = call.map(|(syscall, _)| syscall as usize);
        let result = call.map(|(_, result)| result.map_err(reverie::Errno::into_raw));
        let before = frames.map(|(before, _)| before);
        let after = frames.map(|(_, after)| after);
        eprintln!(
            "returning-injection {backend} mode={mode} record[{index}] sender={} callback={phase} kind={kind} ordinal={ordinal} call_ordinal={call_ordinal:?} pid={} tid={} syscall={syscall:?} result={result:?} before={before:?} after={after:?} byte={byte:?}",
            sender.as_raw(),
            pid.as_raw(),
            tid.as_raw(),
        );
    }
    eprintln!(
        "returning-injection {backend} mode={mode}: rows={} legacy_rows={}",
        rows.len(),
        legacy.len(),
    );
    assert!(
        legacy.is_empty(),
        "returning mode entered the legacy witness"
    );
    ReturningRun { output, rows }
}

fn ptrace_returning(mode: u8) -> ReturningRun {
    eprintln!("returning-injection ptrace image=/bin/true mode={mode}");
    let (output, state) = reverie_test_support::test_cmd_with_config::<
        thread_start_tail_witness::TestTool,
    >("/bin/true", &[], (mode, 0, 0))
    .unwrap();
    returning_output("ptrace", mode, output, state)
}

fn returning_order(mode: u8) -> Vec<(u8, u8, Option<reverie::syscalls::Sysno>)> {
    use reverie::syscalls::Sysno;
    use thread_start_tail_witness::*;

    assert!((START_GETPID..=POST_NO_EFFECT).contains(&mode));
    let selected = if matches!(mode, POST_SEQUENCE | POST_NO_EFFECT) {
        POST_EXEC
    } else {
        STARTUP
    };
    let mut order = Vec::new();
    for phase in [STARTUP, POST_EXEC] {
        order.push((phase, BEGIN, None));
        if phase == selected {
            order.push((
                phase,
                CALL,
                Some(if mode == START_ERRNO {
                    Sysno::close
                } else {
                    Sysno::getpid
                }),
            ));
            if matches!(
                mode,
                START_SEQUENCE | POST_SEQUENCE | START_NO_EFFECT | POST_NO_EFFECT
            ) {
                order.push((phase, MUTATION, None));
                order.push((phase, CALL, Some(Sysno::close)));
                if matches!(mode, START_SEQUENCE | POST_SEQUENCE) {
                    order.push((phase, CALL, Some(Sysno::write)));
                }
            }
        }
        order.push((phase, END, None));
    }
    order
}

fn assert_returning_byte(
    byte: thread_start_tail_witness::ByteRecord,
    frame: &thread_start_tail_witness::ReturningFrame,
) {
    let (address, original, staged, post_call, restored) = byte;
    assert_eq!(Some(address), frame[19].checked_sub(128 + 16));
    assert_ne!(address, 0);
    assert_eq!(staged, thread_start_tail_witness::BYTE);
    assert_eq!(post_call, staged);
    assert_eq!(
        restored, original,
        "returning witness did not restore its byte"
    );
}

fn assert_returning_records(mode: u8, run: &ReturningRun) {
    use reverie::syscalls::Errno;
    use reverie::syscalls::Sysno;
    use thread_start_tail_witness::*;

    const FIELDS: [&str; 27] = [
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx",
        "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds",
        "es", "fs", "gs",
    ];
    let order = returning_order(mode);
    let selected = if matches!(mode, POST_SEQUENCE | POST_NO_EFFECT) {
        POST_EXEC
    } else {
        STARTUP
    };
    let selected_end = order
        .iter()
        .position(|&(phase, kind, _)| phase == selected && kind == END)
        .unwrap()
        + 1;
    // A real baseline frame defect can prevent exec. Require the complete
    // selected callback prefix before allowing its named frame failure; missing
    // actual call evidence is never an intended RED.
    assert!(
        run.rows.len() == selected_end || run.rows.len() == order.len(),
        "incomplete returning callback records"
    );
    let first = &run.rows[0].1;
    let (pid, tid) = (first.4, first.5);
    assert!(pid.as_raw() > 0);
    assert_eq!(pid, tid, "ordinary witness must be the initial thread");
    let mut call_ordinal = 0;
    for (index, ((sender, record), &(phase, kind, syscall))) in
        run.rows.iter().zip(&order).enumerate()
    {
        assert_eq!((*sender, record.4, record.5), (pid, pid, tid));
        assert_eq!(
            (record.0, record.1, usize::from(record.2)),
            (phase, kind, index)
        );
        match syscall {
            Some(syscall) => {
                assert_eq!(record.3, Some(call_ordinal));
                call_ordinal += 1;
                let result = match syscall {
                    Sysno::getpid => Ok(i64::from(pid.as_raw())),
                    Sysno::close => Err(Errno::EBADF),
                    Sysno::write => Ok(1),
                    _ => unreachable!(),
                };
                assert_eq!(
                    record.6,
                    Some((syscall, result)),
                    "returning-injection actual kernel result"
                );
                let (before, _) = record.7.expect("missing actual call frames");
                if syscall == Sysno::write {
                    assert_returning_byte(record.8.expect("missing Write byte evidence"), &before);
                } else {
                    assert!(record.8.is_none());
                }
                eprintln!(
                    "returning-injection result accepted: callback={phase} call={} syscall={} result={:?}",
                    record.3.unwrap(),
                    syscall as usize,
                    result.map_err(reverie::Errno::into_raw)
                );
            }
            None => {
                assert!(record.3.is_none());
                assert!(record.6.is_none());
                if kind == MUTATION {
                    assert!(record.7.is_some());
                    assert!(record.8.is_none());
                } else if phase == selected
                    && kind == END
                    && matches!(mode, START_NO_EFFECT | POST_NO_EFFECT)
                {
                    let (before, after) = record.7.expect("missing NoEffect frames");
                    assert_eq!(before, after, "NoEffect changed the register frame");
                    assert_returning_byte(
                        record.8.expect("missing NoEffect byte evidence"),
                        &before,
                    );
                } else {
                    assert!(record.7.is_none());
                    assert!(record.8.is_none());
                }
            }
        }
    }
    // Compare all fields, including TLS/segment state, before final status and
    // row-count checks. Getpid, Close and Write have no segment side effects.
    for (index, (_, record)) in run.rows.iter().enumerate() {
        if record.1 == CALL {
            let (before, after) = record.7.unwrap();
            let differences: Vec<_> = FIELDS
                .iter()
                .enumerate()
                .filter_map(|(field, name)| (before[field] != after[field]).then_some(*name))
                .collect();
            assert_eq!(
                after,
                before,
                "returning-injection frame mismatch: callback={} call={} syscall={} fields={differences:?}",
                record.0,
                record.3.unwrap(),
                record.6.unwrap().0 as usize
            );
        } else if record.1 == MUTATION {
            let (before, after) = record.7.unwrap();
            assert_eq!(before, run.rows[index - 1].1.7.unwrap().1);
            let mut expected = before;
            expected[10] = if before[10] == 0x5a5a_0101 {
                0x5a5a_0102
            } else {
                0x5a5a_0101
            };
            assert_eq!(after, expected, "explicit Tool RAX write was not retained");
            assert_eq!(
                run.rows[index + 1].1.7.unwrap().0,
                after,
                "next call did not snapshot the Tool write"
            );
        }
    }
    assert_eq!(
        run.rows.len(),
        order.len(),
        "post_exec returning witness UNREACHED"
    );
}

fn assert_returning_completion(run: &ReturningRun, stdout: &[u8]) {
    assert_eq!(run.output.status, reverie::ExitStatus::Exited(0));
    assert_eq!(run.output.stdout, stdout);
    assert!(run.output.stderr.is_empty());
}

fn full_returning_effect(run: &ReturningRun) -> bool {
    use reverie::syscalls::Sysno;
    use thread_start_tail_witness::*;

    // Both the positive and the real successful NoEffect route use this exact
    // predicate, after validating their complete result/frame/cleanup records.
    let writes: Vec<_> = run
        .rows
        .iter()
        .filter(|(_, row)| row.6.is_some_and(|(syscall, _)| syscall == Sysno::write))
        .collect();
    run.output.status == reverie::ExitStatus::Exited(0)
        && run.output.stdout == [BYTE]
        && run.output.stderr.is_empty()
        && run.rows.len() == 8
        && writes.len() == 1
        && writes[0].1.1 == CALL
        && writes[0].1.3 == Some(2)
        && writes[0].1.6 == Some((Sysno::write, Ok(1)))
        && writes[0].1.7.is_some_and(|(before, after)| before == after)
        && writes[0]
            .1
            .8
            .is_some_and(|(_, original, staged, post_call, restored)| {
                staged == BYTE && post_call == BYTE && restored == original
            })
}

fn returning_single(run: fn(u8) -> ReturningRun, mode: u8) {
    let actual = run(mode);
    assert_returning_records(mode, &actual);
    assert_returning_completion(&actual, &[]);
    eprintln!("returning-injection mode={mode}: complete frame/result predicate accepted");
}

fn returning_sequence(run: fn(u8) -> ReturningRun, mode: u8, no_effect: u8) {
    let actual = run(mode);
    assert_returning_records(mode, &actual);
    assert_returning_completion(&actual, &[thread_start_tail_witness::BYTE]);
    assert!(
        full_returning_effect(&actual),
        "returning-injection full effect predicate"
    );
    eprintln!("returning-injection mode={mode}: full effect predicate accepted");

    let control = run(no_effect);
    assert_returning_records(no_effect, &control);
    assert_returning_completion(&control, &[]);
    assert!(
        !full_returning_effect(&control),
        "successful NoEffect satisfied the full effect predicate"
    );
    eprintln!(
        "returning-injection mode={no_effect}: NoEffect own-positive accepted; full effect predicate rejected"
    );
}

#[test]
fn ptrace_returning_startup_getpid_preserves_frame() {
    returning_single(ptrace_returning, thread_start_tail_witness::START_GETPID);
}

#[test]
fn ptrace_returning_startup_errno_preserves_frame() {
    returning_single(ptrace_returning, thread_start_tail_witness::START_ERRNO);
}

#[test]
fn ptrace_returning_startup_mutation_and_effect() {
    returning_sequence(
        ptrace_returning,
        thread_start_tail_witness::START_SEQUENCE,
        thread_start_tail_witness::START_NO_EFFECT,
    );
}

#[test]
fn ptrace_returning_post_exec_preserves_frame_and_effect() {
    returning_sequence(
        ptrace_returning,
        thread_start_tail_witness::POST_SEQUENCE,
        thread_start_tail_witness::POST_NO_EFFECT,
    );
}

/// The first post-exec call's register view before injection is a native ELF
/// execve's: rax 0 and orig_rax 59.
#[test]
fn ptrace_post_exec_orig_rax_before_injection() {
    use thread_start_tail_witness::*;

    let run = ptrace_returning(POST_SEQUENCE);
    assert_returning_records(POST_SEQUENCE, &run);
    assert_returning_completion(&run, &[BYTE]);
    assert!(
        full_returning_effect(&run),
        "returning-injection full effect predicate"
    );
    let mut first_calls = run
        .rows
        .iter()
        .filter(|(_, row)| row.0 == POST_EXEC && row.1 == CALL && row.3 == Some(0));
    let (_, record) = first_calls.next().expect("missing first post_exec call");
    assert!(
        first_calls.next().is_none(),
        "duplicate first post_exec call"
    );
    let frame = record.7.expect("missing first post_exec call frames").0;
    let values = (frame[10], frame[15]);
    eprintln!(
        "post-exec-orig-rax ptrace image=/bin/true mode={POST_SEQUENCE} callback={POST_EXEC} call_ordinal=0 frame=before rax={} orig_rax={}",
        values.0, values.1,
    );
    assert_eq!(values, (0, 59), "native ELF post_exec register view");
}
