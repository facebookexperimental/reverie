/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Actual startup effect and first-instruction evidence using a separate Tool.
//! Build its paired caller with the maintained producer before this test.

use std::fs;
use std::io::Read;
use std::io::Seek;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use reverie::Pid;
use reverie_dbt::CallerArtifact;
use reverie_dbt::DbtRunner;
use sha2::Digest;
use sha2::Sha256;
use tempfile::TempDir;

#[path = "../../tests/tool_fixtures/thread_start_tail_witness.rs"]
pub mod witness;

use witness::Frame;
use witness::Record;

const SELECTOR: &str = "startup_tail_native_entry_observes_effect_and_result";
const CHILD_MODE: &str = "REVERIE_DBT_STARTUP_TAIL_MODE";
const CHILD_ELF: &str = "REVERIE_DBT_STARTUP_TAIL_ELF";
const COMPLETED: &str = "STARTUP_TAIL_NATIVE_COMPLETED";
const SOURCE: &str = include_str!("fixtures/thread-start-tail-entry.S");

fn temporary_directory(prefix: &str) -> TempDir {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(root).unwrap();
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(root)
        .unwrap()
}

// Same owned process-group kill/reap pattern as caller_lifecycle_live. Each
// helper has a ten-second bound; an outer runtime guard bounds the whole test.
struct SupervisedChild(Option<Child>);
impl SupervisedChild {
    fn kill_group(&mut self) {
        if let Some(child) = &mut self.0 {
            let group = i32::try_from(child.id()).unwrap();
            // SAFETY: this child's pre_exec created its own process group.
            let _ = unsafe { libc::kill(-group, libc::SIGKILL) };
            let _ = child.kill();
        }
    }
    fn finish(mut self) -> Output {
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for SupervisedChild {
    fn drop(&mut self) {
        self.kill_group();
        if let Some(mut child) = self.0.take() {
            let _ = child.wait();
        }
    }
}

fn bounded(command: &mut Command) -> Output {
    // SAFETY: setpgid is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // File-backed capture avoids a helper blocking on full stderr while the
    // owner waits/reaps. Evidence is bounded and read before decoding.
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(root).unwrap();
    let mut stdout = tempfile::tempfile_in(root).unwrap();
    let mut stderr = tempfile::tempfile_in(root).unwrap();
    let mut child = SupervisedChild(Some(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone().unwrap()))
            .stderr(Stdio::from(stderr.try_clone().unwrap()))
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    let timed_out = loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            child.kill_group();
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut output = child.finish();
    for (file, bytes) in [
        (&mut stdout, &mut output.stdout),
        (&mut stderr, &mut output.stderr),
    ] {
        assert!(
            file.metadata().unwrap().len() <= 256 * 1024,
            "helper output exceeds bound"
        );
        file.rewind().unwrap();
        file.read_to_end(bytes).unwrap();
    }
    assert!(!timed_out, "startup-tail helper timed out: {output:?}");
    output
}

fn tool_output(command: &mut Command) -> Vec<u8> {
    eprintln!("startup-tail evidence argv={command:?}");
    let output = bounded(command);
    eprintln!(
        "startup-tail evidence status={:?} stdout={:?} stderr={:?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        output.stdout.len() <= 16 * 1024 && output.stderr.len() <= 16 * 1024,
        "evidence output exceeds fixture bound"
    );
    output.stdout
}

fn compile_guest(directory: &Path) -> PathBuf {
    let checked =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/thread-start-tail-entry.S");
    assert_eq!(fs::read_to_string(&checked).unwrap(), SOURCE);
    let elf = directory.join("guest");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = tool_output(
        Command::new(compiler)
            .args([
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(&elf)
            .arg(checked),
    );
    assert!(output.is_empty());
    elf
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn symbol(symbols: &str, name: &str) -> u64 {
    let matches: Vec<_> = symbols
        .lines()
        .filter_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            (parts.len() == 3 && parts[2] == name)
                .then(|| u64::from_str_radix(parts[0], 16).unwrap())
        })
        .collect();
    assert_eq!(matches.len(), 1, "exact symbol {name}");
    matches[0]
}

fn authenticate_guest(elf: &Path) -> (u64, u64) {
    let bytes = fs::read(elf).unwrap();
    assert!((64..=64 * 1024).contains(&bytes.len()));
    assert_eq!(&bytes[..6], b"\x7fELF\x02\x01");
    assert_eq!(
        u16::from_le_bytes(bytes[16..18].try_into().unwrap()),
        2,
        "ET_EXEC"
    );
    assert_eq!(u16::from_le_bytes(bytes[18..20].try_into().unwrap()), 62);
    let entry = word(&bytes, 24);
    let phoff = usize::try_from(word(&bytes, 32)).unwrap();
    let phsize = usize::from(u16::from_le_bytes(bytes[54..56].try_into().unwrap()));
    let phnum = usize::from(u16::from_le_bytes(bytes[56..58].try_into().unwrap()));
    assert_eq!(phsize, 56);
    assert!((1..=16).contains(&phnum));
    assert!(phoff.checked_add(phsize * phnum).unwrap() <= bytes.len());

    let symbols = String::from_utf8(tool_output(Command::new("nm").arg("-n").arg(elf))).unwrap();
    assert_eq!(entry, symbol(&symbols, "_start"));
    let address = symbol(&symbols, "witness_byte");
    let mut executable = 0;
    let mut writable = 0;
    for index in 0..phnum {
        let h = phoff + index * phsize;
        let kind = u32::from_le_bytes(bytes[h..h + 4].try_into().unwrap());
        assert_ne!(kind, 3, "no interpreter");
        if kind != 1 {
            continue;
        }
        let flags = u32::from_le_bytes(bytes[h + 4..h + 8].try_into().unwrap());
        assert_ne!(flags & 3, 3, "no writable executable segment");
        let start = word(&bytes, h + 16);
        let end = start.checked_add(word(&bytes, h + 40)).unwrap();
        if start <= entry && entry < end && flags & 1 != 0 {
            executable += 1;
        }
        if start <= address && address < end && flags & 2 != 0 {
            let offset = word(&bytes, h + 8).checked_add(address - start).unwrap();
            assert!(address - start < word(&bytes, h + 32), "file-backed byte");
            assert_eq!(bytes[usize::try_from(offset).unwrap()], 0);
            writable += 1;
        }
    }
    assert_eq!((executable, writable), (1, 1));
    let disassembly = String::from_utf8(tool_output(
        Command::new("objdump").args(["-d", "-w"]).arg(elf),
    ))
    .unwrap();
    let body = disassembly.split_once("<_start>:\n").unwrap().1;
    let instructions: Vec<_> = body
        .lines()
        .filter_map(|line| {
            let instruction = line.split('\t').nth(2)?;
            let mut words = instruction.split_whitespace();
            Some((words.next()?, words.next().unwrap_or("")))
        })
        .collect();
    let registers = [
        "%rax,", "%rbx,", "%rcx,", "%rdx,", "%rsi,", "%rdi,", "%rbp,", "%rsp,", "%r8,", "%r9,",
        "%r10,", "%r11,", "%r12,", "%r13,", "%r14,", "%r15,",
    ];
    for (index, register) in registers.iter().enumerate() {
        assert_eq!(instructions[index].0, "mov");
        assert!(
            instructions[index].1.starts_with(register),
            "capture {register}"
        );
        assert!(instructions[index].1.contains("(%rip)"));
    }
    assert!(instructions[16].0.starts_with("pushf"));
    assert!(instructions[17].0.starts_with("pop"));
    assert_eq!(
        instructions.iter().position(|row| row.0 == "syscall"),
        Some(24)
    );
    eprintln!(
        "startup-tail ELF image={} sha256={:x} bytes={} entry={entry:#x} writable_byte={address:#x}",
        elf.display(),
        Sha256::digest(&bytes),
        bytes.len()
    );
    (entry, address)
}

fn accepts(mode: u8, output: &Output, rows: &[(Pid, Record)], entry: u64) -> bool {
    if !output.status.success() || !output.stderr.is_empty() || rows.len() != 2 {
        return false;
    }
    let (from, (phase, pid, before, dropped)) = &rows[0];
    let (after_from, (after_phase, after_pid, after, after_dropped)) = &rows[1];
    if *phase != 0
        || *after_phase != 1
        || *dropped != 0
        || *pid <= 0
        || from.as_raw() != *pid
        || after_from != from
        || after_pid != pid
        || *after_dropped != u64::from(mode != witness::NO_EFFECT)
    {
        return false;
    }
    let expected_before: Frame = [
        0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, before[7], 0x108, 0x109, 0x10a, 0x10b,
        0x10c, 0x10d, 0x10e, 0x10f, 0x202, entry,
    ];
    if *before != expected_before || before[7] == 0 {
        return false;
    }
    let mut expected = *before;
    expected[0] = match mode {
        witness::GETPID => *pid as u64,
        witness::WRITE => 1,
        witness::BAD_FD => (-i64::from(libc::EBADF)) as u64,
        witness::NO_EFFECT => before[0],
        _ => return false,
    };
    if *after != expected {
        return false;
    }
    let bytes = if mode == witness::WRITE {
        let Some(frame) = output.stdout.strip_prefix(&[witness::BYTE]) else {
            return false;
        };
        frame
    } else {
        output.stdout.as_slice()
    };
    if bytes.len() != 144 {
        return false;
    }
    let words = bytes.as_chunks::<8>().0;
    words.iter().copied().map(u64::from_le_bytes).eq(expected)
}

fn run_native(mode: u8, elf: &Path) {
    let (entry, address) = authenticate_guest(elf);
    let executable = std::env::current_exe().unwrap();
    let deps = executable.parent().unwrap();
    assert_eq!(deps.file_name().unwrap(), "deps");
    let manifest = deps
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/thread-start-tail-witness/manifest.json");
    let artifact = CallerArtifact::load(&manifest).unwrap();
    let diagnostic = temporary_directory("startup-tail-diagnostics-");
    let log_path = diagnostic.path().join("native.log");
    let log = fs::File::create(&log_path).unwrap();
    let runner = DbtRunner::new(reverie_dbt::bundled_drrun_path(), artifact.native_client())
        .unwrap()
        .diagnostic_file(&log)
        .unwrap();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(runner.output_with_caller_tool::<witness::Witness>(
            &Command::new(elf),
            (mode, address, entry),
        ));
    let diagnostics = fs::read(log_path).unwrap();
    let (output, global) = result.unwrap_or_else(|error| {
        panic!(
            "startup-tail caller failed: {error}; output={:?}; diagnostics={diagnostics:?}",
            reverie_dbt::failed_run_output(&error)
        )
    });
    let rows = global.rows.into_inner().unwrap();
    eprintln!(
        "startup-tail native mode={mode} manifest={} status={:?} stdout={:?} stderr={:?} rows={rows:?} diagnostics={diagnostics:?}",
        manifest.display(),
        output.status,
        output.stdout,
        output.stderr
    );
    assert!(diagnostics.is_empty());
    assert!(
        accepts(mode, &output, &rows, entry),
        "actual startup witness"
    );
    if mode == witness::NO_EFFECT {
        assert!(!accepts(witness::WRITE, &output, &rows, entry));
        eprintln!("startup-tail control: no-effect succeeded; write predicate rejected=true");
    }
    if mode == witness::WRITE {
        let mut bad = output.clone();
        bad.stdout.remove(0);
        assert!(!accepts(mode, &bad, &rows, entry));
        bad = output.clone();
        bad.stdout.insert(0, witness::BYTE);
        assert!(!accepts(mode, &bad, &rows, entry));
        bad = output.clone();
        bad.stdout[1] ^= 1;
        assert!(!accepts(mode, &bad, &rows, entry));
        let mut bad_rows = rows.clone();
        bad_rows.reverse();
        assert!(!accepts(mode, &output, &bad_rows, entry));
        bad_rows = rows.clone();
        bad_rows[1].0 = Pid::from_raw(rows[0].0.as_raw() + 1);
        assert!(!accepts(mode, &output, &bad_rows, entry));
        bad_rows = rows.clone();
        bad_rows[1].1.3 = 0;
        assert!(!accepts(mode, &output, &bad_rows, entry));
        assert!(!accepts(mode, &output, &rows[..1], entry));
        assert!(!accepts(mode, &output, &rows, entry + 1));
        use std::os::unix::process::ExitStatusExt;
        bad = output.clone();
        bad.status = std::process::ExitStatus::from_raw(1 << 8);
        assert!(!accepts(mode, &bad, &rows, entry));
        eprintln!("startup-tail copied-record controls: 9 rejected (not guest executions)");
    }
}

#[test]
fn startup_tail_native_entry_observes_effect_and_result() {
    if let Some(mode) = std::env::var_os(CHILD_MODE) {
        let mode: u8 = mode.to_str().unwrap().parse().unwrap();
        assert!(mode <= witness::NO_EFFECT);
        let elf = PathBuf::from(std::env::var_os(CHILD_ELF).unwrap());
        run_native(mode, &elf);
        println!("{COMPLETED}:{mode}");
        return;
    }
    assert!(std::env::var_os(CHILD_ELF).is_none());
    let directory = temporary_directory("startup-tail-entry-");
    let elf = compile_guest(directory.path());
    let _ = authenticate_guest(&elf);
    for mode in [
        witness::GETPID,
        witness::WRITE,
        witness::BAD_FD,
        witness::NO_EFFECT,
    ] {
        let output = bounded(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", SELECTOR, "--nocapture", "--test-threads=1"])
                .env(CHILD_MODE, mode.to_string())
                .env(CHILD_ELF, &elf),
        );
        eprintln!(
            "startup-tail helper mode={mode} status={:?} stdout={:?} stderr={:?}",
            output.status, output.stdout, output.stderr
        );
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.matches("test result: ok. 1 passed;").count(), 1);
        assert_eq!(stdout.matches(&format!("{COMPLETED}:{mode}\n")).count(), 1);
    }
}
