/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A task's `comm`, `stat` and `status` files, rendered from plain
//! caller-supplied facts.
//!
//! The rules are Linux 6.17's (`fs/proc/array.c` `do_task_stat` and
//! `proc_pid_status`, `fs/exec.c` `begin_new_exec`, `kernel/sys.c`
//! `PR_SET_NAME`, `fs/proc/base.c` `comm_show`). Every decision a line
//! embodies — state letter, flags word, code-bound hiding, which
//! optional lines answer — is the caller's, passed in as decided
//! fields; this module only formats.

/// Linux's `TASK_COMM_LEN`: a task's name and its terminating NUL.
pub const TASK_COMM_LEN: usize = 16;

/// `PF_EXITING` (`include/linux/sched.h`): the task is exiting, which a
/// zombie's `stat` shows in its flags (`do_exit` sets it in
/// `exit_signals`).
pub const PF_EXITING: u64 = 0x0000_0004;

/// `PF_FORKNOEXEC`: the task was forked and has not exec'd.
/// `copy_process` sets it on every new task, threads included
/// (`kernel/fork.c`), and only the task that execs loses it
/// (`begin_new_exec`).
pub const PF_FORKNOEXEC: u64 = 0x0000_0040;

/// A task's name, Linux's `task_struct::comm`: at most 15 bytes, none of
/// them NUL, padded with NULs to [`TASK_COMM_LEN`], as `__set_task_comm`
/// stores it (`strscpy_pad`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CommName(pub [u8; TASK_COMM_LEN]);

impl CommName {
    /// The name Linux stores from `bytes`: the bytes before the first
    /// NUL, at most 15 (`strscpy_pad` into `TASK_COMM_LEN`).
    /// `PR_SET_NAME` reads at most 15 bytes of the caller's string
    /// through its NUL (`strncpy_from_user` with a limit of
    /// `sizeof(me->comm) - 1`), and the kernel's `comm` file holds the
    /// name and a newline.
    pub fn new(bytes: &[u8]) -> Self {
        let length = bytes
            .iter()
            .take(TASK_COMM_LEN - 1)
            .position(|byte| *byte == 0)
            .unwrap_or_else(|| bytes.len().min(TASK_COMM_LEN - 1));
        let mut name = [0; TASK_COMM_LEN];
        name[..length].copy_from_slice(&bytes[..length]);
        Self(name)
    }

    /// The name an exec of `filename` stores: its last component
    /// (`kbasename(bprm->filename)`), cut as [`Self::new`] cuts it. A
    /// new image's `AT_EXECFN` points at a copy of `bprm->filename`
    /// (`create_elf_tables`), so its last component is the name the
    /// exec gave: the path as given for a direct, symbolic-link or
    /// script exec. Only `execveat(fd, "", AT_EMPTY_PATH)` is named
    /// otherwise in Linux 6.14 and later (by the file's dentry,
    /// `comm_from_dentry`).
    pub fn of_exec_filename(filename: &[u8]) -> Self {
        let start = filename
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(0, |slash| slash + 1);
        Self::new(&filename[start..])
    }

    /// The name as the kernel's `/proc/<pid>/comm` holds it: the bytes
    /// before its final newline (`comm_show` prints the name and `\n`).
    pub fn from_comm_file(bytes: &[u8]) -> Self {
        Self::new(bytes.strip_suffix(b"\n").unwrap_or(bytes))
    }

    /// The name's bytes, without the terminating NUL.
    pub fn as_bytes(&self) -> &[u8] {
        let length = self
            .0
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(TASK_COMM_LEN);
        &self.0[..length]
    }
}

/// A task's `comm` file: its name as `proc_task_name` prints it raw,
/// through its first NUL, and a newline.
pub fn render_comm(name: &[u8]) -> Vec<u8> {
    let mut line = name.to_vec();
    line.push(b'\n');
    line
}

/// `stat`'s state letter for a task: `R` for the reader itself, which
/// runs while it reads; `Z` for a zombie; `S` for every other task.
pub fn stat_state(exited: bool, reader_is_task: bool) -> char {
    if exited {
        'Z'
    } else if reader_is_task {
        'R'
    } else {
        'S'
    }
}

/// `stat`'s `flags` (field 9) from the two modelled bits:
/// `PF_FORKNOEXEC` for a task forked without an exec since (every
/// thread that does not lead, and a leader by the caller's wait model),
/// and `PF_EXITING` for a zombie.
pub fn stat_flags(leads: bool, forked_without_exec: bool, exited: bool) -> u64 {
    let mut flags = 0;
    if !leads || forked_without_exec {
        flags |= PF_FORKNOEXEC;
    }
    if exited {
        flags |= PF_EXITING;
    }
    flags
}

/// Every decided value one rendering of a `stat` file prints. CPU times
/// arrive already in clock ticks; the code-bound and exit-code hiding
/// decisions arrive already made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatFields<'a> {
    /// Field 1: the number the file's path names its task by.
    pub pid: i32,
    /// Field 2: the task's name, raw bytes (printed in parentheses).
    pub comm: &'a [u8],
    /// Field 3: the state letter (see [`stat_state`]).
    pub state: char,
    /// Field 4: the process's parent.
    pub ppid: i32,
    /// Field 5: the process group.
    pub process_group: i32,
    /// Field 6: the session.
    pub session: i32,
    /// Field 9: the flags word (see [`stat_flags`]).
    pub flags: u64,
    /// Field 14: user CPU time in clock ticks.
    pub user_ticks: u64,
    /// Field 15: system CPU time in clock ticks.
    pub system_ticks: u64,
    /// Field 16: reaped children's user CPU time in clock ticks.
    pub children_user_ticks: u64,
    /// Field 17: reaped children's system CPU time in clock ticks.
    pub children_system_ticks: u64,
    /// Field 20: the process's task count.
    pub num_threads: i32,
    /// Field 25: the process's `RLIMIT_RSS` soft limit.
    pub rsslim: u64,
    /// Fields 26-27: print the code bounds as 1 (a reader that may not
    /// trace the task, which has memory) instead of 0.
    pub hide_code_bounds: bool,
    /// Field 38: the leader's exit signal, -1 for another thread.
    pub exit_signal: i32,
    /// Field 39: the virtual CPU the task runs on.
    pub processor: u32,
    /// Field 52: a zombie's exit code as the reader may see it (the
    /// caller already zeroes it for an unpermitted reader).
    pub exit_code: i32,
}

/// A task's `stat` line in Linux's 52 fields (`do_task_stat`,
/// `fs/proc/array.c`): the values of [`StatFields`] at their fields,
/// 0 at every other — the fault counts (10-13), guest time (43, 44),
/// `itrealvalue` (21, always 0 in Linux), start time (22), memory
/// sizes and addresses (23, 24, 28-30, 45-51), the four obsolete
/// signal words (31-34), `wchan` (35), `nswap`/`cnswap` (36, 37),
/// block-I/O delay (42), and priority/nice/rt_priority/policy fixed
/// at 20/0/0/0 with no controlling terminal (7, 8: 0, -1).
pub fn render_stat(fields: &StatFields<'_>) -> Vec<u8> {
    let mut line = format!("{} (", fields.pid).into_bytes();
    line.extend_from_slice(fields.comm);
    let code_bound = if fields.hide_code_bounds { "1" } else { "0" };
    let rest: [String; 50] = [
        // 3 state
        fields.state.to_string(),
        // 4 ppid, 5 pgrp, 6 session, 7 tty_nr, 8 tpgid
        fields.ppid.to_string(),
        fields.process_group.to_string(),
        fields.session.to_string(),
        "0".to_owned(),
        "-1".to_owned(),
        // 9 flags
        fields.flags.to_string(),
        // 10 minflt .. 13 cmajflt
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        // 14 utime .. 17 cstime
        fields.user_ticks.to_string(),
        fields.system_ticks.to_string(),
        fields.children_user_ticks.to_string(),
        fields.children_system_ticks.to_string(),
        // 18 priority, 19 nice, 20 num_threads
        "20".to_owned(),
        "0".to_owned(),
        fields.num_threads.to_string(),
        // 21 itrealvalue, 22 starttime, 23 vsize, 24 rss
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        // 25 rsslim
        fields.rsslim.to_string(),
        // 26 startcode, 27 endcode, 28 startstack .. 37 cnswap
        code_bound.to_owned(),
        code_bound.to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        // 38 exit_signal, 39 processor, 40 rt_priority, 41 policy
        fields.exit_signal.to_string(),
        fields.processor.to_string(),
        "0".to_owned(),
        "0".to_owned(),
        // 42 delayacct_blkio_ticks .. 51 env_end
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        // 52 exit_code
        fields.exit_code.to_string(),
    ];
    line.extend_from_slice(b") ");
    line.extend_from_slice(rest.join(" ").as_bytes());
    line.push(b'\n');
    line
}

/// A task's five signal sets as its `status` shows them (`task_sig`,
/// `fs/proc/array.c`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusSignals {
    pub pending: u64,
    pub shared_pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
}

/// A task's capability sets as its `status` shows them (`task_cap`,
/// `fs/proc/array.c`), each where its source answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusCapabilities {
    /// `CapInh`, `CapPrm` and `CapEff`.
    pub inheritable_permitted_effective: Option<(u64, u64, u64)>,
    /// `CapBnd`.
    pub bounding: Option<u64>,
    /// `CapAmb`.
    pub ambient: Option<u64>,
}

/// Every decided value one rendering of a `status` file prints. Lines
/// whose source does not answer for the task are absent by
/// construction: the memory block appears only with `has_memory`, the
/// signal lines only with `signals`, each capability line only with
/// its `Some`. Lines this struct has no field for are never printed;
/// which those are is the caller's policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusFields<'a> {
    /// The task's name, raw bytes (escaped as Linux escapes it).
    pub comm: &'a [u8],
    /// The state letter (see [`stat_state`]).
    pub state: char,
    /// The thread group ID (`Tgid`, `NStgid`).
    pub tgid: i32,
    /// The task ID (`Pid`, `NSpid`).
    pub pid: i32,
    /// The parent process ID (`PPid`).
    pub ppid: i32,
    /// Real, effective, saved-set and filesystem user IDs (`Uid`).
    pub uid: [u32; 4],
    /// Real, effective, saved-set and filesystem group IDs (`Gid`).
    pub gid: [u32; 4],
    /// Supplementary groups (`Groups`), space-separated with a
    /// trailing space, as Linux prints them.
    pub groups: &'a [u32],
    /// The process group (`NSpgid`).
    pub process_group: i32,
    /// The session (`NSsid`).
    pub session: i32,
    /// The task has memory (not a zombie): print the zeroed memory
    /// block.
    pub has_memory: bool,
    /// The process's task count (`Threads`).
    pub num_threads: i32,
    /// The signal sets, `None` where no source reports them.
    pub signals: Option<StatusSignals>,
    /// The capability sets.
    pub capabilities: StatusCapabilities,
    /// `Cpus_allowed` mask and `Cpus_allowed_list`, already rendered.
    pub cpus_allowed: (String, String),
}

/// `status`'s `State` line for `stat`'s state letter
/// (`task_state_array`, `fs/proc/array.c`).
fn state_name(letter: char) -> &'static str {
    match letter {
        'R' => "R (running)",
        'Z' => "Z (zombie)",
        _ => "S (sleeping)",
    }
}

/// The memory lines Linux prints for a task with an mm (`task_mem` and
/// `hugetlb_report_usage`), in its order.
const MEMORY_LINES: [&str; 16] = [
    "VmPeak",
    "VmSize",
    "VmLck",
    "VmPin",
    "VmHWM",
    "VmRSS",
    "RssAnon",
    "RssFile",
    "RssShmem",
    "VmData",
    "VmStk",
    "VmExe",
    "VmLib",
    "VmPTE",
    "VmSwap",
    "HugetlbPages",
];

/// A task's `status` in Linux's order (`proc_pid_status`,
/// `fs/proc/array.c`: `task_state`, `task_mem` with an mm, `task_sig`,
/// `task_cap`, `task_seccomp` lines absent here, `task_cpus_allowed`,
/// `cpuset_task_status_allowed`, `task_context_switch_counts`), with
/// each line's value from [`StatusFields`]. Context-switch counts and
/// the single-node `Mems_allowed` lines print as Linux's no-NUMA
/// kernel prints them (0, and node 0 alone).
pub fn render_status(fields: &StatusFields<'_>) -> Vec<u8> {
    let mut lines: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut line = |name: &'static str, value: String| lines.push((name, value.into_bytes()));
    line("State", state_name(fields.state).to_owned());
    line("Tgid", fields.tgid.to_string());
    line("Ngid", "0".to_owned());
    line("Pid", fields.pid.to_string());
    line("PPid", fields.ppid.to_string());
    line("TracerPid", "0".to_owned());
    line(
        "Uid",
        format!(
            "{}\t{}\t{}\t{}",
            fields.uid[0], fields.uid[1], fields.uid[2], fields.uid[3]
        ),
    );
    line(
        "Gid",
        format!(
            "{}\t{}\t{}\t{}",
            fields.gid[0], fields.gid[1], fields.gid[2], fields.gid[3]
        ),
    );
    // `task_state` separates the groups with spaces and ends the list
    // with one more, so no groups print as a lone space.
    let mut groups = fields
        .groups
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    groups.push(' ');
    line("Groups", groups);
    line("NStgid", fields.tgid.to_string());
    line("NSpid", fields.pid.to_string());
    line("NSpgid", fields.process_group.to_string());
    line("NSsid", fields.session.to_string());
    line("Kthread", "0".to_owned());
    if fields.has_memory {
        for name in MEMORY_LINES {
            line(name, format!("{:>8} kB", 0));
        }
    }
    line("Threads", fields.num_threads.to_string());
    if let Some(signals) = fields.signals {
        line("SigPnd", format!("{:016x}", signals.pending));
        line("ShdPnd", format!("{:016x}", signals.shared_pending));
        line("SigBlk", format!("{:016x}", signals.blocked));
        line("SigIgn", format!("{:016x}", signals.ignored));
        line("SigCgt", format!("{:016x}", signals.caught));
    }
    let capabilities = fields.capabilities;
    if let Some((inheritable, permitted, effective)) = capabilities.inheritable_permitted_effective
    {
        line("CapInh", format!("{inheritable:016x}"));
        line("CapPrm", format!("{permitted:016x}"));
        line("CapEff", format!("{effective:016x}"));
    }
    if let Some(bounding) = capabilities.bounding {
        line("CapBnd", format!("{bounding:016x}"));
    }
    if let Some(ambient) = capabilities.ambient {
        line("CapAmb", format!("{ambient:016x}"));
    }
    line("Cpus_allowed", fields.cpus_allowed.0.clone());
    line("Cpus_allowed_list", fields.cpus_allowed.1.clone());
    line("Mems_allowed", "1".to_owned());
    line("Mems_allowed_list", "0".to_owned());
    line("voluntary_ctxt_switches", "0".to_owned());
    line("nonvoluntary_ctxt_switches", "0".to_owned());

    let mut text = b"Name:\t".to_vec();
    text.extend_from_slice(&crate::escape_status_name(fields.comm));
    text.push(b'\n');
    for (name, value) in lines {
        text.extend_from_slice(name.as_bytes());
        text.extend_from_slice(b":\t");
        text.extend_from_slice(&value);
        text.push(b'\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_fields() -> StatFields<'static> {
        StatFields {
            pid: 7,
            comm: b"probe",
            state: stat_state(false, true),
            ppid: 3,
            process_group: 7,
            session: 3,
            flags: stat_flags(true, false, false),
            user_ticks: 0,
            system_ticks: 0,
            children_user_ticks: 0,
            children_system_ticks: 0,
            num_threads: 2,
            rsslim: u64::MAX,
            hide_code_bounds: false,
            exit_signal: 17,
            processor: 3,
            exit_code: 0,
        }
    }

    fn fields(line: &[u8]) -> (String, Vec<String>) {
        let text = String::from_utf8_lossy(line).into_owned();
        assert!(text.ends_with('\n'), "{text:?}");
        let open = text.find(" (").unwrap();
        let close = text.rfind(") ").unwrap();
        let comm = text[open + 2..close].to_owned();
        let mut fields = vec![text[..open].to_owned(), format!("({comm})")];
        fields.extend(text[close + 2..].split_whitespace().map(str::to_owned));
        (comm, fields)
    }

    /// The rendered line has Linux's 52 fields, in `do_task_stat`'s
    /// order, with the caller's values where it owns them and the
    /// documented fixed values elsewhere.
    #[test]
    fn stat_has_linuxs_52_fields_in_order() {
        let line = render_stat(&stat_fields());
        let (comm, fields) = fields(&line);
        assert_eq!(comm, "probe");
        assert_eq!(fields.len(), 52, "{fields:?}");
        let expected: [(usize, &str); 17] = [
            (1, "7"),
            (2, "(probe)"),
            (3, "R"),
            (4, "3"),
            (5, "7"),
            (6, "3"),
            (7, "0"),
            (8, "-1"),
            (9, "0"),
            (18, "20"),
            (19, "0"),
            (20, "2"),
            (25, "18446744073709551615"),
            (38, "17"),
            (39, "3"),
            (41, "0"),
            (52, "0"),
        ];
        for (field, value) in expected {
            assert_eq!(fields[field - 1], value, "field {field}");
        }
        let fixed: Vec<usize> = expected.iter().map(|(field, _)| *field).collect();
        for (index, value) in fields.iter().enumerate() {
            if !fixed.contains(&(index + 1)) {
                assert_eq!(value, "0", "field {} of {fields:?}", index + 1);
            }
        }
        assert_eq!(
            String::from_utf8(line).unwrap(),
            "7 (probe) R 3 7 3 0 -1 0 0 0 0 0 0 0 0 0 20 0 2 0 0 0 0 18446744073709551615 \
             0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        );
    }

    /// The CPU times print as given, already in clock ticks.
    #[test]
    fn stat_shows_the_cpu_times_in_clock_ticks() {
        let stat = StatFields {
            user_ticks: 123,
            system_ticks: 0,
            children_user_ticks: 2,
            children_system_ticks: 1,
            ..stat_fields()
        };
        let (_, fields) = fields(&render_stat(&stat));
        assert_eq!(fields[13..17], ["123", "0", "2", "1"], "{fields:?}");
    }

    /// A thread that does not lead shows exit signal -1 and
    /// `PF_FORKNOEXEC`, and a sibling's state is `S`; a zombie's is
    /// `Z`, with `PF_EXITING`.
    #[test]
    fn stat_of_a_sibling_thread_and_a_zombie() {
        let sibling = StatFields {
            pid: 8,
            comm: b"worker",
            state: stat_state(false, false),
            flags: stat_flags(false, false, false),
            rsslim: 4096,
            exit_signal: -1,
            ..stat_fields()
        };
        let (_, sibling_fields) = fields(&render_stat(&sibling));
        assert_eq!(sibling_fields.len(), 52);
        assert_eq!(sibling_fields[1], "(worker)");
        assert_eq!(sibling_fields[2], "S");
        assert_eq!(sibling_fields[8], PF_FORKNOEXEC.to_string());
        assert_eq!(sibling_fields[24], "4096");
        assert_eq!(sibling_fields[37], "-1");
        let zombie = StatFields {
            state: stat_state(true, false),
            flags: stat_flags(true, true, true),
            ..sibling
        };
        let (_, zombie_fields) = fields(&render_stat(&zombie));
        assert_eq!(zombie_fields[2], "Z");
        assert_eq!(zombie_fields[8], (PF_FORKNOEXEC | PF_EXITING).to_string());
    }

    /// The name is kept raw: a newline, a backslash, a byte that is not
    /// UTF-8 and a closing parenthesis are printed as they are
    /// (`proc_task_name(m, p, false)`), and a parser finds it between
    /// the first ` (` and the last `) `. The kernel's `comm` file's
    /// newline is not part of the name.
    #[test]
    fn comm_is_raw_in_stat() {
        let comm = CommName::from_comm_file(b"a)b\n\\\xff c\n");
        assert_eq!(comm.as_bytes(), b"a)b\n\\\xff c");
        let stat = StatFields {
            pid: 1,
            comm: comm.as_bytes(),
            ppid: 0,
            ..stat_fields()
        };
        let line = render_stat(&stat);
        assert!(line.starts_with(b"1 (a)b\n\\\xff c) R 0 "), "{line:?}");
        assert_eq!(CommName::from_comm_file(b"\n").as_bytes(), b"");
        assert_eq!(CommName::from_comm_file(b"x").as_bytes(), b"x");
    }

    /// Linux stores at most 15 bytes and stops at the first NUL
    /// (`strscpy_pad`).
    #[test]
    fn comm_is_cut_at_15_bytes_and_the_first_nul() {
        assert_eq!(
            CommName::new(b"0123456789abcdefghij").as_bytes(),
            b"0123456789abcde"
        );
        assert_eq!(CommName::new(b"w1\n").as_bytes(), b"w1\n");
        assert_eq!(CommName::new(b"ab\0cd").as_bytes(), b"ab");
        assert_eq!(CommName::new(b"").as_bytes(), b"");
        // A NUL at the 16th byte or later is past the cut.
        assert_eq!(
            CommName::new(b"0123456789abcdef\0").as_bytes(),
            b"0123456789abcde"
        );
    }

    /// An exec names the task by the last component of the path it was
    /// given (`AT_EXECFN`), cut to 15 bytes, as Linux does for a
    /// direct, a symbolic-link and a script exec.
    #[test]
    fn exec_names_the_task_by_the_paths_last_component() {
        let name = |path: &[u8]| CommName::of_exec_filename(path).as_bytes().to_vec();
        assert_eq!(name(b"/usr/bin/true"), b"true");
        assert_eq!(name(b"true"), b"true");
        assert_eq!(name(b"/proc/self/exe"), b"exe");
        assert_eq!(name(b"/dev/fd/3"), b"3");
        assert_eq!(name(b"sub/execat"), b"execat");
        assert_eq!(
            name(b"/tmp/a-very-long-symlink-name-xyz"),
            b"a-very-long-sym"
        );
    }

    /// A `comm` file is the name, raw, and a newline (`comm_show`).
    #[test]
    fn a_comm_file_is_the_name_and_a_newline() {
        assert_eq!(render_comm(CommName::new(b"probe").as_bytes()), b"probe\n");
        assert_eq!(
            render_comm(CommName::new(b"0123456789abcdefghij").as_bytes()),
            b"0123456789abcde\n"
        );
        assert_eq!(
            render_comm(CommName::new(b"a)b\n\\c").as_bytes()),
            b"a)b\n\\c\n"
        );
        assert_eq!(render_comm(CommName::new(b"").as_bytes()), b"\n");
        // What the kernel's file holds is the name back.
        let comm = CommName::new(b"w1\n");
        assert_eq!(
            CommName::from_comm_file(&render_comm(comm.as_bytes())),
            comm
        );
    }

    /// Code bounds print as 1 where the caller decided to hide them,
    /// the exit code as decided; a zombie has no memory, so its caller
    /// decides bounds 0 even when hiding.
    #[test]
    fn stat_hides_the_code_bounds_where_the_caller_decides() {
        let live = StatFields {
            pid: 8,
            ..stat_fields()
        };
        let (_, permitted) = fields(&render_stat(&live));
        assert_eq!(permitted[25..27], ["0", "0"]);
        let (_, refused) = fields(&render_stat(&StatFields {
            hide_code_bounds: true,
            ..live
        }));
        assert_eq!(refused[25..27], ["1", "1"]);
        let zombie = StatFields {
            state: stat_state(true, false),
            exit_code: 7 << 8,
            ..live
        };
        let (_, permitted) = fields(&render_stat(&zombie));
        assert_eq!(permitted[2], "Z");
        assert_eq!(permitted[25..27], ["0", "0"]);
        assert_eq!(permitted[51], "1792");
    }

    fn status_fields(exited: bool, reader_is_task: bool) -> StatusFields<'static> {
        StatusFields {
            comm: b"worker",
            state: stat_state(exited, reader_is_task),
            tgid: 7,
            pid: 9,
            ppid: 3,
            uid: [0; 4],
            gid: [0; 4],
            groups: &[0, 65534],
            process_group: 0,
            session: 0,
            has_memory: !exited,
            num_threads: 2,
            signals: Some(StatusSignals {
                pending: 0,
                shared_pending: 0x4000,
                blocked: 0x200,
                ignored: 0x8000_0800,
                caught: 0x1_0000_0000,
            }),
            capabilities: StatusCapabilities {
                inheritable_permitted_effective: Some((0, 0x1ff_ffff_ffff, 0x1ff_ffff_ffff)),
                bounding: None,
                ambient: None,
            },
            cpus_allowed: (
                "00000000,00000000,00000000,00000001".to_owned(),
                "0".to_owned(),
            ),
        }
    }

    fn names(text: &[u8]) -> Vec<String> {
        String::from_utf8(text.to_vec())
            .unwrap()
            .lines()
            .map(|line| line.split(':').next().unwrap().to_owned())
            .collect()
    }

    /// A live thread's status has Linux's lines in Linux's order, the
    /// memory block at `0 kB` printed as `task_mem` pads it.
    #[test]
    fn a_live_threads_status_has_linuxs_lines_in_its_order() {
        let text = String::from_utf8(render_status(&status_fields(false, false))).unwrap();
        let expected = "Name:\tworker\n\
            State:\tS (sleeping)\n\
            Tgid:\t7\n\
            Ngid:\t0\n\
            Pid:\t9\n\
            PPid:\t3\n\
            TracerPid:\t0\n\
            Uid:\t0\t0\t0\t0\n\
            Gid:\t0\t0\t0\t0\n\
            Groups:\t0 65534 \n\
            NStgid:\t7\n\
            NSpid:\t9\n\
            NSpgid:\t0\n\
            NSsid:\t0\n\
            Kthread:\t0\n\
            VmPeak:\t       0 kB\n\
            VmSize:\t       0 kB\n\
            VmLck:\t       0 kB\n\
            VmPin:\t       0 kB\n\
            VmHWM:\t       0 kB\n\
            VmRSS:\t       0 kB\n\
            RssAnon:\t       0 kB\n\
            RssFile:\t       0 kB\n\
            RssShmem:\t       0 kB\n\
            VmData:\t       0 kB\n\
            VmStk:\t       0 kB\n\
            VmExe:\t       0 kB\n\
            VmLib:\t       0 kB\n\
            VmPTE:\t       0 kB\n\
            VmSwap:\t       0 kB\n\
            HugetlbPages:\t       0 kB\n\
            Threads:\t2\n\
            SigPnd:\t0000000000000000\n\
            ShdPnd:\t0000000000004000\n\
            SigBlk:\t0000000000000200\n\
            SigIgn:\t0000000080000800\n\
            SigCgt:\t0000000100000000\n\
            CapInh:\t0000000000000000\n\
            CapPrm:\t000001ffffffffff\n\
            CapEff:\t000001ffffffffff\n\
            Cpus_allowed:\t00000000,00000000,00000000,00000001\n\
            Cpus_allowed_list:\t0\n\
            Mems_allowed:\t1\n\
            Mems_allowed_list:\t0\n\
            voluntary_ctxt_switches:\t0\n\
            nonvoluntary_ctxt_switches:\t0\n";
        assert_eq!(text, expected);
    }

    /// A zombie's status says `Z (zombie)` and has no memory block, as
    /// Linux prints it only with an mm; with no signal sets reported
    /// for it, it has no signal lines either.
    #[test]
    fn a_zombies_status_has_no_memory_block() {
        let mut zombie = status_fields(true, false);
        zombie.signals = None;
        zombie.groups = &[];
        let text = render_status(&zombie);
        // No groups print as Linux's lone trailing space.
        assert!(String::from_utf8_lossy(&text).contains("Groups:\t \n"));
        let names = names(&text);
        assert!(String::from_utf8_lossy(&text).contains("State:\tZ (zombie)\n"));
        assert!(
            names
                .iter()
                .all(|name| !MEMORY_LINES.contains(&name.as_str()))
        );
        assert!(!names.contains(&"SigBlk".to_owned()));
        assert!(names.contains(&"Threads".to_owned()));
        assert!(names.contains(&"CapEff".to_owned()));
    }

    /// The reader's own task is running; its bounding and ambient sets
    /// show where given, and capability lines are left out where not.
    #[test]
    fn the_readers_own_status_is_running_and_shows_what_is_given() {
        let mut own = status_fields(false, true);
        own.capabilities = StatusCapabilities {
            inheritable_permitted_effective: None,
            bounding: Some(0x1ff_ffff_ffff),
            ambient: Some(0),
        };
        let text = String::from_utf8(render_status(&own)).unwrap();
        assert!(text.contains("State:\tR (running)\n"), "{text}");
        assert!(text.contains("CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n"));
        assert!(!text.contains("CapInh"), "{text}");
    }

    /// Caller-rendered affinity strings print verbatim.
    #[test]
    fn a_status_shows_the_given_affinity() {
        let mut virtual_cpus = status_fields(false, false);
        virtual_cpus.cpus_allowed = ("f".to_owned(), "0-3".to_owned());
        let text = String::from_utf8(render_status(&virtual_cpus)).unwrap();
        assert!(
            text.contains("Cpus_allowed:\tf\nCpus_allowed_list:\t0-3\n"),
            "{text}"
        );
    }
}
