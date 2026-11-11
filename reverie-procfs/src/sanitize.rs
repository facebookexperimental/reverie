/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Sanitizers for kernel-captured `/proc` snapshots: pure transforms
//! from captured bytes to the bytes a guest may see, with host counters,
//! identities and addresses determinized. Each function documents the
//! Linux format it rewrites. Anything time-, CPU- or identity-shaped
//! arrives as a parameter the caller decided; nothing here reads the
//! host. Sanitizers coupled to caller state (mount snapshots, lock
//! ledgers, signal-delivery policy) deliberately do not live here.

/// Every `smaps`/`smaps_rollup` field that counts pages the host currently
/// holds for the mapping: resident, dirty, swapped, huge-page backed, reclaim
/// pending, or locked. Reclaim, writeback, khugepaged and swap change these
/// without any guest action, so both sanitizers report each one as `0 kB`.
/// The zero `Rss` bounds every field except `Swap` and `SwapPss`, which count
/// swapped-out pages, and `Shared_Hugetlb` and `Private_Hugetlb`, which count
/// hugetlb pages that the kernel keeps out of `Rss`. All zero is still a
/// state Linux reports, for example for an untouched mapping.
const SMAPS_ACCOUNTING_FIELDS: &[&str] = &[
    "Rss",
    "Pss",
    "Pss_Dirty",
    "Pss_Anon",
    "Pss_File",
    "Pss_Shmem",
    "Shared_Clean",
    "Shared_Dirty",
    "Private_Clean",
    // Counts a page as dirty when its page-cache copy is dirty, not only
    // when the guest wrote it, so a freshly written executable reports
    // 4 kB per text mapping until host writeback runs.
    "Private_Dirty",
    "Referenced",
    "Anonymous",
    "KSM",
    "LazyFree",
    "AnonHugePages",
    "ShmemPmdMapped",
    "FilePmdMapped",
    "Shared_Hugetlb",
    "Private_Hugetlb",
    "Swap",
    "SwapPss",
    "Locked",
];

fn sockstat_field(fields: &[String], name: &str) -> Option<String> {
    let index = fields.iter().position(|field| field == name)?;
    fields.get(index + 1).cloned()
}

fn replace_sockstat_field(fields: &mut [String], name: &str, value: &str) {
    let Some(index) = fields.iter().position(|field| field == name) else {
        return;
    };
    let Some(field_value) = fields.get_mut(index + 1) else {
        return;
    };
    *field_value = value.to_owned();
}

pub fn sanitize_numeric_lines(contents: &[u8], stable_fields: usize) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(contents.len());
    for line in contents.split_inclusive(|byte| *byte == b'\n') {
        let has_newline = line.last() == Some(&b'\n');
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let fields = body
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let counters = fields.get(stable_fields..).unwrap_or_default();
        if !counters.is_empty()
            && counters
                .iter()
                .all(|field| field.iter().all(u8::is_ascii_digit))
        {
            for (index, field) in fields.iter().take(stable_fields).enumerate() {
                if index > 0 {
                    normalized.push(b' ');
                }
                normalized.extend_from_slice(field);
            }
            for (index, _) in counters.iter().enumerate() {
                if !normalized.is_empty() && normalized.last() != Some(&b'\n') {
                    normalized.push(b' ');
                }
                let value = match index {
                    0 | 4 => 1,
                    2 | 6 => 8,
                    _ => 0,
                };
                normalized.extend_from_slice(value.to_string().as_bytes());
            }
        } else {
            normalized.extend_from_slice(body);
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_stat(contents: &[u8], virtual_identity: Option<(i32, i32)>) -> Vec<u8> {
    const VOLATILE_FIELDS: &[usize] = &[
        10, 11, 12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 39, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ];

    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let Some(comm_start) = text.find(" (") else {
        return contents.to_vec();
    };
    let Some(comm_end) = text.rfind(") ") else {
        return contents.to_vec();
    };
    let comm = &text[comm_start..=comm_end];
    let mut fields = text[comm_end + 2..]
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if fields.len() < 50 {
        return contents.to_vec();
    }

    // `fields` starts with proc stat field 3 (state).
    let pid = if let Some((virtual_pid, virtual_ppid)) = virtual_identity {
        fields[4 - 3] = virtual_ppid.to_string();
        fields[5 - 3] = "0".to_owned();
        fields[6 - 3] = "0".to_owned();
        virtual_pid.to_string()
    } else {
        fields[0] = "S".to_owned();
        text[..comm_start].to_owned()
    };
    for field in VOLATILE_FIELDS {
        fields[*field - 3] = "0".to_owned();
    }
    format!("{pid}{comm} {}\n", fields.join(" ")).into_bytes()
}

pub fn sanitize_statm(contents: &[u8]) -> Vec<u8> {
    let fields = contents
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    if fields.len() != 7
        || fields
            .iter()
            .any(|field| !field.iter().all(u8::is_ascii_digit))
    {
        return contents.to_vec();
    }
    b"0 0 0 0 0 0 0\n".to_vec()
}

pub fn sanitize_diskstats(contents: &[u8]) -> Vec<u8> {
    sanitize_numeric_lines(contents, 3)
}

pub fn sanitize_process_io(contents: &[u8]) -> Vec<u8> {
    const COUNTERS: &[&[u8]] = &[
        b"rchar",
        b"wchar",
        b"syscr",
        b"syscw",
        b"read_bytes",
        b"write_bytes",
        b"cancelled_write_bytes",
    ];

    let mut normalized = Vec::with_capacity(contents.len());
    for line in contents.split_inclusive(|byte| *byte == b'\n') {
        let has_newline = line.last() == Some(&b'\n');
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let name_end = body.iter().position(|byte| *byte == b':');
        let name = name_end.map_or(body, |end| &body[..end]);
        if COUNTERS.contains(&name) {
            normalized.extend_from_slice(name);
            normalized.extend_from_slice(b": 0");
        } else {
            normalized.extend_from_slice(body);
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_uptime(contents: &[u8], virtual_uptime_seconds: u64) -> Vec<u8> {
    if contents.is_empty() {
        Vec::new()
    } else {
        format!("{virtual_uptime_seconds}.00 0.00\n").into_bytes()
    }
}

/// `/proc/stat` for a snapshot the kernel's file was captured for (under
/// record and replay, or after a `chroot`): the same bytes the caller renders
/// for its own open ([`render_system_stat`]), so that the file has one layout
/// whichever opened it. Nothing of the capture is kept but whether it was
/// empty: the host's lines, such as its `intr` line with a field per host
/// interrupt number, would show the host.
pub fn sanitize_system_stat(
    contents: &[u8],
    virtual_uptime_seconds: u64,
    virtual_boot_time_seconds: i64,
    cpus: u32,
) -> Vec<u8> {
    if contents.is_empty() {
        Vec::new()
    } else {
        render_system_stat(virtual_uptime_seconds, virtual_boot_time_seconds, cpus)
    }
}

/// The kernel-shaped bytes a rendered `/proc/stat` snapshot starts from:
/// [`render_system_stat`] at uptime 0 and boot time 0 on one CPU.
pub const SYSTEM_STAT_TEMPLATE: &[u8] = b"cpu  0 0 0 0 0 0 0 0 0 0\n\
cpu0 0 0 0 0 0 0 0 0 0 0\n\
intr 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
ctxt 0\n\
btime 0\n\
processes 0\n\
procs_running 0\n\
procs_blocked 0\n\
softirq 0 0 0 0 0 0 0 0 0 0 0\n";

/// `/proc/stat` in the layout of Linux's `show_stat` (`fs/proc/stat.c`), for
/// a machine of `cpus` CPUs whose uptime is `virtual_uptime_seconds` and whose
/// boot instant is `virtual_boot_time_seconds`:
///
/// - the aggregate line, spelled `cpu` and two spaces as Linux spells it, and
///   a `cpuN` line per CPU, each with Linux's ten columns in USER_HZ (100)
///   ticks. Every CPU spent the whole uptime in the first column (user),
///   none of it idle, as `/proc/uptime`'s idle time of 0 says; the aggregate
///   is their sum.
/// - `intr`, the total and one count per interrupt number, for the
///   [`crate::fixed::NR_IRQS`] numbers every x86 kernel has (`/proc/interrupts`
///   lists lines below it); `ctxt`; `btime`, the boot instant, which is fixed
///   for the run; `processes`, `procs_running` and `procs_blocked`; and
///   `softirq`, the total and one count per softirq ([`crate::fixed::SOFTIRQS`],
///   Linux's `NR_SOFTIRQS`). Every count is 0, as `/proc/interrupts` and
///   `/proc/softirqs` show.
///
/// Nothing here comes from the host, so every backend renders the same bytes.
pub fn render_system_stat(
    virtual_uptime_seconds: u64,
    virtual_boot_time_seconds: i64,
    cpus: u32,
) -> Vec<u8> {
    // USER_HZ.
    let per_cpu = virtual_uptime_seconds.saturating_mul(100);
    let total = per_cpu.saturating_mul(u64::from(cpus));
    let idle_columns = " 0".repeat(9);
    let mut out = format!("cpu  {total}{idle_columns}\n");
    for cpu in 0..cpus {
        out += &format!("cpu{cpu} {per_cpu}{idle_columns}\n");
    }
    out += &format!("intr 0{}\n", " 0".repeat(crate::fixed::NR_IRQS));
    out += &format!(
        "ctxt 0\nbtime {virtual_boot_time_seconds}\nprocesses 0\nprocs_running 0\nprocs_blocked 0\n"
    );
    out += &format!("softirq 0{}\n", " 0".repeat(crate::fixed::SOFTIRQS.len()));
    out.into_bytes()
}

pub fn sanitize_pty_nr(contents: &[u8], virtual_count: usize) -> Vec<u8> {
    let Ok(value) = std::str::from_utf8(contents) else {
        return Vec::new();
    };
    if value.trim().parse::<u64>().is_err() {
        return Vec::new();
    }
    format!("{virtual_count}\n").into_bytes()
}

pub fn sanitize_sockstat(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let mut fields = body
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        match fields.first().map(String::as_str) {
            Some("TCP:") => {
                let inuse = sockstat_field(&fields, "inuse").unwrap_or_else(|| "0".to_owned());
                replace_sockstat_field(&mut fields, "orphan", "0");
                replace_sockstat_field(&mut fields, "alloc", &inuse);
                replace_sockstat_field(&mut fields, "mem", "0");
            }
            Some("UDP:") => replace_sockstat_field(&mut fields, "mem", "0"),
            _ => {}
        }

        normalized.extend_from_slice(fields.join(" ").as_bytes());
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_self_sched(contents: &[u8]) -> Vec<u8> {
    const FLOAT_FIELDS: &[&str] = &["se.exec_start", "se.vruntime", "se.sum_exec_runtime"];
    const INTEGER_FIELDS: &[&str] = &[
        "se.nr_migrations",
        "nr_switches",
        "nr_voluntary_switches",
        "nr_involuntary_switches",
        "se.avg.load_sum",
        "se.avg.runnable_sum",
        "se.avg.util_sum",
        "se.avg.load_avg",
        "se.avg.runnable_avg",
        "se.avg.util_avg",
        "se.avg.last_update_time",
        "se.avg.util_est",
        "clock-delta",
    ];
    const STABLE_INTEGER_FIELDS: &[&str] = &[
        "se.load.weight",
        "policy",
        "prio",
        "se.slice",
        "ext.enabled",
        "uclamp.min",
        "uclamp.max",
        "effective uclamp.min",
        "effective uclamp.max",
    ];
    const UCLAMP_FIELDS: &[(&str, &str)] = &[
        ("uclamp.min", "0"),
        ("uclamp.max", "1024"),
        ("effective uclamp.min", "0"),
        ("effective uclamp.max", "1024"),
    ];
    // NUMA balancing's lines, with its `current_node=` line and a
    // `numa_faults` line per node, which a kernel built without NUMA does
    // not print (`sched_show_numa`, kernel/sched/debug.c:1250-1262 at v7.1,
    // under `CONFIG_NUMA_BALANCING`, which depends on `CONFIG_NUMA`): each is
    // checked as the others are and left out, as is how many nodes the host
    // has.
    const NUMA_BALANCING_FIELDS: &[&str] = &[
        "mm->numa_scan_seq",
        "numa_pages_migrated",
        "numa_preferred_nid",
        "total_numa_faults",
    ];

    let Ok(text) = std::str::from_utf8(contents) else {
        return Vec::new();
    };
    let mut normalized = Vec::with_capacity(contents.len());
    let mut core_fields_seen = [false; 3];
    let mut header_seen = false;

    for (line_index, line) in text.split_inclusive('\n').enumerate() {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        if line_index == 0 {
            let Some((name, details)) = body.rsplit_once(" (") else {
                return Vec::new();
            };
            let Some(details) = details.strip_suffix(')') else {
                return Vec::new();
            };
            let Some((pid, threads)) = details.split_once(", #threads: ") else {
                return Vec::new();
            };
            if pid.parse::<i32>().is_err() || threads.parse::<u64>().is_err() {
                return Vec::new();
            }
            normalized.extend_from_slice(format!("{name} (0, #threads: 1)").as_bytes());
            if has_newline {
                normalized.push(b'\n');
            }
            header_seen = true;
            continue;
        }
        let Some((left, right)) = body.split_once(':') else {
            if !body.is_empty() && body.bytes().all(|byte| byte == b'-') {
                normalized.extend_from_slice(body.as_bytes());
            } else if body.starts_with("current_node=") {
                let fields = body
                    .replace(',', "")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if fields.len() != 2
                    || !fields.iter().all(|field| {
                        field.split_once('=').is_some_and(|(name, value)| {
                            matches!(name, "current_node" | "numa_group_id")
                                && value.parse::<i64>().is_ok()
                        })
                    })
                {
                    return Vec::new();
                }
                continue;
            } else if body.starts_with("numa_faults ") {
                let fields = body.split_whitespace().skip(1).collect::<Vec<_>>();
                let expected = [
                    "node",
                    "task_private",
                    "task_shared",
                    "group_private",
                    "group_shared",
                ];
                if fields.len() != expected.len()
                    || !fields.iter().zip(expected).all(|(field, expected)| {
                        field.split_once('=').is_some_and(|(name, value)| {
                            name == expected && value.parse::<u64>().is_ok()
                        })
                    })
                {
                    return Vec::new();
                }
                continue;
            } else {
                return Vec::new();
            }
            if has_newline {
                normalized.push(b'\n');
            }
            continue;
        };
        let label = left.trim();
        if NUMA_BALANCING_FIELDS.contains(&label) {
            if right.trim().parse::<i128>().is_err() {
                return Vec::new();
            }
            continue;
        }
        let replacement = if let Some(index) = FLOAT_FIELDS.iter().position(|field| *field == label)
        {
            let Ok(value) = right.trim().parse::<f64>() else {
                return Vec::new();
            };
            if !value.is_finite() || value.is_sign_negative() {
                return Vec::new();
            }
            core_fields_seen[index] = true;
            Some("0.000000")
        } else if let Some((_, replacement)) =
            UCLAMP_FIELDS.iter().find(|(field, _)| *field == label)
        {
            if right.trim().parse::<u128>().is_err() {
                return Vec::new();
            }
            Some(*replacement)
        } else if INTEGER_FIELDS.contains(&label) {
            if right.trim().parse::<u128>().is_err() {
                return Vec::new();
            }
            Some("0")
        } else if STABLE_INTEGER_FIELDS.contains(&label) {
            if right.trim().parse::<i128>().is_err() {
                return Vec::new();
            }
            None
        } else if right.trim().parse::<u128>().is_ok() {
            // New kernels may append observational scheduler counters. Keep
            // forward-compatible numeric telemetry deterministic without
            // accepting malformed or negative unknown fields.
            Some("0")
        } else if right
            .trim()
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite() && !value.is_sign_negative())
            && right.trim().contains('.')
        {
            // With kernel.sched_schedstats=1 the kernel adds nanosecond fields
            // printed as milliseconds with six decimals (sum_sleep_runtime,
            // wait_max, avg_atom, ...; kernel/sched/debug.c,
            // proc_sched_show_task). They are host timing, so they become
            // zero; refusing them emptied the whole file for the guest.
            Some("0.000000")
        } else {
            return Vec::new();
        };

        if let Some(value) = replacement {
            normalized.extend_from_slice(left.as_bytes());
            normalized.extend_from_slice(b": ");
            normalized.extend_from_slice(value.as_bytes());
        } else {
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }

    if header_seen && core_fields_seen.iter().all(|seen| *seen) {
        normalized
    } else {
        Vec::new()
    }
}

pub fn sanitize_fdinfo(contents: &[u8], identity: Option<(u64, i32, u64, u64)>) -> Vec<u8> {
    let Some((virtual_inode, logical_flags, virtual_open_file, virtual_mount_id)) = identity else {
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(contents) else {
        return Vec::new();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        if body.starts_with("mnt_id:") {
            normalized.extend_from_slice(format!("mnt_id:\t{virtual_mount_id}").as_bytes());
        } else if body.starts_with("ino:") {
            normalized.extend_from_slice(format!("ino:\t{virtual_inode}").as_bytes());
        } else if body.starts_with("flags:") {
            normalized.extend_from_slice(format!("flags:\t{logical_flags:07o}").as_bytes());
        } else if body.starts_with("eventfd-id:") {
            normalized.extend_from_slice(format!("eventfd-id: {virtual_open_file}").as_bytes());
        } else if body.starts_with("Pid:") {
            normalized.extend_from_slice(b"Pid:\t1");
        } else if body.starts_with("NSpid:") {
            normalized.extend_from_slice(b"NSpid:\t1");
        } else if body.starts_with("tfd:")
            || body.starts_with("inotify ")
            || body.starts_with("lock:")
        {
            return Vec::new();
        } else {
            let allowed = body.split_once(':').is_some_and(|(label, _)| {
                matches!(
                    label,
                    "pos"
                        | "eventfd-count"
                        | "eventfd-semaphore"
                        | "sigmask"
                        | "clockid"
                        | "ticks"
                        | "settime flags"
                        | "it_value"
                        | "it_interval"
                        | "seals"
                        // Linux reports the number of descriptors currently
                        // queued on this socket. It is socket state, not a
                        // host-assigned identity, so preserve it verbatim.
                        | "scm_fds"
                )
            });
            if !allowed {
                return Vec::new();
            }
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_smaps_rollup(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let accounting_label = body.split_once(':').and_then(|(label, value)| {
            let mut fields = value.split_whitespace();
            let amount = fields.next()?;
            (amount.parse::<u64>().is_ok()
                && fields.next() == Some("kB")
                && fields.next().is_none())
            .then_some(label)
        });
        if let Some(label) =
            accounting_label.filter(|label| SMAPS_ACCOUNTING_FIELDS.contains(label))
        {
            normalized.extend_from_slice(label.as_bytes());
            normalized.extend_from_slice(b":\t0 kB");
        } else {
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

/// A process's cgroup, as for a process in the root cgroup: every
/// `hierarchy-ID:controllers:path` line keeps its ID and controllers and gets
/// the path `/`. That agrees with the guest's other views, which are the
/// initial cgroup namespace's (`/proc/self/ns/cgroup`) and the host's
/// `/sys/fs/cgroup`. The host's path names whatever launched Hermit, such as a
/// systemd unit named after its start time, so two separately launched runs
/// read different bytes, and Go, which reads this file at every process start
/// to size GOMAXPROCS from its cgroup's `cpu.max`, then took different
/// branches, ran for different virtual times and wrote different timestamps
/// into its build cache (https://github.com/rrnewton/hermit/issues/4378).
/// With the path `/`, Go reads `/sys/fs/cgroup/cpu.max` instead: absent on a
/// host's real root cgroup, but the launcher's quota at the root of a private
/// cgroup namespace (a container), so launchers with different quotas can
/// still differ (https://github.com/rrnewton/hermit/issues/4388).
///
/// Split on bytes: a cgroup directory name may hold any byte but `/` and NUL,
/// and a name that is not UTF-8 must not pass through.
pub fn sanitize_process_cgroup(contents: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(contents.len());
    for line in contents.split_inclusive(|&byte| byte == b'\n') {
        let has_newline = line.ends_with(b"\n");
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let mut fields = body.splitn(3, |&byte| byte == b':');
        match (fields.next(), fields.next(), fields.next()) {
            (Some(hierarchy), Some(controllers), Some(_path)) => {
                normalized.extend_from_slice(hierarchy);
                normalized.push(b':');
                normalized.extend_from_slice(controllers);
                normalized.extend_from_slice(b":/");
            }
            _ => normalized.extend_from_slice(body),
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_arch_status(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        // The kernel prints -1 for a task that has never used AVX-512
        // (arch/x86/kernel/fpu/xstate.c, avx512_status), so whether a guest
        // sees -1 or a time depends on whether the host's libraries chose
        // AVX-512 code. Both become 0, the same on every host.
        let elapsed = body
            .strip_prefix("AVX512_elapsed_ms:")
            .map(str::trim)
            .filter(|value| *value == "-1" || value.parse::<u64>().is_ok());
        if elapsed.is_some() {
            normalized.extend_from_slice(b"AVX512_elapsed_ms:\t0");
        } else {
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_pressure(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let fields = body
            .split_whitespace()
            .map(|field| {
                let Some((name, _)) = field.split_once('=') else {
                    return field.to_owned();
                };
                match name {
                    "avg10" | "avg60" | "avg300" => format!("{name}=0.00"),
                    "total" => "total=0".to_owned(),
                    _ => field.to_owned(),
                }
            })
            .collect::<Vec<_>>();

        normalized.extend_from_slice(fields.join(" ").as_bytes());
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

/// A task's `schedstat` (`proc_pid_schedstat`, fs/proc/base.c:511-523 at
/// v6.16): its runtime, `runtime` (`se.sum_exec_runtime`, in nanoseconds),
/// where the caller knows it, else 0; and 0 for the time it waited on a run
/// queue and the times it ran (`sched_info.run_delay`, `pcount`), which
/// callers of this crate do not model, as `getrusage`'s context-switch counts stay 0.
pub fn sanitize_task_schedstat(contents: &[u8], runtime_nanos: Option<u64>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields.iter().any(|field| field.parse::<u64>().is_err()) {
        return contents.to_vec();
    }
    let runtime = runtime_nanos.unwrap_or(0);
    let newline = if text.ends_with('\n') { "\n" } else { "" };
    format!("{runtime} 0 0{newline}").into_bytes()
}

/// Exposes the virtual CPUs, `cpus` of them, and hides host CPU count,
/// hotplug state, CPU identifiers, and live network backlog counters: one
/// idle row per CPU, whose thirteenth column is the CPU's number, as
/// `softnet_seq_show` prints it.
pub fn sanitize_softnet_stat(cpus: u32) -> Vec<u8> {
    (0..cpus)
        .map(|cpu| format!("{}{cpu:08x} 00000000 00000000\n", "00000000 ".repeat(12)))
        .collect::<String>()
        .into_bytes()
}

pub fn sanitize_protocols(contents: &[u8]) -> Vec<u8> {
    const HEADER: &[&str] = &[
        "protocol", "size", "sockets", "memory", "press", "maxhdr", "slab", "module",
    ];

    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return contents.to_vec();
    };
    let header_fields = header.split_whitespace().collect::<Vec<_>>();
    if !header_fields.starts_with(HEADER) {
        return contents.to_vec();
    }

    let mut normalized = Vec::new();
    normalized.push(header.to_owned());
    for line in lines {
        let mut fields = line
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if fields.len() != header_fields.len()
            || fields[1].parse::<u64>().is_err()
            || fields[2].parse::<u64>().is_err()
            || (fields[3] != "-1" && fields[3].parse::<u64>().is_err())
        {
            return contents.to_vec();
        }

        fields[2] = "0".to_owned();
        if fields[3] != "-1" {
            fields[3] = "0".to_owned();
        }
        normalized.push(fields.join(" "));
    }
    if normalized.len() == 1 {
        return contents.to_vec();
    }

    let mut output = normalized.join("\n").into_bytes();
    if text.ends_with('\n') {
        output.push(b'\n');
    }
    output
}

pub fn sanitize_random_uuid(contents: &[u8], mut random: [u8; 16]) -> Vec<u8> {
    const HYPHENS: &[usize] = &[8, 13, 18, 23];

    if contents.len() != 37 || contents[36] != b'\n' {
        return contents.to_vec();
    }
    for (index, byte) in contents[..36].iter().copied().enumerate() {
        if HYPHENS.contains(&index) {
            if byte != b'-' {
                return contents.to_vec();
            }
        } else if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
            return contents.to_vec();
        }
    }
    if contents[14] != b'4' || !matches!(contents[19], b'8' | b'9' | b'a' | b'b') {
        return contents.to_vec();
    }

    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\n",
        random[0],
        random[1],
        random[2],
        random[3],
        random[4],
        random[5],
        random[6],
        random[7],
        random[8],
        random[9],
        random[10],
        random[11],
        random[12],
        random[13],
        random[14],
        random[15]
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_normalizes_runtime_counters() {
        let input = b"3 (name with spaces) R 1 0 0 0 -1 0 89 0 1 2 3 4 5 6 20 0 1 7 520343512 2879488 123 18446744073709551615 100 200 300 0 0 0 0 3145728 0 0 0 0 17 114 0 0 9 10 11 400 500 600 700 800 900 1000 0\n";
        let output = String::from_utf8(sanitize_stat(input, Some((3, 1)))).unwrap();
        let comm_end = output.rfind(") ").unwrap();
        let fields = output[comm_end + 2..]
            .split_whitespace()
            .collect::<Vec<_>>();
        for field in [
            10, 11, 12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36, 37, 39, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
        ] {
            assert_eq!(fields[field - 3], "0", "field {field} was not normalized");
        }
        assert!(output.starts_with("3 (name with spaces) R 1 0 0 "));
    }

    #[test]
    fn softnet_stat_synthesizes_one_idle_row_per_virtual_cpu() {
        let row = |cpu: &str| {
            format!(
                "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 \
                 00000000 00000000 00000000 00000000 {cpu} 00000000 00000000\n"
            )
        };
        assert_eq!(
            String::from_utf8(sanitize_softnet_stat(1)).unwrap(),
            row("00000000")
        );
        assert_eq!(
            String::from_utf8(sanitize_softnet_stat(3)).unwrap(),
            row("00000000") + &row("00000001") + &row("00000002")
        );
    }

    #[test]
    fn system_stat_uses_virtual_uptime_and_boot_time() {
        // Linux's layout (`show_stat`): `cpu` and two spaces, ten columns, a
        // count per interrupt number below NR_IRQS, and the ten softirqs.
        let expected: &[u8] = b"cpu  12000 0 0 0 0 0 0 0 0 0\n\
cpu0 12000 0 0 0 0 0 0 0 0 0\n\
intr 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
ctxt 0\n\
btime 1767225480\n\
processes 0\n\
procs_running 0\n\
procs_blocked 0\n\
softirq 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(render_system_stat(120, 1_767_225_480, 1), expected);
        for host in [
            &b"cpu  1 2 3 4 5 6 7 8 9 10\ncpu0 1 2 3 4 5 6 7 8 9 10\nintr 9 8 7\nbtime 1234\nprocesses 55\n"[..],
            b"cpu  1 2 3\ncpu0 1 2 3\ncpu1 4 5 6\nintr 400 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20\nctxt 99\nbtime 7\nsoftirq 5 1 1 1 1 1\n",
            b"x",
        ] {
            assert_eq!(
                sanitize_system_stat(host, 120, 1_767_225_480, 1),
                expected,
                "{}",
                String::from_utf8_lossy(host)
            );
        }
        assert_eq!(sanitize_system_stat(b"", 120, 1_767_225_480, 1), b"");
        let two = String::from_utf8(render_system_stat(120, -5, 2)).unwrap();
        assert!(
            two.starts_with(
                "cpu  24000 0 0 0 0 0 0 0 0 0\ncpu0 12000 0 0 0 0 0 0 0 0 0\n\
                 cpu1 12000 0 0 0 0 0 0 0 0 0\nintr 0"
            ),
            "{two}"
        );
        assert!(two.contains("\nbtime -5\n"), "{two}");
        let huge = String::from_utf8(render_system_stat(u64::MAX / 10, 0, 1)).unwrap();
        assert!(huge.starts_with(&format!("cpu  {} 0", u64::MAX)), "{huge}");
    }

    #[test]
    fn io_accounting_counters_use_synthetic_values() {
        assert_eq!(
            sanitize_diskstats(b"259 0 nvme0n1 100 2 300 4 500 6 700 8 9 10 11\n"),
            b"259 0 nvme0n1 1 0 8 0 1 0 8 0 0 0 0\n"
        );
        assert_eq!(
            sanitize_process_io(
                b"rchar: 100\nwchar: 200\nsyscr: 3\nsyscw: 4\nread_bytes: 5\nwrite_bytes: 6\ncancelled_write_bytes: 7\n"
            ),
            b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n"
        );
    }

    #[test]
    fn uptime_uses_the_virtual_value() {
        assert_eq!(
            sanitize_uptime(b"156980.56 37990755.08\n", 120),
            b"120.00 0.00\n"
        );
    }

    #[test]
    fn pty_nr_hides_host_global_allocations() {
        assert_eq!(sanitize_pty_nr(b"107\n", 2), b"2\n");
        assert!(sanitize_pty_nr(b"", 2).is_empty());
    }

    #[test]
    fn sockstat_hides_host_global_allocation_and_memory_counters() {
        let contents = b"sockets: used 41\n\
TCP: inuse 3 orphan 2 tw 7 alloc 100 mem 200\n\
UDP: inuse 4 mem 99\n\
RAW: inuse 5\n";
        assert_eq!(
            sanitize_sockstat(contents),
            b"sockets: used 41\n\
TCP: inuse 3 orphan 0 tw 7 alloc 3 mem 0\n\
UDP: inuse 4 mem 0\n\
RAW: inuse 5\n"
        );
    }

    #[test]
    fn pressure_hides_host_stall_averages_and_totals() {
        let contents = b"some avg10=12.34 avg60=23.45 avg300=34.56 total=123456\n\
full avg10=1.23 avg60=2.34 avg300=3.45 total=654321\n";
        assert_eq!(
            sanitize_pressure(contents),
            b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\
full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        );
    }

    #[test]
    fn protocols_hides_live_socket_and_memory_counters() {
        let contents = b"protocol size sockets memory press maxhdr slab module cl co\n\
TCP 2304 17 12309 no 256 yes kernel y y\n\
RAW 1008 4 -1 NI 0 yes kernel y y\n";
        assert_eq!(
            sanitize_protocols(contents),
            b"protocol size sockets memory press maxhdr slab module cl co\n\
TCP 2304 0 0 no 256 yes kernel y y\n\
RAW 1008 0 -1 NI 0 yes kernel y y\n"
        );
        let missing_column = b"protocol size sockets press\nTCP 2304 17 no\n";
        assert_eq!(sanitize_protocols(missing_column), missing_column);
        let invalid_counter = b"protocol size sockets memory press maxhdr slab module\n\
TCP 2304 many 12309 no 256 yes kernel\n";
        assert_eq!(sanitize_protocols(invalid_counter), invalid_counter);
    }

    #[test]
    fn task_schedstat_hides_host_scheduler_accounting() {
        assert_eq!(
            sanitize_task_schedstat(b"3029609 1559338 150\n", None),
            b"0 0 0\n"
        );
        assert_eq!(
            sanitize_task_schedstat(b"3029609 1559338 150", None),
            b"0 0 0"
        );
    }

    /// The runtime is the task's CPU time in nanoseconds, where the
    /// caller knows it; the run-queue wait and the run count stay 0.
    #[test]
    fn task_schedstat_shows_the_tasks_runtime() {
        let runtime = Some(41_250_370);
        assert_eq!(
            sanitize_task_schedstat(b"3029609 1559338 150\n", runtime),
            b"41250370 0 0\n"
        );
        assert_eq!(sanitize_task_schedstat(b"0 0 0", runtime), b"41250370 0 0");
    }

    #[test]
    fn task_schedstat_leaves_unknown_formats_untouched() {
        let runtime = Some(7);
        let extra_field = b"3029609 1559338 150 4\n";
        assert_eq!(sanitize_task_schedstat(extra_field, runtime), extra_field);
        let invalid_counter = b"3029609 waiting 150\n";
        assert_eq!(
            sanitize_task_schedstat(invalid_counter, runtime),
            invalid_counter
        );
    }

    #[test]
    fn fdinfo_hides_backing_identity_only() {
        let contents = b"pos:\t1\n\
flags:\t0100002\n\
mnt_id:\t16368\n\
ino:\t47761541\n\
eventfd-count: 0000000000000007\n\
scm_fds: 2\n";
        assert_eq!(
            sanitize_fdinfo(contents, Some((9007, 0o100002, 42, 7))),
            b"pos:\t1\n\
flags:\t0100002\n\
mnt_id:\t7\n\
ino:\t9007\n\
eventfd-count: 0000000000000007\n\
scm_fds: 2\n"
        );
        assert!(
            sanitize_fdinfo(
                b"pos:\t1\nflags:\t02\nmnt_id:\t7\nino:\t8\nunknown-field: 9\n",
                Some((9007, 2, 42, 7))
            )
            .is_empty(),
            "an unknown fdinfo field must continue to refuse normalization"
        );
    }
}
